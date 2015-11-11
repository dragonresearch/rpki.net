# $Id$
#
# Copyright (C) 2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2009-2013  Internet Systems Consortium ("ISC")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL AND ISC DISCLAIM ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL DRL OR
# ISC BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
# DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA
# OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
# TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""
Server implementation for the RPKI-RTR protocol (RFC 6810 et sequalia).
"""

import os
import sys
import errno
import socket
import signal
import logging
import asyncore
import rpki.POW
import rpki.oids
import rpki.rtr.pdus
import rpki.rtr.channels

from rpki.rtr.pdus import (clone_pdu_root, CacheResponsePDU, EndOfDataPDU, CacheResetPDU, SerialNotifyPDU)


# Disable incremental updates.  Debugging only, should be False in production.
disable_incrementals = False

# These should be configurable in some sane fashion.
kickme_dir  = "sockets"
kickme_base = os.path.join(kickme_dir, "kickme")


class PDU(rpki.rtr.pdus.PDU):
    """
    Generic server PDU.
    """

    def send_file(self, server, filename):
        """
        Send a content of a file as a cache response.  Caller should catch IOError.
        """

        fn2 = os.path.splitext(filename)[1]
        assert fn2.startswith(".v") and fn2[2:].isdigit() and int(fn2[2:]) == server.version

        f = open(filename, "rb")
        server.push_pdu(CacheResponsePDU(version = server.version,
                                         nonce   = server.current_nonce))
        server.push_file(f)
        server.push_pdu(EndOfDataPDU(version = server.version,
                                     serial  = server.current_serial,
                                     nonce   = server.current_nonce,
                                     refresh = server.refresh,
                                     retry   = server.retry,
                                     expire  = server.expire))

    def send_nodata(self, server):
        """
        Send a nodata error.
        """

        server.push_pdu(ErrorReportPDU(version = server.version,
                                       errno = ErrorReportPDU.codes["No Data Available"],
                                       errpdu = self))


clone_pdu = clone_pdu_root(PDU)


@clone_pdu
class SerialQueryPDU(PDU, rpki.rtr.pdus.SerialQueryPDU):
    """
    Serial Query PDU.
    """

    def serve(self, server):
        """
        Received a serial query, send incremental transfer in response.
        If client is already up to date, just send an empty incremental
        transfer.
        """

        server.logger.debug(self)
        if server.get_serial() is None:
            self.send_nodata(server)
        elif server.current_nonce != self.nonce:
            server.logger.info("[Client requested wrong nonce, resetting client]")
            server.push_pdu(CacheResetPDU(version = server.version))
        elif server.current_serial == self.serial:
            server.logger.debug("[Client is already current, sending empty IXFR]")
            server.push_pdu(CacheResponsePDU(version = server.version,
                                             nonce   = server.current_nonce))
            server.push_pdu(EndOfDataPDU(version = server.version,
                                         serial  = server.current_serial,
                                         nonce   = server.current_nonce,
                                         refresh = server.refresh,
                                         retry   = server.retry,
                                         expire  = server.expire))
        elif disable_incrementals:
            server.push_pdu(CacheResetPDU(version = server.version))
        else:
            try:
                self.send_file(server, "%d.ix.%d.v%d" % (server.current_serial, self.serial, server.version))
            except IOError:
                server.push_pdu(CacheResetPDU(version = server.version))


@clone_pdu
class ResetQueryPDU(PDU, rpki.rtr.pdus.ResetQueryPDU):
    """
    Reset Query PDU.
    """

    def serve(self, server):
        """
        Received a reset query, send full current state in response.
        """

        server.logger.debug(self)
        if server.get_serial() is None:
            self.send_nodata(server)
        else:
            try:
                fn = "%d.ax.v%d" % (server.current_serial, server.version)
                self.send_file(server, fn)
            except IOError:
                server.push_pdu(ErrorReportPDU(version = server.version,
                                               errno   = ErrorReportPDU.codes["Internal Error"],
                                               errpdu  = self,
                                               errmsg  = "Couldn't open %s" % fn))


@clone_pdu
class ErrorReportPDU(rpki.rtr.pdus.ErrorReportPDU):
    """
    Error Report PDU.
    """

    def serve(self, server):
        """
        Received an ErrorReportPDU from client.  Not much we can do beyond
        logging it, then killing the connection if error was fatal.
        """

        server.logger.error(self)
        if self.errno in self.fatal:
            server.logger.error("[Shutting down due to reported fatal protocol error]")
            sys.exit(1)


def read_current(version):
    """
    Read current serial number and nonce.  Return None for both if
    serial and nonce not recorded.  For backwards compatibility, treat
    file containing just a serial number as having a nonce of zero.
    """

    if version is None:
        return None, None
    try:
        with open("current.v%d" % version, "r") as f:
            values = tuple(int(s) for s in f.read().split())
        return values[0], values[1]
    except IndexError:
        return values[0], 0
    except IOError:
        return None, None


def write_current(serial, nonce, version):
    """
    Write serial number and nonce.
    """

    curfn = "current.v%d" % version
    tmpfn = curfn + "%d.tmp" % os.getpid()
    with open(tmpfn, "w") as f:
        f.write("%d %d\n" % (serial, nonce))
    os.rename(tmpfn, curfn)


class FileProducer(object):
    """
    File-based producer object for asynchat.
    """

    def __init__(self, handle, buffersize):
        self.handle = handle
        self.buffersize = buffersize

    def more(self):
        return self.handle.read(self.buffersize)


class ServerWriteChannel(rpki.rtr.channels.PDUChannel):
    """
    Kludge to deal with ssh's habit of sometimes (compile time option)
    invoking us with two unidirectional pipes instead of one
    bidirectional socketpair.  All the server logic is in the
    ServerChannel class, this class just deals with sending the
    server's output to a different file descriptor.
    """

    def __init__(self):
        """
        Set up stdout.
        """

        super(ServerWriteChannel, self).__init__(root_pdu_class = PDU)
        self.init_file_dispatcher(sys.stdout.fileno())

    def readable(self):
        """
        This channel is never readable.
        """

        return False

    def push_file(self, f):
        """
        Write content of a file to stream.
        """

        try:
            self.push_with_producer(FileProducer(f, self.ac_out_buffer_size))
        except OSError, e:
            if e.errno != errno.EAGAIN:
                raise


class ServerChannel(rpki.rtr.channels.PDUChannel):
    """
    Server protocol engine, handles upcalls from PDUChannel to
    implement protocol logic.
    """

    def __init__(self, logger, refresh, retry, expire):
        """
        Set up stdin and stdout as connection and start listening for
        first PDU.
        """

        super(ServerChannel, self).__init__(root_pdu_class = PDU)
        self.init_file_dispatcher(sys.stdin.fileno())
        self.writer = ServerWriteChannel()
        self.logger = logger
        self.refresh = refresh
        self.retry = retry
        self.expire = expire
        self.get_serial()
        self.start_new_pdu()

    def writable(self):
        """
        This channel is never writable.
        """

        return False

    def push(self, data):
        """
        Redirect to writer channel.
        """

        return self.writer.push(data)

    def push_with_producer(self, producer):
        """
        Redirect to writer channel.
        """

        return self.writer.push_with_producer(producer)

    def push_pdu(self, pdu):
        """
        Redirect to writer channel.
        """

        return self.writer.push_pdu(pdu)

    def push_file(self, f):
        """
        Redirect to writer channel.
        """

        return self.writer.push_file(f)

    def deliver_pdu(self, pdu):
        """
        Handle received PDU.
        """

        pdu.serve(self)

    def get_serial(self):
        """
        Read, cache, and return current serial number, or None if we can't
        find the serial number file.  The latter condition should never
        happen, but maybe we got started in server mode while the cronjob
        mode instance is still building its database.
        """

        self.current_serial, self.current_nonce = read_current(self.version)
        return self.current_serial

    def check_serial(self):
        """
        Check for a new serial number.
        """

        old_serial = self.current_serial
        return old_serial != self.get_serial()

    def notify(self, data = None, force = False):
        """
        Cronjob instance kicked us: check whether our serial number has
        changed, and send a notify message if so.

        We have to check rather than just blindly notifying when kicked
        because the cronjob instance has no good way of knowing which
        protocol version we're running, thus has no good way of knowing
        whether we care about a particular change set or not.
        """

        if force or self.check_serial():
            self.push_pdu(SerialNotifyPDU(version = self.version,
                                          serial  = self.current_serial,
                                          nonce   = self.current_nonce))
        else:
            self.logger.debug("Cronjob kicked me but I see no serial change, ignoring")


class KickmeChannel(asyncore.dispatcher, object):
    """
    asyncore dispatcher for the PF_UNIX socket that cronjob mode uses to
    kick servers when it's time to send notify PDUs to clients.
    """

    def __init__(self, server):
        asyncore.dispatcher.__init__(self)                  # Old-style class
        self.server = server
        self.sockname = "%s.%d" % (kickme_base, os.getpid())
        self.create_socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            self.bind(self.sockname)
            os.chmod(self.sockname, 0660)
        except socket.error, e:
            self.server.logger.exception("Couldn't bind() kickme socket: %r", e)
            self.close()
        except OSError, e:
            self.server.logger.exception("Couldn't chmod() kickme socket: %r", e)

    def writable(self):
        """
        This socket is read-only, never writable.
        """

        return False

    def handle_connect(self):
        """
        Ignore connect events (not very useful on datagram socket).
        """

        pass

    def handle_read(self):
        """
        Handle receipt of a datagram.
        """

        data = self.recv(512)
        self.server.notify(data)

    def cleanup(self):
        """
        Clean up this dispatcher's socket.
        """

        self.close()
        try:
            os.unlink(self.sockname)
        except:
            pass

    def log(self, msg):
        """
        Intercept asyncore's logging.
        """

        self.server.logger.info(msg)

    def log_info(self, msg, tag = "info"):
        """
        Intercept asyncore's logging.
        """

        self.server.logger.info("asyncore: %s: %s", tag, msg)

    def handle_error(self):
        """
        Handle errors caught by asyncore main loop.
        """

        self.server.logger.exception("[Unhandled exception]")
        self.server.logger.critical("[Exiting after unhandled exception]")
        sys.exit(1)


def hostport_tag():
    """
    Construct hostname/address + port when we're running under a
    protocol we understand well enough to do that.  This is all
    kludgery.  Just grit your teeth, or perhaps just close your eyes.
    """

    proto = None

    if proto is None:
        try:
            host, port = socket.fromfd(0, socket.AF_INET, socket.SOCK_STREAM).getpeername()
            proto = "tcp"
        except:
            pass

    if proto is None:
        try:
            host, port = socket.fromfd(0, socket.AF_INET6, socket.SOCK_STREAM).getpeername()[0:2]
            proto = "tcp"
        except:
            pass

    if proto is None:
        try:
            host, port = os.environ["SSH_CONNECTION"].split()[0:2]
            proto = "ssh"
        except:
            pass

    if proto is None:
        try:
            host, port = os.environ["REMOTE_HOST"], os.getenv("REMOTE_PORT")
            proto = "ssl"
        except:
            pass

    if proto is None:
        return ""
    elif not port:
        return "/%s/%s" % (proto, host)
    elif ":" in host:
        return "/%s/%s.%s" % (proto, host, port)
    else:
        return "/%s/%s:%s" % (proto, host, port)


def server_main(args):
    """
    Implement the server side of the rpkk-router protocol.  Other than
    one PF_UNIX socket inode, this doesn't write anything to disk, so it
    can be run with minimal privileges.  Most of the work has already
    been done by the database generator, so all this server has to do is
    pass the results along to a client.
    """

    logger = logging.LoggerAdapter(logging.root, dict(connection = hostport_tag()))

    logger.debug("[Starting]")

    if args.rpki_rtr_dir:
        try:
            os.chdir(args.rpki_rtr_dir)
        except OSError, e:
            sys.exit(e)

    kickme = None
    try:
        server = rpki.rtr.server.ServerChannel(logger = logger, refresh = args.refresh, retry = args.retry, expire = args.expire)
        kickme = rpki.rtr.server.KickmeChannel(server = server)
        asyncore.loop(timeout = None)
        signal.signal(signal.SIGINT, signal.SIG_IGN) # Theorized race condition
    except KeyboardInterrupt:
        sys.exit(0)
    finally:
        signal.signal(signal.SIGINT, signal.SIG_IGN) # Observed race condition
        if kickme is not None:
            kickme.cleanup()


def listener_main(args):
    """
    Totally insecure TCP listener for rpki-rtr protocol.  We only
    implement this because it's all that the routers currently support.
    In theory, we will all be running TCP-AO in the future, at which
    point this listener will go away or become a TCP-AO listener.
    """

    # Perhaps we should daemonize?  Deal with that later.

    # server_main() handles args.rpki_rtr_dir.

    listener = None
    try:
        listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    except:
        if listener is not None:
            listener.close()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except AttributeError:
        pass
    listener.bind(("", args.port))
    listener.listen(5)
    logging.debug("[Listening on port %s]", args.port)
    while True:
        try:
            s, ai = listener.accept()
        except KeyboardInterrupt:
            sys.exit(0)
        logging.debug("[Received connection from %r]", ai)
        pid = os.fork()
        if pid == 0:
            os.dup2(s.fileno(), 0)      # pylint: disable=E1101
            os.dup2(s.fileno(), 1)      # pylint: disable=E1101
            s.close()
            #os.closerange(3, os.sysconf("SC_OPEN_MAX"))
            server_main(args)
            sys.exit()
        else:
            logging.debug("[Spawned server %d]", pid)
            while True:
                try:
                    pid, status = os.waitpid(0, os.WNOHANG)
                    if pid:
                        logging.debug("[Server %s exited with status 0x%x]", pid, status)
                        continue
                except:
                    pass
                break


def argparse_setup(subparsers):
    """
    Set up argparse stuff for commands in this module.
    """

    # These could have been lambdas, but doing it this way results in
    # more useful error messages on argparse failures.

    def refresh(v):
        return rpki.rtr.pdus.valid_refresh(int(v))

    def retry(v):
        return rpki.rtr.pdus.valid_retry(int(v))

    def expire(v):
        return rpki.rtr.pdus.valid_expire(int(v))

    # Some duplication of arguments here, not enough to be worth huge
    # effort to clean up, worry about it later in any case.

    subparser = subparsers.add_parser("server", description = server_main.__doc__,
                                      help = "RPKI-RTR protocol server")
    subparser.set_defaults(func = server_main, default_log_to = "syslog")
    subparser.add_argument("--refresh", type = refresh, help = "override default refresh timer")
    subparser.add_argument("--retry",   type = retry,   help = "override default retry timer")
    subparser.add_argument("--expire",  type = expire,  help = "override default expire timer")
    subparser.add_argument("rpki_rtr_dir", nargs = "?", help = "directory containing RPKI-RTR database")

    subparser = subparsers.add_parser("listener", description = listener_main.__doc__,
                                      help = "TCP listener for RPKI-RTR protocol server")
    subparser.set_defaults(func = listener_main, default_log_to = "syslog")
    subparser.add_argument("--refresh", type = refresh, help = "override default refresh timer")
    subparser.add_argument("--retry",   type = retry,   help = "override default retry timer")
    subparser.add_argument("--expire",  type = expire,  help = "override default expire timer")
    subparser.add_argument("port",      type = int,     help = "TCP port on which to listen")
    subparser.add_argument("rpki_rtr_dir", nargs = "?", help = "directory containing RPKI-RTR database")
