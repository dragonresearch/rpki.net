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
Client implementation for the RPKI-RTR protocol (RFC 6810 et sequalia).
"""

import os
import sys
import base64
import socket
import signal
import logging
import asyncore
import subprocess
import rpki.rtr.pdus
import rpki.rtr.channels

from rpki.rtr.pdus     import ResetQueryPDU, SerialQueryPDU
from rpki.rtr.channels import Timestamp


class PDU(rpki.rtr.pdus.PDU):

    def consume(self, client):
        """
        Handle results in test client.  Default behavior is just to print
        out the PDU; data PDU subclasses may override this.
        """

        logging.debug(self)


clone_pdu = rpki.rtr.pdus.clone_pdu_root(PDU)


@clone_pdu
class SerialNotifyPDU(rpki.rtr.pdus.SerialNotifyPDU):

    def consume(self, client):
        """
        Respond to a SerialNotifyPDU with either a SerialQueryPDU or a
        ResetQueryPDU, depending on what we already know.
        """

        logging.debug(self)
        if client.serial is None or client.nonce != self.nonce:
            client.push_pdu(ResetQueryPDU(version = client.version))
        elif self.serial != client.serial:
            client.push_pdu(SerialQueryPDU(version = client.version,
                                           serial  = client.serial,
                                           nonce   = client.nonce))
        else:
            logging.debug("[Notify did not change serial number, ignoring]")


@clone_pdu
class CacheResponsePDU(rpki.rtr.pdus.CacheResponsePDU):

    def consume(self, client):
        """
        Handle CacheResponsePDU.
        """

        logging.debug(self)
        if self.nonce != client.nonce:
            logging.debug("[Nonce changed, resetting]")
            client.cache_reset()

@clone_pdu
class EndOfDataPDUv0(rpki.rtr.pdus.EndOfDataPDUv0):

    def consume(self, client):
        """
        Handle EndOfDataPDU response.
        """

        logging.debug(self)
        client.end_of_data(self.version, self.serial, self.nonce, self.refresh, self.retry, self.expire)

@clone_pdu
class EndOfDataPDUv1(rpki.rtr.pdus.EndOfDataPDUv1):

    def consume(self, client):
        """
        Handle EndOfDataPDU response.
        """

        logging.debug(self)
        client.end_of_data(self.version, self.serial, self.nonce, self.refresh, self.retry, self.expire)


@clone_pdu
class CacheResetPDU(rpki.rtr.pdus.CacheResetPDU):

    def consume(self, client):
        """
        Handle CacheResetPDU response, by issuing a ResetQueryPDU.
        """

        logging.debug(self)
        client.cache_reset()
        client.push_pdu(ResetQueryPDU(version = client.version))


class PrefixPDU(rpki.rtr.pdus.PrefixPDU):
    """
    Object representing one prefix.  This corresponds closely to one PDU
    in the rpki-router protocol, so closely that we use lexical ordering
    of the wire format of the PDU as the ordering for this class.

    This is a virtual class, but the .from_text() constructor
    instantiates the correct concrete subclass (IPv4PrefixPDU or
    IPv6PrefixPDU) depending on the syntax of its input text.
    """

    def consume(self, client):
        """
        Handle one incoming prefix PDU
        """

        logging.debug(self)
        client.consume_prefix(self)


@clone_pdu
class IPv4PrefixPDU(PrefixPDU, rpki.rtr.pdus.IPv4PrefixPDU):
    pass

@clone_pdu
class IPv6PrefixPDU(PrefixPDU, rpki.rtr.pdus.IPv6PrefixPDU):
    pass

@clone_pdu
class ErrorReportPDU(PDU, rpki.rtr.pdus.ErrorReportPDU):
    pass

@clone_pdu
class RouterKeyPDU(rpki.rtr.pdus.RouterKeyPDU):
    """
    Router Key PDU.
    """

    def consume(self, client):
        """
        Handle one incoming Router Key PDU
        """

        logging.debug(self)
        client.consume_routerkey(self)


class ClientChannel(rpki.rtr.channels.PDUChannel):
    """
    Client protocol engine, handles upcalls from PDUChannel.
    """

    serial   = None
    nonce    = None
    sql      = None
    host     = None
    port     = None
    cache_id = None
    refresh  = rpki.rtr.pdus.default_refresh
    retry    = rpki.rtr.pdus.default_retry
    expire   = rpki.rtr.pdus.default_expire
    updated  = Timestamp(0)

    def __init__(self, sock, proc, killsig, args, host = None, port = None):
        self.killsig = killsig
        self.proc = proc
        self.args = args
        self.host = args.host if host is None else host
        self.port = args.port if port is None else port
        super(ClientChannel, self).__init__(sock = sock, root_pdu_class = PDU)
        if args.force_version is not None:
            self.version = args.force_version
        self.start_new_pdu()
        if args.sql_database:
            self.setup_sql()

    @classmethod
    def ssh(cls, args):
        """
        Set up ssh connection and start listening for first PDU.
        """

        if args.port is None:
            argv = ("ssh", "-s", args.host, "rpki-rtr")
        else:
            argv = ("ssh", "-p", args.port, "-s", args.host, "rpki-rtr")
        logging.debug("[Running ssh: %s]", " ".join(argv))
        s = socket.socketpair()
        return cls(sock = s[1],
                   proc = subprocess.Popen(argv, executable = "/usr/bin/ssh",
                                           stdin = s[0], stdout = s[0], close_fds = True),
                   killsig = signal.SIGKILL, args = args)

    @classmethod
    def tcp(cls, args):
        """
        Set up TCP connection and start listening for first PDU.
        """

        logging.debug("[Starting raw TCP connection to %s:%s]", args.host, args.port)
        try:
            addrinfo = socket.getaddrinfo(args.host, args.port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.error, e:
            logging.debug("[socket.getaddrinfo() failed: %s]", e)
        else:
            for ai in addrinfo:
                af, socktype, proto, cn, sa = ai                # pylint: disable=W0612
                logging.debug("[Trying addr %s port %s]", sa[0], sa[1])
                try:
                    s = socket.socket(af, socktype, proto)
                except socket.error, e:
                    logging.debug("[socket.socket() failed: %s]", e)
                    continue
                try:
                    s.connect(sa)
                except socket.error, e:
                    logging.exception("[socket.connect() failed: %s]", e)
                    s.close()
                    continue
                return cls(sock = s, proc = None, killsig = None, args = args)
        sys.exit(1)

    @classmethod
    def loopback(cls, args):
        """
        Set up loopback connection and start listening for first PDU.
        """

        s = socket.socketpair()
        logging.debug("[Using direct subprocess kludge for testing]")
        argv = (sys.executable, sys.argv[0], "server")
        return cls(sock = s[1],
                   proc = subprocess.Popen(argv, stdin = s[0], stdout = s[0], close_fds = True),
                   killsig = signal.SIGINT, args = args,
                   host = args.host or "none", port = args.port or "none")

    @classmethod
    def tls(cls, args):
        """
        Set up TLS connection and start listening for first PDU.

        NB: This uses OpenSSL's "s_client" command, which does not
        check server certificates properly, so this is not suitable for
        production use.  Fixing this would be a trivial change, it just
        requires using a client program which does check certificates
        properly (eg, gnutls-cli, or stunnel's client mode if that works
        for such purposes this week).
        """

        argv = ("openssl", "s_client", "-tls1", "-quiet", "-connect", "%s:%s" % (args.host, args.port))
        logging.debug("[Running: %s]", " ".join(argv))
        s = socket.socketpair()
        return cls(sock = s[1],
                   proc = subprocess.Popen(argv, stdin = s[0], stdout = s[0], close_fds = True),
                   killsig = signal.SIGKILL, args = args)

    def setup_sql(self):
        """
        Set up an SQLite database to contain the table we receive.  If
        necessary, we will create the database.
        """

        import sqlite3
        missing = not os.path.exists(self.args.sql_database)
        self.sql = sqlite3.connect(self.args.sql_database, detect_types = sqlite3.PARSE_DECLTYPES)
        self.sql.text_factory = str
        cur = self.sql.cursor()
        cur.execute("PRAGMA foreign_keys = on")
        if missing:
            cur.execute('''
                CREATE TABLE cache (
                        cache_id        INTEGER PRIMARY KEY NOT NULL,
                        host            TEXT NOT NULL,
                        port            TEXT NOT NULL,
                        version         INTEGER,
                        nonce           INTEGER,
                        serial          INTEGER,
                        updated         INTEGER,
                        refresh         INTEGER,
                        retry           INTEGER,
                        expire          INTEGER,
                        UNIQUE          (host, port))''')
            cur.execute('''
                CREATE TABLE prefix (
                        cache_id        INTEGER NOT NULL
                                        REFERENCES cache(cache_id)
                                        ON DELETE CASCADE
                                        ON UPDATE CASCADE,
                        asn             INTEGER NOT NULL,
                        prefix          TEXT NOT NULL,
                        prefixlen       INTEGER NOT NULL,
                        max_prefixlen   INTEGER NOT NULL,
                        UNIQUE          (cache_id, asn, prefix, prefixlen, max_prefixlen))''')
            cur.execute('''
                CREATE TABLE routerkey (
                        cache_id        INTEGER NOT NULL
                                        REFERENCES cache(cache_id)
                                        ON DELETE CASCADE
                                        ON UPDATE CASCADE,
                        asn             INTEGER NOT NULL,
                        ski             TEXT NOT NULL,
                        key             TEXT NOT NULL,
                        UNIQUE          (cache_id, asn, ski),
                        UNIQUE          (cache_id, asn, key))''')
        elif self.args.reset_session:
            cur.execute("DELETE FROM cache WHERE host = ? and port = ?", (self.host, self.port))
        cur.execute("SELECT cache_id, version, nonce, serial, refresh, retry, expire, updated "
                    "FROM cache WHERE host = ? AND port = ?",
                    (self.host, self.port))
        try:
            self.cache_id, version, self.nonce, self.serial, refresh, retry, expire, updated = cur.fetchone()
            if version is not None and self.version is not None and version != self.version:
                cur.execute("DELETE FROM cache WHERE host = ? and port = ?", (self.host, self.port))
                raise TypeError                 # Simulate lookup failure case
            if version is not None:
                self.version = version
            if refresh is not None:
                self.refresh = refresh
            if retry is not None:
                self.retry = retry
            if expire is not None:
                self.expire = expire
            if updated is not None:
                self.updated = Timestamp(updated)
        except TypeError:
            cur.execute("INSERT INTO cache (host, port) VALUES (?, ?)", (self.host, self.port))
            self.cache_id = cur.lastrowid
        self.sql.commit()
        logging.info("[Session %d version %s nonce %s serial %s refresh %s retry %s expire %s updated %s]",
                     self.cache_id, self.version, self.nonce,
                     self.serial, self.refresh, self.retry, self.expire, self.updated)

    def cache_reset(self):
        """
        Handle CacheResetPDU actions.
        """

        self.serial = None
        if self.sql:
            cur = self.sql.cursor()
            cur.execute("DELETE FROM prefix WHERE cache_id = ?", (self.cache_id,))
            cur.execute("DELETE FROM routerkey WHERE cache_id = ?", (self.cache_id,))
            cur.execute("UPDATE cache SET version = ?, serial = NULL WHERE cache_id = ?", (self.version, self.cache_id))
            self.sql.commit()

    def end_of_data(self, version, serial, nonce, refresh, retry, expire):
        """
        Handle EndOfDataPDU actions.
        """

        assert version == self.version
        self.serial  = serial
        self.nonce   = nonce
        self.refresh = refresh
        self.retry   = retry
        self.expire  = expire
        self.updated = Timestamp.now()
        if self.sql:
            self.sql.execute("UPDATE cache SET"
                             " version = ?, serial = ?, nonce  = ?,"
                             " refresh = ?, retry  = ?, expire = ?,"
                             " updated = ? "
                             "WHERE cache_id = ?",
                             (version, serial, nonce, refresh, retry, expire, int(self.updated), self.cache_id))
            self.sql.commit()

    def consume_prefix(self, prefix):
        """
        Handle one prefix PDU.
        """

        if self.sql:
            values = (self.cache_id, prefix.asn, str(prefix.prefix), prefix.prefixlen, prefix.max_prefixlen)
            if prefix.announce:
                self.sql.execute("INSERT INTO prefix (cache_id, asn, prefix, prefixlen, max_prefixlen) "
                                 "VALUES (?, ?, ?, ?, ?)",
                                 values)
            else:
                self.sql.execute("DELETE FROM prefix "
                                 "WHERE cache_id = ? AND asn = ? AND prefix = ? AND prefixlen = ? AND max_prefixlen = ?",
                                 values)

    def consume_routerkey(self, routerkey):
        """
        Handle one Router Key PDU.
        """

        if self.sql:
            values = (self.cache_id, routerkey.asn,
                      base64.urlsafe_b64encode(routerkey.ski).rstrip("="),
                      base64.b64encode(routerkey.key))
            if routerkey.announce:
                self.sql.execute("INSERT INTO routerkey (cache_id, asn, ski, key) "
                                 "VALUES (?, ?, ?, ?)",
                                 values)
            else:
                self.sql.execute("DELETE FROM routerkey "
                                 "WHERE cache_id = ? AND asn = ? AND (ski = ? OR key = ?)",
                                 values)

    def deliver_pdu(self, pdu):
        """
        Handle received PDU.
        """

        pdu.consume(self)

    def push_pdu(self, pdu):
        """
        Log outbound PDU then write it to stream.
        """

        logging.debug(pdu)
        super(ClientChannel, self).push_pdu(pdu)

    def cleanup(self):
        """
        Force clean up this client's child process.  If everything goes
        well, child will have exited already before this method is called,
        but we may need to whack it with a stick if something breaks.
        """

        if self.proc is not None and self.proc.returncode is None:
            try:
                os.kill(self.proc.pid, self.killsig)
            except OSError:
                pass

    def handle_close(self):
        """
        Intercept close event so we can log it, then shut down.
        """

        logging.debug("Server closed channel")
        super(ClientChannel, self).handle_close()


# Hack to let us subclass this from scripts without needing to rewrite client_main().

ClientChannelClass = ClientChannel

def client_main(args):
    """
    Test client, intended primarily for debugging.
    """

    logging.debug("[Startup]")

    assert issubclass(ClientChannelClass, ClientChannel)
    constructor = getattr(ClientChannelClass, args.protocol)

    client = None
    try:
        client = constructor(args)

        polled = client.updated
        wakeup = None

        while True:

            now = Timestamp.now()

            if client.serial is not None and now > client.updated + client.expire:
                logging.info("[Expiring client data: serial %s, last updated %s, expire %s]",
                             client.serial, client.updated, client.expire)
                client.cache_reset()

            if client.serial is None or client.nonce is None:
                polled = now
                client.push_pdu(ResetQueryPDU(version = client.version))

            elif now >= client.updated + client.refresh:
                polled = now
                client.push_pdu(SerialQueryPDU(version = client.version,
                                               serial  = client.serial,
                                               nonce   = client.nonce))

            remaining = 1

            while remaining > 0:
                now = Timestamp.now()
                timer = client.retry if (now >= client.updated + client.refresh) else client.refresh
                wokeup = wakeup
                wakeup = max(now, Timestamp(max(polled, client.updated) + timer))
                remaining = wakeup - now
                if wakeup != wokeup:
                    logging.info("[Last client poll %s, next %s]", polled, wakeup)
                asyncore.loop(timeout = remaining, count = 1)

    except KeyboardInterrupt:
        sys.exit(0)

    finally:
        if client is not None:
            client.cleanup()


def argparse_setup(subparsers):
    """
    Set up argparse stuff for commands in this module.
    """

    subparser = subparsers.add_parser("client", description = client_main.__doc__,
                                      help = "Test client for RPKI-RTR protocol")
    subparser.set_defaults(func = client_main, default_log_destination = "stderr")
    subparser.add_argument("--sql-database", help = "filename for sqlite3 database of client state")
    subparser.add_argument("--force-version", type = int, choices = PDU.version_map, help = "force specific protocol version")
    subparser.add_argument("--reset-session", action = "store_true", help = "reset any existing session found in sqlite3 database")
    subparser.add_argument("protocol", choices = ("loopback", "tcp", "ssh", "tls"), help = "connection protocol")
    subparser.add_argument("host", nargs = "?", help = "server host")
    subparser.add_argument("port", nargs = "?", help = "server port")
    return subparser
