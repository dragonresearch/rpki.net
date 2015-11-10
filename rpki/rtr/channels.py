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
I/O system of RPKI-RTR protocol implementation.
"""

import os
import sys
import time
import fcntl
import errno
import logging
import asyncore
import asynchat
import rpki.rtr.pdus


class Timestamp(int):
    """
    Wrapper around time module.
    """

    def __new__(cls, t):
        # __new__() is a static method, not a class method, hence the odd calling sequence.
        return super(Timestamp, cls).__new__(cls, t)

    @classmethod
    def now(cls, delta = 0):
        return cls(time.time() + delta)

    def __str__(self):
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self))


class ReadBuffer(object):
    """
    Wrapper around synchronous/asynchronous read state.

    This also handles tracking the current protocol version,
    because it has to go somewhere and there's no better place.
    """

    def __init__(self):
        self.buffer = ""
        self.version = None

    def update(self, need, callback):
        """
        Update count of needed bytes and callback, then dispatch to callback.
        """

        self.need = need
        self.callback = callback
        return self.retry()

    def retry(self):
        """
        Try dispatching to the callback again.
        """

        return self.callback(self)

    def available(self):
        """
        How much data do we have available in this buffer?
        """

        return len(self.buffer)

    def needed(self):
        """
        How much more data does this buffer need to become ready?
        """

        return self.need - self.available()

    def ready(self):
        """
        Is this buffer ready to read yet?
        """

        return self.available() >= self.need

    def get(self, n):
        """
        Hand some data to the caller.
        """

        b = self.buffer[:n]
        self.buffer = self.buffer[n:]
        return b

    def put(self, b):
        """
        Accumulate some data.
        """

        self.buffer += b

    def check_version(self, version):
        """
        Track version number of PDUs read from this buffer.
        Once set, the version must not change.
        """

        if self.version is not None and version != self.version:
            raise rpki.rtr.pdus.CorruptData(
                "Received PDU version %d, expected %d" % (version, self.version))
        if self.version is None and version not in rpki.rtr.pdus.PDU.version_map:
            raise rpki.rtr.pdus.UnsupportedProtocolVersion(
                "Received PDU version %s, known versions %s" % (
                    version, ", ".join(str(v) for v in rpki.rtr.pdus.PDU.version_map)))
        self.version = version


class PDUChannel(asynchat.async_chat, object):
    """
    asynchat subclass that understands our PDUs.  This just handles
    network I/O.  Specific engines (client, server) should be subclasses
    of this with methods that do something useful with the resulting
    PDUs.
    """

    def __init__(self, root_pdu_class, sock = None):
        asynchat.async_chat.__init__(self, sock)            # Old-style class, can't use super()
        self.reader = ReadBuffer()
        assert issubclass(root_pdu_class, rpki.rtr.pdus.PDU)
        self.root_pdu_class = root_pdu_class

    @property
    def version(self):
        return self.reader.version

    @version.setter
    def version(self, version):
        self.reader.check_version(version)

    def start_new_pdu(self):
        """
        Start read of a new PDU.
        """

        try:
            p = self.root_pdu_class.read_pdu(self.reader)
            while p is not None:
                self.deliver_pdu(p)
                p = self.root_pdu_class.read_pdu(self.reader)
        except rpki.rtr.pdus.PDUException, e:
            self.push_pdu(e.make_error_report(version = self.version))
            self.close_when_done()
        else:
            assert not self.reader.ready()
            self.set_terminator(self.reader.needed())

    def collect_incoming_data(self, data):
        """
        Collect data into the read buffer.
        """

        self.reader.put(data)

    def found_terminator(self):
        """
        Got requested data, see if we now have a PDU.  If so, pass it
        along, then restart cycle for a new PDU.
        """

        p = self.reader.retry()
        if p is None:
            self.set_terminator(self.reader.needed())
        else:
            self.deliver_pdu(p)
            self.start_new_pdu()

    def push_pdu(self, pdu):
        """
        Write PDU to stream.
        """

        try:
            self.push(pdu.to_pdu())
        except OSError, e:
            if e.errno != errno.EAGAIN:
                raise

    def log(self, msg):
        """
        Intercept asyncore's logging.
        """

        logging.info(msg)

    def log_info(self, msg, tag = "info"):
        """
        Intercept asynchat's logging.
        """

        logging.info("asynchat: %s: %s", tag, msg)

    def handle_error(self):
        """
        Handle errors caught by asyncore main loop.
        """

        logging.exception("[Unhandled exception]")
        logging.critical("[Exiting after unhandled exception]")
        sys.exit(1)

    def init_file_dispatcher(self, fd):
        """
        Kludge to plug asyncore.file_dispatcher into asynchat.  Call from
        subclass's __init__() method, after calling
        PDUChannel.__init__(), and don't read this on a full stomach.
        """

        self.connected = True
        self._fileno = fd
        self.socket = asyncore.file_wrapper(fd)
        self.add_channel()
        flags = fcntl.fcntl(fd, fcntl.F_GETFL, 0)
        flags = flags | os.O_NONBLOCK
        fcntl.fcntl(fd, fcntl.F_SETFL, flags)

    def handle_close(self):
        """
        Exit when channel closed.
        """

        asynchat.async_chat.handle_close(self)
        sys.exit(0)
