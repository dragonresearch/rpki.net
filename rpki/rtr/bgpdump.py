# $Id$
#
# Copyright (C) 2015--2016  Parsons Government Services ("PARSONS")
# Portions copyright (C) 2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2009--2013  Internet Systems Consortium ("ISC")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND PARSONS, DRL, AND ISC DISCLAIM
# ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL
# PARSONS, DRL, OR ISC BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
# CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
# OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
# WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""
rpki-rtr simulation code using bgpdump as an input source.  Test
purposes only, not included in the normal rpki-rtr program.
"""

import sys
import os
import time
import glob
import logging
import asyncore
import subprocess
import bisect
import rpki.POW
import rpki.oids
import rpki.rtr.pdus
import rpki.rtr.server
import rpki.rtr.generator

from rpki.rtr.channels import Timestamp


class IgnoreThisRecord(Exception):
    pass


class PrefixPDU(rpki.rtr.generator.PrefixPDU):

    @staticmethod
    def from_bgpdump(line, rib_dump):
        try:
            assert isinstance(rib_dump, bool)
            fields = line.split("|")

            # Parse prefix, including figuring out IP protocol version
            cls = rpki.rtr.generator.IPv6PrefixPDU if ":" in fields[5] else rpki.rtr.generator.IPv4PrefixPDU
            self = cls(version = min(rpki.rtr.pdus.PDU.version_map))
            self.timestamp = Timestamp(fields[1])
            p, l = fields[5].split("/")
            self.prefix = rpki.POW.IPAddress(p)
            self.prefixlen = self.max_prefixlen = int(l)

            # Withdrawals don't have AS paths, so be careful
            assert fields[2] == "B" if rib_dump else fields[2] in ("A", "W")
            if fields[2] == "W":
                self.asn = 0
                self.announce = 0
            else:
                self.announce = 1
                if not fields[6] or "{" in fields[6] or "(" in fields[6]:
                    raise IgnoreThisRecord
                a  = fields[6].split()[-1]
                if "." in a:
                    a = [int(s) for s in a.split(".")]
                    if len(a) != 2 or a[0] < 0 or a[0] > 65535 or a[1] < 0 or a[1] > 65535:
                        logging.warn("Bad dotted ASNum %r, ignoring record", fields[6])
                        raise IgnoreThisRecord
                    a = (a[0] << 16) | a[1]
                else:
                    a = int(a)
                self.asn = a

            self.check()
            return self

        except IgnoreThisRecord:
            raise

        except Exception, e:
            logging.warn("Ignoring line %r: %s", line, e)
            raise IgnoreThisRecord


class AXFRSet(rpki.rtr.generator.AXFRSet):

    serial = None

    @staticmethod
    def read_bgpdump(filename):
        assert filename.endswith(".bz2")
        logging.debug("Reading %s", filename)
        bunzip2 = subprocess.Popen(("bzip2", "-c", "-d", filename), stdout = subprocess.PIPE)
        bgpdump = subprocess.Popen(("bgpdump", "-m", "-"), stdin = bunzip2.stdout, stdout = subprocess.PIPE)
        return bgpdump.stdout

    @classmethod
    def parse_bgpdump_rib_dump(cls, filename):
        # pylint: disable=W0201
        assert os.path.basename(filename).startswith("ribs.")
        self = cls(version = min(rpki.rtr.pdus.PDU.version_map))
        self.serial = None
        for line in cls.read_bgpdump(filename):
            try:
                pfx = PrefixPDU.from_bgpdump(line, rib_dump = True)
            except IgnoreThisRecord:
                continue
            self.append(pfx)
            self.serial = pfx.timestamp
        if self.serial is None:
            sys.exit("Failed to parse anything useful from %s" % filename)
        self.sort()
        for i in xrange(len(self) - 2, -1, -1):
            if self[i] == self[i + 1]:
                del self[i + 1]
        return self

    def parse_bgpdump_update(self, filename):
        assert os.path.basename(filename).startswith("updates.")
        for line in self.read_bgpdump(filename):
            try:
                pfx = PrefixPDU.from_bgpdump(line, rib_dump = False)
            except IgnoreThisRecord:
                continue
            announce = pfx.announce
            pfx.announce = 1
            i = bisect.bisect_left(self, pfx)
            if announce:
                if i >= len(self) or pfx != self[i]:
                    self.insert(i, pfx)
            else:
                while i < len(self) and pfx.prefix == self[i].prefix and pfx.prefixlen == self[i].prefixlen:
                    del self[i]
            self.serial = pfx.timestamp


def bgpdump_convert_main(args):
    """
    * DANGER WILL ROBINSON! * DEBUGGING AND TEST USE ONLY! *
    Simulate route origin data from a set of BGP dump files.
    argv is an ordered list of filenames.  Each file must be a BGP RIB
    dumps, a BGP UPDATE dumps, or an AXFR dump in the format written by
    this program's --cronjob command.  The first file must be a RIB dump
    or AXFR dump, it cannot be an UPDATE dump.  Output will be a set of
    AXFR and IXFR files with timestamps derived from the BGP dumps,
    which can be used as input to this program's --server command for
    test purposes.  SUCH DATA PROVIDE NO SECURITY AT ALL.
    * DANGER WILL ROBINSON! * DEBUGGING AND TEST USE ONLY! *
    """

    first = True
    db = None
    axfrs = []
    version = max(rpki.rtr.pdus.PDU.version_map.iterkeys())

    for filename in args.files:

        if ".ax.v" in filename:
            logging.debug("Reading %s", filename)
            db = AXFRSet.load(filename)

        elif os.path.basename(filename).startswith("ribs."):
            db = AXFRSet.parse_bgpdump_rib_dump(filename)
            db.save_axfr()

        elif not first:
            assert db is not None
            db.parse_bgpdump_update(filename)
            db.save_axfr()

        else:
            sys.exit("First argument must be a RIB dump or .ax file, don't know what to do with %s" % filename)

        logging.debug("DB serial now %d (%s)", db.serial, db.serial)
        if first and rpki.rtr.server.read_current(version) == (None, None):
            db.mark_current()
        first = False

        for axfr in axfrs:
            logging.debug("Loading %s", axfr)
            ax = AXFRSet.load(axfr)
            logging.debug("Computing changes from %d (%s) to %d (%s)", ax.serial, ax.serial, db.serial, db.serial)
            db.save_ixfr(ax)
            del ax

        axfrs.append(db.filename())


def bgpdump_select_main(args):
    """
    * DANGER WILL ROBINSON! * DEBUGGING AND TEST USE ONLY! *
    Simulate route origin data from a set of BGP dump files.
    Set current serial number to correspond to an .ax file created by
    converting BGP dump files.  SUCH DATA PROVIDE NO SECURITY AT ALL.
    * DANGER WILL ROBINSON! * DEBUGGING AND TEST USE ONLY! *
    """


    head, sep, tail = os.path.basename(args.ax_file).partition(".")
    if not head.isdigit() or sep != "." or not tail.startswith("ax.v") or not tail[4:].isdigit():
        sys.exit("Argument must be name of a .ax file")

    serial = Timestamp(head)
    version = int(tail[4:])

    if version not in rpki.rtr.pdus.PDU.version_map:
        sys.exit("Unknown protocol version %d" % version)

    nonce = rpki.rtr.server.read_current(version)[1]
    if nonce is None:
        nonce = rpki.rtr.generator.AXFRSet.new_nonce(force_zero_nonce = False)

    rpki.rtr.server.write_current(serial, nonce, version)
    rpki.rtr.generator.kick_all(serial)


class BGPDumpReplayClock(object):
    """
    Internal clock for replaying BGP dump files.

                        * DANGER WILL ROBINSON! *
                     * DEBUGGING AND TEST USE ONLY! *

    This class replaces the normal on-disk serial number mechanism with
    an in-memory version based on pre-computed data.

    bgpdump_server_main() uses this hack to replay historical data for
    testing purposes.  DO NOT USE THIS IN PRODUCTION.

    You have been warned.
    """

    def __init__(self):
        self.timestamps = [Timestamp(int(f.split(".")[0])) for f in glob.iglob("*.ax.v*")]
        self.timestamps.sort()
        self.offset = self.timestamps[0] - int(time.time())
        self.nonce = rpki.rtr.generator.AXFRSet.new_nonce(force_zero_nonce = False)

    def __nonzero__(self):
        return len(self.timestamps) > 0

    def now(self):
        return Timestamp.now(self.offset)

    def read_current(self, version):
        now = self.now()
        while len(self.timestamps) > 1 and now >= self.timestamps[1]:
            del self.timestamps[0]
        return self.timestamps[0], self.nonce

    def siesta(self):
        now = self.now()
        if len(self.timestamps) <= 1:
            return None
        elif now < self.timestamps[1]:
            return self.timestamps[1] - now
        else:
            return 1


def bgpdump_server_main(args):
    """
    Simulate route origin data from a set of BGP dump files.

                        * DANGER WILL ROBINSON! *
                     * DEBUGGING AND TEST USE ONLY! *

    This is a clone of server_main() which replaces the external serial
    number updates triggered via the kickme channel by cronjob_main with
    an internal clocking mechanism to replay historical test data.

    DO NOT USE THIS IN PRODUCTION.

    You have been warned.
    """

    logger = logging.LoggerAdapter(logging.root, dict(connection = rpki.rtr.server.hostport_tag()))

    logger.debug("[Starting]")

    if args.rpki_rtr_dir:
        try:
            os.chdir(args.rpki_rtr_dir)
        except OSError, e:
            sys.exit(e)

    # Yes, this really does replace a global function defined in another
    # module with a bound method to our clock object.  Fun stuff, huh?
    #
    clock = BGPDumpReplayClock()
    rpki.rtr.server.read_current = clock.read_current

    try:
        server = rpki.rtr.server.ServerChannel(logger = logger, refresh = args.refresh, retry = args.retry, expire = args.expire)
        old_serial = server.get_serial()
        logger.debug("[Starting at serial %d (%s)]", old_serial, old_serial)
        while clock:
            new_serial = server.get_serial()
            if old_serial != new_serial:
                logger.debug("[Serial bumped from %d (%s) to %d (%s)]", old_serial, old_serial, new_serial, new_serial)
                server.notify()
                old_serial = new_serial
            asyncore.loop(timeout = clock.siesta(), count = 1)
    except KeyboardInterrupt:
        sys.exit(0)


def argparse_setup(subparsers):
    """
    Set up argparse stuff for commands in this module.
    """

    subparser = subparsers.add_parser("bgpdump-convert", description = bgpdump_convert_main.__doc__,
                                      help = "Convert bgpdump to fake ROAs")
    subparser.set_defaults(func = bgpdump_convert_main, default_log_destination = "syslog")
    subparser.add_argument("files", nargs = "+", help = "input files")

    subparser = subparsers.add_parser("bgpdump-select", description = bgpdump_select_main.__doc__,
                                      help = "Set current serial number for fake ROA data")
    subparser.set_defaults(func = bgpdump_select_main, default_log_destination = "syslog")
    subparser.add_argument("ax_file", help = "name of the .ax to select")

    subparser = subparsers.add_parser("bgpdump-server", description = bgpdump_server_main.__doc__,
                                      help = "Replay fake ROAs generated from historical data")
    subparser.set_defaults(func = bgpdump_server_main, default_log_destination = "syslog")
    subparser.add_argument("rpki_rtr_dir", nargs = "?", help = "directory containing RPKI-RTR database")
