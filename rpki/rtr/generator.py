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
Database generator for RPKI-RTR server (RFC 6810 et sequalia).
"""

import os
import sys
import glob
import socket
import base64
import random
import logging
import subprocess
import rpki.POW
import rpki.oids
import rpki.rtr.pdus
import rpki.rtr.channels
import rpki.rtr.server

from rpki.rtr.channels import Timestamp

class PrefixPDU(rpki.rtr.pdus.PrefixPDU):
  """
  Object representing one prefix.  This corresponds closely to one PDU
  in the rpki-router protocol, so closely that we use lexical ordering
  of the wire format of the PDU as the ordering for this class.

  This is a virtual class, but the .from_text() constructor
  instantiates the correct concrete subclass (IPv4PrefixPDU or
  IPv6PrefixPDU) depending on the syntax of its input text.
  """

  @staticmethod
  def from_text(version, asn, addr):
    """
    Construct a prefix from its text form.
    """

    cls = IPv6PrefixPDU if ":" in addr else IPv4PrefixPDU
    self = cls(version = version)
    self.asn = long(asn)
    p, l = addr.split("/")
    self.prefix = rpki.POW.IPAddress(p)
    if "-" in l:
      self.prefixlen, self.max_prefixlen = tuple(int(i) for i in l.split("-"))
    else:
      self.prefixlen = self.max_prefixlen = int(l)
    self.announce = 1
    self.check()
    return self

  @staticmethod
  def from_roa(version, asn, prefix_tuple):
    """
    Construct a prefix from a ROA.
    """

    address, length, maxlength = prefix_tuple
    cls = IPv6PrefixPDU if address.version == 6 else IPv4PrefixPDU
    self = cls(version = version)
    self.asn = asn
    self.prefix = address
    self.prefixlen = length
    self.max_prefixlen = length if maxlength is None else maxlength
    self.announce = 1
    self.check()
    return self


class IPv4PrefixPDU(PrefixPDU):
  """
  IPv4 flavor of a prefix.
  """

  pdu_type = 4
  address_byte_count = 4

class IPv6PrefixPDU(PrefixPDU):
  """
  IPv6 flavor of a prefix.
  """

  pdu_type = 6
  address_byte_count = 16

class RouterKeyPDU(rpki.rtr.pdus.RouterKeyPDU):
  """
  Router Key PDU.
  """

  @classmethod
  def from_text(cls, version, asn, gski, key):
    """
    Construct a router key from its text form.
    """

    self = cls(version = version)
    self.asn = long(asn)
    self.ski = base64.urlsafe_b64decode(gski + "=")
    self.key = base64.b64decode(key)
    self.announce = 1
    self.check()
    return self

  @classmethod
  def from_certificate(cls, version, asn, ski, key):
    """
    Construct a router key from a certificate.
    """

    self = cls(version = version)
    self.asn = asn
    self.ski = ski
    self.key = key
    self.announce = 1
    self.check()
    return self


class ROA(rpki.POW.ROA):                # pylint: disable=W0232
  """
  Minor additions to rpki.POW.ROA.
  """

  @classmethod
  def derReadFile(cls, fn):             # pylint: disable=E1002
    self = super(ROA, cls).derReadFile(fn)
    self.extractWithoutVerifying()
    return self

  @property
  def prefixes(self):
    v4, v6 = self.getPrefixes()
    if v4 is not None:
      for p in v4:
        yield p
    if v6 is not None:
      for p in v6:
        yield p

class X509(rpki.POW.X509):              # pylint: disable=W0232
  """
  Minor additions to rpki.POW.X509.
  """

  @property
  def asns(self):
    resources = self.getRFC3779()
    if resources is not None and resources[0] is not None:
      for min_asn, max_asn in resources[0]:
        for asn in xrange(min_asn, max_asn + 1):
          yield asn


class PDUSet(list):
  """
  Object representing a set of PDUs, that is, one versioned and
  (theoretically) consistant set of prefixes and router keys extracted
  from rcynic's output.
  """

  def __init__(self, version):
    assert version in rpki.rtr.pdus.PDU.version_map
    super(PDUSet, self).__init__()
    self.version = version

  @classmethod
  def _load_file(cls, filename, version):
    """
    Low-level method to read PDUSet from a file.
    """

    self = cls(version = version)
    f = open(filename, "rb")
    r = rpki.rtr.channels.ReadBuffer()
    while True:
      p = rpki.rtr.pdus.PDU.read_pdu(r)
      while p is None:
        b = f.read(r.needed())
        if b == "":
          assert r.available() == 0
          return self
        r.put(b)
        p = r.retry()
      assert p.version == self.version
      self.append(p)

  @staticmethod
  def seq_ge(a, b):
    return ((a - b) % (1 << 32)) < (1 << 31)


class AXFRSet(PDUSet):
  """
  Object representing a complete set of PDUs, that is, one versioned
  and (theoretically) consistant set of prefixes and router
  certificates extracted from rcynic's output, all with the announce
  field set.
  """

  @classmethod
  def parse_rcynic(cls, rcynic_dir, version, scan_roas = None, scan_routercerts = None):
    """
    Parse ROAS and router certificates fetched (and validated!) by
    rcynic to create a new AXFRSet.

    In normal operation, we use os.walk() and the rpki.POW library to
    parse these data directly, but we can, if so instructed, use
    external programs instead, for testing, simulation, or to provide
    a way to inject local data.

    At some point the ability to parse these data from external
    programs may move to a separate constructor function, so that we
    can make this one a bit simpler and faster.
    """

    self = cls(version = version)
    self.serial = rpki.rtr.channels.Timestamp.now()

    include_routercerts = RouterKeyPDU.pdu_type in rpki.rtr.pdus.PDU.version_map[version]

    if scan_roas is None or (scan_routercerts is None and include_routercerts):
      for root, dirs, files in os.walk(rcynic_dir):     # pylint: disable=W0612
        for fn in files:
          if scan_roas is None and fn.endswith(".roa"):
            roa = ROA.derReadFile(os.path.join(root, fn))
            asn = roa.getASID()
            self.extend(PrefixPDU.from_roa(version = version, asn = asn, prefix_tuple = prefix_tuple)
                        for prefix_tuple in roa.prefixes)
          if include_routercerts and scan_routercerts is None and fn.endswith(".cer"):
            x = X509.derReadFile(os.path.join(root, fn))
            eku = x.getEKU()
            if eku is not None and rpki.oids.id_kp_bgpsec_router in eku:
              ski = x.getSKI()
              key = x.getPublicKey().derWritePublic()
              self.extend(RouterKeyPDU.from_certificate(version = version, asn = asn, ski = ski, key = key)
                          for asn in x.asns)

    if scan_roas is not None:
      try:
        p = subprocess.Popen((scan_roas, rcynic_dir), stdout = subprocess.PIPE)
        for line in p.stdout:
          line = line.split()
          asn = line[1]
          self.extend(PrefixPDU.from_text(version = version, asn = asn, addr = addr)
                      for addr in line[2:])
      except OSError, e:
        sys.exit("Could not run %s: %s" % (scan_roas, e))

    if include_routercerts and scan_routercerts is not None:
      try:
        p = subprocess.Popen((scan_routercerts, rcynic_dir), stdout = subprocess.PIPE)
        for line in p.stdout:
          line = line.split()
          gski = line[0]
          key  = line[-1]
          self.extend(RouterKeyPDU.from_text(version = version, asn = asn, gski = gski, key = key)
                      for asn in line[1:-1])
      except OSError, e:
        sys.exit("Could not run %s: %s" % (scan_routercerts, e))

    self.sort()
    for i in xrange(len(self) - 2, -1, -1):
      if self[i] == self[i + 1]:
        del self[i + 1]
    return self

  @classmethod
  def load(cls, filename):
    """
    Load an AXFRSet from a file, parse filename to obtain version and serial.
    """

    fn1, fn2, fn3 = os.path.basename(filename).split(".")
    assert fn1.isdigit() and fn2 == "ax" and fn3.startswith("v") and fn3[1:].isdigit()
    version = int(fn3[1:])
    self = cls._load_file(filename, version)
    self.serial = rpki.rtr.channels.Timestamp(fn1)
    return self

  def filename(self):
    """
    Generate filename for this AXFRSet.
    """

    return "%d.ax.v%d" % (self.serial, self.version)

  @classmethod
  def load_current(cls, version):
    """
    Load current AXFRSet.  Return None if can't.
    """

    serial = rpki.rtr.server.read_current(version)[0]
    if serial is None:
      return None
    try:
      return cls.load("%d.ax.v%d" % (serial, version))
    except IOError:
      return None

  def save_axfr(self):
    """
    Write AXFRSet to file with magic filename.
    """

    f = open(self.filename(), "wb")
    for p in self:
      f.write(p.to_pdu())
    f.close()

  def destroy_old_data(self):
    """
    Destroy old data files, presumably because our nonce changed and
    the old serial numbers are no longer valid.
    """

    for i in glob.iglob("*.ix.*.v%d" % self.version):
      os.unlink(i)
    for i in glob.iglob("*.ax.v%d" % self.version):
      if i != self.filename():
        os.unlink(i)

  @staticmethod
  def new_nonce(force_zero_nonce):
    """
    Create and return a new nonce value.
    """

    if force_zero_nonce:
      return 0
    try:
      return int(random.SystemRandom().getrandbits(16))
    except NotImplementedError:
      return int(random.getrandbits(16))

  def mark_current(self, force_zero_nonce = False):
    """
    Save current serial number and nonce, creating new nonce if
    necessary.  Creating a new nonce triggers cleanup of old state, as
    the new nonce invalidates all old serial numbers.
    """

    assert self.version in rpki.rtr.pdus.PDU.version_map
    old_serial, nonce = rpki.rtr.server.read_current(self.version)
    if old_serial is None or self.seq_ge(old_serial, self.serial):
      logging.debug("Creating new nonce and deleting stale data")
      nonce = self.new_nonce(force_zero_nonce)
      self.destroy_old_data()
    rpki.rtr.server.write_current(self.serial, nonce, self.version)

  def save_ixfr(self, other):
    """
    Comparing this AXFRSet with an older one and write the resulting
    IXFRSet to file with magic filename.  Since we store PDUSets
    in sorted order, computing the difference is a trivial linear
    comparison.
    """

    f = open("%d.ix.%d.v%d" % (self.serial, other.serial, self.version), "wb")
    old = other
    new = self
    len_old = len(old)
    len_new = len(new)
    i_old = i_new = 0
    while i_old < len_old and i_new < len_new:
      if old[i_old] < new[i_new]:
        f.write(old[i_old].to_pdu(announce = 0))
        i_old += 1
      elif old[i_old] > new[i_new]:
        f.write(new[i_new].to_pdu(announce = 1))
        i_new += 1
      else:
        i_old += 1
        i_new += 1
    for i in xrange(i_old, len_old):
      f.write(old[i].to_pdu(announce = 0))
    for i in xrange(i_new, len_new):
      f.write(new[i].to_pdu(announce = 1))
    f.close()

  def show(self):
    """
    Print this AXFRSet.
    """

    logging.debug("# AXFR %d (%s) v%d", self.serial, self.serial, self.version)
    for p in self:
      logging.debug(p)


class IXFRSet(PDUSet):
  """
  Object representing an incremental set of PDUs, that is, the
  differences between one versioned and (theoretically) consistant set
  of prefixes and router certificates extracted from rcynic's output
  and another, with the announce fields set or cleared as necessary to
  indicate the changes.
  """

  @classmethod
  def load(cls, filename):
    """
    Load an IXFRSet from a file, parse filename to obtain version and serials.
    """

    fn1, fn2, fn3, fn4 = os.path.basename(filename).split(".")
    assert fn1.isdigit() and fn2 == "ix" and fn3.isdigit() and fn4.startswith("v") and fn4[1:].isdigit()
    version = int(fn4[1:])
    self = cls._load_file(filename, version)
    self.from_serial = rpki.rtr.channels.Timestamp(fn3)
    self.to_serial = rpki.rtr.channels.Timestamp(fn1)
    return self

  def filename(self):
    """
    Generate filename for this IXFRSet.
    """

    return "%d.ix.%d.v%d" % (self.to_serial, self.from_serial, self.version)

  def show(self):
    """
    Print this IXFRSet.
    """

    logging.debug("# IXFR %d (%s) -> %d (%s) v%d",
                  self.from_serial, self.from_serial,
                  self.to_serial,   self.to_serial,
                  self.version)
    for p in self:
      logging.debug(p)


def kick_all(serial):
  """
  Kick any existing server processes to wake them up.
  """

  try:
    os.stat(rpki.rtr.server.kickme_dir)
  except OSError:
    logging.debug('# Creating directory "%s"', rpki.rtr.server.kickme_dir)
    os.makedirs(rpki.rtr.server.kickme_dir)

  msg = "Good morning, serial %d is ready" % serial
  sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
  for name in glob.iglob("%s.*" % rpki.rtr.server.kickme_base):
    try:
      logging.debug("# Kicking %s", name)
      sock.sendto(msg, name)
    except socket.error:
      try:
        logging.exception("# Failed to kick %s, probably dead socket, attempting cleanup", name)
        os.unlink(name)
      except Exception, e:
        logging.exception("# Couldn't unlink suspected dead socket %s: %s", name, e)
    except Exception, e:
      logging.warning("# Failed to kick %s and don't understand why: %s", name, e)
  sock.close()


def cronjob_main(args):
  """
  Run this right after running rcynic to wade through the ROAs and
  router certificates that rcynic collects and translate that data
  into the form used in the rpki-router protocol.  Output is an
  updated database containing both full dumps (AXFR) and incremental
  dumps against a specific prior version (IXFR).  After updating the
  database, kicks any active servers, so that they can notify their
  clients that a new version is available.
  """

  if args.rpki_rtr_dir:
    try:
      if not os.path.isdir(args.rpki_rtr_dir):
        os.makedirs(args.rpki_rtr_dir)
      os.chdir(args.rpki_rtr_dir)
    except OSError, e:
      logging.critical(str(e))
      sys.exit(1)

  for version in sorted(rpki.rtr.server.PDU.version_map.iterkeys(), reverse = True):

    logging.debug("# Generating updates for protocol version %d", version)

    old_ixfrs = glob.glob("*.ix.*.v%d" % version)

    current = rpki.rtr.server.read_current(version)[0]
    cutoff = Timestamp.now(-(24 * 60 * 60))
    for f in glob.iglob("*.ax.v%d" % version):
      t = Timestamp(int(f.split(".")[0]))
      if  t < cutoff and t != current:
        logging.debug("# Deleting old file %s, timestamp %s", f, t)
        os.unlink(f)

    pdus = rpki.rtr.generator.AXFRSet.parse_rcynic(args.rcynic_dir, version, args.scan_roas, args.scan_routercerts)
    if pdus == rpki.rtr.generator.AXFRSet.load_current(version):
      logging.debug("# No change, new serial not needed")
      continue
    pdus.save_axfr()
    for axfr in glob.iglob("*.ax.v%d" % version):
      if axfr != pdus.filename():
        pdus.save_ixfr(rpki.rtr.generator.AXFRSet.load(axfr))
    pdus.mark_current(args.force_zero_nonce)

    logging.debug("# New serial is %d (%s)", pdus.serial, pdus.serial)

    rpki.rtr.generator.kick_all(pdus.serial)

    old_ixfrs.sort()
    for ixfr in old_ixfrs:
      try:
        logging.debug("# Deleting old file %s", ixfr)
        os.unlink(ixfr)
      except OSError:
        pass


def show_main(args):
  """
  Display current rpki-rtr server database in textual form.
  """

  if args.rpki_rtr_dir:
    try:
      os.chdir(args.rpki_rtr_dir)
    except OSError, e:
      sys.exit(e)

  g = glob.glob("*.ax.v*")
  g.sort()
  for f in g:
    rpki.rtr.generator.AXFRSet.load(f).show()

  g = glob.glob("*.ix.*.v*")
  g.sort()
  for f in g:
    rpki.rtr.generator.IXFRSet.load(f).show()

def argparse_setup(subparsers):
  """
  Set up argparse stuff for commands in this module.
  """

  subparser = subparsers.add_parser("cronjob", description = cronjob_main.__doc__,
                                    help = "Generate RPKI-RTR database from rcynic output")
  subparser.set_defaults(func = cronjob_main, default_log_to = "syslog")
  subparser.add_argument("--scan-roas", help = "specify an external scan_roas program")
  subparser.add_argument("--scan-routercerts", help = "specify an external scan_routercerts program")
  subparser.add_argument("--force_zero_nonce", action = "store_true", help = "force nonce value of zero")
  subparser.add_argument("rcynic_dir", help = "directory containing validated rcynic output tree")
  subparser.add_argument("rpki_rtr_dir", nargs = "?", help = "directory containing RPKI-RTR database")

  subparser = subparsers.add_parser("show", description = show_main.__doc__,
                                    help = "Display content of RPKI-RTR database")
  subparser.set_defaults(func = show_main, default_log_to = "stderr")
  subparser.add_argument("rpki_rtr_dir", nargs = "?", help = "directory containing RPKI-RTR database")
