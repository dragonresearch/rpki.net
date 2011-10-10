#!/usr/bin/env python

# Router origin-authentication rpki-router protocol implementation.  See
# draft-ietf-sidr-rpki-rtr in fine Internet-Draft repositories near you.
# 
# Run the program with the --help argument for usage information, or see
# documentation for the *_main() functions.
#
# 
# $Id$
# 
# Copyright (C) 2009-2011  Internet Systems Consortium ("ISC")
# 
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

import sys, os, struct, time, glob, socket, fcntl, signal, syslog, errno
import asyncore, asynchat, subprocess, traceback, getopt, bisect, random

# Debugging only, should be False in production
disable_incrementals = False

# Whether to log backtraces
backtrace_on_exceptions = False

class IgnoreThisRecord(Exception):
  pass


class timestamp(int):
  """
  Wrapper around time module.
  """

  def __new__(cls, x):
    return int.__new__(cls, x)

  @classmethod
  def now(cls, delta = 0):
    return cls(time.time() + delta)

  def __str__(self):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self))


class ipaddr(object):
  """
  IP addresses.
  """

  def __init__(self, string = None, value = None):
    assert (string is None) != (value is None)
    if string is not None:
      value = socket.inet_pton(self.af, string)
    assert len(value) == self.size
    self.value = value

  def __str__(self):
    return socket.inet_ntop(self.af, self.value)

  def __cmp__(self, other):
    return cmp(self.value, other.value)

class v4addr(ipaddr):
  af = socket.AF_INET
  size = 4

class v6addr(ipaddr):
  af = socket.AF_INET6
  size = 16


def read_current():
  """
  Read current serial number and nonce.  Return None for both if
  serial and nonce not recorded.  For backwards compatibility, treat
  file containing just a serial number as having a nonce of zero.
  """
  try:
    f = open("current", "r")
    values = tuple(int(s) for s in f.read().split())
    f.close()
    return values[0], values[1]
  except IndexError:
    return values[0], 0
  except IOError:
    return None, None

def write_current(serial, nonce):
  """
  Write serial number and nonce.
  """
  tmpfn = "current.%d.tmp" % os.getpid()
  try:
    f = open(tmpfn, "w")
    f.write("%d %d\n" % (serial, nonce))
    f.close()
    os.rename(tmpfn, "current")
  finally:
    try:
      os.unlink(tmpfn)
    except:
      pass


def new_nonce():
  """
  Create and return a new nonce value.
  """
  if force_zero_nonce:
    return 0
  try:
    return int(random.SystemRandom().getrandbits(16))
  except NotImplementedError:
    return int(random.getrandbits(16))


class read_buffer(object):
  """
  Wrapper around synchronous/asynchronous read state.
  """

  def __init__(self):
    self.buffer = ""

  def update(self, need, callback):
    """
    Update count of needed bytes and callback, then dispatch to callback.
    """
    self.need = need
    self.callback = callback
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

  def retry(self):
    """
    Try dispatching to the callback again.
    """
    return self.callback(self)

class pdu(object):
  """
  Object representing a generic PDU in the rpki-router protocol.
  Real PDUs are subclasses of this class.
  """

  version = 0                           # Protocol version

  _pdu = None                           # Cached when first generated

  header_struct = struct.Struct("!BBHL")

  def __cmp__(self, other):
    return cmp(self.to_pdu(), other.to_pdu())

  def check(self):
    """
    Check attributes to make sure they're within range.
    """
    pass

  @classmethod
  def read_pdu(cls, reader):
    return reader.update(need = cls.header_struct.size, callback = cls.got_header)

  @classmethod
  def got_header(cls, reader):
    if not reader.ready():
      return None
    assert reader.available() >= cls.header_struct.size
    version, pdu_type, whatever, length = cls.header_struct.unpack(reader.buffer[:cls.header_struct.size])
    assert version == cls.version, "PDU version is %d, expected %d" % (version, cls.version)
    assert length >= 8
    self = cls.pdu_map[pdu_type]()
    return reader.update(need = length, callback = self.got_pdu)

  def consume(self, client):
    """
    Handle results in test client.  Default behavior is just to print
    out the PDU.
    """
    blather(self)

  def send_file(self, server, filename):
    """
    Send a content of a file as a cache response.  Caller should catch IOError.
    """
    f = open(filename, "rb")
    server.push_pdu(cache_response(nonce = server.current_nonce))
    server.push_file(f)
    server.push_pdu(end_of_data(serial = server.current_serial, nonce = server.current_nonce))

  def send_nodata(self, server):
    """
    Send a nodata error.
    """
    server.push_pdu(error_report(errno = error_report.codes["No Data Available"], errpdu = self))

class pdu_with_serial(pdu):
  """
  Base class for PDUs consisting of just a serial number and nonce.
  """

  header_struct = struct.Struct("!BBHLL")

  def __init__(self, serial = None, nonce = None):
    if serial is not None:
      assert isinstance(serial, int)
      self.serial = serial
    if nonce is not None:
      assert isinstance(nonce, int)
      self.nonce = nonce

  def __str__(self):
    return "[%s, serial #%d nonce %d]" % (self.__class__.__name__, self.serial, self.nonce)

  def to_pdu(self):
    """
    Generate the wire format PDU.
    """
    if self._pdu is None:
      self._pdu = self.header_struct.pack(self.version, self.pdu_type, self.nonce, self.header_struct.size, self.serial)
    return self._pdu

  def got_pdu(self, reader):
    if not reader.ready():
      return None
    b = reader.get(self.header_struct.size)
    version, pdu_type, self.nonce, length, self.serial = self.header_struct.unpack(b)
    assert length == 12
    assert b == self.to_pdu()
    return self

class pdu_nonce(pdu):
  """
  Base class for PDUs consisting of just a nonce.
  """

  header_struct = struct.Struct("!BBHL")

  def __init__(self, nonce = None):
    if nonce is not None:
      assert isinstance(nonce, int)
      self.nonce = nonce

  def __str__(self):
    return "[%s, nonce %d]" % (self.__class__.__name__, self.nonce)

  def to_pdu(self):
    """
    Generate the wire format PDU.
    """
    if self._pdu is None:
      self._pdu = self.header_struct.pack(self.version, self.pdu_type, self.nonce, self.header_struct.size)
    return self._pdu

  def got_pdu(self, reader):
    if not reader.ready():
      return None
    b = reader.get(self.header_struct.size)
    version, pdu_type, self.nonce, length = self.header_struct.unpack(b)
    assert length == 8
    assert b == self.to_pdu()
    return self

class pdu_empty(pdu):
  """
  Base class for empty PDUs.
  """

  header_struct = struct.Struct("!BBHL")

  def __str__(self):
    return "[%s]" % self.__class__.__name__

  def to_pdu(self):
    """
    Generate the wire format PDU for this prefix.
    """
    if self._pdu is None:
      self._pdu = self.header_struct.pack(self.version, self.pdu_type, 0, self.header_struct.size)
    return self._pdu

  def got_pdu(self, reader):
    if not reader.ready():
      return None
    b = reader.get(self.header_struct.size)
    version, pdu_type, zero, length = self.header_struct.unpack(b)
    assert zero == 0
    assert length == 8
    assert b == self.to_pdu()
    return self

class serial_notify(pdu_with_serial):
  """
  Serial Notify PDU.
  """

  pdu_type = 0

  def consume(self, client):
    """
    Respond to a serial_notify message with either a serial_query or
    reset_query, depending on what we already know.
    """
    blather(self)
    if client.current_serial is None or client.current_nonce != self.nonce:
      client.push_pdu(reset_query())
    elif self.serial != client.current_serial:
      client.push_pdu(serial_query(serial = client.current_serial, nonce = client.current_nonce))
    else:
      blather("[Notify did not change serial number, ignoring]")

class serial_query(pdu_with_serial):
  """
  Serial Query PDU.
  """

  pdu_type = 1

  def serve(self, server):
    """
    Received a serial query, send incremental transfer in response.
    If client is already up to date, just send an empty incremental
    transfer.
    """
    blather(self)
    if server.get_serial() is None:
      self.send_nodata(server)
    elif server.current_nonce != self.nonce:
      log("[Client requested wrong nonce, resetting client]")
      server.push_pdu(cache_reset())
    elif server.current_serial == self.serial:
      blather("[Client is already current, sending empty IXFR]")
      server.push_pdu(cache_response(nonce = server.current_nonce))
      server.push_pdu(end_of_data(serial = server.current_serial, nonce = server.current_nonce))
    elif disable_incrementals:
      server.push_pdu(cache_reset())
    else:
      try:
        self.send_file(server, "%d.ix.%d" % (server.current_serial, self.serial))
      except IOError:
        server.push_pdu(cache_reset())

class reset_query(pdu_empty):
  """
  Reset Query PDU.
  """

  pdu_type = 2

  def serve(self, server):
    """
    Received a reset query, send full current state in response.
    """
    blather(self)
    if server.get_serial() is None:
      self.send_nodata(server)
    else:
      try:
        fn = "%d.ax" % server.current_serial
        self.send_file(server, fn)
      except IOError:
        server.push_pdu(error_report(errno = error_report.codes["Internal Error"], errpdu = self, errmsg = "Couldn't open %s" % fn))

class cache_response(pdu_nonce):
  """
  Incremental Response PDU.
  """

  pdu_type = 3

class end_of_data(pdu_with_serial):
  """
  End of Data PDU.
  """

  pdu_type = 7

  def consume(self, client):
    """
    Handle end_of_data response.
    """
    blather(self)
    client.current_serial = self.serial
    client.current_nonce  = self.nonce

class cache_reset(pdu_empty):
  """
  Cache reset PDU.
  """

  pdu_type = 8

  def consume(self, client):
    """
    Handle cache_reset response, by issuing a reset_query.
    """
    blather(self)
    client.push_pdu(reset_query())

class prefix(pdu):
  """
  Object representing one prefix.  This corresponds closely to one PDU
  in the rpki-router protocol, so closely that we use lexical ordering
  of the wire format of the PDU as the ordering for this class.

  This is a virtual class, but the .from_text() constructor
  instantiates the correct concrete subclass (ipv4_prefix or
  ipv6_prefix) depending on the syntax of its input text.
  """

  header_struct = struct.Struct("!BB2xLBBBx")
  asnum_struct = struct.Struct("!L")

  @staticmethod
  def from_text(asnum, addr):
    """
    Construct a prefix from its text form.
    """
    cls = ipv6_prefix if ":" in addr else ipv4_prefix
    self = cls()
    self.asn = long(asnum)
    p, l = addr.split("/")
    self.prefix = self.addr_type(string = p)
    if "-" in l:
      self.prefixlen, self.max_prefixlen = tuple(int(i) for i in l.split("-"))
    else:
      self.prefixlen = self.max_prefixlen = int(l)
    self.announce = 1
    self.check()
    return self
    
  def __str__(self):
    plm = "%s/%s-%s" % (self.prefix, self.prefixlen, self.max_prefixlen)
    return "%s %8s  %-32s %s" % ("+" if self.announce else "-", self.asn, plm, ":".join(("%02X" % ord(b) for b in self.to_pdu())))

  def show(self):
    blather("# Class:        %s" % self.__class__.__name__)
    blather("# ASN:          %s" % self.asn)
    blather("# Prefix:       %s" % self.prefix)
    blather("# Prefixlen:    %s" % self.prefixlen)
    blather("# MaxPrefixlen: %s" % self.max_prefixlen)
    blather("# Announce:     %s" % self.announce)

  def check(self):
    """
    Check attributes to make sure they're within range.
    """
    assert self.announce in (0, 1)
    assert self.prefixlen >= 0 and self.prefixlen <= self.addr_type.size * 8
    assert self.max_prefixlen >= self.prefixlen and self.max_prefixlen <= self.addr_type.size * 8
    pdulen = self.header_struct.size + self.addr_type.size + self.asnum_struct.size
    assert len(self.to_pdu()) == pdulen, "Expected %d byte PDU, got %d" % pd(pdulen, len(self.to_pdu()))

  def to_pdu(self, announce = None):
    """
    Generate the wire format PDU for this prefix.
    """
    if announce is not None:
      assert announce in (0, 1)
    elif self._pdu is not None:
      return self._pdu
    pdulen = self.header_struct.size + self.addr_type.size + self.asnum_struct.size
    pdu = (self.header_struct.pack(self.version, self.pdu_type, pdulen,
                                   announce if announce is not None else self.announce,
                                   self.prefixlen, self.max_prefixlen) +
           self.prefix.value +
           self.asnum_struct.pack(self.asn))
    if announce is None:
      assert self._pdu is None
      self._pdu = pdu
    return pdu

  def got_pdu(self, reader):
    if not reader.ready():
      return None
    b1 = reader.get(self.header_struct.size)
    b2 = reader.get(self.addr_type.size)
    b3 = reader.get(self.asnum_struct.size)
    version, pdu_type, length, self.announce, self.prefixlen, self.max_prefixlen = self.header_struct.unpack(b1)
    assert length == len(b1) + len(b2) + len(b3)
    self.prefix = self.addr_type(value = b2)
    self.asn = self.asnum_struct.unpack(b3)[0]
    assert b1 + b2 + b3 == self.to_pdu()
    return self

  @staticmethod
  def from_bgpdump(line, rib_dump):
    try:
      assert isinstance(rib_dump, bool)
      fields = line.split("|")

      # Parse prefix, including figuring out IP protocol version
      cls = ipv6_prefix if ":" in fields[5] else ipv4_prefix
      self = cls()
      self.timestamp = timestamp(fields[1])
      p, l = fields[5].split("/")
      self.prefix = self.addr_type(p)
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
            log("Bad dotted ASNum %r, ignoring record" % fields[6])
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
      log("Ignoring line %r: %s" % (line, e))
      raise IgnoreThisRecord

class ipv4_prefix(prefix):
  """
  IPv4 flavor of a prefix.
  """
  pdu_type = 4
  addr_type = v4addr

class ipv6_prefix(prefix):
  """
  IPv6 flavor of a prefix.
  """
  pdu_type = 6
  addr_type = v6addr

class error_report(pdu):
  """
  Error Report PDU.
  """

  pdu_type = 10

  header_struct = struct.Struct("!BBHL")
  string_struct = struct.Struct("!L")

  errors = {
    2 : "No Data Available" }

  fatal = {
    0 : "Corrupt Data",
    1 : "Internal Error",
    3 : "Invalid Request",
    4 : "Unsupported Protocol Version",
    5 : "Unsupported PDU Type",
    6 : "Withdrawal of Unknown Record",
    7 : "Duplicate Announcement Received" }

  assert set(errors).isdisjoint(set(fatal))

  errors.update(fatal)

  codes = dict((v, k) for k, v in errors.items())

  def __init__(self, errno = None, errpdu = None, errmsg = None):
    assert errno is None or errno in self.errors
    self.errno = errno
    self.errpdu = errpdu
    self.errmsg = errmsg if errmsg is not None or errno is None else self.errors[errno]

  def __str__(self):
    return "[%s, error #%s: %r]" % (self.__class__.__name__, self.errno, self.errmsg)

  def to_counted_string(self, s):
    return self.string_struct.pack(len(s)) + s

  def read_counted_string(self, reader, remaining):
    assert remaining >= self.string_struct.size
    n = self.string_struct.unpack(reader.get(self.string_struct.size))[0]
    assert remaining >= self.string_struct.size + n
    return n, reader.get(n), (remaining - self.string_struct.size - n)

  def to_pdu(self):
    """
    Generate the wire format PDU for this prefix.
    """
    if self._pdu is None:
      assert isinstance(self.errno, int)
      assert not isinstance(self.errpdu, error_report)
      p = self.errpdu
      if p is None:
        p = ""
      elif isinstance(p, pdu):
        p = p.to_pdu()
      assert isinstance(p, str)
      pdulen = self.header_struct.size + self.string_struct.size * 2 + len(p) + len(self.errmsg)
      self._pdu = self.header_struct.pack(self.version, self.pdu_type, self.errno, pdulen)
      self._pdu += self.to_counted_string(p)
      self._pdu += self.to_counted_string(self.errmsg.encode("utf8"))
    return self._pdu

  def got_pdu(self, reader):
    if not reader.ready():
      return None
    header = reader.get(self.header_struct.size)
    version, pdu_type, self.errno, length = self.header_struct.unpack(header)
    remaining = length - self.header_struct.size
    self.pdulen, self.errpdu, remaining = self.read_counted_string(reader, remaining)
    self.errlen, self.errmsg, remaining = self.read_counted_string(reader, remaining)
    assert length == self.header_struct.size + self.string_struct.size * 2 + self.pdulen + self.errlen
    assert header + self.to_counted_string(self.errpdu) + self.to_counted_string(self.errmsg.encode("utf8")) == self.to_pdu()
    return self

  def serve(self, server):
    """
    Received an error_report from client.  Not much we can do beyond
    logging it, then killing the connection if error was fatal.
    """
    log(self)
    if self.errno in self.fatal:
      log("[Shutting down due to reported fatal protocol error]")
      sys.exit(1)

pdu.pdu_map = dict((p.pdu_type, p) for p in (ipv4_prefix, ipv6_prefix, serial_notify, serial_query, reset_query,
                                             cache_response, end_of_data, cache_reset, error_report))

class prefix_set(list):
  """
  Object representing a set of prefixes, that is, one versioned and
  (theoretically) consistant set of prefixes extracted from rcynic's
  output.
  """

  @classmethod
  def _load_file(cls, filename):
    """
    Low-level method to read prefix_set from a file.
    """
    self = cls()
    f = open(filename, "rb")
    r = read_buffer()
    while True:
      p = pdu.read_pdu(r)
      while p is None:
        b = f.read(r.needed())
        if b == "":
          assert r.available() == 0
          return self
        r.put(b)
        p = r.retry()
      self.append(p)

  @staticmethod
  def seq_ge(a, b):
    return ((a - b) % (1 << 32)) < (1 << 31)


class axfr_set(prefix_set):
  """
  Object representing a complete set of prefixes, that is, one
  versioned and (theoretically) consistant set of prefixes extracted
  from rcynic's output, all with the announce field set.
  """

  xargs_count = 500

  @classmethod
  def parse_rcynic(cls, rcynic_dir):
    """
    Parse ROAS fetched (and validated!) by rcynic to create a new
    axfr_set.  We use the scan_roas utility to parse the ASN.1.  We
    used to parse ROAs internally, but that made this program depend
    on all of the complex stuff for building Python extensions, which
    is way over the top for a relying party tool.

    """
    self = cls()
    self.serial = timestamp.now()
    roa_files = []
    try:
      p = subprocess.Popen((scan_roas, rcynic_dir), stdout = subprocess.PIPE)
      for line in p.stdout:
        line = line.split()
        asn = line[1]
        self.extend(prefix.from_text(asn, addr) for addr in line[2:])
    except OSError, e:
      sys.exit("Could not run %s, check your $PATH variable? (%s)" % (scan_roas, e))
    self.sort()
    for i in xrange(len(self) - 2, -1, -1):
      if self[i] == self[i + 1]:
        del self[i + 1]
    return self

  @classmethod
  def load(cls, filename):
    """
    Load an axfr_set from a file, parse filename to obtain serial.
    """
    fn1, fn2 = os.path.basename(filename).split(".")
    assert fn1.isdigit() and fn2 == "ax"
    self = cls._load_file(filename)
    self.serial = timestamp(fn1)
    return self

  def filename(self):
    """
    Generate filename for this axfr_set.
    """
    return "%d.ax" % self.serial

  @classmethod
  def load_current(cls):
    """
    Load current axfr_set.  Return None if can't.
    """
    serial = read_current()[0]
    if serial is None:
      return None
    try:
      return cls.load("%d.ax" % serial)
    except IOError:
      return None

  def save_axfr(self):
    """
    Write axfr__set to file with magic filename.
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
    for i in glob.iglob("*.ix.*"):
      os.unlink(i)
    for i in glob.iglob("*.ax"):
      if i != self.filename():
        os.unlink(i)

  def mark_current(self):
    """
    Save current serial number and nonce, creating new nonce if
    necessary.  Creating a new nonce triggers cleanup of old state, as
    the new nonce invalidates all old serial numbers.
    """
    old_serial, nonce = read_current()
    if old_serial is None or self.seq_ge(old_serial, self.serial):
      blather("Creating new nonce and deleting stale data")
      nonce = new_nonce()
      self.destroy_old_data()
    write_current(self.serial, nonce)

  def save_ixfr(self, other):
    """
    Comparing this axfr_set with an older one and write the resulting
    ixfr_set to file with magic filename.  Since we store prefix_sets
    in sorted order, computing the difference is a trivial linear
    comparison.
    """
    f = open("%d.ix.%d" % (self.serial, other.serial), "wb")
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
    Print this axfr_set.
    """
    blather("# AXFR %d (%s)" % (self.serial, self.serial))
    for p in self:
      blather(p)

  @staticmethod
  def read_bgpdump(filename):
    assert filename.endswith(".bz2")
    blather("Reading %s" % filename)
    bunzip2 = subprocess.Popen(("bzip2", "-c", "-d", filename), stdout = subprocess.PIPE)
    bgpdump = subprocess.Popen(("bgpdump", "-m", "-"), stdin = bunzip2.stdout, stdout = subprocess.PIPE)
    return bgpdump.stdout

  @classmethod
  def parse_bgpdump_rib_dump(cls, filename):
    assert os.path.basename(filename).startswith("ribs.")
    self = cls()
    for line in cls.read_bgpdump(filename):
      try:
        pfx = prefix.from_bgpdump(line, rib_dump = True)
      except IgnoreThisRecord:
        continue
      self.append(pfx)
      self.serial = pfx.timestamp
    self.sort()
    for i in xrange(len(self) - 2, -1, -1):
      if self[i] == self[i + 1]:
        del self[i + 1]
    return self

  def parse_bgpdump_update(self, filename):
    assert os.path.basename(filename).startswith("updates.")
    for line in self.read_bgpdump(filename):
      try:
        pfx = prefix.from_bgpdump(line, rib_dump = False)
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

class ixfr_set(prefix_set):
  """
  Object representing an incremental set of prefixes, that is, the
  differences between one versioned and (theoretically) consistant set
  of prefixes extracted from rcynic's output and another, with the
  announce fields set or cleared as necessary to indicate the changes.
  """

  @classmethod
  def load(cls, filename):
    """
    Load an ixfr_set from a file, parse filename to obtain serials.
    """
    fn1, fn2, fn3 = os.path.basename(filename).split(".")
    assert fn1.isdigit() and fn2 == "ix" and fn3.isdigit()
    self = cls._load_file(filename)
    self.from_serial = timestamp(fn3)
    self.to_serial = timestamp(fn1)
    return self

  def filename(self):
    """
    Generate filename for this ixfr_set.
    """
    return "%d.ix.%d" % (self.to_serial, self.from_serial)

  def show(self):
    """
    Print this ixfr_set.
    """
    blather("# IXFR %d (%s) -> %d (%s)" % (self.from_serial, self.from_serial,
                                           self.to_serial,   self.to_serial))
    for p in self:
      blather(p)

class file_producer(object):
  """
  File-based producer object for asynchat.
  """

  def __init__(self, handle, buffersize):
    self.handle = handle
    self.buffersize = buffersize

  def more(self):
    return self.handle.read(self.buffersize)

class pdu_channel(asynchat.async_chat):
  """
  asynchat subclass that understands our PDUs.  This just handles
  network I/O.  Specific engines (client, server) should be subclasses
  of this with methods that do something useful with the resulting
  PDUs.
  """

  def __init__(self, conn = None):
    asynchat.async_chat.__init__(self, conn)
    self.reader = read_buffer()

  def start_new_pdu(self):
    """
    Start read of a new PDU.
    """
    p = pdu.read_pdu(self.reader)
    while p is not None:
      self.deliver_pdu(p)
      p = pdu.read_pdu(self.reader)
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

  def push_file(self, f):
    """
    Write content of a file to stream.
    """
    try:
      self.push_with_producer(file_producer(f, self.ac_out_buffer_size))
    except OSError, e:
      if e.errno != errno.EAGAIN:
        raise

  def log(self, msg):
    """
    Intercept asyncore's logging.
    """
    log(msg)

  def log_info(self, msg, tag = "info"):
    """
    Intercept asynchat's logging.
    """
    log("asynchat: %s: %s" % (tag, msg))

  def handle_error(self):
    """
    Handle errors caught by asyncore main loop.
    """
    if backtrace_on_exceptions:
      for line in traceback.format_exc().splitlines():
        log(line)
    else:
      log("[Exception: %s]" % sys.exc_info()[1])
    log("[Exiting after unhandled exception]")
    sys.exit(1)

  def init_file_dispatcher(self, fd):
    """
    Kludge to plug asyncore.file_dispatcher into asynchat.  Call from
    subclass's __init__() method, after calling
    pdu_channel.__init__(), and don't read this on a full stomach.
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

class server_write_channel(pdu_channel):
  """
  Kludge to deal with ssh's habit of sometimes (compile time option)
  invoking us with two unidirectional pipes instead of one
  bidirectional socketpair.  All the server logic is in the
  server_channel class, this class just deals with sending the
  server's output to a different file descriptor.
  """

  def __init__(self):
    """
    Set up stdout.
    """
    pdu_channel.__init__(self)
    self.init_file_dispatcher(sys.stdout.fileno())

  def readable(self):
    """
    This channel is never readable.
    """
    return False

class server_channel(pdu_channel):
  """
  Server protocol engine, handles upcalls from pdu_channel to
  implement protocol logic.
  """

  def __init__(self):
    """
    Set up stdin and stdout as connection and start listening for
    first PDU.
    """
    pdu_channel.__init__(self)
    self.init_file_dispatcher(sys.stdin.fileno())
    self.writer = server_write_channel()
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
    self.current_serial, self.current_nonce = read_current()
    return self.current_serial

  def check_serial(self):
    """
    Check for a new serial number.
    """
    old_serial = self.current_serial
    return old_serial != self.get_serial()

  def notify(self, data = None):
    """
    Cronjob instance kicked us, send a notify message.
    """
    if self.check_serial() is not None:
      self.push_pdu(serial_notify(serial = self.current_serial, nonce = self.current_nonce))
    else:
      log("Cronjob kicked me without a valid current serial number")

class client_channel(pdu_channel):
  """
  Client protocol engine, handles upcalls from pdu_channel.
  """

  current_serial = None
  current_nonce  = None

  def __init__(self, sock, proc, killsig):
    self.killsig = killsig
    self.proc = proc
    pdu_channel.__init__(self, conn = sock)
    self.start_new_pdu()

  @classmethod
  def ssh(cls, host, port):
    """
    Set up ssh connection and start listening for first PDU.
    """
    args = ("ssh", "-p", port, "-s", host, "rpki-rtr")
    blather("[Running ssh: %s]" % " ".join(args))
    s = socket.socketpair()
    return cls(sock = s[1],
               proc = subprocess.Popen(args, executable = "/usr/bin/ssh", stdin = s[0], stdout = s[0], close_fds = True),
               killsig = signal.SIGKILL)

  @classmethod
  def tcp(cls, host, port):
    """
    Set up TCP connection and start listening for first PDU.
    """
    blather("[Starting raw TCP connection to %s:%s]" % (host, port))
    s = socket.socket()
    s.connect((host, int(port)))
    return cls(sock = s, proc = None, killsig = None)

  @classmethod
  def loopback(cls):
    """
    Set up loopback connection and start listening for first PDU.
    """
    s = socket.socketpair()
    blather("[Using direct subprocess kludge for testing]")
    argv = [sys.executable, sys.argv[0], "--server"]
    if "--syslog" in sys.argv:
      argv.extend(("--syslog", sys.argv[sys.argv.index("--syslog") + 1]))
    return cls(sock = s[1],
               proc = subprocess.Popen(argv, stdin = s[0], stdout = s[0], close_fds = True),
               killsig = signal.SIGINT)

  def deliver_pdu(self, pdu):
    """
    Handle received PDU.
    """
    pdu.consume(self)

  def push_pdu(self, pdu):
    """
    Log outbound PDU then write it to stream.
    """
    blather(pdu)
    pdu_channel.push_pdu(self, pdu)

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
    blather("Server closed channel")
    pdu_channel.handle_close(self)

class kickme_channel(asyncore.dispatcher):
  """
  asyncore dispatcher for the PF_UNIX socket that cronjob mode uses to
  kick servers when it's time to send notify PDUs to clients.
  """

  def __init__(self, server):
    asyncore.dispatcher.__init__(self)
    self.server = server
    self.sockname = "%s.%d" % (kickme_base, os.getpid())
    self.create_socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
      self.bind(self.sockname)
      os.chmod(self.sockname, 0660)
    except socket.error, e:
      log("Couldn't bind() kickme socket: %r" % e)
      self.close()
    except OSError, e:
      log("Couldn't chmod() kickme socket: %r" % e)

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
    log(msg)

  def log_info(self, msg, tag = "info"):
    """
    Intercept asyncore's logging.
    """
    log("asyncore: %s: %s" % (tag, msg))

  def handle_error(self):
    """
    Handle errors caught by asyncore main loop.
    """
    if backtrace_on_exceptions:
      for line in traceback.format_exc().splitlines():
        log(line)
    else:
      log("[Exception: %s]" % sys.exc_info()[1])
    log("[Exiting after unhandled exception]")
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


def kick_all(serial):
  """
  Kick any existing server processes to wake them up.
  """

  try:
    os.stat(kickme_dir)
  except OSError:
    blather('# Creating directory "%s"' % kickme_dir)
    os.makedirs(kickme_dir)

  msg = "Good morning, serial %d is ready" % serial
  sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
  for name in glob.iglob("%s.*" % kickme_base):
    try:
      blather("# Kicking %s" % name)
      sock.sendto(msg, name)
    except:
      log("# Failed to kick %s" % name)
  sock.close()

def cronjob_main(argv):
  """
  Run this mode right after rcynic to do the real work of groveling
  through the ROAs that rcynic collects and translating that data into
  the form used in the rpki-router protocol.  This mode prepares both
  full dumps (AXFR) and incremental dumps against a specific prior
  version (IXFR).  [Terminology here borrowed from DNS, as is much of
  the protocol design.]  Finally, this mode kicks any active servers,
  so that they can notify their clients that a new version is
  available.

  Run this in the directory where you want to write its output files,
  which should also be the directory in which you run this program in
  --server mode.

  This mode takes one argument on the command line, which specifies
  the directory name of rcynic's authenticated output tree (normally
  $somewhere/rcynic-data/authenticated/).
  """

  if len(argv) != 1:
    sys.exit("Expected one argument, got %r" % (argv,))

  old_ixfrs = glob.glob("*.ix.*")

  current = read_current()[0]
  cutoff = timestamp.now(-(24 * 60 * 60))
  for f in glob.iglob("*.ax"):
    t = timestamp(int(f.split(".")[0]))
    if  t < cutoff and t != current:
      blather("# Deleting old file %s, timestamp %s" % (f, t))
      os.unlink(f)
  
  pdus = axfr_set.parse_rcynic(argv[0])
  if pdus == axfr_set.load_current():
    blather("# No change, new version not needed")
    sys.exit()
  pdus.save_axfr()
  for axfr in glob.iglob("*.ax"):
    if axfr != pdus.filename():
      pdus.save_ixfr(axfr_set.load(axfr))
  pdus.mark_current()

  blather("# New serial is %d (%s)" % (pdus.serial, pdus.serial))

  kick_all(pdus.serial)

  old_ixfrs.sort()
  for ixfr in old_ixfrs:
    try:
      blather("# Deleting old file %s" % ixfr)
      os.unlink(ixfr)
    except OSError:
      pass

def show_main(argv):
  """
  Display dumps created by --cronjob mode in textual form.
  Intended only for debugging.

  This mode takes no command line arguments.  Run it in the directory
  where you ran --cronjob mode.
  """

  if argv:
    sys.exit("Unexpected arguments: %r" % (argv,))

  g = glob.glob("*.ax")
  g.sort()
  for f in g:
    axfr_set.load(f).show()

  g = glob.glob("*.ix.*")
  g.sort()
  for f in g:
    ixfr_set.load(f).show()

def server_main(argv):
  """
  Implement the server side of the rpkk-router protocol.  Other than
  one PF_UNIX socket inode, this doesn't write anything to disk, so it
  can be run with minimal privileges.  Most of the hard work has
  already been done in --cronjob mode, so all that this mode has to do
  is serve up the results.

  In production use this server should run under sshd.  The subsystem
  mechanism in sshd does not allow us to pass arguments on the command
  line, so setting this up might require a wrapper script, but in
  production use you will probably want to lock down the public key
  used to authenticate the ssh session so that it can only run this
  one command, in which case you can just specify the full command
  including any arguments in the authorized_keys file.

  Unless you do something special, sshd will have this program running
  in whatever it thinks is the home directory associated with the
  username given in the ssh prototocol setup, so it may be easiest to
  set this up so that the home directory sshd puts this program into
  is the one where --cronjob left its files for this mode to pick up.

  This mode must be run in the directory where you ran --cronjob mode.

  This mode takes one optional argument: if provided, the argument is
  the name of a directory to which the program should chdir() on
  startup; this may simplify setup when running under inetd.

  The server is event driven, so everything interesting happens in the
  channel classes.
  """

  blather("[Starting]")
  if len(argv) > 1:
    sys.exit("Unexpected arguments: %r" % (argv,))
  if argv:
    try:
      os.chdir(argv[0])
    except OSError, e:
      sys.exit(e)
  kickme = None
  try:
    server = server_channel()
    kickme = kickme_channel(server = server)
    asyncore.loop(timeout = None)
  except KeyboardInterrupt:
    sys.exit(0)
  finally:
    if kickme is not None:
      kickme.cleanup()


def client_main(argv):
  """
  Toy client, intended only for debugging.

  This program takes one or more arguments.  The first argument
  determines what kind of connection it should open to the server, the
  remaining arguments are connection details specific to this
  particular type of connection.

  If the first argument is "loopback", the client will run a copy of
  the server directly in a subprocess, and communicate with it via a
  PF_UNIX socket pair.  This sub-mode takes no further arguments.

  If the first argument is "ssh", the client will attempt to run ssh
  in as subprocess to connect to the server using the ssh subsystem
  mechanism as specified for this protocol.  The remaining arguments
  should be a hostname (or IP address in a form acceptable to ssh) and
  a TCP port number.

  If the first argument is "tcp", the client will attempt to open a
  direct (and completely insecure!) TCP connection to the server.
  The remaining arguments should be a hostname (or IP address) and
  a TCP port number.
  """

  blather("[Startup]")
  client = None
  try:
    if not argv or (argv[0] == "loopback" and len(argv) == 1):
      client = client_channel.loopback()
    elif argv[0] == "ssh" and len(argv) == 3:
      client = client_channel.ssh(*argv[1:])
    elif argv[0] == "tcp" and len(argv) == 3:
      client = client_channel.tcp(*argv[1:])
    else:
      sys.exit("Unexpected arguments: %r" % (argv,))
    while True:
      if client.current_serial is None or client.current_nonce is None:
        client.push_pdu(reset_query())
      else:
        client.push_pdu(serial_query(serial = client.current_serial, nonce = client.current_nonce))
      wakeup = time.time() + 600
      while True:
        remaining = wakeup - time.time()
        if remaining < 0:
          break
        asyncore.loop(timeout = remaining, count = 1)

  except KeyboardInterrupt:
    sys.exit(0)
  finally:
    if client is not None:
      client.cleanup()

def bgpdump_convert_main(argv):
  """
  Simulate route origin data from a set of BGP dump files.

                      * DANGER WILL ROBINSON! *
                   * DEBUGGING AND TEST USE ONLY! *

  argv is an ordered list of filenames.  Each file must be a BGP RIB
  dumps, a BGP UPDATE dumps, or an AXFR dump in the format written by
  this program's --cronjob command.  The first file must be a RIB dump
  or AXFR dump, it cannot be an UPDATE dump.  Output will be a set of
  AXFR and IXFR files with timestamps derived from the BGP dumps,
  which can be used as input to this program's --server command for
  test purposes.  SUCH DATA PROVIDE NO SECURITY AT ALL.

  You have been warned.
  """

  first = True
  db = None
  axfrs = []

  for filename in argv:

    if filename.endswith(".ax"):
      blather("Reading %s" % filename)
      db = axfr_set.load(filename)

    elif os.path.basename(filename).startswith("ribs."):
      db = axfr_set.parse_bgpdump_rib_dump(filename)
      db.save_axfr()

    elif not first:
      assert db is not None
      db.parse_bgpdump_update(filename)
      db.save_axfr()

    else:
      sys.exit("First argument must be a RIB dump or .ax file, don't know what to do with %s" % filename)

    blather("DB serial now %d (%s)" % (db.serial, db.serial))
    if first and read_current() == (None, None):
      db.mark_current()
    first = False

    for axfr in axfrs:
      blather("Loading %s" % axfr)
      ax = axfr_set.load(axfr)
      blather("Computing changes from %d (%s) to %d (%s)" % (ax.serial, ax.serial, db.serial, db.serial))
      db.save_ixfr(ax)
      del ax

    axfrs.append(db.filename())


def bgpdump_select_main(argv):
  """
  Simulate route origin data from a set of BGP dump files.

                      * DANGER WILL ROBINSON! *
                   * DEBUGGING AND TEST USE ONLY! *

  Set current serial number to correspond to an .ax file created by
  converting BGP dump files.  SUCH DATA PROVIDE NO SECURITY AT ALL.

  You have been warned.
  """

  serial = None
  try:
    head, sep, tail = os.path.basename(argv[0]).partition(".")
    if len(argv) == 1 and head.isdigit() and sep == "." and tail == "ax":
      serial = timestamp(head)
  except:
    pass
  if serial is None:
    sys.exit("Argument must be name of a .ax file")

  nonce = read_current()[1]
  if nonce is None:
    nonce = new_nonce()

  write_current(serial, nonce)
  kick_all(serial)


class bgpsec_replay_clock(object):
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
    self.timestamps = [timestamp(int(f.split(".")[0])) for f in glob.iglob("*.ax")]
    self.timestamps.sort()
    self.offset = self.timestamps[0] - int(time.time())
    self.nonce = new_nonce()

  def __nonzero__(self):
    return len(self.timestamps) > 0

  def now(self):
    return timestamp.now(self.offset)

  def read_current(self):
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


def bgpdump_server_main(argv):
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

  blather("[Starting]")
  if len(argv) > 1:
    sys.exit("Unexpected arguments: %r" % (argv,))
  if argv:
    try:
      os.chdir(argv[0])
    except OSError, e:
      sys.exit(e)
  #
  # Yes, this really does replace a global function with a bound
  # method to our clock object.  Fun stuff, huh?
  #
  global read_current
  clock = bgpsec_replay_clock()
  read_current = clock.read_current
  #
  try:
    server = server_channel()
    old_serial = server.get_serial()
    blather("[Starting at serial %d (%s)]" % (old_serial, old_serial))
    while clock:
      new_serial = server.get_serial()
      if old_serial != new_serial:
        blather("[Serial bumped from %d (%s) to %d (%s)]" % (old_serial, old_serial, new_serial, new_serial))
        server.notify()
        old_serial = new_serial
      asyncore.loop(timeout = clock.siesta(), count = 1)
  except KeyboardInterrupt:
    sys.exit(0)


scan_roas = os.path.normpath(os.path.join(sys.path[0], "..", "utils",
                                          "scan_roas", "scan_roas"))
if not os.path.exists(scan_roas):
  scan_roas = "scan_roas"

force_zero_nonce = False

kickme_dir  = "sockets"
kickme_base = os.path.join(kickme_dir, "kickme")

main_dispatch = {
  "cronjob"             : cronjob_main,
  "client"              : client_main,
  "server"              : server_main,
  "show"                : show_main,
  "bgpdump_convert"     : bgpdump_convert_main,
  "bgpdump_select"      : bgpdump_select_main,
  "bgpdump_server"      : bgpdump_server_main }

def usage(msg = None):
  f = sys.stderr if msg else sys.stdout
  f.write("Usage: %s [options] --mode [arguments]\n" % sys.argv[0])
  f.write("\n")
  f.write("where options are zero or more of:\n")
  f.write("\n")
  f.write("--syslog facility.warning_priority[.info_priority]\n")
  f.write("\n")
  f.write("--zero-nonce\n")
  f.write("\n")
  f.write("and --mode is one of:\n")
  f.write("\n")
  for name, func in main_dispatch.iteritems():
    f.write("--%s:\n" % name)
    f.write(func.__doc__)
    f.write("\n")
  sys.exit(msg)

if __name__ == "__main__":

  os.environ["TZ"] = "UTC"
  time.tzset()

  mode = None

  syslog_facility, syslog_warning, syslog_info = syslog.LOG_DAEMON, syslog.LOG_WARNING, syslog.LOG_INFO

  opts, argv = getopt.getopt(sys.argv[1:], "hs:z?", ["help", "syslog=", "zero-nonce"] + main_dispatch.keys())
  for o, a in opts:
    if o in ("-h", "--help", "-?"):
      usage()
    elif o in ("-z", "--zero-nonce"):
      force_zero_nonce = True
    elif o in ("-s", "--syslog"):
      try:
        a = [getattr(syslog, "LOG_" + i.upper()) for i in a.split(".")]
        if len(a) == 2:
          a.append(a[1])
        syslog_facility, syslog_warning, syslog_info = a
        if syslog_facility < 8 or syslog_warning >= 8 or syslog_info >= 8:
          raise ValueError
      except:
        usage("Bad value specified for --syslog option")
    elif len(o) > 2 and o[2:] in main_dispatch:
      if mode is not None:
        sys.exit("Conflicting modes specified")
      mode = o[2:]

  if mode is None:
    usage("No mode specified")

  log_tag = "rtr-origin/" + mode

  if mode in ("server", "bgpdump_server"):
    log_tag += hostport_tag()

  if mode in ("cronjob", "server" , "bgpdump_server"):
    syslog.openlog(log_tag, syslog.LOG_PID, syslog_facility)
    def log(msg):
      return syslog.syslog(syslog_warning, str(msg))
    def blather(msg):
      return syslog.syslog(syslog_info, str(msg))

  elif mode == "show":
    def log(msg):
      try:
        os.write(sys.stdout.fileno(), "%s\n" % msg)
      except OSError, e:
        if e.errno != errno.EPIPE:
          raise
    blather = log

  else:
    def log(msg):
      sys.stderr.write("%s %s[%d]: %s\n" % (time.strftime("%F %T"), log_tag, os.getpid(), msg))
    blather = log

  main_dispatch[mode](argv)
