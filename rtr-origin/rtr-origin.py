"""
Router origin-authentication update job.  Work in progress.

This should be run under cron, after rcynic finishes.  It chews over
the data rcynic collected and generates output suitable as input for a
companion server program (not yet written) which serves the resulting
data to the routers.

$Id$

Copyright (C) 2009  Internet Systems Consortium ("ISC")

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

import sys, os, struct, time, glob, socket, asyncore, asynchat, subprocess, fcntl, signal
import rpki.x509, rpki.ipaddrs, rpki.sundial

os.environ["TZ"] = "UTC"
time.tzset()

class pdu(object):
  """Object representing a generic PDU in the rpki-router protocol.
  Real PDUs are subclasses of this class.
  """

  version = 0                           # Protocol version

  _pdu = None                           # Cached when first generated

  common_header_struct = struct.Struct("!BB")

  def __cmp__(self, other):
    return cmp(self.to_pdu(), other.to_pdu())

  def check(self):
    """Check attributes to make sure they're within range."""
    pass

  @classmethod
  def from_pdu_file(cls, f):
    """Read one wire format PDU from a file.  This is intended to be
    used in an iterator, so it raises StopIteration on end of file.
    """
    assert cls._pdu is None
    b = f.read(cls.common_header_struct.size)
    if b == "":
      raise StopIteration
    version, pdu_type = cls.common_header_struct.unpack(b)
    assert version == cls.version, "PDU version is %d, expected %d" % (version, cls.version)
    self = cls.pdu_map[pdu_type]()
    self.from_pdu_file_helper(f, b)
    self.check()
    return self

  @classmethod
  def initial_asynchat_decoder(cls, chat):
    """Set up initial read for asynchat PDU reader."""
    log("initial_asynchat_decoder()")
    chat.set_terminator(cls.common_header_struct.size)
    chat.set_next_decoder(cls.chat_decode_common_header)

  @classmethod
  def chat_decode_common_header(cls, chat, b):
    """Decode PDU header from an asynchat reader."""
    log("chat_decode_common_header()")
    assert cls._pdu is None
    version, pdu_type = cls.common_header_struct.unpack(b)
    assert version == cls.version, "PDU version is %d, expected %d" % (version, cls.version)
    self = cls.pdu_map[pdu_type]()
    if len(b) >= self.header_struct.size:
      return self.chat_decode_header(chat, b)
    else:
      chat.set_terminator(self.header_struct.size - cls.common_header_struct.size)
      chat.set_next_decoder(self.chat_decode_header)
      return None

class pdu_with_serial(pdu):
  """Base class for PDUs consisting of just a serial number."""

  header_struct = struct.Struct("!BBHL")

  def __str__(self):
    log("__str__()")
    return "#%s" % self.serial

  def to_pdu(self):
    """Generate the wire format PDU for this prefix."""
    if self._pdu is None:
      self._pdu = self.header_struct.pack(self.version, self.pdu_type, 0, self.serial)
    return self._pdu

  def from_pdu_file_helper(self, f, b):
    """Read one wire format prefix PDU from a file."""
    b += f.read(self.header_struct.size - len(b))
    version, pdu_type, zero, self.serial = self.header_struct.unpack(b)
    assert zero == 0
    assert b == self.to_pdu()

  def chat_decode_header(self, chat, b):
    """Decode PDU from an asynchat reader."""
    log("chat_decode_header()")
    version, pdu_type, zero, self.serial = self.header_struct.unpack(b)
    assert zero == 0
    assert b == self.to_pdu()
    return self

class pdu_empty(pdu):
  """Base class for emtpy PDUs."""

  header_struct = struct.Struct("!BBH")

  def to_pdu(self):
    """Generate the wire format PDU for this prefix."""
    if self._pdu is None:
      self._pdu = self.header_struct.pack(self.version, self.pdu_type, 0)
    return self._pdu

  def from_pdu_file_helper(self, f, b):
    """Read one wire format prefix PDU from a file."""
    b += f.read(self.header_struct.size - len(b))
    version, pdu_type, zero = self.header_struct.unpack(b)
    assert zero == 0
    assert b == self.to_pdu()

  def chat_decode_header(self, chat, b):
    """Decode PDU from an asynchat reader."""
    log("chat_decode_header()")
    version, pdu_type, zero = self.header_struct.unpack(b)
    assert zero == 0
    assert b == self.to_pdu()
    return self

class serial_notify(pdu_with_serial):
  """Serial Notify PDU."""
  pdu_type = 0

class serial_query(pdu_with_serial):
  """Serial Query PDU."""
  pdu_type = 1

class reset_query(pdu_empty):
  """Reset Query PDU."""

  pdu_type = 2

  def serve(self, chat):
    """Received a reset query, send full current state in response."""
    f = open("current", "r")
    current = f.read().strip() + ".ax"
    f.close()
    chat.push_file(open(current, "rb"))

class cache_response(pdu_empty):
  """Cache Response PDU."""
  pdu_type = 3

class end_of_data(pdu_with_serial):
  """End of Data PDU."""
  pdu_type = 7

class cache_reset(pdu_empty):
  """Cache reset PDU."""
  pdu_type = 8

class prefix(pdu):
  """Object representing one prefix.  This corresponds closely to one
  PDU in the rpki-router protocol, so closely that we use lexical
  ordering of the wire format of the PDU as the ordering for this
  class.
  """

  source = 0                            # Source (0 == RPKI)

  header_struct = struct.Struct("!BBHBBBB")
  asnum_struct = struct.Struct("!L")

  @classmethod
  def from_asn1(cls, asn, t):
    """Read a prefix from a ROA in the tuple format used by our ASN.1 decoder."""
    x = 0L
    for y in t[0]:
      x = (x << 1) | y
    for y in xrange(cls.addr_type.bits - len(t[0])):
      x = (x << 1)
    self = cls()
    self.asn = asn
    self.prefix = cls.addr_type(x)
    self.prefixlen = len(t[0])
    self.max_prefixlen = self.prefixlen if t[1] is None else t[1]
    self.color = 0
    self.announce = 1
    self.check()
    return self

  def __str__(self):
    log("__str__()")
    plm = "%s/%s-%s" % (self.prefix, self.prefixlen, self.max_prefixlen)
    return "%s %8s  %-32s %s" % ("+" if self.announce else "-", self.asn, plm, ":".join(("%02X" % ord(b) for b in self.to_pdu())))

  def pprint(self):
    print "# Class:       ", self.__class__.__name__
    print "# ASN:         ", self.asn
    print "# Prefix:      ", self.prefix
    print "# Prefixlen:   ", self.prefixlen
    print "# MaxPrefixlen:", self.max_prefixlen
    print "# Color:       ", self.color
    print "# Announce:    ", self.announce

  def check(self):
    """Check attributes to make sure they're within range."""
    assert self.announce in (0, 1)
    assert self.prefixlen >= 0 and self.prefixlen <= self.addr_type.bits
    assert self.max_prefixlen >= self.prefixlen and self.max_prefixlen <= self.addr_type.bits
    assert len(self.to_pdu()) == 12 + self.addr_type.bits / 8, "Expected %d byte PDU, got %d" % (12 + self.addr_type.bits / 8, len(self.to_pdu()))

  def to_pdu(self, announce = None):
    """Generate the wire format PDU for this prefix."""
    if announce is not None:
      assert announce in (0, 1)
    elif self._pdu is not None:
      return self._pdu
    pdu = (self.header_struct.pack(self.version, self.pdu_type, self.color,
                                   announce if announce is not None else self.announce,
                                   self.prefixlen, self.max_prefixlen, self.source) +
           self.prefix.to_bytes() +
           self.asnum_struct.pack(self.asn))
    if announce is None:
      assert self._pdu is None
      self._pdu = pdu
    return pdu

  def from_pdu_file_helper(self, f, b):
    """Read one wire format prefix PDU from a file."""
    b += f.read(self.header_struct.size - len(b))
    p = b
    version, pdu_type, self.color, self.announce, self.prefixlen, self.max_prefixlen, source = self.header_struct.unpack(b)
    assert source == self.source
    b = f.read(self.addr_type.bits / 8)
    p += b
    self.prefix = self.addr_type.from_bytes(b)
    b = f.read(self.asnum_struct.size)
    p += b
    self.asn = self.asnum_struct.unpack(b)[0]
    assert p == self.to_pdu()

  def chat_decode_header(self, chat, b):
    """Decode PDU header from an asynchat reader."""
    log("chat_decode_header()")
    version, pdu_type, self.color, self.announce, self.prefixlen, self.max_prefixlen, source = self.header_struct.unpack(b)
    assert source == self.source
    chat.consume(self.header_struct.size)
    chat.set_terminator(self.addr_type.bits / 8)
    chat.set_next_decoder(self.chat_decode_prefix)
    return None

  def chat_decode_prefix(self, chat, b):
    """Decode prefix from an asynchat reader."""
    log("chat_decode_prefix()")
    self.prefix = self.addr_type.from_bytes(b)
    chat.consume(self.addr_type.bits / 8)
    chat.set_terminator(self.asnum_struct.size)
    chat.set_next_decoder(self.chat_decode_asnum)
    return None

  def chat_decode_asnum(self, chat, b):
    """Decode autonomous system number from an asynchat reader."""
    self.asn = self.asnum_struct.unpack(b)[0]
    return self

class ipv4_prefix(prefix):
  """IPv4 flavor of a prefix."""
  pdu_type = 4
  addr_type = rpki.ipaddrs.v4addr

class ipv6_prefix(prefix):
  """IPv6 flavor of a prefix."""
  pdu_type = 6
  addr_type = rpki.ipaddrs.v6addr

class error_report(pdu):
  """Error Report PDU.  This is kind of painful to parse, an explicit
  count for the encapsulated PDU would simplify this considerably.
  """

  pdu_type = 10

  header_struct = struct.Struct("!BBH")
  errlen_struct = struct.Struct("!B")

  errmsg = ""

  def __str__(self):
    log("__str__()")
    return "#%s: %s" % (self.errno, self.errmsg)

  def to_pdu(self):
    """Generate the wire format PDU for this prefix."""
    if self._pdu is None:
      assert isinstance(self.errno, int)
      assert isinstance(self.errpdu, pdu)
      assert not isinstance(self.errpdu, error_report)
      self._pdu = (self.header_struct.pack(self.version, self.pdu_type, self.errno) +
                   self.errpdu.to_pdu() +
                   self.errlen_struct.pack(len(self.errmsg)) +
                   self.errmsg)
    return self._pdu

  def from_pdu_file_helper(self, f, b):
    """Read one wire format prefix PDU from a file."""
    b += f.read(self.header_struct.size - len(b))
    version, pdu_type, self.errno = self.header_struct.unpack(b)
    self.errpdu = pdu.from_pdu_file(f)
    b = f.read(self.errlen_struct.size)
    n = self.errlen_struct.unpack(b)
    if n:
      self.errmsg = f.read(n)

prefix.afi_map = { "\x00\x01" : ipv4_prefix, "\x00\x02" : ipv6_prefix }

pdu.pdu_map = dict((p.pdu_type, p) for p in (ipv4_prefix, ipv6_prefix, serial_notify, serial_query, reset_query, cache_response, end_of_data, cache_reset, error_report))

class pdufile(file):
  """File subclass with PDU iterator."""

  def __iter__(self):
    return self

  def next(self):
    return pdu.from_pdu_file(self)

class prefix_set(list):
  """Object representing a set of prefixes, that is, one versioned and
  (theoretically) consistant set of prefixes extracted from rcynic's
  output.
  """

  @classmethod
  def parse_rcynic(cls, rcynic_dir):
    """Parse ROAS fetched (and validated!) by rcynic to create a new
    prefix_set.
    """
    self = cls()
    self.serial = rpki.sundial.now().totimestamp()
    for root, dirs, files in os.walk(rcynic_dir):
      for f in files:
        if f.endswith(".roa"):
          roa = rpki.x509.ROA(DER_file = os.path.join(root, f)).extract().get()
          assert roa[0] == 0, "ROA version is %d, expected 0" % roa[0]
          asn = roa[1]
          for afi, addrs in roa[2]:
            for addr in addrs:
              self.append(prefix.afi_map[afi].from_asn1(asn, addr))
    self.sort()
    for i in xrange(len(self) - 2, -1, -1):
      if self[i] == self[i + 1]:
        del self[i + 1]
    return self

  @classmethod
  def _load_file(cls, filename):
    """Low-level method to read prefix_set from a file."""
    self = cls()
    f = pdufile(filename, "rb")
    for p in f:
      self.append(p)
    f.close()
    return self

  @classmethod
  def load_axfr(cls, filename):
    """Load an AXFR-style prefix_set from a file, parse filename to
    obtain serial.
    """
    fn1, fn2 = os.path.basename(filename).split(".")
    assert fn1.isdigit() and fn2 == "ax"
    self = cls._load_file(filename)
    self.serial = int(fn1)
    return self

  @classmethod
  def load_ixfr(cls, filename):
    """Load an IXFR-style prefix_set from a file, parse filename to
    obtain serials.
    """
    fn1, fn2, fn3 = os.path.basename(filename).split(".")
    assert fn1.isdigit() and fn2 == "ix" and fn3.isdigit()
    self = cls._load_file(filename)
    self.from_serial = int(fn3)
    self.to_serial = int(fn1)
    return self

  def save_axfr(self):
    """Write AXFR-style prefix_set to file with magic filename."""
    f = pdufile("%d.ax" % self.serial, "wb")
    for p in self:
      f.write(p.to_pdu())
    f.close()

  def mark_current(self):
    """Mark the current serial number as current."""
    tmpfn = "current.%d.tmp" % os.getpid()
    try:
      f = open(tmpfn, "w")
      f.write("%d\n" % self.serial)
      f.close()
      os.rename(tmpfn, "current")
    except:
      os.unlink(tmpfn)
      raise

  def save_ixfr(self, other):
    """Comparing this prefix_set with an older one and write the
    resulting IXFR-style prefix-set to file with magic filename.
    Since we store prefix_sets in sorted order, computing the
    difference is a trivial linear comparison.
    """
    f = pdufile("%d.ix.%d" % (self.serial, other.serial), "wb")
    old = other[:]
    new = self[:]
    while old and new:
      if old[0] < new[0]:
        f.write(old.pop(0).to_pdu(announce = 0))
      elif old[0] > new[0]:
        f.write(new.pop(0).to_pdu(announce = 1))
      else:
        del old[0]
        del new[0]
    while old:
      f.write(old.pop(0).to_pdu(announce = 0))
    while new:
      f.write(new.pop(0).to_pdu(announce = 1))
    f.close()

def updater_main():
  """Toy version of main program for updater.  This isn't ready for
  real use yet, but does most of the basic operations.  Sending notify
  wakeup calls to server processes is waiting for me to write server
  code for this to talk to.  Still needs cleanup, config file (instead
  of wired in magic filenames), etc.
  """

  axfrs = [prefix_set.load_axfr(f) for f in glob.glob("*.ax")]

  for dir in ("../rcynic/rcynic-data/authenticated", "../rpkid/testbed.dir/rcynic-data/authenticated"):
    p = prefix_set.parse_rcynic(dir)
    p.save_axfr()
    for a in axfrs:
      p.save_ixfr(a)
    p.mark_current()
    axfrs.append(p)
    time.sleep(2)

  ixfrs = [prefix_set.load_ixfr(f) for f in glob.glob("*.ix.*")]

  def pp(serial):
    return "%d (%s)" % (serial, rpki.sundial.datetime.utcfromtimestamp(serial))

  for a in axfrs:
    print "# AXFR", pp(a.serial)
    for p in a:
      print p

  for i in ixfrs:
    print "# IXFR", pp(i.from_serial), "->", pp(i.to_serial)
    for p in i:
      print p

class file_producer(object):
  """File-based producer object for asynchat."""

  def __init__(self, handle, buffersize):
    self.handle = handle
    self.buffersize = buffersize

  def more(self):
    log("more()")
    return self.handle.read(self.buffersize)

class pdu_asynchat(asynchat.async_chat):
  """asynchat subclass that understands our PDUs.  This just handles
  the network I/O.  Specific engines (client, server) should be
  subclasses of this with methods that do something useful with the
  resulting PDUs.
  """

  def start_new_pdu(self):
    """Starting read of a new PDU, set up initial decoder."""
    log("start_new_pdu()")
    self.buffer = ""
    self.next_decoder = None
    pdu.initial_asynchat_decoder(self)
    assert self.next_decoder is not None

  def consume(self, n):
    """Consume n bytes from the input buffer."""
    log("consume()")
    self.buffer = self.buffer[n:]

  def collect_incoming_data(self, data):
    """Collect data into the input buffer."""
    log("collect_incoming_data()")
    self.buffer += data

  def set_next_decoder(self, decoder):
    """Set decoder to use with the next chunk of data."""
    log("set_next_decoder()")
    self.next_decoder = decoder

  def found_terminator(self):
    """Got requested data, hand it to decoder.  If we get back a PDU,
    pass it up, then loop back to listen for another PDU.
    """
    log("found_terminator()")
    pdu = self.next_decoder(self, self.buffer)
    if pdu is not None:
      self.deliver_pdu(pdu)
      self.start_new_pdu()

  def deliver_pdu(self, pdu):
    """Subclass must implement this."""
    raise NotImplementedError

  def push_pdu(self, pdu):
    """Write PDU to asynchat stream."""
    data = pdu.to_pdu()
    log("push_pdu(%d)" % len(data))
    self.push(data)

  def push_file(self, f):
    """Write content of a file to an asynchat stream."""
    log("push_file()")
    self.push_with_producer(file_producer(f, self.ac_out_buffer_size))

  def log(self, message):
    """Intercept asyncore's logging."""
    log_really("asyncore: %s" % message)

  def log_info(self, message, type = "info"):
    """Intercept asyncore's logging."""
    log_really("asyncore[%s]: %s" % (type, message))

  if False:

    # Whole bunch of nasty debugging code that I hope I will never
    # need to use again but would rather not have to type ever again
    # either.

    def initiate_send(self):
      """DEBUGGING KLUDGE"""
      log("initiate_send()")
      asynchat.async_chat.initiate_send(self)

    def refill_buffer(self):
      """DEBUGGING KLUDGE"""
      log("refill_buffer()")
      asynchat.async_chat.refill_buffer(self)

    def send(self, data):
      """DEBUGGING KLUDGE"""
      log("send(%s)" % repr(data))
      ret = asynchat.async_chat.send(self, data)
      log("send(): %s" % repr(ret))
      return ret

    def recv(self, size):
      """DEBUGGING KLUDGE"""
      log("recv(%d)" % size)
      ret = asynchat.async_chat.recv(self, size)
      log("recv(): %s" % repr(ret))
      return ret

    def readable(self):
      """DEBUGGING KLUDGE"""
      log("readable()")
      return asynchat.async_chat.readable(self)

    def handle_read_event(self):
      """DEBUGGING KLUDGE"""
      log("handle_read_event()")
      asynchat.async_chat.handle_read_event(self)

    def __getattr__(self, attr):
      """DEBUGGING KLUDGE"""
      log("__getattr__(%s, %s)" % (repr(self), repr(attr)))
      ret = asynchat.async_chat.__getattr__(self, attr)
      log("__getattr__(): %s" % repr(ret))
      return ret

    def __repr__(self):
      """DEBUGGING KLUDGE"""
      return asyncore.dispatcher.__repr__(self)

    def __strr__(self):
      """DEBUGGING KLUDGE"""
      return asyncore.dispatcher.__repr__(self)

class server_asynchat(pdu_asynchat):
  """Server protocol engine, handles upcalls from pdu_asynchat to
  implement protocol logic.
  """

  def __init__(self):
    """Set up stdin as connection and start listening for first PDU."""
    log("server_asynchat.__init__()")
    asynchat.async_chat.__init__(self)
    #
    # I don't know a sane way to get asynchat.async_chat.__init__() to
    # call asyncore.file_dispatcher.__init__(), so shut your eyes for
    # a moment while I cut and paste.
    #
    fd = sys.stdin.fileno()
    self.connected = True
    self._fileno = fd
    self.socket = asyncore.file_wrapper(fd)
    self.add_channel()
    flags = fcntl.fcntl(fd, fcntl.F_GETFL, 0)
    flags = flags | os.O_NONBLOCK
    fcntl.fcntl(fd, fcntl.F_SETFL, flags)
    #
    # Ok, you can look again now.
    #
    self.start_new_pdu()
    log("server_asynchat.__init__(%s)" % repr(self))

  def deliver_pdu(self, pdu):
    """Handle received PDU."""
    log("deliver_pdu(%s)" % pdu)
    pdu.serve(self)

  wakeup = None

  def set_wakeup(self, wakeup):
    """Record companion wakeup socket, for shutdown."""
    self.wakeup = wakeup

  def handle_close(self):
    """Intercept close event so we can shut down wakeup socket too."""
    if self.wakeup is not None:
      self.wakeup.close()
    asynchat.async_chat.handle_close(self)

class client_asynchat(pdu_asynchat):
  """Client protocol engine, handles upcalls from pdu_asynchat."""

  def __init__(self, *sshargs):
    """Set up ssh connection and start listening for first PDU."""
    s = socket.socketpair()
    if False:
      self.ssh = subprocess.Popen(sshargs, executable = "/usr/bin/ssh", stdin = s[0], stdout = s[0], close_fds = True)
    else:
      print "[Ignoring arguments, using direct socket loopback kludge for testing]"
      self.ssh = subprocess.Popen(["/usr/local/bin/python", "rtr-origin.py", "server"], stdin = s[0], stdout = s[0], close_fds = True)
    asynchat.async_chat.__init__(self, conn = s[1])
    self.start_new_pdu()

  def deliver_pdu(self, pdu):
    """Handle received PDU.  For now, just print it and shut down."""
    log("deliver_pdu(%s)" % pdu)
    print pdu
    self.close()

  def cleanup(self):
    """Clean up this chat session's child process."""
    try:
      os.kill(self.ssh.pid, signal.SIGINT)
    except:
      pass

class server_wakeup(asyncore.dispatcher):
  """asycnore dispatcher for server.  This just handles the PF_UNIX
  sockets we use to receive wakeup calls from the cronjob when it's
  time for us to send a notify PDU to our client.
  """

  def __init__(self, chat):
    asyncore.dispatcher.__init__(self)
    self.my_asynchat_handle = chat
    self.my_socket_filename = "wakeup.%d" % os.getpid()
    self.create_socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    self.bind(self.my_socket_filename)
    self.listen(5)

  def writable(self):
    """This socket is read-only, never writable."""
    return False

  def handle_read(self):
    """Handle receipt of a datagram."""
    log("handle_read()")
    self.my_asynchat_handle.notify(self.recv(512))

  def cleanup(self):
    """Clean up this dispatcher's socket."""
    log("wakeup.close()")
    self.close()
    try:
      os.unlink(self.my_socket_filename)
    except:
      pass

def server_main():
  """Main program for server mode.  Not really written yet."""
  wakeup = None
  try:
    log("starting chat")
    server = server_asynchat()
    log("chat setup got %s" % repr(server))
    log("chat connected: %s" % server.connected)
    log("starting wakeup")
    wakeup = server_wakeup(chat = server)
    log("wakeup setup got %s" % repr(wakeup))
    log("setting chat's wakeup handle")
    server.set_wakeup(wakeup)
    log("looping")
    asyncore.loop()
  finally:
    log("finally")
    if wakeup is not None:
      wakeup.cleanup()

def client_main():
  """Main program for client mode.  Not really written yet."""
  client = None
  try:
    client = client_asynchat()
    log("chat connected: %s" % client.connected)
    log("sleeping...")
    time.sleep(2)
    client.push_pdu(reset_query())
    log("chat connected: %s" % client.connected)
    asyncore.loop()
  except:
    if client is not None:
      client.cleanup()
    raise

def log_really(msg):
  """Logging hack, debugging code only, clean up later..."""
  sys.stderr.write(("[%s] " % jane) + msg + "\n")

def log(msg):
  """Logging hack, debugging code only, clean up later..."""
  if False:
    log_really(msg)

if len(sys.argv) == 1:
  jane = "client"
else:
  assert len(sys.argv) == 2
  jane = sys.argv[1]

{ "updater" : updater_main,
  "client"  : client_main,
  "server"  : server_main,
  }[jane]()
