"""
Basic asynchronous DNS code, using asyncore and Bob Halley's excellent
dnspython package.

$Id$

Copyright (C) 2010  Internet Systems Consortium ("ISC")

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

Portions copyright (C) 2003-2007, 2009, 2010 Nominum, Inc.

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose with or without fee is hereby granted,
provided that the above copyright notice and this permission notice
appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND NOMINUM DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NOMINUM BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
"""

import asyncore, socket, time, sys
import rpki.async, rpki.sundial, rpki.log

try:
  import dns.resolver, dns.rdatatype, dns.rdataclass, dns.name, dns.message
  import dns.inet, dns.exception, dns.query, dns.rcode, dns.ipv4, dns.ipv6
except ImportError:
  if __name__ == "__main__":
    sys.exit("DNSPython not available, skipping rpki.adns unit test")
  else:
    raise

## @var resolver
# Resolver object, shared by everything using this module

resolver = dns.resolver.Resolver()
if resolver.cache is None:
  resolver.cache = dns.resolver.Cache()

## @var nameservers
# Nameservers from resolver.nameservers converted to (af, address)
# pairs.  The latter turns out to be a more useful form for us to use
# internally, because it simplifies the checks we need to make upon
# packet receiption.

nameservers = []

for ns in resolver.nameservers:
  try:
    nameservers.append((socket.AF_INET, dns.ipv4.inet_aton(ns)))
    continue          
  except:
    pass
  try:
    nameservers.append((socket.AF_INET6, dns.ipv6.inet_aton(ns)))
    continue
  except:
    pass
  rpki.log.error("Couldn't parse nameserver address %r" % ns)

class dispatcher(asyncore.dispatcher):
  """
  Basic UDP socket reader for use with asyncore.
  """

  def __init__(self, cb, eb, af, bufsize = 65535):
    asyncore.dispatcher.__init__(self)
    self.cb = cb
    self.eb = eb
    self.af = af
    self.bufsize = bufsize
    self.create_socket(af, socket.SOCK_DGRAM)

  def handle_read(self):
    """
    Receive a packet, hand it off to query class callback.
    """
    wire, from_address = self.recvfrom(self.bufsize)
    self.cb(self.af, from_address[0], from_address[1], wire)

  def handle_error(self):
    """
    Pass errors to query class errback.
    """
    self.eb(sys.exc_info()[1])

  def handle_connect(self):
    """
    Quietly ignore UDP "connection" events.
    """
    pass

  def writable(self):
    """
    We don't need to hear about UDP socket becoming writable.
    """
    return False


class query(object):
  """
  Simplified (no search paths) asynchronous adaptation of
  dns.resolver.Resolver.query() (q.v.).
  """

  def __init__(self, cb, eb, qname, qtype = dns.rdatatype.A, qclass = dns.rdataclass.IN):
    if isinstance(qname, (str, unicode)):
      qname = dns.name.from_text(qname)
    if isinstance(qtype, str):
      qtype = dns.rdatatype.from_text(qtype)   
    if isinstance(qclass, str):
      qclass = dns.rdataclass.from_text(qclass)
    assert qname.is_absolute()
    self.cb = cb
    self.eb = eb
    self.qname = qname
    self.qtype = qtype
    self.qclass = qclass
    self.start = time.time()
    rpki.async.defer(self.go)

  def go(self):
    """
    Start running the query.  Check our cache before doing network
    query; if we find an answer there, just return it.  Otherwise
    start the network query.
    """
    if resolver.cache:
      answer = resolver.cache.get((self.qname, self.qtype, self.qclass))
    else:
      answer = None
    if answer:
      self.cb(self, answer)
    else:
      self.timer = rpki.async.timer()
      self.sockets = {}
      self.request = dns.message.make_query(self.qname, self.qtype, self.qclass)
      if resolver.keyname is not None:
        self.request.use_tsig(resolver.keyring, resolver.keyname, resolver.keyalgorithm)
      self.request.use_edns(resolver.edns, resolver.ednsflags, resolver.payload)
      self.response = None
      self.backoff = 0.10
      self.nameservers = nameservers[:]
      self.loop1()

  def loop1(self):
    """
    Outer loop.  If we haven't got a response yet and still have
    nameservers to check, start inner loop.  Otherwise, we're done.
    """
    self.timer.cancel()
    if self.response is None and self.nameservers:
      self.iterator = rpki.async.iterator(self.nameservers[:], self.loop2, self.done2)
    else:
      self.done1()

  def loop2(self, iterator, nameserver):
    """
    Inner loop.  Send query to next nameserver in our list, unless
    we've hit the overall timeout for this query.
    """
    self.timer.cancel()
    try:
      timeout = resolver._compute_timeout(self.start)
    except dns.resolver.Timeout, e:
      self.lose(e)
    else:
      af, addr = nameserver
      if af not in self.sockets:
        self.sockets[af] = dispatcher(self.socket_cb, self.socket_eb, af)
      self.sockets[af].sendto(self.request.to_wire(),
                              (dns.inet.inet_ntop(af, addr), resolver.port))
      self.timer.set_handler(self.socket_timeout)
      self.timer.set_errback(self.socket_eb)
      self.timer.set(rpki.sundial.timedelta(seconds = timeout))

  def socket_timeout(self):
    """
    No answer from nameserver, move on to next one (inner loop).
    """
    self.response = None
    self.iterator()

  def socket_eb(self, e):
    """
    UDP socket signaled error.  If it really is some kind of socket
    error, handle as if we've timed out on this nameserver; otherwise,
    pass error back to caller.
    """
    self.timer.cancel()
    if isinstance(e, socket.error):
      self.response = None
      self.iterator()
    else:
      self.lose(e)

  def socket_cb(self, af, from_host, from_port, wire):
    """
    Received a packet that might be a DNS message.  If it doesn't look
    like it came from one of our nameservers, just drop it and leave
    the timer running.  Otherwise, try parsing it: if it's an answer,
    we're done, otherwise handle error appropriately and move on to
    next nameserver.
    """
    sender = (af, dns.inet.inet_pton(af, from_host))
    if from_port != resolver.port or sender not in self.nameservers:
      return
    self.timer.cancel()
    try:
      self.response = dns.message.from_wire(wire, keyring = self.request.keyring, request_mac = self.request.mac, one_rr_per_rrset = False)
    except dns.exception.FormError:
      self.nameservers.remove(sender)
    else:
      rcode = self.response.rcode()
      if rcode in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
        self.done1()
        return
      if rcode != dns.rcode.SERVFAIL:
        self.nameservers.remove(sender)
    self.response = None
    self.iterator()

  def done2(self):
    """
    Done with inner loop.  If we still haven't got an answer and
    haven't (yet?) eliminated all of our nameservers, wait a little
    while before starting the cycle again, unless we've hit the
    timeout threshold for the whole query.
    """
    if self.response is None and self.nameservers:
      try:
        delay = rpki.sundial.timedelta(seconds = min(resolver._compute_timeout(self.start), self.backoff))
        self.backoff *= 2
        self.timer.set_handler(self.loop1)
        self.timer.set_errback(self.lose)
        self.timer.set(delay)
      except dns.resolver.Timeout, e:
        self.lose(e)
    else:
      self.loop1()

  def cleanup(self):
    """
    Shut down our timer and sockets.
    """
    self.timer.cancel()
    for s in self.sockets.itervalues():
      s.close()

  def lose(self, e):
    """
    Something bad happened.  Clean up, then pass error back to caller.
    """
    self.cleanup()
    self.eb(self, e)

  def done1(self):
    """
    Done with outer loop.  If we got a useful answer, cache it, then
    pass it back to caller; if we got an error, pass the appropriate
    exception back to caller.
    """
    self.cleanup()
    try:
      if not self.nameservers:
        raise dns.resolver.NoNameservers
      if self.response.rcode() == dns.rcode.NXDOMAIN:
        raise dns.resolver.NXDOMAIN
      answer = dns.resolver.Answer(self.qname, self.qtype, self.qclass, self.response)
      if resolver.cache:
        resolver.cache.put((self.qname, self.qtype, self.qclass), answer)
      self.cb(self, answer)
    except (rpki.async.ExitNow, SystemExit):
      raise
    except Exception, e:
      self.lose(e)

class getaddrinfo(object):

  typemap = { dns.rdatatype.A    : socket.AF_INET,
              dns.rdatatype.AAAA : socket.AF_INET6 }

  def __init__(self, cb, eb, host, address_families = typemap.values()):
    self.cb = cb
    self.eb = eb
    self.host = host
    self.result = []
    self.queries = [query(self.done, self.lose, host, qtype)
                    for qtype in self.typemap
                    if self.typemap[qtype] in address_families]

  def done(self, q, answer):
    if answer is not None:
      for a in answer:
        self.result.append((self.typemap[a.rdtype], a.address))
    self.queries.remove(q)
    if not self.queries:
      self.cb(self.result)

  def lose(self, q, e):
    if isinstance(e, dns.resolver.NoAnswer):
      self.done(q, None)
    else:
      for q in self.queries:
        q.cleanup()
      self.eb(e)

if __name__ == "__main__":

  rpki.log.use_syslog = False
  print "Some adns tests may take a minute or two, please be patient"

  class test_getaddrinfo(object):

    def __init__(self, qname):
      self.qname = qname
      getaddrinfo(self.done, self.lose, qname)

    def done(self, result):
      print "getaddrinfo(%s) returned: %s" % (
        self.qname,
        ", ".join(str(r) for r in result))

    def lose(self, e):
      print "getaddrinfo(%s) failed: %r" % (self.qname, e)

  class test_query(object):

    def __init__(self, qname, qtype = dns.rdatatype.A, qclass = dns.rdataclass.IN):
      self.qname = qname
      self.qtype = qtype
      self.qclass = qclass
      query(self.done, self.lose, qname, qtype = qtype, qclass = qclass)

    def done(self, q, result):
      print "query(%s, %s, %s) returned: %s" % (
        self.qname,
        dns.rdatatype.to_text(self.qtype),
        dns.rdataclass.to_text(self.qclass),
        ", ".join(str(r) for r in result))

    def lose(self, q, e):
      print "getaddrinfo(%s, %s, %s) failed: %r" % (
        self.qname,
        dns.rdatatype.to_text(self.qtype),
        dns.rdataclass.to_text(self.qclass),
        e)

  if True:
    for qtype in (dns.rdatatype.A, dns.rdatatype.AAAA, dns.rdatatype.HINFO):
      test_query("subvert-rpki.hactrn.net", qtype)
    test_query("nonexistant.rpki.net")
    test_query("subvert-rpki.hactrn.net", qclass = dns.rdataclass.CH)

  for host in ("subvert-rpki.hactrn.net", "nonexistant.rpki.net"):
    test_getaddrinfo(host)

  rpki.async.event_loop()
