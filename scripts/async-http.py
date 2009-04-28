"""
Testbed for figuring out how to write asynchronous HTTPS code.

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

# Command that may be useful for testing server side of this:
#
#    lynx -post_data -mime_header -source http://127.0.0.1:8000/

import sys, os, time, socket, asyncore, asynchat, traceback, urlparse
import rpki.async

debug = True

allow_persistence = False

class http_message(object):

  software_name = "BalmyBandicoot HTTP test code"

  def __init__(self, version = None, body = None, headers = None):
    self.version = version
    self.body = body
    self.headers = headers
    self.normalize_headers()

  def normalize_headers(self, headers = None):
    if headers is None:
      headers = () if self.headers is None else self.headers.items()
      translate_underscore = True
    else:
      translate_underscore = False
    result = {}
    for k,v in headers:
      if translate_underscore:
        k = k.replace("_", "-")
      k = "-".join(s.capitalize() for s in k.split("-"))
      v = v.strip()
      if k in result:
        result[k] += ", " + v
      else:
        result[k] = v
    self.headers = result

  @classmethod
  def parse_from_wire(cls, headers):
    self = cls()
    headers = headers.split("\r\n")
    self.parse_first_line(*headers.pop(0).split(None, 2))
    for i in xrange(len(headers) - 2, -1, -1):
      if headers[i + 1][0].isspace():
        headers[i] += headers[i + 1]
        del headers[i + 1]
    self.normalize_headers([h.split(":", 1) for h in headers])
    return self

  def format(self):
    s = self.format_first_line()
    if self.body is not None:
      assert isinstance(self.body, str)
      self.headers["Content-Length"] = len(self.body)
    for kv in self.headers.iteritems():
      s += "%s: %s\r\n" % kv
    s += "\r\n"
    if self.body is not None:
      s += self.body
    return s

  def __str__(self):
    return self.format()

  def parse_version(self, version):
    if version[:5] != "HTTP/":
      raise RuntimeError, "Couldn't parse version %s" % version
    self.version = tuple(int(i) for i in version[5:].split("."))

  def persistent(self):
    c = self.headers.get("Connection")
    if self.version == (1,1):
      return c is None or "close" not in c.lower()
    elif self.version == (1,0):
      return c is not None and "keep-alive" in c.lower()
    else:
      return False

class http_request(http_message):

  def __init__(self, cmd = None, path = None, version = (1,0), body = None, **headers):
    if cmd is not None and cmd != "POST" and body is not None:
      raise RuntimeError
    http_message.__init__(self, version = version, body = body, headers = headers)
    self.cmd = cmd
    self.path = path

  def parse_first_line(self, cmd, path, version):
    self.parse_version(version)
    self.cmd = cmd
    self.path = path

  def format_first_line(self):
    self.headers.setdefault("User-Agent", self.software_name)
    return "%s %s HTTP/%d.%d\r\n" % (self.cmd, self.path, self.version[0], self.version[1])

class http_response(http_message):

  def __init__(self, code = None, reason = None, version = (1,0), body = None, **headers):
    http_message.__init__(self, version = version, body = body, headers = headers)
    self.code = code
    self.reason = reason

  def parse_first_line(self, version, code, reason):
    self.parse_version(version)
    self.code = int(code)
    self.reason = reason

  def format_first_line(self):
    self.headers.setdefault("Date", time.strftime("%a, %d %b %Y %T GMT"))
    self.headers.setdefault("Server", self.software_name)
    return "HTTP/%d.%d %s %s\r\n" % (self.version[0], self.version[1], self.code, self.reason)

class http_stream(asynchat.async_chat):

  def __init__(self, conn = None):
    asynchat.async_chat.__init__(self, conn = conn)
    self.buffer = []
    self.restart()

  def restart(self):
    assert not self.buffer
    self.set_terminator("\r\n\r\n")

  def collect_incoming_data(self, data):
    """Buffer the data"""
    self.buffer.append(data)

  def get_buffer(self):
    val = "".join(self.buffer)
    self.buffer = []
    return val

  def found_terminator(self):
    if isinstance(self.get_terminator(), str):
      return self.handle_headers()
    else:
      return self.handle_body()

  def handle_body(self):
    self.msg.body = self.get_buffer()
    #assert len(self.msg.body) == int(self.msg.headers["Content-Length"])
    self.handle_message()

  def handle_error(self):
    if debug: print "[Error]"
    print traceback.format_exc()
    asyncore.close_all()

class http_server(http_stream):

  def handle_headers(self):
    if debug: print "[Got headers]"
    self.msg = http_request.parse_from_wire(self.get_buffer())
    if self.msg.cmd == "POST":
      if debug: print "[Waiting for POST body]"
      self.set_terminator(int(self.msg.headers["Content-Length"]))
    else:
      self.handle_message()

  def handle_message(self):
    if debug: print "[Got message]"
    if debug: print "[Connection %s persistent]" % ("is" if self.msg.persistent() else "isn't")
    print "Query:"
    print self.msg
    print
    msg = http_response(code = 200, reason = "OK", body = self.msg.format(),
                        Connection = "Keep-Alive" if allow_persistence and self.msg.persistent() else "Close",
                        Cache_Control = "no-cache,no-store",
                        Content_Type = "text/plain")

    print "Reply:"
    print msg
    print
    self.push(msg.format())
    if allow_persistence and self.msg.persistent():
      if debug: print "[Listening for next message]"
      self.restart()
    else:
      if debug: print "[Closing]"
      self.close_when_done()

class http_listener(asyncore.dispatcher):

  def __init__(self, port):
    asyncore.dispatcher.__init__(self)
    self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
    self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    self.bind(("", port))
    self.listen(5)
    if debug: print "[Listening on port %s]" % port

  def handle_accept(self):
    if debug: print "[Accepting connection]"
    server = http_server(self.accept()[0])

  def handle_error(self):
    if debug: print "[Error]"
    print traceback.format_exc()
    asyncore.close_all()

class http_client(http_stream):

  def __init__(self, narrator, hostport):
    if debug: print "[Creating new connection]"
    http_stream.__init__(self)
    self.narrator = narrator
    self.hostport = hostport
    self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
    self.connect(hostport)

  def handle_headers(self):
    self.msg = http_response.parse_from_wire(self.get_buffer())
    if "Content-Length" in self.msg.headers:
      self.set_terminator(int(self.msg.headers["Content-Length"]))
    else:
      self.set_terminator(None)

  def handle_message(self):
    if debug: print "[Got message]"
    if debug: print "[Connection %s persistent]" % ("is" if self.msg.persistent() else "isn't")
    print "Query:"
    print self.narrator.done_msg(self.hostport)
    print
    print "Reply:"
    print self.msg
    print
    self.next_msg(first = False)

  def handle_connect(self):
    if debug: print "[Connected]"
    self.next_msg(first = True)

  def queue_message(self, msg):
    if debug: print "[Adding message to queue]"
    self.message_queue.append(msg)

  def next_msg(self, first):
    msg = self.narrator.next_msg(self.hostport, first or (allow_persistence and self.msg.persistent()))
    if msg is not None:
      if debug: print "[Got a new message to send from my queue]"
      self.push(msg.format())
      self.restart()
    else:
      if debug: print "[No messages left in queue]"
      self.close_when_done()

  def handle_close(self):
    if self.get_terminator() is None:
      self.found_terminator()

class http_narrator(object):

  def __init__(self):
    self.clients = {}
    self.queues  = {}

  def query(self, url, body = None):
    u = urlparse.urlparse(url)
    assert u.scheme == "http" and u.username is None and u.password is None and u.params == "" and u.query == "" and u.fragment == ""
    request = http_request(cmd = "POST", path = u.path, body = body,
                           Content_Type = "text/plain",
                           Connection = "Keep-Alive" if allow_persistence else "Close")
    hostport = (u.hostname or "localhost", u.port or 80)
    if hostport in self.queues:
      self.queues[hostport].append(request)
    else:
      self.queues[hostport] = [request]
    if hostport not in self.clients:
      self.clients[hostport] = http_client(self, hostport)
      
  def done_msg(self, hostport):
    return self.queues[hostport].pop(0)

  def next_msg(self, hostport, usable):
    queue = self.queues.get(hostport)
    if queue and not usable:
      self.clients[hostport] = http_client(self, hostport)
    if queue and usable:
      if debug: print "[Reusing existing connection]"
      return queue[0]
    else:
      return None

if len(sys.argv) == 1:

  listener = http_listener(port = 8000)

else:

  narrator = http_narrator()
  for url in sys.argv[1:]:
    narrator.query(url = url, body = "Hi, I'm trying to talk to URL %s" % url)

rpki.async.event_loop()
