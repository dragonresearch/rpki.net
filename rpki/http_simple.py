# $Id$

# Copyright (C) 2014  Dragon Research Labs ("DRL")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL DRL BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""
HTTP using Python standard libraries, for RPKI programs that don't
need the full-blown rpki.http asynchronous code.
"""

import logging
import BaseHTTPServer

logger = logging.getLogger(__name__)


rpki_content_type = "application/x-rpki"


class HTTPRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
  """
  HTTP request handler simple RPKI servers.
  """

  def do_POST(self):
    try:
      content_type   = self.headers.get("Content-Type")
      content_length = self.headers.get("Content-Length")
      if content_type != rpki_content_type:
        self.send_error(415, "No handler for Content-Type %s" % content_type)
      else:
        for prefix, handler in self.rpki_handlers:
          if self.path.startswith(prefix):
            handler(self, (self.rfile.read()
                           if content_length is None else
                           self.rfile.read(int(content_length))))
            break
        else:
          self.send_error(404, "No handler for path %s" % self.path)
    except Exception, e:
      logger.exception("Unhandled exception")
      self.send_error(501, "Unhandled exception")

  def send_cms_response(self, der):
    self.send_response(200)
    self.send_header("Content-Type", rpki_content_type)
    self.send_header("Content-Length", str(len(der)))
    self.end_headers()
    self.wfile.write(der)

  def log_message(self, *args):
    # Might want to use LogAdapter for connection info here?
    logger.info(*args)


def server(handlers, port, host = ""):
  """
  Run an HTTP server and wait (forever) for connections.
  """

  if not isinstance(handlers, (tuple, list)):
    handlers = (("/", handlers),)

  class RequestHandler(HTTPRequestHandler):
    rpki_handlers = handlers

  BaseHTTPServer.HTTPServer((host, port), RequestHandler).serve_forever()
