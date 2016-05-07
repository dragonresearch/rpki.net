# $Id$
#
# Copyright (C) 2015--2016  Parsons Government Services ("PARSONS")
# Portions copyright (C) 2014  Dragon Research Labs ("DRL")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND PARSONS AND DRL DISCLAIM ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL
# PARSONS OR DRL BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
# CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
# OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
# WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""
HTTP using Python standard libraries, for RPKI programs that don't
need the full-blown rpki.http asynchronous code.
"""

import logging
import httplib
import urlparse
import BaseHTTPServer

logger = logging.getLogger(__name__)


default_content_type = "application/x-rpki"


class HTTPRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    """
    HTTP request handler simple RPKI servers.
    """

    rpki_handlers = ()

    def do_POST(self):
        try:
            content_type   = self.headers.get("Content-Type")
            content_length = self.headers.get("Content-Length")
            for handler_path, handler, handler_content_type in self.rpki_handlers:
                if self.path.startswith(handler_path) and content_type in handler_content_type:
                    return handler(self,
                                   self.rfile.read()
                                   if content_length is None else
                                   self.rfile.read(int(content_length)))
            self.send_error(404, "No handler for path %s" % self.path)
        except Exception, e:
            logger.exception("Unhandled exception")
            self.send_error(501, "Unhandled exception %s" % e)

    def send_cms_response(self, der):
        self.send_response(200)
        self.send_header("Content-Type", default_content_type)
        self.send_header("Content-Length", str(len(der)))
        self.end_headers()
        self.wfile.write(der)

    def log_message(self, *args):
        logger.info(*args, extra = dict(context = "%s:%s" % self.client_address))

    def send_error(self, code, message = None):
        # BaseHTTPRequestHandler.send_error() generates HTML error messages,
        # which we don't want, so we override the method to suppress this.
        self.send_response(code, message)
        self.send_header("Content-Type", default_content_type)
        self.send_header("Connection", "close")
        self.end_headers()


def server(handlers, port, host = ""):
    """
    Run an HTTP server and wait (forever) for connections.
    """

    if isinstance(handlers, (tuple, list)):
        handlers = tuple(h[:3] if len(h) > 2 else (h[0], h[1], default_content_type)
                         for h in handlers)
    else:
        handlers = (("/", handlers, default_content_type),)

    class RequestHandler(HTTPRequestHandler):
        rpki_handlers = handlers

    BaseHTTPServer.HTTPServer((host, port), RequestHandler).serve_forever()


class BadURL(Exception):
    "Bad contact URL"

class RequestFailed(Exception):
    "HTTP returned failure"

class BadContentType(Exception):
    "Wrong HTTP Content-Type"


def client(proto_cms_msg, client_key, client_cert, server_ta, server_cert, url, q_msg,
           debug = None, replay_track = None, client_crl = None, content_type = default_content_type):
    """
    Issue single a query and return the response, handling all the CMS and XML goo.
    """

    u = urlparse.urlparse(url)

    if u.scheme not in ("", "http") or u.username or u.password or u.params or u.query or u.fragment:
        raise BadURL("Unusable URL %s", url)

    q_cms = proto_cms_msg()
    q_der = q_cms.wrap(q_msg, client_key, client_cert, client_crl)

    if debug is not None:
        debug.write("<!-- Query -->\n" + q_cms.pretty_print_content() + "\n")

    http = httplib.HTTPConnection(u.hostname, u.port or httplib.HTTP_PORT)
    http.request("POST", u.path, q_der, {"Content-Type" : content_type})
    r = http.getresponse()

    if r.status != 200:
        raise RequestFailed("HTTP request failed with status %r reason %r" % (r.status, r.reason))

    if r.getheader("Content-Type") != content_type:
        raise BadContentType("HTTP Content-Type %r, expected %r" % (r.getheader("Content-Type"), content_type))

    r_der = r.read()
    r_cms = proto_cms_msg(DER = r_der)
    r_msg = r_cms.unwrap((server_ta, server_cert))

    if replay_track is not None:
        replay_track.cms_timestamp = r_cms.check_replay(replay_track.cms_timestamp, url)

    if debug is not None:
        debug.write("<!-- Reply -->\n" + r_cms.pretty_print_content() + "\n")

    return r_msg
