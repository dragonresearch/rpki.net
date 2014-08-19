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
RPKI-Router protocol implementation.  See RFC 6810 et sequalia in fine
RFC and Internet-Draft repositories near you.
"""

import os
import sys
import time
import logging
import logging.handlers
import argparse


class Formatter(logging.Formatter):

  converter = time.gmtime

  def __init__(self, debug, fmt, datefmt):
    self.debug = debug
    super(Formatter, self).__init__(fmt, datefmt)

  def format(self, record):
    if getattr(record, "connection", None) is None:
      record.connection = ""
    return super(Formatter, self).format(record)

  def formatException(self, ei):
    if self.debug:
      return super(Formatter, self).formatException(ei)
    else:
      return str(ei[1])

def main():

  os.environ["TZ"] = "UTC"
  time.tzset()

  from rpki.rtr.server    import argparse_setup as argparse_setup_server
  from rpki.rtr.client    import argparse_setup as argparse_setup_client
  from rpki.rtr.generator import argparse_setup as argparse_setup_generator

  if "rpki.rtr.bgpdump" in sys.modules:
    from rpki.rtr.bgpdump import argparse_setup as argparse_setup_bgpdump
  else:
    def argparse_setup_bgpdump(ignored):
      pass

  argparser = argparse.ArgumentParser(description = __doc__)
  argparser.add_argument("--debug", action = "store_true", help = "debugging mode")
  argparser.add_argument("--log-level", default = "debug",
                         choices = ("debug", "info", "warning", "error", "critical"),
                         type = lambda s: s.lower())
  argparser.add_argument("--log-to",
                         choices = ("syslog", "stderr"))
  subparsers = argparser.add_subparsers(title = "Commands", metavar = "", dest = "mode")
  argparse_setup_server(subparsers)
  argparse_setup_client(subparsers)
  argparse_setup_generator(subparsers)
  argparse_setup_bgpdump(subparsers)
  args = argparser.parse_args()

  fmt = "rpki-rtr/" + args.mode + "%(connection)s[%(process)d] %(message)s"

  if (args.log_to or args.default_log_to) == "stderr":
    handler = logging.StreamHandler()
    fmt = "%(asctime)s " + fmt
  elif os.path.exists("/dev/log"):
    handler = logging.handlers.SysLogHandler("/dev/log")
  else:
    handler = logging.handlers.SysLogHandler()

  handler.setFormatter(Formatter(args.debug, fmt, "%Y-%m-%dT%H:%M:%SZ"))
  logging.root.addHandler(handler)
  logging.root.setLevel(int(getattr(logging, args.log_level.upper())))

  return args.func(args)
