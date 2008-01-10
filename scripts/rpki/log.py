# $Id$

# Copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""Logging facilities for RPKI libraries.
"""

import syslog, traceback

enable_trace = False

def init(ident = "rpki", flags = syslog.LOG_PID | syslog.LOG_PERROR, facility = syslog.LOG_DAEMON, trace = False):
  """Initialize logging system."""

  global enable_trace
  enable_trace = trace

  return syslog.openlog(ident, flags, facility)

class logger(object):
  """Closure for logging."""

  def __init__(self, priority):
    self.priority = priority

  def __call__(self, message):
    return syslog.syslog(self.priority, message)

error   = logger(syslog.LOG_ERR)
warning = logger(syslog.LOG_WARNING)
notice  = logger(syslog.LOG_NOTICE)
info    = logger(syslog.LOG_INFO)
debug   = logger(syslog.LOG_DEBUG)

def trace():
  """Execution trace -- where are we now, and whence came we here?"""
  if enable_trace:
    bt = traceback.extract_stack(limit = 3)
    return debug("[%s() at %s:%d from %s:%d]" % (bt[1][2], bt[1][0], bt[1][1], bt[0][0], bt[0][1]))
