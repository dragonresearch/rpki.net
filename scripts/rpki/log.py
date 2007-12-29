# $Id$

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
