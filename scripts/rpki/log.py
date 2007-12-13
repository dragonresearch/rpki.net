# $Id$

"""Logging facilities for RPKI libraries.
"""

import syslog, traceback

def init(ident = "rpki"):
  """Initialize logging system."""
  return syslog.openlog(ident, syslog.LOG_PID | syslog.LOG_PERROR, syslog.LOG_DAEMON)

class logger(object):
  """Closure for logging."""

  def __init__(self, priority):
    self.set_priority(priority)

  def set_priority(self, priority):
    self.priority = priority

  def __call__(self, message):
    return syslog.syslog(self.priority, message)

error   = logger(syslog.LOG_ERR)
warning = logger(syslog.LOG_WARNING)
notice  = logger(syslog.LOG_NOTICE)
info    = logger(syslog.LOG_INFO)
debug   = logger(syslog.LOG_DEBUG)

enable_trace = False

def trace():
  """Execution trace -- where are we now, and whence came we here?"""
  if enable_trace:
    bt = traceback.extract_stack(limit = 3)
    return debug("[%s() at %s:%d from %s:%d]" % (bt[1][2], bt[1][0], bt[1][1], bt[0][0], bt[0][1]))
