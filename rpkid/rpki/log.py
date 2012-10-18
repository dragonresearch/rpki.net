"""
Logging facilities for RPKI libraries.

$Id$

Copyright (C) 2009--2012  Internet Systems Consortium ("ISC")

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

Portions copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

import syslog
import sys
import os
import time
import traceback as tb

try:
  import setproctitle
  have_setproctitle = True
except ImportError:
  have_setproctitle = False

## @var enable_trace
# Whether call tracing is enabled.

enable_trace = False

## @var use_syslog
# Whether to use syslog

use_syslog = True

## @var show_python_ids
# Whether __repr__() methods should show Python id numbers

show_python_ids = False

## @var enable_tracebacks
# Whether tracebacks are enabled globally.  Individual classes and
# modules may choose to override this.

enable_tracebacks = True

## @var use_setproctitle
# Whether to use setproctitle (if available) to change name shown for
# this process in ps listings (etc).

use_setproctitle = True

## @var proctitle_extra

# Extra text to include in proctitle display.  By default this is the
# tail of the current directory name, as this is often useful, but you
# can set it to something else if you like.  If None or the empty
# string, the extra information field will be omitted from the proctitle.

proctitle_extra = os.path.basename(os.getcwd())

tag = ""
pid = 0

def init(ident = "rpki", flags = syslog.LOG_PID, facility = syslog.LOG_DAEMON):
  """
  Initialize logging system.
  """

  if use_syslog:
    return syslog.openlog(ident, flags, facility)
  else:
    global tag, pid
    tag = ident
    pid = os.getpid()
  if ident and have_setproctitle and use_setproctitle:
    if proctitle_extra:
      setproctitle.setproctitle("%s (%s)" % (ident, proctitle_extra))
    else:
      setproctitle.setproctitle(ident)

def set_trace(enable):
  """
  Enable or disable call tracing.
  """

  global enable_trace
  enable_trace = enable

class logger(object):
  """
  Closure for logging.
  """

  def __init__(self, priority):
    self.priority = priority

  def __call__(self, message):
    if use_syslog:
      return syslog.syslog(self.priority, message)
    else:
      sys.stderr.write("%s %s[%d]: %s\n" % (time.strftime("%F %T"), tag, pid, message))

error = logger(syslog.LOG_ERR)
warn  = logger(syslog.LOG_WARNING)
note  = logger(syslog.LOG_NOTICE)
info  = logger(syslog.LOG_INFO)
debug = logger(syslog.LOG_DEBUG)

def trace():
  """
  Execution trace -- where are we now, and whence came we here?
  """

  if enable_trace:
    bt = tb.extract_stack(limit = 3)
    return debug("[%s() at %s:%d from %s:%d]" % (bt[1][2], bt[1][0], bt[1][1], bt[0][0], bt[0][1]))

def traceback(do_it = None):
  """
  Consolidated backtrace facility with a bit of extra info.  Argument
  specifies whether or not to log the traceback (some modules and
  classes have their own controls for this, this lets us provide a
  unified interface).  If no argument is specified, we use the global
  default value rpki.log.enable_tracebacks.

  Assertion failures generate backtraces unconditionally, on the
  theory that (a) assertion failures are programming errors by
  definition, and (b) it's often hard to figure out what's triggering
  a particular assertion failure without the backtrace.
  """

  if do_it is None:
    do_it = enable_tracebacks

  e = sys.exc_info()[1]
  assert e is not None, "rpki.log.traceback() called without valid trace on stack!  This should not happen."

  if do_it or isinstance(e, AssertionError):
    bt = tb.extract_stack(limit = 3)
    error("Exception caught in %s() at %s:%d called from %s:%d" % (bt[1][2], bt[1][0], bt[1][1], bt[0][0], bt[0][1]))
    bt = tb.format_exc()
    assert bt is not None, "Apparently I'm still not using the right test for null backtrace"
    for line in bt.splitlines():
      warn(line)

def log_repr(obj, *tokens):
  """
  Constructor for __repr__() strings, handles suppression of Python
  IDs as needed, includes self_handle when available.
  """

  # pylint: disable=W0702
  words = ["%s.%s" % (obj.__class__.__module__, obj.__class__.__name__)]
  try:
    words.append("{%s}" % obj.self.self_handle)
  except:
    pass
  for token in tokens:
    if token is not None and token != "":
      try:
        assert token is not None
        words.append(str(token))
      except:
        debug("Failed to generate repr() string for object of type %r" % type(token))
        traceback()
        words.append("???")
  if show_python_ids:
    words.append(" at %#x" % id(obj))
  return "<" + " ".join(words) + ">"
