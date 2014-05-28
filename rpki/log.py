# $Id$
# 
# Copyright (C) 2013--2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2009--2012  Internet Systems Consortium ("ISC")
# Portions copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
# 
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL, ISC, AND ARIN DISCLAIM ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL DRL,
# ISC, OR ARIN BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
# CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
# OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
# WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""
Logging facilities for RPKI libraries.
"""

import os
import sys
import time
import logging
import logging.handlers
import argparse
import traceback as tb

try:
  have_setproctitle = False
  if os.getenv("DISABLE_SETPROCTITLE") is None:
    import setproctitle
    have_setproctitle = True
except ImportError:
  pass

logger = logging.getLogger(__name__)

## @var show_python_ids
# Whether __repr__() methods should show Python id numbers

show_python_ids = False

## @var enable_tracebacks
# Whether tracebacks are enabled globally.  Individual classes and
# modules may choose to override this.

enable_tracebacks = False

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

def argparse_setup(parser):
  """
  Set up argparse stuff for functionality in this module.

  Default logging destination is syslog, but also see rpki.log.init().
  """

  class RotatingFile(argparse.Action):
    def __call__(self, parser, namespace, values, option_string = None):
      setattr(namespace, self.dest, values[0])
      setattr(namespace, self.dest + "_maxBytes",    int(values[1]) * 1024)
      setattr(namespace, self.dest + "_backupCount", int(values[2]))

  class TimedRotatingFile(argparse.Action):
    def __call__(self, parser, namespace, values, option_string = None):
      setattr(namespace, self.dest, values[0])
      setattr(namespace, self.dest + "_interval",    int(values[1]))
      setattr(namespace, self.dest + "_backupCount", int(values[2]))

  parser.add_argument("--log-level", default = logging.WARNING,
                      choices = ("debug", "info", "warning", "error", "critical"),
                      type = lambda s: int(getattr(logging, s.upper())),
                      help = "how verbosely to log")
  group = parser.add_mutually_exclusive_group()
  group.add_argument("--log-syslog", nargs = "?", default = "daemon",
                     choices = sorted(logging.handlers.SysLogHandler.facility_names.keys()),
                     help = "send logging to syslog")
  group.add_argument("--log-stderr", dest = "log_stream", action = "store_const", const = sys.stderr,
                     help = "send logging to standard error")
  group.add_argument("--log-stdout", dest = "log_stream", action = "store_const", const = sys.stdout,
                     help = "send logging to standard output")
  group.add_argument("--log-file",
                     help = "send logging to a plain old file")
  group.add_argument("--log-rotating-file", action = RotatingFile,
                     nargs = 3, metavar = ("FILENAME", "KBYTES", "COUNT"),
                     help = "send logging to rotating file")
  group.add_argument("--log-timed-rotating-file", action = TimedRotatingFile,
                     nargs = 3, metavar = ("FILENAME", "HOURS", "COUNT"),
                     help = "send logging to timed rotating file")


def init(ident = "rpki", args = argparse.Namespace(log_level = logging.DEBUG, log_stream = sys.stderr)):
  """
  Initialize logging system.

  Default logging destination is syslog if "args" is specified, stderr otherwise.
  """

  assert isinstance(args, argparse.Namespace)

  if args.log_stream:
    handler = logging.StreamHandler(stream = args.log_stream)

  elif args.log_file:
    handler = logging.FileHandler(filename = args.log_file)

  elif args.log_rotating_file:
    handler = logging.handlers.RotatingFileHandler(
      filename = args.log_rotating_file,
      maxBytes = args.log_rotating_file_maxBytes,
      backupCount = args.log_rotating_file_backupCount)

  elif args.log_timed_rotating_file:
    handler = logging.handlers.TimedRotatingFileHandler(
      filename = args.log_timed_rotating_file,
      interval = args.log_timed_rotating_file_interval,
      backupCount = args.log_timed_rotating_file_backupCount)

  elif args.log_syslog:
    handler = logging.handlers.SysLogHandler(
      address = "/dev/log" if os.path.exists("/dev/log") else ("localhost", logging.handlers.SYSLOG_UDP_PORT),
      facility = args.log_syslog)

  else:
    raise ValueError
  
  format = ident + "[%(process)d]: %(message)s"
  if not isinstance(handler, logging.handlers.SysLogHandler):
    format = "%(asctime)s " + format

  # At some point we will probably want our own subclass of
  # logging.Formatter so we can support LoggingAdapters with extra
  # fields, but this suffices for the moment.

  formatter = logging.Formatter(format, "%Y-%m-%d %H:%M:%S")
  formatter.converter = time.gmtime
  handler.setFormatter(formatter)

  root_logger = logging.getLogger()
  root_logger.addHandler(handler)
  root_logger.setLevel(args.log_level)

  if ident and have_setproctitle and use_setproctitle:
    if proctitle_extra:
      setproctitle.setproctitle("%s (%s)" % (ident, proctitle_extra))
    else:
      setproctitle.setproctitle(ident)


def traceback(trace_logger, do_it = None):
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

  logging.exception() doesn't do quite what we want here, or we'd just
  use that.  In particular, logging.exception() puts the entire
  traceback (or, rather, the portion that it choses to print) into a
  single log message, and is pretty much tied to that model because
  its getting the exception data from one log record.  This doesn't
  work well with syslog, which has a maximum record size.  Maybe the
  real answer here is just that we shouldn't attempt to backtrace when
  logging via syslog, but, for now, keep using our old hack.
  """

  if do_it is None:
    do_it = enable_tracebacks

  e = sys.exc_info()[1]
  assert e is not None, "rpki.log.traceback() called without valid trace on stack!  This should not happen."

  if do_it or isinstance(e, AssertionError):
    bt = tb.extract_stack(limit = 3)
    trace_logger.error("Exception caught in %s() at %s:%d called from %s:%d" % (bt[1][2], bt[1][0], bt[1][1], bt[0][0], bt[0][1]))
    bt = tb.format_exc()
    assert bt is not None, "Apparently I'm still not using the right test for null backtrace"
    for line in bt.splitlines():
      trace_logger.warning(line)

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
    if token is not None:
      try:
        s = str(token)
      except:
        s = "???"
        logger.debug("Failed to generate repr() string for object of type %r" % type(token))
        traceback(logger)
      if s:
        words.append(s)

  if show_python_ids:
    words.append(" at %#x" % id(obj))

  return "<" + " ".join(words) + ">"
