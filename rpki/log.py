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


class Formatter(object):
  """
  Reimplementation (easier than subclassing in this case) of
  logging.Formatter.

  It turns out that the logging code only cares about this class's
  .format(record) method, everything else is internal; so long as
  .format() converts a record into a properly formatted string, the
  logging code is happy.

  So, rather than mess around with dynamically constructing and
  deconstructing and tweaking format strings and ten zillion options
  we don't use, we just provide our own implementation that supports
  what we do need.
  """

  converter = time.gmtime

  def __init__(self, ident, handler):
    self.ident = ident
    self.is_syslog = isinstance(handler, logging.handlers.SysLogHandler)

  def format(self, record):
    return "".join(self.coformat(record)).rstrip("\n")

  def coformat(self, record):
    if not self.is_syslog:
      yield time.strftime("%Y-%m-%d %H:%M:%S ", time.gmtime(record.created))
    yield "%s[%d]: " % (self.ident, record.process)
    try:
      if isinstance(record.context, (str, unicode)):
        yield record.context + " "
      else:
        yield repr(record.context) + " "
    except AttributeError:
      pass
    yield record.getMessage()
    if record.exc_info:
      if self.is_syslog or not enable_tracebacks:
        lines = tb.format_exception_only(record.exc_info[0], record.exc_info[1])
        lines.insert(0, ": ")
      else:
        lines = tb.format_exception(record.exc_info[0], record.exc_info[1], record.exc_info[2])
        lines.insert(0, "\n")
      for line in lines:
        yield line


def argparse_setup(parser, default_thunk = None):
  """
  Set up argparse stuff for functionality in this module.

  Default logging destination is syslog, but you can change this
  by setting default_thunk to a callable which takes no arguments
  and which returns a instance of a logging.Handler subclass.

  Also see rpki.log.init().
  """

  class LogLevelAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string = None):
      setattr(namespace, self.dest, getattr(logging, values.upper()))

  parser.add_argument("--log-level", default = logging.WARNING, action = LogLevelAction,
                      choices = ("debug", "info", "warning", "error", "critical"),
                      help = "how verbosely to log")

  group = parser.add_mutually_exclusive_group()

  syslog_address = "/dev/log" if os.path.exists("/dev/log") else ("localhost", logging.handlers.SYSLOG_UDP_PORT)

  class SyslogAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string = None):
      namespace.log_handler = lambda: logging.handlers.SysLogHandler(address = syslog_address, facility = values)

  group.add_argument("--log-syslog", nargs = "?", const = "daemon", action = SyslogAction,
                     choices = sorted(logging.handlers.SysLogHandler.facility_names.keys()),
                     help = "send logging to syslog")

  class StreamAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string = None):
      namespace.log_handler = lambda: logging.StreamHandler(stream = self.const)

  group.add_argument("--log-stderr", nargs = 0, action = StreamAction, const = sys.stderr,
                     help = "send logging to standard error")

  group.add_argument("--log-stdout", nargs = 0, action = StreamAction, const = sys.stdout,
                     help = "send logging to standard output")

  class WatchedFileAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string = None):
      namespace.log_handler = lambda: logging.handlers.WatchedFileHandler(filename = values)

  group.add_argument("--log-file", action = WatchedFileAction,
                     help = "send logging to a file, reopening if rotated away")

  class RotatingFileAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string = None):
      namespace.log_handler = lambda: logging.handlers.RotatingFileHandler(
        filename    = values[0],
        maxBytes    = int(values[1]) * 1024,
        backupCount = int(values[2]))

  group.add_argument("--log-rotating-file", action = RotatingFileAction,
                     nargs = 3, metavar = ("FILENAME", "KBYTES", "COUNT"),
                     help = "send logging to rotating file")

  class TimedRotatingFileAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string = None):
      namespace.log_handler = lambda: logging.handlers.TimedRotatingFileHandler(
        filename    = values[0],
        interval    = int(values[1]),
        backupCount = int(values[2]),
        when        = "H",
        utc         = True)

  group.add_argument("--log-timed-rotating-file", action = TimedRotatingFileAction,
                     nargs = 3, metavar = ("FILENAME", "HOURS", "COUNT"),
                     help = "send logging to timed rotating file")

  if default_thunk is None:
    default_thunk = lambda: logging.handlers.SysLogHandler(address = syslog_address, facility = "daemon")

  parser.set_defaults(log_handler = default_thunk)


def init(ident = None, args = None):
  """
  Initialize logging system.

  Default logging destination is stderr if "args" is not specified.
  """

  # pylint: disable=E1103

  if ident is None:
    ident = os.path.basename(sys.argv[0])

  if args is None:
    args = argparse.Namespace(log_level   = logging.WARNING,
                              log_handler = logging.StreamHandler)

  handler = args.log_handler()
  handler.setFormatter(Formatter(ident, handler))

  root_logger = logging.getLogger()
  root_logger.addHandler(handler)
  root_logger.setLevel(args.log_level)

  if ident and have_setproctitle and use_setproctitle:
    if proctitle_extra:
      setproctitle.setproctitle("%s (%s)" % (ident, proctitle_extra))
    else:
      setproctitle.setproctitle(ident)


def class_logger(module_logger, attribute = "logger"):
  """
  Class decorator to add a class-level Logger object as a class
  attribute.  This allows control of debugging messages at the class
  level rather than just the module level.

  This decorator takes the module logger as an argument.
  """

  def decorator(cls):
    setattr(cls, attribute, module_logger.getChild(cls.__name__))
    return cls
  return decorator


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
        logger.exception("Failed to generate repr() string for object of type %r", type(token))
      if s:
        words.append(s)

  if show_python_ids:
    words.append(" at %#x" % id(obj))

  return "<" + " ".join(words) + ">"


def show_stack(stack_logger = None):
  """
  Log a stack trace.
  """

  if stack_logger is None:
    stack_logger = logger

  for frame in tb.format_stack():
    for line in frame.split("\n"):
      if line:
        stack_logger.debug("%s", line.rstrip())
