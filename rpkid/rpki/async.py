"""
Utilities for event-driven programming.

$Id$

Copyright (C) 2009--2011  Internet Systems Consortium ("ISC")

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

import asyncore, signal, traceback, gc, sys
import rpki.log, rpki.sundial

ExitNow = asyncore.ExitNow

class iterator(object):
  """
  Iteration construct for event-driven code.  Takes three
  arguments:

  - Some kind of iterable object

  - A callback to call on each item in the iteration

  - A callback to call after the iteration terminates.

  The item callback receives two arguments: the callable iterator
  object and the current value of the iteration.  It should call the
  iterator (or arrange for the iterator to be called) when it is time
  to continue to the next item in the iteration.

  The termination callback receives no arguments.

  Special case for memory constrained cases: if keyword argument
  pop_list is True, iterable must be a list, which is modified in
  place, popping items off of it until it's empty.
  """

  def __init__(self, iterable, item_callback, done_callback, unwind_stack = True, pop_list = False):
    assert not pop_list or isinstance(iterable, list), "iterable must be a list when using pop_list"
    self.item_callback = item_callback
    self.done_callback = done_callback
    self.caller_file, self.caller_line, self.caller_function = traceback.extract_stack(limit = 2)[0][0:3]
    self.unwind_stack = unwind_stack
    self.pop_list = pop_list
    try:
      if self.pop_list:
        self.iterator = iterable
      else:
        self.iterator = iter(iterable)
    except (ExitNow, SystemExit):
      raise
    except Exception:
      rpki.log.debug("Problem constructing iterator for %r" % (iterable,))
      raise
    self.doit()

  def __repr__(self):
    return ("<%s created at %s:%s %s at 0x%x>" %
            (self.__class__.__name__,
             self.caller_file, self.caller_line, self.caller_function, id(self)))

  def __call__(self):
    if self.unwind_stack:
      event_defer(self.doit)
    else:
      self.doit()

  def doit(self):
    """
    Implement the iterator protocol: attempt to call the item handler
    with the next iteration value, call the termination handler if the
    iterator signaled StopIteration.
    """
    if self.pop_list:
      if self.iterator:
        self.item_callback(self, self.iterator.pop(0))
      elif self.done_callback is not None:
        self.done_callback()
    else:
      try:
        self.item_callback(self, self.iterator.next())
      except StopIteration:
        if self.done_callback is not None:
          self.done_callback()


## @var timer_queue
# Timer queue.

timer_queue = []

class timer(object):
  """
  Timer construct for event-driven code.  It can be used in either of two ways:

  - As a virtual class, in which case the subclass should provide a
    handler() method to receive the wakup event when the timer expires; or

  - By setting an explicit handler callback, either via the
    constructor or the set_handler() method.

  Subclassing is probably more Pythonic, but setting an explict
  handler turns out to be very convenient when combined with bound
  methods to other objects.
  """

  ## @var gc_debug
  # Verbose chatter about timers states and garbage collection.
  gc_debug = False

  ## @var run_debug
  # Verbose chatter about timers being run.
  run_debug = False

  def __init__(self, handler = None, errback = None):
    if handler is not None:
      self.set_handler(handler)
    if errback is not None:
      self.set_errback(errback)
    self.when = None
    if self.gc_debug:
      self.trace("Creating %r" % self)

  def trace(self, msg):
    """
    Debug logging.
    """
    if self.gc_debug:
      bt = traceback.extract_stack(limit = 3)
      rpki.log.debug("%s from %s:%d" % (msg, bt[0][0], bt[0][1]))

  def set(self, when):
    """
    Set a timer.  Argument can be a datetime, to specify an absolute
    time, or a timedelta, to specify an offset time.
    """
    if self.gc_debug:
      self.trace("Setting %r to %r" % (self, when))
    if isinstance(when, rpki.sundial.timedelta):
      self.when = rpki.sundial.now() + when
    else:
      self.when = when
    assert isinstance(self.when, rpki.sundial.datetime), "%r: Expecting a datetime, got %r" % (self, self.when)
    if self not in timer_queue:
      timer_queue.append(self)
    timer_queue.sort(key = lambda x: x.when)

  def __cmp__(self, other):
    return cmp(id(self), id(other))

  if gc_debug:
    def __del__(self):
      rpki.log.debug("Deleting %r" % self)

  def cancel(self):
    """
    Cancel a timer, if it was set.
    """
    if self.gc_debug:
      self.trace("Canceling %r" % self)
    try:
      while True:
        timer_queue.remove(self)
    except ValueError:
      pass

  def is_set(self):
    """
    Test whether this timer is currently set.
    """
    return self in timer_queue

  def handler(self):
    """
    Handle a timer that has expired.  This must either be overriden by
    a subclass or set dynamically by set_handler().
    """
    raise NotImplementedError

  def set_handler(self, handler):
    """
    Set timer's expiration handler.  This is an alternative to
    subclassing the timer class, and may be easier to use when
    integrating timers into other classes (eg, the handler can be a
    bound method to an object in a class representing a network
    connection).
    """
    self.handler = handler

  def errback(self, e):
    """
    Error callback.  May be overridden, or set with set_errback().
    """
    rpki.log.error("Unhandled exception from timer: %s" % e)
    rpki.log.traceback()

  def set_errback(self, errback):
    """
    Set a timer's errback.  Like set_handler(), for errbacks.
    """
    self.errback = errback

  @classmethod
  def runq(cls):
    """
    Run the timer queue: for each timer whose call time has passed,
    pull the timer off the queue and call its handler() method.
    """
    if timer_queue and rpki.sundial.now() >= timer_queue[0].when:
      t = timer_queue.pop(0)
      if cls.run_debug:
        rpki.log.debug("Running %r" % t)
      try:
        t.handler()
      except (ExitNow, SystemExit):
        raise
      except Exception, e:
        t.errback(e)

  def __repr__(self):
    return rpki.log.log_repr(self, self.when, repr(self.handler))

  @classmethod
  def seconds_until_wakeup(cls):
    """
    Calculate delay until next timer expires, or None if no timers are
    set and we should wait indefinitely.  Rounds up to avoid spinning
    in select() or poll().  We could calculate fractional seconds in
    the right units instead, but select() and poll() don't even take
    the same units (argh!), and we're not doing anything that
    hair-triggered, so rounding up is simplest.
    """
    if not timer_queue:
      return None
    now = rpki.sundial.now()
    if now >= timer_queue[0].when:
      return 0
    delay = timer_queue[0].when - now
    seconds = delay.convert_to_seconds()
    if delay.microseconds:
      seconds += 1
    return seconds

  @classmethod
  def clear(cls):
    """
    Cancel every timer on the queue.  We could just throw away the
    queue content, but this way we can notify subclasses that provide
    their own cancel() method.
    """
    while timer_queue:
      timer_queue.pop(0).cancel()

def _raiseExitNow(signum, frame):
  """
  Signal handler for event_loop().
  """
  raise ExitNow

def exit_event_loop():
  """
  Force exit from event_loop().
  """
  raise ExitNow

def event_defer(handler, delay = rpki.sundial.timedelta(seconds = 0)):
  """
  Use a near-term (default: zero interval) timer to schedule an event
  to run after letting the I/O system have a turn.
  """
  timer(handler).set(delay)

## @var debug_event_timing
# Enable insanely verbose logging of event timing

debug_event_timing = False

def event_loop(catch_signals = (signal.SIGINT, signal.SIGTERM)):
  """
  Replacement for asyncore.loop(), adding timer and signal support.
  """
  old_signal_handlers = {}
  while True:
    save_sigs = len(old_signal_handlers) == 0
    try:
      for sig in catch_signals:
        old = signal.signal(sig, _raiseExitNow)
        if save_sigs:
          old_signal_handlers[sig] = old
      while asyncore.socket_map or timer_queue:
        t = timer.seconds_until_wakeup()
        if debug_event_timing:
          rpki.log.debug("Dismissing to asyncore.poll(), t = %s, q = %r" % (t, timer_queue))
        asyncore.poll(t, asyncore.socket_map)
        timer.runq()
        if timer.gc_debug:
          gc.collect()
          if gc.garbage:
            for i in gc.garbage:
              rpki.log.debug("GC-cycle %r" % i)
            del gc.garbage[:]
    except ExitNow:
      break
    except SystemExit:
      raise
    except ValueError, e:
      if str(e) == "filedescriptor out of range in select()":
        rpki.log.error("Something is badly wrong, select() thinks we gave it a bad file descriptor.")
        rpki.log.error("Content of asyncore.socket_map:")
        for fd in sorted(asyncore.socket_map.iterkeys()):
          rpki.log.error("  fd %s obj %r" % (fd, asyncore.socket_map[fd]))
        rpki.log.error("Not safe to continue due to risk of spin loop on select().  Exiting.")
        sys.exit(1)
      rpki.log.error("event_loop() exited with exception %r, this is not supposed to happen, restarting" % e)
    except Exception, e:
      rpki.log.error("event_loop() exited with exception %r, this is not supposed to happen, restarting" % e)
    else:
      break
    finally:
      for sig in old_signal_handlers:
        signal.signal(sig, old_signal_handlers[sig])

class sync_wrapper(object):
  """
  Synchronous wrapper around asynchronous functions.  Running in
  asynchronous mode at all times makes sense for event-driven daemons,
  but is kind of tedious for simple scripts, hence this wrapper.

  The wrapped function should take at least two arguments: a callback
  function and an errback function.  If any arguments are passed to
  the wrapper, they will be passed as additional arguments to the
  wrapped function.
  """

  res = None
  err = None

  def __init__(self, func):
    self.func = func

  def cb(self, res = None):
    """
    Wrapped code has requested normal termination.  Store result, and
    exit the event loop.
    """
    self.res = res
    raise ExitNow

  def eb(self, err):
    """
    Wrapped code raised an exception.  Store exception data, then exit
    the event loop.
    """
    exc_info = sys.exc_info()
    self.err = exc_info if exc_info[1] is err else err
    raise ExitNow

  def __call__(self, *args, **kwargs):

    def thunk():
      try:
        self.func(self.cb, self.eb, *args, **kwargs)
      except ExitNow:
        raise
      except Exception, e:
        self.eb(e)
      
    event_defer(thunk)
    event_loop()
    if self.err is None:
      return self.res
    elif isinstance(self.err, tuple):
      raise self.err[0], self.err[1], self.err[2]
    else:
      raise self.err

class gc_summary(object):
  """
  Periodic summary of GC state, for tracking down memory bloat.
  """

  def __init__(self, interval, threshold = 0):
    if isinstance(interval, (int, long)):
      interval = rpki.sundial.timedelta(seconds = interval)
    self.interval = interval
    self.threshold = threshold
    self.timer = timer(handler = self.handler)
    self.timer.set(self.interval)

  def handler(self):
    """
    Collect and log GC state for this period, reset timer.
    """
    rpki.log.debug("gc_summary: Running gc.collect()")
    gc.collect()
    rpki.log.debug("gc_summary: Summarizing (threshold %d)" % self.threshold)
    total = {}
    tuples = {}
    for g in gc.get_objects():
      k = type(g).__name__
      total[k] = total.get(k, 0) + 1
      if isinstance(g, tuple):
        k = ", ".join(type(x).__name__ for x in g)
        tuples[k] = tuples.get(k, 0) + 1
    rpki.log.debug("gc_summary: Sorting result")
    total = total.items()
    total.sort(reverse = True, key = lambda x: x[1])
    tuples = tuples.items()
    tuples.sort(reverse = True, key = lambda x: x[1])
    rpki.log.debug("gc_summary: Object type counts in descending order")
    for name, count in total:
      if count > self.threshold:
        rpki.log.debug("gc_summary: %8d %s" % (count, name))
    rpki.log.debug("gc_summary: Tuple content type signature counts in descending order")
    for types, count in tuples:
      if count > self.threshold:
        rpki.log.debug("gc_summary: %8d (%s)" % (count, types))
    rpki.log.debug("gc_summary: Scheduling next cycle")
    self.timer.set(self.interval)
