"""
Unified RPKI date/time handling, based on the standard Python datetime module.

Module name chosen to sidestep a nightmare of import-related errors
that occur with the more obvious module names.

List of arithmetic methods that require result casting was derived by
inspection of the datetime module, to wit:

  >>> import datetime
  >>> for t in (datetime.datetime, datetime.timedelta):
  ...  for k in t.__dict__.keys():
  ...   if k.startswith("__"):
  ...    print "%s.%s()" % (t.__name__, k)

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

import datetime as pydatetime
import re

def now():
  """
  Get current timestamp.
  """
  return datetime.utcnow()

class ParseFailure(Exception):
  """
  Parse failure constructing timedelta.
  """

class datetime(pydatetime.datetime):
  """
  RPKI extensions to standard datetime.datetime class.  All work here
  is in UTC, so we use naive datetime objects.
  """

  def totimestamp(self):
    """
    Convert to seconds from epoch (like time.time()).  Conversion
    method is a bit silly, but avoids time module timezone whackiness.
    """
    return int(self.strftime("%s"))

  @classmethod
  def fromXMLtime(cls, x):
    """
    Convert from XML time representation.
    """
    if x is None:
      return None
    else:
      return cls.strptime(x, "%Y-%m-%dT%H:%M:%SZ")

  def toXMLtime(self):
    """
    Convert to XML time representation.
    """
    return self.strftime("%Y-%m-%dT%H:%M:%SZ")

  def __str__(self):
    return self.toXMLtime()

  @classmethod
  def fromdatetime(cls, x):
    """
    Convert a datetime.datetime object into this subclass.  This is
    whacky due to the weird constructors for datetime.
    """
    return cls.combine(x.date(), x.time())

  @classmethod
  def fromOpenSSL(cls, x):
    """
    Convert from the format OpenSSL's command line tool uses into this
    subclass.  May require rewriting if we run into locale problems.
    """
    if x.startswith("notBefore=") or x.startswith("notAfter="):
      x = x.partition("=")[2]
    return cls.strptime(x, "%b %d %H:%M:%S %Y GMT")

  @classmethod
  def from_sql(cls, x):
    """
    Convert from SQL storage format.
    """
    return cls.fromdatetime(x)

  def to_sql(self):
    """
    Convert to SQL storage format.

    There's something whacky going on in the MySQLdb module, it throws
    range errors when storing a derived type into a DATETIME column.
    Investigate some day, but for now brute force this by copying the
    relevant fields into a datetime.datetime for MySQLdb's
    consumption.

    """
    return pydatetime.datetime(year = self.year, month = self.month, day = self.day,
                               hour = self.hour, minute = self.minute, second = self.second,
                               microsecond = 0, tzinfo = None)

  def later(self, other):
    """
    Return the later of two timestamps.
    """
    return other if other > self else self

  def earlier(self, other):
    """
    Return the earlier of two timestamps.
    """
    return other if other < self else self

  def __add__(self, y):  return _cast(pydatetime.datetime.__add__(self, y))
  def __radd__(self, y): return _cast(pydatetime.datetime.__radd__(self, y))
  def __rsub__(self, y): return _cast(pydatetime.datetime.__rsub__(self, y))
  def __sub__(self, y):  return _cast(pydatetime.datetime.__sub__(self, y))

class timedelta(pydatetime.timedelta):
  """
  Timedelta with text parsing.  This accepts two input formats:

  - A simple integer, indicating a number of seconds.

  - A string of the form "uY vW wD xH yM zS" where u, v, w, x, y, and z
    are integers and Y, W, D, H, M, and S indicate years, weeks, days,
    hours, minutes, and seconds.  All of the fields are optional, but
    at least one must be specified.  Eg,"3D4H" means "three days plus
    four hours".

  There is no "months" format, because the definition of a month is too
  fuzzy to be useful (what day is six months from August 30th?)

  Similarly, the "years" conversion may produce surprising results, as
  "one year" in conventional English does not refer to a fixed interval
  but rather a fixed (and in some cases undefined) offset within the
  Gregorian calendar (what day is one year from February 29th?)  1Y as
  implemented by this code refers to a specific number of seconds.
  If you mean 365 days or 52 weeks, say that instead.
  """

  ## @var regexp
  # Hideously ugly regular expression to parse the complex text form.
  # Tags are intended for use with re.MatchObject.groupdict() and map
  # directly to the keywords expected by the timedelta constructor.

  regexp = re.compile("\\s*".join(("^",
                                   "(?:(?P<years>\\d+)Y)?",
                                   "(?:(?P<weeks>\\d+)W)?",
                                   "(?:(?P<days>\\d+)D)?",
                                   "(?:(?P<hours>\\d+)H)?",
                                   "(?:(?P<minutes>\\d+)M)?",
                                   "(?:(?P<seconds>\\d+)S)?",
                                   "$")),
                      re.I)

  ## @var years_to_seconds
  # Conversion factor from years to seconds (value furnished by the
  # "units" program).

  years_to_seconds = 31556926

  @classmethod
  def parse(cls, arg):
    """
    Parse text into a timedelta object.
    """
    if not isinstance(arg, str):
      return cls(seconds = arg)
    elif arg.isdigit():
      return cls(seconds = int(arg))
    else:
      match = cls.regexp.match(arg)
      if match:
        #return cls(**dict((k, int(v)) for (k, v) in match.groupdict().items() if v is not None))
        d = match.groupdict("0")
        for k, v in d.iteritems():
          d[k] = int(v)
        d["days"]    += d.pop("weeks") * 7
        d["seconds"] += d.pop("years") * cls.years_to_seconds
        return cls(**d)
      else:
        raise ParseFailure, "Couldn't parse timedelta %r" % (arg,)

  def convert_to_seconds(self):
    """
    Convert a timedelta interval to seconds.
    """
    return self.days * 24 * 60 * 60 + self.seconds

  @classmethod
  def fromtimedelta(cls, x):
    """
    Convert a datetime.timedelta object into this subclass.
    """
    return cls(days = x.days, seconds = x.seconds, microseconds = x.microseconds)

  def __abs__(self):          return _cast(pydatetime.timedelta.__abs__(self))
  def __add__(self, x):       return _cast(pydatetime.timedelta.__add__(self, x))
  def __div__(self, x):       return _cast(pydatetime.timedelta.__div__(self, x))
  def __floordiv__(self, x):  return _cast(pydatetime.timedelta.__floordiv__(self, x))
  def __mul__(self, x):       return _cast(pydatetime.timedelta.__mul__(self, x))
  def __neg__(self):          return _cast(pydatetime.timedelta.__neg__(self))
  def __pos__(self):          return _cast(pydatetime.timedelta.__pos__(self))
  def __radd__(self, x):      return _cast(pydatetime.timedelta.__radd__(self, x))
  def __rdiv__(self, x):      return _cast(pydatetime.timedelta.__rdiv__(self, x))
  def __rfloordiv__(self, x): return _cast(pydatetime.timedelta.__rfloordiv__(self, x))
  def __rmul__(self, x):      return _cast(pydatetime.timedelta.__rmul__(self, x))
  def __rsub__(self, x):      return _cast(pydatetime.timedelta.__rsub__(self, x))
  def __sub__(self, x):       return _cast(pydatetime.timedelta.__sub__(self, x))

def _cast(x):
  """
  Cast result of arithmetic operations back into correct subtype.
  """
  if isinstance(x, pydatetime.datetime):
    return datetime.fromdatetime(x)
  if isinstance(x, pydatetime.timedelta):
    return timedelta.fromtimedelta(x)
  return x

if __name__ == "__main__":

  def test(t):
    print
    print "str:                ", t
    print "repr:               ", repr(t)
    print "seconds since epoch:", t.strftime("%s")
    print "XMLtime:            ", t.toXMLtime()
    print

  print
  print "Testing time conversion routines"
  test(now())
  test(now() + timedelta(days = 30))
  test(now() + timedelta.parse("3d5s"))
  test(now() + timedelta.parse(" 3d 5s "))
  test(now() + timedelta.parse("1y3d5h"))
