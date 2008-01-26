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

"""Unified RPKI date/time handling, based on the standard Python datetime module.

Module name chosen to sidestep a nightmare of import-related errors
that occur with the more obvious module names.
"""

import datetime as pydatetime

class datetime(pydatetime.datetime):
  """RPKI extensions to standard datetime.datetime class.  All work
  here is in UTC, so we use naive datetime objects.
  """

  def totimestamp(self):
    """Convert to seconds from epoch (like time.time()).  Conversion
    method is a bit silly, but avoids time module timezone whackiness.
    """
    return int(self.strftime("%s"))

  @classmethod
  def fromUTCTime(cls, x):
    """Convert from ASN.1 UTCTime."""
    return cls.strptime(x, "%y%m%d%H%M%SZ")

  def toUTCTime(self):
    """Convert to ASN.1 UTCTime."""
    return self.strftime("%y%m%d%H%M%SZ")

  @classmethod
  def fromGeneralizedTime(cls, x):
    """Convert from ASN.1 GeneralizedTime."""
    return cls.strptime(x, "%Y%m%d%H%M%SZ")

  def toGeneralizedTime(self):
    """Convert to ASN.1 GeneralizedTime."""
    return self.strftime("%Y%m%d%H%M%SZ")

  @classmethod
  def fromASN1tuple(cls, x):
    """Convert from ASN.1 tuple representation."""
    assert isinstance(x, tuple) and len(x) == 2 and x[0] in ("utcTime", "generalTime")
    if x[0] == "utcTime":
      return cls.fromUTCTime(x[1])
    else:
      return cls.fromGeneralizedTime(x[1])

  ## @var PKIX_threshhold
  # Threshold specified in RFC 3280 for switchover from UTCTime to GeneralizedTime.

  PKIX_threshhold = pydatetime.datetime(2050, 1, 1)

  def toASN1tuple(self):
    """Convert to ASN.1 tuple representation."""
    if self < self.PKIX_threshhold:
      return "utcTime", self.toUTCTime()
    else:
      return "generalTime", self.toGeneralizedTime()

  @classmethod
  def fromXMLtime(cls, x):
    """Convert from XML time representation."""
    return cls.strptime(x, "%Y-%m-%dT%H:%M:%SZ")

  def toXMLtime(self):
    """Convert to XML time representation."""
    return self.strftime("%Y-%m-%dT%H:%M:%SZ")

  @classmethod
  def fromdatetime(cls, x):
    """Convert a datetime.datetime object into this subclass.
    This is whacky due to the weird constructors for datetime.
    """
    return cls.combine(x.date(), x.time())

  def __add__(self, other):
    """Force correct class for timedelta results."""
    return self.fromdatetime(pydatetime.datetime.__add__(self, other))
  
  def __sub__(self, other):
    """Force correct class for timedelta results."""
    return self.fromdatetime(pydatetime.datetime.__sub__(self, other))
  
  @classmethod
  def from_sql(cls, x):
    """Convert from SQL storage format."""
    return cls.fromdatetime(x)

  def to_sql(self):
    """Convert to SQL storage format."""
    return self

  def later(self, other):
    """Return the later of two timestamps."""
    return other if other > self else self

  def earlier(self, other):
    """Return the earlier of two timestamps."""
    return other if other < self else self

# Alias to simplify imports for callers

timedelta = pydatetime.timedelta

if __name__ == "__main__":

  now = datetime.utcnow()
  print now
  print repr(now)
  print now.strftime("%s")
  print now.toUTCTime()
  print now.toGeneralizedTime()
  print now.toASN1tuple()
  print now.toXMLtime()

  print

  then = now
  then += timedelta(days = 30)
  print then
  print repr(then)
  print then.strftime("%s")
  print then.toUTCTime()
  print then.toGeneralizedTime()
  print then.toASN1tuple()
  print then.toXMLtime()
