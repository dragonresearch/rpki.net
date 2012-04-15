"""
CSV utilities, moved here from myrpki.py.

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

import csv
import os

class BadCSVSyntax(Exception):
  """
  Bad CSV syntax.
  """

class csv_reader(object):
  """
  Reader for tab-delimited text that's (slightly) friendlier than the
  stock Python csv module (which isn't intended for direct use by
  humans anyway, and neither was this package originally, but that
  seems to be the way that it has evolved...).

  Columns parameter specifies how many columns users of the reader
  expect to see; lines with fewer columns will be padded with None
  values.

  Original API design for this class courtesy of Warren Kumari, but
  don't blame him if you don't like what I did with his ideas.
  """

  def __init__(self, filename, columns = None, min_columns = None, comment_characters = "#;"):
    assert columns is None or isinstance(columns, int)
    assert min_columns is None or isinstance(min_columns, int)
    if columns is not None and min_columns is None:
      min_columns = columns
    self.filename = filename
    self.columns = columns
    self.min_columns = min_columns
    self.comment_characters = comment_characters 
    self.file = open(filename, "r")

  def __iter__(self):
    line_number = 0
    for line in self.file:
      line_number += 1
      line = line.strip()
      if not line or line[0] in self.comment_characters:
        continue
      fields = line.split()
      if self.min_columns is not None and len(fields) < self.min_columns:
        raise BadCSVSyntax, "%s:%d: Not enough columns in line %r" % (self.filename, line_number, line)
      if self.columns is not None and len(fields) > self.columns:
        raise BadCSVSyntax, "%s:%d: Too many  columns in line %r" % (self.filename, line_number, line)
      if self.columns is not None and len(fields) < self.columns:
        fields += tuple(None for i in xrange(self.columns - len(fields)))
      yield fields

class csv_writer(object):
  """
  Writer object for tab delimited text.  We just use the stock CSV
  module in excel-tab mode for this.

  If "renmwo" is set (default), the file will be written to
  a temporary name and renamed to the real filename after closing.
  """

  def __init__(self, filename, renmwo = True):
    self.filename = filename
    self.renmwo = "%s.~renmwo%d~" % (filename, os.getpid()) if renmwo else filename
    self.file = open(self.renmwo, "w")
    self.writer = csv.writer(self.file, dialect = csv.get_dialect("excel-tab"))

  def close(self):
    """
    Close this writer.
    """
    if self.file is not None:
      self.file.close()
      self.file = None
      if self.filename != self.renmwo:
        os.rename(self.renmwo, self.filename)

  def __getattr__(self, attr):
    """
    Fake inheritance from whatever object csv.writer deigns to give us.
    """
    return getattr(self.writer, attr)
