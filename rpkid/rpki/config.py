"""Configuration file parsing utilities, layered on top of stock
Python ConfigParser module.

$Id$

Copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")

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

import ConfigParser

class parser(ConfigParser.RawConfigParser):

  def __init__(self, filename = None, section = None):
    """Initialize this parser."""
    ConfigParser.RawConfigParser.__init__(self)
    if filename:
      self.read(filename)
    self.default_section = section

  def multiget(self, option, section = None):
    """Parse OpenSSL-style foo.0, foo.1, ... subscripted options.

    Returns a list of values matching the specified option name.
    """
    matches = []
    if section is None:
      section = self.default_section
    if self.has_option(section, option):
      matches.append((-1, self.get(option, section = section)))
    for key, value in self.items(section):
      s = key.rsplit(".", 1)
      if len(s) == 2 and s[0] == option and s[1].isdigit():
        matches.append((int(s[1]), value))
    matches.sort()
    return [match[1] for match in matches]

  def get(self, option, default = None, section = None):
    """Get an option, perhaps with a default value."""
    if section is None:
      section = self.default_section
    if default is None or self.has_option(section, option):
      return ConfigParser.RawConfigParser.get(self, section, option)
    else:
      return default
