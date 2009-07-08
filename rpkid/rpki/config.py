"""
Configuration file parsing utilities, layered on top of stock Python
ConfigParser module.

$Id$

Copyright (C) 2009  Internet Systems Consortium ("ISC")

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

import ConfigParser

class parser(ConfigParser.RawConfigParser):
  """
  Extensions to stock Python ConfigParser:

  Read config file and set default section while initializing parser object.

  Support for OpenSSL-style subscripted options.

  get-methods with default values and default section name.
  """

  def __init__(self, filename = None, section = None):
    """
    Initialize this parser.
    """
    ConfigParser.RawConfigParser.__init__(self)
    if filename:
      self.read(filename)
    self.default_section = section

  def multiget(self, option, section = None):
    """
    Parse OpenSSL-style foo.0, foo.1, ... subscripted options.

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

  def _get_wrapper(self, method, section, option, default):
    """
    Wrapper method to add default value and default section support to
    ConfigParser methods.
    """
    if section is None:
      section = self.default_section
    if default is None or self.has_option(section, option):
      return method(self, section, option)
    else:
      return default


  def get(self, option, default = None, section = None):
    """
    Get an option, perhaps with a default value.
    """
    return self._get_wrapper(ConfigParser.RawConfigParser.get,
                             section, option, default)

  def getboolean(self, option, default = None, section = None):
    """
    Get a boolean option, perhaps with a default value.
    """
    return self._get_wrapper(ConfigParser.RawConfigParser.getboolean,
                             section, option, default)
