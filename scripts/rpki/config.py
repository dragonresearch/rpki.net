# $Id$

"""Configuration file parsing utilities.

Layered on top of stock Python ConfigParser module.
"""

import ConfigParser

class parser(ConfigParser.RawConfigParser):

  def __init__(self, file = None, section = None):
    """Initialize this parser."""
    ConfigParser.RawConfigParser.__init__(self)
    if file:
      self.read(file)
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
