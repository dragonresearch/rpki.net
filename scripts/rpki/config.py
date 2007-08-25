# $Id$

"""Configuration file parsing utilities.

Layered on top of stock Python ConfigParser module.
"""

import ConfigParser

class parser(ConfigParser.RawConfigParser):

  def __init__(self, file=None):
    super(parser, self).__init__()
    if file:
      self.read(file)

  def multiget(self, section, option):
    """Parse OpenSSL-style foo.0, foo.1, ... subscripted options.

    Returns a list of values matching the specified option name.
    """
    matches = []
    for key, value in self.items():
      name, index = key.rsplit(".", 1)
      if name == option and index.isdigit():
        matches.append(tuple(int(index), value))
    matches.sort()
    return [match[1] for match in matches]

  def get(self, section, option, default=None):
    """Get an option, perhaps with a default value."""
    if default is None or self.has_option(section, option):
      return super(parser, self).get(section, option)
    else:
      return default
