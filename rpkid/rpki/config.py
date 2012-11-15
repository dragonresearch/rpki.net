"""
Configuration file parsing utilities, layered on top of stock Python
ConfigParser module.

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

import ConfigParser
import os
import re

## @var default_filename
# Default name of config file if caller doesn't specify one explictly.

default_filename = "rpki.conf"

## @var default_dirname
# Default name of directory to check for global config file, or None
# if no global config file.  Autoconf-generated code may set this to a
# non-None value during script startup.

default_dirname = None

## @var default_envname
# Name of environment variable containing config file name.

default_envname = "RPKI_CONF"

class parser(object):
  """
  Extensions to stock Python ConfigParser:

  Read config file and set default section while initializing parser object.

  Support for OpenSSL-style subscripted options and a limited form of
  OpenSSL-style indirect variable references (${section::option}).

  get-methods with default values and default section name.

  If no filename is given to the constructor (filename = None), we
  check for an environment variable naming the config file, then we
  check for a default filename in the current directory, then finally
  we check for a global config file if autoconf provided a directory
  name to check.
  """

  def __init__(self, filename = None, section = None, allow_missing = False):

    self.cfg = ConfigParser.RawConfigParser()
    self.default_section = section

    filenames = []
    if filename is not None:
      filenames.append(filename)
    else:
      if default_envname in os.environ:
        filenames.append(os.environ[default_envname])
      filenames.append(default_filename)
      if default_dirname is not None:
        filenames.append("%s/%s" % (default_dirname, default_filename))

    f = fn = None

    for fn in filenames:
      try:
        f = open(fn)
        break
      except IOError:
        f = None

    if f is not None:
      self.filename = fn
      self.cfg.readfp(f, fn)
    elif allow_missing:
      self.filename = None
    else:
      raise

  def has_section(self, section):
    """
    Test whether a section exists.
    """

    return self.cfg.has_section(section)

  def has_option(self, option, section = None):
    """
    Test whether an option exists.
    """

    if section is None:
      section = self.default_section
    return self.cfg.has_option(section, option)

  def multiget(self, option, section = None):
    """
    Parse OpenSSL-style foo.0, foo.1, ... subscripted options.

    Returns a list of values matching the specified option name.
    """

    matches = []
    if section is None:
      section = self.default_section
    if self.cfg.has_option(section, option):
      matches.append((-1, self.get(option, section = section)))
    for key in self.cfg.options(section):
      s = key.rsplit(".", 1)
      if len(s) == 2 and s[0] == option and s[1].isdigit():
        matches.append((int(s[1]), self.get(option, section = section)))
    matches.sort()
    return [match[1] for match in matches]

  _regexp = re.compile("\\${(.*?)::(.*?)}")

  def _repl(self, m):
    """
    Replacement function for indirect variable substitution.
    This is intended for use with re.subn().
    """
    section, option = m.group(1, 2)
    if section == "ENV":
      return os.getenv(option, "")
    else:
      return self.cfg.get(section, option)

  def get(self, option, default = None, section = None):
    """
    Get an option, perhaps with a default value.
    """
    if section is None:
      section = self.default_section
    if default is not None and not self.cfg.has_option(section, option):
      return default
    val = self.cfg.get(section, option)
    while True:
      val, modified = self._regexp.subn(self._repl, val, 1)
      if not modified:
        return val

  def getboolean(self, option, default = None, section = None):
    """
    Get a boolean option, perhaps with a default value.
    """
    v = self.get(option, default, section)
    if isinstance(v, str):
      v = v.lower()
      if v not in self.cfg._boolean_states:
        raise ValueError, "Not a boolean: %s" % v
      v = self.cfg._boolean_states[v]
    return v

  def getint(self, option, default = None, section = None):
    """
    Get an integer option, perhaps with a default value.
    """
    return int(self.get(option, default, section))

  def getlong(self, option, default = None, section = None):
    """
    Get a long integer option, perhaps with a default value.
    """
    return long(self.get(option, default, section))

  def set_global_flags(self):
    """
    Consolidated control for all the little global control flags
    scattered through the libraries.  This isn't a particularly good
    place for this function to live, but it has to live somewhere and
    making it a method of the config parser from which it gets all of
    its data is less silly than the available alternatives.
    """

    import rpki.http
    import rpki.x509
    import rpki.sql
    import rpki.async
    import rpki.log
    import rpki.daemonize

    try:
      rpki.http.debug_http = self.getboolean("debug_http")
    except ConfigParser.NoOptionError:
      pass

    try:
      rpki.http.want_persistent_client = self.getboolean("want_persistent_client")
    except ConfigParser.NoOptionError:
      pass

    try:
      rpki.http.want_persistent_server = self.getboolean("want_persistent_server")
    except ConfigParser.NoOptionError:
      pass

    try:
      rpki.http.use_adns = self.getboolean("use_adns")
    except ConfigParser.NoOptionError:
      pass

    try:
      rpki.http.enable_ipv6_clients = self.getboolean("enable_ipv6_clients")
    except ConfigParser.NoOptionError:
      pass

    try:
      rpki.http.enable_ipv6_servers = self.getboolean("enable_ipv6_servers")
    except ConfigParser.NoOptionError:
      pass

    try:
      rpki.x509.CMS_object.debug_cms_certs = self.getboolean("debug_cms_certs")
    except ConfigParser.NoOptionError:
      pass

    try:
      rpki.sql.sql_persistent.sql_debug = self.getboolean("sql_debug")
    except ConfigParser.NoOptionError:
      pass

    try:
      rpki.async.timer.gc_debug = self.getboolean("gc_debug")
    except ConfigParser.NoOptionError:
      pass

    try:
      rpki.async.timer.run_debug = self.getboolean("timer_debug")
    except ConfigParser.NoOptionError:
      pass

    try:
      rpki.x509.XML_CMS_object.dump_outbound_cms = rpki.x509.DeadDrop(self.get("dump_outbound_cms"))
    except OSError, e:
      rpki.log.warn("Couldn't initialize mailbox %s: %s" % (self.get("dump_outbound_cms"), e))
    except ConfigParser.NoOptionError:
      pass

    try:
      rpki.x509.XML_CMS_object.dump_inbound_cms = rpki.x509.DeadDrop(self.get("dump_inbound_cms"))
    except OSError, e:
      rpki.log.warn("Couldn't initialize mailbox %s: %s" % (self.get("dump_inbound_cms"), e))
    except ConfigParser.NoOptionError:
      pass

    try:
      rpki.x509.XML_CMS_object.check_inbound_schema = self.getboolean("check_inbound_schema")
    except ConfigParser.NoOptionError:
      pass

    try:
      rpki.x509.XML_CMS_object.check_outbound_schema = self.getboolean("check_outbound_schema")
    except ConfigParser.NoOptionError:
      pass

    try:
      rpki.async.gc_summary(self.getint("gc_summary"), self.getint("gc_summary_threshold", 0))
    except ConfigParser.NoOptionError:
      pass

    try:
      rpki.log.enable_tracebacks = self.getboolean("enable_tracebacks")
    except ConfigParser.NoOptionError:
      pass

    try:
      rpki.daemonize.default_pid_directory = self.get("pid_directory")
    except ConfigParser.NoOptionError:
      pass

    try:
      rpki.daemonize.pid_filename = self.get("pid_filename")
    except ConfigParser.NoOptionError:
      pass

    try:
      rpki.x509.generate_insecure_debug_only_rsa_key = rpki.x509.insecure_debug_only_rsa_key_generator(*self.get("insecure-debug-only-rsa-key-db").split())
    except ConfigParser.NoOptionError:
      pass
    except:
      rpki.log.warn("insecure-debug-only-rsa-key-db configured but initialization failed, check for corrupted database file")
