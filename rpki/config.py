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
Configuration file parsing utilities, layered on top of stock Python
ConfigParser module.
"""

import ConfigParser
import logging
import os
import re

logger = logging.getLogger(__name__)

## @var default_filename
# Default name of config file if caller doesn't specify one explictly.

try:
  import rpki.autoconf
  default_filename = os.path.join(rpki.autoconf.sysconfdir, "rpki.conf")
except ImportError:
  default_filename = None

## @var rpki_conf_envname
# Name of environment variable containing config file name.

rpki_conf_envname = "RPKI_CONF"

class parser(object):
  """
  Extensions to stock Python ConfigParser:

  Read config file and set default section while initializing parser object.

  Support for OpenSSL-style subscripted options and a limited form of
  OpenSSL-style indirect variable references (${section::option}).

  get-methods with default values and default section name.

  If no filename is given to the constructor (filename and
  set_filename both None), we check for an environment variable naming
  the config file, then finally we check for a global config file if
  autoconf provided a directory name to check.

  NB: Programs which accept a configuration filename on the command
  lines should pass that filename using set_filename so that we can
  set the magic environment variable.  Constraints from some external
  libraries (principally Django) sometimes require library code to
  look things up in the configuration file without the knowledge of
  the controlling program, but setting the environment variable
  insures that everybody's reading from the same script, as it were.
  """

  # Odd keyword-only calling sequence is a defense against old code
  # that thinks it knows how __init__() handles positional arguments.

  def __init__(self, **kwargs):
    section       = kwargs.pop("section",       None)
    allow_missing = kwargs.pop("allow_missing", False)
    set_filename  = kwargs.pop("set_filename",  None)
    filename      = kwargs.pop("filename",      set_filename)

    assert not kwargs, "Unexpected keyword arguments: " + ", ".join("%s = %r" % kv for kv in kwargs.iteritems())

    if set_filename is not None:
      os.environ[rpki_conf_envname] = set_filename

    self.cfg = ConfigParser.RawConfigParser()
    self.default_section = section

    self.filename = filename or os.getenv(rpki_conf_envname) or default_filename

    try:
      with open(self.filename, "r") as f:
        self.cfg.readfp(f)
    except IOError:
      if allow_missing:
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

    Returns iteration of values matching the specified option name.
    """

    matches = []
    if section is None:
      section = self.default_section
    if self.cfg.has_option(section, option):
      yield self.cfg.get(section, option)
    option += "."
    matches = [o for o in self.cfg.options(section) if o.startswith(option) and o[len(option):].isdigit()]
    matches.sort()
    for option in matches:
      yield self.cfg.get(section, option)


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
        raise ValueError("Not a boolean: %s" % v)
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

    # pylint: disable=W0621
    import rpki.http
    import rpki.x509
    import rpki.async
    import rpki.log
    import rpki.daemonize

    for line in self.multiget("configure_logger"):
      try:
        name, level = line.split()
        logging.getLogger(name).setLevel(getattr(logging, level.upper()))
      except Exception, e:
        logger.warning("Could not process configure_logger line %r: %s", line, e)

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
      logger.warning("Couldn't initialize mailbox %s: %s", self.get("dump_outbound_cms"), e)
    except ConfigParser.NoOptionError:
      pass

    try:
      rpki.x509.XML_CMS_object.dump_inbound_cms = rpki.x509.DeadDrop(self.get("dump_inbound_cms"))
    except OSError, e:
      logger.warning("Couldn't initialize mailbox %s: %s", self.get("dump_inbound_cms"), e)
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
    except:                             # pylint: disable=W0702
      logger.warning("insecure-debug-only-rsa-key-db configured but initialization failed, check for corrupted database file")

    try:
      rpki.up_down.content_type = self.get("up_down_content_type")
    except ConfigParser.NoOptionError:
      pass
