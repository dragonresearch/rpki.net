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
import argparse
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
        argparser     = kwargs.pop("argparser",     None)

        assert not kwargs, "Unexpected keyword arguments: {}".format(
            ", ".join("{} = {!r}".format(k, v) for k, v in kwargs.iteritems()))

        if set_filename is not None:
            os.environ[rpki_conf_envname] = set_filename

        self.cfg = ConfigParser.RawConfigParser()
        self.default_section = section

        self.filename = filename or os.getenv(rpki_conf_envname) or default_filename
        self.argparser = argparser

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
        matches = [o for o in self.cfg.options(section) 
                   if o.startswith(option) and o[len(option):].isdigit()]
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

        # pylint: disable=W0212
        v = self.get(option, default, section)
        if isinstance(v, str):
            v = v.lower()
            if v not in self.cfg._boolean_states:
                raise ValueError("Not boolean: {}".format(v))
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


    def add_argument(self, *names, **kwargs):
        """
        Combined command line and config file argument.  Takes
        arguments mostly like ArgumentParser.add_argument(), but also
        looks in config file for option of the same name.

        The "section" and "default" arguments are used for the config file
        lookup; the resulting value is used as the "default" parameter for 
        the argument parser.

        If a "type" argument is specified, it applies to both the value
        parsed from the config file and the argument parser.
        """

        section = kwargs.pop("section", None)
        default = kwargs.pop("default", None)

        for name in names:
            if name.startswith("--"):
                name = name[2:]
                break
        else:
            raise ValueError

        default = self.get(name, default = default, section = section)

        if "type" in kwargs:
            default = kwargs["type"](default)

        kwargs["default"] = default

        return self.argparser.add_argument(*names, **kwargs)

    def add_boolean_argument(self, name, **kwargs):
        """
        Combined command line and config file boolean argument.  Takes
        arguments mostly like ArgumentParser.add_argument(), but also
        looks in config file for option of the same name.

        The "section" and "default" arguments are used for the config file
        lookup; the resulting value is used as the default value for 
        the argument parser.

        Usage is a bit different from the normal ArgumentParser boolean
        handling: because the command line default is controlled by the
        config file, the "store_true" / "store_false" semantics don't
        really work for us.  So, instead, we use the --foo / --no-foo
        convention, and generate a pair of command line arguments with
        those names controlling a single "foo" value in the result.
        """

        section = kwargs.pop("section", None)
        default = kwargs.pop("default", None)
        help    = kwargs.pop("help",    None)

        if not name.startswith("--"):
            raise ValueError
        name = name[2:]

        default = self.getboolean(name, default = default, section = section)

        kwargs["action"] = "store_const"
        kwargs["dest"] = name.replace("-", "_")

        group = self.argparser.add_mutually_exclusive_group()

        kwargs["const"] = True
        group.add_argument("--" + name, **kwargs)

        kwargs["const"] = False
        kwargs["help"] = help
        group.add_argument("--no-" + name, **kwargs)

        self.argparser.set_defaults(**{ kwargs["dest"] : default })

    def set_global_flags(self):
        """
        Consolidated control for all the little global control flags
        scattered through the libraries.  This isn't a particularly good
        place for this function to live, but it has to live somewhere and
        making it a method of the config parser from which it gets all of
        its data is less silly than the available alternatives.
        """

        # pylint: disable=W0621
        import rpki.x509
        import rpki.log
        import rpki.daemonize

        for line in self.multiget("configure_logger"):
            try:
                name, level = line.split()
                logging.getLogger(name).setLevel(getattr(logging, level.upper()))
            except Exception, e:
                logger.warning("Could not process configure_logger line %r: %s", line, e)

        try:
            rpki.x509.CMS_object.debug_cms_certs = self.getboolean("debug_cms_certs")
        except ConfigParser.NoOptionError:
            pass

        try:
            rpki.x509.XML_CMS_object.dump_outbound_cms = rpki.x509.DeadDrop(
                self.get("dump_outbound_cms"))
        except OSError, e:
            logger.warning("Couldn't initialize mailbox %s: %s", self.get("dump_outbound_cms"), e)
        except ConfigParser.NoOptionError:
            pass

        try:
            rpki.x509.XML_CMS_object.dump_inbound_cms = rpki.x509.DeadDrop(
                self.get("dump_inbound_cms"))
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
            logger.warning("insecure-debug-only-rsa-key-db configured but initialization failed, check for corrupted database file")

        try:
            rpki.up_down.content_type = self.get("up_down_content_type")
        except ConfigParser.NoOptionError:
            pass


def argparser(section = None, doc = None, cfg_optional = False):
    """
    First cut at a combined configuration mechanism based on ConfigParser and argparse.

    General idea here is to do an initial pass on the arguments to handle the config file,
    then return the config file and a parser to use for the rest of the arguments.
    """

    # Basic approach here is a variation on:
    # http://blog.vwelch.com/2011/04/combining-configparser-and-argparse.html

    # For most of our uses of argparse, this should be a trivial
    # drop-in, and should reduce the amount of repetitive code.  There
    # are a couple of special cases which will require attention:
    #
    # - rpki.rtr: The rpki-rtr modules have their own handling of all
    #   the logging setup, and use an argparse subparser.  I -think-
    #   that the way they're already handling the logging setup should
    #   work fine, but there may be a few tricky bits reconciling the
    #   rpki-rtr logging setup with the generalized version in rpki.log.
    #
    # - rpki.rpkic: Use of argparse in rpkic is very complicated due to
    #   support for both the external command line and the internal
    #   command loop.  Overall it works quite well, but the setup is
    #   tricky.  rpki.rpkic.main.top_argparse may need to move outside
    #   the main class, but that may raise its own issues.  Maybe we
    #   can get away with just replacing the current setup of
    #   top_argparser with a call to this function and otherwise
    #   leaving the whole structure alone?  Try and see, I guess.

    # Setting cfg_optional here doesn't really work, because the cfg
    # object returned here is separate from the one that the Django
    # ORM gets when it tries to look for databases.  Given that just
    # about everything which uses this module also uses Django,
    # perhaps we should just resign ourselves to the config being a
    # global thing we read exactly once, so we can stop playing this
    # game.

    topparser = argparse.ArgumentParser(add_help = False)
    topparser.add_argument("-c", "--config",
                           default = os.getenv(rpki_conf_envname, default_filename),
                           help = "override default location of configuration file")

    cfgparser = argparse.ArgumentParser(parents = [topparser], add_help = False)
    cfgparser.add_argument("-h", "--help", action = "store_true")

    args, remaining_argv = cfgparser.parse_known_args()

    argparser = argparse.ArgumentParser(parents = [topparser], description = doc)

    cfg = parser(section       = section,
                 set_filename  = args.config,
                 argparser     = argparser,
                 allow_missing = cfg_optional or args.help)

    return cfg
