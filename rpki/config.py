# $Id$
#
# Copyright (C) 2015-2016  Parsons Government Services ("PARSONS")
# Portions copyright (C) 2013-2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2009-2012  Internet Systems Consortium ("ISC")
# Portions copyright (C) 2007-2008  American Registry for Internet Numbers ("ARIN")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND PARSONS, DRL, ISC, AND ARIN
# DISCLAIM ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT
# SHALL PARSONS, DRL, ISC, OR ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
# RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
# CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""
Configuration file parsing utilities, layered on top of stock Python
ConfigParser module.
"""

import ConfigParser
import argparse
import logging
import logging.handlers
import traceback
import time
import sys
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
        self.logging_defaults = None

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


    def _get_argument_default(self, names, kwargs):
        section = kwargs.pop("section", None)
        default = kwargs.pop("default", None)

        for name in names:
            if name.startswith("--"):
                name = name[2:]
                break
        else:
            raise ValueError

        if self.has_option(option = name, section = section):
            default = self.get(option = name, section = section, default = default)

            if "type" in kwargs:
                default = kwargs["type"](default)

            if "choices" in kwargs and default not in kwargs["choices"]:
                raise ValueError

        kwargs["default"] = default

        return name, default, kwargs


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

        name, default, kwargs = self._get_argument_default(names, kwargs)
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


    def _add_logging_argument(self, *names, **kwargs):
        group = kwargs.pop("group", self.argparser)
        name, default, kwargs = self._get_argument_default(names, kwargs)
        setattr(self.logging_defaults, name.replace("-", "_"), default)
        if group is not None:
            group.add_argument(*names, **kwargs)


    def add_logging_arguments(self, section = None):
        """
        Set up standard logging-related arguments.  This can be called
        even when we're not going to parse the command line (eg,
        because we're a WSGI app and therefore don't have a command
        line), to handle whacking arguments from the config file into
        the format that the logging setup code expects to see.
        """

        self.logging_defaults = argparse.Namespace(
            default_log_destination = None)

        if self.argparser is not None:
            self.argparser.set_defaults(
                default_log_destination = None)

        class non_negative_integer(int):
            def __init__(self, value):
                if self < 0:
                    raise ValueError

        class positive_integer(int):
            def __init__(self, value):
                if self <= 0:
                    raise ValueError

        if self.argparser is None:
            limit_group = None
        else:
            limit_group = self.argparser.add_mutually_exclusive_group()

        self._add_logging_argument(
            "--log-level",
            default = "warning",
            choices = ("debug", "info", "warning", "error", "critical"),
            help    = "how verbosely to log")

        self._add_logging_argument(
            "--log-destination",
            choices = ("syslog", "stdout", "stderr", "file"),
            help    = "logging mechanism to use")

        self._add_logging_argument(
            "--log-filename",
            help    = "where to log when log destination is \"file\"")

        self._add_logging_argument(
            "--log-facility",
            default = "daemon",
            choices = sorted(logging.handlers.SysLogHandler.facility_names.keys()),
            help    = "syslog facility to use when log destination is \"syslog\"")

        self._add_logging_argument(
            "--log-count",
            default = "7",
            type    = positive_integer,
            help    = "how many logs to keep when rotating for log destination \"file\""),

        self._add_logging_argument(
            "--log-size-limit",
            group   = limit_group,
            default = 0,
            type    = non_negative_integer,
            help    = "size in kbytes after which to rotate log for destination \"file\"")

        self._add_logging_argument(
            "--log-time-limit",
            group   = limit_group,
            default = 0,
            type    = non_negative_integer,
            help    = "hours after which to rotate log for destination \"file\"")


    def configure_logging(self, args = None, ident = None):
        """
        Configure the logging system, using information from both the
        config file and the command line; if this particular program
        doesn't use the command line (eg, a WSGI app), we just use the
        config file.
        """

        if self.logging_defaults is None:
            self.add_logging_arguments()

        if args is None:
            args = self.logging_defaults

        log_level = getattr(logging, args.log_level.upper())

        log_destination = args.log_destination or args.default_log_destination or "stderr"

        if log_destination == "stderr":
            log_handler = logging.StreamHandler(
                stream = sys.stderr)

        elif log_destination == "stdout":
            log_handler = logging.StreamHandler(
                stream = sys.stdout)

        elif log_destination == "syslog":
            log_handler = logging.handlers.SysLogHandler(
                address = ("/dev/log" if os.path.exists("/dev/log")
                           else ("localhost", logging.handlers.SYSLOG_UDP_PORT)),
                facility = logging.handlers.SysLogHandler.facility_names[args.log_facility])

        elif log_destination == "file" and (args.log_size_limit == 0 and 
                                            args.log_time_limit == 0):
            log_handler = logging.handlers.WatchedFileHandler(
                filename = args.log_filename)

        elif log_destination == "file" and args.log_time_limit == 0:
            log_handler = logging.handlers.RotatingFileHandler(
                filename    = args.log_filename,
                maxBytes    = args.log_size_limit * 1024,
                backupCount = args.log_count)

        elif log_destination == "file" and args.log_size_limit == 0:
            log_handler = logging.handlers.TimedRotatingFileHandler(
                filename    = args.log_filename,
                interval    = args.log_time_limit,
                backupCount = args.log_count,
                when        = "H",
                utc         = True)
            
        else:
            raise ValueError

        if ident is None:
            ident = os.path.basename(sys.argv[0])

        log_handler.setFormatter(Formatter(ident, log_handler, log_level))

        root_logger = logging.getLogger()
        root_logger.addHandler(log_handler)
        root_logger.setLevel(log_level)


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


class Formatter(object):
    """
    Reimplementation (easier than subclassing in this case) of
    logging.Formatter.

    It turns out that the logging code only cares about this class's
    .format(record) method, everything else is internal; so long as
    .format() converts a record into a properly formatted string, the
    logging code is happy.

    So, rather than mess around with dynamically constructing and
    deconstructing and tweaking format strings and ten zillion options
    we don't use, we just provide our own implementation that supports
    what we do need.
    """

    converter = time.gmtime

    def __init__(self, ident, handler, level):
        self.ident = ident
        self.is_syslog = isinstance(handler, logging.handlers.SysLogHandler)
        self.debugging = level == logging.DEBUG

    def format(self, record):
        return "".join(self.coformat(record)).rstrip("\n")

    def coformat(self, record):

        try:
            if not self.is_syslog:
                yield time.strftime("%Y-%m-%d %H:%M:%S ", time.gmtime(record.created))
        except:
            yield "[$!$Time format failed]"

        try:
            yield "{}[{:d}]: ".format(self.ident, record.process)
        except:
            yield "[$!$ident format failed]"

        try:
            if isinstance(record.context, (str, unicode)):
                yield record.context + " "
            else:
                yield repr(record.context) + " "
        except AttributeError:
            pass
        except:
            yield "[$!$context format failed]"

        try:
            yield record.getMessage()
        except:
            yield "[$!$record.getMessage() failed]"

        try:
            if record.exc_info:
                if self.is_syslog or not self.debugging:
                    lines = traceback.format_exception_only(
                        record.exc_info[0], record.exc_info[1])
                    lines.insert(0, ": ")
                else:
                    lines = traceback.format_exception(
                        record.exc_info[0], record.exc_info[1], record.exc_info[2])
                    lines.insert(0, "\n")
                for line in lines:
                    yield line
        except:
            yield "[$!$exception formatting failed]"
