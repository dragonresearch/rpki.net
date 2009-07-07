# $Id$

# Copyright (C) 2009  Internet Systems Consortium ("ISC")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

# Portions copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
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


# This file exists to tell Python that this the content of this
# directory constitute a Python package.  Since we're not doing
# anything exotic, this file doesn't need to contain any code, but
# since its existance defines the package, it's as sensible a place as
# any to put the Doxygen mainpage.

# The "usage" text for irbe_cli in the OPERATIONS section is generated
# automatically by running the program with its --help command.
# Should do the same with the other programs.  Don't yet have a sane
# way to automate options in config files, though.  Would be nice.

## @mainpage RPKI Engine Reference Manual
#
# This collection of Python modules implements a prototype of the
# RPKI Engine.  This is a work in progress.
#
# See http://viewvc.hactrn.net/subvert-rpki.hactrn.net/ for code,
# design documents, a text mirror of portions of APNIC's Wiki, etc.
#
# The RPKI Engine is an implementation of the production-side tools
# for generating certificates, CRLs, and ROAs.  The
# <a href="http://viewvc.hactrn.net/subvert-rpki.hactrn.net/rcynic/">relying party tools</a>
# are a separate (and much simpler) package.
#
# The Subversion repository for the entire project is available for
# (read-only) anonymous access at http://subvert-rpki.hactrn.net/.
#
# The documentation you're reading is generated automatically by
# Doxygen from comments and documentation in
# <a href="http://viewvc.hactrn.net/subvert-rpki.hactrn.net/rpkid/rpki/">the code</a>.
#
# Besides the automatically-generated code documentation, this manual
# also includes documentation of the overall package:
#
# @li The @subpage Installation "installation instructions"
# @li The @subpage Operation "operation instructions"
# @li A description of the @subpage Left-right "left-right protocol"
# @li A description of the @subpage Publication "publication protocol"
# @li A description of the @subpage bpki-model "BPKI model"
#     used to secure the up-down, left-right, and %publication protocols
# @li A description of the several @subpage sql-schemas "SQL database schemas"
# @li Some suggestions for @subpage further-reading "further reading"
#
# This work was funded from 2006 through 2008 by <a
# href="http://www.arin.net/">ARIN</a>, in collaboration with the
# other Regional Internet Registries.  Current work is funded by DHS.

## @page further-reading Further Reading
#
# If you're interested in this package you might also be interested
# in:
#
# @li <a href="http://viewvc.hactrn.net/subvert-rpki.hactrn.net/rcynic/">The rcynic validation tool</a>
# @li <a href="http://www.hactrn.net/opaque/rcynic.html">A live sample of rcynic's summary output</a>
# @li <a href="http://mirin.apnic.net/resourcecerts/wiki/">APNIC's Wiki</a>
# @li <a href="http://mirin.apnic.net/trac/">APNIC's project Trac instance</a>

## @page Installation Installation Guide
#
# Preliminary installation instructions for rpkid et al.  These are the
# production-side RPKI tools, for Internet Registries (RIRs, LIRs, etc).
# See the "rcynic" program for relying party tools.
#
# rpkid is a set of Python modules supporting generation and maintenance
# of resource certificates.  Most of the code is in the rpkid/rpki/
# directory.  rpkid itself is a relatively small program that calls the
# library modules.  There are several other programs that make use of
# the same libraries, as well as a collection of test programs.
#
# At present the package is intended to be run out of its build
# directory.  Setting up proper installation in a system area using the
# Python distutils package would likely not be very hard but has not yet
# been done.
#
# Note that initial development of this code has been on FreeBSD, so
# installation will probably be easiest on FreeBSD.
#
# Before attempting to build the package, you need to install any
# missing prerequisites.  Note that the Python code requires Python
# version 2.5.  rpkid et al are mostly self-contained, but do require
# a small number of external packages to run.
#
# <ul>
#   <li>
#     <a href="http://codespeak.net/lxml/">http://codespeak.net/lxml/</a>.
#     lxml in turn requires the Gnome LibXML2 C libraries.
#     <ul>
#       <li>FreeBSD: /usr/ports/devel/py-lxml</li>
#       <li>Fedora:  python-lxml.i386</li>
#     </ul>
#   </li>
#   <li>
#     <a href="http://sourceforge.net/projects/mysql-python/">http://sourceforge.net/projects/mysql-python/</a>.
#     MySQLdb in turn requires MySQL client and server.  rpkid et al have
#     been tested with MySQL 5.0 and 5.1.
#     <ul>
#       <li>FreeBSD: /usr/ports/databases/py-MySQLdb</li>
#       <li>Fedora:  MySQL-python.i386</li>
#     </ul>
#   </li>
# </ul>
#
# rpkid et al also make heavy use of a modified copy of the Python
# OpenSSL Wrappers (POW) package, but this copy has enough modifications
# and additions that it's included in the subversion tree.
#
# The next step is to build the OpenSSL and POW binaries.  At present
# the OpenSSL code is just a copy of the stock OpenSSL 0.9.8g release,
# compiled with special options to enable RFC 3779 support that ISC
# wrote under previous contract to ARIN.  The POW (Python OpenSSL
# Wrapper) library is an extended copy of the stock POW release.
#
# To build these, cd to the top-level directory in the distribution and
# type "make".
#
# @verbatim
#   $ cd $top
#   $ make
# @endverbatim
#
# This should automatically build everything, in the right order,
# including staticly linking the POW extension module with the OpenSSL
# library to provide RFC 3779 support.
#
# You will also need a MySQL installation.  This code was developed
# using MySQL 5.1 and has been tested with MySQL 5.0 and 5.1.
#
# The architecture is intended to support hardware signing modules
# (HSMs), but the code to support them has not been written.
#
# At this point, you should have all the necessary software installed.
# You will probably want to test it.  All tests should be run from the
# rpkid/ directory.  The test suite requires a few more external
# packages, only one of which is Python code.
#
# <ul>
#   <li>
#     <a href="http://pyyaml.org/">http://pyyaml.org/</a>.
#     testpoke.py (an up-down protocol command line test client) and
#     testbed.py (a test harness) use PyYAML.
#     <ul>
#       <li>FreeBSD: /usr/ports/devel/py-yaml</li>
#     </ul>
#   </li>
#   <li>
#     <a href="http://xmlsoft.org/XSLT/">http://xmlsoft.org/XSLT/</a>.
#     Some of the test code uses xsltproc, from the Gnome LibXSLT
#     package.
#     <ul>
#       <li>FreeBSD: /usr/ports/textproc/libxslt</li>
#     </ul>
#   </li>
#   <li>
#     <a href="http://w3m.sourceforge.net/">http://w3m.sourceforge.net/</a>.
#     testbed.py uses w3m to display the summary output from rcynic.
#     Nothing terrible will happen if w3m isn't available, testbed.py
#     will just complain about it being missing and won't display
#     rcynic's output.
#     <ul>
#       <li>FreeBSD: /usr/ports/www/w3m</li>
#     </ul>
#   </li>
# </ul>
#
# Some of the tests require MySQL databases to store their data.  To set
# up all the databases that the tests will need, run the SQL commands in
# rpkid/testbed.sql.  The MySQL command line client is usually the
# easiest way to do this, eg:
#
# @verbatim
#   $ cd $top/rpkid
#   $ mysql -u root -p <testbed.sql
# @endverbatim
#
# To run the tests, run "make all-tests":
#
# @verbatim
#   $ cd $top/rpkid
#   $ make all-tests
# @endverbatim
#
# If nothing explodes, your installation is probably ok.  Any Python
# backtraces in the output indicate a problem.
#
# There's a last set of tools that only developers should need, as
# they're only used when modifying schemas or regenerating the
# documentation.  These tools are listed here for completeness.
#
# <ul>
#   <li>
#     <a href="http://www.doxygen.org/">http://www.doxygen.org/</a>.
#     Doxygen in turn pulls in several other tools, notably Graphviz,
#     pdfLaTeX, and Ghostscript.
#     <ul>
#       <li>FreeBSD: /usr/ports/devel/doxygen</li>
#     </ul>
#   </li>
#   <li>
#     <a href="http://lynx.isc.org/current/">http://lynx.isc.org/current/</a>.
#     The documentation build process uses xsltproc and Lynx to dump
#     flat text versions of a few critical documentation pages.
#     <ul>
#       <li>FreeBSD: /usr/ports/www/lynx</li>
#     </ul>
#   </li>
#   <li>
#     <a href="http://www.thaiopensource.com/relaxng/trang.html">http://www.thaiopensource.com/relaxng/trang.html</a>.
#     Trang is used to convert RelaxNG schemas from the human-readable
#     "compact" form to the XML form that LibXML2 understands.  Trang in
#     turn requires Java.
#     <ul>
#       <li>FreeBSD: /usr/ports/textproc/trang</li>
#     </ul>
#   </li>
#   <li>
#     <a href="http://search.cpan.org/dist/SQL-Translator/">http://search.cpan.org/dist/SQL-Translator/</a>.
#     SQL-Translator, also known as "SQL Fairy", includes code to parse
#     an SQL schema and dump a description of it as Graphviz input.
#     SQL Fairy in turn requires Perl.
#   </li>
# </ul>

## @page Operation Operation Guide
#
# Preliminary operation instructions for rpkid et al.  These are the
# production-side RPKI tools, for Internet Registries (RIRs, LIRs, etc).
# See rcynic/README for relying party tools.
#
# @warning
# rpkid is still in development, and the code changes more often than
# the hand-maintained portions of this documentation.  The following
# text was reasonably accurate at the time it was written but may be
# obsolete by the time you read it.
#
# At present the package is intended to be run out of the @c rpkid/
# directory.
#
# In addition to the library routines in the @c rpkid/rpki/ directory,
# the package includes the following programs:
#
# @li @c rpkid.py:
#              The main RPKI engine daemon.
#
# @li @c pubd.py:
#              The publication engine daemon.
#
# @li @c rootd.py:
#              A separate daemon for handling the root of an RPKI
#              certificate tree.  This is essentially a stripped down
#              version of rpkid with no SQL database, no left-right
#              protocol implementation, and only the parent side of
#              the up-down protocol.  It's separate because the root
#              is a special case in several ways and it was simpler
#              to keep the special cases out of the main daemon.
#
# @li @c irdbd.py:
#              A sample implementation of an IR database daemon.
#              rpkid calls into this to perform lookups via the
#              left-right protocol.
#
# @li @c irbe_cli.py:
#              A command-line client for the left-right control
#              protocol.
#
# @li @c cross_certify.py:
#              A BPKI cross-certification tool.
#
# @li @c irbe-setup.py:
#              An example of a script to set up the mappings between
#              the IRDB and rpkid's own database, using the
#              left-right control protocol.
#
# @li @c cronjob.py:
#              A trivial HTTP client used to drive rpkid cron events.
#
# @li @c testbed.py:
#              A test tool for running a collection of rpkid and irdb
#              instances under common control, driven by a unified
#              test script.
#
# @li @c testpoke.py:
#              A simple client for the up-down protocol, mostly
#              compatable with APNIC's rpki_poke.pl tool.
#
# Most of these programs take configuration files in a common format
# similar to that used by the OpenSSL command line tool.  The test
# programs also take input in YAML format to drive the tests.  Runs of
# the testbed.py test tool will generate a fairly complete set
# configuration files which may be useful as examples.
#
# Basic operation consists of creating the appropriate MySQL databases,
# starting rpkid, pubd, rootd, and irdbd, using the left-right control
# protocol to set up rpkid's internal state, and setting up a cron job
# to invoke rpkid's cron action at regular intervals.  All other
# operations should occur either as a result of cron events or as a
# result of incoming left-right and up-down protocol requests.
#
# Note that the full event-driven model for rpkid hasn't yet been
# implemented.  The design is intended to allow an arbitrary number of
# hosted RPKI engines to run in a single rpkid instance, but without the
# event-driven tasking model one must set up a separate rpkid instance
# for each hosted RPKI engine.
#
# At present the daemon programs all run in foreground, that is, if one
# wants them to run in background one must do so manually, eg, using
# Bourne shell syntax:
#
# @verbatim
#   $ python whatever.py &
#   $ echo >whatever.pid  "$!"
# @endverbatim
#
# All of the daemons use syslog.  At present they all set LOG_PERROR, so
# all logging also goes to stderr.
#
#
# @section rpkid rpkid.py
#
# rpkid is the main RPKI engine daemon.  Configuration of rpkid is a
# two step process: a %config file to bootstrap rpkid to the point
# where it can speak using the @link Left-right left-right protocol,
# @endlink followed by dynamic configuration via the left-right
# protocol.  In production use the latter stage would be handled by
# the IRBE stub; for test and develoment purposes it's handled by the
# irbe_cli.py command line interface or by the testbed.py test
# framework.
#
# rpkid stores dynamic data in an SQL database, which must have been
# created for it, as explained in the @link Installation installation
# guide. @endlink
#
# The default %config file is rpkid.conf, start rpkid with "-c filename"
# to choose a different %config file.  All options are in the section
# "[rpkid]".  Certificates, keys, and trust anchors may be in either DER
# or PEM format.
#
# %Config file options:
#
# @li @c startup-message:
#                      String to %log on startup, useful when
#                      debugging a collection of rpkid instances at
#                      once.
#
# @li @c sql-username:
#                      Username to hand to MySQL when connecting to
#                      rpkid's database.
#
# @li @c sql-database:
#                      MySQL's database name for rpkid's database.
#
# @li @c sql-password:
#                      Password to hand to MySQL when connecting to
#                      rpkid's database.
#
# @li @c bpki-ta:
#                      Name of file containing BPKI trust anchor.
#                      All BPKI certificate verification within rpkid
#                      traces back to this trust anchor. 
#
# @li @c rpkid-cert:
#                      Name of file containing rpkid's own BPKI EE
#                      certificate.
#
# @li @c rpkid-key:
#                      Name of file containing RSA key corresponding
#                      to rpkid-cert.
#
# @li @c irbe-cert:
#                      Name of file containing BPKI certificate used
#                      by IRBE when talking to rpkid.
#
# @li @c irdb-cert:
#                      Name of file containing BPKI certificate used
#                      by irdbd.
#
# @li @c irdb-url:
#                      Service URL for irdbd.  Must be a %https:// URL.
#
# @li @c server-host:
#                      Hostname or IP address on which to listen for
#                      HTTPS connections.  Current default is
#                      INADDR_ANY (IPv4 0.0.0.0); this will need to
#                      be hacked to support IPv6 for production.
#
# @li @c server-port:
#                      TCP port on which to listen for HTTPS
#                      connections.
#
#
# @section pubd pubd.py
#
# pubd is the publication daemon.  It implements the server side of
# the publication protocol, and is used by rpkid to publish the
# certificates and other objects that rpkid generates.
#
# pubd is separate from rpkid for two reasons:
#
# @li The hosting model allows entities which choose to run their own
#     copies of rpkid to publish their output under a common
#     publication point.  In general, encouraging shared publication
#     services where practical is a good thing for relying parties,
#     as it will speed up rcynic synchronization time.
#
# @li The publication server has to run on (or at least close to) the
#     publication point itself, which in turn must be on a publically
#     reachable server to be useful.  rpkid, on the other hand, need
#     only be reachable by the IRBE and its children in the RPKI tree.
#     rpkid is a much more complex piece of software than pubd, so in
#     some situations it might make sense to wrap tighter firewall
#     constraints around rpkid than would be practical if rpkid and
#     pubd were a single program.
#
# pubd stores dynamic data in an SQL database, which must have been
# created for it, as explained in the installation guide.  pubd also
# stores the published objects themselves as disk files in a
# configurable location which should correspond to an appropriate
# module definition in rsync.conf.
#
# The default %config file is pubd.conf, start pubd with "-c
# filename" to choose a different %config file.  ALl options are in
# the section "[pubd]".  Certifiates, keys, and trust anchors may be
# either DER or PEM format.
#
# %Config file options:
#
# @li @c sql-username:
#                      Username to hand to MySQL when connecting to
#                      pubd's database.
#
# @li @c sql-database:
#                      MySQL's database name for pubd's database.
#
# @li @c sql-password:
#                      Password to hand to MySQL when connecting to
#                      pubd's database.
#
# @li @c bpki-ta:
#                      Name of file containing master BPKI trust
#                      anchor for  pubd.  All BPKI validation in pubd
#                      traces back to this trust anchor.
#
# @li @c irbe-cert:
#                      Name of file containing BPKI certificate used
#                      by IRBE when talking to pubd.
#
# @li @c pubd-cert:
#                      Name of file containing BPKI certificate used
#                      by pubd.
#
# @li @c pubd-key:
#                      Name of file containing RSA key corresponding
#                      to @c pubd-cert.
#
# @li @c server-host:
#                      Hostname or IP address on which to listen for
#                      HTTPS connections.  Current default is
#                      INADDR_ANY (IPv4 0.0.0.0); this will need to
#                      be hacked to support IPv6 for production.
#
# @li @c server-port:
#                      TCP port on which to listen for HTTPS
#                      connections.
#
# @li @c publication-base:
#                      Path to base of filesystem tree where pubd
#                      should store publishable objects.  Default is
#                      "publication/".
#
#
# @section rootd rootd.py
#
# rootd is a stripped down implmenetation of (only) the server side of
# the up-down protocol.  It's a separate program because the root
# certificate of an RPKI certificate tree requires special handling and
# may also require a special handling policy.  rootd is a simple
# implementation intended for test use, it's not suitable for use in a
# production system.  All configuration comes via the %config file.
#
# The default %config file is rootd.conf, start rootd with "-c filename"
# to choose a different %config file.  All options are in the section
# "[rootd]".  Certificates, keys, and trust anchors may be in either DER
# or PEM format.
#
# %Config file options:
#
# @li @c bpki-ta:
#                      Name of file containing BPKI trust anchor.  All
#                      BPKI certificate validation in rootd traces
#                      back to this trust anchor.
#
# @li @c rootd-bpki-cert:
#                      Name of file containing rootd's own BPKI
#                      certificate. 
#
# @li @c rootd-bpki-key:
#                      Name of file containing RSA key corresponding to
#                      rootd-bpki-cert.
#
# @li @c rootd-bpki-crl:
#                      Name of file containing BPKI CRL that would
#                      cover rootd-bpki-cert had it been revoked.
#
# @li @c child-bpki-cert:
#                      Name of file containing BPKI certificate for 
#                      rootd's one and only child (RPKI engine to
#                      which rootd issues an RPKI certificate).
#
# @li @c server-host:
#                      Hostname or IP address on which to listen for
#                      HTTPS connections.  Default is localhost.
#
# @li @c server-port:
#                      TCP port on which to listen for HTTPS
#                      connections.
#
# @li @c rpki-root-key:
#                      Name of file containing RSA key to use in
#                      signing resource certificates.
#
# @li @c rpki-root-cert:
#                      Name of file containing self-signed root
#                      resource certificate corresponding to
#                      rpki-root-key.
#
# @li @c rpki-root-dir:
#                      Name of directory where rootd should write
#                      RPKI subject certificate, manifest, and CRL.
#
# @li @c rpki-subject-cert:
#                      Name of file that rootd should use to save the
#                      one and only certificate it issues.
#                      Default is "Subroot.cer".
#
# @li @c rpki-root-crl:
#                      Name of file to which rootd should save its
#                      RPKI CRL.  Default is "Root.crl".
#
# @li @c rpki-root-manifest:
#                      Name of file to which rootd should save its
#                      RPKI manifest.  Default is "Root.mnf".
#
# @li @c rpki-subject-pkcs10:
#                      Name of file that rootd should use when saving
#                      a copy of the received PKCS #10 request for a
#                      resource certificate.  This is only used for
#                      debugging.  Default is not to save the PKCS
#                      #10 request.
#
#
# @section irdbd irdbd.py
#
# irdbd is a sample implemntation of the server side of the IRDB
# callback subset of the left-right protocol.  In production use this
# service is a function of the IRBE stub; irdbd may be suitable for
# production use in simple cases, but an IR with a complex IRDB may need
# to extend or rewrite irdbd.
#
# irdbd requires a pre-populated database to represent the IR's
# customers.  irdbd expects this database to use the SQL schema defined
# in rpkid/irdbd.sql.  Once this database has been populated, the
# IRBE stub needs to create the appropriate objects in rpkid's database
# via the control subset of the left-right protocol, and store the
# linkage IDs (foreign keys into rpkid's database, basicly) in the
# IRDB.  The irbe-setup.py program shows an example of how to do this.
#
# irdbd's default %config file is irdbd.conf, start irdbd with "-c
# filename" to choose a different %config file.  All options are in the
# section "[irdbd]".  Certificates, keys, and trust anchors may be in
# either DER or PEM format.
#
# %Config file options:
#
# @li @c startup-message:
#                      String to %log on startup, useful when
#                      debugging a collection of irdbd instances at
#                      once.
#
# @li @c sql-username:
#                      Username to hand to MySQL when connecting to
#                      irdbd's database.
#
# @li @c sql-database:
#                      MySQL's database name for irdbd's database.
#
# @li @c sql-password:
#                      Password to hand to MySQL when connecting to
#                      irdbd's database.
#
# @li @c bpki-ta:
#                      Name of file containing BPKI trust anchor.  All
#                      BPKI certificate validation in irdbd traces
#                      back to this trust anchor.
#
# @li @c irdbd-cert:
#                      Name of file containing irdbd's own BPKI
#                      certificate. 
#
# @li @c irdbd-key:
#                      Name of file containing RSA key corresponding
#                      to irdbd-cert.
#
# @li @c rpkid-cert:
#                      Name of file containing certificate used the
#                      one and only by rpkid instance authorized to
#                      contact this irdbd instance.
#
# @li @c https-url:
#                      Service URL for irdbd.  Must be a %https:// URL.
#
#
# @section irdbd_cli irbe_cli.py
#
# irbe_cli is a simple command line client for the control subsets of
# the @link Left-right left-right @endlink and @link Publication
# publication @endlink protocols.  In production use this
# functionality would be part of the IRBE stub.
#
# Basic configuration of irbe_cli is handled via a %config file.  The
# specific action or actions to be performed are specified on the
# command line, and map closely to the protocols themselves.
#
# At present the user is assumed to be able to read the (XML)
# left-right and publication protocol messages, and with one
# exception, irdbd-cli makes no attempt to interpret the responses
# other than to check for signature and syntax errors.  The one
# exception is that, if the @c --pem_out option is specified on the
# command line, any PKCS \#10 requests received from rpkid will be
# written in PEM format to that file; this makes it easier to hand
# these requests off to the business PKI (BPKI in order to issue signing
# certs corresponding to newly generated business keys.
#
# @verbinclude irbe_cli.usage
#
# Global options (@c --config, @c --help, @c --pem_out) come first,
# then zero or more commands (@c parent, @c repository, @c self, @c
# child, @c bsc, @c config, @c client), each followed by its own set
# of options.  The commands map to elements in the protocols, and the
# command-specific options map to attributes or subelements for those
# commands.
#
# @c --tag is an optional arbitrary tag (think IMAP) to simplify
# matching up replies with batched queries.
#
# @c --*_handle options refer to object primary keys.
#
# The remaining options are specific to the particular commands, and
# follow directly from the protocol specifications.
#
# A trailing "=" in the above option summary indicates that an option
# takes a value, eg, "--action create" or "--action=create".  Options
# without a trailing "=" correspond to boolean control attributes.
#
# The default %config file for irbe_cli is irbe_cli.conf, start
# irbe_cli with "-c filename" (or "--config filename") to choose a
# different %config file.  All options are in the section
# "[irbe_cli]".  Certificates, keys, and trust anchors may be in
# either DER or PEM format.
#
# %Config file options:
#
# @li @c rpkid-bpki-ta:
#                      Name of file containing BPKI trust anchor to
#                      use when authenticating messages from rpkid.
#
# @li @c rpkid-irbe-cert:
#                      Name of file containing BPKI certificate
#                      irbe_cli should use when talking to rpkid.
#
# @li @c rpkid-irbe-key:
#                      Name of file containing RSA key corresponding to
#                      rpkid-irbe-cert.
#
# @li @c rpkid-cert:
#                      Name of file containing rpkid's BPKI certificate.
#
# @li @c rpkid-url:
#                      Service URL for rpkid.  Must be a %https:// URL.
#
# @li @c pubd-bpki-ta:
#                      Name of file containing BPKI trust anchor to
#                      use when authenticating messages from pubd.
#
# @li @c pubd-irbe-cert:
#                      Name of file containing BPKI certificate
#                      irbe_cli should use when talking to pubd.
#
# @li @c pubd-irbe-key:
#                      Name of file containing RSA key corresponding to
#                      pubd-irbe-cert.
#
# @li @c pubd-cert:
#                      Name of file containing pubd's BPKI certificate.
#
# @li @c pubd-url:
#                      Service URL for pubd.  Must be a %https:// URL.
#
#
#
# @section cross_certify cross_certify.py
#
# cross_certify.py is a small tool to extract certain fields from an
# existing X.509 certificate and generate issue a new certificate that
# can be used as part of a cross-certification chain.  cross_certify
# doesn't take a config file, all of its arguments are specified on
# the command line.
#
# @verbatim
#    python cross_certify.py { -i | --in     } input_cert
#                            { -c | --ca     } issuing_cert
#                            { -k | --key    } issuing_cert_key
#                            { -s | --serial } serial_filename
#                            [ { -h | --help } ]
#                            [ { -o | --out  }     filename ]
#                            [ { -l | --lifetime } timedelta ]
# @endverbatim
#
#
# @section irbe_setup irbe-setup.py config file
#
# @warning
# irbe-setup is old code, not currently used, kept in case it is
# useful at some later date.  It may not work properly or at all.  If
# you don't understand what it does, you don't need it. You have been
# warned.
#
# The default %config file is irbe.conf, start rpkid with "-c filename"
# to choose a different %config file.  Most options are in the section
# "[irbe_cli]", but a few are in the section "[irdbd]".  Certificates,
# keys, and trust anchors may be in either DER or PEM format.
#
# Options in the "[irbe_cli]" section:
#
# @li @c bpki-ta:
#                      Name of file containing BPKI trust anchor.
#
# @li @c irbe-cert:
#                      Name of file containing BPKI certificate
#                      irbe-setup should use.
#
# @li @c irbe-key:
#                      Name of file containing RSA key corresponding
#                      to irbe-cert.
#
# @li @c rpkid-cert:
#                      Name of file containing rpkid's BPKI
#                      certificate. 
#
# @li @c https-url:
#                      Service URL for rpkid.  Must be a %https:// URL.
#
# Options in the "[irdbd]" section:
#
# @li @c sql-username:
#                      Username to hand to MySQL when connecting to
#                      irdbd's database.
#
# @li @c sql-database:
#                      MySQL's database name for irdbd's database.
#
# @li @c sql-password:
#                      Password to hand to MySQL when connecting to
#                      irdbd's database.
#
#
# @section cronjob cronjob.py
#
# This is a trivial program to trigger a cron run within rpkid.  Once
# rpkid has been converted to the planned event-driven model, this
# function will be handled internally, but for now it has to be
# triggered by an external program.  For pseudo-production use one would
# run this program under the system cron daemon.  For scripted testing
# it happens to be useful to be able to control when cron cycles occur,
# so at the current stage of code development use of an external trigger
# is a useful feature.
#
# The default %config file is cronjob.conf, start cronjob with "-c
# filename" to choose a different %config file.  All options are in the
# section "[cronjob]".  Certificates, keys, and trust anchors may be in
# either DER or PEM format.
#
# %Config file options:
#
# @li @c bpki-ta:
#                      Name of file containing BPKI trust anchor.
#
# @li @c irbe-cert:
#                      Name of file containing cronjob.py's BPKI
#                      certificate.
#
# @li @c https-key:
#                      Name of file containing RSA key corresponding
#                      to irbe-cert.
#
# @li @c rpkid-cert:
#                      Name of file containing rpkid's BPKI certificate.
#
# @li @c https-url:
#                      Service URL for rpkid.  Must be a %https:// URL.
#
#
# @section testbed testbed.py:
#
# testbed is a test harness to set up and run a collection of rpkid and
# irdbd instances under scripted control.  testbed is a very recent
# addition to the toolset and is still evolving rapidly.
#
# Unlike the programs described above, testbed takes two configuration
# files in different languages.  The first configuration file uses the
# same syntax as the above configuration files but is completely
# optional.  The second configuration file is the test script, which is
# encoded using the YAML serialization language (see
# http://www.yaml.org/ for more information on YAML).  The YAML script
# is not optional, as it describes the test layout.  testbed is designed
# to support running a fairly wide set of test configurations as canned
# scripts without writing any new control code.  The intent is to make
# it possible to write meaningful regression tests.
#
# All of the options in in the first (optional) configuration file are
# just overrides for wired-in default values.   In most cases the
# defaults will suffice, and the set of options is still in flux, so
# only a few of the options are described here.    The default name for
# this configuration file is testbed.conf, run testbed with "-c
# filename" to change it.
#
# testbed.conf options:
#
# @li @c testbed_dir:
#              Working directory into which testbed should write the
#              (many) files it generates.  Default is "testbed.dir".
#
# @li @c irdb_db_pass:
#              MySQL password for the "irdb" user.  Default is
#              "fnord".  You may want to override this.
#
# @li @c rpki_db_pass:
#              MySQL password for the "rpki" user.  Default is
#              "fnord".  You may want to override this.
#
# @li @c rootd_sia:
#              rsync URI naming a (perhaps fictious) directory to use
#              as the id-ad-caRepository SIA value in the generated
#              root resource certificate.  Default is
#              "rsync://wombat.invalid/".  You may want to override
#              this if you intend to run an rsync server and test
#              against the generated results using rcynic.   This
#              default will likely change if and when testbed learns
#              how to run rcynic itself as part of the test suite.
#
# The second configuration file is named testbed.yaml by default, run
# testbed with "-y filename" to change it.  The YAML file contains
# multiple YAML "documents".  The first document describes the initial
# test layout and resource allocations, subsequent documents describe
# modifications to the initial allocations and other parameters.
# Resources listed in the initial layout are aggregated automatically,
# so that a node in the resource hierarchy automatically receives the
# resources it needs to issue whatever its children are listed as
# holding.  Actions in the subsequent documents are modifications to the
# current resource set, modifications to validity dates or other
# non-resource parameters, or special commands like "sleep".  The
# details are still evolving, but here's an example of current usage:
#
# @verbatim
#     name:           RIR
#     valid_for:      2d
#     sia_base:       "rsync://wombat.invalid/"
#     kids:
#       - name: LIR0
#      kids:
#        - name: Alice
#          ipv4: 192.0.2.1-192.0.2.33
#          asn:  64533
#     ---
#     - name: Alice
#       valid_add:   10
#     ---
#     - name: Alice
#       add_as: 33
#       valid_add:   2d
#     ---
#     - name: Alice
#       valid_sub:   2d
#     ---
#     - name: Alice
#       valid_for:   10d
# @endverbatim
#
# This specifies an initial layout consisting of an RPKI engine named
# "RIR", with one child "LIR0", which in turn has one child "Alice".
# Alice has a set of assigned resources, and all resources in the system
# are initially set to be valid for two days from the time at which the
# test is started.  The first subsequent document adds ten seconds to
# the validity interval for Alice's resources and makes no other
# modifications.  The second subsequent document grants Alice additional
# resources and adds another two days to the validity interval for
# Alice's resources.  The next document subtracts two days from the
# validity interval for Alice's resources.  The final document sets the
# validity interval for Alice's resources to ten days.
#
# Operators in subsequent (update) documents:
#
# @li @c add_as, @c add_v4, @c add_v6:
#              These add ASN, IPv4, or IPv6 resources, respectively.
#
# @li @c sub_as, @c sub_v4, @c sub_v6:
#              These subtract resources.
#
# @li @c valid_until:
#              Set an absolute expiration date.
#
# @li @c valid_for:
#              Set a relative expiration date.
#
# @li @c valid_add, @c valid_sub:
#              Add to or subtract from validity interval.
#
# @li @c sleep [interval]:
#              Sleep for specified interval, or until testbed receives a SIGALRM signal.
#
# Absolute timestamps should be in the form shown (UTC timestamp format
# as used in XML).
#
# Intervals (@c valid_add, @c valid_sub, @c valid_for, @c sleep) are either
# integers, in which case they're interpreted as seconds, or are a
# string of the form "wD xH yM zS" where w, x, y, and z are integers and
# D, H, M, and S indicate days, hours, minutes, and seconds.  In the
# latter case all of the fields are optional, but at least one must be
# specified.  For example, "3D4H" means "three days plus four hours".
#
#
# @section testpoke testpoke.py
#
# This is a command-line client for the up-down protocol.  Unlike all of
# the above programs, testpoke does not accept a %config file in
# OpenSSL-compatable format at all.  Instead, it is configured
# exclusively by a YAML script.  testpoke's design was constrained by a
# desire to have it be compatable with APNIC's rpki_poke.pl tool, so
# that the two tools could use a common configuration language to
# simplify scripted testing.  There are minor variations due to slightly
# different feature sets, but YAML files intended for one program will
# usually work with the other.
#
# README for APNIC's tool describing the input language can be found at
# <a href="http://mirin.apnic.net/svn/rpki_engine/branches/gary-poker/client/poke/README">
# http://mirin.apnic.net/svn/rpki_engine/branches/gary-poker/client/poke/README</a>.
#
# testpoke.py takes a simplified command line and uses only one YAML
# input file.
#
# @verbatim
# Usage: python testpoke.py [ { -y | --yaml }    configfile ]
#                           [ { -r | --request } requestname ]
#                           [ { -h | --help } ]
# @endverbatim
#
# Default configuration file is testpoke.yaml, override with --yaml
# option.
#
# The --request option specifies the specific command within the YAML
# file to execute.
#
# Sample configuration file:
#
# @verbatim
#     ---
#     # Sample YAML configuration file for testpoke.py
#
#     version: 1
#     posturl: https://localhost:4433/up-down/1
#     recipient-id: wombat
#     sender-id: "1"
#
#     cms-cert-file: biz-certs/Frank-EE.cer
#     cms-key-file: biz-certs/Frank-EE.key
#     cms-ca-cert-file: biz-certs/Bob-Root.cer
#     cms-cert-chain-file: [ biz-certs/Frank-CA.cer ]
#
#     ssl-cert-file: biz-certs/Frank-EE.cer
#     ssl-key-file: biz-certs/Frank-EE.key
#     ssl-ca-cert-file: biz-certs/Bob-Root.cer
#
#     requests:
#       list:
#      type: list
#       issue:
#      type: issue
#      class: 1
#      sia: [ "rsync://bandicoot.invalid/some/where/" ]
#       revoke:
#      type: revoke
#      class: 1
#      ski: "CB5K6APY-4KcGAW9jaK_cVPXKX0"
# @endverbatim
#
# testpoke adds one extension to the language described in APNIC's
# README: the cms-cert-chain-* and ssl-cert-chain-* options, which allow
# one to specify a chain of intermediate certificates to be presented in
# the CMS or TLS protocol.  APNIC's initial implementation required
# direct knowledge of the issuing certificate (ie, it supported a
# maximum chain length of one); subsequent APNIC code changes have
# probably relaxed this restriction, and with luck APNIC has copied
# testpoke's syntax to express chains of intermediate certificates.

## @page Left-right Left-right protocol
#
# The left-right protocol is really two separate client/server
# protocols over separate channels between the RPKI engine and the IR
# back end (IRBE).  The IRBE is the client for one of the
# subprotocols, the RPKI engine is the client for the other.
#
# @section Terminology
#
# @li @em IRBE: Internet Registry Back End
#
# @li @em IRDB: Internet Registry Data Base
#
# @li @em BPKI: Business PKI
#
# @li @em RPKI: Resource PKI
#
# @section Operations initiated by the IRBE
#
# This part of the protcol uses a kind of message-passing.  Each %object
# that the RPKI engine knows about takes five messages: "create", "set",
# "get", "list", and "destroy".  Actions which are not just data
# operations on %objects are handled via an SNMP-like mechanism, as if
# they were fields to be set.  For example, to generate a keypair one
# "sets" the "generate-keypair" field of a BSC %object, even though there
# is no such field in the %object itself as stored in SQL.  This is a bit
# of a kludge, but the reason for doing it as if these were variables
# being set is to allow composite operations such as creating a BSC,
# populating all of its data fields, and generating a keypair, all as a
# single operation.  With this model, that's trivial, otherwise it's at
# least two round trips.
#
# Fields can be set in either "create" or "set" operations, the
# difference just being whether the %object already exists.  A "get"
# operation returns all visible fields of the %object.  A "list"
# operation returns a %list containing what "get" would have returned on
# each of those %objects.
#
# Left-right protocol %objects are encoded as signed CMS messages
# containing XML as eContent and using an eContentType OID of @c id-ct-xml
# (1.2.840.113549.1.9.16.1.28).  These CMS messages are in turn passed
# as the data for HTTPS POST operations, with an HTTP content type of
# "application/x-rpki" for both the POST data and the response data.
#
# All operations allow an optional "tag" attribute which can be any
# alphanumeric token.  The main purpose of the tag attribute is to allow
# batching of multiple requests into a single PDU.
#
# @subsection self_obj <self/> object
#
# A @c &lt;self/&gt; %object represents one virtual RPKI engine.  In simple cases
# where the RPKI engine operator operates the engine only on their own
# behalf, there will only be one @c &lt;self/&gt; %object, representing the engine
# operator's organization, but in environments where the engine operator
# hosts other entities, there will be one @c @c &lt;self/&gt; %object per hosted
# entity (probably including the engine operator's own organization,
# considered as a hosted customer of itself).
#
# Some of the RPKI engine's configured parameters and data are shared by
# all hosted entities, but most are tied to a specific @c &lt;self/&gt; %object.
# Data which are shared by all hosted entities are referred to as
# "per-engine" data, data which are specific to a particular @c &lt;self/&gt;
# %object are "per-self" data.
#
# Since all other RPKI engine %objects refer to a @c &lt;self/&gt; %object via a
# "self_handle" value, one must create a @c &lt;self/&gt; %object before one can
# usefully configure any other left-right protocol %objects.
#
# Every @c &lt;self/&gt; %object has a self_handle attribute, which must be specified
# for the "create", "set", "get", and "destroy" actions.
#
# Payload data which can be configured in a @c &lt;self/&gt; %object:
#
# @li @c use_hsm (attribute):
#     Whether to use a Hardware Signing Module.  At present this option
#     has no effect, as the implementation does not yet support HSMs.
#
# @li @c crl_interval (attribute):
#     Positive integer representing the planned lifetime of an RPKI CRL
#     for this @c &lt;self/&gt;, measured in seconds.
#
# @li @c regen_margin (attribute):
#     Positive integer representing how long before expiration of an
#     RPKI certificiate a new one should be generated, measured in
#     seconds.  At present this only affects the one-off EE certificates
#     associated with ROAs.
#
# @li @c bpki_cert (element):
#     BPKI CA certificate for this @c &lt;self/&gt;.  This is used as part of the
#     certificate chain when validating incoming TLS and CMS messages,
#     and should be the issuer of cross-certification BPKI certificates
#     used in @c &lt;repository/&gt;, @c &lt;parent/&gt;, and @c &lt;child/&gt; %objects.  If the
#     bpki_glue certificate is in use (below), the bpki_cert certificate
#     should be issued by the bpki_glue certificate; otherwise, the
#     bpki_cert certificate should be issued by the per-engine bpki_ta
#     certificate.
#
# @li @c bpki_glue (element):
#     Another BPKI CA certificate for this @c &lt;self/&gt;, usually not needed.
#     Certain pathological cross-certification cases require a
#     two-certificate chain due to issuer name conflicts.  If used, the
#     bpki_glue certificate should be the issuer of the bpki_cert
#     certificate and should be issued by the per-engine bpki_ta
#     certificate; if not needed, the bpki_glue certificate should be
#     left unset.
#
# Control attributes that can be set to "yes" to force actions:
#
# @li @c rekey:
#     Start a key rollover for every RPKI CA associated with every
#     @c &lt;parent/&gt; %object associated with this @c &lt;self/&gt; %object.  This is the
#     first phase of a key rollover operation.
#
# @li @c revoke:
#     Revoke any remaining certificates for any expired key associated
#     with any RPKI CA for any @c &lt;parent/&gt; %object associated with this
#     @c &lt;self/&gt; %object.   This is the second (cleanup) phase for a key
#     rollover operation; it's separate from the first phase to leave
#     time for new RPKI certificates to propegate and be installed.
#
# @li @c reissue:
#     Not implemented, may be removed from protocol.  Original theory
#     was that this operation would force reissuance of any %object with
#     a changed key, but as that happens automatically as part of the
#     key rollover mechanism this operation seems unnecessary.
#
# @li @c run_now:
#     Force immediate processing for all tasks associated with this
#     @c &lt;self/&gt; %object that would ordinarily be performed under cron.  Not
#     currently implemented.
#
# @li @c publish_world_now:
#     Force (re)publication of every publishable %object for this @c &lt;self/&gt;
#     %object.  Not currently implemented.   Intended to aid in recovery
#     if RPKI engine and publication engine somehow get out of sync.
#
#
# @subsection bsc_obj <bsc/> object
#
# The @c &lt;bsc/&gt; ("business signing context") %object represents all the BPKI
# data needed to sign outgoing CMS or HTTPS messages.  Various other
# %objects include pointers to a @c &lt;bsc/&gt; %object.  Whether a particular
# @c &lt;self/&gt; uses only one @c &lt;bsc/&gt; or multiple is a configuration decision
# based on external requirements: the RPKI engine code doesn't care, it
# just cares that, for any %object representing a relationship for which
# it must sign messages, there be a @c &lt;bsc/&gt; %object that it can use to
# produce that signature.
#
# Every @c &lt;bsc/&gt; %object has a bsc_handle, which must be specified for the
# "create", "get", "set", and "destroy" actions.  Every @c &lt;bsc/&gt; also has a self_handle
# attribute which indicates the @c &lt;self/&gt; %object with which this @c &lt;bsc/&gt;
# %object is associated.
#
# Payload data which can be configured in a @c &lt;isc/&gt; %object:
#
# @li @c signing_cert (element):
#     BPKI certificate to use when generating a signature.
#
# @li @c signing_cert_crl (element):
#     CRL which would %list signing_cert if it had been revoked.
#
# Control attributes that can be set to "yes" to force actions:
#
# @li @c generate_keypair:
#     Generate a new BPKI keypair and return a PKCS #10 certificate
#     request.  The resulting certificate, once issued, should be
#     configured as this @c &lt;bsc/&gt; %object's signing_cert.
#
# Additional attributes which may be specified when specifying
# "generate_keypair":
#
# @li @c key_type:
#     Type of BPKI keypair to generate.  "rsa" is both the default and,
#     at the moment, the only allowed value.
#
# @li @c hash_alg:
#     Cryptographic hash algorithm to use with this keypair.  "sha256"
#     is both the default and, at the moment, the only allowed value.
#
# @li @c key_length:
#     Length in bits of the keypair to be generated.  "2048" is both the
#     default and, at the moment, the only allowed value.
#
# Replies to "create" and "set" actions that specify "generate-keypair"
# include a &lt;bsc_pkcs10/> element, as do replies to "get" and "list"
# actions for a @c &lt;bsc/&gt; %object for which a "generate-keypair" command has
# been issued.  The RPKI engine stores the PKCS #10 request, which
# allows the IRBE to reuse the request if and when it needs to reissue
# the corresponding BPKI signing certificate.
#
# @subsection parent_obj <parent/> object
#
# The @c &lt;parent/&gt; %object represents the RPKI engine's view of a particular
# parent of the current @c &lt;self/&gt; %object in the up-down protocol.  Due to
# the way that the resource hierarchy works, a given @c &lt;self/&gt; may obtain
# resources from multiple parents, but it will always have at least one;
# in the case of IANA or an RIR, the parent RPKI engine may be a trivial
# stub.
#
# Every @c &lt;parent/&gt; %object has a parent_handle, which must be specified for
# the "create", "get", "set", and "destroy" actions.  Every @c &lt;parent/&gt; also has a
# self_handle attribute which indicates the @c &lt;self/&gt; %object with which this
# @c &lt;parent/&gt; %object is associated, a bsc_handle attribute indicating the @c &lt;bsc/&gt;
# %object to be used when signing messages sent to this parent, and a
# repository_handle indicating the @c &lt;repository/&gt; %object to be used when
# publishing issued by the certificate issued by this parent.
#
# Payload data which can be configured in a @c &lt;parent/&gt; %object:
#
# @li @c peer_contact_uri (attribute):
#     HTTPS URI used to contact this parent.
#
# @li @c sia_base (attribute):
#     The leading portion of an rsync URI that the RPKI engine should
#     use when composing the publication URI for %objects issued by the
#     RPKI certificate issued by this parent.
#
# @li @c sender_name (attribute):
#     Sender name to use in the up-down protocol when talking to this
#     parent.  The RPKI engine doesn't really care what this value is,
#     but other implementations of the up-down protocol do care.
#
# @li @c recipient_name (attribute):
#     Recipient name to use in the up-down protocol when talking to this
#     parent.   The RPKI engine doesn't really care what this value is,
#     but other implementations of the up-down protocol do care.
#
# @li @c bpki_cms_cert (element):
#     BPKI CMS CA certificate for this @c &lt;parent/&gt;.  This is used as part
#     of the certificate chain when validating incoming CMS messages If
#     the bpki_cms_glue certificate is in use (below), the bpki_cms_cert
#     certificate should be issued by the bpki_cms_glue certificate;
#     otherwise, the bpki_cms_cert certificate should be issued by the
#     bpki_cert certificate in the @c &lt;self/&gt; %object.
#
# @li @c bpki_cms_glue (element):
#     Another BPKI CMS CA certificate for this @c &lt;parent/&gt;, usually not
#     needed.  Certain pathological cross-certification cases require a
#     two-certificate chain due to issuer name conflicts.  If used, the
#     bpki_cms_glue certificate should be the issuer of the
#     bpki_cms_cert certificate and should be issued by the bpki_cert
#     certificate in the @c &lt;self/&gt; %object; if not needed, the
#     bpki_cms_glue certificate should be left unset.
#
# @li @c bpki_https_cert (element):
#     BPKI HTTPS CA certificate for this @c &lt;parent/&gt;.  This is like the
#     bpki_cms_cert %object, only used for validating incoming TLS
#     messages rather than CMS.
#
# @li @c bpki_cms_glue (element):
#     Another BPKI HTTPS CA certificate for this @c &lt;parent/&gt;, usually not
#     needed.  This is like the bpki_cms_glue certificate, only used for
#     validating incoming TLS messages rather than CMS.
#
# Control attributes that can be set to "yes" to force actions:
#
# @li @c rekey:
#     This is like the rekey command in the @c &lt;self/&gt; %object, but limited
#     to RPKI CAs under this parent.
#
# @li @c reissue:
#     This is like the reissue command in the @c &lt;self/&gt; %object, but limited
#     to RPKI CAs under this parent.
#
# @li @c revoke:
#     This is like the revoke command in the @c &lt;self/&gt; %object, but limited
#     to RPKI CAs under this parent.
#
# @subsection child_obj <child/> object
#
# The @c &lt;child/&gt; %object represents the RPKI engine's view of particular
# child of the current @c &lt;self/&gt; in the up-down protocol.
#
# Every @c &lt;child/&gt; %object has a child_handle, which must be specified for the
# "create", "get", "set", and "destroy" actions.  Every @c &lt;child/&gt; also has a
# self_handle attribute which indicates the @c &lt;self/&gt; %object with which this
# @c &lt;child/&gt; %object is associated.
#
# Payload data which can be configured in a @c &lt;child/&gt; %object:
#
# @li @c bpki_cert (element):
#     BPKI CA certificate for this @c &lt;child/&gt;.  This is used as part of
#     the certificate chain when validating incoming TLS and CMS
#     messages.  If the bpki_glue certificate is in use (below), the
#     bpki_cert certificate should be issued by the bpki_glue
#     certificate; otherwise, the bpki_cert certificate should be issued
#     by the bpki_cert certificate in the @c &lt;self/&gt; %object.
#
# @li @c bpki_glue (element):
#     Another BPKI CA certificate for this @c &lt;child/&gt;, usually not needed.
#     Certain pathological cross-certification cases require a
#     two-certificate chain due to issuer name conflicts.  If used, the
#     bpki_glue certificate should be the issuer of the bpki_cert
#     certificate and should be issued by the bpki_cert certificate in
#     the @c &lt;self/&gt; %object; if not needed, the bpki_glue certificate
#     should be left unset.
#
# Control attributes that can be set to "yes" to force actions:
#
# @li @c reissue:
#     Not implemented, may be removed from protocol.
#
# @subsection repository_obj <repository/> object
#
# The @c &lt;repository/&gt; %object represents the RPKI engine's view of a
# particular publication repository used by the current @c &lt;self/&gt; %object.
#
# Every @c &lt;repository/&gt; %object has a repository_handle, which must be
# specified for the "create", "get", "set", and "destroy" actions.  Every
# @c &lt;repository/&gt; also has a self_handle attribute which indicates the @c &lt;self/&gt;
# %object with which this @c &lt;repository/&gt; %object is associated.
#
# Payload data which can be configured in a @c &lt;repository/&gt; %object:
#
# @li @c peer_contact_uri (attribute):
#     HTTPS URI used to contact this repository.
#
# @li @c bpki_cms_cert (element):
#     BPKI CMS CA certificate for this @c &lt;repository/&gt;.  This is used as part
#     of the certificate chain when validating incoming CMS messages If
#     the bpki_cms_glue certificate is in use (below), the bpki_cms_cert
#     certificate should be issued by the bpki_cms_glue certificate;
#     otherwise, the bpki_cms_cert certificate should be issued by the
#     bpki_cert certificate in the @c &lt;self/&gt; %object.
#
# @li @c bpki_cms_glue (element):
#     Another BPKI CMS CA certificate for this @c &lt;repository/&gt;, usually not
#     needed.  Certain pathological cross-certification cases require a
#     two-certificate chain due to issuer name conflicts.  If used, the
#     bpki_cms_glue certificate should be the issuer of the
#     bpki_cms_cert certificate and should be issued by the bpki_cert
#     certificate in the @c &lt;self/&gt; %object; if not needed, the
#     bpki_cms_glue certificate should be left unset.
#
# @li @c bpki_https_cert (element):
#     BPKI HTTPS CA certificate for this @c &lt;repository/&gt;.  This is like the
#     bpki_cms_cert %object, only used for validating incoming TLS
#     messages rather than CMS.
#
# @li @c bpki_cms_glue (element):
#     Another BPKI HTTPS CA certificate for this @c &lt;repository/&gt;, usually not
#     needed.  This is like the bpki_cms_glue certificate, only used for
#     validating incoming TLS messages rather than CMS.
#
# At present there are no control attributes for @c &lt;repository/&gt; %objects.
#
# @subsection route_origin_obj <route_origin/> object
#
# This section is out-of-date. The @c &lt;route_origin/&gt; %object
# has been replaced by the @c &lt;list_roa_requests/&gt; IRDB query,
# but the documentation for that hasn't been written yet.
#
# The @c &lt;route_origin/&gt; %object is a kind of prototype for a ROA.  It
# contains all the information needed to generate a ROA once the RPKI
# engine obtains the appropriate RPKI certificates from its parent(s).
#
# Note that a @c &lt;route_origin/&gt; %object represents a ROA to be generated on
# behalf of @c &lt;self/&gt;, not on behalf of a @c &lt;child/&gt;.  Thus, a hosted entity
# that has no children but which does need to generate ROAs would be
# represented by a hosted @c &lt;self/&gt; with no @c &lt;child/&gt; %objects but one or
# more @c &lt;route_origin/&gt; %objects.   While lumping ROA generation in with
# the other RPKI engine activities may seem a little odd at first, it's
# a natural consequence of the design requirement that the RPKI daemon
# never transmit private keys across the network in any form; given this
# requirement, the RPKI engine that holds the private keys for an RPKI
# certificate must also be the engine which generates any ROAs that
# derive from that RPKI certificate.
#
# The precise content of the @c &lt;route_origin/&gt; has changed over time as
# the underlying ROA specification has changed.  The current
# implementation as of this writing matches what we expect to see in
# draft-ietf-sidr-roa-format-03, once it is issued.  In particular, note
# that the exactMatch boolean from the -02 draft has been replaced by
# the prefix and maxLength encoding used in the -03 draft.
#
# Payload data which can be configured in a @c &lt;route_origin/&gt; %object:
#
# @li @c asn (attribute):
#     Autonomous System Number (ASN) to place in the generated ROA.  A
#     single ROA can only grant authorization to a single ASN; multiple
#     ASNs require multiple ROAs, thus multiple @c &lt;route_origin/&gt; %objects.
#
# @li @c ipv4 (attribute):
#     %List of IPv4 prefix and maxLength values, see below for format.
#
# @li @c ipv6 (attribute):
#     %List of IPv6 prefix and maxLength values, see below for format.
#
# Control attributes that can be set to "yes" to force actions:
#
# @li @c suppress_publication:
#     Not implemented, may be removed from protocol.
#
# The lists of IPv4 and IPv6 prefix and maxLength values are represented
# as comma-separated text strings, with no whitespace permitted.  Each
# entry in such a string represents a single prefix/maxLength pair.
#
# ABNF for these address lists:
#
# @verbatim
#
#   <ROAIPAddress> ::= <address> "/" <prefixlen> [ "-" <max_prefixlen> ]
#                         ; Where <max_prefixlen> defaults to the same
#                         ; value as <prefixlen>.
#
#   <ROAIPAddressList> ::= <ROAIPAddress> *( "," <ROAIPAddress> )
#
# @endverbatim
#
# For example, @c "10.0.1.0/24-32,10.0.2.0/24", which is a shorthand
# form of @c "10.0.1.0/24-32,10.0.2.0/24-24".
#
# @section irdb_queries Operations initiated by the RPKI engine
#
# The left-right protocol also includes queries from the RPKI engine
# back to the IRDB.  These queries do not follow the message-passing
# pattern used in the IRBE-initiated part of the protocol.  Instead,
# there's a single query back to the IRDB, with a corresponding
# response.  The CMS and HTTPS encoding are the same as in the rest of
# the protocol, but the BPKI certificates will be different as the
# back-queries and responses form a separate communication channel.
#
# @subsection list_resources_msg <list_resources/> messages
#
# The @c &lt;list_resources/&gt; query and response allow the RPKI engine to ask
# the IRDB for information about resources assigned to a particular
# child.  The query must include both a @c "self_handle" attribute naming
# the @c &lt;self/&gt; that is making the request and also a @c "child_handle"
# attribute naming the child that is the subject of the query.  The
# query and response also allow an optional @c "tag" attribute of the
# same form used elsewhere in this protocol, to allow batching.
#
# A @c &lt;list_resources/&gt; response includes the following attributes, along
# with the @c tag (if specified), @c self_handle, and @c child_handle copied
# from the request:
#
# @li @c valid_until:
#     A timestamp indicating the date and time at which certificates
#     generated by the RPKI engine for these data should expire.  The
#     timestamp is expressed as an XML @c xsd:dateTime, must be
#     expressed in UTC, and must carry the "Z" suffix indicating UTC.
#
# @li @c asn:
#     A %list of autonomous sequence numbers, expressed as a
#     comma-separated sequence of decimal integers with no whitespace.
#
# @li @c ipv4:
#     A %list of IPv4 address prefixes and ranges, expressed as a
#     comma-separated %list of prefixes and ranges with no whitespace.
#     See below for format details.
#
# @li @c ipv6:
#     A %list of IPv6 address prefixes and ranges, expressed as a
#     comma-separated %list of prefixes and ranges with no whitespace.
#     See below for format details.
#
# Entries in a %list of address prefixes and ranges can be either
# prefixes, which are written in the usual address/prefixlen notation,
# or ranges, which are expressed as a pair of addresses denoting the
# beginning and end of the range, written in ascending order separated
# by a single "-" character.  This format is superficially similar to
# the format used for prefix and maxLength values in the @c &lt;route_origin/&gt;
# %object, but the semantics differ: note in particular that
# @c &lt;route_origin/&gt; %objects don't allow ranges, while @c &lt;list_resources/&gt;
# messages don't allow a maxLength specification.
#
# @section left_right_error_handling Error handling
#
# Error in this protocol are handled at two levels.
#
# Since all messages in this protocol are conveyed over HTTPS
# connections, basic errors are indicated via the HTTP response code.
# 4xx and 5xx responses indicate that something bad happened.  Errors
# that make it impossible to decode a query or encode a response are
# handled in this way.
#
# Where possible, errors will result in a @c &lt;report_error/&gt; message which
# takes the place of the expected protocol response message.
# @c &lt;report_error/&gt; messages are CMS-signed XML messages like the rest of
# this protocol, and thus can be archived to provide an audit trail.
#
# @c &lt;report_error/&gt; messages only appear in replies, never in queries.
# The @c &lt;report_error/&gt; message can appear on either the "forward" (IRBE
# as client of RPKI engine) or "back" (RPKI engine as client of IRDB)
# communication channel.
#
# The @c &lt;report_error/&gt; message includes an optional @c "tag" attribute to
# assist in matching the error with a particular query when using
# batching, and also includes a @c "self_handle" attribute indicating the
# @c &lt;self/&gt; that issued the error.
#
# The error itself is conveyed in the @c error_code (attribute).  The
# value of this attribute is a token indicating the specific error that
# occurred.  At present this will be the name of a Python exception; the
# production version of this protocol will nail down the allowed error
# tokens here, probably in the RelaxNG schema.
#
# The body of the @c &lt;report_error/&gt; element itself is an optional text
# string; if present, this is debugging information.  At present this
# capabilty is not used, debugging information goes to syslog.

## @page Publication Publication protocol
#
# The %publication protocol is really two separate client/server
# protocols, between different parties.  The first is a configuration
# protocol for an IRBE to use to configure a %publication engine,
# the second is the interface by which authorized clients request
# %publication of specific objects.
#
# Much of the architecture of the %publication protocol is borrowed
# from the @link Left-right left-right protocol: @endlink like the
# left-right protocol, the %publication protocol uses CMS-wrapped XML
# over HTTPS with the same eContentType OID and the same HTTPS
# content-type, and the overall style of the XML messages is very
# similar to the left-right protocol.  All operations allow an
# optional "tag" attribute to allow batching.
#
# The %publication engine operates a single HTTPS server which serves
# both of these subprotocols.  The two subprotocols share a single
# server port, but use distinct URLs to allow demultiplexing.
#
# @section Terminology
#
# @li @em IRBE: Internet Registry Back End
#
# @li @em IRDB: Internet Registry Data Base
#
# @li @em BPKI: Business PKI
#
# @li @em RPKI: Resource PKI
#
# @section Publication-control Publication control subprotocol
#
# The control subprotocol reuses the message-passing design of the
# left-right protocol.  Configured objects support the "create", "set",
# "get", "list", and "destroy" actions, or a subset thereof when the
# full set of actions doesn't make sense.
#
# @subsection config_obj <config/> object
#
# The &lt;config/&gt; %object allows configuration of data that apply to the
# entire %publication server rather than a particular client.
#
# There is exactly one &lt;config/&gt; %object in the %publication server, and
# it only supports the "set" and "get" actions -- it cannot be created
# or destroyed.
#
# Payload data which can be configured in a &lt;config/&gt; %object:
#
# @li @c bpki_crl (element):
#     This is the BPKI CRL used by the %publication server when
#     signing the CMS wrapper on responses in the %publication
#     subprotocol.  As the CRL must be updated at regular intervals,
#     it's not practical to restart the %publication server when the
#     BPKI CRL needs to be updated.  The BPKI model doesn't require
#     use of a BPKI CRL between the IRBE and the %publication server,
#     so we can use the %publication control subprotocol to update the
#     BPKI CRL.
#
# @subsection client_obj <client/> object
#
# The &lt;client/&gt; %object represents one client authorized to use the
# %publication server.
#
# The &lt;client/&gt; %object supports the full set of "create", "set", "get",
# "list", and "destroy" actions.  Each client has a "client_handle"
# attribute, which is used in responses and must be specified in "create", "set",
# "get", or "destroy" actions.
#
# Payload data which can be configured in a &lt;client/&gt; %object:
#
# @li @c base_uri (attribute):
#     This is the base URI below which this client is allowed to publish
#     data.  The %publication server may impose additional constraints in
#     the case of a child publishing beneath its parent.
#
# @li @c bpki_cert (element):
#     BPKI CA certificate for this &lt;client/&gt;.  This is used as part of
#     the certificate chain when validating incoming TLS and CMS
#     messages.  If the bpki_glue certificate is in use (below), the
#     bpki_cert certificate should be issued by the bpki_glue
#     certificate; otherwise, the bpki_cert certificate should be issued
#     by the %publication engine's bpki_ta certificate.
#
# @li @c bpki_glue (element):
#     Another BPKI CA certificate for this &lt;client/&gt;, usually not
#     needed.  Certain pathological cross-certification cases require a
#     two-certificate chain due to issuer name conflicts.  If used, the
#     bpki_glue certificate should be the issuer of the bpki_cert
#     certificate and should be issued by the %publication engine's
#     bpki_ta certificate; if not needed, the bpki_glue certificate
#     should be left unset.
#
# @section Publication-publication Publication subprotocol
#
# The %publication subprotocol is structured somewhat differently from
# the %publication control protocol.  Objects in the %publication
# subprotocol represent objects to be published or objects to be
# withdrawn from %publication.  Each kind of %object supports two actions:
# "publish" and "withdraw".  In each case the XML element representing
# hte %object to be published or withdrawn has a "uri" attribute which
# contains the %publication URI.  For "publish" actions, the XML element
# body contains the DER %object to be published, encoded in Base64; for
# "withdraw" actions, the XML element body is empty.
#
# In theory, the detailed access control for each kind of %object might
# be different.  In practice, as of this writing, access control for all
# objects is a simple check that the client's @c "base_uri" is a leading
# substring of the %publication URI.  Details of why access control might
# need to become more complicated are discussed in a later section.
#
# @subsection certificate_obj <certificate/> object
#
# The &lt;certificate/&gt; %object represents an RPKI certificate to be
# published or withdrawn.
#
# @subsection crl_obj <crl/> object
#
# The &lt;crl/&gt; %object represents an RPKI CRL to be published or withdrawn.
#
# @subsection manifest_obj <manifest/> object
#
# The &lt;manifest/&gt; %object represents an RPKI %publication %manifest to be
# published or withdrawn.
#
# Note that part of the reason for the batching support in the
# %publication protocol is because @em every %publication or withdrawal
# action requires a new %manifest, thus every %publication or withdrawal
# action will involve at least two objects.
#
# @subsection roa_obj <roa/> object
#
# The &lt;roa/&gt; %object represents a ROA to be published or withdrawn.
#
# @section publication_error_handling Error handling
#
# Error in this protocol are handled at two levels.
#
# Since all messages in this protocol are conveyed over HTTPS
# connections, basic errors are indicated via the HTTP response code.
# 4xx and 5xx responses indicate that something bad happened.  Errors
# that make it impossible to decode a query or encode a response are
# handled in this way.
#
# Where possible, errors will result in a &lt;report_error/&gt; message which
# takes the place of the expected protocol response message.
# &lt;report_error/&gt; messages are CMS-signed XML messages like the rest of
# this protocol, and thus can be archived to provide an audit trail.
#
# &lt;report_error/&gt; messages only appear in replies, never in
# queries.  The &lt;report_error/&gt; message can appear in both the
# control and publication subprotocols.
#
# The &lt;report_error/&gt; message includes an optional @c "tag" attribute to
# assist in matching the error with a particular query when using
# batching.
#
# The error itself is conveyed in the @c error_code (attribute).  The
# value of this attribute is a token indicating the specific error that
# occurred.  At present this will be the name of a Python exception; the
# production version of this protocol will nail down the allowed error
# tokens here, probably in the RelaxNG schema.
#
# The body of the &lt;report_error/&gt; element itself is an optional text
# string; if present, this is debugging information.  At present this
# capabilty is not used, debugging information goes to syslog.
#
# @section publication_access_control Additional access control considerations.
#
# As detailed above, the %publication protocol is trivially simple.  This
# glosses over two bits of potential complexity:
#
# @li In the case where parent and child are sharing a repository, we'd
#     like to nest child under parent, because testing has demonstrated
#     that even on relatively slow hardware the delays involved in
#     setting up separate rsync connections tend to dominate
#     synchronization time for relying parties.
#
# @li The repository operator might also want to do some checks to
#     assure itself that what it's about to allow the RPKI engine to
#     publish is not dangerous toxic waste.
#
# The up-down protocol includes a mechanism by which a parent can
# suggest a %publication URI to each of its children.  The children are
# not required to accept this hint, and the children must make separate
# arrangements with the repository operator (who might or might not be
# the same as the entity that hosts the children's RPKI engine
# operations) to use the suggested %publication point, but if everything
# works out, this allows children to nest cleanly under their parents
# %publication points, which helps reduce synchronization time for
# relying parties.
#
# In this case, one could argue that the %publication server is
# responsible for preventing one of its clients (the child in the above
# description) from stomping on data published by another of its clients
# (the parent in the above description).  This goes beyond the basic
# access check and requires the %publication server to determine whether
# the parent has given its consent for the child to publish under the
# parent.  Since the RPKI certificate profile requires the child's
# %publication point to be indicated in an SIA extension in a certificate
# issued by the parent to the child, the %publication engine can infer
# this permission from the parent's issuance of a certificate to the
# child.  Since, by definition, the parent also uses this %publication
# server, this is an easy check, as the %publication server should
# already have the parent's certificate available by the time it needs
# to check the child's certificate.
#
# The previous paragraph only covers a "publish" action for a
# &lt;certificate/&gt; %object.  For "publish" actions on other
# objects, the %publication server would need to trace permission back
# to the certificate issued by the parent; for "withdraw" actions,
# the %publication server would have to perform the same checks it
# would perform for a "publish" action, using the current published
# data before withdrawing it.  The latter in turn implies an ordering
# constraint on "withdraw" actions in order to preserve the data
# necessary for these access control decisions; as this may prove
# impractical, the %publication server may probably need to make
# periodic sweeps over its published data looking for orphaned
# objects, but that's probably a good idea anyway.
#
# Note that, in this %publication model, any agreement that the
# repository makes to publish the RPKI engine's output is conditional
# upon the %object to be published passing whatever access control checks
# the %publication server imposes.

## @page sql-schemas SQL database schemas
#
# @li @subpage rpkid-sql "rpkid database schema"
# @li @subpage pubd-sql "pubd database schema"
# @li @subpage irdbd-sql "irdbd database schema"

## @page rpkid-sql rpkid SQL schema
#
# @dotfile rpkid.dot "Diagram of rpkid.sql"
#
# @verbinclude rpkid.sql

## @page pubd-sql pubd SQL Schema
#
# @dotfile pubd.dot "Diagram of pubd.sql"
#
# @verbinclude pubd.sql

## @page irdbd-sql irdbd SQL Schema
#
# @dotfile irdbd.dot "Diagram of irdbd.sql"
#
# @verbinclude irdbd.sql

## @page bpki-model BPKI model
#
# The "business PKI" (BPKI) is the PKI used to authenticate
# communication on the up-down, left-right, and %publication protocols.
# BPKI certificates are @em not resource PKI (RPKI) certificates.  The
# BPKI is a separate PKI that represents relationships between the
# various entities involved in the production side of the RPKI system.
# In most cases the BPKI tree will follow existing business
# relationships, hence the name "BPKI".
#
# Setup of the BPKI is handled by the back end; for the most part,
# rpkid and pubd just use the result.  The one place where the engines
# are directly involved in creation of new BPKI certificates is in the
# production of end-entity certificates for use by the engines.
#
# There are a few design principals that underly the chosen BPKI model:
# @li Each engine should rely on a single BPKI trust anchor which is
#     controlled by the back end entity that runs the engine; all
#     other trust material should be cross-certified into the engine's
#     BPKI tree.
# @li Private keys must never transit the network.
# @li Except for end entity certificates, the engine should only have
#     access to the BPKI certificates; in particular, the private key
#     for the BPKI trust anchor should not be accessible to the engine.
# @li The number of BPKI keys and certificates that the engine has to
#     manage should be no larger than is necessary.
#
# rpkid's hosting model adds an additional constraint: rpkid's BPKI
# trust anchor belongs to the entity operating rpkid, but the entities
# hosted by rpkid should have control of their own BPKI private keys.
# This implies the need for an additional layer of BPKI certificate
# hierarchy within rpkid.
#
# Here is a simplified picture of what the BPKI might look like for an
# rpkid operator that hosts two entities, "Alice" and "Ellen":
#
# @dot
# // Color code:
# //   Black:   Hosting entity
# //   Blue:    Hosted entity
# //   Red:     Cross-certified peer
# //
# // Shape code:
# //   Octagon: TA
# //   Diamond: CA
# //   Record:  EE
# 
# digraph bpki_rpkid {
#       splines = true;
#       size = "14,14";
#       node                    [ fontname = Times, fontsize = 9 ];
# 
#       // Hosting entity
#       node                    [ color = black, shape = record ];
#       TA                      [ shape = octagon, label = "BPKI TA" ];
#       rpkid                   [ label = "rpkid|{HTTPS server|HTTPS left-right client|CMS left-right}" ];
#       irdbd                   [ label = "irdbd|{HTTPS left-right server|CMS left-right}" ];
#       irbe                    [ label = "IRBE|{HTTPS left-right client|CMS left-right}" ];
# 
#       // Hosted entities
#       node                    [ color = blue, fontcolor = blue ];
#       Alice_CA                [ shape = diamond ];
#       Alice_EE                [ label = "Alice\nBSC EE|{HTTPS up-down client|CMS up-down}" ];
#       Ellen_CA                [ shape = diamond ];
#       Ellen_EE                [ label = "Ellen\nBSC EE|{HTTPS up-down client|CMS up-down}" ];
# 
#       // Peers
#       node                    [ color = red, fontcolor = red, shape = diamond ];
#       Bob_CA;
#       Carol_CA;
#       Dave_CA;
#       Frank_CA;
#       Ginny_CA;
#       Harry_CA;
#       node                    [ shape = record ];
#       Bob_EE                  [ label = "Bob\nEE|{HTTPS up-down|CMS up-down}" ];
#       Carol_EE                [ label = "Carol\nEE|{HTTPS up-down|CMS up-down}" ];
#       Dave_EE                 [ label = "Dave\nEE|{HTTPS up-down|CMS up-down}" ];
#       Frank_EE                [ label = "Frank\nEE|{HTTPS up-down|CMS up-down}" ];
#       Ginny_EE                [ label = "Ginny\nEE|{HTTPS up-down|CMS up-down}" ];
#       Harry_EE                [ label = "Bob\nEE|{HTTPS up-down|CMS up-down}" ];
# 
#       edge                    [ color = black, style = solid ];
#       TA -> Alice_CA;
#       TA -> Ellen_CA;
# 
#       edge                    [ color = black, style = dotted ];
#       TA -> rpkid;
#       TA -> irdbd;
#       TA -> irbe;
# 
#       edge                    [ color = blue, style = solid ];
#       Alice_CA -> Bob_CA;
#       Alice_CA -> Carol_CA;
#       Alice_CA -> Dave_CA;
#       Ellen_CA -> Frank_CA;
#       Ellen_CA -> Ginny_CA;
#       Ellen_CA -> Harry_CA;
# 
#       edge                    [ color = blue, style = dotted ];
#       Alice_CA -> Alice_EE;
#       Ellen_CA -> Ellen_EE;
# 
#       edge                    [ color = red, style = solid ];
#       Bob_CA   -> Bob_EE;
#       Carol_CA -> Carol_EE;
#       Dave_CA  -> Dave_EE;
#       Frank_CA -> Frank_EE;
#       Ginny_CA -> Ginny_EE;
#       Harry_CA -> Harry_EE;
# }
# @enddot
#
# Black objects belong to the hosting entity, blue objects belong to
# the hosted entities, red objects are cross-certified objects from
# the hosted entities' peers.  The arrows indicate certificate
# issuance: solid arrows are the ones that rpkid will care about
# during certificate validation, dotted arrows show the origin of the
# EE certificates that rpkid uses to sign CMS and TLS messages.
#
# There's one nasty bit where the model had to bend to fit the current
# state of the underlying protocols: it's not possible to use exactly
# the same BPKI keys and certificates for HTTPS and CMS.  The reason
# for this is simple: each hosted entity has its own BPKI, as does the
# hosting entity, but the HTTPS listener is shared.  The only ways to
# avoid sharing the HTTPS server certificate would be to use separate
# listeners for each hosted entity, which scales poorly, or to rely on
# the TLS "Server Name Indication" extension (RFC 4366 3.1) which is
# not yet widely implemented.
#
# The certificate tree looks complicated, but the set of certificates
# needed to build any particular validation chain is obvious, again
# excepting the HTTPS server case, where the client certificate is the
# first hint that the engine has of the client's identity, so the
# server must be prepared to accept any current client certificate.
#
# Detailed instructions on how to build a BPKI are beyond the scope of
# this document, but one can handle simple cases using the OpenSSL
# command line tool and cross_certify.py; the latter is a tool
# designed specifically for the purpose of generating the
# cross-certification certificates needed to splice foreign trust
# material into a BPKI tree.
#
# The BPKI tree for a pubd instance is similar to to the BPKI tree for
# an rpkid instance, but is a bit simpler, as pubd does not provide
# hosting in the same sense that rpkid does: pubd is a relatively
# simple server that publishes objects as instructed by its clients.
#
# Here's a simplified picture of what the BPKI might look like for a
# pubd operator that serves two clients, "Alice" and "Bob":
#
# @dot
# // Color code:
# //   Black:   Operating entity
# //   Red:     Cross-certified client
# //
# // Shape code:
# //   Octagon: TA
# //   Diamond: CA
# //   Record:  EE
# 
# digraph bpki_pubd {
#       splines = true;
#       size = "14,14";
#       node                    [ fontname = Times, fontsize = 9 ];
# 
#       // Operating entity
#       node                    [ color = black, fontcolor = black, shape = record ];
#       TA                      [ shape = octagon, label = "BPKI TA" ];
#       pubd                    [ label = "pubd|{HTTPS server|CMS}" ];
#       ctl                     [ label = "Control|{HTTPS client|CMS}" ];
# 
#       // Clients
#       node                    [ color = red, fontcolor = red, shape = diamond ];
#       Alice_CA;
#       Bob_CA;
#       node                    [ color = red, fontcolor = red, shape = record ];
#       Alice_EE                [ label = "Alice\nEE|{HTTPS client|CMS}" ];
#       Bob_EE                  [ label = "Bob\nEE|{HTTPS client|CMS}" ];
# 
#       edge                    [ color = black, style = dotted ];
#       TA -> pubd;
#       TA -> ctl;
#
#       edge                    [ color = black, style = solid ];
#       TA -> Alice_CA;
#       TA -> Bob_CA;
#
#       edge                    [ color = red, style = solid ];
#       Alice_CA -> Alice_EE;
#       Bob_CA -> Bob_EE;
# }
# @enddot
#
# While it is likely that RIRs (at least) will operate both rpkid and
# pubd instances, the two functions are conceptually separate.  As far
# as pubd is concerned, it doesn't matter who operates the rpkid
# instance: pubd just has clients, each of which has trust material
# that has been cross-certified into pubd's BPKI.  Similarly, rpkid
# doesn't really care who operates a pubd instance that it's been
# configured to use, it just treats that pubd as a foreign BPKI whose
# trust material has to be cross-certified into its own BPKI.  Cross
# certification itself is done by the back end operator, using
# cross_certify or some equivalent tool; the resulting BPKI
# certificates are configured into rpkid and pubd via the left-right
# protocol and the control subprotocol of the publication protocol,
# respectively.
#
# Because the BPKI tree is almost entirely controlled by the operating
# entity, CRLs are not necessary for most of the BPKI.  The one
# exception to this is the EE certificates issued under the
# cross-certification points.  These EE certificates are generated by
# the peer, not the local operator, and thus require CRLs.  Because of
# this, both rpkid and pubd require regular updates of certain BPKI
# CRLs, again via the left-right and publication control protocols.
#
# Because the left-right protocol and the publication control
# subprotocol are used to configure BPKI certificates and CRLs, they
# cannot themselves use certificates and CRLs configured in this way.
# This is why the configuration files for rpkid and pubd require
# static configuration of the left-right and publication control
# certificates.

# Local Variables:
# compile-command: "cd .. && make doc"
# End:
