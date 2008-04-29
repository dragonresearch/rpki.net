# $Id$

# Copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
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

# The "usage" text in the OPERATIONS section is a pain to keep
# syncrhonized with programs like irbe-cli.py which generate their
# usage dynamically.  In theory we could address this by running each
# of these programs with the --help option, saving the resulting usage
# message to a file, and including it here using Doxygen's
# "verbinclude" command.  There's a similar problem with config files,
# though, and I see no obvious way to automate them.  Keeping the
# documentation with the config file options would be nice.  Someday.

## @mainpage
##
## This collection of Python modules implements a prototype of the
## RPKI Engine.  This is a work in progress.
##
## See http://viewvc.hactrn.net/subvert-rpki.hactrn.net/ for code,
## design documents, a text mirror of portions of APNIC's Wiki, etc.
##
## The documentation you're reading is generated automatically by
## Doxygen from comments and documentation in
## <a href="http://viewvc.hactrn.net/subvert-rpki.hactrn.net/rpkid/rpki/">the code</a>.
##
## This work is funded by <a href="http://www.arin.net/">ARIN</a>, in
## collaboration with the other RIRs.  If you're interested in this
## package you might also be interested in:
##
## @li <a href="http://viewvc.hactrn.net/subvert-rpki.hactrn.net/rcynic/">the rcynic validation tool</a>
## @li <a href="http://www.hactrn.net/opaque/rcynic.html">a sample of rcynic's summary output</a>
## @li <a href="http://mirin.apnic.net/resourcecerts/wiki/">APNIC's Wiki</a>
## @li <a href="http://mirin.apnic.net/trac/">APNIC's project Trac instance</a>
##
## @page Installation Installation
##
## Preliminary installation instructions for rpkid et al.  These are the
## production-side RPKI tools, for Internet Registries (RIRs, LIRs, etc).
## See ../rcynic/README for relying party tools.
## 
## rpkid is a set of Python modules supporting generation and maintenance
## of resource certificates.  Most of the code is in the rpkid/rpki/
## directory.  rpkid itself is a relatively small program that calls the
## library modules.  There are several other programs that make use of
## the same libraries, as well as a collection of test programs.
## 
## At present the package is intended to be run out of its build
## directory.  Setting up proper installation in a system area using the
## Python distutils package would likely not be very hard but has not yet
## been done.
## 
## Note that initial development of this code has been on FreeBSD, so
## installation will probably be easiest on FreeBSD.
## 
## The first step to running the code is to build the OpenSSL and POW
## binaries.  At present the OpenSSL code is just a copy of the stock
## OpenSSL 0.9.8g release, compiled with special options to enable
## RFC 3779 support that ISC wrote under previous contract to ARIN.  The
## POW (Python OpenSSL Wrapper) library is an extended copy of the stock
## POW release.
## 
## To build these, cd to the top-level directory in the distribution and
## type "make".
## 
## @verbatim
##   $ cd $top
##   $ make
## @endverbatim
## 
## This should automatically build everything, in the right order,
## including staticly linking the POW extension module with the OpenSSL
## library to provide RFC 3779 support.
## 
## Next, see the %list of required Python modules in rpkid/README.  Note
## that the Python code requires Python version 2.5.  Install any modules
## that might be missing.
## 
## You will also need a MySQL installation.  This code was developed
## using MySQL 5.1 and has been tested with MySQL 5.0 and 5.1.
## 
## The architecture is intended to support hardware signing modules
## (HSMs), but the code to support them has not been written.
## 
## At this point, you should have all the necessary software installed.
## You will probably want to test it.  All tests should be run from the
## rpkid/ directory.
## 
## Some of the tests require MySQL databases to store their data.  To set
## up all the databases that the tests will need, run the SQL commands in
## rpkid/testbed.sql.  The MySQL command line client is usually the
## easiest way to do this, eg:
## 
## @verbatim
##   $ cd $top/rpkid
##   $ mysql -u root -p <testbed.sql
## @endverbatim
## 
## To run the tests, run "make all-tests":
## 
## @verbatim
##   $ cd $top/rpkid
##   $ make all-tests
## @endverbatim
## 
## If nothing explodes, your installation is probably ok.  Any Python
## backtraces in the output indicate a problem.
##
##
##
## @page Operation Operation
##
## Preliminary operation instructions for rpkid et al.  These are the
## production-side RPKI tools, for Internet Registries (RIRs, LIRs, etc).
## See ../rcynic/README for relying party tools.
## 
## @warning
## rpkid is still in development, and the code changes more often than
## the hand-maintained portions of this documentation.  The following
## text was reasonably accurate at the time it was written but may be
## obsolete by the time you read it.
##
## At present the package is intended to be run out of the @c rpkid/
## directory.
## 
## In addition to the library routines in the @c rpkid/rpki/ directory,
## the package includes the following programs:
## 
## @li @c rpkid.py
##              The main RPKI engine daemon
## 
## @li @c rootd.py
##              A separate daemon for handling the root of an RPKI
##              certificate tree.  This is essentially a stripped down
##              version of rpkid with no SQL database, no left-right
##              protocol implementation, and only the parent side of
##              the up-down protocol.  It's separate because the root
##              is a special case in several ways and it was simpler
##              to keep the special cases out of the main daemon.
## 
## @li @c irdbd.py
##              A sample implementation of an IR database daemon.
##              rpkid calls into this to perform lookups via the
##              left-right protocol.
## 
## @li @c irbe-cli.py
##              A command-line client for the left-right control
##              protocol. 
## 
## @li @c irbe-setup.py
##              An example of a script to set up the mappings between
##              the IRDB and rpkid's own database, using the
##              left-right control protocol.
## 
## @li @c cronjob.py
##              A trivial HTTP client used to drive rpkid cron events.
## 
## @li @c testbed.py
##              A test tool for running a collection of rpkid and irdb
##              instances under common control, driven by a unified
##              test script.
## 
## @li @c testpoke.py
##              A simple client for the up-down protocol, mostly
##              compatable with APNIC's rpki_poke.pl tool.
## 
## Most of these programs take configuration files in a common format
## similar to that used by the OpenSSL command line tool.  The test
## programs also take input in YAML format to drive the tests.  Runs of
## the testbed.py test tool will generate a fairly complete set
## configuration files which may be useful as examples.
## 
## Basic operation consists of creating the appropriate MySQL databases,
## starting rpkid, rootd, and irdbd, using the left-right control
## protocol to set up rpkid's internal state, and setting up a cron job
## to invoke rpkid's cron action at regular intervals.  All other
## operations should occur either as a result of cron events or as a
## result of incoming left-right and up-down protocol requests.
## 
## Note that the publication protocol isn't fully specified yet, much
## less implmenented.  At the moment rpkid just writes its outputs to a
## local directory tree.
## 
## Note that the full event-driven model for rpkid hasn't yet been
## implemented.  The design is intended to allow an arbitrary number of
## hosted RPKI engines to run in a single rpkid instance, but without the
## event-driven tasking model one has to set up a separate rpkid instance
## for each hosted RPKI engine.
## 
## At present the daemon programs all run in foreground, that is, if one
## wants them to run in background one must do so manually, eg, using
## Bourne shell syntax:
## 
## @verbatim
##   $ python whatever.py &
##   $ echo >whatever.pid  "$!"
## @endverbatim
## 
## All of the daemons use syslog.  At present they all set LOG_PERROR, so
## all logging also goes to stderr.
##
##
## @section rpkid rpkid.py
## 
## rpkid is the main RPKI engine daemon.  Configuration of rpkid is a two
## step process: a %config file to bootstrap rpkid to the point where it
## can speak using the left-right protocol, followed by dynamic
## configuration via the left-right protocol.  In production use the
## latter stage would be handled by the IRBE stub; for test and
## develoment purposes it's handled by the irbe-cli.py command line
## interface or by the testbed.py test framework.
## 
## rpkid stores dynamic data in an SQL database, which must have been
## created for it, as explained in the installation guide.
## 
## The default %config file is rpkid.conf, start rpkid with "-c filename"
## to choose a different %config file.  All options are in the section
## "[rpkid]".  Certificates, keys, and trust anchors may be in either DER
## or PEM format.
## 
## %Config file options:
## 
## @li @c startup-message
##                      String to %log on startup, useful when
##                      debugging a collection of rpkid instances at
##                      once.
## 
## @li @c sql-username
##                      Username to hand to MySQL when connecting to
##                      rpkid's database.
## 
## @li @c sql-database
##                      MySQL's database name for rpkid's database.
## 
## @li @c sql-password
##                      Password to hand to MySQL when connecting to
##                      rpkid's database.
## 
## @li @c cms-ta-irdb
##                      Name of file containing CMS trust anchor to
##                      use when authenticating messages from irdbd.
## 
## @li @c cms-ta-irbe
##                      Name of file containing CMS trust anchor to
##                      use when authenticating control messages from
##                      IRBE.
## 
## @li @c cms-key
##                      Name of file containing RSA key to use when
##                      signing CMS messages to IRBE or irdbd.
## 
## @li @c cms-cert
##                      Name(s) of file(s) containing certificate(s)
##                      to include in CMS wrapper when signing
##                      messages to IRBE or irdbd.   You can specify
##                      more than one certificate using OpenSSL-style
##                      subscripts: cms-cert.0, cms-cert.1, etc.
## 
## @li @c https-key
##                      Name of file containing RSA key to use, both
##                      in the HTTPS server role (for both up-down and
##                      left-right protocols) and in the HTTPS client
##                      role (left-right protocol only).
## 
## @li @c https-cert
##                      Name(s) of file(s) containing certificate(s)
##                      to use in same contexts where https-key is
##                      used.  You can specify more than one
##                      certificate using OpenSSL-style subscripts:
##                      https-cert.0, https-cert.1, etc.
## 
## @li @c https-ta
##                      Name of file containing trust anchor to use
##                      when verifying irdbd's HTTPS server
##                      certificate.
## 
## @li @c irdb-url
##                      Service URL for irdbd.  Must be a %https:// URL.
## 
## @li @c https-server-host
##                      Hostname or IP address on which to listen for
##                      HTTPS connections.  Current default is
##                      INADDR_ANY (IPv4 0.0.0.0); this will need to
##                      be hacked to support IPv6 for production.
## 
## @li @c https-server-port
##                      TCP port on which to listen for HTTPS
##                      connections.
## 
## @li @c publication-kludge-base
##                      [TEMPORARY] Local directory under which
##                      generated certificates etc should be
##                      published.  This is a temporary expedient
##                      until the publication protocol is defined and
##                      implemented.  Default is "publication/"
##
##
## @section rootd rootd.py
## 
## rootd is a stripped down implmenetation of (only) the server side of
## the up-down protocol.  It's a separate program because the root
## certificate of an RPKI certificate tree requires special handling and
## may also require a special handling policy.  rootd is a simple
## implementation intended for test use, it's not suitable for use in a
## production system.  All configuration comes via the %config file.
## 
## The default %config file is rootd.conf, start rootd with "-c filename"
## to choose a different %config file.  All options are in the section
## "[rootd]".  Certificates, keys, and trust anchors may be in either DER
## or PEM format.
## 
## %Config file options:
## 
## @li @c cms-ta
##                      Name of file containing trust anchor to use
##                      when verifying CMS up-down queries.
## 
## @li @c cms-key
##                      Name of file containing RSA key to use when
##                      signing CMS up-down replies.
## 
## @li @c cms-cert
##                      Name(s) of file(s) containing certificate(s)
##                      to include in CMS wrapper when signing up-down
##                      replies.   You can specify more than one
##                      certificate using OpenSSL-style subscripts:
##                      cms-cert.0, cms-cert.1, etc.
## 
## @li @c https-key
##                      Name of file containing RSA key to use in the
##                      HTTPS server role for the up-down protocol.
## 
## @li @c https-cert
##                      Name(s) of file(s) containing certificate(s)
##                      to use in the HTTPS server role for the
##                      up-down protocol.  You can specify more than
##                      one certificate using OpenSSL-style
##                      subscripts: https-cert.0, https-cert.1,
##                      etc.
## 
## @li @c https-server-host
##                      Hostname or IP address on which to listen for
##                      HTTPS connections.  Default is localhost.
## 
## @li @c https-server-port
##                      TCP port on which to listen for HTTPS
##                      connections.
## 
## @li @c rpki-key
##                      Name of file containing RSA key to use in
##                      signing resource certificates.
## 
## @li @c rpki-issuer
##                      Name of file containing self-signed root
##                      resource certificate corresponding to
##                      rpki-key.
## 
## rpki-subject-filename:
##                      Name of file that rootd should use to save the
##                      one and only certificate it issues.
## 
## rpki-pkcs10-filename:
##                      Name of file that rootd should use when saving
##                      a copy of the received PKCS #10 request for a
##                      resource certificate.  This is only used for
##                      debugging.  Default is not to save the PKCS
##                      #10 request.
## 
## 
## @section irdbd irdbd.py
## 
## irdbd is a sample implemntation of the server side of the IRDB
## callback subset of the left-right protocol.  In production use this
## service is a function of the IRBE stub; irdbd may be suitable for
## production use in simple cases, but an IR with a complex IRDB may need
## to extend or rewrite irdbd.
## 
## irdbd requires a pre-populated database to represent the IR's
## customers.  irdbd expects this database to use the SQL schema defined
## in rpkid/irdbd.sql.  Once this database has been populated, the
## IRBE stub needs to create the appropriate objects in rpkid's database
## via the control subset of the left-right protocol, and store the
## linkage IDs (foreign keys into rpkid's database, basicly) in the
## IRDB.  The irbe-setup.py program shows an example of how to do this.
## 
## irdbd's default %config file is irdbd.conf, start irdbd with "-c
## filename" to choose a different %config file.  All options are in the
## section "[irdbd]".  Certificates, keys, and trust anchors may be in
## either DER or PEM format.
## 
## %Config file options:
## 
## @li @c startup-message
##                      String to %log on startup, useful when
##                      debugging a collection of irdbd instances at
##                      once.
## 
## @li @c sql-username
##                      Username to hand to MySQL when connecting to
##                      irdbd's database.
## 
## @li @c sql-database
##                      MySQL's database name for irdbd's database.
## 
## @li @c sql-password
##                      Password to hand to MySQL when connecting to
##                      irdbd's database.
## 
## @li @c cms-ta
##                      Name of file containing CMS trust anchor to
##                      use when authenticating messages from rpkid.
## 
## @li @c cms-key
##                      Name of file containing RSA key to use when
##                      signing CMS messages to rpkid.
## 
## @li @c cms-cert
##                      Name(s) of file(s) containing certificate(s)
##                      to include in CMS wrapper when signing
##                      messages to rpkid.  You can specify more than
##                      one certificate using OpenSSL-style
##                      subscripts: cms-cert.0, cms-cert.1, etc.
## 
## @li @c https-key
##                      Name of file containing RSA key to use in the
##                      HTTPS server role when listening for
##                      connections from rpkid. 
## 
## @li @c https-cert
##                      Name(s) of file(s) containing certificate(s)
##                      to use in the HTTPS server role when listening
##                      for connections from rpkid.  You can specify
##                      more than one certificate using OpenSSL-style
##                      subscripts: https-cert.0, https-cert.1, etc.
## 
## @li @c https-url
##                      Service URL for irdbd.  Must be a %https:// URL.
## 
## 
## @section irdbd_cli irbe-cli.py
## 
## irbe-cli is a simple command line client for the control subset of the
## left-right protocol.  In production use this functionality would be
## part of the IRBE stub.
## 
## Basic configuration of irbe-cli is handled via a %config file.  The
## specific action or actions to be performed are specified on the
## command line, and map closely to the left-right protocol itself.
## 
## At present the user is assumed to be able to read the (XML) left-right
## protocol messages, and with one exception, no attempt is made to
## interpret the responses other than to check for errors.  The one
## exception is that, if the @c --pem_out option is specified on the command
## line, any PKCS \#10 requests received from rpkid will be written in PEM
## format to that file; this makes it easier to hand these requests off
## to the business PKI in order to issue signing certs corresponding to
## newly generated business keys.
## 
## @verbatim
## Usage: irbe-cli.py --config= --help --pem_out=
## 
##   parent     --action= --type= --tag= --self_id= --parent_id=
##              --bsc_id= --repository_id= --peer_contact_uri=
##              --sia_base= --sender_name= --recipient_name=
##              --bpki_cms_cert= --bpki_cms_glue=
##              --bpki_https_cert= --bpki_https_glue=
##              --rekey --reissue --revoke
## 
##   repository --action= --type= --tag= --self_id= --repository_id=
##              --bsc_id= --peer_contact_uri=
##              --bpki_cms_cert= --bpki_cms_glue= 
##              --bpki_https_cert= --bpki_https_glue=
## 
##   self       --action= --type= --tag= --self_id= --crl_interval=
##              --bpki_cert= --bpki_glue=
##              --extension_preference= --rekey --reissue --revoke
##              --run_now --publish_world_now
##              --clear_extension_preferences
## 
##   child      --action= --type= --tag= --self_id= --child_id=
##              --bsc_id= --bpki_cms_cert= --bpki_cms_glue= --reissue
## 
##   route_origin --action= --type= --tag= --self_id= --route_origin_id=
##               --as_number= --ipv4= --ipv6= --suppress_publication
## 
##   bsc        --action= --type= --tag= --self_id= --bsc_id=
##              --key_type= --hash_alg= --key_length= --signing_cert=
##              --generate_keypair --clear_signing_certs
## @endverbatim
## 
## Global options (@c --config, @c --help, @c --pem_out) come first, then zero or
## more commands (parent, repository, self, child, route_origin, bsc),
## each followed by its own set of options.   The commands map to
## elements in the left-right protocol, and the command-specific options
## map to attributes or subelements for those commands.
## 
## @c --action is one of create, set, get, %list, or destroy; exactly one of
## these must be specified for each command.
## 
## @c --type is query or reply; since irbe-cli is a client, query is the
## default. 
## 
## @c --tag is an optional arbitrary tag (think IMAP) to simplify matching
## up replies with batched queries.
## 
## @c --*_id options refer to the primary keys of previously created
## objects.
## 
## The remaining options are specific to the particular commands, and
## follow directly from the left-right protocol specification.
## 
## A trailing "=" in the above option summary indicates that an option
## takes a value, eg, "--action create" or "--action=create".  Options
## without a trailing "=" correspond to boolean control attributes.
## 
## The default %config file for irbe-cli is irbe.conf, start rpkid with
## "-c filename" (or "--config filename") to choose a different %config
## file.  All options are in the section "[irbe-cli]".  Certificates,
## keys, and trust anchors may be in either DER or PEM format.
## 
## %Config file options:
## 
## @li @c cms-ta
##                      Name of file containing CMS trust anchor to
##                      use when authenticating messages from rpkid.
## 
## @li @c cms-key
##                      Name of file containing RSA key to use when
##                      signing CMS messages to rpkid.
## 
## @li @c cms-cert
##                      Name(s) of file(s) containing certificate(s)
##                      to include in CMS wrapper when signing
##                      messages to rpkid.  You can specify more than
##                      one certificate using OpenSSL-style
##                      subscripts: cms-cert.0, cms-cert.1, etc.
## 
## @li @c https-key
##                      Name of file containing RSA key to use in the
##                      HTTPS client role when contacting rpkid. 
## 
## @li @c https-cert
##                      Name(s) of file(s) containing certificate(s)
##                      to use in the HTTPS client role when
##                      contacting rpkid.  You can specify more than
##                      one certificate using OpenSSL-style
##                      subscripts: https-cert.0, https-cert.1,
##                      etc.
## 
## @li @c https-ta
##                      Name of file containing trust anchor to use
##                      when verifying rpkid's HTTPS server
##                      certificate.
## 
## @li @c https-url
##                      Service URL for rpkid.  Must be a %https:// URL.
## 
## 
## @section irbe_setup irbe-setup.py config file
## 
## The default %config file is irbe.conf, start rpkid with "-c filename"
## to choose a different %config file.  Most options are in the section
## "[irbe-cli]", but a few are in the section "[irdbd]".  Certificates,
## keys, and trust anchors may be in either DER or PEM format.
## 
## Options in the "[irbe-cli]" section:
## 
## @li @c cms-ta
##                      Name of file containing CMS trust anchor to
##                      use when authenticating messages from rpkid.
## 
## @li @c cms-key
##                      Name of file containing RSA key to use when
##                      signing CMS messages to rpkid.
## 
## @li @c cms-cert
##                      Name(s) of file(s) containing certificate(s)
##                      to include in CMS wrapper when signing
##                      messages to rpkid.  You can specify more than
##                      one certificate using OpenSSL-style
##                      subscripts: cms-cert.0, cms-cert.1, etc.
## 
## @li @c https-key
##                      Name of file containing RSA key to use in the
##                      HTTPS client role when contacting rpkid. 
## 
## @li @c https-cert
##                      Name(s) of file(s) containing certificate(s)
##                      to use in the HTTPS client role when
##                      contacting rpkid.  You can specify more than
##                      one certificate using OpenSSL-style
##                      subscripts: https-cert.0, https-cert.1,
##                      etc.
## 
## @li @c https-ta
##                      Name of file containing trust anchor to use
##                      when verifying rpkid's HTTPS server
##                      certificate.
## 
## @li @c https-url
##                      Service URL for rpkid.  Must be a %https:// URL.
## 
## Options in the "[irdbd]" section:
## 
## @li @c sql-username
##                      Username to hand to MySQL when connecting to
##                      irdbd's database.
## 
## @li @c sql-database
##                      MySQL's database name for irdbd's database.
## 
## @li @c sql-password
##                      Password to hand to MySQL when connecting to
##                      irdbd's database.
## 
## 
## @section cronjob cronjob.py
## 
## This is a trivial program to trigger a cron run within rpkid.  Once
## rpkid has been converted to the planned event-driven model, this
## function will be handled internally, but for now it has to be
## triggered by an external program.  For pseudo-production use one would
## run this program under the system cron daemon.  For scripted testing
## it happens to be useful to be able to control when cron cycles occur,
## so at the current stage of code development use of an external trigger
## is a useful feature.
## 
## The default %config file is cronjob.conf, start cronjob with "-c
## filename" to choose a different %config file.  All options are in the
## section "[cronjob]".  Certificates, keys, and trust anchors may be in
## either DER or PEM format.
## 
## %Config file options:
## 
## @li @c https-key
##                      Name of file containing RSA key to use in the
##                      HTTPS client role when contacting rpkid. 
## 
## @li @c https-cert
##                      Name(s) of file(s) containing certificate(s)
##                      to use in the HTTPS client role when
##                      contacting rpkid.  You can specify more than
##                      one certificate using OpenSSL-style
##                      subscripts: https-cert.0, https-cert.1,
##                      etc.
## 
## @li @c https-ta
##                      Name of file containing trust anchor to use
##                      when verifying rpkid's HTTPS server
##                      certificate.
## 
## @li @c https-url
##                      Service URL for rpkid.  Must be a %https:// URL.
## 
## 
## @section testbed testbed.py:
## 
## testbed is a test harness to set up and run a collection of rpkid and
## irdbd instances under scripted control.  testbed is a very recent
## addition to the toolset and is still evolving rapidly.
## 
## Unlike the programs described above, testbed takes two configuration
## files in different languages.  The first configuration file uses the
## same syntax as the above configuration files but is completely
## optional.  The second configuration file is the test script, which is
## encoded using the YAML serialization language (see
## http://www.yaml.org/ for more information on YAML).  The YAML script
## is not optional, as it describes the test layout.  testbed is designed
## to support running a fairly wide set of test configurations as canned
## scripts without writing any new control code.  The intent is to make
## it possible to write meaningful regression tests.
## 
## All of the options in in the first (optional) configuration file are
## just overrides for wired-in default values.   In most cases the
## defaults will suffice, and the set of options is still in flux, so
## only a few of the options are described here.    The default name for
## this configuration file is testbed.conf, run testbed with "-c
## filename" to change it.
## 
## testbed.conf options:
## 
## testbed_dir: Working directory into which testbed should write the
##              (many) files it generates.  Default is "testbed.dir".
## 
## irdb_db_pass:        MySQL password for the "irdb" user.  Default is
##              "fnord".  You may want to override this.
## 
## rpki_db_pass:        MySQL password for the "rpki" user.  Default is
##              "fnord".  You may want to override this.
## 
## rootd_sia:   rsync URI naming a (perhaps fictious) directory to use
##              as the id-ad-caRepository SIA value in the generated
##              root resource certificate.  Default is
##              "rsync://wombat.invalid/".  You may want to override
##              this if you intend to run an rsync server and test
##              against the generated results using rcynic.   This
##              default will likely change if and when testbed learns
##              how to run rcynic itself as part of the test suite.
## 
## The second configuration file is named testbed.yaml by default, run
## testbed with "-y filename" to change it.  The YAML file contains
## multiple YAML "documents".  The first document describes the initial
## test layout and resource allocations, subsequent documents describe
## modifications to the initial allocations and other parameters.
## Resources listed in the initial layout are aggregated automatically,
## so that a node in the resource hierarchy automatically receives the
## resources it needs to issue whatever its children are listed as
## holding.  Actions in the subsequent documents are modifications to the
## current resource set, modifications to validity dates or other
## non-resource parameters, or special commands like "sleep".  The
## details are still evolving, but here's an example of current usage:
## 
## @verbatim
##     name:           RIR
##     valid_for:      2d
##     sia_base:       "rsync://wombat.invalid/"
##     kids:
##       - name: LIR0
##      kids:
##        - name: Alice
##          ipv4: 192.0.2.1-192.0.2.33
##          asn:  64533
##     ---
##     - name: Alice
##       valid_add:   10
##     ---
##     - name: Alice
##       add_as: 33
##       valid_add:   2d
##     ---
##     - name: Alice
##       valid_sub:   2d
##     ---
##     - name: Alice
##       valid_for:   10d
## @endverbatim
## 
## This specifies an initial layout consisting of an RPKI engine named
## "RIR", with one child "LIR0", which in turn has one child "Alice".
## Alice has a set of assigned resources, and all resources in the system
## are initially set to be valid for two days from the time at which the
## test is started.  The first subsequent document adds ten seconds to
## the validity interval for Alice's resources and makes no other
## modifications.  The second subsequent document grants Alice additional
## resources and adds another two days to the validity interval for
## Alice's resources.  The next document subtracts two days from the
## validity interval for Alice's resources.  The final document sets the
## validity interval for Alice's resources to ten days.
## 
## Operators in subsequent (update) documents:
## 
##   add_as, add_v4, add_v6:    These add ASN, IPv4, or IPv6
##                              resources, respectively.
## 
##   sub_as, sub_v4, sub_v6:    These subtract resources.
## 
##   valid_until:               Set an absolute expiration date.
## 
##   valid_for:                 Set a relative expiration date.
## 
##   valid_add, valid_sub:      Add to or subtract from validity interval.
## 
##   sleep [interval]:          Sleep for specified interval, or until
##                              testbed receives a SIGALRM signal.
## 
## Absolute timestamps should be in the form shown (UTC timestamp format
## as used in XML).
## 
## Intervals (valid_add, valid_sub, valid_for, sleep) are either
## integers, in which case they're interpreted as seconds, or are a
## string of the form "wD xH yM zS" where w, x, y, and z are integers and
## D, H, M, and S indicate days, hours, minutes, and seconds.  In the
## latter case all of the fields are optional, but at least one must be
## specified.  For example, "3D4H" means "three days plus four hours".
## 
## 
## @section testpoke testpoke.py
## 
## This is a command-line client for the up-down protocol.  Unlike all of
## the above programs, testpoke does not accept a %config file in
## OpenSSL-compatable format at all.  Instead, it is configured
## exclusively by a YAML script.  testpoke's design was constrained by a
## desire to have it be compatable with APNIC's rpki_poke.pl tool, so
## that the two tools could use a common configuration language to
## simplify scripted testing.  There are minor variations due to slightly
## different feature sets, but YAML files intended for one program will
## usually work with the other.
## 
## README for APNIC's tool describing the input language can be found at
## http://mirin.apnic.net/svn/rpki_engine/branches/gary-poker/client/poke/README
## 
## testpoke.py takes a simplified command line and uses only one YAML
## input file.
## 
## @verbatim
## Usage: python testpoke.py [ { -y | --yaml }    configfile ]
##                           [ { -r | --request } requestname ]
##                           [ { -h | --help } ]
## @endverbatim
## 
## Default configuration file is testpoke.yaml, override with --yaml
## option.
## 
## The --request option specifies the specific command within the YAML
## file to execute.   
## 
## Sample configuration file:
## 
## @verbatim
##     ---
##     # $Id$
## 
##     version: 1
##     posturl: https://localhost:4433/up-down/1
##     recipient-id: wombat
##     sender-id: "1"
## 
##     cms-cert-file: biz-certs/Frank-EE.cer
##     cms-key-file: biz-certs/Frank-EE.key
##     cms-ca-cert-file: biz-certs/Bob-Root.cer
##     cms-cert-chain-file: [ biz-certs/Frank-CA.cer ]
## 
##     ssl-cert-file: biz-certs/Frank-EE.cer
##     ssl-key-file: biz-certs/Frank-EE.key
##     ssl-ca-cert-file: biz-certs/Bob-Root.cer
## 
##     requests:
##       list:
##      type: list
##       issue:
##      type: issue
##      class: 1
##      sia: [ "rsync://bandicoot.invalid/some/where/" ]
##       revoke:
##      type: revoke
##      class: 1
##      ski: "CB5K6APY-4KcGAW9jaK_cVPXKX0"
## @endverbatim
## 
## testpoke adds one extension to the language described in APNIC's
## README: the cms-cert-chain-* and ssl-cert-chain-* options, which allow
## one to specify a chain of intermediate certificates to be presented in
## the CMS or TLS protocol.  APNIC's initial implementation required
## direct knowledge of the issuing certificate (ie, it supported a
## maximum chain length of one); subsequent APNIC code changes have
## probably relaxed this restriction, and with luck APNIC has copied
## testpoke's syntax to express chains of intermediate certificates.
