"""
This is a command line configuration and control tool for rpkid et al.

Type "help" on the prompt, or run the program with the --help option for an
overview of the available commands; type "help foo" for (more) detailed help
on the "foo" command.


This program is a rewrite of the old myrpki program, replacing ten
zillion XML and X.509 disk files and subprocess calls to the OpenSSL
command line tool with SQL data and direct calls to the rpki.POW
library.  This version abandons all pretense that this program might
somehow work without rpki.POW, lxml, and Django installed, but since
those packages are required for rpkid anyway, this seems like a small
price to pay for major simplification of the code and better
integration with the Django-based GUI interface.

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
"""

# NB: As of this writing, I'm trying really hard to avoid having this
# program depend on a Django settings.py file.  This may prove to be a
# waste of time in the long run, but for for now, this means that one
# has to be careful about exactly how and when one imports Django
# modules, or anything that imports Django modules.  Bottom line is
# that we don't import such modules until we need them.

import csv
import re
import os
import getopt
import sys
import base64
import time
import glob
import copy
import warnings
import rpki.config
import rpki.cli
import rpki.sundial
import rpki.log
import rpki.oids
import rpki.http
import rpki.resource_set
import rpki.relaxng
import rpki.exceptions
import rpki.left_right
import rpki.x509
import rpki.async

class BadCommandSyntax(Exception):      "Bad command line syntax."
class BadPrefixSyntax(Exception):       "Bad prefix syntax."
class CouldntTalkToDaemon(Exception):   "Couldn't talk to daemon."
class BadXMLMessage(Exception):         "Bad XML message."
class PastExpiration(Exception):        "Expiration date has already passed."
class CantRunRootd(Exception):          "Can't run rootd."

class main(rpki.cli.Cmd):

  prompt = "rpkic> "

  completedefault = rpki.cli.Cmd.filename_complete

  def __init__(self):
    os.environ["TZ"] = "UTC"
    time.tzset()

    rpki.log.use_syslog = False

    cfg_file = None
    handle = None

    opts, argv = getopt.getopt(sys.argv[1:], "c:hi:?", ["config=", "help", "identity="])
    for o, a in opts:
      if o in ("-c", "--config"):
        cfg_file = a
      elif o in ("-h", "--help", "-?"):
        argv = ["help"]
      elif o in ("-i", "--identity"):
        handle = a

    if not argv or argv[0] != "help":
      rpki.log.init("rpkic")
      self.read_config(cfg_file, handle)

    rpki.cli.Cmd.__init__(self, argv)

  def read_config(self, cfg_file, handle):
    global rpki

    cfg = rpki.config.parser(cfg_file, "myrpki")
    cfg.set_global_flags()

    from django.conf import settings

    settings.configure(
      DATABASES = { "default" : {
        "ENGINE"   : "django.db.backends.mysql",
        "NAME"     : cfg.get("sql-database", section = "irdbd"),
        "USER"     : cfg.get("sql-username", section = "irdbd"),
        "PASSWORD" : cfg.get("sql-password", section = "irdbd"),
        "HOST"     : "",
        "PORT"     : "",
        "OPTIONS"  : { "init_command": "SET storage_engine=INNODB" }}},
      INSTALLED_APPS = ("rpki.irdb",),
    )

    import rpki.irdb

    import django.core.management
    django.core.management.call_command("syncdb", verbosity = 0, load_initial_data = False)

    self.zoo = rpki.irdb.Zookeeper(cfg = cfg, handle = handle, logstream = sys.stdout)

  def help_overview(self):
    """
    Show program __doc__ string.  Perhaps there's some clever way to
    do this using the textwrap module, but for now something simple
    and crude will suffice.
    """

    for line in __doc__.splitlines(True):
      self.stdout.write(" " * 4 + line)
    self.stdout.write("\n")

  def irdb_handle_complete(self, klass, text, line, begidx, endidx):
    return [obj.handle for obj in klass.objects.all() if obj.handle and obj.handle.startswith(text)]

  def do_select_identity(self, arg):
    """
    Select an identity handle for use with later commands.
    """

    argv = arg.split()
    if len(argv) != 1:
      raise BadCommandSyntax("This command expexcts one argument, not %r" % arg)
    self.zoo.reset_identity(argv[0])

  def complete_select_identity(self, *args):
    return self.irdb_handle_complete(rpki.irdb.ResourceHolderCA, *args)


  def do_initialize(self, arg):
    """
    Initialize an RPKI installation.  This command reads the
    configuration file, creates the BPKI and EntityDB directories,
    generates the initial BPKI certificates, and creates an XML file
    describing the resource-holding aspect of this RPKI installation.
    """

    if arg:
      raise BadCommandSyntax, "This command takes no arguments"

    r = self.zoo.initialize()
    r.save("%s.identity.xml" % self.zoo.handle,
           None if self.zoo.run_pubd else sys.stdout)

    if self.zoo.run_rootd and self.zoo.handle == self.zoo.cfg.get("handle"):
      r = self.zoo.configure_rootd()
      if r is not None:
        r.save("%s.%s.repository-request.xml" % (self.zoo.handle, self.zoo.handle), sys.stdout)

    self.zoo.write_bpki_files()


  def do_update_bpki(self, arg):
    """
    Update BPKI certificates.  Assumes an existing RPKI installation.

    Basic plan here is to reissue all BPKI certificates we can, right
    now.  In the long run we might want to be more clever about only
    touching ones that need maintenance, but this will do for a start.

    We also reissue CRLs for all CAs.

    Most likely this should be run under cron.
    """

    self.zoo.update_bpki()


  def do_configure_child(self, arg):
    """
    Configure a new child of this RPKI entity, given the child's XML
    identity file as an input.  This command extracts the child's data
    from the XML, cross-certifies the child's resource-holding BPKI
    certificate, and generates an XML file describing the relationship
    between the child and this parent, including this parent's BPKI
    data and up-down protocol service URI.
    """

    child_handle = None

    opts, argv = getopt.getopt(arg.split(), "", ["child_handle="])
    for o, a in opts:
      if o == "--child_handle":
        child_handle = a
    
    if len(argv) != 1:
      raise BadCommandSyntax, "Need to specify filename for child.xml"

    r, child_handle = self.zoo.configure_child(argv[0], child_handle)
    r.save("%s.%s.parent-response.xml" % (self.zoo.handle, child_handle), sys.stdout)


  def do_delete_child(self, arg):
    """
    Delete a child of this RPKI entity.
    """

    try:
      self.zoo.delete_child(arg)
    except rpki.irdb.Child.DoesNotExist:
      print "No such child \"%s\"" % arg

  def complete_delete_child(self, *args):
    return self.irdb_handle_complete(rpki.irdb.Child, *args)


  def do_configure_parent(self, arg):
    """
    Configure a new parent of this RPKI entity, given the output of
    the parent's configure_child command as input.  This command reads
    the parent's response XML, extracts the parent's BPKI and service
    URI information, cross-certifies the parent's BPKI data into this
    entity's BPKI, and checks for offers or referrals of publication
    service.  If a publication offer or referral is present, we
    generate a request-for-service message to that repository, in case
    the user wants to avail herself of the referral or offer.
    """

    parent_handle = None

    opts, argv = getopt.getopt(arg.split(), "", ["parent_handle="])
    for o, a in opts:
      if o == "--parent_handle":
        parent_handle = a

    if len(argv) != 1:
      raise BadCommandSyntax, "Need to specify filename for parent.xml on command line"

    r, parent_handle = self.zoo.configure_parent(argv[0], parent_handle)
    r.save("%s.%s.repository-request.xml" % (self.zoo.handle, parent_handle), sys.stdout)


  def do_delete_parent(self, arg):
    """
    Delete a parent of this RPKI entity.
    """

    try:
      self.zoo.delete_parent(arg)
    except rpki.irdb.Parent.DoesNotExist:
      print "No such parent \"%s\"" % arg

  def complete_delete_parent(self, *args):
    return self.irdb_handle_complete(rpki.irdb.Parent, *args)


  def do_configure_publication_client(self, arg):
    """
    Configure publication server to know about a new client, given the
    client's request-for-service message as input.  This command reads
    the client's request for service, cross-certifies the client's
    BPKI data, and generates a response message containing the
    repository's BPKI data and service URI.
    """

    sia_base = None

    opts, argv = getopt.getopt(arg.split(), "", ["sia_base="])
    for o, a in opts:
      if o == "--sia_base":
        sia_base = a
    
    if len(argv) != 1:
      raise BadCommandSyntax, "Need to specify filename for client.xml"

    r, client_handle = self.zoo.configure_publication_client(argv[0], sia_base)
    r.save("%s.repository-response.xml" % client_handle.replace("/", "."), sys.stdout)


  def do_delete_publication_client(self, arg):
    """
    Delete a publication client of this RPKI entity.
    """

    try:
      self.zoo.delete_publication_client(arg).delete()
    except rpki.irdb.Client.DoesNotExist:
      print "No such client \"%s\"" % arg

  def complete_delete_publication_client(self, *args):
    return self.irdb_handle_complete(rpki.irdb.Client, *args)


  def do_configure_repository(self, arg):
    """
    Configure a publication repository for this RPKI entity, given the
    repository's response to our request-for-service message as input.
    This command reads the repository's response, extracts and
    cross-certifies the BPKI data and service URI, and links the
    repository data with the corresponding parent data in our local
    database.
    """

    parent_handle = None

    opts, argv = getopt.getopt(arg.split(), "", ["parent_handle="])
    for o, a in opts:
      if o == "--parent_handle":
        parent_handle = a

    if len(argv) != 1:
      raise BadCommandSyntax, "Need to specify filename for repository.xml on command line"

    self.zoo.configure_repository(argv[0], parent_handle)

  def do_delete_repository(self, arg):
    """
    Delete a repository of this RPKI entity.

    This should check that the XML file it's deleting really is a
    repository, but doesn't, yet.
    """

    try:
      self.zoo.delete_repository(arg)
    except rpki.irdb.Repository.DoesNotExist:
      print "No such repository \"%s\"" % arg

  def complete_delete_repository(self, *args):
    return self.irdb_handle_complete(rpki.irdb.Repository, *args)


  def do_delete_self(self, arg):
    """
    Delete the current RPKI entity (<self/> object).
    """

    self.zoo.delete_self()


  def do_renew_child(self, arg):
    """
    Update validity period for one child entity.
    """

    valid_until = None

    opts, argv = getopt.getopt(arg.split(), "", ["valid_until"])
    for o, a in opts:
      if o == "--valid_until":
        valid_until = a

    if len(argv) != 1:
      raise BadCommandSyntax, "Need to specify child handle"

    self.zoo.renew_children(argv[0], valid_until)

  def complete_renew_child(self, *args):
    return self.irdb_handle_complete(rpki.irdb.Child, *args)


  def do_renew_all_children(self, arg):
    """
    Update validity period for all child entities.
    """

    valid_until = None

    opts, argv = getopt.getopt(arg.split(), "", ["valid_until"])
    for o, a in opts:
      if o == "--valid_until":
        valid_until = a

    if len(argv) != 0:
      raise BadCommandSyntax, "Unexpected arguments"

    self.zoo.renew_children(None, valid_until)


  def do_load_prefixes(self, arg):
    """
    Load prefixes into IRDB from CSV file.
    """

    argv = arg.split()

    if len(argv) != 1:
      raise BadCommandSyntax("Need to specify prefixes.csv filename")

    self.zoo.load_prefixes(argv[0])


  def do_show_child_resources(self, arg):
    """
    Show resources assigned to children.
    """

    if arg.strip():
      raise BadCommandSyntax("This command takes no arguments")

    for child in self.zoo.resource_ca.children.all():
      resources = child.resource_bag

      print "Child:", child.handle
      if resources.asn:
        print "  ASN:", resources.asn
      if resources.v4:
        print " IPv4:", resources.v4
      if resources.v6:
        print " IPv6:", resources.v6


  def do_load_asns(self, arg):
    """
    Load ASNs into IRDB from CSV file.
    """

    argv = arg.split()

    if len(argv) != 1:
      raise BadCommandSyntax("Need to specify asns.csv filename")

    self.zoo.load_asns(argv[0])


  def do_load_roa_requests(self, arg):
    """
    Load ROA requests into IRDB from CSV file.
    """

    argv = arg.split()

    if len(argv) != 1:
      raise BadCommandSyntax("Need to specify roa.csv filename")

    self.zoo.load_roa_requests(argv[0])


  def do_synchronize(self, arg):
    """
    Whack daemons to match IRDB.

    This command may be replaced by implicit synchronization embedded
    in of other commands, haven't decided yet.
    """

    if arg:
      raise BadCommandSyntax("Unexpected argument(s): %r" % arg)

    self.zoo.synchronize()
