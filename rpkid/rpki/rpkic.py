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

import os
import getopt
import sys
import time
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

    self.cfg_file = None
    self.handle = None
    profile = None

    opts, self.argv = getopt.getopt(sys.argv[1:], "c:hi:?",
                                    ["config=", "help", "identity=", "profile="])
    for o, a in opts:
      if o in ("-c", "--config"):
        self.cfg_file = a
      elif o in ("-h", "--help", "-?"):
        self.argv = ["help"]
      elif o in ("-i", "--identity"):
        self.handle = a
      elif o == "--profile":
        profile = a

    if self.argv and self.argv[0] == "help":
      rpki.cli.Cmd.__init__(self, self.argv)
    elif profile:
      import cProfile
      prof = cProfile.Profile()
      try:
        prof.runcall(self.main)
      finally:
        prof.dump_stats(profile)
        print "Dumped profile data to %s" % profile
    else:
      self.main()

  def main(self):
    rpki.log.init("rpkic", use_syslog = False)
    self.read_config()
    rpki.cli.Cmd.__init__(self, self.argv)

  def read_config(self):
    global rpki                         # pylint: disable=W0602

    cfg = rpki.config.parser(self.cfg_file, "myrpki")
    cfg.set_global_flags()
    self.histfile = cfg.get("history_file", os.path.expanduser("~/.rpkic_history"))
    self.autosync = cfg.getboolean("autosync", True, section = "rpkic")

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

    import rpki.irdb                    # pylint: disable=W0621

    try:
      rpki.irdb.models.ca_certificate_lifetime = rpki.sundial.timedelta.parse(
        cfg.get("bpki_ca_certificate_lifetime", section = "rpkic"))
    except rpki.config.ConfigParser.Error:
      pass

    try:
      rpki.irdb.models.ee_certificate_lifetime = rpki.sundial.timedelta.parse(
        cfg.get("bpki_ee_certificate_lifetime", section = "rpkic"))
    except rpki.config.ConfigParser.Error:
      pass

    try:
      rpki.irdb.models.crl_interval = rpki.sundial.timedelta.parse(
        cfg.get("bpki_crl_interval", section = "rpkic"))
    except rpki.config.ConfigParser.Error:
      pass

    import django.core.management
    django.core.management.call_command("syncdb", verbosity = 0, load_initial_data = False)

    self.zoo = rpki.irdb.Zookeeper(cfg = cfg, handle = self.handle, logstream = sys.stdout)

  def help_overview(self):
    """
    Show program __doc__ string.  Perhaps there's some clever way to
    do this using the textwrap module, but for now something simple
    and crude will suffice.
    """

    for line in __doc__.splitlines(True):
      self.stdout.write(" " * 4 + line)
    self.stdout.write("\n")

  def irdb_handle_complete(self, manager, text, line, begidx, endidx):
    return [obj.handle for obj in manager.all() if obj.handle and obj.handle.startswith(text)]


  def do_select_identity(self, arg):
    """
    Select an identity handle for use with later commands.
    """

    argv = arg.split()
    if len(argv) != 1:
      raise BadCommandSyntax("This command expexcts one argument, not %r" % arg)
    self.zoo.reset_identity(argv[0])

  def complete_select_identity(self, *args):
    return self.irdb_handle_complete(rpki.irdb.ResourceHolderCA.objects, *args)


  def do_initialize(self, arg):
    """
    Initialize an RPKI installation.  This command reads the
    configuration file, creates the BPKI and EntityDB directories,
    generates the initial BPKI certificates, and creates an XML file
    describing the resource-holding aspect of this RPKI installation.
    """

    if arg:
      raise BadCommandSyntax, "This command takes no arguments"

    rootd_case = self.zoo.run_rootd and self.zoo.handle == self.zoo.cfg.get("handle")

    r = self.zoo.initialize()
    r.save("%s.identity.xml" % self.zoo.handle,
           None if rootd_case else sys.stdout)

    if rootd_case:
      r = self.zoo.configure_rootd()
      if r is not None:
        r.save("%s.%s.repository-request.xml" % (self.zoo.handle, self.zoo.handle), sys.stdout)

    self.zoo.write_bpki_files()


  # These aren't quite ready for prime time yet.  See https://trac.rpki.net/ticket/466

  if False:

    def do_create_identity(self, arg):
      """
      Create a new resource-holding entity.  Argument is the handle of
      the entity to create.  Returns XML file describing the new
      resource holder.

      This command is idempotent: calling it for a resource holder which
      already exists returns the existing identity.
      """

      argv = arg.split()
      if len(argv) != 1:
        raise BadCommandSyntax("This command expexcts one argument, not %r" % arg)

      self.zoo.reset_identity(argv[0])

      rootd_case = self.zoo.run_rootd and self.zoo.handle == self.zoo.cfg.get("handle")

      r = self.zoo.initialize_resource_bpki()
      r.save("%s.identity.xml" % self.zoo.handle,
             None if rootd_case else sys.stdout)

      if rootd_case:
        r = self.zoo.configure_rootd()
        if r is not None:
          r.save("%s.%s.repository-request.xml" % (self.zoo.handle, self.zoo.handle), sys.stdout)

    def do_initialize_server_bpki(self, arg):
      """
      Initialize server BPKI portion of an RPKI installation.  Reads
      server configuration from configuration file and creates the
      server BPKI objects needed to start daemons.
      """

      if arg:
        raise BadCommandSyntax, "This command takes no arguments"
      self.zoo.initialize_server_bpki()
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

    if arg:
      raise BadCommandSyntax, "This command takes no arguments"
    self.zoo.update_bpki()
    self.zoo.write_bpki_files()


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
    self.zoo.synchronize_ca()


  def do_delete_child(self, arg):
    """
    Delete a child of this RPKI entity.
    """

    try:
      self.zoo.delete_child(arg)
      self.zoo.synchronize_ca()
    except rpki.irdb.ResourceHolderCA.DoesNotExist:
      print "No such resource holder \"%s\"" % self.zoo.handle
    except rpki.irdb.Child.DoesNotExist:
      print "No such child \"%s\"" % arg

  def complete_delete_child(self, *args):
    return self.irdb_handle_complete(self.zoo.resource_ca.children, *args)


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

    We do NOT attempt automatic synchronization with rpkid at the
    completion of this command, because synchronization at this point
    will usually fail due to the repository not being set up yet.  If
    you know what you are doing and for some reason really want to
    synchronize here, run the synchronize command yourself.
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
      self.zoo.synchronize_ca()
    except rpki.irdb.ResourceHolderCA.DoesNotExist:
      print "No such resource holder \"%s\"" % self.zoo.handle
    except rpki.irdb.Parent.DoesNotExist:
      print "No such parent \"%s\"" % arg

  def complete_delete_parent(self, *args):
    return self.irdb_handle_complete(self.zoo.resource_ca.parents, *args)


  def do_delete_rootd(self, arg):
    """
    Delete rootd associated with this RPKI entity.
    """

    try:
      self.zoo.delete_rootd()
      self.zoo.synchronize_ca()
    except rpki.irdb.ResourceHolderCA.DoesNotExist:
      print "No such resource holder \"%s\"" % self.zoo.handle
    except rpki.irdb.Rootd.DoesNotExist:
      print "No associated rootd"


  def do_configure_publication_client(self, arg):
    """
    Configure publication server to know about a new client, given the
    client's request-for-service message as input.  This command reads
    the client's request for service, cross-certifies the client's
    BPKI data, and generates a response message containing the
    repository's BPKI data and service URI.
    """

    sia_base = None
    flat = False

    opts, argv = getopt.getopt(arg.split(), "", ["flat", "sia_base="])
    for o, a in opts:
      if o == "--flat":
        flat = True
      elif o == "--sia_base":
        sia_base = a
    
    if len(argv) != 1:
      raise BadCommandSyntax, "Need to specify filename for client.xml"

    r, client_handle = self.zoo.configure_publication_client(argv[0], sia_base, flat)
    r.save("%s.repository-response.xml" % client_handle.replace("/", "."), sys.stdout)

    try:
      self.zoo.synchronize_pubd()
    except rpki.irdb.Repository.DoesNotExist:
      pass


  def do_delete_publication_client(self, arg):
    """
    Delete a publication client of this RPKI entity.
    """

    try:
      self.zoo.delete_publication_client(arg)
      self.zoo.synchronize_pubd()
    except rpki.irdb.ResourceHolderCA.DoesNotExist:
      print "No such resource holder \"%s\"" % self.zoo.handle
    except rpki.irdb.Client.DoesNotExist:
      print "No such client \"%s\"" % arg

  def complete_delete_publication_client(self, *args):
    return self.irdb_handle_complete(self.zoo.server_ca.clients, *args)


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
    self.zoo.synchronize_ca()

  def do_delete_repository(self, arg):
    """
    Delete a repository of this RPKI entity.

    This should check that the XML file it's deleting really is a
    repository, but doesn't, yet.
    """

    try:
      self.zoo.delete_repository(arg)
      self.zoo.synchronize_ca()
    except rpki.irdb.ResourceHolderCA.DoesNotExist:
      print "No such resource holder \"%s\"" % self.zoo.handle
    except rpki.irdb.Repository.DoesNotExist:
      print "No such repository \"%s\"" % arg

  def complete_delete_repository(self, *args):
    return self.irdb_handle_complete(self.zoo.resource_ca.repositories, *args)


  def do_delete_self(self, arg):
    """
    Delete the current RPKI entity (<self/> object).
    """

    try:
      self.zoo.delete_self()
      self.zoo.synchronize_deleted_ca()
    except rpki.irdb.ResourceHolderCA.DoesNotExist:
      print "No such resource holder \"%s\"" % self.zoo.handle


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
    self.zoo.synchronize_ca()
    if self.autosync:
      self.zoo.run_rpkid_now()

  def complete_renew_child(self, *args):
    return self.irdb_handle_complete(self.zoo.resource_ca.children, *args)


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
    self.zoo.synchronize_ca()
    if self.autosync:
      self.zoo.run_rpkid_now()


  def do_load_prefixes(self, arg):
    """
    Load prefixes into IRDB from CSV file.
    """

    argv = arg.split()

    if len(argv) != 1:
      raise BadCommandSyntax("Need to specify prefixes.csv filename")

    self.zoo.load_prefixes(argv[0], True)
    if self.autosync:
      self.zoo.run_rpkid_now()


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

    self.zoo.load_asns(argv[0], True)
    if self.autosync:
      self.zoo.run_rpkid_now()


  def do_load_roa_requests(self, arg):
    """
    Load ROA requests into IRDB from CSV file.
    """

    argv = arg.split()

    if len(argv) != 1:
      raise BadCommandSyntax("Need to specify roa.csv filename")

    self.zoo.load_roa_requests(argv[0])
    if self.autosync:
      self.zoo.run_rpkid_now()


  def do_synchronize(self, arg):
    """
    Whack daemons to match IRDB.

    This command may be replaced by implicit synchronization embedded
    in of other commands, haven't decided yet.
    """

    if arg:
      raise BadCommandSyntax("Unexpected argument(s): %r" % arg)

    self.zoo.synchronize()


  def do_force_publication(self, arg):
    """
    Whack rpkid to force (re)publication of everything.

    This is not usually necessary, as rpkid automatically publishes
    changes it makes, but this command can be useful occasionally when
    a fault or configuration error has left rpkid holding data which
    it has not been able to publish.
    """

    if arg:
      raise BadCommandSyntax("Unexpected argument(s): %r" % arg)

    self.zoo.publish_world_now()


  def do_force_reissue(self, arg):
    """
    Whack rpkid to force reissuance of everything.

    This is not usually necessary, as rpkid reissues automatically
    objects automatically as needed, but this command can be useful
    occasionally when a fault or configuration error has prevented
    rpkid from reissuing when it should have.
    """

    if arg:
      raise BadCommandSyntax("Unexpected argument(s): %r" % arg)

    self.zoo.reissue()


  def do_up_down_rekey(self, arg):
    """
    Initiate a "rekey" operation: tell rpkid to generate new keys for
    each certificate issued to it via the up-down protocol.

    This is the first stage of a key rollover operation.  You will
    need to follow it up later with a "revoke" operation to clean up
    the old keys
    """

    if arg:
      raise BadCommandSyntax("Unexpected argument(s): %r" % arg)

    self.zoo.rekey()


  def do_up_down_revoke(self, arg):
    """
    Initiate a "revoke" operation: tell rpkid to clean up old keys
    formerly used by certificates issued to it via the up-down
    protocol.

    This is the cleanup stage of a key rollover operation.
    """

    if arg:
      raise BadCommandSyntax("Unexpected argument(s): %r" % arg)

    self.zoo.revoke()


  def do_revoke_forgotten(self, arg):
    """
    Initiate a "revoke_forgotten" operation: tell rpkid to ask its
    parent to revoke certificates for which rpkid does not know the
    private keys.  This should never happen during ordinary operation,
    but can happen if rpkid is misconfigured or its database has been
    damaged, so we need a way to resynchronize rpkid with its parent
    in such cases.  We could do this automatically, but as we don't
    know the precise cause of the failure we don't know if it's
    recoverable locally (eg, from an SQL backup), so we require a
    manual trigger before discarding possibly-useful certificates.
    """

    if arg:
      raise BadCommandSyntax("Unexpected argument(s): %r" % arg)

    self.zoo.revoke_forgotten()


  def do_clear_all_sql_cms_replay_protection(self, arg):
    """
    Tell rpkid and pubd to clear replay protection for all SQL-based
    entities.  This is a fairly blunt instrument, but as we don't
    expect this to be necessary except in the case of gross
    misconfiguration, it should suffice
    """

    if arg:
      raise BadCommandSyntax("Unexpected argument(s): %r" % arg)

    self.zoo.clear_all_sql_cms_replay_protection()
