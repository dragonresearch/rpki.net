# $Id$
#
# Copyright (C) 2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2009--2013  Internet Systems Consortium ("ISC")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL AND ISC DISCLAIM ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL DRL OR
# ISC BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
# DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA
# OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
# TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""
Command line configuration and control tool for rpkid et al.

Type "help" at the inernal prompt, or run the program with the --help option for
an overview of the available commands; type "help foo" for (more) detailed help
on the "foo" command.
"""

# NB: As of this writing, I'm trying really hard to avoid having this
# program depend on a Django settings.py file.  This may prove to be a
# waste of time in the long run, but for for now, this means that one
# has to be careful about exactly how and when one imports Django
# modules, or anything that imports Django modules.  Bottom line is
# that we don't import such modules until we need them.

import os
import argparse
import sys
import time
import rpki.config
import rpki.sundial
import rpki.log
import rpki.http
import rpki.resource_set
import rpki.relaxng
import rpki.exceptions
import rpki.left_right
import rpki.x509
import rpki.async
import rpki.version

from lxml.etree import Element, SubElement

from rpki.cli import Cmd, parsecmd, cmdarg

class BadPrefixSyntax(Exception):       "Bad prefix syntax."
class CouldntTalkToDaemon(Exception):   "Couldn't talk to daemon."
class BadXMLMessage(Exception):         "Bad XML message."
class PastExpiration(Exception):        "Expiration date has already passed."
class CantRunRootd(Exception):          "Can't run rootd."

module_doc = __doc__

class main(Cmd):

  prompt = "rpkic> "

  completedefault = Cmd.filename_complete

  # Top-level argparser, for stuff that one might want when starting
  # up the interactive command loop.  Not sure -i belongs here, but
  # it's harmless so leave it here for the moment.

  top_argparser = argparse.ArgumentParser(add_help = False)
  top_argparser.add_argument("-c", "--config",
                             help = "override default location of configuration file")
  top_argparser.add_argument("-i", "--identity", "--handle",
                             help = "set initial entity handdle")
  top_argparser.add_argument("--profile",
                             help = "enable profiling, saving data to PROFILE")

  # Argparser for non-interactive commands (no command loop).

  full_argparser = argparse.ArgumentParser(parents = [top_argparser],
                                           description = module_doc)
  argsubparsers = full_argparser.add_subparsers(title = "Commands", metavar = "")

  def __init__(self):

    Cmd.__init__(self)
    os.environ["TZ"] = "UTC"
    time.tzset()

    # Try parsing just the arguments that make sense if we're
    # going to be running an interactive command loop.  If that
    # parses everything, we're interactive, otherwise, it's either
    # a non-interactive command or a parse error, so we let the full
    # parser sort that out for us.

    args, argv = self.top_argparser.parse_known_args()
    self.interactive = not argv
    if not self.interactive:
      args = self.full_argparser.parse_args()

    self.cfg_file = args.config
    self.handle = args.identity

    if args.profile:
      import cProfile
      prof = cProfile.Profile()
      try:
        prof.runcall(self.main, args)
      finally:
        prof.dump_stats(args.profile)
        print "Dumped profile data to %s" % args.profile
    else:
      self.main(args)

  def main(self, args):
    rpki.log.init("rpkic")
    self.read_config()
    if self.interactive:
      self.cmdloop_with_history()
    else:
      args.func(self, args)

  def read_config(self):
    global rpki                         # pylint: disable=W0602

    try:
      cfg = rpki.config.parser(set_filename = self.cfg_file, section = "myrpki")
      cfg.set_global_flags()
    except IOError, e:
      sys.exit("%s: %s" % (e.strerror, e.filename))

    self.histfile = cfg.get("history_file", os.path.expanduser("~/.rpkic_history"))
    self.autosync = cfg.getboolean("autosync", True, section = "rpkic")

    # This should go away now that we have rpki.django_settings, but
    # let's get a verbose log with it present first to see what
    # changes.

    use_south = True
    setup_db  = False

    if use_south:
      os.environ.update(DJANGO_SETTINGS_MODULE = "rpki.django_settings")

    else:
      import django
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
        MIDDLEWARE_CLASSES = (),          # API change, feh
      )

      if django.VERSION >= (1, 7):        # API change, feh
        from django.apps import apps
        apps.populate(settings.INSTALLED_APPS)

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

    if setup_db:
      import django.core.management
      django.core.management.call_command("syncdb", verbosity = 3, load_initial_data = False)

    if setup_db and use_south:
        django.core.management.call_command("migrate", verbosity = 3)

    self.zoo = rpki.irdb.Zookeeper(cfg = cfg, handle = self.handle, logstream = sys.stdout)


  def do_help(self, arg):
    """
    List available commands with "help" or detailed help with "help cmd".
    """

    argv = arg.split()

    if not argv:
      #return self.full_argparser.print_help()
      return self.print_topics(
        self.doc_header,
        sorted(set(name[3:] for name in self.get_names()
                   if name.startswith("do_")
                   and getattr(self, name).__doc__)),
        15, 80)

    try:
      return getattr(self, "help_" + argv[0])()
    except AttributeError:
      pass

    func = getattr(self, "do_" + argv[0], None)

    try:
      return func.argparser.print_help()
    except AttributeError:
      pass

    try:
      return self.stdout.write(func.__doc__ + "\n")
    except AttributeError:
      pass

    self.stdout.write((self.nohelp + "\n") % arg)


  def irdb_handle_complete(self, manager, text, line, begidx, endidx):
    return [obj.handle for obj in manager.all() if obj.handle and obj.handle.startswith(text)]


  @parsecmd(argsubparsers,
            cmdarg("handle", help = "new handle"))
  def do_select_identity(self, args):
    """
    Select an identity handle for use with later commands.
    """

    self.zoo.reset_identity(args.handle)

  def complete_select_identity(self, *args):
    return self.irdb_handle_complete(rpki.irdb.ResourceHolderCA.objects, *args)


  @parsecmd(argsubparsers)
  def do_initialize(self, args):
    """
    Initialize an RPKI installation.  DEPRECATED.

    This command reads the configuration file, creates the BPKI and
    EntityDB directories, generates the initial BPKI certificates, and
    creates an XML file describing the resource-holding aspect of this
    RPKI installation.
    """

    rootd_case = self.zoo.run_rootd and self.zoo.handle == self.zoo.cfg.get("handle")

    r = self.zoo.initialize()
    r.save("%s.identity.xml" % self.zoo.handle,
           None if rootd_case else sys.stdout)

    if rootd_case:
      r = self.zoo.configure_rootd()
      if r is not None:
        r.save("%s.%s.repository-request.xml" % (self.zoo.handle, self.zoo.handle), sys.stdout)

    self.zoo.write_bpki_files()


  @parsecmd(argsubparsers,
            cmdarg("handle", help = "handle of entity to create"))
  def do_create_identity(self, args):
    """
    Create a new resource-holding entity.

    Returns XML file describing the new resource holder.

    This command is idempotent: calling it for a resource holder which
    already exists returns the existing identity.
    """

    self.zoo.reset_identity(args.handle)

    r = self.zoo.initialize_resource_bpki()
    r.save("%s.identity.xml" % self.zoo.handle, sys.stdout)


  @parsecmd(argsubparsers)
  def do_initialize_server_bpki(self, args):
    """
    Initialize server BPKI portion of an RPKI installation.

    Reads server configuration from configuration file and creates the
    server BPKI objects needed to start daemons.
    """

    self.zoo.initialize_server_bpki()
    self.zoo.write_bpki_files()


  @parsecmd(argsubparsers)
  def do_update_bpki(self, args):
    """
    Update BPKI certificates.  Assumes an existing RPKI installation.

    Basic plan here is to reissue all BPKI certificates we can, right
    now.  In the long run we might want to be more clever about only
    touching ones that need maintenance, but this will do for a start.

    We also reissue CRLs for all CAs.

    Most likely this should be run under cron.
    """

    self.zoo.update_bpki()
    self.zoo.write_bpki_files()
    try:
      self.zoo.synchronize_bpki()
    except Exception, e:
      print "Couldn't push updated BPKI material into daemons: %s" % e


  @parsecmd(argsubparsers,
            cmdarg("--child_handle", help = "override default handle for new child"),
            cmdarg("--valid_until",  help = "override default validity interval"),
            cmdarg("child_xml",      help = "XML file containing child's identity"))
  def do_configure_child(self, args):
    """
    Configure a new child of this RPKI entity.

    This command extracts the child's data from an XML input file,
    cross-certifies the child's resource-holding BPKI certificate, and
    generates an XML output file describing the relationship between
    the child and this parent, including this parent's BPKI data and
    up-down protocol service URI.
    """

    r, child_handle = self.zoo.configure_child(args.child_xml, args.child_handle, args.valid_until)
    r.save("%s.%s.parent-response.xml" % (self.zoo.handle, child_handle), sys.stdout)
    self.zoo.synchronize_ca()


  @parsecmd(argsubparsers,
            cmdarg("child_handle", help = "handle of child to delete"))
  def do_delete_child(self, args):
    """
    Delete a child of this RPKI entity.
    """

    try:
      self.zoo.delete_child(args.child_handle)
      self.zoo.synchronize_ca()
    except rpki.irdb.ResourceHolderCA.DoesNotExist:
      print "No such resource holder \"%s\"" % self.zoo.handle
    except rpki.irdb.Child.DoesNotExist:
      print "No such child \"%s\"" % args.child_handle

  def complete_delete_child(self, *args):
    return self.irdb_handle_complete(self.zoo.resource_ca.children, *args)


  @parsecmd(argsubparsers,
            cmdarg("--parent_handle", help = "override default handle for new parent"),
            cmdarg("parent_xml",      help = "XML file containing parent's response"))
  def do_configure_parent(self, args):
    """
    Configure a new parent of this RPKI entity.

    This command reads the parent's response XML, extracts the
    parent's BPKI and service URI information, cross-certifies the
    parent's BPKI data into this entity's BPKI, and checks for offers
    or referrals of publication service.  If a publication offer or
    referral is present, we generate a request-for-service message to
    that repository, in case the user wants to avail herself of the
    referral or offer.

    We do NOT attempt automatic synchronization with rpkid at the
    completion of this command, because synchronization at this point
    will usually fail due to the repository not being set up yet.  If
    you know what you are doing and for some reason really want to
    synchronize here, run the synchronize command yourself.
    """

    r, parent_handle = self.zoo.configure_parent(args.parent_xml, args.parent_handle)
    r.save("%s.%s.repository-request.xml" % (self.zoo.handle, parent_handle), sys.stdout)


  @parsecmd(argsubparsers,
            cmdarg("parent_handle", help = "handle of parent to delete"))
  def do_delete_parent(self, args):
    """
    Delete a parent of this RPKI entity.
    """

    try:
      self.zoo.delete_parent(args.parent_handle)
      self.zoo.synchronize_ca()
    except rpki.irdb.ResourceHolderCA.DoesNotExist:
      print "No such resource holder \"%s\"" % self.zoo.handle
    except rpki.irdb.Parent.DoesNotExist:
      print "No such parent \"%s\"" % args.parent_handle

  def complete_delete_parent(self, *args):
    return self.irdb_handle_complete(self.zoo.resource_ca.parents, *args)


  @parsecmd(argsubparsers)
  def do_configure_root(self, args):
    """
    Configure the current resource holding identity as a root.

    This configures rpkid to talk to rootd as (one of) its parent(s).
    Returns repository request XML file like configure_parent does.
    """

    r = self.zoo.configure_rootd()
    if r is not None:
      r.save("%s.%s.repository-request.xml" % (self.zoo.handle, self.zoo.handle), sys.stdout)
    self.zoo.write_bpki_files()


  @parsecmd(argsubparsers)
  def do_delete_root(self, args):
    """
    Delete local RPKI root as parent of the current entity.

    This tells the current rpkid identity (<self/>) to stop talking to
    rootd.
    """

    try:
      self.zoo.delete_rootd()
      self.zoo.synchronize_ca()
    except rpki.irdb.ResourceHolderCA.DoesNotExist:
      print "No such resource holder \"%s\"" % self.zoo.handle
    except rpki.irdb.Rootd.DoesNotExist:
      print "No associated rootd"


  @parsecmd(argsubparsers,
            cmdarg("--flat",     help = "use flat publication scheme", action = "store_true"),
            cmdarg("--sia_base", help = "override SIA base value"),
            cmdarg("client_xml", help = "XML file containing client request"))
  def do_configure_publication_client(self, args):
    """
    Configure publication server to know about a new client.

    This command reads the client's request for service,
    cross-certifies the client's BPKI data, and generates a response
    message containing the repository's BPKI data and service URI.
    """

    r, client_handle = self.zoo.configure_publication_client(args.client_xml, args.sia_base, args.flat)
    r.save("%s.repository-response.xml" % client_handle.replace("/", "."), sys.stdout)
    try:
      self.zoo.synchronize_pubd()
    except rpki.irdb.Repository.DoesNotExist:
      pass


  @parsecmd(argsubparsers,
            cmdarg("client_handle", help = "handle of client to delete"))
  def do_delete_publication_client(self, args):
    """
    Delete a publication client of this RPKI entity.
    """

    try:
      self.zoo.delete_publication_client(args.client_handle)
      self.zoo.synchronize_pubd()
    except rpki.irdb.ResourceHolderCA.DoesNotExist:
      print "No such resource holder \"%s\"" % self.zoo.handle
    except rpki.irdb.Client.DoesNotExist:
      print "No such client \"%s\"" % args.client_handle

  def complete_delete_publication_client(self, *args):
    return self.irdb_handle_complete(self.zoo.server_ca.clients, *args)


  @parsecmd(argsubparsers,
            cmdarg("--parent_handle", help = "override default parent handle"),
            cmdarg("repository_xml",  help = "XML file containing repository response"))
  def do_configure_repository(self, args):
    """
    Configure a publication repository for this RPKI entity.

    This command reads the repository's response to this entity's
    request for publication service, extracts and cross-certifies the
    BPKI data and service URI, and links the repository data with the
    corresponding parent data in our local database.
    """

    self.zoo.configure_repository(args.repository_xml, args.parent_handle)
    self.zoo.synchronize_ca()


  @parsecmd(argsubparsers,
            cmdarg("repository_handle", help = "handle of repository to delete"))
  def do_delete_repository(self, args):
    """
    Delete a repository of this RPKI entity.
    """

    try:
      self.zoo.delete_repository(args.repository_handle)
      self.zoo.synchronize_ca()
    except rpki.irdb.ResourceHolderCA.DoesNotExist:
      print "No such resource holder \"%s\"" % self.zoo.handle
    except rpki.irdb.Repository.DoesNotExist:
      print "No such repository \"%s\"" % args.repository_handle

  def complete_delete_repository(self, *args):
    return self.irdb_handle_complete(self.zoo.resource_ca.repositories, *args)


  @parsecmd(argsubparsers)
  def do_delete_identity(self, args):
    """
    Delete the current RPKI identity (rpkid <self/> object).
    """

    try:
      self.zoo.delete_self()
      self.zoo.synchronize_deleted_ca()
    except rpki.irdb.ResourceHolderCA.DoesNotExist:
      print "No such resource holder \"%s\"" % self.zoo.handle


  @parsecmd(argsubparsers,
            cmdarg("--valid_until", help = "override default new validity interval"),
            cmdarg("child_handle",  help = "handle of child to renew"))
  def do_renew_child(self, args):
    """
    Update validity period for one child entity.
    """

    self.zoo.renew_children(args.child_handle, args.valid_until)
    self.zoo.synchronize_ca()
    if self.autosync:
      self.zoo.run_rpkid_now()

  def complete_renew_child(self, *args):
    return self.irdb_handle_complete(self.zoo.resource_ca.children, *args)


  @parsecmd(argsubparsers,
            cmdarg("--valid_until", help = "override default new validity interval"))
  def do_renew_all_children(self, args):
    """
    Update validity period for all child entities.
    """

    self.zoo.renew_children(None, args.valid_until)
    self.zoo.synchronize_ca()
    if self.autosync:
      self.zoo.run_rpkid_now()


  @parsecmd(argsubparsers,
            cmdarg("prefixes_csv", help = "CSV file listing prefixes"))
  def do_load_prefixes(self, args):
    """
    Load prefixes into IRDB from CSV file.
    """

    self.zoo.load_prefixes(args.prefixes_csv, True)
    if self.autosync:
      self.zoo.run_rpkid_now()


  @parsecmd(argsubparsers)
  def do_show_child_resources(self, args):
    """
    Show resources assigned to children.
    """

    for child in self.zoo.resource_ca.children.all():
      resources = child.resource_bag
      print "Child:", child.handle
      if resources.asn:
        print "  ASN:", resources.asn
      if resources.v4:
        print " IPv4:", resources.v4
      if resources.v6:
        print " IPv6:", resources.v6


  @parsecmd(argsubparsers)
  def do_show_roa_requests(self, args):
    """
    Show ROA requests.
    """

    for roa_request in self.zoo.resource_ca.roa_requests.all():
      prefixes = roa_request.roa_prefix_bag
      print "ASN:  ", roa_request.asn
      if prefixes.v4:
        print " IPv4:", prefixes.v4
      if prefixes.v6:
        print " IPv6:", prefixes.v6


  @parsecmd(argsubparsers)
  def do_show_ghostbuster_requests(self, args):
    """
    Show Ghostbuster requests.
    """

    for ghostbuster_request in self.zoo.resource_ca.ghostbuster_requests.all():
      print "Parent:", ghostbuster_request.parent or "*"
      print ghostbuster_request.vcard


  @parsecmd(argsubparsers)
  def do_show_received_resources(self, args):
    """
    Show resources received by this entity from its parent(s).
    """

    for pdu in self.zoo.call_rpkid(
      rpki.left_right.list_received_resources_elt.make_pdu(self_handle = self.zoo.handle)):

      print "Parent:     ", pdu.parent_handle
      print "  notBefore:", pdu.notBefore
      print "  notAfter: ", pdu.notAfter
      print "  URI:      ", pdu.uri
      print "  SIA URI:  ", pdu.sia_uri
      print "  AIA URI:  ", pdu.aia_uri
      print "  ASN:      ", pdu.asn
      print "  IPv4:     ", pdu.ipv4
      print "  IPv6:     ", pdu.ipv6


  @parsecmd(argsubparsers)
  def do_show_published_objects(self, args):
    """
    Show published objects.
    """

    q_msg = self.zoo._compose_left_right_query()
    SubElement(q_msg, rpki.left_right.tag_list_published_objects, self_handle = self.zoo.handle)

    for r_pdu in self.zoo.call_rpkid(q_msg):
      uri = r_pdu.get("uri")
      track = rpki.x509.uri_dispatch(uri)(Base64 = r_pdu.text).tracking_data(uri)
      child_handle = r_pdu.get("child_handle")

      if child_handle is None:
        print track
      else:
        print track, child_handle


  @parsecmd(argsubparsers)
  def do_show_bpki(self, args):
    """
    Show this entity's BPKI objects.
    """

    print "Self:       ", self.zoo.resource_ca.handle
    print "  notBefore:", self.zoo.resource_ca.certificate.getNotBefore()
    print "  notAfter: ", self.zoo.resource_ca.certificate.getNotAfter()
    print "  Subject:  ", self.zoo.resource_ca.certificate.getSubject()
    print "  SKI:      ", self.zoo.resource_ca.certificate.hSKI()
    for bsc in self.zoo.resource_ca.bscs.all():
      print "BSC:        ", bsc.handle
      print "  notBefore:", bsc.certificate.getNotBefore()
      print "  notAfter: ", bsc.certificate.getNotAfter()
      print "  Subject:  ", bsc.certificate.getSubject()
      print "  SKI:      ", bsc.certificate.hSKI()
    for parent in self.zoo.resource_ca.parents.all():
      print "Parent:     ", parent.handle
      print "  notBefore:", parent.certificate.getNotBefore()
      print "  notAfter: ", parent.certificate.getNotAfter()
      print "  Subject:  ", parent.certificate.getSubject()
      print "  SKI:      ", parent.certificate.hSKI()
      print "  URL:      ", parent.service_uri
    for child in self.zoo.resource_ca.children.all():
      print "Child:      ", child.handle
      print "  notBefore:", child.certificate.getNotBefore()
      print "  notAfter: ", child.certificate.getNotAfter()
      print "  Subject:  ", child.certificate.getSubject()
      print "  SKI:      ", child.certificate.hSKI()
    for repository in self.zoo.resource_ca.repositories.all():
      print "Repository: ", repository.handle
      print "  notBefore:", repository.certificate.getNotBefore()
      print "  notAfter: ", repository.certificate.getNotAfter()
      print "  Subject:  ", repository.certificate.getSubject()
      print "  SKI:      ", repository.certificate.hSKI()
      print "  URL:      ", repository.service_uri


  @parsecmd(argsubparsers,
            cmdarg("asns_csv", help = "CSV file listing ASNs"))
  def do_load_asns(self, args):
    """
    Load ASNs into IRDB from CSV file.
    """

    self.zoo.load_asns(args.asns_csv, True)
    if self.autosync:
      self.zoo.run_rpkid_now()


  @parsecmd(argsubparsers,
            cmdarg("roa_requests_csv", help = "CSV file listing ROA requests"))
  def do_load_roa_requests(self, args):
    """
    Load ROA requests into IRDB from CSV file.
    """

    self.zoo.load_roa_requests(args.roa_requests_csv)
    if self.autosync:
      self.zoo.run_rpkid_now()


  @parsecmd(argsubparsers,
            cmdarg("ghostbuster_requests", help = "file listing Ghostbuster requests as a sequence of VCards"))
  def do_load_ghostbuster_requests(self, args):
    """
    Load Ghostbuster requests into IRDB from file.
    """

    self.zoo.load_ghostbuster_requests(args.ghostbuster_requests)
    if self.autosync:
      self.zoo.run_rpkid_now()


  @parsecmd(argsubparsers,
            cmdarg("--valid_until",  help = "override default validity interval"),
            cmdarg("router_certificate_request_xml", help = "file containing XML router certificate request"))
  def do_add_router_certificate_request(self, args):
    """
    Load router certificate request(s) into IRDB from XML file.
    """

    self.zoo.add_router_certificate_request(args.router_certificate_request_xml, args.valid_until)
    if self.autosync:
      self.zoo.run_rpkid_now()

  @parsecmd(argsubparsers,
            cmdarg("gski", help = "g(SKI) of router certificate request to delete"))
  def do_delete_router_certificate_request(self, args):
    """
    Delete a router certificate request from the IRDB.
    """

    try:
      self.zoo.delete_router_certificate_request(args.gski)
      if self.autosync:
        self.zoo.run_rpkid_now()
    except rpki.irdb.ResourceHolderCA.DoesNotExist:
      print "No such resource holder \"%s\"" % self.zoo.handle
    except rpki.irdb.EECertificateRequest.DoesNotExist:
      print "No certificate request matching g(SKI) \"%s\"" % args.gski

  def complete_delete_router_certificate_request(self, text, line, begidx, endidx):
    return [obj.gski for obj in self.zoo.resource_ca.ee_certificate_requests.all()
            if obj.gski and obj.gski.startswith(text)]


  @parsecmd(argsubparsers)
  def do_show_router_certificate_requests(self, args):
    """
    Show this entity's router certificate requests.
    """

    for req in self.zoo.resource_ca.ee_certificate_requests.all():
      print "%s  %s  %s  %s" % (req.gski, req.valid_until, req.cn, req.sn)


  # What about updates?  Validity interval, change router-id, change
  # ASNs.  Not sure what this looks like yet, blunder ahead with the
  # core code while mulling over the UI.


  @parsecmd(argsubparsers)
  def do_synchronize(self, args):
    """
    Whack daemons to match IRDB.

    This command may be replaced by implicit synchronization embedded
    in of other commands, haven't decided yet.
    """

    self.zoo.synchronize()


  @parsecmd(argsubparsers)
  def do_force_publication(self, args):
    """
    Whack rpkid to force (re)publication of everything.

    This is not usually necessary, as rpkid automatically publishes
    changes it makes, but this command can be useful occasionally when
    a fault or configuration error has left rpkid holding data which
    it has not been able to publish.
    """

    self.zoo.publish_world_now()


  @parsecmd(argsubparsers)
  def do_force_reissue(self, args):
    """
    Whack rpkid to force reissuance of everything.

    This is not usually necessary, as rpkid reissues automatically
    objects automatically as needed, but this command can be useful
    occasionally when a fault or configuration error has prevented
    rpkid from reissuing when it should have.
    """

    self.zoo.reissue()


  @parsecmd(argsubparsers)
  def do_up_down_rekey(self, args):
    """
    Initiate a "rekey" operation.

    This tells rpkid to generate new keys for each certificate issued
    to it via the up-down protocol.

    Rekeying is the first stage of a key rollover operation.  You will
    need to follow it up later with a "revoke" operation to clean up
    the old keys
    """

    self.zoo.rekey()


  @parsecmd(argsubparsers)
  def do_up_down_revoke(self, args):
    """
    Initiate a "revoke" operation.

    This tells rpkid to clean up old keys formerly used by
    certificates issued to it via the up-down protocol.

    This is the cleanup stage of a key rollover operation.
    """

    self.zoo.revoke()


  @parsecmd(argsubparsers)
  def do_revoke_forgotten(self, args):
    """
    Initiate a "revoke_forgotten" operation.

    This tells rpkid to ask its parent to revoke certificates for
    which rpkid does not know the private keys.

    This should never happen during ordinary operation, but can happen
    if rpkid is misconfigured or its database has been damaged, so we
    need a way to resynchronize rpkid with its parent in such cases.
    We could do this automatically, but as we don't know the precise
    cause of the failure we don't know if it's recoverable locally
    (eg, from an SQL backup), so we require a manual trigger before
    discarding possibly-useful certificates.
    """

    self.zoo.revoke_forgotten()


  @parsecmd(argsubparsers)
  def do_clear_all_sql_cms_replay_protection(self, args):
    """
    Tell rpkid and pubd to clear replay protection.

    This clears the replay protection timestamps stored in SQL for all
    entities known to rpkid and pubd.  This is a fairly blunt
    instrument, but as we don't expect this to be necessary except in
    the case of gross misconfiguration, it should suffice
    """

    self.zoo.clear_all_sql_cms_replay_protection()


  @parsecmd(argsubparsers)
  def do_version(self, args):
    """
    Show current software version number.
    """

    print rpki.version.VERSION


  @parsecmd(argsubparsers)
  def do_list_self_handles(self, args):
    """
    List all <self/> handles in this rpkid instance.
    """

    for ca in rpki.irdb.ResourceHolderCA.objects.all():
      print ca.handle

