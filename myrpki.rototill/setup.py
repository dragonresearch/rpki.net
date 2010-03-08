"""
$Id$

Copyright (C) 2010  Internet Systems Consortium ("ISC")

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

import subprocess, csv, re, os, getopt, sys, base64, time, glob
import myrpki, rpki.config, rpki.cli, rpki.sundial

try:
  from lxml.etree import Element, SubElement, ElementTree
except ImportError:
  from xml.etree.ElementTree import Element, SubElement, ElementTree

PEMElement = myrpki.PEMElement

class main(rpki.cli.Cmd):

  prompt = "setup> "

  completedefault = rpki.cli.Cmd.filename_complete

  me = None
  parents = {}
  children = {}
  repositories = {}


  def __init__(self):
    os.environ["TZ"] = "UTC"
    time.tzset()

    self.cfg_file = os.getenv("MYRPKI_CONF", "myrpki.conf")

    opts, argv = getopt.getopt(sys.argv[1:], "c:h?", ["config=", "help"])
    for o, a in opts:
      if o in ("-c", "--config"):
        self.cfg_file = a
      elif o in ("-h", "--help", "-?"):
        argv = ["help"]

    if not argv or argv[0] != "help":
      self.read_config()

    rpki.cli.Cmd.__init__(self, argv)


  def read_config(self):

    self.cfg = rpki.config.parser(self.cfg_file, "myrpki")
    myrpki.openssl = self.cfg.get("openssl", "openssl")
    self.histfile  = self.cfg.get("history_file", ".setup_history")

    self.handle    = self.cfg.get("handle")
    self.run_rpkid = self.cfg.getboolean("run_rpkid")
    self.run_pubd  = self.cfg.getboolean("run_pubd")
    self.run_rootd = self.cfg.getboolean("run_rootd")

    self.entitydb = myrpki.EntityDB(self.cfg)

    if self.run_rootd and (not self.run_pubd or not self.run_rpkid):
      raise RuntimeError, "Can't run rootd unless also running rpkid and pubd"

    self.bpki_resources = myrpki.CA(self.cfg_file, self.cfg.get("bpki_resources_directory"))
    if self.run_rpkid or self.run_pubd or self.run_rootd:
      self.bpki_servers = myrpki.CA(self.cfg_file, self.cfg.get("bpki_servers_directory"))

    self.pubd_contact_info = self.cfg.get("pubd_contact_info", "")

    self.rsync_module = self.cfg.get("publication_rsync_module")
    self.rsync_server = self.cfg.get("publication_rsync_server")


  def do_initialize(self, arg):
    if arg:
      raise RuntimeError, "This command takes no arguments"

    print "Generating RSA keys, this may take a little while..."

    self.bpki_resources.setup(self.cfg.get("bpki_resources_ta_dn",
                                           "/CN=%s BPKI Resource Trust Anchor" % self.handle))
    if self.run_rpkid or self.run_pubd or self.run_rootd:
      self.bpki_servers.setup(self.cfg.get("bpki_servers_ta_dn",
                                           "/CN=%s BPKI Server Trust Anchor" % self.handle))

    # Create entitydb directories.

    for i in ("parents", "children", "repositories", "pubclients"):
      d = self.entitydb(i)
      if not os.path.exists(d):
        os.makedirs(d)

    if self.run_rpkid or self.run_pubd or self.run_rootd:

      if self.run_rpkid:
        self.bpki_servers.ee(self.cfg.get("bpki_rpkid_ee_dn",
                                          "/CN=%s rpkid server certificate" % self.handle), "rpkid")
        self.bpki_servers.ee(self.cfg.get("bpki_irdbd_ee_dn",
                                          "/CN=%s irdbd server certificate" % self.handle), "irdbd")
      if self.run_pubd:
        self.bpki_servers.ee(self.cfg.get("bpki_pubd_ee_dn",
                                          "/CN=%s pubd server certificate" % self.handle), "pubd")
      if self.run_rpkid or self.run_pubd:
        self.bpki_servers.ee(self.cfg.get("bpki_irbe_ee_dn",
                                          "/CN=%s irbe client certificate" % self.handle), "irbe")
      if self.run_rootd:
        self.bpki_servers.ee(self.cfg.get("bpki_rootd_ee_dn",
                                          "/CN=%s rootd server certificate" % self.handle), "rootd")

    # Build the identity.xml file.  Need to check for existing file so we don't
    # overwrite?  Worry about that later.

    e = Element("identity", handle = self.handle)
    PEMElement(e, "bpki_ta", self.bpki_resources.cer)
    myrpki.etree_write(e, self.entitydb("identity.xml"))

    # If we're running rootd, construct a fake parent to go with it,
    # and cross-certify in both directions so we can talk to rootd.

    if self.run_rootd:

      e = Element("parent", parent_handle = self.handle, child_handle = self.handle,
                  service_uri = "https://localhost:%s/" % self.cfg.get("rootd_server_port"),
                  valid_until = str(rpki.sundial.now() + rpki.sundial.timedelta(days = 365)))
      PEMElement(e, "bpki_resource_ta", self.bpki_servers.cer)
      PEMElement(e, "bpki_server_ta", self.bpki_servers.cer)
      PEMElement(e, "bpki_child_ta", self.bpki_resources.cer)
      SubElement(e, "repository", type = "offer")
      myrpki.etree_write(e, self.entitydb("parents", "%s.xml" % self.handle))

      self.bpki_resources.xcert(self.bpki_servers.cer)

      rootd_child_fn = self.cfg.get("child-bpki-cert", None, "rootd")
      if not os.path.exists(rootd_child_fn):
        os.link(self.bpki_servers.xcert(self.bpki_resources.cer), rootd_child_fn)

    # If we're running pubd, construct repository request for it, as
    # if we had received an offer.

    if self.run_pubd:
      e = Element("repository", type = "request", handle = self.handle, parent_handle = self.handle)
      SubElement(e, "contact_info").text = self.pubd_contact_info
      PEMElement(e, "bpki_ta", self.bpki_resources.cer)
      myrpki.etree_write(e, self.entitydb("repositories", "%s.xml" % self.handle))


  def do_answer_child(self, arg):

    child_handle = None

    opts, argv = getopt.getopt(arg.split(), "", ["child_handle="])
    for o, a in opts:
      if o == "--child_handle":
        child_handle = a
    
    if len(argv) != 1:
      raise RuntimeError, "Need to specify filename for child.xml"

    if not self.run_rpkid:
      raise RuntimeError, "Don't (yet) know how to set up child unless we run rpkid"

    c = myrpki.etree_read(argv[0])

    if child_handle is None:
      child_handle = c.get("handle")

    print "Child calls itself %r, we call it %r" % (c.get("handle"), child_handle)

    self.bpki_servers.fxcert(c.findtext("bpki_ta"))

    e = Element("parent", parent_handle = self.handle, child_handle = child_handle,
                service_uri = "https://%s:%s/up-down/%s/%s" % (self.cfg.get("rpkid_server_host"),
                                                               self.cfg.get("rpkid_server_port"),
                                                               self.handle, child_handle),
                valid_until = str(rpki.sundial.now() + rpki.sundial.timedelta(days = 365)))

    PEMElement(e, "bpki_resource_ta", self.bpki_resources.cer)
    PEMElement(e, "bpki_server_ta",   self.bpki_servers.cer)
    SubElement(e, "bpki_child_ta").text = c.findtext("bpki_ta")

    try:
      repo = None
      for f in self.entitydb.iterate("repositories", "*.xml"):
        r = myrpki.etree_read(f)
        if r.get("type") == "confirmed":
          if repo is not None:
            raise RuntimeError, "Too many repositories, I don't know what to do, not giving referral"
          repo_handle = os.path.splitext(os.path.split(f)[-1])[0]
          repo = r
      if repo is None:
        raise RuntimeError, "Couldn't find any usable repositories, not giving referral"

      if repo_handle == self.handle:
        SubElement(e, "repository", type = "offer")
      else:
        r = SubElement(e, "repository", type = "hint",
                       proposed_sia_base = repo.get("sia_base") + child_handle + "/")
        SubElement(r, "contact_info").text = repo.findtext("contact_info")
        # CMS-signed blob authorizing use of part of our space by our
        # child goes here, once I've written that code.

    except RuntimeError, err:
      print err

    myrpki.etree_write(e, self.entitydb("children", "%s.xml" % child_handle))


  def do_process_parent_answer(self, arg):

    parent_handle = None

    opts, argv = getopt.getopt(arg.split(), "", ["parent_handle="])
    for o, a in opts:
      if o == "--parent_handle":
        parent_handle = a

    if len(argv) != 1:
      raise RuntimeError, "Need to specify filename for parent.xml on command line"

    p = myrpki.etree_read(argv[0])

    if parent_handle is None:
      parent_handle = p.get("parent_handle")

    print "Parent calls itself %r, we call it %r" % (p.get("parent_handle"), parent_handle)
    print "Parent calls us %r" % p.get("child_handle")

    self.bpki_resources.fxcert(p.findtext("bpki_resource_ta"))
    self.bpki_resources.fxcert(p.findtext("bpki_server_ta"))

    myrpki.etree_write(p, self.entitydb("parents", "%s.xml" % parent_handle))

    r = p.find("repository")

    if r is not None and r.get("type") in ("offer", "hint"):
      r.set("handle", self.handle)
      r.set("parent_handle", parent_handle)
      PEMElement(r, "bpki_ta", self.bpki_resources.cer)
      myrpki.etree_write(r, self.entitydb("repositories", "%s.xml" % parent_handle))

    else:
      print "Couldn't find repository offer or hint"


  def do_answer_repository_client(self, arg):

    sia_base = None

    opts, argv = getopt.getopt(arg.split(), "", ["sia_base="])
    for o, a in opts:
      if o == "--sia_base":
        sia_base = a
    
    if len(argv) != 1:
      raise RuntimeError, "Need to specify filename for client.xml"

    c = myrpki.etree_read(argv[0])

    # Critical thing at this point is to figure out what client's
    # sia_base value should be.  Three cases:
    #
    # - client has no particular relationship to any other client:
    #   sia_base is top-level, or as close as we can make it taking
    #   rsyncd module into account (maybe homed under us, hmm, how do
    #   we detect case where we are talking to ourself?)
    #
    # - client is a direct child of ours to whom we (in our parent
    #   role) made an offer of publication service.  client homes
    #   under us, presumably.
    #
    # - client is a child of a client of ours who referred the new
    #   client to us, along with a signed referral.  signed referral
    #   includes sia_base of referring client, new client homes under
    #   that per referring client's wishes.
    #
    # ... which implies that there's a fourth case, where we are both
    # the client and the server.

    # Checking of signed referrals goes somewhere around here.  Must
    # be after reading client's XML, but before deciding what the
    # client's sia_base and handle will be.

    # For the moment we cheat egregiously, no crypto, blind trust of
    # what we're sent, while I focus on the basic semantics.

    if sia_base is None and c.get("proposed_sia_base"):
      sia_base = c.get("proposed_sia_base")
    elif sia_base is None and c.get("handle") == self.handle:
      sia_base = "rsync://%s/%s/" % (self.rsync_server, self.rsync_module)
    else:
      sia_base = "rsync://%s/%s/%s/" % (self.rsync_server, self.rsync_module, c.get("handle"))

    client_handle = "/".join(sia_base.rstrip("/").split("/")[3:])

    parent_handle = c.get("parent_handle")

    print "Client calls itself %r, we call it %r" % (c.get("handle"), client_handle)
    print "Client says its parent handle is %r" % parent_handle

    self.bpki_servers.fxcert(c.findtext("bpki_ta"))

    e = Element("repository", type = "confirmed",
                repository_handle = self.handle,
                client_handle = client_handle,
                parent_handle = parent_handle,
                sia_base = sia_base,
                service_uri = "https://%s:%s/client/%s" % (self.cfg.get("pubd_server_host"),
                                                           self.cfg.get("pubd_server_port"),
                                                           client_handle))

    PEMElement(e, "bpki_server_ta", self.bpki_servers.cer)
    SubElement(e, "bpki_client_ta").text = c.findtext("bpki_ta")
    SubElement(e, "contact_info").text = self.pubd_contact_info
    myrpki.etree_write(e, self.entitydb("pubclients", "%s.xml" % client_handle.replace("/", ".")))


  def do_process_repository_answer(self, arg):

    argv = arg.split()

    if len(argv) != 1:
      raise RuntimeError, "Need to specify filename for repository.xml on command line"

    r = myrpki.etree_read(argv[0])

    parent_handle = r.get("parent_handle")

    print "Repository calls itself %r, calls us %r" % (r.get("repository_handle"), r.get("client_handle"))
    print "Repository response associated with parent_handle %r" % parent_handle

    myrpki.etree_write(r, self.entitydb("repositories", "%s.xml" % parent_handle))


  def do_compose_request_to_host(self, arg):
    pass

  def do_answer_hosted_entity(self, arg):
    pass

  def do_process_host_answer(self, arg):
    pass


if __name__ == "__main__":
  main()
