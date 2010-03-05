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
import myrpki, rpki.config, rpki.cli

from xml.etree.ElementTree import Element, SubElement, ElementTree

namespace = myrpki.namespace
tag = myrpki.tag

def read_xml_handle_tree(filename):
  handle = os.path.splitext(os.path.split(filename)[-1])[0]
  etree  = myrpki.etree_read(filename)
  return handle, etree

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

    self.cfg = rpki.config.parser(self.cfg_file, "myrpki")
    myrpki.openssl = self.cfg.get("openssl", "openssl")
    self.histfile  = self.cfg.get("history_file", ".setup_history")

    self.handle    = self.cfg.get("handle")
    self.run_rpkid = self.cfg.getboolean("run_rpkid")
    self.run_pubd  = self.cfg.getboolean("run_pubd")
    self.run_rootd = self.cfg.getboolean("run_rootd")

    if self.run_rootd and (not self.run_pubd or not self.run_rpkid):
      raise RuntimeError, "Can't run rootd unless also running rpkid and pubd"

    self.bpki_myrpki = myrpki.CA(self.cfg_file, self.cfg.get("bpki_resources_directory"))
    if self.run_rpkid or self.run_pubd or self.run_rootd:
      self.bpki_myirbe = myrpki.CA(self.cfg_file, self.cfg.get("bpki_servers_directory"))

    rpki.cli.Cmd.__init__(self, argv)

  def load_xml(self):
    handle, self.me   = read_xml_handle_tree("%s.xml" % self.handle)
    self.parents      = dict(read_xml_handle_tree(i) for i in glob.glob("parents/*.xml"))
    self.children     = dict(read_xml_handle_tree(i) for i in glob.glob("children/*.xml"))
    self.repositories = dict(read_xml_handle_tree(i) for i in glob.glob("repositories/*.xml"))
    assert handle == self.handle

  def do_initialize(self, arg):
    if arg:
      raise RuntimeError, "This command takes no arguments"

    self.bpki_myrpki.setup(self.cfg.get("bpki_myrpki_ta_dn",
                                        "/CN=%s BPKI Resource Trust Anchor" % self.handle))
    if self.run_rpkid or self.run_pubd or self.run_rootd:
      self.bpki_myirbe.setup(self.cfg.get("bpki_myirbe_ta_dn",
                                          "/CN=%s BPKI Server Trust Anchor" % self.handle))

    # Create directories for parents, children, and repositories.
    # Directory names should become configurable (later).

    for i in ("parents", "children", "repositories"):
      if not os.path.exists(i):
        os.makedirs(i)

    if self.run_rpkid or self.run_pubd or self.run_rootd:

      if self.run_rpkid:
        self.bpki_myirbe.ee(self.cfg.get("bpki_rpkid_ee_dn",
                                         "/CN=%s rpkid server certificate" % self.handle), "rpkid")
        self.bpki_myirbe.ee(self.cfg.get("bpki_irdbd_ee_dn",
                                         "/CN=%s irdbd server certificate" % self.handle), "irdbd")

      if self.run_pubd:
        self.bpki_myirbe.ee(self.cfg.get("bpki_pubd_ee_dn",
                                         "/CN=%s pubd server certificate" % self.handle), "pubd")

      if self.run_rpkid or self.run_pubd:
        self.bpki_myirbe.ee(self.cfg.get("bpki_irbe_ee_dn",
                                         "/CN=%s irbe client certificate" % self.handle), "irbe")

      if self.run_rootd:
        self.bpki_myirbe.ee(self.cfg.get("bpki_rootd_ee_dn",
                                         "/CN=%s rootd server certificate" % self.handle), "rootd")

    # Build the me.xml file.  Need to check for existing file so we don't
    # overwrite?  Worry about that later.

    e = Element("me", xmlns = namespace, version = "1", handle = self.handle)
    myrpki.PEMElement(e, "bpki_ca_certificate", self.bpki_myrpki.cer)
    myrpki.etree_write(e, "%s.xml" % self.handle)

    # If we're running pubd, construct repository entry for it.

    if self.run_pubd:
      r = Element("repository", type = "offer",
                  service_url = "https://%s:%s/" % (self.cfg.get("pubd_server_host"),
                                                    self.cfg.get("pubd_server_port")))

    # If we're running rootd, construct a fake parent to go with it,
    # and cross-certify in both directions so we can talk to rootd.

    if self.run_rootd:

      e = Element(tag("parent"), version = "1",
                  parent_handle = "rootd", child_handle = self.handle,
                  service_url = "https://localhost:%s/" % self.cfg.get("rootd_server_port"))

      myrpki.PEMElement(e, tag("bpki_resource_ca"), self.bpki_myirbe.cer)
      myrpki.PEMElement(e, tag("bpki_server_ca"),   self.bpki_myirbe.cer)

      e.append(r)
      myrpki.etree_write(e, "parents/rootd.xml")

      self.bpki_myrpki.xcert(self.bpki_myirbe.cer)

      rootd_child_fn = self.cfg.get("child-bpki-cert", None, "rootd")
      if not os.path.exists(rootd_child_fn):
        os.link(self.bpki_myirbe.xcert(self.bpki_myrpki.cer), rootd_child_fn)

    # Save repository entry.

    if self.run_pubd:
      r.set("xmlns", namespace)
      r.set("version", "1")
      myrpki.etree_write(r, "repositories/%s.xml" % self.handle)

  def do_receive_from_child(self, arg):

    self.load_xml()

    child_handle = None

    opts, argv = getopt.getopt(arg.split(), "", ["child_handle="])
    for o, a in opts:
      if o == "--child_handle":
        child_handle = a
    
    if len(argv) != 1 or not os.path.exists(argv[0]):
      raise RuntimeError, "Need to specify filename for child.xml on command line"

    if not self.run_rpkid:
      raise RuntimeError, "Don't (yet) know how to set up child unless we run rpkid"

    c = myrpki.etree_read(argv[0])

    if child_handle is None:
      child_handle = c.get("handle")

    print "Child calls itself %r, we call it %r" % (c.get("handle"), child_handle)

    self.bpki_myirbe.fxcert(c.findtext(myrpki.tag("bpki_ca_certificate")))

    e = Element("parent", xmlns = namespace, version = "1",
                parent_handle = self.handle, child_handle = child_handle,
                service_url = "https://%s:%s/up-down/%s/%s" % (self.cfg.get("rpkid_server_host"),
                                                               self.cfg.get("rpkid_server_port"),
                                                               self.handle, child_handle))

    myrpki.PEMElement(e, "bpki_resource_ca", self.bpki_myrpki.cer)
    myrpki.PEMElement(e, "bpki_server_ca",   self.bpki_myirbe.cer)

    if self.run_pubd:
      SubElement(e, "repository", type = "offer",
                 service_url = "https://%s:%s/" % (self.cfg.get("pubd_server_host"),
                                                   self.cfg.get("pubd_server_port")))
    else:
      print "Warning: I don't yet know how to do publication hints, only offers"

    myrpki.etree_write(e, "children/%s.xml" % child_handle)

  def do_receive_from_parent(self, arg):

    self.load_xml()

    parent_handle = None
    repository_handle = None

    opts, argv = getopt.getopt(arg.split(), "", ["parent_handle", "repository_handle"])
    for o, a in opts:
      if o == "--parent_handle":
        parent_handle = a
      elif o == "--repository_handle":
        repository_handle = a

    if len(argv) != 1 or not os.path.exists(argv[0]):
      raise RuntimeError, "Ned to specify filename for parent.xml on command line"

    p = myrpki.etree_read(argv[0])

    if parent_handle is None:
      parent_handle = p.get("parent_handle")

    if repository_handle is None:
      repository_handle = parent_handle

    print "Parent calls itself %r, we call it %r" % (p.get("parent_handle"), parent_handle)
    print "Parent calls us %r" % p.get("child_handle")
    print "We call repository %r" % repository_handle

    self.bpki_myrpki.fxcert(p.findtext(myrpki.tag("bpki_resource_ca")))
    b = self.bpki_myrpki.fxcert(p.findtext(myrpki.tag("bpki_server_ca")))

    myrpki.etree_write(p, "parents/%s.xml" % parent_handle)

    r = p.find(myrpki.tag("repository"))

    if r is not None and r.get("type") == "offer":
      e = Element("repository", xmlns = namespace, version = "1",
                  service_url = r.get("service_url"))
      myrpki.PEMElement(e, "bpki_server_ca", b)
      myrpki.etree_write(e, "repositories/%s.xml" % repository_handle)

    elif r is not None and r.get("type") == "hint":
      print "Found repository hint but don't know how to handle that (yet)"

    else:
      print "Couldn't find repository offer or hint"
    
if __name__ == "__main__":
  main()
