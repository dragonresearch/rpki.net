"""
Step 1: User runs a new "initialize" script.  This reads the .conf file
        and creates the resource-holding "self" BPKI identity (what
        we've been calling bpki.myrpki/ca.cer, although that name
        should change and the user shouldn't need to know it anymore).
        If the .conf file says that this user will be running any
        servers at all (rpkid, irdbd, pubd, rootd), this script also
        creates what we've been calling bpki.myirbe/ca.cer and issues
        bpki ee certificates for all the servers we will be running.
        It bundles up the "self" identity (bpki.myrpki/ca.cer and the
        "handle" value from the [myrpki] section of the .conf file) as
        an xml blob, which it writes out to some filename (call it
        me.xml for now).

        The general idea here is to start with all the setup that we
        can do based just on the .conf file without talking to anybody
        else.

        rootd is a special case, in this as in all else.  when we're
        running rootd, the initalize script should probably just
        create everything needed for rootd and for rpkid to know about
        rootd as its parent.  rootd is always operated by the same
        entity as the rpkid that uses this rootd as its parent, so
        this is a bit tedious but should be straightforward.
        similarly, i think it's ok for us to insist that the operator
        running rootd must also run its own pubd.

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

import subprocess, csv, re, os, getopt, sys, base64, time, myrpki, rpki.config

from xml.etree.ElementTree import Element, SubElement, ElementTree

os.environ["TZ"] = "UTC"
time.tzset()

cfg_file = "myrpki.conf"

opts, argv = getopt.getopt(sys.argv[1:], "c:h?", ["config=", "help"])
for o, a in opts:
  if o in ("-c", "--config"):
    cfg_file = a
  elif o in ("-h", "--help", "-?"):
    print __doc__
    sys.exit(0)
if argv:
  print __doc__
  sys.exit(1)

cfg = rpki.config.parser(cfg_file, "myrpki")

handle    = cfg.get("handle")
run_rpkid = cfg.getboolean("run_rpkid")
run_pubd  = cfg.getboolean("run_pubd")
run_rootd = cfg.getboolean("run_rootd")

if run_rootd and (not run_pubd or not run_rpkid):
  raise RuntimeError, "Can't run rootd unless also running rpkid and pubd"

myrpki.openssl = cfg.get("openssl", "openssl")

# Create directories for parents, children, and repositories.
# Directory names should become configurable (later).

for i in ("parents", "children", "repositories"):
  if not os.path.exists(i):
    print "Creating %s/" % i
    os.makedirs(i)
  else:
    print "%s/ already exists" % i

# First create the "myrpki" (resource holding) BPKI and trust anchor

bpki_myrpki = myrpki.CA(cfg_file, cfg.get("myrpki_bpki_directory"))

bpki_myrpki.setup(cfg.get("bpki_myrpki_ta_dn",
                          "/CN=%s BPKI Resource Trust Anchor" % handle))

# If we're running any daemons at all, we also need to set up the
# "myirbe" (server-operating) BPKI, its trust anchor, and EE certs for
# each program we need to run.

if run_rpkid or run_pubd or run_rootd:

  bpki_myirbe = myrpki.CA(cfg_file, cfg.get("myirbe_bpki_directory"))

  bpki_myirbe.setup(cfg.get("bpki_myirbe_ta_dn",
                            "/CN=%s BPKI Server Trust Anchor" % handle))

  if run_rpkid:
    
    bpki_myirbe.ee(cfg.get("bpki_rpkid_ee_dn",
                           "/CN=%s rpkid server certificate" % handle), "rpkid")

    # rpkid implies irdbd

    bpki_myirbe.ee(cfg.get("bpki_irdbd_ee_dn",
                           "/CN=%s irdbd server certificate" % handle), "irdbd")

  if run_pubd:
    bpki_myirbe.ee(cfg.get("bpki_pubd_ee_dn",
                           "/CN=%s pubd server certificate" % handle), "pubd")

  if run_rpkid or run_pubd:
    
    # Client cert for myirbe and irbe_cli

    bpki_myirbe.ee(cfg.get("bpki_irbe_ee_dn",
                           "/CN=%s irbe client certificate" % handle), "irbe")

  if run_rootd:

    bpki_myirbe.ee(cfg.get("bpki_rootd_ee_dn",
                           "/CN=%s rootd server certificate" % handle), "rootd")

# Build the me.xml file.  Need to check for existing file so we don't
# overwrite?  Worry about that later.

e = Element("me", xmlns = myrpki.namespace, version = "1", handle = handle)
myrpki.PEMElement(e, "bpki_ca_certificate", bpki_myrpki.cer)
myrpki.etree_write(e, handle + ".xml")

# If we're running rootd, construct a fake parent to go with it.

if run_rootd:

  e = Element("parent", xmlns = myrpki.namespace, version = "1",
              parent_handle = "rootd", child_handle = handle,
              service_url = "https://localhost:%s/" % cfg.get("rootd_server_port"))

  myrpki.PEMElement(e, "bpki_resource_ca", bpki_myirbe.cer)
  myrpki.PEMElement(e, "bpki_server_ca",   bpki_myirbe.cer)

  SubElement(e, "repository", type = "offer",
             service_url = "https://%s:%d/" % (cfg.get("pubd_server_host"),
                                               cfg.get("pubd_server_port")))
  rootd_filename = "parents/rootd.xml"
  print "Writing", rootd_filename
  myrpki.etree_write(e, rootd_filename)
