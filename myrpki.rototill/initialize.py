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

cfg = rpki.config.parser(cfg_file, "myrpki")

handle     = cfg.get("handle")
want_rpkid = cfg.getboolean("want_rpkid")
want_pubd  = cfg.getboolean("want_pubd")
want_rootd = cfg.getboolean("want_rootd")

myrpki.openssl = cfg.get("openssl", "openssl")

# First create the "myrpki" (resource holding) BPKI and trust anchor

bpki_myrpki = myrpki.CA(cfg_file, cfg.get("myrpki_bpki_directory"))

bpki_myrpki.setup(cfg.get("bpki_myrpki_ta_dn",
                          "/CN=%s BPKI Resource Trust Anchor" % handle))

# If we're running any daemons at all, we also need to set up the
# "myirbe" (server-operating) BPKI, its trust anchor, and EE certs for
# each program we need to run.

if want_rpkid or want_pubd or want_rootd:

  bpki_myirbe = myrpki.CA(cfg_file, cfg.get("myirbe_bpki_directory"))

  bpki_myirbe.setup(cfg.get("bpki_myirbe_ta_dn",
                            "/CN=%s BPKI Server Trust Anchor" % handle))

  if want_rpkid:                        # rpkid implies irdbd

    bpki_myirbe.ee(cfg.get("bpki_rpkid_ee_dn",
                           "/CN=%s rpkid server certificate" % handle), "rpkid")

    bpki_myirbe.ee(cfg.get("bpki_irdbd_ee_dn",
                           "/CN=%s irdbd server certificate" % handle), "irdbd")

  if want_pubd:
    bpki_myirbe.ee(cfg.get("bpki_pubd_ee_dn",
                           "/CN=%s pubd server certificate" % handle), "pubd")

  if want_rpkid or want_irdbd:          # Client cert for myirbe and irbe_cli
    
    bpki_myirbe.ee(cfg.get("bpki_irbe_ee_dn",
                           "/CN=%s irbe client certificate" % handle), "irbe")

  if want_rootd:

    bpki_myirbe.ee(cfg.get("bpki_rootd_ee_dn",
                           "/CN=%s rootd server certificate" % handle), "rootd")

# Now build the me.xml file (name should be configurable, and should
# check for existing file so we don't overwrite, ... hack later ...).

e = Element("me", xmlns = myrpki.namespace, version = "1", handle = handle)

myrpki.PEMElement(e, "bpki_ca_certificate", bpki_myrpki.cer)

ElementTree(e).write("me.xml.tmp")
os.rename("me.xml.tmp", "me.xml")
