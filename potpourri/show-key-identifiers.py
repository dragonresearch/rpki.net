#!/usr/bin/env python
#
# $Id$
#
# Copyright (C) 2014 Dragon Research Labs ("DRL")
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL DRL BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""
Print out URIs, resources, and key identifiers.  Yet another twist on
the same basic tree walk, just different data fields for a different
research project.
"""

import os
import argparse
import rpki.POW
import rpki.oids


def check_dir(s):
    if os.path.isdir(s):
        return os.path.abspath(s)
    else:
        raise argparse.ArgumentTypeError("%r is not a directory" % s)


def filename_to_uri(filename):
    if not filename.startswith(args.rcynic_dir):
        raise ValueError
    return "rsync://" + filename[len(args.rcynic_dir):].lstrip("/")


def get_roa(fn):
    return rpki.POW.CMS.derReadFile(fn).certs()[0]

def get_crl(fn):
    return rpki.POW.CRL.derReadFile(fn)

def get_cer(fn):
    return rpki.POW.X509.derReadFile(fn)

dispatch = dict(roa = get_roa,
                crl = get_crl,
                cer = get_cer)

parser = argparse.ArgumentParser(description = __doc__)
parser.add_argument("rcynic_dir", type = check_dir, help = "rcynic authenticated output directory")
args = parser.parse_args()

for root, dirs, files in os.walk(args.rcynic_dir):
    for fn in files:
        fn = os.path.join(root, fn)
        fn2 = os.path.splitext(fn)[1][1:]
        if fn2 not in dispatch:
            continue
        obj = dispatch[fn2](fn)
        uri = filename_to_uri(fn)
        try:
            ski = obj.getSKI().encode("hex")
        except:
            ski = ""
        try:
            aki = obj.getAKI().encode("hex")
        except:
            aki = ""
        try:
            res = ",".join(",".join("%s-%s" % r2 for r2 in r1) for r1 in obj.getRFC3779() if r1 is not None)
        except:
            res = ""
        print "\t".join((uri, ski, aki, res))
