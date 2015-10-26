# $Id$

# Copyright (C) 2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2008  American Registry for Internet Numbers ("ARIN")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL AND AND ARIN DISCLAIM ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL DRL OR
# ARIN BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
# DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA
# OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
# TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""
Extract a private key from rpkid's database.

This is a debugging tool.  rpkid goes to some trouble not to expose
private keys, which is correct for normal operation, but for debugging
it is occasionally useful to be able to extract the private key from
MySQL.  This script is just a convenience, it doesn't enable anything
that couldn't be done via the mysql command line tool.

While we're at this we also extract the corresponding certificate.
"""

import os
import time
import argparse
import sys
import MySQLdb
import rpki.x509

os.environ["TZ"] = "UTC"
time.tzset()

parser = argparse.ArgumentParser(description = __doc__)
parser.add_argument("-s", "--self",     required = True, help = "self handle")
parser.add_argument("-b", "--bsc",      required = True, help = "BSC handle")
parser.add_argument("-u", "--user",     required = True, help = "MySQL user name")
parser.add_argument("-d", "--db",       required = True, help = "MySQL database name")
parser.add_argument("-p", "--password", required = True, help = "MySQL password")
args = parser.parse_args()

cur = MySQLdb.connect(user = args.user, db = args.db, passwd = args.password).cursor()

cur.execute(
    """
      SELECT bsc.private_key_id, bsc.signing_cert
      FROM bsc, self
      WHERE self.self_handle = %s AND self.self_id = bsc.self_id AND bsc_handle = %s
    """,
    (args.self, args.bsc))

key, cer = cur.fetchone()

print rpki.x509.RSA(DER = key).get_PEM()

if cer:
    print rpki.x509.X509(DER = cer).get_PEM()
