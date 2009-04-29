"""
Extract a private key from rpkid's database.

This is a debugging tool.  rpkid goes to some trouble not to expose
private keys, which is correct for normal operation, but for debugging
it is occasionally useful to be able to extract the private key from
MySQL.  This script is just a convenience, it doesn't enable anything
that couldn't be done via the mysql command line tool.

While we're at this we also extract the corresponding certificate.

Usage: python extract-key.py [ { -s | --self     } self_id        ]
                             [ { -b | --bsc      } bsc_id         ]
                             [ { -u | --user     } mysql_user_id  ]
                             [ { -d | --db       } mysql_database ]
                             [ { -p | --password } mysql_password ]
                             [ { -h | --help     } ]

Default for both self_id and bsc_id is 1.
Default for both user and db is "rpki".

$Id$

Copyright (C) 2008  American Registry for Internet Numbers ("ARIN")

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

import os, time, getopt, sys, MySQLdb
import rpki.x509

os.environ["TZ"] = "UTC"
time.tzset()

def usage(code):
  print __doc__
  sys.exit(code)

self_id = 1
bsc_id  = 1

user = "rpki"
passwd = "fnord"
db   = "rpki"

opts, argv = getopt.getopt(sys.argv[1:], "s:b:u:p:d:h?",
                           ["self=", "bsc=", "user=", "password=", "db=", "help"])
for o, a in opts:
  if o in ("-h", "--help", "-?"):
    usage(0)
  elif o in ("-s", "--self"):
    self_id = int(a)
  elif o in ("-b", "--bsc"):
    bsc_id = int(a)
  elif o in ("-u", "--user"):
    user = a
  elif o in ("-p", "--password"):
    passwd = a
  elif o in ("-d", "--db"):
    db = a
if argv:
  usage(1)

cur = MySQLdb.connect(user = user, db = db, passwd = passwd).cursor()

cur.execute("SELECT private_key_id, signing_cert FROM bsc WHERE self_id = %s AND bsc_id = %s",
            (self_id, bsc_id))

key, cer = cur.fetchone()

print rpki.x509.RSA(DER = key).get_PEM()

if cer:
  print rpki.x509.X509(DER = cer).get_PEM()
