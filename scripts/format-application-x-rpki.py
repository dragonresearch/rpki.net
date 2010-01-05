"""
Take the basic application/x-rpki messages that rpkid and friends
log and translate them into a text version that's easier to search,
without losing any of the original data.  We use MH for the output
format because nmh makes a handy viewer.

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

import email.mime, email.mime.application, email.mime.text, email.mime.multipart, email.utils, email.encoders
import mailbox, POW, lxml.etree, getopt, sys, base64

source_name = None
destination_name = None
mark_seen = False
kill_seen = False
unseen_only = False
target_tag = "{http://www.apnic.net/specs/rescerts/up-down/}message"

def usage(ok):
  print "Usage: %s [--mark] [--kill] [--tag tag]] [--unseen] --input maildir --output mhfolder" % sys.argv[0]
  print __doc__
  sys.exit(0 if ok else 1)

opts, argv = getopt.getopt(sys.argv[1:], "hi:kmo:t:u?", ["help", "input=", "kill", "mark", "output=", "tag=", "unseen"])
for o, a in opts:
  if o in ("-h", "--help", "-?"):
    usage(ok = True)
  elif o in ("-i", "--input"):
    source_name = a
  elif o in ("-m", "--mark"):
    mark_seen = True
  elif o in ("-k", "--kill"):
    kill_seen = True
  elif o in ("-o", "--output"):
    destination_name = a
  elif o in ("-t", "--tag"):
    target_tag = a
  elif o in ("-u", "--unseen"):
    unseen_only = True
if argv or source_name is None or destination_name is None:
  usage(ok = False)

def pprint_cert(b64):
  return POW.derRead(POW.X509_CERTIFICATE, base64.b64decode(b64)).pprint()
  
def up_down():
  msg["X-RPKI-Up-Down-Type"] = xml.get("type")
  msg["X-RPKI-Up-Down-Sender"] = xml.get("sender")
  msg["X-RPKI-Up-Down-Recipient"] = xml.get("recipient")
  msg["Subject"] = "Up-down %s %s => %s" % (xml.get("type"), xml.get("sender"), xml.get("recipient"))
  for x in xml:
    if x.tag.endswith("class"):
      for y in x:
        if y.tag.endswith("certificate") or y.tag.endswith("issuer"):
          msg.attach(email.mime.text.MIMEText(pprint_cert(y.text)))

def left_right():
  msg["X-RPKI-Left-Right-Type"] = xml.get("type")
  msg["Subject"] = "Left-right %s" % xml.get("type")

def publication():
  msg["X-RPKI-Left-Right-Type"] = xml.get("type")
  msg["Subject"] = "Publication %s" % xml.get("type")

dispatch = { "{http://www.apnic.net/specs/rescerts/up-down/}message" : up_down,
             "{http://www.hactrn.net/uris/rpki/left-right-spec/}msg" : left_right,
             "{http://www.hactrn.net/uris/rpki/publication-spec/}msg" : publication }

def fix_headers():
  if "X-RPKI-PID" in srcmsg or "X-RPKI-Object" in srcmsg:
    msg["X-RPKI-PID"] = srcmsg["X-RPKI-PID"]
    msg["X-RPKI-Object"] = srcmsg["X-RPKI-Object"]
  else:
    words = srcmsg["Subject"].split()
    msg["X-RPKI-PID"] = words[1]
    msg["X-RPKI-Object"] = " ".join(words[4:])
  
destination = None
source = None
try:
  destination = mailbox.MH(destination_name, factory = None, create = True)
  source = mailbox.Maildir(source_name, factory = None)

  for srckey, srcmsg in source.iteritems():
    if unseen_only and "S" in srcmsg.get_flags():
      continue
    assert not srcmsg.is_multipart() and srcmsg.get_content_type() == "application/x-rpki"
    payload = srcmsg.get_payload(decode = True)
    cms = POW.derRead(POW.CMS_MESSAGE, payload)
    txt = cms.verify(POW.X509Store(), None, POW.CMS_NOCRL | POW.CMS_NO_SIGNER_CERT_VERIFY | POW.CMS_NO_ATTR_VERIFY | POW.CMS_NO_CONTENT_VERIFY)
    xml = lxml.etree.fromstring(txt)
    tag = xml.tag
    if target_tag and tag != target_tag:
      continue
    msg = email.mime.multipart.MIMEMultipart("related")
    msg["X-RPKI-Tag"] = tag
    for i in ("Date", "Message-ID", "X-RPKI-Timestamp"):
      msg[i] = srcmsg[i]
    fix_headers()
    if tag in dispatch:
      dispatch[tag]()
    if "Subject" not in msg:
      msg["Subject"] = srcmsg["Subject"]
    msg.attach(email.mime.text.MIMEText(txt))
    msg.attach(email.mime.application.MIMEApplication(payload, "x-rpki"))
    msg.epilogue = "\n"                 # Force trailing newline
    key = destination.add(msg)
    print "Added", key
    if kill_seen:
      del source[srckey]
    elif mark_seen:
      srcmsg.set_subdir("cur")
      srcmsg.add_flag("S")
      source[srckey] = srcmsg

finally:
  if destination:
    destination.close()
  if source:
    source.close()
