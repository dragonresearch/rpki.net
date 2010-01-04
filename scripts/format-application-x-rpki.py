# $Id$
#
# Copyright (C) 2010  Internet Systems Consortium ("ISC")
# 
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

# Take the basic application/x-rpki messages that rpkid and friends
# log and translate them into an expanded version that's easier to
# view without losing any of the original content.
#
# Python's mailbox library rocks.

import email.mime, email.mime.application, email.mime.text, email.mime.multipart, email.utils, email.encoders
import mailbox, POW, lxml.etree

multipart = False
source_name = "/tmp/deaddrop"
destination_name = "~/.mh_dir/pretty-x-rpki"

destination = None
try:
  destination = mailbox.MH(destination_name, factory = None, create = True)

  for key in destination.iterkeys():
    destination.discard(key)
  destination.flush()

  # See http://bugs.python.org/issue7627 for why we only set this lock
  # -after- discarding old messages in destination mailbox.
  destination.lock()

  for message in mailbox.Maildir(source_name, factory = None):
    assert not message.is_multipart() and message.get_content_type() == "application/x-rpki"
    headers = dict(kv for kv in message.items())
    payload = message.get_payload(decode = True)
    cms = POW.derRead(POW.CMS_MESSAGE, payload)
    txt = cms.verify(POW.X509Store(), None, POW.CMS_NOCRL | POW.CMS_NO_SIGNER_CERT_VERIFY | POW.CMS_NO_ATTR_VERIFY | POW.CMS_NO_CONTENT_VERIFY)
    msg = email.mime.text.MIMEText(txt)
    if multipart:
      msg = email.mime.multipart.MIMEMultipart("related", None, (msg, email.mime.application.MIMEApplication(payload, "x-rpki", email.encoders.encode_7or8bit)))
    for k, v in headers.iteritems():
      if k not in msg:
        msg[k] = v
    key = destination.add(msg)
    print "Added", key

finally:
  if destination:
    destination.unlock()
    destination.close()
