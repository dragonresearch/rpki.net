# $Id$
# Copyright (C) 2011  SPARTA, Inc. dba Cobham Analytic Solutions
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND SPARTA DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL SPARTA BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.
#
#
# Helper script for use on the server side when using rpkidemo.
# Takes a xml result from either configure_parent or
# configure_publication_client and places it in the portal gui
# outbox with the appropriate rfc822 header fields.

import os
os.environ['DJANGO_SETTINGS_MODULE'] = 'rpki.gui.settings'

import sys
import pwd
import email.message, email.utils, mailbox
from django.conf import settings

if len(sys.argv) < 4:
    sys.stderr.write("""usage: rpkigui-response <target-handle> <response-type> <xml-response-file>

<target-handle>        the handle for the rpkidemo user to which this
                       response should be sent

<response-type>        'parent' for a configure_child response, or
                       'repository' for a configure_publication_client
                       response

<xml-response-file>    the file containing the xml response for a
                       configure_child or configure_publication_client
                       command
""")

    sys.exit(0)

class InvalidResponseType(Exception):
    """
    Invalid response type.
    """

request_type = sys.argv[2]
if not request_type in ('parent', 'repository'):
    raise InvalidResponseType, 'invalid response type: %s' % request_type

# make sure apache process can manipulate the outbox!
os.setuid(pwd.getpwnam(settings.WEB_USER)[2])

msg = email.message.Message()
msg['X-rpki-self-handle'] = sys.argv[1]
msg['X-rpki-type'] = request_type
msg['Date'] = email.utils.formatdate()
msg['Message-ID'] = email.utils.make_msgid()
msg.set_type('application/x-rpki-setup')
msg.set_payload(open(sys.argv[3]).read())

box = mailbox.Maildir(settings.OUTBOX)
box.add(msg)

# vim:sw=4 ts=8 expandtab
