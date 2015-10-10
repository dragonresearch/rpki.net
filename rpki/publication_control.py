# $Id$
#
# Copyright (C) 2013--2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2009--2012  Internet Systems Consortium ("ISC")
# Portions copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL, ISC, AND ARIN DISCLAIM ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL DRL,
# ISC, OR ARIN BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
# CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
# OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
# WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""
RPKI publication control protocol.

Per IETF SIDR WG discussion, this is now separate from the publication
protocol itself.
"""

import logging
import collections

import rpki.x509
import rpki.exceptions
import rpki.relaxng

logger = logging.getLogger(__name__)


nsmap    = rpki.relaxng.publication_control.nsmap
version  = rpki.relaxng.publication_control.version

tag_msg           = rpki.relaxng.publication_control.xmlns + "msg"
tag_client        = rpki.relaxng.publication_control.xmlns + "client"
tag_bpki_cert     = rpki.relaxng.publication_control.xmlns + "bpki_cert"
tag_bpki_glue     = rpki.relaxng.publication_control.xmlns + "bpki_glue"
tag_report_error  = rpki.relaxng.publication_control.xmlns + "report_error"


def raise_if_error(pdu):
  """
  Raise an appropriate error if this is a <report_error/> PDU.

  As a convience, this will also accept a <msg/> PDU and raise an
  appropriate error if it contains any <report_error/> PDUs.
  """

  if pdu.tag == tag_report_error:
    code = pdu.get("error_code")
    logger.debug("<report_error/> code %r", code)
    e = getattr(rpki.exceptions, code, None)
    if e is not None and issubclass(e, rpki.exceptions.RPKI_Exception):
      raise e(pdu.text)
    else:
      raise rpki.exceptions.BadPublicationReply("Unexpected response from pubd: %r, %r" % (code, pdu))

  if pdu.tag == tag_msg:
    for p in pdu:
      raise_if_error(p)


class cms_msg(rpki.x509.XML_CMS_object):
  """
  CMS-signed publication control PDU.
  """

  encoding = "us-ascii"
  schema = rpki.relaxng.publication_control
