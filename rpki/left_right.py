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
RPKI "left-right" protocol.
"""

import logging

import rpki.x509
import rpki.exceptions
import rpki.http
import rpki.up_down
import rpki.relaxng
import rpki.sundial
import rpki.log
import rpki.publication
import rpki.async
import rpki.rpkid_tasks


logger = logging.getLogger(__name__)


xmlns   = rpki.relaxng.left_right.xmlns
nsmap   = rpki.relaxng.left_right.nsmap
version = rpki.relaxng.left_right.version

tag_bpki_cert                    = xmlns + "bpki_cert"
tag_bpki_glue                    = xmlns + "bpki_glue"
tag_bsc                          = xmlns + "bsc"
tag_child                        = xmlns + "child"
tag_list_ee_certificate_requests = xmlns + "list_ee_certificate_requests"
tag_list_ghostbuster_requests    = xmlns + "list_ghostbuster_requests"
tag_list_published_objects       = xmlns + "list_published_objects"
tag_list_received_resources      = xmlns + "list_received_resources"
tag_list_resources               = xmlns + "list_resources"
tag_list_roa_requests            = xmlns + "list_roa_requests"
tag_msg                          = xmlns + "msg"
tag_parent                       = xmlns + "parent"
tag_pkcs10                       = xmlns + "pkcs10"
tag_pkcs10_request               = xmlns + "pkcs10_request"
tag_report_error                 = xmlns + "report_error"
tag_repository                   = xmlns + "repository"
tag_self                         = xmlns + "self"
tag_signing_cert                 = xmlns + "signing_cert"
tag_signing_cert_crl             = xmlns + "signing_cert_crl"


class cms_msg(rpki.x509.XML_CMS_object):
  """
  CMS-signed left-right PDU.
  """

  encoding = "us-ascii"
  schema = rpki.relaxng.left_right
