# $Id$
#
# Copyright (C) 2015-2016  Parsons Government Services ("PARSONS")
# Portions copyright (C) 2013-2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2009-2012  Internet Systems Consortium ("ISC")
# Portions copyright (C) 2007-2008  American Registry for Internet Numbers ("ARIN")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND PARSONS, DRL, ISC, AND ARIN
# DISCLAIM ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT
# SHALL PARSONS, DRL, ISC, OR ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
# RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
# CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""
RPKI "up-down" protocol.
"""

import logging
import rpki.resource_set
import rpki.x509
import rpki.exceptions
import rpki.log
import rpki.relaxng

from lxml.etree import SubElement, tostring as ElementToString

logger = logging.getLogger(__name__)

xmlns   = rpki.relaxng.up_down.xmlns
nsmap   = rpki.relaxng.up_down.nsmap
version = "1"

## @var content_type
# MIME content type to use when sending up-down queries.
content_type = "application/rpki-updown"
#content_type = "application/x-rpki"

## @var allowed_content_types
# MIME content types which we consider acceptable for incoming up-down
# queries.
allowed_content_types = ("application/rpki-updown", "application/x-rpki")

## @var enforce_strict_up_down_xml_sender
# Enforce strict checking of XML "sender" field in up-down protocol

enforce_strict_up_down_xml_sender = False

tag_certificate = xmlns + "certificate"
tag_class       = xmlns + "class"
tag_description = xmlns + "description"
tag_issuer      = xmlns + "issuer"
tag_key         = xmlns + "key"
tag_message     = xmlns + "message"
tag_request     = xmlns + "request"
tag_status      = xmlns + "status"


class multi_uri(list):
    """
    Container for a set of URIs.  This probably could be simplified.
    """

    def __init__(self, ini):
        list.__init__(self)
        if isinstance(ini, (list, tuple)):
            self[:] = ini
        elif isinstance(ini, str):
            self[:] = ini.split(",")
            for s in self:
                if s.strip() != s or "://" not in s:
                    raise rpki.exceptions.BadURISyntax("Bad URI \"%s\"" % s)
        else:
            raise TypeError

    def __str__(self):
        return ",".join(self)

    def rsync(self):
        """
        Find first rsync://... URI in self.
        """

        for s in self:
            if s.startswith("rsync://"):
                return s
        return None


error_response_codes = {
    1101 : "Already processing request",
    1102 : "Version number error",
    1103 : "Unrecognised request type",
    1201 : "Request - no such resource class",
    1202 : "Request - no resources allocated in resource class",
    1203 : "Request - badly formed certificate request",
    1301 : "Revoke - no such resource class",
    1302 : "Revoke - no such key",
    2001 : "Internal Server Error - Request not performed" }


exception_map = {
    rpki.exceptions.NoActiveCA                    : 1202,
    (rpki.exceptions.ClassNameUnknown, "revoke")  : 1301,
    rpki.exceptions.ClassNameUnknown              : 1201,
    (rpki.exceptions.NotInDatabase,    "revoke")  : 1302 }


def check_response(r_msg, q_type):
    """
    Additional checks beyond the XML schema for whether this looks like
    a reasonable up-down response message.
    """

    r_type = r_msg.get("type")

    if r_type == "error_response":
        raise rpki.exceptions.UpstreamError(error_response_codes[int(r_msg.findtext(tag_status))])

    if r_type != q_type + "_response":
        raise rpki.exceptions.UnexpectedUpDownResponse

    if r_type == "issue_response" and (len(r_msg) != 1 or len(r_msg[0]) != 2):
        logger.debug("Weird issue_response %r: len(r_msg) %s len(r_msg[0]) %s",
                     r_msg, len(r_msg), len(r_msg[0]) if len(r_msg) else None)
        logger.debug("Offending message\n%s", ElementToString(r_msg))
        raise rpki.exceptions.BadIssueResponse


def generate_error_response(r_msg, status = 2001, description = None):
    """
    Generate an error response.  If status is given, it specifies the
    numeric code to use, otherwise we default to "internal error".
    If description is specified, we use it as the description, otherwise
    we just use the default string associated with status.
    """

    assert status in error_response_codes
    del r_msg[:]
    r_msg.set("type", "error_response")
    SubElement(r_msg, tag_status).text = str(status)
    se = SubElement(r_msg, tag_description)
    se.set("{http://www.w3.org/XML/1998/namespace}lang", "en-US")
    se.text = str(description or error_response_codes[status])


def generate_error_response_from_exception(r_msg, e, q_type):
    """
    Construct an error response from an exception.  q_type
    specifies the kind of query to which this is a response, since the
    same exception can generate different codes in response to different
    queries.
    """

    t = type(e)
    code = (exception_map.get((t, q_type)) or exception_map.get(t) or 2001)
    generate_error_response(r_msg, code, e)


class cms_msg(rpki.x509.XML_CMS_object):
    """
    CMS-signed up-down PDU.
    """

    encoding = "UTF-8"
    schema = rpki.relaxng.up_down
    allow_extra_certs = True
    allow_extra_crls = True
