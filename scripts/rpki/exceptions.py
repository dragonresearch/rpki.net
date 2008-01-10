# $Id$

# Copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""Exception definitions for RPKI modules."""

class NotInDatabase(Exception):
  """Lookup failed for an object expected to be in the database."""

class BadURISyntax(Exception):
  """Illegal syntax for a URI."""

class BadStatusCode(Exception):
  """Unrecognized protocol status code."""

class BadQuery(Exception):
  """Unexpected protocol query."""

class DBConsistancyError(Exception):
  """Found multiple matches for a database query that shouldn't ever return that."""

class CMSVerificationFailed(Exception):
  """Verification of a CMS message failed."""

class HTTPRequestFailed(Exception):
  """HTTP request failed."""

class DERObjectConversionError(Exception):
  """Error trying to convert a DER-based object from one representation to another."""

class NotACertificateChain(Exception):
  """Certificates don't form a proper chain."""

class BadContactURL(Exception):
  """Error trying to parse up-down protocol contact URL."""

class BadClassNameSyntax(Exception):
  """Illegal syntax for a class_name."""

class BadIssueResponse(Exception):
  """issue_response PDU with wrong number of classes or certificates."""

class NotImplementedYet(Exception):
  """Internal error -- not implemented yet."""

class BadPKCS10(Exception):
  """Bad PKCS #10 object."""

class UpstreamError(Exception):
  """Received an error from upstream."""

class ChildNotFound(Exception):
  """Could not find specified child in database."""

class BSCNotFound(Exception):
  """Could not find specified BSC in database."""

class BadSender(Exception):
  """Unexpected XML sender value."""

class ClassNameMismatch(Exception):
  """class_name does not match child context."""

class SKIMismatch(Exception):
  """SKI value in response does not match request."""

class SubprocessError(Exception):
  """Subprocess returned unexpected error."""

class BadIRDBReply(Exception):
  """Unexpected reply to IRDB query."""

class NotFound(Exception):
  """Object not found in database."""
