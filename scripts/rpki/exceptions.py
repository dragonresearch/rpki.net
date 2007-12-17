# $Id$

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
