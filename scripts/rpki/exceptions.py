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

class MultipleROAsFound(Exception):
  """Found multiple ROAs in a relationship that should be one-to-one."""

class CMSVerificationFailed(Exception):
  """Verification of a CMS message failed."""

class HTTPRequestFailed(Exception):
  """HTTP request failed."""

class DERObjectConversionError(Exception):
  """Error trying to convert a DER-based object from one representation to another."""

class NotACertificateChain(Exception):
  """Certificates don't form a proper chain."""
