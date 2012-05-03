"""
Exception definitions for RPKI modules.

$Id$

Copyright (C) 2009--2010  Internet Systems Consortium ("ISC")

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

Portions copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")

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

class RPKI_Exception(Exception):
  """
  Base class for RPKI exceptions.
  """

class NotInDatabase(RPKI_Exception):
  """
  Lookup failed for an object expected to be in the database.
  """

class BadURISyntax(RPKI_Exception):
  """
  Illegal syntax for a URI.
  """

class BadStatusCode(RPKI_Exception):
  """
  Unrecognized protocol status code.
  """

class BadQuery(RPKI_Exception):
  """
  Unexpected protocol query.
  """

class DBConsistancyError(RPKI_Exception):
  """
  Found multiple matches for a database query that shouldn't ever
  return that.
  """

class CMSVerificationFailed(RPKI_Exception):
  """
  Verification of a CMS message failed.
  """

class HTTPRequestFailed(RPKI_Exception):
  """
  HTTP request failed.
  """

class DERObjectConversionError(RPKI_Exception):
  """
  Error trying to convert a DER-based object from one representation
  to another.
  """

class NotACertificateChain(RPKI_Exception):
  """
  Certificates don't form a proper chain.
  """

class BadContactURL(RPKI_Exception):
  """
  Error trying to parse contact URL.
  """

class BadClassNameSyntax(RPKI_Exception):
  """
  Illegal syntax for a class_name.
  """

class BadIssueResponse(RPKI_Exception):
  """
  issue_response PDU with wrong number of classes or certificates.
  """

class NotImplementedYet(RPKI_Exception):
  """
  Internal error -- not implemented yet.
  """

class BadPKCS10(RPKI_Exception):
  """
  Bad PKCS #10 object.
  """

class UpstreamError(RPKI_Exception):
  """
  Received an error from upstream.
  """

class ChildNotFound(RPKI_Exception):
  """
  Could not find specified child in database.
  """

class BSCNotFound(RPKI_Exception):
  """
  Could not find specified BSC in database.
  """

class BadSender(RPKI_Exception):
  """
  Unexpected XML sender value.
  """

class ClassNameMismatch(RPKI_Exception):
  """
  class_name does not match child context.
  """

class ClassNameUnknown(RPKI_Exception):
  """
  Unknown class_name.
  """

class SKIMismatch(RPKI_Exception):
  """
  SKI value in response does not match request.
  """

class SubprocessError(RPKI_Exception):
  """
  Subprocess returned unexpected error.
  """

class BadIRDBReply(RPKI_Exception):
  """
  Unexpected reply to IRDB query.
  """

class NotFound(RPKI_Exception):
  """
  Object not found in database.
  """

class MustBePrefix(RPKI_Exception):
  """
  Resource range cannot be expressed as a prefix.
  """

class TLSValidationError(RPKI_Exception):
  """
  TLS certificate validation error.
  """

class MultipleTLSEECert(TLSValidationError):
  """
  Received more than one TLS EE certificate.
  """

class ReceivedTLSCACert(TLSValidationError):
  """
  Received CA certificate via TLS.
  """

class WrongEContentType(RPKI_Exception):
  """
  Received wrong CMS eContentType.
  """
  
class EmptyPEM(RPKI_Exception):
  """
  Couldn't find PEM block to convert.
  """

class UnexpectedCMSCerts(RPKI_Exception):
  """
  Received CMS certs when not expecting any.
  """

class UnexpectedCMSCRLs(RPKI_Exception):
  """
  Received CMS CRLs when not expecting any.
  """

class MissingCMSEEcert(RPKI_Exception):
  """
  Didn't receive CMS EE cert when expecting one.
  """

class MissingCMSCRL(RPKI_Exception):
  """
  Didn't receive CMS CRL when expecting one.
  """

class UnparsableCMSDER(RPKI_Exception):
  """
  Alleged CMS DER wasn't parsable.
  """

class CMSCRLNotSet(RPKI_Exception):
  """
  CMS CRL has not been configured.
  """

class ServerShuttingDown(RPKI_Exception):
  """
  Server is shutting down.
  """

class NoActiveCA(RPKI_Exception):
  """
  No active ca_detail for specified class.
  """

class BadClientURL(RPKI_Exception):
  """
  URL given to HTTP client does not match profile.
  """

class ClientNotFound(RPKI_Exception):
  """
  Could not find specified client in database.
  """

class BadExtension(RPKI_Exception):
  """
  Forbidden X.509 extension.
  """

class ForbiddenURI(RPKI_Exception):
  """
  Forbidden URI, does not start with correct base URI.
  """

class HTTPClientAborted(RPKI_Exception):
  """
  HTTP client connection closed while in request-sent state.
  """

class BadPublicationReply(RPKI_Exception):
  """
  Unexpected reply to publication query.
  """

class DuplicateObject(RPKI_Exception):
  """
  Attempt to create an object that already exists.
  """

class EmptyROAPrefixList(RPKI_Exception):
  """
  Can't create ROA with an empty prefix list.
  """

class NoCoveringCertForROA(RPKI_Exception):
  """
  Couldn't find a covering certificate to generate ROA.
  """

class BSCNotReady(RPKI_Exception):
  """
  BSC not yet in a usable state, signing_cert not set.
  """

class HTTPUnexpectedState(RPKI_Exception):
  """
  HTTP event occurred in an unexpected state.
  """

class HTTPBadVersion(RPKI_Exception):
  """
  HTTP couldn't parse HTTP version.
  """

class HandleTranslationError(RPKI_Exception):
  """
  Internal error translating protocol handle -> SQL id.
  """

class NoObjectAtURI(RPKI_Exception):
  """
  No object published at specified URI.
  """

class CMSContentNotSet(RPKI_Exception):
  """
  Inner content of a CMS_object has not been set.  If object is known
  to be valid, the .extract() method should be able to set the
  content; otherwise, only the .verify() method (which checks
  signatures) is safe.
  """

class HTTPTimeout(RPKI_Exception):
  """
  HTTP connection timed out.
  """

class BadIPResource(RPKI_Exception):
  """
  Parse failure for alleged IP resource string.
  """

class BadROAPrefix(RPKI_Exception):
  """
  Parse failure for alleged ROA prefix string.
  """

class CommandParseFailure(RPKI_Exception):
  """
  Failed to parse command line.
  """

class CMSCertHasExpired(RPKI_Exception):
  """
  CMS certificate has expired.
  """

class TrustedCMSCertHasExpired(RPKI_Exception):
  """
  Trusted CMS certificate has expired.
  """

class MultipleCMSEECert(RPKI_Exception):
  """
  Can't have more than one CMS EE certificate in validation chain.
  """

class ResourceOverlap(RPKI_Exception):
  """
  Overlapping resources in resource_set.
  """
