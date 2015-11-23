# $Id$
#
# Copyright (C) 2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2009--2013  Internet Systems Consortium ("ISC")
# Portions copyright (C) 2006--2008  American Registry for Internet Numbers ("ARIN")
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

# pylint: disable=W0401,W0622

from ._POW import *
from ._POW import __doc__


# Set callback to let POW construct rpki.sundial.datetime objects.

from rpki.sundial import datetime as sundial_datetime
customDatetime(sundial_datetime)
del sundial_datetime


# Status code mechanism, (mostly) moved out of POW.c.

class StatusCode(object):

    def __init__(self, name, text, kind, code = None):
        assert code is None or isinstance(code, int)
        assert kind in ("good", "bad", "warn")
        self.code = code
        self.name = name
        self.text = text
        self.kind = kind

    def __str__(self):
        return self.name

    def __repr__(self):
        return "<StatusCode object \"{}\" at {}>".format(self.text, id(self))

    def __hash__(self):
        return hash(self.name)

    def __cmp__(self, other):
        return cmp(self.name, str(other))


class StatusCodeDB(object):

    def __init__(self, bad, warn, good, verification_errors):
        self._map = dict((name, StatusCode(code = code, name = name, text = text,
                                           kind = "bad" if code != 0 else "good"))
                         for code, name, text in verification_errors)
        self._map.update((k, StatusCode(name = k, text = v, kind = "bad"))
                         for k, v in bad.iteritems())
        self._map.update((k, StatusCode(name = k, text = v, kind = "warn"))
                         for k, v in warn.iteritems())
        self._map.update((k, StatusCode(name = k, text = v, kind = "good"))
                         for k, v in good.iteritems())
        for k, v in self._map.iteritems():
            setattr(self, k, v)
        self._map.update((s.code, s) for s in self._map.values() if s.code is not None)

    def all(self):
        return set(self._map.itervalues())

    def normalize(self, status):
        convert = set(s for s in status if isinstance(s, (int, str)))
        status |= set(self._map[s] for s in convert)
        status -= convert


validation_status = StatusCodeDB(
    bad = dict(
        AIA_EXTENSION_MISSING                = "AIA extension missing",
        AIA_EXTENSION_FORBIDDEN              = "AIA extension forbidden",
        AIA_URI_MISSING                      = "AIA URI missing",
        AKI_EXTENSION_ISSUER_MISMATCH        = "AKI extension issuer mismatch",
        AKI_EXTENSION_MISSING                = "AKI extension missing",
        AKI_EXTENSION_WRONG_FORMAT           = "AKI extension is wrong format",
        BAD_ASIDENTIFIERS                    = "Bad ASIdentifiers extension",
        BAD_CERTIFICATE_POLICY               = "Bad certificate policy",
        BAD_CMS_ECONTENTTYPE                 = "Bad CMS eContentType",
        BAD_CMS_SI_CONTENTTYPE               = "Bad CMS SI ContentType",
        BAD_CMS_SIGNER                       = "Bad CMS signer",
        BAD_CMS_SIGNER_INFOS                 = "Bad CMS signerInfos",
        BAD_CRL                              = "Bad CRL",
        BAD_IPADDRBLOCKS                     = "Bad IPAddrBlocks extension",
        BAD_KEY_USAGE                        = "Bad keyUsage",
        BAD_MANIFEST_DIGEST_LENGTH           = "Bad manifest digest length",
        BAD_PUBLIC_KEY                       = "Bad public key",
        BAD_ROA_ASID                         = "Bad ROA asID",
        BAD_CERTIFICATE_SERIAL_NUMBER        = "Bad certificate serialNumber",
        BAD_MANIFEST_NUMBER                  = "Bad manifestNumber",
        CERTIFICATE_BAD_SIGNATURE            = "Bad certificate signature",
        CERTIFICATE_FAILED_VALIDATION        = "Certificate failed validation",
        CMS_ECONTENT_DECODE_ERROR            = "CMS eContent decode error",
        CMS_INCLUDES_CRLS                    = "CMS includes CRLs",
        CMS_SIGNER_MISSING                   = "CMS signer missing",
        CMS_SKI_MISMATCH                     = "CMS SKI mismatch",
        CMS_VALIDATION_FAILURE               = "CMS validation failure",
        CRL_ISSUER_NAME_MISMATCH             = "CRL issuer name mismatch",
        CRL_NOT_IN_MANIFEST                  = "CRL not listed in manifest",
        CRL_NOT_YET_VALID                    = "CRL not yet valid",
        CRL_NUMBER_EXTENSION_MISSING         = "CRL number extension missing",
        CRL_NUMBER_IS_NEGATIVE               = "CRL number is negative",
        CRL_NUMBER_OUT_OF_RANGE              = "CRL number out of range",
        CRLDP_DOESNT_MATCH_ISSUER_SIA        = "CRLDP doesn't match issuer's SIA",
        CRLDP_EXTENSION_FORBIDDEN            = "CRLDP extension forbidden",
        CRLDP_EXTENSION_MISSING              = "CRLDP extension missing",
        CRLDP_URI_MISSING                    = "CRLDP URI missing",
        DISALLOWED_X509V3_EXTENSION          = "Disallowed X.509v3 extension",
        DUPLICATE_NAME_IN_MANIFEST           = "Duplicate name in manifest",
        INAPPROPRIATE_EKU_EXTENSION          = "Inappropriate EKU extension",
        MALFORMED_AIA_EXTENSION              = "Malformed AIA extension",
        MALFORMED_SIA_EXTENSION              = "Malformed SIA extension",
        MALFORMED_BASIC_CONSTRAINTS          = "Malformed basicConstraints",
        MALFORMED_TRUST_ANCHOR               = "Malformed trust anchor",
        MALFORMED_CADIRECTORY_URI            = "Malformed caDirectory URI",
        MALFORMED_CRLDP_EXTENSION            = "Malformed CRDLP extension",
        MALFORMED_CRLDP_URI                  = "Malformed CRDLP URI",
        MALFORMED_ROA_ADDRESSFAMILY          = "Malformed ROA addressFamily",
        MALFORMED_TAL_URI                    = "Malformed TAL URI",
        MANIFEST_CAREPOSITORY_MISMATCH       = "Manifest caRepository mismatch",
        MANIFEST_INTERVAL_OVERRUNS_CERT      = "Manifest interval overruns certificate",
        MANIFEST_LISTS_MISSING_OBJECT        = "Manifest lists missing object",
        MANIFEST_NOT_YET_VALID               = "Manifest not yet valid",
        MANIFEST_EE_REVOKED                  = "Manifest EE certificate revoked",
        MISSING_RESOURCES                    = "Missing resources",
        NONCONFORMANT_ASN1_TIME_VALUE        = "Nonconformant ASN.1 time value",
        NONCONFORMANT_PUBLIC_KEY_ALGORITHM   = "Nonconformant public key algorithm",
        NONCONFORMANT_SIGNATURE_ALGORITHM    = "Nonconformant signature algorithm",
        NONCONFORMANT_DIGEST_ALGORITHM       = "Nonconformant digest algorithm",
        NONCONFORMANT_CERTIFICATE_UID        = "Nonconformant certificate UID",
        OBJECT_REJECTED                      = "Object rejected",
        RFC3779_INHERITANCE_REQUIRED         = "RFC 3779 inheritance required",
        ROA_CONTAINS_BAD_AFI_VALUE           = "ROA contains bad AFI value",
        ROA_MAX_PREFIXLEN_TOO_SHORT          = "ROA maxPrefixlen too short",
        ROA_RESOURCE_NOT_IN_EE               = "ROA resource not in EE",
        ROA_RESOURCES_MALFORMED              = "ROA resources malformed",
        RSYNC_TRANSFER_FAILED                = "rsync transfer failed",
        RSYNC_TRANSFER_TIMED_OUT             = "rsync transfer timed out",
        SAFI_NOT_ALLOWED                     = "SAFI not allowed",
        SIA_CADIRECTORY_URI_MISSING          = "SIA caDirectory URI missing",
        SIA_EXTENSION_FORBIDDEN              = "SIA extension forbidden",
        SIA_EXTENSION_MISSING                = "SIA extension missing",
        SIA_MANIFEST_URI_MISSING             = "SIA manifest URI missing",
        SKI_EXTENSION_MISSING                = "SKI extension missing",
        SKI_PUBLIC_KEY_MISMATCH              = "SKI public key mismatch",
        TRUST_ANCHOR_KEY_MISMATCH            = "Trust anchor key mismatch",
        TRUST_ANCHOR_WITH_CRLDP              = "Trust anchor can't have CRLDP",
        UNKNOWN_AFI                          = "Unknown AFI",
        UNKNOWN_OPENSSL_VERIFY_ERROR         = "Unknown OpenSSL verify error",
        UNREADABLE_TRUST_ANCHOR              = "Unreadable trust anchor",
        UNREADABLE_TRUST_ANCHOR_LOCATOR      = "Unreadable trust anchor locator",
        WRONG_OBJECT_VERSION                 = "Wrong object version",
        OBJECT_NOT_FOUND                     = "Object not found"),

    warn = dict(
        AIA_DOESNT_MATCH_ISSUER              = "AIA doesn't match issuer",
        BACKUP_THISUPDATE_NEWER_THAN_CURRENT = "Backup thisUpdate newer than current",
        BACKUP_NUMBER_HIGHER_THAN_CURRENT    = "Backup number higher than current",
        BAD_THISUPDATE                       = "Bad CRL thisUpdate",
        BAD_CMS_SI_SIGNED_ATTRIBUTES         = "Bad CMS SI signed attributes",
        BAD_SIGNED_OBJECT_URI                = "Bad signedObject URI",
        CRLDP_NAMES_NEWER_CRL                = "CRLDP names newer CRL",
        DIGEST_MISMATCH                      = "Digest mismatch",
        EE_CERTIFICATE_WITH_1024_BIT_KEY     = "EE certificate with 1024 bit key",
        ISSUER_USES_MULTIPLE_CRLDP_VALUES    = "Issuer uses multiple CRLDP values",\
        MULTIPLE_RSYNC_URIS_IN_EXTENSION     = "Multiple rsync URIs in extension",
        NONCONFORMANT_ISSUER_NAME            = "Nonconformant X.509 issuer name",
        NONCONFORMANT_SUBJECT_NAME           = "Nonconformant X.509 subject name",
        POLICY_QUALIFIER_CPS                 = "Policy Qualifier CPS",
        RSYNC_PARTIAL_TRANSFER               = "rsync partial transfer",
        RSYNC_TRANSFER_SKIPPED               = "rsync transfer skipped",
        SIA_EXTENSION_MISSING_FROM_EE        = "SIA extension missing from EE",
        SKIPPED_BECAUSE_NOT_IN_MANIFEST      = "Skipped because not in manifest",
        STALE_CRL_OR_MANIFEST                = "Stale CRL or manifest",
        TAINTED_BY_STALE_CRL                 = "Tainted by stale CRL",
        TAINTED_BY_STALE_MANIFEST            = "Tainted by stale manifest",
        TAINTED_BY_NOT_BEING_IN_MANIFEST     = "Tainted by not being in manifest",
        TRUST_ANCHOR_NOT_SELF_SIGNED         = "Trust anchor not self-signed",
        TRUST_ANCHOR_SKIPPED                 = "Trust anchor skipped",
        UNKNOWN_OBJECT_TYPE_SKIPPED          = "Unknown object type skipped",
        URI_TOO_LONG                         = "URI too long",
        WRONG_CMS_SI_SIGNATURE_ALGORITHM     = "Wrong CMS SI signature algorithm",
        WRONG_CMS_SI_DIGEST_ALGORITHM        = "Wrong CMS SI digest algorithm"),

    good = dict(
        NON_RSYNC_URI_IN_EXTENSION           = "Non-rsync URI in extension",
        OBJECT_ACCEPTED                      = "Object accepted",
        RECHECKING_OBJECT                    = "Rechecking object",
        RSYNC_TRANSFER_SUCCEEDED             = "rsync transfer succeeded",
        VALIDATION_OK                        = "OK"),

    verification_errors = _POW.getVerificationErrors())
