# $Id$

"""OID database."""

## @var oid2name
# Mapping table of OIDs to conventional string names.

oid2name = {
  (1, 2, 840, 113549, 1, 1, 11) : "sha256WithRSAEncryption",
  (1, 2, 840, 113549, 1, 1, 12) : "sha384WithRSAEncryption",
  (1, 2, 840, 113549, 1, 1, 13) : "sha512WithRSAEncryption",
  (1, 3, 6, 1, 5, 5, 7, 1, 1)   : "authorityInfoAccess",
  (1, 3, 6, 1, 5, 5, 7, 1, 11)  : "subjectInfoAccess",
  (1, 3, 6, 1, 5, 5, 7, 1, 7)   : "sbgp-ipAddrBlock",
  (1, 3, 6, 1, 5, 5, 7, 1, 8)   : "sbgp-autonomousSysNum",
  (1, 3, 6, 1, 5, 5, 7, 14, 2)  : "id-cp-ipAddr-asNumber",
  (1, 3, 6, 1, 5, 5, 7, 48, 2)  : "id-ad-caIssuers",
  (1, 3, 6, 1, 5, 5, 7, 48, 5)  : "id-ad-caRepository",
  (1, 3, 6, 1, 5, 5, 7, 48, 9)  : "id-ad-signedObjectRepository",
  (1, 3, 6, 1, 5, 5, 7, 48, 10) : "id-ad-rpkiManifest",
  (1, 3, 6, 1, 5, 5, 7, 48, 11) : "id-ad-signedObject",
  (2, 5, 29, 14)                : "subjectKeyIdentifier",
  (2, 5, 29, 15)                : "keyUsage",
  (2, 5, 29, 19)                : "basicConstraints",
  (2, 5, 29, 20)                : "cRLNumber",
  (2, 5, 29, 31)                : "cRLDistributionPoints",
  (2, 5, 29, 32)                : "certificatePolicies",
  (2, 5, 29, 35)                : "authorityKeyIdentifier",
  (2, 5, 4, 3)                  : "commonName",
}

## @var name2oid
# Mapping table of string names to OIDs

name2oid = dict((v,k) for k,v in oid2name.items())
