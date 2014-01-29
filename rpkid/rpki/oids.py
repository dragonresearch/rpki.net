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
OID database.
"""

def defoid(name, *numbers):
  """
  Define a new OID, including adding it to a few dictionaries and
  making an entry for it in the rpki.oids module symbol table, so
  other code can refer to it as an ordinary symbol.
  """

  assert all(isinstance(n, (int, long)) for n in numbers)

  dotted = ".".join(str(n) for n in numbers)
  name_ = name.replace("-", "_")

  assert name_ not in globals()

  global oid2name
  oid2name[numbers] = name

  globals()[name_] = dotted

  global dotted2name
  dotted2name[dotted] = name

  global dotted2name_
  dotted2name_[dotted] = name_

  global name2dotted
  name2dotted[name] = dotted
  name2dotted[name_] = dotted


## @var oid2name
# Mapping table of OIDs to conventional string names.

oid2name = {
  (1, 2, 840, 10045, 4, 3, 2)           : "ecdsa-with-SHA256",
  (1, 2, 840, 113549, 1, 1, 11)         : "sha256WithRSAEncryption",
  (1, 2, 840, 113549, 1, 1, 12)         : "sha384WithRSAEncryption",
  (1, 2, 840, 113549, 1, 1, 13)         : "sha512WithRSAEncryption",
  (1, 2, 840, 113549, 1, 7,  1)         : "id-data",
  (1, 2, 840, 113549, 1, 9, 16)         : "id-smime",
  (1, 2, 840, 113549, 1, 9, 16, 1)      : "id-ct",
  (1, 2, 840, 113549, 1, 9, 16, 1, 24)  : "id-ct-routeOriginAttestation",
  (1, 2, 840, 113549, 1, 9, 16, 1, 26)  : "id-ct-rpkiManifest",
  (1, 2, 840, 113549, 1, 9, 16, 1, 28)  : "id-ct-xml",
  (1, 2, 840, 113549, 1, 9, 16, 1, 35)  : "id-ct-rpkiGhostbusters",
  (1, 3, 6, 1, 5, 5, 7, 1, 1)           : "authorityInfoAccess",
  (1, 3, 6, 1, 5, 5, 7, 1, 11)          : "subjectInfoAccess",
  (1, 3, 6, 1, 5, 5, 7, 1, 7)           : "sbgp-ipAddrBlock",
  (1, 3, 6, 1, 5, 5, 7, 1, 8)           : "sbgp-autonomousSysNum",
  (1, 3, 6, 1, 5, 5, 7, 14, 2)          : "id-cp-ipAddr-asNumber",
  (1, 3, 6, 1, 5, 5, 7, 3, 666)         : "id-kp-bgpsec-router",        # {id-kp, 666} -- Real value not known yet
  (1, 3, 6, 1, 5, 5, 7, 48, 10)         : "id-ad-rpkiManifest",
  (1, 3, 6, 1, 5, 5, 7, 48, 11)         : "id-ad-signedObject",
  (1, 3, 6, 1, 5, 5, 7, 48, 2)          : "id-ad-caIssuers",
  (1, 3, 6, 1, 5, 5, 7, 48, 5)          : "id-ad-caRepository",
  (1, 3, 6, 1, 5, 5, 7, 48, 9)          : "id-ad-signedObjectRepository",
  (2, 16, 840, 1, 101, 3, 4, 2, 1)      : "id-sha256",
  (2, 5, 29, 14)                        : "subjectKeyIdentifier",
  (2, 5, 29, 15)                        : "keyUsage",
  (2, 5, 29, 19)                        : "basicConstraints",
  (2, 5, 29, 20)                        : "cRLNumber",
  (2, 5, 29, 31)                        : "cRLDistributionPoints",
  (2, 5, 29, 32)                        : "certificatePolicies",
  (2, 5, 29, 35)                        : "authorityKeyIdentifier",
  (2, 5, 29, 37)                        : "extendedKeyUsage",
  (2, 5, 4, 10)                         : "organizationName",
  (2, 5, 4, 11)                         : "organizationalUnitName",
  (2, 5, 4, 3)                          : "commonName",
  (2, 5, 4, 5)                          : "serialNumber",
  (2, 5, 4, 6)                          : "countryName",
  (2, 5, 4, 7)                          : "localityName",
  (2, 5, 4, 8)                          : "stateOrProvinceName",
  (2, 5, 4, 9)                          : "streetAddress",
}

## @var name2oid
# Mapping table of string names to OIDs

name2oid = dict((v, k) for k, v in oid2name.items())

def safe_name2oid(name):
  """
  Map name to OID, also parsing numeric (dotted decimal) format.
  """

  try:
    return name2oid[name]    
  except KeyError:
    fields = name.split(".")
    if all(field.isdigit() for field in fields):
      return tuple(int(field) for field in fields)
    raise

def safe_oid2name(oid):
  """
  Map OID to name.  If we have no mapping, generate numeric (dotted
  decimal) format.
  """

  try:
    return oid2name[oid]
  except KeyError:
    return oid2dotted(oid)

def oid2dotted(oid):
  """
  Convert OID to numeric (dotted decimal) format.
  """

  return ".".join(str(field) for field in oid)

def dotted2oid(dotted):
  """
  Convert dotted decimal format to OID tuple.
  """
  
  fields = dotted.split(".")
  if all(field.isdigit() for field in fields):
    return tuple(int(field) for field in fields)
  raise ValueError("%r is not a dotted decimal OID" % dotted)

def safe_name2dotted(name):
  """
  Convert name to dotted decimal format.
  """

  return oid2dotted(safe_name2oid(name))

def safe_dotted2name(dotted):
  """
  Convert dotted decimal to name if we know one,
  otherwise just return dotted.
  """

  try:
    return oid2name[dotted2oid(dotted)]
  except KeyError:
    return dotted
