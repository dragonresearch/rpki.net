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

This used to be fairly complicated, with multiple representations and
a collection of conversion functions, but now it is very simple:

- We represent OIDs as Python strings, holding the dotted-decimal
  form of an OID.  Nothing but decimal digits and "." is legal.
  This is compatible with the format that rpki.POW uses.

- We define symbols in this module whose values are OIDs.

That's pretty much it.  There's a bit of code at the end which checks
the syntax of the defined strings and provides a pretty-print function
for the rare occasion when we need to print an OID, but other than
that this is just a collection of symbolic names for text strings.
"""

ecdsa_with_SHA256               = "1.2.840.10045.4.3.2"
sha256WithRSAEncryption         = "1.2.840.113549.1.1.11"
sha384WithRSAEncryption         = "1.2.840.113549.1.1.12"
sha512WithRSAEncryption         = "1.2.840.113549.1.1.13"
id_data                         = "1.2.840.113549.1.7.1"
id_smime                        = "1.2.840.113549.1.9.16"
id_ct                           = "1.2.840.113549.1.9.16.1"
id_ct_routeOriginAttestation    = "1.2.840.113549.1.9.16.1.24"
id_ct_rpkiManifest              = "1.2.840.113549.1.9.16.1.26"
id_ct_xml                       = "1.2.840.113549.1.9.16.1.28"
id_ct_rpkiGhostbusters          = "1.2.840.113549.1.9.16.1.35"
authorityInfoAccess             = "1.3.6.1.5.5.7.1.1"
subjectInfoAccess               = "1.3.6.1.5.5.7.1.11"
sbgp_ipAddrBlock                = "1.3.6.1.5.5.7.1.7"
sbgp_autonomousSysNum           = "1.3.6.1.5.5.7.1.8"
id_cp_ipAddr_asNumber           = "1.3.6.1.5.5.7.14.2"
id_kp_bgpsec_router             = "1.3.6.1.5.5.7.3.666"         # {id_kp, 666} -- Real value not known yet
id_ad_rpkiManifest              = "1.3.6.1.5.5.7.48.10"
id_ad_signedObject              = "1.3.6.1.5.5.7.48.11"
id_ad_caIssuers                 = "1.3.6.1.5.5.7.48.2"
id_ad_caRepository              = "1.3.6.1.5.5.7.48.5"
id_ad_signedObjectRepository    = "1.3.6.1.5.5.7.48.9"
id_sha256                       = "2.16.840.1.101.3.4.2.1"
subjectKeyIdentifier            = "2.5.29.14"
keyUsage                        = "2.5.29.15"
basicConstraints                = "2.5.29.19"
cRLNumber                       = "2.5.29.20"
cRLDistributionPoints           = "2.5.29.31"
certificatePolicies             = "2.5.29.32"
authorityKeyIdentifier          = "2.5.29.35"
extendedKeyUsage                = "2.5.29.37"
organizationName                = "2.5.4.10"
organizationalUnitName          = "2.5.4.11"
commonName                      = "2.5.4.3"
serialNumber                    = "2.5.4.5"
countryName                     = "2.5.4.6"
localityName                    = "2.5.4.7"
stateOrProvinceName             = "2.5.4.8"
streetAddress                   = "2.5.4.9"

# Make sure all symbols exported so far look like OIDs, and build a
# dictionary to use when pretty-printing.

_oid2name = {}

for _sym in dir():
  if not _sym.startswith("_"):
    _val = globals()[_sym]
    if not isinstance(_val, str) or not all(_v.isdigit() for _v in _val.split(".")):
      raise ValueError("Bad OID definition: %s = %r" % (_sym, _val))
    _oid2name[_val] = _sym.replace("_", "-")

del _sym
del _val

def oid2name(oid):
  """
  Translate an OID into a string suitable for printing.
  """

  if not isinstance(oid, (str, unicode)) or not all(o.isdigit() for o in oid.split(".")):
    raise ValueError("Parameter does not look like an OID string: " + repr(oid))

  return _oid2name.get(oid, oid)
