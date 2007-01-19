#!/bin/sh -
# $Id$

# Demo of how one could use the xmlsec package to sign and verify XML
# messages.  On FreeBSD, the xmlsec 1.x command line program is called
# "xmlsec1" to distinuish it from the old xmlsec 0.x program, which
# had a somewhat different command line syntax.  YMMV.
#
# Basic idea of the demo is to create a four level deep cert chain,
# use that to sign an XML document, then demonstrate that it verifies.

set -xe

: ${input=input.xml} ${unsigned=unsigned.xml} ${signed=signed.xml}
: ${alice=alice} ${bob=bob} ${carol=carol} ${dave=dave}
: ${xmlsec=xmlsec1}

# Some input with which to work.  Feel free to supply your own instead.

test -r $input || cat >$input <<'EOF'
  <reference anchor="RFC3779">
    <front>
      <title>X.509 Extensions for IP Addresses and AS Identifiers</title>
      <author fullname="C. Lynn" initials="C." surname="Lynn">
	<organization/>
      </author>
      <author fullname="S. Kent" initials="S." surname="Kent">
	<organization/>
      </author>
      <author fullname="K. Seo" initials="K." surname="Seo">
	<organization/>
      </author>
      <date month="June" year="2004"/>
      <keyword>allocation</keyword>
      <keyword>atrribute certificate</keyword>
      <keyword>authorization</keyword>
      <keyword>autonomous system number authorization</keyword>
      <keyword>certificate</keyword>
      <keyword>delegation</keyword>
      <keyword>internet registry</keyword>
      <keyword>ip address authorization</keyword>
      <keyword>public key infrastructure</keyword>
      <keyword>right-to-use</keyword>
      <keyword>secure allocation </keyword>
      <abstract>
	<t>This document defines two X.509 v3 certificate extensions. The
	  first binds a list of IP address blocks, or prefixes, to the
	  subject of a certificate. The second binds a list of autonomous
	  system identifiers to the subject of a certificate. These
	  extensions may be used to convey the authorization of the
	  subject to use the IP addresses and autonomous system
	  identifiers contained in the extensions. [STANDARDS TRACK] 
	</t>
      </abstract>
    </front>
    <seriesInfo name="RFC" value="3779"/>
    <format type="TXT" octets="60732" target="http://www.rfc-editor.org/rfc/rfc3779.txt"/>
    <!-- current-status PROPOSED STANDARD -->
    <!-- publication-status PROPOSED STANDARD -->
  </reference>
EOF

# Set up a simple chain of certs.

for i in $alice $bob $carol $dave
do
  test -r $i.cnf || cat >$i.cnf <<EOF

    [ req ]
    distinguished_name		= req_dn
    x509_extensions		= req_x509_ext
    prompt			= no
    default_md			= sha1

    [ req_dn ]
    CN				= Test Certificate $i

    [ req_x509_ext ]
    basicConstraints		= CA:true
    subjectKeyIdentifier	= hash
    authorityKeyIdentifier	= keyid:always

EOF

  test -r $i.key -a -r $i.req ||
  openssl req -new -newkey rsa:2048 -nodes -keyout $i.key -out $i.req -config $i.cnf

done

test -r $alice.cer || openssl x509 -req -in $alice.req -out $alice.cer -extfile $alice.cnf -extensions req_x509_ext -signkey $alice.key
test -r $bob.cer   || openssl x509 -req -in $bob.req   -out $bob.cer   -extfile $bob.cnf   -extensions req_x509_ext -CA $alice.cer -CAkey $alice.key -CAcreateserial
test -r $carol.cer || openssl x509 -req -in $carol.req -out $carol.cer -extfile $carol.cnf -extensions req_x509_ext -CA $bob.cer   -CAkey $bob.key   -CAcreateserial
test -r $dave.cer  || openssl x509 -req -in $dave.req  -out $dave.cer  -extfile $dave.cnf  -extensions req_x509_ext -CA $carol.cer -CAkey $carol.key -CAcreateserial

# The xmlsec command line tool takes most of its instructions in the
# form of an XML template.  XSLT was designed for this kind of work,
# so just use an XSL transform to wrap our input with the template.
#
# NB: The XML signature specification supports several different
# signing modes.  In theory, which one of them I get is determined by
# the template.  Documentation is a bit sparse, though, so I just went
# with the first halfway sane thing I found in the supplied examples.

test -r $unsigned ||
xsltproc --output $unsigned - $input <<'EOF'

  <xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
    <xsl:output method="xml" encoding="us-ascii" indent="yes"/>
    <xsl:template match="/">
      <Envelope xmlns="urn:envelope">
	<xsl:copy-of select="/"/>
	<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
	  <SignedInfo>
	    <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
	    <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
	    <Reference>
	      <Transforms>
		<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
	      </Transforms>
	      <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
	      <DigestValue>HjY8ilZAIEM2tBbPn5mYO1ieIX4=</DigestValue>
	    </Reference>
	  </SignedInfo>
	  <SignatureValue/>
	  <KeyInfo>
	    <X509Data>
	      <X509Certificate/>
	    </X509Data>
	  </KeyInfo>
	</Signature>
      </Envelope>
    </xsl:template>
  </xsl:stylesheet>

EOF

# Sign the template we generated.  We sign with the bottommost key,
# and include the two bottommost certs in the signed document.

test -r $signed ||
$xmlsec sign --privkey-pem $dave.key,$dave.cer,$carol.cer --output $signed $unsigned

# Verify the signed message.  We tell xmlsec to trust the root cert,
# and supply the second level cert as it's not in the signed message.
# This should be enough for xmlsec to verify the signature; removing
# any these should cause verification to fail (try it!).

$xmlsec verify --trusted-pem $alice.cer --untrusted-pem $bob.cer $signed
