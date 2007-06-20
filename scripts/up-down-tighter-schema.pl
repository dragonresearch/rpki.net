# $Id$
#
# Trivial Perl script to generate a RelaxNG (Compact Syntax) Schema
# for RPKI up-down protocol.  This is based on the schema in the APNIC
# Wiki, but has much tighter constraints on a number of fields.  It's
# a Perl script to work around the lack of a mechanism for reusing
# restrictions in a RelaxNG schema.
#
# libxml2 (including xmllint) only groks the XML syntax of RelaxNG, so
# run the output of this script through a converter like trang to get
# XML syntax.

# Note that the regexps here are RelaxNG, not Perl, slightly different.

my $as		= '([0-9]+|[0-9]+-[0-9]+)';
my $as_set	= "(${as}(,${as})*)?";

my $octet	= '([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])';
my $ipv4	= "(${octet}\\.){3}${octet}";
my $ipv4p	= "(${ipv4}/([0-9]|[12][0-9]|3[0-2]))";
my $ipv4r	= "${ipv4}-${ipv4}";
my $ipv4pr	= "(${ipv4p}|${ipv4r})";
my $ipv4_set	= "(${ipv4pr}(,${ipv4pr})*)?";

my $nibble	= '(0|[1-9a-fA-F][0-9a-fA-F]{0,3})';
my $ipv6	= "(::|(${nibble}:){0,7}(:|${nibble}))";
my $ipv6p	= "(${ipv6}/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))";
my $ipv6r	= "${ipv6}-${ipv6}";
my $ipv6pr	= "(${ipv6r}|${ipv6p})";
my $ipv6_set	= "(${ipv6pr}(,${ipv6pr})*)?";

my $rnc = qq{# \$Id\$
# Automatically generated from $0

     default namespace = "http://www.apnic.net/specs/rescerts/up-down/"

     grammar {
       start = element message {
         attribute version   { xsd:positiveInteger { maxInclusive="1" } },
         attribute sender    { xsd:token { maxLength="1024" } },
         attribute recipient { xsd:token { maxLength="1024" } },
         attribute msg_ref   { xsd:positiveInteger { maxInclusive="999999999999999" } },
         payload
       }

       payload |= attribute type { "list" }, list_request
       payload |= attribute type { "list_response"}, list_response
       payload |= attribute type { "issue" }, issue_request
       payload |= attribute type { "issue_response"}, issue_response
       payload |= attribute type { "revoke" }, revoke_request
       payload |= attribute type { "revoke_response"}, revoke_response
       payload |= attribute type { "error_response"}, error_response

       list_request = empty
       list_response = class*

       class = element class {
         attribute class_name { xsd:token { maxLength="1024" } },
         attribute cert_url { xsd:anyURI { maxLength="1024" } },
         attribute cert_ski { xsd:token { maxLength="1024" } },
         attribute resource_set_as { xsd:string { maxLength="512000" pattern="${as_set}" } },
         attribute resource_set_ipv4 { xsd:string { maxLength="512000" pattern="${ipv4_set}" } },
         attribute resource_set_ipv6 { xsd:string { maxLength="512000" pattern="${ipv6_set}" } },
         attribute suggested_sia_head { xsd:anyURI { maxLength="1024" } }?,
         element certificate {
           attribute cert_url { xsd:anyURI { maxLength="1024" } },
           attribute cert_ski { xsd:token { maxLength="1024" } },
           attribute cert_aki { xsd:token { maxLength="1024" } },
           attribute cert_serial { xsd:positiveInteger },
           attribute resource_set_as { xsd:string { maxLength="512000" pattern="${as_set}" } },
           attribute resource_set_ipv4 { xsd:string { maxLength="512000" pattern="${ipv4_set}" } },
           attribute resource_set_ipv6 { xsd:string { maxLength="512000" pattern="${ipv6_set}" } },
           attribute req_resource_set_as { xsd:string { maxLength="512000" pattern="${as_set}" } }?,
           attribute req_resource_set_ipv4 { xsd:string { maxLength="512000" pattern="${ipv4_set}" } }?,
           attribute req_resource_set_ipv6 { xsd:string { maxLength="512000" pattern="${ipv6_set}" } }?,
           attribute status { "undersize" | "match" | "oversize" },
           xsd:base64Binary { maxLength="512000" }
         }*,
         element issuer { xsd:base64Binary { maxLength="512000" } }
       }

       issue_request = element request {
         attribute class_name { xsd:token { maxLength="1024" } },
         attribute req_resource_set_as { xsd:string { maxLength="512000" pattern="${as_set}" } }?,
         attribute req_resource_set_ipv4 { xsd:string { maxLength="512000" pattern="${ipv4_set}" } }?,
         attribute req_resource_set_ipv6 { xsd:string { maxLength="512000" pattern="${ipv6_set}" } }?,
         xsd:base64Binary { maxLength="512000" }
       }
       issue_response = class

       revoke_request = revocation
       revoke_response = revocation

       revocation = element key {
         attribute class_name { xsd:token { maxLength="1024" } },
         attribute ski { xsd:token { maxLength="1024" } }
       }

       error_response =
         element status { 
	    "1101" |	# Message too old
	    "1102" |	# msg_ref value is invalid
	    "1103" |	# out of order msg_ref value
	    "1104" |	# version number error
	    "1105" |	# unrecognised request type
	    "1201" |	# request - no such resource class
	    "1202" |	# request - no resources allocated in resource class
	    "1203" |	# request - badly formed certificate request
	    "1301" |	# revoke - no such resource class
	    "1302" |	# revoke - no such key
	    "2001" 	# Internal Server Error - Request not performed
         },
         element last_msg_processed { xsd:positiveInteger { maxInclusive="999999999999999" } }?,
         element description { attribute xml:lang { xsd:language }, xsd:string { maxLength="1024" } }?
     }
};

$_ = $0;
s/\.pl$//;

open(F, ">", "$_.rnc") or die;
print(F $rnc) or die;
close(F) or die;
exec("trang", "$_.rnc", "$_.rng") or die;

# Local Variables:
# compile-command: "perl up-down-tighter-schema.pl"
# End:
