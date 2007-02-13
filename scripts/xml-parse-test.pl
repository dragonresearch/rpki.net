# $Id$
#
# Test of XML::Simple as a tool for encoding and decoding
#
#   http://mirin.apnic.net/resourcecerts/wiki/index.php/IR-ISP_Definition

eval 'exec perl -w -S $0 ${1+"$@"}'
    if 0;

use strict;
use XML::Simple;
use Data::Dumper;

my @xml = ('
    <message version="1">
        <header  sender="sender name"
                 recipient = "recipient name"
                 msg_ref="reference" />
        <resource_class_list_query ca="ca_name" />
    </message>
','
    <message version="1">
        <header  sender="sender name"
                 recipient = "recipient name"
                 msg_ref="reference" />
        <list_class ca="ca_name"
                     cert_url="url"
                     cert_ski="g(ski)"
                     cert_serial="serial"
                     cert_aki="g(aki)"
                     status="keyword" />
        <list_class ca="ca_name"
                     cert_url="url"
                     cert_ski="g(ski)"
                     cert_serial="serial"
                     cert_aki="g(aki)"
                     status="keyword" />
        <!-- [repeated for each active class where the ISP has resources]  -->
    </message>
','
    <message version="1">
        <header  sender="sender name"
                 recipient = "recipient name"
                 msg_ref="reference" />
        <issue_request_class ca="ca_name"
                              subca="subca_ident">
            [Certificate request]
        </issue_request_class>
    </message>
','
    <message version="1">
        <header  sender="sender name"
                 recipient = "recipient name"
                 msg_ref="reference" />
        <certificate ca="ca_name"
                     subca="subca_ident"
                     cert_url="url"
                     cert_ski="g(ski)"
                     cert_serial="serial"
                     cert_aki="g(aki)">
            [certificate]
        </certificate>
    </message>
','
    <message version="1">
        <header  sender="sender name"
                 recipient = "recipient name"
                 msg_ref="reference" />
        <revoke_request_class ca="ca_name"
                               cert_ski="g(ski)" />
    </message>
','
    <message version="1">
        <header  sender="sender name"
                 recipient = "recipient name"
                 msg_ref="reference" />
        <revoke_response_class ca="ca_name"
                               cert_ski="g(ski)" />
    </message>
','
    <message version="1">
        <header  sender="sender name"
                 recipient = "recipient name"
                 msg_ref="reference" />
        <status code="reason code">
            [Readable text]
        </status>
    </message>
');    

my $xs = XML::Simple->new(KeepRoot => 1, Forcearray => [qw(list_class)]);

for my $xml (@xml) {
    my $x = $xs->XMLin($xml);
    my $t = $xs->XMLout($x);
    print("\n###\n", $xml, "\n", Dumper($x), "\n", $t);
}
