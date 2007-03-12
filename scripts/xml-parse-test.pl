# $Id$
#
# Test of XML::Simple as a tool for encoding and decoding
#
#   http://mirin.apnic.net/resourcecerts/wiki/index.php/IR-ISP_Definition

# CMS wrapper for this (not yet written) would look something like:
#
# openssl smime -sign -nodetach -outform DER -in foo.xml -out foo.cms \
#		-signer foo.cer -inkey foo.key
#
# openssl smime -verify -CApath . -inform DER -in foo.cms -out foo.xml

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
        <issue_request_class ca="ca_name">
            [Certificate request]
        </issue_request_class>
    </message>
','
    <message version="1">
        <header  sender="sender name"
                 recipient = "recipient name"
                 msg_ref="reference" />
        <certificate ca="ca_name"
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

my $xs = XML::Simple->new(KeepRoot => 1,
			  ForceArray => [qw(list_class)],
			  KeyAttr => [qw(header)],
 			  NormalizeSpace => 2);

for my $xml (@xml) {
    my $x = $xs->XMLin($xml);
    my $t = $xs->XMLout($x);
    print("\n###\n", $xml, "\n", Dumper($x), "\n", $t);
}

__END__

# Test of IPC::Open2

# CMS wrapper for this (not yet written) would look something like:
#
# openssl smime -sign -nodetach -outform DER -in foo.xml -out foo.cms \
#		-signer foo.cer -inkey foo.key
#
# openssl smime -verify -CApath . -inform DER -in foo.cms -out foo.xml

eval 'exec perl -w -S $0 ${1+"$@"}'
    if 0;

use strict;
use IPC::Open2;

my $xml = '
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
';

sub run2 {
    my $arg = shift;
    my $i;
    my $o;
    my $pid = open2($o, $i, @_)
	or die("Couldn't run @_");
    print($i $arg)
	or die("Couldn't write to @_");
    close($i)
	or die("Couldn't close @_");
    my @res = <$o>;
    waitpid($pid, 0)
	or die("Couldn't reap @_");
    return @res;
}

my $p7b = "-----BEGIN PKCS7-----\n";
my $p7e = "-----END PKCS7-----\n";

sub encode {
    my $arg = shift;
    my @res = run2($arg, qw(openssl smime -sign -nodetach -outform PEM -signer foo.cer -inkey foo.key));
    die("Missing PKCS7 markers")
	unless $res[0] eq $p7b && $res[@res-1] eq $p7e;
    return join('', @res[1..@res-2]);
}

sub decode {
    my $arg = shift;
    my @res = run2($p7b . $arg . $p7e, qw(openssl smime -verify -CApath . -inform PEM));
    return join('', @res);
}

print("1:\n", $xml, "\n");

my $cms = encode($xml);

print("2:\n", $cms, "\n");

print("3:\n", decode($cms), "\n");
