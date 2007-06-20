# $Id$
#
# Test of XML::Simple as a tool for encoding and decoding

eval 'exec perl -w -S $0 ${1+"$@"}'
    if 0;

use strict;
use XML::Simple;
use Data::Dumper;
use IPC::Open2;

my %opt;

if (0) {
    use Getopt::Long;
    my $usage = "Use The Source, Luke";
    die($usage)
	unless GetOptions(\%opt, qw(encode! decode! schema=s key=s cert=s dir=s))
	and $opt{encode} + $opt{decode} == 1;
    die($usage)
	if $opt{encode} and !$opt{cert} || !$opt{key};
    die($usage)
	if $opt{decode} and !$opt{schema} || !$opt{dir};
} else {
    $opt{dir}	 = "biz-certs";
    $opt{cert}	 = "biz-certs/Alice-EE.cer";
    $opt{key}	 = "biz-certs/Alice-EE.key";
    $opt{schema} = "up-down-schema.rng";
}

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
    local $/;
    my $res = <$o>;
    waitpid($pid, 0)
	or die("Couldn't reap @_");
    return $res;
}

sub encode {
    my $arg = shift;
    my $cer = shift;
    my $key = shift;
    return run2($arg, qw(openssl smime -sign -nodetach -outform PEM -signer), $cer, q(-inkey), $key);
}

sub decode {
    my $arg = shift;
    my $dir = shift;
    return run2($arg, qw(openssl smime -verify -inform PEM -CApath), $dir);
}

sub relaxng {
    my $xml = shift;
    my $schema = shift;
    open(F, "| xmllint --relaxng $schema - 2>&1") or die;
    print(F $xml) or die;
    return close(F);
}

my $xs = XML::Simple->new(KeepRoot => 1,
			  ForceArray => [qw(list_class)],
			  KeyAttr => [qw(header)],
 			  NormalizeSpace => 2);



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

for my $xml (@xml) {
    print("1:\n", $xml, "\n");
    print("2:\n", Dumper($xs->XMLin($xml)), "\n");
    print("3:\n");
    my $cms = encode($xml, $opt{cert}, $opt{key});
    print($cms, "\n");
    print("4:\n");
    $xml = decode($cms, $opt{dir});
    print($xml, "\n");
    print("5:\n", Dumper($xs->XMLin($xml)), "\n");
    print("6:\n");
    relaxng($xml, $opt{schema});
    print("\n");

#   my $x = $xs->XMLin($xml);
#   my $t = $xs->XMLout($x);
#   print("\n###\n", $xml, "\n", Dumper($x), "\n", $t);
}
