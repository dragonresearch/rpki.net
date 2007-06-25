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
    $opt{schema} = "up-down-medium-schema.rng";
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



my @xml = ('<?xml version="1.0" encoding="UTF-8"?>
<message xmlns="http://www.apnic.net/specs/rescerts/up-down/"
         version="1"
	 sender="sender name"
	 recipient="recipient name"
	 msg_ref="42"
	 type="error_response">
    <status>2001</status>
    <last_msg_processed>17</last_msg_processed>
    <description xml:lang="en-US">[Readable text]</description>
</message>
','<?xml version="1.0" encoding="UTF-8"?>
<message xmlns="http://www.apnic.net/specs/rescerts/up-down/"
         version="1"
	 sender="sender name"
	 recipient="recipient name"
	 msg_ref="42" type="issue">
    <request class_name="class name"
             req_resource_set_as=""
	     req_resource_set_ipv4="10.0.0.44/32"
	     req_resource_set_ipv6="dead:beef::/32">
        deadbeef
    </request>
</message>
','<?xml version="1.0" encoding="UTF-8"?>
<message xmlns="http://www.apnic.net/specs/rescerts/up-down/"
         version="1"
	 sender="sender name"
	 recipient="recipient name"
	 msg_ref="1"
	 type="issue_response">
    <class class_name="class name"
           cert_url="url"
	   cert_ski="g(ski)"
	   resource_set_as="22,42,44444-5555555"
	   resource_set_ipv4="10.0.0.44-10.3.0.44,10.6.0.2/32"
	   resource_set_ipv6="dead:beef::/128">
        <certificate cert_url="url"
	             cert_ski="g(ski)"
		     cert_aki="g(aki)"
		     cert_serial="1"
		     resource_set_as="14-17"
		     resource_set_ipv4="128.224.1.136/22"
		     resource_set_ipv6="0:0::/22"
		     req_resource_set_as=""
		     req_resource_set_ipv4="10.0.0.77/16,127.0.0.1/8"
		     req_resource_set_ipv6="dead:beef::/16"
		     status="match">
            deadbeef
        </certificate>
        <issuer>deadbeef</issuer>
    </class>
</message>
','<?xml version="1.0" encoding="UTF-8"?>
<message xmlns="http://www.apnic.net/specs/rescerts/up-down/"
         version="1"
	 sender="sender name"
	 recipient="recipient name"
	 msg_ref="42"
	 type="list"/>
','<?xml version="1.0" encoding="UTF-8"?>
<message xmlns="http://www.apnic.net/specs/rescerts/up-down/"
         version="1"
	 sender="sender name"
	 recipient="recipient name"
	 msg_ref="42"
	 type="list_response">
    <class class_name="class name"
           cert_url="url"
	   cert_ski="g(ski)"
	   resource_set_as="1,2,4,6,16-32"
	   resource_set_ipv4="128.224.1.1-128.22.4.32"
	   resource_set_ipv6=""
	   suggested_sia_head="rsync://wombat.example/fnord/">
        <certificate cert_url="url"
	             cert_ski="g(ski)"
		     cert_aki="g(aki)"
		     cert_serial="1"
		     resource_set_as=""
		     resource_set_ipv4=""
		     resource_set_ipv6=""
		     req_resource_set_as=""
		     req_resource_set_ipv4=""
		     req_resource_set_ipv6=""
		     status="match">
            deadbeef
        </certificate>
        <!-- Repeated for each current certificate naming the client as subject -->
        <issuer>deadbeef</issuer>
    </class>
</message>
','<?xml version="1.0" encoding="UTF-8"?>
<message xmlns="http://www.apnic.net/specs/rescerts/up-down/" 
         version="1"
	 sender="sender name"
	 recipient="recipient name"
	 msg_ref="42"
	 type="revoke">
    <key class_name="class name"
         ski="g(ski)"/>
</message>
','<?xml version="1.0" encoding="UTF-8"?>
<message xmlns="http://www.apnic.net/specs/rescerts/up-down/"
         version="1"
	 sender="sender name"
	 recipient="recipient name"
	 msg_ref="42"
	 type="revoke_response">
    <key class_name="class name"
         ski="g(ski)"/>
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
