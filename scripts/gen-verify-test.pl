:
# $Id$
eval 'exec perl -w -S $0 ${1+"$@"}'
    if 0;

use strict;

my $openssl = "/u/sra/isc/route-pki/subvert-rpki.hactrn.net/openssl/openssl-0.9.8f/apps/openssl";

my $verify_options = "-verbose -crl_check_all -policy_check -explicit_policy -policy 1.3.6.1.5.5.7.14.2 -x509_strict";

my $verbose = 1;

my $debug = $ENV{DEBUG};

exit unless (@ARGV);

# Find all certificates in the repository

open(F, "-|", "find", @ARGV, qw(-type f -name *.cer))
    or die("Couldn't run find: $!\n");
chomp(my @files = <F>);
close(F);
@ARGV = ();

# Snarf all the AIA and CDP values from the certs we're examining.
# Icky screen scraping, better mechanism needed.

my %aia;
my %cdp;

for my $f (@files) {
    my ($a, $c) = (0, 0);
    open(F, "-|", $openssl, qw(x509 -noout -text -inform DER -in), $f)
	or die("Couldn't run openssl x509 on $f: $!\n");
    while (<F>) {
	chomp;
	s{^.+URI:rsync://}{};
	$a = $. + 1
	    if (/Authority Information Access:/);
	$c = $. + 1
	    if (/X509v3 CRL Distribution Points:/);
	$aia{$f} = $_
	    if ($a && $. == $a);
	$cdp{$f} = $_
	    if ($c && $. == $c);
    }
    print(STDERR $f, " ", ($aia{$f} || "-"), " ", ($cdp{$f} || "-"), "\n")
	if ($debug);
    close(F);
}

# Sort out ancestry

my %daddy;

for my $f (@files) {
    next unless ($aia{$f});
    my @daddy = grep({ $_ eq $aia{$f} } @files);
    die("Can't figure out who my daddy is! $f @{[join(' ', @daddy)]}\n")
	if (@daddy > 1);
    $daddy{$f} = $daddy[0]
	if (@daddy && $daddy[0] ne $f);
    print(STDERR "me: $f, daddy: $daddy[0]\n")
	if ($debug);
}

# Generate a test script based on all of the above

for my $f (@files) {
    my @ancestors;
    for (my $d = $daddy{$f}; $d; $d = $daddy{$d}) {
	push(@ancestors, $d);
    }
    next unless (@ancestors);
    my @crls;
    for my $c (map {$cdp{$_}} ($f, @ancestors)) {
	push(@crls, $c)
	    unless (grep {$_ eq $c} @crls);
    }
    print("echo ", "=" x 40, "\n",
	  "echo Checking chain:\n")
	if ($verbose > 0);
    for (($f, @ancestors)) {
	print("echo '    Certificate: $_'\n")
	    if ($verbose > 0);
	print("$openssl x509 -noout -text -inform DER -certopt no_header,no_signame,no_validity,no_pubkey,no_sigdump,no_version -in $_\n")
	    if ($verbose > 1);
    }
    for (@crls) {
	print("echo '    CRL:         $_'\n")
	    if ($verbose > 0);
	print("$openssl crl -noout -text -inform DER -in $_\n")
	    if ($verbose > 1);
    }
    print("rm -f CAfile.pem cert-in-hand.pem\n");
    print("$openssl x509 -inform DER -outform PEM >>CAfile.pem -in $_\n")
	foreach (@ancestors);
    print("$openssl crl  -inform DER -outform PEM >>CAfile.pem -in $_\n")
	foreach (@crls);
    print("$openssl x509 -inform DER -outform PEM -out cert-in-hand.pem -in $f\n",
	  "$openssl verify -CAfile CAfile.pem $verify_options cert-in-hand.pem\n",
	  "rm -f CAfile.pem cert-in-hand.pem\n");
}
