:
# $Id$
eval 'exec perl -w -S $0 ${1+"$@"}'
    if 0;

use strict;

my $openssl = "/u/sra/isc/route-pki/subvert-rpki.hactrn.net/openssl/trunk/apps/openssl";

exit unless (@ARGV);

open(F, "-|", "find", @ARGV, qw(-type f -name *.cer))
    or die("Couldn't run find: $!\n");
chomp(my @files = <F>);
close(F);

# Convert to PEM ("openssl verify" is lame)

for (@files) {
    my $f = $_;
    s/\.cer$/.pem/;		# This modifies @files
    next if -f $_;
    !system($openssl, qw(x509 -inform DER -in), $f, "-out", $_)
	or die("Couldn't convert $f to PEM format: $!\n");
}

# Snarf all the AKI and SKI values from the certs we're examining

my %aki;
my %ski;

for my $f (@files) {
    my ($a, $s);
    open(F, "-|", $openssl, qw(x509 -noout -text -in), $f)
	or die("Couldn't run openssl x509 on $f: $!\n");
    while (<F>) {
	chomp;
	s/^\s*//;
	s/^keyid://;
	$a = $. + 1
	    if (/X509v3 Authority Key Identifier:/);
	$s = $. + 1
	    if (/X509v3 Subject Key Identifier:/);    
	$aki{$f} = $_
	    if ($a && $. == $a);
	$ski{$f} = $_
	    if ($s && $. == $s);
    }
    close(F);
}

# Figure out who everybody's parents are

my %daddy;

for my $f (@files) {
    next unless ($aki{$f});
    my @daddy = grep({ $ski{$_} eq $aki{$f} } @files);
    $daddy{$f} = $daddy[0]
	if (@daddy == 1 && $daddy[0] ne $f);
}

# Generate a test script based on all of the above

my $verbose = 1;

for my $f (@files) {
    my @parents;
    for (my $d = $daddy{$f}; $d; $d = $daddy{$d}) {
	push(@parents, $d);
    }
    next unless (@parents);
    print("echo ", "=" x 40, "\n",
	  "echo Checking chain:\n")
	if ($verbose > 0);
    for (($f, @parents)) {
	print("echo '    File: $_'\n")
	    if ($verbose > 0);
	print("$openssl x509 -noout -text -certopt no_header,no_signame,no_validity,no_pubkey,no_sigdump,no_version -in $_\n")
	    if ($verbose > 1);
    }
    print("cat >CAfile.pem");
    print(" $_")
	foreach (@parents);
    print("\n",
	  "$openssl verify -verbose -CAfile CAfile.pem \\\n",
	  "\t$f\n",
	  "rm CAfile.pem\n");
}
