:
# $Id$
eval 'exec perl -w -S $0 ${1+"$@"}'
    if 0;

my $openssl = "/u/sra/isc/route-pki/subvert-rpki.hactrn.net/openssl/trunk/apps/openssl";

exit unless (@ARGV);

open(F, "-|", "find", @ARGV, qw(-type f -name *.cer))
    or die("Couldn't run find: $!\n");
chomp(my @files = <F>);
close(F);

# Convert files to PEM (openssl verify is lame)

for (@files) {
    my $f = $_;
    s/\.cer$/.pem/;		# This modifies @files
    next if -f $_;
    !system($openssl, qw(x509 -inform DER -in), $f, "-out", $_)
	or die("Couldn't convert $f to PEM format: $!\n");
}

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

# This isn't a full test yet, this only tests one level (total chain
# two certs deep).  What we really need, after this much of it is
# working, is to build up a %daddy hash based on the following tests,
# then build up and test full chains from that.

for my $f (@files) {
    next unless ($aki{$f});
    my @daddy = grep({ $ski{$_} eq $aki{$f} } @files);
    next unless (@daddy == 1);
    print("$openssl verify -verbose -issuer_checks \\\n\t-CAfile ",
	  $daddy[0], " \\\n\t\t", $f, "\n");
}
