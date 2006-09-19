:
# $Id$
eval 'exec perl -w -S $0 ${1+"$@"}'
    if 0;

use strict;

my $format = "DER";
my $badsia = 0;

while ($ARGV[0] =~ /^--/) {
    $_ = shift;
    if (/^--der/)	{ $format = "DER"; next }
    if (/^--pem/)	{ $format = "PEM"; next }
    if (/^--badsia/)	{ $badsia = 1;   next }
    if (/^--help/)	{
	print("$0 [ --der | --pem ] [ --badsia ] cert [ cert ...]\n");
	exit;
    }
    die("Unrecognized option: $_");
}

while (@ARGV) {
    my $file = shift(@ARGV);
    my ($aia, $sia, $cdp, $a, $s, $c) = qw(- - -);
    next unless ($file =~ /\.cer$/);
    open(F, "-|", ( qw(openssl x509 -noout -inform), $format,
		    qw(-text -in), $file))
	or die("Couldn't run openssl x509 on $file: $!\n");
    while (<F>) {
	chomp;
	s{^.+URI:rsync://}{};
	$a = $. + 1
	    if (/Authority Information Access:/);
	$s = $. + 1
	    if (/Subject Information Access:/);
	$c = $. + 1
	    if (/X509v3 CRL Distribution Points:/);
	$aia = $_
	    if ($a && $. == $a);
	$sia = $_
	    if ($s && $. == $s);
	$cdp = $_
	    if ($c && $. == $c);
    }
    close(F);
    if ($badsia) {
	print("$file\n\t$sia\n")
	    if ($sia && $sia =~ m=[^/]$=);
    } else {
	print("$aia $sia $cdp $file\n");
    }
}
