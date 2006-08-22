:
# $Id$
eval 'exec perl -w -S $0 ${1+"$@"}'
    if 0;

while (@ARGV) {
    my $file = shift(@ARGV);
    my ($aia, $sia, $crl, $a, $s, $c) = qw(- - -);
    next unless ($file =~ /\.cer$/);
    open(F, "-|", qw(openssl x509 -noout -inform DER -text -in), $file)
	or die("Couldn't run openssl x509 on $file: $!\n");
    while (<F>) {
	chomp;
	s{^.+URI:}{};
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
	$crl = $_
	    if ($c && $. == $c);
    }
    close(F);
    print("$aia $crl $sia $file\n");
}
