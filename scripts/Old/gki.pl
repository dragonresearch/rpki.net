:
# $Id$
eval 'exec perl -w -S $0 ${1+"$@"}'
    if 0;

use MIME::Base64;

sub g {
    my $x = shift;
    $x =~ s{:}{}g;
    $x = pack("H*", $x);
    $x = encode_base64($x, "");
    $x =~ y{+/}{-_};
    $x =~ s{=+$}{};
    return $x;
}

while (@ARGV) {
    my ($file, $aki, $ski, $a, $s) = shift(@ARGV);
    if ($file =~ /\.cer$/) {
	open(F, "-|", qw(openssl x509 -noout -inform DER -text -in), $file)
	    or die("Couldn't run openssl x509 on $file: $!\n");
    } elsif  ($file =~ /\.crl$/) {
	open(F, "-|", qw(openssl crl  -noout -inform DER -text -in), $file)
	    or die("Couldn't run openssl x509 on $file: $!\n");
    } else {
	next;
    }
    while (<F>) {
	chomp;
	s/^\s*//;
	s/^keyid://;
	$a = $. + 1
	    if (/X509v3 Authority Key Identifier:/);
	$s = $. + 1
	    if (/X509v3 Subject Key Identifier:/);    
	$aki = $_
	    if ($a && $. == $a);
	$ski = $_
	    if ($s && $. == $s);
    }
    close(F);
    my $gaki = $aki ? g($aki) : "=" x 27;
    my $gski = $ski ? g($ski) : "=" x 27;
    print("$gaki $gski $file\n");
}
