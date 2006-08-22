:
eval 'exec perl -S $0 ${1+"$@"}'
    if 0;

use MIME::Base64;

my $openssl = "/u/sra/isc/route-pki/subvert-rpki.hactrn.net/openssl/trunk/apps/openssl";

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
    my $f = shift(@ARGV);
    open(F, "-|", $openssl, qw(x509 -noout -inform DER -text -in), $f)
	or die("Couldn't run openssl x509 on $f: $!\n");
    while (<F>) {
	chomp;
	if (/X509v3 Authority Key Identifier:/) {
	    $aki = $. + 1;
	}
	if ($aki && $. == $aki) {
	    s/^[ \t]*keyid://;
	    $a = $_;
	}
    }
    close(F);
    print(g($a), " $f\n");
}
