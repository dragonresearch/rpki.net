#  -*- Perl -*-
# $Id$

my $openssl = "/u/sra/isc/route-pki/subvert-rpki.hactrn.net/openssl/trunk/apps/openssl";

my $dir = "hashed";

my %count;

open(F, "-|", qw{find repository.apnic.net/APNIC -type f ( -name *.cer -o -name *.crl )})
    or die("Couldn't run find: $!\n");
my @files = <F>;
close(F);
chomp(@files);

print("test -d $dir || mkdir $dir\n");

for my $f (@files) {
    my $prog = ($f =~ /\.cer$/) ? "x509" : "crl";
    my $h = `$openssl $prog -inform DER -in $f -noout -hash`;
    chomp($h);
    my $n = 0 + $count{$h}++;
    print("$openssl $prog -inform DER -outform PEM -out $dir/$h.$n -in $f\n");
}
