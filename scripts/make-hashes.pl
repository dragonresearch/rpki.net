#  -*- Perl -*-
# $Id$

use strict;

my $openssl = "/u/sra/isc/route-pki/subvert-rpki.hactrn.net/openssl/trunk/apps/openssl";
my $dir     = "hashed";

my @cmds;
my %hashes;

exit unless (@ARGV);

open(F, "-|", "find", @ARGV, qw{-type f ( -name *.cer -o -name *.crl )})
    or die("Couldn't run find: $!\n");

@ARGV = ();

while (<F>) {
    chomp;
    my $f = $_;
    my $type = /\.cer$/ ? "x509" : "crl";
    $_ = "$dir/$f";
    s=/[^/]+$==;
    my $d = $_;
    my $h = `$openssl $type -inform DER -in $f -noout -hash`;
    chomp($h);
    $h .= ".";
    $h .= "r" if ($type eq "crl");
    $h .= 0 + $hashes{$d}{$h}++;
    push(@cmds, "$openssl $type -inform DER -outform PEM -out $d/$h -in $f\n");
}

close(F);

print("test -d $_ || mkdir -p $_\n")
    foreach (sort(keys(%hashes)));

print($_)
    foreach (@cmds);
