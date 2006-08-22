#  -*- Perl -*-
# $Id$

use strict;

my $openssl = "/u/sra/isc/route-pki/subvert-rpki.hactrn.net/openssl/trunk/apps/openssl";

my $dir = "hashed";
my %dirs = ($dir => 1);
my @cmds;
my %count;

exit unless (@ARGV);

open(F, "-|", "find", @ARGV, qw{-type f ( -name *.cer -o -name *.crl )})
    or die("Couldn't run find: $!\n");

@ARGV = ();

while (<F>) {
    chomp;
    my $f = $_;
    my $type = /\.cer$/ ? "x509" : "crl";
    my $h = `$openssl $type -inform DER -in $f -noout -hash`;
    chomp($h);
    $h .= ".";
    $h .= "r" if ($type eq "crl");
    my $n = 0 + $count{$h}++;
    $_ = "$dir/$f";
    s=/[^/]+$==;
    $dirs{$_} = 1;
    push(@cmds, "$openssl $type -inform DER -outform PEM -out $_/$h$n -in $f\n");
}

close(F);

print("test -d $_ || mkdir $_\n")
    foreach (sort(keys(%dirs)));

print($_)
    foreach (@cmds);
