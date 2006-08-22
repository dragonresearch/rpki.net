#!/usr/local/bin/perl
eval 'exec /usr/local/bin/perl -S $0 ${1+"$@"}'
    if $running_under_some_shell;
			# this emulates #! processing on NIH machines.
			# (remove #! line above if indigestible)

eval '$'.$1.'$2;' while $ARGV[0] =~ /^([A-Za-z_0-9]+=)(.*)/ && shift;
			# process any FOO=bar switches

$, = ' ';		# set output field separator
$\ = "\n";		# set output record separator

while (<>) {
    chomp;	# strip record separator
    if (/X509v3 Subject Key Identifier:/) {
	$ski = $. + 1;
    }
    if (/X509v3 Authority Key Identifier:/) {
	$aki = $. + 1;
    }
    if ($ski && $. == $ski) {
	s/^[        ]*//;
	$S = $_;
    }
    if ($aki && $. == $aki) {
	s/^[        ]*keyid://;
	$a = $_;
    }
}

print $S, $a, $f;

