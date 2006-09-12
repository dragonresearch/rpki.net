# $Id$

# Hack to generate a small test repository for testing Apache + OpenSSL + RPKI

use strict;

my %resources;
my %parent;
my @ordering;
my %hashes;

my $openssl	= "../../openssl/trunk/apps/openssl";
my $subdir	= "apacheca";
my $passwd	= "fnord";
my $keybits	= 2048;
my $verbose	= 0;
my $debug	= 1;

sub openssl {
    print(STDERR join(" ", qw(+ openssl), @_), "\n")
	if ($debug);
    !system($openssl, @_)
	or die("openssl @_ returned $?\n");
}

# Ok, this is a bit complicated, but the idea is to let us specify the
# resources we're giving to each leaf entity and let the program do
# the work of figuring out what resources each issuers need to have,
# the order in which we need to generate the certificates, which
# certificates need to sign which other certificates, etcetera.
#
# This would be much easier to read in a sane language (eg, Scheme).

{
    my @ctx;
    my $loop ;
    $loop= sub {
	my $x = shift;
	if (ref($x) eq "HASH") {
	    while (my ($k, $v) = each(%$x)) {
		$parent{$k} = $ctx[@ctx - 1];
		push(@ordering, $k);
		push(@ctx, $k); $loop->($v); pop(@ctx);
	    }
	} else {
	    for my $c (@ctx) { push(@{$resources{$c}}, @$x) }
	}
    };
    $loop->({
	RIR => {
	    LIR1 => {
		ISP1 => [IPv4 => "10.0.1.1-10.0.3.255", AS => "33"],
		ISP2 => [IPv4 => "10.3.0.0-10.3.0.255"],
	    },
	    LIR2 => {
		ISP3 => [IPv6 => "2002::44-2002::100"],
		ISP4 => [IPv6 => "2002::10:0:44", AS => "44"],
	    },
	},
    });
}

# Put this stuff into a subdirectory

mkdir($subdir) unless (-d $subdir);
chdir($subdir) or die;

# Generate configurations for each entity.

while (my ($entity, $resources) = each(%resources)) {
    my %r;
    print($entity, ":\n")
	if ($verbose);
    for (my $i = 0; $i < @$resources; $i += 2) {
	printf("  %4s: %s\n", $resources->[$i], $resources->[$i+1])
	    if ($verbose);
	push(@{$r{$resources->[$i]}}, $resources->[$i+1]);
    }
    open(F, ">${entity}.cnf") or die;
    print(F <<EOF);

	[ ca ]
	default_ca = ca_default

	[ ca_default ]

	certificate = ${entity}.cer
	serial = ${entity}/serial
	private_key = ${entity}.key
	database = ${entity}/index
	new_certs_dir = ${entity}
	name_opt = ca_default
	cert_opt = ca_default
	default_days = 365
	default_crl_days = 30
	default_md = sha1
	preserve = no
	copy_extensions = copy
	policy = ca_policy_anything
	unique_subject = no

	[ ca_policy_anything ]
	countryName = optional
	stateOrProvinceName = optional
	localityName = optional
	organizationName = optional
	organizationalUnitName = optional
	commonName = supplied
	emailAddress = optional
	givenName = optional
	surname = optional

	[ req ]
	default_bits = $keybits
	encrypt_key = no
	distinguished_name = req_dn
	x509_extensions = req_x509_ext
	prompt = no

	[ req_dn ]

	CN = TEST ENTITY $entity

	[ req_x509_ext ]

	basicConstraints = critical,CA:true
	subjectKeyIdentifier = hash
	authorityKeyIdentifier = keyid
	keyUsage = critical,keyCertSign,cRLSign
	subjectInfoAccess = 1.3.6.1.5.5.7.48.5;URI:rsync://wombats-r-us.hactrn.net/

EOF

    print(F <<EOF) if ($parent{$entity});

	authorityInfoAccess = caIssuers;URI:rsync://wombats-r-us.hactrn.net/$parent{$entity}.cer

EOF

    print(F <<EOF) if ($r{AS} || $r{RDI});

	sbgp-autonomousSysNum = critical,\@asid_ext

EOF

    print(F <<EOF) if ($r{IPv4} || $r{IPv6});

	sbgp-ipAddrBlock = critical,\@addr_ext

EOF

    print(F <<EOF);

	[ asid_ext ]

EOF

    for my $n (qw(AS RDI)) {
	my $i = 0;
	for my $a (@{$r{$n}}) {
	    print(F "\t", $n, ".", $i++, " = ", $a, "\n");
	}
    }

    print(F <<EOF);


	[ addr_ext ]

EOF

    for my $n (qw(IPv4 IPv6)) {
	my $i = 0;
	for my $a (@{$r{$n}}) {
	    print(F "\t", $n, ".", $i++, " = ", $a, "\n");
	}
    }
    close(F);
}

# Run OpenSSL to create the keys and certificates.  We generate keys
# separately to avoid wasting /dev/random bits if we need to change
# the configuration.

for my $entity (@ordering) {
    openssl("genrsa", "-out", "${entity}.key", $keybits)
	unless (-f "${entity}.key");
    openssl("req", "-new", "-config", "${entity}.cnf", "-key", "${entity}.key", "-out", "${entity}.req");

    mkdir($entity)
	unless (-d $entity);
    if (!-f "${entity}/index") {
	open(F, ">${entity}/index") or die;
	close(F);
    }
    if (!-f "${entity}/serial") {
	open(F, ">${entity}/serial") or die;
	print(F "01\n") or die;
	close(F);
    }

    openssl("ca", "-batch", "-verbose", "-out", "${entity}.cer", "-in", "${entity}.req",
	    "-extensions", "req_x509_ext", "-extfile", "${entity}.cnf",
	    ($parent{$entity}
	     ? ("-config", "${parent{$entity}}.cnf")
	     : ("-config", "${entity}.cnf", "-selfsign")));
}

# Generate CRLs

for my $entity (@ordering) {
    openssl("ca", "-batch", "-verbose", "-out", "${entity}.crl", 
	    "-config", "${entity}.cnf", "-gencrl");
}

# Generate EE certs

for my $parent (@ordering) {
    my $entity = "${parent}-EE";
    open(F, ">${entity}.cnf") or die;
    print(F <<EOF);

	[ req ]
	default_bits = $keybits
	encrypt_key = no
	distinguished_name = req_dn
	x509_extensions = req_x509_ext
	prompt = no

	[ req_dn ]

	CN = TEST ENDPOINT ENTITY ${entity}

	[ req_x509_ext ]

	basicConstraints = critical,CA:false
	subjectKeyIdentifier = hash
	authorityKeyIdentifier = keyid
	subjectInfoAccess = 1.3.6.1.5.5.7.48.5;URI:rsync://wombats-r-us.hactrn.net/
	authorityInfoAccess = caIssuers;URI:rsync://wombats-r-us.hactrn.net/$parent.cer

EOF

    close(F);
    openssl("genrsa", "-out", "${entity}.key", $keybits)
	unless (-f "${entity}.key");
    openssl("req", "-new", "-config", "${entity}.cnf", "-key", "${entity}.key", "-out", "${entity}.req");

    mkdir($entity)
	unless (-d $entity);
    if (!-f "${entity}/index") {
	open(F, ">${entity}/index") or die;
	close(F);
    }
    if (!-f "${entity}/serial") {
	open(F, ">${entity}/serial") or die;
	print(F "01\n") or die;
	close(F);
    }

    openssl("ca", "-batch", "-verbose", "-config", "${parent}.cnf",
	    "-extensions", "req_x509_ext", "-extfile", "${entity}.cnf",
	    "-out", "${entity}.cer", "-in", "${entity}.req");
}

# Generate hashes

for my $cert (map({("$_.cer", "$_-EE.cer")} @ordering)) {
    my $hash = `$openssl x509 -noout -hash -in $cert`;
    chomp($hash);
    $hash .= ".";
    $hash .= (0 + $hashes{$hash}++);
    unlink($hash) if (-l $hash);
    symlink($cert, $hash)
	or die("Couldn't link $hash to $cert: $!\n");
}

for my $crl (map({"$_.crl"} @ordering)) {
    my $hash = `$openssl crl -noout -hash -in $crl`;
    chomp($hash);
    $hash .= ".r";
    $hash .= (0 + $hashes{$hash}++);
    unlink($hash) if (-l $hash);
    symlink($crl, $hash)
	or die("Couldn't link $hash to $crl: $!\n");
}

# Generate PKCS12 forms of EE certificates
# -chain argument to pkcs12 requires certificate store, which we configure via an environment variable

$ENV{SSL_CERT_DIR} = do { my $pwd = `pwd`; chomp($pwd); $pwd; };

for my $ee (map({"$_-EE"} @ordering)) {
    my @cmd = ("pkcs12", "-export", "-in", "$ee.cer",  "-inkey", "$ee.key", "-password", "pass:$passwd");
    openssl(@cmd, "-out", "$ee.p12");
    openssl(@cmd, "-out", "$ee.chain.p12", "-chain");
}

# Finally, generate an unrelated self-signed certificate for the server

my $hostname = `hostname`;
chomp($hostname);
open(F, ">server.cnf") or die;
print(F <<EOF);

	[ req ]
	default_bits = $keybits
	encrypt_key = no
	distinguished_name = req_dn
	prompt = no

	[ req_dn ]

	CN = $hostname

EOF

close(F);
openssl(qw(genrsa -out server.key), $keybits)
    unless (-f "server.key");
openssl(qw(req -new -config server.cnf -key server.key -out server.req));
openssl(qw(x509 -req -CAcreateserial -in server.req -out server.cer -signkey server.key));

# Local Variables:
# compile-command: "perl generate-testrepo.pl"
# End:
