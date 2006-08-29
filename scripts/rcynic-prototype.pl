# $Id$

# This is a PROTOTYPE of rcynic, just to see whether I have the
# general algorithms and data flow right.
#
# Most bad things are fatal errors in the initial version of this
# prototype.  Many of them will need better error recovery later, once
# I'm confident that I'm detecting errors in the certificates rather
# than errors in my silly code.

use strict;

my $openssl		 = "/u/sra/isc/route-pki/subvert-rpki.hactrn.net/openssl/trunk/apps/openssl";

my $root		 = "rcynic-data";
my $trust_anchor_tree	 = "$root/trust-anchors";
my $preaggregated_tree	 = "$root/preaggregated";
my $unauthenticated_tree = "$root/unauthenticated";
my $authenticated_tree   = "$root/authenticated";
my $temporary_tree	 = "$root/temporary";
my $cafile		 = "$root/CAfile.pem";

my @anchors;
my @preaggregated;
my %certs;

sub mkdir_maybe {
    my $dir = shift;
    $dir =~ s=[^/]+$==;
    !system("mkdir", "-p", $dir)
	or die("Couldn't make $dir")
	unless (-d $dir);
}

sub rsync {
    !system("rsync", "-ai", @_)
	or die("Couldn't rsync @_");
}

sub openssl {
    !system($openssl, @_)
	or die("Couldn't openssl @_");
}

sub openssl_pipe {
    my $pid = open(F, "-|");
    if ($pid) {
	my @result = <F>;
	close(F);
	chomp(@result);
	return @result;
    } else {
	open(STDERR, ">&STDOUT")
	    or die("Couldn't dup() STDOUT: $!");
	exec($openssl, @_)
	    or die("Couldn't exec() openssl @_: $!");
    }
}

sub uri_to_filename {
    local $_ = shift;
    if ($_) {
	die("Not an rsync URI: $_")
	    unless (m=^rsync://=);
	s=^rsync://==;
	die("Evil character sequences in URI: $_")
	    if (m=^/= || m=^\.\.$= || m=^\.\./= || m=/\.\./= || m=/\.\.$= || m=//=);
    }
    return $_;
}

sub extract_cert_uris {
    my $uri = shift;
    my $dir = shift || $authenticated_tree;
    my $file = uri_to_filename($uri);
    my %res = (file => $file, uri => $uri);
    my ($a, $s, $c);
    my @txt = openssl_pipe(qw(x509 -noout -text -in), "$dir/$file");
    local $_;
    s=^.+URI:==
	foreach (@txt);
    for (my $i = 0; $i < @txt; ++$i) {
	$_ = $txt[$i];
	$res{aia} = $txt[$i+1]
	    if (/Authority Information Access:/);
	$res{sia} = $txt[$i+1]
	    if (/Subject Information Access:/);
	$res{cdp} = $txt[$i+1]
	    if (/X509v3 CRL Distribution Points:/);
    }
    if ($res{sia} && $res{sia} !~ m=/$=) {
	warn("Badly formatted AIA URI, compensating: $res{sia}");
	$res{sia} .= "/";
    }
    return \%res;
}

sub copy_cert {
    my $name = shift;
    my $indir = shift || $unauthenticated_tree;
    my $outdir = shift || $temporary_tree;
    mkdir_maybe("$outdir/$name");
    openssl("x509", "-inform", "DER", "-in", "$indir/$name", "-outform", "PEM", "-out", "$outdir/$name");
}

sub install_cert {
    my $name = shift;
    my $indir = shift ||  $temporary_tree;
    my $outdir = shift || $authenticated_tree;
    mkdir_maybe("$outdir/$name");
    rename("$indir/$name", "$outdir/$name")
	or die("Couldn't rename $indir/$name to $outdir/$name");
}

sub copy_crl {
    my $name = shift;
    my $indir = shift || $unauthenticated_tree;
    my $outdir = shift || $authenticated_tree;
    mkdir_maybe("$outdir/$name");
    openssl("crl", "-inform", "DER", "-in", "$indir/$name", "-outform", "PEM", "-out", "$outdir/$name");
}

sub setup_cafile {
    local $_;
    open(OUT, ">$cafile")
	or die("Couldn't open $cafile: $!");
    for my $f (@_) {
	open(IN, "$authenticated_tree/$f")
	    or die("Couldn't open $authenticated_tree/$f: $!");
	print(OUT $_)
	    foreach (<IN>);
	close(IN);
    }
    close(OUT);
}

sub check_crl {
    my $uri = shift;
    my $crl = shift;
    mkdir_maybe("$unauthenticated_tree/$crl");
    rsync($uri, "$unauthenticated_tree/$crl");
    setup_cafile(@_);
    my @result = openssl_pipe("crl", "-inform", "DER", "-CAfile", $cafile, "-in", "$unauthenticated_tree/$crl");
    local $_;
    for (@result) {
	return 1 if (/verify OK/);
	return 0 if (/verify failure/);
	warn("Unexpected verification result: $_");
    }
    die("Don't understand openssl crl verification results");
}

sub verify_cert {
    my $cert = shift;
    setup_cafile(@_);
    my @result = openssl_pipe(qw(verify -verbose -crl_check_all -policy_check -explicit_policy -policy 1.3.6.1.5.5.7.14.2 -x509_strict -CAfile), $cafile,
			      "$temporary_tree/$cert");
    local $_;
    my $ok;
    for (@result) {
	$ok = 1 if (/OK$/);
    }
    return $ok;
}

# $1:	 -verified- cert we're examining (we start from a trust anchor)
# &rest: ancestor certs and crls
#
sub check_cert {
    my $cert = shift;
    my @chain = @_;

    print("Starting check of $cert\n");

    my $u = extract_cert_uris($cert);
    die("Couldn't extract URIs from certificate: $cert")
	unless ($u);

    my $crl;
    if ($u->{cdp}) {
	$crl = uri_to_filename($u->{cdp});
	die ("Problem with CRL signature: $u->{cdp}")
	    unless (check_crl($u->{cdp}, $crl, $u->{file}, @chain));
	copy_crl($crl);
    } else {
	warn("CDP missing for cert: $cert");
    }

    if (@chain && !$u->{aia}) {
	warn("Non-trust-anchor certificate missing AIA extension: $cert");
    } elsif (@chain && $chain[0] ne $u->{aia}) {
	warn("AIA does not match parent URI: $cert");
    }

    unshift(@chain, $crl)
	if ($crl);
    unshift(@chain, $u->{file});

    # Should check whether certificate is a CA here: SIA must be set
    # if it's a CA and must not be set if it's not a CA.

    if ($u->{sia}) {
	my $sia = uri_to_filename($u->{sia});
	mkdir_maybe("$unauthenticated_tree/$sia");
	rsync($u->{sia}, "$unauthenticated_tree/$sia");
	for my $file (glob("$unauthenticated_tree/${sia}*.cer")) {
	    $file =~ s=^$unauthenticated_tree/==;
	    my $uri = "rsync://" . $file;
	    print("Found cert $uri\n");
	    copy_cert($file);
	    if (!verify_cert($file, @chain)) {
		warn("Verification failure for $file, skipping");
		next;
	    }
	    install_cert($file);
	    check_cert($uri, @chain);
	}
    }

    print("Finished check of $cert\n");
}

###

# Easier to wire parameters into this script for initial debugging

if (1) {
    push(@anchors, qw(rsync://ca-trial.ripe.net/ARIN/root/root.cer
		      rsync://ca-trial.ripe.net/RIPE/root/root.cer
		      rsync://ca-trial.ripe.net/arinroot/repos/root.cer
		      rsync://ca-trial.ripe.net/riperoot/repos/root.cer
		      rsync://repository.apnic.net/APNIC/APNIC.cer
		      rsync://repository.apnic.net/trust-anchor.cer));
#   push(@preaggregated, qw());
} else {
    # Read config
    while (<>) {
	chomp;
	next if (/^\s*$/ || /^\s*[;\#]/);
	my @argv = split;
	if ($argv[0] eq "anchor") {
	    push(@anchors, $argv[1]);
	} elsif ($argv[0] eq "preaggregated") {
	    push(@preaggregated, $argv[1]);
	} else {
	    die("Could not parse: $_");
	}
    }
}

# Create any missing directories.

for my $dir (($trust_anchor_tree, $preaggregated_tree, $unauthenticated_tree, $authenticated_tree, $temporary_tree)) {
    mkdir_maybe("$dir/");
}

# Pull over any pre-aggregated data.  We'll still have to check
# signatures in all of this, it's just a convenience to get us
# started.

for my $uri (@preaggregated) {
    my $dir = uri_to_filename($uri);
    mkdir_maybe("$preaggregated_tree/$dir");
    rsync($uri, "$preaggregated_tree/$dir");
}

# Update our unauthenticated tree from the pre-aggregated data.  Will
# need to pay attention to rsync parameters here to make sure we don't
# overwrite newer stuff.

rsync("$preaggregated_tree/", "$unauthenticated_tree/");

# Local trust anchors always win over anything else, so seed our
# authenticated tree with them

for my $anchor (@anchors) {
    copy_cert(uri_to_filename($anchor), $trust_anchor_tree, $authenticated_tree);
}

# Now start walking the tree, starting with our trust anchors.

for my $anchor (@anchors) {
    check_cert($anchor);
}


################################################################
#
# Date: Sat, 19 Aug 2006 02:53:25 -0400
# From: Rob Austein <sra@hactrn.net>
# Subject: rcynic design
# Message-Id: <20060819065325.B4C525C53@thrintun.hactrn.net>
# 
# overall tasks: collect certificates from publication points, assemble
# them into a local certificate store, perform validation checks on all
# of them, discarding the ones that don't pass.  output is a valid
# repository containing a snapshot of all the (valid, accessible)
# certificates in the rpki system.  also want to provide ability for
# others to synchronize from this repository, so mustn't do anything
# that precludes serving results via rsync.  code should also support
# building a validated repository purely from locally maintained data.
# 
# inputs to the process:
# 
# - a (small) set of trust anchors
# 
# - zero or more rsync uris for pre-aggregated object collections
# 
# - a configuration file containing or pointing to the above inputs and
#   whatever other parameters we turn out to need.
# 
# i was initially arguing for a collection phase followed by a
# validation phase after fetching all the data.  randy convinced me that
# we don't want to follow uris that didn't come from local config or a
# cert we've already checked.  most paranoid version of this would
# involve pulling one directory at a time via rsync, but that's wasteful
# of tcp connections and process forks, so we compromised on allowing
# rsync of everything under a given uri once we've validated it.
# 
# so we end up with a two phase model that looks like this:
# 
# 1) fetch pre-aggregated stuff from zero or more uris specified in
#    config file.  listing a uri in this part of the config file is
#    construed as willingness to rsync data from it without further
#    checks.  we will validate all of this later, we just don't have to
#    validate it while we're fetching it.
# 
# 2) walk the tree starting with the trust anchors, checking stuff, and
#    examining uris.  optionally follow rsync sia uris from validated
#    certs, fetching more stuff that's missing or stale in our store,
#    applying this process recursively until we run out of new uris to
#    follow or decide that we've followed too many uris ("too many" is a
#    configurable parameter with a relatively high default).
# 
# if we don't fetch anything in either phase, this is just a check of a
# pre-existing tree, which is an operation we want to have anyway.
# 
# we need to maintain two separate collections:
# 
# a) everything we got via rsync from whichever parties we were willing
#    to ask, and
# 
# b) only the stuff we've blessed.
# 
# there may be transient states in which we have both old and new
# versions of each of these, although probably not of both at once.
# 
# we need to perform certain sanity checks on any uris we use
# (principally checking for "/../" sequences and any other pathnames
# which are potentially dangerous and which we don't there's any sane
# reason for us ever to see), and if possible we want to run rsync
# inside a chroot jail with restricted permissions and a paranoid set of
# client options (in particular, we don't want to receive symlinks).
# the chroot code should be written in such a way that it is easy for a
# paranoid administrator to verify, and so that it can be omitted if the
# administrator's paranoia trusts rsync more than they trust our chroot
# code (which, by definition, has to run as root).
# 
# output of the collection stage is a local disk mirror of all the
# candidate certificates and crls we could fetch.  some may not have
# been accessible, in which case we may have to fall back to previously
# fetched data from an earlier pass, if we have any and if it's still
# valid.  if a validation pass finds that we're broken badly enough, we
# may need to disable distribution of our results to others (ie, disable
# rsync server), but we may not have a lot of choice about using some of
# the new data, as clocks will be ticking and old stuff will time out.
# 
# unless i think of a better way to do it, local store will be organized
# in approximately the way that wget would organize such a collection: a
# top level directory, each first level subdirectory of which is named
# for the hostname portion of the publication uri, second (and lower)
# level subdirectories track the directory structure at each of the
# publication points.
# 
# when validating our candidate set of certificates and crls, we need to
# walk through them, probably top down, checking each one (signature,
# revocation, path validation including well-formed 3779 extensions).
# we build a parallel tree (same directory structure) containing only
# objects that pass our checks.  if we have not already pruned out all
# non-file, non-directory objects at an earlier stage, we check for this
# (posix stat() call) before we open any object file.
# 
# rsync efficiency issue: any changes we make to our local copy to
# correct a remote problem will be overwritten by the same remote
# problem the next time we run rsync unless the problem has been
# corrected.  it'd be nice to avoid continually fetching the same
# mistakes.  so we don't want to delete stuff from our raw unvalidated
# mirror, we just don't copy it to our validated mirror.  there may be
# other ways to deal with this, eg, having three local trees: one
# maintained by rsync, a second which is a copy of the first with
# symlinks etc cleaned out, and a third which we've validated.
# 
# failure mode: can't get new copies of stuff we already had.  recovery:
# reuse old stuff if still valid.  we want to use our old unvalidated
# copies (a) for this, since some time skew problems may have fixed
# themselves by now and there might be now-valid stuff in our old
# unvalidated store that didn't pass validation last time.
# 
# failure mode: pulled new broken copies of stuff for which we had old
# valid copies.  recovery: reuse the old valid copies (b), unless we got
# to a three step model just to preserve old unvalidated stuff for this
# case too (probably unnecessary).
# 
# additional check we should perform: do we get the same answer if we
# follow the aia uris upwards within our local store as we get when we
# follow the sia uris downwards?  not clear how we should handle this if
# the answer is "no": warning at minimum, but probably should reject at
# least some of the certificates involved if this check fails.  whether
# we should reject all the certificates that mismatch or only the
# children is a tricky, as rejecting all could be an invitation to
# denial of service attacks (bozo-isp intentionally or through
# incompetence generates bogus uri, arin's validator stops running,
# oops!), so this may need to be a configurable choice.  randy suspects
# that most mismatches will be due to time skews, for which "retry
# later" might be a plausible recovery.
