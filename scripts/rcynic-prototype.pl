# $Id$

# This is a PROTOTYPE of rcynic, to see whether I have the general
# algorithms and data flow right.
#
# Some bad things that are fatal errors here will need better error
# recovery once I'm confident that I'm detecting errors in the data
# rather than in my silly code.

use strict;

my $openssl		 = "/usr/local/bin/openssl";

my $trust_anchor_tree	 = "rcynic-trust-anchors";

my $root		 = "rcynic-data";
my $preaggregated_tree	 = "$root/preaggregated";
my $unauthenticated_tree = "$root/unauthenticated";
my $authenticated_tree   = "$root/authenticated";
my $temporary_tree	 = "$root/temporary";
my $cafile		 = "$root/CAfile.pem";

my @anchors;			# Trust anchor URIs
my @preaggregated;		# Pre-aggregation source URIs
my %rsync_cache;	        # URIs from which we've already rsynced
my %parse_cache;		# Certs we've already parsed

my $verbose_run		 = 0;	# Log all external programs
my $verbose_cache	 = 0;	# Log various cache hits
my $verbose_walk	 = 0;	# Log more info during certificate walk
my $verbose_aia		 = 0;	# Log more info for AIA errors
my $verbose_sia_fixup	 = 1;	# Log when fixing up SIA URIs

my $disable_network	 = 0;	# Return immediate failure for all rsync commands (testing only)

sub run {			# Run a program
    print(join(" ", "Running", @_), "\n")
	if ($verbose_run);
    system(@_);
    print("$_[0] returned $?\n")
	if ($? != 0);
    return $? == 0;
}

sub run_pipe {			# Run a program and hand back its output
    print(join(" ", "Running", @_), "\n")
	if ($verbose_run);
    my $pid = open(F, "-|");
    if ($pid) {
	my @result = <F>;
	close(F);
	chomp(@result);
	print("$_[0] returned $?\n")
	    if ($? != 0);
	return @result;
    } else {
	open(STDERR, ">&STDOUT")
	    or die("Couldn't dup() STDOUT: $!");
	exec(@_)
	    or die("Couldn't exec() ", join(" ", @_), ": $!");
    }
}

sub mkdir_maybe {		# Create missing directories
    my $dir = shift;
    $dir =~ s=[^/]+$==;
    run("mkdir", "-p", $dir)
	unless (-d $dir);
}

sub rsync {			# Run rsync with our preferred options
    return 0 if ($disable_network);
    return run("rsync", "-tiLku", @_);
}

sub rsync_cache {		# Run rsync unless we've already done so for a URI covering this one
    my $recursive = shift;
    my @path = split("/", uri_to_filename($_[0]));
    my $path = join("/", @path);
    unshift(@_, "-r")
	if ($recursive);
    pop(@path)
	while (@path && !$rsync_cache{join("/", @path)});
    if (@path) {
	print("Cache hit ($path, ", join("/", @path), "), skipping rsync\n")
	    if ($verbose_cache);
	return 1;
    } else {
	my $result = rsync(@_);
	$rsync_cache{$path} = 1;
	return $result;
    }
}

sub openssl {			# Run our version of openssl
    run($openssl, @_);
}

sub openssl_pipe {		# Run our version of opessl with output
    run_pipe($openssl, @_);
}

sub uri_to_filename {		# Check a URI and conver it to a filename
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

sub parse_cert {		# Parse interesting fields from a certificate
    my $uri = shift;
    my $dir = shift;
    my $file = uri_to_filename($uri);
    if ($parse_cache{$file}) {
	print("Already parsed certificate $uri\n")
	    if ($verbose_cache);
	return $parse_cache{$file};
    }
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
	$res{ca} = 1
	    if (/X509v3 Basic Constraints/ && $txt[$i+1] =~ /^\s*CA:TRUE\s*$/);
    }
    if ($res{sia} && $res{sia} !~ m=/$=) {
	print("Badly formatted AIA URI, compensating: $res{sia}\n")
	    if ($verbose_sia_fixup);
	$res{sia} .= "/";
    }
    return $parse_cache{$file} = \%res;
}

sub setup_cafile {		# Set up -CAfile data for verification
    local $_;
    my %saw;			# This shouldn't be necessary, something's confused
    open(OUT, ">$cafile")
	or die("Couldn't open $cafile: $!");
    for my $f (@_) {
	next if ($saw{$f});
	$saw{$f} = 1;
	open(IN, "$authenticated_tree/$f")
	    or die("Couldn't open $authenticated_tree/$f: $!");
	print(OUT $_)
	    foreach (<IN>);
	close(IN);
    }
    close(OUT);
}

sub copy_cert {			# Convert a certificate from DER to PEM
    my $name = shift;
    my $indir = shift;
    my $outdir = shift;
    if (-f "$outdir/$name") {
	print("Already copied certificate rsync://$name\n")
	    if ($verbose_cache);
	return;
    }
    mkdir_maybe("$outdir/$name");
    openssl("x509", "-inform", "DER", "-in", "$indir/$name", "-outform", "PEM", "-out", "$outdir/$name");
}

sub check_crl {			# Check signature chain on a CRL, install CRL if all is well
    my $uri = shift;
    return undef
	unless ($uri);
    my $file = uri_to_filename($uri);
    if (-f "$authenticated_tree/$file") {
	print("Already checked CRL $uri\n")
	    if ($verbose_cache);
	return $file;
    }
    mkdir_maybe("$unauthenticated_tree/$file");
    rsync_cache(0, $uri, "$unauthenticated_tree/$file");
    return undef unless (-f "$unauthenticated_tree/$file");
    setup_cafile(@_);
    my @result = openssl_pipe("crl", "-inform", "DER", "-CAfile", $cafile,
			      "-in", "$unauthenticated_tree/$file");
    local $_;
    if (grep(/verify OK/, @result)) {
	mkdir_maybe("$authenticated_tree/$file");
	openssl("crl", "-inform", "DER", "-in", "$unauthenticated_tree/$file",
		"-outform", "PEM", "-out", "$authenticated_tree/$file");
	return $file;
    } elsif (grep(/certificate revoked/, @result)) {
	print("Revoked certificate in path for CRL $uri\n");
	return undef;
    } else {
	print("Verification failure for CRL $uri:\n");
	print("  Inputs:\n");
	print("    $_\n")
	    foreach (($file, @_));
	print("  Result:\n");
	print("    $_\n")
	    foreach (@result);
	return undef;
    }
}

sub move {
    my $source = shift;
    my $destination = shift;
    mkdir_maybe($destination);
    rename($source, $destination)
	or die("Couldn't rename $source to $destination");
}


sub check_cert {		# Check signature chain etc on a certificate, install if all's well
    my $uri = shift;
    my $file = shift;
    setup_cafile(@_);
    my @result = openssl_pipe(qw(verify -verbose -crl_check_all -policy_check -explicit_policy
				 -policy 1.3.6.1.5.5.7.14.2 -x509_strict -CAfile),
			      $cafile, "$temporary_tree/$file");
    local $_;
    if (grep(/OK$/, @result)) {
	move("$temporary_tree/$file", "$authenticated_tree/$file");
	return 1;
    } elsif (grep(/certificate revoked/, @result)) {
	print("Revoked certificate in path for certificate $uri\n");
	return 0;
    } else {
	print("Verification failure for certificate $uri:\n");
	print("  Inputs:\n");
	print("    $_\n")
	    foreach (($file, @_));
	print("  Result:\n");
	print("  $_\n")
	    foreach (@result);
	return 0;
    }
}

sub walk_cert {			# Process a certificate -- this is the core of the program
    my $p = shift;
    
    die("No certificate to process!")
	unless ($p);

    print("Starting walk of $p->{uri}\n");
    if ($verbose_walk) {
	print("CA:  ", ($p->{ca} ? "Yes" : "No"), "\n");
	print("TA:  ", ($p->{ta} ? "Yes" : "No"), "\n");
	print("AIA: $p->{aia}\n") if ($p->{aia});
	print("SIA: $p->{sia}\n") if ($p->{sia});
	print("CDP: $p->{cdp}\n") if ($p->{cdp});
    }

    if ($p->{sia}) {
	my @chain = (uri_to_filename($p->{cdp}), $p->{file}, @_);
	my $sia = uri_to_filename($p->{sia});
	mkdir_maybe("$unauthenticated_tree/$sia");
	rsync_cache(1, $p->{sia}, "$unauthenticated_tree/$sia");

	# In theory this should check all files in this directory, not
	# just ones matching *.cer.  Punt on that for now as it'd be
	# painful in this kludgy script.

	for my $file (glob("$unauthenticated_tree/${sia}*.cer")) {
	    $file =~ s=^$unauthenticated_tree/==;
	    my $uri = "rsync://" . $file;
	    print("Found cert $uri\n");
	    if (-f "$authenticated_tree/$file") {
		print("Already checked certificate $uri, skipping\n")
		    if ($verbose_cache);
		next;
	    }
	    die("Certificate $uri is its own ancestor?!?")
		if (grep({$file eq $_} @chain));
	    copy_cert($file, $unauthenticated_tree, $temporary_tree);
	    my $c = parse_cert($uri, $temporary_tree);
	    if (!$c) {
		print("Parse failure for $uri, skipping\n");
		next;
	    }
	    if (!$c->{aia}) {
		print("AIA missing for $uri, skipping\n");
		next;
	    }
	    if (!$p->{ta} && $c->{aia} ne $p->{uri}) {
		print("AIA of $uri doesn't match parent, skipping\n");
		print("\tSubject AIA: $c->{aia}\n",
		      "\t Issuer URI: $p->{uri}\n")
		    if ($verbose_aia);
		if ($verbose_aia > 1) {
		    my $c_aia = "$unauthenticated_tree/" . uri_to_filename($c->{aia});
		    my $p_uri = "$unauthenticated_tree/" . uri_to_filename($p->{uri});
		    my $res = run("cmp", "-sz", $c_aia, $p_uri);
		    if ($res == 0) {
			print("\tBoth certificates exist, content is identical\n");
		    } elsif ($res == 1) {
			print("\tBoth certificates exist, content differs\n");
		    } elsif (! -f $c_aia) {
			print("\tCertificate indicated by AIA not found\n");
		    }
		}
		next;
	    }
	    if ($c->{ca} && !$c->{sia}) {
		print("CA certificate $uri without SIA extension, skipping\n");
		next;
	    }
	    if (!$c->{ca} && $c->{sia}) {
		print("EE certificate $uri with SIA extension, skipping\n");
		next;
	    }
	    if (!$c->{cdp}) {
		print("CDP missing for $uri, skipping\n");
		next;
	    }
	    my $crl = check_crl($c->{cdp}, @chain);
	    if (!$crl) {
		print("Problem with CRL for $uri, skipping\n");
		next;
	    }
	    if (!check_cert($uri, $file, $crl, @chain)) {
		print("Verification failure for $uri, skipping\n");
		next;
	    }
	    walk_cert($c, @chain);
	}
    }

    print("Finished walk of $p->{uri}\n");
}

sub main {			# Main program

    my $start_time = time;
    print("Started at ", scalar(localtime($start_time)), "\n");

    # We should read a configuration file, but for debugging it's
    # easier just to wire the parameters into the script.

    if (1) {
	push(@anchors, qw(rsync://ca-trial.ripe.net/ARIN/root/root.cer
			  rsync://ca-trial.ripe.net/RIPE/root/root.cer
			  rsync://ca-trial.ripe.net/arinroot/repos/root.cer
			  rsync://ca-trial.ripe.net/riperoot/repos/root.cer
			  rsync://repository.apnic.net/APNIC/APNIC.cer
			  rsync://repository.apnic.net/trust-anchor.cer));
	push(@preaggregated, qw());
    } else {
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

    # Initial cleanup.

    run("rm", "-rf", $temporary_tree, "${authenticated_tree}.old");
    rename($authenticated_tree, "${authenticated_tree}.old");
    die("Couldn't clear $authenticated_tree from previous run")
	if (-d $authenticated_tree);

    # Create any missing directories.

    for my $dir (($preaggregated_tree, $unauthenticated_tree, $authenticated_tree, $temporary_tree)) {
	mkdir_maybe("$dir/");
    }

    # Pull over any pre-aggregated data.  We'll still have to check
    # signatures in all of this, it's just a convenience to get us
    # started.

    for my $uri (@preaggregated) {
	my $dir = uri_to_filename($uri);
	mkdir_maybe("$preaggregated_tree/$dir");
	rsync("-r", $uri, "$preaggregated_tree/$dir");
    }

    # Update our unauthenticated tree from the pre-aggregated data.
    # Will need to pay attention to rsync parameters here to make sure
    # we don't overwrite newer stuff.

    rsync("-r", "$preaggregated_tree/", "$unauthenticated_tree/");

    # Local trust anchors always win over anything else, so seed our
    # authenticated tree with them

    for my $anchor (@anchors) {
	copy_cert(uri_to_filename($anchor), $trust_anchor_tree, $authenticated_tree);
    }

    # Now start walking the tree, starting with our trust anchors.

    for my $anchor (@anchors) {
	my $t = parse_cert($anchor, $authenticated_tree);
	die("Couldn't parse trust anchor! $anchor\n")
	    unless($t);
	$t->{ta} = 1;
	if (!$t->{cdp}) {
	    print("Trust anchor $anchor has no CRL distribution point, skipping\n");
	    next;
	}
	if (!check_crl($t->{cdp}, $t->{file})) {
	    print("Problem with trust anchor $anchor CRL $t->{cdp}, skipping\n");
	    next;
	}
	walk_cert($t);
    }

    my $stop_time = time;
    print("Finished at ", scalar(localtime($stop_time)), "\n");

    my $elapsed = $stop_time - $start_time;
    my $seconds = $elapsed % 60;  $elapsed /= 60;
    my $minutes = $elapsed % 60;  $elapsed /= 60;
    my $hours   = $elapsed;

    printf("Elapsed time: %d:%02d:%02d\n", $hours, $minutes, $seconds);

}

main()

################################################################
#
# Stuff that still needs work:
#
# 1) Trust anchors don't really have origin URIs in the sense we're
#    using for everything else.  Perhaps just should not live in
#    the authenticated tree at all?
#
# 2) Need to rework walk_cert() to allow us to walk the old
#    authenticated tree after we're done checking everything else, to
#    pick up old stuff that's still valid in the old tree and is now
#    bogus or missing in the updated unauthenticated tree.
#
# 3) Should have a log() function so can add timestamps, etc.
#
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
#
################################################################

# Local Variables:
# compile-command: "perl rcynic-prototype.pl"
# End:
