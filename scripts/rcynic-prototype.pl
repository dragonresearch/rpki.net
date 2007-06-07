# $Id$

# This is a PROTOTYPE of rcynic, to see whether I have the general
# algorithms and data flow right.
#
# Some bad things that are fatal errors here will need better error
# recovery once I'm confident that I'm detecting errors in the data
# rather than in my silly code.

use strict;

my $openssl			= "../openssl/openssl-0.9.8e/apps/openssl";

my $trust_anchor_tree		= "rcynic-trust-anchors";

my $root			= "rcynic-data";
my $authenticated_pem		= "$root/authenticated_pem";
my $old_authenticated_pem	= "$authenticated_pem.old";
my $preaggregated_der		= "$root/preaggregated_der";
my $unauthenticated_der		= "$root/unauthenticated_der";
my $unauthenticated_pem		= "$root/unauthenticated_pem";
my $cafile			= "$root/CAfile.pem";

my @anchors;			# Trust anchor URIs
my @preaggregated;		# Pre-aggregation source URIs
my %rsync_cache;	        # URIs from which we've already rsynced
my %parse_cache;		# Certs we've already parsed

my $verbose_run		 = 0;	# Log all external programs
my $verbose_cache	 = 0;	# Log various cache hits
my $verbose_walk	 = 0;	# Log more info during certificate walk
my $verbose_aia		 = 0;	# Log more info for AIA errors
my $verbose_accept	 = 1;	# Log when accepting an object

my $disable_network	 = 0;	# Return immediate failure for all rsync commands
my $retain_old_certs	 = 1;	# Retain old valid certificates from previous runs
my $fix_broken_sia	 = 0;	# Fix broken SIA URIs

sub logmsg {
    my @t = gmtime;
    my $t = sprintf("%02d:%02d:%02d ", $t[2], $t[1], $t[0]);
    print($t, @_, "\n");
}

sub run {			# Run a program
    logmsg(join(" ", "Running", @_))
	if ($verbose_run);
    system(@_);
    logmsg(join(" ", @_, "returned", $?))
	if ($? != 0);
    return $? == 0;
}

sub run_pipe {			# Run a program and hand back its output
    logmsg(join(" ", "Running", @_))
	if ($verbose_run);
    my $pid = open(F, "-|");
    if ($pid) {
	my @result = <F>;
	close(F);
	chomp(@result);
	logmsg(join(" ", @_, "returned", $?))
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
    # --copy-dirlinks apparently not needed
    return 0 if ($disable_network);
    return run(qw(rsync --update --times --copy-links --itemize-changes), @_);
}

sub rsync_cache {		# Run rsync unless we've already done so for a URI covering this one
    my $uri = (grep({!/^-/} @_))[0];
    die("Can't find source URI in rsync command: @_")
	unless ($uri);
    my @path = split("/", uri_to_filename($uri));
    my $path = join("/", @path);
    pop(@path)
	while (@path && !$rsync_cache{join("/", @path)});
    if (@path) {
	logmsg("Cache hit ($path, ", join("/", @path), "), skipping rsync")
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
    my $path = "$dir/$file";
    if ($parse_cache{$path}) {
	logmsg("Already parsed certificate $uri")
	    if ($verbose_cache);
	return $parse_cache{$path};
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
    if ($res{sia} && $res{sia} !~ m=/$= && $fix_broken_sia) {
	logmsg("Malformed SIA URI, compensating: $res{sia}");
	$res{sia} .= "/";
    }
    return $parse_cache{$path} = \%res;
}

sub log_cert {
    my $obj = shift;
    logmsg("URI: $obj->{uri}");
    logmsg("CA:  ", ($obj->{ca} ? "Yes" : "No"));
    logmsg("TA:  ", ($obj->{ta} ? "Yes" : "No"));
    logmsg("AIA: $obj->{aia}") if ($obj->{aia});
    logmsg("SIA: $obj->{sia}") if ($obj->{sia});
    logmsg("CDP: $obj->{cdp}") if ($obj->{cdp});
}

sub setup_cafile {		# Set up -CAfile data for verification
    local $_;
    my %saw;			# This shouldn't be necessary, something's confused
    open(OUT, ">$cafile")
	or die("Couldn't open $cafile: $!");
    for my $f (@_) {
	next if ($saw{$f});
	$saw{$f} = 1;
	open(IN, "$authenticated_pem/$f")
	    or die("Couldn't open $authenticated_pem/$f: $!");
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
	logmsg("Already copied certificate rsync://$name")
	    if ($verbose_cache);
	return;
    }
    mkdir_maybe("$outdir/$name");
    openssl("x509", "-inform", "DER", "-in", "$indir/$name", "-outform", "PEM", "-out", "$outdir/$name");
}

sub mv {			# Move an object from one tree to another
    my $source = shift;
    my $destination = shift;
    mkdir_maybe($destination);
    rename($source, $destination)
	or die("Couldn't rename $source to $destination");
}

sub ln {			# Link an object from one tree to another
    my $source = shift;
    my $destination = shift;
    mkdir_maybe($destination);
    link($source, $destination)
	or die("Couldn't link $source to $destination");
}

sub check_crl {			# Check signature chain on a CRL, install CRL if all is well
    my $uri = shift;
    return undef
	unless ($uri);
    my $file = uri_to_filename($uri);
    if (-f "$authenticated_pem/$file") {
	logmsg("Already checked CRL $uri")
	    if ($verbose_cache);
	return $file;
    }
    mkdir_maybe("$unauthenticated_der/$file");
    rsync_cache($uri, "$unauthenticated_der/$file");
    return undef
	unless (-f "$unauthenticated_der/$file" ||
		-f "$old_authenticated_pem/$file");
    setup_cafile(@_);
    local $_;
    for my $source (($unauthenticated_der, $old_authenticated_pem)) {
	next unless (-f "$source/$file");
	logmsg("Checking saved old CRL $uri")
	    if ($source eq $old_authenticated_pem);
	my @result = openssl_pipe("crl", "-CAfile", $cafile, "-noout",
				  "-in", "$source/$file", "-inform",
				  ($source eq $old_authenticated_pem ? "PEM" : "DER"));
	if (grep(/verify OK/, @result)) {
	    logmsg("Accepting CRL $uri")
		if ($verbose_accept);
	    if ($source eq $old_authenticated_pem) {
		ln("$old_authenticated_pem/$file", "$authenticated_pem/$file");
	    } else {
		mkdir_maybe("$authenticated_pem/$file");
		openssl("crl", "-inform", "DER", "-in", "$source/$file",
			"-outform", "PEM", "-out", "$authenticated_pem/$file");
	    }
	    return $file;
	} elsif (grep(/certificate revoked/, @result)) {
	    logmsg("Revoked certificate in path for CRL $uri");
	} else {
	    logmsg("Verification failure for CRL $uri:");
	    logmsg("  Inputs:");
	    logmsg("    $_")
		foreach (($file, @_));
	    logmsg("  Result:");
	    logmsg("    $_")
		foreach (@result);
	}
    }
    return undef;
}

sub check_cert {		# Check signature chain etc on a certificate, install if all's well
    my $uri = shift;
    my $file = shift;
    my $source = shift;
    die("No certificate to process!")
	unless (-f "$source/$file");
    setup_cafile(@_);
    my @result = openssl_pipe(qw(verify -verbose -crl_check_all -policy_check -explicit_policy
				 -policy 1.3.6.1.5.5.7.14.2 -x509_strict -CAfile),
			      $cafile, "$source/$file");
    local $_;
    if (grep(/OK$/, @result)) {
	logmsg("Accepting certificate $uri")
	    if ($verbose_accept);
	if ($source eq $old_authenticated_pem) {
	    ln("$source/$file", "$authenticated_pem/$file");
	} else {
	    mv("$source/$file", "$authenticated_pem/$file");
	}
	return 1;
    } elsif (grep(/certificate revoked/, @result)) {
	logmsg("Revoked certificate in path for certificate $uri");
    } else {
	logmsg("Verification failure for certificate $uri:");
	logmsg("  Inputs:");
	logmsg("    $_")
	    foreach (($file, @_));
	logmsg("  Result:");
	logmsg("  $_")
	    foreach (@result);
    }
    return 0;
}

sub walk_cert {			# Process a certificate -- core of the program
    my $p = shift;
    
    die("No certificate to process!")
	unless ($p);

    logmsg("Starting walk of $p->{uri}");
    log_cert($p)
	if ($verbose_walk);

    if ($p->{sia}) {
	my @chain = (uri_to_filename($p->{cdp}), $p->{file}, @_);
	my $sia = uri_to_filename($p->{sia});
	mkdir_maybe("$unauthenticated_der/$sia");
	rsync_cache(qw(--recursive --delete),
		    $p->{sia}, "$unauthenticated_der/$sia");
	my @files = do {
	    my %files;
	    for my $f (glob("$unauthenticated_der/${sia}*.cer")) {
		$f =~ s=^$unauthenticated_der/==;
		$files{$f} = 1;
	    }
	    if ($retain_old_certs) {
		for my $f (glob("$old_authenticated_pem/${sia}*.cer")) {
		    $f =~ s=^$old_authenticated_pem/==;
		    $files{$f} = 1;
		}
	    }
	    keys(%files);
	};
	for my $file (@files) {
	    my $uri = "rsync://" . $file;
	    logmsg("Found certificate $uri");
	    if (-f "$authenticated_pem/$file") {
		logmsg("Already checked certificate $uri, skipping")
		    if ($verbose_cache);
		next;
	    }
	    die("Certificate $uri is its own ancestor?!?")
		if (grep({$file eq $_} @chain));
	    copy_cert($file, $unauthenticated_der, $unauthenticated_pem)
		if (-f "$unauthenticated_der/$file");
	    my $cert;
	    for my $source (($unauthenticated_pem, $old_authenticated_pem)) {
		next
		    unless (-f "$source/$file");
		logmsg("Checking saved old certificate $uri")
		    if ($source eq $old_authenticated_pem);
		my $c = parse_cert($uri, $source);
		if (!$c) {
		    logmsg("Parse failure for $uri, skipping");
		    next;
		}
		log_cert($c)
		    if ($verbose_walk);
		if ($c->{sia} && $c->{sia} !~ m=/$=) {
		    logmsg("Malformed SIA for $uri, skipping");
		    next;
		}
		if (!$c->{aia}) {
		    logmsg("AIA missing for $uri, skipping");
		    next;
		}
		if (!$p->{ta} && $c->{aia} ne $p->{uri}) {
		    logmsg("AIA of $uri doesn't match parent, skipping");
		    if ($verbose_aia) {
			logmsg("\tSubject AIA: $c->{aia}");
			logmsg("\t Issuer URI: $p->{uri}");
		    }
		    next;
		}
		if ($c->{ca} && !$c->{sia}) {
		    logmsg("CA certificate $uri without SIA extension, skipping");
		    next;
		}
		if (!$c->{ca} && $c->{sia}) {
		    logmsg("EE certificate $uri with SIA extension, skipping");
		    next;
		}
		if (!$c->{cdp}) {
		    logmsg("CDP missing for $uri, skipping");
		    next;
		}
		my $crl = check_crl($c->{cdp}, @chain);
		if (!$crl) {
		    logmsg("Problem with CRL for $uri, skipping");
		    next;
		}
		if (!check_cert($uri, $file, $source, $crl, @chain)) {
		    logmsg("Verification failure for $uri, skipping");
		    next;
		}
		$cert = $c;	# If we get here, we found a good cert,
		last;		# so remember it and get out of inner loop
	    }

	    next unless ($cert);
	    walk_cert($cert, @chain);
	}
    }

    logmsg("Finished walk of $p->{uri}");
}

sub main {			# Main program

    my $start_time = time;
    logmsg("Started at ", scalar(gmtime($start_time)), " UTC");

    # We should read a configuration file, but for debugging it's
    # easier just to wire the parameters into the script.

    if (1) {
	push(@anchors, qw(rsync://ca-trial.ripe.net/arinroot/repos/root.cer
			  rsync://ca-trial.ripe.net/riperoot/repos/root.cer
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

    run("rm", "-rf", $unauthenticated_pem, $old_authenticated_pem);
    rename($authenticated_pem, $old_authenticated_pem);
    die("Couldn't clear $authenticated_pem from previous run")
	if (-d $authenticated_pem);

    # Create any missing directories.

    for my $dir (($preaggregated_der, $unauthenticated_der,
		  $authenticated_pem, $unauthenticated_pem)) {
	mkdir_maybe("$dir/");
    }

    # Pull over any pre-aggregated data.  We'll still have to check
    # signatures in all of this, it's just a convenience to get us
    # started.

    for my $uri (@preaggregated) {
	my $dir = uri_to_filename($uri);
	mkdir_maybe("$preaggregated_der/$dir");
	rsync("--recursive", $uri, "$preaggregated_der/$dir");
    }

    # Update our unauthenticated tree from the pre-aggregated data.
    # Will need to pay attention to rsync parameters here to make sure
    # we don't overwrite newer stuff.

    rsync("--recursive", "$preaggregated_der/", "$unauthenticated_der/");

    # Local trust anchors always win over anything else, so seed our
    # authenticated tree with them

    for my $anchor (@anchors) {
	copy_cert(uri_to_filename($anchor), $trust_anchor_tree, $authenticated_pem);
    }

    # Now start walking the tree, starting with our trust anchors.

    for my $anchor (@anchors) {
	my $t = parse_cert($anchor, $authenticated_pem);
	die("Couldn't parse trust anchor! $anchor\n")
	    unless($t);
	$t->{ta} = 1;
	if (!$t->{cdp}) {
	    logmsg("Trust anchor $anchor has no CRL distribution point, skipping");
	    next;
	}
	if (!check_crl($t->{cdp}, $t->{file})) {
	    logmsg("Problem with trust anchor $anchor CRL $t->{cdp}, skipping");
	    next;
	}
	walk_cert($t);
    }

    unlink($cafile);

    my $stop_time = time;
    logmsg("Finished at ", scalar(gmtime($stop_time)), " UTC");

    my $elapsed = $stop_time - $start_time;
    my $seconds = $elapsed % 60;  $elapsed /= 60;
    my $minutes = $elapsed % 60;  $elapsed /= 60;
    my $hours   = $elapsed;

    logmsg("Elapsed time: ", sprintf("%d:%02d:%02d", $hours, $minutes, $seconds));

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
