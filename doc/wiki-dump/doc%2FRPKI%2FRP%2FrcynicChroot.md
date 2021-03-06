# Running rcynic chrooted

This is an attempt to describe the process of setting up rcynic in a chrooted
environment. The installation scripts that ship with rcynic attempt to do this
automatically when requested for the platforms we support, but the process is
somewhat finicky, so some explanation seems in order. If you're running on one
of the supported platforms, the following steps may be handled for you by the
Makefiles, but you may still want to understand what all this is trying to do.

rcynic itself does not include any direct support for running chrooted, but is
designed to be (relatively) easy to run in a chroot jail.

To enable chroot support during installation, you should [install from
source][1] and use the `--enable-rcynic-jail` option to `./configure`.

rcynic-cron includes support for running chrooted. To use it, specify the
`--chroot` option on rcynic-cron's command line. This will cause rcynic-cron
to run rcynic in the chrooted environment. Note that, in order for this to
work, rcynic-cron itself must run as root, since only root can issue the
`chroot()` system call. When run as root, rcynic-cron takes care of changing
the user ID of each process it starts to the unprivileged "`rcynic`" user.

## Creating the chroot jail environment

By far the most tedious and finicky part of setting up rcynic to run in a
chroot jail is setting the jail itself. The underlying principal is simple and
obvious: a process running in the jail can't use files outside the jail. The
difficulty is that the list of files that needs to be in the jail is system-
dependent, can be rather long, and sometimes can only be discovered by trial
and error.

You'll either need staticly linked copies of rcynic and rsync, or you'll need
to figure out which shared libraries these programs need (try using the "ldd"
command). Here we assume staticly linked binaries, because that's simpler, but
be warned that statically linked binaries are not even possible on some
platforms, whether due to concious decisions on the part of operating system
vendors or due to hidden use of dynamic loading by other libraries at runtime.
Once again, the Makefiles attempt to do the correct thing for your environment
if they know what it is, but they might get it wrong.

You may also find that the dynamic loader looks in a different place than you
(and the Makefiles) would expect when running within the chroot jail. For
example, you might think that library `/usr/local/lib/libfoo.so` being
installed into a jail named `/var/rcynic` should go into
`/var/rcynic/usr/local/lib/libfoo.so`, but we've seen cases where the dynamic
loader ended up expecting to find it in `/var/rcynic/lib/libfoo.so`. Getting
this right may require a bit of trial and error.

You'll need a chroot wrapper program. As mentioned above, rcynic-cron can act
as that wrapper program; if this works for you, we recommend it, because it
works the same way on all platforms and doesn't require additional external
programs. Otherwise, you'll have to find a suitable wrapper program. Your
platform may already have one (FreeBSD does -- `/usr/sbin/chroot`), but if you
don't, you can download Wietse Venema's "chrootuid" program from
<ftp://ftp.porcupine.org/pub/security/chrootuid1.3.tar.gz>.

Warning

     The chroot program included in at least some GNU/Linux distributions is not adaquate to this task. You need a wrapper that knows how to drop privileges after performing the chroot() operation itself. If in doubt, use chrootuid. 

Unfortunately, the precise details of setting up a proper chroot jail vary
wildly from one system to another, so the following instructions may not be a
precise match for the preferred way of doing this on your platform. Please
feel free to contribute scripts for other platforms.

  1. Build the static binaries. You might want to test them at this stage too, although you can defer that until after you've got the jail built. 
  2. Create a userid under which to run rcynic. Here we'll assume that's a user named "rcynic", whose default group is also named "rcynic". Do not add any other userids to the rcynic group unless you really know what you are doing. 
  3. Build the jail. You'll need, at minimum, a directory in which to put the binaries, a subdirectory tree that's writable by the userid which will be running rcynic and rsync, your trust anchors, and whatever device inodes the various libraries need on your system. Most likely the devices that matter will be `/dev/null`, `/dev/random`, and `/dev/urandom`; if you're running a FreeBSD system with devfs, you do this by mounting and configuring a devfs instance in the jail, on other platforms you probably use the `mknod` program or something similar. 

Important

     Other than the directories that you want rcynic and rsync to be able to modify, _nothing_ in the initial jail setup should be writable by the rcynic userid. In particular, rcynic and rsync should _not_ be allowed to modify: their own binary images, any of the configuration files, or your trust anchors. It's simplest just to have root own all the files and directories that rcynic and rsync are not allowed to modify, and make sure that the permissions for all of those directories and files make them writable only by root. 

Sample jail tree, assuming that we're putting all of this under `/var/rcynic`:

    
    
    $ mkdir /var/rcynic
    $ mkdir /var/rcynic/bin
    $ mkdir /var/rcynic/data
    $ mkdir /var/rcynic/dev
    $ mkdir /var/rcynic/etc
    $ mkdir /var/rcynic/etc/trust-anchors
    

Copy your trust anchors into `/var/rcynic/etc/trust-anchors`.

Copy the staticly linked rcynic and rsync into `/var/rcynic/bin`.

Copy `/etc/resolv.conf` and `/etc/localtime` (if it exists) into
`/var/rcynic/etc`.

Write an rcynic configuration file as `/var/rcynic/etc/rcynic.conf`. Path
names in this file must match the jail setup, more on this below.

    
    
    $ chmod -R go-w /var/rcynic
    $ chown -R root:wheel /var/rcynic
    $ chown -R rcynic:rcynic /var/rcynic/data
    

If you're using devfs, arrange for it to be mounted at `/var/rcynic/dev`;
otherwise, create whatever device inodes you need in `/var/rcynic/dev` and
make sure that they have sane permissions (copying whatever permissions are
used in your system `/dev` directory should suffice).

`rcynic.conf` to match this configuration:

    
    
    [rcynic]
    
    rsync-program           = /bin/rsync
    authenticated           = /data/authenticated
    unauthenticated         = /data/unauthenticated
    xml-summary             = /data/rcynic.xml
    trust-anchor-directory  = /etc/trust-anchors
    

Once you've got all this set up, you're ready to try running rcynic in the
jail. Try it from the command line first, then if that works, you should be
able to run it under cron.

Note: chroot, chrootuid, and other programs of this type are usually intended
to be run by root, and should _not_ be setuid programs unless you _really_
know what you are doing.

Sample command line:

    
    
    $ /usr/local/bin/chrootuid /var/rcynic rcynic /bin/rcynic -s -c /etc/rcynic.conf
    

Note that we use absolute pathnames everywhere. This is not an accident.
Programs running in jails under cron should not make assumptions about the
current working directory or environment variable settings, and programs
running in chroot jails would need different `PATH` settings anyway. Best just
to specify everything.

### Building static binaries

On FreeBSD, building a staticly linked rsync is easy: one just sets the
environment variable `LDFLAGS='-static'` before building rsync and the right
thing will happen. Since this is really just GNU configure picking up the
environment variable, the same trick should work on other platforms...except
that some compilers don't support `-static`, and some platforms are missing
some or all of the non-shared libraries you'd need to link the resulting
binary.

For simplicity, we've taken the same approach with rcynic, so

    
    
    $ make LDFLAGS='-static'
    

works. This isn't necessary on platforms where we know that static linking
works -- the default is static linking where supported.

### syslog from chrooted environment

Depending on how the `syslog()` library call and the syslog daemon (`syslogd`,
`rsyslogd`, ...) are implemented on your platform, syslog may not work
properly with rcynic in a chroot jail. On FreeBSD, the easiest way to fix this
is to add the following lines to /etc/rc.conf:

    
    
    altlog_proglist="named rcynic"
    rcynic_chrootdir="/var/rcynic"
    rcynic_enable="YES"
    

This tells syslogd to listen on an additional `PF_UNIX` socket within rcynic's
chroot jail.

   [1]: #_.wiki.doc.RPKI.Installation.FromSource

