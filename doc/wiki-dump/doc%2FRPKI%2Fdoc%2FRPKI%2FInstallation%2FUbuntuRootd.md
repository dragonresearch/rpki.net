# Ubuntu trusty 14.04 RPKI Install with rootd

Given a running Ubuntu 14.04 server, this should take an hour or less.

## Rationale

Due to the ravages of time and the business of hackers, documentation of the
arcane process of installing the RPKI CA software has not kept as current as
it might. Additionally, back in the day, we thought that installing a root
instance would be exceedingly rare, so tools and documentation of that process
are poor. This page attempts to patch that pothole.

Many users will be happy installing a rootless CA instance. This page may
still help them as it puts everything in one place; just skip the root parts.

But a root instance turns out to be very helpful for:

  * Experimenting, where one does not want to mess up the global RPKI 
  * Certifying use of RFC1918 and other private spaces 
  * Running private environments 

## Prerequisites

You can start with the following:

  * A small VM, 4GB disk, 512MB RAM, one processor 
  * Ubuntu 14.04 i386 server version 
  * opensshd, and 
  * Emacs, of course 

I am lazy and log in as root as pretty much everything I do is going to
require being root. If you like sudo, then just prefix a lot with it.

This example uses apt-get. If you prefer other tools, see the more detailed
page, <https://trac.rpki.net/wiki/doc/RPKI/Installation/DebianPackages>.

## Install the Basic RPKI CA and RP Software

You should only need to perform these steps once for any particular machine.

Add the GPG public key for this repository (optional, but APT will whine
unless you do this):

    
    
    wget -q -O - http://download.rpki.net/APT/apt-gpg-key.asc | sudo apt-key add -
    

Configure APT to use this repository (for Ubuntu Trusty systems):

    
    
    wget -q -O /etc/apt/sources.list.d/rpki.list http://download.rpki.net/APT/rpki.trusty.list
    

Update available packages:

    
    
    apt-get update
    

Install the software:

    
    
    apt-get install rpki-rp rpki-ca
    

You will be prompted to enter

    
    
    New password for the MySQL "root" user:
    

This will be the password for root@localhost on the MySQL server. Make one up,
save it somewhere safe, and enter it twice. [ insert lecture on strong
passwords. ]

## Minimal Configuration

This example install uses the server hostname `test.dfw.rg.net`. Any use of
that hostname below will have to be replaced with your host's name, of course.

### Relying Party - rcynic

The RP (Relying Party) software should have installed and should be running.
You can test it by browsing to <https://test.dfw.rg.net/rcynic/>. It uses a
self-signed TLS certificate; you can be lazy and decided to accept it as
opposed to installing a real one generated from from your own TLS CA; your
call.

The rcynic web page had not populated yet because the cron job to populate is
generated for a socially polite cache which fetches once an hour.

    
    
    test.dfw.rg.net:/root# crontab -u rcynic -l
    MAILTO=root
    49 * * * *      exec /usr/bin/rcynic-cron
    

Do not change this now as it would place an asocial load on the global RPKI.

If you plan to use the rpki-rtr protocol to feed a router from the RP cache
you just installed, check `/etc/xinetd.d/rpki-rtr` to be sure the port number
is 323, the IANA assigned port, as opposed to some old hacks that were used
pre [RFC 6810][1].

    
    
    cat /etc/xinetd.d/rpki-rtr
    service rpki-rtr
    {
        type           = UNLISTED
        flags          = IPv4
        socket_type    = stream
        protocol       = tcp
        port           = 323
        wait           = no
        user           = rpkirtr
        server         = /usr/bin/rpki-rtr
        server_args    = server /var/rcynic/rpki-rtr
    }
    

The configuration for rcynic is in `/etc/rcynic.conf`. Note that it says to
use the trust anchors in the directory `/etc/rpki/trust-anchors`. As you
intend to install the created root instance's trust anchor there, try to
remembered how to find it.

### CA Configuration - rpki.conf

`/etc/rpki.conf` is the core configuration file for the CA. You need to make
very minimal changes. If you want an explanation for all the options, go to
<https://trac.rpki.net/wiki/doc/RPKI/CA/Configuration>. Get coffee first.

`handle` is generated as `test_dfw_rg_net`. You may want to change it to
something more intuitive such as `testCA`. You do not really need to do this,
but let's assume you do.

`run_rootd` was generated as `no` because most folk do not want to run rootd.
But if you intend to have the rootd part of this exercise, change it to `yes`.

Observe that the `publication_base_directory` expands/decodes to
`/usr/share/rpki/publication`. Similarly, `bpki_servers_directory` decodes to
`/usr/share/rpki`.

That is it for configuration or `/etc/rpki.conf`!

### Creating a Root Certificate

At this point, you may want to

    
    
    cd /usr/share/rpki
    

so that everything is in one place; otherwise it is easy to get confused.

If you intend to run a root CA, i.e. run rootd, you need to create a root
certificate with all possible resources, i.e.  
ASs 0-4294967295,  
0.0.0.0/0, and  
0::/0

sra made a great hack to do this, so you so not have to go through all the
arcane (and not working for me) instructions on
<https://trac.rpki.net/wiki/doc/RPKI/CA/Configuration/CreatingRoot>

    
    
    wget https://subvert-rpki.hactrn.net/trunk/potpourri/generate-root-certificate --no-check-certificate
    

And then

    
    
    python generate-root-certificate 
    

This should give you

    
    
    /usr/share/rpki# ls -l root.*
    -rw-r--r-- 1 root root 1056 Aug  7 06:55 root.cer
    -rw-r--r-- 1 root root 1194 Aug  7 06:55 root.key
    -rw-r--r-- 1 root root  439 Aug  7 06:55 root.tal
    

For security considerations, the root certificate really should not be in the
publication point. And the script does not make a stash for it. so you should
make and use one.

    
    
    mkdir /usr/share/rpki/publication.root
    rsync root.cer /usr/share/rpki/publication.root
    

Remember that RP software runs from the trust anchors in `/etc/rpki/trust-
anchors`. In this example, you want the root to be the only trust anchor, so

    
    
    rm /etc/rpki/trust-anchors/*
    rsync root.tal /etc/rpki/trust-anchors/TestRoot.tal
    

And now it it safe to hack rcynic's crontab to be frequent

    
    
    crontab -u rcynic -l
    MAILTO=root
    */10 * * * *    exec /usr/bin/rcynic-cron
    

### rsyncd Configuration

Next, you want to get the rsync daemon working. First you need to tell the
rsync daemon what it should serve. Remember that we decided to serve root and
data separately. So configure `/etc/rsyncd.conf` as follows:

    
    
    cat > /etc/rsyncd.conf << EOF
    uid             = nobody
    gid             = rcynic
    
    [root]
        use chroot          = no
        read only           = yes
        transfer logging    = yes
        path                = /usr/share/rpki/publication.root
        comment             = ROOT publication
    
    [rpki]
        use chroot          = no
        read only           = yes
        transfer logging    = yes
        path                = /usr/share/rpki/publication
        comment             = RPKI publication
    EOF
    

Then tell xinetd to run the rsync deamon when asked and then to restart xinetd

    
    
    cat > /etc/xinetd.d/rsync << EOF
    service rsync
    {
        disable         = no
        socket_type     = stream
        port            = 873
        protocol        = tcp
        wait            = no
        user            = root
        server          = /usr/bin/rsync
        server_args     = --daemon
        log_on_failure  += USERID
    }
    EOF
    service xinetd restart
    

It is recommended that you test it from a remote system

    
    
    rsync rsync://test.dfw.rg.net/root/root.cer
    -rw-r--r--        1056 2015/08/07 16:28:10 root.cer
    

## CA Data Initialization

The remaining configuration was done using the RPKI software itself.

### Starting Services

Before configuring the CA daemon and database, you should first restart the
daemons.

    
    
    service rpki-ca restart
    

You should see all four daemons running

    
    
    /bin/ps axu | grep rpki.conf | grep -v grep
    root      1541  0.1  4.0  42244 20580 ?        Ss   Aug07   2:15 /usr/bin/python /usr/lib/rpki/irdbd --config /etc/rpki.conf --log-level warning --log-syslog daemon
    root      1543  0.1  2.8  35144 14232 ?        Ss   Aug07   3:37 /usr/bin/python /usr/lib/rpki/rpkid --config /etc/rpki.conf --log-level warning --log-syslog daemon
    root      1546  0.0  1.9  33584  9780 ?        Ss   Aug07   0:00 /usr/bin/python /usr/lib/rpki/pubd --config /etc/rpki.conf --log-level warning --log-syslog daemon
    root      1559  0.0  1.8  24496  9608 ?        Ss   Aug07   0:22 /usr/bin/python /usr/lib/rpki/rootd --config /etc/rpki.conf --log-level warning --log-syslog daemon
    

### Initializing the CA

The command utility, `rpkic` is a CLI for dealing with the CA. This example
uses it instead of the GUI, especially for initial setup, as it is easier to
copy and paste into a wiki. The CLI has tab completion, and the other features
offered by readline().

rpkic has the concept of the current identity. Initially, it starts with the
identity from the handle in `/etc/rpki.conf`, testCA in this example

    
    
    rpkic
    rpkic> 
    

Before you do anything else, you need to initialize the CA.

    
    
    rpkic> initialize
    Wrote /usr/share/rpki/testCA.testCA.repository-request.xml
    This is the "repository offer" file for you to use if you want to publish in your own repository
    Writing /usr/share/rpki/ca.crl
    Writing /usr/share/rpki/rootd.key
    Writing /usr/share/rpki/rootd.cer
    Writing /usr/share/rpki/child.cer
    

The root instance will need a repository, so it should accept its own offer
made above

    
    
    rpkic> configure_publication_client /usr/share/rpki/testCA.testCA.repository-request.xml
    This looks like an offer, checking
    This client's parent is rootd
    Don't know where to nest this client, defaulting to top-level
    Client calls itself 'testCA', we call it 'testCA'
    Client says its parent handle is 'testCA'
    Wrote /usr/share/rpki/testCA.repository-response.xml
    Send this file back to the publication client you just configured
    

And then configure the repository using the response

    
    
    rpkic> configure_repository /usr/share/rpki/testCA.repository-response.xml
    Repository calls us 'testCA'
    Repository response associated with parent_handle 'testCA'
    rpkic> 
    

You can see if it is publishing

    
    
    ls -l /usr/share/rpki/publication
    total 16
    -rw-r--r-- 1 root root  433 Aug  7 07:38 root.crl
    -rw-r--r-- 1 root root 1747 Aug  7 07:38 root.mft
    drwxr-xr-x 2 root root 4096 Aug  7 07:38 testCA/
    -rw-r--r-- 1 root root 1219 Aug  7 07:38 testCA.cer
    

### The GUI Should Now Work

One simple test is to try the GUI. But first you need to set up the GUI
superuser password. [ insert lecture on strong passwords ]

    
    
    rpki-manage createsuperuser
    Username (leave blank to use 'root'): 
    Email address: randy@psg.com
    Password: 
    Password (again): 
    Superuser created successfully.
    

and write it down somewhere safe.

Then you can point your browser at `https://test.dfw.rg.net`, and you should
see the login page. Enter the user 'root' and the password from
createsuperuser above. This should take you to testCA's dashboard. For some
reason, it often comes up with no resources; so push the Refresh button, and
it should show that you own the whole Internet!

   [1]: http://www.rfc-editor.org/rfc/rfc6810.txt

