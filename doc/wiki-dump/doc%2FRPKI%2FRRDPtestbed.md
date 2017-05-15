# Building a DRLng Certificate Authority on Ubuntu Xenial

I wanted to build a DRLng (rrdp, integrated root CA, seriously reworked and
meaner and leaner) Certificate Authority.

  * I prefer Ubuntu these days. 
  * I wanted to build it on Ubuntu Xenial because Xenial has the upgraded TLS for rrdp. 

## System Requirements

I built the following:

  * 32GB of hard disk, enough to leave headroom unless you plan a LOT of certificates, as in thousands; 
  * 2GB or RAM, as it still is a bit of a RAM hog; and 
  * One CPU should be enough to start. 
  * The server must not have an AAAA DNS RR unless it has working IPv6 connectivity. 

## Xenial Install

  * [16.04 Ubuntu Xenial LTS 64-bit server][1]
  * I do a fairly basic install, OpenSSH, basic utilities, and grub 
  * apt update and apt dist-upgrade of course 
  * I install automatic updates, emacs-nox, ntp, ... with ansible. Note that ansible requires python2 and xenial installs python3. So I had to install python2.7 

I am lazy and log in as root as pretty much everything I do is going to
require being root. If you like sudo, then just prefix a lot with it.

## Install the Basic RPKI CA and RP Software

You should only need to perform these steps once for any particular machine.

Add the GPG public key for this repository (optional, but APT will whine
unless you do this):
    
    # wget -q -O - http://download.rpki.net/APTng/apt-gpg-key.asc | sudo apt-key add -
    
Configure APT to use this repository (for Ubuntu Trusty systems):

    # wget -q -O /etc/apt/sources.list.d/rpki.list http://download.rpki.net/APTng/rpki.trusty.list
    

Update available packages:

    
    
    # apt update
    

Install the software:

    
    
    # apt install rpki-rp rpki-ca
    

500kg of packages will be installed. The daemons should also be started.

    
    
    # /bin/ps axu | grep rpki | grep -v grep
    rpki      5250  0.0  0.4 308040  8404 ?        Sl   07:37   0:00 (wsgi:rpkigui)    -k start
    rpki      5436  0.0  0.4  45184  9380 ?        Ss   07:37   0:00 /usr/bin/python /usr/lib/rpki/rpki-nanny --log-level warning --log-directory /var/log/rpki --log-rotating-file-hours 3 --log-backup-count 56
    rpki      5437  1.1  2.2 220204 45584 ?        S    07:37   0:00 /usr/bin/python /usr/lib/rpki/irdbd --foreground --log-level warning --log-timed-rotating-file /var/log/rpki/irdbd.log 3 56
    rpki      5439  1.1  2.0 206428 42220 ?        S    07:37   0:00 /usr/bin/python /usr/lib/rpki/pubd --foreground --log-level warning --log-timed-rotating-file /var/log/rpki/pubd.log 3 56
    postgres  5499  0.0  0.7 302016 15272 ?        Ss   07:37   0:00 postgres: rpki rpki [local] idle
    

## Minimal Configuration

This example install uses the server hostname `ca.rg.net`. Any use of that
hostname below will have to be replaced with your host's name, of course.

### Relying Party - rcynic

The RP (Relying Party) software should have installed and should be running.
You can test it by browsing to <https://ca.rg.net/rcynic/>. It uses a self-
signed TLS certificate; you can be lazy and decided to accept it as opposed to
installing a real one. If you want to use a Lets Encrypt certificate, you
might try [this homegrown recipe using acme_tiny.py][2], which will require a
bit of hacking as the rpki package puts apache credentials in an odd place.

!!!!!!!!! THE RCYNIC PAGE IS EMPTY !!!!!!

The rcynic web page has not populated yet because the cron job to populate is
generated for a socially polite cache which fetches once an hour.

    
    
    # crontab -l -u rpki
    MAILTO=root
    41 * * * *      exec /usr/bin/rcynic-cron
    

Do not change this now as it would place an asocial load on the global RPKI.

If you plan to use the rpki-rtr protocol to feed a router from the RP cache
you just installed, check `/etc/xinetd.d/rpki-rtr` to be sure the port number
is 323, the IANA assigned port, as opposed to some old hacks that were used
pre [RFC 6810][3].

    
    
    # cat > /etc/xinetd.d/rpki-rtr << EOF
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
    EOF
    

If you have to change it, remember to

    
    
    # systemctl restart xinetd
    

The configuration for rcynic is in `/etc/rpki.conf`. Note that it says to use
the trust anchors in the directory `/etc/rpki/trust-anchors`. You may want to
change the set of trust anchors if you have unusual requirements.

### CA Configuration - rpki.conf

`/etc/rpki.conf` is the core configuration file for the CA. You need to make
very minimal changes. If you want an explanation for all the options, go to
<https://trac.rpki.net/wiki/doc/RPKI/CA/Configuration>. Get coffee first.

`handle` is generated as `ca_rg_net` or whatever. You may want to change it to
something more intuitive such as `testCA` or whatever you like. You do not
really need to do this, but let's assume you do. I changed it to `RGnet`, as I
was creating a CA for RGnet's resources.

The `handle` in rpkic.conf is a historical relic (dating back to the
`myrpki.xml` interface, circa 2008). It's become just the default for `-i` /
`--identity` / `select_identity` and may eventually go away completely.

If you may offer publication services to other CAs, you will want to put the
contact email in `pubd_contact_info`.

Observe that the `publication_base_directory` expands/decodes to
`/usr/share/rpki/publication`. Similarly, `bpki_servers_directory` decodes to
`/usr/share/rpki`.

That is it for configuration of `/etc/rpki.conf`!

### rsyncd Configuration

Next, you want to get the rsync daemon working. First you need to tell the
rsync daemon what it should serve. So configure `/etc/rsyncd.conf` as follows:

    
    
    # cat > /etc/rsyncd.conf << EOF
    uid             = nobody
    gid             = rpki
    
    [rpki]
        use chroot          = no
        read only           = yes
        transfer logging    = yes
        path                = /usr/share/rpki/publication
        comment             = RPKI publication
    
    # the following is only of you plan to run a root CA
    [tal]
        use chroot          = no
        read only           = yes
        transfer logging    = yes
        path                = /usr/share/rpki/rrdp-publication
        comment             = altCA TAL
    EOF
    

Then tell xinetd to run the rsync deamon when asked and then to restart xinetd

    
    
    # cat > /etc/xinetd.d/rsync << EOF
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
    

Remember to

    
    
    # systemctl restart xinetd
    

## CA Data Initialization

The remaining configuration is done using the RPKI software itself.

### Starting Services

Before configuring the CA daemon and database, you should first restart the
daemons.

    
    
    # systemctl restart rpki-ca
    

You should see the daemons running

    
    
    # /bin/ps axu | grep rpki | grep -v grep
    rpki      5250  0.1  2.7 546316 57316 ?        Sl   07:37   0:00 (wsgi:rpkigui)    -k start
    rpki      5597  0.0  0.3  25348  7132 ?        Ss   07:42   0:00 /usr/bin/python /usr/bin/rcynic-cron
    rpki      5598 25.6  5.7 287132 116880 ?       R    07:42   1:44 /usr/bin/python /usr/bin/rcynic
    postgres  5601  9.9  4.4 305024 91336 ?        Rs   07:42   0:40 postgres: rpki rpki [local] idle
    rpki      7183  0.0  0.4  45184  9440 ?        Ss   07:48   0:00 /usr/bin/python /usr/lib/rpki/rpki-nanny --log-level warning --log-directory /var/log/rpki --log-rotating-file-hours 3 --log-backup-count 56
    rpki      7184  4.0  2.2 220140 45848 ?        S    07:48   0:00 /usr/bin/python /usr/lib/rpki/irdbd --foreground --log-level warning --log-timed-rotating-file /var/log/rpki/irdbd.log 3 56
    rpki      7186  3.7  2.0 206424 42308 ?        S    07:48   0:00 /usr/bin/python /usr/lib/rpki/pubd --foreground --log-level warning --log-timed-rotating-file /var/log/rpki/pubd.log 3 56
    postgres  7193  0.0  0.6 302016 13104 ?        Ss   07:48   0:00 postgres: rpki rpki [local] idle
    

### Initializing the CA

The command utility, `rpkic` is a CLI for dealing with the CA. This example
uses it instead of the GUI, especially for initial setup, as it is easier to
copy and paste into a wiki. The CLI has tab completion, and the other features
offered by readline().

It makes life easier if you do all this in a sub-directory to keep it all
together. Also, files are written and read from the current directory, often
with code running under the uid of rpki. So make the director writiable by
that uid.

    
    
    # mkdir CA-data
    # chown rpki CA-data
    # cd CA-data
    

rpkic has the concept of the current identity. Initially, it starts with the
identity from the handle in `/etc/rpki.conf`, RGnetCA in this example

    
    
    # rpkic
    rpkic>
    

Before you do anything else, you need to initialize the CA. Note that we now
use `create_identity` as opposed to `initialize`. As mentioned previously, for
the moment the identity should be the same as the `handle` in /etc/rpki.conf.

    
    
    # rpkic
    # rpkic create_identity RGnet
    Wrote /root/CA-data/RGnet.identity.xml
    This is the "identity" file you will need to send to your parent
    

For testing, copy the identity to the publication point.

    
    
    # rsync RGnet.identity.xml /usr/share/rpki/publication
    

As the publication point now has data, it is recommended that you test it from
a remote system

    
    
    % rsync rsync://ca.rg.net/rpki/RGnet.identity.xml
    -rw-r--r--        1175 2016/04/24 16:53:53 RGnet.identity.xml
    

## Identity and Publication

You need to establish the BPKI relationship with your parent CA. In this case,
that was RIPE

You may want to look below at the [Using the rpkic CLI in setup phase][4] for
a general description of the provisioning steps.

### The Identity/Repository Handshake

I browsed to [RIPE's provisioning page][5] and uploaded /root/CA-
data/RGnet.identity.xml and received back issuer-identity-20160513.xml

I used that file to configure my server's view of its parent

    
    
    # rpkic configure_parent issuer-identity-20160513.xml 
    Parent calls itself '3336711f-25e1-4b5c-9748-e6c58bef82a5', we call it '3336711f-25e1-4b5c-9748-e6c58bef82a5'
    Parent calls us 'f1400649-ab90-4332-b7e3-3da6b7e44cdb'
    Wrote /root/CA-data/RGnet.3336711f-25e1-4b5c-9748-e6c58bef82a5.repository-request.xml
    This is the file to send to the repository operator
    

The CA will need a repository, and we are assuming that we will also host it.
So it should accept its own offer made above

    
    
    # rpkic configure_publication_client RGnet.3336711f-25e1-4b5c-9748-e6c58bef82a5.repository-request.xml 
    This might be an offer, checking
    We don't host this client's parent, so we didn't make an offer
    Don't know where else to nest this client, so defaulting to top-level
    Client calls itself 'RGnet', we call it 'RGnet'
    Wrote /root/CA-data/RGnet.repository-response.xml
    Send this file back to the publication client you just configured
    

And then I configured the repository using the response from above

    
    
    # rpkic configure_repository RGnet.repository-response.xml
    Repository calls us 'RGnet'
    No explicit parent_handle given, guessing parent 3336711f-25e1-4b5c-9748-e6c58bef82a5
    

You can see if it is publishing, maybe using a bit of coercion

    
    
    # rpkic force_publication
    # ls -l /usr/share/rpki/publication
    total 8
    drwxr-xr-x 2 rpki rpki 4096 May 14 07:39 RGnet/
    -rw-r--r-- 1 root root 1175 May 14 07:10 RGnet.identity.xml
    

If the publication sub-directory is not there, go work on something else for a
while and come back.

### The GUI Should Now Work

One simple test is to try the GUI. But first you need to set up the GUI
superuser password. [ insert lecture on strong passwords ]

    
    
    # rpki-manage createsuperuser
    Username (leave blank to use 'rpki'): RGnet
    Email address: randy@psg.com
    Password: 
    Password (again): 
    Superuser created successfully.
    

and write it down somewhere safe.

Then you can point your browser at `https://ca.rg.net`, and you should see the
login page. Enter the user 'RGnet' (per above) and the password from
createsuperuser above. This should take you to RGnet's dashboard.

## Using the rpkic CLI in setup phase

See the [introduction to the user interfaces][6] for an overview of how setup
phase works. The general structure of the setup phase in rpkic is as described
there, but here we provide the specific commands involved. The following
assumes that you have already installed the software and started the servers.

  * The rpkic "initialize" command writes out an "identity.xml" file in addition to all of its other tasks. 
  * A parent who is using rpkic runs the "configure_child" command to configure the child, giving this command the identity.xml file the child supplied as input. configure_child will write out a response XML file, which the parent sends back to the child. 
  * A child who is running rpkic runs the "configure_parent" command to process the parent's response, giving it the XML file sent back by the parent as input to this command. configure_parent will write out a publication request XML file, which the child sents to the repository operator. 
  * A repository operator who is using rpkic runs the "configure_publication_client" command to process a client's publication request. configure_publication_client generates a confirmation XML message which the repository operator sends back to the client. 
  * A publication client who is using rpkic runs the "configure_repository" command to process the repository's response. 

## Creating a New Root Authority

If you also need to be a CA for private address space, legacy space ARIN will
not certify, etc. you will want to create a root CA.

    
    
    # rpkic configure_root
    Generating root for resources ASN: 0-4294967295, V4: 0.0.0.0/0, V6: ::/0
    Wrote /root/CA-stuff/altCA.altCA.repository-request.xml
    This is the file to send to the repository operator
    

creates a weird kind of parent object, gives you back the XML for repository
setup (same as it did before, difference is just the implementation).

configure_root can take an optional --resources argument which configures the
set of resources for the root to hold. As you can see, by default it's
everything (0-4294967295,0.0.0.0/8,::/0).

### Extract Root Certificate and TAL

There are two new commands to extract root cert and TAL:

    
    
    # rpkic extract_root_certificate
    # rpkic extract_root_tal
    

The latter is a bit iffy in the sense that it has no way of knowing how you
really set up all the things beyond its direct control: the TAL it generates
should be correct if you used the default setup, but if you did something
weird (eg, in your Apache or rsyncd configuration) it might have the wrong
URIs, and it has no real way of knowing what you did.

Both certificate and TAL will be written to names derived from the g(SKI) of
the certificate, in the current directory (.).

You can rename the TAL to anything you like, but you should preserve the
g(SKI) filename of the certificate, because that's what the TAL will be
expecting to find.

Note that RRDP does *not* help with publication of the root certificate (the
root certificate is how the RP finds RRDP, not the other way around), so
you'll need to put a copy of the root certificate in the location named by the
HTTPS URI in the TAL (/usr/share/rpki/rrdp-publication/ in the default Ubuntu
setup).

   [1]: http://releases.ubuntu.com/16.04/ubuntu-16.04-server-amd64.iso

   [2]: https://wiki.rg.net/AcmeTinyUbuntu

   [3]: http://www.rfc-editor.org/rfc/rfc6810.txt

   [4]: https://trac.rpki.net/wiki/doc/RPKI/RRDPtestbed#UsingtherpkicCLIinsetupphase

   [5]: https://my.ripe.net/#/provisioning/non-hosted

   [6]: #_.wiki.doc.RPKI

