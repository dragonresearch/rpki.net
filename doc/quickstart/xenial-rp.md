# Ubuntu xenial 16.04 RPKI Relying Party Cache Install

Given a running Ubuntu 16.04 xenial server, this should take ten
minutes.

## System Requirements

I built the following:

  * 32GB of hard disk, enough to leave headroom unless you plan a LOT of
    certificates, as in thousands;  
  * 1GB or RAM, as it still is a bit of a RAM hog; and 
  * One CPU should be enough to start. 
  * The server must not have an AAAA DNS RR unless it has working IPv6
    connectivity.  

## Ingredients

You can start with the following:

  * [16.04 Ubuntu Xenial LTS 64-bit server](http://releases.ubuntu.com/16.04/ubuntu-16.04-server-amd64.iso)
  * I do a fairly basic install, OpenSSH, basic utilities, and grub 
  * apt update and apt dist-upgrade of course 
  * I install automatic updates, emacs-nox, ntp, ... with ansible. Note
    that ansible requires python2 and xenial installs python3. So I had to
    install python2.7 

I am lazy and log in as root as pretty much everything I do is going to
require being root. If you like sudo, then just prefix a lot with it.

## Install the Basic RPKI RP Software

You should only need to perform these steps once for any particular
machine.

Add the GPG public key for this repository (optional, but APT will whine
unless you do this):
    
    # wget -q -O /etc/apt/trusted.gpg.d/rpki.asc   https://download.rpki.net/APTng/apt-gpg-key.asc
    
Configure APT to use this repository (for Ubuntu Xenial):

    # wget -q -O /etc/apt/sources.list.d/rpki.list https://download.rpki.net/APTng/rpki.xenial.list
    
Update available packages:
    
    # apt update

Install the software:
    
    # apt install rpki-rp

## Minimal Configuration

This example install uses the server hostname `test.dfw.rg.net`. Any use of
that hostname below will have to be replaced with your host's name, of course.

### Relying Party - rcynic

The RP (Relying Party) software should have installed and should be
running.  You can test it by browsing to
<https://test.dfw.rg.net/rcynic/> (use your URL, of course).  It uses a
self-signed TLS certificate; you can be lazy and decided to accept it as
opposed to installing a real one.  If you want to use a Let's Encrypt
certificate, you might try [this homegrown recipe using
acme_tiny.py](https://wiki.rg.net/AcmeTinyUbuntu), which will require a
bit of hacking as the rpki package puts apache credentials in an odd
place.

The rcynic web page is likely not yet populated because the cron job to
populate is generated for a socially polite cache which fetches once an
hour.
    
    # crontab -l -u rpki
    MAILTO=root
    42 * * * *      exec /usr/bin/rcynic-cron

Do not change this now as it would place an asocial load on the global RPKI.

If you plan to use the rpki-rtr protocol to feed a router from the RP cache
you just installed, check `/etc/xinetd.d/rpki-rtr` to be sure the port number
is 323, the IANA assigned port, as opposed to some old hacks that were used
pre [RFC 6810](http://www.rfc-editor.org/rfc/rfc6810.txt).

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
    
The configuration for rcynic is in `/etc/rpki.conf`. Note that it says
to use the trust anchors in the directory `/etc/rpki/trust-anchors`. You
may want to change the set of trust anchors if you have unusual
requirements.

That's it!
