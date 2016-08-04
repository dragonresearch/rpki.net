# Ubuntu trusty 14.04 RPKI Relying Party Cache Install

Given a running Ubuntu 14.04 server, this should take ten minutes.

## Ingredients

You can start with the following:

  * A small VM, 4GB disk, 512MB RAM, one processor 
  * Ubuntu 14.04 i386 server version 
  * opensshd, and 
  * Emacs, of course 

I am lazy and log in as root as pretty much everything I do is going to
require being root. If you like sudo, then just prefix a lot with it.

This example uses apt-get. If you prefer other tools, see the more detailed
page, <https://trac.rpki.net/wiki/doc/RPKI/Installation/DebianPackages>.

## Install the Basic RPKI RP Software

You should only need to perform these steps once for any particular machine.

Add the GPG public key for this repository (optional, but APT will whine
unless you do this):

    
    
    wget -q -O - http://download.rpki.net/APT/apt-gpg-key.asc | sudo apt-key add -
    

Configure APT to use this repository (for Ubuntu Trusty systems):

    
    
    wget -q -O /etc/apt/sources.list.d/rpki.list http://download.rpki.net/APT/rpki.trusty.list
    

Update available packages:

    
    
    apt-get update
    

Install the software:

    
    
    apt-get install rpki-rp
    

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

That's it!

   [1]: http://www.rfc-editor.org/rfc/rfc6810.txt

