# Download and Installation

There are a few different ways to install the RPKI code, depending on what the
platform on which you're trying to install.

  * On Ubuntu 12.04 LTS ("Precise Pangolin"), Ubuntu 14.04 ("Trusty Tahir"), or Debian 7 ("Wheezy"), you can use [Debian binary packages][1]. 

## Simple RPKI Cache Install

if you want to install a simple RPKI cache to feed routers from a Ubuntu 14.04
system, [here is a one page ten minute recipe][2].

## install a CA and a cache on a Ubuntu 14.04 with a rootd CA

If you want to install a CA and a cache on a Ubuntu 14.04 with a rootd CA,
[here is a one page hack][3]. It will take less than an hour.

## Try the rrdp testbed CA and RP on Ubuntu Xenial

If you are feeling adventurous and want to try the rrdp testbed CA and RP on
Ubuntu Xenial 16.04 [here is a one page hack.][4] It supports a much simpler
root CA.

## FreeBSD

On FreeBSD, you can use [FreeBSD ports][5].

## Other Platforms

On all other platforms, or on the above platforms if the pre-packaged versions
don't suit your needs, you will have to [install from source code][6].

Once you've finished installing the code, you will need to configure it. Since
CAs are generally also relying parties (if only so that they can check the
results of their own actions), you will generally want to start by configuring
the [relying party tools][7], then configure the [CA tools][8] if you're
planning to use them.

   [1]: #_.wiki.doc.RPKI.Installation.DebianPackages

   [2]: #_.wiki.doc.RPKI.doc.RPKI.Installation.UbuntuRP

   [3]: #_.wiki.doc.RPKI.doc.RPKI.Installation.UbuntuRootd

   [4]: #_.wiki.doc.RPKI.RRDPtestbed

   [5]: #_.wiki.doc.RPKI.Installation.FreeBSDPorts

   [6]: #_.wiki.doc.RPKI.Installation.FromSource

   [7]: #_.wiki.doc.RPKI.RP

   [8]: #_.wiki.doc.RPKI.CA

