# rpki.net project site

This is the Trac site for the rpki.net project. The project provides a free,
BSD License, open source, complete system for the Internet Registry or ISP. It
includes separate components which may be combined to suit your needs:

  * Certification Engine 
  * Relying Party Cache (sometimes called a 'validator') 
  * rpki-rtr protocol, to feed the data to routers doing RPKI-based origin validation 
  * GUI for use by users of the 'hosted' model (i.e. customers who do not run their own CA) 
  * Web Reporting Pages so you can see what your cache has found 
  * Creation of pseudo-IRR data for those who wish to feed RPSL toolchains 

If you're looking for the general RPKI Wiki (not specific to our software),
it's [over here][1].

## Downloads

See [the documentation][2] for how to download and install the code.

We now have [Debian packages][3], [Ubuntu packages][4], and [FreeBSD ports][5]
of the code.

You can also [browse the source code][6].

## Documentation

Primary [documentation for the code][2] is here, in the Trac wiki. PDF and
flat text forms derived from are available in [the source code repository][6].

## Bug Reports

The [ticket queue][7] is open for public read. Please [register for an
account][8] if you need to create a ticket.

## Monitoring

[Current status of RPKI system as seen by one relying party][9].

## TLS Certificate

If you're trying to connect to this site (<https://rpki.net/>) using HTTPS,
you may see warnings about an untrusted certificate. There's nothing wrong,
this just means that your web browser doesn't know about the Certification
Authority that we use.

You can [download a PGP-signed version of the HACTRN CA certificate][10] to
fix this.

If you don't care about checking the CA certificate and just want the warning
to go away, you can set a browser exception or just [install the HACTRN CA
certificate][11] without checking it.

## APRICOT 2013

Hot link to information for [APRICOT 2013 Hackathon][12].

Thanks to JPNIC, [a VirtualBox appliance image][13] is available, [with
documentation][14].

   [1]: http://wiki.rpki.net/

   [2]: /wiki/doc/RPKI

   [3]: http://download.rpki.net/APT/debian/

   [4]: http://download.rpki.net/APT/ubuntu/

   [5]: http://download.rpki.net/FreeBSD_Packages/

   [6]: /browser

   [7]: /query

   [8]: /register

   [9]: http://www.hactrn.net/opaque/rcynic/

   [10]: http://www.hactrn.net/cacert.asc

   [11]: http://www.hactrn.net/cacert.cer

   [12]: #_.wiki.APRICOT-2013-Hackathon

   [13]: http://psg.com/rpki/RPKI-CA-RP.ova

   [14]: http://psg.com/rpki/RPKI-VM.pdf

