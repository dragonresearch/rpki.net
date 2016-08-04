# RPKI Manual Table Of Contents

**DANGER, WILL ROBINSON!!** **

**This is not a normal Wiki page, it's input to a Trac macro.**

**Read carefully before touching anything here.**

This page is the table of contents for the RPKI manual. This uses the TracNav
macro, to avoid replicating the list of pages everywhere; instead, each page
uses TracNav to refer to this page, which contains the one and only copy. This
list is also used to generate the PDF and flat text documentation, via some ad
hoc scripting and a preprosterous set of text processing tools.

Be very careful when modifying this page. In particular, be careful about
modifying the following list, as messing it up will break the navigation for
the entire manual.

Also note that syntax for links containing square brackets in the label is
very tricky and somewhat fragile. We use this for TOC entries corresponding to
rpki.conf sections. We can do this using WikiCreole? link syntax so long as we
have whitespace before the double close square bracket that ends the link.
Yes, this is a kludge. See <http://trac.edgewall.org/ticket/616> for details.

  * [RPKI Tools][1]
    * [Installation][2]
      * [Debian and Ubuntu Binary Packages][3]
      * [FreeBSD Ports][4]
      * [Installing From Source Code][5]
    * [Relying Party Tools][6]
      * [rcynic][7]
      * [rpki-rtr][8]
      * [Alternative cron jobs][9]
      * [Hierarchical rsync][10]
      * [Running rcynic chrooted][11]
    * [CA Tools][12]
      * [Configuration][13]
        * [Common Options][14]
        * [ [myrpki] section ][15]
        * [ [rpkid] section ][16]
        * [ [irdbd] section ][17]
        * [ [pubd] section ][18]
        * [ [rootd] section ][19]
        * [Creating a RPKI Root Certificate][20]
        * [ [web_portal] section ][21]
        * [ [autoconf] section ][22]
        * [Test configuration][23]
        * [Using Different Servers][24]
      * [MySQL Setup][25]
      * [The out-of-band setup protocol][26]
      * [The user interface][27]
        * [Command line interface][28]
        * [Web interface][29]
          * [Installing the GUI][30]
          * [Upgrading the GUI][31]
          * [Before migrating the GUI][32]
          * [Configuring the GUI][33]
          * [Configuring Apache for the GUI][34]
          * [GUI user model][35]
        * [The left-right protocol][36]
    * [Utility programs][37]
    * [Protocol diagrams][38]
      * [Out-of-band setup protocol][39]
      * ["Up-Down" provisioning protocol][40]

I (sra) just added the GUI subpages as they were missing entirely. Titles
might need work, and we don't yet know whether the HTML-to-text hack will work
on these as we haven't tried it yet.

The following is a non-list of nodes in the old (Doxygen) manual which don't
currently have any place in the new manual. I haven't yet figured out which of
these we should keep, or where to put them. So long as they aren't formatted
as part of the Wiki list, TracNav will ignore them.

Not sure where these should go yet. Perhaps a RPKI/CA/Reference section,
except that sounds too much like a command reference.

RPKI/CA/Protocols/Publication RPKI/CA/SQLSchemas RPKI/CA/SQLSchemas/pubd
RPKI/CA/SQLSchemas/rpkid RPKI/CA/BPKIModel

   [1]: #_.wiki.doc.RPKI

   [2]: #_.wiki.doc.RPKI.Installation

   [3]: #_.wiki.doc.RPKI.Installation.DebianPackages

   [4]: #_.wiki.doc.RPKI.Installation.FreeBSDPorts

   [5]: #_.wiki.doc.RPKI.Installation.FromSource

   [6]: #_.wiki.doc.RPKI.RP

   [7]: #_.wiki.doc.RPKI.RP.rcynic

   [8]: #_.wiki.doc.RPKI.RP.rpki-rtr

   [9]: #_.wiki.doc.RPKI.RP.RunningUnderCron

   [10]: #_.wiki.doc.RPKI.RP.HierarchicalRsync

   [11]: #_.wiki.doc.RPKI.RP.rcynicChroot

   [12]: #_.wiki.doc.RPKI.CA

   [13]: #_.wiki.doc.RPKI.CA.Configuration

   [14]: #_.wiki.doc.RPKI.CA.Configuration.Common

   [15]: #_.wiki.doc.RPKI.CA.Configuration.myrpki

   [16]: #_.wiki.doc.RPKI.CA.Configuration.rpkid

   [17]: #_.wiki.doc.RPKI.CA.Configuration.irdbd

   [18]: #_.wiki.doc.RPKI.CA.Configuration.pubd

   [19]: #_.wiki.doc.RPKI.CA.Configuration.rootd

   [20]: #_.wiki.doc.RPKI.CA.Configuration.CreatingRoot

   [21]: #_.wiki.doc.RPKI.CA.Configuration.web_portal

   [22]: #_.wiki.doc.RPKI.CA.Configuration.autoconf

   [23]: #_.wiki.doc.RPKI.CA.Configuration.Tests

   [24]: #_.wiki.doc.RPKI.CA.Configuration.DifferentServer

   [25]: #_.wiki.doc.RPKI.CA.MySQLSetup

   [26]: #_.wiki.doc.RPKI.CA.OOBSetup

   [27]: #_.wiki.doc.RPKI.CA.UI

   [28]: #_.wiki.doc.RPKI.CA.UI.rpkic

   [29]: #_.wiki.doc.RPKI.CA.UI.GUI

   [30]: #_.wiki.doc.RPKI.CA.UI.GUI.Installing

   [31]: #_.wiki.doc.RPKI.CA.UI.GUI.Upgrading

   [32]: #_.wiki.doc.RPKI.CA.UI.GUI.Upgrading.BeforeMigration

   [33]: #_.wiki.doc.RPKI.CA.UI.GUI.Configuring

   [34]: #_.wiki.doc.RPKI.CA.UI.GUI.Configuring.Apache

   [35]: #_.wiki.doc.RPKI.CA.UI.GUI.UserModel

   [36]: #_.wiki.doc.RPKI.CA.Protocols.LeftRight

   [37]: #_.wiki.doc.RPKI.Utils

   [38]: #_.wiki.doc.RPKI.Protocols

   [39]: #_.wiki.doc.RPKI.Protocols.OOB

   [40]: #_.wiki.doc.RPKI.Protocols.Up-Down

