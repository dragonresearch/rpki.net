# List of RPKI programs

This is the beginning of a list of all the programs included in the RPKI
toolkit. It's not complete yet. At the moment, its primary purpose is just to
move fragments of such a list out of other documentation pages where they just
clutter things up and make the text unreadable.

## RP tools

Relying party ("RP") tools.

### rcynic

rcynic is the primary validation tool.

See the [rcynic documentation][1] for details.

### rcynic-html

rcynic-html is a post-processor which converts rcyic's XML status output into
a set of HTML pages displaying status and history.

### rcynic-cron

rcynic-cron is a small script to run the most common set of relying party
tools under cron.

### rtr-origin

rtr-origin is an implementation of the rpki-rtr protocol, using [rcynic's][2]
output as its data source.

See the [rtr-origin documentation][3] for details.

### roa-to-irr

roa-to-irr is an experimental program for converting RPKI ROA data into IRR
data. Some operators have established procedures that depend heavily on IRR,
so being able to distribute validated RPKI data via IRR is somewhat useful to
these operators.

roa-to-irr expects its output to be piped to the `irr_rpsl_submit` program.

Opinions vary regarding exactly what the RPSL corresponding to a particular
set of ROAs should look like, so roa-to-irr is currently experimental code at
best. Operators who really care about this may well end up writing their own
ROA to IRR conversion tools.

   [1]: #_.wiki.doc.RPKI.RP.rcynic

   [2]: #_.wiki.doc.RPKI.ListOfPrograms#rcynic

   [3]: #_.wiki.doc.RPKI.RP.rpki-rtr

