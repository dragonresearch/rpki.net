# $Id$
#
# Nasty hack to generate debian/changelog entries from subversion.
# This is useful to the extent that it allows us to generate new
# packages automatically with version numbers corresponding to
# subversion revisions; the human-readable part of the changelog may
# or may not be all that useful
#
#
# Copyright (C) 2013 Internet Systems Consortium, Inc. ("ISC")
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.


import debian.changelog
import email.utils
import subprocess
import textwrap
import time
import calendar
import errno
import os

try:
    from lxml.etree            import XML
except ImportError:
    from xml.etree.ElementTree import XML

fn = "debian/changelog"

ignore_trivial_changes = False

trivial_changes =  ("Pull from trunk.", "Merge from trunk.", "Checkpoint.", "Cleanup.")

# Fill this in (somehow) with real email addresses if and when we
# care.  Right now we only care to the extent that failing to comply
# with the required syntax breaks package builds.

author_map = {}

author_default_format = "%s <%s@rpki.net>"

# Main

changelog = debian.changelog.Changelog()

try:
    with open(fn) as f:
        changelog.parse_changelog(f)
        latest = int(str(changelog.version).split(".")[1])
        print "Parsed", fn, "latest change", latest
except IOError, e:
    if e.errno == errno.ENOENT:
        print fn, "not found, starting new changelog"
        latest = 0
    else:
        raise

print "Pulling change list from subversion"

svn = XML(subprocess.check_output(("svn", "log", "--xml", "--revision", "%s:COMMITTED" % (latest + 1))))

first_wrapper = textwrap.TextWrapper(initial_indent = "  * ", subsequent_indent = "    ")
rest_wrapper  = textwrap.TextWrapper(initial_indent = "    ", subsequent_indent = "    ")

changed = 0

print "Generating new change entries"

for elt in svn.findall("logentry"):
    msg = elt.findtext("msg")
    author = elt.findtext("author")

    if ignore_trivial_changes and (msg in trivial_changes or msg + "." in trivial_changes):
        continue

    author = author_map.get(author, author_default_format % (author, author))

    changelog.new_block(
        package         = changelog.package,
        version         = "0." + elt.get("revision"),
        distributions   = changelog.distributions,
        urgency         = changelog.urgency,
        author          = author,
        date            = email.utils.formatdate(calendar.timegm(time.strptime(elt.findtext("date"),
                                                                        "%Y-%m-%dT%H:%M:%S.%fZ"))))
    changelog.add_change("\n\n".join((rest_wrapper if i else first_wrapper).fill(s)
                                     for i, s in enumerate(msg.split("\n\n"))))

    changed += 1

if changed:
    print changed, "new entries"
    with open(fn + ".new", "w") as f:
        print "Writing", f.name
        changelog.write_to_open_file(f)
    print "Renaming %s.new to %s" % (fn, fn)
    os.rename(fn + ".new", fn)
else:
    print "No changes"
