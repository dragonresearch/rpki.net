#!/bin/sh -

ls | fgrep -v . |
while read page
do
    base="https://trac.rpki.net"
    path="/wiki/$(echo $page | sed s=%2F=/=g)"

    # Fetch the Wiki page, extract the useful portion of the HTML, convert that into Markdown
    curl "${base}${path}" |
    xsltproc --html extract-wiki-content.xsl - |
    html2markdown --no-skip-internal-links --reference-links >"$page.md"

    # Fetch a ZIP file containing any attachments, clean up if result is empty or broken
    curl "${base}/zip-attachment${path}/" >"$page.zip"
    zipinfo "$page.zip" >/dev/null 2>&1 || rm -f "$page.zip"

done
