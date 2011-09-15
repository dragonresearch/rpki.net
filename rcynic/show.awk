# $Id$
#
# Copyright (C) 2010-2011  Internet Systems Consortium, Inc. ("ISC")
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

# Prettyprint tab-delimited rcynic summary data.  This is intended as
# a postprocessor for show.xsl.

BEGIN {
  FS = "\t";
  label[++nlabels] = "hostname";
  head["hostname", 1] = "Repository";
  head["hostname", 2] = "Host";
  width["hostname"] = length(head["hostname", 1]);
}

!NF {
  got_labels = 1;
  next;
}

!got_labels {
  label[++nlabels] = $1;
  nh = split($2, h, /[ \t]+/);
  for (i = 1; i <= nh; i++) {
    head[$1, i] = h[i];
    if (length(h[i]) > width[$1])
      width[$1] = length(h[i]);
  }
}

got_labels && $3 ~ /^rsync:\/\/.+/ {
  hostname = $3;
  sub(/^rsync:\/\//, "", hostname);
  sub(/\/.*$/, "", hostname);
  if (!seen[hostname])
    seen[hostname] = ++nhostnames;
  data[hostname, $2]++;
  total[$2]++;
  if (length(hostname) > width["hostname"])
    width["hostname"] = length(hostname);
}

END {

  for (i = 1;; i++) {
    blank = 1;
    for (j = 1; j <= nlabels; j++)
      if (head[label[j], i] && (j == 1 || total[label[j]] > 0))
	blank = 0;
    if (blank)
      break;
    for (j = 1; j <= nlabels; j++) {
      if (j == 1)
	printf "%-*s", width[label[j]], head[label[j], i];
      else if (total[label[j]] > 0)
	printf "   %*s", width[label[j]], head[label[j], i];
    }
    print "";
  }

  for (i in seen)
    hostnames[seen[i]] = i;

  for (i = 1; i <= nhostnames; i++) {
    for (j = 1; j <= nlabels; j++) {
      if (j == 1)
	printf "%-*s", width[label[j]], hostnames[i];
      else if (total[label[j]] > 0)
	printf "   %*s", width[label[j]], data[hostnames[i], label[j]];
    }
    print "";
  }

  for (j = 1; j <= nlabels; j++) {
    if (j == 1)
      printf "%-*s", width[label[j]], "Total";
    else if (total[label[j]] > 0)
      printf "   %*s", width[label[j]], total[label[j]];
  }
  print "";
}
