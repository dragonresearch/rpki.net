# $Id$
#
# Copyright (C) 2010  Internet Systems Consortium, Inc. ("ISC")
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
}

NR == 1 {
  nf = NF;
  for (i = 1; i <= nf; i++) {
    split($i, h, /[ \t]+/);
    for (j = 1; j <= length(h); j++) {
      head[i, j] = h[j];
      if (length(h[j]) > width[i])
	width[i] = length(h[j]);
    }
  }
}

NR > 1 {
  nr = NR - 1;
  for (j = 1; j <= NF; j++) {
    data[nr, j] = $j;
    sum[j] += $j;
    if (length($j) > width[j])
      width[j] = length($j);
  }
}

END {
  for (i = 1;; i++) {
    blank = 1;
    for (j = 2; j <= nf; j++)
      if (head[j, i] && sum[j] > 0)
	blank = 0;
    if (blank)
      break;
    for (j = 1; j <= nf; j++)
      if (j == 1)
	printf "%*s", width[j], head[j, i];
      else if (sum[j] > 0)
	printf "   %*s", width[j], head[j, i];
    print "";
  }
  for (i = 1; i <= nr; i++) {
    for (j = 1; j <= nf; j++)
      if (j == 1)
	printf "%*s", width[j], data[i, j];
      else if (sum[j] > 0)
	printf "   %*s", width[j], data[i, j];
    print "";
  }
  for (j = 1; j <= nf; j++)
    if (j == 1)
      printf "%*s", width[j], "Total";
    else if (sum[j] > 0)
      printf "   %*s", width[j], sum[j];
  print "";
}
