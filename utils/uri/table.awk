#!/usr/bin/awk -f
# $Id$
#
# Reformat uri.c's output in a way that's more useful
# for some kinds of scripting.  Perhaps this functionality should be
# part of uri.c itself, but for now this script will do.

BEGIN {
  cmd = "find /var/rcynic/data/unauthenticated -type f -name '*.cer' -print0 | xargs -0 ./uri -d";
  while ((cmd | getline) == 1) {
    if ($1 == "File") {
      if (f)
	print f, u, a, s, c;
      a = s = c = "-";
      f = $2;
      sub("/var/rcynic/data/unauthenticated/","rsync://");
      u = $2;
      continue;
    }
    if ($1 == "SIA:") {
      s = $2;
      continue;
    }
    if ($1 == "AIA:") {
      a = $2;
      continue;
    }
    if ($1 == "CRL:") {
      c = $2;
      continue;
    }
  }
  if (f != "-")
    print f, u, a, s, c;
}
