#!/usr/bin/awk -f
# $Id$
#
# This doesn't really work right yet, and even if it did, the graph
# it would generate would be hopelessly large.

BEGIN {
  cmd = "find /var/rcynic/data/unauthenticated -type f -name '*.cer' -print0 | xargs -0 ./uri -d";
  while ((cmd | getline) == 1) {
    if ($1 == "File") {
      sub("/var/rcynic/data/unauthenticated/", "rsync://");
      u = $2;
      uri[u] = ++n;
      continue;
    }
    if ($1 == "SIA:") {
      sia[u] = $2;
      continue;
    }
    if ($1 == "AIA:") {
      aia[u] = $2;
      continue;
    }
  }
  print "digraph rpki {";
  for (u in uri) {
    printf "n%06d\t[ label=\"%s\" ];\n", uri[u], u;
    if (sia[u])
      printf "n%06d -> n%06d\t [ color=blue ];\n", uri[u], uri[sia[u]];
    if (aia[u])
      printf "n%06d -> n%06d\t [ color=green ];\n", uri[u], uri[aia[u]];
  }
  print "}";
}
