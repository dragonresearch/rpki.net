#!/usr/bin/awk -f
# $Id$

# ftp -pa ftp://ftp.ripe.net/pub/stats/ripencc/membership/alloclist.txt

function done() {
    for (i = 1; i <= n_allocs; i++)
	print handle "\t" alloc[i];
    n_allocs = 0;
}

/^[a-z]/ {
    done();
    handle = $0;
    nr = NR;
}

NR == nr + 1 {
    name = $0;
}

NR > nr + 2 && NF > 1 {
    alloc[++n_allocs] = $2;
}

END {
    done();
}
