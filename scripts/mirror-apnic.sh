#!/bin/sh -
# $Id$

# An unknown entity representing itself as gmm says that this is the
# trust anchor for the APNIC test repository.
#
fetch -m -o repository.apnic.net/trust-anchor.cer \
    http://mirin.apnic.net/resourcecerts/trust-anchor.cer

# Mirror the repository itself
#
rsync -aiz --delete rsync://repository.apnic.net/APNIC/ repository.apnic.net/APNIC/
