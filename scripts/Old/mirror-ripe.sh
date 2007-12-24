#!/bin/sh -
# $Id$

# The following are freshly produced in conformance with Geoff &
# George's latest developments - I hope.

# Trust Anchors (consider this an out-of-band delivery method):

# RIPE TA:
fetch -m -o ca-trial.ripe.net/riperoot/repos/root.cer \
    http://ca-trial.ripe.net/~riperoot/repos/root.cer

# ARIN TA: 
fetch -m -o ca-trial.ripe.net/arinroot/repos/root.cer \
    http://ca-trial.ripe.net/~arinroot/repos/root.cer

# The repositories are here:
rsync -aiz --delete rsync://ca-trial.ripe.net/RIPE/ ca-trial.ripe.net/RIPE/
rsync -aiz --delete rsync://ca-trial.ripe.net/ARIN/ ca-trial.ripe.net/ARIN/

# Some test certificates:

# RIPE->RIPE->ISP: 
fetch -m -o ca-trial.ripe.net/ripeprod/repos/ripe-08.cer \
    http://ca-trial.ripe.net/~ripeprod/repos/ripe-08.cer

# ARIN->ARIN->ISP: 
fetch -m -o ca-trial.ripe.net/arinprod/repos/arin-01.cer \
    http://ca-trial.ripe.net/~arinprod/repos/arin-01.cer

# RIPE->ARIN->ISP: 
fetch -m -o ca-trial.ripe.net/arinprod/repos/ripe-01.cer \
    http://ca-trial.ripe.net/~arinprod/repos/ripe-01.cer

# ARIN->RIPE->ISP: 
fetch -m -o ca-trial.ripe.net/ripeprod/repos/arin-01.cer \
    http://ca-trial.ripe.net/~ripeprod/repos/arin-01.cer

# I think they work with full up-down chaining, provided that I copied 
# everything in place.
#
# George, please look at these, I believe I only need your SIA for these to be 
# ready:
#
# RIPE->APNIC cert currently: http://ca-trial.ripe.net/~riperoot/repos/root-0E.cer
# ARIN->APNIC cert currently: http://ca-trial.ripe.net/~arinroot/repos/root-09.cer
