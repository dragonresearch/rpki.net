#!/bin/sh -
# $Id$
#
# Test client using APNIC's rpki_poke.pl script.

: ${pokedir=../../mirin.apnic.net/rpki_engine/branches/gary-poker/client/poke}

exec perl -I $pokedir $pokedir/rpki_poke.pl ${1+"$@"}
