#!/bin/sh

i=oix-full-snapshot-latest.dat.bz2
o=/tmp/$i

#curl -s -S -o $o http://archive.routeviews.org/oix-route-views/$i
# wget is stock in Ubuntu so use that instead of curl
wget -q -O $o http://archive.routeviews.org/oix-route-views/$i

if [ $? -eq 0 ]; then
       rpkigui-import-routes -l error $o
fi
