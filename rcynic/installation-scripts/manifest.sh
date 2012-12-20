#!/bin/sh -
# $Id$

echo >>${abs_top_builddir}/installation-manifest D %%RCYNICJAILDIR%%
echo >>${abs_top_builddir}/installation-manifest D %%RCYNICJAILDIR%%/bin
echo >>${abs_top_builddir}/installation-manifest D %%RCYNICJAILDIR%%/dev
echo >>${abs_top_builddir}/installation-manifest D %%RCYNICJAILDIR%%/etc
echo >>${abs_top_builddir}/installation-manifest D %%RCYNICJAILDIR%%/etc/trust-anchors
echo >>${abs_top_builddir}/installation-manifest D %%RCYNICJAILDIR%%/var
echo >>${abs_top_builddir}/installation-manifest D %%RCYNICJAILDIR%%/data

echo >>${abs_top_builddir}/installation-manifest F %%RCYNICJAILDIR%%/bin/rcynic
echo >>${abs_top_builddir}/installation-manifest F %%RCYNICJAILDIR%%/bin/rsync
echo >>${abs_top_builddir}/installation-manifest F %%RCYNICJAILDIR%%/bin/rcynic-html

# Not sure what to do about %%RCYNICJAILDIR%%/${libdir}/* on Linux, as we
# don't know what goes there until we compute the transitive closure
# of ldd dependencies.  Ick.  Ignore for now.

case "${host_os}" in
freebsd*)	echo >>${abs_top_builddir}/installation-manifest F %%RCDIR%%/rcynic;;
darwin*)	echo >>${abs_top_builddir}/installation-manifest F /Library/StartupItems/RCynic;;
esac
