# -*- Autoconf -*-
# $Id$

AC_PREREQ([2.61])
AC_INIT([rpkitools], [1.0])

# AC_REVISION is a great idea in theory, but the revision will always
# be wrong unless we do two checkins, so skip it for now.  Someday.

dnl AC_REVISION([$Revision$])

AC_CONFIG_SRCDIR([rcynic/rcynic.c])
AC_CONFIG_AUX_DIR([buildtools])

# I'm not sure we should really be using the $host_* variables as we
# are, some of the stuff we're doing with them looks more like
# $target_* to me now, but on the theory that we should not fix things
# that aren't broken, stick with $host_* for now.

AC_CANONICAL_HOST
dnl AC_CANONICAL_TARGET

# Remember whether CFLAGS or LDFLAGS were set explictly.  This has to
# come early in the script, before we mess it up testing things.

if test "x${CFLAGS+set}" = "x" && test "x${LDFLAGS+set}" = "x"
then
	CFLAGS_or_LDFLAGS_were_set=no
else
	CFLAGS_or_LDFLAGS_were_set=yes
fi

# Put the user option stuff up front.

AC_ARG_WITH([system_openssl],		[AS_HELP_STRING([--with-system-openssl],		  [Link against system copy of OpenSSL])],        [], [with_system_openssl=auto])
AC_ARG_ENABLE([rcynic_jail],		[AS_HELP_STRING([--enable-rcynic-jail],			  [Run rcynic in chroot jail])],                  [], [enable_rcynic_jail=no])
AC_ARG_ENABLE([openssl_asm],		[AS_HELP_STRING([--disable-openssl-asm],		  [Don't let OpenSSL build assembler code])],     [], [enable_openssl_asm=auto])
AC_ARG_ENABLE([ca_tools],		[AS_HELP_STRING([--disable-ca-tools],			  [Don't build any of the CA tools])],            [], [enable_ca_tools=yes])
AC_ARG_ENABLE([rp_tools],		[AS_HELP_STRING([--disable-rp-tools],			  [Don't build any of the relying party tools])], [], [enable_rp_tools=yes])
AC_ARG_ENABLE([target_installation],	[AS_HELP_STRING([--disable-target-installation],	  [Don't perform final target installation])],    [], [enable_target_installation=yes])
AC_ARG_ENABLE([wsgi_daemon_mode],	[AS_HELP_STRING([--enable-wsgi-daemon-mode=user[:group]], [Run the web portal as a separate process])],   [], [enable_wsgi_daemon_mode=no])
AC_ARG_ENABLE([python_install_layout],	[AS_HELP_STRING([--enable-python-install-layout=layout],  [Specify Python --install-layout])],		  [], [enable_python_install_layout=auto])

AC_ARG_VAR([RCYNIC_DIR],		[Where to put output files from rcynic and rtr-origin; also controls jail location for --enable-rcynic-jail])

# Obsolete options.  If you know of a better way to handle this, tell me.

AC_ARG_ENABLE([python],   [AS_HELP_STRING([--disable-python],	[(Obsolete, do not use)])], [AC_MSG_ERROR([--disable-python is obsolete.  Please see the --disable-ca-tools option])], [])
AC_ARG_ENABLE([django],   [AS_HELP_STRING([--disable-django],	[(Obsolete, do not use)])], [AC_MSG_ERROR([--disable-django is obsolete.  Please see the --disable-ca-tools option])], [])
AC_ARG_ENABLE([rpki_rtr], [AS_HELP_STRING([--disable-rpki-rtr],	[(Obsolete, do not use)])], [AC_MSG_ERROR([--disable-rpki-rtr is obsolete.  Please see the --disable-rp-tools option])], [])

AC_PROG_CC
AC_PROG_INSTALL

AC_CHECK_SIZEOF([long])

# We'd like to build rcynic as a static binary if we can, because that
# makes it much simpler to run rcynic in a chroot jail, but we don't
# know how to do it on all platforms, so we try the hack we know, and
# if that doesn't work, oh well.
#
# Sadly, it's even worse than this, because there are platforms like
# Fedora where the compiler and linker support -static just fine, but
# the default libraries do not, and if you start down the primrose
# path of installing the necessary libraries, you eventually hit a
# wall where one of the static libraries you downloaded depends on
# something that's not available as a static library, ie, you lose.
#
# So for now I'm just going to make this a FreeBSD-only option.
# Feh. Those of you who choose to use other platforms are welcome to
# fix this and send me the patch, if you care.

dnl  AC_MSG_CHECKING([whether linker supports -static])
dnl  old_LDFLAGS="$LDFLAGS"
dnl  LDFLAGS="$LDFLAGS -static"
dnl  AC_LINK_IFELSE(
dnl  	[AC_LANG_SOURCE([[int main (int argc, char *argv[]) { return 0; }]])],
dnl  	[
dnl  		AC_MSG_RESULT(yes)
dnl  		LD_STATIC_FLAG='-static'
dnl  	],
dnl  	[
dnl  		AC_MSG_RESULT(no)
dnl  		LD_STATIC_FLAG=''
dnl  	]
dnl  )
dnl  LDFLAGS="$old_LDFLAGS"
dnl  unset old_LDFLAGS

case $host_os in
	freebsd*)
		LD_STATIC_FLAG='-static'
		;;
	*)
		LD_STATIC_FLAG=''
		;;
esac
AC_SUBST(LD_STATIC_FLAG)

AC_MSG_CHECKING([whether compiler and linker support -Wl,-Bsymbolic])
old_LDFLAGS="$LDFLAGS"
LDFLAGS="$LDFLAGS -Wl,-Bsymbolic"
AC_LINK_IFELSE([AC_LANG_SOURCE([[int main (int argc, char *argv[]) { return 0; }]])],
	       [linker_supports_Bsymbolic=yes],
	       [linker_supports_Bsymbolic=no])
AC_MSG_RESULT([$linker_supports_Bsymbolic])
LDFLAGS="$old_LDFLAGS"
unset old_LDFLAGS
if test $linker_supports_Bsymbolic = yes
then
	POW_LDFLAGS='-Wl,-Bsymbolic'
else
	POW_LDFLAGS=''
fi
AC_SUBST(POW_LDFLAGS)

AC_MSG_CHECKING([whether compiler and linker support -Wl,-z,noexecstack])
old_LDFLAGS="$LDFLAGS"
LDFLAGS="$LDFLAGS -Wl,-z,noexecstack"
AC_LINK_IFELSE([AC_LANG_SOURCE([[int main (int argc, char *argv[]) { return 0; }]])],
	       [linker_supports_znoexecstack=yes],
	       [linker_supports_znoexecstack=no])
AC_MSG_RESULT([$linker_supports_znoexecstack])
if test $linker_supports_znoexecstack = no
then
	LDFLAGS="$old_LDFLAGS"
fi
unset old_LDFLAGS

AC_PROG_GREP
AC_PATH_PROG([PYTHON], [python])
AC_PATH_PROG([XSLTPROC], [xsltproc])
AC_PATH_PROG([AWK], [awk])
AC_PATH_PROG([SORT], [sort])
AC_PATH_PROG([RRDTOOL], [rrdtool])
AC_PATH_PROG([TRANG], [trang], [\${abs_top_srcdir}/buildtools/trang-not-found])
AC_PATH_PROG([RSYNC], [rsync])

# Figure out whether we need to build our own OpenSSL library or can
# use the system libraries.  We're looking for two recent features:
# CMS and RFC 3779 support.  We also have to check whether the user
# has an opinion on all this.  In the "auto" case (no
# --with-system-openssl option specified in any form), we may need to
# check a platform-specific location (eg, /usr/local on FreeBSD).

old_CFLAGS="$CFLAGS"
old_LDFLAGS="$LDFLAGS"

case $with_system_openssl in
	yes|auto)
		if test $CFLAGS_or_LDFLAGS_were_set = no
		then
			case $host_os in
			freebsd*)
				CFLAGS="-I/usr/local/include $CFLAGS"
				LDFLAGS="-L/usr/local/lib $LDFLAGS"
				;;
			esac
		fi
		;;
	no|/usr)
		:
		;;

	*)
		CFLAGS="-I$with_system_openssl/include $CFLAGS"
		LDFLAGS="-L$with_system_openssl/lib $LDFLAGS"
esac

case $with_system_openssl in
	no)
		have_usable_openssl=no
		;;
	*)
		AC_CHECK_LIB([crypto], [v3_addr_validate_path],
				       [system_openssl_has_rfc3779=yes],
				       [system_openssl_has_rfc3779=no])

		AC_CHECK_LIB([crypto], [CMS_verify],
				       [system_openssl_has_cms=yes],
				       [system_openssl_has_cms=no])

		if test $system_openssl_has_rfc3779 = yes && test $system_openssl_has_cms = yes
		then
			have_usable_openssl=yes
		else
			have_usable_openssl=no
		fi
esac

case $with_system_openssl in
     yes)
		build_openssl=no
		if test $have_usable_openssl = no
		then
			AC_MSG_ERROR([Can't find OpenSSL crypto library with CMS and RFC 3779 support, try --with-system-openssl=/path/to/openssl])
		fi
		;;
     no)
		build_openssl=yes
		;;
     auto)
		if test $have_usable_openssl = no
		then
			build_openssl=yes
		else
			build_openssl=no
		fi
		;;
     *)
		build_openssl=no
		if test $have_usable_openssl = no
		then
			AC_MSG_ERROR([Can't find OpenSSL crypto library with CMS and RFC 3779 support in $with_system_openssl])
		fi
esac

if test $build_openssl = yes
then
	CFLAGS="$old_CFLAGS"
	LDFLAGS="$old_LDFLAGS"
fi

case $enable_openssl_asm in
     yes|no)
		build_openssl_asm=$enable_openssl_asm
		;;
     auto)
		case $host in
			x86_64-*-linux*)
				build_openssl_asm=no
				;;
			*)
				build_openssl_asm=yes
				;;
		esac
		;;
     *)
		AC_MSG_ERROR([Unrecognized value for --enable-openssl-asm: $enable_openssl_asm])
		;;
esac     

# RCYNIC_DIR is a "precious" argument variable to this script (see
# autoconf doc), which means that autoconf is careful with whatever
# value (if any) was passed in, and that it's already been declared
# for variable substitution.  We still have to set a default value for
# it, though, and we might as well handle DESTDIR while we're at it.

if test "X$RCYNIC_DIR" = "X"
then
	rcynic_base_dir='/var/rcynic'
else
	rcynic_base_dir="${RCYNIC_DIR}"
fi

RCYNIC_DIR='${DESTDIR}'"${rcynic_base_dir}"

# Figure out whether to run rcynic in a chroot jail, which determines
# a bunch of other settings.

AC_MSG_CHECKING([whether to build chroot jail for rcynic])

case $enable_rcynic_jail in
	yes)
		use_rcynic_jail=yes
		RCYNIC_CONF_FILE='${RCYNIC_DIR}/etc/rcynic.conf'
		RCYNIC_TA_DIR='${RCYNIC_DIR}/etc/trust-anchors'
		RCYNIC_BIN_RCYNIC='${RCYNIC_DIR}/bin/rcynic'
		RCYNIC_CONF_RSYNC='/bin/rsync'
		RCYNIC_CONF_DATA='/data'
		RCYNIC_CONF_TA_DIR='/etc/trust-anchors'
		RCYNIC_CRON_USER='root'
		RCYNIC_JAIL_DIRS='${RCYNIC_DIR}/bin ${RCYNIC_DIR}/dev ${RCYNIC_DIR}/etc'
		if test "X$host_os" = "Xlinux"
		then
			RCYNIC_JAIL_DIRS="RCYNIC_JAIL_DIRS "'${RCYNIC_DIR}/lib ${RCYNIC_DIR}/lib64 ${RCYNIC_DIR}/usr/lib'
		fi
		;;
	no)
		use_rcynic_jail=no
		RCYNIC_CONF_FILE='${DESTDIR}${sysconfdir}/rcynic.conf'
		RCYNIC_TA_DIR='${DESTDIR}${sysconfdir}/rpki/trust-anchors'
		RCYNIC_BIN_RCYNIC='${DESTDIR}${bindir}/rcynic'
		RCYNIC_CONF_RSYNC="${RSYNC}"
		RCYNIC_CONF_DATA="${rcynic_base_dir}/data"
		RCYNIC_CONF_TA_DIR='${sysconfdir}/rpki/trust-anchors'
		RCYNIC_CRON_USER='${RCYNIC_USER}'
		RCYNIC_JAIL_DIRS=''
		;;
	*)
		AC_MSG_ERROR([Unrecognized value for --enable-rcynic-jail: $enable_rcynic_jail])
		;;
esac

AC_SUBST(RCYNIC_JAIL_DIRS)
AC_SUBST(RCYNIC_CONF_FILE)
AC_SUBST(RCYNIC_TA_DIR)
AC_SUBST(RCYNIC_BIN_RCYNIC)
AC_SUBST(RCYNIC_CONF_RSYNC)
AC_SUBST(RCYNIC_CONF_DATA)
AC_SUBST(RCYNIC_CONF_TA_DIR)
AC_SUBST(RCYNIC_CRON_USER)

AC_MSG_RESULT([$use_rcynic_jail])

if test $use_rcynic_jail = yes && test "X$LD_STATIC_FLAG" != "X"
then
	RCYNIC_STATIC_RSYNC='static-rsync/rsync'
else
	RCYNIC_STATIC_RSYNC=''
fi

AC_SUBST(RCYNIC_STATIC_RSYNC)

# Check whether to do "final target installation".  This means actions
# that can only be done when installing a package, as opposed to when
# building a package.  On FreeBSD this is sort of irrelevant, because
# of the way package installs work when building from source, but on
# Debian and Ubuntu, for example, there's a strict separation between
# things that are done during package build and things that are done
# by the binary package's {pre,post}inst scripts.

AC_MSG_CHECKING([whether to do final target installation on "make install"])

case $enable_target_installation in
	yes|no)
		;;
	*)
		AC_MSG_ERROR([Unrecognized value for --enable-target-installation: $enable_target_installation])
		;;
esac

AC_MSG_RESULT([$enable_target_installation])

# rcynic jail setup is complicated enough that it's simplest to have
# different rule sets for different platforms.  Icky, but....
# rpki-rtr isn't as complicated, but has similar issues, same hack.
# rpkid isn't as complicated either, but same hack.

case $host_os in
	darwin*)
		RCYNIC_MAKE_RULES='rcynic/rules.darwin.mk'
		RTR_ORIGIN_MAKE_RULES='rtr-origin/rules.darwin.mk'
		RPKID_MAKE_RULES='rpkid/rules.darwin.mk'
		;;
	freebsd*)
		RCYNIC_MAKE_RULES='rcynic/rules.freebsd.mk'
		RTR_ORIGIN_MAKE_RULES='rtr-origin/rules.freebsd.mk'
		RPKID_MAKE_RULES='rpkid/rules.freebsd.mk'
		;;
	linux*)
		RCYNIC_MAKE_RULES='rcynic/rules.linux.mk'
		RTR_ORIGIN_MAKE_RULES='rtr-origin/rules.linux.mk'
		RPKID_MAKE_RULES='rpkid/rules.linux.mk'
		;;
	*)
		RCYNIC_MAKE_RULES='rcynic/rules.unknown.mk'
		RTR_ORIGIN_MAKE_RULES='rtr-origin/rules.unknown.mk'
		RPKID_MAKE_RULES='rpkid/rules.unknown.mk'
		;;
esac

AC_SUBST_FILE(RCYNIC_MAKE_RULES)
AC_SUBST_FILE(RTR_ORIGIN_MAKE_RULES)
AC_SUBST_FILE(RPKID_MAKE_RULES)

# Where to put HTML files is similarly platform dependent, we have to know.
# rcynic-cron will skip generating HTML files if it has no place to put them.

case $host_os in
	freebsd*)
		RCYNIC_HTML_DIR='/usr/local/www/apache22/data/rcynic'
		;;
	linux*)
		if test -d /var/www/html
		then
			# RHEL/CentOS
			RCYNIC_HTML_DIR='/var/www/html/rcynic'
		else
			# Ubuntu
			RCYNIC_HTML_DIR='/var/www/rcynic'
		fi
		;;
	*)
		RCYNIC_HTML_DIR=''
		;;
esac

AC_SUBST(RCYNIC_HTML_DIR)

# Sort out which things to install, depending on rcynic jail status and whether
# we're doing final target installation.

RCYNIC_INSTALL_TARGETS='install-always'
RTR_ORIGIN_INSTALL_TARGETS='install-always'
RPKID_INSTALL_TARGETS='install-always'

if test $use_rcynic_jail = yes
then
	RCYNIC_INSTALL_TARGETS="$RCYNIC_INSTALL_TARGETS install-jailed"
fi

if test $enable_target_installation = yes
then
	RCYNIC_INSTALL_TARGETS="$RCYNIC_INSTALL_TARGETS install-postconf"
	RTR_ORIGIN_INSTALL_TARGETS="$RTR_ORIGIN_INSTALL_TARGETS install-postconf"
	RPKID_INSTALL_TARGETS="$RPKID_INSTALL_TARGETS install-postconf"
fi

AC_SUBST(RCYNIC_INSTALL_TARGETS)
AC_SUBST(RTR_ORIGIN_INSTALL_TARGETS)
AC_SUBST(RPKID_INSTALL_TARGETS)

# Now a bunch of checks to figure out what we can do with Python.  If
# we don't have Python at all, none of the rest of this matters.  If
# we do have Python, we need to check for required packages and
# versions.

have_python=no
have_acceptable_python=no
have_python_h=no
have_django=no
have_acceptable_django=no
have_lxml=no
have_mysqldb=no
have_pyyaml=no
have_vobject=no
have_django_south=no
have_acceptable_django_south=no
have_argparse=no

if test "x$PYTHON" != "x"
then
	have_python=yes

	AC_MSG_CHECKING([for Python version 2.6 or higher])
	have_acceptable_python=`$PYTHON -c 'import sys; print "yes" if sys.version_info[[0]] == 2 and sys.version_info[[1]] >= 6 else "no"'`
	AC_MSG_RESULT([$have_acceptable_python])

	AC_MSG_CHECKING([distutils to find out where Python.h should be])
	python_h=`$PYTHON -c 'import distutils.sysconfig; print distutils.sysconfig.get_python_inc() + "/Python.h"'`
	AC_MSG_RESULT([$python_h])

	AC_CHECK_HEADER([$python_h], [have_python_h=yes], [have_python_h=no])

	AC_MSG_CHECKING([for lxml.etree])
	if $PYTHON -c 'import lxml.etree' 2>/dev/null
	then
		have_lxml=yes
	fi
	AC_MSG_RESULT([$have_lxml])

	AC_MSG_CHECKING([for MySQLdb])
	if $PYTHON -c 'import MySQLdb' 2>/dev/null
	then
		have_mysqldb=yes
	fi
	AC_MSG_RESULT([$have_mysqldb])

	AC_MSG_CHECKING([for Django])
	if $PYTHON -c 'import django' 2>/dev/null
	then
		have_django="yes"
	fi
	AC_MSG_RESULT([$have_django])

	if test $have_django = yes
	then
		AC_MSG_CHECKING([for Django 1.3.7 or higher])
		have_acceptable_django=`$PYTHON -c "import django; print 'no' if django.VERSION < (1, 3, 7) else 'yes'"`
		AC_MSG_RESULT([$have_acceptable_django])
	fi

	AC_MSG_CHECKING([for PyYAML])
	if $PYTHON -c 'import yaml' 2>/dev/null
	then
		have_pyyaml=yes
	fi
	AC_MSG_RESULT([$have_pyyaml])

	AC_MSG_CHECKING([for vobject])
	if $PYTHON -c 'import vobject' 2>/dev/null
	then
		have_vobject=yes
	fi
	AC_MSG_RESULT([$have_vobject])

	AC_MSG_CHECKING([for Django South])
	if $PYTHON -c 'import south' 2>/dev/null
	then
		have_django_south=yes
	fi
	AC_MSG_RESULT([$have_django_south])

	if test $have_django_south = yes
	then
		AC_MSG_CHECKING([for Django South 0.7.5 or later])
		have_acceptable_django_south=`$PYTHON -c "import south; print 'no' if map(int,south.__version__.split('.')) < [[0, 7, 5]] else 'yes'"`
		AC_MSG_RESULT([$have_acceptable_django_south])
	fi

	AC_MSG_CHECKING([for argparse])
	if $PYTHON -c 'import argparse' 2>/dev/null
	then
		have_argparse=yes
	fi
	AC_MSG_RESULT([$have_argparse])
fi

ok=yes

if test $have_python = no
then
	ok=no
	AC_MSG_WARN([I can't find a Python binary, perhaps you need to set PATH?])
fi

if test $have_acceptable_python = no
then
	ok=no
	AC_MSG_WARN([The RPKI code requires Python version 2.x, for x = 6 or higher.])
fi

case $enable_rp_tools in
     yes)	build_rp_tools=yes
     		;;
     no)	build_rp_tools=no
     		;;
     *)		AC_MSG_ERROR([Unrecognized value for --enable-rp-tools: $enable_rp_tools])
     		;;
esac

case $enable_ca_tools in
     yes)	build_ca_tools=yes
		if test $have_python_h = no
		then
			ok=no
			AC_MSG_WARN([I can't find Python.h.  Python sources are required to build the CA tools.])
		fi
		if test $have_lxml = no
		then
			ok=no
			AC_MSG_WARN([The RPKI tools require the Python LXML module.])
		fi
		if test $have_acceptable_django = no
		then
			ok=no
			AC_MSG_WARN([The RPKI CA tools require Django 1.3.7 or higher.])
		fi
		if test $have_vobject = no
		then
			ok=no
			AC_MSG_WARN([The RPKI CA GUI requires the Python vobject module.])
		fi
		if test $have_acceptable_django_south = no
		then
			ok=no
			AC_MSG_WARN([The RPKI CA tools require Django South 0.7.5 or higher.])
		fi
		if test $have_argparse = no
		then
			ok=no
			AC_MSG_WARN([The RPKI CA tools require the Python argparse module.])
		fi
		#
		# This should be the last test in this group, so that failures get the --disable-ca-tools warning.
		#
		if test $ok = no
		then
			AC_MSG_WARN([If you do not wish to install the RPKI CA tools, please specify --disable-ca-tools as an argument to this configure script.])
		fi
		;;
     no)	build_ca_tools=no
		;;
     *)		AC_MSG_ERROR([Unrecognized value for --enable-ca-tools: $enable_ca_tools]);;
esac

if test $build_ca_tools = yes && test $have_pyyaml = no
then
	AC_MSG_WARN([PyYAML missing, so "make test" will not work properly.])
fi

if test "x$XSLTPROC" = "x"
then
	AC_MSG_WARN([xsltproc missing, so "make test" will not work properly.])
fi

if test "x$RRDTOOL" = "x"
then
	AC_MSG_WARN([rrdtool missing, so rcynic-html won't be able to draw graphs.])
fi

if test $use_rcynic_jail = no && test "X$RSYNC" = "X"
then
	ok=no
	AC_MSG_WARN([The RPKI relying party tools require rsync.])
fi

if test $ok = no
then
	AC_MSG_ERROR([Please correct the problems above then re-run this configuration script.])
fi

# Figure out whether we are on a Debian-derived system where we need
# to tell setup.py about Debian installation layout.

if test $build_ca_tools = yes
then
	AC_MSG_CHECKING([whether we need to tell distutils to use a particular installation layout])
	looks_like_debian=no
	if test -x /usr/bin/lsb_release
	then
		case `/usr/bin/lsb_release -is` in
		Debian|Ubuntu)
			looks_like_debian=yes
			;;
		esac
	fi
	if test $looks_like_debian = yes
	then
		install_layout="deb"
	else
		install_layout="unix"
	fi
	case $enable_python_install_layout in
	yes|no)
		use_install_layout=$enable_python_install_layout
		;;
	auto)
		use_install_layout=no
		;;
	*)
		use_install_layout=yes
		install_layout="$enable_python_install_layout"
		;;
	esac
	if test $use_install_layout = yes
	then
		SETUP_PY_INSTALL_LAYOUT="--install-layout=$install_layout"
	else
		SETUP_PY_INSTALL_LAYOUT=''

	fi
	AC_MSG_RESULT([$use_install_layout $SETUP_PY_INSTALL_LAYOUT])
	AC_SUBST(SETUP_PY_INSTALL_LAYOUT)
fi

# Figure out which parts of this package we have to build.

			      TOP_LEVEL_SUBDIRS="h"
test $build_openssl  = yes && TOP_LEVEL_SUBDIRS="$TOP_LEVEL_SUBDIRS openssl"
test $build_rp_tools = yes && TOP_LEVEL_SUBDIRS="$TOP_LEVEL_SUBDIRS rcynic utils rtr-origin"
test $build_ca_tools = yes && TOP_LEVEL_SUBDIRS="$TOP_LEVEL_SUBDIRS rpkid"

AC_SUBST(TOP_LEVEL_SUBDIRS)

AC_CONFIG_FILES([Makefile
		 h/Makefile])

if test "X$RCYNIC_STATIC_RSYNC" != "X"
then
	AC_CONFIG_FILES([rcynic/static-rsync/Makefile])
fi

# OpenSSL has its own build system that bears no relationship to
# anything but itself, and our use of it is a bit weird, so this is a
# BFMI (Brute Force and Massive Ignorance) job.

if test $build_openssl = yes
then
	AC_CONFIG_FILES([openssl/Makefile openssl/tests/Makefile])

	AC_MSG_CHECKING([what configuration target to use when building OpenSSL])
	case $host in
	i*86-apple-darwin*)
		if test "$ac_cv_sizeof_long" = 8
		then
			OPENSSL_CONFIG_COMMAND='./Configure darwin64-x86_64-cc'
		fi
		;;
	*)
		if test $build_openssl_asm = yes
		then
			OPENSSL_CONFIG_COMMAND="MACHINE=$host_cpu ./config"
		else
			OPENSSL_CONFIG_COMMAND="MACHINE=$host_cpu ./config no-asm"
		fi
		;;
	esac
	AC_SUBST(OPENSSL_CONFIG_COMMAND)
	AC_MSG_RESULT([$OPENSSL_CONFIG_COMMAND])

	AC_MSG_CHECKING([what glob to use when renaming OpenSSL shared libraries])
	case $host in
	*-apple-darwin*)
		OPENSSL_SO_GLOB='*.dylib'
		;;
	*)
		OPENSSL_SO_GLOB='*.so*'
		;;
	esac
	AC_SUBST(OPENSSL_SO_GLOB)
	AC_MSG_RESULT([$OPENSSL_SO_GLOB])

	# NB: We put our OpenSSL directory at the *front* of the
	# search list to preempt conflicts with system copies.

	CFLAGS="-I\${abs_top_srcdir}/openssl/openssl/include $CFLAGS"
	LIBS="\${abs_top_builddir}/openssl/openssl/libcrypto.a $LIBS"
else
	LIBS="$LIBS -lcrypto"
fi

if test $build_rp_tools = yes
then
	AC_CONFIG_FILES([rcynic/Makefile
			 utils/Makefile
			 utils/find_roa/Makefile
			 utils/hashdir/Makefile
			 utils/print_rpki_manifest/Makefile
			 utils/print_roa/Makefile
			 utils/scan_roas/Makefile
			 utils/uri/Makefile
			 rtr-origin/Makefile])
fi

if test $build_ca_tools = yes
then
	if test "$enable_wsgi_daemon_mode" != no
	then
		if test "$enable_wsgi_daemon_mode" = yes; then
			AC_MSG_ERROR([You must specify the user to run the wsgi process as with --enable-wsgi-daemon-mode=USER])
		fi
		save_IFS="$IFS"
		IFS=':' read user group <<_EOF
$enable_wsgi_daemon_mode
_EOF
		IFS="$save_IFS"
		AC_SUBST(WSGI_DAEMON_PROCESS, "WSGIDaemonProcess rpkigui user=$user ${group:+group=}${group} display-name=%{GROUP}")
		AC_SUBST(WSGI_PROCESS_GROUP, "WSGIProcessGroup rpkigui")
		AC_MSG_RESULT([running mod_wsgi in daemon mode with user "$user" and group "${group:-default}"])
	fi

	AC_CONFIG_FILES([rpkid/Makefile rpkid/tests/Makefile rpkid/portal-gui/Makefile])
fi

# Now that we're finally done with all the conditional changes to
# CFLAGS, add a search directive for our own header directory.  If we
# ever get to the point of having our own library directory, we'd add
# it here too, but for the moment our shared C code is all in .h files.

CFLAGS="$CFLAGS -I\${abs_top_srcdir}/h"

AC_OUTPUT
