# -*- Autoconf -*-
# $Id$

AC_PREREQ([2.61])
AC_INIT([rpkitools], [1.0])

# AC_REVISION is a great idea in theory, but the revision will always
# be wrong unless we do two checkins, so skip it for now.  Someday.

dnl AC_REVISION([$Revision$])

AC_CONFIG_SRCDIR([rcynic/rcynic.c])
AC_CONFIG_AUX_DIR([buildtools])
AC_CANONICAL_HOST

# Remember whether CFLAGS or LDFLAGS were set explictly.  This has to
# come early in the script, before we mess it up testing things.

if test "x${CFLAGS+set}" = "x" && test "x${LDFLAGS+set}" = "x"
then
	CFLAGS_or_LDFLAGS_were_set=no
else
	CFLAGS_or_LDFLAGS_were_set=yes
fi

# Put the user option stuff up front.

AC_ARG_WITH([system_openssl], [AS_HELP_STRING([--with-system-openssl], [Link against system copy of OpenSSL])],    [], [with_system_openssl=auto])
AC_ARG_ENABLE([openssl_asm],  [AS_HELP_STRING([--disable-openssl-asm], [Don't let OpenSSL build assembler code])], [], [enable_openssl_asm=auto])
AC_ARG_ENABLE([ca_tools],     [AS_HELP_STRING([--disable-ca-tools],    [Don't build any of the CA tools])],        [], [enable_ca_tools=yes])
AC_ARG_ENABLE([rpki_rtr],     [AS_HELP_STRING([--disable-rpki-rtr],    [Don't build the rpki-rtr code])],	   [], [enable_rpki_rtr=yes])

# Obsolete options.  If you know of a better way to handle this, tell me.

AC_ARG_ENABLE([python], [AS_HELP_STRING([--disable-python], [(Obsolete, do not use)])], [AC_MSG_ERROR([--disable-python is obsolete.  Please see the --disable-ca-tools option])], [])
AC_ARG_ENABLE([django], [AS_HELP_STRING([--disable-django], [(Obsolete, do not use)])],	[AC_MSG_ERROR([--disable-django is obsolete.  Please see the --disable-ca-tools option])], [])

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
freebsd*)	LD_STATIC_FLAG='-static';;
*)		LD_STATIC_FLAG='';;
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

AC_PATH_PROG([XSLTPROC], [xsltproc])
AC_PATH_PROG([AWK], [awk])
AC_PATH_PROG([SORT], [sort])
AC_PROG_GREP

if test "x$XSLTPROC" != "x" && test "x$AWK" != "x"
then
	AC_CONFIG_FILES([rcynic/show.sh],
			[chmod +x rcynic/show.sh])
fi

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

# Now a bunch of checks to figure out what we can do with Python.  If
# we don't have Python at all, none of the rest of this matters.  If
# we do have Python, we need to check what antics we need to go
# through to build the OpenSSL interface extension module, and also
# whether the Django code is installed for our GUI.

AC_PATH_PROG([PYTHON], [python])

if test "x$PYTHON" = "x"
then
	have_python=no
	have_python_h=no
	have_django=no
else
	have_python=yes

	AC_MSG_CHECKING([for Python version 2.6 or higher])
	python_version_ok=`$PYTHON -c 'import sys; print "yes" if sys.version_info[[0]] == 2 and sys.version_info[[1]] >= 6 else "no"'`
	AC_MSG_RESULT([$python_version_ok])

	AC_MSG_CHECKING([distutils to find out where Python.h should be])
	python_h=`$PYTHON -c 'import distutils.sysconfig; print distutils.sysconfig.get_python_inc() + "/Python.h"'`
	AC_MSG_RESULT([$python_h])

	AC_CHECK_HEADER([$python_h],
			[have_python_h=yes],
			[have_python_h=no])

	AC_MSG_CHECKING([for Django])
	if $PYTHON -c 'import django' 2>/dev/null
	then
		have_django="yes"
	else
		have_django="no"
	fi
	AC_MSG_RESULT([$have_django])

	if test $have_django = yes
	then
		AC_MSG_CHECKING([for Django 1.2 or higher])
		django_recent=`$PYTHON -c "import django; print 'no' if django.VERSION < (1, 2) else 'yes'"`
		AC_MSG_RESULT([$django_recent])
	fi
fi

if test $enable_ca_tools = yes || test $enable_rpki_rtr = yes
then
	if test $have_python = no
	then
		AC_MSG_ERROR([I can't find a Python binary, maybe you need to set PATH?])
	fi
	if test $python_version_ok = no
	then
		AC_MSG_ERROR([The RPKI code requires Python version 2.x, for x = 6 or higher.])
	fi
fi

case $enable_ca_tools in
     yes)	build_ca_tools=yes
		if test $have_python_h = no
		then
			AC_MSG_ERROR([I can't find Python.h.  Python sources are required to build the CA tools, please install them.
			              If you do not wish to install the CA tools, please specify --disable-ca-tools as an argument to this configure script.])
		fi
		if test $have_django = no
		then
			AC_MSG_ERROR([You don't appear to have Django installed.  Django is required by the CA tools, please install Django version 1.2 or higher.
			              If you do not wish to install the CA tools, please specify --disable-ca-tools as an argument to this configure script.])
		fi
		if test $django_recent = no
		then
			AC_MSG_ERROR([The CA tools require Django 1.2 or higher.])
		fi
		;;
     no)	build_ca_tools=no
		;;
     *)		AC_MSG_ERROR([Unrecognized value for --enable-ca-tools: $enable_ca_tools]);;
esac

case $enable_rpki_rtr in
     yes)	build_rpki_rtr=yes
     		;;
     no)	build_rpki_rtr=no
     		;;
     *)		AC_MSG_ERROR([Unrecognized value for --enable-rpki-rtr: $enable_rpki_rtr]);;
esac

# Figure out which parts of this package we have to build.

				TOP_LEVEL_SUBDIRS=""
test $build_openssl = yes &&	TOP_LEVEL_SUBDIRS="$TOP_LEVEL_SUBDIRS openssl"
				TOP_LEVEL_SUBDIRS="$TOP_LEVEL_SUBDIRS rcynic utils"
test $build_ca_tools = yes &&	TOP_LEVEL_SUBDIRS="$TOP_LEVEL_SUBDIRS rpkid"
test $build_rpki_rtr = yes &&	TOP_LEVEL_SUBDIRS="$TOP_LEVEL_SUBDIRS rtr-origin"

AC_SUBST(TOP_LEVEL_SUBDIRS)

AC_CONFIG_FILES([Makefile
		 rcynic/Makefile
		 rcynic/static-rsync/Makefile
		 utils/Makefile
		 utils/find_roa/Makefile
		 utils/hashdir/Makefile
		 utils/print_rpki_manifest/Makefile
		 utils/print_roa/Makefile
		 utils/scan_roas/Makefile
		 utils/uri/Makefile])

case $host_os in
linux*)
	AC_CONFIG_FILES([rcynic/installation-scripts/linux/install.sh])
	;;
esac

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
			OPENSSL_CONFIG_COMMAND='./config'
		else
			OPENSSL_CONFIG_COMMAND='./config no-asm'
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
	LIBS="\${abs_top_builddir}/openssl/openssl/libssl.a \${abs_top_builddir}/openssl/openssl/libcrypto.a $LIBS"
else
	LIBS="$LIBS -lssl -lcrypto"
fi

if test $build_ca_tools = yes
then
	AC_MSG_CHECKING([if running under virtualenv])
	if test x$VIRTUAL_ENV != x; then
		AC_SUBST(VIRTUAL_ENV, [$VIRTUAL_ENV])
		AC_MSG_RESULT([$VIRTUAL_ENV])
	else
		AC_MSG_RESULT(no)
	fi

        # Source: http://blog.leosoto.com/2008/04/django-secretkey-generation.html
        AC_SUBST(SECRET_KEY, `$PYTHON -c 'import random; print "".join([random.choice("abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)") for i in range(50)])'`)

	AC_SUBST(DJANGO_DIR, [`$PYTHON -c 'import os,sys; print [[os.path.join(p, "django") for p in sys.path if os.path.exists(os.path.join(p, "django"))]][[0]]'`])

        # There is no standard name for this tool, so check for it.
        AC_PATH_PROGS(DJANGO_ADMIN, [django-admin django-admin.py])

	AC_CONFIG_FILES([rpkid/Makefile rpkid/tests/Makefile rpkid/portal-gui/Makefile])
fi

if test $build_rpki_rtr = yes
then
	AC_CONFIG_FILES([rtr-origin/Makefile])
fi

AC_OUTPUT
