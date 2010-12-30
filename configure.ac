# -*- Autoconf -*-
# $Id$

AC_PREREQ(2.61)
AC_INIT(rpkitools, 1.0,)
AC_CONFIG_SRCDIR([rcynic/rcynic.c])
AC_CONFIG_AUX_DIR([buildtools])
AC_PROG_CC

AC_CANONICAL_HOST

AC_CHECK_SIZEOF([long])

# We'd like to build rcynic as a static binary if we can, because that
# makes it much simpler to run rcynic in a chroot jail, but we don't
# know how to do it on all platforms, so we try the hack we know, and
# if that doesn't work, oh well.

AC_MSG_CHECKING([whether linker supports -static])
old_LDFLAGS="$LDFLAGS"
LDFLAGS="$LDFLAGS -static"
AC_LINK_IFELSE(
	[AC_LANG_SOURCE([[int main (int argc, char *argv[]) { return 0; }]])],
	[
		AC_MSG_RESULT(yes)
		LD_STATIC_FLAG='-static'
	],
	[
		AC_MSG_RESULT(no)
		LD_STATIC_FLAG=''
	]
)
AC_SUBST(LD_STATIC_FLAG)
LDFLAGS="$old_LDFLAGS"
unset old_LDFLAGS

AC_PATH_PROG([XSLTPROC], [xsltproc])
AC_PATH_PROG([AWK], [awk])

if test "x$XSLTPROC" != "x" && test "x$AWK" != "x"
then
	AC_CONFIG_FILES([rcynic/show.sh],
			[chmod +x rcynic/show.sh])
fi

# Figure out whether we need to build our own OpenSSL library or can
# use the system libraries.  We're looking for two recent features:
# CMS and RFC 3779 support.

AC_CHECK_LIB([crypto], [v3_addr_validate_path],
		       [system_openssl_has_rfc3779=yes],
		       [system_openssl_has_rfc3779=no])

AC_CHECK_LIB([crypto], [CMS_verify],
		       [system_openssl_has_cms=yes],
		       [system_openssl_has_cms=no])

if test "$system_openssl_has_rfc3779" = yes && test "$system_openssl_has_cms" = yes
then
	have_usable_openssl=yes
else
	have_usable_openssl=no
fi

# Figure out whether we need to use shared libraries to build POW.
# This is a world of hurt, but appears to be required on some 64-bit
# platforms due to a deficiency in the GNU linker: it flat out refuses
# to build a shared object (.so) file that uses functions from a
# static library (.a) or static object (.o) file.  This in turn
# creates a nightmare of library version dependency issues, so we use
# static libraries where we can, dynamic where we must.
#
# My autoconf-fu isn't strong enough to construct a test for the real
# condition, so for the moment I'm just testing to see if it's the GNU
# loader and problematic word length.  If you know how to write the
# real test, please do so and send it to me.  So far the least silly
# idea I've had for how to do this would be to use AC_LINK_IFELSE() to
# test a fragment of C code calling some ISO C math function with
# LDFLAGS='-Wl,--library=:libm.a -shared' and CFLAGS='-fPIC' to see if
# the linker explodes.

AC_PROG_GREP
if test "x$GREP" = x
then
	AC_MSG_ERROR([Next test requires grep, sorry])
fi

AC_MSG_CHECKING([whether we're using the GNU loader])
if ld --version 2>&1 | $GREP 'GNU ld' >/dev/null 2>&1
then
	using_gnu_ld=yes
else
	using_gnu_ld=no
fi
AC_MSG_RESULT([$using_gnu_ld])

AC_MSG_CHECKING([whether building Python extension will require shared OpenSSL libraries])
if test $using_gnu_ld = yes && test "$ac_cv_sizeof_long" -gt 4
then
	need_openssl_shared=yes
else
	need_openssl_shared=no
fi
AC_MSG_RESULT([$need_openssl_shared])

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
	need_pywrap=no
	have_django=no
	need_openssl_shared=no
else
	have_python=yes

	AC_MSG_CHECKING([distutils to find out where Python.h should be])
	python_h=`$PYTHON -c 'import distutils.sysconfig; print distutils.sysconfig.get_python_inc() + "/Python.h"'`
	AC_MSG_RESULT([$python_h])

	AC_CHECK_HEADER([$python_h],
			[have_python_h=yes],
			[have_python_h=no])

	if test "x$have_python_h" = "xyes" && test $need_openssl_shared = yes
	then
		AC_MSG_CHECKING([whether Python links against libcrypto])
		if ldd $PYTHON 2>&AS_MESSAGE_LOG_FD | $PYTHON -c 'import sys; sys.exit("libcrypto" not in sys.stdin.read())'
		then
			need_pywrap=yes
		else
			need_pywrap=no
		fi
		AC_MSG_RESULT([$need_pywrap])
	else
		need_pywrap=no
	fi

	AC_MSG_CHECKING([for Django])
	if $PYTHON -c 'import django' 2>/dev/null
	then
		have_django="yes"
	else
		have_django="no"
	fi
	AC_MSG_RESULT([$have_django])

fi

# Ok, now that we've sorted out what we've got to work with, we need
# to check what the user is telling us to do.  In the default case, we
# try to do something sane.  If the user tells us to do something
# that's silly but harmless, we say so; if the user tells us to do
# something that just won't work, we say so and fail.

AC_ARG_ENABLE([system_openssl], [AS_HELP_STRING([--disable-system-openssl],	[Don't build against system copy of OpenSSL])],	[], [enable_system_openssl=auto])
AC_ARG_ENABLE([shared_openssl], [AS_HELP_STRING([--enable-shared-openssl],	[Build shared OpenSSL libraries])],	        [], [enable_shared_openssl=auto])
AC_ARG_ENABLE([python],		[AS_HELP_STRING([--disable-python],		[Don't build any of the Python-based tools])],	[], [enable_python=auto])
AC_ARG_ENABLE([pywrap],		[AS_HELP_STRING([--enable-pywrap],		[Build pywrap])],				[], [enable_pywrap=auto])
AC_ARG_ENABLE([django],		[AS_HELP_STRING([--disable-django],		[Don't build Django GUI])],			[], [enable_django=auto])

case $enable_system_openssl in
     yes)	build_openssl=no
		if test $have_usable_openssl = no
		then
			AC_MSG_ERROR([I can't find an OpenSSL crypto library with CMS and RFC 3779 support, maybe you need to set LDFLAGS?])
		fi
		;;
     no)	build_openssl=yes
		;;
     auto)	if test $have_usable_openssl = no
		then
			build_openssl=yes
		else
			build_openssl=no
		fi
		;;
     *)		AC_MSG_ERROR([Unrecognized value for --enable-system-openssl: $enable_system_openssl]);;
esac

case $enable_shared_openssl in
     yes)	build_shared_openssl=yes
		if test $build_openssl = no
		then
			AC_MSG_WARN([Not building OpenSSL at all, ignoring request to build it as shared libraries])
		fi
		;;
     no)	build_shared_openssl=no
		if test $build_openssl = yes && test $need_openssl_shared = yes
		then
			AC_MSG_ERROR([This platform appears to require shared OpenSSL libraries])
		fi
		;;
     auto)	build_shared_openssl=$need_openssl_shared
		;;
     *)		AC_MSG_ERROR([Unrecognized value for --enable-shared-openssl: $enable_shared_openssl]);;
esac

case $enable_python in
     yes)	build_python=yes
		if test $have_python = no
		then
			AC_MSG_ERROR([I can't find a Python binary, maybe you need to set PATH?])
		fi
		;;
     no)	build_python=no
		;;
     auto)	build_python=$have_python
		if test $have_python = no
		then
			AC_MSG_WARN([I can't find your Python binary, disabling build for all Python-using code])
		fi
		;;
     *)		AC_MSG_ERROR([Unrecognized value for --enable-python: $enable_python]);;
esac

case $enable_pywrap in
     yes)	build_pywrap=yes
		if test $build_python = no
		then
			AC_MSG_ERROR([Building pywrap without Python makes no sense])
		fi
		if test $build_openssl = no || test $need_openssl_shared = no
		then
			AC_MSG_WARN([pywrap not needed (but I'll try to build it anyway)])
		fi
		;;
     no)	build_pywrap=no
		if test $need_pywrap = yes
		then
			AC_MSG_ERROR([This platform appears to require pywrap])
		fi
		;;
     auto)	build_pywrap=$need_pywrap
		;;
     *)		AC_MSG_ERROR([Unrecognized value for --enable-pywrap: $enable_pywrap]);;
esac

case $enable_django in
     yes)	build_django=yes
		if test $have_django = no
		then
			AC_MSG_WARN([You don't appear to have Django installed (but I'll try to build the Django-based GUI anyway)])
		fi
		;;
     no)	build_django=no
		;;
     auto)	build_django=$have_django
		;;
     *)		AC_MSG_ERROR([Unrecognized value for --enable-django: $enable_django]);;
esac

if test $build_python = yes && test $have_python_h = no
then
	AC_MSG_ERROR([Need Python sources to build extension module, either install sources or rerun with --disable-python])
fi

# Figure out which parts of this package we have to build.

				TOP_LEVEL_SUBDIRS=""
test $build_openssl = yes &&	TOP_LEVEL_SUBDIRS="$TOP_LEVEL_SUBDIRS openssl"
				TOP_LEVEL_SUBDIRS="$TOP_LEVEL_SUBDIRS rcynic utils"
test $build_pywrap = yes &&	TOP_LEVEL_SUBDIRS="$TOP_LEVEL_SUBDIRS pywrap"
test $build_python = yes &&	TOP_LEVEL_SUBDIRS="$TOP_LEVEL_SUBDIRS pow rpkid"

AC_SUBST(TOP_LEVEL_SUBDIRS)

AC_CONFIG_FILES([Makefile
		 rcynic/Makefile
		 utils/Makefile
		 utils/find_roa/Makefile
		 utils/hashdir/Makefile
		 utils/print_manifest/Makefile
		 utils/print_roa/Makefile
		 utils/uri/Makefile])

# If there's some sane way to do this with a built-in autoconf
# variable, I don't know what it is, so copy what BIND9 does.

RPKITOOLS_TOP_BUILDDIR=`pwd`
AC_SUBST(RPKITOOLS_TOP_BUILDDIR)

# OpenSSL has its own build system that bears no relationship to
# anything but itself.  On at least one platform, OpenSSL's opinion on
# the right thing to do is so completely at odds with everything else
# that the resulting libraries require special compilation options for
# any program that wants to use them.  We also have to sort out whether
# the linker is going to require shared libraries.  Feh.
#
# The -rpath insanity will need to change once we install this stuff.
#
# Don't bother with any of this unless we're building OpenSSL.

if test $build_openssl = yes
then
	AC_CONFIG_FILES([openssl/Makefile])

	AC_MSG_CHECKING([what configuration target to use when building OpenSSL])
	OPENSSL_CONFIG_COMMAND='./config'
	case $host in
	i*86-apple-darwin*)
		if test "$ac_cv_sizeof_long" = 8
		then
			OPENSSL_CONFIG_COMMAND='./Configure darwin64-x86_64-cc'
		fi
		;;
	esac
	AC_SUBST(OPENSSL_CONFIG_COMMAND)
	AC_MSG_RESULT([$OPENSSL_CONFIG_COMMAND])

	LDFLAGS="$LDFLAGS -L$RPKITOOLS_TOP_BUILDDIR/openssl/openssl"
	CFLAGS="$CFLAGS -I$RPKITOOLS_TOP_BUILDDIR/openssl/openssl/include"

	if test $build_shared_openssl = yes
	then
		OPENSSL_SHARED_LIBRARIES='enable-shared'
		LDFLAGS="$LDFLAGS -Wl,-rpath,$RPKITOOLS_TOP_BUILDDIR/openssl/openssl"
	else
		OPENSSL_SHARED_LIBRARIES='disable-shared'
	fi
	AC_SUBST(OPENSSL_SHARED_LIBRARIES)
fi

# Sort out which interpreter POW-using Python programs should use.

if test $build_pywrap = yes
then
	AC_CONFIG_FILES([pywrap/Makefile])

	# Eventually this should be the installation directory, but
	# for now we're still running out of the build tree.
	PYWRAP=$RPKITOOLS_TOP_BUILDDIR/pow/pywrap/pywrap
else
	# If we don't need pywrap, just make it expand to python
	PYWRAP=$PYTHON
fi
AC_SUBST(PYWRAP)

if test $build_python = yes
then
	AC_CONFIG_FILES([pow/Makefile rpkid/Makefile rpkid/tests/Makefile])

	# These are plain Python scripts, do not require pywrap
	AC_CONFIG_FILES([rpkid/backup-sql:buildtools/python-header:rpkid/backup-sql.py],		[chmod +x rpkid/backup-sql])
	AC_CONFIG_FILES([rpkid/sql-setup:buildtools/python-header:rpkid/sql-setup.py],			[chmod +x rpkid/sql-setup])
	AC_CONFIG_FILES([rpkid/start-servers:buildtools/python-header:rpkid/start-servers.py],		[chmod +x rpkid/start-servers])
	AC_CONFIG_FILES([rpkid/tests/sql-cleaner:buildtools/python-header:rpkid/tests/sql-cleaner.py],	[chmod +x rpkid/tests/sql-cleaner])
	AC_CONFIG_FILES([rpkid/tests/sql-dumper:buildtools/python-header:rpkid/tests/sql-dumper.py],	[chmod +x rpkid/tests/sql-dumper])

	# These use POW, so may require pywrap	
	AC_CONFIG_FILES([rpkid/irbe_cli:buildtools/pywrap-header:rpkid/irbe_cli.py],			[chmod +x rpkid/irbe_cli])
	AC_CONFIG_FILES([rpkid/irdbd:buildtools/pywrap-header:rpkid/irdbd.py],				[chmod +x rpkid/irdbd])
	AC_CONFIG_FILES([rpkid/myrpki:buildtools/pywrap-header:rpkid/myrpki.py],			[chmod +x rpkid/myrpki])
	AC_CONFIG_FILES([rpkid/pubd:buildtools/pywrap-header:rpkid/pubd.py],				[chmod +x rpkid/pubd])
	AC_CONFIG_FILES([rpkid/rootd:buildtools/pywrap-header:rpkid/rootd.py],				[chmod +x rpkid/rootd])
	AC_CONFIG_FILES([rpkid/rpkid:buildtools/pywrap-header:rpkid/rpkid.py],				[chmod +x rpkid/rpkid])
	AC_CONFIG_FILES([rpkid/tests/smoketest:buildtools/pywrap-header:rpkid/tests/smoketest.py],	[chmod +x rpkid/tests/smoketest])
	AC_CONFIG_FILES([rpkid/tests/yamltest:buildtools/pywrap-header:rpkid/tests/yamltest.py],	[chmod +x rpkid/tests/yamltest])
	AC_CONFIG_FILES([rpkid/tests/testpoke:buildtools/pywrap-header:rpkid/tests/testpoke.py],	[chmod +x rpkid/tests/testpoke])
fi

# This should go away once its content has migrated from Doxygen into DocBook.
AC_CONFIG_FILES([rpkid/rpki/__doc__.py])

AC_OUTPUT
