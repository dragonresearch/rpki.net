# -*- Autoconf -*-
# $Id$

# Bare-bones autoconf for RPKI tools.  This will almost certainly
# expand later, right now I'm only using it for things that absolutely
# must be configured just to get the code to build at all.

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

AC_MSG_CHECKING([if linker supports -static])
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

AC_PATH_PROG([PYTHON], [python])

if test "x$PYTHON" = "x"
then
	have_python=no
	have_python_h=no
	need_pywrap=no
	have_django=no
else
	have_python=yes

	AC_MSG_CHECKING([distutils to find out where Python.h should be])
	python_h=`$PYTHON -c 'import distutils.sysconfig; print distutils.sysconfig.get_python_inc() + "/Python.h"'`
	AC_MSG_RESULT([$python_h])

	AC_CHECK_HEADER([$python_h],
			[have_python_h=yes],
			[have_python_h=no])

	if test "x$have_python_h" = "xyes"
	then
		AC_MSG_CHECKING([whether Python links against libcrypto])
		if ldd $PYTHON 2>&AS_MESSAGE_LOG_FD | $PYTHON -c 'import sys; sys.exit("libcrypto" not in sys.stdin.read())'
		then
			need_pywrap=yes
		else
			need_pywrap=no
		fi
		AC_MSG_RESULT([$need_pywrap])
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

AC_ARG_ENABLE([system_openssl], [AS_HELP_STRING([--disable-system-openssl],	[Don't build against system copy of OpenSSL])],	[], [enable_system_openssl=auto])
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
     *)		AC_MSG_ERROR([Unrecognized value for --enable-system-openssl: $enable-system-openssl]);;
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
     *)		AC_MSG_ERROR([Unrecognized value for --enable-python: $enable-python]);;
esac


case $enable_pywrap in
     yes)	build_pywrap=yes
		if test $build_python = no
		then
			AC_MSG_ERROR([Building pywrap without Python makes no sense])
		fi
		if test $build_openssl = no
		then
			AC_MSG_WARN([Building pywrap when using system OpenSSL library makes no sense (but I'll try to do it anyway)])
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
     *)		AC_MSG_ERROR([Unrecognized value for --enable-pywrap: $enable-pywrap]);;
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
     *)		AC_MSG_ERROR([Unrecognized value for --enable-django: $enable-django]);;
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

# OpenSSL has its own build system that bears no relationship to
# anything but itself.  On at least one platform, OpenSSL's opinion on
# the right thing to do is so completely at odds with everything else
# that the resulting libraries require special compilation options for
# any program that wants to use them.  Feh.
#
# Don't bother with this unless we're building our own OpenSSL.

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
fi

# Sort out which interpreter POW-using Python programs should use.

if test $build_pywrap = yes
then
	# Eventually this should be the installation directory, but
	# for now we're still running out of the build tree.
	PYWRAP=`pwd`/pow/pywrap/pywrap
else
	# If we don't need pywrap, just make it expand to python
	PYWRAP=$PYTHON
fi
AC_SUBST(PYWRAP)

if test $build_python = yes
then
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
