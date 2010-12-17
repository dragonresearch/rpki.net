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

# OpenSSL has its own build system that bears no relationship to
# anything but itself.  On at least one platform, OpenSSL's opinion on
# the right thing to do is so completely add odds with everything else
# that the resulting libraries require special compilation options for
# any program that wants to use them.  Feh.

AC_MSG_CHECKING([what configuration target to use when building OpenSSL])
OPENSSL_CONFIG_COMMAND='./config'
case "$host" in
i*86-apple-darwin*)
	if test "$ac_cv_sizeof_long" = 8
	then
		OPENSSL_CONFIG_COMMAND='./Configure darwin64-x86_64-cc'
	fi
	;;
esac
AC_SUBST(OPENSSL_CONFIG_COMMAND)
AC_MSG_RESULT([$OPENSSL_CONFIG_COMMAND])

AC_PATH_PROG([XSLTPROC], [xsltproc])
AC_PATH_PROG([AWK], [awk])

if test "x$XSLTPROC" != "x" && test "x$AWK" != "x"
then
	AC_CONFIG_FILES([rcynic/show.sh],	[chmod +x rcynic/show.sh])
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

if test "x$system_openssl_has_rfc3779" = "xyes" && test "x$system_openssl_has_cms" = "xyes"
then
	build_openssl=yes
else
	build_openssl=no
fi

AC_PATH_PROG([PYTHON], [python])

if test "x$PYTHON" = "x"
then
	build_pow=no
	build_pywrap=no
else
	AC_MSG_CHECKING([distutils to find out where Python.h should be])
	python_h=`$PYTHON -c 'import distutils.sysconfig; print distutils.sysconfig.get_python_inc() + "/Python.h"'`
	AC_MSG_RESULT([$python_h])

	AC_CHECK_HEADER([$python_h],
			[build_pow=yes],
			[build_pow=no])

	if test "x$build_pow" = "xyes"
	then
		AC_MSG_CHECKING([whether Python links against libcrypto])
		if ldd $PYTHON 2>&AS_MESSAGE_LOG_FD | $PYTHON -c 'import sys; sys.exit("libcrypto" not in sys.stdin.read())'
		then
			build_pywrap=yes
		else
			build_pywrap=no
		fi
		AC_MSG_RESULT([$build_pywrap])
	fi

	AC_CONFIG_FILES([rpkid/backup-sql],	[chmod +x rpkid/backup-sql])
	AC_CONFIG_FILES([rpkid/irbe_cli],	[chmod +x rpkid/irbe_cli])
	AC_CONFIG_FILES([rpkid/irdbd],		[chmod +x rpkid/irdbd])
	AC_CONFIG_FILES([rpkid/myrpki],		[chmod +x rpkid/myrpki])
	AC_CONFIG_FILES([rpkid/pubd],		[chmod +x rpkid/pubd])
	AC_CONFIG_FILES([rpkid/rootd],		[chmod +x rpkid/rootd])
	AC_CONFIG_FILES([rpkid/rpkid],		[chmod +x rpkid/rpkid])
	AC_CONFIG_FILES([rpkid/sql-setup],	[chmod +x rpkid/sql-setup])
	AC_CONFIG_FILES([rpkid/start-servers],	[chmod +x rpkid/start-servers])
fi

# Maze of Python-related tests is complicated.
#
# - If we don't have Python at all, we can't run any of the Python
#   tools and probably should not even attempt to configure them.
#
# - If the system Python executable was linked against OpenSSL -and-
#   we had to build our own copy of OpenSSL (because the system copy
#   wasn't good enough), we need to build pywrap and configure scripts
#   to use it.
#
# - Otherwise (we have python and it's not linked against the wrong
#   version of OpenSSL), we can use the system Python executable and
#   don't need pywrap.
#
# - Unless we're punting on Python entirely, we need to build POW,
#   either against the system OpenSSL or against our own copy.
#
# - If we're building either POW or pywrap, we need Python.h.
#
# If any of this fails, we need to tell the user and give useful hint
# on what to do next (doc reference, whatever).
#
# Oh, and the user has to be able to override all of our guessing,
# with --enable/--disable or whatever autoconf hack we're using this
# week.




# This isn't the complete list of Makefiles (let alone setup.py, etc
# files) in this tree, just the ones we're customizing today.  At some
# point I should do a pass through the rest of the tree, making clever
# use of abs_top_builddir, etc.

AC_CONFIG_FILES([Makefile
		 openssl/Makefile
		 rcynic/Makefile
		 rpkid/rpki/__doc__.py])

AC_OUTPUT
