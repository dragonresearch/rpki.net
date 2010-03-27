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

# This isn't the complete list of Makefiles (let alone setup.py, etc
# files) in this tree, just the ones we're customizing today.  At some
# point I should do a pass through the rest of the tree, making clever
# use of abs_top_builddir, etc.

AC_CONFIG_FILES([Makefile openssl/Makefile rcynic/Makefile])

AC_OUTPUT
