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

# On some platforms we want to search /usr/local for libraries unless
# LDFLAGS and CFLAGS are set explictly by the user.  At the moment we
# just do this for FreeBSD; add other systems here as needed.

if test "x${CFLAGS+set}" = "x" && test "x${LDFLAGS+set}" = "x"
then
	case $host_os in
	freebsd*)
		CFLAGS="-I/usr/local/include"
		LDFLAGS="-L/usr/local/lib"
		;;
	esac
fi

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
else
	have_python=yes

	AC_MSG_CHECKING([distutils to find out where Python.h should be])
	python_h=`$PYTHON -c 'import distutils.sysconfig; print distutils.sysconfig.get_python_inc() + "/Python.h"'`
	AC_MSG_RESULT([$python_h])

	AC_CHECK_HEADER([$python_h],
			[have_python_h=yes],
			[have_python_h=no])

	AC_MSG_CHECKING([whether we need pywrap])
	if ldd $PYTHON 2>&AS_MESSAGE_LOG_FD | $GREP 'libcrypto' >/dev/null 2>&1
	then
		need_pywrap=yes
	else
		need_pywrap=no
	fi
	AC_MSG_RESULT([$need_pywrap])

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
AC_ARG_ENABLE([openssl_asm],	[AS_HELP_STRING([--disable-openssl-asm],	[Don't let OpenSSL build assembler code])],     [], [enable_openssl_asm=auto])
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

case $enable_openssl_asm in
     yes|no)	build_openssl_asm=$enable_openssl_asm
		;;
     auto)	case $host in
			x86_64-*-linux*)
				build_openssl_asm=no
				;;
			*)
				build_openssl_asm=yes
				;;
		esac
		;;
     *)		AC_MSG_ERROR([Unrecognized value for --enable-openssl-asm: $enable_openssl_asm]);;
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
		if test $build_openssl = no
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
test $build_python = yes &&	TOP_LEVEL_SUBDIRS="$TOP_LEVEL_SUBDIRS rpkid"
test $have_python = yes &&	TOP_LEVEL_SUBDIRS="$TOP_LEVEL_SUBDIRS rtr-origin"

AC_SUBST(TOP_LEVEL_SUBDIRS)

# Conditionally build subsets of the rpkid tools
                            RPKID_SUBDIRS=""
test $build_django = yes && RPKID_SUBDIRS="$RPKID_SUBDIRS portal-gui"

AC_SUBST(RPKID_SUBDIRS)

AC_CONFIG_FILES([Makefile
		 rcynic/Makefile
		 rcynic/static-rsync/Makefile
		 utils/Makefile
		 utils/find_roa/Makefile
		 utils/hashdir/Makefile
		 utils/print_rpki_manifest/Makefile
		 utils/print_roa/Makefile
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

	CFLAGS="$CFLAGS -I\${abs_top_srcdir}/openssl/openssl/include"
	LIBS="$LIBS \${abs_top_builddir}/openssl/openssl/libssl.a \${abs_top_builddir}/openssl/openssl/libcrypto.a"
else
	LIBS="$LIBS -lssl -lcrypto"
fi

# Sort out which interpreter POW-using Python programs should use.

if test $build_pywrap = yes
then
	AC_CONFIG_FILES([pywrap/Makefile])
	PYWRAP='${libexecdir}/pywrap'
	PYWRAP_CMD='LD_LIBRARY_PATH="${abs_top_builddir}/openssl/openssl" ${abs_top_builddir}/pywrap/pywrap'
	PYWRAP_LIBDIR='${libdir}/pywrap'
else
	PYWRAP="$PYTHON"
	PYWRAP_CMD="$PYTHON"
	PYWRAP_LIBDIR=''
fi
AC_SUBST(PYWRAP)
AC_SUBST(PYWRAP_CMD)
AC_SUBST(PYWRAP_LIBDIR)

if test $build_python = yes
then
	AC_CONFIG_FILES([rpkid/Makefile rpkid/tests/Makefile])
fi

if test $build_django = yes
then
	# the user that the apache process is running as
	if test "x$WEBUSER" = "x"; then
		for u in apache www www-data; do
			if $GREP $u /etc/passwd >/dev/null 2>&1; then
				WEBUSER=$u
				break
			fi
		done
		if test "x$WEBUSER" = "x"; then
			AC_MSG_ERROR([Could not determine which user the apache process runs as.  Please specify WEBUSER=<USERNAME>.])
		fi
	fi
	AC_SUBST(WEBUSER)

        # source: http://blog.leosoto.com/2008/04/django-secretkey-generation.html
        AC_SUBST(SECRET_KEY, `$PYTHON -c 'import random; print "".join([random.choice("abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)") for i in range(50)])'`)

        # there is no standard name for this tool, so check for it
        AC_PATH_PROGS(DJANGO_ADMIN, [django-admin django-admin.py])

        AC_CONFIG_FILES([rpkid/portal-gui/Makefile])
fi

if test $have_python = yes
then
	AC_CONFIG_FILES([rtr-origin/Makefile])
fi

# This should go away once its content has migrated from Doxygen into DocBook.
AC_CONFIG_FILES([rpkid/rpki/__doc__.py])

AC_OUTPUT
