# $Id$

AC_INIT(portal-gui, 1.0)

AC_ARG_WITH([python],
        [AS_HELP_STRING([--with-python=PATH], [specify location of the python interpreter to use])],
        [],
        [with_python=detect])

AC_ARG_WITH([myrpki],
        [AS_HELP_STRING([--with-myrpki=DIR], [specify the directory containing the myrpki.py command line tool])],
	[],
	[with_myrpki=no])

AS_IF([test "x$with_python" = "xdetect"],
        [AC_CHECK_PROGS(PYTHON, [python2.6 python2.5 python], [none])],
        [PYTHON=$with_python])
AS_IF([test "x$PYTHON" = "xnone"],
        [AC_MSG_ERROR([unable to find python interpreter, use --with-python])])
AC_MSG_RESULT([Using python interpreter at $PYTHON])

AS_IF([test "x$with_myrpki" = "xno"],
        [AC_MSG_ERROR([must specify the --with-myrpki option])])

MYRPKIDIR=$with_myrpki
MYRPKI_TOOL=$with_myrpki/myrpki.py
AC_MSG_RESULT([Full path to rpki Python module is $MYRPKIDIR])
AC_MSG_RESULT([Full path to the myrpki.py tool is $MYRPKI_TOOL])
AC_SUBST(MYRPKIDIR)
AC_SUBST(MYRPKI_TOOL)

# this is a bit of nastiness to expand $datarootdir for subsitution into
# the python scripts since we can't expand $prefix inline
if test x$prefix = xNONE; then
	prefix=$ac_default_prefix
fi
eval datarootdir=${datarootdir}
eval localstatedir=${localstatedir}

AC_SUBST(MEDIADIR, "$datarootdir/$PACKAGE_NAME/media")
AC_SUBST(TEMPLATEDIR, "$datarootdir/$PACKAGE_NAME/rpkigui/templates")
AC_SUBST(INSTDIR, "$datarootdir/$PACKAGE_NAME")
AC_MSG_RESULT([Installing portal-gui into $INSTDIR])

if test "x$DATABASE_PATH" = x; then
	DATABASE_PATH="$localstatedir/$PACKAGE_NAME/rpkiop"
fi
AC_SUBST(DATABASE_PATH)
AC_MSG_RESULT([Full path to the portal-gui database is $DATABASE_PATH])

if test "x$CONFDIR" = x; then
	AC_MSG_ERROR('Must specify the toplevel directory containing your resource handle files with CONFDIR=<DIR>')
fi
AC_MSG_RESULT([Toplevel resource directory is $CONFDIR])
AC_SUBST(CONFDIR)

if test "x$WEBUSER" = x; then
	AC_MSG_ERROR('Must specify the user that the apache daemons runs with WEBUSER=<user>')
fi
AC_MSG_RESULT([Web server runs as user $WEBUSER])
AC_SUBST(WEBUSER)

# source: http://blog.leosoto.com/2008/04/django-secretkey-generation.html
AC_SUBST(SECRET_KEY, `$PYTHON -c 'import random; print "".join([random.choice("abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)") for i in range(50)])'`)

AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([rpkigui/settings.py rpkigui/urls.py scripts/helper])
AC_CONFIG_FILES([apache/django.wsgi apache/zmyrpki.conf])

AC_OUTPUT
