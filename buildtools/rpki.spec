Name:		rpki
Version:	0.5158
Release:	1%{?dist}
Summary:	rpki.net tool suite

License:	BSD
URL:		http://trac.rpki.net/
Source0:	rpki-0.5158.tar.gz
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires:	python-devel, openssl-devel, PyYAML, rrdtool, autoconf

%description


%prep
%setup -q -n rpki


%build
%configure --disable-target-installation
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT


%clean
rm -rf $RPM_BUILD_ROOT


%package rp
Requires: rsync, rrdtool, httpd, xinetd
Summary: rpki.net relying party tools


%description rp
"Relying party" validation tools from the rpki.net toolkit.  See the online
documentation at http://rpki.net/.


%pre rp
# create user/group for rcynic if not already present
getent group rcynic >/dev/null || groupadd -r rcynic
getent passwd rcynic >/dev/null || useradd -r -M -N -g rcynic -d /var/rcynic -s /sbin/nologin -c "RPKI validation system" rcynic

# create directories with proper permissions
install -o rcynic -g rcynic -d /var/rcynic/data /var/rcynic/rpki-rtr
install -o rcynic -g rcynic -d /var/www/html/rcynic

exit 0


%post rp
crontab -l -u rcynic 2>/dev/null |
awk -v t=`hexdump -n 2 -e '"%u\n"' /dev/urandom` '
  BEGIN { cmd = "exec /usr/bin/rcynic-cron" }
  $0 !~ cmd { print }
  END { printf "%u * * * *\t%s\n", t % 60, cmd }
' |
crontab -u rcynic -
service xinetd reload
exit 0


%postun rp
crontab -u rcynic -r
userdel rcynic
groupdel rcynic
exit 0


%files rp
%{_bindir}/find_roa
%{_bindir}/hashdir
%{_bindir}/print_roa
%{_bindir}/print_rpki_manifest
%{_bindir}/rcynic
%{_bindir}/rcynic-cron
%{_bindir}/rcynic-html
%{_bindir}/rcynic-svn
%{_bindir}/rcynic-text
%{_bindir}/rtr-origin
%{_bindir}/scan_roas
%{_bindir}/validation_status
%config %{_sysconfdir}/rcynic.conf
%{_sysconfdir}/xinetd.d/rpki-rtr
%{_sysconfdir}/rpki/trust-anchors


%package ca
Requires: mysql-server, MySQL-python, python, httpd, python-lxml, libxslt, mod_wsgi, mod_ssl, PyYAML, libxml2, python-pip
Summary: rpki.net certification authority tools

%description ca
"Certification authority" tools for issuing RPKI certificates and related
objects using the rpki.net toolkit.  See the online documentation at
http://rpki.net/.


%pre ca
getent group rpkid 2>/dev/null || groupadd rpkid
getent passwd rpkid 2>/dev/null || useradd -g rpkid -M -N -d /nonexistent -s /sbin/nologin -c "RPKI certification authority engine(s)" rpkid

# extra python modules not available in RHEL6
pip-python install -q django==1.4.5
pip-python install -q south
pip-python install -q vobject

# setup web portal on default ssl vhost
if test "$(grep Include /etc/httpd/conf.d/ssl.conf)" = ""
then
  conf=/etc/httpd/conf.d/ssl.conf
  awk < ${conf} > ${conf}.tmp$$ '
    $0 ~ /^<\/VirtualHost>/ { print "Include /etc/rpki/apache.conf" }
    { print }
  '
  cp $conf ${conf}.orig
  mv ${conf}.tmp$$ ${conf}
fi

# set up cron job for fetching/importing routeviews.org data
t=$(hexdump -n 1 -e '"%u"' /dev/urandom) && echo "$(($t % 60)) */2 * * * nobody /usr/share/rpki/routeviews.sh" > /etc/cron.d/rpkigui-routeviews
chmod 644 /etc/cron.d/rpkigui-routeviews
ln -sf /usr/sbin/rpkigui-check-expired /etc/cron.daily/rpkigui-check-expired

exit 0


%post ca
# perform automatic upgrade when we are already configured
if test -f /etc/rpki.conf
then
  rpki-manage syncdb
  rpki-manage migrate
fi

service httpd restart

exit 0


%postun ca
userdel rpkid
groupdel rpkid
exit 0


%files ca
%{_datadir}/rpki
%{_libdir}/python2.6/site-packages/rpki
%{_libdir}/python2.6/site-packages/rpkitoolkit-1.0-py2.6.egg-info
%{_sbindir}/irbe_cli
%{_sbindir}/irdbd
%{_sbindir}/pubd
%{_sbindir}/rootd
%{_sbindir}/rpkic
%{_sbindir}/rpkid
%{_sbindir}/rpkigui-check-expired
%{_sbindir}/rpkigui-import-routes
%{_sbindir}/rpkigui-rcynic
%{_sbindir}/rpki-manage
%{_sbindir}/rpki-sql-backup
%{_sbindir}/rpki-sql-setup
%{_sbindir}/rpki-start-servers
%{_sysconfdir}/rpki.conf.sample
%config %{_sysconfdir}/rpki/settings.py
%{_sysconfdir}/rpki/settings.pyc
%{_sysconfdir}/rpki/settings.pyo
%config %{_sysconfdir}/rpki/apache.conf


%changelog


