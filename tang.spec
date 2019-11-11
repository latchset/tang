Name:           tang
Version:        7
Release:        3%{?dist}
Summary:        Network Presence Binding Daemon

License:        GPLv3+
URL:            https://github.com/latchset/%{name}
Source0:        https://github.com/latchset/%{name}/releases/download/v%{version}/%{name}-%{version}.tar.bz2

BuildRequires:  gcc
BuildRequires:  jose >= 8
BuildRequires:  libjose-devel >= 8
BuildRequires:  libjose-zlib-devel >= 8
BuildRequires:  libjose-openssl-devel >= 8

BuildRequires:  http-parser-devel >= 2.7.1-3
BuildRequires:  systemd-devel
BuildRequires:  pkgconfig

BuildRequires:  systemd
BuildRequires:  curl

BuildRequires:  asciidoc
BuildRequires:  coreutils
BuildRequires:  grep
BuildRequires:  sed

%{?systemd_requires}
Requires:       coreutils
Requires:       jose >= 8
Requires:       grep
Requires:       sed

Requires(pre):  shadow-utils

%description
Tang is a small daemon for binding data to the presence of a third party.

%prep
%setup -q

%build
%configure
make %{?_smp_mflags} V=1

%install
rm -rf $RPM_BUILD_ROOT
%make_install
%{__sed} -i 's|DirectoryMode=0700||' $RPM_BUILD_ROOT/%{_unitdir}/%{name}d-update.path
%{__sed} -i 's|MakeDirectory=true||' $RPM_BUILD_ROOT/%{_unitdir}/%{name}d-update.path
echo "User=%{name}" >> $RPM_BUILD_ROOT/%{_unitdir}/%{name}d-update.service
echo "User=%{name}" >> $RPM_BUILD_ROOT/%{_unitdir}/%{name}d@.service
%{__mkdir_p} $RPM_BUILD_ROOT/%{_localstatedir}/cache/%{name}
%{__mkdir_p} $RPM_BUILD_ROOT/%{_localstatedir}/db/%{name}

%check
if ! make %{?_smp_mflags} check; then
    cat test-suite.log
    false
fi

%pre
getent group %{name} >/dev/null || groupadd -r %{name}
getent passwd %{name} >/dev/null || \
    useradd -r -g %{name} -d %{_localstatedir}/cache/%{name} -s /sbin/nologin \
    -c "Tang Network Presence Daemon user" %{name}
exit 0

%post
%systemd_post %{name}d.socket
%systemd_post %{name}d-update.path
%systemd_post %{name}d-update.service
%systemd_post %{name}d-keygen.service

%preun
%systemd_preun %{name}d.socket
%systemd_preun %{name}d-update.path
%systemd_preun %{name}d-update.service
%systemd_preun %{name}d-keygen.service

%postun
%systemd_postun_with_restart %{name}d.socket
%systemd_postun_with_restart %{name}d-update.path
%systemd_postun_with_restart %{name}d-update.service
%systemd_postun_with_restart %{name}d-keygen.service

%files
%license COPYING
%attr(0750, %{name}, %{name}) %{_localstatedir}/cache/%{name}
%attr(2570, %{name}, %{name}) %{_localstatedir}/db/%{name}
%{_unitdir}/%{name}d-keygen.service
%{_unitdir}/%{name}d-update.service
%{_unitdir}/%{name}d-update.path
%{_unitdir}/%{name}d@.service
%{_unitdir}/%{name}d.socket
%{_libexecdir}/%{name}d-keygen
%{_libexecdir}/%{name}d-update
%{_libexecdir}/%{name}d
%{_mandir}/man8/tang.8*
%{_bindir}/%{name}-show-keys
%{_mandir}/man1/tang-show-keys.1*

%changelog
* Sat Jul 27 2019 Fedora Release Engineering <releng@fedoraproject.org> - 7-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_31_Mass_Rebuild

* Sun Feb 03 2019 Fedora Release Engineering <releng@fedoraproject.org> - 7-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_30_Mass_Rebuild

* Fri Aug 10 2018 Nathaniel McCallum <npmccallum@redhat.com> - 7-1
- New upstream release
- Retire tang-nagios package (now separate upstream)

* Sat Jul 14 2018 Fedora Release Engineering <releng@fedoraproject.org> - 6-5
- Rebuilt for https://fedoraproject.org/wiki/Fedora_29_Mass_Rebuild

* Fri Feb 09 2018 Fedora Release Engineering <releng@fedoraproject.org> - 6-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_28_Mass_Rebuild

* Thu Aug 03 2017 Fedora Release Engineering <releng@fedoraproject.org> - 6-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Binutils_Mass_Rebuild

* Thu Jul 27 2017 Fedora Release Engineering <releng@fedoraproject.org> - 6-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Mass_Rebuild

* Wed Jun 14 2017 Nathaniel McCallum <npmccallum@redhat.com> - 6-1
- New upstream release

* Wed Jun 14 2017 Nathaniel McCallum <npmccallum@redhat.com> - 5-2
- Fix incorrect dependencies

* Wed Jun 14 2017 Nathaniel McCallum <npmccallum@redhat.com> - 5-1
- New upstream release

* Sat Feb 11 2017 Fedora Release Engineering <releng@fedoraproject.org> - 4-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_26_Mass_Rebuild

* Mon Nov 14 2016 Nathaniel McCallum <npmccallum@redhat.com> - 4-2
- Fix a race condition in one of the tests

* Thu Nov 10 2016 Nathaniel McCallum <npmccallum@redhat.com> - 4-1
- New upstream release
- Add nagios subpackage

* Wed Oct 26 2016 Nathaniel McCallum <npmccallum@redhat.com> - 3-1
- New upstream release

* Wed Oct 19 2016 Nathaniel McCallum <npmccallum@redhat.com> - 2-1
- New upstream release

* Tue Aug 23 2016 Nathaniel McCallum <npmccallum@redhat.com> - 1-1
- First release
