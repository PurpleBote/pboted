%define git_hash %(git rev-parse HEAD | cut -c -7)

Name:          pboted-git
Version:       0.7.9
Release:       git%{git_hash}%{?dist}
Summary:       I2P-Bote service written in C++
Conflicts:     pboted

License:       BSD
URL:           https://github.com/polistern/pboted
Source0:       https://github.com/polistern/pboted/archive/master/pboted-master.tar.gz

%if 0%{?rhel} == 7
BuildRequires: cmake3
%else
BuildRequires: cmake
%endif

BuildRequires: chrpath
BuildRequires: gcc-c++
BuildRequires: zlib-devel
BuildRequires: boost-devel
BuildRequires: openssl-devel
BuildRequires: mimetic-devel
BuildRequires: systemd-units

Requires:      logrotate
Requires:      systemd
Requires(pre): %{_sbindir}/useradd %{_sbindir}/groupadd


%description
I2P-Bote service written in C++.


%prep
%setup -q -n pboted-master


%build
cd build
%if 0%{?rhel} == 7
%cmake3 .
%else
%cmake .
%endif

%if 0%{?rhel} == 9
pushd redhat-linux-build
%endif

%if 0%{?fedora} >= 35
%if 0%{?fedora} < 37
pushd redhat-linux-build
%endif
%else
%if 0%{?fedora} >= 33
pushd %{_target_platform}
%endif
%endif

%if 0%{?mageia} > 7
pushd build
%endif

make %{?_smp_mflags}

%if 0%{?rhel} == 9
popd
%endif

%if 0%{?fedora} >= 33
%if 0%{?fedora} < 37
popd
%endif
%endif

%if 0%{?mageia} > 7
popd
%endif


%install
pushd build

%if 0%{?rhel} == 9
pushd redhat-linux-build
%endif

%if 0%{?fedora} >= 35
%if 0%{?fedora} < 37
pushd redhat-linux-build
%endif
%else
%if 0%{?fedora} >= 33
pushd %{_target_platform}
%endif
%endif

%if 0%{?mageia}
pushd build
%endif

chrpath -d pboted
%{__install} -D -m 755 pboted %{buildroot}%{_sbindir}/pboted
%{__install} -d -m 755 %{buildroot}%{_datadir}/pboted
%{__install} -d -m 700 %{buildroot}%{_sharedstatedir}/pboted
%{__install} -d -m 700 %{buildroot}%{_localstatedir}/log/pboted
%{__install} -D -m 644 %{_builddir}/pboted-master/contrib/pboted.conf %{buildroot}%{_sysconfdir}/pboted/pboted.conf
%{__install} -D -m 644 %{_builddir}/pboted-master/contrib/pboted.logrotate %{buildroot}%{_sysconfdir}/logrotate.d/pboted
%{__install} -D -m 644 %{_builddir}/pboted-master/contrib/pboted.service %{buildroot}%{_unitdir}/pboted.service
%{__install} -D -m 644 %{_builddir}/pboted-master/debian/pboted.1 %{buildroot}%{_mandir}/man1/pboted.1


%pre
getent group pboted >/dev/null || %{_sbindir}/groupadd -r pboted
getent passwd pboted >/dev/null || \
  %{_sbindir}/useradd -r -g pboted -s %{_sbindir}/nologin \
                      -d %{_sharedstatedir}/pboted -c 'I2P-Bote Service' pboted


%post
%systemd_post pboted.service


%preun
%systemd_preun pboted.service


%postun
%systemd_postun_with_restart pboted.service


%files
%doc LICENSE README.md contrib/pboted.conf
%{_sbindir}/pboted
%config(noreplace) %{_sysconfdir}/i2pd/*.conf
%{_sysconfdir}/logrotate.d/pboted
%{_unitdir}/pboted.service
%{_mandir}/man1/pboted.1*
%dir %attr(0700,pboted,pboted) %{_sharedstatedir}/pboted
%dir %attr(0700,pboted,pboted) %{_localstatedir}/log/pboted


%changelog
* Thu Jun 9 2022 polistern <polistern@i2pmail.org> - 0.7.9
- updated to 0.7.9

* Sun Feb 20 2022 polistern <polistern@i2pmail.org>- 0.7.8
- updated to 0.7.8

* Thu Feb 3 2022 polistern <polistern@i2pmail.org> - 0.7.7
- updated to 0.7.7

* Sat Jan 22 2022 polistern <polistern@i2pmail.org> - 0.7.6
- updated to 0.7.6

* Mon Dec 13 2021 polistern <polistern@i2pmail.org> - 0.7.5
- updated to 0.7.5

* Thu Dec 2 2021 polistern <polistern@i2pmail.org> - 0.7.4
- updated to 0.7.4

* Fri Nov 19 2021 polistern <polistern@i2pmail.org> - 0.7.3
- updated to 0.7.3
- updated default config file (#13)

* Fri Nov 12 2021 polistern <polistern@i2pmail.org> - 0.7.2
- Initial pboted-git based on pboted 0.7.2-1 spec
