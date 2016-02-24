Name:       vpnsvc-pkg
Summary:    VPN service library in TIZEN C API
Version:    1.0.5
Release:    1
Group:      System/Network
License:    Apache License, Version 2.0
URL:        N/A
Source0:    %{name}-%{version}.tar.gz
Source1:    vpnsvc-daemon.service
Source2:    org.tizen.vpnsvc.service
Source3:    dbus-vpnsvc-daemon.conf
BuildRequires:	cmake
BuildRequires:	pkgconfig(dlog)
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:	pkgconfig(capi-base-common)
BuildRequires:  pkgconfig(capi-appfw-application)
BuildRequires:  pkgconfig(capi-appfw-package-manager)
BuildRequires:  pkgconfig(capi-appfw-app-manager)
BuildRequires:	pkgconfig(capi-system-info)
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description
capi-vpn-service framework, service

%package -n capi-vpnsvc
Summary:  VPN service library in TIZEN C API
Group:    Development/Libraries
#Requires: capi-vpnsvc

%description -n capi-vpnsvc
capi-vpnsvc CAPI package

%package -n capi-vpnsvc-devel
Summary:  VPN service library in TIZEN C API (Development)
Group:    Development/Libraries

%description -n capi-vpnsvc-devel
capi-vpnsvc CAPI devel package

%package -n vpnsvc-test
Summary:  Vpnsvc test
Group:    Development/Libraries

%description -n vpnsvc-test
vpnsvc test package

%package -n vpnsvc-daemon
Summary:  Vpnsvc daemon
Group:    Development/Libraries
Requires:         systemd
Requires(preun):  systemd
Requires(post):   systemd
Requires(postun): systemd

%description -n vpnsvc-daemon
vpnsvc daemon package

%prep
%setup -q

%build
%if 0%{?sec_build_binary_debug_enable}
export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"
%endif

%if 0%{?tizen_build_binary_release_type_eng}
export CFLAGS="$CFLAGS -DTIZEN_ENGINEER_MODE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_ENGINEER_MODE"
export FFLAGS="$FFLAGS -DTIZEN_ENGINEER_MODE"
%endif

export LDFLAGS+="-Wl,--rpath=%{_libdir}"

MAJORVER=`echo %{version} | awk 'BEGIN {FS="."}{print $1}'`
%cmake . -DVERSION=%{version} \
		-DFULLVER=%{version} \
		-DMAJORVER=${MAJORVER} \
        -DCMAKE_BUILD_TYPE=%{?build_type:%build_type}%{!?build_type:RELEASE} \
		-DTIZEN_ENGINEER_MODE=%{?tizen_build_binary_release_type_eng:1}%{!?tizen_build_binary_release_type_eng:0} \
        -DCMAKE_VERBOSE_MAKEFILE=ON \
        -DLIB_INSTALL_DIR=%{_libdir}

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}

mkdir -p %{buildroot}/%{_datadir}/license
cp LICENSE-Apache.v2.0 %{buildroot}/%{_datadir}/license/capi-vpnsvc
#cp LICENSE.APLv2 %{buildroot}/usr/share/license/fpasmtztransport

%make_install
mkdir -p %{buildroot}%{_sysconfdir}/dbus-1/system.d
install -m 0644 %{SOURCE3} %{buildroot}%{_sysconfdir}/dbus-1/system.d/vpnsvc-daemon.conf
mkdir -p %{buildroot}%{_libdir}/systemd/system
install -m 0644 %{SOURCE1} %{buildroot}%{_libdir}/systemd/system/vpnsvc-daemon.service
mkdir -p %{buildroot}%{_datadir}/dbus-1/system-services
install -m 0644 %{SOURCE2} %{buildroot}%{_datadir}/dbus-1/system-services/org.tizen.vpnsvc.service

%clean
rm -rf %{buildroot}

%post -n capi-vpnsvc
ln -s %{_libdir}/libcapi-vpnsvc.so.0 %{_libdir}/libcapi-vpnsvc.so

%postun
if [ $1 == 0 ]; then
    # unistall
    systemctl daemon-reload
fi

%files -n vpnsvc-daemon
%manifest daemon/vpnsvc-daemon.manifest
%attr(0755,root,root) %{_bindir}/vpnsvc-daemon
%defattr(-,root,root,-)
%{_sysconfdir}/dbus-1/system.d/*.conf
%{_libdir}/systemd/system/vpnsvc-daemon.service
%{_datadir}/dbus-1/system-services/org.tizen.vpnsvc.service

%files -n capi-vpnsvc
%manifest framework/capi-vpnsvc.manifest
%{_libdir}/libcapi-vpnsvc.so.*
%{_datadir}/license/capi-vpnsvc

%files -n capi-vpnsvc-devel
%{_includedir}/*.h
%{_libdir}/pkgconfig/capi-vpnsvc.pc
%{_libdir}/libcapi-vpnsvc.so

%files -n vpnsvc-test
%manifest test/vpnsvc-test.manifest
/usr/sbin/vpnsvc-test

