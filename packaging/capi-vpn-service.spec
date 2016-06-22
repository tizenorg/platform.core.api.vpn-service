Name:       vpnsvc-pkg
Summary:    VPN service library in TIZEN C API
Version:    1.0.23
Release:    1
Group:      System/Network
License:    Apache-2.0
URL:        N/A
Source0:    %{name}-%{version}.tar.gz
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
capi-vpn-service

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

#%package -n vpnsvc_test
#Summary:  Vpnsvc test
#Group:    Development/Libraries

#%description -n vpnsvc_test
#vpnsvc test package

%prep
%setup -q

%build
export LDFLAGS+="-Wl,--rpath=%{_libdir}"

MAJORVER=`echo %{version} | awk 'BEGIN {FS="."}{print $1}'`
%cmake . -DVERSION=%{version} \
	-DFULLVER=%{version} \
	-DMAJORVER=${MAJORVER} \
        -DCMAKE_BUILD_TYPE=%{?build_type:%build_type}%{!?build_type:RELEASE} \
        -DCMAKE_VERBOSE_MAKEFILE=ON \
        -DLIB_INSTALL_DIR=%{_libdir}

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}

mkdir -p %{buildroot}/%{_datadir}/license
cp LICENSE %{buildroot}/%{_datadir}/license/capi-vpnsvc
#cp LICENSE.APLv2 %{buildroot}/usr/share/license/fpasmtztransport

%make_install

%clean
rm -rf %{buildroot}

%post -n capi-vpnsvc
ln -s %{_libdir}/libcapi-vpnsvc.so.0 %{_libdir}/libcapi-vpnsvc.so

%postun

%files -n capi-vpnsvc
%manifest capi-vpnsvc.manifest
%{_libdir}/libcapi-vpnsvc.so.*
%{_datadir}/license/capi-vpnsvc
%{_bindir}/vpnsvc_test

%files -n capi-vpnsvc-devel
%{_includedir}/*.h
%{_libdir}/pkgconfig/capi-vpnsvc.pc
%{_libdir}/libcapi-vpnsvc.so

#%files -n vpnsvc_test
#%manifest test/vpnsvc-test.manifest
#%{_bindir}/vpnsvc_test

