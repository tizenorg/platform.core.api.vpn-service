Name:       capi-network-vpn
Summary:    Default VPN Library
Version:    0.1.0_0
Release:    1
Group:      System/Network
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1001: 	capi-network-vpn.manifest
BuildRequires:  cmake
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(capi-base-common)

%description
Library code for CAPI's to interact with the Default VPN functionality on TIZEN platform.

%package devel
Summary:  Default VPN Development Package
Group:    System/Network
Requires: %{name} = %{version}-%{release}

%description devel
Development Library for Default VPN functionality on TIZEN platform.

%package test
Summary:    Default VPN Test Package
Requires:   %{name} = %{version}

%description test
Test cases for Default VPN Functionality on TIZEN platform.

%prep
%setup -q
cp %{SOURCE1001} .


%build
MAJORVER=`echo %{version} | awk 'BEGIN {FS="."}{print $1}'`
%cmake . -DFULLVER=%{version} -DMAJORVER=${MAJORVER}

make %{?_smp_mflags}


%install
%make_install

#License
mkdir -p %{buildroot}%{_datadir}/license
cp LICENSE.APLv2 %{buildroot}%{_datadir}/license/capi-network-vpn

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig


%files
%manifest %{name}.manifest
%attr(644,-,-) %{_libdir}/libcapi-network-vpn.so.*
%{_datadir}/license/capi-network-vpn

%files devel
%manifest %{name}.manifest
#%{_includedir}/network/*.h
%{_libdir}/pkgconfig/*.pc
%{_libdir}/libcapi-network-vpn.so

%files test
%manifest %{name}.manifest
%{_libdir}/vpn-capi-test/capi-vpn-test
