# $Id$
# Snort.org's SPEC file for Snort

# Other useful bits
%define SnortRulesDir %{_sysconfdir}/snort/rules
%define noShell /bin/false
%define _unpackaged_files_terminate_build 0

%define vendor Snort.org
%define for_distro RPMs
%define release %{__release}
%define realname snort3

# Look for a directory to see if we're building under cAos 
# Exit status is usually 0 if the dir exists, 1 if not, so
# we reverse that with the '!'
%define caos %([ ! -d /usr/lib/rpm/caos ]; echo $?)

%if %{caos}
  # We are building for cAos (www.caosity.org) and the autobuilder doesn't
  # have command line options so we have to fake the options for whatever
  # packages we actually want here, in addition to tweaking the package
  # info.
  %define vendor cAos Linux 
  %define for_distro RPMs for cAos Linux
  %define release 1.caos
%endif

Name: %{realname}
Version: %{__version}
Summary: An open source Network Intrusion Detection System (NIDS)
Epoch: 1
Release: %{release}%{?dist}
Group: Applications/Internet
License: GPL
Url: http://www.snort.org/
Source0: %{realname}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Packager: Official Snort.org %{for_distro}
Vendor: %{vendor}
Requires: libgeolite, libmaxminddb, libdaq, libdaq-modules, libdnet, hwloc, luajit, openssl, libpcap, pcre, hyperscan, flatbuffers, libuuid, gperftools-libs, zlib, librdkafka, xz
BuildRequires: libgeolite-devel, libmaxminddb-devel, xz-devel,flex, libdaq-devel, cmake, gcc, gcc-c++, libdnet-devel, librdkafka-devel, hwloc-devel, luajit-devel, openssl-devel, libpcap-devel, pcre-devel, hyperscan-devel, flatbuffers-devel, glibc-headers, libuuid-devel, gperftools, gperftools-devel, zlib-devel, asciidoc, dblatex

%description
Snort is an open source network intrusion detection system, capable of
performing real-time traffic analysis and packet logging on IP networks.
It can perform protocol analysis, content searching/matching and can be
used to detect a variety of attacks and probes, such as buffer overflows,
stealth port scans, CGI attacks, SMB probes, OS fingerprinting attempts,
and much more.

Snort has three primary uses. It can be used as a straight packet sniffer
like tcpdump(1), a packet logger (useful for network traffic debugging,
etc), or as a full blown network intrusion detection system. 

You MUST edit /etc/snort/snort.conf to configure snort before it will work!

Please see the documentation in %{_docdir}/%{realname}-%{version} for more
information on snort features and configuration.

%package devel
Summary: Development tools for Snort
Requires: %{name} == %{version}

%description devel
Development tools for Snort


%prep
%setup -q -n %{realname}-%{version}

%build
#%{__sed} -i -r -e '/-DCMAKE_EXPORT_COMPILE_COMMANDS/ a -DLIBLZMA_LIBRARIES=/usr/lib64/liblzma.so.5 \\' ./configure_cmake.sh
CFLAGS="$RPM_OPT_FLAGS"
export AM_CFLAGS="-g -O2"
./configure_cmake.sh --prefix=%{_prefix} --disable-static-daq --enable-hardened-build --enable-pie --enable-tcmalloc --enable-shell
# --disable-gdb
cd ./build
%{make_build} VERBOSE=1


%install
cd ./build
%{make_install}

%{__mv} $RPM_BUILD_ROOT%{_libdir}/snort/daq $RPM_BUILD_ROOT%{_libdir}/daq
[[ "X$RPM_BUILD_ROOT" = "X/" ]] || %{__rm} -rf $RPM_BUILD_ROOT%{_libdir}/snort
%{__mkdir_p} $RPM_BUILD_ROOT%{_sbindir}
%{__mv} $RPM_BUILD_ROOT%{_bindir}/snort $RPM_BUILD_ROOT%{_sbindir}/
%{__mkdir_p} $RPM_BUILD_ROOT%{_sysconfdir}/snort
%{__mv} $RPM_BUILD_ROOT%{_prefix}/etc/snort $RPM_BUILD_ROOT%{_sysconfdir}/
[ -n "$RPM_BUILD_ROOT" -a "$RPM_BUILD_ROOT" != / ] && %{__rm} -rf $RPM_BUILD_ROOT%{_prefix}/etc
%{__mkdir_p} $RPM_BUILD_ROOT%{SnortRulesDir}
%{__mv} $RPM_BUILD_ROOT%{_docdir}/snort $RPM_BUILD_ROOT%{_docdir}/snort-%{version}
%{__mkdir_p} $RPM_BUILD_ROOT%{_var}/log/snort
%{__install} -p -m 0644 packaging/rpm/snort3@.service $RPM_BUILD_ROOT/usr/lib/systemd/system/snort3@.service


%clean
[ -n "$RPM_BUILD_ROOT" -a "$RPM_BUILD_ROOT" != / ] && rm -rf $RPM_BUILD_ROOT


%pre
# Don't do all this stuff if we are upgrading
if [ $1 = 1 ] ; then
	/usr/sbin/groupadd snort 2> /dev/null || true
	/usr/sbin/useradd -M -d %{_var}/log/snort -s %{noShell} -c "snort" -g snort snort 2>/dev/null || true
fi

%postun
# Only do this if we are actually removing snort
if [ $1 = 0 ] ; then
	if [ -L %{_sbindir}/snort ]; then
		%__rm -f %{_sbindir}/snort
	fi

	/usr/sbin/userdel snort 2>/dev/null
fi

%files
%defattr(-,root,root)
%attr(0755,root,root) %{_libdir}/daq/*.so
%attr(0755,root,root) %{_bindir}/u2boat
%attr(0755,root,root) %{_bindir}/u2spewfoo
%attr(0755,root,root) %{_bindir}/snort2lua
%attr(0755,root,root) %{_sbindir}/snort
%attr(0755,root,root) %dir %{_sysconfdir}/snort
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/snort/*.lua
%attr(0755,root,root) %dir %{SnortRulesDir}
%attr(0644,root,root) %{_includedir}/snort/lua/*.lua
%attr(0755,snort,snort) %dir %{_var}/log/snort
%doc %{_docdir}/snort-%{version}

%files devel
%{_libdir}/pkgconfig/snort.pc
%{_includedir}/snort/*/*.h
%{_includedir}/snort/*/*/*.h
