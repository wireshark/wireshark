# Note that this is NOT a relocatable package
%define ver      0.7.2
%define rel      1
%define prefix   /usr/X11R6

Summary:	Network traffic analyzer
Name:		ethereal
Version:	%ver
Release:	%rel
Copyright:	GPL
Group:		Networking/Utilities
Source:		ethereal-%{PACKAGE_VERSION}.tar.gz
URL:		http://ethereal.zing.org/
BuildRoot:	/tmp/ethereal-%{PACKAGE_VERSION}-root
Packager:	FastJack <fastjack@i-s-o.net>
Requires:	gtk+
Requires:	libpcap

%description
Ethereal is a network traffic analyzer for Unix-ish operating systems.

%prep
%setup
CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix=%prefix --sysconfdir=/etc
make

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/{etc,usr/X11R6/bin,usr/X11R6/man/man1}

# can't use make install here. It would put manuf directly into /etc
cp ethereal $RPM_BUILD_ROOT/usr/X11R6/bin
cp ethereal.1 $RPM_BUILD_ROOT/usr/X11R6/man/man1
cp manuf $RPM_BUILD_ROOT/etc

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-, root, root)
%doc AUTHORS COPYING ChangeLog INSTALL NEWS README
%config /etc/manuf
/usr/X11R6/bin/ethereal
/usr/X11R6/man/man1/ethereal.1

%changelog
* Tue Aug 03 1999 Gilbert Ramirez <gram@xiexie.org>
- updated to 0.7.0 and changed gtk+ requirement

* Sun Jan 01 1999 Gerald Combs <gerald@zing.org>
- updated to 0.5.1

* Fri Nov 20 1998 FastJack <fastjack@i-s-o.net>
- updated to 0.5.0

* Sun Nov 15 1998 FastJack <fastjack@i-s-o.net>
- created .spec file

