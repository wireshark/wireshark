# Makefile.am
# Automake file for Ethereal
#
# $Id: Makefile.am,v 1.239 2000/10/26 09:14:28 guy Exp $
#
# Ethereal - Network traffic analyzer
# By Gerald Combs <gerald@zing.org>
# Copyright 1998 Gerald Combs
#
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

ACLOCAL_AMFLAGS = `./aclocal-flags`

EXTRA_PROGRAMS = ethereal_static
bin_PROGRAMS = ethereal editcap tethereal

man_MANS = ethereal.1 editcap.1 tethereal.1

sysconf_DATA = manuf

DISSECTOR_SOURCES = \
	packet-aarp.c  \
	packet-afs.c   \
	packet-arp.c   \
	packet-ascend.c\
	packet-atalk.c \
	packet-atm.c   \
	packet-auto_rp.c   \
	packet-bgp.c   \
	packet-bootp.c \
	packet-bootparams.c \
	packet-bpdu.c  \
	packet-bxxp.c \
	packet-cdp.c   \
	packet-cgmp.c  \
	packet-clip.c  \
	packet-clnp.c  \
	packet-cops.c  \
	packet-data.c  \
	packet-ddtp.c  \
	packet-diameter.c \
	packet-dns.c   \
	packet-eigrp.c \
	packet-esis.c  \
	packet-eth.c   \
	packet-ethertype.c   \
	packet-fddi.c  \
	packet-frame.c  \
	packet-ftp.c   \
	packet-giop.c  \
	packet-gre.c   \
	packet-h1.c    \
	packet-h261.c  \
	packet-hsrp.c  \
	packet-http.c  \
	packet-icmpv6.c\
	packet-icp.c   \
	packet-icq.c   \
	packet-igrp.c  \
	packet-imap.c   \
	packet-ip.c    \
	packet-ipp.c   \
	packet-ipsec.c \
	packet-ipv6.c  \
	packet-ipx.c   \
	packet-irc.c   \
	packet-isakmp.c\
	packet-isis.c  \
	packet-isis-clv.c \
	packet-isis-hello.c \
	packet-isis-lsp.c \
	packet-isis-snp.c \
	packet-isl.c   \
	packet-kerberos.c \
	packet-l2tp.c  \
	packet-lapb.c  \
	packet-lapd.c  \
	packet-ldap.c  \
	packet-llc.c   \
	packet-lpd.c   \
	packet-mapi.c  \
	packet-mip.c  \
	packet-mount.c \
	packet-mpls.c \
	packet-msproxy.c \
	packet-nbipx.c \
	packet-nbns.c  \
	packet-ncp.c   \
	packet-ncp2222.c   \
	packet-netbios.c \
	packet-nfs.c   \
	packet-nlm.c   \
	packet-nntp.c  \
	packet-ntp.c  \
	packet-null.c  \
	packet-osi.c   \
	packet-osi-options.c \
	packet-ospf.c  \
	packet-pim.c   \
	packet-pop.c   \
	packet-portmap.c   \
	packet-ppp.c   \
	packet-pppoe.c \
	packet-pptp.c  \
	packet-q2931.c \
	packet-q931.c  \
	packet-quake.c \
	packet-radius.c\
	packet-raw.c   \
	packet-rip.c   \
	packet-ripng.c \
	packet-rlogin.c \
	packet-rpc.c   \
	packet-rsh.c   \
	packet-rsvp.c  \
	packet-rtcp.c  \
	packet-rtp.c   \
	packet-rtsp.c  \
	packet-rx.c  \
	packet-sap.c   \
	packet-sctp.c   \
	packet-sdp.c   \
	packet-smb.c   \
	packet-smb-browse.c \
	packet-smb-common.c \
	packet-smb-logon.c \
	packet-smb-mailslot.c \
	packet-smb-pipe.c \
        packet-smtp.c \
	packet-sna.c   \
	packet-snmp.c	\
	packet-socks.c \
	packet-srvloc.c \
	packet-sscop.c \
	packet-stat.c   \
	packet-syslog.c \
	packet-tacacs.c \
	packet-tcp.c   \
	packet-telnet.c\
	packet-tftp.c  \
	packet-time.c  \
	packet-tns.c \
	packet-tpkt.c  \
	packet-tr.c    \
	packet-trmac.c \
	packet-udp.c   \
	packet-v120.c \
	packet-vines.c \
	packet-vlan.c \
	packet-vrrp.c \
	packet-vtp.c  \
	packet-wccp.c \
	packet-who.c  \
	packet-x11.c   \
	packet-x25.c   \
	packet-yhoo.c  \
	packet-ypbind.c \
	packet-ypserv.c \
	packet-ypxfr.c \
	packet-zebra.c

noinst_HEADERS = \
	packet-afs.h   \
	packet-arp.h   \
	packet-ascend.h\
	packet-atalk.h \
	packet-atm.h   \
	packet-bgp.h   \
	packet-bootparams.h \
	packet-bpdu.h  \
	packet-cdp.h   \
	packet-cgmp.h  \
	packet-clip.h  \
	packet-clnp.h  \
	packet-ddtp.h  \
	packet-diameter.h \
	packet-diameter-defs.h \
	packet-dns.h   \
	packet-esis.h  \
	packet-eth.h   \
	packet-fddi.h  \
	packet-frame.h  \
	packet-h261.h  \
	packet-http.h  \
	packet-ip.h    \
	packet-ipp.h   \
	packet-ipsec.h \
	packet-ipv6.h  \
	packet-ipx.h   \
	packet-isis.h  \
	packet-isis-clv.h \
	packet-isis-hello.h \
	packet-isis-lsp.h \
	packet-isis-snp.h \
	packet-isl.h   \
	packet-kerberos.h \
	packet-lapb.h  \
	packet-lapd.h  \
	packet-ldap.h  \
	packet-llc.h   \
	packet-mount.h \
	packet-nbipx.h \
	packet-ncp-int.h \
	packet-netbios.h \
	packet-nfs.h   \
	packet-nlm.h   \
	packet-ntp.h  \
	packet-null.h  \
	packet-osi.h   \
	packet-osi-options.h \
	packet-ospf.h  \
	packet-portmap.h   \
	packet-ppp.h   \
	packet-q2931.h \
	packet-q931.h  \
	packet-raw.h   \
	packet-rip.h   \
	packet-ripng.h \
	packet-rpc.h   \
	packet-rtcp.h  \
	packet-rtp.h   \
	packet-rx.h  \
	packet-sdp.h   \
	packet-smb.h   \
	packet-smb-common.h \
	packet-sna.h   \
	packet-snmp.h	\
	packet-sscop.h \
	packet-stat.h   \
	packet-tcp.h   \
	packet-tns.h \
	packet-tpkt.h  \
	packet-tr.h    \
	packet-trmac.h \
	packet-udp.h   \
	packet-v120.h \
	packet-vines.h \
	packet-vlan.h \
	packet-vtp.h  \
	packet-x11-declarations.h	\
	packet-x11-register-info.h	\
	packet-x11-keysym.h	\
	packet-x25.h   \
	packet-yhoo.h  \
	packet-ypbind.h \
	packet-ypserv.h \
	packet-ypxfr.h 

ETHEREAL_COMMON_SOURCES = \
	alignment.h    \
	asn1.c         \
	asn1.h         \
	column.c       \
	column.h       \
	etypes.h       \
	follow.c       \
	follow.h       \
	ipproto.c      \
	llcsaps.h      \
	nlpid.h        \
	oui.h          \
	ppptypes.h     \
	prefs.c        \
	prefs.h        \
	prefs-int.h    \
	print.c        \
	print.h        \
	ps.c           \
	ps.h           \
	ptvcursor.c	\
	ptvcursor.h	\
	register.c     \
	register.h     \
	smb.h          \
	timestamp.h    \
	util.c         \
	util.h         \
	xdlc.c         \
	xdlc.h

ethereal_SOURCES = \
	$(DISSECTOR_SOURCES) \
	$(ETHEREAL_COMMON_SOURCES) \
	capture.c      \
	capture.h      \
	file.c         \
	file.h         \
	globals.h      \
	menu.h         \
	simple_dialog.h \
	summary.c      \
	summary.h      \
	ui_util.h

ethereal_static_SOURCES = \
	$(ethereal_SOURCES)

EXTRA_ethereal_SOURCES = \
	snprintf.c	\
	snprintf.h	\
	snprintf-imp.h	\
	strerror.c	\
	strerror.h	\
	strcasecmp.c	\
	strncasecmp.c	\
	mkstemp.c	\
	mkstemp.h

# Optional objects that I know how to build. These will be
# linked into the ethereal executable.
# They will also be linked into the tethereal executable; if this
# list ever grows to include something that can't be linked with
# tethereal, or if tethereal needs something that ethereal doesn't,
# we should probably split this into stuff needed both
# by ethereal and tethereal and stuff needed only by one or the
# other.
ethereal_optional_objects = @SNPRINTF_O@ @STRERROR_O@ \
	@STRCASECMP_O@ @STRNCASECMP_O@ @MKSTEMP_O@

# Additional libs that I know how to build. These will be
# linked into the ethereal executable.
ethereal_additional_libs = wiretap/libwiretap.a gtk/libui.a epan/libethereal.a

# This is the automake dependency variable for the executable
ethereal_DEPENDENCIES = \
	$(ethereal_optional_objects)	\
	$(ethereal_additional_libs)	\
	plugins/gryphon/gryphon.la

ethereal_static_DEPENDENCIES = \
	$(ethereal_optional_objects)	\
	$(ethereal_additional_libs)

# This automake variable adds to the link-line for the executable.
#
# Note that Ethereal doesn't have to be linked with @GLIB_LIBS@, as
# they are included in @GTK_LIBS@, and doesn't have to be linked with
# @SOCKET_LIBS@ or @NSL_LIBS@, as those should also be included in
# @GTK_LIBS@ (as those are also needed for X applications, and GTK+
# applications are X applications).
ethereal_LDADD = \
	$(ethereal_optional_objects)	\
	$(ethereal_additional_libs)	\
	@SNMP_LIBS@			\
	"-dlopen" self	\
	"-dlopen" plugins/gryphon/gryphon.la @PCAP_LIBS@ @GTK_LIBS@

ethereal_static_LDADD = \
	$(ethereal_optional_objects)	\
	$(ethereal_additional_libs) \
	@SNMP_LIBS@			\
	@PCAP_LIBS@ @GTK_LIBS@

ethereal_LDFLAGS = -export-dynamic
ethereal_static_LDFLAGS = -Wl,-static

tethereal_SOURCES = \
	$(DISSECTOR_SOURCES) \
	$(ETHEREAL_COMMON_SOURCES) \
	tethereal.c

# Additional libs that I know how to build. These will be
# linked into the tethereal executable.
tethereal_additional_libs = wiretap/libwiretap.a epan/libethereal.a

# This is the automake dependency variable for the executable
tethereal_DEPENDENCIES = \
	$(ethereal_optional_objects)	\
	$(tethereal_additional_libs)	\
	plugins/gryphon/gryphon.la

# This automake variable adds to the link-line for the executable
tethereal_LDADD = wiretap/libwiretap.a	\
	$(ethereal_optional_objects)	\
	$(tethereal_additional_libs)	\
	@SNMP_LIBS@			\
	"-dlopen" self	\
	"-dlopen" plugins/gryphon/gryphon.la @GLIB_LIBS@ -lm \
	@PCAP_LIBS@ @SOCKET_LIBS@ @NSL_LIBS@

tethereal_LDFLAGS = -export-dynamic

editcap_SOURCES = editcap.c

# This is the automake dependency variable for the executable
editcap_DEPENDENCIES = wiretap/libwiretap.a

# This automake variable adds to the link-line for the executable
editcap_LDADD = wiretap/libwiretap.a @GLIB_LIBS@

#
# Build "register.c", which contains a function "register_all_protocols()"
# that calls the register routines for all protocols.
#
# We do this by grepping through sources.  If that turns out to be too slow,
# maybe we could just require every .o file to have an register routine
# of a given name (packet-aarp.o -> proto_register_aarp, etc.).
#
# Formatting conventions:  The name of the proto_register_* routines must
# start in column zero, or must be preceded only by "void " starting in
# column zero, and must not be inside #if.
#
# We assume that all dissector routines are in "packet-XXX.c" files.
#
# For some unknown reason, having a big "for" loop in the Makefile
# to scan all the "packet-XXX.c" files doesn't work with some "make"s;
# they seem to pass only the first few names in the list to the shell,
# for some reason.
#
# Therefore, we have a script to generate the "register.c" file.
#
# The first argument is the directory in which the source files live.
# All subsequent arguments are the files to scan.
#
register.c: $(DISSECTOR_SOURCES) $(srcdir)/make-reg-dotc
	@echo Making register.c
	@$(srcdir)/make-reg-dotc $(srcdir) $(DISSECTOR_SOURCES)

ps.c: print.ps rdps
	./rdps $(srcdir)/print.ps ps.c

rdps: rdps.c
	$(CC) $(CFLAGS) -o rdps $(srcdir)/rdps.c

randpkt.o: randpkt.c
	$(CC) -DHAVE_CONFIG_H -I. `glib-config --cflags` -c $(srcdir)/randpkt.c

randpkt: randpkt.o wiretap/libwiretap.a
	$(LINK) -o randpkt randpkt.o wiretap/libwiretap.a `glib-config --libs` -lz

DISTCLEANFILES =	\
	register.c	\
	rdps		\
	ps.c		\
	*~

EXTRA_DIST = \
	aclocal-flags		\
	config.h.win32		\
	config.nmake		\
	debian/README.debian	\
	debian/changelog	\
	debian/control		\
	debian/copyright	\
	debian/dirs		\
	debian/docs		\
	debian/menu		\
	debian/postinst		\
	debian/prerm		\
	debian/rules		\
	doc/README.developer    \
	doc/Makefile.in         \
	doc/Makefile.am         \
	doc/README.regression   \
	doc/README.tvbuff	\
	doc/dfilter2pod.pl	\
	doc/editcap.pod		\
	doc/ethereal.pod.template \
	doc/randpkt.txt		\
	doc/tethereal.pod.template \
	editcap.c		\
	getopt.c		\
	getopt.h		\
	ieee-float.h		\
	image/editcap.rc	\
	image/ethereal48x48-trans.png  \
	image/ethereal48x48.png \
	image/ethereal.ico	\
	image/ethereal.rc	\
	image/icon-excl.xpm     \
	image/icon-ethereal.xpm \
	image/tethereal.rc	\
	INSTALL.configure       \
	libpcap-0.4.HPUX.HPUXPAC.patch \
	libpcap-0.4.HPUX.LBL.patch \
	libpcap-0.5.HPUX.tcpdump.org.patch \
	Makefile.nmake		\
	make-reg-dotc		\
	manuf                   \
	ncp2222.py              \
	packet-ncp2222.inc	\
	print.ps                \
	README.aix		\
	README.bsd		\
	README.hpux		\
	README.irix		\
	README.linux		\
	README.tru64		\
	README.vmware		\
	README.win32		\
	randpkt.c		\
	rdps.c			\
	TODO

if SETUID_INSTALL
install-exec-hook:
	-chmod +s $(DESTDIR)$(bindir)/ethereal
	-chmod +s $(DESTDIR)$(bindir)/tethereal
	-chmod +s $(DESTDIR)$(bindir)/ethereal_static
else
install-exec-hook:
endif

#
# Currently register.c can be included in the distribution because
# we always build all protocol dissectors. We used to have to check
# whether or not to build the snmp dissector. If we again need to
# variably build something, making register.c non-portable, uncomment
# the dist-hook line below.
#
# Oh, yuk.  We don't want to include "register.c" in the distribution, as
# its contents depend on the configuration, and therefore we want it
# to be built when the first "make" is done; however, Automake insists
# on putting *all* source into the distribution.
#
# We work around this by having a "dist-hook" rule that deletes
# "register.c", so that "dist" won't pick it up.
#
#dist-hook:
#	@rm -f $(distdir)/register.c

SUBDIRS = wiretap epan gtk plugins packaging @ethereal_SUBDIRS@

ethereal.1: ethereal doc/ethereal.pod.template
	(cd doc ; \
	$(MAKE) ../ethereal.1 )

tethereal.1: tethereal doc/tethereal.pod.template
	(cd doc ; \
	$(MAKE) ../tethereal.1 )

editcap.1: doc/editcap.pod
	(cd doc ; \
	$(MAKE) ../editcap.1 )

packet-ncp2222.c : ncp2222.py
	$(PYTHON) $(srcdir)/ncp2222.py > $@

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

# We load top_stagedir with an explicit path so that libtool doesn't freak.
top_stagedir=`cd $(top_srcdir) && pwd`/packaging/svr4.stage
stagedir=$(top_stagedir)/$(PACKAGE).stage
host_cpu=@host_cpu@
host_os=@host_os@

svr4-package: $(bin_SCRIPTS) $(lib_LTLIBRARIES)
	if test x$(HAVE_SVR4_PACKAGING) = xyes ; then \
		rm -rf $(stagedir) ; \
		$(MAKE) DESTDIR=$(stagedir) install-strip; \
		$(srcdir)/packaging/svr4/mkpkg \
			$(PACKAGE) \
			$(PACKAGE)-$(VERSION)-$(host_os)-$(host_cpu)-local \
			$(prefix) \
			$(top_stagedir) ; \
	else \
		echo "Error: SVR4 packaging tools not found." ; \
		echo "Package build abandoned." ; \
	fi

solaris-package: svr4-package

specfile=$(top_srcdir)/packaging/rpm/ethereal.spec

rpm-package: dist
	if test x$(HAVE_RPM_PACKAGING) = xyes ; then \
		cp $(top_srcdir)/$(distdir).tar.gz $(RPM_SOURCEDIR) ; \
		rpm -bb --clean --rmsource $(specfile) ; \
	else \
		echo "Error: RPM executable and/or source directory not found." ; \
		echo "Package build abandoned." ; \
	fi

srpm-package: dist
	if test x$(HAVE_RPM_PACKAGING) = xyes ; then \
		cp $(top_srcdir)/$(distdir).tar.gz $(RPM_SOURCEDIR) ; \
		rpm -bs --clean --rmsource $(specfile) ; \
	else \
		echo "Error: RPM executable and/or source directory not found." ; \
		echo "Package build abandoned." ; \
	fi

debian-package: debian/rules
	dpkg-buildpackage -rfakeroot -us -uc

clean-local:
	rm -rf $(top_stagedir)

