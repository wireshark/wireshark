# Makefile.am
# Automake file for Wireshark
#
# $Id$
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
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

#
# This is a hideous hack.
#
# Automake needs to know into which sections to install various man
# pages; if the names in "man_MANS" have suffixes, it can infer the
# sections from the name (e.g., "hello.1" goes in section 1), but if
# they don't have suffixes, it can't tell what sections to put them, and
# it just gives up and doesn't create any rules to install them (and it
# gives up silently, so you have no clue what's wrong).
#
# Therefore, we can't just set "man_MANS" to a list of variables to be
# filled in by the configure script, as those variables don't have man
# page section numbers.
#
# It turns out (although this is not documented anywhere I could find
# in the automake Info file) that if you define, instead, variables with
# names like "man{section}_MANS", automake will infer that the names in
# those variables are the names of man pages to be installed in section
# "{section}".
#
# So, as all our man pages go in section 1, we define "man1_MANS" to
# contain all the man page.
#
# *However*, if "man_MANS" isn't defined at all, automake concludes that
# there are no man pages, the fact that, say, "man1_MANS" is defined
# nonwithstanding!  (I suspect this is the result of a mistaken attempt
# to get people to fix their automake files not to use "MANS"; if "MANS"
# is defined, it prints a warning and sets the exit status, but doesn't
# exit, and then it just gives up if "man_MANS" isn't defined,
# presumably on the theory that the only reason it wouldn't be defined
# is because the automake file uses the obsolete "MANS" variable instead
# of the shiny new "man_MANS" variable.)
#
# So we also define "man_MANS", but don't define it as anything;
# automake will arrange that the Makefile define it as the union of all
# the "man{section}_MANS" variables.
#
bin_PROGRAMS = @wireshark_bin@ @capinfos_bin@ @editcap_bin@ @mergecap_bin@ @tshark_bin@ @dftest_bin@ @randpkt_bin@ @text2pcap_bin@ @dumpcap_bin@
bin_SCRIPTS = @idl2wrs_bin@
man1_MANS = @wireshark_man@ @capinfos_man@ @editcap_man@ @mergecap_man@ @tshark_man@ @text2pcap_man@ @dumpcap_man@ @idl2wrs_man@
man4_MANS = @wiresharkfilter_man@
man_MANS =

EXTRA_PROGRAMS = wireshark tshark capinfos editcap mergecap dftest \
	randpkt text2pcap dumpcap
EXTRA_SCRIPTS = idl2wrs

idl2wrs: tools/idl2wrs.sh Makefile
	cp tools/idl2wrs.sh idl2wrs
	chmod +x idl2wrs

#
# Wireshark configuration files are put in $(pkgdatadir).
#
pkgdata_DATA = AUTHORS-SHORT COPYING manuf wireshark.html tshark.html \
	wireshark-filter.html capinfos.html editcap.html \
	idl2wrs.html mergecap.html text2pcap.html dumpcap.html \
	cfilters colorfilters dfilters

#
# Install the Diameter DTD and XML files in the "diameter" subdirectory
# of that directory.
#
diameterdir = $(pkgdatadir)/diameter
diameter_DATA = \
	diameter/chargecontrol.xml \
	diameter/dictionary.dtd \
	diameter/dictionary.xml \
	diameter/imscxdx.xml \
	diameter/mobileipv4.xml \
	diameter/nasreq.xml \
	diameter/sip.xml \
	diameter/sunping.xml \
	diameter/TGPPSh.xml

#
# Install the DTDs directory files in the "dtds" subdirectory
# of that directory
#
dtdsdir = $(pkgdatadir)/dtds
dtds_DATA = \
	dtds/dc.dtd \
	dtds/itunes.dtd \
	dtds/pocsettings.dtd \
	dtds/presence.dtd \
	dtds/reginfo.dtd \
	dtds/rlmi.dtd \
	dtds/rss.dtd \
	dtds/smil.dtd \
	dtds/xcap-caps.dtd \
	dtds/watcherinfo.dtd
#
# Install the RADIUS directory files in the "radius" subdirectory
# of that directory.
#
radiusdir = $(pkgdatadir)/radius
radius_DATA = \
	radius/dictionary  \
	radius/dictionary.3com  \
	radius/dictionary.3gpp  \
	radius/dictionary.3gpp2  \
	radius/dictionary.acc  \
	radius/dictionary.alcatel  \
	radius/dictionary.alteon  \
	radius/dictionary.altiga  \
	radius/dictionary.aptis  \
	radius/dictionary.ascend  \
	radius/dictionary.bay  \
	radius/dictionary.bintec  \
	radius/dictionary.bristol  \
	radius/dictionary.cablelabs  \
	radius/dictionary.cabletron  \
	radius/dictionary.cisco  \
	radius/dictionary.cisco.bbsm  \
	radius/dictionary.cisco.vpn3000  \
	radius/dictionary.cisco.vpn5000  \
	radius/dictionary.colubris  \
	radius/dictionary.columbia_university  \
	radius/dictionary.compat  \
	radius/dictionary.cosine  \
	radius/dictionary.ericsson  \
	radius/dictionary.erx  \
	radius/dictionary.extreme  \
	radius/dictionary.foundry  \
	radius/dictionary.freeradius  \
	radius/dictionary.gandalf  \
	radius/dictionary.garderos  \
	radius/dictionary.gemtek  \
	radius/dictionary.itk  \
	radius/dictionary.juniper  \
	radius/dictionary.karlnet  \
	radius/dictionary.livingston  \
	radius/dictionary.localweb  \
	radius/dictionary.merit  \
	radius/dictionary.microsoft  \
	radius/dictionary.mikrotik  \
	radius/dictionary.navini  \
	radius/dictionary.netscreen  \
	radius/dictionary.nokia  \
	radius/dictionary.nomadix  \
	radius/dictionary.propel  \
	radius/dictionary.quintum  \
	radius/dictionary.redback  \
	radius/dictionary.redcreek  \
	radius/dictionary.shasta  \
	radius/dictionary.shiva  \
	radius/dictionary.sonicwall  \
	radius/dictionary.springtide  \
	radius/dictionary.t_systems_nova  \
	radius/dictionary.telebit  \
	radius/dictionary.trapeze  \
	radius/dictionary.tunnel  \
	radius/dictionary.unisphere  \
	radius/dictionary.unix  \
	radius/dictionary.usr  \
	radius/dictionary.valemount  \
	radius/dictionary.versanet  \
	radius/dictionary.wispr  \
	radius/dictionary.xedia

PLATFORM_SRC = capture-pcap-util-unix.c

include Makefile.common

if HAVE_PLUGINS

plugin_libs = \
	plugins/agentx/agentx.la \
	plugins/artnet/artnet.la \
	plugins/asn1/asn1.la \
	plugins/ciscosm/ciscosm.la \
	plugins/docsis/docsis.la \
	plugins/enttec/enttec.la \
	plugins/giop/cosnaming.la \
	plugins/giop/coseventcomm.la \
	plugins/gryphon/gryphon.la \
	plugins/irda/irda.la \
	plugins/lwres/lwres.la \
	plugins/mate/mate.la \
	plugins/megaco/megaco.la \
	plugins/mgcp/mgcp.la \
	plugins/opsi/opsi.la \
	plugins/pcli/pcli.la \
	plugins/profinet/profinet.la \
	plugins/rlm/rlm.la \
	plugins/rtnet/rtnet.la \
	plugins/rudp/rudp.la \
	plugins/sbus/sbus.la \
	plugins/stats_tree/stats_tree.la \
	plugins/v5ua/v5ua.la

if ENABLE_STATIC
plugin_ldadd = $(plugin_libs)

else		# ENABLE_STATIC

plugin_ldadd = \
	"-dlopen" self	\
	"-dlopen" plugins/agentx/agentx.la \
	"-dlopen" plugins/artnet/artnet.la \
	"-dlopen" plugins/asn1/asn1.la \
	"-dlopen" plugins/ciscosm/ciscosm.la \
	"-dlopen" plugins/docsis/docsis.la \
	"-dlopen" plugins/enttec/enttec.la \
	"-dlopen" plugins/giop/cosnaming.la \
	"-dlopen" plugins/giop/coseventcomm.la \
	"-dlopen" plugins/gryphon/gryphon.la \
	"-dlopen" plugins/h223/h223.la \
	"-dlopen" plugins/irda/irda.la \
	"-dlopen" plugins/lwres/lwres.la \
	"-dlopen" plugins/mate/mate.la \
	"-dlopen" plugins/megaco/megaco.la \
	"-dlopen" plugins/mgcp/mgcp.la \
	"-dlopen" plugins/opsi/opsi.la \
	"-dlopen" plugins/pcli/pcli.la \
	"-dlopen" plugins/profinet/profinet.la \
	"-dlopen" plugins/rlm/rlm.la \
	"-dlopen" plugins/rtnet/rtnet.la \
	"-dlopen" plugins/rudp/rudp.la \
	"-dlopen" plugins/sbus/sbus.la \
	"-dlopen" plugins/stats_tree/stats_tree.la \
	"-dlopen" plugins/v5ua/v5ua.la

endif		# ENABLE_STATIC

else		# HAVE_PLUGINS
plugin_libs =

plugin_ldadd =
endif		# HAVE_PLUGINS

# Optional objects that I know how to build. These will be
# linked into the wireshark executable.
# They will also be linked into the tshark executable; if this
# list ever grows to include something that can't be linked with
# tshark, or if tshark needs something that wireshark doesn't,
# we should probably split this into stuff needed both
# by wireshark and tshark and stuff needed only by one or the
# other.
wireshark_optional_objects = @GETOPT_O@ @STRERROR_O@ \
	@STRCASECMP_O@ @STRNCASECMP_O@ @MKSTEMP_O@ @STRPTIME_O@

# Additional libs that I know how to build. These will be
# linked into the wireshark executable.
wireshark_additional_libs = \
	gtk/libui.a		\
	codecs/libcodec.a	\
	wiretap/libwiretap.la	\
	epan/libwireshark.la

# This is the automake dependency variable for the executable
wireshark_DEPENDENCIES = \
	$(wireshark_optional_objects)	\
	$(wireshark_additional_libs)	\
	$(plugin_libs)

# This automake variable adds to the link-line for the executable.
#
# Note that Wireshark doesn't have to be linked with @GLIB_LIBS@, as
# they are included in @GTK_LIBS@, and doesn't have to be linked with
# @SOCKET_LIBS@ or @NSL_LIBS@, as those should also be included in
# @GTK_LIBS@ (as those are also needed for X applications, and GTK+
# applications are X applications).

if ENABLE_STATIC
wireshark_LDFLAGS = -Wl,-static -all-static
else
wireshark_LDFLAGS = -export-dynamic
endif

wireshark_LDADD = \
	$(wireshark_optional_objects)	\
	$(wireshark_additional_libs)	\
	@SNMP_LIBS@ @SSL_LIBS@ 		\
	$(plugin_ldadd)			\
	@PCRE_LIBS@			\
	@PCAP_LIBS@ @GTK_LIBS@ @ADNS_LIBS@ @KRB5_LIBS@ @FRAMEWORKS@ \
	@LIBICONV@			\
	@LIBGCRYPT_LIBS@		\
	@LIBGNUTLS_LIBS@		\
	@PORTAUDIO_LIBS@

# Additional libs that I know how to build. These will be
# linked into the tshark executable.
tshark_additional_libs =		\
	wiretap/libwiretap.la		\
	epan/libwireshark.la

# This is the automake dependency variable for the executable
tshark_DEPENDENCIES = \
	$(wireshark_optional_objects)	\
	$(tshark_additional_libs)	\
	$(plugin_libs)

# This automake variable adds to the link-line for the executable
tshark_LDADD = \
	$(wireshark_optional_objects)	\
	$(tshark_additional_libs)	\
	@SNMP_LIBS@ @SSL_LIBS@		\
	$(plugin_ldadd)			\
	@PCRE_LIBS@			\
	@GLIB_LIBS@ -lm			\
	@PCAP_LIBS@ @SOCKET_LIBS@ @NSL_LIBS@ @ADNS_LIBS@ @KRB5_LIBS@ \
	@LIBICONV@			\
	@LIBGCRYPT_LIBS@		\
	@LIBGNUTLS_LIBS@

if ENABLE_STATIC
tshark_LDFLAGS = -Wl,-static -all-static
else
tshark_LDFLAGS = -export-dynamic
endif

# Optional objects that I know how to build, and that are needed by
# text2pcap.
text2pcap_optional_objects = @STRERROR_O@ @STRPTIME_O@

text2pcap_DEPENDENCIES = text2pcap.h

# This automake variable adds to the link-line for the executable
text2pcap_LDADD = $(text2pcap_optional_objects) \
	@GLIB_LIBS@ -lm

mergecap_DEPENDENCIES = wiretap/libwiretap.la

# This is the automake dependency variable for the executable
capinfos_DEPENDENCIES = wiretap/libwiretap.la
editcap_DEPENDENCIES = wiretap/libwiretap.la

# This automake variable adds to the link-line for the executable
capinfos_LDADD = wiretap/libwiretap.la @GLIB_LIBS@
editcap_LDADD = wiretap/libwiretap.la @GLIB_LIBS@
mergecap_LDADD = wiretap/libwiretap.la @GLIB_LIBS@

# Common headers
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/wiretap \
	$(LIBGNUTLS_CFLAGS) $(LIBGCRYPT_CFLAGS)

#
# Build the version string
#
# FORCE is the portable version of .PHONY
FORCE:

svnversion.h: FORCE
	$(PERL) $(srcdir)/make-version.pl $(srcdir)

#
# Build the short version of the authors file for the about dialog
#
AUTHORS-SHORT: AUTHORS make-authors-short.pl
	$(PERL) $(srcdir)/perlnoutf.pl $(srcdir)/make-authors-short.pl < $(srcdir)/AUTHORS > AUTHORS-SHORT

#
# Build the short version of the authors file with formatting codes for the
# man page
#
AUTHORS-SHORT-FORMAT: AUTHORS-SHORT make-authors-format.pl
	$(PERL) $(srcdir)/perlnoutf.pl $(srcdir)/make-authors-format.pl < AUTHORS-SHORT > AUTHORS-SHORT-FORMAT

#
# Build shell scripts by doing variable substitution.
# Taken from autoconf 2.13.
#
editsh = sed -e 's,@''SHELL''@,$(SHELL),g'

SUFFIXES = .sh
.sh:
	rm -f $@ $@.tmp
	$(editsh) $< > $@.tmp && chmod +x $@.tmp && mv $@.tmp $@

#
# Build "tshark-tap-register.c", which contains a function
# "register_all_tap_listeners()"
# that calls the register routines for all tshark tap listeners.
#
# We do this by grepping through sources.
#
# Formatting conventions:  The name of the tap_listener_register_*
# routines must start in column zero, or must be preceded only by
# "void " starting in column zero, and must not be inside #if.
#
# The first argument is the directory in which the source files live.
# All subsequent arguments are the files to scan.
#
tshark-tap-register.c: $(TSHARK_TAP_SRC) $(srcdir)/make-tapreg-dotc
	@echo Making tshark-tap-register.c
	@$(srcdir)/make-tapreg-dotc tshark-tap-register.c $(srcdir) $(TSHARK_TAP_SRC)

ps.c: print.ps rdps
	./rdps $(srcdir)/print.ps ps.c

rdps: rdps.c
	$(CC_FOR_BUILD) $(CFLAGS_FOR_BUILD) -o rdps $(srcdir)/rdps.c

randpkt_additional_libs = wiretap/libwiretap.la

randpkt_DEPENDENCIES = \
	$(randpkt_additional_libs)

randpkt_LDADD = \
	$(randpkt_additional_libs) \
	@GLIB_LIBS@ -lm			\
	@PCAP_LIBS@ @SOCKET_LIBS@ @NSL_LIBS@ @ADNS_LIBS@

dftest_additional_libs =		\
	wiretap/libwiretap.la		\
	epan/libwireshark.la

dftest_DEPENDENCIES = \
	$(wireshark_optional_objects)	\
	$(dftest_additional_libs)	\
	$(plugin_libs)

# This automake variable adds to the link-line for the executable
dftest_LDADD = \
	$(wireshark_optional_objects)	\
	$(dftest_additional_libs)	\
	@SNMP_LIBS@ @SSL_LIBS@		\
	$(plugin_ldadd)			\
	@PCRE_LIBS@			\
	@GLIB_LIBS@ -lm			\
	@PCAP_LIBS@ @SOCKET_LIBS@ @NSL_LIBS@ @ADNS_LIBS@ @KRB5_LIBS@ \
	@LIBICONV@			\
	@LIBGCRYPT_LIBS@		\
	@LIBGNUTLS_LIBS@

dftest_LDFLAGS = -export-dynamic

dumpcap_additional_libs = \
	wiretap/libwiretap.la

dumpcap_DEPENDENCIES = \
	$(dumpcap_additional_libs)

dumpcap_LDADD = \
	$(dumpcap_additional_libs)	\
	@GLIB_LIBS@			\
	@LIBGCRYPT_LIBS@		\
	@PCAP_LIBS@ @SOCKET_LIBS@ @NSL_LIBS@

#
# XXX - "svnversion.h" is distributed in the release tarball; should
# we be deleting it with "make clean", or should we only do that with
# "make maintainer-clean"?
#
CLEANFILES =		\
	svnversion.h	\
	@rdps_bin@	\
	idl2wrs		\
	*~		\
	vgcore.pid*

#
# XXX - "ps.c" is distributed in the source tarballs; why is it in the
# list of files removed by "make distclean"?  (It's deliberately
# included in that list.)
#
DISTCLEANFILES = \
	AUTHORS-SHORT		\
	AUTHORS-SHORT-FORMAT	\
	ps.c

MAINTAINERCLEANFILES =		\
	$(GENERATED_FILES)	\
	Makefile.in		\
	aclocal.m4		\
	config.h.in		\
	configure		\
	depcomp			\
	install-sh		\
	ltmain.sh		\
	missing

EXTRA_DIST = \
	FAQ			\
	INSTALL.configure	\
	Makefile.common		\
	Makefile.nmake		\
	README.aix		\
	README.bsd		\
	README.hpux		\
	README.irix		\
	README.linux		\
	README.macos		\
	README.tru64		\
	README.vmware		\
	README.win32		\
	aclocal-fallback/glib-2.0.m4 \
	aclocal-fallback/glib.m4 \
	aclocal-fallback/gtk-2.0.m4 \
	aclocal-fallback/gtk.m4 \
	aclocal-fallback/iconv.m4 \
	aclocal-flags		\
	autogen.sh		\
	capinfos.c		\
	capture-wpcap.c		\
	capture-wpcap.h		\
	capture_wpcap_packet.c  \
	capture_wpcap_packet.h  \
	cfilters 		\
	colorfilters 		\
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
	dfilters 		\
	doc/Makefile.am		\
	doc/Makefile.nmake	\
	doc/README.capture	\
	doc/README.design	\
	doc/README.developer	\
	doc/README.idl2wrs	\
	doc/README.malloc	\
	doc/README.plugins	\
	doc/README.regression   \
	doc/README.stats_tree	\
	doc/README.tapping	\
	doc/README.xml-output	\
	doc/capinfos.pod		\
	doc/dfilter2pod.pl	\
	doc/editcap.pod		\
	doc/wireshark-filter.pod.template \
	doc/wireshark.pod	\
	doc/idl2wrs.pod		\
	doc/mergecap.pod	\
	doc/randpkt.txt		\
	doc/tshark.pod	\
	doc/text2pcap.pod	\
	doc/dumpcap.pod	\
	docbook/Makefile.auto.am	\
	doxygen.cfg.in		\
	dumpcap.c	\
	editcap.c		\
	epan/libwireshark.def	\
	wireshark.desktop	\
	image/capinfos.rc.in	\
	image/clist_ascend.xpm	\
	image/clist_descend.xpm	\
	image/dn_arrow.xpm	\
	image/dumpcap.rc.in	\
	image/editcap.rc.in	\
	image/hi16-app-wireshark.png	\
	image/hi32-app-wireshark.png	\
	image/hi48-app-wireshark.png	\
	image/icon_layout_1.xpm \
	image/icon_layout_2.xpm \
	image/icon_layout_3.xpm \
	image/icon_layout_4.xpm \
	image/icon_layout_5.xpm \
	image/icon_layout_6.xpm \
	image/libwireshark.rc.in	\
	image/lo16-app-wireshark.png	\
	image/lo32-app-wireshark.png	\
	image/lo48-app-wireshark.png	\
	image/Makefile.nmake	\
	image/mergecap.rc.in	\
	image/nsis-checked.bmp	\
	image/nsis-unchecked.bmp	\
	image/README.image	\
	image/stock_dialog_error_48.xpm	\
	image/stock_dialog_info_48.xpm	\
	image/stock_dialog_question_48.xpm	\
	image/stock_dialog_stop_48.xpm	\
	image/stock_dialog_warning_48.xpm	\
	image/text2pcap.rc.in	\
	image/toolbar/autoscroll_24.xpm	\
	image/toolbar/capture_airpcap_16.xpm \
	image/toolbar/capture_capture_16.xpm \
	image/toolbar/capture_details_16.xpm \
	image/toolbar/capture_details_24.xpm \
	image/toolbar/capture_ethernet_16.xpm  \
	image/toolbar/capture_filter_24.xpm	\
	image/toolbar/capture_interfaces_24.xpm	\
	image/toolbar/capture_options_24.xpm	\
	image/toolbar/capture_prepare_16.xpm \
	image/toolbar/capture_restart_24.xpm	\
	image/toolbar/capture_start_24.xpm	\
	image/toolbar/capture_stop_24.xpm	\
	image/toolbar/checkbox_16.xpm	\
	image/toolbar/colorize_24.xpm	\
	image/toolbar/conversations_16.xpm	\
	image/toolbar/decode_as_16.xpm	\
	image/toolbar/display_filter_24.xpm	\
	image/toolbar/endpoints_16.xpm	\
	image/toolbar/file_set_list_16.xpm	\
	image/toolbar/file_set_next_16.xpm	\
	image/toolbar/file_set_previous_16.xpm	\
	image/toolbar/graphs_16.xpm	\
	image/toolbar/internet_24.xpm	\
	image/toolbar/resize_columns_24.xpm	\
	image/toolbar/stock_add_24.xpm	\
	image/toolbar/stock_bottom_24.xpm	\
	image/toolbar/stock_clear_24.xpm	\
	image/toolbar/stock_close_24.xpm	\
	image/toolbar/stock_colorselector_24.xpm	\
	image/toolbar/stock_help_24.xpm	\
	image/toolbar/stock_jump_to_24.xpm	\
	image/toolbar/stock_left_arrow_24.xpm	\
	image/toolbar/stock_ok_20.xpm	\
	image/toolbar/stock_open_24.xpm	\
	image/toolbar/stock_preferences_24.xpm	\
	image/toolbar/stock_print_24.xpm	\
	image/toolbar/stock_properties_24.xpm	\
	image/toolbar/stock_refresh_24.xpm	\
	image/toolbar/stock_right_arrow_24.xpm	\
	image/toolbar/stock_save_24.xpm	\
	image/toolbar/stock_save_as_24.xpm	\
	image/toolbar/stock_search_24.xpm	\
	image/toolbar/stock_stop_24.xpm	\
	image/toolbar/stock_top_24.xpm	\
	image/toolbar/stock_zoom_1_24.xpm	\
	image/toolbar/stock_zoom_in_24.xpm	\
	image/toolbar/stock_zoom_out_24.xpm	\
	image/toolbar/telephony_16.xpm	\
	image/toolbar/time_24.xpm	\
	image/toolbar/web_support_24.xpm	\
	image/toolbar/wep_closed_24.xpm \
	image/toolbar/wiki_24.xpm	\
	image/tshark.rc.in	\
	image/up_arrow.xpm	\
	image/win32-file-dlg.rc \
	image/wiresharkdoc.ico	\
	image/wireshark.exe.manifest.in \
	image/wireshark.ico	\
	image/wireshark.rc.in	\
	image/wiretap.rc.in	\
	image/wsicon.svg	\
	image/wsicon16.png	\
	image/wsicon16.xpm	\
	image/wsicon256.png	\
	image/wsicon32.png	\
	image/wsicon32.xpm	\
	image/wsicon48.png	\
	image/wsicon48.xpm	\
	image/wsicon64.png	\
	image/wsicon64.xpm	\
	image/wsiconcap.svg	\
	image/wsiconcap16.xpm	\
	image/wsiconcap256.png	\
	image/wsiconcap32.xpm	\
	image/wsiconcap48.xpm	\
	image/wsicondoc.svg	\
	image/wsicondoc256.png	\
	image/wslogo.eps	\
	image/wslogo.svg	\
	image/wssplash.xpm	\
	make-authors-format.pl	\
	make-authors-short.pl	\
	make-manuf		\
	make-tapreg-dotc	\
	make-version.pl		\
	manuf			\
	manuf.tmpl		\
	mergecap.c		\
	perlnoutf.pl		\
	print.ps		\
	$(diameter_DATA)	\
	$(dtds_DATA)		\
	$(radius_DATA)		\
	randpkt.c		\
	rdps.c			\
	text2pcap-scanner.l	\
	text2pcap.c		\
	text2pcap.h		\
	packaging/u3/win32/README.txt		\
	packaging/u3/win32/makefile.nmake	\
	packaging/u3/win32/manifest.tmpl	\
	packaging/u3/win32/u3util.c		\
	tools/idl2wrs.sh.in			\
	wka.tmpl

if SETUID_INSTALL
install-exec-hook:
	-chmod +s $(DESTDIR)$(bindir)/dumpcap
	-chmod +s $(DESTDIR)$(bindir)/tshark
else
install-exec-hook:
endif

DIST_SUBDIRS = asn1 codecs doc epan gtk help packaging plugins tools wiretap

if HAVE_PLUGINS
SUBDIRS = tools wiretap doc epan plugins packaging help @wireshark_SUBDIRS@
else
SUBDIRS = tools wiretap doc epan packaging help @wireshark_SUBDIRS@
endif

wireshark.1: doc/wireshark.pod AUTHORS-SHORT-FORMAT
	(cd doc ; \
	$(MAKE) ../wireshark.1 )

tshark.1: doc/tshark.pod
	(cd doc ; \
	$(MAKE) ../tshark.1 )

wireshark-filter.4: tshark doc/wireshark-filter.pod.template
	(cd doc ; \
	$(MAKE) ../wireshark-filter.4 )

capinfos.1: doc/capinfos.pod
	(cd doc ; \
	$(MAKE) ../capinfos.1 )

editcap.1: doc/editcap.pod
	(cd doc ; \
	$(MAKE) ../editcap.1 )

idl2wrs.1: doc/idl2wrs.pod
	(cd doc ; \
	$(MAKE) ../idl2wrs.1 )

mergecap.1: doc/mergecap.pod
	(cd doc ; \
	$(MAKE) ../mergecap.1 )

text2pcap.1: doc/text2pcap.pod
	(cd doc ; \
	$(MAKE) ../text2pcap.1 )

dumpcap.1: doc/dumpcap.pod
	(cd doc ; \
	$(MAKE) ../dumpcap.1 )

wireshark.html: doc/wireshark.pod AUTHORS-SHORT-FORMAT
	(cd doc ; \
	$(MAKE) ../wireshark.html )

tshark.html: doc/tshark.pod
	(cd doc ; \
	$(MAKE) ../tshark.html )

wireshark-filter.html: tshark doc/wireshark-filter.pod.template
	(cd doc ; \
	$(MAKE) ../wireshark-filter.html )

capinfos.html: doc/capinfos.pod
	(cd doc ; \
	$(MAKE) ../capinfos.html )

editcap.html: doc/editcap.pod
	(cd doc ; \
	$(MAKE) ../editcap.html )

idl2wrs.html: doc/idl2wrs.pod
	(cd doc ; \
	$(MAKE) ../idl2wrs.html )

mergecap.html: doc/mergecap.pod
	(cd doc ; \
	$(MAKE) ../mergecap.html )

text2pcap.html: doc/text2pcap.pod
	(cd doc ; \
	$(MAKE) ../text2pcap.html )

dumpcap.html: doc/dumpcap.pod
	(cd doc ; \
	$(MAKE) ../dumpcap.html )

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

# We load top_stagedir with an explicit path so that libtool doesn't freak.
top_stagedir=`cd $(top_srcdir) && pwd`/packaging/svr4.stage
stagedir=$(top_stagedir)/$(PACKAGE).stage
host_cpu=@host_cpu@
host_os=@host_os@

svr4-package: $(bin_SCRIPTS) $(lib_LTLIBRARIES)
	@if test x$(HAVE_SVR4_PACKAGING) = xyes ; then \
		rm -rf $(stagedir) ; \
		$(MAKE) DESTDIR=$(stagedir) install; \
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

rpm_topdir=`cd $(top_srcdir) && pwd`/packaging/rpm
rpm-package: dist
	if test x$(HAVE_RPM) = xyes ; then \
		cd $(rpm_topdir) ; \
		mkdir -p BUILD RPMS SOURCES ; \
		cd SOURCES ; \
		ln -s ../../../$(distdir).tar.gz ; \
		ln -s ../../../wireshark.desktop ; \
		ln -s ../../../image/wsicon64.png wireshark.png ; \
		cd .. ; \
		rpmbuild --define "_topdir `cd . && pwd`" -bb SPECS/wireshark.spec && \
			echo "Package successfully built in `pwd`/RPMS." ; \
	else \
		echo "Error: RPM executable and/or source directory not found." ; \
	fi
srpm-package: dist
	if test x$(HAVE_RPM) = xyes ; then \
		cd $(rpm_topdir) ; \
		mkdir -p BUILD SRPMS SOURCES ; \
		cd SOURCES ; \
		ln -s ../../../$(distdir).tar.gz ; \
		ln -s ../../../wireshark.desktop ; \
		ln -s ../../../image/wsicon64.png wireshark.png ; \
		cd .. ; \
		rpmbuild --define "_topdir `cd . && pwd`" -bs SPECS/wireshark.spec && \
			echo "Package successfully built in `pwd`/SRPMS." ; \
	else \
		echo "Error: RPM executable and/or source directory not found." ; \
	fi

debian-package: debian/rules
	dpkg-buildpackage -rfakeroot -us -uc

clean-local:
	rm -rf $(top_stagedir)

