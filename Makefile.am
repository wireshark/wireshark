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

INCLUDES= @LUA_INCLUDES@

if HAVE_LIBPY
py_dissectors_dir = -DPYTHON_DIR=\"@pythondir@\"
else
py_dissectors_dir = -DPYTHON_DIR=
endif


if HAVE_WARNINGS_AS_ERRORS
AM_CLEAN_CFLAGS = -Werror
endif

bin_PROGRAMS = \
	@wireshark_bin@	\
	@tshark_bin@	\
	@text2pcap_bin@	\
	@mergecap_bin@	\
	@capinfos_bin@	\
	@editcap_bin@	\
	@randpkt_bin@	\
	@dftest_bin@	\
	@dumpcap_bin@	\
	@rawshark_bin@

EXTRA_PROGRAMS = wireshark tshark capinfos editcap mergecap dftest \
	randpkt text2pcap dumpcap rawshark
bin_SCRIPTS = tools/idl2wrs

#
# Wireshark configuration files are put in $(pkgdatadir).
#
pkgdata_DATA = COPYING manuf services cfilters colorfilters dfilters \
	smi_modules ipmap.html pdml2html.xsl

#
# Install the Diameter DTD and XML files in the "diameter" subdirectory
# of that directory.
#
diameterdir = $(pkgdatadir)/diameter
diameter_DATA = \
	diameter/chargecontrol.xml \
	diameter/Cisco.xml \
	diameter/dictionary.dtd \
	diameter/dictionary.xml \
	diameter/eap.xml \
	diameter/Ericsson.xml \
	diameter/etsie2e4.xml \
	diameter/gqpolicy.xml \
	diameter/imscxdx.xml \
	diameter/mobileipv4.xml \
	diameter/mobileipv6.xml \
	diameter/nasreq.xml \
	diameter/sip.xml \
	diameter/sunping.xml \
	diameter/TGPPGmb.xml \
	diameter/TGPPRx.xml \
	diameter/TGPPSh.xml	\
	diameter/Vodafone.xml

#
# Install the DTDs directory files in the "dtds" subdirectory
# of that directory
#
dtdsdir = $(pkgdatadir)/dtds
dtds_DATA = \
	dtds/dc.dtd \
	dtds/itunes.dtd \
	dtds/mscml.dtd \
	dtds/pocsettings.dtd \
	dtds/presence.dtd \
	dtds/reginfo.dtd \
	dtds/rlmi.dtd \
	dtds/rss.dtd \
	dtds/smil.dtd \
	dtds/xcap-caps.dtd \
	dtds/xcap-error.dtd \
	dtds/watcherinfo.dtd

#
# Install the RADIUS directory files in the "radius" subdirectory
# of that directory.
#
radiusdir = $(pkgdatadir)/radius
radius_DATA = \
	radius/README.radius_dictionary  \
	radius/dictionary  \
	radius/dictionary.3com  \
	radius/dictionary.3gpp  \
	radius/dictionary.3gpp2  \
	radius/dictionary.acc  \
	radius/dictionary.acme \
	radius/dictionary.airespace \
	radius/dictionary.alcatel  \
	radius/dictionary.alcatel.esam \
	radius/dictionary.alcatel.sr \
	radius/dictionary.alteon  \
	radius/dictionary.altiga  \
	radius/dictionary.alvarion \
	radius/dictionary.apc \
	radius/dictionary.aptis  \
	radius/dictionary.aruba  \
	radius/dictionary.ascend  \
	radius/dictionary.asn \
	radius/dictionary.audiocodes \
	radius/dictionary.avaya \
	radius/dictionary.azaire \
	radius/dictionary.bay  \
	radius/dictionary.bintec  \
	radius/dictionary.bristol  \
	radius/dictionary.cablelabs  \
	radius/dictionary.cabletron  \
	radius/dictionary.chillispot \
	radius/dictionary.cisco  \
	radius/dictionary.cisco.bbsm  \
	radius/dictionary.cisco.vpn3000  \
	radius/dictionary.cisco.vpn5000  \
	radius/dictionary.clavister \
	radius/dictionary.colubris  \
	radius/dictionary.columbia_university  \
	radius/dictionary.compat  \
	radius/dictionary.cosine  \
	radius/dictionary.dhcp \
	radius/dictionary.digium \
	radius/dictionary.eltex \
	radius/dictionary.epygi \
	radius/dictionary.ericsson  \
	radius/dictionary.erx  \
	radius/dictionary.extreme  \
	radius/dictionary.fortinet \
	radius/dictionary.foundry  \
	radius/dictionary.freeradius  \
	radius/dictionary.freeradius.internal  \
	radius/dictionary.freeswitch \
	radius/dictionary.gandalf  \
	radius/dictionary.garderos  \
	radius/dictionary.gemtek  \
	radius/dictionary.h3c \
	radius/dictionary.hp \
	radius/dictionary.huawei \
	radius/dictionary.iea \
	radius/dictionary.infonet \
	radius/dictionary.ipunplugged \
	radius/dictionary.issanni \
	radius/dictionary.itk  \
	radius/dictionary.jradius \
	radius/dictionary.juniper  \
	radius/dictionary.karlnet  \
	radius/dictionary.lancom \
	radius/dictionary.livingston  \
	radius/dictionary.localweb  \
	radius/dictionary.lucent \
	radius/dictionary.manzara \
	radius/dictionary.merit  \
	radius/dictionary.microsoft  \
	radius/dictionary.mikrotik  \
	radius/dictionary.motorola \
	radius/dictionary.motorola.wimax \
	radius/dictionary.navini  \
	radius/dictionary.netscreen  \
	radius/dictionary.networkphysics \
	radius/dictionary.nexans \
	radius/dictionary.nokia  \
	radius/dictionary.nokia.conflict \
	radius/dictionary.nomadix  \
	radius/dictionary.nortel \
	radius/dictionary.ntua \
	radius/dictionary.openser \
	radius/dictionary.packeteer \
	radius/dictionary.patton \
	radius/dictionary.propel  \
	radius/dictionary.prosoft \
	radius/dictionary.quiconnect \
	radius/dictionary.quintum  \
	radius/dictionary.redback  \
	radius/dictionary.redcreek  \
	radius/dictionary.rfc2865 \
	radius/dictionary.rfc2866 \
	radius/dictionary.rfc2867 \
	radius/dictionary.rfc2868 \
	radius/dictionary.rfc2869 \
	radius/dictionary.rfc3162 \
	radius/dictionary.rfc3576 \
	radius/dictionary.rfc3580 \
	radius/dictionary.rfc4072 \
	radius/dictionary.rfc4372 \
	radius/dictionary.rfc4603 \
	radius/dictionary.rfc4675 \
	radius/dictionary.rfc4679 \
	radius/dictionary.rfc4818 \
	radius/dictionary.rfc4849 \
	radius/dictionary.rfc5090 \
	radius/dictionary.rfc5176 \
	radius/dictionary.rfc5580 \
	radius/dictionary.rfc5607 \
	radius/dictionary.rfc5904 \
	radius/dictionary.riverstone \
	radius/dictionary.roaringpenguin \
	radius/dictionary.shasta  \
	radius/dictionary.shiva  \
	radius/dictionary.slipstream \
	radius/dictionary.sofaware \
	radius/dictionary.sonicwall  \
	radius/dictionary.springtide  \
	radius/dictionary.starent  \
	radius/dictionary.t_systems_nova  \
	radius/dictionary.telebit  \
	radius/dictionary.telkom \
	radius/dictionary.trapeze  \
	radius/dictionary.tropos \
	radius/dictionary.ukerna  \
	radius/dictionary.unix  \
	radius/dictionary.usr  \
	radius/dictionary.utstarcom \
	radius/dictionary.valemount  \
	radius/dictionary.versanet  \
	radius/dictionary.vqp \
	radius/dictionary.walabi \
	radius/dictionary.waverider \
	radius/dictionary.wichorus \
	radius/dictionary.wimax  \
	radius/dictionary.wimax.wichorus \
	radius/dictionary.wispr  \
	radius/dictionary.xedia \
	radius/dictionary.xylan \
	radius/dictionary.zyxel

#
# Install the tpncp directory files in the "tpncp" subdirectory
# of that directory
#
tpncpdir = $(pkgdatadir)/tpncp
tpncp_DATA = \
	tpncp/tpncp.dat

#
# Install the ui directory files in the "ui" subdirectory
# of that directory
#
uidir = $(pkgdatadir)/ui
ui_DATA = \
	ui/gtk/ui/main-menubar-ui.xml

#
# Install the wimaxasncp directory files in the "wimaxasncp" subdirectory
# of that directory
#
wimaxasncpdir = $(pkgdatadir)/wimaxasncp
wimaxasncp_DATA = \
	wimaxasncp/dictionary.xml \
	wimaxasncp/dictionary.dtd

PLATFORM_SRC = capture-pcap-util-unix.c

if HAVE_PLUGINS
-include plugins/Custom.make
plugin_ldadd = $(_CUSTOM_plugin_ldadd_) \
	-dlopen plugins/asn1/asn1.la \
	-dlopen plugins/docsis/docsis.la \
	-dlopen plugins/ethercat/ethercat.la \
	-dlopen plugins/giop/cosnaming.la \
	-dlopen plugins/giop/coseventcomm.la \
	-dlopen plugins/gryphon/gryphon.la \
	-dlopen plugins/irda/irda.la \
	-dlopen plugins/m2m/m2m.la \
	-dlopen plugins/mate/mate.la \
	-dlopen plugins/opcua/opcua.la \
	-dlopen plugins/profinet/profinet.la \
	-dlopen plugins/stats_tree/stats_tree.la \
	-dlopen plugins/unistim/unistim.la \
	-dlopen plugins/wimax/wimax.la

WTAP_PLUGIN_SOURCES = \
       epan/plugins.c \
       epan/report_err.c \
       epan/filesystem.c

else		# HAVE_PLUGINS

plugin_ldadd =
WTAP_PLUGIN_SOURCES =

endif		# HAVE_PLUGINS

include Makefile.common

if ENABLE_STATIC
wireshark_LDFLAGS = -Wl,-static -all-static
else
wireshark_LDFLAGS = -export-dynamic
endif

# Libraries and plugin flags with which to link wireshark.
#
# Note that Wireshark doesn't have to be linked with @GLIB_LIBS@, as
# they are included in @GTK_LIBS@, and doesn't have to be linked with
# @SOCKET_LIBS@ or @NSL_LIBS@, as those should also be included in
# @GTK_LIBS@ (as those are also needed for X applications, and GTK+
# applications are X applications).
wireshark_LDADD = \
	ui/gtk/libui.a			\
	ui/gtk/libui_dirty.a		\
	codecs/libcodec.a		\
	wiretap/libwiretap.la		\
	epan/libwireshark.la		\
	wsutil/libwsutil.la		\
	@SSL_LIBS@			\
	$(plugin_ldadd)			\
	@PCAP_LIBS@			\
	@GTK_LIBS@ -lm			\
	@C_ARES_LIBS@			\
	@ADNS_LIBS@			\
	@KRB5_LIBS@			\
	@LAUNCHSERVICES_FRAMEWORKS@	\
	@CORESERVICES_FRAMEWORKS@	\
	@PY_LIBS@			\
	@LIBGCRYPT_LIBS@		\
	@LIBGNUTLS_LIBS@		\
	@LIBSMI_LDFLAGS@		\
	@PORTAUDIO_LIBS@
wireshark_CFLAGS = $(AM_CLEAN_CFLAGS) $(py_dissectors_dir)

if ENABLE_STATIC
tshark_LDFLAGS = -Wl,-static -all-static
else
tshark_LDFLAGS = -export-dynamic
endif

# Libraries and plugin flags with which to link tshark.
tshark_LDADD = \
	wiretap/libwiretap.la		\
	epan/libwireshark.la		\
	wsutil/libwsutil.la		\
	@SSL_LIBS@			\
	$(plugin_ldadd)			\
	@GLIB_LIBS@ -lm			\
	@PCAP_LIBS@			\
	@SOCKET_LIBS@			\
	@NSL_LIBS@			\
	@C_ARES_LIBS@			\
	@ADNS_LIBS@			\
	@KRB5_LIBS@			\
	@CORESERVICES_FRAMEWORKS@	\
	@PY_LIBS@			\
	@LIBGCRYPT_LIBS@		\
	@LIBGNUTLS_LIBS@		\
	@LIBSMI_LDFLAGS@
tshark_CFLAGS = $(AM_CLEAN_CFLAGS) $(py_dissectors_dir)

if ENABLE_STATIC
rawshark_LDFLAGS = -Wl,-static -all-static
else
rawshark_LDFLAGS = -export-dynamic
endif

# Libraries and plugin flags with which to link rawshark.
rawshark_LDADD = \
	wiretap/libwiretap.la		\
	epan/libwireshark.la		\
	wsutil/libwsutil.la		\
	@SSL_LIBS@			\
	$(plugin_ldadd)			\
	@GLIB_LIBS@ -lm			\
	@PCAP_LIBS@			\
	@SOCKET_LIBS@			\
	@NSL_LIBS@			\
	@C_ARES_LIBS@			\
	@ADNS_LIBS@			\
	@KRB5_LIBS@			\
	@CORESERVICES_FRAMEWORKS@	\
	@PY_LIBS@			\
	@LIBGCRYPT_LIBS@		\
	@LIBGNUTLS_LIBS@		\
	@LIBSMI_LDFLAGS@
rawshark_CFLAGS = $(AM_CLEAN_CFLAGS) $(py_dissectors_dir)

# Libraries with which to link text2pcap.
text2pcap_LDADD = \
	wiretap/libwiretap.la		\
	wsutil/libwsutil.la		\
	@GLIB_LIBS@ -lm
# Don't turn on -Werror for text2pcap: its source includes text2pcap-scanner.c
# which is generated (and therefore not always clean).
# We could generate text2pcap.o as a library with -Werror but for now it
# doesn't seem worth the effort.
#text2pcap_CFLAGS = $(AM_CLEAN_CFLAGS)

# Libraries with which to link mergecap.
mergecap_LDADD = \
	wiretap/libwiretap.la		\
	wsutil/libwsutil.la		\
	@GLIB_LIBS@
mergecap_CFLAGS = $(AM_CLEAN_CFLAGS)

# Libraries with which to link capinfos.
capinfos_LDADD = \
	wiretap/libwiretap.la		\
	wsutil/libwsutil.la		\
	@GLIB_LIBS@			\
	@LIBGCRYPT_LIBS@
capinfos_CFLAGS = $(AM_CLEAN_CFLAGS) $(py_dissectors_dir)

# Libraries with which to link editcap.
editcap_LDADD = \
	wiretap/libwiretap.la		\
	wsutil/libwsutil.la		\
	@GLIB_LIBS@
editcap_CFLAGS = $(AM_CLEAN_CFLAGS) $(py_dissectors_dir)

# Libraries with which to link randpkt.
randpkt_LDADD = \
	wiretap/libwiretap.la		\
	wsutil/libwsutil.la		\
	@GLIB_LIBS@ -lm			\
	@PCAP_LIBS@			\
	@SOCKET_LIBS@			\
	@NSL_LIBS@			\
	@C_ARES_LIBS@			\
	@ADNS_LIBS@
randpkt_CFLAGS = $(AM_CLEAN_CFLAGS)

# Libraries and plugin flags with which to link dftest.
dftest_LDADD = \
	wiretap/libwiretap.la		\
	wsutil/libwsutil.la		\
	epan/libwireshark.la		\
	@SSL_LIBS@			\
	$(plugin_ldadd)			\
	@GLIB_LIBS@ -lm			\
	@PCAP_LIBS@			\
	@SOCKET_LIBS@			\
	@NSL_LIBS@			\
	@C_ARES_LIBS@			\
	@ADNS_LIBS@			\
	@KRB5_LIBS@			\
	@PY_LIBS@			\
	@LIBGCRYPT_LIBS@		\
	@LIBGNUTLS_LIBS@		\
	@LIBSMI_LDFLAGS@
dftest_CFLAGS = $(AM_CLEAN_CFLAGS) $(py_dissectors_dir)

# Libraries with which to link dumpcap.
dumpcap_LDADD = \
	wsutil/libwsutil.la		\
	@GLIB_LIBS@			\
	@PCAP_LIBS@			\
	@SOCKET_LIBS@			\
	@NSL_LIBS@			\
	@CORESERVICES_FRAMEWORKS@	\
	@LIBCAP_LIBS@
dumpcap_CFLAGS = $(AM_CLEAN_CFLAGS)

# Common headers
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/wiretap \
	$(LIBGNUTLS_CFLAGS) $(LIBGCRYPT_CFLAGS) $(LIBSMI_CFLAGS) $(PY_CFLAGS)

#
# Build the version string
#
# FORCE is the portable version of .PHONY
FORCE:

svnversion.h: FORCE
	$(PERL) $(srcdir)/make-version.pl $(srcdir)

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
tshark-tap-register.c: $(TSHARK_TAP_SRC) $(srcdir)/tools/make-tapreg-dotc
	@echo Making tshark-tap-register.c
	@$(srcdir)/tools/make-tapreg-dotc tshark-tap-register.c $(srcdir) $(TSHARK_TAP_SRC)

ps.c: print.ps $(srcdir)/tools/rdps.py
	$(PYTHON) $(srcdir)/tools/rdps.py $(srcdir)/print.ps ps.c

services: tools/make-services.pl
	$(PERL) $(srcdir)/tools/make-services.pl

CLEANFILES =		\
	*~		\
	vgcore.*

#
# We have to remove svnversion.h with "make distclean", as, otherwise,
# "make distcheck" fails.  We still need to make the tarballs work
# even if you do "make distclean" and try to rebuild; that's a work in
# progress.
#
# XXX - "ps.c" is distributed in the source tarballs; why is it in the
# list of files removed by "make distclean"?  (It's deliberately
# included in that list.)
#
DISTCLEANFILES = \
	ps.c			\
	svnversion.h

MAINTAINERCLEANFILES =		\
	$(GENERATED_FILES)	\
	Makefile.in		\
	aclocal.m4		\
	compile			\
	config.h.in		\
	configure		\
	depcomp			\
	install-sh		\
	ltmain.sh		\
	missing			\
	ylwrap

EXTRA_DIST = \
	INSTALL.configure	\
	Makefile.am.inc		\
	Makefile.common		\
	Makefile.nmake		\
	Makefile.nmake.inc	\
	README.aix		\
	README.bsd		\
	README.DECT		\
	README.hpux		\
	README.irix		\
	README.linux		\
	README.macos		\
	README.tru64		\
	README.vmware		\
	README.windows		\
	abi-descriptor.template	\
	aclocal-fallback/glib-2.0.m4 \
	aclocal-fallback/gtk-2.0.m4 \
	aclocal-flags		\
	adns_dll.dep		\
	adns_dll.rc		\
	autogen.sh		\
	capinfos.c		\
	capture-wpcap.c		\
	capture-wpcap.h		\
	capture_wpcap_packet.c  \
	capture_wpcap_packet.h  \
	cfilters		\
	colorfilters		\
	config.h.win32		\
	config.nmake		\
	debian/changelog	\
	debian/compat		\
	debian/control		\
	debian/copyright	\
	debian/dirs		\
	debian/headers-check.c	\
	debian/patches/00list	\
	debian/patches/03_preferences.dpatch \
	debian/postinst		\
	debian/pycompat		\
	debian/pyversions	\
	debian/rules		\
	debian/README.source	\
	debian/tshark.files	\
	debian/tshark.manpages	\
	debian/watch		\
	debian/wireshark-common.files \
	debian/wireshark-common.manpages \
	debian/wireshark-common.shlibs \
	debian/wireshark-dev.docs \
	debian/wireshark-dev.files \
	debian/wireshark-dev.header-files \
	debian/wireshark-dev.manpages \
	debian/wireshark-dev.prerm \
	debian/wireshark-root.desktop \
	debian/wireshark.desktop \
	debian/wireshark.files \
	debian/wireshark.manpages \
	debian/wireshark.menu	\
	epan/dfilter/README.dfilter	\
	dfilters		\
	doxygen.cfg.in		\
	dumpcap.c	\
	editcap.c		\
	fix/FIX.xml		\
	fix/FIX40.xml		\
	fix/FIX41.xml		\
	fix/FIX42.xml		\
	fix/FIX43.xml		\
	fix/FIX44.xml		\
	fix/README		\
	fix/Values.xsl		\
	fix/hfDecl.xsl		\
	fix/hfField.xsl		\
	fix/hfList.xsl		\
	idl/coseventcomm.idl	\
	idl/cosnaming.idl	\
	idl/tango.idl	\
	idl/parlay/am.idl	\
	idl/parlay/cccs.idl	\
	idl/parlay/cm.idl	\
	idl/parlay/common_cc_data.idl	\
	idl/parlay/cs.idl	\
	idl/parlay/dsc.idl	\
	idl/parlay/fw_data.idl	\
	idl/parlay/fw_if.idl	\
	idl/parlay/fw_if_access.idl	\
	idl/parlay/fw_if_app.idl	\
	idl/parlay/fw_if_entop.idl	\
	idl/parlay/fw_if_service.idl	\
	idl/parlay/gcc_data.idl	\
	idl/parlay/gcc_interfaces.idl	\
	idl/parlay/gms.idl	\
	idl/parlay/mm.idl	\
	idl/parlay/mmccs.idl	\
	idl/parlay/mmm.idl	\
	idl/parlay/mpcc_data.idl	\
	idl/parlay/mpcc_interfaces.idl	\
	idl/parlay/osa.idl	\
	idl/parlay/pam_data.idl	\
	idl/parlay/pam_interfaces.idl	\
	idl/parlay/Parlay.idl	\
	idl/parlay/policy_data.idl	\
	idl/parlay/policy_interfaces.idl	\
	idl/parlay/README.parlay	\
	idl/parlay/termcap.idl	\
	idl/parlay/ui_data.idl	\
	idl/parlay/ui_interfaces.idl	\
	image/capinfos.rc.in	\
	image/clist_ascend.xpm	\
	image/clist_descend.xpm	\
	image/dumpcap.rc.in	\
	image/editcap.rc.in	\
	image/file_dlg_win32.rc \
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
	image/libwsutil.rc.in	\
	image/lo16-app-wireshark.png	\
	image/lo32-app-wireshark.png	\
	image/lo48-app-wireshark.png	\
	image/Makefile.nmake	\
	image/mergecap.rc.in	\
	image/nsis-checked.bmp	\
	image/nsis-unchecked.bmp	\
	image/rawshark.rc.in	\
	image/README.image	\
	image/stock_dialog_error_48.xpm	\
	image/stock_dialog_info_48.xpm	\
	image/stock_dialog_question_48.xpm	\
	image/stock_dialog_stop_48.xpm	\
	image/stock_dialog_warning_48.xpm	\
	image/text2pcap.rc.in	\
	image/WiresharkDoc_24.xpm	\
	image/toolbar/analyze_24.xpm \
	image/toolbar/audio_player_24.xpm	\
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
	image/toolbar/decode_24.xpm	\
	image/toolbar/decode_as_16.xpm	\
	image/toolbar/display_filter_24.xpm	\
	image/toolbar/endpoints_16.xpm	\
	image/toolbar/expert_info_16.xpm	\
	image/toolbar/file_set_list_16.xpm	\
	image/toolbar/file_set_next_16.xpm	\
	image/toolbar/file_set_previous_16.xpm	\
	image/toolbar/flow_graph_16.xpm	\
	image/toolbar/graphs_16.xpm	\
	image/toolbar/icon_color_0.xpm	\
	image/toolbar/icon_color_1.xpm	\
	image/toolbar/icon_color_2.xpm	\
	image/toolbar/icon_color_3.xpm	\
	image/toolbar/icon_color_4.xpm	\
	image/toolbar/icon_color_5.xpm	\
	image/toolbar/icon_color_6.xpm	\
	image/toolbar/icon_color_7.xpm	\
	image/toolbar/icon_color_8.xpm	\
	image/toolbar/icon_color_9.xpm	\
	image/toolbar/internet_24.xpm	\
	image/toolbar/modem_16.png	\
	image/toolbar/modem_16.xpm	\
	image/toolbar/network_bluetooth_16.png	\
	image/toolbar/network_usb.svg		\
	image/toolbar/network_usb_16.png	\
	image/toolbar/network_virtual_16.xpm	\
	image/toolbar/network_wired_16.png	\
	image/toolbar/network_wireless_16.png	\
	image/toolbar/pipe_16.png	\
	image/toolbar/remote_arrow_16.png	\
	image/toolbar/remote_globe_16.png	\
	image/toolbar/remote_sat_16.png	\
	image/toolbar/resize_columns_24.xpm	\
	image/toolbar/telephone_16.xpm	\
	image/toolbar/telephony_16.xpm	\
	image/toolbar/time_24.xpm	\
	image/toolbar/voip_flow_24.xpm	\
	image/toolbar/web_support_24.xpm	\
	image/toolbar/wep_closed_24.xpm \
	image/toolbar/wiki_24.xpm	\
	image/tshark.rc.in	\
	image/voip_bg.xpm	\
	image/voip_select.xpm	\
	image/wireshark.exe.manifest.in \
	image/wireshark.ico	\
	image/wireshark.rc.in	\
	image/WiresharkDoc-128.png	\
	image/WiresharkDoc-16.png	\
	image/WiresharkDoc-24.png	\
	image/WiresharkDoc-256.png	\
	image/WiresharkDoc-32.png	\
	image/WiresharkDoc-48.png	\
	image/WiresharkDoc-64.png	\
	image/wiresharkdoc.ico	\
	image/wiresharkinst.ico	\
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
	image/wsiconinst.svg	\
	image/wsiconinst256.png	\
	image/wslogo.eps	\
	image/wslogo.svg	\
	image/wssplash-dev.xpm	\
	image/wssplash.xpm	\
	ipmap.html		\
	macosx-setup.sh		\
	macosx-support-lib-patches/glib-gconvert.patch \
	macosx-support-lib-patches/glib-pkgconfig.patch \
	macosx-support-lib-patches/gnutls-pkgconfig.patch \
	make-version.pl		\
	manuf			\
	manuf.tmpl		\
	mergecap.c		\
	pdml2html.xsl		\
	print.ps		\
	$(diameter_DATA)	\
	$(dtds_DATA)		\
	$(radius_DATA)		\
	$(tpncp_DATA)		\
	$(ui_DATA)		\
	$(wimaxasncp_DATA)	\
	randpkt.c		\
	smi_modules		\
	text2pcap-scanner.l	\
	text2pcap.c		\
	text2pcap.h		\
	services		\
	wireshark.desktop	\
	wka.tmpl		\
	CMakeLists.txt		\
	cmakeconfig.h.in	\
	wsutil/CMakeLists.txt	\
	CMakeOptions.txt	\
	wiretap/CMakeLists.txt	\
	README.cmake		\
	ConfigureChecks.cmake	\
	cmake/modules/CMakeInstallDirs.cmake	\
	cmake/modules/COPYING-CMAKE-SCRIPTS	\
	cmake/modules/CheckCLinkerFlag.cmake	\
	cmake/modules/FeatureSummary.cmake	\
	cmake/modules/FindADNS.cmake		\
	cmake/modules/FindCAP.cmake		\
	cmake/modules/FindCARES.cmake		\
	cmake/modules/FindFOP.cmake		\
	cmake/modules/FindGCRYPT.cmake		\
	cmake/modules/FindGEOIP.cmake		\
	cmake/modules/FindGLIB2.cmake		\
	cmake/modules/FindGMODULE2.cmake	\
	cmake/modules/FindGNUTLS.cmake		\
	cmake/modules/FindGTHREAD2.cmake	\
	cmake/modules/FindGTK2.cmake		\
	cmake/modules/FindGTK3.cmake		\
	cmake/modules/FindHtmlViewer.cmake	\
	cmake/modules/FindKERBEROS.cmake	\
	cmake/modules/FindLEX.cmake		\
	cmake/modules/FindLUA.cmake		\
	cmake/modules/FindLYNX.cmake		\
	cmake/modules/FindM.cmake		\
	cmake/modules/FindPCAP.cmake		\
	cmake/modules/FindPOD.cmake		\
	cmake/modules/FindPORTAUDIO.cmake	\
	cmake/modules/FindPYTHON.cmake		\
	cmake/modules/FindSED.cmake		\
	cmake/modules/FindSH.cmake		\
	cmake/modules/FindSMI.cmake		\
	cmake/modules/FindXMLLINT.cmake		\
	cmake/modules/FindXSLTPROC.cmake	\
	cmake/modules/FindYACC.cmake		\
	cmake/modules/FindYAPP.cmake		\
	cmake/modules/FindZLIB.cmake		\
	cmake/modules/LICENSE.txt		\
	cmake/modules/UseLemon.cmake		\
	cmake/modules/UseMakeDissectorReg.cmake	\
	cmake/modules/UseMakeTapReg.cmake	\
	cmake/modules/readme.txt		\
	ui/win32/Makefile.nmake			\
	ui/win32/file_dlg_win32.c		\
	ui/win32/file_dlg_win32.h		\
	ui/win32/print_win32.c			\
	ui/win32/print_win32.h			\
	CPackConfig.txt				\
	all.vcproj				\
	dumpcap.vcproj				\
	packaging.vcproj			\
	tshark.vcproj				\
	wireshark.vcproj

install-exec-hook:
if HAVE_DUMPCAP_GROUP
	-chgrp $(DUMPCAP_GROUP) $(DESTDIR)$(bindir)/dumpcap
endif
if SETCAP_INSTALL
	-$(SETCAP) cap_net_raw,cap_net_admin+eip $(DESTDIR)$(bindir)/dumpcap
	-chmod o-rws $(DESTDIR)$(bindir)/dumpcap
else
if SETUID_INSTALL
	-chmod o-rws $(DESTDIR)$(bindir)/dumpcap
	-chmod +s $(DESTDIR)$(bindir)/dumpcap
endif
endif


DIST_SUBDIRS = asn1 codecs doc epan ui/gtk help packaging plugins tools wiretap wsutil docbook

if HAVE_PLUGINS
SUBDIRS = tools wsutil wiretap epan plugins packaging help @wireshark_SUBDIRS@ . doc
else
SUBDIRS = tools wsutil wiretap epan packaging help @wireshark_SUBDIRS@ . doc
endif

help/faq.txt: $(srcdir)/help/faq.py
	(cd help ; \
	$(MAKE) faq.txt ;)

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

# Used by svr4-package and osx-package
# We load top_stagedir with an explicit path so that libtool doesn't freak.
top_stagedir=`cd $(top_srcdir) && pwd`/packaging/staging
stagedir=$(top_stagedir)/$(PACKAGE).inst

host_cpu=@host_cpu@
host_os=@host_os@

svr4-package: $(PROGRAMS) $(SCRIPTS) $(MANS) $(DATA)
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

rpm_topdir=`cd $(top_builddir) && pwd`/packaging/rpm
rpm-package: dist
	if test x$(HAVE_RPM) = xyes ; then \
		cd $(rpm_topdir) ; \
		mkdir -p BUILD RPMS SOURCES ; \
		cd SOURCES ; \
		ln -s ../../../$(distdir).tar.bz2 ; \
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
		ln -s ../../../$(distdir).tar.bz2 ; \
		ln -s ../../../wireshark.desktop ; \
		ln -s ../../../image/wsicon64.png wireshark.png ; \
		cd .. ; \
		rpmbuild --define "_topdir `cd . && pwd`" -bs SPECS/wireshark.spec && \
			echo "Package successfully built in `pwd`/SRPMS." ; \
	else \
		echo "Error: RPM executable and/or source directory not found." ; \
	fi

debian-package: debian/rules
	@if test x$(HAVE_DPKG_BUILDPACKAGE) = xyes ; then \
		dpkg-buildpackage -rfakeroot -us -uc ; \
	else \
		echo "Error: Debian packaging tools not found." ; \
		echo "Package build abandoned." ; \
	fi

# XXX - This assumes we're building from the source directory.
osx-app: $(PROGRAMS) $(SCRIPTS) $(MANS) $(DATA) packaging/macosx/Info.plist
	@if test x$(HAVE_OSX_PACKAGING) = xyes ; then \
		rm -rf $(stagedir) ; \
		$(MAKE) DESTDIR=$(stagedir) install; \
		cd $(srcdir)/packaging/macosx ;  \
		./osx-app.sh -bp ../staging/$(PACKAGE).inst$(bindir) ; \
	else \
		echo "Error: OS X packaging tools not found." ; \
		echo "Package build abandoned." ; \
	fi

packaging/macosx/COPYING.txt: COPYING
	(cd packaging/macosx ; \
	$(MAKE) COPYING.txt ;)

osx-package: osx-app packaging/macosx/COPYING.txt
	@if test x$(HAVE_OSX_PACKAGING) = xyes ; then \
		cd $(srcdir)/packaging/macosx ;  \
		./osx-dmg.sh ; \
	fi

osx-install: osx-app
	@if test x$(HAVE_OSX_PACKAGING) = xyes ; then \
		echo "Copying Wireshark.app to /Applications" ; \
		cp -pr $(srcdir)/packaging/macosx/Wireshark.app /Applications ;  \
	fi

clean-local:
	rm -rf $(top_stagedir)

dumpabi:
	$(MAKE) -C wiretap dumpabi
	$(MAKE) -C epan dumpabi
	$(MAKE) -C wsutil dumpabi

checkapi_local:
	$(PERL) tools/checkAPIs.pl \
	$(TSHARK_TAP_SRC) \
	$(wireshark_SOURCES)
#	$(EXTRA_wireshark_SOURCES)

checkapi: checkapi_local
	cd wiretap && $(MAKE) checkapi
	cd codecs && $(MAKE) checkapi
	cd ui/gtk && $(MAKE) checkapi
##	cd epan && $(MAKE) checkapi
##	cd epan/crypt && $(MAKE) checkapi
	cd epan/dfilter && $(MAKE) checkapi
##	cd epan/ftypes && $(MAKE) checkapi
##	cd epan/wslua && $(MAKE) checkapi
	cd epan/dissectors && $(MAKE) checkapi
	cd plugins && $(MAKE) checkapi
	cd wsutil && $(MAKE) checkapi
