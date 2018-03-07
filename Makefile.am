# Makefile.am
# Automake file for Wireshark
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

include ./Makefile.am.inc

AM_DISTCHECK_CONFIGURE_FLAGS=@GUI_CONFIGURE_FLAGS@
# Make sure to keep ACLOCAL_AMFLAGS in Makefile.am and AC_CONFIG_MACRO_DIRS
# in configure.ac in sync, otherwise there will be an error running autogen.sh.
ACLOCAL_AMFLAGS = -I m4

# Common headers
COMMONCPPFLAGS =

AM_CPPFLAGS = $(INCLUDEDIRS) $(WS_CPPFLAGS) $(COMMONCPPFLAGS)

bin_PROGRAMS = \
	@capinfos_bin@		\
	@captype_bin@		\
	@dumpcap_bin@		\
	@editcap_bin@		\
	@mergecap_bin@		\
	@mmdbresolve_bin@	\
	@randpkt_bin@		\
	@rawshark_bin@		\
	@reordercap_bin@	\
	@sharkd_bin@		\
	@text2pcap_bin@		\
	@tfshark_bin@		\
	@tshark_bin@		\
	@wireshark_bin@

noinst_PROGRAMS = \
	@dftest_bin@		\
	@fuzzshark_bin@

EXTRA_PROGRAMS = wireshark-gtk wireshark tshark tfshark capinfos captype \
	editcap mergecap dftest randpkt text2pcap dumpcap reordercap \
	mmdbresolve rawshark sharkd fuzzshark

#
# Wireshark configuration files are put in $(pkgdatadir).
#
dist_pkgdata_DATA = COPYING manuf services cfilters colorfilters dfilters \
	smi_modules pdml2html.xsl enterprises.tsv wka

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = wireshark.pc

#
# Install global profiles in the "profiles" subdirectory
#
profilesdir = $(pkgdatadir)
nobase_dist_profiles_DATA = \
	profiles/Bluetooth/colorfilters \
	profiles/Bluetooth/preferences \
	profiles/Classic/colorfilters

#
# Install the Diameter DTD and XML files in the "diameter" subdirectory
# of that directory.
#
diameterdir = $(pkgdatadir)/diameter
include diameter/Custom.make
dist_diameter_DATA = $(_CUSTOM_diameter_xml_files_) \
	diameter/chargecontrol.xml \
	diameter/Cisco.xml \
	diameter/CiscoSystems.xml \
	diameter/Custom.xml \
	diameter/dictionary.dtd \
	diameter/dictionary.xml \
	diameter/eap.xml \
	diameter/Ericsson.xml \
	diameter/etsie2e4.xml \
	diameter/Inovar.xml \
	diameter/Juniper.xml \
	diameter/mobileipv4.xml \
	diameter/mobileipv6.xml \
	diameter/nasreq.xml \
	diameter/sip.xml \
	diameter/Starent.xml \
	diameter/sunping.xml \
	diameter/TGPP.xml \
	diameter/TGPP2.xml \
	diameter/Vodafone.xml \
	diameter/AlcatelLucent.xml \
	diameter/Nokia.xml \
	diameter/NokiaSolutionsAndNetworks.xml \
	diameter/HP.xml \
	diameter/Huawei.xml \
	diameter/Oracle.xml

#
# Install the DTDs directory files in the "dtds" subdirectory
# of that directory
#
dtdsdir = $(pkgdatadir)/dtds
dist_dtds_DATA = \
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
include radius/Custom.make
dist_radius_DATA = $(_CUSTOM_radius_dict_) \
	radius/README.radius_dictionary \
	radius/custom.includes \
	radius/dictionary \
	radius/dictionary.3com \
	radius/dictionary.3gpp \
	radius/dictionary.3gpp2 \
	radius/dictionary.acc \
	radius/dictionary.acme \
	radius/dictionary.actelis \
	radius/dictionary.aerohive \
	radius/dictionary.airespace \
	radius/dictionary.alcatel \
	radius/dictionary.alcatel-lucent.aaa \
	radius/dictionary.alcatel.esam \
	radius/dictionary.alcatel.sr \
	radius/dictionary.alteon \
	radius/dictionary.altiga \
	radius/dictionary.alvarion \
	radius/dictionary.alvarion.wimax.v2_2 \
	radius/dictionary.apc \
	radius/dictionary.aptis \
	radius/dictionary.arbor \
	radius/dictionary.aruba \
	radius/dictionary.ascend \
	radius/dictionary.asn \
	radius/dictionary.audiocodes \
	radius/dictionary.avaya \
	radius/dictionary.azaire \
	radius/dictionary.bay \
	radius/dictionary.bintec \
	radius/dictionary.bluecoat \
	radius/dictionary.bristol \
	radius/dictionary.broadsoft \
	radius/dictionary.brocade \
	radius/dictionary.bskyb \
	radius/dictionary.bt \
	radius/dictionary.cablelabs \
	radius/dictionary.cabletron \
	radius/dictionary.camiant \
	radius/dictionary.chillispot \
	radius/dictionary.cisco \
	radius/dictionary.cisco.asa \
	radius/dictionary.cisco.bbsm \
	radius/dictionary.cisco.vpn3000 \
	radius/dictionary.cisco.vpn5000 \
	radius/dictionary.citrix \
	radius/dictionary.clavister \
	radius/dictionary.cnergee \
	radius/dictionary.colubris \
	radius/dictionary.columbia_university \
	radius/dictionary.compat \
	radius/dictionary.compatible \
	radius/dictionary.cosine \
	radius/dictionary.dante \
	radius/dictionary.dellemc \
	radius/dictionary.dhcp \
	radius/dictionary.digium \
	radius/dictionary.dlink \
	radius/dictionary.dragonwave \
	radius/dictionary.efficientip \
	radius/dictionary.eltex \
	radius/dictionary.epygi \
	radius/dictionary.equallogic \
	radius/dictionary.ericsson \
	radius/dictionary.ericsson.ab \
	radius/dictionary.ericsson.packet.core.networks \
	radius/dictionary.extreme \
	radius/dictionary.f5 \
	radius/dictionary.fdxtended \
	radius/dictionary.fortinet \
	radius/dictionary.foundry \
	radius/dictionary.freedhcp \
	radius/dictionary.freeradius \
	radius/dictionary.freeradius.internal \
	radius/dictionary.freeswitch \
	radius/dictionary.gandalf \
	radius/dictionary.garderos \
	radius/dictionary.gemtek \
	radius/dictionary.h3c \
	radius/dictionary.hp \
	radius/dictionary.huawei \
	radius/dictionary.iana \
	radius/dictionary.iea \
	radius/dictionary.infoblox \
	radius/dictionary.infonet \
	radius/dictionary.ipunplugged \
	radius/dictionary.issanni \
	radius/dictionary.itk \
	radius/dictionary.jradius \
	radius/dictionary.juniper \
	radius/dictionary.karlnet \
	radius/dictionary.kineto \
	radius/dictionary.lancom \
	radius/dictionary.livingston \
	radius/dictionary.localweb \
	radius/dictionary.lucent \
	radius/dictionary.manzara \
	radius/dictionary.meinberg \
	radius/dictionary.merit \
	radius/dictionary.meru \
	radius/dictionary.microsemi \
	radius/dictionary.microsoft \
	radius/dictionary.mikrotik \
	radius/dictionary.motorola \
	radius/dictionary.motorola.wimax \
	radius/dictionary.navini \
	radius/dictionary.netscreen \
	radius/dictionary.networkphysics \
	radius/dictionary.nexans \
	radius/dictionary.nokia \
	radius/dictionary.nokia.conflict \
	radius/dictionary.nomadix \
	radius/dictionary.nortel \
	radius/dictionary.ntua \
	radius/dictionary.openser \
	radius/dictionary.packeteer \
	radius/dictionary.paloalto \
	radius/dictionary.patton \
	radius/dictionary.perle \
	radius/dictionary.propel \
	radius/dictionary.prosoft \
	radius/dictionary.proxim \
	radius/dictionary.purewave \
	radius/dictionary.quiconnect \
	radius/dictionary.quintum \
	radius/dictionary.redcreek \
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
	radius/dictionary.rfc5447 \
	radius/dictionary.rfc5580 \
	radius/dictionary.rfc5607 \
	radius/dictionary.rfc5904 \
	radius/dictionary.rfc6519 \
	radius/dictionary.rfc6572 \
	radius/dictionary.rfc6677 \
	radius/dictionary.rfc6911 \
	radius/dictionary.rfc6929 \
	radius/dictionary.rfc6930 \
	radius/dictionary.rfc7055 \
	radius/dictionary.rfc7155 \
	radius/dictionary.rfc7268 \
	radius/dictionary.rfc7499 \
	radius/dictionary.rfc7930 \
	radius/dictionary.riverbed \
	radius/dictionary.riverstone \
	radius/dictionary.roaringpenguin \
	radius/dictionary.ruckus \
	radius/dictionary.ruggedcom \
	radius/dictionary.sangoma \
	radius/dictionary.sg \
	radius/dictionary.shasta \
	radius/dictionary.shiva \
	radius/dictionary.siemens \
	radius/dictionary.slipstream \
	radius/dictionary.sofaware \
	radius/dictionary.sonicwall \
	radius/dictionary.springtide \
	radius/dictionary.starent \
	radius/dictionary.starent.vsa1 \
	radius/dictionary.surfnet \
	radius/dictionary.symbol \
	radius/dictionary.t_systems_nova \
	radius/dictionary.telebit \
	radius/dictionary.telkom \
	radius/dictionary.terena \
	radius/dictionary.trapeze \
	radius/dictionary.travelping \
	radius/dictionary.tropos \
	radius/dictionary.ukerna \
	radius/dictionary.unisphere \
	radius/dictionary.unix \
	radius/dictionary.usr \
	radius/dictionary.utstarcom \
	radius/dictionary.valemount \
	radius/dictionary.versanet \
	radius/dictionary.vqp \
	radius/dictionary.walabi \
	radius/dictionary.waverider \
	radius/dictionary.wichorus \
	radius/dictionary.wimax \
	radius/dictionary.wimax.alvarion \
	radius/dictionary.wimax.wichorus \
	radius/dictionary.wispr \
	radius/dictionary.xedia \
	radius/dictionary.xylan \
	radius/dictionary.yubico \
	radius/dictionary.zeus \
	radius/dictionary.zte \
	radius/dictionary.zyxel

#
# Install the tpncp directory files in the "tpncp" subdirectory
# of that directory
#
tpncpdir = $(pkgdatadir)/tpncp
dist_tpncp_DATA = \
	tpncp/tpncp.dat

#
# Install the wimaxasncp directory files in the "wimaxasncp" subdirectory
# of that directory
#
wimaxasncpdir = $(pkgdatadir)/wimaxasncp
dist_wimaxasncp_DATA = \
	wimaxasncp/dictionary.xml \
	wimaxasncp/dictionary.dtd

# "BUILT_SOURCES" are built before any "make all" or "make check" targets.
BUILT_HEADER_FILES = \
	version.h

BUILT_C_FILES =

BUILT_SOURCES =	$(BUILT_C_FILES) $(BUILT_HEADER_FILES)

# Header files generated from source files.
GENERATED_HEADER_FILES = \
	text2pcap-scanner_lex.h \
	$(BUILT_HEADER_FILES)

# C source files generated from source files.
GENERATED_C_FILES =

# All the generated files.
GENERATED_FILES = $(GENERATED_C_FILES) $(GENERATED_HEADER_FILES)

# sources common for wireshark, tshark, and rawshark
SHARK_COMMON_SRC = \
	cfile.c			\
	file_packet_provider.c	\
	frame_tvbuff.c		\
	sync_pipe_write.c	\
	extcap.c		\
	extcap_parser.c

# wireshark specifics
WIRESHARK_COMMON_SRC = \
	$(SHARK_COMMON_SRC)	\
	capture_info.c		\
	capture_opts.c		\
	file.c			\
	fileset.c		\
	version_info.c

EPAN_EXTRA_LIBS = \
	@C_ARES_LIBS@			\
	@KRB5_LIBS@			\
	@LIBGCRYPT_LIBS@		\
	@LIBGNUTLS_LIBS@		\
	@LIBSMI_LIBS@

# Libraries and plugin flags with which to link wireshark.
#
# GTK_CFLAGS/GTK_LIBS is a strict superset of GLIB_CFLAGS/GLIB_LIBS
# (see configure.ac for pkg-config modules used).
#
wireshark_common_ldadd = \
	capchild/libcapchild.a		\
	caputils/libcaputils.a		\
	ui/libui.a			\
	ui/libui_generated.a		\
	codecs/libwscodecs.la		\
	wiretap/libwiretap.la		\
	epan/libwireshark.la		\
	wsutil/libwsutil.la		\
	@PCAP_LIBS@			\
	$(EPAN_EXTRA_LIBS)		\
	@LIBNL_LIBS@

if HAVE_Qt
wireshark_SOURCES = $(WIRESHARK_COMMON_SRC) wireshark-qt.cpp

wireshark_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS) $(Qt_CFLAGS)
# Define compatibility macros for Qt 4.8
if HAVE_QT_VERSION_4
wireshark_CPPFLAGS += -DQ_NULLPTR=NULL
endif

wireshark_LDFLAGS = $(AM_LDFLAGS) $(Qt_LDFLAGS)

wireshark_LDADD = \
	ui/qt/libqtui.a			\
	$(wireshark_common_ldadd)	\
	$(GLIB_LIBS)			\
	$(Qt_LIBS)

if HAVE_SPEEXDSP
wireshark_LDADD += $(SPEEXDSP_LIBS)
endif
endif	# HAVE_Qt

if HAVE_GTK
wireshark_gtk_SOURCES = $(WIRESHARK_COMMON_SRC)

wireshark_gtk_CPPFLAGS = $(AM_CPPFLAGS) $(GTK_CFLAGS)

wireshark_gtk_LDFLAGS = $(AM_LDFLAGS)

wireshark_gtk_LDADD = \
	ui/gtk/libgtkui.a		\
	$(wireshark_common_ldadd)	\
	$(GTK_LIBS)			\
	@PORTAUDIO_LIBS@
endif

fuzzshark_SOURCES = \
	tools/oss-fuzzshark/fuzzshark.c \
	tools/oss-fuzzshark/StandaloneFuzzTargetMain.c \
	version_info.c

fuzzshark_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS)

fuzzshark_LDFLAGS = $(AM_LDFLAGS)

fuzzshark_LDADD = \
	wiretap/libwiretap.la		\
	epan/libwireshark.la		\
	wsutil/libwsutil.la		\
	@GLIB_LIBS@			\
	${EPAN_EXTRA_LIBS}

tshark_SOURCES = \
	$(SHARK_COMMON_SRC)	\
	capture_opts.c		\
	tshark.c		\
	version_info.c

tshark_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS)

tshark_LDFLAGS = $(AM_LDFLAGS)

# Libraries and plugin flags with which to link tshark.
tshark_LDADD = \
	capchild/libcapchild.a		\
	caputils/libcaputils.a		\
	ui/cli/libcliui.a		\
	ui/libui.a			\
	wiretap/libwiretap.la		\
	epan/libwireshark.la		\
	wsutil/libwsutil.la		\
	@GLIB_LIBS@			\
	@PCAP_LIBS@			\
	${EPAN_EXTRA_LIBS}

tfshark_SOURCES = \
	$(SHARK_COMMON_SRC)	\
	tfshark.c		\
	version_info.c

tfshark_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS)

tfshark_LDFLAGS = $(AM_LDFLAGS)

# Libraries and plugin flags with which to link tfshark.
tfshark_LDADD = \
	ui/cli/libcliui.a		\
	ui/libui.a			\
	wiretap/libwiretap.la		\
	epan/libwireshark.la		\
	wsutil/libwsutil.la		\
	@GLIB_LIBS@			\
	@PCAP_LIBS@			\
	${EPAN_EXTRA_LIBS}

rawshark_SOURCES = \
	$(SHARK_COMMON_SRC)	\
	rawshark.c		\
	version_info.c

rawshark_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS)

rawshark_LDFLAGS = $(AM_LDFLAGS)

# Libraries and plugin flags with which to link rawshark.
rawshark_LDADD = \
	caputils/libcaputils.a		\
	ui/libui.a			\
	wiretap/libwiretap.la		\
	epan/libwireshark.la		\
	wsutil/libwsutil.la		\
	@GLIB_LIBS@			\
	@PCAP_LIBS@			\
	${EPAN_EXTRA_LIBS}

mmdbresolve_SOURCES = mmdbresolve.c
mmdbresolve_CPPFLAGS = $(AM_CPPFLAGS)
mmdbresolve_LDFLAGS = $(AM_LDFLAGS)
mmdbresolve_LDADD = @MAXMINDDB_LIBS@

sharkd_SOURCES = \
	$(SHARK_COMMON_SRC)	\
	sharkd.c		\
	sharkd.h		\
	sharkd_daemon.c		\
	sharkd_session.c	\
	version_info.c

sharkd_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS)

if HAVE_SPEEXDSP
sharkd_CPPFLAGS += $(SPEEXDSP_CFLAGS)
endif

sharkd_LDFLAGS = $(AM_LDFLAGS)

# Libraries and plugin flags with which to link sharkd.
sharkd_LDADD = \
	ui/cli/libcliui.a		\
	ui/libui.a			\
	codecs/libwscodecs.la		\
	wiretap/libwiretap.la		\
	epan/libwireshark.la		\
	wsutil/libwsutil.la		\
	@GLIB_LIBS@			\
	@PCAP_LIBS@			\
	${EPAN_EXTRA_LIBS}

if HAVE_SPEEXDSP
sharkd_LDADD += $(SPEEXDSP_LIBS)
endif

text2pcap_SOURCES = \
	text2pcap.c		\
	text2pcap-scanner.l	\
	version_info.c

text2pcap_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS)

text2pcap_CFLAGS = $(AM_CFLAGS)

# Libraries with which to link text2pcap.
text2pcap_LDADD = \
	writecap/libwritecap.a		\
	wsutil/libwsutil.la		\
	@GLIB_LIBS@

mergecap_SOURCES = \
	mergecap.c	\
	version_info.c

mergecap_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS)

# Libraries with which to link mergecap.
mergecap_LDADD = \
	ui/libui.a			\
	wiretap/libwiretap.la		\
	wsutil/libwsutil.la		\
	@GLIB_LIBS@

capinfos_SOURCES = \
	capinfos.c	\
	version_info.c

capinfos_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS)

# Libraries with which to link capinfos.
capinfos_LDADD = \
	ui/libui.a			\
	wiretap/libwiretap.la		\
	wsutil/libwsutil.la		\
	@GLIB_LIBS@			\
	@LIBGCRYPT_LIBS@

captype_SOURCES = \
	captype.c	\
	version_info.c

captype_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS)

# Libraries with which to link captype.
captype_LDADD = \
	ui/libui.a			\
	wiretap/libwiretap.la		\
	wsutil/libwsutil.la		\
	@GLIB_LIBS@

editcap_SOURCES = \
	editcap.c	\
	version_info.c

editcap_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS)

# Libraries with which to link editcap.
editcap_LDADD = \
	ui/libui.a			\
	wiretap/libwiretap.la		\
	wsutil/libwsutil.la		\
	@GLIB_LIBS@			\
	@LIBGCRYPT_LIBS@

reordercap_SOURCES = \
	reordercap.c	\
	version_info.c

reordercap_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS)

# Libraries with which to link reordercap.
reordercap_LDADD = \
	ui/libui.a			\
	wiretap/libwiretap.la		\
	wsutil/libwsutil.la		\
	@GLIB_LIBS@

randpkt_SOURCES = \
	randpkt.c	\
	version_info.c

randpkt_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS)

# Libraries with which to link randpkt.
randpkt_LDADD = \
	randpkt_core/librandpkt_core.a	\
	ui/libui.a			\
	wiretap/libwiretap.la		\
	wsutil/libwsutil.la		\
	@GLIB_LIBS@			\
	@PCAP_LIBS@			\
	@C_ARES_LIBS@

dftest_SOURCES = \
	dftest.c

dftest_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS)

# Libraries and plugin flags with which to link dftest.
dftest_LDADD = \
	ui/libui.a			\
	wiretap/libwiretap.la		\
	wsutil/libwsutil.la		\
	epan/libwireshark.la		\
	@GLIB_LIBS@			\
	@PCAP_LIBS@			\
	${EPAN_EXTRA_LIBS}

dumpcap_SOURCES = \
	capture_opts.c			\
	capture_stop_conditions.c	\
	conditions.c			\
	dumpcap.c			\
	ringbuffer.c			\
	sync_pipe_write.c		\
	version_info.c

dumpcap_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS)

dumpcap_CFLAGS = $(AM_CFLAGS) $(PIE_CFLAGS)

dumpcap_LDFLAGS = $(AM_LDFLAGS) $(PIE_LDFLAGS)

# Libraries with which to link dumpcap.
dumpcap_LDADD = \
	caputils/libcaputils.a		\
	ui/libui.a			\
	writecap/libwritecap.a		\
	wsutil/libwsutil.la		\
	@GLIB_LIBS@			\
	@PCAP_LIBS@			\
	@LIBCAP_LIBS@			\
	@LIBNL_LIBS@

pkginclude_HEADERS = \
	cfile.h			\
	file.h			\
	globals.h		\
	log.h			\
	ws_attributes.h		\
	ws_compiler_tests.h	\
	ws_diag_control.h	\
	ws_symbol_export.h

# this target needed for distribution only
noinst_HEADERS = \
	tools/oss-fuzzshark/FuzzerInterface.h \
	capture_info.h		\
	capture_opts.h		\
	capture_stop_conditions.h	\
	conditions.h		\
	extcap.h		\
	extcap_parser.h		\
	fileset.h		\
	frame_tvbuff.h		\
	ringbuffer.h		\
	sync_pipe.h		\
	version_info.h

#
# Build the version string
#
# FORCE is the portable version of .PHONY
FORCE:

version.h: FORCE
	$(AM_V_PERL)$(PERL) $(srcdir)/make-version.pl $(srcdir)

#
# Build shell scripts by doing variable substitution.
# Taken from autoconf 2.13.
#
editsh = sed -e 's,@''SHELL''@,$(SHELL),g'

SUFFIXES = .sh
.sh:
	rm -f $@ $@.tmp
	$(editsh) $< > $@.tmp && chmod +x $@.tmp && mv $@.tmp $@

services:
	$(PYTHON) $(srcdir)/tools/make-services.py

CLEANFILES = \
	doxygen-core.tag	\
	vgcore.*

DISTCLEANFILES = \
	version.h

MAINTAINERCLEANFILES = \
	$(GENERATED_FILES)

EXTRA_DIST = \
	.editorconfig		\
	.mailmap		\
	INSTALL.configure	\
	Makefile.am.inc		\
	README.aix		\
	README.bsd		\
	README.DECT		\
	README.hpux		\
	README.linux		\
	README.macos		\
	README.md		\
	README.windows		\
	abi-descriptor.template	\
	autogen.sh		\
	cfilters		\
	colorfilters		\
	debian			\
	dfilters		\
	doxygen_global.cfg	\
	doxygen.cfg.in		\
	enterprises.tsv		\
	fix			\
	idl			\
	image			\
	m4			\
	macosx-support-lib-patches	\
	make-version.pl		\
	manuf			\
	manuf.tmpl		\
	pdml2html.xsl		\
	smi_modules		\
	text2pcap-scanner.l	\
	text2pcap.h		\
	services		\
	wireshark.desktop	\
	wireshark-gtk.desktop	\
	wireshark-mime-package.xml	\
	wireshark.appdata.xml	\
	wireshark.pc.in		\
	wka			\
	CMakeLists.txt		\
	CMakeListsCustom.txt.example	\
	cmakeconfig.h.in	\
	CMakeOptions.txt	\
	ConfigureChecks.cmake	\
	cmake

install-exec-hook:
if HAVE_DUMPCAP_GROUP
	chgrp $(DUMPCAP_GROUP) $(DESTDIR)$(bindir)/dumpcap
endif
if SETCAP_INSTALL
	$(SETCAP) cap_net_raw,cap_net_admin+ep $(DESTDIR)$(bindir)/dumpcap
	chmod o-rws $(DESTDIR)$(bindir)/dumpcap
else
if SETUID_INSTALL
	chmod o-rws $(DESTDIR)$(bindir)/dumpcap
	chmod +s $(DESTDIR)$(bindir)/dumpcap
endif
endif


if HAVE_PLUGINS
if !ENABLE_STATIC
plugins_subdir = plugins
endif
endif

extcap_subdir = extcap

DIST_SUBDIRS = \
	capchild	\
	caputils	\
	codecs		\
	doc		\
	docbook		\
	epan		\
	ui		\
	ui/cli		\
	ui/gtk		\
	ui/qt		\
	help		\
	packaging	\
	plugins		\
	randpkt_core	\
	tools		\
	wiretap		\
	writecap	\
	wsutil		\
	extcap

SUBDIRS = \
	tools			\
	wsutil			\
	writecap		\
	wiretap			\
	epan			\
	capchild		\
	caputils		\
	$(plugins_subdir)	\
	help			\
	ui			\
	codecs			\
	@wireshark_SUBDIRS@	\
	ui/cli			\
	randpkt_core		\
	$(extcap_subdir)	\
	.			\
	doc			\
	docbook

help/faq.txt: $(srcdir)/help/faq.py
	$(AM_V_GEN)(cd help ; \
	$(MAKE) faq.txt ;)

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck


#
# Install icons and other desktop files for (for use with GNOME, KDE, or
# any other freedesktop.org-compliant desktops).
#
# We use $(datadir).  If the desktop doesn't look for them there,
# the desktop is broken; the latest XDG Base Directory Specification
# can be consulted at
#
#    http://standards.freedesktop.org/basedir-spec/basedir-spec-latest.html
#
# We neither need nor want any of this if we're not building Wireshark
# (that being the only desktop app).
#
install-data-local:
if BUILDING_WIRESHARK
	$(MKDIR_P) $(DESTDIR)$(datadir)/mime/packages
	$(INSTALL) -m 644 $(srcdir)/wireshark-mime-package.xml $(DESTDIR)$(datadir)/mime/packages/wireshark.xml
	$(MKDIR_P) $(DESTDIR)$(datadir)/appdata
	$(INSTALL) -m 644 $(srcdir)/wireshark.appdata.xml $(DESTDIR)$(datadir)/appdata/wireshark.appdata.xml
	$(MKDIR_P) $(DESTDIR)$(datadir)/applications
	$(INSTALL) -m 644 $(srcdir)/wireshark.desktop $(srcdir)/wireshark-gtk.desktop $(DESTDIR)$(datadir)/applications
	for size in 16 24 32 48 64 128 256; \
	do \
		$(MKDIR_P) $(DESTDIR)$(datadir)/icons/hicolor/$${size}x$${size}/apps ; \
		$(INSTALL) -m 644 $(srcdir)/image/wsicon$${size}.png $(DESTDIR)$(datadir)/icons/hicolor/$${size}x$${size}/apps/wireshark.png ; \
		$(MKDIR_P) $(DESTDIR)$(datadir)/icons/hicolor/$${size}x$${size}/mimetypes ; \
		$(INSTALL) -m 644 $(srcdir)/image/WiresharkDoc-$${size}.png $(DESTDIR)$(datadir)/icons/hicolor/$${size}x$${size}/mimetypes/application-wireshark-doc.png ; \
	done
	$(MKDIR_P) $(DESTDIR)$(datadir)/icons/hicolor/scalable/apps
	$(INSTALL) -m 644 $(srcdir)/image/wsicon.svg $(DESTDIR)$(datadir)/icons/hicolor/scalable/apps/wireshark.svg
endif

uninstall-local:
if BUILDING_WIRESHARK
	rm -f $(DESTDIR)$(datadir)/appdata/wireshark.appdata.xml
	rm -f $(DESTDIR)$(datadir)/applications/wireshark.desktop
	rm -f $(DESTDIR)$(datadir)/applications/wireshark-gtk.desktop
	rm -f $(DESTDIR)$(datadir)/mime/packages/wireshark.xml
	for size in 16 24 32 48 64 128 256; \
	do \
		rm -f $(DESTDIR)$(datadir)/icons/hicolor/$${size}x$${size}/apps/wireshark.png ; \
		rm -f $(DESTDIR)$(datadir)/icons/hicolor/$${size}x$${size}/mimetypes/application-wireshark-doc.png ; \
	done
	rm -f $(DESTDIR)$(datadir)/icons/hicolor/scalable/apps/wireshark.svg
endif

install-data-hook: update-databases-and-caches-install
uninstall-hook: update-databases-and-caches-uninstall

#
# ldconfig may be needed to update a shared library cache.
#
# update-desktop-database and update-mime-database may be needed on
# freedesktop.org desktops.
#
# gtk-update-icon-cache may be needed only if we're installing a GTK+
# version of Wireshark.
#
# Only ldconfig may be needed if we're not building Wireshark
# (that being the only desktop app).
#
update-databases-and-caches-common:
	@echo "-------------------------------------------------------------------------------"
	@echo "You may need to run \"ldconfig\" as root"
if BUILDING_WIRESHARK
	@echo "You may need to run \"update-desktop-database $(datadir)/applications\""
	@echo "You may need to run \"update-mime-database $(datadir)/mime\""
	@echo "You may need to run \"gtk-update-icon-cache -f -t $(datadir)/icons/hicolor\""
endif
	@echo "-------------------------------------------------------------------------------"

update-databases-and-caches-install: update-databases-and-caches-common

update-databases-and-caches-uninstall: update-databases-and-caches-common

rpm-package: dist
	$(MAKE) -C packaging/rpm

test-programs:
	cd epan && $(MAKE) $@

checkapi_local:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -build \
	-sourcedir=$(srcdir) \
	$(TSHARK_TAP_SRC) \
	$(wireshark_gtk_SOURCES)
#	$(EXTRA_wireshark_gtk_SOURCES)

checkapi: checkapi_local
	cd wiretap && $(MAKE) checkapi
	cd codecs && $(MAKE) checkapi
	cd capchild && $(MAKE) checkapi
	cd caputils && $(MAKE) checkapi
	cd ui && $(MAKE) checkapi
	cd ui/gtk && $(MAKE) checkapi
	cd ui/cli && $(MAKE) checkapi
	cd epan && $(MAKE) checkapi
	cd epan/crypt && $(MAKE) checkapi
	cd epan/dfilter && $(MAKE) checkapi
	cd epan/ftypes && $(MAKE) checkapi
	cd epan/wmem && $(MAKE) checkapi
	cd epan/wslua && $(MAKE) checkapi
	cd epan/dissectors && $(MAKE) checkapi
	cd plugins && $(MAKE) checkapi
	cd randpkt_core && $(MAKE) checkapi
	cd writecap && $(MAKE) checkapi
	cd wsutil && $(MAKE) checkapi

# --external-sources requires 0.4.0 or later.
shellcheck:
	cd $(top_srcdir) && \
	$(SHELLCHECK) --external-sources \
	  tools/fuzz-test.sh \
	  tools/randpkt-test.sh \
	  tools/test-captures.sh \
	  tools/valgrind-wireshark.sh

wsar_html: doxygen.cfg doxygen_global.cfg FORCE
if HAVE_DOXYGEN
	rm -rf wsar_html
	cd epan && $(MAKE) $@
	cd capchild && $(MAKE) $@
	cd caputils && $(MAKE) $@
	cd randpkt_core && $(MAKE) $@
	cd ui && $(MAKE) $@
	(umask 022 ; $(DOXYGEN) doxygen.cfg)
endif

wsar-zip: wsar_html
if HAVE_DOXYGEN
	rm -f wsar_html.zip
	zip -rq wsar_html.zip wsar_html
endif

# Update AUTHORS file with entries from git shortlog
gen-authors:
	cd $(top_srcdir) && $(PERL) tools/generate_authors.pl AUTHORS.src > AUTHORS

dist-hook:
	printf "git_description=%s\n" "$$(git -C $(top_srcdir) describe --match 'v[1-9]*')" \
		> $(top_distdir)/version.conf
