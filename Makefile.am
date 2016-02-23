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
ACLOCAL_AMFLAGS = `./aclocal-flags`

# Common headers
COMMONCPPFLAGS =

AM_CPPFLAGS = $(INCLUDEDIRS) $(WS_CPPFLAGS) $(COMMONCPPFLAGS)

bin_PROGRAMS = \
	@wireshark_bin@		\
	@tshark_bin@		\
	@tfshark_bin@		\
	@text2pcap_bin@		\
	@mergecap_bin@		\
	@capinfos_bin@		\
	@captype_bin@		\
	@editcap_bin@		\
	@randpkt_bin@		\
	@dftest_bin@		\
	@dumpcap_bin@		\
	@reordercap_bin@	\
	@rawshark_bin@		\
	@echld_test_bin@

EXTRA_PROGRAMS = wireshark-gtk wireshark tshark tfshark capinfos captype \
	editcap mergecap dftest randpkt text2pcap dumpcap reordercap \
	rawshark echld_test

#
# Wireshark configuration files are put in $(pkgdatadir).
#
dist_pkgdata_DATA = COPYING manuf services cfilters colorfilters dfilters \
	smi_modules ipmap.html pdml2html.xsl

#
# Install global profiles in the "profiles" subdirectory
#
profilesdir = $(pkgdatadir)
nobase_dist_profiles_DATA = \
	profiles/Bluetooth/colorfilters \
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
	diameter/Custom.xml \
	diameter/dictionary.dtd \
	diameter/dictionary.xml \
	diameter/eap.xml \
	diameter/Ericsson.xml \
	diameter/etsie2e4.xml \
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
	radius/dictionary.airespace \
	radius/dictionary.actelis \
	radius/dictionary.aerohive \
	radius/dictionary.alcatel \
	radius/dictionary.alcatel.esam \
	radius/dictionary.alcatel.sr \
	radius/dictionary.alcatel-lucent.aaa \
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
	radius/dictionary.bluecoat \
	radius/dictionary.bintec \
	radius/dictionary.broadsoft \
	radius/dictionary.brocade \
	radius/dictionary.bskyb \
	radius/dictionary.bristol \
	radius/dictionary.bt \
	radius/dictionary.camiant \
	radius/dictionary.cablelabs \
	radius/dictionary.cabletron \
	radius/dictionary.chillispot \
	radius/dictionary.cisco \
	radius/dictionary.cisco.asa \
	radius/dictionary.cisco.bbsm \
	radius/dictionary.cisco.vpn3000 \
	radius/dictionary.cisco.vpn5000 \
	radius/dictionary.citrix \
	radius/dictionary.clavister \
	radius/dictionary.colubris \
	radius/dictionary.columbia_university \
	radius/dictionary.compatible \
	radius/dictionary.compat \
	radius/dictionary.cosine \
	radius/dictionary.dante \
	radius/dictionary.dhcp \
	radius/dictionary.dlink \
	radius/dictionary.digium \
	radius/dictionary.dragonwave \
	radius/dictionary.efficientip \
	radius/dictionary.eltex \
	radius/dictionary.epygi \
	radius/dictionary.equallogic \
	radius/dictionary.ericsson \
	radius/dictionary.ericsson.ab \
	radius/dictionary.ericsson.packet.core.networks \
	radius/dictionary.erx \
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
	radius/dictionary.kineto \
	radius/dictionary.karlnet \
	radius/dictionary.lancom \
	radius/dictionary.livingston \
	radius/dictionary.localweb \
	radius/dictionary.lucent \
	radius/dictionary.manzara \
	radius/dictionary.meinberg \
	radius/dictionary.merit \
	radius/dictionary.meru \
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
	radius/dictionary.riverbed \
	radius/dictionary.riverstone \
	radius/dictionary.roaringpenguin \
	radius/dictionary.ruckus \
	radius/dictionary.ruggedcom \
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

if HAVE_PLUGINS
-include plugins/Custom.make
plugin_ldadd = $(_CUSTOM_plugin_ldadd_) \
	-dlopen plugins/docsis/docsis.la \
	-dlopen plugins/ethercat/ethercat.la \
	-dlopen plugins/gryphon/gryphon.la \
	-dlopen plugins/irda/irda.la \
	-dlopen plugins/m2m/m2m.la \
	-dlopen plugins/mate/mate.la \
	-dlopen plugins/opcua/opcua.la \
	-dlopen plugins/profinet/profinet.la \
	-dlopen plugins/stats_tree/stats_tree.la \
	-dlopen plugins/unistim/unistim.la \
	-dlopen plugins/wimax/wimax.la \
	-dlopen plugins/wimaxmacphy/wimaxmacphy.la

else		# HAVE_PLUGINS

plugin_ldadd =

endif		# HAVE_PLUGINS

include Makefile.common

if ENABLE_STATIC
EXTRALINKFLAGS = -Wl,-static -all-static
else
EXTRALINKFLAGS = -export-dynamic
endif

# Libraries and plugin flags with which to link wireshark.
#
# Note that Wireshark, when built with a version of GTK+ that runs
# atop X11, doesn't have to be linked with @SOCKET_LIBS@ or @NSL_LIBS@,
# as those should also be included in @GTK_LIBS@ (as those are also
# needed for X applications, and GTK+ applications are X applications
# if the version of GTK+ they're built with runs atop X11).
#
# GTK_CFLAGS/GTK_LIBS is a strict superset of GLIB_CFLAGS/GLIB_LIBS
# (see configure.ac for pkg-config modules used).
#
wireshark_common_ldadd = \
	capchild/libcapchild.a		\
	caputils/libcaputils.a		\
	ui/libui.a			\
	ui/libui_dirty.a		\
	codecs/libwscodecs.la		\
	wiretap/libwiretap.la		\
	epan/libwireshark.la		\
	wsutil/libwsutil.la		\
	@SSL_LIBS@			\
	$(plugin_ldadd)			\
	@PCAP_LIBS@			\
	@C_ARES_LIBS@			\
	@ADNS_LIBS@			\
	@KRB5_LIBS@			\
	@APPLICATIONSERVICES_FRAMEWORKS@	\
	@SYSTEMCONFIGURATION_FRAMEWORKS@	\
	@COREFOUNDATION_FRAMEWORKS@	\
	@LIBGCRYPT_LIBS@		\
	@LIBGNUTLS_LIBS@		\
	@LIBSMI_LDFLAGS@		\
	@LIBNL_LIBS@

if HAVE_Qt
wireshark_SOURCES = $(WIRESHARK_COMMON_SRC) wireshark-qt.cpp

wireshark_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS) $(Qt_CFLAGS)

wireshark_LDFLAGS = $(AM_LDFLAGS) $(EXTRALINKFLAGS) $(Qt_LDFLAGS)

wireshark_LDADD = \
	ui/qt/libqtui.a			\
	$(wireshark_common_ldadd)	\
	$(GLIB_LIBS)			\
	$(Qt_LIBS)
endif

if HAVE_GTK
wireshark_gtk_SOURCES = $(WIRESHARK_COMMON_SRC)

wireshark_gtk_CPPFLAGS = $(AM_CPPFLAGS) $(GTK_CFLAGS)

wireshark_gtk_LDFLAGS = $(AM_LDFLAGS) $(EXTRALINKFLAGS)

wireshark_gtk_LDADD = \
	ui/gtk/libgtkui.a		\
	$(wireshark_common_ldadd)	\
	$(GTK_LIBS)			\
	@PORTAUDIO_LIBS@
endif

tshark_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS)

tshark_LDFLAGS = $(AM_LDFLAGS) $(EXTRALINKFLAGS)

# Libraries and plugin flags with which to link tshark.
tshark_LDADD = \
	capchild/libcapchild.a		\
	caputils/libcaputils.a		\
	ui/cli/libcliui.a		\
	ui/libui.a			\
	wiretap/libwiretap.la		\
	epan/libwireshark.la		\
	wsutil/libwsutil.la		\
	@SSL_LIBS@			\
	$(plugin_ldadd)			\
	@GLIB_LIBS@			\
	@PCAP_LIBS@			\
	@SOCKET_LIBS@			\
	@NSL_LIBS@			\
	@C_ARES_LIBS@			\
	@ADNS_LIBS@			\
	@KRB5_LIBS@			\
	@SYSTEMCONFIGURATION_FRAMEWORKS@	\
	@COREFOUNDATION_FRAMEWORKS@	\
	@LIBGCRYPT_LIBS@		\
	@LIBGNUTLS_LIBS@		\
	@LIBSMI_LDFLAGS@

tfshark_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS)

tfshark_LDFLAGS = $(AM_LDFLAGS) $(EXTRALINKFLAGS)

# Libraries and plugin flags with which to link tfshark.
tfshark_LDADD = \
	ui/cli/libcliui.a		\
	ui/libui.a			\
	wiretap/libwiretap.la		\
	epan/libwireshark.la		\
	wsutil/libwsutil.la		\
	@SSL_LIBS@			\
	$(plugin_ldadd)			\
	@GLIB_LIBS@			\
	@PCAP_LIBS@			\
	@SOCKET_LIBS@			\
	@NSL_LIBS@			\
	@KRB5_LIBS@			\
	@SYSTEMCONFIGURATION_FRAMEWORKS@	\
	@COREFOUNDATION_FRAMEWORKS@	\
	@LIBGNUTLS_LIBS@		\
	@LIBSMI_LDFLAGS@

rawshark_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS)

rawshark_LDFLAGS = $(AM_LDFLAGS) $(EXTRALINKFLAGS)

# Libraries and plugin flags with which to link rawshark.
rawshark_LDADD = \
	caputils/libcaputils.a		\
	ui/libui.a			\
	wiretap/libwiretap.la		\
	epan/libwireshark.la		\
	wsutil/libwsutil.la		\
	@SSL_LIBS@			\
	$(plugin_ldadd)			\
	@GLIB_LIBS@			\
	@PCAP_LIBS@			\
	@SOCKET_LIBS@			\
	@NSL_LIBS@			\
	@C_ARES_LIBS@			\
	@ADNS_LIBS@			\
	@KRB5_LIBS@			\
	@SYSTEMCONFIGURATION_FRAMEWORKS@	\
	@COREFOUNDATION_FRAMEWORKS@	\
	@LIBGCRYPT_LIBS@		\
	@LIBGNUTLS_LIBS@		\
	@LIBSMI_LDFLAGS@

text2pcap_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS)

# Don't turn on -Werror for text2pcap: its source includes text2pcap-scanner.c
# which is generated (and therefore not always clean).
# We could generate text2pcap.o as a library with -Werror but for now it
# doesn't seem worth the effort.
text2pcap_CFLAGS = $(GENERATED_CFLAGS)

# Libraries with which to link text2pcap.
text2pcap_LDADD = \
	wsutil/libwsutil.la		\
	@GLIB_LIBS@

mergecap_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS)

# Libraries with which to link mergecap.
mergecap_LDADD = \
	wiretap/libwiretap.la		\
	wsutil/libwsutil.la		\
	@GLIB_LIBS@

capinfos_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS)

# Libraries with which to link capinfos.
capinfos_LDADD = \
	wiretap/libwiretap.la		\
	wsutil/libwsutil.la		\
	@GLIB_LIBS@			\
	@LIBGCRYPT_LIBS@

captype_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS)

# Libraries with which to link captype.
captype_LDADD = \
	wiretap/libwiretap.la		\
	wsutil/libwsutil.la		\
	@GLIB_LIBS@

editcap_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS)

# Libraries with which to link editcap.
editcap_LDADD = \
	wiretap/libwiretap.la		\
	wsutil/libwsutil.la		\
	@GLIB_LIBS@

reordercap_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS)

# Libraries with which to link reordercap.
reordercap_LDADD = \
	wiretap/libwiretap.la		\
	wsutil/libwsutil.la		\
	@GLIB_LIBS@

randpkt_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS)

# Libraries with which to link randpkt.
randpkt_LDADD = \
	randpkt_core/librandpkt_core.a	\
	wiretap/libwiretap.la		\
	wsutil/libwsutil.la		\
	@GLIB_LIBS@			\
	@PCAP_LIBS@			\
	@SOCKET_LIBS@			\
	@NSL_LIBS@			\
	@C_ARES_LIBS@			\
	@ADNS_LIBS@

dftest_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS)

# Libraries and plugin flags with which to link dftest.
dftest_LDADD = \
	ui/libui.a			\
	wiretap/libwiretap.la		\
	wsutil/libwsutil.la		\
	epan/libwireshark.la		\
	@SSL_LIBS@			\
	$(plugin_ldadd)			\
	@GLIB_LIBS@			\
	@PCAP_LIBS@			\
	@SOCKET_LIBS@			\
	@NSL_LIBS@			\
	@C_ARES_LIBS@			\
	@ADNS_LIBS@			\
	@KRB5_LIBS@			\
	@LIBGCRYPT_LIBS@		\
	@LIBGNUTLS_LIBS@		\
	@LIBSMI_LDFLAGS@

echld_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS)

echld_test_LDADD = \
	epan/libwireshark.la		\
	echld/libechld.la		\
	wsutil/libwsutil.la		\
	@GLIB_LIBS@			\
	@PCAP_LIBS@			\
	@SOCKET_LIBS@			\
	@NSL_LIBS@			\
	@C_ARES_LIBS@			\
	@ADNS_LIBS@

echld_test_DEPENDENCIES = \
	echld/libechld.la \
	epan/libwireshark.la

dumpcap_CPPFLAGS = $(AM_CPPFLAGS) $(GLIB_CFLAGS)

dumpcap_CFLAGS = $(AM_CFLAGS) $(PIE_CFLAGS)

dumpcap_LDFLAGS = $(AM_LDFLAGS) $(PIE_LDFLAGS)

# Libraries with which to link dumpcap.
dumpcap_LDADD = \
	caputils/libcaputils.a		\
	wsutil/libwsutil.la		\
	@GLIB_LIBS@			\
	@PCAP_LIBS@			\
	@SOCKET_LIBS@			\
	@NSL_LIBS@			\
	@SYSTEMCONFIGURATION_FRAMEWORKS@	\
	@COREFOUNDATION_FRAMEWORKS@	\
	@LIBCAP_LIBS@			\
	@LIBNL_LIBS@

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

CLEANFILES =		\
	*~		\
	doxygen-core.tag	\
	vgcore.*

#
# We have to remove version.h with "make distclean", as, otherwise,
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
	version.h

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
	.mailmap		\
	INSTALL.configure	\
	Makefile.am.inc		\
	Makefile.common		\
	Makefile.nmake		\
	Makefile.nmake.inc	\
	README.aix		\
	README.bsd		\
	README.DECT		\
	README.hpux		\
	README.linux		\
	README.macos		\
	README.tru64		\
	README.vmware		\
	README.windows		\
	abi-descriptor.template	\
	aclocal-fallback/ax_append_flag.m4		\
	aclocal-fallback/ax_check_compile_flag.m4	\
	aclocal-fallback/ax_compiler_vendor.m4		\
	aclocal-fallback/ax_ext.m4			\
	aclocal-fallback/ax_gcc_x86_cpuid.m4		\
	aclocal-fallback/ax_gcc_x86_avx_xgetbv.m4	\
	aclocal-fallback/libsmi.m4			\
	aclocal-fallback/libgcrypt.m4			\
	aclocal-flags		\
	adns_dll.dep		\
	adns_dll.rc		\
	autogen.sh		\
	capinfos.c		\
	captype.c		\
	cfilters		\
	colorfilters		\
	config.h.win32		\
	config.nmake		\
	debian/changelog	\
	debian/compat		\
	debian/control		\
	debian/copyright	\
	debian/dirs		\
	debian/ethereal-common.NEWS	\
	debian/geoip_db_paths	\
	debian/headers-check.c	\
	debian/libwireshark0.install	\
	debian/libwireshark0.symbols	\
	debian/libwireshark-data.install	\
	debian/libwireshark-dev.install	\
	debian/libwiretap0.docs	\
	debian/libwiretap0.install	\
	debian/libwiretap0.symbols	\
	debian/libwiretap-dev.install	\
	debian/libwscodecs0.install	\
	debian/libwscodecs0.symbols	\
	debian/libwsutil0.install	\
	debian/libwsutil0.symbols	\
	debian/libwsutil-dev.install	\
	debian/license-text-about-dialog	\
	debian/patches/02_use_packaged_openlayers_js.patch	\
	debian/patches/04_asn2wrs_ply.patch	\
	debian/patches/05_note-README-when-running-as-root.patch	\
	debian/patches/06_release-version.patch	\
	debian/patches/08_wireshark-desktop-menu.patch	\
	debian/patches/09_idl2wrs.patch	\
	debian/patches/16_licence_about_location.patch	\
	debian/patches/series	\
	debian/po/POTFILES.in	\
	debian/po/cs.po	\
	debian/po/da.po	\
	debian/po/de.po	\
	debian/po/es.po	\
	debian/po/eu.po	\
	debian/po/fi.po	\
	debian/po/fr.po	\
	debian/po/hu.po	\
	debian/po/id.po	\
	debian/po/it.po	\
	debian/po/ja.po	\
	debian/po/ko.po	\
	debian/po/nl.po	\
	debian/po/pt.po	\
	debian/po/pt_BR.po	\
	debian/po/ru.po	\
	debian/po/sk.po	\
	debian/po/sv.po	\
	debian/po/templates.pot	\
	debian/po/vi.po	\
	debian/postinst		\
	debian/README.Debian	\
	debian/README.Debian.security	\
	debian/rules		\
	debian/source/format	\
	debian/templates	\
	debian/tshark.docs	\
	debian/tshark.install	\
	debian/tshark.manpages	\
	debian/wireshark-common.config	\
	debian/wireshark-common.install	\
	debian/wireshark-common.manpages \
	debian/wireshark-common.postinst	\
	debian/wireshark-common.postrm	\
	debian/wireshark-dev.docs \
	debian/wireshark-dev.install	\
	debian/wireshark-dev.manpages \
	debian/wireshark-dev.prerm \
	debian/wireshark-doc.docs	\
	debian/wireshark-gtk.docs	\
	debian/wireshark-gtk.install	\
	debian/wireshark-qt.docs	\
	debian/wireshark-qt.install	\
	debian/wireshark-qt.manpages \
	dfilters		\
	doxygen_global.cfg	\
	doxygen.cfg.in		\
	dumpcap.c		\
	editcap.c		\
	epan/print.ps		\
	fix/FIX.xml		\
	fix/FIX40.xml		\
	fix/FIX41.xml		\
	fix/FIX42.xml		\
	fix/FIX43.xml		\
	fix/FIX44.xml		\
	fix/FIX50.xml		\
	fix/FIX50SP1.xml	\
	fix/FIX50SP2.xml	\
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
	image/captype.rc.in	\
	image/capture_comment.svg	\
	image/capture_comment_add.png	\
	image/capture_comment_disabled.png	\
	image/capture_comment_update.png	\
	image/capture_comment_update.svg	\
	image/clist_ascend.xpm			\
	image/clist_descend.xpm			\
	image/copy-8.png			\
	image/dumpcap.rc.in	\
	image/editcap.rc.in	\
	image/file_dlg_win32.rc \
	image/hi16-app-wireshark.png	\
	image/hi32-app-wireshark.png	\
	image/hi48-app-wireshark.png	\
	image/languages/de.svg		\
	image/languages/en.svg		\
	image/languages/fr.svg		\
	image/languages/it.svg		\
	image/languages/ja_JP.svg	\
	image/languages/pl.svg		\
	image/languages/zh_CN.svg	\
	image/layout_1.png		\
	image/layout_1@2x.png		\
	image/layout_2.png		\
	image/layout_2@2x.png		\
	image/layout_3.png		\
	image/layout_3@2x.png		\
	image/layout_4.png		\
	image/layout_4@2x.png		\
	image/layout_5.png		\
	image/layout_5@2x.png		\
	image/layout_6.png		\
	image/layout_6@2x.png		\
	image/libwscodecs.rc.in		\
	image/libwireshark.rc.in	\
	image/libwsutil.rc.in		\
	image/lo16-app-wireshark.png	\
	image/lo32-app-wireshark.png	\
	image/lo48-app-wireshark.png	\
	image/Makefile.nmake			\
	image/mergecap.rc.in			\
	image/minus-8.png			\
	image/nsis-checked.bmp			\
	image/nsis-unchecked.bmp		\
	image/openhand-16.png			\
	image/plus-8.png			\
	image/rawshark.rc.in			\
	image/README.image			\
	image/reordercap.rc.in			\
	image/rubberband-16.png			\
	image/stock_dialog_error_48.xpm		\
	image/stock_dialog_info_48.xpm		\
	image/stock_dialog_question_48.xpm	\
	image/stock_dialog_stop_48.xpm		\
	image/stock_dialog_warning_48.xpm	\
	image/text2pcap.rc.in			\
	image/tfshark.rc.in			\
	image/expert_ok.png			\
	image/toolbar/14x14/x-capture-comment-update.png	\
	image/toolbar/14x14/x-capture-comment-update.svg	\
	image/toolbar/14x14/x-capture-comment-update@2x.png	\
	image/toolbar/14x14/x-capture-filter-bookmark.active.png \
	image/toolbar/14x14/x-capture-filter-bookmark.active.svg \
	image/toolbar/14x14/x-capture-filter-bookmark.active@2x.png \
	image/toolbar/14x14/x-capture-filter-bookmark.png \
	image/toolbar/14x14/x-capture-filter-bookmark.selected.png \
	image/toolbar/14x14/x-capture-filter-bookmark.selected.svg \
	image/toolbar/14x14/x-capture-filter-bookmark.selected@2x.png \
	image/toolbar/14x14/x-capture-filter-bookmark.svg \
	image/toolbar/14x14/x-capture-filter-bookmark@2x.png \
	image/toolbar/14x14/x-display-filter-bookmark.active.png \
	image/toolbar/14x14/x-display-filter-bookmark.active.svg \
	image/toolbar/14x14/x-display-filter-bookmark.active@2x.png \
	image/toolbar/14x14/x-display-filter-bookmark.png \
	image/toolbar/14x14/x-display-filter-bookmark.selected.png \
	image/toolbar/14x14/x-display-filter-bookmark.selected.svg \
	image/toolbar/14x14/x-display-filter-bookmark.selected@2x.png \
	image/toolbar/14x14/x-display-filter-bookmark.svg \
	image/toolbar/14x14/x-display-filter-bookmark@2x.png \
	image/toolbar/14x14/x-expert-chat.png	\
	image/toolbar/14x14/x-expert-chat@2x.png	\
	image/toolbar/14x14/x-expert-error.png	\
	image/toolbar/14x14/x-expert-error@2x.png	\
	image/toolbar/14x14/x-expert-indicators-all.svg	\
	image/toolbar/14x14/x-expert-none.png	\
	image/toolbar/14x14/x-expert-none@2x.png	\
	image/toolbar/14x14/x-expert-note.png	\
	image/toolbar/14x14/x-expert-note@2x.png	\
	image/toolbar/14x14/x-expert-warn.png	\
	image/toolbar/14x14/x-expert-warn@2x.png	\
	image/toolbar/14x14/x-filter-clear.active.png \
	image/toolbar/14x14/x-filter-clear.active.svg \
	image/toolbar/14x14/x-filter-clear.active@2x.png \
	image/toolbar/14x14/x-filter-clear.png \
	image/toolbar/14x14/x-filter-clear.selected.png \
	image/toolbar/14x14/x-filter-clear.selected.svg \
	image/toolbar/14x14/x-filter-clear.selected@2x.png \
	image/toolbar/14x14/x-filter-clear.svg \
	image/toolbar/14x14/x-filter-clear@2x.png \
	image/toolbar/14x14/x-filter-dropdown.png \
	image/toolbar/14x14/x-filter-dropdown.svg \
	image/toolbar/14x14/x-filter-dropdown@2x.png \
	image/toolbar/14x14/x-filter-matching-bookmark.active.png \
	image/toolbar/14x14/x-filter-matching-bookmark.active.svg \
	image/toolbar/14x14/x-filter-matching-bookmark.active@2x.png \
	image/toolbar/14x14/x-filter-matching-bookmark.png \
	image/toolbar/14x14/x-filter-matching-bookmark.selected.png \
	image/toolbar/14x14/x-filter-matching-bookmark.selected.svg \
	image/toolbar/14x14/x-filter-matching-bookmark.selected@2x.png \
	image/toolbar/14x14/x-filter-matching-bookmark.svg \
	image/toolbar/14x14/x-filter-matching-bookmark@2x.png \
	image/toolbar/16x16/edit-find.png		\
	image/toolbar/16x16/edit-find.svg		\
	image/toolbar/16x16/edit-find@2x.png		\
	image/toolbar/16x16/go-first.png		\
	image/toolbar/16x16/go-first.svg		\
	image/toolbar/16x16/go-first@2x.png		\
	image/toolbar/16x16/go-jump.png			\
	image/toolbar/16x16/go-jump.svg			\
	image/toolbar/16x16/go-jump@2x.png		\
	image/toolbar/16x16/go-last.png			\
	image/toolbar/16x16/go-last.svg			\
	image/toolbar/16x16/go-last@2x.png		\
	image/toolbar/16x16/go-next.png			\
	image/toolbar/16x16/go-next.svg			\
	image/toolbar/16x16/go-next@2x.png		\
	image/toolbar/16x16/go-previous.png		\
	image/toolbar/16x16/go-previous.svg		\
	image/toolbar/16x16/go-previous@2x.png		\
	image/toolbar/16x16/x-capture-file-close.png	\
	image/toolbar/16x16/x-capture-file-close.svg	\
	image/toolbar/16x16/x-capture-file-close@2x.png	\
	image/toolbar/16x16/x-capture-file-close@2x.svg	\
	image/toolbar/16x16/x-capture-file-reload.png	\
	image/toolbar/16x16/x-capture-file-reload.svg	\
	image/toolbar/16x16/x-capture-file-reload@2x.png	\
	image/toolbar/16x16/x-capture-file-reload@2x.svg	\
	image/toolbar/16x16/x-capture-file-save.png	\
	image/toolbar/16x16/x-capture-file-save.svg	\
	image/toolbar/16x16/x-capture-file-save@2x.png	\
	image/toolbar/16x16/x-capture-file-save@2x.svg	\
	image/toolbar/16x16/x-capture-options-gear.svg	\
	image/toolbar/16x16/x-capture-options-wrench.svg	\
	image/toolbar/16x16/x-capture-options.png	\
	image/toolbar/16x16/x-capture-options@2x.png	\
	image/toolbar/16x16/x-capture-restart-fin.svg	\
	image/toolbar/16x16/x-capture-restart-triangle1.svg	\
	image/toolbar/16x16/x-capture-restart-triangle2.svg	\
	image/toolbar/16x16/x-capture-restart-turn1.svg	\
	image/toolbar/16x16/x-capture-restart-turn2.svg	\
	image/toolbar/16x16/x-capture-restart.png	\
	image/toolbar/16x16/x-capture-restart@2x.png	\
	image/toolbar/16x16/x-capture-start.on.png	\
	image/toolbar/16x16/x-capture-start.on.svg	\
	image/toolbar/16x16/x-capture-start.on@2x.png	\
	image/toolbar/16x16/x-capture-start.png		\
	image/toolbar/16x16/x-capture-start.svg		\
	image/toolbar/16x16/x-capture-start@2x.png	\
	image/toolbar/16x16/x-capture-stop-red.svg	\
	image/toolbar/16x16/x-capture-stop-white.svg	\
	image/toolbar/16x16/x-capture-stop.png		\
	image/toolbar/16x16/x-capture-stop@2x.png	\
	image/toolbar/16x16/x-colorize-packets.png	\
	image/toolbar/16x16/x-colorize-packets.svg	\
	image/toolbar/16x16/x-colorize-packets@2x.png	\
	image/toolbar/16x16/x-resize-columns.png	\
	image/toolbar/16x16/x-resize-columns.svg	\
	image/toolbar/16x16/x-resize-columns@2x.png	\
	image/toolbar/16x16/x-stay-last.png		\
	image/toolbar/16x16/x-stay-last.svg		\
	image/toolbar/16x16/x-stay-last@2x.png		\
	image/toolbar/16x16/zoom-in.png			\
	image/toolbar/16x16/zoom-in.svg			\
	image/toolbar/16x16/zoom-in@2x.png		\
	image/toolbar/16x16/zoom-original.png		\
	image/toolbar/16x16/zoom-original.svg		\
	image/toolbar/16x16/zoom-original@2x.png	\
	image/toolbar/16x16/zoom-out.png		\
	image/toolbar/16x16/zoom-out.svg		\
	image/toolbar/16x16/zoom-out@2x.png		\
	image/toolbar/24x14/x-filter-apply.active.png \
	image/toolbar/24x14/x-filter-apply.active.svg \
	image/toolbar/24x14/x-filter-apply.active@2x.png \
	image/toolbar/24x14/x-filter-apply.png \
	image/toolbar/24x14/x-filter-apply.selected.png \
	image/toolbar/24x14/x-filter-apply.selected.svg \
	image/toolbar/24x14/x-filter-apply.selected@2x.png \
	image/toolbar/24x14/x-filter-apply.svg \
	image/toolbar/24x14/x-filter-apply@2x.png \
	image/toolbar/24x24/edit-find.png	\
	image/toolbar/24x24/edit-find.svg	\
	image/toolbar/24x24/edit-find@2x.png	\
	image/toolbar/24x24/go-first.png	\
	image/toolbar/24x24/go-first.svg	\
	image/toolbar/24x24/go-first@2x.png	\
	image/toolbar/24x24/go-jump.png		\
	image/toolbar/24x24/go-jump.svg		\
	image/toolbar/24x24/go-jump@2x.png	\
	image/toolbar/24x24/go-last.png		\
	image/toolbar/24x24/go-last.svg		\
	image/toolbar/24x24/go-last@2x.png	\
	image/toolbar/24x24/go-next.png		\
	image/toolbar/24x24/go-next.svg		\
	image/toolbar/24x24/go-next@2x.png	\
	image/toolbar/24x24/go-previous.png	\
	image/toolbar/24x24/go-previous.svg	\
	image/toolbar/24x24/go-previous@2x.png	\
	image/toolbar/24x24/x-capture-file-close.png		\
	image/toolbar/24x24/x-capture-file-close.svg		\
	image/toolbar/24x24/x-capture-file-close@2x.png		\
	image/toolbar/24x24/x-capture-file-close@2x.svg		\
	image/toolbar/24x24/x-capture-file-reload.png		\
	image/toolbar/24x24/x-capture-file-reload.svg		\
	image/toolbar/24x24/x-capture-file-reload@2x.png	\
	image/toolbar/24x24/x-capture-file-reload@2x.svg	\
	image/toolbar/24x24/x-capture-file-save.png		\
	image/toolbar/24x24/x-capture-file-save.svg		\
	image/toolbar/24x24/x-capture-file-save@2x.png		\
	image/toolbar/24x24/x-capture-file-save@2x.svg		\
	image/toolbar/24x24/x-capture-options-gear.svg		\
	image/toolbar/24x24/x-capture-options-wrench.svg	\
	image/toolbar/24x24/x-capture-options.png		\
	image/toolbar/24x24/x-capture-options@2x.png		\
	image/toolbar/24x24/x-capture-restart-fin.svg		\
	image/toolbar/24x24/x-capture-restart-triangle1.svg	\
	image/toolbar/24x24/x-capture-restart-triangle2.svg	\
	image/toolbar/24x24/x-capture-restart-turn1.svg		\
	image/toolbar/24x24/x-capture-restart-turn2.svg		\
	image/toolbar/24x24/x-capture-restart.png		\
	image/toolbar/24x24/x-capture-restart@2x.png		\
	image/toolbar/24x24/x-capture-start.on.png		\
	image/toolbar/24x24/x-capture-start.on.svg		\
	image/toolbar/24x24/x-capture-start.on@2x.png		\
	image/toolbar/24x24/x-capture-start.png		\
	image/toolbar/24x24/x-capture-start.svg		\
	image/toolbar/24x24/x-capture-start@2x.png	\
	image/toolbar/24x24/x-capture-stop-red.svg	\
	image/toolbar/24x24/x-capture-stop-white.svg	\
	image/toolbar/24x24/x-capture-stop.png		\
	image/toolbar/24x24/x-capture-stop@2x.png	\
	image/toolbar/24x24/x-colorize-packets.png	\
	image/toolbar/24x24/x-colorize-packets.svg	\
	image/toolbar/24x24/x-colorize-packets@2x.png	\
	image/toolbar/24x24/x-resize-columns-motion.svg	\
	image/toolbar/24x24/x-resize-columns.png	\
	image/toolbar/24x24/x-resize-columns.svg	\
	image/toolbar/24x24/x-resize-columns@2x.png	\
	image/toolbar/24x24/x-stay-last.png		\
	image/toolbar/24x24/x-stay-last.svg		\
	image/toolbar/24x24/x-stay-last@2x.png		\
	image/toolbar/24x24/zoom-in.png			\
	image/toolbar/24x24/zoom-in.svg			\
	image/toolbar/24x24/zoom-in@2x.png		\
	image/toolbar/24x24/zoom-original.png		\
	image/toolbar/24x24/zoom-original.svg		\
	image/toolbar/24x24/zoom-original@2x.png	\
	image/toolbar/24x24/zoom-out.png		\
	image/toolbar/24x24/zoom-out.svg		\
	image/toolbar/24x24/zoom-out@2x.png		\
	image/toolbar.qrc			\
	image/toolbar/analyze_24.xpm 		\
	image/toolbar/audio_player_24.xpm	\
	image/toolbar/autoscroll_24.xpm		\
	image/toolbar/capture_airpcap_16.xpm	\
	image/toolbar/capture_capture_16.xpm	\
	image/toolbar/capture_details_16.xpm	\
	image/toolbar/capture_details_24.xpm	\
	image/toolbar/capture_ethernet_16.xpm	\
	image/toolbar/capture_filter_24.xpm	\
	image/toolbar/capture_interfaces_16.png	\
	image/toolbar/capture_interfaces_16.svg \
	image/toolbar/capture_interfaces_24.png	\
	image/toolbar/capture_interfaces_24.svg \
	image/toolbar/capture_pause_16.png	\
	image/toolbar/capture_pause_16.svg	\
	image/toolbar/capture_pause_24.png	\
	image/toolbar/capture_pause_24.svg	\
	image/toolbar/capture_prepare_16.xpm	\
	image/toolbar/checkbox_16.xpm		\
	image/toolbar/colorize_24.xpm		\
	image/toolbar/conversations_16.xpm	\
	image/toolbar/decode_24.xpm		\
	image/toolbar/decode_as_16.xpm		\
	image/toolbar/display_filter_24.xpm	\
	image/toolbar/endpoints_16.xpm		\
	image/toolbar/expert_info_16.xpm	\
	image/toolbar/file_set_list_16.xpm	\
	image/toolbar/file_set_next_16.xpm	\
	image/toolbar/file_set_previous_16.xpm	\
	image/toolbar/flow_graph_16.xpm	\
	image/toolbar/gnome_emblem_web_16.png	\
	image/toolbar/gnome_emblem_web_24.png	\
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
	image/toolbar/svg-to-png.sh	\
	image/toolbar/svg/x-filter-apply.svg	\
	image/toolbar/svg/x-filter-bookmark.svg	\
	image/toolbar/svg/x-filter-clear.svg	\
	image/toolbar/telephone_16.xpm	\
	image/toolbar/telephony_16.xpm	\
	image/toolbar/time_24.xpm	\
	image/toolbar/voip_flow_24.xpm	\
	image/toolbar/web_support_24.xpm	\
	image/toolbar/wep_closed_24.xpm	\
	image/tshark.rc.in	\
	image/voip_select.xpm	\
	image/wireshark.exe.manifest.in \
	image/wireshark.ico	\
	image/wireshark.rc.in	\
	image/wiresharkdoc.ico	\
	image/wiresharkinst.ico	\
	image/WiresharkDoc-16.png	\
	image/WiresharkDoc-24.png	\
	image/WiresharkDoc-32.png	\
	image/WiresharkDoc-48.png	\
	image/WiresharkDoc-64.png	\
	image/WiresharkDoc-128.png	\
	image/WiresharkDoc-256.png	\
	image/wiretap.rc.in	\
	image/wsicon.qrc	\
	image/wsicon.svg	\
	image/wsicon16.png	\
	image/wsicon24.png	\
	image/wsicon32.png	\
	image/wsicon48.png	\
	image/wsicon64.png	\
	image/wsicon128.png	\
	image/wsicon256.png	\
	image/wsicon512.png	\
	image/wsicon1024.png	\
	image/wsicon-ask.png	\
	image/wsicon-ask.svg	\
	image/wsiconcap.svg	\
	image/wsiconcap16.png	\
	image/wsiconcap24.png	\
	image/wsiconcap32.png	\
	image/wsiconcap48.png	\
	image/wsiconcap64.png	\
	image/wsiconcap128.png	\
	image/wsiconcap256.png	\
	image/wsiconcap512.png	\
	image/wsiconcap1024.png	\
	image/wsiconinst.svg	\
	image/wsiconinst256.png	\
	image/wslogo-dev.svg	\
	image/wslogo.eps	\
	image/wslogo.svg	\
	image/wssplash_dev.png	\
	image/wssplash.png	\
	ipmap.html		\
	macosx-setup.sh		\
	macosx-support-lib-patches/glib-gconvert.c.patch \
	macosx-support-lib-patches/glib-pkgconfig.patch \
	macosx-support-lib-patches/gnutls-pkgconfig.patch \
	macosx-support-lib-patches/portaudio-pa_mac_core.h.patch \
	macosx-support-lib-patches/portaudio-pa_mac_core.c.patch \
	macosx-support-lib-patches/qt-fix-pc-file \
	macosx-support-lib-patches/qt-fix-pc-files \
	make-version.pl		\
	manuf			\
	manuf.tmpl		\
	mergecap.c		\
	pdml2html.xsl		\
	reordercap.c		\
	smi_modules		\
	text2pcap-scanner.l	\
	text2pcap.h		\
	services		\
	wireshark.desktop	\
	wireshark-gtk.desktop	\
	wireshark-mime-package.xml \
	wireshark.appdata.xml	\
	wireshark.pc.in		\
	wka.tmpl		\
	CMakeLists.txt		\
	CMakeListsCustom.txt.example		\
	cmakeconfig.h.in	\
	wsutil/CMakeLists.txt	\
	CMakeOptions.txt	\
	wiretap/CMakeLists.txt	\
	README.cmake		\
	ConfigureChecks.cmake	\
	cmake/modules/CheckCCompilerFlag.cmake	\
	cmake/modules/CheckCLinkerFlag.cmake	\
	cmake/modules/CMakeInstallDirs.cmake	\
	cmake/modules/COPYING-CMAKE-SCRIPTS	\
	cmake/modules/FindADNS.cmake		\
	cmake/modules/FindAIRPCAP.cmake		\
	cmake/modules/FindASCIIDOC.cmake	\
	cmake/modules/FindCAP.cmake		\
	cmake/modules/FindCARES.cmake		\
	cmake/modules/FindChocolatey.cmake	\
	cmake/modules/FindDOXYGEN.cmake		\
	cmake/modules/FindFOP.cmake		\
	cmake/modules/FindFreetype.cmake	\
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
	cmake/modules/FindMSVC_REDIST.cmake	\
	cmake/modules/FindNL.cmake		\
	cmake/modules/FindNSIS.cmake		\
	cmake/modules/FindOS_X_FRAMEWORKS.cmake	\
	cmake/modules/FindPCAP.cmake		\
	cmake/modules/FindPOD.cmake		\
	cmake/modules/FindPortableApps.cmake	\
	cmake/modules/FindPORTAUDIO.cmake	\
	cmake/modules/FindPowerShell.cmake	\
	cmake/modules/FindSBC.cmake		\
	cmake/modules/FindSED.cmake		\
	cmake/modules/FindSETCAP.cmake		\
	cmake/modules/FindSH.cmake		\
	cmake/modules/FindSMI.cmake		\
	cmake/modules/FindLIBSSH.cmake	\
	cmake/modules/FindWinSparkle.cmake	\
	cmake/modules/FindWireshark.cmake	\
	cmake/modules/FindWSWinLibs.cmake	\
	cmake/modules/FindXMLLINT.cmake		\
	cmake/modules/FindXSLTPROC.cmake	\
	cmake/modules/FindYACC.cmake		\
	cmake/modules/FindYAPP.cmake		\
	cmake/modules/FindZLIB.cmake		\
	cmake/modules/GenerateTestSh.cmake	\
	cmake/modules/gmxTestLargeFiles.cmake	\
	cmake/modules/hhc.cmake	\
	cmake/modules/LICENSE.txt		\
	cmake/modules/LocatePythonExecutable.cmake	\
	cmake/modules/LocatePythonModule.cmake	\
	cmake/modules/readme.txt		\
	cmake/modules/UseABICheck.cmake		\
	cmake/modules/UseAsn2Wrs.cmake		\
	cmake/modules/UseCheckAPI.cmake		\
	cmake/modules/UseCustomIncludes.cmake		\
	cmake/modules/UseLemon.cmake		\
	cmake/modules/UseMakeDissectorReg.cmake	\
	cmake/modules/UseMakeTapReg.cmake	\
	cmake/modules/UseWinLibs.cmake		\
	cmake/modules/WiresharkConfig.cmake.in	\
	cmake/modules/WiresharkConfigVersion.cmake.in \
	cmake/modules/WiresharkPlugin.cmake	\
	cmake/TestFileOffsetBits.c	\
	cmake/TestLargeFiles.c.cmakein	\
	cmake/TestWindowsFSeek.c	\
	ui/win32/Makefile.nmake			\
	ui/win32/console_win32.c		\
	ui/win32/console_win32.h		\
	ui/win32/file_dlg_win32.c		\
	ui/win32/file_dlg_win32.h		\
	ui/win32/print_win32.c			\
	ui/win32/print_win32.h			\
	ui/win32/settings.ini			\
	version.h.in				\
	CPackConfig.txt

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


DIST_SUBDIRS = \
	asn1		\
	capchild	\
	caputils	\
	codecs		\
	doc		\
	epan		\
	echld		\
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
	wsutil		\
	extcap		\
	docbook

SUBDIRS = \
	tools			\
	wsutil			\
	wiretap			\
	epan			\
	capchild		\
	caputils		\
	@echld_dir@		\
	@plugins_dir@		\
	packaging		\
	help			\
	ui			\
	@wireshark_SUBDIRS@	\
	ui/cli			\
	randpkt_core		\
	extcap			\
	.			\
	doc

help/faq.txt: $(srcdir)/help/faq.py
	$(AM_V_GEN)(cd help ; \
	$(MAKE) faq.txt ;)

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck


# Used by patch-bzip2
# Trim off any extra version information and find the previous micro release.
BASE_VERSION=`echo "$(VERSION)" | awk -F. '{$$3 = $$3 + 0 ; printf("%d.%d.%d"), $$1, $$2, $$3}'`
PREV_VERSION=`echo "$(VERSION)" | awk -F. '{$$3 = $$3 + 0 ; if ($$3 > 0) $$3-- ; printf("%d.%d.%d"), $$1, $$2, $$3}'`
PREV_DIR="wireshark-$(PREV_VERSION)"
PREV_FILE="$(PREV_DIR).tar.bz2"
PREV_URL="https://www.wireshark.org/download/src/all-versions/$(PREV_FILE)"

patch-bzip2: distdir
	if test x$(BASE_VERSION) != x$(PREV_VERSION) ; then \
		curl --time-cond $(PREV_FILE) --location --output $(PREV_FILE) $(PREV_URL) && \
		tar -xjf $(PREV_FILE) && \
		diff -urN $(PREV_DIR) $(distdir) | bzip2 > patch-wireshark-$(PREV_VERSION)-to-$(VERSION).bz2 && \
		echo "Created patch-bzip2" ; \
		rm -rf "$(PREV_FILE)" "$(PREV_DIR)" ; \
	else \
		echo "This appears to be the first micro version ($(PREV_VERSION)). Skipping." ; \
	fi
	$(am__remove_distdir)

#
# Install icons and other desktop files for (for use with GNOME, KDE, or
# any other freedesktop.org-compliant desktops).
#
# We use $(datadir).  If the desktop doesn't look for them there,
# the desktop is broken; the latest XDG Base Directory Specification
# at
#
#    http://standards.freedesktop.org/basedir-spec/basedir-spec-latest.html
#
# says
#
# $XDG_DATA_DIRS defines the preference-ordered set of base directories
# to search for data files in addition to the $XDG_DATA_HOME base
# directory. The directories in $XDG_DATA_DIRS should be seperated with a
# colon ':'.
#
# If $XDG_DATA_DIRS is either not set or empty, a value equal to
# /usr/local/share/:/usr/share/ should be used.
#
# so:
#
#    if this is configured to install under /usr, that should Just Work,
#    unless XDG_DATA_DIRS is set incorrectly or the desktop isn't
#    compliant with the latest version of the spec;
#
#    if this installs under the default /usr/share, that should Just Work,
#    unless XDG_DATA_DIRS is set incorrectly or the desktop isn't
#    compliant with the latest version of the spec;
#
#    if this is configured to install somewhere else, whoever configured
#    it should also have made sure that XDG_DATA_DIRS was set correctly
#    and, if that doesn't work, the desktop isn't compliant with the
#    latest version of the spec.
#
# We install these as part of the standard installation process, just
# as, for example, Inkscape does with its icons.  See bug 10737.
#
# Do not use the -T flag to the install command, as it's not portable.
# Some versions of install don't support a -T flag at all, and the
# FreeBSD install command has a -T flag that takes an argument and
# that has completely different semantics.
#
# We neither need nor want any of this on OS X, nor do we want it if
# we're not building Wireshark (that being the only desktop app).
#
install-data-local:
if BUILDING_WIRESHARK
if NOT_OS_X
	mkdir -p $(DESTDIR)$(datadir)/mime/packages
	install -m 644 $(srcdir)/wireshark-mime-package.xml $(DESTDIR)$(datadir)/mime/packages/wireshark.xml
	mkdir -p $(DESTDIR)$(datadir)/appdata
	install -m 644 $(srcdir)/wireshark.appdata.xml $(DESTDIR)$(datadir)/appdata/wireshark.appdata.xml
	mkdir -p $(DESTDIR)$(datadir)/applications
	if test x$(DESKTOP_FILE_INSTALL) != x ; then \
		$(DESKTOP_FILE_INSTALL) --dir $(DESTDIR)$(datadir)/applications $(srcdir)/wireshark.desktop  $(srcdir)/wireshark-gtk.desktop ; \
	else \
		install -m 644 $(srcdir)/wireshark.desktop $(srcdir)/wireshark-gtk.desktop $(DESTDIR)$(datadir)/applications; \
	fi
	for size in 16 24 32 48 64 128 256; \
	do \
		mkdir -p $(DESTDIR)$(datadir)/icons/hicolor/$${size}x$${size}/apps ; \
		install -m 644 $(srcdir)/image/wsicon$${size}.png $(DESTDIR)$(datadir)/icons/hicolor/$${size}x$${size}/apps/wireshark.png ; \
		mkdir -p $(DESTDIR)$(datadir)/icons/hicolor/$${size}x$${size}/mimetypes ; \
		install -m 644 $(srcdir)/image/WiresharkDoc-$${size}.png $(DESTDIR)$(datadir)/icons/hicolor/$${size}x$${size}/mimetypes/application-wireshark-doc.png ; \
	done
	mkdir -p $(DESTDIR)$(datadir)/icons/hicolor/scalable/apps
	install -m 644 $(srcdir)/image/wsicon.svg $(DESTDIR)$(datadir)/icons/hicolor/scalable/apps/wireshark.svg
endif
endif

uninstall-local:
if BUILDING_WIRESHARK
if NOT_OS_X
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
endif

install-data-hook: update-databases-and-caches-install
uninstall-hook: update-databases-and-caches-uninstall

#
# XXX - which of this stuff can, and should, we do ourselves?
#
# If we're "installing" under $(DESTDIR) as part of the process of
# building a package, we probably don't need to, and shouldn't, do
# any of this.
#
# If we're installing for use, we may need to do some of this; which
# of them do we need to tell where to search, especially if we're
# installing somewhere other than under /usr or /usr/local?
#
# What if we're installing in the user's home directory?
#
# What if we're installing under /opt?
#
# We only need to run ldconfig on systems where it's necessary in order
# to update a shared library cache to know about our shared libraries.
#
# We only need to run update-desktop-database and update-mime-database
# on freedesktop.org desktops.
#
# We only need to run gtk-update-icon-cache if we're installing a GTK+
# version of Wireshark.
#
# We neither need nor want any of this on OS X, nor do we want it if
# we're not building Wireshark (that being the only desktop app).
#
update-databases-and-caches-common:
if BUILDING_WIRESHARK
if NOT_OS_X
	@echo "You may need to run \"ldconfig\" as root"
	@echo "You may need to run \"update-desktop-database $(datadir)/applications\""
	@echo "You may need to run \"update-mime-database $(datadir)/mime\""
	@echo "You may need to run \"gtk-update-icon-cache -f -t $(datadir)/icons/hicolor\""
endif
endif

update-databases-and-caches-install: update-databases-and-caches-common

update-databases-and-caches-uninstall: update-databases-and-caches-common

# Used by svr4-package and osx-package
# We load top_stagedir with an absolute path so that libtool doesn't freak.
top_stagedir=$(abs_top_builddir)/packaging/staging
stagedir=$(top_stagedir)/$(PACKAGE).inst

host_cpu=@host_cpu@
host_os=@host_os@

solaris-package: svr4-package

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


rpm_topdir=`cd $(top_builddir) && pwd`/packaging/rpm
rpm-package: dist
	@if test x$(HAVE_RPM) = xyes ; then \
		cd $(rpm_topdir) ; \
		mkdir -p BUILD RPMS SOURCES SRPMS; \
		cd SOURCES ; \
		ln -sf ../../../$(distdir).tar.bz2 ; \
		cd .. ; \
		rpmbuild --define "_topdir `cd . && pwd`" --define "_prefix $(prefix)" \
			@RPMBUILD_WITH_ARGS@ --clean -ba SPECS/wireshark.spec && \
			echo "Package successfully built in `pwd`/RPMS." && \
			rm -f SOURCES/$(distdir).tar.bz2 $(distdir).tar.bz2 ; \
	else \
		echo "Error: RPM executable and/or source directory not found." ; \
		false; \
	fi

# XXX - This assumes we're building from the source directory.
osx-app: $(PROGRAMS) $(SCRIPTS) $(MANS) $(DATA) packaging/macosx/Info.plist
	@if test x$(HAVE_OSX_PACKAGING) = xyes ; then \
		rm -rf $(stagedir) ; \
		$(MAKE) DESTDIR=$(stagedir) install; \
		cd $(srcdir)/packaging/macosx ; \
		./osx-app.sh @OSX_APP_FLAGS@ \
			--create-bundle \
			--binary-path ../staging/$(PACKAGE).inst$(bindir) \
			--plugin-path ../staging/$(PACKAGE).inst$(plugindir) \
			--extcap-path ../staging/$(PACKAGE).inst$(extcapdir) \
			--library-path ../staging/$(PACKAGE).inst$(libdir) ; \
	else \
		echo "Error: OS X packaging tools not found." ; \
		echo "Package build abandoned." ; \
	fi

packaging/macosx/COPYING.txt: COPYING
	(cd packaging/macosx ; \
	$(MAKE) COPYING.txt ;)

osx-package: osx-app packaging/macosx/COPYING.txt
	@if test x$(HAVE_OSX_PACKAGING) = xyes ; then \
		cd $(srcdir)/packaging/macosx ; \
		chmod +x ./osx-dmg.sh ; \
		./osx-dmg.sh @OSX_DMG_FLAGS@ ; \
	fi

osx-install: osx-app
	@if test x$(HAVE_OSX_PACKAGING) = xyes ; then \
		echo "Copying Wireshark.app to /Applications" ; \
		cp -pr $(srcdir)/packaging/macosx/Wireshark.app /Applications ; \
	fi

test-programs:
	cd epan && $(MAKE) $@

clean-local:
	rm -rf $(top_stagedir)

dumpabi:
	$(MAKE) -C wiretap dumpabi-libwiretap
	$(MAKE) -C epan dumpabi-libwireshark
	$(MAKE) -C wsutil dumpabi-libwsutil

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
##	cd epan && $(MAKE) checkapi
##	cd epan/crypt && $(MAKE) checkapi
	cd epan/dfilter && $(MAKE) checkapi
##	cd epan/ftypes && $(MAKE) checkapi
##	cd epan/wslua && $(MAKE) checkapi
	cd epan/dissectors && $(MAKE) checkapi
	cd epan/dissectors/dcerpc && $(MAKE) checkapi
	cd plugins && $(MAKE) checkapi
	cd randpkt_core && $(MAKE) checkapi
	cd wsutil && $(MAKE) checkapi

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
