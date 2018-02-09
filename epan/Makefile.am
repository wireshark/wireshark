# Makefile.am
# Automake file for the libwireshark library
# (EPAN is a historical name; it stands for Ethereal Protocol ANalyzer
# Library)
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

include $(top_srcdir)/Makefile.am.inc

if HAVE_LIBLUA
wslua_dir = wslua
endif

SUBDIRS = crypt ftypes dfilter dissectors wmem $(wslua_dir)

AM_CPPFLAGS = $(INCLUDEDIRS) $(WS_CPPFLAGS) \
	$(GLIB_CFLAGS) $(PCAP_CFLAGS) $(LUA_CFLAGS) $(LIBGNUTLS_CFLAGS) \
	$(LIBGCRYPT_CFLAGS) $(LIBSMI_CFLAGS) $(LZ4_CFLAGS) $(KRB5_CFLAGS) \
	$(SNAPPY_CFLAGS) $(LIBXML2_CFLAGS)

lib_LTLIBRARIES = libwireshark.la

LIBWIRESHARK_NONGENERATED_SRC = \
	addr_and_mask.c		\
	addr_resolv.c		\
	address_types.c		\
	afn.c			\
	aftypes.c		\
	app_mem_usage.c		\
	asn1.c			\
	capture_dissectors.c	\
	charsets.c		\
	color_filters.c		\
	column.c		\
	column-utils.c		\
	conversation.c		\
	conversation_table.c	\
	crc10-tvb.c		\
	crc16-tvb.c		\
	crc32-tvb.c		\
	crc6-tvb.c		\
	crc8-tvb.c		\
	decode_as.c		\
	disabled_protos.c	\
	dissector_filters.c	\
	dvb_chartbl.c		\
	epan.c			\
	ex-opt.c		\
	except.c		\
	expert.c		\
	export_object.c		\
	exported_pdu.c		\
	filter_expressions.c	\
	follow.c		\
	frame_data.c		\
	frame_data_sequence.c	\
	funnel.c		\
	golay.c			\
	guid-utils.c		\
	iana_charsets.c		\
	in_cksum.c		\
	ipproto.c		\
	maxmind_db.c		\
	media_params.c		\
	next_tvb.c		\
	oids.c			\
	osi-utils.c		\
	packet.c		\
	plugin_if.c		\
	prefs.c			\
	print.c			\
	print_stream.c		\
	proto.c			\
	proto_data.c		\
	range.c			\
	reassemble.c		\
	reedsolomon.c		\
	req_resp_hdrs.c		\
	register.c		\
	rtd_table.c		\
	sequence_analysis.c	\
	show_exception.c	\
	srt_table.c		\
	stat_tap_ui.c		\
	stats_tree.c		\
	strutil.c		\
	stream.c		\
	t35.c			\
	tap.c			\
	timestamp.c		\
	timestats.c		\
	tfs.c			\
	to_str.c		\
	tvbparse.c		\
	tvbuff_base64.c		\
	tvbuff_composite.c	\
	tvbuff_real.c		\
	tvbuff_subset.c		\
	tvbuff_zlib.c		\
	tvbuff.c		\
	uat.c			\
	unit_strings.c		\
	value_string.c		\
	xdlc.c

#
# We distribute Lemon and rdps.py with Wireshark, so we don't distribute the
# files they produce.
#
NODIST_LIBWIRESHARK_GENERATED_C_FILES = \
	dtd_grammar.c			\
	ps.c

NODIST_LIBWIRESHARK_GENERATED_HEADER_FILES = \
	dtd_grammar.h

#
# These don't get removed on "make distclean", as the tools we use to
# generate them aren't part of the Wireshark distribution, and aren't
# tools assumed to be present for any system capable of compiling
# from a tarball (e.g., make and a C compiler are assumed to be present,
# but Flex isn't).
#
LIBWIRESHARK_GENERATED_C_FILES = \
	diam_dict.c		\
	dtd_parse.c		\
	dtd_preparse.c		\
	radius_dict.c		\
	uat_load.c

LIBWIRESHARK_GENERATED_HEADER_FILES = \
	diam_dict_lex.h		\
	dtd_parse_lex.h		\
	dtd_preparse_lex.h	\
	radius_dict_lex.h	\
	uat_load_lex.h

LIBWIRESHARK_GENERATED_SRC = \
	$(LIBWIRESHARK_GENERATED_C_FILES) \
	$(NODIST_LIBWIRESHARK_GENERATED_C_FILES)

LIBWIRESHARK_SRC = \
	$(LIBWIRESHARK_NONGENERATED_SRC)	\
	$(LIBWIRESHARK_GENERATED_SRC)

LIBWIRESHARK_INCLUDES_PUBLIC = \
	addr_and_mask.h		\
	addr_resolv.h		\
	address.h		\
	address_types.h		\
	afn.h			\
	aftypes.h		\
	app_mem_usage.h		\
	arcnet_pids.h		\
	arptypes.h		\
	asn1.h			\
	ax25_pids.h		\
	bridged_pids.h		\
	capture_dissectors.h	\
	charsets.h		\
	chdlctypes.h		\
	color_filters.h		\
	column.h		\
	column-info.h		\
	column-utils.h		\
	conversation.h		\
	conversation_debug.h	\
	conversation_table.h	\
	conv_id.h		\
	crc10-tvb.h		\
	crc16-tvb.h		\
	crc32-tvb.h		\
	crc6-tvb.h		\
	crc8-tvb.h		\
	decode_as.h		\
	diam_dict.h		\
	disabled_protos.h	\
	dissector_filters.h	\
	dtd.h			\
	dtd_parse.h		\
	dvb_chartbl.h		\
	eap.h			\
	eapol_keydes_types.h	\
	epan.h			\
	epan_dissect.h		\
	etypes.h		\
	ex-opt.h		\
	except.h		\
	exceptions.h		\
	expert.h		\
	export_object.h		\
	exported_pdu.h		\
	filter_expressions.h	\
	follow.h		\
	frame_data.h		\
	frame_data_sequence.h	\
	funnel.h		\
	garrayfix.h		\
	golay.h			\
	guid-utils.h		\
	iana_charsets.h		\
	iax2_codec_type.h	\
	in_cksum.h		\
	ip_opts.h		\
	ipproto.h		\
	ipv4.h			\
	ipv6.h			\
	lapd_sapi.h		\
	llcsaps.h		\
	maxmind_db.h		\
	media_params.h		\
	next_tvb.h		\
	nlpid.h			\
	oids.h			\
	osi-utils.h		\
	oui.h			\
	packet.h		\
	packet_info.h		\
	params.h		\
	plugin_if.h		\
	ppptypes.h		\
	print.h			\
	print_stream.h		\
	prefs.h			\
	prefs-int.h		\
	proto.h			\
	proto_data.h		\
	ps.h			\
	ptvcursor.h		\
	range.h			\
	reassemble.h		\
	reedsolomon.h		\
	register.h		\
	req_resp_hdrs.h		\
	rtd_table.h		\
	rtp_pt.h		\
	sctpppids.h		\
	sequence_analysis.h	\
	show_exception.h	\
	slow_protocol_subtypes.h \
	sminmpec.h		\
	srt_table.h		\
	stat_tap_ui.h		\
	stat_groups.h		\
	stats_tree.h		\
	stats_tree_priv.h	\
	stream.h		\
	strutil.h		\
	t35.h			\
	tap.h			\
	tap-voip.h		\
	timestamp.h		\
	timestats.h		\
	tfs.h			\
	time_fmt.h		\
	to_str.h		\
	tvbparse.h		\
	tvbuff.h		\
	tvbuff-int.h		\
	uat.h			\
	uat-int.h		\
	unit_strings.h		\
	value_string.h		\
	x264_prt_id.h		\
	xdlc.h

LIBWIRESHARK_INCLUDES_PRIVATE = \
	to_str-int.h

subpkgincludedir = $(pkgincludedir)/epan

subpkginclude_HEADERS = $(LIBWIRESHARK_INCLUDES_PUBLIC)

libwireshark_la_SOURCES = \
	$(LIBWIRESHARK_NONGENERATED_SRC)	\
	$(LIBWIRESHARK_GENERATED_C_FILES)	\
	$(LIBWIRESHARK_INCLUDES_PRIVATE)	\
	version_info.c

nodist_libwireshark_la_SOURCES = \
	$(NODIST_LIBWIRESHARK_GENERATED_C_FILES) \
	$(NODIST_LIBWIRESHARK_GENERATED_HEADER_FILES)

libwireshark_la_CPPFLAGS = $(AM_CPPFLAGS) -DWS_BUILD_DLL

# http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
libwireshark_la_LDFLAGS = -version-info 0:0:0 @LDFLAGS_BIGSHAREDLIB@ @LDFLAGS_SHAREDLIB@

if HAVE_LIBLUA
wslua_lib = wslua/libwslua.la
endif

#
# Add the object files for missing routines, if any.
#
libwireshark_la_LIBADD = \
	crypt/libdot11decrypt.la		\
	ftypes/libftypes.la			\
	dfilter/libdfilter.la			\
	dissectors/libdissectors.la		\
	dissectors/libdirtydissectors.la	\
	dissectors/libfiledissectors.la		\
	wmem/libwmem.la				\
	$(wslua_lib)				\
	${top_builddir}/wiretap/libwiretap.la	\
	${top_builddir}/wsutil/libwsutil.la	\
	@C_ARES_LIBS@		\
	@KRB5_LIBS@		\
	@LIBGCRYPT_LIBS@	\
	@LIBGNUTLS_LIBS@	\
	@LIBSMI_LIBS@	\
	@LZ4_LIBS@		\
	@NGHTTP2_LIBS@		\
	@SNAPPY_LIBS@		\
	@LIBXML2_LIBS@		\
	@GLIB_LIBS@

libwireshark_la_DEPENDENCIES = \
	crypt/libdot11decrypt.la		\
	ftypes/libftypes.la			\
	dfilter/libdfilter.la			\
	dissectors/libdissectors.la		\
	dissectors/libdirtydissectors.la	\
	wmem/libwmem.la				\
	$(wslua_lib)				\
	${top_builddir}/wsutil/libwsutil.la	\
	${top_builddir}/wiretap/libwiretap.la

EXTRA_DIST = \
	.editorconfig		\
	diam_dict.l		\
	dtd_grammar.lemon	\
	dtd_parse.l		\
	dtd_parse.h		\
	dtd_preparse.l		\
	radius_dict.l		\
	uat_load.l		\
	doxygen.cfg.in		\
	CMakeLists.txt		\
	print.ps

CLEANFILES = \
	doxygen-epan.tag

DISTCLEANFILES = \
	$(NODIST_LIBWIRESHARK_GENERATED_C_FILES) \
	$(NODIST_LIBWIRESHARK_GENERATED_HEADER_FILES) \
	dtd_grammar.out \
	version_info.c

MAINTAINERCLEANFILES = \
	$(LIBWIRESHARK_GENERATED_C_FILES) \
	$(LIBWIRESHARK_GENERATED_HEADER_FILES)

BUILT_SOURCES = \
	$(LIBWIRESHARK_GENERATED_HEADER_FILES) \
	$(NODIST_LIBWIRESHARK_GENERATED_HEADER_FILES) \
	version_info.c

EXTRA_PROGRAMS = reassemble_test tvbtest oids_test exntest

reassemble_test_LDADD = \
	libwireshark.la \
	$(GLIB_LIBS) \
	-lz

tvbtest_LDADD = \
	libwireshark.la \
	$(GLIB_LIBS) \
	-lz

oids_test_LDADD = \
	libwireshark.la \
	$(GLIB_LIBS) \
	-lz

exntest_SOURCES = exntest.c except.c

exntest_LDADD = $(GLIB_LIBS)

test-programs: $(EXTRA_PROGRAMS)
	$(MAKE) -C wmem $@

diam_dict_lex.h: diam_dict.c

dtd_parse_lex.h: dtd_parse.c

dtd_preparse_lex.h: dtd_preparse.c

radius_dict_lex.h: radius_dict.c

uat_load_lex.h: uat_load.c

dtd_grammar.h: dtd_grammar.c
dtd_grammar.c : $(LEMON) $(lemon_srcdir)/lempar.c $(srcdir)/dtd_grammar.lemon
	$(AM_V_LEMON)$(LEMON) T=$(lemon_srcdir)/lempar.c $(srcdir)/dtd_grammar.lemon

version_info.c: $(top_srcdir)/version_info.c
	$(AM_V_LN_S)$(LN_S) $< $(builddir)

tvbtest.o exntest.o oids_test.o: exceptions.h

ps.c: print.ps $(top_srcdir)/tools/rdps.py
	$(AM_V_python)$(PYTHON) $(top_srcdir)/tools/rdps.py $(srcdir)/print.ps ps.c

doxygen:
if HAVE_DOXYGEN
	$(AM_V_GEN)$(DOXYGEN) doxygen.cfg
endif		# HAVE_DOXYGEN

wsar_html: doxygen.cfg ../doxygen_global.cfg
if HAVE_DOXYGEN
	(umask 022 ; $(DOXYGEN) doxygen.cfg)
endif

checkapi:
	$(AM_V_GEN)$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g termoutput -build \
	-sourcedir=$(srcdir) \
	$(LIBWIRESHARK_NONGENERATED_SRC)
