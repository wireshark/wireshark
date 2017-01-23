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
wslua_lib = wslua/libwslua.la
wslua_dir = wslua
wslua_dist_dir =
else		# HAVE_LIBLUA
wslua_lib =
wslua_dir =
wslua_dist_dir = wslua
endif		# HAVE_LIBLUA

SUBDIRS = compress crypt ftypes dfilter dissectors nghttp2 wmem $(wslua_dir)

DIST_SUBDIRS = $(SUBDIRS) $(wslua_dist_dir)

AM_CPPFLAGS = $(INCLUDEDIRS) -I$(builddir)/wslua $(WS_CPPFLAGS) \
	$(GLIB_CFLAGS) $(LUA_CFLAGS) $(LIBGNUTLS_CFLAGS) \
	$(LIBGCRYPT_CFLAGS) $(LIBSMI_CFLAGS) $(LIBGEOIP_CFLAGS) \
	$(KRB5_CFLAGS)

noinst_LTLIBRARIES = libwireshark_generated.la libwireshark_asmopt.la
lib_LTLIBRARIES = libwireshark.la

LIBWIRESHARK_SRC = \
	addr_and_mask.c		\
	addr_resolv.c		\
	address_types.c		\
	afn.c			\
	aftypes.c		\
	app_mem_usage.c		\
	asn1.c			\
	capture_dissectors.c	\
	charsets.c		\
	circuit.c		\
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
	dwarf.c			\
	epan.c			\
	ex-opt.c		\
	except.c		\
	expert.c		\
	exported_pdu.c		\
	plugin_if.c		\
	filter_expressions.c	\
	follow.c		\
	frame_data.c		\
	frame_data_sequence.c	\
	funnel.c		\
	g_int64_hash_routines.c	\
	geoip_db.c		\
	golay.c			\
	guid-utils.c		\
	iana_charsets.c		\
	in_cksum.c		\
	ipproto.c		\
	ipv4.c			\
	media_params.c		\
	next_tvb.c		\
	oids.c			\
	osi-utils.c		\
	oui.c			\
	packet-range.c		\
	packet.c		\
	prefs.c			\
	print.c			\
	print_stream.c		\
	proto.c			\
	proto_data.c		\
	range.c			\
	reassemble.c		\
	reedsolomon.c		\
	req_resp_hdrs.c		\
	rtd_table.c		\
	show_exception.c	\
	sminmpec.c		\
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

LIBWIRESHARK_ALL_SRC = \
	$(LIBWIRESHARK_SRC)	\
	$(LIBWIRESHARK_GENERATED_SRC)

LIBWIRESHARK_INCLUDES = \
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
	circuit.h		\
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
	dwarf.h			\
	eap.h			\
	eapol_keydes_types.h	\
	epan-int.h		\
	epan.h			\
	epan_dissect.h		\
	etypes.h		\
	ex-opt.h		\
	except.h		\
	exceptions.h		\
	expert.h		\
	exported_pdu.h		\
	plugin_if.h		\
	filter_expressions.h	\
	follow.h		\
	frame_data.h		\
	frame_data_sequence.h	\
	funnel.h		\
	g_int64_hash_routines.h	\
	garrayfix.h		\
	geoip_db.h		\
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
	media_params.h		\
	next_tvb.h		\
	nlpid.h			\
	oids.h			\
	osi-utils.h		\
	oui.h			\
	packet-range.h		\
	packet.h		\
	packet_info.h		\
	params.h		\
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
	req_resp_hdrs.h		\
	rtd_table.h		\
	rtp_pt.h		\
	sctpppids.h		\
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
	to_str-int.h		\
	tvbparse.h		\
	tvbuff.h		\
	tvbuff-int.h		\
	uat.h			\
	uat-int.h		\
	value_string.h		\
	x264_prt_id.h		\
	xdlc.h

#Since code generated by lex may trigger gcc warnings, we are now generating two
#libraries. A single library is generated with the lex code without the barrier
#"stop on warning". An other library is generated from the remaining source
#files with the "stop on warning" barrier.
libwireshark_la_SOURCES = \
	$(LIBWIRESHARK_SRC)		\
	$(LIBWIRESHARK_INCLUDES)	\
	ws_version_info.c

libwireshark_la_CPPFLAGS = $(AM_CPPFLAGS) -DWS_BUILD_DLL

# http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
libwireshark_la_LDFLAGS = -version-info 9:5:1 @LDFLAGS_SHAREDLIB@

#
# Add the object files for missing routines, if any.
#
libwireshark_la_LIBADD = \
	libwireshark_generated.la		\
	libwireshark_asmopt.la			\
	crypt/libairpdcap.la			\
	ftypes/libftypes.la			\
	dfilter/libdfilter.la			\
	dissectors/libdissectors.la		\
	dissectors/libdirtydissectors.la	\
	dissectors/libfiledissectors.la		\
	nghttp2/libnghttp2.la			\
	wmem/libwmem.la				\
	$(wslua_lib)				\
	${top_builddir}/wiretap/libwiretap.la	\
	${top_builddir}/wsutil/libwsutil.la	\
	@C_ARES_LIBS@		\
	@LIBGCRYPT_LIBS@	\
	@LIBGNUTLS_LIBS@	\
	@KRB5_LIBS@		\
	@SSL_LIBS@		\
	@LIBSMI_LDFLAGS@	\
	@GEOIP_LIBS@		\
	@GLIB_LIBS@

libwireshark_la_DEPENDENCIES = \
	libwireshark_generated.la		\
	compress/liblzxpress.la			\
	libwireshark_asmopt.la			\
	crypt/libairpdcap.la			\
	ftypes/libftypes.la			\
	dfilter/libdfilter.la			\
	dissectors/libdissectors.la		\
	dissectors/libdirtydissectors.la	\
	nghttp2/libnghttp2.la			\
	wmem/libwmem.la				\
	$(wslua_lib)				\
	${top_builddir}/wsutil/libwsutil.la	\
	${top_builddir}/wiretap/libwiretap.la

libwireshark_generated_la_SOURCES = \
	$(LIBWIRESHARK_GENERATED_C_FILES) \
	$(LIBWIRESHARK_GENERATED_HEADER_FILES)

nodist_libwireshark_generated_la_SOURCES = \
	$(NODIST_LIBWIRESHARK_GENERATED_C_FILES) \
	$(NODIST_LIBWIRESHARK_GENERATED_HEADER_FILES)

libwireshark_generated_la_CFLAGS = $(GENERATED_CFLAGS)

# code optionally implemented in assembler
# only C source available for platforms other than Win32
libwireshark_asmopt_la_SOURCES = \
	asm_utils.c		\
	asm_utils.h		\
	asm_utils_win32_x86.asm

EXTRA_DIST = \
	.editorconfig		\
	diam_dict.l		\
	dtd_grammar.lemon	\
	dtd_parse.l		\
	dtd_parse.h		\
	dtd_preparse.l		\
	enterprise-numbers	\
	radius_dict.l		\
	uat_load.l		\
	doxygen.cfg.in		\
	CMakeLists.txt		\
	print.ps

CLEANFILES = \
	doxygen-epan.tag		\
	libwireshark.a			\
	libwireshark.la			\
	libwireshark_generated.a	\
	libwireshark_generated.la	\
	libwireshark_asmopt.a		\
	libwireshark_asmopt.la		\
	*~

DISTCLEANFILES = \
	$(NODIST_LIBWIRESHARK_GENERATED_C_FILES) \
	$(NODIST_LIBWIRESHARK_GENERATED_HEADER_FILES) \
	dtd_grammar.out \
	ws_version_info.c

MAINTAINERCLEANFILES = \
	$(LIBWIRESHARK_GENERATED_C_FILES) \
	$(LIBWIRESHARK_GENERATED_HEADER_FILES) \
	Makefile.in

BUILT_SOURCES = \
	$(LIBWIRESHARK_GENERATED_HEADER_FILES) \
	$(NODIST_LIBWIRESHARK_GENERATED_HEADER_FILES) \
	ws_version_info.c

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

ws_version_info.c: $(top_srcdir)/ws_version_info.c
	$(AM_V_LN_S)$(LN_S) $<

tvbtest.o exntest.o oids_test.o: exceptions.h

update-sminmpec:
	$(PERL) $(srcdir)/../tools/make-sminmpec.pl

ps.c: print.ps $(top_srcdir)/tools/rdps.py
	$(AM_V_python)$(PYTHON) $(top_srcdir)/tools/rdps.py $(srcdir)/print.ps ps.c

if HAVE_PLUGINS

if ENABLE_STATIC
-include ../plugins/Custom.make
plugin_src = \
	../plugins/asn1/packet-asn1.c \
	../plugins/docsis/packet-bintrngreq.c \
	../plugins/docsis/packet-bpkmattr.c \
	../plugins/docsis/packet-bpkmreq.c \
	../plugins/docsis/packet-bpkmrsp.c \
	../plugins/docsis/packet-docsis.c \
	../plugins/docsis/packet-dsaack.c \
	../plugins/docsis/packet-dsareq.c \
	../plugins/docsis/packet-dsarsp.c \
	../plugins/docsis/packet-dscack.c \
	../plugins/docsis/packet-dscreq.c \
	../plugins/docsis/packet-dscrsp.c \
	../plugins/docsis/packet-dsdreq.c \
	../plugins/docsis/packet-dsdrsp.c \
	../plugins/docsis/packet-intrngreq.c \
	../plugins/docsis/packet-macmgmt.c \
	../plugins/docsis/packet-map.c \
	../plugins/docsis/packet-regack.c \
	../plugins/docsis/packet-regreq.c \
	../plugins/docsis/packet-regrsp.c \
	../plugins/docsis/packet-rngreq.c \
	../plugins/docsis/packet-rngrsp.c \
	../plugins/docsis/packet-tlv.c \
	../plugins/docsis/packet-type29ucd.c \
	../plugins/docsis/packet-uccreq.c \
	../plugins/docsis/packet-uccrsp.c \
	../plugins/docsis/packet-ucd.c \
	../plugins/gryphon/packet-gryphon.c \
	../plugins/irda/packet-irda.c \
	../plugins/m2m/packet-m2m.c \
	../plugins/m2m/wimax_tlv.c \
	../plugins/wimax/crc.c \
	../plugins/wimax/crc_data.c \
	../plugins/wimax/mac_hd_generic_decoder.c \
	../plugins/wimax/mac_hd_type1_decoder.c \
	../plugins/wimax/mac_hd_type2_decoder.c \
	../plugins/wimax/mac_mgmt_msg_decoder.c \
	../plugins/wimax/msg_aas_beam.c \
	../plugins/wimax/msg_aas_fbck.c \
	../plugins/wimax/msg_arq.c \
	../plugins/wimax/msg_clk_cmp.c \
	../plugins/wimax/msg_dcd.c \
	../plugins/wimax/msg_dlmap.c \
	../plugins/wimax/msg_dreg.c \
	../plugins/wimax/msg_dsa.c \
	../plugins/wimax/msg_dsc.c \
	../plugins/wimax/msg_dsd.c \
	../plugins/wimax/msg_dsx_rvd.c \
	../plugins/wimax/msg_fpc.c \
	../plugins/wimax/msg_pkm.c \
	../plugins/wimax/msg_pmc.c \
	../plugins/wimax/msg_prc_lt_ctrl.c \
	../plugins/wimax/msg_reg_req.c \
	../plugins/wimax/msg_reg_rsp.c \
	../plugins/wimax/msg_rep.c \
	../plugins/wimax/msg_res_cmd.c \
	../plugins/wimax/msg_rng_req.c \
	../plugins/wimax/msg_rng_rsp.c \
	../plugins/wimax/msg_sbc.c \
	../plugins/wimax/msg_ucd.c \
	../plugins/wimax/msg_ulmap.c \
	../plugins/wimax/packet-wmx.c \
	../plugins/wimax/wimax_cdma_code_decoder.c \
	../plugins/wimax/wimax_compact_dlmap_ie_decoder.c \
	../plugins/wimax/wimax_compact_ulmap_ie_decoder.c \
	../plugins/wimax/wimax_fch_decoder.c \
	../plugins/wimax/wimax_ffb_decoder.c \
	../plugins/wimax/wimax_hack_decoder.c \
	../plugins/wimax/wimax_harq_map_decoder.c \
	../plugins/wimax/wimax_pdu_decoder.c \
	../plugins/wimax/wimax_phy_attributes_decoder.c \
	../plugins/wimax/wimax_tlv.c \
	../plugins/wimax/wimax_utils.c


else		# ENABLE_STATIC

plugin_src =

endif		# ENABLE_STATIC

else		# HAVE_PLUGINS
plugin_src =

endif		# HAVE_PLUGINS

doxygen:
if HAVE_DOXYGEN
	$(AM_V_GEN)$(DOXYGEN) doxygen.cfg
endif		# HAVE_DOXYGEN

wsar_html: doxygen.cfg ../doxygen_global.cfg
if HAVE_DOXYGEN
	(umask 022 ; $(DOXYGEN) doxygen.cfg)
endif

# ABI compliance checker can be obtained from
# http://ispras.linux-foundation.org/index.php/ABI_compliance_checker
# Checked using version 1.21.12
dumpabi-libwireshark: all abi-descriptor.xml
	rm -rf abi-check-headers abi_dumps .libs/*.abi.tar.gz
	mkdir abi-check-headers
	cp ../config.h ../register.h abi-check-headers/
	mkdir abi-check-headers/epan
	cp *.h abi-check-headers/epan
	mkdir abi-check-headers/crypt
	cp crypt/*.h abi-check-headers/crypt
	mkdir abi-check-headers/compress
	cp compress/*.h abi-check-headers/compress
	mkdir abi-check-headers/dfilter
	cp dfilter/*.h ../tools/lemon/cppmagic.h abi-check-headers/dfilter
	mkdir abi-check-headers/dissectors
	cp dissectors/*.h abi-check-headers/dissectors
	rm \
		abi-check-headers/dissectors/x11-extension-implementation.h \
		abi-check-headers/dissectors/x11-glx-render-enum.h \
		abi-check-headers/dissectors/x11-register-info.h \
		abi-check-headers/dissectors/packet-idmp.h
	mkdir abi-check-headers/ftypes
	cp ftypes/*.h abi-check-headers/ftypes
	mkdir abi-check-headers/wmem
	cp wmem/*.h abi-check-headers/wmem
	abi-compliance-checker -log-path abi_logs/log.txt -l libwireshark -v1 `readlink .libs/libwireshark.so | sed 's/.*\.so\.//'` \
		-relpath $(abs_srcdir) -dump-abi abi-descriptor.xml || \
		cat abi_logs/log.txt logs/libwireshark/[0-9]*/log.txt
	cp -f abi_dumps/libwireshark/libwireshark_* .libs/
	cd .libs && ln -sf libwireshark_*.abi.tar.gz libwireshark.abi.tar.gz

maintainer-clean-local: clean-dumpabi-libwireshark

.PHONY: clean-dumpabi-libwireshark

clean-dumpabi-libwireshark:
	rm -rf abi-check-headers abi_dumps .libs/*.abi.tar.gz abi_logs abi-descriptor.xml

checkapi:
	$(AM_V_GEN)$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g termoutput -build \
	-sourcedir=$(srcdir) \
	$(LIBWIRESHARK_SRC)
