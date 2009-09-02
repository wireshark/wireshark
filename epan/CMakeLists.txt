# CMakeLists.txt
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
#

subdirs(
	dissectors
)

ADD_CUSTOM_COMMAND(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/sminmpec.c
    COMMAND ${PERL_EXECUTABLE}
    ARGS
    ${CMAKE_CURRENT_SOURCE_DIR}/make-sminmpec.pl
    ${CMAKE_CURRENT_SOURCE_DIR}/enterprise-numbers
    ${CMAKE_CURRENT_BINARY_DIR}/sminmpec.c
    DEPENDS enterprise-numbers
)

set(LIBWIRESHARK_FILES
	addr_and_mask.c
	addr_resolv.c
	adler32.c
	afn.c
	asn1.c
	atalk-utils.c
	base64.c
	bitswap.c
	camel-persistentdata.c
	charsets.c
	circuit.c
	codecs.c
	column.c
	column-utils.c
	conversation.c
	crc10.c
	crc16.c
	crc32.c
	crc6.c
	crcdrm.c
	dissector_filters.c
	emem.c
	epan.c
	ex-opt.c
	except.c
	expert.c
	filesystem.c
	follow.c
	frame_data.c
	frequency-utils.c
	funnel.c
	gcp.c
	geoip_db.c
	golay.c
	guid-utils.c
	h225-persistentdata.c
	in_cksum.c
	ipproto.c
	ipv4.c
	next_tvb.c
	nstime.c
	oids.c
	osi-utils.c
	packet.c
	plugins.c
	prefs.c
	proto.c
	range.c
	reassemble.c
	reedsolomon.c
	report_err.c
	req_resp_hdrs.c
	sigcomp_state_hdlr.c
	sigcomp-udvm.c
	sminmpec.c
	sna-utils.c
	stat_cmd_args.c
	stats_tree.c
	strutil.c
	stream.c
	t35.c
	tap.c
	tcap-persistentdata.c
	timestamp.c
	tfs.c
	to_str.c
	tvbparse.c
	tvbuff.c
	uat.c
	value_string.c
	xdlc.c
)

add_lex_files(LIBWIRESHARK_FILES
	diam_dict.l
	dtd_parse.l
	dtd_preparse.l
	radius_dict.l
	uat_load.l
)

add_lemon_files(LIBWIRESHARK_FILES
	dtd_grammar.lemon
)

# add_dependency(ascend.c ascend_scanner_lex.h)

add_library(libwireshark SHARED
	${LIBWIRESHARK_FILES}
)

install(TARGETS libwireshark
	LIBRARY DESTINATION lib
	RUNTIME DESTINATION lib
	ARCHIVE DESTINATION lib
)

