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

if (HAVE_LIBLUA)
	add_subdirectory( wslua )
	set(WSLUA_LIB wslua)
else()
	set(WSLUA_LIB )
endif()
if (HAVE_LIBPYTHON)
	add_subdirectory( wspython )
	set(WSPYTHON_LIB wspython)
else()
	set(WSPYTHON_LIB )
endif()

add_subdirectory( crc )
set(CRC_LIB crc )

add_subdirectory( crypt )
set(CRYPT_LIB crypt )

add_subdirectory( dissectors )
set(DISSECTORS_LIB dissectors )

add_subdirectory( dfilter )
set(DFILTER_LIB dfilter )

add_subdirectory( ftypes )
set(FTYPES_LIB ftypes )

include_directories(
	${CMAKE_CURRENT_BINARY_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}/dfilter
	${CMAKE_CURRENT_SOURCE_DIR}/dissectors
	${CMAKE_CURRENT_SOURCE_DIR}/ftypes
)

link_directories(
	crc
	crypt
	dissectors
	dfilter
	ftypes
	wslua
	wspython
)

ADD_CUSTOM_COMMAND(
    OUTPUT sminmpec.c
    COMMAND ${PERL_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/make-sminmpec.pl
      ${CMAKE_CURRENT_SOURCE_DIR}/enterprise-numbers
      sminmpec.c
    DEPENDS
      enterprise-numbers
      make-sminmpec.pl
)

set(LIBWIRESHARK_ASM_FILES
	asm_utils.c
#	!IFDEF NASM
#	asm_utils_win32_x86.obj: asm_utils_win32_x86.asm
#	        $(NASM) -f $(WIRESHARK_TARGET_PLATFORM) -o $@ $?
#	!ENDIF
#	...
#	!IF defined(NASM) && "$(WIRESHARK_TARGET_PLATFORM)" == "win32"
#	        asm_utils_win32_x86.obj
#	!ELSE
#	        asm_utils.obj
#	!ENDIF
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

set(epan_LIBS
	wiretap
	wsutil
#	@INET_ATON_LO@
#	@INET_PTON_LO@
#	@INET_NTOP_LO@
#	@SSL_LIBS@
	${PCRE_LIBRARIES}
	${GLIB2_LIBRARIES}
	${PCAP_LIBRARIES}
#	@SOCKET_LIBS@
#	@NSL_LIBS@
	${CARES_LIBRARIES}
	${ADNS_LIBRARIES}
	${KERBEROS_LIBRARIES}
#	@FRAMEWORKS@
	${GEOIP_LIBRARIES}
	${GCRYPT_LIBRARIES}
	${GNUTLS_LIBRARIES}
	${SMI_LIBRARIES}
	${M_LIBRARIES}
)

add_library(epan SHARED
	${LIBWIRESHARK_FILES}
	${LIBWIRESHARK_ASM_FILES}
)
# In case we want the libwireshark name back
# SET_TARGET_PROPERTIES(epan PROPERTIES OUTPUT_NAME "wireshark")

target_link_libraries(epan
	${CRC_LIB}
	${DISSECTORS_LIB}
	${DFILTER_LIB}
	${FTYPES_LIB}
	${WSLUA_LIB}
	${WSPYTHON_LIB}
)

target_link_libraries(epan ${epan_LIBS})

add_dependencies(epan lemon)

install(TARGETS epan
	LIBRARY DESTINATION lib
	RUNTIME DESTINATION lib
	ARCHIVE DESTINATION lib
)

