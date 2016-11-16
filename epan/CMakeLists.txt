# CMakeLists.txt
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
#

include(UseABICheck)

if (HAVE_HFI_SECTION_INIT)
	add_definitions(
		-DHAVE_HFI_SECTION_INIT
	)
endif()

add_subdirectory(crypt)
add_subdirectory(dfilter)
add_subdirectory(dissectors)
add_subdirectory(ftypes)
add_subdirectory(nghttp2)
add_subdirectory(wmem)
if (HAVE_LIBLUA)
	add_subdirectory(wslua)
endif()

include_directories(
	${CMAKE_CURRENT_BINARY_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}
)

set(COMPRESS_FILES
	compress/lzxpress.c
)
source_group(compress FILES ${COMPRESS_FILES})

set(LIBWIRESHARK_ASM_FILES
	asm_utils.c
# todo
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

add_custom_target(
	update-sminmpec
	COMMAND ${PERL_EXECUTABLE}
		${CMAKE_SOURCE_DIR}/tools/make-sminmpec.pl
	DEPENDS
		enterprise-numbers
		${CMAKE_SOURCE_DIR}/tools/make-sminmpec.pl
)
set_target_properties(update-sminmpec PROPERTIES FOLDER "tools")

add_custom_command(
	OUTPUT ps.c
	COMMAND ${PYTHON_EXECUTABLE}
		${CMAKE_SOURCE_DIR}/tools/rdps.py
		${CMAKE_CURRENT_SOURCE_DIR}/print.ps
		ps.c
	DEPENDS
		${CMAKE_SOURCE_DIR}/tools/rdps.py
		${CMAKE_CURRENT_SOURCE_DIR}/print.ps
)

set(LIBWIRESHARK_FILES
	addr_and_mask.c
	addr_resolv.c
	address_types.c
	afn.c
	aftypes.c
	app_mem_usage.c
	asn1.c
	capture_dissectors.c
	charsets.c
	circuit.c
	color_filters.c
	column.c
	column-utils.c
	conversation.c
	conversation_table.c
	crc10-tvb.c
	crc16-tvb.c
	crc32-tvb.c
	crc6-tvb.c
	crc8-tvb.c
	decode_as.c
	disabled_protos.c
	dissector_filters.c
	dvb_chartbl.c
	dwarf.c
	epan.c
	ex-opt.c
	except.c
	expert.c
	exported_pdu.c
	plugin_if.c
	filter_expressions.c
	follow.c
	frame_data.c
	frame_data_sequence.c
	funnel.c
	g_int64_hash_routines.c
	geoip_db.c
	golay.c
	guid-utils.c
	iana_charsets.c
	in_cksum.c
	ipproto.c
	ipv4.c
	media_params.c
	next_tvb.c
	oids.c
	osi-utils.c
	oui.c
	packet-range.c
	packet.c
	print.c
	print_stream.c
	prefs.c
	proto.c
	proto_data.c
	ps.c
	range.c
	reassemble.c
	reedsolomon.c
	req_resp_hdrs.c
	rtd_table.c
	show_exception.c
	sminmpec.c
	srt_table.c
	stat_tap_ui.c
	stats_tree.c
	strutil.c
	stream.c
	t35.c
	tap.c
	timestamp.c
	timestats.c
	tfs.c
	to_str.c
	tvbparse.c
	tvbuff.c
	tvbuff_base64.c
	tvbuff_composite.c
	tvbuff_real.c
	tvbuff_subset.c
	tvbuff_zlib.c
	uat.c
	value_string.c
	xdlc.c
	${CMAKE_SOURCE_DIR}/ws_version_info.c
)

set(LIBWIRESHARK_CLEAN_FILES
	${LIBWIRESHARK_FILES}
)

add_lex_files(LEX_FILES GENERATED_FILES
	diam_dict.l
	dtd_parse.l
	dtd_preparse.l
	radius_dict.l
	uat_load.l
)

add_lemon_files(LEMON_FILES GENERATED_FILES
	dtd_grammar.lemon
)

set(epan_LIBS
	wiretap
	wsutil
	${GLIB2_LIBRARIES}
	${PCAP_LIBRARIES}
	${CARES_LIBRARIES}
	${KERBEROS_LIBRARIES}
	${GEOIP_LIBRARIES}
	${GCRYPT_LIBRARIES}
	${GNUTLS_LIBRARIES}
	${SMI_LIBRARIES}
	${M_LIBRARIES}
	${LUA_LIBRARIES}
	${WIN_PSAPI_LIBRARY}
)

set(CLEAN_FILES
	${LIBWIRESHARK_CLEAN_FILES}
	${COMPRESS_FILES}
	${LIBWIRESHARK_ASM_FILES}
)

if (WERROR_COMMON_FLAGS)
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS ${WERROR_COMMON_FLAGS}
	)
endif()

# Cannot use $<$<BOOL:${HAVE_LIBLUA}>:$<TARGET_OBJECTS:wslua>> as that breaks
# get_target_property(_libwireshark_location epan LOCATION).
if(HAVE_LIBLUA)
	set(wslua_sources $<TARGET_OBJECTS:wslua>)
else()
	set(wslua_sources)
endif()
add_library(epan ${LINK_MODE_LIB}
	${LIBWIRESHARK_FILES}
	${GENERATED_FILES}
	${COMPRESS_FILES}
	${LIBWIRESHARK_ASM_FILES}
	$<TARGET_OBJECTS:crypt>
	$<TARGET_OBJECTS:dfilter>
	$<TARGET_OBJECTS:dissectors>
	$<TARGET_OBJECTS:dissectors-corba>
	$<TARGET_OBJECTS:ftypes>
	$<TARGET_OBJECTS:nghttp2>
	$<TARGET_OBJECTS:wmem>
	${wslua_sources}
	${CMAKE_BINARY_DIR}/image/libwireshark.rc
)

add_dependencies(epan version)

set(FULL_SO_VERSION "8.1.3")

set_target_properties(epan PROPERTIES COMPILE_DEFINITIONS "WS_BUILD_DLL")
set_target_properties(epan PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")
set_target_properties(epan PROPERTIES VERSION ${FULL_SO_VERSION} SOVERSION 8)

if(ENABLE_APPLICATION_BUNDLE)
	set_target_properties(epan PROPERTIES
		LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/run/Wireshark.app/Contents/Frameworks
	)
endif()

ABICHECK(libwireshark)

set(TOP_LEVEL_HEADERS ${CMAKE_BINARY_DIR}/config.h ${CMAKE_SOURCE_DIR}/register.h)
file(GLOB CRYPT_HEADERS crypt/*.h)
file(GLOB COMPRESS_HEADERS compress/*.h)
file(GLOB DFILTER_HEADERS dfilter/*.h ../tools/lemon/cppmagic.h)
file(GLOB D_HEADERS dissectors/*.h)
file(GLOB FTYPES_HEADERS ftypes/*.h)
file(GLOB WMEM_HEADERS wmem/*.h)
file(GLOB NGHTTP2_HEADERS nghttp2/*.h)

add_custom_command(OUTPUT libwireshark.abi.tar.gz
	COMMAND ${CMAKE_COMMAND} -E remove_directory ${ABICHECK_TMPDIR}
	COMMAND ${CMAKE_COMMAND} -E make_directory ${ABICHECK_TMPDIR}
	COMMAND ${CMAKE_COMMAND} -E make_directory ${ABICHECK_TMPDIR}/epan
	COMMAND ${CMAKE_COMMAND} -E make_directory ${ABICHECK_TMPDIR}/crypt
	COMMAND ${CMAKE_COMMAND} -E make_directory ${ABICHECK_TMPDIR}/compress
	COMMAND ${CMAKE_COMMAND} -E make_directory ${ABICHECK_TMPDIR}/dfilter
	COMMAND ${CMAKE_COMMAND} -E make_directory ${ABICHECK_TMPDIR}/dissectors
	COMMAND ${CMAKE_COMMAND} -E make_directory ${ABICHECK_TMPDIR}/ftypes
	COMMAND ${CMAKE_COMMAND} -E make_directory ${ABICHECK_TMPDIR}/wmem
	COMMAND ${CMAKE_COMMAND} -E make_directory ${ABICHECK_TMPDIR}/nghttp2
	COMMAND ${ABI_COPY_COMMAND} ${TOP_LEVEL_HEADERS} ${ABICHECK_TMPDIR} ${ABI_COPY_FLAGS}
	COMMAND ${ABI_COPY_COMMAND} ${ABICHECK_HEADERS} ${ABICHECK_TMPDIR}/epan ${ABI_COPY_FLAGS}
	COMMAND ${ABI_COPY_COMMAND} ${CRYPT_HEADERS} ${ABICHECK_TMPDIR}/crypt ${ABI_COPY_FLAGS}
	COMMAND ${ABI_COPY_COMMAND} ${COMPRESS_HEADERS} ${ABICHECK_TMPDIR}/compress ${ABI_COPY_FLAGS}
	COMMAND ${ABI_COPY_COMMAND} ${DFILTER_HEADERS} ${ABICHECK_TMPDIR}/dfilter ${ABI_COPY_FLAGS}
	COMMAND ${ABI_COPY_COMMAND} ${D_HEADERS} ${ABICHECK_TMPDIR}/dissectors ${ABI_COPY_FLAGS}
	COMMAND ${ABI_COPY_COMMAND} ${FTYPES_HEADERS} ${ABICHECK_TMPDIR}/ftypes ${ABI_COPY_FLAGS}
	COMMAND ${ABI_COPY_COMMAND} ${WMEM_HEADERS} ${ABICHECK_TMPDIR}/wmem ${ABI_COPY_FLAGS}
	COMMAND ${ABI_COPY_COMMAND} ${NGHTTP2_HEADERS} ${ABICHECK_TMPDIR}/nghttp2 ${ABI_COPY_FLAGS}
	COMMAND rm -f ${ABICHECK_TMPDIR}/dissectors/x11-extension-implementation.h
		${ABICHECK_TMPDIR}/dissectors/packet-rtps.h
		${ABICHECK_TMPDIR}/dissectors/x11-glx-render-enum.h
		${ABICHECK_TMPDIR}/dissectors/x11-register-info.h
		${ABICHECK_TMPDIR}/dissectors/packet-idmp.h
	COMMAND ${ABICHECK_COMMAND}
	COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/abi_dumps/libwireshark/libwireshark_* ${CMAKE_CURRENT_BINARY_DIR}/libwireshark.abi.tar.gz
	COMMAND rm -rf ${ABICHECK_TMPDIR} ${CMAKE_CURRENT_BINARY_DIR}/abi_dumps
#	COMMAND rm -rf ${CMAKE_CURRENT_BINARY_DIR}/abi_dumps ${ABICHECK_TMPDIR}/config.h
#		${ABICHECK_TMPDIR}/epan/* ${ABICHECK_TMPDIR}/crypt/*
#		${ABICHECK_TMPDIR}/epan/* ${ABICHECK_TMPDIR}/compress/*
#		${ABICHECK_TMPDIR}/dfilter/* ${ABICHECK_TMPDIR}/dissectors/*
#		${ABICHECK_TMPDIR}/ftypes/* ${ABICHECK_TMPDIR}/wmem/*
#		${ABICHECK_TMPDIR}/nghttp2/*
	DEPENDS ${HEADERS}
		${CRYPT_HEADERS} ${COMPRESS_HEADERS} ${DFILTER_HEADERS} ${D_HEADERS}
		${FTYPES_HEADERS} ${WMEM_HEADERS} ${NGHTTP2_HEADERS} epan)

# By default the name for a library with target name epan will be libepan,
# but Ethereal is now named Wireshark
set_target_properties(epan PROPERTIES
	OUTPUT_NAME "wireshark"
	PREFIX "lib"
	FOLDER "DLLs"
)

target_link_libraries(epan ${epan_LIBS})

add_dependencies(epan lemon)

if(NOT ${ENABLE_STATIC})
	install(TARGETS epan
		LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
		RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}
		ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	)
endif()

add_executable(exntest EXCLUDE_FROM_ALL exntest.c except.c)
target_link_libraries(exntest ${GLIB2_LIBRARIES})
set_target_properties(exntest PROPERTIES
	FOLDER "Tests"
	COMPILE_DEFINITIONS "WS_BUILD_DLL"
)

add_executable(oids_test EXCLUDE_FROM_ALL oids_test.c)
target_link_libraries(oids_test epan ${ZLIB_LIBRARIES})
set_target_properties(oids_test PROPERTIES
	FOLDER "Tests"
	COMPILE_DEFINITIONS "WS_BUILD_DLL"
)

add_executable(reassemble_test EXCLUDE_FROM_ALL reassemble_test.c)
target_link_libraries(reassemble_test epan)
set_target_properties(reassemble_test PROPERTIES
	FOLDER "Tests"
)

add_executable(tvbtest EXCLUDE_FROM_ALL tvbtest.c)
target_link_libraries(tvbtest epan)
set_target_properties(tvbtest PROPERTIES
	FOLDER "Tests"
	COMPILE_DEFINITIONS "WS_BUILD_DLL"
)

CHECKAPI(
	NAME
	  epan
	SWITCHES
	  -g termoutput -build
	SOURCES
	  ${LIBWIRESHARK_FILES}
)

#
# Editor modelines  -  http://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
#
