# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

file(TO_NATIVE_PATH "${CMAKE_INSTALL_PREFIX}" PATH_INSTALL_PREFIX)
string(REPLACE "\\" "\\\\" PATH_INSTALL_PREFIX "${PATH_INSTALL_PREFIX}")
file(TO_NATIVE_PATH "${CMAKE_INSTALL_DATADIR}" PATH_DATA_DIR)
string(REPLACE "\\" "\\\\" PATH_DATA_DIR "${PATH_DATA_DIR}")
file(TO_NATIVE_PATH "${CMAKE_INSTALL_DOCDIR}" PATH_DOC_DIR)
string(REPLACE "\\" "\\\\" PATH_DOC_DIR "${PATH_DOC_DIR}")
file(TO_NATIVE_PATH "${PLUGIN_INSTALL_LIBDIR}" PATH_PLUGIN_DIR)
string(REPLACE "\\" "\\\\" PATH_PLUGIN_DIR "${PATH_PLUGIN_DIR}")
file(TO_NATIVE_PATH "${EXTCAP_INSTALL_LIBDIR}" PATH_EXTCAP_DIR)
string(REPLACE "\\" "\\\\" PATH_EXTCAP_DIR "${PATH_EXTCAP_DIR}")
file(TO_NATIVE_PATH "${LOG_EXTCAP_INSTALL_LIBDIR}" PATH_LOG_EXTCAP_DIR)
string(REPLACE "\\" "\\\\" PATH_LOG_EXTCAP_DIR "${PATH_LOG_EXTCAP_DIR}")

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/path_config.h.in ${CMAKE_CURRENT_BINARY_DIR}/path_config.h)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(WMEM_PUBLIC_HEADERS
	wmem/wmem.h
	wmem/wmem_array.h
	wmem/wmem_core.h
	wmem/wmem_list.h
	wmem/wmem_map.h
	wmem/wmem_miscutl.h
	wmem/wmem_multimap.h
	wmem/wmem_queue.h
	wmem/wmem_stack.h
	wmem/wmem_strbuf.h
	wmem/wmem_strutl.h
	wmem/wmem_tree.h
	wmem/wmem_interval_tree.h
	wmem/wmem_user_cb.h
)

set(WMEM_HEADER_FILES
	${WMEM_PUBLIC_HEADERS}
	wmem/wmem_allocator.h
	wmem/wmem_allocator_block.h
	wmem/wmem_allocator_block_fast.h
	wmem/wmem_allocator_simple.h
	wmem/wmem_allocator_strict.h
	wmem/wmem_interval_tree.h
	wmem/wmem_map_int.h
	wmem/wmem_tree-int.h
	wmem/wmem_user_cb_int.h
)

set(WMEM_FILES
	wmem/wmem_array.c
	wmem/wmem_core.c
	wmem/wmem_allocator_block.c
	wmem/wmem_allocator_block_fast.c
	wmem/wmem_allocator_simple.c
	wmem/wmem_allocator_strict.c
	wmem/wmem_interval_tree.c
	wmem/wmem_list.c
	wmem/wmem_map.c
	wmem/wmem_miscutl.c
	wmem/wmem_multimap.c
	wmem/wmem_stack.c
	wmem/wmem_strbuf.c
	wmem/wmem_strutl.c
	wmem/wmem_tree.c
	wmem/wmem_user_cb.c
)

set(WSUTIL_PUBLIC_HEADERS
	802_11-utils.h
	adler32.h
	array.h
	base32.h
	bits_count_ones.h
	bits_ctz.h
	bitswap.h
	buffer.h
	clopts_common.h
	cmdarg_err.h
	codecs.h
	color.h
	cpu_info.h
	crash_info.h
	crc5.h
	crc6.h
	crc7.h
	crc8.h
	crc10.h
	crc11.h
	crc16.h
	crc16-plain.h
	crc32.h
	curve25519.h
	eax.h
	epochs.h
	exported_pdu_tlvs.h
	feature_list.h
	filesystem.h
	g711.h
	inet_addr.h
	inet_cidr.h
	interface.h
	introspection.h
	jsmn.h
	json_dumper.h
	mpeg-audio.h
	nstime.h
	os_version_info.h
	pint.h
	please_report_bug.h
	plugins.h
	pow2.h
	privileges.h
	processes.h
	regex.h
	report_message.h
	sign_ext.h
	sober128.h
	socket.h
	str_util.h
	strnatcmp.h
	strtoi.h
	tempfile.h
	time_util.h
	to_str.h
	type_util.h
	unicode-utils.h
	utf8_entities.h
	version_info.h
	ws_assert.h
	ws_cpuid.h
	glib-compat.h
	ws_getopt.h
	ws_mempbrk.h
	ws_mempbrk_int.h
	ws_pipe.h
	ws_roundup.h
	ws_strptime.h
	wsgcrypt.h
	wsjson.h
	wslog.h
	xtea.h
)

set(WSUTIL_COMMON_FILES
	802_11-utils.c
	adler32.c
	base32.c
	bitswap.c
	buffer.c
	clopts_common.c
	cmdarg_err.c
	codecs.c
	crash_info.c
	crc10.c
	crc16.c
	crc16-plain.c
	crc32.c
	crc5.c
	crc6.c
	crc7.c
	crc8.c
	crc11.c
	curve25519.c
	dot11decrypt_wep.c
	eax.c
	feature_list.c
	filesystem.c
	filter_files.c
	g711.c
	inet_addr.c
	inet_cidr.c
	interface.c
	introspection.c
	jsmn.c
	json_dumper.c
	mpeg-audio.c
	nstime.c
	cpu_info.c
	os_version_info.c
	please_report_bug.c
	privileges.c
	regex.c
	rsa.c
	sober128.c
	socket.c
	strnatcmp.c
	str_util.c
	strtoi.c
	report_message.c
	tempfile.c
	time_util.c
	to_str.c
	type_util.c
	unicode-utils.c
	version_info.c
	ws_getopt.c
	ws_mempbrk.c
	ws_pipe.c
	ws_strptime.c
	wsgcrypt.c
	wsjson.c
	wslog.c
	xtea.c
)

if(WIN32)
	list(APPEND WSUTIL_COMMON_FILES
		console_win32.c
	)
endif()

if(ENABLE_PLUGINS)
	list(APPEND WSUTIL_COMMON_FILES
		plugins.c
	)
endif()

set(WSUTIL_FILES
	${WMEM_FILES}
	${WSUTIL_COMMON_FILES}
)

if(WIN32)
	list(APPEND WSUTIL_FILES
		file_util.c
		win32-utils.c
	)
endif(WIN32)


if(HAVE_MACOS_FRAMEWORKS)
	list(APPEND WSUTIL_FILES cfutils.c)
endif()

#
# XXX - we're assuming MSVC doesn't require a flag to enable SSE 4.2
# support, and that, if the compiler supports a flag for SSE 4.2
# support, the intrinsics are supported iff we can include the
# <nmmintrin.h> flag.
#
# We only check for the GCC-style -msse4.2 flag and the Sun C
# -xarch=sse4_2 flag.
#
if(CMAKE_C_COMPILER_ID MATCHES "MSVC")
	set(COMPILER_CAN_HANDLE_SSE4_2 TRUE)
	set(SSE4_2_FLAG "")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "i686|x86|x86_64|AMD64")
	check_c_compiler_flag(-msse4.2 COMPILER_CAN_HANDLE_SSE4_2)
	if(COMPILER_CAN_HANDLE_SSE4_2)
		set(SSE4_2_FLAG "-msse4.2")
	else()
		check_c_compiler_flag(-xarch=sse4_2 COMPILER_CAN_HANDLE_SSE4_2)
		if(COMPILER_CAN_HANDLE_SSE4_2)
			set(SSE4_2_FLAG "-xarch=sse4_2")
		endif()
	endif()
else()
	set(COMPILE_CAN_HANDLE_SSE4_2 FALSE)
	set(SSE4_2_FLAG "")
endif()

if(SSE4_2_FLAG)
	message(STATUS "SSE4.2 compiler flag: ${SSE4_2_FLAG}")
else()
	message(STATUS "No SSE4.2 compiler flag enabled")
endif()
if(COMPILER_CAN_HANDLE_SSE4_2)
	#
	# Make sure we have the necessary headers for the SSE4.2 intrinsics
	# and that we can use them.
	#
	# First, check whether we have emmintrin.h and can use it
	# *without* the SSE 4.2 flag.
	#
	check_include_file("emmintrin.h" EMMINTRIN_H_WORKS)

	#
	# OK, if that works, see whether we have nmmintrin.h and
	# can use it *with* the SSE 4.2 flag.
	#
	if(EMMINTRIN_H_WORKS)
		#
		# Does this add the SSE4.2 flags to the beginning of
		# CFLAGS?
		#
		# Note that if there's a mix of "enable SSE 4.2" and
		# "disable SSE 4.2" flags, this may not indicate that
		# we can use the header.  That's not a bug, that's a
		# feature; the other flags may have been forced by
		# the build process, e.g. in Gentoo Linux, and we want
		# to check this with whatever flags will actually be
		# used when building (see bug 10792).
		#
		cmake_push_check_state()
		set(CMAKE_REQUIRED_FLAGS "${SSE4_2_FLAG}")
		check_include_file("nmmintrin.h" HAVE_SSE4_2)
		cmake_pop_check_state()
	endif()
endif()
if(HAVE_SSE4_2)
	list(APPEND WSUTIL_FILES ws_mempbrk_sse42.c)
endif()

if(APPLE)
	#
	# We assume that APPLE means macOS so that we have the macOS
	# frameworks.
	#
	FIND_LIBRARY (APPLE_CORE_FOUNDATION_LIBRARY CoreFoundation)
endif()

set_source_files_properties(
	${WSUTIL_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

if (HAVE_SSE4_2)
	# TODO with CMake 2.8.12, we could use COMPILE_OPTIONS and just append
	# instead of this COMPILE_FLAGS duplication...
	set_source_files_properties(
		ws_mempbrk_sse42.c
		PROPERTIES
		COMPILE_FLAGS "${WERROR_COMMON_FLAGS} ${SSE4_2_FLAG}"
	)
endif()

if (ENABLE_APPLICATION_BUNDLE)
	set_source_files_properties(
		filesystem.c
		PROPERTIES
		COMPILE_FLAGS "${WERROR_COMMON_FLAGS} -DENABLE_APPLICATION_BUNDLE"
)
endif()

add_library(wsutil
	${WSUTIL_FILES}
	${CMAKE_BINARY_DIR}/resources/libwsutil.rc
)

if(NOT VCSVERSION_OVERRIDE)
	add_dependencies(wsutil vcs_version)
endif()

target_compile_definitions(wsutil PRIVATE
	WS_BUILD_DLL
	BUILD_WSUTIL
)

set_target_properties(wsutil PROPERTIES
	PREFIX "lib"
	LINK_FLAGS "${WS_LINK_FLAGS}"
	VERSION "0.0.0" SOVERSION 0
	FOLDER "DLLs"
	INSTALL_RPATH "${LIBRARY_INSTALL_RPATH}"
)
if(MSVC)
	set_target_properties(wsutil PROPERTIES LINK_FLAGS_DEBUG "${WS_MSVC_DEBUG_LINK_FLAGS}")
endif()

target_link_libraries(wsutil
	PUBLIC
		${GLIB2_LIBRARIES}
	PRIVATE
		${GMODULE2_LIBRARIES}
		${APPLE_CORE_FOUNDATION_LIBRARY}
		${CMAKE_DL_LIBS}
		${GCRYPT_LIBRARIES}
		${GNUTLS_LIBRARIES}
		${M_LIBRARIES}
		${ZLIB_LIBRARIES}
		${ZLIBNG_LIBRARIES}
		$<IF:$<CONFIG:Debug>,${PCRE2_DEBUG_LIBRARIES},${PCRE2_LIBRARIES}>
		${WIN_IPHLPAPI_LIBRARY}
		${WIN_WS2_32_LIBRARY}
)

target_include_directories(wsutil SYSTEM
	PUBLIC
		${GLIB2_INCLUDE_DIRS}
		${GCRYPT_INCLUDE_DIRS}
		${GNUTLS_INCLUDE_DIRS}
	PRIVATE
		${GMODULE2_INCLUDE_DIRS}
		${ZLIB_INCLUDE_DIRS}
		${ZLIBNG_INCLUDE_DIRS}
		${PCRE2_INCLUDE_DIRS}
)

install(TARGETS wsutil
	EXPORT WiresharkTargets
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(FILES ${WMEM_PUBLIC_HEADERS}
	DESTINATION "${PROJECT_INSTALL_INCLUDEDIR}/wsutil/wmem"
	COMPONENT "Development"
	EXCLUDE_FROM_ALL
)

install(FILES ${WSUTIL_PUBLIC_HEADERS}
	DESTINATION "${PROJECT_INSTALL_INCLUDEDIR}/wsutil"
	COMPONENT "Development"
	EXCLUDE_FROM_ALL
)

add_library(wsutil_static STATIC
	${WSUTIL_FILES}
)

target_compile_definitions(wsutil_static PRIVATE
	ENABLE_STATIC
	BUILD_WSUTIL
)

target_link_libraries(wsutil_static
	PUBLIC
		${GLIB2_LIBRARIES}
	PRIVATE
		${GMODULE2_LIBRARIES}
		${APPLE_CORE_FOUNDATION_LIBRARY}
		${CMAKE_DL_LIBS}
		${GCRYPT_LIBRARIES}
		${GNUTLS_LIBRARIES}
		${ZLIB_LIBRARIES}
		${ZLIBNG_LIBRARIES}
		$<IF:$<CONFIG:Debug>,${PCRE2_DEBUG_LIBRARIES},${PCRE2_LIBRARIES}>
		${WIN_IPHLPAPI_LIBRARY}
		${WIN_WS2_32_LIBRARY}
)

target_include_directories(wsutil_static SYSTEM
	PUBLIC
		${GLIB2_INCLUDE_DIRS}
		${GCRYPT_INCLUDE_DIRS}
		${GNUTLS_INCLUDE_DIRS}
	PRIVATE
		${GMODULE2_INCLUDE_DIRS}
		${ZLIB_INCLUDE_DIRS}
		${ZLIBNG_INCLUDE_DIRS}
		${PCRE2_INCLUDE_DIRS}
)

if(NOT VCSVERSION_OVERRIDE)
	add_dependencies(wsutil_static vcs_version)
endif()

add_executable(wmem_test EXCLUDE_FROM_ALL wmem/wmem_test.c ${WMEM_FILES})

target_link_libraries(wmem_test wsutil)

set_target_properties(wmem_test PROPERTIES
	FOLDER "Tests"
	EXCLUDE_FROM_DEFAULT_BUILD True
	COMPILE_DEFINITIONS "WS_BUILD_DLL"
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

add_executable(test_wsutil EXCLUDE_FROM_ALL
	test_wsutil.c
)

target_link_libraries(test_wsutil ${GLIB2_LIBRARIES} wsutil)

set_target_properties(test_wsutil PROPERTIES
	FOLDER "Tests"
	EXCLUDE_FROM_DEFAULT_BUILD True
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

CHECKAPI(
	NAME
	  wsutil
	SWITCHES
	SOURCES
	  ${WMEM_FILES}
	  ${WSUTIL_COMMON_FILES}
)

set_source_files_properties(jsmn.c PROPERTIES COMPILE_DEFINITIONS "JSMN_STRICT")

#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
