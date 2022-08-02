# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

add_definitions(-DPLUGIN_DIR=\"${CMAKE_INSTALL_PREFIX}/${PLUGIN_INSTALL_LIBDIR}\")
add_definitions(-DEXTCAP_DIR=\"${CMAKE_INSTALL_PREFIX}/${EXTCAP_INSTALL_LIBDIR}\")
add_definitions(-DDATA_DIR=\"${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATADIR}\")

add_subdirectory(wmem)

set(WSUTIL_PUBLIC_HEADERS
	802_11-utils.h
	adler32.h
	base32.h
	bits_count_ones.h
	bits_ctz.h
	bitswap.h
	buffer.h
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
	inet_ipv4.h
	inet_ipv6.h
	interface.h
	jsmn.h
	json_dumper.h
	mpeg-audio.h
	netlink.h
	nstime.h
	os_version_info.h
	pint.h
	please_report_bug.h
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
	ws_assert.h
	ws_cpuid.h
	glib-compat.h
	ws_getopt.h
	ws_mempbrk.h
	ws_mempbrk_int.h
	ws_pipe.h
	ws_roundup.h
	ws_return.h
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
	g711.c
	inet_addr.c
	interface.c
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
	ws_getopt.c
	ws_mempbrk.c
	ws_pipe.c
	wsgcrypt.c
	wsjson.c
	wslog.c
	xtea.c
)

if(ENABLE_PLUGINS)
	list(APPEND WSUTIL_COMMON_FILES
		plugins.c
	)
endif()

set(WSUTIL_FILES ${WSUTIL_COMMON_FILES})
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
else()
	check_c_compiler_flag(-msse4.2 COMPILER_CAN_HANDLE_SSE4_2)
	if(COMPILER_CAN_HANDLE_SSE4_2)
		set(SSE4_2_FLAG "-msse4.2")
	else()
		check_c_compiler_flag(-xarch=sse4_2 COMPILER_CAN_HANDLE_SSE4_2)
		if(COMPILER_CAN_HANDLE_SSE4_2)
			set(SSE4_2_FLAG "-xarch=sse4_2")
		endif()
	endif()
	if(SSE4_2_FLAG)
		message(STATUS "SSE4.2 compiler flag: ${SSE4_2_FLAG}")
	else()
		message(STATUS "No SSE4.2 compiler flag enabled")
	endif()
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

if(NOT HAVE_STRPTIME)
	list(APPEND WSUTIL_FILES strptime.c)
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

add_library(wsutil
	${WSUTIL_FILES}
	$<TARGET_OBJECTS:wmem>
	${CMAKE_BINARY_DIR}/resources/libwsutil.rc
)

set_target_properties(wsutil PROPERTIES
	PREFIX "lib"
	COMPILE_DEFINITIONS "WS_BUILD_DLL"
	LINK_FLAGS "${WS_LINK_FLAGS}"
	VERSION "0.0.0" SOVERSION 0
	FOLDER "DLLs"
	INSTALL_RPATH "${LIBRARY_INSTALL_RPATH}"
)
if(MSVC)
	set_target_properties(wsutil PROPERTIES LINK_FLAGS_DEBUG "${WS_MSVC_DEBUG_LINK_FLAGS}")
endif()

target_link_libraries(wsutil
	# *Lots* of our targets that link with wsutil also link with
	# GLib and GModule. Mark them PUBLIC so that dependent targets
	# don't have to link them directly.
	PUBLIC
		${GLIB2_LIBRARIES}
		${GMODULE2_LIBRARIES}
	PRIVATE
		${APPLE_CORE_FOUNDATION_LIBRARY}
		${CMAKE_DL_LIBS}
		${GCRYPT_LIBRARIES}
		${GNUTLS_LIBRARIES}
		${PCRE2_LIBRARIES}
		${M_LIBRARIES}
		${WIN_IPHLPAPI_LIBRARY}
		${WIN_WS2_32_LIBRARY}
)

target_include_directories(wsutil
	SYSTEM PRIVATE
		${GCRYPT_INCLUDE_DIRS}
		${GNUTLS_INCLUDE_DIRS}
		${PCRE2_INCLUDE_DIRS}
)

install(TARGETS wsutil
	EXPORT WiresharkTargets
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

add_executable(test_wsutil EXCLUDE_FROM_ALL
	test_wsutil.c
)

target_link_libraries(test_wsutil ${GLIB2_LIBRARIES} wsutil)

set_target_properties(test_wsutil PROPERTIES
	FOLDER "Tests"
	EXCLUDE_FROM_DEFAULT_BUILD True
)

install(FILES ${WSUTIL_PUBLIC_HEADERS}
	DESTINATION "${PROJECT_INSTALL_INCLUDEDIR}/wsutil"
)

CHECKAPI(
	NAME
	  wsutil
	SWITCHES
	SOURCES
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
