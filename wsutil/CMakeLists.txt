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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

include(UseABICheck)

set(WSUTIL_COMMON_FILES
	adler32.c
	aes.c
	airpdcap_wep.c
	base64.c
	bitswap.c
	buffer.c
	clopts_common.c
	cmdarg_err.c
	copyright_info.c
	crash_info.c
	crc10.c
	crc16.c
	crc16-plain.c
	crc32.c
	crc6.c
	crc7.c
	crc8.c
	crc11.c
	des.c
	eax.c
	filesystem.c
	frequency-utils.c
	g711.c
	inet_addr.c
	interface.c
	jsmn.c
	md4.c
	md5.c
	mpeg-audio.c
	nstime.c
	os_version_info.c
	plugins.c
	privileges.c
	sha1.c
	sha2.c
	sober128.c
	strnatcmp.c
	str_util.c
	rc4.c
	report_err.c
	tempfile.c
	time_util.c
	type_util.c
	unicode-utils.c
	ws_mempbrk.c
)

set(WSUTIL_FILES ${WSUTIL_COMMON_FILES})
if(WIN32)
	list(APPEND WSUTIL_FILES
		file_util.c
		inet_ntop.c
		inet_pton.c
		win32-utils.c
	)
ENDIF(WIN32)


if(HAVE_OS_X_FRAMEWORKS)
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
	message(STATUS "Checking for c-compiler flag: -msse4.2")
	check_c_compiler_flag(-msse4.2 COMPILER_CAN_HANDLE_SSE4_2)
	if(COMPILER_CAN_HANDLE_SSE4_2)
		set(SSE4_2_FLAG "-msse4.2")
	else()
		message(STATUS "Checking for c-compiler flag: -xarch=sse4_2")
		check_c_compiler_flag(-xarch=sse4_2 COMPILER_CAN_HANDLE_SSE4_2)
		if(COMPILER_CAN_HANDLE_SSE4_2)
			set(SSE4_2_FLAG "-xarch=sse4_2")
		endif()
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

if(NOT HAVE_GETOPT_LONG)
	list(APPEND WSUTIL_FILES getopt_long.c)
endif()

if(NOT HAVE_INET_ATON)
	list(APPEND WSUTIL_FILES inet_aton.c)
endif()

if(NOT HAVE_POPCOUNT)
	list(APPEND WSUTIL_FILES popcount.c)
endif()

if(NOT HAVE_STRPTIME)
	list(APPEND WSUTIL_FILES strptime.c)
endif()

if(APPLE)
	#
	# We assume that APPLE means OS X so that we have the OS X
	# frameworks.
	#
	FIND_LIBRARY (APPLE_CORE_FOUNDATION_LIBRARY CoreFoundation)
endif()

set(wsutil_LIBS
	${CMAKE_DL_LIBS}
	${APPLE_CORE_FOUNDATION_LIBRARY}
	${GMODULE2_LIBRARIES}
	${GLIB2_LIBRARIES}
	${GCRYPT_LIBRARIES}
	${ZLIB_LIBRARIES}
	${WIN_WSOCK32_LIBRARY}
)
IF(WIN32)
	set(wsutil_LIBS ${wsutil_LIBS} "ws2_32.lib")
ENDIF(WIN32)

set(CLEAN_FILES
	${WSUTIL_FILES}
)

if (WERROR_COMMON_FLAGS)
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS ${WERROR_COMMON_FLAGS}
	)
else()
	#
	# Set the property to an empty string, so that if we try
	# to get it below, it succeeds.
	#
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS ""
	)
endif()
if (HAVE_SSE4_2)
	get_source_file_property(
		WS_MEMPBRK_SSE42_COMPILE_FLAGS
		ws_mempbrk_sse42.c
		COMPILE_FLAGS
	)
	set_source_files_properties(
		ws_mempbrk_sse42.c
		PROPERTIES
		COMPILE_FLAGS "${WS_MEMPBRK_SSE42_COMPILE_FLAGS} ${SSE4_2_FLAG}"
	)
endif()

add_library(wsutil ${LINK_MODE_LIB}
	${WSUTIL_FILES}
	${CMAKE_BINARY_DIR}/image/libwsutil.rc
)

set(FULL_SO_VERSION "7.0.0")

set_target_properties(wsutil PROPERTIES
	PREFIX "lib"
	COMPILE_DEFINITIONS "WS_BUILD_DLL"
	LINK_FLAGS "${WS_LINK_FLAGS}"
	VERSION ${FULL_SO_VERSION} SOVERSION 7
	FOLDER "DLLs")

if(ENABLE_APPLICATION_BUNDLE)
	set_target_properties(wsutil PROPERTIES
		LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/run/Wireshark.app/Contents/Frameworks
	)
endif()

ABICHECK(libwsutil)

add_custom_command(OUTPUT libwsutil.abi.tar.gz
	COMMAND ${CMAKE_COMMAND} -E remove_directory ${ABICHECK_TMPDIR}
	COMMAND ${CMAKE_COMMAND} -E make_directory ${ABICHECK_TMPDIR}
	COMMAND ${ABI_COPY_COMMAND} ../config.h ${ABICHECK_TMPDIR}/ ${ABI_COPY_FLAGS}
	COMMAND ${ABI_COPY_COMMAND} ${ABICHECK_HEADERS} ${ABICHECK_TMPDIR}/ ${ABI_COPY_FLAGS}
	COMMAND ${ABICHECK_COMMAND}
	COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/abi_dumps/libwsutil/libwsutil_* ${CMAKE_CURRENT_BINARY_DIR}/libwsutil.abi.tar.gz
	COMMAND rm -rf ${ABICHECK_TMPDIR} ${CMAKE_CURRENT_BINARY_DIR}/abi_dumps
	DEPENDS ${HEADERS} wsutil)

target_link_libraries(wsutil ${wsutil_LIBS})

if(NOT ${ENABLE_STATIC})
	install(TARGETS wsutil
		LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
		RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}
		ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	)
endif()

add_definitions( -DTOP_SRCDIR=\"${CMAKE_SOURCE_DIR}\" )

CHECKAPI(
	NAME
	  wsutil
	SWITCHES
	  -g termoutput -build
	SOURCES
	  ${WSUTIL_COMMON_FILES}
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
