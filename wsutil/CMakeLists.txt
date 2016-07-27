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

IF(WIN32)
  set(WSUTIL_PLATFORM_FILES
    file_util.c
    inet_aton.c
    inet_ntop.c
    inet_pton.c
    strptime.c
  )
ENDIF(WIN32)

set(WSUTIL_FILES
  adler32.c
  aes.c
  airpdcap_wep.c
  base64.c
  bitswap.c
  buffer.c
  crash_info.c
  crc10.c
  crc16.c
  crc16-plain.c
  crc32.c
  crc6.c
  crc7.c
  crc8.c
  crc11.c
  crcdrm.c
  des.c
  eax.c
  filesystem.c
  g711.c
  md4.c
  md5.c
  mpeg-audio.c
  nstime.c
  plugins.c
  privileges.c
  sha1.c
  strnatcmp.c
  str_util.c
  rc4.c
  report_err.c
  tempfile.c
  time_util.c
  type_util.c
  u3.c
  unicode-utils.c
  ${WSUTIL_PLATFORM_FILES}
)

if(NOT HAVE_GETOPT_LONG)
	set(WSUTIL_FILES ${WSUTIL_FILES} wsgetopt.c)
endif()

set(wsutil_LIBS
  ${GMODULE2_LIBRARIES}
  ${GLIB2_LIBRARIES}
  ${GCRYPT_LIBRARIES}
  ${WIN_WSOCK32_LIBRARY}
)
IF(WIN32)
  set(wsutil_LIBS ${wsutil_LIBS} "ws2_32.lib")
ENDIF(WIN32)

set(CLEAN_FILES
  ${WSUTIL_FILES}
)

if (WERROR)
  set_source_files_properties(
    ${CLEAN_FILES}
    PROPERTIES
    COMPILE_FLAGS -Werror
  )
endif()

add_library(wsutil ${LINK_MODE_LIB}
  ${WSUTIL_FILES}
)

set(FULL_SO_VERSION "5.1.0")

set_target_properties(wsutil PROPERTIES COMPILE_DEFINITIONS "WS_BUILD_DLL")
set_target_properties(wsutil PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")
set_target_properties(wsutil PROPERTIES VERSION ${FULL_SO_VERSION} SOVERSION 4)
set_target_properties(wsutil PROPERTIES FOLDER "DLLs")

ABICHECK(libwsutil)

add_custom_command(OUTPUT libwsutil.abi.tar.gz
	COMMAND cp ../config.h ${ABICHECK_TMPDIR}/
	COMMAND ${ABICHECK_COMMAND}
	COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/abi_dumps/libwsutil/libwsutil_* ${CMAKE_CURRENT_BINARY_DIR}/libwsutil.abi.tar.gz
	COMMAND rm -rf ${ABICHECK_TMPDIR}/* ${CMAKE_CURRENT_BINARY_DIR}/abi_dumps
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
