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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

IF(WIN32)
  set(WSUTIL_PLATFORM_FILES
    file_util.c
    unicode-utils.c
  )
ENDIF(WIN32)

set(WSUTIL_FILES
#		@GETOPT_LO@	# wsgetopt.c
#		@INET_ATON_LO@	# inet_aton.c
#		@INET_NTOP_LO@	# inet_ntop.c
#		@INET_PTON_LO@	# inet_pton.c
#		@STRNCASECMP_LO@ # strncasecmp.c
#		@STRPTIME_LO@	# strptime.c
  airpdcap_wep.c
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
  mpeg-audio.c
  privileges.c
  str_util.c
  type_util.c
  ${WSUTIL_PLATFORM_FILES}
)

set(wsutil_LIBS
  ${GLIB2_LIBRARIES}
)

add_library(wsutil ${LINK_MODE_LIB}
  ${WSUTIL_FILES}
)

set(FULL_SO_VERSION "3.0.0")

set_target_properties(wsutil PROPERTIES COMPILE_DEFINITIONS "WS_BUILD_DLL")
set_target_properties(wsutil PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")
set_target_properties(wsutil PROPERTIES VERSION ${FULL_SO_VERSION} SOVERSION 3)

# discover and substitute list of include directories for ABI compatibility
# checks
get_directory_property(INCLUDE_DIRS INCLUDE_DIRECTORIES)
list(REMOVE_DUPLICATES INCLUDE_DIRS)
string(REGEX REPLACE ";" "\n" INCLUDE_DIRS "${INCLUDE_DIRS}")
configure_file(../abi-descriptor.template abi-descriptor.xml)

# ABI compliance checker can be obtained from
# http://ispras.linux-foundation.org/index.php/ABI_compliance_checker
# Checked using version 1.21.12
file(GLOB HEADERS *.h)
file(MAKE_DIRECTORY abi-check-headers)

file(COPY ${HEADERS} ../ws_symbol_export.h DESTINATION abi-check-headers)

add_custom_command(OUTPUT libwsutil.abi.tar.gz
	COMMAND cp ../config.h abi-check-headers/
	COMMAND abi-compliance-checker -l libwsutil -v1 ${FULL_SO_VERSION}
		-relpath ${CMAKE_CURRENT_BINARY_DIR} -dump-abi abi-descriptor.xml
		|| cat logs/libwsutil/[0-9]*/log.txt
	COMMAND cp abi_dumps/libwsutil/libwsutil_* libwsutil.abi.tar.gz
	COMMAND rm -rf abi-check-headers/* abi_dumps
	DEPENDS ${HEADERS} wsutil)
add_custom_target(dumpabi-libwsutil DEPENDS libwsutil.abi.tar.gz)

target_link_libraries(wsutil ${wsutil_LIBS})

if(NOT ${ENABLE_STATIC})
	install(TARGETS wsutil
		LIBRARY DESTINATION lib
		RUNTIME DESTINATION lib
		ARCHIVE DESTINATION lib
	)
endif()

