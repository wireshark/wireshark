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

set(PLUGIN_FILES
	http-parser.c
	packet-http.c
)

set(CLEAN_FILES
	${PLUGIN_FILES}
)

if (WERROR)
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS -Werror
	)
endif()

include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(_tpg ${CMAKE_SOURCE_DIR}/tools/tpg)

ADD_CUSTOM_COMMAND(
    OUTPUT
	TPG.pm
    COMMAND ${YAPP_EXECUTABLE}
	-v
	-m TPG
	${_tpg}/tpg.yp
    DEPENDS
	${_tpg}/tpg.yp
)

ADD_CUSTOM_COMMAND(
    OUTPUT
      http-parser.h
      http-parser.c
    COMMAND ${PERL_EXECUTABLE}
      -I${CMAKE_BINARY_DIR}
      -I${_tpg}
      ${_tpg}/tpg.pl
      ${CMAKE_CURRENT_SOURCE_DIR}/http.tpg
    DEPENDS
      ${_tpg}/tpg.pl
      TPG.pm
      ${_tpg}/V2P.pm
      ${CMAKE_CURRENT_SOURCE_DIR}/http.tpg
)

add_library(tpg ${LINK_MODE_MODULE}
	${PLUGIN_FILES}
	plugin.rc
)
set_target_properties(tpg PROPERTIES PREFIX "")
set_target_properties(tpg PROPERTIES LINK_FLAGS ${WS_LINK_FLAGS})
set_target_properties(tpg PROPERTIES FOLDER "Plugins")

target_link_libraries(tpg epan)

install(TARGETS tpg
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION} NAMELINK_SKIP
	RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION}
)

