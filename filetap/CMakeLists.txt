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

set(CLEAN_FILES
	buffer.c
	file_access.c
	ft_file_wrappers.c
	ftap.c
)

set(DIRTY_FILES
)

set(FILETAP_FILES
	${CLEAN_FILES}
	${DIRTY_FILES}
)

if (WERROR)
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS -Werror
	)
endif()

set(filetap_LIBS
	${GLIB2_LIBRARIES}
	${GMODULE2_LIBRARIES}
	${ZLIB_LIBRARIES}
	wsutil
)

add_library(filetap ${LINK_MODE_LIB}
	${FILETAP_FILES}
	../image/filetap.rc
)

set(FULL_SO_VERSION "0.0.0")

set_target_properties(filetap PROPERTIES COMPILE_DEFINITIONS "WS_BUILD_DLL")
set_target_properties(filetap PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")
set_target_properties(filetap PROPERTIES VERSION ${FULL_SO_VERSION} SOVERSION 0)
set_target_properties(filetap PROPERTIES FOLDER "DLLs")

ABICHECK(libfiletap)

add_custom_command(OUTPUT libfiletap.abi.tar.gz
	COMMAND cp ../config.h ${ABICHECK_TMPDIR}/
	COMMAND ${ABICHECK_COMMAND}
	COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/abi_dumps/libfiletap/libfiletap_* ${CMAKE_CURRENT_BINARY_DIR}/libfiletap.abi.tar.gz
	COMMAND rm -rf ${ABICHECK_TMPDIR}/* ${CMAKE_CURRENT_BINARY_DIR}/abi_dumps
	DEPENDS ${HEADERS} filetap)

target_link_libraries(filetap ${filetap_LIBS})

if(NOT ${ENABLE_STATIC})
	install(TARGETS filetap
		LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
		RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}
		ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	)
endif()

