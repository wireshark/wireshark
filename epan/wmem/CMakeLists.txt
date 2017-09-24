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

include_directories(
	${CMAKE_CURRENT_BINARY_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}
)

set(WMEM_PUBLIC_HEADERS
	wmem.h
	wmem_array.h
	wmem_core.h
	wmem_list.h
	wmem_map.h
	wmem_miscutl.h
	wmem_queue.h
	wmem_scopes.h
	wmem_stack.h
	wmem_strbuf.h
	wmem_strutl.h
	wmem_tree.h
	wmem_interval_tree.h
	wmem_user_cb.h
)

set(WMEM_FILES
	wmem_array.c
	wmem_core.c
	wmem_allocator_block.c
	wmem_allocator_block_fast.c
	wmem_allocator_simple.c
	wmem_allocator_strict.c
	wmem_interval_tree.c
	wmem_list.c
	wmem_map.c
	wmem_miscutl.c
	wmem_scopes.c
	wmem_stack.c
	wmem_strbuf.c
	wmem_strutl.c
	wmem_tree.c
	wmem_user_cb.c
)
source_group(wmem FILES ${WMEM_FILES})

set_source_files_properties(
	${WMEM_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

add_library(wmem OBJECT
	${WMEM_FILES}
)

set_target_properties(wmem PROPERTIES
	FOLDER "Libs/epan/wmem"
	COMPILE_DEFINITIONS "WS_BUILD_DLL"
)

add_executable(wmem_test EXCLUDE_FROM_ALL wmem_test.c $<TARGET_OBJECTS:wmem>)

target_link_libraries(wmem_test ${GLIB2_LIBRARIES} wsutil)

set_target_properties(wmem_test PROPERTIES
	FOLDER "Tests"
	COMPILE_DEFINITIONS "WS_BUILD_DLL"
)

if(NOT WIN32)
	install(FILES ${WMEM_PUBLIC_HEADERS}
		DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${CPACK_PACKAGE_NAME}/epan/wmem"
	)
endif()

CHECKAPI(
	NAME
	  wmem
	SWITCHES
	  -g termoutput -build
	SOURCES
	  ${WMEM_FILES}
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
