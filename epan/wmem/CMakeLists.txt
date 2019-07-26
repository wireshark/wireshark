# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

set(WMEM_HEADER_FILES
	${WMEM_PUBLIC_HEADERS}
	wmem_allocator.h
	wmem_allocator_block.h
	wmem_allocator_block_fast.h
	wmem_allocator_simple.h
	wmem_allocator_strict.h
	wmem_interval_tree.h
	wmem_map_int.h
	wmem_tree-int.h
	wmem_user_cb_int.h
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
	#Included so that Visual Studio can properly put header files in solution
	${WMEM_HEADER_FILES}

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
	EXCLUDE_FROM_DEFAULT_BUILD True
	COMPILE_DEFINITIONS "WS_BUILD_DLL"
)

install(FILES ${WMEM_PUBLIC_HEADERS}
	DESTINATION "${PROJECT_INSTALL_INCLUDEDIR}/epan/wmem"
)

CHECKAPI(
	NAME
	  wmem
	SWITCHES
	  --group termoutput:1 --summary-group termoutput
	  --build
	SOURCES
	  ${WMEM_FILES}
)

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
