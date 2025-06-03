# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

set(WRITECAP_SRC
	${CMAKE_SOURCE_DIR}/wiretap/file_wrappers.c
	pcapio.c
)

if(WIN32)
	list(APPEND WRITECAP_SRC
		${CMAKE_SOURCE_DIR}/wsutil/file_util.c
	)
endif()

set_source_files_properties(
	${WRITECAP_SRC}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)


add_library(writecap STATIC
	${WRITECAP_SRC}
)

set_target_properties(writecap PROPERTIES
	LINK_FLAGS "${WS_LINK_FLAGS}"
	FOLDER "Libs"
)

target_compile_definitions(writecap
	PRIVATE
		# Necessary to avoid C4273 inconsistent DLL linkage on MSVC
		ENABLE_STATIC
)

target_link_libraries(writecap
	PRIVATE
		${GMODULE2_LIBRARIES}
		${LZ4_LIBRARIES}
		${ZLIB_LIBRARIES}
		${ZLIBNG_LIBRARIES}
		${ZSTD_LIBRARIES}
		${WIN_WS2_32_LIBRARY}
)

target_include_directories(writecap SYSTEM
	PRIVATE
		${LZ4_INCLUDE_DIRS}
		${ZLIB_INCLUDE_DIRS}
		${ZLIBNG_INCLUDE_DIRS}
		${ZSTD_INCLUDE_DIRS}
)
