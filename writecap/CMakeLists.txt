# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

set(WRITECAP_SRC
	pcapio.c
)

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
		${WIN_WS2_32_LIBRARY}
		wsutil
)
