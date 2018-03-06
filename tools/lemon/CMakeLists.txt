# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

set(lemon_FILES
	lemon.c
)

set_source_files_properties(
	${lemon_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS} ${NO_SANITIZE_CFLAGS}"
)

set(lemon_LIBS
	# Do we need something here on any platform?
)

add_executable(lemon ${lemon_FILES})

set_target_properties(lemon PROPERTIES
	FOLDER "tools"
	LINK_FLAGS "${NO_SANITIZE_LDFLAGS}"
)

target_link_libraries(lemon ${lemon_LIBS})

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
