# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

add_subdirectory(lemon)

add_executable(make-dissectors make-dissectors.c make-lib.c)
target_link_libraries(make-dissectors ${GLIB2_LIBRARIES})
if(WIN32)
	add_dependencies(make-dissectors copy_cli_dlls)
endif()

add_executable(make-taps make-taps.c make-lib.c)
target_link_libraries(make-taps ${GLIB2_LIBRARIES})

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
