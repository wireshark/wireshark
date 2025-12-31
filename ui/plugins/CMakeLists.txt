# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

set(UIPLUGINS_PUBLIC_HEADERS
	include/uiqt_plugin.h
)

set(UIPLUGINS_HEADER_FILES
	${UIPLUGINS_PUBLIC_HEADERS}
)

set(UIPLUGINS_FILES
	uiqt_plugin.c
)

set_source_files_properties(
	${UIPLUGINS_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

add_library(uiqt_plugin
	${UIPLUGINS_FILES}
)

if(NOT VCSVERSION_OVERRIDE)
	add_dependencies(uiqt_plugin vcs_version)
endif()

target_compile_definitions(uiqt_plugin PRIVATE
	WS_BUILD_DLL
)

set_target_properties(uiqt_plugin PROPERTIES
	PREFIX "lib"
	LINK_FLAGS "${WS_LINK_FLAGS}"
	VERSION "0.0.0" SOVERSION 0
	FOLDER "DLLs"
	INSTALL_RPATH "${LIBRARY_INSTALL_RPATH}"
)
if(MSVC)
	set_target_properties(uiqt_plugin PROPERTIES LINK_FLAGS_DEBUG "${WS_MSVC_DEBUG_LINK_FLAGS}")
endif()

target_link_libraries(uiqt_plugin wsutil ${GLIB2_LIBRARIES})

install(TARGETS uiqt_plugin
	EXPORT WiresharkTargets
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(FILES ${UIPLUGINS_PUBLIC_HEADERS}
	DESTINATION "${PROJECT_INSTALL_INCLUDEDIR}/uiqt"
	COMPONENT "Development"
	EXCLUDE_FROM_ALL
)

CHECKAPI(
	NAME
	  uiqt_plugin
	SWITCHES
	SOURCES
	  ${UIPLUGINS_FILES}
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
