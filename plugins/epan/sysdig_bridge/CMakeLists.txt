# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

include(WiresharkPlugin)

# Plugin name and version info (major minor micro extra)
set_module_info(sysdig-plugins 0 0 4 0)

set(DISSECTOR_SRC
	packet-sysdig-bridge.c
	sinsp-span.cpp
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
)

set_source_files_properties(
	${PLUGIN_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

register_plugin_files(plugin.c
	plugin
	${DISSECTOR_SRC}
)

add_plugin_library(sysdig-plugins epan)

find_package(Sinsp REQUIRED)

# XXX Hacks; need to fix in falcosecurity-libs.
target_compile_definitions(sysdig-plugins PRIVATE
	HAVE_STRLCPY=1
	)
# target_compile_options(sysdig-plugins PRIVATE -Wno-address-of-packed-member)

target_include_directories(sysdig-plugins SYSTEM PRIVATE
	${SINSP_INCLUDE_DIRS}
)

target_link_libraries(sysdig-plugins
	epan
	${SINSP_LIBRARIES}
)

install_plugin(sysdig-plugins epan)

file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
CHECKAPI(
	NAME
	  sysdig-plugins
	SWITCHES
	  --group dissectors-prohibited
	  --group dissectors-restricted
	SOURCES
	  ${DISSECTOR_SRC}
	  ${DISSECTOR_HEADERS}
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
