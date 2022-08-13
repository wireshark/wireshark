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
set_module_info(pluginifdemo 0 0 2 0)

SET(CMAKE_AUTOMOC ON)
SET(CMAKE_AUTOUIC ON)

find_package(Qt6Core)
find_package(Qt6PrintSupport)
find_package(Qt6Widgets)

set(DISSECTOR_SRC
	pluginifdemo.c
	ui/uihandler.cpp
	ui/uiclasshandler.cpp
	ui/pluginifdemo_main.cpp
	ui/pluginifdemo_about.cpp
	${UI_SRC}
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
)

set_source_files_properties(
	plugin.c
	PROPERTIES
	SKIP_AUTOGEN ON
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

add_wireshark_plugin_library(pluginifdemo epan)

target_link_libraries(pluginifdemo epan Qt6::Core Qt6::Widgets Qt6::PrintSupport)

install_plugin(pluginifdemo epan)

file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
CHECKAPI(
	NAME
	  pluginifdemo
	SWITCHES
	  --group dissectors-prohibited
	  --group dissectors-restricted
	SOURCES
	  ${DISSECTOR_SRC}
	  ${DISSECTOR_HEADERS}
)
