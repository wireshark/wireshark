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
set_module_info(pluginifdemo 0 0 1 0)

SET(CMAKE_AUTOMOC ON)
SET(CMAKE_AUTOUIC ON)

find_package(Qt5Core)
find_package(Qt5PrintSupport)
find_package(Qt5Widgets)

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
	${PLUGIN_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

include_directories( ui ${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

register_plugin_files(plugin.c
	plugin
	${DISSECTOR_SRC}
)

add_plugin_library(pluginifdemo epan)

target_link_libraries(pluginifdemo epan Qt5::Core Qt5::Widgets Qt5::PrintSupport)

install_plugin(pluginifdemo epan)

file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
CHECKAPI(
	NAME
	  pluginifdemo
	SWITCHES
	  -g abort -g termoutput -build
	SOURCES
	  ${DISSECTOR_SRC}
	  ${DISSECTOR_HEADERS}
)
