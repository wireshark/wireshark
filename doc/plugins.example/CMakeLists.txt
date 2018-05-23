# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

cmake_minimum_required(VERSION 3.1)
cmake_policy(SET CMP0048 NEW)

project(Hello VERSION 0.0.1 DESCRIPTION "Wireshark Hello Plugin" LANGUAGES C)

option(SYSTEM_INSTALLATION "Install to system plugin directory" ON)

find_package(PkgConfig REQUIRED)

pkg_check_modules(WIRESHARK REQUIRED wireshark>=2.5)
pkg_get_variable(WIRESHARK_VERSION_RELEASE wireshark VERSION_RELEASE)
pkg_get_variable(WIRESHARK_PLUGIN_DIR wireshark plugindir)

include(CMakePushCheckState)
include(CheckSymbolExists)

cmake_push_check_state()
set(CMAKE_REQUIRED_INCLUDES ${WIRESHARK_INCLUDE_DIRS})
set(CMAKE_REQUIRED_LIBRARIES ${WIRESHARK_LIBRARIES})
set(CMAKE_REQUIRED_DEFINITIONS -DHAVE_PLUGINS)
check_symbol_exists("proto_register_plugin" "epan/proto.h" HAVE_PROTO_REGISTER_PLUGIN)
cmake_pop_check_state()
if(NOT HAVE_PROTO_REGISTER_PLUGIN)
	message(FATAL_ERROR "Wireshark was compiled without support for plugins")
endif()

set(CMAKE_C_VISIBILITY_PRESET hidden)
if (CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS  "-Wall -Wextra ${CMAKE_C_FLAGS}")
endif()

add_definitions(-DHAVE_PLUGINS -DVERSION=\"${PROJECT_VERSION}\" -DVERSION_RELEASE=\"${WIRESHARK_VERSION_RELEASE}\")

add_library(hello MODULE hello.c)
set_target_properties(hello PROPERTIES PREFIX "" DEFINE_SYMBOL "")
target_link_libraries(hello ${WIRESHARK_LIBRARIES})
target_compile_options(hello PUBLIC ${WIRESHARK_CFLAGS})

if(SYSTEM_INSTALLATION)
	set(PLUGIN_INSTALL_LIBDIR "${WIRESHARK_PLUGIN_DIR}/epan")
else()
	set(PLUGIN_INSTALL_LIBDIR "$ENV{HOME}/.local/lib/wireshark/plugins/${WIRESHARK_VERSION_RELEASE}/epan")
endif()

install(TARGETS hello
		LIBRARY DESTINATION ${PLUGIN_INSTALL_LIBDIR} NAMELINK_SKIP
)
