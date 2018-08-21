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

find_package(PkgConfig REQUIRED)

pkg_check_modules(WIRESHARK REQUIRED wireshark>=2.5)
### CMake Bug: Use PKG_CONFIG_PATH instead of CMAKE_PREFIX_PATH
# https://gitlab.kitware.com/cmake/cmake/issues/15805
### CMake Bug: If you run into problems please use the "Unix Makefiles" generator.
### Ninja just wipes the pkg-config variables.
# https://gitlab.kitware.com/cmake/cmake/issues/17531 (and probably others)
pkg_get_variable(WIRESHARK_VERSION_RELEASE wireshark VERSION_RELEASE)
pkg_get_variable(WIRESHARK_PLUGIN_DIR wireshark plugindir)

set(PLUGIN_INSTALL_LIBDIR "${WIRESHARK_PLUGIN_DIR}/epan")

include(CMakePushCheckState)
include(CheckFunctionExists)

cmake_push_check_state()
set(CMAKE_REQUIRED_LIBRARIES ${WIRESHARK_LDFLAGS})
check_function_exists("proto_register_plugin" HAVE_PROTO_REGISTER_PLUGIN)
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
target_link_libraries(hello ${WIRESHARK_LDFLAGS})
target_compile_options(hello PUBLIC ${WIRESHARK_CFLAGS})

install(TARGETS hello
	LIBRARY DESTINATION "${PLUGIN_INSTALL_LIBDIR}" NAMELINK_SKIP
)
