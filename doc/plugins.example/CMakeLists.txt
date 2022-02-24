# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

cmake_minimum_required(VERSION 3.12)
cmake_policy(SET CMP0048 NEW)

project(Hello VERSION 0.0.1 DESCRIPTION "Wireshark Hello Plugin" LANGUAGES C)

find_package(Wireshark CONFIG REQUIRED)

if(NOT Wireshark_PLUGINS_ENABLED)
	message(WARNING "Wireshark was compiled without support for plugins")
endif()

include(CheckTypeSize)
check_type_size("ssize_t" SSIZE_T)

set(CMAKE_C_VISIBILITY_PRESET hidden)
if (CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS  "-Wall -Wextra ${CMAKE_C_FLAGS}")
endif()

add_compile_definitions(
	VERSION=\"${PROJECT_VERSION}\"
	$<$<BOOL:${HAVE_SSIZE_T}>:HAVE_SSIZE_T>
)

add_library(hello MODULE hello.c)
set_target_properties(hello PROPERTIES PREFIX "" DEFINE_SYMBOL "")
target_link_libraries(hello epan)

install(TARGETS hello
	LIBRARY DESTINATION "${Wireshark_PLUGIN_INSTALL_DIR}/epan" NAMELINK_SKIP
)
