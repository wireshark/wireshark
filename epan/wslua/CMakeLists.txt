# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

add_subdirectory(lrexlib)

set(WSLUA_MODULES
	${CMAKE_CURRENT_SOURCE_DIR}/lua_bitop.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_address.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_byte_array.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_capture_info.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_column.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_dir.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_dissector.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_dumper.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_field.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_file.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_file_common.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_file_handler.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_frame_info.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_gui.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_int64.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_internals.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_listener.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_nstime.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_pinfo.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_pref.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_proto.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_proto_expert.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_proto_field.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_struct.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_tree.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_tvb.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_util.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_wtap.c
)

set(WSLUA_FILES
	${WSLUA_MODULES}
	${CMAKE_CURRENT_BINARY_DIR}/taps_wslua.c
	${CMAKE_CURRENT_BINARY_DIR}/register_wslua.c
	${CMAKE_CURRENT_SOURCE_DIR}/init_wslua.c
)
source_group(wslua FILES ${WSLUA_FILES})

set_source_files_properties(
	${WSLUA_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

# make-taps.pl depends on the current working directory
# to find the dissector files (contents of taps file
# depend on this actually, so just changing the paths
# in these lists won't help).

# Used with untypical CWD
set(WSLUA_TAPS_USED
	${CMAKE_SOURCE_DIR}/epan/dissectors/packet-http.h
	${CMAKE_SOURCE_DIR}/epan/dissectors/packet-ip.h
	${CMAKE_SOURCE_DIR}/epan/dissectors/packet-udp.h
	${CMAKE_SOURCE_DIR}/epan/dissectors/packet-h225.h
	${CMAKE_SOURCE_DIR}/epan/dissectors/packet-ieee80211.h
)

add_custom_command(
	OUTPUT
		${CMAKE_BINARY_DIR}/epan/wslua/taps_wslua.c
		${CMAKE_BINARY_DIR}/epan/wslua/taps.txt
	COMMAND
		${PERL_EXECUTABLE}
		${CMAKE_SOURCE_DIR}/epan/wslua/make-taps.pl
		${CMAKE_SOURCE_DIR}/epan/wslua/taps
		${CMAKE_BINARY_DIR}/epan/wslua/taps_wslua.c
		${CMAKE_BINARY_DIR}/epan/wslua/taps.txt
		${CMAKE_SOURCE_DIR}/epan/wslua
	DEPENDS
		${CMAKE_SOURCE_DIR}/epan/wslua/taps
		${CMAKE_SOURCE_DIR}/epan/wslua/make-taps.pl
		# Only here to add dependencies for the taps "source"files
		${WSLUA_TAPS_USED}
)


add_custom_command(
	OUTPUT
		${CMAKE_BINARY_DIR}/epan/wslua/declare_wslua.h
		${CMAKE_BINARY_DIR}/epan/wslua/register_wslua.c
	COMMAND
		${PYTHON_EXECUTABLE}
		${CMAKE_SOURCE_DIR}/epan/wslua/make-reg.py
		${WSLUA_MODULES}
	WORKING_DIRECTORY
		${CMAKE_BINARY_DIR}/epan/wslua
	DEPENDS
		${CMAKE_SOURCE_DIR}/epan/wslua/make-reg.py
		${WSLUA_MODULES}
		# ${CMAKE_CURRENT_BINARY_DIR}/taps_wslua.c
)

add_custom_command(
	OUTPUT init.lua
	COMMAND ${PERL_EXECUTABLE}
		${CMAKE_CURRENT_SOURCE_DIR}/make-init-lua.pl
		${CMAKE_SOURCE_DIR}
		${CMAKE_CURRENT_SOURCE_DIR}/template-init.lua
		> init.lua
	DEPENDS
		${CMAKE_CURRENT_SOURCE_DIR}/make-init-lua.pl
		${CMAKE_CURRENT_SOURCE_DIR}/template-init.lua
		${CMAKE_SOURCE_DIR}/epan/ftypes/ftypes.h
		${CMAKE_SOURCE_DIR}/wiretap/wtap.h
		${CMAKE_SOURCE_DIR}/epan/epan.h
		${CMAKE_SOURCE_DIR}/epan/stat_groups.h
)

add_custom_target(
	wsluaauxiliary ALL
	DEPENDS
		init.lua
)

set_target_properties(wsluaauxiliary PROPERTIES FOLDER "Auxiliary")

install(
	FILES
		console.lua
		dtd_gen.lua
		${CMAKE_CURRENT_BINARY_DIR}/init.lua
	DESTINATION
		${CMAKE_INSTALL_DATADIR}
)

add_library(wslua OBJECT
	${WSLUA_FILES}
)

target_include_directories(wslua
	SYSTEM PRIVATE
		${LUA_INCLUDE_DIRS}
	PRIVATE
		${CMAKE_CURRENT_BINARY_DIR}
		${CMAKE_CURRENT_SOURCE_DIR}
)

set_target_properties(wslua PROPERTIES
	FOLDER "Libs/epan/wslua"
	COMPILE_DEFINITIONS "WS_BUILD_DLL"
)

CHECKAPI(
	NAME
	  wslua
	SWITCHES
	SOURCES
	  ${WSLUA_FILES}
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
