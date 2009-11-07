# CMakeLists.txt
#
# $Id$
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#

include_directories(
	${CMAKE_CURRENT_BINARY_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}
)

set(WSLUA_MODULES
	${CMAKE_CURRENT_SOURCE_DIR}/lua_bitop.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_tvb.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_proto.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_tree.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_pinfo.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_listener.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_gui.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_util.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_field.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua_dumper.c
)

set(WSLUA_FILES
	${WSLUA_MODULES}
	taps_wslua.c
	register_wslua.c
	init_wslua.c
)

set(CLEAN_FILES
	${WSLUA_FILES}
)

if (WERROR)
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS -Werror
	)
endif()

# Used with untypical CWD
set(WSLUA_TAPS_USED
	${CMAKE_SOURCE_DIR}/epan/dissectors/packet-http.h
	${CMAKE_SOURCE_DIR}/epan/dissectors/packet-ip.h
	${CMAKE_SOURCE_DIR}/epan/dissectors/packet-udp.h
	${CMAKE_SOURCE_DIR}/epan/dissectors/packet-h225.h
	${CMAKE_SOURCE_DIR}/epan/dissectors/packet-ieee80211.h
)

# make-taps.pl depends on the current working directory
# to find the dissector files (contents of taps file
# depend on this actually, so just changing the paths
# in these lists won't help).
ADD_CUSTOM_COMMAND(
    OUTPUT
      ${CMAKE_CURRENT_BINARY_DIR}/taps_wslua.c
      ${CMAKE_CURRENT_BINARY_DIR}/taps.txt
    COMMAND ${PERL_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/make-taps.pl
      ${CMAKE_CURRENT_SOURCE_DIR}/taps
      ${CMAKE_CURRENT_BINARY_DIR}/taps_wslua.c
      ${CMAKE_CURRENT_BINARY_DIR}/taps.txt
    WORKING_DIRECTORY
      ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS
      ${CMAKE_CURRENT_SOURCE_DIR}/taps
      ${CMAKE_CURRENT_SOURCE_DIR}/make-taps.pl
      # Only here to add dependencies for the taps "source"files
      ${WSLUA_TAPS_USED}
)

ADD_CUSTOM_COMMAND(
    OUTPUT
      declare_wslua.h
      register_wslua.c
    COMMAND ${PERL_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/make-reg.pl
      ${WSLUA_MODULES}
    DEPENDS
      ${CMAKE_CURRENT_SOURCE_DIR}/make-reg.pl
      ${WSLUA_MODULES}
      # ${CMAKE_CURRENT_BINARY_DIR}/taps_wslua.c
)

ADD_CUSTOM_COMMAND(
    OUTPUT init.lua
    COMMAND ${PERL_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/make-init-lua.pl
      ${CMAKE_CURRENT_SOURCE_DIR}
      ${CMAKE_CURRENT_SOURCE_DIR}/template-init.lua
      > init.lua
    DEPENDS
      ${CMAKE_CURRENT_SOURCE_DIR}/make-init-lua.pl
      ${CMAKE_CURRENT_SOURCE_DIR}/template-init.lua
      ${CMAKE_SOURCE_DIR}/epan/ftypes/ftypes.h
      ${CMAKE_SOURCE_DIR}/wiretap/wtap.h
      ${CMAKE_SOURCE_DIR}/epan/epan.h
      ${CMAKE_SOURCE_DIR}/stat_menu.h
)

set(wslua_LIBS
	${LUA_LIBRARIES}
)

add_library(wslua STATIC
	${WSLUA_FILES}
)

add_custom_target(
     wsluaauxiliary ALL
     DEPENDS
	init.lua
)

target_link_libraries(wslua ${wslua_LIBS})

install(
    FILES
	console.lua
	dtd_gen.lua
	${CMAKE_CURRENT_BINARY_DIR}/init.lua
    DESTINATION
	${CMAKE_INSTALL_DATADIR}/${CPACK_PACKAGE_NAME}
)

