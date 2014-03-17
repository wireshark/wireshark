# CMakeLists.txt
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

# This file is to be included/run from epan/CMakeLists.txt

set(WSLUA_MODULES
	${CMAKE_CURRENT_SOURCE_DIR}/wslua/lua_bitop.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua/lrexlib.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua/lrexlib_glib.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua/lrexlib_glib_f.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua/wslua_int64.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua/wslua_tvb.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua/wslua_proto.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua/wslua_tree.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua/wslua_pinfo.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua/wslua_listener.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua/wslua_gui.c
  ${CMAKE_CURRENT_SOURCE_DIR}/wslua/wslua_dir.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua/wslua_util.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua/wslua_field.c
  ${CMAKE_CURRENT_SOURCE_DIR}/wslua/wslua_file.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua/wslua_struct.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua/wslua_dumper.c
	${CMAKE_CURRENT_SOURCE_DIR}/wslua/wslua_internals.c
)

set(WSLUA_FILES
	${WSLUA_MODULES}
	taps_wslua.c
	register_wslua.c
	wslua/init_wslua.c
)

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
      ${CMAKE_CURRENT_SOURCE_DIR}/wslua/make-taps.pl
      ${CMAKE_CURRENT_SOURCE_DIR}/wslua/taps
      ${CMAKE_CURRENT_BINARY_DIR}/taps_wslua.c
      ${CMAKE_CURRENT_BINARY_DIR}/taps.txt
    WORKING_DIRECTORY
      ${CMAKE_CURRENT_SOURCE_DIR}/wslua
    DEPENDS
      ${CMAKE_CURRENT_SOURCE_DIR}/wslua/taps
      ${CMAKE_CURRENT_SOURCE_DIR}/wslua/make-taps.pl
      # Only here to add dependencies for the taps "source"files
      ${WSLUA_TAPS_USED}
)

ADD_CUSTOM_COMMAND(
    OUTPUT
      declare_wslua.h
      register_wslua.c
    COMMAND ${PERL_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/wslua/make-reg.pl
      ${WSLUA_MODULES}
    DEPENDS
      ${CMAKE_CURRENT_SOURCE_DIR}/wslua/make-reg.pl
      ${WSLUA_MODULES}
      # ${CMAKE_CURRENT_BINARY_DIR}/taps_wslua.c
)

ADD_CUSTOM_COMMAND(
    OUTPUT init.lua
    COMMAND ${PERL_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/wslua/make-init-lua.pl
      ${CMAKE_SOURCE_DIR}
      ${CMAKE_CURRENT_SOURCE_DIR}/wslua/template-init.lua
      > init.lua
    DEPENDS
      ${CMAKE_CURRENT_SOURCE_DIR}/wslua/make-init-lua.pl
      ${CMAKE_CURRENT_SOURCE_DIR}/wslua/template-init.lua
      ${CMAKE_SOURCE_DIR}/epan/ftypes/ftypes.h
      ${CMAKE_SOURCE_DIR}/wiretap/wtap.h
      ${CMAKE_SOURCE_DIR}/epan/epan.h
      ${CMAKE_SOURCE_DIR}/stat_menu.h
)

add_custom_target(
     wsluaauxiliary ALL
     DEPENDS
	init.lua
)
set_target_properties(wsluaauxiliary PROPERTIES FOLDER "Auxiliary")

install(
    FILES
	wslua/console.lua
	wslua/dtd_gen.lua
	${CMAKE_CURRENT_BINARY_DIR}/init.lua
    DESTINATION
	${CMAKE_INSTALL_DATADIR}/${CPACK_PACKAGE_NAME}
)

