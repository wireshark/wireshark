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


set(WSLUA_MODULES
	lua_bitop.c
	wslua_tvb.c
	wslua_proto.c
	wslua_tree.c
	wslua_pinfo.c
	wslua_listener.c
	wslua_gui.c
	wslua_util.c
	wslua_field.c
	wslua_dumper.c
)

set(WSLUA_FILES
	${WSLUA_MODULES}
	${CMAKE_CURRENT_BINARY_DIR}/taps_wslua.c
	register_wslua.c
	${CMAKE_CURRENT_SOURCE_DIR}/init_wslua.c
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
# depend on this actually).
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
      ${CMAKE_CURRENT_BINARY_DIR}/taps_wslua.c
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

add_library(wslua STATIC
	${WSLUA_FILES}
)

