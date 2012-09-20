# CMakeLists.txt
#
# $Id: CMakeLists.txt 30460 2009-10-10 05:35:21Z krj $
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

set(lemon_FILES
	lemon.c
)

set(CLEAN_FILES
	${lemon_FILES}
)

if (WERROR)
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS -Werror
	)
endif()

set(lemon_LIBS
	# Do we need something here on any platform?
)

if(CMAKE_COMPILER_IS_GNUCC)
	add_definitions(-D_U_=__attribute__\(\(unused\)\))
else()
	add_definitions(-D_U_=)
endif()

add_executable(lemon ${lemon_FILES})

target_link_libraries(lemon ${lemon_LIBS})
