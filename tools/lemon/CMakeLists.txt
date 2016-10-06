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

set(lemon_FILES
	lemon.c
)

set(CLEAN_FILES
	${lemon_FILES}
)

set_source_files_properties(
	${CLEAN_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS} ${NO_SANITIZE_CFLAGS}"
)

set(lemon_LIBS
	# Do we need something here on any platform?
)

add_executable(lemon ${lemon_FILES})
set_target_properties(lemon PROPERTIES FOLDER "tools")
set_target_properties(lemon PROPERTIES COMPILE_OPTIONS "${WS_WARNINGS_C_FLAGS}")
set_target_properties(lemon PROPERTIES LINK_FLAGS "${NO_SANITIZE_LDFLAGS}")

target_link_libraries(lemon ${lemon_LIBS})

#
# Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
