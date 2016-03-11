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

include_directories(
	${CMAKE_CURRENT_BINARY_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}
)

set(DFILTER_FILES
	dfilter.c
	dfilter-macro.c
	dfunctions.c
	dfvm.c
	drange.c
	gencode.c
	semcheck.c
	sttype-function.c
	sttype-integer.c
	sttype-pointer.c
	sttype-range.c
	sttype-set.c
	sttype-string.c
	sttype-test.c
	syntax-tree.c
)
source_group(dfilter FILES ${DFILTER_FILES})

if(WERROR_COMMON_FLAGS)
	set_source_files_properties(
		${DFILTER_FILES}
		PROPERTIES
		COMPILE_FLAGS ${WERROR_COMMON_FLAGS}
	)
endif()

add_lex_files(LEX_FILES GENERATED_FILES
	scanner.l
)

add_lemon_files(LEMON_FILES GENERATED_FILES
	grammar.lemon
)

add_library(dfilter OBJECT
	${DFILTER_FILES}
	${GENERATED_FILES}
)

set_target_properties(dfilter PROPERTIES
	FOLDER "Libs/epan/dfilter"
	COMPILE_DEFINITIONS "WS_BUILD_DLL"
)

CHECKAPI(
	NAME
	  dfilter
	SWITCHES
	  -g termoutput -build
	SOURCES
	  ${DFILTER_FILES}
# LEX files commented out due to use of malloc, free etc.
#	  ${LEX_FILES}
	  ${LEMON_FILES}
)

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
