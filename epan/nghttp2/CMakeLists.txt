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

set(NGHTTP2_FILES
	nghttp2_buf.c
	nghttp2_hd.c
	nghttp2_hd_huffman.c
	nghttp2_hd_huffman_data.c
	nghttp2_helper.c
	nghttp2_mem.c
	nghttp2_rcbuf.c
)
source_group(nghttp2 FILES ${NGHTTP2_FILES})

if(WERROR_COMMON_FLAGS)
	set_source_files_properties(
		${NGHTTP2_FILES}
		PROPERTIES
		COMPILE_FLAGS ${WERROR_COMMON_FLAGS}
	)
endif()

add_library(nghttp2 OBJECT
	${NGHTTP2_FILES}
)

set_target_properties(nghttp2 PROPERTIES
	FOLDER "Libs/epan/nghttp2"
	COMPILE_DEFINITIONS "WS_BUILD_DLL"
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
