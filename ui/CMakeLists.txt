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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#


set(COMMON_UI_SRC
	alert_box.c
	export_object.c
	export_object_dicom.c
	export_object_http.c
	export_object_smb.c
	help_url.c
	iface_lists.c
	ssl_key_export.c
	text_import.c
	util.c
)

set(CLEAN_FILES
	${COMMON_UI_SRC}
)

add_lex_files(COMMON_UI_SRC
	text_import_scanner.l
)

if (WERROR)
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS -Werror
	)
endif()


add_library(ui STATIC
	${COMMON_UI_SRC}
)

set_target_properties(ui PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")
