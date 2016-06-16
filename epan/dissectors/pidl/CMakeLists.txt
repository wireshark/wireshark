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

set(PIDL_DISSECTOR_NAMES
	atsvc
	dfs
	dnsserver
	dssetup
	efs
	eventlog
	frsrpc
	frstrans
	initshutdown
	lsa
	mapi
	mdssvc
	misc
	nspi
	rfr
	samr
	#srvsvc
	winreg
	witness
	#wkssvc
	wzcsvc
)

set(PIDL_DISSECTOR_dssetup_EXTRA_DEPS
	misc/misc.idl
)
set(PIDL_DISSECTOR_eventlog_EXTRA_DEPS
	idl_types.h
)
set(PIDL_DISSECTOR_frsrpc_EXTRA_DEPS
	misc/misc.idl
	idl_types.h
)
set(PIDL_DISSECTOR_frstrans_EXTRA_DEPS
	misc/misc.idl
	idl_types.h
)
set(PIDL_DISSECTOR_initshutdown_EXTRA_DEPS
	lsa/lsa.idl
	idl_types.h
)
set(PIDL_DISSECTOR_lsa_EXTRA_DEPS
	idl_types.h
)
set(PIDL_DISSECTOR_mapi_EXTRA_DEPS
	mapi/request.cnf.c
	mapi/response.cnf.c
	idl_types.h
	mapicodes_enum.h
	mapitags_enum.h
)
set(PIDL_DISSECTOR_mdssvc_EXTRA_DEPS
	misc/misc.idl
)
set(PIDL_DISSECTOR_misc_EXTRA_DEPS
	idl_types.h
)
set(PIDL_DISSECTOR_nspi_EXTRA_DEPS
	idl_types.h
	mapicodes_enum.h
	mapitags_enum.h
)
set(PIDL_DISSECTOR_rfr_EXTRA_DEPS
	idl_types.h
	mapicodes_enum.h
)
set(PIDL_DISSECTOR_samr_EXTRA_DEPS
	idl_types.h
)
set(PIDL_DISSECTOR_srvsvc_EXTRA_DEPS
	idl_types.h
)
set(PIDL_DISSECTOR_winreg_EXTRA_DEPS
	misc/misc.idl
)
set(PIDL_DISSECTOR_witness_EXTRA_DEPS
	misc/misc.idl
	idl_types.h
)
set(PIDL_DISSECTOR_wkssvc_EXTRA_DEPS
	lsa/lsa.idl
	srvsvc/srvsvc.idl
	idl_types.h
)

set(PIDL_DISSECTOR_TARGETS)
set(PIDL_DISSECTOR_SRC)
# TODO fix these dissectors, remove this and update PIDL_DISSECTOR_NAMES above.
list(APPEND PIDL_DISSECTOR_SRC
	packet-dcerpc-srvsvc.c
	packet-dcerpc-wkssvc.c
)

foreach(PROTOCOL_NAME IN LISTS PIDL_DISSECTOR_NAMES)
	add_custom_command(
		OUTPUT packet-dcerpc-${PROTOCOL_NAME}-stamp
		COMMAND "${PERL_EXECUTABLE}"
			"${CMAKE_SOURCE_DIR}/tools/pidl/pidl"
			--ws-parser
			--outputdir ../..
			--includedir ..
			--
			${PROTOCOL_NAME}.idl
		COMMAND
			"${CMAKE_COMMAND}" -E touch
			"${CMAKE_CURRENT_BINARY_DIR}/packet-dcerpc-${PROTOCOL_NAME}-stamp"
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/${PROTOCOL_NAME}"
		DEPENDS
			"${CMAKE_SOURCE_DIR}/tools/pidl/pidl"
			${PROTOCOL_NAME}/${PROTOCOL_NAME}.idl
			${PROTOCOL_NAME}/${PROTOCOL_NAME}.cnf
			${PIDL_DISSECTOR_${PROTOCOL_NAME}_EXTRA_DEPS}
		VERBATIM
	)
	add_custom_target(generate_dissector-dcerpc-${PROTOCOL_NAME}
		DEPENDS packet-dcerpc-${PROTOCOL_NAME}-stamp
	)
	set_target_properties(generate_dissector-dcerpc-${PROTOCOL_NAME}
		PROPERTIES FOLDER "Generated Dissectors/PIDL"
	)
	list(APPEND PIDL_DISSECTOR_TARGETS
		generate_dissector-dcerpc-${PROTOCOL_NAME}
	)
	list(APPEND PIDL_DISSECTOR_SRC
		packet-dcerpc-${PROTOCOL_NAME}.c
	)
endforeach()

set(PIDL_DISSECTOR_SRC ${PIDL_DISSECTOR_SRC} PARENT_SCOPE)

add_custom_target(pidl-dissectors ALL DEPENDS ${PIDL_DISSECTOR_TARGETS})
set_target_properties(pidl-dissectors
	PROPERTIES FOLDER "Generated Dissectors/PIDL"
)

#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 4
# tab-width: 4
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=4 tabstop=4 noexpandtab:
# :indentSize=4:tabSize=4:noTabs=false:
#
