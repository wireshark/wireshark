# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

set(PIDL_DISSECTOR_NAMES
	atsvc
	browser
	clusapi
	dfs
	drsuapi
	dssetup
	efs
	frsrpc
	frstrans
	fsrvp
	initshutdown
	iwbemlevel1login
	iwbemloginclientid
	iwbemloginclientidex
	iwbemservices
	lsa
	mdssvc
	misc
	rfr
	samr
	srvsvc
	svcctl
	winreg
	witness
	wkssvc
	wzcsvc
)

#
# These cannot be built using from source:
#
# dnsserver - "dnsserver.idl:159: error: Inline arrays not supported"
# eventlog - "eventlog.idl:54: error: Inline arrays not supported"
# nspi - "nspi.idl:154: error: Syntax error near '/'"
# mapi - includes nspi.idl, so it gets the above error
# winspool - it requires spoolss.idl, and we don't have that.
#

set(PIDL_DISSECTOR_browser_EXTRA_DEPS
	srvsvc/srvsvc.idl
)
set(PIDL_DISSECTOR_clusapi_EXTRA_DEPS
	winreg/winreg.idl
	misc/misc.idl
)
set(PIDL_DISSECTOR_drsuapi_EXTRA_DEPS
	misc/misc.idl
	lsa/lsa.idl
	samr/samr.idl
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
set(PIDL_DISSECTOR_fsrvp_EXTRA_DEPS
	idl_types.h
)
set(PIDL_DISSECTOR_initshutdown_EXTRA_DEPS
	lsa/lsa.idl
	idl_types.h
)
set(PIDL_DISSECTOR_iwbemlevel1login_EXTRA_DEPS
	idl_types.h
)
set(PIDL_DISSECTOR_iwbemloginclientid_EXTRA_DEPS
	idl_types.h
)
set(PIDL_DISSECTOR_iwbemloginclientidex_EXTRA_DEPS
	idl_types.h
)
set(PIDL_DISSECTOR_iwbemservices_EXTRA_DEPS
	idl_types.h
)
set(PIDL_DISSECTOR_lsa_EXTRA_DEPS
	idl_types.h
)
set(PIDL_DISSECTOR_mapi_EXTRA_DEPS
	idl_types.h
	nspi/nspi.idl
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
	misc/misc.idl
	lsa/lsa.idl
)
set(PIDL_DISSECTOR_srvsvc_EXTRA_DEPS
	idl_types.h
)
set(PIDL_DISSECTOR_winreg_EXTRA_DEPS
	misc/misc.idl
)
set(PIDL_DISSECTOR_winspool_EXTRA_DEPS
	idl_types.h
	misc/misc.idl
	winreg/winreg.idl
	spoolss/spoolss.idl
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

foreach(PROTOCOL_NAME IN LISTS PIDL_DISSECTOR_NAMES)
	#
	# Construct, from the list of extra dependencies for
	# this dissector, a list of --includedir options
	# for all the directories in which those dependencies
	# reside. We add --includedir .. for all targets.
	#
	set(INCLUDE_DIRS "")
	list(APPEND INCLUDE_DIRS --includedir ..)
	foreach(DEPENDENCY in ${PIDL_DISSECTOR_${PROTOCOL_NAME}_EXTRA_DEPS})
		get_filename_component(PARENT_DIR ${DEPENDENCY} DIRECTORY)
		if (NOT PARENT_DIR STREQUAL "")
			list(APPEND INCLUDE_DIRS  --includedir ../${PARENT_DIR})
		endif()
	endforeach()
	#
	# COMMAND_EXPAND_LISTS is required to cause the list
	# INCLUDE_DIRS to be expanded into a set of individual
	# arguments to the pidl command.
	#
	add_custom_command(
		OUTPUT packet-dcerpc-${PROTOCOL_NAME}-stamp
		COMMAND "${PERL_EXECUTABLE}"
			"${CMAKE_SOURCE_DIR}/tools/pidl/pidl"
			--ws-parser
			--outputdir ../..
			${INCLUDE_DIRS}
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
		COMMAND_EXPAND_LISTS
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
endforeach()

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
