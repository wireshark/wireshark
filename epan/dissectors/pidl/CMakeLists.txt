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
	dnsserver
	dfs
	drsuapi
	dssetup
	efs
	eventlog
	frsrpc
	frstrans
	fsrvp
	initshutdown
	iwbemlevel1login
	iwbemloginclientid
	iwbemloginclientidex
	iwbemservices
	lsa
	mapi
	mdssvc
	misc
	nspi
	rcg
	rfr
	samr
	srvsvc
	svcctl
	winreg
	winspool
	witness
	wkssvc
	wzcsvc
)

#
# These can give some (not-fatal) errors building from source:
#
# nspi - "nspi.idl:154: error: Syntax error near '/'"
# mapi - includes nspi.idl, so it gets the above error
# winspool - we have a hand-written spoolss dissector we use instead of spoolss.idl
#
# XXX - the "Syntax error near '/'" errors show up if cpp doesn't strip
# C99/C++ comments and the file in question - nspi.idl - contains
# C99/C++ comments, because the parser runs cpp, by default, to strip
# comments and process #includes.  Those errors may cause
# packet-dcerpc-nspi.c, and possibly packet-dcerpc-mapi.c not to be
# generated.  GCC's cpp appears to strip them by default, but Xcode's
# cpp, at least as of Xcode 15.2, does not - cc -E does, however,
# strip them.  (Both of them strip "classic C" /* ... */ comments.)
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
set(PIDL_DISSECTOR_rcg_EXTRA_DEPS
	idl_types.h
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
	# Wireshark supplies the spoolss elements through a hand-written dissector
	#spoolss/spoolss.idl
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
			"${CMAKE_SOURCE_DIR}/tools/pidl/lib/Parse/Pidl/Wireshark/NDR.pm"
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
