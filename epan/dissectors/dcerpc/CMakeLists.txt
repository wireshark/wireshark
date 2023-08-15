# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

set(PIDL_DISSECTOR_NAMES
	budb
	butc
)

foreach(PROTOCOL_NAME IN LISTS PIDL_DISSECTOR_NAMES)
	# Use a stamp file instead of OUTPUT to packet-dcerpc-X.c to
	# avoid removing the .c file on clean.
	add_custom_command(
		OUTPUT packet-dcerpc-${PROTOCOL_NAME}-stamp
		COMMAND
			idl2wrs ${PROTOCOL_NAME}
		COMMAND
			"${CMAKE_COMMAND}" -E copy_if_different
			packet-dcerpc-${PROTOCOL_NAME}.c
			"${CMAKE_CURRENT_SOURCE_DIR}/../packet-dcerpc-${PROTOCOL_NAME}.c"
		COMMAND
			"${CMAKE_COMMAND}" -E copy_if_different
			packet-dcerpc-${PROTOCOL_NAME}.h
			"${CMAKE_CURRENT_SOURCE_DIR}/../packet-dcerpc-${PROTOCOL_NAME}.h"
		COMMAND
			"${CMAKE_COMMAND}" -E touch
			"${CMAKE_CURRENT_BINARY_DIR}/packet-dcerpc-${PROTOCOL_NAME}-stamp"
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/${PROTOCOL_NAME}"
		DEPENDS
			"${CMAKE_SOURCE_DIR}/tools/pidl/pidl"
			${PROTOCOL_NAME}/${PROTOCOL_NAME}.idl
			${PROTOCOL_NAME}/${PROTOCOL_NAME}.cnf
			${PROTOCOL_NAME}/packet-dcerpc-${PROTOCOL_NAME}-template.h
			${PROTOCOL_NAME}/packet-dcerpc-${PROTOCOL_NAME}-template.c
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
endforeach()

# TODO should probably just merge this into pidl-dissectors
add_custom_target(idl2wrs-dissectors ALL DEPENDS ${PIDL_DISSECTOR_TARGETS})
set_target_properties(idl2wrs-dissectors
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
