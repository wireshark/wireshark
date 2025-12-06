# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

set(CORBA_DISSECTOR_NAMES
	coseventcomm
	cosnaming
	gias
	# parlay - retired, IDL still present
	tango
)

set(CORBA_DISSECTOR_TARGETS)

find_program(OMNIIDL_EXECUTABLE omniidl
	DOC "Path to the omniidl script or executable."
)

if(OMNIIDL_EXECUTABLE)
	foreach(PROTOCOL_NAME IN LISTS CORBA_DISSECTOR_NAMES)

		add_custom_command(
			OUTPUT packet-${PROTOCOL_NAME}-stamp
			COMMAND
				omniidl
				-p "${CMAKE_SOURCE_DIR}/tools"
				-b wireshark_be
				"-Wbpath=${CMAKE_CURRENT_SOURCE_DIR}/.."
				${PROTOCOL_NAME}.idl
			COMMAND "${CMAKE_COMMAND}" -E touch
				"${CMAKE_CURRENT_BINARY_DIR}/packet-${PROTOCOL_NAME}-stamp"
			WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/${PROTOCOL_NAME}"
			DEPENDS
				"${CMAKE_SOURCE_DIR}/tools/wireshark_be.py"
				"${CMAKE_SOURCE_DIR}/tools/wireshark_gen.py"
				${PROTOCOL_NAME}/${PROTOCOL_NAME}.idl
			VERBATIM
		)
		add_custom_target(generate_dissector-${PROTOCOL_NAME}
			DEPENDS packet-${PROTOCOL_NAME}-stamp
		)
		list(APPEND CORBA_DISSECTOR_TARGETS
			generate_dissector-${PROTOCOL_NAME}
		)
	endforeach()
endif()

add_custom_target(corba-dissectors ALL DEPENDS ${CORBA_DISSECTOR_TARGETS})
set_target_properties(corba-dissectors
	PROPERTIES FOLDER "Generated Dissectors/CORBA"
)
