# - Convert ASN.1 file into C source and header files that can be used to create a wireshark dissector
#
#  A2W_OUTPUT_DIR   - directory where the generated packet-${PROTOCOL_NAME}.c is
#                     saved. The default location is meant for the Wireshark
#                     source tree. For external dissectors, set it to the
#                     absolute path (e.g. "${CMAKE_CURRENT_SOURCE_DIR}").

include(LocatePythonModule)
locate_python_module(asn2wrs REQUIRED PATHS "${CMAKE_SOURCE_DIR}/tools")

function(ASN2WRS)
	if(NOT PROTO_OPT)
		set(PROTO_OPT -p ${PROTOCOL_NAME})
	elseif(PROTO_OPT STREQUAL "_EMPTY_")
		set(PROTO_OPT)
	endif()

	if(NOT A2W_OUTPUT_DIR)
		set(A2W_OUTPUT_DIR "${CMAKE_SOURCE_DIR}/epan/dissectors")
	endif()

	set(DISSECTOR "${A2W_OUTPUT_DIR}/packet-${PROTOCOL_NAME}.c")

	# Besides the file dependency (for timestamp comparison), add a target such
	# that other directories can request it to be built (ordering dependency).
	foreach(_v EXTRA_CNF EXPORT_DEPENDS)
		set(${_v}_targets)
		foreach(entry IN LISTS ${_v})
			string(REGEX MATCH "[^/]+-exp\\.cnf$" _exp_cnf_filename "${entry}")
			if(_exp_cnf_filename)
				list(APPEND ${_v}_targets generate-${_exp_cnf_filename})
			endif()
		endforeach()
	endforeach()

	# Creates a dissector in the source directory and store the timestamp.
	add_custom_command(
		OUTPUT packet-${PROTOCOL_NAME}-stamp
		COMMAND "${PYTHON_EXECUTABLE}"
			${PY_ASN2WRS}
			${A2W_FLAGS}
			${PROTO_OPT}
			-c "${CMAKE_CURRENT_SOURCE_DIR}/${PROTOCOL_NAME}.cnf"
			-s "${CMAKE_CURRENT_SOURCE_DIR}/packet-${PROTOCOL_NAME}-template"
			-D "${CMAKE_CURRENT_SOURCE_DIR}"
			-O "${A2W_OUTPUT_DIR}"
			${EXT_ASN_FILE_LIST} ${ASN_FILE_LIST} ${EXT_ASN_FILE_LIST_LATE}
		COMMAND
			"${PYTHON_EXECUTABLE}" -c
				"import shutil, sys; x,s,d=sys.argv; open(d, 'w'); shutil.copystat(s, d)"
				"${A2W_OUTPUT_DIR}/packet-${PROTOCOL_NAME}.c"
				packet-${PROTOCOL_NAME}-stamp
		DEPENDS
			"${PY_ASN2WRS}"
			${SRC_FILES}
			${EXTRA_CNF_targets}
			${EXTRA_CNF}
		VERBATIM
	)

	add_custom_target(generate_dissector-${PROTOCOL_NAME} ALL
		DEPENDS packet-${PROTOCOL_NAME}-stamp
	)

	foreach(_asn2wrs_export_file IN LISTS EXPORT_FILES)
		add_custom_command(
			OUTPUT ${_asn2wrs_export_file}
			COMMAND "${PYTHON_EXECUTABLE}"
				"${PY_ASN2WRS}"
				-E
				${A2W_FLAGS}
				${PROTO_OPT}
				-c "${CMAKE_CURRENT_SOURCE_DIR}/${PROTOCOL_NAME}.cnf"
				-D "${CMAKE_CURRENT_SOURCE_DIR}"
				${EXT_ASN_FILE_LIST} ${ASN_FILE_LIST} ${EXT_ASN_FILE_LIST_LATE}
			DEPENDS
				"${PY_ASN2WRS}"
				${SRC_FILES}
				${EXPORT_DEPENDS_targets}
				${EXPORT_DEPENDS}
		)
		# This target enables other dissectors to trigger the -exp cnf build
		add_custom_target(generate-${_asn2wrs_export_file}
			DEPENDS ${_asn2wrs_export_file}
		)
	endforeach()

endfunction()
