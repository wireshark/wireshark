# - Convert ASN.1 file into C source and header files that can be used to create a wireshark dissector

MACRO(ASN2WRS)
	include(LocatePythonModule)
	locate_python_module(asn2wrs REQUIRED PATHS ${CMAKE_SOURCE_DIR}/tools)

	set( DISSECTOR ${CMAKE_SOURCE_DIR}/epan/dissectors/packet-${PROTOCOL_NAME}.c )

	if ( NOT PROTO_OPT )
		set( PROTO_OPT -p ${PROTOCOL_NAME} )
	elseif ( PROTO_OPT STREQUAL "_EMPTY_" )
		set( PROTO_OPT )
	endif()

	# Backwards compability for build in dissectors,
	# set to '_EMPTY_' for out of source dissector builds
	if ( NOT A2W_OUTPUT_DIR )
		set (A2W_OUTPUT_DIR -O ${CMAKE_SOURCE_DIR}/epan/dissectors)
	elseif ( A2W_OUTPUT_DIR STREQUAL "_EMPTY_" )
		set( A2W_OUTPUT_DIR )
	endif()

	# Don't use packet-${PROTOCOL_NAME}.c instead of generate_dissector, it will
	# cause EXCLUDE_FROM_ALL to be ignored.
	ADD_CUSTOM_TARGET(generate_dissector-${PROTOCOL_NAME} ALL
		COMMAND ${PYTHON_EXECUTABLE}
		  ${PY_ASN2WRS}
		  ${A2W_FLAGS}
		  ${PROTO_OPT}
		  -c ${CMAKE_CURRENT_SOURCE_DIR}/${PROTOCOL_NAME}.cnf
		  -s ${CMAKE_CURRENT_SOURCE_DIR}/packet-${PROTOCOL_NAME}-template
		  -D ${CMAKE_CURRENT_SOURCE_DIR}
		  ${A2W_OUTPUT_DIR}
		  ${EXT_ASN_FILE_LIST} ${ASN_FILE_LIST} ${EXT_ASN_FILE_LIST_LATE}
		DEPENDS
		  ${PY_ASN2WRS}
		  ${SRC_FILES}
		  ${EXTRA_CNF}
	)

	foreach( _asn2wrs_export_file IN LISTS EXPORT_FILES )
		ADD_CUSTOM_TARGET( ${_asn2wrs_export_file}
			WORKING_DIRECTORY .
			COMMAND ${PYTHON_EXECUTABLE}
			  ${PY_ASN2WRS}
			  -E
			  ${A2W_FLAGS}
			  ${PROTO_OPT}
			  -c ${CMAKE_CURRENT_SOURCE_DIR}/${PROTOCOL_NAME}.cnf
			  -D ${CMAKE_CURRENT_SOURCE_DIR}
			  ${EXT_ASN_FILE_LIST} ${ASN_FILE_LIST} ${EXT_ASN_FILE_LIST_LATE}
			DEPENDS
			  ${PY_ASN2WRS}
			  ${SRC_FILES}
			  ${EXPORT_DEPENDS}
		)
	endforeach()
ENDMACRO()
