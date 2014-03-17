#
MACRO(ASN2WRS)
	set( DISSECTOR ${CMAKE_SOURCE_DIR}/epan/dissectors/packet-${PROTOCOL_NAME}.c )

	if ( NOT PROTO_OPT )
		set( PROTO_OPT -p ${PROTOCOL_NAME} )
	elseif ( PROTO_OPT STREQUAL "_EMPTY_" )
		set( PROTO_OPT )
	endif()

	# Don't use packet-${PROTOCOL_NAME}.c instead of generate_dissector, it will
	# cause EXCLUDE_FROM_ALL to be ignored.
	ADD_CUSTOM_TARGET(generate_dissector-${PROTOCOL_NAME} ALL
		COMMAND ${PYTHON_EXECUTABLE}
		  ${CMAKE_SOURCE_DIR}/tools/asn2wrs.py
		  ${A2W_FLAGS}
		  ${PROTO_OPT}
		  -c ${CMAKE_CURRENT_SOURCE_DIR}/${PROTOCOL_NAME}.cnf
		  -s ${CMAKE_CURRENT_SOURCE_DIR}/packet-${PROTOCOL_NAME}-template
		  -D ${CMAKE_CURRENT_SOURCE_DIR}
		  -O ${CMAKE_SOURCE_DIR}/epan/dissectors
		  ${EXT_ASN_FILE_LIST} ${ASN_FILE_LIST} ${EXT_ASN_FILE_LIST_LATE}
		DEPENDS
		  ${CMAKE_SOURCE_DIR}/tools/asn2wrs.py
		  ${SRC_FILES}
		  ${EXTRA_CNF}
	)

	foreach( _asn2wrs_export_file IN LISTS EXPORT_FILES )
		ADD_CUSTOM_TARGET( ${_asn2wrs_export_file}
			WORKING_DIRECTORY .
			COMMAND ${PYTHON_EXECUTABLE}
			  ${CMAKE_SOURCE_DIR}/tools/asn2wrs.py
			  -E
			  ${A2W_FLAGS}
			  ${PROTO_OPT}
			  -c ${CMAKE_CURRENT_SOURCE_DIR}/${PROTOCOL_NAME}.cnf
			  -D ${CMAKE_CURRENT_SOURCE_DIR}
			  ${EXT_ASN_FILE_LIST} ${ASN_FILE_LIST} ${EXT_ASN_FILE_LIST_LATE}
			DEPENDS
			  ${CMAKE_SOURCE_DIR}/tools/asn2wrs.py
			  ${SRC_FILES}
			  ${EXPORT_DEPENDS}
		)
	endforeach()
ENDMACRO()
