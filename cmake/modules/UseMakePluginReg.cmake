#
function(register_plugin_files _outputfile _registertype _blurb)
	file(RELATIVE_PATH output "${CMAKE_BINARY_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/${_outputfile}")
	add_custom_command(
	    OUTPUT
	      ${_outputfile}
	    COMMAND ${Python3_EXECUTABLE}
	      ${CMAKE_SOURCE_DIR}/tools/make-plugin-reg.py
	      ${CMAKE_CURRENT_SOURCE_DIR}
	      ${_registertype}
	      ${_blurb}
	      ${ARGN}
	    COMMENT "Generating ${output}"
	    DEPENDS
	      ${ARGN}
	      ${CMAKE_SOURCE_DIR}/tools/make-plugin-reg.py
	    VERBATIM
	)
endfunction()
