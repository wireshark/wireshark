#
function(make_plugin_register _outputfile _registertype _api_level _blurb)
	file(RELATIVE_PATH output "${CMAKE_BINARY_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/${_outputfile}")
	add_custom_command(
	    OUTPUT
	      ${_outputfile}
	    COMMAND ${Python3_EXECUTABLE}
	      ${CMAKE_SOURCE_DIR}/tools/make-plugin-reg.py
	      ${CMAKE_CURRENT_SOURCE_DIR}
	      ${_registertype}
	      ${_blurb}
	      ${_api_level}
	      ${ARGN}
	    COMMENT "Generating ${output}"
	    DEPENDS
	      ${ARGN}
	      ${CMAKE_SOURCE_DIR}/tools/make-plugin-reg.py
	    VERBATIM
	)
endfunction()

macro(register_plugin_files _outputfile _registertype _blurb)
	make_plugin_register(${_outputfile} ${_registertype} 0 ${_blurb} ${ARGN})
endmacro()

macro(register_codec_files _outputfile _api_level _blurb)
	make_plugin_register(${_outputfile} plugin_codec ${_api_level} ${_blurb} ${ARGN})
endmacro()
