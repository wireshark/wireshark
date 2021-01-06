#
function(register_plugin_files _outputfile _registertype)
	include(LocatePythonModule)
	locate_python_module(make-plugin-reg REQUIRED PATHS ${CMAKE_SOURCE_DIR}/tools)

	file(RELATIVE_PATH output "${CMAKE_BINARY_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/${_outputfile}")
	add_custom_command(
	    OUTPUT
	      ${_outputfile}
	    COMMAND ${PYTHON_EXECUTABLE}
	      ${PY_MAKE-PLUGIN-REG}
	      ${CMAKE_CURRENT_SOURCE_DIR}
	      ${_registertype}
	      ${ARGN}
	    COMMENT "Generating ${output}"
	    DEPENDS
	      ${ARGN}
	      ${PY_MAKE-PLUGIN-REG}
	)
endfunction()
