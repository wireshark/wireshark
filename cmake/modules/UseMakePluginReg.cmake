#
MACRO(REGISTER_PLUGIN_FILES _outputfile _registertype )
	include(LocatePythonModule)
	locate_python_module(make-plugin-reg REQUIRED PATHS ${CMAKE_SOURCE_DIR}/tools)

	ADD_CUSTOM_COMMAND(
	    OUTPUT
	      ${_outputfile}
	    COMMAND ${PYTHON_EXECUTABLE}
	      ${PY_MAKE-PLUGIN-REG}
	      ${CMAKE_CURRENT_SOURCE_DIR}
	      ${_registertype}
	      ${ARGN}
	    DEPENDS
	      ${ARGN}
	      ${PY_MAKE-PLUGIN-REG}
	)
ENDMACRO(REGISTER_PLUGIN_FILES)
