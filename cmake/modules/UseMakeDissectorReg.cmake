#
MACRO(REGISTER_DISSECTOR_FILES _outputfile _registertype )
	include(LocatePythonModule)
	locate_python_module(make-plugin-reg REQUIRED PATHS ${CMAKE_SOURCE_DIR}/tools)

	set( _makeregistertype ${_registertype} )
	set( _sources ${ARGN} )
	set( _depends ${_sources} )
	ADD_CUSTOM_COMMAND(
	    OUTPUT
	      ${_outputfile}
	    COMMAND ${PYTHON_EXECUTABLE}
	      ${PY_MAKE-PLUGIN-REG}
	      ${CMAKE_CURRENT_SOURCE_DIR}
	      ${_makeregistertype}
	      ${_sources}
	    DEPENDS
	      ${_depends}
	      ${PY_MAKE-PLUGIN-REG}
	)
ENDMACRO(REGISTER_DISSECTOR_FILES)
