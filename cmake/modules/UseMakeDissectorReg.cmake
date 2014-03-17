#
MACRO(REGISTER_DISSECTOR_FILES _outputfile _registertype )
	if(${_registertype} STREQUAL "dissectors" )
	    set( _makeregistertype "dissectorsinfile" )
	    set( _ftmp "${CMAKE_CURRENT_BINARY_DIR}/_regc.tmp" )
	    set( _depends ${ARGN} )
	    file(REMOVE ${_ftmp})
	    foreach(f ${_depends})
	      file(APPEND ${_ftmp} "${f}\n")
	    endforeach()
	    set( _sources ${_ftmp} )
	else()
	    set( _makeregistertype ${_registertype} )
	    set( _sources ${ARGN} )
	    set( _depends ${_sources} )
	endif()
	ADD_CUSTOM_COMMAND(
	    OUTPUT
	      ${_outputfile}
	    COMMAND ${PYTHON_EXECUTABLE}
	      ${CMAKE_SOURCE_DIR}/tools/make-dissector-reg.py
	      ${CMAKE_CURRENT_SOURCE_DIR}
	      ${_makeregistertype}
	      ${_sources}
	    DEPENDS
	      ${_depends}
	      ${CMAKE_SOURCE_DIR}/tools/make-dissector-reg
	      ${CMAKE_SOURCE_DIR}/tools/make-dissector-reg.py
	)
ENDMACRO(REGISTER_DISSECTOR_FILES)

