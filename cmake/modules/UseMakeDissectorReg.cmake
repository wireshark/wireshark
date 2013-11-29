#
# $Id$
#
MACRO(REGISTER_DISSECTOR_FILES _outputfile _registertype )
	if(${_registertype} STREQUAL "dissectors" )
	    set( _makeregistertype "dissectorsinfile" )
	    set( _ftmp "${CMAKE_CURRENT_BINARY_DIR}/_regc.tmp" )
	    file(REMOVE ${_ftmp})
	    foreach(f ${ARGN})
	      file(APPEND ${_ftmp} "${f}\n")
	    endforeach()
	    set( _sources ${_ftmp} )
	else()
	    set( _makeregistertype ${_registertype} )
	    set( _sources ${ARGN} )
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
	      ${_sources}
	      ${CMAKE_SOURCE_DIR}/tools/make-dissector-reg
	      ${CMAKE_SOURCE_DIR}/tools/make-dissector-reg.py
	)
ENDMACRO(REGISTER_DISSECTOR_FILES)

