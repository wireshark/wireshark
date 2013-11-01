#
# $Id$
#
MACRO(REGISTER_DISSECTOR_FILES _outputfile _registertype )
	set( _sources ${ARGN} )
	ADD_CUSTOM_COMMAND(
	    OUTPUT
	      ${_outputfile}
	    COMMAND ${PYTHON_EXECUTABLE}
	      ${CMAKE_SOURCE_DIR}/tools/make-dissector-reg.py
	      ${CMAKE_CURRENT_SOURCE_DIR}
	      ${_registertype}
	      ${_sources}
	    DEPENDS
	      ${_sources}
	      ${CMAKE_SOURCE_DIR}/tools/make-dissector-reg
	      ${CMAKE_SOURCE_DIR}/tools/make-dissector-reg.py
	)
ENDMACRO(REGISTER_DISSECTOR_FILES)

