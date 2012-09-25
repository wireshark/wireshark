#
# $Id$
#
MACRO(REGISTER_DISSECTOR_FILES _outputfile _registertype )
	# FIXME: Only the Python stuff has been implemented
	#        Make this into a MACRO, to avoid duplication with plugins/.../
	#register.c: $(plugin_src) $(ALL_DISSECTORS_SRC) $(top_srcdir)/tools/make-dissector-reg \
	#    $(top_srcdir)/tools/make-dissector-reg.py
	#        @if test -n "$(PYTHON)"; then \
	#                echo Making register.c with python ; \
	#                $(PYTHON) $(top_srcdir)/tools/make-dissector-reg.py $(srcdir) \
	#                    dissectors $(ALL_DISSECTORS_SRC) ; \
	#        else \
	#                echo Making register.c with shell script ; \
	#                $(top_srcdir)/tools/make-dissector-reg $(srcdir) \
	#                   dissectors $(plugin_src) $(ALL_DISSECTORS_SRC) ; \
	#        fi
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

