#
# - Find unix commands from cygwin
# This module looks for some usual Unix commands.
#

INCLUDE(FindCygwin)

FIND_PROGRAM(XMLLINT_EXECUTABLE
  NAMES
    xmllint
  PATHS
    ${CYGWIN_INSTALL_PATH}/bin
    /bin
    /usr/bin
    /usr/local/bin
    /sbin
)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(XMLLINT DEFAULT_MSG XMLLINT_EXECUTABLE)

MARK_AS_ADVANCED(XMLLINT_EXECUTABLE)

# Validate XML
MACRO(VALIDATE_XML _validated _sources)
    # FIXME: How do I extract the first element of a variable containing a
    # list of values? Isn't there a "cleaner" solution?
    # Oh, and I have no idea why I can't directly use _source instead of
    # having to introduce _tmpsource.
    FOREACH(_tmpsource ${${_sources}})
	set(_source ${_tmpsource})
	BREAK()
    ENDFOREACH()
    ADD_CUSTOM_COMMAND(
	OUTPUT
	    ${_validated}
	COMMAND ${XMLLINT_EXECUTABLE}
	  --path "${CMAKE_CURRENT_SOURCE_DIR}:${CMAKE_CURRENT_BINARY_DIR}:${CMAKE_CURRENT_BINARY_DIR}/wsluarm_src"
	  --valid
	  --noout
	  ${_source}
	COMMAND touch
	  ${_validated}
	DEPENDS
	  ${${_sources}}
    )
ENDMACRO(VALIDATE_XML)
