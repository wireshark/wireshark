#
# $Id$
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
    message(STATUS "Source(s): ${${_sources}}")
    # FIXME: How do I extract the first element of a variable containing a
    # list of values? Isn't there a "cleaner" solution?
    FOREACH(_source ${${_sources}})
	BREAK()
    ENDFOREACH()
    ADD_CUSTOM_COMMAND(
        OUTPUT
          ${CMAKE_CURRENT_BINARY_DIR}/${_validated}
        COMMAND ${XMLLINT_EXECUTABLE}
	  --valid
	  --noout
	  --path "${CMAKE_CURRENT_BINARY_DIR}:${CMAKE_CURRENT_SOURCE_DIR}"
          ${_source}
        COMMAND touch
          ${CMAKE_CURRENT_BINARY_DIR}/${_validated}
        DEPENDS
          ${_source}
	  svn_version.xml
    )
ENDMACRO(VALIDATE_XML)
