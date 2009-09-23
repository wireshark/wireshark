#
# $Id$
#
MACRO(ADD_LEMON_FILES _sources )
    set(_lemonpardir ${CMAKE_SOURCE_DIR}/tools/lemon)
    FOREACH (_current_FILE ${ARGN})
      GET_FILENAME_COMPONENT(_in ${_current_FILE} ABSOLUTE)
      GET_FILENAME_COMPONENT(_basename ${_current_FILE} NAME_WE)

      SET(_out ${CMAKE_CURRENT_BINARY_DIR}/${_basename}.c)

      ADD_CUSTOM_COMMAND(
         OUTPUT ${_out}
         COMMAND ${CMAKE_BINARY_DIR}/lemon
           t=${_lemonpardir}/lempar.c
           ${srcdir}/${_in}
         DEPENDS ${_in}
      )

      SET(${_sources} ${${_sources}} ${_out} )
   ENDFOREACH (_current_FILE)
ENDMACRO(ADD_LEMON_FILES)

