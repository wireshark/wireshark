#
MACRO(ADD_LEMON_FILES _source _generated)
    set(_lemonpardir ${CMAKE_SOURCE_DIR}/tools/lemon)
    FOREACH (_current_FILE ${ARGN})
      GET_FILENAME_COMPONENT(_in ${_current_FILE} ABSOLUTE)
      GET_FILENAME_COMPONENT(_basename ${_current_FILE} NAME_WE)

      SET(_out ${CMAKE_CURRENT_BINARY_DIR}/${_basename})

      ADD_CUSTOM_COMMAND(
         OUTPUT
          ${_out}.c
          # These files are generated as side-effect
          ${_out}.h
          ${_out}.out
         COMMAND lemon
           T=${_lemonpardir}/lempar.c
           ${_in}
         DEPENDS
           ${_in}
           lemon
           ${_lemonpardir}/lempar.c
      )

      LIST(APPEND ${_source} ${_in})
      LIST(APPEND ${_generated} ${_out}.c)
   ENDFOREACH (_current_FILE)
ENDMACRO(ADD_LEMON_FILES)
