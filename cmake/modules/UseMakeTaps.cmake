#
MACRO(REGISTER_TAP_FILES _outputfile)
    set(_sources ${ARGN})
    ADD_CUSTOM_COMMAND(
        OUTPUT
          ${_outputfile}
        COMMAND
          make-taps ${_outputfile} ${_sources}
        DEPENDS
          make-taps
          ${_sources}
        COMMENT
          "Making ${_outputfile}"
)
ENDMACRO(REGISTER_TAP_FILES)
