#
MACRO(REGISTER_TAP_FILES _outputfile _registertype )
    set( _sources ${ARGN})
    ADD_CUSTOM_COMMAND(
        OUTPUT
          ${_outputfile}
        COMMAND ${PYTHON_EXECUTABLE}
          ${CMAKE_SOURCE_DIR}/tools/make-tap-reg.py
          "${CMAKE_CURRENT_SOURCE_DIR}"
          ${_registertype}
          ${_sources}
        DEPENDS
          ${CMAKE_SOURCE_DIR}/tools/make-tap-reg.py
          ${_sources}
)
ENDMACRO(REGISTER_TAP_FILES)

