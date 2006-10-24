# - Check if the function exists.
# CHECK_64BIT_FORMAT(FORMAT VARIABLE)
# - macro which checks if the function exists
#  FORMAT - the format, e.g ll, L, q or I64
#  VARIABLE - variable to store the format if it is a valdid format
#
# Example of use in a CMakeLists.txt
#
# include(Check64BitFormat)
# 
# check_64bit_format(ll FORMAT_64BIT)
# check_64bit_format(L FORMAT_64BIT)
# check_64bit_format(q FORMAT_64BIT)
# check_64bit_format(I64 FORMAT_64BIT)
# 
# if(NOT FORMAT_64BIT)
#   message(FATAL " 64 bit formart missing")
# endif(NOT FORMAT_64BIT)
# 
# set(PRIX64 "${FORMAT_64BIT}X")
# set(PRIx64 "${FORMAT_64BIT}x")
# set(PRId64 "${FORMAT_64BIT}d")
# set(PRIo64 "${FORMAT_64BIT}o")
# set(PRIu64 "${FORMAT_64BIT}u")



MACRO(CHECK_64BIT_FORMAT FORMAT VARIABLE)
  IF(NOT ${VARIABLE})
    SET(FORMAT ${FORMAT})
#CONFIGURE_FILE("${CMAKE_ROOT}/Modules/Check64BitFormat.c.in"
    CONFIGURE_FILE("${CMAKE_SOURCE_DIR}/cmake/modules/Check64BitFormat.c.in"
      "${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeTmp/Check64BitFormat.c" IMMEDIATE @ONLY)

    TRY_RUN(RUN_RESULT_VAR COMPILE_RESULT_VAR
      ${CMAKE_BINARY_DIR}
      ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeTmp/Check64BitFormat.c
      OUTPUT_VARIABLE OUTPUT)
    
    IF(${RUN_RESULT_VAR} STREQUAL "0")
      SET(${VARIABLE} 1 CACHE INTERNAL "Have format ${FORMAT}")
      MESSAGE(STATUS "Looking for 64bit format ${FORMAT} - found")
      FILE(APPEND ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeOutput.log 
        "Determining if the format ${FORMAT} runs passed with the following output:\n"
        "${OUTPUT}\n\n")
      SET(${VARIABLE} ${FORMAT})
    ELSE(${RUN_RESULT_VAR} STREQUAL "0")
      MESSAGE(STATUS "Looking for 64bit format ${FORMAT} - not found")
      SET(${VARIABLE} "" CACHE INTERNAL "Have format ${FORMAT}")
      FILE(APPEND ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeError.log 
        "Determining if the format ${FORMAT} runs with the following output:\n"
        "${OUTPUT}\n\n")
    ENDIF(${RUN_RESULT_VAR} STREQUAL "0")
  ENDIF(NOT ${VARIABLE})
ENDMACRO(CHECK_64BIT_FORMAT)
