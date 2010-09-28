# - Check whether the C linker supports a given flag.
# CHECK_C_LINKER_FLAG(FLAG VARIABLE)
#
#  FLAG - the compiler flag
#  VARIABLE - variable to store the result
# 
#  This actually calls the check_c_source_compiles macro.
#  See help for CheckCSourceCompiles for a listing of variables
#  that can modify the build.

# Copyright (c) 2010, Joerg Mayer (see AUTHORS file)
#
# Redistribution and use is allowed according to the terms of the BSD license.

INCLUDE(CheckCSourceRuns)

MACRO (CHECK_C_LINKER_FLAG _FLAG _RESULT)
   SET(CMAKE_REQUIRED_FLAGS "${_FLAG}")
   message(status "check linker flag - test linker flags: ${CMAKE_REQUIRED_FLAGS}")
   CHECK_C_SOURCE_RUNS("int main() { return 0;}" ${_RESULT})
   SET(CMAKE_REQUIRED_FLAGS "")
ENDMACRO (CHECK_C_LINKER_FLAG)

