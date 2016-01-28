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
   #
   # This is ugly.
   #
   # See CMake bug 0015934:
   #
   #    https://cmake.org/Bug/view.php?id=15934
   #
   # So we add the flags to CMAKE_REQUIRED_LIBRARIES, to sneak it into
   # the linker flags.
   #
   # This may or may not work with versions earlier than 2.8.11, although
   # 2.8.10's Xcode generator doesn't appear to work at all - it fails
   # with an internal CMake error.
   #
   # With 3.2 and later, we could also set policy CMP0056 to NEW and
   # set CMAKE_EXE_LINKER_FLAGS.
   #
   set(save_CMAKE_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES}")
   if(CMAKE_C_COMPILER_ID MATCHES "MSVC")
      #
      # This means the linker is presumably the Microsoft linker;
      # we need to pass /WX in order to have the linker fail,
      # rather than just complaining and driving on, if it's
      # passed a flag it doesn't handle.
      #
      set(CMAKE_REQUIRED_LIBRARIES "/WX")
   elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")
      #
      # We'll be running the linker through the compiler driver, so
      # we may need to pass -Werror=unused-command-line-argument to have it
      # fail, rather than just complaining and driving on, if it's
      # passed a flag it doesn't handle.
      set(CMAKE_REQUIRED_LIBRARIES "-Werror=unused-command-line-argument")
   endif()
   set(CMAKE_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES} ${_FLAG}")
   message(status "check linker flag - test linker flags: ${_FLAG}")
   check_c_source_compiles("int main() { return 0;}" ${_RESULT})
   set(CMAKE_REQUIRED_LIBRARIES "${save_CMAKE_REQUIRED_LIBRARIES}")
ENDMACRO (CHECK_C_LINKER_FLAG)

