#
# - Find the Microsoft HTML Help compiler.
# Sets HHC_EXECUTABLE to the path to hhc.exe
# Sets HHC_WRAPPER to a wrapper script that ignores hhc.exe's return value.
#

FIND_PROGRAM(HHC_EXECUTABLE
  NAMES
    hhc
  HINTS
    $ENV{PROGRAMFILES}/HTML Help Workshop
)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(HHC DEFAULT_MSG HHC_EXECUTABLE)

MARK_AS_ADVANCED(HHC_EXECUTABLE)

if(WIN32)
  # hhc.exe returns 1 on success. Create a wrapper script that ignores
  # this.
  set(HHC_WRAPPER ${CMAKE_BINARY_DIR}/tools/hhc.cmd)
  file(TO_NATIVE_PATH "${HHC_EXECUTABLE}" HHC_EXECUTABLE_NATIVE_WINDOWS_PATH)
  configure_file(${CMAKE_SOURCE_DIR}/tools/hhc.cmd.in
    ${HHC_WRAPPER}
    NEWLINE_STYLE WIN32
  )
  FIND_PACKAGE_HANDLE_STANDARD_ARGS(HHC DEFAULT_MSG HHC_WRAPPER)
  MARK_AS_ADVANCED(HHC_WRAPPER)
endif()
