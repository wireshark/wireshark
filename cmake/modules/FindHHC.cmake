#
# - Find the Microsoft HTML Help compiler.
# Sets HHC_EXECUTABLE to the path to hhc.exe
# Sets HHC_WRAPPER to a wrapper script that ignores hhc.exe's return value.
#

find_package(HTMLHelp)
set(HHC_EXECUTABLE ${HTML_HELP_COMPILER})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(HHC DEFAULT_MSG HHC_EXECUTABLE)

mark_as_advanced(HHC_EXECUTABLE)

if(WIN32)
  # hhc.exe returns 1 on success. Create a wrapper script that ignores
  # this.
  set(HHC_WRAPPER ${CMAKE_BINARY_DIR}/tools/hhc.cmd)
  file(TO_NATIVE_PATH "${HHC_EXECUTABLE}" HHC_EXECUTABLE_NATIVE_WINDOWS_PATH)
  configure_file(${CMAKE_SOURCE_DIR}/tools/hhc.cmd.in
    ${HHC_WRAPPER}
    NEWLINE_STYLE WIN32
  )
  find_package_handle_standard_args(HHC DEFAULT_MSG HHC_WRAPPER)
  mark_as_advanced(HHC_WRAPPER)
endif()
