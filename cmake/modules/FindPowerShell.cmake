#
# Find PowerShell
# This module looks for PowerShell and sets the following:
# POWERSHELL_EXECUTABLE - Path to PowerShell.
# POWERSHELL_COMMAND - Command suitable for running .ps1 scripts
#
# To do:
# - Add a version check
#

find_program(POWERSHELL_EXECUTABLE
  NAMES powershell
  DOC "PowerShell command"
)

INCLUDE(FindPackageHandleStandardArgs)
find_package_handle_standard_args(POWERSHELL DEFAULT_MSG POWERSHELL_EXECUTABLE)

set(_powershell_command "POWERSHELL_COMMAND-NOTFOUND")
if(POWERSHELL_FOUND)
  # Calling a script using "-File" doesn't properly return exit codes.
  # Use dot sourcing instead
  # https://connect.microsoft.com/PowerShell/feedback/details/777375/powershell-exe-does-not-set-an-exit-code-when-file-is-used
  set(_powershell_command "${POWERSHELL_EXECUTABLE}" -NoProfile -NonInteractive -executionpolicy bypass .)
endif()
set(POWERSHELL_COMMAND ${_powershell_command}
  CACHE STRING "Command suitable for running PowerShell scripts."
)

mark_as_advanced(POWERSHELL_EXECUTABLE POWERSHELL_COMMAND)
