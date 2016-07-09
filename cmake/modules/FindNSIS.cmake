#
# - Find NSIS
# Find the makensis command
#
#  MAKENSIS_EXECUTABLE - path to the makensis utility.
#  CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS - System runtime DLLs

# Find makensis
set(_PF86 "PROGRAMFILES(x86)")
find_program(MAKENSIS_EXECUTABLE makensis
	PATH "$ENV{PROGRAMFILES}/NSIS" "$ENV{${_PF86}}/NSIS" "$ENV{PROGRAMW6432}/NSIS"
	DOC "Path to the makensis utility."
)
