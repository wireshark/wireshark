#
# - Find the WiX command line tool
#   This finds the "wix" command.
#   https://github.com/wixtoolset/wix/releases
#
#  WIX_EXECUTABLE - path to the wix utility. It provides the "build" command.

# "dotnet tool install --global" puts wix.exe in %USERPROFILE%\.dotnet\tools,
# which is normally in PATH. $ENV{WIX} and the Program Files directories
# cover other installation methods.
find_program(WIX_EXECUTABLE wix
	HINTS
		"$ENV{WIX}"
		"$ENV{WIX}/bin"
		"$ENV{USERPROFILE}/.dotnet/tools"
		"$ENV{PROGRAMFILES}/WiX Toolset v7.0/bin"
		"$ENV{PROGRAMFILES}/WiX Toolset v7/bin"
	DOC "Path to the WiX command line utility."
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(WiX DEFAULT_MSG WIX_EXECUTABLE)

mark_as_advanced(WIX_EXECUTABLE)
