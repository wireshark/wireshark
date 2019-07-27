#
# - Find Wix executables
# Find the candle and light command
#
#  MAKEWIX_EXECUTABLE - path to the candle utility.
#  CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS - System runtime DLLs

set(_PF86 "PROGRAMFILES(x86)")

# According to
# https://stackoverflow.com/questions/2375322/variable-for-wix-bin-directory-path
# and
# https://weblogs.sqlteam.com/mladenp/2010/02/23/wix-3-tutorial-generating-filedirectory-fragments-with-heat.exe/
# WiX binaries are in $ENV{WIX}/bin.

# Find candle
find_program(WIX_CANDLE_EXECUTABLE candle
	PATH
		"$ENV{WIX}/bin"
		"$ENV{PROGRAMFILES}/WiX Toolset v3.10/bin"
		"$ENV{${_PF86}}/WiX Toolset v3.10/bin"
		"$ENV{PROGRAMW6432}/WiX Toolset v3.10/bin"
	DOC "Path to the WiX candle utility."
)

# Find light
find_program(WIX_LIGHT_EXECUTABLE light
	PATH
		"$ENV{WIX}/bin"
		"$ENV{PROGRAMFILES}/WiX Toolset v3.10/bin"
		"$ENV{${_PF86}}/WiX Toolset v3.10/bin"
		"$ENV{PROGRAMW6432}/WiX Toolset v3.10/bin"
	DOC "Path to the WiX light utility."
)

# Find heat
find_program(WIX_HEAT_EXECUTABLE heat
	PATH
		"$ENV{WIX}/bin"
		"$ENV{PROGRAMFILES}/WiX Toolset v3.10/bin"
		"$ENV{${_PF86}}/WiX Toolset v3.10/bin"
		"$ENV{PROGRAMW6432}/WiX Toolset v3.10/bin"
	DOC "Path to the WiX heat utility."
)
