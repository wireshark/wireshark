# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

# To keep lemon.c as close to upstream as possible, deliberately ignore
# some stylistic issues.
set(lemon_cflags)
if(NOT CMAKE_C_COMPILER_ID MATCHES "MSVC")
	# Includes warnings from ENABLE_EXTRA_COMPILER_WARNINGS as well
	set(lemon_cflags_test
		# GCC 8.2.1 is not smart enough to recognize "Fall thru ..."
		-Wimplicit-fallthrough
		-Wsign-compare
		-Wunused-parameter
		-Wshorten-64-to-32
		# From WIRESHARK_C_ONLY_FLAGS
		-Wc++-compat
		-Wold-style-definition
		-Wstrict-prototypes
	)
	if(ENABLE_EXTRA_COMPILER_WARNINGS)
		list(APPEND lemon_cflags_test
			-Wpedantic
			-Wstrict-overflow
			-Wcast-qual
			-Wredundant-decls
			-Wmissing-prototypes
			-Wmissing-declarations
			-Wcast-align
		)
	endif()
	foreach(THIS_FLAG IN LISTS lemon_cflags_test)
		string(MAKE_C_IDENTIFIER "C${THIS_FLAG}_VALID" _flag_var)
		check_c_linker_flag(${THIS_FLAG} ${_flag_var})
		if(${_flag_var})
			# Look for -Wfoo flags above in case it is cached, but
			# actually disable the warning here with -Wno-foo.
			string(REPLACE "-W" "-Wno-" THIS_FLAG "${THIS_FLAG}")
			list(APPEND lemon_cflags ${THIS_FLAG})
		endif()
	endforeach()
endif()
set_source_files_properties(lemon.c
	PROPERTIES
	COMPILE_OPTIONS "${lemon_cflags}"
)
add_executable(lemon lemon.c)

#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
#
