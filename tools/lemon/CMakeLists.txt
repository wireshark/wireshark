# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

add_executable(lemon lemon.c)

# To keep lemon.c as close to upstream as possible, deliberately ignore
# some stylistic issues.
set(lemon_cflags)
if(CMAKE_C_COMPILER_ID MATCHES "MSVC")
	# Normal MSVC has no warnings, but VS Code Analysis finds a bunch
	# (when ENABLE_CODE_ANALYSIS is set).
	set(lemon_cflags
		/wd6001     # Using uninitialized memory '*zBuf'.
		/wd6011     # Dereferencing NULL pointer 'cp'.
		/wd6308     # realloc may return NULL and leak original memory.
		/wd6385     # Buffer overrun (read) in Parse, related to 'cp'
		/wd6386     # Buffer overrun (write) in Parse, related to 'filebuf'
		/wd6387     # strlen(argv[0]) could receive a NULL pointer.
		/wd28182    # Dereferencing NULL pointer. 'ap2' contains the same NULL value as 'ap' did.
		/wd28183    # passing 0 (from realloc) to memcpy
		/wd28199    # Using possibly uninitialized memory
	)
else()
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
		check_c_compiler_flag(${THIS_FLAG} ${_flag_var})
		if(${_flag_var})
			# Look for -Wfoo flags above in case it is cached, but
			# actually disable the warning here with -Wno-foo.
			string(REPLACE "-W" "-Wno-" THIS_FLAG "${THIS_FLAG}")
			list(APPEND lemon_cflags ${THIS_FLAG})
		endif()
	endforeach()
endif()
target_compile_options(lemon PRIVATE ${lemon_cflags})

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
