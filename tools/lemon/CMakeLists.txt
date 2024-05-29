# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

add_executable(lemon lemon.c)

if(DEFINED LEMON_C_COMPILER)
	set(CMAKE_C_COMPILER "${LEMON_C_COMPILER}")
	set(CMAKE_C_FLAGS "")
	set(CMAKE_EXE_LINKER_FLAGS "")
	set(CMAKE_SYSROOT "")
endif()

# To keep lemon.c as close to upstream as possible disable all warnings
if(CMAKE_C_COMPILER_ID MATCHES "MSVC")
	target_compile_options(lemon PRIVATE /w)
else()
	target_compile_options(lemon PRIVATE -w)
endif()
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
	# Disable static analysis for lemon source code. These issues don't
	# affect Wireshark at runtime.
	target_compile_options(lemon PRIVATE -Xclang -analyzer-disable-all-checks)
endif()
if(DEFINED NO_SANITIZE_CFLAGS)
	target_compile_options(lemon PRIVATE ${NO_SANITIZE_CFLAGS})
endif()
if(DEFINED NO_SANITIZE_LDFLAGS)
	target_link_options(lemon PRIVATE ${NO_SANITIZE_LDFLAGS})
endif()

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
