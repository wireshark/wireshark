# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

ADD_CUSTOM_CMAKE_INCLUDE()


include_directories(
	${CMAKE_CURRENT_BINARY_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}
)

set(CRYPT_HEADER_FILES
	dot11decrypt_debug.h
	dot11decrypt_int.h
	dot11decrypt_interop.h
	dot11decrypt_system.h
	dot11decrypt_user.h
	dot11decrypt_util.h
	dot11decrypt_ws.h
	kasumi.h
	wep-wpadefs.h
)

set(CRYPT_FILES
	dot11decrypt.c
	dot11decrypt_tkip.c
	${CUSTOM_CRYPT_SRC}
)

if (GCRYPT_VERSION VERSION_LESS 1.6.0)
	list(APPEND CRYPT_FILES
		dot11decrypt_ccmp_compat.c
	)
else()
	list(APPEND CRYPT_FILES
		dot11decrypt_ccmp.c
		dot11decrypt_util.c
		dot11decrypt_gcmp.c
	)
endif()

source_group(crypt FILES ${CRYPT_FILES})

set_source_files_properties(
	${CRYPT_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

add_library(crypt OBJECT
	#Included so that Visual Studio can properly put header files in solution
	${CRYPT_HEADER_FILES}

	${CRYPT_FILES}
)

set_target_properties(crypt PROPERTIES
	FOLDER "Libs/epan/crypt"
	COMPILE_DEFINITIONS "WS_BUILD_DLL"
)

CHECKAPI(
	NAME
	  crypt
	SWITCHES
	  -g termoutput -build
	SOURCES
	  ${CRYPT_FILES}
)

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
