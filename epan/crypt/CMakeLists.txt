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

set(CRYPT_FILES
	dot11decrypt.c
	dot11decrypt_ccmp.c
	dot11decrypt_rijndael.c
	dot11decrypt_tkip.c
	${CUSTOM_CRYPT_SRC}
)
source_group(crypt FILES ${CRYPT_FILES})

set_source_files_properties(
	${CRYPT_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

add_library(crypt OBJECT
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
# Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
