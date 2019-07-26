# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

include_directories(
	${CMAKE_CURRENT_BINARY_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_SOURCE_DIR}/epan
	${CMAKE_SOURCE_DIR}/tools/lemon
)

set(DFILTER_PUBLIC_HEADERS
	dfilter.h
	drange.h
)

set(DFILTER_HEADER_FILES
	${DFILTER_PUBLIC_HEADERS}
	dfilter-int.h
	dfilter-macro.h
	dfilter.h
	dfunctions.h
	dfvm.h
	drange.h
	gencode.h
	semcheck.h
	sttype-function.h
	sttype-range.h
	sttype-set.h
	sttype-test.h
	syntax-tree.h
)

set(DFILTER_NONGENERATED_FILES
	dfilter.c
	dfilter-macro.c
	dfunctions.c
	dfvm.c
	drange.c
	gencode.c
	semcheck.c
	sttype-function.c
	sttype-integer.c
	sttype-pointer.c
	sttype-range.c
	sttype-set.c
	sttype-string.c
	sttype-test.c
	syntax-tree.c
)
source_group(dfilter FILES ${DFILTER_NONGENERATED_FILES})

set(DFILTER_FILES ${DFILTER_NONGENERATED_FILES})

add_lex_files(LEX_FILES DFILTER_FILES
	scanner.l
)

add_lemon_files(LEMON_FILES DFILTER_FILES
	grammar.lemon
)

#
# We don't enable -Werror on generated code to make the build a
# little less fragile when configured warnings change.
#
set_source_files_properties(
	${DFILTER_NONGENERATED_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

add_library(dfilter OBJECT

	#Included so that Visual Studio can properly put header files in solution
	${DFILTER_HEADER_FILES}

	${DFILTER_FILES}
)

set_target_properties(dfilter PROPERTIES
	FOLDER "Libs/epan/dfilter"
	COMPILE_DEFINITIONS "WS_BUILD_DLL"
)

install(FILES ${DFILTER_PUBLIC_HEADERS}
	DESTINATION "${PROJECT_INSTALL_INCLUDEDIR}/epan/dfilter"
)

CHECKAPI(
	NAME
	  dfilter
	SWITCHES
	  -g termoutput -build
	SOURCES
	  ${DFILTER_NONGENERATED_FILES}
# LEX files commented out due to use of malloc, free etc.
#	  ${LEX_FILES}
	  ${LEMON_FILES}
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
