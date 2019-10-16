#
# - Try to find GModule2
# Find GModule headers, libraries and the answer to all questions.
#
#  GMODULE2_FOUND               True if GMODULE2 was found
#  GMODULE2_INCLUDE_DIRS        Location of GMODULE2 headers
#  GMODULE2_LIBRARIES           List of libraries to use GMODULE2
#

include(FindWSWinLibs)
FindWSWinLibs("vcpkg-export-*" "GMODULE2_HINTS")

if(NOT WIN32)
	find_package(PkgConfig QUIET)
	pkg_check_modules(PC_GMODULE2 gmodule-2.0)
endif()

find_path(GMODULE2_INCLUDE_DIR
	NAMES
		gmodule.h
	PATH_SUFFIXES
		glib-2.0
	HINTS
		${PC_GMODULE2_INCLUDE_DIRS}
		"${GMODULE2_HINTS}/include"
)
include(FindWSLibrary)
FindWSLibrary(GMODULE2_LIBRARY
	NAMES
		gmodule-2.0 gmodule
	HINTS
		${PC_GMODULE2_LIBRARY_DIRS}
	WIN32_HINTS
		${GMODULE2_HINTS}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GMODULE2 DEFAULT_MSG GMODULE2_LIBRARY GMODULE2_INCLUDE_DIR)

if(GMODULE2_FOUND)
	set(GMODULE2_INCLUDE_DIRS ${GMODULE2_INCLUDE_DIR})
	set(GMODULE2_LIBRARIES ${GMODULE2_LIBRARY})
else()
	set(GMODULE2_INCLUDE_DIRS)
	set(GMODULE2_LIBRARIES)
endif()

mark_as_advanced(GMODULE2_LIBRARIES GMODULE2_INCLUDE_DIRS)
