#
# - Try to find GThread2
# Find GThread headers, libraries and the answer to all questions.
#
#  GTHREAD2_FOUND               True if GTHREAD2 was found
#  GTHREAD2_INCLUDE_DIRS        Location of GTHREAD2 headers
#  GTHREAD2_LIBRARIES           List of libraries to use GTHREAD2
#

include(FindWSWinLibs)
FindWSWinLibs("vcpkg-export-*" "GTHREAD2_HINTS")

if(NOT WIN32)
	find_package(PkgConfig QUIET)
	pkg_check_modules(PC_GTHREAD2 gthread-2.0)
endif()

find_path(GTHREAD2_INCLUDE_DIR
	NAMES
		glib/gthread.h
	PATH_SUFFIXES
		glib-2.0
	HINTS
		${PC_GTHREAD2_INCLUDE_DIRS}
		"${GTHREAD2_HINTS}/include"
)
include(FindWSLibrary)
FindWSLibrary(GTHREAD2_LIBRARY
	NAMES
		gthread-2.0 gthread
	HINTS
		${PC_GTHREAD2_LIBRARY_DIRS}
	WIN32_HINTS
		${GTHREAD2_HINTS}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GTHREAD2 DEFAULT_MSG GTHREAD2_LIBRARY GTHREAD2_INCLUDE_DIR)

if(GTHREAD2_FOUND)
	set(GTHREAD2_INCLUDE_DIRS ${GTHREAD2_INCLUDE_DIR})
	set(GTHREAD2_LIBRARIES ${GTHREAD2_LIBRARY})
else()
	set(GTHREAD2_INCLUDE_DIRS)
	set(GTHREAD2_LIBRARIES)
endif()

mark_as_advanced(GTHREAD2_LIBRARIES GTHREAD2_INCLUDE_DIRS)
