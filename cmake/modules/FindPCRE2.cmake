#
# - Find PCRE2 libraries
#
#  PCRE2_INCLUDE_DIRS - where to find PCRE2 headers.
#  PCRE2_LIBRARIES    - List of libraries when using PCRE2.
#  PCRE2_FOUND        - True if PCRE2 is found.
#  PCRE2_DLL_DIR      - (Windows) Path to the PCRE2 DLL
#  PCRE2_DLL          - (Windows) Name of the PCRE2 DLL

# Note that the "8" in "libpcre2-8" refers to "PCRE library version 2 with
# support for 8-bit code units".

include( FindWSWinLibs )
FindWSWinLibs( "pcre2-.*" "PCRE2_HINTS" )

if( NOT WIN32)
	find_package(PkgConfig QUIET)
	pkg_search_module(PC_PCRE2 QUIET "libpcre2-8")
endif()

find_path(PCRE2_INCLUDE_DIR
	NAMES
		pcre2.h
	HINTS
		${PC_PCRE2_INCLUDE_DIRS}
		${PCRE2_HINTS}/include
)

find_library(PCRE2_LIBRARY
	NAMES
		"pcre2-8"
	HINTS
		${PC_PCRE2_LIBRARY_DIRS}
		${PCRE2_HINTS}/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCRE2
	REQUIRED_VARS   PCRE2_LIBRARY PCRE2_INCLUDE_DIR
	VERSION_VAR     PC_PCRE2_VERSION
)

if(PCRE2_FOUND)
	set(PCRE2_LIBRARIES ${PCRE2_LIBRARY})
	set(PCRE2_INCLUDE_DIRS ${PCRE2_INCLUDE_DIR})
	if (WIN32)
	set (PCRE2_DLL_DIR "${PCRE2_HINTS}/bin"
		CACHE PATH "Path to PCRE2 DLL"
	)
	file(GLOB _pcre2_dll RELATIVE "${PCRE2_DLL_DIR}"
		"${PCRE2_DLL_DIR}/pcre2-8*.dll"
	)
	set (PCRE2_DLL ${_pcre2_dll}
		# We're storing filenames only. Should we use STRING instead?
		CACHE FILEPATH "PCRE2 DLL file name"
	)
	file(GLOB _pcre2_pdb RELATIVE "${PCRE2_DLL_DIR}"
		"${PCRE2_DLL_DIR}/pcre2-8*.pdb"
	)
	set (PCRE2_PDB ${_pcre2_pdb}
		CACHE FILEPATH "PCRE2 PDB file name"
	)
	mark_as_advanced(PCRE2_DLL_DIR PCRE2_DLL PCRE2_PDB)
      endif()
    else()
	set(PCRE2_LIBRARIES)
	set(PCRE2_INCLUDE_DIRS)
endif()

mark_as_advanced(PCRE2_LIBRARIES PCRE2_INCLUDE_DIRS)
