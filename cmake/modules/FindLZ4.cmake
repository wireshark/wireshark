#
# - Find lz4
# Find LZ4 includes and library
#
#  LZ4_INCLUDE_DIRS  - where to find lz4.h, etc.
#  LZ4_LIBRARIES     - List of libraries when using LZ4.
#  LZ4_FOUND         - True if LZ4 found.
#  LZ4_DLL_DIR       - (Windows) Path to the LZ4 DLL
#  LZ4_DLL           - (Windows) Name of the LZ4 DLL
#  LZ4_PDB           - (Windows) Name of the LZ4 PDB
#  LZ4_DLL_DIR_DEBUG - (Windows) Path to the LZ4 Debug DLL
#  LZ4_DLL_DEBUG     - (Windows) Name of the LZ4 Debug DLL
#  LZ4_PDB_DEBUG     - (Windows) Name of the LZ4 Debug PDB
#
# Creates an IMPORTED target LZ4::LZ4 if found

include( FindWSWinLibs )
FindWSWinLibs( "lz4-.*" "LZ4_HINTS" )

if( NOT USE_REPOSITORY)
  find_package(PkgConfig)
  pkg_search_module(LZ4 lz4 liblz4)
endif()

find_path(LZ4_INCLUDE_DIR
  NAMES lz4.h
  HINTS "${LZ4_INCLUDEDIR}" "${LZ4_HINTS}/include"
  PATHS
    /usr/local/include
    /usr/include
)

include(FindWSLibrary)
FindWSLibrary(LZ4_LIBRARY
  NAMES lz4 liblz4 lz4d
  HINTS "${LZ4_LIBDIR}"
  PATHS
    /usr/local/lib
    /usr/lib
  WIN32_HINTS
    "${LZ4_HINTS}"
)

if (LZ4_INCLUDE_DIR)
  file(STRINGS ${LZ4_INCLUDE_DIR}/lz4.h _lz4_version_lines
    REGEX "#define[ \t]+LZ4_VERSION_(MAJOR|MINOR|RELEASE)[ \t]+[0-9]+")
  string(REGEX REPLACE "^.*LZ4_VERSION_MAJOR +\([0-9]+\).*" "\\1" LZ4_VERSION_MAJOR "${_lz4_version_lines}")
  string(REGEX REPLACE "^.*LZ4_VERSION_MINOR +\([0-9]+\).*" "\\1" LZ4_VERSION_MINOR "${_lz4_version_lines}")
  string(REGEX REPLACE "^.*LZ4_VERSION_RELEASE +\([0-9]+\).*" "\\1" LZ4_VERSION_RELEASE "${_lz4_version_lines}")
  set(LZ4_VERSION ${LZ4_VERSION_MAJOR}.${LZ4_VERSION_MINOR}.${LZ4_VERSION_RELEASE})
  unset(_lz4_version_lines)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LZ4
  REQUIRED_VARS LZ4_LIBRARY LZ4_INCLUDE_DIR
  VERSION_VAR LZ4_VERSION
)

if( LZ4_FOUND )
  include( CheckIncludeFile )
  include( CMakePushCheckState )

  set( LZ4_INCLUDE_DIRS ${LZ4_INCLUDE_DIR} )
  set( LZ4_LIBRARIES ${LZ4_LIBRARY} )

  cmake_push_check_state()
  set( CMAKE_REQUIRED_INCLUDES ${LZ4_INCLUDE_DIRS} )
  # lz4frame.h should be present at least in versions >= 1.7.3
  check_include_file( lz4frame.h HAVE_LZ4FRAME_H )
  cmake_pop_check_state()

  AddWSWinDLL(LZ4 LZ4_HINTS "lz4*")

  if (NOT TARGET LZ4::LZ4)
    add_library(LZ4::LZ4 UNKNOWN IMPORTED)
    if (USE_REPOSITORY)
      set_target_properties(LZ4::LZ4 PROPERTIES
        IMPORTED_CONFIGURATIONS "RELEASE;DEBUG"
        IMPORTED_LOCATION "${LZ4_LIBRARY_RELEASE}"
        IMPORTED_LOCATION_DEBUG "${LZ4_LIBRARY_DEBUG}"
        INTERFACE_INCLUDE_DIRECTORIES "${LZ4_INCLUDE_DIR}"
      )
    else()
      set_target_properties(LZ4::LZ4 PROPERTIES
        IMPORTED_LOCATION "${LZ4_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${LZ4_INCLUDE_DIR}"
      )
    endif()
  endif()

else()
  set( LZ4_INCLUDE_DIRS )
  set( LZ4_LIBRARIES )
endif()

mark_as_advanced( LZ4_LIBRARIES LZ4_INCLUDE_DIRS )
