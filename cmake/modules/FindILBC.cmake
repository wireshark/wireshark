# Find the system's ilbc includes and library
#
#  ILBC_INCLUDE_DIRS - where to find ilbc.h
#  ILBC_LIBRARIES    - List of libraries when using ilbc
#  ILBC_FOUND        - True if ilbc found
#  ILBC_DLL_DIR      - (Windows) Path to the ilbc DLL
#  ILBC_DLL          - (Windows) Name of the ilbc DLL

include( FindWSWinLibs )
FindWSWinLibs( "libilbc-.*" "ILBC_HINTS" )

if (NOT WIN32)
  find_package(PkgConfig)
  pkg_search_module(PC_ILBC libilbc)
endif()

find_path(ILBC_INCLUDE_DIR
  NAMES ilbc.h
  HINTS
    "${PC_ILBC_INCLUDE_DIRS}"
    "${ILBC_HINTS}/include"
  PATHS /usr/local/include /usr/include
)

find_library(ILBC_LIBRARY
  NAMES
    ilbc
    libilbc
  HINTS
    "${PC_ILBC_LIBRARY_DIRS}"
    "${ILBC_HINTS}/lib"
  PATHS /usr/local/lib /usr/lib
)

# Check if ilbc library is WebRTC from https://github.com/TimothyGu/libilbc
if(ILBC_INCLUDE_DIR AND ILBC_LIBRARY)
  include(CheckSymbolExists)
  cmake_push_check_state()
  set(CMAKE_REQUIRED_INCLUDES ${ILBC_INCLUDE_DIR})
  set(CMAKE_REQUIRED_LIBRARIES ${ILBC_LIBRARY})
  check_symbol_exists("WebRtcIlbcfix_DecoderCreate" "ilbc.h" HAVE_ILBC_LIB_WEBRTC)
  cmake_pop_check_state()

  if(NOT HAVE_ILBC_LIB_WEBRTC)
    message(STATUS "Ignoring incompatible iLBC library.")
    # Unset the variables so the search will rerun next time
    set(ILBC_INCLUDE_DIR "ILBC_INCLUDE_DIR-NOTFOUND" CACHE PATH "" FORCE)
    set(ILBC_LIBRARY "ILBC_LIBRARY-NOTFOUND" CACHE FILEPATH "" FORCE)
    unset(HAVE_ILBC_LIB_WEBRTC CACHE)
  endif()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(ILBC DEFAULT_MSG ILBC_LIBRARY ILBC_INCLUDE_DIR)

if( ILBC_FOUND )
  set( ILBC_INCLUDE_DIRS ${ILBC_INCLUDE_DIR} )
  set( ILBC_LIBRARIES ${ILBC_LIBRARY} )
  if (WIN32)
    set ( ILBC_DLL_DIR "${ILBC_HINTS}/bin"
      CACHE PATH "Path to ilbc DLL"
    )
    file( GLOB _ilbc_dll RELATIVE "${ILBC_DLL_DIR}"
      "${ILBC_DLL_DIR}/libilbc.dll"
    )
    set ( ILBC_DLL ${_ilbc_dll}
      # We're storing filenames only. Should we use STRING instead?
      CACHE FILEPATH "ilbc DLL file name"
    )
    mark_as_advanced( ILBC_DLL_DIR ILBC_DLL )
  endif()
else()
  set( ILBC_INCLUDE_DIRS )
  set( ILBC_LIBRARIES )
endif()

mark_as_advanced( ILBC_LIBRARIES ILBC_INCLUDE_DIRS )
