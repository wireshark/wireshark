# Find the native Bluetooth SBC Codec includes and library
#
#  SBC_INCLUDE_DIRS - where to find sbc.h
#  SBC_LIBRARIES    - List of libraries when using SBC
#  SBC_FOUND        - True if SBC found
#  SBC_DLL_DIR      - (Windows) Path to the SBC DLL
#  SBC_DLL          - (Windows) Name of the SBC DLL

include( FindWSWinLibs )
FindWSWinLibs( "sbc-.*" "SBC_HINTS" )

find_path( SBC_INCLUDE_DIR
  NAMES
  sbc/sbc.h
  HINTS
    "${SBC_HINTS}/include"
)

find_library( SBC_LIBRARY
  NAMES
    sbc
  HINTS
    "${SBC_HINTS}/lib"
)

include( FindPackageHandleStandardArgs )
find_package_handle_standard_args( SBC DEFAULT_MSG SBC_LIBRARY SBC_INCLUDE_DIR )

if( SBC_FOUND )
  set( SBC_INCLUDE_DIRS ${SBC_INCLUDE_DIR} )
  set( SBC_LIBRARIES ${SBC_LIBRARY} )
  if (WIN32)
    set ( SBC_DLL_DIR "${SBC_HINTS}/bin"
      CACHE PATH "Path to SBC DLL"
    )
    file( GLOB _sbc_dll RELATIVE "${SBC_DLL_DIR}"
      "${SBC_DLL_DIR}/libsbc-*.dll"
    )
    set ( SBC_DLL ${_sbc_dll}
      # We're storing filenames only. Should we use STRING instead?
      CACHE FILEPATH "SBC DLL file name"
    )
    mark_as_advanced( SBC_DLL_DIR SBC_DLL )
  endif()
else()
  set( SBC_INCLUDE_DIRS )
  set( SBC_LIBRARIES )
endif()

mark_as_advanced( SBC_LIBRARIES SBC_INCLUDE_DIRS )
