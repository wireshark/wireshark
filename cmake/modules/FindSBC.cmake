# Find the native Bluetooth SBC Codec includes and library
#
#  SBC_INCLUDE_DIRS - where to find sbc.h
#  SBC_LIBRARIES    - List of libraries when using SBC
#  SBC_FOUND        - True if SBC found

include( FindWSWinLibs )
FindWSWinLibs( "sbc" "SBC_HINTS" )

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
find_package_handle_standard_args( SBC DEFAULT_MSG SBC_INCLUDE_DIR SBC_LIBRARY )

if( SBC_FOUND )
  set( SBC_INCLUDE_DIRS ${SBC_INCLUDE_DIR} )
  set( SBC_LIBRARIES ${SBC_LIBRARY} )
else()
  set( SBC_INCLUDE_DIRS )
  set( SBC_LIBRARIES )
endif()

mark_as_advanced( SBC_LIBRARIES SBC_INCLUDE_DIRS )
