#
# - Find airpcap
# Find the native AIRPCAP includes and library
#
#  AIRPCAP_INCLUDE_DIRS - where to find pcap.h, etc.
#  AIRPCAP_LIBRARIES    - List of libraries when using pcap.
#  AIRPCAP_FOUND        - True if pcap found.

include( FindWSWinLibs )
FindWSWinLibs( "AirPcap" AIRPCAP_TMP_HINTS )
#message( STATUS "AIRPCAP TMP HINTS: ${AIRPCAP_TMP_HINTS}" )
FindWSWinLibs( "Airpcap_" AIRPCAP_HINTS "${AIRPCAP_TMP_HINTS}" )
#message( STATUS "AIRPCAP HINTS: ${AIRPCAP_HINTS}" )

find_path( AIRPCAP_INCLUDE_DIR
  NAMES
  airpcap.h
  pcap.h
  HINTS
    "${AIRPCAP_HINTS}/include"
)

find_library( AIRPCAP_LIBRARY
  NAMES
    airpcap
  HINTS
    "${AIRPCAP_HINTS}/lib"
)


include( FindPackageHandleStandardArgs )
find_package_handle_standard_args( AIRPCAP DEFAULT_MSG AIRPCAP_INCLUDE_DIR AIRPCAP_LIBRARY )

if( AIRPCAP_FOUND )
  set( AIRPCAP_INCLUDE_DIRS ${AIRPCAP_INCLUDE_DIR} )
  set( AIRPCAP_LIBRARIES ${AIRPCAP_LIBRARY} )
else()
  set( AIRPCAP_INCLUDE_DIRS )
  set( AIRPCAP_LIBRARIES )
endif()

mark_as_advanced( AIRPCAP_LIBRARIES AIRPCAP_INCLUDE_DIRS )
