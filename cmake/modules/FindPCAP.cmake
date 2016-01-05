#
# - Find pcap and winpcap
# Find the native PCAP includes and library
#
#  PCAP_INCLUDE_DIRS - where to find pcap.h, etc.
#  PCAP_LIBRARIES    - List of libraries when using pcap.
#  PCAP_FOUND        - True if pcap found.

include( FindWSWinLibs )
FindWSWinLibs( "WpdPack" "PCAP_HINTS" )

# The 64-bit wpcap.lib is under /x64
set ( _PLATFORM_SUBDIR "" )
if( WIN32 AND "${WIRESHARK_TARGET_PLATFORM}" STREQUAL "win64" )
  set ( _PLATFORM_SUBDIR "/x64" )
endif()

find_path( PCAP_INCLUDE_DIR
  NAMES
  pcap/pcap.h
  pcap.h
  HINTS
    "${PCAP_HINTS}/include"
)

find_library( PCAP_LIBRARY
  NAMES
    pcap
    wpcap
  HINTS
    "${PCAP_HINTS}/lib${_PLATFORM_SUBDIR}"
)


include( FindPackageHandleStandardArgs )
find_package_handle_standard_args( PCAP DEFAULT_MSG PCAP_INCLUDE_DIR PCAP_LIBRARY )

if( PCAP_FOUND )
  set( PCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR} )
  set( PCAP_LIBRARIES ${PCAP_LIBRARY} )
else()
  set( PCAP_INCLUDE_DIRS )
  set( PCAP_LIBRARIES )
endif()

#Functions
include( CMakePushCheckState )
include( CheckFunctionExists )
include( CheckVariableExists )

cmake_push_check_state()
set( CMAKE_REQUIRED_INCLUDES ${PCAP_INCLUDE_DIRS} )
set( CMAKE_REQUIRED_LIBRARIES ${PCAP_LIBRARIES} )

check_function_exists( "pcap_open_dead" HAVE_PCAP_OPEN_DEAD )
check_function_exists( "pcap_freecode" HAVE_PCAP_FREECODE )
#
# Note: for pcap_breakloop() and pcap_findalldevs(), the autoconf script
# checks for more than just whether the function exists, it also checks
# for whether pcap.h declares it; Mac OS X software/security updates can
# update libpcap without updating the headers.
#
check_function_exists( "pcap_breakloop" HAVE_PCAP_BREAKLOOP )
check_function_exists( "pcap_create" HAVE_PCAP_CREATE )
if( HAVE_PCAP_CREATE OR WIN32 )
 #
 # If we have pcap_create(), we have pcap_set_buffer_size(), and
 # can set the capture buffer size.
 #
 # Otherwise, if this is Windows, we have pcap_setbuff(), and can
 # set the capture buffer size.
 #
 set( CAN_SET_CAPTURE_BUFFER_SIZE TRUE )
endif()
check_function_exists( "pcap_datalink_name_to_val" HAVE_PCAP_DATALINK_NAME_TO_VAL )
check_function_exists( "pcap_datalink_val_to_description" HAVE_PCAP_DATALINK_VAL_TO_DESCRIPTION )
check_function_exists( "pcap_datalink_val_to_name" HAVE_PCAP_DATALINK_VAL_TO_NAME )
check_function_exists( "pcap_findalldevs" HAVE_PCAP_FINDALLDEVS )
check_function_exists( "pcap_free_datalinks" HAVE_PCAP_FREE_DATALINKS )
check_function_exists( "pcap_get_selectable_fd" HAVE_PCAP_GET_SELECTABLE_FD )
check_function_exists( "pcap_lib_version" HAVE_PCAP_LIB_VERSION )
check_function_exists( "pcap_list_datalinks" HAVE_PCAP_LIST_DATALINKS )
check_function_exists( "pcap_set_datalink" HAVE_PCAP_SET_DATALINK )
check_function_exists( "bpf_image" HAVE_BPF_IMAGE )
check_function_exists( "pcap_setsampling" HAVE_PCAP_SETSAMPLING )
check_function_exists( "pcap_set_tstamp_precision" HAVE_PCAP_SET_TSTAMP_PRECISION )
# Remote pcap checks
check_function_exists( "pcap_open" HAVE_PCAP_OPEN )
if( HAVE_PCAP_OPEN )
  set( HAVE_PCAP_REMOTE 1 )
  set( HAVE_REMOTE 1 )
endif()

cmake_pop_check_state()

mark_as_advanced( PCAP_LIBRARIES PCAP_INCLUDE_DIRS )
