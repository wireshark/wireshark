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
find_package_handle_standard_args( PCAP DEFAULT_MSG PCAP_LIBRARY PCAP_INCLUDE_DIR )

if( PCAP_FOUND )
  set( PCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR} )
  set( PCAP_LIBRARIES ${PCAP_LIBRARY} )
else()
  set( PCAP_INCLUDE_DIRS )
  set( PCAP_LIBRARIES )
endif()

if( PCAP_FOUND )
  #Functions
  include( CMakePushCheckState )
  include( CheckFunctionExists )
  include( CheckVariableExists )

  cmake_push_check_state()
  set( CMAKE_REQUIRED_INCLUDES ${PCAP_INCLUDE_DIRS} )
  set( CMAKE_REQUIRED_LIBRARIES ${PCAP_LIBRARIES} )

  if(WIN32)
    # Prepopulate some values. WinPcap and Npcap always have these and
    # compilation checks on Windows can be slow.
    set(HAVE_PCAP_OPEN_DEAD TRUE)
    set(HAVE_PCAP_FREECODE TRUE)
    set(HAVE_PCAP_BREAKLOOP TRUE)
    set(HAVE_PCAP_CREATE TRUE)
    set(HAVE_PCAP_DATALINK_NAME_TO_VAL TRUE)
    set(HAVE_PCAP_DATALINK_VAL_TO_DESCRIPTION TRUE)
    set(HAVE_PCAP_DATALINK_VAL_TO_NAME TRUE)
    set(HAVE_PCAP_FINDALLDEVS TRUE)
    set(HAVE_PCAP_FREE_DATALINKS TRUE)
    set(HAVE_PCAP_LIB_VERSION TRUE)
    set(HAVE_PCAP_LIST_DATALINKS TRUE)
    set(HAVE_PCAP_SET_DATALINK TRUE)
    set(HAVE_BPF_IMAGE TRUE)
    set(HAVE_PCAP_OPEN TRUE)
    set(HAVE_PCAP_SETSAMPLING TRUE)
  endif(WIN32)

  check_function_exists( "pcap_open_dead" HAVE_PCAP_OPEN_DEAD )
  check_function_exists( "pcap_freecode" HAVE_PCAP_FREECODE )
  #
  # Note: for pcap_breakloop() and pcap_findalldevs(), the autoconf script
  # checked for more than just whether the function exists, it also checked
  # for whether pcap.h declares it; macOS software/security updates can
  # update libpcap without updating the headers.
  #
  check_function_exists( "pcap_breakloop" HAVE_PCAP_BREAKLOOP )
  check_function_exists( "pcap_create" HAVE_PCAP_CREATE )
  if( HAVE_PCAP_CREATE )
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
  check_function_exists( "pcap_set_tstamp_precision" HAVE_PCAP_SET_TSTAMP_PRECISION )
  check_function_exists( "pcap_set_tstamp_type" HAVE_PCAP_SET_TSTAMP_TYPE )
  # Remote pcap checks
  check_function_exists( "pcap_open" HAVE_PCAP_OPEN )
  if( HAVE_PCAP_OPEN )
    set( HAVE_PCAP_REMOTE 1 )
    #
    # XXX - this *should* be checked for independently of checking
    # for pcap_open(), as you might have pcap_setsampling() without
    # remote capture support.
    #
    # However, 1) the sampling options are treated as remote options
    # in the GUI and and 2) having pcap_setsampling() doesn't mean
    # you have sampling support.  libpcap needs a way to indicate
    # whether a given device supports sampling, and the GUI should
    # be changed to decouple them.
    #
    # (Actually, libpcap needs a general mechanism to offer options
    # for particular devices, and Wireshark needs to use that
    # mechanism.  The former is a work in progress.)
    #
    # (Note: another work in progress is support for remote
    # capturing using pcap_create()/pcap_activate(), which we
    # also need to support once it's available.)
    #
    check_function_exists( "pcap_setsampling" HAVE_PCAP_SETSAMPLING )
  endif()

  cmake_pop_check_state()
endif()

mark_as_advanced( PCAP_LIBRARIES PCAP_INCLUDE_DIRS )
