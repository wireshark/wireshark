#
# - Find pcap and winpcap
# Find the native PCAP includes and library
#
#  PCAP_INCLUDE_DIRS - where to find pcap.h, etc.
#  PCAP_LIBRARIES    - List of libraries when using pcap.
#  PCAP_FOUND        - True if pcap found.

include(FindWSWinLibs)
FindWSWinLibs("WpdPack" "PCAP_HINTS")

# The 64-bit wpcap.lib is under /x64
set(_PLATFORM_SUBDIR "")
if(WIN32 AND WIRESHARK_TARGET_PLATFORM STREQUAL "win64")
  set(_PLATFORM_SUBDIR "/x64")
endif()

#
# First, try pkg-config on platforms other than Windows.
#
if(NOT WIN32)
  find_package(PkgConfig)
  pkg_search_module(PC_PCAP libpcap)
endif()

if(NOT PC_PCAP_FOUND AND NOT WIN32)
  #
  # That didn't work.  Try to retrieve hints from pcap-config.
  # Do not use it on Windows as pcap-config is a shell script.
  #
  find_program(PCAP_CONFIG pcap-config)
  if(PCAP_CONFIG)
    #
    # We have pcap-config; use it.
    #
    # First, get the include directory.
    #
    execute_process(COMMAND "${PCAP_CONFIG}" "--cflags"
      RESULT_VARIABLE PCAP_CONFIG_RESULT
      OUTPUT_VARIABLE PCAP_CONFIG_OUTPUT
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(NOT PCAP_CONFIG_RESULT EQUAL 0)
      message(FATAL_ERROR "pcap-config --cflags failed")
    endif()
    #
    # Assumes there's exactly one -I flag in the output
    # of pcap-config --cflags.  That *should* be the case.
    # Note that the hint might be bogus, on macOS it could be
    # -I/usr/local/include even though the header isn't
    # there (it may be under /usr/include or it may be
    # buried in the Xcode app bundle).
    #
    string(REGEX REPLACE "^-I" "" PCAP_CONFIG_INCLUDE_DIRS "${PCAP_CONFIG_OUTPUT}")

    # Now, get the library search path.
    execute_process(COMMAND "${PCAP_CONFIG}" "--libs"
      RESULT_VARIABLE PCAP_CONFIG_RESULT
      OUTPUT_VARIABLE PCAP_CONFIG_OUTPUT
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(NOT PCAP_CONFIG_RESULT EQUAL 0)
      message(FATAL_ERROR "pcap-config --libs failed")
    endif()
    separate_arguments(LIBS_LIST UNIX_COMMAND ${PCAP_CONFIG_OUTPUT})
    set(PCAP_CONFIG_LIBRARY_DIRS "")
    foreach(_arg IN LISTS LIBS_LIST)
      # At most one -L path is expected for -lpcap.
      if(_arg MATCHES "^-L")
        string(REGEX REPLACE "^-L" "" _dir ${_arg})
        list(APPEND PCAP_CONFIG_LIBRARY_DIRS ${_dir})
      endif()
    endforeach()

    if(UNIX AND CMAKE_FIND_LIBRARY_SUFFIXES STREQUAL ".a")
      # Now, get the library directories and libraries for static linking.
      # (XXX - what about AIX?)
      execute_process(COMMAND "${PCAP_CONFIG}" "--libs" "--static"
        RESULT_VARIABLE PCAP_CONFIG_RESULT
        OUTPUT_VARIABLE PCAP_CONFIG_OUTPUT
      )
      if(NOT PCAP_CONFIG_RESULT EQUAL 0)
        message(FATAL_ERROR "pcap-config --libs --static failed")
      endif()
      separate_arguments(LIBS_LIST UNIX_COMMAND ${PCAP_CONFIG_OUTPUT})
      set(PCAP_CONFIG_STATIC_LIBRARY_DIRS "")
      set(PCAP_CONFIG_STATIC_LIBRARIES "")
      foreach(_arg IN LISTS LIBS_LIST)
        if(_arg MATCHES "^-L")
          # Add this directory to the library directory hints.
          string(REGEX REPLACE "^-L" "" _dir ${_arg})
          list(APPEND PCAP_CONFIG_STATIC_LIBRARY_DIRS ${_dir})
        elseif(_arg MATCHES "^-l")
          # Add this library to the requirements for static linking.
          string(REGEX REPLACE "^-l" "" _lib ${_arg})
          list(APPEND PCAP_CONFIG_STATIC_LIBRARIES ${_lib})
        endif()
      endforeach()
    endif()
  endif()
endif()

#
# Locate the actual include directory. For pkg-config the
# PC_PCAP_INCLUDE_DIRS variable could be empty if the default
# header search path is sufficient to locate the header file.
# For macOS, the directory returned by pcap-config is wrong, so
# this will make sure to find a valid path.
#
find_path(PCAP_INCLUDE_DIR
  NAMES
    pcap/pcap.h
    pcap.h
  HINTS
    ${PC_PCAP_INCLUDE_DIRS}
    ${PCAP_CONFIG_INCLUDE_DIRS}
    "${PCAP_HINTS}/Include"
)

find_library(PCAP_LIBRARY
  NAMES
    pcap
    wpcap
  HINTS
    ${PC_PCAP_LIBRARY_DIRS}
    ${PCAP_CONFIG_LIBRARY_DIRS}
    "${PCAP_HINTS}/Lib${_PLATFORM_SUBDIR}"
)

if(UNIX AND CMAKE_FIND_LIBRARY_SUFFIXES STREQUAL ".a")
  # Try to find the static library (XXX - what about AIX?)
  if(PC_PCAP_FOUND)
    set(_pcap_static_libraries ${PC_PCAP_STATIC_LIBRARIES})
  elseif(PCAP_CONFIG)
    set(_pcap_static_libraries ${PCAP_CONFIG_STATIC_LIBRARIES})
  else()
    #
    # No pkg-config nor pcap-config found, hope that this single library is
    # sufficient for static linking.
    #
    set(_pcap_static_libraries pcap)
  endif()

  set(PCAP_STATIC_LIBRARIES "")
  foreach(_lib IN LISTS _pcap_static_libraries)
    #
    # Try to find that library, so we get its full path, as
    # we do with dynamic libraries.
    #
    string(MAKE_C_IDENTIFIER "PCAP_STATIC_${_lib}_LIBRARY" _libvar)
    find_library(${_libvar} ${_lib}
      HINTS
      ${PC_PCAP_STATIC_LIBRARY_DIRS}
      ${PCAP_CONFIG_STATIC_LIBRARY_DIRS}
    )
    set(_libpath ${${_libvar}})
    if(_libpath)
      list(APPEND PCAP_STATIC_LIBRARIES ${_libpath})
    endif()
  endforeach()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCAP DEFAULT_MSG PCAP_LIBRARY PCAP_INCLUDE_DIR)
mark_as_advanced(PCAP_LIBRARY PCAP_INCLUDE_DIR)

if(PCAP_FOUND)
  set(PCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR})
  if(UNIX AND CMAKE_FIND_LIBRARY_SUFFIXES STREQUAL ".a")
    # Link with static libpcap and its transitive dependencies.
    set(PCAP_LIBRARIES ${PCAP_STATIC_LIBRARIES})
  else()
    set(PCAP_LIBRARIES ${PCAP_LIBRARY})
  endif()

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

if(PCAP_FOUND AND NOT TARGET pcap::pcap)
  add_library(pcap::pcap UNKNOWN IMPORTED)
  set_target_properties(pcap::pcap PROPERTIES
    IMPORTED_LOCATION "${PCAP_LIBRARIES}"
    INTERFACE_INCLUDE_DIRECTORIES "${PCAP_INCLUDE_DIRS}"
  )
endif()
