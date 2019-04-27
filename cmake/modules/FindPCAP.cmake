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

#
# First, try pkg-config.
#
find_package( PkgConfig )
pkg_search_module( PCAP libpcap )

if( PCAP_FOUND )
  #
  # That worked.
  # Now, for each library, try to find it, so we get its full path.
  # CMake *really* doesn't like the notion of specifying "here are
  # the directories in which to look for libraries" except in
  # find_library() calls; it *really* prefers using full paths to
  # library files, rather than library names.
  #
  set( _pcap_libraries "${PCAP_LIBRARIES}" )
  set( PCAP_LIBRARIES "" )
  foreach( _lib IN LISTS _pcap_libraries )
      #
      # Try to find that library.
      #
      find_library( _libfullpath ${_lib} HINTS ${PCAP_LIBRARY_DIRS} )
      list( APPEND PCAP_LIBRARIES ${_libfullpath} )
      #
      # Remove that from the cache; we're using it as a local variable,
      # but find_library insists on making it a cache variable.
      #
      unset( _libfullpath CACHE )
    endforeach()

    #
    # Now find the static libraries.
    # (XXX - what about AIX?)
    #
    set( _pcap_static_libraries "${PCAP_STATIC_LIBRARIES}" )
    set( PCAP_STATIC_LIBRARIES "" )
    set( SAVED_CMAKE_FIND_LIBRARY_SUFFIXES "${CMAKE_FIND_LIBRARY_SUFFIXES}" )
    set( CMAKE_FIND_LIBRARY_SUFFIXES ".a" )
    foreach( _lib IN LISTS _pcap_static_libraries )
      #
      # Try to find that library, so we get its full path, as
      # we do with dynamic libraries.
      #
      find_library( _libfullpath ${_lib} HINTS ${PCAP_LIBRARY_DIRS} )
      list( APPEND PCAP_STATIC_LIBRARIES ${_libfullpath} )
      #
      # Remove that from the cache; we're using it as a local variable,
      # but find_library insists on making it a cache variable.
      #
      unset( _libfullpath CACHE )
    endforeach()
    set( CMAKE_FIND_LIBRARY_SUFFIXES "${SAVED_CMAKE_FIND_LIBRARY_SUFFIXES}" )
else( PCAP_FOUND )
  #
  # That didn't work.  Try pcap-config.
  #
  find_program( PCAP_CONFIG pcap-config )
  if( PCAP_CONFIG )
    #
    # We have pcap-config; use it.
    # XXX - what if this is on Windows?  If you're using, for example,
    # MinGW, that might be the right thing to do, *if* pcap-config
    # were made to work properly on Windows, but what about MSVC?
    #
    # First, get the include directory.
    #
    execute_process( COMMAND "${PCAP_CONFIG}" "--cflags"
      RESULT_VARIABLE PCAP_CONFIG_RESULT
      OUTPUT_VARIABLE PCAP_CONFIG_OUTPUT
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if( NOT PCAP_CONFIG_RESULT EQUAL 0 )
      message( FATAL_ERROR "pcap-config --cflags failed" )
    endif()
    #
    # XXX - this assumes that there's only one -I flag in the output
    # of pcap-config --cflags.  That *should* be the case.
    #
    string(REGEX REPLACE "-I" "" _pcap_include_dir "${PCAP_CONFIG_OUTPUT}")

    # Try to find the header
    # We use what pcap-config provided as a hint, because the
    # pcap-config that ships with macOS bogusly supplies
    # -I/usr/local/include even though the header isn't
    # there (it may be under /usr/include or it may be
    # buried in the Xcode app bundle).
    find_path(PCAP_INCLUDE_DIRS pcap.h HINTS ${_pcap_include_dir})

    # Now, get the libraries.
    execute_process( COMMAND "${PCAP_CONFIG}" "--libs"
      RESULT_VARIABLE PCAP_CONFIG_RESULT
      OUTPUT_VARIABLE PCAP_CONFIG_OUTPUT
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if( NOT PCAP_CONFIG_RESULT EQUAL 0 )
      message( FATAL_ERROR "pcap-config --libs failed" )
    endif()
    separate_arguments( LIBS_LIST UNIX_COMMAND ${PCAP_CONFIG_OUTPUT} )
    set( _pcap_library_dirs "" )
    set( PCAP_LIBRARIES "" )
    foreach( _arg IN LISTS LIBS_LIST )
      if( _arg MATCHES "^-L" )
        # Add this directory to _pcap_library_dirs
        string( REGEX REPLACE "-L" "" _dir ${_arg} )
        list( APPEND _pcap_library_dirs ${_dir} )
      elseif( _arg MATCHES "^-l" )
        string( REGEX REPLACE "-l" "" _lib ${_arg} )
        #
        # Try to find that library, so we get its full path.  See the
        # comment above for why we do this.
        #
        # Furthermore, the pcap-config shipped with macOS reports
        # -I/usr/local/include for --cflags and -L/usr/local/lib for
        # --libs, rather than reporting the appropriate system (or
        # Xcode application) directory.
        #
        find_library( _libfullpath ${_lib} HINTS ${__pcap_library_dirs} )
        list( APPEND PCAP_LIBRARIES ${_libfullpath} )
        #
        # Remove that from the cache; we're using it as a local variable,
        # but find_library insists on making it a cache variable.
        #
        unset( _libfullpath CACHE )
      endif()
    endforeach()

    # Now, get the library directories and libraries for static linking.
    # (XXX - what about AIX?)
    execute_process( COMMAND "${PCAP_CONFIG}" "--libs" "--static"
      RESULT_VARIABLE PCAP_CONFIG_RESULT
      OUTPUT_VARIABLE PCAP_CONFIG_OUTPUT
    )
    if( NOT PCAP_CONFIG_RESULT EQUAL 0 )
      message( FATAL_ERROR "pcap-config --libs --static failed" )
    endif()
    separate_arguments( LIBS_LIST UNIX_COMMAND ${PCAP_CONFIG_OUTPUT} )
    set( _pcap_static_library_dirs "" )
    set( PCAP_STATIC_LIBRARIES "" )
    set( SAVED_CMAKE_FIND_LIBRARY_SUFFIXES "${CMAKE_FIND_LIBRARY_SUFFIXES}" )
    set( CMAKE_FIND_LIBRARY_SUFFIXES ".a" )
    foreach( _arg IN LISTS LIBS_LIST )
      if( _arg MATCHES "^-L" )
        # Add this directory to _pcap_static_library_dirs
        string( REGEX REPLACE "-L" "" _dir ${_arg} )
        list( APPEND _pcap_static_library_dirs ${_dir} )
      elseif( _arg MATCHES "^-l" )
        string( REGEX REPLACE "-l" "" _lib ${_arg} )
        #
        # Try to find that library, so we get its full path, as
        # we do with dynamic libraries.
        #
        find_library( _libfullpath ${_lib} HINTS ${__pcap_static_library_dirs} )
        list( APPEND PCAP_STATIC_LIBRARIES ${_libfullpath} )
        #
        # Remove that from the cache; we're using it as a local variable,
        # but find_library insists on making it a cache variable.
        #
        unset( _libfullpath CACHE )
      endif()
    endforeach()

    set( CMAKE_FIND_LIBRARY_SUFFIXES "${SAVED_CMAKE_FIND_LIBRARY_SUFFIXES}" )
  else( PCAP_CONFIG )
    #
    # We don't have pcap-config.
    # Try to find the header by just looking for it in whatever
    # directories find_path() uses by default, plus ${PCAP_HINTS}.
    #
    find_path( PCAP_INCLUDE_DIRS
      NAMES
      pcap/pcap.h
      pcap.h
      HINTS
      "${PCAP_HINTS}/include"
    )

    # Try to find the library
    if( WIN32 )
      # The 64-bit Packet.lib is located under /x64
      if( "${WIRESHARK_TARGET_PLATFORM}" STREQUAL "win64" )
        #
        # For the WinPcap and Npcap SDKs, the Lib subdirectory of the top-level
        # directory contains 32-bit libraries; the 64-bit libraries are in the
        # Lib/x64 directory.
        #
        # The only way to *FORCE* CMake to look in the Lib/x64 directory
        # without searching in the Lib directory first appears to be to set
        # CMAKE_LIBRARY_ARCHITECTURE to "x64".
        #
        set(CMAKE_LIBRARY_ARCHITECTURE "x64")
      endif()
    endif()

    find_library( PCAP_LIBRARIES
      NAMES
        pcap
        wpcap
      HINTS
        "${PCAP_HINTS}/lib${_PLATFORM_SUBDIR}"
    )

    if( NOT WIN32 )
      # Try to find the static library (XXX - what about AIX?)
      set( SAVED_CMAKE_FIND_LIBRARY_SUFFIXES "${CMAKE_FIND_LIBRARY_SUFFIXES}")
      set( CMAKE_FIND_LIBRARY_SUFFIXES ".a" )
      find_library( PCAP_STATIC_LIBRARIES
        NAMES
          pcap
          wpcap
        HINTS
          "${PCAP_HINTS}/lib${_PLATFORM_SUBDIR}"
      )
      set( CMAKE_FIND_LIBRARY_SUFFIXES "${SAVED_CMAKE_FIND_LIBRARY_SUFFIXES}")
    endif( NOT WIN32 )
  endif( PCAP_CONFIG )
endif( PCAP_FOUND )

include( FindPackageHandleStandardArgs )
find_package_handle_standard_args( PCAP DEFAULT_MSG PCAP_LIBRARIES PCAP_INCLUDE_DIRS )

mark_as_advanced( PCAP_INCLUDE_DIR PCAP_LIBRARY PCAP_STATIC_LIBRARY )

if( PCAP_FOUND )
  # Include transitive dependencies for static linking.
  if( UNIX AND CMAKE_FIND_LIBRARY_SUFFIXES STREQUAL ".a" )
    set( PCAP_LIBRARIES ${PCAP_STATIC_LIBRARIES} )
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
