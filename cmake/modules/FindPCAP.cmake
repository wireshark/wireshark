#
# - Find libpcap
# Find the native PCAP includes and library
#
#  PCAP_INCLUDE_DIRS - where to find pcap.h, etc.
#  PCAP_LIBRARIES    - List of libraries when using pcap.
#  PCAP_FOUND        - True if pcap found.

include(FindWSWinLibs)
FindWSWinLibs("libpcap-*" "PCAP_HINTS")

function(write_temp_pcap out_file_path)
	# We already require Python in the project main CMakeLists.txt
	# Writing a binary file that includes NULs is difficult from CMake,
	# which wants to treat everything as a NUL terminated string.
	find_package(Python3 3.6 REQUIRED)
	string(CONCAT python_script [[
with open(']] "${out_file_path}" [[', 'wb') as f:
	f.write(b'\324\303\262\241\002\000\004\000\000\000\000\000\000\000\000\000\377\377\000\000\344\000\000\000Y\371I\\\262u\003\000)\000\000\000)\000\000\000E\000\000)\000\001\000\000@\006f\314\n\000\000\001\n\000\000\002\377\230\001\273\000\000\000e\000\000\000\311P\020 \000bO\000\000\027')
]]
	)
	execute_process(
		COMMAND "${Python3_EXECUTABLE}" -c ${python_script}
		RESULT_VARIABLE python_result
	)

	if(NOT python_result EQUAL 0)
		message(FATAL_ERROR "Python failed to write temp file ${out_file_path}")
	endif()
endfunction()

set(_pcap_test_source [=[
#include <pcap/pcap.h>
#include <stdint.h>

int main(void) {
	char err_buf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *pkt_header;
	const uint8_t *pkt_data;
	/* It is important to pick a file with non-zero usec so that
	   the test works under all sizes and endianness. */
	pcap_t *pcap_h = pcap_open_offline("@temp_pcap_file@", err_buf);

	if (!pcap_h)
		return 1;
	if (pcap_next_ex(pcap_h, &pkt_header, &pkt_data) != 1)
		return 2;
	/* This doesn't access memory outside the struct whether we're
	   using 32-bit time_t and libpcap 64-bit time_t, or vice versa,
	   due to the presence of the caplen and len members. */
	if (pkt_header->ts.tv_sec != 0x5c49f959 || pkt_header->ts.tv_usec != 0x000375b2)
		return 3;

	return 0;
}
]=]
)

#
# First, try pkg-config on platforms other than Windows.
#
if(NOT USE_REPOSITORY)
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
# CMake 3.25 adds a VALIDATOR option to find_path and find_library
# that makes it easier to only find includes and libraries that have
# necessary symbols and functions.
#
#function(pcap_include_check validator_result_var item)
#  cmake_push_check_state()
#  set( CMAKE_REQUIRED_INCLUDES "${item}" )
#
#  include(CheckSymbolExists)
#
#  # libpcap 1.5.0 (2013-11-07)
#  check_symbol_exists(PCAP_ERROR_PROMISC_PERM_DENIED "pcap/pcap.h" HAVE_PCAP_ERROR_PROMISC_PERM_DENIED)
#
#  if (NOT HAVE_PCAP_ERROR_PROMISC_PERM_DENIED)
#    set(${validator_result_var} FALSE PARENT_SCOPE)
#  endif()
#
#  cmake_pop_check_state()
#endfunction()

#
# Locate the actual include directory. For pkg-config the
# PC_PCAP_INCLUDE_DIRS variable could be empty if the default
# header search path is sufficient to locate the header file.
# For macOS, the directory returned by pcap-config is wrong, so
# this will make sure to find a valid path.
#
if (WIN32 AND (CMAKE_CROSSCOMPILING OR USE_MSYSTEM))
  # For cross-compiling, just use the internal headers.
  # We have to turn off the sysroot.
  # (For cross-compiling where CMAKE_CROSSCOMPILING_EMULATOR
  # is set we could possibly take the other path.)
  find_path(PCAP_INCLUDE_DIR
    NAMES
      pcap/pcap.h
    PATHS
      "${CMAKE_SOURCE_DIR}/libpcap"
    NO_DEFAULT_PATH
    NO_CMAKE_FIND_ROOT_PATH
    #VALIDATOR pcap_include_check
  )
else()
  find_path(PCAP_INCLUDE_DIR
    NAMES
      pcap/pcap.h
    HINTS
      ${PC_PCAP_INCLUDE_DIRS}
      ${PCAP_CONFIG_INCLUDE_DIRS}
      "${PCAP_HINTS}/Include"
    PATHS
      "${CMAKE_SOURCE_DIR}/libpcap"
    #VALIDATOR pcap_include_check
  )
endif()

# On Windows we load wpcap.dll explicitly and probe its functions in
# capture\capture-wpcap.c. We don't want to link with pcap.lib since
# that would bring in the non-capturing (null) pcap.dll from the vcpkg
# library, similarly the non-capturing libpcap.dll from the MSYS2 library.
if(WIN32)
  set(_pkg_required_vars PCAP_INCLUDE_DIR)
else()
  find_library(PCAP_LIBRARY
    NAMES
      pcap
    HINTS
      ${PC_PCAP_LIBRARY_DIRS}
      ${PCAP_CONFIG_LIBRARY_DIRS}
  )
  set(_pkg_required_vars PCAP_LIBRARY PCAP_INCLUDE_DIR)
endif()

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
find_package_handle_standard_args(PCAP DEFAULT_MSG ${_pkg_required_vars})
mark_as_advanced(${_pkg_required_vars})

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
  set( CMAKE_REQUIRED_DEFINITIONS ${LFS_DEFINITIONS} ${TIME64_DEFINITIONS} )

  include(CheckSymbolExists)
  include(CheckSourceRuns)

  if(WIN32)
    #
    # Prepopulate some values. Npcap has these in its SDK, and compilation
    # checks on Windows can be slow.  We check whether they're present at run
    # time, when we load wpcap.dll, and work around their absence or report
    # an error.
    #
    set(HAVE_PCAP_INIT TRUE)
    set(HAVE_PCAP_OPEN TRUE)
    set(HAVE_PCAP_SETSAMPLING TRUE)
    set(HAVE_PCAP_SET_TSTAMP_PRECISION TRUE)
  else(WIN32)
    #
    # Make sure we have at least libpcap 1.5, because we require at
    # least libpcap 1.5's APIs.
    #
    # We check whether pcap_set_tstamp_precision is defined in the pcap header,
    # using it as a proxy for all the 1.5 API's.  if not, we fail.
    #
    check_function_exists( "pcap_set_tstamp_precision" HAVE_PCAP_SET_TSTAMP_PRECISION )
    if( NOT HAVE_PCAP_SET_TSTAMP_PRECISION )
      message(FATAL_ERROR "You need libpcap 1.5 or later")
    endif()

    # pcap_init was introduced in libpcap 1.10, so if it is present we can
    # assume other things about libpcap, even though, at least for the moment,
    # we don't use pcap_init itself on non-Windows.
    check_function_exists( "pcap_init" HAVE_PCAP_INIT )

    if(NOT CMAKE_CROSSCOMPILING AND CMAKE_SIZEOF_VOID_P EQUAL 4)
      # On 32-bit platforms, check whether libpcap was compiled with the same
      # size time_t that we're using.
      unset(PCAP_TEST_WORKS CACHE)
      set(temp_pcap_file "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/temp.pcap")
      write_temp_pcap(${temp_pcap_file})
      string(CONFIGURE "${_pcap_test_source}" pcap_test_source @ONLY)
      check_source_runs(C "${pcap_test_source}" PCAP_TEST_WORKS)

      file(REMOVE temp_pcap_file)
      if (NOT PCAP_TEST_WORKS)
        message(FATAL_ERROR "Using libpcap to read a pcap offline failed, probably because libpcap was compiled with a different size time_t.")
      endif()
    endif()

    #
    # macOS Sonoma's libpcap includes stub versions of the remote-
    # capture APIs.  They are exported as "weakly linked symbols".
    #
    # Xcode 15 offers only a macOS Sonoma SDK, which has a .tbd
    # file for libpcap that claims it includes those APIs.  (Newer
    # versions of macOS don't provide the system shared libraries,
    # they only provide the dyld shared cache containing those
    # libraries, so the OS provides SDKs that include a .tbd file
    # to use when linking.)
    #
    # This means that check_function_exists() will think that
    # the remote-capture APIs are present, including pcap_open().
    #
    # However, they are *not* present in macOS Ventura and earlier,
    # which means that building on Ventura with Xcode 15 produces
    # executables that fail to start because one of those APIs
    # isn't found in the system libpcap.
    #
    # Protecting calls to those APIs with __builtin_available()
    # does not prevent this, because the libpcap header files
    # in the Sonoma SDK mark them as being first available
    # in macOS 10.13, just like all the other routines introduced
    # in libpcap 1.9, even though they're only available if libpcap
    # is built with remote capture enabled or stub routines are
    # provided.  (A fix to enable this has been checked into the
    # libpcap repository, and may end up in a later version of
    # the SDK.)
    #
    # Given all that, and given that the versions of the
    # remote-capture APIs in Sonoma are stubs that always fail,
    # there doesn't seem to be any point in checking for pcap_open()
    # if we're linking against the Apple libpcap.
    #
    # However, if we're *not* linking against the Apple libpcap,
    # we should check for it, so that we can use it if it's present.
    #
    # So we check for pcap_open if 1) this isn't macOS or 2) the
    # the libpcap we found is not a system library, meaning that
    # its path begins neither with /usr/lib (meaning it's a system
    # dylib) nor /Application/Xcode.app (meaning it's a file in
    # the Xcode SDK).
    #
    if( NOT APPLE OR NOT
       (PCAP_LIBRARY MATCHES "/usr/lib/.*" OR
        PCAP_LIBRARY MATCHES "/Application/Xcode.app/.*"))
      check_function_exists( "pcap_open" HAVE_PCAP_OPEN )
    endif()
    if( HAVE_PCAP_OPEN )
      #
      # XXX - this *should* be checked for independently of checking
      # for pcap_open(), as you might have pcap_setsampling() without
      # remote capture support.
      #
      # However, 1) the sampling options are treated as remote options
      # in the GUI and 2) having pcap_setsampling() doesn't mean
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
    endif( HAVE_PCAP_OPEN )
  endif()

  # Remote pcap checks
  if( HAVE_PCAP_OPEN )
    set( HAVE_PCAP_REMOTE 1 )
  endif()

  check_symbol_exists(PCAP_ERROR_PROMISC_PERM_DENIED "pcap/pcap.h" HAVE_PCAP_ERROR_PROMISC_PERM_DENIED)
  if( NOT HAVE_PCAP_ERROR_PROMISC_PERM_DENIED )
    message(FATAL_ERROR "You need libpcap 1.5 or later")
  endif()

  cmake_pop_check_state()
endif()

if(PCAP_FOUND AND NOT TARGET pcap::pcap)
  if(WIN32)
    add_library(pcap::pcap INTERFACE IMPORTED)
    set_target_properties(pcap::pcap PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${PCAP_INCLUDE_DIRS}"
    )
  else()
    add_library(pcap::pcap UNKNOWN IMPORTED)
    set_target_properties(pcap::pcap PROPERTIES
      IMPORTED_LOCATION "${PCAP_LIBRARIES}"
      INTERFACE_INCLUDE_DIRECTORIES "${PCAP_INCLUDE_DIRS}"
    )
  endif()
endif()
