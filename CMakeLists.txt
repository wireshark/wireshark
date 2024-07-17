# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
if(DEFINED ENV{FORCE_CMAKE_NINJA_NON_VERBOSE})
	#
	# Forcibly unset CMAKE_VERBOSE_MAKEFILE,
	# to make *CERTAIN* that we don't do
	# anything verbose here!
	#
	unset(CMAKE_VERBOSE_MAKEFILE CACHE)
endif()

# Needed for add_custom_command() WORKING_DIRECTORY generator expressions
cmake_minimum_required(VERSION 3.13)
if(POLICY CMP0083)
	cmake_policy(SET CMP0083 NEW)
endif()
if(POLICY CMP0092)
	cmake_policy(SET CMP0092 NEW)
endif()
if(POLICY CMP0135)
	cmake_policy(SET CMP0135 NEW)
endif()

if(WIN32 AND NOT DEFINED ENV{MSYSTEM})
	set(_project_name Wireshark)
	set(_log_project_name Logray)
else()
	set(_project_name wireshark)
	set(_log_project_name logray)
endif()

project(${_project_name} C CXX)

if(WIN32)
	set(_msystem False)
	set(_repository False)
	if(DEFINED ENV{MSYSTEM})
		set(_msystem $ENV{MSYSTEM})
		message(STATUS "Using MSYS2 with MSYSTEM=${_msystem}")
	elseif(MSVC)
		set(_repository True)
		message(STATUS "Using 3rd party repository")
	else()
		# Neither own package repository nor MSYS2 repository.
	endif()
	set(USE_MSYSTEM ${_msystem} CACHE INTERNAL "Use MSYS2 subsystem")
	set(HAVE_MSYSTEM ${USE_MSYSTEM}) # For config.h
	set(USE_REPOSITORY ${_repository} CACHE INTERNAL "Use Wireshark 3rd Party Repository")
endif()

# Updated by tools/make-version.py
set(PROJECT_MAJOR_VERSION 4)
set(PROJECT_MINOR_VERSION 3)
set(PROJECT_PATCH_VERSION 1)
set(PROJECT_BUILD_VERSION 0)
set(PROJECT_VERSION_EXTENSION "")

if(DEFINED ENV{WIRESHARK_VERSION_EXTRA})
	set(PROJECT_VERSION_EXTENSION "$ENV{WIRESHARK_VERSION_EXTRA}")
endif()

set(PROJECT_VERSION "${PROJECT_MAJOR_VERSION}.${PROJECT_MINOR_VERSION}.${PROJECT_PATCH_VERSION}${PROJECT_VERSION_EXTENSION}")

set(LOG_PROJECT_NAME ${_log_project_name})
set(LOG_PROJECT_MAJOR_VERSION 0)
set(LOG_PROJECT_MINOR_VERSION 9)
set(LOG_PROJECT_PATCH_VERSION 0)
set(LOG_PROJECT_VERSION "${LOG_PROJECT_MAJOR_VERSION}.${LOG_PROJECT_MINOR_VERSION}.${LOG_PROJECT_PATCH_VERSION}${PROJECT_VERSION_EXTENSION}")

include( CMakeOptions.txt )

# We require minimum C11
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# We require minimum C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

message(STATUS "Generating build using CMake ${CMAKE_VERSION}")

if(USE_MSYSTEM)
	# Use the deprecated FindPythonInterp.cmake module to Work around bugs and odd behavior in MSYS2 CMake
	# searching in the wrong paths for python3.exe using FindPython3.cmake
	find_package(PythonInterp REQUIRED)
	set(Python3_EXECUTABLE ${PYTHON_EXECUTABLE} CACHE FILEPATH "")
else()
	find_package(Python3 3.6 REQUIRED)
endif()

# Set a default build type if none was specified
set(_default_build_type "RelWithDebInfo")
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
	set(CMAKE_BUILD_TYPE "${_default_build_type}" CACHE STRING "Choose the type of build." FORCE)
	# Set the possible values of build type for cmake-gui
	set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

# Build type is ignored by multi-config generators.
if (NOT CMAKE_CONFIGURATION_TYPES)
	message(STATUS "Using \"${CMAKE_GENERATOR}\" generator and build type \"${CMAKE_BUILD_TYPE}\"")
else()
	message(STATUS "Using \"${CMAKE_GENERATOR}\" generator (multi-config)")
endif()

#Where to find local cmake scripts
set(WS_CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules)
set(CMAKE_MODULE_PATH ${WS_CMAKE_MODULE_PATH})

# CMake >= 3.9.0 supports LTO/IPO.
if (ENABLE_LTO)
	include(CheckIPOSupported)
	check_ipo_supported(RESULT lto_supported OUTPUT lto_output)
	if(lto_supported)
		set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
		message(STATUS "LTO/IPO is enabled for Release configuration")
	else()
		message(STATUS "LTO/IPO requested but it is not supported by the compiler: ${lto_output}")
	endif()
else()
	message(STATUS "LTO/IPO is not enabled")
endif()

# If our target platform is enforced by our generator, set
# WIRESHARK_TARGET_PLATFORM accordingly. Otherwise use
# %WIRESHARK_TARGET_PLATFORM%.

if(WIN32)
	if(DEFINED ENV{WIRESHARK_TARGET_PLATFORM})
		string(TOLOWER $ENV{WIRESHARK_TARGET_PLATFORM} _target_platform)
		set(WIRESHARK_TARGET_PLATFORM ${_target_platform})
	elseif(USE_MSYSTEM MATCHES "MINGW64|CLANG64|UCRT64")
		# https://www.msys2.org/docs/environments
		#    MSYS2 comes with different environments/subsystems and
		#    the first thing you have to decide is which one to use.
		#    The differences among the environments are mainly environment
		#    variables, default compilers/linkers, architecture,
		#    system libraries used etc. If you are unsure, go with UCRT64.
		set(WIRESHARK_TARGET_PLATFORM x64)
	elseif(USE_MSYSTEM)
		if($ENV{MSYSTEM_CARCH} MATCHES "x86_64")
			set(WIRESHARK_TARGET_PLATFORM x64)
		elseif($ENV{MSYSTEM_CARCH} MATCHES "i686")
			set(WIRESHARK_TARGET_PLATFORM win32)
		elseif($ENV{MSYSTEM_CARCH} MATCHES "aarch64")
			set(WIRESHARK_TARGET_PLATFORM "arm64")
		else()
			set(WIRESHARK_TARGET_PLATFORM "$ENV{MSYSTEM_CARCH}")
		endif()
	elseif($ENV{Platform} MATCHES arm64 OR CMAKE_GENERATOR_PLATFORM MATCHES arm64)
		set(WIRESHARK_TARGET_PLATFORM arm64)
	elseif(CMAKE_CL_64 OR CMAKE_GENERATOR MATCHES x64)
		set(WIRESHARK_TARGET_PLATFORM x64)
	else()
		message(WARNING "Assuming \"x64\" target platform")
		set(WIRESHARK_TARGET_PLATFORM x64)
	endif()

	if(WIRESHARK_TARGET_PLATFORM MATCHES "win32")
		message(FATAL_ERROR "Deprecated target platform ${WIRESHARK_TARGET_PLATFORM}. See https://gitlab.com/wireshark/wireshark/-/issues/17779 for details.")
	elseif(NOT (WIRESHARK_TARGET_PLATFORM MATCHES "x64" OR WIRESHARK_TARGET_PLATFORM MATCHES "arm64"))
		message(FATAL_ERROR "Invalid target platform: ${WIRESHARK_TARGET_PLATFORM}")
	endif()

	# Sanity check
	if(MSVC AND DEFINED ENV{PLATFORM})
		string(TOLOWER $ENV{PLATFORM} _vs_platform)
		if(
			(_vs_platform STREQUAL "x64" AND NOT WIRESHARK_TARGET_PLATFORM STREQUAL "x64")
			OR
			(_vs_platform STREQUAL "arm64" AND NOT WIRESHARK_TARGET_PLATFORM STREQUAL "arm64")
		)
			message(FATAL_ERROR "The PLATFORM environment variable (${_vs_platform})"
				" doesn't match the generator platform (${WIRESHARK_TARGET_PLATFORM})")
		endif()
	endif()

	message(STATUS
		"Building for ${WIRESHARK_TARGET_PLATFORM}"
	)

	if(NOT CMAKE_CROSSCOMPILING)
		find_package(PowerShell REQUIRED)
	endif()

	# Determine where the 3rd party libraries will be
	if(USE_REPOSITORY)
		if( DEFINED ENV{WIRESHARK_LIB_DIR} )
			# The buildbots set WIRESHARK_LIB_DIR but not WIRESHARK_BASE_DIR.
			file( TO_CMAKE_PATH "$ENV{WIRESHARK_LIB_DIR}" _PROJECT_LIB_DIR )
		elseif( DEFINED ENV{WIRESHARK_BASE_DIR} )
			file( TO_CMAKE_PATH "$ENV{WIRESHARK_BASE_DIR}" _WS_BASE_DIR )
			set( _PROJECT_LIB_DIR "${_WS_BASE_DIR}/wireshark-${WIRESHARK_TARGET_PLATFORM}-libs" )
		else()
			# Don't know what to do
			message(FATAL_ERROR "Neither WIRESHARK_BASE_DIR or WIRESHARK_LIB_DIR are defined")
		endif()

		# Download third-party libraries
		file (TO_NATIVE_PATH ${CMAKE_SOURCE_DIR}/tools/win-setup.ps1 _win_setup)
		file (TO_NATIVE_PATH ${_PROJECT_LIB_DIR} _ws_lib_dir)
		file (TO_NATIVE_PATH ${CMAKE_COMMAND} _win_cmake_command)

		# Is it possible to have a one-time, non-cached option in CMake? If
		# so, we could add a "-DFORCE_WIN_SETUP" which passes -Force to
		# win-setup.ps1.
		execute_process(
			COMMAND ${POWERSHELL_COMMAND} "\"${_win_setup}\"" -Destination "${_ws_lib_dir}" -Platform ${WIRESHARK_TARGET_PLATFORM} -CMakeExecutable "\"${_win_cmake_command}\""
			RESULT_VARIABLE _win_setup_failed
			ERROR_VARIABLE _win_setup_error_output
		)
		if(_win_setup_failed)
			message(FATAL_ERROR "Windows setup (win-setup.ps1) failed: ${_win_setup_error_output}.")
		endif()

		set(EXTRA_INSTALLER_DIR ${_ws_lib_dir})

		# XXX Add a dependency on ${_ws_lib_dir}/current_tag.txt?
	else()
		set(EXTRA_INSTALLER_DIR ${CMAKE_BINARY_DIR}/packaging/nsis)
	endif()

	include(FetchContent)
	set(LIBS_URL "https://dev-libs.wireshark.org/windows/packages")
	file(TO_CMAKE_PATH ${EXTRA_INSTALLER_DIR} _file_download_dir)

	# Download Npcap required by the Windows installer
	set(NPCAP_VERSION "1.79")
	set(NPCAP_SHA256 "a95577ebbc67fc45b319e2ef3a55f4e9b211fe82ed4cb9d8be6b1a9e2425ce53")
	set(NPCAP_FILENAME "npcap-${NPCAP_VERSION}.exe")
	set(NPCAP_URL "${LIBS_URL}/Npcap/${NPCAP_FILENAME}")
	FetchContent_Declare(Npcap
		URL ${NPCAP_URL}
		DOWNLOAD_DIR ${_file_download_dir}
		URL_HASH SHA256=${NPCAP_SHA256}
		DOWNLOAD_NO_EXTRACT True
	)

	# Download USBPcap required by the Windows installer
	set(USBPCAP_VERSION "1.5.4.0")
	set(USBPCAP_SHA256 "87a7edf9bbbcf07b5f4373d9a192a6770d2ff3add7aa1e276e82e38582ccb622")
	set(USBPCAP_FILENAME "USBPcapSetup-${USBPCAP_VERSION}.exe")
	set(USBPCAP_URL "${LIBS_URL}/USBPcap/${USBPCAP_FILENAME}")
	FetchContent_Declare(USBPcap
		URL ${USBPCAP_URL}
		DOWNLOAD_DIR ${_file_download_dir}
		URL_HASH SHA256=${USBPCAP_SHA256}
		DOWNLOAD_NO_EXTRACT True
	)
endif(WIN32)

include(UseCustomIncludes)
ADD_CUSTOM_CMAKE_INCLUDE()

# Ensure that all executables and libraries end up in the same directory. Actual
# files might end up in a configuration subdirectory, e.g. run/Debug or
# run/Release. We try to set DATAFILE_DIR to actual location below.
if(NOT ARCHIVE_OUTPUT_PATH)
	set(ARCHIVE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/run CACHE INTERNAL
		   "Single output directory for building all archives.")
endif()
if(NOT EXECUTABLE_OUTPUT_PATH)
	set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/run CACHE INTERNAL
		   "Single output directory for building all executables.")
endif()
if(NOT LIBRARY_OUTPUT_PATH)
	set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/run CACHE INTERNAL
		   "Single output directory for building all libraries.")
endif()

#
# The release mode (CMAKE_BUILD_TYPE=release) defines NDEBUG for
# the Unix Makefile generator.
#

# Defines CMAKE_INSTALL_BINDIR, CMAKE_INSTALL_DATADIR, etc ...
if(WIN32 AND NOT USE_MSYSTEM)
	# Override some values on Windows, to match the existing
	# convention of installing everything to a single root folder.
	set(CMAKE_INSTALL_BINDIR ".")
	set(CMAKE_INSTALL_LIBDIR ".")
	set(CMAKE_INSTALL_INCLUDEDIR "include")
	set(CMAKE_INSTALL_DATADIR ".")
	set(CMAKE_INSTALL_DOCDIR ".")
endif()
include(GNUInstallDirs)

set(PROJECT_INSTALL_INCLUDEDIR "${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}")

# Make sure our executables can load our libraries if we install into
# a non-default directory on Unix-like systems other than macOS.
# https://gitlab.kitware.com/cmake/community/wikis/doc/cmake/RPATH-handling
set(LIBRARY_INSTALL_RPATH "${CMAKE_INSTALL_RPATH}")
set(EXECUTABLE_INSTALL_RPATH "${CMAKE_INSTALL_RPATH}")
set(EXTCAP_INSTALL_RPATH "${CMAKE_INSTALL_RPATH}")
if(NOT (WIN32 OR APPLE OR USE_STATIC))
	# Try to set a RPATH for installed binaries if the library directory is
	# not already included in the default search list.
	list(FIND CMAKE_C_IMPLICIT_LINK_DIRECTORIES "${CMAKE_INSTALL_FULL_LIBDIR}" IS_SYSTEM_DIR)
	if(IS_SYSTEM_DIR EQUAL -1)
		# Some systems support $ORIGIN in RPATH to enable relocatable
		# binaries. In other cases, only absolute paths can be used.
		# https://www.lekensteyn.nl/rpath.html
		#
		# Also note that some systems (notably those using GNU libc)
		# silently ignore $ORIGIN in RPATH for binaries that are
		# setuid root or use privileged capabilities.
		#
		if(CMAKE_SYSTEM_NAME MATCHES "^(Linux|SunOS|FreeBSD)$")
			set(_enable_rpath_origin TRUE)
		else()
			set(_enable_rpath_origin FALSE)
		endif()

		# Provide a knob to optionally force absolute rpaths,
		# to support old/buggy systems and as a user preference
		# for hardening.
		# XXX Should this be a CMake option?
		set(ENABLE_RPATH_ORIGIN ${_enable_rpath_origin} CACHE BOOL
			"Use $ORIGIN with INSTALL_RPATH")
		mark_as_advanced(ENABLE_RPATH_ORIGIN)

		if(ENABLE_RPATH_ORIGIN)
			set(LIBRARY_INSTALL_RPATH     "$ORIGIN")
			set(EXECUTABLE_INSTALL_RPATH  "$ORIGIN/../${CMAKE_INSTALL_LIBDIR}")
			set(EXTCAP_INSTALL_RPATH      "$ORIGIN/../..")
		else()
			set(LIBRARY_INSTALL_RPATH     "${CMAKE_INSTALL_FULL_LIBDIR}")
			set(EXECUTABLE_INSTALL_RPATH  "${CMAKE_INSTALL_FULL_LIBDIR}")
			set(EXTCAP_INSTALL_RPATH      "${CMAKE_INSTALL_FULL_LIBDIR}")
		endif()
		# Include non-standard external libraries by default in RPATH.
		if(NOT DEFINED CMAKE_INSTALL_RPATH_USE_LINK_PATH)
			set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
		endif()
	endif()
endif()

# Ensure that executables in the build directory always have the same RPATH.
# This ensures relocatable binaries and reproducible builds (invariant of the
# build directory location). (Requires CMake 3.14)
set(CMAKE_BUILD_RPATH_USE_ORIGIN ON)

if(MSVC)
    # Linking with wsetargv.obj enables "wildcard expansion" of
    # command-line arguments.
    set(WILDCARD_OBJ wsetargv.obj)
endif()

include(CheckSymbolExists)

#
# Large file support on UN*X, a/k/a LFS.
#
# On Windows, we require _fseeki64() and _ftelli64().  Visual
# Studio has had supported them since Visual Studio 2005/MSVCR80,
# and we require newer versions, so we know we have them.
#
if(NOT MSVC)
	include(FindLFS)
	if(LFS_FOUND)
		#
		# Add the required #defines.
		#
		add_definitions(${LFS_DEFINITIONS})
	endif()

	#
	# Check for fseeko as well.
	#
	include(FindFseeko)
	if(FSEEKO_FOUND)
		set(HAVE_FSEEKO ON)

		#
		# Add the required #defines.
		#
		add_definitions(${FSEEKO_DEFINITIONS})
	endif()
endif()

# Banner shown at top right of Qt welcome screen.
if(DEFINED ENV{WIRESHARK_VERSION_FLAVOR})
	set(VERSION_FLAVOR "$ENV{WIRESHARK_VERSION_FLAVOR}")
else()
	set(VERSION_FLAVOR "Development Build")
endif()

# Used in .rc files and manifests
set(MANIFEST_PROCESSOR_ARCHITECTURE ${WIRESHARK_TARGET_PLATFORM})
if (MANIFEST_PROCESSOR_ARCHITECTURE MATCHES "x64")
	set(MANIFEST_PROCESSOR_ARCHITECTURE "amd64")
endif()
set(RC_VERSION ${PROJECT_MAJOR_VERSION},${PROJECT_MINOR_VERSION},${PROJECT_PATCH_VERSION},${PROJECT_BUILD_VERSION})
set(LOG_RC_VERSION ${LOG_PROJECT_MAJOR_VERSION},${LOG_PROJECT_MINOR_VERSION},${PROJECT_PATCH_VERSION},${PROJECT_BUILD_VERSION})

message(STATUS "V: ${PROJECT_VERSION}, MaV: ${PROJECT_MAJOR_VERSION}, MiV: ${PROJECT_MINOR_VERSION}, PL: ${PROJECT_PATCH_VERSION}, EV: ${PROJECT_VERSION_EXTENSION}.")

include(UseLemon)
include(UseMakePluginReg)
include(UseMakeTaps)
include(UseExecutableResources)
include(UseAsn2Wrs)

# The following snippet has been taken from
# https://github.com/USESystemEngineeringBV/cmake-eclipse-helper/wiki/HowToWorkaroundIndexer
# The eclipse indexer otherwise assumes __cplusplus=199711L which will lead to broken
# lookup tables for the epan libraries
# Check if CXX flags have been set to c++11 -> Setup Eclipse Indexer correctly!
# Also setup the project slightly different
if(CMAKE_EXTRA_GENERATOR MATCHES "Eclipse CDT4")
	SET(CXX_ENABLED 0)
	LIST(LENGTH CMAKE_EXTRA_GENERATOR_CXX_SYSTEM_DEFINED_MACROS LIST_LEN)
	if(LIST_LEN GREATER 0)
		SET(CXX_ENABLED 1)
	endif()
	SET(C_ENABLED 0)
	LIST(LENGTH CMAKE_EXTRA_GENERATOR_C_SYSTEM_DEFINED_MACROS LIST_LEN)
	if(LIST_LEN GREATER 0)
		SET(C_ENABLED 1)
	endif()
	if(C_ENABLED EQUAL 1 AND CXX_ENABLED EQUAL 1)
		# Combined project (C and CXX). This will confuse the indexer. For that reason
		# we unsert set the __cplusplus variable for the indexer
		list(FIND CMAKE_EXTRA_GENERATOR_CXX_SYSTEM_DEFINED_MACROS "__cplusplus" GEN_MACRO_INDEX)
		if(GEN_MACRO_INDEX GREATER -1)
			list(REMOVE_AT CMAKE_EXTRA_GENERATOR_CXX_SYSTEM_DEFINED_MACROS ${GEN_MACRO_INDEX})
			list(REMOVE_AT CMAKE_EXTRA_GENERATOR_CXX_SYSTEM_DEFINED_MACROS ${GEN_MACRO_INDEX})
		endif()
		SET(CMAKE_EXTRA_GENERATOR_CXX_SYSTEM_DEFINED_MACROS ${CMAKE_EXTRA_GENERATOR_CXX_SYSTEM_DEFINED_MACROS} CACHE INTERNAL "")
	elseif((CXX_ENABLED EQUAL 1) AND (CMAKE_CXX_FLAGS MATCHES ".*-std=c\\+\\+11.*"))
		#add_definitions (-D__cplusplus=201103L)
		# CMAKE_EXTRA_GENERATOR_CXX_SYSTEM_DEFINED_MACROS
		list(FIND CMAKE_EXTRA_GENERATOR_CXX_SYSTEM_DEFINED_MACROS "199711L" GEN_MACRO_INDEX)
		if(GEN_MACRO_INDEX GREATER -1)
			list(REMOVE_AT CMAKE_EXTRA_GENERATOR_CXX_SYSTEM_DEFINED_MACROS ${GEN_MACRO_INDEX})
			list(INSERT CMAKE_EXTRA_GENERATOR_CXX_SYSTEM_DEFINED_MACROS ${GEN_MACRO_INDEX} "201103L")
			SET(CMAKE_EXTRA_GENERATOR_CXX_SYSTEM_DEFINED_MACROS ${CMAKE_EXTRA_GENERATOR_CXX_SYSTEM_DEFINED_MACROS} CACHE INTERNAL "")
		endif()
	endif()
endif()

include_directories(
	${CMAKE_BINARY_DIR}
	${CMAKE_SOURCE_DIR}
	${CMAKE_SOURCE_DIR}/include
)

if( DUMPCAP_INSTALL_OPTION STREQUAL "suid" )
	set( DUMPCAP_SETUID "SETUID" )
else()
	set( DUMPCAP_SETUID )
endif()
if( NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" AND
	DUMPCAP_INSTALL_OPTION STREQUAL "capabilities" )
	message( WARNING "Capabilities are only supported on Linux" )
	set( DUMPCAP_INSTALL_OPTION )
endif()

set(OSS_FUZZ OFF CACHE BOOL "Whether building for oss-fuzz")
mark_as_advanced(OSS_FUZZ)
if(OSS_FUZZ)
	if(ENABLE_FUZZER)
		# In oss-fuzz mode, the fuzzing engine can be afl or libFuzzer.
		message(FATAL_ERROR "Cannot force libFuzzer when using oss-fuzz")
	endif()
	# Must not depend on external dependencies so statically link all libs.
	set(USE_STATIC ON)
endif()

if(USE_STATIC)
	set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
endif()

#
# Linking can consume a lot of memory, especially when built with ASAN and
# static libraries (like oss-fuzz) or Debug mode. With Ninja, the number of
# parallel linker processes is constrained by job parallelism (-j), but this can
# be reduced further by setting "job pools" to a lower number.
#
if(CMAKE_MAKE_PROGRAM MATCHES "ninja" AND OSS_FUZZ)
	# Assume oss-fuzz linker jobs do not require more than 1.2G per task
	set(per_job_memory_mb 1200)
	cmake_host_system_information(RESULT total_memory_mb QUERY TOTAL_PHYSICAL_MEMORY)
	math(EXPR parallel_link_jobs "${total_memory_mb} / ${per_job_memory_mb}")
	if(parallel_link_jobs LESS 1)
		set(parallel_link_jobs 1)
	endif()
	set_property(GLOBAL APPEND PROPERTY JOB_POOLS link_job_pool=${parallel_link_jobs})
	set(CMAKE_JOB_POOL_LINK link_job_pool)
	message(STATUS "Ninja job pool size: ${parallel_link_jobs}")
endif()

# Always enable position-independent code when compiling, even for
# executables, so you can build position-independent executables.
# -pie is added below for non-MSVC, but requires objects to be built with
# -fPIC/-fPIE (so set CMAKE_POSITION_INDEPENDENT_CODE to enable that).
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Preprocessor definitions common to all compilers
set_property(DIRECTORY
	PROPERTY COMPILE_DEFINITIONS
		"G_DISABLE_DEPRECATED"
		"G_DISABLE_SINGLE_INCLUDES"
		$<$<OR:$<BOOL:${ENABLE_DEBUG}>,$<CONFIG:Debug>>:WS_DEBUG>
		$<$<OR:$<AND:$<BOOL:${ENABLE_DEBUG}>,$<BOOL:${ENABLE_DEBUG_UTF_8}>>,$<CONFIG:Debug>>:WS_DEBUG_UTF_8>
		$<$<BOOL:${ENABLE_ASSERT}>:ENABLE_ASSERT>
)

if(WIN32)
	#
	# NOTE: Because of the way Qt moc is including "config.h" (not as the
	# first header) this *MUST* be defined on the command line to precede
	# every included header and not trigger symbol redefinition errors.
	#
	add_definitions(
		-DWIN32_LEAN_AND_MEAN
		#
		# Use Unicode in Windows runtime functions.
		#
		-DUNICODE
		-D_UNICODE
		#
		# NOMINMAX keeps windows.h from defining "min" and "max" via windef.h.
		# This avoids conflicts with the C++ standard library.
		#
		-DNOMINMAX
	)
endif()

if(MINGW)
	add_definitions(
		#
		# Enable POSIX APIs. This will switch stdio to ANSI C functions and
		# enable C99 conformant vsnprintf() among other things.
		#
		-D_POSIX
	)
	list(APPEND CMAKE_REQUIRED_DEFINITIONS -D_POSIX)
endif()

if( CMAKE_C_COMPILER_ID MATCHES "MSVC")
	if (MSVC_VERSION LESS "1928")
		message(FATAL_ERROR "Microsoft Visual Studio 2019 version 16.8 or later is required")
	endif()
	if (MSVC_VERSION GREATER_EQUAL "2000")
		message(FATAL_ERROR "You are using an unsupported version of MSVC")
	endif()

	add_definitions(
		/D_CRT_SECURE_NO_DEPRECATE
		# -DPSAPI_VERSION=1                 Programs that must run on earlier versions of Windows as well as Windows 7 and later
		#                                   versions should always call this function as GetProcessMemoryInfo. To ensure correct
		#                                   resolution of symbols, add Psapi.lib to the TARGETLIBS macro and compile the program
		#                                   with -DPSAPI_VERSION=1.To use run-time dynamic linking, load Psapi.dll.
		#                                   https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getprocessmemoryinfo
		# -D_ALLOW_KEYWORD_MACROS           For VS2012 onwards the, C++ STL does not permit macro redefinitions of keywords
		#                                   (see https://docs.microsoft.com/en-us/previous-versions/visualstudio/visual-studio-2012/bb531344(v=vs.110))
		#                                   This definition prevents the complaint about the redefinition of inline by WinPCap
		#                                   in pcap-stdinc.h when compiling C++ files, e.g. the Qt UI
		/DPSAPI_VERSION=1
		/D_ALLOW_KEYWORD_MACROS
		# Disable deprecation of POSIX function names.
		# https://stackoverflow.com/questions/37845163/what-is-the-purpose-of-microsofts-underscore-c-functions
		/D_CRT_NONSTDC_NO_WARNINGS
	)

	if(NOT WIRESHARK_TARGET_PLATFORM STREQUAL "x64")
		add_definitions("/D_BIND_TO_CURRENT_CRT_VERSION=1")
	endif()

	set(LOCAL_CFLAGS
		/MP
	)

	set(WS_LINK_FLAGS "/LARGEADDRESSAWARE /MANIFEST:NO /INCREMENTAL:NO /RELEASE")

	# To do: Add /external:... See https://devblogs.microsoft.com/cppblog/broken-warnings-theory/
	#
	# /diagnostics:caret                Place a caret under compilation issues similar to
	#                                   Clang and gcc.
	# /Zo                               Enhanced debugging of optimised code
	# /utf-8                            Set Source and Executable character sets to UTF-8
	#                                   VS2015(MSVC14): On by default when /Zi or /Z7 used.
	# /guard:cf                         Control Flow Guard (compile and link).
	#                                   See https://docs.microsoft.com/en-us/windows/win32/secbp/control-flow-guard
	#                                   Note: This requires CMake 3.9.0 or newer.
	#                                   https://gitlab.kitware.com/cmake/cmake/commit/f973d49ab9d4c59b93f6dac812a94bb130200836
	# /Qspectre                         Speculative execution attack mitigation
	#                                   See https://devblogs.microsoft.com/cppblog/spectre-mitigations-in-msvc/
	list(APPEND LOCAL_CFLAGS /diagnostics:caret /Zo /utf-8 /guard:cf)
	set(WS_LINK_FLAGS "${WS_LINK_FLAGS} /guard:cf")
	set(WS_LINK_FLAGS "${WS_LINK_FLAGS} /STACK:0x800000")
	# /Qspectre depends on the optional "Microsoft.VisualStudio.Component...Spectre" components,
	# so we need to test for its availability.
	set(WIRESHARK_COMMON_FLAGS /Qspectre)

	if(ENABLE_CODE_ANALYSIS)
		# We should probably add a code_analysis.props file and use it to set
		# CAExcludePath, otherwise we trigger on Qt's headers:
		# https://stackoverflow.com/questions/59669026/how-to-add-property-to-affect-code-analysis-in-cmake
		# https://gitlab.kitware.com/cmake/cmake/-/issues/19682
		# For now, we set CAExcludePath=C:\Qt;%include% in the Visual Studio
		# Code Analys builder's environment.
		list(APPEND LOCAL_CFLAGS
			/analyze:WX-
			/analyze:log:format:sarif
			)
	endif()

	# Additional compiler warnings to be treated as "Level 3"
	# when compiling Wireshark sources. (Selected from "level 4" warnings).
	## 4295: array is too small to include a terminating null character
	## 4100: unreferenced formal parameter
	## 4189: local variable is initialized but not referenced
	# Disable warnings about use of flexible array members:
	## 4200: nonstandard extension used : zero-sized array in struct/union
	list(APPEND LOCAL_CFLAGS /w34295 /w34100 /w34189 /wd4200)

	# MSVC 14.28 + C11 enables C5105, but older Windows SDKs aren't completely compatible.
	# Windows SDK 10.0.17763.0 generates syntax errors with C11 enabled.
	# The variable CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION does not work with the Ninja generator. Presumably it requires a VS generator.
	if (CMAKE_GENERATOR MATCHES "Visual Studio")
		if (CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION VERSION_LESS 10.0.18362.0)
			message(FATAL_ERROR "Windows SDK ${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION} doesn't support C11. Please make sure you're using 10.0.20348.0 or later.")
		endif()
		# Windows SDK 10.0.18362.0 to 10.0.19041.685 generate warning C5105 with C11 enabled.
		if(CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION VERSION_LESS 10.0.20348.0)
			message(WARNING "Windows SDK ${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION} doesn't support C11. Please make sure you're using 10.0.20348.0 or later.")
			## 5105: macro expansion producing 'defined' has undefined behavior
			list(APPEND LOCAL_CFLAGS /wd5105)
		endif()
	endif()

	# We've matched these to specific compiler versions using the
	# checks above. There's no need to pass them to check_c_compiler_flag
	# or check_cxx_compiler_flag, which can be slow.
	string(REPLACE ";" " " _flags "${LOCAL_CFLAGS}")
	set(CMAKE_C_FLAGS "${_flags} ${CMAKE_C_FLAGS}")
	set(CMAKE_CXX_FLAGS "${_flags} ${CMAKE_CXX_FLAGS}")

else() # ! MSVC
	if(APPLE)
		# MIN_MACOS_VERSION is used to set LSMinimumSystemVersion
		# in Info.plist, so start with something low.
		set(MIN_MACOS_VERSION 10.11)
		if(CMAKE_OSX_DEPLOYMENT_TARGET)
			if(CMAKE_OSX_DEPLOYMENT_TARGET VERSION_LESS MIN_MACOS_VERSION)
				message(FATAL_ERROR "We don't support building for macOS < ${MIN_MACOS_VERSION}")
			endif()
			set(MIN_MACOS_VERSION ${CMAKE_OSX_DEPLOYMENT_TARGET})
		endif()
	endif()

	#
	# NOTE: Adding new warnings is a policy decision that can have far-reaching
	# implications for the project and each developers workflow. Modern
	# C compilers are on a race to add new warnings, not always sensibly.
	# They are opt-in so take a moment to fully consider the implications
	# of enabling the latest shiny new warning.
	# If in doubt ask on the Wireshark developer list (recommended).
	#
	list(APPEND WIRESHARK_COMMON_FLAGS
		#
		### Flags common to C and C++ ###
		#
		# -O<X> and -g get set by the CMAKE_BUILD_TYPE
		-Wall
		-Wextra
		-Wpointer-arith
		-Wformat-security
		-fno-strict-overflow
		-fexcess-precision=fast	# GCC-only
		-Wvla
		-Wattributes
		-Wpragmas		# Clang-only
		-Wheader-guard		# Clang-only
		-Wcomma			# Clang-only
		-Wshorten-64-to-32	# Clang-only
		-Wredundant-decls
		-Wunreachable-code	# Clang-only
		-Wdocumentation		# Clang-only
		-Wlogical-op		# GCC-only
		#
		# Disable errors unconditionally for some static analysis warnings
		# that are dormant at lower optimizations levels or active only in
		# bleeding edge versions of a compiler and possibly also
		# prone to false positives and compiler bugs. This is
		# a big nuisance because the warning is dormant and a low
		# priority target for action. That is very disruptive
		# with -Werror enabled (the default on the master branch).
		#
		-Wno-error=stringop-overflow=
		#
		# XXX Now that we have a CI job with Release build type (using
		# -O3 optimization level) the dormancy issue should be ameliorated
		# so comment out these exceptions to re-evaluate the impact.
		#-Wno-error=maybe-uninitialized
		#-Wno-error=alloc-size-larger-than=
		#
		# Updating external dependencies can introduce new deprecations.
		# Also fixing new internal deprecations takes time.
		# We want to be able to build with -Werror in that case. New
		# code should not introduce new deprecations in any case.
		#
		-Wno-error=deprecated-declarations
	)

	if((NOT ENABLE_ASAN) AND (NOT ENABLE_TSAN) AND (NOT ENABLE_UBSAN) AND (NOT DISABLE_FRAME_LARGER_THAN_WARNING))
		#
		# Only do this if none of ASan, TSan, and UBSan are
		# enabled; the instrumentation they add increases
		# the stack usage - we only care about stack
		# usage in normal operation.
		#
		list(APPEND WIRESHARK_COMMON_FLAGS
			-Wframe-larger-than=32768
		)
	endif()

	list(APPEND WIRESHARK_C_ONLY_FLAGS
		#
		### Flags for C only ###
		#
		#
		# XXX - some versions of GCC, including the one in at
		# least some Xcode versions that come with Mac OS X
		# 10.5, complain about variables in function and
		# function pointer *declarations* shadowing other
		# variables.  The autoconf script checked for that; we
		# don't.
		-Wshadow
		-Wold-style-definition
		-Wstrict-prototypes
	)

	#
	# The universal zero initializer (in C: struct s x = { 0 };) for
	# structures with multiple members is perfectly legal, but some older
	# compilers warn about it. Silence those older compilers.
	#
	if((CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_C_COMPILER_VERSION VERSION_LESS "5.1") OR
	   (CMAKE_C_COMPILER_ID STREQUAL "Clang" AND CMAKE_C_COMPILER_VERSION VERSION_LESS "6.0") OR
	   (CMAKE_C_COMPILER_ID STREQUAL "AppleClang" AND CMAKE_C_COMPILER_VERSION VERSION_LESS "12.0"))
		if(NOT CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_VERSION VERSION_LESS "5.0")
			list(APPEND WIRESHARK_C_ONLY_FLAGS -Wno-missing-field-initializers)
		endif()
		# Silence warnings for initialization of nested structs like
		# struct { struct { int a, b; } s; int c; } v = { 0 };
		list(APPEND WIRESHARK_C_ONLY_FLAGS -Wno-missing-braces)
	endif()

	list(APPEND WIRESHARK_CXX_ONLY_FLAGS
		#
		### Flags for C++ only ###
		#
		-Wextra-semi	# Clang-only
	)

	#
	# Not all warnings are the same. They fall on a spectrum from "critical"
	# to "pedantic nonsense". These are warnings that realistically are worth
	# fixing eventually.
	#
	if(ENABLE_TODO_WARNINGS)
		list(APPEND WIRESHARK_COMMON_FLAGS
			#
			# All the registration functions block these for now.
			#
			-Wmissing-prototypes
			-Wmissing-declarations
			#
			# A bunch of "that might not work on SPARC" code blocks
			# this one for now; some of it is code that *will* work
			# on SPARC, such as casts of "struct sockaddr *" to
			# "struct sockaddr_in *", which are required by some
			# APIs such as getifaddrs().
			#
			-Wcast-align
		)
	else()
		list(APPEND WIRESHARK_COMMON_FLAGS
			#
			# Converting from g_printf() and g_snprintf() to stdio.h turns
			# up many of these warnings. They will have to be handled later.
			# It can be a lot of work to fix properly and none of them
			# seem to flag very interesting issues.
			#
			-Wno-format-truncation # Enabled with -Wall
		)
		list(APPEND WIRESHARK_C_ONLY_FLAGS
			-Wno-pointer-sign # Enabled with -Wall
		)
	endif()

	#
	# These are not enabled by default, because the warnings they
	# produce are very hard or impossible to eliminate.
	#
	if(ENABLE_PEDANTIC_COMPILER_WARNINGS)
		list(APPEND WIRESHARK_COMMON_FLAGS
			# The following are for C and C++
			-Wpedantic
			-Wno-overlength-strings
			-Wno-long-long
			#
			# As we use variadic macros, we don't want warnings
			# about them, even with -Wpedantic.
			#
			-Wno-variadic-macros
			#
			# Various code blocks this one.
			#
			-Woverflow
			-fstrict-overflow -Wstrict-overflow=4
			#
			# Due to various places where APIs we don't control
			# require us to cast away constness, we can probably
			# never enable this one with -Werror.
			#
			-Wcast-qual
			#
			# Doesn't warn of interesting issues. Usually the
			# duplicated branches are protocol constants that
			# happen to be equal and are relevant for documentation
			# and readability and are trivially optimized by the
			# compiler.
			#
			-Wduplicated-branches		# GCC-only
			#
			# No longer supported by El Capitan clang on C++
			# XXX - is this one of those where CMake's check
			# doesn't fail, so it won't reject this?
			#
			-fno-delete-null-pointer-checks
		)

		#
		# Some loops are safe, but it's hard to convince the compiler of
		# that. Always disable the warning on GCC 7 due to a bug that
		# cause lots of false positives.
		# https://gcc.gnu.org/bugzilla/show_bug.cgi?id=81408
		#
		if(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND NOT CMAKE_C_COMPILER_VERSION MATCHES "^7\\.")
			list(APPEND WIRESHARK_COMMON_FLAGS -Wunsafe-loop-optimizations)
		endif()

		list(APPEND WIRESHARK_C_ONLY_FLAGS
			# The following are C only, not C++
			#
			# Due to various places where APIs we don't control
			# require us to cast away constness, we can probably
			# never enable this one with -Werror.
			#
			-Wbad-function-cast
		)

		list(APPEND WIRESHARK_CXX_ONLY_FLAGS
		)
	endif()

	if(ENABLE_COMPILER_COLOR_DIAGNOSTICS)
		if(CMAKE_C_COMPILER_ID MATCHES "Clang")
			set(WIRESHARK_COMMON_FLAGS ${WIRESHARK_COMMON_FLAGS}
				-fcolor-diagnostics
			)
		elseif(CMAKE_C_COMPILER_ID MATCHES "GNU")
			set(WIRESHARK_COMMON_FLAGS ${WIRESHARK_COMMON_FLAGS}
				-fdiagnostics-color=always
			)
		endif()
	endif()

	set(WIRESHARK_LD_FLAGS
		# See also CheckCLinkerFlag.cmake
		-Wl,--as-needed
		# -flto
		# -fwhopr
		# -fwhole-program
	)
endif() # ! MSVC

# Counterhack to work around some cache magic in CHECK_C_SOURCE_COMPILES
include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)

if(ENABLE_STATIC)
	set(BUILD_SHARED_LIBS 0)
else()
	set(BUILD_SHARED_LIBS 1)
endif()

function(test_compiler_flag _lang _this_flag _valid_flags_var)
	string(MAKE_C_IDENTIFIER "${_lang}${_this_flag}_VALID" _flag_var)
	set(_test_flags "${${_valid_flags_var}} ${_this_flag}")
	if(_lang STREQUAL "C")
		check_c_compiler_flag("${_test_flags}" ${_flag_var})
	elseif(_lang STREQUAL "CXX")
		check_cxx_compiler_flag("${_test_flags}" ${_flag_var})
	else()
		message(FATAL_ERROR "Language must be C or CXX")
	endif()
	if (${_flag_var})
		set(${_valid_flags_var} "${_test_flags}" PARENT_SCOPE)
	endif()
endfunction()

foreach(THIS_FLAG ${WIRESHARK_COMMON_FLAGS} ${WIRESHARK_C_ONLY_FLAGS})
	test_compiler_flag(C ${THIS_FLAG} ADDED_CMAKE_C_FLAGS)
endforeach()
set(CMAKE_C_FLAGS "${ADDED_CMAKE_C_FLAGS} ${CMAKE_C_FLAGS}")

foreach(THIS_FLAG ${WIRESHARK_COMMON_FLAGS} ${WIRESHARK_CXX_ONLY_FLAGS})
	test_compiler_flag(CXX ${THIS_FLAG} ADDED_CMAKE_CXX_FLAGS)
endforeach()
set(CMAKE_CXX_FLAGS "${ADDED_CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS}")

# Strips the source and build directory prefix from the __FILE__ macro to ensure
# reproducible builds. Supported since GCC 8, Clang support is pending.
if(CMAKE_C_COMPILER_ID MATCHES "GNU" OR CMAKE_C_COMPILER_ID MATCHES "Clang")
	# If the build dir is within the source dir, CMake will use something
	# like ../epan/dfilter/semcheck.c. Map these relative paths in addition
	# to CMAKE_BINARY_DIR since compile_commands.json uses absolute paths.
	file(RELATIVE_PATH _relative_source_dir "${CMAKE_BINARY_DIR}" "${CMAKE_SOURCE_DIR}")
	string(REGEX REPLACE "/$" "" _relative_source_dir "${_relative_source_dir}")

	check_c_compiler_flag(-fmacro-prefix-map=old=new C_fmacro_prefix_map_old_new_VALID)
	check_cxx_compiler_flag(-fmacro-prefix-map=old=new CXX_fmacro_prefix_map_old_new_VALID)
	foreach(_lang C CXX)
		if(${_lang}_fmacro_prefix_map_old_new_VALID)
			set(_flags CMAKE_${_lang}_FLAGS)
			set(${_flags} "${${_flags}} -fmacro-prefix-map=\"${CMAKE_SOURCE_DIR}/\"=")
			set(${_flags} "${${_flags}} -fmacro-prefix-map=\"${CMAKE_BINARY_DIR}/\"=")
			if(_relative_source_dir MATCHES "\\.\\.$")
				set(${_flags} "${${_flags}} -fmacro-prefix-map=\"${_relative_source_dir}/\"=")
			endif()
		endif()
	endforeach()
endif()

include(CMakePushCheckState)

if(ENABLE_ASAN)
	# Available since MSVC 2019 version 16.9 (https://gitlab.com/wireshark/wireshark/-/merge_requests/14912 for more details)
	cmake_push_check_state()
	set(ASAN_FLAG "-fsanitize=address")
	set(CMAKE_REQUIRED_FLAGS ${ASAN_FLAG})
	if(MSVC)
		message(NOTICE "ENABLE_ASAN was requested. Checking if ASAN is supported requires SPECTRE-mitigation to be disabled globally impacting all build types.")
		message(NOTICE "If ASAN is supported, then it is re-enabled selectively depending on the build types.")
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /Qspectre-")
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /Qspectre-")
	endif()
	check_c_compiler_flag(${ASAN_FLAG} C__fsanitize_address_VALID)
	check_cxx_compiler_flag(${ASAN_FLAG} CXX__fsanitize_address_VALID)
	cmake_pop_check_state()
	if(NOT C__fsanitize_address_VALID OR NOT CXX__fsanitize_address_VALID)
		message(FATAL_ERROR "ENABLE_ASAN was requested, but not supported!")
	endif()
	if(MSVC)
		message(NOTICE "ASAN is supported.")
		if(ENABLE_ASAN_WITH_SPECTRE)
			message(NOTICE "ENABLE_ASAN_WITH_SPECTRE was requested.")
			message(NOTICE "For Debug and RelWithDebInfo, SPECTRE-mitigation has been re-enabled and ASAN has been enabled too.")
			add_compile_options("$<$<CONFIG:Debug>:/Qspectre>" "$<$<CONFIG:Debug>:${ASAN_FLAG}>")
			add_compile_options("$<$<CONFIG:RelWithDebInfo>:/Qspectre>" "$<$<CONFIG:RelWithDebInfo>:${ASAN_FLAG}>")
			set(CPU ${WIRESHARK_TARGET_PLATFORM})
			if (${CPU} MATCHES "win32")
				set(CPU x86)
			endif()
			add_link_options("$<$<CONFIG:Debug>:/libpath:$ENV{VCToolsInstallDir}lib\\spectre\\${CPU}>" "$<$<CONFIG:Debug>:/libpath:$ENV{VCToolsInstallDir}lib\\${CPU}>")
			add_link_options("$<$<CONFIG:RelWithDebInfo>:/libpath:$ENV{VCToolsInstallDir}lib\\spectre\\${CPU}>" "$<$<CONFIG:RelWithDebInfo>:/libpath:$ENV{VCToolsInstallDir}lib\\${CPU}>")
		else()
			message(NOTICE "ENABLE_ASAN_WITH_SPECTRE was not requested")
			message(NOTICE "For Debug and RelWithDebInfo, SPECTRE-mitigation stays disabled and ASAN has been enabled.")
			add_compile_options("$<$<CONFIG:Debug>:${ASAN_FLAG}>")
			add_compile_options("$<$<CONFIG:RelWithDebInfo>:${ASAN_FLAG}>")
		endif()
		message(NOTICE "For Release and MinSizeRel, SPECTRE-mitigation has been re-enabled and ASAN has been skipped.")
		add_compile_options("$<$<CONFIG:Release>:/Qspectre>")
		add_compile_options("$<$<CONFIG:MinSizeRel>:/Qspectre>")
	else()
		add_compile_options(${ASAN_FLAG})
	endif()
	if(MSVC)
		# Using ASAN makes some of our code require object files with
		# a 32-bit index to the section table instead of 16-bit.
		# This makes the .obj files slightly larger (~2%) and makes
		# it so that Microsoft linkers prior to MSVC 2005 can't read
		# the files, but those are too old anyway.
		add_compile_options(/bigobj)
		# The Microsoft LINK linker doesn't recognize or need the
		# ASAN flag, and will give a LNK4044 warning.
	else()
		# Clang/gcc need the flag added to the linker
		# add_link_options since CMake 3.13 (our minimum)
		add_link_options(${ASAN_FLAG})
	endif()
endif()

if(MSVC)
	if(NOT ENABLE_ASAN AND ENABLE_ASAN_WITH_SPECTRE)
		message(FATAL_ERROR "ENABLE_ASAN_WITH_SPECTRE was requested, but without ENABLE_ASAN!")
	endif()
endif()

if(ENABLE_TSAN)
	# Available since Clang >= 3.2 and GCC >= 4.8
	cmake_push_check_state()
	set(CMAKE_REQUIRED_LIBRARIES "-fsanitize=thread")
	check_c_compiler_flag(-fsanitize=thread C__fsanitize_thread_VALID)
	check_cxx_compiler_flag(-fsanitize=thread CXX__fsanitize_thread_VALID)
	cmake_pop_check_state()
	if(NOT C__fsanitize_thread_VALID OR NOT CXX__fsanitize_thread_VALID)
		message(FATAL_ERROR "ENABLE_TSAN was requested, but not supported!")
	endif()
	set(CMAKE_C_FLAGS "-fsanitize=thread ${CMAKE_C_FLAGS}")
	set(CMAKE_CXX_FLAGS "-fsanitize=thread ${CMAKE_CXX_FLAGS}")
	set(WS_LINK_FLAGS "-fsanitize=thread ${WS_LINK_FLAGS}")
endif()

if(ENABLE_UBSAN)
	# Available since Clang >= 3.3 and GCC >= 4.9
	cmake_push_check_state()
	set(CMAKE_REQUIRED_LIBRARIES "-fsanitize=undefined")
	check_c_compiler_flag(-fsanitize=undefined C__fsanitize_undefined_VALID)
	check_cxx_compiler_flag(-fsanitize=undefined CXX__fsanitize_undefined_VALID)
	cmake_pop_check_state()
	if(NOT C__fsanitize_undefined_VALID OR NOT CXX__fsanitize_undefined_VALID)
		message(FATAL_ERROR "ENABLE_UBSAN was requested, but not supported!")
	endif()
	set(CMAKE_C_FLAGS "-fsanitize=undefined ${CMAKE_C_FLAGS}")
	set(CMAKE_CXX_FLAGS "-fsanitize=undefined ${CMAKE_CXX_FLAGS}")
endif()

if(ENABLE_LSAN)
	# Available since Clang >= 3.4 and GCC >= 4.9
	cmake_push_check_state()
	set(CMAKE_REQUIRED_LIBRARIES "-fsanitize=leak")
	check_c_compiler_flag(-fsanitize=leak C__fsanitize_leak_VALID)
	check_cxx_compiler_flag(-fsanitize=leak CXX__fsanitize_leak_VALID)
	cmake_pop_check_state()
	if(NOT C__fsanitize_leak_VALID OR NOT CXX__fsanitize_leak_VALID)
		message(FATAL_ERROR "ENABLE_LSAN was requested, but not supported!")
	endif()
	set(CMAKE_C_FLAGS "-fsanitize=leak ${CMAKE_C_FLAGS}")
	set(CMAKE_CXX_FLAGS "-fsanitize=leak ${CMAKE_CXX_FLAGS}")
endif()

if(ENABLE_FUZZER)
	# Available since Clang >= 6
	# Will enable coverage flags which can be used by the fuzzshark target.
	cmake_push_check_state()
	set(CMAKE_REQUIRED_LIBRARIES "-fsanitize=fuzzer-no-link")
	check_c_compiler_flag(-fsanitize=fuzzer C__fsanitize_fuzzer_no_link_VALID)
	check_cxx_compiler_flag(-fsanitize=fuzzer CXX__fsanitize_fuzzer_no_link_VALID)
	cmake_pop_check_state()
	if(NOT C__fsanitize_fuzzer_no_link_VALID OR NOT CXX__fsanitize_fuzzer_no_link_VALID)
		message(FATAL_ERROR "ENABLE_FUZZER was requested, but not supported!")
	endif()
	set(CMAKE_C_FLAGS "-fsanitize=fuzzer-no-link ${CMAKE_C_FLAGS}")
	set(CMAKE_CXX_FLAGS "-fsanitize=fuzzer-no-link ${CMAKE_CXX_FLAGS}")
endif()

if(ENABLE_ASAN OR ENABLE_TSAN OR ENABLE_UBSAN OR ENABLE_LSAN OR ENABLE_FUZZER)
	# Disable sanitizers for build-time tools, e.g. lemon
	# (MSVC doesn't support this flag)
	check_c_compiler_flag(-fno-sanitize=all C__fno_sanitize_all_VALID)
	if(C__fno_sanitize_all_VALID)
		set(NO_SANITIZE_CFLAGS "-fno-sanitize=all")
		set(NO_SANITIZE_LDFLAGS "-fno-sanitize=all")
	endif()
endif()

if(MSVC)
	if(ENABLE_VLD)
		include(FindVLD)
		if(NOT VLD_FOUND)
			message(FATAL_ERROR "ENABLE_VLD was requested, but not found!")
		endif()
		message(STATUS "Enabling Visual Leak Detector in Debug configuration")
		set(WS_MSVC_DEBUG_LINK_FLAGS ${VLD_LINK_FLAGS})
	endif()
endif()

set(WERROR_COMMON_FLAGS "")
if(ENABLE_WERROR)
	if(CMAKE_C_COMPILER_ID MATCHES "MSVC")
		set(WERROR_COMMON_FLAGS "/WX")
	else()
		#
		# If a warning has been enabled by -Wall or -W,
		# and have specified -Werror, there appears to be
		# no way, in Apple's llvm-gcc, to prevent that
		# particular warning from giving an error - not
		# with a pragma, not with -Wno-{warning}, and not
		# with -Wno-error={warning}.
		#
		# Therefore, with that compiler, we just disable
		# -Werror.
		#
		if ((NOT APPLE) OR CMAKE_C_COMPILER_ID MATCHES "Clang")
			check_c_compiler_flag(-Werror WERROR)
			if (WERROR)
				set(WERROR_COMMON_FLAGS "-Werror")
			endif()
		endif()
	endif()
endif()

#
# Try to have the compiler default to hiding symbols, so that only
# symbols explicitly exported with WS_DLL_PUBLIC will be visible
# outside (shared) libraries; that way, more UN*X builds will catch
# failures to export symbols, rather than having that fail only on
# Windows.
#
# We don't need that with MSVC, as that's the default.
#
if( NOT CMAKE_C_COMPILER_ID MATCHES "MSVC")
	#
	# Try the GCC-and-compatible -fvisibility-hidden first.
	#
	check_c_compiler_flag(-fvisibility=hidden FVHIDDEN)
	if(FVHIDDEN)
		set(CMAKE_C_FLAGS "-fvisibility=hidden ${CMAKE_C_FLAGS}")
	else()
		#
		# OK, try the Sun^WOracle C -xldscope=hidden
		#
		check_c_compiler_flag(-xldscope=hidden XLDSCOPEHIDDEN)
		if(XLDSCOPEHIDDEN)
			set(CMAKE_C_FLAGS "-xldscope=hidden ${CMAKE_C_FLAGS}")
		else()
			#
			# Anything else?
			# If there is anything else, we might want to
			# make a list of options to try, and try them
			# in a loop.
			#
			message(WARNING "Hiding shared library symbols is not supported by the compiler."
				" All shared library symbols will be exported.")
		endif()
	endif()
endif()

include(CheckCLinkerFlag)

if(NOT CMAKE_C_COMPILER_ID MATCHES "MSVC" AND NOT OSS_FUZZ)
	#
	# The -pie linker option produces a position-independent executable.
	# Some Linux distributions have this enabled by default in the compiler,
	# so setting it here will be superfluous though.
	#
	# Note that linking with static libraries that are not position
	# independent may fail, the user can set CMAKE_EXE_LINKER_FLAGS=-no-pie
	# as a workaround.
	#
	if(CMAKE_VERSION VERSION_LESS "3.14")
		check_c_linker_flag(-pie LINK_pie_VALID)
		if(LINK_pie_VALID)
			set(CMAKE_EXE_LINKER_FLAGS "-pie ${CMAKE_EXE_LINKER_FLAGS}")
		endif()
	else()
		include(CheckPIESupported)
		check_pie_supported()
	endif()
endif()

foreach(THIS_FLAG ${WIRESHARK_LD_FLAGS})
	string(MAKE_C_IDENTIFIER "LINK${THIS_FLAG}_VALID" _flag_var)
	check_c_linker_flag(${THIS_FLAG} ${_flag_var})
	if (${_flag_var})
		set(WS_LINK_FLAGS "${WS_LINK_FLAGS} ${THIS_FLAG}")
	endif()
endforeach()
message(STATUS "Linker flags: ${WS_LINK_FLAGS}")

if(APPLE AND EXISTS /usr/local/opt/gettext)
	# GLib on macOS requires libintl. Homebrew installs gettext (and
	# libintl) in /usr/local/opt/gettext
	include_directories(SYSTEM /usr/local/opt/gettext/include)
	link_directories(/usr/local/opt/gettext/lib)
endif()

# Resets cache variables if the <PackageName>_LIBRARY has become invalid.
# Call it before a find_package(<PackageName> ...) invocation that uses
# find_library(<PackageName>_LIBRARY ...).
#
# Usage: reset_find_package(<PackageName> [<extra variables to clear>])
function(reset_find_package _package_name)
	set(variables
		# find_library / find_package
		${_package_name}_LIBRARY
		${_package_name}_INCLUDE_DIR
		# mark_as_advanced
		${_package_name}_LIBRARIES
		${_package_name}_INCLUDE_DIRS
		# Others
		${_package_name}_DLL_DIR
		${_package_name}_DLLS
		${_package_name}_DLL
		${_package_name}_PDB
		${ARGN}
	)
	if(NOT ${_package_name}_LIBRARY OR EXISTS ${${_package_name}_LIBRARY})
		# Cache variable is already missing or cache entry is valid.
		return()
	endif()
	message(STATUS "Package ${_package_name} has changed, clearing cache.")
	foreach(_var IN LISTS variables)
		unset(${_var} CACHE)
	endforeach()
endfunction()

# ws_find_package(<PackageName>
#             <CMakeOptions.txt boolean variable>
#             <cmakeconfig.h.in macro definition>
#             [remaining find_package() arguments])
macro(ws_find_package _package_name _enable_package _package_cmakedefine)
	if(${_enable_package})
		# Clear outdated cache variables if not already.
		reset_find_package(${_package_name})
		find_package(${_package_name} ${ARGN})
		if(${_package_name}_FOUND)
			set(${_package_cmakedefine} 1)
		endif()
	endif()
endmacro()

# The minimum package list
find_package(Git)
reset_find_package(GLIB2 GLIB2_MAIN_INCLUDE_DIR GLIB2_INTERNAL_INCLUDE_DIR)
find_package(GLIB2 "2.54.0" REQUIRED)
include_directories(SYSTEM ${GLIB2_INCLUDE_DIRS})
reset_find_package(GMODULE2)
find_package(GMODULE2)
reset_find_package(GTHREAD2)
find_package(GTHREAD2 REQUIRED)
reset_find_package(GCRYPT GCRYPT_ERROR_LIBRARY)
find_package(GCRYPT "1.8.0" REQUIRED)
# C Asynchronous resolver
reset_find_package(CARES)
find_package(CARES "1.13.0" REQUIRED)
if (CARES_VERSION VERSION_GREATER_EQUAL "1.28.0")
	# Suppress deprecation warnings.
	add_compile_definitions(CARES_NO_DEPRECATED)
endif ()
find_package(LEX REQUIRED)
find_package(Perl)
reset_find_package(PCRE2 PCRE2_DEBUG_LIBRARY)
find_package(PCRE2 REQUIRED)

if (NOT WIN32)
	find_package(Gettext)
	find_package(M REQUIRED)
endif()

if(BUILD_sshdump OR BUILD_ciscodump OR BUILD_wifidump)
	set(ENABLE_LIBSSH ON)
else()
	set(ENABLE_LIBSSH OFF)
endif()
ws_find_package(LIBSSH ENABLE_LIBSSH HAVE_LIBSSH "0.8.5")

ws_find_package(PCAP ENABLE_PCAP HAVE_LIBPCAP)
ws_find_package(AIRPCAP ENABLE_AIRPCAP HAVE_AIRPCAP)
ws_find_package(Systemd BUILD_sdjournal HAVE_SYSTEMD)

# Build one of the Qt GUIs?
if(BUILD_wireshark OR BUILD_logray)
	if(USE_qt6)
		set(qtver 6)
		if(DEFINED ENV{WIRESHARK_QT6_PREFIX_PATH})
			list(APPEND CMAKE_PREFIX_PATH $ENV{WIRESHARK_QT6_PREFIX_PATH})
		endif()

		set(CMAKE_CXX_STANDARD 17)
		# Setting CMAKE_CXX_STANDARD is not sufficient with MSVC, see
		#   https://gitlab.kitware.com/cmake/cmake/-/issues/18837
		# The below test can be found in Qt6, lib/cmake/Qt6/QtFeature.cmake
		if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC" AND MSVC_VERSION GREATER_EQUAL 1913)
			# Cannot use add_definitions() here because rc.exe does not understand this flag.
			# https://cmake.org/pipermail/cmake/2009-August/031672.html
			set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Zc:__cplusplus")
		endif()

		find_package(Qt6 REQUIRED
			COMPONENTS
				Core
				Gui
				LinguistTools
				PrintSupport
				Widgets
				Concurrent
				Core5Compat
				DBus
			OPTIONAL_COMPONENTS
				Multimedia
		)
	else(USE_qt6)
		set(qtver 5)
		if(DEFINED ENV{WIRESHARK_QT5_PREFIX_PATH})
			list(APPEND CMAKE_PREFIX_PATH $ENV{WIRESHARK_QT5_PREFIX_PATH})
		endif()
		if(APPLE AND EXISTS /usr/local/opt/qt5)
			# Homebrew installs Qt5 (up to at least 5.11.0) in
			# /usr/local/qt5. Ensure that it can be found by CMake
			# since it is not in the default /usr/local prefix.
			# Add it to PATHS so that it doesn't override the
			# CMAKE_PREFIX_PATH environment variable.
			# QT_FIND_PACKAGE_OPTIONS should be passed to find_package,
			# e.g. find_package(Qt5Core ${QT_FIND_PACKAGE_OPTIONS})
			list(APPEND QT5_FIND_PACKAGE_OPTIONS PATHS /usr/local/opt/qt5)
		endif()

		set(QT5_PACKAGELIST
			Qt5Core
			Qt5Gui
			Qt5LinguistTools
			Qt5PrintSupport
			Qt5Widgets
			Qt5Concurrent
		)
		set(QT5_OPTIONAL_PACKAGELIST
			Qt5Multimedia
		)
		if(WIN32)
			list(APPEND QT5_PACKAGELIST Qt5WinExtras)
		endif()
		if(NOT WIN32 AND NOT APPLE)
			# DBus is a core component of Qt6, but was an add-on in Qt5.
			list(APPEND QT5_OPTIONAL_PACKAGELIST Qt5DBus)
		endif()
		foreach(_qt5_package IN LISTS QT5_PACKAGELIST)
			find_package(${_qt5_package} REQUIRED ${QT5_FIND_PACKAGE_OPTIONS})
			list(APPEND QT5_LIBRARIES ${${_qt5_package}_LIBRARIES})
			list(APPEND QT5_INCLUDE_DIRS ${${_qt5_package}_INCLUDE_DIRS})
			list(APPEND QT5_COMPILE_DEFINITIONS ${${_qt5_package}_COMPILE_DEFINITIONS})
		endforeach()
		foreach(_qt5_package IN LISTS QT5_OPTIONAL_PACKAGELIST)
			find_package(${_qt5_package} ${QT5_FIND_PACKAGE_OPTIONS})
			list(APPEND QT5_LIBRARIES ${${_qt5_package}_LIBRARIES})
			list(APPEND QT5_INCLUDE_DIRS ${${_qt5_package}_INCLUDE_DIRS})
			list(APPEND QT5_COMPILE_DEFINITIONS ${${_qt5_package}_COMPILE_DEFINITIONS})
		endforeach()

		if (Qt5Widgets_VERSION VERSION_LESS 5.11)
			message(FATAL_ERROR "Qt 5.12 or later is required.")
		endif()
		if (Qt5Widgets_VERSION VERSION_LESS 5.12)
			message(WARNING "Wireshark can be built with this version of Qt, though 5.12 or higher is recommended.")
		endif()

		if(APPLE AND "/usr/local/opt/qt5/lib/QtCore.framework" IN_LIST Qt5Core_INCLUDE_DIRS)
			# When qt@6 and qt@5 are both installed via Homebrew,
			# /usr/local/include/QtCore/qvariant.h points to Qt 6 headers.
			# Normally the Headers from `-iframework /usr/local/opt/qt5/lib`
			# should be used, but `-isystem /usr/local/include` (via
			# Libgcrypt and others) seems to prioritized, resulting in use
			# of the Qt6 headers. Resolve this by explicit including Qt5.
			list(APPEND QT5_INCLUDE_DIRS /usr/local/opt/qt5/include)
		endif()
	endif(USE_qt6)

	set(QT_FOUND ON)
	if(APPLE)
		ws_find_package(Sparkle ENABLE_SPARKLE HAVE_SOFTWARE_UPDATE 2)
	endif()
	if(Qt6Multimedia_FOUND OR Qt5Multimedia_FOUND)
		set(QT_MULTIMEDIA_LIB 1)
	endif()
	if(Qt6DBus_FOUND OR Qt5DBus_FOUND)
		set(QT_DBUS_LIB 1)
	endif()
	if(NOT DEFINED MOC_OPTIONS)
		# Squelch moc verbose "nothing to do" output
		set(MOC_OPTIONS -nn)
	endif()
endif()

# MaxMind DB address resolution
reset_find_package(MAXMINDDB)
ws_find_package(MaxMindDB BUILD_mmdbresolve HAVE_MAXMINDDB)

# SMI SNMP
reset_find_package(SMI SMI_SHARE_DIR)
ws_find_package(SMI ENABLE_SMI HAVE_LIBSMI)

# Support for TLS decryption using RSA private keys.
ws_find_package(GNUTLS ENABLE_GNUTLS HAVE_LIBGNUTLS "3.5.8")

# Kerberos
ws_find_package(KERBEROS ENABLE_KERBEROS HAVE_KERBEROS)

# Zlib-ng compression
ws_find_package(ZLIBNG ENABLE_ZLIBNG HAVE_ZLIBNG)

#if(NOT ZLIBNG_FOUND)
    # Zlib compression
    ws_find_package(ZLIB ENABLE_ZLIB HAVE_ZLIB)
#endif()

# Minizip-ng compression
ws_find_package(Minizipng ENABLE_MINIZIPNG HAVE_MINIZIPNG)

if(NOT MINIZIPNG_FOUND)
  # Minizip compression
  ws_find_package(Minizip ENABLE_MINIZIP HAVE_MINIZIP)
endif()

# Brotli compression
ws_find_package(BROTLI ENABLE_BROTLI HAVE_BROTLI)

# LZ4 compression
ws_find_package(LZ4 ENABLE_LZ4 HAVE_LZ4)

# Snappy compression
ws_find_package(SNAPPY ENABLE_SNAPPY HAVE_SNAPPY)

# zstd compression
ws_find_package(ZSTD ENABLE_ZSTD HAVE_ZSTD "1.0.0")

# Enhanced HTTP/2 dissection
ws_find_package(NGHTTP2 ENABLE_NGHTTP2 HAVE_NGHTTP2 "1.11.0")

# Enhanced HTTP/3 dissection
ws_find_package(NGHTTP3 ENABLE_NGHTTP3 HAVE_NGHTTP3)

# Embedded Lua interpreter
if(FETCH_lua)
	# Download and build lua
	include(${CMAKE_SOURCE_DIR}/cmake/external/lua53/Lua53.cmake)
else()
	set(LUA_FIND_VERSIONS "5.4;5.3" CACHE STRING "Lua versions valid for the build (as a list)")
	ws_find_package(Lua ENABLE_LUA HAVE_LUA)
endif()

ws_find_package(NL ENABLE_NETLINK HAVE_LIBNL)

ws_find_package(SBC ENABLE_SBC HAVE_SBC)

# SpanDSP codec
ws_find_package(SPANDSP ENABLE_SPANDSP HAVE_SPANDSP)

ws_find_package(BCG729 ENABLE_BCG729 HAVE_BCG729)

ws_find_package(AMRNB ENABLE_AMRNB HAVE_AMRNB)

ws_find_package(ILBC ENABLE_ILBC HAVE_ILBC)

ws_find_package(OPUS ENABLE_OPUS HAVE_OPUS)

if (BUILD_logray)
	# libsinsp+libscap, required for falco-bridge
	ws_find_package(Sinsp ENABLE_SINSP HAVE_SINSP)
endif()

# CMake 3.9 and below used 'LIBXML2_LIBRARIES' as the name of the cache entry
# storing the find_library result. Transfer it to the new cache variable such
# that reset_find_package can detect and clear outdated cache variables.
if(DEFINED LIBXML2_LIBRARIES AND NOT DEFINED LIBXML2_LIBRARY)
	set(LIBXML2_LIBRARY ${LIBXML2_LIBRARIES} CACHE FILEPATH "")
endif()
# Call reset_find_package explicitly since variables are in upper case.
reset_find_package(LIBXML2)
ws_find_package(LibXml2 ENABLE_LIBXML2 HAVE_LIBXML2)
if(NOT LIBXML2_FOUND)
	# CMake 3.9 and below used LIBXML2_LIBRARIES as the name of
	# the cache entry storing the find_library result.
	# Current CMake (3.13) and below sets LIBXML2_LIBRARIES and LIBXML2_INCLUDE_DIRS
	# to a non-empty value, be sure to clear it when not found.
	set(LIBXML2_LIBRARIES "")
	set(LIBXML2_INCLUDE_DIRS "")
endif()

# Capabilities to run dumpcap as non-root user.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	ws_find_package(CAP ENABLE_CAP HAVE_LIBCAP)
	find_package(SETCAP)
endif()

# Windows version updates
ws_find_package(WinSparkle ENABLE_WINSPARKLE HAVE_SOFTWARE_UPDATE)

find_package( Asciidoctor 1.5 )
find_package( XSLTPROC )

find_package(DOXYGEN)

# The SpeexDSP resampler is required iff building wireshark or sharkd.
if(BUILD_wireshark OR BUILD_logray OR BUILD_sharkd)
	find_package(SpeexDSP REQUIRED)
endif()

# Generate the distribution tarball.
add_custom_target(dist
	COMMAND ${CMAKE_BINARY_DIR}/packaging/source/git-export-release.sh -d "${CMAKE_BINARY_DIR}"
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

if(GNUTLS_FOUND)
	# Calculating public keys from PKCS #11 private keys requires GnuTLS
	# 3.4.0 or greater.
	#
	# Check that the support is present in case GnuTLS was compiled
	# --without-p11-kit as macos-setup.sh did until December 2020.
	cmake_push_check_state()
	if(WIN32 AND NOT MINGW)
		set(CMAKE_REQUIRED_DEFINITIONS -Dssize_t=int)
	endif()
	set(CMAKE_REQUIRED_INCLUDES ${GNUTLS_INCLUDE_DIRS})
	set(CMAKE_REQUIRED_LIBRARIES ${GNUTLS_LIBRARIES})
	check_symbol_exists(gnutls_pkcs11_obj_list_import_url4 gnutls/pkcs11.h HAVE_GNUTLS_PKCS11)
	cmake_pop_check_state()
endif()

if (QT_FOUND)
	# CMake uses qmake to find Qt4. It relies on Qt's CMake modules
	# to find Qt5. This means that we can't assume that the qmake
	# in our PATH is the correct one. We can fetch qmake's location
	# from Qt5::qmake, which is defined in Qt5CoreConfigExtras.cmake.
	get_target_property(QT_QMAKE_EXECUTABLE Qt${qtver}::qmake IMPORTED_LOCATION)
	get_filename_component(_qt_bin_path "${QT_QMAKE_EXECUTABLE}" DIRECTORY)
	set(QT_BIN_PATH "${_qt_bin_path}" CACHE INTERNAL
		"Path to qmake, macdeployqt, windeployqt, and other Qt utilities."
	)
	# Use qmake to find windeployqt and macdeployqt. Ideally one of
	# the modules in ${QTDIR}/lib/cmake would do this for us.
	if(WIN32)
		if (USE_qt6 AND USE_MSYSTEM)
			set(_windeployqt_name "windeployqt-qt6")
		else()
			set(_windeployqt_name "windeployqt")
		endif()
		find_program(QT_WINDEPLOYQT_EXECUTABLE ${_windeployqt_name}
			HINTS "${QT_BIN_PATH}"
			DOC "Path to the windeployqt utility."
		)
		# As of Qt 6.5.0, the official Qt "MSVC 2019 ARM64 (TP)" libraries don't ship
		# with native Arm64 executables. Instead, you get x64 executables installed in
		# msvc2019_x64. Look for the path to "qmake.bat", which has to be passed to
		# windeployqt so that it can install the proper DLLs.
		# https://bugreports.qt.io/browse/QTBUG-100070
		set(QT_WINDEPLOYQT_EXTRA_ARGS)
		find_program(_qt_qmake_bat qmake.bat
			HINTS ENV CMAKE_PREFIX_PATH
			PATH_SUFFIXES bin
			DOC "Path to qmake.bat."
		)
		if(_qt_qmake_bat)
			set (QT_WINDEPLOYQT_EXTRA_ARGS "--qmake \"${_qt_qmake_bat}\"")
		endif()
	elseif(APPLE)
		find_program(QT_MACDEPLOYQT_EXECUTABLE macdeployqt
			HINTS "${QT_BIN_PATH}"
			DOC "Path to the macdeployqt utility."
		)
		find_program(DMGBUILD_EXECUTABLE dmgbuild
			DOC "Path to the dmgbuild utility"
		)
		# https://doc.qt.io/qt-5/supported-platforms.html
		# https://doc.qt.io/qt-5.11/supported-platforms-and-configurations.html
		# https://doc.qt.io/qt-5.15/supported-platforms.html
		# https://doc-snapshots.qt.io/qt6-dev/supported-platforms.html
		if(Qt${qtver}Widgets_VERSION VERSION_GREATER_EQUAL "6.5.0" AND MIN_MACOS_VERSION VERSION_LESS "11.0")
			set(MIN_MACOS_VERSION 11.0)
		elseif(Qt${qtver}Widgets_VERSION VERSION_GREATER_EQUAL "6.0.0" AND MIN_MACOS_VERSION VERSION_LESS "10.14")
			set(MIN_MACOS_VERSION 10.14)
		elseif(Qt5Widgets_VERSION VERSION_GREATER_EQUAL "5.14.0" AND MIN_MACOS_VERSION VERSION_LESS "10.13")
			set(MIN_MACOS_VERSION 10.13)
		elseif(Qt5Widgets_VERSION VERSION_GREATER_EQUAL "5.12.0" AND MIN_MACOS_VERSION VERSION_LESS "10.12")
			set(MIN_MACOS_VERSION 10.12)
		endif()
		if(CMAKE_OSX_DEPLOYMENT_TARGET AND CMAKE_OSX_DEPLOYMENT_TARGET VERSION_LESS MIN_MACOS_VERSION)
			message(FATAL_ERROR "Qt version ${Qt${qtver}Widgets_VERSION} requires CMAKE_OSX_DEPLOYMENT_TARGET (${CMAKE_OSX_DEPLOYMENT_TARGET}) >= ${MIN_MACOS_VERSION}")
		endif()
	endif()

	# Qt requires MSVC /permissive- option since 6.3 release
	if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC" AND Qt${qtver}Widgets_VERSION VERSION_GREATER_EQUAL "6.3.0")
		add_compile_options("/permissive-")
	endif()
endif()

if(ENABLE_CHECKHF_CONFLICT)
	set(ENABLE_CHECK_FILTER 1)
endif()

#
# Platform-specific additional libraries.
#
if(WIN32)
	set(WIN_COMCTL32_LIBRARY comctl32.lib)
	set(WIN_IPHLPAPI_LIBRARY iphlpapi.lib)
	set(WIN_PSAPI_LIBRARY    psapi.lib)
	set(WIN_VERSION_LIBRARY  version.lib)
	set(WIN_WS2_32_LIBRARY   ws2_32.lib)
endif()

if(APPLE)
	#
	# We assume that APPLE means macOS so that we have the macOS
	# frameworks.
	#
	set(HAVE_MACOS_FRAMEWORKS 1)
	FIND_LIBRARY (APPLE_APPLICATION_SERVICES_LIBRARY ApplicationServices)
	FIND_LIBRARY (APPLE_APPKIT_LIBRARY AppKit)
	FIND_LIBRARY (APPLE_CORE_FOUNDATION_LIBRARY CoreFoundation)
	FIND_LIBRARY (APPLE_SYSTEM_CONFIGURATION_LIBRARY SystemConfiguration)

	message(STATUS "Building for Mac OS X/OS X/macOS ${MIN_MACOS_VERSION} using SDK ${CMAKE_OSX_SYSROOT}")
endif()

include(ConfigureChecks.cmake)

# Global properties
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

if(ENABLE_CCACHE)
	if(NOT (CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID MATCHES "Clang"))
		# https://ccache.dev/platform-compiler-language-support.html
		message(WARNING "Ccache is enabled, but your compiler is ${CMAKE_C_COMPILER_ID}."
		" We wish you the best of luck.")
	endif()
	find_program(CCACHE_EXECUTABLE ccache)
	if(CCACHE_EXECUTABLE)
		set(CMAKE_C_COMPILER_LAUNCHER "${CCACHE_EXECUTABLE}")
		set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_EXECUTABLE}")
		set(CMAKE_C_LINKER_LAUNCHER "${CCACHE_EXECUTABLE}")
		set(CMAKE_CXX_LINKER_LAUNCHER "${CCACHE_EXECUTABLE}")
	endif()
endif()

# The top level checkAPIs target, add before subdirectory calls so it's available to all
add_custom_target(checkAPI)
set_target_properties(checkAPI
	PROPERTIES
		FOLDER "Auxiliary"
		EXCLUDE_FROM_ALL True
		EXCLUDE_FROM_DEFAULT_BUILD True
)

include( UseCheckAPI )

# Target platform locations
# UN*X in general, including macOS if not building an app bundle:
# $DESTDIR/lib/wireshark/extcap
# Windows: $DESTDIR/extcap
# macOS app bundle: Wireshark.app/Contents/Resources/share/wireshark/extcap
# If you change the nesting level be sure to check also the INSTALL_RPATH
# target property.
if(WIN32 AND NOT USE_MSYSTEM)
	set(EXTCAP_INSTALL_LIBDIR "extcap/${PROJECT_NAME}" CACHE INTERNAL "The Wireshark extcap dir")
	if (BUILD_logray)
		set(LOG_EXTCAP_INSTALL_LIBDIR "extcap/${LOG_PROJECT_NAME}" CACHE INTERNAL "The Logray extcap dir")
	endif()
else()
	set(EXTCAP_INSTALL_LIBDIR "${CMAKE_INSTALL_LIBDIR}/${PROJECT_NAME}/extcap" CACHE INTERNAL "The Wireshark extcap dir")
	if (BUILD_logray)
		set(LOG_EXTCAP_INSTALL_LIBDIR "${CMAKE_INSTALL_LIBDIR}/${LOG_PROJECT_NAME}/extcap" CACHE INTERNAL "The Logray extcap dir")
	endif()
endif()

if(APPLE)
	#
	# As https://developer.apple.com/library/archive/technotes/tn2206/_index.html
	# says,
	#
	# "Note that a location where code is expected to reside cannot generally
	# contain directories full of nested code, because those directories tend
	# to be interpreted as bundles. So this occasional practice is not
	# recommended and not officially supported. If you do do this, do not use
	# periods in the directory names. The code signing machinery interprets
	# directories with periods in their names as code bundles and will reject
	# them if they don't conform to the expected code bundle layout."
	#
	set(PLUGIN_PATH_ID "${PROJECT_MAJOR_VERSION}-${PROJECT_MINOR_VERSION}")
else()
	set(PLUGIN_PATH_ID "${PROJECT_MAJOR_VERSION}.${PROJECT_MINOR_VERSION}")
endif()

# Directory where plugins and Lua dissectors can be found.
if(WIN32 AND NOT USE_MSYSTEM)
	set(PLUGIN_INSTALL_LIBDIR "plugins" CACHE INTERNAL "The plugin dir")
else()
	set(PLUGIN_INSTALL_LIBDIR "${CMAKE_INSTALL_LIBDIR}/${PROJECT_NAME}/plugins" CACHE INTERNAL "The plugin dir")
endif()
set(PLUGIN_INSTALL_FULL_LIBDIR "${CMAKE_INSTALL_PREFIX}/${PLUGIN_INSTALL_LIBDIR}")
set(PLUGIN_INSTALL_VERSION_LIBDIR "${PLUGIN_INSTALL_LIBDIR}/${PLUGIN_PATH_ID}")
set(PLUGIN_VERSION_DIR "plugins/${PLUGIN_PATH_ID}")

add_subdirectory( capture )
add_subdirectory( doc )
add_subdirectory( epan )
add_subdirectory( extcap )
add_subdirectory( randpkt_core )
if(NOT LEMON_EXECUTABLE)
	add_subdirectory( tools/lemon )
endif()
if(PCAP_FOUND)
	add_subdirectory( tools/radiotap-gen )
endif()
add_subdirectory( ui )
add_subdirectory( wiretap )
add_subdirectory( writecap )

# Location of our data files. This should be set to a value that allows
# running from the build directory on Windows, on macOS when building an
# application bundle, and on UNIX in general if
# WIRESHARK_RUN_FROM_BUILD_DIRECTORY is set.
if(ENABLE_APPLICATION_BUNDLE)
	if(CMAKE_CFG_INTDIR STREQUAL ".")
		set(_datafile_dir "${CMAKE_BINARY_DIR}/run/Wireshark.app/Contents/Resources/share/wireshark")
	else()
		# Xcode
		set(_datafile_dir "${CMAKE_BINARY_DIR}/run/${CMAKE_CFG_INTDIR}/Wireshark.app/Contents/Resources/share/wireshark")
	endif()
elseif(NOT CMAKE_CFG_INTDIR STREQUAL ".")
	# Visual Studio, Xcode, etc.
	set(_datafile_dir "${CMAKE_BINARY_DIR}/run/${CMAKE_CFG_INTDIR}")
else()
	# Makefile, Ninja, etc.
	set(_datafile_dir "${CMAKE_BINARY_DIR}/run")
endif()

set(DATAFILE_DIR ${_datafile_dir} CACHE INTERNAL "Build time data file location.")

if(ENABLE_APPLICATION_BUNDLE)
	if(CMAKE_CFG_INTDIR STREQUAL ".")
		set(_log_datafile_dir "${CMAKE_BINARY_DIR}/run/Logray.app/Contents/Resources/share/logray")
	else()
		# Xcode
		set(_log_datafile_dir "${CMAKE_BINARY_DIR}/run/${CMAKE_CFG_INTDIR}/Logray.app/Contents/Resources/share/logray")
	endif()
	set(LOG_DATAFILE_DIR ${_log_datafile_dir} CACHE INTERNAL "Build time log analysis data file location.")
# XXX We need to update wsutil/filesystem.c and packaging/nsis/*logray* to match.
# elseif(NOT CMAKE_CFG_INTDIR STREQUAL ".")
# 	# Visual Studio, Xcode, etc.
# 	set(_log_datafile_dir "${CMAKE_BINARY_DIR}/run/${CMAKE_CFG_INTDIR}/share/logray")
# else()
# 	# Makefile, Ninja, etc.
# 	set(_log_datafile_dir "${CMAKE_BINARY_DIR}/run/share/logray")
endif()

# wsutil must be added after DATAFILE_DIR is set such that filesystem.c can
# learn about the directory location.
add_subdirectory( wsutil )

# docbook must be added after DATAFILE_DIR is set so that the guides can be
# copied there for running from the build directory
add_subdirectory( docbook EXCLUDE_FROM_ALL )

if(BUILD_wireshark AND QT_FOUND)
	add_subdirectory( ui/qt )
elseif(BUILD_wireshark AND USE_qt6)
	message(VERBOSE "To use Qt5 instead of Qt6 use CMake option USE_qt6=OFF.")
endif()

if(BUILD_logray AND QT_FOUND)
	add_subdirectory( ui/logray )
endif()

# Location of our plugins. PLUGIN_DIR should allow running
# from the build directory similar to DATAFILE_DIR above.
if(ENABLE_PLUGINS)
	# Target platform locations
	# UN*X in general, including macOS if not building an app bundle:
	# $DESTDIR/lib/wireshark/plugins/$VERSION
	# Windows: $DESTDIR/wireshark/plugins/$VERSION
	# macOS app bundle: Wireshark.app/Contents/PlugIns/wireshark
	set(HAVE_PLUGINS 1)
	add_custom_target(plugins)
	set_target_properties(plugins PROPERTIES FOLDER "Plugins")
	set(PLUGIN_SRC_DIRS
		plugins/epan/ethercat
		plugins/epan/gryphon
		plugins/epan/irda
		plugins/epan/mate
		plugins/epan/opcua
		plugins/epan/profinet
		plugins/epan/stats_tree
		plugins/epan/transum
		plugins/epan/unistim
		plugins/epan/wimax
		plugins/epan/wimaxasncp
		plugins/epan/wimaxmacphy
		plugins/epan/dfilter/ipaddr
		plugins/wiretap/usbdump
		plugins/codecs/G711
		plugins/codecs/l16_mono
		${CUSTOM_PLUGIN_SRC_DIR}
	)
	set(LOGRAY_PLUGIN_SRC_DIRS)
	if(SINSP_FOUND)
		list(APPEND LOGRAY_PLUGIN_SRC_DIRS
			plugins/epan/falco_bridge
		)
	endif()
	if(SPANDSP_FOUND)
		list(APPEND PLUGIN_SRC_DIRS
			plugins/codecs/G722
			plugins/codecs/G726
		)
	endif()
	if(BCG729_FOUND)
		list(APPEND PLUGIN_SRC_DIRS
			plugins/codecs/G729
		)
	endif()
	if(AMRNB_FOUND)
		list(APPEND PLUGIN_SRC_DIRS
			plugins/codecs/amrnb
		)
	endif()
	if(ILBC_FOUND)
		list(APPEND PLUGIN_SRC_DIRS
			plugins/codecs/iLBC
		)
	endif()
	if(OPUS_FOUND)
		list(APPEND PLUGIN_SRC_DIRS
			plugins/codecs/opus_dec
		)
	endif()
	if(SBC_FOUND)
		list(APPEND PLUGIN_SRC_DIRS
			plugins/codecs/sbc
		)
	endif()

	# Build demo plugin, only if asked explicitly
	if(ENABLE_PLUGIN_IFDEMO)
		list(APPEND PLUGIN_SRC_DIRS
			plugins/epan/pluginifdemo
		)
	endif()

else()
	set(PLUGIN_SRC_DIRS )
	set(LOGRAY_PLUGIN_SRC_DIRS )
endif()

if(ENABLE_APPLICATION_BUNDLE)
	if(CMAKE_CFG_INTDIR STREQUAL ".")
		set(_plugin_dir "${CMAKE_BINARY_DIR}/run/Wireshark.app/Contents/PlugIns/wireshark/${PLUGIN_PATH_ID}")
	else()
		# Xcode
		set(_plugin_dir "${CMAKE_BINARY_DIR}/run/$<CONFIG>/Wireshark.app/Contents/PlugIns/wireshark/${PLUGIN_PATH_ID}")
	endif()
	if(CMAKE_CFG_INTDIR STREQUAL ".")
		set(_logray_plugin_dir "${CMAKE_BINARY_DIR}/run/Logray.app/Contents/PlugIns/logray/${PLUGIN_PATH_ID}")
	else()
		# Xcode
		set(_logray_plugin_dir "${CMAKE_BINARY_DIR}/run/$<CONFIG>/Logray.app/Contents/PlugIns/logray/${PLUGIN_PATH_ID}")
	endif()
elseif(MSVC AND NOT CMAKE_CFG_INTDIR STREQUAL ".")
	set(_plugin_dir "${CMAKE_BINARY_DIR}/run/$<CONFIG>/${PLUGIN_VERSION_DIR}")
	set(_logray_plugin_dir ${_plugin_dir})
else()
	set(_plugin_dir "${DATAFILE_DIR}/${PLUGIN_VERSION_DIR}")
	set(_logray_plugin_dir ${_plugin_dir})
endif()
set (PLUGIN_DIR ${_plugin_dir} CACHE INTERNAL "Build time plugin location.")
set (LOGRAY_PLUGIN_DIR ${_logray_plugin_dir} CACHE INTERNAL "Build time Logray plugin location.")

foreach(_plugin_src_dir ${PLUGIN_SRC_DIRS} ${LOGRAY_PLUGIN_SRC_DIRS})
	add_subdirectory( ${_plugin_src_dir} )
endforeach()

if(VCSVERSION_OVERRIDE)
	# Allow distributors to override detection of the Git tag and version.
	string(CONFIGURE "#define VCSVERSION \"@VCSVERSION_OVERRIDE@\"\n"
		_version_h_contents ESCAPE_QUOTES)
	file(WRITE "${CMAKE_BINARY_DIR}/vcs_version.h" "${_version_h_contents}")
	message(STATUS "VCSVERSION_OVERRIDE: ${VCSVERSION_OVERRIDE}")
else()
	add_custom_target(vcs_version
		BYPRODUCTS vcs_version.h
		COMMAND ${Python3_EXECUTABLE}
			${CMAKE_SOURCE_DIR}/tools/make-version.py
			${CMAKE_SOURCE_DIR}
	)
	set_target_properties(vcs_version PROPERTIES FOLDER "Auxiliary")
endif()

set( configure_input "Built with CMake ${CMAKE_VERSION}" )
configure_file(${CMAKE_SOURCE_DIR}/cmakeconfig.h.in ${CMAKE_BINARY_DIR}/config.h)

configure_file(${CMAKE_SOURCE_DIR}/ws_version.h.in ${CMAKE_BINARY_DIR}/ws_version.h)

# Doxygen variables
file(GLOB TOP_LEVEL_SOURCE_LIST *.c *.cpp *.h)
string (REPLACE ";" " " DOXYGEN_TOP_LEVEL_SOURCES "${TOP_LEVEL_SOURCE_LIST}")
set(DOXYGEN_INPUT_DIRECTORY ${CMAKE_SOURCE_DIR})
set(DOXYGEN_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

set(CFG_OUT_FILES
	doxygen.cfg
	packaging/macosx/osx-app.sh
	packaging/macosx/osx-dmg.sh
	packaging/macosx/wireshark-app.dmgbuild
	packaging/macosx/wireshark-dsym.dmgbuild
	packaging/macosx/WiresharkInfo.plist
	packaging/source/git-export-release.sh
	resources/dumpcap.rc
	resources/libwireshark.rc
	resources/libwiretap.rc
	resources/libwsutil.rc
	resources/wireshark.exe.manifest
	resources/wireshark.pc
	resources/wireshark.rc
)

if(BUILD_logray)
	list(APPEND CFG_OUT_FILES
		packaging/macosx/LograyInfo.plist
		packaging/macosx/logray-app.dmgbuild
		packaging/macosx/logray-dsym.dmgbuild
		resources/logray.exe.manifest
	)
endif()

foreach( _cfg_file ${CFG_OUT_FILES} )
	configure_file( ${CMAKE_SOURCE_DIR}/${_cfg_file}.in ${CMAKE_BINARY_DIR}/${_cfg_file} @ONLY )
endforeach()

include(FeatureSummary)
set_package_properties(CAP PROPERTIES
	DESCRIPTION "The Libcap package implements the user-space interfaces to the POSIX 1003.1e capabilities available in Linux kernels"
	URL "https://sites.google.com/site/fullycapable/"
	PURPOSE "Allow packet captures without running as root"
)
set_package_properties(SBC PROPERTIES
	DESCRIPTION "Bluetooth low-complexity, subband codec (SBC) decoder"
	URL "https://git.kernel.org/pub/scm/bluetooth/sbc.git"
	PURPOSE "Support for playing SBC codec in RTP player"
)
set_package_properties(SPANDSP PROPERTIES
	DESCRIPTION "a library of many DSP functions for telephony"
	URL "https://www.soft-switch.org"
	PURPOSE "Support for G.722 and G.726 codecs in RTP player"
)
set_package_properties(BCG729 PROPERTIES
	DESCRIPTION "G.729 decoder"
	URL "https://www.linphone.org/technical-corner/bcg729"
	PURPOSE "Support for G.729 codec in RTP player"
)
set_package_properties(AMRNB PROPERTIES
	DESCRIPTION "AMRNB decoder"
	URL "https://sourceforge.net/p/opencore-amr"
	PURPOSE "Support for AMRNB codec in RTP player"
)
set_package_properties(ILBC PROPERTIES
	DESCRIPTION "iLBC decoder"
	URL "https://github.com/TimothyGu/libilbc"
	PURPOSE "Support for iLBC codec in RTP player"
)
set_package_properties(OPUS PROPERTIES
	DESCRIPTION "opus decoder"
	URL "https://opus-codec.org/"
	PURPOSE "Support for opus codec in RTP player"
)
set_package_properties(LIBXML2 PROPERTIES
	DESCRIPTION "XML parsing library"
	URL "http://xmlsoft.org/"
	PURPOSE "Read XML configuration files in EPL dissector"
)
set_package_properties(LIBSSH PROPERTIES
	DESCRIPTION "Library for implementing SSH clients"
	URL "https://www.libssh.org/"
	PURPOSE "extcap remote SSH interfaces (sshdump, ciscodump, wifidump)"
)
set_package_properties(LZ4 PROPERTIES
	DESCRIPTION "LZ4 is a fast lossless compression algorithm"
	URL "http://www.lz4.org"
	PURPOSE "LZ4 decompression in CQL and Kafka dissectors, read compressed capture files"
)
set_package_properties(SNAPPY PROPERTIES
	DESCRIPTION "A fast compressor/decompressor from Google"
	URL "https://google.github.io/snappy/"
	PURPOSE "Snappy decompression in Couchbase, CQL, Kafka and Mongo dissectors"
)
set_package_properties(ZSTD PROPERTIES
	DESCRIPTION "A compressor/decompressor from Facebook providing better compression than Snappy at a cost of speed"
	URL "https://facebook.github.io/zstd/"
	PURPOSE "Zstd decompression in Kafka dissector, read compressed capture files"
)
set_package_properties(NGHTTP2 PROPERTIES
	DESCRIPTION "HTTP/2 C library and tools"
	URL "https://nghttp2.org"
	PURPOSE "Header decompression in HTTP2"
)
set_package_properties(NGHTTP3 PROPERTIES
	DESCRIPTION "HTTP/3 C library and tools"
	URL "https://nghttp2.org"
	PURPOSE "Header decompression in HTTP3"
)
set_package_properties(CARES PROPERTIES
	DESCRIPTION "Library for asynchronous DNS requests"
	URL "https://c-ares.org/"
	PURPOSE "DNS name resolution for captures"
)
set_package_properties(Systemd PROPERTIES
	URL "https://freedesktop.org/wiki/Software/systemd/"
	DESCRIPTION "System and Service Manager (libraries)"
	PURPOSE "Support for systemd journal extcap interface (sdjournal)"
)
set_package_properties(NL PROPERTIES
	URL "https://www.infradead.org/~tgr/libnl/"
	DESCRIPTION "Libraries for using the Netlink protocol on Linux"
	PURPOSE "Support for managing wireless 802.11 interfaces"
)
set_package_properties(MaxMindDB PROPERTIES
	URL "https://github.com/maxmind/libmaxminddb"
	DESCRIPTION "C library for the MaxMind DB file format"
	PURPOSE "Support for GeoIP lookup"
)
set_package_properties(SpeexDSP PROPERTIES
	URL "https://www.speex.org/"
	DESCRIPTION "SpeexDSP is a patent-free, Open Source/Free Software DSP library"
	PURPOSE "RTP audio resampling"
)
set_package_properties(Minizip PROPERTIES
	URL "https://github.com/madler/zlib"
	DESCRIPTION "Mini zip and unzip based on zlib"
	PURPOSE "Support for profiles import/export"
)
set_package_properties(Minizipng PROPERTIES
	URL "https://github.com/zlib-ng/minizip-ng"
	DESCRIPTION "A fork of the minizip library - Mini zip and unzip based on zlib"
	PURPOSE "Support for profiles import/export"
)
set_package_properties(SMI PROPERTIES
	URL "https://www.ibr.cs.tu-bs.de/projects/libsmi/"
	DESCRIPTION "Library to access SMI management information"
	PURPOSE "Support MIB and PIB parsing and OID resolution"
)
set_package_properties(PCRE2 PROPERTIES
	URL "https://www.pcre.org"
	DESCRIPTION "Regular expression pattern matching using the same syntax and semantics as Perl 5"
	PURPOSE "Support for regular expressions"
)
set_package_properties(Sinsp PROPERTIES
	DESCRIPTION "libsinsp and libscap"
	URL "https://github.com/falcosecurity/libs/"
	PURPOSE "Support for Falco plugins"
)
set_package_properties(Lua PROPERTIES
	DESCRIPTION "Lua is a powerful, efficient, lightweight, embeddable scripting language"
	URL "https://www.lua.org/"
	PURPOSE "Lua allows writing dissectors and other extensions without a C/C++ compiler"
)

string(TOUPPER "${CMAKE_BUILD_TYPE}" _build_type)
message(STATUS "C-Flags: ${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${_build_type}}")
message(STATUS "CXX-Flags: ${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${_build_type}}")
if(WERROR_COMMON_FLAGS)
	message(STATUS "Warnings as errors enabled: ${WERROR_COMMON_FLAGS}")
else()
	message(STATUS "Warnings as errors disabled")
endif()

feature_summary(WHAT ALL)

# Should this be part of libui?
if(WIN32)
	set(PLATFORM_UI_SRC
		ui/win32/file_dlg_win32.cpp
	)
elseif(APPLE)
	set(PLATFORM_UI_SRC
		ui/macosx/cocoa_bridge.mm
	)
	if (SPARKLE_FOUND)
		list(APPEND PLATFORM_UI_SRC ui/macosx/sparkle_bridge.m)
	endif()
endif()

set(TSHARK_TAP_SRC
	${CMAKE_SOURCE_DIR}/ui/cli/tap-credentials.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-camelsrt.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-diameter-avp.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-expert.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-exportobject.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-endpoints.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-flow.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-follow.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-funnel.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-gsm_astat.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-hosts.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-httpstat.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-icmpstat.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-icmpv6stat.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-iostat.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-iousers.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-macltestat.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-protocolinfo.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-protohierstat.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-rlcltestat.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-rpcprogs.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-rtd.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-rtp.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-rtspstat.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-sctpchunkstat.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-simple_stattable.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-sipstat.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-smbsids.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-srt.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-stats_tree.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-sv.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-voip.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-wspstat.c
	${CUSTOM_TSHARK_TAP_SRC}

)

# Copied into ${DATAFILE_DIR} at build time and ${CMAKE_INSTALL_DATADIR}/wireshark
# at install time.
set(INSTALL_DIRS
	resources/share/wireshark/profiles
	resources/protocols/diameter
	resources/protocols/dtds
	resources/protocols/radius
	resources/protocols/tpncp
	resources/protocols/wimaxasncp
)

# Copied into ${DATAFILE_DIR} at build time and ${CMAKE_INSTALL_DATADIR}/wireshark
# at install time.
set(INSTALL_FILES
	resources/share/wireshark/cfilters
	resources/share/wireshark/colorfilters
	resources/share/wireshark/dmacros
	resources/share/wireshark/dfilters
	resources/share/wireshark/ipmap.html
	resources/share/wireshark/smi_modules
	wka
)

set(DOC_FILES
	resources/share/doc/wireshark/pdml2html.xsl
	doc/README.xml-output
	doc/ws.css
)

if (BUILD_logray)
	set(LOG_INSTALL_DIRS
		resources/share/logray/profiles
	)

	set(LOG_INSTALL_FILES
		doc/ws.css
		resources/share/logray/colorfilters
		resources/share/logray/dfilter_buttons
	)
endif()

if (ASCIIDOCTOR_FOUND)
	list(APPEND DOC_FILES
		${CMAKE_BINARY_DIR}/doc/man_pages/androiddump.html
		${CMAKE_BINARY_DIR}/doc/man_pages/udpdump.html
		${CMAKE_BINARY_DIR}/doc/man_pages/capinfos.html
		${CMAKE_BINARY_DIR}/doc/man_pages/captype.html
		${CMAKE_BINARY_DIR}/doc/man_pages/ciscodump.html
		${CMAKE_BINARY_DIR}/doc/man_pages/dumpcap.html
		${CMAKE_BINARY_DIR}/doc/man_pages/editcap.html
		${CMAKE_BINARY_DIR}/doc/man_pages/extcap.html
		${CMAKE_BINARY_DIR}/doc/man_pages/mergecap.html
		${CMAKE_BINARY_DIR}/doc/man_pages/randpkt.html
		${CMAKE_BINARY_DIR}/doc/man_pages/randpktdump.html
		${CMAKE_BINARY_DIR}/doc/man_pages/etwdump.html
		${CMAKE_BINARY_DIR}/doc/man_pages/rawshark.html
		${CMAKE_BINARY_DIR}/doc/man_pages/reordercap.html
		${CMAKE_BINARY_DIR}/doc/man_pages/sshdump.html
		${CMAKE_BINARY_DIR}/doc/man_pages/wifidump.html
		${CMAKE_BINARY_DIR}/doc/man_pages/text2pcap.html
		${CMAKE_BINARY_DIR}/doc/man_pages/tshark.html
		${CMAKE_BINARY_DIR}/doc/man_pages/wireshark.html
		${CMAKE_BINARY_DIR}/doc/man_pages/wireshark-filter.html
		${CMAKE_BINARY_DIR}/doc/release-notes.html
	)
	if(MAXMINDDB_FOUND)
		list(APPEND DOC_FILES ${CMAKE_BINARY_DIR}/doc/man_pages/mmdbresolve.html)
	endif()

	if (BUILD_corbaidl2wrs)
		list(APPEND DOC_FILES ${CMAKE_BINARY_DIR}/doc/man_pages/idl2wrs.html)
	endif()
	if (BUILD_xxx2deb)
		list(APPEND DOC_FILES
			${CMAKE_BINARY_DIR}/doc/man_pages/asn2deb.html
			${CMAKE_BINARY_DIR}/doc/man_pages/idl2deb.html
		)
	endif()
	if (BUILD_logray)
		list(APPEND DOC_FILES
			${CMAKE_BINARY_DIR}/doc/man_pages/falcodump.html
		)
	endif()
endif()

if(NOT WIN32)
	# We do this for Windows further down in the copy_data_files target.
	list(APPEND DOC_FILES COPYING)
endif()

if(USE_REPOSITORY)
	set(_dll_output_dir "$<TARGET_FILE_DIR:wsutil>")
	add_custom_target(copy_cli_dlls)
	set_target_properties(copy_cli_dlls PROPERTIES FOLDER "Copy Tasks")
	add_custom_command(TARGET copy_cli_dlls PRE_BUILD
		COMMAND ${CMAKE_COMMAND} -E make_directory "${_dll_output_dir}"
	)

	# XXX Can (and should) we iterate over these similar to the way
	# the top-level CMakeLists.txt iterates over the package list?

	# Required DLLs and their corresponding PDBs.
	add_custom_command(TARGET copy_cli_dlls PRE_BUILD
		COMMAND ${CMAKE_COMMAND} -E copy_if_different
			"$<IF:$<CONFIG:Debug>,${GLIB2_DLLS_DEBUG},${GLIB2_DLLS_RELEASE}>"
			"$<IF:$<CONFIG:Debug>,${GLIB2_PDBS_DEBUG},${GLIB2_PDBS_RELEASE}>"
			"${_dll_output_dir}"
		WORKING_DIRECTORY $<IF:$<CONFIG:Debug>,${GLIB2_DLL_DIR_DEBUG},${GLIB2_DLL_DIR_RELEASE}>
		COMMAND_EXPAND_LISTS
	)

	add_custom_command(TARGET copy_cli_dlls PRE_BUILD
		COMMAND ${CMAKE_COMMAND} -E copy_if_different
			"$<IF:$<CONFIG:Debug>,${PCRE2_DEBUG_DLL},${PCRE2_RELEASE_DLL}>"
			"$<IF:$<CONFIG:Debug>,${PCRE2_DEBUG_PDB},${PCRE2_RELEASE_PDB}>"
			"${_dll_output_dir}"
		WORKING_DIRECTORY $<IF:$<CONFIG:Debug>,${PCRE2_DEBUG_DLL_DIR},${PCRE2_RELEASE_DLL_DIR}>
		COMMAND_EXPAND_LISTS
	)

	if (MSVC AND VLD_FOUND)
		add_custom_command(TARGET copy_cli_dlls PRE_BUILD
			COMMAND ${CMAKE_COMMAND} -E "$<IF:$<CONFIG:Debug>,copy_if_different,true>"
			"${VLD_FILES}"
			"${_dll_output_dir}"
			COMMAND_EXPAND_LISTS
		)
	endif()

	# Third party DLLs and PDBs.
	set (THIRD_PARTY_DLLS)
	set (THIRD_PARTY_PDBS)
	if (AIRPCAP_FOUND)
		list (APPEND THIRD_PARTY_DLLS "${AIRPCAP_DLL_DIR}/${AIRPCAP_DLL}")
	endif(AIRPCAP_FOUND)
	list (APPEND THIRD_PARTY_DLLS "${CARES_DLL_DIR}/${CARES_DLL}")
	list (APPEND THIRD_PARTY_PDBS "${CARES_DLL_DIR}/${CARES_PDB}")
	# vcpkg's libmaxminddb is static-only for now. This can be uncommented when
	# https://github.com/maxmind/libmaxminddb/commit/3998f42bdb6678cbaa1a543057e5c81ba1668ac2
	# percolates up to vcpkg.
	# if (MAXMINDDB_FOUND)
	# 	list (APPEND THIRD_PARTY_DLLS "${MAXMINDDB_DLL_DIR}/${MAXMINDDB_DLL}")
	# endif(MAXMINDDB_FOUND)
	if (LIBSSH_FOUND)
		foreach( _dll ${LIBSSH_DLLS} )
			list (APPEND THIRD_PARTY_DLLS "${LIBSSH_DLL_DIR}/${_dll}")
		endforeach(_dll)
	endif(LIBSSH_FOUND)
	foreach( _dll ${GCRYPT_DLLS} )
		list (APPEND THIRD_PARTY_DLLS "${GCRYPT_DLL_DIR}/${_dll}")
	endforeach(_dll)
	foreach( _dll ${GNUTLS_DLLS} )
		list (APPEND THIRD_PARTY_DLLS "${GNUTLS_DLL_DIR}/${_dll}")
	endforeach(_dll)
	foreach( _dll ${KERBEROS_DLLS} )
		list (APPEND THIRD_PARTY_DLLS "${KERBEROS_DLL_DIR}/${_dll}")
	endforeach(_dll)
	if (LUA_FOUND)
		list (APPEND THIRD_PARTY_DLLS "${LUA_DLL_DIR}/${LUA_DLL}")
	endif(LUA_FOUND)
	if (LZ4_FOUND)
		list (APPEND THIRD_PARTY_DLLS "${LZ4_DLL_DIR}/${LZ4_DLL}")
		list (APPEND THIRD_PARTY_PDBS "${LZ4_DLL_DIR}/${LZ4_PDB}")
	endif(LZ4_FOUND)
	if (MINIZIP_FOUND)
		list (APPEND THIRD_PARTY_DLLS "${MINIZIP_DLL_DIR}/${MINIZIP_DLL}")
		list (APPEND THIRD_PARTY_PDBS "${MINIZIP_DLL_DIR}/${MINIZIP_PDB}")
	endif()
	if (MINIZIPNG_FOUND)
		foreach( _dll ${MINIZIPNG_DLLS} )
			list (APPEND THIRD_PARTY_DLLS "${MINIZIPNG_DLL_DIR}/${_dll}")
		endforeach(_dll)
		foreach( _pdb ${MINIZIPNG_PDBS} )
			list (APPEND THIRD_PARTY_PDBS "${MINIZIPNG_DLL_DIR}/${_pdb}")
		endforeach(_pdb)
	endif()
	if (NGHTTP2_FOUND)
		list (APPEND THIRD_PARTY_DLLS "${NGHTTP2_DLL_DIR}/${NGHTTP2_DLL}")
		list (APPEND THIRD_PARTY_PDBS "${NGHTTP2_DLL_DIR}/${NGHTTP2_PDB}")
	endif(NGHTTP2_FOUND)
	if (NGHTTP3_FOUND)
		list (APPEND THIRD_PARTY_DLLS "${NGHTTP3_DLL_DIR}/${NGHTTP3_DLL}")
		list (APPEND THIRD_PARTY_PDBS "${NGHTTP3_DLL_DIR}/${NGHTTP3_PDB}")
	endif(NGHTTP3_FOUND)
	if (SBC_FOUND)
		list (APPEND THIRD_PARTY_DLLS "${SBC_DLL_DIR}/${SBC_DLL}")
	endif(SBC_FOUND)
	if (SPANDSP_FOUND)
		list (APPEND THIRD_PARTY_DLLS "${SPANDSP_DLL_DIR}/${SPANDSP_DLL}")
	endif(SPANDSP_FOUND)
	if (BCG729_FOUND)
		list (APPEND THIRD_PARTY_DLLS "${BCG729_DLL_DIR}/${BCG729_DLL}")
	endif(BCG729_FOUND)
	if (AMRNB_FOUND)
		list (APPEND THIRD_PARTY_DLLS "${AMRNB_DLL_DIR}/${AMRNB_DLL}")
	endif(AMRNB_FOUND)
	if (ILBC_FOUND)
		list (APPEND THIRD_PARTY_DLLS "${ILBC_DLL_DIR}/${ILBC_DLL}")
	endif(ILBC_FOUND)
	if (OPUS_FOUND)
		list (APPEND THIRD_PARTY_DLLS "${OPUS_DLL_DIR}/${OPUS_DLL}")
	endif(OPUS_FOUND)
	if (LIBXML2_FOUND)
		foreach( _dll ${LIBXML2_DLLS} )
			list (APPEND THIRD_PARTY_DLLS "${LIBXML2_DLL_DIR}/${_dll}")
		endforeach(_dll)
		foreach( _pdb ${LIBXML2_PDBS} )
			list (APPEND THIRD_PARTY_PDBS "${LIBXML2_DLL_DIR}/${_pdb}")
		endforeach(_pdb)
	endif(LIBXML2_FOUND)
	if (SMI_FOUND)
		list (APPEND THIRD_PARTY_DLLS "${SMI_DLL_DIR}/${SMI_DLL}")
		# Wireshark.nsi wants SMI_DIR which is the base SMI directory
		get_filename_component(SMI_DIR ${SMI_DLL_DIR} DIRECTORY)
		add_custom_command(TARGET copy_cli_dlls PRE_BUILD
			COMMAND ${CMAKE_COMMAND} -E make_directory
				"${_dll_output_dir}/snmp"
			COMMAND ${CMAKE_COMMAND} -E make_directory
				"${_dll_output_dir}/snmp/mibs"
			COMMAND ${CMAKE_COMMAND} -E copy_directory
				"${SMI_SHARE_DIR}/mibs/iana"
				"${_dll_output_dir}/snmp/mibs"
			COMMAND ${CMAKE_COMMAND} -E copy_directory
				"${SMI_SHARE_DIR}/mibs/ietf"
				"${_dll_output_dir}/snmp/mibs"
			COMMAND ${CMAKE_COMMAND} -E copy_directory
				"${SMI_SHARE_DIR}/mibs/irtf"
				"${_dll_output_dir}/snmp/mibs"
			COMMAND ${CMAKE_COMMAND} -E copy_directory
				"${SMI_SHARE_DIR}/mibs/site"
				"${_dll_output_dir}/snmp/mibs"
			COMMAND ${CMAKE_COMMAND} -E copy_directory
				"${SMI_SHARE_DIR}/mibs/tubs"
				"${_dll_output_dir}/snmp/mibs"
			COMMAND ${CMAKE_COMMAND} -E copy_directory
				"${SMI_SHARE_DIR}/pibs"
				"${_dll_output_dir}/snmp/mibs"
			COMMAND ${CMAKE_COMMAND} -E copy_directory
				"${SMI_SHARE_DIR}/yang"
				"${_dll_output_dir}/snmp/mibs"
			#remove the extra directories copied (shallow copying the above would remove the need for this)
			COMMAND ${CMAKE_COMMAND} -E remove_directory
				"${_dll_output_dir}/snmp/mibs/iana"
			COMMAND ${CMAKE_COMMAND} -E remove_directory
				"${_dll_output_dir}/snmp/mibs/ietf"
			COMMAND ${CMAKE_COMMAND} -E remove_directory
				"${_dll_output_dir}/snmp/mibs/site"
			COMMAND ${CMAKE_COMMAND} -E remove_directory
				"${_dll_output_dir}/snmp/mibs/tubs"
		)
	endif(SMI_FOUND)
	if (SNAPPY_FOUND)
		list (APPEND THIRD_PARTY_DLLS "${SNAPPY_DLL_DIR}/${SNAPPY_DLL}")
	endif(SNAPPY_FOUND)
	if (WINSPARKLE_FOUND)
		list (APPEND THIRD_PARTY_DLLS "${WINSPARKLE_DLL_DIR}/${WINSPARKLE_DLL}")
	endif(WINSPARKLE_FOUND)
	if (ZLIB_FOUND)
		list (APPEND THIRD_PARTY_DLLS "${ZLIB_DLL_DIR}/${ZLIB_DLL}")
		list (APPEND THIRD_PARTY_PDBS "${ZLIB_DLL_DIR}/${ZLIB_PDB}")
	endif(ZLIB_FOUND)
	if (ZLIBNG_FOUND)
		list (APPEND THIRD_PARTY_DLLS "${ZLIBNG_DLL_DIR}/${ZLIBNG_DLL}")
		list (APPEND THIRD_PARTY_PDBS "${ZLIBNG_DLL_DIR}/${ZLIBNG_PDB}")
	endif(ZLIBNG_FOUND)
	if (BROTLI_FOUND)
		foreach( _dll ${BROTLI_DLLS} )
			list (APPEND THIRD_PARTY_DLLS "${BROTLI_DLL_DIR}/${_dll}")
		endforeach(_dll)
	endif(BROTLI_FOUND)
	if (SPEEXDSP_FOUND)
		list (APPEND THIRD_PARTY_DLLS "${SPEEXDSP_DLL_DIR}/${SPEEXDSP_DLL}")
	endif()
	if (ZSTD_FOUND)
		list (APPEND THIRD_PARTY_DLLS "${ZSTD_DLL_DIR}/${ZSTD_DLL}")
	endif()

	# With libs downloaded to c:/wireshark-x64-libs this currently
	# (early 2018) expands to about 1900 characters.
	if (THIRD_PARTY_DLLS)
		add_custom_command(TARGET copy_cli_dlls PRE_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy_if_different
				${THIRD_PARTY_DLLS}
				"${_dll_output_dir}"
			VERBATIM
		)
		install(FILES ${THIRD_PARTY_DLLS} DESTINATION "${CMAKE_INSTALL_BINDIR}")
	endif(THIRD_PARTY_DLLS)

	if (THIRD_PARTY_PDBS)
		add_custom_command(TARGET copy_cli_dlls PRE_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy_if_different
				${THIRD_PARTY_PDBS}
				"${_dll_output_dir}"
			VERBATIM
		)
	endif(THIRD_PARTY_PDBS)

	add_dependencies(epan copy_cli_dlls)

	# We have a lot of choices for creating zip archives:
	# - 7z, WinZip, etc., which require a separate download+install.
	# - "CMake -E tar cz", which creates a tar file.
	# - CPack, which requires a CPack configuration.
	# - PowerShell via PSCX or System.IO.Compression.FileSystem.
	# - Python via zipfile.
	# For now, just look for 7z. It's installed on the Windows builders,
	# which might be the only systems that use this target.
	find_program(ZIP_EXECUTABLE 7z
		PATH "$ENV{PROGRAMFILES}/7-Zip" "$ENV{PROGRAMW6432}/7-Zip"
		DOC "Path to the 7z utility."
	)
	if(ZIP_EXECUTABLE)
		add_custom_target(pdb_zip_package COMMENT "This packages .PDBs but will not create them.")
		set_target_properties(pdb_zip_package PROPERTIES FOLDER "Packaging")
		set(_pdb_zip "${CMAKE_BINARY_DIR}/Wireshark-pdb-${PROJECT_VERSION}-${WIRESHARK_TARGET_PLATFORM}.zip")
		file(TO_NATIVE_PATH "${_pdb_zip}" _pdb_zip_win)
		add_custom_command(TARGET pdb_zip_package POST_BUILD
			COMMAND ${CMAKE_COMMAND} -E remove -f "${_pdb_zip}"
			COMMAND ${ZIP_EXECUTABLE} a -tzip -mmt=on "${_pdb_zip_win}"
				-bb0 -bd
				-r *.pdb *.lib
			WORKING_DIRECTORY "${_dll_output_dir}"
		)
	endif()
endif()

# List of extra dependencies for the "copy_data_files" target
set(copy_data_files_depends)

if(WIN32)
	foreach(_install_as_txt_file COPYING NEWS README.md)
		# On Windows, install some files with a .txt extension so that they're
		# double-clickable.
		string(REGEX REPLACE ".md$" "" _no_md_file ${_install_as_txt_file})
		set(_output_file "${DATAFILE_DIR}/${_no_md_file}.txt")
		add_custom_command(OUTPUT ${_output_file}
			COMMAND ${CMAKE_COMMAND} -E copy_if_different
				${CMAKE_SOURCE_DIR}/${_install_as_txt_file}
				${_output_file}
			DEPENDS
				${CMAKE_SOURCE_DIR}/${_install_as_txt_file}
		)
		list(APPEND copy_data_files_depends "${_output_file}")
	endforeach()
endif()

foreach(_install_file ${INSTALL_FILES} ${DOC_FILES})
	get_filename_component(_install_file_src "${_install_file}" ABSOLUTE)
	get_filename_component(_install_basename "${_install_file}" NAME)
	set(_output_file "${DATAFILE_DIR}/${_install_basename}")
	add_custom_command(OUTPUT "${_output_file}"
		COMMAND ${CMAKE_COMMAND} -E copy_if_different
			"${_install_file_src}"
			"${_output_file}"
		DEPENDS
			docs
			"${_install_file}"
	)
	list(APPEND copy_data_files_depends "${_output_file}")
endforeach()

if (BUILD_logray)
	if (ENABLE_APPLICATION_BUNDLE)
		foreach(_install_file ${LOG_INSTALL_FILES})
			get_filename_component(_install_file_src "${_install_file}" ABSOLUTE)
			get_filename_component(_install_basename "${_install_file}" NAME)
			set(_output_file "${LOG_DATAFILE_DIR}/${_install_basename}")
			add_custom_command(OUTPUT "${_output_file}"
				COMMAND ${CMAKE_COMMAND} -E copy_if_different
					"${_install_file_src}"
					"${_output_file}"
				DEPENDS
					docs
					"${_install_file}"
			)
			list(APPEND copy_data_files_depends "${_output_file}")
		endforeach()
	else()
		# XXX The default profile (colorfilters, dfilters) is at the
		# top-level resources directory for both Wireshark and Logray.
	endif()
endif()

set(_protocol_data_dir ${CMAKE_SOURCE_DIR}/resources/protocols)
# Glob patterns relative to the source directory that should be copied to
# ${DATAFILE_DIR} (including directory prefixes)
# TODO shouldn't this use full (relative) paths instead of glob patterns?
set(DATA_FILES_SRC
	${_protocol_data_dir}/tpncp/tpncp.dat
	${_protocol_data_dir}/wimaxasncp/*.dtd
	${_protocol_data_dir}/wimaxasncp/*.xml
)

# Copy all paths from the source tree to the data directory. Directories are
# automatically created if missing as the filename is given.
file(GLOB _data_files RELATIVE ${_protocol_data_dir} ${DATA_FILES_SRC})
foreach(_data_file ${_data_files})
	add_custom_command(OUTPUT "${DATAFILE_DIR}/${_data_file}"
		COMMAND ${CMAKE_COMMAND} -E copy_if_different
			${_protocol_data_dir}/${_data_file}
			${DATAFILE_DIR}/${_data_file}
		DEPENDS
			${_protocol_data_dir}/${_data_file}
	)
	list(APPEND copy_data_files_depends ${DATAFILE_DIR}/${_data_file})
endforeach()

file(GLOB _dtds_src_files RELATIVE ${_protocol_data_dir} ${_protocol_data_dir}/dtds/*.dtd)

set (_dtds_data_files)
set (_dtds_dep_files)
foreach(_data_file ${_dtds_src_files})
	list(APPEND _dtds_data_files ${DATAFILE_DIR}/${_data_file})
	list(APPEND _dtds_dep_files ${_protocol_data_dir}/${_data_file})
endforeach()

add_custom_command(
	OUTPUT ${_dtds_data_files}
	COMMAND ${CMAKE_COMMAND} -E make_directory ${DATAFILE_DIR}/dtds
	COMMAND ${CMAKE_COMMAND} -E copy_if_different
		${_dtds_src_files}
		${DATAFILE_DIR}/dtds
	VERBATIM
	DEPENDS ${_dtds_dep_files}
	WORKING_DIRECTORY ${_protocol_data_dir}
)

file(GLOB _diameter_src_files RELATIVE ${_protocol_data_dir}
	${_protocol_data_dir}/diameter/*.dtd
	${_protocol_data_dir}/diameter/*.xml
)

set (_diameter_data_files)
set (_diameter_dep_files)
foreach(_data_file ${_diameter_src_files})
	list(APPEND _diameter_data_files ${DATAFILE_DIR}/${_data_file})
	list(APPEND _diameter_dep_files ${_protocol_data_dir}/${_data_file})
endforeach()

add_custom_command(
	OUTPUT ${_diameter_data_files}
	COMMAND ${CMAKE_COMMAND} -E make_directory ${DATAFILE_DIR}/diameter
	COMMAND ${CMAKE_COMMAND} -E copy_if_different
		${_diameter_src_files}
		${DATAFILE_DIR}/diameter
	VERBATIM
	DEPENDS ${_diameter_dep_files}
	WORKING_DIRECTORY ${_protocol_data_dir}
)

file(GLOB _radius_src_files RELATIVE ${_protocol_data_dir}
	CONFIGURE_DEPENDS
	${_protocol_data_dir}/radius/README.radius_dictionary
	${_protocol_data_dir}/radius/custom.includes
	${_protocol_data_dir}/radius/dictionary
	${_protocol_data_dir}/radius/dictionary.*
)

set (_radius_data_files)
set (_radius_dep_files)
foreach(_data_file ${_radius_src_files})
	list(APPEND _radius_data_files ${DATAFILE_DIR}/${_data_file})
	list(APPEND _radius_dep_files ${_protocol_data_dir}/${_data_file})
endforeach()

add_custom_command(
	OUTPUT ${_radius_data_files}
	COMMAND ${CMAKE_COMMAND} -E make_directory ${DATAFILE_DIR}/radius
	COMMAND ${CMAKE_COMMAND} -E copy_if_different
		${_radius_src_files}
		${DATAFILE_DIR}/radius
	VERBATIM
	DEPENDS ${_radius_dep_files}
	WORKING_DIRECTORY ${_protocol_data_dir}
)

file(GLOB _protobuf_src_files RELATIVE ${_protocol_data_dir}
	${_protocol_data_dir}/protobuf/*.proto
)
set (_protobuf_data_files)
set (_protobuf_dep_files)
foreach(_data_file ${_protobuf_src_files})
	list(APPEND _protobuf_data_files ${DATAFILE_DIR}/${_data_file})
	list(APPEND _protobuf_dep_files ${_protocol_data_dir}/${_data_file})
endforeach()

add_custom_command(
	OUTPUT ${_protobuf_data_files}
	COMMAND ${CMAKE_COMMAND} -E make_directory ${DATAFILE_DIR}/protobuf
	COMMAND ${CMAKE_COMMAND} -E copy_if_different
		${_protobuf_src_files}
		${DATAFILE_DIR}/protobuf
	VERBATIM
	DEPENDS ${_protobuf_dep_files}
	WORKING_DIRECTORY ${_protocol_data_dir}
)

set(_profiles_src_dir ${CMAKE_SOURCE_DIR}/resources/share/wireshark)
file(GLOB _profiles_src_files RELATIVE ${_profiles_src_dir} ${_profiles_src_dir}/profiles/*/*)
set (_profiles_data_files)
foreach(_data_file ${_profiles_src_files})
	list(APPEND _profiles_data_files "${DATAFILE_DIR}/${_data_file}")
endforeach()

add_custom_command(
	OUTPUT ${_profiles_data_files}
	COMMAND ${CMAKE_COMMAND} -E copy_directory
		"${CMAKE_SOURCE_DIR}/resources/share/wireshark/profiles" "${DATAFILE_DIR}/profiles"
)

set (_log_profiles_data_files)
if (BUILD_logray AND ENABLE_APPLICATION_BUNDLE)
	set(_profiles_src_dir ${CMAKE_SOURCE_DIR}/resources/share/logray)
	file(GLOB _profiles_src_files RELATIVE ${_profiles_src_dir} ${_profiles_src_dir}/profiles/*/*)
	foreach(_data_file ${_profiles_src_files})
		list(APPEND _log_profiles_data_files "${LOG_DATAFILE_DIR}/${_data_file}")
	endforeach()

	add_custom_command(
		OUTPUT ${_log_profiles_data_files}
		COMMAND ${CMAKE_COMMAND} -E copy_directory
			"${CMAKE_SOURCE_DIR}/resources/share/logray/profiles" "${LOG_DATAFILE_DIR}/profiles"
	)
endif()

list(APPEND copy_data_files_depends
	${_dtds_data_files}
	${_diameter_data_files}
	${_radius_data_files}
	${_protobuf_data_files}
	${_profiles_data_files}
	${_log_profiles_data_files}
)

# Copy files including ${INSTALL_FILES} and ${INSTALL_DIRS} to ${DATAFILE_DIR}
add_custom_target(copy_data_files ALL DEPENDS ${copy_data_files_depends} )
set_target_properties(copy_data_files PROPERTIES FOLDER "Copy Tasks")

# sources common for wireshark, tshark, rawshark and sharkd
add_library(shark_common OBJECT
	cfile.c
	extcap_parser.c
	file_packet_provider.c
	frame_tvbuff.c
	sync_pipe_write.c
)
add_library(cli_main OBJECT cli_main.c)
add_library(capture_opts OBJECT capture_opts.c)
target_include_directories(capture_opts SYSTEM PRIVATE ${PCAP_INCLUDE_DIRS})
set_target_properties(shark_common cli_main capture_opts
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)


if(BUILD_wireshark AND QT_FOUND)
	set(WIRESHARK_SRC
		file.c
		fileset.c
		extcap.c
		${PLATFORM_UI_SRC}
	)
	set(wireshark_FILES
		$<TARGET_OBJECTS:capture_opts>
		$<TARGET_OBJECTS:shark_common>
		${WIRESHARK_SRC}
		${PLATFORM_UI_RC_FILES}
	)
	set_executable_resources(wireshark "Wireshark" UNIQUE_RC)
endif()

if(BUILD_logray AND QT_FOUND)
	set(LOGRAY_SRC
		file.c
		fileset.c
		extcap.c
		${PLATFORM_UI_SRC}
	)
	set(logray_FILES
		$<TARGET_OBJECTS:capture_opts>
		$<TARGET_OBJECTS:shark_common>
		${LOGRAY_SRC}
		${PLATFORM_UI_RC_FILES}
	)
	set_executable_resources(logray "Logray" UNIQUE_RC)
endif()

if(ENABLE_APPLICATION_BUNDLE)
	#
	# Add -Wl,-single_module to the LDFLAGS used with shared
	# libraries, to fix some error that show up in some cases;
	# some Apple documentation recommends it for most shared
	# libraries.
	#
	set( CMAKE_SHARED_LINKER_FLAGS "-Wl,-single_module ${CMAKE_SHARED_LINKER_FLAGS}" )
	#
	# Add -Wl,-headerpad_max_install_names to the LDFLAGS, as
	# code-signing issues is running out of padding space.
	#
	# Add -Wl,-search_paths_first to make sure that if we search
	# directories A and B, in that order, for a given library, a
	# non-shared version in directory A, rather than a shared
	# version in directory B, is chosen (so we can use
	# --with-pcap=/usr/local to force all programs to be linked
	# with a static version installed in /usr/local/lib rather than
	# the system version in /usr/lib).
	#

	set(CMAKE_EXE_LINKER_FLAGS
	"-Wl,-headerpad_max_install_names -Wl,-search_paths_first ${CMAKE_EXE_LINKER_FLAGS}"
	)

	# Add files to the Wireshark application bundle
	# Wireshark.app/Contents
	file(WRITE ${CMAKE_BINARY_DIR}/packaging/macosx/wireshark/PkgInfo "APPLWshk\n")
	set(WIRESHARK_BUNDLE_CONTENTS_FILES
		${CMAKE_BINARY_DIR}/packaging/macosx/wireshark/PkgInfo
	)
	set_source_files_properties(${WIRESHARK_BUNDLE_CONTENTS_FILES} PROPERTIES
		MACOSX_PACKAGE_LOCATION .
	)

	# Wireshark.app/Contents/Resources
	set(WIRESHARK_BUNDLE_RESOURCE_FILES
		${CMAKE_SOURCE_DIR}/packaging/macosx/Wireshark.icns
		${CMAKE_SOURCE_DIR}/packaging/macosx/Wiresharkdoc.icns
	)
	set_source_files_properties(${WIRESHARK_BUNDLE_RESOURCE_FILES} PROPERTIES
		MACOSX_PACKAGE_LOCATION Resources
	)

	# Wireshark.app/Contents/Resources/share/man/man1
	set_source_files_properties(${WIRESHARK_BUNDLE_RESOURCE_SHARE_MAN1_FILES} PROPERTIES
		MACOSX_PACKAGE_LOCATION Resources/share/man/man1
		GENERATED 1
	)

	# Wireshark.app/Contents/Resources/share/man/man4
	set_source_files_properties(${WIRESHARK_BUNDLE_RESOURCE_SHARE_MAN4_FILES} PROPERTIES
		MACOSX_PACKAGE_LOCATION Resources/share/man/man4
		GENERATED 1
	)

	# INSTALL_FILES and INSTALL_DIRS are handled by copy_data_files

	set(EXTRA_WIRESHARK_BUNDLE_FILES
		${WIRESHARK_BUNDLE_CONTENTS_FILES}
		${WIRESHARK_BUNDLE_RESOURCE_FILES}
		${WIRESHARK_BUNDLE_RESOURCE_SHARE_MAN1_FILES}
		${WIRESHARK_BUNDLE_RESOURCE_SHARE_MAN4_FILES}
	)

	# Add files to the Logray application bundle
	# Logray.app/Contents
	file(WRITE ${CMAKE_BINARY_DIR}/packaging/macosx/logray/PkgInfo "APPLLgry\n")
	set(LOGRAY_BUNDLE_CONTENTS_FILES
		${CMAKE_BINARY_DIR}/packaging/macosx/logray/PkgInfo
	)
	set_source_files_properties(${LOGRAY_BUNDLE_CONTENTS_FILES} PROPERTIES
		MACOSX_PACKAGE_LOCATION .
	)

	# Logray.app/Contents/Resources
	set(LOGRAY_BUNDLE_RESOURCE_FILES
		${CMAKE_SOURCE_DIR}/packaging/macosx/Logray.icns
		${CMAKE_SOURCE_DIR}/packaging/macosx/Wiresharkdoc.icns
	)
	set_source_files_properties(${LOGRAY_BUNDLE_RESOURCE_FILES} PROPERTIES
		MACOSX_PACKAGE_LOCATION Resources
	)

	# Logray.app/Contents/Resources/share/man/man1
	set_source_files_properties(${LOGRAY_BUNDLE_RESOURCE_SHARE_MAN1_FILES} PROPERTIES
		MACOSX_PACKAGE_LOCATION Resources/share/man/man1
		GENERATED 1
	)

	# Logray.app/Contents/Resources/share/man/man4
	set_source_files_properties(${LOGRAY_BUNDLE_RESOURCE_SHARE_MAN4_FILES} PROPERTIES
		MACOSX_PACKAGE_LOCATION Resources/share/man/man4
		GENERATED 1
	)

	# INSTALL_FILES and INSTALL_DIRS are handled by copy_data_files

	set(EXTRA_LOGRAY_BUNDLE_FILES
		${LOGRAY_BUNDLE_CONTENTS_FILES}
		${LOGRAY_BUNDLE_RESOURCE_FILES}
		${LOGRAY_BUNDLE_RESOURCE_SHARE_MAN1_FILES}
		${LOGRAY_BUNDLE_RESOURCE_SHARE_MAN4_FILES}
	)

else()
	set(EXTRA_WIRESHARK_BUNDLE_FILES)
	set(EXTRA_LOGRAY_BUNDLE_FILES)
endif()

if(BUILD_wireshark AND QT_FOUND)
	set(wireshark_LIBS
		ui
		qtui
		capchild
		caputils
		iface_monitor
		wiretap
		epan
		summary
		${QT5_LIBRARIES}
		${APPLE_APPLICATION_SERVICES_LIBRARY}
		${APPLE_APPKIT_LIBRARY}
		${APPLE_CORE_FOUNDATION_LIBRARY}
		${APPLE_SYSTEM_CONFIGURATION_LIBRARY}
		${SPARKLE_LIBRARIES}
		${WIN_WS2_32_LIBRARY}
		${WIN_VERSION_LIBRARY}
		${WINSPARKLE_LIBRARIES}
		$<$<BOOL:${WIN32}>:uxtheme.lib>
		${SPEEXDSP_LIBRARIES}
		${ZLIB_LIBRARIES}
		${ZLIBNG_LIBRARIES}
		${MINIZIP_LIBRARIES}
		${MINIZIPNG_LIBRARIES}
	)

	add_executable(wireshark WIN32 MACOSX_BUNDLE ${wireshark_FILES} ${EXTRA_WIRESHARK_BUNDLE_FILES})
	if(MSVC)
		set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT wireshark)
	endif()
	set(PROGLIST ${PROGLIST} wireshark)
	set_target_properties(wireshark PROPERTIES
		LINK_FLAGS "${WS_LINK_FLAGS}"
		FOLDER "Executables"
		INSTALL_RPATH "${EXECUTABLE_INSTALL_RPATH}"
		AUTOMOC ON
		AUTOUIC ON
		AUTORCC ON
	)
	if(MSVC)
		set_target_properties(wireshark PROPERTIES LINK_FLAGS_DEBUG "${WS_MSVC_DEBUG_LINK_FLAGS}")
	endif()
	if (USE_MSYSTEM)
		set_target_properties(wireshark PROPERTIES OUTPUT_NAME wireshark)
	elseif(ENABLE_APPLICATION_BUNDLE OR WIN32)
		set_target_properties(wireshark PROPERTIES OUTPUT_NAME Wireshark)
	endif()

	if(ENABLE_APPLICATION_BUNDLE)
		if(ASCIIDOCTOR_FOUND)
			# Make sure to generate files referenced by
			# WIRESHARK_BUNDLE_RESOURCE_SHARE_MAN1_FILES
			add_dependencies(wireshark manpages)
		endif()
		set_target_properties(
			wireshark PROPERTIES
				MACOSX_BUNDLE_INFO_PLIST ${CMAKE_BINARY_DIR}/packaging/macosx/WiresharkInfo.plist
		)
		if(CMAKE_CFG_INTDIR STREQUAL ".")
			# Add a wrapper script which opens the bundle. This is more convenient
			# and lets Sparkle find our CFBundleIdentifier, but means that you have
			# to pass the full path to run/Wireshark.app/Contents/MacOS/Wireshark
			# to your debugger.
			# It is not created if using Xcode
			file(REMOVE ${CMAKE_BINARY_DIR}/run/wireshark)
			file(WRITE ${CMAKE_BINARY_DIR}/run/wireshark "#!/bin/sh\n")
			file(APPEND ${CMAKE_BINARY_DIR}/run/wireshark "# Generated by ${CMAKE_CURRENT_LIST_FILE}\n")
			file(APPEND ${CMAKE_BINARY_DIR}/run/wireshark "# Wrapper script which ensures that we're properly activated via Launch Services\n")
			file(APPEND ${CMAKE_BINARY_DIR}/run/wireshark "exec \"${CMAKE_BINARY_DIR}/run/Wireshark.app/Contents/MacOS/Wireshark\" \"\$\@\"\n")
			execute_process(COMMAND chmod a+x ${CMAKE_BINARY_DIR}/run/wireshark)
		endif()
	endif()

	target_link_libraries(wireshark ${wireshark_LIBS})
	target_include_directories(wireshark SYSTEM PRIVATE ${SPARKLE_INCLUDE_DIRS})

	install(
		TARGETS wireshark
		RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
		BUNDLE DESTINATION ${CMAKE_INSTALL_BINDIR}
	)

	if(QT_WINDEPLOYQT_EXECUTABLE)
		add_custom_target(copy_qt_dlls ALL)
		set_target_properties(copy_qt_dlls PROPERTIES FOLDER "Copy Tasks")
		# Will we ever need to use --debug? Windeployqt seems to
		# be smart enough to copy debug DLLs when needed.
		if (USE_MSYSTEM AND Qt${qtver}Widgets_VERSION VERSION_EQUAL 6.5.0)
			# windeployqt released with Qt 6.5.0 is broken.
			# https://bugreports.qt.io/browse/QTBUG-112204
			message(WARNING "Qt Deploy Tool 6.5.0 is broken, please upgrade to a later version.")
			# lconvert will fail
		endif()
		add_custom_command(TARGET copy_qt_dlls
			POST_BUILD
			COMMAND set "PATH=${QT_BIN_PATH};%PATH%"
			COMMAND "${QT_WINDEPLOYQT_EXECUTABLE}"
				${QT_WINDEPLOYQT_EXTRA_ARGS}
				--no-compiler-runtime
				--verbose 0
				$<$<BOOL:${MSVC}>:--pdb>
				"$<TARGET_FILE:wireshark>"
		)
		add_dependencies(copy_qt_dlls wireshark)

		install(CODE "execute_process(COMMAND
			\"${QT_WINDEPLOYQT_EXECUTABLE}\"
			--no-compiler-runtime
			\"\${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}/Wireshark.exe\")"
		)

	endif(QT_WINDEPLOYQT_EXECUTABLE)
endif()

if(BUILD_logray AND QT_FOUND)
	set(logray_LIBS
		ui
		ui_logray
		capchild
		caputils
		iface_monitor
		wiretap
		epan
		summary
		${QT5_LIBRARIES}
		${APPLE_APPLICATION_SERVICES_LIBRARY}
		${APPLE_APPKIT_LIBRARY}
		${APPLE_CORE_FOUNDATION_LIBRARY}
		${APPLE_SYSTEM_CONFIGURATION_LIBRARY}
		${SPARKLE_LIBRARIES}
		${WIN_WS2_32_LIBRARY}
		${WIN_VERSION_LIBRARY}
		${WINSPARKLE_LIBRARIES}
		$<$<BOOL:${WIN32}>:uxtheme.lib>
		${SPEEXDSP_LIBRARIES}
		${ZLIB_LIBRARIES}
		${ZLIBNG_LIBRARIES}
		${MINIZIP_LIBRARIES}
		${MINIZIPNG_LIBRARIES}
	)

	add_executable(logray WIN32 MACOSX_BUNDLE ${logray_FILES} ${EXTRA_LOGRAY_BUNDLE_FILES})
	if(WIN32 AND NOT BUILD_wireshark)
		set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT logray)
	endif()
	set(PROGLIST ${PROGLIST} logray)
	set_target_properties(logray PROPERTIES
		LINK_FLAGS "${WS_LINK_FLAGS}"
		FOLDER "Executables"
		INSTALL_RPATH "${EXECUTABLE_INSTALL_RPATH}"
		AUTOMOC ON
		AUTOUIC ON
		AUTORCC ON
	)
	if(MSVC)
		set_target_properties(logray PROPERTIES LINK_FLAGS_DEBUG "${WS_MSVC_DEBUG_LINK_FLAGS}")
	endif()
	if(ENABLE_APPLICATION_BUNDLE OR WIN32)
		set_target_properties(logray PROPERTIES OUTPUT_NAME Logray)
	endif()

	if(ENABLE_APPLICATION_BUNDLE)
		if(ASCIIDOCTOR_FOUND)
			# Make sure to generate files referenced by
			# LOGRAY_BUNDLE_RESOURCE_SHARE_MAN1_FILES
			add_dependencies(logray manpages)
		endif()
		set_target_properties(
			logray PROPERTIES
				MACOSX_BUNDLE_INFO_PLIST ${CMAKE_BINARY_DIR}/packaging/macosx/LograyInfo.plist
		)
		if(CMAKE_CFG_INTDIR STREQUAL ".")
			# Add a wrapper script which opens the bundle. This is more convenient
			# and lets Sparkle find our CFBundleIdentifier, but means that you have
			# to pass the full path to run/Wireshark.app/Contents/MacOS/Logray
			# to your debugger.
			# It is not created if using Xcode
			file(REMOVE ${CMAKE_BINARY_DIR}/run/logray)
			file(WRITE ${CMAKE_BINARY_DIR}/run/logray "#!/bin/sh\n")
			file(APPEND ${CMAKE_BINARY_DIR}/run/logray "# Generated by ${CMAKE_CURRENT_LIST_FILE}\n")
			file(APPEND ${CMAKE_BINARY_DIR}/run/logray "# Wrapper script which ensures that we're properly activated via Launch Services\n")
			file(APPEND ${CMAKE_BINARY_DIR}/run/logray "exec \"${CMAKE_BINARY_DIR}/run/Logray.app/Contents/MacOS/Logray\" \"\$\@\"\n")
			execute_process(COMMAND chmod a+x ${CMAKE_BINARY_DIR}/run/logray)
		endif()
	endif()

	target_link_libraries(logray ${logray_LIBS})
	target_include_directories(logray SYSTEM PRIVATE ${SPARKLE_INCLUDE_DIRS})

	install(
		TARGETS logray
		RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
		BUNDLE DESTINATION ${CMAKE_INSTALL_BINDIR}
	)

	if(QT_WINDEPLOYQT_EXECUTABLE)
		add_custom_target(copy_logray_qt_dlls ALL)
		set_target_properties(copy_logray_qt_dlls PROPERTIES FOLDER "Copy Tasks")
		# Will we ever need to use --debug? Windeployqt seems to
		# be smart enough to copy debug DLLs when needed.
		add_custom_command(TARGET copy_logray_qt_dlls
			POST_BUILD
			COMMAND set "PATH=${QT_BIN_PATH};%PATH%"
			COMMAND "${QT_WINDEPLOYQT_EXECUTABLE}"
				--no-compiler-runtime
				--verbose 0
				$<$<BOOL:${MSVC}>:--pdb>
				"$<TARGET_FILE:logray>"
		)
		add_dependencies(copy_logray_qt_dlls logray)

		install(CODE "execute_process(COMMAND
			\"${QT_WINDEPLOYQT_EXECUTABLE}\"
			--no-compiler-runtime
			\"\${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}/Logray.exe\")"
		)

	endif(QT_WINDEPLOYQT_EXECUTABLE)
endif()

if (BUILD_logray AND FALCO_PLUGINS)
	add_custom_target(copy_falco_plugins)
	add_custom_command(TARGET copy_falco_plugins
		# XXX Falco plugins should probably be installed in a path that reflects
		# the Falco version or its plugin API version.
		COMMAND ${CMAKE_COMMAND} -E make_directory ${LOGRAY_PLUGIN_DIR}/../falco
		COMMAND ${CMAKE_COMMAND} -E copy_if_different ${FALCO_PLUGINS} ${LOGRAY_PLUGIN_DIR}/../falco
		VERBATIM
	)
	add_dependencies(logray copy_falco_plugins)
endif()

# Common properties for CLI executables
macro(set_extra_executable_properties _executable _folder)
	set_target_properties(${_executable} PROPERTIES
		LINK_FLAGS "${WILDCARD_OBJ} ${WS_LINK_FLAGS}"
		FOLDER ${_folder}
		INSTALL_RPATH "${EXECUTABLE_INSTALL_RPATH}"
	)
	if(MSVC)
		set_target_properties(${_executable} PROPERTIES LINK_FLAGS_DEBUG "${WS_MSVC_DEBUG_LINK_FLAGS}")
	endif()

	set(PROGLIST ${PROGLIST} ${_executable})

	if(ENABLE_APPLICATION_BUNDLE)
		if(NOT CMAKE_CFG_INTDIR STREQUAL ".")
			# Xcode
			set_target_properties(${_executable} PROPERTIES
				RUNTIME_OUTPUT_DIRECTORY run/$<CONFIG>/Wireshark.app/Contents/MacOS
			)
		else ()
			set_target_properties(${_executable} PROPERTIES
				RUNTIME_OUTPUT_DIRECTORY run/Wireshark.app/Contents/MacOS
			)
			# Create a convenience link from run/<name> to its respective
			# target in the application bundle.
			add_custom_target(${_executable}-symlink
				COMMAND ln -s -f
					Wireshark.app/Contents/MacOS/${_executable}
					${CMAKE_BINARY_DIR}/run/${_executable}
			)
			add_dependencies(${_executable} ${_executable}-symlink)
		endif()
	endif()
endmacro()

macro(executable_link_mingw_unicode _target)
	# target_link_options() requires CMake >= 3.13
	if (MINGW)
		target_link_options(${_target} PRIVATE "-municode")
	endif()
endmacro()

register_tap_files(tshark-tap-register.c
	${TSHARK_TAP_SRC}
)

if(BUILD_tshark)
	set(tshark_LIBS
		ui
		capchild
		caputils
		wiretap
		epan
		wsutil
		${APPLE_CORE_FOUNDATION_LIBRARY}
		${APPLE_SYSTEM_CONFIGURATION_LIBRARY}
		${WIN_WS2_32_LIBRARY}
	)
	set(tshark_FILES
		$<TARGET_OBJECTS:capture_opts>
		$<TARGET_OBJECTS:cli_main>
		$<TARGET_OBJECTS:shark_common>
		tshark-tap-register.c
		tshark.c
		extcap.c
		${TSHARK_TAP_SRC}
	)

	set_executable_resources(tshark "TShark" UNIQUE_RC)
	add_executable(tshark ${tshark_FILES})
	set_extra_executable_properties(tshark "Executables")
	target_link_libraries(tshark ${tshark_LIBS})
	executable_link_mingw_unicode(tshark)
	install(TARGETS tshark RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_tfshark)
	set(tfshark_LIBS
		m
		ui
		wiretap
		epan
		${APPLE_CORE_FOUNDATION_LIBRARY}
		${APPLE_SYSTEM_CONFIGURATION_LIBRARY}
	)
	set(tfshark_FILES
		$<TARGET_OBJECTS:cli_main>
		$<TARGET_OBJECTS:shark_common>
		tfshark.c
		${TSHARK_TAP_SRC}
	)
	set_executable_resources(tfshark "TFShark")
	add_executable(tfshark ${tfshark_FILES})
	set_extra_executable_properties(tfshark "Executables")
	target_link_libraries(tfshark ${tfshark_LIBS})
	install(TARGETS tfshark RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_rawshark AND PCAP_FOUND)
	set(rawshark_LIBS
		caputils
		ui
		wiretap
		epan
		${APPLE_CORE_FOUNDATION_LIBRARY}
		${APPLE_SYSTEM_CONFIGURATION_LIBRARY}
		${WIN_WS2_32_LIBRARY}
	)
	set(rawshark_FILES
		$<TARGET_OBJECTS:cli_main>
		$<TARGET_OBJECTS:shark_common>
		rawshark.c
	)
	set_executable_resources(rawshark "Rawshark")
	add_executable(rawshark ${rawshark_FILES})
	set_extra_executable_properties(rawshark "Executables")
	target_link_libraries(rawshark ${rawshark_LIBS})
	executable_link_mingw_unicode(rawshark)
	install(TARGETS rawshark RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_sharkd)
	set(sharkd_LIBS
		ui
		wiretap
		epan
		${APPLE_CORE_FOUNDATION_LIBRARY}
		${APPLE_SYSTEM_CONFIGURATION_LIBRARY}
		${WIN_WS2_32_LIBRARY}
		${SPEEXDSP_LIBRARIES}
		${GCRYPT_LIBRARIES}
	)
	set(sharkd_FILES
		#
		# XXX - currently doesn't work on Windows if it uses
		# $<TARGET_OBJECTS:cli_main> and has real_main().
		#
		$<TARGET_OBJECTS:shark_common>
		ui/cli/simple_dialog.c
		sharkd.c
		sharkd_daemon.c
		sharkd_session.c
		${TSHARK_TAP_SRC}
	)
	set_executable_resources(sharkd "SharkD")
	add_executable(sharkd ${sharkd_FILES})
	set_extra_executable_properties(sharkd "Executables")
	target_link_libraries(sharkd ${sharkd_LIBS})
	target_include_directories(sharkd SYSTEM PUBLIC ${SPEEXDSP_INCLUDE_DIRS})

	install(TARGETS sharkd RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_dftest)
	set(dftest_LIBS
		ui
		wiretap
		epan
	)
	set(dftest_FILES
		dftest.c
	)
	set_executable_resources(dftest "Dftest")
	add_executable(dftest ${dftest_FILES})
	set_extra_executable_properties(dftest "Tests")
	target_link_libraries(dftest ${dftest_LIBS})
endif()

if(BUILD_randpkt)
	set(randpkt_LIBS
		randpkt_core
		ui
		wiretap
		wsutil
	)
	set(randpkt_FILES
		$<TARGET_OBJECTS:cli_main>
		randpkt.c
	)
	set_executable_resources(randpkt "Randpkt"
		COPYRIGHT_INFO "Copyright (C) 1999 by Gilbert Ramirez <gram@alumni.rice.edu>")
	add_executable(randpkt ${randpkt_FILES})
	set_extra_executable_properties(randpkt "Executables")
	target_link_libraries(randpkt ${randpkt_LIBS})
	executable_link_mingw_unicode(randpkt)
	install(TARGETS randpkt RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_fuzzshark OR ENABLE_FUZZER OR OSS_FUZZ)
	add_subdirectory(fuzz)
endif()

if(BUILD_text2pcap)
	set(text2pcap_LIBS
		wiretap
		wsutil
		ui
		epan
		${ZLIB_LIBRARIES}
		${ZLIBNG_LIBRARIES}
	)
	set(text2pcap_FILES
		$<TARGET_OBJECTS:cli_main>
		text2pcap.c
	)
	set_executable_resources(text2pcap "Text2pcap"
		COPYRIGHT_INFO "2001 Ashok Narayanan <ashokn@cisco.com>")
	add_executable(text2pcap ${text2pcap_FILES})
	set_extra_executable_properties(text2pcap "Executables")
	target_link_libraries(text2pcap ${text2pcap_LIBS})
	executable_link_mingw_unicode(text2pcap)
	install(TARGETS text2pcap RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_mergecap)
	set(mergecap_LIBS
		ui
		wiretap
		${ZLIB_LIBRARIES}
		${ZLIBNG_LIBRARIES}
		${CMAKE_DL_LIBS}
	)
	set(mergecap_FILES
		$<TARGET_OBJECTS:cli_main>
		mergecap.c
	)
	set_executable_resources(mergecap "Mergecap")
	add_executable(mergecap ${mergecap_FILES})
	set_extra_executable_properties(mergecap "Executables")
	target_link_libraries(mergecap ${mergecap_LIBS})
	executable_link_mingw_unicode(mergecap)
	install(TARGETS mergecap RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_reordercap)
	set(reordercap_LIBS
		ui
		wiretap
		${ZLIB_LIBRARIES}
		${ZLIBNG_LIBRARIES}
		${CMAKE_DL_LIBS}
	)
	set(reordercap_FILES
		$<TARGET_OBJECTS:cli_main>
		reordercap.c
	)
	set_executable_resources(reordercap "Reordercap")
	add_executable(reordercap ${reordercap_FILES})
	set_extra_executable_properties(reordercap "Executables")
	target_link_libraries(reordercap ${reordercap_LIBS})
	executable_link_mingw_unicode(reordercap)
	install(TARGETS reordercap RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_capinfos)
	set(capinfos_LIBS
		ui
		wiretap
		wsutil
		${ZLIB_LIBRARIES}
		${ZLIBNG_LIBRARIES}
		${GCRYPT_LIBRARIES}
		${CMAKE_DL_LIBS}
	)
	set(capinfos_FILES
		$<TARGET_OBJECTS:cli_main>
		capinfos.c
	)
	set_executable_resources(capinfos "Capinfos")
	add_executable(capinfos ${capinfos_FILES})
	set_extra_executable_properties(capinfos "Executables")
	target_link_libraries(capinfos ${capinfos_LIBS})
	target_include_directories(capinfos SYSTEM PRIVATE ${GCRYPT_INCLUDE_DIRS})
	executable_link_mingw_unicode(capinfos)
	install(TARGETS capinfos RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_captype)
	set(captype_LIBS
		ui
		wiretap
		wsutil
		${ZLIB_LIBRARIES}
		${ZLIBNG_LIBRARIES}
		${CMAKE_DL_LIBS}
	)
	set(captype_FILES
		$<TARGET_OBJECTS:cli_main>
		captype.c
	)
	set_executable_resources(captype "Captype")
	add_executable(captype ${captype_FILES})
	set_extra_executable_properties(captype "Executables")
	target_link_libraries(captype ${captype_LIBS})
	executable_link_mingw_unicode(captype)
	install(TARGETS captype RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_editcap)
	set(editcap_LIBS
		ui
		wiretap
		${ZLIB_LIBRARIES}
		${ZLIBNG_LIBRARIES}
		${GCRYPT_LIBRARIES}
		${CMAKE_DL_LIBS}
	)
	set(editcap_FILES
		$<TARGET_OBJECTS:cli_main>
		editcap.c
	)
	set_executable_resources(editcap "Editcap")
	add_executable(editcap ${editcap_FILES})
	set_extra_executable_properties(editcap "Executables")
	target_link_libraries(editcap ${editcap_LIBS})
	target_include_directories(editcap SYSTEM PRIVATE ${GCRYPT_INCLUDE_DIRS})
	executable_link_mingw_unicode(editcap)
	install(TARGETS editcap RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_dumpcap AND PCAP_FOUND)
	set(dumpcap_LIBS
		writecap
		wsutil_static
		pcap::pcap
		${CAP_LIBRARIES}
		${ZLIB_LIBRARIES}
		${ZLIBNG_LIBRARIES}
		${NL_LIBRARIES}
		${APPLE_CORE_FOUNDATION_LIBRARY}
		${APPLE_SYSTEM_CONFIGURATION_LIBRARY}
		${WIN_WS2_32_LIBRARY}
	)
	if(UNIX)
		list(APPEND CAPUTILS_SRC
			capture/capture-pcap-util-unix.c)
	endif()
	if(WIN32)
		list(APPEND CAPUTILS_SRC
			capture/capture_win_ifnames.c
			capture/capture-wpcap.c
		)
	endif()
	list(APPEND CAPUTILS_SRC
		capture/capture-pcap-util.c
	)
	if (AIRPCAP_FOUND)
		list(APPEND CAPUTILS_SRC capture/airpcap_loader.c)
	endif()
	set(dumpcap_FILES
		capture_opts.c
		cli_main.c
		dumpcap.c
		ringbuffer.c
		sync_pipe_write.c
		capture/iface_monitor.c
		capture/ws80211_utils.c
		${CAPUTILS_SRC}
	)
	set_executable_resources(dumpcap "Dumpcap" UNIQUE_RC)
	add_executable(dumpcap ${dumpcap_FILES})
	set_extra_executable_properties(dumpcap "Executables")
	target_link_libraries(dumpcap ${dumpcap_LIBS})
	target_include_directories(dumpcap SYSTEM PRIVATE ${ZLIB_INCLUDE_DIRS} ${ZLIBNG_INCLUDE_DIRS} ${NL_INCLUDE_DIRS})
	target_compile_definitions(dumpcap PRIVATE ENABLE_STATIC)
	executable_link_mingw_unicode(dumpcap)
	install(TARGETS dumpcap
			RUNTIME	DESTINATION ${CMAKE_INSTALL_BINDIR}
			PERMISSIONS ${DUMPCAP_SETUID}
				OWNER_READ OWNER_WRITE OWNER_EXECUTE
				GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
	)
	if(ENABLE_DUMPCAP_GROUP)
		install(CODE "execute_process(COMMAND chgrp ${DUMPCAP_INSTALL_GROUP} ${CMAKE_INSTALL_FULL_BINDIR}/dumpcap)")
		install(CODE "execute_process(COMMAND chmod o-x ${CMAKE_INSTALL_FULL_BINDIR}/dumpcap)")
	endif()
	if(DUMPCAP_INSTALL_OPTION STREQUAL "capabilities")
		install( CODE "execute_process(
			COMMAND
				${SETCAP_EXECUTABLE}
				cap_net_raw,cap_net_admin+ep
				${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}/dumpcap${CMAKE_EXECUTABLE_SUFFIX}
			RESULT_VARIABLE
				_SETCAP_RESULT
			)
			if( _SETCAP_RESULT )
				message( WARNING \"setcap failed (${_SETCAP_RESULT}).\")
			endif()"
		)
	endif()
	if(BUILD_logray AND ENABLE_APPLICATION_BUNDLE)
		add_custom_command(TARGET dumpcap POST_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy_if_different
				$<TARGET_FILE:dumpcap> run/Logray.app/Contents/MacOS/dumpcap
		)
	endif()
elseif(BUILD_dumpcap AND ENABLE_PCAP)
	message(WARNING "Dumpcap was requested but libpcap dependency is not available. "
		"Wireshark will be built without packet capture capability.")
endif()

# We have two idl2wrs utilities: this and the CORBA version in tools.
# We probably shouldn't do that.
if(BUILD_dcerpcidl2wrs)
	set(idl2wrs_LIBS
		wsutil
	)
	set(idl2wrs_FILES
		epan/dissectors/dcerpc/idl2wrs.c
	)

	add_executable(idl2wrs ${idl2wrs_FILES})
	set_target_properties(idl2wrs PROPERTIES FOLDER "Executables")
	set_extra_executable_properties(idl2wrs "Executables")
	target_link_libraries(idl2wrs ${idl2wrs_LIBS})
	install(TARGETS idl2wrs RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(WIN32)
	find_package( MSVC_REDIST )

	# Must come after executable targets are defined.
	find_package( NSIS )

	if(MAKENSIS_EXECUTABLE)
		add_subdirectory( packaging/nsis EXCLUDE_FROM_ALL )
		ADD_NSIS_PACKAGE_TARGETS()
	endif()

	find_package( WiX )

	if(WIX_CANDLE_EXECUTABLE)
		add_subdirectory( packaging/wix EXCLUDE_FROM_ALL )
		ADD_WIX_PACKAGE_TARGET()
	endif()

	find_package( PortableApps )
	if(PORTABLEAPPS_LAUNCHER_GENERATOR_EXECUTABLE AND PORTABLEAPPS_INSTALLER_EXECUTABLE)
		add_subdirectory( packaging/portableapps EXCLUDE_FROM_ALL )
		ADD_PORTABLEAPPS_PACKAGE_TARGET()
	endif()
endif()

if (MAXMINDDB_FOUND)
	set(mmdbresolve_LIBS
		# Note: libmaxminddb is not GPL-2 compatible.
		${MAXMINDDB_LIBRARY}
		# Needed for CMake-built libmaxminddb.lib <= 1.43.
		${WIN_WS2_32_LIBRARY}
	)
	set(mmdbresolve_FILES
		mmdbresolve.c
	)
	set_executable_resources(mmdbresolve "Mmdbresolve")
	add_executable(mmdbresolve ${mmdbresolve_FILES})
	set_extra_executable_properties(mmdbresolve "Executables")
	target_link_libraries(mmdbresolve ${mmdbresolve_LIBS})
	target_include_directories(mmdbresolve PUBLIC ${MAXMINDDB_INCLUDE_DIRS})
	target_compile_definitions(mmdbresolve PUBLIC ${MAXMINDDB_DEFINITIONS})
	install(TARGETS mmdbresolve RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(ENABLE_APPLICATION_BUNDLE AND BUILD_wireshark)
	file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/run/${CMAKE_CFG_INTDIR}/Wireshark.app/Contents/Resources/Extras")

	# --preserve-xattr is undocumented but ensures that we install
	# a signed ChmodBPF script.
	set (_chmodbpf_version 1.2)
	set (install_chmodbpf_component_pkg "${CMAKE_BINARY_DIR}/install.ChmodBPF.pkg")
	add_custom_command(OUTPUT "${install_chmodbpf_component_pkg}"
		COMMAND find
			"${CMAKE_SOURCE_DIR}/packaging/macosx/ChmodBPF/root"
			-type d
			-exec chmod 755 "{}" +
		COMMAND chmod 644
			"${CMAKE_SOURCE_DIR}/packaging/macosx/ChmodBPF/root/Library/LaunchDaemons/org.wireshark.ChmodBPF.plist"
		COMMAND chmod 755
			"${CMAKE_SOURCE_DIR}/packaging/macosx/ChmodBPF/root/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF"
		COMMAND "${CMAKE_SOURCE_DIR}/packaging/macosx/osx-extras.sh"
		COMMAND pkgbuild
			--identifier org.wireshark.ChmodBPF.pkg
			--version ${_chmodbpf_version}
			--preserve-xattr
			--root "${CMAKE_SOURCE_DIR}/packaging/macosx/ChmodBPF/root"
			--scripts "${CMAKE_SOURCE_DIR}/packaging/macosx/ChmodBPF/install-scripts"
			${install_chmodbpf_component_pkg}
		DEPENDS
			"${CMAKE_SOURCE_DIR}/packaging/macosx/ChmodBPF/root/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF"
			"${CMAKE_SOURCE_DIR}/packaging/macosx/ChmodBPF/root/Library/LaunchDaemons/org.wireshark.ChmodBPF.plist"
			"${CMAKE_SOURCE_DIR}/packaging/macosx/ChmodBPF/install-scripts/postinstall"
	)
	set (install_chmodbpf_pkg "${CMAKE_BINARY_DIR}/run/Wireshark.app/Contents/Resources/Extras/Install ChmodBPF.pkg")
	add_custom_command(OUTPUT "${install_chmodbpf_pkg}"
		COMMAND productbuild
			--identifier org.wireshark.install.ChmodBPF.product
			--version ${_chmodbpf_version}
			--distribution "${CMAKE_SOURCE_DIR}/packaging/macosx/ChmodBPF/install-distribution.xml"
			--package-path "${CMAKE_BINARY_DIR}"
			${install_chmodbpf_pkg}
		DEPENDS
			"${CMAKE_SOURCE_DIR}/packaging/macosx/ChmodBPF/install-distribution.xml"
			${install_chmodbpf_component_pkg}
	)

	set (uninstall_chmodbpf_component_pkg "${CMAKE_BINARY_DIR}/uninstall.ChmodBPF.pkg")
	add_custom_command(OUTPUT "${uninstall_chmodbpf_component_pkg}"
		COMMAND pkgbuild
			--identifier org.wireshark.uninstall.ChmodBPF.pkg
			--version ${_chmodbpf_version}
			--nopayload
			--scripts "${CMAKE_SOURCE_DIR}/packaging/macosx/ChmodBPF/uninstall-scripts"
			${uninstall_chmodbpf_component_pkg}
		DEPENDS
			"${CMAKE_SOURCE_DIR}/packaging/macosx/ChmodBPF/uninstall-scripts/postinstall"
	)
	set (uninstall_chmodbpf_pkg "${CMAKE_BINARY_DIR}/run/Wireshark.app/Contents/Resources/Extras/Uninstall ChmodBPF.pkg")
	add_custom_command(OUTPUT "${uninstall_chmodbpf_pkg}"
		COMMAND productbuild
			--identifier org.wireshark.uninstall.ChmodBPF.product
			--version ${_chmodbpf_version}
			--distribution "${CMAKE_SOURCE_DIR}/packaging/macosx/ChmodBPF/uninstall-distribution.xml"
			--package-path "${CMAKE_BINARY_DIR}"
			${uninstall_chmodbpf_pkg}
		DEPENDS
			"${CMAKE_SOURCE_DIR}/packaging/macosx/ChmodBPF/uninstall-distribution.xml"
			${uninstall_chmodbpf_component_pkg}
	)

	add_custom_target(chmodbpf DEPENDS ${install_chmodbpf_pkg} ${uninstall_chmodbpf_pkg})

	set (_path_helper_version 1.1)
	set (install_path_helper_component_pkg "${CMAKE_BINARY_DIR}/install.path_helper.pkg")
	add_custom_command(OUTPUT "${install_path_helper_component_pkg}"
		COMMAND find
			"${CMAKE_SOURCE_DIR}/packaging/macosx/path_helper/root"
			-type d
			-exec chmod 755 "{}" +
		COMMAND find
			"${CMAKE_SOURCE_DIR}/packaging/macosx/path_helper/root"
			-type f
			-exec chmod 644 "{}" +
		COMMAND pkgbuild
			--identifier org.wireshark.path_helper.pkg
			--version ${_path_helper_version}
			--root "${CMAKE_SOURCE_DIR}/packaging/macosx/path_helper/root/etc"
			--install-location /private/etc
			${install_path_helper_component_pkg}
		DEPENDS
			"${CMAKE_SOURCE_DIR}/packaging/macosx/path_helper/root/etc/paths.d/Wireshark"
			"${CMAKE_SOURCE_DIR}/packaging/macosx/path_helper/root/etc/manpaths.d/Wireshark"
	)
	set (install_path_helper_pkg "${CMAKE_BINARY_DIR}/run/Wireshark.app/Contents/Resources/Extras/Add Wireshark to the system path.pkg")
	add_custom_command(OUTPUT "${install_path_helper_pkg}"
		COMMAND productbuild
			--identifier org.wireshark.install.path_helper.product
			--version ${_path_helper_version}
			--distribution "${CMAKE_SOURCE_DIR}/packaging/macosx/path_helper/install-distribution.xml"
			--package-path "${CMAKE_BINARY_DIR}"
			${install_path_helper_pkg}
		DEPENDS
			"${CMAKE_SOURCE_DIR}/packaging/macosx/path_helper/install-distribution.xml"
			${install_path_helper_component_pkg}
	)

	set (uninstall_path_helper_component_pkg "${CMAKE_BINARY_DIR}/uninstall.path_helper.pkg")
	add_custom_command(OUTPUT "${uninstall_path_helper_component_pkg}"
		COMMAND pkgbuild
			--identifier org.wireshark.uninstall.path_helper.pkg
			--version ${_path_helper_version}
			--nopayload
			--scripts "${CMAKE_SOURCE_DIR}/packaging/macosx/path_helper/uninstall-scripts"
			${uninstall_path_helper_component_pkg}
		DEPENDS
			"${CMAKE_SOURCE_DIR}/packaging/macosx/path_helper/uninstall-scripts/postinstall"
	)
	set (uninstall_path_helper_pkg "${CMAKE_BINARY_DIR}/run/Wireshark.app/Contents/Resources/Extras/Remove Wireshark from the system path.pkg")
	add_custom_command(OUTPUT "${uninstall_path_helper_pkg}"
		COMMAND productbuild
			--identifier org.wireshark.uninstall.path_helper.product
			--version ${_path_helper_version}
			--distribution "${CMAKE_SOURCE_DIR}/packaging/macosx/path_helper/uninstall-distribution.xml"
			--package-path "${CMAKE_BINARY_DIR}"
			${uninstall_path_helper_pkg}
		DEPENDS
			${CMAKE_SOURCE_DIR}/packaging/macosx/path_helper/uninstall-distribution.xml
			${uninstall_path_helper_component_pkg}
	)

	add_custom_target(path_helper DEPENDS ${install_path_helper_pkg} ${uninstall_path_helper_pkg})

	add_custom_target(wireshark_app_bundle)
	set_target_properties(wireshark_app_bundle PROPERTIES FOLDER "Copy Tasks")
	add_custom_command(TARGET wireshark_app_bundle
		POST_BUILD
		COMMAND "${CMAKE_BINARY_DIR}/packaging/macosx/osx-app.sh"
		WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/run"
	)
	add_dependencies(wireshark_app_bundle ${PROGLIST} chmodbpf path_helper)

	add_custom_target(wireshark_dmg_prep DEPENDS wireshark_app_bundle)

	FILE(MAKE_DIRECTORY packaging/macosx/wireshark)

	set(_wireshark_read_me_first "packaging/macosx/wireshark/Read me first.html")
	ADD_CUSTOM_COMMAND(
	OUTPUT
		${_wireshark_read_me_first}
	COMMAND ${ASCIIDOCTOR_EXECUTABLE}
		--backend html
		--out-file ${_wireshark_read_me_first}
		--attribute include-dir=${CMAKE_SOURCE_DIR}/doc
		--attribute min-macos-version=${MIN_MACOS_VERSION}
		${CMAKE_CURRENT_SOURCE_DIR}/packaging/macosx/Wireshark_read_me_first.adoc
	DEPENDS
		${CMAKE_CURRENT_SOURCE_DIR}/packaging/macosx/Wireshark_read_me_first.adoc
	)

	set(_wireshark_donate "packaging/macosx/wireshark/Donate to the Wireshark Foundation.html")
	ADD_CUSTOM_COMMAND(
	OUTPUT
		${_wireshark_donate}
	COMMAND ${ASCIIDOCTOR_EXECUTABLE}
		--backend html
		--out-file ${_wireshark_donate}
		--attribute include-dir=${CMAKE_SOURCE_DIR}/doc
		--attribute min-macos-version=${MIN_MACOS_VERSION}
		${CMAKE_CURRENT_SOURCE_DIR}/packaging/macosx/Donate_to_the_Wireshark_Foundation.adoc
	DEPENDS
		${CMAKE_CURRENT_SOURCE_DIR}/packaging/macosx/Donate_to_the_Wireshark_Foundation.adoc
	)

	set(_wireshark_dsym_installation "packaging/macosx/wireshark/Debugging symbols installation.html")
	ADD_CUSTOM_COMMAND(
	OUTPUT
		${_wireshark_dsym_installation}
	COMMAND ${ASCIIDOCTOR_EXECUTABLE}
		--backend html
		--out-file ${_wireshark_dsym_installation}
		--attribute include-dir=${CMAKE_SOURCE_DIR}/doc
		${CMAKE_CURRENT_SOURCE_DIR}/packaging/macosx/Wireshark_dsym_installation.adoc
	DEPENDS
		${CMAKE_CURRENT_SOURCE_DIR}/packaging/macosx/Wireshark_dsym_installation.adoc
	)

	add_custom_target(wireshark_dmg_readmes DEPENDS ${_wireshark_read_me_first} ${_wireshark_donate} ${_wireshark_dsym_installation} )
	add_dependencies(wireshark_dmg_prep wireshark_dmg_readmes)

	ADD_CUSTOM_TARGET( wireshark_dmg
		COMMAND bash -x ${CMAKE_BINARY_DIR}/packaging/macosx/osx-dmg.sh
		# Unlike wireshark_nsis_prep + wireshark_nsis, we can add a direct
		# dependency here.
		DEPENDS wireshark_dmg_prep
		# We create Wireshark.app in "run". Do our work there.
		WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/run
	)

endif()

if(ENABLE_APPLICATION_BUNDLE AND BUILD_logray)
	add_custom_target(logray_app_bundle)
	set_target_properties(logray_app_bundle PROPERTIES FOLDER "Copy Tasks")
	add_custom_command(TARGET logray_app_bundle
		POST_BUILD
		COMMAND "${CMAKE_BINARY_DIR}/packaging/macosx/osx-app.sh" --bundle Logray.app
		WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/run"
	)

	add_custom_target(logray_dmg_prep DEPENDS logray_app_bundle)

	FILE(MAKE_DIRECTORY packaging/macosx/logray)

	set(_logray_read_me_first "packaging/macosx/logray/Read me first.html")
	ADD_CUSTOM_COMMAND(
	OUTPUT
		${_logray_read_me_first}
	COMMAND ${ASCIIDOCTOR_EXECUTABLE}
		--backend html
		--out-file ${_logray_read_me_first}
		--attribute include-dir=${CMAKE_SOURCE_DIR}/doc
		--attribute min-macos-version=${MIN_MACOS_VERSION}
		${CMAKE_CURRENT_SOURCE_DIR}/packaging/macosx/Logray_read_me_first.adoc
	DEPENDS
		${CMAKE_CURRENT_SOURCE_DIR}/packaging/macosx/Logray_read_me_first.adoc
	)

	set(_logray_dsym_installation "packaging/macosx/logray/Debugging symbols installation.html")
	ADD_CUSTOM_COMMAND(
	OUTPUT
		${_logray_dsym_installation}
	COMMAND ${ASCIIDOCTOR_EXECUTABLE}
		--backend html
		--out-file ${_logray_dsym_installation}
		--attribute include-dir=${CMAKE_SOURCE_DIR}/doc
		${CMAKE_CURRENT_SOURCE_DIR}/packaging/macosx/Logray_dsym_installation.adoc
	DEPENDS
		${CMAKE_CURRENT_SOURCE_DIR}/packaging/macosx/Logray_dsym_installation.adoc
	)

	add_custom_target(logray_dmg_readmes DEPENDS ${_logray_read_me_first} ${_logray_dsym_installation} )
	add_dependencies(logray_dmg_prep logray_dmg_readmes)

	ADD_CUSTOM_TARGET( logray_dmg
		COMMAND bash -x ${CMAKE_BINARY_DIR}/packaging/macosx/osx-dmg.sh --app-name Logray
		# Unlike wireshark_nsis_prep + wireshark_nsis, we can add a direct
		# dependency here.
		DEPENDS logray_dmg_prep
		# We create Wireshark.app in "run". Do our work there.
		WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/run
	)

endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	find_program(RPMBUILD_EXECUTABLE rpmbuild)
	find_program(GIT_EXECUTABLE git)
	# Should we add appimaged's monitored directories
	# as HINTS?
	# https://github.com/AppImage/appimaged
	find_program(LINUXDEPLOY_EXECUTABLE NAMES linuxdeploy-x86_64.AppImage linuxdeploy)
	find_program(_linuxdeploy_plugin_qt NAMES linuxdeploy-plugin-qt-x86_64.AppImage linuxdeploy-plugin-qt)
	find_program(APPIMAGETOOL_EXECUTABLE NAMES appimagetool-x86_64.AppImage
 appimagetool)
endif()


string(REPLACE "-" "_" RPM_VERSION "${PROJECT_VERSION}")
configure_file(packaging/rpm/wireshark.spec.in ${CMAKE_BINARY_DIR}/packaging/rpm/SPECS/wireshark.spec)
if(RPMBUILD_EXECUTABLE)
	foreach(_rpm_dir BUILD RPMS SOURCES SPECS SRPMS)
		file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/packaging/rpm/${_rpm_dir}")
	endforeach()

	set(_rpmbuild_with_args)
	#
	# This is ugly.
	#
	# At least some versions of rpmbuild define the cmake_build
	# macro to run "cmake --build" with the "--verbose" option,
	# with no obvious way to easily override that, so, if you
	# are doing a build with lots of source files, and with
	# lots of compiler options (for example, a log of -W flags),
	# you can get a lot of output from rpmbuild.
	#
	# Wireshark is a program with lots of source files and
	# lots of compiler options.
	#
	# GitLab's shared builders have a limit of 4MB on logs
	# from build jobs.
	#
	# Wireshark uses the shared builders, and can produce
	# more than 4MB with the Fedora RPM build; this causes
	# the builds to fail.
	#
	# Forcibly overriding the cmake_build macro with a
	# version that lacks the --version file should
	# prevent ninja from being run with the -v flag,
	# so that it prints the compact output rather
	# than the raw command.
	#
	# We don't do that by default; if the build has the
	# FORCE_CMAKE_NINJA_QUIET environment variable set,
	# it will add it.
	#
	if(DEFINED ENV{FORCE_CMAKE_NINJA_NON_VERBOSE})
		#
		# Get the output of a pipeline running
		# "rpmbuild --showrc", to find the settings
		# of all macros, piped to an awk script
		# to extract the value of the cmake_build
		# macro.
		#
		execute_process(
			COMMAND rpmbuild --showrc
			COMMAND awk "/: cmake_build/ { getline; print \$0; exit }"
			OUTPUT_VARIABLE CMAKE_BUILD_VALUE
			OUTPUT_STRIP_TRAILING_WHITESPACE)
		if (CMAKE_BUILD_VALUE MATCHES ".*--verbose.*")
			#
			# OK, the setting contains "--verbose".
			# Rip it out.
			#
			string(REPLACE "--verbose" ""
				NON_VERBOSE_CMAKE_BUILD_VALUE
				${CMAKE_BUILD_VALUE})
			list(APPEND _rpmbuild_with_args --define "cmake_build ${NON_VERBOSE_CMAKE_BUILD_VALUE}")
		endif()
	else()
		if(CMAKE_VERBOSE_MAKEFILE)
			list(APPEND _rpmbuild_with_args -v)
		endif()
	endif()
	if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
		list(APPEND _rpmbuild_with_args --with toolchain_clang)
	endif()
	if(CMAKE_GENERATOR STREQUAL "Ninja")
		list(APPEND _rpmbuild_with_args --with ninja)
	endif()
	if(CCACHE_EXECUTABLE)
		list(APPEND _rpmbuild_with_args --with ccache)
	endif()
	if(NOT BUILD_wireshark)
		list(APPEND _rpmbuild_with_args --without qt5 --without qt6)
	elseif(USE_qt6)
		list(APPEND _rpmbuild_with_args --without qt5 --with qt6)
	else()
		list(APPEND _rpmbuild_with_args --with qt5 --without qt6)
	endif()
	if (MAXMINDDB_FOUND)
		list(APPEND _rpmbuild_with_args --with mmdbresolve)
	endif()
	if (LUA_FOUND)
		list(APPEND _rpmbuild_with_args --with lua)
	endif()
	if (LZ4_FOUND AND SNAPPY_FOUND)
		list(APPEND _rpmbuild_with_args --with lz4_and_snappy)
	endif()
	if (SPANDSP_FOUND)
		list(APPEND _rpmbuild_with_args --with spandsp)
	endif()
	if (BCG729_FOUND)
		list(APPEND _rpmbuild_with_args --with bcg729)
	endif()
	if (AMRNB_FOUND)
		list(APPEND _rpmbuild_with_args --with amrnb)
	endif()
	if (ILBC_FOUND)
		list(APPEND _rpmbuild_with_args --with ilbc)
	endif()
	if (OPUS_FOUND)
		list(APPEND _rpmbuild_with_args --with opus)
	endif()
	if (LIBXML2_FOUND)
		list(APPEND _rpmbuild_with_args --with libxml2)
	endif()
	if (NGHTTP2_FOUND)
		list(APPEND _rpmbuild_with_args --with nghttp2)
	endif()
	if (NGHTTP3_FOUND)
		list(APPEND _rpmbuild_with_args --with nghttp3)
	endif()
	if (SYSTEMD_FOUND)
		list(APPEND _rpmbuild_with_args --with sdjournal)
	endif()
	if (BROTLI_FOUND)
		list(APPEND _rpmbuild_with_args --with brotli)
	endif()
	if(ASCIIDOCTOR_FOUND AND XSLTPROC_EXECUTABLE)
		list(APPEND _rpmbuild_with_args --with guides)
	endif()

	execute_process(
		COMMAND ${Python3_EXECUTABLE}
			${CMAKE_SOURCE_DIR}/tools/make-version.py
			${CMAKE_SOURCE_DIR}
	)

	add_custom_target(copy-dist
		COMMAND cp ${CMAKE_BINARY_DIR}/wireshark*tar* ${CMAKE_BINARY_DIR}/packaging/rpm/SOURCES/
		DEPENDS dist
	)
	add_custom_target(wireshark_rpm
		COMMAND ${RPMBUILD_EXECUTABLE}
			--define "_topdir ${CMAKE_BINARY_DIR}/packaging/rpm"
			--define "_prefix ${CMAKE_INSTALL_PREFIX}"
			${_rpmbuild_with_args}
			-ba SPECS/wireshark.spec
		DEPENDS copy-dist
		WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/packaging/rpm"
		COMMENT "Create a rpm from the current git commit."
	)
endif()

if(BUILD_wireshark AND QT_FOUND AND LINUXDEPLOY_EXECUTABLE AND _linuxdeploy_plugin_qt AND APPIMAGETOOL_EXECUTABLE)
	configure_file(packaging/appimage/Wireshark-AppRun.in ${CMAKE_BINARY_DIR}/packaging/appimage/Wireshark-AppRun @ONLY)
	# Require production builds (/usr + Release).
	if (CMAKE_BUILD_TYPE STREQUAL "Release" AND CMAKE_INSTALL_PREFIX STREQUAL "/usr" )
		add_custom_target(wireshark_appimage_prerequisites)
		add_dependencies(wireshark_appimage_prerequisites ${PROGLIST})
	else()
		add_custom_target(wireshark_appimage_prerequisites
			COMMAND echo "CMAKE_BUILD_TYPE isn't Release or CMAKE_INSTALL_PREFIX isn't /usr."
			COMMAND false
		)
	endif()
	set (_wireshark_ai_appdir ${CMAKE_BINARY_DIR}/packaging/appimage/wireshark.appdir)
	add_custom_target(wireshark_appimage_appdir
		COMMAND ${CMAKE_COMMAND} -E make_directory ${_wireshark_ai_appdir}
		COMMAND env DESTDIR=${_wireshark_ai_appdir}
			${CMAKE_COMMAND} --build . --target install
		DEPENDS wireshark_appimage_prerequisites
	)
	set(_wireshark_appimage_exe_args)
	foreach(_prog ${PROGLIST})
		# XXX This needs to be more robust.
		if (${_prog} STREQUAL "dftest" OR ${_prog} STREQUAL "logray")
			continue()
		endif()
		list(APPEND _wireshark_appimage_exe_args --executable=${_wireshark_ai_appdir}/usr/bin/${_prog})
	endforeach()
	# It looks like linuxdeploy can't handle executables in nonstandard
	# locations, so use it to prep our staging directory here and use
	# appimagetool to to build the appimage.
	add_custom_target(wireshark_appimage_prep
		COMMAND env LD_LIBRARY_PATH=${_wireshark_ai_appdir}/${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR} ${LINUXDEPLOY_EXECUTABLE}
			--appdir=${_wireshark_ai_appdir}
			${_wireshark_appimage_exe_args}
			--desktop-file=${_wireshark_ai_appdir}/usr/share/applications/org.wireshark.Wireshark.desktop
			--icon-file=${CMAKE_SOURCE_DIR}/resources/icons/wsicon256.png
			--custom-apprun=${CMAKE_BINARY_DIR}/packaging/appimage/Wireshark-AppRun
			--plugin=qt
		DEPENDS wireshark_appimage_appdir
	)
	add_custom_target(wireshark_appimage
		COMMAND env VERSION=${PROJECT_VERSION} ${APPIMAGETOOL_EXECUTABLE} ${_wireshark_ai_appdir}
		DEPENDS wireshark_appimage_prep
	)
endif()

if(BUILD_logray AND QT_FOUND AND LINUXDEPLOY_EXECUTABLE AND _linuxdeploy_plugin_qt AND APPIMAGETOOL_EXECUTABLE)
	configure_file(packaging/appimage/Logray-AppRun.in ${CMAKE_BINARY_DIR}/packaging/appimage/Logray-AppRun @ONLY)
	# Require production builds (/usr + Release).
	if (CMAKE_BUILD_TYPE STREQUAL "Release" AND CMAKE_INSTALL_PREFIX STREQUAL "/usr" )
		add_custom_target(logray_appimage_prerequisites)
		add_dependencies(logray_appimage_prerequisites ${PROGLIST})
	else()
		add_custom_target(logray_appimage_prerequisites
			COMMAND echo "CMAKE_BUILD_TYPE isn't Release or CMAKE_INSTALL_PREFIX isn't /usr."
			COMMAND false
		)
	endif()
	set (_logray_ai_appdir ${CMAKE_BINARY_DIR}/packaging/appimage/logray.appdir)
	add_custom_target(logray_appimage_appdir
		COMMAND ${CMAKE_COMMAND} -E make_directory ${_logray_ai_appdir}
		COMMAND env DESTDIR=${_logray_ai_appdir}
			${CMAKE_COMMAND} --build . --target install
		DEPENDS logray_appimage_prerequisites
	)
	set(_logray_appimage_exe_args)
	foreach(_prog ${PROGLIST})
		# XXX This needs to be more robust.
		if (${_prog} STREQUAL "dftest" OR ${_prog} STREQUAL "logray")
			continue()
		endif()
		list(APPEND _logray_appimage_exe_args --executable=${_logray_ai_appdir}/usr/bin/${_prog})
	endforeach()
	# It looks like linuxdeploy can't handle executables in nonstandard
	# locations, so use it to prep our staging directory here and use
	# appimagetool to to build the appimage.
	add_custom_target(logray_appimage_prep
		COMMAND env LD_LIBRARY_PATH=${_logray_ai_appdir}/${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR} ${LINUXDEPLOY_EXECUTABLE}
			--appdir=${_logray_ai_appdir}
			${_logray_appimage_exe_args}
			--desktop-file=${_logray_ai_appdir}/usr/share/applications/org.wireshark.Logray.desktop
			--icon-file=${CMAKE_SOURCE_DIR}/resources/icons/lricon256.png
			--custom-apprun=${CMAKE_BINARY_DIR}/packaging/appimage/Logray-AppRun
			--plugin=qt
		DEPENDS logray_appimage_appdir
	)
	add_custom_target(logray_appimage
		COMMAND env VERSION=${LOG_PROJECT_VERSION} ${APPIMAGETOOL_EXECUTABLE} ${_logray_ai_appdir}
		DEPENDS logray_appimage_prep
	)
endif()

set(CLEAN_C_FILES
	${dumpcap_FILES}
	${wireshark_FILES}
	${logray_FILES}
	${tshark_FILES}
	${tfshark_FILES}
	${rawshark_FILES}
	${dftest_FILES}
	${randpkt_FILES}
	${randpktdump_FILES}
	${etwdump_FILES}
	${falcodump_FILES}
	${udpdump_FILES}
	${text2pcap_FILES}
	${mergecap_FILES}
	${capinfos_FILES}
	${captype_FILES}
	${editcap_FILES}
	${idl2wrs_FILES}
	${mmdbresolve_FILES}
	${sharkd_FILES}
)

if(CLEAN_C_FILES)
	# Make sure we don't pass /WX to rc.exe. Rc doesn't have a /WX flag,
	# but it does have /W (warn about invalid code pages) and /X (ignore
	# the INCLUDE environment variable).
	# This should apparently be handled for us via CMAKE_RC_FLAG_REGEX
	# in CMakeRCInformation.cmake but that doesn't appear to work.
	if(WIN32)
		list(FILTER CLEAN_C_FILES EXCLUDE REGEX ".*\\.rc")
	endif()

	# XXX This also contains object files ($<TARGET_OBJECTS:...>), is that an issue?
	set_source_files_properties(
		${CLEAN_C_FILES}
		PROPERTIES
		COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
	)
endif()

install(
	FILES
		${INSTALL_FILES}
	PERMISSIONS
		OWNER_WRITE OWNER_READ
		GROUP_READ
		WORLD_READ
	DESTINATION
		${CMAKE_INSTALL_DATADIR}/${PROJECT_NAME}
)

if (BUILD_logray)
	install(
		FILES
			${LOG_INSTALL_FILES}
		PERMISSIONS
			OWNER_WRITE OWNER_READ
			GROUP_READ
			WORLD_READ
		DESTINATION
			${CMAKE_INSTALL_DATADIR}/${LOG_PROJECT_NAME}
	)
endif()

install(
	FILES
		${DOC_FILES}
	DESTINATION
		${CMAKE_INSTALL_DOCDIR}
)

if(ASCIIDOCTOR_FOUND AND XSLTPROC_EXECUTABLE)
	install(
		DIRECTORY "${CMAKE_BINARY_DIR}/docbook/wsug_html_chunked"
		DESTINATION "${CMAKE_INSTALL_DOCDIR}"
		COMPONENT "UserGuide"
		EXCLUDE_FROM_ALL
	)
	install(
		DIRECTORY "${CMAKE_BINARY_DIR}/docbook/wsdg_html_chunked"
		DESTINATION "${CMAKE_INSTALL_DOCDIR}"
		COMPONENT "DeveloperGuide"
		EXCLUDE_FROM_ALL
	)
endif()

set(SHARK_PUBLIC_HEADERS
	cfile.h
	cli_main.h
	file.h
	include/ws_attributes.h
	include/ws_codepoints.h
	include/ws_compiler_tests.h
	include/ws_diag_control.h
	include/ws_exit_codes.h
	include/ws_log_defs.h
	include/ws_posix_compat.h
	include/ws_symbol_export.h
	include/wireshark.h
	${CMAKE_BINARY_DIR}/ws_version.h
)

install(FILES ${SHARK_PUBLIC_HEADERS}
	DESTINATION ${PROJECT_INSTALL_INCLUDEDIR}
	COMPONENT "Development"
	EXCLUDE_FROM_ALL
)

# Install icons and other desktop files for Freedesktop.org-compliant desktops.
if(BUILD_wireshark AND QT_FOUND AND NOT APPLE AND (NOT WIN32 OR USE_MSYSTEM))
	install(FILES resources/freedesktop/org.wireshark.Wireshark-mime.xml
		DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/mime/packages"
		RENAME org.wireshark.Wireshark.xml
	)
	install(FILES resources/freedesktop/org.wireshark.Wireshark.metainfo.xml
		DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/metainfo"
	)
	if(BUILD_wireshark AND QT_FOUND)
		install(FILES resources/freedesktop/org.wireshark.Wireshark.desktop
			DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/applications")
	endif()
	foreach(size 16 24 32 48 64 128 256)
		install(FILES resources/icons/wsicon${size}.png
			DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/icons/hicolor/${size}x${size}/apps"
			RENAME org.wireshark.Wireshark.png)
		install(FILES resources/icons/WiresharkDoc-${size}.png
			DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/icons/hicolor/${size}x${size}/mimetypes"
			RENAME org.wireshark.Wireshark-mimetype.png)
	endforeach()
endif()

if(BUILD_logray AND QT_FOUND AND NOT APPLE AND (NOT WIN32 OR USE_MSYSTEM))
	install(FILES resources/freedesktop/org.wireshark.Logray-mime.xml
		DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/mime/packages"
		RENAME org.wireshark.Logray.xml
	)
	install(FILES resources/freedesktop/org.wireshark.Logray.metainfo.xml
		DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/metainfo"
	)
	if(BUILD_wireshark AND QT_FOUND)
		install(FILES resources/freedesktop/org.wireshark.Logray.desktop
			DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/applications")
	endif()
	foreach(size 16 32 48 64 128 256)
		install(FILES resources/icons/lricon${size}.png
			DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/icons/hicolor/${size}x${size}/apps"
			RENAME org.wireshark.Logray.png)
		install(FILES resources/icons/WiresharkDoc-${size}.png
			DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/icons/hicolor/${size}x${size}/mimetypes"
			RENAME org.wireshark.Logray-mimetype.png)
	endforeach()
	install(FILES resources/icons/lricon.svg
		DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/icons/hicolor/scalable/apps"
		RENAME org.wireshark.Logray.svg)
endif()

install(FILES "${CMAKE_BINARY_DIR}/resources/wireshark.pc"
	DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
	COMPONENT "Development"
	EXCLUDE_FROM_ALL
)

install(
	DIRECTORY
		${INSTALL_DIRS}
	DESTINATION
		${CMAKE_INSTALL_DATADIR}/${PROJECT_NAME}
	FILE_PERMISSIONS
		OWNER_WRITE OWNER_READ
		GROUP_READ
		WORLD_READ
	DIRECTORY_PERMISSIONS
		OWNER_EXECUTE OWNER_WRITE OWNER_READ
		GROUP_EXECUTE GROUP_READ
		WORLD_EXECUTE WORLD_READ
	PATTERN ".git" EXCLUDE
	PATTERN ".svn" EXCLUDE
	PATTERN "Makefile.*" EXCLUDE
)

if (BUILD_logray)
	install(
		DIRECTORY
			${LOG_INSTALL_DIRS}
		DESTINATION
			${CMAKE_INSTALL_DATADIR}/${LOG_PROJECT_NAME}
		FILE_PERMISSIONS
			OWNER_WRITE OWNER_READ
			GROUP_READ
			WORLD_READ
		DIRECTORY_PERMISSIONS
			OWNER_EXECUTE OWNER_WRITE OWNER_READ
			GROUP_EXECUTE GROUP_READ
			WORLD_EXECUTE WORLD_READ
		PATTERN ".git" EXCLUDE
		PATTERN ".svn" EXCLUDE
		PATTERN "Makefile.*" EXCLUDE
	)
endif()

if(WIN32 AND NOT USE_MSYSTEM)
	# Note: CMake export mechanism misbehaves with a '.' in the
	# path (incorrect relative path computation).
	set(WIRESHARK_INSTALL_CMAKEDIR "cmake")
else()
	set(WIRESHARK_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}")
endif()

include(CMakePackageConfigHelpers)

configure_package_config_file(WiresharkConfig.cmake.in
	${CMAKE_BINARY_DIR}/WiresharkConfig.cmake
	INSTALL_DESTINATION ${WIRESHARK_INSTALL_CMAKEDIR}
	PATH_VARS
		CMAKE_INSTALL_LIBDIR
		CMAKE_INSTALL_INCLUDEDIR
		PLUGIN_INSTALL_VERSION_LIBDIR
		EXTCAP_INSTALL_LIBDIR
)

write_basic_package_version_file(
	${CMAKE_BINARY_DIR}/WiresharkConfigVersion.cmake
	COMPATIBILITY AnyNewerVersion
)

install(
	FILES
		${CMAKE_BINARY_DIR}/WiresharkConfig.cmake
		${CMAKE_BINARY_DIR}/WiresharkConfigVersion.cmake
	DESTINATION
		${WIRESHARK_INSTALL_CMAKEDIR}
	COMPONENT
		"Development"
	EXCLUDE_FROM_ALL
)

install(EXPORT WiresharkTargets
	DESTINATION ${WIRESHARK_INSTALL_CMAKEDIR}
	COMPONENT "Development"
	EXCLUDE_FROM_ALL
)

# This isn't strictly needed but it makes working around debhelper's
# cleverness a lot easier.
add_custom_target(install-headers
	COMMAND ${CMAKE_COMMAND} -DCOMPONENT=Development -P cmake_install.cmake
)

if (DOXYGEN_EXECUTABLE)
	# API reference
	# We don't have a good way of tracking dependencies, so we simply
	# recreate the whole thing from scratch each time.
	add_custom_target(wsar_html
		COMMAND ${CMAKE_COMMAND} -E remove_directory wsar_html
		COMMAND ${DOXYGEN_EXECUTABLE} doxygen.cfg
	)

	if(WIN32 AND NOT USE_MSYSTEM)
		add_custom_target(wsar_html_perms DEPENDS wsar_html)
	else()
		add_custom_target(wsar_html_perms
			COMMAND find wsar_html
				-type d
				-exec chmod 755 "{}" +
			COMMAND find wsar_html
				-type f
				-exec chmod 644 "{}" +
			DEPENDS wsar_html)
	endif()

	add_custom_target(wsar_html_zip
		COMMAND ${CMAKE_COMMAND} -E tar "cfv" "wsar_html.zip" --format=zip wsar_html
		DEPENDS wsar_html_perms
	)
	set_target_properties(wsar_html wsar_html_zip PROPERTIES
		FOLDER "Documentation"
		EXCLUDE_FROM_DEFAULT_BUILD True
	)
endif(DOXYGEN_EXECUTABLE)

add_custom_target(test-programs
	DEPENDS exntest
		fifo_string_cache_test
		oids_test
		reassemble_test
		tvbtest
		wmem_test
		wscbor_test
		test_epan
		test_wsutil
	COMMENT "Building unit test programs and wrapper"
)
set_target_properties(test-programs PROPERTIES
	FOLDER "Tests"
	EXCLUDE_FROM_DEFAULT_BUILD True
)

# Add target to enable capturing from the build directory. Requires Linux capabilities
# and running with sudo.
if(TARGET dumpcap AND SETCAP_EXECUTABLE)
	add_custom_target(test-capture
		COMMAND ${SETCAP_EXECUTABLE} cap_net_raw,cap_net_admin+ep $<TARGET_FILE:dumpcap>
	)
endif()

add_custom_target(test
	COMMAND ${CMAKE_COMMAND} -E env PYTHONIOENCODING=UTF-8
		${Python3_EXECUTABLE} -m pytest
	WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
	DEPENDS test-programs
	USES_TERMINAL
)

# Make it possible to run pytest without passing the full path as argument.
if(NOT CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
	file(READ "${CMAKE_CURRENT_SOURCE_DIR}/pytest.ini" pytest_ini)
	string(REGEX REPLACE "\naddopts = ([^\n]+)"
		"\naddopts = ${CMAKE_CURRENT_SOURCE_DIR}/test \\1"
		pytest_ini "${pytest_ini}")
	file(WRITE "${CMAKE_BINARY_DIR}/pytest.ini" "${pytest_ini}")
endif()

if (GIT_EXECUTABLE)
	# Update AUTHORS file with entries from git shortlog
	add_custom_target(
		gen-authors
		COMMAND ${Python3_EXECUTABLE} tools/generate_authors.py AUTHORS
		WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
	)
else (GIT_EXECUTABLE)
	add_custom_target( gen-authors COMMAND ${CMAKE_COMMAND} -E echo "Git not found." )
endif (GIT_EXECUTABLE)
set_target_properties(gen-authors PROPERTIES FOLDER "Documentation")

if(WIN32 AND NOT USE_MSYSTEM)
	file (TO_NATIVE_PATH ${CMAKE_SOURCE_DIR}/tools/Get-HardenFlags.ps1 _win_harden_flags)
	add_custom_target(hardening-check
		COMMAND ${POWERSHELL_COMMAND} "${_win_harden_flags}" "${_dll_output_dir_win}"
		DEPENDS ${PROGLIST}
		COMMENT "Checking binaries for security features"
	)
	set_target_properties(hardening-check PROPERTIES FOLDER "Tests")
else()
	find_program(HARDENING_CHECK_EXECUTABLE hardening-check
		DOC "Path to the hardening-check utility."
	)
	if(HARDENING_CHECK_EXECUTABLE)
		foreach(_prog ${PROGLIST})
			get_target_property(_prog_dir ${_prog} RUNTIME_OUTPUT_DIRECTORY)
			if(NOT _prog_dir)
				set(_prog_dir "${CMAKE_BINARY_DIR}/run")
			endif()
			set(_prog_paths ${_prog_paths} "${_prog_dir}/${_prog}")
		endforeach()
		add_custom_target(hardening-check
			COMMAND ${HARDENING_CHECK_EXECUTABLE} ${_prog_paths}
			DEPENDS ${PROGLIST}
			COMMENT "Checking binaries for security features"
		)
	endif()
endif()

CHECKAPI(
	NAME
	  main
	SWITCHES
	SOURCES
	  ${WIRESHARK_SRC}
	  ${TSHARK_TAP_SRC}
)

find_program(SHELLCHECK_EXECUTABLE shellcheck
	DOC "Path to the shellcheck utility."
)
if(SHELLCHECK_EXECUTABLE)
	add_custom_target(shellcheck)
	set_target_properties(shellcheck PROPERTIES FOLDER "Tests")
	# --external-sources requires 0.4.0 or later.
	# ChmodBPF uses "shellcheck shell=bash". Not sure which version
	# added support for that.
	add_custom_command(TARGET shellcheck POST_BUILD
		COMMAND shellcheck --external-sources
			resources/stock_icons/svg-to-png.sh
			packaging/appimage/Logray-AppRun.in
			packaging/appimage/Wireshark-AppRun.in
			"packaging/macosx/ChmodBPF/root/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF"
			packaging/macosx/osx-app.sh.in
			packaging/macosx/osx-dmg.sh.in
			packaging/source/git-export-release.sh.in
			tools/arch-setup.sh
			tools/bsd-setup.sh
			tools/debian-setup.sh
			tools/fuzz-test.sh
			tools/gen-bugnote
			tools/macos-setup-brew.sh
			tools/pre-commit
			tools/randpkt-test.sh
			tools/release-update-debian-soversions.sh
			tools/rpm-setup.sh
			tools/test-captures.sh
			tools/update-tx
			tools/valgrind-wireshark.sh
		WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
	)
endif()

# uninstall target
configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
	"${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
	IMMEDIATE @ONLY)

add_custom_target(uninstall
	COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)

# Break on programmer errors when debugging in Visual Studio
if(MSVC)
	get_property(_targets DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY BUILDSYSTEM_TARGETS)
	foreach(_target ${_targets})
		set_target_properties(${_target} PROPERTIES VS_DEBUGGER_ENVIRONMENT "G_DEBUG=fatal-criticals")
	endforeach()
endif()

# -----------------------------------------------------------------------------
# Packaging (CPack)
# -----------------------------------------------------------------------------
include(ConfigCPack.cmake)

#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
#
