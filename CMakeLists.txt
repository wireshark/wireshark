# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

if(WIN32)
	# Needed for add_custom_command() WORKING_DIRECTORY generator expressions
	cmake_minimum_required(VERSION 3.13)
else()
	cmake_minimum_required(VERSION 3.5)
endif()
if(POLICY CMP0069)
	cmake_policy(SET CMP0069 NEW)
endif()
if(POLICY CMP0074)
	cmake_policy(SET CMP0074 NEW)
endif()
if(POLICY CMP0083)
	cmake_policy(SET CMP0083 NEW)
endif()

if(WIN32)
	set(_project_name Wireshark)
else()
	set(_project_name wireshark)
endif()

project(${_project_name} C CXX)

# Updated by tools/make-version.pl
set(GIT_REVISION 0)
set(PROJECT_MAJOR_VERSION 3)
set(PROJECT_MINOR_VERSION 3)
set(PROJECT_PATCH_VERSION 0)
set(PROJECT_BUILD_VERSION ${GIT_REVISION})
set(PROJECT_VERSION_EXTENSION "")

if(DEFINED ENV{WIRESHARK_VERSION_EXTRA})
	set(PROJECT_VERSION_EXTENSION "$ENV{WIRESHARK_VERSION_EXTRA}")
endif()

set(PROJECT_VERSION "${PROJECT_MAJOR_VERSION}.${PROJECT_MINOR_VERSION}.${PROJECT_PATCH_VERSION}${PROJECT_VERSION_EXTENSION}")

set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")

include( CMakeOptions.txt )

# We require minimum C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

message(STATUS "Generating build using CMake ${CMAKE_VERSION}")

#Where to find local cmake scripts
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules)

# CMake >= 3.9.0 enables LTO/IPO
# Policy CMP0069 enables this behavior when we set the minimum CMake version < 3.9.0
if (ENABLE_LTO)
	include(CheckIPOSupported)
	check_ipo_supported(RESULT lto_supported)
	if(lto_supported)
		set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
	endif()
endif()
if (CMAKE_INTERPROCEDURAL_OPTIMIZATION)
	message(STATUS "LTO/IPO is enabled")
else()
	message(STATUS "LTO/LPO is not enabled")
endif()

# If our target platform is enforced by our generator, set
# WIRESHARK_TARGET_PLATFORM accordingly. Otherwise use
# %WIRESHARK_TARGET_PLATFORM%.

if(WIN32)
	find_package(PowerShell REQUIRED)

	if(CMAKE_CL_64 OR CMAKE_GENERATOR MATCHES "Win64")
		set(WIRESHARK_TARGET_PLATFORM win64)
	elseif(CMAKE_GENERATOR MATCHES "Visual Studio")
		set(WIRESHARK_TARGET_PLATFORM win32)
	else()
		set(WIRESHARK_TARGET_PLATFORM $ENV{WIRESHARK_TARGET_PLATFORM})
	endif()

	if(WIRESHARK_TARGET_PLATFORM MATCHES "win64")
		set(WIRESHARK_TARGET_PROCESSOR_ARCHITECTURE amd64)
	else()
		set(WIRESHARK_TARGET_PROCESSOR_ARCHITECTURE x86)
	endif()

	# Sanity check
	if(DEFINED ENV{PLATFORM})
		string(TOLOWER $ENV{PLATFORM} _vs_platform)
	else()
		set(_vs_platform "[undefined]") # x86
	endif()
	if(
		(_vs_platform STREQUAL "x64" AND NOT WIRESHARK_TARGET_PLATFORM STREQUAL "win64")
		OR
		(_vs_platform STREQUAL "[undefined]" AND NOT WIRESHARK_TARGET_PLATFORM STREQUAL "win32")
	)
		message(FATAL_ERROR "The PLATFORM environment variable (${_vs_platform})"
			" doesn't match the generator platform (${WIRESHARK_TARGET_PLATFORM})")
	endif()
	message(STATUS "Building for ${WIRESHARK_TARGET_PLATFORM} using ${CMAKE_GENERATOR}")

	# Determine where the 3rd party libraries will be
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

	# Is it possible to have a one-time, non-cached option in CMake? If
	# so, we could add a "-DFORCE_WIN_SETUP" which passes -Force to
	# win-setup.ps1.
	execute_process(
		COMMAND ${POWERSHELL_COMMAND} "\"${_win_setup}\"" -Destination "${_ws_lib_dir}" -Platform ${WIRESHARK_TARGET_PLATFORM}
		RESULT_VARIABLE _win_setup_failed
	)
	if(_win_setup_failed)
		message(FATAL_ERROR "Windows setup (win-setup.ps1) failed.")
	endif()

	set(EXTRA_INSTALLER_DIR ${_ws_lib_dir})

	# XXX Add a dependency on ${_ws_lib_dir}/current_tag.txt?

	# Prepopulate some ConfigureChecks values. Compilation checks
	# on Windows can be slow.
	set(HAVE_FCNTL_H TRUE)
	set(HAVE_FLOORL TRUE)
endif(WIN32)

include(UseCustomIncludes)
ADD_CUSTOM_CMAKE_INCLUDE()

# This cannot be implemented via option(...)
if( NOT CMAKE_BUILD_TYPE )
	set( CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING
		"Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel."
		FORCE)
endif()
message(STATUS "CMake build type: ${CMAKE_BUILD_TYPE}")

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
if(WIN32)
	# Override some values on Windows, to match the existing
	# convention of installing everything to a single root folder.
	set(CMAKE_INSTALL_BINDIR ".")
	set(CMAKE_INSTALL_LIBDIR ".")
	set(CMAKE_INSTALL_INCLUDEDIR "include")
	set(CMAKE_INSTALL_DATADIR ".")
	set(CMAKE_INSTALL_DOCDIR ".")
else()
	# By default INSTALL_DATADIR is set to INSTALL_DATAROOTDIR, set the
	# proper value here.
	set(CMAKE_INSTALL_DATADIR "share/${PROJECT_NAME}"
		CACHE PATH "Read-only architecture-independent data"
	)
endif()
include(GNUInstallDirs)

set(PROJECT_INSTALL_INCLUDEDIR "${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}")

# Make sure our executables can can load our libraries if we install into
# a non-default directory on Unix-like systems other than macOS.
# https://gitlab.kitware.com/cmake/community/wikis/doc/cmake/RPATH-handling
set(LIBRARY_INSTALL_RPATH "")
set(EXECUTABLE_INSTALL_RPATH "")
set(EXTCAP_INSTALL_RPATH "")
if(NOT (WIN32 OR APPLE OR USE_STATIC))
	# Try to set a RPATH for installed binaries if the library directory is
	# not already included in the default search list.
	list(FIND CMAKE_C_IMPLICIT_LINK_DIRECTORIES "${CMAKE_INSTALL_FULL_LIBDIR}" IS_SYSTEM_DIR)
	if(IS_SYSTEM_DIR EQUAL -1)
		# Some systems support $ORIGIN in RPATH to enable relocatable
		# binaries. In other cases, only absolute paths can be used.
		# https://www.lekensteyn.nl/rpath.html
		if(CMAKE_SYSTEM_NAME MATCHES "^(Linux|SunOS|FreeBSD)$")
			set(_enable_rpath_origin TRUE)
			if(BUILD_dumpcap AND ENABLE_PCAP)
				# dumpcap will most likely be installed with
				# capabilities or setuid. Relative RPATHs that
				# resolve to non-standard library directories
				# are ignored for such binaries and since we
				# cannot achieve relocatable builds, just
				# disable it by default.
				set(_enable_rpath_origin FALSE)
			endif()
			# Provide a knob to optionally force absolute rpaths,
			# to support old/buggy systems and as a user preference
			# for hardening.
			set(ENABLE_RPATH_ORIGIN ${_enable_rpath_origin} CACHE BOOL
				"Use $ORIGIN with INSTALL_RPATH")
			mark_as_advanced(ENABLE_RPATH_ORIGIN)
		else()
			set(ENABLE_RPATH_ORIGIN FALSE)
		endif()
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

if(WIN32)
    # Linking with wsetargv.obj enables "wildcard expansion" of
    # command-line arguments.
    set(WILDCARD_OBJ wsetargv.obj)
endif(WIN32)

# Banner shown at top right of Qt welcome screen.
if(DEFINED ENV{WIRESHARK_VERSION_FLAVOR})
	set(VERSION_FLAVOR "$ENV{WIRESHARK_VERSION_FLAVOR}")
else()
	set(VERSION_FLAVOR "Development Build")
endif()

# These are required in .rc files and manifests
set(VERSION_MAJOR ${PROJECT_MAJOR_VERSION})
set(VERSION_MINOR ${PROJECT_MINOR_VERSION})
set(VERSION_MICRO ${PROJECT_PATCH_VERSION})
set(VERSION_BUILD ${PROJECT_BUILD_VERSION})
set(RC_VERSION ${PROJECT_MAJOR_VERSION},${PROJECT_MINOR_VERSION},${PROJECT_PATCH_VERSION},${PROJECT_BUILD_VERSION})

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

# Path to our generated executables (or wrapper scripts)
if(WIN32)
	set(WS_PROGRAM_PATH ./run/$<CONFIG>)
else()
	set(WS_PROGRAM_PATH ./run)
endif()

if( CMAKE_C_COMPILER_ID MATCHES "MSVC")
	if ((MSVC_VERSION LESS "1900") OR (MSVC_VERSION GREATER_EQUAL "2000"))
		message(FATAL_ERROR "You are using an unsupported version of MSVC")
	endif()

	add_definitions(
		/DWIN32_LEAN_AND_MEAN
		/D_CRT_SECURE_NO_DEPRECATE
		# NOMINMAX keeps windows.h from defining "min" and "max" via windef.h.
		# This avoids conflicts with the C++ standard library.
		/DNOMINMAX
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
	)

	if(NOT WIRESHARK_TARGET_PLATFORM STREQUAL "win64")
		add_definitions("/D_BIND_TO_CURRENT_CRT_VERSION=1")
	endif()

	set(LOCAL_CFLAGS
		/MP
	)

	set(WS_LINK_FLAGS "/LARGEADDRESSAWARE /MANIFEST:NO /INCREMENTAL:NO /RELEASE")

	# To do: Add /external:... See https://devblogs.microsoft.com/cppblog/broken-warnings-theory/
	#
	# /Zo                               Enhanced debugging of optimised code
	# /utf-8                            Set Source and Executable character sets to UTF-8
	#                                   VS2015(MSVC14): On by default when /Zi or /Z7 used.
	# /guard:cf                         Control Flow Guard (compile and link).
	#                                   See https://docs.microsoft.com/en-us/windows/win32/secbp/control-flow-guard
	#                                   Note: This requires CMake 3.9.0 or newer.
	#                                   https://gitlab.kitware.com/cmake/cmake/commit/f973d49ab9d4c59b93f6dac812a94bb130200836
	# /Qspectre                         Speculative execution attack mitigation
	#                                   See https://devblogs.microsoft.com/cppblog/spectre-mitigations-in-msvc/
	list(APPEND LOCAL_CFLAGS /Zo /utf-8 /guard:cf)
	set(WS_LINK_FLAGS "${WS_LINK_FLAGS} /guard:cf")
	# /Qspectre is not available for VS2015 or older VS2017. Test for its availability.
	set(WIRESHARK_COMMON_FLAGS /Qspectre)

	if(ENABLE_CODE_ANALYSIS)
		list(APPEND LOCAL_CFLAGS /analyze:WX-)
	endif()

	# Additional compiler warnings to be treated as "Level 3"
	# when compiling Wireshark sources. (Selected from "level 4" warnings).
	## 4295: array is too small to include a terminating null character
	## 4100: unreferenced formal parameter
	## 4189: local variable is initialized but not referenced
	# Disable warnings about about use of flexible array members:
	## 4200: nonstandard extension used : zero-sized array in struct/union
	list(APPEND LOCAL_CFLAGS /w34295 /w34100 /w34189 /wd4200)

	# We've matched these to specific compiler versions using the
	# checks above. There's no need to pass them to check_c_compiler_flag
	# or check_cxx_compiler_flag, which can be slow.
	string(REPLACE ";" " " _flags "${LOCAL_CFLAGS}")
	set(CMAKE_C_FLAGS "${_flags} ${CMAKE_C_FLAGS}")
	set(CMAKE_CXX_FLAGS "${_flags} ${CMAKE_CXX_FLAGS}")

else() # ! MSVC
	if(APPLE)
		set(MIN_MACOS_VERSION 10.6) # Arbitrary.
		if(CMAKE_OSX_DEPLOYMENT_TARGET)
			if(CMAKE_OSX_DEPLOYMENT_TARGET VERSION_LESS MIN_MACOS_VERSION)
				message(FATAL_ERROR "We don't support building for macOS < ${MIN_MACOS_VERSION}")
			endif()
			set(MIN_MACOS_VERSION ${CMAKE_OSX_DEPLOYMENT_TARGET})
			message(STATUS "Building for Mac OS X/OS X/macOS ${CMAKE_OSX_DEPLOYMENT_TARGET}")
		endif()
	elseif(CMAKE_OSX_DEPLOYMENT_TARGET)
		message(FATAL_ERROR "CMAKE_OSX_DEPLOYMENT_TARGET only applies when building for macOS")
	endif()

	#
	# Do whatever is necessary to enable as much C99 support as
	# possible in the C compiler.  Newer versions of compilers
	# might default to supporting C99, but older versions may
	# require a special flag.
	#
	# We do not want strict C99 support, as we may also want to
	# use compiler extensions.
	#
	# Prior to CMake 3.1, setting CMAKE_C_STANDARD will not have
	# any effect, so, unless and until we require CMake 3.1 or
	# later, we have to do it ourselves on pre-3.1 CMake, so we
	# just do it ourselves on all versions of CMake.
	#
	# Note: with CMake 3.1 through 3.5, the only compilers for
	# which CMake handles CMAKE_C_STANDARD are GCC and Clang.
	# 3.6 adds support only for Intel C; 3.9 adds support for
	# PGI C, Sun C, and IBM XL C, and 3.10 adds support for
	# Cray C and IAR C, but no version of CMake has support for
	# HP C.  Therefore, even if we use CMAKE_C_STANDARD with
	# compilers for which CMake supports it, we may still have
	# to do it ourselves on other compilers.
	#
	# In addition, CMake 3.5.2 seems to think that GCC versions
	# less than 4.4 don't support -std=gnu99, which we need in
	# order to get support for "for (int i = 0; i < n; i++) ;",
	# which is another reason not to rely on CMake's CMAKE_C_STANDARD
	# support.
	#
	# See the CMake documentation for the CMAKE_<LANG>_COMPILER_ID
	# variables for a list of compiler IDs.
	#
	# We don't worry about MSVC; it doesn't have such a flag -
	# either it doesn't support the C99 features we need at all,
	# or it supports them regardless of the compiler flag.
	#
	# XXX - we add the flag for a given compiler to CMAKE_C_FLAGS,
	# so we test whether it works and add it if we do.  We don't
	# test whether it's necessary in order to get the C99 features
	# that we use; if we ever have a user who tries to compile with
	# a compiler that can't be made to support those features, we
	# can add a test to make sure we actually *have* C99 support.
	#
	if(CMAKE_C_COMPILER_ID MATCHES "GNU" OR
	   CMAKE_C_COMPILER_ID MATCHES "Clang")
		#
		# We use -std=gnu99 rather than -std=c99 because, for
		# some older compilers such as GCC 4.4.7, -std=gnu99
		# is required to avoid errors about C99 constructs
		# such as "for (int i = 0; i < n; i++) ;".
		#
		set(CMAKE_C_FLAGS "-std=gnu99 ${CMAKE_C_FLAGS}")
	elseif(CMAKE_C_COMPILER_ID MATCHES "XL")
		#
		# We want support for extensions picked up for
		# GNU C compatibility, so we use -qlanglvl=extc99.
		#
		set(CMAKE_C_FLAGS "-qlanglvl=extc99 ${CMAKE_C_FLAGS}")
	elseif(CMAKE_C_COMPILER_ID MATCHES "HP")
		#
		# We also need to add -Wp,-H200000 to handle some large
		# #defines we have; that flag is not necessary for the
		# C++ compiler unless the "legacy" C++ preprocessor is
		# being used (+legacy_cpp).  We don't want the legacy
		# preprocessor if it's not the default, so we just add
		# -Wp,-H200000 to the C flags.  (If there are older
		# versions of aC++ that only support the legacy
		# preprocessor, and require that we boost the table
		# size, we'd have to check whether -Wp,-H200000 is
		# supported by the C++ compiler and add it only if it is.)
		#
		set(CMAKE_C_FLAGS "-AC99 -Wp,-H200000 $WS_CFLAGS ${CMAKE_C_FLAGS}")
	elseif(CMAKE_C_COMPILER_ID MATCHES "Sun")
		#
		# We also crank up the warning level.
		#
		set(CMAKE_C_FLAGS "-xc99 -v ${CMAKE_C_FLAGS}")
	elseif(CMAKE_C_COMPILER_ID MATCHES "Intel")
		set(CMAKE_C_FLAGS "-c99 ${CMAKE_C_FLAGS}")
	endif()

	if(CMAKE_C_COMPILER_ID MATCHES "Clang")
		set(WIRESHARK_COMMON_FLAGS ${WIRESHARK_COMMON_FLAGS}
			# avoid "argument unused during compilation" warnings
			# (for example, when getting the -gsplit-dwarf option or
			# when combining -fwrapv with -fno-strict-overflow)
			-Qunused-arguments
		)
	else()
		set(WIRESHARK_COMMON_FLAGS ${WIRESHARK_COMMON_FLAGS}
			-fexcess-precision=fast
		)
	endif()

	list(APPEND WIRESHARK_COMMON_FLAGS
		# The following are for C and C++
		# -O<X> and -g get set by the CMAKE_BUILD_TYPE
		-Wall
		-Wextra
		-Wendif-labels
		-Wpointer-arith
		-Wformat-security
		-fwrapv
		-fno-strict-overflow
		-Wvla
		-Waddress
		-Wattributes
		-Wdiv-by-zero
		-Wignored-qualifiers
		-Wpragmas
		-Wno-overlength-strings
		-Wno-long-long
		-Wheader-guard
		-Wcomma
		-Wshorten-64-to-32
	)

	#
	# Code that may be worth looking into (coding practices)
	#
	if((NOT ENABLE_ASAN) AND (NOT ENABLE_TSAN) AND (NOT ENABLE_UBSAN) AND (NOT DISABLE_FRAME_LARGER_THAN_WARNING))
		#
		# Only do this if none of ASan, TSan, and UBSan are
		# enabled; the instrumentation they add increases
		# the stack usage - we only care about stack
		# usage in normal operation.
		#
		set(WIRESHARK_COMMON_FLAGS ${WIRESHARK_COMMON_FLAGS}
			-Wframe-larger-than=32768
		)
	endif()

	list(APPEND WIRESHARK_C_ONLY_FLAGS
		# The following are C only, not C++
		-Wc++-compat
		-Wunused-const-variable
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
		#
		# Some versions of GCC, such as 4.3.2 and 4.4.5,
		# generate logical-op warnings when strchr() is given a
		# constant string.  The autoconf script checked for that;
		# we don't.
		#
		-Wlogical-op
		-Wjump-misses-init
		#
		# Implicit function declarations are an error in C++ and most
		# likely a programming error in C. Turn -Wimplicit-int and
		# -Wimplicit-function-declaration into an error by default.
		#
		-Werror=implicit
	)

	#
	# The universal zero initializer (in C: struct s x = { 0 };) for
	# structures with multiple members is perfectly legal, but some older
	# compilers warn about it. Silence those older compilers.
	#
	if((CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_C_COMPILER_VERSION VERSION_LESS "5.1") OR
	   (CMAKE_C_COMPILER_ID STREQUAL "Clang" AND CMAKE_C_COMPILER_VERSION VERSION_LESS "6.0") OR
	   (CMAKE_C_COMPILER_ID STREQUAL "AppleClang" AND CMAKE_C_COMPILER_VERSION VERSION_LESS "10.0"))
		if(NOT CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_VERSION VERSION_LESS "4.7")
			list(APPEND WIRESHARK_C_ONLY_FLAGS -Wno-missing-field-initializers)
		endif()
		# Silence warnings for initialization of nested structs like
		# struct { struct { int a, b; } s; int c; } v = { 0 };
		list(APPEND WIRESHARK_C_ONLY_FLAGS -Wno-missing-braces)
	endif()


	list(APPEND WIRESHARK_CXX_ONLY_FLAGS
		-Wextra-semi
	)

	#
	# These are not enabled by default, because the warnings they
	# produce are very hard or impossible to eliminate.
	#
	if(ENABLE_EXTRA_COMPILER_WARNINGS)   # This overrides -Werror
		list(APPEND WIRESHARK_COMMON_FLAGS
			# The following are for C and C++
			-Wpedantic
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
			# Some generated ASN.1 dissectors block this one;
			# multiple function declarations for the same
			# function are being generated.
			#
			-Wredundant-decls
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
			#
			# Works only with Clang
			#
			-Wunreachable-code
			#
			# Works only with Clang but generates a lot of warnings
			# (about glib library not using Doxygen)
			#
			-Wdocumentation
			#
			# Works only with GCC 7
			#
			-Wduplicated-branches
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
	else()
		#
		# -Wpointer-sign is a default test we get with -Wall and
		# -W, but for some reason we were suppressing it -
		# unconditionally.  Suppress it only without the extra
		# warnings, so we can at least see how much we get.
		# (This would have caught at least one error - the one
		# in change https://code.wireshark.org/review/33234,
		# which would have suggested that the wrong
		# proto_tree_add_ret_ call was being used.)
		#
		list(APPEND WIRESHARK_C_ONLY_FLAGS
			-Wno-pointer-sign
		)
	endif()

	add_definitions(
		-DG_DISABLE_DEPRECATED
		-DG_DISABLE_SINGLE_INCLUDES
	)

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
			set(${_flags} "${${_flags}} -fmacro-prefix-map=${CMAKE_SOURCE_DIR}/=")
			set(${_flags} "${${_flags}} -fmacro-prefix-map=${CMAKE_BINARY_DIR}/=")
			if(_relative_source_dir MATCHES "\\.\\.$")
				set(${_flags} "${${_flags}} -fmacro-prefix-map=${_relative_source_dir}/=")
			endif()
		endif()
	endforeach()
endif()

include(CMakePushCheckState)

if(ENABLE_ASAN)
	cmake_push_check_state()
	set(CMAKE_REQUIRED_LIBRARIES "-fsanitize=address")
	check_c_compiler_flag(-fsanitize=address C__fsanitize_address_VALID)
	check_cxx_compiler_flag(-fsanitize=address CXX__fsanitize_address_VALID)
	cmake_pop_check_state()
	if(NOT C__fsanitize_address_VALID OR NOT CXX__fsanitize_address_VALID)
		message(FATAL_ERROR "ENABLE_ASAN was requested, but not supported!")
	endif()
	set(CMAKE_C_FLAGS "-fsanitize=address ${CMAKE_C_FLAGS}")
	set(CMAKE_CXX_FLAGS "-fsanitize=address ${CMAKE_CXX_FLAGS}")
	# Disable ASAN for build-time tools, e.g. lemon
	check_c_compiler_flag(-fno-sanitize=all C__fno_sanitize_all_VALID)
	if(C__fno_sanitize_all_VALID)
		set(NO_SANITIZE_CFLAGS "-fno-sanitize=all")
		set(NO_SANITIZE_LDFLAGS "-fno-sanitize=all")
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

set(WERROR_COMMON_FLAGS "")
if(NOT DISABLE_WERROR AND NOT ENABLE_EXTRA_COMPILER_WARNINGS)
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
	include_directories(/usr/local/opt/gettext/include)
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
find_package(GLIB2 "2.32.0" REQUIRED)
include_directories(SYSTEM ${GLIB2_INCLUDE_DIRS})
reset_find_package(GMODULE2)
find_package(GMODULE2)
reset_find_package(GTHREAD2)
find_package(GTHREAD2 REQUIRED)
reset_find_package(GCRYPT GCRYPT_ERROR_LIBRARY)
find_package(GCRYPT "1.4.2" REQUIRED)
# C Asynchronous resolver
reset_find_package(CARES)
find_package(CARES "1.5.0" REQUIRED)
find_package(LEX REQUIRED)
find_package(YACC REQUIRED)
find_package(Perl REQUIRED)

if(CMAKE_VERSION VERSION_LESS "3.12")
	# Locate the Python interpreter. Finds the wrong (Python 2) version if:
	# - PATH contains python3.6, but not python3 (3.4). Affects RHEL7+EPEL.
	# - Path contains C:\Python27 but not C:\Python37 (which is installed,
	#   but not present in PATH).
	find_package(PythonInterp 3.4 REQUIRED)
else()
	find_package(Python3 3.4 REQUIRED)
	# Several files (including LocatePythonModule) still use the old name
	# from FindPythonInterp, let's stick to it for now.
	set(PYTHON_EXECUTABLE ${Python3_EXECUTABLE})
endif()

if (NOT WIN32)
	find_package(Gettext)
	find_package(M REQUIRED)
endif()

if(BUILD_sshdump OR BUILD_ciscodump)
	set(ENABLE_LIBSSH ON)
else()
	set(ENABLE_LIBSSH OFF)
endif()
ws_find_package(LIBSSH ENABLE_LIBSSH HAVE_LIBSSH "0.6")

ws_find_package(PCAP ENABLE_PCAP HAVE_LIBPCAP)
ws_find_package(AIRPCAP ENABLE_AIRPCAP HAVE_AIRPCAP)
ws_find_package(Systemd BUILD_sdjournal HAVE_SYSTEMD)

# Build the Qt GUI?
if(BUILD_wireshark)
	# Untested, may not work if CMAKE_PREFIX_PATH gets overwritten
	# somewhere. The if WIN32 in this place is annoying as well.
	if(WIN32)
		set(QT5_BASE_PATH "$ENV{QT5_BASE_DIR}")
		set(CMAKE_PREFIX_PATH "${QT5_BASE_PATH}")
	endif()
	if(APPLE AND EXISTS /usr/local/opt/qt5)
		# Homebrew installs Qt5 (up to at least 5.11.0) in
		# /usr/local/qt5. Ensure that it can be found by CMake
		# since it is not in the default /usr/local prefix.
		# Add it to PATHS so that it doesn't override the
		# CMAKE_PREFIX_PATH environment variable.
		# QT_FIND_PACKAGE_OPTIONS should be passed to find_package,
		# e.g. find_package(Qt5Core ${QT_FIND_PACKAGE_OPTIONS})
		list(APPEND QT_FIND_PACKAGE_OPTIONS PATHS /usr/local/opt/qt5)
	endif()
	set(QT_PACKAGELIST
		Qt5Core
		Qt5LinguistTools
		Qt5Multimedia
		Qt5PrintSupport
		Qt5Widgets
	)
	if(APPLE)
		list(APPEND QT_PACKAGELIST Qt5MacExtras)
		ws_find_package(Sparkle ENABLE_SPARKLE HAVE_SOFTWARE_UPDATE)
	endif()
	if(WIN32)
		list(APPEND QT_PACKAGELIST Qt5WinExtras)
	endif()
	foreach(_qt_package IN LISTS QT_PACKAGELIST)
		find_package(${_qt_package} REQUIRED ${QT_FIND_PACKAGE_OPTIONS})
		list(APPEND QT_LIBRARIES ${${_qt_package}_LIBRARIES})
		list(APPEND QT_INCLUDE_DIRS ${${_qt_package}_INCLUDE_DIRS})
		list(APPEND QT_COMPILE_DEFINITIONS ${${_qt_package}_COMPILE_DEFINITIONS})
	endforeach()
	set(QT_FOUND ON)
	if(Qt5MacExtras_FOUND)
		set(QT_MACEXTRAS_LIB 1)
	endif()
endif()

# MaxMind DB address resolution
ws_find_package(MaxMindDB BUILD_mmdbresolve HAVE_MAXMINDDB)

# SMI SNMP
reset_find_package(SMI SMI_SHARE_DIR)
ws_find_package(SMI ENABLE_SMI HAVE_LIBSMI)

# Support for TLS decryption using RSA private keys.
ws_find_package(GNUTLS ENABLE_GNUTLS HAVE_LIBGNUTLS "3.2.0")

# Kerberos
ws_find_package(KERBEROS ENABLE_KERBEROS HAVE_KERBEROS)

# Zlib compression
ws_find_package(ZLIB ENABLE_ZLIB HAVE_ZLIB)

# Minizip compression
ws_find_package(Minizip ENABLE_MINIZIP HAVE_MINIZIP)

# Brotli compression
ws_find_package(BROTLI ENABLE_BROTLI HAVE_BROTLI)

# LZ4 compression
ws_find_package(LZ4 ENABLE_LZ4 HAVE_LZ4)

# Snappy compression
ws_find_package(SNAPPY ENABLE_SNAPPY HAVE_SNAPPY)

# zstd compression
ws_find_package(ZSTD ENABLE_ZSTD HAVE_ZSTD "1.0.0")

# Enhanced HTTP/2 dissection
ws_find_package(NGHTTP2 ENABLE_NGHTTP2 HAVE_NGHTTP2)

# Embedded Lua interpreter
ws_find_package(LUA ENABLE_LUA HAVE_LUA "5.1")

ws_find_package(NL ENABLE_NETLINK HAVE_LIBNL)

ws_find_package(SBC ENABLE_SBC HAVE_SBC)

ws_find_package(SPANDSP ENABLE_SPANDSP HAVE_SPANDSP)

ws_find_package(BCG729 ENABLE_BCG729 HAVE_BCG729)

ws_find_package(ILBC ENABLE_ILBC HAVE_ILBC)

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

# Include minizip include directories
if(MINIZIP_FOUND)
	include_directories(
		${MINIZIP_INCLUDE_DIRS}
	)
else()
	set(MINIZIP_LIBRARY "")
endif()

# Windows version updates
ws_find_package(WinSparkle ENABLE_WINSPARKLE HAVE_SOFTWARE_UPDATE)

find_package( Asciidoctor 1.5 )

find_package(POD REQUIRED)

find_package(DOXYGEN)

# The SpeexDSP resampler is required iff building wireshark or sharkd.
if(BUILD_wireshark OR BUILD_sharkd)
	find_package(SpeexDSP)
	if(SpeexDSP_FOUND)
		set(HAVE_SPEEXDSP 1)
	else()
		add_subdirectory(speexdsp)
		set(SPEEXDSP_INCLUDE_DIRS "")
		set(SPEEXDSP_LIBRARIES "speexresampler")
	endif()
endif()

# dist target that prepares source dir
# XXX Duplicated in the RPM section below.
add_custom_target(dist
	COMMAND ${CMAKE_BINARY_DIR}/packaging/source/git-export-release.sh -d "${CMAKE_BINARY_DIR}"
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

if(GNUTLS_FOUND AND NOT GNUTLS_VERSION VERSION_LESS "3.4.0")
	# While all Linux and Windows builds have PKCS #11 support enabled,
	# macos-setup.sh explicitly disables it using --without-p11-kit.
	#
	# Require at least GnuTLS 3.4.0 such that public keys can be calculated
	# from PKCS #11 private keys.
	include(CheckSymbolExists)
	cmake_push_check_state()
	if(WIN32)
		set(CMAKE_REQUIRED_DEFINITIONS -Dssize_t=int)
	endif()
	set(CMAKE_REQUIRED_INCLUDES ${GNUTLS_INCLUDE_DIRS})
	set(CMAKE_REQUIRED_LIBRARIES ${GNUTLS_LIBRARIES})
	check_symbol_exists(gnutls_pkcs11_obj_list_import_url4 gnutls/pkcs11.h HAVE_GNUTLS_PKCS11)
	cmake_pop_check_state()
endif()

if (QT_FOUND)
	if (Qt5Widgets_VERSION VERSION_LESS 5.3)
		message(FATAL_ERROR "Qt 5.3 or later is required.")
	endif()
	if (Qt5Widgets_VERSION VERSION_GREATER 5.6
	    AND (CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID MATCHES "Clang"))
		# Qt 5.7 and later require C++ 11.
		set(CMAKE_CXX_STANDARD 11)
		set(CMAKE_CXX_STANDARD_REQUIRED ON)
	endif()
	if(NOT DEFINED MOC_OPTIONS)
		# Squelch moc verbose "nothing to do" output
		set(MOC_OPTIONS -nn)
	endif()

	# CMake uses qmake to find Qt4. It relies on Qt's CMake modules
	# to find Qt5. This means that we can't assume that the qmake
	# in our PATH is the correct one. We can fetch qmake's location
	# from Qt5::qmake, which is is defined in Qt5CoreConfigExtras.cmake.
	get_target_property(QT_QMAKE_EXECUTABLE Qt5::qmake IMPORTED_LOCATION)
	get_filename_component(_qt_bin_path "${QT_QMAKE_EXECUTABLE}" DIRECTORY)
	set(QT_BIN_PATH "${_qt_bin_path}" CACHE INTERNAL
		"Path to qmake, macdeployqt, windeployqt, and other Qt utilities."
	)
	# Use qmake to find windeployqt and macdeployqt. Ideally one of
	# the modules in ${QTDIR}/lib/cmake would do this for us.
	if(WIN32)
		find_program(QT_WINDEPLOYQT_EXECUTABLE windeployqt
			HINTS "${QT_BIN_PATH}"
			DOC "Path to the windeployqt utility."
		)
		if(Qt5Widgets_VERSION VERSION_GREATER "5.5.999")
			set(QT_WINDEPLOYQT_EXTRA_OPTS --pdb)
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
		# CMake < 3.7 doesn't support VERSION_GREATER_EQUAL.
		if(Qt5Widgets_VERSION VERSION_GREATER "5.14.999")
			set(MIN_MACOS_VERSION 10.13)
		elseif(Qt5Widgets_VERSION VERSION_GREATER "5.11.999")
			set(MIN_MACOS_VERSION 10.12)
		elseif(Qt5Widgets_VERSION VERSION_GREATER "5.9.999")
			set(MIN_MACOS_VERSION 10.11)
		elseif(Qt5Widgets_VERSION VERSION_GREATER "5.8.999")
			set(MIN_MACOS_VERSION 10.10)
		elseif(Qt5Widgets_VERSION VERSION_GREATER "5.7.999")
			set(MIN_MACOS_VERSION 10.9)
		elseif(Qt5Widgets_VERSION VERSION_GREATER "5.4.999")
			set(MIN_MACOS_VERSION 10.8)
		endif()
		if(CMAKE_OSX_DEPLOYMENT_TARGET AND CMAKE_OSX_DEPLOYMENT_TARGET VERSION_LESS MIN_MACOS_VERSION)
			message(FATAL_ERROR "Qt version ${Qt5Widgets_VERSION} requires CMAKE_OSX_DEPLOYMENT_TARGET (${CMAKE_OSX_DEPLOYMENT_TARGET}) >= ${MIN_MACOS_VERSION}")
		endif()
	endif()

endif()

if(ENABLE_CHECKHF_CONFLICT)
	set(ENABLE_CHECK_FILTER 1)
endif()

#
# Platform-specific additional libraries.
#
if(WIN32)
	set(WIN_PSAPI_LIBRARY    psapi.lib)
	set(WIN_WS2_32_LIBRARY   ws2_32.lib)
	set(WIN_COMCTL32_LIBRARY comctl32.lib )
	set(WIN_VERSION_LIBRARY  version.lib)
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
endif()

include(ConfigureChecks.cmake)

# Global properties
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

if(ENABLE_CCACHE AND (CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID MATCHES "Clang"))
	# https://stackoverflow.com/questions/1815688/how-to-use-ccache-with-cmake/24305849#24305849
	find_program(CCACHE_EXECUTABLE ccache)
	if(CCACHE_EXECUTABLE)
		set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_EXECUTABLE}")
		set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK "${CCACHE_EXECUTABLE}")
	endif()
endif()

# The top level checkAPIs target, add before subdirectory calls so it's avaiable to all
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
if (WIN32)
	set(EXTCAP_INSTALL_LIBDIR "extcap" CACHE INTERNAL "The extcap dir")
else ()
	set(EXTCAP_INSTALL_LIBDIR "${CMAKE_INSTALL_LIBDIR}/${PROJECT_NAME}/extcap" CACHE INTERNAL "The extcap dir")
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
if(WIN32)
	set(PLUGIN_INSTALL_LIBDIR "plugins" CACHE INTERNAL "The plugin dir")
else()
	set(PLUGIN_INSTALL_LIBDIR "${CMAKE_INSTALL_LIBDIR}/${PROJECT_NAME}/plugins" CACHE INTERNAL "The plugin dir")
endif()
set(PLUGIN_INSTALL_VERSION_LIBDIR "${PLUGIN_INSTALL_LIBDIR}/${PLUGIN_PATH_ID}")
set(PLUGIN_VERSION_DIR "plugins/${PLUGIN_PATH_ID}")

add_subdirectory( capchild )
add_subdirectory( caputils )
add_subdirectory( doc )
add_subdirectory( docbook EXCLUDE_FROM_ALL )
add_subdirectory( epan )
add_subdirectory( extcap )
add_subdirectory( randpkt_core )
add_subdirectory( tools/lemon )
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

# wsutil must be added after DATAFILE_DIR is set such that filesystem.c can
# learn about the directory location.
add_subdirectory( wsutil )

if(BUILD_wireshark AND QT_FOUND)
	add_subdirectory( ui/qt )
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
		plugins/wiretap/usbdump
		plugins/codecs/G711
		plugins/codecs/l16_mono
		${CUSTOM_PLUGIN_SRC_DIR}
	)
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
	if(ILBC_FOUND)
		list(APPEND PLUGIN_SRC_DIRS
			plugins/codecs/iLBC
		)
	endif()
	if(SBC_FOUND)
		list(APPEND PLUGIN_SRC_DIRS
			plugins/codecs/sbc
		)
	endif()

	# Build demo plugin, only if asked explicitly
	if(ENABLE_PLUGIN_IFDEMO)
		set(PLUGIN_SRC_DIRS
			${PLUGIN_SRC_DIRS}
			plugins/epan/pluginifdemo
		)
	endif()

else()
	set(PLUGIN_SRC_DIRS )
endif()

if(ENABLE_APPLICATION_BUNDLE)
	if(CMAKE_CFG_INTDIR STREQUAL ".")
		set(_plugin_dir "${CMAKE_BINARY_DIR}/run/Wireshark.app/Contents/PlugIns/wireshark/${PLUGIN_PATH_ID}")
	else()
		# Xcode
		set(_plugin_dir "${CMAKE_BINARY_DIR}/run/$<CONFIG>/Wireshark.app/Contents/PlugIns/wireshark/${PLUGIN_PATH_ID}")
	endif()
elseif(WIN32 AND NOT CMAKE_CFG_INTDIR STREQUAL ".")
	set(_plugin_dir "${CMAKE_BINARY_DIR}/run/$<CONFIG>/${PLUGIN_VERSION_DIR}")
else()
	set(_plugin_dir "${DATAFILE_DIR}/${PLUGIN_VERSION_DIR}")
endif()
set (PLUGIN_DIR ${_plugin_dir} CACHE INTERNAL "Build time plugin location.")

foreach(_plugin_src_dir ${PLUGIN_SRC_DIRS})
	add_subdirectory( ${_plugin_src_dir} )
endforeach()

# Large file support (e.g. make off_t 64 bit if supported)
include(gmxTestLargeFiles)
gmx_test_large_files(GMX_LARGEFILES)

set( VERSION ${PROJECT_VERSION} )
if(VCSVERSION_OVERRIDE)
	# Allow distributors to override detection of the Git tag and version.
	string(CONFIGURE "#define VCSVERSION \"@VCSVERSION_OVERRIDE@\"\n"
		_version_h_contents ESCAPE_QUOTES)
	file(WRITE "${CMAKE_BINARY_DIR}/version.h" "${_version_h_contents}")
	message(STATUS "VCSVERSION_OVERRIDE: ${VCSVERSION_OVERRIDE}")
else()
	add_custom_target(version
		BYPRODUCTS version.h
		COMMAND ${PERL_EXECUTABLE}
			${CMAKE_SOURCE_DIR}/tools/make-version.pl
			${CMAKE_SOURCE_DIR}
	)
	set_target_properties(version PROPERTIES FOLDER "Auxiliary")
endif()

set( configure_input "Built with CMake ${CMAKE_VERSION}" )
configure_file(${CMAKE_SOURCE_DIR}/cmakeconfig.h.in ${CMAKE_BINARY_DIR}/config.h)

configure_file(${CMAKE_SOURCE_DIR}/ws_version.h.in ${CMAKE_BINARY_DIR}/ws_version.h)

set( prefix "${CMAKE_INSTALL_PREFIX}" )
set( exec_prefix "\${prefix}" )
set( libdir "\${exec_prefix}/${CMAKE_INSTALL_LIBDIR}" )
set( includedir  "\${prefix}/include" )
set( plugindir "\${libdir}/wireshark/${PLUGIN_VERSION_DIR}" )

# Doxygen variables
file(GLOB TOP_LEVEL_SOURCE_LIST *.c *.cpp *.h)
string (REPLACE ";" " " DOXYGEN_TOP_LEVEL_SOURCES "${TOP_LEVEL_SOURCE_LIST}")
set(DOXYGEN_INPUT_DIRECTORY ${CMAKE_SOURCE_DIR})
set(DOXYGEN_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

set(CFG_OUT_FILES
	doxygen.cfg
	image/libwireshark.rc
	image/wireshark.rc
	image/dumpcap.rc
	image/libwsutil.rc
	image/wiretap.rc
	image/wireshark.exe.manifest
	packaging/macosx/Info.plist
	packaging/macosx/dmgbuild-settings.py
	packaging/macosx/osx-app.sh
	packaging/macosx/osx-dmg.sh
	packaging/source/git-export-release.sh
	wireshark.pc
)
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
	URL "https://www.linphone.org/technical-corner/bcg729/overview"
	PURPOSE "Support for G.729 codec in RTP player"
)
set_package_properties(ILBC PROPERTIES
	DESCRIPTION "iLBC decoder"
	URL "https://github.com/TimothyGu/libilbc"
	PURPOSE "Support for iLBC codec in RTP player"
)
set_package_properties(LIBXML2 PROPERTIES
	DESCRIPTION "XML parsing library"
	URL "http://xmlsoft.org/"
	PURPOSE "Read XML configuration files in EPL dissector"
)
set_package_properties(LIBSSH PROPERTIES
	DESCRIPTION "Library for implementing SSH clients"
	URL "https://www.libssh.org/"
	PURPOSE "extcap remote SSH interfaces (sshdump, ciscodump)"
)
set_package_properties(LZ4 PROPERTIES
	DESCRIPTION "LZ4 is lossless compression algorithm used in some protocol (CQL...)"
	URL "http://www.lz4.org"
	PURPOSE "LZ4 decompression in CQL and Kafka dissectors"
)
set_package_properties(SNAPPY PROPERTIES
	DESCRIPTION "A fast compressor/decompressor from Google"
	URL "https://google.github.io/snappy/"
	PURPOSE "Snappy decompression in CQL and Kafka dissectors"
)
set_package_properties(ZSTD PROPERTIES
	DESCRIPTION "A compressor/decompressor from Facebook providing better compression than Snappy at a cost of speed"
	URL "https://facebook.github.io/zstd/"
	PURPOSE "Zstd decompression in Kafka dissector"
)
set_package_properties(NGHTTP2 PROPERTIES
	DESCRIPTION "HTTP/2 C library and tools"
	URL "https://nghttp2.org"
	PURPOSE "Header decompression in HTTP2"
)
set_package_properties(CARES PROPERTIES
	DESCRIPTION "Library for asynchronous DNS requests"
	URL "https://c-ares.haxx.se/"
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
	URL "https://www.winimage.com/zLibDll/minizip.html"
	DESCRIPTION "C library for supporting zip/unzip functionality"
	PURPOSE "Support for profiles import/export"
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

# Newer Libgcrypt versions may be required for certain functionality:
# 1.6
# - IEEE 802.11 TDLS, AES-GCMP-128 and AES-GCMP-256 decryption
# - IEEE 802.11 WPA3-Personal / SAE decryption
# - BT Mesh decryption
# - Distributed Object Framework (DOF) decryption
# - IKEv2 integrity check
# - LoRaWAN integrity check
# - LTE PDCP EIA2 integrity check
# - QUIC decryption support
# - SMB3 AES-128-CCM/GCM decryption
# - TLS 1.3 0-RTT decryption
# - TLS GCM/CCM ciphers integrity check
# 1.7
# - QUIC ChaCha20-Poly1305 decryption
# - TLS 1.3 ChaCha20-Poly1305 decryption
# 1.8
# - dcerpc-netlogon NETLOGON_FLAG_AES decryption
# - WireGuard decryption
if(GCRYPT_VERSION VERSION_LESS 1.6.0)
	message(WARNING "Libgcrypt version 1.6.0 or newer is strongly recommended for improved decryption support, found ${GCRYPT_VERSION}")
elseif(GCRYPT_VERSION VERSION_LESS 1.8.0)
	message(WARNING "Libgcrypt version 1.8.0 or newer is recommended for full decryption functionality, found ${GCRYPT_VERSION}")
endif()

# Should this be part of libui?
if(WIN32)
	set(PLATFORM_UI_SRC
		ui/win32/console_win32.c
		ui/win32/file_dlg_win32.c
	)
	set(PLATFORM_UI_RC_FILES
		image/file_dlg_win32.rc
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
	${CMAKE_SOURCE_DIR}/ui/cli/tap-wspstat.c
	${CUSTOM_TSHARK_TAP_SRC}

)

set(INSTALL_DIRS
	diameter
	dtds
	profiles
	radius
	tpncp
	wimaxasncp
)

set(INSTALL_FILES
	cfilters
	colorfilters
	dfilters
	dfilter_macros
	enterprises.tsv
	ipmap.html
	manuf
	pdml2html.xsl
	services
	smi_modules
	wka
	docbook/ws.css
	${CMAKE_BINARY_DIR}/doc/AUTHORS-SHORT
	${CMAKE_BINARY_DIR}/doc/androiddump.html
	${CMAKE_BINARY_DIR}/doc/udpdump.html
	${CMAKE_BINARY_DIR}/doc/capinfos.html
	${CMAKE_BINARY_DIR}/doc/captype.html
	${CMAKE_BINARY_DIR}/doc/ciscodump.html
	${CMAKE_BINARY_DIR}/doc/dftest.html
	${CMAKE_BINARY_DIR}/doc/dumpcap.html
	${CMAKE_BINARY_DIR}/doc/editcap.html
	${CMAKE_BINARY_DIR}/doc/extcap.html
	${CMAKE_BINARY_DIR}/doc/mergecap.html
	${CMAKE_BINARY_DIR}/doc/randpkt.html
	${CMAKE_BINARY_DIR}/doc/randpktdump.html
	${CMAKE_BINARY_DIR}/doc/rawshark.html
	${CMAKE_BINARY_DIR}/doc/reordercap.html
	${CMAKE_BINARY_DIR}/doc/sshdump.html
	${CMAKE_BINARY_DIR}/doc/text2pcap.html
	${CMAKE_BINARY_DIR}/doc/tshark.html
	${CMAKE_BINARY_DIR}/doc/wireshark.html
	${CMAKE_BINARY_DIR}/doc/wireshark-filter.html
)

if(MAXMINDDB_FOUND)
	list(APPEND INSTALL_FILES ${CMAKE_BINARY_DIR}/doc/mmdbresolve.html)
endif()

if (BUILD_corbaidl2wrs)
	list(APPEND INSTALL_FILES ${CMAKE_BINARY_DIR}/doc/idl2wrs.html)
endif()
if (BUILD_xxx2deb)
	list(APPEND INSTALL_FILES
		${CMAKE_BINARY_DIR}/doc/asn2deb.html
		${CMAKE_BINARY_DIR}/doc/idl2deb.html
	)
endif()

if(NOT WIN32)
	# We do this for Windows further down in the copy_data_files target.
	list(APPEND INSTALL_FILES COPYING)
endif()

set(VERSION_INFO_LIBS
	${ZLIB_LIBRARIES}
)
set(VERSION_INFO_INCLUDE_DIRS
	${ZLIB_INCLUDE_DIRS}
)

if(WIN32)
	set(_dll_output_dir "${DATAFILE_DIR}")
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

	# Optional DLLs and PDBs.
	set (OPTIONAL_DLLS)
	set (OPTIONAL_PDBS)
	if (AIRPCAP_FOUND)
		list (APPEND OPTIONAL_DLLS "${AIRPCAP_DLL_DIR}/${AIRPCAP_DLL}")
	endif(AIRPCAP_FOUND)
	if (CARES_FOUND)
		list (APPEND OPTIONAL_DLLS "${CARES_DLL_DIR}/${CARES_DLL}")
		list (APPEND OPTIONAL_PDBS "${CARES_DLL_DIR}/${CARES_PDB}")
	endif(CARES_FOUND)
	if (MAXMINDDB_FOUND)
		list (APPEND OPTIONAL_DLLS "${MAXMINDDB_DLL_DIR}/${MAXMINDDB_DLL}")
	endif(MAXMINDDB_FOUND)
	if (LIBSSH_FOUND)
		list (APPEND OPTIONAL_DLLS "${LIBSSH_DLL_DIR}/${LIBSSH_DLL}")
	endif(LIBSSH_FOUND)
	foreach( _dll ${GCRYPT_DLLS} )
		list (APPEND OPTIONAL_DLLS "${GCRYPT_DLL_DIR}/${_dll}")
	endforeach(_dll)
	foreach( _dll ${GNUTLS_DLLS} )
		list (APPEND OPTIONAL_DLLS "${GNUTLS_DLL_DIR}/${_dll}")
	endforeach(_dll)
	foreach( _dll ${KERBEROS_DLLS} )
		list (APPEND OPTIONAL_DLLS "${KERBEROS_DLL_DIR}/${_dll}")
	endforeach(_dll)
	if (LUA_FOUND)
		list (APPEND OPTIONAL_DLLS "${LUA_DLL_DIR}/${LUA_DLL}")
	endif(LUA_FOUND)
	if (LZ4_FOUND)
		list (APPEND OPTIONAL_DLLS "${LZ4_DLL_DIR}/${LZ4_DLL}")
		list (APPEND OPTIONAL_PDBS "${LZ4_DLL_DIR}/${LZ4_PDB}")
	endif(LZ4_FOUND)
	if (ZSTD_FOUND)
		list (APPEND OPTIONAL_DLLS "${ZSTD_DLL_DIR}/${ZSTD_DLL}")
	endif(ZSTD_FOUND)
	if (NGHTTP2_FOUND)
		list (APPEND OPTIONAL_DLLS "${NGHTTP2_DLL_DIR}/${NGHTTP2_DLL}")
		list (APPEND OPTIONAL_PDBS "${NGHTTP2_DLL_DIR}/${NGHTTP2_PDB}")
	endif(NGHTTP2_FOUND)
	if (SBC_FOUND)
		list (APPEND OPTIONAL_DLLS "${SBC_DLL_DIR}/${SBC_DLL}")
	endif(SBC_FOUND)
	if (SPANDSP_FOUND)
		list (APPEND OPTIONAL_DLLS "${SPANDSP_DLL_DIR}/${SPANDSP_DLL}")
	endif(SPANDSP_FOUND)
	if (BCG729_FOUND)
		list (APPEND OPTIONAL_DLLS "${BCG729_DLL_DIR}/${BCG729_DLL}")
	endif(BCG729_FOUND)
	if (ILBC_FOUND)
		list (APPEND OPTIONAL_DLLS "${ILBC_DLL_DIR}/${ILBC_DLL}")
	endif(ILBC_FOUND)
	if (LIBXML2_FOUND)
		foreach( _dll ${LIBXML2_DLLS} )
			list (APPEND OPTIONAL_DLLS "${LIBXML2_DLL_DIR}/${_dll}")
		endforeach(_dll)
		foreach( _pdb ${LIBXML2_PDBS} )
			list (APPEND OPTIONAL_PDBS "${LIBXML2_DLL_DIR}/${_pdb}")
		endforeach(_pdb)
	endif(LIBXML2_FOUND)
	if (SMI_FOUND)
		list (APPEND OPTIONAL_DLLS "${SMI_DLL_DIR}/${SMI_DLL}")
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
		list (APPEND OPTIONAL_DLLS "${SNAPPY_DLL_DIR}/${SNAPPY_DLL}")
	endif(SNAPPY_FOUND)
	if (WINSPARKLE_FOUND)
		list (APPEND OPTIONAL_DLLS "${WINSPARKLE_DLL_DIR}/${WINSPARKLE_DLL}")
	endif(WINSPARKLE_FOUND)
	if (ZLIB_FOUND)
		list (APPEND OPTIONAL_DLLS "${ZLIB_DLL_DIR}/${ZLIB_DLL}")
		list (APPEND OPTIONAL_PDBS "${ZLIB_DLL_DIR}/${ZLIB_PDB}")
	endif(ZLIB_FOUND)
	if (BROTLI_FOUND)
		foreach( _dll ${BROTLI_DLLS} )
			list (APPEND OPTIONAL_DLLS "${BROTLI_DLL_DIR}/${_dll}")
		endforeach(_dll)
	endif(BROTLI_FOUND)

	# With libs downloaded to c:/wireshark-win64-libs this currently
	# (early 2018) expands to about 1900 characters.
	if (OPTIONAL_DLLS)
		add_custom_command(TARGET copy_cli_dlls PRE_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy_if_different
				${OPTIONAL_DLLS}
				"${_dll_output_dir}"
			VERBATIM
		)
		install(FILES ${OPTIONAL_DLLS} DESTINATION "${CMAKE_INSTALL_BINDIR}")
	endif(OPTIONAL_DLLS)

	if (OPTIONAL_PDBS)
		add_custom_command(TARGET copy_cli_dlls PRE_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy_if_different
				${OPTIONAL_PDBS}
				"${_dll_output_dir}"
			VERBATIM
		)
	endif(OPTIONAL_PDBS)

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
		set(_pdb_zip "${CMAKE_BINARY_DIR}/Wireshark-pdb-${WIRESHARK_TARGET_PLATFORM}-${VERSION}.zip")
		file(TO_NATIVE_PATH "${_pdb_zip}" _pdb_zip_win)
		add_custom_command(TARGET pdb_zip_package POST_BUILD
			COMMAND ${CMAKE_COMMAND} -E remove -f "${_pdb_zip}"
			COMMAND ${ZIP_EXECUTABLE} a -tzip -mmt=on "${_pdb_zip_win}"
				-bb2
				-r *.pdb *.lib
			WORKING_DIRECTORY "${_dll_output_dir}"
		)
	endif()
endif(WIN32)

# List of extra dependencies for the "copy_data_files" target
set(copy_data_files_depends)

if(WIN32)
	foreach(_install_as_txt_file COPYING NEWS README.md README.windows)
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

foreach(_install_file ${INSTALL_FILES})
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

# Install LUA files in staging directory such that LUA can used when Wireshark
# is ran from the build directory. For install targets, see
# epan/wslua/CMakeLists.txt
if(LUA_FOUND AND ENABLE_LUA)
	set(_lua_files
		"${CMAKE_BINARY_DIR}/epan/wslua/init.lua"
		"${CMAKE_SOURCE_DIR}/epan/wslua/console.lua"
		"${CMAKE_SOURCE_DIR}/epan/wslua/dtd_gen.lua"
	)
	foreach(_lua_file ${_lua_files})
		get_filename_component(_lua_filename "${_lua_file}" NAME)
		list(APPEND copy_data_files_depends
			"${DATAFILE_DIR}/${_lua_filename}")
		add_custom_command(OUTPUT "${DATAFILE_DIR}/${_lua_filename}"
			COMMAND ${CMAKE_COMMAND} -E copy_if_different
				"${_lua_file}"
				"${DATAFILE_DIR}/${_lua_filename}"
			DEPENDS
				wsluaauxiliary
				"${_lua_file}"
		)
	endforeach()
endif(LUA_FOUND AND ENABLE_LUA)
# doc/*.html handled elsewhere.

# Glob patterns relative to the source directory that should be copied to
# ${DATAFILE_DIR} (including directory prefixes)
# TODO shouldn't this use full (relative) paths instead of glob patterns?
set(DATA_FILES_SRC
	"tpncp/tpncp.dat"
	"wimaxasncp/*.dtd"
	"wimaxasncp/*.xml"
)

# Copy all paths from the source tree to the data directory. Directories are
# automatically created if missing as the filename is given.
file(GLOB _data_files RELATIVE "${CMAKE_SOURCE_DIR}" ${DATA_FILES_SRC})
foreach(_data_file ${_data_files})
	add_custom_command(OUTPUT "${DATAFILE_DIR}/${_data_file}"
		COMMAND ${CMAKE_COMMAND} -E copy_if_different
			"${CMAKE_SOURCE_DIR}/${_data_file}"
			"${DATAFILE_DIR}/${_data_file}"
		DEPENDS
			"${CMAKE_SOURCE_DIR}/${_data_file}"
	)
	list(APPEND copy_data_files_depends "${DATAFILE_DIR}/${_data_file}")
endforeach()

file(GLOB _dtds_src_files RELATIVE "${CMAKE_SOURCE_DIR}" "dtds/*.dtd")

set (_dtds_data_files)
foreach(_data_file ${_dtds_src_files})
	list(APPEND _dtds_data_files "${DATAFILE_DIR}/${_data_file}")
endforeach()

add_custom_command(
	OUTPUT ${_dtds_data_files}
	COMMAND ${CMAKE_COMMAND} -E make_directory "${DATAFILE_DIR}/dtds"
	COMMAND ${CMAKE_COMMAND} -E copy_if_different
		${_dtds_src_files}
		"${DATAFILE_DIR}/dtds"
	VERBATIM
	DEPENDS ${_dtds_src_files}
	WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

file(GLOB _diameter_src_files RELATIVE "${CMAKE_SOURCE_DIR}"
	diameter/*.dtd
	diameter/*.xml
)

set (_diameter_data_files)
foreach(_data_file ${_diameter_src_files})
	list(APPEND _diameter_data_files "${DATAFILE_DIR}/${_data_file}")
endforeach()

add_custom_command(
	OUTPUT ${_diameter_data_files}
	COMMAND ${CMAKE_COMMAND} -E make_directory "${DATAFILE_DIR}/diameter"
	COMMAND ${CMAKE_COMMAND} -E copy_if_different
		${_diameter_src_files}
		"${DATAFILE_DIR}/diameter"
	VERBATIM
	DEPENDS ${_diameter_src_files}
	WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

file(GLOB _radius_src_files RELATIVE "${CMAKE_SOURCE_DIR}"
	radius/README.radius_dictionary
	radius/custom.includes
	radius/dictionary
	radius/dictionary.*
)

set (_radius_data_files)
foreach(_data_file ${_radius_src_files})
	list(APPEND _radius_data_files "${DATAFILE_DIR}/${_data_file}")
endforeach()

add_custom_command(
	OUTPUT ${_radius_data_files}
	COMMAND ${CMAKE_COMMAND} -E make_directory "${DATAFILE_DIR}/radius"
	COMMAND ${CMAKE_COMMAND} -E copy_if_different
		${_radius_src_files}
		"${DATAFILE_DIR}/radius"
	VERBATIM
	DEPENDS ${_radius_src_files}
	WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

file(GLOB _profiles_src_files RELATIVE "${CMAKE_SOURCE_DIR}" profiles/*/*)
set (_profiles_data_files)
foreach(_data_file ${_profiles_src_files})
	list(APPEND _profiles_data_files "${DATAFILE_DIR}/${_data_file}")
endforeach()

add_custom_command(
	OUTPUT ${_profiles_data_files}
	COMMAND ${CMAKE_COMMAND} -E copy_directory
		"${CMAKE_SOURCE_DIR}/profiles" "${DATAFILE_DIR}/profiles"
)

list(APPEND copy_data_files_depends
	${_dtds_data_files}
	${_diameter_data_files}
	${_radius_data_files}
	${_profiles_data_files}
)

# Copy files including ${INSTALL_FILES} and ${INSTALL_DIRS} to ${DATAFILE_DIR}
add_custom_target(copy_data_files ALL DEPENDS ${copy_data_files_depends} )
set_target_properties(copy_data_files PROPERTIES FOLDER "Copy Tasks")


# Shared code, build object files once for all users.
add_library(version_info OBJECT version_info.c)
target_include_directories(version_info SYSTEM PRIVATE ${VERSION_INFO_INCLUDE_DIRS})
if(NOT VCSVERSION_OVERRIDE)
	add_dependencies(version_info version)
endif()
# sources common for wireshark, tshark, rawshark and sharkd
add_library(shark_common OBJECT
	cfile.c
	extcap.c
	extcap_parser.c
	file_packet_provider.c
	frame_tvbuff.c
	sync_pipe_write.c
)
add_library(cli_main OBJECT cli_main.c)
add_library(capture_opts OBJECT capture_opts.c)
target_include_directories(capture_opts SYSTEM PRIVATE ${PCAP_INCLUDE_DIRS})
set_target_properties(version_info shark_common cli_main capture_opts
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)


if(BUILD_wireshark AND QT_FOUND)
	set(WIRESHARK_SRC
		file.c
		fileset.c
		${PLATFORM_UI_SRC}
	)
	set(wireshark_FILES
		$<TARGET_OBJECTS:capture_opts>
		$<TARGET_OBJECTS:qtui>
		$<TARGET_OBJECTS:shark_common>
		$<TARGET_OBJECTS:version_info>
		${WIRESHARK_SRC}
		${PLATFORM_UI_RC_FILES}
	)
	set_executable_resources(wireshark "Wireshark" UNIQUE_RC)
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

	# Create our Frameworks directory
	file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/run/${CMAKE_CFG_INTDIR}/Wireshark.app/Contents/Frameworks")

	# Add files to the app bundle
	# Wireshark.app/Contents
	file(WRITE ${CMAKE_BINARY_DIR}/packaging/macosx/PkgInfo "APPLWshk\n")
	set(BUNDLE_CONTENTS_FILES
		${CMAKE_BINARY_DIR}/packaging/macosx/PkgInfo
	)
	set_source_files_properties(${BUNDLE_CONTENTS_FILES} PROPERTIES
		MACOSX_PACKAGE_LOCATION .
	)

	# Wireshark.app/Contents/Resources
	set(BUNDLE_RESOURCE_FILES
		${CMAKE_SOURCE_DIR}/packaging/macosx/Wireshark.icns
		${CMAKE_SOURCE_DIR}/packaging/macosx/Wiresharkdoc.icns
	)
	set_source_files_properties(${BUNDLE_RESOURCE_FILES} PROPERTIES
		MACOSX_PACKAGE_LOCATION Resources
	)

	# Wireshark.app/Contents/Resources/share/man/man1
	set_source_files_properties(${BUNDLE_RESOURCE_SHARE_MAN1_FILES} PROPERTIES
		MACOSX_PACKAGE_LOCATION Resources/share/man/man1
		GENERATED 1
	)

	# Wireshark.app/Contents/Resources/share/man/man4
	set_source_files_properties(${BUNDLE_RESOURCE_SHARE_MAN4_FILES} PROPERTIES
		MACOSX_PACKAGE_LOCATION Resources/share/man/man4
		GENERATED 1
	)

	# INSTALL_FILES and INSTALL_DIRS are handled by copy_data_files

	set(EXTRA_BUNDLE_FILES
		${BUNDLE_CONTENTS_FILES}
		${BUNDLE_RESOURCE_FILES}
		${BUNDLE_RESOURCE_SHARE_MAN1_FILES}
		${BUNDLE_RESOURCE_SHARE_MAN4_FILES}
	)
else()
	set(EXTRA_BUNDLE_FILES)
endif()

if(BUILD_wireshark AND QT_FOUND)
	set(wireshark_LIBS
		ui
		capchild
		caputils
		wiretap
		epan
		${QT_LIBRARIES}
		${VERSION_INFO_LIBS}
		${APPLE_APPLICATION_SERVICES_LIBRARY}
		${APPLE_APPKIT_LIBRARY}
		${APPLE_CORE_FOUNDATION_LIBRARY}
		${APPLE_SYSTEM_CONFIGURATION_LIBRARY}
		${SPARKLE_LIBRARIES}
		${WIN_WS2_32_LIBRARY}
		${WIN_VERSION_LIBRARY}
		${WINSPARKLE_LIBRARIES}
		$<$<BOOL:${WIN32}>:UxTheme.lib>
		${SPEEXDSP_LIBRARIES}
		${MINIZIP_LIBRARIES}
	)

	add_executable(wireshark WIN32 MACOSX_BUNDLE ${wireshark_FILES} ${EXTRA_BUNDLE_FILES})
	if(WIN32)
		set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT wireshark)
	endif()
	set(PROGLIST ${PROGLIST} wireshark)
	set_target_properties(wireshark PROPERTIES
		LINK_FLAGS "${WS_LINK_FLAGS}"
		FOLDER "Executables"
		INSTALL_RPATH "${EXECUTABLE_INSTALL_RPATH}"
	)
	if(ENABLE_APPLICATION_BUNDLE OR WIN32)
		set_target_properties(wireshark PROPERTIES OUTPUT_NAME Wireshark)
	endif()

	if(ENABLE_APPLICATION_BUNDLE)
		add_dependencies(wireshark manpages)
		set_target_properties(
			wireshark PROPERTIES
				MACOSX_BUNDLE_INFO_PLIST ${CMAKE_BINARY_DIR}/packaging/macosx/Info.plist
		)
		if(CMAKE_CFG_INTDIR STREQUAL ".")
			# Add a wrapper script which opens the bundle. This adds
			# convenience but makes debugging more difficult.
			# It is not created if using Xcode
			# XXX Running run/Wireshark.app/Contents/MacOS/Wireshark works
			# fine for me (Gerald) here on Mojave. Can we just make this a
			# symlink?
			file(REMOVE ${CMAKE_BINARY_DIR}/run/wireshark)
			file(WRITE ${CMAKE_BINARY_DIR}/run/wireshark "#!/bin/sh\n")
			file(APPEND ${CMAKE_BINARY_DIR}/run/wireshark "# Generated by ${CMAKE_CURRENT_LIST_FILE}\n")
			file(APPEND ${CMAKE_BINARY_DIR}/run/wireshark "# Wrapper script which should work around the issue described at\n")
			file(APPEND ${CMAKE_BINARY_DIR}/run/wireshark "# https://stackoverflow.com/questions/25318524/what-exactly-should-i-pass-to-nsapp-activateignoringotherapps-to-get-my-appl\n")
			file(APPEND ${CMAKE_BINARY_DIR}/run/wireshark "exec ${CMAKE_BINARY_DIR}/run/Wireshark.app/Contents/MacOS/Wireshark \"\$\@\"\n")
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
		add_custom_command(TARGET copy_qt_dlls
			POST_BUILD
			COMMAND set "PATH=${QT_BIN_PATH};%PATH%"
			COMMAND "${QT_WINDEPLOYQT_EXECUTABLE}"
				$<$<CONFIG:Debug>:--debug>
				$<$<NOT:$<CONFIG:Debug>>:--release>
				--no-compiler-runtime
				--verbose 10
				${QT_WINDEPLOYQT_EXTRA_OPTS}
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

# Common properties for CLI executables
macro(set_extra_executable_properties _executable _folder)
	set_target_properties(${_executable} PROPERTIES
		LINK_FLAGS "${WILDCARD_OBJ} ${WS_LINK_FLAGS}"
		FOLDER ${_folder}
		INSTALL_RPATH "${EXECUTABLE_INSTALL_RPATH}"
	)

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
		${VERSION_INFO_LIBS}
		${APPLE_CORE_FOUNDATION_LIBRARY}
		${APPLE_SYSTEM_CONFIGURATION_LIBRARY}
		${WIN_WS2_32_LIBRARY}
		${M_LIBRARIES}
	)
	set(tshark_FILES
		$<TARGET_OBJECTS:capture_opts>
		$<TARGET_OBJECTS:cli_main>
		$<TARGET_OBJECTS:shark_common>
		$<TARGET_OBJECTS:version_info>
		tshark-tap-register.c
		tshark.c
		${TSHARK_TAP_SRC}
	)

	set_executable_resources(tshark "TShark" UNIQUE_RC)
	add_executable(tshark ${tshark_FILES})
	set_extra_executable_properties(tshark "Executables")
	target_link_libraries(tshark ${tshark_LIBS})
	install(TARGETS tshark RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_tfshark)
	set(tfshark_LIBS
		m
		ui
		wiretap
		epan
		${VERSION_INFO_LIBS}
		${APPLE_CORE_FOUNDATION_LIBRARY}
		${APPLE_SYSTEM_CONFIGURATION_LIBRARY}
	)
	set(tfshark_FILES
		$<TARGET_OBJECTS:cli_main>
		$<TARGET_OBJECTS:shark_common>
		$<TARGET_OBJECTS:version_info>
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
		${VERSION_INFO_LIBS}
		${APPLE_CORE_FOUNDATION_LIBRARY}
		${APPLE_SYSTEM_CONFIGURATION_LIBRARY}
		${WIN_WS2_32_LIBRARY}
	)
	set(rawshark_FILES
		$<TARGET_OBJECTS:cli_main>
		$<TARGET_OBJECTS:shark_common>
		$<TARGET_OBJECTS:version_info>
		rawshark.c
	)
	set_executable_resources(rawshark "Rawshark")
	add_executable(rawshark ${rawshark_FILES})
	set_extra_executable_properties(rawshark "Executables")
	target_link_libraries(rawshark ${rawshark_LIBS})
	install(TARGETS rawshark RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_sharkd)
	set(sharkd_LIBS
		ui
		wiretap
		epan
		${VERSION_INFO_LIBS}
		${APPLE_CORE_FOUNDATION_LIBRARY}
		${APPLE_SYSTEM_CONFIGURATION_LIBRARY}
		${WIN_WS2_32_LIBRARY}
		${SPEEXDSP_LIBRARIES}
		${M_LIBRARIES}
	)
	set(sharkd_FILES
		#
		# XXX - currently doesn't work on Windows if it uses
		# $<TARGET_OBJECTS:cli_main> and has real_main().
		#
		$<TARGET_OBJECTS:shark_common>
		$<TARGET_OBJECTS:version_info>
		sharkd.c
		sharkd_daemon.c
		sharkd_session.c
	)
	set_executable_resources(sharkd "SharkD")
	add_executable(sharkd ${sharkd_FILES})
	set_extra_executable_properties(sharkd "Executables")
	target_link_libraries(sharkd ${sharkd_LIBS})
	target_include_directories(sharkd SYSTEM
		PUBLIC
			${SPEEXDSP_INCLUDE_DIRS}
	)

	install(TARGETS sharkd RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_dftest)
	set(dftest_LIBS
		ui
		wiretap
		epan
		${VERSION_INFO_LIBS}
	)
	set(dftest_FILES
		dftest.c
	)
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
		${M_LIBRARIES}
		${CARES_LIBRARIES}
		${ZLIB_LIBRARIES}
	)
	set(randpkt_FILES
		$<TARGET_OBJECTS:cli_main>
		$<TARGET_OBJECTS:version_info>
		randpkt.c
	)
	add_executable(randpkt ${randpkt_FILES})
	set_extra_executable_properties(randpkt "Executables")
	target_link_libraries(randpkt ${randpkt_LIBS})
	install(TARGETS randpkt RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_fuzzshark OR ENABLE_FUZZER OR OSS_FUZZ)
	add_subdirectory(fuzz)
endif()

if(BUILD_text2pcap)
	set(text2pcap_LIBS
		writecap
		wsutil
		${M_LIBRARIES}
		${ZLIB_LIBRARIES}
	)
	set(text2pcap_FILES
		$<TARGET_OBJECTS:cli_main>
		$<TARGET_OBJECTS:version_info>
		text2pcap.c
	)
	add_lex_files(text2pcap_LEX_FILES text2pcap_FILES
		text2pcap-scanner.l
	)
	set_executable_resources(text2pcap "Text2pcap"
		COPYRIGHT_INFO "2001 Ashok Narayanan <ashokn@cisco.com>")
	add_executable(text2pcap ${text2pcap_FILES})
	set_extra_executable_properties(text2pcap "Executables")
	target_link_libraries(text2pcap ${text2pcap_LIBS})
	install(TARGETS text2pcap RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_mergecap)
	set(mergecap_LIBS
		ui
		wiretap
		${ZLIB_LIBRARIES}
		${CMAKE_DL_LIBS}
	)
	set(mergecap_FILES
		$<TARGET_OBJECTS:cli_main>
		$<TARGET_OBJECTS:version_info>
		mergecap.c
	)
	set_executable_resources(mergecap "Mergecap")
	add_executable(mergecap ${mergecap_FILES})
	set_extra_executable_properties(mergecap "Executables")
	target_link_libraries(mergecap ${mergecap_LIBS})
	install(TARGETS mergecap RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_reordercap)
	set(reordercap_LIBS
		ui
		wiretap
		${ZLIB_LIBRARIES}
		${CMAKE_DL_LIBS}
	)
	set(reordercap_FILES
		$<TARGET_OBJECTS:cli_main>
		$<TARGET_OBJECTS:version_info>
		reordercap.c
	)
	set_executable_resources(reordercap "Reordercap")
	add_executable(reordercap ${reordercap_FILES})
	set_extra_executable_properties(reordercap "Executables")
	target_link_libraries(reordercap ${reordercap_LIBS})
	install(TARGETS reordercap RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_capinfos)
	set(capinfos_LIBS
		ui
		wiretap
		wsutil
		${ZLIB_LIBRARIES}
		${GCRYPT_LIBRARIES}
		${CMAKE_DL_LIBS}
	)
	set(capinfos_FILES
		$<TARGET_OBJECTS:cli_main>
		$<TARGET_OBJECTS:version_info>
		capinfos.c
	)
	set_executable_resources(capinfos "Capinfos")
	add_executable(capinfos ${capinfos_FILES})
	set_extra_executable_properties(capinfos "Executables")
	target_link_libraries(capinfos ${capinfos_LIBS})
	install(TARGETS capinfos RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_captype)
	set(captype_LIBS
		ui
		wiretap
		wsutil
		${ZLIB_LIBRARIES}
		${CMAKE_DL_LIBS}
	)
	set(captype_FILES
		$<TARGET_OBJECTS:cli_main>
		$<TARGET_OBJECTS:version_info>
		captype.c
	)
	set_executable_resources(captype "Captype")
	add_executable(captype ${captype_FILES})
	set_extra_executable_properties(captype "Executables")
	target_link_libraries(captype ${captype_LIBS})
	install(TARGETS captype RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_editcap)
	set(editcap_LIBS
		ui
		wiretap
		${ZLIB_LIBRARIES}
		${GCRYPT_LIBRARIES}
		${CMAKE_DL_LIBS}
	)
	set(editcap_FILES
		$<TARGET_OBJECTS:cli_main>
		$<TARGET_OBJECTS:version_info>
		editcap.c
	)
	set_executable_resources(editcap "Editcap")
	add_executable(editcap ${editcap_FILES})
	set_extra_executable_properties(editcap "Executables")
	target_link_libraries(editcap ${editcap_LIBS})
	install(TARGETS editcap RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_dumpcap AND PCAP_FOUND)
	set(dumpcap_LIBS
		writecap
		wsutil
		caputils
		ui
		pcap::pcap
		${CAP_LIBRARIES}
		${GLIB2_LIBRARIES}
		${GTHREAD2_LIBRARIES}
		${ZLIB_LIBRARIES}
		${APPLE_CORE_FOUNDATION_LIBRARY}
		${APPLE_SYSTEM_CONFIGURATION_LIBRARY}
		${WIN_WS2_32_LIBRARY}
	)
	set(dumpcap_FILES
		$<TARGET_OBJECTS:capture_opts>
		$<TARGET_OBJECTS:cli_main>
		$<TARGET_OBJECTS:version_info>
		dumpcap.c
		ringbuffer.c
		sync_pipe_write.c
	)
	set_executable_resources(dumpcap "Dumpcap" UNIQUE_RC)
	add_executable(dumpcap ${dumpcap_FILES})
	set_extra_executable_properties(dumpcap "Executables")
	target_link_libraries(dumpcap ${dumpcap_LIBS})
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
elseif(BUILD_dumpcap AND ENABLE_PCAP)
	message(WARNING "Dumpcap was requested but libpcap dependency is not available. "
		"Wireshark will be built without packet capture capability.")
endif()

# We have two idl2wrs utilities: this and the CORBA version in tools.
# We probably shouldn't do that.
if(BUILD_dcerpcidl2wrs)
	set(idl2wrs_LIBS
		${GLIB2_LIBRARIES}
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

if (WIN32)
	find_package( MSVC_REDIST )

	# Must come after executable targets are defined.
	find_package( NSIS )

	if(MAKENSIS_EXECUTABLE)
		add_subdirectory( packaging/nsis EXCLUDE_FROM_ALL )
		ADD_NSIS_UNINSTALLER_TARGET()
		ADD_NSIS_PACKAGE_TARGET()
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
	)
	set(mmdbresolve_FILES
		mmdbresolve.c
	)
	add_executable(mmdbresolve ${mmdbresolve_FILES})
	set_extra_executable_properties(mmdbresolve "Executables")
	target_link_libraries(mmdbresolve ${mmdbresolve_LIBS})
	target_include_directories(mmdbresolve PUBLIC ${MAXMINDDB_INCLUDE_DIRS})
	target_compile_definitions(mmdbresolve PUBLIC ${MAXMINDDB_DEFINITIONS})
	install(TARGETS mmdbresolve RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(ENABLE_APPLICATION_BUNDLE)
	# --preserve-xattr is undocumented but ensures that we install
	# a signed ChmodBPF script.
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
			--version 1.1
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
			--version 1.1
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
			--version 1.1
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
			--version 1.1
			--distribution "${CMAKE_SOURCE_DIR}/packaging/macosx/ChmodBPF/uninstall-distribution.xml"
			--package-path "${CMAKE_BINARY_DIR}"
			${uninstall_chmodbpf_pkg}
		DEPENDS
			"${CMAKE_SOURCE_DIR}/packaging/macosx/ChmodBPF/uninstall-distribution.xml"
			${uninstall_chmodbpf_component_pkg}
	)

	add_custom_target(chmodbpf DEPENDS ${install_chmodbpf_pkg} ${uninstall_chmodbpf_pkg})

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
			--version 1.0
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
			--version 1.0
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
			--version 1.0
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
			--version 1.0
			--distribution "${CMAKE_SOURCE_DIR}/packaging/macosx/path_helper/uninstall-distribution.xml"
			--package-path "${CMAKE_BINARY_DIR}"
			${uninstall_path_helper_pkg}
		DEPENDS
			${CMAKE_SOURCE_DIR}/packaging/macosx/path_helper/uninstall-distribution.xml
			${uninstall_path_helper_component_pkg}
	)

	add_custom_target(path_helper DEPENDS ${install_path_helper_pkg} ${uninstall_path_helper_pkg})

	add_custom_target(app_bundle)
	set_target_properties(app_bundle PROPERTIES FOLDER "Copy Tasks")
	add_custom_command(TARGET app_bundle
		POST_BUILD
		COMMAND "${CMAKE_BINARY_DIR}/packaging/macosx/osx-app.sh"
		WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/run"
	)
	add_dependencies(app_bundle ${PROGLIST} chmodbpf path_helper)

	add_custom_target(dmg_package_prep DEPENDS app_bundle)

	set(_read_me_first "packaging/macosx/Read me first.html")
	ADD_CUSTOM_COMMAND(
	OUTPUT
		${_read_me_first}
	COMMAND ${ASCIIDOCTOR_EXECUTABLE}
		--backend html
		--out-file ${_read_me_first}
		--attribute include-dir=${CMAKE_SOURCE_DIR}/docbook
		--attribute min-macos-version=${MIN_MACOS_VERSION}
		${CMAKE_CURRENT_SOURCE_DIR}/packaging/macosx/Read_me_first.adoc
	DEPENDS
		${CMAKE_CURRENT_SOURCE_DIR}/packaging/macosx/Read_me_first.adoc
	)
	add_custom_target(read_me_first_html DEPENDS ${_read_me_first} )
	add_dependencies(dmg_package_prep read_me_first_html)

	ADD_CUSTOM_TARGET( dmg_package
		COMMAND bash -x ${CMAKE_BINARY_DIR}/packaging/macosx/osx-dmg.sh
		# Unlike nsis_package_prep + nsis_package, we can add a direct
		# dependency here.
		DEPENDS dmg_package_prep
		# We create Wireshark.app in "run". Do our work there.
		WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/run
	)

endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	find_program(RPMBUILD_EXECUTABLE rpmbuild)
	find_program(DPKG_BUILDPACKAGE_EXECUTABLE dpkg-buildpackage)
	find_program(GIT_EXECUTABLE git)
	# Should we add appimaged's monitored directories
	# as HINTS?
	# https://github.com/AppImage/appimaged
	find_program(LINUXDEPLOYQT_EXECUTABLE linuxdeployqt)
	find_program(APPIMAGETOOL_EXECUTABLE appimagetool)
endif()


string(REPLACE "-" "_" RPM_VERSION "${VERSION}")
configure_file(packaging/rpm/wireshark.spec.in ${CMAKE_BINARY_DIR}/packaging/rpm/SPECS/wireshark.spec)
if(RPMBUILD_EXECUTABLE)
	foreach(_rpm_dir BUILD RPMS SOURCES SPECS SRPMS)
		file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/packaging/rpm/${_rpm_dir}")
	endforeach()

	set(_rpmbuild_with_args)
	if(CMAKE_GENERATOR STREQUAL "Ninja")
		list(APPEND _rpmbuild_with_args --with ninja)
	endif()
	if(CCACHE_EXECUTABLE)
		list(APPEND _rpmbuild_with_args --with ccache)
	endif()
	if(NOT BUILD_wireshark)
		list(APPEND _rpmbuild_with_args --without qt5)
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
	if (CARES_FOUND)
		list(APPEND _rpmbuild_with_args --with c_ares)
	endif()
	if (SPANDSP_FOUND)
		list(APPEND _rpmbuild_with_args --with spandsp)
	endif()
	if (BCG729_FOUND)
		list(APPEND _rpmbuild_with_args --with bcg729)
	endif()
	if (ILBC_FOUND)
		list(APPEND _rpmbuild_with_args --with ilbc)
	endif()
	if (LIBXML2_FOUND)
		list(APPEND _rpmbuild_with_args --with libxml2)
	endif()
	if (NGHTTP2_FOUND)
		list(APPEND _rpmbuild_with_args --with nghttp2)
	endif()
	if (SYSTEMD_FOUND)
		list(APPEND _rpmbuild_with_args --with sdjournal)
	endif()
	if (BROTLI_FOUND)
		list(APPEND _rpmbuild_with_args --with brotli)
	endif()

	execute_process(
		COMMAND ${PERL_EXECUTABLE}
			${CMAKE_SOURCE_DIR}/tools/make-version.pl
			${CMAKE_SOURCE_DIR}
	)

	# XXX Replace with the "dist" target?
	set(_export_tarball "${PROJECT_NAME}-${VERSION}.tar.xz")
	add_custom_command(
		OUTPUT "${CMAKE_BINARY_DIR}/packaging/rpm/SOURCES/${_export_tarball}"
		COMMAND ${CMAKE_BINARY_DIR}/packaging/source/git-export-release.sh
			-d "${CMAKE_BINARY_DIR}/packaging/rpm/SOURCES"
			"${VERSION}"
		WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
	)
	add_custom_target(rpm-package
		COMMAND ${RPMBUILD_EXECUTABLE}
			--define "_topdir ${CMAKE_BINARY_DIR}/packaging/rpm"
			--define "_prefix ${CMAKE_INSTALL_PREFIX}"
			${_rpmbuild_with_args}
			-v
			-ba SPECS/wireshark.spec
		DEPENDS "${CMAKE_BINARY_DIR}/packaging/rpm/SOURCES/${_export_tarball}"
		WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/packaging/rpm"
		COMMENT "Create a tarball from the current git commit."
	)
endif()

if(DPKG_BUILDPACKAGE_EXECUTABLE)
	add_custom_target(deb-package
		COMMAND ${DPKG_BUILDPACKAGE_EXECUTABLE} -us -uc
		WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
	)
endif()

if(LINUXDEPLOYQT_EXECUTABLE AND APPIMAGETOOL_EXECUTABLE)
	# The documentation at https://github.com/probonopd/linuxdeployqt
	# says that you need to set CMAKE_BUILD_TYPE=Release and
	# CMAKE_INSTALL_PREFIX=/usr. I (gcc) also had to set
	# CMAKE_INSTALL_LIBDIR=/usr/lib.
	if (CMAKE_BUILD_TYPE STREQUAL "Release" AND CMAKE_INSTALL_PREFIX STREQUAL "/usr" AND CMAKE_INSTALL_LIBDIR STREQUAL "/usr/lib" )
		add_custom_target(appimage-prerequisites)
		add_dependencies(appimage-prerequisites ${PROGLIST})
	else()
		add_custom_target(appimage-prerequisites
			COMMAND echo "CMAKE_BUILD_TYPE isn't Release or CMAKE_INSTALL_PREFIX isn't /usr or CMAKE_INSTALL_LIBDIR isn't /usr/lib."
			COMMAND false
		)
	endif()
	set (_ai_appdir "${CMAKE_BINARY_DIR}/packaging/appimage/appdir")
	add_custom_target(appimage-appdir
		COMMAND ${CMAKE_COMMAND} -E make_directory "${_ai_appdir}"
		COMMAND env DESTDIR=${_ai_appdir}
			${CMAKE_COMMAND} --build . --target install
		DEPENDS appimage-prerequisites
	)
	set(_exe_args)
	foreach(_prog ${PROGLIST})
		# XXX Is this the correct path?
		list(APPEND _exe_args "-executable=${_ai_appdir}/usr/bin/${_prog}")
	endforeach()
	# linuxdeployqt currently clobbers AppRun:
	# https://github.com/probonopd/linuxdeployqt/issues/159
	# When that's fixed we will no longer need appimagetool. Until
	# then, we need to prep and package in two steps:
	# https://github.com/probonopd/linuxdeployqt/wiki/Custom-wrapper-script-instead-of-AppRun
	add_custom_target(appimage-prep
		COMMAND ${LINUXDEPLOYQT_EXECUTABLE}
			"${_ai_appdir}/usr/share/applications/wireshark.desktop"
			${_exe_args}
		COMMAND rm -f "${_ai_appdir}/AppRun"
		COMMAND install
			"${CMAKE_SOURCE_DIR}/packaging/appimage/AppRun"
			"${_ai_appdir}/AppRun"
		DEPENDS appimage-appdir
	)
	add_custom_target(appimage
		COMMAND env VERSION=${PROJECT_VERSION} ${APPIMAGETOOL_EXECUTABLE} appdir
		WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/packaging/appimage"
		DEPENDS appimage-prep
	)
endif()

set(CLEAN_C_FILES
	${dumpcap_FILES}
	${wireshark_FILES}
	${tshark_FILES}
	${rawshark_FILES}
	${dftest_FILES}
	${randpkt_FILES}
	${randpktdump_FILES}
	${udpdump_FILES}
	${text2pcap_FILES}
	${mergecap_FILES}
	${capinfos_FILES}
	${captype_FILES}
	${editcap_FILES}
	${idl2wrs_FILES}
	${mmdbresolve_FILES}
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
		${CMAKE_INSTALL_DATADIR}
)

set(SHARK_PUBLIC_HEADERS
	cfile.h
	cli_main.h
	file.h
	globals.h
	log.h
	ws_attributes.h
	ws_compiler_tests.h
	ws_diag_control.h
	ws_symbol_export.h
	version_info.h
	${CMAKE_BINARY_DIR}/ws_version.h
)

install(FILES ${SHARK_PUBLIC_HEADERS}
	DESTINATION ${PROJECT_INSTALL_INCLUDEDIR}
)

# Install icons and other desktop files for Freedesktop.org-compliant desktops.
if((BUILD_wireshark AND QT_FOUND) AND NOT (WIN32 OR APPLE))
	install(FILES wireshark-mime-package.xml
		DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/mime/packages"
		RENAME wireshark.xml
	)
	install(FILES wireshark.appdata.xml
		DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/appdata"
	)
	if(BUILD_wireshark AND QT_FOUND)
		install(FILES wireshark.desktop
			DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/applications")
	endif()
	foreach(size 16 24 32 48 64 128 256)
		install(FILES image/wsicon${size}.png
			DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/icons/hicolor/${size}x${size}/apps"
			RENAME wireshark.png)
		install(FILES image/WiresharkDoc-${size}.png
			DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/icons/hicolor/${size}x${size}/mimetypes"
			RENAME application-wireshark-doc.png)
	endforeach()
	install(FILES image/wsicon.svg
		DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/icons/hicolor/scalable/apps"
		RENAME wireshark.svg)
endif()

install(
	FILES
		"${CMAKE_BINARY_DIR}/wireshark.pc"
	DESTINATION
		${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

install(
	DIRECTORY
		${INSTALL_DIRS}
	DESTINATION
		${CMAKE_INSTALL_DATADIR}
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

if(WIN32)
	# Note: CMake export mechanism misbehaves with a '.' in the
	# path (incorrect relative path computation).
	set(WIRESHARK_INSTALL_CMAKEDIR "cmake")
else()
	set(WIRESHARK_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/${PROJECT_NAME}/cmake")
endif()

install(
	FILES
		${CMAKE_MODULE_PATH}/FindGLIB2.cmake
		${CMAKE_MODULE_PATH}/FindWSLibrary.cmake
		${CMAKE_MODULE_PATH}/FindWSWinLibs.cmake
		${CMAKE_MODULE_PATH}/UseAsn2Wrs.cmake
		${CMAKE_MODULE_PATH}/LocatePythonModule.cmake
		${CMAKE_MODULE_PATH}/UseMakePluginReg.cmake
	DESTINATION
		${WIRESHARK_INSTALL_CMAKEDIR}
)

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
)

install(EXPORT WiresharkTargets
	DESTINATION ${WIRESHARK_INSTALL_CMAKEDIR}
)

if (DOXYGEN_EXECUTABLE)
	# API reference
	# We don't have a good way of tracking dependencies, so we simply
	# recreate the whole thing from scratch each time.
	add_custom_target(wsar_html
		COMMAND ${CMAKE_COMMAND} -E remove_directory wsar_html
		COMMAND ${DOXYGEN_EXECUTABLE} doxygen.cfg
	)

	if (WIN32)
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
		FOLDER "Docs"
		EXCLUDE_FROM_DEFAULT_BUILD True
	)
endif(DOXYGEN_EXECUTABLE)

add_custom_target(test-programs
	DEPENDS exntest
		oids_test
		reassemble_test
		tvbtest
		wmem_test
	COMMENT "Building unit test programs and wrapper"
)
set_target_properties(test-programs PROPERTIES
	FOLDER "Tests"
	EXCLUDE_FROM_DEFAULT_BUILD True
)

# Test suites
enable_testing()
# We could try to build this list dynamically, but given that we tend to
# go years between adding suites just run
#     test/test.py --list-groups | sort
# and paste the output here.
set(_test_group_list
	suite_capture
	suite_clopts
	suite_decryption
	suite_dfilter.group_bytes_ether
	suite_dfilter.group_bytes_ipv6
	suite_dfilter.group_bytes_type
	suite_dfilter.group_double
	suite_dfilter.group_dfunction_string
	suite_dfilter.group_integer
	suite_dfilter.group_integer_1byte
	suite_dfilter.group_ipv4
	suite_dfilter.group_membership
	suite_dfilter.group_range_method
	suite_dfilter.group_scanner
	suite_dfilter.group_string_type
	suite_dfilter.group_stringz
	suite_dfilter.group_time_relative
	suite_dfilter.group_time_type
	suite_dfilter.group_tvb
	suite_dfilter.group_uint64
	suite_dissection
	suite_dissectors.group_asterix
	suite_extcaps
	suite_fileformats
	suite_follow
	suite_io
	suite_mergecap
	suite_nameres
	suite_outputformats
	suite_release
	suite_text2pcap
	suite_sharkd
	suite_unittests
	suite_wslua
)

# We don't currently handle spaces in arguments. On Windows this
# means that you will probably have to pass in an interface index
# instead of a name.
set(TEST_EXTRA_ARGS "" CACHE STRING "Extra arguments to pass to test/test.py")
separate_arguments(TEST_EXTRA_ARGS)

foreach(_group_name ${_test_group_list})
	add_test(
		NAME ${_group_name}
		COMMAND ${CMAKE_COMMAND} -E env PYTHONIOENCODING=UTF-8
			${PYTHON_EXECUTABLE} ${CMAKE_SOURCE_DIR}/test/test.py
			--verbose
			--program-path ${WS_PROGRAM_PATH}
			${TEST_EXTRA_ARGS}
			${_group_name}
		)
	set_tests_properties(${_group_name} PROPERTIES TIMEOUT 600)
endforeach()

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
		COMMAND ${PERL_EXECUTABLE} tools/generate_authors.pl AUTHORS.src > AUTHORS
		WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
	)
else (GIT_EXECUTABLE)
	add_custom_target( gen-authors COMMAND ${CMAKE_COMMAND} -E echo "Git not found." )
endif (GIT_EXECUTABLE)
set_target_properties(gen-authors PROPERTIES FOLDER "Docs")

if (WIN32)
	file (TO_NATIVE_PATH ${CMAKE_SOURCE_DIR}/tools/Get-HardenFlags.ps1 _win_harden_flags)
	add_custom_target(hardening-check
		COMMAND ${POWERSHELL_COMMAND} "${_win_harden_flags}" "${_dll_output_dir_win}"
		DEPENDS ${PROGLIST}
		COMMENT "Checking binaries for security features"
	)
	set_target_properties(hardening-check PROPERTIES FOLDER "Tests")
else ()
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
	  -build
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
	add_custom_command(TARGET shellcheck POST_BUILD
		COMMAND shellcheck --external-sources
			image/stock_icons/svg-to-png.sh
			packaging/appimage/AppRun
			packaging/macosx/osx-app.sh.in
			packaging/macosx/osx-dmg.sh.in
			packaging/source/git-export-release.sh.in
			tools/compress-pngs.sh
			tools/debian-setup.sh
			tools/fuzz-test.sh
			tools/gen-bugnote
			tools/pre-commit
			tools/randpkt-test.sh
			tools/release-update-debian-soversions.sh
			tools/test-captures.sh
			tools/update-tx
			tools/valgrind-wireshark.sh
		WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
	)
endif()

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
