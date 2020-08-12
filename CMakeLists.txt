# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

project(Wireshark C CXX)

# Updated by make-version.pl
set(GIT_REVISION 0)
set(PROJECT_MAJOR_VERSION 2)
set(PROJECT_MINOR_VERSION 6)
set(PROJECT_PATCH_VERSION 20)
set(PROJECT_BUILD_VERSION ${GIT_REVISION})
set(PROJECT_VERSION_EXTENSION "")
set(PROJECT_RELEASE_VERSION "${PROJECT_MAJOR_VERSION}.${PROJECT_MINOR_VERSION}")

if(DEFINED ENV{WIRESHARK_VERSION_EXTRA})
	set(PROJECT_VERSION_EXTENSION "$ENV{WIRESHARK_VERSION_EXTRA}")
endif()

set(PROJECT_VERSION "${PROJECT_MAJOR_VERSION}.${PROJECT_MINOR_VERSION}.${PROJECT_PATCH_VERSION}${PROJECT_VERSION_EXTENSION}")

# packaging information
if(WIN32)
        set(CPACK_PACKAGE_NAME Wireshark)
else()
        set(CPACK_PACKAGE_NAME wireshark)
endif()

set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")

message(STATUS "Generating build using CMake ${CMAKE_VERSION}")
if(WIN32)
	# Needed for GREATER_EQUAL operator
	cmake_minimum_required(VERSION 3.7)
else()
	cmake_minimum_required(VERSION 2.8.12)
endif()

#Where to find local cmake scripts
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules)

# Set old behaviour for MACOSX_RPATH (since 3.0)
if (POLICY CMP0042)
	cmake_policy(SET CMP0042 OLD)
endif()

# Set old behaviour for variable quoting (since 3.1)
if (POLICY CMP0054)
	cmake_policy(SET CMP0054 OLD)
endif()

# If our target platform is enforced by our generator, set
# WIRESHARK_TARGET_PLATFORM accordingly. Otherwise use
# %WIRESHARK_TARGET_PLATFORM%.

if(WIN32)
	find_package(PowerShell REQUIRED)

	if(${CMAKE_CL_64} OR "${CMAKE_GENERATOR}" MATCHES "Win64")
		set(WIRESHARK_TARGET_PLATFORM win64)
	elseif("${CMAKE_GENERATOR}" MATCHES "Visual Studio")
		set(WIRESHARK_TARGET_PLATFORM win32)
	else()
		set(WIRESHARK_TARGET_PLATFORM $ENV{WIRESHARK_TARGET_PLATFORM})
	endif()

	if ("${WIRESHARK_TARGET_PLATFORM}" MATCHES "win64")
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
		set( _PROJECT_LIB_DIR "${_WS_BASE_DIR}/wireshark-${WIRESHARK_TARGET_PLATFORM}-libs-2.6" )
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
	if (${_win_setup_failed})
		message(FATAL_ERROR "Windows setup (win-setup.ps1) failed.")
	endif()

	# XXX Add a dependency on ${_ws_lib_dir}/current_tag.txt?

	# Head off any attempts to use Cygwin's Python.
	include(LocatePythonExecutable)
endif(WIN32)

include(UseCustomIncludes)
ADD_CUSTOM_CMAKE_INCLUDE()

# This cannot be implemented via option(...)
if( NOT CMAKE_BUILD_TYPE )
	set( CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING
		"Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel."
		FORCE)
endif()
message(STATUS "Configuration types: ${CMAKE_CONFIGURATION_TYPES}")
string(TOUPPER "${CMAKE_BUILD_TYPE}" _build_type)
message(STATUS "CMAKE_C_FLAGS_${_build_type}: ${CMAKE_C_FLAGS_${_build_type}}")
message(STATUS "CMAKE_CXX_FLAGS_${_build_type}: ${CMAKE_CXX_FLAGS_${_build_type}}")

# Ensure that all executables and libraries end up in the same directory. Actual
# files might end up in a configuration subdirectory, e.g. run/Debug or
# run/Release. We try to set DATAFILE_DIR to actual location below.
if(NOT ARCHIVE_OUTPUT_PATH)
	set(ARCHIVE_OUTPUT_PATH ${Wireshark_BINARY_DIR}/run CACHE INTERNAL
		   "Single output directory for building all archives.")
endif()
if(NOT EXECUTABLE_OUTPUT_PATH)
	set(EXECUTABLE_OUTPUT_PATH ${Wireshark_BINARY_DIR}/run CACHE INTERNAL
		   "Single output directory for building all executables.")
endif()
if(NOT LIBRARY_OUTPUT_PATH)
	set(LIBRARY_OUTPUT_PATH ${Wireshark_BINARY_DIR}/run CACHE INTERNAL
		   "Single output directory for building all libraries.")
endif()

#
# The release mode (CMAKE_BUILD_TYPE=release) defines NDEBUG for
# the Unix Makefile generator.
#

#Defines CMAKE_INSTALL_BINDIR, CMAKE_INSTALL_DATADIR, etc ...
include(GNUInstallDirs)
# Make sure our executables can can load our libraries if we install into
# a non-default directory on Unix-like systems other than macOS.
# https://cmake.org/Wiki/CMake_RPATH_handling
if(NOT CMAKE_INSTALL_RPATH AND NOT (WIN32 OR APPLE))
	LIST(FIND CMAKE_C_IMPLICIT_LINK_DIRECTORIES "${CMAKE_INSTALL_FULL_LIBDIR}" IS_SYSTEM_DIR)
	if("${IS_SYSTEM_DIR}" STREQUAL "-1")
		SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_FULL_LIBDIR}")
		SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
	endif("${IS_SYSTEM_DIR}" STREQUAL "-1")
endif()


if(WIN32)
    # Linking with wsetargv.obj enables "wildcard expansion" of
    # command-line arguments.
    set(WILDCARD_OBJ wsetargv.obj)
endif(WIN32)

# Banner shown at top right of Qt welcome screen.
if(DEFINED ENV{WIRESHARK_VERSION_FLAVOR})
	set(VERSION_FLAVOR "$ENV{WIRESHARK_VERSION_FLAVOR}")
#else()
#	set(VERSION_FLAVOR "Development Build")
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
include(UseAsn2Wrs)

# The following snippet has been taken from
# https://github.com/USESystemEngineeringBV/cmake-eclipse-helper/wiki/HowToWorkaroundIndexer
# The eclipse indexer otherwise assumes __cplusplus=199711L which will lead to broken
# lookup tables for the epan libraries
# Check if CXX flags have been set to c++11 -> Setup Eclipse Indexer correctly!
# Also setup the project slightly different
if (${CMAKE_EXTRA_GENERATOR} MATCHES "Eclipse CDT4" )
	SET(CXX_ENABLED 0)
	LIST(LENGTH CMAKE_EXTRA_GENERATOR_CXX_SYSTEM_DEFINED_MACROS LIST_LEN)
	if ( ${LIST_LEN} GREATER 0 )
		SET(CXX_ENABLED 1)
	endif()
	SET(C_ENABLED 0)
	LIST(LENGTH CMAKE_EXTRA_GENERATOR_C_SYSTEM_DEFINED_MACROS LIST_LEN)
	if ( ${LIST_LEN} GREATER 0)
		SET(C_ENABLED 1)
	endif()
	if (${C_ENABLED} EQUAL 1 AND ${CXX_ENABLED} EQUAL 1)
		# Combined project (C and CXX). This will confuse the indexer. For that reason
		# we unsert set the __cplusplus variable for the indexer
		list(FIND CMAKE_EXTRA_GENERATOR_CXX_SYSTEM_DEFINED_MACROS "__cplusplus" GEN_MACRO_INDEX)
		if( ${GEN_MACRO_INDEX} GREATER -1 )
			list(REMOVE_AT CMAKE_EXTRA_GENERATOR_CXX_SYSTEM_DEFINED_MACROS ${GEN_MACRO_INDEX})
			list(REMOVE_AT CMAKE_EXTRA_GENERATOR_CXX_SYSTEM_DEFINED_MACROS ${GEN_MACRO_INDEX})
		endif()
		SET(CMAKE_EXTRA_GENERATOR_CXX_SYSTEM_DEFINED_MACROS ${CMAKE_EXTRA_GENERATOR_CXX_SYSTEM_DEFINED_MACROS} CACHE INTERNAL "")
	elseif ( (${CXX_ENABLED} EQUAL 1) AND (${CMAKE_CXX_FLAGS} MATCHES ".*-std=c\\+\\+11.*"))
		#add_definitions (-D__cplusplus=201103L)
		# CMAKE_EXTRA_GENERATOR_CXX_SYSTEM_DEFINED_MACROS
		list(FIND CMAKE_EXTRA_GENERATOR_CXX_SYSTEM_DEFINED_MACROS "199711L" GEN_MACRO_INDEX)
		if( ${GEN_MACRO_INDEX} GREATER -1 )
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

include( CMakeOptions.txt )
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

if(APPLE AND EXISTS /usr/local/opt/qt5)
	# Homebrew installs Qt5 (up to at least 5.11.0) in
	# /usr/local/qt5. Ensure that it can be found by CMake
	# since it is not in the default /usr/local prefix.
	# Add it to PATHS so that it doesn't override the
	# CMAKE_PREFIX_PATH environment variable.
	# QT_FIND_PACKAGE_OPTIONS should be passed to find_package,
	# e.g. find_package(Qt5Core ${QT_FIND_PACKAGE_OPTIONS})
	set (QT_FIND_PACKAGE_OPTIONS PATHS /usr/local/opt/qt5)
endif()

# Always enable position-independent code when compiling, even for
# executables, so you can build position-independent executables.
# -pie is added below for non-MSVC.
# Needed when either:
# - Qt5_POSITION_INDEPENDENT_CODE is set and CMake < 2.8.11
# - PIE is wanted (-pie) and you want to add -fPIC/-fPIE automatically.
# This option only has an effect on CMake >= 2.8.9
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
		#                                   http://msdn.microsoft.com/en-us/library/windows/desktop/ms683219(v=vs.85).aspx
		# -D_ALLOW_KEYWORD_MACROS           For VS2012 onwards the, C++ STL does not permit macro redefinitions of keywords
		#                                   (see http://msdn.microsoft.com/en-us/library/bb531344(v=vs.110).aspx)
		#                                   This definition prevents the complaint about the redefinition of inline by WinPCap
		#                                   in pcap-stdinc.h when compiling C++ files, e.g. the Qt UI
		/DPSAPI_VERSION=1
		/D_ALLOW_KEYWORD_MACROS
	)

	if(NOT "${WIRESHARK_TARGET_PLATFORM}" STREQUAL "win64")
		add_definitions("/D_BIND_TO_CURRENT_CRT_VERSION=1")
	endif()

	# FIXME: WINPCAP_VERSION cannot be determined from source or executable.
	set(WINPCAP_VERSION "4_1_3")
	add_definitions("/DWINPCAP_VERSION=${WINPCAP_VERSION}")

	set(LOCAL_CFLAGS
		/MP
	)

	set(WS_LINK_FLAGS "/LARGEADDRESSAWARE /MANIFEST:NO /INCREMENTAL:NO /RELEASE")

	# /Zo                               Enhanced debugging of optimised code
	# /utf-8                            Set Source and Executable character sets to UTF-8
	#                                   VS2015(MSVC14): On by default when /Zi or /Z7 used.
	# /guard:cf                         Control Flow Guard (compile and link).
	#                                   See https://msdn.microsoft.com/en-us/library/windows/desktop/mt637065.aspx
	#                                   Note: This requires CMake 3.9.0 or newer.
	#                                   https://gitlab.kitware.com/cmake/cmake/commit/f973d49ab9d4c59b93f6dac812a94bb130200836
	# /Qspectre                         Speculative execution attack mitigation
	#                                   See https://blogs.msdn.microsoft.com/vcblog/2018/01/15/spectre-mitigations-in-msvc/
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
	## 4189: local variable is initialized but not referenced
	# Disable warnings about about use of flexible array members:
	## 4200: nonstandard extension used : zero-sized array in struct/union
	list(APPEND LOCAL_CFLAGS /w34295 /w34189 /wd4200)

	# We've matched these to specific compiler versions using the
	# checks above. There's no need to pass them to check_c_compiler_flag
	# or check_cxx_compiler_flag, which can be slow.
	string(REPLACE ";" " " _flags "${LOCAL_CFLAGS}")
	set(CMAKE_C_FLAGS "${_flags} ${CMAKE_C_FLAGS}")
	set(CMAKE_CXX_FLAGS "${_flags} ${CMAKE_CXX_FLAGS}")

else() # ! MSVC
	if(CMAKE_OSX_DEPLOYMENT_TARGET)
		if(APPLE)
			if(${CMAKE_OSX_DEPLOYMENT_TARGET} STREQUAL "10.0")
				message(FATAL_ERROR "We don't support building for Mac OS X 10.0")
			elseif(${CMAKE_OSX_DEPLOYMENT_TARGET} STREQUAL "10.1")
				message(FATAL_ERROR "We don't support building for Mac OS X 10.1")
			elseif(${CMAKE_OSX_DEPLOYMENT_TARGET} STREQUAL "10.2")
				message(FATAL_ERROR "We don't support building for Mac OS X 10.2")
			elseif(${CMAKE_OSX_DEPLOYMENT_TARGET} STREQUAL "10.4" OR ${CMAKE_OSX_DEPLOYMENT_TARGET} STREQUAL "10.5")
				#
				# Only 32-bit builds are supported.  10.5
				# (and 10.4?) had a bug that causes some BPF
				# functions not to work with 64-bit userland
				# code, so capturing won't work.
				#
				set(CMAKE_C_FLAGS "-m32 ${CMAKE_C_FLAGS}")
				set(CMAKE_CXX_FLAGS "-m32 ${CMAKE_CXX_FLAGS}")
				set(WS_LINK_FLAGS "-m32 ${WS_LINK_FLAGS}")
			endif()
			message(STATUS "Building for Mac OS X/OS X/macOS ${CMAKE_OSX_DEPLOYMENT_TARGET}")
		else()
			message(FATAL_ERROR "CMAKE_OSX_DEPLOYMENT_TARGET only applies when building for macOS")
		endif()
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

	set(COMMON_WARN_FLAGS
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
		set(COMMON_WARN_FLAGS ${COMMON_WARN_FLAGS}
			-Wframe-larger-than=32768
		)
	endif()

	set(C_WARN_FLAGS
		# The following are C only, not C++
		-Wc++-compat
		-Wunused-const-variable
		#
		# XXX - some versions of GCC, including the one in at
		# least some Xcode versions that come with Mac OS X
		# 10.5, complain about variables in function and
		# function pointer *declarations* shadowing other
		# variables.  The autoconf script checks for that; we
		# don't.
		-Wshadow
		-Wno-pointer-sign
		-Wold-style-definition
		-Wstrict-prototypes
		#
		# Some versions of GCC, such as 4.3.2 and 4.4.5,
		# generate logical-op warnings when strchr() is given a
		# constant string.  The autoconf script checks for that;
		# we don't.
		#
		-Wlogical-op
		-Wjump-misses-init
		#
		# The Qt headers generate a ton of shortening warnings
		# on 64-bit systems, so we only enable this for C for
		# now.
		#
		-Wshorten-64-to-32
		#
		# Implicit function declarations are an error in C++ and most
		# likely a programming error in C. Turn -Wimplicit-int and
		# -Wimplicit-function-declaration into an error by default.
		#
		-Werror=implicit
		#
		# The Qt headers in version 5.10 introduced a lot of
		# "Possible misuse of comma operator here" warnings.
		#
		-Wcomma
	)

	set(CXX_WARN_FLAGS
	)

	find_package(Qt5Core ${QT_FIND_PACKAGE_OPTIONS}) # Needed to check for Qt version
	if (Qt5Core_VERSION VERSION_GREATER 5.8)
		# The Qt headers in version 5.8 and older generate a ton of shortening
		# errors on 64-bit systems so only enable this for version 5.9 and greater.
		set(CXX_WARN_FLAGS ${CXX_WARN_FLAGS}
			-Wshorten-64-to-32
		)
	endif()
	if (Qt5Core_VERSION VERSION_LESS 5.10)
		# The Qt headers in version 5.10 introduced a lot of
		# "Possible misuse of comma operator here" warnings.
		set(CXX_WARN_FLAGS ${CXX_WARN_FLAGS}
			-Wcomma
		)
	endif()

	#
	# These are not enabled by default, because the warnings they
	# produce are very hard or impossible to eliminate.
	#
	set(COMMON_EXTRA_WARN_FLAGS
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
		# Some loops are safe, but it's hard to convince the
		# compiler of that.
		#
		-Wunsafe-loop-optimizations
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

	set(C_EXTRA_WARN_FLAGS
		# The following are C only, not C++
		#
		# Due to various places where APIs we don't control
		# require us to cast away constness, we can probably
		# never enable this one with -Werror.
		#
		-Wbad-function-cast
	)

	set(CXX_EXTRA_WARN_FLAGS
	)

	if(ENABLE_EXTRA_COMPILER_WARNINGS)   # This overrides -Werror
		set(COMMON_WARN_FLAGS ${COMMON_WARN_FLAGS} ${COMMON_EXTRA_WARN_FLAGS})
		set(C_WARN_FLAGS ${C_WARN_FLAGS} ${C_EXTRA_WARN_FLAGS})
		set(CXX_WARN_FLAGS ${CXX_WARN_FLAGS} ${CXX_EXTRA_WARN_FLAGS})
	endif()

	add_definitions(
		-DG_DISABLE_DEPRECATED
		-DG_DISABLE_SINGLE_INCLUDES
	)

	set(WIRESHARK_LD_FLAGS
		-Wl,--as-needed
		# -flto
		# -fwhopr
		# -fwhole-program
	)
	# CMAKE_POSITION_INDEPENDENT_CODE is only supported starting with CMake
	# 2.8.9. Do not add -pie automatically for older versions.
	#
	# XXX - are there other compilers that don't support -pie?  It's
	# not as if the only platforms we support are Windows and Linux....
	#
	if(NOT CMAKE_VERSION VERSION_LESS "2.8.9")
		set(WIRESHARK_LD_FLAGS ${WIRESHARK_LD_FLAGS}
			-pie
		)
	endif()
endif() # ! MSVC

set( C_FLAG_TESTS ${WIRESHARK_COMMON_FLAGS} ${WIRESHARK_C_ONLY_FLAGS} )
set( CXX_FLAG_TESTS ${WIRESHARK_COMMON_FLAGS} ${WIRESHARK_CXX_ONLY_FLAGS} )

set( C_WARN_TESTS ${COMMON_WARN_FLAGS} ${C_WARN_FLAGS} )
set( CXX_WARN_TESTS ${COMMON_WARN_FLAGS} ${CXX_WARN_FLAGS} )

# Counterhack to work around some cache magic in CHECK_C_SOURCE_COMPILES
include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)

if(ENABLE_STATIC)
	set(BUILD_SHARED_LIBS 0)
else()
	set(BUILD_SHARED_LIBS 1)
endif()

# Sigh: Have to use THIS_FLAG instead of ${F} for some reason
foreach(THIS_FLAG ${C_FLAG_TESTS})
	string( REGEX REPLACE "[^a-zA-Z0-9_]+" "_" F ${THIS_FLAG} )
	set(${F} ${THIS_FLAG})
	set(V C_${F}_VALID)
	message(STATUS "Checking for c-compiler flag: ${THIS_FLAG}")
	check_c_compiler_flag("${ADDED_CMAKE_C_FLAGS} ${${F}}" ${V})
	if (${${V}})
		set(ADDED_CMAKE_C_FLAGS "${ADDED_CMAKE_C_FLAGS} ${${F}}")
	endif()
endforeach()
set(CMAKE_C_FLAGS "${ADDED_CMAKE_C_FLAGS} ${CMAKE_C_FLAGS}")

foreach(THIS_FLAG ${CXX_FLAG_TESTS})
	string( REGEX REPLACE "[^a-zA-Z0-9_]+" "_" F ${THIS_FLAG} )
	set(${F} ${THIS_FLAG})
	set(V CXX_${F}_VALID)
	message(STATUS "Checking for c++-compiler flag: ${THIS_FLAG}")
	check_cxx_compiler_flag("${ADDED_CMAKE_CXX_FLAGS} ${${F}}" ${V})
	if (${${V}})
		set(ADDED_CMAKE_CXX_FLAGS "${ADDED_CMAKE_CXX_FLAGS} ${${F}}")
	endif()
endforeach()
set(CMAKE_CXX_FLAGS "${ADDED_CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS}")

foreach(THIS_FLAG ${C_WARN_TESTS})
	string( REGEX REPLACE "[^a-zA-Z0-9_]+" "_" F ${THIS_FLAG} )
	set(${F} ${THIS_FLAG})
	set(V C_${F}_VALID)
	message(STATUS "Checking for c-compiler flag: ${THIS_FLAG}")
	check_c_compiler_flag("${C_FLAG_TESTS} ${${F}}" ${V})
	if (${${V}})
		set(ADDED_WARN_C_FLAGS "${ADDED_WARN_C_FLAGS} ${${F}}")
	endif()
endforeach()
set(CMAKE_C_FLAGS "${ADDED_WARN_C_FLAGS} ${CMAKE_C_FLAGS}")

foreach(THIS_FLAG ${CXX_WARN_TESTS})
	string( REGEX REPLACE "[^a-zA-Z0-9_]+" "_" F ${THIS_FLAG} )
	set(${F} ${THIS_FLAG})
	set(V CXX_${F}_VALID)
	message(STATUS "Checking for c++-compiler flag: ${THIS_FLAG}")
	check_cxx_compiler_flag("${CXX_FLAG_TESTS} ${${F}}" ${V})
	if (${${V}})
		set(ADDED_WARN_CXX_FLAGS "${ADDED_WARN_CXX_FLAGS} ${${F}}")
	endif()
endforeach()
set(CMAKE_CXX_FLAGS "${ADDED_WARN_CXX_FLAGS} ${CMAKE_CXX_FLAGS}")

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

set(WERROR_COMMON_FLAGS "")
set(NO_ERROR_DEPRECATED_DECLARATIONS_COMPILE_FLAGS "")
if(NOT DISABLE_WERROR AND NOT ENABLE_EXTRA_COMPILER_WARNINGS)
	if(CMAKE_C_COMPILER_ID MATCHES "MSVC")
		set(WERROR_COMMON_FLAGS "/WX")
	else()
		check_c_compiler_flag(-Werror WERROR)
		if (WERROR)
			set(WERROR_COMMON_FLAGS "-Werror")
			set(NO_ERROR_DEPRECATED_DECLARATIONS_COMPILE_FLAGS "-Wno-error=deprecated-declarations")
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
set(_C 0)
# Sigh: Have to use THIS_FLAG instead of ${F} for some reason
foreach(THIS_FLAG ${WIRESHARK_LD_FLAGS})
	set(F WS_LD_FLAG_${_C})
	set(${F} ${THIS_FLAG})
	set(V WS_LD_FLAG_VALID${_C})
	check_c_linker_flag(${${F}} ${V})
	if (${${V}})
		set(WS_LINK_FLAGS "${WS_LINK_FLAGS} ${${F}}")
	endif()
	math(EXPR _C "${_C} + 1")
endforeach()

if(APPLE AND EXISTS /usr/local/opt/gettext)
	# GLib on macOS requires libintl. Homebrew installs gettext (and
	# libintl) in /usr/local/opt/gettext
	include_directories(/usr/local/opt/gettext/include)
	link_directories(/usr/local/opt/gettext/lib)
endif()

# The packagelist is doing some magic: If we add XXX to the packagelist, we
# - may optionally set XXX_OPTIONS to pass to the find_package command
# - will call FindXXX.cmake or find_package
# - return found libraries in XXX_LIBRARIES
# - return found include in XXX_INCLUDE_DIRS
# - set HAVE_XXX

# The minimum package list
set(PACKAGELIST Git GLIB2 GMODULE2 GTHREAD2 GCRYPT LEX YACC Perl PythonInterp)
set(LEX_OPTIONS REQUIRED)
set(GLIB2_OPTIONS REQUIRED)
set(GLIB2_FIND_OPTIONS REQUIRED)
set(GLIB2_MIN_VERSION 2.22.0)
set(GTHREAD2_OPTIONS REQUIRED)
set(GCRYPT_OPTIONS "1.4.2" REQUIRED)
set(PythonInterp_FIND_VERSION 2)
set(Python_ADDITIONAL_VERSIONS 3)
set(YACC_OPTIONS REQUIRED)

if (NOT WIN32)
	set(PACKAGELIST ${PACKAGELIST} Gettext M)
	set(M_OPTIONS REQUIRED)
endif()

set(PACKAGELIST ${PACKAGELIST} LIBSSH)
set(LIBSSH_OPTIONS "0.6")

if(ENABLE_PCAP)
	set(PACKAGELIST ${PACKAGELIST} PCAP)
endif()

if(ENABLE_AIRPCAP)
	set(PACKAGELIST ${PACKAGELIST} AIRPCAP)
endif()

# Build the GTK-GUI?
if(BUILD_wireshark_gtk)
	if(ENABLE_GTK3)
		set(PACKAGELIST ${PACKAGELIST} GTK3)
	else()
		set(PACKAGELIST ${PACKAGELIST} GTK2)
		set(GTK2_OPTIONS COMPONENTS gtk)
		set(GTK2_FIND_VERSION 2.12)
		set(GTK2_DEBUG false)
	endif()
endif()

# Build the Qt GUI?
if(BUILD_wireshark)
	if(ENABLE_QT5)
		# Untested, may not work if CMAKE_PREFIX_PATH gets overwritten
		# somewhere. The if WIN32 in this place is annoying as well.
		if( WIN32 )
			set( QT5_BASE_PATH "$ENV{QT5_BASE_DIR}" )
			set( CMAKE_PREFIX_PATH "${QT5_BASE_PATH}" )
		endif()
		list (INSERT QT_FIND_PACKAGE_OPTIONS 0 REQUIRED)
		set(PACKAGELIST ${PACKAGELIST}
			Qt5Core
			Qt5LinguistTools
			Qt5Multimedia
			Qt5PrintSupport
			Qt5Svg
			Qt5Widgets
		)
		set(Qt5Core_OPTIONS ${QT_FIND_PACKAGE_OPTIONS})
		set(Qt5LinguistTools_OPTIONS ${QT_FIND_PACKAGE_OPTIONS})
		set(Qt5Multimedia_OPTIONS ${QT_FIND_PACKAGE_OPTIONS})
		set(Qt5PrintSupport_OPTIONS ${QT_FIND_PACKAGE_OPTIONS})
		set(Qt5Svg_OPTIONS ${QT_FIND_PACKAGE_OPTIONS})
		set(Qt5Widgets_OPTIONS ${QT_FIND_PACKAGE_OPTIONS})
		if (APPLE)
			set(PACKAGELIST ${PACKAGELIST} Qt5MacExtras)
			set(Qt5MacExtras_OPTIONS ${QT_FIND_PACKAGE_OPTIONS})
		endif()
		if( WIN32 )
			set(PACKAGELIST ${PACKAGELIST} Qt5WinExtras)
			set(Qt5WinExtras_OPTIONS ${QT_FIND_PACKAGE_OPTIONS})
		endif()
		set(QT_VERSION 5)
	else()
		set(PACKAGELIST ${PACKAGELIST} Qt4)
		set(Qt4_OPTIONS 4.8 REQUIRED QtCore QtGui)
		set(QT_VERSION 4)
	endif()
endif()

# MaxMind DB address resolution
if(BUILD_mmdbresolve)
	set(PACKAGELIST ${PACKAGELIST} MaxMindDB)
endif()

# SMI SNMP
if(ENABLE_SMI)
	set(PACKAGELIST ${PACKAGELIST} SMI)
endif()

# GNU SSL/TLS support
if(ENABLE_GNUTLS)
	set(PACKAGELIST ${PACKAGELIST} GNUTLS)
	# Minimum version needed.
	set(GNUTLS_OPTIONS "2.12.0")
endif()

# Kerberos
if(ENABLE_KERBEROS)
	set(PACKAGELIST ${PACKAGELIST} KERBEROS)
endif()

# Portable audio (GTK+ only)
if(ENABLE_PORTAUDIO AND BUILD_wireshark_gtk)
	set(PACKAGELIST ${PACKAGELIST} PORTAUDIO)
endif()


# C Asynchronous resolver
if(ENABLE_CARES)
	set(PACKAGELIST ${PACKAGELIST} CARES)
	# Minimum version needed.
	set(CARES_OPTIONS "1.5.0")
endif()

# Zlib compression
if(ENABLE_ZLIB)
	if (WIN32)
		# On Windows we build our own version of zlib, so add the paths
		set(ZLIB_SRC_DIR "${_PROJECT_LIB_DIR}/zlib-1.2.11-2-ws")
		set(SKIP_INSTALL_ALL True) # We copy the DLL ourselves.
		add_subdirectory("${ZLIB_SRC_DIR}" "${CMAKE_BINARY_DIR}/zlib")
		unset(SKIP_INSTALL_ALL)
		set(ZLIB_INCLUDE_DIR  "${ZLIB_SRC_DIR}" "${CMAKE_BINARY_DIR}/zlib")
		set(ZLIB_LIBRARY zlib)
		set(ZLIB_DLL "zlib1.dll")
		set_target_properties(zlib PROPERTIES FOLDER "Libs/zlib")
		# Annoyingly zlib also builds some other stuff we aren't interested in
		set_target_properties(zlibstatic PROPERTIES
			FOLDER "Libs/zlib"
			EXCLUDE_FROM_ALL True
			EXCLUDE_FROM_DEFAULT_BUILD True
		)
	endif()
	set(PACKAGELIST ${PACKAGELIST} ZLIB)
endif()

# LZ4 compression
if(ENABLE_LZ4)
	set(PACKAGELIST ${PACKAGELIST} LZ4)
endif()

# Snappy compression
if(ENABLE_SNAPPY)
	set(PACKAGELIST ${PACKAGELIST} SNAPPY)
endif()

# Enhanced HTTP/2 dissection
if(ENABLE_NGHTTP2)
	set(PACKAGELIST ${PACKAGELIST} NGHTTP2)
endif()

# Embedded Lua interpreter
if(ENABLE_LUA)
	set(PACKAGELIST ${PACKAGELIST} LUA)
endif()

if(ENABLE_NETLINK)
	set(PACKAGELIST ${PACKAGELIST} NL)
endif()

if(ENABLE_SBC)
	set(PACKAGELIST ${PACKAGELIST} SBC)
endif()

if(ENABLE_SPANDSP)
	set(PACKAGELIST ${PACKAGELIST} SPANDSP)
endif()

if(ENABLE_BCG729)
	set(PACKAGELIST ${PACKAGELIST} BCG729)
endif()

if(ENABLE_LIBXML2)
	set(PACKAGELIST ${PACKAGELIST} LibXml2)
endif()

# Capabilities
if(ENABLE_CAP)
	set(PACKAGELIST ${PACKAGELIST} CAP SETCAP)
endif()

# Windows version updates
if(ENABLE_WINSPARKLE)
	set(PACKAGELIST ${PACKAGELIST} WINSPARKLE)
endif()

set(PACKAGELIST ${PACKAGELIST} POD)

set(PACKAGELIST ${PACKAGELIST} DOXYGEN)

set(PROGLIST)

# Sort the package list
list(SORT PACKAGELIST)
string(REPLACE ";" " " _package_list "${PACKAGELIST}")
message(STATUS "Package List: ${_package_list}")
# Let's loop the package list
foreach(PACKAGE ${PACKAGELIST})
	if(${PACKAGE} STREQUAL "Qt4")
		set(PACKAGE_VAR "QT")
	elseif(${PACKAGE} STREQUAL "PythonInterp")
		set(PACKAGE_VAR "PYTHONINTERP")
	elseif(${PACKAGE} STREQUAL "Gettext")
		set(PACKAGE_VAR "GETTEXT")
	elseif(${PACKAGE} STREQUAL "Perl")
		set(PACKAGE_VAR "PERL")
	elseif(${PACKAGE} STREQUAL "LibXml2")
		set(PACKAGE_VAR "LIBXML2")
	else()
		set(PACKAGE_VAR ${PACKAGE})
	endif()
	if(${PACKAGE}_OPTIONS)
		find_package(${PACKAGE} ${${PACKAGE}_OPTIONS})
	else()
		find_package(${PACKAGE})
	endif()
	# FindPackageHandleStandardArgs before CMake 3.2 always uses uppercase
	# for the FOUND variables (e.g. GIT_FOUND is set, but not Git_FOUND).
	string(TOUPPER "${PACKAGE_VAR}" PACKAGE_VAR_UPPER)
	if (${PACKAGE_VAR}_FOUND OR ${PACKAGE_VAR_UPPER}_FOUND)
		message(STATUS "${PACKAGE_VAR} FOUND")
		set(HAVE_LIB${PACKAGE_VAR} 1)
		if (NOT DEFINED ${PACKAGE_VAR}_INCLUDE_DIRS AND ${PACKAGE_VAR}_INCLUDE_DIR)
			set(${PACKAGE_VAR}_INCLUDE_DIRS ${${PACKAGE_VAR}_INCLUDE_DIR})
		endif()
		if (${PACKAGE_VAR}_INCLUDE_DIRS)
			include_directories(SYSTEM ${${PACKAGE_VAR}_INCLUDE_DIRS})
			message(STATUS "${PACKAGE} includes: ${${PACKAGE_VAR}_INCLUDE_DIRS}")
		endif()
		if (${PACKAGE_VAR}_LIBRARIES)
			list(APPEND WS_ALL_LIBS ${${PACKAGE_VAR}_LIBRARIES})
			message(STATUS "${PACKAGE} libs: ${${PACKAGE_VAR}_LIBRARIES}")
		endif()
		if (${PACKAGE_VAR}_DEFINITIONS)
			message(STATUS "${PACKAGE} definitions: ${${PACKAGE_VAR}_DEFINITIONS}")
		endif()
		if (${PACKAGE_VAR}_EXECUTABLE)
			message(STATUS "${PACKAGE} executable: ${${PACKAGE_VAR}_EXECUTABLE}")
		endif()
	else()
		#
		# Not finding a package is only a fatal error if the
		# package is required; if it's required, then its
		# XXX_OPTIONS variable contains REQUIRED, and the above
		# code will pass REQUIRED to find_package, and the
		# configure will fail if the package isn't found.
		#
		# Do *NOT* report this as an error!
		#
		message(STATUS "${PACKAGE_VAR} NOT FOUND")
	endif()
endforeach()

# Provide Windows system lib names
include( UseWinLibs )

# dist target that prepares source dir
add_custom_target(dist
    COMMAND "${CMAKE_COMMAND}"
        -DPROJECT_SOURCE_DIR="${PROJECT_SOURCE_DIR}"
        -DGIT_EXECUTABLE="${GIT_EXECUTABLE}"
        -DWS_SOURCE_DIR="${WS_SOURCE_DIR}"
        -P "${CMAKE_SOURCE_DIR}/cmake/modules/Dist.cmake"
    COMMAND "${CMAKE_MAKE_PROGRAM}" package_source
)


if(HAVE_LIBAIRPCAP)
	set(HAVE_AIRPCAP 1)
endif()
if(HAVE_LIBLUA)
	set(HAVE_LUA_H 1)
	set(HAVE_LUA 1)
endif()
if(HAVE_LIBKERBEROS)
	set(HAVE_KERBEROS 1)
endif()
if(MAXMINDDB_FOUND)
	set(HAVE_MAXMINDDB 1)
endif()
if(LIBSSH_FOUND)
	set(HAVE_LIBSSH 1)
endif()
if(NGHTTP2_FOUND)
	set(HAVE_NGHTTP2 1)
endif()
if(HAVE_LIBCARES)
	set(HAVE_C_ARES 1)
endif()
if(NOT HAVE_LIBCARES)
	message(WARNING "Not using c-ares.")
	message(WARNING "DNS name resolution for captures will be disabled.")
endif()
if(HAVE_LIBNL AND HAVE_AIRPCAP)
	message(ERROR "Airpcap and Libnl support are mutually exclusive")
endif()
if(HAVE_LIBSBC)
	set(HAVE_SBC 1)
endif()
if(SPANDSP_FOUND)
	set(HAVE_SPANDSP 1)
endif()
if(BCG729_FOUND)
	set(HAVE_BCG729 1)
endif()
if(LIBXML2_FOUND)
	set(HAVE_LIBXML2 1)
else()
	# The (official) FindLibXml2.cmake file sets this cache variable to a
	# non-empty value, be sure to clear it when not found.
	set(LIBXML2_LIBRARIES "")
endif()
if(EXTCAP_ANDROIDDUMP_LIBPCAP)
	set(ANDROIDDUMP_USE_LIBPCAP 1)
endif()

if (HAVE_LIBWINSPARKLE)
	set(HAVE_SOFTWARE_UPDATE 1)
endif()

# No matter which version of GTK is present
if(GTK2_FOUND OR GTK3_FOUND)
	message(WARNING "The GTK+ UI is deprecated and will be removed in a future release.")
	set(GTK_FOUND ON)
endif()

if(HAVE_LIBZLIB)
	set(HAVE_ZLIB 1)
	# Always include the "true" zlib includes first. This works around a
	# bug in the Windows setup of GTK[23] which has a faulty zconf.h.
	include_directories(BEFORE ${ZLIB_INCLUDE_DIRS})
endif()
if(HAVE_LIBLZ4)
	set(HAVE_LZ4 1)
endif()
if(SNAPPY_FOUND)
	set(HAVE_SNAPPY 1)
endif()
if (Qt5Widgets_FOUND)
	if (Qt5Widgets_VERSION VERSION_GREATER 5.6
	    AND (CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID MATCHES "Clang"))
		# Qt 5.7 and later require C++ 11. If our minmimu required CMake version
		# is ever >= 3.1 we can use CXX_STANDARD + CXX_STANDARD_REQUIRED.
		message(STATUS "Checking for C++ 11 support (Required by Qt 5.7 and later)")
		check_cxx_compiler_flag(-std=c++11 CXX__std_c__11_VALID)
		if(NOT CXX__std_c__11_VALID)
			message(FATAL_ERROR "Qt ${Qt5Widgets_VERSION} requires C++ 11")
		endif()
		set(CMAKE_CXX_FLAGS "-std=c++11 ${CMAKE_CXX_FLAGS}")
	endif()
	set (QT_FOUND ON)
	set (QT_LIBRARIES ${Qt5Widgets_LIBRARIES} ${Qt5PrintSupport_LIBRARIES})
	if(Qt5Multimedia_FOUND)
		set (QT_LIBRARIES ${QT_LIBRARIES} ${Qt5Multimedia_LIBRARIES})
		# That's the name autofoo uses
		set(QT_MULTIMEDIA_LIB 1)
	endif()
	if(Qt5Svg_FOUND)
		set (QT_LIBRARIES ${QT_LIBRARIES} ${Qt5Svg_LIBRARIES})
		# That's the name autofoo uses
		set(QT_SVG_LIB 1)
	endif()
	if(Qt5MacExtras_FOUND)
		set (QT_LIBRARIES ${QT_LIBRARIES} ${Qt5MacExtras_LIBRARIES})
		# That's the name autofoo uses
		set(QT_MACEXTRAS_LIB 1)
	endif()
	if(Qt5WinExtras_FOUND)
		set (QT_LIBRARIES ${QT_LIBRARIES} ${Qt5WinExtras_LIBRARIES})
		# set(QT_WINEXTRAS_LIB 1) # Not needed?
	endif()
	if(NOT DEFINED MOC_OPTIONS)
		# Squelch moc verbose "nothing to do" output
		set(MOC_OPTIONS -nn)
	endif()
# If Qt4: QT_LIBRARIES and QT_INCLUDES are not set above. They require extra magic
elseif(QT4_FOUND)
	include(${QT_USE_FILE})
	include_directories(${QT_INCLUDE_DIR})
	message(STATUS "Qt includes: ${QT_INCLUDE_DIR}")
	message(STATUS "Qt libs: ${QT_LIBRARIES}")
	if(QT_QTMULTIMEDIA_FOUND)
		include_directories(${QT_QTMULTIMEDIA_INCLUDE_DIR})
		message(STATUS "QtMultimedia includes: ${QT_INCLUDE_DIR}")
		set (QT_LIBRARIES ${QT_LIBRARIES} ${QT_QTMULTIMEDIA_LIBRARY})
		message(STATUS "QtMultimedia libs: ${QT_QTMULTIMEDIA_LIBRARY}")
		# That's the name autofoo uses
		set(QT_MULTIMEDIA_LIB 1)
	endif()
	if(NOT DEFINED MOC_OPTIONS)
		if(QT_VERSION_MAJOR EQUAL 4 AND QT_VERSION_MINOR GREATER 7)
			set(MOC_OPTIONS -nn)
		endif()
	endif()
	if(WIN32 OR APPLE)
		message(FATAL_ERROR "Windows and macOS builds should use Qt5.")
	endif()
endif()

if(ENABLE_CHECKHF_CONFLICT)
	set(ENABLE_CHECK_FILTER 1)
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
	# http://stackoverflow.com/a/24305849/82195
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

add_subdirectory( capchild )
add_subdirectory( caputils )
add_subdirectory( codecs )
add_subdirectory( doc )
add_subdirectory( docbook EXCLUDE_FROM_ALL )
add_subdirectory( epan )
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
	set(_datafile_dir "${CMAKE_BINARY_DIR}/run/Wireshark.app/Contents/Resources/share/wireshark")
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

if(NOT WIN32)
	add_custom_target(dumpabi DEPENDS dumpabi-libwireshark dumpabi-libwiretap dumpabi-libwsutil)
endif()

if(BUILD_wireshark_gtk AND GTK_FOUND)
	add_subdirectory( ui/gtk )
endif()

if(BUILD_wireshark AND QT_FOUND)
	add_subdirectory( ui/qt )
endif()

# Target platform locations
# UN*X in general, including macOS if not building an app bundle:
# $DESTDIR/lib/wireshark/extcap
# Windows: $DESTDIR/extcap
# macOS app bundle: Wireshark.app/Contents/Resources/share/wireshark/extcap
if (WIN32)
	set(EXTCAP_DIR "extcap")
else ()
	set(EXTCAP_DIR "${CMAKE_INSTALL_FULL_LIBDIR}/${CPACK_PACKAGE_NAME}/extcap")
endif()

if(LIBSSH_FOUND)
	SET(CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES} ${LIBSSH_LIBRARIES})
	CHECK_FUNCTION_EXISTS(ssh_userauth_agent LIBSSH_USERAUTH_AGENT_FOUND)
	if(LIBSSH_USERAUTH_AGENT_FOUND)
		set(HAVE_SSH_USERAUTH_AGENT 1)
	endif()
endif()

# Directory where plugins and Lua dissectors can be found.
set(PLUGIN_VERSION_DIR "plugins/${PROJECT_RELEASE_VERSION}")
set(PLUGIN_INSTALL_LIBDIR "${CMAKE_INSTALL_LIBDIR}/${CPACK_PACKAGE_NAME}/${PLUGIN_VERSION_DIR}")
# Used by the WiresharkConfig.cmake.in module
if (WIN32)
	set(PLUGIN_INSTALL_DIR "${PLUGIN_VERSION_DIR}")
else ()
	set(PLUGIN_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/${PLUGIN_INSTALL_LIBDIR}")
endif()

# Location of our plugins. PLUGIN_DIR should allow running
# from the build directory similar to DATAFILE_DIR above.
if(ENABLE_PLUGINS)
	# Target platform locations
	# UN*X in general, including macOS if not building an app bundle:
	# $DESTDIR/lib/wireshark/plugins/$VERSION
	# Windows: $DESTDIR/wireshark/plubins/$VERSION
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
		plugins/codecs/l16_mono
		${CUSTOM_PLUGIN_SRC_DIR}
	)

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
	set(_plugin_dir "${CMAKE_BINARY_DIR}/run/Wireshark.app/Contents/PlugIns/wireshark/${PROJECT_RELEASE_VERSION}")
else()
	set(_plugin_dir "${DATAFILE_DIR}/${PLUGIN_VERSION_DIR}")
endif()
set (PLUGIN_DIR ${_plugin_dir} CACHE INTERNAL "Build time plugin location.")

foreach(_plugin_src_dir ${PLUGIN_SRC_DIRS})
	add_subdirectory( ${_plugin_src_dir} )
endforeach()

if(ENABLE_PCAP_NG_DEFAULT)
	set(PCAP_NG_DEFAULT 1)
endif()

# Large file support (e.g. make off_t 64 bit if supported)
include(gmxTestLargeFiles)
gmx_test_large_files(GMX_LARGEFILES)

add_definitions( -DTOP_SRCDIR=\"${CMAKE_SOURCE_DIR}\" )

if (${GIT_EXECUTABLE})
	set(GIT_BIN_PARAM "--git-bin ${GIT_EXECUTABLE}")
endif()
set( VERSION ${PROJECT_VERSION} )
if(NOT CMAKE_VERSION VERSION_LESS "3.2.1")
	# Prevents unnecessary rebuilds by ensuring that dependents are not
	# built before make-version.pl finishes (which may touch version.h).
	set(version_byproducts BYPRODUCTS version.h)
else()
	set(version_byproducts "")
endif()
add_custom_target(version
	${version_byproducts}
	COMMAND ${PERL_EXECUTABLE}
		${CMAKE_SOURCE_DIR}/make-version.pl
		--set-vcs ${GIT_BIN_PARAM}
		${CMAKE_SOURCE_DIR}
)
set_target_properties(version PROPERTIES FOLDER "Auxiliary")

set( configure_input "Built with CMake ${CMAKE_VERSION}" )
configure_file(${CMAKE_SOURCE_DIR}/cmakeconfig.h.in ${CMAKE_BINARY_DIR}/config.h)

set( prefix "${CMAKE_INSTALL_PREFIX}" )
set( exec_prefix "\${prefix}" )
set( libdir "\${exec_prefix}/${CMAKE_INSTALL_LIBDIR}" )
set( includedir  "\${prefix}/include" )
set( plugindir "\${libdir}/wireshark/${PLUGIN_VERSION_DIR}" )

set(ICON_PATH "${CMAKE_SOURCE_DIR}/image/")
set( IN_FILES
	capchild/doxygen.cfg.in
	caputils/doxygen.cfg.in
	doxygen.cfg.in
	doxygen_global.cfg
	epan/doxygen.cfg.in
	image/libwireshark.rc.in
	image/text2pcap.rc.in
	image/capinfos.rc.in
	image/wireshark.rc.in
	image/mergecap.rc.in
	image/tshark.rc.in
	image/dumpcap.rc.in
	image/reordercap.rc.in
	image/rawshark.rc.in
	image/file_dlg_win32.rc
	image/tfshark.rc.in
	image/editcap.rc.in
	image/captype.rc.in
	image/libwscodecs.rc.in
	image/libwsutil.rc.in
	image/wiretap.rc.in
	image/wireshark.exe.manifest.in
	packaging/macosx/Info.plist.in
	packaging/macosx/osx-app.sh.in
	packaging/macosx/osx-dmg.sh.in
	packaging/macosx/Wireshark_package.pmdoc/index.xml.in
	randpkt_core/doxygen.cfg.in
	ui/doxygen.cfg.in
	ui/gtk/doxygen.cfg.in
	ui/qt/doxygen.cfg.in
	wireshark.pc.in
	writecap/doxygen.cfg.in
)
foreach( _in_file ${IN_FILES} )
	get_filename_component( _path ${_in_file} PATH )
	string( REGEX REPLACE "(.*)\\.in" "\\1" _outfile ${_in_file}  )
	configure_file( ${CMAKE_SOURCE_DIR}/${_in_file} ${CMAKE_BINARY_DIR}/${_outfile} @ONLY )
endforeach()

include(FeatureSummary)
set_package_properties(SBC PROPERTIES
	DESCRIPTION "Bluetooth low-complexity, subband codec (SBC) decoder"
	URL "https://git.kernel.org/pub/scm/bluetooth/sbc.git"
	PURPOSE "Support for playing SBC codec in RTP player"
)
set_package_properties(SPANDSP PROPERTIES
	DESCRIPTION "a library of many DSP functions for telephony"
	URL "http://www.soft-switch.org/"
	PURPOSE "Support for G.722 and G.726 codecs in RTP player"
)
set_package_properties(BCG729 PROPERTIES
	DESCRIPTION "G.729 decoder"
	URL "https://www.linphone.org/technical-corner/bcg729/overview"
	PURPOSE "Support for G.729 codec in RTP player"
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
	URL "http://google.github.io/snappy/"
	PURPOSE "Snappy decompression in CQL and Kafka dissectors"
)
set_package_properties(NGHTTP2 PROPERTIES
	DESCRIPTION "HTTP/2 C library and tools"
	URL "https://nghttp2.org"
	PURPOSE "Header decompression in HTTP2"
)

message(STATUS "C-Flags: ${CMAKE_C_FLAGS}")
message(STATUS "CXX-Flags: ${CMAKE_CXX_FLAGS}")
message(STATUS "Warnings as errors: ${WERROR_COMMON_FLAGS}")

feature_summary(WHAT ALL)

link_directories(
	${CMAKE_BINARY_DIR}/ui
	${CMAKE_BINARY_DIR}/ui/gtk
	${CMAKE_BINARY_DIR}/ui/qt
	${CMAKE_BINARY_DIR}/capchild
	${CMAKE_BINARY_DIR}/caputils
	${CMAKE_BINARY_DIR}/codecs
	${CMAKE_BINARY_DIR}/epan
	${CMAKE_BINARY_DIR}/randpkt_core
	${CMAKE_BINARY_DIR}/wiretap
	${CMAKE_BINARY_DIR}/writecap
	${CMAKE_BINARY_DIR}/wsutil
)

if(WIN32)
	set(PLATFORM_UI_SRC
		ui/win32/console_win32.c
		ui/win32/file_dlg_win32.c
		ui/win32/print_win32.c
	)
	set(PLATFORM_UI_RC_FILES
		image/file_dlg_win32.rc
	)
elseif(APPLE)
	set(PLATFORM_UI_SRC
		ui/macosx/cocoa_bridge.mm
	)
endif()

# sources common for wireshark, tshark, rawshark and sharkd
set(SHARK_COMMON_SRC
	cfile.c
	file_packet_provider.c
	frame_tvbuff.c
	sync_pipe_write.c
	version_info.c
	extcap.c
	extcap_parser.c
)

set(TSHARK_TAP_SRC
	${CMAKE_SOURCE_DIR}/ui/cli/tap-camelsrt.c
	${CMAKE_SOURCE_DIR}/ui/cli/tap-comparestat.c
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
)

set(INSTALL_DIRS
	diameter
	dtds
	${DATAFILE_DIR}/help
	profiles
	radius
	tpncp
	wimaxasncp
)

set(INSTALL_FILES
	cfilters
	colorfilters
	dfilters
	enterprises.tsv
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

if(WIN32)
	set(TEXTIFY_FILES COPYING NEWS README.windows)
	set(TEXTIFY_MD_FILES README.md)
	foreach(_text_file ${TEXTIFY_FILES} ${TEXTIFY_MD_FILES})
		string(REGEX REPLACE ".md$" "" _out_file ${_text_file})
		set(INSTALL_FILES ${CMAKE_BINARY_DIR}/${_out_file}.txt ${INSTALL_FILES})
	endforeach()
else()
	set(INSTALL_FILES COPYING ${INSTALL_FILES})
endif()

set(LIBEPAN_LIBS
		epan
		${AIRPCAP_LIBRARIES}
		${PCAP_LIBRARIES}
		${CARES_LIBRARIES}
		${KERBEROS_LIBRARIES}
		${LUA_LIBRARIES}
		${PYTHON_LIBRARIES}
		${GEOIP_LIBRARIES}
		${GCRYPT_LIBRARIES}
		${GNUTLS_LIBRARIES}
		${SMI_LIBRARIES}
		${ZLIB_LIBRARIES}
		${LZ4_LIBRARIES}
		${SNAPPY_LIBRARIES}
		${M_LIBRARIES}
		${WINSPARKLE_LIBRARIES}
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

	# Required DLLs.
	# The cairo, freetype, gio, gnutls, png, and other OBS-generated DLLs
	# depend on zlib1.dll. We compile zlib locally but the Debug
	# configuration (the default) creates zlibd1.dll.
	# Note: Passing multiple files to copy_if_different requires
	# CMake 3.5 or later.
	add_custom_command(TARGET copy_cli_dlls PRE_BUILD
		COMMAND ${CMAKE_COMMAND} -E copy_if_different
			${GLIB2_DLLS} $<$<CONFIG:Debug>:zlib1.dll>
			"${_dll_output_dir}"
		WORKING_DIRECTORY "${GLIB2_DLL_DIR}"
	)

	# Optional DLLs and PDBs.
	set (OPTIONAL_DLLS)
	set (OPTIONAL_PDBS)
	if (AIRPCAP_FOUND)
		list (APPEND OPTIONAL_DLLS "${AIRPCAP_DLL_DIR}/${AIRPCAP_DLL}")
	endif(AIRPCAP_FOUND)
	if (CARES_FOUND)
		list (APPEND OPTIONAL_DLLS "${CARES_DLL_DIR}/${CARES_DLL}")
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
	endif(LZ4_FOUND)
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
	if (LIBXML2_FOUND)
		list (APPEND OPTIONAL_DLLS "${LIBXML2_DLL_DIR}/${LIBXML2_DLL}")
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

	# With libs downloaded to c:/wireshark-win64-libs this currently
	# (early 2018) expands to about 1900 characters.
	if (OPTIONAL_DLLS)
		add_custom_command(TARGET copy_cli_dlls PRE_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy_if_different
				${OPTIONAL_DLLS}
				"${_dll_output_dir}"
			VERBATIM
		)
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
	# - Cygwin's zip, which requires Cygwin.
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
	# XXX "if(ZIP_EXECUTABLE)" doesn't work here. It looks like the
	# absence of "-NOTFOUND" doesn't equal "true".
	if (NOT "${ZIP_EXECUTABLE}" STREQUAL "ZIP_EXECUTABLE-NOTFOUND")
		add_custom_target(pdb_zip_package COMMENT "This packages .PDBs but will not create them.")
		set_target_properties(pdb_zip_package PROPERTIES FOLDER "Packaging")
		set(_pdb_zip "${CMAKE_BINARY_DIR}/Wireshark-pdb-${WIRESHARK_TARGET_PLATFORM}-${VERSION}.zip")
		file(TO_NATIVE_PATH "${_pdb_zip}" _pdb_zip_win)
		add_custom_command(TARGET pdb_zip_package POST_BUILD
			COMMAND ${CMAKE_COMMAND} -E remove -f "${_pdb_zip}"
			COMMAND ${ZIP_EXECUTABLE} a -tzip -mmt=on "${_pdb_zip_win}"
				*.pdb *.lib
				extcap/*.pdb
				${PLUGIN_VERSION_DIR}/epan/*.pdb
				${PLUGIN_VERSION_DIR}/wiretap/*.pdb
			WORKING_DIRECTORY "${_dll_output_dir}"
		)
	endif()
endif(WIN32)

# List of extra dependencies for the "copy_data_files" target
set(copy_data_files_depends)

# glob patterns relative to the source directory that should be copied to
# ${DATAFILE_DIR} (including directory prefixes)
set(DATA_FILES_SRC
	"help/toc"
)

if(WIN32)
	foreach(_text_file ${TEXTIFY_FILES})
		add_custom_command(OUTPUT ${CMAKE_BINARY_DIR}/${_text_file}.txt
			COMMAND ${POWERSHELL_COMMAND} "${CMAKE_SOURCE_DIR}/tools/textify.ps1"
				-Destination ${CMAKE_BINARY_DIR}
				${CMAKE_SOURCE_DIR}/${_text_file}
			DEPENDS
				${CMAKE_SOURCE_DIR}/${_text_file}
		)
	endforeach()
	foreach(_md_file ${TEXTIFY_MD_FILES})
		string(REGEX REPLACE ".md$" ".txt" _text_file ${_md_file})
		add_custom_command(OUTPUT ${CMAKE_BINARY_DIR}/${_text_file}
			COMMAND ${POWERSHELL_COMMAND} "${CMAKE_SOURCE_DIR}/tools/textify.ps1"
				-Destination ${CMAKE_BINARY_DIR}
				${CMAKE_SOURCE_DIR}/${_md_file}
			COMMAND ${CMAKE_COMMAND} -E rename
				${CMAKE_BINARY_DIR}/${_md_file}.txt
				${CMAKE_BINARY_DIR}/${_text_file}
			DEPENDS
				${CMAKE_SOURCE_DIR}/${_text_file}
		)
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

# Ensure "run/extcap" exists
add_custom_command(OUTPUT "${DATAFILE_DIR}/extcap"
	COMMAND ${CMAKE_COMMAND} -E make_directory
		"${DATAFILE_DIR}/extcap"
)
list(APPEND copy_data_files_depends "${DATAFILE_DIR}/extcap")

# faq.txt is handled separately below.
set(_help_source_files
	help/capture_filters.txt
	help/capturing.txt
	help/display_filters.txt
	help/getting_started.txt
	help/overview.txt
)

if(WIN32)
	file(TO_NATIVE_PATH "${DATAFILE_DIR}/help" _help_dest_dir)
	foreach(_help_file IN LISTS _help_source_files)
		add_custom_command(OUTPUT "${DATAFILE_DIR}/${_help_file}"
			COMMAND ${CMAKE_COMMAND} -E make_directory "${DATAFILE_DIR}/help"
			COMMAND ${POWERSHELL_COMMAND} "${CMAKE_SOURCE_DIR}/tools/textify.ps1"
				-Destination "${_help_dest_dir}"
				"${CMAKE_SOURCE_DIR}/${_help_file}"
			DEPENDS
				"${CMAKE_SOURCE_DIR}/${_help_file}"
		)
		list(APPEND copy_data_files_depends "${DATAFILE_DIR}/${_help_file}")
	endforeach()
else()
	list(APPEND DATA_FILES_SRC ${_help_source_files})
endif(WIN32)

# Create help/faq.txt when missing
add_custom_command(OUTPUT "${DATAFILE_DIR}/help/faq.txt"
	COMMAND ${CMAKE_COMMAND} -E make_directory "${DATAFILE_DIR}/help"
	COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_SOURCE_DIR}/help/faq.py -b > faq.tmp.html
	COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tools/html2text.py
		faq.tmp.html > "${DATAFILE_DIR}/help/faq.txt"
	COMMAND ${CMAKE_COMMAND} -E remove faq.tmp.html
	DEPENDS
		"${CMAKE_SOURCE_DIR}/help/faq.py"
		"${CMAKE_SOURCE_DIR}/tools/html2text.py"
)
list(APPEND copy_data_files_depends "${DATAFILE_DIR}/help/faq.txt")

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

# TODO shouldn't this use full (relative) paths instead of glob patterns?
list(APPEND DATA_FILES_SRC
	"tpncp/tpncp.dat"
	"wimaxasncp/*.dtd"
	"wimaxasncp/*.xml"
)

# Copy all paths from the source tree to the data directory. Directories are
# automatically created if missing as the filename is given.
# TODO Switch to cmake -E copy_if_different when our minimum CMake version
# is >= 3.5 everywhere.
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

if(CMAKE_VERSION VERSION_LESS 3.5)
	# To bad -u / --update is a GNU extension.
	set (MULTI_COPY_COMMAND cp)
else()
	set (MULTI_COPY_COMMAND ${CMAKE_COMMAND} -E copy_if_different)
endif()

add_custom_command(
	OUTPUT "${DATAFILE_DIR}/dtds" "${DATAFILE_DIR}/diameter" "${DATAFILE_DIR}/radius"
	COMMAND ${CMAKE_COMMAND} -E make_directory "${DATAFILE_DIR}/dtds"
	COMMAND ${CMAKE_COMMAND} -E make_directory "${DATAFILE_DIR}/diameter"
	COMMAND ${CMAKE_COMMAND} -E make_directory "${DATAFILE_DIR}/radius"
)

file(GLOB _dtds_src_files RELATIVE "${CMAKE_SOURCE_DIR}" "dtds/*.dtd")

set (_dtds_data_files)
foreach(_data_file ${_dtds_src_files})
	list(APPEND _dtds_data_files "${DATAFILE_DIR}/${_data_file}")
endforeach()

add_custom_command(
	OUTPUT ${_dtds_data_files}
	COMMAND ${MULTI_COPY_COMMAND}
		${_dtds_src_files}
		"${DATAFILE_DIR}/dtds"
	VERBATIM
	DEPENDS "${DATAFILE_DIR}/dtds"
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
	COMMAND ${MULTI_COPY_COMMAND}
		${_diameter_src_files}
		"${DATAFILE_DIR}/diameter"
	VERBATIM
	DEPENDS "${DATAFILE_DIR}/diameter"
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
	COMMAND ${MULTI_COPY_COMMAND}
		${_radius_src_files}
		"${DATAFILE_DIR}/radius"
	VERBATIM
	DEPENDS "${DATAFILE_DIR}/radius"
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

if( (BUILD_wireshark AND QT_FOUND) OR (BUILD_wireshark_gtk AND GTK_FOUND) )
	set(WIRESHARK_SRC
		capture_info.c
		capture_opts.c
		file.c
		fileset.c
		${SHARK_COMMON_SRC}
		${PLATFORM_UI_SRC}
	)
	set(wireshark_FILES
		${WIRESHARK_SRC}
		${CMAKE_BINARY_DIR}/image/wireshark.rc
		${PLATFORM_UI_RC_FILES}
	)
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
		qtui
		ui
		capchild
		caputils
		${QT_LIBRARIES}
		${GTHREAD2_LIBRARIES}
		wscodecs
		${LIBEPAN_LIBS}
		${APPLE_APPLICATION_SERVICES_LIBRARY}
		${APPLE_APPKIT_LIBRARY}
		${APPLE_CORE_FOUNDATION_LIBRARY}
		${APPLE_SYSTEM_CONFIGURATION_LIBRARY}
		${NL_LIBRARIES}
		${WIN_VERSION_LIBRARY}
	)

	add_executable(wireshark WIN32 MACOSX_BUNDLE wireshark-qt.cpp ${wireshark_FILES} ${EXTRA_BUNDLE_FILES})
	if(QT_VERSION EQUAL 4)
		target_compile_definitions(wireshark PRIVATE Q_NULLPTR=NULL)
	endif()
	add_dependencies(wireshark version)
	set(PROGLIST ${PROGLIST} wireshark)
	if(CMAKE_VERSION VERSION_LESS "2.8.12"
	    AND (CMAKE_CXX_COMPILER_ID STREQUAL "GNU"
	    AND NOT CMAKE_CXX_COMPILER_VERSION VERSION_LESS 5.0))
		#
		# https://doc.qt.io/qt-5/cmake-manual.html says that for CMake
		# versions older than 2.8.12,
		# Qt5<Module>_EXECUTABLE_COMPILE_FLAGS must be added such that
		# -fPIC is included. We should not do add this to
		# CMAKE_CXX_FLAGS though since it may end up before the -fPIE
		# option. Instead, add it to the target COMPILE_FLAGS. This
		# option is deprecated in newer CMake versions and not necessary
		# either since Qt uses the INTERFACE_COMPILE_OPTIONS property.
		#
		set_target_properties(wireshark PROPERTIES COMPILE_FLAGS "${Qt5Widgets_EXECUTABLE_COMPILE_FLAGS}")
	endif()
	set_target_properties(wireshark PROPERTIES
		LINK_FLAGS "${WS_LINK_FLAGS}"
		FOLDER "Executables"
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
		# Add a wrapper script which opens the bundle. This adds
		# convenience but makes debugging more difficult.
		file(REMOVE ${CMAKE_BINARY_DIR}/run/wireshark)
		file(WRITE ${CMAKE_BINARY_DIR}/run/wireshark "#!/bin/sh\n")
		file(APPEND ${CMAKE_BINARY_DIR}/run/wireshark "# Generated by ${CMAKE_CURRENT_LIST_FILE}\n")
		file(APPEND ${CMAKE_BINARY_DIR}/run/wireshark "exec ${CMAKE_BINARY_DIR}/run/Wireshark.app/Contents/MacOS/Wireshark \"\$\@\"\n")
		execute_process(COMMAND chmod a+x ${CMAKE_BINARY_DIR}/run/wireshark)
	endif()

	target_link_libraries(wireshark ${wireshark_LIBS})
	install(
		TARGETS wireshark
		RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
		BUNDLE DESTINATION ${CMAKE_INSTALL_BINDIR}
	)

	if(WIN32 AND Qt5Core_FOUND)
		# Use windeployqt to copy our required DLLs to the run path.
		# Ideally one of the modules in ${QTDIR}/lib/cmake would expose
		# the path to windeployqt. For that matter having a reliable
		# path to qmake would be *amazingly convenient*. We don't have
		# either of those so we try to discover the path via Qt5Core.
		# http://stackoverflow.com/questions/24650936/qt5-with-cmake-how-to-find-qt-translations-dir

		get_target_property(_qmake_location Qt5::qmake IMPORTED_LOCATION)
		get_filename_component(_qt_bin_path "${_qmake_location}" DIRECTORY)
		find_program(QT_WINDEPLOYQT_EXECUTABLE windeployqt
			HINTS "${_qmake_location}"
			DOC "Path to the windeployqt utility."
		)
		if (NOT "${QT_WINDEPLOYQT_EXECUTABLE}" STREQUAL "QT_WINDEPLOYQT_EXECUTABLE-NOTFOUND")
			set(QT_BIN_PATH "${_qt_bin_path}" CACHE INTERNAL
				"Path to qmake, windeployqt, and other Qt utilities."
			)
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
					"$<TARGET_FILE:wireshark>"
			)
			add_dependencies(copy_qt_dlls wireshark)
		endif()
	endif(WIN32 AND Qt5Core_FOUND)
endif()

# Common properties for CLI executables
macro(set_extra_executable_properties _executable _folder)
	set_target_properties(${_executable} PROPERTIES
		LINK_FLAGS "${WILDCARD_OBJ} ${WS_LINK_FLAGS}"
		FOLDER ${_folder}
	)

	set(PROGLIST ${PROGLIST} ${_executable})

	if(ENABLE_APPLICATION_BUNDLE)
		set_target_properties(${_executable} PROPERTIES
			RUNTIME_OUTPUT_DIRECTORY run/Wireshark.app/Contents/MacOS
		)
		# Add a wrapper script which runs each executable from the
		# correct location. This adds convenience but makes debugging
		# more difficult.
		file(REMOVE ${CMAKE_BINARY_DIR}/run/${_executable})
		file(WRITE ${CMAKE_BINARY_DIR}/run/${_executable} "#!/bin/sh\n")
		file(APPEND ${CMAKE_BINARY_DIR}/run/${_executable} "exec ${CMAKE_BINARY_DIR}/run/Wireshark.app/Contents/MacOS/${_executable} \"\$\@\"\n")
		execute_process(COMMAND chmod a+x ${CMAKE_BINARY_DIR}/run/${_executable})
	endif()
endmacro()

macro(set_extcap_executable_properties _executable)
	set_target_properties(${_executable} PROPERTIES FOLDER "Executables/Extcaps")

	set(PROGLIST ${PROGLIST} ${_executable})

	if(WIN32)
		set_target_properties(${_executable} PROPERTIES
			LINK_FLAGS "${WS_LINK_FLAGS}"
			RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/run/extcap
			RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/run/Debug/extcap
			RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/run/Release/extcap
			RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL ${CMAKE_BINARY_DIR}/run/MinSizeRel/extcap
			RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO ${CMAKE_BINARY_DIR}/run/RelWithDebInfo/extcap
		)
	else()
		set_target_properties(${_executable} PROPERTIES
			LINK_FLAGS "${WS_LINK_FLAGS}"
			RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/run/extcap
		)
		if(ENABLE_APPLICATION_BUNDLE)
			set_target_properties(${_executable} PROPERTIES
				RUNTIME_OUTPUT_DIRECTORY run/Wireshark.app/Contents/MacOS/extcap
			)
			# Add a wrapper script which runs each executable from the
			# correct location. This adds convenience but makes debugging
			# more difficult.
			file(REMOVE ${CMAKE_BINARY_DIR}/run/${_executable})
			file(WRITE ${CMAKE_BINARY_DIR}/run/${_executable} "#!/bin/sh\n")
			file(APPEND ${CMAKE_BINARY_DIR}/run/${_executable} "exec ${CMAKE_BINARY_DIR}/run/Wireshark.app/Contents/MacOS/extcap/${_executable} \"\$\@\"\n")
			execute_process(COMMAND chmod a+x ${CMAKE_BINARY_DIR}/run/${_executable})
		endif()
	endif()
endmacro()

if(BUILD_wireshark_gtk AND GTK_FOUND)
	set(wireshark_gtk_LIBS
		gtkui
		ui
		capchild
		caputils
		${GTK2_LIBRARIES}
		${GTK3_LIBRARIES}
		${GTHREAD2_LIBRARIES}
		wscodecs
		${PORTAUDIO_LIBRARIES}
		${LIBEPAN_LIBS}
		${APPLE_APPLICATION_SERVICES_LIBRARY}
		${APPLE_CORE_SERVICES_LIBRARY}
		${APPLE_SYSTEM_CONFIGURATION_LIBRARY}
		${NL_LIBRARIES}
		${WIN_COMCTL32_LIBRARY}
	)
	# wireshark and wireshark-gtk share wireshark_FILES

	add_executable(wireshark-gtk WIN32 ${wireshark_FILES})
	add_dependencies(wireshark-gtk version)
	set(PROGLIST ${PROGLIST} wireshark-gtk)
	set_target_properties(wireshark-gtk PROPERTIES
		LINK_FLAGS "${WS_LINK_FLAGS}"
		FOLDER "Executables"
	)
	target_link_libraries(wireshark-gtk ${wireshark_gtk_LIBS})
	install(TARGETS wireshark-gtk RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

	if(WIN32)
		add_custom_target(copy_gtk_dlls)
		set_target_properties(copy_gtk_dlls PROPERTIES FOLDER "Copy Tasks")
		add_custom_command(TARGET copy_gtk_dlls PRE_BUILD
			COMMAND ${CMAKE_COMMAND} -E make_directory "${_dll_output_dir}"
		)

		if(GTK2_FOUND)
			set(_gtk_dll_dir "${GTK2_DLL_DIR}")
			set(_gtk_etc_dir "${GTK2_ETC_DIR}")
			set(_gtk_dlls "${GTK2_DLLS}")
			set(_gtk_etc_dir "${GTK2_ETC_DIR}")
		else()
			set(_gtk_dll_dir "${GTK3_DLL_DIR}")
			set(_gtk_dlls "${GTK3_DLLS}")
			set(_gtk_etc_dir "${GTK3_ETC_DIR}")
		endif()

		foreach(_dll ${_gtk_dlls})
			add_custom_command(TARGET copy_gtk_dlls PRE_BUILD
				COMMAND ${CMAKE_COMMAND} -E copy_if_different
					"${_gtk_dll_dir}/${_dll}" "${_dll_output_dir}"
			)
		endforeach(_dll)

		# /etc
		add_custom_command(TARGET copy_gtk_dlls PRE_BUILD
			COMMAND ${CMAKE_COMMAND} -E make_directory "${_dll_output_dir}/etc"
		)
		add_custom_command(TARGET copy_gtk_dlls PRE_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy_directory
				"${_gtk_etc_dir}" "${_dll_output_dir}/etc"
		)

		# XXX - Omitting ${GTK2_LIB_DIR}\loaders copying from Makefile.nmake
		if(GTK2_FOUND)
			# Engines
			set (_engines_output_dir "${_dll_output_dir}/lib/gtk-2.0/2.10.0/engines")
			add_custom_command(TARGET copy_gtk_dlls PRE_BUILD
				COMMAND ${CMAKE_COMMAND} -E make_directory "${_engines_output_dir}"
			)
			foreach(_dll ${GTK2_ENGINES_DLLS})
				add_custom_command(TARGET copy_gtk_dlls PRE_BUILD
					COMMAND ${CMAKE_COMMAND} -E copy_if_different
						"${GTK2_ENGINES_DLL_DIR}/${_dll}" "${_engines_output_dir}"
				)
			endforeach(_dll)

			# Themes
			add_custom_command(TARGET copy_gtk_dlls PRE_BUILD
				COMMAND ${CMAKE_COMMAND} -E copy_if_different
					"${GTK2_THEMES_DIR}/gtkrc" "${_dll_output_dir}/etc/gtk-2.0"
			)

			# Modules
			add_custom_command(TARGET copy_gtk_dlls PRE_BUILD
				COMMAND ${CMAKE_COMMAND} -E copy_directory
					"${GTK2_LIB_DIR}" "${_dll_output_dir}/lib/gtk-2.0"
			)
		else()
			add_custom_command(TARGET copy_gtk_dlls PRE_BUILD
				COMMAND ${CMAKE_COMMAND} -E copy_directory
					"${CMAKE_SOURCE_DIR}/ui/win32/settings.ini" "${_dll_output_dir}/etc"
			)
		endif()

		add_dependencies(wireshark-gtk copy_gtk_dlls copy_cli_dlls)
	endif(WIN32)
endif()

register_tap_files(tshark-tap-register.c
	${TSHARK_TAP_SRC}
)

if(BUILD_tshark)
	set(tshark_LIBS
		ui
		capchild
		caputils
		${LIBEPAN_LIBS}
		${APPLE_CORE_FOUNDATION_LIBRARY}
		${APPLE_SYSTEM_CONFIGURATION_LIBRARY}
	)
	set(tshark_FILES
		capture_opts.c
		tshark-tap-register.c
		tshark.c
		${TSHARK_TAP_SRC}
		${SHARK_COMMON_SRC}
		${CMAKE_BINARY_DIR}/image/tshark.rc
	)
	add_executable(tshark ${tshark_FILES})
	add_dependencies(tshark version)
	set_extra_executable_properties(tshark "Executables")
	target_link_libraries(tshark ${tshark_LIBS})
	install(TARGETS tshark RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_tfshark)
	set(tfshark_LIBS
		ui
		${LIBEPAN_LIBS}
		${APPLE_CORE_FOUNDATION_LIBRARY}
		${APPLE_SYSTEM_CONFIGURATION_LIBRARY}
	)
	set(tfshark_FILES
		tfshark.c
		${TSHARK_TAP_SRC}
		${SHARK_COMMON_SRC}
		${CMAKE_BINARY_DIR}/image/tfshark.rc
	)
	add_executable(tfshark ${tfshark_FILES})
	add_dependencies(tfshark version)
	set_extra_executable_properties(tfshark "Executables")
	target_link_libraries(tfshark ${tfshark_LIBS})
	install(TARGETS tfshark RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_rawshark AND PCAP_FOUND)
	set(rawshark_LIBS
		caputils
		ui
		${LIBEPAN_LIBS}
		${APPLE_CORE_FOUNDATION_LIBRARY}
		${APPLE_SYSTEM_CONFIGURATION_LIBRARY}
	)
	set(rawshark_FILES
		${SHARK_COMMON_SRC}
		rawshark.c
		${CMAKE_BINARY_DIR}/image/rawshark.rc
	)
	add_executable(rawshark ${rawshark_FILES})
	add_dependencies(rawshark version)
	set_extra_executable_properties(rawshark "Executables")
	target_link_libraries(rawshark ${rawshark_LIBS})
	install(TARGETS rawshark RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_sharkd)
	set(sharkd_LIBS
		ui
		wscodecs
		${LIBEPAN_LIBS}
		${APPLE_CORE_FOUNDATION_LIBRARY}
		${APPLE_SYSTEM_CONFIGURATION_LIBRARY}
	)
	set(sharkd_FILES
		sharkd.c
		sharkd_daemon.c
		sharkd_session.c
		${SHARK_COMMON_SRC}
	)
	add_executable(sharkd ${sharkd_FILES})
	add_dependencies(sharkd version)
	set_extra_executable_properties(sharkd "Executables")
	target_link_libraries(sharkd ${sharkd_LIBS})
	install(TARGETS sharkd RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_dftest)
	set(dftest_LIBS
		ui
		${LIBEPAN_LIBS}
	)
	set(dftest_FILES
		dftest.c
	)
	add_executable(dftest ${dftest_FILES})
	add_dependencies(dftest version)
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
		${PCAP_LIBRARIES}
		${CARES_LIBRARIES}
		${ZLIB_LIBRARIES}
	)
	set(randpkt_FILES
		randpkt.c
		version_info.c
	)
	add_executable(randpkt ${randpkt_FILES})
	add_dependencies(randpkt version)
	set_extra_executable_properties(randpkt "Executables")
	target_link_libraries(randpkt ${randpkt_LIBS})
	install(TARGETS randpkt RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_fuzzshark)
	set(fuzzshark_LIBS
		${LIBEPAN_LIBS}
	)
	set(fuzzshark_FILES
		tools/oss-fuzzshark/fuzzshark.c
		tools/oss-fuzzshark/StandaloneFuzzTargetMain.c
		version_info.c
	)
	add_executable(fuzzshark ${fuzzshark_FILES})
	add_dependencies(fuzzshark version)
	set_extra_executable_properties(fuzzshark "Executables")
	target_link_libraries(fuzzshark ${fuzzshark_LIBS})
endif()

if(BUILD_text2pcap)
	set(text2pcap_LIBS
		writecap
		wsutil
		${M_LIBRARIES}
		${ZLIB_LIBRARIES}
	)
	set(text2pcap_FILES
		text2pcap.c
		version_info.c
	)
	add_lex_files(text2pcap_LEX_FILES text2pcap_FILES
		text2pcap-scanner.l
	)
	add_executable(text2pcap ${text2pcap_FILES}
		${CMAKE_BINARY_DIR}/image/text2pcap.rc)
	add_dependencies(text2pcap version)
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
		mergecap.c
		version_info.c
		${CMAKE_BINARY_DIR}/image/mergecap.rc
	)
	add_executable(mergecap ${mergecap_FILES})
	add_dependencies(mergecap version)
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
		reordercap.c
		version_info.c
		${CMAKE_BINARY_DIR}/image/reordercap.rc
	)
	add_executable(reordercap ${reordercap_FILES})
	add_dependencies(reordercap version)
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
		capinfos.c
		version_info.c
		${CMAKE_BINARY_DIR}/image/capinfos.rc
	)
	add_executable(capinfos ${capinfos_FILES})
	add_dependencies(capinfos version)
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
		captype.c
		version_info.c
		${CMAKE_BINARY_DIR}/image/captype.rc
	)
	add_executable(captype ${captype_FILES})
	add_dependencies(captype version)
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
		editcap.c
		version_info.c
		${CMAKE_BINARY_DIR}/image/editcap.rc
	)
	add_executable(editcap ${editcap_FILES})
	add_dependencies(editcap version)
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
		${PCAP_LIBRARIES}
		${CAP_LIBRARIES}
		${GLIB2_LIBRARIES}
		${GTHREAD2_LIBRARIES}
		${ZLIB_LIBRARIES}
		${APPLE_CORE_FOUNDATION_LIBRARY}
		${APPLE_SYSTEM_CONFIGURATION_LIBRARY}
		${NL_LIBRARIES}
	)
	set(dumpcap_FILES
		capture_opts.c
		capture_stop_conditions.c
		conditions.c
		dumpcap.c
		ringbuffer.c
		sync_pipe_write.c
		version_info.c
		${CMAKE_BINARY_DIR}/image/dumpcap.rc
	)
	add_executable(dumpcap ${dumpcap_FILES})
	add_dependencies(dumpcap version)
	set_extra_executable_properties(dumpcap "Executables")
	target_link_libraries(dumpcap ${dumpcap_LIBS})
	install(TARGETS dumpcap
			RUNTIME	DESTINATION ${CMAKE_INSTALL_BINDIR}
			PERMISSIONS ${DUMPCAP_SETUID}
				OWNER_READ OWNER_WRITE OWNER_EXECUTE
				GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
	)
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

	if (NOT "${MAKENSIS_EXECUTABLE}" STREQUAL "MAKENSIS_EXECUTABLE-NOTFOUND")
		add_subdirectory( packaging/nsis EXCLUDE_FROM_ALL )
		ADD_NSIS_UNINSTALLER_TARGET()
		ADD_NSIS_PACKAGE_TARGET()
	endif()

	find_package( WiX )

	if (NOT "${WIX_CANDLE_EXECUTABLE}" STREQUAL "WIX_CANDLE_EXECUTABLE-NOTFOUND")
		add_subdirectory( packaging/wix EXCLUDE_FROM_ALL )
		ADD_WIX_PACKAGE_TARGET()
	endif()

	find_package( PortableApps )
	if (
		NOT "${PORTABLEAPPS_LAUNCHER_GENERATOR_EXECUTABLE}" STREQUAL "PORTABLEAPPS_LAUNCHER_GENERATOR_EXECUTABLE-NOTFOUND"
		AND
		NOT "${PORTABLEAPPS_INSTALLER_EXECUTABLE}" STREQUAL "PORTABLEAPPS_INSTALLER_EXECUTABLE-NOTFOUND"
	)
		add_subdirectory( packaging/portableapps EXCLUDE_FROM_ALL )
		ADD_PORTABLEAPPS_PACKAGE_TARGET()
	endif()
endif()

add_custom_target(extcaps)

if(BUILD_androiddump)
	if(EXTCAP_ANDROIDDUMP_LIBPCAP)
		if(HAVE_LIBPCAP)
			set(androiddump_LIBS
				ui
				${GLIB2_LIBRARIES}
				${PCAP_LIBRARIES}
			)
		else()
			message(FATAL_ERROR "You are trying to build androiddump with libpcap but do not have it")
		endif()
	else()
		set(androiddump_LIBS
			ui
			wiretap
			${GLIB2_LIBRARIES}
			${ZLIB_LIBRARIES}
			${CMAKE_DL_LIBS}
		)
	endif()
	set(androiddump_FILES
		extcap/androiddump.c
		extcap/extcap-base.c
	)

	add_executable(androiddump WIN32 ${androiddump_FILES})
	set_extcap_executable_properties(androiddump)
	target_link_libraries(androiddump ${androiddump_LIBS})
	install(TARGETS androiddump RUNTIME DESTINATION ${EXTCAP_DIR})
	add_dependencies(extcaps androiddump)
endif()

if(BUILD_sshdump AND LIBSSH_FOUND)
	set(sshdump_LIBS
		wsutil
		${GLIB2_LIBRARIES}
		${CMAKE_DL_LIBS}
		${LIBSSH_LIBRARIES}
	)
	set(sshdump_FILES
		extcap/sshdump.c
		extcap/extcap-base.c
		extcap/ssh-base.c
	)

	add_executable(sshdump WIN32 ${sshdump_FILES})
	set_extcap_executable_properties(sshdump)
	target_link_libraries(sshdump ${sshdump_LIBS})
	target_include_directories(sshdump PUBLIC ${LIBSSH_INCLUDE_DIR})
	install(TARGETS sshdump RUNTIME DESTINATION ${EXTCAP_DIR})
	add_dependencies(extcaps sshdump)
elseif (BUILD_sshdump)
	#message( WARNING "Cannot find libssh, cannot build sshdump" )
endif()

if(BUILD_ciscodump AND LIBSSH_FOUND)
	set(ciscodump_LIBS
		writecap
		wsutil
		${GLIB2_LIBRARIES}
		${CMAKE_DL_LIBS}
		${LIBSSH_LIBRARIES}
	)
	set(ciscodump_FILES
		extcap/ciscodump.c
		extcap/extcap-base.c
		extcap/ssh-base.c
	)

	add_executable(ciscodump WIN32 ${ciscodump_FILES})
	set_extcap_executable_properties(ciscodump)
	target_link_libraries(ciscodump ${ciscodump_LIBS})
	target_include_directories(ciscodump PUBLIC ${LIBSSH_INCLUDE_DIR})
	install(TARGETS ciscodump RUNTIME DESTINATION ${EXTCAP_DIR})
	add_dependencies(extcaps ciscodump)
elseif (BUILD_ciscodump)
	#message( WARNING "Cannot find libssh, cannot build ciscodump" )
endif()

if(BUILD_udpdump)
	set(udpdump_LIBS
		${GLIB2_LIBRARIES}
		${CMAKE_DL_LIBS}
		wsutil
		writecap
	)
	set(udpdump_FILES
		extcap/udpdump.c
		extcap/extcap-base.c
	)

	add_executable(udpdump WIN32 ${udpdump_FILES})
	set_extcap_executable_properties(udpdump)
	target_link_libraries(udpdump ${udpdump_LIBS})
	install(TARGETS udpdump RUNTIME DESTINATION ${EXTCAP_DIR})
	add_dependencies(extcaps udpdump)
endif()

if(BUILD_randpktdump)
	set(randpktdump_LIBS
		randpkt_core
		ui
		wiretap
		${GLIB2_LIBRARIES}
		${ZLIB_LIBRARIES}
		${CMAKE_DL_LIBS}
	)
	set(randpktdump_FILES
		extcap/extcap-base.c
		extcap/randpktdump.c
	)

	add_executable(randpktdump WIN32 ${randpktdump_FILES})
	set_extcap_executable_properties(randpktdump)
	target_link_libraries(randpktdump ${randpktdump_LIBS})
	install(TARGETS randpktdump RUNTIME DESTINATION ${EXTCAP_DIR})
	add_dependencies(extcaps randpktdump)
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
	target_include_directories(mmdbresolve PUBLIC ${MAXMINDDB_INCLUDE_DIR})
	install(TARGETS mmdbresolve RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(ENABLE_APPLICATION_BUNDLE)
	add_custom_target(app_bundle)
	set_target_properties(app_bundle PROPERTIES FOLDER "Copy Tasks")
	add_custom_command(TARGET app_bundle
		POST_BUILD
		COMMAND "${CMAKE_BINARY_DIR}/packaging/macosx/osx-app.sh"
		WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/run"
	)
	add_dependencies(app_bundle ${PROGLIST})

	add_custom_target(dmg_package_prep DEPENDS app_bundle)

	ADD_CUSTOM_COMMAND(
		OUTPUT ${CMAKE_BINARY_DIR}/packaging/macosx/PkgInfo
		COMMAND ${CMAKE_COMMAND} -E echo APPLWshk > ${CMAKE_BINARY_DIR}/packaging/macosx/PkgInfo
	)

	ADD_CUSTOM_TARGET( dmg_package
		COMMAND ${CMAKE_COMMAND} -E copy_directory
					${CMAKE_SOURCE_DIR}/packaging/macosx/ChmodBPF
					${CMAKE_BINARY_DIR}/run/ChmodBPF
		COMMAND ${CMAKE_COMMAND} -E copy_directory
					${CMAKE_SOURCE_DIR}/packaging/macosx/Scripts
					${CMAKE_BINARY_DIR}/run/Scripts
		COMMAND ${CMAKE_COMMAND} -E copy_directory
					${CMAKE_SOURCE_DIR}/packaging/macosx/utility-launcher
					${CMAKE_BINARY_DIR}/run/utility-launcher
		COMMAND ${CMAKE_COMMAND} -E copy_if_different
					${CMAKE_SOURCE_DIR}/COPYING
					${CMAKE_BINARY_DIR}/run/COPYING.txt
		COMMAND ${CMAKE_COMMAND} -E copy_directory
					${CMAKE_SOURCE_DIR}/packaging/macosx/Wireshark_package.pmdoc
					${CMAKE_BINARY_DIR}/run/Wireshark_package.pmdoc
		COMMAND ${CMAKE_COMMAND} -E copy_if_different
					${CMAKE_BINARY_DIR}/packaging/macosx/Wireshark_package.pmdoc/index.xml
					${CMAKE_BINARY_DIR}/run/Wireshark_package.pmdoc/index.xml
		COMMAND ${CMAKE_COMMAND} -E copy_if_different
					${CMAKE_SOURCE_DIR}/packaging/macosx/dmg_background.png
					${CMAKE_BINARY_DIR}/run/dmg_background.png
		COMMAND bash -x ${CMAKE_BINARY_DIR}/packaging/macosx/osx-dmg.sh
			--source-directory ${CMAKE_SOURCE_DIR}/packaging/macosx
		# Unlike nsis_package_prep + nsis_package, we can add a direct
		# dependency here.
		DEPENDS dmg_package_prep
		# We create Wireshark.app in "run". Do our work there.
		WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/run
	)

endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	find_program(RPMBUILD_EXECUTABLE rpmbuild)
	find_program(GIT_EXECUTABLE git)
endif()

# RPM target must be built from a git checkout. We simply test for .git for now.
if(RPMBUILD_EXECUTABLE AND GIT_EXECUTABLE AND EXISTS "${CMAKE_SOURCE_DIR}/.git")
	foreach(_rpm_dir BUILD RPMS SOURCES SPECS SRPMS)
		file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/packaging/rpm/${_rpm_dir}")
	endforeach()

	set(_rpmbuild_with_args)
	if(CMAKE_GENERATOR STREQUAL "Ninja")
		list(APPEND _rpmbuild_with_args --with ninja)
	endif()
	if (BUILD_wireshark)
		list(APPEND _rpmbuild_with_args --with qt5)
	endif()
	if (BUILD_mmdbresolve)
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
	if (LIBXML2_FOUND)
		list(APPEND _rpmbuild_with_args --with libxml2)
	endif()
	if (NGHTTP2_FOUND)
		list(APPEND _rpmbuild_with_args --with nghttp2)
	endif()

	execute_process(
		COMMAND git describe --abbrev=8 --match v[1-9]*
		OUTPUT_VARIABLE _git_description
		OUTPUT_STRIP_TRAILING_WHITESPACE
		WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
	)
	string(SUBSTRING "${_git_description}" 1 -1 RPM_TARBALL_VERSION)
	string(REPLACE "-" "_" RPM_VERSION "${RPM_TARBALL_VERSION}")
	configure_file(packaging/rpm/wireshark.spec.in ${CMAKE_BINARY_DIR}/packaging/rpm/SPECS/wireshark.spec)

	set(_export_tarball "${CPACK_PACKAGE_NAME}-${RPM_TARBALL_VERSION}.tar.xz")
	add_custom_command(
		OUTPUT "${CMAKE_SOURCE_DIR}/${_export_tarball}"
		COMMAND ./tools/git-export-release.sh "${_git_description}"
		# XXX Add an option to git-export-release.sh to write to a
		# specific directory so that we can get rid of `ln` below.
		WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
	)
	add_custom_target(rpm-package
		COMMAND ${CMAKE_COMMAND} -E create_symlink
			"${CMAKE_SOURCE_DIR}/${_export_tarball}"
			"SOURCES/${_export_tarball}"
		COMMAND ${RPMBUILD_EXECUTABLE}
			--define "_topdir ${CMAKE_BINARY_DIR}/packaging/rpm"
			--define "_prefix ${CMAKE_INSTALL_PREFIX}"
			${_rpmbuild_with_args}
			-ba SPECS/wireshark.spec
		DEPENDS "${CMAKE_SOURCE_DIR}/${_export_tarball}"
		WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/packaging/rpm"
		COMMENT "Create a tarball from the current git commit."
	)
endif()

set(CLEAN_C_FILES
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
	${dumpcap_FILES}
	${androiddump_FILES}
	${sshdump_FILES}
	${ciscodump_FILES}
	${mmdbresolve_FILES}
)

# Make sure we don't pass /WX to rc.exe. Rc doesn't have a /WX flag,
# but it does have /W (warn about invalid code pages) and /X (ignore
# the INCLUDE environment variable).
# This should apparently be handled for us via CMAKE_RC_FLAG_REGEX
# in CMakeRCInformation.cmake but that doesn't appear to work.
if (WIN32)
	list(FILTER CLEAN_C_FILES EXCLUDE REGEX ".*\\.rc")
endif (WIN32)

set_source_files_properties(
	${CLEAN_C_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

install(
	FILES
		${INSTALL_FILES}
	PERMISSIONS
		OWNER_WRITE OWNER_READ
		GROUP_READ
		WORLD_READ
	DESTINATION
		${CMAKE_INSTALL_DATADIR}/${CPACK_PACKAGE_NAME}
)

set(SHARK_PUBLIC_HEADERS
	cfile.h
	file.h
	globals.h
	log.h
	ws_attributes.h
	ws_compiler_tests.h
	ws_diag_control.h
	ws_symbol_export.h
)

if(NOT WIN32)
	install(
		FILES
			${SHARK_PUBLIC_HEADERS}
		DESTINATION
			${CMAKE_INSTALL_INCLUDEDIR}/${CPACK_PACKAGE_NAME}
	)
endif()

# Install icons and other desktop files for Freedesktop.org-compliant desktops.
if(((BUILD_wireshark AND QT_FOUND) OR BUILD_wireshark_gtk) AND NOT (WIN32 OR APPLE))
	install(FILES wireshark-mime-package.xml
		DESTINATION "${CMAKE_INSTALL_DATADIR}/mime/packages"
		RENAME wireshark.xml
	)
	install(FILES wireshark.appdata.xml
		DESTINATION "${CMAKE_INSTALL_DATADIR}/appdata"
	)
	if(BUILD_wireshark AND QT_FOUND)
		install(FILES wireshark.desktop
			DESTINATION "${CMAKE_INSTALL_DATADIR}/applications")
	endif()
	if(BUILD_wireshark_gtk)
		install(FILES wireshark-gtk.desktop
			DESTINATION "${CMAKE_INSTALL_DATADIR}/applications")
	endif()
	foreach(size 16 24 32 48 64 128 256)
		install(FILES image/wsicon${size}.png
			DESTINATION "${CMAKE_INSTALL_DATADIR}/icons/hicolor/${size}x${size}/apps"
			RENAME wireshark.png)
		install(FILES image/WiresharkDoc-${size}.png
			DESTINATION "${CMAKE_INSTALL_DATADIR}/icons/hicolor/${size}x${size}/mimetypes"
			RENAME application-wireshark-doc.png)
	endforeach()
	install(FILES image/wsicon.svg
		DESTINATION "${CMAKE_INSTALL_DATADIR}/icons/hicolor/scalable/apps"
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
		${CMAKE_INSTALL_DATADIR}/${CPACK_PACKAGE_NAME}
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

set(CMAKE_INSTALL_MODULES_DIR ${CMAKE_INSTALL_LIBDIR}/${CPACK_PACKAGE_NAME})
configure_file("${CMAKE_MODULE_PATH}/WiresharkConfig.cmake.in" "${CMAKE_BINARY_DIR}/WiresharkConfig.cmake" @ONLY)
configure_file("${CMAKE_MODULE_PATH}/WiresharkConfigVersion.cmake.in" "${CMAKE_BINARY_DIR}/WiresharkConfigVersion.cmake" @ONLY)
install(
	FILES
		${CMAKE_MODULE_PATH}/FindGLIB2.cmake
		${CMAKE_MODULE_PATH}/FindWireshark.cmake
		${CMAKE_MODULE_PATH}/FindWSWinLibs.cmake
		${CMAKE_MODULE_PATH}/UseAsn2Wrs.cmake
		${CMAKE_MODULE_PATH}/LocatePythonModule.cmake
		${CMAKE_MODULE_PATH}/UseMakePluginReg.cmake
		${CMAKE_BINARY_DIR}/WiresharkConfig.cmake
		${CMAKE_BINARY_DIR}/WiresharkConfigVersion.cmake
	DESTINATION
		${CMAKE_INSTALL_MODULES_DIR}
)

# Test suite wrapper
if(ENABLE_APPLICATION_BUNDLE)
	set(TEST_SH_BIN_DIR ${CMAKE_BINARY_DIR}/run)
else()
	set(TEST_SH_BIN_DIR $<TARGET_FILE_DIR:epan>)
endif()

add_custom_target(test-sh
	COMMAND ${CMAKE_COMMAND}
		-DCMAKE_MODULE_PATH=${CMAKE_MODULE_PATH}
		-DTEST_SH_BIN_DIR=${TEST_SH_BIN_DIR}
		-DTEST_SH_SRC_DIR=${CMAKE_SOURCE_DIR}/test
		-P ${CMAKE_SOURCE_DIR}/cmake/modules/GenerateTestSh.cmake
	DEPENDS ${CMAKE_SOURCE_DIR}/cmake/modules/GenerateTestSh.cmake
)
set_target_properties(test-sh PROPERTIES
	FOLDER "Tests"
	EXCLUDE_FROM_DEFAULT_BUILD True
)

add_custom_target(test-programs
	DEPENDS test-sh
		exntest
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
find_program(BASH_EXECUTABLE bash)
if (BASH_EXECUTABLE)
	enable_testing()
	add_test(
		NAME all_tests
		COMMAND ${BASH_EXECUTABLE} ${CMAKE_SOURCE_DIR}/test/test.sh -c -s all
		)
	set_tests_properties(all_tests PROPERTIES TIMEOUT 600)
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
	if (NOT "${HARDENING_CHECK_EXECUTABLE}" STREQUAL "HARDENING_CHECK_EXECUTABLE-NOTFOUND")
		foreach(_prog ${PROGLIST})
			get_target_property(_prog_dir ${_prog} RUNTIME_OUTPUT_DIRECTORY)
			if ("${_prog_dir}" STREQUAL "_prog_dir-NOTFOUND")
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

include( UseCheckAPI )
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
if (NOT "${SHELLCHECK_EXECUTABLE}" STREQUAL "SHELLCHECK_EXECUTABLE-NOTFOUND")
	add_custom_target(shellcheck)
	set_target_properties(shellcheck PROPERTIES FOLDER "Tests")
	# --external-sources requires 0.4.0 or later.
	add_custom_command(TARGET shellcheck POST_BUILD
		COMMAND shellcheck --external-sources
			tools/fuzz-test.sh
			tools/randpkt-test.sh
			tools/test-captures.sh
			tools/valgrind-wireshark.sh
		WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
	)
endif()

#
# Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
