# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

project(Wireshark C CXX)

# Updated by make-version.pl
set(GIT_REVISION 0)
set(PROJECT_MAJOR_VERSION 2)
set(PROJECT_MINOR_VERSION 2)
set(PROJECT_PATCH_VERSION 3)
set(PROJECT_BUILD_VERSION ${GIT_REVISION})
set(PROJECT_VERSION_EXTENSION "")

if(DEFINED ENV{WIRESHARK_VERSION_EXTRA})
	set(PROJECT_VERSION_EXTENSION "$ENV{WIRESHARK_VERSION_EXTRA}")
endif()

set(PROJECT_VERSION "${PROJECT_MAJOR_VERSION}.${PROJECT_MINOR_VERSION}.${PROJECT_PATCH_VERSION}${PROJECT_VERSION_EXTENSION}")

message(STATUS "Generating build using CMake ${CMAKE_VERSION}")
if(WIN32)
	# Needed for proper Qt linking. See
	# http://www.cmake.org/cmake/help/v3.0/policy/CMP0020.html
	# 3.1.3 is the currently supported version
	cmake_minimum_required(VERSION 3.1.3)
else()
	cmake_minimum_required(VERSION 2.8.8)
endif()

# Needs to be set after cmake_minimum_required or cmake_policy(VERSION)
# Policy since 2.6.1
cmake_policy(SET CMP0008 NEW)
# Policy since 2.6.3
# Backward compatibility for versions < 2.6.3
cmake_policy(SET CMP0011 OLD)
# Policy since 2.8.1
cmake_policy(SET CMP0015 NEW)

#Where to find local cmake scripts
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules)

# Set old behaviour for LOCATION property
if (POLICY CMP0026)
	cmake_policy(SET CMP0026 OLD)
endif()

# Set old behaviour for variable quoting
if (POLICY CMP0054)
	cmake_policy(SET CMP0054 OLD)
endif()

# Set old behaviour for MACOSX_RPATH
if (POLICY CMP0042)
	cmake_policy(SET CMP0042 OLD)
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
		set(PROCESSOR_ARCHITECTURE amd64)
	else()
		set(PROCESSOR_ARCHITECTURE x86)
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
		set( _PROJECT_LIB_DIR "${_WS_BASE_DIR}/Wireshark-${WIRESHARK_TARGET_PLATFORM}-libs-2.2" )
	else()
		# Don't know what to do
		message(FATAL_ERROR "Neither WIRESHARK_BASE_DIR or WIRESHARK_LIB_DIR are defined")
	endif()

	# Download third-party libraries
	file (TO_NATIVE_PATH ${CMAKE_SOURCE_DIR}/tools/win-setup.ps1 _win_setup)
	file (TO_NATIVE_PATH ${_PROJECT_LIB_DIR} _ws_lib_dir)
	if(MSVC14)
		set(_vsversion_args "14")
	elseif(MSVC12)
		set(_vsversion_args "12")
	elseif(MSVC11)
		set(_vsversion_args "11")
	elseif(MSVC10)
		set(_vsversion_args "10")
	else()
		message(FATAL_ERROR "Unsupported compiler ${CMAKE_C_COMPILER}")
	endif()

	# Is it possible to have a one-time, non-cached option in CMake? If
	# so, we could add a "-DFORCE_WIN_SETUP" which passes -Force to
	# win-setup.ps1.
	execute_process(
		COMMAND ${POWERSHELL_COMMAND} "\"${_win_setup}\"" -Destination "${_ws_lib_dir}" -Platform ${WIRESHARK_TARGET_PLATFORM} -VSVersion ${_vsversion_args}
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

# Where to put executables and libraries in the build tree
# Note: Executables and libraries might end end up in a configuration
# subdirectory, e.g. run/Debug or run/Release. We try to set DATAFILE_DIR
# to a corresponding value below.
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

# Under linux the release mode (CMAKE_BUILD_TYPE=release) defines NDEBUG
#Defines CMAKE_INSTALL_BINDIR, CMAKE_INSTALL_DATADIR, etc ...
include(CMakeInstallDirs)

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
include(UseMakeDissectorReg)
include(UseMakeTapReg)
include(UseAsn2Wrs)

include_directories(
	${CMAKE_BINARY_DIR}
	${CMAKE_SOURCE_DIR}
	${CMAKE_SOURCE_DIR}/epan
	${CMAKE_SOURCE_DIR}/tools/lemon
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

# Always enable position-independent code when compiling, even for
# executables, so you can build position-independent executables.
# -pie is added below for non-MSVC.
# Needed when either:
# - Qt5_POSITION_INDEPENDENT_CODE is set and CMake < 2.8.11
# - PIE is wanted (-pie) and you want to add -fPIC/-fPIE automatically.
# This option only has an effect on CMake >= 2.8.9
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if( CMAKE_C_COMPILER_ID MATCHES "MSVC")
	if (MSVC10)
		set(MSC_VER_REQUIRED 1600)
	elseif(MSVC11)
		set(MSC_VER_REQUIRED 1700)
	elseif(MSVC12)
		set(MSC_VER_REQUIRED 1800)
	elseif(MSVC14)
		set(MSC_VER_REQUIRED 1900)
	else()
		message(FATAL_ERROR "You are using an unsupported version of MSVC")
	endif()

	add_definitions(
		/DWIN32_LEAN_AND_MEAN
		"/DMSC_VER_REQUIRED=${MSC_VER_REQUIRED}"
		/D_CRT_SECURE_NO_DEPRECATE
		# NOMINMAX keeps windows.h from defining "min" and "max" via windef.h.
		# This avoids conflicts with the C++ standard library.
		/DNOMINMAX
		# -DPSAPI_VERSION=1                 Programs that must run on earlier versions of Windows as well as Windows 7 and later
		#                                   versions should always call this function as GetProcessMemoryInfo. To ensure correct
		#                                   resolution of symbols, add Psapi.lib to the TARGETLIBS macro and compile the program
		#                                   with -DPSAPI_VERSION=1.To use run-time dynamic linking, load Psapi.dll.
		#                                   http://msdn.microsoft.com/en-us/library/windows/desktop/ms683219(v=vs.85).aspx
		# -DBUILD_WINDOWS                   Starting from VS2013, GetVersionEx is deprecated and we are recommended to use
		#                                   VerifyVersionInfo instead
		#                                   http://msdn.microsoft.com/en-us/library/windows/desktop/ms724429(v=vs.85).aspx
		#                                   http://msdn.microsoft.com/en-us/library/windows/desktop/ms725491(v=vs.85).aspx
		#                                   To continue to use GetVersionEx, we can define BUILD_WINDOWS
		# -D_ALLOW_KEYWORD_MACROS           For VS2012 onwards the, C++ STL does not permit macro redefinitions of keywords
		#                                   (see http://msdn.microsoft.com/en-us/library/bb531344(v=vs.110).aspx)
		#                                   This definition prevents the complaint about the redefinition of inline by WinPCap
		#                                   in pcap-stdinc.h when compiling C++ files, e.g. the Qt UI
		/DPSAPI_VERSION=1
		/DBUILD_WINDOWS
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

	if(MSVC12)
		# /Zo                               Enhanced debugging of optimised code for VS2013 Update 3 and beyond,
		#                                   Assume all VS2013 builds are at least Update 3.
		#                                   See http://msdn.microsoft.com/en-us/library/dn785163.aspx
		set(LOCAL_CFLAGS ${LOCAL_CFLAGS} "/Zo")
	elseif(MSVC14)
		# /Zo                               Enhanced debugging of optimised code
		# /utf-8                            Set Source and Executable character sets to UTF-8
		#                                   VS2015(MSVC14): On by default when /Zi or /Z7 used.
		set(LOCAL_CFLAGS ${LOCAL_CFLAGS} "/Zo" "/utf-8")
	endif()

	if(ENABLE_CODE_ANALYSIS)
		set(LOCAL_CFLAGS ${LOCAL_CFLAGS} "/analyze:WX-")
	endif()

	# Additional compiler warnings to be treated as "Level 3"
	#  when compiling Wireshark sources. (Selected from "level 4" warnings).
	## 4295: array is too small to include a terminating null character
	## 4189: local variable is initialized but not referenced
	set(WARNINGS_CFLAGS "/w34295 /w34189")

	set(WIRESHARK_COMMON_FLAGS
		${LOCAL_CFLAGS}
		${WARNINGS_CFLAGS}
	)

	set(WS_LINK_FLAGS "/LARGEADDRESSAWARE /MANIFEST:NO /INCREMENTAL:NO /RELEASE")

else()
	if(CMAKE_OSX_DEPLOYMENT_TARGET)
		if(APPLE)
			if(${CMAKE_OSX_DEPLOYMENT_TARGET} STREQUAL "10.0")
				message(FATAL_ERROR "We don't support building for OS X 10.0")
			elseif(${CMAKE_OSX_DEPLOYMENT_TARGET} STREQUAL "10.1")
				message(FATAL_ERROR "We don't support building for OS X 10.1")
			elseif(${CMAKE_OSX_DEPLOYMENT_TARGET} STREQUAL "10.2")
				message(FATAL_ERROR "We don't support building for OS X 10.2")
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
			message(STATUS "Building for OS X ${CMAKE_OSX_DEPLOYMENT_TARGET}")
		else()
			message(FATAL_ERROR "CMAKE_OSX_DEPLOYMENT_TARGET only applies when building for OS X")
		endif()
	endif()

	set(WIRESHARK_COMMON_FLAGS
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

	set(WIRESHARK_C_ONLY_FLAGS
		# The following are C only, not C++
		-Wc++-compat
		-Wdeclaration-after-statement
		-Wshadow
		-Wno-pointer-sign
		-Wold-style-definition
		-Wstrict-prototypes
		-Wlogical-op
		-Wjump-misses-init
		-Wunused-const-variable
		# The Qt headers generate a ton of shortening errors on 64-bit systems
		# so only enable this for C for now.
		-Wshorten-64-to-32
		# Clang only
		-Wc99-extensions
	)

	set(WIRESHARK_CXX_ONLY_FLAGS
	)

	set(WIRESHARK_EXTRA_COMPILER_COMMON_FLAGS
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
		# this one for now.
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
		# No longer supported by El Capitan clang on C++
		#
		-fno-delete-null-pointer-checks
	)

	set(WIRESHARK_EXTRA_COMPILER_C_ONLY_FLAGS
		# The following are C only, not C++
		#
		# Due to various places where APIs we don't control
		# require us to cast away constness, we can probably
		# never enable this one with -Werror.
		#
		-Wbad-function-cast
	)

	set(WIRESHARK_EXTRA_COMPILER_CXX_ONLY_FLAGS
	)

	if(CMAKE_C_COMPILER_ID MATCHES "Clang")
		set(WIRESHARK_COMMON_FLAGS ${WIRESHARK_COMMON_FLAGS}
			# avoid "argument unused during compilation" warnings
			# (for example, when getting the -gsplit-dwarf option or
			# when combining -fwrapv with -fno-strict-overflow)
			-Qunused-arguments
		)

		set(WIRESHARK_CXX_ONLY_FLAGS ${WIRESHARK_CXX_ONLY_FLAGS}
		)
	else()
		set(WIRESHARK_COMMON_FLAGS ${WIRESHARK_COMMON_FLAGS}
			-fexcess-precision=fast
		)

		set(WIRESHARK_C_ONLY_FLAGS ${WIRESHARK_C_ONLY_FLAGS}
		)
	endif()

	if(ENABLE_EXTRA_COMPILER_WARNINGS)   # This overrides -Werror
		set(WIRESHARK_COMMON_FLAGS ${WIRESHARK_COMMON_FLAGS} ${WIRESHARK_EXTRA_COMPILER_COMMON_FLAGS})
		set(WIRESHARK_C_ONLY_FLAGS ${WIRESHARK_C_ONLY_FLAGS} ${WIRESHARK_EXTRA_COMPILER_C_ONLY_FLAGS})
		set(WIRESHARK_CXX_ONLY_FLAGS ${WIRESHARK_CXX_ONLY_FLAGS} ${WIRESHARK_EXTRA_COMPILER_CXX_ONLY_FLAGS})
	endif()

	add_definitions(
		-DG_DISABLE_DEPRECATED
		-DG_DISABLE_SINGLE_INCLUDES
	)
endif()

set( C_FLAG_TESTS ${WIRESHARK_COMMON_FLAGS} ${WIRESHARK_C_ONLY_FLAGS} )
set( CXX_FLAG_TESTS ${WIRESHARK_COMMON_FLAGS} ${WIRESHARK_CXX_ONLY_FLAGS} )

# Counterhack to work around some cache magic in CHECK_C_SOURCE_COMPILES
include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)

if(ENABLE_STATIC)
	set(BUILD_SHARED_LIBS 0)
	set(LINK_MODE_LIB STATIC)
	set(LINK_MODE_MODULE STATIC)
else()
	set(BUILD_SHARED_LIBS 1)
	set(LINK_MODE_LIB SHARED)
	set(LINK_MODE_MODULE MODULE)
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

if(ENABLE_ASAN)
	set(CMAKE_REQUIRED_LIBRARIES "-fsanitize=address")
	check_c_compiler_flag(-fsanitize=address C__fsanitize_address_VALID)
	check_cxx_compiler_flag(-fsanitize=address CXX__fsanitize_address_VALID)
	set(CMAKE_REQUIRED_LIBRARIES "")
	if(NOT C__fsanitize_address_VALID OR NOT CXX__fsanitize_address_VALID)
		message(FATAL_ERROR "ENABLE_ASAN was requested, but not supported!")
	endif()
	set(CMAKE_C_FLAGS "-fsanitize=address ${CMAKE_C_FLAGS}")
	set(CMAKE_CXX_FLAGS "-fsanitize=address ${CMAKE_CXX_FLAGS}")
endif()

if(NOT DISABLE_WERROR AND NOT ENABLE_EXTRA_COMPILER_WARNINGS)
	if(CMAKE_C_COMPILER_ID MATCHES "MSVC")
		set(WERROR_COMMON_FLAGS "/WX")
		set(NO_ERROR_DEPRECATED_DECLARATIONS_COMPILE_FLAGS)
	else()
		check_c_compiler_flag(-Werror WERROR)
		if (WERROR)
			set(WERROR_COMMON_FLAGS "-Werror")
			set(NO_ERROR_DEPRECATED_DECLARATIONS_COMPILE_FLAGS "-Wno-error=deprecated-declarations")
		endif()
	endif()
else()
	set(WERROR_COMMON_FLAGS FALSE)
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
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden")
	else()
		#
		# OK, try the Sun^WOracle C -xldscope=hidden
		#
		check_c_compiler_flag(-xldscope=hidden XLDSCOPEHIDDEN)
		if(XLDSCOPEHIDDEN)
			set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -xldscope=hidden")
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

if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID MATCHES "Clang")
	set (C_UNUSED	    "__attribute__((unused))" )
	set (WS_NORETURN    "__attribute__((noreturn))")
elseif(MSVC)
	set (C_UNUSED	    "")
	set (WS_NORETURN    "__declspec(noreturn)")
else()
	set (C_UNUSED	    "")
	set (WS_NORETURN    "")
endif()

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
	# GLib on OS X requires libintl. Homebrew installs gettext (and
	# libintl) in /usr/local/opt/gettext
	include_directories(/usr/local/opt/gettext/include)
	link_directories(/usr/local/opt/gettext/lib)
endif()

# The packagelist is doing some magic:  If we add XXX to the packagelist, we
# - may optionally set XXX_OPTIONS to pass to the find_package command
# - will call FindXXX.cmake
# - return found libraries in XXX_LIBRARIES
# - return found include in XXX_INCLUDE_DIRS
# - set HAVE_XXX

#The minimum package list
set(PACKAGELIST Gettext M Git GLIB2 GMODULE2 GTHREAD2 LEX YACC Perl SED SH PythonInterp)
set(LEX_REQUIRED TRUE)
set(GLIB2_REQUIRED TRUE)
set(GLIB2_FIND_REQUIRED TRUE)
set(GLIB2_MIN_VERSION 2.14.0)
set(GTHREAD2_REQUIRED TRUE)
set(PythonInterp_FIND_VERSION 2)
set(Python_ADDITIONAL_VERSIONS 3)
set(YACC_REQUIRED TRUE)

if (NOT WIN32)
	set(M_REQUIRED TRUE)
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
		set(PACKAGELIST ${PACKAGELIST}
			Qt5Core
			Qt5LinguistTools
			Qt5Multimedia
			Qt5PrintSupport
			Qt5Svg
			Qt5Widgets
		)
		if (APPLE)
			set(PACKAGELIST ${PACKAGELIST} Qt5MacExtras)
		endif()
		if( WIN32 )
			set(PACKAGELIST ${PACKAGELIST} Qt5WinExtras)
		endif()
		set(QT_VERSION 5)
	else()
		set(PACKAGELIST ${PACKAGELIST} Qt4)
		set(Qt4_OPTIONS 4.7.1 REQUIRED QtCore QtGui)
		set(QT_VERSION 4)
	endif()
endif()

# SMI SNMP
if(ENABLE_SMI)
	set(PACKAGELIST ${PACKAGELIST} SMI)
endif()

# GNU crypto
if(ENABLE_GCRYPT)
	set(PACKAGELIST ${PACKAGELIST} GCRYPT)
	# Minimum version needed.
	set(GCRYPT_OPTIONS "1.4.2")
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
endif()

# Zlib compression
if(ENABLE_ZLIB)
	if (WIN32)
		# On Windows we build our own version of zlib, so add the paths
		set(ZLIB_SRC_DIR "${_PROJECT_LIB_DIR}/zlib-1.2.8-ws")
		set(SKIP_INSTALL_ALL True) # We copy the DLL ourselves.
		add_subdirectory("${ZLIB_SRC_DIR}" "${CMAKE_BINARY_DIR}/zlib")
		unset(SKIP_INSTALL_ALL)
		set(ZLIB_INCLUDE_DIR  "${ZLIB_SRC_DIR}" "${CMAKE_BINARY_DIR}/zlib")
		set(ZLIB_LIBRARY zlib)
		set(ZLIB_DLL "zlib1.dll")
		set_target_properties(zlib PROPERTIES FOLDER "Libs/zlib")
		# Annoyingly zlib also builds some other stuff we aren't interested in
		set_target_properties(zlibstatic PROPERTIES FOLDER "Libs/zlib")
	endif()
	set(PACKAGELIST ${PACKAGELIST} ZLIB)
endif()

# Embedded Lua interpreter
if(ENABLE_LUA)
	set(PACKAGELIST ${PACKAGELIST} LUA)
endif()

# GeoIP address resolving
if(ENABLE_GEOIP)
	set(PACKAGELIST ${PACKAGELIST} GEOIP)
endif()

if(ENABLE_NETLINK)
	set(PACKAGELIST ${PACKAGELIST} NL)
endif()

if(ENABLE_SBC)
	set(PACKAGELIST ${PACKAGELIST} SBC)
endif()

# Capabilities
if(ENABLE_CAP)
	set(PACKAGELIST ${PACKAGELIST} CAP SETCAP)
endif()

# Windows version updates
if(ENABLE_WINSPARKLE)
	set(PACKAGELIST ${PACKAGELIST} WINSPARKLE)
endif()

set(PACKAGELIST ${PACKAGELIST} YAPP)

set(PACKAGELIST ${PACKAGELIST} POD)

if(ENABLE_HTML_GUIDES)
	set(PACKAGELIST ${PACKAGELIST} DOXYGEN)
endif()

set(PROGLIST)

# Sort the package list
list(SORT PACKAGELIST)
message(STATUS "Packagelist: ${PACKAGELIST}")
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
	else()
		set(PACKAGE_VAR ${PACKAGE})
	endif()
	if(${PACKAGE}_OPTIONS)
		find_package(${PACKAGE} ${${PACKAGE}_OPTIONS})
	elseif(${PACKAGE}_REQUIRED)
		find_package(${PACKAGE} REQUIRED)
	else()
		find_package(${PACKAGE})
	endif()
	if (${PACKAGE_VAR}_FOUND)
		message(STATUS "${PACKAGE_VAR} FOUND")
		set(HAVE_LIB${PACKAGE_VAR} 1)
		include_directories(SYSTEM ${${PACKAGE_VAR}_INCLUDE_DIRS})
		set(WS_ALL_LIBS ${WS_ALL_LIBS} ${${PACKAGE_VAR}_LIBRARIES})
		message(STATUS "${PACKAGE} includes: ${${PACKAGE_VAR}_INCLUDE_DIRS}")
		message(STATUS "${PACKAGE} libs: ${${PACKAGE_VAR}_LIBRARIES}")
		if (${PACKAGE}_DEFINITIONS)
			message(STATUS "${PACKAGE} definitions: ${${PACKAGE_VAR}_DEFINITIONS}")
		endif()
		if (${PACKAGE_VAR}_EXECUTABLE)
			message(STATUS "${PACKAGE} executable: ${${PACKAGE_VAR}_EXECUTABLE}")
		endif()
	else()
		#
		# Not finding a package is only a fatal error if the
		# package is required; if it's required, then its
		# XXX_REQUIRED variable is set to TRUE, and the above
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

#packaging
include(CPackConfig.txt)

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
if(HAVE_LIBGEOIP)
	set(HAVE_GEOIP 1)
endif()
if(LIBSSH_FOUND)
	set(HAVE_LIBSSH 1)
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
if(EXTCAP_ANDROIDDUMP_LIBPCAP)
	set(ANDROIDDUMP_USE_LIBPCAP 1)
endif()

if (HAVE_LIBWINSPARKLE)
	set(HAVE_SOFTWARE_UPDATE 1)
endif()

# No matter which version of GTK is present
if(GTK2_FOUND OR GTK3_FOUND)
	set(GTK_FOUND ON)
endif()

if(HAVE_LIBZLIB)
	set(HAVE_ZLIB 1)
	# Always include the "true" zlib includes first. This works around a
	# bug in the Windows setup of GTK[23] which has a faulty zconf.h.
	include_directories(BEFORE ${ZLIB_INCLUDE_DIRS})
endif()
if (Qt5Widgets_FOUND)
	#
	# Qt5CoreConfigExtras.cmake in Qt 5.5.0 sets -fPIC unconditionally:
	#
	#    https://bugreports.qt.io/browse/QTBUG-47942
	#
	# There's a fix in Gerrit for that:
	#
	#     https://codereview.qt-project.org/#/c/139645/
	#
	# Do the same check as that fix does and, if the check says we
	# should *not* add -fPIC, remove it.
	#
	# XXX - if that check gets changed in the future, we'll have to
	# detect that and change it.
	#
	if (CMAKE_VERSION VERSION_LESS 2.8.12
	    AND (CMAKE_CXX_COMPILER_ID STREQUAL \"GNU\"
	    AND NOT CMAKE_CXX_COMPILER_VERSION VERSION_LESS 5.0))
		#
		# Yes, it should have been; leave it there.
		#
	else()
		#
		# No, it shouldn't have been; remove it.
		#
		list(REMOVE_ITEM Qt5Widgets_EXECUTABLE_COMPILE_FLAGS "-fPIC")
	endif()
	if (Qt5Widgets_VERSION VERSION_GREATER 5.6
	    AND (CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID MATCHES "Clang"))
		# Qt 5.7 and later require C++ 11. If our minmimu required CMake version
		# is ever >= 3.1 we can use CXX_STANDARD + CXX_STANDARD_REQUIRED.
		message(STATUS "Checking for C++ 11 support (Required by Qt 5.7 and later)")
		check_cxx_compiler_flag(-std=c++11 CXX__std_c__11_VALID)
		if(NOT CXX__std_c__11_VALID)
			message(FATAL_ERROR "Qt ${Qt5Widgets_VERSION} requires C++ 11")
		endif()
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
	endif()
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${Qt5Widgets_EXECUTABLE_COMPILE_FLAGS}")
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
elseif(QT_FOUND)
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
endif()

if(ENABLE_CHECKHF_CONFLICT)
	set(ENABLE_CHECK_FILTER 1)
endif()

message(STATUS "C-Flags: ${CMAKE_C_FLAGS}")
message(STATUS "CXX-Flags: ${CMAKE_CXX_FLAGS}")
message(STATUS "Warnings as errors: ${WERROR_COMMON_FLAGS}")

if(APPLE)
	#
	# We assume that APPLE means OS X so that we have the OS X
	# frameworks.
	#
	set(HAVE_OS_X_FRAMEWORKS 1)
	FIND_LIBRARY (APPLE_APPLICATION_SERVICES_LIBRARY ApplicationServices)
	FIND_LIBRARY (APPLE_CORE_FOUNDATION_LIBRARY CoreFoundation)
	FIND_LIBRARY (APPLE_SYSTEM_CONFIGURATION_LIBRARY SystemConfiguration)
endif()

include(ConfigureChecks.cmake)

#Big or little endian ?
include(TestBigEndian)
test_big_endian(WORDS_BIGENDIAN)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

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
add_subdirectory( docbook )
add_subdirectory( epan )
add_subdirectory( randpkt_core )
add_subdirectory( tools/lemon )
add_subdirectory( ui )
add_subdirectory( wiretap )
add_subdirectory( writecap )
add_subdirectory( wsutil )

if(NOT WIN32)
	add_custom_target(dumpabi DEPENDS dumpabi-libwireshark dumpabi-libwiretap dumpabi-libwsutil)
endif()

if(ENABLE_ECHLD)
	add_subdirectory( echld )
endif()

if(BUILD_wireshark_gtk AND GTK_FOUND)
	add_subdirectory( ui/gtk )
endif()

if(BUILD_wireshark AND QT_FOUND)
	add_subdirectory( ui/qt )
endif()

# Location of our data files. This should be set to a value that allows
# running from the build directory on Windows, on OS X when building an
# application bundle, and on UNIX if WIRESHARK_RUN_FROM_BUILD_DIRECTORY
# is set.
if(ENABLE_APPLICATION_BUNDLE)
	set(_datafile_dir "${CMAKE_BINARY_DIR}/run/Wireshark.app/Contents/Resources/share/wireshark")
else()
	get_target_property(_libwireshark_location epan LOCATION)
	get_filename_component(_datafile_dir "${_libwireshark_location}" PATH)
endif()

set(DATAFILE_DIR ${_datafile_dir} CACHE INTERNAL "Build time data file location.")

if(ENABLE_EXTCAP)
	# Target platform locations
	# UNIX, Linux, non-bundled OS X: $DESTDIR/lib/wireshark/extcap
	# Windows: $DESTDIR/extcap
	# OS X app bundle: Wireshark.app/Contents/Resources/share/wireshark/extcap
	set(HAVE_EXTCAP 1)
	if (WIN32)
		set(EXTCAP_DIR "extcap")
	else ()
		set(EXTCAP_DIR "${CMAKE_INSTALL_LIBDIR}/${CPACK_PACKAGE_NAME}/extcap")
	endif()
endif()

if(LIBSSH_FOUND)
	SET(CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES} ${LIBSSH_LIBRARIES})
	CHECK_FUNCTION_EXISTS(ssh_userauth_agent LIBSSH_USERAUTH_AGENT_FOUND)
	if(LIBSSH_USERAUTH_AGENT_FOUND)
		set(HAVE_SSH_USERAUTH_AGENT 1)
	endif()
endif()

# Location of our plugins. PLUGIN_DIRECTORY should allow running
# from the build directory similar to DATAFILE_DIR above.
if(ENABLE_PLUGINS)
	# Target platform locations
	# UNIX, Linux, non-bundled OS X: $DESTDIR/lib/wireshark/plugins/$VERSION
	# Windows: $DESTDIR/wireshark/plubins/$VERSION
	# OS X app bundle: Wireshark.app/Contents/PlugIns/wireshark
	set(HAVE_PLUGINS 1)
	add_custom_target(plugins)
	set_target_properties(plugins PROPERTIES FOLDER "Plugins")
	if (WIN32)
		set(PLUGIN_INSTALL_DIR "plugins/${CPACK_PACKAGE_VERSION}")
	else ()
		set(PLUGIN_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}/${CPACK_PACKAGE_NAME}/plugins/${CPACK_PACKAGE_VERSION}")
	endif()
	set(PLUGIN_SRC_DIRS
		plugins/docsis
		plugins/ethercat
		plugins/gryphon
		plugins/irda
		plugins/m2m
		plugins/mate
		plugins/opcua
		plugins/profinet
		plugins/stats_tree
		plugins/unistim
		plugins/wimax
		plugins/wimaxasncp
		plugins/wimaxmacphy
		${CUSTOM_PLUGIN_SRC_DIR}
	)
# It seems this stuff doesn't build with autofoo either...
#	if(YAPP_FOUND)
#		set(PLUGIN_SRC_DIRS
#			${PLUGIN_SRC_DIRS}
#			plugins/tpg
#		)
#	endif()
else()
	set(PLUGIN_SRC_DIRS )
endif()

if(ENABLE_APPLICATION_BUNDLE)
	set(_plugin_dir "${CMAKE_BINARY_DIR}/run/Wireshark.app/Contents/PlugIns/wireshark")
else()
	get_target_property(_libwireshark_location epan LOCATION)
	get_filename_component(_plugin_dir "${_libwireshark_location}" PATH)
	set(_plugin_dir "${_plugin_dir}/plugins")
endif()
# XXX The NMake environment appends the version. Should we do so here?
set (PLUGIN_DIR ${_plugin_dir} CACHE INTERNAL "Build time plugin location.")

foreach(_plugin_src_dir ${PLUGIN_SRC_DIRS})
	add_subdirectory( ${_plugin_src_dir} )
endforeach()


# Basedir where to install guides
set(DOC_DIR "$ENV{docdir}" CACHE FILEPATH "Installation directory for ug and dg pdfs.")
message(STATUS "docdir: ${DOC_DIR}")

if(ENABLE_PCAP_NG_DEFAULT)
	set(PCAP_NG_DEFAULT 1)
endif()

# Large file support (e.g. make off_t 64 bit if supported)
include(gmxTestLargeFiles)
gmx_test_large_files(GMX_LARGEFILES)

add_definitions( -DTOP_SRCDIR=\"${CMAKE_SOURCE_DIR}\" )

if(WIN32)
	# Disable deprecation
	if(MSVC80 OR MSVC90)
		add_definitions(-D_CRT_SECURE_NO_DEPRECATE -D_CRT_NONSTDC_NO_DEPRECATE)
	endif()
endif()

if (${GIT_EXECUTABLE})
	set(GIT_BIN_PARAM "--git-bin ${GIT_EXECUTABLE}")
endif()
set( VERSION ${PROJECT_VERSION} )
add_custom_target(version
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
set( plugindir "\${libdir}/wireshark/plugins/${CPACK_PACKAGE_VERSION}" )

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
#SET_FEATURE_INFO(NAME DESCRIPTION [URL [COMMENT] ])
SET_FEATURE_INFO(SBC "SBC Codec for Bluetooth A2DP stream playing" "www: http://git.kernel.org/cgit/bluetooth/sbc.git" )
SET_FEATURE_INFO(LIBSSH "libssh is library for ssh connections and it is needed to build sshdump/ciscodump" "www: https://www.libssh.org/get-it/" )

FEATURE_SUMMARY(WHAT ALL)

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
endif()

# sources common for wireshark, tshark, and rawshark
set(SHARK_COMMON_SRC
	cfile.c
	frame_tvbuff.c
	sync_pipe_write.c
	ws_version_info.c
)

# sources for external capture interfaces
if(ENABLE_EXTCAP)
	set(SHARK_COMMON_SRC
		${SHARK_COMMON_SRC}
		extcap.c
		extcap_parser.c
		extcap_spawn.c
	)
endif()

set(TSHARK_TAP_SRC
	ui/cli/tap-camelsrt.c
	ui/cli/tap-comparestat.c
	ui/cli/tap-diameter-avp.c
	ui/cli/tap-expert.c
	ui/cli/tap-endpoints.c
	ui/cli/tap-follow.c
	ui/cli/tap-funnel.c
	ui/cli/tap-gsm_astat.c
	ui/cli/tap-hosts.c
	ui/cli/tap-httpstat.c
	ui/cli/tap-icmpstat.c
	ui/cli/tap-icmpv6stat.c
	ui/cli/tap-iostat.c
	ui/cli/tap-iousers.c
	ui/cli/tap-macltestat.c
	ui/cli/tap-protocolinfo.c
	ui/cli/tap-protohierstat.c
	ui/cli/tap-rlcltestat.c
	ui/cli/tap-rpcprogs.c
	ui/cli/tap-rtd.c
	ui/cli/tap-rtp.c
	ui/cli/tap-rtspstat.c
	ui/cli/tap-sctpchunkstat.c
	ui/cli/tap-simple_stattable.c
	ui/cli/tap-sipstat.c
	ui/cli/tap-smbsids.c
	ui/cli/tap-srt.c
	ui/cli/tap-stats_tree.c
	ui/cli/tap-sv.c
	ui/cli/tap-wspstat.c
)

set(INSTALL_DIRS
	diameter
	dtds
	help
	radius
	tpncp
	wimaxasncp
)

set(INSTALL_FILES
	cfilters
	colorfilters
	dfilters
	ipmap.html
	manuf
	pdml2html.xsl
	services
	smi_modules
	docbook/ws.css
	${CMAKE_BINARY_DIR}/doc/AUTHORS-SHORT
	${CMAKE_BINARY_DIR}/doc/asn2deb.html
	${CMAKE_BINARY_DIR}/doc/androiddump.html
	${CMAKE_BINARY_DIR}/doc/capinfos.html
	${CMAKE_BINARY_DIR}/doc/captype.html
	${CMAKE_BINARY_DIR}/doc/ciscodump.html
	${CMAKE_BINARY_DIR}/doc/dftest.html
	${CMAKE_BINARY_DIR}/doc/dumpcap.html
	${CMAKE_BINARY_DIR}/doc/editcap.html
	${CMAKE_BINARY_DIR}/doc/extcap.html
	${CMAKE_BINARY_DIR}/doc/idl2deb.html
	${CMAKE_BINARY_DIR}/doc/idl2wrs.html
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

if(WIN32)
	set(TEXTIFY_FILES COPYING NEWS README README.windows)
	foreach(_text_file ${TEXTIFY_FILES})
		set(INSTALL_FILES ${CMAKE_BINARY_DIR}/${_text_file}.txt ${INSTALL_FILES})
	endforeach()
else()
	set(INSTALL_FILES COPYING ${INSTALL_FILES})
endif()

set(LIBEPAN_LIBS
#		@SSL_LIBS@	# -lcrypto
		epan
#		$(plugin_ldadd)	# in case of static
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
		${M_LIBRARIES}
		${WINSPARKLE_LIBRARIES}
)

if(WIN32)
	# According to http://stackoverflow.com/questions/14474659/cmake-how-to-have-a-target-for-copying-files
	# we can't just use "set(_dll_output_dir "$<TARGET_FILE_DIR:epan>")"
	# DATAFILE_DIR is set using the same property. We could probably
	# get away with using it here.
	get_target_property(_libwireshark_location epan LOCATION)
	get_filename_component(_dll_output_dir "${_libwireshark_location}" PATH)
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
	file (TO_NATIVE_PATH "${_dll_output_dir}" _dll_output_dir_win )
	foreach( _dll ${GLIB2_DLLS} $<$<CONFIG:Debug>:zlib1.dll> )
		add_custom_command(TARGET copy_cli_dlls PRE_BUILD
			# It would be really handy if copy, xcopy, or "cmake
			# -E copy_if_different" supported multiple files
			# separated by whitespace, or if robocpy had a sane
			# notion of exit codes.
			COMMAND if exist \"${_dll}\" xcopy ${_dll} "${_dll_output_dir_win}" /D /Y
			WORKING_DIRECTORY "${GLIB2_DLL_DIR}"
		)
	endforeach(_dll)

	# Optional
	if (AIRPCAP_FOUND)
		add_custom_command(TARGET copy_cli_dlls PRE_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy_if_different
				"${AIRPCAP_DLL_DIR}/${AIRPCAP_DLL}"
				"${_dll_output_dir}"
		)
	endif(AIRPCAP_FOUND)
	if (CARES_FOUND)
		add_custom_command(TARGET copy_cli_dlls PRE_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy_if_different
				"${CARES_DLL_DIR}/${CARES_DLL}"
				"${_dll_output_dir}"
		)
	endif(CARES_FOUND)
	if (GEOIP_FOUND)
		add_custom_command(TARGET copy_cli_dlls PRE_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy_if_different
				"${GEOIP_DLL_DIR}/${GEOIP_DLL}"
				"${_dll_output_dir}"
		)
	endif(GEOIP_FOUND)
	if (LIBSSH_FOUND)
		add_custom_command(TARGET copy_cli_dlls PRE_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy_if_different
				"${LIBSSH_DLL_DIR}/${LIBSSH_DLL}"
				"${_dll_output_dir}"
		)
	endif(LIBSSH_FOUND)
	if(GCRYPT_FOUND)
		foreach( _dll ${GCRYPT_DLLS} )
			add_custom_command(TARGET copy_cli_dlls PRE_BUILD
				COMMAND ${CMAKE_COMMAND} -E copy_if_different
					"${GCRYPT_DLL_DIR}/${_dll}"
					"${_dll_output_dir}"
			)
		endforeach(_dll)
	endif(GCRYPT_FOUND)
	if(GNUTLS_FOUND)
		foreach( _dll ${GNUTLS_DLLS} )
			add_custom_command(TARGET copy_cli_dlls PRE_BUILD
				COMMAND ${CMAKE_COMMAND} -E copy_if_different
					"${GNUTLS_DLL_DIR}/${_dll}"
					"${_dll_output_dir}"
			)
		endforeach(_dll)
	endif(GNUTLS_FOUND)
	if(KERBEROS_FOUND)
		foreach( _dll ${KERBEROS_DLLS} )
			add_custom_command(TARGET copy_cli_dlls PRE_BUILD
				COMMAND ${CMAKE_COMMAND} -E copy_if_different
					"${KERBEROS_DLL_DIR}/${_dll}"
					"${_dll_output_dir}"
			)
		endforeach(_dll)
	endif(KERBEROS_FOUND)
	if (LUA_FOUND)
		add_custom_command(TARGET copy_cli_dlls PRE_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy_if_different
				"${LUA_DLL_DIR}/${LUA_DLL}"
				"${_dll_output_dir}"
		)
	endif(LUA_FOUND)
	if (SMI_FOUND)
		# Wireshark.nsi wants SMI_DIR which is the base SMI directory
		get_filename_component(SMI_DIR ${SMI_DLL_DIR} DIRECTORY)
		add_custom_command(TARGET copy_cli_dlls PRE_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy_if_different
				"${SMI_DLL_DIR}/${SMI_DLL}"
				"${_dll_output_dir}"
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
	if (WINSPARKLE_FOUND)
		add_custom_command(TARGET copy_cli_dlls PRE_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy_if_different
				"${WINSPARKLE_DLL_DIR}/${WINSPARKLE_DLL}"
				"${_dll_output_dir}"
		)
	endif(WINSPARKLE_FOUND)

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
		add_custom_target(pdb_zip_package)
		set_target_properties(pdb_zip_package PROPERTIES FOLDER "Packaging")
		set(_pdb_zip "${CMAKE_BINARY_DIR}/Wireshark-pdb-${WIRESHARK_TARGET_PLATFORM}-${VERSION}.zip")
		file(TO_NATIVE_PATH "${_pdb_zip}" _pdb_zip_win)
		add_custom_command(TARGET pdb_zip_package POST_BUILD
			COMMAND ${CMAKE_COMMAND} -E remove -f "${_pdb_zip}"
			COMMAND ${ZIP_EXECUTABLE} a -tzip -mmt=on "${_pdb_zip_win}" *.pdb *.lib
			WORKING_DIRECTORY "${_dll_output_dir}"
		)
		add_dependencies(pdb_zip_package epan)
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
endif()

foreach(_install_file ${INSTALL_FILES})
	get_filename_component(_install_basename "${_install_file}" NAME)
	set(_output_file "${DATAFILE_DIR}/${_install_basename}")
	add_custom_command(OUTPUT "${_output_file}"
		COMMAND ${CMAKE_COMMAND} -E copy
			"${_install_file}"
			"${_output_file}"
		WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
		DEPENDS
			docs
			"${_install_file}"
	)
	list(APPEND copy_data_files_depends "${_output_file}")
endforeach()

if(ENABLE_EXTCAP)
	# Ensure "run/extcap" exists
	add_custom_command(OUTPUT "${DATAFILE_DIR}/extcap"
		COMMAND ${CMAKE_COMMAND} -E make_directory
			"${DATAFILE_DIR}/extcap"
	)
	list(APPEND copy_data_files_depends "${DATAFILE_DIR}/extcap")
endif()
set(_help_files
	help/capture_filters.txt
	help/capturing.txt
	help/display_filters.txt
	help/getting_started.txt
	help/overview.txt
)
if(WIN32)
	file(TO_NATIVE_PATH "${DATAFILE_DIR}/help" _help_dest_dir)
	foreach(_help_file IN LISTS _help_files)
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
	list(APPEND DATA_FILES_SRC ${_help_files})
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
			COMMAND ${CMAKE_COMMAND} -E copy
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
	"dtds/*.dtd"

	"radius/README.radius_dictionary"
	"radius/custom.includes"
	"radius/dictionary"
	"radius/dictionary.*"

	"diameter/*.dtd"
	"diameter/*.xml"
	"profiles/*/*"
	"tpncp/tpncp.dat"
	"wimaxasncp/*.dtd"
	"wimaxasncp/*.xml"
)

# Copy all paths from the source tree to the data directory. Directories are
# automatically created if missing as the filename is given.
file(GLOB _data_files RELATIVE "${CMAKE_SOURCE_DIR}" ${DATA_FILES_SRC})
foreach(_data_file ${_data_files})
	add_custom_command(OUTPUT "${DATAFILE_DIR}/${_data_file}"
		COMMAND ${CMAKE_COMMAND} -E copy
			"${CMAKE_SOURCE_DIR}/${_data_file}"
			"${DATAFILE_DIR}/${_data_file}"
		DEPENDS
			"${CMAKE_SOURCE_DIR}/${_data_file}"
	)
	list(APPEND copy_data_files_depends "${DATAFILE_DIR}/${_data_file}")
endforeach()

# Copy files including ${INSTALL_FILES} and ${INSTALL_DIRS} to ${DATAFILE_DIR}
add_custom_target(copy_data_files ALL DEPENDS ${copy_data_files_depends})
set_target_properties(copy_data_files PROPERTIES FOLDER "Copy Tasks")

if( (BUILD_wireshark AND QT_FOUND) OR (BUILD_wireshark_gtk AND GTK_FOUND) )
	set(WIRESHARK_SRC
		capture_info.c
		capture_opts.c
		file.c
		fileset.c
		filter_files.c
		summary.c
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

	# Wireshark.app/Contents/Resources/share/man/man1
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
		${APPLE_CORE_FOUNDATION_LIBRARY}
		${APPLE_SYSTEM_CONFIGURATION_LIBRARY}
		${NL_LIBRARIES}
	)

	# Policy since 2.8.11
	if (POLICY CMP0020)
		cmake_policy(SET CMP0020 NEW)
	endif()

	add_executable(wireshark WIN32 MACOSX_BUNDLE wireshark-qt.cpp ${wireshark_FILES} ${EXTRA_BUNDLE_FILES})
	add_dependencies(wireshark version)
	set(PROGLIST ${PROGLIST} wireshark)
	set_target_properties(wireshark PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")
	set_target_properties(wireshark PROPERTIES FOLDER "Executables")
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

	if(NOT ENABLE_APPLICATION_BUNDLE)
		# Map for endpoints dialog
		ADD_CUSTOM_COMMAND(
			TARGET wireshark
			POST_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy_if_different
				"${PROJECT_SOURCE_DIR}/ipmap.html"
				$<TARGET_FILE_DIR:wireshark>
		)
	endif()

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
				COMMAND set "PATH=%PATH%;${QT_BIN_PATH}"
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
		LINK_FLAGS "${WS_LINK_FLAGS}"
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
	set_target_properties(wireshark-gtk PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")
	set_target_properties(wireshark-gtk PROPERTIES FOLDER "Executables")
	target_link_libraries(wireshark-gtk ${wireshark_gtk_LIBS})
	install(TARGETS wireshark-gtk RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

	# Map for endpoints dialog
	ADD_CUSTOM_COMMAND(
		TARGET wireshark-gtk
		POST_BUILD
		COMMAND ${CMAKE_COMMAND} -E copy_if_different
			"${PROJECT_SOURCE_DIR}/ipmap.html"
			$<TARGET_FILE_DIR:wireshark-gtk>
	)

	if(WIN32)
		get_target_property(_wsgtk_location wireshark-gtk LOCATION)
		get_filename_component(_dll_output_dir "${_wsgtk_location}" PATH)
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
	tshark-taps
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
		filter_files.c
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
		${LIBEPAN_LIBS}
		${APPLE_CORE_FOUNDATION_LIBRARY}
		${APPLE_SYSTEM_CONFIGURATION_LIBRARY}
	)
	set(rawshark_FILES
		${SHARK_COMMON_SRC}
		rawshark.c
		ui/util.c
		${CMAKE_BINARY_DIR}/image/rawshark.rc
	)
	add_executable(rawshark ${rawshark_FILES})
	add_dependencies(rawshark version)
	set_extra_executable_properties(rawshark "Executables")
	target_link_libraries(rawshark ${rawshark_LIBS})
	install(TARGETS rawshark RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_dftest)
	set(dftest_LIBS
		${LIBEPAN_LIBS}
	)
	set(dftest_FILES
		dftest.c
		ui/util.c
	)
	add_executable(dftest ${dftest_FILES})
	add_dependencies(dftest version)
	set_extra_executable_properties(dftest "Tests")
	target_link_libraries(dftest ${dftest_LIBS})
	install(TARGETS dftest RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_randpkt)
	set(randpkt_LIBS
		randpkt_core
		wiretap
		wsutil
		${M_LIBRARIES}
		${PCAP_LIBRARIES}
		${CARES_LIBRARIES}
		${ZLIB_LIBRARIES}
	)
	set(randpkt_FILES
		randpkt.c
		ws_version_info.c
	)
	add_executable(randpkt ${randpkt_FILES})
	add_dependencies(randpkt version)
	set_extra_executable_properties(randpkt "Executables")
	target_link_libraries(randpkt ${randpkt_LIBS})
	install(TARGETS randpkt RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_text2pcap)
	set(text2pcap_LIBS
		writecap
		wsutil
		${M_LIBRARIES}
		${ZLIB_LIBRARIES}
	)
	set(text2pcap_CLEAN_FILES
		text2pcap.c
		ws_version_info.c
	)
	set(text2pcap_FILES
		${text2pcap_CLEAN_FILES}
		${CMAKE_BINARY_DIR}/image/text2pcap.rc
	)
	add_lex_files(text2pcap_LEX_FILES text2pcap_GENERATED_FILES
		text2pcap-scanner.l
	)
	add_executable(text2pcap ${text2pcap_FILES} ${text2pcap_GENERATED_FILES})
	add_dependencies(text2pcap version)
	set_extra_executable_properties(text2pcap "Executables")
	target_link_libraries(text2pcap ${text2pcap_LIBS})
	install(TARGETS text2pcap RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_mergecap)
	set(mergecap_LIBS
		wiretap
		${ZLIB_LIBRARIES}
		${CMAKE_DL_LIBS}
	)
	set(mergecap_FILES
		mergecap.c
		ws_version_info.c
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
		wiretap
		${ZLIB_LIBRARIES}
		${CMAKE_DL_LIBS}
	)
	set(reordercap_FILES
		reordercap.c
		ws_version_info.c
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
		wiretap
		wsutil
		${ZLIB_LIBRARIES}
		${GCRYPT_LIBRARIES}
		${CMAKE_DL_LIBS}
	)
	set(capinfos_FILES
		capinfos.c
		ws_version_info.c
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
		wiretap
		wsutil
		${ZLIB_LIBRARIES}
		${CMAKE_DL_LIBS}
	)
	set(captype_FILES
		captype.c
		ws_version_info.c
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
		wiretap
		${ZLIB_LIBRARIES}
		${CMAKE_DL_LIBS}
	)
	set(editcap_FILES
		editcap.c
		ws_version_info.c
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
		filter_files.c
		ringbuffer.c
		sync_pipe_write.c
		ws_version_info.c
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

if(ENABLE_EXTCAP AND BUILD_androiddump)
	if(EXTCAP_ANDROIDDUMP_LIBPCAP)
		if(HAVE_LIBPCAP)
			set(androiddump_LIBS
				${GLIB2_LIBRARIES}
				${PCAP_LIBRARIES}
			)
		else()
			message(FATAL_ERROR "You try to build androiddump with libpcap but do not have it")
		endif()
	else()
		set(androiddump_LIBS
			wiretap
			${GLIB2_LIBRARIES}
			${CMAKE_DL_LIBS}
		)
	endif()
	set(androiddump_FILES
		extcap/androiddump.c
		extcap/extcap-base.c
	)

	add_executable(androiddump WIN32 ${androiddump_FILES})
	# XXX Shouldn't we add wsutil to androiddump_LIBS instead?
	set_extcap_executable_properties(androiddump)
	target_link_libraries(androiddump ${androiddump_LIBS})
	install(TARGETS androiddump RUNTIME DESTINATION ${EXTCAP_DIR})
endif()

if(ENABLE_EXTCAP AND BUILD_sshdump AND LIBSSH_FOUND)
	set(sshdump_LIBS
		wsutil
		${GLIB2_LIBRARIES}
		${CMAKE_DL_LIBS}
		${LIBSSH_LIBRARIES}
	)
	if (WIN32)
		set(sshdump_LIBS wsutil ${sshdump_LIBS})
	endif()
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
elseif (BUILD_sshdump)
	#message( WARNING "Cannot find libssh, cannot build sshdump" )
endif()

if(ENABLE_EXTCAP AND BUILD_ciscodump AND LIBSSH_FOUND)
	set(ciscodump_LIBS
		writecap
		wsutil
		${GLIB2_LIBRARIES}
		${CMAKE_DL_LIBS}
		${LIBSSH_LIBRARIES}
	)
	if (WIN32)
		set(ciscodump_LIBS wsutil ${ciscodump_LIBS})
	endif()
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
elseif (BUILD_ciscodump)
	#message( WARNING "Cannot find libssh, cannot build ciscodump" )
endif()

if(ENABLE_EXTCAP AND BUILD_randpktdump)
	set(randpktdump_LIBS
		randpkt_core
		wiretap
		${GLIB2_LIBRARIES}
		${CMAKE_DL_LIBS}
	)
	set(randpktdump_FILES
		extcap/extcap-base.c
		extcap/randpktdump.c
	)

	add_executable(randpktdump WIN32 ${randpktdump_FILES})
	# XXX Shouldn't we add wsutil to randpktdump_LIBS instead?
	set_extcap_executable_properties(randpktdump)
	target_link_libraries(randpktdump ${randpktdump_LIBS})
	install(TARGETS randpktdump RUNTIME DESTINATION ${EXTCAP_DIR})
endif()

if(ENABLE_APPLICATION_BUNDLE)
	add_custom_target(app_bundle)
	set_target_properties(app_bundle PROPERTIES FOLDER "Copy Tasks")
	add_custom_command(TARGET app_bundle
		POST_BUILD
		COMMAND "${CMAKE_SOURCE_DIR}/packaging/macosx/osx-app.sh"
		WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/run"
	)
	add_dependencies(app_bundle ${PROGLIST})

	add_custom_target(dmg_package_prep DEPENDS app_bundle)

	ADD_CUSTOM_COMMAND(
		OUTPUT ${CMAKE_BINARY_DIR}/packaging/macosx/PkgInfo
		COMMAND ${CMAKE_COMMAND} -E echo APPLWshk > ${CMAKE_BINARY_DIR}/packaging/macosx/PkgInfo
	)

	ADD_CUSTOM_TARGET( dmg_package
		COMMAND ${CMAKE_COMMAND} -E copy_if_different
					"${PROJECT_SOURCE_DIR}/ipmap.html"
					$<TARGET_FILE_DIR:wireshark>
		COMMAND ${CMAKE_COMMAND} -E copy_directory
					${CMAKE_SOURCE_DIR}/packaging/macosx/ChmodBPF
					${CMAKE_BINARY_DIR}/run/ChmodBPF
		COMMAND ${CMAKE_COMMAND} -E copy_directory
					${CMAKE_SOURCE_DIR}/packaging/macosx/Resources
					${CMAKE_BINARY_DIR}/run/Resources
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

set(CLEAN_FILES
	${wireshark_FILES}
	${tshark_FILES}
	${rawshark_FILES}
	${dftest_FILES}
	${randpkt_FILES}
	${randpktdump_FILES}
	${text2pcap_CLEAN_FILES}
	${mergecap_FILES}
	${capinfos_FILES}
	${captype_FILES}
	${editcap_FILES}
	${dumpcap_FILES}
	${androiddump_FILES}
	${sshdump_FILES}
	${ciscodump_FILES}
)

if (WERROR_COMMON_FLAGS)
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS ${WERROR_COMMON_FLAGS}
	)
endif()

install(
	FILES
		${INSTALL_FILES}
	DESTINATION
		${CMAKE_INSTALL_DATADIR}/${CPACK_PACKAGE_NAME}
)

install(
	FILES
		"${CMAKE_BINARY_DIR}/wireshark.pc"
	DESTINATION
		${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

install(
	DIRECTORY
		${INSTALL_DIRS}
	DIRECTORY_PERMISSIONS
		OWNER_EXECUTE OWNER_WRITE OWNER_READ
		GROUP_EXECUTE GROUP_READ
		WORLD_EXECUTE WORLD_READ
	DESTINATION
		${CMAKE_INSTALL_DATADIR}/${CPACK_PACKAGE_NAME}
	PATTERN ".git" EXCLUDE
	PATTERN ".svn" EXCLUDE
	PATTERN "Makefile.*" EXCLUDE
	PATTERN "faq.py" EXCLUDE
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
		${CMAKE_MODULE_PATH}/UseMakeDissectorReg.cmake
		${CMAKE_BINARY_DIR}/WiresharkConfig.cmake
		${CMAKE_BINARY_DIR}/WiresharkConfigVersion.cmake
	DESTINATION
		${CMAKE_INSTALL_MODULES_DIR}
)

if(DOC_DIR)
	message(STATUS "Docdir install: ${DOC_DIR}")
	INSTALL(
		DIRECTORY
			${CMAKE_BINARY_DIR}/docbook/
		DIRECTORY_PERMISSIONS
			OWNER_EXECUTE OWNER_WRITE OWNER_READ
			GROUP_EXECUTE GROUP_READ
			WORLD_EXECUTE WORLD_READ
		DESTINATION
			${DOC_DIR}/guides
		FILES_MATCHING
		PATTERN "*.pdf"
	)
endif()

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
set_target_properties(test-sh PROPERTIES FOLDER "Tests")

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

add_custom_target(test-programs
	DEPENDS test-sh
		exntest
		oids_test
		reassemble_test
		tvbtest
		wmem_test
	COMMENT "Building unit test programs and wrapper"
)
set_target_properties(test-programs PROPERTIES FOLDER "Tests")

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
