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

cmake_minimum_required(VERSION 2.8.3)

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

include(UseCustomIncludes)
ADD_CUSTOM_CMAKE_INCLUDE()

# This cannot be implemented via option(...)
if( NOT CMAKE_BUILD_TYPE )
	set( CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING
		"Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel."
		FORCE)
endif()
message(STATUS "Configuration types: ${CMAKE_CONFIGURATION_TYPES}")
message(STATUS "${CMAKE_BUILD_TYPE}: ${CMAKE_C_FLAGS_RELWITHDEBINFO}")
#Where to put executables and libraries in the build tree
if(NOT ARCHIVE_OUTPUT_PATH)
	set(ARCHIVE_OUTPUT_PATH ${Wireshark_BINARY_DIR}/run CACHE INTERNAL
		   "Single output directory for building all archives.")
endif()
if(NOT EXECUTABLE_OUTPUT_PATH)
	set(EXECUTABLE_OUTPUT_PATH ${Wireshark_BINARY_DIR}/run CACHE INTERNAL
		   "Single output directory for building all executables.")
	file(MAKE_DIRECTORY ${EXECUTABLE_OUTPUT_PATH}/extcap)
endif()
if(NOT LIBRARY_OUTPUT_PATH)
	set(LIBRARY_OUTPUT_PATH ${Wireshark_BINARY_DIR}/run CACHE INTERNAL
		   "Single output directory for building all libraries.")
endif()
# Under linux the release mode (CMAKE_BUILD_TYPE=release) defines NDEBUG
#Defines CMAKE_INSTALL_BINDIR, CMAKE_INSTALL_DATADIR, etc ...
include(CMakeInstallDirs)

# set(PROJECT_MAJOR_VERSION 1)
# set(PROJECT_MINOR_VERSION 9)
# set(PROJECT_PATCH_VERSION 0)
# set(PROJECT_VERSION_EXTENSION "-rc5")
# If not set, copy over Wireshark version from configure.ac
if(NOT PROJECT_MAJOR_VERSION)
	file(STRINGS
		${CMAKE_SOURCE_DIR}/configure.ac
		PROJECT_MAJOR_VERSION_TMP
		REGEX "^m4_define\\(\\[?version_major\\]?, *\\[?[0-9]+\\]?\\)"
	)
	file(STRINGS
		${CMAKE_SOURCE_DIR}/configure.ac
		PROJECT_MINOR_VERSION_TMP
		REGEX "^m4_define\\(\\[?version_minor\\]?, *\\[?[0-9]+\\]?\\)"
	)
	file(STRINGS
		${CMAKE_SOURCE_DIR}/configure.ac
		PROJECT_PATCH_VERSION_TMP
		REGEX "^m4_define\\(\\[?version_micro\\]?, *\\[?[0-9]+\\]?\\)"
	)
	# XXX pull VERSION_EXTENSION out of configure.ac ?

	string(REGEX REPLACE "m4_define\\(\\[?version_major\\]?, *\\[?([0-9]+)\\]?\\)"
		"\\1"
		PROJECT_MAJOR_VERSION
		${PROJECT_MAJOR_VERSION_TMP}
	)
	string(REGEX REPLACE "m4_define\\(\\[?version_minor\\]?, *\\[?([0-9]+)\\]?\\)"
		"\\1"
		PROJECT_MINOR_VERSION
		${PROJECT_MINOR_VERSION_TMP}
	)
	string(REGEX REPLACE "m4_define\\(\\[?version_micro\\]?, *\\[?([0-9]+)\\]?\\)"
		"\\1"
		PROJECT_PATCH_VERSION
		${PROJECT_PATCH_VERSION_TMP}
	)
endif()

if(PROJECT_VERSION_EXTENSION)
	set(PROJECT_VERSION ${PROJECT_MAJOR_VERSION}.${PROJECT_MINOR_VERSION}.${PROJECT_PATCH_VERSION}${PROJECT_VERSION_EXTENSION})
else()
	set(PROJECT_VERSION ${PROJECT_MAJOR_VERSION}.${PROJECT_MINOR_VERSION}.${PROJECT_PATCH_VERSION})
endif()

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
	${CMAKE_SOURCE_DIR}/wiretap
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

if( CMAKE_C_COMPILER_ID MATCHES "MSVC")
	if (MSVC10)
		set(MSC_VER_REQUIRED 1600)
	elseif(MSVC11)
		set(MSC_VER_REQUIRED 1700)
	elseif(MSVC12)
		set(MSC_VER_REQUIRED 1800)
	else()
		message(FATAL_ERROR "You are using an unsupported version of MSVC")
	endif()
	set(LOCAL_CFLAGS
		/Zi
		/W3
		/MDd
		/DWIN32_LEAN_AND_MEAN
		"/DMSC_VER_REQUIRED=${MSC_VER_REQUIRED}"
		/D_CRT_SECURE_NO_DEPRECATE
		/D_CRT_NONSTDC_NO_DEPRECATE
		/MP
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
		#                                   in pcap-stdinc.h when compiling CPP files, e.g. the Qt UI
		/DPSAPI_VERSION=1
		/DBUILD_WINDOWS
		/D_ALLOW_KEYWORD_MACROS
	)

	if(NOT WIN64)
		set(LOCAL_CFLAGS ${LOCAL_CFLAGS} "/D_BIND_TO_CURRENT_CRT_VERSION=1")
	endif()

	# Additional compiler warnings to be treated as "Level 3"
	#  when compiling Wireshark sources. (Selected from "level 4" warnings).
	## 4295: array is too small to include a terminating null character
	## 4189: local variable is initialized but not referenced
	set(WARNINGS_CFLAGS "/w34295 /w34189")

	# FIXME: WINPCAP_VERSION cannot be determined from source or executable.
	set(WINPCAP_VERSION "unknown")
	set(WIRESHARK_COMMON_FLAGS
		"/DWINPCAP_VERSION=${WINPCAP_VERSION}"
		${LOCAL_CFLAGS}
		${WARNINGS_CFLAGS}
	)
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
		-W
		-Wextra
		-Wendif-labels
		-Wpointer-arith
		-Warray-bounds
		-Wformat-security
		-fwrapv
		-fno-strict-overflow
		-fno-delete-null-pointer-checks
		-Wvla
		-Waddress
		-Wattributes
		-Wdiv-by-zero
		-Wignored-qualifiers
		-Wpragmas
		-Wno-overlength-strings
		-Wwrite-strings
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
		# The Qt headers generate a ton of shortening errors on 64-bit systems
		# so only enable this for C for now.
		-Wshorten-64-to-32
	)

	set(WIRESHARK_CPP_ONLY_FLAGS
	)

	set(WIRESHARK_EXTRA_COMPILER_COMMON_FLAGS
		# The following are for C and C++
		-pedantic
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

	set(WIRESHARK_EXTRA_COMPILER_CPP_ONLY_FLAGS
	)

	if(CMAKE_C_COMPILER_ID MATCHES "Clang")
		set(WIRESHARK_COMMON_FLAGS ${WIRESHARK_COMMON_FLAGS}
			#-fcolor-diagnostics
		)

		# ccache + clang++ can result in "argument unused during
		# compilation" warnings.
		set(WIRESHARK_CPP_ONLY_FLAGS ${WIRESHARK_CPP_ONLY_FLAGS}
			-Qunused-arguments
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
		set(WIRESHARK_CPP_ONLY_FLAGS ${WIRESHARK_CPP_ONLY_FLAGS} ${WIRESHARK_EXTRA_COMPILER_CPP_ONLY_FLAGS})
	endif()

	add_definitions(
		-DG_DISABLE_DEPRECATED
		-DG_DISABLE_SINGLE_INCLUDES
	)
endif()

set( C_FLAG_TESTS ${WIRESHARK_COMMON_FLAGS} ${WIRESHARK_C_ONLY_FLAGS} )
set( CPP_FLAG_TESTS ${WIRESHARK_COMMON_FLAGS} ${WIRESHARK_CPP_ONLY_FLAGS} )

# Counterhack to work around some cache magic in CHECK_C_SOURCE_COMPILES
include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)

if(NOT DISABLE_WERROR AND NOT ENABLE_EXTRA_COMPILER_WARNINGS)
	check_c_compiler_flag(-Werror WERROR)
else()
	set(WERROR FALSE)
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

foreach(THIS_FLAG ${CPP_FLAG_TESTS})
	string( REGEX REPLACE "[^a-zA-Z0-9_]+" "_" F ${THIS_FLAG} )
	set(${F} ${THIS_FLAG})
	set(V CPP_${F}_VALID)
	message(STATUS "Checking for c++-compiler flag: ${THIS_FLAG}")
	check_cxx_compiler_flag("${ADDED_CMAKE_CXX_FLAGS} ${${F}}" ${V})
	if (${${V}})
		set(ADDED_CMAKE_CXX_FLAGS "${ADDED_CMAKE_CXX_FLAGS} ${${F}}")
	endif()
endforeach()
set(CMAKE_CXX_FLAGS "${ADDED_CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS}")

#
# XXX - we're assuming MSVC supports the SSE 4.2 intrinsics and
# that other C compilers support them iff they support the
# -msse4.2 flag.
#
# Perhaps we should check whether we can compile something
# that uses them, instead, and do something else to figure
# out what compiler flag, if any, we need to pass to the
# compiler to compile code that uses them.
#
if(CMAKE_C_COMPILER_ID MATCHES "MSVC")
	set(HAVE_SSE4_2 TRUE)
else()
	message(STATUS "Checking for c-compiler flag: -msse4.2")
	check_c_compiler_flag(-msse4.2 HAVE_SSE4_2)
endif()

check_c_compiler_flag(-fvisibility=hidden FVHIDDEN)
if(FVHIDDEN)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden")
else() # TODO add alternate compiler flags for hiding symbols
	if( NOT CMAKE_C_COMPILER_ID MATCHES "MSVC")
		message(WARNING "Hiding shared library symbols is not supported by the compiler."
			" All shared library symbols will be exported.")
	endif()
endif()

if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID MATCHES "Clang")
	set (C_UNUSED "__attribute__((unused))" )
else()
	set (C_UNUSED "" )
endif()


if( CMAKE_C_COMPILER_ID MATCHES "MSVC")
	# Set in Makefile.nmake
	set(WIRESHARK_LD_FLAGS
		/LARGEADDRESSAWARE
		/MANIFEST:NO
	)
else()
	set(WIRESHARK_LD_FLAGS
		-Wl,--as-needed
		# -flto
		# -fwhopr
		# -fwhole-program
	)
endif()

include(CheckCLinkerFlag)
set(C 0)
# Sigh: Have to use THIS_FLAG instead of ${F} for some reason
foreach(THIS_FLAG ${WIRESHARK_LD_FLAGS})
	set(F WS_LD_FLAG_${C})
	set(${F} ${THIS_FLAG})
	set(V WS_LD_FLAG_VALID${C})
	check_c_linker_flag(${${F}} ${V})
	if (${${V}})
		set(WS_LINK_FLAGS "${WS_LINK_FLAGS} ${${F}}")
	endif()
	math(EXPR C "${C} + 1")
endforeach()

if(ENABLE_STATIC)
	set(LINK_MODE_LIB STATIC)
	set(LINK_MODE_MODULE STATIC)
else()
	set(LINK_MODE_LIB SHARED)
	set(LINK_MODE_MODULE MODULE)
endif()

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
set(PACKAGELIST Gettext M GLIB2 GMODULE2 GTHREAD2 LEX YACC Perl SED SH PythonInterp)
set(GLIB2_REQUIRED TRUE)
set(GLIB2_FIND_REQUIRED TRUE)
set(GLIB2_MIN_VERSION 2.14.0)
set(GTHREAD2_REQUIRED TRUE)
set(PythonInterp_FIND_VERSION 2)
set(Python_ADDITIONAL_VERSIONS 3)
if (NOT WIN32)
	set(M_REQUIRED TRUE)
endif()

set(PACKAGELIST ${PACKAGELIST} HtmlViewer)

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
			# Used for the creation of setpath.bat
			set( QT5_DLL_PATH "${QT5_BASE_PATH}/bin" )
			set( WS_ALL_LIBS ${WS_ALL_LIBS} ${QT5_DLL_PATH} )
		endif()
		set(PACKAGELIST ${PACKAGELIST} Qt5Widgets Qt5PrintSupport Qt5LinguistTools)
		if (APPLE)
			set(PACKAGELIST ${PACKAGELIST} Qt5MacExtras)
		endif()
		if( WIN32 )
			set(PACKAGELIST ${PACKAGELIST} Qt5WinExtras)
		endif()
		set(QT_VERSION 5)
	else()
		set(PACKAGELIST ${PACKAGELIST} Qt4)
		# set(Qt4_OPTIONS 4.7.1 REQUIRED QtCore QtGui)
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
endif()

# GNU SSL/TLS support
if(ENABLE_GNUTLS)
	set(PACKAGELIST ${PACKAGELIST} GNUTLS)
endif()

# Kerberos
if(ENABLE_KERBEROS)
	set(PACKAGELIST ${PACKAGELIST} KERBEROS)
endif()

# Portable audio
if(ENABLE_PORTAUDIO AND BUILD_wireshark_gtk)
	set(PACKAGELIST ${PACKAGELIST} PORTAUDIO)
endif()


# Prefer c-ares over adns
if(ENABLE_CARES) # C Asynchronouse resolver
	set(PACKAGELIST ${PACKAGELIST} CARES)
elseif(ENABLE_ADNS) # Gnu asynchronous DNS
	set(PACKAGELIST ${PACKAGELIST} ADNS)
endif()

# Zlib compression
if(ENABLE_ZLIB)
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

if(ENABLE_GUIDES)
	set(PACKAGELIST ${PACKAGELIST} DOXYGEN)
endif()

set(PROGLIST text2pcap mergecap capinfos captype editcap reordercap dumpcap)

#Sort the package list
list(SORT PACKAGELIST)
message(STATUS "Packagelist: ${PACKAGELIST}")
#Let's loop the package list
foreach(PACKAGE ${PACKAGELIST})
	if(${PACKAGE} STREQUAL "Qt4")
		set(PACKAGE_VAR "QT")
	elseif(${PACKAGE} STREQUAL "PythonInterp")
		set(PACKAGE_VAR "PYTHONINTERP")
	elseif(${PACKAGE} STREQUAL "Gettext")
		set(PACKAGE_VAR "GETTEXT")
	elseif(${PACKAGE} STREQUAL "HtmlViewer")
		set(PACKAGE_VAR "HTML_VIEWER")
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
		message("${PACKAGE_VAR} FOUND")
		set(HAVE_LIB${PACKAGE_VAR} 1)
		include_directories(${${PACKAGE_VAR}_INCLUDE_DIRS})
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
		message("${PACKAGE_VAR} NOT FOUND")
	endif()
endforeach()

# Provide Windows system lib names
include( UseWinLibs )

# Create file to set paths to run binaries from build dir
WSExtendPath( "${WS_ALL_LIBS}" "${CMAKE_BINARY_DIR}/setpath.bat" )

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
	# HAVE_HEIMDAL_KERBEROS
	set(HAVE_MIT_KERBEROS 1)
	set(HAVE_KEYTYPE_ARCFOUR_56 1)
endif()
if(HAVE_LIBGEOIP)
	set(HAVE_GEOIP 1)
endif()
if(HAVE_LIBCARES)
	set(HAVE_C_ARES 1)
endif()
if(HAVE_LIBADNS)
	set(HAVE_GNU_ADNS 1)
endif()
if(HAVE_LIBNL AND HAVE_AIRPCAP)
	message(ERROR "Airpcap and Libnl support are mutually exclusive")
endif()
if(HAVE_LIBSBC)
	set(HAVE_SBC 1)
endif()

if (HAVE_LIBWINSPARKLE)
	set(HAVE_SOFTWARE_UPDATE 1)
endif()

# No matter which version of GTK is present
if(GTK2_FOUND OR GTK3_FOUND)
	set(GTK_FOUND ON)
endif()
# That's the name autofoo uses
if(HAVE_LIBZLIB)
	set(HAVE_LIBZ 1)
	# Always include the "true" zlib includes first. This works around a
	# bug in the Windows setup of GTK[23] which has a faulty zconf.h.
	include_directories(BEFORE ${ZLIB_INCLUDE_DIRS})
endif()
if (Qt5Widgets_FOUND)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${Qt5Widgets_EXECUTABLE_COMPILE_FLAGS}")
	if (Qt5_POSITION_INDEPENDENT_CODE)
		set(CMAKE_POSITION_INDEPENDENT_CODE ON)
	endif()
	set (QT_FOUND ON)
	set (QT_LIBRARIES ${Qt5Widgets_LIBRARIES} ${Qt5PrintSupport_LIBRARIES})
	if(Qt5MacExtras_FOUND)
		set (QT_LIBRARIES ${QT_LIBRARIES} ${Qt5MacExtras_LIBRARIES})
		# That's the name autofoo uses
		set(QT_MACEXTRAS_LIB 1)
	endif()
	if(Qt5WinExtras_FOUND)
		set (QT_LIBRARIES ${QT_LIBRARIES} ${Qt5WinExtras_LIBRARIES})
		# set(QT_WINEXTRAS_LIB 1) # Not needed?
	endif()
# If Qt4: QT_LIBRARIES and QT_INCLUDES are not set above. They require extra magic
elseif(QT_FOUND)
	include(${QT_USE_FILE})
	include_directories(${QT_INCLUDE_DIR})
	message(STATUS "QT includes: ${QT_INCLUDE_DIR}")
	message(STATUS "QT libs: ${QT_LIBRARIES}")
endif()

message(STATUS "C-Flags: ${CMAKE_C_FLAGS}")
message(STATUS "CXX-Flags: ${CMAKE_CXX_FLAGS}")

include(ConfigureChecks.cmake)

#Big or little endian ?
include(TestBigEndian)
test_big_endian(WORDS_BIGENDIAN)

set(DATAFILE_DIR "${CMAKE_INSTALL_PREFIX}/share/${CPACK_PACKAGE_NAME}")

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

ADD_CUSTOM_TARGET(
	gitversion ALL
	COMMAND ${PERL_EXECUTABLE}
		${CMAKE_CURRENT_SOURCE_DIR}/make-version.pl
		${CMAKE_CURRENT_SOURCE_DIR}
	DEPENDS
		${CMAKE_CURRENT_SOURCE_DIR}/make-version.pl
)
set_target_properties(gitversion PROPERTIES FOLDER "Auxiliary")

ADD_CUSTOM_COMMAND(
	OUTPUT	${CMAKE_BINARY_DIR}/version.h
	COMMAND ${PERL_EXECUTABLE}
		${CMAKE_CURRENT_SOURCE_DIR}/make-version.pl
		${CMAKE_CURRENT_SOURCE_DIR}
	DEPENDS
		${CMAKE_CURRENT_SOURCE_DIR}/make-version.pl
)

if(ENABLE_PLUGINS)
	set(HAVE_PLUGINS 1)
	set(PLUGIN_DIR "${DATAFILE_DIR}/plugins/${CPACK_PACKAGE_VERSION}")
	set(PLUGIN_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION}")
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

foreach(PLUGIN_DIR ${PLUGIN_SRC_DIRS})
	add_subdirectory( ${PLUGIN_DIR} )
endforeach()

if(ENABLE_EXTCAP)
	set(HAVE_EXTCAP 1)
	set(EXTCAP_DIR "${DATAFILE_DIR}/extcap/")
endif()

add_subdirectory( asn1 EXCLUDE_FROM_ALL )
add_subdirectory( capchild )
add_subdirectory( caputils )
add_subdirectory( codecs )
add_subdirectory( epan )
add_subdirectory( tools/lemon )
add_subdirectory( ui )
add_subdirectory( wiretap )
add_subdirectory( wsutil )

if(NOT WIN32)
	add_custom_target(dumpabi DEPENDS dumpabi-libwireshark dumpabi-libwiretap dumpabi-libwsutil color.h)
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


# Basedir where to install guides
set(DOC_DIR "$ENV{docdir}" CACHE FILEPATH "Installation directory for ug and dg pdfs.")
message(STATUS "docdir: ${DOC_DIR}")

if(ENABLE_GUIDES)
	add_subdirectory( docbook )
endif()

if(ENABLE_PCAP_NG_DEFAULT)
	set(PCAP_NG_DEFAULT 1)
endif()

# Large file support (e.g. make off_t 64 bit if supported)
include(gmxTestLargeFiles)
gmx_test_large_files(GMX_LARGEFILES)

add_definitions( -DTOP_SRCDIR=\"${CMAKE_SOURCE_DIR}\" )

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

if(WIN32)
	set(WS_MSVC_NORETURN "__declspec(noreturn)")

	# Disable deprecation
	if(MSVC80 OR MSVC90)
		add_definitions(-D_CRT_SECURE_NO_DEPRECATE -D_CRT_NONSTDC_NO_DEPRECATE)
	endif()
else()
	set(WS_MSVC_NORETURN " ")
endif()

set( VERSION ${PROJECT_VERSION} )
set( configure_input "Built with CMake ${CMAKE_VERSION}" )
configure_file(${CMAKE_SOURCE_DIR}/cmakeconfig.h.in ${CMAKE_BINARY_DIR}/config.h)
set( IN_FILES
	adns_dll.rc
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
	image/libwsutil.rc.in
	image/wiretap.rc.in
	packaging/macosx/Info.plist.in
	plugins/ethercat/plugin.rc.in
	plugins/unistim/plugin.rc.in
	plugins/opcua/plugin.rc.in
	plugins/wimax/plugin.rc.in
	plugins/gryphon/plugin.rc.in
	plugins/profinet/plugin.rc.in
	plugins/m2m/plugin.rc.in
	plugins/stats_tree/plugin.rc.in
	plugins/wimaxasncp/plugin.rc.in
	plugins/mate/plugin.rc.in
	plugins/wimaxmacphy/plugin.rc.in
	plugins/irda/plugin.rc.in
	plugins/docsis/plugin.rc.in
	plugins/easy_codec/plugin.rc.in
	${CUSTOM_PLUGIN_IN_FILES}
	ui/doxygen.cfg.in
	ui/gtk/doxygen.cfg.in
	ui/qt/doxygen.cfg.in
	wireshark.pc.in
)
foreach( _in_file ${IN_FILES} )
	get_filename_component( _path ${_in_file} PATH )
	string( REGEX REPLACE "(.*)\\.in" "\\1" _outfile ${_in_file}  )
	configure_file( ${CMAKE_SOURCE_DIR}/${_in_file} ${CMAKE_BINARY_DIR}/${_outfile} @ONLY )
endforeach()

include(FeatureSummary)
#SET_FEATURE_INFO(NAME DESCRIPTION [URL [COMMENT] ]
SET_FEATURE_INFO(SBC "SBC Codec for Bluetooth A2DP stream playing" "www: http://git.kernel.org/cgit/bluetooth/sbc.git" )

FEATURE_SUMMARY(WHAT ALL)

link_directories(
	${CMAKE_BINARY_DIR}/ui
	${CMAKE_BINARY_DIR}/ui/gtk
	${CMAKE_BINARY_DIR}/ui/qt
	${CMAKE_BINARY_DIR}/capchild
	${CMAKE_BINARY_DIR}/caputils
	${CMAKE_BINARY_DIR}/codecs
	${CMAKE_BINARY_DIR}/epan
	${CMAKE_BINARY_DIR}/wiretap
	${CMAKE_BINARY_DIR}/wsutil
)

if(WIN32)
	set(PLATFORM_UI_SRC
		ui/win32/console_win32.c
		ui/win32/file_dlg_win32.c
		ui/win32/print_win32.c
		image/file_dlg_win32.rc
	)
endif()

# sources common for wireshark, tshark, and rawshark
set(SHARK_COMMON_SRC
	cfile.c
	frame_tvbuff.c
	sync_pipe_write.c
	version_info.c
)

# sources for external capture interfaces
if(ENABLE_EXTCAP)
	set(SHARK_COMMON_SRC
		${SHARK_COMMON_SRC}
		extcap.c
		extcap_parser.c
	)
endif()

set(TSHARK_TAP_SRC
	ui/cli/tap-afpstat.c
	ui/cli/tap-ansi_astat.c
	ui/cli/tap-bootpstat.c
	ui/cli/tap-camelcounter.c
	ui/cli/tap-camelsrt.c
	ui/cli/tap-comparestat.c
	ui/cli/tap-dcerpcstat.c
	ui/cli/tap-diameter-avp.c
	ui/cli/tap-expert.c
	ui/cli/tap-follow.c
	ui/cli/tap-funnel.c
	ui/cli/tap-gsm_astat.c
	ui/cli/tap-h225counter.c
	ui/cli/tap-h225rassrt.c
	ui/cli/tap-hosts.c
	ui/cli/tap-httpstat.c
	ui/cli/tap-icmpstat.c
	ui/cli/tap-icmpv6stat.c
	ui/cli/tap-iostat.c
	ui/cli/tap-iousers.c
	ui/cli/tap-macltestat.c
	ui/cli/tap-mgcpstat.c
	ui/cli/tap-megacostat.c
	ui/cli/tap-protocolinfo.c
	ui/cli/tap-protohierstat.c
	ui/cli/tap-radiusstat.c
	ui/cli/tap-rlcltestat.c
	ui/cli/tap-rpcstat.c
	ui/cli/tap-rpcprogs.c
	ui/cli/tap-rtp.c
	ui/cli/tap-rtspstat.c
	ui/cli/tap-scsistat.c
	ui/cli/tap-sctpchunkstat.c
	ui/cli/tap-sipstat.c
	ui/cli/tap-smbsids.c
	ui/cli/tap-smbstat.c
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
	${CMAKE_BINARY_DIR}/AUTHORS-SHORT
	COPYING
	${CMAKE_BINARY_DIR}/capinfos.html
	${CMAKE_BINARY_DIR}/captype.html
	cfilters
	colorfilters
	dfilters
	${CMAKE_BINARY_DIR}/dftest.html
	${CMAKE_BINARY_DIR}/dumpcap.html
	${CMAKE_BINARY_DIR}/editcap.html
	${CMAKE_BINARY_DIR}/asn2deb.html
	${CMAKE_BINARY_DIR}/idl2deb.html
	${CMAKE_BINARY_DIR}/idl2wrs.html
	ipmap.html
	manuf
	${CMAKE_BINARY_DIR}/mergecap.html
	pdml2html.xsl
	${CMAKE_BINARY_DIR}/randpkt.html
	${CMAKE_BINARY_DIR}/rawshark.html
	${CMAKE_BINARY_DIR}/reordercap.html
	services
	smi_modules
	${CMAKE_BINARY_DIR}/text2pcap.html
	${CMAKE_BINARY_DIR}/tshark.html
	${CMAKE_BINARY_DIR}/wireshark-filter.html
	${CMAKE_BINARY_DIR}/wireshark.html
	docbook/ws.css
)

set(MAN1_FILES
	${CMAKE_BINARY_DIR}/capinfos.1
	${CMAKE_BINARY_DIR}/captype.1
	${CMAKE_BINARY_DIR}/dftest.1
	${CMAKE_BINARY_DIR}/dumpcap.1
	${CMAKE_BINARY_DIR}/editcap.1
	${CMAKE_BINARY_DIR}/idl2wrs.1
	${CMAKE_BINARY_DIR}/mergecap.1
	${CMAKE_BINARY_DIR}/randpkt.1
	${CMAKE_BINARY_DIR}/rawshark.1
	${CMAKE_BINARY_DIR}/reordercap.1
	${CMAKE_BINARY_DIR}/text2pcap.1
	${CMAKE_BINARY_DIR}/tshark.1
	${CMAKE_BINARY_DIR}/wireshark.1
)

set(MAN4_FILES
	${CMAKE_BINARY_DIR}/wireshark-filter.4
)

set(LIBEPAN_LIBS
#		@NSL_LIBS@	# -lnsl
#		@SOCKET_LIBS@	# -lsocket
#		@SSL_LIBS@	# -lcrypto
		epan
#		$(plugin_ldadd)	# in case of static
		${AIRPCAP_LIBRARIES}
		${PCAP_LIBRARIES}
		${CARES_LIBRARIES}
		${ADNS_LIBRARIES}
		${KERBEROS_LIBRARIES}
		${LUA_LIBRARIES}
		${PYTHON_LIBRARIES}
		${GEOIP_LIBRARIES}
		${GCRYPT_LIBRARIES}
		${GNUTLS_LIBRARIES}
		${SMI_LIBRARIES}
		${ZLIB_LIBRARIES}
		${M_LIBRARIES}
		${SBC_LIBRARIES}
		${WINSPARKLE_LIBRARIES}
)

if( (BUILD_wireshark AND QT_FOUND) OR (BUILD_wireshark_gtk AND GTK_FOUND) )
	set(WIRESHARK_SRC
		capture_info.c
		capture_opts.c
		color_filters.c
		file.c
		fileset.c
		summary.c
		${SHARK_COMMON_SRC}
		${PLATFORM_UI_SRC}
	)
	set(wireshark_FILES
		${WIRESHARK_SRC}
		image/wireshark.rc
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
	# Also add -Wl,-rpath,@executable_path/../lib and
	# -Wl,-rpath,/usr/local/lib, so that, if we build an app
	# bundle, we can tweak all the executable images, shared
	# libraries, and plugins in the bundle to look for non-system
	# libraries in the rpath, rather than having a script tweak
	# DYLD_LIBRARY_PATH.
	#

	set(CMAKE_EXE_LINKER_FLAGS
	"-Wl,-headerpad_max_install_names -Wl,-search_paths_first -Wl,-rpath,@executable_path/../lib -Wl,-rpath,@executable_path/../Frameworks -Wl,-rpath,/usr/local/lib ${CMAKE_EXE_LINKER_FLAGS}"
	)

	# Add files to the app bundle
	# Wireshark.app/Contents
	set(BUNDLE_CONTENTS_FILES
		${CMAKE_BINARY_DIR}/packaging/macosx/PkgInfo
	)
	set_source_files_properties(${BUNDLE_CONTENTS_FILES} PROPERTIES
		MACOSX_PACKAGE_LOCATION .
	)

	# Wireshark.app/Contents/Resources
	set(BUNDLE_RESOURCE_FILES
		${CMAKE_SOURCE_DIR}/packaging/macosx/Resources/Wireshark.icns
		${CMAKE_SOURCE_DIR}/packaging/macosx/Resources/Wiresharkdoc.icns
	)
	set_source_files_properties(${BUNDLE_RESOURCE_FILES} PROPERTIES
		MACOSX_PACKAGE_LOCATION Resources
	)

	# Wireshark.app/Contents/Resources/share/man/man1
	set(BUNDLE_RESOURCE_SHARE_MAN1_FILES ${MAN1_FILES})
	set_source_files_properties(${BUNDLE_RESOURCE_SHARE_MAN1_FILES} PROPERTIES
		MACOSX_PACKAGE_LOCATION Resources/share/man/man1
	)

	# Wireshark.app/Contents/Resources/share/man/man1
	set(BUNDLE_RESOURCE_SHARE_MAN4_FILES ${MAN4_FILES})
	set_source_files_properties(${BUNDLE_RESOURCE_SHARE_MAN4_FILES} PROPERTIES
		MACOSX_PACKAGE_LOCATION Resources/share/man/man4
	)

	# Wireshark.app/Contents/Resources/share/wireshark
	set(BUNDLE_RESOURCE_SHARE_WIRESHARK_FILES
		${INSTALL_FILES}
	)
	set_source_files_properties(${BUNDLE_RESOURCE_SHARE_WIRESHARK_FILES} PROPERTIES
		MACOSX_PACKAGE_LOCATION Resources/share/wireshark
	)

	# Wireshark.app/Contents/Resources/share/wireshark/*/*
	# This is a bit messy but copying directories using
	# MACOSX_PACKAGE_LOCATION is currently broken:
	# http://public.kitware.com/Bug/view.php?id=13784
	# We also assume INSTALL_DIRS are all one level deep
	set(BUNDLE_RESOURCE_SHARE_WIRESHARK_SUBIDR_FILES)
	foreach (_subdir ${INSTALL_DIRS})
		file(GLOB _subdir_files RELATIVE ${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/${_subdir}/*)
		list(REMOVE_ITEM _subdir_files ${_subdir}/Custom.make)
		set(BUNDLE_RESOURCE_SHARE_WIRESHARK_SUBIDR_FILES
			${BUNDLE_RESOURCE_SHARE_WIRESHARK_SUBIDR_FILES}
			${_subdir_files}
		)
		set_source_files_properties(${_subdir_files} PROPERTIES
			MACOSX_PACKAGE_LOCATION Resources/share/wireshark/${_subdir}
		)
	endforeach()

	set(EXTRA_BUNDLE_FILES
		${BUNDLE_CONTENTS_FILES}
		${BUNDLE_RESOURCE_FILES}
		${BUNDLE_RESOURCE_SHARE_MAN1_FILES}
		${BUNDLE_RESOURCE_SHARE_MAN4_FILES}
		${BUNDLE_RESOURCE_SHARE_WIRESHARK_FILES}
		${BUNDLE_RESOURCE_SHARE_WIRESHARK_SUBIDR_FILES}
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
		codecs
		${LIBEPAN_LIBS}
		${APPLE_APPLICATION_SERVICES_LIBRARY}
		${APPLE_CORE_FOUNDATION_LIBRARY}
		${APPLE_SYSTEM_CONFIGURATION_LIBRARY}
		${NL_LIBRARIES}
	)
	# wireshark and wireshark-gtk share wireshark_FILES

	# Policy since 2.8.11
	if (POLICY CMP0020)
		cmake_policy(SET CMP0020 OLD)
	endif()

	add_executable(wireshark MACOSX_BUNDLE ${wireshark_FILES} ${EXTRA_BUNDLE_FILES})
	set_target_properties(wireshark PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")
	set_target_properties(wireshark PROPERTIES FOLDER "Executables")
	if(ENABLE_APPLICATION_BUNDLE OR WIN32)
		set_target_properties(wireshark PROPERTIES OUTPUT_NAME Wireshark)
	endif()
	if(ENABLE_APPLICATION_BUNDLE)
		set_target_properties(
			wireshark PROPERTIES
				MACOSX_BUNDLE_INFO_PLIST ${CMAKE_BINARY_DIR}/packaging/macosx/Info.plist
		)
		add_custom_command(
			TARGET wireshark POST_BUILD
			COMMAND ln -sf ${CMAKE_BINARY_DIR}/run/Wireshark.app/Contents/MacOS/Wireshark ${CMAKE_BINARY_DIR}/run/wireshark
		)
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
endif()

# Common properties for CLI executables
macro(set_extra_executable_properties _executable _folder)
	set_target_properties(${_executable} PROPERTIES
		LINK_FLAGS "${WS_LINK_FLAGS}"
		FOLDER ${_folder}
	)

	if(ENABLE_APPLICATION_BUNDLE)
		set_target_properties(${_executable} PROPERTIES
			RUNTIME_OUTPUT_DIRECTORY run/Wireshark.app/Contents/MacOS
		)
	add_custom_command(
		TARGET ${_executable} POST_BUILD
		COMMAND ln -sf ${CMAKE_BINARY_DIR}/run/Wireshark.app/Contents/MacOS/${_executable} ${CMAKE_BINARY_DIR}/run/
	)
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
		codecs
		${PORTAUDIO_LIBRARIES}
		${LIBEPAN_LIBS}
		${APPLE_APPLICATION_SERVICES_LIBRARY}
		${APPLE_CORE_SERVICES_LIBRARY}
		${APPLE_SYSTEM_CONFIGURATION_LIBRARY}
		${NL_LIBRARIES}
		${WIN_COMCTL32_LIBRARY}
	)
	# wireshark and wireshark-gtk share wireshark_FILES

	add_executable(wireshark-gtk ${wireshark_FILES})
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
		tshark-tap-register.c
		tshark.c
		${TSHARK_TAP_SRC}
		${SHARK_COMMON_SRC}
		image/tshark.rc
	)
	add_executable(tshark ${tshark_FILES})
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
		image/tfshark.rc
	)
	add_executable(tfshark ${tfshark_FILES})
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
		image/rawshark.rc
	)
	add_executable(rawshark ${rawshark_FILES})
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
	set_extra_executable_properties(dftest "Tests")
	target_link_libraries(dftest ${dftest_LIBS})
	install(TARGETS dftest RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_randpkt)
	set(randpkt_LIBS
		wiretap
		wsutil
		${M_LIBRARIES}
		${PCAP_LIBRARIES}
#		@SOCKET_LIBS@
#		@NSL_LIBS@
		${CARES_LIBRARIES}
		${ADNS_LIBRARIES}
		${ZLIB_LIBRARIES}
	)
	set(randpkt_FILES
		randpkt.c
	)
	add_executable(randpkt ${randpkt_FILES})
	set_extra_executable_properties(randpkt "Executables")
	target_link_libraries(randpkt ${randpkt_LIBS})
	install(TARGETS randpkt RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_text2pcap)
	set(text2pcap_LIBS
		wsutil
		${M_LIBRARIES}
		${ZLIB_LIBRARIES}
	)
	set(text2pcap_CLEAN_FILES
		text2pcap.c
		pcapio.c
		version_info.c
	)
	set(text2pcap_FILES
		${text2pcap_CLEAN_FILES}
		image/text2pcap.rc
	)
	add_lex_files(text2pcap_FILES
		text2pcap-scanner.l
	)
	add_executable(text2pcap ${text2pcap_FILES})
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
		version_info.c
		image/mergecap.rc
	)
	add_executable(mergecap ${mergecap_FILES})
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
		version_info.c
		image/reordercap.rc
	)
	add_executable(reordercap ${reordercap_FILES})
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
		version_info.c
		image/capinfos.rc
	)
	add_executable(capinfos ${capinfos_FILES})
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
		version_info.c
		image/captype.rc
	)
	add_executable(captype ${captype_FILES})
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
		version_info.c
		image/editcap.rc
	)
	add_executable(editcap ${editcap_FILES})
	set_extra_executable_properties(editcap "Executables")
	target_link_libraries(editcap ${editcap_LIBS})
	install(TARGETS editcap RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_dumpcap AND PCAP_FOUND)
	set(dumpcap_LIBS
		wsutil
		caputils
		${PCAP_LIBRARIES}
		${CAP_LIBRARIES}
#		@SOCKET_LIBS@
#		@NSL_LIBS@
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
		pcapio.c
		ringbuffer.c
		sync_pipe_write.c
		version_info.c
		image/dumpcap.rc
	)
	add_executable(dumpcap ${dumpcap_FILES})
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

ADD_CUSTOM_COMMAND(
	OUTPUT	${CMAKE_BINARY_DIR}/AUTHORS-SHORT
	COMMAND ${PERL_EXECUTABLE}
		${CMAKE_SOURCE_DIR}/doc/perlnoutf.pl
		${CMAKE_SOURCE_DIR}/doc/make-authors-short.pl
		< ${CMAKE_SOURCE_DIR}/AUTHORS
		> ${CMAKE_BINARY_DIR}/AUTHORS-SHORT
	DEPENDS
		${CMAKE_SOURCE_DIR}/doc/perlnoutf.pl
		${CMAKE_SOURCE_DIR}/doc/make-authors-short.pl
		${CMAKE_SOURCE_DIR}/AUTHORS
)

ADD_CUSTOM_COMMAND(
	OUTPUT	${CMAKE_BINARY_DIR}/AUTHORS-SHORT-FORMAT
	COMMAND ${PERL_EXECUTABLE}
		${CMAKE_SOURCE_DIR}/doc/perlnoutf.pl
		${CMAKE_SOURCE_DIR}/doc/make-authors-format.pl
		< ${CMAKE_BINARY_DIR}/AUTHORS-SHORT
		> ${CMAKE_BINARY_DIR}/AUTHORS-SHORT-FORMAT
	DEPENDS
		${CMAKE_SOURCE_DIR}/doc/perlnoutf.pl
		${CMAKE_SOURCE_DIR}/doc/make-authors-format.pl
		${CMAKE_BINARY_DIR}/AUTHORS-SHORT
)

if(WIN32)
FILE(TO_NATIVE_PATH ${CMAKE_SOURCE_DIR}/doc/wireshark.pod.template WPT_WIN_PATH)
FILE(TO_NATIVE_PATH ${CMAKE_BINARY_DIR}/AUTHORS-SHORT-FORMAT ASF_WIN_PATH)
FILE(TO_NATIVE_PATH ${CMAKE_BINARY_DIR}/wireshark.pod WP_WIN_PATH)
ADD_CUSTOM_COMMAND(
        OUTPUT	${CMAKE_BINARY_DIR}/wireshark.pod
        COMMAND copy /B ${WPT_WIN_PATH} + ${ASF_WIN_PATH} ${WP_WIN_PATH}
        DEPENDS
                ${CMAKE_SOURCE_DIR}/doc/wireshark.pod.template
                ${CMAKE_BINARY_DIR}/AUTHORS-SHORT-FORMAT
)
else()

ADD_CUSTOM_COMMAND(
        OUTPUT	${CMAKE_BINARY_DIR}/wireshark.pod
        COMMAND cat
                ${CMAKE_SOURCE_DIR}/doc/wireshark.pod.template
                ${CMAKE_BINARY_DIR}/AUTHORS-SHORT-FORMAT
                > ${CMAKE_BINARY_DIR}/wireshark.pod
        DEPENDS
                ${CMAKE_SOURCE_DIR}/doc/wireshark.pod.template
                ${CMAKE_BINARY_DIR}/AUTHORS-SHORT-FORMAT
)
endif()

if(ENABLE_APPLICATION_BUNDLE)
ADD_CUSTOM_COMMAND(
	OUTPUT ${CMAKE_BINARY_DIR}/packaging/macosx/PkgInfo
	COMMAND ${CMAKE_COMMAND} -E echo APPLWshk > ${CMAKE_BINARY_DIR}/packaging/macosx/PkgInfo
)

ADD_CUSTOM_TARGET(osx-app
	COMMAND ${CMAKE_SOURCE_DIR}/packaging/macosx/osx-app.sh
	WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/run
)
endif()

pod2manhtml( ${CMAKE_SOURCE_DIR}/doc/capinfos 1 )
pod2manhtml( ${CMAKE_SOURCE_DIR}/doc/captype 1 )
pod2manhtml( ${CMAKE_SOURCE_DIR}/doc/dftest 1 )
pod2manhtml( ${CMAKE_SOURCE_DIR}/doc/dumpcap 1 )
pod2manhtml( ${CMAKE_SOURCE_DIR}/doc/editcap 1 )
pod2manhtml( ${CMAKE_SOURCE_DIR}/doc/asn2deb 1 )
pod2manhtml( ${CMAKE_SOURCE_DIR}/doc/idl2deb 1 )
pod2manhtml( ${CMAKE_SOURCE_DIR}/doc/idl2wrs 1 )
pod2manhtml( ${CMAKE_SOURCE_DIR}/doc/mergecap 1 )
pod2manhtml( ${CMAKE_SOURCE_DIR}/doc/randpkt 1 )
pod2manhtml( ${CMAKE_SOURCE_DIR}/doc/rawshark 1 )
pod2manhtml( ${CMAKE_SOURCE_DIR}/doc/reordercap 1 )
pod2manhtml( ${CMAKE_SOURCE_DIR}/doc/text2pcap 1 )
pod2manhtml( ${CMAKE_SOURCE_DIR}/doc/tshark 1 )
pod2manhtml( ${CMAKE_BINARY_DIR}/wireshark 1 )
pod2manhtml( ${CMAKE_SOURCE_DIR}/doc/wireshark-filter 4 )

add_custom_target(
	auxiliary ALL
	DEPENDS
		${CMAKE_BINARY_DIR}/AUTHORS-SHORT
		capinfos.html
		captype.html
		dftest.html
		dumpcap.html
		editcap.html
		asn2deb.html
		idl2deb.html
		idl2wrs.html
		mergecap.html
		randpkt.html
		rawshark.html
		reordercap.html
		text2pcap.html
		tshark.html
		wireshark.html
		wireshark-filter.html
)
set_target_properties(auxiliary PROPERTIES FOLDER "Docs")

set(CLEAN_FILES
	${wireshark_FILES}
	${tshark_FILES}
	${rawshark_FILES}
	${dftest_FILES}
	${randpkt_FILES}
	${text2pcap_CLEAN_FILES}
	${mergecap_FILES}
	${capinfos_FILES}
	${captype_FILES}
	${editcap_FILES}
	${dumpcap_FILES}
)

if (WERROR)
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS -Werror
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
		${MAN1_FILES}
	DESTINATION
		${CMAKE_INSTALL_MANDIR}/man1
)

install(
	FILES
		${MAN4_FILES}
	DESTINATION
		${CMAKE_INSTALL_MANDIR}/man4
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

include( UseCheckAPI )
CHECKAPI(
	${TSHARK_TAP_SRC}
	${WIRESHARK_SRC}
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
