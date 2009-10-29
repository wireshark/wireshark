# CMakeLists.txt
#
# $Id$
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#

project(Wireshark C)

cmake_minimum_required(VERSION 2.6)

#Where to find local cmake scripts
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules)
INCLUDE(UseLemon)
INCLUDE(UseMakeDissectorReg)
INCLUDE(UseMakeTapReg)

# Under linux the release mode (CMAKE_BUILD_TYPE=release) defines NDEBUG

# Disable this later. Alternative: "make VERBOSE=1"
set(CMAKE_VERBOSE_MAKEFILE ON)

set(BUILD_SHARED_LIBS ON)

#Defines CMAKE_INSTALL_BINDIR, CMAKE_INSTALL_DATADIR, etc ...
include(CMakeInstallDirs)

include_directories(
	${CMAKE_BINARY_DIR}
	${CMAKE_SOURCE_DIR}
	${CMAKE_SOURCE_DIR}/epan
	${CMAKE_SOURCE_DIR}/tools/lemon
	${CMAKE_SOURCE_DIR}/wiretap
)

#Where to put libraries
if(NOT LIBRARY_OUTPUT_PATH)
	set(LIBRARY_OUTPUT_PATH ${Wireshark_BINARY_DIR}/lib CACHE INTERNAL
		   "Single output directory for building all libraries.")
endif()

option(BUILD_wireshark   "Build the GUI version of Wireshark" ON)
option(BUILD_tshark      "Build tshark" ON)
option(BUILD_rawshark    "Build rawshark" ON)
option(BUILD_dumpcap     "Build dumpcap" ON)
option(BUILD_text2pcap   "Build text2pcap" ON)
option(BUILD_mergecap    "Build mergecap" ON)
option(BUILD_editcap     "Build editcap" ON)
option(BUILD_capinfos    "Build capinfos" ON)
option(BUILD_randpkt     "Build randpkt" ON)
option(BUILD_dftest      "Build dftest" ON)
option(AUTOGEN_dcerpc    "Autogenerate dcerpc dissectors" OFF)
option(AUTOGEN_pidl      "Autogenerate pidl dissectors" OFF)

option(DISABLE_WERROR	 "Do not treat Warnings as errors" OFF)
option(ENABLE_EXTRA_GCC_CHECKS "Do additional -W checks in GCC (disables -Werror)" ON)
option(ENABLE_AIRPCAP	 "Enable Airpcap support" ON)
# todo
option(ENABLE_STATIC     "Build a static version of Wireshark" OFF)
option(ENABLE_PLUGINS    "Build with plugins" ON)

option(ENABLE_ADNS       "Build with adns support" ON)
option(ENABLE_PCRE       "Build with pcre support" ON)
option(ENABLE_PORTAUDIO  "Build with portaudio support" ON)
option(ENABLE_Z          "Build with zlib compression support" ON)
option(ENABLE_LUA	 "Build with lua dissector support" ON)
option(ENABLE_PYTHON	 "Build with python dissector support" ON)
option(ENABLE_SMI	 "Build with smi snmp support" ON)
option(ENABLE_GNUTLS	 "Build with GNU TLS support" ON)
option(ENABLE_GCRYPT	 "Build with GNU crypto support" ON)
option(ENABLE_GEOIP	 "Build with GeoIP support" ON)
option(ENABLE_CAP	 "Build with posix capabilities support" ON)
option(ENABLE_CARES      "Build with c_ares support" ON)
# todo Mostly hardcoded
option(ENABLE_KERBEROS	 "Build with Kerberos support" ON)


set(WIRESHARK_C_FLAGS
	-O2
	-Werror
	-Wall
	-W
	-Wextra
	-Wdeclaration-after-statement
	-Wendif-labels
	-Wpointer-arith
	-Wno-pointer-sign
	-Warray-bounds
	-Wcast-align
	-Wformat-security
)

set(WIRESHARK_EXTRA_C_FLAGS
	-pedantic
	-Woverflow
	-Wlogical-op
	-Wno-overlength-strings
	-fstrict-overflow -Wstrict-overflow=4
	-Wunreachable-code
	-Wunsafe-loop-optimizations
	-Wno-long-long
	-Wbad-function-cast
	-Wcast-qual
	-Waddress
	-Warray-bounds
	-Wattributes
	-Wdiv-by-zero
	-Wformat-security
	-Wignored-qualifiers
	-Wpragmas
	-Wredundant-decls
	-Wvla
	# packet-ncp2222.inc prevents this from going into all warnings
	-Wwrite-strings
	-Wstrict-prototypes
	-Wmissing-declarations
	# Problem with packet-afs.c
	-Wshadow
	# More cleanup needed for this on LP64
	-Wshorten-64-to-32
)

if(ENABLE_EXTRA_GCC_CHECKS)
	set(WIRESHARK_C_FLAGS ${WIRESHARK_C_FLAGS} ${WIRESHARK_EXTRA_C_FLAGS})
endif()

add_definitions(
	-DHAVE_CONFIG_H
	-DPACKAGE=\"wireshark\"
	-DNEW_PACKET_LIST
)

# Counterhack to work around some cache magic in CHECK_C_SOURCE_COMPILES
include(CheckCCompilerFlag)
set(C 0)
# Sigh: Have to use THIS_FLAG instead of ${F} for some reason
foreach(THIS_FLAG ${WIRESHARK_C_FLAGS})
	set(F WS_C_FLAG_${C})
	set(${F} ${THIS_FLAG})
	set(V WS_C_FLAG_VALID${C})
	check_c_compiler_flag(${${F}} ${V})
	if (${${V}})
		add_definitions(${${F}})
	endif()
	math(EXPR C "${C} + 1")
endforeach()

if(DISABLE_WERROR OR ENABLE_EXTRA_GCC_CHECKS)
	remove_definitions( -Werror )
endif()

if(CMAKE_COMPILER_IS_GNUCC)
	add_definitions( -D_U_=__attribute__\(\(unused\)\) )
else()
	add_definitions( -D_U_=\"\" )
endif()

# todo
# Same for linker flags, but it looks like it's do-it-yourself here
# AC_WIRESHARK_GCC_LDFLAGS_CHECK([-Wl,--as-needed])

#The minimum package list
set(PACKAGELIST GLIB2 PCAP M LEX YACC Perl SH PythonInterp HtmlViewer ${PACKAGELIST})

#Build the gui ?
if(BUILD_wireshark)
	set(PACKAGELIST GTK2 ${PACKAGELIST})
endif()

# SMI SNMP
if(ENABLE_SMI)
	set(PACKAGELIST SMI ${PACKAGELIST})
endif()

# GNU crypto
if(ENABLE_GCRYPT)
	set(PACKAGELIST GCRYPT ${PACKAGELIST})
endif()

# GNU SSL/TLS support
if(ENABLE_GNUTLS)
	set(PACKAGELIST GNUTLS ${PACKAGELIST})
endif()

# Regular expressions lib
if(ENABLE_PCRE)
	set(PACKAGELIST PCRE ${PACKAGELIST})
endif()

# Kerberos
if(ENABLE_KERBEROS)
	set(PACKAGELIST KERBEROS ${PACKAGELIST})
endif()

# Portable audio
if(ENABLE_PORTAUDIO)
	set(PACKAGELIST PORTAUDIO ${PACKAGELIST})
endif()


# Prefer c-ares over adns
if(ENABLE_CARES)        # C Asynchronouse resolver
	set(PACKAGELIST CARES ${PACKAGELIST})
elseif(ENABLE_ADNS)     # Gnu asynchronous DNS
	set(PACKAGELIST ADNS ${PACKAGELIST})
endif()

# Zlib compression
if(ENABLE_Z)
	set(PACKAGELIST Z ${PACKAGELIST})
endif()

# Lua 5.1 dissectors
if(ENABLE_LUA)
	set(PACKAGELIST LUA ${PACKAGELIST})
endif()

# GeoIP address resolving
if(ENABLE_GEOIP)
	set(PACKAGELIST GEOIP ${PACKAGELIST})
endif()

# Capabilities
if(ENABLE_CAP)
	set(PACKAGELIST CAP ${PACKAGELIST})
endif()

if(ENABLE_PYTHON)
	set(PACKAGELIST PYTHON ${PACKAGELIST})
endif()

set(PROGLIST text2pcap mergecap capinfos editcap dumpcap)

#Let's loop the package list
foreach(PACKAGE ${PACKAGELIST})
	find_package(${PACKAGE} REQUIRED)
	message(${PACKAGE}_FOUND)
	if (${PACKAGE}_FOUND)
		set(HAVE_LIB${PACKAGE} 1)
		include_directories(${${PACKAGE}_INCLUDE_DIRS})
		message(STATUS "${PACKAGE} includes: ${${PACKAGE}_INCLUDE_DIRS}")
		message(STATUS "${PACKAGE} libs: ${${PACKAGE}_LIBRARIES}")
	endif()
endforeach()

find_package(YAPP)

if(HAVE_LIBPYTHON)
	set(HAVE_PYTHON 1)
	set(PYTHON_DIR "${CMAKE_INSTALL_PREFIX}/lib/wireshark/python/${VERSION}")
endif()
if(HAVE_LIBLUA)
	set(HAVE_LUA_H 1)
	set(HAVE_LUA_5_1 1)
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
if(ENABLE_AIRPCAP)
	set(HAVE_AIRPCAP 1)
endif()

include(ConfigureChecks.cmake)

#Big or little endian ?
include(TestBigEndian)
test_big_endian(WORDS_BIGENDIAN)

#packaging
set(CPACK_PACKAGE_NAME wireshark)
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "capture packet")
set(CPACK_PACKAGE_VENDOR "wireshark")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/COPYING")
set(CPACK_PACKAGE_VERSION_MAJOR "1")
set(CPACK_PACKAGE_VERSION_MINOR "3")
set(CPACK_PACKAGE_VERSION_PATCH "2")
set(CPACK_PACKAGE_VERSION "${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")

set(CPACK_SOURCE_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "/usr")
set(CPACK_GENERATOR "TGZ")
set(CPACK_SOURCE_GENERATOR "TGZ")

set(DATAFILE_DIR "${CMAKE_INSTALL_PREFIX}/share/${CPACK_PACKAGE_NAME}")

if(ENABLE_PLUGINS)
	set(HAVE_PLUGINS 1)
	set(PLUGIN_DIR="${DATAFILE_DIR}/plugins/${CPACK_PACKAGE_VERSION}")
	set(PLUGIN_SRC_DIRS
		plugins/asn1
		plugins/docsis
		plugins/ethercat
		plugins/giop
		plugins/gryphon
		plugins/irda
		plugins/m2m
		plugins/mate
		plugins/opcua
		plugins/profinet
		plugins/sercosiii
		plugins/stats_tree
		plugins/unistim
		plugins/wimax
		plugins/wimaxasncp
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

add_subdirectory( codecs )
add_subdirectory( epan )
add_subdirectory( gtk )
add_subdirectory( tools/lemon )
add_subdirectory( wiretap )
add_subdirectory( wsutil )

#Platform specific
if(UNIX)
	set(WS_VAR_IMPORT "extern")
endif()

if(APPLE)
#TODO verify that APPLE implies HAVE_OS_X_FRAMEWORKS
	set(HAVE_OS_X_FRAMEWORKS 1)
	FIND_LIBRARY (APPLE_CORE_SERVICES_LIBRARY CoreServices)
	FIND_LIBRARY (APPLE_COCOA_LIBRARY Cocoa)
endif()

if(WIN32)
	add_definitions(-D_NEED_VAR_IMPORT_)
	set(WS_VAR_IMPORT "__declspec(dllimport) extern")

	# Disable deprecation
	if(MSVC80 OR MSVC90)
		add_definitions(-D_CRT_SECURE_NO_DEPRECATE -D_CRT_NONSTDC_NO_DEPRECATE)
	endif()
endif()

configure_file(${CMAKE_SOURCE_DIR}/cmakeconfig.h.in ${CMAKE_BINARY_DIR}/config.h)

include(FeatureSummary)
#SET_FEATURE_INFO(NAME DESCRIPTION [URL [COMMENT] ]
PRINT_ENABLED_FEATURES()
PRINT_DISABLED_FEATURES()

link_directories(
	gtk
	codecs
	epan
	wiretap
	wsutil
)

ADD_CUSTOM_COMMAND(
	OUTPUT svnversion.h
	COMMAND ${PERL}
		${CMAKE_CURRENT_SOURCE_DIR}/make-version.pl
		${CMAKE_CURRENT_SOURCE_DIR}
	DEPENDS
		${CMAKE_CURRENT_SOURCE_DIR}/make-version.pl
)

register_tap_files(tshark-tap-register.c
	${TSHARK_TAP_SRC}
)

ADD_CUSTOM_COMMAND(
	OUTPUT ps.c
	COMMAND ${PYTHON_EXECUTABLE}
	  ${CMAKE_CURRENT_SOURCE_DIR}/tools/rdps.py
	  ${CMAKE_CURRENT_SOURCE_DIR}/print.ps
	  ps.c
	DEPENDS
	  ${CMAKE_CURRENT_SOURCE_DIR}/tools/rdps.py
	  ${CMAKE_CURRENT_SOURCE_DIR}/print.ps
)

if(UNIX)
	set(PLATFORM_SRC
		capture-pcap-util-unix.c
	)
endif()

if(WIN32)
	set(PLATFORM_SRC
		capture-wpcap.c capture_wpcap_packet.c
	)
endif()

set(WTAP_PLUGIN_SOURCES
	epan/plugins.c
	epan/report_err.c
	epan/filesystem.c
)

set(WIRESHARK_COMMON_SRC
	${PLATFORM_SRC}
	capture_errs.c
	capture-pcap-util.c
	capture_ui_utils.c
	cfile.c
	clopts_common.c
	disabled_protos.c
	packet-range.c
	print.c
	ps.c
	sync_pipe_write.c
	timestats.c
	util.c
	tap-megaco-common.c
	tap-rtp-common.c
	version_info.c
)

set(TSHARK_TAP_SRC
        tap-afpstat.c
        tap-ansi_astat.c
        tap-bootpstat.c
        tap-camelcounter.c
        tap-camelsrt.c
        tap-comparestat.c
        tap-dcerpcstat.c
        tap-funnel.c
        tap-gsm_astat.c
        tap-h225counter.c
        tap-h225rassrt.c
        tap-httpstat.c
        tap-iostat.c
        tap-iousers.c
        tap-mgcpstat.c
        tap-megacostat.c
        tap-protocolinfo.c
        tap-protohierstat.c
        tap-radiusstat.c
        tap-rpcstat.c
        tap-rpcprogs.c
        tap-rtp.c
        tap-sctpchunkstat.c
        tap-sipstat.c
        tap-smbsids.c
        tap-smbstat.c
        tap-stats_tree.c
        tap-wspstat.c
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
#	capinfos.html
	cfilters
	colorfilters
#	console.lua
	dfilters
#	dtd_gen.lua
#	dumpcap.html
#	editcap.html
#	idl2wrs.html
#	init.lua
#	ipmap.html
	manuf
#	mergecap.html
#	rawshark.html
	services
	smi_modules
#	text2pcap.html
#	tshark.html
#	wireshark-filter.html
#	wireshark.html
#	ws.css
)

set(LIBEPAN_LIBS
#		$(wireshark_optional_objects)
		epan
#		@INET_PTON_LO@
#		@INET_NTOP_LO@
#		@SSL_LIBS@
#		$(plugin_ldadd)
		${PCRE_LIBRARIES}
		${PCAP_LIBRARIES}
#		@SOCKET_LIBS@
#		@NSL_LIBS@
		${CARES_LIBRARIES}
		${ADNS_LIBRARIES}
		${KERBEROS_LIBRARIES}
#		@FRAMEWORKS@
		${LUA_LIBRARIES}
		${PYTHON_LIBRARIES}
		${GEOIP_LIBRARIES}
		${GCRYPT_LIBRARIES}
		${GNUTLS_LIBRARIES}
		${SMI_LIBRARIES}
		${Z_LIBRARIES}
		${M_LIBRARIES}
)

if(BUILD_wireshark)
	set(wireshark_LIBS
		ui
		${GTK2_LIBRARIES}
		codecs
		${PORTAUDIO_LIBRARIES}
		${LIBEPAN_LIBS}
		${APPLE_CORE_SERVICES_LIBRARY}
		${APPLE_COCOA_LIBRARY}
	)
	set(wireshark_FILES
		airpcap_loader.c
		alert_box.c
		capture.c
		capture_info.c
		capture_opts.c
		capture_sync.c
		color_filters.c
		file.c
		fileset.c
		filters.c
		g711.c
		merge.c
		proto_hier_stats.c
		summary.c
		tempfile.c
		${WIRESHARK_COMMON_SRC}
	)
	add_executable(wireshark ${wireshark_FILES})
	target_link_libraries(wireshark ${wireshark_LIBS})
	install(TARGETS wireshark RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_tshark)
	set(tshark_LIBS
		${LIBEPAN_LIBS}
		${APPLE_COCOA_LIBRARY}
	)
	set(tshark_FILES
		capture_opts.c
		capture_sync.c
		tempfile.c
		tshark-tap-register.c
		tshark.c
		${TSHARK_TAP_SRC}
	        ${WIRESHARK_COMMON_SRC}
	)
	add_executable(tshark ${tshark_FILES})
	target_link_libraries(tshark ${tshark_LIBS})
	install(TARGETS tshark RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_rawshark)
	set(rawshark_LIBS
		${LIBEPAN_LIBS}
		${APPLE_COCOA_LIBRARY}
	)
	set(rawshark_FILES
	        ${WIRESHARK_COMMON_SRC}
		rawshark.c
	)
	add_executable(rawshark ${rawshark_FILES})
	target_link_libraries(rawshark ${rawshark_LIBS})
	install(TARGETS rawshark RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_dftest)
	set(dftest_LIBS
		${LIBEPAN_LIBS}
	)
	set(dftest_FILES
		dftest.c
		util.c
	)
	add_executable(dftest ${dftest_FILES})
	target_link_libraries(dftest ${dftest_LIBS})
	install(TARGETS dftest RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_randpkt)
	set(randpkt_LIBS
		wiretap
		${M_LIBRARIES}
		${PCAP_LIBRARIES}
#		@SOCKET_LIBS@
#		@NSL_LIBS@
		${CARES_LIBRARIES}
		${ADNS_LIBRARIES}
		${Z_LIBRARIES}
	)
	set(randpkt_FILES
		randpkt.c
	)
	add_executable(randpkt ${randpkt_FILES})
	target_link_libraries(randpkt ${randpkt_LIBS})
	install(TARGETS randpkt RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_text2pcap)
	set(text2pcap_LIBS
		wiretap
		${M_LIBRARIES}
		${Z_LIBRARIES}
	)
	set(text2pcap_FILES
		text2pcap.c
	)
	add_lex_files(text2pcap_FILES
		text2pcap-scanner.l
	)
	add_executable(text2pcap ${text2pcap_FILES})
	target_link_libraries(text2pcap ${text2pcap_LIBS})
	install(TARGETS text2pcap RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_mergecap)
	set(mergecap_LIBS
		wiretap
		${Z_LIBRARIES}
	)
	set(mergecap_FILES
		mergecap.c
		merge.c
		svnversion.h
	)
	add_executable(mergecap ${mergecap_FILES})
	target_link_libraries(mergecap ${mergecap_LIBS})
	install(TARGETS mergecap RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_capinfos)
	set(capinfos_LIBS
		wiretap
		${Z_LIBRARIES}
		${APPLE_COCOA_LIBRARY}
	)
	set(capinfos_FILES
		capinfos.c
		${WTAP_PLUGIN_SOURCES}
	)
	add_executable(capinfos ${capinfos_FILES})
	target_link_libraries(capinfos ${capinfos_LIBS})
	install(TARGETS capinfos RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_editcap)
	set(editcap_LIBS
		wiretap
		${Z_LIBRARIES}
	)
	set(editcap_FILES
		editcap.c
		epan/crypt/crypt-md5.c
		epan/nstime.c
		${WTAP_PLUGIN_SOURCES}
	)
	add_executable(editcap ${editcap_FILES})
	target_link_libraries(editcap ${editcap_LIBS})
	install(TARGETS editcap RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_dumpcap)
	set(dumpcap_LIBS
		wiretap
#		@INET_NTOP_LO@
		${PCAP_LIBRARIES}
		${CAP_LIBRARIES}
#		@SOCKET_LIBS@
#		@NSL_LIBS@
#		@FRAMEWORKS@
		${GCRYPT_LIBRARIES}
		${GNUTLS_LIBRARIES}
		${Z_LIBRARIES}
		${APPLE_COCOA_LIBRARY}
	)
	set(dumpcap_FILES
		svnversion.h
		capture_opts.c
		capture-pcap-util.c
		capture_stop_conditions.c
		clopts_common.c
		conditions.c
		dumpcap.c
		pcapio.c
		ringbuffer.c
		sync_pipe_write.c
		tempfile.c
		version_info.c
		${PLATFORM_SRC}
	)
	add_executable(dumpcap ${dumpcap_FILES})
	target_link_libraries(dumpcap ${dumpcap_LIBS})
	install(TARGETS dumpcap RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

ADD_CUSTOM_COMMAND(
	OUTPUT	AUTHORS-SHORT
	COMMAND ${PERL}
		${CMAKE_SOURCE_DIR}/doc/perlnoutf.pl
		${CMAKE_SOURCE_DIR}/doc/make-authors-short.pl
		< ${CMAKE_SOURCE_DIR}/AUTHORS
		> AUTHORS-SHORT
	DEPENDS
		${CMAKE_SOURCE_DIR}/doc/perlnoutf.pl
		${CMAKE_SOURCE_DIR}/doc/make-authors-short.pl
		${CMAKE_SOURCE_DIR}/AUTHORS
)

add_custom_target(
	auxiliary ALL
	DEPENDS
		AUTHORS-SHORT
		# todo: Add manpages and onlinedocs and generate them
)

install(
	FILES
		${INSTALL_FILES}
	DESTINATION
		${CMAKE_INSTALL_DATADIR}/${CPACK_PACKAGE_NAME}
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
	PATTERN ".svn" EXCLUDE
	PATTERN "Makefile.*" EXCLUDE
	PATTERN "faq.py" EXCLUDE
)
