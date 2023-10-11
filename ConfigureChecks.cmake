# ConfigureChecks.cmake
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

include(CMakePushCheckState)

#check system for includes
include(CheckIncludeFile)
include(CheckIncludeFiles)
check_include_file("arpa/inet.h"            HAVE_ARPA_INET_H)
check_include_file("grp.h"                  HAVE_GRP_H)
#
# This may require <sys/types.h> to be included
#
check_include_files("sys/types.h;ifaddrs.h" HAVE_IFADDRS_H)
check_include_file("netinet/in.h"           HAVE_NETINET_IN_H)
check_include_file("netdb.h"                HAVE_NETDB_H)
check_include_file("pwd.h"                  HAVE_PWD_H)
check_include_file("sys/select.h"           HAVE_SYS_SELECT_H)
check_include_file("sys/socket.h"           HAVE_SYS_SOCKET_H)
check_include_file("sys/time.h"             HAVE_SYS_TIME_H)
check_include_file("sys/utsname.h"          HAVE_SYS_UTSNAME_H)
check_include_file("sys/wait.h"             HAVE_SYS_WAIT_H)
check_include_file("unistd.h"               HAVE_UNISTD_H)

#
# On Linux, check for some additional headers, which we need as a
# workaround for a bonding driver bug and for libpcap's current lack
# of its own workaround for that bug.
#
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	#
	# Those header files require <sys/socket.h>.
	#
	check_c_source_compiles(
		"#include <sys/socket.h>
		#include <linux/sockios.h>
		int main(void)
		{
			return 0;
		}"
		HAVE_LINUX_SOCKIOS_H
	)
	check_c_source_compiles(
		"#include <sys/socket.h>
		#include <linux/if_bonding.h>
		int main(void)
		{
			return 0;
		}"
		HAVE_LINUX_IF_BONDING_H
	)
endif()

#Functions
include(CheckFunctionExists)
include(CheckSymbolExists)

#
# Platform-specific functions used in platform-specific code.
# We check for them only on the platform on which we use them.
#
if(CMAKE_SYSTEM_NAME STREQUAL "HP-UX")
	#
	# HP-UX
	#
	cmake_push_check_state()
	set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_DL_LIBS})
	check_function_exists("dlget"           HAVE_DLGET)
	cmake_pop_check_state()
elseif(CMAKE_SYSTEM_NAME STREQUAL "SunOS" AND CMAKE_SYSTEM_VERSION MATCHES "5[.][0-9.]*")
	#
	# Solaris
	#
	check_function_exists("getexecname"     HAVE_GETEXECNAME)
endif()

check_symbol_exists("clock_gettime"  "time.h"   HAVE_CLOCK_GETTIME)
# Some platforms (macOS pre 10.15) are non-conformant with C11 and lack timespec_get()
check_symbol_exists("timespec_get"   "time.h"   HAVE_TIMESPEC_GET)
if(NOT MSVC)
	check_symbol_exists("localtime_r"    "time.h"   HAVE_LOCALTIME_R)
	check_symbol_exists("gmtime_r"       "time.h"   HAVE_GMTIME_R)
	check_symbol_exists("timegm"         "time.h"   HAVE_TIMEGM)
	check_symbol_exists("tzset"          "time.h"   HAVE_TZSET)
	check_symbol_exists("tzname"         "time.h"   HAVE_TZNAME)
endif()
check_function_exists("getifaddrs"       HAVE_GETIFADDRS)
check_function_exists("issetugid"        HAVE_ISSETUGID)
check_function_exists("setresgid"        HAVE_SETRESGID)
check_function_exists("setresuid"        HAVE_SETRESUID)
if (APPLE)
	cmake_push_check_state()
	set(CMAKE_REQUIRED_LIBRARIES ${APPLE_CORE_FOUNDATION_LIBRARY})
	check_function_exists("CFPropertyListCreateWithStream" HAVE_CFPROPERTYLISTCREATEWITHSTREAM)
	cmake_pop_check_state()
endif()
if(UNIX)
	cmake_push_check_state()
	list(APPEND CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)
	check_symbol_exists("memmem"        "string.h"   HAVE_MEMMEM)
	check_symbol_exists("memrchr"       "string.h"   HAVE_MEMRCHR)
	check_symbol_exists("strerrorname_np" "string.h" HAVE_STRERRORNAME_NP)
	check_symbol_exists("strptime"      "time.h"     HAVE_STRPTIME)
	check_symbol_exists("vasprintf"     "stdio.h"    HAVE_VASPRINTF)
	cmake_pop_check_state()
endif()

#Struct members
include(CheckStructHasMember)
check_struct_has_member("struct stat"     st_blksize     sys/stat.h   HAVE_STRUCT_STAT_ST_BLKSIZE)
check_struct_has_member("struct stat"     st_birthtime   sys/stat.h   HAVE_STRUCT_STAT_ST_BIRTHTIME)
check_struct_has_member("struct stat"     __st_birthtime sys/stat.h   HAVE_STRUCT_STAT___ST_BIRTHTIME)
check_struct_has_member("struct tm"       tm_zone        time.h       HAVE_STRUCT_TM_TM_ZONE)
check_struct_has_member("struct tm"       tm_gmtoff      time.h       HAVE_STRUCT_TM_TM_GMTOFF)

# Types
include(CheckTypeSize)
check_type_size("ssize_t"       SSIZE_T)

#
# Check if the libc vsnprintf() conforms to C99. If this fails we may
# need to fall-back on GLib I/O.
#
# If cross-compiling we can't check so just assume this requirement is met.
#
if(NOT CMAKE_CROSSCOMPILING)
	check_c_source_runs("
		#include <stdio.h>
		int main(void)
		{
			/* Check that snprintf() and vsnprintf() don't return
			* -1 if the buffer is too small. C99 says this value
			* is the length that would be written not including
			* the nul byte. */
			char buf[3];
			return snprintf(buf, sizeof(buf), \"%s\", \"ABCDEF\") > 0 ? 0 : 1;
		}"
		HAVE_C99_VSNPRINTF
	)
	if (NOT HAVE_C99_VSNPRINTF)
		message(FATAL_ERROR
"Building Wireshark requires a C99 compliant vsnprintf() and this \
target does not meet that requirement. Compiling for ${CMAKE_SYSTEM} \
using ${CMAKE_C_COMPILER_ID}. Please report this issue to the Wireshark \
developers at wireshark-dev@wireshark.org."
		)
	endif()
endif()

#
# *If* we found libnl, check if we can use nl80211 stuff with it.
#
if (NL_FOUND)
	check_c_source_compiles(
		"#include <linux/nl80211.h>
		int main(void) {
			int x = NL80211_FREQUENCY_ATTR_MAX_TX_POWER;
			x |= NL80211_ATTR_SUPPORTED_IFTYPES;
			x |= NL80211_ATTR_SUPPORTED_COMMANDS;
			x |= NL80211_ATTR_WIPHY_FREQ;
			x |= NL80211_CHAN_NO_HT;
			(void)x;
		}"
		HAVE_NL80211
	)
	check_c_source_compiles(
		"#include <linux/nl80211.h>
		int main(void) {
			enum nl80211_commands x = NL80211_CMD_SET_CHANNEL;
		}"
		HAVE_NL80211_CMD_SET_CHANNEL
	)
	check_c_source_compiles(
		"#include <linux/nl80211.h>
		int main(void) {
			enum nl80211_protocol_features x = NL80211_PROTOCOL_FEATURE_SPLIT_WIPHY_DUMP;
		}"
		HAVE_NL80211_SPLIT_WIPHY_DUMP
	)
	check_c_source_compiles(
		"#include <linux/nl80211.h>
		int main(void) {
			enum nl80211_attrs x = NL80211_ATTR_VHT_CAPABILITY;
		}"
		HAVE_NL80211_VHT_CAPABILITY
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
