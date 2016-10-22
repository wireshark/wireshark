# ConfigureChecks.cmake
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

include(CMakePushCheckState)

#check system for includes
include(CheckIncludeFile)
check_include_file("arpa/inet.h"         HAVE_ARPA_INET_H)
check_include_file("arpa/nameser.h"      HAVE_ARPA_NAMESER_H)
check_include_file("dlfcn.h"             HAVE_DLFCN_H)
check_include_file("fcntl.h"             HAVE_FCNTL_H)
check_include_file("getopt.h"            HAVE_GETOPT_H)
check_include_file("grp.h"               HAVE_GRP_H)
check_include_file("ifaddrs.h"           HAVE_IFADDRS_H)
check_include_file("inttypes.h"          HAVE_INTTYPES_H)
check_include_file("netinet/in.h"        HAVE_NETINET_IN_H)
check_include_file("netdb.h"             HAVE_NETDB_H)
# We need to set the path to Wpdpack in order to find Ntddndis.h
#cmake_push_check_state()
#set(CMAKE_REQUIRED_INCLUDES ${PCAP_INCLUDE_DIRS})
#check_include_file("Ntddndis.h"          HAVE_NTDDNDIS_H)
#cmake_pop_check_state()
check_include_file("portaudio.h"         HAVE_PORTAUDIO_H)
check_include_file("pwd.h"               HAVE_PWD_H)
check_include_file("stdint.h"            HAVE_STDINT_H)
check_include_file("sys/ioctl.h"         HAVE_SYS_IOCTL_H)
check_include_file("sys/param.h"         HAVE_SYS_PARAM_H)
check_include_file("sys/socket.h"        HAVE_SYS_SOCKET_H)
check_include_file("sys/sockio.h"        HAVE_SYS_SOCKIO_H)
check_include_file("sys/stat.h"          HAVE_SYS_STAT_H)
check_include_file("sys/time.h"          HAVE_SYS_TIME_H)
check_include_file("sys/types.h"         HAVE_SYS_TYPES_H)
check_include_file("sys/utsname.h"       HAVE_SYS_UTSNAME_H)
check_include_file("sys/wait.h"          HAVE_SYS_WAIT_H)
check_include_file("unistd.h"            HAVE_UNISTD_H)
check_include_file("windows.h"           HAVE_WINDOWS_H)
check_include_file("winsock2.h"          HAVE_WINSOCK2_H)

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
check_function_exists("chown"            HAVE_CHOWN)

cmake_push_check_state()
set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_DL_LIBS})
check_function_exists("dladdr"           HAVE_DLADDR)
cmake_pop_check_state()

#
# Use check_symbol_exists just in case math.h does something magic
# and there's not actually a function named floorl()
#
cmake_push_check_state()
set(CMAKE_REQUIRED_INCLUDES ${M_INCLUDE_DIRS})
set(CMAKE_REQUIRED_LIBRARIES ${M_LIBRARIES})
check_symbol_exists("floorl" "math.h"    HAVE_FLOORL)
check_symbol_exists("lrint"  "math.h"    HAVE_LRINT)
cmake_pop_check_state()

check_function_exists("getopt_long"      HAVE_GETOPT_LONG)
if(HAVE_GETOPT_LONG)
	if(HAVE_GETOPT_H)
		check_symbol_exists("optreset" "getopt.h" HAVE_OPTRESET)
	else()
		check_symbol_exists("optreset"           HAVE_OPTRESET)
	endif()
endif()
check_function_exists("getprotobynumber" HAVE_GETPROTOBYNUMBER)
check_function_exists("getifaddrs"       HAVE_GETIFADDRS)
check_function_exists("inet_aton"        HAVE_INET_ATON)
check_function_exists("inet_ntop"        HAVE_INET_NTOP)
check_function_exists("inet_pton"        HAVE_INET_PTON)
check_function_exists("issetugid"        HAVE_ISSETUGID)
check_function_exists("mkdtemp"          HAVE_MKDTEMP)
check_function_exists("mkstemps"         HAVE_MKSTEMPS)
check_function_exists("popcount"         HAVE_POPCOUNT)
check_function_exists("setresgid"        HAVE_SETRESGID)
check_function_exists("setresuid"        HAVE_SETRESUID)
check_function_exists("strptime"         HAVE_STRPTIME)
check_function_exists("sysconf"          HAVE_SYSCONF)
if (APPLE)
	cmake_push_check_state()
	set(CMAKE_REQUIRED_LIBRARIES ${APPLE_CORE_FOUNDATION_LIBRARY})
	check_function_exists("CFPropertyListCreateWithStream" HAVE_CFPROPERTYLISTCREATEWITHSTREAM)
	cmake_pop_check_state()
endif()

#Struct members
include(CheckStructHasMember)
check_struct_has_member("struct sockaddr" sa_len         sys/socket.h HAVE_STRUCT_SOCKADDR_SA_LEN)
check_struct_has_member("struct stat"     st_flags       sys/stat.h   HAVE_STRUCT_STAT_ST_FLAGS)
check_struct_has_member("struct stat"     st_birthtime   sys/stat.h   HAVE_STRUCT_STAT_ST_BIRTHTIME)
check_struct_has_member("struct stat"     __st_birthtime sys/stat.h   HAVE_STRUCT_STAT___ST_BIRTHTIME)
check_struct_has_member("struct tm"       tm_zone        time.h       HAVE_STRUCT_TM_TM_ZONE)

#Symbols but NOT enums or types
check_symbol_exists(tzname "time.h" HAVE_TZNAME)

# Check for stuff that isn't testable via the tests above

#
# *If* we found libnl, check if we can use nl80211 stuff with it.
#
if (NL_FOUND)
	check_c_source_compiles(
		"#include <linux/nl80211.h>
		int main() {
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
		int main() {
			enum nl80211_commands x = NL80211_CMD_SET_CHANNEL;
		}"
		HAVE_NL80211_CMD_SET_CHANNEL
	)
	check_c_source_compiles(
		"#include <linux/nl80211.h>
		int main() {
			enum nl80211_protocol_features x = NL80211_PROTOCOL_FEATURE_SPLIT_WIPHY_DUMP;
		}"
		HAVE_NL80211_SPLIT_WIPHY_DUMP
	)
	check_c_source_compiles(
		"#include <linux/nl80211.h>
		int main() {
			enum nl80211_attrs x = NL80211_ATTR_VHT_CAPABILITY;
		}"
		HAVE_NL80211_VHT_CAPABILITY
	)
endif()

#
# Check whether GLib's printf supports thousands grouping. (This might
# be different from the system's printf since GLib can optionally use
# its own printf implementation.)
#
if (CMAKE_CROSSCOMPILING OR WIN32)
	#
	# Play it safe when cross-compiling.
	#
	# XXX - compiling and trying to run the test below appears
	# to loop infinitely on Windows, and the locale is wrong in
	# any case, so we don't do this on Window for now.
	#
	set(HAVE_GLIB_PRINTF_GROUPING FALSE)
else()
	cmake_push_check_state()
	set(CMAKE_REQUIRED_INCLUDES ${GLIB2_INCLUDE_DIRS})
	set(CMAKE_REQUIRED_LIBRARIES ${GLIB2_LIBRARIES})
	check_c_source_runs(
		"#include <glib.h>
		#include <locale.h>
		#include <stdio.h>
		#include <string.h>

		int
		main ()
		{
		  gchar *str;
		  setlocale(LC_ALL, \"en_US.UTF-8\");
		  str = g_strdup_printf(\"%'u\", 123456);
		  return (strcmp (str, \"123,456\") != 0);
		}" HAVE_GLIB_PRINTF_GROUPING)
	cmake_pop_check_state()
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
