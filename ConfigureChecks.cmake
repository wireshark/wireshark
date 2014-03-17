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
check_include_file("direct.h"            HAVE_DIRECT_H)
check_include_file("dirent.h"            HAVE_DIRENT_H)
check_include_file("dlfcn.h"             HAVE_DLFCN_H)
check_include_file("fcntl.h"             HAVE_FCNTL_H)
check_include_file("getopt.h"            HAVE_GETOPT_H)
check_include_file("grp.h"               HAVE_GRP_H)
check_include_file("inet/aton.h"         HAVE_INET_ATON_H)
check_include_file("inttypes.h"          HAVE_INTTYPES_H)
check_include_file("memory.h"            HAVE_MEMORY_H)
check_include_file("netinet/in.h"        HAVE_NETINET_IN_H)
check_include_file("netdb.h"             HAVE_NETDB_H)
# We need to set the path to Wpdpack in order to find Ntddndis.h
#cmake_push_check_state()
#set(CMAKE_REQUIRED_INCLUDES %{PCAP_INCLUDE_DIRS})
#check_include_file("Ntddndis.h"          HAVE_NTDDNDIS_H)
#cmake_pop_check_state()
check_include_file("portaudio.h"         HAVE_PORTAUDIO_H)
check_include_file("pwd.h"               HAVE_PWD_H)
check_include_file("stdarg.h"            HAVE_STDARG_H)
check_include_file("stddef.h"            HAVE_STDDEF_H)
check_include_file("stdint.h"            HAVE_STDINT_H)
check_include_file("stdlib.h"            HAVE_STDLIB_H)
check_include_file("strings.h"           HAVE_STRINGS_H)
check_include_file("string.h"            HAVE_STRING_H)
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

#Functions
include(CheckFunctionExists)
check_function_exists("chown"            HAVE_CHOWN)

cmake_push_check_state()
#
# XXX - this is *not* finding dladdr() on OS X (at least not on
# Mountain Lion), even though it's available; autoconf does find
# it.  The dl* functions can be tricky, in that they might be
# exported by the run-time linker rather than by any library,
# so the only way to check for it that might work is "can I link
# a program that calls this function?", not, for example, "do
# any of these libraries define this function?"
#
set(CMAKE_REQUIRED_LIBRARIES %{CMAKE_DL_LIBS})
check_function_exists("dladdr"           HAVE_DLADDR)
cmake_pop_check_state()

check_function_exists("gethostbyname2"   HAVE_GETHOSTBYNAME2)
check_function_exists("getopt"           HAVE_GETOPT)
check_function_exists("getprotobynumber" HAVE_GETPROTOBYNUMBER)
check_function_exists("inet_ntop"        HAVE_INET_NTOP_PROTO)
check_function_exists("issetugid"        HAVE_ISSETUGID)
check_function_exists("mmap"             HAVE_MMAP)
check_function_exists("mprotect"         HAVE_MPROTECT)
check_function_exists("mkdtemp"          HAVE_MKDTEMP)
check_function_exists("mkstemp"          HAVE_MKSTEMP)
check_function_exists("setresgid"        HAVE_SETRESGID)
check_function_exists("setresuid"        HAVE_SETRESUID)
check_function_exists("sysconf"          HAVE_SYSCONF)

#Struct members
include(CheckStructHasMember)
check_struct_has_member("struct sockaddr" sa_len   sys/socket.h HAVE_SA_LEN)
check_struct_has_member("struct stat"     st_flags sys/stat.h   HAVE_ST_FLAGS)
check_struct_has_member("struct tm"       tm_zone  time.h       HAVE_TM_ZONE)

#Symbols but NOT enums or types
include(CheckSymbolExists)
check_symbol_exists(tzname "time.h" HAVE_TZNAME)

# Check for stuff that isn't testable via the tests above
#include(CheckCSourceCompiles)
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
		int x = NL80211_FREQUENCY_ATTR_MAX_TX_POWER;
		x = NL80211_ATTR_SUPPORTED_IFTYPES;
		x = NL80211_ATTR_SUPPORTED_COMMANDS;
		x = NL80211_ATTR_WIPHY_FREQ;
		x = NL80211_CHAN_NO_HT;
	}"
	HAVE_NL80211
)

