# ConfigureChecks.cmake
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

# todo: result for NEED_... is wrong (inverted)

#check system for includes
include(CheckIncludeFile)
check_include_file("arpa/inet.h"         HAVE_ARPA_INET_H)
check_include_file("arpa/nameser.h"      HAVE_ARPA_NAMESER_H)
check_include_file("direct.h"            HAVE_DIRECT_H)
check_include_file("dirent.h"            HAVE_DIRENT_H)
check_include_file("dlfcn.h"             HAVE_DLFCN_H)
check_include_file("fcntl.h"             HAVE_FCNTL_H)
check_include_file("grp.h"               HAVE_GRP_H)
check_include_file("g_ascii_strtoull.h"  NEED_G_ASCII_STRTOULL_H)
check_include_file("inet/aton.h"         NEED_INET_ATON_H)
check_include_file("inttypes.h"          HAVE_INTTYPES_H)
check_include_file("lauxlib.h"           HAVE_LAUXLIB_H)
check_include_file("memory.h"            HAVE_MEMORY_H)
check_include_file("netinet/in.h"        HAVE_NETINET_IN_H)
check_include_file("netdb.h"             HAVE_NETDB_H)
# XXX: We need to set the path to Wpdpack in order to find Ntddndis.h
check_include_file("Ntddndis.h"          HAVE_NTDDNDIS_H)
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
check_function_exists("gethostbyname2"   HAVE_GETHOSTBYNAME2)
check_function_exists("getopt"           HAVE_GETOPT)
check_function_exists("getprotobynumber" HAVE_GETPROTOBYNUMBER)
check_function_exists("inet_ntop"        HAVE_INET_NTOP_PROTO)
check_function_exists("issetugid"        HAVE_ISSETUGID)
check_function_exists("mmap"             HAVE_MMAP)
check_function_exists("mprotect"         HAVE_MPROTECT)
check_function_exists("mkdtemp"          HAVE_MKDTEMP)
check_function_exists("mkstemp"          HAVE_MKSTEMP)
check_function_exists("sysconf"          HAVE_SYSCONF)
