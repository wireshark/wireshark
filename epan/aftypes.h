/* aftypes.h
 * AF_ values on various OSes; they're used in some network protocols, as
 * well as in BSD DLT_NULL and DLT_LOOP headers.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 *
 * This file created and by Mike Hall <mlh@io.com>
 * Copyright 1998
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __AFTYPES_H__
#define __AFTYPES_H__

#include <epan/value_string.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define COMMON_AF_UNSPEC	0
/* Pretty much everybody uses the same value for AF_INET. */
#define COMMON_AF_INET		2

/* BSD AF_ values. */
#define BSD_AF_INET		2
#define BSD_AF_ISO		7
#define BSD_AF_APPLETALK	16
#define BSD_AF_IPX		23
#define BSD_AF_INET6_BSD	24	/* OpenBSD (and probably NetBSD), BSD/OS */
#define BSD_AF_INET6_FREEBSD	28
#define BSD_AF_INET6_DARWIN	30

/* Linux AF_ values. */
#define LINUX_AF_UNSPEC		 0
#define LINUX_AF_LOCAL		 1
#define LINUX_AF_INET		 2
#define LINUX_AF_AX25		 3
#define LINUX_AF_IPX		 4
#define LINUX_AF_APPLETALK	 5
#define LINUX_AF_NETROM		 6
#define LINUX_AF_BRIDGE		 7
#define LINUX_AF_ATMPVC		 8
#define LINUX_AF_X25		 9
#define LINUX_AF_INET6		10
#define LINUX_AF_ROSE		11
#define LINUX_AF_DECnet		12
#define LINUX_AF_NETBEUI	13
#define LINUX_AF_SECURITY	14
#define LINUX_AF_KEY		15
#define LINUX_AF_NETLINK	16
#define LINUX_AF_PACKET		17
#define LINUX_AF_ASH		18
#define LINUX_AF_ECONET		19
#define LINUX_AF_ATMSVC		20
#define LINUX_AF_RDS		21
#define LINUX_AF_SNA		22
#define LINUX_AF_IRDA		23
#define LINUX_AF_PPPOX		24
#define LINUX_AF_WANPIPE	25
#define LINUX_AF_LLC		26
#define LINUX_AF_CAN		29
#define LINUX_AF_TIPC		30
#define LINUX_AF_BLUETOOTH	31
#define LINUX_AF_IUCV		32
#define LINUX_AF_RXRPC		33
#define LINUX_AF_ISDN		34
#define LINUX_AF_PHONET		35
#define LINUX_AF_IEEE802154	36
#define LINUX_AF_CAIF		37
#define LINUX_AF_ALG		38
#define LINUX_AF_NFC		39

extern value_string_ext linux_af_vals_ext;

/* Solaris AF_ values. */
#define SOLARIS_AF_INET		2
#define SOLARIS_AF_INET6	26

/* Winsock AF_ values. */

#define WINSOCK_AF_UNSPEC	0
#define WINSOCK_AF_UNIX		1
#define WINSOCK_AF_INET		2
#define WINSOCK_AF_IMPLINK	3
#define WINSOCK_AF_PUP		4
#define WINSOCK_AF_CHAOS	5
#define WINSOCK_AF_IPX		6
#define WINSOCK_AF_NS		6
#define WINSOCK_AF_ISO		7
#define WINSOCK_AF_OSI		WINSOCK_AF_ISO
#define WINSOCK_AF_ECMA		8
#define WINSOCK_AF_DATAKIT	9
#define WINSOCK_AF_CCITT	10
#define WINSOCK_AF_SNA		11
#define WINSOCK_AF_DECnet	12
#define WINSOCK_AF_DLI		13
#define WINSOCK_AF_LAT		14
#define WINSOCK_AF_HYLINK	15
#define WINSOCK_AF_APPLETALK	16
#define WINSOCK_AF_NETBIOS	17
#define WINSOCK_AF_VOICEVIEW	18
#define WINSOCK_AF_FIREFOX	19
#define WINSOCK_AF_UNKNOWN1	20
#define WINSOCK_AF_BAN		21
#define WINSOCK_AF_ATM		22
#define WINSOCK_AF_INET6	23
#define WINSOCK_AF_BTH		32

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* aftypes.h */
