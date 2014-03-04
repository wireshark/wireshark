/* aftypes.c
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

#include "config.h"

#include <epan/value_string.h>
#include <epan/aftypes.h>

static const value_string linux_af_vals[] = {
	{ LINUX_AF_UNSPEC,	"AF_UNSPEC" },
	{ LINUX_AF_LOCAL,	"AF_LOCAL" }, /* AF_UNIX? */
	{ LINUX_AF_INET,	"AF_INET" },
	{ LINUX_AF_AX25,	"AF_AX25" },
	{ LINUX_AF_IPX,		"AF_IPX" },
	{ LINUX_AF_APPLETALK,	"AF_APPLETALK" },
	{ LINUX_AF_NETROM,	"AF_NETROM" },
	{ LINUX_AF_BRIDGE,	"AF_BRIDGE" },
	{ LINUX_AF_ATMPVC,	"AF_ATMPVC" },
	{ LINUX_AF_X25,		"AF_X25" },
	{ LINUX_AF_INET6,	"AF_INET6" },
	{ LINUX_AF_ROSE,	"AF_ROSE" },
	{ LINUX_AF_DECnet,	"AF_DECnet" },
	{ LINUX_AF_NETBEUI,	"AF_NETBEUI" },
	{ LINUX_AF_SECURITY,	"AF_SECURITY" },
	{ LINUX_AF_KEY,		"AF_KEY" },
	{ LINUX_AF_NETLINK,	"AF_NETLINK" },
	{ LINUX_AF_PACKET,	"AF_PACKET" },
	{ LINUX_AF_ASH,		"AF_ASH" },
	{ LINUX_AF_ECONET,	"AF_ECONET" },
	{ LINUX_AF_ATMSVC,	"AF_ATMSVC" },
	{ LINUX_AF_RDS,		"AF_RDS" },
	{ LINUX_AF_SNA,		"AF_SNA" },
	{ LINUX_AF_IRDA,	"AF_IRDA" },
	{ LINUX_AF_PPPOX,	"AF_PPPOX" },
	{ LINUX_AF_WANPIPE,	"AF_WANPIPE" },
	{ LINUX_AF_LLC,		"AF_LLC" },
	{ LINUX_AF_CAN,		"AF_CAN" },
	{ LINUX_AF_TIPC,	"AF_TIPC" },
	{ LINUX_AF_BLUETOOTH,	"AF_BLUETOOTH" },
	{ LINUX_AF_IUCV,	"AF_IUCV" },
	{ LINUX_AF_RXRPC,	"AF_RXRPC" },
	{ LINUX_AF_ISDN,	"AF_ISDN" },
	{ LINUX_AF_PHONET,	"AF_PHONET" },
	{ LINUX_AF_IEEE802154,	"AF_IEEE802154" },
	{ LINUX_AF_CAIF,	"AF_CAIF" },
	{ LINUX_AF_ALG,		"AF_ALG" },
	{ LINUX_AF_NFC,		"AF_NFC" },
	{ 0, NULL }
};

value_string_ext linux_af_vals_ext = VALUE_STRING_EXT_INIT(linux_af_vals);
