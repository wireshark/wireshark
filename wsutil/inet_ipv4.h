/* inet_ipv4.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#ifndef __INET_IPV4_H__
#define __INET_IPV4_H__

#include <glib.h>

typedef guint32 ws_in4_addr;	/* 32 bit IPv4 address, in network byte order */

/*
 * We define these in *network byte order*, unlike the C library. Therefore
 * it uses a different prefix than INADDR_* to make the distinction more obvious.
 */
#define WS_IN4_LOOPBACK ((ws_in4_addr)GUINT32_TO_BE(0x7f000001))

/**
 * Unicast Local
 * Returns true if the address is in the 224.0.0.0/24 local network
 * control block
 */
#define in4_addr_is_local_network_control_block(addr) \
  ((addr & 0xffffff00) == 0xe0000000)

/**
 * Multicast
 * Returns true if the address is in the 224.0.0.0/4 network block
 */
#define in4_addr_is_multicast(addr) \
  ((addr & 0xf0000000) == 0xe0000000)

#endif
