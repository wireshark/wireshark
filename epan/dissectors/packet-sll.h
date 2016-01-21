/* packet-sll.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
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

#ifndef __PACKET_SLL_H__
#define __PACKET_SLL_H__

#include "ws_symbol_export.h"

/*
 * The LINUX_SLL_ values for "sll_protocol".
 * https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_ether.h ?
 */
#define LINUX_SLL_P_802_3	0x0001	/* Novell 802.3 frames without 802.2 LLC header */
#define LINUX_SLL_P_ETHERNET	0x0003	/* Ethernet */
#define LINUX_SLL_P_802_2	0x0004	/* 802.2 frames (not D/I/X Ethernet) */
#define LINUX_SLL_P_PPPHDLC	0x0007	/* PPP HDLC frames */
#define LINUX_SLL_P_CAN		0x000C	/* Controller Area Network */
#define LINUX_SLL_P_IRDA_LAP	0x0017	/* IrDA Link Access Protocol */
#define LINUX_SLL_P_ISI		0x00F5  /* Intelligent Service Interface */
#define LINUX_SLL_P_IEEE802154	0x00f6	/* 802.15.4 on monitor inteface */
#define LINUX_SLL_P_NETLINK	0x0338	/* Netlink */

#endif
