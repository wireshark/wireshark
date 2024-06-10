/* packet-sll.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_SLL_H__
#define __PACKET_SLL_H__

#include "ws_symbol_export.h"

/*
 * The LINUX_SLL_ values for "sll_protocol".
 * https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_ether.h
 */
#define LINUX_SLL_P_802_3	0x0001	/* Novell 802.3 frames without 802.2 LLC header */
#define LINUX_SLL_P_ETHERNET	0x0003	/* Ethernet */
#define LINUX_SLL_P_802_2	0x0004	/* 802.2 frames (not D/I/X Ethernet) */
#define LINUX_SLL_P_PPPHDLC	0x0007	/* PPP HDLC frames */
#define LINUX_SLL_P_CAN		0x000C	/* Controller Area Network */
#define LINUX_SLL_P_CANFD	0x000D	/* Controller Area Network flexible data rate */
#define LINUX_SLL_P_CANXL	0x000E	/* Controller Area Network extended length */
#define LINUX_SLL_P_IRDA_LAP	0x0017	/* IrDA Link Access Protocol */
#define LINUX_SLL_P_ISI		0x00F5  /* Intelligent Service Interface */
#define LINUX_SLL_P_IEEE802154	0x00f6	/* 802.15.4 on monitor interface */
#define LINUX_SLL_P_MCTP	0x00fa	/* Management Component Transport Protocol */

#endif
