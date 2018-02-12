/* packet-l2tp.h
 * Routines for Layer Two Tunnelling Protocol (L2TP) packet disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __PACKET_L2TP_H__
#define __PACKET_L2TP_H__

typedef struct _l2tp_cntrl_data {
	guint32     ccid;
	int         msg_type;
} l2tp_cntrl_data_t;

#define L2TPv3_PROTOCOL_ETH         0
#define L2TPv3_PROTOCOL_CHDLC       1
#define L2TPv3_PROTOCOL_FR          2
#define L2TPv3_PROTOCOL_PPP         3
#define L2TPv3_PROTOCOL_IP          4
#define L2TPv3_PROTOCOL_MPLS        5
#define L2TPv3_PROTOCOL_AAL5        6
#define L2TPv3_PROTOCOL_LAPD        7
#define L2TPv3_PROTOCOL_DOCSIS_DMPT 8
#define L2TPv3_PROTOCOL_ERICSSON    9
#define L2TPv3_PROTOCOL_MAX         (L2TPv3_PROTOCOL_ERICSSON + 1)

#endif /* __PACKET_L2TP_H__ */
