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

/* L2TPv3 Pseudowire Types
 * https://www.iana.org/assignments/l2tp-parameters/l2tp-parameters.xhtml
 */
/* 0 is unassigned, use for Decode As of sessions where we do not have a
 * PW Type AVP. (Perhaps if no control packets are captured.)  */
#define L2TPv3_PW_DEFAULT     0x0000
#define L2TPv3_PW_FR          0x0001
#define L2TPv3_PW_AAL5        0x0002
#define L2TPv3_PW_ATM_PORT    0x0003
#define L2TPv3_PW_ETH_VLAN    0x0004
#define L2TPv3_PW_ETH         0x0005
#define L2TPv3_PW_CHDLC       0x0006
#define L2TPv3_PW_PPP         0x0007 /* Expired draft, unassigned */
#define L2TPv3_PW_ATM_VCC     0x0009
#define L2TPv3_PW_ATM_VPC     0x000A
#define L2TPv3_PW_IP          0x000B /* Expired draft, unassigned */
#define L2TPv3_PW_DOCSIS_DMPT 0x000C /* MPEG2-TS */
#define L2TPv3_PW_DOCSIS_PSP  0x000D
#define L2TPv3_PW_E1          0x0011
#define L2TPv3_PW_T1          0x0012
#define L2TPv3_PW_E3          0x0013
#define L2TPv3_PW_T3          0x0014
#define L2TPv3_PW_CESOPSN     0x0015
#define L2TPv3_PW_CESOPSN_CAS 0x0017

#if 0
/* Other dissectors that do not have Pseudowire Types assigned.
 * Were any of the unassigned numbers used for these in the past,
 * as with PPP and IP?
 */
#define L2TPv3_PW_MPLS
#define L2TPv3_PW_LAPD
#define L2TPv3_PW_ERICSSON
#endif

#endif /* __PACKET_L2TP_H__ */
