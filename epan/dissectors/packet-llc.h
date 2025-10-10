/* packet-llc.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_LLC_H__
#define __PACKET_LLC_H__

#include "ws_symbol_export.h"

/*
 * Definitions of protocol IDs for the 00-80-C2 OUI, used for
 * bridging various networks over ATM (RFC 2684) or Frame Relay (RFC 2427).
 */
#define BPID_ETH_WITH_FCS	0x0001	/* 802.3/Ethernet with preserved FCS */
#define BPID_ETH_WITHOUT_FCS	0x0007	/* 802.3/Ethernet without preserved FCS */

#define BPID_802_4_WITH_FCS	0x0002	/* 802.4 with preserved FCS */
#define BPID_802_4_WITHOUT_FCS	0x0008	/* 802.4 without preserved FCS */

#define BPID_802_5_WITH_FCS	0x0003	/* 802.5 with preserved FCS */
#define BPID_802_5_WITHOUT_FCS	0x0009	/* 802.5 without preserved FCS */

#define BPID_FDDI_WITH_FCS	0x0004	/* FDDI with preserved FCS */
#define BPID_FDDI_WITHOUT_FCS	0x000A	/* FDDI without preserved FCS */

#define BPID_802_6_WITH_FCS	0x0005	/* 802.6 with preserved FCS */
#define BPID_802_6_WITHOUT_FCS	0x000B	/* 802.6 without preserved FCS */

#define BPID_FRAGMENTS		0x000D

#define BPID_BPDU		0x000E	/* 802.1(d) or 802.1(g) BPDUs */

#define BPID_SR_BPDU		0x000F	/* Source Routing BPDUs */


/* LLC SAP values. */

#define	SAP_NULL		0x00
#define	SAP_LLC_SLMGMT		0x02
#define	SAP_SNA_PATHCTRL	0x04
#define	SAP_IP			0x06
#define	SAP_SNA1		0x08
#define	SAP_SNA2		0x0C
#define	SAP_PROWAY_NM_INIT	0x0E
#define SAP_NETWARE1		0x10
#define SAP_OSINL1		0x14
#define	SAP_TI			0x18
#define SAP_OSINL2		0x20
#define SAP_OSINL3		0x34
#define	SAP_SNA3		0x40
#define	SAP_BPDU		0x42
#define	SAP_RS511		0x4E
#define SAP_OSINL4		0x54
#define	SAP_X25                 0x7E
#define	SAP_XNS			0x80
#define	SAP_BACNET		0x82
#define	SAP_NESTAR		0x86
#define	SAP_PROWAY_ASLM		0x8E
#define	SAP_ARP			0x98
#define	SAP_SNAP		0xAA
#define	SAP_HPJD		0xB4
#define	SAP_VINES1		0xBA
#define	SAP_VINES2		0xBC
#define	SAP_SNA4		0xC8
#define	SAP_NETWARE2		0xE0
#define	SAP_NETBIOS		0xF0
#define	SAP_IBMNM		0xF4
#define	SAP_HPEXT		0xF8
#define	SAP_UB			0xFA
#define	SAP_RPL			0xFC
#define	SAP_OSINL5		0xFE
#define	SAP_GLOBAL		0xFF


extern const value_string sap_vals[];

void dissect_snap(tvbuff_t *, int, packet_info *, proto_tree *,
    proto_tree *, int, int, int, int, int);

/*
 * Add an entry for a new OUI.
 */
WS_DLL_PUBLIC
void llc_add_oui(uint32_t, const char *, const char *, hf_register_info *, const int);

/*
 * SNAP information about the PID for a particular OUI:
 *
 *	the dissector table to use with the PID's value;
 *	the field to use for the PID.
 */
typedef struct {
	dissector_table_t table;
	hf_register_info *field_info;
} oui_info_t;

/*
 * Return the oui_info_t for the PID for a particular OUI value, or NULL
 * if there isn't one.
 */
oui_info_t *get_snap_oui_info(uint32_t);

#endif
