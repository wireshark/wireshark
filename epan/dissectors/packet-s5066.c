/* packet-s5066.c
 * Routines for STANAG 5066 SIS layer packet disassembly
 *
 * $Id$
 *
 * Copyright (c) 2005 by Menno Andriesse <s5066 [AT] nc3a.nato.int>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/dissectors/packet-tcp.h> /* For tcp_dissect_pdus() */

/* Forward reference */
/* Register functions */
void proto_reg_handoff_s5066(void);
/* Main dissectors */
static void dissect_s5066_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static guint get_s5066_pdu_len(packet_info *pinfo, tvbuff_t *tvb, int offset);
static void dissect_s5066_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
/* Service type and address dissectors */
static guint dissect_s5066_servicetype(tvbuff_t *tvb, guint offset, proto_tree *tree);
static guint dissect_s5066_address(tvbuff_t *tvb, guint offset, proto_tree *tree, gint source);
/* S-Primitive dissectors */
static guint dissect_s5066_01(tvbuff_t *tvb, guint offset, proto_tree *tree);
/* static guint dissect_s5066_02(tvbuff_t *tvb, guint offset, proto_tree *tree); */
static guint dissect_s5066_03(tvbuff_t *tvb, guint offset, proto_tree *tree);
static guint dissect_s5066_04(tvbuff_t *tvb, guint offset, proto_tree *tree);
static guint dissect_s5066_05(tvbuff_t *tvb, guint offset, proto_tree *tree);
static guint dissect_s5066_06(tvbuff_t *tvb, guint offset, proto_tree *tree);
static guint dissect_s5066_07(tvbuff_t *tvb, guint offset, proto_tree *tree);
static guint dissect_s5066_08(tvbuff_t *tvb, guint offset, proto_tree *tree);
static guint dissect_s5066_09(tvbuff_t *tvb, guint offset, proto_tree *tree);
static guint dissect_s5066_10(tvbuff_t *tvb, guint offset, proto_tree *tree);
static guint dissect_s5066_11(tvbuff_t *tvb, guint offset, proto_tree *tree);
static guint dissect_s5066_12(tvbuff_t *tvb, guint offset, proto_tree *tree);
static guint dissect_s5066_13(tvbuff_t *tvb, guint offset, proto_tree *tree);
static guint dissect_s5066_14(tvbuff_t *tvb, guint offset, proto_tree *tree);
/* static guint dissect_s5066_15(tvbuff_t *tvb, guint offset, proto_tree *tree); */
/* static guint dissect_s5066_16(tvbuff_t *tvb, guint offset, proto_tree *tree); */
/* static guint dissect_s5066_17(tvbuff_t *tvb, guint offset, proto_tree *tree); */
static guint dissect_s5066_18(tvbuff_t *tvb, guint offset, proto_tree *tree, guint pdu_size);
static guint dissect_s5066_19(tvbuff_t *tvb, guint offset, proto_tree *tree, guint pdu_size);
static guint dissect_s5066_20(tvbuff_t *tvb, guint offset, proto_tree *tree);
static guint dissect_s5066_21(tvbuff_t *tvb, guint offset, proto_tree *tree, guint pdu_size);
static guint dissect_s5066_22(tvbuff_t *tvb, guint offset, proto_tree *tree);
static guint dissect_s5066_23(tvbuff_t *tvb, guint offset, proto_tree *tree);
static guint dissect_s5066_24(tvbuff_t *tvb, guint offset, proto_tree *tree);
static guint dissect_s5066_25(tvbuff_t *tvb, guint offset, proto_tree *tree, guint pdu_size);
static guint dissect_s5066_26(tvbuff_t *tvb, guint offset, proto_tree *tree);
static guint dissect_s5066_27(tvbuff_t *tvb, guint offset, proto_tree *tree);

static gint proto_s5066 = -1;
static dissector_handle_t data_handle;

/* Enable desegmentation of S5066 over TCP */
static gboolean s5066_desegment = TRUE;
/* Dissect old 'edition 1' of STANAG 5066 (It lacks the 'version' field.) */
static gboolean s5066_edition_one = FALSE;
/* This port is registered with IANA */
static guint global_s5066_port = 5066;
/* Size of header outside 'size' field */
static gint s5066_header_size = 5;
/* Offset of 'size' field */
static gint s5066_size_offset = 3;

/* Sync should be 0x90EB */
static gint hf_s5066_sync_word = -1;
/* Version should be 0x00 */
static gint hf_s5066_version = -1;
/* Total size of the PDU, excluding this size and previous fields */
/* So total size is this + 5 bytes (s5066_header_size) */
static gint hf_s5066_size = -1;
/* Th type of PDU */
static gint hf_s5066_type = -1;
static const value_string s5066_pdu_type[] = {
	{ 1, "S_BIND_REQUEST"},
	{ 2, "S_UNBIND_REQUEST"},
	{ 3, "S_BIND_ACCEPTED"},
	{ 4, "S_BIND_REJECTED"},
	{ 5, "S_UNBIND_INDICATION"},
	{ 6, "S_HARD_LINK_ESTABLISH"},
	{ 7, "S_HARD_LINK_TERMINATE"},
	{ 8, "S_HARD_LINK_ESTABLISHED"},
	{ 9, "S_HARD_LINK_REJECTED"},
	{10, "S_HARD_LINK_TERMINATED"},
	{11, "S_HARD_LINK_INDICATION"},
	{12, "S_HARD_LINK_ACCEPT"},
	{13, "S_HARD_LINK_REJECT"},
	{14, "S_SUBNET_AVAILABILITY"},
	{15, "S_DATAFLOW_ON"},
	{16, "S_DATAFLOW_OFF"},
	{17, "S_KEEP_ALIVE"},
	{18, "S_MANAGEMENT_MESSAGE_REQUEST"},
	{19, "S_MANAGEMENT_MESSAGE_INDICATION"},
	{20, "S_UNIDATA_REQUEST"},
	{21, "S_UNIDATA_INDICATION"},
	{22, "S_UNIDATA_REQUEST_CONFIRM"},
	{23, "S_UNIDATA_REQUEST_REJECTED"},
	{24, "S_EXPEDITED_UNIDATA_REQUEST"},
	{25, "S_EXPEDITED_UNIDATA_INDICATION"},
	{26, "S_EXPEDITED_UNIDATA_REQUEST_CONFIRM"},
	{27, "S_EXPEDITED_UNIDATA_REQUEST_REJECTED"},
	{ 0, NULL },
};

/* STANAG 5066 Address */
/* Size is defined in nibbles (4 bits) */
static gint hf_s5066_ad_size = -1;
/* Group flag: 0 = false, 1 = true */
static gint hf_s5066_ad_group = -1;
/* The remainder of the 4 bytes form the address */
static gint hf_s5066_ad_address = -1;

/* Service type */
/* Transmission mode: */
static gint hf_s5066_st_txmode = -1;
static const value_string s5066_st_txmode[] = {
	{ 0, "Ignore service type field"},
	{ 1, "ARQ"},
	{ 2, "Non-ARQ (Broadcast)"},
	{ 3, "Non-ARQ (with errors)"},
	{ 4, "Other non-ARQ types"},
	{ 5, "Other non-ARQ types"},
	{ 6, "Other non-ARQ types"},
	{ 7, "Other non-ARQ types"},
	{ 8, "Other non-ARQ types"},
	{ 9, "Other non-ARQ types"},
	{10, "Other non-ARQ types"},
	{11, "Other non-ARQ types"},
	{12, "Other non-ARQ types"},
	{13, "Other non-ARQ types"},
	{14, "Other non-ARQ types"},
	{15, "Other non-ARQ types"},
	{ 0, NULL },
};
/* Delivery confirmation: */
static gint hf_s5066_st_delivery_confirmation = -1;
static const value_string s5066_st_delivery_confirmation[] = {
	{ 0, "No confirmation"},
	{ 1, "Node delivery confirmation"},
	{ 2, "Client delivery confirmation"},
	{ 3, "-- Not defined --"},
	{ 0, NULL },
};
/* Delivery order: */
static gint hf_s5066_st_delivery_order = -1;
static const value_string s5066_st_delivery_order[] = {
	{ 0, "In-order delivery"},
	{ 1, "As-they-arrive"},
	{ 0, NULL },
};
/* Extended field present: (Never in the current version.) */
static gint hf_s5066_st_extended = -1;
static const value_string s5066_st_extended[] = {
	{ 0, "No extended field"},
	{ 1, "Extended field follows"},
	{ 0, NULL },
};
/* Number of retransmissions when in Non-ARQ: */
static gint hf_s5066_st_retries = -1;

/* Type  1: S_BIND_REQUEST */
static gint hf_s5066_01_sapid = -1;
static gint hf_s5066_01_rank = -1;
static gint hf_s5066_01_unused = -1;

/* Type  2: S_UNBIND_REQUEST */
/*   --- no subfields ---   */

/* Type  3: S_BIND_ACCEPTED */
static gint hf_s5066_03_sapid = -1;
static gint hf_s5066_03_unused = -1;
static gint hf_s5066_03_mtu = -1;

/* Type  4: S_BIND_REJECTED */
static gint hf_s5066_04_reason = -1;
static const value_string s5066_04_reason[] = {
	{ 0, "Unknown reason"},
	{ 1, "Not enough resources"},
	{ 2, "Invalid Sap ID"},
	{ 3, "Sap ID already allocated"},
	{ 4, "ARQ mode unsupportable during broadcast session"},
	{ 0, NULL },
};

/* Type  5: S_UNBIND_INDICATION */
static gint hf_s5066_05_reason = -1;
static const value_string s5066_05_reason[] = {
	{ 0, "Unknown reason"},
	{ 1, "Connection pre-empted by higher ranking client"},
	{ 2, "Inactivity (failure to respond to 'Keep-alive')"},
	{ 3, "Too many invalid primitives"},
	{ 4, "Too many expedited data request primitives"},
	{ 5, "ARQ mode unsupportable during broadcast session"},
	{ 0, NULL },
};

/* Hard links: hardlinktype value string array. */
static const value_string s5066_hard_link_type[] = {
	{ 0, "Link reservation"},
	{ 1, "Partial Bandwidth reservation"},
	{ 2, "Full Bandwidth reservation"},
	{ 3, "--- undefined ---"},
	{ 0, NULL },
};

/* Type  6: S_HARD_LINK_ESTABLISH */
static gint hf_s5066_06_link_type = -1;
static gint hf_s5066_06_link_priority = -1;
static gint hf_s5066_06_sapid = -1;

/* Type  7: S_HARD_LINK_TERMINATE */
/* Only  remote node address */

/* Type  8: S_HARD_LINK_ESTABLISHED */
static gint hf_s5066_08_remote_status = -1;
static const value_string s5066_08_remote_status[] = {
	{ 0, "ERROR"},
	{ 1, "OK"},
	{ 0, NULL },
};
static gint hf_s5066_08_link_type = -1;
static gint hf_s5066_08_link_priority = -1;
static gint hf_s5066_08_sapid = -1;

/* Type  9: S_HARD_LINK_REJECTED */
static gint hf_s5066_09_reason = -1;
static const value_string s5066_09_reason[] = {
	{ 0, "--- undefined ---"},
	{ 1, "Remote node busy"},
	{ 2, "Higher priority link exists"},
	{ 3, "Remote node not responding"},
	{ 4, "Destination Sap ID not bound"},
	{ 5, "Requested Type-0 link exists"},
	{ 0, NULL },
};
static gint hf_s5066_09_link_type = -1;
static gint hf_s5066_09_link_priority = -1;
static gint hf_s5066_09_sapid = -1;

/* Type 10: S_HARD_LINK_TERMINATED */
static gint hf_s5066_10_reason = -1;
static const value_string s5066_10_reason[] = {
	{ 0, "--- undefined ---"},
	{ 1, "Link terminated by remote node"},
	{ 2, "Higher priority link requested"},
	{ 3, "Remote node not responding"},
	{ 4, "Destination Sap ID not bound"},
	{ 5, "Physical link broken"},
	{ 0, NULL },
};
static gint hf_s5066_10_link_type = -1;
static gint hf_s5066_10_link_priority = -1;
static gint hf_s5066_10_sapid = -1;

/* Type 11: S_HARD_LINK_INDICATION */
static gint hf_s5066_11_remote_status = -1;
static const value_string s5066_11_remote_status[] = {
	{ 0, "ERROR"},
	{ 1, "OK"},
	{ 0, NULL },
};
static gint hf_s5066_11_link_type = -1;
static gint hf_s5066_11_link_priority = -1;
static gint hf_s5066_11_sapid = -1;

/* Type 12: S_HARD_LINK_ACCEPT */
static gint hf_s5066_12_link_type = -1;
static gint hf_s5066_12_link_priority = -1;
static gint hf_s5066_12_sapid = -1;

/* Type 13: S_HARD_LINK_REJECT */
static gint hf_s5066_13_reason = -1;
static const value_string s5066_13_reason[] = {
	{ 0, "--- undefined ---"},
	{ 0, NULL },
};
static gint hf_s5066_13_link_type = -1;
static gint hf_s5066_13_link_priority = -1;
static gint hf_s5066_13_sapid = -1;

/* Type 14: S_SUBNET_AVAILABILITY */
static gint hf_s5066_14_status= -1;
static const value_string s5066_14_status[] = {
	{ 0, "Off"},
	{ 1, "On"},
	{ 2, "Receive only"},
	{ 3, "Half-duplex"},
	{ 4, "Full-duplex"},
	{ 0, NULL },
};
static gint hf_s5066_14_reason= -1;
static const value_string s5066_14_reason[] = {
	{ 0, "Unknown reason"},
	{ 1, "Local node in EMCON"},
	{ 2, "Higher priority link requested"},
	{ 0, NULL },
};

/* Type 15: S_DATAFLOW_ON */
/*   --- no subfields ---   */

/* Type 16: S_DATAFLOW_OFF */
/*   --- no subfields ---   */

/* Type 17: S_KEEP_ALIVE */
/*   --- no subfields ---   */

/* Type 18: S_MANAGEMENT_MESSAGE_REQUEST */
static gint hf_s5066_18_type = -1;
static gint hf_s5066_18_body = -1;

/* Type 19: S_MANAGEMENT_MESSAGE_INDICATION */
static gint hf_s5066_19_type = -1;
static gint hf_s5066_19_body = -1;

/* Type 20: S_UNIDATA_REQUEST */
static gint hf_s5066_20_priority = -1;
static gint hf_s5066_20_sapid = -1;
static gint hf_s5066_20_ttl = -1;
static gint hf_s5066_20_size = -1;

/* Type 21: S_UNIDATA_INDICATION */
static gint hf_s5066_21_priority = -1;
static gint hf_s5066_21_dest_sapid = -1;
static gint hf_s5066_21_tx_mode = -1;
static gint hf_s5066_21_src_sapid = -1;
static gint hf_s5066_21_size = -1;
static gint hf_s5066_21_err_blocks = -1;
static gint hf_s5066_21_err_ptr = -1;
static gint hf_s5066_21_err_size = -1;
static gint hf_s5066_21_nrx_blocks = -1;
static gint hf_s5066_21_nrx_ptr = -1;
static gint hf_s5066_21_nrx_size = -1;


/* Type 22: S_UNIDATA_REQUEST_CONFIRM */
static gint hf_s5066_22_unused = -1;
static gint hf_s5066_22_sapid = -1;
static gint hf_s5066_22_size = -1;
static gint hf_s5066_22_data = -1;

/* Type 23: S_UNIDATA_REQUEST_REJECTED */
static gint hf_s5066_23_reason = -1;
static const value_string s5066_23_reason[] = {
	{ 0, "Unknown reason"},
	{ 1, "Time-To-Live expired"},
	{ 2, "Destination SapID not bound"},
	{ 3, "Destination node not responding"},
	{ 4, "U_PDU larger than MTU"},
	{ 5, "Transmission Mode not specified"},
	{ 0, NULL },
};
static gint hf_s5066_23_sapid = -1;
static gint hf_s5066_23_size = -1;
static gint hf_s5066_23_data = -1;

/* Type 24: S_EXPEDITED_UNIDATA_REQUEST */
static gint hf_s5066_24_unused = -1;
static gint hf_s5066_24_sapid = -1;
static gint hf_s5066_24_ttl = -1;
static gint hf_s5066_24_size = -1;

/* Type 25: S_EXPEDITED_UNIDATA_INDICATION */
static gint hf_s5066_25_unused = -1;
static gint hf_s5066_25_dest_sapid = -1;
static gint hf_s5066_25_tx_mode = -1;
static gint hf_s5066_25_src_sapid = -1;
static gint hf_s5066_25_size = -1;
static gint hf_s5066_25_err_blocks = -1;
static gint hf_s5066_25_err_ptr = -1;
static gint hf_s5066_25_err_size = -1;
static gint hf_s5066_25_nrx_blocks = -1;
static gint hf_s5066_25_nrx_ptr = -1;
static gint hf_s5066_25_nrx_size = -1;

/* Type 26: S_EXPEDITED_UNIDATA_REQUEST_CONFIRM */
static gint hf_s5066_26_unused = -1;
static gint hf_s5066_26_sapid = -1;
static gint hf_s5066_26_size = -1;
static gint hf_s5066_26_data = -1;

/* Type 27: S_EXPEDITED_UNIDATA_REQUEST_REJECTED */
static gint hf_s5066_27_reason = -1;
static const value_string s5066_27_reason[] = {
	{ 0, "Unknown reason"},
	{ 1, "Time-To-Live expired"},
	{ 2, "Destination SapID not bound"},
	{ 3, "Destination node not responding"},
	{ 4, "U_PDU larger than MTU"},
	{ 5, "Transmission Mode not specified"},
	{ 0, NULL },
};
static gint hf_s5066_27_sapid = -1;
static gint hf_s5066_27_size = -1;
static gint hf_s5066_27_data = -1;


static gint ett_s5066 = -1;
static gint ett_s5066_pdu = -1;
static gint ett_s5066_servicetype = -1;
static gint ett_s5066_address = -1;

void
proto_register_s5066(void)
{
	static hf_register_info hf[] = {
		{ &hf_s5066_sync_word,
			{ "Sync preamble", "s5066.sync", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_s5066_version,
			{ "S5066 version", "s5066.version", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_s5066_size,
			{ "S_Primitive size", "s5066.size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_s5066_type,
			{ "PDU Type", "s5066.type", FT_UINT8, BASE_DEC, VALS(s5066_pdu_type), 0x0, NULL, HFILL }
		},
		/* STANAG 5066 Address */
		{ &hf_s5066_ad_size,
			{ "Address size (1/2 Bytes)", "s5066.address.size", FT_UINT8, BASE_HEX, NULL, 0xE0, NULL, HFILL }
		},
		{ &hf_s5066_ad_group,
			{ "Group address", "s5066.address.group", FT_UINT8, BASE_HEX, NULL, 0x10, NULL, HFILL }
		},
		{ &hf_s5066_ad_address,
			{ "Address", "s5066.address.address", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }
		},
		/* Service type */
		{ &hf_s5066_st_txmode,
			{ "Transmission mode", "s5066.st.txmode", FT_UINT8, BASE_HEX, VALS(s5066_st_txmode), 0xF0, NULL, HFILL }
		},
		{ &hf_s5066_st_delivery_confirmation,
			{ "Delivery confirmation", "s5066.st.confirm", FT_UINT8, BASE_HEX, VALS(s5066_st_delivery_confirmation),  0x0C, NULL, HFILL }
		},
		{ &hf_s5066_st_delivery_order,
			{ "Delivery order", "s5066.st.order", FT_UINT8, BASE_HEX, VALS(s5066_st_delivery_order), 0x02, NULL, HFILL }
		},
		{ &hf_s5066_st_extended,
			{ "Extended field", "s5066.st.extended", FT_UINT8, BASE_HEX, VALS(s5066_st_extended), 0x01, NULL, HFILL }
		},
		{ &hf_s5066_st_retries,
			{ "Minimum number of retransmissions", "s5066.st.retries", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }
		},
		/* PDU Type 01: S_BIND_REQUEST */
		{ &hf_s5066_01_sapid,
			{ "Sap ID", "s5066.01.sapid", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }
		},
		{ &hf_s5066_01_rank,
			{ "Rank", "s5066.01.rank", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }
		},
		{ &hf_s5066_01_unused,
			{ "(Unused)", "s5066.01.unused", FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL }
		},
		/* PDU Type 02: S_UNBIND_REQUEST */
		/*     --- no subfields ---     */
		/* PDU Type 03: S_BIND_ACCEPTED */
		{ &hf_s5066_03_sapid,
			{ "Sap ID", "s5066.03.sapid", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }
		},
		{ &hf_s5066_03_unused,
			{ "(Unused)", "s5066.03.unused", FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL }
		},
		{ &hf_s5066_03_mtu,
			{ "MTU", "s5066.03.mtu", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* PDU Type 04: S_BIND_REJECTED */
		{ &hf_s5066_04_reason,
			{ "Reason", "s5066.04.reason", FT_UINT8, BASE_DEC, VALS(s5066_04_reason), 0x0, NULL, HFILL }
		},
		/* PDU Type 05: S_UNBIND_INDICATION */
		{ &hf_s5066_05_reason,
			{ "Reason", "s5066.05.reason", FT_UINT8, BASE_DEC, VALS(s5066_05_reason), 0x0, NULL, HFILL }
		},
		/* Type  6: S_HARD_LINK_ESTABLISH */
		{ &hf_s5066_06_link_type,
			{ "Hardlink type", "s5066.06.type", FT_UINT8, BASE_DEC, VALS(s5066_hard_link_type), 0xC0, NULL, HFILL }
		},
		{ &hf_s5066_06_link_priority,
			{ "Priority", "s5066.06.priority", FT_UINT8, BASE_DEC, NULL, 0x30, NULL, HFILL }
		},
		{ &hf_s5066_06_sapid,
			{ "Remote Sap ID", "s5066.06.sapid", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }
		},
		/* Type  7: S_HARD_LINK_TERMINATE */
		/* --- Only remote node address --- */
		/* Type  8: S_HARD_LINK_ESTABLISHED */
		{ &hf_s5066_08_remote_status,
			{ "Remote node status", "s5066.08.status", FT_UINT8, BASE_DEC, VALS(s5066_08_remote_status), 0x0, NULL, HFILL }
		},
		{ &hf_s5066_08_link_type,
			{ "Hardlink type", "s5066.08.type", FT_UINT8, BASE_DEC, VALS(s5066_hard_link_type), 0xC0, NULL, HFILL }
		},
		{ &hf_s5066_08_link_priority,
			{ "Priority", "s5066.08.priority", FT_UINT8, BASE_DEC, NULL, 0x30, NULL, HFILL }
		},
		{ &hf_s5066_08_sapid,
			{ "Remote Sap ID", "s5066.08.sapid", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }
		},
		/* Type  9: S_HARD_LINK_REJECTED */
		{ &hf_s5066_09_reason,
			{ "Reason", "s5066.09.reason", FT_UINT8, BASE_DEC, VALS(s5066_09_reason), 0x0, NULL, HFILL }
		},
		{ &hf_s5066_09_link_type,
			{ "Hardlink type", "s5066.09.type", FT_UINT8, BASE_DEC, VALS(s5066_hard_link_type), 0xC0, NULL, HFILL }
		},
		{ &hf_s5066_09_link_priority,
			{ "Priority", "s5066.09.priority", FT_UINT8, BASE_DEC, NULL, 0x30, NULL, HFILL }
		},
		{ &hf_s5066_09_sapid,
			{ "Remote Sap ID", "s5066.09.sapid", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }
		},
		/* Type 10: S_HARD_LINK_TERMINATED */
		{ &hf_s5066_10_reason,
			{ "Reason", "s5066.10.reason", FT_UINT8, BASE_DEC, VALS(s5066_10_reason), 0x0, NULL, HFILL }
		},
		{ &hf_s5066_10_link_type,
			{ "Hardlink type", "s5066.10.type", FT_UINT8, BASE_DEC, VALS(s5066_hard_link_type), 0xC0, NULL, HFILL }
		},
		{ &hf_s5066_10_link_priority,
			{ "Priority", "s5066.10.priority", FT_UINT8, BASE_DEC, NULL, 0x30, NULL, HFILL }
		},
		{ &hf_s5066_10_sapid,
			{ "Remote Sap ID", "s5066.10.sapid", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }
		},
		/* Type 11: S_HARD_LINK_INDICATION */
		{ &hf_s5066_11_remote_status,
			{ "Remote node status", "s5066.11.status", FT_UINT8, BASE_DEC, VALS(s5066_11_remote_status), 0x0, NULL, HFILL }
		},
		{ &hf_s5066_11_link_type,
			{ "Hardlink type", "s5066.11.type", FT_UINT8, BASE_DEC, VALS(s5066_hard_link_type), 0xC0, NULL, HFILL }
		},
		{ &hf_s5066_11_link_priority,
			{ "Priority", "s5066.11.priority", FT_UINT8, BASE_DEC, NULL, 0x30, NULL, HFILL }
		},
		{ &hf_s5066_11_sapid,
			{ "Remote Sap ID", "s5066.11.sapid", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }
		},
		/* Type 12: S_HARD_LINK_ACCEPT */
		{ &hf_s5066_12_link_type,
			{ "Hardlink type", "s5066.12.type", FT_UINT8, BASE_DEC, VALS(s5066_hard_link_type), 0xC0, NULL, HFILL }
		},
		{ &hf_s5066_12_link_priority,
			{ "Priority", "s5066.12.priority", FT_UINT8, BASE_DEC, NULL, 0x30, NULL, HFILL }
		},
		{ &hf_s5066_12_sapid,
			{ "Remote Sap ID", "s5066.12.sapid", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }
		},
		/* Type 13: S_HARD_LINK_REJECT */
		{ &hf_s5066_13_reason,
			{ "Reason", "s5066.13.reason", FT_UINT8, BASE_DEC, VALS(s5066_13_reason), 0x0, NULL, HFILL }
		},
		{ &hf_s5066_13_link_type,
			{ "Hardlink type", "s5066.13.type", FT_UINT8, BASE_DEC, VALS(s5066_hard_link_type), 0xC0, NULL, HFILL }
		},
		{ &hf_s5066_13_link_priority,
			{ "Priority", "s5066.13.priority", FT_UINT8, BASE_DEC, NULL, 0x30, NULL, HFILL }
		},
		{ &hf_s5066_13_sapid,
			{ "Remote Sap ID", "s5066.13.sapid", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }
		},
		/* Type 14: S_SUBNET_AVAILABILITY */
		{ &hf_s5066_14_status,
			{ "Status", "s5066.14.status", FT_UINT8, BASE_DEC, VALS(s5066_14_status), 0x0, NULL, HFILL }
		},
		{ &hf_s5066_14_reason,
			{ "Reason", "s5066.14.reason", FT_UINT8, BASE_DEC, VALS(s5066_14_reason), 0x0, NULL, HFILL }
		},
		/* Type 15: S_DATAFLOW_ON */
		/*   --- no subfields ---   */
		/* Type 16: S_DATAFLOW_OFF */
		/*   --- no subfields ---   */
		/* Type 17: S_KEEP_ALIVE */
		/*   --- no subfields ---   */
		/* Type 18: S_MANAGEMENT_MESSAGE_REQUEST */
		{ &hf_s5066_18_type,
			{ "Message Type", "s5066.18.type", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_s5066_18_body,
			{ "Message Body", "s5066.18.body", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* Type 19: S_MANAGEMENT_MESSAGE_INDICATION */
		{ &hf_s5066_19_type,
			{ "Message Type", "s5066.19.type", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_s5066_19_body,
			{ "Message Body", "s5066.19.body", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* Type 20: S_UNIDATA_REQUEST */
		{ &hf_s5066_20_priority,
			{ "Priority", "s5066.20.priority", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }
		},
		{ &hf_s5066_20_sapid,
			{ "Destination Sap ID", "s5066.20.sapid", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }
		},
		{ &hf_s5066_20_ttl,
			{ "Time-To-Live (x2 seconds)", "s5066.20.ttl", FT_UINT24, BASE_DEC, NULL, 0x0FFFFF, NULL, HFILL }
		},
		{ &hf_s5066_20_size,
			{ "U_PDU Size", "s5066.20.size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* Type 21: S_UNIDATA_INDICATION */
		{ &hf_s5066_21_priority,
			{ "Priority", "s5066.21.priority", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }
		},
		{ &hf_s5066_21_dest_sapid,
			{ "Destination Sap ID", "s5066.21.dest_sapid", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }
		},
		{ &hf_s5066_21_tx_mode,
			{ "Transmission Mode", "s5066.21.txmode", FT_UINT8, BASE_HEX, VALS(s5066_st_txmode), 0xF0, NULL, HFILL }
		},
		{ &hf_s5066_21_src_sapid,
			{ "Source Sap ID", "s5066.21.src_sapid", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }
		},
		{ &hf_s5066_21_size,
			{ "U_PDU Size", "s5066.21.size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_s5066_21_err_blocks,
			{ "Number of errored blocks", "s5066.21.err_blocks", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_s5066_21_err_ptr,
			{ "Pointer to error block", "s5066.21.err_ptr", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_s5066_21_err_size,
			{ "Size of error block", "s5066.21.err_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_s5066_21_nrx_blocks,
			{ "Number of non-received blocks", "s5066.21.nrx_blocks", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_s5066_21_nrx_ptr,
			{ "Pointer to non-received block", "s5066.21.nrx_ptr", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_s5066_21_nrx_size,
			{ "Size of non-received block", "s5066.21.nrx_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* Type 22: S_UNIDATA_REQUEST_CONFIRM */
		{ &hf_s5066_22_unused,
			{ "(Unused)", "s5066.22.unused", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }
		},
		{ &hf_s5066_22_sapid,
			{ "Destination Sap ID", "s5066.22.sapid", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }
		},
		{ &hf_s5066_22_size,
			{ "U_PDU Size", "s5066.22.size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_s5066_22_data,
			{ "(Part of) Confirmed data", "s5066.22.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* Type 23: S_UNIDATA_REQUEST_REJECTED */
		{ &hf_s5066_23_reason,
			{ "Reason", "s5066.23.reason", FT_UINT8, BASE_DEC, VALS(s5066_23_reason), 0xF0, NULL, HFILL }
		},
		{ &hf_s5066_23_sapid,
			{ "Destination Sap ID", "s5066.23.sapid", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }
		},
		{ &hf_s5066_23_size,
			{ "U_PDU Size", "s5066.23.size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_s5066_23_data,
			{ "(Part of) Rejected data", "s5066.23.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* Type 24: S_EXPEDITED_UNIDATA_REQUEST */
		{ &hf_s5066_24_unused,
			{ "(Unused)", "s5066.24.unused", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }
		},
		{ &hf_s5066_24_sapid,
			{ "Destination Sap ID", "s5066.24.sapid", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }
		},
		{ &hf_s5066_24_ttl,
			{ "Time-To-Live (x2 seconds)", "s5066.24.ttl", FT_UINT24, BASE_DEC, NULL, 0x0FFFFF, NULL, HFILL }
		},
		{ &hf_s5066_24_size,
			{ "U_PDU Size", "s5066.24.size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* Type 25: S_EXPEDITED_UNIDATA_INDICATION */
		{ &hf_s5066_25_unused,
			{ "(Unused)", "s5066.25.unused", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }
		},
		{ &hf_s5066_25_dest_sapid,
			{ "Destination Sap ID", "s5066.25.dest_sapid", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }
		},
		{ &hf_s5066_25_tx_mode,
			{ "Transmission Mode", "s5066.25.txmode", FT_UINT8, BASE_HEX, VALS(s5066_st_txmode), 0xF0, NULL, HFILL }
		},
		{ &hf_s5066_25_src_sapid,
			{ "Source Sap ID", "s5066.25.src_sapid", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }
		},
		{ &hf_s5066_25_size,
			{ "U_PDU Size", "s5066.25.size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_s5066_25_err_blocks,
			{ "Number of errored blocks", "s5066.25.err_blocks", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_s5066_25_err_ptr,
			{ "Pointer to error block", "s5066.25.err_ptr", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_s5066_25_err_size,
			{ "Size of error block", "s5066.25.err_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_s5066_25_nrx_blocks,
			{ "Number of non-received blocks", "s5066.25.nrx_blocks", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_s5066_25_nrx_ptr,
			{ "Pointer to non-received block", "s5066.25.nrx_ptr", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_s5066_25_nrx_size,
			{ "Size of non-received block", "s5066.25.nrx_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* Type 26: S_EXPEDITED_UNIDATA_REQUEST_CONFIRM */
		{ &hf_s5066_26_unused,
			{ "(Unused)", "s5066.26.unused", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }
		},
		{ &hf_s5066_26_sapid,
			{ "Destination Sap ID", "s5066.26.sapid", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }
		},
		{ &hf_s5066_26_size,
			{ "U_PDU Size", "s5066.26.size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_s5066_26_data,
			{ "(Part of) Confirmed data", "s5066.26.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		/* Type 27: S_EXPEDITED_UNIDATA_REQUEST_REJECTED */
		{ &hf_s5066_27_reason,
			{ "Reason", "s5066.27.reason", FT_UINT8, BASE_DEC, VALS(s5066_27_reason), 0xF0, NULL, HFILL }
		},
		{ &hf_s5066_27_sapid,
			{ "Destination Sap ID", "s5066.27.sapid", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }
		},
		{ &hf_s5066_27_size,
			{ "U_PDU Size", "s5066.27.size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_s5066_27_data,
			{ "(Part of) Rejected data", "s5066.27.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_s5066,
		&ett_s5066_pdu,
		&ett_s5066_servicetype,
		&ett_s5066_address,
	};

	module_t *s5066_module;

	proto_s5066 = proto_register_protocol (
			"STANAG 5066 (SIS layer)",	/* name */
			"STANAG 5066",			/* short name*/
			"s5066"				/* abbrev */
		);
	proto_register_field_array(proto_s5066, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	s5066_module = prefs_register_protocol(proto_s5066, proto_reg_handoff_s5066);
	prefs_register_bool_preference(s5066_module, "desegment_pdus",
				       "Reassemble S5066 PDUs spanning multiple TCP segments",
				       "Whether the S5066 dissector should reassemble PDUs spanning multiple TCP segments."
				       " The default is to use reassembly.",
				       &s5066_desegment);
	prefs_register_bool_preference(s5066_module, "edition_one",
				       "Dissect edition 1.0 of STANAG 5066",
				       "Whether the S5066 dissector should dissect this edition of the STANAG."
				       " This edition was never formally approved and is very rare. The common edition is edition 1.2.",
				       &s5066_edition_one);
	prefs_register_uint_preference(s5066_module, "tcp.port",
				       "STANAG 5066 TCP Port",
				       "Set the port for STANAG 5066. (If other than the default 5066."
				       " This number is registered with IANA.)",
				       10, &global_s5066_port);
}

void
proto_reg_handoff_s5066(void)
{
	static gboolean Initialized = FALSE;
	static dissector_handle_t s5066_tcp_handle;
	static guint saved_s5066_port;

	if (!Initialized) {
		s5066_tcp_handle = create_dissector_handle(dissect_s5066_tcp, proto_s5066);
		data_handle = find_dissector("data");
		Initialized = TRUE;
	} else {
		dissector_delete_uint("tcp.port", saved_s5066_port, s5066_tcp_handle);
	}

	dissector_add_uint("tcp.port", global_s5066_port, s5066_tcp_handle);
	saved_s5066_port = global_s5066_port;

	if (!s5066_edition_one) {
		s5066_header_size = 5;
		s5066_size_offset = 3;
	} else {
		s5066_header_size = 4;
		s5066_size_offset = 2;
	}
}

static guint
dissect_s5066_address(tvbuff_t *tvb, guint offset, proto_tree *tree, gint source)
{
        proto_item *ti = NULL;
        proto_tree *s5066_tree_address = NULL;
	guint32 addr;

        if (source) {
		ti = proto_tree_add_text(tree, tvb, offset, 4, "Source Address");
	}
	else {
		ti = proto_tree_add_text(tree, tvb, offset, 4, "Destination Address");
	}
        s5066_tree_address = proto_item_add_subtree(ti, ett_s5066_address);
	proto_tree_add_item(s5066_tree_address, hf_s5066_ad_size, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(s5066_tree_address, hf_s5066_ad_group, tvb, offset, 1, ENC_BIG_ENDIAN);
	addr = tvb_get_ntohl(tvb, offset);
	addr = addr & 0x1FFFFFFF;
	proto_tree_add_ipv4(s5066_tree_address, hf_s5066_ad_address, tvb, offset, 4, g_htonl(addr));

	return offset + 4;
}

static guint
dissect_s5066_servicetype(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
        proto_item *ti = NULL;
        proto_tree *s5066_tree_servicetype = NULL;

        ti = proto_tree_add_text(tree, tvb, offset, 2, "Service type");
        s5066_tree_servicetype = proto_item_add_subtree(ti, ett_s5066_servicetype);

	proto_tree_add_item(s5066_tree_servicetype, hf_s5066_st_txmode, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(s5066_tree_servicetype, hf_s5066_st_delivery_confirmation, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(s5066_tree_servicetype, hf_s5066_st_delivery_order, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(s5066_tree_servicetype, hf_s5066_st_extended, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	proto_tree_add_item(s5066_tree_servicetype, hf_s5066_st_retries, tvb, offset, 1, ENC_BIG_ENDIAN);

	return offset;
}

/* S_BIND_REQUEST */
static guint
dissect_s5066_01(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_s5066_01_sapid, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_s5066_01_rank, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;

	offset = dissect_s5066_servicetype(tvb, offset, tree);

	proto_tree_add_item(tree, hf_s5066_01_unused, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	return offset;
}

/* S_UNBIND_REQUEST */
/* Commented out: does nothing and causes <variable not used> messages.
static guint
dissect_s5066_02(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
	return offset;
}
*/

/* S_BIND_ACCEPTED */
static guint
dissect_s5066_03(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_s5066_03_sapid, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_s5066_03_unused, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	proto_tree_add_item(tree, hf_s5066_03_mtu, tvb, offset, 2, ENC_BIG_ENDIAN); offset +=2;
	return offset;
}

/* S_BIND_REJECTED */
static guint
dissect_s5066_04(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_s5066_04_reason, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	return offset;
}

/* S_UNBIND_INDICATION */
static guint
dissect_s5066_05(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_s5066_05_reason, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	return offset;
}

/* S_HARD_LINK_ESTABLISH */
static guint
dissect_s5066_06(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_s5066_06_link_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_s5066_06_link_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_s5066_06_sapid, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	offset = dissect_s5066_address(tvb, offset, tree, FALSE);
	return offset;
}

/* S_HARD_LINK_TERMINATE */
static guint
dissect_s5066_07(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
	offset = dissect_s5066_address(tvb, offset, tree, FALSE);
	return offset;
}

/* S_HARD_LINK_ESTABLISHED */
static guint
dissect_s5066_08(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_s5066_08_remote_status, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	proto_tree_add_item(tree, hf_s5066_08_link_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_s5066_08_link_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_s5066_08_sapid, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	offset = dissect_s5066_address(tvb, offset, tree, FALSE);
	return offset;
}

/* S_HARD_LINK_REJECTED */
static guint
dissect_s5066_09(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_s5066_09_reason, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	proto_tree_add_item(tree, hf_s5066_09_link_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_s5066_09_link_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_s5066_09_sapid, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	offset = dissect_s5066_address(tvb, offset, tree, FALSE);
	return offset;
}

/* S_HARD_LINK_TERMINATED */
static guint
dissect_s5066_10(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_s5066_10_reason, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	proto_tree_add_item(tree, hf_s5066_10_link_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_s5066_10_link_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_s5066_10_sapid, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	offset = dissect_s5066_address(tvb, offset, tree, FALSE);
	return offset;
}

/* S_HARD_LINK_INDICATION */
static guint
dissect_s5066_11(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_s5066_11_remote_status, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	proto_tree_add_item(tree, hf_s5066_11_link_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_s5066_11_link_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_s5066_11_sapid, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	offset = dissect_s5066_address(tvb, offset, tree, FALSE);
	return offset;
}

/* S_HARD_LINK_ACCEPT */
static guint
dissect_s5066_12(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_s5066_12_link_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_s5066_12_link_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_s5066_12_sapid, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	offset = dissect_s5066_address(tvb, offset, tree, FALSE);
	return offset;
}

/* S_HARD_LINK_REJECT */
static guint
dissect_s5066_13(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_s5066_13_reason, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	proto_tree_add_item(tree, hf_s5066_13_link_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_s5066_13_link_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_s5066_13_sapid, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	offset = dissect_s5066_address(tvb, offset, tree, FALSE);
	return offset;
}

/* S_SUBNET_AVAILABILITY */
static guint
dissect_s5066_14(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_s5066_14_status, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	proto_tree_add_item(tree, hf_s5066_14_reason, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	return offset;
}

/* Following three commented out: do nothing and cause <variable not used> messages. */
/* S_DATA_FLOW_ON */
/*
static guint
dissect_s5066_15(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
	return offset;
}
*/

/* S_DATA_FLOW_OFF */
/*
static guint
dissect_s5066_16(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
	return offset;
}
*/

/* S_KEEP_ALIVE */
/*
static guint
dissect_s5066_17(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
	return offset;
}
*/

/* S_MANAGEMENT_MESSAGE_REQUEST */
static guint
dissect_s5066_18(tvbuff_t *tvb, guint offset, proto_tree *tree, guint pdu_size)
{
	guint body_size = 0;
	proto_tree_add_item(tree, hf_s5066_18_type, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	body_size = pdu_size - offset;
	proto_tree_add_item(tree, hf_s5066_18_body, tvb, offset, body_size, ENC_NA); offset += body_size;
	return offset;
}

/* S_MANAGEMENT_MESSAGE_INDICATION */
static guint
dissect_s5066_19(tvbuff_t *tvb, guint offset, proto_tree *tree, guint pdu_size)
{
	guint body_size = 0;
	proto_tree_add_item(tree, hf_s5066_19_type, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	body_size = pdu_size - offset;
	proto_tree_add_item(tree, hf_s5066_19_body, tvb, offset, body_size, ENC_NA); offset += body_size;
	return offset;
}

/* S_UNIDATA_REQUEST */
static guint
dissect_s5066_20(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_s5066_20_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_s5066_20_sapid, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	offset = dissect_s5066_address(tvb, offset, tree, FALSE);
	offset = dissect_s5066_servicetype(tvb, offset, tree);
	proto_tree_add_item(tree, hf_s5066_20_ttl, tvb, offset, 3, ENC_BIG_ENDIAN); offset += 3;
	proto_tree_add_item(tree, hf_s5066_20_size, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;

	return offset;
}

/* S_UNIDATA_INDICATION */
static guint
dissect_s5066_21(tvbuff_t *tvb, guint offset, proto_tree *tree, guint pdu_size)
{
	guint i=0;
	proto_item *ti = NULL;
	guint d_pdu_size = 0;
	guint8 tx_mode = 0;
	guint16 no_err_blocks = 0;
	guint16 no_nrx_blocks = 0;
	gboolean non_arq_w_errors = FALSE;

	proto_tree_add_item(tree, hf_s5066_21_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_s5066_21_dest_sapid, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	offset = dissect_s5066_address(tvb, offset, tree, FALSE);

	tx_mode = tvb_get_guint8(tvb, offset);
	tx_mode = (tx_mode & 0xF0) >> 4;
	if (tx_mode == 3) {
		non_arq_w_errors = TRUE;
	}

	proto_tree_add_item(tree, hf_s5066_21_tx_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_s5066_21_src_sapid, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	offset = dissect_s5066_address(tvb, offset, tree, TRUE);

	d_pdu_size = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_s5066_21_size, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;

	/* Handle RockwellCollins (<= v2.1) 4-byte offset */
	if ( (pdu_size - offset) == (d_pdu_size + 4) ) {
		ti = proto_tree_add_item(tree, hf_s5066_21_err_blocks, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
		proto_item_append_text(ti, ", (Field should not be present. Rockwell Collins v2.1 or earlier.) ");
		ti = proto_tree_add_item(tree, hf_s5066_21_nrx_blocks, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
		proto_item_append_text(ti, ", (Field should not be present. Rockwell Collins v2.1 or earlier.) ");
	}
	/* Handle Non-ARQ with errors */
	if ( non_arq_w_errors ) {
		no_err_blocks = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(tree, hf_s5066_21_err_blocks, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
		for (i=0; i<no_err_blocks; i++) {
			proto_tree_add_item(tree, hf_s5066_21_err_ptr, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
			proto_tree_add_item(tree, hf_s5066_21_err_size, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
		}
		no_nrx_blocks = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(tree, hf_s5066_21_nrx_blocks, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
		for (i=0; i<no_nrx_blocks; i++) {
			proto_tree_add_item(tree, hf_s5066_21_nrx_ptr, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
			proto_tree_add_item(tree, hf_s5066_21_nrx_size, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
		}
	}
	return offset;
}

/* S_UNIDATA_REQUEST_CONFIRM */
static guint
dissect_s5066_22(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
	guint pdu_size = 0;
	proto_tree_add_item(tree, hf_s5066_22_unused, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_s5066_22_sapid, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	offset = dissect_s5066_address(tvb, offset, tree, FALSE);
	pdu_size = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_s5066_22_size, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
	proto_tree_add_item(tree, hf_s5066_22_data, tvb, offset, pdu_size, ENC_NA); offset += pdu_size;

	return offset;
}

/* S_UNIDATA_REQUEST_REJECTED */
static guint
dissect_s5066_23(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
	guint pdu_size = 0;
	proto_tree_add_item(tree, hf_s5066_23_reason, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_s5066_23_sapid, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	offset = dissect_s5066_address(tvb, offset, tree, FALSE);
	pdu_size = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_s5066_23_size, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
	proto_tree_add_item(tree, hf_s5066_23_data, tvb, offset, pdu_size, ENC_NA); offset += pdu_size;

	return offset;
}

/* S_EXPEDITED_UNIDATA_REQUEST */
static guint
dissect_s5066_24(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_s5066_24_unused, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_s5066_24_sapid, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	offset = dissect_s5066_address(tvb, offset, tree, FALSE);
	offset = dissect_s5066_servicetype(tvb, offset, tree);
	proto_tree_add_item(tree, hf_s5066_24_ttl, tvb, offset, 3, ENC_BIG_ENDIAN); offset += 3;
	proto_tree_add_item(tree, hf_s5066_24_size, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;

	return offset;
}

/* S_EXPEDITED_UNIDATA_INDICATION */
static guint
dissect_s5066_25(tvbuff_t *tvb, guint offset, proto_tree *tree, guint pdu_size)
{
	guint i=0;
	proto_item *ti = NULL;
	guint d_pdu_size = 0;
	guint8 tx_mode = 0;
	guint16 no_err_blocks = 0;
	guint16 no_nrx_blocks = 0;
	gboolean non_arq_w_errors = FALSE;

	proto_tree_add_item(tree, hf_s5066_25_unused, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_s5066_25_dest_sapid, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	offset = dissect_s5066_address(tvb, offset, tree, FALSE);

	tx_mode = tvb_get_guint8(tvb, offset);
	tx_mode = (tx_mode & 0xF0) >> 4;
	if (tx_mode == 3) {
		non_arq_w_errors = TRUE;
	}

	proto_tree_add_item(tree, hf_s5066_25_tx_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_s5066_25_src_sapid, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	offset = dissect_s5066_address(tvb, offset, tree, TRUE);

	d_pdu_size = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_s5066_25_size, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;

	/* Handle RockwellCollins (<= v2.1) 4-byte offset */
	if ( (pdu_size - offset) == (d_pdu_size + 4) ) {
		ti = proto_tree_add_item(tree, hf_s5066_25_err_blocks, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
		proto_item_append_text(ti, ", (Field should not be present. Rockwell Collins v2.1 or earlier.) ");
		ti = proto_tree_add_item(tree, hf_s5066_25_nrx_blocks, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
		proto_item_append_text(ti, ", (Field should not be present. Rockwell Collins v2.1 or earlier.) ");
	}
	/* Handle Non-ARQ with errors */
	if ( non_arq_w_errors ) {
		no_err_blocks = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(tree, hf_s5066_25_err_blocks, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
		for (i=0; i<no_err_blocks; i++) {
			proto_tree_add_item(tree, hf_s5066_25_err_ptr, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
			proto_tree_add_item(tree, hf_s5066_25_err_size, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
		}
		no_nrx_blocks = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(tree, hf_s5066_25_nrx_blocks, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
		for (i=0; i<no_nrx_blocks; i++) {
			proto_tree_add_item(tree, hf_s5066_25_nrx_ptr, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
			proto_tree_add_item(tree, hf_s5066_25_nrx_size, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
		}
	}
	return offset;
}

/* S_EXPEDITED_UNIDATA_REQUEST_CONFIRM */
static guint
dissect_s5066_26(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
	guint pdu_size = 0;
	proto_tree_add_item(tree, hf_s5066_26_unused, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_s5066_26_sapid, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	offset = dissect_s5066_address(tvb, offset, tree, FALSE);
	pdu_size = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_s5066_26_size, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
	proto_tree_add_item(tree, hf_s5066_26_data, tvb, offset, pdu_size, ENC_NA); offset += pdu_size;

	return offset;
}

/* S_EXPEDITED_UNIDATA_REQUEST_REJECTED */
static guint
dissect_s5066_27(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
	guint pdu_size = 0;
	proto_tree_add_item(tree, hf_s5066_27_reason, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_s5066_27_sapid, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	offset = dissect_s5066_address(tvb, offset, tree, FALSE);
	pdu_size = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_s5066_27_size, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
	proto_tree_add_item(tree, hf_s5066_27_data, tvb, offset, pdu_size, ENC_NA); offset += pdu_size;

	return offset;
}

static guint
get_s5066_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
  guint16 plen;

  /* Get the length of the S5066 PDU. */
  plen = tvb_get_ntohs(tvb, offset + s5066_size_offset);

  /* That length doesn't include the sync, version and length fields; add that in. */
  return plen + s5066_header_size;
}

static void
dissect_s5066_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	/* Make sure there are enough bytes... */
	if (tvb_length(tvb) < 5)
		return;
	/* Check if the first two bytes are 0x90 0xEB: if not,
	   then this is not a S5066 PDU or an unreassembled one.
	   The third byte is the STANAG 5066 version: Right now only 0x00 is defined. */
	if( (tvb_get_guint8(tvb, 0) != 0x90) ||
	    (tvb_get_guint8(tvb, 1) != 0xEB) ||
	    (tvb_get_guint8(tvb, 2) != 0x00) ) {
		return;
	}
	tcp_dissect_pdus(tvb, pinfo, tree, s5066_desegment, s5066_header_size, get_s5066_pdu_len, dissect_s5066_common);
}

static void
dissect_s5066_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset = 0;
	guint pdu_size = 0;
	proto_item *ti_s5066 = NULL;
	proto_item *ti_pdu = NULL;
	tvbuff_t *next_tvb;
	gint available_length = 0;
	gint reported_length = 0;

	/* Determine PDU type to display in INFO column */
	guint8 pdu_type = tvb_get_guint8(tvb, s5066_header_size);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "S5066");
	/* Clear out stuff in the info column, the add PDU type */
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "PDU type %s", val_to_str(pdu_type, s5066_pdu_type, "Unknown (0x%02x)"));
	}

	if (tree) { /* We are being asked for details */
		proto_tree *s5066_tree = NULL;
		proto_tree *s5066_tree_pdu = NULL;

		pdu_size = tvb_get_ntohs(tvb, s5066_size_offset) + s5066_header_size;

		ti_s5066 = proto_tree_add_item(tree, proto_s5066, tvb, 0, -1, ENC_NA);
		proto_item_append_text(ti_s5066, ", PDU type %s", val_to_str(pdu_type, s5066_pdu_type, "Unknown (0x%02x)"));
		s5066_tree = proto_item_add_subtree(ti_s5066, ett_s5066);
		proto_tree_add_item(s5066_tree, hf_s5066_sync_word, tvb, offset, 2, ENC_BIG_ENDIAN); offset +=2;
		if (!s5066_edition_one) {
			proto_tree_add_item(s5066_tree, hf_s5066_version,   tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
		}
		proto_tree_add_item(s5066_tree, hf_s5066_size,      tvb, offset, 2, ENC_BIG_ENDIAN); offset +=2;
		ti_pdu = proto_tree_add_item(s5066_tree, hf_s5066_type, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
		s5066_tree_pdu = proto_item_add_subtree(ti_pdu, ett_s5066_pdu);
		switch (pdu_type) {
		case  1: offset = dissect_s5066_01(tvb, offset, s5066_tree_pdu); break;
		/* case  2: offset = dissect_s5066_02(tvb, offset, s5066_tree_pdu); break; */
		case  3: offset = dissect_s5066_03(tvb, offset, s5066_tree_pdu); break;
		case  4: offset = dissect_s5066_04(tvb, offset, s5066_tree_pdu); break;
		case  5: offset = dissect_s5066_05(tvb, offset, s5066_tree_pdu); break;
		case  6: offset = dissect_s5066_06(tvb, offset, s5066_tree_pdu); break;
		case  7: offset = dissect_s5066_07(tvb, offset, s5066_tree_pdu); break;
		case  8: offset = dissect_s5066_08(tvb, offset, s5066_tree_pdu); break;
		case  9: offset = dissect_s5066_09(tvb, offset, s5066_tree_pdu); break;
		case 10: offset = dissect_s5066_10(tvb, offset, s5066_tree_pdu); break;
		case 11: offset = dissect_s5066_11(tvb, offset, s5066_tree_pdu); break;
		case 12: offset = dissect_s5066_12(tvb, offset, s5066_tree_pdu); break;
		case 13: offset = dissect_s5066_13(tvb, offset, s5066_tree_pdu); break;
		case 14: offset = dissect_s5066_14(tvb, offset, s5066_tree_pdu); break;
		/* case 15: offset = dissect_s5066_15(tvb, offset, s5066_tree_pdu); break; */
		/* case 16: offset = dissect_s5066_16(tvb, offset, s5066_tree_pdu); break; */
		/* case 17: offset = dissect_s5066_17(tvb, offset, s5066_tree_pdu); break; */
		case 18: offset = dissect_s5066_18(tvb, offset, s5066_tree_pdu, pdu_size); break;
		case 19: offset = dissect_s5066_19(tvb, offset, s5066_tree_pdu, pdu_size); break;
		case 20: offset = dissect_s5066_20(tvb, offset, s5066_tree_pdu); break;
		case 21: offset = dissect_s5066_21(tvb, offset, s5066_tree_pdu, pdu_size); break;
		case 22: offset = dissect_s5066_22(tvb, offset, s5066_tree_pdu); break;
		case 23: offset = dissect_s5066_23(tvb, offset, s5066_tree_pdu); break;
		case 24: offset = dissect_s5066_24(tvb, offset, s5066_tree_pdu); break;
		case 25: offset = dissect_s5066_25(tvb, offset, s5066_tree_pdu, pdu_size); break;
		case 26: offset = dissect_s5066_26(tvb, offset, s5066_tree_pdu); break;
		case 27: offset = dissect_s5066_27(tvb, offset, s5066_tree_pdu); break;
		}
	}
	proto_item_set_len(ti_s5066, offset);

	/* Call sub dissector(s) */
	reported_length = pdu_size - offset;
	available_length = tvb_length(tvb) - offset;

	next_tvb = tvb_new_subset(tvb, offset, MIN(available_length, reported_length), reported_length);
	call_dissector(data_handle, next_tvb, pinfo, tree);

	return;
}
