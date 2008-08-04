/* packet-gsm_bsslap.c
 * Routines for Location Services (LCS) Serving Mobile Location Centre - Base Station System (SMLC-BSS) dissection
 * Copyright 2008, Anders Broman <anders.broman[at]ericsson.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * References: 3GPP TS 48.071 version 7.2.0 Release 7
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>

#include "packet-gsm_a_common.h"

/* Initialize the protocol and registered fields */
static int proto_gsm_bsslap			= -1;
static int hf_gsm_bsslap_msg_type	= -1;
static int hf_gsm_bsslap_ie			= -1;
static int hf_gsm_bsslap_cell_id	= -1;
static int hf_gsm_bsslap_ta			= -1;
static int hf_gsm_bsslap_length		= -1;

/* Initialize the subtree pointers */
static int ett_gsm_bsslap = -1;
static int ett_gsm_bsslap_ie = -1;
static int ett_gsm_bsslap_ta = -1;
static int ett_gsm_bsslap_meas_rep = -1;
static int ett_gsm_bsslap_enh_meas_rep = -1;
static int ett_gsm_bsslap_cell_id = -1;

/* Table 5.1: Element Indentifier codes */

static const value_string gsm_bsslap_ie_code_vals[] = {
	{  0x00,	"Reserved" },
	{  0x01,	"Timing Advance" },
	{  0x08,	"Reserved" },			/* (note) */
	{  0x09,	"Cell Identity" },	
	{  0x0a,	"Reserved" },			/* (note) */
	{  0x0b,	"Reserved" },			/* (note) */
	{  0x0c,	"Reserved" },			/* (note) */
	{  0x10,	"Channel Description" },
	{  0x11,	"Reserved" },			/* (note) */
	{  0x12,	"Reserved" },			/* (note) */
	{  0x13,	"Reserved" },			/* (note) */
	{  0x14,	"Measurement Report" },
	{  0x15,	"Reserved" },			/* (note) */
	{  0x18,	"Cause" },
	{  0x19,	"RRLP Flag" },
	{  0x1b,	"RRLP IE" },
	{  0x1c,	"Cell Identity List" },
	{  0x1d,	"Enhanced Measurement Report" },
	{  0x1e,	"Location Area Code" },
	{  0x21,	"Frequency List" },
	{  0x22,	"MS Power" },
	{  0x23,	"Delta Timer" },
	{  0x24,	"Serving Cell Identifier" },
	{  0x25,	"Encryption Key (Kc)" },
	{  0x26,	"Cipher Mode Setting" },
	{  0x27,	"Channel Mode" },
	{  0x28,	"MultiRate Configuration" },
	{  0x29,	"Polling Repetition" },
	{  0x2a,	"Packet Channel Description" },
	{  0x2b,	"TLLI" },
	{  0x2c,	"TFI" },
	{  0x2d,	"Starting Time" },
	{ 0,		NULL },
};

/*
 *	NOTE: These values of the codepoints shall not be used as they were used in an earlier version of the
 *	protocol.
 *	All unassigned codes are spare.
 */


#define BSSLAP_TA_REQUEST	1
#define BSSLAP_TA_RESPONSE	2
#define BSSLAP_REJECT		10
#define BSSLAP_RESET		11
#define BSSLAP_ABORT		12
#define BSSLAP_TA_LAYER3	13
#define BSSLAP_MS_POS_CMD	15
#define BSSLAP_MS_POS_RES	16
#define BSSLAP_U_TDOA_REQ	17
#define BSSLAP_U_TDOA_RES	18

/* Table 5.1.1: Message Type codes */
static const value_string gsm_bsslap_msg_type_vals[] = {
	{  0x00,				"Reserved" },
	{  BSSLAP_TA_REQUEST,	"TA REQUEST" },
	{  BSSLAP_TA_RESPONSE,	"TA RESPONSE" },
	{  0x04,				"Reserved" },
	{  0x05,				"Reserved" },
	{  BSSLAP_REJECT,		"REJECT" },
	{  BSSLAP_RESET,		"RESET" },
	{  BSSLAP_ABORT,		"ABORT" },
	{  BSSLAP_TA_LAYER3,	"TA LAYER3" },
	{  BSSLAP_MS_POS_CMD,	"MS Position Command" },
	{  BSSLAP_MS_POS_RES,	"MS Position Response" },
	{  BSSLAP_U_TDOA_REQ,	"U-TDOA Request" },
	{  BSSLAP_U_TDOA_RES,	"U-TDOA Response" },
	{ 0,			NULL }
};

/* 4.2.1 TA Request ETSI TS 148 071 V7.2.0 (2007-06) */
static int
dissect_gsm_bsslap_ta(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	/* Message Type IE / 5.1 M V 1 */
	proto_tree_add_item(tree, hf_gsm_bsslap_msg_type, tvb, offset, 1, FALSE);
	offset++;
	return offset;
}

/* 4.2.2 TA Response ETSI TS 148 071 V7.2.0 (2007-06) */
static int
dissect_gsm_bsslap_ta_res(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	proto_item	*item = NULL;
	proto_tree	*subtree = NULL;
	guint16 value;
	guint8 octet;
	guint8 length;

	/* Message Type IE / 5.1 M V 1 */
	proto_tree_add_item(tree, hf_gsm_bsslap_msg_type, tvb, offset, 1, FALSE);
	offset++;

	/* Cell Identity IE / 5.4 M TV 3 */
	item = proto_tree_add_text(tree,tvb, offset, 3,"Serving Cell Identity - ");
	subtree = proto_item_add_subtree(item, ett_gsm_bsslap_ie);
	proto_tree_add_item(subtree, hf_gsm_bsslap_ie, tvb, offset, 1, FALSE);
	offset++;
	value = tvb_get_ntohs(tvb, offset);
	proto_item_append_text(item ,"0x%x(%u)",value,value);
	proto_tree_add_item(subtree, hf_gsm_bsslap_cell_id, tvb, offset, 2, FALSE);
	offset = offset + 2;

	/* Timing Advance IE / 5.2 M TV 2 */
	item = proto_tree_add_text(tree,tvb, offset, 2,"Timing Advance - ");
	subtree = proto_item_add_subtree(item, ett_gsm_bsslap_ta);
	proto_tree_add_item(subtree, hf_gsm_bsslap_ie, tvb, offset, 1, FALSE);
	offset++;
	octet = tvb_get_guint8(tvb,offset);
	proto_tree_add_item(subtree, hf_gsm_bsslap_ta, tvb, offset, 1, FALSE);
	proto_item_append_text(item ,"%u",octet);
	offset++;

	if(tvb_reported_length_remaining(tvb,offset)==0){
		return offset;
	}
	/* Measurement Report IE / 5.12 O TLV 18 */
	item = proto_tree_add_text(tree,tvb, offset, 18,"Measurement Report");
	subtree = proto_item_add_subtree(item, ett_gsm_bsslap_meas_rep);
	proto_tree_add_item(subtree, hf_gsm_bsslap_ie, tvb, offset, 1, FALSE);
	offset++;
	length = tvb_get_guint8(tvb,offset);
	proto_tree_add_item(subtree, hf_gsm_bsslap_length, tvb, offset, 1, FALSE);
	offset++;
	/*TODO: Check this, may not give correct decoding */
	de_rr_meas_res(tvb, subtree, offset, length, NULL, 0);
	offset = offset + length;
	if(tvb_reported_length_remaining(tvb,offset)==0){
		return offset;
	}

	/* Enhanced Measurement Report IE / 5.18 O TLV 4-n */
	item = proto_tree_add_text(tree,tvb, offset, -1,"Enhanced Measurement Report");
	subtree = proto_item_add_subtree(item, ett_gsm_bsslap_enh_meas_rep);
	proto_tree_add_item(subtree, hf_gsm_bsslap_ie, tvb, offset, 1, FALSE);
	offset++;
	length = tvb_get_guint8(tvb,offset);
	proto_item_set_len(item, length+2);
	proto_tree_add_item(subtree, hf_gsm_bsslap_length, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_text(tree,tvb, offset, length,"Data not decoded(yet)");
	offset = offset + length;
	if(tvb_reported_length_remaining(tvb,offset)==0){
		return offset;
	}

	/* Cell Identity List IE / 5.17 O TLV 6-n */
	item = proto_tree_add_text(tree,tvb, offset, -1,"Enhanced Measurement Report");
	subtree = proto_item_add_subtree(item, ett_gsm_bsslap_cell_id);
	proto_tree_add_item(subtree, hf_gsm_bsslap_ie, tvb, offset, 1, FALSE);
	offset++;
	length = tvb_get_guint8(tvb,offset);
	proto_item_set_len(item, length+2);
	proto_tree_add_item(subtree, hf_gsm_bsslap_length, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_text(tree,tvb, offset, length,"Data not decoded(yet)");
	offset = offset + length;

	return offset;

}


/* 4.2.3 (void)   ETSI TS 148 071 V7.2.0 (2007-06) */
/* 4.2.4 (void)   ETSI TS 148 071 V7.2.0 (2007-06) */
/* 4.2.5 Reject   ETSI TS 148 071 V7.2.0 (2007-06) */
static int
dissect_gsm_bsslap_reject(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	/* Message Type IE / 5.1 M V 1 */
	proto_tree_add_item(tree, hf_gsm_bsslap_msg_type, tvb, offset, 1, FALSE);
	offset++;
	return offset;
}

/* 4.2.6 Reset   ETSI TS 148 071 V7.2.0 (2007-06) */
static int
dissect_gsm_bsslap_reset(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	/* Message Type IE / 5.1 M V 1 */
	proto_tree_add_item(tree, hf_gsm_bsslap_msg_type, tvb, offset, 1, FALSE);
	offset++;
	return offset;
}

/* 4.2.7 Abort  ETSI TS 148 071 V7.2.0 (2007-06) */
static int
dissect_gsm_bsslap_abort(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	/* Message Type IE / 5.1 M V 1 */
	proto_tree_add_item(tree, hf_gsm_bsslap_msg_type, tvb, offset, 1, FALSE);
	offset++;
	return offset;
}
/* 4.2.8 TA Layer3  ETSI TS 148 071 V7.2.0 (2007-06) */
static int
dissect_gsm_bsslap_ta_layer3(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	/* Message Type IE / 5.1 M V 1 */
	proto_tree_add_item(tree, hf_gsm_bsslap_msg_type, tvb, offset, 1, FALSE);
	offset++;
	return offset;
}
/* 4.2.9 MS Position Command  ETSI TS 148 071 V7.2.0 (2007-06) */
static int
dissect_gsm_bsslap_ms_pos_cmd(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	/* Message Type IE / 5.1 M V 1 */
	proto_tree_add_item(tree, hf_gsm_bsslap_msg_type, tvb, offset, 1, FALSE);
	offset++;
	return offset;
}
/* 4.2.10 MS Position Response   ETSI TS 148 071 V7.2.0 (2007-06) */
static int
dissect_gsm_bsslap_ms_pos_res(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	/* Message Type IE / 5.1 M V 1 */
	proto_tree_add_item(tree, hf_gsm_bsslap_msg_type, tvb, offset, 1, FALSE);
	offset++;
	return offset;
}
/* 4.2.11 U-TDOA Request   ETSI TS 148 071 V7.2.0 (2007-06) */
static int
dissect_gsm_bsslap_u_tdoa_req(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	/* Message Type IE / 5.1 M V 1 */
	proto_tree_add_item(tree, hf_gsm_bsslap_msg_type, tvb, offset, 1, FALSE);
	offset++;
	return offset;
}
/* 4.2.12 U-TDOA Response  ETSI TS 148 071 V7.2.0 (2007-06) */
static int
dissect_gsm_bsslap_u_tdoa_res(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	/* Message Type IE / 5.1 M V 1 */
	proto_tree_add_item(tree, hf_gsm_bsslap_msg_type, tvb, offset, 1, FALSE);
	offset++;
	return offset;
}


static void
dissect_gsm_bsslap_apdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *item;
	proto_tree *sub_tree;
	int	offset=0;
	guint8 octet;

/* Make entries in Protocol column and Info column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_append_str(pinfo->cinfo, COL_PROTOCOL, "/BSSLAP");
	if (tree) {
		octet = tvb_get_guint8(tvb, offset);
		item = proto_tree_add_item(tree, proto_gsm_bsslap, tvb, 0, -1, FALSE);
		sub_tree = proto_item_add_subtree(item, ett_gsm_bsslap);

		switch (octet){
		case BSSLAP_TA_REQUEST:
			offset = dissect_gsm_bsslap_ta(tvb, sub_tree, offset);
			break;
		case BSSLAP_TA_RESPONSE:
			offset = dissect_gsm_bsslap_ta_res(tvb, sub_tree, offset); 
			break;
		case BSSLAP_REJECT:
			offset = dissect_gsm_bsslap_reject(tvb, sub_tree, offset);
			break;
		case BSSLAP_RESET:
			offset = dissect_gsm_bsslap_reset(tvb, sub_tree, offset);
			break;
		case BSSLAP_ABORT:			
			offset = dissect_gsm_bsslap_abort(tvb, sub_tree, offset);
			break;
		case BSSLAP_TA_LAYER3:
			offset = dissect_gsm_bsslap_ta_layer3(tvb, sub_tree, offset);
			break;
		case BSSLAP_MS_POS_CMD:
			offset = dissect_gsm_bsslap_ms_pos_cmd(tvb, sub_tree, offset);
			break;
		case BSSLAP_MS_POS_RES:
			offset = dissect_gsm_bsslap_ms_pos_res(tvb, sub_tree, offset);
			break;
		case BSSLAP_U_TDOA_REQ:
			offset = dissect_gsm_bsslap_u_tdoa_req(tvb, sub_tree, offset);
			break;
		case BSSLAP_U_TDOA_RES:
			offset = dissect_gsm_bsslap_u_tdoa_res(tvb, sub_tree, offset);
			break;
		default:
			break;
		}
	}


}

void
proto_reg_handoff_gsm_bsslap(void)
{
	dissector_handle_t gsm_bsslap_handle;
	
	gsm_bsslap_handle = create_dissector_handle(dissect_gsm_bsslap_apdu, proto_gsm_bsslap);

}

void
proto_register_gsm_bsslap(void)
{                 


/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_gsm_bsslap_msg_type,
			{ "Message Type IE",           "gsm_bsslap.msg_type",
			FT_UINT8, BASE_DEC, VALS(gsm_bsslap_msg_type_vals), 0x0,          
			"Message Type IE", HFILL }
		},
		{ &hf_gsm_bsslap_ie,
			{ "Element identifier",           "gsm_bsslap.ie",
			FT_UINT8, BASE_DEC, VALS(gsm_bsslap_ie_code_vals), 0x0,          
			"Message Type IE", HFILL }
		},
		{ &hf_gsm_bsslap_cell_id,
			{ "Cell ID",	"gsm_bsslap.cell_id",
			FT_UINT16, BASE_HEX_DEC, 0, 0x0,
			"", HFILL }
		},
		{ &hf_gsm_bsslap_ta,
			{ "Timing Advance",           "gsm_bsslap.ta",
			FT_UINT8, BASE_HEX, NULL, 0x0,          
			"Timing Advance", HFILL }
		},
		{ &hf_gsm_bsslap_length,
			{ "Length",           "gsm_bsslap.length",
			FT_UINT8, BASE_DEC, NULL, 0x0,          
			"Length", HFILL }
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_gsm_bsslap,
		&ett_gsm_bsslap_ie,
		&ett_gsm_bsslap_ta,
		&ett_gsm_bsslap_meas_rep,
		&ett_gsm_bsslap_enh_meas_rep,
		&ett_gsm_bsslap_cell_id,
	};

/* Register the protocol name and description */
	proto_gsm_bsslap = 
		proto_register_protocol("BSS LCS Assistance Protocol",
		"BSSLAP", "bsslap");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_gsm_bsslap, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("gsm_bsslap", dissect_gsm_bsslap_apdu, proto_gsm_bsslap);
}
