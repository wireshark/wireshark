/* packet-mstp.c
 * Routines for BACnet MS/TP datalink dissection
 * Copyright 2008 Steve Karg <skarg@users.sourceforge.net> Alabama
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/oui.h>
#include <epan/llcsaps.h>
#include <epan/expert.h>
#include "packet-llc.h"
#include "packet-mstp.h"

/* Probably should be a preference, but here for now */
#define BACNET_MSTP_SUMMARY_IN_TREE
#define BACNET_MSTP_CHECKSUM_VALIDATE

/* MS/TP Frame Type */
/* Frame Types 8 through 127 are reserved by ASHRAE. */
#define MSTP_TOKEN 0
#define MSTP_POLL_FOR_MASTER 1
#define MSTP_REPLY_TO_POLL_FOR_MASTER 2
#define MSTP_TEST_REQUEST 3
#define MSTP_TEST_RESPONSE 4
#define MSTP_BACNET_DATA_EXPECTING_REPLY 5
#define MSTP_BACNET_DATA_NOT_EXPECTING_REPLY 6
#define MSTP_REPLY_POSTPONED 7

static const value_string
bacnet_mstp_frame_type_name[] = {
	{MSTP_TOKEN, "Token"},
	{MSTP_POLL_FOR_MASTER, "Poll For Master"},
	{MSTP_REPLY_TO_POLL_FOR_MASTER, "Reply To Poll For Master"},
	{MSTP_TEST_REQUEST, "Test_Request"},
	{MSTP_TEST_RESPONSE, "Test_Response"},
	{MSTP_BACNET_DATA_EXPECTING_REPLY, "BACnet Data Expecting Reply"},
	{MSTP_BACNET_DATA_NOT_EXPECTING_REPLY, "BACnet Data Not Expecting Reply"},
	{MSTP_REPLY_POSTPONED, "Reply Postponed"},
	/* Frame Types 128 through 255: Proprietary Frames */
	{0, NULL }
};

static dissector_handle_t data_handle;
static dissector_table_t subdissector_table;

static int proto_mstp = -1;

static gint ett_bacnet_mstp = -1;
static gint ett_bacnet_mstp_checksum = -1;

static int hf_mstp_preamble_55 = -1;
static int hf_mstp_preamble_FF = -1;
static int hf_mstp_frame_type = -1;
static int hf_mstp_frame_destination = -1;
static int hf_mstp_frame_source = -1;
static int hf_mstp_frame_vendor_id = -1;
static int hf_mstp_frame_pdu_len = -1;
static int hf_mstp_frame_crc8 = -1;
static int hf_mstp_frame_crc16 = -1;
static int hf_mstp_frame_checksum_bad = -1;
static int hf_mstp_frame_checksum_good = -1;

#if defined(BACNET_MSTP_CHECKSUM_VALIDATE)
/* Accumulate "dataValue" into the CRC in crcValue. */
/* Return value is updated CRC */
/*  The ^ operator means exclusive OR. */
/* Note: This function is copied directly from the BACnet standard. */
static guint8
CRC_Calc_Header(
	guint8 dataValue,
	guint8 crcValue)
{
	guint16 crc;

	crc = crcValue ^ dataValue; /* XOR C7..C0 with D7..D0 */

	/* Exclusive OR the terms in the table (top down) */
	crc = crc ^ (crc << 1) ^ (crc << 2) ^ (crc << 3)
		^ (crc << 4) ^ (crc << 5) ^ (crc << 6)
		^ (crc << 7);

	/* Combine bits shifted out left hand end */
	return (crc & 0xfe) ^ ((crc >> 8) & 1);
}
#endif

#if defined(BACNET_MSTP_CHECKSUM_VALIDATE)
/* Accumulate "dataValue" into the CRC in crcValue. */
/*  Return value is updated CRC */
/*  The ^ operator means exclusive OR. */
/* Note: This function is copied directly from the BACnet standard. */
static guint16
CRC_Calc_Data(
	guint8 dataValue,
	guint16 crcValue)
{
	guint16 crcLow;

	crcLow = (crcValue & 0xff) ^ dataValue;     /* XOR C7..C0 with D7..D0 */

	/* Exclusive OR the terms in the table (top down) */
	return (crcValue >> 8) ^ (crcLow << 8) ^ (crcLow << 3)
		^ (crcLow << 12) ^ (crcLow >> 4)
		^ (crcLow & 0x0f) ^ ((crcLow & 0x0f) << 7);
}
#endif

/* Common frame type text */
const gchar *
mstp_frame_type_text(guint32 val)
{
	return val_to_str(val,
		bacnet_mstp_frame_type_name,
		"Unknown Frame Type (%u)");
}

/* dissects a BACnet MS/TP frame */
/* preamble 0x55 0xFF is not included in Cimetrics U+4 output */
void
dissect_mstp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	proto_tree *subtree, gint offset)
{
	guint8 mstp_frame_type = 0;
	guint16 mstp_frame_pdu_len = 0;
	guint16 mstp_tvb_pdu_len = 0;
	guint16 vendorid = 0;
	tvbuff_t *next_tvb = NULL;
	proto_item *item;
#if defined(BACNET_MSTP_CHECKSUM_VALIDATE)
	/* used to calculate the crc value */
	guint8 crc8 = 0xFF, framecrc8;
	guint16 crc16 = 0xFFFF, framecrc16;
	guint8 crcdata;
	guint16 i; /* loop counter */
	guint16 max_len = 0;
	proto_tree *checksum_tree;
#endif

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BACnet");
	col_set_str(pinfo->cinfo, COL_INFO, "BACnet MS/TP");
	mstp_frame_type = tvb_get_guint8(tvb, offset);
	mstp_frame_pdu_len = tvb_get_ntohs(tvb, offset+3);
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
			mstp_frame_type_text(mstp_frame_type));
	}
	/* Add the items to the tree */
	proto_tree_add_item(subtree, hf_mstp_frame_type, tvb,
			offset, 1, TRUE);
	proto_tree_add_item(subtree, hf_mstp_frame_destination, tvb,
			offset+1, 1, TRUE);
	proto_tree_add_item(subtree, hf_mstp_frame_source, tvb,
			offset+2, 1, TRUE);
	item = proto_tree_add_item(subtree, hf_mstp_frame_pdu_len, tvb,
			offset+3, 2, FALSE);
	mstp_tvb_pdu_len = tvb_length_remaining(tvb, offset+6);
	/* check the length - which does not include the crc16 checksum */
	if (mstp_tvb_pdu_len > 2) {
		if (mstp_frame_pdu_len > (mstp_tvb_pdu_len-2)) {
			expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR,
				"Length field value goes past the end of the payload");
		}
	}
#if defined(BACNET_MSTP_CHECKSUM_VALIDATE)
	/* calculate checksum to validate */
	for (i = 0; i < 5; i++) {
		crcdata = tvb_get_guint8(tvb, offset+i);
		crc8 = CRC_Calc_Header(crcdata, crc8);
	}
	crc8 = ~crc8;
	framecrc8 = tvb_get_guint8(tvb, offset+5);
	if (framecrc8 == crc8) {
		item = proto_tree_add_uint_format(subtree, hf_mstp_frame_crc8,
			tvb, offset+5, 1, framecrc8,
			"Header CRC: 0x%02x [correct]", framecrc8);
		checksum_tree = proto_item_add_subtree(item, ett_bacnet_mstp_checksum);
		item = proto_tree_add_boolean(checksum_tree,
			hf_mstp_frame_checksum_good,
			tvb, offset+5, 1, TRUE);
		PROTO_ITEM_SET_GENERATED(item);
		item = proto_tree_add_boolean(checksum_tree,
			hf_mstp_frame_checksum_bad,
			tvb, offset+5, 1, FALSE);
		PROTO_ITEM_SET_GENERATED(item);
	} else {
		item = proto_tree_add_uint_format(subtree, hf_mstp_frame_crc8,
			tvb, offset+5, 1, framecrc8,
			"Header CRC: 0x%02x [incorrect, should be 0x%02x]",
			framecrc8, crc8);
		checksum_tree = proto_item_add_subtree(item, ett_bacnet_mstp_checksum);
		item = proto_tree_add_boolean(checksum_tree,
			hf_mstp_frame_checksum_good,
			tvb, offset+5, 1, FALSE);
		PROTO_ITEM_SET_GENERATED(item);
		item = proto_tree_add_boolean(checksum_tree,
			hf_mstp_frame_checksum_bad,
			tvb, offset+5, 1, TRUE);
		PROTO_ITEM_SET_GENERATED(item);
		expert_add_info_format(pinfo, item, PI_CHECKSUM, PI_ERROR,
			"Bad Checksum");
	}
#else
	proto_tree_add_item(subtree, hf_mstp_frame_crc8,
		tvb, offset+5, 1, TRUE);
#endif

	/* dissect BACnet PDU if there is one */
	offset += 6;
	if (mstp_tvb_pdu_len > 2) {
		/* remove the 16-bit crc checksum bytes */
		mstp_tvb_pdu_len -= 2;
		if (mstp_frame_type < 128) {
			vendorid = 0;
			next_tvb = tvb_new_subset(tvb, offset,
				mstp_tvb_pdu_len, mstp_frame_pdu_len);
		} else {
			/* With Vendor ID */
			vendorid = tvb_get_ntohs(tvb, offset);

			/* Write Vendor ID as tree */
			proto_tree_add_item(subtree, hf_mstp_frame_vendor_id, tvb,
				offset, 2, FALSE);

			/* NPDU - call the Vendor specific dissector */
			next_tvb = tvb_new_subset(tvb, offset+2,
				mstp_tvb_pdu_len-2, mstp_frame_pdu_len);
		}

		if (!(dissector_try_uint(subdissector_table, (vendorid<<16) + mstp_frame_type,
			next_tvb, pinfo, tree))) {
				/* Unknown function - dissect the payload as data */
				call_dissector(data_handle, next_tvb, pinfo, tree);
		}
#if defined(BACNET_MSTP_CHECKSUM_VALIDATE)
		/* 16-bit checksum - calculate to validate */
		max_len = MIN(mstp_frame_pdu_len, mstp_tvb_pdu_len);
		for (i = 0; i < max_len; i++) {
			crcdata = tvb_get_guint8(tvb, offset+i);
			crc16 = CRC_Calc_Data(crcdata, crc16);
		}
		crc16 = ~crc16;
		/* convert it to on-the-wire format */
		crc16 = g_htons(crc16);
		/* get the actual CRC from the frame */
		framecrc16 = tvb_get_ntohs(tvb, offset+mstp_frame_pdu_len);
		if (framecrc16 == crc16) {
			item = proto_tree_add_uint_format(subtree, hf_mstp_frame_crc16,
				tvb, offset+mstp_frame_pdu_len, 2, framecrc16,
				"Data CRC: 0x%04x [correct]", framecrc16);
			checksum_tree = proto_item_add_subtree(item,
				ett_bacnet_mstp_checksum);
			item = proto_tree_add_boolean(checksum_tree,
				hf_mstp_frame_checksum_good,
				tvb, offset+mstp_frame_pdu_len, 2, TRUE);
			PROTO_ITEM_SET_GENERATED(item);
			item = proto_tree_add_boolean(checksum_tree,
				hf_mstp_frame_checksum_bad,
				tvb, offset+mstp_frame_pdu_len, 2, FALSE);
			PROTO_ITEM_SET_GENERATED(item);
		} else {
			item = proto_tree_add_uint_format(subtree, hf_mstp_frame_crc16,
				tvb, offset+mstp_frame_pdu_len, 2, framecrc16,
				"Data CRC: 0x%04x [incorrect, should be 0x%04x]",
				framecrc16, crc16);
			checksum_tree = proto_item_add_subtree(item,
				ett_bacnet_mstp_checksum);
			item = proto_tree_add_boolean(checksum_tree,
				hf_mstp_frame_checksum_good,
				tvb, offset+mstp_frame_pdu_len, 2, FALSE);
			PROTO_ITEM_SET_GENERATED(item);
			item = proto_tree_add_boolean(checksum_tree,
				hf_mstp_frame_checksum_bad,
				tvb, offset+mstp_frame_pdu_len, 2, TRUE);
			PROTO_ITEM_SET_GENERATED(item);
			expert_add_info_format(pinfo, item, PI_CHECKSUM, PI_ERROR,
				"Bad Checksum");
		}
#else
		proto_tree_add_item(subtree, hf_mstp_frame_crc16,
			tvb, offset+mstp_frame_pdu_len, 2, TRUE);
#endif
	}
}

static void
dissect_mstp_wtap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *subtree;
	gint offset = 0;
#ifdef BACNET_MSTP_SUMMARY_IN_TREE
	guint8 mstp_frame_type = 0;
	guint8 mstp_frame_source = 0;
	guint8 mstp_frame_destination = 0;
#endif

	/* set the MS/TP MAC address in the source/destination */
	/* Use AT_ARCNET since it is similar to BACnet MS/TP */
	SET_ADDRESS(&pinfo->dl_dst,	AT_ARCNET, 1, tvb_get_ptr(tvb, offset+3, 1));
	SET_ADDRESS(&pinfo->dst,	AT_ARCNET, 1, tvb_get_ptr(tvb, offset+3, 1));
	SET_ADDRESS(&pinfo->dl_src,	AT_ARCNET, 1, tvb_get_ptr(tvb, offset+4, 1));
	SET_ADDRESS(&pinfo->src,	AT_ARCNET, 1, tvb_get_ptr(tvb, offset+4, 1));

#ifdef BACNET_MSTP_SUMMARY_IN_TREE
	mstp_frame_type = tvb_get_guint8(tvb, offset+2);
	mstp_frame_destination = tvb_get_guint8(tvb, offset+3);
	mstp_frame_source = tvb_get_guint8(tvb, offset+4);
	ti = proto_tree_add_protocol_format(tree, proto_mstp, tvb, offset, 8,
		"BACnet MS/TP, Src (%u), Dst (%u), %s",
		mstp_frame_source, mstp_frame_destination,
		mstp_frame_type_text(mstp_frame_type));
#else
	ti = proto_tree_add_item(tree, proto_mstp, tvb, offset, 8, FALSE);
#endif
	subtree = proto_item_add_subtree(ti, ett_bacnet_mstp);
	proto_tree_add_item(subtree, hf_mstp_preamble_55, tvb,
			offset, 1, TRUE);
	proto_tree_add_item(subtree, hf_mstp_preamble_FF, tvb,
			offset+1, 1, TRUE);
	dissect_mstp(tvb, pinfo, tree, subtree, offset+2);
}

void
proto_register_mstp(void)
{
	static hf_register_info hf[] = {
		{ &hf_mstp_preamble_55,
			{ "Preamble 55", "mstp.preamble_55",
			FT_UINT8, BASE_HEX, NULL, 0,
			"MS/TP Preamble 55", HFILL }
		},
		{ &hf_mstp_preamble_FF,
			{ "Preamble FF", "mstp.preamble_FF",
			FT_UINT8, BASE_HEX, NULL, 0,
			"MS/TP Preamble FF", HFILL }
		},
		{ &hf_mstp_frame_type,
			{ "Frame Type", "mstp.frame_type",
			FT_UINT8, BASE_DEC, VALS(bacnet_mstp_frame_type_name), 0,
			"MS/TP Frame Type", HFILL }
		},
		{ &hf_mstp_frame_destination,
			{ "Destination Address", "mstp.dst",
			FT_UINT8, BASE_DEC, NULL, 0,
			"Destination MS/TP MAC Address", HFILL }
		},
		{ &hf_mstp_frame_source,
			{ "Source Address", "mstp.src",
			FT_UINT8, BASE_DEC, NULL, 0,
			"Source MS/TP MAC Address", HFILL }
		},
		{ &hf_mstp_frame_vendor_id,
			{ "VendorID", "mstp.vendorid",
			FT_UINT16, BASE_DEC, NULL, 0,
			"MS/TP Vendor ID of proprietary frametypes", HFILL }
		},
		{ &hf_mstp_frame_pdu_len,
			{ "Length", "mstp.len",
			FT_UINT16, BASE_DEC, NULL, 0,
			"MS/TP Data Length", HFILL }
		},
		{ &hf_mstp_frame_crc8,
			{ "Header CRC",  "mstp.hdr_crc",
			FT_UINT8, BASE_HEX, NULL, 0,
			"MS/TP Header CRC", HFILL }
		},
		{ &hf_mstp_frame_crc16,
			{ "Data CRC",  "mstp.data_crc",
			FT_UINT16, BASE_HEX, NULL, 0,
			"MS/TP Data CRC", HFILL }
		},
		{ &hf_mstp_frame_checksum_bad,
			{ "Bad", "mstp.checksum_bad",
			FT_BOOLEAN, BASE_NONE,	NULL, 0x0,
			"True: checksum doesn't match packet content; False: matches content or not checked", HFILL }
		},
		{ &hf_mstp_frame_checksum_good,
			{ "Good", "mstp.checksum_good",
			FT_BOOLEAN, BASE_NONE,	NULL, 0x0,
			"True: checksum matches packet content; False: doesn't match content or not checked", HFILL }
		}
	};

	static gint *ett[] = {
		&ett_bacnet_mstp,
		&ett_bacnet_mstp_checksum
	};

	proto_mstp = proto_register_protocol("BACnet MS/TP",
	    "BACnet MS/TP", "mstp");

	proto_register_field_array(proto_mstp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("mstp", dissect_mstp_wtap, proto_mstp);

	subdissector_table = register_dissector_table("mstp.vendor_frame_type",
	    "MSTP Vendor specific Frametypes", FT_UINT24, BASE_DEC);
	/* Table_type: (Vendor ID << 16) + Frametype */
}

void
proto_reg_handoff_mstp(void)
{
	dissector_handle_t mstp_handle;
	dissector_handle_t bacnet_handle;

	mstp_handle = find_dissector("mstp");
	dissector_add_uint("wtap_encap", WTAP_ENCAP_BACNET_MS_TP, mstp_handle);

	bacnet_handle = find_dissector("bacnet");
	data_handle = find_dissector("data");

	dissector_add_uint("mstp.vendor_frame_type", (0/*VendorID ASHRAE*/ << 16) + MSTP_BACNET_DATA_EXPECTING_REPLY, bacnet_handle);
	dissector_add_uint("mstp.vendor_frame_type", (0/*VendorID ASHRAE*/ << 16) + MSTP_BACNET_DATA_NOT_EXPECTING_REPLY, bacnet_handle);
}
