/* packet-mstp.c
 * Routines for BACnet MS/TP datalink dissection
 * Copyright 2008 Steve Karg <skarg@users.sourceforge.net> Alabama
 *
 * This is described in Clause 9 of ANSI/ASHRAE Standard 135-2004,
 * BACnet - A Data Communication Protocol for Building Automation
 * and Contrl Networks; clause 9 "describes a Master-Slave/Token-Passing
 * (MS/TP) data link protocol, which provides the same services to the
 * network layer as ISO 8802-2 Logical Link Control. It uses services
 * provided by the EIA-485 physical layer."  See section 9.3 for the
 * frame format.
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

#include "config.h"

#include <epan/packet.h>
#include <wiretap/wtap.h>
#include <epan/expert.h>
#include <epan/address_types.h>
#include <epan/to_str.h>
#include "packet-mstp.h"

void proto_register_mstp(void);
void proto_reg_handoff_mstp(void);

/* Probably should be a preference, but here for now */
#define BACNET_MSTP_SUMMARY_IN_TREE
#define BACNET_MSTP_CHECKSUM_VALIDATE

/* MS/TP Frame Type */
/* Frame Types 8 through 127 are reserved by ASHRAE. */
#define MSTP_TOKEN                           0
#define MSTP_POLL_FOR_MASTER                 1
#define MSTP_REPLY_TO_POLL_FOR_MASTER        2
#define MSTP_TEST_REQUEST                    3
#define MSTP_TEST_RESPONSE                   4
#define MSTP_BACNET_DATA_EXPECTING_REPLY     5
#define MSTP_BACNET_DATA_NOT_EXPECTING_REPLY 6
#define MSTP_REPLY_POSTPONED                 7

static const value_string
bacnet_mstp_frame_type_name[] = {
	{MSTP_TOKEN,                           "Token"},
	{MSTP_POLL_FOR_MASTER,                 "Poll For Master"},
	{MSTP_REPLY_TO_POLL_FOR_MASTER,        "Reply To Poll For Master"},
	{MSTP_TEST_REQUEST,                    "Test_Request"},
	{MSTP_TEST_RESPONSE,                   "Test_Response"},
	{MSTP_BACNET_DATA_EXPECTING_REPLY,     "BACnet Data Expecting Reply"},
	{MSTP_BACNET_DATA_NOT_EXPECTING_REPLY, "BACnet Data Not Expecting Reply"},
	{MSTP_REPLY_POSTPONED,                 "Reply Postponed"},
	/* Frame Types 128 through 255: Proprietary Frames */
	{0, NULL }
};

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
static int hf_mstp_frame_checksum_status = -1;

static expert_field ei_mstp_frame_pdu_len = EI_INIT;
static expert_field ei_mstp_frame_checksum_bad = EI_INIT;

static int mstp_address_type = -1;

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

static int mstp_str_len(const address* addr _U_)
{
	return 5;
}

static int mstp_to_str(const address* addr, gchar *buf, int buf_len _U_)
{
	*buf++ = '0';
	*buf++ = 'x';
	buf = bytes_to_hexstr(buf, (const guint8 *)addr->data, 1);
	*buf = '\0'; /* NULL terminate */

	return mstp_str_len(addr);
}

static const char* mstp_col_filter_str(const address* addr _U_, gboolean is_src)
{
	if (is_src)
		return "mstp.src";

	return "mstp.dst";
}

static int mstp_len(void)
{
	return 1;
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
	guint8 crc8 = 0xFF;
	guint16 crc16 = 0xFFFF;
	guint8 crcdata;
	guint16 i; /* loop counter */
	guint16 max_len = 0;
#endif

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BACnet");
	col_set_str(pinfo->cinfo, COL_INFO, "BACnet MS/TP");
	mstp_frame_type = tvb_get_guint8(tvb, offset);
	mstp_frame_pdu_len = tvb_get_ntohs(tvb, offset+3);
	col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
			mstp_frame_type_text(mstp_frame_type));

	/* Add the items to the tree */
	proto_tree_add_item(subtree, hf_mstp_frame_type, tvb,
			offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(subtree, hf_mstp_frame_destination, tvb,
			offset+1, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(subtree, hf_mstp_frame_source, tvb,
			offset+2, 1, ENC_LITTLE_ENDIAN);
	item = proto_tree_add_item(subtree, hf_mstp_frame_pdu_len, tvb,
			offset+3, 2, ENC_BIG_ENDIAN);
	mstp_tvb_pdu_len = tvb_reported_length_remaining(tvb, offset+6);
	/* check the length - which does not include the crc16 checksum */
	if (mstp_tvb_pdu_len > 2) {
		if (mstp_frame_pdu_len > (mstp_tvb_pdu_len-2)) {
			expert_add_info(pinfo, item, &ei_mstp_frame_pdu_len);
		}
	}
#if defined(BACNET_MSTP_CHECKSUM_VALIDATE)
	/* calculate checksum to validate */
	for (i = 0; i < 5; i++) {
		crcdata = tvb_get_guint8(tvb, offset+i);
		crc8 = CRC_Calc_Header(crcdata, crc8);
	}
	crc8 = ~crc8;
	proto_tree_add_checksum(subtree, tvb, offset+5, hf_mstp_frame_crc8, hf_mstp_frame_checksum_status, &ei_mstp_frame_checksum_bad, pinfo, crc8,
							ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
#else
	proto_tree_add_checksum(subtree, tvb, offset+5, hf_mstp_frame_crc8, hf_mstp_frame_checksum_status, &ei_mstp_frame_checksum_bad, pinfo, 0,
							PROTO_CHECKSUM_NO_FLAGS);
#endif

	/* dissect BACnet PDU if there is one */
	offset += 6;
	if (mstp_tvb_pdu_len > 2) {
		/* remove the 16-bit crc checksum bytes */
		mstp_tvb_pdu_len -= 2;
		if (mstp_frame_type < 128) {
			vendorid = 0;
			next_tvb = tvb_new_subset_length(tvb, offset,
				mstp_tvb_pdu_len);
		} else {
			/* With Vendor ID */
			vendorid = tvb_get_ntohs(tvb, offset);

			/* Write Vendor ID as tree */
			proto_tree_add_item(subtree, hf_mstp_frame_vendor_id, tvb,
				offset, 2, ENC_BIG_ENDIAN);

			/* NPDU - call the Vendor specific dissector */
			next_tvb = tvb_new_subset(tvb, offset+2,
				mstp_tvb_pdu_len-2, mstp_frame_pdu_len);
		}

		if (!(dissector_try_uint(subdissector_table, (vendorid<<16) + mstp_frame_type,
			next_tvb, pinfo, tree))) {
				/* Unknown function - dissect the payload as data */
				call_data_dissector(next_tvb, pinfo, tree);
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

		proto_tree_add_checksum(subtree, tvb, offset+mstp_frame_pdu_len, hf_mstp_frame_crc16, hf_mstp_frame_checksum_status, &ei_mstp_frame_checksum_bad, pinfo, crc16,
							ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
#else
		proto_tree_add_checksum(subtree, tvb, offset+mstp_frame_pdu_len, hf_mstp_frame_crc16, hf_mstp_frame_checksum_status, &ei_mstp_frame_checksum_bad, pinfo, 0,
							ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
#endif
	}
}

static int
dissect_mstp_wtap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
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
	set_address_tvb(&pinfo->dl_dst,	mstp_address_type, 1, tvb, offset+3);
	copy_address_shallow(&pinfo->dst, &pinfo->dl_dst);
	set_address_tvb(&pinfo->dl_src,	mstp_address_type, 1, tvb, offset+4);
	copy_address_shallow(&pinfo->src, &pinfo->dl_src);

#ifdef BACNET_MSTP_SUMMARY_IN_TREE
	mstp_frame_type = tvb_get_guint8(tvb, offset+2);
	mstp_frame_destination = tvb_get_guint8(tvb, offset+3);
	mstp_frame_source = tvb_get_guint8(tvb, offset+4);
	ti = proto_tree_add_protocol_format(tree, proto_mstp, tvb, offset, 8,
		"BACnet MS/TP, Src (%u), Dst (%u), %s",
		mstp_frame_source, mstp_frame_destination,
		mstp_frame_type_text(mstp_frame_type));
#else
	ti = proto_tree_add_item(tree, proto_mstp, tvb, offset, 8, ENC_NA);
#endif
	subtree = proto_item_add_subtree(ti, ett_bacnet_mstp);
	proto_tree_add_item(subtree, hf_mstp_preamble_55, tvb,
			offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(subtree, hf_mstp_preamble_FF, tvb,
			offset+1, 1, ENC_LITTLE_ENDIAN);
	dissect_mstp(tvb, pinfo, tree, subtree, offset+2);
	return tvb_captured_length(tvb);
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
		{ &hf_mstp_frame_checksum_status,
			{ "Checksum status", "mstp.checksum.status",
			FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
			NULL, HFILL }
		},
	};

	static gint *ett[] = {
		&ett_bacnet_mstp,
		&ett_bacnet_mstp_checksum
	};

	static ei_register_info ei[] = {
		{ &ei_mstp_frame_pdu_len, { "mstp.len.bad", PI_MALFORMED, PI_ERROR, "Length field value goes past the end of the payload", EXPFILL }},
		{ &ei_mstp_frame_checksum_bad, { "mstp.checksum_bad.expert", PI_CHECKSUM, PI_WARN, "Bad Checksum", EXPFILL }},
	};

	expert_module_t* expert_mstp;

	proto_mstp = proto_register_protocol("BACnet MS/TP",
	    "BACnet MS/TP", "mstp");

	proto_register_field_array(proto_mstp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_mstp = expert_register_protocol(proto_mstp);
	expert_register_field_array(expert_mstp, ei, array_length(ei));

	register_dissector("mstp", dissect_mstp_wtap, proto_mstp);

	subdissector_table = register_dissector_table("mstp.vendor_frame_type",
	    "MSTP Vendor specific Frametypes", proto_mstp, FT_UINT24, BASE_DEC);
	/* Table_type: (Vendor ID << 16) + Frametype */

	mstp_address_type = address_type_dissector_register("AT_MSTP", "BACnet MS/TP Address", mstp_to_str, mstp_str_len, NULL, mstp_col_filter_str, mstp_len, NULL, NULL);
}

void
proto_reg_handoff_mstp(void)
{
	dissector_handle_t mstp_handle;
	dissector_handle_t bacnet_handle;

	mstp_handle = find_dissector("mstp");
	dissector_add_uint("wtap_encap", WTAP_ENCAP_BACNET_MS_TP, mstp_handle);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_BACNET_MS_TP_WITH_PHDR, mstp_handle);

	bacnet_handle = find_dissector("bacnet");

	dissector_add_uint("mstp.vendor_frame_type", (0/*VendorID ASHRAE*/ << 16) + MSTP_BACNET_DATA_EXPECTING_REPLY, bacnet_handle);
	dissector_add_uint("mstp.vendor_frame_type", (0/*VendorID ASHRAE*/ << 16) + MSTP_BACNET_DATA_NOT_EXPECTING_REPLY, bacnet_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
