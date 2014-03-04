/* packet-bvlc.c
 * Routines for BACnet/IP (BVLL, BVLC) dissection
 * Copyright 2001, Hartmut Mueller <hartmut@abmlinux.org>, FH Dortmund
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer,v 1.23
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

#include <epan/prefs.h>
#include <epan/strutil.h>

#include <glib.h>

#include <epan/packet.h>

void proto_register_bvlc(void);
void proto_reg_handoff_bvlc(void);

/* Taken from add-135a (BACnet-IP-standard paper):
 *
 * The default UDP port for both directed messages and broadcasts shall
 * be X'BAC0' and all B/IP devices shall support it. In some cases,
 * e.g., a situation where it is desirable for two groups of BACnet devices
 * to coexist independently on the same IP subnet, the UDP port may be
 * configured locally to a different value without it being considered
 * a violation of this protocol.
 */
static guint global_additional_bvlc_udp_port = 0;

static int proto_bvlc = -1;
static int hf_bvlc_type = -1;
static int hf_bvlc_function = -1;
static int hf_bvlc_length = -1;
static int hf_bvlc_result = -1;
static int hf_bvlc_bdt_ip = -1;
static int hf_bvlc_bdt_mask = -1;
static int hf_bvlc_bdt_port = -1;
static int hf_bvlc_reg_ttl = -1;
static int hf_bvlc_fdt_ip = -1;
static int hf_bvlc_fdt_port = -1;
static int hf_bvlc_fdt_ttl = -1;
static int hf_bvlc_fdt_timeout = -1;
static int hf_bvlc_fwd_ip = -1;
static int hf_bvlc_fwd_port = -1;

static dissector_handle_t data_handle;

static dissector_table_t bvlc_dissector_table;

static const value_string bvlc_function_names[] = {
	{ 0x00, "BVLC-Result", },
	{ 0x01, "Write-Broadcast-Distribution-Table", },
	{ 0x02, "Read-Broadcast-Distribution-Table", },
	{ 0x03, "Read-Broadcast-Distribution-Table-Ack", },
	{ 0x04, "Forwarded-NPDU", },
	{ 0x05, "Register-Foreign-Device", },
	{ 0x06, "Read-Foreign-Device-Table", },
	{ 0x07, "Read-Foreign-Device-Table-Ack", },
	{ 0x08, "Delete-Foreign-Device-Table-Entry", },
	{ 0x09, "Distribute-Broadcast-To-Network", },
	{ 0x0a, "Original-Unicast-NPDU", },
	{ 0x0b, "Original-Broadcast-NPDU" },
	{ 0,    NULL }
};

static const value_string bvlc_result_names[] = {
	{ 0x00, "Successful completion" },
	{ 0x10, "Write-Broadcast-Distribution-Table NAK" },
	{ 0x20, "Read-Broadcast-Distribution-Table NAK" },
	{ 0x30, "Register-Foreign-Device NAK" },
	{ 0x40, "Read-Foreign-Device-Table NAK" },
	{ 0x50, "Delete-Foreign-Device-Table-Entry NAK" },
	{ 0x60, "Distribute-Broadcast-To-Network NAK" },
	{ 0,    NULL }
};

static gint ett_bvlc = -1;
static gint ett_bdt = -1;
static gint ett_fdt = -1;

#define BACNET_IP_ANNEX_J	0x81

static const value_string bvlc_types[] = {
	{ BACNET_IP_ANNEX_J,	"BACnet/IP (Annex J)" },
	{ 0,			NULL }
};

static int
dissect_bvlc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

	proto_item *ti;
	proto_item *ti_bdt;
	proto_item *ti_fdt;
	proto_tree *bvlc_tree;
	proto_tree *bdt_tree; /* Broadcast Distribution Table */
	proto_tree *fdt_tree; /* Foreign Device Table */

	gint offset;
	guint8 bvlc_type;
	guint8 bvlc_function;
	guint16 bvlc_length;
	guint16 packet_length;
	guint npdu_length;
	guint length_remaining;
	guint16 bvlc_result;
	tvbuff_t *next_tvb;

	offset = 0;

	bvlc_type =  tvb_get_guint8(tvb, offset);

	/*
	 * Simple sanity check - make sure the type is one we know about.
	 */
	if (try_val_to_str(bvlc_type, bvlc_types) == NULL)
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BVLC");

	col_set_str(pinfo->cinfo, COL_INFO, "BACnet Virtual Link Control");

	bvlc_function = tvb_get_guint8(tvb, offset+1);
	packet_length = tvb_get_ntohs(tvb, offset+2);
	length_remaining = tvb_reported_length_remaining(tvb, offset);
	if (bvlc_function > 0x08) {
		/*  We have a constant header length of BVLC of 4 in every
		 *  BVLC-packet forewarding an NPDU. Beware: Changes in the
		 *  BACnet-IP-standard may break this.
		 *  At the moment, no functions above 0x0b
		 *  exist (Addendum 135a to ANSI/ASHRAE 135-1995 - BACnet)
		 */
		bvlc_length = 4;
	} else if(bvlc_function == 0x04) {
		/* 4 Bytes + 6 Bytes for B/IP Address of Originating Device */
		bvlc_length = 10;
	} else {
		/*  BVLC-packets with function below 0x09 contain
		 *  routing-level data (e.g. Broadcast Distribution)
		 *  but no NPDU for BACnet, so bvlc_length goes up to the end
		 *  of the captured frame.
		 */
		bvlc_length = packet_length;
	}

	if (tree) {
		if (bvlc_length < 4) {
			proto_tree_add_text(tree, tvb, 2, 2,
				"Bogus length: %d", bvlc_length);
			return tvb_reported_length(tvb);	/* XXX - reject? */
		}
		ti = proto_tree_add_item(tree, proto_bvlc, tvb, 0,
			bvlc_length, ENC_NA);
		bvlc_tree = proto_item_add_subtree(ti, ett_bvlc);
		proto_tree_add_uint(bvlc_tree, hf_bvlc_type, tvb, offset, 1,
			bvlc_type);
		offset ++;
		proto_tree_add_uint(bvlc_tree, hf_bvlc_function, tvb,
			offset, 1, bvlc_function);
		offset ++;
		if (length_remaining != packet_length)
			proto_tree_add_uint_format_value(bvlc_tree, hf_bvlc_length, tvb, offset,
				2, bvlc_length,
				"%d of %d bytes (invalid length - expected %d bytes)",
				bvlc_length, packet_length, length_remaining);
		else
			proto_tree_add_uint_format_value(bvlc_tree, hf_bvlc_length, tvb, offset,
				2, bvlc_length, "%d of %d bytes BACnet packet length",
				bvlc_length, packet_length);
		offset += 2;
		switch (bvlc_function) {
		case 0x00: /* BVLC-Result */
			bvlc_result = tvb_get_ntohs(tvb, offset);
			/* I dont know why the result code is encoded in 4 nibbles,
			 * but only using one: 0x00r0. Shifting left 4 bits.
			 */
			/* We should bitmask the result correctly when we have a
		 	* packet to dissect, see README.developer, 1.6.2, FID */
			proto_tree_add_uint_format_value(bvlc_tree, hf_bvlc_result, tvb,
				offset, 2, bvlc_result,"0x%04x (%s)",
							 bvlc_result,
							 val_to_str_const(bvlc_result,
									  bvlc_result_names,
									  "Unknown"));
			/*offset += 2;*/
			break;
		case 0x01: /* Write-Broadcast-Distribution-Table */
		case 0x03: /* Read-Broadcast-Distribution-Table-Ack */
			/* List of BDT Entries:	N*10-octet */
			ti_bdt = proto_tree_add_item(bvlc_tree, proto_bvlc, tvb,
				offset, bvlc_length-4, ENC_NA);
			bdt_tree = proto_item_add_subtree(ti_bdt, ett_bdt);
			/* List of BDT Entries:	N*10-octet */
			while ((bvlc_length - offset) > 9) {
				proto_tree_add_item(bdt_tree, hf_bvlc_bdt_ip,
					tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(bdt_tree, hf_bvlc_bdt_port,
					tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_item(bdt_tree,
					hf_bvlc_bdt_mask, tvb, offset, 4,
					ENC_NA);
				offset += 4;
			}
			/* We check this if we get a BDT-packet somewhere */
			break;
		case 0x02: /* Read-Broadcast-Distribution-Table */
			/* nothing to do here */
			break;
		case 0x05: /* Register-Foreign-Device */
			/* Time-to-Live	2-octets T, Time-to-Live T, in seconds */
			proto_tree_add_item(bvlc_tree, hf_bvlc_reg_ttl,
				tvb, offset, 2, ENC_BIG_ENDIAN);
			/*offset += 2;*/
			break;
		case 0x06: /* Read-Foreign-Device-Table */
			/* nothing to do here */
			break;
		case 0x07: /* Read-Foreign-Device-Table-Ack */
			/* List of FDT Entries:	N*10-octet */
			/* N indicates the number of entries in the FDT whose
			 * contents are being returned. Each returned entry
			 * consists of the 6-octet B/IP address of the registrant;
			 * the 2-octet Time-to-Live value supplied at the time of
			 * registration; and a 2-octet value representing the
			 * number of seconds remaining before the BBMD will purge
			 * the registrant's FDT entry if no re-registration occurs.
			 */
			ti_fdt = proto_tree_add_item(bvlc_tree, proto_bvlc, tvb,
				offset, bvlc_length -4, ENC_NA);
			fdt_tree = proto_item_add_subtree(ti_fdt, ett_fdt);
			/* List of FDT Entries:	N*10-octet */
			while ((bvlc_length - offset) > 9) {
				proto_tree_add_item(fdt_tree, hf_bvlc_fdt_ip,
					tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(fdt_tree, hf_bvlc_fdt_port,
					tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_item(fdt_tree,
					hf_bvlc_fdt_ttl, tvb, offset, 2,
					ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_item(fdt_tree,
					hf_bvlc_fdt_timeout, tvb, offset, 2,
					ENC_BIG_ENDIAN);
				offset += 2;
			}
			/* We check this if we get a FDT-packet somewhere */
			break;
		case 0x08: /* Delete-Foreign-Device-Table-Entry */
			/* FDT Entry:	6-octets */
			proto_tree_add_item(bvlc_tree, hf_bvlc_fdt_ip,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(bvlc_tree, hf_bvlc_fdt_port,
				tvb, offset, 2, ENC_BIG_ENDIAN);
			/*offset += 2;*/
			break;
			/* We check this if we get a FDT-packet somewhere */
		case 0x04:	/* Forwarded-NPDU
				 * Why is this 0x04? It would have been a better
				 * idea to append all forewarded NPDUs at the
				 * end of the function table in the B/IP-standard!
				 */
			/* proto_tree_add_bytes_format(); */
			proto_tree_add_item(bvlc_tree, hf_bvlc_fwd_ip,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(bvlc_tree, hf_bvlc_fwd_port,
				tvb, offset, 2, ENC_BIG_ENDIAN);
			/*offset += 2;*/
		default:/* Distribute-Broadcast-To-Network
			 * Original-Unicast-NPDU
			 * Original-Broadcast-NPDU
			 * Going to the next dissector...
			 */
			break;
		}

	}
/* Ok, no routing information BVLC packet. Dissect as
 * BACnet NPDU
 */
	npdu_length = packet_length - bvlc_length;
	next_tvb = tvb_new_subset(tvb,bvlc_length,-1,npdu_length);
	/* Code from Guy Harris */
	if (!dissector_try_uint(bvlc_dissector_table,
	    bvlc_function, next_tvb, pinfo, tree)) {
		/* Unknown function - dissect the paylod as data */
		call_dissector(data_handle,next_tvb, pinfo, tree);
	}
	return tvb_reported_length(tvb);
}

void
proto_register_bvlc(void)
{
	static hf_register_info hf[] = {
		{ &hf_bvlc_type,
			{ "Type",           "bvlc.type",
			FT_UINT8, BASE_HEX, VALS(bvlc_types), 0,
			NULL, HFILL }
		},
		{ &hf_bvlc_function,
			{ "Function",           "bvlc.function",
			FT_UINT8, BASE_HEX, VALS(bvlc_function_names), 0,
			"BVLC Function", HFILL }
		},
		{ &hf_bvlc_length,
			{ "BVLC-Length",        "bvlc.length",
			FT_UINT16, BASE_DEC, NULL, 0,
			"Length of BVLC", HFILL }
		},
		/* We should bitmask the result correctly when we have a
		 * packet to dissect */
		{ &hf_bvlc_result,
			{ "Result",           "bvlc.result",
			FT_UINT16, BASE_HEX, NULL, 0,
			"Result Code", HFILL }
		},
		{ &hf_bvlc_bdt_ip,
			{ "IP",           "bvlc.bdt_ip",
			FT_IPv4, BASE_NONE, NULL, 0,
			"BDT IP", HFILL }
		},
		{ &hf_bvlc_bdt_port,
			{ "Port",           "bvlc.bdt_port",
			FT_UINT16, BASE_DEC, NULL, 0,
			"BDT Port", HFILL }
		},
		{ &hf_bvlc_bdt_mask,
			{ "Mask",           "bvlc.bdt_mask",
			FT_BYTES, BASE_NONE, NULL, 0,
			"BDT Broadcast Distribution Mask", HFILL }
		},
		{ &hf_bvlc_reg_ttl,
			{ "TTL",           "bvlc.reg_ttl",
			FT_UINT16, BASE_DEC, NULL, 0,
			"Foreign Device Time To Live", HFILL }
		},
		{ &hf_bvlc_fdt_ip,
			{ "IP",           "bvlc.fdt_ip",
			FT_IPv4, BASE_NONE, NULL, 0,
			"FDT IP", HFILL }
		},
		{ &hf_bvlc_fdt_port,
			{ "Port",           "bvlc.fdt_port",
			FT_UINT16, BASE_DEC, NULL, 0,
			"FDT Port", HFILL }
		},
		{ &hf_bvlc_fdt_ttl,
			{ "TTL",           "bvlc.fdt_ttl",
			FT_UINT16, BASE_DEC, NULL, 0,
			"Foreign Device Time To Live", HFILL }
		},
		{ &hf_bvlc_fdt_timeout,
			{ "Timeout",           "bvlc.fdt_timeout",
			FT_UINT16, BASE_DEC, NULL, 0,
			"Foreign Device Timeout (seconds)", HFILL }
		},
		{ &hf_bvlc_fwd_ip,
			{ "IP",           "bvlc.fwd_ip",
			FT_IPv4, BASE_NONE, NULL, 0,
			"FWD IP", HFILL }
		},
		{ &hf_bvlc_fwd_port,
			{ "Port",           "bvlc.fwd_port",
			FT_UINT16, BASE_DEC, NULL, 0,
			"FWD Port", HFILL }
		},
	};

	static gint *ett[] = {
		&ett_bvlc,
		&ett_bdt,
		&ett_fdt,
	};

	module_t *bvlc_module;

	proto_bvlc = proto_register_protocol("BACnet Virtual Link Control",
	    "BVLC", "bvlc");

	proto_register_field_array(proto_bvlc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	bvlc_module = prefs_register_protocol(proto_bvlc, proto_reg_handoff_bvlc);
	prefs_register_uint_preference(bvlc_module, "additional_udp_port",
					"Additional UDP port", "Set an additional UDP port, "
					"besides the standard X'BAC0' (47808) port.",
					10, &global_additional_bvlc_udp_port);

	new_register_dissector("bvlc", dissect_bvlc, proto_bvlc);

	bvlc_dissector_table = register_dissector_table("bvlc.function",
	    "BVLC Function", FT_UINT8, BASE_HEX);
}

void
proto_reg_handoff_bvlc(void)
{
	static gboolean bvlc_initialized = FALSE;
	static dissector_handle_t bvlc_handle;
	static guint additional_bvlc_udp_port;

	if (!bvlc_initialized)
	{
		bvlc_handle = find_dissector("bvlc");
		dissector_add_uint("udp.port", 0xBAC0, bvlc_handle);
		data_handle = find_dissector("data");
		bvlc_initialized = TRUE;
	}
	else
	{
		if (additional_bvlc_udp_port != 0) {
			dissector_delete_uint("udp.port", additional_bvlc_udp_port, bvlc_handle);
		}
	}

	if (global_additional_bvlc_udp_port != 0) {
		dissector_add_uint("udp.port", global_additional_bvlc_udp_port, bvlc_handle);
	}
	additional_bvlc_udp_port = global_additional_bvlc_udp_port;
}
