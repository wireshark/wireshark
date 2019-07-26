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
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-bacnet.h"

void proto_register_bvlc(void);
void proto_reg_handoff_bvlc(void);

#define BVLC_UDP_PORT 0xBAC0

/* Network Layer Wrapper Control Information */
#define BAC_WRAPPER_CONTROL_NET		0x80
#define BAC_WRAPPER_MSG_ENCRYPED	0x40
#define BAC_WRAPPER_RESERVED		0x20
#define BAC_WRAPPER_AUTHD_PRESENT	0x10
#define BAC_WRAPPER_DO_NOT_UNWRAP	0x08
#define BAC_WRAPPER_DO_NOT_DECRPT	0x04
#define BAC_WRAPPER_NO_TRUST_SRC	0x02
#define BAC_WRAPPER_SECURE_BY_RTR	0x01

static int proto_bvlc = -1;
static int hf_bvlc_type = -1;
static int hf_bvlc_function = -1;
static int hf_bvlc_ipv6_function = -1;
static int hf_bvlc_length = -1;
static int hf_bvlc_result_ip4 = -1;
static int hf_bvlc_result_ip6 = -1;
static int hf_bvlc_bdt_ip = -1;
static int hf_bvlc_bdt_mask = -1;
static int hf_bvlc_bdt_port = -1;
static int hf_bvlc_reg_ttl = -1;
static int hf_bvlc_fdt_ip = -1;
static int hf_bvlc_fdt_ipv6 = -1;
static int hf_bvlc_fdt_port = -1;
static int hf_bvlc_fdt_ttl = -1;
static int hf_bvlc_fdt_timeout = -1;
static int hf_bvlc_fwd_ip = -1;
static int hf_bvlc_fwd_port = -1;
static int hf_bvlc_virt_source = -1;
static int hf_bvlc_virt_dest = -1;
static int hf_bvlc_orig_source_addr = -1;
static int hf_bvlc_orig_source_port = -1;

static dissector_table_t bvlc_dissector_table;
static dissector_table_t bvlc_ipv6_dissector_table;
static dissector_handle_t bvlc_handle = NULL;

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
	{ 0x0c, "Secured-BVLL" },
	{ 0, NULL }
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

static const value_string bvlc_ipv6_function_names[] = {
	{ 0x00, "BVLC-Result", },
	{ 0x01, "Original-Unicast-NPDU", },
	{ 0x02, "Original-Broadcast-NPDU", },
	{ 0x03, "Address-Resolution", },
	{ 0x04, "Forwarded-Address-Resolution", },
	{ 0x05, "Address-Resolution-ACK", },
	{ 0x06, "Virtual-Address-Resolution", },
	{ 0x07, "Virtual-Address-Resolution-ACK", },
	{ 0x08, "Forwarded-NPDU", },
	{ 0x09, "Register-Foreign-Device", },
	{ 0x0A, "Delete-Foreign-Device-Table-Entry", },
	{ 0x0B, "Secure-BVLL", },
	{ 0x0C, "Distribute-Broadcast-To-Network", },
	{ 0, NULL }
};

static const value_string bvlc_ipv6_result_names[] = {
	{ 0x00, "Successful completion" },
	{ 0x30, "Address-Resolution NAK" },
	{ 0x60, "Virtual-Address-Resolution NAK" },
	{ 0x90, "Register-Foreign-Device NAK" },
	{ 0xA0, "Delete-Foreign-Device-Table-Entry NAK" },
	{ 0xC0, "Distribute-Broadcast-To-Network NAK" },
	{ 0, NULL }
};

static gint ett_bvlc = -1;
static gint ett_bdt = -1;
static gint ett_fdt = -1;

#define BACNET_IP_ANNEX_J		0x81
#define BACNET_IPV6_ANNEX_U		0x82

static const value_string bvlc_types[] = {
	{ BACNET_IP_ANNEX_J,	"BACnet/IP (Annex J)" },
	{ BACNET_IPV6_ANNEX_U,	"BACnet/IPV6 (Annex U)" },
	{ 0, NULL }
};

static int
dissect_ipv4_bvlc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
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
	tvbuff_t *next_tvb;

	offset = 0;

	bvlc_type = tvb_get_guint8(tvb, offset);
	bvlc_function = tvb_get_guint8(tvb, offset + 1);
	packet_length = tvb_get_ntohs(tvb, offset + 2);
	length_remaining = tvb_reported_length_remaining(tvb, offset);

	if (bvlc_function > 0x08) {
		/*  We have a constant header length of BVLC of 4 in every
		 *  BVLC-packet forewarding an NPDU. Beware: Changes in the
		 *  BACnet-IP-standard may break this.
		 */
		bvlc_length = 4;
	} else if (bvlc_function == 0x04) {
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

	if (bvlc_length < 4 || bvlc_length > packet_length) {
		return 0;	/* reject */
	}

	ti = proto_tree_add_item(tree, proto_bvlc, tvb, 0, bvlc_length, ENC_NA);
	bvlc_tree = proto_item_add_subtree(ti, ett_bvlc);
	proto_tree_add_uint(bvlc_tree, hf_bvlc_type, tvb, offset, 1,
		bvlc_type);
	offset++;
	proto_tree_add_uint(bvlc_tree, hf_bvlc_function, tvb,
		offset, 1, bvlc_function);
	offset++;
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
		/* I don't know why the result code is encoded in 4 nibbles,
		 * but only using one: 0x00r0. Shifting left 4 bits.
		 */
		/* We should bitmask the result correctly when we have a
		 * packet to dissect, see README.developer, 1.6.2, FID */
		proto_tree_add_item(bvlc_tree, hf_bvlc_result_ip4, tvb,
			offset, 2, ENC_BIG_ENDIAN);
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
	case 0x0C: /* Secure-BVLL */
		offset = bacnet_dissect_sec_wrapper(tvb, pinfo, tree, offset, NULL);
		if (offset < 0) {
			call_data_dissector(tvb, pinfo, tree);
			return tvb_captured_length(tvb);
		}
		dissect_ipv4_bvlc(tvb, pinfo, tree, data);
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
		break;
	default:
		/* Distribute-Broadcast-To-Network
		 * Original-Unicast-NPDU
		 * Original-Broadcast-NPDU
		 * Going to the next dissector...
		 */
		break;
	}

	/* Ok, no routing information BVLC packet. Dissect as
	 * BACnet NPDU
	 */
	npdu_length = packet_length - bvlc_length;
	next_tvb = tvb_new_subset_length_caplen(tvb, bvlc_length, -1, npdu_length);
	/* Code from Guy Harris */
	if (!dissector_try_uint(bvlc_dissector_table,
		bvlc_function, next_tvb, pinfo, tree)) {
		/* Unknown function - dissect the paylod as data */
		call_data_dissector(next_tvb, pinfo, tree);
	}
	return tvb_reported_length(tvb);
}

static int
dissect_ipv6_bvlc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *ti;
	proto_tree *bvlc_tree;

	gint offset;
	guint8 bvlc_type;
	guint8 bvlc_function;
	guint16 bvlc_length = 0;
	guint16 packet_length;
	guint npdu_length;
	guint length_remaining;
	tvbuff_t *next_tvb;

	offset = 0;

	bvlc_type = tvb_get_guint8(tvb, offset);
	bvlc_function = tvb_get_guint8(tvb, offset + 1);
	packet_length = tvb_get_ntohs(tvb, offset + 2);
	length_remaining = tvb_reported_length_remaining(tvb, offset);

	switch (bvlc_function) {
	case 0x00:
	case 0x09:
		bvlc_length = 9;
		break;
	case 0x01:
		bvlc_length = 10;
		break;
	case 0x02:
	case 0x06:
	case 0x0C:
		bvlc_length = 7;
		break;
	case 0x03:
	case 0x05:
	case 0x07:
		bvlc_length = 10;
		break;
	case 0x04:
		bvlc_length = 28;
		break;
	case 0x08:
	case 0x0A:
		bvlc_length = 25;
		break;
	case 0x0B:
		bvlc_length = 4;
		break;
	default:
		break;
	}

	if (bvlc_length > packet_length) {
		return 0;	/* reject */
	}

	ti = proto_tree_add_item(tree, proto_bvlc, tvb, 0,
		bvlc_length, ENC_NA);
	bvlc_tree = proto_item_add_subtree(ti, ett_bvlc);
	/* add the BVLC type */
	proto_tree_add_uint(bvlc_tree, hf_bvlc_type, tvb, offset, 1,
		bvlc_type);
	offset++;
	/* add the BVLC function */
	proto_tree_add_uint(bvlc_tree, hf_bvlc_ipv6_function, tvb,
		offset, 1, bvlc_function);
	offset++;
	/* add the length information */
	if (length_remaining != packet_length)
		proto_tree_add_uint_format_value(bvlc_tree, hf_bvlc_length, tvb, offset,
			2, bvlc_length,
			"%d of %d bytes (invalid length - expected %d bytes)",
			bvlc_length, packet_length, length_remaining);
	else
		proto_tree_add_uint_format_value(bvlc_tree, hf_bvlc_length, tvb, offset,
			2, bvlc_length,
			"%d of %d bytes BACnet packet length",
			bvlc_length, packet_length);
	offset += 2;

	/* add the optional present virtual source address */
	if (bvlc_function != 0x0B) {
		proto_tree_add_item(bvlc_tree, hf_bvlc_virt_source, tvb, offset,
			3, ENC_BIG_ENDIAN);
		offset += 3;
	}

	/* handle additional function parameters */
	switch (bvlc_function) {
	case 0x00: /* BVLC-Result */
		proto_tree_add_item(bvlc_tree, hf_bvlc_result_ip6, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		break;
	case 0x01: /* Original-Unicast-NPDU */
	case 0x03: /* Address-Resolution */
	case 0x05: /* Address-Resolution-ACK */
	case 0x07: /* Virtual-Address-Resolution-ACK */
		proto_tree_add_item(bvlc_tree, hf_bvlc_virt_dest, tvb, offset,
			3, ENC_BIG_ENDIAN);
		offset += 3;
		break;
	case 0x04: /* Forwarded-Address-Resolution */
	case 0x08: /* Forwarded-NPDU */
		proto_tree_add_item(bvlc_tree, hf_bvlc_virt_dest, tvb, offset,
			3, ENC_BIG_ENDIAN);
		offset += 3;
		proto_tree_add_item(bvlc_tree, hf_bvlc_orig_source_addr,
			tvb, offset, 16, ENC_NA);
		offset += 16;
		proto_tree_add_item(bvlc_tree, hf_bvlc_orig_source_port,
			tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		break;
	case 0x06: /* Virtual-Address-Resolution */
		break;
	case 0x09: /* Register-Foreign-Device */
		proto_tree_add_item(bvlc_tree, hf_bvlc_reg_ttl,
			tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		break;
	case 0x0A: /* Delete-Foreign-Device-Table-Entry */
		proto_tree_add_item(bvlc_tree, hf_bvlc_fdt_ipv6,
			tvb, offset, 16, ENC_NA);
		offset += 16;
		proto_tree_add_item(bvlc_tree, hf_bvlc_fdt_port,
			tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		break;
	case 0x0B: /* Secure-BVLL */
		offset = bacnet_dissect_sec_wrapper(tvb, pinfo, tree, offset, NULL);
		if (offset < 0) {
			call_data_dissector(tvb, pinfo, tree);
			return tvb_captured_length(tvb);
		}
		dissect_ipv6_bvlc(tvb, pinfo, tree, data);
		break;
	case 0x02: /* Original-Broadcast-NPDU */
	case 0x0c: /* Distribute-Broadcast-To-Network */
	default:
		/*
		 * Going to the next dissector...
		 */
		break;
	}

	/* Ok, no routing information BVLC packet. Dissect as
	 * BACnet NPDU
	 */
	npdu_length = packet_length - offset;
	next_tvb = tvb_new_subset_length_caplen(tvb, offset, -1, npdu_length);
	/* Code from Guy Harris */
	if ( ! dissector_try_uint(bvlc_ipv6_dissector_table,
		bvlc_function, next_tvb, pinfo, tree)) {
		/* Unknown function - dissect the paylod as data */
		call_data_dissector(next_tvb, pinfo, tree);
	}

	return tvb_reported_length(tvb);
}

static int
dissect_bvlc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	guint8 bvlc_type;
	guint ret = 0;

	bvlc_type = tvb_get_guint8(tvb, 0);

	/*
	 * Simple sanity check - make sure the type is one we know about.
	 */
	if (try_val_to_str(bvlc_type, bvlc_types) == NULL)
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BVLC");
	col_set_str(pinfo->cinfo, COL_INFO, "BACnet Virtual Link Control");

	switch (bvlc_type)
	{
	case BACNET_IP_ANNEX_J:
		ret = dissect_ipv4_bvlc(tvb, pinfo, tree, data);
		break;
	case BACNET_IPV6_ANNEX_U:
		ret = dissect_ipv6_bvlc(tvb, pinfo, tree, data);
		break;
	}

	return ret;
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
		{ &hf_bvlc_ipv6_function,
			{ "Function",           "bvlc.function_ipv6",
			FT_UINT8, BASE_HEX, VALS(bvlc_ipv6_function_names), 0,
			"BVLC Function IPV6", HFILL }
		},
		{ &hf_bvlc_length,
			{ "BVLC-Length",        "bvlc.length",
			FT_UINT16, BASE_DEC, NULL, 0,
			"Length of BVLC", HFILL }
		},
		{ &hf_bvlc_virt_source,
			{ "BVLC-Virtual-Source", "bvlc.virtual_source",
			FT_UINT24, BASE_DEC_HEX, NULL, 0,
			"Virtual source address of BVLC", HFILL }
		},
		{ &hf_bvlc_virt_dest,
			{ "BVLC-Virtual-Destination", "bvlc.virtual_dest",
			FT_UINT24, BASE_DEC_HEX, NULL, 0,
			"Virtual destination address of BVLC", HFILL }
		},
		{ &hf_bvlc_result_ip4,
			{ "Result",           "bvlc.result",
			FT_UINT16, BASE_HEX, VALS(bvlc_result_names), 0,
			"Result Code", HFILL }
		},
		{ &hf_bvlc_result_ip6,
			{ "Result",           "bvlc.result",
			FT_UINT16, BASE_HEX, VALS(bvlc_ipv6_result_names), 0,
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
		{ &hf_bvlc_fdt_ipv6,
			{ "IP",           "bvlc.fdt_ipv6",
			FT_IPv6, BASE_NONE, NULL, 0,
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
		{ &hf_bvlc_orig_source_addr,
			{ "IP",             "bvlc.orig_source_addr",
			FT_IPv6, BASE_NONE, NULL, 0,
			"ORIG IP", HFILL }
		},
		{ &hf_bvlc_orig_source_port,
			{ "Port",           "bvlc.orig_source_port",
			FT_UINT16, BASE_DEC, NULL, 0,
			"ORIG Port", HFILL }
		},
	};

	static gint *ett[] = {
		&ett_bvlc,
		&ett_bdt,
		&ett_fdt,
	};


	proto_bvlc = proto_register_protocol("BACnet Virtual Link Control", "BVLC", "bvlc");

	proto_register_field_array(proto_bvlc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	bvlc_handle = register_dissector("bvlc", dissect_bvlc, proto_bvlc);

	bvlc_dissector_table = register_dissector_table("bvlc.function", "BVLC Function", proto_bvlc, FT_UINT8, BASE_HEX);
	bvlc_ipv6_dissector_table = register_dissector_table("bvlc.function_ipv6", "BVLC Function IPV6", proto_bvlc, FT_UINT8, BASE_HEX);
}

void
proto_reg_handoff_bvlc(void)
{
	dissector_add_uint_with_preference("udp.port", BVLC_UDP_PORT, bvlc_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
