/* packet-mint.c
 * Routines for the disassembly of the Chantry/HiPath AP-Controller
 * tunneling protocol.
 *
 * $Id$
 *
 * Copyright 2013 Joerg Mayer (see AUTHORS file)
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

/*
 * Motorola/Symbol WLAN proprietary protocol
 * http://www.awimobility.com/s.nl/ctype.KB/it.I/id.7761/KB.81/.f
 * looks like a mixture of lwapp/capwap and is-is/ospf
 */

/* We don't want the tranported data to pollute the output until
 * we know how to correctly determine the packet type and length
 */
#define MINT_DEVELOPMENT 1

#define NEW_PROTO_TREE_API 1

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/wmem/wmem.h>
#include <epan/expert.h>
#include <epan/show_exception.h>

#define PROTO_SHORT_NAME "MiNT"
#define PROTO_LONG_NAME "Media indepentend Network Transport"

/* 0x8783 ETHERTYPE_MINT */
/* 0x6000 */
#define PORT_MINT_CONTROL_TUNNEL	24576
/* 0x6001 */
#define PORT_MINT_DATA_TUNNEL		24577

static dissector_handle_t eth_handle;

/* ett handles */
static int ett_mint_ethshim = -1;
static int ett_mint = -1;
static int ett_mint_header = -1;
static int ett_mint_ctrl = -1;
static int ett_mint_data = -1;
static int ett_mint_eth = -1;

static dissector_handle_t mint_control_handle;
static dissector_handle_t mint_data_handle;
static dissector_handle_t mint_eth_handle;

typedef enum {
	MINT_TYPE_DATA_UC   = 0x01,
	MINT_TYPE_DATA_BCMC = 0x02,
	MINT_TYPE_CTRL_0x0c = 0x0c,
	MINT_TYPE_CTRL_0x0e = 0x0e,
	MINT_TYPE_CTRL_0x1e = 0x1e,
	MINT_TYPE_ETH_0x22  = 0x22
} mint_packettype_t;

static const value_string mint_packettype_vals[] = {
	{ MINT_TYPE_DATA_UC,	"Unicast data"},
	{ MINT_TYPE_DATA_BCMC,	"BC/MC data"},
	{ MINT_TYPE_CTRL_0x0c,	"Ctrl_0x0c"},
	{ MINT_TYPE_CTRL_0x0e,	"Ctrl_0x0e"},
	{ MINT_TYPE_CTRL_0x1e,	"Ctrl_0x1e"},
	{ MINT_TYPE_ETH_0x22,	"Eth_0x22"},

	{ 0,    NULL }
};

/* hfi elements */
#define MINT_HF_INIT HFI_INIT(proto_mint)
static header_field_info *hfi_mint = NULL;
/* MiNT Eth Shim */
static header_field_info hfi_mint_ethshim MINT_HF_INIT =
	{ "MiNT Ethernet Shim",    "mint.ethshim", FT_PROTOCOL, BASE_NONE, NULL,
		0x0, NULL, HFILL };

static header_field_info hfi_mint_ethshim_unknown MINT_HF_INIT =
	{ "Unknown",	"mint.ethshim.unknown", FT_BYTES, BASE_NONE, NULL,
		0x0, NULL, HFILL };

static header_field_info hfi_mint_ethshim_length MINT_HF_INIT =
	{ "Length",	"mint.ethshim.length", FT_UINT16, BASE_DEC, NULL,
		0x0, NULL, HFILL };

/* MiNT common */
static header_field_info hfi_mint_header MINT_HF_INIT =
	{ "Header",    "mint.header", FT_PROTOCOL, BASE_NONE, NULL,
		0x0, NULL, HFILL };

static header_field_info hfi_mint_header_unknown1 MINT_HF_INIT =
	{ "HdrUnk1",	"mint.header.unknown1", FT_BYTES, BASE_NONE, NULL,
		0x0, NULL, HFILL };

static header_field_info hfi_mint_header_srcid MINT_HF_INIT =
	{ "Src MiNT ID",	"mint.header.srcid", FT_BYTES, BASE_NONE, NULL,
		0x0, NULL, HFILL };

static header_field_info hfi_mint_header_dstid MINT_HF_INIT =
	{ "Dst MiNT ID",	"mint.header.dstid", FT_BYTES, BASE_NONE, NULL,
		0x0, NULL, HFILL };

static header_field_info hfi_mint_header_srcdatatype MINT_HF_INIT =
	{ "Src type",	"mint.header.srctype", FT_UINT16, BASE_DEC, VALS(mint_packettype_vals),
		0x0, NULL, HFILL };

static header_field_info hfi_mint_header_dstdatatype MINT_HF_INIT =
	{ "Dst type",	"mint.header.dsttype", FT_UINT16, BASE_DEC, VALS(mint_packettype_vals),
		0x0, NULL, HFILL };

/* MiNT Data */
static header_field_info hfi_mint_data MINT_HF_INIT =
	{ "Data Frame",    "mint.data", FT_PROTOCOL, BASE_NONE, NULL,
		0x0, NULL, HFILL };

static header_field_info hfi_mint_data_vlan MINT_HF_INIT =
	{ "Data VLAN",	"mint.data.vlan", FT_UINT16, BASE_DEC, NULL,
		0x0, NULL, HFILL };

static header_field_info hfi_mint_data_seqno MINT_HF_INIT =
	{ "Seqence Number",	"mint.data.seqno", FT_UINT32, BASE_DEC, NULL,
		0x0, NULL, HFILL };

static header_field_info hfi_mint_data_unknown1 MINT_HF_INIT =
	{ "DataUnk1",	"mint.data.unknown1", FT_BYTES, BASE_NONE, NULL,
		0x0, NULL, HFILL };

/* MiNT Control */
static header_field_info hfi_mint_control MINT_HF_INIT =
	{ "Control Frame",    "mint.control", FT_PROTOCOL, BASE_NONE, NULL,
		0x0, NULL, HFILL };

static header_field_info hfi_mint_control_unknown1 MINT_HF_INIT =
	{ "CtrlUnk1",	"mint.control.unknown1", FT_BYTES, BASE_NONE, NULL,
		0x0, NULL, HFILL };

/* MiNT Eth */
static header_field_info hfi_mint_eth MINT_HF_INIT =
	{ "Ethernet Frame",    "mint.eth", FT_PROTOCOL, BASE_NONE, NULL,
		0x0, NULL, HFILL };

static header_field_info hfi_mint_eth_unknown1 MINT_HF_INIT =
	{ "EthUnk1",	"mint.eth.unknown1", FT_BYTES, BASE_NONE, NULL,
		0x0, NULL, HFILL };
/* End hfi elements */

static int
dissect_eth_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *mint_tree,
	volatile guint32 offset, guint32 length)
{
	tvbuff_t *eth_tvb;

#ifdef MINT_DEVELOPMENT
        col_set_writable(pinfo->cinfo, FALSE);
#endif

	eth_tvb = tvb_new_subset(tvb, offset, length, length);
	/* Continue after Ethernet dissection errors */
	TRY {
		call_dissector(eth_handle, eth_tvb, pinfo, mint_tree);
	} CATCH_NONFATAL_ERRORS {
		show_exception(eth_tvb, pinfo, mint_tree, EXCEPT_CODE, GET_MESSAGE);
	} ENDTRY;
	offset += length;

#ifdef MINT_DEVELOPMENT
        col_set_writable(pinfo->cinfo, TRUE);
#endif
	return offset;
}

static int
dissect_mint_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	guint32 offset, guint32 packet_length, guint received_via)
{
	proto_item *ti;
	proto_tree *mint_tree = NULL;
	proto_tree *mint_header_tree = NULL;
	proto_tree *mint_data_tree = NULL;
	proto_tree *mint_ctrl_tree = NULL;
	proto_tree *mint_eth_tree = NULL;
	guint16 bytes_remaining;
	guint16 packet_type;

	if (!tree)
		return packet_length;

	packet_type = tvb_get_ntohs(tvb, offset + 12);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_SHORT_NAME);
	col_add_str(pinfo->cinfo, COL_INFO, val_to_str(packet_type,
		mint_packettype_vals, "Type 0x%02x"));

	ti = proto_tree_add_item(tree, hfi_mint, tvb,
		offset, packet_length, ENC_NA);
	mint_tree = proto_item_add_subtree(ti, ett_mint);

	ti = proto_tree_add_item(mint_tree, &hfi_mint_header, tvb,
		offset, 16, ENC_NA);
	mint_header_tree = proto_item_add_subtree(ti, ett_mint_header);

	/* MiNT header */
	proto_tree_add_item(mint_header_tree, &hfi_mint_header_unknown1, tvb,
		offset, 4, ENC_NA);
	offset += 4;
	proto_tree_add_item(mint_header_tree, &hfi_mint_header_dstid, tvb,
		offset, 4, ENC_NA);
	offset += 4;
	proto_tree_add_item(mint_header_tree, &hfi_mint_header_srcid, tvb,
		offset, 4, ENC_NA);
	offset += 4;
	proto_tree_add_item(mint_header_tree, &hfi_mint_header_dstdatatype, tvb,
		offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(mint_header_tree, &hfi_mint_header_srcdatatype, tvb,
		offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	/* FIXME: This is probably not the right way to determine the packet type.
	 *	  It's more likely something in mint_header_unknown1 but I haven't
         *        found out what. */
	switch(packet_type) {
	case MINT_TYPE_DATA_UC:
		ti = proto_tree_add_item(mint_tree, &hfi_mint_data, tvb,
			offset, packet_length - 16, ENC_NA);
		mint_data_tree = proto_item_add_subtree(ti, ett_mint_data);
		proto_tree_add_item(mint_data_tree, &hfi_mint_data_unknown1, tvb,
			offset, 2, ENC_NA);
		offset += 2;
		/* Transported user frame */
		if (offset < packet_length)
			offset += dissect_eth_frame(tvb, pinfo, tree,
				offset, packet_length - offset);
		break;
	case MINT_TYPE_DATA_BCMC:
		ti = proto_tree_add_item(mint_tree, &hfi_mint_data, tvb,
			offset, packet_length - 16, ENC_NA);
		mint_data_tree = proto_item_add_subtree(ti, ett_mint_data);
		/* Decode as vlan only for now. To be verified against a capture
		 * with CoS != 0 */
		proto_tree_add_item(mint_data_tree, &hfi_mint_data_vlan, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(mint_data_tree, &hfi_mint_data_seqno, tvb,
			offset, 4, ENC_NA);
		offset += 4;
		proto_tree_add_item(mint_data_tree, &hfi_mint_data_unknown1, tvb,
			offset, 4, ENC_NA);
		offset += 4;
		/* Transported user frame */
		if (offset < packet_length)
			offset += dissect_eth_frame(tvb, pinfo, tree,
				offset, packet_length - offset);
		break;
        case MINT_TYPE_CTRL_0x0c:
        case MINT_TYPE_CTRL_0x0e:
        case MINT_TYPE_CTRL_0x1e:
		ti = proto_tree_add_item(mint_tree, &hfi_mint_control, tvb,
			offset, packet_length - 16, ENC_NA);
		mint_ctrl_tree = proto_item_add_subtree(ti, ett_mint_ctrl);
		bytes_remaining = packet_length - offset;
		proto_tree_add_item(mint_ctrl_tree, &hfi_mint_control_unknown1, tvb,
			offset, bytes_remaining, ENC_NA);
		offset += bytes_remaining;
		break;
        case MINT_TYPE_ETH_0x22:
		ti = proto_tree_add_item(mint_tree, &hfi_mint_eth, tvb,
			offset, packet_length - 16, ENC_NA);
		mint_eth_tree = proto_item_add_subtree(ti, ett_mint_eth);
		bytes_remaining = packet_length - offset;
		proto_tree_add_item(mint_eth_tree, &hfi_mint_eth_unknown1, tvb,
			offset, bytes_remaining, ENC_NA);
		offset += bytes_remaining;
		break;
	default:
		bytes_remaining = packet_length - offset;
		switch(received_via) {
		case PORT_MINT_CONTROL_TUNNEL:
			proto_tree_add_item(mint_tree, &hfi_mint_control_unknown1, tvb,
				offset, bytes_remaining, ENC_NA);
			break;
		case PORT_MINT_DATA_TUNNEL:
			proto_tree_add_item(mint_tree, &hfi_mint_data_unknown1, tvb,
				offset, bytes_remaining, ENC_NA);
			break;
		case ETHERTYPE_MINT:
			proto_tree_add_item(mint_tree, &hfi_mint_eth_unknown1, tvb,
				offset, bytes_remaining, ENC_NA);
			break;
		default:
			DISSECTOR_ASSERT_NOT_REACHED();
		}
		offset += bytes_remaining;
		break;
	}
#if defined MINT_DEVELOPMENT
	/* tree_expanded_set(ett_mint, TRUE); */
	tree_expanded_set(ett_mint_header, TRUE);
	tree_expanded_set(ett_mint_ctrl, TRUE);
	tree_expanded_set(ett_mint_data, TRUE);
	tree_expanded_set(ett_mint_eth, TRUE);
#endif
	return offset;
}

static int
dissect_mint_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint32 offset = 0;
	guint32 packet_length = tvb_length_remaining(tvb, 0);

	offset += dissect_mint_common(tvb, pinfo, tree, 0, packet_length,
		PORT_MINT_CONTROL_TUNNEL);

	return offset;
}

static int
dissect_mint_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint32 offset = 0;
	guint32 packet_length = tvb_length_remaining(tvb, 0);

	offset += dissect_mint_common(tvb, pinfo, tree, 0, packet_length,
		PORT_MINT_DATA_TUNNEL);

	return offset;
}

static int
dissect_mint_eth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *mint_ethshim_tree = NULL;
	guint32 offset = 0;
	guint32 packet_length;

	ti = proto_tree_add_item(tree, &hfi_mint_ethshim, tvb,
		offset, 4, ENC_NA);
	mint_ethshim_tree = proto_item_add_subtree(ti, ett_mint_ethshim);

	proto_tree_add_item(mint_ethshim_tree, &hfi_mint_ethshim_unknown, tvb,
		offset, 2, ENC_NA);
	offset += 2;
	proto_tree_add_item(mint_ethshim_tree, &hfi_mint_ethshim_length, tvb,
		offset, 2, ENC_BIG_ENDIAN);
	packet_length = tvb_get_ntohs(tvb, offset) + 4;
	offset += 2;

	offset += dissect_mint_common(tvb, pinfo, tree, 4, packet_length, ETHERTYPE_MINT);

	return offset;
}

static gboolean
test_mint_control(tvbuff_t *tvb _U_)
{
#if 0
	/* Minimum of 8 bytes, first byte (version) has value of 3 */
	if ( tvb_length(tvb) < 8
		    || tvb_get_guint8(tvb, 0) != 3
		    /* || tvb_get_guint8(tvb, 2) != 0
		    || tvb_get_ntohs(tvb, 6) > tvb_reported_length(tvb) */
	) {
		return FALSE;
	}
#endif
	return TRUE;
}

static gboolean
test_mint_data(tvbuff_t *tvb _U_)
{
#if 0
	/* Minimum of 8 bytes, first byte (version) has value of 3 */
	if ( tvb_length(tvb) < 8
		    || tvb_get_guint8(tvb, 0) != 3
		    /* || tvb_get_guint8(tvb, 2) != 0
		    || tvb_get_ntohs(tvb, 6) > tvb_reported_length(tvb) */
	) {
		return FALSE;
	}
#endif
	return TRUE;
}

static gboolean
test_mint_eth(tvbuff_t *tvb _U_)
{
#if 0
	/* Minimum of 8 bytes, first byte (version) has value of 3 */
	if ( tvb_length(tvb) < 8
		    || tvb_get_guint8(tvb, 0) != 3
		    /* || tvb_get_guint8(tvb, 2) != 0
		    || tvb_get_ntohs(tvb, 6) > tvb_reported_length(tvb) */
	) {
		return FALSE;
	}
#endif
	return TRUE;
}

static int
dissect_mint_control_static(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	if ( !test_mint_control(tvb) ) {
		return 0;
	}
	return dissect_mint_control(tvb, pinfo, tree);
}

static int
dissect_mint_data_static(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	if ( !test_mint_data(tvb) ) {
		return 0;
	}
	return dissect_mint_data(tvb, pinfo, tree);
}

static int
dissect_mint_eth_static(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	if ( !test_mint_eth(tvb) ) {
		return 0;
	}
	return dissect_mint_eth(tvb, pinfo, tree);
}

void
proto_register_mint(void)
{
	static header_field_info *hfi[] = {

	/* MiNT Eth Shim */
		&hfi_mint_ethshim,
		&hfi_mint_ethshim_unknown,
		&hfi_mint_ethshim_length,
	/* MiNT common */
		&hfi_mint_header,
		&hfi_mint_header_unknown1,
		&hfi_mint_header_srcid,
		&hfi_mint_header_dstid,
		&hfi_mint_header_srcdatatype,
		&hfi_mint_header_dstdatatype,
	/* MiNT Control */
		&hfi_mint_control,
		&hfi_mint_control_unknown1,
	/* MiNT Data */
		&hfi_mint_data,
		&hfi_mint_data_vlan,
		&hfi_mint_data_seqno,
		&hfi_mint_data_unknown1,
	/* MiNT Eth */
		&hfi_mint_eth,
		&hfi_mint_eth_unknown1,
	};
	static gint *ett[] = {
		&ett_mint_ethshim,
		&ett_mint,
		&ett_mint_header,
		&ett_mint_ctrl,
		&ett_mint_data,
		&ett_mint_eth,
	};

	int proto_mint;

	proto_mint = proto_register_protocol(PROTO_LONG_NAME, PROTO_SHORT_NAME, "mint");
	hfi_mint = proto_registrar_get_nth(proto_mint);
	proto_register_fields(proto_mint, hfi, array_length(hfi));
	proto_register_subtree_array(ett, array_length(ett));

	mint_control_handle = new_create_dissector_handle(dissect_mint_control_static, proto_mint);
	mint_data_handle = new_create_dissector_handle(dissect_mint_data_static, proto_mint);
	mint_eth_handle = new_create_dissector_handle(dissect_mint_eth_static, proto_mint);
}

void
proto_reg_handoff_mint(void)
{
	dissector_add_uint("udp.port", PORT_MINT_CONTROL_TUNNEL, mint_control_handle);
	dissector_add_uint("udp.port", PORT_MINT_DATA_TUNNEL, mint_data_handle);
	dissector_add_uint("ethertype", ETHERTYPE_MINT, mint_eth_handle);

	eth_handle = find_dissector("eth_withoutfcs");
}

