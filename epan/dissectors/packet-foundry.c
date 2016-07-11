/* packet-foundry.c
 * Routines for the disassembly of Foundry LLC messages (currently
 * Foundry Discovery Protocol - FDP only)
 *
 * Copyright 2012 Joerg Mayer (see AUTHORS file)
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
#include <epan/expert.h>
#include <epan/strutil.h>
#include "packet-llc.h"
#include <epan/oui.h>

void proto_register_fdp(void);
void proto_reg_handoff_fdp(void);

static int hf_llc_foundry_pid = -1;

static int proto_fdp = -1;
/* FDP header */
static int hf_fdp_version = -1;
static int hf_fdp_holdtime = -1;
static int hf_fdp_checksum = -1;
/* TLV header */
static int hf_fdp_tlv_type = -1;
static int hf_fdp_tlv_length = -1;
/* Unknown element */
static int hf_fdp_unknown = -1;
static int hf_fdp_unknown_data = -1;
/* Port Tag element */
static int hf_fdp_tag = -1;
static int hf_fdp_tag_native = -1;
static int hf_fdp_tag_type = -1;
static int hf_fdp_tag_unknown = -1;
/* VLAN Bitmap */
static int hf_fdp_vlanmap = -1;
static int hf_fdp_vlanmap_vlan = -1;
/* String element */
static int hf_fdp_string = -1;
static int hf_fdp_string_data = -1;
static int hf_fdp_string_text = -1;
/* Net? element */
static int hf_fdp_net = -1;
static int hf_fdp_net_unknown = -1;
static int hf_fdp_net_ip = -1;
static int hf_fdp_net_iplength = -1;

static gint ett_fdp = -1;
static gint ett_fdp_tlv_header = -1;
static gint ett_fdp_unknown = -1;
static gint ett_fdp_string = -1;
static gint ett_fdp_net = -1;
static gint ett_fdp_tag = -1;
static gint ett_fdp_vlanmap = -1;

static expert_field ei_fdp_tlv_length = EI_INIT;

#define PROTO_SHORT_NAME "FDP"
#define PROTO_LONG_NAME "Foundry Discovery Protocol"

static const value_string foundry_pid_vals[] = {
	{ 0x2000,	"FDP" },

	{ 0,		NULL }
};

typedef enum {
	FDP_TYPE_NAME = 1,
	FDP_TYPE_NET = 2,
	FDP_TYPE_PORT = 3,
	FDP_TYPE_CAPABILITIES = 4,
	FDP_TYPE_VERSION = 5,
	FDP_TYPE_MODEL = 6,
	FDP_TYPE_VLANMAP = 0x0101,
	FDP_TYPE_TAG = 0x0102
} fdp_type_t;

static const value_string fdp_type_vals[] = {
	{ FDP_TYPE_NAME,		"DeviceID"},
	{ FDP_TYPE_NET,			"Net?"},
	{ FDP_TYPE_PORT,		"Interface"},
	{ FDP_TYPE_CAPABILITIES,	"Capabilities"},
	{ FDP_TYPE_VERSION,		"Version"},
	{ FDP_TYPE_MODEL,		"Platform"},
	{ FDP_TYPE_VLANMAP,		"VLAN-Bitmap"},
	{ FDP_TYPE_TAG,			"Tagging-Info"},

	{ 0,    NULL }
};

static int
dissect_tlv_header(tvbuff_t *tvb, packet_info *pinfo _U_, int offset, int length _U_, proto_tree *tree)
{
	proto_tree	*tlv_tree;
	guint16		tlv_type;
	guint16		tlv_length;

	tlv_type = tvb_get_ntohs(tvb, offset);
	tlv_length = tvb_get_ntohs(tvb, offset + 2);

	tlv_tree = proto_tree_add_subtree_format(tree, tvb, offset, 4,
		ett_fdp_tlv_header, NULL, "Length %d, type %d = %s",
		tlv_length, tlv_type,
		val_to_str(tlv_type, fdp_type_vals, "Unknown (%d)"));

	proto_tree_add_uint(tlv_tree, hf_fdp_tlv_type, tvb, offset, 2, tlv_type);
	offset += 2;

	proto_tree_add_uint(tlv_tree, hf_fdp_tlv_length, tvb, offset, 2, tlv_length);
	offset += 2;

	return offset;
}

static int
dissect_string_tlv(tvbuff_t *tvb, packet_info *pinfo, int offset, int length, proto_tree *tree, const char* type_string)
{
	proto_item	*string_item;
	proto_tree	*string_tree;
	const guint8	*string_value;

	string_item = proto_tree_add_protocol_format(tree, hf_fdp_string,
		tvb, offset, length, "%s", type_string);

	string_tree = proto_item_add_subtree(string_item, ett_fdp_string);

	dissect_tlv_header(tvb, pinfo, offset, 4, string_tree);
	offset += 4;
	length -= 4;

	proto_tree_add_item(string_tree, hf_fdp_string_data, tvb, offset, length, ENC_NA);
	proto_tree_add_item_ret_string(string_tree, hf_fdp_string_text, tvb, offset, length, ENC_ASCII|ENC_NA, wmem_packet_scope(), &string_value);
	proto_item_append_text(string_item, ": \"%s\"",
		format_text(string_value, strlen(string_value)));

	return offset;
}

static void
dissect_net_tlv(tvbuff_t *tvb, packet_info *pinfo, int offset, int length, proto_tree *tree)
{
	proto_item	*net_item;
	proto_tree	*net_tree;

	net_item = proto_tree_add_protocol_format(tree, hf_fdp_net,
		tvb, offset, length, "Net?");

	net_tree = proto_item_add_subtree(net_item, ett_fdp_net);

	dissect_tlv_header(tvb, pinfo, offset, 4, net_tree);
	offset += 4;
	length -= 4;

	proto_tree_add_item(net_tree, hf_fdp_net_unknown, tvb, offset, 7, ENC_NA);
	offset += 7;
	length -= 7;

	/* Length of IP address block in bytes */
	proto_tree_add_item(net_tree, hf_fdp_net_iplength, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	while (length >= 4) {
		proto_tree_add_item(net_tree, hf_fdp_net_ip, tvb, offset, 4, ENC_NA);
		offset += 4;
		length -= 4;
	}
}

static void
dissect_vlanmap_tlv(tvbuff_t *tvb, packet_info *pinfo, int offset, int length, proto_tree *tree)
{
	proto_item	*vlanmap_item;
	proto_tree	*vlanmap_tree;
	guint		vlan, voffset;
	guint		bitoffset, byteoffset;

	vlanmap_item = proto_tree_add_protocol_format(tree, hf_fdp_vlanmap,
		tvb, offset, length, "VLAN-Map");

	vlanmap_tree = proto_item_add_subtree(vlanmap_item, ett_fdp_vlanmap);

	dissect_tlv_header(tvb, pinfo, offset, 4, vlanmap_tree);
	offset += 4;
	length -= 4;

	voffset = 1;
	for (vlan = 1; vlan <= (guint)length*8; vlan++) {
		byteoffset = (vlan - voffset) / 8;
		bitoffset = (vlan - voffset) % 8;
		if (tvb_get_guint8(tvb, offset + byteoffset) & (1 << bitoffset)) {

			proto_tree_add_uint(vlanmap_tree, hf_fdp_vlanmap_vlan, tvb,
				offset + byteoffset, 1, vlan);
		}
	}
}

static void
dissect_tag_tlv(tvbuff_t *tvb, packet_info *pinfo, int offset, int length, proto_tree *tree)
{
	proto_item	*tag_item;
	proto_tree	*tag_tree;

	tag_item = proto_tree_add_protocol_format(tree, hf_fdp_tag,
		tvb, offset, length, "Port tag");

	tag_tree = proto_item_add_subtree(tag_item, ett_fdp_tag);

	dissect_tlv_header(tvb, pinfo, offset, 4, tag_tree);
	offset += 4;
	length -= 4;
	proto_tree_add_item(tag_tree, hf_fdp_tag_native, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;
	proto_tree_add_item(tag_tree, hf_fdp_tag_type, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;
	proto_tree_add_item(tag_tree, hf_fdp_tag_unknown, tvb, offset, length, ENC_NA);
}

static void
dissect_unknown_tlv(tvbuff_t *tvb, packet_info *pinfo, int offset, int length, proto_tree *tree)
{
	proto_item	*unknown_item;
	proto_tree	*unknown_tree;
	guint16		tlv_type;

	tlv_type = tvb_get_ntohs(tvb, offset);

	unknown_item = proto_tree_add_protocol_format(tree, hf_fdp_unknown,
		tvb, offset, length, "Unknown element [%u]", tlv_type);

	unknown_tree = proto_item_add_subtree(unknown_item, ett_fdp_unknown);

	dissect_tlv_header(tvb, pinfo, offset, 4, unknown_tree);
	offset += 4;
	length -= 4;

	proto_tree_add_item(unknown_tree, hf_fdp_unknown_data, tvb, offset, length, ENC_NA);
}

static int
dissect_fdp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *ti;
	proto_tree *fdp_tree = NULL;
	gint offset = 0;
	guint16 tlv_type;
	guint16 tlv_length;
	gint data_length;
	const char *type_string;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_SHORT_NAME);
	col_set_str(pinfo->cinfo, COL_INFO, PROTO_SHORT_NAME ":");

	if (tree) {
		data_length = tvb_reported_length_remaining(tvb, offset);

		ti = proto_tree_add_item(tree, proto_fdp, tvb, offset, -1, ENC_NA);
		fdp_tree = proto_item_add_subtree(ti, ett_fdp);

		proto_tree_add_item(fdp_tree, hf_fdp_version, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(fdp_tree, hf_fdp_holdtime, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_checksum(fdp_tree, tvb, offset, hf_fdp_checksum, -1, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
		offset += 2;

		/* Decode the individual TLVs */
		while (offset < data_length) {
			if (data_length - offset < 4) {
				proto_tree_add_expert_format(fdp_tree, pinfo, &ei_fdp_tlv_length, tvb, offset, 4,
					"Too few bytes left for TLV: %u (< 4)", data_length - offset);
				break;
			}
			tlv_type = tvb_get_ntohs(tvb, offset);
			tlv_length = tvb_get_ntohs(tvb, offset + 2);

			if ((tlv_length < 4) || (tlv_length > (data_length - offset))) {
				proto_tree_add_expert_format(fdp_tree, pinfo, &ei_fdp_tlv_length, tvb, offset, 0,
					"TLV with invalid length: %u", tlv_length);
				break;
			}
			type_string = val_to_str(tlv_type, fdp_type_vals, "[%u]");
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s", type_string);

			switch (tlv_type) {
			case FDP_TYPE_NAME:
			case FDP_TYPE_PORT:
			case FDP_TYPE_CAPABILITIES:
			case FDP_TYPE_VERSION:
			case FDP_TYPE_MODEL:
				dissect_string_tlv(tvb, pinfo, offset, tlv_length, fdp_tree, type_string);
				break;
			case FDP_TYPE_NET:
				dissect_net_tlv(tvb, pinfo, offset, tlv_length, fdp_tree);
				break;
			case FDP_TYPE_TAG:
				dissect_tag_tlv(tvb, pinfo, offset, tlv_length, fdp_tree);
				break;
			case FDP_TYPE_VLANMAP:
				dissect_vlanmap_tlv(tvb, pinfo, offset, tlv_length, fdp_tree);
				break;
			default:
				dissect_unknown_tlv(tvb, pinfo, offset, tlv_length, fdp_tree);
				break;
			}
			offset += tlv_length;
		}

	}
	return tvb_captured_length(tvb);
}

void
proto_register_fdp(void)
{
	static hf_register_info hf[] = {

	/* FDP header */
		{ &hf_fdp_version,
		{ "Version?",	"fdp.version", FT_UINT8, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_fdp_holdtime,
		{ "Holdtime",	"fdp.holdtime", FT_UINT8, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_fdp_checksum,
		{ "Checksum?",	"fdp.checksum", FT_UINT16, BASE_HEX, NULL,
			0x0, NULL, HFILL }},

	/* TLV header */
		{ &hf_fdp_tlv_type,
		{ "TLV type",	"fdp.tlv.type", FT_UINT16, BASE_DEC, VALS(fdp_type_vals),
			0x0, NULL, HFILL }},

		{ &hf_fdp_tlv_length,
		{ "TLV length",	"fdp.tlv.length", FT_UINT16, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

	/* Unknown element */
		{ &hf_fdp_unknown,
		{ "Unknown",	"fdp.unknown", FT_PROTOCOL, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_fdp_unknown_data,
		{ "Unknown",	"fdp.unknown.data", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

	/* String element */
		{ &hf_fdp_string,
		{ "DeviceID",	"fdp.deviceid", FT_PROTOCOL, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_fdp_string_data,
		{ "Data",	"fdp.string.data", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_fdp_string_text,
		{ "Text",	"fdp.string.text", FT_STRING, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

	/* Net? element */
		{ &hf_fdp_net,
		{ "Net?",	"fdp.net", FT_PROTOCOL, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_fdp_net_unknown,
		{ "Net Unknown?",	"fdp.net.unknown", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_fdp_net_iplength,
		{ "Net IP Bytes?",	"fdp.net.iplength", FT_UINT16, BASE_DEC, NULL,
			0x0, "Number of bytes carrying IP addresses", HFILL }},

		{ &hf_fdp_net_ip,
		{ "Net IP Address?",	"fdp.net.ip", FT_IPv4, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

	/* VLAN Bitmap */
		{ &hf_fdp_vlanmap,
		{ "VLAN Map",	"fdp.vlanmap", FT_PROTOCOL, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_fdp_vlanmap_vlan,
		{ "VLAN",		"fdp.vlanmap.vlan", FT_UINT16, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

	/* Port Tag element */
		{ &hf_fdp_tag,
		{ "Tag",	"fdp.tag", FT_PROTOCOL, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_fdp_tag_native,
		{ "Native",	"fdp.tag.native", FT_UINT16, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_fdp_tag_type,
		{ "Type",	"fdp.tag.type", FT_UINT16, BASE_HEX, NULL,
			0x0, NULL, HFILL }},

		{ &hf_fdp_tag_unknown,
		{ "Unknown",	"fdp.tag.unknown", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

	};

	static hf_register_info oui_hf[] = {
	  { &hf_llc_foundry_pid,
		{ "PID",	"llc.foundry_pid",  FT_UINT16, BASE_HEX,
		  VALS(foundry_pid_vals), 0x0, NULL, HFILL }
	  }
	};

	static gint *ett[] = {
		&ett_fdp,
		&ett_fdp_tlv_header,
		&ett_fdp_unknown,
		&ett_fdp_string,
		&ett_fdp_net,
		&ett_fdp_tag,
		&ett_fdp_vlanmap,
	};

	static ei_register_info ei[] = {
		{ &ei_fdp_tlv_length, { "fdp.tlv.length.invalid", PI_MALFORMED, PI_ERROR, "Invalid length", EXPFILL }},
	};

	expert_module_t* expert_fdp;

	proto_fdp = proto_register_protocol(PROTO_LONG_NAME, PROTO_SHORT_NAME, "fdp");

	proto_register_field_array(proto_fdp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_fdp = expert_register_protocol(proto_fdp);
	expert_register_field_array(expert_fdp, ei, array_length(ei));

	llc_add_oui(OUI_FOUNDRY, "llc.foundry_pid", "LLC Foundry OUI PID", oui_hf, proto_fdp);
}

void
proto_reg_handoff_fdp(void)
{
	dissector_handle_t fdp_handle;

	fdp_handle = create_dissector_handle(dissect_fdp, proto_fdp);
	dissector_add_uint("llc.foundry_pid", 0x2000, fdp_handle);
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
