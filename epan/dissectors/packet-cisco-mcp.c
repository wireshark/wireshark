/* packet-cisco-mcp.c
 * Routines for the disassembly of Cisco's MCP (Miscabling Protocol)
 *
 * Copyright 2019 Joerg Mayer (see AUTHORS file)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
  TODO:
  - Figure out the meaning of more types
  - Figure out the hash calculation
  - Display Value in TLV toplevel item where appropriate

Specs: No specs available
  No header
  Sequence of TLVs of format
  Type (1 byte)
  Length (1 byte)
  Value (Length bytes of Data)

Patent:
  http://www.freepatentsonline.com/20150124643.pdf
Documentation:
  https://www.cisco.com/c/en/us/solutions/collateral/data-center-virtualization/application-centric-infrastructure/white-paper-c11-737909.pdf
  https://unofficialaciguide.com/2018/03/27/using-mcp-miscabling-protocol-for-aci/
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/to_str.h>
#include <epan/cisco_pid.h>

void proto_register_mcp(void);
void proto_reg_handoff_mcp(void);

static int proto_mcp = -1;
/* TLV header */
static int hf_mcp_tlv_type = -1;
static int hf_mcp_tlv_length = -1;
/* Values */
static int hf_mcp_1 = -1;
static int hf_mcp_switchid = -1;
static int hf_mcp_3 = -1;
static int hf_mcp_ifindex = -1;
static int hf_mcp_timestamp = -1;
static int hf_mcp_hmac = -1;
// static int hf_mcp_end = -1;
static int hf_mcp_unknown = -1;

static expert_field ei_mcp_short_tlv = EI_INIT;
static expert_field ei_mcp_trailing_bytes = EI_INIT;
static expert_field ei_mcp_unexpected_tlv_length = EI_INIT;

static gint ett_mcp = -1;
static gint ett_mcp_tlv_header = -1;

#define PROTO_SHORT_NAME "MCP"
#define PROTO_LONG_NAME "Miscabling Protocol"

typedef enum {
	MCP_TYPE_1 = 1,		// Len=4, perhaps version or fabric-id
	MCP_TYPE_SWITCHID = 2,	// Len=4,
	MCP_TYPE_3 = 3,		// Len=12,
	MCP_TYPE_IFINDEX = 4,	// Len=4,
	MCP_TYPE_TIMESTAMP = 5,	// Len=4,
	MCP_TYPE_HMAC = 6,	// Len=20, Guessing, possibly SHA1
	MCP_TYPE_END = 7	// Len=0
} mcp_type_t;

static const value_string mcp_type_vals[] = {
	{ MCP_TYPE_1,		"Unknown1"},
	{ MCP_TYPE_SWITCHID,	"SwitchID"},
	{ MCP_TYPE_3,		"Unknown3"},
	{ MCP_TYPE_IFINDEX,	"IfIndex"},
	{ MCP_TYPE_TIMESTAMP,	"Timestamp"},
	{ MCP_TYPE_HMAC,	"HMAC?"},
	{ MCP_TYPE_END,		"End"},

	{ 0,	NULL }
};

static int
dissect_mcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *ti;
	proto_tree *mcp_tree;
	proto_tree *tlv_tree;
	guint32 offset = 0;
	gboolean last = FALSE;
	guint8 tlv_type;
	guint16 tlv_length;
	guint16 data_length = tvb_reported_length_remaining(tvb, offset);;
	guint32 switchid, ifindex, timestamp;
	gchar* timestamp_str;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_SHORT_NAME);
	col_set_str(pinfo->cinfo, COL_INFO, "");

	ti = proto_tree_add_item(tree, proto_mcp, tvb, offset, -1,
				 ENC_NA);
	mcp_tree = proto_item_add_subtree(ti, ett_mcp);

	/* No header whatsoever, just a plain sequence of TLVs */
	while (offset < data_length && !last) {
		if (data_length - offset < 2) {
			proto_tree_add_expert_format(mcp_tree, pinfo, &ei_mcp_short_tlv, tvb,
				offset, 4, "Too few bytes left for TLV (%u < 2)", data_length - offset);
			break;
		}
		tlv_type = tvb_get_guint8(tvb, offset);
		tlv_length = tvb_get_guint8(tvb, offset + 1);

		tlv_tree = proto_tree_add_subtree_format(mcp_tree, tvb, offset, tlv_length + 2,
			ett_mcp_tlv_header, NULL, "TLV length %d, type %d = %s",
			tlv_length, tlv_type, val_to_str(tlv_type, mcp_type_vals, "Unknown (0x%02x)"));

		proto_tree_add_uint(tlv_tree, hf_mcp_tlv_type, tvb, offset, 1, tlv_type);
		offset += 1;

		proto_tree_add_uint(tlv_tree, hf_mcp_tlv_length, tvb, offset, 1, tlv_length);
		if (tlv_length > (data_length - (offset + 1))) {
			proto_tree_add_expert_format(tlv_tree, pinfo, &ei_mcp_short_tlv, tvb,
				offset, 1, "TLV length (%u) passes end of packet", tlv_length);
			break;
		}
		offset += 1;

		switch (tlv_type) {
		case MCP_TYPE_1:
			if (tlv_length == 4) {
				proto_tree_add_item(tlv_tree, hf_mcp_1, tvb, offset, tlv_length, ENC_BIG_ENDIAN);
			} else {
				proto_tree_add_expert_format(mcp_tree, pinfo, &ei_mcp_unexpected_tlv_length, tvb,
					offset, tlv_length, "Expected value length differs from seen length (%u != %u)",
					4, tlv_length);
			}
			break;
		case MCP_TYPE_SWITCHID:
			if (tlv_length == 4) {
				proto_tree_add_item_ret_uint(tlv_tree, hf_mcp_switchid, tvb, offset, tlv_length, ENC_BIG_ENDIAN, &switchid);
				proto_item_append_text(tlv_tree, ": %u", switchid);
				col_append_fstr(pinfo->cinfo, COL_INFO, "SwID/%u ", switchid);
			} else {
				proto_tree_add_expert_format(mcp_tree, pinfo, &ei_mcp_unexpected_tlv_length, tvb,
					offset, tlv_length, "Expected value length differs from seen length (%u != %u)",
					4, tlv_length);
			}
			break;
		case MCP_TYPE_3:
			proto_tree_add_item(tlv_tree, hf_mcp_3, tvb, offset, tlv_length, ENC_NA);
			break;
		case MCP_TYPE_IFINDEX:
			if (tlv_length == 4) {
				proto_tree_add_item_ret_uint(tlv_tree, hf_mcp_ifindex, tvb, offset, tlv_length, ENC_BIG_ENDIAN, &ifindex);
				proto_item_append_text(tlv_tree, ": 0x%08x", ifindex);
				col_append_fstr(pinfo->cinfo, COL_INFO, "ifIdx/0x%08x ", ifindex);
			} else {
				proto_tree_add_expert_format(mcp_tree, pinfo, &ei_mcp_unexpected_tlv_length, tvb,
					offset, tlv_length, "Expected value length differs from seen length (%u != %u)",
					4, tlv_length);
			}
			break;
		case MCP_TYPE_TIMESTAMP:
			if (tlv_length == 4) {
				proto_tree_add_item(tlv_tree, hf_mcp_timestamp, tvb, offset, tlv_length, ENC_TIME_SECS|ENC_BIG_ENDIAN);
				timestamp = tvb_get_ntohl(tvb, offset);
				timestamp_str = abs_time_secs_to_str(wmem_packet_scope(), timestamp, ABSOLUTE_TIME_LOCAL, TRUE);
				proto_item_append_text(tlv_tree, ": %s", timestamp_str);
				col_append_fstr(pinfo->cinfo, COL_INFO, "time/%s ", timestamp_str);
			} else {
				proto_tree_add_expert_format(mcp_tree, pinfo, &ei_mcp_unexpected_tlv_length, tvb,
					offset, tlv_length, "Expected value length differs from seen length (%u != %u)",
					4, tlv_length);
			}
			break;
		case MCP_TYPE_HMAC:
			if (tlv_length == 20) {
				proto_tree_add_item(tlv_tree, hf_mcp_hmac, tvb, offset, tlv_length, ENC_NA);
			} else {
				proto_tree_add_expert_format(mcp_tree, pinfo, &ei_mcp_unexpected_tlv_length, tvb,
					offset, tlv_length, "Expected value length differs from seen length (%u != %u)",
					20, tlv_length);
			}
			break;
		case MCP_TYPE_END:
			last = TRUE;
			if (tlv_length != 0) {
				proto_tree_add_expert_format(mcp_tree, pinfo, &ei_mcp_unexpected_tlv_length, tvb,
					offset, tlv_length, "Expected value length differs from seen length (%u != %u)",
					0, tlv_length);
			}
			break;
		default:
			proto_tree_add_item(tlv_tree, hf_mcp_unknown, tvb, offset, tlv_length, ENC_NA);
			break;
		}
		offset += tlv_length;
	}
	if (offset < data_length) {
		proto_tree_add_expert(mcp_tree, pinfo, &ei_mcp_trailing_bytes, tvb, offset,
			data_length - offset);
	}

	return tvb_captured_length(tvb);
}

void
proto_register_mcp(void)
{
	static hf_register_info hf[] = {

	/* TLV header (aka TL) */
		{ &hf_mcp_tlv_type,
		{ "TLV type",	"mcp.tlv.type", FT_UINT8, BASE_DEC, VALS(mcp_type_vals),
			0x0, NULL, HFILL }},

		{ &hf_mcp_tlv_length,
		{ "TLV length",	"mcp.tlv.length", FT_UINT16, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

	/* TLV data (aka V) */
		{ &hf_mcp_1,
		{ "Type1",	"mcp.type1", FT_UINT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_mcp_switchid,
		{ "Switch ID",	"mcp.switchid", FT_UINT32, BASE_DEC, NULL,
			0x0, "Originating Switch", HFILL }},

		{ &hf_mcp_3,
		{ "Type3",	"mcp.type3", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_mcp_ifindex,
		{ "IfIndex",	"mcp.ifindex", FT_UINT32, BASE_HEX, NULL,
			0x0, NULL, HFILL }},

		{ &hf_mcp_timestamp,
		{ "Timestamp",	"mcp.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL,
			0x0, NULL, HFILL }},

		{ &hf_mcp_hmac,
		{ "HMAC(?)",	"mcp.hmac", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_mcp_unknown,
		{ "Unknown",	"mcp.unknown", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

	};

	static gint *ett[] = {
		&ett_mcp,
		&ett_mcp_tlv_header,
	};

	static ei_register_info ei[] = {
		{ &ei_mcp_short_tlv,
		{ "mcp.short_tlv", PI_MALFORMED, PI_ERROR,
			"TLV is too short", EXPFILL }},

		{ &ei_mcp_trailing_bytes,
		{ "mcp.trailing_bytes", PI_PROTOCOL, PI_WARN,
			"Trailing bytes after last TLV", EXPFILL }},

		{ &ei_mcp_unexpected_tlv_length,
		{ "mcp.unexpected_tlv_length", PI_PROTOCOL, PI_WARN,
			"Expected Value length differs from seen length", EXPFILL }},
	};

	expert_module_t* expert_mcp;

	proto_mcp = proto_register_protocol(PROTO_LONG_NAME, PROTO_SHORT_NAME, "mcp");
	proto_register_field_array(proto_mcp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_mcp = expert_register_protocol(proto_mcp);
	expert_register_field_array(expert_mcp, ei, array_length(ei));
}

void
proto_reg_handoff_mcp(void)
{
	dissector_handle_t mcp_handle;

	mcp_handle = create_dissector_handle(dissect_mcp, proto_mcp);
	dissector_add_uint("llc.cisco_pid", CISCO_PID_MCP, mcp_handle);
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
