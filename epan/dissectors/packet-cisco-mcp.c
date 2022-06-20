/* packet-cisco-mcp.c
 * Routines for the disassembly of Cisco's MCP (MisCabling Protocol)
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
  - Figure out the hash calculation
  - Figure out strict mode tlv

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
  knet_parser.py from Cisco
Strict mode:
  https://www.cisco.com/c/en/us/td/docs/dcn/aci/apic/5x/aci-fundamentals/cisco-aci-fundamentals-52x/fundamentals-52x.html#Cisco_Concept.dita_637b67a2-6826-4cc4-8fbf-6998dc791d8b
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
static int hf_mcp_strict_tlv_type = -1;
static int hf_mcp_tlv_length = -1;
/* Values */
static int hf_mcp_fabric_id = -1;
static int hf_mcp_node_id = -1;
static int hf_mcp_vpc_domain = -1;
static int hf_mcp_vpc_id = -1;
static int hf_mcp_vpc_vtep = -1;
static int hf_mcp_port_id = -1;
static int hf_mcp_send_time = -1;
static int hf_mcp_strictmode = -1;
static int hf_mcp_digest = -1;
static int hf_mcp_unknown = -1;

static expert_field ei_mcp_short_tlv = EI_INIT;
static expert_field ei_mcp_trailing_bytes = EI_INIT;
static expert_field ei_mcp_unexpected_tlv_length = EI_INIT;

static gint ett_mcp = -1;
static gint ett_mcp_tlv_header = -1;

#define PROTO_SHORT_NAME "MCP"
#define PROTO_LONG_NAME "Miscabling Protocol"

// non-strict mode
typedef enum { // Total length of MCPDU = 62
	MCP_TYPE_FABRIC_ID = 1,		// Len=4,
	MCP_TYPE_NODE_ID = 2,		// Len=4,
	MCP_TYPE_VPC_INFO = 3,		// Len=12,
	MCP_TYPE_PORT_ID = 4,		// Len=4,
	MCP_TYPE_SEND_TIME = 5,		// Len=4,
	MCP_TYPE_DIGEST = 6,		// Len=20,
	MCP_TYPE_END = 7		// Len=0
} mcp_type_t;

// strict mode - minimum ACI software: 5.2(4)
typedef enum { // Total length of MCPDU = 68
	MCPS_TYPE_FABRIC_ID = 1,	// Len=4,
	MCPS_TYPE_NODE_ID = 2,		// Len=4,
	MCPS_TYPE_VPC_INFO = 3,		// Len=12,
	MCPS_TYPE_PORT_ID = 4,		// Len=4,
	MCPS_TYPE_SEND_TIME = 5,	// Len=4,
	MCPS_TYPE_STRICTMODE = 6,	// Len=4
	MCPS_TYPE_DIGEST = 7,		// Len=20,
	MCPS_TYPE_END = 8		// Len=0
} mcp_strict_type_t;

static const value_string mcp_type_vals[] = {
	{ MCP_TYPE_FABRIC_ID,	"Fabric ID"},
	{ MCP_TYPE_NODE_ID,	"Node ID"},
	{ MCP_TYPE_VPC_INFO,	"VPC Info"},
	{ MCP_TYPE_PORT_ID,	"Port ID"},
	{ MCP_TYPE_SEND_TIME,	"Send Time"},
	{ MCP_TYPE_DIGEST,	"Digest"},
	{ MCP_TYPE_END,		"End"},

	{ 0,	NULL }
};

static const value_string mcp_strict_type_vals[] = {
	{ MCPS_TYPE_FABRIC_ID,	"Fabric ID"},
	{ MCPS_TYPE_NODE_ID,	"Node ID"},
	{ MCPS_TYPE_VPC_INFO,	"VPC Info"},
	{ MCPS_TYPE_PORT_ID,	"Port ID"},
	{ MCPS_TYPE_SEND_TIME,	"Send Time"},
	{ MCPS_TYPE_STRICTMODE,	"Strictmode?"},
	{ MCPS_TYPE_DIGEST,	"Digest"},
	{ MCPS_TYPE_END,	"End"},

	{ 0,	NULL }
};

static int
dissect_mcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *ti, *pi;
	proto_tree *mcp_tree;
	proto_tree *tlv_tree;
	guint32 offset = 0;
	gboolean last = FALSE;
	gboolean strict_mode = TRUE;
	guint8 tlv_type, use_tlv;
	guint16 tlv_length;
	guint16 data_length = tvb_reported_length_remaining(tvb, offset);
	guint32 fabricid, nodeid, vpcdomain, vpcid, portid, sendtime, strictmode;
	gchar *sendtime_str, *vpcvtep_str;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_SHORT_NAME);
	col_set_str(pinfo->cinfo, COL_INFO, "");

	ti = proto_tree_add_item(tree, proto_mcp, tvb, offset, -1,
				 ENC_NA);
	mcp_tree = proto_item_add_subtree(ti, ett_mcp);

	/* No header whatsoever, just a plain sequence of TLVs */
	while (offset < data_length && !last) {
		if (data_length - offset < 2) {
			proto_tree_add_expert_format(mcp_tree, pinfo, &ei_mcp_short_tlv, tvb,
				offset, data_length, "Too few bytes left for TLV (%u < 2)", data_length - offset);
			break;
		}
		tlv_type = tvb_get_guint8(tvb, offset);
		// HACK: Interestring version handling
		use_tlv = tlv_type;
		if (data_length == 62) {
			strict_mode = FALSE;
			if (tlv_type >= MCPS_TYPE_STRICTMODE) {
				use_tlv = tlv_type + 1;
			}
		}

		tlv_length = tvb_get_guint8(tvb, offset + 1);

		if (strict_mode) {
			tlv_tree = proto_tree_add_subtree_format(mcp_tree, tvb, offset, tlv_length + 2,
				ett_mcp_tlv_header, NULL, "%s", val_to_str(tlv_type, mcp_strict_type_vals, "Unknown (0x%02x)"));
			proto_tree_add_uint(tlv_tree, hf_mcp_strict_tlv_type, tvb, offset, 1, tlv_type);
		} else {
			tlv_tree = proto_tree_add_subtree_format(mcp_tree, tvb, offset, tlv_length + 2,
				ett_mcp_tlv_header, NULL, "%s", val_to_str(tlv_type, mcp_type_vals, "Unknown (0x%02x)"));
		proto_tree_add_uint(tlv_tree, hf_mcp_tlv_type, tvb, offset, 1, tlv_type);
		}
		offset += 1;

		proto_tree_add_uint(tlv_tree, hf_mcp_tlv_length, tvb, offset, 1, tlv_length);
		if (tlv_length > (data_length - (offset + 1))) {
			proto_tree_add_expert_format(tlv_tree, pinfo, &ei_mcp_short_tlv, tvb,
				offset, 1, "TLV length (%u) passes end of packet", tlv_length);
			break;
		}
		offset += 1;

		switch (use_tlv) {
		case MCPS_TYPE_FABRIC_ID:
			if (tlv_length == 4) {
				proto_tree_add_item_ret_uint(tlv_tree, hf_mcp_fabric_id, tvb, offset, tlv_length, ENC_BIG_ENDIAN, &fabricid);
				proto_item_append_text(tlv_tree, ": %u", fabricid);
				col_append_fstr(pinfo->cinfo, COL_INFO, "FabricID/%u ", fabricid);
			} else {
				proto_tree_add_expert_format(mcp_tree, pinfo, &ei_mcp_unexpected_tlv_length, tvb,
					offset, tlv_length, "Expected value length differs from seen length (%u != %u)",
					4, tlv_length);
			}
			break;
		case MCPS_TYPE_NODE_ID:
			if (tlv_length == 4) {
				proto_tree_add_item_ret_uint(tlv_tree, hf_mcp_node_id, tvb, offset, tlv_length, ENC_BIG_ENDIAN, &nodeid);
				proto_item_append_text(tlv_tree, ": %u", nodeid);
				col_append_fstr(pinfo->cinfo, COL_INFO, "NodeID/%u ", nodeid);
			} else {
				proto_tree_add_expert_format(mcp_tree, pinfo, &ei_mcp_unexpected_tlv_length, tvb,
					offset, tlv_length, "Expected value length differs from seen length (%u != %u)",
					4, tlv_length);
			}
			break;
		case MCPS_TYPE_VPC_INFO:
			proto_tree_add_item_ret_uint(tlv_tree, hf_mcp_vpc_domain, tvb, offset, 4, ENC_NA, &vpcdomain);
			proto_tree_add_item_ret_uint(tlv_tree, hf_mcp_vpc_id, tvb, offset + 4, 4, ENC_NA, &vpcid);
			pi = proto_tree_add_item(tlv_tree, hf_mcp_vpc_vtep, tvb, offset + 8, 4, ENC_NA);
			vpcvtep_str = proto_item_get_display_repr(pinfo->pool, pi);
			proto_item_append_text(tlv_tree, ": %u/%u/%s", vpcdomain, vpcid, vpcvtep_str);
// FIXME: Why is vpcvtep_str displayed as "(null)" in COL_INFO but not above??? scope???
			if (vpcvtep_str)
				col_append_fstr(pinfo->cinfo, COL_INFO, "VpcInfo/%u,%u,%s ", vpcdomain, vpcid, vpcvtep_str);
			break;
		case MCPS_TYPE_PORT_ID:
			if (tlv_length == 4) {
				proto_tree_add_item_ret_uint(tlv_tree, hf_mcp_port_id, tvb, offset, tlv_length, ENC_BIG_ENDIAN, &portid);
				proto_item_append_text(tlv_tree, ": 0x%08x", portid);
				col_append_fstr(pinfo->cinfo, COL_INFO, "PortID/0x%08x ", portid);
			} else {
				proto_tree_add_expert_format(mcp_tree, pinfo, &ei_mcp_unexpected_tlv_length, tvb,
					offset, tlv_length, "Expected value length differs from seen length (%u != %u)",
					4, tlv_length);
			}
			break;
		case MCPS_TYPE_SEND_TIME:
			if (tlv_length == 4) {
				proto_tree_add_item(tlv_tree, hf_mcp_send_time, tvb, offset, tlv_length, ENC_TIME_SECS|ENC_BIG_ENDIAN);
				sendtime = tvb_get_ntohl(tvb, offset);
				sendtime_str = abs_time_secs_to_str(pinfo->pool, sendtime, ABSOLUTE_TIME_LOCAL, TRUE);
				proto_item_append_text(tlv_tree, ": %s", sendtime_str);
				col_append_fstr(pinfo->cinfo, COL_INFO, "SendTime/%s ", sendtime_str);
			} else {
				proto_tree_add_expert_format(mcp_tree, pinfo, &ei_mcp_unexpected_tlv_length, tvb,
					offset, tlv_length, "Expected value length differs from seen length (%u != %u)",
					4, tlv_length);
			}
			break;
		case MCPS_TYPE_STRICTMODE:
			if (tlv_length == 4) {
				proto_tree_add_item_ret_uint(tlv_tree, hf_mcp_strictmode, tvb, offset, tlv_length, ENC_BIG_ENDIAN, &strictmode);
				proto_item_append_text(tlv_tree, ": %d", strictmode);
				col_append_fstr(pinfo->cinfo, COL_INFO, "Unk1/%d ", strictmode);
			} else {
				proto_tree_add_expert_format(mcp_tree, pinfo, &ei_mcp_unexpected_tlv_length, tvb,
					offset, tlv_length, "Expected value length differs from seen length (%u != %u)",
					4, tlv_length);
			}
			break;
		case MCPS_TYPE_DIGEST:
			if (tlv_length == 20) {
				proto_tree_add_item(tlv_tree, hf_mcp_digest, tvb, offset, tlv_length, ENC_NA);
			} else {
				proto_tree_add_expert_format(mcp_tree, pinfo, &ei_mcp_unexpected_tlv_length, tvb,
					offset, tlv_length, "Expected value length differs from seen length (%u != %u)",
					20, tlv_length);
			}
			break;
		case MCPS_TYPE_END:
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

		{ &hf_mcp_strict_tlv_type,
		{ "TLV type",	"mcp.tlv.type", FT_UINT8, BASE_DEC, VALS(mcp_strict_type_vals),
			0x0, NULL, HFILL }},

		{ &hf_mcp_tlv_length,
		{ "TLV length",	"mcp.tlv.length", FT_UINT16, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

	/* TLV data (aka V) */
		{ &hf_mcp_fabric_id,
		{ "Fabric ID",	"mcp.fabric_id", FT_UINT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_mcp_node_id,
		{ "Node ID",	"mcp.node_id", FT_UINT32, BASE_DEC, NULL,
			0x0, "Originating Switch", HFILL }},

		{ &hf_mcp_vpc_domain,
		{ "VPC Domain",	"mcp.vpc.domain", FT_UINT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_mcp_vpc_id,
		{ "VPC ID",	"mcp.vpc.id", FT_UINT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_mcp_vpc_vtep,
		{ "VPC VTEP",	"mcp.vpc.vtep", FT_IPv4, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_mcp_port_id,
		{ "Port ID",	"mcp.port_id", FT_UINT32, BASE_HEX, NULL,
			0x0, NULL, HFILL }},

		{ &hf_mcp_send_time,
		{ "Send Time",	"mcp.send_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL,
			0x0, NULL, HFILL }},

		{ &hf_mcp_strictmode,
		{ "Strict Mode?",	"mcp.strictmode", FT_UINT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_mcp_digest,
		{ "Digest",	"mcp.digest", FT_BYTES, BASE_NONE, NULL,
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
