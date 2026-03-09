/* packet-netlink-ovs_packet.c
 * Routines for Open vSwitch packet netlink protocol dissection
 * Copyright 2026, Red Hat Inc.
 * By Timothy Redaelli <tredaelli@redhat.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* ovs_packet handles upcall and execute of packets via Generic Netlink
 *
 * Relevant Linux kernel header file:
 * include/uapi/linux/openvswitch.h
 */

#include "config.h"

#include <epan/packet.h>

#include "packet-netlink.h"
#include "packet-netlink-ovs_flow.h"

void proto_register_netlink_ovs_packet(void);
void proto_reg_handoff_netlink_ovs_packet(void);

/* from <include/uapi/linux/openvswitch.h> prefixed with WS_ */
enum ws_ovs_packet_cmd {
	WS_OVS_PACKET_CMD_UNSPEC,
	WS_OVS_PACKET_CMD_MISS,
	WS_OVS_PACKET_CMD_ACTION,
	WS_OVS_PACKET_CMD_EXECUTE,
};

enum ws_ovs_packet_attr {
	WS_OVS_PACKET_ATTR_UNSPEC,
	WS_OVS_PACKET_ATTR_PACKET,
	WS_OVS_PACKET_ATTR_KEY,
	WS_OVS_PACKET_ATTR_ACTIONS,
	WS_OVS_PACKET_ATTR_USERDATA,
	WS_OVS_PACKET_ATTR_EGRESS_TUN_KEY,
	WS_OVS_PACKET_ATTR_UNUSED1,
	WS_OVS_PACKET_ATTR_UNUSED2,
	WS_OVS_PACKET_ATTR_PROBE,
	WS_OVS_PACKET_ATTR_MRU,
	WS_OVS_PACKET_ATTR_LEN,
	WS_OVS_PACKET_ATTR_HASH,
	WS_OVS_PACKET_ATTR_UPCALL_PID,
};

static const value_string ws_ovs_packet_commands_vals[] = {
	{ WS_OVS_PACKET_CMD_UNSPEC,	"OVS_PACKET_CMD_UNSPEC" },
	{ WS_OVS_PACKET_CMD_MISS,	"OVS_PACKET_CMD_MISS" },
	{ WS_OVS_PACKET_CMD_ACTION,	"OVS_PACKET_CMD_ACTION" },
	{ WS_OVS_PACKET_CMD_EXECUTE,	"OVS_PACKET_CMD_EXECUTE" },
	{ 0, NULL }
};

static const value_string ws_ovs_packet_attr_vals[] = {
	{ WS_OVS_PACKET_ATTR_UNSPEC,		"OVS_PACKET_ATTR_UNSPEC" },
	{ WS_OVS_PACKET_ATTR_PACKET,		"OVS_PACKET_ATTR_PACKET" },
	{ WS_OVS_PACKET_ATTR_KEY,		"OVS_PACKET_ATTR_KEY" },
	{ WS_OVS_PACKET_ATTR_ACTIONS,		"OVS_PACKET_ATTR_ACTIONS" },
	{ WS_OVS_PACKET_ATTR_USERDATA,		"OVS_PACKET_ATTR_USERDATA" },
	{ WS_OVS_PACKET_ATTR_EGRESS_TUN_KEY,	"OVS_PACKET_ATTR_EGRESS_TUN_KEY" },
	{ WS_OVS_PACKET_ATTR_UNUSED1,		"OVS_PACKET_ATTR_UNUSED1" },
	{ WS_OVS_PACKET_ATTR_UNUSED2,		"OVS_PACKET_ATTR_UNUSED2" },
	{ WS_OVS_PACKET_ATTR_PROBE,		"OVS_PACKET_ATTR_PROBE" },
	{ WS_OVS_PACKET_ATTR_MRU,		"OVS_PACKET_ATTR_MRU" },
	{ WS_OVS_PACKET_ATTR_LEN,		"OVS_PACKET_ATTR_LEN" },
	{ WS_OVS_PACKET_ATTR_HASH,		"OVS_PACKET_ATTR_HASH" },
	{ WS_OVS_PACKET_ATTR_UPCALL_PID,	"OVS_PACKET_ATTR_UPCALL_PID" },
	{ 0, NULL }
};

struct netlink_ovs_packet_info {
	packet_info *pinfo;
};

static dissector_handle_t netlink_ovs_packet_handle;

static int proto_netlink_ovs_packet;

static int hf_ovs_packet_commands;
static int hf_ovs_packet_dp_ifindex;
static int hf_ovs_packet_attr;
static int hf_ovs_packet_data;
static int hf_ovs_packet_userdata;
static int hf_ovs_packet_mru;
static int hf_ovs_packet_len;
static int hf_ovs_packet_hash;
static int hf_ovs_packet_upcall_pid;

static int ett_ovs_packet;
static int ett_ovs_packet_attrs;

static int
dissect_ovs_packet_attrs(tvbuff_t *tvb, void *data,
	struct packet_netlink_data *nl_data, proto_tree *tree,
	int nla_type, int offset, int len)
{
	struct netlink_ovs_packet_info *info =
		(struct netlink_ovs_packet_info *) data;
	enum ws_ovs_packet_attr type = (enum ws_ovs_packet_attr) nla_type;
	uint32_t value;

	DISSECTOR_ASSERT(info);

	switch (type) {
	case WS_OVS_PACKET_ATTR_PACKET:
		proto_tree_add_item(tree, hf_ovs_packet_data, tvb,
			offset, len, ENC_NA);
		return 1;

	case WS_OVS_PACKET_ATTR_KEY:
		return ovs_flow_dissect_key(tvb, info->pinfo, nl_data,
			tree, offset, len);

	case WS_OVS_PACKET_ATTR_ACTIONS:
		return ovs_flow_dissect_actions(tvb, info->pinfo, nl_data,
			tree, offset, len);

	case WS_OVS_PACKET_ATTR_USERDATA:
		proto_tree_add_item(tree, hf_ovs_packet_userdata, tvb,
			offset, len, ENC_NA);
		return 1;

	case WS_OVS_PACKET_ATTR_EGRESS_TUN_KEY:
		return ovs_flow_dissect_tunnel_key(tvb, info->pinfo, nl_data,
			tree, offset, len);

	case WS_OVS_PACKET_ATTR_PROBE:
		return 1;

	case WS_OVS_PACKET_ATTR_MRU:
		proto_tree_add_item_ret_uint(tree, hf_ovs_packet_mru, tvb,
			offset, 2, nl_data->encoding, &value);
		proto_item_append_text(tree, ": %u", value);
		return 1;

	case WS_OVS_PACKET_ATTR_LEN:
		proto_tree_add_item_ret_uint(tree, hf_ovs_packet_len, tvb,
			offset, 4, nl_data->encoding, &value);
		proto_item_append_text(tree, ": %u", value);
		return 1;

	case WS_OVS_PACKET_ATTR_HASH:
		proto_tree_add_item(tree, hf_ovs_packet_hash, tvb,
			offset, 4, nl_data->encoding);
		return 1;

	case WS_OVS_PACKET_ATTR_UPCALL_PID:
		proto_tree_add_item_ret_uint(tree, hf_ovs_packet_upcall_pid,
			tvb, offset, 4, nl_data->encoding, &value);
		proto_item_append_text(tree, ": %u", value);
		return 1;

	default:
		return 0;
	}
}

static int
dissect_netlink_ovs_packet(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, void *data)
{
	genl_info_t *genl_info = (genl_info_t *) data;
	struct netlink_ovs_packet_info info;
	proto_tree *nlmsg_tree;
	proto_item *pi;
	int offset;

	DISSECTOR_ASSERT(genl_info);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ovs_packet");
	col_clear(pinfo->cinfo, COL_INFO);

	offset = dissect_genl_header(tvb, genl_info, genl_info->nl_data,
		hf_ovs_packet_commands);

	if (tvb_reported_length_remaining(tvb, offset) < 4)
		return offset;

	pi = proto_tree_add_item(tree, proto_netlink_ovs_packet, tvb, offset,
		-1, ENC_NA);
	nlmsg_tree = proto_item_add_subtree(pi, ett_ovs_packet);

	proto_tree_add_item(nlmsg_tree, hf_ovs_packet_dp_ifindex, tvb,
		offset, 4, genl_info->nl_data->encoding);
	offset += 4;

	if (!tvb_reported_length_remaining(tvb, offset))
		return offset;

	info.pinfo = pinfo;
	offset = dissect_netlink_attributes_to_end(tvb, hf_ovs_packet_attr,
		ett_ovs_packet_attrs, &info, genl_info->nl_data, nlmsg_tree,
		offset, dissect_ovs_packet_attrs);

	return offset;
}

void
proto_register_netlink_ovs_packet(void)
{
	static hf_register_info hf[] = {
		{ &hf_ovs_packet_commands,
			{ "Command", "ovs_packet.cmd",
			  FT_UINT8, BASE_DEC,
			  VALS(ws_ovs_packet_commands_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_ovs_packet_dp_ifindex,
			{ "Datapath ifindex", "ovs_packet.dp_ifindex",
			  FT_INT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_packet_attr,
			{ "Attribute type", "ovs_packet.attr_type",
			  FT_UINT16, BASE_DEC,
			  VALS(ws_ovs_packet_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_ovs_packet_data,
			{ "Packet data", "ovs_packet.data",
			  FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_packet_userdata,
			{ "User data", "ovs_packet.userdata",
			  FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_packet_mru,
			{ "MRU", "ovs_packet.mru",
			  FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_packet_len,
			{ "Original packet length", "ovs_packet.len",
			  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_packet_hash,
			{ "Packet hash", "ovs_packet.hash",
			  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_packet_upcall_pid,
			{ "Upcall PID", "ovs_packet.upcall_pid",
			  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
	};

	static int *ett[] = {
		&ett_ovs_packet,
		&ett_ovs_packet_attrs,
	};

	proto_netlink_ovs_packet = proto_register_protocol(
		"Linux ovs_packet (Open vSwitch Packet) protocol",
		"ovs_packet", "ovs_packet");
	proto_register_field_array(proto_netlink_ovs_packet, hf,
		array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	netlink_ovs_packet_handle = register_dissector("ovs_packet",
		dissect_netlink_ovs_packet, proto_netlink_ovs_packet);
}

void
proto_reg_handoff_netlink_ovs_packet(void)
{
	dissector_add_string("genl.family", "ovs_packet",
		netlink_ovs_packet_handle);
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
