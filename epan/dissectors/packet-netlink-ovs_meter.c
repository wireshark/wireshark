/* packet-netlink-ovs_meter.c
 * Routines for Open vSwitch meter netlink protocol dissection
 * Copyright 2026, Red Hat Inc.
 * By Timothy Redaelli <tredaelli@redhat.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* ovs_meter manages Open vSwitch meter entries via Generic Netlink
 *
 * Relevant Linux kernel header file:
 * include/uapi/linux/openvswitch.h
 */

#include "config.h"

#include <epan/packet.h>

#include "packet-netlink.h"

void proto_register_netlink_ovs_meter(void);
void proto_reg_handoff_netlink_ovs_meter(void);

/* from <include/uapi/linux/openvswitch.h> prefixed with WS_ */
enum ws_ovs_meter_cmd {
	WS_OVS_METER_CMD_UNSPEC,
	WS_OVS_METER_CMD_FEATURES,
	WS_OVS_METER_CMD_SET,
	WS_OVS_METER_CMD_DEL,
	WS_OVS_METER_CMD_GET,
};

enum ws_ovs_meter_attr {
	WS_OVS_METER_ATTR_UNSPEC,
	WS_OVS_METER_ATTR_ID,
	WS_OVS_METER_ATTR_KBPS,
	WS_OVS_METER_ATTR_STATS,
	WS_OVS_METER_ATTR_BANDS,
	WS_OVS_METER_ATTR_USED,
	WS_OVS_METER_ATTR_CLEAR,
	WS_OVS_METER_ATTR_MAX_METERS,
	WS_OVS_METER_ATTR_MAX_BANDS,
	WS_OVS_METER_ATTR_PAD,
};

enum ws_ovs_band_attr {
	WS_OVS_BAND_ATTR_UNSPEC,
	WS_OVS_BAND_ATTR_TYPE,
	WS_OVS_BAND_ATTR_RATE,
	WS_OVS_BAND_ATTR_BURST,
	WS_OVS_BAND_ATTR_STATS,
};

enum ws_ovs_meter_band_type {
	WS_OVS_METER_BAND_TYPE_UNSPEC,
	WS_OVS_METER_BAND_TYPE_DROP,
};

static const value_string ws_ovs_meter_commands_vals[] = {
	{ WS_OVS_METER_CMD_UNSPEC,	"OVS_METER_CMD_UNSPEC" },
	{ WS_OVS_METER_CMD_FEATURES,	"OVS_METER_CMD_FEATURES" },
	{ WS_OVS_METER_CMD_SET,	"OVS_METER_CMD_SET" },
	{ WS_OVS_METER_CMD_DEL,	"OVS_METER_CMD_DEL" },
	{ WS_OVS_METER_CMD_GET,	"OVS_METER_CMD_GET" },
	{ 0, NULL }
};

static const value_string ws_ovs_meter_attr_vals[] = {
	{ WS_OVS_METER_ATTR_UNSPEC,		"OVS_METER_ATTR_UNSPEC" },
	{ WS_OVS_METER_ATTR_ID,		"OVS_METER_ATTR_ID" },
	{ WS_OVS_METER_ATTR_KBPS,		"OVS_METER_ATTR_KBPS" },
	{ WS_OVS_METER_ATTR_STATS,		"OVS_METER_ATTR_STATS" },
	{ WS_OVS_METER_ATTR_BANDS,		"OVS_METER_ATTR_BANDS" },
	{ WS_OVS_METER_ATTR_USED,		"OVS_METER_ATTR_USED" },
	{ WS_OVS_METER_ATTR_CLEAR,		"OVS_METER_ATTR_CLEAR" },
	{ WS_OVS_METER_ATTR_MAX_METERS,	"OVS_METER_ATTR_MAX_METERS" },
	{ WS_OVS_METER_ATTR_MAX_BANDS,		"OVS_METER_ATTR_MAX_BANDS" },
	{ WS_OVS_METER_ATTR_PAD,		"OVS_METER_ATTR_PAD" },
	{ 0, NULL }
};

static const value_string ws_ovs_band_attr_vals[] = {
	{ WS_OVS_BAND_ATTR_UNSPEC,	"OVS_BAND_ATTR_UNSPEC" },
	{ WS_OVS_BAND_ATTR_TYPE,	"OVS_BAND_ATTR_TYPE" },
	{ WS_OVS_BAND_ATTR_RATE,	"OVS_BAND_ATTR_RATE" },
	{ WS_OVS_BAND_ATTR_BURST,	"OVS_BAND_ATTR_BURST" },
	{ WS_OVS_BAND_ATTR_STATS,	"OVS_BAND_ATTR_STATS" },
	{ 0, NULL }
};

static const value_string ws_ovs_meter_band_type_vals[] = {
	{ WS_OVS_METER_BAND_TYPE_UNSPEC,	"OVS_METER_BAND_TYPE_UNSPEC" },
	{ WS_OVS_METER_BAND_TYPE_DROP,		"OVS_METER_BAND_TYPE_DROP" },
	{ 0, NULL }
};

struct netlink_ovs_meter_info {
	packet_info *pinfo;
};

static dissector_handle_t netlink_ovs_meter_handle;

static int proto_netlink_ovs_meter;

static int hf_ovs_meter_commands;
static int hf_ovs_meter_dp_ifindex;
static int hf_ovs_meter_attr;
static int hf_ovs_meter_id;
static int hf_ovs_meter_stats_n_packets;
static int hf_ovs_meter_stats_n_bytes;
static int hf_ovs_meter_used;
static int hf_ovs_meter_max_meters;
static int hf_ovs_meter_max_bands;
static int hf_ovs_meter_band_attr;
static int hf_ovs_meter_band_type;
static int hf_ovs_meter_band_rate;
static int hf_ovs_meter_band_burst;
static int hf_ovs_meter_band_stats_n_packets;
static int hf_ovs_meter_band_stats_n_bytes;

static int ett_ovs_meter;
static int ett_ovs_meter_attrs;
static int ett_ovs_meter_stats;
static int ett_ovs_meter_bands;
static int ett_ovs_meter_band_attrs;
static int ett_ovs_meter_band_stats;

static int
dissect_ovs_meter_band_attrs(tvbuff_t *tvb, void *data,
	struct packet_netlink_data *nl_data, proto_tree *tree,
	int nla_type, int offset, int len)
{
	enum ws_ovs_band_attr type = (enum ws_ovs_band_attr) nla_type;
	uint32_t value;
	proto_item *pi;
	proto_tree *ptree;

	switch (type) {
	case WS_OVS_BAND_ATTR_TYPE:
		{
			struct netlink_ovs_meter_info *info =
				(struct netlink_ovs_meter_info *) data;
			DISSECTOR_ASSERT(info);
			proto_tree_add_item_ret_uint(tree,
				hf_ovs_meter_band_type, tvb, offset, 4,
				nl_data->encoding, &value);
			proto_item_append_text(tree, ": %s",
				val_to_str(info->pinfo->pool, value,
					ws_ovs_meter_band_type_vals,
					"Unknown (%u)"));
		}
		return 1;

	case WS_OVS_BAND_ATTR_RATE:
		proto_tree_add_item_ret_uint(tree, hf_ovs_meter_band_rate,
			tvb, offset, 4, nl_data->encoding, &value);
		proto_item_append_text(tree, ": %u", value);
		return 1;

	case WS_OVS_BAND_ATTR_BURST:
		proto_tree_add_item_ret_uint(tree, hf_ovs_meter_band_burst,
			tvb, offset, 4, nl_data->encoding, &value);
		proto_item_append_text(tree, ": %u", value);
		return 1;

	case WS_OVS_BAND_ATTR_STATS:
		/* struct ovs_flow_stats: n_packets(u64)+n_bytes(u64)=16 */
		if (len == 16) {
			pi = proto_tree_add_subtree(tree, tvb, offset, len,
				ett_ovs_meter_band_stats, NULL, "Band Statistics");
			ptree = proto_item_add_subtree(pi,
				ett_ovs_meter_band_stats);
			proto_tree_add_item(ptree,
				hf_ovs_meter_band_stats_n_packets,
				tvb, offset, 8, nl_data->encoding);
			proto_tree_add_item(ptree,
				hf_ovs_meter_band_stats_n_bytes,
				tvb, offset + 8, 8, nl_data->encoding);
			return 1;
		}
		return 0;

	default:
		return 0;
	}
}

static int
dissect_ovs_meter_attrs(tvbuff_t *tvb, void *data,
	struct packet_netlink_data *nl_data, proto_tree *tree,
	int nla_type, int offset, int len)
{
	enum ws_ovs_meter_attr type = (enum ws_ovs_meter_attr) nla_type;
	uint32_t value;
	proto_item *pi;
	proto_tree *ptree;

	switch (type) {
	case WS_OVS_METER_ATTR_ID:
		proto_tree_add_item_ret_uint(tree, hf_ovs_meter_id, tvb,
			offset, 4, nl_data->encoding, &value);
		proto_item_append_text(tree, ": %u", value);
		return 1;

	case WS_OVS_METER_ATTR_KBPS:
		return 1;

	case WS_OVS_METER_ATTR_STATS:
		/* struct ovs_flow_stats: n_packets(u64)+n_bytes(u64)=16 */
		if (len == 16) {
			pi = proto_tree_add_subtree(tree, tvb, offset, len,
				ett_ovs_meter_stats, NULL, "Meter Statistics");
			ptree = proto_item_add_subtree(pi,
				ett_ovs_meter_stats);
			proto_tree_add_item(ptree,
				hf_ovs_meter_stats_n_packets,
				tvb, offset, 8, nl_data->encoding);
			proto_tree_add_item(ptree,
				hf_ovs_meter_stats_n_bytes,
				tvb, offset + 8, 8, nl_data->encoding);
			return 1;
		}
		return 0;

	case WS_OVS_METER_ATTR_BANDS:
		return dissect_netlink_attributes_array(tvb,
			hf_ovs_meter_band_attr, ett_ovs_meter_bands,
			ett_ovs_meter_band_attrs, data, nl_data,
			tree, offset, len,
			dissect_ovs_meter_band_attrs);

	case WS_OVS_METER_ATTR_USED:
		proto_tree_add_item(tree, hf_ovs_meter_used, tvb,
			offset, 8, nl_data->encoding);
		return 1;

	case WS_OVS_METER_ATTR_CLEAR:
		return 1;

	case WS_OVS_METER_ATTR_MAX_METERS:
		proto_tree_add_item_ret_uint(tree, hf_ovs_meter_max_meters,
			tvb, offset, 4, nl_data->encoding, &value);
		proto_item_append_text(tree, ": %u", value);
		return 1;

	case WS_OVS_METER_ATTR_MAX_BANDS:
		proto_tree_add_item_ret_uint(tree, hf_ovs_meter_max_bands,
			tvb, offset, 4, nl_data->encoding, &value);
		proto_item_append_text(tree, ": %u", value);
		return 1;

	default:
		return 0;
	}
}

static int
dissect_netlink_ovs_meter(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, void *data)
{
	genl_info_t *genl_info = (genl_info_t *) data;
	struct netlink_ovs_meter_info info;
	proto_tree *nlmsg_tree;
	proto_item *pi;
	int offset;

	DISSECTOR_ASSERT(genl_info);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ovs_meter");
	col_clear(pinfo->cinfo, COL_INFO);

	offset = dissect_genl_header(tvb, genl_info, genl_info->nl_data,
		hf_ovs_meter_commands);

	if (tvb_reported_length_remaining(tvb, offset) < 4)
		return offset;

	pi = proto_tree_add_item(tree, proto_netlink_ovs_meter, tvb, offset,
		-1, ENC_NA);
	nlmsg_tree = proto_item_add_subtree(pi, ett_ovs_meter);

	proto_tree_add_item(nlmsg_tree, hf_ovs_meter_dp_ifindex, tvb,
		offset, 4, genl_info->nl_data->encoding);
	offset += 4;

	if (!tvb_reported_length_remaining(tvb, offset))
		return offset;

	info.pinfo = pinfo;
	offset = dissect_netlink_attributes_to_end(tvb, hf_ovs_meter_attr,
		ett_ovs_meter_attrs, &info, genl_info->nl_data,
		nlmsg_tree, offset, dissect_ovs_meter_attrs);

	return offset;
}

void
proto_register_netlink_ovs_meter(void)
{
	static hf_register_info hf[] = {
		{ &hf_ovs_meter_commands,
			{ "Command", "ovs_meter.cmd",
			  FT_UINT8, BASE_DEC,
			  VALS(ws_ovs_meter_commands_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_ovs_meter_dp_ifindex,
			{ "Datapath ifindex", "ovs_meter.dp_ifindex",
			  FT_INT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_meter_attr,
			{ "Attribute type", "ovs_meter.attr_type",
			  FT_UINT16, BASE_DEC,
			  VALS(ws_ovs_meter_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_ovs_meter_id,
			{ "Meter ID", "ovs_meter.id",
			  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_meter_stats_n_packets,
			{ "Packets", "ovs_meter.stats.n_packets",
			  FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_meter_stats_n_bytes,
			{ "Bytes", "ovs_meter.stats.n_bytes",
			  FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_meter_used,
			{ "Last used (ms)", "ovs_meter.used",
			  FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_meter_max_meters,
			{ "Max meters", "ovs_meter.max_meters",
			  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_meter_max_bands,
			{ "Max bands", "ovs_meter.max_bands",
			  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_meter_band_attr,
			{ "Band attribute type",
			  "ovs_meter.band.attr_type",
			  FT_UINT16, BASE_DEC,
			  VALS(ws_ovs_band_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_ovs_meter_band_type,
			{ "Band type", "ovs_meter.band.type",
			  FT_UINT32, BASE_DEC,
			  VALS(ws_ovs_meter_band_type_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_ovs_meter_band_rate,
			{ "Band rate", "ovs_meter.band.rate",
			  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_meter_band_burst,
			{ "Band burst", "ovs_meter.band.burst",
			  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_meter_band_stats_n_packets,
			{ "Packets", "ovs_meter.band.stats.n_packets",
			  FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_meter_band_stats_n_bytes,
			{ "Bytes", "ovs_meter.band.stats.n_bytes",
			  FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
	};

	static int *ett[] = {
		&ett_ovs_meter,
		&ett_ovs_meter_attrs,
		&ett_ovs_meter_stats,
		&ett_ovs_meter_bands,
		&ett_ovs_meter_band_attrs,
		&ett_ovs_meter_band_stats,
	};

	proto_netlink_ovs_meter = proto_register_protocol(
		"Linux ovs_meter (Open vSwitch Meter) protocol",
		"ovs_meter", "ovs_meter");
	proto_register_field_array(proto_netlink_ovs_meter, hf,
		array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	netlink_ovs_meter_handle = register_dissector("ovs_meter",
		dissect_netlink_ovs_meter, proto_netlink_ovs_meter);
}

void
proto_reg_handoff_netlink_ovs_meter(void)
{
	dissector_add_string("genl.family", "ovs_meter",
		netlink_ovs_meter_handle);
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
