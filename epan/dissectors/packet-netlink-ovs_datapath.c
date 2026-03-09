/* packet-netlink-ovs_datapath.c
 * Routines for Open vSwitch datapath netlink protocol dissection
 * Copyright 2026, Red Hat Inc.
 * By Timothy Redaelli <tredaelli@redhat.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* ovs_datapath manages Open vSwitch datapaths via Generic Netlink
 *
 * Relevant Linux kernel header file:
 * include/uapi/linux/openvswitch.h
 */

#include "config.h"

#include <epan/packet.h>

#include "packet-netlink.h"

void proto_register_netlink_ovs_datapath(void);
void proto_reg_handoff_netlink_ovs_datapath(void);

/* from <include/uapi/linux/openvswitch.h> prefixed with WS_ */
enum ws_ovs_dp_cmd {
	WS_OVS_DP_CMD_UNSPEC,
	WS_OVS_DP_CMD_NEW,
	WS_OVS_DP_CMD_DEL,
	WS_OVS_DP_CMD_GET,
	WS_OVS_DP_CMD_SET,
};

enum ws_ovs_dp_attr {
	WS_OVS_DP_ATTR_UNSPEC,
	WS_OVS_DP_ATTR_NAME,
	WS_OVS_DP_ATTR_UPCALL_PID,
	WS_OVS_DP_ATTR_STATS,
	WS_OVS_DP_ATTR_MEGAFLOW_STATS,
	WS_OVS_DP_ATTR_USER_FEATURES,
	WS_OVS_DP_ATTR_PAD,
	WS_OVS_DP_ATTR_MASKS_CACHE_SIZE,
	WS_OVS_DP_ATTR_PER_CPU_PIDS,
	WS_OVS_DP_ATTR_IFINDEX,
};

static const value_string ws_ovs_dp_commands_vals[] = {
	{ WS_OVS_DP_CMD_UNSPEC,	"OVS_DP_CMD_UNSPEC" },
	{ WS_OVS_DP_CMD_NEW,		"OVS_DP_CMD_NEW" },
	{ WS_OVS_DP_CMD_DEL,		"OVS_DP_CMD_DEL" },
	{ WS_OVS_DP_CMD_GET,		"OVS_DP_CMD_GET" },
	{ WS_OVS_DP_CMD_SET,		"OVS_DP_CMD_SET" },
	{ 0, NULL }
};

static const value_string ws_ovs_dp_attr_vals[] = {
	{ WS_OVS_DP_ATTR_UNSPEC,		"OVS_DP_ATTR_UNSPEC" },
	{ WS_OVS_DP_ATTR_NAME,			"OVS_DP_ATTR_NAME" },
	{ WS_OVS_DP_ATTR_UPCALL_PID,		"OVS_DP_ATTR_UPCALL_PID" },
	{ WS_OVS_DP_ATTR_STATS,		"OVS_DP_ATTR_STATS" },
	{ WS_OVS_DP_ATTR_MEGAFLOW_STATS,	"OVS_DP_ATTR_MEGAFLOW_STATS" },
	{ WS_OVS_DP_ATTR_USER_FEATURES,	"OVS_DP_ATTR_USER_FEATURES" },
	{ WS_OVS_DP_ATTR_PAD,			"OVS_DP_ATTR_PAD" },
	{ WS_OVS_DP_ATTR_MASKS_CACHE_SIZE,	"OVS_DP_ATTR_MASKS_CACHE_SIZE" },
	{ WS_OVS_DP_ATTR_PER_CPU_PIDS,		"OVS_DP_ATTR_PER_CPU_PIDS" },
	{ WS_OVS_DP_ATTR_IFINDEX,		"OVS_DP_ATTR_IFINDEX" },
	{ 0, NULL }
};

struct netlink_ovs_dp_info {
	packet_info *pinfo;
};

static dissector_handle_t netlink_ovs_dp_handle;

static int proto_netlink_ovs_dp;

static int hf_ovs_dp_commands;
static int hf_ovs_dp_dp_ifindex;
static int hf_ovs_dp_attr;
static int hf_ovs_dp_name;
static int hf_ovs_dp_upcall_pid;
static int hf_ovs_dp_stats_n_hit;
static int hf_ovs_dp_stats_n_missed;
static int hf_ovs_dp_stats_n_lost;
static int hf_ovs_dp_stats_n_flows;
static int hf_ovs_dp_megaflow_stats_n_mask_hit;
static int hf_ovs_dp_megaflow_stats_n_masks;
static int hf_ovs_dp_megaflow_stats_n_cache_hit;
static int hf_ovs_dp_user_features;
static int hf_ovs_dp_user_features_unaligned;
static int hf_ovs_dp_user_features_vport_pids;
static int hf_ovs_dp_user_features_tc_recirc;
static int hf_ovs_dp_user_features_per_cpu;
static int hf_ovs_dp_masks_cache_size;
static int hf_ovs_dp_ifindex;

static int ett_ovs_dp;
static int ett_ovs_dp_attrs;
static int ett_ovs_dp_stats;
static int ett_ovs_dp_megaflow_stats;
static int ett_ovs_dp_user_features;

static int * const ovs_dp_user_features_fields[] = {
	&hf_ovs_dp_user_features_unaligned,
	&hf_ovs_dp_user_features_vport_pids,
	&hf_ovs_dp_user_features_tc_recirc,
	&hf_ovs_dp_user_features_per_cpu,
	NULL
};

static int
dissect_ovs_dp_attrs(tvbuff_t *tvb, void *data,
	struct packet_netlink_data *nl_data, proto_tree *tree,
	int nla_type, int offset, int len)
{
	enum ws_ovs_dp_attr type = (enum ws_ovs_dp_attr) nla_type;
	struct netlink_ovs_dp_info *info = (struct netlink_ovs_dp_info *) data;
	const uint8_t *str;
	proto_item *pi;
	proto_tree *ptree;
	uint32_t value;

	switch (type) {
	case WS_OVS_DP_ATTR_NAME:
		DISSECTOR_ASSERT(info);
		proto_tree_add_item_ret_string(tree, hf_ovs_dp_name,
			tvb, offset, len, ENC_ASCII | ENC_NA,
			info->pinfo->pool, &str);
		proto_item_append_text(tree, ": %s", str);
		return 1;

	case WS_OVS_DP_ATTR_UPCALL_PID:
		proto_tree_add_item_ret_uint(tree, hf_ovs_dp_upcall_pid, tvb,
			offset, 4, nl_data->encoding, &value);
		proto_item_append_text(tree, ": %u", value);
		return 1;

	case WS_OVS_DP_ATTR_STATS:
		/* struct ovs_dp_stats: n_hit(u64), n_missed(u64),
		 * n_lost(u64), n_flows(u64) = 32 bytes */
		if (len == 32) {
			int off = offset;
			pi = proto_tree_add_subtree(tree, tvb, offset, len,
				ett_ovs_dp_stats, NULL, "Datapath Statistics");
			ptree = proto_item_add_subtree(pi, ett_ovs_dp_stats);
			proto_tree_add_item(ptree, hf_ovs_dp_stats_n_hit,
				tvb, off, 8, nl_data->encoding);
			off += 8;
			proto_tree_add_item(ptree, hf_ovs_dp_stats_n_missed,
				tvb, off, 8, nl_data->encoding);
			off += 8;
			proto_tree_add_item(ptree, hf_ovs_dp_stats_n_lost,
				tvb, off, 8, nl_data->encoding);
			off += 8;
			proto_tree_add_item(ptree, hf_ovs_dp_stats_n_flows,
				tvb, off, 8, nl_data->encoding);
			return 1;
		}
		return 0;

	case WS_OVS_DP_ATTR_MEGAFLOW_STATS:
		/* struct ovs_dp_megaflow_stats: n_mask_hit(u64),
		 * n_masks(u32), pad0(u32), n_cache_hit(u64),
		 * pad1(u64) = 32 bytes.  Accept >= 16 for forward compat. */
		if (len >= 16) {
			int off = offset;
			pi = proto_tree_add_subtree(tree, tvb, offset, len,
				ett_ovs_dp_megaflow_stats, NULL, "Megaflow Statistics");
			ptree = proto_item_add_subtree(pi,
				ett_ovs_dp_megaflow_stats);
			proto_tree_add_item(ptree,
				hf_ovs_dp_megaflow_stats_n_mask_hit,
				tvb, off, 8, nl_data->encoding);
			off += 8;
			proto_tree_add_item(ptree,
				hf_ovs_dp_megaflow_stats_n_masks,
				tvb, off, 4, nl_data->encoding);
			off += 4;
			off += 4; /* pad0 */
			if (off + 8 <= offset + len) {
				proto_tree_add_item(ptree,
					hf_ovs_dp_megaflow_stats_n_cache_hit,
					tvb, off, 8, nl_data->encoding);
			}
			return 1;
		}
		return 0;

	case WS_OVS_DP_ATTR_USER_FEATURES:
		proto_tree_add_bitmask(tree, tvb, offset,
			hf_ovs_dp_user_features, ett_ovs_dp_user_features,
			ovs_dp_user_features_fields, nl_data->encoding);
		return 1;

	case WS_OVS_DP_ATTR_MASKS_CACHE_SIZE:
		proto_tree_add_item_ret_uint(tree, hf_ovs_dp_masks_cache_size,
			tvb, offset, 4, nl_data->encoding, &value);
		proto_item_append_text(tree, ": %u", value);
		return 1;

	case WS_OVS_DP_ATTR_PER_CPU_PIDS:
		/* Array of u32 PIDs, one per CPU */
		for (int i = 0; i + 4 <= len; i += 4) {
			proto_tree_add_item(tree, hf_ovs_dp_upcall_pid, tvb,
				offset + i, 4, nl_data->encoding);
		}
		return 1;

	case WS_OVS_DP_ATTR_IFINDEX:
		proto_tree_add_item_ret_uint(tree, hf_ovs_dp_ifindex, tvb,
			offset, 4, nl_data->encoding, &value);
		proto_item_append_text(tree, ": %u", value);
		return 1;

	default:
		return 0;
	}
}

static int
dissect_netlink_ovs_datapath(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, void *data)
{
	genl_info_t *genl_info = (genl_info_t *) data;
	struct netlink_ovs_dp_info info;
	proto_tree *nlmsg_tree;
	proto_item *pi;
	int offset;

	DISSECTOR_ASSERT(genl_info);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ovs_datapath");
	col_clear(pinfo->cinfo, COL_INFO);

	offset = dissect_genl_header(tvb, genl_info, genl_info->nl_data,
		hf_ovs_dp_commands);

	/* OVS header (dp_ifindex) */
	if (tvb_reported_length_remaining(tvb, offset) < 4)
		return offset;

	pi = proto_tree_add_item(tree, proto_netlink_ovs_dp, tvb, offset,
		-1, ENC_NA);
	nlmsg_tree = proto_item_add_subtree(pi, ett_ovs_dp);

	proto_tree_add_item(nlmsg_tree, hf_ovs_dp_dp_ifindex, tvb, offset,
		4, genl_info->nl_data->encoding);
	offset += 4;

	if (!tvb_reported_length_remaining(tvb, offset))
		return offset;

	info.pinfo = pinfo;
	offset = dissect_netlink_attributes_to_end(tvb, hf_ovs_dp_attr,
		ett_ovs_dp_attrs, &info, genl_info->nl_data,
		nlmsg_tree, offset, dissect_ovs_dp_attrs);

	return offset;
}

void
proto_register_netlink_ovs_datapath(void)
{
	static hf_register_info hf[] = {
		{ &hf_ovs_dp_commands,
			{ "Command", "ovs_datapath.cmd",
			  FT_UINT8, BASE_DEC,
			  VALS(ws_ovs_dp_commands_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_ovs_dp_dp_ifindex,
			{ "Datapath ifindex", "ovs_datapath.dp_ifindex",
			  FT_INT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_dp_attr,
			{ "Attribute type", "ovs_datapath.attr_type",
			  FT_UINT16, BASE_DEC, VALS(ws_ovs_dp_attr_vals),
			  NLA_TYPE_MASK, NULL, HFILL }
		},
		{ &hf_ovs_dp_name,
			{ "Name", "ovs_datapath.name",
			  FT_STRINGZ, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_dp_upcall_pid,
			{ "Upcall PID", "ovs_datapath.upcall_pid",
			  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_dp_stats_n_hit,
			{ "Flows hit", "ovs_datapath.stats.n_hit",
			  FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_dp_stats_n_missed,
			{ "Flows missed", "ovs_datapath.stats.n_missed",
			  FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_dp_stats_n_lost,
			{ "Flows lost", "ovs_datapath.stats.n_lost",
			  FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_dp_stats_n_flows,
			{ "Number of flows", "ovs_datapath.stats.n_flows",
			  FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_dp_megaflow_stats_n_mask_hit,
			{ "Mask hits",
			  "ovs_datapath.megaflow_stats.n_mask_hit",
			  FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_dp_megaflow_stats_n_masks,
			{ "Number of masks",
			  "ovs_datapath.megaflow_stats.n_masks",
			  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_dp_megaflow_stats_n_cache_hit,
			{ "Cache hits",
			  "ovs_datapath.megaflow_stats.n_cache_hit",
			  FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_dp_user_features,
			{ "User features", "ovs_datapath.user_features",
			  FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_dp_user_features_unaligned,
			{ "Unaligned NL attributes",
			  "ovs_datapath.user_features.unaligned",
			  FT_BOOLEAN, 32, NULL, 0x00000001, NULL, HFILL }
		},
		{ &hf_ovs_dp_user_features_vport_pids,
			{ "Multiple PIDs per vport",
			  "ovs_datapath.user_features.vport_pids",
			  FT_BOOLEAN, 32, NULL, 0x00000002, NULL, HFILL }
		},
		{ &hf_ovs_dp_user_features_tc_recirc,
			{ "TC offload recirc sharing",
			  "ovs_datapath.user_features.tc_recirc",
			  FT_BOOLEAN, 32, NULL, 0x00000004, NULL, HFILL }
		},
		{ &hf_ovs_dp_user_features_per_cpu,
			{ "Per-CPU upcall dispatch",
			  "ovs_datapath.user_features.per_cpu",
			  FT_BOOLEAN, 32, NULL, 0x00000008, NULL, HFILL }
		},
		{ &hf_ovs_dp_masks_cache_size,
			{ "Masks cache size",
			  "ovs_datapath.masks_cache_size",
			  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_dp_ifindex,
			{ "Interface index", "ovs_datapath.ifindex",
			  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
	};

	static int *ett[] = {
		&ett_ovs_dp,
		&ett_ovs_dp_attrs,
		&ett_ovs_dp_stats,
		&ett_ovs_dp_megaflow_stats,
		&ett_ovs_dp_user_features,
	};

	proto_netlink_ovs_dp = proto_register_protocol(
		"Linux ovs_datapath (Open vSwitch Datapath) protocol",
		"ovs_datapath", "ovs_datapath");
	proto_register_field_array(proto_netlink_ovs_dp, hf,
		array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	netlink_ovs_dp_handle = register_dissector("ovs_datapath",
		dissect_netlink_ovs_datapath, proto_netlink_ovs_dp);
}

void
proto_reg_handoff_netlink_ovs_datapath(void)
{
	dissector_add_string("genl.family", "ovs_datapath",
		netlink_ovs_dp_handle);
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
