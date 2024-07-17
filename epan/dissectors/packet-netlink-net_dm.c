/* packet-netlink-net_dm.c
 * Routines for netlink-net_dm dissection
 * Based on netlink-route and netlink-generic dissectors
 * Copyright 2019, Mellanox Technologies Ltd.
 * Code by Ido Schimmel <idosch@mellanox.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* net_dm (network drop monitor) is a netlink-based protocol via which alerts
 * about dropped packets are sent to user space
 *
 * Relevant Linux kernel header file:
 * include/uapi/linux/net_dropmon.h
 *
 * Man page:
 * man 1 dropwatch
 */

#include "config.h"

#include <epan/packet.h>

#include "packet-netlink.h"
#include "packet-sll.h"

void proto_register_netlink_net_dm(void);
void proto_reg_handoff_netlink_net_dm(void);

enum ws_net_dm_commands {
	WS_NET_DM_CMD_UNSPEC,
	WS_NET_DM_CMD_ALERT,
	WS_NET_DM_CMD_CONFIG,
	WS_NET_DM_CMD_START,
	WS_NET_DM_CMD_STOP,
	WS_NET_DM_CMD_PACKET_ALERT,
	WS_NET_DM_CMD_CONFIG_GET,
	WS_NET_DM_CMD_CONFIG_NEW,
	WS_NET_DM_CMD_STATS_GET,
	WS_NET_DM_CMD_STATS_NEW,
};

enum ws_net_dm_attrs {
	WS_NET_DM_ATTR_UNSPEC,
	WS_NET_DM_ATTR_ALERT_MODE,
	WS_NET_DM_ATTR_PC,
	WS_NET_DM_ATTR_SYMBOL,
	WS_NET_DM_ATTR_IN_PORT,
	WS_NET_DM_ATTR_TIMESTAMP,
	WS_NET_DM_ATTR_PROTO,
	WS_NET_DM_ATTR_PAYLOAD,
	WS_NET_DM_ATTR_PAD,
	WS_NET_DM_ATTR_TRUNC_LEN,
	WS_NET_DM_ATTR_ORIG_LEN,
	WS_NET_DM_ATTR_QUEUE_LEN,
	WS_NET_DM_ATTR_STATS,
	WS_NET_DM_ATTR_HW_STATS,
	WS_NET_DM_ATTR_ORIGIN,
	WS_NET_DM_ATTR_HW_TRAP_GROUP_NAME,
	WS_NET_DM_ATTR_HW_TRAP_NAME,
	WS_NET_DM_ATTR_HW_ENTRIES,
	WS_NET_DM_ATTR_HW_ENTRY,
	WS_NET_DM_ATTR_HW_TRAP_COUNT,
	WS_NET_DM_ATTR_SW_DROPS,
	WS_NET_DM_ATTR_HW_DROPS,
	WS_NET_DM_ATTR_FLOW_ACTION_COOKIE,
	WS_NET_DM_ATTR_REASON,
};

enum ws_net_dm_attrs_port {
	WS_NET_DM_ATTR_PORT_NETDEV_IFINDEX,
	WS_NET_DM_ATTR_PORT_NETDEV_NAME,
};

enum ws_net_dm_attrs_stats {
	WS_NET_DM_ATTR_STATS_DROPPED,
};

enum ws_net_dm_alert_mode {
	WS_NET_DM_ALERT_MODE_SUMMARY,
	WS_NET_DM_ALERT_MODE_PACKET,
};

enum ws_net_dm_origin {
	WS_NET_DM_ORIGIN_SW,
	WS_NET_DM_ORIGIN_HW,
};

struct netlink_net_dm_info {
	packet_info *pinfo;
	uint16_t protocol; /* protocol for packet payload */
};

static dissector_handle_t netlink_net_dm_handle;
static dissector_table_t sll_ltype_table;
static dissector_table_t ethertype_table;

static int proto_netlink_net_dm;

static int hf_net_dm_alert_mode;
static int hf_net_dm_attrs;
static int hf_net_dm_attrs_port;
static int hf_net_dm_attrs_stats;
static int hf_net_dm_commands;
static int hf_net_dm_flow_action_cookie;
static int hf_net_dm_hw;
static int hf_net_dm_hw_trap_count;
static int hf_net_dm_hw_trap_group_name;
static int hf_net_dm_hw_trap_name;
static int hf_net_dm_orig_len;
static int hf_net_dm_origin;
static int hf_net_dm_pc;
static int hf_net_dm_port_netdev_index;
static int hf_net_dm_port_netdev_name;
static int hf_net_dm_proto;
static int hf_net_dm_queue_len;
static int hf_net_dm_stats_dropped;
static int hf_net_dm_sw;
static int hf_net_dm_symbol;
static int hf_net_dm_timestamp;
static int hf_net_dm_trunc_len;
static int hf_net_dm_reason;

static int ett_net_dm;
static int ett_net_dm_attrs;
static int ett_net_dm_attrs_in_port;
static int ett_net_dm_attrs_stats;
static int ett_net_dm_attrs_hw_stats;
static int ett_net_dm_attrs_hw_entries;
static int ett_net_dm_attrs_hw_entry;

static const value_string ws_net_dm_commands_vals[] = {
	{ WS_NET_DM_CMD_UNSPEC,			"Unspecified command" },
	{ WS_NET_DM_CMD_ALERT,			"Drop alert (summary)" },
	{ WS_NET_DM_CMD_CONFIG,			"Configure drop monitor" },
	{ WS_NET_DM_CMD_START,			"Start monitoring" },
	{ WS_NET_DM_CMD_STOP,			"Stop monitoring" },
	{ WS_NET_DM_CMD_PACKET_ALERT,		"Drop alert (packet)" },
	{ WS_NET_DM_CMD_CONFIG_GET,		"Get drop monitor configuration" },
	{ WS_NET_DM_CMD_CONFIG_NEW,		"New drop monitor configuration" },
	{ WS_NET_DM_CMD_STATS_GET,		"Get drop monitor statistics" },
	{ WS_NET_DM_CMD_STATS_NEW,		"New drop monitor statistics" },
	{ 0, NULL },
};

static value_string_ext ws_net_dm_commands_vals_ext = VALUE_STRING_EXT_INIT(ws_net_dm_commands_vals);

static const value_string ws_net_dm_attrs_vals[] = {
	{ WS_NET_DM_ATTR_UNSPEC,			"Unspecified" },
	{ WS_NET_DM_ATTR_ALERT_MODE,			"Alert mode" },
	{ WS_NET_DM_ATTR_PC,				"Drop location (PC)" },
	{ WS_NET_DM_ATTR_SYMBOL,			"Drop location (symbol)" },
	{ WS_NET_DM_ATTR_IN_PORT,			"Input port" },
	{ WS_NET_DM_ATTR_TIMESTAMP,			"Timestamp" },
	{ WS_NET_DM_ATTR_PROTO,				"Protocol" },
	{ WS_NET_DM_ATTR_PAYLOAD,			"Payload" },
	{ WS_NET_DM_ATTR_PAD,				"Pad" },
	{ WS_NET_DM_ATTR_TRUNC_LEN,			"Truncation length" },
	{ WS_NET_DM_ATTR_ORIG_LEN,			"Original length" },
	{ WS_NET_DM_ATTR_QUEUE_LEN,			"Queue length" },
	{ WS_NET_DM_ATTR_STATS,				"Software statistics" },
	{ WS_NET_DM_ATTR_HW_STATS,			"Hardware statistics" },
	{ WS_NET_DM_ATTR_ORIGIN,			"Packet origin" },
	{ WS_NET_DM_ATTR_HW_TRAP_GROUP_NAME,		"Hardware trap group name" },
	{ WS_NET_DM_ATTR_HW_TRAP_NAME,			"Hardware trap name" },
	{ WS_NET_DM_ATTR_HW_ENTRIES,			"Hardware trap entries" },
	{ WS_NET_DM_ATTR_HW_ENTRY,			"Hardware trap entry" },
	{ WS_NET_DM_ATTR_HW_TRAP_COUNT,			"Hardware trap count" },
	{ WS_NET_DM_ATTR_SW_DROPS,			"Software drops" },
	{ WS_NET_DM_ATTR_HW_DROPS,			"Hardware drops" },
	{ WS_NET_DM_ATTR_FLOW_ACTION_COOKIE,		"Flow action cookie" },
	{ WS_NET_DM_ATTR_REASON,			"Reason" },
	{ 0, NULL },
};

static value_string_ext ws_net_dm_attrs_vals_ext = VALUE_STRING_EXT_INIT(ws_net_dm_attrs_vals);

static const value_string ws_net_dm_attrs_port_vals[] = {
	{ WS_NET_DM_ATTR_PORT_NETDEV_IFINDEX,		"Net device index" },
	{ WS_NET_DM_ATTR_PORT_NETDEV_NAME,		"Net device name" },
	{ 0, NULL },
};

static const value_string ws_net_dm_attrs_stats_vals[] = {
	{ WS_NET_DM_ATTR_STATS_DROPPED,			"Dropped" },
	{ 0, NULL },
};

static const value_string ws_net_dm_alert_mode_vals[] = {
	{ WS_NET_DM_ALERT_MODE_SUMMARY,		"Summary" },
	{ WS_NET_DM_ALERT_MODE_PACKET,		"Packet" },
	{ 0, NULL },
};

static const value_string ws_net_dm_origin_vals[] = {
	{ WS_NET_DM_ORIGIN_SW,		"Software" },
	{ WS_NET_DM_ORIGIN_HW,		"Hardware" },
	{ 0, NULL },
};

static int
dissect_net_dm_attrs_port(tvbuff_t *tvb, void *data _U_, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_net_dm_attrs_port type = (enum ws_net_dm_attrs_port) nla_type & NLA_TYPE_MASK;
	const uint8_t *str;
	uint32_t value;

	switch (type) {
	case WS_NET_DM_ATTR_PORT_NETDEV_IFINDEX:
		proto_tree_add_item_ret_uint(tree, hf_net_dm_port_netdev_index, tvb, offset, len, nl_data->encoding, &value);
		proto_item_append_text(tree, ": %u", value);
		return 1;
	case WS_NET_DM_ATTR_PORT_NETDEV_NAME:
		proto_tree_add_item_ret_string(tree, hf_net_dm_port_netdev_name, tvb, offset, len, ENC_ASCII | ENC_NA, wmem_packet_scope(), &str);
		proto_item_append_text(tree, ": %s", str);
		return 1;
	default:
		return 0;
	}
}

static int
dissect_net_dm_attrs_stats(tvbuff_t *tvb, void *data _U_, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_net_dm_attrs_port type = (enum ws_net_dm_attrs_port) nla_type & NLA_TYPE_MASK;

	switch (type) {
	case WS_NET_DM_ATTR_STATS_DROPPED:
		proto_tree_add_item(tree, hf_net_dm_stats_dropped, tvb, offset, len, nl_data->encoding);
		return 1;
	default:
		return 0;
	}
}

static int
dissect_net_dm_attrs(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_net_dm_attrs type = (enum ws_net_dm_attrs) nla_type & NLA_TYPE_MASK;
	struct netlink_net_dm_info *info = (struct netlink_net_dm_info *) data;
	uint64_t pc, timestamp;
	nstime_t ts_nstime;
	uint32_t value;
	uint16_t protocol;
	static dissector_table_t dissector_table;
	tvbuff_t *next_tvb;
	const uint8_t *str;

	switch (type) {
	case WS_NET_DM_ATTR_ALERT_MODE:
		proto_tree_add_item(tree, hf_net_dm_alert_mode, tvb, offset, len, nl_data->encoding);
		return 1;
	case WS_NET_DM_ATTR_PC:
		proto_tree_add_item_ret_uint64(tree, hf_net_dm_pc, tvb,
					       offset, 8, nl_data->encoding, &pc);
		proto_item_append_text(tree, ": 0x%" PRIx64, pc);
		return 1;
	case WS_NET_DM_ATTR_SYMBOL:
		proto_tree_add_item_ret_string(tree, hf_net_dm_symbol, tvb, offset, len, ENC_ASCII | ENC_NA, wmem_packet_scope(), &str);
		proto_item_append_text(tree, ": %s", str);
		return 1;
	case WS_NET_DM_ATTR_IN_PORT:
		return dissect_netlink_attributes(tvb, hf_net_dm_attrs_port, ett_net_dm_attrs_in_port, info, nl_data, tree, offset, len,
						  dissect_net_dm_attrs_port);
	case WS_NET_DM_ATTR_TIMESTAMP:
		timestamp = tvb_get_uint64(tvb, offset, nl_data->encoding);
		ts_nstime.secs = timestamp / 1000000000;
		ts_nstime.nsecs = timestamp % 1000000000;
		proto_tree_add_time(tree, hf_net_dm_timestamp, tvb, offset, 8, &ts_nstime);
		return 1;
	case WS_NET_DM_ATTR_PROTO:
		info->protocol = tvb_get_uint16(tvb, offset, nl_data->encoding);

		proto_tree_add_item(tree, hf_net_dm_proto, tvb, offset, len, nl_data->encoding);
		return 1;
	case WS_NET_DM_ATTR_PAYLOAD:
		/* This whole payload protocol thing is messed up:
		* We can't know from the kernel netlink message what we get exacly
		*/
		protocol = info->protocol;
		dissector_table = sll_ltype_table;
		/* This attribute encodes 'skb->protocol' and if it is greater
		 * than or equal to 1536 (0x0600), then it is an Ethertype and
		 * we need to treat the packet as Ethernet.
		 */
		if (info->protocol >= 1536 || info->protocol == LINUX_SLL_P_802_2) {
			/* It might be ethernet, but we're not really sure what the packet actually is.
			* We try a guess: if two bytes 12-14 match the Ethertype, then it's ethernet,
			* otherwise we just assume that we have is a payload of the Ethertype itself.
			* (this is not a perfect match, but in practice gives good enough results)
			*
			* If it's too short to be Ethernet, then for sure we don't have an Ethernet payload.
			*/
			if (len >= 14 && tvb_get_uint16(tvb, offset + 12, ENC_BIG_ENDIAN) == info->protocol) {
				protocol = LINUX_SLL_P_ETHERNET;
			} else {
				dissector_table = ethertype_table;
			}
		}


		next_tvb = tvb_new_subset_length(tvb, offset, len);
		if (!dissector_try_uint(dissector_table, protocol, next_tvb, info->pinfo, tree))
			call_data_dissector(next_tvb, info->pinfo, tree);
		return 1;
	case WS_NET_DM_ATTR_TRUNC_LEN:
		proto_tree_add_item_ret_uint(tree, hf_net_dm_trunc_len, tvb, offset, len, nl_data->encoding, &value);
		proto_item_append_text(tree, ": %u", value);
		return 1;
	case WS_NET_DM_ATTR_ORIG_LEN:
		proto_tree_add_item_ret_uint(tree, hf_net_dm_orig_len, tvb, offset, len, nl_data->encoding, &value);
		proto_item_append_text(tree, ": %u", value);
		return 1;
	case WS_NET_DM_ATTR_QUEUE_LEN:
		proto_tree_add_item_ret_uint(tree, hf_net_dm_queue_len, tvb, offset, len, nl_data->encoding, &value);
		proto_item_append_text(tree, ": %u", value);
		return 1;
	case WS_NET_DM_ATTR_STATS:
		return dissect_netlink_attributes(tvb, hf_net_dm_attrs_stats, ett_net_dm_attrs_stats, info, nl_data, tree, offset, len,
						  dissect_net_dm_attrs_stats);
	case WS_NET_DM_ATTR_HW_STATS:
		return dissect_netlink_attributes(tvb, hf_net_dm_attrs_stats, ett_net_dm_attrs_hw_stats, info, nl_data, tree, offset, len,
						  dissect_net_dm_attrs_stats);
	case WS_NET_DM_ATTR_ORIGIN:
		proto_tree_add_item(tree, hf_net_dm_origin, tvb, offset, len, nl_data->encoding);
		return 1;
	case WS_NET_DM_ATTR_HW_TRAP_GROUP_NAME:
		proto_tree_add_item_ret_string(tree, hf_net_dm_hw_trap_group_name, tvb, offset, len, ENC_ASCII | ENC_NA, wmem_packet_scope(), &str);
		proto_item_append_text(tree, ": %s", str);
		return 1;
	case WS_NET_DM_ATTR_HW_TRAP_NAME:
		proto_tree_add_item_ret_string(tree, hf_net_dm_hw_trap_name, tvb, offset, len, ENC_ASCII | ENC_NA, wmem_packet_scope(), &str);
		proto_item_append_text(tree, ": %s", str);
		return 1;
	case WS_NET_DM_ATTR_HW_ENTRIES:
		return dissect_netlink_attributes(tvb, hf_net_dm_attrs, ett_net_dm_attrs_hw_entries, info, nl_data, tree, offset, len,
						  dissect_net_dm_attrs);
	case WS_NET_DM_ATTR_HW_ENTRY:
		return dissect_netlink_attributes(tvb, hf_net_dm_attrs, ett_net_dm_attrs_hw_entry, info, nl_data, tree, offset, len,
						  dissect_net_dm_attrs);
	case WS_NET_DM_ATTR_HW_TRAP_COUNT:
		proto_tree_add_item_ret_uint(tree, hf_net_dm_hw_trap_count, tvb, offset, len, nl_data->encoding, &value);
		proto_item_append_text(tree, ": %u", value);
		return 1;
	case WS_NET_DM_ATTR_SW_DROPS:
		proto_tree_add_item(tree, hf_net_dm_sw, tvb, offset, len, nl_data->encoding);
		return 1;
	case WS_NET_DM_ATTR_HW_DROPS:
		proto_tree_add_item(tree, hf_net_dm_hw, tvb, offset, len, nl_data->encoding);
		return 1;
	case WS_NET_DM_ATTR_FLOW_ACTION_COOKIE:
		proto_tree_add_item(tree, hf_net_dm_flow_action_cookie, tvb, offset, len, ENC_NA);
		return 1;
	case WS_NET_DM_ATTR_REASON:
		proto_tree_add_item_ret_string(tree, hf_net_dm_reason, tvb, offset, len, ENC_ASCII | ENC_NA, wmem_packet_scope(), &str);
		proto_item_append_text(tree, ": %s", str);
		return 1;
	default:
		return 0;
	}
}

static int
dissect_netlink_net_dm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	genl_info_t *genl_info = (genl_info_t *)data;
	struct netlink_net_dm_info info;
	proto_tree *nlmsg_tree;
	proto_item *pi;
	int offset;

	DISSECTOR_ASSERT(genl_info);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "net_dm");
	col_clear(pinfo->cinfo, COL_INFO);

	/* Generic netlink header */
	offset = dissect_genl_header(tvb, genl_info, genl_info->nl_data, hf_net_dm_commands);

	/* Not all commands have a payload */
	if (!tvb_reported_length_remaining(tvb, offset))
		/* XXX If you do not set the protocol item, you cannot filter on these messages */
		return offset;

	pi = proto_tree_add_item(tree, proto_netlink_net_dm, tvb, offset, -1, ENC_NA);
	nlmsg_tree = proto_item_add_subtree(pi, ett_net_dm);

	info.pinfo = pinfo;
	info.protocol = 0;

	offset = dissect_netlink_attributes_to_end(tvb, hf_net_dm_attrs, ett_net_dm_attrs, &info, genl_info->nl_data, nlmsg_tree, offset, dissect_net_dm_attrs);

	return offset;
}

void
proto_register_netlink_net_dm(void)
{
	static hf_register_info hf[] = {
		{ &hf_net_dm_commands,
			{ "Command", "net_dm.cmd",
			  FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ws_net_dm_commands_vals_ext, 0x00,
			  NULL, HFILL }
		},
		{ &hf_net_dm_attrs,
			{ "Attribute type", "net_dm.attr_type",
			  FT_UINT16, BASE_DEC | BASE_EXT_STRING, &ws_net_dm_attrs_vals_ext, NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_net_dm_alert_mode,
			{ "Alert mode", "net_dm.alert_mode",
			  FT_UINT8, BASE_DEC, VALS(ws_net_dm_alert_mode_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_net_dm_pc,
			{ "Program counter", "net_dm.pc",
			  FT_UINT64, BASE_HEX, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_net_dm_symbol,
			{ "Symbol", "net_dm.symbol",
			  FT_STRINGZ, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_net_dm_attrs_port,
			{ "Attribute type", "net_dm.port.attr_type",
			  FT_UINT16, BASE_DEC, VALS(ws_net_dm_attrs_port_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_net_dm_timestamp,
			{ "Timestamp", "net_dm.timestamp",
			  FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_net_dm_proto,
			{ "Protocol", "net_dm.proto",
			  FT_UINT16, BASE_HEX, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_net_dm_trunc_len,
			{ "Truncation length", "net_dm.trunc_len",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_net_dm_orig_len,
			{ "Original length", "net_dm.orig_len",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_net_dm_queue_len,
			{ "Queue length", "net_dm.queue_len",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_net_dm_attrs_stats,
			{ "Attribute type", "net_dm.stats.attr_type",
			  FT_UINT16, BASE_DEC, VALS(ws_net_dm_attrs_stats_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_net_dm_origin,
			{ "Packet origin", "net_dm.origin",
			  FT_UINT16, BASE_DEC, VALS(ws_net_dm_origin_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_net_dm_hw_trap_group_name,
			{ "Hardware trap group name", "net_dm.hw_trap_group_name",
			  FT_STRINGZ, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_net_dm_hw_trap_name,
			{ "Hardware trap name", "net_dm.hw_trap_name",
			  FT_STRINGZ, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_net_dm_hw_trap_count,
			{ "Hardware trap count", "net_dm.hw_trap_count",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_net_dm_sw,
			{ "Software", "net_dm.sw",
			  FT_NONE, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_net_dm_hw,
			{ "Hardware", "net_dm.hw",
			  FT_NONE, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_net_dm_port_netdev_index,
			{ "Port net device index", "net_dm.port.netdev_index",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_net_dm_port_netdev_name,
			{ "Port net device name", "net_dm.port.netdev_name",
			  FT_STRINGZ, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_net_dm_stats_dropped,
			{ "Dropped", "net_dm.stats.dropped",
			  FT_UINT64, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_net_dm_flow_action_cookie,
			{ "Flow action cookie", "net_dm.cookie",
			  FT_BYTES, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_net_dm_reason,
			{ "Reason", "net_dm.reason",
			  FT_STRINGZ, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
	};

	static int *ett[] = {
		&ett_net_dm,
		&ett_net_dm_attrs,
		&ett_net_dm_attrs_in_port,
		&ett_net_dm_attrs_stats,
		&ett_net_dm_attrs_hw_stats,
		&ett_net_dm_attrs_hw_entries,
		&ett_net_dm_attrs_hw_entry,
	};

	proto_netlink_net_dm = proto_register_protocol("Linux net_dm (network drop monitor) protocol", "net_dm", "net_dm");
	proto_register_field_array(proto_netlink_net_dm, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	netlink_net_dm_handle = register_dissector("net_dm", dissect_netlink_net_dm, proto_netlink_net_dm);
}

void
proto_reg_handoff_netlink_net_dm(void)
{
	dissector_add_string("genl.family", "NET_DM", netlink_net_dm_handle);
	sll_ltype_table = find_dissector_table("sll.ltype");
	ethertype_table = find_dissector_table("ethertype");
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
