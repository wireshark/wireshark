/* packet-netlink-psample.c
 * Routines for netlink-psample dissection
 * Based on netlink-net_dm and netlink-generic dissectors
 * Copyright 2021, Mellanox Technologies Ltd.
 * Code by Amit Cohen <amcohen@nvidia.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* psample is a netlink-based protocol via which alerts
 * about sampled packets are sent to user space
 *
 * Relevant Linux kernel header file:
 * include/uapi/linux/psample.h
 */

#define NEW_PROTO_TREE_API

#include "config.h"

#include <epan/packet.h>

#include "packet-netlink.h"
#include "packet-sll.h"

void proto_register_netlink_psample(void);
void proto_reg_handoff_netlink_psample(void);

enum ws_psample_commands {
	WS_PSAMPLE_CMD_SAMPLE,
	WS_PSAMPLE_CMD_GET_GROUP,
	WS_PSAMPLE_CMD_NEW_GROUP,
	WS_PSAMPLE_CMD_DEL_GROUP,
};

enum ws_psample_attrs {
	WS_PSAMPLE_ATTR_IIFINDEX,
	WS_PSAMPLE_ATTR_OIFINDEX,
	WS_PSAMPLE_ATTR_ORIGSIZE,
	WS_PSAMPLE_ATTR_SAMPLE_GROUP,
	WS_PSAMPLE_ATTR_GROUP_SEQ,
	WS_PSAMPLE_ATTR_SAMPLE_RATE,
	WS_PSAMPLE_ATTR_DATA,
	WS_PSAMPLE_ATTR_GROUP_REFCOUNT,
	WS_PSAMPLE_ATTR_TUNNEL,
	WS_PSAMPLE_ATTR_PAD,
	WS_PSAMPLE_ATTR_OUT_TC,
	WS_PSAMPLE_ATTR_OUT_TC_OCC,
	WS_PSAMPLE_ATTR_LATENCY,
	WS_PSAMPLE_ATTR_TIMESTAMP,
	WS_PSAMPLE_ATTR_PROTO,
};

struct netlink_psample_info {
	packet_info *pinfo;
	guint16 protocol; /* protocol for packet payload */
};

static int proto_netlink_psample = -1;

static dissector_handle_t netlink_psample_handle;
static dissector_table_t sll_ltype_table;

static header_field_info *hfi_netlink_psample = NULL;

#define NETLINK_PSAMPLE_HFI_INIT HFI_INIT(proto_netlink_psample)

static gint ett_psample = -1;
static gint ett_psample_attrs = -1;

static const value_string ws_psample_commands_vals[] = {
	{ WS_PSAMPLE_CMD_SAMPLE,		"Sample" },
	{ WS_PSAMPLE_CMD_GET_GROUP,		"Get group" },
	{ WS_PSAMPLE_CMD_NEW_GROUP,		"New group" },
	{ WS_PSAMPLE_CMD_DEL_GROUP,		"Delete group" },
	{ 0, NULL },
};

static value_string_ext ws_psample_commands_vals_ext = VALUE_STRING_EXT_INIT(ws_psample_commands_vals);

static const value_string ws_psample_attrs_vals[] = {
	{ WS_PSAMPLE_ATTR_IIFINDEX,		"Input interface index" },
	{ WS_PSAMPLE_ATTR_OIFINDEX,		"Output interface index" },
	{ WS_PSAMPLE_ATTR_ORIGSIZE,		"Original size" },
	{ WS_PSAMPLE_ATTR_SAMPLE_GROUP,		"Sample group" },
	{ WS_PSAMPLE_ATTR_GROUP_SEQ,		"Group sequence number" },
	{ WS_PSAMPLE_ATTR_SAMPLE_RATE,		"Sample rate" },
	{ WS_PSAMPLE_ATTR_DATA,			"Data" },
	{ WS_PSAMPLE_ATTR_GROUP_REFCOUNT,	"Group reference count" },
	{ WS_PSAMPLE_ATTR_TUNNEL,		"Tunnel" },
	{ WS_PSAMPLE_ATTR_PAD,			"Pad" },
	{ WS_PSAMPLE_ATTR_OUT_TC,		"Output traffic class" },
	{ WS_PSAMPLE_ATTR_OUT_TC_OCC,		"Output traffic class occupancy" },
	{ WS_PSAMPLE_ATTR_LATENCY,		"Latency" },
	{ WS_PSAMPLE_ATTR_TIMESTAMP,		"Timestamp" },
	{ WS_PSAMPLE_ATTR_PROTO,		"Protocol" },
	{ 0, NULL },
};

static value_string_ext ws_psample_attrs_vals_ext = VALUE_STRING_EXT_INIT(ws_psample_attrs_vals);

static header_field_info hfi_psample_commands NETLINK_PSAMPLE_HFI_INIT =
	{ "Command", "netlink.psample.cmd", FT_UINT8, BASE_DEC | BASE_EXT_STRING,
	  &ws_psample_commands_vals_ext, 0x00, NULL, HFILL };

static header_field_info hfi_psample_attrs NETLINK_PSAMPLE_HFI_INIT =
	{ "Attribute type", "netlink.psample.attr_type", FT_UINT16, BASE_DEC | BASE_EXT_STRING,
	  &ws_psample_attrs_vals_ext, NLA_TYPE_MASK, NULL, HFILL };

static header_field_info hfi_psample_iifindex NETLINK_PSAMPLE_HFI_INIT =
	{ "Input interface index", "netlink.psample.iifindex", FT_UINT16, BASE_HEX,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_psample_oifindex NETLINK_PSAMPLE_HFI_INIT =
	{ "Output interface index", "netlink.psample.oifindex", FT_UINT16, BASE_HEX,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_psample_origsize NETLINK_PSAMPLE_HFI_INIT =
	{ "Original size", "netlink.psample.origsize", FT_UINT32, BASE_HEX,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_psample_sample_group NETLINK_PSAMPLE_HFI_INIT =
	{ "Sample group", "netlink.psample.sample_group", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_psample_group_seq NETLINK_PSAMPLE_HFI_INIT =
	{ "Group sequence number", "netlink.psample.group_seq_num", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_psample_sample_rate NETLINK_PSAMPLE_HFI_INIT =
	{ "Sample rate", "netlink.psample.sample_rate", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_psample_tunnel NETLINK_PSAMPLE_HFI_INIT =
	{ "Tunnel", "netlink.psample.tunnel", FT_UINT32, BASE_HEX,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_psample_group_refcount NETLINK_PSAMPLE_HFI_INIT =
	{ "Group reference count", "netlink.psample.group_refcount", FT_UINT32, BASE_HEX,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_psample_out_tc NETLINK_PSAMPLE_HFI_INIT =
	{ "Output traffic class", "netlink.psample.out_tc", FT_UINT16, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_psample_out_tc_occ NETLINK_PSAMPLE_HFI_INIT =
	{ "Output traffic class occupancy", "netlink.psample.out_tc_occ", FT_UINT64, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_psample_latency NETLINK_PSAMPLE_HFI_INIT =
	{ "Latency", "netlink.psample.latency", FT_UINT64, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_psample_timestamp NETLINK_PSAMPLE_HFI_INIT =
	{ "Timestamp", "netlink.psample.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_psample_proto NETLINK_PSAMPLE_HFI_INIT =
	{ "Protocol", "netlink.psample.proto", FT_UINT16, BASE_HEX,
	  NULL, 0x00, NULL, HFILL };

static int
dissect_psample_attrs(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_psample_attrs type = (enum ws_psample_attrs) nla_type & NLA_TYPE_MASK;
	struct netlink_psample_info *info = (struct netlink_psample_info *) data;
	guint64 value64, timestamp;
	nstime_t ts_nstime;
	tvbuff_t *next_tvb;
	guint32 value;

	switch (type) {
	case WS_PSAMPLE_ATTR_IIFINDEX:
		proto_tree_add_item_ret_uint(tree, &hfi_psample_iifindex, tvb, offset, len, nl_data->encoding, &value);
		proto_item_append_text(tree, ": %u", value);
		return 1;
	case WS_PSAMPLE_ATTR_OIFINDEX:
		proto_tree_add_item_ret_uint(tree, &hfi_psample_oifindex, tvb, offset, len, nl_data->encoding, &value);
		proto_item_append_text(tree, ": %u", value);
		return 1;
	case WS_PSAMPLE_ATTR_ORIGSIZE:
		proto_tree_add_item_ret_uint(tree, &hfi_psample_origsize, tvb, offset, len, nl_data->encoding, &value);
		proto_item_append_text(tree, ": %u", value);
		return 1;
	case WS_PSAMPLE_ATTR_SAMPLE_GROUP:
		proto_tree_add_item_ret_uint(tree, &hfi_psample_sample_group, tvb, offset, len, nl_data->encoding, &value);
		proto_item_append_text(tree, ": %u", value);
		return 1;
	case WS_PSAMPLE_ATTR_GROUP_SEQ:
		proto_tree_add_item_ret_uint(tree, &hfi_psample_group_seq, tvb, offset, len, nl_data->encoding, &value);
		proto_item_append_text(tree, ": %u", value);
		return 1;
	case WS_PSAMPLE_ATTR_SAMPLE_RATE:
		proto_tree_add_item_ret_uint(tree, &hfi_psample_sample_rate, tvb, offset, len, nl_data->encoding, &value);
		proto_item_append_text(tree, ": %u", value);
		return 1;
	case WS_PSAMPLE_ATTR_DATA:
		next_tvb = tvb_new_subset_length(tvb, offset, len);
		if (!dissector_try_uint(sll_ltype_table, info->protocol, next_tvb, info->pinfo, tree))
			call_data_dissector(next_tvb, info->pinfo, tree);
		return 1;
	case WS_PSAMPLE_ATTR_GROUP_REFCOUNT:
		proto_tree_add_item_ret_uint(tree, &hfi_psample_group_refcount, tvb, offset, len, nl_data->encoding, &value);
		proto_item_append_text(tree, ": %u", value);
		return 1;
	case WS_PSAMPLE_ATTR_TUNNEL:
		/* Currently there is no support for tunnel dissection. */
		return 0;
	case WS_PSAMPLE_ATTR_OUT_TC:
		proto_tree_add_item_ret_uint(tree, &hfi_psample_out_tc, tvb, offset, len, nl_data->encoding, &value);
		proto_item_append_text(tree, ": %u", value);
		return 1;
	case WS_PSAMPLE_ATTR_OUT_TC_OCC:
		proto_tree_add_item_ret_uint64(tree, &hfi_psample_out_tc_occ, tvb, offset, len, nl_data->encoding, &value64);
		proto_item_append_text(tree, ": %"G_GUINT64_FORMAT, value64);
		return 1;
	case WS_PSAMPLE_ATTR_LATENCY:
		proto_tree_add_item_ret_uint64(tree, &hfi_psample_latency, tvb, offset, len, nl_data->encoding, &value64);
		proto_item_append_text(tree, ": %"G_GUINT64_FORMAT, value64);
		return 1;
	case WS_PSAMPLE_ATTR_TIMESTAMP:
		timestamp = tvb_get_guint64(tvb, offset, nl_data->encoding);
		ts_nstime.secs = timestamp / 1000000000;
		ts_nstime.nsecs = timestamp % 1000000000;
		proto_tree_add_time(tree, &hfi_psample_timestamp, tvb, offset, 8, &ts_nstime);
		return 1;
	case WS_PSAMPLE_ATTR_PROTO:
		info->protocol = tvb_get_guint16(tvb, offset, nl_data->encoding);
		/* This attribute encodes 'skb->protocol' and if it is greater
		 * than or equal to 1536 (0x0600), then it is an Ethertype and
		 * we need to treat the packet as Ethernet.
		 */
		if (info->protocol >= 1536 || info->protocol == LINUX_SLL_P_802_2)
			info->protocol = LINUX_SLL_P_ETHERNET;
		proto_tree_add_item(tree, &hfi_psample_proto, tvb, offset, len, nl_data->encoding);
		return 1;
	default:
		return 0;
	}
}

static int
dissect_netlink_psample(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	genl_info_t *genl_info = (genl_info_t *)data;
	struct netlink_psample_info info;
	proto_tree *nlmsg_tree;
	proto_item *pi;
	int offset;

	DISSECTOR_ASSERT(genl_info);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "psample");
	col_clear(pinfo->cinfo, COL_INFO);

	/* Generic netlink header */
	offset = dissect_genl_header(tvb, genl_info, genl_info->nl_data, &hfi_psample_commands);

	/* Not all commands have a payload */
	if (!tvb_reported_length_remaining(tvb, offset))
		/* XXX If you do not set the protocol item, you cannot filter on these messages */
		return offset;

	pi = proto_tree_add_item(tree, proto_registrar_get_nth(proto_netlink_psample), tvb, offset, -1, ENC_NA);
	nlmsg_tree = proto_item_add_subtree(pi, ett_psample);

	info.pinfo = pinfo;
	info.protocol = 0;

	offset = dissect_netlink_attributes(tvb, &hfi_psample_attrs, ett_psample_attrs, &info, genl_info->nl_data, nlmsg_tree, offset, -1, dissect_psample_attrs);

	return offset;
}

void
proto_register_netlink_psample(void)
{
#ifndef HAVE_HFI_SECTION_INIT
	static header_field_info *hfi[] = {
		&hfi_psample_commands,
		&hfi_psample_attrs,
		&hfi_psample_iifindex,
		&hfi_psample_oifindex,
		&hfi_psample_origsize,
		&hfi_psample_sample_group,
		&hfi_psample_group_seq,
		&hfi_psample_sample_rate,
		&hfi_psample_tunnel,
		&hfi_psample_group_refcount,
		&hfi_psample_out_tc,
		&hfi_psample_out_tc_occ,
		&hfi_psample_latency,
		&hfi_psample_timestamp,
		&hfi_psample_proto,
	};
#endif

	static gint *ett[] = {
		&ett_psample,
		&ett_psample_attrs,
	};

	proto_netlink_psample = proto_register_protocol("Linux psample protocol", "psample", "psample");
	hfi_netlink_psample = proto_registrar_get_nth(proto_netlink_psample);

	proto_register_fields(proto_netlink_psample, hfi, array_length(hfi));
	proto_register_subtree_array(ett, array_length(ett));

	netlink_psample_handle = create_dissector_handle(dissect_netlink_psample, proto_netlink_psample);
}

void
proto_reg_handoff_netlink_psample(void)
{
	dissector_add_string("genl.family", "psample", netlink_psample_handle);
	sll_ltype_table = find_dissector_table("sll.ltype");
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
