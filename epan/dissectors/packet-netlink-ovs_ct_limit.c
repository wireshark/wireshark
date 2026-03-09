/* packet-netlink-ovs_ct_limit.c
 * Routines for Open vSwitch conntrack zone limit netlink protocol dissection
 * Copyright 2026, Red Hat Inc.
 * By Timothy Redaelli <tredaelli@redhat.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* ovs_ct_limit manages Open vSwitch conntrack zone limits via
 * Generic Netlink
 *
 * Relevant Linux kernel header file:
 * include/uapi/linux/openvswitch.h
 */

#include "config.h"

#include <epan/packet.h>

#include "packet-netlink.h"

void proto_register_netlink_ovs_ct_limit(void);
void proto_reg_handoff_netlink_ovs_ct_limit(void);

/* from <include/uapi/linux/openvswitch.h> prefixed with WS_ */
enum ws_ovs_ct_limit_cmd {
	WS_OVS_CT_LIMIT_CMD_UNSPEC,
	WS_OVS_CT_LIMIT_CMD_SET,
	WS_OVS_CT_LIMIT_CMD_DEL,
	WS_OVS_CT_LIMIT_CMD_GET,
};

enum ws_ovs_ct_limit_attr {
	WS_OVS_CT_LIMIT_ATTR_UNSPEC,
	WS_OVS_CT_LIMIT_ATTR_ZONE_LIMIT,
};

static const value_string ws_ovs_ct_limit_commands_vals[] = {
	{ WS_OVS_CT_LIMIT_CMD_UNSPEC,	"OVS_CT_LIMIT_CMD_UNSPEC" },
	{ WS_OVS_CT_LIMIT_CMD_SET,	"OVS_CT_LIMIT_CMD_SET" },
	{ WS_OVS_CT_LIMIT_CMD_DEL,	"OVS_CT_LIMIT_CMD_DEL" },
	{ WS_OVS_CT_LIMIT_CMD_GET,	"OVS_CT_LIMIT_CMD_GET" },
	{ 0, NULL }
};

static const value_string ws_ovs_ct_limit_attr_vals[] = {
	{ WS_OVS_CT_LIMIT_ATTR_UNSPEC,		"OVS_CT_LIMIT_ATTR_UNSPEC" },
	{ WS_OVS_CT_LIMIT_ATTR_ZONE_LIMIT,	"OVS_CT_LIMIT_ATTR_ZONE_LIMIT" },
	{ 0, NULL }
};

static dissector_handle_t netlink_ovs_ct_limit_handle;

static int proto_netlink_ovs_ct_limit;

static int hf_ovs_ct_limit_commands;
static int hf_ovs_ct_limit_dp_ifindex;
static int hf_ovs_ct_limit_attr;
static int hf_ovs_ct_limit_zone_id;
static int hf_ovs_ct_limit_limit;
static int hf_ovs_ct_limit_count;

static int ett_ovs_ct_limit;
static int ett_ovs_ct_limit_attrs;
static int ett_ovs_ct_limit_zone;

static int
dissect_ovs_ct_limit_attrs(tvbuff_t *tvb, void *data _U_,
	struct packet_netlink_data *nl_data, proto_tree *tree,
	int nla_type, int offset, int len)
{
	enum ws_ovs_ct_limit_attr type =
		(enum ws_ovs_ct_limit_attr) nla_type;

	switch (type) {
	case WS_OVS_CT_LIMIT_ATTR_ZONE_LIMIT:
		/* struct ovs_zone_limit: zone_id(i32)+limit(u32)+
		 * count(u32)=12 */
		{
			int off = offset;
			int remaining = len;

			while (remaining >= 12) {
				proto_item *pi;
				proto_tree *ptree;
				int32_t zone_id;

				zone_id = tvb_get_int32(tvb, off,
					nl_data->encoding);
				pi = proto_tree_add_subtree_format(tree, tvb,
					off, 12, ett_ovs_ct_limit_zone, NULL,
					"Zone Limit (zone %d)", zone_id);
				ptree = proto_item_add_subtree(pi,
					ett_ovs_ct_limit_zone);
				proto_tree_add_item(ptree,
					hf_ovs_ct_limit_zone_id,
					tvb, off, 4, nl_data->encoding);
				off += 4;
				proto_tree_add_item(ptree,
					hf_ovs_ct_limit_limit,
					tvb, off, 4, nl_data->encoding);
				off += 4;
				proto_tree_add_item(ptree,
					hf_ovs_ct_limit_count,
					tvb, off, 4, nl_data->encoding);
				off += 4;
				remaining -= 12;
			}
		}
		return 1;

	default:
		return 0;
	}
}

static int
dissect_netlink_ovs_ct_limit(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, void *data)
{
	genl_info_t *genl_info = (genl_info_t *) data;
	proto_tree *nlmsg_tree;
	proto_item *pi;
	int offset;

	DISSECTOR_ASSERT(genl_info);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ovs_ct_limit");
	col_clear(pinfo->cinfo, COL_INFO);

	offset = dissect_genl_header(tvb, genl_info, genl_info->nl_data,
		hf_ovs_ct_limit_commands);

	/* OVS header (dp_ifindex) */
	if (tvb_reported_length_remaining(tvb, offset) < 4)
		return offset;

	pi = proto_tree_add_item(tree, proto_netlink_ovs_ct_limit, tvb,
		offset, -1, ENC_NA);
	nlmsg_tree = proto_item_add_subtree(pi, ett_ovs_ct_limit);

	proto_tree_add_item(nlmsg_tree, hf_ovs_ct_limit_dp_ifindex, tvb,
		offset, 4, genl_info->nl_data->encoding);
	offset += 4;

	if (!tvb_reported_length_remaining(tvb, offset))
		return offset;

	offset = dissect_netlink_attributes_to_end(tvb, hf_ovs_ct_limit_attr,
		ett_ovs_ct_limit_attrs, NULL, genl_info->nl_data, nlmsg_tree,
		offset, dissect_ovs_ct_limit_attrs);

	return offset;
}

void
proto_register_netlink_ovs_ct_limit(void)
{
	static hf_register_info hf[] = {
		{ &hf_ovs_ct_limit_commands,
			{ "Command", "ovs_ct_limit.cmd",
			  FT_UINT8, BASE_DEC,
			  VALS(ws_ovs_ct_limit_commands_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_ovs_ct_limit_dp_ifindex,
			{ "Datapath ifindex", "ovs_ct_limit.dp_ifindex",
			  FT_INT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_ct_limit_attr,
			{ "Attribute type", "ovs_ct_limit.attr_type",
			  FT_UINT16, BASE_DEC,
			  VALS(ws_ovs_ct_limit_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_ovs_ct_limit_zone_id,
			{ "Zone ID", "ovs_ct_limit.zone_id",
			  FT_INT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_ct_limit_limit,
			{ "Limit", "ovs_ct_limit.limit",
			  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_ovs_ct_limit_count,
			{ "Count", "ovs_ct_limit.count",
			  FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
	};

	static int *ett[] = {
		&ett_ovs_ct_limit,
		&ett_ovs_ct_limit_attrs,
		&ett_ovs_ct_limit_zone,
	};

	proto_netlink_ovs_ct_limit = proto_register_protocol(
		"Linux ovs_ct_limit (Open vSwitch CT Limit) protocol",
		"ovs_ct_limit", "ovs_ct_limit");
	proto_register_field_array(proto_netlink_ovs_ct_limit, hf,
		array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	netlink_ovs_ct_limit_handle = register_dissector("ovs_ct_limit",
		dissect_netlink_ovs_ct_limit, proto_netlink_ovs_ct_limit);
}

void
proto_reg_handoff_netlink_ovs_ct_limit(void)
{
	dissector_add_string("genl.family", "ovs_ct_limit",
		netlink_ovs_ct_limit_handle);
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
