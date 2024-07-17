/* packet-netlink-generic.c
 * Dissector for Linux Generic Netlink.
 *
 * Copyright (c) 2017, Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-netlink.h"

/*
 * Documentation:
 * https://wiki.linuxfoundation.org/networking/generic_netlink_howto#message-format
 * include/uapi/linux/netlink.h
 * include/uapi/linux/genetlink.h
 *
 * For the meaning of fields in genlmsghdr, see genlmsg_put in
 * net/netlink/genetlink.c, note that it has no user-specific message header
 * (genl_ctrl.hdr_size==0).
 */

void proto_register_netlink_generic(void);
void proto_reg_handoff_netlink_generic(void);

typedef struct {
	/* Values parsed from the attributes (only valid in this packet). */
	uint16_t        family_id;
	const uint8_t  *family_name;
} genl_ctrl_info_t;

/* from include/uapi/linux/genetlink.h */
enum {
	WS_CTRL_CMD_UNSPEC,
	WS_CTRL_CMD_NEWFAMILY,
	WS_CTRL_CMD_DELFAMILY,
	WS_CTRL_CMD_GETFAMILY,
	WS_CTRL_CMD_NEWOPS,
	WS_CTRL_CMD_DELOPS,
	WS_CTRL_CMD_GETOPS,
	WS_CTRL_CMD_NEWMCAST_GRP,
	WS_CTRL_CMD_DELMCAST_GRP,
	WS_CTRL_CMD_GETMCAST_GRP,
	WS_CTRL_CMD_GETPOLICY,
};

enum ws_genl_ctrl_attr {
	WS_CTRL_ATTR_UNSPEC,
	WS_CTRL_ATTR_FAMILY_ID,
	WS_CTRL_ATTR_FAMILY_NAME,
	WS_CTRL_ATTR_VERSION,
	WS_CTRL_ATTR_HDRSIZE,
	WS_CTRL_ATTR_MAXATTR,
	WS_CTRL_ATTR_OPS,
	WS_CTRL_ATTR_MCAST_GROUPS,
	WS_CTRL_ATTR_POLICY,
	WS_CTRL_ATTR_OP_POLICY,
	WS_CTRL_ATTR_OP,
};

enum ws_genl_ctrl_op_attr {
	WS_CTRL_ATTR_OP_UNSPEC,
	WS_CTRL_ATTR_OP_ID,
	WS_CTRL_ATTR_OP_FLAGS,
};

enum ws_genl_ctrl_group_attr {
	WS_CTRL_ATTR_MCAST_GRP_UNSPEC,
	WS_CTRL_ATTR_MCAST_GRP_NAME,
	WS_CTRL_ATTR_MCAST_GRP_ID,
};

#define WS_GENL_ID_CTRL 0x10
#define GENL_CTRL_NAME "nlctrl"

static const value_string genl_ctrl_cmds[] = {
	{ WS_CTRL_CMD_UNSPEC,           "CTRL_CMD_UNSPEC" },
	{ WS_CTRL_CMD_NEWFAMILY,        "CTRL_CMD_NEWFAMILY" },
	{ WS_CTRL_CMD_DELFAMILY,        "CTRL_CMD_DELFAMILY" },
	{ WS_CTRL_CMD_GETFAMILY,        "CTRL_CMD_GETFAMILY" },
	{ WS_CTRL_CMD_NEWOPS,           "CTRL_CMD_NEWOPS" },
	{ WS_CTRL_CMD_DELOPS,           "CTRL_CMD_DELOPS" },
	{ WS_CTRL_CMD_GETOPS,           "CTRL_CMD_GETOPS" },
	{ WS_CTRL_CMD_NEWMCAST_GRP,     "CTRL_CMD_NEWMCAST_GRP" },
	{ WS_CTRL_CMD_DELMCAST_GRP,     "CTRL_CMD_DELMCAST_GRP" },
	{ WS_CTRL_CMD_GETMCAST_GRP,     "CTRL_CMD_GETMCAST_GRP" },
	{ WS_CTRL_CMD_GETPOLICY,        "CTRL_CMD_GETPOLICY" },
	{ 0, NULL }
};

static const value_string genl_ctrl_attr_vals[] = {
	{ WS_CTRL_ATTR_UNSPEC,          "CTRL_ATTR_UNSPEC" },
	{ WS_CTRL_ATTR_FAMILY_ID,       "CTRL_ATTR_FAMILY_ID" },
	{ WS_CTRL_ATTR_FAMILY_NAME,     "CTRL_ATTR_FAMILY_NAME" },
	{ WS_CTRL_ATTR_VERSION,         "CTRL_ATTR_VERSION" },
	{ WS_CTRL_ATTR_HDRSIZE,         "CTRL_ATTR_HDRSIZE" },
	{ WS_CTRL_ATTR_MAXATTR,         "CTRL_ATTR_MAXATTR" },
	{ WS_CTRL_ATTR_OPS,             "CTRL_ATTR_OPS" },
	{ WS_CTRL_ATTR_MCAST_GROUPS,    "CTRL_ATTR_MCAST_GROUPS" },
	{ WS_CTRL_ATTR_POLICY,          "CTRL_ATTR_POLICY" },
	{ WS_CTRL_ATTR_OP_POLICY,       "CTRL_ATTR_OP_POLICY" },
	{ WS_CTRL_ATTR_OP,              "CTRL_ATTR_OP" },
	{ 0, NULL }
};

static const value_string genl_ctrl_op_attr_vals[] = {
	{ WS_CTRL_ATTR_OP_UNSPEC,       "CTRL_ATTR_OP_UNSPEC" },
	{ WS_CTRL_ATTR_OP_ID,           "CTRL_ATTR_OP_ID" },
	{ WS_CTRL_ATTR_OP_FLAGS,        "CTRL_ATTR_OP_FLAGS" },
	{ 0, NULL }
};

static const value_string genl_ctrl_group_attr_vals[] = {
	{ WS_CTRL_ATTR_MCAST_GRP_UNSPEC, "CTRL_ATTR_MCAST_GRP_UNSPEC" },
	{ WS_CTRL_ATTR_MCAST_GRP_NAME,  "CTRL_ATTR_MCAST_GRP_NAME" },
	{ WS_CTRL_ATTR_MCAST_GRP_ID,    "CTRL_ATTR_MCAST_GRP_ID" },
	{ 0, NULL }
};

static dissector_handle_t netlink_generic;
static dissector_handle_t netlink_generic_ctrl;
static dissector_table_t genl_dissector_table;

static int proto_netlink_generic;

static int hf_genl_cmd;
static int hf_genl_ctrl_attr;
static int hf_genl_ctrl_cmd;
static int hf_genl_ctrl_family_id;
static int hf_genl_ctrl_family_name;
static int hf_genl_ctrl_group_id;
static int hf_genl_ctrl_group_name;
static int hf_genl_ctrl_groups_attr;
static int hf_genl_ctrl_hdrsize;
static int hf_genl_ctrl_maxattr;
static int hf_genl_ctrl_op_flags;
static int hf_genl_ctrl_op_flags_admin_perm;
static int hf_genl_ctrl_op_flags_cmd_cap_do;
static int hf_genl_ctrl_op_flags_cmd_cap_dump;
static int hf_genl_ctrl_op_flags_cmd_cap_haspol;
static int hf_genl_ctrl_op_flags_uns_admin_perm;
static int hf_genl_ctrl_op_id;
static int hf_genl_ctrl_ops_attr;
static int hf_genl_ctrl_version;
static int hf_genl_family_id;
static int hf_genl_reserved;
static int hf_genl_version;

static int ett_netlink_generic;
static int ett_genl_ctrl_attr;
static int ett_genl_ctrl_ops;
static int ett_genl_ctrl_ops_attr;
static int ett_genl_ctrl_op_flags;
static int ett_genl_ctrl_groups;
static int ett_genl_ctrl_groups_attr;
static int ett_genl_nested_attr;

/*
 * Maps family IDs (integers) to family names (strings) within a capture file.
 */
static wmem_map_t *genl_family_map;

static int * const genl_ctrl_op_flags_fields[] = {
	&hf_genl_ctrl_op_flags_admin_perm,
	&hf_genl_ctrl_op_flags_cmd_cap_do,
	&hf_genl_ctrl_op_flags_cmd_cap_dump,
	&hf_genl_ctrl_op_flags_cmd_cap_haspol,
	&hf_genl_ctrl_op_flags_uns_admin_perm,
	NULL
};

static int
dissect_genl_ctrl_ops_attrs(tvbuff_t *tvb, void *data _U_, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_genl_ctrl_op_attr type = (enum ws_genl_ctrl_op_attr) nla_type;
	proto_tree *ptree = proto_tree_get_parent_tree(tree);
	uint32_t value;

	switch (type) {
	case WS_CTRL_ATTR_OP_UNSPEC:
		break;
	case WS_CTRL_ATTR_OP_ID:
		if (len == 4) {
			proto_tree_add_item_ret_uint(tree, hf_genl_ctrl_op_id, tvb, offset, 4, nl_data->encoding, &value);
			proto_item_append_text(tree, ": %u", value);
			proto_item_append_text(ptree, ", id=%u", value);
			offset += 4;
		}
		break;
	case WS_CTRL_ATTR_OP_FLAGS:
		if (len == 4) {
			uint64_t op_flags;
			/* XXX it would be nice if the flag names are appended to the tree */
			proto_tree_add_bitmask_with_flags_ret_uint64(tree, tvb, offset, hf_genl_ctrl_op_flags,
				ett_genl_ctrl_op_flags, genl_ctrl_op_flags_fields, nl_data->encoding, BMT_NO_FALSE, &op_flags);
			proto_item_append_text(tree, ": 0x%08x", (uint32_t)op_flags);
			proto_item_append_text(ptree, ", flags=0x%08x", (uint32_t)op_flags);
			offset += 4;
		}
		break;
	}

	return offset;
}

static int
dissect_genl_ctrl_groups_attrs(tvbuff_t *tvb, void *data _U_, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_genl_ctrl_group_attr type = (enum ws_genl_ctrl_group_attr) nla_type;
	proto_tree *ptree = proto_tree_get_parent_tree(tree);
	uint32_t value;
	const uint8_t *strval;

	switch (type) {
	case WS_CTRL_ATTR_MCAST_GRP_UNSPEC:
		break;
	case WS_CTRL_ATTR_MCAST_GRP_NAME:
		proto_tree_add_item_ret_string(tree, hf_genl_ctrl_group_name, tvb, offset, len, ENC_ASCII, wmem_packet_scope(), &strval);
		proto_item_append_text(tree, ": %s", strval);
		proto_item_append_text(ptree, ", name=%s", strval);
		offset += len;
		break;
	case WS_CTRL_ATTR_MCAST_GRP_ID:
		if (len == 4) {
			proto_tree_add_item_ret_uint(tree, hf_genl_ctrl_group_id, tvb, offset, 4, nl_data->encoding, &value);
			proto_item_append_text(tree, ": %u", value);
			proto_item_append_text(ptree, ", id=%u", value);
			offset += 4;
		}
		break;
	}

	return offset;
}

static int
dissect_genl_ctrl_attrs(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_genl_ctrl_attr type = (enum ws_genl_ctrl_attr) nla_type;
	genl_ctrl_info_t *info = (genl_ctrl_info_t *) data;
	uint32_t value;

	switch (type) {
	case WS_CTRL_CMD_UNSPEC:
		break;
	case WS_CTRL_ATTR_FAMILY_ID:
		if (len == 2) {
			proto_tree_add_item_ret_uint(tree, hf_genl_ctrl_family_id, tvb, offset, 2, nl_data->encoding, &value);
			proto_item_append_text(tree, ": %#x", value);
			info->family_id = value;
			offset += 2;
		}
		break;
	case WS_CTRL_ATTR_FAMILY_NAME:
		proto_tree_add_item_ret_string(tree, hf_genl_ctrl_family_name, tvb, offset, len, ENC_ASCII, wmem_packet_scope(), &info->family_name);
		proto_item_append_text(tree, ": %s", info->family_name);
		offset += len;
		break;
	case WS_CTRL_ATTR_VERSION:
		if (len == 4) {
			proto_tree_add_item_ret_uint(tree, hf_genl_ctrl_version, tvb, offset, 4, nl_data->encoding, &value);
			proto_item_append_text(tree, ": %u", value);
			offset += 4;
		}
		break;
	case WS_CTRL_ATTR_HDRSIZE:
		if (len == 4) {
			proto_tree_add_item_ret_uint(tree, hf_genl_ctrl_hdrsize, tvb, offset, 4, nl_data->encoding, &value);
			proto_item_append_text(tree, ": %u", value);
			offset += 4;
		}
		break;
	case WS_CTRL_ATTR_MAXATTR:
		if (len == 4) {
			proto_tree_add_item_ret_uint(tree, hf_genl_ctrl_maxattr, tvb, offset, 4, nl_data->encoding, &value);
			proto_item_append_text(tree, ": %u", value);
			offset += 4;
		}
		break;
	case WS_CTRL_ATTR_OPS:
		offset = dissect_netlink_attributes_array(tvb, hf_genl_ctrl_ops_attr, ett_genl_ctrl_ops, ett_genl_ctrl_ops_attr, info, nl_data, tree, offset, len, dissect_genl_ctrl_ops_attrs);
		break;
	case WS_CTRL_ATTR_MCAST_GROUPS:
		offset = dissect_netlink_attributes_array(tvb, hf_genl_ctrl_groups_attr, ett_genl_ctrl_groups, ett_genl_ctrl_groups_attr, info, nl_data, tree, offset, len, dissect_genl_ctrl_groups_attrs);
		break;
	case WS_CTRL_ATTR_POLICY:
	case WS_CTRL_ATTR_OP_POLICY:
	case WS_CTRL_ATTR_OP:
		break;
	}

	return offset;
}

static int
dissect_genl_ctrl(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data)
{
	genl_info_t *genl_info = (genl_info_t *) data;
	genl_ctrl_info_t info;
	int offset;

	if (!genl_info) {
		return 0;
	}

	info.family_id = 0;
	info.family_name = NULL;

	offset = dissect_genl_header(tvb, genl_info, genl_info->nl_data, hf_genl_ctrl_cmd);

	/* Return if command has no payload */
	if (!tvb_reported_length_remaining(tvb, offset))
	    return offset;

	dissect_netlink_attributes_to_end(tvb, hf_genl_ctrl_attr, ett_genl_ctrl_attr, &info, genl_info->nl_data, genl_info->genl_tree, offset, dissect_genl_ctrl_attrs);

	/*
	 * Remember association of dynamic ID with the family name such that
	 * future packets can be linked to a protocol.
	 * Do not allow overwriting our control protocol.
	 */
	if (info.family_id && info.family_id != WS_GENL_ID_CTRL && info.family_name) {
		wmem_map_insert(genl_family_map, GUINT_TO_POINTER(info.family_id), wmem_strdup(wmem_file_scope(), info.family_name));
	}

	return tvb_captured_length(tvb);
}

int dissect_genl_header(tvbuff_t *tvb, genl_info_t *genl_info, struct packet_netlink_data *nl_data, int hf_cmd)
{
	int offset = 0;

	if (hf_cmd <= 0) {
		hf_cmd = hf_genl_cmd;
	}
	proto_tree_add_item(genl_info->genl_tree, hf_cmd, tvb, offset, 1, ENC_NA);
	offset++;
	/* XXX Family dissectors may want to know this */
	proto_tree_add_item(genl_info->genl_tree, hf_genl_version, tvb, offset, 1, ENC_NA);
	offset++;
	proto_tree_add_item(genl_info->genl_tree, hf_genl_reserved, tvb, offset, 2, nl_data->encoding);
	offset += 2;
	return offset;
}

static int
dissect_netlink_generic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	struct packet_netlink_data *nl_data = (struct packet_netlink_data *) data;
	genl_info_t info;
	proto_tree *nlmsg_tree;
	proto_item *pi, *pi_type;
	const char *family_name;
	tvbuff_t *next_tvb;
	int offset = 0;

	DISSECTOR_ASSERT(nl_data && nl_data->magic == PACKET_NETLINK_MAGIC);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Netlink generic");
	col_clear(pinfo->cinfo, COL_INFO);

	pi = proto_tree_add_item(tree, proto_netlink_generic, tvb, 0, -1, ENC_NA);
	nlmsg_tree = proto_item_add_subtree(pi, ett_netlink_generic);

	/* Netlink message header (nlmsghdr) */
	offset = dissect_netlink_header(tvb, nlmsg_tree, offset, nl_data->encoding, hf_genl_family_id, &pi_type);
	family_name = (const char *)wmem_map_lookup(genl_family_map, GUINT_TO_POINTER(nl_data->type));
	proto_item_append_text(pi_type, " (%s)", family_name ? family_name : "Unknown");

	/* Populate info from Generic Netlink message header (genlmsghdr) */
	info.nl_data = nl_data;
	info.genl_tree = nlmsg_tree;
	info.cmd = tvb_get_uint8(tvb, offset);

	/* Optional user-specific message header and optional message payload. */
	next_tvb = tvb_new_subset_remaining(tvb, offset);
	if (family_name) {
		int ret;
		/* Invoke subdissector with genlmsghdr present. */
		ret = dissector_try_string(genl_dissector_table, family_name, next_tvb, pinfo, tree, &info);
		if (ret) {
			return ret;
		}
	}

	/* No subdissector added the genl header, do it now. */
	offset = dissect_genl_header(next_tvb, &info, nl_data, -1);
	if (tvb_reported_length_remaining(tvb, offset)) {
		next_tvb = tvb_new_subset_remaining(tvb, offset);
		call_data_dissector(next_tvb, pinfo, tree);
	}

	return offset;
}

static void
genl_init(void)
{
	/* Add fixed family entry (0x10 maps to "nlctrl"). */
	wmem_map_insert(genl_family_map, GUINT_TO_POINTER(WS_GENL_ID_CTRL), GENL_CTRL_NAME);
}

void
proto_register_netlink_generic(void)
{
	static hf_register_info hf[] = {
		{ &hf_genl_ctrl_op_id,
			{ "Operation ID", "genl.ctrl.op_id",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_genl_ctrl_op_flags,
			{ "Operation Flags", "genl.ctrl.op_flags",
			  FT_UINT32, BASE_HEX, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_genl_ctrl_op_flags_admin_perm,
			{ "GENL_ADMIN_PERM", "genl.ctrl.op_flags.admin_perm",
			  FT_BOOLEAN, 32, NULL, 0x00000001,
			  NULL, HFILL }
		},
		{ &hf_genl_ctrl_op_flags_cmd_cap_do,
			{ "GENL_CMD_CAP_DO", "genl.ctrl.op_flags.cmd_cap_do",
			  FT_BOOLEAN, 32, NULL, 0x00000002,
			  NULL, HFILL }
		},
		{ &hf_genl_ctrl_op_flags_cmd_cap_dump,
			{ "GENL_CMD_CAP_DUMP", "genl.ctrl.op_flags.cmd_cap_dump",
			  FT_BOOLEAN, 32, NULL, 0x00000004,
			  NULL, HFILL }
		},
		{ &hf_genl_ctrl_op_flags_cmd_cap_haspol,
			{ "GENL_CMD_CAP_HASPOL", "genl.ctrl.op_flags.cmd_cap_haspol",
			  FT_BOOLEAN, 32, NULL, 0x00000008,
			  NULL, HFILL }
		},
		{ &hf_genl_ctrl_op_flags_uns_admin_perm,
			{ "GENL_UNS_ADMIN_PERM", "genl.ctrl.op_flags.uns_admin_perm",
			  FT_BOOLEAN, 32, NULL, 0x00000010,
			  NULL, HFILL }
		},
		{ &hf_genl_ctrl_group_name,
			{ "Group Name", "genl.ctrl.group_name",
			  FT_STRINGZ, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_genl_ctrl_group_id,
			{ "Group ID", "genl.ctrl.group_id",
			  FT_UINT32, BASE_HEX, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_genl_ctrl_family_id,
			{ "Family ID", "genl.ctrl.family_id",
			  FT_UINT16, BASE_HEX, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_genl_ctrl_family_name,
			{ "Family Name", "genl.ctrl.family_name",
			  FT_STRINGZ, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_genl_ctrl_version,
			{ "Version", "genl.ctrl.version",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  "Family-specific version number", HFILL }
		},
		{ &hf_genl_ctrl_hdrsize,
			{ "Header Size", "genl.ctrl.hdrsize",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  "Size of family-specific header", HFILL }
		},
		{ &hf_genl_ctrl_maxattr,
			{ "Maximum Attributes", "genl.ctrl.maxattr",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  "Maximum number of attributes", HFILL }
		},
		{ &hf_genl_ctrl_ops_attr,
			{ "Type", "genl.ctrl.ops_attr",
			  FT_UINT16, BASE_DEC, VALS(genl_ctrl_op_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_genl_ctrl_groups_attr,
			{ "Type", "genl.ctrl.groups_attr",
			  FT_UINT16, BASE_DEC, VALS(genl_ctrl_group_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_genl_ctrl_cmd,
			{ "Command", "genl.ctrl.cmd",
			  FT_UINT8, BASE_DEC, VALS(genl_ctrl_cmds), 0x0,
			  "Generic Netlink command", HFILL }
		},
		{ &hf_genl_ctrl_attr,
			{ "Type", "genl.ctrl_attr",
			  FT_UINT16, BASE_DEC, VALS(genl_ctrl_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_genl_family_id,
			{ "Family ID", "genl.family_id",
			  FT_UINT8, BASE_HEX, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_genl_cmd,
			{ "Command", "genl.cmd",
			  FT_UINT8, BASE_DEC, NULL, 0x00,
			  "Generic Netlink command", HFILL }
		},
		{ &hf_genl_version,
			{ "Family Version", "genl.version",
			  FT_UINT8, BASE_DEC, NULL, 0x00,
			  "Family-specific version", HFILL }
		},
		{ &hf_genl_reserved,
			{ "Reserved", "genl.reserved",
			  FT_NONE, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
	};

	static int *ett[] = {
		&ett_netlink_generic,
		&ett_genl_ctrl_attr,
		&ett_genl_ctrl_ops,
		&ett_genl_ctrl_ops_attr,
		&ett_genl_ctrl_op_flags,
		&ett_genl_ctrl_groups,
		&ett_genl_ctrl_groups_attr,
		&ett_genl_nested_attr,
	};

	proto_netlink_generic = proto_register_protocol("Linux Generic Netlink protocol", "genl", "genl");
	proto_register_field_array(proto_netlink_generic, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	netlink_generic = register_dissector("genl", dissect_netlink_generic, proto_netlink_generic);
	netlink_generic_ctrl = register_dissector("genl_ctrl", dissect_genl_ctrl, proto_netlink_generic);
	genl_dissector_table = register_dissector_table(
		"genl.family",
		"Linux Generic Netlink family name",
		proto_netlink_generic, FT_STRING,
		STRING_CASE_SENSITIVE
	);

	genl_family_map = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_direct_hash, g_direct_equal);

	register_init_routine(genl_init);
}

void
proto_reg_handoff_netlink_generic(void)
{
	dissector_add_string("genl.family", GENL_CTRL_NAME, netlink_generic_ctrl);
	dissector_add_uint("netlink.protocol", WS_NETLINK_GENERIC, netlink_generic);
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
