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

#define NEW_PROTO_TREE_API

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
	guint16         family_id;
	const guint8   *family_name;
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

static int proto_netlink_generic;

static dissector_handle_t netlink_generic;
static dissector_handle_t netlink_generic_ctrl;
static dissector_table_t genl_dissector_table;

static header_field_info *hfi_netlink_generic = NULL;

#define NETLINK_GENERIC_HFI_INIT HFI_INIT(proto_netlink_generic)

static gint ett_netlink_generic = -1;
static gint ett_genl_ctrl_attr = -1;
static gint ett_genl_ctrl_ops = -1;
static gint ett_genl_ctrl_ops_attr = -1;
static gint ett_genl_ctrl_op_flags = -1;
static gint ett_genl_ctrl_groups = -1;
static gint ett_genl_ctrl_groups_attr = -1;
static gint ett_genl_nested_attr = -1;

/*
 * Maps family IDs (integers) to family names (strings) within a capture file.
 */
static wmem_map_t *genl_family_map;


static header_field_info hfi_genl_ctrl_op_id NETLINK_GENERIC_HFI_INIT =
	{ "Operation ID", "genl.ctrl.op_id", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_genl_ctrl_op_flags NETLINK_GENERIC_HFI_INIT =
	{ "Operation Flags", "genl.ctrl.op_flags", FT_UINT32, BASE_HEX,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_genl_ctrl_op_flags_admin_perm NETLINK_GENERIC_HFI_INIT =
	{ "GENL_ADMIN_PERM", "genl.ctrl.op_flags.admin_perm", FT_BOOLEAN, 32,
	  NULL, 0x01, NULL, HFILL };

static header_field_info hfi_genl_ctrl_op_flags_cmd_cap_do NETLINK_GENERIC_HFI_INIT =
	{ "GENL_CMD_CAP_DO", "genl.ctrl.op_flags.cmd_cap_do", FT_BOOLEAN, 32,
	  NULL, 0x02, NULL, HFILL };

static header_field_info hfi_genl_ctrl_op_flags_cmd_cap_dump NETLINK_GENERIC_HFI_INIT =
	{ "GENL_CMD_CAP_DUMP", "genl.ctrl.op_flags.cmd_cap_dump", FT_BOOLEAN, 32,
	  NULL, 0x04, NULL, HFILL };

static header_field_info hfi_genl_ctrl_op_flags_cmd_cap_haspol NETLINK_GENERIC_HFI_INIT =
	{ "GENL_CMD_CAP_HASPOL", "genl.ctrl.op_flags.cmd_cap_haspol", FT_BOOLEAN, 32,
	  NULL, 0x08, NULL, HFILL };

static header_field_info hfi_genl_ctrl_op_flags_uns_admin_perm NETLINK_GENERIC_HFI_INIT =
	{ "GENL_UNS_ADMIN_PERM", "genl.ctrl.op_flags.uns_admin_perm", FT_BOOLEAN, 32,
	  NULL, 0x10, NULL, HFILL };

static int * const genl_ctrl_op_flags_fields[] = {
	&hfi_genl_ctrl_op_flags_admin_perm.id,
	&hfi_genl_ctrl_op_flags_cmd_cap_do.id,
	&hfi_genl_ctrl_op_flags_cmd_cap_dump.id,
	&hfi_genl_ctrl_op_flags_cmd_cap_haspol.id,
	&hfi_genl_ctrl_op_flags_uns_admin_perm.id,
	NULL
};

static int
dissect_genl_ctrl_ops_attrs(tvbuff_t *tvb, void *data _U_, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_genl_ctrl_op_attr type = (enum ws_genl_ctrl_op_attr) nla_type;
	proto_tree *ptree = proto_tree_get_parent_tree(tree);
	guint32 value;

	switch (type) {
	case WS_CTRL_ATTR_OP_UNSPEC:
		break;
	case WS_CTRL_ATTR_OP_ID:
		if (len == 4) {
			proto_tree_add_item_ret_uint(tree, &hfi_genl_ctrl_op_id, tvb, offset, 4, nl_data->encoding, &value);
			proto_item_append_text(tree, ": %u", value);
			proto_item_append_text(ptree, ", id=%u", value);
			offset += 4;
		}
		break;
	case WS_CTRL_ATTR_OP_FLAGS:
		if (len == 4) {
			guint64 op_flags;
			/* XXX it would be nice if the flag names are appended to the tree */
			proto_tree_add_bitmask_with_flags_ret_uint64(tree, tvb, offset, &hfi_genl_ctrl_op_flags,
				ett_genl_ctrl_op_flags, genl_ctrl_op_flags_fields, nl_data->encoding, BMT_NO_FALSE, &op_flags);
			proto_item_append_text(tree, ": 0x%08x", (guint32)op_flags);
			proto_item_append_text(ptree, ", flags=0x%08x", (guint32)op_flags);
			offset += 4;
		}
		break;
	}

	return offset;
}


static header_field_info hfi_genl_ctrl_group_name NETLINK_GENERIC_HFI_INIT =
	{ "Group Name", "genl.ctrl.group_name", FT_STRINGZ, STR_ASCII,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_genl_ctrl_group_id NETLINK_GENERIC_HFI_INIT =
	{ "Group ID", "genl.ctrl.group_id", FT_UINT32, BASE_HEX,
	  NULL, 0x00, NULL, HFILL };

static int
dissect_genl_ctrl_groups_attrs(tvbuff_t *tvb, void *data _U_, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_genl_ctrl_group_attr type = (enum ws_genl_ctrl_group_attr) nla_type;
	proto_tree *ptree = proto_tree_get_parent_tree(tree);
	guint32 value;
	const guint8 *strval;

	switch (type) {
	case WS_CTRL_ATTR_MCAST_GRP_UNSPEC:
		break;
	case WS_CTRL_ATTR_MCAST_GRP_NAME:
		proto_tree_add_item_ret_string(tree, &hfi_genl_ctrl_group_name, tvb, offset, len, ENC_ASCII, wmem_packet_scope(), &strval);
		proto_item_append_text(tree, ": %s", strval);
		proto_item_append_text(ptree, ", name=%s", strval);
		offset += len;
		break;
	case WS_CTRL_ATTR_MCAST_GRP_ID:
		if (len == 4) {
			proto_tree_add_item_ret_uint(tree, &hfi_genl_ctrl_group_id, tvb, offset, 4, nl_data->encoding, &value);
			proto_item_append_text(tree, ": %u", value);
			proto_item_append_text(ptree, ", id=%u", value);
			offset += 4;
		}
		break;
	}

	return offset;
}


static header_field_info hfi_genl_ctrl_family_id NETLINK_GENERIC_HFI_INIT =
	{ "Family ID", "genl.ctrl.family_id", FT_UINT16, BASE_HEX,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_genl_ctrl_family_name NETLINK_GENERIC_HFI_INIT =
	{ "Family Name", "genl.ctrl.family_name", FT_STRINGZ, STR_ASCII,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_genl_ctrl_version NETLINK_GENERIC_HFI_INIT =
	{ "Version", "genl.ctrl.version", FT_UINT32, BASE_DEC,
	  NULL, 0x00, "Family-specific version number", HFILL };

static header_field_info hfi_genl_ctrl_hdrsize NETLINK_GENERIC_HFI_INIT =
	{ "Header Size", "genl.ctrl.hdrsize", FT_UINT32, BASE_DEC,
	  NULL, 0x00, "Size of family-specific header", HFILL };

static header_field_info hfi_genl_ctrl_maxattr NETLINK_GENERIC_HFI_INIT =
	{ "Maximum Attributes", "genl.ctrl.maxattr", FT_UINT32, BASE_DEC,
	  NULL, 0x00, "Maximum number of attributes", HFILL };

static header_field_info hfi_genl_ctrl_ops_attr NETLINK_GENERIC_HFI_INIT =
	{ "Type", "genl.ctrl.ops_attr", FT_UINT16, BASE_DEC,
	  VALS(genl_ctrl_op_attr_vals), NLA_TYPE_MASK, NULL, HFILL };

static header_field_info hfi_genl_ctrl_groups_attr NETLINK_GENERIC_HFI_INIT =
	{ "Type", "genl.ctrl.groups_attr", FT_UINT16, BASE_DEC,
	  VALS(genl_ctrl_group_attr_vals), NLA_TYPE_MASK, NULL, HFILL };

static int
dissect_genl_ctrl_attrs(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_genl_ctrl_attr type = (enum ws_genl_ctrl_attr) nla_type;
	genl_ctrl_info_t *info = (genl_ctrl_info_t *) data;
	guint32 value;

	switch (type) {
	case WS_CTRL_CMD_UNSPEC:
		break;
	case WS_CTRL_ATTR_FAMILY_ID:
		if (len == 2) {
			proto_tree_add_item_ret_uint(tree, &hfi_genl_ctrl_family_id, tvb, offset, 2, nl_data->encoding, &value);
			proto_item_append_text(tree, ": %#x", value);
			info->family_id = value;
			offset += 2;
		}
		break;
	case WS_CTRL_ATTR_FAMILY_NAME:
		proto_tree_add_item_ret_string(tree, &hfi_genl_ctrl_family_name, tvb, offset, len, ENC_ASCII, wmem_packet_scope(), &info->family_name);
		proto_item_append_text(tree, ": %s", info->family_name);
		offset += len;
		break;
	case WS_CTRL_ATTR_VERSION:
		if (len == 4) {
			proto_tree_add_item_ret_uint(tree, &hfi_genl_ctrl_version, tvb, offset, 4, nl_data->encoding, &value);
			proto_item_append_text(tree, ": %u", value);
			offset += 4;
		}
		break;
	case WS_CTRL_ATTR_HDRSIZE:
		if (len == 4) {
			proto_tree_add_item_ret_uint(tree, &hfi_genl_ctrl_hdrsize, tvb, offset, 4, nl_data->encoding, &value);
			proto_item_append_text(tree, ": %u", value);
			offset += 4;
		}
		break;
	case WS_CTRL_ATTR_MAXATTR:
		if (len == 4) {
			proto_tree_add_item_ret_uint(tree, &hfi_genl_ctrl_maxattr, tvb, offset, 4, nl_data->encoding, &value);
			proto_item_append_text(tree, ": %u", value);
			offset += 4;
		}
		break;
	case WS_CTRL_ATTR_OPS:
		offset = dissect_netlink_attributes_array(tvb, &hfi_genl_ctrl_ops_attr, ett_genl_ctrl_ops, ett_genl_ctrl_ops_attr, info, nl_data, tree, offset, len, dissect_genl_ctrl_ops_attrs);
		break;
	case WS_CTRL_ATTR_MCAST_GROUPS:
		offset = dissect_netlink_attributes_array(tvb, &hfi_genl_ctrl_groups_attr, ett_genl_ctrl_groups, ett_genl_ctrl_groups_attr, info, nl_data, tree, offset, len, dissect_genl_ctrl_groups_attrs);
		break;
	}

	return offset;
}

static header_field_info hfi_genl_ctrl_cmd NETLINK_GENERIC_HFI_INIT =
	{ "Command", "genl.ctrl.cmd", FT_UINT8, BASE_DEC,
	  VALS(genl_ctrl_cmds), 0x00, "Generic Netlink command", HFILL };

static header_field_info hfi_genl_ctrl_attr NETLINK_GENERIC_HFI_INIT =
	{ "Type", "genl.ctrl_attr", FT_UINT16, BASE_DEC,
	  VALS(genl_ctrl_attr_vals), NLA_TYPE_MASK, NULL, HFILL };

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

	offset = dissect_genl_header(tvb, genl_info, genl_info->nl_data, &hfi_genl_ctrl_cmd);

	/* Return if command has no payload */
	if (!tvb_reported_length_remaining(tvb, offset))
	    return offset;

	dissect_netlink_attributes(tvb, &hfi_genl_ctrl_attr, ett_genl_ctrl_attr, &info, genl_info->nl_data, genl_info->genl_tree, offset, -1, dissect_genl_ctrl_attrs);

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


static header_field_info hfi_genl_family_id NETLINK_GENERIC_HFI_INIT =
	{ "Family ID", "genl.family_id", FT_UINT8, BASE_HEX,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_genl_cmd NETLINK_GENERIC_HFI_INIT =
	{ "Command", "genl.cmd", FT_UINT8, BASE_DEC,
	  NULL, 0x00, "Generic Netlink command", HFILL };

static header_field_info hfi_genl_version NETLINK_GENERIC_HFI_INIT =
	{ "Family Version", "genl.version", FT_UINT8, BASE_DEC,
	  NULL, 0x00, "Family-specfic version", HFILL };

static header_field_info hfi_genl_reserved NETLINK_GENERIC_HFI_INIT =
	{ "Reserved", "genl.reserved", FT_NONE, BASE_NONE,
	  NULL, 0x00, NULL, HFILL };

int dissect_genl_header(tvbuff_t *tvb, genl_info_t *genl_info, struct packet_netlink_data *nl_data, header_field_info *hfi_cmd)
{
	int offset = 0;

	if (!hfi_cmd) {
		hfi_cmd = &hfi_genl_cmd;
	}
	proto_tree_add_item(genl_info->genl_tree, hfi_cmd, tvb, offset, 1, ENC_NA);
	offset++;
	/* XXX Family dissectors may want to know this */
	proto_tree_add_item(genl_info->genl_tree, &hfi_genl_version, tvb, offset, 1, ENC_NA);
	offset++;
	proto_tree_add_item(genl_info->genl_tree, &hfi_genl_reserved, tvb, offset, 2, nl_data->encoding);
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

	pi = proto_tree_add_item(tree, proto_registrar_get_nth(proto_netlink_generic), tvb, 0, -1, ENC_NA);
	nlmsg_tree = proto_item_add_subtree(pi, ett_netlink_generic);

	/* Netlink message header (nlmsghdr) */
	offset = dissect_netlink_header(tvb, nlmsg_tree, offset, nl_data->encoding, &hfi_genl_family_id, &pi_type);
	family_name = (const char *)wmem_map_lookup(genl_family_map, GUINT_TO_POINTER(nl_data->type));
	proto_item_append_text(pi_type, " (%s)", family_name ? family_name : "Unknown");

	/* Populate info from Generic Netlink message header (genlmsghdr) */
	info.nl_data = nl_data;
	info.genl_tree = nlmsg_tree;
	info.cmd = tvb_get_guint8(tvb, offset);

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
	offset = dissect_genl_header(next_tvb, &info, nl_data, NULL);
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
#ifndef HAVE_HFI_SECTION_INIT
	static header_field_info *hfi[] = {
		&hfi_genl_family_id,
		&hfi_genl_cmd,
		&hfi_genl_version,
		&hfi_genl_reserved,
		&hfi_genl_ctrl_attr,
		/* Controller */
		&hfi_genl_ctrl_cmd,
		&hfi_genl_ctrl_family_id,
		&hfi_genl_ctrl_family_name,
		&hfi_genl_ctrl_version,
		&hfi_genl_ctrl_hdrsize,
		&hfi_genl_ctrl_maxattr,
		&hfi_genl_ctrl_ops_attr,
		&hfi_genl_ctrl_groups_attr,
		&hfi_genl_ctrl_op_id,
		&hfi_genl_ctrl_op_flags,
		&hfi_genl_ctrl_op_flags_admin_perm,
		&hfi_genl_ctrl_op_flags_cmd_cap_do,
		&hfi_genl_ctrl_op_flags_cmd_cap_dump,
		&hfi_genl_ctrl_op_flags_cmd_cap_haspol,
		&hfi_genl_ctrl_op_flags_uns_admin_perm,
		&hfi_genl_ctrl_group_name,
		&hfi_genl_ctrl_group_id,
	};
#endif

	static gint *ett[] = {
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
	hfi_netlink_generic = proto_registrar_get_nth(proto_netlink_generic);

	proto_register_fields(proto_netlink_generic, hfi, array_length(hfi));
	proto_register_subtree_array(ett, array_length(ett));

	netlink_generic = create_dissector_handle(dissect_netlink_generic, proto_netlink_generic);
	netlink_generic_ctrl = create_dissector_handle(dissect_genl_ctrl, proto_netlink_generic);
	genl_dissector_table = register_dissector_table(
		"genl.family",
		"Linux Generic Netlink family name",
		proto_netlink_generic, FT_STRING,
		BASE_NONE
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
