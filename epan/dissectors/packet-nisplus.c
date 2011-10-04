/* packet-nisplus.c
 * 2001  Ronnie Sahlberg   <See AUTHORS for email>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <time.h>

#include "packet-rpc.h"
#include "packet-nisplus.h"

static int proto_nisplus = -1;
static int hf_nisplus_procedure_v3 = -1;
static int hf_nisplus_object = -1;
static int hf_nisplus_oid = -1;
static int hf_nisplus_object_ctime = -1;
static int hf_nisplus_object_mtime = -1;
static int hf_nisplus_object_name = -1;
static int hf_nisplus_object_owner = -1;
static int hf_nisplus_object_group = -1;
static int hf_nisplus_object_domain = -1;
static int hf_nisplus_object_ttl = -1;
static int hf_nisplus_object_type = -1;
static int hf_nisplus_object_private = -1;
static int hf_nisplus_directory = -1;
static int hf_nisplus_directory_name = -1;
static int hf_nisplus_directory_type = -1;
static int hf_nisplus_directory_ttl = -1;
static int hf_nisplus_directory_mask = -1;
static int hf_nisplus_directory_mask_list = -1;
static int hf_nisplus_access_mask = -1;
static int hf_nisplus_mask_world_read = -1;
static int hf_nisplus_mask_world_modify = -1;
static int hf_nisplus_mask_world_create = -1;
static int hf_nisplus_mask_world_destroy = -1;
static int hf_nisplus_mask_group_read = -1;
static int hf_nisplus_mask_group_modify = -1;
static int hf_nisplus_mask_group_create = -1;
static int hf_nisplus_mask_group_destroy = -1;
static int hf_nisplus_mask_owner_read = -1;
static int hf_nisplus_mask_owner_modify = -1;
static int hf_nisplus_mask_owner_create = -1;
static int hf_nisplus_mask_owner_destroy = -1;
static int hf_nisplus_mask_nobody_read = -1;
static int hf_nisplus_mask_nobody_modify = -1;
static int hf_nisplus_mask_nobody_create = -1;
static int hf_nisplus_mask_nobody_destroy = -1;
static int hf_nisplus_server_name = -1;
static int hf_nisplus_key_type = -1;
static int hf_nisplus_key_data = -1;
static int hf_nisplus_servers = -1;
static int hf_nisplus_cbservers = -1;
static int hf_nisplus_server = -1;
static int hf_nisplus_endpoints = -1;
static int hf_nisplus_endpoint = -1;
static int hf_nisplus_endpoint_uaddr = -1;
static int hf_nisplus_endpoint_family = -1;
static int hf_nisplus_endpoint_proto = -1;
static int hf_nisplus_link = -1;
static int hf_nisplus_attrs_array = -1;
static int hf_nisplus_attr = -1;
static int hf_nisplus_attr_name = -1;
static int hf_nisplus_attr_val = -1;
static int hf_nisplus_entry = -1;
static int hf_nisplus_entry_type = -1;
static int hf_nisplus_entry_cols = -1;
static int hf_nisplus_entry_col = -1;
static int hf_nisplus_entry_flags = -1;
static int hf_nisplus_entry_val = -1;
static int hf_nisplus_entry_mask = -1;
static int hf_nisplus_entry_mask_binary = -1;
static int hf_nisplus_entry_mask_crypt = -1;
static int hf_nisplus_entry_mask_xdr = -1;
static int hf_nisplus_entry_mask_modified = -1;
static int hf_nisplus_entry_mask_asn = -1;
static int hf_nisplus_table = -1;
static int hf_nisplus_table_type = -1;
static int hf_nisplus_table_maxcol = -1;
static int hf_nisplus_table_sep = -1;
static int hf_nisplus_table_cols = -1;
static int hf_nisplus_table_col = -1;
static int hf_nisplus_table_path = -1;
static int hf_nisplus_table_col_name = -1;
static int hf_nisplus_table_col_mask = -1;
static int hf_nisplus_table_col_mask_binary = -1;
static int hf_nisplus_table_col_mask_encrypted = -1;
static int hf_nisplus_table_col_mask_xdr = -1;
static int hf_nisplus_table_col_mask_searchable = -1;
static int hf_nisplus_table_col_mask_casesensitive = -1;
static int hf_nisplus_table_col_mask_modified = -1;
static int hf_nisplus_table_col_mask_asn = -1;
static int hf_nisplus_group = -1;
static int hf_nisplus_group_flags = -1;
static int hf_nisplus_grps = -1;
static int hf_nisplus_group_name = -1;
static int hf_nisplus_ib_flags = -1;
static int hf_nisplus_ib_bufsize = -1;
static int hf_nisplus_cookie = -1;
static int hf_nisplus_fd_dirname = -1;
static int hf_nisplus_fd_requester = -1;
static int hf_nisplus_taglist = -1;
static int hf_nisplus_tag = -1;
static int hf_nisplus_tag_type = -1;
static int hf_nisplus_tag_val = -1;
static int hf_nisplus_dump_dir = -1;
static int hf_nisplus_dump_time = -1;
static int hf_nisplus_dummy = -1;
static int hf_nisplus_ping_dir = -1;
static int hf_nisplus_ping_time = -1;
static int hf_nisplus_error = -1;
static int hf_nisplus_dir_data = -1;
static int hf_nisplus_signature = -1;
static int hf_nisplus_log_entries = -1;
static int hf_nisplus_log_entry = -1;
static int hf_nisplus_log_type = -1;
static int hf_nisplus_log_time = -1;
static int hf_nisplus_log_principal = -1;
static int hf_nisplus_callback_status = -1;
static int hf_nisplus_cp_status = -1;
static int hf_nisplus_cp_zticks = -1;
static int hf_nisplus_cp_dticks = -1;
static int hf_nisplus_zticks = -1;
static int hf_nisplus_dticks = -1;
static int hf_nisplus_aticks = -1;
static int hf_nisplus_cticks = -1;

static gint ett_nisplus = -1;
static gint ett_nisplus_object = -1;
static gint ett_nisplus_oid = -1;
static gint ett_nisplus_directory = -1;
static gint ett_nisplus_directory_mask = -1;
static gint ett_nisplus_access_mask = -1;
static gint ett_nisplus_server = -1;
static gint ett_nisplus_endpoint = -1;
static gint ett_nisplus_link = -1;
static gint ett_nisplus_attr = -1;
static gint ett_nisplus_entry = -1;
static gint ett_nisplus_entry_col = -1;
static gint ett_nisplus_entry_mask = -1;
static gint ett_nisplus_table = -1;
static gint ett_nisplus_table_col = -1;
static gint ett_nisplus_table_col_mask = -1;
static gint ett_nisplus_group = -1;
static gint ett_nisplus_grps = -1;
static gint ett_nisplus_tag = -1;
static gint ett_nisplus_log_entry = -1;


#define NIS_MASK_TABLE_BINARY	0x0001
#define NIS_MASK_TABLE_CRYPT	0x0002
#define NIS_MASK_TABLE_XDR	0x0004
#define NIS_MASK_TABLE_SRCH	0x0008
#define NIS_MASK_TABLE_CASE	0x0010
#define NIS_MASK_TABLE_MODIFIED	0x0020
#define NIS_MASK_TABLE_ASN	0x0040


#define NIS_MASK_ENTRY_BINARY	0x0001
#define NIS_MASK_ENTRY_CRYPT	0x0002
#define NIS_MASK_ENTRY_XDR	0x0004
#define NIS_MASK_ENTRY_MODIFIED	0x0008
#define NIS_MASK_ENTRY_ASN	0x0040


#define NIS_MASK_WORLD_READ	0x0001
#define NIS_MASK_WORLD_MODIFY	0x0002
#define NIS_MASK_WORLD_CREATE	0x0004
#define NIS_MASK_WORLD_DESTROY	0x0008
#define NIS_MASK_GROUP_READ	0x0010
#define NIS_MASK_GROUP_MODIFY	0x0020
#define NIS_MASK_GROUP_CREATE	0x0040
#define NIS_MASK_GROUP_DESTROY	0x0080
#define NIS_MASK_OWNER_READ	0x0100
#define NIS_MASK_OWNER_MODIFY	0x0200
#define NIS_MASK_OWNER_CREATE	0x0400
#define NIS_MASK_OWNER_DESTROY	0x0800
#define NIS_MASK_NOBODY_READ	0x1000
#define NIS_MASK_NOBODY_MODIFY	0x2000
#define NIS_MASK_NOBODY_CREATE	0x4000
#define NIS_MASK_NOBODY_DESTROY	0x8000


static const value_string key_type[] = {
#define NIS_KEY_NONE		0
	{	NIS_KEY_NONE,		"No Public Key (unix/sys auth)"	},
#define NIS_KEY_DH		1
	{	NIS_KEY_DH,		"Diffie-Hellman"	},
#define NIS_KEY_RSA		2
	{	NIS_KEY_RSA,		"RSA"	},
#define NIS_KEY_KERB		3
	{	NIS_KEY_KERB,		"Kerberos"	},
#define NIS_KEY_DHEXT		4
	{	NIS_KEY_DHEXT,		"Extended Diffie-Hellman for RPC-GSS"	},
	{	0,	NULL	},
};

static const value_string obj_type[] = {
#define NIS_BOGUS_OBJ		0
	{	NIS_BOGUS_OBJ,		"Bogus Object"	},
#define NIS_NO_OBJ		1
	{	NIS_NO_OBJ,		"NULL Object"	},
#define NIS_DIRECTORY_OBJ	2
	{	NIS_DIRECTORY_OBJ,	"Directory Object"	},
#define NIS_GROUP_OBJ		3
	{	NIS_GROUP_OBJ,		"Group Object"	},
#define NIS_TABLE_OBJ		4
	{	NIS_TABLE_OBJ,		"Table Object"	},
#define NIS_ENTRY_OBJ		5
	{	NIS_ENTRY_OBJ,		"Entry Object"	},
#define NIS_LINK_OBJ		6
	{	NIS_LINK_OBJ,		"Link Object"	},
#define NIS_PRIVATE_OBJ		7
	{	NIS_PRIVATE_OBJ,	"Private Object"	},
	{	0,	NULL	},
};

static const value_string ns_type[] = {
#define NIS_TYPE_UNKNOWN	0
	{	NIS_TYPE_UNKNOWN,	"UNKNOWN"	},
#define NIS_TYPE_NIS		1
	{	NIS_TYPE_NIS,	"NIS Plus Service"	},
#define NIS_TYPE_SUNYP		2
	{	NIS_TYPE_SUNYP,	"Old NIS Service (YP)"	},
#define NIS_TYPE_IVY		3
	{	NIS_TYPE_IVY,	"NIS Plus Plus Service"	},
#define NIS_TYPE_DNS		4
	{	NIS_TYPE_DNS,	"Domain Name Service (DNS)"	},
#define NIS_TYPE_X500		5
	{	NIS_TYPE_X500,	"ISO/CCITT X.500 Service"	},
#define NIS_TYPE_DNANS		6
	{	NIS_TYPE_DNANS,	"Digital DECNet Name Service"	},
#define NIS_TYPE_XCHS		7
	{	NIS_TYPE_XCHS,	"Xerox ClearingHouse Service"	},
#define NIS_TYPE_CDS		8
	{	NIS_TYPE_CDS,	"CDS"	},
	{	0,	NULL	},
};




static int
dissect_nisplus_time(tvbuff_t *tvb, int offset, proto_tree *tree, int hfindex)
{
	nstime_t ts;

	ts.nsecs = 0;
	ts.secs = tvb_get_ntohl(tvb, offset);
	offset += 4;

	proto_tree_add_time(tree, hfindex, tvb, offset, 4, &ts);

	return offset;
}

static int
dissect_group(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_string(tvb, tree,
			hf_nisplus_group_name, offset, NULL);

	return offset;
}


static int
dissect_group_obj(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_item* lock_item = NULL;
	proto_tree* lock_tree = NULL;
	int old_offset = offset;

	lock_item = proto_tree_add_item(tree, hf_nisplus_group,
			tvb, offset, -1, ENC_NA);

	lock_tree = proto_item_add_subtree(lock_item, ett_nisplus_group);

	offset = dissect_rpc_uint32(tvb, lock_tree,
			hf_nisplus_group_flags, offset);

	offset = dissect_rpc_array(tvb, pinfo, lock_tree, offset,
			dissect_group, hf_nisplus_grps);

	proto_item_set_len(lock_item, offset-old_offset);
	return offset;
}


static int
dissect_access_rights(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_item* mask_item = NULL;
	proto_tree* mask_tree = NULL;
	guint32	mask;

	mask_item = proto_tree_add_item(tree, hf_nisplus_access_mask,
			tvb, offset, 4,	ENC_NA);

	mask_tree = proto_item_add_subtree(mask_item, ett_nisplus_access_mask);
	mask = tvb_get_ntohl(tvb, offset);
	proto_tree_add_boolean(mask_tree, hf_nisplus_mask_world_read, tvb, offset, 4, mask);
	proto_tree_add_boolean(mask_tree, hf_nisplus_mask_world_modify, tvb, offset, 4, mask);
	proto_tree_add_boolean(mask_tree, hf_nisplus_mask_world_create, tvb, offset, 4, mask);
	proto_tree_add_boolean(mask_tree, hf_nisplus_mask_world_destroy, tvb, offset, 4, mask);
	proto_tree_add_boolean(mask_tree, hf_nisplus_mask_group_read, tvb, offset, 4, mask);
	proto_tree_add_boolean(mask_tree, hf_nisplus_mask_group_modify, tvb, offset, 4, mask);
	proto_tree_add_boolean(mask_tree, hf_nisplus_mask_group_create, tvb, offset, 4, mask);
	proto_tree_add_boolean(mask_tree, hf_nisplus_mask_group_destroy, tvb, offset, 4, mask);
	proto_tree_add_boolean(mask_tree, hf_nisplus_mask_owner_read, tvb, offset, 4, mask);
	proto_tree_add_boolean(mask_tree, hf_nisplus_mask_owner_modify, tvb, offset, 4, mask);
	proto_tree_add_boolean(mask_tree, hf_nisplus_mask_owner_create, tvb, offset, 4, mask);
	proto_tree_add_boolean(mask_tree, hf_nisplus_mask_owner_destroy, tvb, offset, 4, mask);
	proto_tree_add_boolean(mask_tree, hf_nisplus_mask_nobody_read, tvb, offset, 4, mask);
	proto_tree_add_boolean(mask_tree, hf_nisplus_mask_nobody_modify, tvb, offset, 4, mask);
	proto_tree_add_boolean(mask_tree, hf_nisplus_mask_nobody_create, tvb, offset, 4, mask);
	proto_tree_add_boolean(mask_tree, hf_nisplus_mask_nobody_destroy, tvb, offset, 4, mask);
	offset += 4;

	return offset;
}

static int
dissect_table(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item* lock_item = NULL;
	proto_tree* lock_tree = NULL;
	proto_item* mask_item = NULL;
	proto_tree* mask_tree = NULL;
	guint32	mask;
	int old_offset = offset;

	lock_item = proto_tree_add_item(tree, hf_nisplus_table_col,
			tvb, offset, -1, ENC_NA);

	lock_tree = proto_item_add_subtree(lock_item, ett_nisplus_table_col);

	offset = dissect_rpc_string(tvb, lock_tree,
			hf_nisplus_table_col_name, offset, NULL);


	mask_item = proto_tree_add_item(lock_tree, hf_nisplus_table_col_mask,
		tvb, offset, 4,
		ENC_NA);
	mask_tree = proto_item_add_subtree(mask_item, ett_nisplus_table_col_mask);
	mask = tvb_get_ntohl(tvb, offset);
	proto_tree_add_boolean(mask_tree, hf_nisplus_table_col_mask_binary,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(mask_tree, hf_nisplus_table_col_mask_encrypted,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(mask_tree, hf_nisplus_table_col_mask_xdr,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(mask_tree, hf_nisplus_table_col_mask_searchable,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(mask_tree, hf_nisplus_table_col_mask_casesensitive,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(mask_tree, hf_nisplus_table_col_mask_modified,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(mask_tree, hf_nisplus_table_col_mask_asn,
		tvb, offset, 4, mask);
	offset += 4;

	offset = dissect_access_rights(tvb, offset, lock_tree);

	proto_item_set_len(lock_item, offset-old_offset);
	return offset;
}

static int
dissect_table_obj(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)

{
	proto_item* lock_item = NULL;
	proto_tree* lock_tree = NULL;
	int old_offset = offset;

	lock_item = proto_tree_add_item(tree, hf_nisplus_table,
			tvb, offset, -1, ENC_NA);

	lock_tree = proto_item_add_subtree(lock_item, ett_nisplus_table);

	offset = dissect_rpc_string(tvb, lock_tree,
			hf_nisplus_table_type, offset, NULL);

	offset = dissect_rpc_uint32(tvb, lock_tree,
			hf_nisplus_table_maxcol, offset);

	offset = dissect_rpc_uint32(tvb, lock_tree,
			hf_nisplus_table_sep, offset);

	offset = dissect_rpc_array(tvb, pinfo, lock_tree, offset,
			dissect_table, hf_nisplus_table_cols);

	offset = dissect_rpc_string(tvb, lock_tree,
			hf_nisplus_table_path, offset, NULL);

	proto_item_set_len(lock_item, offset-old_offset);
	return offset;
}

static int
dissect_entry(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item* lock_item = NULL;
	proto_tree* lock_tree = NULL;
	proto_item* mask_item = NULL;
	proto_tree* mask_tree = NULL;
	guint32	mask;
	int old_offset = offset;

	lock_item = proto_tree_add_item(tree, hf_nisplus_entry_col,
			tvb, offset, -1, ENC_NA);

	lock_tree = proto_item_add_subtree(lock_item, ett_nisplus_entry_col);

	mask_item = proto_tree_add_item(lock_tree, hf_nisplus_entry_mask,
			tvb, offset, 4,
			ENC_NA);

	mask_tree = proto_item_add_subtree(mask_item, ett_nisplus_entry_mask);
	mask = tvb_get_ntohl(tvb, offset);
	proto_tree_add_boolean(mask_tree, hf_nisplus_entry_mask_binary, tvb, offset, 4, mask);
	proto_tree_add_boolean(mask_tree, hf_nisplus_entry_mask_crypt, tvb, offset, 4, mask);
	proto_tree_add_boolean(mask_tree, hf_nisplus_entry_mask_xdr, tvb, offset, 4, mask);
	proto_tree_add_boolean(mask_tree, hf_nisplus_entry_mask_modified, tvb, offset, 4, mask);
	proto_tree_add_boolean(mask_tree, hf_nisplus_entry_mask_asn, tvb, offset, 4, mask);
	offset += 4;

	offset = dissect_rpc_string(tvb, lock_tree,
			hf_nisplus_entry_val, offset, NULL);

	proto_item_set_len(lock_item, offset-old_offset);
	return offset;
}

static int
dissect_entry_obj(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_item* lock_item = NULL;
	proto_tree* lock_tree = NULL;
	int old_offset = offset;

	lock_item = proto_tree_add_item(tree, hf_nisplus_entry,
			tvb, offset, -1, ENC_NA);

	lock_tree = proto_item_add_subtree(lock_item, ett_nisplus_entry);

	offset = dissect_rpc_string(tvb, lock_tree,
			hf_nisplus_entry_type, offset, NULL);

	offset = dissect_rpc_array(tvb, pinfo, lock_tree, offset,
			dissect_entry, hf_nisplus_entry_cols);

	proto_item_set_len(lock_item, offset-old_offset);
	return offset;
}

static int
dissect_attr(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item* lock_item = NULL;
	proto_tree* lock_tree = NULL;
	int old_offset = offset;

	lock_item = proto_tree_add_item(tree, hf_nisplus_attr,
			tvb, offset, -1, ENC_NA);

	lock_tree = proto_item_add_subtree(lock_item, ett_nisplus_attr);

	offset = dissect_rpc_string(tvb, lock_tree,
			hf_nisplus_attr_name, offset, NULL);

	offset = dissect_rpc_data(tvb, lock_tree,
			hf_nisplus_attr_val, offset);

	proto_item_set_len(lock_item, offset-old_offset);
	return offset;
}

static int
dissect_link_obj(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_item* lock_item = NULL;
	proto_tree* lock_tree = NULL;
	int old_offset = offset;

	lock_item = proto_tree_add_item(tree, hf_nisplus_link,
			tvb, offset, -1, ENC_NA);

	lock_tree = proto_item_add_subtree(lock_item, ett_nisplus_link);

	offset = dissect_rpc_uint32(tvb, lock_tree,
			hf_nisplus_object_type, offset);

	offset = dissect_rpc_array(tvb, pinfo, lock_tree, offset,
			dissect_attr, hf_nisplus_attrs_array);

	offset = dissect_rpc_string(tvb, lock_tree,
			hf_nisplus_object_name,	offset, NULL);

	proto_item_set_len(lock_item, offset-old_offset);
	return offset;
}


static int
dissect_endpoint(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item* lock_item = NULL;
	proto_tree* lock_tree = NULL;
	int old_offset = offset;

	lock_item = proto_tree_add_item(tree, hf_nisplus_endpoint,
			tvb, offset, -1, ENC_NA);

	lock_tree = proto_item_add_subtree(lock_item, ett_nisplus_endpoint);

	offset = dissect_rpc_string(tvb, lock_tree,
			hf_nisplus_endpoint_uaddr, offset, NULL);

	offset = dissect_rpc_string(tvb, lock_tree,
			hf_nisplus_endpoint_family, offset, NULL);

	offset = dissect_rpc_string(tvb, lock_tree,
			hf_nisplus_endpoint_proto, offset, NULL);

	proto_item_set_len(lock_item, offset-old_offset);
	return offset;
}


static int
dissect_directory_server(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_item* lock_item = NULL;
	proto_tree* lock_tree = NULL;
	int old_offset = offset;

	lock_item = proto_tree_add_item(tree, hf_nisplus_server,
			tvb, offset, -1, ENC_NA);

	lock_tree = proto_item_add_subtree(lock_item, ett_nisplus_server);

	offset = dissect_rpc_string(tvb, lock_tree,
			hf_nisplus_server_name, offset, NULL);

	offset = dissect_rpc_array(tvb, pinfo, lock_tree, offset,
			dissect_endpoint, hf_nisplus_endpoints);

	offset = dissect_rpc_uint32(tvb, lock_tree,
			hf_nisplus_key_type, offset);

	offset = dissect_rpc_data(tvb, lock_tree,
			hf_nisplus_key_data, offset);

	proto_item_set_len(lock_item, offset-old_offset);
	return offset;
}


static int
dissect_directory_mask(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item* lock_item = NULL;
	proto_tree* lock_tree = NULL;
	int old_offset = offset;

	lock_item = proto_tree_add_item(tree, hf_nisplus_directory_mask,
			tvb, offset, -1, ENC_NA);

	lock_tree = proto_item_add_subtree(lock_item, ett_nisplus_directory_mask);

	offset = dissect_access_rights(tvb, offset, lock_tree);

	offset = dissect_rpc_uint32(tvb, lock_tree,
			hf_nisplus_object_type, offset);

	proto_item_set_len(lock_item, offset-old_offset);
	return offset;
}

static int
dissect_directory_obj(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_item* lock_item = NULL;
	proto_tree* lock_tree = NULL;
	int old_offset = offset;

	lock_item = proto_tree_add_item(tree, hf_nisplus_directory,
			tvb, offset, -1, ENC_NA);

	lock_tree = proto_item_add_subtree(lock_item, ett_nisplus_directory);

	offset = dissect_rpc_string(tvb, lock_tree,
			hf_nisplus_directory_name, offset, NULL);

	offset = dissect_rpc_uint32(tvb, lock_tree,
			hf_nisplus_directory_type, offset);

	offset = dissect_rpc_array(tvb, pinfo, lock_tree, offset,
			dissect_directory_server, hf_nisplus_servers);

	offset = dissect_rpc_uint32(tvb, lock_tree,
			hf_nisplus_directory_ttl, offset);

	offset = dissect_rpc_array(tvb, pinfo, lock_tree, offset,
			dissect_directory_mask, hf_nisplus_directory_mask_list);

	proto_item_set_len(lock_item, offset-old_offset);
	return offset;
}

static int
dissect_nisplus_oid(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_item* lock_item = NULL;
	proto_tree* lock_tree = NULL;
	int old_offset = offset;

	lock_item = proto_tree_add_item(tree, hf_nisplus_oid, tvb,
			offset, -1, ENC_NA);

	lock_tree = proto_item_add_subtree(lock_item, ett_nisplus_oid);

	offset = dissect_nisplus_time(tvb, offset, lock_tree,
			hf_nisplus_object_ctime);

	offset = dissect_nisplus_time(tvb, offset, lock_tree,
			hf_nisplus_object_mtime);

	proto_item_set_len(lock_item, offset-old_offset);
	return offset;
}

static int
dissect_nisplus_object(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_item* lock_item = NULL;
	proto_tree* lock_tree = NULL;
	gint32	type;
	int old_offset = offset;

	lock_item = proto_tree_add_item(tree, hf_nisplus_object, tvb,
			offset, -1, ENC_NA);

	lock_tree = proto_item_add_subtree(lock_item, ett_nisplus_object);

	offset = dissect_nisplus_oid(tvb, offset, lock_tree);

	offset = dissect_rpc_string(tvb, lock_tree,
			hf_nisplus_object_name,	offset, NULL);

	offset = dissect_rpc_string(tvb, lock_tree,
			hf_nisplus_object_owner, offset, NULL);

	offset = dissect_rpc_string(tvb, lock_tree,
			hf_nisplus_object_group, offset, NULL);

	offset = dissect_rpc_string(tvb, lock_tree,
			hf_nisplus_object_domain, offset, NULL);

	offset = dissect_access_rights(tvb, offset, lock_tree);

	offset = dissect_rpc_uint32(tvb, lock_tree,
			hf_nisplus_object_ttl, offset);

	type = tvb_get_ntohl(tvb, offset);
	offset = dissect_rpc_uint32(tvb, lock_tree,
			hf_nisplus_object_type, offset);
	switch (type) {
	case	NIS_DIRECTORY_OBJ:
		offset = dissect_directory_obj(tvb, offset, pinfo, lock_tree);
		break;
	case	NIS_GROUP_OBJ:
		offset = dissect_group_obj(tvb, offset, pinfo, lock_tree);
		break;
	case	NIS_TABLE_OBJ:
		offset = dissect_table_obj(tvb, offset, pinfo, lock_tree);
		break;
	case	NIS_ENTRY_OBJ:
		offset = dissect_entry_obj(tvb, offset, pinfo, lock_tree);
		break;
	case	NIS_LINK_OBJ:
		offset = dissect_link_obj(tvb, offset, pinfo, lock_tree);
		break;
	case	NIS_PRIVATE_OBJ:
		offset = dissect_rpc_data(tvb, lock_tree,
				hf_nisplus_object_private, offset);
		break;
	case	NIS_NO_OBJ:
		break;
	case	NIS_BOGUS_OBJ:
		break;
	default:
		break;
	};

	proto_item_set_len(lock_item, offset-old_offset);
	return offset;
}
/* xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	end of nis object, thats right, all this was the definition of
	ONE SINGLE struct.
*/



static int
dissect_ns_request(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset = dissect_rpc_string(tvb, tree,
			hf_nisplus_object_name, offset, NULL);

	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_nisplus_object, hf_nisplus_object);

	return offset;
}

static int
dissect_ib_request(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset = dissect_rpc_string(tvb, tree,
			hf_nisplus_object_name, offset, NULL);

	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_attr, hf_nisplus_attrs_array);

	offset = dissect_rpc_uint32(tvb, tree,
			hf_nisplus_ib_flags, offset);

	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_nisplus_object, hf_nisplus_object);

	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_directory_server, hf_nisplus_cbservers);

	offset = dissect_rpc_uint32(tvb, tree,
			hf_nisplus_ib_bufsize, offset);

	offset = dissect_rpc_data(tvb, tree,
			hf_nisplus_cookie, offset);

	return offset;
}

static int
dissect_fd_args(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_string(tvb, tree,
			hf_nisplus_fd_dirname, offset, NULL);

	offset = dissect_rpc_string(tvb, tree,
			hf_nisplus_fd_requester, offset, NULL);

	return offset;
}

static int
dissect_nisplus_tag(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item* lock_item = NULL;
	proto_tree* lock_tree = NULL;
	int old_offset = offset;

	lock_item = proto_tree_add_item(tree, hf_nisplus_tag, tvb,
			offset, -1, ENC_NA);

	lock_tree = proto_item_add_subtree(lock_item, ett_nisplus_tag);

	offset = dissect_rpc_uint32(tvb, lock_tree,
			hf_nisplus_tag_type, offset);

	offset = dissect_rpc_string(tvb, lock_tree,
			hf_nisplus_tag_val, offset, NULL);

	proto_item_set_len(lock_item, offset-old_offset);
	return offset;
}

static int
dissect_nisplus_taglist(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_nisplus_tag, hf_nisplus_taglist);

	return offset;
}

static int
dissect_dump_args(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset = dissect_rpc_string(tvb, tree,
			hf_nisplus_dump_dir, offset, NULL);

	offset = dissect_nisplus_time(tvb, offset, tree,
			hf_nisplus_dump_time);

	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_directory_server, hf_nisplus_cbservers);

	return offset;
}

static int
dissect_netobj(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_data(tvb, tree,
			hf_nisplus_dummy, offset);

	return offset;
}

static int
dissect_nisname(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_string(tvb, tree,
			hf_nisplus_object_name, offset, NULL);

	return offset;
}

static int
dissect_ping_args(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_string(tvb, tree,
			hf_nisplus_ping_dir, offset, NULL);

	offset = dissect_nisplus_time(tvb, offset, tree,
			hf_nisplus_ping_time);

	return offset;
}


static const value_string nis_error[] = {
#define NIS_SUCCESS		0
	{	NIS_SUCCESS,		"A-ok, let's rock n roll"	},
#define NIS_S_SUCCESS		1
	{	NIS_S_SUCCESS,		"Name found (maybe)"	},
#define NIS_NOTFOUND		2
	{	NIS_NOTFOUND,		"Name definitely not found"	},
#define NIS_S_NOTFOUND		3
	{	NIS_S_NOTFOUND,		"Name maybe not found"	},
#define NIS_CACHEEXPIRED	4
	{	NIS_CACHEEXPIRED,	"Name exists but cache out of date"	},
#define NIS_NAMEUNREACHABLE	5
	{	NIS_NAMEUNREACHABLE,	"Can't get there from here"	},
#define NIS_UNKNOWNOBJ		6
	{	NIS_UNKNOWNOBJ,		"Object type is bogus"	},
#define NIS_TRYAGAIN		7
	{	NIS_TRYAGAIN,		"I'm busy, call back"	},
#define NIS_SYSTEMERROR		8
	{	NIS_SYSTEMERROR,	"Generic system error"	},
#define NIS_CHAINBROKEN		9
	{	NIS_CHAINBROKEN,	"First/Next warning"	},
#define NIS_PERMISSION		10
	{	NIS_PERMISSION,		"Not enough permission to access"	},
#define NIS_NOTOWNER		11
	{	NIS_NOTOWNER,		"You don't own it, sorry"	},
#define NIS_NOT_ME		12
	{	NIS_NOT_ME,		"I don't serve this name"	},
#define NIS_NOMEMORY		13
	{	NIS_NOMEMORY,		"Outta VM! Help!"	},
#define NIS_NAMEEXISTS		14
	{	NIS_NAMEEXISTS,		"Can't create over another name"	},
#define NIS_NOTMASTER		15
	{	NIS_NOTMASTER,		"I'm just a secondary, don't ask me"	},
#define NIS_INVALIDOBJ		16
	{	NIS_INVALIDOBJ,		"Object is broken somehow"	},
#define NIS_BADNAME		17
	{	NIS_BADNAME,		"Unparsable name"	},
#define NIS_NOCALLBACK		18
	{	NIS_NOCALLBACK,		"Couldn't talk to call back proc"	},
#define NIS_CBRESULTS		19
	{	NIS_CBRESULTS,		"Results being called back to you"	},
#define NIS_NOSUCHNAME		20
	{	NIS_NOSUCHNAME,		"Name unknown"	},
#define NIS_NOTUNIQUE		21
	{	NIS_NOTUNIQUE,		"Value is not uniques (entry)"	},
#define NIS_IBMODERROR		22
	{	NIS_IBMODERROR,		"Inf. Base. Modify error."	},
#define NIS_NOSUCHTABLE		23
	{	NIS_NOSUCHTABLE,	"Name for table was wrong"	},
#define NIS_TYPEMISMATCH	24
	{	NIS_TYPEMISMATCH,	"Entry and table type mismatch"	},
#define NIS_LINKNAMEERROR	25
	{	NIS_LINKNAMEERROR,	"Link points to bogus name"	},
#define NIS_PARTIAL		26
	{	NIS_PARTIAL,		"Partial success, found table"	},
#define NIS_TOOMANYATTRS	27
	{	NIS_TOOMANYATTRS,	"Too many attributes"	},
#define NIS_RPCERROR		28
	{	NIS_RPCERROR,		"RPC error encountered"	},
#define NIS_BADATTRIBUTE	29
	{	NIS_BADATTRIBUTE,	"Bad or invalid attribute"	},
#define NIS_NOTSEARCHABLE	30
	{	NIS_NOTSEARCHABLE,	"Non-searchable object searched"	},
#define NIS_CBERROR		31
	{	NIS_CBERROR,		"Error during callback (svc crash)"	},
#define NIS_FOREIGNNS		32
	{	NIS_FOREIGNNS,		"Foreign Namespace"	},
#define NIS_BADOBJECT		33
	{	NIS_BADOBJECT,		"Malformed object structure"	},
#define NIS_NOTSAMEOBJ		34
	{	NIS_NOTSAMEOBJ,		"Object swapped during deletion"	},
#define NIS_MODFAIL		35
	{	NIS_MODFAIL,		"Failure during a Modify."	},
#define NIS_BADREQUEST		36
	{	NIS_BADREQUEST,		"Illegal query for table"	},
#define NIS_NOTEMPTY		37
	{	NIS_NOTEMPTY,		"Attempt to remove a non-empty tbl"	},
#define NIS_COLDSTART_ERR	38
	{	NIS_COLDSTART_ERR,	"Error accessing the cold start file"	},
#define NIS_RESYNC		39
	{	NIS_RESYNC,		"Transaction log too far out of date"	},
#define NIS_FAIL		40
	{	NIS_FAIL,		"NIS operation failed."	},
#define NIS_UNAVAIL		41
	{	NIS_UNAVAIL,		"NIS+ service is unavailable (client)"	},
#define NIS_RES2BIG		42
	{	NIS_RES2BIG,		"NIS+ result too big for datagram"	},
#define NIS_SRVAUTH		43
	{	NIS_SRVAUTH,		"NIS+ server wasn't authenticated."	},
#define NIS_CLNTAUTH		44
	{	NIS_CLNTAUTH,		"NIS+ Client wasn't authenticated."	},
#define NIS_NOFILESPACE		45
	{	NIS_NOFILESPACE,	"NIS+ server ran out of disk space"	},
#define NIS_NOPROC		46
	{	NIS_NOPROC,		"NIS+ server couldn't create new proc"	},
#define NIS_DUMPLATER		47
	{	NIS_DUMPLATER,		"NIS+ server already has dump child"	},
	{	0,	NULL	},
};

static int
dissect_nisplus_result(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree,
			hf_nisplus_error, offset);

	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_nisplus_object, hf_nisplus_object);

	offset = dissect_rpc_data(tvb, tree,
			hf_nisplus_cookie, offset);

	offset = dissect_rpc_uint32(tvb, tree,
			hf_nisplus_zticks, offset);

	offset = dissect_rpc_uint32(tvb, tree,
			hf_nisplus_dticks, offset);

	offset = dissect_rpc_uint32(tvb, tree,
			hf_nisplus_aticks, offset);

	offset = dissect_rpc_uint32(tvb, tree,
			hf_nisplus_cticks, offset);

	return offset;
}

static int
dissect_fd_result(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree,
			hf_nisplus_error, offset);

	offset = dissect_rpc_string(tvb, tree,
			hf_nisplus_fd_dirname, offset, NULL);

	offset = dissect_rpc_data(tvb, tree,
			hf_nisplus_dir_data, offset);

	offset = dissect_rpc_data(tvb, tree,
			hf_nisplus_signature, offset);

	return offset;
}

static const value_string entry_type[] = {
#define LOG_NOP		0
	{	LOG_NOP,		"NOP"	},
#define LOG_ADD_NAME		1
	{	LOG_ADD_NAME,		"Name Was Added"	},
#define LOG_REM_NAME		2
	{	LOG_REM_NAME,		"Name Was Removed"	},
#define LOG_MOD_NAME_OLD	3
	{	LOG_MOD_NAME_OLD,		"Name Was Modified"	},
#define LOG_MOD_NAME_NEW	4
	{	LOG_MOD_NAME_NEW,		"Name Was Modified"	},
#define LOG_ADD_IBASE		5
	{	LOG_ADD_IBASE,		"Entry Added To Information Base"	},
#define LOG_REM_IBASE		6
	{	LOG_REM_IBASE,		"Entry Removed From Information Base"	},
#define LOG_MOD_IBASE		7
	{	LOG_MOD_IBASE,		"Entry Modified In Information Base"	},
#define LOG_UPD_STAMP		8
	{	LOG_UPD_STAMP,		"Update Timestamp"	},
	{	0,	NULL	},
};
static int
dissect_log_entry(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_item* lock_item = NULL;
	proto_tree* lock_tree = NULL;
	int old_offset = offset;

	lock_item = proto_tree_add_item(tree, hf_nisplus_log_entry,
			tvb, offset, -1, ENC_NA);

	lock_tree = proto_item_add_subtree(lock_item, ett_nisplus_log_entry);

	offset = dissect_nisplus_time(tvb, offset, lock_tree,
			hf_nisplus_log_time);

	offset = dissect_rpc_uint32(tvb, lock_tree,
			hf_nisplus_log_type, offset);

	offset = dissect_rpc_string(tvb, lock_tree,
			hf_nisplus_log_principal, offset, NULL);

	offset = dissect_rpc_string(tvb, lock_tree,
			hf_nisplus_directory_name, offset, NULL);

	offset = dissect_rpc_array(tvb, pinfo, lock_tree, offset,
			dissect_attr, hf_nisplus_attrs_array);

	offset = dissect_nisplus_object(tvb, offset, pinfo, lock_tree);

	proto_item_set_len(lock_item, offset-old_offset);
	return offset;
}

static int
dissect_log_result(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree,
			hf_nisplus_error, offset);

	offset = dissect_rpc_data(tvb, tree,
			hf_nisplus_cookie, offset);

	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_log_entry, hf_nisplus_log_entries);

	return offset;
}

static int
dissect_callback_result(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_bool(tvb, tree, hf_nisplus_callback_status,
			offset);

	return offset;
}

static int
dissect_change_time(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_nisplus_time(tvb, offset, tree,
			hf_nisplus_log_time);

	return offset;
}

static int
dissect_cp_result(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree,
			hf_nisplus_cp_status, offset);

	offset = dissect_rpc_uint32(tvb, tree,
			hf_nisplus_cp_zticks, offset);

	offset = dissect_rpc_uint32(tvb, tree,
			hf_nisplus_cp_dticks, offset);

	return offset;
}

static int
dissect_nisplus_error(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree,
			hf_nisplus_error, offset);

	return offset;
}

/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: type of arguments is "void". */
static const vsff nisplus3_proc[] = {
	{ NISPROC_NULL,			"NULL",
		NULL,	NULL },
	{ NISPROC_LOOKUP,		"LOOKUP",
		dissect_ns_request,	dissect_nisplus_result },
	{ NISPROC_ADD,			"ADD",
		dissect_ns_request,	dissect_nisplus_result },
	{ NISPROC_MODIFY,		"MODIFY",
		dissect_ns_request,	dissect_nisplus_result },
	{ NISPROC_REMOVE,		"REMOVE",
		dissect_ns_request,	dissect_nisplus_result },
	{ NISPROC_IBLIST,		"IBLIST",
		dissect_ib_request,	dissect_nisplus_result },
	{ NISPROC_IBADD,		"IBADD",
		dissect_ib_request,	dissect_nisplus_result },
	{ NISPROC_IBMODIFY,		"IBMODIFY",
		dissect_ib_request,	dissect_nisplus_result },
	{ NISPROC_IBREMOVE,		"IBREMOVE",
		dissect_ib_request,	dissect_nisplus_result },
	{ NISPROC_IBFIRST,		"IBFIRST",
		dissect_ib_request,	dissect_nisplus_result },
	{ NISPROC_IBNEXT,		"IBNEXT",
		dissect_ib_request,	dissect_nisplus_result },
	{ NISPROC_FINDDIRECTORY,	"FINDDIRECTORY",
		dissect_fd_args,	dissect_fd_result },
	{ NISPROC_STATUS,		"STATUS",
		dissect_nisplus_taglist, dissect_nisplus_taglist },
	{ NISPROC_DUMPLOG,		"DUMPLOG",
		dissect_dump_args,	dissect_log_result },
	{ NISPROC_DUMP,			"DUMP",
		dissect_dump_args,	dissect_log_result },
	{ NISPROC_CALLBACK,		"CALLBACK",
		dissect_netobj,		dissect_callback_result },
	{ NISPROC_CPTIME,		"CPTIME",
		dissect_nisname,	dissect_change_time },
	{ NISPROC_CHECKPOINT,		"CHECKPOINT",
		dissect_nisname,	dissect_cp_result },
	{ NISPROC_PING,			"PING",
		dissect_ping_args,	NULL },
	{ NISPROC_SERVSTATE,		"SERVSTATE",
		dissect_nisplus_taglist, dissect_nisplus_taglist },
	{ NISPROC_MKDIR,		"MKDIR",
		dissect_nisname,	dissect_nisplus_error },
	{ NISPROC_RMDIR,		"RMDIR",
		dissect_nisname,	dissect_nisplus_error },
	{ NISPROC_UPDKEYS,		"UPDKEYS",
		dissect_nisname,	dissect_nisplus_error },
	{ 0,	NULL,		NULL,				NULL }
};
static const value_string nisplus3_proc_vals[] = {
	{ NISPROC_NULL,			"NULL" },
	{ NISPROC_LOOKUP,		"LOOKUP" },
	{ NISPROC_ADD,			"ADD" },
	{ NISPROC_MODIFY,		"MODIFY" },
	{ NISPROC_REMOVE,		"REMOVE" },
	{ NISPROC_IBLIST,		"IBLIST" },
	{ NISPROC_IBADD,		"IBADD" },
	{ NISPROC_IBMODIFY,		"IBMODIFY" },
	{ NISPROC_IBREMOVE,		"IBREMOVE" },
	{ NISPROC_IBFIRST,		"IBFIRST" },
	{ NISPROC_IBNEXT,		"IBNEXT" },
	{ NISPROC_FINDDIRECTORY,	"FINDDIRECTORY" },
	{ NISPROC_STATUS,		"STATUS" },
	{ NISPROC_DUMPLOG,		"DUMPLOG" },
	{ NISPROC_DUMP,			"DUMP" },
	{ NISPROC_CALLBACK,		"CALLBACK" },
	{ NISPROC_CPTIME,		"CPTIME" },
	{ NISPROC_CHECKPOINT,		"CHECKPOINT" },
	{ NISPROC_PING,			"PING" },
	{ NISPROC_SERVSTATE,		"SERVSTATE" },
	{ NISPROC_MKDIR,		"MKDIR" },
	{ NISPROC_RMDIR,		"RMDIR" },
	{ NISPROC_UPDKEYS,		"UPDKEYS" },
	{ 0,	NULL }
};



void
proto_register_nis(void)
{
	static const true_false_string tfs_col_binary = {
		"column is binary",
		"column is NOT binary"
	};
	static const true_false_string tfs_col_encrypted = {
		"column is encrypted",
		"column is NOT encrypted"
	};
	static const true_false_string tfs_col_xdr = {
		"column is xdr encoded",
		"column is NOT xdr encoded"
	};
	static const true_false_string tfs_col_searchable = {
		"column is searchable",
		"column is NOT searchable"
	};
	static const true_false_string tfs_col_casesensitive = {
		"column is case sensitive",
		"column is NOT case sensitive"
	};
	static const true_false_string tfs_col_modified = {
		"column is modified",
		"column is NOT modified"
	};
	static const true_false_string tfs_col_asn = {
		"column is asn.1 encoded",
		"column is NOT asn.1 encoded"
	};

	static const true_false_string tfs_entry_binary = {
		"entry is binary",
		"entry is NOT binary"
	};

	static const true_false_string tfs_entry_crypt = {
		"entry is encrypted",
		"entry is NOT encrypted"
	};

	static const true_false_string tfs_entry_xdr = {
		"entry is xdr encoded",
		"entry is NOT xdr encoded"
	};

	static const true_false_string tfs_entry_modified = {
		"entry is modified",
		"entry is NOT modified"
	};

	static const true_false_string tfs_entry_asn = {
		"entry is asn.1 encoded",
		"entry is NOT asn.1 encoded"
	};

	static const true_false_string tfs_world_read = {
		"world can read",
		"world can NOT read"
	};

	static const true_false_string tfs_world_modify = {
		"world can modify",
		"world can NOT modify"
	};

	static const true_false_string tfs_world_create = {
		"world can create",
		"world can NOT create"
	};

	static const true_false_string tfs_world_destroy = {
		"world can destroy",
		"world can NOT destroy"
	};

	static const true_false_string tfs_group_read = {
		"group can read",
		"group can NOT read"
	};

	static const true_false_string tfs_group_modify = {
		"group can modify",
		"group can NOT modify"
	};

	static const true_false_string tfs_group_create = {
		"group can create",
		"group can NOT create"
	};

	static const true_false_string tfs_group_destroy = {
		"group can destroy",
		"group can NOT destroy"
	};

	static const true_false_string tfs_owner_read = {
		"owner can read",
		"owner can NOT read"
	};

	static const true_false_string tfs_owner_modify = {
		"owner can modify",
		"owner can NOT modify"
	};

	static const true_false_string tfs_owner_create = {
		"owner can create",
		"owner can NOT create"
	};

	static const true_false_string tfs_owner_destroy = {
		"owner can destroy",
		"owner can NOT destroy"
	};

	static const true_false_string tfs_nobody_read = {
		"nobody can read",
		"nobody can NOT read"
	};

	static const true_false_string tfs_nobody_modify = {
		"nobody can modify",
		"nobody can NOT modify"
	};

	static const true_false_string tfs_nobody_create = {
		"nobody can create",
		"nobody can NOT create"
	};

	static const true_false_string tfs_nobody_destroy = {
		"nobody can destroy",
		"nobody can NOT destroy"
	};

	static const true_false_string tfs_callback_status = {
		"unknown",
		"unknown"
	};




	static hf_register_info hf[] = {
		{ &hf_nisplus_procedure_v3, {
			"V3 Procedure", "nisplus.procedure_v3", FT_UINT32, BASE_DEC,
			VALS(nisplus3_proc_vals), 0, NULL, HFILL }},
		{ &hf_nisplus_object, {
			"NIS Object", "nisplus.object", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nisplus_oid, {
			"Object Identity Verifier", "nisplus.object.oid", FT_NONE, BASE_NONE,
			NULL, 0, "NIS Object Identity Verifier", HFILL }},

		{ &hf_nisplus_object_name, {
			"name", "nisplus.object.name", FT_STRING, BASE_NONE,
			NULL, 0, "NIS Name For This Object", HFILL }},

		{ &hf_nisplus_object_owner, {
			"owner", "nisplus.object.owner", FT_STRING, BASE_NONE,
			NULL, 0, "NIS Name Of Object Owner", HFILL }},

		{ &hf_nisplus_object_group, {
			"group", "nisplus.object.group", FT_STRING, BASE_NONE,
			NULL, 0, "NIS Name Of Access Group", HFILL }},

		{ &hf_nisplus_object_domain, {
			"domain", "nisplus.object.domain", FT_STRING, BASE_NONE,
			NULL, 0, "NIS Administrator For This Object", HFILL }},

		{ &hf_nisplus_object_ttl, {
			"ttl", "nisplus.object.ttl", FT_UINT32, BASE_DEC,
			NULL, 0, "NIS Time To Live For This Object", HFILL }},

		{ &hf_nisplus_object_private, {
			"private", "nisplus.object.private", FT_BYTES, BASE_NONE,
			NULL, 0, "NIS Private Object", HFILL }},

		{ &hf_nisplus_directory, {
			"directory", "nisplus.directory", FT_NONE, BASE_NONE,
			NULL, 0, "NIS Directory Object", HFILL }},

		{ &hf_nisplus_directory_name, {
			"directory name", "nisplus.directory.name", FT_STRING, BASE_NONE,
			NULL, 0, "Name Of Directory Being Served", HFILL }},

		{ &hf_nisplus_directory_type, {
			"type", "nisplus.directory.type", FT_UINT32, BASE_DEC,
			VALS(ns_type), 0, "NIS Type Of Name Service", HFILL }},

		{ &hf_nisplus_directory_ttl, {
			"ttl", "nisplus.directory.ttl", FT_UINT32, BASE_DEC,
			NULL, 0, "Time To Live", HFILL }},

		{ &hf_nisplus_directory_mask, {
			"mask", "nisplus.directory.mask", FT_NONE, BASE_NONE,
			NULL, 0, "NIS Directory Create/Destroy Rights", HFILL }},

		{ &hf_nisplus_directory_mask_list, {
			"mask list", "nisplus.directory.mask_list", FT_NONE, BASE_NONE,
			NULL, 0, "List Of Directory Create/Destroy Rights", HFILL }},

		{ &hf_nisplus_mask_world_read, {
			"WORLD READ", "nisplus.directory.mask.world_read",
			FT_BOOLEAN, 32, TFS(&tfs_world_read),
			NIS_MASK_WORLD_READ, "World Read Flag", HFILL }},

		{ &hf_nisplus_mask_world_modify, {
			"WORLD MODIFY", "nisplus.directory.mask.world_modify",
			FT_BOOLEAN, 32, TFS(&tfs_world_modify),
			NIS_MASK_WORLD_MODIFY, "World Modify Flag", HFILL }},

		{ &hf_nisplus_mask_world_create, {
			"WORLD CREATE", "nisplus.directory.mask.world_create",
			FT_BOOLEAN, 32, TFS(&tfs_world_create),
			NIS_MASK_WORLD_CREATE, "World Create Flag", HFILL }},

		{ &hf_nisplus_mask_world_destroy, {
			"WORLD DESTROY", "nisplus.directory.mask.world_destroy",
			FT_BOOLEAN, 32, TFS(&tfs_world_destroy),
			NIS_MASK_WORLD_DESTROY, "World Destroy Flag", HFILL }},

		{ &hf_nisplus_mask_group_read, {
			"GROUP READ", "nisplus.directory.mask.group_read",
			FT_BOOLEAN, 32, TFS(&tfs_group_read),
			NIS_MASK_GROUP_READ, "Group Read Flag", HFILL }},

		{ &hf_nisplus_mask_group_modify, {
			"GROUP MODIFY", "nisplus.directory.mask.group_modify",
			FT_BOOLEAN, 32, TFS(&tfs_group_modify),
			NIS_MASK_GROUP_MODIFY, "Group Modify Flag", HFILL }},

		{ &hf_nisplus_mask_group_create, {
			"GROUP CREATE", "nisplus.directory.mask.group_create",
			FT_BOOLEAN, 32, TFS(&tfs_group_create),
			NIS_MASK_GROUP_CREATE, "Group Create Flag", HFILL }},

		{ &hf_nisplus_mask_group_destroy, {
			"GROUP DESTROY", "nisplus.directory.mask.group_destroy",
			FT_BOOLEAN, 32, TFS(&tfs_group_destroy),
			NIS_MASK_GROUP_DESTROY, "Group Destroy Flag", HFILL }},

		{ &hf_nisplus_mask_owner_read, {
			"OWNER READ", "nisplus.directory.mask.owner_read",
			FT_BOOLEAN, 32, TFS(&tfs_owner_read),
			NIS_MASK_OWNER_READ, "Owner Read Flag", HFILL }},

		{ &hf_nisplus_mask_owner_modify, {
			"OWNER MODIFY", "nisplus.directory.mask.owner_modify",
			FT_BOOLEAN, 32, TFS(&tfs_owner_modify),
			NIS_MASK_OWNER_MODIFY, "Owner Modify Flag", HFILL }},

		{ &hf_nisplus_mask_owner_create, {
			"OWNER CREATE", "nisplus.directory.mask.owner_create",
			FT_BOOLEAN, 32, TFS(&tfs_owner_create),
			NIS_MASK_OWNER_CREATE, "Owner Create Flag", HFILL }},

		{ &hf_nisplus_mask_owner_destroy, {
			"OWNER DESTROY", "nisplus.directory.mask.owner_destroy",
			FT_BOOLEAN, 32, TFS(&tfs_owner_destroy),
			NIS_MASK_OWNER_DESTROY, "Owner Destroy Flag", HFILL }},

		{ &hf_nisplus_mask_nobody_read, {
			"NOBODY READ", "nisplus.directory.mask.nobody_read",
			FT_BOOLEAN, 32, TFS(&tfs_nobody_read),
			NIS_MASK_NOBODY_READ, "Nobody Read Flag", HFILL }},

		{ &hf_nisplus_mask_nobody_modify, {
			"NOBODY MODIFY", "nisplus.directory.mask.nobody_modify",
			FT_BOOLEAN, 32, TFS(&tfs_nobody_modify),
			NIS_MASK_NOBODY_MODIFY, "Nobody Modify Flag", HFILL }},

		{ &hf_nisplus_mask_nobody_create, {
			"NOBODY CREATE", "nisplus.directory.mask.nobody_create",
			FT_BOOLEAN, 32, TFS(&tfs_nobody_create),
			NIS_MASK_NOBODY_CREATE, "Nobody Create Flag", HFILL }},

		{ &hf_nisplus_mask_nobody_destroy, {
			"NOBODY DESTROY", "nisplus.directory.mask.nobody_destroy",
			FT_BOOLEAN, 32, TFS(&tfs_nobody_destroy),
			NIS_MASK_NOBODY_DESTROY, "Nobody Destroy Flag", HFILL }},

		{ &hf_nisplus_access_mask, {
			"access mask", "nisplus.access.mask", FT_NONE, BASE_NONE,
			NULL, 0, "NIS Access Mask", HFILL }},

		{ &hf_nisplus_object_type, {
			"type", "nisplus.object.type", FT_UINT32, BASE_DEC,
			VALS(obj_type), 0, "NIS Type Of Object", HFILL }},

		{ &hf_nisplus_servers, {
			"nis servers", "nisplus.servers", FT_NONE, BASE_NONE,
			NULL, 0, "NIS Servers For This Directory", HFILL }},

		{ &hf_nisplus_cbservers, {
			"nis servers", "nisplus.servers", FT_NONE, BASE_NONE,
			NULL, 0, "Optional Callback Server", HFILL }},

		{ &hf_nisplus_server, {
			"server", "nisplus.server", FT_NONE, BASE_NONE,
			NULL, 0, "NIS Server For This Directory", HFILL }},

		{ &hf_nisplus_server_name, {
			"name", "nisplus.server.name", FT_STRING, BASE_NONE,
			NULL, 0, "Name Of NIS Server", HFILL }},

		{ &hf_nisplus_key_type, {
			"type", "nisplus.key.type", FT_UINT32, BASE_DEC,
			VALS(key_type), 0, "Type Of Key", HFILL }},

		{ &hf_nisplus_key_data, {
			"key data", "nisplus.key.data", FT_BYTES, BASE_NONE,
			NULL, 0, "Encryption Key", HFILL }},

		{ &hf_nisplus_endpoints, {
			"nis endpoints", "nisplus.endpoints", FT_NONE, BASE_NONE,
			NULL, 0, "Endpoints For This NIS Server", HFILL }},

		{ &hf_nisplus_endpoint, {
			"endpoint", "nisplus.endpoint", FT_NONE, BASE_NONE,
			NULL, 0, "Endpoint For This NIS Server", HFILL }},

		{ &hf_nisplus_endpoint_uaddr, {
			"addr", "nisplus.endpoint.uaddr", FT_STRING, BASE_NONE,
			NULL, 0, "Address", HFILL }},

		{ &hf_nisplus_endpoint_family, {
			"family", "nisplus.endpoint.family", FT_STRING, BASE_NONE,
			NULL, 0, "Transport Family", HFILL }},

		{ &hf_nisplus_endpoint_proto, {
			"proto", "nisplus.endpoint.proto", FT_STRING, BASE_NONE,
			NULL, 0, "Protocol", HFILL }},

		{ &hf_nisplus_link, {
			"link", "nisplus.link", FT_NONE, BASE_NONE,
			NULL, 0, "NIS Link Object", HFILL }},

		{ &hf_nisplus_attrs_array, {
			"Attributes", "nisplus.attributes", FT_NONE, BASE_NONE,
			NULL, 0, "List Of Attributes", HFILL }},

		{ &hf_nisplus_attr, {
			"Attribute", "nisplus.attr", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nisplus_attr_name, {
			"name", "nisplus.attr.name", FT_STRING, BASE_NONE,
			NULL, 0, "Attribute Name", HFILL }},

		{ &hf_nisplus_attr_val, {
			"val", "nisplus.attr.val", FT_BYTES, BASE_NONE,
			NULL, 0, "Attribute Value", HFILL }},

		{ &hf_nisplus_entry, {
			"entry", "nisplus.entry", FT_NONE, BASE_NONE,
			NULL, 0, "Entry Object", HFILL }},

		{ &hf_nisplus_entry_type, {
			"type", "nisplus.entry.type", FT_STRING, BASE_NONE,
			NULL, 0, "Entry Type", HFILL }},

		{ &hf_nisplus_entry_cols, {
			"columns", "nisplus.entry.cols", FT_NONE, BASE_NONE,
			NULL, 0, "Entry Columns", HFILL }},

		{ &hf_nisplus_entry_col, {
			"column", "nisplus.entry.col", FT_NONE, BASE_NONE,
			NULL, 0, "Entry Column", HFILL }},

		{ &hf_nisplus_entry_flags, {
			"flags", "nisplus.entry.flags", FT_UINT32, BASE_HEX,
			NULL, 0, "Entry Col Flags", HFILL }},

		{ &hf_nisplus_entry_val, {
			"val", "nisplus.entry.val", FT_STRING, BASE_NONE,
			NULL, 0, "Entry Value", HFILL }},

		{ &hf_nisplus_entry_mask, {
			"mask", "nisplus.entry.mask", FT_NONE, BASE_NONE,
			NULL, 0, "Entry Col Mask", HFILL }},

		{ &hf_nisplus_entry_mask_binary, {
			"BINARY", "nisplus.entry.mask.binary",
			FT_BOOLEAN, 32, TFS(&tfs_entry_binary),
			NIS_MASK_ENTRY_BINARY, "Is This Entry BINARY Flag", HFILL }},

		{ &hf_nisplus_entry_mask_crypt, {
			"ENCRYPTED", "nisplus.entry.mask.encrypted",
			FT_BOOLEAN, 32, TFS(&tfs_entry_crypt),
			NIS_MASK_ENTRY_CRYPT, "Is This Entry ENCRYPTED Flag", HFILL }},

		{ &hf_nisplus_entry_mask_xdr, {
			"XDR", "nisplus.entry.mask.xdr",
			FT_BOOLEAN, 32, TFS(&tfs_entry_xdr),
			NIS_MASK_ENTRY_XDR, "Is This Entry XDR Encoded Flag", HFILL }},

		{ &hf_nisplus_entry_mask_modified, {
			"MODIFIED", "nisplus.entry.mask.modified",
			FT_BOOLEAN, 32, TFS(&tfs_entry_modified),
			NIS_MASK_ENTRY_MODIFIED, "Is This Entry MODIFIED Flag", HFILL }},

		{ &hf_nisplus_entry_mask_asn, {
			"ASN.1", "nisplus.entry.mask.asn",
			FT_BOOLEAN, 32, TFS(&tfs_entry_asn),
			NIS_MASK_ENTRY_ASN, "Is This Entry ASN.1 Encoded Flag", HFILL }},

		{ &hf_nisplus_table, {
			"table", "nisplus.table", FT_NONE, BASE_NONE,
			NULL, 0, "Table Object", HFILL }},

		{ &hf_nisplus_table_type, {
			"type", "nisplus.table.type", FT_STRING, BASE_NONE,
			NULL, 0, "Table Type", HFILL }},

		{ &hf_nisplus_table_maxcol, {
			"max columns", "nisplus.table.maxcol", FT_UINT16, BASE_DEC,
			NULL, 0, "Maximum Number Of Columns For Table", HFILL }},

		{ &hf_nisplus_table_sep, {
			"separator", "nisplus.table.separator", FT_UINT8, BASE_HEX,
			NULL, 0, "Separator Character", HFILL }},

		{ &hf_nisplus_table_cols, {
			"columns", "nisplus.table.cols", FT_NONE, BASE_NONE,
			NULL, 0, "Table Columns", HFILL }},

		{ &hf_nisplus_table_col, {
			"column", "nisplus.table.col", FT_NONE, BASE_NONE,
			NULL, 0, "Table Column", HFILL }},

		{ &hf_nisplus_table_path, {
			"path", "nisplus.table.path", FT_STRING, BASE_NONE,
			NULL, 0, "Table Path", HFILL }},

		{ &hf_nisplus_table_col_name, {
			"column name", "nisplus.table.col.name", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nisplus_table_col_mask, {
			"flags", "nisplus.table.col.flags", FT_NONE, BASE_NONE,
			NULL, 0, "Flags For This Column", HFILL }},

		{ &hf_nisplus_table_col_mask_binary, {
			"binary", "nisplus.table.flags.binary",
			FT_BOOLEAN, 32, TFS(&tfs_col_binary),
			NIS_MASK_TABLE_BINARY, "Is This Column BINARY", HFILL }},

		{ &hf_nisplus_table_col_mask_encrypted, {
			"encrypted", "nisplus.table.flags.encrypted",
			FT_BOOLEAN, 32, TFS(&tfs_col_encrypted),
			NIS_MASK_TABLE_CRYPT, "Is This Column ENCRYPTED", HFILL }},

		{ &hf_nisplus_table_col_mask_xdr, {
			"xdr", "nisplus.table.flags.xdr",
			FT_BOOLEAN, 32, TFS(&tfs_col_xdr),
			NIS_MASK_TABLE_XDR, "Is This Column XDR Encoded", HFILL }},

		{ &hf_nisplus_table_col_mask_searchable, {
			"searchable", "nisplus.table.flags.searchable",
			FT_BOOLEAN, 32, TFS(&tfs_col_searchable),
			NIS_MASK_TABLE_SRCH, "Is This Column SEARCHABLE", HFILL }},

		{ &hf_nisplus_table_col_mask_casesensitive, {
			"casesensitive", "nisplus.table.flags.casesensitive",
			FT_BOOLEAN, 32, TFS(&tfs_col_casesensitive),
			NIS_MASK_TABLE_CASE, "Is This Column CASESENSITIVE", HFILL }},

		{ &hf_nisplus_table_col_mask_modified, {
			"modified", "nisplus.table.flags.modified",
			FT_BOOLEAN, 32, TFS(&tfs_col_modified),
			NIS_MASK_TABLE_MODIFIED, "Is This Column MODIFIED", HFILL }},

		{ &hf_nisplus_table_col_mask_asn, {
			"asn", "nisplus.table.flags.asn",
			FT_BOOLEAN, 32, TFS(&tfs_col_asn),
			NIS_MASK_TABLE_ASN, "Is This Column ASN.1 Encoded", HFILL }},

		{ &hf_nisplus_group, {
			"Group", "nisplus.group", FT_NONE, BASE_NONE,
			NULL, 0, "Group Object", HFILL }},

		{ &hf_nisplus_grps, {
			"Groups", "nisplus.grps", FT_NONE, BASE_NONE,
			NULL, 0, "List Of Groups", HFILL }},

		{ &hf_nisplus_group_flags, {
			"flags", "nisplus.group.flags", FT_UINT32, BASE_HEX,
			NULL, 0, "Group Object Flags", HFILL }},

		{ &hf_nisplus_group_name, {
			"group name", "nisplus.group.name", FT_STRING, BASE_NONE,
			NULL, 0, "Name Of Group Member", HFILL }},

		{ &hf_nisplus_object_ctime, {
			"ctime", "nisplus.ctime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
			NULL, 0, "Time Of Creation", HFILL }},

		{ &hf_nisplus_object_mtime, {
			"mtime", "nisplus.mtime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
			NULL, 0, "Time Last Modified", HFILL }},

		{ &hf_nisplus_ib_flags, {
			"flags", "nisplus.ib.flags", FT_UINT32, BASE_HEX,
			NULL, 0, "Information Base Flags", HFILL }},

		{ &hf_nisplus_ib_bufsize, {
			"bufsize", "nisplus.ib.bufsize", FT_UINT32, BASE_HEX,
			NULL, 0, "Optional First/NextBufSize", HFILL }},

		{ &hf_nisplus_cookie, {
			"cookie", "nisplus.cookie", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nisplus_fd_dirname, {
			"dirname", "nisplus.fd.dirname", FT_STRING, BASE_NONE,
			NULL, 0, "Directory Name", HFILL }},

		{ &hf_nisplus_fd_requester, {
			"requester", "nisplus.fd.requester", FT_STRING, BASE_NONE,
			NULL, 0, "Host Principal Name For Signature", HFILL }},

		{ &hf_nisplus_taglist, {
			"taglist", "nisplus.taglist", FT_NONE, BASE_NONE,
			NULL, 0, "List Of Tags", HFILL }},

		{ &hf_nisplus_tag, {
			"tag", "nisplus.tag", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nisplus_tag_type, {
			"type", "nisplus.tag.type", FT_UINT32, BASE_DEC,
			NULL, 0, "Type Of Statistics Tag", HFILL }},

		{ &hf_nisplus_tag_val, {
			"value", "nisplus.tag.value", FT_STRING, BASE_NONE,
			NULL, 0, "Value Of Statistics Tag", HFILL }},

		{ &hf_nisplus_dump_dir, {
			"directory", "nisplus.dump.dir", FT_STRING, BASE_NONE,
			NULL, 0, "Directory To Dump", HFILL }},

		{ &hf_nisplus_dump_time, {
			"time", "nisplus.dump.time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
			NULL, 0, "From This Timestamp", HFILL }},

		{ &hf_nisplus_dummy, {
			"dummy", "nisplus.dummy", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nisplus_ping_time, {
			"time", "nisplus.ping.time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
			NULL, 0, "Timestamp Of The Transaction", HFILL }},

		{ &hf_nisplus_ping_dir, {
			"directory", "nisplus.ping.dir", FT_STRING, BASE_NONE,
			NULL, 0, "Directory That Had The Change", HFILL }},

		{ &hf_nisplus_error, {
			"status", "nisplus.status", FT_UINT32, BASE_DEC,
			VALS(nis_error), 0, "NIS Status Code", HFILL }},

		{ &hf_nisplus_dir_data, {
			"data", "nisplus.fd.dir.data", FT_BYTES, BASE_NONE,
			NULL, 0, "Directory Data In XDR Format", HFILL }},

		{ &hf_nisplus_signature, {
			"signature", "nisplus.fd.sig", FT_BYTES, BASE_NONE,
			NULL, 0, "Signature Of The Source", HFILL }},

		{ &hf_nisplus_log_entries, {
			"log entries", "nisplus.log.entries", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nisplus_log_entry, {
			"log entry", "nisplus.log.entry", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nisplus_log_time, {
			"time", "nisplus.log.time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
			NULL, 0, "Time Of Log Entry", HFILL }},

		{ &hf_nisplus_log_type, {
			"type", "nisplus.log.entry.type", FT_UINT32, BASE_DEC,
			VALS(entry_type), 0, "Type Of Entry In Transaction Log", HFILL }},

		{ &hf_nisplus_log_principal, {
			"principal", "nisplus.log.principal", FT_STRING, BASE_NONE,
			NULL, 0, "Principal Making The Change", HFILL }},

		{ &hf_nisplus_callback_status, {
			"status", "nisplus.callback.status",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_callback_status),
			0x0, "Status Of Callback Thread", HFILL }},

		{ &hf_nisplus_cp_status, {
			"status", "nisplus.checkpoint.status", FT_UINT32, BASE_DEC,
			NULL, 0, "Checkpoint Status", HFILL }},

		{ &hf_nisplus_cp_zticks, {
			"zticks", "nisplus.checkpoint.zticks", FT_UINT32, BASE_DEC,
			NULL, 0, "Service Ticks", HFILL }},

		{ &hf_nisplus_cp_dticks, {
			"dticks", "nisplus.checkpoint.dticks", FT_UINT32, BASE_DEC,
			NULL, 0, "Database Ticks", HFILL }},

		{ &hf_nisplus_zticks, {
			"zticks", "nisplus.zticks", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nisplus_dticks, {
			"dticks", "nisplus.dticks", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nisplus_aticks, {
			"aticks", "nisplus.aticks", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nisplus_cticks, {
			"cticks", "nisplus.cticks", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

	};

	static gint *ett[] = {
		&ett_nisplus,
		&ett_nisplus_object,
		&ett_nisplus_oid,
		&ett_nisplus_directory,
		&ett_nisplus_directory_mask,
		&ett_nisplus_access_mask,
		&ett_nisplus_server,
		&ett_nisplus_endpoint,
		&ett_nisplus_link,
		&ett_nisplus_attr,
		&ett_nisplus_entry,
		&ett_nisplus_entry_col,
		&ett_nisplus_entry_mask,
		&ett_nisplus_table,
		&ett_nisplus_table_col,
		&ett_nisplus_table_col_mask,
		&ett_nisplus_group,
		&ett_nisplus_grps,
		&ett_nisplus_tag,
		&ett_nisplus_log_entry,
	};

	proto_nisplus = proto_register_protocol("NIS+",
	    "NIS+", "nisplus");
	proto_register_field_array(proto_nisplus, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_nis(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_nisplus, NIS_PROGRAM, ett_nisplus);
	/* Register the procedure tables */
	rpc_init_proc_table(NIS_PROGRAM, 3, nisplus3_proc, hf_nisplus_procedure_v3);
}






/* xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   callback protocol for NIS+
   xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx */

static int proto_nispluscb = -1;
static int hf_nispluscb_procedure_v1 = -1;
static int hf_nispluscb_entries = -1;
static int hf_nispluscb_entry = -1;

static gint ett_nispluscb = -1;
static gint ett_nispluscb_entry = -1;

static int
dissect_cb_entry(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item* lock_item = NULL;
	/* proto_tree* lock_tree = NULL; */
	int old_offset = offset;

	lock_item = proto_tree_add_item(tree, hf_nispluscb_entry,
			tvb, offset, -1, ENC_NA);

	/* lock_tree = proto_item_add_subtree(lock_item, ett_nispluscb_entry); */

/*XXXXX Not implemented yet*/

	proto_item_set_len(lock_item, offset-old_offset);
	return offset;
}

static int
dissect_cback_data(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset = dissect_rpc_array(tvb, pinfo, tree, offset,
			dissect_cb_entry, hf_nispluscb_entries);

	return offset;
}

/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: type of arguments is "void". */
static const vsff cb1_proc[] = {
	{ CBPROC_NULL,			"NULL",
		NULL,	NULL },
	{ CBPROC_RECEIVE,		"RECEIVE",
		dissect_cback_data,	dissect_callback_result },
	{ CBPROC_FINISH,		"FINISH",
		NULL,	NULL },
	{ CBPROC_ERROR,			"ERROR",
		dissect_nisplus_error,	NULL },
	{	0,	NULL,	NULL,	NULL },
};
static const value_string nispluscb1_proc_vals[] = {
	{ CBPROC_NULL,		"NULL" },
	{ CBPROC_RECEIVE,	"RECEIVE" },
	{ CBPROC_FINISH,	"FINISH" },
	{ CBPROC_ERROR,		"ERROR" },
	{	0,	NULL }
};

void
proto_register_niscb(void)
{
	static hf_register_info hf[] = {
		{ &hf_nispluscb_procedure_v1, {
			"V1 Procedure", "nispluscb.procedure_v1", FT_UINT32, BASE_DEC,
			VALS(nispluscb1_proc_vals), 0, NULL, HFILL }},
		{ &hf_nispluscb_entries, {
			"entries", "nispluscb.entries", FT_NONE, BASE_NONE,
			NULL, 0, "NIS Callback Entries", HFILL }},

		{ &hf_nispluscb_entry, {
			"entry", "nispluscb.entry", FT_NONE, BASE_NONE,
			NULL, 0, "NIS Callback Entry", HFILL }},

	};

	static gint *ett[] = {
		&ett_nispluscb,
		&ett_nispluscb_entry,
	};

	proto_nispluscb = proto_register_protocol("NIS+ Callback",
	    "NIS+ CB", "nispluscb");
	proto_register_field_array(proto_nispluscb, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_niscb(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_nispluscb, CB_PROGRAM, ett_nispluscb);
	/* Register the procedure tables */
	rpc_init_proc_table(CB_PROGRAM, 1, cb1_proc, hf_nispluscb_procedure_v1);
}
