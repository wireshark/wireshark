/* packet-dcerpc-samr.c
 * Routines for SMB \\PIPE\\samr packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-dcerpc-samr.c,v 1.4 2002/01/25 08:35:59 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"
#include "packet-dcerpc-samr.h"
#include "smb.h"	/* for "NT_errors[]" */

static int proto_dcerpc_samr = -1;

static int hf_samr_hnd = -1;
static int hf_samr_perms = -1;
static int hf_samr_rid = -1;
static int hf_samr_rc = -1;
static int hf_samr_index = -1;
static int hf_samr_acct_ctrl = -1;
static int hf_samr_array_max_count = -1;

static int hf_samr_level = -1;
static int hf_samr_start_idx = -1;
static int hf_samr_max_entries = -1;
static int hf_samr_pref_maxsize = -1;
static int hf_samr_total_size = -1;
static int hf_samr_ret_size = -1;
static int hf_samr_acct_name = -1;
static int hf_samr_full_name = -1;
static int hf_samr_acct_desc = -1;

/* these are used by functions in packet-dcerpc-nt.c */
int hf_nt_str_len = -1;
int hf_nt_str_off = -1;
int hf_nt_str_max_len = -1;
int hf_nt_string_length = -1;
int hf_nt_string_size = -1;


static gint ett_dcerpc_samr = -1;
gint ett_nt_unicode_string = -1;	/* used by packet-dcerpc-nt.c*/
static gint ett_samr_user_dispinfo_1 = -1;

static e_uuid_t uuid_dcerpc_samr = {
        0x12345778, 0x1234, 0xabcd, 
        { 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xac}
};

static guint16 ver_dcerpc_samr = 1;

static int
samr_dissect_gen_open_reply (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                      hf_samr_hnd, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rc, NULL);
        return offset;
}

static int
samr_dissect_close_hnd_rqst (tvbuff_t *tvb, int offset, 
                              packet_info *pinfo, proto_tree *tree, 
                              char *drep)
{
        offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                      hf_samr_hnd, NULL);
        return offset;
}

static int
samr_dissect_open_user_rqst (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                      hf_samr_hnd, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_perms, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rid, NULL);
        return offset;
}


static int
samr_dissect_query_dispinfo_level (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_level, NULL);

	return offset;
}

static int
samr_dissect_query_dispinfo_rqst (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                      hf_samr_hnd, NULL);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_query_dispinfo_level, NDR_POINTER_REF,
			-1);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_start_idx, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_max_entries, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_pref_maxsize, NULL);
        return offset;
}

static int
samr_dissect_USER_DISPINFO_1 (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *parent_tree, 
                             char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"User_DispInfo_1");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_index, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rid, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_acct_ctrl, NULL);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
			hf_samr_acct_name);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
			hf_samr_full_name);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
			hf_samr_acct_desc);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_DISPINFO_1_ARRAY_users (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_USER_DISPINFO_1);

	return offset;
}

static int
samr_dissect_USER_DISPINFO_1_ARRAY (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *parent_tree, 
                             char *drep)
{
	guint32 count;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"User_DispInfo_1 Array");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}


        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_array_max_count, &count);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_USER_DISPINFO_1_ARRAY_users, NDR_POINTER_PTR,
			-1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}



static int
samr_dissect_USER_DISPINFO_2 (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *parent_tree, 
                             char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"User_DispInfo_2");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_index, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rid, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_acct_ctrl, NULL);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
			hf_samr_acct_name);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
			hf_samr_acct_desc);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_DISPINFO_2_ARRAY_users (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_USER_DISPINFO_2);

	return offset;
}

static int
samr_dissect_USER_DISPINFO_2_ARRAY (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *parent_tree, 
                             char *drep)
{
	guint32 count;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"User_DispInfo_2 Array");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}


        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_array_max_count, &count);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_USER_DISPINFO_2_ARRAY_users, NDR_POINTER_PTR,
			-1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}





static int
samr_dissect_GROUP_DISPINFO (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *parent_tree, 
                             char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"Group_DispInfo");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_index, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rid, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_acct_ctrl, NULL);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
			hf_samr_acct_name);
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
			hf_samr_acct_desc);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_GROUP_DISPINFO_ARRAY_groups (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_GROUP_DISPINFO);

	return offset;
}

static int
samr_dissect_GROUP_DISPINFO_ARRAY (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *parent_tree, 
                             char *drep)
{
	guint32 count;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"Group_DispInfo Array");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_array_max_count, &count);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_GROUP_DISPINFO_ARRAY_groups, NDR_POINTER_PTR,
			-1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}



static int
samr_dissect_ASCII_DISPINFO (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *parent_tree, 
                             char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"Ascii_DispInfo");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_index, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rid, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_acct_ctrl, NULL);
	offset = dissect_ndr_nt_STRING(tvb, offset, pinfo, tree, drep,
			hf_samr_acct_name);
	offset = dissect_ndr_nt_STRING(tvb, offset, pinfo, tree, drep,
			hf_samr_acct_desc);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_ASCII_DISPINFO_ARRAY_users (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_ASCII_DISPINFO);

	return offset;
}

static int
samr_dissect_ASCII_DISPINFO_ARRAY (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *parent_tree,
                             char *drep)
{
	guint32 count;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"Ascii_DispInfo Array");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_array_max_count, &count);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_ASCII_DISPINFO_ARRAY_users, NDR_POINTER_PTR,
			-1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
samr_dissect_DISPLAY_INFO (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *parent_tree,
                             char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;
	guint16 level;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"DispInfo");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_level, &level);
	switch(level){
	case 1:	
		offset = samr_dissect_USER_DISPINFO_1_ARRAY(
				tvb, offset, pinfo, tree, drep);
		break;
	case 2:	
		offset = samr_dissect_USER_DISPINFO_2_ARRAY(
				tvb, offset, pinfo, tree, drep);
		break;
	case 3:	
		offset = samr_dissect_GROUP_DISPINFO_ARRAY(
				tvb, offset, pinfo, tree, drep);
		break;
	case 4:	
		offset = samr_dissect_ASCII_DISPINFO_ARRAY(
				tvb, offset, pinfo, tree, drep);
		break;
	case 5:	
		offset = samr_dissect_ASCII_DISPINFO_ARRAY(
				tvb, offset, pinfo, tree, drep);
		break;
	}

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_query_dispinfo_total_size (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_total_size, NULL);
	return offset;
}
static int
samr_dissect_query_dispinfo_ret_size (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_ret_size, NULL);
	return offset;
}

static int
samr_dissect_query_dispinfo_reply (tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_query_dispinfo_total_size, NDR_POINTER_REF,
			-1);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_query_dispinfo_ret_size, NDR_POINTER_REF,
			-1);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_DISPLAY_INFO, NDR_POINTER_REF,
			-1);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rc, NULL);

	return offset;
}


static dcerpc_sub_dissector dcerpc_samr_dissectors[] = {
        { SAMR_CONNECT_ANON, "SAMR_CONNECT_ANON", NULL, samr_dissect_gen_open_reply },
        { SAMR_CLOSE_HND, "SAMR_CLOSE_HND", samr_dissect_close_hnd_rqst, samr_dissect_gen_open_reply },
        { SAMR_UNKNOWN_2, "SAMR_UNKNOWN_2", NULL, NULL },
        { SAMR_QUERY_SEC_OBJECT, "SAMR_QUERY_SEC_OBJECT", NULL, NULL },
        { SAMR_UNKNOWN_4, "SAMR_UNKNOWN_4", NULL, NULL },
        { SAMR_LOOKUP_DOMAIN, "SAMR_LOOKUP_DOMAIN", NULL, NULL },
        { SAMR_ENUM_DOMAINS, "SAMR_ENUM_DOMAINS", NULL, NULL },
        { SAMR_OPEN_DOMAIN, "SAMR_OPEN_DOMAIN", NULL, samr_dissect_gen_open_reply },
        { SAMR_QUERY_DOMAIN_INFO, "SAMR_QUERY_DOMAIN_INFO", NULL, NULL },
        { SAMR_CREATE_DOM_GROUP, "SAMR_CREATE_DOM_GROUP", NULL, NULL },
        { SAMR_ENUM_DOM_GROUPS, "SAMR_ENUM_DOM_GROUPS", NULL, NULL },
        { SAMR_ENUM_DOM_USERS, "SAMR_ENUM_DOM_USERS", NULL, NULL },
        { SAMR_CREATE_DOM_ALIAS, "SAMR_CREATE_DOM_ALIAS", NULL, NULL },
        { SAMR_ENUM_DOM_ALIASES, "SAMR_ENUM_DOM_ALIASES", NULL, NULL },
        { SAMR_QUERY_USERALIASES, "SAMR_QUERY_USERALIASES", NULL, NULL },
        { SAMR_LOOKUP_NAMES, "SAMR_LOOKUP_NAMES", NULL, NULL },
        { SAMR_LOOKUP_RIDS, "SAMR_LOOKUP_RIDS", NULL, NULL },
        { SAMR_OPEN_GROUP, "SAMR_OPEN_GROUP", NULL, samr_dissect_gen_open_reply },
        { SAMR_QUERY_GROUPINFO, "SAMR_QUERY_GROUPINFO", NULL, NULL },
        { SAMR_SET_GROUPINFO, "SAMR_SET_GROUPINFO", NULL, NULL },
        { SAMR_ADD_GROUPMEM, "SAMR_ADD_GROUPMEM", NULL, NULL },
        { SAMR_DELETE_DOM_GROUP, "SAMR_DELETE_DOM_GROUP", NULL, NULL },
        { SAMR_DEL_GROUPMEM, "SAMR_DEL_GROUPMEM", NULL, NULL },
        { SAMR_QUERY_GROUPMEM, "SAMR_QUERY_GROUPMEM", NULL, NULL },
        { SAMR_UNKNOWN_1A, "SAMR_UNKNOWN_1A", NULL, NULL },
        { SAMR_OPEN_ALIAS, "SAMR_OPEN_ALIAS", NULL, samr_dissect_gen_open_reply },
        { SAMR_QUERY_ALIASINFO, "SAMR_QUERY_ALIASINFO", NULL, NULL },
        { SAMR_SET_ALIASINFO, "SAMR_SET_ALIASINFO", NULL, NULL },
        { SAMR_DELETE_DOM_ALIAS, "SAMR_DELETE_DOM_ALIAS", NULL, NULL },
        { SAMR_ADD_ALIASMEM, "SAMR_ADD_ALIASMEM", NULL, NULL },
        { SAMR_DEL_ALIASMEM, "SAMR_DEL_ALIASMEM", NULL, NULL },
        { SAMR_QUERY_ALIASMEM, "SAMR_QUERY_ALIASMEM", NULL, NULL },
        { SAMR_OPEN_USER, "SAMR_OPEN_USER", samr_dissect_open_user_rqst, samr_dissect_gen_open_reply },
        { SAMR_DELETE_DOM_USER, "SAMR_DELETE_DOM_USER", NULL, NULL },
        { SAMR_QUERY_USERINFO, "SAMR_QUERY_USERINFO", NULL, NULL },
        { SAMR_SET_USERINFO2, "SAMR_SET_USERINFO2", NULL, NULL },
        { SAMR_QUERY_USERGROUPS, "SAMR_QUERY_USERGROUPS", NULL, NULL },
        { SAMR_QUERY_DISPINFO, "SAMR_QUERY_DISPINFO", samr_dissect_query_dispinfo_rqst, samr_dissect_query_dispinfo_reply },
        { SAMR_UNKNOWN_29, "SAMR_UNKNOWN_29", NULL, NULL },
        { SAMR_UNKNOWN_2a, "SAMR_UNKNOWN_2a", NULL, NULL },
        { SAMR_UNKNOWN_2b, "SAMR_UNKNOWN_2b", NULL, NULL },
        { SAMR_GET_USRDOM_PWINFO, "SAMR_GET_USRDOM_PWINFO", NULL, NULL },
        { SAMR_UNKNOWN_2D, "SAMR_UNKNOWN_2D", NULL, NULL },
        { SAMR_UNKNOWN_2e, "SAMR_UNKNOWN_2e", NULL, NULL },
        { SAMR_UNKNOWN_2f, "SAMR_UNKNOWN_2f", NULL, NULL },
        { SAMR_QUERY_DISPINFO3, "SAMR_QUERY_DISPINFO3", NULL, NULL },
        { SAMR_UNKNOWN_31, "SAMR_UNKNOWN_31", NULL, NULL },
        { SAMR_CREATE_USER, "SAMR_CREATE_USER", NULL, NULL },
        { SAMR_QUERY_DISPINFO4, "SAMR_QUERY_DISPINFO4", NULL, NULL },
        { SAMR_ADDMULTI_ALIASMEM, "SAMR_ADDMULTI_ALIASMEM", NULL, NULL },
        { SAMR_UNKNOWN_35, "SAMR_UNKNOWN_35", NULL, NULL },
        { SAMR_UNKNOWN_36, "SAMR_UNKNOWN_36", NULL, NULL },
        { SAMR_CHGPASSWD_USER, "SAMR_CHGPASSWD_USER", NULL, NULL },
        { SAMR_GET_DOM_PWINFO, "SAMR_GET_DOM_PWINFO", NULL, NULL },
        { SAMR_CONNECT, "SAMR_CONNECT", NULL, samr_dissect_gen_open_reply },
        { SAMR_SET_USERINFO, "SAMR_SET_USERINFO", NULL, NULL },

        {0, NULL, NULL,  NULL },
};

void 
proto_register_dcerpc_samr(void)
{
        static hf_register_info hf[] = {
                { &hf_samr_hnd,
                  { "Context Handle", "samr.hnd", FT_BYTES, BASE_NONE, NULL, 0x0, "", HFILL }},
                { &hf_samr_perms,
                  { "Access Mask", "samr.perms", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
                { &hf_samr_rid,
                  { "Rid", "samr.rid", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
                { &hf_samr_rc,
                  { "Return code", "samr.rc", FT_UINT32, BASE_HEX, VALS (NT_errors), 0x0, "", HFILL }},

	{ &hf_samr_level,
		{ "Level", "samr.level", FT_UINT16, BASE_DEC, 
		NULL, 0x0, "Level requested/returned for Information", HFILL }},
	{ &hf_samr_start_idx,
		{ "Start Idx", "samr.start_idx", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Start Index for returned Information", HFILL }},

	{ &hf_samr_max_entries,
		{ "Max Entries", "samr.max_entries", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Maximum number of entries to return", HFILL }},

	{ &hf_samr_pref_maxsize,
		{ "Pref MaxSize", "samr.pref_maxsize", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Maximum Size of data to return", HFILL }},

	{ &hf_samr_total_size,
		{ "Total Size", "samr.total_size", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Total size of data", HFILL }},

	{ &hf_samr_ret_size,
		{ "Returned Size", "samr.ret_size", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Number of returned objects in this PDU", HFILL }},

	{ &hf_samr_index,
		{ "Index", "samr.index", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Index", HFILL }},

	{ &hf_samr_acct_ctrl,
		{ "Acct Ctrl", "samr.acct_ctrl", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Acct CTRL", HFILL }},

        { &hf_samr_array_max_count,
          { "Max Count", "samr.array.max_count", FT_UINT32, BASE_DEC, NULL, 0x0, "Maximum Count: Number of elements in the array", HFILL }},

	{ &hf_samr_acct_name,
		{ "Account Name", "samr.acct_name", FT_STRING, BASE_NONE,
		NULL, 0, "Name of Account", HFILL }},

	{ &hf_samr_full_name,
		{ "Full Name", "samr.full_name", FT_STRING, BASE_NONE,
		NULL, 0, "Full Name of Account", HFILL }},

	{ &hf_samr_acct_desc,
		{ "Account Desc", "samr.acct_desc", FT_STRING, BASE_NONE,
		NULL, 0, "Account Description", HFILL }},



	/* these are used by packet-dcerpc-nt.c */
	{ &hf_nt_string_length,
		{ "Length", "nt.string.length", FT_UINT16, BASE_DEC, 
		NULL, 0x0, "Length of string in bytes", HFILL }},

	{ &hf_nt_string_size,
		{ "Size", "nt.string.size", FT_UINT16, BASE_DEC, 
		NULL, 0x0, "Size of string in bytes", HFILL }},

	{ &hf_nt_str_len,
		{ "Length", "nt.str.len", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Length of string in short integers", HFILL }},

	{ &hf_nt_str_off,
		{ "Offset", "nt.str.offset", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Offset into string in short integers", HFILL }},

	{ &hf_nt_str_max_len,
		{ "Max Length", "nt.str.max_len", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Max Length of string in short integers", HFILL }},
        };
        static gint *ett[] = {
                &ett_dcerpc_samr,
                &ett_nt_unicode_string,
		&ett_samr_user_dispinfo_1,
        };

        proto_dcerpc_samr = proto_register_protocol(
                "Microsoft Security Account Manager", "SAMR", "samr");

        proto_register_field_array (proto_dcerpc_samr, hf, array_length (hf));
        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dcerpc_samr(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_samr, ett_dcerpc_samr, &uuid_dcerpc_samr,
                         ver_dcerpc_samr, dcerpc_samr_dissectors);
}
