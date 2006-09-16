/* packet-dcerpc-samr.c
 * Routines for SMB \PIPE\samr packet disassembly
 * Copyright 2001,2003 Tim Potter <tpot@samba.org>
 *   2002 Added all command dissectors  Ronnie Sahlberg
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

#include <glib.h>
#include <epan/packet.h>
#include <string.h>
#include <epan/prefs.h>
#include <epan/crypt-md4.h>
#include <epan/crypt-rc4.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"
#include "packet-dcerpc-samr.h"
#include "packet-windows-common.h"
#include "packet-smb-common.h"
#include <epan/emem.h>

static int proto_dcerpc_samr = -1;

static int hf_samr_opnum = -1;
static int hf_samr_hnd = -1;
static int hf_samr_group = -1;
static int hf_samr_rid = -1;
static int hf_samr_type = -1;
static int hf_samr_alias = -1;
static int hf_samr_rid_attrib = -1;
static int hf_samr_rc = -1;
static int hf_samr_index = -1;
static int hf_samr_count = -1;
static int hf_samr_sd_size = -1;

static int hf_samr_level = -1;
static int hf_samr_start_idx = -1;
static int hf_samr_max_entries = -1;
static int hf_samr_entries = -1;
static int hf_samr_pref_maxsize = -1;
static int hf_samr_total_size = -1;
static int hf_samr_ret_size = -1;
static int hf_samr_alias_name = -1;
static int hf_samr_group_name = -1;
static int hf_samr_acct_name = -1;
static int hf_samr_full_name = -1;
static int hf_samr_acct_desc = -1;
static int hf_samr_home = -1;
static int hf_samr_home_drive = -1;
static int hf_samr_script = -1;
static int hf_samr_workstations = -1;
static int hf_samr_profile = -1;
static int hf_samr_callback = -1;
static int hf_samr_server = -1;
static int hf_samr_domain = -1;
static int hf_samr_controller = -1;
static int hf_samr_access = -1;
static int hf_samr_access_granted = -1;
static int hf_samr_crypt_password = -1;
static int hf_samr_crypt_hash = -1;
static int hf_samr_lm_change = -1;
static int hf_samr_lm_passchange_block = -1;
static int hf_samr_nt_passchange_block = -1;
static int hf_samr_nt_passchange_block_decrypted = -1;
static int hf_samr_nt_passchange_block_newpass = -1;
static int hf_samr_nt_passchange_block_newpass_len = -1;
static int hf_samr_nt_passchange_block_pseudorandom = -1;
static int hf_samr_lm_verifier = -1;
static int hf_samr_nt_verifier = -1;
static int hf_samr_attrib = -1;
static int hf_samr_force_logoff_time = -1;
static int hf_samr_lockout_duration_time = -1;
static int hf_samr_lockout_reset_time = -1;
static int hf_samr_lockout_threshold_short = -1;
static int hf_samr_max_pwd_age = -1;
static int hf_samr_min_pwd_age = -1;
static int hf_samr_min_pwd_len = -1;
static int hf_samr_pwd_history_len = -1;
static int hf_samr_num_users = -1;
static int hf_samr_num_groups = -1;
static int hf_samr_num_aliases = -1;
static int hf_samr_resume_hnd = -1;
static int hf_samr_bad_pwd_count = -1;
static int hf_samr_logon_count = -1;
static int hf_samr_logon_time = -1;
static int hf_samr_logoff_time = -1;
static int hf_samr_kickoff_time = -1;
static int hf_samr_pwd_last_set_time = -1;
static int hf_samr_pwd_can_change_time = -1;
static int hf_samr_pwd_must_change_time = -1;
static int hf_samr_acct_expiry_time = -1;
static int hf_samr_country = -1;
static int hf_samr_codepage = -1;
static int hf_samr_comment = -1;
static int hf_samr_nt_pwd_set = -1;
static int hf_samr_lm_pwd_set = -1;
static int hf_samr_pwd_expired = -1;
static int hf_samr_revision = -1;
static int hf_samr_info_type = -1;
static int hf_samr_primary_group_rid = -1;
static int hf_samr_group_num_of_members = -1;
static int hf_samr_group_desc = -1;
static int hf_samr_alias_num_of_members = -1;
static int hf_samr_alias_desc = -1;

static int hf_samr_unknown_hyper = -1;
static int hf_samr_unknown_long = -1;
static int hf_samr_unknown_short = -1;
static int hf_samr_unknown_char = -1;
static int hf_samr_unknown_string = -1;
static int hf_samr_unknown_time = -1;

static gint ett_dcerpc_samr = -1;
static gint ett_SAM_SECURITY_DESCRIPTOR = -1;
static gint ett_samr_user_dispinfo_1 = -1;
static gint ett_samr_user_dispinfo_1_array = -1;
static gint ett_samr_user_dispinfo_2 = -1;
static gint ett_samr_user_dispinfo_2_array = -1;
static gint ett_samr_group_dispinfo = -1;
static gint ett_samr_group_dispinfo_array = -1;
static gint ett_samr_ascii_dispinfo = -1;
static gint ett_samr_ascii_dispinfo_array = -1;
static gint ett_samr_display_info = -1;
static gint ett_samr_password_info = -1;
static gint ett_samr_server = -1;
static gint ett_samr_user_group = -1;
static gint ett_samr_user_group_array = -1;
static gint ett_samr_alias_info = -1;
static gint ett_samr_group_info = -1;
static gint ett_samr_domain_info_1 = -1;
static gint ett_samr_domain_info_2 = -1;
static gint ett_samr_domain_info_8 = -1;
static gint ett_samr_replication_status = -1;
static gint ett_samr_domain_info_11 = -1;
static gint ett_samr_domain_info_13 = -1;
static gint ett_samr_domain_info = -1;
static gint ett_samr_index_array = -1;
static gint ett_samr_idx_and_name = -1;
static gint ett_samr_idx_and_name_array = -1;
static gint ett_samr_user_info_1 = -1;
static gint ett_samr_user_info_2 = -1;
static gint ett_samr_user_info_3 = -1;
static gint ett_samr_user_info_5 = -1;
static gint ett_samr_user_info_6 = -1;
static gint ett_samr_user_info_10 = -1;
static gint ett_samr_user_info_18 = -1;
static gint ett_samr_user_info_19 = -1;
static gint ett_samr_buffer_buffer = -1;
static gint ett_samr_buffer = -1;
static gint ett_samr_user_info_21 = -1;
static gint ett_samr_user_info_22 = -1;
static gint ett_samr_user_info_23 = -1;
static gint ett_samr_user_info_24 = -1;
static gint ett_samr_user_info_25 = -1;
static gint ett_samr_user_info = -1;
static gint ett_samr_member_array_types = -1;
static gint ett_samr_member_array_rids = -1;
static gint ett_samr_member_array = -1;
static gint ett_samr_names = -1;
static gint ett_samr_rids = -1;
#ifdef SAMR_UNUSED_HANDLES
static gint ett_samr_hnd = -1;
#endif

static e_uuid_t uuid_dcerpc_samr = {
        0x12345778, 0x1234, 0xabcd,
        { 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xac}
};

static guint16 ver_dcerpc_samr = 1;

/* Configuration variables */
static const char *nt_password = NULL;

/* Dissect connect specific access rights */

static gint hf_access_connect_connect_to_server = -1;
static gint hf_access_connect_shutdown_server = -1;
static gint hf_access_connect_initialize_server = -1;
static gint hf_access_connect_create_domain = -1;
static gint hf_access_connect_enum_domains = -1;
static gint hf_access_connect_open_domain = -1;

static void
specific_rights_connect(tvbuff_t *tvb, gint offset, proto_tree *tree,
			guint32 access)
{
	proto_tree_add_boolean(
		tree, hf_access_connect_open_domain,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_connect_enum_domains,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_connect_create_domain,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_connect_initialize_server,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_connect_shutdown_server,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_connect_connect_to_server,
		tvb, offset, 4, access);
}

struct access_mask_info samr_connect_access_mask_info = {
	"SAMR connect",
	specific_rights_connect,
	NULL,			    /* Generic rights mapping */
	NULL                        /* Standard rights mapping */
};


static int
sam_dissect_SAM_SECURITY_DESCRIPTOR_data(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
       guint32 len;
       dcerpc_info *di;

       di=pinfo->private_data;
       if(di->conformant_run){
               /*just a run to handle conformant arrays, nothing to dissect */
               return offset;
       }

       offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                    hf_samr_sd_size, &len);

       dissect_nt_sec_desc(
               tvb, offset, pinfo, tree, drep, TRUE, len,
               &samr_connect_access_mask_info);

       offset += len;

       return offset;
}

static int
sam_dissect_SAM_SECURITY_DESCRIPTOR(tvbuff_t *tvb, int offset,
                       packet_info *pinfo, proto_tree *parent_tree,
                       guint8 *drep)
{
       proto_item *item=NULL;
       proto_tree *tree=NULL;
       int old_offset=offset;

       if(parent_tree){
               item = proto_tree_add_text(parent_tree, tvb, offset, -1,
                       "SAM_SECURITY_DESCRIPTOR:");
               tree = proto_item_add_subtree(item, ett_SAM_SECURITY_DESCRIPTOR);
       }

       offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                   hf_samr_sd_size, NULL);

       offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                       sam_dissect_SAM_SECURITY_DESCRIPTOR_data, NDR_POINTER_UNIQUE,
                       "SAM SECURITY DESCRIPTOR data:", -1);

       proto_item_set_len(item, offset-old_offset);
       return offset;
}


/* Dissect domain specific access rights */

static gint hf_access_domain_lookup_info1 = -1;
static gint hf_access_domain_set_info1 = -1;
static gint hf_access_domain_lookup_info2 = -1;
static gint hf_access_domain_set_info2 = -1;
static gint hf_access_domain_create_user = -1;
static gint hf_access_domain_create_group = -1;
static gint hf_access_domain_create_alias = -1;
static gint hf_access_domain_lookup_alias_by_mem = -1;
static gint hf_access_domain_enum_accounts = -1;
static gint hf_access_domain_open_account = -1;
static gint hf_access_domain_set_info3 = -1;

static void
specific_rights_domain(tvbuff_t *tvb, gint offset, proto_tree *tree,
		       guint32 access)
{
	proto_tree_add_boolean(
		tree, hf_access_domain_set_info3,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_domain_open_account,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_domain_enum_accounts,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_domain_lookup_alias_by_mem,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_domain_create_alias,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_domain_create_group,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_domain_create_user,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_domain_set_info2,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_domain_lookup_info2,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_domain_set_info1,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_domain_lookup_info1,
		tvb, offset, 4, access);
	}

struct access_mask_info samr_domain_access_mask_info = {
	"SAMR domain",
	specific_rights_domain,
	NULL,			/* Generic mapping table */
	NULL			/* Standard mapping table */
};

/* Dissect user specific access rights */

static gint hf_access_user_get_name_etc = -1;
static gint hf_access_user_get_locale = -1;
static gint hf_access_user_get_loc_com = -1;
static gint hf_access_user_get_logoninfo = -1;
static gint hf_access_user_get_attributes = -1;
static gint hf_access_user_set_attributes = -1;
static gint hf_access_user_change_password = -1;
static gint hf_access_user_set_password = -1;
static gint hf_access_user_get_groups = -1;
static gint hf_access_user_get_group_membership = -1;
static gint hf_access_user_change_group_membership = -1;

static void
specific_rights_user(tvbuff_t *tvb, gint offset, proto_tree *tree,
		     guint32 access)
{
	proto_tree_add_boolean(
		tree, hf_access_user_change_group_membership,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_user_get_group_membership,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_user_get_groups,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_user_set_password,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_user_change_password,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_user_set_attributes,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_user_get_attributes,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_user_get_logoninfo,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_user_get_loc_com,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_user_get_locale,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_user_get_name_etc,
		tvb, offset, 4, access);
}

struct access_mask_info samr_user_access_mask_info = {
	"SAMR user",
	specific_rights_user,
	NULL,			/* Generic mapping table */
	NULL			/* Standard mapping table */
};

/* Dissect alias specific access rights */

static gint hf_access_alias_add_member = -1;
static gint hf_access_alias_remove_member = -1;
static gint hf_access_alias_get_members = -1;
static gint hf_access_alias_lookup_info = -1;
static gint hf_access_alias_set_info = -1;

static void
specific_rights_alias(tvbuff_t *tvb, gint offset, proto_tree *tree,
		      guint32 access)
{
	proto_tree_add_boolean(
		tree, hf_access_alias_set_info,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_alias_lookup_info,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_alias_get_members,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_alias_remove_member,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_alias_add_member,
		tvb, offset, 4, access);
}

struct access_mask_info samr_alias_access_mask_info = {
	"SAMR alias",
	specific_rights_alias,
	NULL,			/* Generic mapping table */
	NULL			/* Standard mapping table */
};

/* Dissect group specific access rights */

static gint hf_access_group_lookup_info = -1;
static gint hf_access_group_set_info = -1;
static gint hf_access_group_add_member = -1;
static gint hf_access_group_remove_member = -1;
static gint hf_access_group_get_members = -1;

static void
specific_rights_group(tvbuff_t *tvb, gint offset, proto_tree *tree,
		      guint32 access)
{
	proto_tree_add_boolean(
		tree, hf_access_group_get_members,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_group_remove_member,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_group_add_member,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_group_set_info,
		tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_access_group_lookup_info,
		tvb, offset, 4, access);
}

struct access_mask_info samr_group_access_mask_info = {
	"SAMR group",
	specific_rights_group,
	NULL,			/* Generic mapping table */
	NULL			/* Standard mapping table */
};

static int
dissect_ndr_nt_SID_no_hf(tvbuff_t *tvb, int offset, packet_info *pinfo, 
		   proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_nt_SID(tvb, offset, pinfo, tree, drep);
	return offset;
}

/* above this line, just some general support routines which should be placed
   in some more generic file common to all NT services dissectors
*/

static int
samr_dissect_open_user_rqst(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, guint8 *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 rid;

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

       offset = dissect_nt_access_mask(
               tvb, offset, pinfo, tree, drep, hf_samr_access,
               &samr_user_access_mask_info, NULL);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_rid, &rid);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", rid 0x%x", rid);

	/* OpenUser() stores the rid in se_data */
	if(!pinfo->fd->flags.visited){
		if(!dcv->se_data){
			dcv->se_data = se_strdup_printf("0x%x", rid);
		}
	}

	return offset;
}

static int
samr_dissect_open_user_reply(tvbuff_t *tvb, int offset,
			     packet_info *pinfo, proto_tree *tree,
			     guint8 *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;
	proto_item *hnd_item;
	guint32 status;

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, &policy_hnd, &hnd_item,
				       TRUE, FALSE);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, &status);

	if( status == 0 ){
		char *pol_name;

		if (dcv->se_data){
			pol_name = ep_strdup_printf(
				"SamrOpenUser(rid %s)", (char *)dcv->se_data);
		} else {
			pol_name = "Unknown SamrOpenUser() handle";
		}
		if(!pinfo->fd->flags.visited){
			dcerpc_smb_store_pol_name(&policy_hnd, pinfo, pol_name);
		}

		if(hnd_item)
			proto_item_append_text(hnd_item, ": %s", pol_name);
	}

	return offset;
}

static int
samr_dissect_pointer_long(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
	dcerpc_info *di;

	di=pinfo->private_data;
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     di->hf_index, NULL);
	return offset;
}

static int
samr_dissect_pointer_STRING(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
			di->hf_index, 0);
	return offset;
}

static int
samr_dissect_pointer_short(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
	dcerpc_info *di;

	di=pinfo->private_data;
        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     di->hf_index, NULL);
	return offset;
}


static int
samr_dissect_query_dispinfo_rqst(tvbuff_t *tvb, int offset,
				 packet_info *pinfo, proto_tree *tree,
				 guint8 *drep)
{
	guint16 level;
	guint32 start_idx;

        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_level, &level);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_start_idx, &start_idx);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_max_entries, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_pref_maxsize, NULL);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(
			pinfo->cinfo, COL_INFO, ", level %d, start_idx %d", 
			level, start_idx);

        return offset;
}

static int
samr_dissect_USER_DISPINFO_1(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"User_DispInfo_1");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1);
	}

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
				hf_samr_index, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
				hf_samr_rid, NULL);
	offset = dissect_ndr_nt_acct_ctrl(tvb, offset, pinfo, tree, drep);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_acct_name, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_full_name, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_acct_desc, 0);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_DISPINFO_1_ARRAY_users(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_USER_DISPINFO_1);

	return offset;
}

static int
samr_dissect_USER_DISPINFO_1_ARRAY (tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *parent_tree,
                             guint8 *drep)
{
	guint32 count;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"User_DispInfo_1 Array");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_1_array);
	}


        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_count, &count);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_USER_DISPINFO_1_ARRAY_users, NDR_POINTER_PTR,
			"USER_DISPINFO_1_ARRAY", -1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}



static int
samr_dissect_USER_DISPINFO_2(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"User_DispInfo_2");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_2);
	}

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_index, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_rid, NULL);
	offset = dissect_ndr_nt_acct_ctrl(tvb, offset, pinfo, tree, drep);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
			hf_samr_acct_name, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
			hf_samr_acct_desc, 0);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_DISPINFO_2_ARRAY_users (tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_USER_DISPINFO_2);

	return offset;
}

static int
samr_dissect_USER_DISPINFO_2_ARRAY (tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *parent_tree,
                             guint8 *drep)
{
	guint32 count;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"User_DispInfo_2 Array");
		tree = proto_item_add_subtree(item, ett_samr_user_dispinfo_2_array);
	}


        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_count, &count);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_USER_DISPINFO_2_ARRAY_users, NDR_POINTER_PTR,
			"USER_DISPINFO_2_ARRAY", -1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_GROUP_DISPINFO(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"Group_DispInfo");
		tree = proto_item_add_subtree(item, ett_samr_group_dispinfo);
	}


	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_index, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_rid, NULL);
	offset = dissect_ndr_nt_acct_ctrl(tvb, offset, pinfo, tree, drep);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
			hf_samr_acct_name, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
			hf_samr_acct_desc, 0);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_GROUP_DISPINFO_ARRAY_groups(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_GROUP_DISPINFO);

	return offset;
}

static int
samr_dissect_GROUP_DISPINFO_ARRAY(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	guint32 count;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"Group_DispInfo Array");
		tree = proto_item_add_subtree(item, ett_samr_group_dispinfo_array);
	}

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_count, &count);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_GROUP_DISPINFO_ARRAY_groups, NDR_POINTER_PTR,
			"GROUP_DISPINFO_ARRAY", -1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}



static int
samr_dissect_ASCII_DISPINFO(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"Ascii_DispInfo");
		tree = proto_item_add_subtree(item, ett_samr_ascii_dispinfo);
	}


	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_index, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_rid, NULL);
	offset = dissect_ndr_nt_acct_ctrl(tvb, offset, pinfo, tree, drep);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
			hf_samr_acct_name, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
			hf_samr_acct_desc, 0);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_ASCII_DISPINFO_ARRAY_users(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_ASCII_DISPINFO);

	return offset;
}

static int
samr_dissect_ASCII_DISPINFO_ARRAY(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	guint32 count;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"Ascii_DispInfo Array");
		tree = proto_item_add_subtree(item, ett_samr_ascii_dispinfo_array);
	}

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_count, &count);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_ASCII_DISPINFO_ARRAY_users, NDR_POINTER_PTR,
			"ACSII_DISPINFO_ARRAY", -1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
samr_dissect_DISPLAY_INFO (tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *parent_tree,
                             guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;
	guint16 level;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"DISP_INFO:");
		tree = proto_item_add_subtree(item, ett_samr_display_info);
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
samr_dissect_query_dispinfo_reply(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  guint8 *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_long, NDR_POINTER_REF,
			"Total Size", hf_samr_total_size);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_long, NDR_POINTER_REF,
			"Returned Size", hf_samr_ret_size);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_DISPLAY_INFO, NDR_POINTER_REF,
			"DISPLAY_INFO:", -1);
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
			hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_get_display_enumeration_index_rqst(tvbuff_t *tvb, int offset,
						packet_info *pinfo,
						proto_tree *tree,
						guint8 *drep)
{
	guint16 level;

        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_level, &level);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
			hf_samr_acct_name, 0);

	return offset;
}

static int
samr_dissect_get_display_enumeration_index_reply(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_long, NDR_POINTER_REF,
			"Index", hf_samr_index);

        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}




static int
samr_dissect_PASSWORD_INFO(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	ALIGN_TO_4_BYTES;  /* strcture starts with short, but is aligned for longs */

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"PASSWORD_INFO:");
		tree = proto_item_add_subtree(item, ett_samr_password_info);
	}


	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_short, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_long, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_get_usrdom_pwinfo_rqst(tvbuff_t *tvb, int offset,
				    packet_info *pinfo, proto_tree *tree,
				    guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

	return offset;
}

static int
samr_dissect_get_usrdom_pwinfo_reply(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_PASSWORD_INFO, NDR_POINTER_REF,
			"PASSWORD_INFO:", -1);

        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);
	return offset;
}

static int
samr_dissect_connect2_rqst(tvbuff_t *tvb, int offset,
			   packet_info *pinfo, proto_tree *tree,
			   guint8 *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	char *sn;

	/* ServerName */
	dcv->private_data=NULL;
	offset = dissect_ndr_pointer_cb(
		tvb, offset, pinfo, tree, drep,
		dissect_ndr_wchar_cvstring, NDR_POINTER_UNIQUE,
		"Server", hf_samr_server, cb_wstr_postprocess,
		GINT_TO_POINTER(CB_STR_COL_INFO | CB_STR_SAVE | 1));
	sn=dcv->private_data;
	if(!sn)
		sn="";

	/* Connect2() stores the server in se_data */
	if(!pinfo->fd->flags.visited){
		if(!dcv->se_data){
			dcv->se_data = se_strdup_printf("%s", sn);
		}
	}

	offset = dissect_nt_access_mask(
		tvb, offset, pinfo, tree, drep, hf_samr_access,
		&samr_connect_access_mask_info, NULL);

	return offset;
}

static int
samr_dissect_connect3_4_rqst(tvbuff_t *tvb, int offset,
			   packet_info *pinfo, proto_tree *tree,
			   guint8 *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	char *sn;

	/* ServerName */
	dcv->private_data=NULL;
	offset = dissect_ndr_pointer_cb(
		tvb, offset, pinfo, tree, drep,
		dissect_ndr_wchar_cvstring, NDR_POINTER_UNIQUE,
		"Server", hf_samr_server, cb_wstr_postprocess,
		GINT_TO_POINTER(CB_STR_COL_INFO | CB_STR_SAVE | 1));
	sn=dcv->private_data;
	if(!sn)
		sn="";

	/* Connect3() stores the server in se_data */
	if(!pinfo->fd->flags.visited){
		if(!dcv->se_data){
			dcv->se_data = se_strdup_printf("%s", sn);
		}
	}

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
				     hf_samr_unknown_long, NULL);

	offset = dissect_nt_access_mask(
		tvb, offset, pinfo, tree, drep, hf_samr_access,
		&samr_connect_access_mask_info, NULL);

	return offset;
}

static int
samr_dissect_connect2_reply(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;
	proto_item *hnd_item;
	guint32 status;
	
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, &policy_hnd, &hnd_item,
				       TRUE, FALSE);

        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, &status);

	if( status == 0 ){
		char *pol_name;

		if (dcv->se_data){
			pol_name = ep_strdup_printf(
				"SamrConnect2(%s)", (char *)dcv->se_data);
		} else {
			pol_name = "Unknown SamrConnect2() handle";
		}
		if(!pinfo->fd->flags.visited){
			dcerpc_smb_store_pol_name(&policy_hnd, pinfo, pol_name);
		}

		if(hnd_item)
			proto_item_append_text(hnd_item, ": %s", pol_name);
	}

	return offset;
}

static int
samr_dissect_connect3_reply(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;
	proto_item *hnd_item;
	guint32 status;
	
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, &policy_hnd, &hnd_item,
				       TRUE, FALSE);

        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, &status);

	if( status == 0 ){
		char *pol_name;

		if (dcv->se_data){
			pol_name = ep_strdup_printf(
				"SamrConnect3(%s)", (char *)dcv->se_data);
		} else {
			pol_name = "Unknown SamrConnect3() handle";
		}
		if(!pinfo->fd->flags.visited){
			dcerpc_smb_store_pol_name(&policy_hnd, pinfo, pol_name);
		}

		if(hnd_item)
			proto_item_append_text(hnd_item, ": %s", pol_name);
	}

	return offset;
}

static int
samr_dissect_connect4_reply(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;
	proto_item *hnd_item;
	guint32 status;
	
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, &policy_hnd, &hnd_item,
				       TRUE, FALSE);

        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, &status);

	if( status == 0 ){
		char *pol_name;

		if (dcv->se_data){
			pol_name = ep_strdup_printf(
				"SamrConnect4(%s)", (char *)dcv->se_data);
		} else {
			pol_name = "Unknown SamrConnect4() handle";
		}
		if(!pinfo->fd->flags.visited){
			dcerpc_smb_store_pol_name(&policy_hnd, pinfo, pol_name);
		}

		if(hnd_item)
			proto_item_append_text(hnd_item, ": %s", pol_name);
	}

	return offset;
}

static int
samr_dissect_connect_anon_rqst(tvbuff_t *tvb, int offset,
			       packet_info *pinfo, proto_tree *tree,
			       guint8 *drep)
{
	char str[2];
	guint16 server;

	offset=dissect_ndr_uint16(tvb, offset, pinfo, NULL, drep,
			hf_samr_server, &server);
	str[0]=server&0xff;
	str[1]=0;
	proto_tree_add_string(tree, hf_samr_server, tvb, offset-2, 2, str);

	return offset;
}

static int
samr_dissect_connect_anon_reply(tvbuff_t *tvb, int offset,
				packet_info *pinfo, proto_tree *tree,
				guint8 *drep)
{
	e_ctx_hnd policy_hnd;
	proto_item *hnd_item;
	guint32 status;

        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, &policy_hnd, &hnd_item,
				       TRUE, FALSE);

        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, &status);

	if (status == 0) {
		dcerpc_smb_store_pol_name(&policy_hnd, pinfo,
					  "ConnectAnon handle");

		if (hnd_item != NULL)
			proto_item_append_text(hnd_item, ": ConnectAnon handle");
	}

	return offset;
}

static int
samr_dissect_USER_GROUP(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *parent_tree,
                             guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"USER_GROUP:");
		tree = proto_item_add_subtree(item, ett_samr_user_group);
	}

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rid, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rid_attrib, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_GROUP_ARRAY_groups (tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_USER_GROUP);

	return offset;
}

static int
samr_dissect_USER_GROUP_ARRAY(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	guint32 count;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"USER_GROUP_ARRAY");
		tree = proto_item_add_subtree(item, ett_samr_user_group_array);
	}

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_count, &count);
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_USER_GROUP_ARRAY_groups, NDR_POINTER_UNIQUE,
			"USER_GROUP_ARRAY", -1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_GROUP_ARRAY_ptr(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			guint8 *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_USER_GROUP_ARRAY, NDR_POINTER_UNIQUE,
			"USER_GROUP_ARRAY", -1);
	return offset;
}

static int
samr_dissect_get_groups_for_user_rqst(tvbuff_t *tvb, int offset,
				      packet_info *pinfo, proto_tree *tree,
				      guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

	return offset;
}

static int
samr_dissect_get_groups_for_user_reply(tvbuff_t *tvb, int offset,
				       packet_info *pinfo, proto_tree *tree,
				       guint8 *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_USER_GROUP_ARRAY_ptr, NDR_POINTER_REF,
			"USER_GROUP_ARRAY:", -1);

        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);
	return offset;
}


static int
samr_dissect_open_domain_rqst(tvbuff_t *tvb, int offset,
			      packet_info *pinfo, proto_tree *tree,
			      guint8 *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	char *sid;

        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

	offset = dissect_nt_access_mask(
		tvb, offset, pinfo, tree, drep, hf_samr_access,
		&samr_domain_access_mask_info, NULL);

	/* SID */
	dcv->private_data=NULL;
        offset = dissect_ndr_pointer_cb(
		tvb, offset, pinfo, tree, drep, dissect_ndr_nt_SID_no_hf, 
		NDR_POINTER_REF, "SID:", -1, NULL, NULL);
	sid=dcv->private_data;
	if(!sid)
		sid="";

	/* OpenDomain() stores the sid in se_data */
	if(!pinfo->fd->flags.visited){
		if(!dcv->se_data){
			dcv->se_data = se_strdup_printf("%s", sid);
		}
	}

	if (dcv->private_data && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", sid);

	return offset;
}

static int
samr_dissect_open_domain_reply(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;
	proto_item *hnd_item;
	guint32 status;

        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, &policy_hnd, &hnd_item,
				       TRUE, FALSE);

        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, &status);

	if( status == 0 ){
		char *pol_name;

		if (dcv->se_data){
			pol_name = ep_strdup_printf(
				"OpenDomain(%s)", (char *)dcv->se_data);
		} else {
			pol_name = "Unknown OpenDomain() handle";
		}
		if(!pinfo->fd->flags.visited){
			dcerpc_smb_store_pol_name(&policy_hnd, pinfo, pol_name);
		}

		if(hnd_item)
			proto_item_append_text(hnd_item, ": %s", pol_name);
	}

	return offset;
}

#if 0
static int
samr_dissect_context_handle_SID(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_SID_no_hf, NDR_POINTER_REF,
			"SID pointer", -1);

	return offset;
}
#endif

static int
samr_dissect_add_member_to_group_rqst(tvbuff_t *tvb, int offset,
				      packet_info *pinfo, proto_tree *tree,
				      guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_group, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rid, NULL);

	return offset;
}

static int
samr_dissect_add_member_to_group_reply(tvbuff_t *tvb, int offset,
				       packet_info *pinfo, proto_tree *tree,
				       guint8 *drep)
{
        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_get_boot_key_information_rqst(tvbuff_t *tvb, int offset,
			     packet_info *pinfo, proto_tree *tree,
			     guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

	return offset;
}

static int
samr_dissect_get_boot_key_information_reply(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_short, NDR_POINTER_REF,
			"unknown short", hf_samr_unknown_short);

        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);
	return offset;
}

static int
samr_dissect_create_alias_in_domain_rqst(tvbuff_t *tvb, int offset,
					 packet_info *pinfo, proto_tree *tree,
					 guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_counted_string_ptr, NDR_POINTER_REF,
			"Alias Name", hf_samr_alias_name);

	offset = dissect_nt_access_mask(
		tvb, offset, pinfo, tree, drep, hf_samr_access,
		&samr_alias_access_mask_info, NULL);

	return offset;
}

static int
samr_dissect_create_alias_in_domain_reply(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
	e_ctx_hnd policy_hnd;
	proto_item *hnd_item;
	guint32 status;

        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, &policy_hnd, &hnd_item,
				       TRUE, FALSE);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rid, NULL);

        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, &status);

	if (status == 0) {
		dcerpc_smb_store_pol_name(&policy_hnd, pinfo,
					  "CreateAlias handle");

		if (hnd_item != NULL)
			proto_item_append_text(hnd_item, ": CreateAlias handle");
	}
	return offset;
}

static int
samr_dissect_query_information_alias_rqst(tvbuff_t *tvb, int offset,
					  packet_info *pinfo,
					  proto_tree *tree, guint8 *drep)
{
	guint16 level;

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
			hf_samr_level, &level);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	return offset;
}

static int
samr_dissect_ALIAS_INFO_1 (tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
	offset = dissect_ndr_counted_string(tvb, offset, pinfo,
		tree, drep, hf_samr_alias_name, 0);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_alias_num_of_members, NULL);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo,
		tree, drep, hf_samr_alias_desc, 0);
	return offset;
}

static int
samr_dissect_ALIAS_INFO(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;
	guint16 level;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"ALIAS_INFO:");
		tree = proto_item_add_subtree(item, ett_samr_alias_info);
	}

        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_level, &level);
	switch(level){
	case 1:
		offset = samr_dissect_ALIAS_INFO_1(
				tvb, offset, pinfo, tree, drep);
		break;
	case 2:
		offset = dissect_ndr_counted_string(tvb, offset, pinfo,
			tree, drep, hf_samr_alias_name, 0);
		break;
	case 3:
		offset = dissect_ndr_counted_string(tvb, offset, pinfo,
			tree, drep, hf_samr_alias_desc, 0);
		break;
	}

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_ALIAS_INFO_ptr(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_ALIAS_INFO, NDR_POINTER_UNIQUE,
			"ALIAS_INFO", -1);
	return offset;
}

static int
samr_dissect_query_information_alias_reply(tvbuff_t *tvb, int offset,
					   packet_info *pinfo,
					   proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_ALIAS_INFO_ptr, NDR_POINTER_REF,
			"ALIAS_INFO:", -1);

        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_set_information_alias_rqst(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
	guint16 level;

        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_level, &level);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_ALIAS_INFO, NDR_POINTER_REF,
			"ALIAS_INFO:", -1);
	return offset;
}

static int
samr_dissect_set_information_alias_reply(tvbuff_t *tvb, int offset,
					 packet_info *pinfo, proto_tree *tree,
					 guint8 *drep)
{
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);
	return offset;
}

static int
samr_dissect_CRYPT_PASSWORD(tvbuff_t *tvb, int offset,
			packet_info *pinfo _U_, proto_tree *tree,
			guint8 *drep _U_)
{
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/* just a run to handle conformant arrays, no scalars to dissect */
		return offset;
	}

	proto_tree_add_item(tree, hf_samr_crypt_password, tvb, offset, 516,
		TRUE);
	offset += 516;
	return offset;
}

static int
samr_dissect_CRYPT_HASH(tvbuff_t *tvb, int offset,
			packet_info *pinfo _U_, proto_tree *tree,
			guint8 *drep _U_)
{
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/* just a run to handle conformant arrays, no scalars to dissect */
		return offset;
	}

	proto_tree_add_item(tree, hf_samr_crypt_hash, tvb, offset, 16,
		TRUE);
	offset += 16;
	return offset;
}

#define NT_BLOCK_SIZE 516

static void
samr_dissect_decrypted_NT_PASSCHANGE_BLOCK(tvbuff_t *tvb, int offset,
				 packet_info *pinfo _U_, proto_tree *tree,
				 guint8 *drep _U_)
{
  guint32 new_password_len = 0;
  guint32 pseudorandom_len = 0;
  const char *printable_password;
  guint16 bc;
  int result_length;

  /* The length of the new password is represented in the last four 
     octets of the decrypted buffer.  Since the password length cannot
     exceed 512, we can check the contents of those bytes to determine 
     if decryption was successful.  If the decrypted contents of those 
     four bytes is less than 512, then there is a 99% chance that
     we decrypted the buffer successfully.  Of course, this isn't good
     enough for a security application, (NT uses the "verifier" field 
     to come to the same conclusion), but it should be good enough for
     our dissector. */
  
  new_password_len = tvb_get_letohl(tvb, 512);  

  if (new_password_len <= 512)
    {
      /* Decryption successful */
      proto_tree_add_text (tree, tvb, offset, -1,
			   "Decryption of NT Password Encrypted block successful");

      /* Whatever is before the password is pseudorandom data.  We calculate 
	 the length by examining the password length (at the end), and working
	 backward */    
      pseudorandom_len = NT_BLOCK_SIZE - new_password_len - 4;

      /* Pseudorandom data padding up to password */
      proto_tree_add_item(tree, hf_samr_nt_passchange_block_pseudorandom, 
			  tvb, offset, pseudorandom_len, TRUE);
      offset += pseudorandom_len;

      /* The new password itself */
      bc = new_password_len;
      printable_password = get_unicode_or_ascii_string(tvb, &offset,
						       TRUE,
						       &result_length,
						       FALSE, TRUE, &bc);
      proto_tree_add_string(tree, hf_samr_nt_passchange_block_newpass,
			    tvb, offset, result_length, 
			    printable_password);
      offset += new_password_len;

      /* Length of password */
      proto_tree_add_item(tree, hf_samr_nt_passchange_block_newpass_len,
			  tvb, offset, 4, TRUE);
    }
  else
    {
      /* Decryption failure.  Just show the encrypted block */
      proto_tree_add_text (tree, tvb, offset, -1,
			   "Decryption of NT Passchange block failed");
      
      proto_tree_add_item(tree, hf_samr_nt_passchange_block_decrypted, tvb,
			  offset, NT_BLOCK_SIZE, TRUE);
    }
}

tvbuff_t *
decrypt_tvb_using_nt_password(packet_info *pinfo, tvbuff_t *tvb, int offset, int len)
{
	rc4_state_struct rc4_state;
	guint i;
	size_t password_len;
	unsigned char *password_unicode;
	size_t password_len_unicode;
	unsigned char password_md4_hash[16];
	guint8 *block;
	tvbuff_t *decr_tvb; /* Used to store decrypted buffer */

	if (nt_password[0] == '\0') {
		/* We dont have an NT password, so we cant decrypt the 
		   blob. */
		return NULL;
	}

	/* This implements the the algorithm discussed in lkcl -"DCE/RPC 
	   over SMB" page 257.  Note that this code does not properly support
	   Unicode. */

	/* Convert the password provided in the Wireshark GUI to Unicode 
	   (UCS-2).  Since the input is always ASCII, we can just fake
	   it and pad every other byte with a NUL.  If we ever support
	   UTF-8 in the GUI, we would have to perform a real UTF-8 to
	   UCS-2 conversion */
	password_len = strlen(nt_password);
	password_len_unicode = password_len*2;
	password_unicode = g_malloc(password_len_unicode);
	for (i = 0; i < password_len; i++) {
		password_unicode[i*2] = nt_password[i];
		password_unicode[i*2+1] = 0;
	}

	/* Run MD4 against the resulting Unicode password.  This will
	   be used to perform RC4 decryption on the blob.  
	   Then free the Unicode password, as we're done
	   with it. */
	crypt_md4(password_md4_hash, password_unicode,
	    password_len_unicode);
	g_free(password_unicode);
	
	/* Copy the block into a temporary buffer so we can decrypt
	   it */
	block = g_malloc(len);
	memset(block, 0, len);
	tvb_memcpy(tvb, block, offset, len);

	/* RC4 decrypt the block with the old NT password hash */
	crypt_rc4_init(&rc4_state, password_md4_hash, 16);
	crypt_rc4(&rc4_state, block, len);

	/* Show the decrypted buffer in a new window */
	decr_tvb = tvb_new_real_data(block, len, len);
	tvb_set_free_cb(decr_tvb, g_free);
	tvb_set_child_real_data_tvbuff(tvb, decr_tvb);
	add_new_data_source(pinfo, decr_tvb,
	    "Decrypted NT Blob");

	return decr_tvb;
}

static int
samr_dissect_NT_PASSCHANGE_BLOCK(tvbuff_t *tvb, int offset,
				 packet_info *pinfo, proto_tree *tree,
				 guint8 *drep _U_)
{
	dcerpc_info *di;
	tvbuff_t *decr_tvb; /* Used to store decrypted buffer */
	
	di=pinfo->private_data;
	if(di->conformant_run){
		/* just a run to handle conformant arrays, no scalars to dissect */
		return offset;
	}

	/* Put in a protocol tree entry for the encrypted block. */
	proto_tree_add_text(tree, tvb, offset, NT_BLOCK_SIZE,
	    "Encrypted NT Password Block");

	decr_tvb=decrypt_tvb_using_nt_password(pinfo, tvb, offset, NT_BLOCK_SIZE);

	if(decr_tvb){
		/* Dissect the decrypted block */
		samr_dissect_decrypted_NT_PASSCHANGE_BLOCK(decr_tvb, 0, pinfo,
							   tree, drep);
	}

	offset += NT_BLOCK_SIZE;
	return offset;
}

static int
samr_dissect_LM_PASSCHANGE_BLOCK(tvbuff_t *tvb, int offset,
				 packet_info *pinfo _U_, proto_tree *tree,
				 guint8 *drep _U_)
{
	dcerpc_info *di;

	/* Right now, this just dumps the output.  In the long term, we can use
	   the algorithm discussed in lkcl -"DCE/RPC over SMB" page 257 to
	   actually decrypt the block */

	di=pinfo->private_data;
	if(di->conformant_run){
		/* just a run to handle conformant arrays, no scalars to dissect */
		return offset;
	}

	proto_tree_add_item(tree, hf_samr_lm_passchange_block, tvb, offset, 
			    516, TRUE);
	offset += 516;
	return offset;
}

static int
samr_dissect_LM_VERIFIER(tvbuff_t *tvb, int offset,
			 packet_info *pinfo _U_, proto_tree *tree,
			 guint8 *drep _U_)
{
	dcerpc_info *di;

	/* Right now, this just dumps the output.  In the long term, we can use
	   the algorithm discussed in lkcl -"DCE/RPC over SMB" page 257 to
	   actually validate the verifier */

	di=pinfo->private_data;
	if(di->conformant_run){
		/* just a run to handle conformant arrays, no scalars to dissect */
		return offset;
	}

	proto_tree_add_item(tree, hf_samr_lm_verifier, tvb, offset, 16,
		TRUE);
	offset += 16;
	return offset;
}


static int
samr_dissect_NT_VERIFIER(tvbuff_t *tvb, int offset,
			 packet_info *pinfo _U_, proto_tree *tree,
			 guint8 *drep _U_)
{
	dcerpc_info *di;

	/* Right now, this just dumps the output.  In the long term, we can use
	   the algorithm discussed in lkcl -"DCE/RPC over SMB" page 257 to
	   actually validate the verifier */

	di=pinfo->private_data;
	if(di->conformant_run){
		/* just a run to handle conformant arrays, no scalars to dissect */
		return offset;
	}

	proto_tree_add_item(tree, hf_samr_nt_verifier, tvb, offset, 16,
		TRUE);
	offset += 16;
	return offset;
}


static int
samr_dissect_oem_change_password_user2_rqst(tvbuff_t *tvb, int offset,
					    packet_info *pinfo,
					    proto_tree *tree, guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_STRING, NDR_POINTER_UNIQUE,
			"Server", hf_samr_server);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_STRING, NDR_POINTER_REF,
			"Account Name", hf_samr_acct_name);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_CRYPT_PASSWORD, NDR_POINTER_UNIQUE,
			"Password", -1);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_CRYPT_HASH, NDR_POINTER_UNIQUE,
			"Hash", -1);
	return offset;
}

static int
samr_dissect_oem_change_password_user2_reply(tvbuff_t *tvb, int offset,
					     packet_info *pinfo,
					     proto_tree *tree, guint8 *drep)
{
        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_unicode_change_password_user2_rqst(tvbuff_t *tvb, int offset,
						packet_info *pinfo,
						proto_tree *tree, guint8 *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_PASSWORD_INFO, NDR_POINTER_REF,
			"PASSWORD_INFO:", -1);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_samr_server, 0);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_counted_string_ptr, NDR_POINTER_REF,
			"Account Name", hf_samr_acct_name);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_NT_PASSCHANGE_BLOCK, NDR_POINTER_UNIQUE,
			"New NT Password Encrypted Block", -1);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_NT_VERIFIER, NDR_POINTER_UNIQUE,
			"NT Password Verifier", -1);
        offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_lm_change, NULL);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_LM_PASSCHANGE_BLOCK, NDR_POINTER_UNIQUE,
			"New Lan Manager Password Encrypted Block", -1);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_LM_VERIFIER, NDR_POINTER_UNIQUE,
			"Lan Manager Password Verifier", -1);
	return offset;
}

static int
samr_dissect_unicode_change_password_user2_reply(tvbuff_t *tvb, int offset,
						 packet_info *pinfo,
						 proto_tree *tree, guint8 *drep)
{
        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_set_boot_key_information_rqst(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_unknown_short, NULL);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_counted_string_ptr, NDR_POINTER_UNIQUE,
			"Unknown", hf_samr_unknown_string);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_counted_string_ptr, NDR_POINTER_UNIQUE,
			"Unknown", hf_samr_unknown_string);
	return offset;
}

static int
samr_dissect_set_boot_key_information_reply(tvbuff_t *tvb, int offset,
			      packet_info *pinfo, proto_tree *tree,
			      guint8 *drep)
{
        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_create_user2_in_domain_rqst(tvbuff_t *tvb, int offset,
					 packet_info *pinfo, proto_tree *tree,
					 guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_counted_string_ptr, NDR_POINTER_REF,
			"Account Name", hf_samr_acct_name);

	offset = dissect_ndr_nt_acct_ctrl(tvb, offset, pinfo, tree, drep);

	offset = dissect_nt_access_mask(
		tvb, offset, pinfo, tree, drep, hf_samr_access,
		&samr_user_access_mask_info, NULL);

	return offset;
}

static int
samr_dissect_create_user2_in_domain_reply(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
	e_ctx_hnd policy_hnd;
	proto_item *hnd_item;
	guint32 status;

        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, &policy_hnd, &hnd_item,
				       TRUE, FALSE);

	offset = dissect_nt_access_mask(
		tvb, offset, pinfo, tree, drep, hf_samr_access_granted,
		&samr_user_access_mask_info, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rid, NULL);

        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, &status);

	if (status == 0) {
		dcerpc_smb_store_pol_name(&policy_hnd, pinfo,
					  "CreateUser2 handle");

		if (hnd_item != NULL)
			proto_item_append_text(hnd_item, ": CreateUser2 handle");
	}

	return offset;
}

static int
samr_dissect_get_display_enumeration_index2_rqst(tvbuff_t *tvb, int offset,
						 packet_info *pinfo,
						 proto_tree *tree, guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_level, NULL);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_counted_string_ptr, NDR_POINTER_REF,
			"Account Name", hf_samr_acct_name);
	return offset;
}

static int
samr_dissect_get_display_enumeration_index2_reply(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_index, NULL);

        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);
	return offset;
}

static int
samr_dissect_change_password_user_rqst(tvbuff_t *tvb, int offset,
				       packet_info *pinfo, proto_tree *tree,
				       guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_char, NULL);
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_CRYPT_HASH, NDR_POINTER_UNIQUE,
			"Hash", -1);
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_CRYPT_HASH, NDR_POINTER_UNIQUE,
			"Hash", -1);
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_char, NULL);
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_CRYPT_HASH, NDR_POINTER_UNIQUE,
			"Hash", -1);
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_CRYPT_HASH, NDR_POINTER_UNIQUE,
			"Hash", -1);
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_char, NULL);
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_CRYPT_HASH, NDR_POINTER_UNIQUE,
			"Hash", -1);
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_char, NULL);
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_CRYPT_HASH, NDR_POINTER_UNIQUE,
			"Hash", -1);

	return offset;
}

static int
samr_dissect_change_password_user_reply(tvbuff_t *tvb, int offset,
					packet_info *pinfo, proto_tree *tree,
					guint8 *drep)
{
        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_set_member_attributes_of_group_rqst(tvbuff_t *tvb, int offset,
						 packet_info *pinfo,
						 proto_tree *tree, guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_attrib, NULL);
	return offset;
}

static int
samr_dissect_set_member_attributes_of_group_reply(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_GROUP_INFO_1 (tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
	offset = dissect_ndr_counted_string(tvb, offset, pinfo,
		tree, drep, hf_samr_group_name, 0);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
					hf_samr_unknown_long, NULL);
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_group_num_of_members, NULL);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo,
		tree, drep, hf_samr_group_desc, 0);
	return offset;
}

static int
samr_dissect_GROUP_INFO(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;
	guint16 level;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"GROUP_INFO:");
		tree = proto_item_add_subtree(item, ett_samr_group_info);
	}

        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_level, &level);
	switch(level){
	case 1:
		offset = samr_dissect_GROUP_INFO_1(
				tvb, offset, pinfo, tree, drep);
		break;
	case 2:
		offset = dissect_ndr_counted_string(tvb, offset, pinfo,
			tree, drep, hf_samr_group_name, 0);
		break;
	case 3:
	        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                        hf_samr_attrib, NULL);
		break;
	case 4:
		offset = dissect_ndr_counted_string(tvb, offset, pinfo,
			tree, drep, hf_samr_group_desc, 0);
		break;
	}

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_GROUP_INFO_ptr(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_GROUP_INFO, NDR_POINTER_UNIQUE,
			"GROUP_INFO", -1);
	return offset;
}

static int
samr_dissect_query_information_group_rqst(tvbuff_t *tvb, int offset,
					  packet_info *pinfo,
					  proto_tree *tree, guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_level, NULL);

	return offset;
}

static int
samr_dissect_query_information_group_reply(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_GROUP_INFO_ptr, NDR_POINTER_REF,
			"GROUP_INFO", -1);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);
	return offset;
}

static int
samr_dissect_set_information_group_rqst(tvbuff_t *tvb, int offset,
					packet_info *pinfo, proto_tree *tree,
					guint8 *drep)
{
	guint16 level;

        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_level, &level);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_GROUP_INFO, NDR_POINTER_REF,
			"GROUP_INFO", -1);
	return offset;
}

static int
samr_dissect_set_information_group_reply(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_get_domain_password_information_rqst(tvbuff_t *tvb, int offset,
						  packet_info *pinfo,
						  proto_tree *tree,
						  guint8 *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_PASSWORD_INFO, NDR_POINTER_REF,
			"PASSWORD_INFO:", -1);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Domain", hf_samr_domain, 0);

	return offset;
}

static int
samr_dissect_get_domain_password_information_reply(tvbuff_t *tvb, int offset,
						   packet_info *pinfo,
						   proto_tree *tree,
						   guint8 *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_PASSWORD_INFO, NDR_POINTER_REF,
			"PASSWORD_INFO:", -1);

        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_DOMAIN_INFO_1(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *parent_tree,
                             guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	ALIGN_TO_4_BYTES;  /* strcture starts with short, but is aligned for longs */

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"DOMAIN_INFO_1:");
		tree = proto_item_add_subtree(item, ett_samr_domain_info_1);
	}

        offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
					hf_samr_min_pwd_len, NULL);
        offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
					hf_samr_pwd_history_len, NULL);
        offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
					hf_samr_unknown_long, NULL);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
					hf_samr_max_pwd_age);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
					hf_samr_min_pwd_age);
	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_DOMAIN_INFO_2(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"DOMAIN_INFO_2:");
		tree = proto_item_add_subtree(item, ett_samr_domain_info_2);
	}

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_time);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_string, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
			hf_samr_domain, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
			hf_samr_controller, 0);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_time);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_long, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_long, NULL);
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_char, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_num_users, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_num_groups, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_num_aliases, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_DOMAIN_INFO_8(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *parent_tree,
                             guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"DOMAIN_INFO_8:");
		tree = proto_item_add_subtree(item, ett_samr_domain_info_8);
	}

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
					hf_samr_max_pwd_age);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
					hf_samr_min_pwd_age);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_REPLICATION_STATUS(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"REPLICATION_STATUS:");
		tree = proto_item_add_subtree(item, ett_samr_replication_status);
	}

	offset = dissect_ndr_duint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_hyper, NULL);
	offset = dissect_ndr_duint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_hyper, NULL);
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_short, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_DOMAIN_INFO_11(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *parent_tree,
                             guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"DOMAIN_INFO_11:");
		tree = proto_item_add_subtree(item, ett_samr_domain_info_11);
	}

	offset = samr_dissect_DOMAIN_INFO_2(
			tvb, offset, pinfo, tree, drep);
	offset = samr_dissect_REPLICATION_STATUS(
			tvb, offset, pinfo, tree, drep);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_DOMAIN_INFO_12(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"DOMAIN_INFO_12:");
		tree = proto_item_add_subtree(item, ett_samr_replication_status);
	}

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_lockout_duration_time);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_lockout_reset_time);
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
				hf_samr_lockout_threshold_short, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_DOMAIN_INFO_13(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *parent_tree,
                             guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"DOMAIN_INFO_13:");
		tree = proto_item_add_subtree(item, ett_samr_domain_info_13);
	}

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
					hf_samr_unknown_time);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
					hf_samr_unknown_time);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
					hf_samr_unknown_time);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
samr_dissect_DOMAIN_INFO(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;
	guint16 level;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"DOMAIN_INFO:");
		tree = proto_item_add_subtree(item, ett_samr_domain_info);
	}

        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_level, &level);

	ALIGN_TO_4_BYTES;  /* all union arms aligned to 4 bytes, case 7 and 9 need this  */
	switch(level){
	case 1:
		offset = samr_dissect_DOMAIN_INFO_1(
				tvb, offset, pinfo, tree, drep);
		break;
	case 2:
		offset = samr_dissect_DOMAIN_INFO_2(
				tvb, offset, pinfo, tree, drep);
		break;

	case 3:
		offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_force_logoff_time);
		break;
	case 4:
		offset = dissect_ndr_counted_string(tvb, offset, pinfo,
			tree, drep, hf_samr_unknown_string, 0);
		break;

	case 5:
		offset = dissect_ndr_counted_string(tvb, offset, pinfo,
			tree, drep, hf_samr_domain, 0);
		break;

	case 6:
		offset = dissect_ndr_counted_string(tvb, offset, pinfo,
			tree, drep, hf_samr_controller, 0);
		break;

	case 7:
	        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_short, NULL);
		break;
	case 8:
		offset = samr_dissect_DOMAIN_INFO_8(
				tvb, offset, pinfo, tree, drep);
		break;
	case 9:
	        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_short, NULL);
		break;
	case 11:
		offset = samr_dissect_DOMAIN_INFO_11(
				tvb, offset, pinfo, tree, drep);
		break;
	case 12:
		offset = samr_dissect_DOMAIN_INFO_12(
				tvb, offset, pinfo, tree, drep);
		break;
	case 13:
		offset = samr_dissect_DOMAIN_INFO_13(
				tvb, offset, pinfo, tree, drep);
		break;
	}

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_set_information_domain_rqst(tvbuff_t *tvb, int offset,
					 packet_info *pinfo, proto_tree *tree,
					 guint8 *drep)
{
	guint16 level;

        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_level, &level);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	offset = samr_dissect_DOMAIN_INFO(tvb, offset, pinfo, tree, drep);

	return offset;
}

static int
samr_dissect_set_information_domain_reply(tvbuff_t *tvb, int offset,
					  packet_info *pinfo,
					  proto_tree *tree, guint8 *drep)
{
        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_create_group_in_domain_rqst(tvbuff_t *tvb, int offset,
				packet_info *pinfo, proto_tree *tree,
				guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_counted_string_ptr, NDR_POINTER_REF,
			"Group Name", hf_samr_group_name);

	offset = dissect_nt_access_mask(
		tvb, offset, pinfo, tree, drep, hf_samr_access,
		&samr_group_access_mask_info, NULL);

	return offset;


}

static int
samr_dissect_create_group_in_domain_reply(tvbuff_t *tvb, int offset,
				packet_info *pinfo, proto_tree *tree,
				guint8 *drep)
{
	e_ctx_hnd policy_hnd;
	proto_item *hnd_item;
	guint32 status;

        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, &policy_hnd, &hnd_item,
				       TRUE, FALSE);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rid, NULL);

        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, &status);

	if (status == 0) {
		dcerpc_smb_store_pol_name(&policy_hnd, pinfo,
					  "CreateGroup handle");

		if (hnd_item != NULL)
			proto_item_append_text(hnd_item, ": CreateGroup handle");
	}
	return offset;


}


static int
samr_dissect_lookup_domain_rqst(tvbuff_t *tvb, int offset,
				packet_info *pinfo, proto_tree *tree,
				guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_counted_string_ptr, NDR_POINTER_REF,
			"Domain", hf_samr_domain);

	return offset;
}

static int
samr_dissect_lookup_domain_reply(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_SID_no_hf, NDR_POINTER_UNIQUE,
			"SID pointer", -1);

        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);
	return offset;
}

static int
samr_dissect_index(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
	dcerpc_info *di;

	di=pinfo->private_data;

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			di->hf_index, NULL);

	return offset;
}


static int
samr_dissect_INDEX_ARRAY_value (tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_index);

	return offset;
}

static const char *
plural_ending(const char *string)
{
	size_t string_len;

	string_len = strlen(string);
	if (string_len > 0 && string[string_len - 1] == 's') {
		/* String ends with "s" - pluralize by adding "es" */
		return "es";
	} else {
		/* Field name doesn't end with "s" - pluralize by adding "s" */
		return "s";
	}
}

static int
samr_dissect_INDEX_ARRAY(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	const char *field_name;
	guint32 count;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;
	dcerpc_info *di;
	char str[256];

	di=pinfo->private_data;

	field_name = proto_registrar_get_name(di->hf_index);
	g_snprintf(str, 255, "INDEX_ARRAY: %s%s:", field_name,
	    plural_ending(field_name));
	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"%s", str);
		tree = proto_item_add_subtree(item, ett_samr_index_array);
	}

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_count, &count);
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_INDEX_ARRAY_value, NDR_POINTER_UNIQUE,
			str, di->hf_index);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_get_alias_membership_rqst(tvbuff_t *tvb, int offset,
				       packet_info *pinfo, proto_tree *tree,
				       guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_PSID_ARRAY, NDR_POINTER_REF,
			"PSID_ARRAY:", -1);

	return offset;
}

static int
samr_dissect_get_alias_membership_reply(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_INDEX_ARRAY, NDR_POINTER_REF,
			"INDEX_ARRAY:", hf_samr_alias);

        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_IDX_AND_NAME(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *parent_tree,
                             guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;
	char str[256];
	dcerpc_info *di;

	di=pinfo->private_data;

	g_snprintf(str, 255, "IDX_AND_NAME: %s:",proto_registrar_get_name(di->hf_index));
	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
				"%s",str);
		tree = proto_item_add_subtree(item, ett_samr_idx_and_name);
	}

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_index, NULL);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo,
			tree, drep, di->hf_index, 4);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_IDX_AND_NAME_entry (tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_IDX_AND_NAME);

	return offset;
}


static int
samr_dissect_IDX_AND_NAME_ARRAY(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	const char *field_name;
	guint32 count;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;
	dcerpc_info *di;
	char str[256];

	di=pinfo->private_data;

	field_name = proto_registrar_get_name(di->hf_index);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"IDX_AND_NAME_ARRAY: %s%s:", field_name,
			plural_ending(field_name));
		tree = proto_item_add_subtree(item, ett_samr_idx_and_name_array);
	}


	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_count, &count);
	g_snprintf(str, 255, "IDX_AND_NAME pointer: %s%s:", field_name,
	    plural_ending(field_name));
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_IDX_AND_NAME_entry, NDR_POINTER_UNIQUE,
			str, di->hf_index);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_IDX_AND_NAME_ARRAY_ptr(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			guint8 *drep)
{
	const char *field_name;
	char str[256];
	dcerpc_info *di;

	di=pinfo->private_data;

	field_name = proto_registrar_get_name(di->hf_index);
	g_snprintf(str, 255, "IDX_AND_NAME_ARRAY pointer: %s%s:", field_name,
	    plural_ending(field_name));
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_IDX_AND_NAME_ARRAY, NDR_POINTER_UNIQUE,
			str, di->hf_index);
	return offset;
}

static int
samr_dissect_enum_domains_rqst(tvbuff_t *tvb, int offset,
			       packet_info *pinfo, proto_tree *tree,
			       guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_long, NDR_POINTER_REF,
			"Resume Handle", hf_samr_resume_hnd);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_pref_maxsize, NULL);

	return offset;
}

static int
samr_dissect_enum_domains_reply(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_long, NDR_POINTER_REF,
			"Resume Handle:", hf_samr_resume_hnd);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_IDX_AND_NAME_ARRAY_ptr, NDR_POINTER_REF,
			"IDX_AND_NAME_ARRAY:", hf_samr_domain);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_long, NDR_POINTER_REF,
			"Entries:", hf_samr_entries);

        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_enum_dom_groups_rqst(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_long, NDR_POINTER_REF,
			"Resume Handle:", hf_samr_resume_hnd);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_pref_maxsize, NULL);

	return offset;
}

static int
samr_dissect_enum_dom_groups_reply(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_long, NDR_POINTER_REF,
			"Resume Handle:", hf_samr_resume_hnd);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_IDX_AND_NAME_ARRAY_ptr, NDR_POINTER_REF,
			"IDX_AND_NAME_ARRAY:", hf_samr_group_name);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_long, NDR_POINTER_REF,
			"Entries:", hf_samr_entries);

        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_enum_dom_aliases_rqst(tvbuff_t *tvb, int offset,
				 packet_info *pinfo, proto_tree *tree,
				 guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_long, NDR_POINTER_REF,
			"Resume Handle:", hf_samr_resume_hnd);

	offset = dissect_ndr_nt_acct_ctrl(
		tvb, offset, pinfo, tree, drep);

	return offset;
}

static int
samr_dissect_enum_dom_aliases_reply(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_long, NDR_POINTER_REF,
			"Resume Handle:", hf_samr_resume_hnd);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_IDX_AND_NAME_ARRAY_ptr, NDR_POINTER_REF,
			"IDX_AND_NAME_ARRAY:", hf_samr_alias_name);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_long, NDR_POINTER_REF,
			"Entries:", hf_samr_entries);

        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_get_members_in_alias_rqst(tvbuff_t *tvb, int offset,
				       packet_info *pinfo, proto_tree *tree,
				       guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

	return offset;
}

static int
samr_dissect_get_members_in_alias_reply(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_PSID_ARRAY, NDR_POINTER_REF,
			"PSID_ARRAY:", -1);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_USER_INFO_1(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"USER_INFO_1:");
		tree = proto_item_add_subtree(item, ett_samr_user_info_1);
	}

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_acct_name, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_full_name, 0);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_primary_group_rid, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_acct_desc, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_comment, 0);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_INFO_2(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"USER_INFO_2:");
		tree = proto_item_add_subtree(item, ett_samr_user_info_2);
	}

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_comment, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_unknown_string, 0);
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
				hf_samr_country, NULL);
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
				hf_samr_codepage, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_INFO_3(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"USER_INFO_3:");
		tree = proto_item_add_subtree(item, ett_samr_user_info_3);
	}

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_acct_name, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_full_name, 0);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				hf_samr_rid, NULL);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				hf_samr_primary_group_rid, NULL);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_home, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_home_drive, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_script, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_profile, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_workstations, 0);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_logon_time);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_logoff_time);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_pwd_last_set_time);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_pwd_can_change_time);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_pwd_must_change_time);
	offset = dissect_ndr_nt_LOGON_HOURS(tvb, offset, pinfo, tree, drep);
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
				hf_samr_bad_pwd_count, NULL);
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
				hf_samr_logon_count, NULL);
	offset = dissect_ndr_nt_acct_ctrl(tvb, offset, pinfo, tree, drep);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_INFO_5(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"USER_INFO_5:");
		tree = proto_item_add_subtree(item, ett_samr_user_info_5);
	}

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_acct_name, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_full_name, 0);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				hf_samr_rid, NULL);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				hf_samr_primary_group_rid, NULL);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_home, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_home_drive, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_script, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_acct_desc, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_workstations, 0);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_logon_time);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_logoff_time);
	offset = dissect_ndr_nt_LOGON_HOURS(tvb, offset, pinfo, tree, drep);
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
				hf_samr_bad_pwd_count, NULL);
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
				hf_samr_logon_count, NULL);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_pwd_last_set_time);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_acct_expiry_time);
	offset = dissect_ndr_nt_acct_ctrl(tvb, offset, pinfo, tree, drep);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_INFO_6(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"USER_INFO_6:");
		tree = proto_item_add_subtree(item, ett_samr_user_info_6);
	}

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_acct_name, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_full_name, 0);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_INFO_10(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"USER_INFO_10:");
		tree = proto_item_add_subtree(item, ett_samr_user_info_10);
	}

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_home, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_home_drive, 0);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
samr_dissect_USER_INFO_18(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"USER_INFO_18:");
		tree = proto_item_add_subtree(item, ett_samr_user_info_18);
	}

	offset = samr_dissect_CRYPT_HASH(tvb, offset, pinfo, tree, drep);
	offset = samr_dissect_CRYPT_HASH(tvb, offset, pinfo, tree, drep);
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_char, NULL);
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_char, NULL);
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_char, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_INFO_19(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"USER_INFO_19:");
		tree = proto_item_add_subtree(item, ett_samr_user_info_19);
	}

	offset = dissect_ndr_nt_acct_ctrl(tvb, offset, pinfo, tree, drep);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_logon_time);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_logoff_time);
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
				hf_samr_bad_pwd_count, NULL);
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
				hf_samr_logon_count, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_BUFFER_entry(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
			hf_samr_unknown_char, NULL);
	return offset;
}


static int
samr_dissect_BUFFER_buffer(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *parent_tree,
                             guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"BUFFER:");
		tree = proto_item_add_subtree(item, ett_samr_buffer_buffer);
	}

	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_BUFFER_entry);

	proto_item_set_len(item, offset-old_offset);
	return offset;

	return offset;
}

static int
samr_dissect_BUFFER(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"BUFFER:");
		tree = proto_item_add_subtree(item, ett_samr_buffer);
	}
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
				hf_samr_count, NULL);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_BUFFER_buffer, NDR_POINTER_UNIQUE,
			"BUFFER", -1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_INFO_21(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"USER_INFO_21:");
		tree = proto_item_add_subtree(item, ett_samr_user_info_21);
	}

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_logon_time);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_logoff_time);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_pwd_last_set_time);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_acct_expiry_time);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_pwd_can_change_time);
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_samr_pwd_must_change_time);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_acct_name, 2);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_full_name, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_home, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_home_drive, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_script, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_profile, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_acct_desc, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_workstations, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_comment, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_callback, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_unknown_string, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_unknown_string, 0);
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_unknown_string, 0);
	offset = samr_dissect_BUFFER(tvb, offset, pinfo, tree, drep);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				hf_samr_rid, NULL);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				hf_samr_primary_group_rid, NULL);
	offset = dissect_ndr_nt_acct_ctrl(tvb, offset, pinfo, tree, drep);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
				hf_samr_unknown_long, NULL);
	offset = dissect_ndr_nt_LOGON_HOURS(tvb, offset, pinfo, tree, drep);
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
				hf_samr_bad_pwd_count, NULL);
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
				hf_samr_logon_count, NULL);
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
				hf_samr_country, NULL);
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
				hf_samr_codepage, NULL);
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
				hf_samr_nt_pwd_set, NULL);
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
				hf_samr_lm_pwd_set, NULL);
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
				hf_samr_pwd_expired, NULL);
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
				hf_samr_unknown_char, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_INFO_22(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"USER_INFO_22:");
		tree = proto_item_add_subtree(item, ett_samr_user_info_22);
	}

	offset = samr_dissect_USER_INFO_21(tvb, offset, pinfo, tree, drep);
	offset = dissect_ndr_duint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_revision, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_INFO_23(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"USER_INFO_23:");
		tree = proto_item_add_subtree(item, ett_samr_user_info_23);
	}

	offset = samr_dissect_USER_INFO_21(tvb, offset, pinfo, tree, drep);
	offset = samr_dissect_CRYPT_PASSWORD(tvb, offset, pinfo, tree, drep);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_INFO_24(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"USER_INFO_24:");
		tree = proto_item_add_subtree(item, ett_samr_user_info_24);
	}

	offset = samr_dissect_CRYPT_PASSWORD(tvb, offset, pinfo, tree, drep);
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
				hf_samr_unknown_char, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
samr_dissect_USER_INFO_25(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset = offset;

	if(parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"USER_INFO_25:");
		tree = proto_item_add_subtree(item, ett_samr_user_info_25);
	}

	offset = samr_dissect_USER_INFO_21(tvb, offset, pinfo, tree, drep);

	proto_tree_add_item(tree, hf_samr_crypt_password, tvb, offset, 532,
		TRUE);
	offset += 532;

	proto_item_set_len(item, offset - old_offset);

	return offset;
}


static int
samr_dissect_USER_INFO (tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *parent_tree,
                             guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;
	guint16 level;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"USER_INFO:");
		tree = proto_item_add_subtree(item, ett_samr_user_info);
	}
        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_level, &level);

	switch(level){
	case 1:
		offset = samr_dissect_USER_INFO_1(
				tvb, offset, pinfo, tree, drep);
		break;
	case 2:
		offset = samr_dissect_USER_INFO_2(
				tvb, offset, pinfo, tree, drep);
		break;
	case 3:
		offset = samr_dissect_USER_INFO_3(
				tvb, offset, pinfo, tree, drep);
		break;
	case 4:
		offset = dissect_ndr_nt_LOGON_HOURS(
				tvb, offset, pinfo, tree, drep);
		break;
	case 5:
		offset = samr_dissect_USER_INFO_5(
				tvb, offset, pinfo, tree, drep);
		break;
	case 6:
		offset = samr_dissect_USER_INFO_6(
				tvb, offset, pinfo, tree, drep);
		break;
	case 7:
		offset = dissect_ndr_counted_string(
			tvb, offset, pinfo, tree, drep, hf_samr_acct_name, 0);
		break;
	case 8:
		offset = dissect_ndr_counted_string(
			tvb, offset, pinfo, tree, drep, hf_samr_full_name, 0);
		break;
	case 9:
	        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
        	                             hf_samr_primary_group_rid, NULL);
		break;
	case 10:
		offset = samr_dissect_USER_INFO_10(
				tvb, offset, pinfo, tree, drep);
		break;
	case 11:
		offset = dissect_ndr_counted_string(
			tvb, offset, pinfo, tree, drep, hf_samr_script, 0);
		break;
	case 12:
		offset = dissect_ndr_counted_string(
			tvb, offset, pinfo, tree, drep, hf_samr_profile, 0);
		break;
	case 13:
		offset = dissect_ndr_counted_string(
			tvb, offset, pinfo, tree, drep, hf_samr_acct_desc, 0);
		break;
	case 14:
		offset = dissect_ndr_counted_string(
			tvb, offset, pinfo, tree, drep, hf_samr_workstations, 0);
		break;
	case 16:
	        offset = dissect_ndr_nt_acct_ctrl(tvb, offset, pinfo, tree,
        	                             drep);
		break;
	case 17:
		offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
					hf_samr_acct_expiry_time);
		break;
	case 18:
		offset = samr_dissect_USER_INFO_18(
				tvb, offset, pinfo, tree, drep);
		break;
	case 19:
		offset = samr_dissect_USER_INFO_19(
				tvb, offset, pinfo, tree, drep);
		break;
	case 20:
		offset = dissect_ndr_counted_string(
			tvb, offset, pinfo, tree, drep, hf_samr_callback, 0);
		break;
	case 21:
		offset = samr_dissect_USER_INFO_21(
				tvb, offset, pinfo, tree, drep);
		break;
	case 22:
		offset = samr_dissect_USER_INFO_22(
				tvb, offset, pinfo, tree, drep);
		break;
	case 23:
		offset = samr_dissect_USER_INFO_23(
				tvb, offset, pinfo, tree, drep);
		break;
	case 24:
		offset = samr_dissect_USER_INFO_24(
				tvb, offset, pinfo, tree, drep);
	case 25:
		offset = samr_dissect_USER_INFO_25(
				tvb, offset, pinfo, tree, drep);
		break;
	}

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_USER_INFO_ptr(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_USER_INFO, NDR_POINTER_UNIQUE,
			"USER_INFO pointer", -1);
	return offset;
}

static int
samr_dissect_set_information_user2_rqst(tvbuff_t *tvb, int offset,
					packet_info *pinfo, proto_tree *tree,
					guint8 *drep)
{
	guint16 level;

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
			hf_samr_level, &level);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_USER_INFO, NDR_POINTER_REF,
			"USER_INFO:", -1);

	return offset;
}

static int
samr_dissect_set_information_user2_reply(tvbuff_t *tvb, int offset,
					 packet_info *pinfo, proto_tree *tree,
					 guint8 *drep)
{
        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_query_information_user2_rqst(tvbuff_t *tvb, int offset,
				 packet_info *pinfo, proto_tree *tree,
				 guint8 *drep)
{
	guint16 level;

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
			hf_samr_level, &level);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	return offset;
}

static int
samr_dissect_query_information_user2_reply(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_USER_INFO_ptr, NDR_POINTER_REF,
			"USER_INFO:", -1);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
			hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_MEMBER_ARRAY_type(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				hf_samr_type, NULL);

	return offset;
}


static int
samr_dissect_MEMBER_ARRAY_types(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"MEMBER_ARRAY_types:");
		tree = proto_item_add_subtree(item, ett_samr_member_array_types);
	}

	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_MEMBER_ARRAY_type);

	proto_item_set_len(item, offset-old_offset);
	return offset;

	return offset;
}

static int
samr_dissect_MEMBER_ARRAY_rid(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				hf_samr_rid, NULL);

	return offset;
}


static int
samr_dissect_MEMBER_ARRAY_rids(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"MEMBER_ARRAY_rids:");
		tree = proto_item_add_subtree(item, ett_samr_member_array_rids);
	}

	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_MEMBER_ARRAY_rid);

	proto_item_set_len(item, offset-old_offset);
	return offset;

	return offset;
}

static int
samr_dissect_MEMBER_ARRAY(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	guint32 count;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"MEMBER_ARRAY:");
		tree = proto_item_add_subtree(item, ett_samr_member_array);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_samr_count, &count);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_MEMBER_ARRAY_rids, NDR_POINTER_UNIQUE,
			"RIDs", -1);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_MEMBER_ARRAY_types, NDR_POINTER_UNIQUE,
			"Types", -1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
samr_dissect_MEMBER_ARRAY_ptr(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_MEMBER_ARRAY, NDR_POINTER_UNIQUE,
			"MEMBER_ARRAY", -1);
	return offset;
}

static int
samr_dissect_query_groupmem_rqst(tvbuff_t *tvb, int offset,
				 packet_info *pinfo, proto_tree *tree,
				 guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

        return offset;
}

static int
samr_dissect_query_groupmem_reply(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_MEMBER_ARRAY_ptr, NDR_POINTER_REF,
			"MEMBER_ARRAY:", -1);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_set_sec_object_rqst(tvbuff_t *tvb, int offset,
				 packet_info *pinfo, proto_tree *tree,
				 guint8 *drep)
{
	guint32 info_type;

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_info_type, &info_type);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(
			pinfo->cinfo, COL_INFO, ", info type %d", info_type);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
               sam_dissect_SAM_SECURITY_DESCRIPTOR, NDR_POINTER_REF,
               "SAM_SECURITY_DESCRIPTOR pointer: ", -1);

	return offset;
}

static int
samr_dissect_set_sec_object_reply(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  guint8 *drep)
{
        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_query_sec_object_rqst(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	guint32 info_type;

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_info_type, &info_type);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(
			pinfo->cinfo, COL_INFO, ", info_type %d", info_type);

	return offset;
}

static int
samr_dissect_query_sec_object_reply(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
               sam_dissect_SAM_SECURITY_DESCRIPTOR, NDR_POINTER_UNIQUE,
               "SAM_SECURITY_DESCRIPTOR pointer: ", -1);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_LOOKUP_NAMES_name(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			guint8 *drep)
{
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_acct_name, 1);
	return offset;
}

static int
samr_dissect_LOOKUP_NAMES(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"NAMES:");
		tree = proto_item_add_subtree(item, ett_samr_names);
	}

	offset = dissect_ndr_ucvarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_LOOKUP_NAMES_name);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
samr_dissect_lookup_names_rqst(tvbuff_t *tvb, int offset,
			       packet_info *pinfo, proto_tree *tree,
			       guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_samr_count, NULL);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_LOOKUP_NAMES, NDR_POINTER_REF,
			"LOOKUP_NAMES:", -1);

	return offset;
}

static int
samr_dissect_lookup_names_reply(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			guint8 *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_INDEX_ARRAY, NDR_POINTER_REF,
			"Rids:", hf_samr_rid);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_INDEX_ARRAY, NDR_POINTER_REF,
			"Types:", hf_samr_type);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_LOOKUP_RIDS_rid(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				hf_samr_rid, NULL);

	return offset;
}

static int
samr_dissect_LOOKUP_RIDS(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"RIDS:");
		tree = proto_item_add_subtree(item, ett_samr_rids);
	}

	offset = dissect_ndr_ucvarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_LOOKUP_RIDS_rid);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
samr_dissect_lookup_rids_rqst(tvbuff_t *tvb, int offset,
			      packet_info *pinfo, proto_tree *tree,
			      guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_samr_count, NULL);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_LOOKUP_RIDS, NDR_POINTER_REF,
			"LOOKUP_RIDS:", -1);

	return offset;
}

static int
samr_dissect_UNICODE_STRING_ARRAY_name(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			guint8 *drep)
{
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
				hf_samr_acct_name, 0);
	return offset;
}

static int
samr_dissect_UNICODE_STRING_ARRAY_names(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			samr_dissect_UNICODE_STRING_ARRAY_name);
	return offset;
}

static int
samr_dissect_UNICODE_STRING_ARRAY(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"NAMES:");
		tree = proto_item_add_subtree(item, ett_samr_names);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_samr_count, NULL);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_UNICODE_STRING_ARRAY_names, NDR_POINTER_UNIQUE,
			"Strings", -1);

	proto_item_set_len(item, offset-old_offset);
	return offset;

	return offset;
}


static int
samr_dissect_lookup_rids_reply(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			guint8 *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_UNICODE_STRING_ARRAY, NDR_POINTER_REF,
			"RIDs:", hf_samr_rid);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_INDEX_ARRAY, NDR_POINTER_REF,
			"Types:", hf_samr_type);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_close_hnd_rqst(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, guint8 *drep)
{
	e_ctx_hnd policy_hnd;
	char *name;

        offset = dissect_nt_policy_hnd(
		tvb, offset, pinfo, tree, drep, hf_samr_hnd, &policy_hnd, 
		NULL, FALSE, TRUE);

	dcerpc_smb_fetch_pol(&policy_hnd, &name, NULL, NULL, pinfo->fd->num);

	if (name != NULL && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(
			pinfo->cinfo, COL_INFO, ", %s", name);

	return offset;
}

static int
samr_dissect_close_hnd_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
			     proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
			hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_shutdown_sam_server_rqst(tvbuff_t *tvb, int offset,
				      packet_info *pinfo, proto_tree *tree,
				      guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

        return offset;
}

static int
samr_dissect_shutdown_sam_server_reply(tvbuff_t *tvb, int offset,
				      packet_info *pinfo, proto_tree *tree,
				      guint8 *drep)
{
        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_delete_dom_group_rqst(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

        return offset;
}

static int
samr_dissect_delete_dom_group_reply(tvbuff_t *tvb, int offset,
				    packet_info *pinfo, proto_tree *tree,
				    guint8 *drep)
{
        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_remove_member_from_group_rqst(tvbuff_t *tvb, int offset,
					   packet_info *pinfo,
					   proto_tree *tree, guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_group, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rid, NULL);

	return offset;
}

static int
samr_dissect_remove_member_from_group_reply(tvbuff_t *tvb, int offset,
					    packet_info *pinfo,
					    proto_tree *tree, guint8 *drep)
{
        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_delete_dom_alias_rqst(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

        return offset;
}

static int
samr_dissect_delete_dom_alias_reply(tvbuff_t *tvb, int offset,
				    packet_info *pinfo, proto_tree *tree,
				    guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_add_alias_member_rqst(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_SID_no_hf, NDR_POINTER_REF,
			"SID pointer", -1);

	return offset;
}

static int
samr_dissect_add_alias_member_reply(tvbuff_t *tvb, int offset,
				    packet_info *pinfo, proto_tree *tree,
				    guint8 *drep)
{
        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_remove_alias_member_rqst(tvbuff_t *tvb, int offset,
				      packet_info *pinfo, proto_tree *tree,
				      guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_SID_no_hf, NDR_POINTER_REF,
			"SID pointer", -1);

	return offset;
}

static int
samr_dissect_remove_alias_member_reply(tvbuff_t *tvb, int offset,
				       packet_info *pinfo, proto_tree *tree,
				       guint8 *drep)
{
        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_delete_dom_user_rqst(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

	return offset;
}

static int
samr_dissect_delete_dom_user_reply(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_test_private_fns_domain_rqst(tvbuff_t *tvb, int offset,
					  packet_info *pinfo, proto_tree *tree,
					  guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

	return offset;
}

static int
samr_dissect_test_private_fns_domain_reply(tvbuff_t *tvb, int offset,
					   packet_info *pinfo,
					   proto_tree *tree, guint8 *drep)
{
        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_test_private_fns_user_rqst(tvbuff_t *tvb, int offset,
					packet_info *pinfo, proto_tree *tree,
					guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

	return offset;
}

static int
samr_dissect_test_private_fns_user_reply(tvbuff_t *tvb, int offset,
					 packet_info *pinfo,
					 proto_tree *tree, guint8 *drep)
{
        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_remove_member_from_foreign_domain_rqst(tvbuff_t *tvb, int offset,
						    packet_info *pinfo,
						    proto_tree *tree,
						    guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_SID_no_hf, NDR_POINTER_REF,
			"SID pointer", -1);

	return offset;
}

static int
samr_dissect_remove_member_from_foreign_domain_reply(tvbuff_t *tvb, int offset,
						     packet_info *pinfo,
						     proto_tree *tree,
						     guint8 *drep)
{
        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_remove_multiple_members_from_alias_rqst(tvbuff_t *tvb,
						     int offset,
						     packet_info *pinfo,
						     proto_tree *tree,
						     guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_PSID_ARRAY, NDR_POINTER_REF,
			"PSID_ARRAY:", -1);

	return offset;
}

static int
samr_dissect_remove_multiple_members_from_alias_reply(tvbuff_t *tvb,
						      int offset,
						      packet_info *pinfo,
						      proto_tree *tree,
						      guint8 *drep)
{
        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_open_group_rqst(tvbuff_t *tvb, int offset, packet_info *pinfo,
			    proto_tree *tree, guint8 *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 rid;

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

	offset = dissect_nt_access_mask(
		tvb, offset, pinfo, tree, drep, hf_samr_access,
		&samr_group_access_mask_info, NULL);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_rid, &rid);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", rid 0x%x", rid);

	/* OpenGroup() stores the rid in se_data */
	if(!pinfo->fd->flags.visited){
		if(!dcv->se_data){
			dcv->se_data = se_strdup_printf("0x%x", rid);
		}
	}

	return offset;
}

static int
samr_dissect_open_group_reply(tvbuff_t *tvb, int offset,
			      packet_info *pinfo, proto_tree *tree,
			      guint8 *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 rid = GPOINTER_TO_INT(dcv->private_data);
	e_ctx_hnd policy_hnd;
	proto_item *hnd_item;
	guint32 status;

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, &policy_hnd, &hnd_item,
				       TRUE, FALSE);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
			hf_samr_rc, &status);

	if( status == 0 ){
		char *pol_name;

		if (dcv->se_data){
			pol_name = ep_strdup_printf(
				"SamrOpenGroup(rid %s)", (char *)dcv->se_data);
		} else {
			pol_name = "Unknown SamrOpenGroup() handle";
		}
		if(!pinfo->fd->flags.visited){
			dcerpc_smb_store_pol_name(&policy_hnd, pinfo, pol_name);
		}

		if(hnd_item)
			proto_item_append_text(hnd_item, ": %s", pol_name);
	}

	return offset;
}

static int
samr_dissect_open_alias_rqst(tvbuff_t *tvb, int offset, packet_info *pinfo,
			     proto_tree *tree, guint8 *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	guint32 rid;

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

	offset = dissect_nt_access_mask(
		tvb, offset, pinfo, tree, drep, hf_samr_access,
		&samr_alias_access_mask_info, NULL);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_samr_rid, &rid);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", rid 0x%x", rid);

	/* OpenAlias() stores the rid in se_data */
	if(!pinfo->fd->flags.visited){
		if(!dcv->se_data){
			dcv->se_data = se_strdup_printf("0x%x", rid);
		}
	}

	return offset;
}

static int
samr_dissect_open_alias_reply(tvbuff_t *tvb, int offset,
			      packet_info *pinfo, proto_tree *tree,
			      guint8 *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	e_ctx_hnd policy_hnd;
	proto_item *hnd_item;
	guint32 status;

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, &policy_hnd, &hnd_item,
				       TRUE, FALSE);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
			hf_samr_rc, &status);

	if( status == 0 ){
		char *pol_name;

		if (dcv->se_data){
			pol_name = ep_strdup_printf(
				"SamrOpenAlias(rid %s)", (char *)dcv->se_data);
		} else {
			pol_name = "Unknown SamrOpenAlias() handle";
		}
		if(!pinfo->fd->flags.visited){
			dcerpc_smb_store_pol_name(&policy_hnd, pinfo, pol_name);
		}

		if(hnd_item)
			proto_item_append_text(hnd_item, ": %s", pol_name);
	}

	return offset;
}

static int
samr_dissect_add_multiple_members_to_alias_rqst(tvbuff_t *tvb, int offset,
						packet_info *pinfo,
						proto_tree *tree, guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_PSID_ARRAY, NDR_POINTER_REF,
			"PSID_ARRAY:", -1);

	return offset;
}

static int
samr_dissect_add_multiple_members_to_alias_reply(tvbuff_t *tvb, int offset,
						 packet_info *pinfo,
						 proto_tree *tree, guint8 *drep)
{
        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}

static int
samr_dissect_create_user_in_domain_rqst(tvbuff_t *tvb, int offset,
					 packet_info *pinfo, proto_tree *tree,
					 guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_counted_string_ptr, NDR_POINTER_REF,
			"Account Name", hf_samr_acct_name);

	offset = dissect_nt_access_mask(
		tvb, offset, pinfo, tree, drep, hf_samr_access,
		&samr_user_access_mask_info, NULL);

	return offset;
}

static int
samr_dissect_create_user_in_domain_reply(tvbuff_t *tvb, int offset,
					  packet_info *pinfo, proto_tree *tree,
					  guint8 *drep)
{
	e_ctx_hnd policy_hnd;
	proto_item *hnd_item;
	guint32 rid;
	guint32 status;
	char *pol_name;

        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, &policy_hnd, &hnd_item,
				       TRUE, FALSE);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_rid, &rid);

        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, &status);

	if (status == 0) {
		pol_name = ep_strdup_printf("CreateUser(rid 0x%x)", rid);

		dcerpc_smb_store_pol_name(&policy_hnd, pinfo, pol_name);

		if (hnd_item != NULL)
			proto_item_append_text(hnd_item, ": %s", pol_name);

	}

	return offset;
}


static int
samr_dissect_enum_users_in_domain_rqst(tvbuff_t *tvb, int offset,
					   packet_info *pinfo,
					   proto_tree *tree, guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_long, NDR_POINTER_REF,
			"Resume Handle", hf_samr_resume_hnd);

	offset = dissect_ndr_nt_acct_ctrl(tvb, offset, pinfo, tree, drep);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_samr_pref_maxsize, NULL);

	return offset;
}


static int
samr_dissect_enum_users_in_domain_reply(tvbuff_t *tvb, int offset,
					   packet_info *pinfo,
					   proto_tree *tree, guint8 *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_long, NDR_POINTER_REF,
			"Resume Handle:", hf_samr_resume_hnd);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_IDX_AND_NAME_ARRAY_ptr, NDR_POINTER_REF,
			"IDX_AND_NAME_ARRAY:", hf_samr_acct_name);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_pointer_long, NDR_POINTER_REF,
			"Entries:", hf_samr_entries);

        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}



static int
samr_dissect_query_information_domain_rqst(tvbuff_t *tvb, int offset,
					   packet_info *pinfo,
					   proto_tree *tree, guint8 *drep)
{
	guint16 level;

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
			hf_samr_level, &level);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	return offset;
}

static int
samr_dissect_query_information_domain_reply(tvbuff_t *tvb, int offset,
                        packet_info *pinfo, proto_tree *tree,
                        guint8 *drep)
{
	/*
	 * Yes, in at least one capture with replies from a W2K server,
	 * this was, indeed, a UNIQUE pointer, not a REF pointer.
	 */
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                        samr_dissect_DOMAIN_INFO, NDR_POINTER_UNIQUE,
                        "DOMAIN_INFO pointer", hf_samr_domain);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
			hf_samr_rc, NULL);

        return offset;
}

static int
samr_dissect_query_information_user_rqst(tvbuff_t *tvb, int offset,
					  packet_info *pinfo,
					  proto_tree *tree, guint8 *drep)
{
	guint16 level;

	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_samr_hnd, NULL, NULL, FALSE, FALSE);

	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
			hf_samr_level, &level);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", level %d", level);

	return offset;
}

static int
samr_dissect_query_information_user_reply(tvbuff_t *tvb, int offset,
					   packet_info *pinfo,
					   proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			samr_dissect_USER_INFO_ptr, NDR_POINTER_REF,
			"USER_INFO:", -1);

        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_samr_rc, NULL);

	return offset;
}


static int
samr_dissect_connect5_rqst(tvbuff_t *tvb, int offset, packet_info *pinfo,
                          proto_tree *tree, guint8 *drep)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	char *sn;

	/* ServerName */
	dcv->private_data=NULL;
	offset = dissect_ndr_pointer_cb(
               tvb, offset, pinfo, tree, drep,
               dissect_ndr_wchar_cvstring, NDR_POINTER_UNIQUE,
               "Server", hf_samr_server, cb_wstr_postprocess,
               GINT_TO_POINTER(CB_STR_COL_INFO | CB_STR_SAVE | 1));
	sn=dcv->private_data;
	if(!sn)
		sn="";

	/* Connect5() stores the server in se_data */
	if(!pinfo->fd->flags.visited){
		if(!dcv->se_data){
			dcv->se_data = se_strdup_printf("%s", sn);
		}
	}

	offset = dissect_nt_access_mask(
               tvb, offset, pinfo, tree, drep, hf_samr_access,
               &samr_connect_access_mask_info, NULL);


	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                   hf_samr_unknown_long, NULL);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                   hf_samr_unknown_long, NULL);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                   hf_samr_unknown_long, NULL);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                   hf_samr_unknown_long, NULL);

	return offset;

}


static int
samr_dissect_connect5_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
                          proto_tree *tree, guint8 *drep)
{
       dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
       dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
       e_ctx_hnd policy_hnd;
       proto_item *hnd_item;
       guint32 status;


       offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                   hf_samr_unknown_long, NULL);

       offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                   hf_samr_unknown_long, NULL);

       offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                   hf_samr_unknown_long, NULL);

       offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                   hf_samr_unknown_long, NULL);

        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
                                      hf_samr_hnd, &policy_hnd, 
                                      &hnd_item, TRUE, FALSE);

        offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
                                 hf_samr_rc, &status);

	if( status == 0 ){
		char *pol_name;

		if (dcv->se_data){
			pol_name = ep_strdup_printf(
				"SamrConnect5(%s)", (char *)dcv->se_data);
		} else {
			pol_name = "Unknown SamrConnect5() handle";
		}
		if(!pinfo->fd->flags.visited){
			dcerpc_smb_store_pol_name(&policy_hnd, pinfo, pol_name);
		}

		if(hnd_item)
			proto_item_append_text(hnd_item, ": %s", pol_name);
	}

       return offset;
}



static dcerpc_sub_dissector dcerpc_samr_dissectors[] = {
        { SAMR_CONNECT, "SamrConnect",
		samr_dissect_connect_anon_rqst,
		samr_dissect_connect_anon_reply },
        { SAMR_CLOSE_HND, "SamrCloseHandle",
		samr_dissect_close_hnd_rqst,
		samr_dissect_close_hnd_reply },
        { SAMR_SET_SEC_OBJECT, "SamrSetSecurityObject",
		samr_dissect_set_sec_object_rqst,
		samr_dissect_set_sec_object_reply },
        { SAMR_QUERY_SEC_OBJECT, "SamrQuerySecurityObject",
		samr_dissect_query_sec_object_rqst,
		samr_dissect_query_sec_object_reply },
        { SAMR_SHUTDOWN_SAM_SERVER, "SamrShutdownSamServer",
		samr_dissect_shutdown_sam_server_rqst,
		samr_dissect_shutdown_sam_server_reply },
        { SAMR_LOOKUP_DOMAIN, "SamrLookupDomainInSamServer",
		samr_dissect_lookup_domain_rqst,
		samr_dissect_lookup_domain_reply },
        { SAMR_ENUM_DOMAINS, "SamrEnumerateDomainsInSamServer",
		samr_dissect_enum_domains_rqst,
		samr_dissect_enum_domains_reply },
        { SAMR_OPEN_DOMAIN, "SamrOpenDomain",
		samr_dissect_open_domain_rqst,
		samr_dissect_open_domain_reply },
	{ SAMR_QUERY_DOMAIN_INFO, "SamrQueryInformationDomain",
		samr_dissect_query_information_alias_rqst,
		samr_dissect_query_information_domain_reply },
        { SAMR_SET_DOMAIN_INFO, "SamrSetInformationDomain",
		samr_dissect_set_information_domain_rqst,
		samr_dissect_set_information_domain_reply },
        { SAMR_CREATE_DOM_GROUP, "SamrCreateGroupInDomain",
		samr_dissect_create_group_in_domain_rqst,
		samr_dissect_create_group_in_domain_reply },
        { SAMR_ENUM_DOM_GROUPS, "SamrEnumerateGroupsInDomain",
		samr_dissect_enum_dom_groups_rqst,
		samr_dissect_enum_dom_groups_reply },
	{ SAMR_CREATE_USER_IN_DOMAIN, "SamrCreateUserInDomain",
		samr_dissect_create_user_in_domain_rqst,
		samr_dissect_create_user_in_domain_reply },
        { SAMR_ENUM_DOM_USERS, "SamrEnumerateUsersInDomain",
		samr_dissect_enum_users_in_domain_rqst,
		samr_dissect_enum_users_in_domain_reply },
        { SAMR_CREATE_DOM_ALIAS, "SamrCreateAliasInDomain",
		samr_dissect_create_alias_in_domain_rqst,
		samr_dissect_create_alias_in_domain_reply },
        { SAMR_ENUM_DOM_ALIASES, "SamrEnumerateAliasesInDomain",
		samr_dissect_enum_dom_aliases_rqst,
		samr_dissect_enum_dom_aliases_reply },
        { SAMR_GET_ALIAS_MEMBERSHIP, "SamrGetAliasMembership",
		samr_dissect_get_alias_membership_rqst,
		samr_dissect_get_alias_membership_reply },
        { SAMR_LOOKUP_NAMES, "SamrLookupNamesInDomain",
		samr_dissect_lookup_names_rqst,
		samr_dissect_lookup_names_reply },
        { SAMR_LOOKUP_RIDS, "SamrLookupIdsInDomain",
		samr_dissect_lookup_rids_rqst,
		samr_dissect_lookup_rids_reply },
        { SAMR_OPEN_GROUP, "SamrOpenGroup",
		samr_dissect_open_group_rqst,
		samr_dissect_open_group_reply },
        { SAMR_QUERY_GROUPINFO, "SamrQueryInformationGroup",
		samr_dissect_query_information_group_rqst,
		samr_dissect_query_information_group_reply },
        { SAMR_SET_GROUPINFO, "SamrSetInformationGroup",
		samr_dissect_set_information_group_rqst,
		samr_dissect_set_information_group_reply },
        { SAMR_ADD_GROUPMEM, "SamrAddMemberToGroup",
		samr_dissect_add_member_to_group_rqst,
		samr_dissect_add_member_to_group_reply },
        { SAMR_DELETE_DOM_GROUP, "SamrDeleteGroup",
		samr_dissect_delete_dom_group_rqst,
		samr_dissect_delete_dom_group_reply },
        { SAMR_DEL_GROUPMEM, "SamrRemoveMemberFromGroup",
		samr_dissect_remove_member_from_group_rqst,
		samr_dissect_remove_member_from_group_reply },
        { SAMR_QUERY_GROUPMEM, "SamrGetMembersInGroup",
		samr_dissect_query_groupmem_rqst,
		samr_dissect_query_groupmem_reply },
        { SAMR_SET_MEMBER_ATTRIBUTES_OF_GROUP, "SamrSetMemberAttributesOfGroup",
		samr_dissect_set_member_attributes_of_group_rqst,
		samr_dissect_set_member_attributes_of_group_reply },
        { SAMR_OPEN_ALIAS, "SamrOpenAlias",
		samr_dissect_open_alias_rqst,
		samr_dissect_open_alias_reply },
        { SAMR_QUERY_ALIASINFO, "SamrQueryInformationAlias",
		samr_dissect_query_information_alias_rqst,
		samr_dissect_query_information_alias_reply },
        { SAMR_SET_ALIASINFO, "SamrSetInformationAlias",
		samr_dissect_set_information_alias_rqst,
		samr_dissect_set_information_alias_reply },
        { SAMR_DELETE_DOM_ALIAS, "SamrDeleteAlias",
		samr_dissect_delete_dom_alias_rqst,
		samr_dissect_delete_dom_alias_reply },
        { SAMR_ADD_ALIASMEM, "SamrAddMemberToAlias",
		samr_dissect_add_alias_member_rqst,
		samr_dissect_add_alias_member_reply },
        { SAMR_DEL_ALIASMEM, "SamrRemoveMemberFromAlias",
		samr_dissect_remove_alias_member_rqst,
		samr_dissect_remove_alias_member_reply },
        { SAMR_GET_MEMBERS_IN_ALIAS, "SamrGetMembersInAlias",
		samr_dissect_get_members_in_alias_rqst,
		samr_dissect_get_members_in_alias_reply },
        { SAMR_OPEN_USER, "SamrOpenUser",
		samr_dissect_open_user_rqst,
		samr_dissect_open_user_reply },
        { SAMR_DELETE_DOM_USER, "SamrDeleteUser",
		samr_dissect_delete_dom_user_rqst,
		samr_dissect_delete_dom_user_reply },
        { SAMR_QUERY_USERINFO, "SamrQueryInformationUser",
		samr_dissect_query_information_user_rqst,
		samr_dissect_query_information_user_reply },
        { SAMR_SET_USERINFO, "SamrSetInformationUser",
		samr_dissect_set_information_user2_rqst,
		samr_dissect_set_information_user2_reply },
	{ SAMR_CHANGE_PASSWORD_USER, "SamrChangePasswordUser",
		samr_dissect_change_password_user_rqst,
		samr_dissect_change_password_user_reply },
        { SAMR_GET_GROUPS_FOR_USER, "SamrGetGroupsForUser",
		samr_dissect_get_groups_for_user_rqst,
		samr_dissect_get_groups_for_user_reply },
        { SAMR_QUERY_DISPINFO, "SamrQueryDisplayInformation",
		samr_dissect_query_dispinfo_rqst,
		samr_dissect_query_dispinfo_reply },
        { SAMR_GET_DISPLAY_ENUMERATION_INDEX, "SamrGetDisplayEnumerationIndex",
		samr_dissect_get_display_enumeration_index_rqst,
		samr_dissect_get_display_enumeration_index_reply },
        { SAMR_TEST_PRIVATE_FUNCTIONS_DOMAIN, "SamrTestPrivateFunctionsDomain",
		samr_dissect_test_private_fns_domain_rqst,
		samr_dissect_test_private_fns_domain_reply },
        { SAMR_TEST_PRIVATE_FUNCTIONS_USER, "SamrTestPrivateFunctionsUser",
		samr_dissect_test_private_fns_user_rqst,
		samr_dissect_test_private_fns_user_reply },
        { SAMR_GET_USRDOM_PWINFO, "SamrGetUserDomainPasswordInformation",
		samr_dissect_get_usrdom_pwinfo_rqst,
		samr_dissect_get_usrdom_pwinfo_reply },
        { SAMR_REMOVE_MEMBER_FROM_FOREIGN_DOMAIN, "SamrRemoveMemberFromForeignDomain",
		samr_dissect_remove_member_from_foreign_domain_rqst,
		samr_dissect_remove_member_from_foreign_domain_reply },
        { SAMR_QUERY_INFORMATION_DOMAIN2, "SamrQueryInformationDomain2",
		samr_dissect_query_information_domain_rqst,
		samr_dissect_query_information_domain_reply },
        { SAMR_QUERY_INFORMATION_USER2, "SamrQueryInformationUser2",
		samr_dissect_query_information_user2_rqst,
		samr_dissect_query_information_user2_reply },
        { SAMR_QUERY_DISPINFO2, "SamrQueryDisplayInformation2",
		samr_dissect_query_dispinfo_rqst,
		samr_dissect_query_dispinfo_reply },
        { SAMR_GET_DISPLAY_ENUMERATION_INDEX2, "SamrGetDisplayEnumerationIndex2",
		samr_dissect_get_display_enumeration_index2_rqst,
		samr_dissect_get_display_enumeration_index2_reply },
        { SAMR_CREATE_USER2_IN_DOMAIN, "SamrCreateUser2InDomain",
		samr_dissect_create_user2_in_domain_rqst,
		samr_dissect_create_user2_in_domain_reply },
        { SAMR_QUERY_DISPINFO3, "SamrQueryDisplayInformation3",
		samr_dissect_query_dispinfo_rqst,
		samr_dissect_query_dispinfo_reply },
        { SAMR_ADD_MULTIPLE_MEMBERS_TO_ALIAS, "SamrAddMultipleMembersToAlias",
		samr_dissect_add_multiple_members_to_alias_rqst,
		samr_dissect_add_multiple_members_to_alias_reply },
        { SAMR_REMOVE_MULTIPLE_MEMBERS_FROM_ALIAS, "SamrRemoveMultipleMembersFromAlias",
		samr_dissect_remove_multiple_members_from_alias_rqst,
		samr_dissect_remove_multiple_members_from_alias_reply },
        { SAMR_OEM_CHANGE_PASSWORD_USER2, "SamrOemChangePasswordUser2",
		samr_dissect_oem_change_password_user2_rqst,
		samr_dissect_oem_change_password_user2_reply },
        { SAMR_UNICODE_CHANGE_PASSWORD_USER2, "SamrUnicodeChangePasswordUser2",
		samr_dissect_unicode_change_password_user2_rqst,
		samr_dissect_unicode_change_password_user2_reply },
        { SAMR_GET_DOM_PWINFO, "SamrGetDomainPasswordInformation",
		samr_dissect_get_domain_password_information_rqst,
		samr_dissect_get_domain_password_information_reply },
	{ SAMR_CONNECT2, "SamrConnect2",
		samr_dissect_connect2_rqst,
		samr_dissect_connect2_reply },
        { SAMR_SET_USERINFO2, "SamrSetInformationUser2",
		samr_dissect_set_information_user2_rqst,
		samr_dissect_set_information_user2_reply },
        { SAMR_SET_BOOT_KEY_INFORMATION, "SamrSetBootKeyInformation",
		samr_dissect_set_boot_key_information_rqst,
		samr_dissect_set_boot_key_information_reply },
        { SAMR_GET_BOOT_KEY_INFORMATION, "SamrGetBootKeyInformation",
		samr_dissect_get_boot_key_information_rqst,
		samr_dissect_get_boot_key_information_reply },
	{ SAMR_CONNECT3, "SamrConnect3",
		samr_dissect_connect3_4_rqst,
		samr_dissect_connect3_reply },
	{ SAMR_CONNECT4, "SamrConnect4",
		samr_dissect_connect3_4_rqst,
		samr_dissect_connect4_reply },
	{ SAMR_UNICODE_CHANGE_PASSWORD_USER3, "SamrUnicodeChangePasswordUser3",
		NULL, NULL },
	{ SAMR_CONNECT5, "SamrConnect5",
		samr_dissect_connect5_rqst, 
		samr_dissect_connect5_reply },
	{ SAMR_RID_TO_SID, "SamrRidToSid", NULL, NULL },
	{ SAMR_SET_DSRM_PASSWORD, "SamrSetDSRMPassword", NULL, NULL },
	{ SAMR_VALIDATE_PASSWORD, "SamrValidatePassword", NULL, NULL },
        {0, NULL, NULL,  NULL }
};

void
proto_register_dcerpc_samr(void)
{
        static hf_register_info hf[] = {
		{ &hf_samr_opnum,
		  { "Operation", "samr.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, "Operation", HFILL }},
                { &hf_samr_hnd,
                  { "Context Handle", "samr.hnd", FT_BYTES, BASE_NONE, NULL, 0x0, "", HFILL }},
                { &hf_samr_group,
                  { "Group", "samr.group", FT_UINT32, BASE_DEC, NULL, 0x0, "Group", HFILL }},
                { &hf_samr_rid,
                  { "Rid", "samr.rid", FT_UINT32, BASE_DEC, NULL, 0x0, "RID", HFILL }},
                { &hf_samr_type,
                  { "Type", "samr.type", FT_UINT32, BASE_HEX, NULL, 0x0, "Type", HFILL }},
                { &hf_samr_alias,
                  { "Alias", "samr.alias", FT_UINT32, BASE_HEX, NULL, 0x0, "Alias", HFILL }},
                { &hf_samr_rid_attrib,
                  { "Rid Attrib", "samr.rid.attrib", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
                { &hf_samr_attrib,
                  { "Attributes", "samr.attr", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
                { &hf_samr_rc,
                  { "Return code", "samr.rc", FT_UINT32, BASE_HEX, VALS (NT_errors), 0x0, "", HFILL }},

	{ &hf_samr_level,
		{ "Level", "samr.level", FT_UINT16, BASE_DEC,
		NULL, 0x0, "Level requested/returned for Information", HFILL }},
	{ &hf_samr_start_idx,
		{ "Start Idx", "samr.start_idx", FT_UINT32, BASE_DEC,
		NULL, 0x0, "Start Index for returned Information", HFILL }},

	{ &hf_samr_entries,
		{ "Entries", "samr.entries", FT_UINT32, BASE_DEC,
		NULL, 0x0, "Number of entries to return", HFILL }},

	{ &hf_samr_max_entries,
		{ "Max Entries", "samr.max_entries", FT_UINT32, BASE_DEC,
		NULL, 0x0, "Maximum number of entries", HFILL }},

	{ &hf_samr_pref_maxsize,
		{ "Pref MaxSize", "samr.pref_maxsize", FT_UINT32, BASE_DEC,
		NULL, 0x0, "Maximum Size of data to return", HFILL }},

	{ &hf_samr_total_size,
		{ "Total Size", "samr.total_size", FT_UINT32, BASE_DEC,
		NULL, 0x0, "Total size of data", HFILL }},

	{ &hf_samr_bad_pwd_count,
		{ "Bad Pwd Count", "samr.bad_pwd_count", FT_UINT16, BASE_DEC,
		NULL, 0x0, "Number of bad pwd entries for this user", HFILL }},

	{ &hf_samr_logon_count,
		{ "Logon Count", "samr.logon_count", FT_UINT16, BASE_DEC,
		NULL, 0x0, "Number of logons for this user", HFILL }},

	{ &hf_samr_ret_size,
		{ "Returned Size", "samr.ret_size", FT_UINT32, BASE_DEC,
		NULL, 0x0, "Number of returned objects in this PDU", HFILL }},

	{ &hf_samr_index,
		{ "Index", "samr.index", FT_UINT32, BASE_DEC,
		NULL, 0x0, "Index", HFILL }},

        { &hf_samr_count,
          { "Count", "samr.count", FT_UINT32, BASE_DEC, NULL, 0x0, "Number of elements in following array", HFILL }},

	{ &hf_samr_alias_name,
		{ "Alias Name", "samr.alias_name", FT_STRING, BASE_NONE,
		NULL, 0, "Name of Alias (Local Group)", HFILL }},

	{ &hf_samr_group_name,
		{ "Group Name", "samr.group_name", FT_STRING, BASE_NONE,
		NULL, 0, "Name of Group", HFILL }},

	{ &hf_samr_acct_name,
		{ "Account Name", "samr.acct_name", FT_STRING, BASE_NONE,
		NULL, 0, "Name of Account", HFILL }},

	{ &hf_samr_server,
		{ "Server", "samr.server", FT_STRING, BASE_NONE,
		NULL, 0, "Name of Server", HFILL }},

	{ &hf_samr_domain,
		{ "Domain", "samr.domain", FT_STRING, BASE_NONE,
		NULL, 0, "Name of Domain", HFILL }},

	{ &hf_samr_controller,
		{ "DC", "samr.dc", FT_STRING, BASE_NONE,
		NULL, 0, "Name of Domain Controller", HFILL }},

	{ &hf_samr_full_name,
		{ "Full Name", "samr.full_name", FT_STRING, BASE_NONE,
		NULL, 0, "Full Name of Account", HFILL }},

	{ &hf_samr_home,
		{ "Home", "samr.home", FT_STRING, BASE_NONE,
		NULL, 0, "Home directory for this user", HFILL }},

	{ &hf_samr_home_drive,
		{ "Home Drive", "samr.home_drive", FT_STRING, BASE_NONE,
		NULL, 0, "Home drive for this user", HFILL }},

	{ &hf_samr_script,
		{ "Script", "samr.script", FT_STRING, BASE_NONE,
		NULL, 0, "Login script for this user", HFILL }},

	{ &hf_samr_workstations,
		{ "Workstations", "samr.workstations", FT_STRING, BASE_NONE,
		NULL, 0, "", HFILL }},

	{ &hf_samr_profile,
		{ "Profile", "samr.profile", FT_STRING, BASE_NONE,
		NULL, 0, "Profile for this user", HFILL }},

	{ &hf_samr_acct_desc,
		{ "Account Desc", "samr.acct_desc", FT_STRING, BASE_NONE,
		NULL, 0, "Account Description", HFILL }},

	{ &hf_samr_comment,
		{ "Account Comment", "samr.comment", FT_STRING, BASE_NONE,
		NULL, 0, "Account Comment", HFILL }},

	{ &hf_samr_unknown_string,
		{ "Unknown string", "samr.unknown_string", FT_STRING, BASE_NONE,
		NULL, 0, "Unknown string. If you know what this is, contact wireshark developers.", HFILL }},

	{ &hf_samr_unknown_hyper,
		{ "Unknown hyper", "samr.unknown.hyper", FT_UINT64, BASE_HEX,
		NULL, 0x0, "Unknown hyper. If you know what this is, contact wireshark developers.", HFILL }},
	{ &hf_samr_unknown_long,
		{ "Unknown long", "samr.unknown.long", FT_UINT32, BASE_HEX,
		NULL, 0x0, "Unknown long. If you know what this is, contact wireshark developers.", HFILL }},

	{ &hf_samr_unknown_short,
		{ "Unknown short", "samr.unknown.short", FT_UINT16, BASE_HEX,
		NULL, 0x0, "Unknown short. If you know what this is, contact wireshark developers.", HFILL }},

	{ &hf_samr_unknown_char,
		{ "Unknown char", "samr.unknown.char", FT_UINT8, BASE_HEX,
		NULL, 0x0, "Unknown char. If you know what this is, contact wireshark developers.", HFILL }},

 	{ &hf_samr_revision,
 		{ "Revision", "samr.revision", FT_UINT64, BASE_HEX,
 		NULL, 0x0, "Revision number for this structure", HFILL }},

 	{ &hf_samr_nt_pwd_set,
 		{ "NT Pwd Set", "samr.nt_pwd_set", FT_UINT8, BASE_HEX,
 		NULL, 0x0, "Flag indicating whether the NT password has been set", HFILL }},

 	{ &hf_samr_lm_pwd_set,
 		{ "LM Pwd Set", "samr.lm_pwd_set", FT_UINT8, BASE_HEX,
 		NULL, 0x0, "Flag indicating whether the LanManager password has been set", HFILL }},

 	{ &hf_samr_pwd_expired,
 		{ "Expired flag", "samr.pwd_Expired", FT_UINT8, BASE_HEX,
 		NULL, 0x0, "Flag indicating if the password for this account has expired or not", HFILL }},

	{ &hf_samr_access,
		{ "Access Mask", "samr.access", FT_UINT32, BASE_HEX,
		NULL, 0x0, "Access", HFILL }},

	{ &hf_samr_access_granted,
		{ "Access Granted", "samr.access_granted", FT_UINT32, BASE_HEX,
		NULL, 0x0, "Access Granted", HFILL }},

	{ &hf_samr_crypt_password, {
		"Password", "samr.crypt_password", FT_BYTES, BASE_HEX,
		NULL, 0, "Encrypted Password", HFILL }},

	{ &hf_samr_crypt_hash, {
		"Hash", "samr.crypt_hash", FT_BYTES, BASE_HEX,
		NULL, 0, "Encrypted Hash", HFILL }},

	{ &hf_samr_lm_verifier, {
		"Verifier", "samr.lm_password_verifier", FT_BYTES, BASE_HEX,
		NULL, 0, "Lan Manager Password Verifier", HFILL }},

	{ &hf_samr_nt_verifier, {
		"Verifier", "samr.nt_password_verifier", FT_BYTES, BASE_HEX,
		NULL, 0, "NT Password Verifier", HFILL }},

	{ &hf_samr_lm_passchange_block, {
		"Encrypted Block", "samr.lm_passchange_block", FT_BYTES, 
		BASE_HEX, NULL, 0, "Lan Manager Password Change Block",
		HFILL }},

	{ &hf_samr_nt_passchange_block, {
		"Encrypted Block", "samr.nt_passchange_block", FT_BYTES, 
		BASE_HEX, NULL, 0, "NT Password Change Block", HFILL }},

	{ &hf_samr_nt_passchange_block_decrypted, {
		"Decrypted Block", "samr.nt_passchange_block_decrypted",
		FT_BYTES, BASE_HEX, NULL, 0, 
		"NT Password Change Decrypted Block", HFILL }},

	{ &hf_samr_nt_passchange_block_newpass, {
		"New NT Password", "samr.nt_passchange_block_new_ntpassword", 
		FT_STRING, BASE_NONE, NULL, 0, "New NT Password", HFILL }},

	{ &hf_samr_nt_passchange_block_newpass_len, {
		"New NT Unicode Password length", 
		"samr.nt_passchange_block_new_ntpassword_len", FT_UINT32, 
		BASE_DEC, NULL, 0, "New NT Password Unicode Length", HFILL }},

	{ &hf_samr_nt_passchange_block_pseudorandom, {
		"Pseudorandom data", "samr.nt_passchange_block_pseudorandom",
		FT_BYTES, BASE_HEX, NULL, 0, "Pseudorandom data", HFILL }},

	{ &hf_samr_lm_change, {
		"LM Change", "samr.lm_change", FT_UINT8, BASE_HEX,
		NULL, 0, "LM Change value", HFILL }},

	{ &hf_samr_force_logoff_time,
		{ "Forced Logoff Time After Time Expires", "samr.force_logoff_time", FT_RELATIVE_TIME, BASE_NONE,
		NULL, 0, "Forced logoff time after expires:", HFILL }},

	{ &hf_samr_lockout_duration_time,
		{ "Lockout Duration Time", "samr.lockout_duration_time", FT_RELATIVE_TIME, BASE_NONE,
		NULL, 0, "Lockout duration time:", HFILL }},
	{ &hf_samr_lockout_reset_time,
		{ "Lockout Reset Time", "samr.lockout_reset_time", FT_RELATIVE_TIME, BASE_NONE,
		NULL, 0, "Lockout Reset Time:", HFILL }},
	{ &hf_samr_lockout_threshold_short,
		{ "Lockout Threshold", "samr.lockout_threshold", FT_UINT16, BASE_DEC,
		NULL, 0, "Lockout Threshold:", HFILL }},

	{ &hf_samr_max_pwd_age,
		{ "Max Pwd Age", "samr.max_pwd_age", FT_RELATIVE_TIME, BASE_NONE,
		NULL, 0, "Maximum Password Age before it expires", HFILL }},

	{ &hf_samr_min_pwd_age,
		{ "Min Pwd Age", "samr.min_pwd_age", FT_RELATIVE_TIME, BASE_NONE,
		NULL, 0, "Minimum Password Age before it can be changed", HFILL }},
	{ &hf_samr_unknown_time,
		{ "Unknown time", "samr.unknown_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Unknown NT TIME, contact wireshark developers if you know what this is", HFILL }},
	{ &hf_samr_logon_time,
		{ "Last Logon Time", "samr.logon_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Time for last time this user logged on", HFILL }},
	{ &hf_samr_kickoff_time,
		{ "Kickoff Time", "samr.kickoff_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Time when this user will be kicked off", HFILL }},
	{ &hf_samr_logoff_time,
		{ "Last Logoff Time", "samr.logoff_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Time for last time this user logged off", HFILL }},
	{ &hf_samr_pwd_last_set_time,
		{ "PWD Last Set", "samr.pwd_last_set_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Last time this users password was changed", HFILL }},
	{ &hf_samr_pwd_can_change_time,
		{ "PWD Can Change", "samr.pwd_can_change_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "When this users password may be changed", HFILL }},
	{ &hf_samr_pwd_must_change_time,
		{ "PWD Must Change", "samr.pwd_must_change_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "When this users password must be changed", HFILL }},
	{ &hf_samr_acct_expiry_time,
		{ "Acct Expiry", "samr.acct_expiry_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "When this user account expires", HFILL }},

	{ &hf_samr_min_pwd_len, {
		"Min Pwd Len", "samr.min_pwd_len", FT_UINT16, BASE_DEC,
		NULL, 0, "Minimum Password Length", HFILL }},
	{ &hf_samr_pwd_history_len, {
		"Pwd History Len", "samr.pwd_history_len", FT_UINT16, BASE_DEC,
		NULL, 0, "Password History Length", HFILL }},
	{ &hf_samr_num_users, {
		"Num Users", "samr.num_users", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of users in this domain", HFILL }},
	{ &hf_samr_num_groups, {
		"Num Groups", "samr.num_groups", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of groups in this domain", HFILL }},
	{ &hf_samr_num_aliases, {
		"Num Aliases", "samr.num_aliases", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of aliases in this domain", HFILL }},
	{ &hf_samr_info_type, {
		"Info Type", "samr.info_type", FT_UINT32, BASE_DEC,
		NULL, 0, "Information Type", HFILL }},
	{ &hf_samr_resume_hnd, {
		"Resume Hnd", "samr.resume_hnd", FT_UINT32, BASE_DEC,
		NULL, 0, "Resume handle", HFILL }},
	{ &hf_samr_country, {
		"Country", "samr.country", FT_UINT16, BASE_DEC,
		VALS(ms_country_codes), 0, "Country setting for this user", HFILL }},
	{ &hf_samr_codepage, {
		"Codepage", "samr.codepage", FT_UINT16, BASE_DEC,
		NULL, 0, "Codepage setting for this user", HFILL }},
	{ &hf_samr_primary_group_rid,
		{ "Primary group RID", "samr.primary_group_rid", FT_UINT32,
	          BASE_DEC, NULL, 0x0, "RID of the user primary group", HFILL }},
	{ &hf_samr_callback,
		{ "Callback", "samr.callback", FT_STRING, BASE_NONE,
		NULL, 0, "Callback for this user", HFILL }},
	{ &hf_samr_alias_desc,
		{ "Alias Desc", "samr.alias.desc", FT_STRING, BASE_NONE,
		NULL, 0, "Alias (Local Group) Description", HFILL }},
	{ &hf_samr_alias_num_of_members,
		{ "Num of Members in Alias", "samr.alias.num_of_members", 
		  FT_UINT32, BASE_DEC, NULL, 0, 
		 "Number of members in Alias (Local Group)", HFILL }},
	{ &hf_samr_group_desc,
		{ "Group Desc", "samr.group.desc", FT_STRING, BASE_NONE,
		NULL, 0, "Group Description", HFILL }},
	{ &hf_samr_group_num_of_members,
		{ "Num of Members in Group", "samr.group.num_of_members", 
		  FT_UINT32, BASE_DEC, NULL, 0, 
		 "Number of members in Group", HFILL }},

        /* Object specific access rights */

	{ &hf_access_domain_lookup_info1,
	  { "Lookup info1", "samr_access_mask.domain_lookup_info1",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    DOMAIN_ACCESS_LOOKUP_INFO_1, "Lookup info1", HFILL }},

	{ &hf_access_domain_set_info1,
	  { "Set info1", "samr_access_mask.domain_set_info1",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    DOMAIN_ACCESS_SET_INFO_1, "Set info1", HFILL }},

	{ &hf_access_domain_lookup_info2,
	  { "Lookup info2", "samr_access_mask.domain_lookup_info2",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    DOMAIN_ACCESS_LOOKUP_INFO_2, "Lookup info2", HFILL }},

	{ &hf_access_domain_set_info2,
	  { "Set info2", "samr_access_mask.domain_set_info2",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    DOMAIN_ACCESS_SET_INFO_2, "Set info2", HFILL }},

	{ &hf_access_domain_create_user,
	  { "Create user", "samr_access_mask.domain_create_user",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    DOMAIN_ACCESS_CREATE_USER, "Create user", HFILL }},

	{ &hf_access_domain_create_group,
	  { "Create group", "samr_access_mask.domain_create_group",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    DOMAIN_ACCESS_CREATE_GROUP, "Create group", HFILL }},

	{ &hf_access_domain_create_alias,
	  { "Create alias", "samr_access_mask.domain_create_alias",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    DOMAIN_ACCESS_CREATE_ALIAS, "Create alias", HFILL }},

	{ &hf_access_domain_lookup_alias_by_mem,
	  { "Lookup alias", "samr_access_mask.domain_lookup_alias_by_mem",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    DOMAIN_ACCESS_LOOKUP_ALIAS, "Lookup alias", HFILL }},

	{ &hf_access_domain_enum_accounts,
	  { "Enum accounts", "samr_access_mask.domain_enum_accounts",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    DOMAIN_ACCESS_ENUM_ACCOUNTS, "Enum accounts", HFILL }},

	{ &hf_access_domain_open_account,
	  { "Open account", "samr_access_mask.domain_open_account",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    DOMAIN_ACCESS_OPEN_ACCOUNT, "Open account", HFILL }},

	{ &hf_access_domain_set_info3,
	  { "Set info3", "samr_access_mask.domain_set_info3",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    DOMAIN_ACCESS_SET_INFO_3, "Set info3", HFILL }},

	{ &hf_access_user_get_name_etc,
	  { "Get name, etc", "samr_access_mask.user_get_name_etc",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    USER_ACCESS_GET_NAME_ETC, "Get name, etc", HFILL }},

	{ &hf_access_user_get_locale,
	  { "Get locale", "samr_access_mask.user_get_locale",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    USER_ACCESS_GET_LOCALE, "Get locale", HFILL }},

	{ &hf_access_user_get_loc_com,
	  { "Set loc com", "samr_access_mask.user_set_loc_com",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    USER_ACCESS_SET_LOC_COM, "Set loc com", HFILL }},

	{ &hf_access_user_get_logoninfo,
	  { "Get logon info", "samr_access_mask.user_get_logoninfo",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    USER_ACCESS_GET_LOGONINFO, "Get logon info", HFILL }},

	{ &hf_access_user_get_attributes,
	  { "Get attributes", "samr_access_mask.user_get_attributes",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    USER_ACCESS_GET_ATTRIBUTES, "Get attributes", HFILL }},

	{ &hf_access_user_set_attributes,
	  { "Set attributes", "samr_access_mask.user_set_attributes",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    USER_ACCESS_SET_ATTRIBUTES, "Set attributes", HFILL }},

	{ &hf_access_user_change_password,
	  { "Change password", "samr_access_mask.user_change_password",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    USER_ACCESS_CHANGE_PASSWORD, "Change password", HFILL }},

	{ &hf_access_user_set_password,
	  { "Set password", "samr_access_mask.user_set_password",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    USER_ACCESS_SET_PASSWORD, "Set password", HFILL }},

	{ &hf_access_user_get_groups,
	  { "Get groups", "samr_access_mask.user_get_groups",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    USER_ACCESS_GET_GROUPS, "Get groups", HFILL }},

	{ &hf_access_user_get_group_membership,
	  { "Get group membership", "samr_access_mask.user_get_group_membership",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    USER_ACCESS_GET_GROUP_MEMBERSHIP, "Get group membership", HFILL }},

	{ &hf_access_user_change_group_membership,
	  { "Change group membership", "samr_access_mask.user_change_group_membership",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    USER_ACCESS_CHANGE_GROUP_MEMBERSHIP, "Change group membership", HFILL }},

	{ &hf_access_group_lookup_info,
	  { "Lookup info", "samr_access_mask.group_lookup_info",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    GROUP_ACCESS_LOOKUP_INFO, "Lookup info", HFILL }},

	{ &hf_access_group_set_info,
	  { "Get info", "samr_access_mask.group_set_info",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    GROUP_ACCESS_SET_INFO, "Get info", HFILL }},

	{ &hf_access_group_add_member,
	  { "Add member", "samr_access_mask.group_add_member",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    GROUP_ACCESS_ADD_MEMBER, "Add member", HFILL }},

	{ &hf_access_group_remove_member,
	  { "Remove member", "samr_access_mask.group_remove_member",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    GROUP_ACCESS_REMOVE_MEMBER, "Remove member", HFILL }},

	{ &hf_access_group_get_members,
	  { "Get members", "samr_access_mask.group_get_members",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    GROUP_ACCESS_GET_MEMBERS, "Get members", HFILL }},

	{ &hf_access_alias_add_member,
	  { "Add member", "samr_access_mask.alias_add_member",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    ALIAS_ACCESS_ADD_MEMBER, "Add member", HFILL }},

	{ &hf_access_alias_remove_member,
	  { "Remove member", "samr_access_mask.alias_remove_member",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    ALIAS_ACCESS_REMOVE_MEMBER, "Remove member", HFILL }},

	{ &hf_access_alias_get_members,
	  { "Get members", "samr_access_mask.alias_get_members",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    ALIAS_ACCESS_GET_MEMBERS, "Get members", HFILL }},

	{ &hf_access_alias_lookup_info,
	  { "Lookup info", "samr_access_mask.alias_lookup_info",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    ALIAS_ACCESS_LOOKUP_INFO, "Lookup info", HFILL }},

	{ &hf_access_alias_set_info,
	  { "Set info", "samr_access_mask.alias_set_info",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    ALIAS_ACCESS_SET_INFO, "Set info", HFILL }},

	{ &hf_access_connect_connect_to_server,
	  { "Connect to server", "samr_access_mask.connect_connect_to_server",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    SAMR_ACCESS_CONNECT_TO_SERVER, "Connect to server", HFILL }},

	{ &hf_access_connect_shutdown_server,
	  { "Shutdown server", "samr_access_mask.connect_shutdown_server",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    SAMR_ACCESS_SHUTDOWN_SERVER, "Shutdown server", HFILL }},

	{ &hf_access_connect_initialize_server,
	  { "Initialize server", "samr_access_mask.connect_initialize_server",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    SAMR_ACCESS_INITIALIZE_SERVER, "Initialize server", HFILL }},

	{ &hf_access_connect_create_domain,
	  { "Create domain", "samr_access_mask.connect_create_domain",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    SAMR_ACCESS_CREATE_DOMAIN, "Create domain", HFILL }},

	{ &hf_access_connect_enum_domains,
	  { "Enum domains", "samr_access_mask.connect_enum_domains",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
	    SAMR_ACCESS_ENUM_DOMAINS, "Enum domains", HFILL }},

	{ &hf_access_connect_open_domain,
	  { "Open domain", "samr_access_mask.connect_open_domain",
	    FT_BOOLEAN, 32, TFS(&flags_set_truth),
           SAMR_ACCESS_OPEN_DOMAIN, "Open domain", HFILL }},

       { &hf_samr_sd_size,
               { "Size", "sam.sd_size", FT_UINT32, BASE_DEC,
               NULL, 0x0, "Size of SAM security descriptor", HFILL }},

        };

        static gint *ett[] = {
                &ett_dcerpc_samr,
		&ett_SAM_SECURITY_DESCRIPTOR,
		&ett_samr_user_dispinfo_1,
                &ett_samr_user_dispinfo_1_array,
                &ett_samr_user_dispinfo_2,
                &ett_samr_user_dispinfo_2_array,
                &ett_samr_group_dispinfo,
                &ett_samr_group_dispinfo_array,
                &ett_samr_ascii_dispinfo,
                &ett_samr_ascii_dispinfo_array,
                &ett_samr_display_info,
                &ett_samr_password_info,
                &ett_samr_server,
                &ett_samr_user_group,
                &ett_samr_user_group_array,
                &ett_samr_alias_info,
                &ett_samr_group_info,
                &ett_samr_domain_info_1,
                &ett_samr_domain_info_2,
                &ett_samr_domain_info_8,
                &ett_samr_replication_status,
                &ett_samr_domain_info_11,
                &ett_samr_domain_info_13,
                &ett_samr_domain_info,
                &ett_samr_index_array,
                &ett_samr_idx_and_name,
                &ett_samr_idx_and_name_array,
                &ett_samr_user_info_1,
                &ett_samr_user_info_2,
                &ett_samr_user_info_3,
                &ett_samr_user_info_5,
                &ett_samr_user_info_6,
                &ett_samr_user_info_10,
                &ett_samr_user_info_18,
                &ett_samr_user_info_19,
                &ett_samr_buffer_buffer,
                &ett_samr_buffer,
                &ett_samr_user_info_21,
                &ett_samr_user_info_22,
                &ett_samr_user_info_23,
                &ett_samr_user_info_24,
                &ett_samr_user_info_25,
                &ett_samr_user_info,
                &ett_samr_member_array_types,
                &ett_samr_member_array_rids,
                &ett_samr_member_array,
                &ett_samr_names,
                &ett_samr_rids,
        };
	module_t *dcerpc_samr_module;

        proto_dcerpc_samr = proto_register_protocol(
                "Microsoft Security Account Manager", "SAMR", "samr");

        proto_register_field_array (proto_dcerpc_samr, hf, array_length (hf));
        proto_register_subtree_array(ett, array_length(ett));

	dcerpc_samr_module = prefs_register_protocol(proto_dcerpc_samr, NULL);
	
	prefs_register_string_preference(dcerpc_samr_module, "nt_password",
					 "NT Password",
					 "NT Password (used to verify password changes)",
					 &nt_password);
}

void
proto_reg_handoff_dcerpc_samr(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_samr, ett_dcerpc_samr, &uuid_dcerpc_samr,
                         ver_dcerpc_samr, dcerpc_samr_dissectors, hf_samr_opnum);
}
