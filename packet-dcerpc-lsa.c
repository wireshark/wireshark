/* packet-dcerpc-lsa.c
 * Routines for SMB \PIPE\lsarpc packet disassembly
 * Copyright 2001,2003 Tim Potter <tpot@samba.org>
 *  2002  Added LSA command dissectors  Ronnie Sahlberg
 *
 * $Id: packet-dcerpc-lsa.c,v 1.72 2003/02/08 09:41:43 guy Exp $
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
#include <string.h>

#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"
#include "packet-dcerpc-lsa.h"
#include "packet-smb-common.h"
#include "smb.h"

static int proto_dcerpc_lsa = -1;

static int hf_lsa_opnum = -1;
static int hf_lsa_rc = -1;
static int hf_lsa_hnd = -1;
static int hf_lsa_server = -1;
static int hf_lsa_controller = -1;
static int hf_lsa_obj_attr = -1;
static int hf_lsa_obj_attr_len = -1;
static int hf_lsa_obj_attr_name = -1;
static int hf_lsa_access_mask = -1;
static int hf_lsa_info_level = -1;
static int hf_lsa_trusted_info_level = -1;
static int hf_lsa_sd_size = -1;
static int hf_lsa_qos_len = -1;
static int hf_lsa_qos_impersonation_level = -1;
static int hf_lsa_qos_track_context = -1;
static int hf_lsa_qos_effective_only = -1;
static int hf_lsa_pali_percent_full = -1;
static int hf_lsa_pali_log_size = -1;
static int hf_lsa_pali_retention_period = -1;
static int hf_lsa_pali_time_to_shutdown = -1;
static int hf_lsa_pali_shutdown_in_progress = -1;
static int hf_lsa_pali_next_audit_record = -1;
static int hf_lsa_paei_enabled = -1;
static int hf_lsa_paei_settings = -1;
static int hf_lsa_count = -1;
static int hf_lsa_size = -1;
static int hf_lsa_size16 = -1;
static int hf_lsa_size_needed = -1;
static int hf_lsa_max_count = -1;
static int hf_lsa_index = -1;
static int hf_lsa_domain = -1;
static int hf_lsa_acct = -1;
static int hf_lsa_server_role = -1;
static int hf_lsa_source = -1;
static int hf_lsa_quota_paged_pool = -1;
static int hf_lsa_quota_non_paged_pool = -1;
static int hf_lsa_quota_min_wss = -1;
static int hf_lsa_quota_max_wss = -1;
static int hf_lsa_quota_pagefile = -1;
static int hf_lsa_mod_seq_no = -1;
static int hf_lsa_mod_mtime = -1;
static int hf_lsa_cur_mtime = -1;
static int hf_lsa_old_mtime = -1;
static int hf_lsa_name = -1;
static int hf_lsa_key = -1;
static int hf_lsa_flat_name = -1;
static int hf_lsa_forest = -1;
static int hf_lsa_info_type = -1;
static int hf_lsa_old_pwd = -1;
static int hf_lsa_new_pwd = -1;
static int hf_lsa_sid_type = -1;
static int hf_lsa_rid = -1;
static int hf_lsa_rid_offset = -1;
static int hf_lsa_num_mapped = -1;
static int hf_lsa_policy_information_class = -1;
static int hf_lsa_secret = -1;
static int hf_nt_luid_high = -1;
static int hf_nt_luid_low = -1;
static int hf_lsa_privilege_name = -1;
static int hf_lsa_attr = -1;
static int hf_lsa_resume_handle = -1;
static int hf_lsa_trust_direction = -1;
static int hf_lsa_trust_type = -1;
static int hf_lsa_trust_attr = -1;
static int hf_lsa_trust_attr_non_trans = -1;
static int hf_lsa_trust_attr_uplevel_only = -1;
static int hf_lsa_trust_attr_tree_parent = -1;
static int hf_lsa_trust_attr_tree_root = -1;
static int hf_lsa_auth_update = -1;
static int hf_lsa_auth_type = -1;
static int hf_lsa_auth_len = -1;
static int hf_lsa_auth_blob = -1;
static int hf_lsa_rights = -1;
static int hf_lsa_remove_all = -1;

static int hf_lsa_unknown_hyper = -1;
static int hf_lsa_unknown_long = -1;
static int hf_lsa_unknown_short = -1;
static int hf_lsa_unknown_char = -1;
static int hf_lsa_unknown_string = -1;
#ifdef LSA_UNUSED_HANDLES
static int hf_lsa_unknown_time = -1;
#endif


static gint ett_dcerpc_lsa = -1;
static gint ett_lsa_OBJECT_ATTRIBUTES = -1;
static gint ett_LSA_SECURITY_DESCRIPTOR = -1;
static gint ett_lsa_policy_info = -1;
static gint ett_lsa_policy_audit_log_info = -1;
static gint ett_lsa_policy_audit_events_info = -1;
static gint ett_lsa_policy_primary_domain_info = -1;
static gint ett_lsa_policy_primary_account_info = -1;
static gint ett_lsa_policy_server_role_info = -1;
static gint ett_lsa_policy_replica_source_info = -1;
static gint ett_lsa_policy_default_quota_info = -1;
static gint ett_lsa_policy_modification_info = -1;
static gint ett_lsa_policy_audit_full_set_info = -1;
static gint ett_lsa_policy_audit_full_query_info = -1;
static gint ett_lsa_policy_dns_domain_info = -1;
static gint ett_lsa_translated_names = -1;
static gint ett_lsa_translated_name = -1;
static gint ett_lsa_referenced_domain_list = -1;
static gint ett_lsa_trust_information = -1;
static gint ett_lsa_trust_information_ex = -1;
static gint ett_LUID = -1;
static gint ett_LSA_PRIVILEGES = -1;
static gint ett_LSA_PRIVILEGE = -1;
static gint ett_LSA_LUID_AND_ATTRIBUTES_ARRAY = -1;
static gint ett_LSA_LUID_AND_ATTRIBUTES = -1;
static gint ett_LSA_TRUSTED_DOMAIN_LIST = -1;
static gint ett_LSA_TRUSTED_DOMAIN = -1;
static gint ett_LSA_TRANSLATED_SIDS = -1;
static gint ett_lsa_trusted_domain_info = -1;
static gint ett_lsa_trust_attr = -1;
static gint ett_lsa_trusted_domain_auth_information = -1;
static gint ett_lsa_auth_information = -1;


static int
lsa_dissect_pointer_NTTIME(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             char *drep)
{
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		di->hf_index);

	return offset;
}

static int
lsa_dissect_pointer_UNICODE_STRING(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             char *drep)
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
lsa_dissect_pointer_pointer_UNICODE_STRING(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             char *drep)
{
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_pointer_UNICODE_STRING, NDR_POINTER_UNIQUE,
		"DOMAIN pointer: ", di->hf_index);

	return offset;
}

static int
lsa_dissect_pointer_STRING(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             char *drep)
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
lsa_dissect_LSA_SECRET_data(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             char *drep)
{
	guint32 len;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_sd_size, &len);
	proto_tree_add_item(tree, hf_lsa_secret, tvb, offset, len, FALSE);
	offset += len;

	return offset;
}
int
lsa_dissect_LSA_SECRET(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"LSA_SECRET:");
		tree = proto_item_add_subtree(item, ett_LSA_SECURITY_DESCRIPTOR);
	}

	/* XXX need to figure this one out */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_sd_size, NULL);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			lsa_dissect_LSA_SECRET_data, NDR_POINTER_UNIQUE,
			"LSA SECRET data:", -1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
lsa_dissect_LSA_SECRET_pointer(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_SECRET, NDR_POINTER_UNIQUE,
		"LSA_SECRET pointer: data", -1);

	return offset;
}

/* Dissect LSA specific access rights */

static gint hf_view_local_info = -1;
static gint hf_view_audit_info = -1;
static gint hf_get_private_info = -1;
static gint hf_trust_admin = -1;
static gint hf_create_account = -1;
static gint hf_create_secret = -1;
static gint hf_create_priv = -1;
static gint hf_set_default_quota_limits = -1;
static gint hf_set_audit_requirements = -1;
static gint hf_server_admin = -1;
static gint hf_lookup_names = -1;

static void
lsa_specific_rights(tvbuff_t *tvb, gint offset, proto_tree *tree,
		    guint32 access)
{
	proto_tree_add_boolean(
		tree, hf_lookup_names, tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_server_admin, tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_set_audit_requirements, tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_set_default_quota_limits, tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_create_priv, tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_create_secret, tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_create_account, tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_trust_admin, tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_get_private_info, tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_view_audit_info, tvb, offset, 4, access);

	proto_tree_add_boolean(
		tree, hf_view_local_info, tvb, offset, 4, access);
}

int
lsa_dissect_LSA_SECURITY_DESCRIPTOR_data(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             char *drep)
{
	guint32 len;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
				     hf_lsa_sd_size, &len);

	dissect_nt_sec_desc(
		tvb, offset, pinfo, tree, drep, len, lsa_specific_rights);

	offset += len;

	return offset;
}
int
lsa_dissect_LSA_SECURITY_DESCRIPTOR(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"LSA_SECURITY_DESCRIPTOR:");
		tree = proto_item_add_subtree(item, ett_LSA_SECURITY_DESCRIPTOR);
	}

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
				    hf_lsa_sd_size, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			lsa_dissect_LSA_SECURITY_DESCRIPTOR_data, NDR_POINTER_UNIQUE,
			"LSA SECURITY DESCRIPTOR data:", -1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
lsa_dissect_LPSTR(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
			hf_lsa_unknown_char, NULL);

	return offset;
}

static const value_string lsa_impersonation_level_vals[] = {
	{0,	"Anonymous"},
	{1,	"Identification"},
	{2,	"Impersonation"},
	{3,	"Delegation"},
	{0, NULL}
};


static int
lsa_dissect_SECURITY_QUALITY_OF_SERVICE(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* Length */
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_lsa_qos_len, NULL);

	/* impersonation level */
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
			hf_lsa_qos_impersonation_level, NULL);

	/* context tracking mode */
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
			hf_lsa_qos_track_context, NULL);

	/* effective only */
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
			hf_lsa_qos_effective_only, NULL);

	return offset;
}

static int
lsa_dissect_ACCESS_MASK(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_nt_access_mask(
		tvb, offset, pinfo, tree, drep, hf_lsa_access_mask,
		lsa_specific_rights);

	return offset;
}

static int
lsa_dissect_LSA_HANDLE(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
			hf_lsa_hnd, NULL, FALSE, FALSE);

	return offset;
}

static int
lsa_dissect_LSA_HANDLE_open(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
			hf_lsa_hnd, NULL, TRUE, FALSE);

	return offset;
}

static int
lsa_dissect_LSA_HANDLE_close(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
			hf_lsa_hnd, NULL, FALSE, TRUE);

	return offset;
}


static int
lsa_dissect_LSA_OBJECT_ATTRIBUTES(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	int old_offset=offset;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "Object Attributes");
		tree = proto_item_add_subtree(item, ett_lsa_OBJECT_ATTRIBUTES);
	}

	/* Length */
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_lsa_obj_attr_len, NULL);

	/* LPSTR */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LPSTR, NDR_POINTER_UNIQUE,
		"LSPTR pointer: ", -1);

	/* attribute name */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_pointer_STRING, NDR_POINTER_UNIQUE,
		"NAME pointer: ", hf_lsa_obj_attr_name);

	/* Attr */
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_lsa_obj_attr, NULL);

	/* security descriptor */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_SECURITY_DESCRIPTOR, NDR_POINTER_UNIQUE,
		"LSA_SECURITY_DESCRIPTOR pointer: ", -1);

	/* security quality of service */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_SECURITY_QUALITY_OF_SERVICE, NDR_POINTER_UNIQUE,
		"LSA_SECURITY_QUALITY_OF_SERVICE pointer: ", -1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
lsa_dissect_lsaclose_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_HANDLE_close, NDR_POINTER_REF,
		"LSA_HANDLE", -1);
	return offset;
}


static int
lsa_dissect_lsaclose_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_HANDLE, NDR_POINTER_REF,
		"LSA_HANDLE", -1);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

/* A bug in the NT IDL for lsa openpolicy only stores the first (wide)
   character of the server name which is always '\'.  This is fixed in lsa
   openpolicy2 but the function remains for backwards compatibility. */

static int dissect_lsa_openpolicy_server(tvbuff_t *tvb, int offset,
					     packet_info *pinfo,
					     proto_tree *tree, char *drep)
{
	return dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
				  hf_lsa_server, NULL);
}

static int
lsa_dissect_lsaopenpolicy_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_lsa_openpolicy_server, NDR_POINTER_UNIQUE,
		"Server:", hf_lsa_server);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_OBJECT_ATTRIBUTES, NDR_POINTER_REF,
		"OBJECT_ATTRIBUTES", -1);

	offset = lsa_dissect_ACCESS_MASK(tvb, offset,
		pinfo, tree, drep);
	return offset;
}

static int
lsa_dissect_lsaopenpolicy_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_HANDLE_open, NDR_POINTER_REF,
		"LSA_HANDLE", -1);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsaopenpolicy2_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer_cb(tvb, offset, pinfo, tree, drep,
		dissect_ndr_wchar_cvstring, NDR_POINTER_UNIQUE, "Server", 
		hf_lsa_server, cb_str_postprocess, 
		GINT_TO_POINTER(CB_STR_COL_INFO | CB_STR_SAVE | 1));

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_OBJECT_ATTRIBUTES, NDR_POINTER_REF,
		"OBJECT_ATTRIBUTES", -1);

	offset = lsa_dissect_ACCESS_MASK(tvb, offset,
		pinfo, tree, drep);
	return offset;
}


static int
lsa_dissect_lsaopenpolicy2_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_HANDLE_open, NDR_POINTER_REF,
		"LSA_HANDLE", -1);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static const value_string policy_information_class_vals[] = {
	{1,	"Audit Log Information"},
	{2,	"Audit Events Information"},
	{3,	"Primary Domain Information"},
	{4,	"Pd Account Information"},
	{5,	"Account Domain Information"},
	{6,	"Server Role Information"},
	{7,	"Replica Source Information"},
	{8,	"Default Quota Information"},
	{9,	"Modification Information"},
	{10,	"Audit Full Set Information"},
	{11,	"Audit Full Query Information"},
	{12,	"DNS Domain Information"},
	{0, NULL}
};

static int
lsa_dissect_lsaqueryinformationpolicy_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	guint16 level;

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_HANDLE, NDR_POINTER_REF,
		"LSA_HANDLE", -1);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_lsa_policy_information_class, &level);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(
			pinfo->cinfo, COL_INFO, ", %s",
			val_to_str(level, policy_information_class_vals,
				   "Unknown (%d)"));

	return offset;
}

static int
lsa_dissect_POLICY_AUDIT_LOG_INFO(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"POLICY_AUDIT_LOG_INFO:");
		tree = proto_item_add_subtree(item, ett_lsa_policy_audit_log_info);
	}

	/* percent full */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_pali_percent_full, NULL);

	/* log size */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_pali_log_size, NULL);

	/* retention period */
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_lsa_pali_retention_period);

	/* shutdown in progress */
        offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_pali_shutdown_in_progress, NULL);

	/* time to shutdown */
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_lsa_pali_time_to_shutdown);

	/* next audit record */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_pali_next_audit_record, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
lsa_dissect_POLICY_AUDIT_EVENTS_INFO_settings(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_paei_settings, NULL);
	return offset;
}

static int
lsa_dissect_POLICY_AUDIT_EVENTS_INFO_settings_array(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
		lsa_dissect_POLICY_AUDIT_EVENTS_INFO_settings);

	return offset;
}

static int
lsa_dissect_POLICY_AUDIT_EVENTS_INFO(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"POLICY_AUDIT_EVENTS_INFO:");
		tree = proto_item_add_subtree(item, ett_lsa_policy_audit_events_info);
	}

	/* enabled */
        offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_paei_enabled, NULL);

	/* settings */
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_POLICY_AUDIT_EVENTS_INFO_settings_array, NDR_POINTER_UNIQUE,
		"Settings", -1);

	/* count */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_count, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
lsa_dissect_POLICY_PRIMARY_DOMAIN_INFO(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"POLICY_PRIMARY_DOMAIN_INFO:");
		tree = proto_item_add_subtree(item, ett_lsa_policy_primary_domain_info);
	}

	/* domain */
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_lsa_domain, 0);

	/* sid */
	offset = dissect_ndr_nt_PSID(tvb, offset,
		pinfo, tree, drep);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
lsa_dissect_POLICY_ACCOUNT_DOMAIN_INFO(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"POLICY_ACCOUNT_DOMAIN_INFO:");
		tree = proto_item_add_subtree(item, ett_lsa_policy_primary_account_info);
	}

	/* account */
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_lsa_acct, 0);

	/* sid */
	offset = dissect_ndr_nt_PSID(tvb, offset,
		pinfo, tree, drep);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static const value_string server_role_vals[] = {
	{0,	"Standalone"},
	{1,	"Domain Member"},
	{2,	"Backup"},
	{3,	"Primary"},
	{0, NULL}
};
static int
lsa_dissect_POLICY_SERVER_ROLE_INFO(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"POLICY_SERVER_ROLE_INFO:");
		tree = proto_item_add_subtree(item, ett_lsa_policy_server_role_info);
	}

	/* server role */
        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_server_role, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
lsa_dissect_POLICY_REPLICA_SOURCE_INFO(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"POLICY_REPLICA_SOURCE_INFO:");
		tree = proto_item_add_subtree(item, ett_lsa_policy_replica_source_info);
	}

	/* source */
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_lsa_source, 0);

	/* account */
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_lsa_acct, 0);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
lsa_dissect_POLICY_DEFAULT_QUOTA_INFO(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"POLICY_DEFAULT_QUOTA_INFO:");
		tree = proto_item_add_subtree(item, ett_lsa_policy_default_quota_info);
	}

	/* paged pool */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_quota_paged_pool, NULL);

	/* non paged pool */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_quota_non_paged_pool, NULL);

	/* min wss */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_quota_min_wss, NULL);

	/* max wss */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_quota_max_wss, NULL);

	/* pagefile */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_quota_pagefile, NULL);

	/*  */
        offset = dissect_ndr_uint64 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_unknown_hyper, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
lsa_dissect_POLICY_MODIFICATION_INFO(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"POLICY_MODIFICATION_INFO:");
		tree = proto_item_add_subtree(item, ett_lsa_policy_modification_info);
	}

	/* seq no */
        offset = dissect_ndr_uint64 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_mod_seq_no, NULL);

	/* mtime */
	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
				hf_lsa_mod_mtime);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
lsa_dissect_POLICY_AUDIT_FULL_SET_INFO(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"POLICY_AUDIT_FULL_SET_INFO:");
		tree = proto_item_add_subtree(item, ett_lsa_policy_audit_full_set_info);
	}

	/* unknown */
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
			hf_lsa_unknown_char, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
lsa_dissect_POLICY_AUDIT_FULL_QUERY_INFO(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"POLICY_AUDIT_FULL_QUERY_INFO:");
		tree = proto_item_add_subtree(item, ett_lsa_policy_audit_full_query_info);
	}

	/* unknown */
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
			hf_lsa_unknown_char, NULL);

	/* unknown */
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
			hf_lsa_unknown_char, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


int
lsa_dissect_POLICY_DNS_DOMAIN_INFO(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"POLICY_DNS_DOMAIN_INFO:");
		tree = proto_item_add_subtree(item, ett_lsa_policy_dns_domain_info);
	}

	/* name */
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_lsa_name, 0);

	/* domain */
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_lsa_domain, 0);

	/* forest */
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_lsa_forest, 0);

	/* GUID */
	offset = dissect_nt_GUID(tvb, offset,
		pinfo, tree, drep);

	/* SID pointer */
	offset = dissect_ndr_nt_PSID(tvb, offset, pinfo, tree, drep);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
lsa_dissect_POLICY_INFORMATION(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;
	guint16 level;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"POLICY_INFO:");
		tree = proto_item_add_subtree(item, ett_lsa_policy_info);
	}

        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_info_level, &level);

	ALIGN_TO_4_BYTES;  /* all union arms aligned to 4 bytes, case 7 and 9 need this  */
	switch(level){
	case 1:
		offset = lsa_dissect_POLICY_AUDIT_LOG_INFO(
				tvb, offset, pinfo, tree, drep);
		break;
	case 2:
		offset = lsa_dissect_POLICY_AUDIT_EVENTS_INFO(
				tvb, offset, pinfo, tree, drep);
		break;
	case 3:
		offset = lsa_dissect_POLICY_PRIMARY_DOMAIN_INFO(
				tvb, offset, pinfo, tree, drep);
		break;
	case 4:
		offset = dissect_ndr_counted_string(tvb, offset, pinfo, 
			tree, drep, hf_lsa_acct, 0);
		break;
	case 5:
		offset = lsa_dissect_POLICY_ACCOUNT_DOMAIN_INFO(
				tvb, offset, pinfo, tree, drep);
		break;
	case 6:
		offset = lsa_dissect_POLICY_SERVER_ROLE_INFO(
				tvb, offset, pinfo, tree, drep);
		break;
	case 7:
		offset = lsa_dissect_POLICY_REPLICA_SOURCE_INFO(
				tvb, offset, pinfo, tree, drep);
		break;
	case 8:
		offset = lsa_dissect_POLICY_DEFAULT_QUOTA_INFO(
				tvb, offset, pinfo, tree, drep);
		break;
	case 9:
		offset = lsa_dissect_POLICY_MODIFICATION_INFO(
				tvb, offset, pinfo, tree, drep);
		break;
	case 10:
		offset = lsa_dissect_POLICY_AUDIT_FULL_SET_INFO(
				tvb, offset, pinfo, tree, drep);
		break;
	case 11:
		offset = lsa_dissect_POLICY_AUDIT_FULL_QUERY_INFO(
				tvb, offset, pinfo, tree, drep);
		break;
	case 12:
		offset = lsa_dissect_POLICY_DNS_DOMAIN_INFO(
				tvb, offset, pinfo, tree, drep);
		break;
	}

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
lsa_dissect_lsaqueryinformationpolicy_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* This is really a pointer to a pointer though the first level is REF
	  so we just ignore that one */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_POLICY_INFORMATION, NDR_POINTER_UNIQUE,
		"POLICY_INFORMATION pointer: info", -1);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsadelete_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_HANDLE, NDR_POINTER_REF,
		"LSA_HANDLE", -1);

	return offset;
}

static int
lsa_dissect_lsadelete_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}


static int
lsa_dissect_lsaquerysecurityobject_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_info_type, NULL);

	return offset;
}


static int
lsa_dissect_lsaquerysecurityobject_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_SECURITY_DESCRIPTOR, NDR_POINTER_UNIQUE,
		"LSA_SECURITY_DESCRIPTOR pointer: sec_info", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}


static int
lsa_dissect_lsasetsecurityobject_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_info_type, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_SECURITY_DESCRIPTOR, NDR_POINTER_REF,
		"LSA_SECURITY_DESCRIPTOR: sec_info", -1);

	return offset;
}

static int
lsa_dissect_lsasetsecurityobject_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}


static int
lsa_dissect_lsachangepassword_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* server */
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_lsa_server, 0);

	/* domain */
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_lsa_domain, 0);

	/* account */
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_lsa_acct, 0);

	/* old password */
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_lsa_old_pwd, 0);

	/* new password */
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_lsa_new_pwd, 0);

	return offset;
}

static int
lsa_dissect_lsachangepassword_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static const value_string sid_type_vals[] = {
	{1,	"User"},
	{2,	"Group"},
	{3,	"Domain"},
	{4,	"Alias"},
	{5,	"Well Known Group"},
	{6,	"Deleted Account"},
	{7,	"Invalid"},
	{8,	"Unknown"},
	{9,	"Computer"},
	{0, NULL}
};
static int
lsa_dissect_LSA_TRANSLATED_NAME(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"LSA_TRANSLATED_NAME:");
		tree = proto_item_add_subtree(item, ett_lsa_translated_name);
	}

	/* sid type */
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
			hf_lsa_sid_type, NULL);

	/* name */
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_lsa_name, 0);

	/* index */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_index, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
lsa_dissect_LSA_TRANSLATED_NAME_array(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_TRANSLATED_NAME);

	return offset;
}

static int
lsa_dissect_LSA_TRANSLATED_NAMES(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"LSA_TRANSLATED_NAMES:");
		tree = proto_item_add_subtree(item, ett_lsa_translated_names);
	}

	/* count */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_count, NULL);

	/* settings */
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_TRANSLATED_NAME_array, NDR_POINTER_UNIQUE,
		"TRANSLATED_NAME_ARRAY", -1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
lsa_dissect_lsalookupsids_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_PSID_ARRAY, NDR_POINTER_REF,
			"PSID_ARRAY", -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_TRANSLATED_NAMES, NDR_POINTER_REF,
		"LSA_TRANSLATED_NAMES pointer: names", -1);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_lsa_info_level, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_num_mapped, NULL);

	return offset;
}

static int
lsa_dissect_LSA_TRUST_INFORMATION(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"TRUST INFORMATION:");
		tree = proto_item_add_subtree(item, ett_lsa_trust_information);
	}

	/* name */
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_lsa_name, 0);

	/* sid */
	offset = dissect_ndr_nt_PSID(tvb, offset,
		pinfo, tree, drep);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static const value_string trusted_direction_vals[] = {
	{0,	"Trust disabled"},
	{1,	"Inbound trust"},
	{2,	"Outbound trust"},
	{0,	NULL}
};

static const value_string trusted_type_vals[] = {
	{1,	"Downlevel"},
	{2,	"Uplevel"},
	{3,	"MIT"},
	{4,	"DCE"},
	{0,	NULL}
};

static const true_false_string tfs_trust_attr_non_trans = {
	"NON TRANSITIVE is set",
	"Non transitive is NOT set"
};
static const true_false_string tfs_trust_attr_uplevel_only = {
	"UPLEVEL ONLY is set",
	"Uplevel only is NOT set"
};
static const true_false_string tfs_trust_attr_tree_parent = {
	"TREE PARENT is set",
	"Tree parent is NOT set"
};
static const true_false_string tfs_trust_attr_tree_root = {
	"TREE ROOT is set",
	"Tree root is NOT set"
};
static int
lsa_dissect_trust_attr(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *parent_tree, char *drep)
{
	guint32 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	offset=dissect_ndr_uint32(tvb, offset, pinfo, NULL, drep,
			hf_lsa_trust_attr, &mask);

	if(parent_tree){
		item = proto_tree_add_uint(parent_tree, hf_lsa_trust_attr,
			tvb, offset-4, 4, mask);
		tree = proto_item_add_subtree(item, ett_lsa_trust_attr);
	}

	proto_tree_add_boolean(tree, hf_lsa_trust_attr_tree_root,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_lsa_trust_attr_tree_parent,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_lsa_trust_attr_uplevel_only,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_lsa_trust_attr_non_trans,
		tvb, offset-4, 4, mask);

	return offset;
}

static int
lsa_dissect_LSA_TRUST_INFORMATION_EX(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"TRUST INFORMATION EX:");
		tree = proto_item_add_subtree(item, ett_lsa_trust_information_ex);
	}

	/* name */
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_lsa_name, 0);

	/* flat name */
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_lsa_flat_name, 0);

	/* sid */
	offset = dissect_ndr_nt_PSID(tvb, offset,
		pinfo, tree, drep);

	/* direction */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_trust_direction, NULL);

	/* type */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_trust_type, NULL);

	/* attributes */
	offset = lsa_dissect_trust_attr(tvb, offset, pinfo, tree, drep);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
lsa_dissect_auth_info_blob(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	dcerpc_info *di;
	guint32 len;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	/* len */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_auth_len, &len);

	proto_tree_add_item(tree, hf_lsa_auth_blob, tvb, offset, len, FALSE);
	offset += len;

	return offset;
}

static int
lsa_dissect_auth_info(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"AUTH INFORMATION:");
		tree = proto_item_add_subtree(item, ett_lsa_auth_information);
	}

	/* update */
        offset = dissect_ndr_uint64 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_auth_update, NULL);

	/* type */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_auth_type, NULL);

	/* len */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_auth_len, NULL);

	/* auth info blob */
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			lsa_dissect_auth_info_blob, NDR_POINTER_UNIQUE,
			"AUTH INFO blob:", -1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
lsa_dissect_LSA_TRUSTED_DOMAIN_AUTH_INFORMATION(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"TRUSTED DOMAIN AUTH INFORMATION:");
		tree = proto_item_add_subtree(item, ett_lsa_trusted_domain_auth_information);
	}

	/* unknown */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_unknown_long, NULL);

	/* unknown */
	offset = lsa_dissect_auth_info(tvb, offset, pinfo, tree, drep);

	/* unknown */
	offset = lsa_dissect_auth_info(tvb, offset, pinfo, tree, drep);

	/* unknown */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_unknown_long, NULL);

	/* unknown */
	offset = lsa_dissect_auth_info(tvb, offset, pinfo, tree, drep);

	/* unknown */
	offset = lsa_dissect_auth_info(tvb, offset, pinfo, tree, drep);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
lsa_dissect_LSA_TRUST_INFORMATION_array(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_TRUST_INFORMATION);

	return offset;
}

static int
lsa_dissect_LSA_REFERENCED_DOMAIN_LIST(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"LSA_REFERENCED_DOMAIN_LIST:");
		tree = proto_item_add_subtree(item, ett_lsa_referenced_domain_list);
	}

	/* count */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_count, NULL);

	/* trust information */
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_TRUST_INFORMATION_array, NDR_POINTER_UNIQUE,
		"TRUST INFORMATION array:", -1);

	/* max count */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_max_count, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
lsa_dissect_lsalookupsids_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_REFERENCED_DOMAIN_LIST, NDR_POINTER_UNIQUE,
		"LSA_REFERENCED_DOMAIN_LIST pointer: domains", -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_TRANSLATED_NAMES, NDR_POINTER_REF,
		"LSA_TRANSLATED_NAMES pointer: names", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_num_mapped, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}


static int
lsa_dissect_lsasetquotasforaccount_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_POLICY_DEFAULT_QUOTA_INFO, NDR_POINTER_REF,
		"POLICY_DEFAULT_QUOTA_INFO pointer: quotas", -1);

	return offset;
}


static int
lsa_dissect_lsasetquotasforaccount_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}


static int
lsa_dissect_lsagetquotasforaccount_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	return offset;
}


static int
lsa_dissect_lsagetquotasforaccount_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_POLICY_DEFAULT_QUOTA_INFO, NDR_POINTER_REF,
		"POLICY_DEFAULT_QUOTA_INFO pointer: quotas", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}


static int
lsa_dissect_lsasetinformationpolicy_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_lsa_policy_information_class, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_POLICY_INFORMATION, NDR_POINTER_REF,
		"POLICY_INFORMATION pointer: info", -1);

	return offset;
}


static int
lsa_dissect_lsasetinformationpolicy_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}


static int
lsa_dissect_lsaclearauditlog_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_nt_SID(tvb, offset,
		pinfo, tree, drep);

	/* unknown */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_unknown_long, NULL);

	return offset;
}


static int
lsa_dissect_lsaclearauditlog_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsagetsystemaccessaccount_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	return offset;
}


static int
lsa_dissect_lsagetsystemaccessaccount_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_rid, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}


static int
lsa_dissect_lsasetsystemaccessaccount_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rid, NULL);

	return offset;
}


static int
lsa_dissect_lsasetsystemaccessaccount_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}


static int
lsa_dissect_lsaopentrusteddomain_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_nt_SID(tvb, offset,
		pinfo, tree, drep);

	offset = lsa_dissect_ACCESS_MASK(tvb, offset,
		pinfo, tree, drep);

	return offset;
}


static int
lsa_dissect_lsaopentrusteddomain_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}


static int
lsa_dissect_lsadeletetrusteddomain_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_nt_SID(tvb, offset,
		pinfo, tree, drep);

	return offset;
}


static int
lsa_dissect_lsadeletetrusteddomain_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

int
dissect_nt_LUID(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"LUID:");
		tree = proto_item_add_subtree(item, ett_LUID);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_nt_luid_low, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_nt_luid_high, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
lsa_dissect_LSA_PRIVILEGE(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"LSA_PRIVILEGE:");
		tree = proto_item_add_subtree(item, ett_LSA_PRIVILEGE);
	}

	/* privilege name */
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
			hf_lsa_privilege_name, 0);

	/* LUID */
	offset = dissect_nt_LUID(tvb, offset, pinfo, tree, drep);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
lsa_dissect_LSA_PRIVILEGE_array(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_PRIVILEGE);

	return offset;
}

static int
lsa_dissect_LSA_PRIVILEGES(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"LSA_PRIVILEGES:");
		tree = proto_item_add_subtree(item, ett_LSA_PRIVILEGES);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_count, NULL);

	/* privileges */
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_PRIVILEGE_array, NDR_POINTER_UNIQUE,
		"LSA_PRIVILEGE array:", -1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
lsa_dissect_lsaenumerateprivileges_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_count, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_size, NULL);

	return offset;
}

static int
lsa_dissect_lsaenumerateprivileges_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_count, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_PRIVILEGES, NDR_POINTER_REF,
		"LSA_PRIVILEGES pointer: privs", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsalookupprivilegevalue_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* privilege name */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_pointer_UNICODE_STRING, NDR_POINTER_UNIQUE,
		"NAME pointer: ", hf_lsa_privilege_name);

	return offset;
}


static int
lsa_dissect_lsalookupprivilegevalue_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{

	/* LUID */
	offset = dissect_nt_LUID(tvb, offset, pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}


static int
lsa_dissect_lsalookupprivilegename_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* LUID */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_nt_LUID, NDR_POINTER_REF,
		"LUID pointer: value", -1);

	return offset;
}


static int
lsa_dissect_lsalookupprivilegename_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [out, ref] LSA_UNICODE_STRING **name */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_pointer_UNICODE_STRING, NDR_POINTER_UNIQUE,
		"PRIVILEGE NAME pointer:", hf_lsa_privilege_name);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}


static int
lsa_dissect_lsaenumerateprivilegesaccount_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE hnd */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	return offset;
}


static int
lsa_dissect_LUID_AND_ATTRIBUTES(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"LUID_AND_ATTRIBUTES:");
		tree = proto_item_add_subtree(item, ett_LSA_LUID_AND_ATTRIBUTES);
	}

	/* LUID */
	offset = dissect_nt_LUID(tvb, offset, pinfo, tree, drep);

	/* attr */
        offset = dissect_ndr_uint64 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_attr, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
lsa_dissect_LUID_AND_ATTRIBUTES_array(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LUID_AND_ATTRIBUTES);

	return offset;
}

static int
lsa_dissect_LUID_AND_ATTRIBUTES_ARRAY(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"LUID_AND_ATTRIBUTES_ARRAY:");
		tree = proto_item_add_subtree(item, ett_LSA_LUID_AND_ATTRIBUTES_ARRAY);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_count, NULL);

	/* luid and attributes */
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LUID_AND_ATTRIBUTES_array, NDR_POINTER_UNIQUE,
		"LUID_AND_ATTRIBUTES array:", -1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
lsa_dissect_lsaenumerateprivilegesaccount_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [out, ref] LUID_AND_ATTRIBUTES_ARRAY * *privs */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LUID_AND_ATTRIBUTES_ARRAY, NDR_POINTER_UNIQUE,
		"LUID_AND_ATTRIBUTES_ARRAY pointer: privs", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsaaddprivilegestoaccount_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE hnd */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* [in, ref] LUID_AND_ATTRIBUTES_ARRAY *privs */
	offset = lsa_dissect_LUID_AND_ATTRIBUTES_ARRAY(tvb, offset,
		pinfo, tree, drep);

	return offset;
}


static int
lsa_dissect_lsaaddprivilegestoaccount_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsaremoveprivilegesfromaccount_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE hnd */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* [in] char unknown */
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
			hf_lsa_unknown_char, NULL);

	/* [in, unique] LUID_AND_ATTRIBUTES_ARRAY *privs */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LUID_AND_ATTRIBUTES_ARRAY, NDR_POINTER_UNIQUE,
		"LUID_AND_ATTRIBUTES_ARRAY pointer: privs", -1);

	return offset;
}


static int
lsa_dissect_lsaremoveprivilegesfromaccount_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsaenumerateaccounts_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE hnd */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* [in,out, ref] LSA_ENUMERATION_HANDLE *resume_hnd */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_resume_handle, NULL);

	/* [in] ULONG pref_maxlen */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_max_count, NULL);

	return offset;
}

static int
lsa_dissect_lsaenumerateaccounts_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in,out, ref] LSA_ENUMERATION_HANDLE *resume_hnd */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_resume_handle, NULL);

	/* [out, ref] PSID_ARRAY **accounts */
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_PSID_ARRAY, NDR_POINTER_REF,
			"PSID_ARRAY", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsacreatetrusteddomain_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE hnd_pol */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* [in, ref] LSA_TRUST_INFORMATION *domain */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_TRUST_INFORMATION, NDR_POINTER_REF,
		"LSA_TRUST_INFORMATION pointer: domain", -1);

	/* [in] ACCESS_MASK access */
	offset = lsa_dissect_ACCESS_MASK(tvb, offset,
		pinfo, tree, drep);

	return offset;
}

static int
lsa_dissect_lsacreatetrusteddomain_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [out] LSA_HANDLE *hnd */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsaenumeratetrusteddomains_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE hnd */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* [in, out, ref] LSA_ENUMERATION_HANDLE *resume_hnd */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_resume_handle, NULL);

	/* [in] ULONG pref_maxlen */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_max_count, NULL);

	return offset;
}

static int
lsa_dissect_LSA_TRUSTED_DOMAIN(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"TRUSTED_DOMAIN:");
		tree = proto_item_add_subtree(item, ett_LSA_TRUSTED_DOMAIN);
	}

	/* domain */
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_lsa_domain, 0);

	/* sid */
	offset = dissect_ndr_nt_PSID(tvb, offset,
		pinfo, tree, drep);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
lsa_dissect_LSA_TRUSTED_DOMAIN_array(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_TRUSTED_DOMAIN);

	return offset;
}

static int
lsa_dissect_LSA_TRUSTED_DOMAIN_LIST(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"TRUSTED_DOMAIN_LIST:");
		tree = proto_item_add_subtree(item, ett_LSA_TRUSTED_DOMAIN_LIST);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_count, NULL);

	/* privileges */
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_TRUSTED_DOMAIN_array, NDR_POINTER_UNIQUE,
		"TRUSTED_DOMAIN array:", -1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
lsa_dissect_lsaenumeratetrusteddomains_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in, out, ref] LSA_ENUMERATION_HANDLE *resume_hnd */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_resume_handle, NULL);

	/* [out, ref] LSA_REFERENCED_DOMAIN_LIST *domains */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_TRUSTED_DOMAIN_LIST, NDR_POINTER_REF,
		"LSA_TRUSTED_DOMAIN_LIST pointer: domains", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}


static int
lsa_dissect_LSA_UNICODE_STRING_item(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
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
lsa_dissect_LSA_UNICODE_STRING_array(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_UNICODE_STRING_item);

	return offset;
}

static int
lsa_dissect_LSA_UNICODE_STRING_ARRAY(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	dcerpc_info *di;

	di=pinfo->private_data;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_count, NULL);
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_UNICODE_STRING_array, NDR_POINTER_UNIQUE,
		"UNICODE_STRING pointer: ", di->hf_index);

	return offset;
}

static int
lsa_dissect_LSA_TRANSLATED_SID(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* sid type */
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
			hf_lsa_sid_type, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_rid, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_index, NULL);

	return offset;
}

static int
lsa_dissect_LSA_TRANSLATED_SIDS_array(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_TRANSLATED_SID);

	return offset;
}

static int
lsa_dissect_LSA_TRANSLATED_SIDS(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"LSA_TRANSLATED_SIDS:");
		tree = proto_item_add_subtree(item, ett_LSA_TRANSLATED_SIDS);
	}

	/* count */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_count, NULL);

	/* settings */
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_TRANSLATED_SIDS_array, NDR_POINTER_UNIQUE,
		"Translated SIDS", -1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
lsa_dissect_lsalookupnames_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE hnd */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* [in] ULONG count */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_count, NULL);

	/* [in, size_is(count), ref] LSA_UNICODE_STRING *names */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_UNICODE_STRING_array, NDR_POINTER_REF,
		"Account pointer: names", hf_lsa_acct);

	/* [in, out, ref] LSA_TRANSLATED_SIDS *rids */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_TRANSLATED_SIDS, NDR_POINTER_REF,
		"LSA_TRANSLATED_SIDS pointer: rids", -1);

	/* [in] USHORT level */
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_lsa_info_level, NULL);

	/* [in, out, ref] ULONG *num_mapped */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_num_mapped, NULL);

	return offset;
}


static int
lsa_dissect_lsalookupnames_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [out] LSA_REFERENCED_DOMAIN_LIST *domains */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_REFERENCED_DOMAIN_LIST, NDR_POINTER_UNIQUE,
		"LSA_REFERENCED_DOMAIN_LIST pointer: domains", -1);

	/* [in, out, ref] LSA_TRANSLATED_SIDS *rids */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_TRANSLATED_SIDS, NDR_POINTER_REF,
		"LSA_TRANSLATED_SIDS pointer: rids", -1);

	/* [in, out, ref] ULONG *num_mapped */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_num_mapped, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsacreatesecret_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE hnd_pol */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* [in, ref] LSA_UNICODE_STRING *name */
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_lsa_name, 0);

	/* [in] ACCESS_MASK access */
	offset = lsa_dissect_ACCESS_MASK(tvb, offset,
		pinfo, tree, drep);

	return offset;
}

static int
lsa_dissect_lsacreatesecret_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{

	/* [out] LSA_HANDLE *hnd */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsaopenaccount_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE hnd_pol */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* [in, ref] SID *account */
	offset = dissect_ndr_nt_SID(tvb, offset,
		pinfo, tree, drep);

	/* [in] ACCESS_MASK access */
	offset = lsa_dissect_ACCESS_MASK(tvb, offset,
		pinfo, tree, drep);

	return offset;
}


static int
lsa_dissect_lsaopenaccount_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [out] LSA_HANDLE *hnd */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static const value_string trusted_info_level_vals[] = {
	{1,	"Domain Name Information"},
	{2,	"Controllers Information"},
	{3,	"Posix Offset Information"},
	{4,	"Password Information"},
	{5,	"Domain Information Basic"},
	{6,	"Domain Information Ex"},
	{7,	"Domain Auth Information"},
	{8,	"Domain Full Information"},
	{9,	"Domain Security Descriptor"},
	{10,	"Domain Private Information"},
	{0,	NULL}
};

static int
lsa_dissect_TRUSTED_DOMAIN_INFORMATION(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;
	guint16 level;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"TRUSTED_DOMAIN_INFO:");
		tree = proto_item_add_subtree(item, ett_lsa_trusted_domain_info);
	}

        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_trusted_info_level, &level);

	ALIGN_TO_4_BYTES;  /* all union arms aligned to 4 bytes, case 7 and 9 need this  */
	switch(level){
	case 1:
		offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
			hf_lsa_domain, 0);
		break;
	case 2:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_lsa_count, NULL);
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			lsa_dissect_LSA_UNICODE_STRING_array, NDR_POINTER_UNIQUE,
			"Controllers pointer: ", hf_lsa_controller);
		break;
	case 3:
	        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_lsa_rid_offset, NULL);
		break;
	case 4:
		offset = lsa_dissect_LSA_SECRET(tvb, offset, pinfo, tree, drep);
		offset = lsa_dissect_LSA_SECRET(tvb, offset, pinfo, tree, drep);
		break;
	case 5:
		offset = lsa_dissect_LSA_TRUST_INFORMATION(tvb, offset,
			pinfo, tree, drep);
		break;
	case 6:
		offset = lsa_dissect_LSA_TRUST_INFORMATION_EX(tvb, offset,
			pinfo, tree, drep);
		break;
	case 7:
		offset = lsa_dissect_LSA_TRUSTED_DOMAIN_AUTH_INFORMATION(tvb, offset, pinfo, tree, drep);
		break;
	case 8:
		offset = lsa_dissect_LSA_TRUST_INFORMATION_EX(tvb, offset,
			pinfo, tree, drep);
	        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_lsa_rid_offset, NULL);
		offset = lsa_dissect_LSA_TRUSTED_DOMAIN_AUTH_INFORMATION(tvb, offset, pinfo, tree, drep);
		break;
	case 9:
		offset = lsa_dissect_LSA_SECURITY_DESCRIPTOR(tvb, offset, pinfo, tree, drep);
		break;
	case 10:
		offset = lsa_dissect_LSA_TRUST_INFORMATION_EX(tvb, offset,
			pinfo, tree, drep);
	        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_lsa_rid_offset, NULL);
		offset = lsa_dissect_LSA_SECURITY_DESCRIPTOR(tvb, offset, pinfo, tree, drep);
		break;
	}

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
lsa_dissect_lsaqueryinfotrusteddomain_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE hnd */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* [in] TRUSTED_INFORMATION_CLASS level */
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_lsa_trusted_info_level, NULL);

	return offset;
}


static int
lsa_dissect_lsaqueryinfotrusteddomain_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [out, ref] TRUSTED_DOMAIN_INFORMATION *info */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_TRUSTED_DOMAIN_INFORMATION, NDR_POINTER_REF,
		"TRUSTED_DOMAIN_INFORMATION pointer: info", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsasetinformationtrusteddomain_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE hnd */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* [in] TRUSTED_INFORMATION_CLASS level */
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_lsa_trusted_info_level, NULL);

	/* [in, ref] TRUSTED_DOMAIN_INFORMATION *info */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_TRUSTED_DOMAIN_INFORMATION, NDR_POINTER_REF,
		"TRUSTED_DOMAIN_INFORMATION pointer: info", -1);

	return offset;
}


static int
lsa_dissect_lsasetinformationtrusteddomain_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsaopensecret_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE hnd_pol */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* [in, ref] LSA_UNICODE_STRING *name */
	offset = dissect_ndr_counted_string_cb(
		tvb, offset, pinfo, tree, drep, hf_lsa_name,
		cb_str_postprocess, 
		GINT_TO_POINTER(CB_STR_COL_INFO | 1));

	/* [in] ACCESS_MASK access */
	offset = lsa_dissect_ACCESS_MASK(tvb, offset,
		pinfo, tree, drep);

	return offset;
}


static int
lsa_dissect_lsaopensecret_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [out] LSA_HANDLE *hnd */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsasetsecret_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE hnd */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* [in, unique] LSA_SECRET *new_val */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_SECRET, NDR_POINTER_UNIQUE,
		"LSA_SECRET pointer: new_val", -1);

	/* [in, unique] LSA_SECRET *old_val */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_SECRET, NDR_POINTER_UNIQUE,
		"LSA_SECRET pointer: old_val", -1);

	return offset;
}


static int
lsa_dissect_lsasetsecret_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsaquerysecret_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE hnd */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* [in, out, unique] LSA_SECRET **curr_val */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_SECRET, NDR_POINTER_UNIQUE,
		"LSA_SECRET pointer: curr_val", -1);

	/* [in, out, unique] LARGE_INTEGER *curr_mtime */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_pointer_NTTIME, NDR_POINTER_UNIQUE,
		"NTIME pointer: old_mtime", hf_lsa_cur_mtime);

	/* [in, out, unique] LSA_SECRET **old_val */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_SECRET, NDR_POINTER_UNIQUE,
		"LSA_SECRET pointer: old_val", -1);

	/* [in, out, unique] LARGE_INTEGER *old_mtime */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_pointer_NTTIME, NDR_POINTER_UNIQUE,
		"NTIME pointer: old_mtime", hf_lsa_old_mtime);

	return offset;
}


static int
lsa_dissect_lsaquerysecret_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in, out, unique] LSA_SECRET **curr_val */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_SECRET, NDR_POINTER_UNIQUE,
		"LSA_SECRET pointer: curr_val", -1);

	/* [in, out, unique] LARGE_INTEGER *curr_mtime */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_pointer_NTTIME, NDR_POINTER_UNIQUE,
		"NTIME pointer: old_mtime", hf_lsa_cur_mtime);

	/* [in, out, unique] LSA_SECRET **old_val */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_SECRET, NDR_POINTER_UNIQUE,
		"LSA_SECRET pointer: old_val", -1);

	/* [in, out, unique] LARGE_INTEGER *old_mtime */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_pointer_NTTIME, NDR_POINTER_UNIQUE,
		"NTIME pointer: old_mtime", hf_lsa_old_mtime);

	return offset;
}

static int
lsa_dissect_lsadeleteobject_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE hnd */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	return offset;
}


static int
lsa_dissect_lsadeleteobject_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsaenumerateaccountswithuserright_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE hnd */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* [in, unique] LSA_UNICODE_STRING *rights */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_pointer_UNICODE_STRING, NDR_POINTER_UNIQUE,
		"LSA_UNICODE_STRING pointer: rights", hf_lsa_rights);

	return offset;
}

static int
lsa_dissect_lsaenumerateaccountswithuserright_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [out, ref] LSA_UNICODE_STRING_ARRAY *accounts */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_UNICODE_STRING_ARRAY, NDR_POINTER_REF,
		"Account pointer: names", hf_lsa_acct);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsaenumerateaccountrights_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE hnd */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* [in, ref] SID *account */
	offset = dissect_ndr_nt_SID(tvb, offset,
		pinfo, tree, drep);

	return offset;
}


static int
lsa_dissect_lsaenumerateaccountrights_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [out, ref] LSA_UNICODE_STRING_ARRAY *rights */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_UNICODE_STRING_ARRAY, NDR_POINTER_REF,
		"Account pointer: rights", hf_lsa_rights);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsaaddaccountrights_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE hnd */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* [in, ref] SID *account */
	offset = dissect_ndr_nt_SID(tvb, offset,
		pinfo, tree, drep);

	/* [in, ref] LSA_UNICODE_STRING_ARRAY *rights */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_UNICODE_STRING_ARRAY, NDR_POINTER_REF,
		"Account pointer: rights", hf_lsa_rights);

	return offset;
}


static int
lsa_dissect_lsaaddaccountrights_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsaremoveaccountrights_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE hnd */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* [in, ref] SID *account */
	offset = dissect_ndr_nt_SID(tvb, offset,
		pinfo, tree, drep);

	/* remove all */
	offset = dissect_ndr_uint8 (tvb, offset, pinfo, tree, drep,
			hf_lsa_remove_all, NULL);

	/* [in, ref] LSA_UNICODE_STRING_ARRAY *rights */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_UNICODE_STRING_ARRAY, NDR_POINTER_REF,
		"Account pointer: rights", hf_lsa_rights);

	return offset;
}


static int
lsa_dissect_lsaremoveaccountrights_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}


static int
lsa_dissect_lsaquerytrusteddomaininfobyname_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE handle */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* [in, ref] LSA_UNICODE_STRING *name */
	/* domain */
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_lsa_domain, 0);

	/* [in] TRUSTED_INFORMATION_CLASS level */
        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_trusted_info_level, NULL);

	return offset;
}


static int
lsa_dissect_lsaquerytrusteddomaininfobyname_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [out, ref] TRUSTED_DOMAIN_INFORMATION *info) */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_TRUSTED_DOMAIN_INFORMATION, NDR_POINTER_REF,
		"TRUSTED_DOMAIN_INFORMATION pointer: info", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}


static int
lsa_dissect_lsasettrusteddomaininfobyname_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE handle */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* [in, ref] LSA_UNICODE_STRING *name */
	/* domain */
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_lsa_domain, 0);

	/* [in] TRUSTED_INFORMATION_CLASS level */
        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_trusted_info_level, NULL);

	/* [in, ref] TRUSTED_DOMAIN_INFORMATION *info) */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_TRUSTED_DOMAIN_INFORMATION, NDR_POINTER_REF,
		"TRUSTED_DOMAIN_INFORMATION pointer: info", -1);

	return offset;
}


static int
lsa_dissect_lsasettrusteddomaininfobyname_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsaquerytrusteddomaininfo_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE handle */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* [in, ref] SID *sid */
	offset = dissect_ndr_nt_SID(tvb, offset,
		pinfo, tree, drep);

	/* [in] TRUSTED_INFORMATION_CLASS level */
        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_trusted_info_level, NULL);

	return offset;
}

static int
lsa_dissect_lsaopentrusteddomainbyname_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE handle */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* [in, ref] LSA_UNICODE_STRING *name */
	/* domain */
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_lsa_domain, 0);

	/* [in] ACCESS_MASK access */
	offset = lsa_dissect_ACCESS_MASK(tvb, offset,
		pinfo, tree, drep);

	return offset;
}


static int
lsa_dissect_lsaopentrusteddomainbyname_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [out] LSA_HANDLE handle */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}



static int
lsa_dissect_lsaquerytrusteddomaininfo_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [out, ref] TRUSTED_DOMAIN_INFORMATION *info) */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_TRUSTED_DOMAIN_INFORMATION, NDR_POINTER_REF,
		"TRUSTED_DOMAIN_INFORMATION pointer: info", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsasettrusteddomaininfo_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE handle */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* [in, ref] SID *sid */
	offset = dissect_ndr_nt_SID(tvb, offset,
		pinfo, tree, drep);

	/* [in] TRUSTED_INFORMATION_CLASS level */
        offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_trusted_info_level, NULL);

	/* [ref, ref] TRUSTED_DOMAIN_INFORMATION *info) */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_TRUSTED_DOMAIN_INFORMATION, NDR_POINTER_REF,
		"TRUSTED_DOMAIN_INFORMATION pointer: info", -1);

	return offset;
}


static int
lsa_dissect_lsasettrusteddomaininfo_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsaqueryinformationpolicy2_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_HANDLE, NDR_POINTER_REF,
		"LSA_HANDLE", -1);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_lsa_policy_information_class, NULL);

	return offset;
}

static int
lsa_dissect_lsaqueryinformationpolicy2_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* This is really a pointer to a pointer though the first level is REF
	  so we just ignore that one */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_POLICY_INFORMATION, NDR_POINTER_UNIQUE,
		"POLICY_INFORMATION pointer: info", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsasetinformationpolicy2_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_HANDLE, NDR_POINTER_REF,
		"LSA_HANDLE", -1);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_lsa_policy_information_class, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_POLICY_INFORMATION, NDR_POINTER_REF,
		"POLICY_INFORMATION pointer: info", -1);

	return offset;
}

static int
lsa_dissect_lsasetinformationpolicy2_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsaquerydomaininformationpolicy_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_HANDLE, NDR_POINTER_REF,
		"LSA_HANDLE", -1);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_lsa_policy_information_class, NULL);

	return offset;
}

static int
lsa_dissect_lsaquerydomaininformationpolicy_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_POLICY_INFORMATION, NDR_POINTER_REF,
		"POLICY_INFORMATION pointer: info", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsasetdomaininformationpolicy_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_HANDLE, NDR_POINTER_REF,
		"LSA_HANDLE", -1);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_lsa_policy_information_class, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_POLICY_INFORMATION, NDR_POINTER_REF,
		"POLICY_INFORMATION pointer: info", -1);

	return offset;
}

static int
lsa_dissect_lsasetdomaininformationpolicy_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsalookupnames2_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE hnd */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* [in] ULONG count */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_count, NULL);

	/* [in, size_is(count), ref] LSA_UNICODE_STRING *names */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_UNICODE_STRING_array, NDR_POINTER_REF,
		"Account pointer: names", hf_lsa_acct);

	/* [in, out, ref] LSA_TRANSLATED_SIDS *rids */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_TRANSLATED_SIDS, NDR_POINTER_REF,
		"LSA_TRANSLATED_SIDS pointer: rids", -1);

	/* [in] USHORT level */
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_lsa_info_level, NULL);

	/* [in, out, ref] ULONG *num_mapped */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_num_mapped, NULL);

	/* unknown */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_unknown_long, NULL);

	/* unknown */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_unknown_long, NULL);

	return offset;
}


static int
lsa_dissect_lsalookupnames2_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [out] LSA_REFERENCED_DOMAIN_LIST *domains */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_REFERENCED_DOMAIN_LIST, NDR_POINTER_UNIQUE,
		"LSA_REFERENCED_DOMAIN_LIST pointer: domains", -1);

	/* [in, out, ref] LSA_TRANSLATED_SIDS *rids */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_TRANSLATED_SIDS, NDR_POINTER_REF,
		"LSA_TRANSLATED_SIDS pointer: rids", -1);

	/* [in, out, ref] ULONG *num_mapped */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_num_mapped, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}


static int
lsa_dissect_lsacreateaccount_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE hnd */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_nt_SID(tvb, offset,
		pinfo, tree, drep);

	offset = lsa_dissect_ACCESS_MASK(tvb, offset,
		pinfo, tree, drep);

	return offset;
}

static int
lsa_dissect_lsacreateaccount_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsalookupprivilegedisplayname_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE hnd */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* [in, ref] LSA_UNICODE_STRING *name */
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_lsa_name, 0);

	/* [in] USHORT unknown */
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_lsa_unknown_short, NULL);

	/* [in] USHORT size */
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_lsa_size16, NULL);

	return offset;
}


static int
lsa_dissect_lsalookupprivilegedisplayname_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [out, ref] LSA_UNICODE_STRING **disp_name */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_pointer_UNICODE_STRING, NDR_POINTER_UNIQUE,
		"NAME pointer: ", hf_lsa_privilege_name);

	/* [out, ref] USHORT *size_needed */
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_lsa_size_needed, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsastoreprivatedata_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE hnd */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* [in, ref] LSA_UNICODE_STRING *key */
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_lsa_key, 0);

	/* [in, unique] LSA_SECRET **data */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_SECRET_pointer, NDR_POINTER_UNIQUE,
		"LSA_SECRET* pointer: data", -1);

	return offset;
}


static int
lsa_dissect_lsastoreprivatedata_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsaretrieveprivatedata_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE hnd */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* [in, ref] LSA_UNICODE_STRING *key */
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_lsa_key, 0);

	/* [in, out, ref] LSA_SECRET **data */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_SECRET_pointer, NDR_POINTER_REF,
		"LSA_SECRET* pointer: data", -1);

	return offset;
}


static int
lsa_dissect_lsaretrieveprivatedata_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in, out, ref] LSA_SECRET **data */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_SECRET_pointer, NDR_POINTER_REF,
		"LSA_SECRET* pointer: data", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsaclosetrusteddomainex_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{

	/* [in, out] LSA_HANDLE *tdHnd */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_HANDLE, NDR_POINTER_REF,
		"LSA_HANDLE", -1);

	return offset;
}


static int
lsa_dissect_lsaclosetrusteddomainex_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{

	/* [in, out] LSA_HANDLE *tdHnd */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_HANDLE, NDR_POINTER_REF,
		"LSA_HANDLE", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_LSA_TRANSLATED_NAME_EX(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"LSA_TRANSLATED_NAME:");
		tree = proto_item_add_subtree(item, ett_lsa_translated_name);
	}

	/* sid type */
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
			hf_lsa_sid_type, NULL);

	/* name */
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_lsa_name, 0);

	/* index */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_index, NULL);

	/* unknown */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_unknown_long, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
lsa_dissect_LSA_TRANSLATED_NAME_EX_array(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_TRANSLATED_NAME_EX);

	return offset;
}
static int
lsa_dissect_LSA_TRANSLATED_NAMES_EX(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* count */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_count, NULL);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			lsa_dissect_LSA_TRANSLATED_NAME_EX_array, NDR_POINTER_UNIQUE,
			"LSA_TRANSLATED_NAME_EX: pointer", -1);

	return offset;
}


static int
lsa_dissect_lsalookupsids2_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_PSID_ARRAY, NDR_POINTER_REF,
			"PSID_ARRAY", -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_TRANSLATED_NAMES_EX, NDR_POINTER_REF,
		"LSA_TRANSLATED_NAMES_EX pointer: names", -1);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_lsa_info_level, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_num_mapped, NULL);

	/* unknown */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_unknown_long, NULL);

	/* unknown */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_unknown_long, NULL);

	return offset;
}

static int
lsa_dissect_lsalookupsids2_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_REFERENCED_DOMAIN_LIST, NDR_POINTER_UNIQUE,
		"LSA_REFERENCED_DOMAIN_LIST pointer: domains", -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_TRANSLATED_NAMES_EX, NDR_POINTER_REF,
		"LSA_TRANSLATED_NAMES_EX pointer: names", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_num_mapped, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsagetusername_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{

	/* [in, unique, string] WCHAR *server */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_lsa_openpolicy_server, NDR_POINTER_UNIQUE,
		"Server:", hf_lsa_server);

	/* [in, out, ref] LSA_UNICODE_STRING **user */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_pointer_UNICODE_STRING, NDR_POINTER_UNIQUE,
		"ACCOUNT pointer: ", hf_lsa_acct);

	/* [in, out, unique] LSA_UNICODE_STRING **domain */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_pointer_pointer_UNICODE_STRING, NDR_POINTER_UNIQUE,
		"DOMAIN pointer: ", hf_lsa_domain);

	return offset;
}


static int
lsa_dissect_lsagetusername_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in, out, ref] LSA_UNICODE_STRING **user */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_pointer_UNICODE_STRING, NDR_POINTER_UNIQUE,
		"ACCOUNT pointer: ", hf_lsa_acct);

	/* [in, out, unique] LSA_UNICODE_STRING **domain */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_pointer_pointer_UNICODE_STRING, NDR_POINTER_UNIQUE,
		"DOMAIN pointer: ", hf_lsa_domain);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsacreatetrusteddomainex_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE hnd */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* [in, ref] TRUSTED_DOMAIN_INFORMATION_EX *info */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_TRUST_INFORMATION_EX, NDR_POINTER_REF,
		"TRUSTED_DOMAIN_INFORMATION_EX pointer: info", -1);

	/* [in, ref] TRUSTED_DOMAIN_AUTH_INFORMATION *auth */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_TRUSTED_DOMAIN_AUTH_INFORMATION, NDR_POINTER_REF,
		"TRUSTED_DOMAIN_AUTH_INFORMATION pointer: auth", -1);

	/* [in] ACCESS_MASK mask */
	offset = lsa_dissect_ACCESS_MASK(tvb, offset,
		pinfo, tree, drep);

	return offset;
}


static int
lsa_dissect_lsacreatetrusteddomainex_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [out] LSA_HANDLE *tdHnd) */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsaenumeratetrusteddomainsex_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE hnd */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* [in, out, ref] LSA_ENUMERATION_HANDLE *resume_hnd */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_resume_handle, NULL);

	/* [in] ULONG pref_maxlen */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_max_count, NULL);

	return offset;
}


static int
lsa_dissect_LSA_TRUSTED_DOMAIN_INFORMATION_EX_array(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_TRUST_INFORMATION_EX);

	return offset;
}

static int
lsa_dissect_LSA_TRUSTED_DOMAIN_INFORMATION_LIST_EX(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* count */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_count, NULL);

	/* trust information */
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_TRUSTED_DOMAIN_INFORMATION_EX_array, NDR_POINTER_UNIQUE,
		"TRUST INFORMATION array:", -1);

	/* max count */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_lsa_max_count, NULL);


	return offset;
}

static int
lsa_dissect_lsaenumeratetrusteddomainsex_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in, out, ref] LSA_ENUMERATION_HANDLE *resume_hnd */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_resume_handle, NULL);

	/* [out, ref] TRUSTED_DOMAIN_INFORMATION_LIST_EX *domains */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_TRUSTED_DOMAIN_INFORMATION_LIST_EX, NDR_POINTER_REF,
		"TRUSTED_DOMAIN_INFORMATION_LIST_EX pointer: domains", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}

static int
lsa_dissect_lsafunction_38_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE handle */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* [in] USHORT flag */
	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_lsa_unknown_short, NULL);

	/* [in, ref] LSA_SECURITY_DESCRIPTOR *sd */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_SECURITY_DESCRIPTOR, NDR_POINTER_REF,
		"LSA_SECURITY_DESCRIPTOR pointer: sd", -1);

	return offset;
}


static int
lsa_dissect_lsafunction_38_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [out, ref] LSA_SECURITY_DESCRIPTOR **psd) */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_SECURITY_DESCRIPTOR, NDR_POINTER_UNIQUE,
		"LSA_SECURITY_DESCRIPTOR pointer: psd)", -1);

	return offset;
}

static int
lsa_dissect_lsafunction_3b_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [in] LSA_HANDLE hnd */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	/* [in, ref] TRUSTED_DOMAIN_INFORMATION_EX *info */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_TRUST_INFORMATION_EX, NDR_POINTER_REF,
		"TRUSTED_DOMAIN_INFORMATION_EX pointer: info", -1);

	/* [in, ref] LSA_SECURITY_DESCRIPTOR *sd */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		lsa_dissect_LSA_SECURITY_DESCRIPTOR, NDR_POINTER_REF,
		"LSA_SECURITY_DESCRIPTOR pointer: sd", -1);

	/* [in] ULONG unknown */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_unknown_long, NULL);

	return offset;
}


static int
lsa_dissect_lsafunction_3b_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* [out] LSA_HANDLE *h2) */
	offset = lsa_dissect_LSA_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_lsa_rc, NULL);

	return offset;
}


static dcerpc_sub_dissector dcerpc_lsa_dissectors[] = {
	{ LSA_LSACLOSE, "Close",
		lsa_dissect_lsaclose_rqst,
		lsa_dissect_lsaclose_reply },
	{ LSA_LSADELETE, "Delete",
		lsa_dissect_lsadelete_rqst,
		lsa_dissect_lsadelete_reply },
	{ LSA_LSAENUMERATEPRIVILEGES, "EnumPrivs",
		lsa_dissect_lsaenumerateprivileges_rqst,
		lsa_dissect_lsaenumerateprivileges_reply },
	{ LSA_LSAQUERYSECURITYOBJECT, "QuerySecObject",
		lsa_dissect_lsaquerysecurityobject_rqst,
		lsa_dissect_lsaquerysecurityobject_reply },
	{ LSA_LSASETSECURITYOBJECT, "SetSecObject",
		lsa_dissect_lsasetsecurityobject_rqst,
		lsa_dissect_lsasetsecurityobject_reply },
	{ LSA_LSACHANGEPASSWORD, "ChangePassword",
		lsa_dissect_lsachangepassword_rqst,
		lsa_dissect_lsachangepassword_reply },
	{ LSA_LSAOPENPOLICY, "OpenPolicy",
		lsa_dissect_lsaopenpolicy_rqst,
		lsa_dissect_lsaopenpolicy_reply },
	{ LSA_LSAQUERYINFORMATIONPOLICY, "QueryInfoPolicy",
		lsa_dissect_lsaqueryinformationpolicy_rqst,
		lsa_dissect_lsaqueryinformationpolicy_reply },
	{ LSA_LSASETINFORMATIONPOLICY, "SetInfoPolicy",
		lsa_dissect_lsasetinformationpolicy_rqst,
		lsa_dissect_lsasetinformationpolicy_reply },
	{ LSA_LSACLEARAUDITLOG, "ClearAuditLog",
		lsa_dissect_lsaclearauditlog_rqst,
		lsa_dissect_lsaclearauditlog_reply },
	{ LSA_LSACREATEACCOUNT, "CreateAccount",
		lsa_dissect_lsacreateaccount_rqst,
		lsa_dissect_lsacreateaccount_reply },
	{ LSA_LSAENUMERATEACCOUNTS, "EnumAccounts",
		lsa_dissect_lsaenumerateaccounts_rqst,
		lsa_dissect_lsaenumerateaccounts_reply },
	{ LSA_LSACREATETRUSTEDDOMAIN, "CreateTrustedDomain",
		lsa_dissect_lsacreatetrusteddomain_rqst,
		lsa_dissect_lsacreatetrusteddomain_reply },
	{ LSA_LSAENUMERATETRUSTEDDOMAINS, "EnumTrustedDomains",
		lsa_dissect_lsaenumeratetrusteddomains_rqst,
		lsa_dissect_lsaenumeratetrusteddomains_reply },
	{ LSA_LSALOOKUPNAMES, "LookupNames",
		lsa_dissect_lsalookupnames_rqst,
		lsa_dissect_lsalookupnames_reply },
	{ LSA_LSALOOKUPSIDS, "LookupSIDs",
		lsa_dissect_lsalookupsids_rqst,
		lsa_dissect_lsalookupsids_reply },
	{ LSA_LSACREATESECRET, "CreateSecret",
		lsa_dissect_lsacreatesecret_rqst,
		lsa_dissect_lsacreatesecret_reply },
	{ LSA_LSAOPENACCOUNT, "OpenAccount",
		lsa_dissect_lsaopenaccount_rqst,
		lsa_dissect_lsaopenaccount_reply },
	{ LSA_LSAENUMERATEPRIVILEGESACCOUNT, "EnumPrivsAccount",
		lsa_dissect_lsaenumerateprivilegesaccount_rqst,
		lsa_dissect_lsaenumerateprivilegesaccount_reply },
	{ LSA_LSAADDPRIVILEGESTOACCOUNT, "AddPrivsToAccount",
		lsa_dissect_lsaaddprivilegestoaccount_rqst,
		lsa_dissect_lsaaddprivilegestoaccount_reply },
	{ LSA_LSAREMOVEPRIVILEGESFROMACCOUNT, "MovePrivsFromAccount",
		lsa_dissect_lsaremoveprivilegesfromaccount_rqst,
		lsa_dissect_lsaremoveprivilegesfromaccount_reply },
	{ LSA_LSAGETQUOTASFORACCOUNT, "GetQuotasForAccount",
		lsa_dissect_lsagetquotasforaccount_rqst,
		lsa_dissect_lsagetquotasforaccount_reply },
	{ LSA_LSASETQUOTASFORACCOUNT, "SetQuotasForAccount",
		lsa_dissect_lsasetquotasforaccount_rqst,
		lsa_dissect_lsasetquotasforaccount_reply },
	{ LSA_LSAGETSYSTEMACCESSACCOUNT, "GetSystemAccessAccount",
		lsa_dissect_lsagetsystemaccessaccount_rqst,
		lsa_dissect_lsagetsystemaccessaccount_reply },
	{ LSA_LSASETSYSTEMACCESSACCOUNT, "SetSystemAccessAccount",
		lsa_dissect_lsasetsystemaccessaccount_rqst,
		lsa_dissect_lsasetsystemaccessaccount_reply },
	{ LSA_LSAOPENTRUSTEDDOMAIN, "OpenTrustedDomain",
		lsa_dissect_lsaopentrusteddomain_rqst,
		lsa_dissect_lsaopentrusteddomain_reply },
	{ LSA_LSAQUERYINFOTRUSTEDDOMAIN, "QueryInfoTrustedDomain",
		lsa_dissect_lsaqueryinfotrusteddomain_rqst,
		lsa_dissect_lsaqueryinfotrusteddomain_reply },
	{ LSA_LSASETINFORMATIONTRUSTEDDOMAIN, "SetInfoTrustedDomain",
		lsa_dissect_lsasetinformationtrusteddomain_rqst,
		lsa_dissect_lsasetinformationtrusteddomain_reply },
	{ LSA_LSAOPENSECRET, "OpenSecret",
		lsa_dissect_lsaopensecret_rqst,
		lsa_dissect_lsaopensecret_reply },
	{ LSA_LSASETSECRET, "SetSecret",
		lsa_dissect_lsasetsecret_rqst,
		lsa_dissect_lsasetsecret_reply },
	{ LSA_LSAQUERYSECRET, "QuerySecret",
		lsa_dissect_lsaquerysecret_rqst,
		lsa_dissect_lsaquerysecret_reply },
	{ LSA_LSALOOKUPPRIVILEGEVALUE, "LookupPrivValue",
		lsa_dissect_lsalookupprivilegevalue_rqst,
		lsa_dissect_lsalookupprivilegevalue_reply },
	{ LSA_LSALOOKUPPRIVILEGENAME, "LookupPrivName",
		lsa_dissect_lsalookupprivilegename_rqst,
		lsa_dissect_lsalookupprivilegename_reply },
	{ LSA_LSALOOKUPPRIVILEGEDISPLAYNAME, "LookupPrivDispName",
		lsa_dissect_lsalookupprivilegedisplayname_rqst,
		lsa_dissect_lsalookupprivilegedisplayname_reply },
	{ LSA_LSADELETEOBJECT, "DeleteObject",
		lsa_dissect_lsadeleteobject_rqst,
		lsa_dissect_lsadeleteobject_reply },
	{ LSA_LSAENUMERATEACCOUNTSWITHUSERRIGHT, "EnumAccountsWithUserRight",
		lsa_dissect_lsaenumerateaccountswithuserright_rqst,
		lsa_dissect_lsaenumerateaccountswithuserright_reply },
	{ LSA_LSAENUMERATEACCOUNTRIGHTS, "EnumAccountRights",
		lsa_dissect_lsaenumerateaccountrights_rqst,
		lsa_dissect_lsaenumerateaccountrights_reply },
	{ LSA_LSAADDACCOUNTRIGHTS, "AddAccountRights",
		lsa_dissect_lsaaddaccountrights_rqst,
		lsa_dissect_lsaaddaccountrights_reply },
	{ LSA_LSAREMOVEACCOUNTRIGHTS, "RemoveAccountRights",
		lsa_dissect_lsaremoveaccountrights_rqst,
		lsa_dissect_lsaremoveaccountrights_reply },
	{ LSA_LSAQUERYTRUSTEDDOMAININFO, "QueryTrustedDomainInfo",
		lsa_dissect_lsaquerytrusteddomaininfo_rqst,
		lsa_dissect_lsaquerytrusteddomaininfo_reply },
	{ LSA_LSASETTRUSTEDDOMAININFO, "SetTrustedDomainInfo",
		lsa_dissect_lsasettrusteddomaininfo_rqst,
		lsa_dissect_lsasettrusteddomaininfo_reply },
	{ LSA_LSADELETETRUSTEDDOMAIN, "DeleteTrsutedDomain",
		lsa_dissect_lsadeletetrusteddomain_rqst,
		lsa_dissect_lsadeletetrusteddomain_reply },
	{ LSA_LSASTOREPRIVATEDATA, "StorePrivateData",
		lsa_dissect_lsastoreprivatedata_rqst,
		lsa_dissect_lsastoreprivatedata_reply },
	{ LSA_LSARETRIEVEPRIVATEDATA, "RetrievePrivateData",
		lsa_dissect_lsaretrieveprivatedata_rqst,
		lsa_dissect_lsaretrieveprivatedata_reply },
	{ LSA_LSAOPENPOLICY2, "OpenPolicy2",
		lsa_dissect_lsaopenpolicy2_rqst,
		lsa_dissect_lsaopenpolicy2_reply },
	{ LSA_LSAGETUSERNAME, "GetUsername",
		lsa_dissect_lsagetusername_rqst,
		lsa_dissect_lsagetusername_reply },
	{ LSA_LSAQUERYINFORMATIONPOLICY2, "QueryInformationPolicy2",
		lsa_dissect_lsaqueryinformationpolicy2_rqst,
		lsa_dissect_lsaqueryinformationpolicy2_reply },
	{ LSA_LSASETINFORMATIONPOLICY2, "SetInformationPolicy2",
		lsa_dissect_lsasetinformationpolicy2_rqst,
		lsa_dissect_lsasetinformationpolicy2_reply },
	{ LSA_LSAQUERYTRUSTEDDOMAININFOBYNAME, "QueryTrustedDomainInfoByName",
		lsa_dissect_lsaquerytrusteddomaininfobyname_rqst,
		lsa_dissect_lsaquerytrusteddomaininfobyname_reply },
	{ LSA_LSASETTRUSTEDDOMAININFOBYNAME, "SetTrustedDomainInfoByName",
		lsa_dissect_lsasettrusteddomaininfobyname_rqst,
		lsa_dissect_lsasettrusteddomaininfobyname_reply },
	{ LSA_LSAENUMERATETRUSTEDDOMAINSEX, "EnumTrustedDomainsEx",
		lsa_dissect_lsaenumeratetrusteddomainsex_rqst,
		lsa_dissect_lsaenumeratetrusteddomainsex_reply },
	{ LSA_LSACREATETRUSTEDDOMAINEX, "CreateTrustedDomainEx",
		lsa_dissect_lsacreatetrusteddomainex_rqst,
		lsa_dissect_lsacreatetrusteddomainex_reply },
	{ LSA_LSACLOSETRUSTEDDOMAINEX, "CloseTrustedDomainEx",
		lsa_dissect_lsaclosetrusteddomainex_rqst,
		lsa_dissect_lsaclosetrusteddomainex_reply },
	{ LSA_LSAQUERYDOMAININFORMATIONPOLICY, "QueryDomainInfoPolicy",
		lsa_dissect_lsaquerydomaininformationpolicy_rqst,
		lsa_dissect_lsaquerydomaininformationpolicy_reply },
	{ LSA_LSASETDOMAININFORMATIONPOLICY, "SetDomainInfoPolicy",
		lsa_dissect_lsasetdomaininformationpolicy_rqst,
		lsa_dissect_lsasetdomaininformationpolicy_reply },
	{ LSA_LSAOPENTRUSTEDDOMAINBYNAME, "OpenTrustedDomainByName",
		lsa_dissect_lsaopentrusteddomainbyname_rqst,
		lsa_dissect_lsaopentrusteddomainbyname_reply },
	{ LSA_LSAFUNCTION_38, "LSAFUNCTION_38",
		lsa_dissect_lsafunction_38_rqst,
		lsa_dissect_lsafunction_38_reply },
	{ LSA_LSALOOKUPSIDS2, "LookupSIDs2",
		lsa_dissect_lsalookupsids2_rqst,
		lsa_dissect_lsalookupsids2_reply },
	{ LSA_LSALOOKUPNAMES2, "LookupNames2",
		lsa_dissect_lsalookupnames2_rqst,
		lsa_dissect_lsalookupnames2_reply },
	{ LSA_LSAFUNCTION_3B, "LSAFUNCTION_3B",
		lsa_dissect_lsafunction_3b_rqst,
		lsa_dissect_lsafunction_3b_reply },
	{0, NULL, NULL, NULL}
};

static const value_string lsa_opnum_vals[] = {
	{ LSA_LSACLOSE, "Close" },
	{ LSA_LSADELETE, "Delete" },
	{ LSA_LSAENUMERATEPRIVILEGES, "EnumPrivs" },
	{ LSA_LSAQUERYSECURITYOBJECT, "QuerySecObject" },
	{ LSA_LSASETSECURITYOBJECT, "SetSecObject" },
	{ LSA_LSACHANGEPASSWORD, "ChangePassword" },
	{ LSA_LSAOPENPOLICY, "OpenPolicy" },
	{ LSA_LSAQUERYINFORMATIONPOLICY, "QueryInfoPolicy" },
	{ LSA_LSASETINFORMATIONPOLICY, "SetInfoPolicy" },
	{ LSA_LSACLEARAUDITLOG, "ClearAuditLog" },
	{ LSA_LSACREATEACCOUNT, "CreateAccount" },
	{ LSA_LSAENUMERATEACCOUNTS, "EnumAccounts" },
	{ LSA_LSACREATETRUSTEDDOMAIN, "CreateTrustedDomain" },
	{ LSA_LSAENUMERATETRUSTEDDOMAINS, "EnumTrustedDomains" },
	{ LSA_LSALOOKUPNAMES, "LookupNames" },
	{ LSA_LSALOOKUPSIDS, "LookupSIDs" },
	{ LSA_LSACREATESECRET, "CreateSecret" },
	{ LSA_LSAOPENACCOUNT, "OpenAccount" },
	{ LSA_LSAENUMERATEPRIVILEGESACCOUNT, "EnumPrivsAccount" },
	{ LSA_LSAADDPRIVILEGESTOACCOUNT, "AddPrivsToAccount" },
	{ LSA_LSAREMOVEPRIVILEGESFROMACCOUNT, "MovePrivsFromAccount" },
	{ LSA_LSAGETQUOTASFORACCOUNT, "GetQuotasForAccount" },
	{ LSA_LSASETQUOTASFORACCOUNT, "SetQuotasForAccount" },
	{ LSA_LSAGETSYSTEMACCESSACCOUNT, "GetSystemAccessAccount" },
	{ LSA_LSASETSYSTEMACCESSACCOUNT, "SetSystemAccessAccount" },
	{ LSA_LSAOPENTRUSTEDDOMAIN, "OpenTrustedDomain" },
	{ LSA_LSAQUERYINFOTRUSTEDDOMAIN, "QueryInfoTrustedDomain" },
	{ LSA_LSASETINFORMATIONTRUSTEDDOMAIN, "SetInfoTrustedDomain" },
	{ LSA_LSAOPENSECRET, "OpenSecret" },
	{ LSA_LSASETSECRET, "SetSecret" },
	{ LSA_LSAQUERYSECRET, "QuerySecret" },
	{ LSA_LSALOOKUPPRIVILEGEVALUE, "LookupPrivValue" },
	{ LSA_LSALOOKUPPRIVILEGENAME, "LookupPrivName" },
	{ LSA_LSALOOKUPPRIVILEGEDISPLAYNAME, "LookupPrivDispName" },
	{ LSA_LSADELETEOBJECT, "DeleteObject" },
	{ LSA_LSAENUMERATEACCOUNTSWITHUSERRIGHT, "EnumAccountsWithUserRight" },
	{ LSA_LSAENUMERATEACCOUNTRIGHTS, "EnumAccountRights" },
	{ LSA_LSAADDACCOUNTRIGHTS, "AddAccountRights" },
	{ LSA_LSAREMOVEACCOUNTRIGHTS, "RemoveAccountRights" },
	{ LSA_LSAQUERYTRUSTEDDOMAININFO, "QueryTrustedDomainInfo" },
	{ LSA_LSASETTRUSTEDDOMAININFO, "SetTrustedDomainInfo" },
	{ LSA_LSADELETETRUSTEDDOMAIN, "DeleteTrsutedDomain" },
	{ LSA_LSASTOREPRIVATEDATA, "StorePrivateData" },
	{ LSA_LSARETRIEVEPRIVATEDATA, "RetrievePrivateData" },
	{ LSA_LSAOPENPOLICY2, "OpenPolicy2" },
	{ LSA_LSAGETUSERNAME, "GetUsername" },
	{ LSA_LSAQUERYINFORMATIONPOLICY2, "QueryInformationPolicy2" },
	{ LSA_LSASETINFORMATIONPOLICY2, "SetInformationPolicy2" },
	{ LSA_LSAQUERYTRUSTEDDOMAININFOBYNAME, "QueryTrustedDomainInfoByName" },
	{ LSA_LSASETTRUSTEDDOMAININFOBYNAME, "SetTrustedDomainInfoByName" },
	{ LSA_LSAENUMERATETRUSTEDDOMAINSEX, "EnumTrustedDomainsEx" },
	{ LSA_LSACREATETRUSTEDDOMAINEX, "CreateTrustedDomainEx" },
	{ LSA_LSACLOSETRUSTEDDOMAINEX, "CloseTrustedDomainEx" },
	{ LSA_LSAQUERYDOMAININFORMATIONPOLICY, "QueryDomainInfoPolicy" },
	{ LSA_LSASETDOMAININFORMATIONPOLICY, "SetDomainInfoPolicy" },
	{ LSA_LSAOPENTRUSTEDDOMAINBYNAME, "OpenTrustedDomainByName" },
	{ LSA_LSAFUNCTION_38, "LSAFUNCTION_38" },
	{ LSA_LSALOOKUPSIDS2, "LookupSIDs2" },
	{ LSA_LSALOOKUPNAMES2, "LookupNames2" },
	{ LSA_LSAFUNCTION_3B, "LSAFUNCTION_3B" },
	{ 0, NULL }
};

void
proto_register_dcerpc_lsa(void)
{
        static hf_register_info hf[] = {

        { &hf_lsa_opnum,
	  { "Operation", "lsa.opnum", FT_UINT16, BASE_DEC,
	    VALS(lsa_opnum_vals), 0x0, "Operation", HFILL }},

	{ &hf_lsa_unknown_string,
		{ "Unknown string", "lsa.unknown_string", FT_STRING, BASE_NONE,
		NULL, 0, "Unknown string. If you know what this is, contact ethereal developers.", HFILL }},

	{ &hf_lsa_hnd,
		{ "Context Handle", "lsa.hnd", FT_BYTES, BASE_NONE,
		NULL, 0x0, "LSA policy handle", HFILL }},

	{ &hf_lsa_server,
		{ "Server", "lsa.server", FT_STRING, BASE_NONE,
		NULL, 0, "Name of Server", HFILL }},

	{ &hf_lsa_controller,
		{ "Controller", "lsa.controller", FT_STRING, BASE_NONE,
		NULL, 0, "Name of Domain Controller", HFILL }},

	{ &hf_lsa_unknown_hyper,
		{ "Unknown hyper", "lsa.unknown.hyper", FT_UINT64, BASE_HEX,
		NULL, 0x0, "Unknown hyper. If you know what this is, contact ethereal developers.", HFILL }},

	{ &hf_lsa_unknown_long,
		{ "Unknown long", "lsa.unknown.long", FT_UINT32, BASE_HEX,
		NULL, 0x0, "Unknown long. If you know what this is, contact ethereal developers.", HFILL }},

	{ &hf_lsa_unknown_short,
		{ "Unknown short", "lsa.unknown.short", FT_UINT16, BASE_HEX,
		NULL, 0x0, "Unknown short. If you know what this is, contact ethereal developers.", HFILL }},

	{ &hf_lsa_unknown_char,
		{ "Unknown char", "lsa.unknown.char", FT_UINT8, BASE_HEX,
		NULL, 0x0, "Unknown char. If you know what this is, contact ethereal developers.", HFILL }},

	{ &hf_lsa_rc,
		{ "Return code", "lsa.rc", FT_UINT32, BASE_HEX,
		VALS (NT_errors), 0x0, "LSA return status code", HFILL }},

	{ &hf_lsa_obj_attr,
		{ "Attributes", "lsa.obj_attr", FT_UINT32, BASE_HEX,
		NULL, 0x0, "LSA Attributes", HFILL }},

	{ &hf_lsa_obj_attr_len,
		{ "Length", "lsa.obj_attr.len", FT_UINT32, BASE_DEC,
		NULL, 0x0, "Length of object attribute structure", HFILL }},

	{ &hf_lsa_obj_attr_name,
		{ "Name", "lsa.obj_attr.name", FT_STRING, BASE_NONE,
		NULL, 0x0, "Name of object attribute", HFILL }},

	{ &hf_lsa_access_mask,
		{ "Access Mask", "lsa.access_mask", FT_UINT32, BASE_HEX,
		NULL, 0x0, "LSA Access Mask", HFILL }},

	{ &hf_lsa_info_level,
		{ "Level", "lsa.info.level", FT_UINT16, BASE_DEC,
		NULL, 0x0, "Information level of requested data", HFILL }},

	{ &hf_lsa_trusted_info_level,
		{ "Info Level", "lsa.trusted.info_level", FT_UINT16, BASE_DEC,
		VALS(trusted_info_level_vals), 0x0, "Information level of requested Trusted Domain Information", HFILL }},

	{ &hf_lsa_sd_size,
		{ "Size", "lsa.sd_size", FT_UINT32, BASE_DEC,
		NULL, 0x0, "Size of lsa security descriptor", HFILL }},

	{ &hf_lsa_qos_len,
		{ "Length", "lsa.qos.len", FT_UINT32, BASE_DEC,
		NULL, 0x0, "Length of quality of service structure", HFILL }},

	{ &hf_lsa_qos_impersonation_level,
		{ "Impersonation level", "lsa.qos.imp_lev", FT_UINT16, BASE_DEC,
		VALS(lsa_impersonation_level_vals), 0x0, "QOS Impersonation Level", HFILL }},

	{ &hf_lsa_qos_track_context,
		{ "Context Tracking", "lsa.qos.track_ctx", FT_UINT8, BASE_DEC,
		NULL, 0x0, "QOS Context Tracking Mode", HFILL }},

	{ &hf_lsa_qos_effective_only,
		{ "Effective only", "lsa.qos.effective_only", FT_UINT8, BASE_DEC,
		NULL, 0x0, "QOS Flag whether this is Effective Only or not", HFILL }},

	{ &hf_lsa_pali_percent_full,
		{ "Percent Full", "lsa.pali.percent_full", FT_UINT32, BASE_DEC,
		NULL, 0x0, "How full audit log is in percentage", HFILL }},

	{ &hf_lsa_pali_log_size,
		{ "Log Size", "lsa.pali.log_size", FT_UINT32, BASE_DEC,
		NULL, 0x0, "Size of audit log", HFILL }},

	{ &hf_lsa_pali_retention_period,
		{ "Retention Period", "lsa.pali.retention_period", FT_RELATIVE_TIME, BASE_NONE,
		NULL, 0x0, "", HFILL }},

	{ &hf_lsa_pali_time_to_shutdown,
		{ "Time to shutdown", "lsa.pali.time_to_shutdown", FT_RELATIVE_TIME, BASE_NONE,
		NULL, 0x0, "Time to shutdown", HFILL }},

	{ &hf_lsa_pali_shutdown_in_progress,
		{ "Shutdown in progress", "lsa.pali.shutdown_in_progress", FT_UINT8, BASE_DEC,
		NULL, 0x0, "Flag whether shutdown is in progress or not", HFILL }},

	{ &hf_lsa_pali_next_audit_record,
		{ "Next Audit Record", "lsa.pali.next_audit_record", FT_UINT32, BASE_HEX,
		NULL, 0x0, "Next audit record", HFILL }},

	{ &hf_lsa_paei_enabled,
		{ "Enabled", "lsa.paei.enabled", FT_UINT8, BASE_DEC,
		NULL, 0x0, "If Audit Events Information is Enabled or not", HFILL }},

	{ &hf_lsa_paei_settings,
		{ "Settings", "lsa.paei.settings", FT_UINT32, BASE_HEX,
		NULL, 0x0, "Audit Events Information settings", HFILL }},

	{ &hf_lsa_count,
		{ "Count", "lsa.count", FT_UINT32, BASE_DEC,
		NULL, 0x0, "Count of objects", HFILL }},

	{ &hf_lsa_max_count,
		{ "Max Count", "lsa.max_count", FT_UINT32, BASE_DEC,
		NULL, 0x0, "", HFILL }},

	{ &hf_lsa_domain,
		{ "Domain", "lsa.domain", FT_STRING, BASE_NONE,
		NULL, 0x0, "Domain", HFILL }},

	{ &hf_lsa_acct,
		{ "Account", "lsa.acct", FT_STRING, BASE_NONE,
		NULL, 0x0, "Account", HFILL }},

	{ &hf_lsa_source,
		{ "Source", "lsa.source", FT_STRING, BASE_NONE,
		NULL, 0x0, "Replica Source", HFILL }},

	{ &hf_lsa_server_role,
		{ "Role", "lsa.server_role", FT_UINT16, BASE_DEC,
		VALS(server_role_vals), 0x0, "LSA Server Role", HFILL }},

	{ &hf_lsa_quota_paged_pool,
		{ "Paged Pool", "lsa.quota.paged_pool", FT_UINT32, BASE_DEC,
		NULL, 0x0, "Size of Quota Paged Pool", HFILL }},

	{ &hf_lsa_quota_non_paged_pool,
		{ "Non Paged Pool", "lsa.quota.non_paged_pool", FT_UINT32, BASE_DEC,
		NULL, 0x0, "Size of Quota non-Paged Pool", HFILL }},

	{ &hf_lsa_quota_min_wss,
		{ "Min WSS", "lsa.quota.min_wss", FT_UINT32, BASE_DEC,
		NULL, 0x0, "Size of Quota Min WSS", HFILL }},

	{ &hf_lsa_quota_max_wss,
		{ "Max WSS", "lsa.quota.max_wss", FT_UINT32, BASE_DEC,
		NULL, 0x0, "Size of Quota Max WSS", HFILL }},

	{ &hf_lsa_quota_pagefile,
		{ "Pagefile", "lsa.quota.pagefile", FT_UINT32, BASE_DEC,
		NULL, 0x0, "Size of quota pagefile usage", HFILL }},

	{ &hf_lsa_mod_seq_no,
		{ "Seq No", "lsa.mod.seq_no", FT_UINT64, BASE_DEC,
		NULL, 0x0, "Sequence number for this modification", HFILL }},

	{ &hf_lsa_mod_mtime,
		{ "MTime", "lsa.mod.mtime", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0x0, "Time when this modification occured", HFILL }},

	{ &hf_lsa_cur_mtime,
		{ "Current MTime", "lsa.cur.mtime", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0x0, "Current MTime to set", HFILL }},

	{ &hf_lsa_old_mtime,
		{ "Old MTime", "lsa.old.mtime", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0x0, "Old MTime for this object", HFILL }},

	{ &hf_lsa_name,
		{ "Name", "lsa.name", FT_STRING, BASE_NONE,
		NULL, 0x0, "", HFILL }},

	{ &hf_lsa_key,
		{ "Key", "lsa.key", FT_STRING, BASE_NONE,
		NULL, 0x0, "", HFILL }},

	{ &hf_lsa_flat_name,
		{ "Flat Name", "lsa.flat_name", FT_STRING, BASE_NONE,
		NULL, 0x0, "", HFILL }},

	{ &hf_lsa_forest,
		{ "Forest", "lsa.forest", FT_STRING, BASE_NONE,
		NULL, 0x0, "", HFILL }},

	{ &hf_lsa_info_type,
		{ "Info Type", "lsa.info_type", FT_UINT32, BASE_DEC,
		NULL, 0x0, "", HFILL }},

	{ &hf_lsa_new_pwd,
		{ "New Password", "lsa.new_pwd", FT_BYTES, BASE_HEX,
		NULL, 0x0, "New password", HFILL }},

	{ &hf_lsa_old_pwd,
		{ "Old Password", "lsa.old_pwd", FT_BYTES, BASE_HEX,
		NULL, 0x0, "Old password", HFILL }},

	{ &hf_lsa_sid_type,
		{ "SID Type", "lsa.sid_type", FT_UINT16, BASE_DEC,
		VALS(sid_type_vals), 0x0, "Type of SID", HFILL }},

	{ &hf_lsa_rid,
		{ "RID", "lsa.rid", FT_UINT32, BASE_HEX,
		NULL, 0x0, "RID", HFILL }},

	{ &hf_lsa_rid_offset,
		{ "RID Offset", "lsa.rid.offset", FT_UINT32, BASE_HEX,
		NULL, 0x0, "RID Offset", HFILL }},

	{ &hf_lsa_index,
		{ "Index", "lsa.index", FT_UINT32, BASE_DEC,
		NULL, 0x0, "", HFILL }},

	{ &hf_lsa_num_mapped,
		{ "Num Mapped", "lsa.num_mapped", FT_UINT32, BASE_DEC,
		NULL, 0x0, "", HFILL }},

	{ &hf_lsa_policy_information_class,
		{ "Info Class", "lsa.policy.info", FT_UINT16, BASE_DEC,
		VALS(policy_information_class_vals), 0x0, "Policy information class", HFILL }},

	{ &hf_lsa_secret,
		{ "LSA Secret", "lsa.secret", FT_BYTES, BASE_HEX,
		NULL, 0, "", HFILL }},

	{ &hf_lsa_auth_blob,
		{ "Auth blob", "lsa.auth.blob", FT_BYTES, BASE_HEX,
		NULL, 0, "", HFILL }},

	{ &hf_nt_luid_high,
		{ "High", "nt.luid.high", FT_UINT32, BASE_HEX,
		NULL, 0x0, "LUID High component", HFILL }},

	{ &hf_nt_luid_low,
		{ "Low", "nt.luid.low", FT_UINT32, BASE_HEX,
		NULL, 0x0, "LUID Low component", HFILL }},

	{ &hf_lsa_size,
		{ "Size", "lsa.size", FT_UINT32, BASE_DEC,
		NULL, 0x0, "", HFILL }},

	{ &hf_lsa_size16,
		{ "Size", "lsa.size", FT_UINT16, BASE_DEC,
		NULL, 0x0, "", HFILL }},

	{ &hf_lsa_size_needed,
		{ "Size Needed", "lsa.size_needed", FT_UINT16, BASE_DEC,
		NULL, 0x0, "", HFILL }},

	{ &hf_lsa_privilege_name,
		{ "Name", "lsa.privilege.name", FT_STRING, BASE_NONE,
		NULL, 0x0, "LSA Privilege Name", HFILL }},

	{ &hf_lsa_rights,
		{ "Rights", "lsa.rights", FT_STRING, BASE_NONE,
		NULL, 0x0, "Account Rights", HFILL }},

	{ &hf_lsa_attr,
		{ "Attr", "lsa.attr", FT_UINT64, BASE_HEX,
		NULL, 0x0, "LSA Attributes", HFILL }},

	{ &hf_lsa_auth_update,
		{ "Update", "lsa.auth.update", FT_UINT64, BASE_HEX,
		NULL, 0x0, "LSA Auth Info update", HFILL }},

	{ &hf_lsa_resume_handle,
		{ "Resume Handle", "lsa.resume_handle", FT_UINT32, BASE_DEC,
		NULL, 0x0, "Resume Handle", HFILL }},

	{ &hf_lsa_trust_direction,
		{ "Trust Direction", "lsa.trust.direction", FT_UINT32, BASE_DEC,
		VALS(trusted_direction_vals), 0x0, "Trust direction", HFILL }},

	{ &hf_lsa_trust_type,
		{ "Trust Type", "lsa.trust.type", FT_UINT32, BASE_DEC,
		VALS(trusted_type_vals), 0x0, "Trust type", HFILL }},

	{ &hf_lsa_trust_attr,
		{ "Trust Attr", "lsa.trust.attr", FT_UINT32, BASE_HEX,
		NULL, 0x0, "Trust attributes", HFILL }},

	{ &hf_lsa_trust_attr_non_trans,
		{ "Non Transitive", "lsa.trust.attr.non_trans", FT_BOOLEAN, 32,
		TFS(&tfs_trust_attr_non_trans), 0x00000001, "Non Transitive trust", HFILL }},

	{ &hf_lsa_trust_attr_uplevel_only,
		{ "Upleve only", "lsa.trust.attr.uplevel_only", FT_BOOLEAN, 32,
		TFS(&tfs_trust_attr_uplevel_only), 0x00000002, "Uplevel only trust", HFILL }},

	{ &hf_lsa_trust_attr_tree_parent,
		{ "Tree Parent", "lsa.trust.attr.tree_parent", FT_BOOLEAN, 32,
		TFS(&tfs_trust_attr_tree_parent), 0x00400000, "Tree Parent trust", HFILL }},

	{ &hf_lsa_trust_attr_tree_root,
		{ "Tree Root", "lsa.trust.attr.tree_root", FT_BOOLEAN, 32,
		TFS(&tfs_trust_attr_tree_root), 0x00800000, "Tree Root trust", HFILL }},

	{ &hf_lsa_auth_type,
		{ "Auth Type", "lsa.auth.type", FT_UINT32, BASE_DEC,
		NULL, 0x0, "Auth Info type", HFILL }},

	{ &hf_lsa_auth_len,
		{ "Auth Len", "lsa.auth.len", FT_UINT32, BASE_DEC,
		NULL, 0x0, "Auth Info len", HFILL }},

	{ &hf_lsa_remove_all,
		{ "Remove All", "lsa.remove_all", FT_UINT8, BASE_DEC,
		NULL, 0x0, "Flag whether all rights should be removed or only the specified ones", HFILL }},

	{ &hf_view_local_info,
	        { "View local info", "lsa.access_mask.view_local_info",
		  FT_BOOLEAN, 32, TFS(&flags_set_truth), POLICY_VIEW_LOCAL_INFORMATION,
		  "View local info", HFILL }},

	{ &hf_view_audit_info,
	        { "View audit info", "lsa.access_mask.view_audit_info",
		  FT_BOOLEAN, 32, TFS(&flags_set_truth), POLICY_VIEW_AUDIT_INFORMATION,
		  "View audit info", HFILL }},

	{ &hf_get_private_info,
	        { "Get private info", "lsa.access_mask.get_privateinfo",
		  FT_BOOLEAN, 32, TFS(&flags_set_truth), POLICY_GET_PRIVATE_INFORMATION,
		  "Get private info", HFILL }},

	{ &hf_trust_admin,
	        { "Trust admin", "lsa.access_mask.trust_admin",
		  FT_BOOLEAN, 32, TFS(&flags_set_truth), POLICY_TRUST_ADMIN,
		  "Trust admin", HFILL }},

	{ &hf_create_account,
	        { "Create account", "lsa.access_mask.create_account",
		  FT_BOOLEAN, 32, TFS(&flags_set_truth), POLICY_CREATE_ACCOUNT,
		  "Create account", HFILL }},

	{ &hf_create_secret,
	        { "Create secret", "lsa.access_mask.create_secret",
		  FT_BOOLEAN, 32, TFS(&flags_set_truth), POLICY_CREATE_SECRET,
		  "Create secret", HFILL }},

	{ &hf_create_priv,
	        { "Create privilege", "lsa.access_mask.create_priv",
		  FT_BOOLEAN, 32, TFS(&flags_set_truth), POLICY_CREATE_PRIVILEGE,
		  "Create privilege", HFILL }},

	{ &hf_set_default_quota_limits,
	        { "Set default quota limits", "lsa.access_mask.set_default_quota_limits",
		  FT_BOOLEAN, 32, TFS(&flags_set_truth), POLICY_SET_DEFAULT_QUOTA_LIMITS,
		  "Set default quota limits", HFILL }},

	{ &hf_set_audit_requirements,
	        { "Set audit requirements", "lsa.access_mask.set_audit_requirements",
		  FT_BOOLEAN, 32, TFS(&flags_set_truth), POLICY_SET_AUDIT_REQUIREMENTS,
		  "Set audit requirements", HFILL }},

	{ &hf_server_admin,
	        { "Server admin", "lsa.access_mask.server_admin",
		  FT_BOOLEAN, 32, TFS(&flags_set_truth), POLICY_SERVER_ADMIN,
		  "Server admin", HFILL }},

	{ &hf_lookup_names,
	        { "Lookup names", "lsa.access_mask.lookup_names",
		  FT_BOOLEAN, 32, TFS(&flags_set_truth), POLICY_LOOKUP_NAMES,
		  "Lookup names", HFILL }}
};

        static gint *ett[] = {
		&ett_dcerpc_lsa,
		&ett_lsa_OBJECT_ATTRIBUTES,
		&ett_LSA_SECURITY_DESCRIPTOR,
		&ett_lsa_policy_info,
		&ett_lsa_policy_audit_log_info,
		&ett_lsa_policy_audit_events_info,
		&ett_lsa_policy_primary_domain_info,
		&ett_lsa_policy_primary_account_info,
		&ett_lsa_policy_server_role_info,
		&ett_lsa_policy_replica_source_info,
		&ett_lsa_policy_default_quota_info,
		&ett_lsa_policy_modification_info,
		&ett_lsa_policy_audit_full_set_info,
		&ett_lsa_policy_audit_full_query_info,
		&ett_lsa_policy_dns_domain_info,
		&ett_lsa_translated_names,
		&ett_lsa_translated_name,
		&ett_lsa_referenced_domain_list,
		&ett_lsa_trust_information,
		&ett_lsa_trust_information_ex,
		&ett_LUID,
		&ett_LSA_PRIVILEGES,
		&ett_LSA_PRIVILEGE,
		&ett_LSA_LUID_AND_ATTRIBUTES_ARRAY,
		&ett_LSA_LUID_AND_ATTRIBUTES,
		&ett_LSA_TRUSTED_DOMAIN_LIST,
		&ett_LSA_TRUSTED_DOMAIN,
		&ett_LSA_TRANSLATED_SIDS,
		&ett_lsa_trusted_domain_info,
		&ett_lsa_trust_attr,
		&ett_lsa_trusted_domain_auth_information,
		&ett_lsa_auth_information
        };

        proto_dcerpc_lsa = proto_register_protocol(
                "Microsoft Local Security Architecture", "LSA", "lsa");

        proto_register_field_array (proto_dcerpc_lsa, hf, array_length (hf));
        proto_register_subtree_array(ett, array_length(ett));
}

/* Protocol handoff */

static e_uuid_t uuid_dcerpc_lsa = {
        0x12345778, 0x1234, 0xabcd,
        { 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab}
};

static guint16 ver_dcerpc_lsa = 0;

void
proto_reg_handoff_dcerpc_lsa(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_lsa, ett_dcerpc_lsa, &uuid_dcerpc_lsa,
                         ver_dcerpc_lsa, dcerpc_lsa_dissectors, hf_lsa_opnum);
}
