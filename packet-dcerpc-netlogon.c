/* packet-dcerpc-netlogon.c
 * Routines for SMB \\PIPE\\NETLOGON packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 *  2002 structure and command dissectors by Ronnie Sahlberg
 *
 * $Id: packet-dcerpc-netlogon.c,v 1.7 2002/03/13 11:19:16 sahlberg Exp $
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
#include "packet-dcerpc-netlogon.h"
#include "smb.h"	/* for "NT_errors[]" */
#include "packet-smb-common.h"

static int proto_dcerpc_netlogon = -1;
static int hf_netlogon_rc = -1;
static int hf_netlogon_len = -1;
static int hf_netlogon_status = -1;
static int hf_netlogon_attrs = -1;
static int hf_netlogon_count = -1;
static int hf_netlogon_level = -1;
static int hf_netlogon_level_long = -1;
static int hf_netlogon_unknown_time = -1;
static int hf_netlogon_unknown_string = -1;
static int hf_netlogon_unknown_long = -1;
static int hf_netlogon_unknown_short = -1;
static int hf_netlogon_unknown_char = -1;
static int hf_netlogon_logon_time = -1;
static int hf_netlogon_logoff_time = -1;
static int hf_netlogon_kickoff_time = -1;
static int hf_netlogon_pwd_last_set_time = -1;
static int hf_netlogon_pwd_can_change_time = -1;
static int hf_netlogon_pwd_must_change_time = -1;
static int hf_netlogon_timestamp = -1;
static int hf_netlogon_nt_chal_resp = -1;
static int hf_netlogon_lm_chal_resp = -1;
static int hf_netlogon_credential = -1;
static int hf_netlogon_cypher_block = -1;
static int hf_netlogon_acct_name = -1;
static int hf_netlogon_acct_desc = -1;
static int hf_netlogon_group_desc = -1;
static int hf_netlogon_full_name = -1;
static int hf_netlogon_comment = -1;
static int hf_netlogon_parameters = -1;
static int hf_netlogon_logon_script = -1;
static int hf_netlogon_profile_path = -1;
static int hf_netlogon_home_dir = -1;
static int hf_netlogon_dir_drive = -1;
static int hf_netlogon_logon_count = -1;
static int hf_netlogon_bad_pw_count = -1;
static int hf_netlogon_user_rid = -1;
static int hf_netlogon_alias_rid = -1;
static int hf_netlogon_group_rid = -1;
static int hf_netlogon_logon_srv = -1;
static int hf_netlogon_logon_dom = -1;
static int hf_netlogon_trusted_domain_name = -1;
static int hf_netlogon_num_rids = -1;
static int hf_netlogon_num_other_groups = -1;
static int hf_netlogon_computer_name = -1;
static int hf_netlogon_site_name = -1;
static int hf_netlogon_trusted_dc_name = -1;
static int hf_netlogon_dc_name = -1;
static int hf_netlogon_dc_site_name = -1;
static int hf_netlogon_dns_forest_name = -1;
static int hf_netlogon_dc_address = -1;
static int hf_netlogon_dc_address_type = -1;
static int hf_netlogon_client_name = -1;
static int hf_netlogon_client_site_name = -1;
static int hf_netlogon_workstation_site_name = -1;
static int hf_netlogon_workstation_os = -1;
static int hf_netlogon_workstations = -1;
static int hf_netlogon_workstation_fqdn = -1;
static int hf_netlogon_group_name = -1;
static int hf_netlogon_alias_name = -1;
static int hf_netlogon_cli_name = -1;
static int hf_netlogon_country = -1;
static int hf_netlogon_codepage = -1;
static int hf_netlogon_flags = -1;
static int hf_netlogon_user_flags = -1;
static int hf_netlogon_pwd_expired = -1;
static int hf_netlogon_nt_pwd_present = -1;
static int hf_netlogon_lm_pwd_present = -1;
static int hf_netlogon_code = -1;
static int hf_netlogon_database_id = -1;
static int hf_netlogon_max_size = -1;
static int hf_netlogon_dns_host = -1;
static int hf_netlogon_num_pwd_pairs = -1;
static int hf_netlogon_acct_expiry_time = -1;
static int hf_netlogon_encrypted_lm_owf_password = -1;
static int hf_netlogon_lm_owf_password = -1;
static int hf_netlogon_nt_owf_password = -1;
static int hf_netlogon_param_ctrl = -1;
static int hf_netlogon_logon_id = -1;
static int hf_netlogon_num_deltas = -1;
static int hf_netlogon_user_session_key = -1;
static int hf_netlogon_blob_size = -1;
static int hf_netlogon_blob = -1;
static int hf_netlogon_logon_attempts = -1;
static int hf_netlogon_authoritative = -1;
static int hf_netlogon_secure_channel_type = -1;
static int hf_netlogon_logonsrv_handle = -1;
static int hf_netlogon_lsa_secret = -1;
static int hf_netlogon_lsa_sd_size = -1;
static int hf_netlogon_lsa_sd_data = -1;

static gint ett_dcerpc_netlogon = -1;
static gint ett_NETLOGON_SECURITY_DESCRIPTOR = -1;
static gint ett_TYPE_1 = -1;
static gint ett_TYPE_2 = -1;
static gint ett_CYPHER_BLOCK = -1;
static gint ett_NETLOGON_AUTHENTICATOR = -1;
static gint ett_NETLOGON_LOGON_IDENTITY_INFO = -1;
static gint ett_NETLOGON_INTERACTIVE_INFO = -1;
static gint ett_NETLOGON_NETWORK_INFO = -1;
static gint ett_NETLOGON_VALIDATION_SAM_INFO1 = -1;
static gint ett_NETLOGON_VALIDATION_SAM_INFO2 = -1;
static gint ett_TYPE_16 = -1;
static gint ett_NETLOGON_SAM_DOMAIN_INFO = -1;
static gint ett_NETLOGON_SAM_GROUP_INFO = -1;
static gint ett_TYPE_23 = -1;
static gint ett_NETLOGON_SAM_ACCOUNT_INFO = -1;
static gint ett_NETLOGON_SAM_GROUP_MEM_INFO = -1;
static gint ett_NETLOGON_SAM_ALIAS_INFO = -1;
static gint ett_NETLOGON_SAM_ALIAS_MEM_INFO = -1;
static gint ett_TYPE_30 = -1;
static gint ett_TYPE_29 = -1;
static gint ett_TYPE_31 = -1;
static gint ett_TYPE_32 = -1;
static gint ett_TYPE_33 = -1;
static gint ett_TYPE_34 = -1;
static gint ett_TYPE_35 = -1;
static gint ett_SAM_DELTA = -1;
static gint ett_SAM_DELTA_ARRAY = -1;
static gint ett_TYPE_36 = -1;
static gint ett_NETLOGON_INFO_1 = -1;
static gint ett_NETLOGON_INFO_2 = -1;
static gint ett_NETLOGON_INFO_3 = -1;
static gint ett_NETLOGON_INFO_4 = -1;
static gint ett_UNICODE_MULTI = -1;
static gint ett_DOMAIN_CONTROLLER_INFO = -1;
static gint ett_TYPE_46 = -1;
static gint ett_TYPE_48 = -1;
static gint ett_UNICODE_STRING_512 = -1;
static gint ett_TYPE_50 = -1;
static gint ett_TYPE_51 = -1;
static gint ett_TYPE_52 = -1;
static gint ett_NETLOGON_LEVEL = -1;
static gint ett_NETLOGON_VALIDATION = -1;
static gint ett_TYPE_19 = -1;
static gint ett_NETLOGON_CONTROL_QUERY_INFO = -1;
static gint ett_TYPE_44 = -1;
static gint ett_TYPE_20 = -1;
static gint ett_NETLOGON_INFO = -1;
static gint ett_TYPE_45 = -1;
static gint ett_TYPE_47 = -1;
static gint ett_NETLOGON_CREDENTIAL = -1;
static gint ett_GUID = -1;
static gint ett_ENC_LM_OWF_PASSWORD = -1;
static gint ett_LM_OWF_PASSWORD = -1;
static gint ett_NT_OWF_PASSWORD = -1;
static gint ett_GROUP_MEMBERSHIP = -1;
static gint ett_USER_SESSION_KEY = -1;
static gint ett_BLOB = -1;
static gint ett_rid_array = -1;
static gint ett_attrib_array = -1;
static gint ett_netlogon_lsa_sd_data = -1;

static e_uuid_t uuid_dcerpc_netlogon = {
        0x12345678, 0x1234, 0xabcd,
        { 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0xcf, 0xfb }
};

static guint16 ver_dcerpc_netlogon = 1;


static int
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
                                     hf_netlogon_lsa_sd_size, &len);

	dissect_nt_sec_desc(tvb, pinfo, offset, tree, len);
	offset += len;
/*	proto_tree_add_item(tree, hf_netlogon_lsa_sd_data, tvb, offset, len, FALSE);
	offset += len;
*/

	return offset;
}
static int
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
		tree = proto_item_add_subtree(item, ett_NETLOGON_SECURITY_DESCRIPTOR);
	}

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_netlogon_lsa_sd_size, NULL);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			lsa_dissect_LSA_SECURITY_DESCRIPTOR_data, NDR_POINTER_UNIQUE,
			"LSA SECURITY DESCRIPTOR data:", -1, 0);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

/* XXX temporary, until we get the real one in LSA */
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
                                     hf_netlogon_lsa_sd_size, &len);
	proto_tree_add_item(tree, hf_netlogon_lsa_secret, tvb, offset, len, FALSE);
	offset += len;

	return offset;
}
static int
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
		tree = proto_item_add_subtree(item, ett_NETLOGON_SECURITY_DESCRIPTOR);
	}

	/* XXX need to figure this one out */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_netlogon_lsa_sd_size, NULL);
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			lsa_dissect_LSA_SECRET_data, NDR_POINTER_UNIQUE,
			"LSA SECRET data:", -1, 0);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
netlogon_dissect_pointer_long(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
	dcerpc_info *di;

	di=pinfo->private_data;
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     di->hf_index, NULL);
	return offset;
}

static int
netlogon_dissect_pointer_char(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
	dcerpc_info *di;

	di=pinfo->private_data;
        offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep,
                                     di->hf_index, NULL);
	return offset;
}

static int
netlogon_dissect_pointer_STRING(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	offset = dissect_ndr_nt_STRING(tvb, offset, pinfo, tree, drep,
			di->hf_index, 0);
	return offset;
}


static int
netlogon_dissect_NETLOGON_SECURITY_DESCRIPTOR(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"NETLOGON_SECURITY_DESCRIPTOR:");
		tree = proto_item_add_subtree(item, ett_NETLOGON_SECURITY_DESCRIPTOR);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_len, NULL);

	offset = lsa_dissect_LSA_SECURITY_DESCRIPTOR(tvb, offset,
		pinfo, tree, drep);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_TYPE_1(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"TYPE_1:");
		tree = proto_item_add_subtree(item, ett_TYPE_1);
	}

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_PTR,
		"unknown", hf_netlogon_unknown_string, -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_PTR,
		"unknown", hf_netlogon_unknown_string, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_PTR,
		"unknown", hf_netlogon_unknown_string, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_PTR,
		"unknown", hf_netlogon_unknown_string, -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_TYPE_1_ptr(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_TYPE_1, NDR_POINTER_PTR,
		"TYPE_1 pointer: ", -1, 0);
	return offset;
}

static int
netlogon_dissect_TYPE_2(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"TYPE_2:");
		tree = proto_item_add_subtree(item, ett_TYPE_2);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_short, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_CYPHER_BLOCK(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int i;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect.*/
		return offset;
	}

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 8,
			"CYPHER_BLOCK:");
		tree = proto_item_add_subtree(item, ett_CYPHER_BLOCK);
	}

	proto_tree_add_item(tree, hf_netlogon_cypher_block, tvb, offset, 8,
		FALSE);
	offset += 8;

	return offset;
}

static int
netlogon_dissect_8_unknown_bytes(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int i;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect.*/
		return offset;
	}

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 8,
			"unknown bytes not in IDL:");
		tree = proto_item_add_subtree(item, ett_CYPHER_BLOCK);
	}

	offset += 8;

	return offset;
}

static int
netlogon_dissect_NETLOGON_CREDENTIAL(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int i;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect.*/
		return offset;
	}

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 8,
			"NETLOGON_CREDENTIAL:");
		tree = proto_item_add_subtree(item, ett_NETLOGON_CREDENTIAL);
	}

	proto_tree_add_item(tree, hf_netlogon_credential, tvb, offset, 8,
		FALSE);
	offset += 8;

	return offset;
}

static int
netlogon_dissect_NETLOGON_AUTHENTICATOR(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"NETLOGON_AUTHENTICATOR:");
		tree = proto_item_add_subtree(item, ett_NETLOGON_AUTHENTICATOR);
	}

	offset = netlogon_dissect_NETLOGON_CREDENTIAL(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_timestamp, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_USER_SESSION_KEY(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect.*/
		return offset;
	}

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 16,
			"USER_SESSION_KEY:");
		tree = proto_item_add_subtree(item, ett_USER_SESSION_KEY);
	}

	proto_tree_add_item(tree, hf_netlogon_user_session_key, tvb, offset, 16,
		FALSE);
	offset += 16;

	return offset;
}

static int
netlogon_dissect_ENCRYPTED_LM_OWF_PASSWORD(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect.*/
		return offset;
	}

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 16,
			"ENCRYPTED_LM_OWF_PASSWORD:");
		tree = proto_item_add_subtree(item, ett_ENC_LM_OWF_PASSWORD);
	}

	proto_tree_add_item(tree, hf_netlogon_encrypted_lm_owf_password, tvb, offset, 16,
		FALSE);
	offset += 16;

	return offset;
}

static int
netlogon_dissect_LM_OWF_PASSWORD(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect.*/
		return offset;
	}

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 16,
			"LM_OWF_PASSWORD:");
		tree = proto_item_add_subtree(item, ett_LM_OWF_PASSWORD);
	}

	proto_tree_add_item(tree, hf_netlogon_lm_owf_password, tvb, offset, 16,
		FALSE);
	offset += 16;

	return offset;
}

static int
netlogon_dissect_NT_OWF_PASSWORD(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect.*/
		return offset;
	}

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 16,
			"NT_OWF_PASSWORD:");
		tree = proto_item_add_subtree(item, ett_NT_OWF_PASSWORD);
	}

	proto_tree_add_item(tree, hf_netlogon_nt_owf_password, tvb, offset, 16,
		FALSE);
	offset += 16;

	return offset;
}


static int
netlogon_dissect_NETLOGON_LOGON_IDENTITY_INFO(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"NETLOGON_LOGON_IDENTITY_INFO:");
		tree = proto_item_add_subtree(item, ett_NETLOGON_LOGON_IDENTITY_INFO);
	}

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_dom, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_param_ctrl, NULL);

	offset = dissect_ndr_uint64(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_id, NULL);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_acct_name, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_computer_name, 0);

	/* XXX 8 extra bytes here */
	/* there were 8 extra bytes, either here or in NETWORK_INFO that does not match
	   the idl file. Could be a bug in either the NETLOGON implementation or in the
	   idl file.
	*/
	offset = netlogon_dissect_8_unknown_bytes(tvb, offset, pinfo, tree, drep);

	return offset;
}

static int
netlogon_dissect_NETLOGON_INTERACTIVE_INFO(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"NETLOGON_INTERACTIVE_INFO:");
		tree = proto_item_add_subtree(item, ett_NETLOGON_INTERACTIVE_INFO);
	}

	offset = netlogon_dissect_NETLOGON_LOGON_IDENTITY_INFO(tvb, offset,
		pinfo, tree, drep);

	offset = netlogon_dissect_LM_OWF_PASSWORD(tvb, offset,
		pinfo, tree, drep);

	offset = netlogon_dissect_NT_OWF_PASSWORD(tvb, offset,
		pinfo, tree, drep);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_NETLOGON_NETWORK_INFO(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"NETLOGON_NETWORK_INFO:");
		tree = proto_item_add_subtree(item, ett_NETLOGON_NETWORK_INFO);
	}

	offset = netlogon_dissect_NETLOGON_LOGON_IDENTITY_INFO(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_nt_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_nt_chal_resp, 0);

	offset = dissect_ndr_nt_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_lm_chal_resp, 0);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_GROUP_MEMBERSHIP(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"GROUP_MEMBERSHIP:");
		tree = proto_item_add_subtree(item, ett_GROUP_MEMBERSHIP);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_user_rid, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_attrs, NULL);

	return offset;
}

static int
netlogon_dissect_GROUP_MEMBERSHIP_ARRAY(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_GROUP_MEMBERSHIP);

	return offset;
}

static int
netlogon_dissect_NETLOGON_VALIDATION_SAM_INFO1(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;
	int i;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"NETLOGON_VALIDATION_SAM_INFO1:");
		tree = proto_item_add_subtree(item, ett_NETLOGON_VALIDATION_SAM_INFO1);
	}

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_time);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logoff_time);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_kickoff_time);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_pwd_last_set_time);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_pwd_can_change_time);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_pwd_must_change_time);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_acct_name, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_full_name, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_script, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_profile_path, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_home_dir, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dir_drive, 0);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_count, NULL);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_bad_pw_count, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_user_rid, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_group_rid, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_num_rids, NULL);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_GROUP_MEMBERSHIP_ARRAY, NDR_POINTER_PTR,
		"GROUP_MEMBERSHIP_ARRAY", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_user_flags, NULL);

	offset = netlogon_dissect_USER_SESSION_KEY(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_srv, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_dom, 0);

	offset = dissect_ndr_nt_PSID(tvb, offset,
		pinfo, tree, drep);

	for(i=0;i<10;i++){
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_long, NULL);
	}

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_NETLOGON_VALIDATION_SAM_INFO2(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;
	int i;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"NETLOGON_VALIDATION_SAM_INFO2:");
		tree = proto_item_add_subtree(item, ett_NETLOGON_VALIDATION_SAM_INFO2);
	}

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_time);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logoff_time);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_kickoff_time);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_pwd_last_set_time);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_pwd_can_change_time);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_pwd_must_change_time);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_acct_name, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_full_name, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_script, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_profile_path, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_home_dir, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dir_drive, 0);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_count, NULL);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_bad_pw_count, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_user_rid, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_group_rid, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_num_rids, NULL);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_GROUP_MEMBERSHIP_ARRAY, NDR_POINTER_PTR,
		"GROUP_MEMBERSHIP_ARRAY", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_user_flags, NULL);

	offset = netlogon_dissect_USER_SESSION_KEY(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_srv, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_dom, 0);

	offset = dissect_ndr_nt_PSID(tvb, offset,
		pinfo, tree, drep);

	for(i=0;i<10;i++){
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_long, NULL);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_num_other_groups, NULL);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_SID_AND_ATTRIBUTES_ARRAY, NDR_POINTER_PTR,
		"SID_AND_ATTRIBUTES_ARRAY:", -1, 0);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_TYPE_16(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"TYPE_16:");
		tree = proto_item_add_subtree(item, ett_TYPE_16);
	}

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_time);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
netlogon_dissect_NETLOGON_SAM_DOMAIN_INFO(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"NETLOGON_SAM_DOMAIN_INFO:");
		tree = proto_item_add_subtree(item, ett_NETLOGON_SAM_DOMAIN_INFO);
	}

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_time);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_short, NULL);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_short, NULL);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_time);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_time);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_time);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_time);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
netlogon_dissect_NETLOGON_SAM_GROUP_INFO(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"NETLOGON_SAM_GROUP_INFO:");
		tree = proto_item_add_subtree(item, ett_NETLOGON_SAM_GROUP_INFO);
	}

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_group_name, 0);

	offset = netlogon_dissect_GROUP_MEMBERSHIP(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_group_desc, 0);

	offset = netlogon_dissect_NETLOGON_SECURITY_DESCRIPTOR(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
netlogon_dissect_TYPE_23(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"TYPE_23:");
		tree = proto_item_add_subtree(item, ett_TYPE_23);
	}

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
netlogon_dissect_NETLOGON_SAM_ACCOUNT_INFO(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"NETLOGON_SAM_ACCOUNT_INFO:");
		tree = proto_item_add_subtree(item, ett_NETLOGON_SAM_ACCOUNT_INFO);
	}

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_acct_name, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_full_name, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_user_rid, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_group_rid, NULL);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_home_dir, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dir_drive, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_script, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_acct_desc, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_workstations, 0);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_time);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logoff_time);

	offset = dissect_ndr_nt_LOGON_HOURS(tvb, offset, pinfo, tree, drep);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_bad_pw_count, NULL);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_count, NULL);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_pwd_last_set_time);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_acct_expiry_time);

	offset = dissect_ndr_nt_acct_ctrl(tvb, offset, pinfo, tree, drep);

	offset = netlogon_dissect_LM_OWF_PASSWORD(tvb, offset,
		pinfo, tree, drep);

	offset = netlogon_dissect_NT_OWF_PASSWORD(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep,
		hf_netlogon_nt_pwd_present, NULL);

	offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep,
		hf_netlogon_lm_pwd_present, NULL);

	offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep,
		hf_netlogon_pwd_expired, NULL);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_comment, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_parameters, 0);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_country, NULL);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_codepage, NULL);

	offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep,
		hf_netlogon_num_pwd_pairs, NULL);

	offset = lsa_dissect_LSA_SECRET(tvb, offset,
		pinfo, tree, drep);

	offset = netlogon_dissect_NETLOGON_SECURITY_DESCRIPTOR(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_profile_path, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
netlogon_dissect_rid(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				hf_netlogon_user_rid, NULL);

	return offset;
}

static int
netlogon_dissect_rids_array(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"RID array:");
		tree = proto_item_add_subtree(item, ett_rid_array);
	}

	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_rid);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_attrib(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_attrs, NULL);

	return offset;
}

static int
netlogon_dissect_attribs_array(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"Attrib array:");
		tree = proto_item_add_subtree(item, ett_attrib_array);
	}

	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_attrib);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_NETLOGON_SAM_GROUP_MEM_INFO(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"NETLOGON_SAM_GROUP_MEM_INFO:");
		tree = proto_item_add_subtree(item, ett_NETLOGON_SAM_GROUP_MEM_INFO);
	}

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_rids_array, NDR_POINTER_PTR,
		"RIDs:", -1, 0);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_attribs_array, NDR_POINTER_PTR,
		"Attribs:", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_num_rids, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
netlogon_dissect_NETLOGON_SAM_ALIAS_INFO(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"NETLOGON_SAM_ALIAS_INFO:");
		tree = proto_item_add_subtree(item, ett_NETLOGON_SAM_ALIAS_INFO);
	}


	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_alias_name, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_alias_rid, NULL);

	offset = netlogon_dissect_NETLOGON_SECURITY_DESCRIPTOR(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_acct_desc, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
netlogon_dissect_NETLOGON_SAM_ALIAS_MEM_INFO(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"NETLOGON_SAM_ALIAS_MEM_INFO:");
		tree = proto_item_add_subtree(item, ett_NETLOGON_SAM_ALIAS_MEM_INFO);
	}

	offset = dissect_ndr_nt_PSID_ARRAY(tvb, offset, pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_TYPE_30(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"TYPE_30:");
		tree = proto_item_add_subtree(item, ett_TYPE_30);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_time);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_element_422(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	return offset;
}

static int
netlogon_dissect_element_422_array(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_element_422);

	return offset;
}


static int
netlogon_dissect_TYPE_29(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"TYPE_29:");
		tree = proto_item_add_subtree(item, ett_TYPE_29);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_time);

	offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_char, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_element_422_array, NDR_POINTER_PTR,
		"unknown", -1, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_PSID(tvb, offset,
		pinfo, tree, drep);

	offset = netlogon_dissect_TYPE_30(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_time);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_time);

	offset = netlogon_dissect_NETLOGON_SECURITY_DESCRIPTOR(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
netlogon_dissect_TYPE_31(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"TYPE_31:");
		tree = proto_item_add_subtree(item, ett_TYPE_31);
	}

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_nt_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
netlogon_dissect_TYPE_32(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"TYPE_32:");
		tree = proto_item_add_subtree(item, ett_TYPE_32);
	}

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
netlogon_dissect_attrs(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_attrs, NULL);

	return offset;
}

static int
netlogon_dissect_attrs_array(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_attrs);

	return offset;
}


static int
netlogon_dissect_TYPE_33(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"TYPE_33:");
		tree = proto_item_add_subtree(item, ett_TYPE_33);
	}


	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_count, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_attrs_array, NDR_POINTER_PTR,
		"ATTRS_ARRAY:", -1, 0);

	offset = netlogon_dissect_TYPE_30(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_nt_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
netlogon_dissect_TYPE_34(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"TYPE_34:");
		tree = proto_item_add_subtree(item, ett_TYPE_34);
	}

	offset = dissect_ndr_nt_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_time);

	offset = dissect_ndr_nt_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_time);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_nt_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_TYPE_35(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"TYPE_35:");
		tree = proto_item_add_subtree(item, ett_TYPE_35);
	}

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_PTR,
		"unknown", hf_netlogon_unknown_string, -1);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_WCHAR_ptr(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_PTR,
		"unknown string", hf_netlogon_unknown_string, -1);

	return offset;
}

static int
netlogon_dissect_TYPE_36(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;
	int i;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"TYPE_36:");
		tree = proto_item_add_subtree(item, ett_TYPE_36);
	}

	for(i=0;i<16;i++){
		offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_char, NULL);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_NETLOGON_INFO_1(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"NETLOGON_INFO_1:");
		tree = proto_item_add_subtree(item, ett_NETLOGON_INFO_1);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_flags, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_status, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_NETLOGON_INFO_2(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"NETLOGON_INFO_2:");
		tree = proto_item_add_subtree(item, ett_NETLOGON_INFO_2);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_PTR,
		"unknown", hf_netlogon_unknown_string, -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_NETLOGON_INFO_3(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"NETLOGON_INFO_3:");
		tree = proto_item_add_subtree(item, ett_NETLOGON_INFO_3);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_flags, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_attempts, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_NETLOGON_INFO_4(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"NETLOGON_INFO_4:");
		tree = proto_item_add_subtree(item, ett_NETLOGON_INFO_4);
	}

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_PTR,
		"unknown", hf_netlogon_trusted_dc_name, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_PTR,
		"unknown", hf_netlogon_trusted_domain_name, -1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_UNICODE_MULTI_byte(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
		offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_char, NULL);

	return offset;
}

static int
netlogon_dissect_UNICODE_MULTI_array(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_UNICODE_MULTI_byte);

	return offset;
}

static int
netlogon_dissect_BYTE_byte(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
		offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_char, NULL);

	return offset;
}

static int
netlogon_dissect_BYTE_array(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_BYTE_byte);

	return offset;
}

static int
netlogon_dissect_UNICODE_MULTI(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"UNICODE_MULTI:");
		tree = proto_item_add_subtree(item, ett_UNICODE_MULTI);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_len, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_UNICODE_MULTI_array, NDR_POINTER_PTR,
		"unknown", hf_netlogon_unknown_string, 0);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_GUID(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;
	int i;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"GUID:");
		tree = proto_item_add_subtree(item, ett_GUID);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_short, NULL);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_short, NULL);

	for(i=0;i<8;i++){
		offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_char, NULL);
	}

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_DOMAIN_CONTROLLER_INFO(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"DOMAIN_CONTROLLER_INFO:");
		tree = proto_item_add_subtree(item, ett_DOMAIN_CONTROLLER_INFO);
	}

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_PTR,
		"unknown", hf_netlogon_dc_name, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_PTR,
		"unknown", hf_netlogon_dc_address, -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dc_address_type, NULL);

	offset = netlogon_dissect_GUID(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_PTR,
		"unknown", hf_netlogon_logon_dom, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_PTR,
		"unknown", hf_netlogon_dns_forest_name, -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_flags, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_PTR,
		"unknown", hf_netlogon_dc_site_name, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_PTR,
		"unknown", hf_netlogon_client_site_name, -1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_DOMAIN_CONTROLLER_INFO_ptr(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_DOMAIN_CONTROLLER_INFO, NDR_POINTER_PTR,
		"DOMAIN_CONTROLLER_INFO pointer: info", -1, 0);

	return offset;
}

static int
netlogon_dissect_DOMAIN_CONTROLLER_INFO_ptr_ptr(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_DOMAIN_CONTROLLER_INFO_ptr, NDR_POINTER_PTR,
		"DOMAIN_CONTROLLER_INFO pointer: info", -1, 0);

	return offset;
}

static int
netlogon_dissect_BLOB_array(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	guint32 len;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect.*/
		return offset;
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_blob_size, &len);

	proto_tree_add_item(tree, hf_netlogon_blob, tvb, offset, len,
		FALSE);
	offset += len;

	return offset;
}

static int
netlogon_dissect_BLOB(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"BLOB:");
		tree = proto_item_add_subtree(item, ett_BLOB);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_blob_size, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_BLOB_array, NDR_POINTER_PTR,
		"BLOB:", -1, 0);

	return offset;
}

static int
netlogon_dissect_BLOB_ptr(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_BLOB, NDR_POINTER_PTR,
		"BLOB pointer:", -1, 0);

	return offset;
}

static int
netlogon_dissect_TYPE_46(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"TYPE_46:");
		tree = proto_item_add_subtree(item, ett_TYPE_46);
	}

	offset = netlogon_dissect_BLOB(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_PTR,
		"unknown", hf_netlogon_workstation_fqdn, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_PTR,
		"unknown", hf_netlogon_workstation_site_name, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_PTR,
		"unknown", hf_netlogon_workstation_os, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_PTR,
		"unknown", hf_netlogon_unknown_string, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_PTR,
		"unknown", hf_netlogon_unknown_string, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_PTR,
		"unknown", hf_netlogon_unknown_string, -1);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_TYPE_48(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"TYPE_48:");
		tree = proto_item_add_subtree(item, ett_TYPE_48);
	}

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = netlogon_dissect_GUID(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_nt_PSID(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = netlogon_dissect_BLOB(tvb, offset,
		pinfo, tree, drep);

	offset = netlogon_dissect_BLOB(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_UNICODE_STRING_512(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;
	int i;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"UNICODE_STRING_512:");
		tree = proto_item_add_subtree(item, ett_UNICODE_STRING_512);
	}

	for(i=0;i<512;i++){
		offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_short, NULL);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_NETLOGON_SECURE_CHANNEL_TYPE(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
		offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
			hf_netlogon_secure_channel_type, NULL);

	return offset;
}

static int
netlogon_dissect_element_844_byte(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
		offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_char, NULL);

	return offset;
}

static int
netlogon_dissect_element_844_array(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_element_844_byte);

	return offset;
}

static int
netlogon_dissect_TYPE_50(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"TYPE_50:");
		tree = proto_item_add_subtree(item, ett_TYPE_50);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_element_844_array, NDR_POINTER_UNIQUE,
		"unknown", hf_netlogon_unknown_string, 0);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_TYPE_50_ptr(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_TYPE_50, NDR_POINTER_PTR,
		"TYPE_50 pointer: unknown_TYPE_50", -1, 0);
	
	return offset;
}

static int
netlogon_dissect_TYPE_50_ptr_ptr(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_TYPE_50_ptr, NDR_POINTER_PTR,
		"TYPE_50* pointer: unknown_TYPE_50", -1, 0);
	
	return offset;
}

static int
netlogon_dissect_element_861_byte(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
		offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_char, NULL);

	return offset;
}

static int
netlogon_dissect_element_861_array(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_element_861_byte);

	return offset;
}

static int
netlogon_dissect_TYPE_51(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"TYPE_51:");
		tree = proto_item_add_subtree(item, ett_TYPE_51);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_element_861_array, NDR_POINTER_UNIQUE,
		"unknown", hf_netlogon_unknown_string, 0);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_element_865_byte(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
		offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_char, NULL);

	return offset;
}

static int
netlogon_dissect_element_865_array(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_element_865_byte);

	return offset;
}

static int
netlogon_dissect_element_866_byte(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
		offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_char, NULL);

	return offset;
}

static int
netlogon_dissect_element_866_array(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_element_866_byte);

	return offset;
}

static int
netlogon_dissect_TYPE_52(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"TYPE_52:");
		tree = proto_item_add_subtree(item, ett_TYPE_52);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_element_865_array, NDR_POINTER_UNIQUE,
		"unknown", hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_element_866_array, NDR_POINTER_UNIQUE,
		"unknown", hf_netlogon_unknown_string, 0);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_TYPE_52_ptr(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_TYPE_52, NDR_POINTER_PTR,
		"TYPE_52 pointer: unknown_TYPE_52", -1, 0);
	return offset;
}

static int
netlogon_dissect_TYPE_52_ptr_ptr(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_TYPE_52_ptr, NDR_POINTER_PTR,
		"TYPE_52* pointer: unknown_TYPE_52", -1, 0);
	return offset;
}

static int
netlogon_dissect_NETLOGON_LEVEL(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;
	guint16 level;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"NETLOGON_LEVEL:");
		tree = proto_item_add_subtree(item, ett_NETLOGON_LEVEL);
	}

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_level, &level);

	switch(level){
	case 1:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_NETLOGON_INTERACTIVE_INFO, NDR_POINTER_PTR,
			"INTERACTIVE_INFO pointer:", -1, 0);
		break;
	case 2:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_NETLOGON_NETWORK_INFO, NDR_POINTER_PTR,
			"NETWORK_INFO pointer:", -1, 0);
		break;
	case 3:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_NETLOGON_INTERACTIVE_INFO, NDR_POINTER_PTR,
			"INTERACTIVE_INFO pointer:", -1, 0);
		break;
	case 5:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_NETLOGON_INTERACTIVE_INFO, NDR_POINTER_PTR,
			"INTERACTIVE_INFO pointer:", -1, 0);
		break;
	case 6:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_NETLOGON_NETWORK_INFO, NDR_POINTER_PTR,
			"NETWORK_INFO pointer:", -1, 0);
		break;
	case 7:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_NETLOGON_INTERACTIVE_INFO, NDR_POINTER_PTR,
			"INTERACTIVE_INFO pointer:", -1, 0);
		break;
	}

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_NETLOGON_VALIDATION(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;
	guint16 level;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"NETLOGON_VALIDATION:");
		tree = proto_item_add_subtree(item, ett_NETLOGON_VALIDATION);
	}

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_level, &level);

	switch(level){
	case 2:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_NETLOGON_VALIDATION_SAM_INFO1, NDR_POINTER_PTR,
			"NETLOGON_VALIDATION_SAM_INFO1 pointer:", -1, 0);
		break;
	case 3:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_NETLOGON_VALIDATION_SAM_INFO2, NDR_POINTER_PTR,
			"NETLOGON_VALIDATION_SAM_INFO2 pointer:", -1, 0);
		break;
	case 4:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_pointer_STRING, NDR_POINTER_PTR,
			"STRING pointer:", -1, 0);
		break;
	case 5:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_BLOB_ptr, NDR_POINTER_PTR,
			"BLOB pointer:", -1, 0);
		break;
	}

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
netlogon_dissect_TYPE_19(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;
	guint16 level;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"TYPE_19:");
		tree = proto_item_add_subtree(item, ett_TYPE_19);
	}

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_level, &level);

	ALIGN_TO_4_BYTES;
	switch(level){
	case 1:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_long, NULL);
		break;
	case 2:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_long, NULL);
		break;
	case 3:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_long, NULL);
		break;
	case 4:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_long, NULL);
		break;
	case 5:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_long, NULL);
		break;
	case 6:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_long, NULL);
		break;
	case 7:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_long, NULL);
		break;
	case 8:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_long, NULL);
		break;
	case 9:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_long, NULL);
		break;
	case 10:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_long, NULL);
		break;
	case 11:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_long, NULL);
		break;
	case 12:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_long, NULL);
		break;
	case 20:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_long, NULL);
		break;
	case 21:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_long, NULL);
		break;
	case 13:
		offset = dissect_ndr_nt_PSID(tvb, offset,
			pinfo, tree, drep);
		break;
	case 14:
		offset = dissect_ndr_nt_PSID(tvb, offset,
			pinfo, tree, drep);
		break;
	case 15:
		offset = dissect_ndr_nt_PSID(tvb, offset,
			pinfo, tree, drep);
		break;
	case 16:
		offset = dissect_ndr_nt_PSID(tvb, offset,
			pinfo, tree, drep);
		break;
	case 17:
		offset = dissect_ndr_nt_PSID(tvb, offset,
			pinfo, tree, drep);
		break;
	case 18:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_PTR,
			"unknown", hf_netlogon_unknown_string, -1);
		break;
	case 19:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_PTR,
			"unknown", hf_netlogon_unknown_string, -1);
		break;
	}

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
netlogon_dissect_NETLOGON_CONTROL_QUERY_INFO(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;
	guint32 level;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"NETLOGON_CONTROL_QUERY_INFO:");
		tree = proto_item_add_subtree(item, ett_NETLOGON_CONTROL_QUERY_INFO);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_level_long, &level);

	switch(level){
	case 5:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_PTR,
			"unknown", hf_netlogon_unknown_string, -1);
		break;
	case 6:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_PTR,
			"unknown", hf_netlogon_unknown_string, -1);
		break;
	case 0xfffe:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_long, NULL);
		break;
	case 8:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_PTR,
			"unknown", hf_netlogon_unknown_string, -1);
		break;
	}

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
netlogon_dissect_TYPE_44(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;
	guint32 level;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"TYPE_44:");
		tree = proto_item_add_subtree(item, ett_TYPE_44);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_level_long, &level);

	switch(level){
	case 1:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_long, NULL);
		break;
	}

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_TYPE_20(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;
	guint16 level;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"TYPE_20:");
		tree = proto_item_add_subtree(item, ett_TYPE_20);
	}

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_level, &level);

	ALIGN_TO_4_BYTES;
	switch(level){
	case 1:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_NETLOGON_SAM_DOMAIN_INFO, NDR_POINTER_PTR,
			"NETLOGON_SAM_DOMAIN_INFO pointer:", -1, 0);
		break;
	case 2:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_NETLOGON_SAM_GROUP_INFO, NDR_POINTER_PTR,
			"NETLOGON_SAM_GROUP_INFO pointer:", -1, 0);
		break;
	case 4:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_TYPE_23, NDR_POINTER_PTR,
			"TYPE_23 pointer:", -1, 0);
		break;
	case 5:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_NETLOGON_SAM_ACCOUNT_INFO, NDR_POINTER_PTR,
			"NETLOGON_SAM_ACCOUNT_INFO pointer:", -1, 0);
		break;
	case 7:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_TYPE_23, NDR_POINTER_PTR,
			"TYPE_23 pointer:", -1, 0);
		break;
	case 8:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_NETLOGON_SAM_GROUP_MEM_INFO, NDR_POINTER_PTR,
			"NETLOGON_SAM_GROUP_MEM_INFO pointer:", -1, 0);
		break;
	case 9:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_NETLOGON_SAM_ALIAS_INFO, NDR_POINTER_PTR,
			"NETLOGON_SAM_ALIAS_INFO pointer:", -1, 0);
		break;
	case 11:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_TYPE_23, NDR_POINTER_PTR,
			"TYPE_23 pointer:", -1, 0);
		break;
	case 12:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_NETLOGON_SAM_ALIAS_MEM_INFO, NDR_POINTER_PTR,
			"NETLOGON_SAM_ALIAS_MEM_INFO pointer:", -1, 0);
		break;
	case 13:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_TYPE_29, NDR_POINTER_PTR,
			"TYPE_29 pointer:", -1, 0);
		break;
	case 14:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_TYPE_31, NDR_POINTER_PTR,
			"TYPE_31 pointer:", -1, 0);
		break;
	case 16:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_TYPE_33, NDR_POINTER_PTR,
			"TYPE_33 pointer:", -1, 0);
		break;
	case 18:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_TYPE_34, NDR_POINTER_PTR,
			"TYPE_34 pointer:", -1, 0);
		break;
	case 20:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_TYPE_35, NDR_POINTER_PTR,
			"TYPE_35 pointer:", -1, 0);
		break;
	case 21:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_TYPE_35, NDR_POINTER_PTR,
			"TYPE_35 pointer:", -1, 0);
		break;
	case 22:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_TYPE_16, NDR_POINTER_PTR,
			"TYPE_16 pointer:", -1, 0);
		break;
	}

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_SAM_DELTA(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"SAM_DELTA:");
		tree = proto_item_add_subtree(item, ett_SAM_DELTA);
	}

	offset = netlogon_dissect_TYPE_19(tvb, offset,
		pinfo, tree, drep);

	offset = netlogon_dissect_TYPE_20(tvb, offset,
		pinfo, tree, drep);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_SAM_DELTA_array(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_SAM_DELTA);

	return offset;
}

static int
netlogon_dissect_SAM_DELTA_ARRAY(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"SAM_DELTA_ARRAY:");
		tree = proto_item_add_subtree(item, ett_SAM_DELTA_ARRAY);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_num_deltas, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_SAM_DELTA_array, NDR_POINTER_UNIQUE,
		"unknown", -1, 0);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_SAM_DELTA_ARRAY_ptr(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_SAM_DELTA_ARRAY, NDR_POINTER_PTR,
		"SAM_DELTA_ARRAY pointer: deltas", -1, 0);

	return offset;
}

static int
netlogon_dissect_LOGONSRV_HANDLE(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"Handle:", hf_netlogon_logonsrv_handle, -1);

	return offset;
}

static int
netlogon_dissect_NETLOGON_INFO(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;
	guint32 level;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"NETLOGON_INFO:");
		tree = proto_item_add_subtree(item, ett_NETLOGON_INFO);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_level_long, &level);

	switch(level){
	case 1:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_NETLOGON_INFO_1, NDR_POINTER_PTR,
			"NETLOGON_INFO_1 pointer:", -1, 0);
		break;
	case 2:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_NETLOGON_INFO_2, NDR_POINTER_PTR,
			"NETLOGON_INFO_2 pointer:", -1, 0);
		break;
	case 3:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_NETLOGON_INFO_3, NDR_POINTER_PTR,
			"NETLOGON_INFO_3 pointer:", -1, 0);
		break;
	case 4:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_NETLOGON_INFO_4, NDR_POINTER_PTR,
			"NETLOGON_INFO_4 pointer:", -1, 0);
		break;
	}

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_TYPE_45(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;
	guint32 level;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"TYPE_45:");
		tree = proto_item_add_subtree(item, ett_TYPE_45);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_level_long, &level);

	switch(level){
	case 1:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_TYPE_46, NDR_POINTER_PTR,
			"TYPE_46 pointer:", -1, 0);
		break;
	case 2:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_TYPE_46, NDR_POINTER_PTR,
			"TYPE_46 pointer:", -1, 0);
		break;
	}

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_TYPE_47(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;
	guint32 level;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"TYPE_47:");
		tree = proto_item_add_subtree(item, ett_TYPE_47);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_level_long, &level);

	switch(level){
	case 1:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_TYPE_48, NDR_POINTER_PTR,
			"TYPE_48 pointer:", -1, 0);
		break;
	case 2:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_UNICODE_MULTI, NDR_POINTER_PTR,
			"UNICODE_MULTI pointer:", -1, 0);
		break;
	}

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


static int
netlogon_dissect_function_00_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"unknown string", hf_netlogon_unknown_string, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"unknown string", hf_netlogon_unknown_string, -1);

	return offset;
}


static int
netlogon_dissect_function_00_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_TYPE_1_ptr, NDR_POINTER_REF,
		"TYPE_1* pointer: unknown_TYPE_1", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_function_01_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"unknown string", hf_netlogon_unknown_string, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"unknown string", hf_netlogon_unknown_string, -1);

	return offset;
}


static int
netlogon_dissect_function_01_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_TYPE_2, NDR_POINTER_REF,
		"TYPE_2 pointer: unknown_TYPE_2", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_netlogonsamlogon_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"Computer Name:", hf_netlogon_computer_name, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_UNIQUE,
		"NETLOGON_AUTHENTICATOR pointer: client_cred", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_UNIQUE,
		"NETLOGON_AUTHENTICATOR pointer: server_cred", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_LEVEL, NDR_POINTER_REF,
		"NETLOGON_LEVEL pointer: id_ctr", -1, 0);

	return offset;
}


static int
netlogon_dissect_netlogonsamlogon_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_UNIQUE,
		"NETLOGON_AUTHENTICATOR pointer: server_cred", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_VALIDATION, NDR_POINTER_REF,
		"NETLOGON_VALIDATION pointer: ctr", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_char, NDR_POINTER_REF,
		"BOOLEAN pointer: Authoritative", hf_netlogon_authoritative, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_netlogonsamlogoff_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"unknown string", hf_netlogon_unknown_string, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_UNIQUE,
		"NETLOGON_AUTHENTICATOR pointer: client_cred", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_UNIQUE,
		"NETLOGON_AUTHENTICATOR pointer: server_cred", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_LEVEL, NDR_POINTER_REF,
		"NETLOGON_LEVEL pointer: id_ctr", -1, 0);

	return offset;
}


static int
netlogon_dissect_netlogonsamlogoff_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_UNIQUE,
		"NETLOGON_AUTHENTICATOR pointer: server_cred", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_netserverreqchallenge_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"logon_client", hf_netlogon_client_name, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_CREDENTIAL, NDR_POINTER_REF,
		"NETLOGON_CREDENTIAL pointer: client_chal", -1, 0);

	return offset;
}


static int
netlogon_dissect_netserverreqchallenge_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_CREDENTIAL, NDR_POINTER_REF,
		"NETLOGON_CREDENTIAL pointer: server_chal", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_netserverauthenticate_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"acct_name", hf_netlogon_acct_name, -1);

	offset = netlogon_dissect_NETLOGON_SECURE_CHANNEL_TYPE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"computer_name", hf_netlogon_computer_name, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_CREDENTIAL, NDR_POINTER_REF,
		"NETLOGON_CREDENTIAL pointer: client_chal", -1, 0);

	return offset;
}


static int
netlogon_dissect_netserverauthenticate_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_CREDENTIAL, NDR_POINTER_REF,
		"NETLOGON_CREDENTIAL pointer: server_chal", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_netserverpasswordset_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"acct_name", hf_netlogon_acct_name, -1);

	offset = netlogon_dissect_NETLOGON_SECURE_CHANNEL_TYPE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"computer_name", hf_netlogon_computer_name, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_REF,
		"NETLOGON_AUTHENTICATOR pointer: client_cred", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_ENCRYPTED_LM_OWF_PASSWORD, NDR_POINTER_REF,
		"ENCRYPTED_LM_OWF_PASSWORD pointer: hashed_pwd", -1, 0);

	return offset;
}


static int
netlogon_dissect_netserverpasswordset_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_REF,
		"NETLOGON_AUTHENTICATOR pointer: server_cred", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_netsamdeltas_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* XXX idl file has LOGONSRV_HANDLE here, ms capture has string srv_name */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"srv_name", hf_netlogon_logon_srv, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"cli_name", hf_netlogon_cli_name, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_REF,
		"NETLOGON_AUTHENTICATOR pointer: client_creds", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_REF,
		"NETLOGON_AUTHENTICATOR pointer: server_creds", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_database_id, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_TYPE_16, NDR_POINTER_REF,
		"TYPE_16 pointer: dom_mod_count", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_max_size, NULL);
	return offset;
}


static int
netlogon_dissect_netsamdeltas_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_REF,
		"NETLOGON_AUTHENTICATOR pointer: server_creds", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_TYPE_16, NDR_POINTER_REF,
		"TYPE_16 pointer: dom_mod_count", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_SAM_DELTA_ARRAY_ptr, NDR_POINTER_REF,
		"SAM_DELTA_ARRAY_ptr pointer: deltas", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_function_08_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"srv_name", hf_netlogon_logon_srv, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"cli_name", hf_netlogon_cli_name, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_REF,
		"NETLOGON_AUTHENTICATOR pointer: client_creds", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_REF,
		"NETLOGON_AUTHENTICATOR pointer: server_creds", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_REF,
		"ULONG pointer: unknown_ULONG", hf_netlogon_unknown_long, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);
	return offset;
}


static int
netlogon_dissect_function_08_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_REF,
		"NETLOGON_AUTHENTICATOR pointer: server_creds", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_REF,
		"ULONG pointer: unknown_ULONG", hf_netlogon_unknown_long, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_SAM_DELTA_ARRAY_ptr, NDR_POINTER_REF,
		"SAM_DELTA_ARRAY* pointer: unknown_SAM_DELTA_ARRAY", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_function_09_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"unknown string", hf_netlogon_unknown_string, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_REF,
		"NETLOGON_AUTHENTICATOR pointer: unknown_NETLOGON_AUTHENTICATOR", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_REF,
		"NETLOGON_AUTHENTICATOR pointer: unknown_NETLOGON_AUTHENTICATOR", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_TYPE_36, NDR_POINTER_REF,
		"TYPE_36 pointer: unknown_TYPE_36", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);
	return offset;
}


static int
netlogon_dissect_function_09_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_REF,
		"NETLOGON_AUTHENTICATOR pointer: unknown_NETLOGON_AUTHENTICATOR", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_BYTE_array, NDR_POINTER_REF,
		"BYTE_array pointer: unknown_BYTE", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_REF,
		"ULONG pointer: unknown_ULONG", hf_netlogon_unknown_long, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_REF,
		"ULONG pointer: unknown_ULONG", hf_netlogon_unknown_long, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_TYPE_36, NDR_POINTER_REF,
		"TYPE_36 pointer: unknown_TYPE_36", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_function_0a_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"unknown string", hf_netlogon_unknown_string, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_REF,
		"NETLOGON_AUTHENTICATOR pointer: unknown_NETLOGON_AUTHENTICATOR", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_REF,
		"NETLOGON_AUTHENTICATOR pointer: unknown_NETLOGON_AUTHENTICATOR", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	return offset;
}


static int
netlogon_dissect_function_0a_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_REF,
		"NETLOGON_AUTHENTICATOR pointer: unknown_NETLOGON_AUTHENTICATOR", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_BYTE_array, NDR_POINTER_REF,
		"BYTE_array pointer: unknown_BYTE", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_REF,
		"ULONG pointer: unknown_ULONG", hf_netlogon_unknown_long, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_REF,
		"ULONG pointer: unknown_ULONG", hf_netlogon_unknown_long, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_REF,
		"ULONG pointer: unknown_ULONG", hf_netlogon_unknown_long, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_TYPE_36, NDR_POINTER_REF,
		"TYPE_36 pointer: unknown_TYPE_36", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_function_0b_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"unknown string", hf_netlogon_unknown_string, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"unknown string", hf_netlogon_unknown_string, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_WCHAR_ptr, NDR_POINTER_REF,
		"WCHAR* pointer: unknown string", -1, 0);
	return offset;
}


static int
netlogon_dissect_function_0b_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_WCHAR_ptr, NDR_POINTER_REF,
		"WCHAR* pointer: unknown string", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_netlogoncontrol_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_code, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_level, NULL);

	return offset;
}


static int
netlogon_dissect_netlogoncontrol_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_INFO, NDR_POINTER_REF,
		"NETLOGON_INFO pointer: unknown_NETLOGON_INFO", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_function_0d_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"unknown string", hf_netlogon_unknown_string, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_WCHAR_ptr, NDR_POINTER_REF,
		"WCHAR* pointer: unknown string", -1, 0);
	return offset;
}


static int
netlogon_dissect_function_0d_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_WCHAR_ptr, NDR_POINTER_REF,
		"WCHAR* pointer: unknown string", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_netlogoncontrol2_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_code, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_level, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_CONTROL_QUERY_INFO, NDR_POINTER_REF,
		"NETLOGON_CONTROL_QUERY_INFO pointer: unknown_NETLOGON_CONTROL_QUERY_INFO", -1, 0);

	return offset;
}


static int
netlogon_dissect_netlogoncontrol2_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_INFO, NDR_POINTER_REF,
		"NETLOGON_INFO pointer: unknown_NETLOGON_INFO", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_netserverauthenticate2_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"acct_name", hf_netlogon_acct_name, -1);

	offset = netlogon_dissect_NETLOGON_SECURE_CHANNEL_TYPE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"computer_name", hf_netlogon_computer_name, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_CREDENTIAL, NDR_POINTER_REF,
		"NETLOGON_CREDENTIAL pointer: client_chal", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_REF,
		"ULONG pointer: neg_flags", hf_netlogon_unknown_long, 0);
	return offset;
}


static int
netlogon_dissect_netserverauthenticate2_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_CREDENTIAL, NDR_POINTER_REF,
		"NETLOGON_CREDENTIAL pointer: server_chal", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_REF,
		"ULONG pointer: neg_flags", hf_netlogon_unknown_long, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_netdatabasesync2_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"unknown string", hf_netlogon_unknown_string, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_REF,
		"NETLOGON_AUTHENTICATOR pointer: unknown_NETLOGON_AUTHENTICATOR", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_REF,
		"NETLOGON_AUTHENTICATOR pointer: unknown_NETLOGON_AUTHENTICATOR", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_short, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_REF,
		"ULONG pointer: unknown_ULONG", hf_netlogon_unknown_long, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	return offset;
}


static int
netlogon_dissect_netdatabasesync2_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_REF,
		"NETLOGON_AUTHENTICATOR pointer: unknown_NETLOGON_AUTHENTICATOR", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_REF,
		"ULONG pointer: unknown_ULONG", hf_netlogon_unknown_long, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_SAM_DELTA_ARRAY_ptr, NDR_POINTER_REF,
		"SAM_DELTA_ARRAY* pointer: unknown_SAM_DELTA_ARRAY", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_function_11_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"unknown string", hf_netlogon_unknown_string, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"unknown string", hf_netlogon_unknown_string, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_REF,
		"NETLOGON_AUTHENTICATOR pointer: unknown_NETLOGON_AUTHENTICATOR", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_REF,
		"NETLOGON_AUTHENTICATOR pointer: unknown_NETLOGON_AUTHENTICATOR", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_BYTE_array, NDR_POINTER_REF,
		"BYTE pointer: unknown_BYTE", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	return offset;
}


static int
netlogon_dissect_function_11_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_REF,
		"NETLOGON_AUTHENTICATOR pointer: unknown_NETLOGON_AUTHENTICATOR", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_SAM_DELTA_ARRAY_ptr, NDR_POINTER_REF,
		"SAM_DELTA_ARRAY* pointer: unknown_SAM_DELTA_ARRAY", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_function_12_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_level, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_CONTROL_QUERY_INFO, NDR_POINTER_REF,
		"NETLOGON_CONTROL_QUERY_INFO pointer: unknown_NETLOGON_CONTROL_QUERY_INFO", -1, 0);

	return offset;
}


static int
netlogon_dissect_function_12_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_INFO, NDR_POINTER_REF,
		"NETLOGON_INFO pointer: unknown_NETLOGON_INFO", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_nettrusteddomainlist_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	return offset;
}


static int
netlogon_dissect_nettrusteddomainlist_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_UNICODE_MULTI, NDR_POINTER_REF,
		"UNICODE_MULTI pointer: trust_dom_name_list", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_dsrgetdcname2_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"domain", hf_netlogon_logon_dom, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_GUID, NDR_POINTER_UNIQUE,
		"GUID pointer: domain_guid", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_GUID, NDR_POINTER_UNIQUE,
		"GUID pointer: site_guid", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_flags, NULL);

	return offset;
}


static int
netlogon_dissect_dsrgetdcname2_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_DOMAIN_CONTROLLER_INFO_ptr, NDR_POINTER_REF,
		"DOMAIN_CONTROLLER_INFO* pointer: info", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_function_15_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"unknown string", hf_netlogon_unknown_string, -1);

	offset = netlogon_dissect_NETLOGON_AUTHENTICATOR(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_PTR,
		"NETLOGON_AUTHENTICATOR pointer: unknown_NETLOGON_AUTHENTICATOR", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	return offset;
}


static int
netlogon_dissect_function_15_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_PTR,
		"NETLOGON_AUTHENTICATOR pointer: unknown_NETLOGON_AUTHENTICATOR", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_TYPE_44, NDR_POINTER_PTR,
		"TYPE_44 pointer: unknown_TYPE_44", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_function_16_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	return offset;
}


static int
netlogon_dissect_function_16_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_function_17_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"unknown string", hf_netlogon_unknown_string, -1);

	return offset;
}


static int
netlogon_dissect_function_17_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_PTR,
		"ULONG pointer: unknown_ULONG", hf_netlogon_unknown_long, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_function_18_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_BYTE_array, NDR_POINTER_PTR,
		"BYTE pointer: unknown_BYTE", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	return offset;
}

static int
netlogon_dissect_BYTE_16_array(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	int i;

	for(i=0;i<16;i++){
		offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_char, NULL);
	}

	return offset;
}

static int
netlogon_dissect_function_18_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_BYTE_16_array, NDR_POINTER_PTR,
		"BYTE pointer: unknown_BYTE", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_function_19_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"unknown string", hf_netlogon_unknown_string, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_BYTE_array, NDR_POINTER_PTR,
		"BYTE pointer: unknown_BYTE", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	return offset;
}


static int
netlogon_dissect_function_19_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_BYTE_16_array, NDR_POINTER_PTR,
		"BYTE pointer: unknown_BYTE", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_netserverauthenticate3_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"acct_name", hf_netlogon_acct_name, -1);

	offset = netlogon_dissect_NETLOGON_SECURE_CHANNEL_TYPE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"computer_name", hf_netlogon_computer_name, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_CREDENTIAL, NDR_POINTER_REF,
		"NETLOGON_CREDENTIAL pointer: authenticator", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_PTR,
		"ULONG pointer: negotiate_flags", hf_netlogon_unknown_long, 0);

	return offset;
}


static int
netlogon_dissect_netserverauthenticate3_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_CREDENTIAL, NDR_POINTER_REF,
		"NETLOGON_CREDENTIAL pointer: unknown_NETLOGON_CREDENTIAL", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_PTR,
		"ULONG pointer: negotiate_flags", hf_netlogon_unknown_long, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_PTR,
		"ULONG pointer: unknown_ULONG", hf_netlogon_unknown_long, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_dsrgetdcname_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"domain", hf_netlogon_logon_dom, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_GUID, NDR_POINTER_UNIQUE,
		"GUID pointer: domain_guid", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"site", hf_netlogon_site_name, -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_flags, NULL);

	return offset;
}


static int
netlogon_dissect_dsrgetdcname_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_DOMAIN_CONTROLLER_INFO_ptr, NDR_POINTER_REF,
		"DOMAIN_CONTROLLER_INFO* pointer: info", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_dsrgetsitename_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	return offset;
}


static int
netlogon_dissect_dsrgetsitename_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"site", hf_netlogon_site_name, -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_function_1d_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"computer_name", hf_netlogon_computer_name, -1);

	offset = netlogon_dissect_NETLOGON_AUTHENTICATOR(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_PTR,
		"NETLOGON_AUTHENTICATOR pointer: unknown_NETLOGON_AUTHENTICATOR", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = netlogon_dissect_TYPE_45(tvb, offset,
		pinfo, tree, drep);

	return offset;
}


static int
netlogon_dissect_function_1d_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_PTR,
		"NETLOGON_AUTHENTICATOR pointer: unknown_NETLOGON_AUTHENTICATOR", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_TYPE_47, NDR_POINTER_PTR,
		"TYPE_47 pointer: unknown_TYPE_47", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_function_1e_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"unknown string", hf_netlogon_unknown_string, -1);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_short, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"unknown string", hf_netlogon_unknown_string, -1);

	offset = netlogon_dissect_NETLOGON_AUTHENTICATOR(tvb, offset,
		pinfo, tree, drep);

	offset = netlogon_dissect_UNICODE_STRING_512(tvb, offset,
		pinfo, tree, drep);

	return offset;
}


static int
netlogon_dissect_function_1e_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_PTR,
		"NETLOGON_AUTHENTICATOR pointer: unknown_NETLOGON_AUTHENTICATOR", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_netserverpasswordset2_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"acct_name", hf_netlogon_acct_name, -1);

	offset = netlogon_dissect_NETLOGON_SECURE_CHANNEL_TYPE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"computer_name", hf_netlogon_computer_name, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_REF,
		"NETLOGON_AUTHENTICATOR pointer: client_cred", -1, 0);

	return offset;
}


static int
netlogon_dissect_netserverpasswordset2_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_REF,
		"NETLOGON_AUTHENTICATOR pointer: server_cred", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_LM_OWF_PASSWORD, NDR_POINTER_REF,
		"LM_OWF_PASSWORD pointer: server_pwd", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_function_20_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_PTR,
		"unknown string", hf_netlogon_unknown_string, -1);

	offset = netlogon_dissect_NETLOGON_AUTHENTICATOR(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_BYTE_array, NDR_POINTER_PTR,
		"BYTE pointer: unknown_BYTE", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	return offset;
}


static int
netlogon_dissect_function_20_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_AUTHENTICATOR, NDR_POINTER_PTR,
		"NETLOGON_AUTHENTICATOR pointer: unknown_NETLOGON_AUTHENTICATOR", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_function_21_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_BYTE_array, NDR_POINTER_PTR,
		"BYTE pointer: unknown_BYTE", -1, 0);

	return offset;
}


static int
netlogon_dissect_function_21_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_TYPE_50_ptr_ptr, NDR_POINTER_REF,
		"TYPE_50** pointer: unknown_TYPE_50", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_function_22_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"unknown string", hf_netlogon_unknown_string, -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"unknown string", hf_netlogon_unknown_string, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_GUID, NDR_POINTER_UNIQUE,
		"GUID pointer: unknown_GUID", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"unknown string", hf_netlogon_unknown_string, -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	return offset;
}


static int
netlogon_dissect_function_22_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_DOMAIN_CONTROLLER_INFO_ptr_ptr, NDR_POINTER_REF,
		"DOMAIN_CONTROLLER_INFO** pointer: unknown_DOMAIN_CONTROLLER_INFO", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_function_23_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	return offset;
}


static int
netlogon_dissect_function_23_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_PTR,
		"unknown string", hf_netlogon_unknown_string, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_PTR,
		"ULONG pointer: unknown_ULONG", hf_netlogon_unknown_long, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_function_24_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	return offset;
}


static int
netlogon_dissect_function_24_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_TYPE_51, NDR_POINTER_PTR,
		"TYPE_51 pointer: unknown_TYPE_51", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_function_25_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_BYTE_array, NDR_POINTER_PTR,
		"BYTE pointer: unknown_BYTE", -1, 0);

	return offset;
}


static int
netlogon_dissect_function_25_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_TYPE_52_ptr_ptr, NDR_POINTER_REF,
		"TYPE_52** pointer: unknown_TYPE_52", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}


static int
netlogon_dissect_function_26_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"unknown string", hf_netlogon_unknown_string, -1);

	return offset;
}


static int
netlogon_dissect_function_26_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_TYPE_50_ptr_ptr, NDR_POINTER_REF,
		"TYPE_50** pointer: unknown_TYPE_50", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_function_27_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"unknown string", hf_netlogon_unknown_string, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"unknown string", hf_netlogon_unknown_string, -1);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_short, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_LEVEL, NDR_POINTER_PTR,
		"NETLOGON_LEVEL pointer: unknown_NETLOGON_LEVEL", -1, 0);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_short, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_PTR,
		"ULONG pointer: unknown_ULONG", hf_netlogon_unknown_long, 0);
	return offset;
}


static int
netlogon_dissect_function_27_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_NETLOGON_VALIDATION, NDR_POINTER_PTR,
		"NETLOGON_VALIDATION pointer: unknown_NETLOGON_VALIDATION", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_char, NDR_POINTER_PTR,
		"BOOLEAN pointer: unknown_BOOLEAN", hf_netlogon_unknown_char, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_PTR,
		"ULONG pointer: unknown_ULONG", hf_netlogon_unknown_long, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_dsrrolegetprimarydomaininformation_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	return offset;
}


static int
netlogon_dissect_dsrrolegetprimarydomaininformation_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_TYPE_51, NDR_POINTER_PTR,
		"TYPE_51 pointer: unknown_TYPE_51", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_dsrderegisterdnshostrecords_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"domain", hf_netlogon_logon_dom, -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_GUID, NDR_POINTER_UNIQUE,
		"GUID pointer: domain_guid", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_GUID, NDR_POINTER_UNIQUE,
		"GUID pointer: dsa_guid", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_PTR,
		"dns_host", hf_netlogon_dns_host, -1);

	return offset;
}


static int
netlogon_dissect_dsrderegisterdnshostrecords_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_rc, NULL);

	return offset;
}



static dcerpc_sub_dissector dcerpc_netlogon_dissectors[] = {
	{ NETLOGON_FUNCTION_00, "FUNCTION_00",
		netlogon_dissect_function_00_rqst,
		netlogon_dissect_function_00_reply },
	{ NETLOGON_FUNCTION_01, "FUNCTION_01",
		netlogon_dissect_function_01_rqst,
		netlogon_dissect_function_01_reply },
	{ NETLOGON_NETLOGONSAMLOGON, "NETLOGONSAMLOGON",
		netlogon_dissect_netlogonsamlogon_rqst,
		netlogon_dissect_netlogonsamlogon_reply },
	{ NETLOGON_NETLOGONSAMLOGOFF, "NETLOGONSAMLOGOFF",
		netlogon_dissect_netlogonsamlogoff_rqst,
		netlogon_dissect_netlogonsamlogoff_reply },
	{ NETLOGON_NETSERVERREQCHALLENGE, "NETSERVERREQCHALLENGE",
		netlogon_dissect_netserverreqchallenge_rqst,
		netlogon_dissect_netserverreqchallenge_reply },
	{ NETLOGON_NETSERVERAUTHENTICATE, "NETSERVERAUTHENTICATE",
		netlogon_dissect_netserverauthenticate_rqst,
		netlogon_dissect_netserverauthenticate_reply },
	{ NETLOGON_NETSERVERPASSWORDSET, "NETSERVERPASSWORDSET",
		netlogon_dissect_netserverpasswordset_rqst,
		netlogon_dissect_netserverpasswordset_reply },
	{ NETLOGON_NETSAMDELTAS, "NETSAMDELTAS",
		netlogon_dissect_netsamdeltas_rqst,
		netlogon_dissect_netsamdeltas_reply },
	{ NETLOGON_FUNCTION_08, "FUNCTION_08",
		netlogon_dissect_function_08_rqst,
		netlogon_dissect_function_08_reply },
	{ NETLOGON_FUNCTION_09, "FUNCTION_09",
		netlogon_dissect_function_09_rqst,
		netlogon_dissect_function_09_reply },
	{ NETLOGON_FUNCTION_0A, "FUNCTION_0A",
		netlogon_dissect_function_0a_rqst,
		netlogon_dissect_function_0a_reply },
	{ NETLOGON_FUNCTION_0B, "FUNCTION_0B",
		netlogon_dissect_function_0b_rqst,
		netlogon_dissect_function_0b_reply },
	{ NETLOGON_NETLOGONCONTROL, "NETLOGONCONTROL",
		netlogon_dissect_netlogoncontrol_rqst,
		netlogon_dissect_netlogoncontrol_reply },
	{ NETLOGON_FUNCTION_0D, "FUNCTION_0D",
		netlogon_dissect_function_0d_rqst,
		netlogon_dissect_function_0d_reply },
	{ NETLOGON_NETLOGONCONTROL2, "NETLOGONCONTROL2",
		netlogon_dissect_netlogoncontrol2_rqst,
		netlogon_dissect_netlogoncontrol2_reply },
	{ NETLOGON_NETSERVERAUTHENTICATE2, "NETSERVERAUTHENTICATE2",
		netlogon_dissect_netserverauthenticate2_rqst,
		netlogon_dissect_netserverauthenticate2_reply },
	{ NETLOGON_NETDATABASESYNC2, "NETDATABASESYNC2",
		netlogon_dissect_netdatabasesync2_rqst,
		netlogon_dissect_netdatabasesync2_reply },
	{ NETLOGON_FUNCTION_11, "FUNCTION_11",
		netlogon_dissect_function_11_rqst,
		netlogon_dissect_function_11_reply },
	{ NETLOGON_FUNCTION_12, "FUNCTION_12",
		netlogon_dissect_function_12_rqst,
		netlogon_dissect_function_12_reply },
	{ NETLOGON_NETTRUSTEDDOMAINLIST, "NETTRUSTEDDOMAINLIST",
		netlogon_dissect_nettrusteddomainlist_rqst,
		netlogon_dissect_nettrusteddomainlist_reply },
	{ NETLOGON_DSRGETDCNAME2, "DSRGETDCNAME2",
		netlogon_dissect_dsrgetdcname2_rqst,
		netlogon_dissect_dsrgetdcname2_reply },
	{ NETLOGON_FUNCTION_15, "FUNCTION_15",
		netlogon_dissect_function_15_rqst,
		netlogon_dissect_function_15_reply },
	{ NETLOGON_FUNCTION_16, "FUNCTION_16",
		netlogon_dissect_function_16_rqst,
		netlogon_dissect_function_16_reply },
	{ NETLOGON_FUNCTION_17, "FUNCTION_17",
		netlogon_dissect_function_17_rqst,
		netlogon_dissect_function_17_reply },
	{ NETLOGON_FUNCTION_18, "FUNCTION_18",
		netlogon_dissect_function_18_rqst,
		netlogon_dissect_function_18_reply },
	{ NETLOGON_FUNCTION_19, "FUNCTION_19",
		netlogon_dissect_function_19_rqst,
		netlogon_dissect_function_19_reply },
	{ NETLOGON_NETSERVERAUTHENTICATE3, "NETSERVERAUTHENTICATE3",
		netlogon_dissect_netserverauthenticate3_rqst,
		netlogon_dissect_netserverauthenticate3_reply },
	{ NETLOGON_DSRGETDCNAME, "DSRGETDCNAME",
		netlogon_dissect_dsrgetdcname_rqst,
		netlogon_dissect_dsrgetdcname_reply },
	{ NETLOGON_DSRGETSITENAME, "DSRGETSITENAME",
		netlogon_dissect_dsrgetsitename_rqst,
		netlogon_dissect_dsrgetsitename_reply },
	{ NETLOGON_FUNCTION_1D, "FUNCTION_1D",
		netlogon_dissect_function_1d_rqst,
		netlogon_dissect_function_1d_reply },
	{ NETLOGON_FUNCTION_1E, "FUNCTION_1E",
		netlogon_dissect_function_1e_rqst,
		netlogon_dissect_function_1e_reply },
	{ NETLOGON_NETSERVERPASSWORDSET2, "NETSERVERPASSWORDSET2",
		netlogon_dissect_netserverpasswordset2_rqst,
		netlogon_dissect_netserverpasswordset2_reply },
	{ NETLOGON_FUNCTION_20, "FUNCTION_20",
		netlogon_dissect_function_20_rqst,
		netlogon_dissect_function_20_reply },
	{ NETLOGON_FUNCTION_21, "FUNCTION_21",
		netlogon_dissect_function_21_rqst,
		netlogon_dissect_function_21_reply },
	{ NETLOGON_FUNCTION_22, "FUNCTION_22",
		netlogon_dissect_function_22_rqst,
		netlogon_dissect_function_22_reply },
	{ NETLOGON_FUNCTION_23, "FUNCTION_23",
		netlogon_dissect_function_23_rqst,
		netlogon_dissect_function_23_reply },
	{ NETLOGON_FUNCTION_24, "FUNCTION_24",
		netlogon_dissect_function_24_rqst,
		netlogon_dissect_function_24_reply },
	{ NETLOGON_FUNCTION_25, "FUNCTION_25",
		netlogon_dissect_function_25_rqst,
		netlogon_dissect_function_25_reply },
	{ NETLOGON_FUNCTION_26, "FUNCTION_26",
		netlogon_dissect_function_26_rqst,
		netlogon_dissect_function_26_reply },
	{ NETLOGON_FUNCTION_27, "FUNCTION_27",
		netlogon_dissect_function_27_rqst,
		netlogon_dissect_function_27_reply },
	{ NETLOGON_DSRROLEGETPRIMARYDOMAININFORMATION, "DSRROLEGETPRIMARYDOMAININFORMATION",
		netlogon_dissect_dsrrolegetprimarydomaininformation_rqst,
		netlogon_dissect_dsrrolegetprimarydomaininformation_reply },
	{ NETLOGON_DSRDEREGISTERDNSHOSTRECORDS, "DSRDEREGISTERDNSHOSTRECORDS",
		netlogon_dissect_dsrderegisterdnshostrecords_rqst,
		netlogon_dissect_dsrderegisterdnshostrecords_reply },
        {0, NULL, NULL,  NULL },
};

void 
proto_register_dcerpc_netlogon(void)
{

static hf_register_info hf[] = {
	{ &hf_netlogon_rc, { 
		"Return code", "netlogon.rc", FT_UINT32, BASE_HEX, 
		VALS(NT_errors), 0x0, "Netlogon return code", HFILL }},

	{ &hf_netlogon_param_ctrl, { 
		"Param Ctrl", "netlogon.param_ctrl", FT_UINT32, BASE_HEX, 
		NULL, 0x0, "Param ctrl", HFILL }},

	{ &hf_netlogon_logon_id, { 
		"Logon ID", "netlogon.logon_id", FT_UINT64, BASE_DEC, 
		NULL, 0x0, "Logon ID", HFILL }},

	{ &hf_netlogon_count, { 
		"Count", "netlogon.count", FT_UINT16, BASE_DEC, 
		NULL, 0x0, "", HFILL }},

	{ &hf_netlogon_credential, { 
		"Credential", "netlogon.credential", FT_BYTES, BASE_HEX, 
		NULL, 0x0, "Netlogon credential", HFILL }},

	{ &hf_netlogon_cypher_block, { 
		"Cypher Block", "netlogon.cypher_block", FT_BYTES, BASE_HEX, 
		NULL, 0x0, "Netlogon cypher block", HFILL }},

	{ &hf_netlogon_lm_owf_password, { 
		"LM Pwd", "netlogon.lm_owf_pwd", FT_BYTES, BASE_HEX, 
		NULL, 0x0, "LanManager OWF Password", HFILL }},

	{ &hf_netlogon_user_session_key, { 
		"User Session Key", "netlogon.user_session_key", FT_BYTES, BASE_HEX, 
		NULL, 0x0, "User Session Key", HFILL }},

	{ &hf_netlogon_encrypted_lm_owf_password, { 
		"Encrypted LM Pwd", "netlogon.lm_owf_pwd.encrypted", FT_BYTES, BASE_HEX, 
		NULL, 0x0, "Encrypted LanManager OWF Password", HFILL }},

	{ &hf_netlogon_nt_owf_password, { 
		"NT Pwd", "netlogon.nt_owf_pwd", FT_BYTES, BASE_HEX, 
		NULL, 0x0, "NT OWF Password", HFILL }},

	{ &hf_netlogon_blob, { 
		"BLOB", "netlogon.blob", FT_BYTES, BASE_HEX, 
		NULL, 0x0, "BLOB", HFILL }},

	{ &hf_netlogon_len, {
		"Len", "netlogon.len", FT_UINT32, BASE_DEC,
		NULL, 0, "Length", HFILL }},

	{ &hf_netlogon_status, {
		"Status", "netlogon.status", FT_UINT32, BASE_DEC,
		NULL, 0, "Status", HFILL }},

	{ &hf_netlogon_attrs, {
		"Attributes", "netlogon.attrs", FT_UINT32, BASE_HEX,
		NULL, 0, "Attributes", HFILL }},

	{ &hf_netlogon_unknown_string,
		{ "Unknwon string", "netlogon.unknown_string", FT_STRING, BASE_NONE,
		NULL, 0, "Unknown string. If you know what this is, contact ethereal developers.", HFILL }},
	{ &hf_netlogon_unknown_long,
		{ "Unknown long", "netlogon.unknown.long", FT_UINT32, BASE_HEX, 
		NULL, 0x0, "Unknown long. If you know what this is, contact ethereal developers.", HFILL }},
	{ &hf_netlogon_unknown_short,
		{ "Unknown short", "netlogon.unknown.short", FT_UINT16, BASE_HEX, 
		NULL, 0x0, "Unknown short. If you know what this is, contact ethereal developers.", HFILL }},

	{ &hf_netlogon_unknown_char,
		{ "Unknown char", "netlogon.unknown.char", FT_UINT8, BASE_HEX, 
		NULL, 0x0, "Unknown char. If you know what this is, contact ethereal developers.", HFILL }},

	{ &hf_netlogon_unknown_time,
		{ "Unknown time", "netlogon.unknown.time", FT_ABSOLUTE_TIME, BASE_NONE, 
		NULL, 0x0, "Unknown time. If you know what this is, contact ethereal developers.", HFILL }},

	{ &hf_netlogon_acct_expiry_time,
		{ "Acct Expiry Time", "netlogon.acct.expiry_time", FT_ABSOLUTE_TIME, BASE_NONE, 
		NULL, 0x0, "When this account will expire", HFILL }},

	{ &hf_netlogon_nt_pwd_present,
		{ "NT PWD Present", "netlogon.nt_pwd_present", FT_UINT8, BASE_HEX, 
		NULL, 0x0, "Is NT password present for this account?", HFILL }},

	{ &hf_netlogon_lm_pwd_present,
		{ "LM PWD Present", "netlogon.lm_pwd_present", FT_UINT8, BASE_HEX, 
		NULL, 0x0, "Is LanManager password present for this account?", HFILL }},

	{ &hf_netlogon_pwd_expired,
		{ "PWD Expired", "netlogon.pwd_expired", FT_UINT8, BASE_HEX, 
		NULL, 0x0, "Whether this password has expired or not", HFILL }},

	{ &hf_netlogon_num_pwd_pairs,
		{ "Num PWD Pairs", "netlogon.num_pwd_pairs", FT_UINT8, BASE_DEC, 
		NULL, 0x0, "Number of password pairs. Password history length?", HFILL }},

	{ &hf_netlogon_authoritative,
		{ "Authoritative", "netlogon.authoritative", FT_UINT8, BASE_DEC, 
		NULL, 0x0, "", HFILL }},

	{ &hf_netlogon_nt_chal_resp,
		{ "NT Chal resp", "netlogon.nt_chal_resp", FT_BYTES, BASE_HEX,
		NULL, 0, "Challenge response for NT authentication", HFILL }},

	{ &hf_netlogon_lm_chal_resp,
		{ "LM Chal resp", "netlogon.lm_chal_resp", FT_BYTES, BASE_HEX,
		NULL, 0, "Challenge response for LM authentication", HFILL }},

	{ &hf_netlogon_lsa_secret,
		{ "LSA Secret", "netlogon.lsa.secret", FT_BYTES, BASE_HEX,
		NULL, 0, "", HFILL }},

	{ &hf_netlogon_lsa_sd_data,
		{ "Sec Desc", "netlogon.lsa.sd.data", FT_BYTES, BASE_HEX,
		NULL, 0, "LSA security descriptor data", HFILL }},

	{ &hf_netlogon_acct_name,
		{ "Acct Name", "netlogon.acct_name", FT_STRING, BASE_NONE,
		NULL, 0, "Account Name", HFILL }},

	{ &hf_netlogon_acct_desc,
		{ "Acct Desc", "netlogon.acct_desc", FT_STRING, BASE_NONE,
		NULL, 0, "Account Description", HFILL }},

	{ &hf_netlogon_group_desc,
		{ "Group Desc", "netlogon.group_desc", FT_STRING, BASE_NONE,
		NULL, 0, "Group Description", HFILL }},

	{ &hf_netlogon_full_name,
		{ "Full Name", "netlogon.full_name", FT_STRING, BASE_NONE,
		NULL, 0, "Full Name", HFILL }},

	{ &hf_netlogon_comment,
		{ "Comment", "netlogon.comment", FT_STRING, BASE_NONE,
		NULL, 0, "Comment", HFILL }},

	{ &hf_netlogon_parameters,
		{ "Parameters", "netlogon.parameters", FT_STRING, BASE_NONE,
		NULL, 0, "Parameters", HFILL }},

	{ &hf_netlogon_logon_script,
		{ "Logon Script", "netlogon.logon_script", FT_STRING, BASE_NONE,
		NULL, 0, "Logon Script", HFILL }},

	{ &hf_netlogon_profile_path,
		{ "Profile Path", "netlogon.profile_path", FT_STRING, BASE_NONE,
		NULL, 0, "Profile Path", HFILL }},

	{ &hf_netlogon_home_dir,
		{ "Home Dir", "netlogon.home_dir", FT_STRING, BASE_NONE,
		NULL, 0, "Home Directory", HFILL }},

	{ &hf_netlogon_dir_drive,
		{ "Dir Drive", "netlogon.dir_drive", FT_STRING, BASE_NONE,
		NULL, 0, "Drive letter for home directory", HFILL }},

	{ &hf_netlogon_logon_srv,
		{ "Server", "netlogon.server", FT_STRING, BASE_NONE,
		NULL, 0, "Server", HFILL }},

	{ &hf_netlogon_logon_dom,
		{ "Domain", "netlogon.domain", FT_STRING, BASE_NONE,
		NULL, 0, "Domain", HFILL }},

	{ &hf_netlogon_computer_name,
		{ "Computer Name", "netlogon.computer_name", FT_STRING, BASE_NONE,
		NULL, 0, "Computer Name", HFILL }},

	{ &hf_netlogon_site_name,
		{ "Site Name", "netlogon.site_name", FT_STRING, BASE_NONE,
		NULL, 0, "Site Name", HFILL }},

	{ &hf_netlogon_dc_name,
		{ "DC Name", "netlogon.dc.name", FT_STRING, BASE_NONE,
		NULL, 0, "DC Name", HFILL }},

	{ &hf_netlogon_dc_site_name,
		{ "DC Site Name", "netlogon.dc.site_name", FT_STRING, BASE_NONE,
		NULL, 0, "DC Site Name", HFILL }},

	{ &hf_netlogon_dns_forest_name,
		{ "DNS Forest Name", "netlogon.dns.forest_name", FT_STRING, BASE_NONE,
		NULL, 0, "DNS Forest Name", HFILL }},

	{ &hf_netlogon_dc_address,
		{ "DC Address", "netlogon.dc.address", FT_STRING, BASE_NONE,
		NULL, 0, "DC Address", HFILL }},

	{ &hf_netlogon_dc_address_type,
		{ "DC Address Type", "netlogon.dc.address_type", FT_UINT32, BASE_DEC,
		NULL, 0, "DC Address Type", HFILL }},

	{ &hf_netlogon_client_name,
		{ "Client Name", "netlogon.client.name", FT_STRING, BASE_NONE,
		NULL, 0, "Client Name", HFILL }},

	{ &hf_netlogon_client_site_name,
		{ "Client Site Name", "netlogon.client.site_name", FT_STRING, BASE_NONE,
		NULL, 0, "Client Site Name", HFILL }},

	{ &hf_netlogon_workstation_site_name,
		{ "Wkst Site Name", "netlogon.wkst.site_name", FT_STRING, BASE_NONE,
		NULL, 0, "Workstation Site Name", HFILL }},

	{ &hf_netlogon_workstation_os,
		{ "Wkst OS", "netlogon.wkst.os", FT_STRING, BASE_NONE,
		NULL, 0, "Workstation OS", HFILL }},

	{ &hf_netlogon_workstations,
		{ "Workstations", "netlogon.wksts", FT_STRING, BASE_NONE,
		NULL, 0, "Workstations", HFILL }},

	{ &hf_netlogon_workstation_fqdn,
		{ "Wkst FQDN", "netlogon.wkst.fqdn", FT_STRING, BASE_NONE,
		NULL, 0, "Workstation FQDN", HFILL }},

	{ &hf_netlogon_group_name,
		{ "Group Name", "netlogon.group_name", FT_STRING, BASE_NONE,
		NULL, 0, "Group Name", HFILL }},

	{ &hf_netlogon_alias_name,
		{ "Alias Name", "netlogon.alias_name", FT_STRING, BASE_NONE,
		NULL, 0, "Alias Name", HFILL }},

	{ &hf_netlogon_cli_name,
		{ "CLI Name", "netlogon.cli_name", FT_STRING, BASE_NONE,
		NULL, 0, "CLI Name", HFILL }},

	{ &hf_netlogon_dns_host,
		{ "DNS Host", "netlogon.dns_host", FT_STRING, BASE_NONE,
		NULL, 0, "DNS Host", HFILL }},

	{ &hf_netlogon_trusted_domain_name,
		{ "Trusted Domain", "netlogon.trusted_domain", FT_STRING, BASE_NONE,
		NULL, 0, "Trusted Domain Name", HFILL }},

	{ &hf_netlogon_trusted_dc_name,
		{ "Trusted DC", "netlogon.trusted_dc", FT_STRING, BASE_NONE,
		NULL, 0, "Trusted DC", HFILL }},

	{ &hf_netlogon_logonsrv_handle,
		{ "Handle", "netlogon.handle", FT_STRING, BASE_NONE,
		NULL, 0, "Logon Srv Handle", HFILL }},

	{ &hf_netlogon_logon_count,
		{ "Logon Count", "netlogon.logon_count", FT_UINT16, BASE_DEC, 
		NULL, 0x0, "Number of successful logins", HFILL }},

	{ &hf_netlogon_bad_pw_count,
		{ "Bad PW Count", "netlogon.bad_pw_count", FT_UINT16, BASE_DEC, 
		NULL, 0x0, "Number of failed logins", HFILL }},

	{ &hf_netlogon_country,
		{ "Country", "netlogon.country", FT_UINT16, BASE_DEC, 
		NULL, 0x0, "Country setting for this account", HFILL }},

	{ &hf_netlogon_codepage,
		{ "Codepage", "netlogon.codepage", FT_UINT16, BASE_DEC, 
		NULL, 0x0, "Codepage setting for this account", HFILL }},

	{ &hf_netlogon_level,
		{ "Level", "netlogon.level", FT_UINT16, BASE_DEC, 
		NULL, 0x0, "Which option of the union is represented here", HFILL }},

	{ &hf_netlogon_secure_channel_type,
		{ "Sec Chn Type", "netlogon.sec_chn_type", FT_UINT16, BASE_DEC, 
		NULL, 0x0, "Secure Channel Type", HFILL }},

	{ &hf_netlogon_blob_size,
		{ "Size", "netlogon.blob.size", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Size in bytes of BLOB", HFILL }},

	{ &hf_netlogon_level_long,
		{ "Level", "netlogon.level32", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Which option of the union is represented here", HFILL }},

	{ &hf_netlogon_timestamp,
		{ "Timestamp", "netlogon.timestamp", FT_UINT32, BASE_HEX, 
		NULL, 0x0, "Some sort of timestamp", HFILL }},

	{ &hf_netlogon_user_rid,
		{ "User RID", "netlogon.rid", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "", HFILL }},

	{ &hf_netlogon_alias_rid,
		{ "Alias RID", "netlogon.alias_rid", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "", HFILL }},

	{ &hf_netlogon_group_rid,
		{ "Group RID", "netlogon.group_rid", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "", HFILL }},

	{ &hf_netlogon_num_rids,
		{ "Num RIDs", "netlogon.num_rids", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Number of RIDs", HFILL }},

	{ &hf_netlogon_num_other_groups,
		{ "Num Other Groups", "netlogon.num_other_groups", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "", HFILL }},

	{ &hf_netlogon_flags,
		{ "Flags", "netlogon.flags", FT_UINT32, BASE_HEX, 
		NULL, 0x0, "", HFILL }},

	{ &hf_netlogon_user_flags,
		{ "User Flags", "netlogon.user_flags", FT_UINT32, BASE_HEX, 
		NULL, 0x0, "", HFILL }},

	{ &hf_netlogon_database_id,
		{ "Database Id", "netlogon.database_id", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Database Id", HFILL }},

	{ &hf_netlogon_max_size,
		{ "Max Size", "netlogon.max_size", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Max Size of database", HFILL }},

	{ &hf_netlogon_num_deltas,
		{ "Num Deltas", "netlogon.num_deltas", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Number of SAM Deltas in array", HFILL }},

	{ &hf_netlogon_logon_attempts,
		{ "Logon Attempts", "netlogon.logon_attempts", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Number of logon attempts", HFILL }},

	{ &hf_netlogon_lsa_sd_size,
		{ "Size", "netlogon.lsa_sd_size", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Size of lsa security descriptor", HFILL }},

	{ &hf_netlogon_logon_time,
		{ "Logon Time", "netlogon.logon_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Time for last time this user logged on", HFILL }},

	{ &hf_netlogon_kickoff_time,
		{ "Kickoff Time", "netlogon.kickoff_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Time when this user will be kicked off", HFILL }},

	{ &hf_netlogon_logoff_time,
		{ "Logoff Time", "netlogon.logoff_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Time for last time this user logged off", HFILL }},

	{ &hf_netlogon_pwd_last_set_time,
		{ "PWD Last Set", "netlogon.pwd_last_set_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Last time this users password was changed", HFILL }},

	{ &hf_netlogon_pwd_can_change_time,
		{ "PWD Can Change", "netlogon.pwd_can_change_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "When this users password may be changed", HFILL }},

	{ &hf_netlogon_pwd_must_change_time,
		{ "PWD Must Change", "netlogon.pwd_must_change_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "When this users password must be changed", HFILL }},

	};

        static gint *ett[] = {
                &ett_dcerpc_netlogon,
		&ett_NETLOGON_SECURITY_DESCRIPTOR,
		&ett_TYPE_1,
		&ett_TYPE_2,
		&ett_CYPHER_BLOCK,
		&ett_NETLOGON_AUTHENTICATOR,
		&ett_NETLOGON_LOGON_IDENTITY_INFO,
		&ett_NETLOGON_INTERACTIVE_INFO,
		&ett_NETLOGON_NETWORK_INFO,
		&ett_NETLOGON_VALIDATION_SAM_INFO1,
		&ett_NETLOGON_VALIDATION_SAM_INFO2,
		&ett_TYPE_16,
		&ett_NETLOGON_SAM_DOMAIN_INFO,
		&ett_NETLOGON_SAM_GROUP_INFO,
		&ett_TYPE_23,
		&ett_NETLOGON_SAM_ACCOUNT_INFO,
		&ett_NETLOGON_SAM_GROUP_MEM_INFO,
		&ett_NETLOGON_SAM_ALIAS_INFO,
		&ett_NETLOGON_SAM_ALIAS_MEM_INFO,
		&ett_TYPE_30,
		&ett_TYPE_29,
		&ett_TYPE_31,
		&ett_TYPE_32,
		&ett_TYPE_33,
		&ett_TYPE_34,
		&ett_TYPE_35,
		&ett_SAM_DELTA,
		&ett_SAM_DELTA_ARRAY,
		&ett_TYPE_36,
		&ett_NETLOGON_INFO_1,
		&ett_NETLOGON_INFO_2,
		&ett_NETLOGON_INFO_3,
		&ett_NETLOGON_INFO_4,
		&ett_UNICODE_MULTI,
		&ett_DOMAIN_CONTROLLER_INFO,
		&ett_TYPE_46,
		&ett_TYPE_48,
		&ett_UNICODE_STRING_512,
		&ett_TYPE_50,
		&ett_TYPE_51,
		&ett_TYPE_52,
		&ett_NETLOGON_LEVEL,
		&ett_NETLOGON_VALIDATION,
		&ett_TYPE_19,
		&ett_NETLOGON_CONTROL_QUERY_INFO,
		&ett_TYPE_44,
		&ett_TYPE_20,
		&ett_NETLOGON_INFO,
		&ett_TYPE_45,
		&ett_TYPE_47,
		&ett_NETLOGON_CREDENTIAL,
		&ett_GUID,
		&ett_ENC_LM_OWF_PASSWORD,
		&ett_LM_OWF_PASSWORD,
		&ett_NT_OWF_PASSWORD,
		&ett_GROUP_MEMBERSHIP,
		&ett_USER_SESSION_KEY,
		&ett_BLOB,
		&ett_rid_array,
		&ett_attrib_array,
		&ett_netlogon_lsa_sd_data,
        };

        proto_dcerpc_netlogon = proto_register_protocol(
                "Microsoft Network Logon", "NETLOGON", "rpc_netlogon");

        proto_register_field_array (proto_dcerpc_netlogon, hf, array_length (hf));
        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dcerpc_netlogon(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_netlogon, ett_dcerpc_netlogon, 
                         &uuid_dcerpc_netlogon, ver_dcerpc_netlogon, 
                         dcerpc_netlogon_dissectors);
}
