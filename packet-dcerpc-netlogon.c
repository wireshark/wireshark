/* packet-dcerpc-netlogon.c
 * Routines for SMB \\PIPE\\NETLOGON packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 *  2002 structure and command dissectors by Ronnie Sahlberg
 *
 * $Id: packet-dcerpc-netlogon.c,v 1.38 2002/07/07 11:04:09 sahlberg Exp $
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
#include "packet-dcerpc-lsa.h"

static int proto_dcerpc_netlogon = -1;
static int hf_netlogon_opnum = -1;
static int hf_netlogon_rc = -1;
static int hf_netlogon_len = -1;
static int hf_netlogon_sensitive_data_flag = -1;
static int hf_netlogon_sensitive_data_len = -1;
static int hf_netlogon_sensitive_data = -1;
static int hf_netlogon_security_information = -1;
static int hf_netlogon_dummy = -1;
static int hf_netlogon_minworkingsetsize = -1;
static int hf_netlogon_maxworkingsetsize = -1;
static int hf_netlogon_pagedpoollimit = -1;
static int hf_netlogon_pagefilelimit = -1;
static int hf_netlogon_timelimit = -1;
static int hf_netlogon_nonpagedpoollimit = -1;
static int hf_netlogon_pac_size = -1;
static int hf_netlogon_pac_data = -1;
static int hf_netlogon_auth_size = -1;
static int hf_netlogon_auth_data = -1;
static int hf_netlogon_priv = -1;
static int hf_netlogon_privilege_entries = -1;
static int hf_netlogon_privilege_control = -1;
static int hf_netlogon_privilege_name = -1;
static int hf_netlogon_systemflags = -1;
static int hf_netlogon_status = -1;
static int hf_netlogon_attrs = -1;
static int hf_netlogon_count = -1;
static int hf_netlogon_minpasswdlen = -1;
static int hf_netlogon_passwdhistorylen = -1;
static int hf_netlogon_level16 = -1;
static int hf_netlogon_validation_level = -1;
static int hf_netlogon_level = -1;
static int hf_netlogon_challenge = -1;
static int hf_netlogon_reserved = -1;
static int hf_netlogon_audit_retention_period = -1;
static int hf_netlogon_auditing_mode = -1;
static int hf_netlogon_max_audit_event_count = -1;
static int hf_netlogon_event_audit_option = -1;
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
static int hf_netlogon_last_logon = -1;
static int hf_netlogon_last_logoff = -1;
static int hf_netlogon_logon_count = -1;
static int hf_netlogon_logon_count16 = -1;
static int hf_netlogon_bad_pw_count = -1;
static int hf_netlogon_bad_pw_count16 = -1;
static int hf_netlogon_user_rid = -1;
static int hf_netlogon_alias_rid = -1;
static int hf_netlogon_group_rid = -1;
static int hf_netlogon_logon_srv = -1;
static int hf_netlogon_principal = -1;
static int hf_netlogon_logon_dom = -1;
static int hf_netlogon_domain_name = -1;
static int hf_netlogon_domain_create_time = -1;
static int hf_netlogon_domain_modify_time = -1;
static int hf_netlogon_db_modify_time = -1;
static int hf_netlogon_db_create_time = -1;
static int hf_netlogon_oem_info = -1;
static int hf_netlogon_trusted_domain_name = -1;
static int hf_netlogon_num_rids = -1;
static int hf_netlogon_num_controllers = -1;
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
static int hf_netlogon_workstation = -1;
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
static int hf_netlogon_auth_flags = -1;
static int hf_netlogon_pwd_expired = -1;
static int hf_netlogon_nt_pwd_present = -1;
static int hf_netlogon_lm_pwd_present = -1;
static int hf_netlogon_code = -1;
static int hf_netlogon_database_id = -1;
static int hf_netlogon_max_size = -1;
static int hf_netlogon_max_log_size = -1;
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
static int hf_netlogon_delta_type = -1;

static gint ett_dcerpc_netlogon = -1;
static gint ett_QUOTA_LIMITS = -1;
static gint ett_TYPE_16 = -1;
static gint ett_IDENTITY_INFO = -1;
static gint ett_TYPE_34 = -1;
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
static gint ett_TYPE_19 = -1;
static gint ett_NETLOGON_CONTROL_QUERY_INFO = -1;
static gint ett_TYPE_44 = -1;
static gint ett_TYPE_20 = -1;
static gint ett_NETLOGON_INFO = -1;
static gint ett_TYPE_45 = -1;
static gint ett_TYPE_47 = -1;
static gint ett_GUID = -1;
static gint ett_LM_OWF_PASSWORD = -1;
static gint ett_NT_OWF_PASSWORD = -1;
static gint ett_GROUP_MEMBERSHIP = -1;
static gint ett_BLOB = -1;

static e_uuid_t uuid_dcerpc_netlogon = {
        0x12345678, 0x1234, 0xabcd,
        { 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0xcf, 0xfb }
};

static guint16 ver_dcerpc_netlogon = 1;



static int
netlogon_dissect_LOGONSRV_HANDLE(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"Server Handle", hf_netlogon_logonsrv_handle, 0);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL    [unique][string] wchar_t *effective_name;
 * IDL    long priv;
 * IDL    long auth_flags;
 * IDL    long logon_count;
 * IDL    long bad_pw_count;
 * IDL    long last_logon;
 * IDL    long last_logoff;
 * IDL    long logoff_time;
 * IDL    long kickoff_time;
 * IDL    long password_age;
 * IDL    long pw_can_change;
 * IDL    long pw_must_change;
 * IDL    [unique][string] wchar_t *computer;
 * IDL    [unique][string] wchar_t *domain;
 * IDL    [unique][string] wchar_t *script_path;
 * IDL    long reserved;
 */
static int
netlogon_dissect_VALIDATION_UAS_INFO(tvbuff_t *tvb, int offset,
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
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"Effective Account", hf_netlogon_acct_name, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_priv, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_auth_flags, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_count, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_bad_pw_count, NULL);

	proto_tree_add_text(tree, tvb, offset, 4, "Last Logon: unknown time format");
	offset+= 4;

	proto_tree_add_text(tree, tvb, offset, 4, "Last Logoff: unknown time format");
	offset+= 4;

	proto_tree_add_text(tree, tvb, offset, 4, "Logoff Time: unknown time format");
	offset+= 4;

	proto_tree_add_text(tree, tvb, offset, 4, "Kickoff Time: unknown time format");
	offset+= 4;

	proto_tree_add_text(tree, tvb, offset, 4, "Password Age: unknown time format");
	offset+= 4;

	proto_tree_add_text(tree, tvb, offset, 4, "PW Can Change: unknown time format");
	offset+= 4;

	proto_tree_add_text(tree, tvb, offset, 4, "PW Must Change: unknown time format");
	offset+= 4;

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"Computer", hf_netlogon_computer_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"Domain", hf_netlogon_domain_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"Script", hf_netlogon_logon_script, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	return offset;
}

/*
 * IDL long NetLogonUasLogon(
 * IDL      [in][unique][string] wchar_t *ServerName,
 * IDL      [in][ref][string] wchar_t *UserName,
 * IDL      [in][ref][string] wchar_t *Workstation,
 * IDL      [out][unique] VALIDATION_UAS_INFO *info
 * IDL );
 */
static int
netlogon_dissect_netlogonuaslogon_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"Account", hf_netlogon_acct_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"Workstation", hf_netlogon_workstation, 0);

	return offset;
}


static int
netlogon_dissect_netlogonuaslogon_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_VALIDATION_UAS_INFO, NDR_POINTER_UNIQUE,
		"VALIDATION_UAS_INFO", -1, 0);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long duration;
 * IDL   short logon_count;
 * IDL } LOGOFF_UAS_INFO;
 */
static int
netlogon_dissect_LOGOFF_UAS_INFO(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	proto_tree_add_text(tree, tvb, offset, 4, "Duration: unknown time format");
	offset+= 4;

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_count16, NULL);

	return offset;
}

/*
 * IDL long NetLogonUasLogoff(
 * IDL      [in][unique][string] wchar_t *ServerName,
 * IDL      [in][ref][string] wchar_t *UserName,
 * IDL      [in][ref][string] wchar_t *Workstation,
 * IDL      [out][ref] LOGOFF_UAS_INFO *info
 * IDL );
 */
static int
netlogon_dissect_netlogonuaslogoff_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"Account", hf_netlogon_acct_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"Workstation", hf_netlogon_workstation, 0);

	return offset;
}


static int
netlogon_dissect_netlogonuaslogoff_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_LOGOFF_UAS_INFO, NDR_POINTER_REF,
		"LOGOFF_UAS_INFO", -1, 0);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}




/*
 * IDL typedef struct {
 * IDL   UNICODESTRING LogonDomainName;
 * IDL   long ParameterControl;
 * IDL   uint64 LogonID;
 * IDL   UNICODESTRING UserName;
 * IDL   UNICODESTRING Workstation;
 * IDL } LOGON_IDENTITY_INFO;
 */
static int
netlogon_dissect_LOGON_IDENTITY_INFO(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"IDENTITY_INFO:");
		tree = proto_item_add_subtree(item, ett_IDENTITY_INFO);
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
		hf_netlogon_workstation, 0);

#ifdef REMOVED
	/* NetMon does not recognize these bytes. Ill comment them out until someone complains */
	/* XXX 8 extra bytes here */
	/* there were 8 extra bytes, either here or in NETWORK_INFO that does not match
	   the idl file. Could be a bug in either the NETLOGON implementation or in the
	   idl file.
	*/
	offset = netlogon_dissect_8_unknown_bytes(tvb, offset, pinfo, tree, drep);
#endif

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


/*
 * IDL typedef struct {
 * IDL   char password[16];
 * IDL } LM_OWF_PASSWORD;
 */
static int
netlogon_dissect_LM_OWF_PASSWORD(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep _U_)
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

/*
 * IDL typedef struct {
 * IDL   char password[16];
 * IDL } NT_OWF_PASSWORD;
 */
static int
netlogon_dissect_NT_OWF_PASSWORD(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep _U_)
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


/*
 * IDL typedef struct {
 * IDL   LOGON_IDENTITY_INFO identity_info;
 * IDL   LM_OWF_PASSWORD lmpassword;
 * IDL   NT_OWF_PASSWORD ntpassword;
 * IDL } INTERACTIVE_INFO;
 */
static int
netlogon_dissect_INTERACTIVE_INFO(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = netlogon_dissect_LOGON_IDENTITY_INFO(tvb, offset,
		pinfo, tree, drep);

	offset = netlogon_dissect_LM_OWF_PASSWORD(tvb, offset,
		pinfo, tree, drep);

	offset = netlogon_dissect_NT_OWF_PASSWORD(tvb, offset,
		pinfo, tree, drep);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   char chl[8];
 * IDL } CHALLENGE;
 */
static int
netlogon_dissect_CHALLENGE(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep _U_)
{
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect.*/
		return offset;
	}

	proto_tree_add_item(tree, hf_netlogon_challenge, tvb, offset, 8,
		FALSE);
	offset += 8;

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   LOGON_IDENTITY_INFO logon_info;
 * IDL   CHALLENGE chal;
 * IDL   STRING ntchallengeresponse;
 * IDL   STRING lmchallengeresponse;
 * IDL } NETWORK_INFO;
 */
static int
netlogon_dissect_NETWORK_INFO(tvbuff_t *tvb, int offset,
		packet_info *pinfo, proto_tree *tree,
		char *drep)
{
	offset = netlogon_dissect_LOGON_IDENTITY_INFO(tvb, offset,
		pinfo, tree, drep);

	offset = netlogon_dissect_CHALLENGE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_nt_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_nt_chal_resp, 0);

	offset = dissect_ndr_nt_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_lm_chal_resp, 0);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   LOGON_IDENTITY_INFO logon_info;
 * IDL   LM_OWF_PASSWORD lmpassword;
 * IDL   NT_OWF_PASSWORD ntpassword;
 * IDL } SERVICE_INFO;
 */
static int
netlogon_dissect_SERVICE_INFO(tvbuff_t *tvb, int offset,
		packet_info *pinfo, proto_tree *tree,
		char *drep)
{
	offset = netlogon_dissect_LOGON_IDENTITY_INFO(tvb, offset,
		pinfo, tree, drep);

	offset = netlogon_dissect_LM_OWF_PASSWORD(tvb, offset,
		pinfo, tree, drep);

	offset = netlogon_dissect_NT_OWF_PASSWORD(tvb, offset,
		pinfo, tree, drep);

	return offset;
}

/*
 * IDL typedef [switch_type(short)] union {
 * IDL    [case(1)][unique] INTERACTIVE_INFO *iinfo;
 * IDL    [case(2)][unique] NETWORK_INFO *ninfo;
 * IDL    [case(3)][unique] SERVICE_INFO *sinfo;
 * IDL } LEVEL;
 */
static int
netlogon_dissect_LEVEL(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	guint16 level;

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_level16, &level);

	ALIGN_TO_4_BYTES;
	switch(level){
	case 1:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_INTERACTIVE_INFO, NDR_POINTER_UNIQUE,
			"INTERACTIVE_INFO:", -1, 0);
		break;
	case 2:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_NETWORK_INFO, NDR_POINTER_UNIQUE,
			"NETWORK_INFO:", -1, 0);
		break;
	case 3:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_SERVICE_INFO, NDR_POINTER_UNIQUE,
			"SERVICE_INFO:", -1, 0);
		break;
	}

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   char cred[8];
 * IDL } CREDENTIAL;
 */
static int
netlogon_dissect_CREDENTIAL(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep _U_)
{
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect.*/
		return offset;
	}

	proto_tree_add_item(tree, hf_netlogon_credential, tvb, offset, 8,
		FALSE);
	offset += 8;

	return offset;
}


/*
 * IDL typedef struct {
 * IDL   CREDENTIAL cred;
 * IDL   long timestamp;
 * IDL } AUTHENTICATOR;
 */
static int
netlogon_dissect_AUTHENTICATOR(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = netlogon_dissect_CREDENTIAL(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_timestamp, NULL);

	return offset;
}


/* 
 * IDL typedef struct {
 * IDL   long user_id;
 * IDL   long attributes;
 * IDL } GROUP_MEMBERSHIP;
 */
static int
netlogon_dissect_GROUP_MEMBERSHIP(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

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

/*
 * IDL typedef struct {
 * IDL   char user_session_key[16];
 * IDL } USER_SESSION_KEY;
 */
static int
netlogon_dissect_USER_SESSION_KEY(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep _U_)
{
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect.*/
		return offset;
	}

	proto_tree_add_item(tree, hf_netlogon_user_session_key, tvb, offset, 16,
		FALSE);
	offset += 16;

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   uint64 LogonTime;
 * IDL   uint64 LogoffTime;
 * IDL   uint64 KickOffTime;
 * IDL   uint64 PasswdLastSet;
 * IDL   uint64 PasswdCanChange;
 * IDL   uint64 PasswdMustChange;
 * IDL   unicodestring effectivename;
 * IDL   unicodestring fullname;
 * IDL   unicodestring logonscript;
 * IDL   unicodestring profilepath;
 * IDL   unicodestring homedirectory;
 * IDL   unicodestring homedirectorydrive;
 * IDL   short LogonCount;
 * IDL   short BadPasswdCount;
 * IDL   long userid;
 * IDL   long primarygroup;
 * IDL   long groupcount;
 * IDL   [unique][size_is(groupcount)] GROUP_MEMBERSHIP *groupids;
 * IDL   long userflags;
 * IDL   USER_SESSION_KEY key;
 * IDL   unicodestring logonserver;
 * IDL   unicodestring domainname;
 * IDL   [unique] SID logondomainid;
 * IDL   long expansionroom[10];
 * IDL } VALIDATION_SAM_INFO;
 */
static int
netlogon_dissect_VALIDATION_SAM_INFO(tvbuff_t *tvb, int offset,
		packet_info *pinfo, proto_tree *tree,
		char *drep)
{
	int i;

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
		hf_netlogon_logon_count16, NULL);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_bad_pw_count16, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_user_rid, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_group_rid, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_num_rids, NULL);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_GROUP_MEMBERSHIP_ARRAY, NDR_POINTER_UNIQUE,
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
			hf_netlogon_reserved, NULL);
	}

	return offset;
}



/*
 * IDL typedef struct {
 * IDL   uint64 LogonTime;
 * IDL   uint64 LogoffTime;
 * IDL   uint64 KickOffTime;
 * IDL   uint64 PasswdLastSet;
 * IDL   uint64 PasswdCanChange;
 * IDL   uint64 PasswdMustChange;
 * IDL   unicodestring effectivename;
 * IDL   unicodestring fullname;
 * IDL   unicodestring logonscript;
 * IDL   unicodestring profilepath;
 * IDL   unicodestring homedirectory;
 * IDL   unicodestring homedirectorydrive;
 * IDL   short LogonCount;
 * IDL   short BadPasswdCount;
 * IDL   long userid;
 * IDL   long primarygroup;
 * IDL   long groupcount;
 * IDL   [unique] GROUP_MEMBERSHIP *groupids;
 * IDL   long userflags;
 * IDL   USER_SESSION_KEY key;
 * IDL   unicodestring logonserver;
 * IDL   unicodestring domainname;
 * IDL   [unique] SID logondomainid;
 * IDL   long expansionroom[10];
 * IDL   long sidcount;
 * IDL   [unique] SID_AND_ATTRIBS;
 * IDL } VALIDATION_SAM_INFO2;
 */ 
static int
netlogon_dissect_VALIDATION_SAM_INFO2(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	int i;

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
		hf_netlogon_logon_count16, NULL);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_bad_pw_count16, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_user_rid, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_group_rid, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_num_rids, NULL);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_GROUP_MEMBERSHIP_ARRAY, NDR_POINTER_UNIQUE,
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
		dissect_ndr_nt_SID_AND_ATTRIBUTES_ARRAY, NDR_POINTER_UNIQUE,
		"SID_AND_ATTRIBUTES_ARRAY:", -1, 0);

	return offset;
}



static int
netlogon_dissect_PAC(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep _U_)
{
	dcerpc_info *di;
	guint32 pac_size;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_pac_size, &pac_size);

	proto_tree_add_item(tree, hf_netlogon_pac_data, tvb, offset, pac_size,
		FALSE);
	offset += pac_size;

	return offset;
}

static int
netlogon_dissect_AUTH(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep _U_)
{
	dcerpc_info *di;
	guint32 auth_size;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_auth_size, &auth_size);

	proto_tree_add_item(tree, hf_netlogon_auth_data, tvb, offset, auth_size,
		FALSE);
	offset += auth_size;

	return offset;
}


/*
 * IDL typedef struct {
 * IDL   long pac_size
 * IDL   [unique][size_is(pac_size)] char *pac;
 * IDL   UNICODESTRING logondomain;
 * IDL   UNICODESTRING logonserver;
 * IDL   UNICODESTRING principalname;
 * IDL   long auth_size;
 * IDL   [unique][size_is(auth_size)] char *auth;
 * IDL   USER_SESSION_KEY user_session_key;
 * IDL   long expansionroom[10];
 * IDL   UNICODESTRING dummy1;
 * IDL   UNICODESTRING dummy2;
 * IDL   UNICODESTRING dummy3;
 * IDL   UNICODESTRING dummy4;
 * IDL } VALIDATION_PAC_INFO;
 */
static int
netlogon_dissect_VALIDATION_PAC_INFO(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	int i;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_pac_size, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_PAC, NDR_POINTER_UNIQUE,
		"PAC:", -1, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_dom, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_srv, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_principal, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_auth_size, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTH, NDR_POINTER_UNIQUE,
		"AUTH:", -1, 0);

	offset = netlogon_dissect_USER_SESSION_KEY(tvb, offset,
		pinfo, tree, drep);

	for(i=0;i<10;i++){
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_long, NULL);
	}

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	return offset;
}


/*
 * IDL typedef [switch_type(short)] union {
 * IDL    [case(2)][unique] VALIDATION_SAM_INFO *sam;
 * IDL    [case(3)][unique] VALIDATION_SAM_INFO2 *sam2;
 * IDL    [case(4)][unique] VALIDATION_PAC_INFO *pac;
 * IDL    [case(5)][unique] VALIDATION_PAC_INFO *pac2;
 * IDL } VALIDATION;
 */
static int
netlogon_dissect_VALIDATION(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	guint16 level;

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_validation_level, &level);

	ALIGN_TO_4_BYTES;
	switch(level){
	case 2:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_VALIDATION_SAM_INFO, NDR_POINTER_UNIQUE,
			"VALIDATION_SAM_INFO:", -1, 0);
		break;
	case 3:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_VALIDATION_SAM_INFO2, NDR_POINTER_UNIQUE,
			"VALIDATION_SAM_INFO2:", -1, 0);
		break;
	case 4:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_VALIDATION_PAC_INFO, NDR_POINTER_UNIQUE,
			"VALIDATION_PAC_INFO:", -1, 0);
		break;
	case 5:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_VALIDATION_PAC_INFO, NDR_POINTER_UNIQUE,
			"VALIDATION_PAC_INFO:", -1, 0);
		break;
	}

	return offset;
}


/*
 * IDL long NetLogonSamLogon(
 * IDL      [in][unique][string] wchar_t *ServerName,
 * IDL      [in][unique][string] wchar_t *Workstation,
 * IDL      [in][unique] AUTHENTICATOR *credential,
 * IDL      [in][out][unique] AUTHENTICATOR *returnauthenticator,
 * IDL      [in] short LogonLevel,
 * IDL      [in][ref] LOGON_LEVEL *logonlevel,
 * IDL      [in] short ValidationLevel,
 * IDL      [out][ref] VALIDATION *validation,
 * IDL      [out][ref] boolean Authorative
 * IDL );
 */
static int
netlogon_dissect_netlogonsamlogon_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "SamLogon request");

	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"Computer Name", hf_netlogon_computer_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_UNIQUE,
		"AUTHENTICATOR: credential", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_UNIQUE,
		"AUTHENTICATOR: return_authenticator", -1, 0);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_level16, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_LEVEL, NDR_POINTER_REF,
		"LEVEL: LogonLevel", -1, 0);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_validation_level, NULL);

	return offset;
}

static int
netlogon_dissect_netlogonsamlogon_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "SamLogon response");

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_UNIQUE,
		"AUTHENTICATOR: return_authenticator", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_VALIDATION, NDR_POINTER_REF,
		"VALIDATION:", -1, 0);

	offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep,
		hf_netlogon_authoritative, NULL);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}


/*
 * IDL long NetLogonSamLogoff(
 * IDL      [in][unique][string] wchar_t *ServerName,
 * IDL      [in][unique][string] wchar_t *ComputerName,
 * IDL      [in][unique] AUTHENTICATOR credential,
 * IDL      [in][unique] AUTHENTICATOR return_authenticator,
 * IDL      [in] short logon_level,
 * IDL      [in][ref] LEVEL logoninformation
 * IDL );
 */
static int
netlogon_dissect_netlogonsamlogoff_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"Computer Name", hf_netlogon_computer_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_UNIQUE,
		"AUTHENTICATOR: credential", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_UNIQUE,
		"AUTHENTICATOR: return_authenticator", -1, 0);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_level16, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_LEVEL, NDR_POINTER_REF,
		"LEVEL: logoninformation", -1, 0);

	return offset;
}
static int
netlogon_dissect_netlogonsamlogoff_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_UNIQUE,
		"AUTHENTICATOR: return_authenticator", -1, 0);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}


/*
 * IDL long NetServerReqChallenge(
 * IDL      [in][unique][string] wchar_t *ServerName,
 * IDL      [in][ref][string] wchar_t *ComputerName,
 * IDL      [in][ref] CREDENTIAL client_credential,
 * IDL      [out][ref] CREDENTIAL server_credential
 * IDL );
 */
static int
netlogon_dissect_netserverreqchallenge_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, 
			    "RequestChallenge request");

	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"Computer Name", hf_netlogon_computer_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_CREDENTIAL, NDR_POINTER_REF,
		"CREDENTIAL: client challenge", -1, 0);

	return offset;
}
static int
netlogon_dissect_netserverreqchallenge_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, 
			    "RequestChallenge response");

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_CREDENTIAL, NDR_POINTER_REF,
		"CREDENTIAL: server credential", -1, 0);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

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


/*
 * IDL long NetServerAuthenticate(
 * IDL      [in][unique][string] wchar_t *ServerName,
 * IDL      [in][ref][string] wchar_t *UserName,
 * IDL      [in] short secure_challenge_type,
 * IDL      [in][ref][string] wchar_t *ComputerName,
 * IDL      [in][ref] CREDENTIAL client_challenge,
 * IDL      [out][ref] CREDENTIAL server_challenge
 * IDL );
 */
static int
netlogon_dissect_netserverauthenticate_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"User Name", hf_netlogon_acct_name, 0);

	offset = netlogon_dissect_NETLOGON_SECURE_CHANNEL_TYPE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"Computer Name", hf_netlogon_computer_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_CREDENTIAL, NDR_POINTER_REF,
		"CREDENTIAL: client challenge", -1, 0);

	return offset;
}
static int
netlogon_dissect_netserverauthenticate_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_CREDENTIAL, NDR_POINTER_REF,
		"CREDENTIAL: server challenge", -1, 0);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}



/*
 * IDL typedef struct {
 * IDL   char encrypted_password[16];
 * IDL } ENCRYPTED_LM_OWF_PASSWORD;
 */
static int
netlogon_dissect_ENCRYPTED_LM_OWF_PASSWORD(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep _U_)
{
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect.*/
		return offset;
	}

	proto_tree_add_item(tree, hf_netlogon_encrypted_lm_owf_password, tvb, offset, 16,
		FALSE);
	offset += 16;

	return offset;
}

/*
 * IDL long NetServerPasswordSet(
 * IDL      [in][unique][string] wchar_t *ServerName,
 * IDL      [in][ref][string] wchar_t *UserName,
 * IDL      [in] short secure_challenge_type,
 * IDL      [in][ref][string] wchar_t *ComputerName,
 * IDL      [in][ref] AUTHENTICATOR credential,
 * IDL      [in][ref] LM_OWF_PASSWORD UasNewPassword,
 * IDL      [out][ref] AUTHENTICATOR return_authenticator
 * IDL );
 */
static int
netlogon_dissect_netserverpasswordset_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"User Name", hf_netlogon_acct_name, 0);

	offset = netlogon_dissect_NETLOGON_SECURE_CHANNEL_TYPE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"Computer Name", hf_netlogon_computer_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: credential", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_ENCRYPTED_LM_OWF_PASSWORD, NDR_POINTER_REF,
		"ENCRYPTED_LM_OWF_PASSWORD: hashed_pwd", -1, 0);

	return offset;
}
static int
netlogon_dissect_netserverpasswordset_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: return_authenticator", -1, 0);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}


/*
 * IDL typedef struct {
 * IDL   [unique][string] wchar_t *UserName;
 * IDL   UNICODESTRING dummy1;
 * IDL   UNICODESTRING dummy2;
 * IDL   UNICODESTRING dummy3;
 * IDL   UNICODESTRING dummy4;
 * IDL   long dummy5;
 * IDL   long dummy6;
 * IDL   long dummy7;
 * IDL   long dummy8;
 * IDL } DELTA_DELETE_USER;
 */
static int
netlogon_dissect_DELTA_DELETE_USER(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"Account Name", hf_netlogon_acct_name, -1);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	return offset;
}


/*
 * IDL typedef struct {
 * IDL   bool SensitiveDataFlag;
 * IDL   long DataLength;
 * IDL   [unique][size_is(DataLength)] char *SensitiveData;
 * IDL } USER_PRIVATE_INFO;
 */
static int
netlogon_dissect_SENSITIVE_DATA(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	dcerpc_info *di;
	guint32 data_len;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_sensitive_data_len, &data_len);

	proto_tree_add_item(tree, hf_netlogon_sensitive_data, tvb, offset, 
		data_len, FALSE);
	offset += data_len;

	return offset;
}
static int
netlogon_dissect_USER_PRIVATE_INFO(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep,
		hf_netlogon_sensitive_data_flag, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_sensitive_data_len, NULL);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_SENSITIVE_DATA, NDR_POINTER_UNIQUE,
		"SENSITIVE_DATA", -1, 0);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   UNICODESTRING UserName;
 * IDL   UNICODESTRING FullName;
 * IDL   long UserID;
 * IDL   long PrimaryGroupID;
 * IDL   UNICODESTRING HomeDir;
 * IDL   UNICODESTRING HomeDirDrive;
 * IDL   UNICODESTRING LogonScript;
 * IDL   UNICODESTRING Comment;
 * IDL   UNICODESTRING Workstations;
 * IDL   NTTIME LastLogon;
 * IDL   NTTIME LastLogoff;
 * IDL   LOGON_HOURS logonhours;
 * IDL   short BadPwCount;
 * IDL   short LogonCount;
 * IDL   NTTIME PwLastSet;
 * IDL   NTTIME AccountExpires;
 * IDL   long AccountControl;
 * IDL   LM_OWF_PASSWORD lmpw;
 * IDL   NT_OWF_PASSWORD ntpw;
 * IDL   bool NTPwPresent;
 * IDL   bool LMPwPresent;
 * IDL   bool PwExpired;
 * IDL   UNICODESTRING UserComment;
 * IDL   UNICODESTRING Parameters;
 * IDL   short CountryCode;
 * IDL   short CodePage;
 * IDL   USER_PRIVATE_INFO user_private_info;
 * IDL   long SecurityInformation;
 * IDL   LSA_SECURITY_DESCRIPTOR sec_desc;
 * IDL   UNICODESTRING dummy1;
 * IDL   UNICODESTRING dummy2;
 * IDL   UNICODESTRING dummy3;
 * IDL   UNICODESTRING dummy4;
 * IDL   long dummy5;
 * IDL   long dummy6;
 * IDL   long dummy7;
 * IDL   long dummy8;
 * IDL } DELTA_USER;
 */
static int
netlogon_dissect_DELTA_USER(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
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
		hf_netlogon_bad_pw_count16, NULL);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_count16, NULL);

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

	offset = netlogon_dissect_USER_PRIVATE_INFO(tvb, offset, pinfo, tree,
		drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_security_information, NULL);

	offset = lsa_dissect_LSA_SECURITY_DESCRIPTOR(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	return offset;
}


/*
 * IDL typedef struct {
 * IDL   UNICODESTRING DomainName;
 * IDL   UNICODESTRING OEMInfo;
 * IDL   NTTIME forcedlogoff;
 * IDL   short minpasswdlen;
 * IDL   short passwdhistorylen;
 * IDL   NTTIME pwd_must_change_time;
 * IDL   NTTIME pwd_can_change_time;
 * IDL   NTTIME domain_modify_time;
 * IDL   NTTIME domain_create_time;
 * IDL   long SecurityInformation;
 * IDL   LSA_SECURITY_DESCRIPTOR sec_desc;
 * IDL   UNICODESTRING dummy1;
 * IDL   UNICODESTRING dummy2;
 * IDL   UNICODESTRING dummy3;
 * IDL   UNICODESTRING dummy4;
 * IDL   long dummy5;
 * IDL   long dummy6;
 * IDL   long dummy7;
 * IDL   long dummy8;
 * IDL } DELTA_DOMAIN;
 */
static int
netlogon_dissect_DELTA_DOMAIN(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_domain_name, 1);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_oem_info, 0);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_kickoff_time);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_minpasswdlen, NULL);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_passwdhistorylen, NULL);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_pwd_must_change_time);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_pwd_can_change_time);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_domain_modify_time);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_domain_create_time);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_security_information, NULL);

	offset = lsa_dissect_LSA_SECURITY_DESCRIPTOR(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	return offset;
}


/*
 * IDL typedef struct {
 * IDL   UNICODESTRING groupname;
 * IDL   GROUP_MEMBERSHIP group_membership;
 * IDL   UNICODESTRING comment;
 * IDL   long SecurityInformation;
 * IDL   LSA_SECURITY_DESCRIPTOR sec_desc;
 * IDL   UNICODESTRING dummy1;
 * IDL   UNICODESTRING dummy2;
 * IDL   UNICODESTRING dummy3;
 * IDL   UNICODESTRING dummy4;
 * IDL   long dummy5;
 * IDL   long dummy6;
 * IDL   long dummy7;
 * IDL   long dummy8;
 * IDL } DELTA_GROUP;
 */
static int
netlogon_dissect_DELTA_GROUP(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_group_name, 1);

	offset = netlogon_dissect_GROUP_MEMBERSHIP(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_group_desc, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_security_information, NULL);

	offset = lsa_dissect_LSA_SECURITY_DESCRIPTOR(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	return offset;
}


/*
 * IDL typedef struct {
 * IDL   UNICODESTRING OldName;
 * IDL   UNICODESTRING NewName;
 * IDL   UNICODESTRING dummy1;
 * IDL   UNICODESTRING dummy2;
 * IDL   UNICODESTRING dummy3;
 * IDL   UNICODESTRING dummy4;
 * IDL   long dummy5;
 * IDL   long dummy6;
 * IDL   long dummy7;
 * IDL   long dummy8;
 * IDL } DELTA_RENAME;
 */
static int
netlogon_dissect_DELTA_RENAME(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	dcerpc_info *di;

	di=pinfo->private_data;

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		di->hf_index, 1);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		di->hf_index, 1);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	return offset;
}


static int
netlogon_dissect_RID(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				hf_netlogon_user_rid, NULL);

	return offset;
}

static int
netlogon_dissect_RID_array(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_RID);

	return offset;
}

static int
netlogon_dissect_ATTRIB(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_attrs, NULL);

	return offset;
}

static int
netlogon_dissect_ATTRIB_array(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_ATTRIB);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   [unique][size_is(num_rids)] long *rids;
 * IDL   [unique][size_is(num_rids)] long *attribs;
 * IDL   long num_rids;
 * IDL   long dummy1;
 * IDL   long dummy2;
 * IDL   long dummy3;
 * IDL   long dummy4;
 * IDL } DELTA_GROUP_MEMBER;
 */
static int
netlogon_dissect_DELTA_GROUP_MEMBER(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_RID_array, NDR_POINTER_UNIQUE,
		"RIDs:", -1, 0);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_ATTRIB_array, NDR_POINTER_UNIQUE,
		"Attribs:", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_num_rids, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	return offset;
}


/*
 * IDL typedef struct {
 * IDL   UNICODESTRING alias_name;
 * IDL   long rid;
 * IDL   long SecurityInformation;
 * IDL   LSA_SECURITY_DESCRIPTOR sec_desc;
 * IDL   UNICODESTRING dummy1;
 * IDL   UNICODESTRING dummy2;
 * IDL   UNICODESTRING dummy3;
 * IDL   UNICODESTRING dummy4;
 * IDL   long dummy5;
 * IDL   long dummy6;
 * IDL   long dummy7;
 * IDL   long dummy8;
 * IDL } DELTA_ALIAS;
 */
static int
netlogon_dissect_DELTA_ALIAS(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_alias_name, 1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_alias_rid, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_security_information, NULL);

	offset = lsa_dissect_LSA_SECURITY_DESCRIPTOR(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	return offset;
}


/*
 * IDL typedef struct {
 * IDL   [unique] SID_ARRAY sids;
 * IDL   long dummy1;
 * IDL   long dummy2;
 * IDL   long dummy3;
 * IDL   long dummy4;
 * IDL } DELTA_ALIAS_MEMBER;
 */
static int
netlogon_dissect_DELTA_ALIAS_MEMBER(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_nt_PSID_ARRAY(tvb, offset, pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	return offset;
}


static int
netlogon_dissect_EVENT_AUDIT_OPTION(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_event_audit_option, NULL);

	return offset;
}

static int
netlogon_dissect_EVENT_AUDIT_OPTIONS_ARRAY(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_EVENT_AUDIT_OPTION);

	return offset;
}


/*
 * IDL typedef struct {
 * IDL   long pagedpoollimit;
 * IDL   long nonpagedpoollimit;
 * IDL   long minimumworkingsetsize;
 * IDL   long maximumworkingsetsize;
 * IDL   long pagefilelimit;
 * IDL   NTTIME timelimit;
 * IDL } QUOTA_LIMITS;
 */
static int
netlogon_dissect_QUOTA_LIMITS(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"QUOTA_LIMTS:");
		tree = proto_item_add_subtree(item, ett_QUOTA_LIMITS);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_pagedpoollimit, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_nonpagedpoollimit, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_minworkingsetsize, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_maxworkingsetsize, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_pagefilelimit, NULL);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_timelimit);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}


/*
 * IDL typedef struct {
 * IDL   long maxlogsize;
 * IDL   NTTIME auditretentionperiod;
 * IDL   bool auditingmode;
 * IDL   long maxauditeventcount;
 * IDL   [unique][size_is(maxauditeventcount)] long *eventauditoptions;
 * IDL   UNICODESTRING primarydomainname;
 * IDL   [unique] SID *sid;
 * IDL   QUOTA_LIMITS quota_limits;
 * IDL   NTTIME db_modify_time;
 * IDL   NTTIME db_create_time;
 * IDL   long SecurityInformation;
 * IDL   LSA_SECURITY_DESCRIPTOR sec_desc;
 * IDL   UNICODESTRING dummy1;
 * IDL   UNICODESTRING dummy2;
 * IDL   UNICODESTRING dummy3;
 * IDL   UNICODESTRING dummy4;
 * IDL   long dummy5;
 * IDL   long dummy6;
 * IDL   long dummy7;
 * IDL   long dummy8;
 * IDL } DELTA_POLICY;
 */
static int
netlogon_dissect_DELTA_POLICY(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_max_log_size, NULL);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_audit_retention_period);

	offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep,
		hf_netlogon_auditing_mode, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_max_audit_event_count, NULL);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_EVENT_AUDIT_OPTIONS_ARRAY, NDR_POINTER_UNIQUE,
		"Event Audit Options:", -1, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_domain_name, 0);

	offset = dissect_ndr_nt_PSID(tvb, offset,
		pinfo, tree, drep);

	offset = netlogon_dissect_QUOTA_LIMITS(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_db_modify_time);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_db_create_time);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_security_information, NULL);

	offset = lsa_dissect_LSA_SECURITY_DESCRIPTOR(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	return offset;
}


static int
netlogon_dissect_CONTROLLER(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dc_name, 1);

	return offset;
}

static int
netlogon_dissect_CONTROLLER_ARRAY(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_CONTROLLER);

	return offset;
}


/*
 * IDL typedef struct {
 * IDL   UNICODESTRING DomainName;
 * IDL   long num_controllers;
 * IDL   [unique][size_is(num_controllers)] UNICODESTRING *controller_names;
 * IDL   long SecurityInformation;
 * IDL   LSA_SECURITY_DESCRIPTOR sec_desc;
 * IDL   UNICODESTRING dummy1;
 * IDL   UNICODESTRING dummy2;
 * IDL   UNICODESTRING dummy3;
 * IDL   UNICODESTRING dummy4;
 * IDL   long dummy5;
 * IDL   long dummy6;
 * IDL   long dummy7;
 * IDL   long dummy8;
 * IDL } DELTA_TRUSTED_DOMAINS;
 */
static int
netlogon_dissect_DELTA_TRUSTED_DOMAINS(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_domain_name, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_num_controllers, NULL);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_CONTROLLER_ARRAY, NDR_POINTER_UNIQUE,
		"Domain Controllers:", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_security_information, NULL);

	offset = lsa_dissect_LSA_SECURITY_DESCRIPTOR(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	return offset;
}


static int
netlogon_dissect_PRIV_ATTR(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_attrs, NULL);

	return offset;
}

static int
netlogon_dissect_PRIV_ATTR_ARRAY(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_PRIV_ATTR);

	return offset;
}

static int
netlogon_dissect_PRIV_NAME(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_privilege_name, 1);

	return offset;
}

static int
netlogon_dissect_PRIV_NAME_ARRAY(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_PRIV_NAME);

	return offset;
}



/*
 * IDL typedef struct {
 * IDL   long privilegeentries;
 * IDL   long provolegecontrol;
 * IDL   [unique][size_is(privilege_entries)] long *privilege_attrib;
 * IDL   [unique][size_is(privilege_entries)] UNICODESTRING *privilege_name;
 * IDL   QUOTALIMITS quotalimits;
 * IDL   long SecurityInformation;
 * IDL   LSA_SECURITY_DESCRIPTOR sec_desc;
 * IDL   UNICODESTRING dummy1;
 * IDL   UNICODESTRING dummy2;
 * IDL   UNICODESTRING dummy3;
 * IDL   UNICODESTRING dummy4;
 * IDL   long dummy5;
 * IDL   long dummy6;
 * IDL   long dummy7;
 * IDL   long dummy8;
 * IDL } DELTA_ACCOUNTS;
 */
static int
netlogon_dissect_DELTA_ACCOUNTS(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_privilege_entries, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_privilege_control, NULL);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_PRIV_ATTR_ARRAY, NDR_POINTER_UNIQUE,
		"PRIV_ATTR_ARRAY:", -1, 0);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_PRIV_NAME_ARRAY, NDR_POINTER_UNIQUE,
		"PRIV_NAME_ARRAY:", -1, 0);

	offset = netlogon_dissect_QUOTA_LIMITS(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_systemflags, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_security_information, NULL);

	offset = lsa_dissect_LSA_SECURITY_DESCRIPTOR(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_nt_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

	return offset;
}








/*qqq*/
/* Updated above this line */






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
netlogon_dissect_UNICODE_STRING(tvbuff_t *tvb, int offset, 
			packet_info *pinfo, proto_tree *parent_tree, 
			char *drep, int type, int hf_index, int levels)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int old_offset=offset;
	dcerpc_info *di;
	char *name;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	name = proto_registrar_get_name(hf_index);
	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, -1,
			"%s", name);
		tree = proto_item_add_subtree(item, ett_nt_unicode_string);
	}

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			dissect_ndr_nt_UNICODE_STRING_str, type,
			name, hf_index, levels);

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

int
dissect_nt_GUID(tvbuff_t *tvb, int offset,
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

	offset = dissect_nt_GUID(tvb, offset,
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

	offset = dissect_nt_GUID(tvb, offset,
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
		hf_netlogon_level16, &level);

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
		hf_netlogon_level, &level);

	ALIGN_TO_4_BYTES;
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
		hf_netlogon_level, &level);

	ALIGN_TO_4_BYTES;
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
		hf_netlogon_level16, &level);

	ALIGN_TO_4_BYTES;
	switch(level){
	case 1:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DELTA_DOMAIN, NDR_POINTER_UNIQUE,
			"DELTA_DOMAIN:", -1, 0);
		break;
	case 2:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DELTA_GROUP, NDR_POINTER_UNIQUE,
			"DELTA_GROUP:", -1, 0);
		break;
	case 4:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DELTA_RENAME, NDR_POINTER_UNIQUE,
			"DELTA_RENAME_GROUP:", hf_netlogon_group_name, 0);
		break;
	case 5:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DELTA_USER, NDR_POINTER_UNIQUE,
			"DELTA_USER:", -1, 0);
		break;
	case 7:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DELTA_RENAME, NDR_POINTER_UNIQUE,
			"DELTA_RENAME_USER:", hf_netlogon_acct_name, 0);
		break;
	case 8:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DELTA_GROUP_MEMBER, NDR_POINTER_UNIQUE,
			"DELTA_GROUP_MEMBER:", -1, 0);
		break;
	case 9:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DELTA_ALIAS, NDR_POINTER_UNIQUE,
			"DELTA_ALIAS:", -1, 0);
		break;
	case 11:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DELTA_RENAME, NDR_POINTER_UNIQUE,
			"DELTA_RENAME_ALIAS:", hf_netlogon_alias_name, 0);
		break;
	case 12:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DELTA_ALIAS_MEMBER, NDR_POINTER_UNIQUE,
			"DELTA_ALIAS_MEMBER:", -1, 0);
		break;
	case 13:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DELTA_POLICY, NDR_POINTER_UNIQUE,
			"DELTA_POLICY:", -1, 0);
		break;
	case 14:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DELTA_TRUSTED_DOMAINS, NDR_POINTER_UNIQUE,
			"DELTA_TRUSTED_DOMAINS:", -1, 0);
		break;
	case 16:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DELTA_ACCOUNTS, NDR_POINTER_UNIQUE,
			"DELTA_ACCOUNTS:", -1, 0);
		break;
	case 18:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_TYPE_34, NDR_POINTER_PTR,
			"TYPE_34 pointer:", -1, 0);
		break;
	case 20:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DELTA_DELETE_USER, NDR_POINTER_UNIQUE,
			"DELTA_DELETE_GROUP:", -1, 0);
		break;
	case 21:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DELTA_DELETE_USER, NDR_POINTER_UNIQUE,
			"DELTA_DELETE_GROUP:", -1, 0);
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

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_delta_type, NULL);

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
		"DELTA_ENUM: deltas", -1, 0);

	proto_item_set_len(item, offset-old_offset);
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
		hf_netlogon_level, &level);

	ALIGN_TO_4_BYTES;
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
		hf_netlogon_level, &level);

	ALIGN_TO_4_BYTES;
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
		hf_netlogon_level, &level);

	ALIGN_TO_4_BYTES;
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
netlogon_dissect_netsamdeltas_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	/* XXX idl file has LOGONSRV_HANDLE here, ms capture has string srv_name */
	offset = netlogon_dissect_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, hf_netlogon_logon_srv, 0);

	offset = netlogon_dissect_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, hf_netlogon_cli_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: credential", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: return_authenticator", -1, 0);

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
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: return_authenticator", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_TYPE_16, NDR_POINTER_REF,
		"TYPE_16 pointer: dom_mod_count", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_SAM_DELTA_ARRAY, NDR_POINTER_UNIQUE,
		"SAM_DELTA_ARRAY: deltas", -1, 0);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_netlogondatabasesync_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, hf_netlogon_logon_srv, 0);

	offset = netlogon_dissect_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, hf_netlogon_cli_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: credential", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: return_authenticator", -1, 0);

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
netlogon_dissect_netlogondatabasesync_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: return_authenticator", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_REF,
		"ULONG pointer: unknown_ULONG", hf_netlogon_unknown_long, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_SAM_DELTA_ARRAY, NDR_POINTER_UNIQUE,
		"SAM_DELTA_ARRAY: deltas", -1, 0);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_netlogonaccountdeltas_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = netlogon_dissect_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: credential", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: return_authenticator", -1, 0);

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
netlogon_dissect_netlogonaccountdeltas_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: return_authenticator", -1, 0);

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

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_netlogonaccountsync_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = netlogon_dissect_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: credential", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: return_authenticator", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	return offset;
}


static int
netlogon_dissect_netlogonaccountsync_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: return_authenticator", -1, 0);

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

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_netlogongetdcname_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{

	offset = netlogon_dissect_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"unknown string", hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_WCHAR_ptr, NDR_POINTER_REF,
		"WCHAR* pointer: unknown string", -1, 0);
	return offset;
}


static int
netlogon_dissect_netlogongetdcname_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_WCHAR_ptr, NDR_POINTER_REF,
		"WCHAR* pointer: unknown string", -1, 0);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
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

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_netlogongetanydcname_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"unknown string", hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_WCHAR_ptr, NDR_POINTER_REF,
		"WCHAR* pointer: unknown string", -1, 0);
	return offset;
}


static int
netlogon_dissect_netlogongetanydcname_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_WCHAR_ptr, NDR_POINTER_REF,
		"WCHAR* pointer: unknown string", -1, 0);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
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

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_netserverauthenticate2_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "Auth2 request");

	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"User Name", hf_netlogon_acct_name, 0);

	offset = netlogon_dissect_NETLOGON_SECURE_CHANNEL_TYPE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_REF,
		"Computer Name", hf_netlogon_computer_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_CREDENTIAL, NDR_POINTER_REF,
		"CREDENTIAL pointer: client_chal", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_REF,
		"ULONG pointer: neg_flags", hf_netlogon_unknown_long, 0);
	return offset;
}


static int
netlogon_dissect_netserverauthenticate2_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "Auth2 response");

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_CREDENTIAL, NDR_POINTER_REF,
		"CREDENTIAL pointer: server_chal", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_REF,
		"ULONG pointer: neg_flags", hf_netlogon_unknown_long, 0);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_netdatabasesync2_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = netlogon_dissect_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: credential", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: return_authenticator", -1, 0);

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
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: return_authenticator", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_REF,
		"ULONG pointer: unknown_ULONG", hf_netlogon_unknown_long, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_SAM_DELTA_ARRAY, NDR_POINTER_UNIQUE,
		"SAM_DELTA_ARRAY: deltas", -1, 0);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_netlogondatabaseredo_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, hf_netlogon_unknown_string, 0);

	offset = netlogon_dissect_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: credential", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: return_authenticator", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_BYTE_array, NDR_POINTER_REF,
		"BYTE pointer: unknown_BYTE", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	return offset;
}


static int
netlogon_dissect_netlogondatabaseredo_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: return_authenticator", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_SAM_DELTA_ARRAY, NDR_POINTER_UNIQUE,
		"SAM_DELTA_ARRAY: deltas", -1, 0);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
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

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
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

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
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
		"Domain", hf_netlogon_logon_dom, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_nt_GUID, NDR_POINTER_UNIQUE,
		"GUID pointer: domain_guid", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_nt_GUID, NDR_POINTER_UNIQUE,
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

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
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
		"unknown string", hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: credential", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_PTR,
		"AUTHENTICATOR: return_authenticator", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	return offset;
}


static int
netlogon_dissect_function_15_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_PTR,
		"AUTHENTICATOR: return_authenticator", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_TYPE_44, NDR_POINTER_PTR,
		"TYPE_44 pointer: unknown_TYPE_44", -1, 0);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
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
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
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
		"unknown string", hf_netlogon_unknown_string, 0);

	return offset;
}


static int
netlogon_dissect_function_17_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_PTR,
		"ULONG pointer: unknown_ULONG", hf_netlogon_unknown_long, 0);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
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

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
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
		"unknown string", hf_netlogon_unknown_string, 0);

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

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
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
		"Acct Name", hf_netlogon_acct_name, 0);

	offset = netlogon_dissect_NETLOGON_SECURE_CHANNEL_TYPE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"Computer Name", hf_netlogon_computer_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_CREDENTIAL, NDR_POINTER_REF,
		"CREDENTIAL pointer: authenticator", -1, 0);

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
		netlogon_dissect_CREDENTIAL, NDR_POINTER_REF,
		"CREDENTIAL pointer: unknown_NETLOGON_CREDENTIAL", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_PTR,
		"ULONG pointer: negotiate_flags", hf_netlogon_unknown_long, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_PTR,
		"ULONG pointer: unknown_ULONG", hf_netlogon_unknown_long, 0);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
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
		"Domain", hf_netlogon_logon_dom, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_nt_GUID, NDR_POINTER_UNIQUE,
		"GUID pointer: domain_guid", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"Site Name", hf_netlogon_site_name, 0);

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

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
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

	offset = netlogon_dissect_UNICODE_STRING(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, hf_netlogon_site_name, 0);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
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
		"Computer Name", hf_netlogon_computer_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: credential", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_PTR,
		"AUTHENTICATOR: return_authenticator", -1, 0);

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
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_PTR,
		"AUTHENTICATOR: return_authenticator", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_TYPE_47, NDR_POINTER_PTR,
		"TYPE_47 pointer: unknown_TYPE_47", -1, 0);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
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
		"unknown string", hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_short, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"unknown string", hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: credential", -1, 0);

	offset = netlogon_dissect_UNICODE_STRING_512(tvb, offset,
		pinfo, tree, drep);

	return offset;
}


static int
netlogon_dissect_function_1e_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_PTR,
		"AUTHENTICATOR: return_authenticator", -1, 0);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
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
		"Acct Name", hf_netlogon_acct_name, 0);

	offset = netlogon_dissect_NETLOGON_SECURE_CHANNEL_TYPE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"Computer Name", hf_netlogon_computer_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: credential", -1, 0);

	return offset;
}


static int
netlogon_dissect_netserverpasswordset2_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: return_authenticator", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_LM_OWF_PASSWORD, NDR_POINTER_REF,
		"LM_OWF_PASSWORD pointer: server_pwd", -1, 0);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
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

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: credential", -1, 0);

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
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_PTR,
		"AUTHENTICATOR: return_authenticator", -1, 0);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
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

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
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
		"unknown string", hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"unknown string", hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_nt_GUID, NDR_POINTER_UNIQUE,
		"GUID pointer: unknown_GUID", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"unknown string", hf_netlogon_unknown_string, 0);

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

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
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

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
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

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
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

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}


static int
netlogon_dissect_function_26_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"unknown string", hf_netlogon_unknown_string, 0);

	return offset;
}


static int
netlogon_dissect_function_26_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_TYPE_50_ptr_ptr, NDR_POINTER_REF,
		"TYPE_50** pointer: unknown_TYPE_50", -1, 0);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_function_27_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"unknown string", hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_UNICODE_STRING_str, NDR_POINTER_UNIQUE,
		"unknown string", hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_short, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_LEVEL, NDR_POINTER_PTR,
		"LEVEL pointer: unknown_NETLOGON_LEVEL", -1, 0);

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
		netlogon_dissect_VALIDATION, NDR_POINTER_PTR,
		"VALIDATION: unknown_NETLOGON_VALIDATION", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_char, NDR_POINTER_PTR,
		"BOOLEAN pointer: unknown_BOOLEAN", hf_netlogon_unknown_char, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_PTR,
		"ULONG pointer: unknown_ULONG", hf_netlogon_unknown_long, 0);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
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

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
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
		"Domain", hf_netlogon_logon_dom, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_nt_GUID, NDR_POINTER_UNIQUE,
		"GUID pointer: domain_guid", -1, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_nt_GUID, NDR_POINTER_UNIQUE,
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
	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}



static dcerpc_sub_dissector dcerpc_netlogon_dissectors[] = {
	{ NETLOGON_UASLOGON, "UasLogon",
		netlogon_dissect_netlogonuaslogon_rqst,
		netlogon_dissect_netlogonuaslogon_reply },
	{ NETLOGON_UASLOGOFF, "UasLogoff",
		netlogon_dissect_netlogonuaslogoff_rqst,
		netlogon_dissect_netlogonuaslogoff_reply },
	{ NETLOGON_NETLOGONSAMLOGON, "SamLogon",
		netlogon_dissect_netlogonsamlogon_rqst,
		netlogon_dissect_netlogonsamlogon_reply },
	{ NETLOGON_NETLOGONSAMLOGOFF, "SamLogoff",
		netlogon_dissect_netlogonsamlogoff_rqst,
		netlogon_dissect_netlogonsamlogoff_reply },
	{ NETLOGON_NETSERVERREQCHALLENGE, "ServerReqChallenge",
		netlogon_dissect_netserverreqchallenge_rqst,
		netlogon_dissect_netserverreqchallenge_reply },
	{ NETLOGON_NETSERVERAUTHENTICATE, "ServerAuthenticate",
		netlogon_dissect_netserverauthenticate_rqst,
		netlogon_dissect_netserverauthenticate_reply },
	{ NETLOGON_NETSERVERPASSWORDSET, "ServerPasswdSet",
		netlogon_dissect_netserverpasswordset_rqst,
		netlogon_dissect_netserverpasswordset_reply },
	{ NETLOGON_NETSAMDELTAS, "NETSAMDELTAS",
		netlogon_dissect_netsamdeltas_rqst,
		netlogon_dissect_netsamdeltas_reply },
	{ NETLOGON_DATABASESYNC, "DatabaseSync",
		netlogon_dissect_netlogondatabasesync_rqst,
		netlogon_dissect_netlogondatabasesync_reply },
	{ NETLOGON_ACCOUNTDELTAS, "AccountDeltas",
		netlogon_dissect_netlogonaccountdeltas_rqst,
		netlogon_dissect_netlogonaccountdeltas_reply },
	{ NETLOGON_ACCOUNTSYNC, "AccountSync",
		netlogon_dissect_netlogonaccountsync_rqst,
		netlogon_dissect_netlogonaccountsync_reply },
	{ NETLOGON_GETDCNAME, "GetDCName",
		netlogon_dissect_netlogongetdcname_rqst,
		netlogon_dissect_netlogongetdcname_reply },
	{ NETLOGON_NETLOGONCONTROL, "NETLOGONCONTROL",
		netlogon_dissect_netlogoncontrol_rqst,
		netlogon_dissect_netlogoncontrol_reply },
	{ NETLOGON_GETANYDCNAME, "GetAnyDCName",
		netlogon_dissect_netlogongetanydcname_rqst,
		netlogon_dissect_netlogongetanydcname_reply },
	{ NETLOGON_NETLOGONCONTROL2, "NETLOGONCONTROL2",
		netlogon_dissect_netlogoncontrol2_rqst,
		netlogon_dissect_netlogoncontrol2_reply },
	{ NETLOGON_NETSERVERAUTHENTICATE2, "NETSERVERAUTHENTICATE2",
		netlogon_dissect_netserverauthenticate2_rqst,
		netlogon_dissect_netserverauthenticate2_reply },
	{ NETLOGON_NETDATABASESYNC2, "NETDATABASESYNC2",
		netlogon_dissect_netdatabasesync2_rqst,
		netlogon_dissect_netdatabasesync2_reply },
	{ NETLOGON_DATABASEREDO, "DatabaseRedo",
		netlogon_dissect_netlogondatabaseredo_rqst,
		netlogon_dissect_netlogondatabaseredo_reply },
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
        {0, NULL, NULL,  NULL }
};

static const value_string netlogon_opnum_vals[] = {
	{ NETLOGON_UASLOGON, "UasLogon" },
	{ NETLOGON_UASLOGOFF, "UasLogoff" },
	{ NETLOGON_NETLOGONSAMLOGON, "SamLogon" },
	{ NETLOGON_NETLOGONSAMLOGOFF, "SamLogoff" },
	{ NETLOGON_NETSERVERREQCHALLENGE, "ServerReqChallenge" },
	{ NETLOGON_NETSERVERAUTHENTICATE, "ServerAuthenticate" },
	{ NETLOGON_NETSERVERPASSWORDSET, "ServerPasswdSet" },
	{ NETLOGON_NETSAMDELTAS, "NETSAMDELTAS" },
	{ NETLOGON_DATABASESYNC, "DatabaseSync" },
	{ NETLOGON_ACCOUNTDELTAS, "AccountDeltas" },
	{ NETLOGON_ACCOUNTSYNC, "AccountSync" },
	{ NETLOGON_GETDCNAME, "GetDCName" },
	{ NETLOGON_NETLOGONCONTROL, "NETLOGONCONTROL" },
	{ NETLOGON_GETANYDCNAME, "GetAnyDCName" },
	{ NETLOGON_NETLOGONCONTROL2, "NETLOGONCONTROL2" },
	{ NETLOGON_NETSERVERAUTHENTICATE2, "NETSERVERAUTHENTICATE2" },
	{ NETLOGON_NETDATABASESYNC2, "NETDATABASESYNC2" },
	{ NETLOGON_DATABASEREDO, "DatabaseRedo" },
	{ NETLOGON_FUNCTION_12, "FUNCTION_12" },
	{ NETLOGON_NETTRUSTEDDOMAINLIST, "NETTRUSTEDDOMAINLIST" },
	{ NETLOGON_DSRGETDCNAME2, "DSRGETDCNAME2" },
	{ NETLOGON_FUNCTION_15, "FUNCTION_15" },
	{ NETLOGON_FUNCTION_16, "FUNCTION_16" },
	{ NETLOGON_FUNCTION_17, "FUNCTION_17" },
	{ NETLOGON_FUNCTION_18, "FUNCTION_18" },
	{ NETLOGON_FUNCTION_19, "FUNCTION_19" },
	{ NETLOGON_NETSERVERAUTHENTICATE3, "NETSERVERAUTHENTICATE3" },
	{ NETLOGON_DSRGETDCNAME, "DSRGETDCNAME" },
	{ NETLOGON_DSRGETSITENAME, "DSRGETSITENAME" },
	{ NETLOGON_FUNCTION_1D, "FUNCTION_1D" },
	{ NETLOGON_FUNCTION_1E, "FUNCTION_1E" },
	{ NETLOGON_NETSERVERPASSWORDSET2, "NETSERVERPASSWORDSET2" },
	{ NETLOGON_FUNCTION_20, "FUNCTION_20" },
	{ NETLOGON_FUNCTION_21, "FUNCTION_21" },
	{ NETLOGON_FUNCTION_22, "FUNCTION_22" },
	{ NETLOGON_FUNCTION_23, "FUNCTION_23" },
	{ NETLOGON_FUNCTION_24, "FUNCTION_24" },
	{ NETLOGON_FUNCTION_25, "FUNCTION_25" },
	{ NETLOGON_FUNCTION_26, "FUNCTION_26" },
	{ NETLOGON_FUNCTION_27, "FUNCTION_27" },
	{ NETLOGON_DSRROLEGETPRIMARYDOMAININFORMATION, "DSRROLEGETPRIMARYDOMAININFORMATION" },
	{ NETLOGON_DSRDEREGISTERDNSHOSTRECORDS, "DSRDEREGISTERDNSHOSTRECORDS" },
	{ 0, NULL }
};

void 
proto_register_dcerpc_netlogon(void)
{

static hf_register_info hf[] = {
	{ &hf_netlogon_opnum,
	  { "Operation", "netlogon.opnum", FT_UINT16, BASE_DEC,
	    VALS(netlogon_opnum_vals), 0x0, "Operation", HFILL }},

	{ &hf_netlogon_rc, { 
		"Return code", "netlogon.rc", FT_UINT32, BASE_HEX, 
		VALS(NT_errors), 0x0, "Netlogon return code", HFILL }},

	{ &hf_netlogon_param_ctrl, { 
		"Param Ctrl", "netlogon.param_ctrl", FT_UINT32, BASE_HEX, 
		NULL, 0x0, "Param ctrl", HFILL }},

	{ &hf_netlogon_logon_id, { 
		"Logon ID", "netlogon.logon_id", FT_UINT64, BASE_DEC, 
		NULL, 0x0, "Logon ID", HFILL }},

	{ &hf_netlogon_security_information, { 
		"Security Information", "netlogon.security_information", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Security Information", HFILL }},

	{ &hf_netlogon_count, { 
		"Count", "netlogon.count", FT_UINT16, BASE_DEC, 
		NULL, 0x0, "", HFILL }},

	{ &hf_netlogon_credential, { 
		"Credential", "netlogon.credential", FT_BYTES, BASE_HEX, 
		NULL, 0x0, "Netlogon credential", HFILL }},

	{ &hf_netlogon_challenge, { 
		"Challenge", "netlogon.challenge", FT_BYTES, BASE_HEX, 
		NULL, 0x0, "Netlogon challenge", HFILL }},

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

	{ &hf_netlogon_priv, {
		"Priv", "netlogon.priv", FT_UINT32, BASE_DEC,
		NULL, 0, "", HFILL }},

	{ &hf_netlogon_privilege_entries, {
		"Privilege Entries", "netlogon.privilege_entries", FT_UINT32, BASE_DEC,
		NULL, 0, "", HFILL }},

	{ &hf_netlogon_privilege_control, {
		"Privilege Control", "netlogon.privilege_control", FT_UINT32, BASE_HEX,
		NULL, 0, "", HFILL }},

	{ &hf_netlogon_privilege_name, {
		"Privilege Name", "netlogon.privilege_name", FT_STRING, BASE_HEX,
		NULL, 0, "", HFILL }},

	{ &hf_netlogon_status, {
		"Status", "netlogon.status", FT_UINT32, BASE_DEC,
		NULL, 0, "Status", HFILL }},

	{ &hf_netlogon_attrs, {
		"Attributes", "netlogon.attrs", FT_UINT32, BASE_HEX,
		NULL, 0, "Attributes", HFILL }},

	{ &hf_netlogon_unknown_string,
		{ "Unknown string", "netlogon.unknown_string", FT_STRING, BASE_NONE,
		NULL, 0, "Unknown string. If you know what this is, contact ethereal developers.", HFILL }},
	{ &hf_netlogon_unknown_long,
		{ "Unknown long", "netlogon.unknown.long", FT_UINT32, BASE_HEX, 
		NULL, 0x0, "Unknown long. If you know what this is, contact ethereal developers.", HFILL }},
	{ &hf_netlogon_reserved,
		{ "Reserved", "netlogon.reserved", FT_UINT32, BASE_HEX, 
		NULL, 0x0, "Reserved", HFILL }},
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

	{ &hf_netlogon_sensitive_data_flag,
		{ "Sensitive Data", "netlogon.sensitive_data_flag", FT_UINT8, BASE_DEC, 
		NULL, 0x0, "Sensitive data flag", HFILL }},

	{ &hf_netlogon_auditing_mode,
		{ "Auditing Mode", "netlogon.auditing_mode", FT_UINT8, BASE_DEC, 
		NULL, 0x0, "Auditing Mode", HFILL }},

	{ &hf_netlogon_max_audit_event_count,
		{ "Max Audit Event Count", "netlogon.max_audit_event_count", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Max audit event count", HFILL }},

	{ &hf_netlogon_event_audit_option,
		{ "Event Audit Option", "netlogon.event_audit_option", FT_UINT32, BASE_HEX, 
		NULL, 0x0, "Event audit option", HFILL }},

	{ &hf_netlogon_sensitive_data_len,
		{ "Length", "netlogon.sensitive_data_len", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Length of sensitive data", HFILL }},

	{ &hf_netlogon_nt_chal_resp,
		{ "NT Chal resp", "netlogon.nt_chal_resp", FT_BYTES, BASE_HEX,
		NULL, 0, "Challenge response for NT authentication", HFILL }},

	{ &hf_netlogon_lm_chal_resp,
		{ "LM Chal resp", "netlogon.lm_chal_resp", FT_BYTES, BASE_HEX,
		NULL, 0, "Challenge response for LM authentication", HFILL }},

	{ &hf_netlogon_pac_data,
		{ "Pac Data", "netlogon.pac.data", FT_BYTES, BASE_HEX,
		NULL, 0, "Pac Data", HFILL }},

	{ &hf_netlogon_sensitive_data,
		{ "Data", "netlogon.sensitive_data", FT_BYTES, BASE_HEX,
		NULL, 0, "Sensitive Data", HFILL }},

	{ &hf_netlogon_auth_data,
		{ "Auth Data", "netlogon.auth.data", FT_BYTES, BASE_HEX,
		NULL, 0, "Auth Data", HFILL }},

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

	{ &hf_netlogon_principal,
		{ "Principal", "netlogon.principal", FT_STRING, BASE_NONE,
		NULL, 0, "Principal", HFILL }},

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

	{ &hf_netlogon_workstation,
		{ "Wkst Name", "netlogon.wkst.name", FT_STRING, BASE_NONE,
		NULL, 0, "Workstation Name", HFILL }},

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

	{ &hf_netlogon_domain_name,
		{ "Domain", "netlogon.domain", FT_STRING, BASE_NONE,
		NULL, 0, "Domain Name", HFILL }},

	{ &hf_netlogon_oem_info,
		{ "OEM Info", "netlogon.oem_info", FT_STRING, BASE_NONE,
		NULL, 0, "OEM Info", HFILL }},

	{ &hf_netlogon_trusted_dc_name,
		{ "Trusted DC", "netlogon.trusted_dc", FT_STRING, BASE_NONE,
		NULL, 0, "Trusted DC", HFILL }},

	{ &hf_netlogon_logonsrv_handle,
		{ "Handle", "netlogon.handle", FT_STRING, BASE_NONE,
		NULL, 0, "Logon Srv Handle", HFILL }},

	{ &hf_netlogon_dummy,
		{ "Dummy", "netlogon.dummy", FT_STRING, BASE_NONE,
		NULL, 0, "Dummy string", HFILL }},

	{ &hf_netlogon_logon_count16,
		{ "Logon Count", "netlogon.logon_count16", FT_UINT16, BASE_DEC, 
		NULL, 0x0, "Number of successful logins", HFILL }},

	{ &hf_netlogon_logon_count,
		{ "Logon Count", "netlogon.logon_count", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Number of successful logins", HFILL }},

	{ &hf_netlogon_last_logon,
		{ "Last Logon", "netlogon.last_logon", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Last Logon", HFILL }},

	{ &hf_netlogon_last_logoff,
		{ "Last Logoff", "netlogon.last_logoff", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Last Logoff", HFILL }},

	{ &hf_netlogon_bad_pw_count16,
		{ "Bad PW Count", "netlogon.bad_pw_count16", FT_UINT16, BASE_DEC, 
		NULL, 0x0, "Number of failed logins", HFILL }},

	{ &hf_netlogon_bad_pw_count,
		{ "Bad PW Count", "netlogon.bad_pw_count", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Number of failed logins", HFILL }},

	{ &hf_netlogon_country,
		{ "Country", "netlogon.country", FT_UINT16, BASE_DEC, 
		VALS(ms_country_codes), 0x0, "Country setting for this account", HFILL }},

	{ &hf_netlogon_codepage,
		{ "Codepage", "netlogon.codepage", FT_UINT16, BASE_DEC, 
		NULL, 0x0, "Codepage setting for this account", HFILL }},

	{ &hf_netlogon_level16,
		{ "Level", "netlogon.level16", FT_UINT16, BASE_DEC, 
		NULL, 0x0, "Which option of the union is represented here", HFILL }},

	{ &hf_netlogon_validation_level,
		{ "Validation Level", "netlogon.validation_level", FT_UINT16, BASE_DEC, 
		NULL, 0x0, "Requested level of validation", HFILL }},

	{ &hf_netlogon_minpasswdlen,
		{ "Min Password Len", "netlogon.min_passwd_len", FT_UINT16, BASE_DEC, 
		NULL, 0x0, "Minimum length of password", HFILL }},

	{ &hf_netlogon_passwdhistorylen,
		{ "Passwd History Len", "netlogon.passwd_history_len", FT_UINT16, BASE_DEC, 
		NULL, 0x0, "Length of password history", HFILL }},

	{ &hf_netlogon_secure_channel_type,
		{ "Sec Chn Type", "netlogon.sec_chn_type", FT_UINT16, BASE_DEC, 
		NULL, 0x0, "Secure Channel Type", HFILL }},

	{ &hf_netlogon_delta_type,
		{ "Delta Type", "netlogon.delta_type", FT_UINT16, BASE_DEC, 
		NULL, 0x0, "Delta Type", HFILL }},

	{ &hf_netlogon_blob_size,
		{ "Size", "netlogon.blob.size", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Size in bytes of BLOB", HFILL }},

	{ &hf_netlogon_code,
		{ "Code", "netlogon.code", FT_UINT32, BASE_HEX, 
		NULL, 0x0, "Code", HFILL }},

	{ &hf_netlogon_level,
		{ "Level", "netlogon.level", FT_UINT32, BASE_DEC, 
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

	{ &hf_netlogon_num_controllers,
		{ "Num DCs", "netlogon.num_dc", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Number of domain controllers", HFILL }},

	{ &hf_netlogon_num_other_groups,
		{ "Num Other Groups", "netlogon.num_other_groups", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "", HFILL }},

	{ &hf_netlogon_flags,
		{ "Flags", "netlogon.flags", FT_UINT32, BASE_HEX, 
		NULL, 0x0, "", HFILL }},

	{ &hf_netlogon_user_flags,
		{ "User Flags", "netlogon.user_flags", FT_UINT32, BASE_HEX, 
		NULL, 0x0, "", HFILL }},

	{ &hf_netlogon_auth_flags,
		{ "Auth Flags", "netlogon.auth_flags", FT_UINT32, BASE_HEX, 
		NULL, 0x0, "", HFILL }},

	{ &hf_netlogon_systemflags,
		{ "System Flags", "netlogon.system_flags", FT_UINT32, BASE_HEX, 
		NULL, 0x0, "", HFILL }},

	{ &hf_netlogon_database_id,
		{ "Database Id", "netlogon.database_id", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Database Id", HFILL }},

	{ &hf_netlogon_max_size,
		{ "Max Size", "netlogon.max_size", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Max Size of database", HFILL }},

	{ &hf_netlogon_max_log_size,
		{ "Max Log Size", "netlogon.max_log_size", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Max Size of log", HFILL }},

	{ &hf_netlogon_pac_size,
		{ "Pac Size", "netlogon.pac.size", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Size of PacData in bytes", HFILL }},

	{ &hf_netlogon_auth_size,
		{ "Auth Size", "netlogon.auth.size", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Size of AuthData in bytes", HFILL }},

	{ &hf_netlogon_num_deltas,
		{ "Num Deltas", "netlogon.num_deltas", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Number of SAM Deltas in array", HFILL }},

	{ &hf_netlogon_logon_attempts,
		{ "Logon Attempts", "netlogon.logon_attempts", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "Number of logon attempts", HFILL }},

	{ &hf_netlogon_pagefilelimit,
		{ "Page File Limit", "netlogon.page_file_limit", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "", HFILL }},

	{ &hf_netlogon_pagedpoollimit,
		{ "Paged Pool Limit", "netlogon.paged_pool_limit", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "", HFILL }},

	{ &hf_netlogon_nonpagedpoollimit,
		{ "Non-Paged Pool Limit", "netlogon.nonpaged_pool_limit", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "", HFILL }},

	{ &hf_netlogon_minworkingsetsize,
		{ "Min Working Set Size", "netlogon.min_working_set_size", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "", HFILL }},

	{ &hf_netlogon_maxworkingsetsize,
		{ "Max Working Set Size", "netlogon.max_working_set_size", FT_UINT32, BASE_DEC, 
		NULL, 0x0, "", HFILL }},

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

	{ &hf_netlogon_domain_create_time,
		{ "Domain Create Time", "netlogon.domain_create_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Time when this domain was created", HFILL }},

	{ &hf_netlogon_domain_modify_time,
		{ "Domain Modify Time", "netlogon.domain_modify_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Time when this domain was last modified", HFILL }},

	{ &hf_netlogon_db_modify_time,
		{ "DB Modify Time", "netlogon.db_modify_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Time when last modified", HFILL }},

	{ &hf_netlogon_db_create_time,
		{ "DB Create Time", "netlogon.db_create_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Time when created", HFILL }},

	{ &hf_netlogon_audit_retention_period,
		{ "Audit Retention Period", "netlogon.audit_retention_period", FT_RELATIVE_TIME, BASE_NONE,
		NULL, 0, "Audit retention period", HFILL }},

	{ &hf_netlogon_timelimit,
		{ "Time Limit", "netlogon.time_limit", FT_RELATIVE_TIME, BASE_NONE,
		NULL, 0, "", HFILL }}

	};

        static gint *ett[] = {
                &ett_dcerpc_netlogon,
		&ett_TYPE_16,
		&ett_QUOTA_LIMITS,
		&ett_IDENTITY_INFO,
		&ett_TYPE_34,
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
		&ett_TYPE_19,
		&ett_NETLOGON_CONTROL_QUERY_INFO,
		&ett_TYPE_44,
		&ett_TYPE_20,
		&ett_NETLOGON_INFO,
		&ett_TYPE_45,
		&ett_TYPE_47,
		&ett_GUID,
		&ett_LM_OWF_PASSWORD,
		&ett_NT_OWF_PASSWORD,
		&ett_GROUP_MEMBERSHIP,
		&ett_BLOB
        };

        proto_dcerpc_netlogon = proto_register_protocol(
                "Microsoft Network Logon", "NETLOGON", "rpc_netlogon");

        proto_register_field_array(proto_dcerpc_netlogon, hf, 
				   array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dcerpc_netlogon(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_netlogon, ett_dcerpc_netlogon, 
                         &uuid_dcerpc_netlogon, ver_dcerpc_netlogon, 
                         dcerpc_netlogon_dissectors, hf_netlogon_opnum);
}
