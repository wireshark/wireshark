/* packet-dcerpc-netlogon.c
 * Routines for SMB \PIPE\NETLOGON packet disassembly
 * Copyright 2001,2003 Tim Potter <tpot@samba.org>
 *  2002 structure and command dissectors by Ronnie Sahlberg
 *
 * $Id: packet-dcerpc-netlogon.c,v 1.82 2003/06/02 03:53:32 tpot Exp $
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
static int hf_netlogon_guid = -1;
static int hf_netlogon_rc = -1;
static int hf_netlogon_len = -1;
static int hf_netlogon_sensitive_data_flag = -1;
static int hf_netlogon_sensitive_data_len = -1;
static int hf_netlogon_sensitive_data = -1;
static int hf_netlogon_security_information = -1;
static int hf_netlogon_dummy = -1;
static int hf_netlogon_neg_flags = -1;
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
static int hf_netlogon_cipher_len = -1;
static int hf_netlogon_cipher_maxlen = -1;
static int hf_netlogon_cipher_current_data = -1;
static int hf_netlogon_cipher_current_set_time = -1;
static int hf_netlogon_cipher_old_data = -1;
static int hf_netlogon_cipher_old_set_time = -1;
static int hf_netlogon_priv = -1;
static int hf_netlogon_privilege_entries = -1;
static int hf_netlogon_privilege_control = -1;
static int hf_netlogon_privilege_name = -1;
static int hf_netlogon_systemflags = -1;
static int hf_netlogon_pdc_connection_status = -1;
static int hf_netlogon_tc_connection_status = -1;
static int hf_netlogon_restart_state = -1;
static int hf_netlogon_attrs = -1;
static int hf_netlogon_count = -1;
static int hf_netlogon_entries = -1;
static int hf_netlogon_minpasswdlen = -1;
static int hf_netlogon_passwdhistorylen = -1;
static int hf_netlogon_level16 = -1;
static int hf_netlogon_validation_level = -1;
static int hf_netlogon_reference = -1;
static int hf_netlogon_next_reference = -1;
static int hf_netlogon_timestamp = -1;
static int hf_netlogon_level = -1;
static int hf_netlogon_challenge = -1;
static int hf_netlogon_reserved = -1;
static int hf_netlogon_audit_retention_period = -1;
static int hf_netlogon_auditing_mode = -1;
static int hf_netlogon_max_audit_event_count = -1;
static int hf_netlogon_event_audit_option = -1;
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
static int hf_netlogon_downlevel_domain_name = -1;
static int hf_netlogon_dns_domain_name = -1;
static int hf_netlogon_domain_name = -1;
static int hf_netlogon_domain_create_time = -1;
static int hf_netlogon_domain_modify_time = -1;
static int hf_netlogon_modify_count = -1;
static int hf_netlogon_db_modify_time = -1;
static int hf_netlogon_db_create_time = -1;
static int hf_netlogon_oem_info = -1;
static int hf_netlogon_serial_number = -1;
static int hf_netlogon_num_rids = -1;
static int hf_netlogon_num_trusts = -1;
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
static int hf_netlogon_client_site_name = -1;
static int hf_netlogon_workstation = -1;
static int hf_netlogon_workstation_site_name = -1;
static int hf_netlogon_workstation_os = -1;
static int hf_netlogon_workstations = -1;
static int hf_netlogon_workstation_fqdn = -1;
static int hf_netlogon_group_name = -1;
static int hf_netlogon_alias_name = -1;
static int hf_netlogon_country = -1;
static int hf_netlogon_codepage = -1;
static int hf_netlogon_flags = -1;
static int hf_netlogon_trust_attribs = -1;
static int hf_netlogon_trust_type = -1;
static int hf_netlogon_trust_flags = -1;
static int hf_netlogon_trust_flags_inbound = -1;
static int hf_netlogon_trust_flags_outbound = -1;
static int hf_netlogon_trust_flags_in_forest = -1;
static int hf_netlogon_trust_flags_native_mode = -1;
static int hf_netlogon_trust_flags_primary = -1;
static int hf_netlogon_trust_flags_tree_root = -1;
static int hf_netlogon_trust_parent_index = -1;
static int hf_netlogon_user_flags = -1;
static int hf_netlogon_auth_flags = -1;
static int hf_netlogon_pwd_expired = -1;
static int hf_netlogon_nt_pwd_present = -1;
static int hf_netlogon_lm_pwd_present = -1;
static int hf_netlogon_code = -1;
static int hf_netlogon_database_id = -1;
static int hf_netlogon_sync_context = -1;
static int hf_netlogon_max_size = -1;
static int hf_netlogon_max_log_size = -1;
static int hf_netlogon_dns_host = -1;
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
static int hf_netlogon_get_dcname_request_flags = -1;
static int hf_netlogon_get_dcname_request_flags_force_rediscovery = -1;
static int hf_netlogon_get_dcname_request_flags_directory_service_required = -1;
static int hf_netlogon_get_dcname_request_flags_directory_service_preferred = -1;
static int hf_netlogon_get_dcname_request_flags_gc_server_required = -1;
static int hf_netlogon_get_dcname_request_flags_pdc_required = -1;
static int hf_netlogon_get_dcname_request_flags_background_only = -1;
static int hf_netlogon_get_dcname_request_flags_ip_required = -1;
static int hf_netlogon_get_dcname_request_flags_kdc_required = -1;
static int hf_netlogon_get_dcname_request_flags_timeserv_required = -1;
static int hf_netlogon_get_dcname_request_flags_writable_required = -1;
static int hf_netlogon_get_dcname_request_flags_good_timeserv_preferred = -1;
static int hf_netlogon_get_dcname_request_flags_avoid_self = -1;
static int hf_netlogon_get_dcname_request_flags_only_ldap_needed = -1;
static int hf_netlogon_get_dcname_request_flags_is_flat_name = -1;
static int hf_netlogon_get_dcname_request_flags_is_dns_name = -1;
static int hf_netlogon_get_dcname_request_flags_return_dns_name = -1;
static int hf_netlogon_get_dcname_request_flags_return_flat_name = -1;
static int hf_netlogon_dc_flags = -1;
static int hf_netlogon_dc_flags_pdc_flag = -1;
static int hf_netlogon_dc_flags_gc_flag = -1;
static int hf_netlogon_dc_flags_ldap_flag = -1;
static int hf_netlogon_dc_flags_ds_flag = -1;
static int hf_netlogon_dc_flags_kdc_flag = -1;
static int hf_netlogon_dc_flags_timeserv_flag = -1;
static int hf_netlogon_dc_flags_closest_flag = -1;
static int hf_netlogon_dc_flags_writable_flag = -1;
static int hf_netlogon_dc_flags_good_timeserv_flag = -1;
static int hf_netlogon_dc_flags_ndnc_flag = -1;
static int hf_netlogon_dc_flags_dns_controller_flag = -1;
static int hf_netlogon_dc_flags_dns_domain_flag = -1;
static int hf_netlogon_dc_flags_dns_forest_flag = -1;

static gint ett_dcerpc_netlogon = -1;
static gint ett_QUOTA_LIMITS = -1;
static gint ett_IDENTITY_INFO = -1;
static gint ett_DELTA_ENUM = -1;
static gint ett_CYPHER_VALUE = -1;
static gint ett_UNICODE_MULTI = -1;
static gint ett_DOMAIN_CONTROLLER_INFO = -1;
static gint ett_UNICODE_STRING_512 = -1;
static gint ett_TYPE_50 = -1;
static gint ett_TYPE_52 = -1;
static gint ett_DELTA_ID_UNION = -1;
static gint ett_TYPE_44 = -1;
static gint ett_DELTA_UNION = -1;
static gint ett_LM_OWF_PASSWORD = -1;
static gint ett_NT_OWF_PASSWORD = -1;
static gint ett_GROUP_MEMBERSHIP = -1;
static gint ett_BLOB = -1;
static gint ett_DS_DOMAIN_TRUSTS = -1;
static gint ett_DOMAIN_TRUST_INFO = -1;
static gint ett_trust_flags = -1;
static gint ett_get_dcname_request_flags = -1;
static gint ett_dc_flags = -1;

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
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "Server Handle", 
		hf_netlogon_logonsrv_handle, 0);

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

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "Effective Account", 
		hf_netlogon_acct_name, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_priv, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_auth_flags, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_count, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_bad_pw_count, NULL);

	/* XXX - are these all UNIX "time_t"s, like the time stamps in
	   credentials?

	   Or are they, as per some RAP-based operations, UTIMEs? */
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

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "Computer", hf_netlogon_computer_name, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "Domain", hf_netlogon_domain_name, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "Script", hf_netlogon_logon_script, 0);

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

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, "Account", hf_netlogon_acct_name, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, "Workstation", hf_netlogon_workstation, 0);

	return offset;
}


static int
netlogon_dissect_netlogonuaslogon_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_VALIDATION_UAS_INFO, NDR_POINTER_UNIQUE,
		"VALIDATION_UAS_INFO", -1);

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

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, "Account", hf_netlogon_acct_name, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, "Workstation", hf_netlogon_workstation, 0);

	return offset;
}


static int
netlogon_dissect_netlogonuaslogoff_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_LOGOFF_UAS_INFO, NDR_POINTER_REF,
		"LOGOFF_UAS_INFO", -1);

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

	/* XXX: It would be nice to get the domain and account name 
           displayed in COL_INFO. */

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_dom, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_param_ctrl, NULL);

	offset = dissect_ndr_uint64(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_id, NULL);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_acct_name, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
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

static void dissect_nt_chal_resp_cb(packet_info *pinfo _U_, proto_tree *tree, 
				    proto_item *item _U_, tvbuff_t *tvb, 
				    int start_offset, int end_offset, 
				    void *callback_args _U_)
{
	int len;

	/* Skip over 3 guint32's in NDR format */

	if (start_offset % 4)
		start_offset += 4 - (start_offset % 4);

	start_offset += 12;
	len = end_offset - start_offset;

	/* Call ntlmv2 response dissector */

	if (len > 24)
		dissect_ntlmv2_response(tvb, tree, start_offset, len);
}

static int
netlogon_dissect_NETWORK_INFO(tvbuff_t *tvb, int offset,
		packet_info *pinfo, proto_tree *tree,
		char *drep)
{
	offset = netlogon_dissect_LOGON_IDENTITY_INFO(tvb, offset,
		pinfo, tree, drep);

	offset = netlogon_dissect_CHALLENGE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_counted_byte_array_cb(
		tvb, offset, pinfo, tree, drep, hf_netlogon_nt_chal_resp,
		dissect_nt_chal_resp_cb, NULL);

	offset = dissect_ndr_counted_byte_array(tvb, offset, pinfo, tree, drep,
		hf_netlogon_lm_chal_resp);

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
			"INTERACTIVE_INFO:", -1);
		break;
	case 2:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_NETWORK_INFO, NDR_POINTER_UNIQUE,
			"NETWORK_INFO:", -1);
		break;
	case 3:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_SERVICE_INFO, NDR_POINTER_UNIQUE,
			"SERVICE_INFO:", -1);
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
	dcerpc_info *di;
	nstime_t ts;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	offset = netlogon_dissect_CREDENTIAL(tvb, offset,
		pinfo, tree, drep);

	/*
	 * XXX - this appears to be a UNIX time_t in some credentials, but
	 * appears to be random junk in other credentials.
	 * For example, it looks like a UNIX time_t in "credential"
	 * AUTHENTICATORs, but like random junk in "return_authenticator"
	 * AUTHENTICATORs.
	 */
	ALIGN_TO_4_BYTES;
	ts.secs = tvb_get_letohl(tvb, offset);
	ts.nsecs = 0;
	proto_tree_add_time(tree, hf_netlogon_timestamp, tvb, offset, 4, &ts);
	offset+= 4;

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

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_acct_name, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_full_name, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_script, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_profile_path, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_home_dir, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
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
		"GROUP_MEMBERSHIP_ARRAY", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_user_flags, NULL);

	offset = netlogon_dissect_USER_SESSION_KEY(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_srv, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_dom, 0);

	offset = dissect_ndr_nt_PSID(tvb, offset,
		pinfo, tree, drep, -1);

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

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_acct_name, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_full_name, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_script, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_profile_path, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_home_dir, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
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
		"GROUP_MEMBERSHIP_ARRAY", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_user_flags, NULL);

	offset = netlogon_dissect_USER_SESSION_KEY(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_srv, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_dom, 0);

	offset = dissect_ndr_nt_PSID(tvb, offset,
		pinfo, tree, drep, -1);

	for(i=0;i<10;i++){
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_long, NULL);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_num_other_groups, NULL);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_ndr_nt_SID_AND_ATTRIBUTES_ARRAY, NDR_POINTER_UNIQUE,
		"SID_AND_ATTRIBUTES_ARRAY:", -1);

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
		netlogon_dissect_PAC, NDR_POINTER_UNIQUE, "PAC:", -1);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_dom, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_srv, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_principal, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_auth_size, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTH, NDR_POINTER_UNIQUE, "AUTH:", -1);

	offset = netlogon_dissect_USER_SESSION_KEY(tvb, offset,
		pinfo, tree, drep);

	for(i=0;i<10;i++){
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_long, NULL);
	}

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
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
			"VALIDATION_SAM_INFO:", -1);
		break;
	case 3:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_VALIDATION_SAM_INFO2, NDR_POINTER_UNIQUE,
			"VALIDATION_SAM_INFO2:", -1);
		break;
	case 4:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_VALIDATION_PAC_INFO, NDR_POINTER_UNIQUE,
			"VALIDATION_PAC_INFO:", -1);
		break;
	case 5:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_VALIDATION_PAC_INFO, NDR_POINTER_UNIQUE,
			"VALIDATION_PAC_INFO:", -1);
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
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "Computer Name", 
		hf_netlogon_computer_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_UNIQUE,
		"AUTHENTICATOR: credential", -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_UNIQUE,
		"AUTHENTICATOR: return_authenticator", -1);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_level16, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_LEVEL, NDR_POINTER_REF,
		"LEVEL: LogonLevel", -1);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_validation_level, NULL);

	return offset;
}

static int
netlogon_dissect_netlogonsamlogon_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_UNIQUE,
		"AUTHENTICATOR: return_authenticator", -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_VALIDATION, NDR_POINTER_REF,
		"VALIDATION:", -1);

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

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "Computer Name", 
		hf_netlogon_computer_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_UNIQUE,
		"AUTHENTICATOR: credential", -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_UNIQUE,
		"AUTHENTICATOR: return_authenticator", -1);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_level16, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_LEVEL, NDR_POINTER_REF,
		"LEVEL: logoninformation", -1);

	return offset;
}
static int
netlogon_dissect_netlogonsamlogoff_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_UNIQUE,
		"AUTHENTICATOR: return_authenticator", -1);

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
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer_cb(
		tvb, offset, pinfo, tree, drep, 
		dissect_ndr_wchar_cvstring, NDR_POINTER_REF, 
		"Computer Name", hf_netlogon_computer_name, 
		cb_wstr_postprocess, 
		GINT_TO_POINTER(CB_STR_COL_INFO | 1));

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_CREDENTIAL, NDR_POINTER_REF,
		"CREDENTIAL: client challenge", -1);

	return offset;
}
static int
netlogon_dissect_netserverreqchallenge_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_CREDENTIAL, NDR_POINTER_REF,
		"CREDENTIAL: server credential", -1);

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

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, "User Name", hf_netlogon_acct_name, 0);

	offset = netlogon_dissect_NETLOGON_SECURE_CHANNEL_TYPE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, "Computer Name", hf_netlogon_computer_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_CREDENTIAL, NDR_POINTER_REF,
		"CREDENTIAL: client challenge", -1);

	return offset;
}
static int
netlogon_dissect_netserverauthenticate_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_CREDENTIAL, NDR_POINTER_REF,
		"CREDENTIAL: server challenge", -1);

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

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, "User Name", hf_netlogon_acct_name, 0);

	offset = netlogon_dissect_NETLOGON_SECURE_CHANNEL_TYPE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, "Computer Name", hf_netlogon_computer_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: credential", -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_ENCRYPTED_LM_OWF_PASSWORD, NDR_POINTER_REF,
		"ENCRYPTED_LM_OWF_PASSWORD: hashed_pwd", -1);

	return offset;
}
static int
netlogon_dissect_netserverpasswordset_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: return_authenticator", -1);

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
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "Account Name", hf_netlogon_acct_name, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
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
		"SENSITIVE_DATA", -1);

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
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_acct_name, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_full_name, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_user_rid, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_group_rid, NULL);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_home_dir, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dir_drive, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_script, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_acct_desc, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
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

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_comment, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
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

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
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
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_domain_name, 1);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
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

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
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
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_group_name, 0);

	offset = netlogon_dissect_GROUP_MEMBERSHIP(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_group_desc, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_security_information, NULL);

	offset = lsa_dissect_LSA_SECURITY_DESCRIPTOR(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
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

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		di->hf_index, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		di->hf_index, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
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
		"RIDs:", -1);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_ATTRIB_array, NDR_POINTER_UNIQUE,
		"Attribs:", -1);

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
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_alias_name, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_alias_rid, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_security_information, NULL);

	offset = lsa_dissect_LSA_SECURITY_DESCRIPTOR(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
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
		"Event Audit Options:", -1);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_domain_name, 0);

	offset = dissect_ndr_nt_PSID(tvb, offset,
		pinfo, tree, drep, -1);

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

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
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
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dc_name, 0);

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
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_domain_name, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_num_controllers, NULL);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_CONTROLLER_ARRAY, NDR_POINTER_UNIQUE,
		"Domain Controllers:", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_security_information, NULL);

	offset = lsa_dissect_LSA_SECURITY_DESCRIPTOR(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
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
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
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
		"PRIV_ATTR_ARRAY:", -1);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_PRIV_NAME_ARRAY, NDR_POINTER_UNIQUE,
		"PRIV_NAME_ARRAY:", -1);

	offset = netlogon_dissect_QUOTA_LIMITS(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_systemflags, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_security_information, NULL);

	offset = lsa_dissect_LSA_SECURITY_DESCRIPTOR(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
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
 * IDL   long len;
 * IDL   long maxlen;
 * IDL   [unique][size_is(maxlen)][length_is(len)] char *cipher_data;
 * IDL } CIPHER_VALUE;
 */
static int
netlogon_dissect_CIPHER_VALUE_DATA(tvbuff_t *tvb, int offset,
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

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
		hf_netlogon_cipher_maxlen, NULL);

	/* skip offset */
	offset += 4;

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
		hf_netlogon_cipher_len, &data_len);

	proto_tree_add_item(tree, di->hf_index, tvb, offset,
		data_len, FALSE);
	offset += data_len;

	return offset;
}
static int
netlogon_dissect_CIPHER_VALUE(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep, char *name, int hf_index)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			name);
		tree = proto_item_add_subtree(item, ett_CYPHER_VALUE);
	}

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
		hf_netlogon_cipher_len, NULL);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
		hf_netlogon_cipher_maxlen, NULL);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_CIPHER_VALUE_DATA, NDR_POINTER_UNIQUE,
		name, hf_index);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

/*
 * IDL typedef struct {
 * IDL   CIPHER_VALUE current_cipher;
 * IDL   NTTIME current_cipher_set_time;
 * IDL   CIPHER_VALUE old_cipher;
 * IDL   NTTIME old_cipher_set_time;
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
 * IDL } DELTA_SECRET;
 */
static int
netlogon_dissect_DELTA_SECRET(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = netlogon_dissect_CIPHER_VALUE(tvb, offset,
		pinfo, tree, drep,
		"CIPHER_VALUE: current cipher value",
		hf_netlogon_cipher_current_data);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_cipher_current_set_time);

	offset = netlogon_dissect_CIPHER_VALUE(tvb, offset,
		pinfo, tree, drep,
		"CIPHER_VALUE: old cipher value",
		hf_netlogon_cipher_old_data);

	offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
		hf_netlogon_cipher_old_set_time);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_security_information, NULL);

	offset = lsa_dissect_LSA_SECURITY_DESCRIPTOR(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dummy, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
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
 * IDL   long low_value;
 * IDL   long high_value;
 * } MODIFIED_COUNT;
 */
static int
netlogon_dissect_MODIFIED_COUNT(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint64(tvb, offset, pinfo, tree, drep,
		hf_netlogon_modify_count, NULL);

	return offset;
}


#define DT_DELTA_DOMAIN			1
#define DT_DELTA_GROUP			2
#define DT_DELTA_RENAME_GROUP		4
#define DT_DELTA_USER			5
#define DT_DELTA_RENAME_USER		7
#define DT_DELTA_GROUP_MEMBER		8
#define DT_DELTA_ALIAS			9
#define DT_DELTA_RENAME_ALIAS		11
#define DT_DELTA_ALIAS_MEMBER		12
#define DT_DELTA_POLICY			13
#define DT_DELTA_TRUSTED_DOMAINS	14
#define DT_DELTA_ACCOUNTS		16
#define DT_DELTA_SECRET			18
#define DT_DELTA_DELETE_GROUP		20
#define DT_DELTA_DELETE_USER		21
#define DT_MODIFIED_COUNT		22
static const value_string delta_type_vals[] = {
	{ DT_DELTA_DOMAIN,		"Domain" },
	{ DT_DELTA_GROUP,		"Group" },
	{ DT_DELTA_RENAME_GROUP,	"Rename Group" },
	{ DT_DELTA_USER,		"User" },
	{ DT_DELTA_RENAME_USER,		"Rename User" },
	{ DT_DELTA_GROUP_MEMBER,	"Group Member" },
	{ DT_DELTA_ALIAS,		"Alias" },
	{ DT_DELTA_RENAME_ALIAS,	"Rename Alias" },
	{ DT_DELTA_ALIAS_MEMBER,	"Alias Member" },
	{ DT_DELTA_POLICY,		"Policy" },
	{ DT_DELTA_TRUSTED_DOMAINS,	"Trusted Domains" },
	{ DT_DELTA_ACCOUNTS,		"Accounts" },
	{ DT_DELTA_SECRET,		"Secret" },
	{ DT_DELTA_DELETE_GROUP,	"Delete Group" },
	{ DT_DELTA_DELETE_USER,		"Delete User" },
	{ DT_MODIFIED_COUNT,		"Modified Count" },
	{ 0, NULL }
};
/*
 * IDL typedef [switch_type(short)] union {
 * IDL   [case(1)][unique] DELTA_DOMAIN *domain;
 * IDL   [case(2)][unique] DELTA_GROUP *group;
 * IDL   [case(4)][unique] DELTA_RENAME_GROUP *rename_group;
 * IDL   [case(5)][unique] DELTA_USER *user;
 * IDL   [case(7)][unique] DELTA_RENAME_USER *rename_user;
 * IDL   [case(8)][unique] DELTA_GROUP_MEMBER *group_member;
 * IDL   [case(9)][unique] DELTA_ALIAS *alias;
 * IDL   [case(11)][unique] DELTA_RENAME_ALIAS *rename_alias;
 * IDL   [case(12)][unique] DELTA_ALIAS_MEMBER *alias_member;
 * IDL   [case(13)][unique] DELTA_POLICY *policy;
 * IDL   [case(14)][unique] DELTA_TRUSTED_DOMAINS *trusted_domains;
 * IDL   [case(16)][unique] DELTA_ACCOUNTS *accounts;
 * IDL   [case(18)][unique] DELTA_SECRET *secret;
 * IDL   [case(20)][unique] DELTA_DELETE_USER *delete_group;
 * IDL   [case(21)][unique] DELTA_DELETE_USER *delete_user;
 * IDL   [case(22)][unique] MODIFIED_COUNT *modified_count;
 * IDL } DELTA_UNION;
 */
static int
netlogon_dissect_DELTA_UNION(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;
	guint16 level;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"DELTA_UNION:");
		tree = proto_item_add_subtree(item, ett_DELTA_UNION);
	}

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_delta_type, &level);

	ALIGN_TO_4_BYTES;
	switch(level){
	case 1:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DELTA_DOMAIN, NDR_POINTER_UNIQUE,
			"DELTA_DOMAIN:", -1);
		break;
	case 2:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DELTA_GROUP, NDR_POINTER_UNIQUE,
			"DELTA_GROUP:", -1);
		break;
	case 4:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DELTA_RENAME, NDR_POINTER_UNIQUE,
			"DELTA_RENAME_GROUP:", hf_netlogon_group_name);
		break;
	case 5:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DELTA_USER, NDR_POINTER_UNIQUE,
			"DELTA_USER:", -1);
		break;
	case 7:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DELTA_RENAME, NDR_POINTER_UNIQUE,
			"DELTA_RENAME_USER:", hf_netlogon_acct_name);
		break;
	case 8:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DELTA_GROUP_MEMBER, NDR_POINTER_UNIQUE,
			"DELTA_GROUP_MEMBER:", -1);
		break;
	case 9:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DELTA_ALIAS, NDR_POINTER_UNIQUE,
			"DELTA_ALIAS:", -1);
		break;
	case 11:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DELTA_RENAME, NDR_POINTER_UNIQUE,
			"DELTA_RENAME_ALIAS:", hf_netlogon_alias_name);
		break;
	case 12:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DELTA_ALIAS_MEMBER, NDR_POINTER_UNIQUE,
			"DELTA_ALIAS_MEMBER:", -1);
		break;
	case 13:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DELTA_POLICY, NDR_POINTER_UNIQUE,
			"DELTA_POLICY:", -1);
		break;
	case 14:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DELTA_TRUSTED_DOMAINS, NDR_POINTER_UNIQUE,
			"DELTA_TRUSTED_DOMAINS:", -1);
		break;
	case 16:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DELTA_ACCOUNTS, NDR_POINTER_UNIQUE,
			"DELTA_ACCOUNTS:", -1);
		break;
	case 18:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DELTA_SECRET, NDR_POINTER_UNIQUE,
			"DELTA_SECRET:", -1);
		break;
	case 20:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DELTA_DELETE_USER, NDR_POINTER_UNIQUE,
			"DELTA_DELETE_GROUP:", -1);
		break;
	case 21:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DELTA_DELETE_USER, NDR_POINTER_UNIQUE,
			"DELTA_DELETE_USER:", -1);
		break;
	case 22:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_MODIFIED_COUNT, NDR_POINTER_UNIQUE,
			"MODIFIED_COUNT:", -1);
		break;
	}

	proto_item_set_len(item, offset-old_offset);
	return offset;
}



/* IDL XXX must verify this one, especially 13-19
 * IDL typedef [switch_type(short)] union {
 * IDL   [case(1)] long rid;
 * IDL   [case(2)] long rid;
 * IDL   [case(3)] long rid;
 * IDL   [case(4)] long rid;
 * IDL   [case(5)] long rid;
 * IDL   [case(6)] long rid;
 * IDL   [case(7)] long rid;
 * IDL   [case(8)] long rid;
 * IDL   [case(9)] long rid;
 * IDL   [case(10)] long rid;
 * IDL   [case(11)] long rid;
 * IDL   [case(12)] long rid;
 * IDL   [case(13)] [unique] SID *sid;
 * IDL   [case(14)] [unique] SID *sid;
 * IDL   [case(15)] [unique] SID *sid;
 * IDL   [case(16)] [unique] SID *sid;
 * IDL   [case(17)] [unique] SID *sid;
 * IDL   [case(18)] [unique][string] wchar_t *Name ;
 * IDL   [case(19)] [unique][string] wchar_t *Name ;
 * IDL   [case(20)] long rid;
 * IDL   [case(21)] long rid;
 * IDL } DELTA_ID_UNION;
 */
static int
netlogon_dissect_DELTA_ID_UNION(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;
	guint16 level;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"DELTA_ID_UNION:");
		tree = proto_item_add_subtree(item, ett_DELTA_ID_UNION);
	}

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_level16, &level);

	ALIGN_TO_4_BYTES;
	switch(level){
	case 1:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_user_rid, NULL);
		break;
	case 2:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_user_rid, NULL);
		break;
	case 3:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_user_rid, NULL);
		break;
	case 4:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_user_rid, NULL);
		break;
	case 5:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_user_rid, NULL);
		break;
	case 6:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_user_rid, NULL);
		break;
	case 7:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_user_rid, NULL);
		break;
	case 8:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_user_rid, NULL);
		break;
	case 9:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_user_rid, NULL);
		break;
	case 10:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_user_rid, NULL);
		break;
	case 11:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_user_rid, NULL);
		break;
	case 12:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_user_rid, NULL);
		break;
	case 13:
		offset = dissect_ndr_nt_PSID(tvb, offset,
			pinfo, tree, drep, -1);
		break;
	case 14:
		offset = dissect_ndr_nt_PSID(tvb, offset,
			pinfo, tree, drep, -1);
		break;
	case 15:
		offset = dissect_ndr_nt_PSID(tvb, offset,
			pinfo, tree, drep, -1);
		break;
	case 16:
		offset = dissect_ndr_nt_PSID(tvb, offset,
			pinfo, tree, drep, -1);
		break;
	case 17:
		offset = dissect_ndr_nt_PSID(tvb, offset,
			pinfo, tree, drep, -1);
		break;
	case 18:
		offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, 
			tree, drep, NDR_POINTER_UNIQUE, "unknown", 
			hf_netlogon_unknown_string, 0);
		break;
	case 19:
		offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, 
			tree, drep, NDR_POINTER_UNIQUE, "unknown", 
			hf_netlogon_unknown_string, 0);
		break;
	case 20:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_user_rid, NULL);
		break;
	case 21:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_user_rid, NULL);
		break;
	}

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

/*
 * IDL typedef struct {
 * IDL   short delta_type;
 * IDL   DELTA_ID_UNION delta_id_union;
 * IDL   DELTA_UNION delta_union;
 * IDL } DELTA_ENUM;
 */
static int
netlogon_dissect_DELTA_ENUM(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"DELTA_ENUM:");
		tree = proto_item_add_subtree(item, ett_DELTA_ENUM);
	}

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_delta_type, NULL);

	offset = netlogon_dissect_DELTA_ID_UNION(tvb, offset,
		pinfo, tree, drep);

	offset = netlogon_dissect_DELTA_UNION(tvb, offset,
		pinfo, tree, drep);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_DELTA_ENUM_array(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_DELTA_ENUM);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long num_deltas;
 * IDL   [unique][size_is(num_deltas)] DELTA_ENUM *delta_enum;
 * IDL } DELTA_ENUM_ARRAY;
 */
static int
netlogon_dissect_DELTA_ENUM_ARRAY(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_num_deltas, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_DELTA_ENUM_array, NDR_POINTER_UNIQUE,
		"DELTA_ENUM: deltas", -1);

	return offset;
}


/*
 * IDL long NetDatabaseDeltas(
 * IDL      [in][string][ref] wchar_t *logonserver, # REF!!!
 * IDL      [in][string][ref] wchar_t *computername,
 * IDL      [in][ref] AUTHENTICATOR credential,
 * IDL      [in][out][ref] AUTHENTICATOR return_authenticator,
 * IDL      [in] long database_id,
 * IDL      [in][out][ref] MODIFIED_COUNT domain_modify_count,
 * IDL      [in] long preferredmaximumlength,
 * IDL      [out][unique] DELTA_ENUM_ARRAY *delta_enum_array
 * IDL );
 */
static int
netlogon_dissect_netsamdeltas_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, "Server Handle", hf_netlogon_logonsrv_handle, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, "Computer Name", hf_netlogon_computer_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: credential", -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: return_authenticator", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_database_id, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_MODIFIED_COUNT, NDR_POINTER_REF,
		"MODIFIED_COUNT: domain modified count", -1);

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
		"AUTHENTICATOR: return_authenticator", -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_MODIFIED_COUNT, NDR_POINTER_REF,
		"MODIFIED_COUNT: domain modified count", -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_DELTA_ENUM_ARRAY, NDR_POINTER_UNIQUE,
		"DELTA_ENUM_ARRAY: deltas", -1);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}


/*
 * IDL long NetDatabaseSync(
 * IDL      [in][string][ref] wchar_t *logonserver, # REF!!!
 * IDL      [in][string][ref] wchar_t *computername,
 * IDL      [in][ref] AUTHENTICATOR credential,
 * IDL      [in][out][ref] AUTHENTICATOR return_authenticator,
 * IDL      [in] long database_id,
 * IDL      [in][out][ref] long sync_context,
 * IDL      [in] long preferredmaximumlength,
 * IDL      [out][unique] DELTA_ENUM_ARRAY *delta_enum_array
 * IDL );
 */
static int
netlogon_dissect_netlogondatabasesync_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, "Server Handle", hf_netlogon_logonsrv_handle, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, "Computer Name", hf_netlogon_computer_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: credential", -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: return_authenticator", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_database_id, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_sync_context, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_max_size, NULL);

	return offset;
}


static int
netlogon_dissect_netlogondatabasesync_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: return_authenticator", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_sync_context, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_DELTA_ENUM_ARRAY, NDR_POINTER_UNIQUE,
		"DELTA_ENUM_ARRAY: deltas", -1);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   char computer_name[16];
 * IDL   long timecreated;
 * IDL   long serial_number;
 * IDL } UAS_INFO_0;
 */
static int
netlogon_dissect_UAS_INFO_0(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	proto_tree_add_item(tree, hf_netlogon_computer_name, tvb, offset, 16, FALSE);
	offset += 16;

	proto_tree_add_text(tree, tvb, offset, 4, "Time Created: unknown time format");
	offset+= 4;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_serial_number, NULL);

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

/*
 * IDL long NetAccountDelta(
 * IDL      [in][string][unique] wchar_t *logonserver,
 * IDL      [in][string][ref] wchar_t *computername,
 * IDL      [in][ref] AUTHENTICATOR credential,
 * IDL      [in][out][ref] AUTHENTICATOR return_authenticator,
 * IDL      [out][ref][size_is(count_returned)] char *Buffer,
 * IDL      [out][ref] long count_returned,
 * IDL      [out][ref] long total_entries,
 * IDL      [in][out][ref] UAS_INFO_0 recordid,
 * IDL      [in][long] count,
 * IDL      [in][long] level,
 * IDL      [in][long] buffersize,
 * IDL );
 */
static int
netlogon_dissect_netlogonaccountdeltas_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, "Computer Name", hf_netlogon_computer_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: credential", -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: return_authenticator", -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_UAS_INFO_0, NDR_POINTER_REF,
		"UAS_INFO_0: RecordID", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_count, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_level, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_max_size, NULL);

	return offset;
}
static int
netlogon_dissect_netlogonaccountdeltas_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: return_authenticator", -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_BYTE_array, NDR_POINTER_REF,
		"BYTE_array: Buffer", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_count, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_UAS_INFO_0, NDR_POINTER_REF,
		"UAS_INFO_0: RecordID", -1);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}


/*
 * IDL long NetAccountDelta(
 * IDL      [in][string][unique] wchar_t *logonserver,
 * IDL      [in][string][ref] wchar_t *computername,
 * IDL      [in][ref] AUTHENTICATOR credential,
 * IDL      [in][out][ref] AUTHENTICATOR return_authenticator,
 * IDL      [out][ref][size_is(count_returned)] char *Buffer,
 * IDL      [out][ref] long count_returned,
 * IDL      [out][ref] long total_entries,
 * IDL      [out][ref] long next_reference,
 * IDL      [in][long] reference,
 * IDL      [in][long] level,
 * IDL      [in][long] buffersize,
 * IDL      [in][out][ref] UAS_INFO_0 recordid,
 * IDL );
 */
static int
netlogon_dissect_netlogonaccountsync_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, "Computer Name", hf_netlogon_computer_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: credential", -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: return_authenticator", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reference, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_level, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_max_size, NULL);

	return offset;
}
static int
netlogon_dissect_netlogonaccountsync_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: return_authenticator", -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_BYTE_array, NDR_POINTER_REF,
		"BYTE_array: Buffer", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_count, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_entries, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_next_reference, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_UAS_INFO_0, NDR_POINTER_REF,
		"UAS_INFO_0: RecordID", -1);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}


/*
 * IDL long NetGetDCName(
 * IDL    [in][ref][string] wchar_t *logon_server,
 * IDL    [in][unique][string] wchar_t *domainname,
 * IDL    [out][unique][string] wchar_t *dcname,
 * IDL };
 */
static int
netlogon_dissect_netlogongetdcname_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, "Server Handle", hf_netlogon_logonsrv_handle, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "Domain", hf_netlogon_domain_name, 0);

	return offset;
}
static int
netlogon_dissect_netlogongetdcname_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "Domain", hf_netlogon_dc_name, 0);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}



/*
 * IDL typedef struct {
 * IDL   long flags;
 * IDL   long pdc_connection_status;
 * IDL } NETLOGON_INFO_1;
 */
static int
netlogon_dissect_NETLOGON_INFO_1(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_flags, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_pdc_connection_status, NULL);

	return offset;
}


/*
 * IDL typedef struct {
 * IDL   long flags;
 * IDL   long pdc_connection_status;
 * IDL   [unique][string] wchar_t trusted_dc_name;
 * IDL   long tc_connection_status;
 * IDL } NETLOGON_INFO_2;
 */
static int
netlogon_dissect_NETLOGON_INFO_2(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_flags, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_pdc_connection_status, NULL);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "Trusted DC Name", 
		hf_netlogon_trusted_dc_name, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_tc_connection_status, NULL);

	return offset;
}


/*
 * IDL typedef struct {
 * IDL   long flags;
 * IDL   long logon_attempts;
 * IDL   long reserved;
 * IDL   long reserved;
 * IDL   long reserved;
 * IDL   long reserved;
 * IDL   long reserved;
 * IDL } NETLOGON_INFO_3;
 */
static int
netlogon_dissect_NETLOGON_INFO_3(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_flags, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_logon_attempts, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_reserved, NULL);

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
 * IDL typedef [switch_type(long)] union {
 * IDL   [case(1)] [unique] NETLOGON_INFO_1 *i1;
 * IDL   [case(2)] [unique] NETLOGON_INFO_2 *i2;
 * IDL   [case(3)] [unique] NETLOGON_INFO_3 *i3;
 * IDL } CONTROL_QUERY_INFORMATION;
 */
static int
netlogon_dissect_CONTROL_QUERY_INFORMATION(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	guint32 level;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_level, &level);

	ALIGN_TO_4_BYTES;
	switch(level){
	case 1:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_NETLOGON_INFO_1, NDR_POINTER_UNIQUE,
			"NETLOGON_INFO_1:", -1);
		break;
	case 2:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_NETLOGON_INFO_2, NDR_POINTER_UNIQUE,
			"NETLOGON_INFO_2:", -1);
		break;
	case 3:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_NETLOGON_INFO_3, NDR_POINTER_UNIQUE,
			"NETLOGON_INFO_3:", -1);
		break;
	}

	return offset;
}


/*
 * IDL long NetLogonControl(
 * IDL      [in][string][unique] wchar_t *logonserver,
 * IDL      [in] long function_code,
 * IDL      [in] long level,
 * IDL      [out][ref] CONTROL_QUERY_INFORMATION
 * IDL );
 */
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
		netlogon_dissect_CONTROL_QUERY_INFORMATION, NDR_POINTER_REF,
		"CONTROL_QUERY_INFORMATION:", -1);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}


/*
 * IDL long NetGetDCName(
 * IDL    [in][unique][string] wchar_t *logon_server,
 * IDL    [in][unique][string] wchar_t *domainname,
 * IDL    [out][unique][string] wchar_t *dcname,
 * IDL };
 */
static int
netlogon_dissect_netlogongetanydcname_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "Server Handle", 
		hf_netlogon_logonsrv_handle, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "Domain", hf_netlogon_domain_name, 0);

	return offset;
}
static int
netlogon_dissect_netlogongetanydcname_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "Domain", hf_netlogon_dc_name, 0);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}


/*
 * IDL typedef [switch_type(long)] union {
 * IDL   [case(5)] [unique][string] wchar_t *unknown;
 * IDL   [case(6)] [unique][string] wchar_t *unknown;
 * IDL   [case(0xfffe)] long unknown;
 * IDL   [case(7)] [unique][string] wchar_t *unknown;
 * IDL } CONTROL_DATA_INFORMATION;
 */
/* XXX
 * According to muddle this is what CONTROL_DATA_INFORMATION is supposed
 * to look like. However NetMon does not recognize any such informationlevels.
 *
 * Ill leave it as CONTROL_DATA_INFORMATION with no informationlevels
 * until someone has any source of better authority to call upon.
 */
static int
netlogon_dissect_CONTROL_DATA_INFORMATION(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	guint32 level;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_level, &level);

	ALIGN_TO_4_BYTES;
	switch(level){
	case 5:
		offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, 
			tree, drep, NDR_POINTER_UNIQUE, "unknown", 
			hf_netlogon_unknown_string, 0);
		break;
	case 6:
		offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, 
			tree, drep, NDR_POINTER_UNIQUE, "unknown", 
			hf_netlogon_unknown_string, 0);
		break;
	case 0xfffe:
		offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_netlogon_unknown_long, NULL);
		break;
	case 8:
		offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, 
			tree, drep, NDR_POINTER_UNIQUE, "unknown", 
			hf_netlogon_unknown_string, 0);
		break;
	}

	return offset;
}


/*
 * IDL long NetLogonControl2(
 * IDL      [in][string][unique] wchar_t *logonserver,
 * IDL      [in] long function_code,
 * IDL      [in] long level,
 * IDL      [in][ref] CONTROL_DATA_INFORMATION *data,
 * IDL      [out][ref] CONTROL_QUERY_INFORMATION *query
 * IDL );
 */
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
		netlogon_dissect_CONTROL_DATA_INFORMATION, NDR_POINTER_REF,
		"CONTROL_DATA_INFORMATION: ", -1);

	return offset;
}

static int
netlogon_dissect_netlogoncontrol2_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_CONTROL_QUERY_INFORMATION, NDR_POINTER_REF,
		"CONTROL_QUERY_INFORMATION:", -1);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}


/*
 * IDL long NetServerAuthenticate2(
 * IDL      [in][string][unique] wchar_t *logonserver,
 * IDL      [in][ref][string] wchar_t *username,
 * IDL      [in] short secure_channel_type,
 * IDL      [in][ref][string] wchar_t *computername,
 * IDL      [in][ref] CREDENTIAL *client_chal,
 * IDL      [out][ref] CREDENTIAL *server_chal,
 * IDL      [in][out][ref] long *negotiate_flags,
 * IDL );
 */
static int
netlogon_dissect_netserverauthenticate2_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_pointer_cb(
		tvb, offset, pinfo, tree, drep, 
		dissect_ndr_wchar_cvstring, NDR_POINTER_REF, 
		"User Name", hf_netlogon_acct_name, 
		cb_wstr_postprocess, GINT_TO_POINTER(CB_STR_COL_INFO | 1));

	offset = netlogon_dissect_NETLOGON_SECURE_CHANNEL_TYPE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, "Computer Name", hf_netlogon_computer_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_CREDENTIAL, NDR_POINTER_REF,
		"CREDENTIAL: client_chal", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_neg_flags, NULL);

	return offset;
}

static int
netlogon_dissect_netserverauthenticate2_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_CREDENTIAL, NDR_POINTER_REF,
		"CREDENTIAL: server_chal", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_neg_flags, NULL);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}


/*
 * IDL long NetDatabaseSync2(
 * IDL      [in][string][ref] wchar_t *logonserver, # REF!!!
 * IDL      [in][string][ref] wchar_t *computername,
 * IDL      [in][ref] AUTHENTICATOR credential,
 * IDL      [in][out][ref] AUTHENTICATOR return_authenticator,
 * IDL      [in] long database_id,
 * IDL      [in] short restart_state,
 * IDL      [in][out][ref] long *sync_context,
 * IDL      [in] long preferredmaximumlength,
 * IDL      [out][unique] DELTA_ENUM_ARRAY *delta_enum_array
 * IDL );
 */
static int
netlogon_dissect_netdatabasesync2_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, "Server Handle", hf_netlogon_logonsrv_handle, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, "Computer Name", hf_netlogon_computer_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: credential", -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: return_authenticator", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_database_id, NULL);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_restart_state, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_sync_context, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_max_size, NULL);

	return offset;
}

static int
netlogon_dissect_netdatabasesync2_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: return_authenticator", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_sync_context, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_DELTA_ENUM_ARRAY, NDR_POINTER_UNIQUE,
		"DELTA_ENUM_ARRAY: deltas", -1);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}


/*
 * IDL long NetDatabaseRedo(
 * IDL      [in][string][ref] wchar_t *logonserver, # REF!!!
 * IDL      [in][string][ref] wchar_t *computername,
 * IDL      [in][ref] AUTHENTICATOR credential,
 * IDL      [in][out][ref] AUTHENTICATOR return_authenticator,
 * IDL      [in][ref][size_is(change_log_entry_size)] char *change_log_entry,
 * IDL      [in] long change_log_entry_size,
 * IDL      [out][unique] DELTA_ENUM_ARRAY *delta_enum_array
 * IDL );
 */
static int
netlogon_dissect_netlogondatabaseredo_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, "Server Handle", hf_netlogon_logonsrv_handle, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, "Computer Name", hf_netlogon_computer_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: credential", -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: return_authenticator", -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_BYTE_array, NDR_POINTER_REF,
		"Change log entry: ", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_max_log_size, NULL);

	return offset;
}

static int
netlogon_dissect_netlogondatabaseredo_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: return_authenticator", -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_DELTA_ENUM_ARRAY, NDR_POINTER_UNIQUE,
		"DELTA_ENUM_ARRAY: deltas", -1);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}


/* XXX NetMon does not recognize this as a valid function. Muddle however
 * tells us what parameters it takes but not their names.
 * It looks similar to logoncontrol2.  perhaps it is logoncontrol3?
 */
/*
 * IDL long NetFunction_12(
 * IDL      [in][string][unique] wchar_t *logonserver,
 * IDL      [in] long function_code,
 * IDL      [in] long level,
 * IDL      [in][ref] CONTROL_DATA_INFORMATION *data,
 * IDL      [out][ref] CONTROL_QUERY_INFORMATION *query
 * IDL );
 */
static int
netlogon_dissect_function_12_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_code, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_level, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_CONTROL_DATA_INFORMATION, NDR_POINTER_REF,
		"CONTROL_DATA_INFORMATION: ", -1);

	return offset;
}
static int
netlogon_dissect_function_12_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_CONTROL_QUERY_INFORMATION, NDR_POINTER_REF,
		"CONTROL_QUERY_INFORMATION:", -1);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}




/*qqq*/
/* Updated above this line */

static const value_string trust_type_vals[] = {
	{ 1,				"DOWNLEVEL" },
	{ 2,				"UPLEVEL" },
	{ 3,				"MIT" },
	{ 4,				"DCE" },
	{ 0, NULL }
};

#define DS_INET_ADDRESS		1
#define DS_NETBIOS_ADDRESS	2
static const value_string dc_address_types[] = {
	{ DS_INET_ADDRESS,		"IP/DNS name" },
	{ DS_NETBIOS_ADDRESS,		"NetBIOS name" },
	{ 0, NULL}
};


#define DS_DOMAIN_IN_FOREST		0x0001
#define DS_DOMAIN_DIRECT_OUTBOUND	0x0002
#define DS_DOMAIN_TREE_ROOT		0x0004
#define DS_DOMAIN_PRIMARY		0x0008
#define DS_DOMAIN_NATIVE_MODE		0x0010
#define DS_DOMAIN_DIRECT_INBOUND	0x0020
static const true_false_string trust_inbound = {
	"There is a DIRECT INBOUND trust for the servers domain",
	"There is NO direct inbound trust for the servers domain"
};
static const true_false_string trust_outbound = {
	"There is a DIRECT OUTBOUND trust for this domain",
	"There is NO direct outbound trust for this domain"
};
static const true_false_string trust_in_forest = {
	"The domain is a member IN the same FOREST as the queried server",
	"The domain is NOT a member of the queried servers domain"
};
static const true_false_string trust_native_mode = {
	"The primary domain is a NATIVE MODE w2k domain",
	"The primary is NOT a native mode w2k domain"
};
static const true_false_string trust_primary = {
	"The domain is the PRIMARY domain of the queried server",
	"The domain is NOT the primary domain of the queried server"
};
static const true_false_string trust_tree_root = {
	"The domain is the ROOT of a domain TREE",
	"The domain is NOT a root of a domain tree"
};
static int
netlogon_dissect_DOMAIN_TRUST_FLAGS(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	guint32 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	offset=dissect_ndr_uint32(tvb, offset, pinfo, NULL, drep,
			hf_netlogon_trust_flags, &mask);

	if(parent_tree){
		item = proto_tree_add_uint(parent_tree, hf_netlogon_trust_flags,
			tvb, offset-4, 4, mask);
		tree = proto_item_add_subtree(item, ett_trust_flags);
	}

	proto_tree_add_boolean(tree, hf_netlogon_trust_flags_inbound,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_trust_flags_native_mode,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_trust_flags_primary,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_trust_flags_tree_root,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_trust_flags_outbound,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_trust_flags_in_forest,
		tvb, offset-4, 4, mask);

	return offset;
}


#define DS_FORCE_REDISCOVERY		0x00000001
#define DS_DIRECTORY_SERVICE_REQUIRED	0x00000010
#define DS_DIRECTORY_SERVICE_PREFERRED	0x00000020
#define DS_GC_SERVER_REQUIRED		0x00000040
#define DS_PDC_REQUIRED			0x00000080
#define DS_BACKGROUND_ONLY		0x00000100
#define DS_IP_REQUIRED			0x00000200
#define DS_KDC_REQUIRED			0x00000400
#define DS_TIMESERV_REQUIRED		0x00000800
#define DS_WRITABLE_REQUIRED		0x00001000
#define DS_GOOD_TIMESERV_PREFERRED	0x00002000
#define DS_AVOID_SELF			0x00004000
#define DS_ONLY_LDAP_NEEDED		0x00008000
#define DS_IS_FLAT_NAME			0x00010000
#define DS_IS_DNS_NAME			0x00020000
#define DS_RETURN_DNS_NAME		0x40000000
#define DS_RETURN_FLAT_NAME		0x80000000
static const true_false_string get_dcname_request_flags_force_rediscovery = {
	"FORCE REDISCOVERY of any cached data",
	"You may return cached data"
};
static const true_false_string get_dcname_request_flags_directory_service_required = {
	"DIRECRTORY SERVICE is REQUIRED on the server",
	"We do NOT require directory service servers"
};
static const true_false_string get_dcname_request_flags_directory_service_preferred = {
	"DIRECTORY SERVICE servers are PREFERRED",
	"We do NOT have a preference for directory service servers"
};
static const true_false_string get_dcname_request_flags_gc_server_required = {
	"GC SERVER is REQUIRED",
	"gc server is NOT required"
};
static const true_false_string get_dcname_request_flags_pdc_required = {
	"PDC SERVER is REQUIRED",
	"pdc server is NOT required"
};
static const true_false_string get_dcname_request_flags_background_only = {
	"Only returned cahced data, even if it has expired",
	"Return cached data unless it has expired"
};
static const true_false_string get_dcname_request_flags_ip_required = {
	"IP address is REQUIRED",
	"ip address is NOT required"
};
static const true_false_string get_dcname_request_flags_kdc_required = {
	"KDC server is REQUIRED",
	"kdc server is NOT required"
};
static const true_false_string get_dcname_request_flags_timeserv_required = {
	"TIMESERV service is REQUIRED",
	"timeserv service is NOT required"
};
static const true_false_string get_dcname_request_flags_writable_required = {
	"the requrned dc MUST be WRITEABLE",
	"a read-only dc may be returned"
};
static const true_false_string get_dcname_request_flags_good_timeserv_preferred = {
	"GOOD TIMESERV servers are PREFERRED",
	"we do NOT have a preference for good timeserv servers"
};
static const true_false_string get_dcname_request_flags_avoid_self = {
	"do NOT return self as dc, return someone else",
	"you may return yourSELF as the dc"
};
static const true_false_string get_dcname_request_flags_only_ldap_needed = {
	"we ONLY NEED LDAP, you dont have to return a dc",
	"we need a normal dc, an ldap only server will not do"
};
static const true_false_string get_dcname_request_flags_is_flat_name = {
	"the name we specify is a NetBIOS name",
	"the name we specify is NOT a NetBIOS name"
};
static const true_false_string get_dcname_request_flags_is_dns_name = {
	"the name we specify is a DNS name",
	"ther name we specify is NOT a dns name"
};
static const true_false_string get_dcname_request_flags_return_dns_name = {
	"return a DNS name",
	"you may return a NON-dns name"
};
static const true_false_string get_dcname_request_flags_return_flat_name = {
	"return a NetBIOS name",
	"you may return a NON-NetBIOS name"
};
static int
netlogon_dissect_GET_DCNAME_REQUEST_FLAGS(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	guint32 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	offset=dissect_ndr_uint32(tvb, offset, pinfo, NULL, drep,
			hf_netlogon_get_dcname_request_flags, &mask);

	if(parent_tree){
		item = proto_tree_add_uint(parent_tree, hf_netlogon_get_dcname_request_flags,
			tvb, offset-4, 4, mask);
		tree = proto_item_add_subtree(item, ett_get_dcname_request_flags);
	}

	proto_tree_add_boolean(tree, hf_netlogon_get_dcname_request_flags_return_flat_name,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_get_dcname_request_flags_return_dns_name,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_get_dcname_request_flags_is_flat_name,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_get_dcname_request_flags_is_dns_name,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_get_dcname_request_flags_only_ldap_needed,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_get_dcname_request_flags_avoid_self,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_get_dcname_request_flags_good_timeserv_preferred,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_get_dcname_request_flags_writable_required,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_get_dcname_request_flags_timeserv_required,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_get_dcname_request_flags_kdc_required,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_get_dcname_request_flags_ip_required,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_get_dcname_request_flags_background_only,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_get_dcname_request_flags_pdc_required,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_get_dcname_request_flags_gc_server_required,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_get_dcname_request_flags_directory_service_preferred,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_get_dcname_request_flags_directory_service_required,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_get_dcname_request_flags_force_rediscovery,
		tvb, offset-4, 4, mask);
	
	return offset;
}



#define DS_PDC_FLAG		0x00000001
#define DS_GC_FLAG		0x00000004
#define DS_LDAP_FLAG		0x00000008
#define DS_DS_FLAG		0x00000010
#define DS_KDC_FLAG		0x00000020
#define DS_TIMESERV_FLAG	0x00000040
#define DS_CLOSEST_FLAG		0x00000080
#define DS_WRITABLE_FLAG	0x00000100
#define DS_GOOD_TIMESERV_FLAG	0x00000200
#define DS_NDNC_FLAG		0x00000400
#define DS_DNS_CONTROLLER_FLAG	0x20000000
#define DS_DNS_DOMAIN_FLAG	0x40000000
#define DS_DNS_FOREST_FLAG	0x80000000
static const true_false_string dc_flags_pdc_flag = {
	"this is the PDC of the domain",
	"this is NOT the pdc of the domain"
};
static const true_false_string dc_flags_gc_flag = {
	"this is the GC of the forest",
	"this is NOT the gc of the forest"
};
static const true_false_string dc_flags_ldap_flag = {
	"this is an LDAP server",
	"this is NOT an ldap server"
};
static const true_false_string dc_flags_ds_flag = {
	"this is a DS server",
	"this is NOT a ds server"
};
static const true_false_string dc_flags_kdc_flag = {
	"this is a KDC server",
	"this is NOT a kdc server"
};
static const true_false_string dc_flags_timeserv_flag = {
	"this is a TIMESERV server",
	"this is NOT a timeserv server"
};
static const true_false_string dc_flags_closest_flag = {
	"this is the CLOSEST server",
	"this is NOT the closest server"
};
static const true_false_string dc_flags_writable_flag = {
	"this server has a WRITABLE ds database",
	"this server has a READ-ONLY ds database"
};
static const true_false_string dc_flags_good_timeserv_flag = {
	"this server is a GOOD TIMESERV server",
	"this is NOT a good timeserv server"
};
static const true_false_string dc_flags_ndnc_flag = {
	"NDNC is set",
	"ndnc is NOT set"
};
static const true_false_string dc_flags_dns_controller_flag = {
	"DomainControllerName is a DNS name",
	"DomainControllerName is NOT a dns name"
};
static const true_false_string dc_flags_dns_domain_flag = {
	"DomainName is a DNS name",
	"DomainName is NOT a dns name"
};
static const true_false_string dc_flags_dns_forest_flag = {
	"DnsForestName is a DNS name",
	"DnsForestName is NOT a dns name"
};
static int
netlogon_dissect_DC_FLAGS(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	guint32 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	offset=dissect_ndr_uint32(tvb, offset, pinfo, NULL, drep,
			hf_netlogon_dc_flags, &mask);

	if(parent_tree){
		item = proto_tree_add_uint_format(parent_tree, hf_netlogon_dc_flags,
				tvb, offset-4, 4, mask, "Domain Controller Flags: 0x%08x%s", mask, (mask==0x0000ffff)?"  PING (mask==0x0000ffff)":"");
		tree = proto_item_add_subtree(item, ett_dc_flags);
	}

	proto_tree_add_boolean(tree, hf_netlogon_dc_flags_dns_forest_flag,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_dc_flags_dns_domain_flag,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_dc_flags_dns_controller_flag,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_dc_flags_ndnc_flag,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_dc_flags_good_timeserv_flag,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_dc_flags_writable_flag,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_dc_flags_closest_flag,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_dc_flags_timeserv_flag,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_dc_flags_kdc_flag,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_dc_flags_ds_flag,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_dc_flags_ldap_flag,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_dc_flags_gc_flag,
		tvb, offset-4, 4, mask);
	proto_tree_add_boolean(tree, hf_netlogon_dc_flags_pdc_flag,
		tvb, offset-4, 4, mask);

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
netlogon_dissect_UNICODE_STRING(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep, int type, int hf_index, dcerpc_callback_fnct_t *callback)
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

	offset = dissect_ndr_pointer_cb(tvb, offset, pinfo, tree, drep,
			dissect_ndr_wchar_cvstring, type,
			name, hf_index, callback, NULL);

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
		netlogon_dissect_UNICODE_MULTI_array, NDR_POINTER_UNIQUE,
		"unknown", hf_netlogon_unknown_string);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

int
dissect_nt_GUID(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset=dissect_ndr_uuid_t(tvb, offset, pinfo, tree, drep, hf_netlogon_guid, NULL);

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

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "DC Name", hf_netlogon_dc_name, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "DC Address", hf_netlogon_dc_address, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dc_address_type, NULL);

	offset = dissect_nt_GUID(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "Logon Domain", hf_netlogon_logon_dom, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "DNS Forest", hf_netlogon_dns_forest_name, 0);

	offset = netlogon_dissect_DC_FLAGS(tvb, offset, pinfo, tree, drep);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "DC Site", hf_netlogon_dc_site_name, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "Client Site", 
		hf_netlogon_client_site_name, 0);

	proto_item_set_len(item, offset-old_offset);
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
		netlogon_dissect_BLOB_array, NDR_POINTER_UNIQUE,
		"BLOB:", -1);

	return offset;
}

static int
netlogon_dissect_DOMAIN_TRUST_INFO(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"DOMAIN_TRUST_INFO:");
		tree = proto_item_add_subtree(item, ett_DOMAIN_TRUST_INFO);
	}


	offset = lsa_dissect_POLICY_DNS_DOMAIN_INFO(tvb, offset, pinfo, tree, drep);

	/* Guesses at best. */
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
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
netlogon_dissect_DOMAIN_TRUST_INFO_ARRAY(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_DOMAIN_TRUST_INFO);

	return offset;
}

static int
netlogon_dissect_DOMAIN_QUERY_1(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = netlogon_dissect_BLOB(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "Workstation FQDN", 
		hf_netlogon_workstation_fqdn, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "Workstation Site", 
		hf_netlogon_workstation_site_name, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "unknown", hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "unknown", hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "unknown", hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "unknown", hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_workstation_os, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	return offset;
}

static int
netlogon_dissect_DOMAIN_INFO_1(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = netlogon_dissect_DOMAIN_TRUST_INFO(tvb, offset, pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_num_trusts, NULL);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_DOMAIN_TRUST_INFO_ARRAY, NDR_POINTER_UNIQUE,
		"DOMAIN_TRUST_ARRAY: Trusts", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_num_trusts, NULL);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_DOMAIN_TRUST_INFO_ARRAY, NDR_POINTER_UNIQUE,
		"DOMAIN_TRUST_ARRAY:", -1);
 
	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_dns_domain_name, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_string, 0);

	/* These four integers appear to mirror the last four in the query. */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	return offset;
}


static int
netlogon_dissect_DOMAIN_INFO(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	guint32 level;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_level, &level);

	ALIGN_TO_4_BYTES;
	switch(level){
	case 1:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DOMAIN_INFO_1, NDR_POINTER_UNIQUE,
			"DOMAIN_INFO_1:", -1);
		break;
	}

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
		"unknown", hf_netlogon_unknown_string);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_TYPE_50_ptr(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_TYPE_50, NDR_POINTER_UNIQUE,
		"TYPE_50 pointer: unknown_TYPE_50", -1);

	return offset;
}

static int
netlogon_dissect_DS_DOMAIN_TRUSTS(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	guint32 tmp;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
 	int old_offset=offset;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 0,
			"DS_DOMAIN_TRUSTS");
		tree = proto_item_add_subtree(item, ett_DS_DOMAIN_TRUSTS);
	}

	/* name */
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "NetBIOS Name", 
		hf_netlogon_downlevel_domain_name, 0);

	/* domain */
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "DNS Domain Name", 
		hf_netlogon_dns_domain_name, 0);

	offset = netlogon_dissect_DOMAIN_TRUST_FLAGS(tvb, offset, pinfo, tree, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_trust_parent_index, &tmp);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_trust_type, &tmp);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_trust_attribs, &tmp);

	/* SID pointer */
	offset = dissect_ndr_nt_PSID(tvb, offset, pinfo, tree, drep, -1);

	/* GUID */
	offset = dissect_nt_GUID(tvb, offset, pinfo, tree, drep);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_DS_DOMAIN_TRUSTS_ARRAY(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_DS_DOMAIN_TRUSTS);

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
		"unknown", hf_netlogon_unknown_string);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_element_866_array, NDR_POINTER_UNIQUE,
		"unknown", hf_netlogon_unknown_string);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
netlogon_dissect_TYPE_52_ptr(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_TYPE_52, NDR_POINTER_UNIQUE,
		"TYPE_52 pointer: unknown_TYPE_52", -1);
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
netlogon_dissect_DOMAIN_QUERY(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	guint32 level;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_level, &level);

	ALIGN_TO_4_BYTES;
	switch(level){
	case 1:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DOMAIN_QUERY_1, NDR_POINTER_UNIQUE,
			"DOMAIN_QUERY_1:", -1);
		break;
	case 2:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			netlogon_dissect_DOMAIN_QUERY_1, NDR_POINTER_UNIQUE,
			"DOMAIN_QUERY_1:", -1);
		break;
	}

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
		"UNICODE_MULTI pointer: trust_dom_name_list", -1);

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

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "Domain", hf_netlogon_logon_dom, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_nt_GUID, NDR_POINTER_UNIQUE,
		"GUID pointer: domain_guid", -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_nt_GUID, NDR_POINTER_UNIQUE,
		"GUID pointer: site_guid", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_flags, NULL);

	return offset;
}


static int
netlogon_dissect_dsrgetdcname2_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_DOMAIN_CONTROLLER_INFO, NDR_POINTER_UNIQUE,
		"DOMAIN_CONTROLLER_INFO:", -1);

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

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "unknown string", 
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: credential", -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_UNIQUE,
		"AUTHENTICATOR: return_authenticator", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	return offset;
}


static int
netlogon_dissect_function_15_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_UNIQUE,
		"AUTHENTICATOR: return_authenticator", -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_TYPE_44, NDR_POINTER_UNIQUE,
		"TYPE_44 pointer: unknown_TYPE_44", -1);

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

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "unknown string", 
		hf_netlogon_unknown_string, 0);

	return offset;
}


static int
netlogon_dissect_function_17_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_UNIQUE,
		"ULONG pointer: unknown_ULONG", hf_netlogon_unknown_long);

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
		netlogon_dissect_BYTE_array, NDR_POINTER_UNIQUE,
		"BYTE pointer: unknown_BYTE", -1);

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
		netlogon_dissect_BYTE_16_array, NDR_POINTER_UNIQUE,
		"BYTE pointer: unknown_BYTE", -1);

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

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "unknown string", 
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_BYTE_array, NDR_POINTER_UNIQUE,
		"BYTE pointer: unknown_BYTE", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	return offset;
}


static int
netlogon_dissect_function_19_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_BYTE_16_array, NDR_POINTER_UNIQUE,
		"BYTE pointer: unknown_BYTE", -1);

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

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, "Acct Name", hf_netlogon_acct_name, 0);

	offset = netlogon_dissect_NETLOGON_SECURE_CHANNEL_TYPE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_REF, "Computer Name", hf_netlogon_computer_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_CREDENTIAL, NDR_POINTER_REF,
		"CREDENTIAL: authenticator", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_neg_flags, NULL);

	return offset;
}


static int
netlogon_dissect_netserverauthenticate3_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_CREDENTIAL, NDR_POINTER_REF,
		"CREDENTIAL pointer: unknown_NETLOGON_CREDENTIAL", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_neg_flags, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_REF,
		"ULONG: unknown_ULONG", hf_netlogon_unknown_long);

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

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "Domain", hf_netlogon_logon_dom, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_nt_GUID, NDR_POINTER_UNIQUE,
		"GUID pointer: domain_guid", -1);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "Site Name", hf_netlogon_site_name, 0);

	offset = netlogon_dissect_GET_DCNAME_REQUEST_FLAGS(tvb, offset, pinfo, tree, drep);

	return offset;
}


static int
netlogon_dissect_dsrgetdcname_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_DOMAIN_CONTROLLER_INFO, NDR_POINTER_UNIQUE,
		"DOMAIN_CONTROLLER_INFO:", -1);

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
netlogon_dissect_netrlogongetdomaininfo_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
       /* Unlike the other NETLOGON RPCs, this is not a unique pointer. */
       offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
               NDR_POINTER_REF, "Server Handle", hf_netlogon_computer_name, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "Computer Name", 
		hf_netlogon_computer_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: credential", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: return_authenticator", -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_DOMAIN_QUERY, NDR_POINTER_REF,
		"DOMAIN_QUERY: ", -1);

	return offset;
}


static int
netlogon_dissect_netrlogongetdomaininfo_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: return_authenticator", -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_DOMAIN_INFO, NDR_POINTER_REF,
		"DOMAIN_INFO: ", -1);

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

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "unknown string", 
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_short, NULL);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "unknown string", 
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: credential", -1);

	offset = netlogon_dissect_UNICODE_STRING_512(tvb, offset,
		pinfo, tree, drep);

	return offset;
}


static int
netlogon_dissect_function_1e_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_UNIQUE,
		"AUTHENTICATOR: return_authenticator", -1);

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

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "Acct Name", hf_netlogon_acct_name, 0);

	offset = netlogon_dissect_NETLOGON_SECURE_CHANNEL_TYPE(tvb, offset,
		pinfo, tree, drep);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "Computer Name", 
		hf_netlogon_computer_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: credential", -1);

	return offset;
}


static int
netlogon_dissect_netserverpasswordset2_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: return_authenticator", -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_LM_OWF_PASSWORD, NDR_POINTER_REF,
		"LM_OWF_PASSWORD pointer: server_pwd", -1);

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

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "unknown string", 
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
		"AUTHENTICATOR: credential", -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_BYTE_array, NDR_POINTER_UNIQUE,
		"BYTE pointer: unknown_BYTE", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	return offset;
}


static int
netlogon_dissect_function_20_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_AUTHENTICATOR, NDR_POINTER_UNIQUE,
		"AUTHENTICATOR: return_authenticator", -1);

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
		netlogon_dissect_BYTE_array, NDR_POINTER_UNIQUE,
		"BYTE pointer: unknown_BYTE", -1);

	return offset;
}


static int
netlogon_dissect_function_21_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_TYPE_50_ptr, NDR_POINTER_UNIQUE,
		"TYPE_50** pointer: unknown_TYPE_50", -1);

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

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "unknown string", 
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "unknown string", 
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_nt_GUID, NDR_POINTER_UNIQUE,
		"GUID pointer: unknown_GUID", -1);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "unknown string", 
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_long, NULL);

	return offset;
}


static int
netlogon_dissect_function_22_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_DOMAIN_CONTROLLER_INFO, NDR_POINTER_UNIQUE,
		"DOMAIN_CONTROLLER_INFO:", -1);

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
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "unknown string", 
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_UNIQUE,
		"ULONG pointer: unknown_ULONG", hf_netlogon_unknown_long);

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
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_DS_DOMAIN_TRUSTS_ARRAY, NDR_POINTER_UNIQUE,
		"DS_DOMAIN_TRUSTS_ARRAY:", -1);

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
		netlogon_dissect_BYTE_array, NDR_POINTER_UNIQUE,
		"BYTE pointer: unknown_BYTE", -1);

	return offset;
}


static int
netlogon_dissect_function_25_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_TYPE_52_ptr, NDR_POINTER_UNIQUE,
		"TYPE_52 pointer: unknown_TYPE_52", -1);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}


static int
netlogon_dissect_function_26_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "unknown string", 
		hf_netlogon_unknown_string, 0);

	return offset;
}


static int
netlogon_dissect_function_26_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_TYPE_50_ptr, NDR_POINTER_UNIQUE,
		"TYPE_50** pointer: unknown_TYPE_50", -1);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}

static int
netlogon_dissect_logonsamlogonex_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "unknown string", 
	        hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "unknown string", 
		hf_netlogon_unknown_string, 0);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_short, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_LEVEL, NDR_POINTER_UNIQUE,
		"LEVEL pointer: unknown_NETLOGON_LEVEL", -1);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
		hf_netlogon_unknown_short, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_UNIQUE,
		"ULONG pointer: unknown_ULONG", hf_netlogon_unknown_long);
	return offset;
}


static int
netlogon_dissect_logonsamlogonex_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_VALIDATION, NDR_POINTER_UNIQUE,
		"VALIDATION: unknown_NETLOGON_VALIDATION", -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_char, NDR_POINTER_UNIQUE,
		"BOOLEAN pointer: unknown_BOOLEAN", hf_netlogon_unknown_char);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_pointer_long, NDR_POINTER_UNIQUE,
		"ULONG pointer: unknown_ULONG", hf_netlogon_unknown_long);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
				  hf_netlogon_rc, NULL);

	return offset;
}


static int
netlogon_dissect_dsenumeratetrusteddomains_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
		pinfo, tree, drep);

	offset = netlogon_dissect_DOMAIN_TRUST_FLAGS(tvb, offset, pinfo, tree, drep);

	return offset;
}


static int
netlogon_dissect_dsenumeratetrusteddomains_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_netlogon_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_DS_DOMAIN_TRUSTS_ARRAY, NDR_POINTER_UNIQUE,
		"DS_DOMAIN_TRUSTS_ARRAY:", -1);

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

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "Domain", hf_netlogon_logon_dom, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_nt_GUID, NDR_POINTER_UNIQUE,
		"GUID pointer: domain_guid", -1);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		dissect_nt_GUID, NDR_POINTER_UNIQUE,
		"GUID pointer: dsa_guid", -1);

	offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
		NDR_POINTER_UNIQUE, "dns_host", hf_netlogon_dns_host, 0);

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

/* Dissect secure channel stuff */

static int hf_netlogon_secchan_bind_unknown1 = -1;
static int hf_netlogon_secchan_bind_unknown2 = -1;
static int hf_netlogon_secchan_domain = -1;
static int hf_netlogon_secchan_host = -1;
static int hf_netlogon_secchan_bind_ack_unknown1 = -1;
static int hf_netlogon_secchan_bind_ack_unknown2 = -1;
static int hf_netlogon_secchan_bind_ack_unknown3 = -1;

static gint ett_secchan = -1;
static gint ett_secchan_bind_creds = -1;
static gint ett_secchan_bind_ack_creds = -1;

int netlogon_dissect_secchan_bind_creds(tvbuff_t *tvb, int offset,
					packet_info *pinfo, proto_tree *tree,
					char *drep)
{
	int start_offset = offset;
	proto_item *item = NULL;
	proto_tree *subtree = NULL;
	int len;

	if (tree) {
		item = proto_tree_add_text(
			tree, tvb, offset, 0,
			"Secure Channel Bind Credentials");
		subtree = proto_item_add_subtree(
			item, ett_secchan_bind_creds);
	}

	/* We can't use the NDR routines as the DCERPC call data hasn't
           been initialised since we haven't made a DCERPC call yet, just
           a bind request. */

	offset = dissect_dcerpc_uint32(
		tvb, offset, pinfo, subtree, drep, 
		hf_netlogon_secchan_bind_unknown1, NULL);

	offset = dissect_dcerpc_uint32(
		tvb, offset, pinfo, subtree, drep, 
		hf_netlogon_secchan_bind_unknown2, NULL);

	len = tvb_strsize(tvb, offset);

	proto_tree_add_item(
		subtree, hf_netlogon_secchan_domain, tvb, offset, len, FALSE);

	offset += len;

	len = tvb_strsize(tvb, offset);

	proto_tree_add_item(
		subtree, hf_netlogon_secchan_host, tvb, offset, len, FALSE);

	offset += len;

	proto_item_set_len(item, offset - start_offset);

	return offset;
}

int netlogon_dissect_secchan_bind_ack_creds(tvbuff_t *tvb, int offset,
					    packet_info *pinfo, 
					    proto_tree *tree, char *drep)
{
	proto_item *item = NULL;
	proto_tree *subtree = NULL;

	if (tree) {
		item = proto_tree_add_text(
			tree, tvb, offset, 0,
			"Secure Channel Bind ACK Credentials");
		subtree = proto_item_add_subtree(
			item, ett_secchan_bind_ack_creds);
	}

	/* Don't use NDR routines here */

	offset = dissect_dcerpc_uint32(
		tvb, offset, pinfo, subtree, drep, 
		hf_netlogon_secchan_bind_ack_unknown1, NULL);

	offset = dissect_dcerpc_uint32(
		tvb, offset, pinfo, subtree, drep, 
		hf_netlogon_secchan_bind_ack_unknown2, NULL);

	offset = dissect_dcerpc_uint32(
		tvb, offset, pinfo, subtree, drep, 
		hf_netlogon_secchan_bind_ack_unknown3, NULL);

	return offset;
}

static int hf_netlogon_secchan = -1;
static int hf_netlogon_secchan_sig = -1;
static int hf_netlogon_secchan_unk = -1;
static int hf_netlogon_secchan_seq = -1;
static int hf_netlogon_secchan_nonce = -1;

int netlogon_dissect_secchan_verf(tvbuff_t *tvb, int offset, 
				  packet_info *pinfo _U_, proto_tree *tree, 
				  char *drep _U_)
{
	proto_item *vf;
	proto_tree *sec_chan_tree;
	/*
         * Create a new tree, and split into 4 components ...
         */
	vf = proto_tree_add_item(tree, hf_netlogon_secchan, tvb, 
				 offset, -1, FALSE);
	sec_chan_tree = proto_item_add_subtree(vf, ett_secchan);
	
	proto_tree_add_item(sec_chan_tree, hf_netlogon_secchan_sig, tvb, 
			    offset, 8, FALSE);
	
	proto_tree_add_item(sec_chan_tree, hf_netlogon_secchan_unk, tvb, 
			    offset + 8, 8, FALSE);
	
	proto_tree_add_item(sec_chan_tree, hf_netlogon_secchan_seq, tvb, 
			    offset + 16, 8, FALSE);
	
	proto_tree_add_item(sec_chan_tree, hf_netlogon_secchan_nonce, tvb, 
			    offset + 24, 8, FALSE);
	
	return offset;
}

/* Subdissectors */

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
	{ NETLOGON_NETSAMDELTAS, "DatabaseDeltas",
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
	{ NETLOGON_NETLOGONCONTROL, "LogonControl",
		netlogon_dissect_netlogoncontrol_rqst,
		netlogon_dissect_netlogoncontrol_reply },
	{ NETLOGON_GETANYDCNAME, "GetAnyDCName",
		netlogon_dissect_netlogongetanydcname_rqst,
		netlogon_dissect_netlogongetanydcname_reply },
	{ NETLOGON_NETLOGONCONTROL2, "LogonControl2",
		netlogon_dissect_netlogoncontrol2_rqst,
		netlogon_dissect_netlogoncontrol2_reply },
	{ NETLOGON_NETSERVERAUTHENTICATE2, "ServerAuthenticate2",
		netlogon_dissect_netserverauthenticate2_rqst,
		netlogon_dissect_netserverauthenticate2_reply },
	{ NETLOGON_NETDATABASESYNC2, "DatabaseSync2",
		netlogon_dissect_netdatabasesync2_rqst,
		netlogon_dissect_netdatabasesync2_reply },
	{ NETLOGON_DATABASEREDO, "DatabaseRedo",
		netlogon_dissect_netlogondatabaseredo_rqst,
		netlogon_dissect_netlogondatabaseredo_reply },
	{ NETLOGON_FUNCTION_12, "Function_0x12",
		netlogon_dissect_function_12_rqst,
		netlogon_dissect_function_12_reply },
	{ NETLOGON_NETTRUSTEDDOMAINLIST, "TrustedDomainList",
		netlogon_dissect_nettrusteddomainlist_rqst,
		netlogon_dissect_nettrusteddomainlist_reply },
	{ NETLOGON_DSRGETDCNAME2, "DsrGetDCName2",
		netlogon_dissect_dsrgetdcname2_rqst,
		netlogon_dissect_dsrgetdcname2_reply },
	{ NETLOGON_FUNCTION_15, "Function 0x15",
		netlogon_dissect_function_15_rqst,
		netlogon_dissect_function_15_reply },
	{ NETLOGON_FUNCTION_16, "Function 0x16",
		netlogon_dissect_function_16_rqst,
		netlogon_dissect_function_16_reply },
	{ NETLOGON_FUNCTION_17, "Function 0x17",
		netlogon_dissect_function_17_rqst,
		netlogon_dissect_function_17_reply },
	{ NETLOGON_FUNCTION_18, "Function 0x18",
		netlogon_dissect_function_18_rqst,
		netlogon_dissect_function_18_reply },
	{ NETLOGON_FUNCTION_19, "Function 0x19",
		netlogon_dissect_function_19_rqst,
		netlogon_dissect_function_19_reply },
	{ NETLOGON_NETSERVERAUTHENTICATE3, "ServerAuthenticate3",
		netlogon_dissect_netserverauthenticate3_rqst,
		netlogon_dissect_netserverauthenticate3_reply },
	{ NETLOGON_DSRGETDCNAME, "DsrGetDCName",
		netlogon_dissect_dsrgetdcname_rqst,
		netlogon_dissect_dsrgetdcname_reply },
	{ NETLOGON_DSRGETSITENAME, "DsrGetSiteName",
		netlogon_dissect_dsrgetsitename_rqst,
		netlogon_dissect_dsrgetsitename_reply },
	{ NETLOGON_NETRLOGONGETDOMAININFO, "NetrLogonGetDomainInfo",
		netlogon_dissect_netrlogongetdomaininfo_rqst,
		netlogon_dissect_netrlogongetdomaininfo_reply },
	{ NETLOGON_FUNCTION_1E, "Function_0x1E",
		netlogon_dissect_function_1e_rqst,
		netlogon_dissect_function_1e_reply },
	{ NETLOGON_NETSERVERPASSWORDSET2, "ServerPasswordSet2",
		netlogon_dissect_netserverpasswordset2_rqst,
		netlogon_dissect_netserverpasswordset2_reply },
	{ NETLOGON_FUNCTION_20, "Function_0x20",
		netlogon_dissect_function_20_rqst,
		netlogon_dissect_function_20_reply },
	{ NETLOGON_FUNCTION_21, "Function_0x21",
		netlogon_dissect_function_21_rqst,
		netlogon_dissect_function_21_reply },
	{ NETLOGON_FUNCTION_22, "Function_0x22",
		netlogon_dissect_function_22_rqst,
		netlogon_dissect_function_22_reply },
	{ NETLOGON_FUNCTION_23, "Function_0x23",
		netlogon_dissect_function_23_rqst,
		netlogon_dissect_function_23_reply },
	{ NETLOGON_FUNCTION_24, "Function_0x24",
		netlogon_dissect_function_24_rqst,
		netlogon_dissect_function_24_reply },
	{ NETLOGON_FUNCTION_25, "Function_0x25",
		netlogon_dissect_function_25_rqst,
		netlogon_dissect_function_25_reply },
	{ NETLOGON_FUNCTION_26, "Function_0x26",
		netlogon_dissect_function_26_rqst,
		netlogon_dissect_function_26_reply },
	{ NETLOGON_LOGONSAMLOGONEX, "LogonSamLogonEx",
		netlogon_dissect_logonsamlogonex_rqst,
		netlogon_dissect_logonsamlogonex_reply },
	{ NETLOGON_DSENUMERATETRUSTEDDOMAINS, "DSEnumerateTrustedDomains",
		netlogon_dissect_dsenumeratetrusteddomains_rqst,
		netlogon_dissect_dsenumeratetrusteddomains_reply },
	{ NETLOGON_DSRDEREGISTERDNSHOSTRECORDS, "DsrDeregisterDNSHostRecords",
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
	{ NETLOGON_NETSAMDELTAS, "DatabaseDeltas" },
	{ NETLOGON_DATABASESYNC, "DatabaseSync" },
	{ NETLOGON_ACCOUNTDELTAS, "AccountDeltas" },
	{ NETLOGON_ACCOUNTSYNC, "AccountSync" },
	{ NETLOGON_GETDCNAME, "GetDCName" },
	{ NETLOGON_NETLOGONCONTROL, "LogonControl" },
	{ NETLOGON_GETANYDCNAME, "GetAnyDCName" },
	{ NETLOGON_NETLOGONCONTROL2, "LogonControl2" },
	{ NETLOGON_NETSERVERAUTHENTICATE2, "ServerAuthenticate2" },
	{ NETLOGON_NETDATABASESYNC2, "DatabaseSync2" },
	{ NETLOGON_DATABASEREDO, "DatabaseRedo" },
	{ NETLOGON_FUNCTION_12, "Function_0x12" },
	{ NETLOGON_NETTRUSTEDDOMAINLIST, "TrustedDomainList" },
	{ NETLOGON_DSRGETDCNAME2, "DsrGetDCName2" },
	{ NETLOGON_FUNCTION_15, "Function_0x15" },
	{ NETLOGON_FUNCTION_16, "Function_0x16" },
	{ NETLOGON_FUNCTION_17, "Function_0x17" },
	{ NETLOGON_FUNCTION_18, "Function_0x18" },
	{ NETLOGON_FUNCTION_19, "Function_0x19" },
	{ NETLOGON_NETSERVERAUTHENTICATE3, "ServerAuthenticate3" },
	{ NETLOGON_DSRGETDCNAME, "DsrGetDCName" },
	{ NETLOGON_DSRGETSITENAME, "DsrGetSiteName" },
	{ NETLOGON_NETRLOGONGETDOMAININFO, "NetrLogonGetDomainInfo" },
	{ NETLOGON_FUNCTION_1E, "Function_0x1E" },
	{ NETLOGON_NETSERVERPASSWORDSET2, "ServerPasswordSet2" },
	{ NETLOGON_FUNCTION_20, "Function_0x20" },
	{ NETLOGON_FUNCTION_21, "Function_0x21" },
	{ NETLOGON_FUNCTION_22, "Function_0x22" },
	{ NETLOGON_FUNCTION_23, "Function_0x23" },
	{ NETLOGON_FUNCTION_24, "Function_0x24" },
	{ NETLOGON_FUNCTION_25, "Function_0x25" },
	{ NETLOGON_FUNCTION_26, "Function_0x26" },
	{ NETLOGON_LOGONSAMLOGONEX, "LogonSamLogonEx" },
	{ NETLOGON_DSENUMERATETRUSTEDDOMAINS, "DSEnumerateTrustedDomains" },
	{ NETLOGON_DSRDEREGISTERDNSHOSTRECORDS, "DsrDeregisterDNSHostRecords" },
	{ 0, NULL }
};

/* Secure channel types */

static const value_string sec_chan_type_vals[] = {
	{ SEC_CHAN_WKSTA,  "Workstation" },
	{ SEC_CHAN_DOMAIN, "Domain trust" },
	{ SEC_CHAN_BDC,    "Backup domain controller" },
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

	{ &hf_netlogon_modify_count, {
		"Modify Count", "netlogon.modify_count", FT_UINT64, BASE_DEC,
		NULL, 0x0, "How many times the object has been modified", HFILL }},

	{ &hf_netlogon_security_information, {
		"Security Information", "netlogon.security_information", FT_UINT32, BASE_DEC,
		NULL, 0x0, "Security Information", HFILL }},

	{ &hf_netlogon_count, {
		"Count", "netlogon.count", FT_UINT32, BASE_DEC,
		NULL, 0x0, "", HFILL }},

	{ &hf_netlogon_entries, {
		"Entries", "netlogon.entries", FT_UINT32, BASE_DEC,
		NULL, 0x0, "", HFILL }},

	{ &hf_netlogon_credential, {
		"Credential", "netlogon.credential", FT_BYTES, BASE_HEX,
		NULL, 0x0, "Netlogon Credential", HFILL }},

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

	{ &hf_netlogon_pdc_connection_status, {
		"PDC Connection Status", "netlogon.pdc_connection_status", FT_UINT32, BASE_DEC,
		NULL, 0, "PDC Connection Status", HFILL }},

	{ &hf_netlogon_tc_connection_status, {
		"TC Connection Status", "netlogon.tc_connection_status", FT_UINT32, BASE_DEC,
		NULL, 0, "TC Connection Status", HFILL }},

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

	{ &hf_netlogon_cipher_len,
		{ "Cipher Len", "netlogon.cipher_len", FT_UINT32, BASE_DEC,
		NULL, 0, "", HFILL }},

	{ &hf_netlogon_cipher_maxlen,
		{ "Cipher Max Len", "netlogon.cipher_maxlen", FT_UINT32, BASE_DEC,
		NULL, 0, "", HFILL }},

	{ &hf_netlogon_pac_data,
		{ "Pac Data", "netlogon.pac.data", FT_BYTES, BASE_HEX,
		NULL, 0, "Pac Data", HFILL }},

	{ &hf_netlogon_sensitive_data,
		{ "Data", "netlogon.sensitive_data", FT_BYTES, BASE_HEX,
		NULL, 0, "Sensitive Data", HFILL }},

	{ &hf_netlogon_auth_data,
		{ "Auth Data", "netlogon.auth.data", FT_BYTES, BASE_HEX,
		NULL, 0, "Auth Data", HFILL }},

	{ &hf_netlogon_cipher_current_data,
		{ "Cipher Current Data", "netlogon.cipher_current_data", FT_BYTES, BASE_HEX,
		NULL, 0, "", HFILL }},

	{ &hf_netlogon_cipher_old_data,
		{ "Cipher Old Data", "netlogon.cipher_old_data", FT_BYTES, BASE_HEX,
		NULL, 0, "", HFILL }},

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
		VALS(dc_address_types), 0, "DC Address Type", HFILL }},

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

	{ &hf_netlogon_dns_host,
		{ "DNS Host", "netlogon.dns_host", FT_STRING, BASE_NONE,
		NULL, 0, "DNS Host", HFILL }},

	{ &hf_netlogon_downlevel_domain_name,
		{ "Downlevel Domain", "netlogon.downlevel_domain", FT_STRING, BASE_NONE,
		NULL, 0, "Downlevel Domain Name", HFILL }},

	{ &hf_netlogon_dns_domain_name,
		{ "DNS Domain", "netlogon.dns_domain", FT_STRING, BASE_NONE,
		NULL, 0, "DNS Domain Name", HFILL }},

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
		{ "Sec Chan Type", "netlogon.sec_chan_type", FT_UINT16, BASE_DEC,
		VALS(sec_chan_type_vals), 0x0, "Secure Channel Type", HFILL }},

	{ &hf_netlogon_restart_state,
		{ "Restart State", "netlogon.restart_state", FT_UINT16, BASE_DEC,
		NULL, 0x0, "Restart State", HFILL }},

	{ &hf_netlogon_delta_type,
		{ "Delta Type", "netlogon.delta_type", FT_UINT16, BASE_DEC,
		VALS(delta_type_vals), 0x0, "Delta Type", HFILL }},

	{ &hf_netlogon_blob_size,
		{ "Size", "netlogon.blob.size", FT_UINT32, BASE_DEC,
		NULL, 0x0, "Size in bytes of BLOB", HFILL }},

	{ &hf_netlogon_code,
		{ "Code", "netlogon.code", FT_UINT32, BASE_HEX,
		NULL, 0x0, "Code", HFILL }},

	{ &hf_netlogon_level,
		{ "Level", "netlogon.level", FT_UINT32, BASE_DEC,
		NULL, 0x0, "Which option of the union is represented here", HFILL }},

	{ &hf_netlogon_reference,
		{ "Reference", "netlogon.reference", FT_UINT32, BASE_DEC,
		NULL, 0x0, "", HFILL }},

	{ &hf_netlogon_next_reference,
		{ "Next Reference", "netlogon.next_reference", FT_UINT32, BASE_DEC,
		NULL, 0x0, "", HFILL }},

	{ &hf_netlogon_timestamp,
		{ "Timestamp", "netlogon.timestamp", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "", HFILL }},

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

	{ &hf_netlogon_sync_context,
		{ "Sync Context", "netlogon.sync_context", FT_UINT32, BASE_DEC,
		NULL, 0x0, "Sync Context", HFILL }},

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

	{ &hf_netlogon_num_trusts,
		{ "Num Trusts", "netlogon.num_trusts", FT_UINT32, BASE_DEC,
		NULL, 0x0, "", HFILL }},

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

	{ &hf_netlogon_serial_number,
		{ "Serial Number", "netlogon.serial_number", FT_UINT32, BASE_DEC,
		NULL, 0x0, "", HFILL }},

	{ &hf_netlogon_neg_flags,
		{ "Neg Flags", "netlogon.neg_flags", FT_UINT32, BASE_HEX,
		NULL, 0x0, "Negotiation Flags", HFILL }},

	{ &hf_netlogon_dc_flags,
		{ "Flags", "netlogon.dc.flags", FT_UINT32, BASE_HEX,
		NULL, 0x0, "Domain Controller Flags", HFILL }},

	{ &hf_netlogon_dc_flags_pdc_flag,
	        { "PDC", "netlogon.dc.flags.pdc",
		  FT_BOOLEAN, 32, TFS(&dc_flags_pdc_flag), DS_PDC_FLAG,
		  "If this server is a PDC", HFILL }},

	{ &hf_netlogon_dc_flags_gc_flag,
	        { "GC", "netlogon.dc.flags.gc",
		  FT_BOOLEAN, 32, TFS(&dc_flags_gc_flag), DS_GC_FLAG,
		  "If this server is a GC", HFILL }},

	{ &hf_netlogon_dc_flags_ldap_flag,
	        { "LDAP", "netlogon.dc.flags.ldap",
		  FT_BOOLEAN, 32, TFS(&dc_flags_ldap_flag), DS_LDAP_FLAG,
		  "If this is an LDAP server", HFILL }},

	{ &hf_netlogon_dc_flags_ds_flag,
	        { "DS", "netlogon.dc.flags.ds",
		  FT_BOOLEAN, 32, TFS(&dc_flags_ds_flag), DS_DS_FLAG,
		  "If this server is a DS", HFILL }},

	{ &hf_netlogon_dc_flags_kdc_flag,
	        { "KDC", "netlogon.dc.flags.kdc",
		  FT_BOOLEAN, 32, TFS(&dc_flags_kdc_flag), DS_KDC_FLAG,
		  "If this is a KDC", HFILL }},

	{ &hf_netlogon_dc_flags_timeserv_flag,
	        { "Timeserv", "netlogon.dc.flags.timeserv",
		  FT_BOOLEAN, 32, TFS(&dc_flags_timeserv_flag), DS_TIMESERV_FLAG,
		  "If this server is a TimeServer", HFILL }},

	{ &hf_netlogon_dc_flags_closest_flag,
	        { "Closest", "netlogon.dc.flags.closest",
		  FT_BOOLEAN, 32, TFS(&dc_flags_closest_flag), DS_CLOSEST_FLAG,
		  "If this is the closest server", HFILL }},

	{ &hf_netlogon_dc_flags_writable_flag,
	        { "Writable", "netlogon.dc.flags.writable",
		  FT_BOOLEAN, 32, TFS(&dc_flags_writable_flag), DS_WRITABLE_FLAG,
		  "If this server can do updates to the database", HFILL }},

	{ &hf_netlogon_dc_flags_good_timeserv_flag,
	        { "Good Timeserv", "netlogon.dc.flags.good_timeserv",
		  FT_BOOLEAN, 32, TFS(&dc_flags_good_timeserv_flag), DS_GOOD_TIMESERV_FLAG,
		  "If this is a Good TimeServer", HFILL }},

	{ &hf_netlogon_dc_flags_ndnc_flag,
	        { "NDNC", "netlogon.dc.flags.ndnc",
		  FT_BOOLEAN, 32, TFS(&dc_flags_ndnc_flag), DS_NDNC_FLAG,
		  "If this is an NDNC server", HFILL }},

	{ &hf_netlogon_dc_flags_dns_controller_flag,
	        { "DNS Controller", "netlogon.dc.flags.dns_controller",
		  FT_BOOLEAN, 32, TFS(&dc_flags_dns_controller_flag), DS_DNS_CONTROLLER_FLAG,
		  "If this server is a DNS Controller", HFILL }},

	{ &hf_netlogon_dc_flags_dns_domain_flag,
	        { "DNS Domain", "netlogon.dc.flags.dns_domain",
		  FT_BOOLEAN, 32, TFS(&dc_flags_dns_domain_flag), DS_DNS_DOMAIN_FLAG,
		  "", HFILL }},

	{ &hf_netlogon_dc_flags_dns_forest_flag,
	        { "DNS Forest", "netlogon.dc.flags.dns_forest",
		  FT_BOOLEAN, 32, TFS(&dc_flags_dns_forest_flag), DS_DNS_FOREST_FLAG,
		  "", HFILL }},

	{ &hf_netlogon_get_dcname_request_flags,
		{ "Flags", "netlogon.get_dcname.request.flags", FT_UINT32, BASE_HEX,
		NULL, 0x0, "Flags for DSGetDCName request", HFILL }},

	{ &hf_netlogon_get_dcname_request_flags_force_rediscovery,
	        { "Force Rediscovery", "netlogon.get_dcname.request.flags.force_rediscovery",
		  FT_BOOLEAN, 32, TFS(&get_dcname_request_flags_force_rediscovery), DS_FORCE_REDISCOVERY,
		  "Whether to allow the server to returned cached information or not", HFILL }},

	{ &hf_netlogon_get_dcname_request_flags_directory_service_required,
	        { "DS Required", "netlogon.get_dcname.request.flags.ds_required",
		  FT_BOOLEAN, 32, TFS(&get_dcname_request_flags_directory_service_required), DS_DIRECTORY_SERVICE_REQUIRED,
		  "Whether we require that the returned DC supports w2k or not", HFILL }},

	{ &hf_netlogon_get_dcname_request_flags_directory_service_preferred,
	        { "DS Preferred", "netlogon.get_dcname.request.flags.ds_preferred",
		  FT_BOOLEAN, 32, TFS(&get_dcname_request_flags_directory_service_preferred), DS_DIRECTORY_SERVICE_PREFERRED,
		  "Whether we prefer the call to return a w2k server (if available)", HFILL }},

	{ &hf_netlogon_get_dcname_request_flags_gc_server_required,
	        { "GC Required", "netlogon.get_dcname.request.flags.gc_server_required",
		  FT_BOOLEAN, 32, TFS(&get_dcname_request_flags_gc_server_required), DS_GC_SERVER_REQUIRED,
		  "Whether we require that the returned DC is a Global Catalog server", HFILL }},

	{ &hf_netlogon_get_dcname_request_flags_pdc_required,
	        { "PDC Required", "netlogon.get_dcname.request.flags.pdc_required",
		  FT_BOOLEAN, 32, TFS(&get_dcname_request_flags_pdc_required), DS_PDC_REQUIRED,
		  "Whether we require the returned DC to be the PDC", HFILL }},

	{ &hf_netlogon_get_dcname_request_flags_background_only,
	        { "Background Only", "netlogon.get_dcname.request.flags.background_only",
		  FT_BOOLEAN, 32, TFS(&get_dcname_request_flags_background_only), DS_BACKGROUND_ONLY,
		  "If we want cached data, even if it may have expired", HFILL }},

	{ &hf_netlogon_get_dcname_request_flags_ip_required,
	        { "IP Required", "netlogon.get_dcname.request.flags.ip_required",
		  FT_BOOLEAN, 32, TFS(&get_dcname_request_flags_ip_required), DS_IP_REQUIRED,
		  "If we requre the IP of the DC in the reply", HFILL }},

	{ &hf_netlogon_get_dcname_request_flags_kdc_required,
	        { "KDC Required", "netlogon.get_dcname.request.flags.kdc_required",
		  FT_BOOLEAN, 32, TFS(&get_dcname_request_flags_kdc_required), DS_KDC_REQUIRED,
		  "If we require that the returned server is a KDC", HFILL }},

	{ &hf_netlogon_get_dcname_request_flags_timeserv_required,
	        { "Timeserv Required", "netlogon.get_dcname.request.flags.timeserv_required",
		  FT_BOOLEAN, 32, TFS(&get_dcname_request_flags_timeserv_required), DS_TIMESERV_REQUIRED,
		  "If we require the retruned server to be a NTP serveruns WindowsTimeServicer", HFILL }},

	{ &hf_netlogon_get_dcname_request_flags_writable_required,
	        { "Writable Required", "netlogon.get_dcname.request.flags.writable_required",
		  FT_BOOLEAN, 32, TFS(&get_dcname_request_flags_writable_required), DS_WRITABLE_REQUIRED,
		  "If we require that the return server is writable", HFILL }},

	{ &hf_netlogon_get_dcname_request_flags_good_timeserv_preferred,
	        { "Timeserv Preferred", "netlogon.get_dcname.request.flags.good_timeserv_preferred",
		  FT_BOOLEAN, 32, TFS(&get_dcname_request_flags_good_timeserv_preferred), DS_GOOD_TIMESERV_PREFERRED,
		  "If we prefer Windows Time Servers", HFILL }},

	{ &hf_netlogon_get_dcname_request_flags_avoid_self,
	        { "Avoid Self", "netlogon.get_dcname.request.flags.avoid_self",
		  FT_BOOLEAN, 32, TFS(&get_dcname_request_flags_avoid_self), DS_AVOID_SELF,
		  "Return another DC than the one we ask", HFILL }},

	{ &hf_netlogon_get_dcname_request_flags_only_ldap_needed,
	        { "Only LDAP Needed", "netlogon.get_dcname.request.flags.only_ldap_needed",
		  FT_BOOLEAN, 32, TFS(&get_dcname_request_flags_only_ldap_needed), DS_ONLY_LDAP_NEEDED,
		  "We just want an LDAP server, it does not have to be a DC", HFILL }},

	{ &hf_netlogon_get_dcname_request_flags_is_flat_name,
	        { "Is Flat Name", "netlogon.get_dcname.request.flags.is_flat_name",
		  FT_BOOLEAN, 32, TFS(&get_dcname_request_flags_is_flat_name), DS_IS_FLAT_NAME,
		  "If the specified domain name is a NetBIOS name", HFILL }},

	{ &hf_netlogon_get_dcname_request_flags_is_dns_name,
	        { "Is DNS Name", "netlogon.get_dcname.request.flags.is_dns_name",
		  FT_BOOLEAN, 32, TFS(&get_dcname_request_flags_is_dns_name), DS_IS_DNS_NAME,
		  "If the specified domain name is a DNS name", HFILL }},

	{ &hf_netlogon_get_dcname_request_flags_return_dns_name,
	        { "Return DNS Name", "netlogon.get_dcname.request.flags.return_dns_name",
		  FT_BOOLEAN, 32, TFS(&get_dcname_request_flags_return_dns_name), DS_RETURN_DNS_NAME,
		  "Only return a DNS name (or an error)", HFILL }},

	{ &hf_netlogon_get_dcname_request_flags_return_flat_name,
	        { "Return Flat Name", "netlogon.get_dcname.request.flags.return_flat_name",
		  FT_BOOLEAN, 32, TFS(&get_dcname_request_flags_return_flat_name), DS_RETURN_FLAT_NAME,
		  "Only return a NetBIOS name (or an error)", HFILL }},

	{ &hf_netlogon_trust_attribs,
		{ "Trust Attributes", "netlogon.trust_attribs", FT_UINT32, BASE_HEX,
		NULL, 0x0, "Trust Attributes", HFILL }},

	{ &hf_netlogon_trust_type,
		{ "Trust Type", "netlogon.trust_type", FT_UINT32, BASE_DEC,
		VALS(trust_type_vals), 0x0, "Trust Type", HFILL }},

	{ &hf_netlogon_trust_flags,
		{ "Trust Flags", "netlogon.trust_flags", FT_UINT32, BASE_HEX,
		NULL, 0x0, "Trust Flags", HFILL }},

	{ &hf_netlogon_trust_flags_inbound,
	        { "Inbound Trust", "netlogon.trust.flags.inbound",
		  FT_BOOLEAN, 32, TFS(&trust_inbound), DS_DOMAIN_DIRECT_INBOUND,
		  "Inbound trust. Whether the domain directly trusts the queried servers domain", HFILL }},

	{ &hf_netlogon_trust_flags_outbound,
	        { "Outbound Trust", "netlogon.trust.flags.outbound",
		  FT_BOOLEAN, 32, TFS(&trust_outbound), DS_DOMAIN_DIRECT_OUTBOUND,
		  "Outbound Trust. Whether the domain is directly trusted by the servers domain", HFILL }},

	{ &hf_netlogon_trust_flags_in_forest,
	        { "In Forest", "netlogon.trust.flags.in_forest",
		  FT_BOOLEAN, 32, TFS(&trust_in_forest), DS_DOMAIN_IN_FOREST,
		  "Whether this domain is a member of the same forest as the servers domain", HFILL }},

	{ &hf_netlogon_trust_flags_native_mode,
	        { "Native Mode", "netlogon.trust.flags.native_mode",
		  FT_BOOLEAN, 32, TFS(&trust_native_mode), DS_DOMAIN_NATIVE_MODE,
		  "Whether the domain is a w2k native mode domain or not", HFILL }},

	{ &hf_netlogon_trust_flags_primary,
	        { "Primary", "netlogon.trust.flags.primary",
		  FT_BOOLEAN, 32, TFS(&trust_primary), DS_DOMAIN_PRIMARY,
		  "Whether the domain is the primary domain for the queried server or not", HFILL }},

	{ &hf_netlogon_trust_flags_tree_root,
	        { "Tree Root", "netlogon.trust.flags.tree_root",
		  FT_BOOLEAN, 32, TFS(&trust_tree_root), DS_DOMAIN_TREE_ROOT,
		  "Whether the domain is the root of the tree for the queried server", HFILL }},

	{ &hf_netlogon_trust_parent_index,
		{ "Parent Index", "netlogon.parent_index", FT_UINT32, BASE_HEX,
		NULL, 0x0, "Parent Index", HFILL }},

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

	{ &hf_netlogon_cipher_current_set_time,
		{ "Cipher Current Set Time", "netlogon.cipher_current_set_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Time when current cipher was initiated", HFILL }},

	{ &hf_netlogon_cipher_old_set_time,
		{ "Cipher Old Set Time", "netlogon.cipher_old_set_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Time when previous cipher was initiated", HFILL }},

	{ &hf_netlogon_audit_retention_period,
		{ "Audit Retention Period", "netlogon.audit_retention_period", FT_RELATIVE_TIME, BASE_NONE,
		NULL, 0, "Audit retention period", HFILL }},

	{ &hf_netlogon_guid,
		{ "GUID", "netlogon.guid", FT_STRING, BASE_NONE, 
		NULL, 0x0, "GUID (uuid for groups?)", HFILL }},

	{ &hf_netlogon_timelimit,
		{ "Time Limit", "netlogon.time_limit", FT_RELATIVE_TIME, BASE_NONE,
		NULL, 0, "", HFILL }},

	/* Secure channel dissection */

	{ &hf_netlogon_secchan_bind_unknown1,
	  { "Unknown1", "netlogon.secchan.bind.unknown1", FT_UINT32, BASE_HEX,
	    NULL, 0x0, "", HFILL }},

	{ &hf_netlogon_secchan_bind_unknown2,
	  { "Unknown2", "netlogon.secchan.bind.unknown2", FT_UINT32, BASE_HEX,
	    NULL, 0x0, "", HFILL }},

	{ &hf_netlogon_secchan_domain,
	  { "Domain", "netlogon.secchan.domain", FT_STRING, BASE_NONE,
	    NULL, 0, "", HFILL }},

	{ &hf_netlogon_secchan_host,
	  { "Host", "netlogon.secchan.host", FT_STRING, BASE_NONE,
	    NULL, 0, "", HFILL }},

	{ &hf_netlogon_secchan_bind_ack_unknown1,
	  { "Unknown1", "netlogon.secchan.bind_ack.unknown1", FT_UINT32, 
	    BASE_HEX, NULL, 0x0, "", HFILL }},

	{ &hf_netlogon_secchan_bind_ack_unknown2,
	  { "Unknown2", "netlogon.secchan.bind_ack.unknown2", FT_UINT32, 
	    BASE_HEX, NULL, 0x0, "", HFILL }},

	{ &hf_netlogon_secchan_bind_ack_unknown3,
	  { "Unknown3", "netlogon.secchan.bind_ack.unknown3", FT_UINT32, 
	    BASE_HEX, NULL, 0x0, "", HFILL }},

        { &hf_netlogon_secchan,
          { "Verifier", "netlogon.secchan.verifier", FT_NONE, BASE_NONE, 
	    NULL, 0x0, "Verifier", HFILL }},

        { &hf_netlogon_secchan_sig,
          { "Signature", "netlogon.secchan.sig", FT_BYTES, BASE_HEX, NULL, 
	    0x0, "Signature", HFILL }}, 

        { &hf_netlogon_secchan_unk,
          { "Unknown", "netlogon.secchan.unk", FT_BYTES, BASE_HEX, NULL, 
          0x0, "Unknown", HFILL }}, 

        { &hf_netlogon_secchan_seq,
          { "Sequence No", "netlogon.secchan.seq", FT_BYTES, BASE_HEX, NULL, 
          0x0, "Sequence No", HFILL }}, 

        { &hf_netlogon_secchan_nonce,
          { "Nonce", "netlogon.secchan.nonce", FT_BYTES, BASE_HEX, NULL, 
          0x0, "Nonce", HFILL }}, 

	};

        static gint *ett[] = {
                &ett_dcerpc_netlogon,
		&ett_CYPHER_VALUE,
		&ett_QUOTA_LIMITS,
		&ett_IDENTITY_INFO,
		&ett_DELTA_ENUM,
		&ett_UNICODE_MULTI,
		&ett_DOMAIN_CONTROLLER_INFO,
		&ett_UNICODE_STRING_512,
		&ett_TYPE_50,
		&ett_TYPE_52,
		&ett_DELTA_ID_UNION,
		&ett_TYPE_44,
		&ett_DELTA_UNION,
		&ett_LM_OWF_PASSWORD,
		&ett_NT_OWF_PASSWORD,
		&ett_GROUP_MEMBERSHIP,
		&ett_DS_DOMAIN_TRUSTS,
		&ett_BLOB,
		&ett_DOMAIN_TRUST_INFO,
		&ett_trust_flags,
		&ett_get_dcname_request_flags,
		&ett_dc_flags,
		&ett_secchan_bind_creds,
		&ett_secchan_bind_ack_creds,
		&ett_secchan,
        };

        proto_dcerpc_netlogon = proto_register_protocol(
                "Microsoft Network Logon", "RPC_NETLOGON", "rpc_netlogon");

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
