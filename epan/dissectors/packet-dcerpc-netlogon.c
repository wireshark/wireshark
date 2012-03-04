/* packet-dcerpc-netlogon.c
 * Routines for SMB \PIPE\NETLOGON packet disassembly
 * Copyright 2001,2003 Tim Potter <tpot@samba.org>
 *  2002 structure and command dissectors by Ronnie Sahlberg
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
#include <string.h>
#include <epan/packet.h>
/* for dissect_mscldap_string */
#include "packet-ldap.h"
#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"
#include "packet-dcerpc-netlogon.h"
#include "packet-windows-common.h"
#include "packet-ntlmssp.h"
#include "packet-dcerpc-lsa.h"
/* for keytab format */
#include <epan/asn1.h>
#include "packet-kerberos.h"
/* for decoding */
#include <epan/crypt/rc4.h>
#include <epan/crypt/md4.h>
#include <epan/crypt/md5.h>
#include <epan/crypt/des.h>

extern const char *gbl_nt_password;
#ifdef DEBUG_NETLOGON
#include <stdio.h>
#define debugprintf(...) fprintf(stderr,__VA_ARGS__)
static void printnbyte(const guint8* tab,int nb,const char* txt,const char* txt2)
{
    int i=0;
    debugprintf("%s ",txt);
    for(i=0;i<nb;i++)
    {
        debugprintf("%02hhX ",*(tab+i));
    }
    debugprintf("%s",txt2);
}
#else
#define debugprintf(...)
static void printnbyte(const guint8* tab _U_,int nb _U_,const char* txt _U_,const char* txt2 _U_) {}
#endif

#define NETLOGON_FLAG_80000000 0x80000000
#define NETLOGON_FLAG_40000000 0x40000000
#define NETLOGON_FLAG_20000000 0x20000000
#define NETLOGON_FLAG_10000000 0x10000000
#define NETLOGON_FLAG_8000000   0x8000000
#define NETLOGON_FLAG_4000000   0x4000000
#define NETLOGON_FLAG_2000000   0x2000000
#define NETLOGON_FLAG_1000000   0x1000000
#define NETLOGON_FLAG_800000     0x800000
#define NETLOGON_FLAG_USEAES     0x400000
#define NETLOGON_FLAG_200000     0x200000
#define NETLOGON_FLAG_100000     0x100000
#define NETLOGON_FLAG_80000       0x80000
#define NETLOGON_FLAG_40000       0x40000
#define NETLOGON_FLAG_20000       0x20000
#define NETLOGON_FLAG_10000       0x10000
#define NETLOGON_FLAG_8000         0x8000
#define NETLOGON_FLAG_STRONGKEY    0x4000
#define NETLOGON_FLAG_2000         0x2000
#define NETLOGON_FLAG_1000         0x1000
#define NETLOGON_FLAG_800           0x800
#define NETLOGON_FLAG_400           0x400
#define NETLOGON_FLAG_200           0x200
#define NETLOGON_FLAG_100           0x100
#define NETLOGON_FLAG_80             0x80
#define NETLOGON_FLAG_40             0x40
#define NETLOGON_FLAG_20             0x20
#define NETLOGON_FLAG_10             0x10
#define NETLOGON_FLAG_8               0x8
#define NETLOGON_FLAG_4               0x4
#define NETLOGON_FLAG_2               0x2
#define NETLOGON_FLAG_1               0x1

static GHashTable *netlogon_auths=NULL;
static GHashTable *schannel_auths;
static gint hf_netlogon_TrustedDomainName_string = -1;
static gint hf_netlogon_UserName_string = -1;
static gint DomainInfo_sid = -1;
static gint DnsDomainInfo_sid = -1;
static gint DnsDomainInfo_domain_guid = -1;
static gint DnsDomainInfo_dns_domain = -1;
static gint DnsDomainInfo_dns_forest = -1;
static gint DnsDomainInfo_name = -1;
static int hf_client_challenge = -1;
static int hf_server_rid = -1;
static int hf_server_challenge = -1;
static int hf_client_credential = -1;
static int hf_server_credential = -1;
static int proto_dcerpc_netlogon = -1;
static int hf_netlogon_logon_dnslogondomainname = -1;
static int hf_netlogon_logon_upn = -1;
static int hf_netlogon_group_attrs_mandatory = -1;
static int hf_netlogon_group_attrs_enabled_by_default = -1;
static int hf_netlogon_group_attrs_enabled = -1;
static int hf_netlogon_opnum = -1;
static int hf_netlogon_data_length = -1;
static int hf_netlogon_extraflags = -1;
static int hf_netlogon_extra_flags_root_forest = -1;
static int hf_netlogon_trust_flags_dc_firsthop = -1;
static int hf_netlogon_trust_flags_rodc_to_dc = -1;
static int hf_netlogon_trust_flags_rodc_ntlm = -1;
static int hf_netlogon_package_name = -1;
static int hf_netlogon_rc = -1;
static int hf_netlogon_dos_rc = -1;
static int hf_netlogon_werr_rc = -1;
static int hf_netlogon_len = -1;
static int hf_netlogon_sensitive_data_flag = -1;
static int hf_netlogon_sensitive_data_len = -1;
static int hf_netlogon_sensitive_data = -1;
static int hf_netlogon_security_information = -1;
static int hf_netlogon_dummy = -1;
static int hf_netlogon_neg_flags = -1;
static int hf_netlogon_neg_flags_80000000 = -1;
static int hf_netlogon_neg_flags_40000000 = -1;
static int hf_netlogon_neg_flags_20000000 = -1;
static int hf_netlogon_neg_flags_10000000 = -1;
static int hf_netlogon_neg_flags_8000000 = -1;
static int hf_netlogon_neg_flags_4000000 = -1;
static int hf_netlogon_neg_flags_2000000 = -1;
static int hf_netlogon_neg_flags_1000000 = -1;
static int hf_netlogon_neg_flags_800000 = -1;
static int hf_netlogon_neg_flags_400000 = -1;
static int hf_netlogon_neg_flags_200000 = -1;
static int hf_netlogon_neg_flags_100000 = -1;
static int hf_netlogon_neg_flags_80000 = -1;
static int hf_netlogon_neg_flags_40000 = -1;
static int hf_netlogon_neg_flags_20000 = -1;
static int hf_netlogon_neg_flags_10000 = -1;
static int hf_netlogon_neg_flags_8000 = -1;
static int hf_netlogon_neg_flags_4000 = -1;
static int hf_netlogon_neg_flags_2000 = -1;
static int hf_netlogon_neg_flags_1000 = -1;
static int hf_netlogon_neg_flags_800 = -1;
static int hf_netlogon_neg_flags_400 = -1;
static int hf_netlogon_neg_flags_200 = -1;
static int hf_netlogon_neg_flags_100 = -1;
static int hf_netlogon_neg_flags_80 = -1;
static int hf_netlogon_neg_flags_40 = -1;
static int hf_netlogon_neg_flags_20 = -1;
static int hf_netlogon_neg_flags_10 = -1;
static int hf_netlogon_neg_flags_8 = -1;
static int hf_netlogon_neg_flags_4 = -1;
static int hf_netlogon_neg_flags_2 = -1;
static int hf_netlogon_neg_flags_1 = -1;
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
static int hf_netlogon_lsapolicy_len = -1;
static int hf_netlogon_lsapolicy_referentid = -1;
static int hf_netlogon_lsapolicy_pointer = -1;
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
static int hf_netlogon_trust_extention = -1;
static int hf_netlogon_trust_max = -1;
static int hf_netlogon_trust_offset = -1;
static int hf_netlogon_trust_len = -1;
static int hf_netlogon_dummy_string = -1;
static int hf_netlogon_dummy_string2 = -1;
static int hf_netlogon_dummy_string3 = -1;
static int hf_netlogon_dummy_string4 = -1;
static int hf_netlogon_dummy_string5 = -1;
static int hf_netlogon_dummy_string6 = -1;
static int hf_netlogon_dummy_string7 = -1;
static int hf_netlogon_dummy_string8 = -1;
static int hf_netlogon_dummy_string9 = -1;
static int hf_netlogon_dummy_string10 = -1;
static int hf_netlogon_unknown_short = -1;
static int hf_netlogon_unknown_long = -1;
static int hf_netlogon_dummy1_long = -1;
static int hf_netlogon_dummy2_long = -1;
static int hf_netlogon_dummy3_long = -1;
static int hf_netlogon_dummy4_long = -1;
static int hf_netlogon_dummy5_long = -1;
static int hf_netlogon_dummy6_long = -1;
static int hf_netlogon_dummy7_long = -1;
static int hf_netlogon_dummy8_long = -1;
static int hf_netlogon_dummy9_long = -1;
static int hf_netlogon_dummy10_long = -1;
static int hf_netlogon_unknown_char = -1;
static int hf_netlogon_logon_time = -1;
static int hf_netlogon_logoff_time = -1;
static int hf_netlogon_last_logoff_time = -1;
static int hf_netlogon_kickoff_time = -1;
static int hf_netlogon_pwd_age = -1;
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
static int hf_netlogon_resourcegroupcount = -1;
static int hf_netlogon_downlevel_domain_name = -1;
static int hf_netlogon_dns_domain_name = -1;
static int hf_netlogon_ad_client_dns_name = -1;
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
static int hf_netlogon_num_sid = -1;
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
static int hf_netlogon_os_version = -1;
static int hf_netlogon_workstation_os = -1;
static int hf_netlogon_workstation_flags = -1;
static int hf_netlogon_supportedenctypes = -1;

static int hf_netlogon_workstations = -1;
static int hf_netlogon_workstation_fqdn = -1;
static int hf_netlogon_group_name = -1;
static int hf_netlogon_alias_name = -1;
static int hf_netlogon_country = -1;
static int hf_netlogon_codepage = -1;
static int hf_netlogon_flags = -1;
static int hf_netlogon_trust_attribs = -1;
static int hf_netlogon_trust_attribs_non_transitive = -1;
static int hf_netlogon_trust_attribs_uplevel_only = -1;
static int hf_netlogon_trust_attribs_quarantined_domain = -1;
static int hf_netlogon_trust_attribs_forest_transitive = -1;
static int hf_netlogon_trust_attribs_cross_organization = -1;
static int hf_netlogon_trust_attribs_within_forest = -1;
static int hf_netlogon_trust_attribs_treat_as_external = -1;
static int hf_netlogon_trust_type = -1;
static int hf_netlogon_trust_flags = -1;
static int hf_netlogon_trust_flags_inbound = -1;
static int hf_netlogon_trust_flags_outbound = -1;
static int hf_netlogon_trust_flags_in_forest = -1;
static int hf_netlogon_trust_flags_native_mode = -1;
static int hf_netlogon_trust_flags_primary = -1;
static int hf_netlogon_trust_flags_tree_root = -1;
static int hf_netlogon_trust_parent_index = -1;
static int hf_netlogon_user_account_control = -1;
static int hf_netlogon_user_account_control_dont_require_preauth = -1;
static int hf_netlogon_user_account_control_use_des_key_only = -1;
static int hf_netlogon_user_account_control_not_delegated = -1;
static int hf_netlogon_user_account_control_trusted_for_delegation = -1;
static int hf_netlogon_user_account_control_smartcard_required = -1;
static int hf_netlogon_user_account_control_encrypted_text_password_allowed = -1;
static int hf_netlogon_user_account_control_account_auto_locked = -1;
static int hf_netlogon_user_account_control_dont_expire_password = -1;
static int hf_netlogon_user_account_control_server_trust_account = -1;
static int hf_netlogon_user_account_control_workstation_trust_account = -1;
static int hf_netlogon_user_account_control_interdomain_trust_account = -1;
static int hf_netlogon_user_account_control_mns_logon_account = -1;
static int hf_netlogon_user_account_control_normal_account = -1;
static int hf_netlogon_user_account_control_temp_duplicate_account = -1;
static int hf_netlogon_user_account_control_password_not_required = -1;
static int hf_netlogon_user_account_control_home_directory_required = -1;
static int hf_netlogon_user_account_control_account_disabled = -1;
static int hf_netlogon_user_flags = -1;
static int hf_netlogon_user_flags_extra_sids = -1;
static int hf_netlogon_user_flags_resource_groups = -1;
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
static int hf_netlogon_dnsdomaininfo = -1;
static int hf_netlogon_s4u2proxytarget = -1;
static int hf_netlogon_transitedlistsize = -1;
static int hf_netlogon_transited_service = -1;

static gint ett_nt_counted_longs_as_string = -1;
static gint ett_dcerpc_netlogon = -1;
static gint ett_group_attrs = -1;
static gint ett_user_flags = -1;
static gint ett_user_account_control = -1;
static gint ett_QUOTA_LIMITS = -1;
static gint ett_IDENTITY_INFO = -1;
static gint ett_DELTA_ENUM = -1;
static gint ett_authenticate_flags = -1;
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
static gint ett_LSA_POLICY_INFO = -1;
static gint ett_DOMAIN_TRUST_INFO = -1;
static gint ett_trust_flags = -1;
static gint ett_trust_attribs = -1;
static gint ett_get_dcname_request_flags = -1;
static gint ett_dc_flags = -1;

typedef struct _netlogon_auth_vars {
    guint64 client_challenge;
    guint64 server_challenge;
    guint8  session_key[16];
    guint8  encryption_key[16];
    guint8  sequence[16];
    guint32 flags;
    guint64 seq;
    guint64 confounder;
    guint8 private_type;
    gboolean can_decrypt;
    void* private;
    char* client_name;
    int start;
    int next_start;
    struct _netlogon_auth_vars *next;
} netlogon_auth_vars;

typedef struct _md4_pass {
    guint8 md4[16];
} md4_pass;

typedef struct _seen_packet {
    gboolean isseen;
    guint32 num;
} seen_packet;

static seen_packet seen;
guint
netlogon_auth_hash (gconstpointer k);
static e_uuid_t uuid_dcerpc_netlogon = {
    0x12345678, 0x1234, 0xabcd,
    { 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0xcf, 0xfb }
};

static guint16 ver_dcerpc_netlogon = 1;

static gint dissect_dcerpc_8bytes (tvbuff_t *tvb, gint offset, packet_info *pinfo _U_,
                                   proto_tree *tree, guint8 *drep,
                                   int hfindex, guint64 *pdata)
{
    guint64 data;

    data = ((drep[0] & DREP_LITTLE_ENDIAN)
            ? tvb_get_letoh64 (tvb, offset)
            : tvb_get_ntoh64 (tvb, offset));

    /* These fields are FT_BYTES, hence the byte order doesn't matter */
    if (tree) {
        proto_tree_add_item(tree, hfindex, tvb, offset, 8, ENC_NA);
    }
    if (pdata)
        *pdata = data;
    return offset+8;
}

static const true_false_string user_account_control_dont_require_preauth= {
    "This account DOESN'T_REQUIRE_PREAUTHENTICATION",
    "This account REQUIRES preauthentication",
};
static const true_false_string user_account_control_use_des_key_only= {
    "This account must USE_DES_KEY_ONLY for passwords",
    "This account does NOT have to use_des_key_only",
};
static const true_false_string user_account_control_not_delegated= {
    "This account is NOT_DELEGATED",
    "This might have been delegated",
};
static const true_false_string user_account_control_trusted_for_delegation= {
    "This account is TRUSTED_FOR_DELEGATION",
    "This account is NOT trusted_for_delegation",
};
static const true_false_string user_account_control_smartcard_required= {
    "This account REQUIRES_SMARTCARD to authenticate",
    "This account does NOT require_smartcard to authenticate",
};
static const true_false_string user_account_control_encrypted_text_password_allowed= {
    "This account allows ENCRYPTED_TEXT_PASSWORD",
    "This account does NOT allow encrypted_text_password",
};
static const true_false_string user_account_control_account_auto_locked= {
    "This account is AUTO_LOCKED",
    "This account is NOT auto_locked",
};
static const true_false_string user_account_control_dont_expire_password= {
    "This account DOESN'T_EXPIRE_PASSWORDs",
    "This account might expire_passwords",
};
static const true_false_string user_account_control_server_trust_account= {
    "This account is a SERVER_TRUST_ACCOUNT",
    "This account is NOT a server_trust_account",
};
static const true_false_string user_account_control_workstation_trust_account= {
    "This account is a WORKSTATION_TRUST_ACCOUNT",
    "This account is NOT a workstation_trust_account",
};
static const true_false_string user_account_control_interdomain_trust_account= {
    "This account is an INTERDOMAIN_TRUST_ACCOUNT",
    "This account is NOT an interdomain_trust_account",
};
static const true_false_string user_account_control_mns_logon_account= {
    "This account is a MNS_LOGON_ACCOUNT",
    "This account is NOT a mns_logon_account",
};
static const true_false_string user_account_control_normal_account= {
    "This account is a NORMAL_ACCOUNT",
    "This account is NOT a normal_account",
};
static const true_false_string user_account_control_temp_duplicate_account= {
    "This account is a TEMP_DUPLICATE_ACCOUNT",
    "This account is NOT a temp_duplicate_account",
};
static const true_false_string user_account_control_password_not_required= {
    "This account REQUIRES_NO_PASSWORD",
    "This account REQUIRES a password",
};
static const true_false_string user_account_control_home_directory_required= {
    "This account REQUIRES_HOME_DIRECTORY",
    "This account does NOT require_home_directory",
};
static const true_false_string user_account_control_account_disabled= {
    "This account is DISABLED",
    "This account is NOT disabled",
};

typedef struct _netlogon_auth_key {
    address src;
    address dst;
    guint32 srcport;
    guint32 dstport;
    char * name;
} netlogon_auth_key;

static gint
netlogon_auth_equal (gconstpointer k1, gconstpointer k2)
{
    const netlogon_auth_key *key1 = (const netlogon_auth_key *)k1;
    const netlogon_auth_key *key2 = (const netlogon_auth_key *)k2;
    if(key1->name == NULL || key2->name ==NULL)
        return ((key1->srcport == key2->srcport) && (key1->dstport == key2->dstport) && ADDRESSES_EQUAL(&key1->src,&key2->src) &&
                ADDRESSES_EQUAL(&key1->dst,&key2->dst));
    else
        return ((strcmp(key1->name,key2->name)==0) && ADDRESSES_EQUAL(&key1->src,&key2->src) &&
                ADDRESSES_EQUAL(&key1->dst,&key2->dst));
}

guint
netlogon_auth_hash (gconstpointer k)
{
    const netlogon_auth_key *key1 = (const netlogon_auth_key *)k;
    guint hash_val1;
    if(key1->name == NULL) {
        hash_val1 = key1->dstport;
        hash_val1 += key1->srcport;
    }
    else {
        unsigned int i = 0;
        hash_val1 = 0;
        for(i=0; i<strlen(key1->name);i++) {
            hash_val1 += key1->name[i];
        }
    }

    ADD_ADDRESS_TO_HASH(hash_val1, &key1->src);
    ADD_ADDRESS_TO_HASH(hash_val1, &key1->dst);
    return hash_val1;
}
static int
netlogon_dissect_EXTRA_FLAGS(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *parent_tree, guint8 *drep)
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
                              hf_netlogon_extraflags, &mask);

    if(parent_tree){
        item = proto_tree_add_uint(parent_tree, hf_netlogon_extraflags,
                                   tvb, offset-4, 4, mask);
        tree = proto_item_add_subtree(item, ett_trust_flags);
    }

    proto_tree_add_boolean(tree, hf_netlogon_extra_flags_root_forest,
                           tvb, offset-4, 4, mask);
    proto_tree_add_boolean(tree, hf_netlogon_trust_flags_dc_firsthop,
                           tvb, offset-4, 4, mask);
    proto_tree_add_boolean(tree, hf_netlogon_trust_flags_rodc_to_dc,
                           tvb, offset-4, 4, mask);
    proto_tree_add_boolean(tree, hf_netlogon_trust_flags_rodc_ntlm,
                           tvb, offset-4, 4, mask);

    return offset;
}
int
dissect_ndr_lm_nt_hash_cb(tvbuff_t *tvb, int offset,
                          packet_info *pinfo, proto_tree *tree,
                          guint8 *drep, int hf_index,
                          dcerpc_callback_fnct_t *callback,
                          void *callback_args)
{
    dcerpc_info *di = pinfo->private_data;
    guint16 len, size;

    /* Structure starts with short, but is aligned for longs */

    ALIGN_TO_4_BYTES;

    if (di->conformant_run)
        return offset;

#if 0
    struct {
        short len;
        short size;
        [size_is(size/2), length_is(len/2), ptr] unsigned short *string;
    } HASH;

#endif

    offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
                                hf_nt_cs_len, &len);

    offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
                                hf_nt_cs_size, &size);

    offset = dissect_ndr_pointer_cb(tvb, offset, pinfo, tree, drep,
                                    dissect_ndr_char_cvstring, NDR_POINTER_UNIQUE,
                                    "Bytes Array", hf_index, callback, callback_args);

    return offset;
}
static int
dissect_ndr_lm_nt_hash_helper(tvbuff_t *tvb, int offset,
                              packet_info *pinfo, proto_tree *tree,
                              guint8 *drep, int hf_index, int levels _U_,
                              gboolean add_subtree)
{
    proto_item *item;
    proto_tree *subtree = tree;

    if (add_subtree) {

        item = proto_tree_add_text(
            tree, tvb, offset, 0, "%s",
            proto_registrar_get_name(hf_index));

        subtree = proto_item_add_subtree(item,ett_LM_OWF_PASSWORD);
    }

    return dissect_ndr_lm_nt_hash_cb(
        tvb, offset, pinfo, subtree, drep, hf_index,
        NULL, NULL);
    /*cb_wstr_postprocess, GINT_TO_POINTER(2 + levels));*/
}
static int
netlogon_dissect_USER_ACCOUNT_CONTROL(tvbuff_t *tvb, int offset,
                                      packet_info *pinfo, proto_tree *parent_tree, guint8 *drep)
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
                              hf_netlogon_user_account_control, &mask);

    if(parent_tree){
        item = proto_tree_add_uint(parent_tree, hf_netlogon_user_account_control,
                                   tvb, offset-4, 4, mask);
        tree = proto_item_add_subtree(item, ett_user_account_control);
    }

    proto_tree_add_boolean(tree, hf_netlogon_user_account_control_dont_require_preauth,
                           tvb, offset-4, 4, mask);
    proto_tree_add_boolean(tree, hf_netlogon_user_account_control_use_des_key_only,
                           tvb, offset-4, 4, mask);
    proto_tree_add_boolean(tree, hf_netlogon_user_account_control_not_delegated,
                           tvb, offset-4, 4, mask);
    proto_tree_add_boolean(tree, hf_netlogon_user_account_control_trusted_for_delegation,
                           tvb, offset-4, 4, mask);
    proto_tree_add_boolean(tree, hf_netlogon_user_account_control_smartcard_required,
                           tvb, offset-4, 4, mask);
    proto_tree_add_boolean(tree, hf_netlogon_user_account_control_encrypted_text_password_allowed,
                           tvb, offset-4, 4, mask);
    proto_tree_add_boolean(tree, hf_netlogon_user_account_control_account_auto_locked,
                           tvb, offset-4, 4, mask);
    proto_tree_add_boolean(tree, hf_netlogon_user_account_control_dont_expire_password,
                           tvb, offset-4, 4, mask);
    proto_tree_add_boolean(tree, hf_netlogon_user_account_control_server_trust_account,
                           tvb, offset-4, 4, mask);
    proto_tree_add_boolean(tree, hf_netlogon_user_account_control_workstation_trust_account,
                           tvb, offset-4, 4, mask);
    proto_tree_add_boolean(tree, hf_netlogon_user_account_control_interdomain_trust_account,
                           tvb, offset-4, 4, mask);
    proto_tree_add_boolean(tree, hf_netlogon_user_account_control_mns_logon_account,
                           tvb, offset-4, 4, mask);
    proto_tree_add_boolean(tree, hf_netlogon_user_account_control_normal_account,
                           tvb, offset-4, 4, mask);
    proto_tree_add_boolean(tree, hf_netlogon_user_account_control_temp_duplicate_account,
                           tvb, offset-4, 4, mask);
    proto_tree_add_boolean(tree, hf_netlogon_user_account_control_password_not_required,
                           tvb, offset-4, 4, mask);
    proto_tree_add_boolean(tree, hf_netlogon_user_account_control_home_directory_required,
                           tvb, offset-4, 4, mask);
    proto_tree_add_boolean(tree, hf_netlogon_user_account_control_account_disabled,
                           tvb, offset-4, 4, mask);
    return offset;
}


static int
netlogon_dissect_LOGONSRV_HANDLE(tvbuff_t *tvb, int offset,
                                 packet_info *pinfo, proto_tree *tree,
                                 guint8 *drep)
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
                                     guint8 *drep)
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


    offset = dissect_ndr_time_t(tvb, offset, pinfo, tree, drep, hf_netlogon_logon_time, NULL);

    offset = dissect_ndr_time_t(tvb, offset, pinfo, tree, drep, hf_netlogon_last_logoff_time, NULL);

    offset = dissect_ndr_time_t(tvb, offset, pinfo, tree, drep, hf_netlogon_logoff_time, NULL);

    offset = dissect_ndr_time_t(tvb, offset, pinfo, tree, drep, hf_netlogon_kickoff_time, NULL);

    offset = dissect_ndr_time_t(tvb, offset, pinfo, tree, drep, hf_netlogon_pwd_age, NULL);

    offset = dissect_ndr_time_t(tvb, offset, pinfo, tree, drep, hf_netlogon_pwd_can_change_time, NULL);

    offset = dissect_ndr_time_t(tvb, offset, pinfo, tree, drep, hf_netlogon_pwd_must_change_time, NULL);

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
 * IDL long NetrLogonUasLogon(
 * IDL      [in][unique][string] wchar_t *ServerName,
 * IDL      [in][ref][string] wchar_t *UserName,
 * IDL      [in][ref][string] wchar_t *Workstation,
 * IDL      [out][unique] VALIDATION_UAS_INFO *info
 * IDL );
 */
static int
netlogon_dissect_netrlogonuaslogon_rqst(tvbuff_t *tvb, int offset,
                                        packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
                                              pinfo, tree, drep);

    offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
                                          NDR_POINTER_REF, "Account", hf_netlogon_acct_name, CB_STR_COL_INFO);

    offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
                                          NDR_POINTER_REF, "Workstation", hf_netlogon_workstation, 0);

    return offset;
}


static int
netlogon_dissect_netrlogonuaslogon_reply(tvbuff_t *tvb, int offset,
                                         packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_VALIDATION_UAS_INFO, NDR_POINTER_UNIQUE,
                                 "VALIDATION_UAS_INFO", -1);

    offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
                              hf_netlogon_dos_rc, NULL);

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
                                 guint8 *drep)
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
 * IDL long NetrLogonUasLogoff(
 * IDL      [in][unique][string] wchar_t *ServerName,
 * IDL      [in][ref][string] wchar_t *UserName,
 * IDL      [in][ref][string] wchar_t *Workstation,
 * IDL      [out][ref] LOGOFF_UAS_INFO *info
 * IDL );
 */
static int
netlogon_dissect_netrlogonuaslogoff_rqst(tvbuff_t *tvb, int offset,
                                         packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
                                              pinfo, tree, drep);

    offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
                                          NDR_POINTER_REF, "Account", hf_netlogon_acct_name, CB_STR_COL_INFO);

    offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
                                          NDR_POINTER_REF, "Workstation", hf_netlogon_workstation, 0);

    return offset;
}


static int
netlogon_dissect_netrlogonuaslogoff_reply(tvbuff_t *tvb, int offset,
                                          packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_LOGOFF_UAS_INFO, NDR_POINTER_REF,
                                 "LOGOFF_UAS_INFO", -1);

    offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
                              hf_netlogon_dos_rc, NULL);

    return offset;
}

static int
netlogon_dissect_BYTE_byte(tvbuff_t *tvb, int offset,
                           packet_info *pinfo, proto_tree *tree,
                           guint8 *drep)
{
    offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep,
                               hf_netlogon_unknown_char, NULL);

    return offset;
}

static int
netlogon_dissect_BYTE_array(tvbuff_t *tvb, int offset,
                            packet_info *pinfo, proto_tree *tree,
                            guint8 *drep)
{
    offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_BYTE_byte);

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
                                     guint8 *drep)
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

    offset = dissect_ndr_duint32(tvb, offset, pinfo, tree, drep,
                                 hf_netlogon_logon_id, NULL);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_acct_name, 1);

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
                                 guint8 *drep _U_)
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
                        ENC_NA);
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
                                 guint8 *drep _U_)
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
                        ENC_NA);
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
                                  guint8 *drep)
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
                           guint8 *drep _U_)
{
    dcerpc_info *di;

    di=pinfo->private_data;
    if(di->conformant_run){
        /*just a run to handle conformant arrays, nothing to dissect.*/
        return offset;
    }

    proto_tree_add_item(tree, hf_netlogon_challenge, tvb, offset, 8,
                        ENC_NA);
    offset += 8;

    return offset;
}

#if 0
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
                                    void *callback_args )
{
    int len;
    gint options = GPOINTER_TO_INT(callback_args);
    gint levels = CB_STR_ITEM_LEVELS(options);
    char *s;


    /* Skip over 3 guint32's in NDR format */

    if (start_offset % 4)
        start_offset += 4 - (start_offset % 4);

    start_offset += 12;
    len = end_offset - start_offset;

    s = tvb_bytes_to_str(tvb, start_offset, len);

    /* Append string to upper-level proto_items */

    if (levels > 0 && item && s && s[0]) {
        proto_item_append_text(item, ": %s", s);
        item = item->parent;
        levels--;
        if (levels > 0) {
            proto_item_append_text(item, ": %s", s);
            item = item->parent;
            levels--;
            while (levels > 0) {
                proto_item_append_text(item, " %s", s);
                item = item->parent;
                levels--;
            }
        }
    }
    /* Call ntlmv2 response dissector */

    if (len > 24)
        dissect_ntlmv2_response(tvb, tree, start_offset, len);
}
#endif

static int
netlogon_dissect_NETWORK_INFO(tvbuff_t *tvb, int offset,
                              packet_info *pinfo, proto_tree *tree,
                              guint8 *drep)
{

    offset = netlogon_dissect_LOGON_IDENTITY_INFO(tvb, offset,
                                                  pinfo, tree, drep);
    offset = netlogon_dissect_CHALLENGE(tvb, offset,
                                        pinfo, tree, drep);
#if 0
    offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
                                          NDR_POINTER_UNIQUE, "NT ",
                                          hf_netlogon_nt_owf_password, 0);
    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_data_length, NULL);
#endif
    offset = dissect_ndr_lm_nt_hash_helper(tvb,offset,pinfo, tree, drep, hf_netlogon_lm_chal_resp, 0,TRUE);
    offset = dissect_ndr_lm_nt_hash_helper(tvb,offset,pinfo, tree, drep, hf_netlogon_lm_chal_resp, 0,TRUE);
    /* Not really sure that it really works with NTLM v2 ....*/
#if 0
    offset = netlogon_dissect_LM_OWF_PASSWORD(tvb, offset,
                                              pinfo, tree, drep);

    offset = netlogon_dissect_NT_OWF_PASSWORD(tvb, offset,
                                              pinfo, tree, drep);
#endif
    return offset;
#if 0
    offset = dissect_ndr_counted_byte_array_cb(
        tvb, offset, pinfo, tree, drep, hf_netlogon_nt_chal_resp,
        dissect_nt_chal_resp_cb,GINT_TO_POINTER(2));

    offset = dissect_ndr_counted_byte_array(tvb, offset, pinfo, tree, drep,
                                            hf_netlogon_lm_chal_resp, 0);

    return offset;
#endif
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
                              guint8 *drep)
{
    offset = netlogon_dissect_LOGON_IDENTITY_INFO(tvb, offset,
                                                  pinfo, tree, drep);

    offset = netlogon_dissect_LM_OWF_PASSWORD(tvb, offset,
                                              pinfo, tree, drep);

    offset = netlogon_dissect_NT_OWF_PASSWORD(tvb, offset,
                                              pinfo, tree, drep);

    return offset;
}

static int
netlogon_dissect_GENERIC_INFO(tvbuff_t *tvb, int offset,
                              packet_info *pinfo, proto_tree *tree,
                              guint8 *drep)
{
    offset = netlogon_dissect_LOGON_IDENTITY_INFO(tvb, offset,
                                                  pinfo, tree, drep);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_package_name, 0|CB_STR_SAVE);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_data_length, NULL);

    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_BYTE_array, NDR_POINTER_REF,
                                 "Logon Data", -1);
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
                       guint8 *drep)
{
    guint16 level = 0;

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
    case 4:
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                     netlogon_dissect_GENERIC_INFO, NDR_POINTER_UNIQUE,
                                     "GENERIC_INFO:", -1);
        break;
    case 5:
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                     netlogon_dissect_INTERACTIVE_INFO, NDR_POINTER_UNIQUE,
                                     "INTERACTIVE_TRANSITIVE_INFO:", -1);
        break;
    case 6:
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                     netlogon_dissect_NETWORK_INFO, NDR_POINTER_UNIQUE,
                                     "NETWORK_TRANSITIVE_INFO", -1);
        break;
    case 7:
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                     netlogon_dissect_SERVICE_INFO, NDR_POINTER_UNIQUE,
                                     "SERVICE_TRANSITIVE_INFO", -1);
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
                            guint8 *drep _U_)
{
    dcerpc_info *di;

    di=pinfo->private_data;
    if(di->conformant_run){
        /*just a run to handle conformant arrays, nothing to dissect.*/
        return offset;
    }

    proto_tree_add_item(tree, hf_netlogon_credential, tvb, offset, 8,
                        ENC_NA);
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
                               guint8 *drep)
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


static const true_false_string group_attrs_mandatory = {
    "The MANDATORY bit is SET",
    "The mandatory bit is NOT set",
};
static const true_false_string group_attrs_enabled_by_default = {
    "The ENABLED_BY_DEFAULT bit is SET",
    "The enabled_by_default bit is NOT set",
};
static const true_false_string group_attrs_enabled = {
    "The enabled bit is SET",
    "The enabled bit is NOT set",
};
static int
netlogon_dissect_GROUP_MEMBERSHIP_ATTRIBUTES(tvbuff_t *tvb, int offset,
                                             packet_info *pinfo, proto_tree *parent_tree, guint8 *drep)
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
                              hf_netlogon_attrs, &mask);

    if(parent_tree){
        item = proto_tree_add_uint(parent_tree, hf_netlogon_attrs,
                                   tvb, offset-4, 4, mask);
        tree = proto_item_add_subtree(item, ett_group_attrs);
    }

    proto_tree_add_boolean(tree, hf_netlogon_group_attrs_enabled,
                           tvb, offset-4, 4, mask);
    proto_tree_add_boolean(tree, hf_netlogon_group_attrs_enabled_by_default,
                           tvb, offset-4, 4, mask);
    proto_tree_add_boolean(tree, hf_netlogon_group_attrs_mandatory,
                           tvb, offset-4, 4, mask);

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
                                  guint8 *drep)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;

    if(parent_tree){
        item = proto_tree_add_text(parent_tree, tvb, offset, 0,
                                   "GROUP_MEMBERSHIP:");
        tree = proto_item_add_subtree(item, ett_GROUP_MEMBERSHIP);
    }

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_group_rid, NULL);

    offset = netlogon_dissect_GROUP_MEMBERSHIP_ATTRIBUTES(tvb, offset,
                                                          pinfo, tree, drep);

    return offset;
}

static int
netlogon_dissect_GROUP_MEMBERSHIP_ARRAY(tvbuff_t *tvb, int offset,
                                        packet_info *pinfo, proto_tree *tree,
                                        guint8 *drep)
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
                                  guint8 *drep _U_)
{
    dcerpc_info *di;

    di=pinfo->private_data;
    if(di->conformant_run){
        /*just a run to handle conformant arrays, nothing to dissect.*/
        return offset;
    }

    proto_tree_add_item(tree, hf_netlogon_user_session_key, tvb, offset, 16,
                        ENC_NA);
    offset += 16;

    return offset;
}



static const true_false_string user_flags_extra_sids= {
    "The EXTRA_SIDS bit is SET",
    "The extra_sids is NOT set",
};
static const true_false_string user_flags_resource_groups= {
    "The RESOURCE_GROUPS bit is SET",
    "The resource_groups is NOT set",
};
static int
netlogon_dissect_USER_FLAGS(tvbuff_t *tvb, int offset,
                            packet_info *pinfo, proto_tree *parent_tree, guint8 *drep)
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
                              hf_netlogon_user_flags, &mask);

    if(parent_tree){
        item = proto_tree_add_uint(parent_tree, hf_netlogon_user_flags,
                                   tvb, offset-4, 4, mask);
        tree = proto_item_add_subtree(item, ett_user_flags);
    }

    proto_tree_add_boolean(tree, hf_netlogon_user_flags_resource_groups,
                           tvb, offset-4, 4, mask);
    proto_tree_add_boolean(tree, hf_netlogon_user_flags_extra_sids,
                           tvb, offset-4, 4, mask);

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
 * IDL   long expansionroom[2];
 * IDL   long useraccountcontrol;
 * IDL   long expansionroom[7];
 * IDL } VALIDATION_SAM_INFO;
 */
static int
netlogon_dissect_VALIDATION_SAM_INFO(tvbuff_t *tvb, int offset,
                                     packet_info *pinfo, proto_tree *tree,
                                     guint8 *drep)
{

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

    offset = netlogon_dissect_USER_FLAGS(tvb, offset,
                                         pinfo, tree, drep);

    offset = netlogon_dissect_USER_SESSION_KEY(tvb, offset,
                                               pinfo, tree, drep);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_logon_srv, 0);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_logon_dom, 0);

    offset = dissect_ndr_nt_PSID(tvb, offset, pinfo, tree, drep);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_dummy1_long, NULL);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_dummy2_long, NULL);

    offset = netlogon_dissect_USER_ACCOUNT_CONTROL(tvb, offset,
                                                   pinfo, tree, drep);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_dummy4_long, NULL);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_dummy5_long, NULL);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_dummy6_long, NULL);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_dummy7_long, NULL);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_dummy8_long, NULL);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_dummy9_long, NULL);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_dummy10_long, NULL);

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
 * IDL   long expansionroom[2];
 * IDL   long useraccountcontrol;
 * IDL   long expansionroom[7];
 * IDL   long sidcount;
 * IDL   [unique] SID_AND_ATTRIBS;
 * IDL } VALIDATION_SAM_INFO2;
 */
static int
netlogon_dissect_VALIDATION_SAM_INFO2(tvbuff_t *tvb, int offset,
                                      packet_info *pinfo, proto_tree *tree,
                                      guint8 *drep)
{
    offset = netlogon_dissect_VALIDATION_SAM_INFO(tvb,offset,pinfo,tree,drep);
#if 0
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

    offset = netlogon_dissect_USER_FLAGS(tvb, offset,
                                         pinfo, tree, drep);

    offset = netlogon_dissect_USER_SESSION_KEY(tvb, offset,
                                               pinfo, tree, drep);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_logon_srv, 0);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_logon_dom, 0);

    offset = dissect_ndr_nt_PSID(tvb, offset, pinfo, tree, drep);

    for(i=0;i<2;i++){
        offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                    hf_netlogon_unknown_long, NULL);
    }
    offset = netlogon_dissect_USER_ACCOUNT_CONTROL(tvb, offset,
                                                   pinfo, tree, drep);

    for(i=0;i<7;i++){
        offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                    hf_netlogon_unknown_long, NULL);
    }
#endif
    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_num_sid, NULL);

    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 dissect_ndr_nt_SID_AND_ATTRIBUTES_ARRAY, NDR_POINTER_UNIQUE,
                                 "SID_AND_ATTRIBUTES_ARRAY:", -1);

    return offset;
}


static int
netlogon_dissect_VALIDATION_SAM_INFO4(tvbuff_t *tvb, int offset,
                                      packet_info *pinfo, proto_tree *tree,
                                      guint8 *drep)
{
    offset = netlogon_dissect_VALIDATION_SAM_INFO2(tvb,offset,pinfo,tree,drep);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_logon_dnslogondomainname, 0);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_logon_upn, 0);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_dummy_string, 0);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_dummy_string2, 0);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_dummy_string3, 0);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_dummy_string4, 0);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_dummy_string5, 0);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_dummy_string6, 0);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_dummy_string7, 0);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_dummy_string8, 0);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_dummy_string9, 0);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_dummy_string10, 0);
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
 * IDL   long expansionroom[2];
 * IDL   long useraccountcontrol;
 * IDL   long expansionroom[7];
 * IDL   long sidcount;
 * IDL   [unique] SID_AND_ATTRIBS;
 * IDL   [unique] SID resourcegroupdomainsid;
 * IDL   long resourcegroupcount;
 qqq
 * IDL } PAC_LOGON_INFO;
 */
int
netlogon_dissect_PAC_LOGON_INFO(tvbuff_t *tvb, int offset,
                                packet_info *pinfo, proto_tree *tree,
                                guint8 *drep)
{
    guint32 rgc;
    offset = netlogon_dissect_VALIDATION_SAM_INFO(tvb,offset,pinfo,tree,drep);
#if 0
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

    offset = netlogon_dissect_USER_FLAGS(tvb, offset,
                                         pinfo, tree, drep);

    offset = netlogon_dissect_USER_SESSION_KEY(tvb, offset,
                                               pinfo, tree, drep);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_logon_srv, 0);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_logon_dom, 0);

    offset = dissect_ndr_nt_PSID(tvb, offset, pinfo, tree, drep);

    for(i=0;i<2;i++){
        offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                    hf_netlogon_unknown_long, NULL);
    }
    offset = netlogon_dissect_USER_ACCOUNT_CONTROL(tvb, offset,
                                                   pinfo, tree, drep);

    for(i=0;i<7;i++){
        offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                    hf_netlogon_unknown_long, NULL);
    }
#endif

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_num_sid, NULL);

    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 dissect_ndr_nt_SID_AND_ATTRIBUTES_ARRAY, NDR_POINTER_UNIQUE,
                                 "SID_AND_ATTRIBUTES_ARRAY:", -1);


    offset = dissect_ndr_nt_PSID(tvb, offset, pinfo, tree, drep);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_resourcegroupcount, &rgc);

    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_GROUP_MEMBERSHIP_ARRAY, NDR_POINTER_UNIQUE,
                                 "ResourceGroupIDs", -1);

    return offset;
}

static int
netlogon_dissect_S4U_Transited_Service_name(tvbuff_t *tvb, int offset,
                                             packet_info *pinfo, proto_tree *tree,
                                             guint8 *drep)
{
    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_transited_service, 1);

    return offset;
}

static int
netlogon_dissect_S4U_Transited_Services_array(tvbuff_t *tvb, int offset,
                                              packet_info *pinfo, proto_tree *tree,
                                              guint8 *drep)
{
    offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_S4U_Transited_Service_name);

    return offset;
}

int
netlogon_dissect_PAC_S4U_DELEGATION_INFO(tvbuff_t *tvb, int offset,
                                            packet_info *pinfo, proto_tree *tree,
                                            guint8 *drep)
{
    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_s4u2proxytarget, 0);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_transitedlistsize, NULL);

    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_S4U_Transited_Services_array, NDR_POINTER_UNIQUE,
                                 "S4UTransitedServices", -1);

    return offset;
}

#if 0
static int
netlogon_dissect_PAC(tvbuff_t *tvb, int offset,
                     packet_info *pinfo, proto_tree *tree,
                     guint8 *drep _U_)
{
    dcerpc_info *di;
    guint32 pac_size;

    di=pinfo->private_data;
    if(di->conformant_run){
        return offset;
    }

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_pac_size, &pac_size);

    proto_tree_add_item(tree, hf_netlogon_pac_data, tvb, offset, pac_size,
                        ENC_NA);
    offset += pac_size;

    return offset;
}

static int
netlogon_dissect_AUTH(tvbuff_t *tvb, int offset,
                      packet_info *pinfo, proto_tree *tree,
                      guint8 *drep _U_)
{
    dcerpc_info *di;
    guint32 auth_size;

    di=pinfo->private_data;
    if(di->conformant_run){
        return offset;
    }

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_auth_size, &auth_size);

    proto_tree_add_item(tree, hf_netlogon_auth_data, tvb, offset, auth_size,
                        ENC_NA);
    offset += auth_size;

    return offset;
}
#endif

static int
netlogon_dissect_VALIDATION_GENERIC_INFO2 (tvbuff_t *tvb, int offset,
                                           packet_info *pinfo, proto_tree *tree,
                                           guint8 *drep)
{
    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_data_length, NULL);

    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_BYTE_array, NDR_POINTER_REF,
                                 "Validation Data", -1);

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
 * IDL   long expansionroom[2];
 * IDL   long useraccountcontrol;
 * IDL   long expansionroom[7];
 * IDL   UNICODESTRING dummy1;
 * IDL   UNICODESTRING dummy2;
 * IDL   UNICODESTRING dummy3;
 * IDL   UNICODESTRING dummy4;
 * IDL } VALIDATION_PAC_INFO;
 */
#if 0 /* Not used (anymore ?) */
static int
netlogon_dissect_VALIDATION_PAC_INFO(tvbuff_t *tvb, int offset,
                                     packet_info *pinfo, proto_tree *tree,
                                     guint8 *drep)
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

    for(i=0;i<2;i++){
        offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                    hf_netlogon_unknown_long, NULL);
    }
    offset = netlogon_dissect_USER_ACCOUNT_CONTROL(tvb, offset,
                                                   pinfo, tree, drep);

    for(i=0;i<7;i++){
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
#endif

/*
 * IDL typedef [switch_type(short)] union {
 * IDL    [case(1)][unique] VALIDATION_UAS *uas;
 * IDL    [case(2)][unique] VALIDATION_SAM_INFO *sam;
 * IDL    [case(3)][unique] VALIDATION_SAM_INFO2 *sam2;
 * IDL    [case(4)][unique] VALIDATION_GENERIC_INFO *generic;
 * IDL    [case(5)][unique] VALIDATION_GENERIC_INFO *generic2;
 * IDL    [case(5)][unique] VALIDATION_GENERIC_INFO *generic2;
 * IDL    [case(6)][unique] VALIDATION_SAM_INFO4 *sam4;
 * IDL } VALIDATION;
 */
static int
netlogon_dissect_VALIDATION(tvbuff_t *tvb, int offset,
                            packet_info *pinfo, proto_tree *tree,
                            guint8 *drep)
{
    guint16 level = 0;

    offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_validation_level, &level);

    ALIGN_TO_4_BYTES;
    switch(level){
    case 1:
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                     netlogon_dissect_VALIDATION_UAS_INFO, NDR_POINTER_UNIQUE,
                                     "VALIDATION_UAS_INFO:", -1);
        break;
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
                                     netlogon_dissect_VALIDATION_GENERIC_INFO2, NDR_POINTER_UNIQUE,
                                     "VALIDATION_INFO:", -1);
        break;
    case 5:
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                     netlogon_dissect_VALIDATION_GENERIC_INFO2, NDR_POINTER_UNIQUE,
                                     "VALIDATION_INFO2:", -1);
        break;
    case 6:
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                     netlogon_dissect_VALIDATION_SAM_INFO4, NDR_POINTER_UNIQUE,
                                     "VALIDATION_SAM_INFO4:", -1);
        break;
    }
    return offset;
}
/*
 * IDL long NetrLogonSamLogonWithFlags(
 * IDL      [in][unique][string] wchar_t *ServerName,
 * IDL      [in][unique][string] wchar_t *Workstation,
 * IDL      [in][unique] AUTHENTICATOR *credential,
 * IDL      [in][out][unique] AUTHENTICATOR *returnauthenticator,
 * IDL      [in] short LogonLevel,
 * IDL      [in][ref] LOGON_LEVEL *logonlevel,
 * IDL      [in] short ValidationLevel,
 * IDL      [out][ref] VALIDATION *validation,
 * IDL      [out][ref] boolean Authorative
 * IDL      [in][out] unsigned long ExtraFlags
 * IDL );
 */
static int
netlogon_dissect_netrlogonsamlogonflags_rqst(tvbuff_t *tvb, int offset,
                                             packet_info *pinfo, proto_tree *tree, guint8 *drep)
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

    offset = netlogon_dissect_EXTRA_FLAGS(tvb, offset, pinfo, tree, drep);

    return offset;
}

static int
netlogon_dissect_netrlogonsamlogonflags_reply(tvbuff_t *tvb, int offset,
                                              packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_AUTHENTICATOR, NDR_POINTER_UNIQUE,
                                 "AUTHENTICATOR: return_authenticator", -1);

    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_VALIDATION, NDR_POINTER_REF,
                                 "VALIDATION:", -1);

    offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep,
                               hf_netlogon_authoritative, NULL);

    offset = netlogon_dissect_EXTRA_FLAGS(tvb, offset, pinfo, tree, drep);

    offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
                              hf_netlogon_rc, NULL);

    return offset;
}



/*
 * IDL long NetrLogonSamLogon(
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
netlogon_dissect_netrlogonsamlogon_rqst(tvbuff_t *tvb, int offset,
                                        packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
netlogon_dissect_netrlogonsamlogon_reply(tvbuff_t *tvb, int offset,
                                         packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
 * IDL long NetrLogonSamLogoff(
 * IDL      [in][unique][string] wchar_t *ServerName,
 * IDL      [in][unique][string] wchar_t *ComputerName,
 * IDL      [in][unique] AUTHENTICATOR credential,
 * IDL      [in][unique] AUTHENTICATOR return_authenticator,
 * IDL      [in] short logon_level,
 * IDL      [in][ref] LEVEL logoninformation
 * IDL );
 */
static int
netlogon_dissect_netrlogonsamlogoff_rqst(tvbuff_t *tvb, int offset,
                                         packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
netlogon_dissect_netrlogonsamlogoff_reply(tvbuff_t *tvb, int offset,
                                          packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_AUTHENTICATOR, NDR_POINTER_UNIQUE,
                                 "AUTHENTICATOR: return_authenticator", -1);

    offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
                              hf_netlogon_rc, NULL);

    return offset;
}

static void generate_hash_key(packet_info *pinfo,unsigned char is_server,netlogon_auth_key *key,char* name)
{
    if(is_server) {
        key->dstport = pinfo->srcport;
        key->srcport = pinfo->destport;
        COPY_ADDRESS(&key->dst,&pinfo->src);
        COPY_ADDRESS(&key->src,&pinfo->dst);
        /* name has been durably allocated */
        key->name = name;
    }
    else {
        COPY_ADDRESS(&key->dst,&pinfo->dst);
        COPY_ADDRESS(&key->src,&pinfo->src);
        key->dstport = pinfo->destport;
        key->srcport = pinfo->srcport;
        /* name has been durably allocated */
        key->name = name;
    }

}

/*
 * IDL long NetrServerReqChallenge(
 * IDL      [in][unique][string] wchar_t *ServerName,
 * IDL      [in][ref][string] wchar_t *ComputerName,
 * IDL      [in][ref] CREDENTIAL client_credential,
 * IDL      [out][ref] CREDENTIAL server_credential
 * IDL );
 */
static int
netlogon_dissect_netrserverreqchallenge_rqst(tvbuff_t *tvb, int offset,
                                             packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    /*int oldoffset = offset;*/
    netlogon_auth_vars *vars;
    netlogon_auth_vars *existing_vars;
    netlogon_auth_key *key = se_alloc(sizeof(netlogon_auth_key));
    guint8 tab[8] = { 0,0,0,0,0,0,0,0};
    dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
    dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

    /* As we are not always keeping this it could be more intelligent to g_malloc it
       and if we decide to keep it then transform it into se_alloc */
    vars = se_alloc(sizeof(netlogon_auth_vars));
    offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset, pinfo, tree, drep);
    offset = dissect_ndr_pointer_cb(
        tvb, offset, pinfo, tree, drep,
        dissect_ndr_wchar_cvstring, NDR_POINTER_REF,
        "Computer Name", hf_netlogon_computer_name,
        cb_wstr_postprocess,
        GINT_TO_POINTER(CB_STR_COL_INFO |CB_STR_SAVE | 1));

    debugprintf("1)Len %d offset %d txt %s\n",(int) strlen(dcv->private_data),offset,(char*)dcv->private_data);
    vars->client_name = se_strdup(dcv->private_data);
    debugprintf("2)Len %d offset %d txt %s\n",(int) strlen(dcv->private_data),offset,vars->client_name);

    offset = dissect_dcerpc_8bytes(tvb, offset, pinfo, tree, drep,
                                   hf_client_challenge,&vars->client_challenge);
    memcpy(tab,&vars->client_challenge,8);

    vars->start = pinfo->fd->num;
    vars->next_start = -1;
    vars->next = NULL;

    generate_hash_key(pinfo,0,key,NULL);
    existing_vars = NULL;
    existing_vars = g_hash_table_lookup(netlogon_auths, key);
    if (!existing_vars) {
        debugprintf("Adding initial vars with this start packet = %d\n",vars->start);
        g_hash_table_insert(netlogon_auths, key, vars);
    }
    else {
        while(existing_vars->next != NULL && existing_vars->start < vars->start) {
            debugprintf("Looping to find existing vars ...\n");
            existing_vars = existing_vars->next;
        }
        if(existing_vars->next != NULL || existing_vars->start == vars->start) {
            debugprintf("It seems that I already record this vars start packet = %d\n",vars->start);
        }
        else {
            debugprintf("Adding a new entry with this start packet = %d\n",vars->start);
            existing_vars->next_start = pinfo->fd->num;
            existing_vars->next = vars;
        }
    }
    /* used by other rpc that use schannel ie lsa */
#if 0
    generate_hash_key(pinfo,0,key,vars->client_name);
    existing_vars = NULL;
    existing_vars = g_hash_table_lookup(schannel_auths, key);
    if (!existing_vars)
    {
        g_hash_table_insert(schannel_auths, key, vars);
    }
    else
    {
        while(existing_vars->next != NULL && existing_vars->start <= vars->start) {
            existing_vars = existing_vars->next;
        }
        if(existing_vars->next != NULL || existing_vars == vars) {
            debugprintf("It seems that I already record this vars (schannel hash)%d\n",vars->start);
        }
        else {
            existing_vars->next_start = pinfo->fd->num;
            existing_vars->next = vars;
        }
#endif
    return offset;
}

static int
netlogon_dissect_netrserverreqchallenge_reply(tvbuff_t *tvb, int offset,
                                              packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    netlogon_auth_vars *vars;
    netlogon_auth_key key;
    guint64 server_challenge;

    generate_hash_key(pinfo,1,&key,NULL);
    vars = g_hash_table_lookup(netlogon_auths,(gconstpointer*) &key);

    offset = dissect_dcerpc_8bytes(tvb, offset, pinfo, tree, drep,
                                   hf_server_challenge, &server_challenge);
    /*offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
      netlogon_dissect_CREDENTIAL, NDR_POINTER_REF,
      "CREDENTIAL: server credential", -1);*/

    offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
                              hf_netlogon_rc, NULL);
    if(vars != NULL) {
        while(vars !=NULL && vars->next_start != -1 && vars->next_start < (int)pinfo->fd->num )
        {
            vars = vars->next;
            debugprintf("looping challenge reply... %d %d \n", vars->next_start, pinfo->fd->num);
        }
        if(vars == NULL)
        {
            debugprintf("Something strange happened while searching for challenge_reply\n");
        }
        else
        {
            vars->server_challenge = server_challenge;
        }
    }
/*
  else
  {
  debugprintf("Vars not found in challenge reply\n");
  }
*/
    return offset;
}


static int
netlogon_dissect_NETLOGON_SECURE_CHANNEL_TYPE(tvbuff_t *tvb, int offset,
                                              packet_info *pinfo, proto_tree *tree,
                                              guint8 *drep)
{
    offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_secure_channel_type, NULL);

    return offset;
}


/*
 * IDL long NetrServerAuthenticate(
 * IDL      [in][unique][string] wchar_t *ServerName,
 * IDL      [in][ref][string] wchar_t *UserName,
 * IDL      [in] short secure_challenge_type,
 * IDL      [in][ref][string] wchar_t *ComputerName,
 * IDL      [in][ref] CREDENTIAL client_challenge,
 * IDL      [out][ref] CREDENTIAL server_challenge
 * IDL );
 */
static int
netlogon_dissect_netrserverauthenticate_rqst(tvbuff_t *tvb, int offset,
                                             packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
                                              pinfo, tree, drep);

    offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
                                          NDR_POINTER_REF, "User Name", hf_netlogon_acct_name, CB_STR_COL_INFO);

    offset = netlogon_dissect_NETLOGON_SECURE_CHANNEL_TYPE(tvb, offset,
                                                           pinfo, tree, drep);

    offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
                                          NDR_POINTER_REF, "Computer Name", hf_netlogon_computer_name, CB_STR_COL_INFO);

    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_CREDENTIAL, NDR_POINTER_REF,
                                 "CREDENTIAL: client challenge", -1);

    return offset;
}
static int
netlogon_dissect_netrserverauthenticate_reply(tvbuff_t *tvb, int offset,
                                              packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
                                           guint8 *drep _U_)
{
    dcerpc_info *di;

    di=pinfo->private_data;
    if(di->conformant_run){
        /*just a run to handle conformant arrays, nothing to dissect.*/
        return offset;
    }

    proto_tree_add_item(tree, hf_netlogon_encrypted_lm_owf_password, tvb, offset, 16,
                        ENC_NA);
    offset += 16;

    return offset;
}

/*
 * IDL long NetrServerPasswordSet(
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
netlogon_dissect_netrserverpasswordset_rqst(tvbuff_t *tvb, int offset,
                                            packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
netlogon_dissect_netrserverpasswordset_reply(tvbuff_t *tvb, int offset,
                                             packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
                                   guint8 *drep)
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
                                guint8 *drep)
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
                        data_len, ENC_NA);
    offset += data_len;

    return offset;
}
static int
netlogon_dissect_USER_PRIVATE_INFO(tvbuff_t *tvb, int offset,
                                   packet_info *pinfo, proto_tree *tree,
                                   guint8 *drep)
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

int
lsarpc_dissect_sec_desc_buf(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);

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
                            guint8 *drep)
{
    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_acct_name, 3);

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

    offset = lsarpc_dissect_sec_desc_buf(tvb, offset, pinfo, tree, drep);

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
                              guint8 *drep)
{
    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_domain_name, 3);

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

    offset = lsarpc_dissect_sec_desc_buf(tvb, offset, pinfo, tree, drep);

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
                             guint8 *drep)
{
    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_group_name, 3);

    offset = netlogon_dissect_GROUP_MEMBERSHIP(tvb, offset,
                                               pinfo, tree, drep);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_group_desc, 0);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_security_information, NULL);

    offset = lsarpc_dissect_sec_desc_buf(tvb, offset, pinfo, tree, drep);

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
                              guint8 *drep)
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
                     guint8 *drep)
{
    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_user_rid, NULL);

    return offset;
}

static int
netlogon_dissect_RID_array(tvbuff_t *tvb, int offset,
                           packet_info *pinfo, proto_tree *tree,
                           guint8 *drep)
{
    offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_RID);

    return offset;
}

static int
netlogon_dissect_ATTRIB(tvbuff_t *tvb, int offset,
                        packet_info *pinfo, proto_tree *tree,
                        guint8 *drep)
{
    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_attrs, NULL);

    return offset;
}

static int
netlogon_dissect_ATTRIB_array(tvbuff_t *tvb, int offset,
                              packet_info *pinfo, proto_tree *tree,
                              guint8 *drep)
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
                                    guint8 *drep)
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
                             guint8 *drep)
{
    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_alias_name, 0);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_alias_rid, NULL);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_security_information, NULL);

    offset = lsarpc_dissect_sec_desc_buf(tvb, offset, pinfo, tree, drep);

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
                                    guint8 *drep)
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
                                    guint8 *drep)
{
    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_event_audit_option, NULL);

    return offset;
}

static int
netlogon_dissect_EVENT_AUDIT_OPTIONS_ARRAY(tvbuff_t *tvb, int offset,
                                           packet_info *pinfo, proto_tree *tree,
                                           guint8 *drep)
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
                              guint8 *drep)
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
                              guint8 *drep)
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

    offset = dissect_ndr_nt_PSID(tvb, offset, pinfo, tree, drep);

    offset = netlogon_dissect_QUOTA_LIMITS(tvb, offset,
                                           pinfo, tree, drep);

    offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
                                   hf_netlogon_db_modify_time);

    offset = dissect_ndr_nt_NTTIME(tvb, offset, pinfo, tree, drep,
                                   hf_netlogon_db_create_time);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_security_information, NULL);

    offset = lsarpc_dissect_sec_desc_buf(tvb, offset, pinfo, tree, drep);

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
                            guint8 *drep)
{
    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_dc_name, 0);

    return offset;
}

static int
netlogon_dissect_CONTROLLER_ARRAY(tvbuff_t *tvb, int offset,
                                  packet_info *pinfo, proto_tree *tree,
                                  guint8 *drep)
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
                                       guint8 *drep)
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

    offset = lsarpc_dissect_sec_desc_buf(tvb, offset, pinfo, tree, drep);

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
                           guint8 *drep)
{
    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_attrs, NULL);

    return offset;
}

static int
netlogon_dissect_PRIV_ATTR_ARRAY(tvbuff_t *tvb, int offset,
                                 packet_info *pinfo, proto_tree *tree,
                                 guint8 *drep)
{
    offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_PRIV_ATTR);

    return offset;
}

static int
netlogon_dissect_PRIV_NAME(tvbuff_t *tvb, int offset,
                           packet_info *pinfo, proto_tree *tree,
                           guint8 *drep)
{
    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_privilege_name, 1);

    return offset;
}

static int
netlogon_dissect_PRIV_NAME_ARRAY(tvbuff_t *tvb, int offset,
                                 packet_info *pinfo, proto_tree *tree,
                                 guint8 *drep)
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
                                guint8 *drep)
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

    offset = lsarpc_dissect_sec_desc_buf(tvb, offset, pinfo, tree, drep);

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
                                   guint8 *drep)
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
                        data_len, ENC_NA);
    offset += data_len;

    return offset;
}
static int
netlogon_dissect_CIPHER_VALUE(tvbuff_t *tvb, int offset,
                              packet_info *pinfo, proto_tree *parent_tree,
                              guint8 *drep, const char *name, int hf_index)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;
    int old_offset=offset;

    if(parent_tree){
        item = proto_tree_add_text(parent_tree, tvb, offset, 0,
                                   "%s", name);
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
                              guint8 *drep)
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

    offset = lsarpc_dissect_sec_desc_buf(tvb, offset, pinfo, tree, drep);

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
                                guint8 *drep)
{
    offset = dissect_ndr_duint32(tvb, offset, pinfo, tree, drep,
                                 hf_netlogon_modify_count, NULL);

    return offset;
}


#define DT_DELTA_DOMAIN                  1
#define DT_DELTA_GROUP                   2
#define DT_DELTA_DELETE_GROUP            3
#define DT_DELTA_RENAME_GROUP            4
#define DT_DELTA_USER                    5
#define DT_DELTA_DELETE_USER             6
#define DT_DELTA_RENAME_USER             7
#define DT_DELTA_GROUP_MEMBER            8
#define DT_DELTA_ALIAS                   9
#define DT_DELTA_DELETE_ALIAS           10
#define DT_DELTA_RENAME_ALIAS           11
#define DT_DELTA_ALIAS_MEMBER           12
#define DT_DELTA_POLICY                 13
#define DT_DELTA_TRUSTED_DOMAINS        14
#define DT_DELTA_DELETE_TRUST           15
#define DT_DELTA_ACCOUNTS               16
#define DT_DELTA_DELETE_ACCOUNT         17
#define DT_DELTA_SECRET                 18
#define DT_DELTA_DELETE_SECRET          19
#define DT_DELTA_DELETE_GROUP2          20
#define DT_DELTA_DELETE_USER2           21
#define DT_MODIFIED_COUNT               22

static const value_string delta_type_vals[] = {
    { DT_DELTA_DOMAIN,          "Domain" },
    { DT_DELTA_GROUP,           "Group" },
    { DT_DELTA_DELETE_GROUP,    "Delete Group" },
    { DT_DELTA_RENAME_GROUP,    "Rename Group" },
    { DT_DELTA_USER,            "User" },
    { DT_DELTA_DELETE_USER,     "Delete User" },
    { DT_DELTA_RENAME_USER,     "Rename User" },
    { DT_DELTA_GROUP_MEMBER,    "Group Member" },
    { DT_DELTA_ALIAS,           "Alias" },
    { DT_DELTA_DELETE_ALIAS,    "Delete Alias" },
    { DT_DELTA_RENAME_ALIAS,    "Rename Alias" },
    { DT_DELTA_ALIAS_MEMBER,    "Alias Member" },
    { DT_DELTA_POLICY,          "Policy" },
    { DT_DELTA_TRUSTED_DOMAINS, "Trusted Domains" },
    { DT_DELTA_DELETE_TRUST,    "Delete Trust" },
    { DT_DELTA_ACCOUNTS,        "Accounts" },
    { DT_DELTA_DELETE_ACCOUNT,  "Delete Account" },
    { DT_DELTA_SECRET,          "Secret" },
    { DT_DELTA_DELETE_SECRET,   "Delete Secret" },
    { DT_DELTA_DELETE_GROUP2,   "Delete Group2" },
    { DT_DELTA_DELETE_USER2,    "Delete User2" },
    { DT_MODIFIED_COUNT,        "Modified Count" },
    { 0, NULL }
};
/*
 * IDL typedef [switch_type(short)] union {
 * IDL   [case(1)][unique] DELTA_DOMAIN *domain;
 * IDL   [case(2)][unique] DELTA_GROUP *group;
 * IDL   [case(3)][unique] rid only ;
 * IDL   [case(4)][unique] DELTA_RENAME_GROUP *rename_group;
 * IDL   [case(5)][unique] DELTA_USER *user;
 * IDL   [case(6)][unique] rid only ;
 * IDL   [case(7)][unique] DELTA_RENAME_USER *rename_user;
 * IDL   [case(8)][unique] DELTA_GROUP_MEMBER *group_member;
 * IDL   [case(9)][unique] DELTA_ALIAS *alias;
 * IDL   [case(10)][unique] rid only ;
 * IDL   [case(11)][unique] DELTA_RENAME_ALIAS *alias;
 * IDL   [case(12)][unique] DELTA_ALIAS_MEMBER *alias_member;
 * IDL   [case(13)][unique] DELTA_POLICY *policy;
 * IDL   [case(14)][unique] DELTA_TRUSTED_DOMAINS *trusted_domains;
 * IDL   [case(15)][unique] PSID ;
 * IDL   [case(16)][unique] DELTA_ACCOUNTS *accounts;
 * IDL   [case(17)][unique] PSID ;
 * IDL   [case(18)][unique] DELTA_SECRET *secret;
 * IDL   [case(19)][unique] string;
 * IDL   [case(20)][unique] DELTA_DELETE_GROUP2 *delete_group;
 * IDL   [case(21)][unique] DELTA_DELETE_USER2 *delete_user;
 * IDL   [case(22)][unique] MODIFIED_COUNT *modified_count;
 * IDL } DELTA_UNION;
 */
static int
netlogon_dissect_DELTA_UNION(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *parent_tree,
                             guint8 *drep)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;
    int old_offset=offset;
    guint16 level = 0;

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
                                guint8 *drep)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;
    int old_offset=offset;
    guint16 level = 0;

    if(parent_tree){
        item = proto_tree_add_text(parent_tree, tvb, offset, 0,
                                   "DELTA_ID_UNION:");
        tree = proto_item_add_subtree(item, ett_DELTA_ID_UNION);
    }

    offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_delta_type, &level);

    ALIGN_TO_4_BYTES;
    switch(level){
    case 1:
        offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                    hf_netlogon_group_rid, NULL);
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
        offset = dissect_ndr_nt_PSID(tvb, offset, pinfo, tree, drep);
        break;
    case 14:
        offset = dissect_ndr_nt_PSID(tvb, offset, pinfo, tree, drep);
        break;
    case 15:
        offset = dissect_ndr_nt_PSID(tvb, offset, pinfo, tree, drep);
        break;
    case 16:
        offset = dissect_ndr_nt_PSID(tvb, offset, pinfo, tree, drep);
        break;
    case 17:
        offset = dissect_ndr_nt_PSID(tvb, offset, pinfo, tree, drep);
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
                            guint8 *drep)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;
    int old_offset=offset;
    guint16 type;

    if(parent_tree){
        item = proto_tree_add_text(parent_tree, tvb, offset, 0,
                                   "DELTA_ENUM:");
        tree = proto_item_add_subtree(item, ett_DELTA_ENUM);
    }

    offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_delta_type, &type);

    proto_item_append_text(item, "%s", val_to_str(
                               type, delta_type_vals, "Unknown"));

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
                                  guint8 *drep)
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
                                  guint8 *drep)
{
    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_num_deltas, NULL);

    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_DELTA_ENUM_array, NDR_POINTER_UNIQUE,
                                 "DELTA_ENUM: deltas", -1);

    return offset;
}


/*
 * IDL long NetrDatabaseDeltas(
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
netlogon_dissect_netrdatabasedeltas_rqst(tvbuff_t *tvb, int offset,
                                         packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
netlogon_dissect_netrdatabasedeltas_reply(tvbuff_t *tvb, int offset,
                                          packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
 * IDL long NetrDatabaseSync(
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
netlogon_dissect_netrdatabasesync_rqst(tvbuff_t *tvb, int offset,
                                       packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
netlogon_dissect_netrdatabasesync_reply(tvbuff_t *tvb, int offset,
                                        packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
                            guint8 *drep)
{
    dcerpc_info *di;

    di=pinfo->private_data;
    if(di->conformant_run){
        /*just a run to handle conformant arrays, nothing to dissect */
        return offset;
    }

    proto_tree_add_item(tree, hf_netlogon_computer_name, tvb, offset, 16, ENC_ASCII|ENC_NA);
    offset += 16;

    proto_tree_add_text(tree, tvb, offset, 4, "Time Created: unknown time format");
    offset+= 4;

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_serial_number, NULL);

    return offset;
}


/*
 * IDL long NetrAccountDeltas(
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
netlogon_dissect_netraccountdeltas_rqst(tvbuff_t *tvb, int offset,
                                        packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
netlogon_dissect_netraccountdeltas_reply(tvbuff_t *tvb, int offset,
                                         packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
 * IDL long NetrAccountSync(
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
netlogon_dissect_netraccountsync_rqst(tvbuff_t *tvb, int offset,
                                      packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
netlogon_dissect_netraccountsync_reply(tvbuff_t *tvb, int offset,
                                       packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
 * IDL long NetrGetDcName(
 * IDL    [in][ref][string] wchar_t *logon_server,
 * IDL    [in][unique][string] wchar_t *domainname,
 * IDL    [out][unique][string] wchar_t *dcname,
 * IDL };
 */
static int
netlogon_dissect_netrgetdcname_rqst(tvbuff_t *tvb, int offset,
                                    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
                                          NDR_POINTER_REF, "Server Handle", hf_netlogon_logonsrv_handle, 0);

    offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
                                          NDR_POINTER_UNIQUE, "Domain", hf_netlogon_domain_name, 0);

    return offset;
}
static int
netlogon_dissect_netrgetdcname_reply(tvbuff_t *tvb, int offset,
                                     packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
                                 guint8 *drep)
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
                                 guint8 *drep)
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
                                 guint8 *drep)
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
                                           guint8 *drep)
{
    guint32 level = 0;

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
 * IDL long NetrLogonControl(
 * IDL      [in][string][unique] wchar_t *logonserver,
 * IDL      [in] long function_code,
 * IDL      [in] long level,
 * IDL      [out][ref] CONTROL_QUERY_INFORMATION
 * IDL );
 */
static int
netlogon_dissect_netrlogoncontrol_rqst(tvbuff_t *tvb, int offset,
                                       packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
netlogon_dissect_netrlogoncontrol_reply(tvbuff_t *tvb, int offset,
                                        packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_CONTROL_QUERY_INFORMATION, NDR_POINTER_REF,
                                 "CONTROL_QUERY_INFORMATION:", -1);

    offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
                              hf_netlogon_dos_rc, NULL);

    return offset;
}


/*
 * IDL long NetrGetAnyDCName(
 * IDL    [in][unique][string] wchar_t *logon_server,
 * IDL    [in][unique][string] wchar_t *domainname,
 * IDL    [out][unique][string] wchar_t *dcname,
 * IDL };
 */
static int
netlogon_dissect_netrgetanydcname_rqst(tvbuff_t *tvb, int offset,
                                       packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
                                          NDR_POINTER_UNIQUE, "Server Handle",
                                          hf_netlogon_logonsrv_handle, 0);

    offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
                                          NDR_POINTER_UNIQUE, "Domain", hf_netlogon_domain_name, 0);

    return offset;
}
static int
netlogon_dissect_netrgetanydcname_reply(tvbuff_t *tvb, int offset,
                                        packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
                                          NDR_POINTER_UNIQUE, "Domain", hf_netlogon_dc_name, 0);

    offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
                              hf_netlogon_dos_rc, NULL);

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
                                          guint8 *drep)
{
    guint32 level = 0;

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_level, &level);

    ALIGN_TO_4_BYTES;
    switch(level){
    case 5:
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo,
                                              tree, drep, NDR_POINTER_UNIQUE, "Trusted Domain Name",
                                              hf_netlogon_TrustedDomainName_string, 0);
        break;
    case 6:
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo,
                                              tree, drep, NDR_POINTER_UNIQUE, "Trusted Domain Name",
                                              hf_netlogon_TrustedDomainName_string, 0);
        break;
    case 0xfffe:
        offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                    hf_netlogon_unknown_long, NULL);
        break;
    case 8:
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo,
                                              tree, drep, NDR_POINTER_UNIQUE, "UserName",
                                              hf_netlogon_UserName_string, 0);
        break;
    }

    return offset;
}


/*
 * IDL long NetrLogonControl2(
 * IDL      [in][string][unique] wchar_t *logonserver,
 * IDL      [in] long function_code,
 * IDL      [in] long level,
 * IDL      [in][ref] CONTROL_DATA_INFORMATION *data,
 * IDL      [out][ref] CONTROL_QUERY_INFORMATION *query
 * IDL );
 */
static int
netlogon_dissect_netrlogoncontrol2_rqst(tvbuff_t *tvb, int offset,
                                        packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
netlogon_dissect_netrlogoncontrol2_reply(tvbuff_t *tvb, int offset,
                                         packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 status;

    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_CONTROL_QUERY_INFORMATION, NDR_POINTER_REF,
                                 "CONTROL_QUERY_INFORMATION:", -1);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_netlogon_werr_rc, &status);

    if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown WERR error 0x%08x"));


    return offset;
}




/*
 * IDL long NetrDatabaseSync2(
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
netlogon_dissect_netrdatabasesync2_rqst(tvbuff_t *tvb, int offset,
                                        packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
netlogon_dissect_netrdatabasesync2_reply(tvbuff_t *tvb, int offset,
                                         packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
 * IDL long NetrDatabaseRedo(
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
netlogon_dissect_netrdatabaseredo_rqst(tvbuff_t *tvb, int offset,
                                       packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
netlogon_dissect_netrdatabaseredo_reply(tvbuff_t *tvb, int offset,
                                        packet_info *pinfo, proto_tree *tree, guint8 *drep)
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


/*
 * IDL long NetrLogonControl2Ex(
 * IDL      [in][string][unique] wchar_t *logonserver,
 * IDL      [in] long function_code,
 * IDL      [in] long level,
 * IDL      [in][ref] CONTROL_DATA_INFORMATION *data,
 * IDL      [out][ref] CONTROL_QUERY_INFORMATION *query
 * IDL );
 */
static int
netlogon_dissect_netrlogoncontrol2ex_rqst(tvbuff_t *tvb, int offset,
                                          packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
netlogon_dissect_netrlogoncontrol2ex_reply(tvbuff_t *tvb, int offset,
                                           packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_CONTROL_QUERY_INFORMATION, NDR_POINTER_REF,
                                 "CONTROL_QUERY_INFORMATION:", -1);

    offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
                              hf_netlogon_dos_rc, NULL);

    return offset;
}




static const value_string trust_type_vals[] = {
    { 1, "NT4 Domain" },
    { 2, "AD Domain" },
    { 3, "MIT Kerberos realm" },
    { 4, "DCE realm" },
    { 0, NULL }
};

#define DS_INET_ADDRESS         1
#define DS_NETBIOS_ADDRESS      2

static const value_string dc_address_types[] = {
    { DS_INET_ADDRESS,    "IP/DNS name" },
    { DS_NETBIOS_ADDRESS, "NetBIOS name" },
    { 0, NULL}
};


#define RQ_ROOT_FOREST              0x0001
#define RQ_DC_XFOREST               0x0002
#define RQ_RODC_DIF_DOMAIN          0x0004
#define RQ_NTLM_FROM_RODC           0x0008

#define DS_DOMAIN_IN_FOREST         0x0001
#define DS_DOMAIN_DIRECT_OUTBOUND   0x0002
#define DS_DOMAIN_TREE_ROOT         0x0004
#define DS_DOMAIN_PRIMARY           0x0008
#define DS_DOMAIN_NATIVE_MODE       0x0010
#define DS_DOMAIN_DIRECT_INBOUND    0x0020

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
                                    packet_info *pinfo, proto_tree *parent_tree, guint8 *drep)
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



static const true_false_string trust_attribs_non_transitive = {
    "This is a NON TRANSITIVE trust relation",
    "This is a normal trust"
};
static const true_false_string trust_attribs_uplevel_only = {
    "This is an UPLEVEL ONLY trust relation",
    "This is a normal trust"
};
static const true_false_string trust_attribs_quarantined_domain = {
    "This is a QUARANTINED DOMAIN (so don't expect lookupsids to work)",
    "This is a normal trust"
};
static const true_false_string trust_attribs_forest_transitive = {
    "This is a FOREST TRANSITIVE trust",
    "This is a normal trust"
};
static const true_false_string trust_attribs_cross_organization = {
    "This is a CROSS ORGANIZATION trust",
    "This is a normal trust"
};
static const true_false_string trust_attribs_within_forest = {
    "This is a WITHIN FOREST trust",
    "This is a normal trust"
};
static const true_false_string trust_attribs_treat_as_external = {
    "TREAT this trust AS an EXTERNAL trust",
    "This is a normal trust"
};

static int
netlogon_dissect_DOMAIN_TRUST_ATTRIBS(tvbuff_t *tvb, int offset,
                                      packet_info *pinfo, proto_tree *parent_tree, guint8 *drep)
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

    offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, drep,
                                hf_netlogon_trust_attribs, &mask);

    if(parent_tree){
        item = proto_tree_add_uint(parent_tree, hf_netlogon_trust_attribs,
                                   tvb, offset-4, 4, mask);
        tree = proto_item_add_subtree(item, ett_trust_attribs);
    }

    proto_tree_add_boolean(tree, hf_netlogon_trust_attribs_treat_as_external,
                           tvb, offset-4, 4, mask);
    proto_tree_add_boolean(tree, hf_netlogon_trust_attribs_within_forest,
                           tvb, offset-4, 4, mask);
    proto_tree_add_boolean(tree, hf_netlogon_trust_attribs_cross_organization,
                           tvb, offset-4, 4, mask);
    proto_tree_add_boolean(tree, hf_netlogon_trust_attribs_forest_transitive,
                           tvb, offset-4, 4, mask);
    proto_tree_add_boolean(tree, hf_netlogon_trust_attribs_quarantined_domain,
                           tvb, offset-4, 4, mask);
    proto_tree_add_boolean(tree, hf_netlogon_trust_attribs_uplevel_only,
                           tvb, offset-4, 4, mask);
    proto_tree_add_boolean(tree, hf_netlogon_trust_attribs_non_transitive,
                           tvb, offset-4, 4, mask);


    return offset;
}


#define DS_FORCE_REDISCOVERY            0x00000001
#define DS_DIRECTORY_SERVICE_REQUIRED   0x00000010
#define DS_DIRECTORY_SERVICE_PREFERRED  0x00000020
#define DS_GC_SERVER_REQUIRED           0x00000040
#define DS_PDC_REQUIRED                 0x00000080
#define DS_BACKGROUND_ONLY              0x00000100
#define DS_IP_REQUIRED                  0x00000200
#define DS_KDC_REQUIRED                 0x00000400
#define DS_TIMESERV_REQUIRED            0x00000800
#define DS_WRITABLE_REQUIRED            0x00001000
#define DS_GOOD_TIMESERV_PREFERRED      0x00002000
#define DS_AVOID_SELF                   0x00004000
#define DS_ONLY_LDAP_NEEDED             0x00008000
#define DS_IS_FLAT_NAME                 0x00010000
#define DS_IS_DNS_NAME                  0x00020000
#define DS_RETURN_DNS_NAME              0x40000000
#define DS_RETURN_FLAT_NAME             0x80000000

static const true_false_string get_dcname_request_flags_force_rediscovery = {
    "FORCE REDISCOVERY of any cached data",
    "You may return cached data"
};
static const true_false_string get_dcname_request_flags_directory_service_required = {
    "DIRECTORY SERVICE is REQUIRED on the server",
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
    "Only return cached data, even if it has expired",
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
    "the returned dc MUST be WRITEABLE",
    "a read-only dc may be returned"
};
static const true_false_string get_dcname_request_flags_good_timeserv_preferred = {
    "GOOD TIMESERV servers are PREFERRED",
    "we do NOT have a preference for good timeserv servers"
};
static const true_false_string get_dcname_request_flags_avoid_self = {
    "do NOT return self as dc; return someone else",
    "you may return yourSELF as the dc"
};
static const true_false_string get_dcname_request_flags_only_ldap_needed = {
    "we ONLY NEED LDAP; you don't have to return a dc",
    "we need a normal dc; an ldap only server will not do"
};
static const true_false_string get_dcname_request_flags_is_flat_name = {
    "the name we specify is a NetBIOS name",
    "the name we specify is NOT a NetBIOS name"
};
static const true_false_string get_dcname_request_flags_is_dns_name = {
    "the name we specify is a DNS name",
    "the name we specify is NOT a dns name"
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
                                          packet_info *pinfo, proto_tree *parent_tree, guint8 *drep)
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



#define DS_PDC_FLAG             0x00000001
#define DS_GC_FLAG              0x00000004
#define DS_LDAP_FLAG            0x00000008
#define DS_DS_FLAG              0x00000010
#define DS_KDC_FLAG             0x00000020
#define DS_TIMESERV_FLAG        0x00000040
#define DS_CLOSEST_FLAG         0x00000080
#define DS_WRITABLE_FLAG        0x00000100
#define DS_GOOD_TIMESERV_FLAG   0x00000200
#define DS_NDNC_FLAG            0x00000400
#define DS_DNS_CONTROLLER_FLAG  0x20000000
#define DS_DNS_DOMAIN_FLAG      0x40000000
#define DS_DNS_FOREST_FLAG      0x80000000

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
                          packet_info *pinfo, proto_tree *parent_tree, guint8 *drep)
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
        item = proto_tree_add_uint_format_value(parent_tree, hf_netlogon_dc_flags,
                                                tvb, offset-4, 4, mask, "0x%08x%s", mask, (mask==0x0000ffff)?"  PING (mask==0x0000ffff)":"");
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
                              guint8 *drep)
{
    dcerpc_info *di;

    di=pinfo->private_data;
    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                 di->hf_index, NULL);
    return offset;
}

#if 0
static int
netlogon_dissect_pointer_char(tvbuff_t *tvb, int offset,
                              packet_info *pinfo, proto_tree *tree,
                              guint8 *drep)
{
    dcerpc_info *di;

    di=pinfo->private_data;
    offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep,
                               di->hf_index, NULL);
    return offset;
}
#endif

static int
netlogon_dissect_UNICODE_MULTI_byte(tvbuff_t *tvb, int offset,
                                    packet_info *pinfo, proto_tree *tree,
                                    guint8 *drep)
{
    offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep,
                               hf_netlogon_unknown_char, NULL);

    return offset;
}

static int
netlogon_dissect_UNICODE_MULTI_array(tvbuff_t *tvb, int offset,
                                     packet_info *pinfo, proto_tree *tree,
                                     guint8 *drep)
{
    offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_UNICODE_MULTI_byte);

    return offset;
}

static int
netlogon_dissect_UNICODE_MULTI(tvbuff_t *tvb, int offset,
                               packet_info *pinfo, proto_tree *parent_tree,
                               guint8 *drep)
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

static int
netlogon_dissect_DOMAIN_CONTROLLER_INFO(tvbuff_t *tvb, int offset,
                                        packet_info *pinfo, proto_tree *parent_tree,
                                        guint8 *drep)
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
dissect_ndr_trust_extension(tvbuff_t *tvb, int offset,
                            packet_info *pinfo, proto_tree *tree,
                            guint8 *drep)
{
    guint32 len,max;
    dcerpc_info *di;

    di=pinfo->private_data;
    if(di->conformant_run){
        return offset;
    }
    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_trust_max, &max);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_trust_offset, NULL);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_trust_len, &len);

    if( max * 2 == 16 ) {
        offset = netlogon_dissect_DOMAIN_TRUST_FLAGS(tvb, offset, pinfo, tree, drep);

        offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                    hf_netlogon_trust_parent_index, NULL);

        offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                    hf_netlogon_trust_type, NULL);

        offset = netlogon_dissect_DOMAIN_TRUST_ATTRIBS(tvb, offset, pinfo, tree, drep);
    }
    /* else do something scream shout .... */

    return offset;
}

static int
netlogon_dissect_BLOB_array(tvbuff_t *tvb, int offset,
                            packet_info *pinfo, proto_tree *tree,
                            guint8 *drep)
{
    guint32 len;
    dcerpc_info *di;

    di=pinfo->private_data;
    if(di->conformant_run){
        return offset;
    }

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_blob_size, &len);

    proto_tree_add_item(tree, hf_netlogon_blob, tvb, offset, len,
                        ENC_NA);
    offset += len;

    return offset;
}

static int
dissect_ndr_ulongs_as_counted_string(tvbuff_t *tvb, int offset,
                                     packet_info *pinfo, proto_tree *tree,
                                     guint8 *drep, int hf_index)
{
    dcerpc_info *di = pinfo->private_data;
    guint16 len, size;
    gboolean add_subtree = TRUE; /* Manage room for evolution*/
    proto_item *item;
    proto_tree *subtree = tree;

    if (add_subtree) {

        item = proto_tree_add_text(
            tree, tvb, offset, 0, "%s",
            proto_registrar_get_name(hf_index));

        subtree = proto_item_add_subtree(item, ett_nt_counted_longs_as_string);
    }
    /* Structure starts with short, but is aligned for longs */
    ALIGN_TO_4_BYTES;

    if (di->conformant_run)
        return offset;

    /*
      struct {
      short len;
      short size;
      [size_is(size/2), length_is(len/2), ptr] unsigned short *string;
      } UNICODE_STRING;

    */

    offset = dissect_ndr_uint16(tvb, offset, pinfo, subtree, drep,
                                hf_nt_cs_len, &len);
    offset = dissect_ndr_uint16(tvb, offset, pinfo, subtree, drep,
                                hf_nt_cs_size, &size);
    offset = dissect_ndr_pointer_cb(tvb, offset, pinfo, subtree, drep,
                                    dissect_ndr_trust_extension, NDR_POINTER_UNIQUE,
                                    "Buffer", hf_index,NULL,NULL);
    return offset;
}

extern int
lsarpc_dissect_struct_dom_sid2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_, int unused1 _U_, int unused2 _U_);

static int
DomainInfo_sid_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
    offset = lsarpc_dissect_struct_dom_sid2(tvb,offset,pinfo,tree,drep,DomainInfo_sid,0);

    return offset;
}
static int
dissect_element_lsa_DnsDomainInfo_sid(tvbuff_t *tvb , int offset , packet_info *pinfo , proto_tree *tree , guint8 *drep )
{
    offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, DomainInfo_sid_, NDR_POINTER_UNIQUE, "Pointer to Sid (dom_sid2)",DnsDomainInfo_sid);

    return offset;
}
static int
dissect_element_lsa_DnsDomainInfo_domain_guid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep )
{
    offset = dissect_ndr_uuid_t(tvb, offset, pinfo, tree, drep, DnsDomainInfo_domain_guid, NULL);

    return offset;
}


static int dissect_part_DnsDomainInfo(tvbuff_t *tvb , int offset, packet_info *pinfo, proto_tree *tree , guint8 *drep,  int hf_index _U_, guint32 param _U_)
{

    offset = lsarpc_dissect_struct_lsa_StringLarge(tvb,offset,pinfo,tree,drep,DnsDomainInfo_name,0);

    offset = lsarpc_dissect_struct_lsa_StringLarge(tvb,offset,pinfo,tree,drep,DnsDomainInfo_dns_domain,0);

    offset = lsarpc_dissect_struct_lsa_StringLarge(tvb,offset,pinfo,tree,drep,DnsDomainInfo_dns_forest,0);

    offset = dissect_element_lsa_DnsDomainInfo_domain_guid(tvb, offset, pinfo, tree, drep);

    offset = dissect_element_lsa_DnsDomainInfo_sid(tvb, offset, pinfo, tree, drep);


    return offset;
}


static int
netlogon_dissect_ONE_DOMAIN_INFO(tvbuff_t *tvb, int offset,
                                 packet_info *pinfo, proto_tree *parent_tree,
                                 guint8 *drep)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;
    int old_offset=offset;

    if(parent_tree){
        item = proto_tree_add_text(parent_tree, tvb, offset, 0,
                                   "ONE_DOMAIN_INFO");
        tree = proto_item_add_subtree(item, ett_DOMAIN_TRUST_INFO);
    }
/*hf_netlogon_dnsdomaininfo*/
    offset = dissect_part_DnsDomainInfo(tvb, offset, pinfo, tree, drep, 0, 0);


    /* It is structed as a string but it's not ... it's 4 ulong */
    offset = dissect_ndr_ulongs_as_counted_string(tvb, offset, pinfo, tree, drep,
                                                  hf_netlogon_trust_extention);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_dummy_string2, 0);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_dummy_string3, 0);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_dummy_string4, 0);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_dummy1_long, NULL);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_dummy2_long, NULL);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_dummy3_long, NULL);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_dummy4_long, NULL);

    proto_item_set_len(item, offset-old_offset);
    return offset;
}

static int
netlogon_dissect_DOMAIN_TRUST_INFO(tvbuff_t *tvb, int offset,
                                   packet_info *pinfo, proto_tree *tree,
                                   guint8 *drep)
{
    offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_ONE_DOMAIN_INFO);

    return offset;
}


static int
netlogon_dissect_LSA_POLICY_INFO(tvbuff_t *tvb _U_, int offset,
                                 packet_info *pinfo _U_, proto_tree *tree _U_,
                                 guint8 *drep _U_ )
{
    proto_item *item=NULL;
    proto_tree *subtree=NULL;
    guint32 len;
    dcerpc_info *di;

    di=pinfo->private_data;
    if(di->conformant_run){
        return offset;
    }

    if(tree){
        item = proto_tree_add_text(tree, tvb, offset, 0,
                                   "LSA Policy");
        subtree = proto_item_add_subtree(item, ett_LSA_POLICY_INFO);
    }
    offset = dissect_ndr_uint32(tvb, offset, pinfo, subtree, drep,
                                hf_netlogon_lsapolicy_len, &len);

    offset = dissect_ndr_pointer(tvb, offset, pinfo, subtree, drep,
                                 netlogon_dissect_BLOB_array, NDR_POINTER_UNIQUE,
                                 "Pointer:", -1);

    return offset;
}




static int
netlogon_dissect_WORKSTATION_INFO(tvbuff_t *tvb , int offset ,
                                  packet_info *pinfo , proto_tree *tree ,
                                  guint8 *drep )
{
    /* This is not the good way to do it ... it stinks ...
     * but after half of a day fighting against wireshark and ndr ...
     * I decided to keep this hack ...
     * At least data are correctly displayed without invented ints ...
     */
    offset = netlogon_dissect_LSA_POLICY_INFO(tvb, offset,
                                              pinfo, tree, drep);

    offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
                                          NDR_POINTER_UNIQUE, "Workstation FQDN",
                                          hf_netlogon_workstation_fqdn, 0);

    offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
                                          NDR_POINTER_UNIQUE, "Workstation Site",
                                          hf_netlogon_workstation_site_name, 0);

    offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
                                          NDR_POINTER_UNIQUE, "Dummy 1", hf_netlogon_dummy_string, 0);

    offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
                                          NDR_POINTER_UNIQUE, "Dummy 2", hf_netlogon_dummy_string2, 0);

    offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
                                          NDR_POINTER_UNIQUE, "Dummy 3", hf_netlogon_dummy_string3, 0);

    offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
                                          NDR_POINTER_UNIQUE, "Dummy 4", hf_netlogon_dummy_string4, 0);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_os_version, 0);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_workstation_os, 0);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_dummy_string3, 0);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_dummy_string4, 0);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_workstation_flags, NULL);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_dummy2_long, NULL);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_dummy3_long, NULL);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_dummy4_long, NULL);
    return offset;
}

static int
netlogon_dissect_WORKSTATION_INFORMATION(tvbuff_t *tvb , int offset ,
                                         packet_info *pinfo , proto_tree *tree ,
                                         guint8 *drep ) {

    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_WORKSTATION_INFO, NDR_POINTER_UNIQUE,
                                 "WORKSTATION INFO", -1);
    return offset;
}

static int
netlogon_dissect_DOMAIN_INFO(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
    offset = netlogon_dissect_ONE_DOMAIN_INFO(tvb, offset, pinfo, tree, drep);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_num_trusts, NULL);

    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_DOMAIN_TRUST_INFO, NDR_POINTER_UNIQUE,
                                 "DOMAIN_TRUST_ARRAY: Trusted domains", -1);

    offset = netlogon_dissect_LSA_POLICY_INFO(tvb,offset,pinfo, tree,drep);

/*      offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
        hf_netlogon_num_trusts, NULL);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
        netlogon_dissect_DOMAIN_TRUST_INFO, NDR_POINTER_UNIQUE,
        "LSA Policy", -1);
*/
    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_ad_client_dns_name, 0);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_dummy_string2, 0);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_dummy_string3, 0);

    offset = dissect_ndr_counted_string(tvb, offset, pinfo, tree, drep,
                                        hf_netlogon_dummy_string4, 0);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_workstation_flags, NULL);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_supportedenctypes, NULL);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_dummy3_long, NULL);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_dummy4_long, NULL);

    return offset;
}


static int
netlogon_dissect_DOMAIN_INFORMATION(tvbuff_t *tvb, int offset,
                                    packet_info *pinfo, proto_tree *tree,
                                    guint8 *drep)
{
    guint32 level = 0;

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_level, &level);

    ALIGN_TO_4_BYTES;
    switch(level){
    case 1:
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                     netlogon_dissect_DOMAIN_INFO, NDR_POINTER_UNIQUE,
                                     "DOMAIN_INFO", -1);
        break;
    }

    return offset;
}

static int
netlogon_dissect_UNICODE_STRING_512(tvbuff_t *tvb, int offset,
                                    packet_info *pinfo, proto_tree *parent_tree,
                                    guint8 *drep)
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
                                  guint8 *drep)
{
    offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep,
                               hf_netlogon_unknown_char, NULL);

    return offset;
}

static int
netlogon_dissect_element_844_array(tvbuff_t *tvb, int offset,
                                   packet_info *pinfo, proto_tree *tree,
                                   guint8 *drep)
{
    offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_element_844_byte);

    return offset;
}

static int
netlogon_dissect_TYPE_50(tvbuff_t *tvb, int offset,
                         packet_info *pinfo, proto_tree *parent_tree,
                         guint8 *drep)
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
                             guint8 *drep)
{
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_TYPE_50, NDR_POINTER_UNIQUE,
                                 "TYPE_50 pointer: unknown_TYPE_50", -1);

    return offset;
}

static int
netlogon_dissect_DS_DOMAIN_TRUSTS(tvbuff_t *tvb, int offset,
                                  packet_info *pinfo, proto_tree *parent_tree, guint8 *drep)
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

    offset = netlogon_dissect_DOMAIN_TRUST_ATTRIBS(tvb, offset, pinfo, tree, drep);

    /* SID pointer */
    offset = dissect_ndr_nt_PSID(tvb, offset, pinfo, tree, drep);

    /* GUID */
    offset = dissect_nt_GUID(tvb, offset, pinfo, tree, drep);

    proto_item_set_len(item, offset-old_offset);
    return offset;
}

static int
netlogon_dissect_DS_DOMAIN_TRUSTS_ARRAY(tvbuff_t *tvb, int offset,
                                        packet_info *pinfo, proto_tree *tree,
                                        guint8 *drep)
{
    offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_DS_DOMAIN_TRUSTS);

    return offset;
}

static int
netlogon_dissect_element_865_byte(tvbuff_t *tvb, int offset,
                                  packet_info *pinfo, proto_tree *tree,
                                  guint8 *drep)
{
    offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep,
                               hf_netlogon_unknown_char, NULL);

    return offset;
}

static int
netlogon_dissect_element_865_array(tvbuff_t *tvb, int offset,
                                   packet_info *pinfo, proto_tree *tree,
                                   guint8 *drep)
{
    offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_element_865_byte);

    return offset;
}

static int
netlogon_dissect_element_866_byte(tvbuff_t *tvb, int offset,
                                  packet_info *pinfo, proto_tree *tree,
                                  guint8 *drep)
{
    offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep,
                               hf_netlogon_unknown_char, NULL);

    return offset;
}

static int
netlogon_dissect_element_866_array(tvbuff_t *tvb, int offset,
                                   packet_info *pinfo, proto_tree *tree,
                                   guint8 *drep)
{
    offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_element_866_byte);

    return offset;
}

static int
netlogon_dissect_TYPE_52(tvbuff_t *tvb, int offset,
                         packet_info *pinfo, proto_tree *parent_tree,
                         guint8 *drep)
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
                             guint8 *drep)
{
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_TYPE_52, NDR_POINTER_UNIQUE,
                                 "TYPE_52 pointer: unknown_TYPE_52", -1);
    return offset;
}


static int
netlogon_dissect_TYPE_44(tvbuff_t *tvb, int offset,
                         packet_info *pinfo, proto_tree *parent_tree,
                         guint8 *drep)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;
    int old_offset=offset;
    guint32 level = 0;

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
netlogon_dissect_WORKSTATION_BUFFER(tvbuff_t *tvb, int offset,
                                    packet_info *pinfo, proto_tree *tree,
                                    guint8 *drep)
{
    guint32 level;

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_level, &level);
    if (level == 2) {
        /* Specs are not very clear (as usual ...) it seems that the
         * structure in both case is a NETLOGON_WORKSTATION_INFO
         * but in this case only the LSA POLICY INFO will contain
         * something
         */
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                     netlogon_dissect_WORKSTATION_INFORMATION, NDR_POINTER_UNIQUE,
                                     "LSA POLICY INFO", -1);
    }
    else {
        if (level == 1) {
            offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                         netlogon_dissect_WORKSTATION_INFORMATION, NDR_POINTER_UNIQUE,
                                         "WORKSTATION INFORMATION", -1);}
    }
    return offset;
}

static int
netlogon_dissect_netrenumeratetrusteddomains_rqst(tvbuff_t *tvb, int offset,
                                                  packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
                                              pinfo, tree, drep);

    return offset;
}


static int
netlogon_dissect_netrenumeratetrusteddomains_reply(tvbuff_t *tvb, int offset,
                                                   packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_UNICODE_MULTI, NDR_POINTER_REF,
                                 "UNICODE_MULTI pointer: trust_dom_name_list", -1);

    offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
                              hf_netlogon_dos_rc, NULL);

    return offset;
}

static int
netlogon_dissect_dsrgetdcname_rqst(tvbuff_t *tvb, int offset,
                                   packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
netlogon_dissect_dsrgetdcname_reply(tvbuff_t *tvb, int offset,
                                    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_DOMAIN_CONTROLLER_INFO, NDR_POINTER_UNIQUE,
                                 "DOMAIN_CONTROLLER_INFO:", -1);

    offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
                              hf_netlogon_dos_rc, NULL);

    return offset;
}

static int
netlogon_dissect_netrlogondummyroutine1_rqst(tvbuff_t *tvb, int offset,
                                             packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
netlogon_dissect_netrlogondummyroutine1_reply(tvbuff_t *tvb, int offset,
                                              packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
netlogon_dissect_netrlogonsetservicebits_rqst(tvbuff_t *tvb, int offset,
                                              packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
netlogon_dissect_netrlogonsetservicebits_reply(tvbuff_t *tvb, int offset,
                                               packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
                              hf_netlogon_rc, NULL);

    return offset;
}


static int
netlogon_dissect_netrlogongettrustrid_rqst(tvbuff_t *tvb, int offset,
                                           packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
                                              pinfo, tree, drep);

    offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
                                          NDR_POINTER_UNIQUE, "unknown string",
                                          hf_netlogon_unknown_string, 0);

    return offset;
}


static int
netlogon_dissect_netrlogongettrustrid_reply(tvbuff_t *tvb, int offset,
                                            packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_pointer_long, NDR_POINTER_UNIQUE,
                                 "ULONG pointer: unknown_ULONG", hf_netlogon_unknown_long);

    offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
                              hf_netlogon_rc, NULL);

    return offset;
}


static int
netlogon_dissect_netrlogoncomputeserverdigest_rqst(tvbuff_t *tvb, int offset,
                                                   packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
                               packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    int i;

    for(i=0;i<16;i++){
        offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep,
                                   hf_netlogon_unknown_char, NULL);
    }

    return offset;
}

static int
netlogon_dissect_netrlogoncomputeserverdigest_reply(tvbuff_t *tvb, int offset,
                                                    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_BYTE_16_array, NDR_POINTER_UNIQUE,
                                 "BYTE pointer: unknown_BYTE", -1);

    offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
                              hf_netlogon_rc, NULL);

    return offset;
}

static int
netlogon_dissect_netrlogoncomputeclientdigest_rqst(tvbuff_t *tvb, int offset,
                                                   packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
netlogon_dissect_netrlogoncomputeclientdigest_reply(tvbuff_t *tvb, int offset,
                                                    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_BYTE_16_array, NDR_POINTER_UNIQUE,
                                 "BYTE pointer: unknown_BYTE", -1);

    offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
                              hf_netlogon_rc, NULL);

    return offset;
}
static int netlogon_dissect_neg_options(tvbuff_t *tvb,proto_tree *tree,guint32 flags,int offset)
{
    if (tree) {
        proto_tree *negotiate_flags_tree = NULL;
        proto_item *tf = NULL;
        tf = proto_tree_add_uint (tree,
                                  hf_netlogon_neg_flags,
                                  tvb, offset, 4,flags);
        negotiate_flags_tree = proto_item_add_subtree (tf,ett_authenticate_flags);

        /*proto_tree_add_boolean (negotiate_flags_tree,
          hf_netlogon_neg_flags_80000000,
          tvb, offset, 4, flags);*/
        proto_tree_add_boolean (negotiate_flags_tree,
                                hf_netlogon_neg_flags_40000000,
                                tvb, offset, 4, flags);
        proto_tree_add_boolean (negotiate_flags_tree,
                                hf_netlogon_neg_flags_20000000,
                                tvb, offset, 4, flags);
        /*
          proto_tree_add_boolean (negotiate_flags_tree,
          hf_netlogon_neg_flags_10000000,
          tvb, offset, 4, flags);
          proto_tree_add_boolean (negotiate_flags_tree,
          hf_netlogon_neg_flags_8000000,
          tvb, offset, 4, flags);
          proto_tree_add_boolean (negotiate_flags_tree,
          hf_netlogon_neg_flags_4000000,
          tvb, offset, 4, flags);
          proto_tree_add_boolean (negotiate_flags_tree,
          hf_netlogon_neg_flags_2000000,
          tvb, offset, 4, flags);
          proto_tree_add_boolean (negotiate_flags_tree,
          hf_netlogon_neg_flags_800000,
          tvb, offset, 4, flags);*/
        proto_tree_add_boolean (negotiate_flags_tree,
                                hf_netlogon_neg_flags_1000000,
                                tvb, offset, 4, flags);
        proto_tree_add_boolean (negotiate_flags_tree,
                                hf_netlogon_neg_flags_400000,
                                tvb, offset, 4, flags);
        proto_tree_add_boolean (negotiate_flags_tree,
                                hf_netlogon_neg_flags_200000,
                                tvb, offset, 4, flags);
        proto_tree_add_boolean (negotiate_flags_tree,
                                hf_netlogon_neg_flags_100000,
                                tvb, offset, 4, flags);
        proto_tree_add_boolean (negotiate_flags_tree,
                                hf_netlogon_neg_flags_80000,
                                tvb, offset, 4, flags);
        proto_tree_add_boolean (negotiate_flags_tree,
                                hf_netlogon_neg_flags_40000,
                                tvb, offset, 4, flags);
        proto_tree_add_boolean (negotiate_flags_tree,
                                hf_netlogon_neg_flags_20000,
                                tvb, offset, 4, flags);
        proto_tree_add_boolean (negotiate_flags_tree,
                                hf_netlogon_neg_flags_10000,
                                tvb, offset, 4, flags);
        proto_tree_add_boolean (negotiate_flags_tree,
                                hf_netlogon_neg_flags_8000,
                                tvb, offset, 4, flags);
        proto_tree_add_boolean (negotiate_flags_tree,
                                hf_netlogon_neg_flags_4000,
                                tvb, offset, 4, flags);
        proto_tree_add_boolean (negotiate_flags_tree,
                                hf_netlogon_neg_flags_2000,
                                tvb, offset, 4, flags);
        proto_tree_add_boolean (negotiate_flags_tree,
                                hf_netlogon_neg_flags_1000,
                                tvb, offset, 4, flags);
        proto_tree_add_boolean (negotiate_flags_tree,
                                hf_netlogon_neg_flags_800,
                                tvb, offset, 4, flags);
        proto_tree_add_boolean (negotiate_flags_tree,
                                hf_netlogon_neg_flags_400,
                                tvb, offset, 4, flags);
        proto_tree_add_boolean (negotiate_flags_tree,
                                hf_netlogon_neg_flags_200,
                                tvb, offset, 4, flags);
        proto_tree_add_boolean (negotiate_flags_tree,
                                hf_netlogon_neg_flags_100,
                                tvb, offset, 4, flags);
        proto_tree_add_boolean (negotiate_flags_tree,
                                hf_netlogon_neg_flags_80,
                                tvb, offset, 4, flags);
        proto_tree_add_boolean (negotiate_flags_tree,
                                hf_netlogon_neg_flags_40,
                                tvb, offset, 4, flags);
        proto_tree_add_boolean (negotiate_flags_tree,
                                hf_netlogon_neg_flags_20,
                                tvb, offset, 4, flags);
        proto_tree_add_boolean (negotiate_flags_tree,
                                hf_netlogon_neg_flags_10,
                                tvb, offset, 4, flags);
        proto_tree_add_boolean (negotiate_flags_tree,
                                hf_netlogon_neg_flags_8,
                                tvb, offset, 4, flags);
        proto_tree_add_boolean (negotiate_flags_tree,
                                hf_netlogon_neg_flags_4,
                                tvb, offset, 4, flags);
        proto_tree_add_boolean (negotiate_flags_tree,
                                hf_netlogon_neg_flags_2,
                                tvb, offset, 4, flags);
        proto_tree_add_boolean (negotiate_flags_tree,
                                hf_netlogon_neg_flags_1,
                                tvb, offset, 4, flags);
    }
    return 0;
}

static int
netlogon_dissect_netrserverauthenticate3_rqst(tvbuff_t *tvb, int offset,
                                              packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint32 flags;
    offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
                                              pinfo, tree, drep);
    offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
                                          NDR_POINTER_REF, "Acct Name", hf_netlogon_acct_name, 0);

    offset = netlogon_dissect_NETLOGON_SECURE_CHANNEL_TYPE(tvb, offset,
                                                           pinfo, tree, drep);

    offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
                                          NDR_POINTER_REF, "Computer Name", hf_netlogon_computer_name, 0);

    offset = dissect_dcerpc_8bytes(tvb, offset, pinfo, tree, drep,
                                   hf_client_credential, NULL);
#if 0
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_CREDENTIAL, NDR_POINTER_REF,
                                 "Client Challenge", -1);
#endif

#if 0
    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_neg_flags, NULL);
#endif
    ALIGN_TO_4_BYTES;

    flags = tvb_get_letohl (tvb, offset);
    netlogon_dissect_neg_options(tvb,tree,flags,offset);
    seen.isseen = FALSE;
    seen.num = 0;
    offset +=4;
    return offset;
}

/*
 * IDL long NetrServerAuthenticate2(
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
netlogon_dissect_netrserverauthenticate2_rqst(tvbuff_t *tvb, int offset,
                                              packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    return netlogon_dissect_netrserverauthenticate3_rqst(tvb,offset,pinfo,tree,drep);
}

#ifdef HAVE_KERBEROS
static void str_to_unicode(const char *nt_password, char *nt_password_unicode)
{
    size_t password_len = 0;
    size_t i;

    password_len = strlen(nt_password);
    if(nt_password_unicode != NULL)
    {
        for(i=0;i<(password_len);i++)
        {
            nt_password_unicode[i*2]=nt_password[i];
            nt_password_unicode[i*2+1]=0;
        }
        nt_password_unicode[2*password_len]='\0';
    }
}
#endif

static guint32 get_keytab_as_list(md4_pass **p_pass_list,const char* ntlm_pass _U_)
{
#ifdef HAVE_KERBEROS
    enc_key_t *ek;
    md4_pass* pass_list;
    md4_pass ntlm_pass_hash;
    int i = 0;
    guint32 nb_pass = 0;
    char ntlm_pass_unicode[258];
    int add_ntlm = 0;
    int password_len;

    if(!krb_decrypt){
        *p_pass_list=NULL;
        return 0;
    }
    read_keytab_file_from_preferences();
    memset(ntlm_pass_hash.md4,0,sizeof(md4_pass));

    for(ek=enc_key_list;ek;ek=ek->next){
        if( ek->keylength == 16 ) {
            nb_pass++;
        }
    }

    if (ntlm_pass[0] != '\0' && ( strlen(ntlm_pass) < 129 )) {
        nb_pass++;
        debugprintf("Password: %s\n",ntlm_pass);
        password_len = strlen(ntlm_pass);
        str_to_unicode(ntlm_pass,ntlm_pass_unicode);
        crypt_md4(ntlm_pass_hash.md4,ntlm_pass_unicode,password_len*2);
        printnbyte(ntlm_pass_hash.md4,16,"Hash of the NT pass: ","\n");
        add_ntlm = 0;
    }

    *p_pass_list = (md4_pass *)ep_alloc(nb_pass*sizeof(md4_pass));
    pass_list=*p_pass_list;
    if(add_ntlm) {
        memcpy(pass_list[0].md4,&(ntlm_pass_hash.md4),sizeof(md4_pass));
        i++;
    }

    for(ek=enc_key_list;ek;ek=ek->next){
        if( ek->keylength == 16 ) {
            memcpy(pass_list[i].md4,ek->keyvalue,16);
            i++;
        }
    }
    return nb_pass;
#else
    *p_pass_list = NULL;
    return 0;
#endif
}

static int
netlogon_dissect_netrserverauthenticate23_reply(tvbuff_t *tvb, int offset,
                                                packet_info *pinfo, proto_tree *tree, guint8 *drep, int version3)
{
    guint32 flags;
    netlogon_auth_vars *vars;
    netlogon_auth_key key;
    guint64 server_cred;

    offset = dissect_dcerpc_8bytes(tvb, offset, pinfo, tree, drep,
                                   hf_server_credential, &server_cred);

    flags = tvb_get_letohl (tvb, offset);
    netlogon_dissect_neg_options(tvb,tree,flags,offset);
    offset +=4;

    ALIGN_TO_4_BYTES;
    if(version3) {
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, tree, drep,
                                       hf_server_rid, NULL);
    }
    offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
                              hf_netlogon_rc, NULL);

    generate_hash_key(pinfo, 1 , &key, NULL);

    vars = (netlogon_auth_vars *)g_hash_table_lookup(netlogon_auths, &key);
    if(vars != NULL) {
        debugprintf("Found some vars (ie. server/client challenges), let's see if I can get a session key\n");
        debugprintf("Context Id = %d \n", pinfo->dcectxid);
        while(vars != NULL && vars->next_start != -1 && vars->next_start < (int) pinfo->fd->num ) {
            debugprintf("looping auth reply...\n");
            vars = vars->next;
        }
        if(vars == NULL ) {
            debugprintf("Something strange happened while searching for authenticate_reply\n");
        }
        else {
            md4_pass *pass_list=NULL;
            guint32 list_size = 0;
            guint8 session_key[16];
            md4_pass password;
            int found = 0;
            unsigned int i = 0;

            vars->flags = flags;
            vars->can_decrypt = FALSE;
            list_size = get_keytab_as_list(&pass_list,gbl_nt_password);
            debugprintf("Found %d passwords \n",list_size);
            if( flags & NETLOGON_FLAG_STRONGKEY ) {
                guint8 zeros[4];
                guint8 md5[16];
                md5_state_t md5state;
                guint8 buf[8];
                guint64 calculated_cred;


                memset(zeros,0,4);
                md5_init(&md5state);
                md5_append(&md5state,zeros,4);
                md5_append(&md5state,(unsigned char*)&vars->client_challenge,8);
                md5_append(&md5state,(unsigned char*)&vars->server_challenge,8);
                md5_finish(&md5state,md5);
                printnbyte(md5,8,"MD5:","\n");
                printnbyte((guint8*)&vars->client_challenge,8,"Client challenge:","\n");
                printnbyte((guint8*)&vars->server_challenge,8,"Server challenge:","\n");
                printnbyte((guint8*)&server_cred,8,"Server creds:","\n");
                for(i=0;i<list_size;i++)
                {
                    password = pass_list[i];
                    md5_hmac(md5,16,(guint8*) &password,16,session_key);
                    crypt_des_ecb(buf,(unsigned char*)&vars->server_challenge,session_key,1);
                    crypt_des_ecb((unsigned char*)&calculated_cred,buf,session_key+7,1);
#if 0
                    printnbyte((guint8*)&calculated_cred,8,"Calculated creds:","\n");
#endif
                    if(calculated_cred==server_cred) {
                        found = 1;
                        break;
                    }
                }
            }
            else if( flags&NETLOGON_FLAG_USEAES)
            {
                /*Not implemented*/
                debugprintf("AES not supported yet\n");
                memset(session_key,0,16);
            }
            else
            {
                /*Not implemented*/
                debugprintf("Else case not implemented\n");
                memset(session_key,0,16);
            }
            if(found) {
                memcpy(&vars->session_key,session_key,16);
                debugprintf("Found the good session key !\n");
            }
            else {
                debugprintf("Session key not found !\n");
                memset(&vars->session_key,0,16);
            }
        }
    } else {
        printnbyte((guint8*)&vars->session_key, 16, "Session key:","\n");
    }

    return offset;
}

static int
netlogon_dissect_netrserverauthenticate3_reply(tvbuff_t *tvb, int offset,
                                               packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    return netlogon_dissect_netrserverauthenticate23_reply(tvb,offset,pinfo,tree,drep,1);
}

static int
netlogon_dissect_netrserverauthenticate2_reply(tvbuff_t *tvb, int offset,
                                               packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    return netlogon_dissect_netrserverauthenticate23_reply(tvb,offset,pinfo,tree,drep,0);
}


static int
netlogon_dissect_dsrgetdcnameex_rqst(tvbuff_t *tvb, int offset,
                                     packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
netlogon_dissect_dsrgetdcnameex_reply(tvbuff_t *tvb, int offset,
                                      packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
                                     packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
                                              pinfo, tree, drep);

    return offset;
}


static int
netlogon_dissect_dsrgetsitename_reply(tvbuff_t *tvb, int offset,
                                      packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

    /* XXX hmmm this does not really look like a UNIQUE pointer but
       will do for now.   I think it is really a 32bit integer followed by
       a REF pointer to a unicode string */
    offset = dissect_ndr_pointer_cb(tvb, offset, pinfo, tree, drep,
                                    dissect_ndr_wchar_cvstring, NDR_POINTER_UNIQUE, "Site Name",
                                    hf_netlogon_site_name, cb_wstr_postprocess,
                                    GINT_TO_POINTER(CB_STR_COL_INFO | 1));

    offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
                              hf_netlogon_dos_rc, NULL);

    return offset;
}

static int
netlogon_dissect_netrlogongetdomaininfo_rqst(tvbuff_t *tvb, int offset,
                                             packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    /* Unlike the other NETLOGON RPCs, this is not a unique pointer. */
    offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
                                          NDR_POINTER_REF, "Server Handle", hf_netlogon_computer_name, 0);
    offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
                                          NDR_POINTER_UNIQUE, "Computer Name",
                                          hf_netlogon_computer_name, 0);

    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
                                 "AUTHENTICATOR: client", -1);

    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
                                 "AUTHENTICATOR: return_authenticator", -1);
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_WORKSTATION_BUFFER, NDR_POINTER_REF,
                                 "WORKSTATION_BUFFER", -1);
    return offset;
}


static int
netlogon_dissect_netrlogongetdomaininfo_reply(tvbuff_t *tvb, int offset,
                                              packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_AUTHENTICATOR, NDR_POINTER_REF,
                                 "AUTHENTICATOR: return_authenticator", -1);

    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_DOMAIN_INFORMATION, NDR_POINTER_REF,
                                 "DOMAIN_INFORMATION", -1);

    offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
                              hf_netlogon_rc, NULL);

    return offset;
}

static int
netlogon_dissect_netrserverpasswordset2_rqst(tvbuff_t *tvb, int offset,
                                             packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
netlogon_dissect_netrserverpasswordset2_reply(tvbuff_t *tvb, int offset,
                                              packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_AUTHENTICATOR, NDR_POINTER_UNIQUE,
                                 "AUTHENTICATOR: return_authenticator", -1);

    offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
                              hf_netlogon_rc, NULL);

    return offset;
}

static int
netlogon_dissect_netrserverpasswordget_rqst(tvbuff_t *tvb, int offset,
                                            packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
netlogon_dissect_netrserverpasswordget_reply(tvbuff_t *tvb, int offset,
                                             packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
netlogon_dissect_netrlogonsendtosam_rqst(tvbuff_t *tvb, int offset,
                                         packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
netlogon_dissect_netrlogonsendtosam_reply(tvbuff_t *tvb, int offset,
                                          packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_AUTHENTICATOR, NDR_POINTER_UNIQUE,
                                 "AUTHENTICATOR: return_authenticator", -1);

    offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
                              hf_netlogon_rc, NULL);

    return offset;
}

static int
netlogon_dissect_dsraddresstositenamesw_rqst(tvbuff_t *tvb, int offset,
                                             packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
netlogon_dissect_dsraddresstositenamesw_reply(tvbuff_t *tvb, int offset,
                                              packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_TYPE_50_ptr, NDR_POINTER_UNIQUE,
                                 "TYPE_50** pointer: unknown_TYPE_50", -1);

    offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
                              hf_netlogon_rc, NULL);

    return offset;
}

static int
netlogon_dissect_dsrgetdcnameex2_rqst(tvbuff_t *tvb, int offset,
                                      packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
                                              pinfo, tree, drep);

    offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
                                          NDR_POINTER_UNIQUE, "Client Account",
                                          hf_netlogon_acct_name, 0);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_unknown_long, NULL);

    offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
                                          NDR_POINTER_UNIQUE, "Client Account",
                                          hf_netlogon_logon_dom, 0);

    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 dissect_nt_GUID, NDR_POINTER_UNIQUE,
                                 "Domain GUID:", -1);

    offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
                                          NDR_POINTER_UNIQUE, "Client Site",
                                          hf_netlogon_site_name, 0);

    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_unknown_long, NULL);

    return offset;
}


static int
netlogon_dissect_dsrgetdcnameex2_reply(tvbuff_t *tvb, int offset,
                                       packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_DOMAIN_CONTROLLER_INFO, NDR_POINTER_UNIQUE,
                                 "DOMAIN_CONTROLLER_INFO:", -1);

    offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
                              hf_netlogon_dos_rc, NULL);

    return offset;
}

static int
netlogon_dissect_netrlogongettimeserviceparentdomain_rqst(tvbuff_t *tvb, int offset,
                                                          packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
                                              pinfo, tree, drep);

    return offset;
}


static int
netlogon_dissect_netrlogongettimeserviceparentdomain_reply(tvbuff_t *tvb, int offset,
                                                           packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
netlogon_dissect_netrenumeratetrusteddomainsex_rqst(tvbuff_t *tvb, int offset,
                                                    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
                                              pinfo, tree, drep);

    return offset;
}

static int
netlogon_dissect_netrenumeratetrusteddomainsex_reply(tvbuff_t *tvb, int offset,
                                                     packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
netlogon_dissect_dsraddresstositenamesexw_rqst(tvbuff_t *tvb, int offset,
                                               packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
netlogon_dissect_dsraddresstositenamesexw_reply(tvbuff_t *tvb, int offset,
                                                packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_TYPE_52_ptr, NDR_POINTER_UNIQUE,
                                 "TYPE_52 pointer: unknown_TYPE_52", -1);

    offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
                              hf_netlogon_rc, NULL);

    return offset;
}


static int
netlogon_dissect_site_name_item(tvbuff_t *tvb, int offset,
                                packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = dissect_ndr_counted_string_cb(
        tvb, offset, pinfo, tree, drep, hf_netlogon_site_name,
        cb_wstr_postprocess,
        GINT_TO_POINTER(CB_STR_COL_INFO | 1));

    return offset;
}
static int
netlogon_dissect_site_name_array(tvbuff_t *tvb, int offset,
                                 packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_site_name_item);

    return offset;
}

static int
netlogon_dissect_site_names(tvbuff_t *tvb, int offset,
                            packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_count, NULL);

    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_site_name_array, NDR_POINTER_UNIQUE,
                                 "Site name array", -1);

    return offset;
}

static int
netlogon_dissect_dsrgetdcsitecoveragew_rqst(tvbuff_t *tvb, int offset,
                                            packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
                                              pinfo, tree, drep);

    return offset;
}


static int
netlogon_dissect_dsrgetdcsitecoveragew_reply(tvbuff_t *tvb, int offset,
                                             packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_site_names, NDR_POINTER_UNIQUE,
                                 "Site names", -1);

    offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
                              hf_netlogon_rc, NULL);

    return offset;
}

static int
netlogon_dissect_netrlogonsamlogonex_rqst(tvbuff_t *tvb, int offset,
                                          packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

    offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
                                          NDR_POINTER_UNIQUE, "LogonServer",
                                          hf_netlogon_computer_name, 0);
    offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
                                          NDR_POINTER_UNIQUE, "Computer Name",
                                          hf_netlogon_computer_name, 0);
    offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_level16, NULL);
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_LEVEL, NDR_POINTER_REF,
                                 "LEVEL: LogonLevel", -1);

    offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_validation_level, NULL);

    offset = netlogon_dissect_EXTRA_FLAGS(tvb, offset, pinfo, tree, drep);

#if 0
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
#endif
    return offset;
}


static int
netlogon_dissect_netrlogonsamlogonex_reply(tvbuff_t *tvb, int offset,
                                           packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_VALIDATION, NDR_POINTER_REF,
                                 "VALIDATION:", -1);

    offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, drep,
                               hf_netlogon_authoritative, NULL);

    offset = netlogon_dissect_EXTRA_FLAGS(tvb, offset, pinfo, tree, drep);

    offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
                              hf_netlogon_rc, NULL);
#if 0
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
#endif
    return offset;
}


static int
netlogon_dissect_dsrenumeratedomaintrusts_rqst(tvbuff_t *tvb, int offset,
                                               packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = netlogon_dissect_LOGONSRV_HANDLE(tvb, offset,
                                              pinfo, tree, drep);

    offset = netlogon_dissect_DOMAIN_TRUST_FLAGS(tvb, offset, pinfo, tree, drep);

    return offset;
}


static int
netlogon_dissect_dsrenumeratedomaintrusts_reply(tvbuff_t *tvb, int offset,
                                                packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
                                hf_netlogon_entries, NULL);

    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                                 netlogon_dissect_DS_DOMAIN_TRUSTS_ARRAY, NDR_POINTER_UNIQUE,
                                 "DS_DOMAIN_TRUSTS_ARRAY:", -1);

    offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
                              hf_netlogon_dos_rc, NULL);

    return offset;
}

static int
netlogon_dissect_dsrderegisterdnshostrecords_rqst(tvbuff_t *tvb, int offset,
                                                  packet_info *pinfo, proto_tree *tree, guint8 *drep)
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
                                          NDR_POINTER_REF, "dns_host", hf_netlogon_dns_host, 0);

    return offset;
}


static int
netlogon_dissect_dsrderegisterdnshostrecords_reply(tvbuff_t *tvb, int offset,
                                                   packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
                              hf_netlogon_rc, NULL);

    return offset;
}

/* Dissect secure channel stuff */

static int hf_netlogon_secchan_nl_message_type = -1;
static int hf_netlogon_secchan_nl_message_flags = -1;
static int hf_netlogon_secchan_nl_message_flags_nb_domain = -1;
static int hf_netlogon_secchan_nl_message_flags_nb_host = -1;
static int hf_netlogon_secchan_nl_message_flags_dns_domain = -1;
static int hf_netlogon_secchan_nl_message_flags_dns_host = -1;
static int hf_netlogon_secchan_nl_message_flags_nb_host_utf8 = -1;
static int hf_netlogon_secchan_nl_nb_domain = -1;
static int hf_netlogon_secchan_nl_nb_host = -1;
static int hf_netlogon_secchan_nl_dns_domain = -1;
static int hf_netlogon_secchan_nl_dns_host = -1;
static int hf_netlogon_secchan_nl_nb_host_utf8 = -1;

static gint ett_secchan_verf = -1;
static gint ett_secchan_nl_auth_message = -1;
static gint ett_secchan_nl_auth_message_flags = -1;

static const value_string nl_auth_types[] = {
    { 0x00000000,         "Request"},
    { 0x00000001,         "Response"},
    { 0, NULL }
};


/* MS-NRPC : 2.2.1.3.1 NL_AUTH_MESSAGE */
static int dissect_secchan_nl_auth_message(tvbuff_t *tvb, int offset,
                                           packet_info *pinfo,
                                           proto_tree *tree, guint8 *drep)
{
    proto_item *item = NULL;
    proto_tree *subtree = NULL;
    guint32 messagetype, messageflags;
    static const int *flag_fields[] = {
        &hf_netlogon_secchan_nl_message_flags_nb_domain,
        &hf_netlogon_secchan_nl_message_flags_nb_host,
        &hf_netlogon_secchan_nl_message_flags_dns_domain,
        &hf_netlogon_secchan_nl_message_flags_dns_host,
        &hf_netlogon_secchan_nl_message_flags_nb_host_utf8,
        NULL
    };
    int len;

    if (tree) {
        item = proto_tree_add_text(
            tree, tvb, offset, -1,
            "Secure Channel NL_AUTH_MESSAGE");
        subtree = proto_item_add_subtree(
            item, ett_secchan_nl_auth_message);
    }

    /* We can't use the NDR routines as the DCERPC call data hasn't
       been initialised since we haven't made a DCERPC call yet, just
       a bind request. */

    /* Type */
    offset = dissect_dcerpc_uint32(
        tvb, offset, pinfo, subtree, drep,
        hf_netlogon_secchan_nl_message_type, &messagetype);

    /* Flags */
    proto_tree_add_bitmask(subtree, tvb, offset, hf_netlogon_secchan_nl_message_flags, ett_secchan_nl_auth_message_flags, flag_fields, (drep[0] & DREP_LITTLE_ENDIAN));
    messageflags = ((drep[0] & DREP_LITTLE_ENDIAN)
                    ? tvb_get_letohl (tvb, offset)
                    : tvb_get_ntohl (tvb, offset));
    offset += 4;


    /* Buffer */
    /* netbios domain name */
    if (messageflags&0x00000001) {
        len = tvb_strsize(tvb, offset);
        proto_tree_add_item(subtree, hf_netlogon_secchan_nl_nb_domain, tvb, offset, len, ENC_ASCII|ENC_NA);
        offset += len;
    }

    /* netbios host name */
    if (messageflags&0x00000002) {
        len = tvb_strsize(tvb, offset);
        proto_tree_add_item(subtree, hf_netlogon_secchan_nl_nb_host, tvb, offset, len, ENC_ASCII|ENC_NA);
        offset += len;
    }

    /* DNS domain name */
    if (messageflags&0x00000004) {
        int old_offset=offset;
        char str[256];

        offset=dissect_mscldap_string(tvb, offset, str, 255, FALSE);
        proto_tree_add_string(subtree, hf_netlogon_secchan_nl_dns_domain, tvb, old_offset, offset-old_offset, str);
    }

    /* DNS host name */
    if (messageflags&0x00000008) {
        int old_offset=offset;
        char str[256];

        offset=dissect_mscldap_string(tvb, offset, str, 255, FALSE);
        proto_tree_add_string(subtree, hf_netlogon_secchan_nl_dns_host, tvb, old_offset, offset-old_offset, str);
    }

    /* NetBios host name (UTF8) */
    if (messageflags&0x00000010) {
        int old_offset=offset;
        char str[256];

        offset=dissect_mscldap_string(tvb, offset, str, 255, FALSE);
        proto_tree_add_string(subtree, hf_netlogon_secchan_nl_nb_host_utf8, tvb, old_offset, offset-old_offset, str);
    }


    return offset;
}

/* Subdissectors */

static dcerpc_sub_dissector dcerpc_netlogon_dissectors[] = {
    { NETLOGON_NETRLOGONUASLOGON, "NetrLogonUasLogon",
      netlogon_dissect_netrlogonuaslogon_rqst,
      netlogon_dissect_netrlogonuaslogon_reply },
    { NETLOGON_NETRLOGONUASLOGOFF, "NetrLogonUasLogoff",
      netlogon_dissect_netrlogonuaslogoff_rqst,
      netlogon_dissect_netrlogonuaslogoff_reply },
    { NETLOGON_NETRLOGONSAMLOGON, "NetrLogonSamLogon",
      netlogon_dissect_netrlogonsamlogon_rqst,
      netlogon_dissect_netrlogonsamlogon_reply },
    { NETLOGON_NETRLOGONSAMLOGOFF, "NetrLogonSamLogoff",
      netlogon_dissect_netrlogonsamlogoff_rqst,
      netlogon_dissect_netrlogonsamlogoff_reply },
    { NETLOGON_NETRSERVERREQCHALLENGE, "NetrServerReqChallenge",
      netlogon_dissect_netrserverreqchallenge_rqst,
      netlogon_dissect_netrserverreqchallenge_reply },
    { NETLOGON_NETRSERVERAUTHENTICATE, "NetrServerAuthenticate",
      netlogon_dissect_netrserverauthenticate_rqst,
      netlogon_dissect_netrserverauthenticate_reply },
    { NETLOGON_NETRSERVERPASSWORDSET, "NetrServerPasswordSet",
      netlogon_dissect_netrserverpasswordset_rqst,
      netlogon_dissect_netrserverpasswordset_reply },
    { NETLOGON_NETRDATABASEDELTAS, "NetrDatabaseDeltas",
      netlogon_dissect_netrdatabasedeltas_rqst,
      netlogon_dissect_netrdatabasedeltas_reply },
    { NETLOGON_NETRDATABASESYNC, "NetrDatabaseSync",
      netlogon_dissect_netrdatabasesync_rqst,
      netlogon_dissect_netrdatabasesync_reply },
    { NETLOGON_NETRACCOUNTDELTAS, "NetrAccountDeltas",
      netlogon_dissect_netraccountdeltas_rqst,
      netlogon_dissect_netraccountdeltas_reply },
    { NETLOGON_NETRACCOUNTSYNC, "NetrAccountSync",
      netlogon_dissect_netraccountsync_rqst,
      netlogon_dissect_netraccountsync_reply },
    { NETLOGON_NETRGETDCNAME, "NetrGetDCName",
      netlogon_dissect_netrgetdcname_rqst,
      netlogon_dissect_netrgetdcname_reply },
    { NETLOGON_NETRLOGONCONTROL, "NetrLogonControl",
      netlogon_dissect_netrlogoncontrol_rqst,
      netlogon_dissect_netrlogoncontrol_reply },
    { NETLOGON_NETRGETANYDCNAME, "NetrGetAnyDCName",
      netlogon_dissect_netrgetanydcname_rqst,
      netlogon_dissect_netrgetanydcname_reply },
    { NETLOGON_NETRLOGONCONTROL2, "NetrLogonControl2",
      netlogon_dissect_netrlogoncontrol2_rqst,
      netlogon_dissect_netrlogoncontrol2_reply },
    { NETLOGON_NETRSERVERAUTHENTICATE2, "NetrServerAuthenticate2",
      netlogon_dissect_netrserverauthenticate2_rqst,
      netlogon_dissect_netrserverauthenticate2_reply },
    { NETLOGON_NETRDATABASESYNC2, "NetrDatabaseSync2",
      netlogon_dissect_netrdatabasesync2_rqst,
      netlogon_dissect_netrdatabasesync2_reply },
    { NETLOGON_NETRDATABASEREDO, "NetrDatabaseRedo",
      netlogon_dissect_netrdatabaseredo_rqst,
      netlogon_dissect_netrdatabaseredo_reply },
    { NETLOGON_NETRLOGONCONTROL2EX, "NetrLogonControl2Ex",
      netlogon_dissect_netrlogoncontrol2ex_rqst,
      netlogon_dissect_netrlogoncontrol2ex_reply },
    { NETLOGON_NETRENUMERATETRUSTEDDOMAINS, "NetrEnumerateTrustedDomains",
      netlogon_dissect_netrenumeratetrusteddomains_rqst,
      netlogon_dissect_netrenumeratetrusteddomains_reply },
    { NETLOGON_DSRGETDCNAME, "DsrGetDcName",
      netlogon_dissect_dsrgetdcname_rqst,
      netlogon_dissect_dsrgetdcname_reply },
    { NETLOGON_NETRLOGONDUMMYROUTINE1, "NetrLogonDummyRoutine1",
      netlogon_dissect_netrlogondummyroutine1_rqst,
      netlogon_dissect_netrlogondummyroutine1_reply },
    { NETLOGON_NETRLOGONSETSERVICEBITS, "NetrLogonSetServiceBits",
      netlogon_dissect_netrlogonsetservicebits_rqst,
      netlogon_dissect_netrlogonsetservicebits_reply },
    { NETLOGON_NETRLOGONGETTRUSTRID, "NetrLogonGetTrustRid",
      netlogon_dissect_netrlogongettrustrid_rqst,
      netlogon_dissect_netrlogongettrustrid_reply },
    { NETLOGON_NETRLOGONCOMPUTESERVERDIGEST, "NetrLogonComputeServerDigest",
      netlogon_dissect_netrlogoncomputeserverdigest_rqst,
      netlogon_dissect_netrlogoncomputeserverdigest_reply },
    { NETLOGON_NETRLOGONCOMPUTECLIENTDIGEST, "NetrLogonComputeClientDigest",
      netlogon_dissect_netrlogoncomputeclientdigest_rqst,
      netlogon_dissect_netrlogoncomputeclientdigest_reply },
    { NETLOGON_NETRSERVERAUTHENTICATE3, "NetrServerAuthenticate3",
      netlogon_dissect_netrserverauthenticate3_rqst,
      netlogon_dissect_netrserverauthenticate3_reply },
    { NETLOGON_DSRGETDCNAMEX, "DsrGetDcNameEx",
      netlogon_dissect_dsrgetdcnameex_rqst,
      netlogon_dissect_dsrgetdcnameex_reply },
    { NETLOGON_DSRGETSITENAME, "DsrGetSiteName",
      netlogon_dissect_dsrgetsitename_rqst,
      netlogon_dissect_dsrgetsitename_reply },
    { NETLOGON_NETRLOGONGETDOMAININFO, "NetrLogonGetDomainInfo",
      netlogon_dissect_netrlogongetdomaininfo_rqst,
      netlogon_dissect_netrlogongetdomaininfo_reply },
    { NETLOGON_NETRSERVERPASSWORDSET2, "NetrServerPasswordSet2",
      netlogon_dissect_netrserverpasswordset2_rqst,
      netlogon_dissect_netrserverpasswordset2_reply },
    { NETLOGON_NETRSERVERPASSWORDGET, "NetrServerPasswordGet",
      netlogon_dissect_netrserverpasswordget_rqst,
      netlogon_dissect_netrserverpasswordget_reply },
    { NETLOGON_NETRLOGONSENDTOSAM, "NetrLogonSendToSam",
      netlogon_dissect_netrlogonsendtosam_rqst,
      netlogon_dissect_netrlogonsendtosam_reply },
    { NETLOGON_DSRADDRESSTOSITENAMESW, "DsrAddressToSiteNamesW",
      netlogon_dissect_dsraddresstositenamesw_rqst,
      netlogon_dissect_dsraddresstositenamesw_reply },
    { NETLOGON_DSRGETDCNAMEEX2, "DsrGetDcNameEx2",
      netlogon_dissect_dsrgetdcnameex2_rqst,
      netlogon_dissect_dsrgetdcnameex2_reply },
    { NETLOGON_NETRLOGONGETTIMESERVICEPARENTDOMAIN,
      "NetrLogonGetTimeServiceParentDomain",
      netlogon_dissect_netrlogongettimeserviceparentdomain_rqst,
      netlogon_dissect_netrlogongettimeserviceparentdomain_reply },
    { NETLOGON_NETRENUMERATETRUSTEDDOMAINSEX, "NetrEnumerateTrustedDomainsEx",
      netlogon_dissect_netrenumeratetrusteddomainsex_rqst,
      netlogon_dissect_netrenumeratetrusteddomainsex_reply },
    { NETLOGON_DSRADDRESSTOSITENAMESEXW, "DsrAddressToSiteNamesExW",
      netlogon_dissect_dsraddresstositenamesexw_rqst,
      netlogon_dissect_dsraddresstositenamesexw_reply },
    { NETLOGON_DSRGETDCSITECOVERAGEW, "DsrGetDcSiteCoverageW",
      netlogon_dissect_dsrgetdcsitecoveragew_rqst,
      netlogon_dissect_dsrgetdcsitecoveragew_reply },
    { NETLOGON_NETRLOGONSAMLOGONEX, "NetrLogonSamLogonEx",
      netlogon_dissect_netrlogonsamlogonex_rqst,
      netlogon_dissect_netrlogonsamlogonex_reply },
    { NETLOGON_DSRENUMERATEDOMAINTRUSTS, "DsrEnumerateDomainTrusts",
      netlogon_dissect_dsrenumeratedomaintrusts_rqst,
      netlogon_dissect_dsrenumeratedomaintrusts_reply },
    { NETLOGON_DSRDEREGISTERDNSHOSTRECORDS, "DsrDeregisterDnsHostRecords",
      netlogon_dissect_dsrderegisterdnshostrecords_rqst,
      netlogon_dissect_dsrderegisterdnshostrecords_reply },
    { NETLOGON_NETRSERVERTRUSTPASSWORDSGET, "NetrServerTrustPasswordsGet",
      NULL, NULL },
    { NETLOGON_DSRGETFORESTTRUSTINFORMATION, "DsrGetForestTrustInformation",
      NULL, NULL },
    { NETLOGON_NETRGETFORESTTRUSTINFORMATION, "NetrGetForestTrustInformation",
      NULL, NULL },
    { NETLOGON_NETRLOGONSAMLOGONWITHFLAGS, "NetrLogonSamLogonWithFlags",
      netlogon_dissect_netrlogonsamlogonflags_rqst,
      netlogon_dissect_netrlogonsamlogonflags_reply },
    { NETLOGON_NETRSERVERGETTRUSTINFO, "NetrServerGetTrustInfo",
      NULL, NULL },
    {0, NULL, NULL,  NULL }
};

static int hf_netlogon_secchan_verf = -1;
static int hf_netlogon_secchan_verf_signalg = -1;
static int hf_netlogon_secchan_verf_sealalg = -1;
static int hf_netlogon_secchan_verf_flag = -1;
static int hf_netlogon_secchan_verf_digest = -1;
static int hf_netlogon_secchan_verf_seq = -1;
static int hf_netlogon_secchan_verf_nonce = -1;

static const value_string sign_algs[] = {
    { 0x0077, "HMAC-MD5"},
    { 0, NULL}
};

static const value_string seal_algs[] = {
    { 0xFFFF, "Not Encrypted"},
    { 0x007A, "RC4"},
    { 0, NULL}
};

static int get_seal_key(const guint8 *session_key,int key_len,guint64 sequence,guint8* seal_key)
{
    guint8 zeros[4];
    guint8 *buf = (guint8 *)g_malloc(key_len);
    guint8 buf2[16];
    guint8 zero_sk[16];
    int i = 0;
    memset(zero_sk,0,16);
    memset(seal_key,0,16);
    if(memcmp(session_key,zero_sk,16)) {
        memset(zeros,0,4);
        for(i=0;i<key_len;i++) {
            buf[i] = session_key[i] ^ 0xF0;
        }
        md5_hmac(zeros,4,buf,key_len,buf2);
        md5_hmac((guint8*)&sequence,8,buf2,16,seal_key);
        g_free(buf);
        return 1;
    }
    else {
        g_free(buf);
        return 0;
    }

}

static guint64 uncrypt_sequence(guint8* session_key,guint64 checksum,guint64 enc_seq,unsigned char is_server _U_)
{
    guint8 zeros[4];
    guint8 buf[16];
    guint8 key[16];
    rc4_state_struct rc4state;
    guint8 *p_seq = (guint8*) &enc_seq;
    /*guint32 temp;*/

    memset(zeros,0,4);
    md5_hmac(zeros,4,session_key,16,buf);
    md5_hmac((guint8*)&checksum,8,buf,16,key);

    crypt_rc4_init(&rc4state,key,16);
    crypt_rc4(&rc4state,p_seq,8);
    /*temp = *((guint32*)p_seq);
     *((guint32*)p_seq) = *((guint32*)p_seq+1);
     *((guint32*)p_seq+1) = temp;

     if(!is_server) {
     *p_seq = *p_seq & 0x7F;
     }
    */
    return enc_seq;
}

static tvbuff_t *
dissect_packet_data(tvbuff_t *tvb ,tvbuff_t *auth_tvb _U_,
                    int offset , packet_info *pinfo ,dcerpc_auth_info *auth_info _U_,unsigned char is_server)
{

    tvbuff_t  *buf = NULL;
    guint8* decrypted;
    netlogon_auth_vars *vars;
    netlogon_auth_key key;
    /*debugprintf("Dissection of request data offset %d len=%d on packet %d\n",offset,tvb_length_remaining(tvb,offset),pinfo->fd->num);*/

    generate_hash_key(pinfo,is_server,&key,NULL);
    vars = (netlogon_auth_vars *)g_hash_table_lookup(netlogon_auths, &key);

    if(vars != NULL  ) {
        while(vars != NULL && vars->next_start != -1 && vars->next_start < (int) pinfo->fd->num ) {
            vars = vars->next;
        }
        if(vars == NULL ) {
            debugprintf("Vars not found %d (packet_data)\n",g_hash_table_size(netlogon_auths));
            return(buf);
        }
        else {
            if(vars->can_decrypt == TRUE) {
                rc4_state_struct rc4state;
                int data_len;
                guint64 copyconfounder = vars->confounder;

                data_len = tvb_length_remaining(tvb,offset);
                if (data_len < 0) {
                    return NULL;
                }
                crypt_rc4_init(&rc4state,vars->encryption_key,16);
                crypt_rc4(&rc4state,(guint8*)&copyconfounder,8);
                decrypted = (guint8*)ep_tvb_memdup(tvb, offset,data_len);
                crypt_rc4_init(&rc4state,vars->encryption_key,16);
                crypt_rc4(&rc4state,decrypted,data_len);
                buf = tvb_new_child_real_data(tvb, decrypted, data_len, data_len);
                /* Note: caller does add_new_data_source(...) */
            }
            else {
                debugprintf("Session key not found can't decrypt ...\n");
            }
        }
    } else {
        debugprintf("Vars not found  %d (packet_data)\n",g_hash_table_size(netlogon_auths));
        return(buf);
    }

    return(buf);
}

static tvbuff_t* dissect_request_data( tvbuff_t *tvb ,tvbuff_t *auth_tvb ,
                                       int offset , packet_info *pinfo ,dcerpc_auth_info *auth_info )
{
    return dissect_packet_data(tvb,auth_tvb,offset,pinfo,auth_info,0);
}
static tvbuff_t* dissect_response_data( tvbuff_t *tvb ,tvbuff_t *auth_tvb ,
                                        int offset , packet_info *pinfo ,dcerpc_auth_info *auth_info )
{
    return dissect_packet_data(tvb,auth_tvb,offset,pinfo,auth_info,1);
}

/* MS-NRPC 2.2.1.3.2 */
static int
dissect_secchan_verf(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
                     proto_tree *tree, guint8 *drep _U_, unsigned char is_server)
{
    netlogon_auth_vars *vars;
    netlogon_auth_key key;
    proto_item *vf = NULL;
    proto_tree *subtree = NULL;
    guint64 encrypted_seq;
    guint64 digest;
    guint64 confounder = 0;
    int update_vars = 0;

    generate_hash_key(pinfo,is_server,&key,NULL);
    vars = (netlogon_auth_vars *)g_hash_table_lookup(netlogon_auths,(gconstpointer*) &key);
    if(  ! (seen.isseen && seen.num == pinfo->fd->num) ) {
        /*
         * Create a new tree, and split into x components ...
         */
        vf = proto_tree_add_item(tree, hf_netlogon_secchan_verf, tvb,
                                 offset, -1, ENC_NA);
        subtree = proto_item_add_subtree(vf, ett_secchan_verf);

        proto_tree_add_item(subtree, hf_netlogon_secchan_verf_signalg, tvb,
                            offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(subtree, hf_netlogon_secchan_verf_sealalg, tvb,
                            offset+2, 2, ENC_LITTLE_ENDIAN);
        /* 2 pad bytes */
        proto_tree_add_item(subtree, hf_netlogon_secchan_verf_flag, tvb,
                            offset+6, 2, ENC_NA);
        offset += 8;

        offset = dissect_dcerpc_8bytes(tvb, offset, pinfo, subtree, drep,
                                       hf_netlogon_secchan_verf_seq, &encrypted_seq);

        offset = dissect_dcerpc_8bytes(tvb, offset, pinfo, subtree, drep,
                                       hf_netlogon_secchan_verf_digest, &digest);

        /* In some cases the nonce if the data/signture are encrypted ("integrity/seal  in MS language")*/

        if (tvb_bytes_exist(tvb, offset, 8)) {
            offset = dissect_dcerpc_8bytes(tvb, offset, pinfo, subtree, drep,
                                           hf_netlogon_secchan_verf_nonce, &confounder);
        }
        update_vars = 1;
    }
    if( vars != NULL ) {
        while(vars != NULL && vars->next_start != -1 && vars->next_start <  (int)pinfo->fd->num ) {
            vars = vars->next;
        }
        if(vars == NULL ) {
            debugprintf("Vars not found %d (packet_data)\n",g_hash_table_size(netlogon_auths));
            return(offset);
        }
        else {
            if(update_vars) {
                vars->confounder = confounder;
                vars->seq = uncrypt_sequence(vars->session_key,digest,encrypted_seq,is_server);
            }

            if(get_seal_key(vars->session_key,16,vars->seq,vars->encryption_key))
            {
                vars->can_decrypt = TRUE;
            }
            else
            {
                debugprintf("get seal key returned 0\n");
            }
        }
    }
    else
    {
        debugprintf("Vars not found (is null %d) %d (dissect_verf)\n",vars==NULL,g_hash_table_size(netlogon_auths));
    }
    /*debugprintf("Setting isseen to true, old packet %d new %d\n",seen.num,pinfo->fd->num);*/
    seen.isseen = TRUE;
    seen.num = pinfo->fd->num;

    return offset;
}
static int
dissect_request_secchan_verf(tvbuff_t *tvb, int offset, packet_info *pinfo ,
                             proto_tree *tree, guint8 *drep )
{
    return dissect_secchan_verf(tvb,offset,pinfo,tree,drep,0);
}
static int
dissect_response_secchan_verf(tvbuff_t *tvb, int offset, packet_info *pinfo ,
                              proto_tree *tree, guint8 *drep )
{
    return dissect_secchan_verf(tvb,offset,pinfo,tree,drep,1);
}

/* Secure channel types */

static const value_string sec_chan_type_vals[] = {
    { SEC_CHAN_WKSTA,  "Workstation" },
    { SEC_CHAN_DOMAIN, "Domain trust" },
    { SEC_CHAN_BDC,    "Backup domain controller" },
    { 0, NULL }
};
static void
netlogon_reassemble_init(void)
{
    if (netlogon_auths){
        g_hash_table_destroy (netlogon_auths);
    }
    netlogon_auths = g_hash_table_new (netlogon_auth_hash, netlogon_auth_equal);
    if (schannel_auths){
        g_hash_table_destroy (schannel_auths);
    }
    schannel_auths = g_hash_table_new (netlogon_auth_hash, netlogon_auth_equal);

}

void
proto_register_dcerpc_netlogon(void)
{

    static hf_register_info hf[] = {
        { &hf_netlogon_opnum,
          { "Operation", "netlogon.opnum", FT_UINT16, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_rc, {
                "Return code", "netlogon.rc", FT_UINT32, BASE_HEX,
                VALS(NT_errors), 0x0, "Netlogon return code", HFILL }},

        { &hf_netlogon_dos_rc,
          { "DOS error code", "netlogon.dos.rc", FT_UINT32,
            BASE_HEX, VALS(DOS_errors), 0x0, NULL, HFILL}},

        { &hf_netlogon_werr_rc,
          { "WERR error code", "netlogon.werr.rc", FT_UINT32,
            BASE_HEX, VALS(WERR_errors), 0x0, NULL, HFILL}},

        { &hf_netlogon_param_ctrl, {
                "Param Ctrl", "netlogon.param_ctrl", FT_UINT32, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_logon_id, {
                "Logon ID", "netlogon.logon_id", FT_UINT64, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_modify_count, {
                "Modify Count", "netlogon.modify_count", FT_UINT64, BASE_DEC,
                NULL, 0x0, "How many times the object has been modified", HFILL }},

        { &hf_netlogon_security_information, {
                "Security Information", "netlogon.security_information", FT_UINT32, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_count, {
                "Count", "netlogon.count", FT_UINT32, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_entries, {
                "Entries", "netlogon.entries", FT_UINT32, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_credential, {
                "Credential", "netlogon.credential", FT_BYTES, BASE_NONE,
                NULL, 0x0, "Netlogon Credential", HFILL }},

        { &hf_netlogon_challenge, {
                "Challenge", "netlogon.challenge", FT_BYTES, BASE_NONE,
                NULL, 0x0, "Netlogon challenge", HFILL }},

        { &hf_netlogon_lm_owf_password, {
                "LM Pwd", "netlogon.lm_owf_pwd", FT_BYTES, BASE_NONE,
                NULL, 0x0, "LanManager OWF Password", HFILL }},

        { &hf_netlogon_user_session_key, {
                "User Session Key", "netlogon.user_session_key", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_encrypted_lm_owf_password, {
                "Encrypted LM Pwd", "netlogon.lm_owf_pwd.encrypted", FT_BYTES, BASE_NONE,
                NULL, 0x0, "Encrypted LanManager OWF Password", HFILL }},

        { &hf_netlogon_nt_owf_password, {
                "NT Pwd", "netlogon.nt_owf_pwd", FT_BYTES, BASE_NONE,
                NULL, 0x0, "NT OWF Password", HFILL }},

        { &hf_netlogon_blob, {
                "BLOB", "netlogon.blob", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_len, {
                "Len", "netlogon.len", FT_UINT32, BASE_DEC,
                NULL, 0, "Length", HFILL }},

        { &hf_netlogon_priv, {
                "Priv", "netlogon.priv", FT_UINT32, BASE_DEC,
                NULL, 0, NULL, HFILL }},

        { &hf_netlogon_privilege_entries, {
                "Privilege Entries", "netlogon.privilege_entries", FT_UINT32, BASE_DEC,
                NULL, 0, NULL, HFILL }},

        { &hf_netlogon_privilege_control, {
                "Privilege Control", "netlogon.privilege_control", FT_UINT32, BASE_HEX,
                NULL, 0, NULL, HFILL }},

        { &hf_netlogon_privilege_name, {
                "Privilege Name", "netlogon.privilege_name", FT_STRING, BASE_NONE,
                NULL, 0, NULL, HFILL }},

        { &hf_netlogon_pdc_connection_status, {
                "PDC Connection Status", "netlogon.pdc_connection_status", FT_UINT32, BASE_DEC,
                NULL, 0, NULL, HFILL }},

        { &hf_netlogon_tc_connection_status, {
                "TC Connection Status", "netlogon.tc_connection_status", FT_UINT32, BASE_DEC,
                NULL, 0, NULL, HFILL }},

        { &hf_netlogon_attrs, {
                "Attributes", "netlogon.attrs", FT_UINT32, BASE_HEX,
                NULL, 0, NULL, HFILL }},

        { &hf_netlogon_lsapolicy_referentid,
          { "Referent ID", "netlogon.lsapolicy.referentID", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_lsapolicy_len,
          { "Length", "netlogon.lsapolicy.length", FT_UINT32, BASE_DEC,
            NULL, 0x0, "Length of the policy buffer", HFILL }},

        { &hf_netlogon_lsapolicy_pointer,
          { "Pointer", "netlogon.lsapolicy.pointer", FT_BYTES, BASE_NONE,
            NULL, 0x0, "Pointer to LSA POLICY", HFILL }},

        { &hf_netlogon_unknown_string,
          { "Unknown string", "netlogon.unknown_string", FT_STRING, BASE_NONE,
            NULL, 0, "Unknown string. If you know what this is, contact wireshark developers.", HFILL }},

        { &hf_netlogon_TrustedDomainName_string,
          { "TrustedDomainName", "netlogon.TrustedDomainName", FT_STRING, BASE_NONE,
            NULL, 0, "TrustedDomainName string.", HFILL }},

        { &hf_netlogon_UserName_string,
          { "UserName", "netlogon.UserName", FT_STRING, BASE_NONE,
            NULL, 0, "UserName string.", HFILL }},

        { &hf_netlogon_dummy_string,
          { "Dummy String", "netlogon.dummy_string", FT_STRING, BASE_NONE,
            NULL, 0, "Dummy String. Used is reserved for next evolutions.", HFILL }},

        { &hf_netlogon_trust_extention,
          { "Trust extension", "netlogon.trust.extention", FT_STRING, BASE_NONE,
            NULL, 0, "Trusts extension.", HFILL }},

        { &hf_netlogon_trust_offset,
          { "Offset", "netlogon.trust.extention_offset", FT_UINT32, BASE_DEC,
            NULL, 0, "Trusts extension.", HFILL }},

        { &hf_netlogon_trust_len,
          { "Length", "netlogon.trust.extention_length", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_trust_max,
          { "Max Count", "netlogon.trust.extention.maxcount", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_dummy_string2,
          { "Dummy String2", "netlogon.dummy_string", FT_STRING, BASE_NONE,
            NULL, 0, "Dummy String 2. Used is reserved for next evolutions.", HFILL }},

        { &hf_netlogon_dummy_string3,
          { "Dummy String3", "netlogon.dummy_string", FT_STRING, BASE_NONE,
            NULL, 0, "Dummy String 3. Used is reserved for next evolutions.", HFILL }},

        { &hf_netlogon_dummy_string4,
          { "Dummy String4", "netlogon.dummy_string", FT_STRING, BASE_NONE,
            NULL, 0, "Dummy String 4. Used is reserved for next evolutions.", HFILL }},

        { &hf_netlogon_dummy_string5,
          { "Dummy String5", "netlogon.dummy_string", FT_STRING, BASE_NONE,
            NULL, 0, "Dummy String 5. Used is reserved for next evolutions.", HFILL }},

        { &hf_netlogon_dummy_string6,
          { "Dummy String6", "netlogon.dummy_string", FT_STRING, BASE_NONE,
            NULL, 0, "Dummy String 6. Used is reserved for next evolutions.", HFILL }},

        { &hf_netlogon_dummy_string7,
          { "Dummy String7", "netlogon.dummy_string", FT_STRING, BASE_NONE,
            NULL, 0, "Dummy String 7. Used is reserved for next evolutions.", HFILL }},

        { &hf_netlogon_dummy_string8,
          { "Dummy String8", "netlogon.dummy_string", FT_STRING, BASE_NONE,
            NULL, 0, "Dummy String 8. Used is reserved for next evolutions.", HFILL }},

        { &hf_netlogon_dummy_string9,
          { "Dummy String9", "netlogon.dummy_string", FT_STRING, BASE_NONE,
            NULL, 0, "Dummy String 9. Used is reserved for next evolutions.", HFILL }},

        { &hf_netlogon_dummy_string10,
          { "Dummy String10", "netlogon.dummy_string", FT_STRING, BASE_NONE,
            NULL, 0, "Dummy String 10. Used is reserved for next evolutions.", HFILL }},

        { &hf_netlogon_unknown_long,
          { "Unknown long", "netlogon.unknown.long", FT_UINT32, BASE_HEX,
            NULL, 0x0, "Unknown long. If you know what this is, contact wireshark developers.", HFILL }},

        { &hf_netlogon_dummy1_long,
          { "Dummy1 Long", "netlogon.dummy.long1", FT_UINT32, BASE_HEX,
            NULL, 0x0, "Dummy long 1. Used is reserved for next evolutions.", HFILL }},

        { &hf_netlogon_dummy2_long,
          { "Dummy2 Long", "netlogon.dummy.long2", FT_UINT32, BASE_HEX,
            NULL, 0x0, "Dummy long 2. Used is reserved for next evolutions.", HFILL }},

        { &hf_netlogon_dummy3_long,
          { "Dummy3 Long", "netlogon.dummy.long3", FT_UINT32, BASE_HEX,
            NULL, 0x0, "Dummy long 3. Used is reserved for next evolutions.", HFILL }},

        { &hf_netlogon_dummy4_long,
          { "Dummy4 Long", "netlogon.dummy.long4", FT_UINT32, BASE_HEX,
            NULL, 0x0, "Dummy long 4. Used is reserved for next evolutions.", HFILL }},

        { &hf_netlogon_dummy5_long,
          { "Dummy5 Long", "netlogon.dummy.long5", FT_UINT32, BASE_HEX,
            NULL, 0x0, "Dummy long 5. Used is reserved for next evolutions.", HFILL }},

        { &hf_netlogon_dummy6_long,
          { "Dummy6 Long", "netlogon.dummy.long6", FT_UINT32, BASE_HEX,
            NULL, 0x0, "Dummy long 6. Used is reserved for next evolutions.", HFILL }},

        { &hf_netlogon_dummy7_long,
          { "Dummy7 Long", "netlogon.dummy.long7", FT_UINT32, BASE_HEX,
            NULL, 0x0, "Dummy long 7. Used is reserved for next evolutions.", HFILL }},

        { &hf_netlogon_dummy8_long,
          { "Dummy8 Long", "netlogon.dummy.long8", FT_UINT32, BASE_HEX,
            NULL, 0x0, "Dummy long 8. Used is reserved for next evolutions.", HFILL }},

        { &hf_netlogon_dummy9_long,
          { "Dummy9 Long", "netlogon.dummy.long9", FT_UINT32, BASE_HEX,
            NULL, 0x0, "Dummy long 9. Used is reserved for next evolutions.", HFILL }},

        { &hf_netlogon_dummy10_long,
          { "Dummy10 Long", "netlogon.dummy.long10", FT_UINT32, BASE_HEX,
            NULL, 0x0, "Dummy long 10. Used is reserved for next evolutions.", HFILL }},


        { &hf_netlogon_supportedenctypes,
          { "Supported Encryption Types", "netlogon.encryption.types", FT_UINT32, BASE_HEX,
            NULL, 0x0, "Encryption types", HFILL }},

        { &hf_netlogon_workstation_flags,
          { "Workstation Flags", "netlogon.workstation.flags", FT_UINT32, BASE_HEX,
            NULL, 0x0, "Flags", HFILL }},

        { &hf_netlogon_reserved,
          { "Reserved", "netlogon.reserved", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},
        { &hf_netlogon_unknown_short,
          { "Unknown short", "netlogon.unknown.short", FT_UINT16, BASE_HEX,
            NULL, 0x0, "Unknown short. If you know what this is, contact wireshark developers.", HFILL }},

        { &hf_netlogon_unknown_char,
          { "Unknown char", "netlogon.unknown.char", FT_UINT8, BASE_HEX,
            NULL, 0x0, "Unknown char. If you know what this is, contact wireshark developers.", HFILL }},

        { &hf_netlogon_acct_expiry_time,
          { "Acct Expiry Time", "netlogon.acct.expiry_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
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
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_sensitive_data_flag,
          { "Sensitive Data", "netlogon.sensitive_data_flag", FT_UINT8, BASE_DEC,
            NULL, 0x0, "Sensitive data flag", HFILL }},

        { &hf_netlogon_auditing_mode,
          { "Auditing Mode", "netlogon.auditing_mode", FT_UINT8, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_max_audit_event_count,
          { "Max Audit Event Count", "netlogon.max_audit_event_count", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_event_audit_option,
          { "Event Audit Option", "netlogon.event_audit_option", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_sensitive_data_len,
          { "Length", "netlogon.sensitive_data_len", FT_UINT32, BASE_DEC,
            NULL, 0x0, "Length of sensitive data", HFILL }},

        { &hf_netlogon_nt_chal_resp,
          { "NT Chal resp", "netlogon.nt_chal_resp", FT_BYTES, BASE_NONE,
            NULL, 0, "Challenge response for NT authentication", HFILL }},

        { &hf_netlogon_lm_chal_resp,
          { "LM Chal resp", "netlogon.lm_chal_resp", FT_BYTES, BASE_NONE,
            NULL, 0, "Challenge response for LM authentication", HFILL }},

        { &hf_netlogon_cipher_len,
          { "Cipher Len", "netlogon.cipher_len", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_cipher_maxlen,
          { "Cipher Max Len", "netlogon.cipher_maxlen", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_pac_data,
          { "Pac Data", "netlogon.pac.data", FT_BYTES, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_sensitive_data,
          { "Data", "netlogon.sensitive_data", FT_BYTES, BASE_NONE,
            NULL, 0, "Sensitive Data", HFILL }},

        { &hf_netlogon_auth_data,
          { "Auth Data", "netlogon.auth.data", FT_BYTES, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_cipher_current_data,
          { "Cipher Current Data", "netlogon.cipher_current_data", FT_BYTES, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_cipher_old_data,
          { "Cipher Old Data", "netlogon.cipher_old_data", FT_BYTES, BASE_NONE,
            NULL, 0, NULL, HFILL }},

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
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_comment,
          { "Comment", "netlogon.comment", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_parameters,
          { "Parameters", "netlogon.parameters", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_logon_script,
          { "Logon Script", "netlogon.logon_script", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_profile_path,
          { "Profile Path", "netlogon.profile_path", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_home_dir,
          { "Home Dir", "netlogon.home_dir", FT_STRING, BASE_NONE,
            NULL, 0, "Home Directory", HFILL }},

        { &hf_netlogon_dir_drive,
          { "Dir Drive", "netlogon.dir_drive", FT_STRING, BASE_NONE,
            NULL, 0, "Drive letter for home directory", HFILL }},

        { &hf_netlogon_logon_srv,
          { "Server", "netlogon.server", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_principal,
          { "Principal", "netlogon.principal", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_logon_dom,
          { "Domain", "netlogon.domain", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_resourcegroupcount,
          { "ResourceGroup count", "netlogon.resourcegroupcount", FT_UINT32, BASE_DEC,
            NULL, 0, "Number of Resource Groups", HFILL }},

        { &hf_netlogon_computer_name,
          { "Computer Name", "netlogon.computer_name", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_site_name,
          { "Site Name", "netlogon.site_name", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_dc_name,
          { "DC Name", "netlogon.dc.name", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_dc_site_name,
          { "DC Site Name", "netlogon.dc.site_name", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_dns_forest_name,
          { "DNS Forest Name", "netlogon.dns.forest_name", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_dc_address,
          { "DC Address", "netlogon.dc.address", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_dc_address_type,
          { "DC Address Type", "netlogon.dc.address_type", FT_UINT32, BASE_DEC,
            VALS(dc_address_types), 0, NULL, HFILL }},

        { &hf_netlogon_client_site_name,
          { "Client Site Name", "netlogon.client.site_name", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_workstation_site_name,
          { "Wkst Site Name", "netlogon.wkst.site_name", FT_STRING, BASE_NONE,
            NULL, 0, "Workstation Site Name", HFILL }},

        { &hf_netlogon_workstation,
          { "Wkst Name", "netlogon.wkst.name", FT_STRING, BASE_NONE,
            NULL, 0, "Workstation Name", HFILL }},

        { &hf_netlogon_os_version,
          { "OS version", "netlogon.os.version", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_workstation_os,
          { "Wkst OS", "netlogon.wkst.os", FT_STRING, BASE_NONE,
            NULL, 0, "Workstation OS", HFILL }},

        { &hf_netlogon_workstations,
          { "Workstations", "netlogon.wksts", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_workstation_fqdn,
          { "Wkst FQDN", "netlogon.wkst.fqdn", FT_STRING, BASE_NONE,
            NULL, 0, "Workstation FQDN", HFILL }},

        { &hf_netlogon_group_name,
          { "Group Name", "netlogon.group_name", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_alias_name,
          { "Alias Name", "netlogon.alias_name", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_dns_host,
          { "DNS Host", "netlogon.dns_host", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_downlevel_domain_name,
          { "Downlevel Domain", "netlogon.downlevel_domain", FT_STRING, BASE_NONE,
            NULL, 0, "Downlevel Domain Name", HFILL }},

        { &hf_netlogon_dns_domain_name,
          { "DNS Domain", "netlogon.dns_domain", FT_STRING, BASE_NONE,
            NULL, 0, "DNS Domain Name", HFILL }},

        { &hf_netlogon_ad_client_dns_name,
          { "Client DNS Name", "netlogon.client_dns_name", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_domain_name,
          { "Domain", "netlogon.domain", FT_STRING, BASE_NONE,
            NULL, 0, "Domain Name", HFILL }},

        { &hf_netlogon_oem_info,
          { "OEM Info", "netlogon.oem_info", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_trusted_dc_name,
          { "Trusted DC", "netlogon.trusted_dc", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_logon_dnslogondomainname,
          { "DNS Logon Domain name", "netlogon.logon.dnslogondomainname", FT_STRING, BASE_NONE,
            NULL, 0, "DNS Name of the logon domain", HFILL }},

        { &hf_netlogon_logon_upn,
          { "UPN", "netlogon.logon.upn", FT_STRING, BASE_NONE,
            NULL, 0, "User Principal Name", HFILL }},

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
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_delta_type,
          { "Delta Type", "netlogon.delta_type", FT_UINT16, BASE_DEC,
            VALS(delta_type_vals), 0x0, NULL, HFILL }},

        { &hf_netlogon_blob_size,
          { "Size", "netlogon.blob.size", FT_UINT32, BASE_DEC,
            NULL, 0x0, "Size in bytes of BLOB", HFILL }},

        { &hf_netlogon_code,
          { "Code", "netlogon.code", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_level,
          { "Level", "netlogon.level", FT_UINT32, BASE_DEC,
            NULL, 0x0, "Which option of the union is represented here", HFILL }},

        { &hf_netlogon_reference,
          { "Reference", "netlogon.reference", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_next_reference,
          { "Next Reference", "netlogon.next_reference", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_timestamp,
          { "Timestamp", "netlogon.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_user_rid,
          { "User RID", "netlogon.rid", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_alias_rid,
          { "Alias RID", "netlogon.alias_rid", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_group_rid,
          { "Group RID", "netlogon.group_rid", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_num_rids,
          { "Num RIDs", "netlogon.num_rids", FT_UINT32, BASE_DEC,
            NULL, 0x0, "Number of RIDs", HFILL }},

        { &hf_netlogon_num_controllers,
          { "Num DCs", "netlogon.num_dc", FT_UINT32, BASE_DEC,
            NULL, 0x0, "Number of domain controllers", HFILL }},

        { &hf_netlogon_num_sid,
          { "Num Extra SID", "netlogon.num_sid", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_flags,
          { "Flags", "netlogon.flags", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_user_account_control,
          { "User Account Control", "netlogon.user_account_control", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_user_flags,
          { "User Flags", "netlogon.user_flags", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_auth_flags,
          { "Auth Flags", "netlogon.auth_flags", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_systemflags,
          { "System Flags", "netlogon.system_flags", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_database_id,
          { "Database Id", "netlogon.database_id", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_sync_context,
          { "Sync Context", "netlogon.sync_context", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},

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
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_logon_attempts,
          { "Logon Attempts", "netlogon.logon_attempts", FT_UINT32, BASE_DEC,
            NULL, 0x0, "Number of logon attempts", HFILL }},

        { &hf_netlogon_pagefilelimit,
          { "Page File Limit", "netlogon.page_file_limit", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_pagedpoollimit,
          { "Paged Pool Limit", "netlogon.paged_pool_limit", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_nonpagedpoollimit,
          { "Non-Paged Pool Limit", "netlogon.nonpaged_pool_limit", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_minworkingsetsize,
          { "Min Working Set Size", "netlogon.min_working_set_size", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_maxworkingsetsize,
          { "Max Working Set Size", "netlogon.max_working_set_size", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_serial_number,
          { "Serial Number", "netlogon.serial_number", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_neg_flags,
          { "Negotiation options", "netlogon.neg_flags", FT_UINT32, BASE_HEX,
            NULL, 0x0, "Negotiation Flags", HFILL }},

        { &hf_netlogon_neg_flags_80000000,
          { "Not used 80000000", "ntlmssp.neg_flags.na8000000", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_80000000, "Not used", HFILL }},

        { &hf_netlogon_neg_flags_40000000,
          { "Authenticated RPC supported", "ntlmssp.neg_flags.na8000000", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_40000000, NULL, HFILL }},

        { &hf_netlogon_neg_flags_20000000,
          { "Authenticated RPC via lsass supported", "ntlmssp.neg_flags.na8000000", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_20000000, "rpc via lsass", HFILL }},

        { &hf_netlogon_neg_flags_10000000,
          { "Not used 10000000", "ntlmssp.neg_flags.na8000000", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_10000000, "Not used", HFILL }},

        { &hf_netlogon_neg_flags_8000000,
          { "Not used 8000000", "ntlmssp.neg_flags.na800000", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_8000000, "Not used", HFILL }},

        { &hf_netlogon_neg_flags_4000000,
          { "Not used 4000000", "ntlmssp.neg_flags.na400000", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_4000000, "Not used", HFILL }},

        { &hf_netlogon_neg_flags_2000000,
          { "Not used 2000000", "ntlmssp.neg_flags.na200000", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_2000000, "Not used", HFILL }},

        { &hf_netlogon_neg_flags_1000000,
          { "AES supported", "ntlmssp.neg_flags.na100000", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_1000000, "AES", HFILL }},

        { &hf_netlogon_neg_flags_800000,
          { "Not used 800000", "ntlmssp.neg_flags.na8000000", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_800000, "Not used", HFILL }},

        { &hf_netlogon_neg_flags_400000,
          { "AES & SHA2 supported", "ntlmssp.neg_flags.na400000", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_USEAES, "AES&SHA2", HFILL }},

        { &hf_netlogon_neg_flags_200000,
          { "RODC pass-through", "ntlmssp.neg_flags.na200000", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_200000, "rodc pt", HFILL }},

        { &hf_netlogon_neg_flags_100000,
          { "NO NT4 emulation", "ntlmssp.neg_flags.na100000", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_100000, "No NT4 emu", HFILL }},

        { &hf_netlogon_neg_flags_80000,
          { "Cross forest trust", "ntlmssp.neg_flags.na80000", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_80000, NULL, HFILL }},

        { &hf_netlogon_neg_flags_40000,
          { "GetDomainInfo supported", "ntlmssp.neg_flags.na40000", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_40000, "GetDomainInfo", HFILL }},

        { &hf_netlogon_neg_flags_20000,
          { "ServerPasswordSet2 supported", "ntlmssp.neg_flags.na20000", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_20000, "PasswordSet2", HFILL }},

        { &hf_netlogon_neg_flags_10000,
          { "DNS trusts supported", "ntlmssp.neg_flags.na10000", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_10000, "DNS Trusts", HFILL }},

        { &hf_netlogon_neg_flags_8000,
          { "Transitive trusts", "ntlmssp.neg_flags.na8000", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_8000, "Transitive trust", HFILL }},

        { &hf_netlogon_neg_flags_4000,
          { "Strong key", "ntlmssp.neg_flags.na4000", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_STRONGKEY, NULL, HFILL }},

        { &hf_netlogon_neg_flags_2000,
          { "Avoid replication Auth database", "ntlmssp.neg_flags.na2000", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_2000, NULL, HFILL }},

        { &hf_netlogon_neg_flags_1000,
          { "Avoid replication account database", "ntlmssp.neg_flags.na1000", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_1000, NULL, HFILL }},

        { &hf_netlogon_neg_flags_800,
          { "Concurent RPC", "ntlmssp.neg_flags.na800", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_800, NULL, HFILL }},

        { &hf_netlogon_neg_flags_400,
          { "Generic pass-through", "ntlmssp.neg_flags.na400", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_400, NULL, HFILL }},

        { &hf_netlogon_neg_flags_200,
          { "SendToSam", "ntlmssp.neg_flags.na200", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_200, NULL, HFILL }},

        { &hf_netlogon_neg_flags_100,
          { "Refusal of password change", "ntlmssp.neg_flags.na100", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_100, "PWD change refusal", HFILL }},

        { &hf_netlogon_neg_flags_80,
          { "DatabaseRedo call", "ntlmssp.neg_flags.na80", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_80, NULL, HFILL }},

        { &hf_netlogon_neg_flags_40,
          { "Handle multiple SIDs", "ntlmssp.neg_flags.na40", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_40, NULL, HFILL }},

        { &hf_netlogon_neg_flags_20,
          { "Restarting full DC sync", "ntlmssp.neg_flags.na20", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_20, NULL, HFILL }},

        { &hf_netlogon_neg_flags_10,
          { "BDC handling Changelogs", "ntlmssp.neg_flags.na10", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_10, "BDC Changelog", HFILL }},

        { &hf_netlogon_neg_flags_8,
          { "Promotion count(deprecated)", "ntlmssp.neg_flags.na8", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_8, "Promotion count", HFILL }},

        { &hf_netlogon_neg_flags_4,
          { "RC4 encryption", "ntlmssp.neg_flags.na4", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_4, "RC4", HFILL }},

        { &hf_netlogon_neg_flags_2,
          { "NT3.5 BDC continuous update", "ntlmssp.neg_flags.na2", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_2, "NT3.5", HFILL }},

        { &hf_netlogon_neg_flags_1,
          { "Account lockout", "ntlmssp.neg_flags.na1", FT_BOOLEAN, 32, TFS(&tfs_set_notset), NETLOGON_FLAG_1, NULL, HFILL }},

        { &hf_netlogon_dc_flags,
          { "Domain Controller Flags", "netlogon.dc.flags", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

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
            NULL, HFILL }},

        { &hf_netlogon_dc_flags_dns_forest_flag,
          { "DNS Forest", "netlogon.dc.flags.dns_forest",
            FT_BOOLEAN, 32, TFS(&dc_flags_dns_forest_flag), DS_DNS_FOREST_FLAG,
            NULL, HFILL }},

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
            "If we require the IP of the DC in the reply", HFILL }},

        { &hf_netlogon_get_dcname_request_flags_kdc_required,
          { "KDC Required", "netlogon.get_dcname.request.flags.kdc_required",
            FT_BOOLEAN, 32, TFS(&get_dcname_request_flags_kdc_required), DS_KDC_REQUIRED,
            "If we require that the returned server is a KDC", HFILL }},

        { &hf_netlogon_get_dcname_request_flags_timeserv_required,
          { "Timeserv Required", "netlogon.get_dcname.request.flags.timeserv_required",
            FT_BOOLEAN, 32, TFS(&get_dcname_request_flags_timeserv_required), DS_TIMESERV_REQUIRED,
            "If we require the returned server to be a WindowsTimeServ server", HFILL }},

        { &hf_netlogon_get_dcname_request_flags_writable_required,
          { "Writable Required", "netlogon.get_dcname.request.flags.writable_required",
            FT_BOOLEAN, 32, TFS(&get_dcname_request_flags_writable_required), DS_WRITABLE_REQUIRED,
            "If we require that the returned server is writable", HFILL }},

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
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_trust_attribs_non_transitive,
          { "Non Transitive", "netlogon.trust.attribs.non_transitive", FT_BOOLEAN, 32,
            TFS(&trust_attribs_non_transitive), 0x00000001, NULL, HFILL }},

        { &hf_netlogon_trust_attribs_uplevel_only,
          { "Uplevel Only", "netlogon.trust.attribs.uplevel_only", FT_BOOLEAN, 32,
            TFS(&trust_attribs_uplevel_only), 0x00000002, NULL, HFILL }},

        { &hf_netlogon_trust_attribs_quarantined_domain,
          { "Quarantined Domain", "netlogon.trust.attribs.quarantined_domain", FT_BOOLEAN, 32,
            TFS(&trust_attribs_quarantined_domain), 0x00000004, NULL, HFILL }},

        { &hf_netlogon_trust_attribs_forest_transitive,
          { "Forest Transitive", "netlogon.trust.attribs.forest_transitive", FT_BOOLEAN, 32,
            TFS(&trust_attribs_forest_transitive), 0x00000008, NULL, HFILL }},

        { &hf_netlogon_trust_attribs_cross_organization,
          { "Cross Organization", "netlogon.trust.attribs.cross_organization", FT_BOOLEAN, 32,
            TFS(&trust_attribs_cross_organization), 0x00000010, NULL, HFILL }},

        { &hf_netlogon_trust_attribs_within_forest,
          { "Within Forest", "netlogon.trust.attribs.within_forest", FT_BOOLEAN, 32,
            TFS(&trust_attribs_within_forest), 0x00000020, NULL, HFILL }},

        { &hf_netlogon_trust_attribs_treat_as_external,
          { "Treat As External", "netlogon.trust.attribs.treat_as_external", FT_BOOLEAN, 32,
            TFS(&trust_attribs_treat_as_external), 0x00000040, NULL, HFILL }},

        { &hf_netlogon_trust_type,
          { "Trust Type", "netlogon.trust_type", FT_UINT32, BASE_DEC,
            VALS(trust_type_vals), 0x0, NULL, HFILL }},

        { &hf_netlogon_extraflags,
          { "Extra Flags", "netlogon.extra_flags", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_extra_flags_root_forest,
          { "Request passed to DC of root forest", "netlogon.extra.flags.rootdc",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), RQ_ROOT_FOREST,
            NULL, HFILL }},

        { &hf_netlogon_trust_flags_dc_firsthop,
          { "DC at the end of the first hop of cross forest", "netlogon.extra.flags.dc_firsthop",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), RQ_DC_XFOREST,
            NULL, HFILL }},

        { &hf_netlogon_trust_flags_rodc_to_dc,
          { "Request from a RODC to a DC from another domain", "netlogon.extra.flags.rodc_to_dc",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), RQ_RODC_DIF_DOMAIN,
            NULL, HFILL }},

        { &hf_netlogon_trust_flags_rodc_ntlm,
          { "Request is a NTLM auth passed by a RODC", "netlogon.extra.flags.rodc_ntlm",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), RQ_NTLM_FROM_RODC,
            NULL, HFILL }},

        { &hf_netlogon_trust_flags,
          { "Trust Flags", "netlogon.trust_flags", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

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
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_logon_time,
          { "Logon Time", "netlogon.logon_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
            NULL, 0, "Time for last time this user logged on", HFILL }},

        { &hf_netlogon_kickoff_time,
          { "Kickoff Time", "netlogon.kickoff_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
            NULL, 0, "Time when this user will be kicked off", HFILL }},

        { &hf_netlogon_logoff_time,
          { "Logoff Time", "netlogon.logoff_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
            NULL, 0, "Time for last time this user logged off", HFILL }},

        { &hf_netlogon_last_logoff_time,
          { "Last Logoff Time", "netlogon.last_logoff_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
            NULL, 0, "Time for last time this user logged off", HFILL }},

        { &hf_netlogon_pwd_last_set_time,
          { "PWD Last Set", "netlogon.pwd_last_set_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
            NULL, 0, "Last time this users password was changed", HFILL }},

        { &hf_netlogon_pwd_age,
          { "PWD Age", "netlogon.pwd_age", FT_RELATIVE_TIME, BASE_NONE,
            NULL, 0, "Time since this users password was changed", HFILL }},

        { &hf_netlogon_pwd_can_change_time,
          { "PWD Can Change", "netlogon.pwd_can_change_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
            NULL, 0, "When this users password may be changed", HFILL }},

        { &hf_netlogon_pwd_must_change_time,
          { "PWD Must Change", "netlogon.pwd_must_change_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
            NULL, 0, "When this users password must be changed", HFILL }},

        { &hf_netlogon_domain_create_time,
          { "Domain Create Time", "netlogon.domain_create_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
            NULL, 0, "Time when this domain was created", HFILL }},

        { &hf_netlogon_domain_modify_time,
          { "Domain Modify Time", "netlogon.domain_modify_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
            NULL, 0, "Time when this domain was last modified", HFILL }},

        { &hf_netlogon_db_modify_time,
          { "DB Modify Time", "netlogon.db_modify_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
            NULL, 0, "Time when last modified", HFILL }},

        { &hf_netlogon_db_create_time,
          { "DB Create Time", "netlogon.db_create_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
            NULL, 0, "Time when created", HFILL }},

        { &hf_netlogon_cipher_current_set_time,
          { "Cipher Current Set Time", "netlogon.cipher_current_set_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
            NULL, 0, "Time when current cipher was initiated", HFILL }},

        { &hf_netlogon_cipher_old_set_time,
          { "Cipher Old Set Time", "netlogon.cipher_old_set_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
            NULL, 0, "Time when previous cipher was initiated", HFILL }},

        { &hf_netlogon_audit_retention_period,
          { "Audit Retention Period", "netlogon.audit_retention_period", FT_RELATIVE_TIME, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_timelimit,
          { "Time Limit", "netlogon.time_limit", FT_RELATIVE_TIME, BASE_NONE,
            NULL, 0, NULL, HFILL }},


        { &hf_client_credential,
          { "Client Credential", "netlogon.clientcred", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},

        { &hf_server_credential,
          { "Server Credential", "netlogon.servercred", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},

        { &hf_server_rid,
          { "Account RID", "netlogon.serverrid", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},

        { &hf_client_challenge,
          { "Client Challenge", "netlogon.clientchallenge", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},

        { &hf_server_challenge,
          { "Server Challenge", "netlogon.serverchallenge", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_secchan_nl_message_type,
          { "Message Type", "netlogon.secchan.nl_auth_message.message_type", FT_UINT32, BASE_HEX,
            VALS(nl_auth_types), 0x0, NULL, HFILL }},

        { &hf_netlogon_secchan_nl_message_flags,
          { "Message Flags", "netlogon.secchan.nl_auth_message.message_flags", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_netlogon_secchan_nl_message_flags_nb_domain,
          { "NetBios Domain", "netlogon.secchan.nl_auth_message.message_flags.nb_domain", FT_BOOLEAN, 32,
            NULL, 0x00000001, NULL, HFILL }},

        { &hf_netlogon_secchan_nl_message_flags_nb_host,
          { "NetBios Host", "netlogon.secchan.nl_auth_message.message_flags.nb_host", FT_BOOLEAN, 32,
            NULL, 0x00000002, NULL, HFILL }},

        { &hf_netlogon_secchan_nl_message_flags_dns_domain,
          { "DNS Domain", "netlogon.secchan.nl_auth_message.message_flags.dns_domain", FT_BOOLEAN, 32,
            NULL, 0x00000004, NULL, HFILL }},

        { &hf_netlogon_secchan_nl_message_flags_dns_host,
          { "DNS Host", "netlogon.secchan.nl_auth_message.message_flags.dns_host", FT_BOOLEAN, 32,
            NULL, 0x00000008, NULL, HFILL }},

        { &hf_netlogon_secchan_nl_message_flags_nb_host_utf8,
          { "NetBios Host(UTF8)", "netlogon.secchan.nl_auth_message.message_flags.nb_host_utf8", FT_BOOLEAN, 32,
            NULL, 0x00000010, NULL, HFILL }},

        { &hf_netlogon_secchan_nl_nb_domain,
          { "NetBios Domain", "netlogon.secchan.nl_auth_message.nb_domain", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_secchan_nl_nb_host,
          { "NetBios Host", "netlogon.secchan.nl_auth_message.nb_host", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_secchan_nl_nb_host_utf8,
          { "NetBios Host(UTF8)", "netlogon.secchan.nl_auth_message.nb_host_utf8", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_secchan_nl_dns_domain,
          { "DNS Domain", "netlogon.secchan.nl_auth_message.dns_domain", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_secchan_nl_dns_host,
          { "DNS Host", "netlogon.secchan.nl_auth_message.dns_host", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_data_length,
          { "Length of Data", "netlogon.data.length", FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_package_name,
          { "SSP Package Name", "netlogon.data.package_name", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }},

        { &hf_netlogon_secchan_verf,
          { "Secure Channel Verifier", "netlogon.secchan.verifier", FT_NONE, BASE_NONE,
            NULL, 0x0, "Verifier", HFILL }},

        { &hf_netlogon_secchan_verf_signalg,
          { "Sign algorithm", "netlogon.secchan.signalg", FT_UINT16, BASE_HEX,
            VALS(sign_algs), 0, NULL, HFILL }},

        { &hf_netlogon_secchan_verf_sealalg,
          { "Seal algorithm", "netlogon.secchan.sealalg", FT_UINT16, BASE_HEX,
            VALS(seal_algs), 0, NULL, HFILL }},

        { &hf_netlogon_secchan_verf_flag,
          { "Flags", "netlogon.secchan.flags", FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }},

        { &hf_netlogon_secchan_verf_digest,
          { "Packet Digest", "netlogon.secchan.digest", FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }},

        { &hf_netlogon_secchan_verf_seq,
          { "Sequence No", "netlogon.secchan.seq", FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }},

        { &hf_netlogon_secchan_verf_nonce,
          { "Nonce", "netlogon.secchan.nonce", FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }},

        { &hf_netlogon_group_attrs_mandatory,
          { "Mandatory", "netlogon.groups.attrs.mandatory",
            FT_BOOLEAN, 32, TFS(&group_attrs_mandatory), 0x00000001,
            "The group attributes MANDATORY flag", HFILL }},

        { &hf_netlogon_group_attrs_enabled_by_default,
          { "Enabled By Default", "netlogon.groups.attrs.enabled_by_default",
            FT_BOOLEAN, 32, TFS(&group_attrs_enabled_by_default), 0x00000002,
            "The group attributes ENABLED_BY_DEFAULT flag", HFILL }},

        { &hf_netlogon_group_attrs_enabled,
          { "Enabled", "netlogon.groups.attrs.enabled",
            FT_BOOLEAN, 32, TFS(&group_attrs_enabled), 0x00000004,
            "The group attributes ENABLED flag", HFILL }},

        { &hf_netlogon_user_flags_extra_sids,
          { "Extra SIDs", "netlogon.user.flags.extra_sids",
            FT_BOOLEAN, 32, TFS(&user_flags_extra_sids), 0x00000020,
            "The user flags EXTRA_SIDS", HFILL }},

        { &hf_netlogon_user_flags_resource_groups,
          { "Resource Groups", "netlogon.user.flags.resource_groups",
            FT_BOOLEAN, 32, TFS(&user_flags_resource_groups), 0x00000200,
            "The user flags RESOURCE_GROUPS", HFILL }},

        { &hf_netlogon_user_account_control_dont_require_preauth,
          { "Don't Require PreAuth", "netlogon.user.account_control.dont_require_preauth",
            FT_BOOLEAN, 32, TFS(&user_account_control_dont_require_preauth), 0x00010000,
            "The user account control DONT_REQUIRE_PREAUTH flag", HFILL }},

        { &hf_netlogon_user_account_control_use_des_key_only,
          { "Use DES Key Only", "netlogon.user.account_control.use_des_key_only",
            FT_BOOLEAN, 32, TFS(&user_account_control_use_des_key_only), 0x00008000,
            "The user account control use_des_key_only flag", HFILL }},

        { &hf_netlogon_user_account_control_not_delegated,
          { "Not Delegated", "netlogon.user.account_control.not_delegated",
            FT_BOOLEAN, 32, TFS(&user_account_control_not_delegated), 0x00004000,
            "The user account control not_delegated flag", HFILL }},

        { &hf_netlogon_user_account_control_trusted_for_delegation,
          { "Trusted For Delegation", "netlogon.user.account_control.trusted_for_delegation",
            FT_BOOLEAN, 32, TFS(&user_account_control_trusted_for_delegation), 0x00002000,
            "The user account control trusted_for_delegation flag", HFILL }},

        { &hf_netlogon_user_account_control_smartcard_required,
          { "SmartCard Required", "netlogon.user.account_control.smartcard_required",
            FT_BOOLEAN, 32, TFS(&user_account_control_smartcard_required), 0x00001000,
            "The user account control smartcard_required flag", HFILL }},

        { &hf_netlogon_user_account_control_encrypted_text_password_allowed,
          { "Encrypted Text Password Allowed", "netlogon.user.account_control.encrypted_text_password_allowed",
            FT_BOOLEAN, 32, TFS(&user_account_control_encrypted_text_password_allowed), 0x00000800,
            "The user account control encrypted_text_password_allowed flag", HFILL }},

        { &hf_netlogon_user_account_control_account_auto_locked,
          { "Account Auto Locked", "netlogon.user.account_control.account_auto_locked",
            FT_BOOLEAN, 32, TFS(&user_account_control_account_auto_locked), 0x00000400,
            "The user account control account_auto_locked flag", HFILL }},

        { &hf_netlogon_user_account_control_dont_expire_password,
          { "Don't Expire Password", "netlogon.user.account_control.dont_expire_password",
            FT_BOOLEAN, 32, TFS(&user_account_control_dont_expire_password), 0x00000200,
            "The user account control dont_expire_password flag", HFILL }},

        { &hf_netlogon_user_account_control_server_trust_account,
          { "Server Trust Account", "netlogon.user.account_control.server_trust_account",
            FT_BOOLEAN, 32, TFS(&user_account_control_server_trust_account), 0x00000100,
            "The user account control server_trust_account flag", HFILL }},

        { &hf_netlogon_user_account_control_workstation_trust_account,
          { "Workstation Trust Account", "netlogon.user.account_control.workstation_trust_account",
            FT_BOOLEAN, 32, TFS(&user_account_control_workstation_trust_account), 0x00000080,
            "The user account control workstation_trust_account flag", HFILL }},

        { &hf_netlogon_user_account_control_interdomain_trust_account,
          { "Interdomain trust Account", "netlogon.user.account_control.interdomain_trust_account",
            FT_BOOLEAN, 32, TFS(&user_account_control_interdomain_trust_account), 0x00000040,
            "The user account control interdomain_trust_account flag", HFILL }},

        { &hf_netlogon_user_account_control_mns_logon_account,
          { "MNS Logon Account", "netlogon.user.account_control.mns_logon_account",
            FT_BOOLEAN, 32, TFS(&user_account_control_mns_logon_account), 0x00000020,
            "The user account control mns_logon_account flag", HFILL }},

        { &hf_netlogon_user_account_control_normal_account,
          { "Normal Account", "netlogon.user.account_control.normal_account",
            FT_BOOLEAN, 32, TFS(&user_account_control_normal_account), 0x00000010,
            "The user account control normal_account flag", HFILL }},

        { &hf_netlogon_user_account_control_temp_duplicate_account,
          { "Temp Duplicate Account", "netlogon.user.account_control.temp_duplicate_account",
            FT_BOOLEAN, 32, TFS(&user_account_control_temp_duplicate_account), 0x00000008,
            "The user account control temp_duplicate_account flag", HFILL }},

        { &hf_netlogon_user_account_control_password_not_required,
          { "Password Not Required", "netlogon.user.account_control.password_not_required",
            FT_BOOLEAN, 32, TFS(&user_account_control_password_not_required), 0x00000004,
            "The user account control password_not_required flag", HFILL }},

        { &hf_netlogon_user_account_control_home_directory_required,
          { "Home Directory Required", "netlogon.user.account_control.home_directory_required",
            FT_BOOLEAN, 32, TFS(&user_account_control_home_directory_required), 0x00000002,
            "The user account control home_directory_required flag", HFILL }},

        { &hf_netlogon_user_account_control_account_disabled,
          { "Account Disabled", "netlogon.user.account_control.account_disabled",
            FT_BOOLEAN, 32, TFS(&user_account_control_account_disabled), 0x00000001,
            "The user account control account_disabled flag", HFILL }},

        { &hf_netlogon_dnsdomaininfo,
          { "DnsDomainInfo", "netlogon.dnsdomaininfo", FT_NONE, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},

        { &DnsDomainInfo_sid,
          { "Sid", "lsarpc.lsa_DnsDomainInfo.sid", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &DomainInfo_sid,
          { "Sid", "lsarpc.lsa_DomainInfo.sid", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &DnsDomainInfo_domain_guid,
          { "Domain Guid", "lsarpc.lsa_DnsDomainInfo.domain_guid", FT_GUID, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &DnsDomainInfo_dns_forest,
          { "Dns Forest", "lsarpc.lsa_DnsDomainInfo.dns_forest", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &DnsDomainInfo_dns_domain,
          { "Dns Domain", "lsarpc.lsa_DnsDomainInfo.dns_domain", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &DnsDomainInfo_name,
          { "Name", "lsarpc.lsa_DnsDomainInfo.name", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_netlogon_s4u2proxytarget,
          { "S4U2proxyTarget", "netlogon.s4u2proxytarget", FT_STRING, BASE_NONE,
            NULL, 0, "Target for constrained delegation using s4u2proxy", HFILL }},
        { &hf_netlogon_transitedlistsize,
          { "TransitedListSize", "netlogon.transited_list_size", FT_UINT32, BASE_HEX,
            NULL, 0x0, "Number of elements in the TransitedServices array.", HFILL }},
        { &hf_netlogon_transited_service,
          { "Transited Service", "netlogon.transited_service", FT_STRING, BASE_NONE,
            NULL, 0, "S4U2 Transited Service name", HFILL }},
    };

    static gint *ett[] = {
        &ett_dcerpc_netlogon,
        &ett_authenticate_flags,
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
        &ett_LSA_POLICY_INFO,
        &ett_trust_flags,
        &ett_trust_attribs,
        &ett_get_dcname_request_flags,
        &ett_dc_flags,
        &ett_secchan_nl_auth_message,
        &ett_secchan_nl_auth_message_flags,
        &ett_secchan_verf,
        &ett_group_attrs,
        &ett_user_flags,
        &ett_nt_counted_longs_as_string,
        &ett_user_account_control
    };

    proto_dcerpc_netlogon = proto_register_protocol(
        "Microsoft Network Logon", "RPC_NETLOGON", "rpc_netlogon");

    proto_register_field_array(proto_dcerpc_netlogon, hf,
                               array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_init_routine(netlogon_reassemble_init);

}

static dcerpc_auth_subdissector_fns secchan_auth_fns = {
    dissect_secchan_nl_auth_message,    /* Bind */
    dissect_secchan_nl_auth_message,    /* Bind ACK */
    NULL,                               /* AUTH3 */
    dissect_request_secchan_verf,       /* Request verifier */
    dissect_response_secchan_verf,      /* Response verifier */
    dissect_request_data,               /* Request data */
    dissect_response_data               /* Response data */
};

void
proto_reg_handoff_dcerpc_netlogon(void)
{
    /* Register protocol as dcerpc */
    seen.isseen = FALSE;
    seen.num = 0;
    dcerpc_init_uuid(proto_dcerpc_netlogon, ett_dcerpc_netlogon,
                     &uuid_dcerpc_netlogon, ver_dcerpc_netlogon,
                     dcerpc_netlogon_dissectors, hf_netlogon_opnum);


    register_dcerpc_auth_subdissector(DCE_C_AUTHN_LEVEL_PKT_INTEGRITY,
                                      DCE_C_RPC_AUTHN_PROTOCOL_SEC_CHAN,
                                      &secchan_auth_fns);
    register_dcerpc_auth_subdissector(DCE_C_AUTHN_LEVEL_PKT_PRIVACY,
                                      DCE_C_RPC_AUTHN_PROTOCOL_SEC_CHAN,
                                      &secchan_auth_fns);
}
