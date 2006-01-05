/* packet-dcerpc-wkssvc.c
 * Routines for SMB \\PIPE\\wkssvc packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 * Copyright 2003, Richard Sharpe <rsharpe@richardsharpe.com>
 *
 * $Id$
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
#include "packet-dcerpc-wkssvc.h"
#include "packet-dcerpc-nt.h"
#include "packet-windows-common.h"

static int proto_dcerpc_wkssvc = -1;
static int hf_wkssvc_opnum = -1;
static int hf_wkssvc_server = -1;
static int hf_wkssvc_info_level = -1;
static int hf_wkssvc_platform_id = -1; 
static int hf_wkssvc_net_group = -1;
static int hf_wkssvc_ver_major = -1;
static int hf_wkssvc_ver_minor = -1;
static int hf_wkssvc_lan_root = -1;
static int hf_wkssvc_rc = -1;
static int hf_wkssvc_logged_on_users = -1;
static int hf_wkssvc_pref_max = -1;
static int hf_wkssvc_enum_handle = -1;
static int hf_wkssvc_junk = -1;
static int hf_wkssvc_user_name = -1;
static int hf_wkssvc_num_entries = -1;
static int hf_wkssvc_logon_domain = -1;
static int hf_wkssvc_other_domains = -1;
static int hf_wkssvc_logon_server = -1;
static int hf_wkssvc_entries_read = -1;
static int hf_wkssvc_total_entries = -1;
static int hf_wkssvc_char_wait = -1;
static int hf_wkssvc_collection_time = -1;
static int hf_wkssvc_maximum_collection_count = -1;
static int hf_wkssvc_keep_conn = -1;
static int hf_wkssvc_max_cmds = -1;
static int hf_wkssvc_sess_timeout = -1;
static int hf_wkssvc_siz_char_buf = -1;
static int hf_wkssvc_max_threads = -1;
static int hf_wkssvc_lock_quota = -1;
static int hf_wkssvc_lock_increment = -1;
static int hf_wkssvc_lock_maximum = -1;
static int hf_wkssvc_pipe_increment = -1;
static int hf_wkssvc_pipe_maximum = -1;
static int hf_wkssvc_cache_file_timeout = -1;
static int hf_wkssvc_dormant_file_limit = -1;
static int hf_wkssvc_read_ahead_throughput = -1;
static int hf_wkssvc_num_mailslot_buffers = -1;
static int hf_wkssvc_num_srv_announce_buffers = -1;
static int hf_wkssvc_max_illegal_datagram_events = -1;
static int hf_wkssvc_illegal_datagram_event_reset_frequency = -1;
static int hf_wkssvc_log_election_packets = -1;
static int hf_wkssvc_use_opportunistic_locking = -1; 
static int hf_wkssvc_use_unlock_behind = -1; 
static int hf_wkssvc_use_close_behind = -1; 
static int hf_wkssvc_buf_named_pipes = -1;
static int hf_wkssvc_use_lock_read_unlock = -1;
static int hf_wkssvc_utilize_nt_caching = -1;
static int hf_wkssvc_use_raw_read = -1;
static int hf_wkssvc_use_raw_write = -1;
static int hf_wkssvc_use_write_raw_data = -1;
static int hf_wkssvc_use_encryption = -1; 
static int hf_wkssvc_buf_files_deny_write = -1;
static int hf_wkssvc_buf_read_only_files = -1;
static int hf_wkssvc_force_core_create_mode = -1;
static int hf_wkssvc_use_512_byte_max_transfer = -1;
static int hf_wkssvc_parm_err = -1;
static int hf_wkssvc_errlog_sz = -1;
static int hf_wkssvc_print_buf_time = -1;
static int hf_wkssvc_wrk_heuristics = -1;
static int hf_wkssvc_quality_of_service = -1;
static int hf_wkssvc_number_of_vcs = -1;
static int hf_wkssvc_transport_name = -1;
static int hf_wkssvc_transport_address = -1;
static int hf_wkssvc_wan_ish = -1;
static int hf_wkssvc_domain_to_join = -1;
static int hf_wkssvc_ou_for_computer_account = -1;
static int hf_wkssvc_account_used_for_join = -1;
static int hf_wkssvc_encrypted_password = -1;
static int hf_wkssvc_join_flags = -1;
static int hf_wkssvc_unjoin_flags = -1;
static int hf_wkssvc_rename_flags = -1;
static int hf_wkssvc_join_options_join_type = -1;
static int hf_wkssvc_join_options_acct_create = -1;
static int hf_wkssvc_unjoin_options_acct_delete = -1;
static int hf_wkssvc_join_options_win9x_upgrade = -1;
static int hf_wkssvc_join_options_domain_join_if_joined = -1;
static int hf_wkssvc_join_options_join_unsecure = -1;
static int hf_wkssvc_join_options_machine_pwd_passed = -1;
static int hf_wkssvc_join_options_defer_spn_set = -1;
static int hf_wkssvc_account_used_for_unjoin = -1;
static int hf_wkssvc_alternate_name = -1;
static int hf_wkssvc_account_used_for_alternate_name = -1;
static int hf_wkssvc_reserved = -1;

static gint ett_dcerpc_wkssvc = -1;
static gint ett_dcerpc_wkssvc_join_flags = -1;


static e_uuid_t uuid_dcerpc_wkssvc = {
        0x6bffd098, 0xa112, 0x3610,
        { 0x98, 0x33, 0x46, 0xc3, 0xf8, 0x7e, 0x34, 0x5a }
};

static int
wkssvc_dissect_ENUM_HANDLE(tvbuff_t *tvb, int offset,
			   packet_info *pinfo, proto_tree *tree,
			   guint8 *drep)
{

  offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			      hf_wkssvc_enum_handle, 0);
  return offset;

}

static guint16 ver_dcerpc_wkssvc = 1;

/*
 * IDL typedef struct {
 * IDL   long platform_id;
 * IDL   [string] [unique] wchar_t *server;
 * IDL   [string] [unique] wchar_t *lan_grp;
 * IDL   long ver_major;
 * IDL   long ver_minor;
 * IDL } WKS_INFO_100;
 */
static int
wkssvc_dissect_WKS_INFO_100(tvbuff_t *tvb, int offset,
			    packet_info *pinfo, proto_tree *tree,
			    guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_platform_id, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_wkssvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Net Group", hf_wkssvc_net_group, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_ver_major, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_ver_minor, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long platform_id;
 * IDL   [string] [unique] wchar_t *server;
 * IDL   [string] [unique] wchar_t *lan_grp;
 * IDL   long ver_major;
 * IDL   long ver_minor;
 * IDL   [string] [unique] wchar_t *lan_root;
 * IDL } WKS_INFO_101;
 */
static int
wkssvc_dissect_WKS_INFO_101(tvbuff_t *tvb, int offset,
			    packet_info *pinfo, proto_tree *tree,
			    guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_platform_id, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_wkssvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Net Group", hf_wkssvc_net_group, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_ver_major, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_ver_minor, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Lan Root", hf_wkssvc_lan_root, 0);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long platform_id;
 * IDL   [string] [unique] wchar_t *server;
 * IDL   [string] [unique] wchar_t *lan_grp;
 * IDL   long ver_major;
 * IDL   long ver_minor;
 * IDL   [string] [unique] wchar_t *lan_root;
 * IDL   long logged_on_users;
 * IDL } WKS_INFO_102;
 */
static int
wkssvc_dissect_WKS_INFO_102(tvbuff_t *tvb, int offset,
			    packet_info *pinfo, proto_tree *tree,
			    guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_platform_id, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_wkssvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Net Group", hf_wkssvc_net_group, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_ver_major, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_ver_minor, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Lan Root", hf_wkssvc_lan_root, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_logged_on_users, NULL);

	return offset;
}
/*
 * IDL typedef struct {
 * IDL   long wki502_sess_timeout;
 * IDL } WKS_INFO_502;
 */
static int
wkssvc_dissect_WKS_INFO_502(tvbuff_t *tvb, int offset,
			    packet_info *pinfo, proto_tree *tree,
			    guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_char_wait, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_collection_time, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_maximum_collection_count, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_keep_conn, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_max_cmds, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_sess_timeout, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_siz_char_buf, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_max_threads, NULL);	

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_lock_quota, NULL);	

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_lock_increment, NULL);	

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_lock_maximum, NULL);	

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_pipe_increment, NULL);	

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_pipe_maximum, NULL);	

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_cache_file_timeout, NULL);	

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_dormant_file_limit, NULL);	

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_read_ahead_throughput, NULL);	

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_num_mailslot_buffers, NULL);	

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_num_srv_announce_buffers, NULL);	

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_max_illegal_datagram_events, NULL);	

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			    hf_wkssvc_illegal_datagram_event_reset_frequency, 
				    NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_log_election_packets, NULL);	

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_use_opportunistic_locking, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_use_unlock_behind, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_use_close_behind, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_buf_named_pipes, NULL);			
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_use_lock_read_unlock, NULL);	

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_utilize_nt_caching, NULL);	

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_use_raw_read, NULL);	

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_use_raw_write, NULL);	

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_use_write_raw_data, NULL);	

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_use_encryption, NULL);	

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_buf_files_deny_write, NULL);	

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_buf_read_only_files, NULL);	

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_force_core_create_mode, NULL);	

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_use_512_byte_max_transfer, NULL);	

	return offset;
}

static int
wkssvc_dissect_WKS_INFO_1010(tvbuff_t *tvb, int offset,
			     packet_info *pinfo, proto_tree *tree,
			     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_char_wait, NULL);

	return offset;
}

static int
wkssvc_dissect_WKS_INFO_1011(tvbuff_t *tvb, int offset,
			     packet_info *pinfo, proto_tree *tree,
			     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_collection_time, NULL);

	return offset;
}

static int
wkssvc_dissect_WKS_INFO_1012(tvbuff_t *tvb, int offset,
			     packet_info *pinfo, proto_tree *tree,
			     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_maximum_collection_count, NULL);

	return offset;
}

static int
wkssvc_dissect_WKS_INFO_1013(tvbuff_t *tvb, int offset,
			     packet_info *pinfo, proto_tree *tree,
			     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_keep_conn, NULL);

	return offset;
}

static int
wkssvc_dissect_WKS_INFO_1018(tvbuff_t *tvb, int offset,
			     packet_info *pinfo, proto_tree *tree,
			     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_sess_timeout, NULL);

	return offset;
}

static int
wkssvc_dissect_WKS_INFO_1023(tvbuff_t *tvb, int offset,
			     packet_info *pinfo, proto_tree *tree,
			     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_siz_char_buf, NULL);

	return offset;
}

static int
wkssvc_dissect_WKS_INFO_1027(tvbuff_t *tvb, int offset,
			     packet_info *pinfo, proto_tree *tree,
			     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_errlog_sz, NULL);

	return offset;
}

static int
wkssvc_dissect_WKS_INFO_1033(tvbuff_t *tvb, int offset,
			     packet_info *pinfo, proto_tree *tree,
			     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_max_threads, NULL);

	return offset;
}

/*
 * IDL long NetWkstaGetInfo(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] long level,
 * IDL      [out] [ref] WKS_INFO_UNION *wks
 * IDL );
 */
static int
wkssvc_dissect_netwkstagetinfo_rqst(tvbuff_t *tvb, int offset, 
				    packet_info *pinfo, proto_tree *tree,
				    guint8 *drep)
{
	dcerpc_info *di;
	guint32 level;

	di = pinfo->private_data;

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
					      NDR_POINTER_UNIQUE, "Server", 
					      hf_wkssvc_server, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_wkssvc_info_level, &level);

	if (!check_col(pinfo->cinfo, COL_INFO))
		return offset;

	switch (level) {
		case 100:
			col_append_str(pinfo->cinfo, COL_INFO, ", WKS_INFO_100 level");
			break;
		case 101:
			col_append_str(pinfo->cinfo, COL_INFO, ", WKS_INFO_101 level");
			break;
		case 102:
			col_append_str(pinfo->cinfo, COL_INFO, ", WKS_INFO_102 level");
			break;
		case 502:
			col_append_str(pinfo->cinfo, COL_INFO, ", WKS_INFO_502 level");
			break;
		default:
			col_append_str(pinfo->cinfo, COL_INFO, ", WKS_INFO_xxx level");
	}	

	return offset;

}

/*
 * IDL typedef [switch_type(long)] union {
 * IDL   [case(100)] [unique] WKS_INFO_100 *wks100;
 * IDL   [case(101)] [unique] WKS_INFO_101 *wks101;
 * IDL   [case(102)] [unique] WKS_INFO_102 *wks102;
 * IDL   [case(502)] [unique] WKS_INFO_502 *wks502;
 * IDL   [case(1010)] [unique] WKS_INFO_1010 *wks1010;
 * IDL   [case(1011)] [unique] WKS_INFO_1011 *wks1011;
 * IDL   [case(1012)] [unique] WKS_INFO_1012 *wks1012;
 * IDL   [case(1013)] [unique] WKS_INFO_1013 *wks1013;
 * IDL   [case(1018)] [unique] WKS_INFO_1018 *wks1018;
 * IDL   [case(1023)] [unique] WKS_INFO_1023 *wks1023;
 * IDL   [case(1027)] [unique] WKS_INFO_1027 *wks1027;
 * IDL   [case(1033)] [unique] WKS_INFO_1033 *wks1033;
 * IDL } WKS_INFO_UNION;
 */
static int
wkssvc_dissect_WKS_GETINFO_UNION(tvbuff_t *tvb, int offset,
				 packet_info *pinfo, proto_tree *tree,
				 guint8 *drep)
{
	guint32 level;

	ALIGN_TO_4_BYTES;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_info_level, &level);

	switch(level){
	case 100:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			wkssvc_dissect_WKS_INFO_100,
			NDR_POINTER_UNIQUE, "WKS_INFO_100:", -1);
		break;

	case 101:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			wkssvc_dissect_WKS_INFO_101,
			NDR_POINTER_UNIQUE, "WKS_INFO_101:", -1);
		break;

	case 102:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			wkssvc_dissect_WKS_INFO_102,
			NDR_POINTER_UNIQUE, "WKS_INFO_102:", -1);
		break;

		/* There is a 302 and 402 level, but I am too lazy today */

	case 502:
	        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
					     wkssvc_dissect_WKS_INFO_502,
					     NDR_POINTER_UNIQUE, 
					     "WKS_INFO_502:", -1);
		break;

	case 1010:
	        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
					     wkssvc_dissect_WKS_INFO_1010,
					     NDR_POINTER_UNIQUE, 
					     "WKS_INFO_1010:", -1);
		break;

	case 1011:
	        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
					     wkssvc_dissect_WKS_INFO_1011,
					     NDR_POINTER_UNIQUE, 
					     "WKS_INFO_1011:", -1);
		break;

	case 1012:
	        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
					     wkssvc_dissect_WKS_INFO_1012,
					     NDR_POINTER_UNIQUE, 
					     "WKS_INFO_1012:", -1);
		break;

	case 1013:
	        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
					     wkssvc_dissect_WKS_INFO_1013,
					     NDR_POINTER_UNIQUE, 
					     "WKS_INFO_1013:", -1);
		break;

	case 1018:
	        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
					     wkssvc_dissect_WKS_INFO_1018,
					     NDR_POINTER_UNIQUE, 
					     "WKS_INFO_1018:", -1);
		break;

	case 1023:
	        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
					     wkssvc_dissect_WKS_INFO_1023,
					     NDR_POINTER_UNIQUE, 
					     "WKS_INFO_1023:", -1);
		break;

	case 1027:
	        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
					     wkssvc_dissect_WKS_INFO_1027,
					     NDR_POINTER_UNIQUE, 
					     "WKS_INFO_1027:", -1);
		break;

	case 1033:
	        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
					     wkssvc_dissect_WKS_INFO_1033,
					     NDR_POINTER_UNIQUE, 
					     "WKS_INFO_1033:", -1);
		break;

		/*	case 1018:
	        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
					     wkssvc_dissect_WKS_INFO_1018,
					     NDR_POINTER_UNIQUE, 
					     "WKS_INFO_1018:", -1);
					     break; */

	}

	return offset;

}

static int wkssvc_dissect_netwkstagetinfo_reply(tvbuff_t *tvb, int offset,
						packet_info *pinfo, 
						proto_tree *tree,
						guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			wkssvc_dissect_WKS_GETINFO_UNION,
			NDR_POINTER_REF, "Server Info", -1);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_rc, NULL);

	return offset;
}

/*
 * IDL long NetWkstaSetInfo(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] long level,
 * IDL      [in] [ref] WKS_INFO_UNION *wks,
 * IDL      [out] long parm_err
 * IDL );
 */
static int wkssvc_dissect_netwkstasetinfo_rqst(tvbuff_t *tvb, int offset,
					       packet_info *pinfo, 
					       proto_tree *tree,
					       guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
					      NDR_POINTER_UNIQUE, "Server", 
					      hf_wkssvc_server, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_wkssvc_info_level, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			wkssvc_dissect_WKS_GETINFO_UNION,
			NDR_POINTER_REF, "Server Info", -1);

	return offset;

}

static int wkssvc_dissect_netwkstasetinfo_reply(tvbuff_t *tvb, int offset,
						packet_info *pinfo, 
						proto_tree *tree,
						guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_wkssvc_parm_err, 0);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
	hf_wkssvc_rc, NULL);

	return offset;

}

/*
 * IDL typedef struct {
 * IDL   [string] [unique] wchar_t *dev;
 * IDL } USER_INFO_0;
 */
static int
wkssvc_dissect_USER_INFO_0(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "User Name", 
			hf_wkssvc_user_name, 0);

	return offset;
}

static int
wkssvc_dissect_USER_INFO_0_array(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			wkssvc_dissect_USER_INFO_0);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long EntriesRead;
 * IDL   [size_is(EntriesRead)] [unique] USER_INFO_0 *devs;
 * IDL } USER_INFO_0_CONTAINER;
 */
static int
wkssvc_dissect_USER_INFO_0_CONTAINER(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_wkssvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		wkssvc_dissect_USER_INFO_0_array, NDR_POINTER_UNIQUE,
		"USER_INFO_0 array:", -1);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   [string] [unique] wchar_t *user_name;
 * IDL   [string] [unique] wchar_t *logon_domain;
 * IDL   [string] [unique] wchar_t *other_domains;
 * IDL   [string] [unique] wchar_t *logon_server;
 * IDL } USER_INFO_1;
 */
static int
wkssvc_dissect_USER_INFO_1(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
					      NDR_POINTER_UNIQUE, "User Name", 
					      hf_wkssvc_user_name, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Logon Domain", 
					      hf_wkssvc_logon_domain, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Other Domains", 
					      hf_wkssvc_other_domains, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Logon Server", 
					      hf_wkssvc_logon_server, 0);


	return offset;
}
static int
wkssvc_dissect_USER_INFO_1_array(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			wkssvc_dissect_USER_INFO_1);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long EntriesRead;
 * IDL   [size_is(EntriesRead)] [unique] USER_INFO_1 *devs;
 * IDL } USER_INFO_1_CONTAINER;
 */
static int
wkssvc_dissect_USER_INFO_1_CONTAINER(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_wkssvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		wkssvc_dissect_USER_INFO_1_array, NDR_POINTER_UNIQUE,
		"USER_INFO_1 array:", -1);

	return offset;
}

/*
 * IDL typedef [switch_type(long)] union {
 * IDL   [case(0)] [unique] USER_INFO_0_CONTAINER *dev0;
 * IDL   [case(1)] [unique] USER_INFO_1_CONTAINER *dev1;
 * IDL } CHARDEV_ENUM_UNION;
 */
static int
wkssvc_dissect_USER_ENUM_UNION(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	guint32 level;
	dcerpc_info *di;

	di = pinfo->private_data;

	ALIGN_TO_4_BYTES;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_info_level, &level);

	switch(level){
	case 0:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			wkssvc_dissect_USER_INFO_0_CONTAINER,
			NDR_POINTER_UNIQUE, "USER_INFO_0_CONTAINER:", -1);
		if (check_col(pinfo->cinfo, COL_INFO) && di->ptype == PDU_REQ)
			col_append_str(pinfo->cinfo, COL_INFO, ", USER_INFO_0 level");
		break;
	case 1:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			wkssvc_dissect_USER_INFO_1_CONTAINER,
			NDR_POINTER_UNIQUE, "USER_INFO_1_CONTAINER:", -1);
		if (check_col(pinfo->cinfo, COL_INFO) && di->ptype == PDU_REQ)
			col_append_str(pinfo->cinfo, COL_INFO, ", USER_INFO_1 level");
		break;
	}

	return offset;
}

/*
 * IDL long NetWkstaEnumUsers(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] long level,
 * IDL      [in] [out] [ref] WKS_USER_ENUM_STRUCT *users,
 * IDL      [in] long prefmaxlen,
 * IDL      [out] long *entriesread,
 * IDL      [out] long *totalentries,
 * IDL      [in] [out] [ref] long *resumehandle
 * IDL );
 */
static int
wkssvc_dissect_netwkstaenumusers_rqst(tvbuff_t *tvb, int offset, 
				      packet_info *pinfo, proto_tree *tree,
				      guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
					      NDR_POINTER_UNIQUE, "Server", 
					      hf_wkssvc_server, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_wkssvc_info_level, 0);

  	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			wkssvc_dissect_USER_ENUM_UNION,
			NDR_POINTER_REF, "User Info", -1);
	/* Seems to be junk here ... */
	/*	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, 
				    hf_wkssvc_junk, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
				     wkssvc_dissect_ENUM_HANDLE,
				     NDR_POINTER_UNIQUE, "Junk Handle", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, 
	hf_wkssvc_junk, 0); */

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_wkssvc_pref_max, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
				     wkssvc_dissect_ENUM_HANDLE,
				     NDR_POINTER_UNIQUE, "Enum Handle", -1);

	return offset;

}

static int wkssvc_dissect_netwkstaenumusers_reply(tvbuff_t *tvb, int offset,
						  packet_info *pinfo, 
						  proto_tree *tree,
						  guint8 *drep)
{
        /* There seems to be an info level there first */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_wkssvc_info_level, 0);

  	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			wkssvc_dissect_USER_ENUM_UNION,
			NDR_POINTER_REF, "User Info", -1);

	/* Entries read seems to be in the enum array ... */

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_wkssvc_total_entries, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
				     wkssvc_dissect_ENUM_HANDLE,
				     NDR_POINTER_UNIQUE, "Enum Handle", -1);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
	hf_wkssvc_rc, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long quality_of_service;
 * IDL   long number_of_vcs;
 * IDL   [string] [unique] wchar_t *transport_name;
 * IDL   [string] [unique] wchar_t *transport_address; 
 * IDL   BOOL wan_ish;
 * IDL } TRANSPORT_INFO_0;
 */
static int
wkssvc_dissect_TRANSPORT_INFO_0(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_wkssvc_quality_of_service, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_wkssvc_number_of_vcs, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Transport Name", 
			hf_wkssvc_transport_name, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Transport Address", 
			hf_wkssvc_transport_address, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_wkssvc_wan_ish, 0);

	return offset;
}

static int
wkssvc_dissect_TRANSPORT_INFO_0_array(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			wkssvc_dissect_TRANSPORT_INFO_0);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long EntriesRead;
 * IDL   [size_is(EntriesRead)] [unique] TRANSPORT_INFO_0 *devs;
 * IDL } TRANSPORT_INFO_0_CONTAINER;
 */
static int
wkssvc_dissect_TRANSPORT_INFO_0_CONTAINER(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_wkssvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		wkssvc_dissect_TRANSPORT_INFO_0_array, NDR_POINTER_UNIQUE,
		"TRANSPORT_INFO_0 array:", -1);

	return offset;
}

/*
 * IDL typedef [switch_type(long)] union {
 * IDL   [case(0)] [unique] TRANSPORT_INFO_0_CONTAINER *dev0;
 * IDL } TRANSPORT_ENUM_UNION;
 */
static int
wkssvc_dissect_TRANSPORT_ENUM_UNION(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	guint32 level;

	ALIGN_TO_4_BYTES;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_wkssvc_info_level, &level);

	switch(level){
	case 0:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			wkssvc_dissect_TRANSPORT_INFO_0_CONTAINER,
			NDR_POINTER_UNIQUE, "TRANSPORT_INFO_0_CONTAINER:", -1);
		break;

	}

	return offset;
}

/*
 * IDL long NetWkstaTransportEnum(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] long level,
 * IDL      [in] [out] [ref] WKS_TRANSPORT_ENUM_STRUCT *users,
 * IDL      [in] long prefmaxlen,
 * IDL      [out] long *entriesread,
 * IDL      [out] long *totalentries,
 * IDL      [in] [out] [ref] long *resumehandle
 * IDL );
 */
static int
wkssvc_dissect_netwkstatransportenum_rqst(tvbuff_t *tvb, int offset, 
				      packet_info *pinfo, proto_tree *tree,
				      guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
					      NDR_POINTER_UNIQUE, "Server", 
					      hf_wkssvc_server, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_wkssvc_info_level, 0);

  	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			wkssvc_dissect_TRANSPORT_ENUM_UNION,
			NDR_POINTER_REF, "Transport Info", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_wkssvc_pref_max, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
				     wkssvc_dissect_ENUM_HANDLE,
				     NDR_POINTER_UNIQUE, "Enum Handle", -1);

	return offset;

}

static int wkssvc_dissect_netwkstatransportenum_reply(tvbuff_t *tvb, 
						      int offset,
						      packet_info *pinfo, 
						      proto_tree *tree,
						      guint8 *drep)
{
        /* There seems to be an info level there first */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_wkssvc_info_level, 0);

  	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			wkssvc_dissect_TRANSPORT_ENUM_UNION,
			NDR_POINTER_REF, "Transport Info", -1);

	/* Entries read seems to be in the enum array ... */

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
				    hf_wkssvc_total_entries, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
				     wkssvc_dissect_ENUM_HANDLE,
				     NDR_POINTER_UNIQUE, "Enum Handle", -1);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
	hf_wkssvc_rc, NULL);

	return offset;
}


/*
 * IDL typedef struct {
 * IDL  char element_278[524];
 * IDL } TYPE_30;
 */

static int
wkssvc_dissect_TYPE_30(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;

	if(di->conformant_run){
		return offset;   /* cant modify offset while performing conformant run */
	}

	proto_tree_add_item(tree, hf_wkssvc_encrypted_password, tvb, offset,
		524, TRUE);
	offset += 524;
	
	return offset;		
}



/*
 * IDL
 * IDL long NetrJoinDomain2(
 * IDL       [in] [unique] [string] wchar_t *ServerName,
 * IDL       [in] [string] wchar_t DomainName,
 * IDL       [in] [unique] [string] wchar_t *AccountOU,
 * IDL       [in] [unique] [string] wchar_t *Account,
 * IDL       [in] [unique] TYPE_30 *Encrypted_password,
 * IDL       [in] long JoinOptions
 * IDL );
 */

static const true_false_string join_flags_domain_join = {
	"Join the computer to a domain",
	"Join the computer to a workgroup"
};

static const true_false_string join_flags_acct_create = {
	"Create the account on the domain",
	"Do not create the account"
};

static const true_false_string unjoin_flags_acct_delete = {
	"Delete the account when a domain is left",
	"Do not delete the account when a domain is left"
};

static const true_false_string join_flags_win9x_upgrade = {
	"The join operation is occurring as part of an upgrade of Windows 9x",
	"The join operation is not part of a Windows 9x upgrade"
};

static const true_false_string join_flags_domain_join_if_joined = {
	"Allow a join to a new domain even if the computer is already joined to a domain",
	"Do not allow join to a new domain if the computer is already joined to a domain"
};

static const true_false_string join_flags_unsecure = {
	"Performs an unsecured join",
	"Perform a secured join"
};

static const true_false_string join_flags_machine_pwd_passed = {
	"Set the machine password after domain join to passed password",
	"Do not set the machine password after domain join to passed password"
};

static const true_false_string join_flags_defer_spn_set = {
	"Defer setting of servicePrincipalName and dNSHostName attributes on the computer object until a rename operation",
	"Set servicePrincipalName and dNSHostName attributes on the computer object"
};


static int wkssvc_dissect_netr_join_domain2_rqst(tvbuff_t *tvb, int offset, 
				      packet_info *pinfo, proto_tree *parent_tree,
				      guint8 *drep)
{
	guint32 join_flags = 0;
  	proto_item *item;
	proto_tree *tree = NULL;

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, parent_tree, drep,
					      NDR_POINTER_UNIQUE, "Server", 
					      hf_wkssvc_server, 0);

        offset = dissect_ndr_cvstring(tvb, offset, pinfo, parent_tree, drep,
				      sizeof(guint16), hf_wkssvc_domain_to_join,
				      TRUE, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, parent_tree, drep,
					      NDR_POINTER_UNIQUE, "Computer account OU", 
					      hf_wkssvc_ou_for_computer_account, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, parent_tree, drep,
					      NDR_POINTER_UNIQUE, 
					      "Account used for join operation", 
					      hf_wkssvc_account_used_for_join, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, parent_tree, drep,
		wkssvc_dissect_TYPE_30, NDR_POINTER_UNIQUE, 
		"Encrypted password", -1);

  	join_flags = tvb_get_letohl(tvb, offset);
  	item = proto_tree_add_item(parent_tree, hf_wkssvc_join_flags, tvb, offset, 4, TRUE);
	if (parent_tree) {
		tree = proto_item_add_subtree(item, ett_dcerpc_wkssvc_join_flags);
	}

	proto_tree_add_boolean(tree, hf_wkssvc_join_options_defer_spn_set, tvb, 
			       offset, 4, join_flags);

	proto_tree_add_boolean(tree, hf_wkssvc_join_options_machine_pwd_passed, tvb, 
			       offset, 4, join_flags);

	proto_tree_add_boolean(tree, hf_wkssvc_join_options_join_unsecure, tvb, 
			       offset, 4, join_flags);

	proto_tree_add_boolean(tree, hf_wkssvc_join_options_domain_join_if_joined, 
			       tvb, offset, 4, join_flags);

	proto_tree_add_boolean(tree, hf_wkssvc_join_options_win9x_upgrade, tvb, 
			       offset, 4, join_flags);

	proto_tree_add_boolean(tree, hf_wkssvc_join_options_acct_create, tvb, 
			       offset, 4, join_flags);

	proto_tree_add_boolean(tree, hf_wkssvc_join_options_join_type, tvb, 
			       offset, 4, join_flags);
	offset += 4;

	return offset;
}


static int wkssvc_dissect_netr_join_domain2_reply(tvbuff_t *tvb, int offset, 
				      packet_info *pinfo, proto_tree *tree,
				      guint8 *drep)
{
	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_rc, NULL);

	return offset;
}


/*
 * IDL long NetrUnjoinDomain2(
 * IDL       [in] [unique] [string] wchar_t *ServerName,
 * IDL       [in] [unique] [string] wchar_t *Account
 * IDL       [in] [unique] TYPE_30 *Encrypted_password,
 * IDL       [in] long UnjoinOptions
 * IDL );
 */

static int wkssvc_dissect_netr_unjoin_domain2_rqst(tvbuff_t *tvb, int offset, 
				      packet_info *pinfo, proto_tree *parent_tree,
				      guint8 *drep)
{
	guint32 unjoin_flags = 0;
  	proto_item *item;
	proto_tree *tree = NULL;


        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, parent_tree, drep,
					      NDR_POINTER_UNIQUE, "Server", 
					      hf_wkssvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, parent_tree, drep,
					      NDR_POINTER_UNIQUE, 
					      "Account used for unjoin operation", 
					      hf_wkssvc_account_used_for_unjoin, 0);


	offset = dissect_ndr_pointer(tvb, offset, pinfo, parent_tree, drep,
		wkssvc_dissect_TYPE_30, NDR_POINTER_UNIQUE, 
		"Encrypted password", -1);

  	unjoin_flags = tvb_get_letohl(tvb, offset);
  	item = proto_tree_add_item(parent_tree, hf_wkssvc_unjoin_flags, tvb, offset, 4, TRUE);
	if (parent_tree) {
		tree = proto_item_add_subtree(item, ett_dcerpc_wkssvc_join_flags);
	}

	proto_tree_add_boolean(tree, hf_wkssvc_unjoin_options_acct_delete, tvb, 
			       offset, 4, unjoin_flags);
	offset += 4;

	return offset;

}


static int wkssvc_dissect_netr_unjoin_domain2_reply(tvbuff_t *tvb, int offset, 
				      packet_info *pinfo, proto_tree *tree,
				      guint8 *drep)
{
	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_rc, NULL);

	return offset;
}



/*
 * IDL long NetrRenameMachineInDomain2(
 * IDL       [in] [unique] [string] wchar_t *ServerName,
 * IDL       [in] [unique] [string] wchar_t *NewMachineName,
 * IDL       [in] [unique] [string] wchar_t *Account,
 * IDL       [in] [unique] TYPE_30 *EncryptedPassword,
 * IDL       [in] long RenameOptions
 * IDL );
 */

static int wkssvc_dissect_netr_rename_machine_in_domain2_rqst(tvbuff_t *tvb, int offset, 
				      packet_info *pinfo, proto_tree *parent_tree,
				      guint8 *drep)
{
	guint32 rename_flags = 0;
  	proto_item *item;
	proto_tree *tree = NULL;


        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, parent_tree, drep,
					      NDR_POINTER_UNIQUE, "Server", 
					      hf_wkssvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, parent_tree, drep,
					      NDR_POINTER_UNIQUE, 
					      "New Machine Name", 
					      hf_wkssvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, parent_tree, drep,
					      NDR_POINTER_UNIQUE, 
					      "Account used for rename operation", 
					      hf_wkssvc_account_used_for_unjoin, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, parent_tree, drep,
		wkssvc_dissect_TYPE_30, NDR_POINTER_UNIQUE, 
		"Encrypted password", -1);

  	rename_flags = tvb_get_letohl(tvb, offset);
  	item = proto_tree_add_item(parent_tree, hf_wkssvc_rename_flags, tvb, offset, 4, TRUE);
	if (parent_tree) {
		tree = proto_item_add_subtree(item, ett_dcerpc_wkssvc_join_flags);
	}

	proto_tree_add_boolean(tree, hf_wkssvc_join_options_acct_create, tvb, 
			       offset, 4, rename_flags);
	offset += 4;

	return offset;

}

static int wkssvc_dissect_netr_rename_machine_in_domain2_reply(tvbuff_t *tvb, int offset, 
				      packet_info *pinfo, proto_tree *tree,
				      guint8 *drep)
{
	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_rc, NULL);

	return offset;
}


/*
 * IDL long NetrAddAlternateComputerName(
 * IDL       [in] [unique] [string] wchar_t *ServerName,
 * IDL       [in] [unique] [string] wchar_t *NewAlternateMachineName,
 * IDL       [in] [unique] [string] wchar_t *Account,
 * IDL       [in] [unique] TYPE_30 *EncryptedPassword,
 * IDL       [in] long Reserved
 * IDL );
 */

static int wkssvc_dissect_netr_add_alternate_computername_rqst(tvbuff_t *tvb, int offset, 
				      packet_info *pinfo, proto_tree *tree,
				      guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
					      NDR_POINTER_UNIQUE, "Server", 
					      hf_wkssvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
					      NDR_POINTER_UNIQUE, "New alternate computer name", 
					      hf_wkssvc_alternate_name, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
					      NDR_POINTER_UNIQUE, "Account name", 
					      hf_wkssvc_account_used_for_alternate_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		wkssvc_dissect_TYPE_30, NDR_POINTER_UNIQUE, 
		"Encrypted password", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_reserved, NULL);

	return offset;
}

static int wkssvc_dissect_netr_add_alternate_computername_reply(tvbuff_t *tvb, int offset, 
				      packet_info *pinfo, proto_tree *tree,
				      guint8 *drep)
{
	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_rc, NULL);

	return offset;
}

/*
 * IDL long NetrRemoveAlternateComputerName(
 * IDL       [in] [unique] [string] wchar_t *ServerName,
 * IDL       [in] [unique] [string] wchar_t *AlternateMachineNameToRemove,
 * IDL       [in] [unique] [string] wchar_t *Account,
 * IDL       [in] [unique] TYPE_30 *EncryptedPassword,
 * IDL       [in] long Reserved
 * IDL );
 */

static int wkssvc_dissect_netr_remove_alternate_computername_rqst(tvbuff_t *tvb, int offset, 
				      packet_info *pinfo, proto_tree *tree,
				      guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
					      NDR_POINTER_UNIQUE, "Server", 
					      hf_wkssvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
					      NDR_POINTER_UNIQUE, "Alternate computer name to remove", 
					      hf_wkssvc_alternate_name, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
					      NDR_POINTER_UNIQUE, "Account name", 
					      hf_wkssvc_account_used_for_alternate_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		wkssvc_dissect_TYPE_30, NDR_POINTER_UNIQUE, 
		"Encrypted password", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_reserved, NULL);

	return offset;
}



static int wkssvc_dissect_netr_remove_alternate_computername_reply(tvbuff_t *tvb, int offset, 
				      packet_info *pinfo, proto_tree *tree,
				      guint8 *drep)
{
	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_wkssvc_rc, NULL);

	return offset;
}

static dcerpc_sub_dissector dcerpc_wkssvc_dissectors[] = {
        { WKS_NETRWKSTAGETINFO, "NetrWkstaGetInfo", 
	  wkssvc_dissect_netwkstagetinfo_rqst, 
	  wkssvc_dissect_netwkstagetinfo_reply},
	{ WKS_NETRWKSTASETINFO, "NetrWkstaSetInfo",
	  wkssvc_dissect_netwkstasetinfo_rqst,
	  wkssvc_dissect_netwkstasetinfo_reply},
        { WKS_NETRWKSTAUSERENUM, "NetrWkstaUserEnum",
	  wkssvc_dissect_netwkstaenumusers_rqst,
 	  wkssvc_dissect_netwkstaenumusers_reply},
	{ WKS_NETRWKSTAUSERGETINFO, "NetrWkstaUserGetInfo", NULL, NULL },
	{ WKS_NETRWKSTAUSERSETINFO, "NetrWkstaUserSetInfo", NULL, NULL },
	{ WKS_NETRWKSTATRANSPORTENUM, "NetrWkstaTransportEnum",
	  wkssvc_dissect_netwkstatransportenum_rqst, 
	  wkssvc_dissect_netwkstatransportenum_reply},
	{ WKS_NETRWKSTATRANSPORTADD, "NetrWkstaTransportAdd", NULL, NULL },
	{ WKS_NETRWKSTATRANSPORTDEL, "NetrWkstaTransportDel", NULL, NULL },
	{ WKS_NETRUSEADD, "NetrUseAdd", NULL, NULL },
	{ WKS_NETRUSEGETINFO, "NetrUseGetInfo", NULL, NULL },
	{ WKS_NETRUSEDEL, "NetrUseDel", NULL, NULL },
	{ WKS_NETRUSEENUM, "NetrUseEnum", NULL, NULL },
	{ WKS_NETRMESSAGEBUFFERSEND, "NetrMessageBufferSend", NULL, NULL },
	{ WKS_NETRWORKSTATIONSTATISTICSGET, "NetrWorkstationStatisticsGet", 
	  NULL, NULL },
	{ WKS_NETRLOGONDOMAINNAMEADD, "NetrLogonDomainNameAdd", NULL, NULL },
	{ WKS_NETRLOGONDOMAINNAMEDEL, "NetrLogonDomainNameDel", NULL, NULL },
	{ WKS_NETRJOINDOMAIN, "NetrJoinDomain", NULL, NULL },
	{ WKS_NETRUNJOINDOMAIN, "NetrUnjoinDomain", NULL, NULL },
	{ WKS_NETRRENAMEMACHINEINDOMAIN, "NetrRenameMachineInDomain", 
	  NULL, NULL },
	{ WKS_NETRVALIDATENAME, "NetrValidateName", NULL, NULL },
	{ WKS_NETRGETJOININFORMATION, "NetrGetJoinInformation", NULL, NULL },
	{ WKS_NETRGETJOINABLEOUS, "NetrGetJoinableOUs", NULL, NULL },
	{ WKS_NETRJOINDOMAIN2, "NetrJoinDomain2", 
	  wkssvc_dissect_netr_join_domain2_rqst, 
	  wkssvc_dissect_netr_join_domain2_reply},
	{ WKS_NETRUNJOINDOMAIN2, "NetrUnjoinDomain2", 
	  wkssvc_dissect_netr_unjoin_domain2_rqst,
	  wkssvc_dissect_netr_unjoin_domain2_reply},
	{ WKS_NETRRENAMEMACHINEINDOMAIN2, "NetrRenameMachineInDomain2", 
	  wkssvc_dissect_netr_rename_machine_in_domain2_rqst,
	  wkssvc_dissect_netr_rename_machine_in_domain2_reply},
	{ WKS_NETRVALIDATENAME2, "NetrValidateName2", NULL, NULL },
	{ WKS_NETRGETJOINABLEOUS2, "NetrGetJoinableOUs2", NULL, NULL },
	{ WKS_NETRADDALTERNATECOMPUTERNAME, "NetrAddAlternateComputerName", 
	   wkssvc_dissect_netr_add_alternate_computername_rqst,
	   wkssvc_dissect_netr_add_alternate_computername_reply},
	{ WKS_NETRREMOVEALTERNATECOMPUTERNAME,
	  "NetrRemoveAlternateComputerName", 
	   wkssvc_dissect_netr_remove_alternate_computername_rqst,
	   wkssvc_dissect_netr_remove_alternate_computername_reply},
 	{ WKS_NETRSETPRIMARYCOMPUTERNAME, "NetrSetPrimaryComputerName", 
	  NULL, NULL },
	{ WKS_NETRENUMERATECOMPUTERNAMES, "NetrEnumerateComputerNames", 
	  NULL, NULL },
        {0, NULL, NULL,  NULL }
};

void
proto_register_dcerpc_wkssvc(void)
{
        static hf_register_info hf[] = { 
	  { &hf_wkssvc_opnum,
	    { "Operation", "wkssvc.opnum", FT_UINT16, BASE_DEC,
	      NULL, 0x0, "", HFILL }},
	  { &hf_wkssvc_server,
	    { "Server", "wkssvc.server", FT_STRING, BASE_NONE,
	      NULL, 0x0, "Server Name", HFILL}},
	  { &hf_wkssvc_net_group,
	    { "Net Group", "wkssvc.netgrp", FT_STRING, BASE_NONE,
	      NULL, 0x0, "Net Group", HFILL}},
	  { &hf_wkssvc_info_level,
	    { "Info Level", "wkssvc.info_level", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Info Level", HFILL}},
	  { &hf_wkssvc_platform_id,
	    { "Platform ID", "wkssvc.info.platform_id", FT_UINT32,
	      BASE_DEC, VALS(platform_id_vals), 0x0, "Platform ID", HFILL}},
	  { &hf_wkssvc_ver_major,
	    { "Major Version", "wkssvc.version.major", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Major Version", HFILL}},
	  { &hf_wkssvc_ver_minor,
	    { "Minor Version", "wkssvc.version.minor", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Minor Version", HFILL}},
	  { &hf_wkssvc_lan_root,
	    { "Lan Root", "wkssvc.lan.root", FT_STRING, BASE_NONE,
	      NULL, 0x0, "Lan Root", HFILL}},
	  { &hf_wkssvc_logged_on_users,
	    { "Logged On Users", "wkssvc.logged.on.users", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Logged On Users", HFILL}},
	  { &hf_wkssvc_pref_max, 
	    { "Preferred Max Len", "wkssvc.pref.max.len", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Preferred Max Len", HFILL}},
	  { &hf_wkssvc_junk, 
	    { "Junk", "wkssvc.junk", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Junk", HFILL}},
	  { &hf_wkssvc_enum_handle,
	    { "Enumeration handle", "wkssvc.enum_hnd", FT_BYTES,
	      BASE_HEX, NULL, 0x0, "Enumeration Handle", HFILL}},
	  { &hf_wkssvc_user_name,
	    { "User Name", "wkssvc.user.name", FT_STRING, BASE_NONE,
	      NULL, 0x0, "User Name", HFILL}},
	  { &hf_wkssvc_logon_domain,
	    { "Logon Domain", "wkssvc.logon.domain", FT_STRING, BASE_NONE,
	      NULL, 0x0, "Logon Domain", HFILL}},
	  { &hf_wkssvc_other_domains,
	    { "Other Domains", "wkssvc.other.domains", FT_STRING, BASE_NONE,
	      NULL, 0x0, "Other Domains", HFILL}},
	  { &hf_wkssvc_logon_server,
	    { "Logon Server", "wkssvc.logon.server", FT_STRING, BASE_NONE,
	      NULL, 0x0, "Logon Server", HFILL}},
	  { &hf_wkssvc_rc,
	    { "Return code", "wkssvc.rc", FT_UINT32,
	      BASE_HEX, VALS(DOS_errors), 0x0, "Return Code", HFILL}},
	  { &hf_wkssvc_num_entries, 
	    { "Num Entries", "wkssvc.num.entries", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Num Entries", HFILL}},
	  { &hf_wkssvc_entries_read, 
	    { "Entries Read", "wkssvc.entries.read", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Entries Read", HFILL}},
	  { &hf_wkssvc_total_entries, 
	    { "Total Entries", "wkssvc.total.entries", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Total Entries", HFILL}},
	  { &hf_wkssvc_char_wait, 
	    { "Char Wait", "wkssvc.char.wait", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Char Wait", HFILL}},
	  { &hf_wkssvc_collection_time, 
	    { "Collection Time", "wkssvc.collection.time", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Collection Time", HFILL}},
	  { &hf_wkssvc_maximum_collection_count, 
	    { "Maximum Collection Count", "wkssvc.maximum.collection.count", 
	      FT_INT32,
	      BASE_DEC, NULL, 0x0, "Maximum Collection Count", HFILL}},
	  { &hf_wkssvc_keep_conn, 
	    { "Keep Connection", "wkssvc.keep.connection", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Keep Connection", HFILL}},
	  { &hf_wkssvc_max_cmds, 
	    { "Maximum Commands", "wkssvc.maximum.commands", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Maximum Commands", HFILL}},
	  { &hf_wkssvc_sess_timeout, 
	    { "Session Timeout", "wkssvc.session.timeout", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Session Timeout", HFILL}},
	  { &hf_wkssvc_siz_char_buf, 
	    { "Character Buffer Size", "wkssvc.size.char.buff", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Character Buffer Size", HFILL}},
	  { &hf_wkssvc_max_threads, 
	    { "Maximum Threads", "wkssvc.maximum.threads", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Maximum Threads", HFILL}},
	  { &hf_wkssvc_lock_quota, 
	    { "Lock Quota", "wkssvc.lock.quota", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Lock Quota", HFILL}},
	  { &hf_wkssvc_lock_increment, 
	    { "Lock Increment", "wkssvc.lock.increment", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Lock Increment", HFILL}},
	  { &hf_wkssvc_lock_maximum, 
	    { "Lock Maximum", "wkssvc.lock.maximum", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Lock Maximum", HFILL}},
	  { &hf_wkssvc_pipe_increment, 
	    { "Pipe Increment", "wkssvc.pipe.increment", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Pipe Increment", HFILL}},
	  { &hf_wkssvc_pipe_maximum, 
	    { "Pipe Maximum", "wkssvc.pipe.maximum", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Pipe Maximum", HFILL}},
	  { &hf_wkssvc_cache_file_timeout, 
	    { "Cache File Timeout", "wkssvc.cache.file.timeout", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Cache File Timeout", HFILL}},
	  { &hf_wkssvc_dormant_file_limit, 
	    { "Dormant File Limit", "wkssvc.dormant.file.limit", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Dormant File Limit", HFILL}},
	  { &hf_wkssvc_read_ahead_throughput, 
	    { "Read Ahead Throughput", "wkssvc.read.ahead.throughput", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Read Ahead Throughput", HFILL}},
	  { &hf_wkssvc_num_mailslot_buffers, 
	    { "Num Mailslot Buffers", "wkssvc.num.mailslot.buffers", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Num Mailslot Buffers", HFILL}},
	  { &hf_wkssvc_num_srv_announce_buffers, 
	    { "Num Srv Announce Buffers", "wkssvc.num.srv.announce.buffers", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Num Srv Announce Buffers", HFILL}},
	  { &hf_wkssvc_max_illegal_datagram_events, 
	    { "Max Illegal Datagram Events", "wkssvc.max.illegal.datagram.events", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Max Illegal Datagram Events", HFILL}},
	  { &hf_wkssvc_illegal_datagram_event_reset_frequency, 
	    { "Illegal Datagram Event Reset Frequency", "wkssvc.illegal.datagram.reset.frequency", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Illegal Datagram Event Reset Frequency", HFILL}},
	  { &hf_wkssvc_log_election_packets, 
	    { "Log Election Packets", "wkssvc.log.election.packets", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Log Election Packets", HFILL}},
	  { &hf_wkssvc_use_opportunistic_locking, 
	    { "Use Opportunistic Locking", "wkssvc.use.oplocks", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Use OpLocks", HFILL}},
	  { &hf_wkssvc_use_unlock_behind, 
	    { "Use Lock Behind", "wkssvc.use.lock.behind", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Use Lock Behind", HFILL}},
	  { &hf_wkssvc_use_close_behind, 
	    { "Use Close Behind", "wkssvc.use.close.behind", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Use Close Behind", HFILL}},
	  { &hf_wkssvc_buf_named_pipes, 
	    { "Buffer Named Pipes", "wkssvc.buffer.named.pipes", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Buffer Named Pipes", HFILL}},
	  { &hf_wkssvc_use_lock_read_unlock, 
	    { "Use Lock Read Unlock", "wkssvc.use.lock.read.unlock", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Use Lock Read Unlock", HFILL}},
	  { &hf_wkssvc_utilize_nt_caching, 
	    { "Utilize NT Caching", "wkssvc.utilize.nt.caching", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Utilize NT Caching", HFILL}},
	  { &hf_wkssvc_use_raw_read, 
	    { "Use Raw Read", "wkssvc.use.raw.read", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Use Raw Read", HFILL}},
	  { &hf_wkssvc_use_raw_write, 
	    { "Use Raw Write", "wkssvc.use.raw.write", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Use Raw Write", HFILL}},
	  { &hf_wkssvc_use_write_raw_data, 
	    { "Use Write Raw Data", "wkssvc.use.write.raw.data", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Use Write Raw Data", HFILL}},
	  { &hf_wkssvc_use_encryption, 
	    { "Use Encryption", "wkssvc.use.encryption", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Use Encryption", HFILL}},
	  { &hf_wkssvc_buf_files_deny_write, 
	    { "Buffer Files Deny Write", "wkssvc.buf.files.deny.write", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Buffer Files Deny Write", HFILL}},
	  { &hf_wkssvc_buf_read_only_files, 
	    { "Buffer Files Read Only", "wkssvc.buf.files.read.only", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Buffer Files Read Only", HFILL}},
	  { &hf_wkssvc_force_core_create_mode, 
	    { "Force Core Create Mode", "wkssvc.force.core.create.mode", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Force Core Create Mode", HFILL}},
	  { &hf_wkssvc_use_512_byte_max_transfer, 
	    { "Use 512 Byte Max Transfer", "wkssvc.use.512.byte.max.transfer", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Use 512 Byte Maximum Transfer", HFILL}},
	  { &hf_wkssvc_parm_err, 
	    { "Parameter Error Offset", "wkssvc.parm.err", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Parameter Error Offset", HFILL}},
	  { &hf_wkssvc_errlog_sz, 
	    { "Error Log Size", "wkssvc.errlog.sz", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Error Log Size", HFILL}},
	  { &hf_wkssvc_print_buf_time, 
	    { "Print Buf Time", "wkssvc.print.buf.time", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Print Buff Time", HFILL}},
	  { &hf_wkssvc_wrk_heuristics, 
	    { "Wrk Heuristics", "wkssvc.wrk.heuristics", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Wrk Heuristics", HFILL}},
	  { &hf_wkssvc_quality_of_service, 
	    { "Quality Of Service", "wkssvc.qos", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Quality Of Service", HFILL}},
	  { &hf_wkssvc_number_of_vcs, 
	    { "Number Of VCs", "wkssvc.number.of.vcs", FT_INT32,
	      BASE_DEC, NULL, 0x0, "Number of VSs", HFILL}},
	  { &hf_wkssvc_transport_name,
	    { "Transport Name", "wkssvc.transport.name", FT_STRING, BASE_NONE,
	      NULL, 0x0, "Transport Name", HFILL}},
	  { &hf_wkssvc_transport_address,
	    { "Transport Address", "wkssvc.transport.address", FT_STRING, 
	      BASE_NONE,
	      NULL, 0x0, "Transport Address", HFILL}},
	  { &hf_wkssvc_wan_ish, 
	    { "WAN ish", "wkssvc.wan.ish", FT_INT32,
	      BASE_DEC, NULL, 0x0, "WAN ish", HFILL}},
	  { &hf_wkssvc_domain_to_join,
	    { "Domain or Workgroup to join", "wkssvc.join.domain", FT_STRING, BASE_NONE,
	      NULL, 0x0, "Domain or Workgroup to join", HFILL}},
	  { &hf_wkssvc_ou_for_computer_account,
	    { "Organizational Unit (OU) for computer account", 
	      "wkssvc.join.computer_account_ou", FT_STRING, BASE_NONE,
	      NULL, 0x0, "Organizational Unit (OU) for computer account", HFILL}},
	  { &hf_wkssvc_account_used_for_join,
	    { "Account used for join operations", "wkssvc.join.account_used", FT_STRING, BASE_NONE,
	      NULL, 0x0, "Account used for join operations", HFILL}},
	  { &hf_wkssvc_join_flags,
	    { "Domain join flags", "wkssvc.join.flags",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "Domain join flags", HFILL }},
	  { &hf_wkssvc_unjoin_flags,
	    { "Domain unjoin flags", "wkssvc.unjoin.flags",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "Domain unjoin flags", HFILL }},
	  { &hf_wkssvc_rename_flags,
	    { "Machine rename flags", "wkssvc.rename.flags",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "Machine rename flags", HFILL }},
	  { &hf_wkssvc_join_options_join_type,
	    { "Join type", "wkssvc.join.options.join_type", 
	      FT_BOOLEAN, 32, TFS(&join_flags_domain_join), 0x00000001,
	      "Join type", HFILL}},
	  { &hf_wkssvc_join_options_acct_create,
	    { "Computer account creation", "wkssvc.join.options.account_create", 
	      FT_BOOLEAN, 32, TFS(&join_flags_acct_create), 0x00000002,
	      "Computer account creation", HFILL}},
	  { &hf_wkssvc_unjoin_options_acct_delete,
	    { "Computer account deletion", "wkssvc.unjoin.options.account_delete", 
	      FT_BOOLEAN, 32, TFS(&unjoin_flags_acct_delete), 0x00000004,
	      "Computer account deletion", HFILL}},
	  { &hf_wkssvc_join_options_win9x_upgrade,
	    { "Win9x upgrade", "wkssvc.join.options.win9x_upgrade", 
	      FT_BOOLEAN, 32, TFS(&join_flags_win9x_upgrade), 0x00000010,
	      "Win9x upgrade", HFILL}},
	  { &hf_wkssvc_join_options_domain_join_if_joined,
	    { "New domain join if already joined", 
	      "wkssvc.join.options.domain_join_if_joined", 
	      FT_BOOLEAN, 32, TFS(&join_flags_domain_join_if_joined),
              0x00000020,
	      "New domain join if already joined", HFILL}},
	  { &hf_wkssvc_join_options_join_unsecure,
	    { "Unsecure join", "wkssvc.join.options.insecure_join", 
	      FT_BOOLEAN, 32, TFS(&join_flags_unsecure), 
	      0x00000040, "Unsecure join", HFILL}},
	  { &hf_wkssvc_join_options_machine_pwd_passed,
	    { "Machine pwd passed", "wkssvc.join.options.machine_pwd_passed",
	      FT_BOOLEAN, 32, TFS(&join_flags_machine_pwd_passed), 
	      0x00000080, "Machine pwd passed", HFILL}},
	  { &hf_wkssvc_join_options_defer_spn_set,
	    { "Defer SPN set", "wkssvc.join.options.defer_spn_set",
	      FT_BOOLEAN, 32, TFS(&join_flags_defer_spn_set), 
	      0x00000100, "Defer SPN set", HFILL}},
	  { &hf_wkssvc_account_used_for_unjoin,
	    { "Account used for unjoin operations", 
	       "wkssvc.unjoin.account_used", FT_STRING, BASE_NONE,
	       NULL, 0x0, "Account used for unjoin operations", HFILL}},
	  { &hf_wkssvc_account_used_for_alternate_name,
	    { "Account used for alternate name operations", 
	      "wkssvc.alternate_operations_account", FT_STRING, BASE_NONE,
	      NULL, 0x0, "Account used for alternate name operations", HFILL}},
	  { &hf_wkssvc_alternate_name,
	    { "Alternate computer name", "wkssvc.alternate_computer_name", FT_STRING, BASE_NONE,
	      NULL, 0x0, "Alternate computer name", HFILL}},
	  { &hf_wkssvc_encrypted_password, 
            { "Encrypted password", "wkssvc.crypt_password", FT_BYTES, BASE_HEX,
		NULL, 0, "Encrypted Password", HFILL }},
	  { &hf_wkssvc_reserved,
	    { "Reserved field", "wkssvc.reserved", FT_INT32,
	      BASE_HEX, NULL, 0x0, "Reserved field", HFILL}},
	};
        static gint *ett[] = {
                &ett_dcerpc_wkssvc,
		&ett_dcerpc_wkssvc_join_flags
        };

        proto_dcerpc_wkssvc = proto_register_protocol(
                "Microsoft Workstation Service", "WKSSVC", "wkssvc");

	proto_register_field_array(proto_dcerpc_wkssvc, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dcerpc_wkssvc(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_wkssvc, ett_dcerpc_wkssvc,
                         &uuid_dcerpc_wkssvc, ver_dcerpc_wkssvc,
                         dcerpc_wkssvc_dissectors, hf_wkssvc_opnum);
}
