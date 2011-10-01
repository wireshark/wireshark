/* packet-smb2.c
 * Routines for smb2 packet dissection
 * Ronnie Sahlberg 2005
 *
 * For documentation of this protocol, see:
 *
 * http://wiki.wireshark.org/SMB2
 * http://msdn.microsoft.com/en-us/library/cc246482(PROT.10).aspx
 *
 * If you edit this file, keep the wiki updated as well.
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
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/tap.h>
#include <epan/emem.h>

#include "packet-smb2.h"
#include "packet-dcerpc.h"
#include "packet-ntlmssp.h"
#include "packet-windows-common.h"
#include "packet-smb-common.h"
#include "packet-smb.h"
#include "packet-dcerpc-nt.h"
#include <string.h>



static int proto_smb2 = -1;
static int hf_smb2_cmd = -1;
static int hf_smb2_nt_status = -1;
static int hf_smb2_response_to = -1;
static int hf_smb2_response_in = -1;
static int hf_smb2_time = -1;
static int hf_smb2_header_len = -1;
static int hf_smb2_seqnum = -1;
static int hf_smb2_pid = -1;
static int hf_smb2_tid = -1;
static int hf_smb2_aid = -1;
static int hf_smb2_sesid = -1;
static int hf_smb2_previous_sesid = -1;
static int hf_smb2_flags_response = -1;
static int hf_smb2_flags_async_cmd = -1;
static int hf_smb2_flags_dfs_op = -1;
static int hf_smb2_flags_chained = -1;
static int hf_smb2_flags_signature = -1;
static int hf_smb2_chain_offset = -1;
static int hf_smb2_response_buffer_offset = -1;
static int hf_smb2_security_blob_offset = -1;
static int hf_smb2_security_blob_len = -1;
static int hf_smb2_security_blob = -1;
static int hf_smb2_ioctl_in_data = -1;
static int hf_smb2_ioctl_out_data = -1;
static int hf_smb2_unknown = -1;
static int hf_smb2_twrp_timestamp = -1;
static int hf_smb2_mxac_timestamp = -1;
static int hf_smb2_mxac_status = -1;
static int hf_smb2_qfid_fid = -1;
static int hf_smb2_create_timestamp = -1;
static int hf_smb2_oplock = -1;
static int hf_smb2_close_flags = -1;
static int hf_smb2_notify_flags = -1;
static int hf_smb2_last_access_timestamp = -1;
static int hf_smb2_last_write_timestamp = -1;
static int hf_smb2_last_change_timestamp = -1;
static int hf_smb2_current_time = -1;
static int hf_smb2_boot_time = -1;
static int hf_smb2_filename = -1;
static int hf_smb2_filename_len = -1;
static int hf_smb2_nlinks = -1;
static int hf_smb2_delete_pending = -1;
static int hf_smb2_is_directory = -1;
static int hf_smb2_file_id = -1;
static int hf_smb2_allocation_size = -1;
static int hf_smb2_end_of_file = -1;
static int hf_smb2_tree = -1;
static int hf_smb2_find_pattern = -1;
static int hf_smb2_find_info_level = -1;
static int hf_smb2_find_info_blob = -1;
static int hf_smb2_client_guid = -1;
static int hf_smb2_server_guid = -1;
static int hf_smb2_object_id = -1;
static int hf_smb2_birth_volume_id = -1;
static int hf_smb2_birth_object_id = -1;
static int hf_smb2_domain_id = -1;
static int hf_smb2_class = -1;
static int hf_smb2_infolevel = -1;
static int hf_smb2_infolevel_file_info = -1;
static int hf_smb2_infolevel_fs_info = -1;
static int hf_smb2_infolevel_sec_info = -1;
static int hf_smb2_max_response_size = -1;
static int hf_smb2_max_ioctl_in_size = -1;
static int hf_smb2_max_ioctl_out_size = -1;
static int hf_smb2_required_buffer_size = -1;
static int hf_smb2_response_size = -1;
static int hf_smb2_setinfo_size = -1;
static int hf_smb2_setinfo_offset = -1;
static int hf_smb2_file_basic_info = -1;
static int hf_smb2_file_standard_info = -1;
static int hf_smb2_file_internal_info = -1;
static int hf_smb2_file_ea_info = -1;
static int hf_smb2_file_access_info = -1;
static int hf_smb2_file_rename_info = -1;
static int hf_smb2_file_disposition_info = -1;
static int hf_smb2_file_position_info = -1;
static int hf_smb2_file_info_0f = -1;
static int hf_smb2_file_mode_info = -1;
static int hf_smb2_file_alignment_info = -1;
static int hf_smb2_file_all_info = -1;
static int hf_smb2_file_allocation_info = -1;
static int hf_smb2_file_endoffile_info = -1;
static int hf_smb2_file_alternate_name_info = -1;
static int hf_smb2_file_stream_info = -1;
static int hf_smb2_file_pipe_info = -1;
static int hf_smb2_file_compression_info = -1;
static int hf_smb2_file_network_open_info = -1;
static int hf_smb2_file_attribute_tag_info = -1;
static int hf_smb2_fs_info_01 = -1;
static int hf_smb2_fs_info_03 = -1;
static int hf_smb2_fs_info_04 = -1;
static int hf_smb2_fs_info_05 = -1;
static int hf_smb2_fs_info_06 = -1;
static int hf_smb2_fs_info_07 = -1;
static int hf_smb2_fs_objectid_info = -1;
static int hf_smb2_sec_info_00 = -1;
static int hf_smb2_fid = -1;
static int hf_smb2_write_length = -1;
static int hf_smb2_write_data = -1;
static int hf_smb2_write_flags = -1;
static int hf_smb2_write_flags_write_through = -1;
static int hf_smb2_write_count = -1;
static int hf_smb2_write_remaining = -1;
static int hf_smb2_read_length = -1;
static int hf_smb2_read_remaining = -1;
static int hf_smb2_file_offset = -1;
static int hf_smb2_read_data = -1;
static int hf_smb2_disposition_delete_on_close = -1;
static int hf_smb2_create_disposition = -1;
static int hf_smb2_create_chain_offset = -1;
static int hf_smb2_create_chain_data = -1;
static int hf_smb2_data_offset = -1;
static int hf_smb2_data_length = -1;
static int hf_smb2_extrainfo = -1;
static int hf_smb2_create_action = -1;
static int hf_smb2_create_rep_flags = -1;
static int hf_smb2_create_rep_flags_reparse_point = -1;
static int hf_smb2_next_offset = -1;
static int hf_smb2_ea_size = -1;
static int hf_smb2_ea_flags = -1;
static int hf_smb2_ea_name_len = -1;
static int hf_smb2_ea_data_len = -1;
static int hf_smb2_ea_name = -1;
static int hf_smb2_ea_data = -1;
static int hf_smb2_buffer_code_len = -1;
static int hf_smb2_buffer_code_flags_dyn = -1;
static int hf_smb2_olb_offset = -1;
static int hf_smb2_olb_length = -1;
static int hf_smb2_tag = -1;
static int hf_smb2_impersonation_level = -1;
static int hf_smb2_ioctl_function = -1;
static int hf_smb2_ioctl_function_device = -1;
static int hf_smb2_ioctl_function_access = -1;
static int hf_smb2_ioctl_function_function = -1;
static int hf_smb2_ioctl_function_method = -1;
static int hf_smb2_ioctl_resiliency_timeout = -1;
static int hf_smb2_ioctl_resiliency_reserved = -1;
static int hf_windows_sockaddr_family = -1;
static int hf_windows_sockaddr_port = -1;
static int hf_windows_sockaddr_in_addr = -1;
static int hf_windows_sockaddr_in6_flowinfo = -1;
static int hf_windows_sockaddr_in6_addr = -1;
static int hf_windows_sockaddr_in6_scope_id = -1;
static int hf_smb2_ioctl_network_interface_next_offset = -1;
static int hf_smb2_ioctl_network_interface_index = -1;
static int hf_smb2_ioctl_network_interface_rss_queue_count = -1;
static int hf_smb2_ioctl_network_interface_capabilities = -1;
static int hf_smb2_ioctl_network_interface_capability_rss = -1;
static int hf_smb2_ioctl_network_interface_capability_rdma = -1;
static int hf_smb2_ioctl_network_interface_link_speed = -1;
static int hf_smb2_ioctl_shadow_copy_num_volumes = -1;
static int hf_smb2_ioctl_shadow_copy_num_labels = -1;
static int hf_smb2_ioctl_shadow_copy_count = -1;
static int hf_smb2_ioctl_shadow_copy_label = -1;
static int hf_smb2_compression_format = -1;
static int hf_smb2_FILE_OBJECTID_BUFFER = -1;
static int hf_smb2_lease_key = -1;
static int hf_smb2_lease_state = -1;
static int hf_smb2_lease_state_read_caching = -1;
static int hf_smb2_lease_state_handle_caching = -1;
static int hf_smb2_lease_state_write_caching = -1;
static int hf_smb2_lease_flags = -1;
static int hf_smb2_lease_flags_break_ack_required = -1;
static int hf_smb2_lease_flags_parent_lease_key_set = -1;
static int hf_smb2_lease_flags_break_in_progress = -1;
static int hf_smb2_lease_duration = -1;
static int hf_smb2_parent_lease_key = -1;
static int hf_smb2_lease_epoch = -1;
static int hf_smb2_lease_break_reason = -1;
static int hf_smb2_lease_access_mask_hint = -1;
static int hf_smb2_lease_share_mask_hint = -1;
static int hf_smb2_acct_name = -1;
static int hf_smb2_domain_name = -1;
static int hf_smb2_host_name = -1;
static int hf_smb2_auth_frame = -1;
static int hf_smb2_tcon_frame = -1;
static int hf_smb2_share_type = -1;
static int hf_smb2_signature = -1;
static int hf_smb2_credit_charge = -1;
static int hf_smb2_credits_requested = -1;
static int hf_smb2_credits_granted = -1;
static int hf_smb2_dialect_count = -1;
static int hf_smb2_security_mode = -1;
static int hf_smb2_secmode_flags_sign_required = -1;
static int hf_smb2_secmode_flags_sign_enabled = -1;
static int hf_smb2_ses_req_flags = -1;
static int hf_smb2_ses_req_flags_session_binding = -1;
static int hf_smb2_capabilities = -1;
static int hf_smb2_cap_dfs = -1;
static int hf_smb2_cap_leasing = -1;
static int hf_smb2_cap_large_mtu = -1;
static int hf_smb2_cap_multi_channel = -1;
static int hf_smb2_cap_persistent_handles = -1;
static int hf_smb2_cap_directory_leasing = -1;
static int hf_smb2_dialect = -1;
static int hf_smb2_max_trans_size = -1;
static int hf_smb2_max_read_size = -1;
static int hf_smb2_max_write_size = -1;
static int hf_smb2_channel = -1;
static int hf_smb2_session_flags = -1;
static int hf_smb2_ses_flags_guest = -1;
static int hf_smb2_ses_flags_null = -1;
static int hf_smb2_share_flags = -1;
static int hf_smb2_share_flags_dfs = -1;
static int hf_smb2_share_flags_dfs_root = -1;
static int hf_smb2_share_flags_restrict_exclusive_opens = -1;
static int hf_smb2_share_flags_force_shared_delete = -1;
static int hf_smb2_share_flags_allow_namespace_caching = -1;
static int hf_smb2_share_flags_access_based_dir_enum = -1;
static int hf_smb2_share_flags_force_levelii_oplock = -1;
static int hf_smb2_share_flags_enable_hash_v1 = -1;
static int hf_smb2_share_flags_enable_hash_v2 = -1;
static int hf_smb2_share_caching = -1;
static int hf_smb2_share_caps = -1;
static int hf_smb2_share_caps_dfs = -1;
static int hf_smb2_share_caps_continuous_availability = -1;
static int hf_smb2_create_flags = -1;
static int hf_smb2_lock_count = -1;
static int hf_smb2_min_count = -1;
static int hf_smb2_remaining_bytes = -1;
static int hf_smb2_channel_info_offset = -1;
static int hf_smb2_channel_info_length = -1;
static int hf_smb2_ioctl_flags = -1;
static int hf_smb2_ioctl_is_fsctl = -1;
static int hf_smb2_close_pq_attrib = -1;
static int hf_smb2_notify_watch_tree = -1;
static int hf_smb2_output_buffer_len = -1;
static int hf_smb2_notify_out_data = -1;
static int hf_smb2_find_flags = -1;
static int hf_smb2_find_flags_restart_scans = -1;
static int hf_smb2_find_flags_single_entry = -1;
static int hf_smb2_find_flags_index_specified = -1;
static int hf_smb2_find_flags_reopen = -1;
static int hf_smb2_file_index = -1;
static int hf_smb2_file_directory_info = -1;
static int hf_smb2_both_directory_info = -1;
static int hf_smb2_short_name_len = -1;
static int hf_smb2_short_name = -1;
static int hf_smb2_id_both_directory_info = -1;
static int hf_smb2_full_directory_info = -1;
static int hf_smb2_file_name_info = -1;
static int hf_smb2_lock_info = -1;
static int hf_smb2_lock_length = -1;
static int hf_smb2_lock_flags = -1;
static int hf_smb2_lock_flags_shared = -1;
static int hf_smb2_lock_flags_exclusive = -1;
static int hf_smb2_lock_flags_unlock = -1;
static int hf_smb2_lock_flags_fail_immediately = -1;
static int hf_smb2_dhnq_buffer_reserved = -1;
static int hf_smb2_dh2x_buffer_timeout = -1;
static int hf_smb2_dh2x_buffer_flags = -1;
static int hf_smb2_dh2x_buffer_flags_persistent_handle = -1;
static int hf_smb2_dh2x_buffer_reserved = -1;
static int hf_smb2_dh2x_buffer_create_guid = -1;
static int hf_smb2_APP_INSTANCE_buffer_struct_size = -1;
static int hf_smb2_APP_INSTANCE_buffer_reserved = -1;
static int hf_smb2_APP_INSTANCE_buffer_app_guid = -1;
static int hf_smb2_error_byte_count = -1;
static int hf_smb2_error_data = -1;
static int hf_smb2_error_reserved = -1;
static int hf_smb2_reserved = -1;

static gint ett_smb2 = -1;
static gint ett_smb2_olb = -1;
static gint ett_smb2_ea = -1;
static gint ett_smb2_header = -1;
static gint ett_smb2_command = -1;
static gint ett_smb2_secblob = -1;
static gint ett_smb2_file_basic_info = -1;
static gint ett_smb2_file_standard_info = -1;
static gint ett_smb2_file_internal_info = -1;
static gint ett_smb2_file_ea_info = -1;
static gint ett_smb2_file_access_info = -1;
static gint ett_smb2_file_position_info = -1;
static gint ett_smb2_file_mode_info = -1;
static gint ett_smb2_file_alignment_info = -1;
static gint ett_smb2_file_all_info = -1;
static gint ett_smb2_file_allocation_info = -1;
static gint ett_smb2_file_endoffile_info = -1;
static gint ett_smb2_file_alternate_name_info = -1;
static gint ett_smb2_file_stream_info = -1;
static gint ett_smb2_file_pipe_info = -1;
static gint ett_smb2_file_compression_info = -1;
static gint ett_smb2_file_network_open_info = -1;
static gint ett_smb2_file_attribute_tag_info = -1;
static gint ett_smb2_file_rename_info = -1;
static gint ett_smb2_file_disposition_info = -1;
static gint ett_smb2_file_info_0f = -1;
static gint ett_smb2_fs_info_01 = -1;
static gint ett_smb2_fs_info_03 = -1;
static gint ett_smb2_fs_info_04 = -1;
static gint ett_smb2_fs_info_05 = -1;
static gint ett_smb2_fs_info_06 = -1;
static gint ett_smb2_fs_info_07 = -1;
static gint ett_smb2_fs_objectid_info = -1;
static gint ett_smb2_sec_info_00 = -1;
static gint ett_smb2_tid_tree = -1;
static gint ett_smb2_sesid_tree = -1;
static gint ett_smb2_create_chain_element = -1;
static gint ett_smb2_MxAc_buffer = -1;
static gint ett_smb2_QFid_buffer = -1;
static gint ett_smb2_RqLs_buffer = -1;
static gint ett_smb2_ioctl_function = -1;
static gint ett_smb2_FILE_OBJECTID_BUFFER = -1;
static gint ett_smb2_flags = -1;
static gint ett_smb2_sec_mode = -1;
static gint ett_smb2_capabilities = -1;
static gint ett_smb2_ses_req_flags = -1;
static gint ett_smb2_ses_flags = -1;
static gint ett_smb2_lease_state = -1;
static gint ett_smb2_lease_flags = -1;
static gint ett_smb2_share_flags = -1;
static gint ett_smb2_create_rep_flags = -1;
static gint ett_smb2_share_caps = -1;
static gint ett_smb2_ioctl_flags = -1;
static gint ett_smb2_ioctl_network_interface = -1;
static gint ett_windows_sockaddr = -1;
static gint ett_smb2_close_flags = -1;
static gint ett_smb2_notify_flags = -1;
static gint ett_smb2_write_flags = -1;
static gint ett_smb2_DH2Q_buffer = -1;
static gint ett_smb2_DH2C_buffer = -1;
static gint ett_smb2_dh2x_flags = -1;
static gint ett_smb2_APP_INSTANCE_buffer = -1;
static gint ett_smb2_find_flags = -1;
static gint ett_smb2_file_directory_info = -1;
static gint ett_smb2_both_directory_info = -1;
static gint ett_smb2_id_both_directory_info = -1;
static gint ett_smb2_full_directory_info = -1;
static gint ett_smb2_file_name_info = -1;
static gint ett_smb2_lock_info = -1;
static gint ett_smb2_lock_flags = -1;

static int smb2_tap = -1;

static dissector_handle_t gssapi_handle = NULL;
static dissector_handle_t ntlmssp_handle = NULL;

static heur_dissector_list_t smb2_heur_subdissector_list;

#define SMB2_CLASS_FILE_INFO	0x01
#define SMB2_CLASS_FS_INFO	0x02
#define SMB2_CLASS_SEC_INFO	0x03
static const value_string smb2_class_vals[] = {
	{ SMB2_CLASS_FILE_INFO,	"FILE_INFO"},
	{ SMB2_CLASS_FS_INFO,	"FS_INFO"},
	{ SMB2_CLASS_SEC_INFO,	"SEC_INFO"},
	{ 0, NULL }
};

#define SMB2_SHARE_TYPE_DISK	0x01
#define SMB2_SHARE_TYPE_PIPE	0x02
#define SMB2_SHARE_TYPE_PRINT	0x03
static const value_string smb2_share_type_vals[] = {
	{ SMB2_SHARE_TYPE_DISK,		"Physical disk" },
	{ SMB2_SHARE_TYPE_PIPE,		"Named pipe" },
	{ SMB2_SHARE_TYPE_PRINT,	"Printer" },
	{ 0, NULL }
};


#define SMB2_FILE_BASIC_INFO	0x04
#define SMB2_FILE_STANDARD_INFO	0x05
#define SMB2_FILE_INTERNAL_INFO	0x06
#define SMB2_FILE_EA_INFO	0x07
#define SMB2_FILE_ACCESS_INFO	0x08
#define SMB2_FILE_RENAME_INFO	0x0a
#define SMB2_FILE_DISPOSITION_INFO	0x0d
#define SMB2_FILE_POSITION_INFO	0x0e
#define SMB2_FILE_INFO_0f	0x0f
#define SMB2_FILE_MODE_INFO	0x10
#define SMB2_FILE_ALIGNMENT_INFO	0x11
#define SMB2_FILE_ALL_INFO	0x12
#define SMB2_FILE_ALLOCATION_INFO	0x13
#define SMB2_FILE_ENDOFFILE_INFO	0x14
#define SMB2_FILE_ALTERNATE_NAME_INFO	0x15
#define SMB2_FILE_STREAM_INFO		0x16
#define SMB2_FILE_PIPE_INFO		0x17
#define SMB2_FILE_COMPRESSION_INFO	0x1c
#define SMB2_FILE_NETWORK_OPEN_INFO	0x22
#define SMB2_FILE_ATTRIBUTE_TAG_INFO	0x23
static const value_string smb2_file_info_levels[] = {
	{SMB2_FILE_BASIC_INFO,		"SMB2_FILE_BASIC_INFO" },
	{SMB2_FILE_STANDARD_INFO,	"SMB2_FILE_STANDARD_INFO" },
	{SMB2_FILE_INTERNAL_INFO,	"SMB2_FILE_INTERNAL_INFO" },
	{SMB2_FILE_EA_INFO,		"SMB2_FILE_EA_INFO" },
	{SMB2_FILE_ACCESS_INFO,		"SMB2_FILE_ACCESS_INFO" },
	{SMB2_FILE_RENAME_INFO,		"SMB2_FILE_RENAME_INFO" },
	{SMB2_FILE_DISPOSITION_INFO,	"SMB2_FILE_DISPOSITION_INFO" },
	{SMB2_FILE_POSITION_INFO,	"SMB2_FILE_POSITION_INFO" },
	{SMB2_FILE_INFO_0f,		"SMB2_FILE_INFO_0f" },
	{SMB2_FILE_MODE_INFO,		"SMB2_FILE_MODE_INFO" },
	{SMB2_FILE_ALIGNMENT_INFO,	"SMB2_FILE_ALIGNMENT_INFO" },
	{SMB2_FILE_ALL_INFO,		"SMB2_FILE_ALL_INFO" },
	{SMB2_FILE_ALLOCATION_INFO,	"SMB2_FILE_ALLOCATION_INFO" },
	{SMB2_FILE_ENDOFFILE_INFO,	"SMB2_FILE_ENDOFFILE_INFO" },
	{SMB2_FILE_ALTERNATE_NAME_INFO,	"SMB2_FILE_ALTERNATE_NAME_INFO" },
	{SMB2_FILE_STREAM_INFO,		"SMB2_FILE_STREAM_INFO" },
	{SMB2_FILE_PIPE_INFO,		"SMB2_FILE_PIPE_INFO" },
	{SMB2_FILE_COMPRESSION_INFO,	"SMB2_FILE_COMPRESSION_INFO" },
	{SMB2_FILE_NETWORK_OPEN_INFO,	"SMB2_FILE_NETWORK_OPEN_INFO" },
	{SMB2_FILE_ATTRIBUTE_TAG_INFO,	"SMB2_FILE_ATTRIBUTE_TAG_INFO" },
	{ 0, NULL }
};



#define SMB2_FS_INFO_01		0x01
#define SMB2_FS_INFO_03		0x03
#define SMB2_FS_INFO_04		0x04
#define SMB2_FS_INFO_05		0x05
#define SMB2_FS_INFO_06		0x06
#define SMB2_FS_INFO_07		0x07
#define SMB2_FS_OBJECTID_INFO	0x08
static const value_string smb2_fs_info_levels[] = {
	{SMB2_FS_INFO_01,	"SMB2_FS_INFO_01" },
	{SMB2_FS_INFO_03,	"SMB2_FS_INFO_03" },
	{SMB2_FS_INFO_04,	"SMB2_FS_INFO_04" },
	{SMB2_FS_INFO_05,	"SMB2_FS_INFO_05" },
	{SMB2_FS_INFO_06,	"SMB2_FS_INFO_06" },
	{SMB2_FS_INFO_07,	"SMB2_FS_INFO_07" },
	{SMB2_FS_OBJECTID_INFO,	"SMB2_FS_OBJECTID_INFO" },
	{ 0, NULL }
};

#define SMB2_SEC_INFO_00	0x00
static const value_string smb2_sec_info_levels[] = {
	{SMB2_SEC_INFO_00,	"SMB2_SEC_INFO_00" },
	{ 0, NULL }
};

#define SMB2_FIND_DIRECTORY_INFO         0x01
#define SMB2_FIND_FULL_DIRECTORY_INFO    0x02
#define SMB2_FIND_BOTH_DIRECTORY_INFO    0x03
#define SMB2_FIND_INDEX_SPECIFIED        0x04
#define SMB2_FIND_NAME_INFO              0x0C
#define SMB2_FIND_ID_BOTH_DIRECTORY_INFO 0x25
#define SMB2_FIND_ID_FULL_DIRECTORY_INFO 0x26
static const value_string smb2_find_info_levels[] = {
	{ SMB2_FIND_DIRECTORY_INFO,		"SMB2_FIND_DIRECTORY_INFO" },
	{ SMB2_FIND_FULL_DIRECTORY_INFO,	"SMB2_FIND_FULL_DIRECTORY_INFO" },
	{ SMB2_FIND_BOTH_DIRECTORY_INFO,	"SMB2_FIND_BOTH_DIRECTORY_INFO" },
	{ SMB2_FIND_INDEX_SPECIFIED,		"SMB2_FIND_INDEX_SPECIFIED" },
	{ SMB2_FIND_NAME_INFO,			"SMB2_FIND_NAME_INFO" },
	{ SMB2_FIND_ID_BOTH_DIRECTORY_INFO,	"SMB2_FIND_ID_BOTH_DIRECTORY_INFO" },
	{ SMB2_FIND_ID_FULL_DIRECTORY_INFO,	"SMB2_FIND_ID_FULL_DIRECTORY_INFO" },
	{ 0, NULL }
};

/* unmatched smb_saved_info structures.
   For unmatched smb_saved_info structures we store the smb_saved_info
   structure using the SEQNUM field.
*/
static gint
smb2_saved_info_equal_unmatched(gconstpointer k1, gconstpointer k2)
{
	smb2_saved_info_t *key1 = (smb2_saved_info_t *)k1;
	smb2_saved_info_t *key2 = (smb2_saved_info_t *)k2;
	return key1->seqnum==key2->seqnum;
}
static guint
smb2_saved_info_hash_unmatched(gconstpointer k)
{
	smb2_saved_info_t *key = (smb2_saved_info_t *)k;
	guint32 hash;

	hash=(guint32) (key->seqnum&0xffffffff);
	return hash;
}

/* matched smb_saved_info structures.
   For matched smb_saved_info structures we store the smb_saved_info
   structure using the SEQNUM field.
*/
static gint
smb2_saved_info_equal_matched(gconstpointer k1, gconstpointer k2)
{
	smb2_saved_info_t *key1 = (smb2_saved_info_t *)k1;
	smb2_saved_info_t *key2 = (smb2_saved_info_t *)k2;
	return key1->seqnum==key2->seqnum;
}
static guint
smb2_saved_info_hash_matched(gconstpointer k)
{
	smb2_saved_info_t *key = (smb2_saved_info_t *)k;
	guint32 hash;

	hash=(guint32) (key->seqnum&0xffffffff);
	return hash;
}

/* For Tids of a specific conversation.
   This keeps track of tid->sharename mappings and other information about the
   tid.
   qqq
   We might need to refine this if it occurs that tids are reused on a single
   conversation.   we dont worry about that yet for simplicity
*/
static gint
smb2_tid_info_equal(gconstpointer k1, gconstpointer k2)
{
	smb2_tid_info_t *key1 = (smb2_tid_info_t *)k1;
	smb2_tid_info_t *key2 = (smb2_tid_info_t *)k2;
	return key1->tid==key2->tid;
}
static guint
smb2_tid_info_hash(gconstpointer k)
{
	smb2_tid_info_t *key = (smb2_tid_info_t *)k;
	guint32 hash;

	hash=key->tid;
	return hash;
}

/* For Uids of a specific conversation.
   This keeps track of uid->acct_name mappings and other information about the
   uid.
   qqq
   We might need to refine this if it occurs that uids are reused on a single
   conversation.   we dont worry about that yet for simplicity
*/
static gint
smb2_sesid_info_equal(gconstpointer k1, gconstpointer k2)
{
	smb2_sesid_info_t *key1 = (smb2_sesid_info_t *)k1;
	smb2_sesid_info_t *key2 = (smb2_sesid_info_t *)k2;
	return key1->sesid==key2->sesid;
}
static guint
smb2_sesid_info_hash(gconstpointer k)
{
	smb2_sesid_info_t *key = (smb2_sesid_info_t *)k;
	guint32 hash;

	hash=(guint32)( ((key->sesid>>32)&0xffffffff)+((key->sesid)&0xffffffff) );
	return hash;
}

static int dissect_smb2_file_info_0f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset, smb2_info_t *si);


/* This is a helper to dissect the common string type
 * uint16 offset
 * uint16 length
 * ...
 * char *string
 *
 * This function is called twice, first to decode the offset/length and
 * second time to dissect the actual string.
 * It is done this way since there is no guarantee that we have the full packet and we dont
 * want to abort dissection too early if the packet ends somewhere between the
 * length/offset and the actual buffer.
 *
 */
enum offset_length_buffer_offset_size {
	OLB_O_UINT16_S_UINT16,
	OLB_O_UINT16_S_UINT32,
	OLB_O_UINT32_S_UINT32,
	OLB_S_UINT32_O_UINT32
};
typedef struct _offset_length_buffer_t {
	guint32 off;
	guint32 len;
	int off_offset;
	int len_offset;
	enum offset_length_buffer_offset_size offset_size;
	int hfindex;
} offset_length_buffer_t;
static int
dissect_smb2_olb_length_offset(tvbuff_t *tvb, int offset, offset_length_buffer_t *olb,
			       enum offset_length_buffer_offset_size offset_size, int hfindex)
{
	olb->hfindex=hfindex;
	olb->offset_size=offset_size;
	switch(offset_size){
	case OLB_O_UINT16_S_UINT16:
		olb->off=tvb_get_letohs(tvb, offset);
		olb->off_offset=offset;
		offset += 2;
		olb->len=tvb_get_letohs(tvb, offset);
		olb->len_offset=offset;
		offset += 2;
		break;
	case OLB_O_UINT16_S_UINT32:
		olb->off=tvb_get_letohs(tvb, offset);
		olb->off_offset=offset;
		offset += 2;
		olb->len=tvb_get_letohl(tvb, offset);
		olb->len_offset=offset;
		offset += 4;
		break;
	case OLB_O_UINT32_S_UINT32:
		olb->off=tvb_get_letohl(tvb, offset);
		olb->off_offset=offset;
		offset += 4;
		olb->len=tvb_get_letohl(tvb, offset);
		olb->len_offset=offset;
		offset += 4;
		break;
	case OLB_S_UINT32_O_UINT32:
		olb->len=tvb_get_letohl(tvb, offset);
		olb->len_offset=offset;
		offset += 4;
		olb->off=tvb_get_letohl(tvb, offset);
		olb->off_offset=offset;
		offset += 4;
		break;
	}

	return offset;
}

#define OLB_TYPE_UNICODE_STRING		0x01
#define OLB_TYPE_ASCII_STRING		0x02
static const char *
dissect_smb2_olb_string(packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, offset_length_buffer_t *olb, int type)
{
	int len, off;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	const char *name=NULL;
	guint16 bc;
	int offset;

	offset=olb->off;
	len=olb->len;
	off=olb->off;
	bc=tvb_length_remaining(tvb, offset);


	/* sanity check */
	tvb_ensure_bytes_exist(tvb, off, len);
	if(((off+len)<off)
	|| ((off+len)>(off+tvb_reported_length_remaining(tvb, off)))){
		proto_tree_add_text(tree, tvb, offset, tvb_length_remaining(tvb, offset),
				    "Invalid offset/length. Malformed packet");

		col_append_str(pinfo->cinfo, COL_INFO, " [Malformed packet]");

		return NULL;
	}


	switch(type){
	case OLB_TYPE_UNICODE_STRING:
		name = get_unicode_or_ascii_string(tvb, &off,
			TRUE, &len, TRUE, TRUE, &bc);
		if(!name){
			name="";
		}
		if(parent_tree){
			item = proto_tree_add_string(parent_tree, olb->hfindex, tvb, offset, len, name);
			tree = proto_item_add_subtree(item, ett_smb2_olb);
		}
		break;
	case OLB_TYPE_ASCII_STRING:
		name = get_unicode_or_ascii_string(tvb, &off,
			FALSE, &len, TRUE, TRUE, &bc);
		if(!name){
			name="";
		}
		if(parent_tree){
			item = proto_tree_add_string(parent_tree, olb->hfindex, tvb, offset, len, name);
			tree = proto_item_add_subtree(item, ett_smb2_olb);
		}
		break;
	}

	switch(olb->offset_size){
	case OLB_O_UINT16_S_UINT16:
		proto_tree_add_item(tree, hf_smb2_olb_offset, tvb, olb->off_offset, 2, TRUE);
		proto_tree_add_item(tree, hf_smb2_olb_length, tvb, olb->len_offset, 2, TRUE);
		break;
	case OLB_O_UINT16_S_UINT32:
		proto_tree_add_item(tree, hf_smb2_olb_offset, tvb, olb->off_offset, 2, TRUE);
		proto_tree_add_item(tree, hf_smb2_olb_length, tvb, olb->len_offset, 4, TRUE);
		break;
	case OLB_O_UINT32_S_UINT32:
		proto_tree_add_item(tree, hf_smb2_olb_offset, tvb, olb->off_offset, 4, TRUE);
		proto_tree_add_item(tree, hf_smb2_olb_length, tvb, olb->len_offset, 4, TRUE);
		break;
	case OLB_S_UINT32_O_UINT32:
		proto_tree_add_item(tree, hf_smb2_olb_length, tvb, olb->len_offset, 4, TRUE);
		proto_tree_add_item(tree, hf_smb2_olb_offset, tvb, olb->off_offset, 4, TRUE);
		break;
	}

	return name;
}

static void
dissect_smb2_olb_buffer(packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb,
			offset_length_buffer_t *olb, smb2_info_t *si,
			void (*dissector)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si))
{
	int len, off;
	proto_item *sub_item=NULL;
	proto_tree *sub_tree=NULL;
	tvbuff_t *sub_tvb=NULL;
	int offset;

	offset=olb->off;
	len=olb->len;
	off=olb->off;

	/* sanity check */
	tvb_ensure_bytes_exist(tvb, off, len);
	if(((off+len)<off)
	|| ((off+len)>(off+tvb_reported_length_remaining(tvb, off)))){
		proto_tree_add_text(parent_tree, tvb, offset, tvb_length_remaining(tvb, offset),
				    "Invalid offset/length. Malformed packet");

		col_append_str(pinfo->cinfo, COL_INFO, " [Malformed packet]");

		return;
	}

	/* if we dont want/need a subtree */
	if(olb->hfindex==-1){
		sub_item=parent_tree;
		sub_tree=parent_tree;
	} else {
		if(parent_tree){
			sub_item = proto_tree_add_item(parent_tree, olb->hfindex, tvb, offset, len, TRUE);
			sub_tree = proto_item_add_subtree(sub_item, ett_smb2_olb);
		}
	}

	switch(olb->offset_size){
	case OLB_O_UINT16_S_UINT16:
		proto_tree_add_item(sub_tree, hf_smb2_olb_offset, tvb, olb->off_offset, 2, TRUE);
		proto_tree_add_item(sub_tree, hf_smb2_olb_length, tvb, olb->len_offset, 2, TRUE);
		break;
	case OLB_O_UINT16_S_UINT32:
		proto_tree_add_item(sub_tree, hf_smb2_olb_offset, tvb, olb->off_offset, 2, TRUE);
		proto_tree_add_item(sub_tree, hf_smb2_olb_length, tvb, olb->len_offset, 4, TRUE);
		break;
	case OLB_O_UINT32_S_UINT32:
		proto_tree_add_item(sub_tree, hf_smb2_olb_offset, tvb, olb->off_offset, 4, TRUE);
		proto_tree_add_item(sub_tree, hf_smb2_olb_length, tvb, olb->len_offset, 4, TRUE);
		break;
	case OLB_S_UINT32_O_UINT32:
		proto_tree_add_item(sub_tree, hf_smb2_olb_length, tvb, olb->len_offset, 4, TRUE);
		proto_tree_add_item(sub_tree, hf_smb2_olb_offset, tvb, olb->off_offset, 4, TRUE);
		break;
	}

	if (off == 0 || len == 0) {
		proto_item_append_text(sub_item, ": NO DATA");
		return;
	}

	if (!dissector) {
		return;
	}

	sub_tvb=tvb_new_subset(tvb, off, MIN((int)len, tvb_length_remaining(tvb, off)), len);

	dissector(sub_tvb, pinfo, sub_tree, si);

	return;
}

static int
dissect_smb2_olb_tvb_max_offset(int offset, offset_length_buffer_t *olb)
{
	if (olb->off == 0) {
		return offset;
	}
	return MAX(offset, (int)(olb->off + olb->len));
}

typedef struct _smb2_function {
       int (*request)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si);
       int (*response)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si);
} smb2_function;

static const true_false_string tfs_flags_response = {
	"This is a RESPONSE",
	"This is a REQUEST"
};

static const true_false_string tfs_flags_async_cmd = {
	"This is an ASYNC command",
	"This is a SYNC command"
};

static const true_false_string tfs_flags_dfs_op = {
	"This is a DFS OPERATION",
	"This is a normal operation"
};

static const true_false_string tfs_flags_chained = {
	"This pdu a CHAINED command",
	"This pdu is NOT a chained command"
};

static const true_false_string tfs_flags_signature = {
	"This pdu is SIGNED",
	"This pdu is NOT signed"
};

static const true_false_string tfs_cap_dfs = {
	"This host supports DFS",
	"This host does NOT support DFS"
};

static const true_false_string tfs_cap_leasing = {
	"This host supports LEASING",
	"This host does NOT support LEASING"
};

static const true_false_string tfs_cap_large_mtu = {
	"This host supports LARGE_MTU",
	"This host does NOT support LARGE_MTU"
};

static const true_false_string tfs_cap_multi_channel = {
	"This host supports MULTI CHANNEL",
	"This host does NOT support MULTI CHANNEL"
};

static const true_false_string tfs_cap_persistent_handles = {
	"This host supports PERSISTENT HANDLES",
	"This host does NOT support PERSISTENT HANDLES"
};

static const true_false_string tfs_cap_directory_leasing = {
	"This host supports DIRECTORY LEASING",
	"This host does NOT support DIRECTORY LEASING"
};

static const true_false_string tfs_smb2_ioctl_network_interface_capability_rss = {
	"This interface supports RSS",
	"This interface does not support RSS"
};

static const true_false_string tfs_smb2_ioctl_network_interface_capability_rdma = {
	"This interface supports RDMA",
	"This interface does not support RDMA"
};

static const value_string compression_format_vals[] = {
  { 0, "COMPRESSION_FORMAT_NONE" },
  { 1, "COMPRESSION_FORMAT_DEFAULT" },
  { 2, "COMPRESSION_FORMAT_LZNT1" },
  { 0, NULL }
};


static const value_string smb2_ioctl_vals[] = {
  /* dissector implemented */
  {0x00060194, "FSCTL_DFS_GET_REFERRALS"},
  {0x0011C017, "FSCTL_PIPE_TRANSCEIVE"},
  {0x001401D4, "FSCTL_LMR_REQUEST_RESILIENCY"},
  {0x001401FC, "FSCTL_QUERY_NETWORK_INTERFACE_INFO"},
  {0x00144064, "FSCTL_GET_SHADOW_COPY_DATA"},
  {0x000900C0, "FSCTL_CREATE_OR_GET_OBJECT_ID"},
  {0x0009009C, "FSCTL_GET_OBJECT_ID"},
  {0x000980A0, "FSCTL_DELETE_OBJECT_ID"}, /* no data in/out */
  {0x00098098, "FSCTL_SET_OBJECT_ID"},
  {0x000980BC, "FSCTL_SET_OBJECT_ID_EXTENDED"},
  {0x0009003C, "FSCTL_GET_COMPRESSION"},
  {0x0009C040, "FSCTL_SET_COMPRESSION"},

  /* dissector not yet implemented */
  {0x001440F2, "FSCTL_SRV_COPYCHUNK"},
  {0x00140078, "FSCTL_SRV_REQUEST_RESUME_KEY"},
  {0x001441bb, "FSCTL_SRV_READ_HASH"},
  {0x001480F2, "FSCTL_SRV_COPYCHUNK_WRITE"},
  {0x00090000, "FSCTL_REQUEST_OPLOCK_LEVEL_1"},
  {0x00090004, "FSCTL_REQUEST_OPLOCK_LEVEL_2"},
  {0x00090008, "FSCTL_REQUEST_BATCH_OPLOCK"},
  {0x0009000C, "FSCTL_OPLOCK_BREAK_ACKNOWLEDGE"},
  {0x00090010, "FSCTL_OPBATCH_ACK_CLOSE_PENDING"},
  {0x00090014, "FSCTL_OPLOCK_BREAK_NOTIFY"},
  {0x00090018, "FSCTL_LOCK_VOLUME"},
  {0x0009001C, "FSCTL_UNLOCK_VOLUME"},
  {0x00090020, "FSCTL_DISMOUNT_VOLUME"},
  {0x00090028, "FSCTL_IS_VOLUME_MOUNTED"},
  {0x0009002C, "FSCTL_IS_PATHNAME_VALID"},
  {0x00090030, "FSCTL_MARK_VOLUME_DIRTY"},
  {0x0009003B, "FSCTL_QUERY_RETRIEVAL_POINTERS"},
  {0x0009004F, "FSCTL_MARK_AS_SYSTEM_HIVE"},
  {0x00090050, "FSCTL_OPLOCK_BREAK_ACK_NO_2"},
  {0x00090054, "FSCTL_INVALIDATE_VOLUMES"},
  {0x00090058, "FSCTL_QUERY_FAT_BPB"},
  {0x0009005C, "FSCTL_REQUEST_FILTER_OPLOCK"},
  {0x00090060, "FSCTL_FILESYSTEM_GET_STATISTICS"},
  {0x00090064, "FSCTL_GET_NTFS_VOLUME_DATA"},
  {0x00090068, "FSCTL_GET_NTFS_FILE_RECORD"},
  {0x0009006F, "FSCTL_GET_VOLUME_BITMAP"},
  {0x00090073, "FSCTL_GET_RETRIEVAL_POINTERS"},
  {0x00090074, "FSCTL_MOVE_FILE"},
  {0x00090078, "FSCTL_IS_VOLUME_DIRTY"},
  {0x0009007C, "FSCTL_GET_HFS_INFORMATION"},
  {0x00090083, "FSCTL_ALLOW_EXTENDED_DASD_IO"},
  {0x00090087, "FSCTL_READ_PROPERTY_DATA"},
  {0x0009008B, "FSCTL_WRITE_PROPERTY_DATA"},
  {0x0009008F, "FSCTL_FIND_FILES_BY_SID"},
  {0x00090097, "FSCTL_DUMP_PROPERTY_DATA"},
  {0x000980A4, "FSCTL_SET_REPARSE_POINT"},
  {0x000900A8, "FSCTL_GET_REPARSE_POINT"},
  {0x000980AC, "FSCTL_DELETE_REPARSE_POINT"},
  {0x000940B3, "FSCTL_ENUM_USN_DATA"},
  {0x000940B7, "FSCTL_SECURITY_ID_CHECK"},
  {0x000940BB, "FSCTL_READ_USN_JOURNAL"},
  {0x000980C4, "FSCTL_SET_SPARSE"},
  {0x000980C8, "FSCTL_SET_ZERO_DATA"},
  {0x000940CF, "FSCTL_QUERY_ALLOCATED_RANGES"},
  {0x000980D0, "FSCTL_ENABLE_UPGRADE"},
  {0x000900D4, "FSCTL_SET_ENCRYPTION"},
  {0x000900DB, "FSCTL_ENCRYPTION_FSCTL_IO"},
  {0x000900DF, "FSCTL_WRITE_RAW_ENCRYPTED"},
  {0x000900E3, "FSCTL_READ_RAW_ENCRYPTED"},
  {0x000940E7, "FSCTL_CREATE_USN_JOURNAL"},
  {0x000940EB, "FSCTL_READ_FILE_USN_DATA"},
  {0x000940EF, "FSCTL_WRITE_USN_CLOSE_RECORD"},
  {0x000900F0, "FSCTL_EXTEND_VOLUME"},
  { 0, NULL }
};


static const value_string smb2_ioctl_device_vals[] = {
  { 0x0001, "BEEP" },
  { 0x0002, "CD_ROM" },
  { 0x0003, "CD_ROM_FILE_SYSTEM" },
  { 0x0004, "CONTROLLER" },
  { 0x0005, "DATALINK" },
  { 0x0006, "DFS" },
  { 0x0007, "DISK" },
  { 0x0008, "DISK_FILE_SYSTEM" },
  { 0x0009, "FILE_SYSTEM" },
  { 0x000a, "INPORT_PORT" },
  { 0x000b, "KEYBOARD" },
  { 0x000c, "MAILSLOT" },
  { 0x000d, "MIDI_IN" },
  { 0x000e, "MIDI_OUT" },
  { 0x000f, "MOUSE" },
  { 0x0010, "MULTI_UNC_PROVIDER" },
  { 0x0011, "NAMED_PIPE" },
  { 0x0012, "NETWORK" },
  { 0x0013, "NETWORK_BROWSER" },
  { 0x0014, "NETWORK_FILE_SYSTEM" },
  { 0x0015, "NULL" },
  { 0x0016, "PARALLEL_PORT" },
  { 0x0017, "PHYSICAL_NETCARD" },
  { 0x0018, "PRINTER" },
  { 0x0019, "SCANNER" },
  { 0x001a, "SERIAL_MOUSE_PORT" },
  { 0x001b, "SERIAL_PORT" },
  { 0x001c, "SCREEN" },
  { 0x001d, "SOUND" },
  { 0x001e, "STREAMS" },
  { 0x001f, "TAPE" },
  { 0x0020, "TAPE_FILE_SYSTEM" },
  { 0x0021, "TRANSPORT" },
  { 0x0022, "UNKNOWN" },
  { 0x0023, "VIDEO" },
  { 0x0024, "VIRTUAL_DISK" },
  { 0x0025, "WAVE_IN" },
  { 0x0026, "WAVE_OUT" },
  { 0x0027, "8042_PORT" },
  { 0x0028, "NETWORK_REDIRECTOR" },
  { 0x0029, "BATTERY" },
  { 0x002a, "BUS_EXTENDER" },
  { 0x002b, "MODEM" },
  { 0x002c, "VDM" },
  { 0x002d, "MASS_STORAGE" },
  { 0x002e, "SMB" },
  { 0x002f, "KS" },
  { 0x0030, "CHANGER" },
  { 0x0031, "SMARTCARD" },
  { 0x0032, "ACPI" },
  { 0x0033, "DVD" },
  { 0x0034, "FULLSCREEN_VIDEO" },
  { 0x0035, "DFS_FILE_SYSTEM" },
  { 0x0036, "DFS_VOLUME" },
  { 0x0037, "SERENUM" },
  { 0x0038, "TERMSRV" },
  { 0x0039, "KSEC" },
  { 0, NULL }
};

static const value_string smb2_ioctl_access_vals[] = {
  { 0x00, "FILE_ANY_ACCESS" },
  { 0x01, "FILE_READ_ACCESS" },
  { 0x02, "FILE_WRITE_ACCESS" },
  { 0x03, "FILE_READ_WRITE_ACCESS" },
  { 0, NULL }
};

static const value_string smb2_ioctl_method_vals[] = {
  { 0x00, "METHOD_BUFFERED" },
  { 0x01, "METHOD_IN_DIRECT" },
  { 0x02, "METHOD_OUT_DIRECT" },
  { 0x03, "METHOD_NEITHER" },
  { 0, NULL }
};

/* this is called from both smb and smb2. */
int
dissect_smb2_ioctl_function(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset, guint32 *ioctlfunc)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint32 ioctl_function;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_ioctl_function, tvb, offset, 4, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_ioctl_function);
	}

	ioctl_function=tvb_get_letohl(tvb, offset);
	if (ioctlfunc)
		*ioctlfunc=ioctl_function;
	if(ioctl_function){
		/* device */
		proto_tree_add_item(tree, hf_smb2_ioctl_function_device, tvb, offset, 4, TRUE);
		if (check_col(pinfo->cinfo, COL_INFO)){
			col_append_fstr(
				pinfo->cinfo, COL_INFO, " %s",
				val_to_str((ioctl_function>>16)&0xffff, smb2_ioctl_device_vals,
				"Unknown (0x%08X)"));
		}

		/* access */
		proto_tree_add_item(tree, hf_smb2_ioctl_function_access, tvb, offset, 4, TRUE);

		/* function */
		proto_tree_add_item(tree, hf_smb2_ioctl_function_function, tvb, offset, 4, TRUE);
		if (check_col(pinfo->cinfo, COL_INFO)){
			col_append_fstr(
				pinfo->cinfo, COL_INFO, " Function:0x%04x",
				(ioctl_function>>2)&0x0fff);
		}

		/* method */
		proto_tree_add_item(tree, hf_smb2_ioctl_function_method, tvb, offset, 4, TRUE);
	}

	offset += 4;

	return offset;
}

/* fake the dce/rpc support structures so we can piggy back on
 * dissect_nt_policy_hnd()   since this will allow us
 * a cheap way to track where FIDs are opened, closed
 * and fid->filename mappings
 * if we want to do those things in the future.
 */
#define FID_MODE_OPEN		0
#define FID_MODE_CLOSE		1
#define FID_MODE_USE		2
#define FID_MODE_DHNQ		3
#define FID_MODE_DHNC		4
static int
dissect_smb2_fid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si, int mode)
{
	guint8 drep[4] = { 0x10, 0x00, 0x00, 0x00}; /* fake DREP struct */
	static dcerpc_info di;	/* fake dcerpc_info struct */
	static dcerpc_call_value call_data;
	void *old_private_data;
	e_ctx_hnd policy_hnd;
	proto_item *hnd_item=NULL;
	char *fid_name;
	guint32 open_frame = 0, close_frame = 0;

	di.conformant_run=0;
	/* we need di->call_data->flags.NDR64 == 0 */
	di.call_data=&call_data;
	old_private_data=pinfo->private_data;
	pinfo->private_data=&di;

	switch(mode){
	case FID_MODE_OPEN:
		offset = dissect_nt_guid_hnd(tvb, offset, pinfo, tree, drep, hf_smb2_fid, &policy_hnd, &hnd_item, TRUE, FALSE);
		if(!pinfo->fd->flags.visited){
			if(si->saved && si->saved->extra_info_type==SMB2_EI_FILENAME){
				fid_name = se_strdup_printf("File: %s", (char *)si->saved->extra_info);
			} else {
				fid_name = se_strdup_printf("File: ");
			}
			dcerpc_store_polhnd_name(&policy_hnd, pinfo,
						  fid_name);
		}
		break;
	case FID_MODE_CLOSE:
		offset = dissect_nt_guid_hnd(tvb, offset, pinfo, tree, drep, hf_smb2_fid, &policy_hnd, &hnd_item, FALSE, TRUE);
		break;
	case FID_MODE_USE:
	case FID_MODE_DHNQ:
	case FID_MODE_DHNC:
		offset = dissect_nt_guid_hnd(tvb, offset, pinfo, tree, drep, hf_smb2_fid, &policy_hnd, &hnd_item, FALSE, FALSE);
		break;
	}

	pinfo->private_data=old_private_data;


	/* put the filename in col_info */
	if (dcerpc_fetch_polhnd_data(&policy_hnd, &fid_name, NULL, &open_frame, &close_frame, pinfo->fd->num)) {
		if(fid_name){
			if(hnd_item){
				proto_item_append_text(hnd_item, " %s", fid_name);
			}
			if (check_col(pinfo->cinfo, COL_INFO)){
				col_append_fstr(pinfo->cinfo, COL_INFO, " %s", fid_name);
			}
		}
	}

	return offset;
}


/* this info level is unique to SMB2 and differst from the corresponding
 * SMB_FILE_ALL_INFO in SMB
 */
static int
dissect_smb2_file_all_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int length;
	const char *name="";
	guint16 bc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_all_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_all_info);
	}

	/* create time */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_create_timestamp);

	/* last access */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_access_timestamp);

	/* last write */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_write_timestamp);

	/* last change */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_change_timestamp);

	/* File Attributes */
	offset = dissect_file_ext_attr(tvb, tree, offset);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 4, FALSE);
	offset += 4;

	/* allocation size */
	proto_tree_add_item(tree, hf_smb2_allocation_size, tvb, offset, 8, TRUE);
	offset += 8;

	/* end of file */
	proto_tree_add_item(tree, hf_smb2_end_of_file, tvb, offset, 8, TRUE);
	offset += 8;

	/* number of links */
	proto_tree_add_item(tree, hf_smb2_nlinks, tvb, offset, 4, TRUE);
	offset += 4;

	/* delete pending */
	proto_tree_add_item(tree, hf_smb2_delete_pending, tvb, offset, 1, TRUE);
	offset += 1;

	/* is directory */
	proto_tree_add_item(tree, hf_smb2_is_directory, tvb, offset, 1, TRUE);
	offset += 1;

	/* padding */
	offset += 2;

	/* file id */
	proto_tree_add_item(tree, hf_smb2_file_id, tvb, offset, 8, TRUE);
	offset += 8;

	/* ea size */
	proto_tree_add_item(tree, hf_smb2_ea_size, tvb, offset, 4, TRUE);
	offset += 4;

	/* access mask */
	offset = dissect_smb_access_mask(tvb, tree, offset);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 16, FALSE);
	offset += 16;

	/* file name length */
	length=tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_filename_len, tvb, offset, 2, TRUE);
	offset += 2;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, FALSE);
	offset += 2;

	/* file name */
	if(length){
		bc=tvb_length_remaining(tvb, offset);
		name = get_unicode_or_ascii_string(tvb, &offset,
			TRUE, &length, TRUE, TRUE, &bc);
		if(name){
			proto_tree_add_string(tree, hf_smb2_filename, tvb,
				offset, length, name);
		}

	}
	offset += length;


	return offset;
}


static int
dissect_smb2_file_allocation_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;
	gboolean trunc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_allocation_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_allocation_info);
	}

	bc=tvb_length_remaining(tvb, offset);
	offset = dissect_qsfi_SMB_FILE_ALLOCATION_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}

static int
dissect_smb2_file_endoffile_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;
	gboolean trunc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_endoffile_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_endoffile_info);
	}

	bc=tvb_length_remaining(tvb, offset);
	offset = dissect_qsfi_SMB_FILE_ENDOFFILE_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}

static int
dissect_smb2_file_alternate_name_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;
	gboolean trunc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_alternate_name_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_alternate_name_info);
	}

	bc=tvb_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_NAME_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}


static int
dissect_smb2_file_basic_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_basic_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_basic_info);
	}

	/* create time */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_create_timestamp);

	/* last access */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_access_timestamp);

	/* last write */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_write_timestamp);

	/* last change */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_change_timestamp);

	/* File Attributes */
	offset = dissect_file_ext_attr(tvb, tree, offset);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 4, FALSE);
	offset += 4;

	return offset;
}

static int
dissect_smb2_file_standard_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;
	gboolean trunc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_standard_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_standard_info);
	}

	bc=tvb_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_STANDARD_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}
static int
dissect_smb2_file_internal_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;
	gboolean trunc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_internal_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_internal_info);
	}

	bc=tvb_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_INTERNAL_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}
static int
dissect_smb2_file_mode_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;
	gboolean trunc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_mode_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_mode_info);
	}

	bc=tvb_length_remaining(tvb, offset);
	offset = dissect_qsfi_SMB_FILE_MODE_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}
static int
dissect_smb2_file_alignment_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;
	gboolean trunc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_alignment_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_alignment_info);
	}

	bc=tvb_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_ALIGNMENT_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}
static int
dissect_smb2_file_position_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;
	gboolean trunc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_position_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_position_info);
	}

	bc=tvb_length_remaining(tvb, offset);
	offset = dissect_qsfi_SMB_FILE_POSITION_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}

static int
dissect_smb2_file_access_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_access_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_access_info);
	}

	/* access mask */
	offset = dissect_smb_access_mask(tvb, tree, offset);

	return offset;
}

static int
dissect_smb2_file_ea_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;
	gboolean trunc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_ea_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_ea_info);
	}

	bc=tvb_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_EA_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}

static int
dissect_smb2_file_stream_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;
	gboolean trunc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_stream_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_stream_info);
	}

	bc=tvb_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_STREAM_INFO(tvb, pinfo, tree, offset, &bc, &trunc, TRUE);

	return offset;
}

static int
dissect_smb2_file_pipe_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;
	gboolean trunc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_pipe_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_pipe_info);
	}

	bc=tvb_length_remaining(tvb, offset);
	offset = dissect_sfi_SMB_FILE_PIPE_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}

static int
dissect_smb2_file_compression_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;
	gboolean trunc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_compression_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_compression_info);
	}

	bc=tvb_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_COMPRESSION_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}

static int
dissect_smb2_file_network_open_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;
	gboolean trunc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_network_open_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_network_open_info);
	}


	bc=tvb_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_NETWORK_OPEN_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}

static int
dissect_smb2_file_attribute_tag_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;
	gboolean trunc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_attribute_tag_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_attribute_tag_info);
	}


	bc=tvb_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_ATTRIBUTE_TAG_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}

static const true_false_string tfs_disposition_delete_on_close = {
	"DELETE this file when closed",
	"Normal access, do not delete on close"
};

static int
dissect_smb2_file_disposition_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_disposition_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_disposition_info);
	}

	/* file disposition */
	proto_tree_add_item(tree, hf_smb2_disposition_delete_on_close, tvb, offset, 1, TRUE);

	return offset;
}

static int
dissect_smb2_file_info_0f(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint32 next_offset;
	guint8 ea_name_len, ea_data_len;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_info_0f, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_info_0f);
	}

	while(1){
		int length;
		const char *name="";
		const char *data="";
		guint16 bc;
		int start_offset=offset;
		proto_item *ea_item=NULL;
		proto_tree *ea_tree=NULL;

		if(tree){
			ea_item = proto_tree_add_text(tree, tvb, offset, -1, "EA:");
			ea_tree = proto_item_add_subtree(ea_item, ett_smb2_ea);
		}

		/* next offset */
		next_offset=tvb_get_letohl(tvb, offset);
		proto_tree_add_item(ea_tree, hf_smb2_next_offset, tvb, offset, 4, TRUE);
		offset += 4;

		/* EA flags */
		proto_tree_add_item(ea_tree, hf_smb2_ea_flags, tvb, offset, 1, TRUE);
		offset += 1;

		/* EA Name Length */
		ea_name_len=tvb_get_guint8(tvb, offset);
		proto_tree_add_item(ea_tree, hf_smb2_ea_name_len, tvb, offset, 1, TRUE);
		offset += 1;

		/* EA Data Length */
		ea_data_len=tvb_get_guint8(tvb, offset);
		proto_tree_add_item(ea_tree, hf_smb2_ea_data_len, tvb, offset, 1, TRUE);
		offset += 1;

		/* some unknown bytes */
		proto_tree_add_item(ea_tree, hf_smb2_unknown, tvb, offset, 1, TRUE);
		offset += 1;

		/* ea name */
		length=ea_name_len;
		if(length){
			bc=tvb_length_remaining(tvb, offset);
			name = get_unicode_or_ascii_string(tvb, &offset,
				FALSE, &length, TRUE, TRUE, &bc);
			if(name){
				proto_tree_add_string(ea_tree, hf_smb2_ea_name, tvb,
					offset, length, name);
			}
		}
		offset += ea_name_len;

		/* separator byte */
		offset += 1;

		/* ea data */
		length=ea_data_len;
		if(length){
			bc=tvb_length_remaining(tvb, offset);
			data = get_unicode_or_ascii_string(tvb, &offset,
				FALSE, &length, TRUE, TRUE, &bc);
			if(data){
				proto_tree_add_string(ea_tree, hf_smb2_ea_data, tvb,
					offset, length, data);
			}
		}
		offset += ea_data_len;


		if(ea_item){
			proto_item_append_text(ea_item, " %s := %s", name, data);
		}
		proto_item_set_len(ea_item, offset-start_offset);


		if(!next_offset){
			break;
		}
		if(next_offset>256){
			break;
		}

		offset = start_offset+next_offset;
	}

	return offset;
}

static int
dissect_smb2_file_rename_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int length;
	const char *name="";
	guint16 bc;


	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_rename_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_rename_info);
	}

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 16, FALSE);
	offset += 16;

	/* file name length */
	length=tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_filename_len, tvb, offset, 2, TRUE);
	offset += 2;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, FALSE);
	offset += 2;

	/* file name */
	if(length){
		bc=tvb_length_remaining(tvb, offset);
		name = get_unicode_or_ascii_string(tvb, &offset,
			TRUE, &length, TRUE, TRUE, &bc);
		if(name){
			proto_tree_add_string(tree, hf_smb2_filename, tvb,
				offset, length, name);
		}

		if (check_col(pinfo->cinfo, COL_INFO)){
			col_append_fstr(pinfo->cinfo, COL_INFO, " NewName:%s",
			name);
		}
	}
	offset += length;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 4, FALSE);
	offset += 4;

	return offset;
}

static int
dissect_smb2_sec_info_00(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_sec_info_00, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_sec_info_00);
	}

	/* security descriptor */
	offset = dissect_nt_sec_desc(tvb, offset, pinfo, tree, NULL, TRUE, tvb_length_remaining(tvb, offset), NULL);

	return offset;
}

static int
dissect_smb2_fs_info_05(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_fs_info_05, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_fs_info_05);
	}

	bc=tvb_length_remaining(tvb, offset);
	offset=dissect_qfsi_FS_ATTRIBUTE_INFO(tvb, pinfo, tree, offset, &bc, TRUE);

	return offset;
}

static int
dissect_smb2_fs_info_06(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_fs_info_06, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_fs_info_06);
	}

	bc=tvb_length_remaining(tvb, offset);
	offset=dissect_nt_quota(tvb, tree, offset, &bc);

	return offset;
}

static int
dissect_smb2_FS_OBJECTID_INFO(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_fs_objectid_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_fs_objectid_info);
	}

	/* FILE_OBJECTID_BUFFER */
	offset=dissect_smb2_FILE_OBJECTID_BUFFER(tvb, pinfo, tree, offset);

	return offset;
}

static int
dissect_smb2_fs_info_07(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_fs_info_07, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_fs_info_07);
	}

	bc=tvb_length_remaining(tvb, offset);
	offset=dissect_qfsi_FS_FULL_SIZE_INFO(tvb, pinfo, tree, offset, &bc);

	return offset;
}

static int
dissect_smb2_fs_info_01(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_fs_info_01, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_fs_info_01);
	}


	bc=tvb_length_remaining(tvb, offset);
	offset=dissect_qfsi_FS_VOLUME_INFO(tvb, pinfo, tree, offset, &bc, TRUE);

	return offset;
}

static int
dissect_smb2_fs_info_03(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_fs_info_03, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_fs_info_03);
	}


	bc=tvb_length_remaining(tvb, offset);
	offset=dissect_qfsi_FS_SIZE_INFO(tvb, pinfo, tree, offset, &bc);

	return offset;
}

static int
dissect_smb2_fs_info_04(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_fs_info_04, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_fs_info_04);
	}


	bc=tvb_length_remaining(tvb, offset);
	offset=dissect_qfsi_FS_DEVICE_INFO(tvb, pinfo, tree, offset, &bc);

	return offset;
}

static const value_string oplock_vals[] = {
	{ 0x00, "No oplock" },
	{ 0x01, "Level2 oplock" },
	{ 0x08, "Exclusive oplock" },
	{ 0x09, "Batch oplock" },
	{ 0xff, "Lease" },
	{ 0, NULL }
};

static int
dissect_smb2_oplock(proto_tree *parent_tree, tvbuff_t *tvb, int offset)
{
	proto_tree_add_item(parent_tree, hf_smb2_oplock, tvb, offset, 1, TRUE);

	offset += 1;
	return offset;
}

static int
dissect_smb2_buffercode(proto_tree *tree, tvbuff_t *tvb, int offset, guint16 *length)
{
	guint16 buffer_code;

	/* dissect the first 2 bytes of the command PDU */
	buffer_code = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb2_buffer_code_len, tvb, offset, 2, buffer_code&0xfffe);
	proto_tree_add_item(tree, hf_smb2_buffer_code_flags_dyn, tvb, offset, 2, TRUE);
	offset += 2;

	if(length){
		*length=buffer_code&0xfffe;
	}

	return offset;
}

#define NEGPROT_CAP_DFS		0x00000001
#define NEGPROT_CAP_LEASING	0x00000002
#define NEGPROT_CAP_LARGE_MTU	0x00000004
#define NEGPROT_CAP_MULTI_CHANNEL	0x00000008
#define NEGPROT_CAP_PERSISTENT_HANDLES	0x00000010
#define NEGPROT_CAP_DIRECTORY_LEASING	0x00000020
static int
dissect_smb2_capabilities(proto_tree *parent_tree, tvbuff_t *tvb, int offset)
{
	guint32 cap;
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	cap = tvb_get_letohl(tvb, offset);

	item = proto_tree_add_item(parent_tree, hf_smb2_capabilities, tvb, offset, 4, TRUE);
	tree = proto_item_add_subtree(item, ett_smb2_capabilities);


	proto_tree_add_boolean(tree, hf_smb2_cap_dfs, tvb, offset, 4, cap);
	proto_tree_add_boolean(tree, hf_smb2_cap_leasing, tvb, offset, 4, cap);
	proto_tree_add_boolean(tree, hf_smb2_cap_large_mtu, tvb, offset, 4, cap);
	proto_tree_add_boolean(tree, hf_smb2_cap_multi_channel, tvb, offset, 4, cap);
	proto_tree_add_boolean(tree, hf_smb2_cap_persistent_handles, tvb, offset, 4, cap);
	proto_tree_add_boolean(tree, hf_smb2_cap_directory_leasing, tvb, offset, 4, cap);

	offset += 4;

	return offset;
}



#define NEGPROT_SIGN_REQ	0x0002
#define NEGPROT_SIGN_ENABLED	0x0001

static int
dissect_smb2_secmode(proto_tree *parent_tree, tvbuff_t *tvb, int offset)
{
	guint8 sm;
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	sm = tvb_get_guint8(tvb, offset);

	item = proto_tree_add_item(parent_tree, hf_smb2_security_mode, tvb, offset, 1, TRUE);
	tree = proto_item_add_subtree(item, ett_smb2_sec_mode);


	proto_tree_add_boolean(tree, hf_smb2_secmode_flags_sign_required, tvb, offset, 1, sm);
	proto_tree_add_boolean(tree, hf_smb2_secmode_flags_sign_enabled, tvb, offset, 1, sm);


	offset += 1;

	return offset;
}

#define SES_REQ_FLAGS_SESSION_BINDING		0x01

static int
dissect_smb2_ses_req_flags(proto_tree *parent_tree, tvbuff_t *tvb, int offset)
{
	guint8 sf;
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	sf = tvb_get_guint8(tvb, offset);

	item = proto_tree_add_item(parent_tree, hf_smb2_ses_req_flags, tvb, offset, 1, TRUE);
	tree = proto_item_add_subtree(item, ett_smb2_ses_req_flags);

	proto_tree_add_boolean(tree, hf_smb2_ses_req_flags_session_binding, tvb, offset, 1, sf);

	offset += 1;

	return offset;
}

#define SES_FLAGS_GUEST		0x0001
#define SES_FLAGS_NULL		0x0002

static int
dissect_smb2_ses_flags(proto_tree *parent_tree, tvbuff_t *tvb, int offset)
{
	guint16 sf;
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	sf = tvb_get_letohs(tvb, offset);

	item = proto_tree_add_item(parent_tree, hf_smb2_session_flags, tvb, offset, 2, TRUE);
	tree = proto_item_add_subtree(item, ett_smb2_ses_flags);


	proto_tree_add_boolean(tree, hf_smb2_ses_flags_null, tvb, offset, 2, sf);
	proto_tree_add_boolean(tree, hf_smb2_ses_flags_guest, tvb, offset, 2, sf);


	offset += 2;

	return offset;
}

#define SHARE_FLAGS_manual_caching		0x00000000
#define SHARE_FLAGS_auto_caching		0x00000010
#define SHARE_FLAGS_vdo_caching			0x00000020
#define SHARE_FLAGS_no_caching			0x00000030

static const value_string share_cache_vals[] = {
	{ SHARE_FLAGS_manual_caching,	"Manual caching" },
	{ SHARE_FLAGS_auto_caching,	"Auto caching" },
	{ SHARE_FLAGS_vdo_caching,	"VDO caching" },
	{ SHARE_FLAGS_no_caching,	"No caching" },
	{ 0, NULL }
};

#define SHARE_FLAGS_dfs				0x00000001
#define SHARE_FLAGS_dfs_root			0x00000002
#define SHARE_FLAGS_restrict_exclusive_opens	0x00000100
#define SHARE_FLAGS_force_shared_delete		0x00000200
#define SHARE_FLAGS_allow_namespace_caching	0x00000400
#define SHARE_FLAGS_access_based_dir_enum	0x00000800
#define SHARE_FLAGS_force_levelii_oplock	0x00001000
#define SHARE_FLAGS_enable_hash_v1		0x00002000
#define SHARE_FLAGS_enable_hash_v2		0x00004000

static int
dissect_smb2_share_flags(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	static const int *sf_fields[] = {
		&hf_smb2_share_flags_dfs,
		&hf_smb2_share_flags_dfs_root,
		&hf_smb2_share_flags_restrict_exclusive_opens,
		&hf_smb2_share_flags_force_shared_delete,
		&hf_smb2_share_flags_allow_namespace_caching,
		&hf_smb2_share_flags_access_based_dir_enum,
		&hf_smb2_share_flags_force_levelii_oplock,
		&hf_smb2_share_flags_enable_hash_v1,
		&hf_smb2_share_flags_enable_hash_v2,
		NULL
	};
	proto_item *item;
	guint32 cp;

	item = proto_tree_add_bitmask(tree, tvb, offset, hf_smb2_share_flags, ett_smb2_share_flags, sf_fields, TRUE);

	cp = tvb_get_letohl(tvb, offset);
	cp &= 0x00000030;
	proto_tree_add_uint_format(item, hf_smb2_share_caching, tvb, offset, 4, cp, "Caching policy: %s (%08x)", val_to_str(cp, share_cache_vals, "Unknown:%u"), cp);


	offset += 4;

	return offset;
}

#define SHARE_CAPS_DFS		0x00000008
#define SHARE_CAPS_CONTINUOUS_AVAILABILITY 0x00000010

static int
dissect_smb2_share_caps(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	static const int *sc_fields[] = {
		&hf_smb2_share_caps_dfs,
		&hf_smb2_share_caps_continuous_availability,
		NULL
	};

	proto_tree_add_bitmask(tree, tvb, offset, hf_smb2_share_caps, ett_smb2_share_caps, sc_fields, TRUE);

	offset += 4;

	return offset;
}

static void
dissect_smb2_secblob(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si _U_)
{
	if( (tvb_length(tvb)>=7)
	&&  (!tvb_memeql(tvb, 0, "NTLMSSP", 7))){
		call_dissector(ntlmssp_handle, tvb, pinfo, tree);
	} else {
		call_dissector(gssapi_handle, tvb, pinfo, tree);
	}
	return;
}

static int
dissect_smb2_session_setup_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	offset_length_buffer_t s_olb;
	const ntlmssp_header_t *ntlmssph;
	static int ntlmssp_tap_id = 0;
	int idx;

	if(!ntlmssp_tap_id){
		GString *error_string;
		/* We dont specify any callbacks at all.
		 * Instead we manually fetch the tapped data after the
		 * security blob has been fully dissected and before
		 * we exit from this dissector.
		 */
		error_string=register_tap_listener("ntlmssp", NULL, NULL,
		    TL_IS_DISSECTOR_HELPER, NULL, NULL, NULL);
		if(!error_string){
			ntlmssp_tap_id=find_tap_id("ntlmssp");
		}
	}


	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);
	/* some unknown bytes */

	/* flags */
	offset = dissect_smb2_ses_req_flags(tree, tvb, offset);

	/* security mode */
	offset = dissect_smb2_secmode(tree, tvb, offset);

	/* capabilities */
	offset = dissect_smb2_capabilities(tree, tvb, offset);

	/* channel */
	proto_tree_add_item(tree, hf_smb2_channel, tvb, offset, 4, TRUE);
	offset += 4;

	/* security blob offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &s_olb, OLB_O_UINT16_S_UINT16, hf_smb2_security_blob);

	/* previous session id */
	proto_tree_add_item(tree, hf_smb2_previous_sesid, tvb, offset, 8, TRUE);
	offset += 8;


	/* the security blob itself */
	dissect_smb2_olb_buffer(pinfo, tree, tvb, &s_olb, si, dissect_smb2_secblob);

	offset = dissect_smb2_olb_tvb_max_offset(offset, &s_olb);

	/* If we have found a uid->acct_name mapping, store it */
	if(!pinfo->fd->flags.visited){
		idx=0;
		while((ntlmssph=fetch_tapped_data(ntlmssp_tap_id, idx++)) != NULL){
			if(ntlmssph && ntlmssph->type==3){
				smb2_sesid_info_t *sesid;
				sesid=se_alloc(sizeof(smb2_sesid_info_t));
				sesid->sesid=si->sesid;
				sesid->acct_name=se_strdup(ntlmssph->acct_name);
				sesid->domain_name=se_strdup(ntlmssph->domain_name);
				sesid->host_name=se_strdup(ntlmssph->host_name);
				sesid->auth_frame=pinfo->fd->num;
				sesid->tids= g_hash_table_new(smb2_tid_info_hash, smb2_tid_info_equal);
				g_hash_table_insert(si->conv->sesids, sesid, sesid);
			}
		}
	}

	return offset;
}

static int
dissect_smb2_error_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	gint byte_count;

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);


	/* Reserved (2 bytes) */
	proto_tree_add_item(tree, hf_smb2_error_reserved, tvb, offset, 2, TRUE);
	offset += 2;

	/* ByteCount (4 bytes): The number of bytes of data contained in ErrorData[]. */
	byte_count = tvb_get_ntohl(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_error_byte_count, tvb, offset, 4, TRUE);
	offset += 4;

	/* If the ByteCount field is zero then the server MUST supply an ErrorData field
	   that is one byte in length */
	if (byte_count == 0) byte_count = 1;

	/* ErrorData (variable): A variable-length data field that contains extended
	   error information.*/
	proto_tree_add_item(tree, hf_smb2_error_data, tvb, offset, byte_count, TRUE);
	offset += byte_count;

	return offset;
}

static int
dissect_smb2_session_setup_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	offset_length_buffer_t s_olb;

	/* session_setup is special and we don't use dissect_smb2_error_response() here! */

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* session flags */
	offset = dissect_smb2_ses_flags(tree, tvb, offset);

	/* security blob offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &s_olb, OLB_O_UINT16_S_UINT16, hf_smb2_security_blob);

	/* the security blob itself */
	dissect_smb2_olb_buffer(pinfo, tree, tvb, &s_olb, si, dissect_smb2_secblob);

	offset = dissect_smb2_olb_tvb_max_offset(offset, &s_olb);

	return offset;
}

static int
dissect_smb2_tree_connect_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	offset_length_buffer_t olb;
	const char *buf;

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* reserved */
	offset += 2;

	/* tree  offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &olb, OLB_O_UINT16_S_UINT16, hf_smb2_tree);

	/* tree string */
	buf = dissect_smb2_olb_string(pinfo, tree, tvb, &olb, OLB_TYPE_UNICODE_STRING);

	offset = dissect_smb2_olb_tvb_max_offset(offset, &olb);

	/* treelen  +1 is overkill here if the string is unicode,
	 * but who ever has more than a handful of TCON in a trace anyways
	 */
	if(!pinfo->fd->flags.visited && si->saved && buf && olb.len){
		si->saved->extra_info_type=SMB2_EI_TREENAME;
		si->saved->extra_info=se_alloc(olb.len+1);
		g_snprintf((char *)si->saved->extra_info,olb.len+1,"%s",buf);
	}

	if (check_col(pinfo->cinfo, COL_INFO)){
		col_append_fstr(pinfo->cinfo, COL_INFO, " Tree: %s", buf);
	}


	return offset;
}
static int
dissect_smb2_tree_connect_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	guint16 share_type;

	switch (si->status) {
	case 0x00000000: break;
	default: return dissect_smb2_error_response(tvb, pinfo, tree, offset, si);
	}

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* share type */
	share_type = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_share_type, tvb, offset, 1, TRUE);
	/* Next byte is reserved  and must be set to zero */
	offset += 2;

	if(!pinfo->fd->flags.visited && si->saved && si->saved->extra_info_type==SMB2_EI_TREENAME && si->session) {
		smb2_tid_info_t *tid, tid_key;

		tid_key.tid=si->tid;
		tid=g_hash_table_lookup(si->session->tids, &tid_key);
		if(tid){
			g_hash_table_remove(si->session->tids, &tid_key);
		}
		tid=se_alloc(sizeof(smb2_tid_info_t));
		tid->tid=si->tid;
		tid->name=(char *)si->saved->extra_info;
		tid->connect_frame=pinfo->fd->num;
		tid->share_type=share_type;

		g_hash_table_insert(si->session->tids, tid, tid);

		si->saved->extra_info_type=SMB2_EI_NONE;
		si->saved->extra_info=NULL;
	}

	/* share flags */
	offset = dissect_smb2_share_flags(tree, tvb, offset);

	/* share capabilities */
	offset = dissect_smb2_share_caps(tree, tvb, offset);

	/* this is some sort of access mask */
	offset = dissect_smb_access_mask(tvb, tree, offset);

	return offset;
}

static int
dissect_smb2_tree_disconnect_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* reserved */
	offset += 2;

	return offset;
}

static int
dissect_smb2_tree_disconnect_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	switch (si->status) {
	case 0x00000000: break;
	default: return dissect_smb2_error_response(tvb, pinfo, tree, offset, si);
	}

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* reserved */
	offset += 2;

	return offset;
}

static int
dissect_smb2_sessionlogoff_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* reserved bytes */
	offset += 2;

	return offset;
}

static int
dissect_smb2_sessionlogoff_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	switch (si->status) {
	case 0x00000000: break;
	default: return dissect_smb2_error_response(tvb, pinfo, tree, offset, si);
	}

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* reserved bytes */
	offset += 2;

	return offset;
}

static int
dissect_smb2_keepalive_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;

	return offset;
}

static int
dissect_smb2_keepalive_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	switch (si->status) {
	case 0x00000000: break;
	default: return dissect_smb2_error_response(tvb, pinfo, tree, offset, si);
	}

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;

	return offset;
}

static int
dissect_smb2_notify_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	proto_tree *flags_tree = NULL;
	proto_item *flags_item = NULL;

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* notify flags */
	if (tree) {
		flags_item = proto_tree_add_item(tree, hf_smb2_notify_flags, tvb, offset, 2, TRUE);
		flags_tree = proto_item_add_subtree(flags_item, ett_smb2_notify_flags);
	}
	proto_tree_add_item(flags_tree, hf_smb2_notify_watch_tree, tvb, offset, 2, TRUE);
	offset += 2;

	/* output buffer length */
	proto_tree_add_item(tree, hf_smb2_output_buffer_len, tvb, offset, 4, TRUE);
	offset += 4;

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

	/* completion filter */
	offset = dissect_nt_notify_completion_filter(tvb, tree, offset);

	/* reserved */
	offset += 4;

	return offset;
}

static void
dissect_smb2_notify_data_out(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, smb2_info_t *si _U_)
{
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, 0, tvb_length(tvb), TRUE);
}

static int
dissect_smb2_notify_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si)
{
	offset_length_buffer_t olb;

	switch (si->status) {
	case 0x00000000: break;
	default: return dissect_smb2_error_response(tvb, pinfo, tree, offset, si);
	}

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* out buffer offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &olb, OLB_O_UINT16_S_UINT32, hf_smb2_notify_out_data);

	/* out buffer */
	dissect_smb2_olb_buffer(pinfo, tree, tvb, &olb, si, dissect_smb2_notify_data_out);
	offset = dissect_smb2_olb_tvb_max_offset(offset, &olb);

	return offset;
}

#define SMB2_FIND_FLAG_RESTART_SCANS		0x01
#define SMB2_FIND_FLAG_SINGLE_ENTRY		0x02
#define SMB2_FIND_FLAG_INDEX_SPECIFIED		0x04
#define SMB2_FIND_FLAG_REOPEN			0x10

static int
dissect_smb2_find_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	offset_length_buffer_t olb;
	const char *buf;
	guint8 il;
	static const int *f_fields[] = {
		&hf_smb2_find_flags_restart_scans,
		&hf_smb2_find_flags_single_entry,
		&hf_smb2_find_flags_index_specified,
		&hf_smb2_find_flags_reopen,
		NULL
	};

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	il=tvb_get_guint8(tvb, offset);
	if(si->saved){
		si->saved->infolevel=il;
	}

	/* infolevel */
	proto_tree_add_uint(tree, hf_smb2_find_info_level, tvb, offset, 1, il);
	offset += 1;

	/* find flags */
	proto_tree_add_bitmask(tree, tvb, offset, hf_smb2_find_flags, ett_smb2_find_flags, f_fields, TRUE);
	offset += 1;

	/* file index */
	proto_tree_add_item(tree, hf_smb2_file_index, tvb, offset, 4, TRUE);
	offset += 4;

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

	/* search pattern  offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &olb, OLB_O_UINT16_S_UINT16, hf_smb2_find_pattern);

	/* output buffer length */
	proto_tree_add_item(tree, hf_smb2_output_buffer_len, tvb, offset, 4, TRUE);
	offset += 4;

	/* search pattern */
	buf = dissect_smb2_olb_string(pinfo, tree, tvb, &olb, OLB_TYPE_UNICODE_STRING);

	offset = dissect_smb2_olb_tvb_max_offset(offset, &olb);

	if(!pinfo->fd->flags.visited && si->saved && olb.len){
		si->saved->extra_info_type=SMB2_EI_FINDPATTERN;
		si->saved->extra_info=g_malloc(olb.len+1);
		g_snprintf((char *)si->saved->extra_info,olb.len+1,"%s",buf);
	}

	if (check_col(pinfo->cinfo, COL_INFO)){
		col_append_fstr(pinfo->cinfo, COL_INFO, " %s Pattern: %s",
			val_to_str(il, smb2_find_info_levels, "(Level:0x%02x)"),
			buf);
	}

	return offset;
}

static void dissect_smb2_file_directory_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, smb2_info_t *si _U_)
{
	int offset = 0;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	const char *name=NULL;
	guint16 bc;

	while(tvb_length_remaining(tvb, offset) > 4){
		int old_offset = offset;
		int next_offset;
		int file_name_len;

		if(parent_tree){
			item = proto_tree_add_item(parent_tree, hf_smb2_file_directory_info, tvb, offset, -1, TRUE);
			tree = proto_item_add_subtree(item, ett_smb2_file_directory_info);
		}

		/* next offset */
		next_offset = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_next_offset, tvb, offset, 4, TRUE);
		offset += 4;

		/* file index */
		proto_tree_add_item(tree, hf_smb2_file_index, tvb, offset, 4, TRUE);
		offset += 4;

		/* create time */
		offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_create_timestamp);

		/* last access */
		offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_access_timestamp);

		/* last write */
		offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_write_timestamp);

		/* last change */
		offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_change_timestamp);

		/* end of file */
		proto_tree_add_item(tree, hf_smb2_end_of_file, tvb, offset, 8, TRUE);
		offset += 8;

		/* allocation size */
		proto_tree_add_item(tree, hf_smb2_allocation_size, tvb, offset, 8, TRUE);
		offset += 8;

		/* File Attributes */
		offset = dissect_file_ext_attr(tvb, tree, offset);

		/* file name length */
		file_name_len=tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_filename_len, tvb, offset, 4, TRUE);
		offset += 4;

		/* file name */
		if(file_name_len){
			bc=file_name_len;
			name = get_unicode_or_ascii_string(tvb, &offset,
				TRUE, &file_name_len, TRUE, TRUE, &bc);
			if(name){
				proto_tree_add_string(tree, hf_smb2_filename, tvb,
					offset, file_name_len, name);
				proto_item_append_text(item, ": %s", name);

			}
		}

		proto_item_set_len(item, offset-old_offset);

		if (next_offset == 0){
			return;
		}

		offset = old_offset+next_offset;
		if (offset < old_offset) {
			proto_tree_add_text(tree, tvb, offset, tvb_length_remaining(tvb, offset),
				    "Invalid offset/length. Malformed packet");
			return;
		}
	}
	return;
}

static void dissect_smb2_full_directory_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, smb2_info_t *si _U_)
{
	int offset = 0;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	const char *name=NULL;
	guint16 bc;

	while(tvb_length_remaining(tvb, offset) > 4){
		int old_offset = offset;
		int next_offset;
		int file_name_len;

		if(parent_tree){
			item = proto_tree_add_item(parent_tree, hf_smb2_full_directory_info, tvb, offset, -1, TRUE);
			tree = proto_item_add_subtree(item, ett_smb2_full_directory_info);
		}

		/* next offset */
		next_offset = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_next_offset, tvb, offset, 4, TRUE);
		offset += 4;

		/* file index */
		proto_tree_add_item(tree, hf_smb2_file_index, tvb, offset, 4, TRUE);
		offset += 4;

		/* create time */
		offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_create_timestamp);

		/* last access */
		offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_access_timestamp);

		/* last write */
		offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_write_timestamp);

		/* last change */
		offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_change_timestamp);

		/* end of file */
		proto_tree_add_item(tree, hf_smb2_end_of_file, tvb, offset, 8, TRUE);
		offset += 8;

		/* allocation size */
		proto_tree_add_item(tree, hf_smb2_allocation_size, tvb, offset, 8, TRUE);
		offset += 8;

		/* File Attributes */
		offset = dissect_file_ext_attr(tvb, tree, offset);

		/* file name length */
		file_name_len=tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_filename_len, tvb, offset, 4, TRUE);
		offset += 4;

		/* ea size */
		proto_tree_add_item(tree, hf_smb2_ea_size, tvb, offset, 4, TRUE);
		offset += 4;

		/* file name */
		if(file_name_len){
			bc=file_name_len;
			name = get_unicode_or_ascii_string(tvb, &offset,
				TRUE, &file_name_len, TRUE, TRUE, &bc);
			if(name){
				proto_tree_add_string(tree, hf_smb2_filename, tvb,
					offset, file_name_len, name);
				proto_item_append_text(item, ": %s", name);

			}
		}

		proto_item_set_len(item, offset-old_offset);

		if (next_offset == 0){
			return;
		}

		offset = old_offset+next_offset;
		if (offset < old_offset) {
			proto_tree_add_text(tree, tvb, offset, tvb_length_remaining(tvb, offset),
				    "Invalid offset/length. Malformed packet");
			return;
		}
	}
	return;
}

static void dissect_smb2_both_directory_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, smb2_info_t *si _U_)
{
	int offset = 0;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	const char *name=NULL;
	guint16 bc;

	while(tvb_length_remaining(tvb, offset) > 4){
		int old_offset = offset;
		int next_offset;
		int file_name_len;
		int short_name_len;

		if(parent_tree){
			item = proto_tree_add_item(parent_tree, hf_smb2_both_directory_info, tvb, offset, -1, TRUE);
			tree = proto_item_add_subtree(item, ett_smb2_both_directory_info);
		}

		/* next offset */
		next_offset = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_next_offset, tvb, offset, 4, TRUE);
		offset += 4;

		/* file index */
		proto_tree_add_item(tree, hf_smb2_file_index, tvb, offset, 4, TRUE);
		offset += 4;

		/* create time */
		offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_create_timestamp);

		/* last access */
		offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_access_timestamp);

		/* last write */
		offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_write_timestamp);

		/* last change */
		offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_change_timestamp);

		/* end of file */
		proto_tree_add_item(tree, hf_smb2_end_of_file, tvb, offset, 8, TRUE);
		offset += 8;

		/* allocation size */
		proto_tree_add_item(tree, hf_smb2_allocation_size, tvb, offset, 8, TRUE);
		offset += 8;

		/* File Attributes */
		offset = dissect_file_ext_attr(tvb, tree, offset);

		/* file name length */
		file_name_len=tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_filename_len, tvb, offset, 4, TRUE);
		offset += 4;

		/* ea size */
		proto_tree_add_item(tree, hf_smb2_ea_size, tvb, offset, 4, TRUE);
		offset += 4;

		/* short name length */
		short_name_len=tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_short_name_len, tvb, offset, 1, TRUE);
		offset += 1;

		/* reserved */
		offset += 1;

		/* short name */
		if(short_name_len){
			bc=short_name_len;
			name = get_unicode_or_ascii_string(tvb, &offset,
				TRUE, &short_name_len, TRUE, TRUE, &bc);
			if(name){
				proto_tree_add_string(tree, hf_smb2_short_name, tvb,
					offset, short_name_len, name);
			}
		}
		offset += 24;

		/* file name */
		if(file_name_len){
			bc=file_name_len;
			name = get_unicode_or_ascii_string(tvb, &offset,
				TRUE, &file_name_len, TRUE, TRUE, &bc);
			if(name){
				proto_tree_add_string(tree, hf_smb2_filename, tvb,
					offset, file_name_len, name);
				proto_item_append_text(item, ": %s", name);

			}
		}

		proto_item_set_len(item, offset-old_offset);

		if (next_offset == 0){
			return;
		}

		offset = old_offset+next_offset;
		if (offset < old_offset) {
			proto_tree_add_text(tree, tvb, offset, tvb_length_remaining(tvb, offset),
				    "Invalid offset/length. Malformed packet");
			return;
		}
	}
	return;
}

static void dissect_smb2_file_name_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, smb2_info_t *si _U_)
{
	int offset = 0;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	const char *name=NULL;
	guint16 bc;

	while(tvb_length_remaining(tvb, offset) > 4){
		int old_offset = offset;
		int next_offset;
		int file_name_len;

		if(parent_tree){
			item = proto_tree_add_item(parent_tree, hf_smb2_both_directory_info, tvb, offset, -1, TRUE);
			tree = proto_item_add_subtree(item, ett_smb2_both_directory_info);
		}

		/* next offset */
		next_offset = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_next_offset, tvb, offset, 4, TRUE);
		offset += 4;

		/* file index */
		proto_tree_add_item(tree, hf_smb2_file_index, tvb, offset, 4, TRUE);
		offset += 4;

		/* file name length */
		file_name_len=tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_filename_len, tvb, offset, 4, TRUE);
		offset += 4;

		/* file name */
		if(file_name_len){
			bc=file_name_len;
			name = get_unicode_or_ascii_string(tvb, &offset,
				TRUE, &file_name_len, TRUE, TRUE, &bc);
			if(name){
				proto_tree_add_string(tree, hf_smb2_filename, tvb,
					offset, file_name_len, name);
				proto_item_append_text(item, ": %s", name);

			}
		}

		proto_item_set_len(item, offset-old_offset);

		if (next_offset == 0){
			return;
		}

		offset = old_offset+next_offset;
		if (offset < old_offset) {
			proto_tree_add_text(tree, tvb, offset, tvb_length_remaining(tvb, offset),
				    "Invalid offset/length. Malformed packet");
			return;
		}
	}
	return;
}

static void dissect_smb2_id_both_directory_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, smb2_info_t *si _U_)
{
	int offset = 0;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	const char *name=NULL;
	guint16 bc;

	while(tvb_length_remaining(tvb, offset) > 4){
		int old_offset = offset;
		int next_offset;
		int file_name_len;
		int short_name_len;

		if(parent_tree){
			item = proto_tree_add_item(parent_tree, hf_smb2_id_both_directory_info, tvb, offset, -1, TRUE);
			tree = proto_item_add_subtree(item, ett_smb2_id_both_directory_info);
		}

		/* next offset */
		next_offset = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_next_offset, tvb, offset, 4, TRUE);
		offset += 4;

		/* file index */
		proto_tree_add_item(tree, hf_smb2_file_index, tvb, offset, 4, TRUE);
		offset += 4;

		/* create time */
		offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_create_timestamp);

		/* last access */
		offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_access_timestamp);

		/* last write */
		offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_write_timestamp);

		/* last change */
		offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_change_timestamp);

		/* end of file */
		proto_tree_add_item(tree, hf_smb2_end_of_file, tvb, offset, 8, TRUE);
		offset += 8;

		/* allocation size */
		proto_tree_add_item(tree, hf_smb2_allocation_size, tvb, offset, 8, TRUE);
		offset += 8;

		/* File Attributes */
		offset = dissect_file_ext_attr(tvb, tree, offset);

		/* file name length */
		file_name_len=tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_filename_len, tvb, offset, 4, TRUE);
		offset += 4;

		/* ea size */
		proto_tree_add_item(tree, hf_smb2_ea_size, tvb, offset, 4, TRUE);
		offset += 4;

		/* short name length */
		short_name_len=tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_short_name_len, tvb, offset, 1, TRUE);
		offset += 1;

		/* reserved */
		offset += 1;

		/* short name */
		if(short_name_len){
			bc=short_name_len;
			name = get_unicode_or_ascii_string(tvb, &offset,
				TRUE, &short_name_len, TRUE, TRUE, &bc);
			if(name){
				proto_tree_add_string(tree, hf_smb2_short_name, tvb,
					offset, short_name_len, name);
			}
		}
		offset += 24;

		/* reserved */
		offset += 2;

		/* file id */
		proto_tree_add_item(tree, hf_smb2_file_id, tvb, offset, 8, TRUE);
		offset += 8;

		/* file name */
		if(file_name_len){
			bc=file_name_len;
			name = get_unicode_or_ascii_string(tvb, &offset,
				TRUE, &file_name_len, TRUE, TRUE, &bc);
			if(name){
				proto_tree_add_string(tree, hf_smb2_filename, tvb,
					offset, file_name_len, name);
				proto_item_append_text(item, ": %s", name);

			}
		}

		proto_item_set_len(item, offset-old_offset);

		if (next_offset == 0){
			return;
		}

		offset = old_offset+next_offset;
		if (offset < old_offset) {
			proto_tree_add_text(tree, tvb, offset, tvb_length_remaining(tvb, offset),
				    "Invalid offset/length. Malformed packet");
			return;
		}
	}
	return;
}


typedef struct _smb2_find_dissector_t {
	guint32	level;
	void (*dissector)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si);
} smb2_find_dissector_t;

smb2_find_dissector_t smb2_find_dissectors[] = {
	{SMB2_FIND_DIRECTORY_INFO,	dissect_smb2_file_directory_info},
	{SMB2_FIND_FULL_DIRECTORY_INFO, dissect_smb2_full_directory_info},
	{SMB2_FIND_BOTH_DIRECTORY_INFO,	dissect_smb2_both_directory_info},
	{SMB2_FIND_NAME_INFO,		dissect_smb2_file_name_info},
	{SMB2_FIND_ID_BOTH_DIRECTORY_INFO,dissect_smb2_id_both_directory_info},
	{0, NULL}
};

static void
dissect_smb2_find_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si)
{
	smb2_find_dissector_t *dis = smb2_find_dissectors;

	while(dis->dissector){
		if(si && si->saved && si->saved){
			if(dis->level ==si->saved->infolevel){
				dis->dissector(tvb, pinfo, tree, si);
				return;
			}
		}
		dis++;
	}

	proto_tree_add_item(tree, hf_smb2_unknown, tvb, 0, tvb_length(tvb), FALSE);
	return;
}

static int
dissect_smb2_find_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	offset_length_buffer_t olb;
	proto_item *item=NULL;

	if(si->saved){
		/* infolevel */
		item=proto_tree_add_uint(tree, hf_smb2_find_info_level, tvb, offset, 0, si->saved->infolevel);
		PROTO_ITEM_SET_GENERATED(item);
	}

	if(!pinfo->fd->flags.visited && si->saved && si->saved->extra_info_type==SMB2_EI_FINDPATTERN) {
		if (check_col(pinfo->cinfo, COL_INFO)){
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s Pattern: %s",
				val_to_str(si->saved->infolevel, smb2_find_info_levels, "(Level:0x%02x)"),
				(const char *)si->saved->extra_info);
		}

		g_free(si->saved->extra_info);
		si->saved->extra_info_type=SMB2_EI_NONE;
		si->saved->extra_info=NULL;
	}

	switch (si->status) {
	case 0x00000000: break;
	default: return dissect_smb2_error_response(tvb, pinfo, tree, offset, si);
	}

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* findinfo offset */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &olb, OLB_O_UINT16_S_UINT32, hf_smb2_find_info_blob);

	/* the buffer */
	dissect_smb2_olb_buffer(pinfo, tree, tvb, &olb, si, dissect_smb2_find_data);

	offset = dissect_smb2_olb_tvb_max_offset(offset, &olb);

	return offset;
}

static int
dissect_smb2_negotiate_protocol_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	guint16 dc;

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* dialect count */
	dc = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_dialect_count, tvb, offset, 2, TRUE);
	offset += 2;

	/* security mode, skip second byte */
	offset = dissect_smb2_secmode(tree, tvb, offset);
	offset++;


	/* reserved */
	offset += 2;

	/* capabilities */
	offset = dissect_smb2_capabilities(tree, tvb, offset);

	/* client guid */
	proto_tree_add_item(tree, hf_smb2_client_guid, tvb, offset, 16, TRUE);
	offset += 16;

	/* client boot time */
	dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_boot_time);
	offset += 8;

	for(;dc>0;dc--){
		proto_tree_add_item(tree, hf_smb2_dialect, tvb, offset, 2, TRUE);
		offset += 2;
	}

	return offset;
}

static int
dissect_smb2_negotiate_protocol_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	offset_length_buffer_t s_olb;

	switch (si->status) {
	case 0x00000000: break;
	default: return dissect_smb2_error_response(tvb, pinfo, tree, offset, si);
	}

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* security mode, skip second byte */
	offset = dissect_smb2_secmode(tree, tvb, offset);
	offset++;

	/* dialect picked */
	proto_tree_add_item(tree, hf_smb2_dialect, tvb, offset, 2, TRUE);
	offset += 2;

	/* reserved */
	offset += 2;

	/* server GUID */
	proto_tree_add_item(tree, hf_smb2_server_guid, tvb, offset, 16, TRUE);
	offset += 16;

	/* capabilities */
	offset = dissect_smb2_capabilities(tree, tvb, offset);

	/* max trans size */
	proto_tree_add_item(tree, hf_smb2_max_trans_size, tvb, offset, 4, TRUE);
	offset += 4;

	/* max read size */
	proto_tree_add_item(tree, hf_smb2_max_read_size, tvb, offset, 4, TRUE);
	offset += 4;

	/* max write size */
	proto_tree_add_item(tree, hf_smb2_max_write_size, tvb, offset, 4, TRUE);
	offset += 4;

	/* current time */
	dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_current_time);
	offset += 8;

	/* boot time */
	dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_boot_time);
	offset += 8;

	/* security blob offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &s_olb, OLB_O_UINT16_S_UINT16, hf_smb2_security_blob);

	/* the security blob itself */
	dissect_smb2_olb_buffer(pinfo, tree, tvb, &s_olb, si, dissect_smb2_secblob);

	/* reserved */
	offset += 4;

	offset = dissect_smb2_olb_tvb_max_offset(offset, &s_olb);

	return offset;
}

static int
dissect_smb2_getinfo_parameters(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si)
{
	switch(si->saved->class){
	case SMB2_CLASS_FILE_INFO:
		switch(si->saved->infolevel){
		default:
			/* we dont handle this infolevel yet */
			proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 16, TRUE);
			offset += tvb_length_remaining(tvb, offset);
		}
		break;
	case SMB2_CLASS_FS_INFO:
		switch(si->saved->infolevel){
		default:
			/* we dont handle this infolevel yet */
			proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 16, TRUE);
			offset += tvb_length_remaining(tvb, offset);
		}
		break;
	case SMB2_CLASS_SEC_INFO:
		switch(si->saved->infolevel){
		case SMB2_SEC_INFO_00:
			dissect_security_information_mask(tvb, tree, offset+8);
			break;
		default:
			/* we dont handle this infolevel yet */
			proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 16, TRUE);
			offset += tvb_length_remaining(tvb, offset);
		}
		break;
	default:
		/* we dont handle this class yet */
		proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 16, TRUE);
		offset += tvb_length_remaining(tvb, offset);
	}
	return offset;
}


static int
dissect_smb2_class_infolevel(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree, smb2_info_t *si)
{
	char cl, il;
	proto_item *item;
	int hfindex;
	static const value_string dummy_value_string[] = {
		{ 0, NULL }
	};
	const value_string *vs;

	if(si->flags & SMB2_FLAGS_RESPONSE){
		if(!si->saved){
			return offset;
		}
		cl=si->saved->class;
		il=si->saved->infolevel;
	} else {
		cl=tvb_get_guint8(tvb, offset);
		il=tvb_get_guint8(tvb, offset+1);
		if(si->saved){
			si->saved->class=cl;
			si->saved->infolevel=il;
		}
	}


	switch(cl){
	case SMB2_CLASS_FILE_INFO:
		hfindex=hf_smb2_infolevel_file_info;
		vs=smb2_file_info_levels;
		break;
	case SMB2_CLASS_FS_INFO:
		hfindex=hf_smb2_infolevel_fs_info;
		vs=smb2_fs_info_levels;
		break;
	case SMB2_CLASS_SEC_INFO:
		hfindex=hf_smb2_infolevel_sec_info;
		vs=smb2_sec_info_levels;
		break;
	default:
		hfindex=hf_smb2_infolevel;
		vs=dummy_value_string;
	}


	/* class */
	item=proto_tree_add_uint(tree, hf_smb2_class, tvb, offset, 1, cl);
	if(si->flags & SMB2_FLAGS_RESPONSE){
		PROTO_ITEM_SET_GENERATED(item);
	}
	/* infolevel */
	item=proto_tree_add_uint(tree, hfindex, tvb, offset+1, 1, il);
	if(si->flags & SMB2_FLAGS_RESPONSE){
		PROTO_ITEM_SET_GENERATED(item);
	}
	offset += 2;

	if(!(si->flags & SMB2_FLAGS_RESPONSE)){
		/* Only update COL_INFO for requests. It clutters the
		 * display ab bit too much if we do it for replies
		 * as well.
		 */
		if (check_col(pinfo->cinfo, COL_INFO)){
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s/%s",
				val_to_str(cl, smb2_class_vals, "(Class:0x%02x)"),
				val_to_str(il, vs, "(Level:0x%02x)"));
		}
	}

	return offset;
}

static int
dissect_smb2_getinfo_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* class and info level */
	offset = dissect_smb2_class_infolevel(pinfo, tvb, offset, tree, si);

	/* max response size */
	proto_tree_add_item(tree, hf_smb2_max_response_size, tvb, offset, 4, TRUE);
	offset += 4;

	/* parameters */
	if(si->saved){
		dissect_smb2_getinfo_parameters(tvb, pinfo, tree, offset, si);
	} else {
		/* some unknown bytes */
		proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 16, TRUE);
	}
	offset += 16;

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

	return offset;
}

static int
dissect_smb2_infolevel(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si, guint8 class, guint8 infolevel)
{
	int old_offset = offset;

	switch(class){
	case SMB2_CLASS_FILE_INFO:
		switch(infolevel){
		case SMB2_FILE_BASIC_INFO:
			offset = dissect_smb2_file_basic_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_STANDARD_INFO:
			offset = dissect_smb2_file_standard_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_INTERNAL_INFO:
			offset = dissect_smb2_file_internal_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_EA_INFO:
			offset = dissect_smb2_file_ea_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_ACCESS_INFO:
			offset = dissect_smb2_file_access_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_RENAME_INFO:
			offset = dissect_smb2_file_rename_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_DISPOSITION_INFO:
			offset = dissect_smb2_file_disposition_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_POSITION_INFO:
			offset = dissect_smb2_file_position_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_INFO_0f:
			offset = dissect_smb2_file_info_0f(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_MODE_INFO:
			offset = dissect_smb2_file_mode_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_ALIGNMENT_INFO:
			offset = dissect_smb2_file_alignment_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_ALL_INFO:
			offset = dissect_smb2_file_all_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_ALLOCATION_INFO:
			offset = dissect_smb2_file_allocation_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_ENDOFFILE_INFO:
			dissect_smb2_file_endoffile_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_ALTERNATE_NAME_INFO:
			offset = dissect_smb2_file_alternate_name_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_STREAM_INFO:
			offset = dissect_smb2_file_stream_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_PIPE_INFO:
			offset = dissect_smb2_file_pipe_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_COMPRESSION_INFO:
			offset = dissect_smb2_file_compression_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_NETWORK_OPEN_INFO:
			offset = dissect_smb2_file_network_open_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_ATTRIBUTE_TAG_INFO:
			offset = dissect_smb2_file_attribute_tag_info(tvb, pinfo, tree, offset, si);
			break;
		default:
			/* we dont handle this infolevel yet */
			proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, tvb_length_remaining(tvb, offset), TRUE);
			offset += tvb_length_remaining(tvb, offset);
		}
		break;
	case SMB2_CLASS_FS_INFO:
		switch(infolevel){
		case SMB2_FS_INFO_01:
			offset = dissect_smb2_fs_info_01(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FS_INFO_03:
			offset = dissect_smb2_fs_info_03(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FS_INFO_04:
			offset = dissect_smb2_fs_info_04(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FS_INFO_05:
			offset = dissect_smb2_fs_info_05(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FS_INFO_06:
			offset = dissect_smb2_fs_info_06(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FS_INFO_07:
			offset = dissect_smb2_fs_info_07(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FS_OBJECTID_INFO:
			offset = dissect_smb2_FS_OBJECTID_INFO(tvb, pinfo, tree, offset, si);
			break;
		default:
			/* we dont handle this infolevel yet */
			proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, tvb_length_remaining(tvb, offset), TRUE);
			offset += tvb_length_remaining(tvb, offset);
		}
		break;
	case SMB2_CLASS_SEC_INFO:
		switch(infolevel){
		case SMB2_SEC_INFO_00:
			offset = dissect_smb2_sec_info_00(tvb, pinfo, tree, offset, si);
			break;
		default:
			/* we dont handle this infolevel yet */
			proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, tvb_length_remaining(tvb, offset), TRUE);
			offset += tvb_length_remaining(tvb, offset);
		}
		break;
	default:
		/* we dont handle this class yet */
		proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, tvb_length_remaining(tvb, offset), TRUE);
		offset += tvb_length_remaining(tvb, offset);
	}

	/* if we get BUFFER_OVERFLOW there will be truncated data */
	if (si->status == 0x80000005) {
		proto_item *item;
		item=proto_tree_add_text(tree, tvb, old_offset, 0, "Truncated...");
		PROTO_ITEM_SET_GENERATED(item);
	}
	return offset;
}

static void
dissect_smb2_getinfo_response_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si)
{
	/* data */
	if(si->saved){
		dissect_smb2_infolevel(tvb, pinfo, tree, 0, si, si->saved->class, si->saved->infolevel);
	} else {
		/* some unknown bytes */
		proto_tree_add_item(tree, hf_smb2_unknown, tvb, 0, tvb_length(tvb), FALSE);
	}

	return;
}


static int
dissect_smb2_getinfo_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	offset_length_buffer_t olb;

	/* class/infolevel */
	dissect_smb2_class_infolevel(pinfo, tvb, offset, tree, si);

	switch (si->status) {
	case 0x00000000: break;
	/* if we get BUFFER_OVERFLOW there will be truncated data */
	case 0x80000005: break;
	/* if we get BUFFER_TOO_SMALL there will not be any data there, only
	 * a guin32 specifying how big the buffer needs to be
	 */
	case 0xc0000023:
		offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);
		offset = dissect_smb2_olb_length_offset(tvb, offset, &olb, OLB_O_UINT16_S_UINT32, -1);
		proto_tree_add_item(tree, hf_smb2_required_buffer_size, tvb, offset, 4, TRUE);
		offset += 4;

		return offset;
	default: return dissect_smb2_error_response(tvb, pinfo, tree, offset, si);
	}


	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);
	 /* response buffer offset  and size */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &olb, OLB_O_UINT16_S_UINT32, -1);

	/* response data*/
	dissect_smb2_olb_buffer(pinfo, tree, tvb, &olb, si, dissect_smb2_getinfo_response_data);

	return offset;
}

static int
dissect_smb2_close_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	proto_tree *flags_tree = NULL;
	proto_item *flags_item = NULL;

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* close flags */
	if (tree) {
		flags_item = proto_tree_add_item(tree, hf_smb2_close_flags, tvb, offset, 2, TRUE);
		flags_tree = proto_item_add_subtree(flags_item, ett_smb2_close_flags);
	}
	proto_tree_add_item(flags_tree, hf_smb2_close_pq_attrib, tvb, offset, 2, TRUE);
	offset += 2;

	/* padding */
	offset += 4;

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_CLOSE);

	return offset;
}

static int
dissect_smb2_close_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	proto_tree *flags_tree = NULL;
	proto_item *flags_item = NULL;

	switch (si->status) {
	case 0x00000000: break;
	default: return dissect_smb2_error_response(tvb, pinfo, tree, offset, si);
	}

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* close flags */
	if (tree) {
		flags_item = proto_tree_add_item(tree, hf_smb2_close_flags, tvb, offset, 2, TRUE);
		flags_tree = proto_item_add_subtree(flags_item, ett_smb2_close_flags);
	}
	proto_tree_add_item(flags_tree, hf_smb2_close_pq_attrib, tvb, offset, 2, TRUE);
	offset += 2;

	/* reserved */
	offset += 4;

	/* create time */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_create_timestamp);

	/* last access */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_access_timestamp);

	/* last write */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_write_timestamp);

	/* last change */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_change_timestamp);

	/* allocation size */
	proto_tree_add_item(tree, hf_smb2_allocation_size, tvb, offset, 8, TRUE);
	offset += 8;

	/* end of file */
	proto_tree_add_item(tree, hf_smb2_end_of_file, tvb, offset, 8, TRUE);
	offset += 8;

	/* File Attributes */
	offset = dissect_file_ext_attr(tvb, tree, offset);

	return offset;
}

static int
dissect_smb2_flush_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 6, TRUE);
	offset += 6;

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

	return offset;
}

static int
dissect_smb2_flush_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	switch (si->status) {
	case 0x00000000: break;
	default: return dissect_smb2_error_response(tvb, pinfo, tree, offset, si);
	}

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;

	return offset;
}


static int
dissect_smb2_lock_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	guint16 lock_count;

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* lock count */
	lock_count = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_lock_count, tvb, offset, 2, TRUE);
	offset += 2;

	/* reserved */
	offset += 4;

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

	while (lock_count--) {
		proto_item *lock_item=NULL;
		proto_tree *lock_tree=NULL;
		static const int *lf_fields[] = {
			&hf_smb2_lock_flags_shared,
			&hf_smb2_lock_flags_exclusive,
			&hf_smb2_lock_flags_unlock,
			&hf_smb2_lock_flags_fail_immediately,
			NULL
		};

		if(tree){
			lock_item = proto_tree_add_item(tree, hf_smb2_lock_info, tvb, offset, 24, TRUE);
			lock_tree = proto_item_add_subtree(lock_item, ett_smb2_lock_info);
		}

		/* offset */
		proto_tree_add_item(tree, hf_smb2_file_offset, tvb, offset, 8, TRUE);
		offset += 8;

		/* count */
		proto_tree_add_item(lock_tree, hf_smb2_lock_length, tvb, offset, 8, TRUE);
		offset += 8;

		/* flags */
		proto_tree_add_bitmask(lock_tree, tvb, offset, hf_smb2_lock_flags, ett_smb2_lock_flags, lf_fields, TRUE);
		offset += 4;

		/* reserved */
		offset += 4;
	}

	return offset;
}

static int
dissect_smb2_lock_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	switch (si->status) {
	case 0x00000000: break;
	default: return dissect_smb2_error_response(tvb, pinfo, tree, offset, si);
	}

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;

	return offset;
}
static int
dissect_smb2_cancel_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;

	return offset;
}


static int
dissect_file_data_dcerpc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, int offset, guint32 datalen, proto_tree *top_tree)
{
	tvbuff_t *dcerpc_tvb;
	dcerpc_tvb = tvb_new_subset(tvb, offset, MIN((int)datalen, tvb_length_remaining(tvb, offset)), datalen);

	/* dissect the full PDU */
	dissector_try_heuristic(smb2_heur_subdissector_list, dcerpc_tvb, pinfo, top_tree);


	offset += datalen;

	return offset;
}

#define SMB2_WRITE_FLAG_WRITE_THROUGH		0x00000001

static int
dissect_smb2_write_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	guint32 length;
	guint64 off;
	static const int *f_fields[] = {
		&hf_smb2_write_flags_write_through,
		NULL
	};

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* data offset */
	proto_tree_add_item(tree, hf_smb2_data_offset, tvb, offset, 2, TRUE);
	offset += 2;

	/* length */
	length=tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_write_length, tvb, offset, 4, TRUE);
	offset += 4;

	/* offset */
	off=tvb_get_letoh64(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_file_offset, tvb, offset, 8, TRUE);
	offset += 8;

	if (check_col(pinfo->cinfo, COL_INFO)){
		col_append_fstr(pinfo->cinfo, COL_INFO, " Len:%d Off:%" G_GINT64_MODIFIER "u", length, off);
	}

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

	/* channel */
	proto_tree_add_item(tree, hf_smb2_channel, tvb, offset, 4, TRUE);
	offset += 4;

	/* remaining bytes */
	proto_tree_add_item(tree, hf_smb2_remaining_bytes, tvb, offset, 4, TRUE);
	offset += 4;

	/* write channel info offset */
	proto_tree_add_item(tree, hf_smb2_channel_info_offset, tvb, offset, 2, TRUE);
	offset += 2;

	/* write channel info length */
	proto_tree_add_item(tree, hf_smb2_channel_info_length, tvb, offset, 2, TRUE);
	offset += 2;

	/* flags */
	proto_tree_add_bitmask(tree, tvb, offset, hf_smb2_write_flags, ett_smb2_write_flags, f_fields, TRUE);
	offset += 4;

	/* data or dcerpc ?*/
	if(length && si->tree && si->tree->share_type == SMB2_SHARE_TYPE_PIPE){
		offset = dissect_file_data_dcerpc(tvb, pinfo, tree, offset, length, si->top_tree);
		return offset;
	}

	/* just ordinary data */
	proto_tree_add_item(tree, hf_smb2_write_data, tvb, offset, length, TRUE);
	offset += MIN(length,(guint32)tvb_length_remaining(tvb, offset));

	return offset;
}


static int
dissect_smb2_write_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	switch (si->status) {
	case 0x00000000: break;
	default: return dissect_smb2_error_response(tvb, pinfo, tree, offset, si);
	}

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* reserved */
	proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 2, TRUE);
	offset += 2;

	/* count */
	proto_tree_add_item(tree, hf_smb2_write_count, tvb, offset, 4, TRUE);
	offset += 4;

	/* remaining, must be set to 0 */
	proto_tree_add_item(tree, hf_smb2_write_remaining, tvb, offset, 4, TRUE);
	offset += 4;

	/* write channel info offset */
	proto_tree_add_item(tree, hf_smb2_channel_info_offset, tvb, offset, 2, TRUE);
	offset += 2;

	/* write channel info length */
	proto_tree_add_item(tree, hf_smb2_channel_info_length, tvb, offset, 2, TRUE);
	offset += 2;

	return offset;
}

static void
dissect_smb2_FSCTL_PIPE_TRANSCEIVE(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *top_tree, gboolean data_in _U_)
{
	dissect_file_data_dcerpc(tvb, pinfo, tree, offset, tvb_length_remaining(tvb, offset), top_tree);

	return;
}

static void
dissect_smb2_FSCTL_LMR_REQUEST_RESILIENCY(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean data_in)
{
	/* There is no out data */
	if(!data_in){
		return;
	}

	/* timeout */
	proto_tree_add_item(tree, hf_smb2_ioctl_resiliency_timeout, tvb, offset, 4, TRUE);
	offset += 4;

	/* reserved */
	proto_tree_add_item(tree, hf_smb2_ioctl_resiliency_reserved, tvb, offset, 4, TRUE);
	offset += 4;

	return;
}

static void
dissect_windows_sockaddr_in(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, int len)
{
	proto_item *sub_item=NULL;
	proto_tree *sub_tree=NULL;
	proto_item *parent_item=NULL;
	guint32 addr;

	if (len == -1) {
		len = 16;
	}

	if(parent_tree){
		sub_item = proto_tree_add_text(parent_tree, tvb, offset, len, "Socket Address");
		sub_tree = proto_item_add_subtree(sub_item, ett_windows_sockaddr);
		parent_item = proto_tree_get_parent(parent_tree);
	}

	/* family */
	proto_tree_add_item(sub_tree, hf_windows_sockaddr_family, tvb, offset, 2, TRUE);
	offset += 2;

	/* port */
	proto_tree_add_item(sub_tree, hf_windows_sockaddr_port, tvb, offset, 2, TRUE);
	offset += 2;

	/* IPv4 address */
	addr = tvb_get_ipv4(tvb, offset);
	proto_tree_add_ipv4(sub_tree, hf_windows_sockaddr_in_addr, tvb, offset, 4, addr);
	if (sub_item) {
		proto_item_append_text(sub_item, ", IPv4: %s", tvb_ip_to_str(tvb, offset));
	}
	if (parent_item) {
		proto_item_append_text(parent_item, ", IPv4: %s", tvb_ip_to_str(tvb, offset));
	}
	offset += 4;

	return;
}

static void
dissect_windows_sockaddr_in6(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, int len)
{
	struct e_in6_addr addr;
	proto_item *sub_item=NULL;
	proto_tree *sub_tree=NULL;
	proto_item *parent_item=NULL;

	if (len == -1) {
		len = 16;
	}

	if(parent_tree){
		sub_item = proto_tree_add_text(parent_tree, tvb, offset, len, "Socket Address");
		sub_tree = proto_item_add_subtree(sub_item, ett_windows_sockaddr);
		parent_item = proto_tree_get_parent(parent_tree);
	}

	/* family */
	proto_tree_add_item(sub_tree, hf_windows_sockaddr_family, tvb, offset, 2, TRUE);
	offset += 2;

	/* port */
	proto_tree_add_item(sub_tree, hf_windows_sockaddr_port, tvb, offset, 2, TRUE);
	offset += 2;

	/* sin6_flowinfo */
	proto_tree_add_item(sub_tree, hf_windows_sockaddr_in6_flowinfo, tvb, offset, 2, TRUE);
	offset += 4;

	/* IPv4 address */
	tvb_get_ipv6(tvb, offset, &addr);
	proto_tree_add_ipv6(sub_tree, hf_windows_sockaddr_in6_addr, tvb, offset, 16, (guint8 *)&addr);
	if (sub_item) {
		proto_item_append_text(sub_item, ", IPv6: %s", tvb_ip6_to_str(tvb, offset));
	}
	if (parent_item) {
		proto_item_append_text(parent_item, ", IPv6: %s", tvb_ip6_to_str(tvb, offset));
	}
	offset += 16;

	/* sin6_scope_id */
	proto_tree_add_item(sub_tree, hf_windows_sockaddr_in6_scope_id, tvb, offset, 2, TRUE);
	offset += 4;
	return;
}

static void
dissect_windows_sockaddr_storage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	int len=128;
	proto_item *sub_item=NULL;
	proto_tree *sub_tree=NULL;
	proto_item *parent_item=NULL;
	guint16 family;

	family = tvb_get_letohs(tvb, offset);
	switch (family) {
	case 2: /* AF_INET */
		dissect_windows_sockaddr_in(tvb, pinfo, parent_tree, offset, len);
		return;
	case 23: /* AF_INET6 */
		dissect_windows_sockaddr_in6(tvb, pinfo, parent_tree, offset, len);
		return;
	}

	if(parent_tree){
		sub_item = proto_tree_add_text(parent_tree, tvb, offset, len, "Socket Address");
		sub_tree = proto_item_add_subtree(sub_item, ett_windows_sockaddr);
		parent_item = proto_tree_get_parent(parent_tree);
	}

	/* ss_family */
	proto_tree_add_item(sub_tree, hf_windows_sockaddr_family, tvb, offset, 2, TRUE);
	if (sub_item) {
		proto_item_append_text(sub_item, ", Family: %d (0x%04x)", family, family);
	}
	if (parent_item) {
		proto_item_append_text(sub_item, ", Family: %d (0x%04x)", family, family);
	}
	offset += 2;

	/* unknown */
	offset += 126;

	return;
}

#define NETWORK_INTERFACE_CAP_RSS 0x00000001
#define NETWORK_INTERFACE_CAP_RMDA 0x00000002

static void
dissect_smb2_NETWORK_INTERFACE_INFO(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	guint32 next_offset;
	int offset=0;
	int len=-1;
	proto_item *sub_item=NULL;
	proto_tree *sub_tree=NULL;
	proto_item *parent_item=NULL;
	proto_item *item=NULL;
	guint32 capabilities;
	guint64 link_speed;
	gfloat val = 0;
	const char *unit = NULL;

	next_offset=tvb_get_letohl(tvb, offset);
	if (next_offset) {
		len = next_offset;
	}

	if(parent_tree){
		sub_item = proto_tree_add_text(parent_tree, tvb, offset, len, "Network Interface");
		sub_tree = proto_item_add_subtree(sub_item, ett_smb2_ioctl_network_interface);
		parent_item = proto_tree_get_parent(parent_tree);
	}

	/* next offset */
	proto_tree_add_item(sub_tree, hf_smb2_ioctl_network_interface_next_offset, tvb, offset, 4, TRUE);
	offset += 4;

	/* interface index */
	proto_tree_add_item(sub_tree, hf_smb2_ioctl_network_interface_index, tvb, offset, 4, TRUE);
	offset += 4;

	/* capabilities */
	capabilities = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(sub_tree, hf_smb2_ioctl_network_interface_capabilities, tvb, offset, 4, TRUE);
	proto_tree_add_boolean(sub_tree, hf_smb2_ioctl_network_interface_capability_rss, tvb, offset, 4, capabilities);
	proto_tree_add_boolean(sub_tree, hf_smb2_ioctl_network_interface_capability_rdma, tvb, offset, 4, capabilities);
	if (capabilities != 0) {
		proto_item_append_text(item, "%s%s",
				       (capabilities & NETWORK_INTERFACE_CAP_RSS)?", RSS":"",
				       (capabilities & NETWORK_INTERFACE_CAP_RMDA)?", RDMA":"");
		if (sub_item) {
			proto_item_append_text(sub_item, "%s%s",
					       (capabilities & NETWORK_INTERFACE_CAP_RSS)?", RSS":"",
					       (capabilities & NETWORK_INTERFACE_CAP_RMDA)?", RDMA":"");
		}
	}
	offset += 4;

	/* rss queue count */
	proto_tree_add_item(sub_tree, hf_smb2_ioctl_network_interface_rss_queue_count, tvb, offset, 4, TRUE);
	offset += 4;

	/* link speed */
	link_speed = tvb_get_letoh64(tvb, offset);
	item = proto_tree_add_item(sub_tree, hf_smb2_ioctl_network_interface_link_speed, tvb, offset, 8, TRUE);
	if (link_speed >= (1000*1000*1000)) {
		val = (gfloat)(link_speed / (1000*1000*1000));
		unit = "G";
	} else if (link_speed >= (1000*1000)) {
		val = (gfloat)(link_speed / (1000*1000));
		unit = "M";
	} else if (link_speed >= (1000)) {
		val = (gfloat)(link_speed / (1000));
		unit = "K";
	} else {
		val = (gfloat)(link_speed);
		unit = "";
	}
	proto_item_append_text(item, ", %.1f %sBits/s", val, unit);
	if (sub_item) {
		proto_item_append_text(sub_item, ", %.1f %sBits/s", val, unit);
	}

	offset += 8;

	/* socket address */
	dissect_windows_sockaddr_storage(tvb, pinfo, sub_tree, offset);
	offset += 128;

	if(next_offset){
		tvbuff_t *next_tvb;
		next_tvb=tvb_new_subset(tvb, next_offset,
					tvb_length_remaining(tvb, next_offset),
					tvb_reported_length_remaining(tvb, next_offset));

		/* next extra info */
		dissect_smb2_NETWORK_INTERFACE_INFO(next_tvb, pinfo, parent_tree);
	}
	return;
}

static void
dissect_smb2_FSCTL_QUERY_NETWORK_INTERFACE_INFO(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset _U_, gboolean data_in)
{
	/* There is no in data */
	if(data_in){
		return;
	}

	dissect_smb2_NETWORK_INTERFACE_INFO(tvb, pinfo, tree);
}

static void
dissect_smb2_FSCTL_GET_SHADOW_COPY_DATA(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean data_in)
{
	guint32 num_volumes;

	/* There is no in data */
	if(data_in){
		return;
	}

	/* num volumes */
	num_volumes=tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_ioctl_shadow_copy_num_volumes, tvb, offset, 4, TRUE);
	offset += 4;

	/* num labels */
	proto_tree_add_item(tree, hf_smb2_ioctl_shadow_copy_num_labels, tvb, offset, 4, TRUE);
	offset += 4;

	/* count */
	proto_tree_add_item(tree, hf_smb2_ioctl_shadow_copy_count, tvb, offset, 4, TRUE);
	offset += 4;

	while(num_volumes--){
		const char *name;
		guint16 bc;
		int len=0;
		int old_offset=offset;

		bc=tvb_length_remaining(tvb, offset);
		name = get_unicode_or_ascii_string(tvb, &offset,
			TRUE, &len, TRUE, FALSE, &bc);
		proto_tree_add_string(tree, hf_smb2_ioctl_shadow_copy_label, tvb, old_offset, len, name);

		offset = old_offset+len;

		if(!len){
			break;
		}
	}

	return;
}

int
dissect_smb2_FILE_OBJECTID_BUFFER(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	/* FILE_OBJECTID_BUFFER */
	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_FILE_OBJECTID_BUFFER, tvb, offset, 64, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_FILE_OBJECTID_BUFFER);
	}

	/* Object ID */
	proto_tree_add_item(tree, hf_smb2_object_id, tvb, offset, 16, TRUE);
	offset += 16;

	/* Birth Volume ID */
	proto_tree_add_item(tree, hf_smb2_birth_volume_id, tvb, offset, 16, TRUE);
	offset += 16;

	/* Birth Object ID */
	proto_tree_add_item(tree, hf_smb2_birth_object_id, tvb, offset, 16, TRUE);
	offset += 16;

	/* Domain ID */
	proto_tree_add_item(tree, hf_smb2_domain_id, tvb, offset, 16, TRUE);
	offset += 16;

	return offset;
}

static int
dissect_smb2_FSCTL_CREATE_OR_GET_OBJECT_ID(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean data_in)
{

	/* There is no in data */
	if(data_in){
		return offset;
	}

	/* FILE_OBJECTID_BUFFER */
	offset = dissect_smb2_FILE_OBJECTID_BUFFER(tvb, pinfo, tree, offset);

	return offset;
}

static int
dissect_smb2_FSCTL_GET_COMPRESSION(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean data_in)
{

	/* There is no in data */
	if(data_in){
		return offset;
	}

	/* compression format */
	proto_tree_add_item(tree, hf_smb2_compression_format, tvb, offset, 2, TRUE);
	offset += 2;

	return offset;
}
static int
dissect_smb2_FSCTL_SET_COMPRESSION(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean data_in)
{

	/* There is no out data */
	if(!data_in){
		return offset;
	}

	/* compression format */
	proto_tree_add_item(tree, hf_smb2_compression_format, tvb, offset, 2, TRUE);
	offset += 2;

	return offset;
}

static int 
dissect_smb2_FSCTL_SET_OBJECT_ID(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean data_in)
{

	/* There is no out data */
	if(!data_in){
		return offset;
	}

	/* FILE_OBJECTID_BUFFER */
	offset = dissect_smb2_FILE_OBJECTID_BUFFER(tvb, pinfo, tree, offset);

	return offset;
}

static int
dissect_smb2_FSCTL_SET_OBJECT_ID_EXTENDED(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean data_in)
{

	/* There is no out data */
	if(!data_in){
		return offset;
	}

	/* FILE_OBJECTID_BUFFER->ExtendedInfo */

	/* Birth Volume ID */
	proto_tree_add_item(tree, hf_smb2_birth_volume_id, tvb, offset, 16, TRUE);
	offset += 16;

	/* Birth Object ID */
	proto_tree_add_item(tree, hf_smb2_birth_object_id, tvb, offset, 16, TRUE);
	offset += 16;

	/* Domain ID */
	proto_tree_add_item(tree, hf_smb2_domain_id, tvb, offset, 16, TRUE);
	offset += 16;

	return offset;
}

void
dissect_smb2_ioctl_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *top_tree, guint32 ioctl_function, gboolean data_in)
{
	guint16 dc;

	dc = tvb_reported_length(tvb);

	switch(ioctl_function){
	case 0x00060194: /* FSCTL_DFS_GET_REFERRALS */
		if (data_in) {
			dissect_get_dfs_request_data(tvb, pinfo, tree, 0, &dc);
		} else {
			dissect_get_dfs_referral_data(tvb, pinfo, tree, 0, &dc);
		}
		break;
	case 0x0011c017:
		dissect_smb2_FSCTL_PIPE_TRANSCEIVE(tvb, pinfo, tree, 0, top_tree, data_in);
		break;
	case 0x001401D4: /* FSCTL_LMR_REQUEST_RESILIENCY */
		dissect_smb2_FSCTL_LMR_REQUEST_RESILIENCY(tvb, pinfo, tree, 0, data_in);
		break;
	case 0x001401FC: /* FSCTL_QUERY_NETWORK_INTERFACE_INFO */
		dissect_smb2_FSCTL_QUERY_NETWORK_INTERFACE_INFO(tvb, pinfo, tree, 0, data_in);
		break;
	case 0x00144064: /* FSCTL_GET_SHADOW_COPY_DATA */
		dissect_smb2_FSCTL_GET_SHADOW_COPY_DATA(tvb, pinfo, tree, 0, data_in);
		break;
	case 0x0009009C: /* FSCTL_GET_OBJECT_ID */
	case 0x000900c0: /* FSCTL_CREATE_OR_GET_OBJECT_ID */
		dissect_smb2_FSCTL_CREATE_OR_GET_OBJECT_ID(tvb, pinfo, tree, 0, data_in);
		break;
	case 0x00098098: /* FSCTL_SET_OBJECT_ID */
		dissect_smb2_FSCTL_SET_OBJECT_ID(tvb, pinfo, tree, 0, data_in);
		break;
	case 0x000980BC: /* FSCTL_SET_OBJECT_ID_EXTENDED */
		dissect_smb2_FSCTL_SET_OBJECT_ID_EXTENDED(tvb, pinfo, tree, 0, data_in);
		break;
	case 0x0009003C: /* FSCTL_GET_COMPRESSION */
		dissect_smb2_FSCTL_GET_COMPRESSION(tvb, pinfo, tree, 0, data_in);
		break;
	case 0x0009C040: /* FSCTL_SET_COMPRESSION */
		dissect_smb2_FSCTL_SET_COMPRESSION(tvb, pinfo, tree, 0, data_in);
		break;
	default:
		proto_tree_add_item(tree, hf_smb2_unknown, tvb, 0, tvb_length(tvb), TRUE);
	}

	return;
}

static void
dissect_smb2_ioctl_data_in(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si)
{
	dissect_smb2_ioctl_data(tvb, pinfo, tree, si->top_tree, si->ioctl_function, TRUE);
}

static void
dissect_smb2_ioctl_data_out(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si)
{
	dissect_smb2_ioctl_data(tvb, pinfo, tree, si->top_tree, si->ioctl_function, FALSE);
}

static int
dissect_smb2_ioctl_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	offset_length_buffer_t o_olb;
	offset_length_buffer_t i_olb;
	proto_tree *flags_tree = NULL;
	proto_item *flags_item = NULL;

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* reserved */
	offset += 2;

	/* ioctl function */
	offset = dissect_smb2_ioctl_function(tvb, pinfo, tree, offset, &si->ioctl_function);

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

	/* in buffer offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &i_olb, OLB_O_UINT32_S_UINT32, hf_smb2_ioctl_in_data);

	/* max ioctl in size */
	proto_tree_add_item(tree, hf_smb2_max_ioctl_in_size, tvb, offset, 4, TRUE);
	offset += 4;

	/* out buffer offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &o_olb, OLB_O_UINT32_S_UINT32, hf_smb2_ioctl_out_data);

	/* max ioctl out size */
	proto_tree_add_item(tree, hf_smb2_max_ioctl_out_size, tvb, offset, 4, TRUE);
	offset += 4;

	/* flags */
	if(tree){
		flags_item = proto_tree_add_item(tree, hf_smb2_ioctl_flags, tvb, offset, 4, TRUE);
		flags_tree = proto_item_add_subtree(flags_item, ett_smb2_ioctl_flags);
	}
	proto_tree_add_item(flags_tree, hf_smb2_ioctl_is_fsctl, tvb, offset, 4, TRUE);
	offset += 4;

	/* reserved */
	offset += 4;

	/* try to decode these blobs in the order they were encoded
	 * so that for "short" packets we will dissect as much as possible
	 * before aborting with "short packet"
	 */
	if(i_olb.off>o_olb.off){
		/* out buffer */
		dissect_smb2_olb_buffer(pinfo, tree, tvb, &o_olb, si, dissect_smb2_ioctl_data_out);
		/* in buffer */
		dissect_smb2_olb_buffer(pinfo, tree, tvb, &i_olb, si, dissect_smb2_ioctl_data_in);
	} else {
		/* in buffer */
		dissect_smb2_olb_buffer(pinfo, tree, tvb, &i_olb, si, dissect_smb2_ioctl_data_in);
		/* out buffer */
		dissect_smb2_olb_buffer(pinfo, tree, tvb, &o_olb, si, dissect_smb2_ioctl_data_out);
	}

	offset = dissect_smb2_olb_tvb_max_offset(offset, &o_olb);
	offset = dissect_smb2_olb_tvb_max_offset(offset, &i_olb);

	return offset;
}

static int
dissect_smb2_ioctl_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	offset_length_buffer_t o_olb;
	offset_length_buffer_t i_olb;

	switch (si->status) {
	case 0x00000000: break;
	default: return dissect_smb2_error_response(tvb, pinfo, tree, offset, si);
	}

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;

	/* ioctl function */
	offset = dissect_smb2_ioctl_function(tvb, pinfo, tree, offset, &si->ioctl_function);

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

	/* in buffer offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &i_olb, OLB_O_UINT32_S_UINT32, hf_smb2_ioctl_in_data);

	/* out buffer offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &o_olb, OLB_O_UINT32_S_UINT32, hf_smb2_ioctl_out_data);


	/* flags: reserved: must be zero */
	offset += 4;

	/* reserved */
	offset += 4;

	/* try to decode these blobs in the order they were encoded
	 * so that for "short" packets we will dissect as much as possible
	 * before aborting with "short packet"
	 */
	if(i_olb.off>o_olb.off){
		/* out buffer */
		dissect_smb2_olb_buffer(pinfo, tree, tvb, &o_olb, si, dissect_smb2_ioctl_data_out);
		/* in buffer */
		dissect_smb2_olb_buffer(pinfo, tree, tvb, &i_olb, si, dissect_smb2_ioctl_data_in);
	} else {
		/* in buffer */
		dissect_smb2_olb_buffer(pinfo, tree, tvb, &i_olb, si, dissect_smb2_ioctl_data_in);
		/* out buffer */
		dissect_smb2_olb_buffer(pinfo, tree, tvb, &o_olb, si, dissect_smb2_ioctl_data_out);
	}

	offset = dissect_smb2_olb_tvb_max_offset(offset, &i_olb);
	offset = dissect_smb2_olb_tvb_max_offset(offset, &o_olb);

	return offset;
}


static int
dissect_smb2_read_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	guint32 len;
	guint64 off;

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* padding and reserved */
	offset += 2;

	/* length */
	len=tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_read_length, tvb, offset, 4, TRUE);
	offset += 4;

	/* offset */
	off=tvb_get_letoh64(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_file_offset, tvb, offset, 8, TRUE);
	offset += 8;

	if (check_col(pinfo->cinfo, COL_INFO)){
		col_append_fstr(pinfo->cinfo, COL_INFO, " Len:%d Off:%" G_GINT64_MODIFIER "u", len, off);
	}

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

	/* minimum count */
	proto_tree_add_item(tree, hf_smb2_min_count, tvb, offset, 4, TRUE);

	/* channel */
	proto_tree_add_item(tree, hf_smb2_channel, tvb, offset, 4, TRUE);
	offset += 4;

	/* remaining bytes */
	proto_tree_add_item(tree, hf_smb2_remaining_bytes, tvb, offset, 4, TRUE);
	offset += 4;

	/* channel info offset */
	proto_tree_add_item(tree, hf_smb2_channel_info_offset, tvb, offset, 2, TRUE);
	offset += 2;

	/* channel info length */
	proto_tree_add_item(tree, hf_smb2_channel_info_length, tvb, offset, 2, TRUE);
	offset += 2;

	/* there is a buffer here   but it is never used (yet) */

	return offset;
}


static int
dissect_smb2_read_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	guint32 length;

	switch (si->status) {
	case 0x00000000: break;
	default: return dissect_smb2_error_response(tvb, pinfo, tree, offset, si);
	}

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* data offset */
	proto_tree_add_item(tree, hf_smb2_data_offset, tvb, offset, 2, TRUE);
	offset += 2;

	/* length  might even be 64bits if they are ambitious*/
	length=tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_read_length, tvb, offset, 4, TRUE);
	offset += 4;

	/* remaining */
	proto_tree_add_item(tree, hf_smb2_read_remaining, tvb, offset, 4, TRUE);
	offset += 4;

	/* reserved */
	offset += 4;

	/* data or dcerpc ?
	 * If the pidvalid flag is set we assume it is a deferred
	 * STATUS_PENDING read and thus a named pipe (==dcerpc)
	 */
	if(length && ( (si->tree && si->tree->share_type == SMB2_SHARE_TYPE_PIPE)||(si->flags & SMB2_FLAGS_ASYNC_CMD))){
		offset = dissect_file_data_dcerpc(tvb, pinfo, tree, offset, length, si->top_tree);
		return offset;
	}

	/* data */
	proto_tree_add_item(tree, hf_smb2_read_data, tvb, offset, length, TRUE);
	offset += MIN(length,(guint32)tvb_length_remaining(tvb, offset));

	return offset;
}

static void
report_create_context_malformed_buffer(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, const char *buffer_desc)
{
	proto_tree_add_text(tree, tvb, 0, tvb_length_remaining(tvb, 0),
			    "%s SHOULD NOT be generated. Malformed packeet", buffer_desc);
}
static void
dissect_smb2_ExtA_buffer_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si)
{
	proto_item *item=NULL;
	if (tree) {
		item = proto_tree_get_parent(tree);
		proto_item_append_text(item, ": SMB2_FILE_INFO_0f");
	}
	dissect_smb2_file_info_0f(tvb, pinfo, tree, 0, si);
	return;
}

static void
dissect_smb2_ExtA_buffer_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si _U_)
{
	report_create_context_malformed_buffer(tvb, pinfo, tree, "ExtA Response");
}

static void
dissect_smb2_SecD_buffer_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si)
{
	proto_item *item=NULL;
	if (tree) {
		item = proto_tree_get_parent(tree);
		proto_item_append_text(item, ": SMB2_SEC_INFO_00");
	}
	dissect_smb2_sec_info_00(tvb, pinfo, tree, 0, si);
	return;
}

static void
dissect_smb2_SecD_buffer_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si _U_)
{
	report_create_context_malformed_buffer(tvb, pinfo, tree, "SecD Response");
}

static void
dissect_smb2_TWrp_buffer_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	if (tree) {
		item = proto_tree_get_parent(tree);
		proto_item_append_text(item, ": Timestamp");
	}
	dissect_nt_64bit_time(tvb, tree, 0, hf_smb2_twrp_timestamp);

	return;
}

static void
dissect_smb2_TWrp_buffer_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, smb2_info_t *si _U_)
{
	report_create_context_malformed_buffer(tvb, pinfo, tree, "TWrp Response");
}

static void
dissect_smb2_QFid_buffer_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, smb2_info_t *si _U_)
{
        proto_item *item=NULL;

        if (tree) {
                item = proto_tree_get_parent(tree);
        }

	if (item) {
		if (tvb_length(tvb) == 0) {
			proto_item_append_text(item, ": NO DATA");
		} else {
			proto_item_append_text(item, ": QFid request should have no data, malformed packet");
		}
	}
}

static void
dissect_smb2_QFid_buffer_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, smb2_info_t *si _U_)
{
	int offset = 0;
	proto_item *item = NULL;
	proto_item *sub_item = NULL;
	proto_item *sub_tree = NULL;

	if (tree) {
		item = proto_tree_get_parent(tree);
	}

	if (item) {
		proto_item_append_text(item, ": QFid INFO");
		sub_item = proto_tree_add_text(tree, tvb, offset, -1, "QFid INFO");
		sub_tree = proto_item_add_subtree(sub_item, ett_smb2_QFid_buffer);
	}

	proto_tree_add_item(sub_tree, hf_smb2_qfid_fid, tvb, offset, 32, FALSE);
}

static void
dissect_smb2_AlSi_buffer_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, smb2_info_t *si _U_)
{
	proto_tree_add_item(tree, hf_smb2_allocation_size, tvb, 0, 8, TRUE);
}

static void
dissect_smb2_AlSi_buffer_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, smb2_info_t *si _U_)
{
	report_create_context_malformed_buffer(tvb, pinfo, tree, "AlSi Response");
}

static void
dissect_smb2_DHnQ_buffer_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si)
{
	dissect_smb2_fid(tvb, pinfo, tree, 0, si, FID_MODE_DHNQ);
}

static void
dissect_smb2_DHnQ_buffer_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, smb2_info_t *si _U_)
{
	proto_tree_add_item(tree, hf_smb2_dhnq_buffer_reserved, tvb, 0, 8, TRUE);
}

static void
dissect_smb2_DHnC_buffer_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si)
{
	dissect_smb2_fid(tvb, pinfo, tree, 0, si, FID_MODE_DHNC);
}

static void
dissect_smb2_DHnC_buffer_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si _U_)
{
	report_create_context_malformed_buffer(tvb, pinfo, tree, "DHnC Response");
}

/*
 * SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2
 *  4 - timeout
 *  4 - flags
 *  8 - reserved
 * 16 - create guid
 *
 * SMB2_CREATE_DURABLE_HANDLE_RESPONSE_V2
 *  4 - timeout
 *  4 - flags
 *
 * SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2
 * 16 - file id
 * 16 - create guid
 *  4 - flags
 *
 * SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2
 * - nothing -
 */
#define SMB2_DH2X_FLAGS_PERSISTENT_HANDLE 0x00000002

static void
dissect_smb2_DH2Q_buffer_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, smb2_info_t *si _U_)
{
	int offset = 0;
	static const int *dh2x_flags_fields[] = {
		&hf_smb2_dh2x_buffer_flags_persistent_handle,
		NULL
	};
	proto_item *item = NULL;
	proto_item *sub_item = NULL;
	proto_item *sub_tree = NULL;

	if (tree) {
		item = proto_tree_get_parent(tree);
	}

	if (item) {
		proto_item_append_text(item, ": DH2Q Request");
		sub_item = proto_tree_add_text(tree, tvb, offset, -1, "DH2Q Request");
		sub_tree = proto_item_add_subtree(sub_item, ett_smb2_DH2Q_buffer);
	}

	/* timeout */
	proto_tree_add_item(sub_tree, hf_smb2_dh2x_buffer_timeout, tvb, offset, 4, TRUE);
	offset += 4;

	/* flags */
	proto_tree_add_bitmask(sub_tree, tvb, offset, hf_smb2_dh2x_buffer_flags,
				ett_smb2_dh2x_flags, dh2x_flags_fields, TRUE);
	offset += 4;

	/* reserved */
	proto_tree_add_item(sub_tree, hf_smb2_dh2x_buffer_reserved, tvb, offset, 8, TRUE);
	offset += 8;

	/* create guid */
	proto_tree_add_item(sub_tree, hf_smb2_dh2x_buffer_create_guid, tvb, offset, 16, TRUE);
	offset += 16;
}

static void
dissect_smb2_DH2Q_buffer_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, smb2_info_t *si _U_)
{
	int offset = 0;
	proto_item *item = NULL;
	proto_item *sub_item = NULL;
	proto_item *sub_tree = NULL;

	if (tree) {
		item = proto_tree_get_parent(tree);
	}

	if (item) {
		proto_item_append_text(item, ": DH2Q Response");
		sub_item = proto_tree_add_text(tree, tvb, offset, -1, "DH2Q Response");
		sub_tree = proto_item_add_subtree(sub_item, ett_smb2_DH2Q_buffer);
	}

	/* timeout */
	proto_tree_add_item(sub_tree, hf_smb2_dh2x_buffer_timeout, tvb, offset, 4, TRUE);
	offset += 4;

	/* flags */
	proto_tree_add_item(sub_tree, hf_smb2_dh2x_buffer_flags, tvb, offset, 4, TRUE);
	offset += 4;
}

static void
dissect_smb2_DH2C_buffer_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si)
{
	int offset = 0;
	proto_item *item = NULL;
	proto_item *sub_item = NULL;
	proto_item *sub_tree = NULL;

	if (tree) {
		item = proto_tree_get_parent(tree);
	}

	if (item) {
		proto_item_append_text(item, ": DH2C Request");
		sub_item = proto_tree_add_text(tree, tvb, offset, -1, "DH2C Request");
		sub_tree = proto_item_add_subtree(sub_item, ett_smb2_DH2C_buffer);
	}

	/* file id */
	dissect_smb2_fid(tvb, pinfo, sub_tree, offset, si, FID_MODE_DHNC);
	offset += 16;

	/* create guid */
	proto_tree_add_item(sub_tree, hf_smb2_dh2x_buffer_create_guid, tvb, offset, 16, TRUE);
	offset += 16;

	/* flags */
	proto_tree_add_item(sub_tree, hf_smb2_dh2x_buffer_flags, tvb, offset, 4, TRUE);
	offset += 4;
}

static void
dissect_smb2_DH2C_buffer_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si _U_)
{
	report_create_context_malformed_buffer(tvb, pinfo, tree, "DH2C Response");
}

static void
dissect_smb2_MxAc_buffer_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, smb2_info_t *si _U_)
{
        int offset=0;
        proto_item *item=NULL;

        if (tree) {
                item = proto_tree_get_parent(tree);
        }

        if (tvb_length(tvb) == 0) {
                if (item) {
                        proto_item_append_text(item, ": NO DATA");
                }
                return;
        }

        if (item) {
                proto_item_append_text(item, ": Timestamp");
        }

	dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_mxac_timestamp);

	return;
}

static void
dissect_smb2_MxAc_buffer_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, smb2_info_t *si _U_)
{
	int offset=0;
	proto_item *item=NULL;
	proto_item *sub_item=NULL;
	proto_tree *sub_tree=NULL;

	if (tree) {
		item = proto_tree_get_parent(tree);
	}

	if (tvb_length(tvb) == 0) {
		if (item) {
			proto_item_append_text(item, ": NO DATA");
		}
		return;
	}

	if (item) {
		proto_item_append_text(item, ": MxAc INFO");
		sub_item = proto_tree_add_text(tree, tvb, offset, -1, "MxAc INFO");
		sub_tree = proto_item_add_subtree(sub_item, ett_smb2_MxAc_buffer);
	}

	proto_tree_add_item(sub_tree, hf_smb2_mxac_status, tvb, offset, 4, FALSE);
	offset += 4;

	dissect_smb_access_mask(tvb, sub_tree, offset);

	return;
}

/*
 * SMB2_CREATE_REQUEST_LEASE 32
 * 16 - lease key
 *  4 - lease state
 *  4 - lease flags
 *  8 - lease duration
 *
 * SMB2_CREATE_REQUEST_LEASE_V2 52
 * 16 - lease key
 *  4 - lease state
 *  4 - lease flags
 *  8 - lease duration
 * 16 - pareant lease key
 *  4 - epoch
 */
#define SMB2_LEASE_STATE_READ_CACHING   0x00000001
#define SMB2_LEASE_STATE_HANDLE_CACHING 0x00000002
#define SMB2_LEASE_STATE_WRITE_CACHING  0x00000004

#define SMB2_LEASE_FLAGS_BREAK_ACK_REQUIRED    0x00000001
#define SMB2_LEASE_FLAGS_BREAK_IN_PROGRESS     0x00000002
#define SMB2_LEASE_FLAGS_PARENT_LEASE_KEY_SET  0x00000004

static const int *lease_state_fields[] = {
	&hf_smb2_lease_state_read_caching,
	&hf_smb2_lease_state_handle_caching,
	&hf_smb2_lease_state_write_caching,
	NULL
};
static const int *lease_flags_fields[] = {
	&hf_smb2_lease_flags_break_ack_required,
	&hf_smb2_lease_flags_break_in_progress,
	&hf_smb2_lease_flags_parent_lease_key_set,
	NULL
};

static void
dissect_SMB2_CREATE_LEASE_VX(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, smb2_info_t *si _U_)
{
	int offset = 0;
	int len;
	proto_item *sub_item=NULL;
	proto_tree *sub_tree=NULL;
	proto_item *parent_item=NULL;

	if (parent_tree) {
		parent_item = proto_tree_get_parent(parent_tree);
	}

	len = tvb_length(tvb);

	switch (len) {
	case 32: /* SMB2_CREATE_REQUEST/RESPONSE_LEASE */
		if (parent_item) {
			proto_item_append_text(parent_item, ": LEASE_V1");
			sub_item = proto_tree_add_text(parent_tree, tvb, offset, len, "LEASE_V1");
			sub_tree = proto_item_add_subtree(sub_item, ett_smb2_RqLs_buffer);
		}

		break;
	case 52: /* SMB2_CREATE_REQUEST/RESPONSE_LEASE_V2 */
		if (parent_item) {
			proto_item_append_text(parent_item, ": LEASE_V2");
			sub_item = proto_tree_add_text(parent_tree, tvb, offset, len, "LEASE_V2");
			sub_tree = proto_item_add_subtree(sub_item, ett_smb2_RqLs_buffer);
		}

		break;
	default:
		report_create_context_malformed_buffer(tvb, pinfo, parent_tree, "RqLs");
		break;
	}

	proto_tree_add_item(sub_tree, hf_smb2_lease_key, tvb, offset, 16, TRUE);
	offset += 16;

	proto_tree_add_bitmask(sub_tree, tvb, offset, hf_smb2_lease_state,
			       ett_smb2_lease_state, lease_state_fields, TRUE);
	offset += 4;

	proto_tree_add_bitmask(sub_tree, tvb, offset, hf_smb2_lease_flags,
			       ett_smb2_lease_flags, lease_flags_fields, TRUE);
	offset += 4;

	proto_tree_add_item(sub_tree, hf_smb2_lease_duration, tvb, offset, 8, TRUE);
	offset += 8;

	if (len < 52) {
		return;
	}

	proto_tree_add_item(sub_tree, hf_smb2_parent_lease_key, tvb, offset, 16, TRUE);
	offset += 16;

	proto_tree_add_item(sub_tree, hf_smb2_lease_epoch, tvb, offset, 4, TRUE);
	offset += 4;
}

static void
dissect_smb2_RqLs_buffer_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, smb2_info_t *si _U_)
{
	dissect_SMB2_CREATE_LEASE_VX(tvb, pinfo, tree, si);
}

static void
dissect_smb2_RqLs_buffer_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, smb2_info_t *si _U_)
{
	dissect_SMB2_CREATE_LEASE_VX(tvb, pinfo, tree, si);
}

/*
 * SMB2_CREATE_APP_INSTANCE_ID
 *  2 - structure size - 20
 *  2 - reserved
 * 16 - application guid
 */

static void
dissect_smb2_APP_INSTANCE_buffer_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, smb2_info_t *si _U_)
{
	int offset = 0;
	proto_item *item = NULL;
	proto_item *sub_item = NULL;
	proto_item *sub_tree = NULL;

	if (tree) {
		item = proto_tree_get_parent(tree);
	}

	if (item) {
		proto_item_append_text(item, ": APP INSTANCE ID");
		sub_item = proto_tree_add_text(tree, tvb, offset, -1, "APP INSTANCE ID");
		sub_tree = proto_item_add_subtree(sub_item, ett_smb2_APP_INSTANCE_buffer);
	}

	/* struct size */
	proto_tree_add_item(sub_tree, hf_smb2_APP_INSTANCE_buffer_struct_size,
			    tvb, offset, 2, TRUE);
	offset += 2;

	/* reserved */
	proto_tree_add_item(sub_tree, hf_smb2_APP_INSTANCE_buffer_reserved,
			    tvb, offset, 2, TRUE);
	offset += 2;

	/* create guid */
	proto_tree_add_item(sub_tree, hf_smb2_APP_INSTANCE_buffer_app_guid, tvb, offset, 16, TRUE);
	offset += 16;
}

static void
dissect_smb2_APP_INSTANCE_buffer_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, smb2_info_t *si _U_)
{
	report_create_context_malformed_buffer(tvb, pinfo, tree, "APP INSTANCE Response");
}

typedef void (*create_context_data_dissector_t)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si);

typedef struct create_context_data_dissectors {
	create_context_data_dissector_t request;
	create_context_data_dissector_t response;
} create_context_data_dissectors_t;

struct create_context_data_tag_dissectors {
	const char *tag;
	create_context_data_dissectors_t dissectors;
};

struct create_context_data_tag_dissectors create_context_dissectors_array[] = {
	{ "ExtA", { dissect_smb2_ExtA_buffer_request, dissect_smb2_ExtA_buffer_response } },
	{ "SecD", { dissect_smb2_SecD_buffer_request, dissect_smb2_SecD_buffer_response } },
	{ "AlSi", { dissect_smb2_AlSi_buffer_request, dissect_smb2_AlSi_buffer_response } },
	{ "MxAc", { dissect_smb2_MxAc_buffer_request, dissect_smb2_MxAc_buffer_response } },
	{ "DHnQ", { dissect_smb2_DHnQ_buffer_request, dissect_smb2_DHnQ_buffer_response } },
	{ "DHnC", { dissect_smb2_DHnC_buffer_request, dissect_smb2_DHnC_buffer_response } },
	{ "DH2Q", { dissect_smb2_DH2Q_buffer_request, dissect_smb2_DH2Q_buffer_response } },
	{ "DH2C", { dissect_smb2_DH2C_buffer_request, dissect_smb2_DH2C_buffer_response } },
	{ "TWrp", { dissect_smb2_TWrp_buffer_request, dissect_smb2_TWrp_buffer_response } },
	{ "QFid", { dissect_smb2_QFid_buffer_request, dissect_smb2_QFid_buffer_response } },
	{ "RqLs", { dissect_smb2_RqLs_buffer_request, dissect_smb2_RqLs_buffer_response } },
	{ "744D142E-46FA-0890-4AF7-A7EF6AA6BC45",
		{ dissect_smb2_APP_INSTANCE_buffer_request,
		  dissect_smb2_APP_INSTANCE_buffer_response } }
};

static struct create_context_data_dissectors*
get_create_context_data_dissectors(const char *tag)
{
	size_t i;
	for (i=0; i<array_length(create_context_dissectors_array); i++) {
		if (!strcmp(tag, create_context_dissectors_array[i].tag))
			return &create_context_dissectors_array[i].dissectors;
	}
	return NULL;
}

static void
dissect_smb2_create_extra_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, smb2_info_t *si)
{
	offset_length_buffer_t tag_olb;
	offset_length_buffer_t data_olb;
	const char *tag;
	guint16 chain_offset;
	int offset=0;
	int len=-1;
	create_context_data_dissectors_t *dissectors = NULL;
	create_context_data_dissector_t dissector = NULL;
	proto_item *sub_item=NULL;
	proto_tree *sub_tree=NULL;
	proto_item *parent_item=NULL;

	chain_offset=tvb_get_letohl(tvb, offset);
	if (chain_offset) {
		len = chain_offset;
	}

	if(parent_tree){
		sub_item = proto_tree_add_text(parent_tree, tvb, offset, len, "Chain Element");
		sub_tree = proto_item_add_subtree(sub_item, ett_smb2_create_chain_element);
		parent_item = proto_tree_get_parent(parent_tree);
	}

	/* chain offset */
	proto_tree_add_item(sub_tree, hf_smb2_create_chain_offset, tvb, offset, 4, TRUE);
	offset += 4;

	/* tag  offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &tag_olb, OLB_O_UINT16_S_UINT32, hf_smb2_tag);

	/* data  offset/length */
	dissect_smb2_olb_length_offset(tvb, offset, &data_olb, OLB_O_UINT16_S_UINT32, hf_smb2_create_chain_data);

	/* tag string */
	tag = dissect_smb2_olb_string(pinfo, sub_tree, tvb, &tag_olb, OLB_TYPE_ASCII_STRING);

	proto_item_append_text(parent_item, " %s", tag);
	proto_item_append_text(sub_item, ": %s", tag);

	/* data */
	dissectors = get_create_context_data_dissectors(tag);
	if (dissectors)
		dissector = (si->flags & SMB2_FLAGS_RESPONSE) ? dissectors->response : dissectors->request;

	dissect_smb2_olb_buffer(pinfo, sub_tree, tvb, &data_olb, si, dissector);

	if(chain_offset){
		tvbuff_t *chain_tvb;
		chain_tvb=tvb_new_subset(tvb, chain_offset, tvb_length_remaining(tvb, chain_offset), tvb_reported_length_remaining(tvb, chain_offset));

		/* next extra info */
		dissect_smb2_create_extra_info(chain_tvb, pinfo, parent_tree, si);
	}
	return;
}

static int
dissect_smb2_create_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	offset_length_buffer_t f_olb, e_olb;
	const char *fname;

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* security flags */
	offset++;

	/* oplock */
	offset = dissect_smb2_oplock(tree, tvb, offset);

	/* impersonation level */
	proto_tree_add_item(tree, hf_smb2_impersonation_level, tvb, offset, 4, TRUE);
	offset += 4;

	/* create flags */
	proto_tree_add_item(tree, hf_smb2_create_flags, tvb, offset, 8, TRUE);
	offset += 8;

	/* reserved */
	offset += 8;

	/* access mask */
	offset = dissect_smb_access_mask(tvb, tree, offset);

	/* File Attributes */
	offset = dissect_file_ext_attr(tvb, tree, offset);

	/* share access */
	offset = dissect_nt_share_access(tvb, tree, offset);

	/* create disposition */
	proto_tree_add_item(tree, hf_smb2_create_disposition, tvb, offset, 4, TRUE);
	offset += 4;

	/* create options */
	offset = dissect_nt_create_options(tvb, tree, offset);

	/* filename  offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &f_olb, OLB_O_UINT16_S_UINT16, hf_smb2_filename);

	/* extrainfo offset */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &e_olb, OLB_O_UINT32_S_UINT32, hf_smb2_extrainfo);

	/* filename string */
	fname = dissect_smb2_olb_string(pinfo, tree, tvb, &f_olb, OLB_TYPE_UNICODE_STRING);
	if (check_col(pinfo->cinfo, COL_INFO)){
		col_append_fstr(pinfo->cinfo, COL_INFO, " File: %s", fname);
	}

	/* save the name if it looks sane */
	if(!pinfo->fd->flags.visited){
		if(si->saved && si->saved->extra_info_type==SMB2_EI_FILENAME){
			g_free(si->saved->extra_info);
			si->saved->extra_info=NULL;
			si->saved->extra_info_type=SMB2_EI_NONE;
		}
		if(si->saved && f_olb.len && f_olb.len<256){
			si->saved->extra_info_type=SMB2_EI_FILENAME;
			si->saved->extra_info=g_malloc(f_olb.len+1);
			g_snprintf(si->saved->extra_info, f_olb.len+1, "%s", fname);
		}
	}

	/* If extrainfo_offset is non-null then this points to another
	 * buffer. The offset is relative to the start of the smb packet
	 */
	dissect_smb2_olb_buffer(pinfo, tree, tvb, &e_olb, si, dissect_smb2_create_extra_info);

	offset = dissect_smb2_olb_tvb_max_offset(offset, &f_olb);
	offset = dissect_smb2_olb_tvb_max_offset(offset, &e_olb);

	return offset;
}

#define SMB2_CREATE_REP_FLAGS_REPARSE_POINT 0x01

static int
dissect_smb2_create_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	offset_length_buffer_t e_olb;
	static const int *create_rep_flags_fields[] = {
		&hf_smb2_create_rep_flags_reparse_point,
		NULL
	};

	switch (si->status) {
	case 0x00000000: break;
	default: return dissect_smb2_error_response(tvb, pinfo, tree, offset, si);
	}

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* oplock */
	offset = dissect_smb2_oplock(tree, tvb, offset);

	/* reserved */
	proto_tree_add_bitmask(tree, tvb, offset, hf_smb2_create_rep_flags,
			       ett_smb2_create_rep_flags, create_rep_flags_fields, TRUE);
	offset += 1;

	/* create action */
	proto_tree_add_item(tree, hf_smb2_create_action, tvb, offset, 4, TRUE);
	offset += 4;

	/* create time */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_create_timestamp);

	/* last access */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_access_timestamp);

	/* last write */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_write_timestamp);

	/* last change */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_change_timestamp);

	/* allocation size */
	proto_tree_add_item(tree, hf_smb2_allocation_size, tvb, offset, 8, TRUE);
	offset += 8;

	/* end of file */
	proto_tree_add_item(tree, hf_smb2_end_of_file, tvb, offset, 8, TRUE);
	offset += 8;

	/* File Attributes */
	offset = dissect_file_ext_attr(tvb, tree, offset);

	/* reserved */
	offset += 4;

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_OPEN);

	/* extrainfo offset */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &e_olb, OLB_O_UINT32_S_UINT32, hf_smb2_extrainfo);

	/* If extrainfo_offset is non-null then this points to another
	 * buffer. The offset is relative to the start of the smb packet
	 */
	dissect_smb2_olb_buffer(pinfo, tree, tvb, &e_olb, si, dissect_smb2_create_extra_info);

	offset = dissect_smb2_olb_tvb_max_offset(offset, &e_olb);

	/* free si->saved->extra_info   we dont need it any more */
	if(si->saved && si->saved->extra_info_type==SMB2_EI_FILENAME){
		g_free(si->saved->extra_info);
		si->saved->extra_info=NULL;
		si->saved->extra_info_type=SMB2_EI_NONE;
	}

	return offset;
}


static int
dissect_smb2_setinfo_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	guint32 setinfo_size;
	guint16 setinfo_offset;

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* class and info level */
	offset = dissect_smb2_class_infolevel(pinfo, tvb, offset, tree, si);

	/* size */
	setinfo_size=tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_setinfo_size, tvb, offset, 4, TRUE);
	offset += 4;

	/* offset */
	setinfo_offset=tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_setinfo_offset, tvb, offset, 2, TRUE);
	offset += 2;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 6, TRUE);
	offset += 6;

	/* fid */
	dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

	/* data */
	if(si->saved)
	  dissect_smb2_infolevel(tvb, pinfo, tree, setinfo_offset, si, si->saved->class, si->saved->infolevel);
	offset = setinfo_offset + setinfo_size;

	return offset;
}

static int
dissect_smb2_setinfo_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	/* class/infolevel */
	dissect_smb2_class_infolevel(pinfo, tvb, offset, tree, si);

	switch (si->status) {
	case 0x00000000: break;
	default: return dissect_smb2_error_response(tvb, pinfo, tree, offset, si);
	}

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	return offset;
}

static int
dissect_smb2_break_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	guint16 buffer_code;

	/* buffer code */
	buffer_code = tvb_get_letohs(tvb, offset);
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	if (buffer_code == 24) {
		/* OPLOCK Break */

		/* oplock */
		offset = dissect_smb2_oplock(tree, tvb, offset);

		/* reserved */
		offset += 1;

		/* reserved */
		offset += 4;

		/* fid */
		offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

		return offset;
	}

	if (buffer_code == 36) {
		/* Lease Break Acknowledgment */

		/* reserved */
		proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 2, TRUE);
		offset +=2;

		/* lease flags */
		proto_tree_add_bitmask(tree, tvb, offset, hf_smb2_lease_flags,
				       ett_smb2_lease_flags, lease_flags_fields, TRUE);
		offset += 4;

		/* lease key */
		proto_tree_add_item(tree, hf_smb2_lease_key, tvb, offset, 16, TRUE);
		offset += 16;

		/* lease state */
		proto_tree_add_bitmask(tree, tvb, offset, hf_smb2_lease_state,
				       ett_smb2_lease_state, lease_state_fields, TRUE);
		offset += 4;

		proto_tree_add_item(tree, hf_smb2_lease_duration, tvb, offset, 8, TRUE);
		offset += 8;

		return offset;
	}

	return offset;
}

static int
dissect_smb2_break_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	guint16 buffer_code;

	switch (si->status) {
	case 0x00000000: break;
	default: return dissect_smb2_error_response(tvb, pinfo, tree, offset, si);
	}

	/* buffer code */
	buffer_code = tvb_get_letohs(tvb, offset);
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	if (buffer_code == 24) {
		/* OPLOCK Break Notification */

		/* oplock */
		offset = dissect_smb2_oplock(tree, tvb, offset);

		/* reserved */
		offset += 1;

		/* reserved */
		offset += 4;

		/* fid */
		offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

		/* in break requests from server to client here're 24 byte zero bytes
		 * which are likely a bug in windows (they may use 2* 24 bytes instead of just
		 * 1 *24 bytes
		 */
		return offset;
	}

	if (buffer_code == 44) {
		proto_item *item;

		/* Lease Break Notification */

		/* reserved */
		proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 2, TRUE);
		offset +=2;

		/* lease flags */
		proto_tree_add_bitmask(tree, tvb, offset, hf_smb2_lease_flags,
				       ett_smb2_lease_flags, lease_flags_fields, TRUE);
		offset += 4;

		/* lease key */
		proto_tree_add_item(tree, hf_smb2_lease_key, tvb, offset, 16, TRUE);
		offset += 16;

		/* current lease state */
		item = proto_tree_add_bitmask(tree, tvb, offset, hf_smb2_lease_state,
					      ett_smb2_lease_state, lease_state_fields, TRUE);
		if (item) {
			proto_item_prepend_text(item, "Current ");
		}
		offset += 4;

		/* new lease state */
		item = proto_tree_add_bitmask(tree, tvb, offset, hf_smb2_lease_state,
					      ett_smb2_lease_state, lease_state_fields, TRUE);
		if (item) {
			proto_item_prepend_text(item, "New ");
		}
		offset += 4;

		/* break reason - reserved */
		proto_tree_add_item(tree, hf_smb2_lease_break_reason, tvb, offset, 4, TRUE);
		offset += 4;

		/* access mask hint - reserved */
		proto_tree_add_item(tree, hf_smb2_lease_access_mask_hint, tvb, offset, 4, TRUE);
		offset += 4;

		/* share mask hint - reserved */
		proto_tree_add_item(tree, hf_smb2_lease_share_mask_hint, tvb, offset, 4, TRUE);
		offset += 4;

		return offset;
	}

	if (buffer_code == 36) {
		/* Lease Break Response */

		/* reserved */
		proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 2, TRUE);
		offset +=2;

		/* lease flags */
		proto_tree_add_bitmask(tree, tvb, offset, hf_smb2_lease_flags,
				       ett_smb2_lease_flags, lease_flags_fields, TRUE);
		offset += 4;

		/* lease key */
		proto_tree_add_item(tree, hf_smb2_lease_key, tvb, offset, 16, TRUE);
		offset += 16;

		/* lease state */
		proto_tree_add_bitmask(tree, tvb, offset, hf_smb2_lease_state,
				       ett_smb2_lease_state, lease_state_fields, TRUE);
		offset += 4;

		proto_tree_add_item(tree, hf_smb2_lease_duration, tvb, offset, 8, TRUE);
		offset += 8;

		return offset;
	}

	return offset;
}

/* names here are just until we find better names for these functions */
static const value_string smb2_cmd_vals[] = {
  { 0x00, "NegotiateProtocol" },
  { 0x01, "SessionSetup" },
  { 0x02, "SessionLogoff" },
  { 0x03, "TreeConnect" },
  { 0x04, "TreeDisconnect" },
  { 0x05, "Create" },
  { 0x06, "Close" },
  { 0x07, "Flush" },
  { 0x08, "Read" },
  { 0x09, "Write" },
  { 0x0A, "Lock" },
  { 0x0B, "Ioctl" },
  { 0x0C, "Cancel" },
  { 0x0D, "KeepAlive" },
  { 0x0E, "Find" },
  { 0x0F, "Notify" },
  { 0x10, "GetInfo" },
  { 0x11, "SetInfo" },
  { 0x12, "Break" },
  { 0x13, "unknown-0x13" },
  { 0x14, "unknown-0x14" },
  { 0x15, "unknown-0x15" },
  { 0x16, "unknown-0x16" },
  { 0x17, "unknown-0x17" },
  { 0x18, "unknown-0x18" },
  { 0x19, "unknown-0x19" },
  { 0x1A, "unknown-0x1A" },
  { 0x1B, "unknown-0x1B" },
  { 0x1C, "unknown-0x1C" },
  { 0x1D, "unknown-0x1D" },
  { 0x1E, "unknown-0x1E" },
  { 0x1F, "unknown-0x1F" },
  { 0x20, "unknown-0x20" },
  { 0x21, "unknown-0x21" },
  { 0x22, "unknown-0x22" },
  { 0x23, "unknown-0x23" },
  { 0x24, "unknown-0x24" },
  { 0x25, "unknown-0x25" },
  { 0x26, "unknown-0x26" },
  { 0x27, "unknown-0x27" },
  { 0x28, "unknown-0x28" },
  { 0x29, "unknown-0x29" },
  { 0x2A, "unknown-0x2A" },
  { 0x2B, "unknown-0x2B" },
  { 0x2C, "unknown-0x2C" },
  { 0x2D, "unknown-0x2D" },
  { 0x2E, "unknown-0x2E" },
  { 0x2F, "unknown-0x2F" },
  { 0x30, "unknown-0x30" },
  { 0x31, "unknown-0x31" },
  { 0x32, "unknown-0x32" },
  { 0x33, "unknown-0x33" },
  { 0x34, "unknown-0x34" },
  { 0x35, "unknown-0x35" },
  { 0x36, "unknown-0x36" },
  { 0x37, "unknown-0x37" },
  { 0x38, "unknown-0x38" },
  { 0x39, "unknown-0x39" },
  { 0x3A, "unknown-0x3A" },
  { 0x3B, "unknown-0x3B" },
  { 0x3C, "unknown-0x3C" },
  { 0x3D, "unknown-0x3D" },
  { 0x3E, "unknown-0x3E" },
  { 0x3F, "unknown-0x3F" },
  { 0x40, "unknown-0x40" },
  { 0x41, "unknown-0x41" },
  { 0x42, "unknown-0x42" },
  { 0x43, "unknown-0x43" },
  { 0x44, "unknown-0x44" },
  { 0x45, "unknown-0x45" },
  { 0x46, "unknown-0x46" },
  { 0x47, "unknown-0x47" },
  { 0x48, "unknown-0x48" },
  { 0x49, "unknown-0x49" },
  { 0x4A, "unknown-0x4A" },
  { 0x4B, "unknown-0x4B" },
  { 0x4C, "unknown-0x4C" },
  { 0x4D, "unknown-0x4D" },
  { 0x4E, "unknown-0x4E" },
  { 0x4F, "unknown-0x4F" },
  { 0x50, "unknown-0x50" },
  { 0x51, "unknown-0x51" },
  { 0x52, "unknown-0x52" },
  { 0x53, "unknown-0x53" },
  { 0x54, "unknown-0x54" },
  { 0x55, "unknown-0x55" },
  { 0x56, "unknown-0x56" },
  { 0x57, "unknown-0x57" },
  { 0x58, "unknown-0x58" },
  { 0x59, "unknown-0x59" },
  { 0x5A, "unknown-0x5A" },
  { 0x5B, "unknown-0x5B" },
  { 0x5C, "unknown-0x5C" },
  { 0x5D, "unknown-0x5D" },
  { 0x5E, "unknown-0x5E" },
  { 0x5F, "unknown-0x5F" },
  { 0x60, "unknown-0x60" },
  { 0x61, "unknown-0x61" },
  { 0x62, "unknown-0x62" },
  { 0x63, "unknown-0x63" },
  { 0x64, "unknown-0x64" },
  { 0x65, "unknown-0x65" },
  { 0x66, "unknown-0x66" },
  { 0x67, "unknown-0x67" },
  { 0x68, "unknown-0x68" },
  { 0x69, "unknown-0x69" },
  { 0x6A, "unknown-0x6A" },
  { 0x6B, "unknown-0x6B" },
  { 0x6C, "unknown-0x6C" },
  { 0x6D, "unknown-0x6D" },
  { 0x6E, "unknown-0x6E" },
  { 0x6F, "unknown-0x6F" },
  { 0x70, "unknown-0x70" },
  { 0x71, "unknown-0x71" },
  { 0x72, "unknown-0x72" },
  { 0x73, "unknown-0x73" },
  { 0x74, "unknown-0x74" },
  { 0x75, "unknown-0x75" },
  { 0x76, "unknown-0x76" },
  { 0x77, "unknown-0x77" },
  { 0x78, "unknown-0x78" },
  { 0x79, "unknown-0x79" },
  { 0x7A, "unknown-0x7A" },
  { 0x7B, "unknown-0x7B" },
  { 0x7C, "unknown-0x7C" },
  { 0x7D, "unknown-0x7D" },
  { 0x7E, "unknown-0x7E" },
  { 0x7F, "unknown-0x7F" },
  { 0x80, "unknown-0x80" },
  { 0x81, "unknown-0x81" },
  { 0x82, "unknown-0x82" },
  { 0x83, "unknown-0x83" },
  { 0x84, "unknown-0x84" },
  { 0x85, "unknown-0x85" },
  { 0x86, "unknown-0x86" },
  { 0x87, "unknown-0x87" },
  { 0x88, "unknown-0x88" },
  { 0x89, "unknown-0x89" },
  { 0x8A, "unknown-0x8A" },
  { 0x8B, "unknown-0x8B" },
  { 0x8C, "unknown-0x8C" },
  { 0x8D, "unknown-0x8D" },
  { 0x8E, "unknown-0x8E" },
  { 0x8F, "unknown-0x8F" },
  { 0x90, "unknown-0x90" },
  { 0x91, "unknown-0x91" },
  { 0x92, "unknown-0x92" },
  { 0x93, "unknown-0x93" },
  { 0x94, "unknown-0x94" },
  { 0x95, "unknown-0x95" },
  { 0x96, "unknown-0x96" },
  { 0x97, "unknown-0x97" },
  { 0x98, "unknown-0x98" },
  { 0x99, "unknown-0x99" },
  { 0x9A, "unknown-0x9A" },
  { 0x9B, "unknown-0x9B" },
  { 0x9C, "unknown-0x9C" },
  { 0x9D, "unknown-0x9D" },
  { 0x9E, "unknown-0x9E" },
  { 0x9F, "unknown-0x9F" },
  { 0xA0, "unknown-0xA0" },
  { 0xA1, "unknown-0xA1" },
  { 0xA2, "unknown-0xA2" },
  { 0xA3, "unknown-0xA3" },
  { 0xA4, "unknown-0xA4" },
  { 0xA5, "unknown-0xA5" },
  { 0xA6, "unknown-0xA6" },
  { 0xA7, "unknown-0xA7" },
  { 0xA8, "unknown-0xA8" },
  { 0xA9, "unknown-0xA9" },
  { 0xAA, "unknown-0xAA" },
  { 0xAB, "unknown-0xAB" },
  { 0xAC, "unknown-0xAC" },
  { 0xAD, "unknown-0xAD" },
  { 0xAE, "unknown-0xAE" },
  { 0xAF, "unknown-0xAF" },
  { 0xB0, "unknown-0xB0" },
  { 0xB1, "unknown-0xB1" },
  { 0xB2, "unknown-0xB2" },
  { 0xB3, "unknown-0xB3" },
  { 0xB4, "unknown-0xB4" },
  { 0xB5, "unknown-0xB5" },
  { 0xB6, "unknown-0xB6" },
  { 0xB7, "unknown-0xB7" },
  { 0xB8, "unknown-0xB8" },
  { 0xB9, "unknown-0xB9" },
  { 0xBA, "unknown-0xBA" },
  { 0xBB, "unknown-0xBB" },
  { 0xBC, "unknown-0xBC" },
  { 0xBD, "unknown-0xBD" },
  { 0xBE, "unknown-0xBE" },
  { 0xBF, "unknown-0xBF" },
  { 0xC0, "unknown-0xC0" },
  { 0xC1, "unknown-0xC1" },
  { 0xC2, "unknown-0xC2" },
  { 0xC3, "unknown-0xC3" },
  { 0xC4, "unknown-0xC4" },
  { 0xC5, "unknown-0xC5" },
  { 0xC6, "unknown-0xC6" },
  { 0xC7, "unknown-0xC7" },
  { 0xC8, "unknown-0xC8" },
  { 0xC9, "unknown-0xC9" },
  { 0xCA, "unknown-0xCA" },
  { 0xCB, "unknown-0xCB" },
  { 0xCC, "unknown-0xCC" },
  { 0xCD, "unknown-0xCD" },
  { 0xCE, "unknown-0xCE" },
  { 0xCF, "unknown-0xCF" },
  { 0xD0, "unknown-0xD0" },
  { 0xD1, "unknown-0xD1" },
  { 0xD2, "unknown-0xD2" },
  { 0xD3, "unknown-0xD3" },
  { 0xD4, "unknown-0xD4" },
  { 0xD5, "unknown-0xD5" },
  { 0xD6, "unknown-0xD6" },
  { 0xD7, "unknown-0xD7" },
  { 0xD8, "unknown-0xD8" },
  { 0xD9, "unknown-0xD9" },
  { 0xDA, "unknown-0xDA" },
  { 0xDB, "unknown-0xDB" },
  { 0xDC, "unknown-0xDC" },
  { 0xDD, "unknown-0xDD" },
  { 0xDE, "unknown-0xDE" },
  { 0xDF, "unknown-0xDF" },
  { 0xE0, "unknown-0xE0" },
  { 0xE1, "unknown-0xE1" },
  { 0xE2, "unknown-0xE2" },
  { 0xE3, "unknown-0xE3" },
  { 0xE4, "unknown-0xE4" },
  { 0xE5, "unknown-0xE5" },
  { 0xE6, "unknown-0xE6" },
  { 0xE7, "unknown-0xE7" },
  { 0xE8, "unknown-0xE8" },
  { 0xE9, "unknown-0xE9" },
  { 0xEA, "unknown-0xEA" },
  { 0xEB, "unknown-0xEB" },
  { 0xEC, "unknown-0xEC" },
  { 0xED, "unknown-0xED" },
  { 0xEE, "unknown-0xEE" },
  { 0xEF, "unknown-0xEF" },
  { 0xF0, "unknown-0xF0" },
  { 0xF1, "unknown-0xF1" },
  { 0xF2, "unknown-0xF2" },
  { 0xF3, "unknown-0xF3" },
  { 0xF4, "unknown-0xF4" },
  { 0xF5, "unknown-0xF5" },
  { 0xF6, "unknown-0xF6" },
  { 0xF7, "unknown-0xF7" },
  { 0xF8, "unknown-0xF8" },
  { 0xF9, "unknown-0xF9" },
  { 0xFA, "unknown-0xFA" },
  { 0xFB, "unknown-0xFB" },
  { 0xFC, "unknown-0xFC" },
  { 0xFD, "unknown-0xFD" },
  { 0xFE, "unknown-0xFE" },
  { 0xFF, "unknown-0xFF" },
  { 0x00, NULL },
};

value_string_ext smb2_cmd_vals_ext = VALUE_STRING_EXT_INIT(smb2_cmd_vals);

static const char *decode_smb2_name(guint16 cmd)
{
  if (cmd > 0xFF) return "unknown";
  return(smb2_cmd_vals[cmd & 0xFF].strptr);
}

static smb2_function smb2_dissector[256] = {
  /* 0x00 NegotiateProtocol*/
	{dissect_smb2_negotiate_protocol_request,
	 dissect_smb2_negotiate_protocol_response},
  /* 0x01 SessionSetup*/
	{dissect_smb2_session_setup_request,
	 dissect_smb2_session_setup_response},
  /* 0x02 SessionLogoff*/
	{dissect_smb2_sessionlogoff_request,
	 dissect_smb2_sessionlogoff_response},
  /* 0x03 TreeConnect*/
	{dissect_smb2_tree_connect_request,
	 dissect_smb2_tree_connect_response},
  /* 0x04 TreeDisconnect*/
	{dissect_smb2_tree_disconnect_request,
	 dissect_smb2_tree_disconnect_response},
  /* 0x05 Create*/
	{dissect_smb2_create_request,
	 dissect_smb2_create_response},
  /* 0x06 Close*/
	{dissect_smb2_close_request,
	 dissect_smb2_close_response},
  /* 0x07 Flush*/
	{dissect_smb2_flush_request,
	 dissect_smb2_flush_response},
  /* 0x08 Read*/
	{dissect_smb2_read_request,
	 dissect_smb2_read_response},
  /* 0x09 Writew*/
	{dissect_smb2_write_request,
	 dissect_smb2_write_response},
  /* 0x0a Lock */
	{dissect_smb2_lock_request,
	 dissect_smb2_lock_response},
  /* 0x0b Ioctl*/
	{dissect_smb2_ioctl_request,
	 dissect_smb2_ioctl_response},
  /* 0x0c Cancel*/
	{dissect_smb2_cancel_request,
	 NULL},
  /* 0x0d KeepAlive*/
	{dissect_smb2_keepalive_request,
	 dissect_smb2_keepalive_response},
  /* 0x0e Find*/
	{dissect_smb2_find_request,
	 dissect_smb2_find_response},
  /* 0x0f Notify*/
	{dissect_smb2_notify_request,
	 dissect_smb2_notify_response},
  /* 0x10 GetInfo*/
	{dissect_smb2_getinfo_request,
	 dissect_smb2_getinfo_response},
  /* 0x11 SetInfo*/
	{dissect_smb2_setinfo_request,
	 dissect_smb2_setinfo_response},
  /* 0x12 Break */
  	{dissect_smb2_break_request,
	 dissect_smb2_break_response},
  /* 0x13 */  {NULL, NULL},
  /* 0x14 */  {NULL, NULL},
  /* 0x15 */  {NULL, NULL},
  /* 0x16 */  {NULL, NULL},
  /* 0x17 */  {NULL, NULL},
  /* 0x18 */  {NULL, NULL},
  /* 0x19 */  {NULL, NULL},
  /* 0x1a */  {NULL, NULL},
  /* 0x1b */  {NULL, NULL},
  /* 0x1c */  {NULL, NULL},
  /* 0x1d */  {NULL, NULL},
  /* 0x1e */  {NULL, NULL},
  /* 0x1f */  {NULL, NULL},
  /* 0x20 */  {NULL, NULL},
  /* 0x21 */  {NULL, NULL},
  /* 0x22 */  {NULL, NULL},
  /* 0x23 */  {NULL, NULL},
  /* 0x24 */  {NULL, NULL},
  /* 0x25 */  {NULL, NULL},
  /* 0x26 */  {NULL, NULL},
  /* 0x27 */  {NULL, NULL},
  /* 0x28 */  {NULL, NULL},
  /* 0x29 */  {NULL, NULL},
  /* 0x2a */  {NULL, NULL},
  /* 0x2b */  {NULL, NULL},
  /* 0x2c */  {NULL, NULL},
  /* 0x2d */  {NULL, NULL},
  /* 0x2e */  {NULL, NULL},
  /* 0x2f */  {NULL, NULL},
  /* 0x30 */  {NULL, NULL},
  /* 0x31 */  {NULL, NULL},
  /* 0x32 */  {NULL, NULL},
  /* 0x33 */  {NULL, NULL},
  /* 0x34 */  {NULL, NULL},
  /* 0x35 */  {NULL, NULL},
  /* 0x36 */  {NULL, NULL},
  /* 0x37 */  {NULL, NULL},
  /* 0x38 */  {NULL, NULL},
  /* 0x39 */  {NULL, NULL},
  /* 0x3a */  {NULL, NULL},
  /* 0x3b */  {NULL, NULL},
  /* 0x3c */  {NULL, NULL},
  /* 0x3d */  {NULL, NULL},
  /* 0x3e */  {NULL, NULL},
  /* 0x3f */  {NULL, NULL},
  /* 0x40 */  {NULL, NULL},
  /* 0x41 */  {NULL, NULL},
  /* 0x42 */  {NULL, NULL},
  /* 0x43 */  {NULL, NULL},
  /* 0x44 */  {NULL, NULL},
  /* 0x45 */  {NULL, NULL},
  /* 0x46 */  {NULL, NULL},
  /* 0x47 */  {NULL, NULL},
  /* 0x48 */  {NULL, NULL},
  /* 0x49 */  {NULL, NULL},
  /* 0x4a */  {NULL, NULL},
  /* 0x4b */  {NULL, NULL},
  /* 0x4c */  {NULL, NULL},
  /* 0x4d */  {NULL, NULL},
  /* 0x4e */  {NULL, NULL},
  /* 0x4f */  {NULL, NULL},
  /* 0x50 */  {NULL, NULL},
  /* 0x51 */  {NULL, NULL},
  /* 0x52 */  {NULL, NULL},
  /* 0x53 */  {NULL, NULL},
  /* 0x54 */  {NULL, NULL},
  /* 0x55 */  {NULL, NULL},
  /* 0x56 */  {NULL, NULL},
  /* 0x57 */  {NULL, NULL},
  /* 0x58 */  {NULL, NULL},
  /* 0x59 */  {NULL, NULL},
  /* 0x5a */  {NULL, NULL},
  /* 0x5b */  {NULL, NULL},
  /* 0x5c */  {NULL, NULL},
  /* 0x5d */  {NULL, NULL},
  /* 0x5e */  {NULL, NULL},
  /* 0x5f */  {NULL, NULL},
  /* 0x60 */  {NULL, NULL},
  /* 0x61 */  {NULL, NULL},
  /* 0x62 */  {NULL, NULL},
  /* 0x63 */  {NULL, NULL},
  /* 0x64 */  {NULL, NULL},
  /* 0x65 */  {NULL, NULL},
  /* 0x66 */  {NULL, NULL},
  /* 0x67 */  {NULL, NULL},
  /* 0x68 */  {NULL, NULL},
  /* 0x69 */  {NULL, NULL},
  /* 0x6a */  {NULL, NULL},
  /* 0x6b */  {NULL, NULL},
  /* 0x6c */  {NULL, NULL},
  /* 0x6d */  {NULL, NULL},
  /* 0x6e */  {NULL, NULL},
  /* 0x6f */  {NULL, NULL},
  /* 0x70 */  {NULL, NULL},
  /* 0x71 */  {NULL, NULL},
  /* 0x72 */  {NULL, NULL},
  /* 0x73 */  {NULL, NULL},
  /* 0x74 */  {NULL, NULL},
  /* 0x75 */  {NULL, NULL},
  /* 0x76 */  {NULL, NULL},
  /* 0x77 */  {NULL, NULL},
  /* 0x78 */  {NULL, NULL},
  /* 0x79 */  {NULL, NULL},
  /* 0x7a */  {NULL, NULL},
  /* 0x7b */  {NULL, NULL},
  /* 0x7c */  {NULL, NULL},
  /* 0x7d */  {NULL, NULL},
  /* 0x7e */  {NULL, NULL},
  /* 0x7f */  {NULL, NULL},
  /* 0x80 */  {NULL, NULL},
  /* 0x81 */  {NULL, NULL},
  /* 0x82 */  {NULL, NULL},
  /* 0x83 */  {NULL, NULL},
  /* 0x84 */  {NULL, NULL},
  /* 0x85 */  {NULL, NULL},
  /* 0x86 */  {NULL, NULL},
  /* 0x87 */  {NULL, NULL},
  /* 0x88 */  {NULL, NULL},
  /* 0x89 */  {NULL, NULL},
  /* 0x8a */  {NULL, NULL},
  /* 0x8b */  {NULL, NULL},
  /* 0x8c */  {NULL, NULL},
  /* 0x8d */  {NULL, NULL},
  /* 0x8e */  {NULL, NULL},
  /* 0x8f */  {NULL, NULL},
  /* 0x90 */  {NULL, NULL},
  /* 0x91 */  {NULL, NULL},
  /* 0x92 */  {NULL, NULL},
  /* 0x93 */  {NULL, NULL},
  /* 0x94 */  {NULL, NULL},
  /* 0x95 */  {NULL, NULL},
  /* 0x96 */  {NULL, NULL},
  /* 0x97 */  {NULL, NULL},
  /* 0x98 */  {NULL, NULL},
  /* 0x99 */  {NULL, NULL},
  /* 0x9a */  {NULL, NULL},
  /* 0x9b */  {NULL, NULL},
  /* 0x9c */  {NULL, NULL},
  /* 0x9d */  {NULL, NULL},
  /* 0x9e */  {NULL, NULL},
  /* 0x9f */  {NULL, NULL},
  /* 0xa0 */  {NULL, NULL},
  /* 0xa1 */  {NULL, NULL},
  /* 0xa2 */  {NULL, NULL},
  /* 0xa3 */  {NULL, NULL},
  /* 0xa4 */  {NULL, NULL},
  /* 0xa5 */  {NULL, NULL},
  /* 0xa6 */  {NULL, NULL},
  /* 0xa7 */  {NULL, NULL},
  /* 0xa8 */  {NULL, NULL},
  /* 0xa9 */  {NULL, NULL},
  /* 0xaa */  {NULL, NULL},
  /* 0xab */  {NULL, NULL},
  /* 0xac */  {NULL, NULL},
  /* 0xad */  {NULL, NULL},
  /* 0xae */  {NULL, NULL},
  /* 0xaf */  {NULL, NULL},
  /* 0xb0 */  {NULL, NULL},
  /* 0xb1 */  {NULL, NULL},
  /* 0xb2 */  {NULL, NULL},
  /* 0xb3 */  {NULL, NULL},
  /* 0xb4 */  {NULL, NULL},
  /* 0xb5 */  {NULL, NULL},
  /* 0xb6 */  {NULL, NULL},
  /* 0xb7 */  {NULL, NULL},
  /* 0xb8 */  {NULL, NULL},
  /* 0xb9 */  {NULL, NULL},
  /* 0xba */  {NULL, NULL},
  /* 0xbb */  {NULL, NULL},
  /* 0xbc */  {NULL, NULL},
  /* 0xbd */  {NULL, NULL},
  /* 0xbe */  {NULL, NULL},
  /* 0xbf */  {NULL, NULL},
  /* 0xc0 */  {NULL, NULL},
  /* 0xc1 */  {NULL, NULL},
  /* 0xc2 */  {NULL, NULL},
  /* 0xc3 */  {NULL, NULL},
  /* 0xc4 */  {NULL, NULL},
  /* 0xc5 */  {NULL, NULL},
  /* 0xc6 */  {NULL, NULL},
  /* 0xc7 */  {NULL, NULL},
  /* 0xc8 */  {NULL, NULL},
  /* 0xc9 */  {NULL, NULL},
  /* 0xca */  {NULL, NULL},
  /* 0xcb */  {NULL, NULL},
  /* 0xcc */  {NULL, NULL},
  /* 0xcd */  {NULL, NULL},
  /* 0xce */  {NULL, NULL},
  /* 0xcf */  {NULL, NULL},
  /* 0xd0 */  {NULL, NULL},
  /* 0xd1 */  {NULL, NULL},
  /* 0xd2 */  {NULL, NULL},
  /* 0xd3 */  {NULL, NULL},
  /* 0xd4 */  {NULL, NULL},
  /* 0xd5 */  {NULL, NULL},
  /* 0xd6 */  {NULL, NULL},
  /* 0xd7 */  {NULL, NULL},
  /* 0xd8 */  {NULL, NULL},
  /* 0xd9 */  {NULL, NULL},
  /* 0xda */  {NULL, NULL},
  /* 0xdb */  {NULL, NULL},
  /* 0xdc */  {NULL, NULL},
  /* 0xdd */  {NULL, NULL},
  /* 0xde */  {NULL, NULL},
  /* 0xdf */  {NULL, NULL},
  /* 0xe0 */  {NULL, NULL},
  /* 0xe1 */  {NULL, NULL},
  /* 0xe2 */  {NULL, NULL},
  /* 0xe3 */  {NULL, NULL},
  /* 0xe4 */  {NULL, NULL},
  /* 0xe5 */  {NULL, NULL},
  /* 0xe6 */  {NULL, NULL},
  /* 0xe7 */  {NULL, NULL},
  /* 0xe8 */  {NULL, NULL},
  /* 0xe9 */  {NULL, NULL},
  /* 0xea */  {NULL, NULL},
  /* 0xeb */  {NULL, NULL},
  /* 0xec */  {NULL, NULL},
  /* 0xed */  {NULL, NULL},
  /* 0xee */  {NULL, NULL},
  /* 0xef */  {NULL, NULL},
  /* 0xf0 */  {NULL, NULL},
  /* 0xf1 */  {NULL, NULL},
  /* 0xf2 */  {NULL, NULL},
  /* 0xf3 */  {NULL, NULL},
  /* 0xf4 */  {NULL, NULL},
  /* 0xf5 */  {NULL, NULL},
  /* 0xf6 */  {NULL, NULL},
  /* 0xf7 */  {NULL, NULL},
  /* 0xf8 */  {NULL, NULL},
  /* 0xf9 */  {NULL, NULL},
  /* 0xfa */  {NULL, NULL},
  /* 0xfb */  {NULL, NULL},
  /* 0xfc */  {NULL, NULL},
  /* 0xfd */  {NULL, NULL},
  /* 0xfe */  {NULL, NULL},
  /* 0xff */  {NULL, NULL},
};


static int
dissect_smb2_command(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, smb2_info_t *si)
{
	int (*cmd_dissector)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si);
	proto_item *cmd_item;
	proto_tree *cmd_tree;
	int old_offset = offset;

	cmd_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s %s (0x%02x)",
			decode_smb2_name(si->opcode),
			(si->flags & SMB2_FLAGS_RESPONSE)?"Response":"Request",
			si->opcode);
	cmd_tree = proto_item_add_subtree(cmd_item, ett_smb2_command);


	cmd_dissector=(si->flags & SMB2_FLAGS_RESPONSE)?
		smb2_dissector[si->opcode&0xff].response:
		smb2_dissector[si->opcode&0xff].request;
	if(cmd_dissector){
		offset=(*cmd_dissector)(tvb, pinfo, cmd_tree, offset, si);
	} else {
		proto_tree_add_item(cmd_tree, hf_smb2_unknown, tvb, offset, -1, FALSE);
		offset=tvb_length(tvb);
	}

	proto_item_set_len(cmd_item, offset-old_offset);

	return offset;
}

static int
dissect_smb2_tid_sesid(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, smb2_info_t *si)
{
	proto_item *tid_item=NULL;
	proto_tree *tid_tree=NULL;
	smb2_tid_info_t tid_key;
	int tid_offset = 0;
	proto_item *sesid_item=NULL;
	proto_tree *sesid_tree=NULL;
	smb2_sesid_info_t sesid_key;
	int sesid_offset;
	proto_item *item;
	unsigned int pid;


	if (si->flags&SMB2_FLAGS_ASYNC_CMD) {
		proto_tree_add_item(tree, hf_smb2_aid, tvb, offset, 8, TRUE);
		offset += 8;
	} else {
		/* Process ID */
		pid=tvb_get_letohl(tvb, offset);
		proto_tree_add_uint_format(tree, hf_smb2_pid, tvb, offset, 4, pid, "Process Id: %08x",pid);
		offset += 4;

		/* Tree ID */
		tid_offset = offset;
		si->tid=tvb_get_letohl(tvb, offset);
		tid_item=proto_tree_add_item(tree, hf_smb2_tid, tvb, offset, 4, TRUE);
		if(tree){
			tid_tree=proto_item_add_subtree(tid_item, ett_smb2_tid_tree);
		}
		offset += 4;
	}

	/* Session ID */
	sesid_offset = offset;
	si->sesid=tvb_get_letoh64(tvb, offset);
	sesid_item=proto_tree_add_item(tree, hf_smb2_sesid, tvb, offset, 8, TRUE);
	if(tree){
		sesid_tree=proto_item_add_subtree(sesid_item, ett_smb2_sesid_tree);
	}
	offset += 8;

	/* now we need to first lookup the uid session */
	sesid_key.sesid=si->sesid;
	si->session=g_hash_table_lookup(si->conv->sesids, &sesid_key);
	if(!si->session) {
		if (si->opcode != 0x03) return offset;

		/* if we come to a session that is unknown, and the operation is
		 * a tree connect, we create a dummy sessison, so we can hang the
		 * tree data on it
		 */
		si->session=se_alloc(sizeof(smb2_sesid_info_t));
		si->session->sesid=si->sesid;
		si->session->acct_name=NULL;
		si->session->domain_name=NULL;
		si->session->host_name=NULL;
		si->session->auth_frame=(guint32)-1;
		si->session->tids= g_hash_table_new(smb2_tid_info_hash, smb2_tid_info_equal);
		g_hash_table_insert(si->conv->sesids, si->session, si->session);

		return offset;
	}

	if (si->session->auth_frame != (guint32)-1) {
		item=proto_tree_add_string(sesid_tree, hf_smb2_acct_name, tvb, sesid_offset, 0, si->session->acct_name);
		PROTO_ITEM_SET_GENERATED(item);
		proto_item_append_text(sesid_item, " Acct:%s", si->session->acct_name);

		item=proto_tree_add_string(sesid_tree, hf_smb2_domain_name, tvb, sesid_offset, 0, si->session->domain_name);
		PROTO_ITEM_SET_GENERATED(item);
		proto_item_append_text(sesid_item, " Domain:%s", si->session->domain_name);

		item=proto_tree_add_string(sesid_tree, hf_smb2_host_name, tvb, sesid_offset, 0, si->session->host_name);
		PROTO_ITEM_SET_GENERATED(item);
		proto_item_append_text(sesid_item, " Host:%s", si->session->host_name);

		item=proto_tree_add_uint(sesid_tree, hf_smb2_auth_frame, tvb, sesid_offset, 0, si->session->auth_frame);
		PROTO_ITEM_SET_GENERATED(item);
	}

	if (!(si->flags&SMB2_FLAGS_ASYNC_CMD)) {
		/* see if we can find the name for this tid */
		tid_key.tid=si->tid;
		si->tree=g_hash_table_lookup(si->session->tids, &tid_key);
		if(!si->tree) return offset;

		item=proto_tree_add_string(tid_tree, hf_smb2_tree, tvb, tid_offset, 4, si->tree->name);
		PROTO_ITEM_SET_GENERATED(item);
		proto_item_append_text(tid_item, "  %s", si->tree->name);

		item=proto_tree_add_uint(tid_tree, hf_smb2_share_type, tvb, tid_offset, 0, si->tree->share_type);
		PROTO_ITEM_SET_GENERATED(item);

		item=proto_tree_add_uint(tid_tree, hf_smb2_tcon_frame, tvb, tid_offset, 0, si->tree->connect_frame);
		PROTO_ITEM_SET_GENERATED(item);
	}

	return offset;
}

static int
dissect_smb2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, gboolean first_in_chain)
{
	proto_item *seqnum_item;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	proto_item *header_item=NULL;
	proto_tree *header_tree=NULL;
	proto_item *flags_item=NULL;
	proto_tree *flags_tree=NULL;
	int offset = 0;
	int chain_offset = 0;
	conversation_t *conversation;
	smb2_saved_info_t *ssi=NULL, ssi_key;
	smb2_info_t *si;

	si=ep_alloc(sizeof(smb2_info_t));
	si->conv=NULL;
	si->saved=NULL;
	si->tree=NULL;
	si->top_tree=parent_tree;

	/* find which conversation we are part of and get the data for that
	 * conversation
	 */
	conversation = find_or_create_conversation(pinfo);
	si->conv=conversation_get_proto_data(conversation, proto_smb2);
	if(!si->conv){
		/* no smb2_into_t structure for this conversation yet,
		 * create it.
		 */
		si->conv=se_alloc(sizeof(smb2_conv_info_t));
		/* qqq this leaks memory for now since we never free
		   the hashtables */
		si->conv->matched= g_hash_table_new(smb2_saved_info_hash_matched,
			smb2_saved_info_equal_matched);
		si->conv->unmatched= g_hash_table_new(smb2_saved_info_hash_unmatched,
			smb2_saved_info_equal_unmatched);
		si->conv->sesids= g_hash_table_new(smb2_sesid_info_hash,
			smb2_sesid_info_equal);

		conversation_add_proto_data(conversation, proto_smb2, si->conv);
	}


	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SMB2");
	if (check_col(pinfo->cinfo, COL_INFO)){
		if (first_in_chain) {
			/* first packet */
			col_clear(pinfo->cinfo, COL_INFO);
		} else {
			col_append_str(pinfo->cinfo, COL_INFO, ";");
		}
	}

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, proto_smb2, tvb, offset,
			-1, FALSE);
		tree = proto_item_add_subtree(item, ett_smb2);
	}


	if (tree) {
		header_item = proto_tree_add_text(tree, tvb, offset, -1, "SMB2 Header");
		header_tree = proto_item_add_subtree(header_item, ett_smb2_header);
	}

	/* Decode the header */
	/* SMB2 marker */
	proto_tree_add_text(header_tree, tvb, offset, 4, "Server Component: SMB2");
	offset += 4;

	/* header length */
	proto_tree_add_item(header_tree, hf_smb2_header_len, tvb, offset, 2, TRUE);
	offset += 2;

	/* credit charge (previously "epoch" (unused) which has been deprecated as of "SMB 2.1") */
	proto_tree_add_item(header_tree, hf_smb2_credit_charge, tvb, offset, 2, TRUE);
	offset += 2;

	/* Status Code */
	si->status=tvb_get_letohl(tvb, offset);
	proto_tree_add_item(header_tree, hf_smb2_nt_status, tvb, offset, 4, TRUE);
	offset += 4;


	/* opcode */
	si->opcode=tvb_get_letohs(tvb, offset);
	proto_tree_add_item(header_tree, hf_smb2_cmd, tvb, offset, 2, TRUE);
	offset += 2;

	/* we need the flags before we know how to parse the credits field */
	si->flags=tvb_get_letohl(tvb, offset+2);

	/* credits */
	if (si->flags & SMB2_FLAGS_RESPONSE) {
		proto_tree_add_item(header_tree, hf_smb2_credits_granted, tvb, offset, 2, TRUE);
	} else {
		proto_tree_add_item(header_tree, hf_smb2_credits_requested, tvb, offset, 2, TRUE);
	}
	offset += 2;

	/* flags */
	if(header_tree){
		flags_item = proto_tree_add_text(header_tree, tvb, offset, 4,
			"Flags: 0x%08x", si->flags);
		flags_tree = proto_item_add_subtree(flags_item, ett_smb2_flags);
	}
	proto_tree_add_boolean(flags_tree, hf_smb2_flags_dfs_op, tvb, offset, 4, si->flags);
	proto_tree_add_boolean(flags_tree, hf_smb2_flags_signature, tvb, offset, 4, si->flags);
	proto_tree_add_boolean(flags_tree, hf_smb2_flags_chained, tvb, offset, 4, si->flags);
	proto_tree_add_boolean(flags_tree, hf_smb2_flags_async_cmd, tvb, offset, 4, si->flags);
	proto_tree_add_boolean(flags_tree, hf_smb2_flags_response, tvb, offset, 4, si->flags);

	offset += 4;

	/* Next Command */
	chain_offset=tvb_get_letohl(tvb, offset);
	proto_tree_add_item(header_tree, hf_smb2_chain_offset, tvb, offset, 4, FALSE);
	offset += 4;

	/* command sequence number*/
	si->seqnum=tvb_get_letoh64(tvb, offset);
	ssi_key.seqnum=si->seqnum;
	seqnum_item=proto_tree_add_item(header_tree, hf_smb2_seqnum, tvb, offset, 8, TRUE);
	if(seqnum_item && (si->seqnum==-1)){
		proto_item_append_text(seqnum_item, " (unsolicited response)");
	}
	offset += 8;

	/* Tree ID and Session ID */
	offset = dissect_smb2_tid_sesid(pinfo, header_tree, tvb, offset, si);

	/* Signature */
	proto_tree_add_item(header_tree, hf_smb2_signature, tvb, offset, 16, FALSE);
	offset += 16;

	proto_item_set_len(header_item, offset);


	if (check_col(pinfo->cinfo, COL_INFO)){
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s %s",
			decode_smb2_name(si->opcode),
			(si->flags & SMB2_FLAGS_RESPONSE)?"Response":"Request");
		if(si->status){
			col_append_fstr(
				pinfo->cinfo, COL_INFO, ", Error: %s",
				val_to_str(si->status, NT_errors,
				"Unknown (0x%08X)"));
		}
	}


	if(!pinfo->fd->flags.visited){
		/* see if we can find this seqnum in the unmatched table */
		ssi=g_hash_table_lookup(si->conv->unmatched, &ssi_key);

		if(!(si->flags & SMB2_FLAGS_RESPONSE)){
			/* This is a request */
			if(ssi){
				/* this is a request and we already found
				 * an older ssi so just delete the previous
				 * one
				 */
				g_hash_table_remove(si->conv->unmatched, ssi);
				ssi=NULL;
			}

			if(!ssi){
				/* no we couldnt find it, so just add it then
				 * if was a request we are decoding
				 */
				ssi=se_alloc(sizeof(smb2_saved_info_t));
				ssi->class=0;
				ssi->infolevel=0;
				ssi->seqnum=ssi_key.seqnum;
				ssi->frame_req=pinfo->fd->num;
				ssi->frame_res=0;
				ssi->req_time=pinfo->fd->abs_ts;
				ssi->extra_info=NULL;
				ssi->extra_info_type=SMB2_EI_NONE;
				g_hash_table_insert(si->conv->unmatched, ssi, ssi);
			}
		} else {
			/* This is a response */
			if(ssi){
				/* just  set the response frame and move it to the matched table */
				ssi->frame_res=pinfo->fd->num;
				g_hash_table_remove(si->conv->unmatched, ssi);
				g_hash_table_insert(si->conv->matched, ssi, ssi);
			}
		}
	} else {
		/* see if we can find this seqnum in the matched table */
		ssi=g_hash_table_lookup(si->conv->matched, &ssi_key);
		/* if we couldnt find it in the matched table, it might still
		 * be in the unmatched table
		 */
		if(!ssi){
			ssi=g_hash_table_lookup(si->conv->unmatched, &ssi_key);
		}
	}

	if(ssi){
		if(!(si->flags & SMB2_FLAGS_RESPONSE)){
			if(ssi->frame_res){
				proto_item *tmp_item;
				tmp_item=proto_tree_add_uint(header_tree, hf_smb2_response_in, tvb, 0, 0, ssi->frame_res);
				PROTO_ITEM_SET_GENERATED(tmp_item);
			}
		} else {
			if(ssi->frame_req){
				proto_item *tmp_item;
				nstime_t t, deltat;

				tmp_item=proto_tree_add_uint(header_tree, hf_smb2_response_to, tvb, 0, 0, ssi->frame_req);
				PROTO_ITEM_SET_GENERATED(tmp_item);
				t = pinfo->fd->abs_ts;
				nstime_delta(&deltat, &t, &ssi->req_time);
				tmp_item=proto_tree_add_time(header_tree, hf_smb2_time, tvb,
				    0, 0, &deltat);
				PROTO_ITEM_SET_GENERATED(tmp_item);
			}
		}
	}
	/* if we dont have ssi yet we must fake it */
	/*qqq*/
	si->saved=ssi;

	tap_queue_packet(smb2_tap, pinfo, si);

	/* Decode the payload */
	offset = dissect_smb2_command(pinfo, tree, tvb, offset, si);

	if (chain_offset > 0) {
		tvbuff_t *next_tvb;

		proto_item_set_len(item, chain_offset);

		next_tvb = tvb_new_subset_remaining(tvb, chain_offset);
		offset = dissect_smb2(next_tvb, pinfo, parent_tree, FALSE);
	}

	return offset;
}

static gboolean
dissect_smb2_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	/* must check that this really is a smb2 packet */
	if (tvb_length(tvb) < 4)
		return FALSE;

	if( (tvb_get_guint8(tvb, 0) != 0xfe)
	    || (tvb_get_guint8(tvb, 1) != 'S')
	    || (tvb_get_guint8(tvb, 2) != 'M')
	    || (tvb_get_guint8(tvb, 3) != 'B') ){
		return FALSE;
	}

	dissect_smb2(tvb, pinfo, parent_tree, TRUE);

	return TRUE;
}

void
proto_register_smb2(void)
{
	static hf_register_info hf[] = {
	{ &hf_smb2_cmd,
		{ "Command", "smb2.cmd", FT_UINT16, BASE_DEC|BASE_EXT_STRING,
		&smb2_cmd_vals_ext, 0, "SMB2 Command Opcode", HFILL }},
	{ &hf_smb2_response_to,
		{ "Response to", "smb2.response_to", FT_FRAMENUM, BASE_NONE,
		NULL, 0, "This packet is a response to the packet in this frame", HFILL }},
	{ &hf_smb2_response_in,
		{ "Response in", "smb2.response_in", FT_FRAMENUM, BASE_NONE,
		NULL, 0, "The response to this packet is in this packet", HFILL }},
	{ &hf_smb2_time,
		{ "Time from request", "smb2.time", FT_RELATIVE_TIME, BASE_NONE,
		NULL, 0, "Time between Request and Response for SMB2 cmds", HFILL }},
	{ &hf_smb2_header_len,
		{ "Header Length", "smb2.header_len", FT_UINT16, BASE_DEC,
		NULL, 0, "SMB2 Size of Header", HFILL }},
	{ &hf_smb2_nt_status,
		{ "NT Status", "smb2.nt_status", FT_UINT32, BASE_HEX,
		VALS(NT_errors), 0, "NT Status code", HFILL }},
	{ &hf_smb2_seqnum,
		{ "Command Sequence Number", "smb2.seq_num", FT_INT64, BASE_DEC,
		NULL, 0, "SMB2 Command Sequence Number", HFILL }},
	{ &hf_smb2_tid,
		{ "Tree Id", "smb2.tid", FT_UINT32, BASE_HEX,
		NULL, 0, "SMB2 Tree Id", HFILL }},
	{ &hf_smb2_aid,
		{ "Async Id", "smb2.aid", FT_UINT64, BASE_HEX,
		NULL, 0, "SMB2 Async Id", HFILL }},
	{ &hf_smb2_sesid,
		{ "Session Id", "smb2.sesid", FT_UINT64, BASE_HEX,
		NULL, 0, "SMB2 Session Id", HFILL }},
	{ &hf_smb2_previous_sesid,
		{ "Previous Session Id", "smb2.previous_sesid", FT_UINT64, BASE_HEX,
		NULL, 0, "SMB2 Previous Session Id", HFILL }},
	{ &hf_smb2_chain_offset,
		{ "Chain Offset", "smb2.chain_offset", FT_UINT32, BASE_HEX,
		NULL, 0, "SMB2 Chain Offset", HFILL }},
	{ &hf_smb2_end_of_file,
		{ "End Of File", "smb2.eof", FT_UINT64, BASE_DEC,
		NULL, 0, "SMB2 End Of File/File size", HFILL }},
	{ &hf_smb2_nlinks,
		{ "Number of Links", "smb2.nlinks", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of links to this object", HFILL }},
	{ &hf_smb2_file_id,
		{ "File Id", "smb2.file_id", FT_UINT64, BASE_HEX,
		NULL, 0, "SMB2 File Id", HFILL }},
	{ &hf_smb2_allocation_size,
		{ "Allocation Size", "smb2.allocation_size", FT_UINT64, BASE_DEC,
		NULL, 0, "SMB2 Allocation Size for this object", HFILL }},
	{ &hf_smb2_max_response_size,
		{ "Max Response Size", "smb2.max_response_size", FT_UINT32, BASE_DEC,
		NULL, 0, "SMB2 Maximum response size", HFILL }},
	{ &hf_smb2_setinfo_size,
		{ "Setinfo Size", "smb2.setinfo_size", FT_UINT32, BASE_DEC,
		NULL, 0, "SMB2 setinfo size", HFILL }},
	{ &hf_smb2_setinfo_offset,
		{ "Setinfo Offset", "smb2.setinfo_offset", FT_UINT16, BASE_HEX,
		NULL, 0, "SMB2 setinfo offset", HFILL }},
	{ &hf_smb2_max_ioctl_out_size,
		{ "Max Ioctl Out Size", "smb2.max_ioctl_out_size", FT_UINT32, BASE_DEC,
		NULL, 0, "SMB2 Maximum ioctl out size", HFILL }},
	{ &hf_smb2_max_ioctl_in_size,
		{ "Max Ioctl In Size", "smb2.max_ioctl_in_size", FT_UINT32, BASE_DEC,
		NULL, 0, "SMB2 Maximum ioctl out size", HFILL }},
	{ &hf_smb2_response_size,
		{ "Response Size", "smb2.response_size", FT_UINT32, BASE_DEC,
		NULL, 0, "SMB2 response size", HFILL }},
	{ &hf_smb2_required_buffer_size,
		{ "Required Buffer Size", "smb2.required_size", FT_UINT32, BASE_DEC,
		NULL, 0, "SMB2 required buffer size", HFILL }},
	{ &hf_smb2_pid,
		{ "Process Id", "smb2.pid", FT_UINT32, BASE_HEX,
		NULL, 0, "SMB2 Process Id", HFILL }},
	{ &hf_smb2_flags_response,
		{ "Response", "smb2.flags.response", FT_BOOLEAN, 32,
		TFS(&tfs_flags_response), SMB2_FLAGS_RESPONSE, "Whether this is an SMB2 Request or Response", HFILL }},
	{ &hf_smb2_flags_async_cmd,
		{ "Async command", "smb2.flags.async", FT_BOOLEAN, 32,
		TFS(&tfs_flags_async_cmd), SMB2_FLAGS_ASYNC_CMD, NULL, HFILL }},
	{ &hf_smb2_flags_dfs_op,
		{ "DFS operation", "smb2.flags.dfs", FT_BOOLEAN, 32,
		TFS(&tfs_flags_dfs_op), SMB2_FLAGS_DFS_OP, NULL, HFILL }},
	{ &hf_smb2_flags_chained,
		{ "Chained", "smb2.flags.chained", FT_BOOLEAN, 32,
		TFS(&tfs_flags_chained), SMB2_FLAGS_CHAINED, "Whether the pdu continues a chain or not", HFILL }},
	{ &hf_smb2_flags_signature,
		{ "Signing", "smb2.flags.signature", FT_BOOLEAN, 32,
		TFS(&tfs_flags_signature), SMB2_FLAGS_SIGNATURE, "Whether the pdu is signed or not", HFILL }},
	{ &hf_smb2_tree,
		{ "Tree", "smb2.tree", FT_STRING, BASE_NONE,
		NULL, 0, "Name of the Tree/Share", HFILL }},
	{ &hf_smb2_filename,
		{ "Filename", "smb2.filename", FT_STRING, BASE_NONE,
		NULL, 0, "Name of the file", HFILL }},
	{ &hf_smb2_filename_len,
		{ "Filename Length", "smb2.filename.len", FT_UINT32, BASE_DEC,
		NULL, 0, "Length of the file name", HFILL }},

	{ &hf_smb2_security_blob_len,
		{ "Security Blob Length", "smb2.security_blob_len", FT_UINT16, BASE_DEC,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_security_blob_offset,
		{ "Security Blob Offset", "smb2.security_blob_offset", FT_UINT16, BASE_HEX,
		NULL, 0, "Offset into the SMB2 PDU of the blob", HFILL }},

	{ &hf_smb2_response_buffer_offset,
		{ "Response Buffer Offset", "smb2.response_buffer_offset", FT_UINT16, BASE_HEX,
		NULL, 0, "Offset of the response buffer", HFILL }},

	{ &hf_smb2_data_offset,
		{ "Data Offset", "smb2.data_offset", FT_UINT16, BASE_HEX,
		NULL, 0, "Offset to data", HFILL }},

	{ &hf_smb2_find_info_level,
		{ "Info Level", "smb2.find.infolevel", FT_UINT32, BASE_DEC,
		VALS(smb2_find_info_levels), 0, "Find_Info Infolevel", HFILL }},
	{ &hf_smb2_find_flags,
		{ "Find Flags", "smb2.find.flags", FT_UINT8, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_find_pattern,
		{ "Search Pattern", "smb2.find.pattern", FT_STRING, BASE_NONE,
		NULL, 0, "Find pattern", HFILL }},

	{ &hf_smb2_find_info_blob,
		{ "Info", "smb2.security_blob", FT_BYTES, BASE_NONE,
		NULL, 0, "Find Info", HFILL }},

	{ &hf_smb2_ea_size,
		{ "EA Size", "smb2.ea_size", FT_UINT32, BASE_DEC,
		NULL, 0, "Size of EA data", HFILL }},

	{ &hf_smb2_class,
		{ "Class", "smb2.class", FT_UINT8, BASE_HEX,
		VALS(smb2_class_vals), 0, "Info class", HFILL }},

	{ &hf_smb2_infolevel,
		{ "InfoLevel", "smb2.infolevel", FT_UINT8, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_infolevel_file_info,
		{ "InfoLevel", "smb2.file_info.infolevel", FT_UINT8, BASE_HEX,
		VALS(smb2_file_info_levels), 0, "File_Info Infolevel", HFILL }},

	{ &hf_smb2_infolevel_fs_info,
		{ "InfoLevel", "smb2.fs_info.infolevel", FT_UINT8, BASE_HEX,
		VALS(smb2_fs_info_levels), 0, "Fs_Info Infolevel", HFILL }},

	{ &hf_smb2_infolevel_sec_info,
		{ "InfoLevel", "smb2.sec_info.infolevel", FT_UINT8, BASE_HEX,
		VALS(smb2_sec_info_levels), 0, "Sec_Info Infolevel", HFILL }},

	{ &hf_smb2_write_length,
		{ "Write Length", "smb2.write_length", FT_UINT32, BASE_DEC,
		NULL, 0, "Amount of data to write", HFILL }},

	{ &hf_smb2_read_length,
		{ "Read Length", "smb2.read_length", FT_UINT32, BASE_DEC,
		NULL, 0, "Amount of data to read", HFILL }},

	{ &hf_smb2_read_remaining,
		{ "Read Remaining", "smb2.read_remaining", FT_UINT32, BASE_DEC,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_create_flags,
		{ "Create Flags", "smb2.create_flags", FT_UINT64, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_file_offset,
		{ "File Offset", "smb2.file_offset", FT_UINT64, BASE_DEC,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_security_blob,
		{ "Security Blob", "smb2.security_blob", FT_BYTES, BASE_NONE,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_ioctl_out_data,
		{ "Out Data", "smb2.ioctl.out", FT_NONE, BASE_NONE,
		NULL, 0, "Ioctl Out", HFILL }},

	{ &hf_smb2_ioctl_in_data,
		{ "In Data", "smb2.ioctl.in", FT_NONE, BASE_NONE,
		NULL, 0, "Ioctl In", HFILL }},

	{ &hf_smb2_server_guid,
	  { "Server Guid", "smb2.server_guid", FT_GUID, BASE_NONE,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_client_guid,
	  { "Client Guid", "smb2.client_guid", FT_GUID, BASE_NONE,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_object_id,
	  { "ObjectId", "smb2.object_id", FT_GUID, BASE_NONE,
		NULL, 0, "ObjectID for this FID", HFILL }},

	{ &hf_smb2_birth_volume_id,
	  { "BirthVolumeId", "smb2.birth_volume_id", FT_GUID, BASE_NONE,
		NULL, 0, "ObjectID for the volume where this FID was originally created", HFILL }},

	{ &hf_smb2_birth_object_id,
	  { "BirthObjectId", "smb2.birth_object_id", FT_GUID, BASE_NONE,
		NULL, 0, "ObjectID for this FID when it was originally created", HFILL }},

	{ &hf_smb2_domain_id,
	  { "DomainId", "smb2.domain_id", FT_GUID, BASE_NONE,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_create_timestamp,
		{ "Create", "smb2.create.time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
		NULL, 0, "Time when this object was created", HFILL }},

	{ &hf_smb2_fid,
		{ "File Id", "smb2.fid", FT_GUID, BASE_NONE,
		NULL, 0, "SMB2 File Id", HFILL }},

	{ &hf_smb2_write_data,
		{ "Write Data", "smb2.write_data", FT_BYTES, BASE_NONE,
		NULL, 0, "SMB2 Data to be written", HFILL }},

	{ &hf_smb2_write_flags,
		{ "Write Flags", "smb2.write.flags", FT_UINT32, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_write_flags_write_through,
		{ "Write through", "smb2.write.flags.write_through", FT_BOOLEAN, 32,
		NULL, SMB2_WRITE_FLAG_WRITE_THROUGH, NULL, HFILL }},

	{ &hf_smb2_write_count,
		{ "Write Count", "smb2.write.count", FT_UINT32, BASE_DEC,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_write_remaining,
		{ "Write Remaining", "smb2.write.remaining", FT_UINT32, BASE_DEC,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_read_data,
		{ "Read Data", "smb2.read_data", FT_BYTES, BASE_NONE,
		NULL, 0, "SMB2 Data that is read", HFILL }},

	{ &hf_smb2_last_access_timestamp,
		{ "Last Access", "smb2.last_access.time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
		NULL, 0, "Time when this object was last accessed", HFILL }},

	{ &hf_smb2_last_write_timestamp,
		{ "Last Write", "smb2.last_write.time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
		NULL, 0, "Time when this object was last written to", HFILL }},

	{ &hf_smb2_last_change_timestamp,
		{ "Last Change", "smb2.last_change.time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
		NULL, 0, "Time when this object was last changed", HFILL }},

	{ &hf_smb2_file_all_info,
		{ "SMB2_FILE_ALL_INFO", "smb2.file_all_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_ALL_INFO structure", HFILL }},

	{ &hf_smb2_file_allocation_info,
		{ "SMB2_FILE_ALLOCATION_INFO", "smb2.file_allocation_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_ALLOCATION_INFO structure", HFILL }},

	{ &hf_smb2_file_endoffile_info,
		{ "SMB2_FILE_ENDOFFILE_INFO", "smb2.file_endoffile_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_ENDOFFILE_INFO structure", HFILL }},

	{ &hf_smb2_file_alternate_name_info,
		{ "SMB2_FILE_ALTERNATE_NAME_INFO", "smb2.file_alternate_name_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_ALTERNATE_NAME_INFO structure", HFILL }},

	{ &hf_smb2_file_stream_info,
		{ "SMB2_FILE_STREAM_INFO", "smb2.file_stream_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_STREAM_INFO structure", HFILL }},

	{ &hf_smb2_file_pipe_info,
		{ "SMB2_FILE_PIPE_INFO", "smb2.file_pipe_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_PIPE_INFO structure", HFILL }},

	{ &hf_smb2_file_compression_info,
		{ "SMB2_FILE_COMPRESSION_INFO", "smb2.file_compression_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_COMPRESSION_INFO structure", HFILL }},

	{ &hf_smb2_file_basic_info,
		{ "SMB2_FILE_BASIC_INFO", "smb2.file_basic_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_BASIC_INFO structure", HFILL }},

	{ &hf_smb2_file_standard_info,
		{ "SMB2_FILE_STANDARD_INFO", "smb2.file_standard_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_STANDARD_INFO structure", HFILL }},

	{ &hf_smb2_file_internal_info,
		{ "SMB2_FILE_INTERNAL_INFO", "smb2.file_internal_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_INTERNAL_INFO structure", HFILL }},

	{ &hf_smb2_file_mode_info,
		{ "SMB2_FILE_MODE_INFO", "smb2.file_mode_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_MODE_INFO structure", HFILL }},

	{ &hf_smb2_file_alignment_info,
		{ "SMB2_FILE_ALIGNMENT_INFO", "smb2.file_alignment_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_ALIGNMENT_INFO structure", HFILL }},

	{ &hf_smb2_file_position_info,
		{ "SMB2_FILE_POSITION_INFO", "smb2.file_position_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_POSITION_INFO structure", HFILL }},

	{ &hf_smb2_file_access_info,
		{ "SMB2_FILE_ACCESS_INFO", "smb2.file_access_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_ACCESS_INFO structure", HFILL }},

	{ &hf_smb2_file_ea_info,
		{ "SMB2_FILE_EA_INFO", "smb2.file_ea_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_EA_INFO structure", HFILL }},

	{ &hf_smb2_file_network_open_info,
		{ "SMB2_FILE_NETWORK_OPEN_INFO", "smb2.file_network_open_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_NETWORK_OPEN_INFO structure", HFILL }},

	{ &hf_smb2_file_attribute_tag_info,
		{ "SMB2_FILE_ATTRIBUTE_TAG_INFO", "smb2.file_attribute_tag_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_ATTRIBUTE_TAG_INFO structure", HFILL }},

	{ &hf_smb2_file_disposition_info,
		{ "SMB2_FILE_DISPOSITION_INFO", "smb2.file_disposition_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_DISPOSITION_INFO structure", HFILL }},

	{ &hf_smb2_file_info_0f,
		{ "SMB2_FILE_INFO_0f", "smb2.file_info_0f", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_INFO_0f structure", HFILL }},

	{ &hf_smb2_file_rename_info,
		{ "SMB2_FILE_RENAME_INFO", "smb2.file_rename_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_RENAME_INFO structure", HFILL }},

	{ &hf_smb2_fs_info_01,
		{ "SMB2_FS_INFO_01", "smb2.fs_info_01", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FS_INFO_01 structure", HFILL }},

	{ &hf_smb2_fs_info_03,
		{ "SMB2_FS_INFO_03", "smb2.fs_info_03", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FS_INFO_03 structure", HFILL }},

	{ &hf_smb2_fs_info_04,
		{ "SMB2_FS_INFO_04", "smb2.fs_info_04", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FS_INFO_04 structure", HFILL }},

	{ &hf_smb2_fs_info_05,
		{ "SMB2_FS_INFO_05", "smb2.fs_info_05", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FS_INFO_05 structure", HFILL }},

	{ &hf_smb2_fs_info_06,
		{ "SMB2_FS_INFO_06", "smb2.fs_info_06", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FS_INFO_06 structure", HFILL }},

	{ &hf_smb2_fs_info_07,
		{ "SMB2_FS_INFO_07", "smb2.fs_info_07", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FS_INFO_07 structure", HFILL }},

	{ &hf_smb2_fs_objectid_info,
		{ "SMB2_FS_OBJECTID_INFO", "smb2.fs_objectid_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FS_OBJECTID_INFO structure", HFILL }},

	{ &hf_smb2_sec_info_00,
		{ "SMB2_SEC_INFO_00", "smb2.sec_info_00", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_SEC_INFO_00 structure", HFILL }},

	{ &hf_smb2_disposition_delete_on_close,
	  { "Delete on close", "smb2.disposition.delete_on_close", FT_BOOLEAN, 8,
		TFS(&tfs_disposition_delete_on_close), 0x01, NULL, HFILL }},


	{ &hf_smb2_create_disposition,
		{ "Disposition", "smb2.create.disposition", FT_UINT32, BASE_DEC,
		VALS(create_disposition_vals), 0, "Create disposition, what to do if the file does/does not exist", HFILL }},

	{ &hf_smb2_create_action,
		{ "Create Action", "smb2.create.action", FT_UINT32, BASE_DEC,
		VALS(oa_open_vals), 0, NULL, HFILL }},

	{ &hf_smb2_create_rep_flags,
		{ "Response Flags", "smb2.create.rep_flags", FT_UINT8, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_create_rep_flags_reparse_point,
		{ "ReparsePoint", "smb2.create.rep_flags.reparse_point", FT_BOOLEAN, 8,
		NULL, SMB2_CREATE_REP_FLAGS_REPARSE_POINT, NULL, HFILL }},

	{ &hf_smb2_extrainfo,
		{ "ExtraInfo", "smb2.create.extrainfo", FT_NONE, BASE_NONE,
		NULL, 0, "Create ExtraInfo", HFILL }},

	{ &hf_smb2_create_chain_offset,
		{ "Chain Offset", "smb2.create.chain_offset", FT_UINT32, BASE_HEX,
		NULL, 0, "Offset to next entry in chain or 0", HFILL }},

	{ &hf_smb2_create_chain_data,
		{ "Data", "smb2.create.chain_data", FT_NONE, BASE_NONE,
		NULL, 0, "Chain Data", HFILL }},

	{ &hf_smb2_FILE_OBJECTID_BUFFER,
		{ "FILE_OBJECTID_BUFFER", "smb2.FILE_OBJECTID_BUFFER", FT_NONE, BASE_NONE,
		NULL, 0, "A FILE_OBJECTID_BUFFER structure", HFILL }},

	{ &hf_smb2_lease_key,
	  { "Lease Key", "smb2.lease.lease_key", FT_GUID, BASE_NONE,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_lease_state,
	  { "Lease State", "smb2.lease.lease_state", FT_UINT32, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_lease_state_read_caching,
	  { "Read Caching", "smb2.lease.lease_state.read_caching", FT_BOOLEAN, 32,
		NULL, SMB2_LEASE_STATE_READ_CACHING, NULL, HFILL }},

	{ &hf_smb2_lease_state_handle_caching,
	  { "Handle Caching", "smb2.lease.lease_state.handle_caching", FT_BOOLEAN, 32,
		NULL, SMB2_LEASE_STATE_HANDLE_CACHING, NULL, HFILL }},

	{ &hf_smb2_lease_state_write_caching,
	  { "Write Caching", "smb2.lease.lease_state.write_caching", FT_BOOLEAN, 32,
		NULL, SMB2_LEASE_STATE_WRITE_CACHING, NULL, HFILL }},

	{ &hf_smb2_lease_flags,
	  { "Lease Flags", "smb2.lease.lease_flags", FT_UINT32, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_lease_flags_break_ack_required,
	  { "Break Ack Required", "smb2.lease.lease_state.break_ack_required", FT_BOOLEAN, 32,
		NULL, SMB2_LEASE_FLAGS_BREAK_ACK_REQUIRED, NULL, HFILL }},

	{ &hf_smb2_lease_flags_break_in_progress,
	  { "Break In Progress", "smb2.lease.lease_state.break_in_progress", FT_BOOLEAN, 32,
		NULL, SMB2_LEASE_FLAGS_BREAK_IN_PROGRESS, NULL, HFILL }},

	{ &hf_smb2_lease_flags_parent_lease_key_set,
	  { "Parent Lease Key Set", "smb2.lease.lease_state.parent_lease_key_set", FT_BOOLEAN, 32,
		NULL, SMB2_LEASE_FLAGS_PARENT_LEASE_KEY_SET, NULL, HFILL }},

	{ &hf_smb2_lease_duration,
	  { "Lease Duration", "smb2.lease.lease_duration", FT_UINT64, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_parent_lease_key,
	  { "Parent Lease Key", "smb2.lease.parent_lease_key", FT_GUID, BASE_NONE,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_lease_epoch,
	  { "Lease Epoch", "smb2.lease.lease_oplock", FT_UINT32, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_lease_break_reason,
	  { "Lease Break Reason", "smb2.lease.lease_break_reason", FT_UINT32, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_lease_access_mask_hint,
	  { "Access Mask Hint", "smb2.lease.access_mask_hint", FT_UINT32, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_lease_share_mask_hint,
	  { "Share Mask Hint", "smb2.lease.share_mask_hint", FT_UINT32, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_data_length,
		{ "Data Length", "smb2.create.data_length", FT_UINT32, BASE_DEC,
		NULL, 0, "Length Data or 0", HFILL }},

	{ &hf_smb2_next_offset,
		{ "Next Offset", "smb2.next_offset", FT_UINT32, BASE_DEC,
		NULL, 0, "Offset to next buffer or 0", HFILL }},

	{ &hf_smb2_current_time,
		{ "Current Time", "smb2.current_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
		NULL, 0, "Current Time at server", HFILL }},

	{ &hf_smb2_boot_time,
		{ "Boot Time", "smb2.boot_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
		NULL, 0, "Boot Time at server", HFILL }},

	{ &hf_smb2_ea_flags,
		{ "EA Flags", "smb2.ea.flags", FT_UINT8, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_ea_name_len,
		{ "EA Name Length", "smb2.ea.name_len", FT_UINT8, BASE_DEC,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_ea_data_len,
		{ "EA Data Length", "smb2.ea.data_len", FT_UINT8, BASE_DEC,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_delete_pending,
		{ "Delete Pending", "smb2.delete_pending", FT_UINT8, BASE_DEC,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_is_directory,
		{ "Is Directory", "smb2.is_directory", FT_UINT8, BASE_DEC,
		NULL, 0, "Is this a directory?", HFILL }},

	{ &hf_smb2_oplock,
		{ "Oplock", "smb2.create.oplock", FT_UINT8, BASE_HEX,
		VALS(oplock_vals), 0, "Oplock type", HFILL }},

	{ &hf_smb2_close_flags,
		{ "Close Flags", "smb2.close.flags", FT_UINT16, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_notify_flags,
		{ "Notify Flags", "smb2.notify.flags", FT_UINT16, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_buffer_code_len,
		{ "Length", "smb2.buffer_code.length", FT_UINT16, BASE_DEC,
		NULL, 0, "Length of fixed portion of PDU", HFILL }},

	{ &hf_smb2_olb_length,
		{ "Length", "smb2.olb.length", FT_UINT32, BASE_DEC,
		NULL, 0, "Length of the buffer", HFILL }},

	{ &hf_smb2_olb_offset,
		{ "Offset", "smb2.olb.offset", FT_UINT32, BASE_HEX,
		NULL, 0, "Offset to the buffer", HFILL }},

	{ &hf_smb2_buffer_code_flags_dyn,
		{ "Dynamic Part", "smb2.buffer_code.dynamic", FT_BOOLEAN, 16,
		NULL, 0x0001, "Whether a dynamic length blob follows", HFILL }},

	{ &hf_smb2_ea_data,
		{ "EA Data", "smb2.ea.data", FT_STRING, BASE_NONE,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_ea_name,
		{ "EA Name", "smb2.ea.name", FT_STRING, BASE_NONE,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_impersonation_level,
		{ "Impersonation", "smb2.impersonation.level", FT_UINT32, BASE_DEC,
		VALS(impersonation_level_vals), 0, "Impersonation level", HFILL }},

	{ &hf_smb2_ioctl_function,
		{ "Function", "smb2.ioctl.function", FT_UINT32, BASE_HEX,
		VALS(smb2_ioctl_vals), 0, "Ioctl function", HFILL }},

	{ &hf_smb2_ioctl_function_device,
		{ "Device", "smb2.ioctl.function.device", FT_UINT32, BASE_HEX,
		VALS(smb2_ioctl_device_vals), 0xffff0000, "Device for Ioctl", HFILL }},

	{ &hf_smb2_ioctl_function_access,
		{ "Access", "smb2.ioctl.function.access", FT_UINT32, BASE_HEX,
		VALS(smb2_ioctl_access_vals), 0x0000c000, "Access for Ioctl", HFILL }},

	{ &hf_smb2_ioctl_function_function,
		{ "Function", "smb2.ioctl.function.function", FT_UINT32, BASE_HEX,
		NULL, 0x00003ffc, "Function for Ioctl", HFILL }},

	{ &hf_smb2_ioctl_function_method,
		{ "Method", "smb2.ioctl.function.method", FT_UINT32, BASE_HEX,
		VALS(smb2_ioctl_method_vals), 0x00000003, "Method for Ioctl", HFILL }},

	{ &hf_smb2_ioctl_resiliency_timeout,
		{ "Timeout", "smb2.ioctl.resiliency.timeout", FT_UINT32, BASE_DEC,
		NULL, 0, "Resiliency timeout", HFILL }},

	{ &hf_smb2_ioctl_resiliency_reserved,
		{ "Reserved", "smb2.ioctl.resiliency.reserved", FT_UINT32, BASE_DEC,
		NULL, 0, "Resiliency reserved", HFILL }},

	{ &hf_windows_sockaddr_family,
		{ "Socket Family", "windows.sockaddr.family", FT_UINT16, BASE_DEC,
		NULL, 0, "The socket address family (on windows)", HFILL }},

	{ &hf_windows_sockaddr_port,
		{ "Socket Port", "windows.sockaddr.port", FT_UINT16, BASE_DEC,
		NULL, 0, "The socket address port", HFILL }},

	{ &hf_windows_sockaddr_in_addr,
		{ "Socket IPv4", "windows.sockaddr.in.addr", FT_IPv4, BASE_NONE,
		NULL, 0, "The IPv4 address", HFILL }},

	{ &hf_windows_sockaddr_in6_flowinfo,
		{ "IPv6 Flow Info", "windows.sockaddr.in6.flow_info", FT_UINT32, BASE_HEX,
		NULL, 0, "The socket IPv6 flow info", HFILL }},

	{ &hf_windows_sockaddr_in6_addr,
		{ "Socket IPv6", "windows.sockaddr.in6.addr", FT_IPv6, BASE_NONE,
		NULL, 0, "The IPv6 address", HFILL }},

	{ &hf_windows_sockaddr_in6_scope_id,
		{ "IPv6 Scope ID", "windows.sockaddr.in6.scope_id", FT_UINT32, BASE_DEC,
		NULL, 0, "The socket IPv6 scope id", HFILL }},

	{ &hf_smb2_ioctl_network_interface_next_offset,
		{ "Next Offset", "smb2.ioctl.network_interfaces.next_offset", FT_UINT32, BASE_HEX,
		NULL, 0, "Offset to next entry in chain or 0", HFILL }},

	{ &hf_smb2_ioctl_network_interface_index,
		{ "Interface Index", "smb2.ioctl.network_interfaces.index", FT_UINT32, BASE_DEC,
		NULL, 0, "The index of the interface", HFILL }},

	{ &hf_smb2_ioctl_network_interface_rss_queue_count,
		{ "RSS Queue Count", "smb2.ioctl.network_interfaces.rss_queue_count", FT_UINT32, BASE_DEC,
		NULL, 0, "The RSS queue count", HFILL }},

	{ &hf_smb2_ioctl_network_interface_capabilities,
		{ "Interface Cababilities", "smb2.ioctl.network_interfaces.capabilities", FT_UINT32, BASE_HEX,
		NULL, 0, "The RSS queue count", HFILL }},

	{ &hf_smb2_ioctl_network_interface_capability_rss,
		{ "RSS", "smb2.ioctl.network_interfaces.capabilities.rss", FT_BOOLEAN, 32,
		TFS(&tfs_smb2_ioctl_network_interface_capability_rss),
		NETWORK_INTERFACE_CAP_RSS, "If the host supports RSS", HFILL }},

	{ &hf_smb2_ioctl_network_interface_capability_rdma,
		{ "RMDA", "smb2.ioctl.network_interfaces.capabilities.rdma", FT_BOOLEAN, 32,
		TFS(&tfs_smb2_ioctl_network_interface_capability_rdma),
		NETWORK_INTERFACE_CAP_RMDA, "If the host supports RDMA", HFILL }},

	{ &hf_smb2_ioctl_network_interface_link_speed,
		{ "Link Speed", "smb2.ioctl.network_interfaces.link_speed", FT_UINT64, BASE_DEC,
		NULL, 0, "The link speed of the interface", HFILL }},

	{ &hf_smb2_ioctl_shadow_copy_num_volumes,
		{ "Num Volumes", "smb2.ioctl.shadow_copy.num_volumes", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of shadow copy volumes", HFILL }},

	{ &hf_smb2_ioctl_shadow_copy_num_labels,
		{ "Num Labels", "smb2.ioctl.shadow_copy.num_labels", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of shadow copy labels", HFILL }},

	{ &hf_smb2_ioctl_shadow_copy_label,
		{ "Label", "smb2.ioctl.shadow_copy.label", FT_STRING, BASE_NONE,
		NULL, 0, "Shadow copy label", HFILL }},

	{ &hf_smb2_compression_format,
		{ "Compression Format", "smb2.compression_format", FT_UINT16, BASE_DEC,
		VALS(compression_format_vals), 0, "Compression to use", HFILL }},

	{ &hf_smb2_share_type,
		{ "Share Type", "smb2.share_type", FT_UINT8, BASE_HEX,
		VALS(smb2_share_type_vals), 0, "Type of share", HFILL }},

	{ &hf_smb2_credit_charge,
		{ "Credit Charge", "smb2.credit.charge", FT_UINT16, BASE_DEC,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_credits_requested,
		{ "Credits requested", "smb2.credits.requested", FT_UINT16, BASE_DEC,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_credits_granted,
		{ "Credits granted", "smb2.credits.granted", FT_UINT16, BASE_DEC,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_dialect_count,
		{ "Dialect count", "smb2.dialect_count", FT_UINT16, BASE_DEC,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_dialect,
		{ "Dialect", "smb2.dialect", FT_UINT16, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_security_mode,
		{ "Security mode", "smb2.sec_mode", FT_UINT8, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_session_flags,
		{ "Session Flags", "smb2.session_flags", FT_UINT16, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_lock_count,
		{ "Lock Count", "smb2.lock_count", FT_UINT16, BASE_DEC,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_capabilities,
		{ "Capabilities", "smb2.capabilities", FT_UINT32, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_ioctl_shadow_copy_count,
		{ "Count", "smb2.ioctl.shadow_copy.count", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of bytes for shadow copy label strings", HFILL }},

	{ &hf_smb2_auth_frame,
		{ "Authenticated in Frame", "smb2.auth_frame", FT_UINT32, BASE_DEC,
		NULL, 0, "Which frame this user was authenticated in", HFILL }},

	{ &hf_smb2_tcon_frame,
		{ "Connected in Frame", "smb2.tcon_frame", FT_UINT32, BASE_DEC,
		NULL, 0, "Which frame this share was connected in", HFILL }},

	{ &hf_smb2_tag,
		{ "Tag", "smb2.tag", FT_STRING, BASE_NONE,
		NULL, 0, "Tag of chain entry", HFILL }},

	{ &hf_smb2_acct_name,
		{ "Account", "smb2.acct", FT_STRING, BASE_NONE,
		NULL, 0, "Account Name", HFILL }},

	{ &hf_smb2_domain_name,
		{ "Domain", "smb2.domain", FT_STRING, BASE_NONE,
		NULL, 0, "Domain Name", HFILL }},

	{ &hf_smb2_host_name,
		{ "Host", "smb2.host", FT_STRING, BASE_NONE,
		NULL, 0, "Host Name", HFILL }},

	{ &hf_smb2_signature,
		{ "Signature", "smb2.signature", FT_BYTES, BASE_NONE,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_unknown,
		{ "unknown", "smb2.unknown", FT_BYTES, BASE_NONE,
		NULL, 0, "Unknown bytes", HFILL }},

	{ &hf_smb2_twrp_timestamp,
		{ "Timestamp", "smb2.twrp_timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
		NULL, 0, "TWrp timestamp", HFILL }},

	{ &hf_smb2_mxac_timestamp,
		{ "Timestamp", "smb2.mxac_timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
		NULL, 0, "MxAc timestamp", HFILL }},

	{ &hf_smb2_mxac_status,
		{ "Query Status", "smb2.mxac_status", FT_UINT32, BASE_HEX,
		VALS(NT_errors), 0, "NT Status code", HFILL }},

	{ &hf_smb2_qfid_fid,
		{ "Opaque File ID", "smb2.qfid_fid", FT_BYTES, BASE_NONE,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_ses_flags_guest,
		{ "Guest", "smb2.ses_flags.guest", FT_BOOLEAN, 16,
		NULL, SES_FLAGS_GUEST, NULL, HFILL }},

	{ &hf_smb2_ses_flags_null,
		{ "Null", "smb2.ses_flags.null", FT_BOOLEAN, 16,
		NULL, SES_FLAGS_NULL, NULL, HFILL }},

	{ &hf_smb2_secmode_flags_sign_required,
		{ "Signing required", "smb2.sec_mode.sign_required", FT_BOOLEAN, 8,
		NULL, NEGPROT_SIGN_REQ, "Is signing required", HFILL }},

	{ &hf_smb2_secmode_flags_sign_enabled,
		{ "Signing enabled", "smb2.sec_mode.sign_enabled", FT_BOOLEAN, 8,
		NULL, NEGPROT_SIGN_ENABLED, "Is signing enabled", HFILL }},

	{ &hf_smb2_ses_req_flags,
		{ "Flags", "smb2.ses_req_flags", FT_UINT8, BASE_DEC,
		NULL, 0, "Flags", HFILL }},

	{ &hf_smb2_ses_req_flags_session_binding,
		{ "Session Binding Request", "smb2.ses_req_flags.session_binding", FT_BOOLEAN, 8,
		NULL, SES_REQ_FLAGS_SESSION_BINDING,
		"The client wants to bind to an existing session", HFILL }},

	{ &hf_smb2_cap_dfs,
		{ "DFS", "smb2.capabilities.dfs", FT_BOOLEAN, 32,
		TFS(&tfs_cap_dfs), NEGPROT_CAP_DFS, "If the host supports dfs", HFILL }},

	{ &hf_smb2_cap_leasing,
		{ "LEASING", "smb2.capabilities.leasing", FT_BOOLEAN, 32,
		TFS(&tfs_cap_leasing), NEGPROT_CAP_LEASING,
		"If the host supports leasing", HFILL }},

	{ &hf_smb2_cap_large_mtu,
		{ "LARGE MTU", "smb2.capabilities.large_mtu", FT_BOOLEAN, 32,
		TFS(&tfs_cap_large_mtu), NEGPROT_CAP_LARGE_MTU,
		"If the host supports LARGE MTU", HFILL }},

	{ &hf_smb2_cap_multi_channel,
		{ "MULTI CHANNEL", "smb2.capabilities.multi_channel", FT_BOOLEAN, 32,
		TFS(&tfs_cap_multi_channel), NEGPROT_CAP_MULTI_CHANNEL,
		"If the host supports MULTI CHANNEL", HFILL }},

	{ &hf_smb2_cap_persistent_handles,
		{ "LARGE MTU", "smb2.capabilities.persistent_handles", FT_BOOLEAN, 32,
		TFS(&tfs_cap_persistent_handles), NEGPROT_CAP_PERSISTENT_HANDLES,
		"If the host supports PERSISTENT HANDLES", HFILL }},

	{ &hf_smb2_cap_directory_leasing,
		{ "DIRECTORY LEASING", "smb2.capabilities.directory_leasing", FT_BOOLEAN, 32,
		TFS(&tfs_cap_directory_leasing), NEGPROT_CAP_DIRECTORY_LEASING,
		"If the host supports DIRECTORY LEASING", HFILL }},

	{ &hf_smb2_max_trans_size,
		{ "Max Transaction Size", "smb2.max_trans_size", FT_UINT32, BASE_DEC,
		NULL, 0, "Maximum size of a transaction", HFILL }},

	{ &hf_smb2_max_read_size,
		{ "Max Read Size", "smb2.max_read_size", FT_UINT32, BASE_DEC,
		NULL, 0, "Maximum size of a read", HFILL }},

	{ &hf_smb2_max_write_size,
		{ "Max Write Size", "smb2.max_write_size", FT_UINT32, BASE_DEC,
		NULL, 0, "Maximum size of a write", HFILL }},

	{ &hf_smb2_channel,
		{ "Channel", "smb2.channel", FT_UINT32, BASE_DEC,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_share_flags,
		{ "Share flags", "smb2.share_flags", FT_UINT32, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_share_flags_dfs,
		{ "DFS", "smb2.share_flags.dfs", FT_BOOLEAN, 32,
		NULL, SHARE_FLAGS_dfs, "The specified share is present in a Distributed File System (DFS) tree structure", HFILL }},

	{ &hf_smb2_share_flags_dfs_root,
		{ "DFS root", "smb2.share_flags.dfs_root", FT_BOOLEAN, 32,
		NULL, SHARE_FLAGS_dfs_root, "The specified share is present in a Distributed File System (DFS) tree structure", HFILL }},

	{ &hf_smb2_share_flags_restrict_exclusive_opens,
		{ "Restrict exclusive opens", "smb2.share_flags.restrict_exclusive_opens", FT_BOOLEAN, 32,
		NULL, SHARE_FLAGS_restrict_exclusive_opens, "The specified share disallows exclusive file opens that deny reads to an open file", HFILL }},

	{ &hf_smb2_share_flags_force_shared_delete,
		{ "Force shared delete", "smb2.share_flags.force_shared_delete", FT_BOOLEAN, 32,
		NULL, SHARE_FLAGS_force_shared_delete, "Shared files in the specified share can be forcibly deleted", HFILL }},

	{ &hf_smb2_share_flags_allow_namespace_caching,
		{ "Allow namepsace caching", "smb2.share_flags.allow_namespace_caching", FT_BOOLEAN, 32,
		NULL, SHARE_FLAGS_allow_namespace_caching, "Clients are allowed to cache the namespace of the specified share", HFILL }},

	{ &hf_smb2_share_flags_access_based_dir_enum,
		{ "Access based directory enum", "smb2.share_flags.access_based_dir_enum", FT_BOOLEAN, 32,
		NULL, SHARE_FLAGS_access_based_dir_enum, "The server will filter directory entries based on the access permissions of the client", HFILL }},

	{ &hf_smb2_share_flags_force_levelii_oplock,
	  	{ "Force level II oplock", "smb2.share_flags.force_levelii_oplock", FT_BOOLEAN, 32,
		NULL, SHARE_FLAGS_force_levelii_oplock, "The server will not issue exclusive caching rights on this share", HFILL }},

	{ &hf_smb2_share_flags_enable_hash_v1,
	  	{ "Enable hash V1", "smb2.share_flags.enable_hash_v1", FT_BOOLEAN, 32,
		NULL, SHARE_FLAGS_enable_hash_v1, "The share supports hash generation V1 for branch cache retrieval of data (see also section 2.2.31.2 of MS-SMB2)", HFILL }},

	{ &hf_smb2_share_flags_enable_hash_v2,
	  	{ "Enable hash V2", "smb2.share_flags.enable_hash_v2", FT_BOOLEAN, 32,
		NULL, SHARE_FLAGS_enable_hash_v2, "The share supports hash generation V2 for branch cache retrieval of data (see also section 2.2.31.2 of MS-SMB2)", HFILL }},

	{ &hf_smb2_share_caching,
		{ "Caching policy", "smb2.share.caching", FT_UINT32, BASE_HEX,
		VALS(share_cache_vals), 0, NULL, HFILL }},

	{ &hf_smb2_share_caps,
		{ "Share Capabilities", "smb2.share_caps", FT_UINT32, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_share_caps_dfs,
		{ "DFS", "smb2.share_caps.dfs", FT_BOOLEAN, 32,
		NULL, SHARE_CAPS_DFS, "The specified share is present in a DFS tree structure", HFILL }},

	{ &hf_smb2_share_caps_continuous_availability,
		{ "CONTINUOUS AVAILABILITY", "smb2.share_caps.continuous_availability", FT_BOOLEAN, 32,
		NULL, SHARE_CAPS_CONTINUOUS_AVAILABILITY,
		"The specified share is continuously available", HFILL }},

	{ &hf_smb2_ioctl_flags,
		{ "Flags", "smb2.ioctl.flags", FT_UINT32, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_min_count,
		{ "Min Count", "smb2.min_count", FT_UINT32, BASE_DEC,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_remaining_bytes,
		{ "Remaining Bytes", "smb2.remaining_bytes", FT_UINT32, BASE_DEC,		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_channel_info_offset,
		{ "Channel Info Offset", "smb2.channel_info_offset", FT_UINT16, BASE_DEC,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_channel_info_length,
		{ "Channel Info Length", "smb2.channel_info_length", FT_UINT16, BASE_DEC,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_ioctl_is_fsctl,
		{ "Is FSCTL", "smb2.ioctl.is_fsctl", FT_BOOLEAN, 32,
		NULL, 0x00000001, NULL, HFILL }},

	{ &hf_smb2_output_buffer_len,
		{ "Output Buffer Length", "smb2.output_buffer_len", FT_UINT16, BASE_DEC,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_close_pq_attrib,
		{ "PostQuery Attrib", "smb2.close.pq_attrib", FT_BOOLEAN, 16,
		NULL, 0x0001, NULL, HFILL }},

	{ &hf_smb2_notify_watch_tree,
		{ "Watch Tree", "smb2.notify.watch_tree", FT_BOOLEAN, 16,
		NULL, 0x0001, NULL, HFILL }},

	{ &hf_smb2_notify_out_data,
		{ "Out Data", "smb2.notify.out", FT_NONE, BASE_NONE,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_find_flags_restart_scans,
		{ "Restart Scans", "smb2.find.restart_scans", FT_BOOLEAN, 8,
		NULL, SMB2_FIND_FLAG_RESTART_SCANS, NULL, HFILL }},

	{ &hf_smb2_find_flags_single_entry,
		{ "Single Entry", "smb2.find.single_entry", FT_BOOLEAN, 8,
		NULL, SMB2_FIND_FLAG_SINGLE_ENTRY, NULL, HFILL }},

	{ &hf_smb2_find_flags_index_specified,
		{ "Index Specified", "smb2.find.index_specified", FT_BOOLEAN, 8,
		NULL, SMB2_FIND_FLAG_INDEX_SPECIFIED, NULL, HFILL }},

	{ &hf_smb2_find_flags_reopen,
		{ "Reopen", "smb2.find.reopen", FT_BOOLEAN, 8,
		NULL, SMB2_FIND_FLAG_REOPEN, NULL, HFILL }},

	{ &hf_smb2_file_index,
		{ "File Index", "smb2.file_index", FT_UINT32, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_file_directory_info,
		{ "FileDirectoryInfo", "smb2.find.file_directory_info", FT_NONE, BASE_NONE,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_full_directory_info,
		{ "FullDirectoryInfo", "smb2.find.full_directory_info", FT_NONE, BASE_NONE,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_both_directory_info,
		{ "FileBothDirectoryInfo", "smb2.find.both_directory_info", FT_NONE, BASE_NONE,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_id_both_directory_info,
		{ "FileIdBothDirectoryInfo", "smb2.find.id_both_directory_info", FT_NONE, BASE_NONE,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_short_name_len,
		{ "Short Name Length", "smb2.short_name_len", FT_UINT8, BASE_DEC,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_short_name,
		{ "Short Name", "smb2.shortname", FT_STRING, BASE_NONE,
		NULL, 0, NULL, HFILL }},
	{ &hf_smb2_file_name_info,
		{ "FileNameInfo", "smb2.find.name_info", FT_NONE, BASE_NONE,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_lock_info,
		{ "Lock Info", "smb2.lock_info", FT_NONE, BASE_NONE,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_lock_length,
		{ "Length", "smb2.lock_length", FT_UINT64, BASE_DEC,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_lock_flags,
		{ "Flags", "smb2.lock_flags", FT_UINT32, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_lock_flags_shared,
		{ "Shared", "smb2.lock_flags.shared", FT_BOOLEAN, 32,
		NULL, 0x00000001, NULL, HFILL }},

	{ &hf_smb2_lock_flags_exclusive,
		{ "Exclusive", "smb2.lock_flags.exclusive", FT_BOOLEAN, 32,
		NULL, 0x00000002, NULL, HFILL }},

	{ &hf_smb2_lock_flags_unlock,
		{ "Unlock", "smb2.lock_flags.unlock", FT_BOOLEAN, 32,
		NULL, 0x00000004, NULL, HFILL }},

	{ &hf_smb2_lock_flags_fail_immediately,
		{ "Fail Immediately", "smb2.lock_flags.fail_immediately", FT_BOOLEAN, 32,
		NULL, 0x00000010, NULL, HFILL }},

	{ &hf_smb2_error_reserved,
		{ "Reserved", "smb2.error.reserved", FT_UINT16, BASE_HEX,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_error_byte_count,
		{ "Byte Count", "smb2.error.byte_count", FT_UINT32, BASE_DEC,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_error_data,
		{ "Error Data", "smb2.error.data", FT_BYTES, BASE_NONE,
		NULL, 0, NULL, HFILL }},

	{ &hf_smb2_reserved,
		{ "Reserved", "smb2.reserved", FT_BYTES, BASE_NONE,
		NULL, 0, "Reserved bytes", HFILL }},

	{ &hf_smb2_dhnq_buffer_reserved,
		{ "Reserved", "smb2.hf_smb2_dhnq_buffer_reserved", FT_UINT64, BASE_HEX,
		NULL, 0, NULL, HFILL}},

	{ &hf_smb2_dh2x_buffer_timeout,
		{ "Timeout", "smb2.dh2x.timeout", FT_UINT32, BASE_DEC,
		NULL, 0, NULL, HFILL}},

	{ &hf_smb2_dh2x_buffer_flags,
		{ "Flags", "smb2.dh2x.flags", FT_UINT32, BASE_HEX,
		NULL, 0, NULL, HFILL}},

	{ &hf_smb2_dh2x_buffer_flags_persistent_handle,
		{ "Persistent Handle", "smb2.dh2x.flags.persistent_handle", FT_BOOLEAN, 32,
		NULL, SMB2_DH2X_FLAGS_PERSISTENT_HANDLE, NULL, HFILL}},

	{ &hf_smb2_dh2x_buffer_reserved,
		{ "Reserved", "smb2.dh2x.reserved", FT_UINT64, BASE_HEX,
		NULL, 0, NULL, HFILL}},

	{ &hf_smb2_dh2x_buffer_create_guid,
		{ "Create Guid", "smb2.dh2x.create_guid", FT_GUID, BASE_NONE,
		NULL, 0, NULL, HFILL}},

	{ &hf_smb2_APP_INSTANCE_buffer_struct_size,
		{ "Struct Size", "smb2.app_instance.struct_size", FT_UINT16, 16,
		NULL, 0, NULL, HFILL}},

	{ &hf_smb2_APP_INSTANCE_buffer_reserved,
		{ "Reserved", "smb2.app_instance.reserved", FT_UINT16, BASE_HEX,
		NULL, 0, NULL, HFILL}},

	{ &hf_smb2_APP_INSTANCE_buffer_app_guid,
		{ "Application Guid", "smb2.app_instance.app_guid", FT_GUID, BASE_NONE,
		NULL, 0, NULL, HFILL}},

	};

	static gint *ett[] = {
		&ett_smb2,
		&ett_smb2_ea,
		&ett_smb2_olb,
		&ett_smb2_header,
		&ett_smb2_command,
		&ett_smb2_secblob,
		&ett_smb2_file_basic_info,
		&ett_smb2_file_standard_info,
		&ett_smb2_file_internal_info,
		&ett_smb2_file_ea_info,
		&ett_smb2_file_access_info,
		&ett_smb2_file_rename_info,
		&ett_smb2_file_disposition_info,
		&ett_smb2_file_position_info,
		&ett_smb2_file_info_0f,
		&ett_smb2_file_mode_info,
		&ett_smb2_file_alignment_info,
		&ett_smb2_file_all_info,
		&ett_smb2_file_allocation_info,
		&ett_smb2_file_endoffile_info,
		&ett_smb2_file_alternate_name_info,
		&ett_smb2_file_stream_info,
		&ett_smb2_file_pipe_info,
		&ett_smb2_file_compression_info,
		&ett_smb2_file_network_open_info,
		&ett_smb2_file_attribute_tag_info,
		&ett_smb2_fs_info_01,
		&ett_smb2_fs_info_03,
		&ett_smb2_fs_info_04,
		&ett_smb2_fs_info_05,
		&ett_smb2_fs_info_06,
		&ett_smb2_fs_info_07,
		&ett_smb2_fs_objectid_info,
		&ett_smb2_sec_info_00,
		&ett_smb2_tid_tree,
		&ett_smb2_sesid_tree,
		&ett_smb2_create_chain_element,
		&ett_smb2_MxAc_buffer,
		&ett_smb2_QFid_buffer,
		&ett_smb2_RqLs_buffer,
		&ett_smb2_ioctl_function,
		&ett_smb2_FILE_OBJECTID_BUFFER,
		&ett_smb2_flags,
		&ett_smb2_sec_mode,
		&ett_smb2_capabilities,
		&ett_smb2_ses_req_flags,
		&ett_smb2_ses_flags,
		&ett_smb2_create_rep_flags,
		&ett_smb2_lease_state,
		&ett_smb2_lease_flags,
		&ett_smb2_share_flags,
		&ett_smb2_share_caps,
		&ett_smb2_ioctl_flags,
		&ett_smb2_ioctl_network_interface,
		&ett_windows_sockaddr,
		&ett_smb2_close_flags,
		&ett_smb2_notify_flags,
		&ett_smb2_write_flags,
		&ett_smb2_find_flags,
		&ett_smb2_file_directory_info,
		&ett_smb2_both_directory_info,
		&ett_smb2_id_both_directory_info,
		&ett_smb2_full_directory_info,
		&ett_smb2_file_name_info,
		&ett_smb2_lock_info,
		&ett_smb2_lock_flags,
		&ett_smb2_DH2Q_buffer,
		&ett_smb2_DH2C_buffer,
		&ett_smb2_dh2x_flags,
		&ett_smb2_APP_INSTANCE_buffer,
	};

	proto_smb2 = proto_register_protocol("SMB2 (Server Message Block Protocol version 2)",
	    "SMB2", "smb2");
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_smb2, hf, array_length(hf));

	register_heur_dissector_list("smb2_heur_subdissectors", &smb2_heur_subdissector_list);
	smb2_tap = register_tap("smb2");
}

void
proto_reg_handoff_smb2(void)
{
	gssapi_handle = find_dissector("gssapi");
	ntlmssp_handle = find_dissector("ntlmssp");
	heur_dissector_add("netbios", dissect_smb2_heur, proto_smb2);
}
