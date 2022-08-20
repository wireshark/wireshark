/* packet-smb2.c
 * Routines for smb2 packet dissection
 * Ronnie Sahlberg 2005
 *
 * For documentation of this protocol, see:
 *
 * https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/
 * https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/
 * https://gitlab.com/wireshark/wireshark/-/wikis/SMB2
 *
 * If you edit this file, keep the wiki updated as well.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/tap.h>
#include <epan/srt_table.h>
#include <epan/aftypes.h>
#include <epan/to_str.h>
#include <epan/strutil.h>
#include <epan/asn1.h>
#include <epan/reassemble.h>
#include <epan/uat.h>

#include "packet-smb2.h"
#include "packet-ntlmssp.h"
#include "packet-kerberos.h"
#include "packet-windows-common.h"
#include "packet-dcerpc-nt.h"

#include "read_keytab_file.h"

#include <wsutil/wsgcrypt.h>
#include <wsutil/ws_roundup.h>

#ifdef _WIN32
#include <windows.h>
#else
/* Defined in winnt.h */
#define OWNER_SECURITY_INFORMATION 0x00000001
#define GROUP_SECURITY_INFORMATION 0x00000002
#define DACL_SECURITY_INFORMATION 0x00000004
#define SACL_SECURITY_INFORMATION 0x00000008
#define LABEL_SECURITY_INFORMATION 0x00000010
#define ATTRIBUTE_SECURITY_INFORMATION 0x00000020
#define SCOPE_SECURITY_INFORMATION 0x00000040
#define BACKUP_SECURITY_INFORMATION 0x00010000
#endif

//#define DEBUG_SMB2
#ifdef DEBUG_SMB2
#define DEBUG(...) g_ ## warning(__VA_ARGS__)
#define HEXDUMP(p, sz) do_hexdump((const guint8 *)(p), sz)
static void
do_hexdump (const guint8 *data, gsize len)
{
	guint n, m;

	for (n = 0; n < len; n += 16) {
		g_printerr ("%04x: ", n);

		for (m = n; m < n + 16; m++) {
			if (m > n && (m%4) == 0)
				g_printerr (" ");
			if (m < len)
				g_printerr ("%02x ", data[m]);
			else
				g_printerr ("   ");
		}

		g_printerr ("   ");

		for (m = n; m < len && m < n + 16; m++)
			g_printerr ("%c", g_ascii_isprint (data[m]) ? data[m] : '.');

		g_printerr ("\n");
	}
}
#else
#define DEBUG(...)
#define HEXDUMP(...)
#endif

#define NT_STATUS_PENDING		0x00000103
#define NT_STATUS_BUFFER_TOO_SMALL	0xC0000023
#define NT_STATUS_STOPPED_ON_SYMLINK	0x8000002D
#define NT_STATUS_BAD_NETWORK_NAME	0xC00000CC

void proto_register_smb2(void);
void proto_reg_handoff_smb2(void);

#define SMB2_NORM_HEADER 0xFE
#define SMB2_ENCR_HEADER 0xFD
#define SMB2_COMP_HEADER 0xFC

static wmem_map_t *smb2_sessions = NULL;

static const char smb_header_label[] = "SMB2 Header";
static const char smb_transform_header_label[] = "SMB2 Transform Header";
static const char smb_comp_transform_header_label[] = "SMB2 Compression Transform Header";
static const char smb_bad_header_label[] = "Bad SMB2 Header";

static int proto_smb2 = -1;
static int hf_smb2_cmd = -1;
static int hf_smb2_nt_status = -1;
static int hf_smb2_response_to = -1;
static int hf_smb2_response_in = -1;
static int hf_smb2_time = -1;
static int hf_smb2_preauth_hash = -1;
static int hf_smb2_header_len = -1;
static int hf_smb2_msg_id = -1;
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
static int hf_smb2_flags_replay_operation = -1;
static int hf_smb2_flags_priority_mask = -1;
static int hf_smb2_chain_offset = -1;
static int hf_smb2_security_blob = -1;
static int hf_smb2_ioctl_in_data = -1;
static int hf_smb2_ioctl_out_data = -1;
static int hf_smb2_unknown = -1;
static int hf_smb2_root_directory_mbz = -1;
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
static int hf_smb2_replace_if = -1;
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
static int hf_smb2_flags = -1;
static int hf_smb2_required_buffer_size = -1;
static int hf_smb2_getinfo_input_size = -1;
static int hf_smb2_getinfo_input_offset = -1;
static int hf_smb2_getsetinfo_additional = -1;
static int hf_smb2_getsetinfo_additionals = -1;
static int hf_smb2_getsetinfo_additional_owner = -1;
static int hf_smb2_getsetinfo_additional_group = -1;
static int hf_smb2_getsetinfo_additional_dacl = -1;
static int hf_smb2_getsetinfo_additional_sacl = -1;
static int hf_smb2_getsetinfo_additional_label = -1;
static int hf_smb2_getsetinfo_additional_attribute = -1;
static int hf_smb2_getsetinfo_additional_scope = -1;
static int hf_smb2_getsetinfo_additional_backup = -1;
static int hf_smb2_getinfo_flags = -1;
static int hf_smb2_setinfo_size = -1;
static int hf_smb2_setinfo_offset = -1;
static int hf_smb2_setinfo_reserved = -1;
static int hf_smb2_file_basic_info = -1;
static int hf_smb2_file_standard_info = -1;
static int hf_smb2_file_internal_info = -1;
static int hf_smb2_file_ea_info = -1;
static int hf_smb2_file_access_info = -1;
static int hf_smb2_file_rename_info = -1;
static int hf_smb2_file_disposition_info = -1;
static int hf_smb2_file_position_info = -1;
static int hf_smb2_file_full_ea_info = -1;
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
static int hf_smb2_file_normalized_name_info = -1;
static int hf_smb2_fs_info_01 = -1;
static int hf_smb2_fs_info_03 = -1;
static int hf_smb2_fs_info_04 = -1;
static int hf_smb2_fs_info_05 = -1;
static int hf_smb2_fs_info_06 = -1;
static int hf_smb2_fs_info_07 = -1;
static int hf_smb2_fs_objectid_info = -1;
static int hf_smb2_sec_info_00 = -1;
static int hf_smb2_quota_info = -1;
static int hf_smb2_query_quota_info = -1;
static int hf_smb2_qq_single = -1;
static int hf_smb2_qq_restart = -1;
static int hf_smb2_qq_sidlist_len = -1;
static int hf_smb2_qq_start_sid_len = -1;
static int hf_smb2_qq_start_sid_offset = -1;
static int hf_smb2_fid = -1;
static int hf_smb2_write_length = -1;
static int hf_smb2_write_data = -1;
static int hf_smb2_write_flags = -1;
static int hf_smb2_write_flags_write_through = -1;
static int hf_smb2_write_flags_write_unbuffered = -1;
static int hf_smb2_write_count = -1;
static int hf_smb2_write_remaining = -1;
static int hf_smb2_read_blob = -1;
static int hf_smb2_read_length = -1;
static int hf_smb2_read_remaining = -1;
static int hf_smb2_read_padding = -1;
static int hf_smb2_read_flags = -1;
static int hf_smb2_read_flags_unbuffered = -1;
static int hf_smb2_read_flags_compressed = -1;
static int hf_smb2_file_offset = -1;
static int hf_smb2_qfr_length = -1;
static int hf_smb2_qfr_usage = -1;
static int hf_smb2_qfr_flags = -1;
static int hf_smb2_qfr_total_region_entry_count = -1;
static int hf_smb2_qfr_region_entry_count = -1;
static int hf_smb2_read_data = -1;
static int hf_smb2_disposition_delete_on_close = -1;
static int hf_smb2_create_disposition = -1;
static int hf_smb2_create_chain_offset = -1;
static int hf_smb2_create_chain_data = -1;
static int hf_smb2_data_offset = -1;
static int hf_smb2_extrainfo = -1;
static int hf_smb2_create_action = -1;
static int hf_smb2_create_rep_flags = -1;
static int hf_smb2_create_rep_flags_reparse_point = -1;
static int hf_smb2_next_offset = -1;
static int hf_smb2_negotiate_context_type = -1;
static int hf_smb2_negotiate_context_data_length = -1;
static int hf_smb2_negotiate_context_offset = -1;
static int hf_smb2_negotiate_context_count = -1;
static int hf_smb2_hash_alg_count = -1;
static int hf_smb2_hash_algorithm = -1;
static int hf_smb2_salt_length = -1;
static int hf_smb2_salt = -1;
static int hf_smb2_cipher_count = -1;
static int hf_smb2_cipher_id = -1;
static int hf_smb2_signing_alg_count = -1;
static int hf_smb2_signing_alg_id = -1;
static int hf_smb2_comp_alg_count = -1;
static int hf_smb2_comp_alg_id = -1;
static int hf_smb2_comp_alg_flags = -1;
static int hf_smb2_comp_alg_flags_chained = -1;
static int hf_smb2_comp_alg_flags_reserved = -1;
static int hf_smb2_netname_neg_id = -1;
static int hf_smb2_transport_ctx_flags = -1;
static int hf_smb2_rdma_transform_count = -1;
static int hf_smb2_rdma_transform_reserved1 = -1;
static int hf_smb2_rdma_transform_reserved2 = -1;
static int hf_smb2_rdma_transform_id = -1;
static int hf_smb2_posix_reserved = -1;
static int hf_smb2_inode = -1;
static int hf_smb2_ea_size = -1;
static int hf_smb2_ea_flags = -1;
static int hf_smb2_ea_name_len = -1;
static int hf_smb2_ea_data_len = -1;
static int hf_smb2_ea_name = -1;
static int hf_smb2_ea_data = -1;
static int hf_smb2_position_information = -1;
static int hf_smb2_mode_information = -1;
static int hf_smb2_mode_file_write_through = -1;
static int hf_smb2_mode_file_sequential_only = -1;
static int hf_smb2_mode_file_no_intermediate_buffering = -1;
static int hf_smb2_mode_file_synchronous_io_alert = -1;
static int hf_smb2_mode_file_synchronous_io_nonalert = -1;
static int hf_smb2_mode_file_delete_on_close = -1;
static int hf_smb2_alignment_information = -1;
static int hf_smb2_buffer_code = -1;
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
static int hf_smb2_fsctl_pipe_wait_timeout = -1;
static int hf_smb2_fsctl_pipe_wait_name = -1;

static int hf_smb2_fsctl_odx_token_type = -1;
static int hf_smb2_fsctl_odx_token_idlen = -1;
static int hf_smb2_fsctl_odx_token_idraw = -1;
static int hf_smb2_fsctl_odx_token_ttl = -1;
static int hf_smb2_fsctl_odx_size = -1;
static int hf_smb2_fsctl_odx_flags = -1;
static int hf_smb2_fsctl_odx_file_offset = -1;
static int hf_smb2_fsctl_odx_copy_length = -1;
static int hf_smb2_fsctl_odx_xfer_length = -1;
static int hf_smb2_fsctl_odx_token_offset = -1;

static int hf_smb2_fsctl_sparse_flag = -1;
static int hf_smb2_fsctl_range_offset = -1;
static int hf_smb2_fsctl_range_length = -1;
static int hf_smb2_ioctl_function_method = -1;
static int hf_smb2_ioctl_resiliency_timeout = -1;
static int hf_smb2_ioctl_resiliency_reserved = -1;
static int hf_smb2_ioctl_shared_virtual_disk_support = -1;
static int hf_smb2_ioctl_shared_virtual_disk_handle_state = -1;
static int hf_smb2_ioctl_sqos_protocol_version = -1;
static int hf_smb2_ioctl_sqos_reserved = -1;
static int hf_smb2_ioctl_sqos_options = -1;
static int hf_smb2_ioctl_sqos_op_set_logical_flow_id = -1;
static int hf_smb2_ioctl_sqos_op_set_policy = -1;
static int hf_smb2_ioctl_sqos_op_probe_policy = -1;
static int hf_smb2_ioctl_sqos_op_get_status = -1;
static int hf_smb2_ioctl_sqos_op_update_counters = -1;
static int hf_smb2_ioctl_sqos_logical_flow_id = -1;
static int hf_smb2_ioctl_sqos_policy_id = -1;
static int hf_smb2_ioctl_sqos_initiator_id = -1;
static int hf_smb2_ioctl_sqos_limit = -1;
static int hf_smb2_ioctl_sqos_reservation = -1;
static int hf_smb2_ioctl_sqos_initiator_name = -1;
static int hf_smb2_ioctl_sqos_initiator_node_name = -1;
static int hf_smb2_ioctl_sqos_io_count_increment = -1;
static int hf_smb2_ioctl_sqos_normalized_io_count_increment = -1;
static int hf_smb2_ioctl_sqos_latency_increment = -1;
static int hf_smb2_ioctl_sqos_lower_latency_increment = -1;
static int hf_smb2_ioctl_sqos_bandwidth_limit = -1;
static int hf_smb2_ioctl_sqos_kilobyte_count_increment = -1;
static int hf_smb2_ioctl_sqos_time_to_live = -1;
static int hf_smb2_ioctl_sqos_status = -1;
static int hf_smb2_ioctl_sqos_maximum_io_rate = -1;
static int hf_smb2_ioctl_sqos_minimum_io_rate = -1;
static int hf_smb2_ioctl_sqos_base_io_size = -1;
static int hf_smb2_ioctl_sqos_reserved2 = -1;
static int hf_smb2_ioctl_sqos_maximum_bandwidth = -1;
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
static int hf_smb2_ioctl_enumerate_snapshots_num_snapshots = -1;
static int hf_smb2_ioctl_enumerate_snapshots_num_snapshots_returned = -1;
static int hf_smb2_ioctl_enumerate_snapshots_snapshot_array_size = -1;
static int hf_smb2_ioctl_enumerate_snapshots_snapshot = -1;
static int hf_smb2_compression_format = -1;
static int hf_smb2_checksum_algorithm = -1;
static int hf_smb2_integrity_reserved = -1;
static int hf_smb2_integrity_flags = -1;
static int hf_smb2_integrity_flags_enforcement_off = -1;
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
static int hf_smb2_lease_reserved = -1;
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
static int hf_smb2_channel_sequence = -1;
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
static int hf_smb2_cap_encryption = -1;
static int hf_smb2_dialect = -1;
static int hf_smb2_max_trans_size = -1;
static int hf_smb2_max_read_size = -1;
static int hf_smb2_max_write_size = -1;
static int hf_smb2_channel = -1;
static int hf_smb2_rdma_v1_offset = -1;
static int hf_smb2_rdma_v1_token = -1;
static int hf_smb2_rdma_v1_length = -1;
static int hf_smb2_session_flags = -1;
static int hf_smb2_ses_flags_guest = -1;
static int hf_smb2_ses_flags_null = -1;
static int hf_smb2_ses_flags_encrypt = -1;
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
static int hf_smb2_share_flags_encrypt_data = -1;
static int hf_smb2_share_flags_identity_remoting = -1;
static int hf_smb2_share_flags_compress_data = -1;
static int hf_smb2_share_caching = -1;
static int hf_smb2_share_caps = -1;
static int hf_smb2_share_caps_dfs = -1;
static int hf_smb2_share_caps_continuous_availability = -1;
static int hf_smb2_share_caps_scaleout = -1;
static int hf_smb2_share_caps_cluster = -1;
static int hf_smb2_share_caps_assymetric = -1;
static int hf_smb2_share_caps_redirect_to_owner = -1;
static int hf_smb2_create_flags = -1;
static int hf_smb2_lock_count = -1;
static int hf_smb2_min_count = -1;
static int hf_smb2_remaining_bytes = -1;
static int hf_smb2_channel_info_offset = -1;
static int hf_smb2_channel_info_length = -1;
static int hf_smb2_channel_info_blob = -1;
static int hf_smb2_ioctl_flags = -1;
static int hf_smb2_ioctl_is_fsctl = -1;
static int hf_smb2_close_pq_attrib = -1;
static int hf_smb2_notify_watch_tree = -1;
static int hf_smb2_output_buffer_len = -1;
static int hf_smb2_notify_out_data = -1;
static int hf_smb2_notify_info = -1;
static int hf_smb2_notify_next_offset = -1;
static int hf_smb2_notify_action = -1;
static int hf_smb2_find_flags = -1;
static int hf_smb2_find_flags_restart_scans = -1;
static int hf_smb2_find_flags_single_entry = -1;
static int hf_smb2_find_flags_index_specified = -1;
static int hf_smb2_find_flags_reopen = -1;
static int hf_smb2_file_index = -1;
static int hf_smb2_file_directory_info = -1;
static int hf_smb2_both_directory_info = -1;
static int hf_smb2_posix_info = -1;
static int hf_smb2_short_name_len = -1;
static int hf_smb2_short_name = -1;
static int hf_smb2_id_both_directory_info = -1;
static int hf_smb2_full_directory_info = -1;
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
static int hf_smb2_svhdx_open_device_context_version = -1;
static int hf_smb2_svhdx_open_device_context_has_initiator_id = -1;
static int hf_smb2_svhdx_open_device_context_reserved = -1;
static int hf_smb2_svhdx_open_device_context_initiator_id = -1;
static int hf_smb2_svhdx_open_device_context_flags = -1;
static int hf_smb2_svhdx_open_device_context_originator_flags = -1;
static int hf_smb2_svhdx_open_device_context_open_request_id = -1;
static int hf_smb2_svhdx_open_device_context_initiator_host_name_len = -1;
static int hf_smb2_svhdx_open_device_context_initiator_host_name = -1;
static int hf_smb2_svhdx_open_device_context_virtual_disk_properties_initialized = -1;
static int hf_smb2_svhdx_open_device_context_server_service_version = -1;
static int hf_smb2_svhdx_open_device_context_virtual_sector_size = -1;
static int hf_smb2_svhdx_open_device_context_physical_sector_size = -1;
static int hf_smb2_svhdx_open_device_context_virtual_size = -1;
static int hf_smb2_app_instance_version_struct_size = -1;
static int hf_smb2_app_instance_version_reserved = -1;
static int hf_smb2_app_instance_version_padding = -1;
static int hf_smb2_app_instance_version_high = -1;
static int hf_smb2_app_instance_version_low = -1;
static int hf_smb2_posix_perms = -1;
static int hf_smb2_aapl_command_code = -1;
static int hf_smb2_aapl_reserved = -1;
static int hf_smb2_aapl_server_query_bitmask = -1;
static int hf_smb2_aapl_server_query_bitmask_server_caps = -1;
static int hf_smb2_aapl_server_query_bitmask_volume_caps = -1;
static int hf_smb2_aapl_server_query_bitmask_model_info = -1;
static int hf_smb2_aapl_server_query_caps = -1;
static int hf_smb2_aapl_server_query_caps_supports_read_dir_attr = -1;
static int hf_smb2_aapl_server_query_caps_supports_osx_copyfile = -1;
static int hf_smb2_aapl_server_query_caps_unix_based = -1;
static int hf_smb2_aapl_server_query_caps_supports_nfs_ace = -1;
static int hf_smb2_aapl_server_query_volume_caps = -1;
static int hf_smb2_aapl_server_query_volume_caps_support_resolve_id = -1;
static int hf_smb2_aapl_server_query_volume_caps_case_sensitive = -1;
static int hf_smb2_aapl_server_query_volume_caps_supports_full_sync = -1;
static int hf_smb2_aapl_server_query_model_string = -1;
static int hf_smb2_aapl_server_query_server_path = -1;
static int hf_smb2_error_context_count = -1;
static int hf_smb2_error_reserved = -1;
static int hf_smb2_error_byte_count = -1;
static int hf_smb2_error_data = -1;
static int hf_smb2_error_context = -1;
static int hf_smb2_error_context_length = -1;
static int hf_smb2_error_context_id = -1;
static int hf_smb2_error_min_buf_length = -1;
static int hf_smb2_error_redir_context = -1;
static int hf_smb2_error_redir_struct_size = -1;
static int hf_smb2_error_redir_notif_type = -1;
static int hf_smb2_error_redir_flags = -1;
static int hf_smb2_error_redir_target_type = -1;
static int hf_smb2_error_redir_ip_count = -1;
static int hf_smb2_error_redir_ip_list = -1;
static int hf_smb2_error_redir_res_name = -1;
static int hf_smb2_reserved = -1;
static int hf_smb2_reserved_random = -1;
static int hf_smb2_transform_signature = -1;
static int hf_smb2_transform_nonce = -1;
static int hf_smb2_transform_msg_size = -1;
static int hf_smb2_transform_reserved = -1;
static int hf_smb2_transform_flags = -1;
static int hf_smb2_transform_flags_encrypted = -1;
static int hf_smb2_transform_encrypted_data = -1;
static int hf_smb2_protocol_id = -1;
static int hf_smb2_comp_transform_orig_size = -1;
static int hf_smb2_comp_transform_comp_alg = -1;
static int hf_smb2_comp_transform_flags = -1;
static int hf_smb2_comp_transform_offset = -1;
static int hf_smb2_comp_transform_length = -1;
static int hf_smb2_comp_transform_data = -1;
static int hf_smb2_comp_transform_orig_payload_size = -1;
static int hf_smb2_comp_pattern_v1_pattern = -1;
static int hf_smb2_comp_pattern_v1_reserved1 = -1;
static int hf_smb2_comp_pattern_v1_reserved2 = -1;
static int hf_smb2_comp_pattern_v1_repetitions = -1;
static int hf_smb2_truncated = -1;
static int hf_smb2_pipe_fragments = -1;
static int hf_smb2_pipe_fragment = -1;
static int hf_smb2_pipe_fragment_overlap = -1;
static int hf_smb2_pipe_fragment_overlap_conflict = -1;
static int hf_smb2_pipe_fragment_multiple_tails = -1;
static int hf_smb2_pipe_fragment_too_long_fragment = -1;
static int hf_smb2_pipe_fragment_error = -1;
static int hf_smb2_pipe_fragment_count = -1;
static int hf_smb2_pipe_reassembled_in = -1;
static int hf_smb2_pipe_reassembled_length = -1;
static int hf_smb2_pipe_reassembled_data = -1;
static int hf_smb2_cchunk_resume_key = -1;
static int hf_smb2_cchunk_count = -1;
static int hf_smb2_cchunk_src_offset = -1;
static int hf_smb2_cchunk_dst_offset = -1;
static int hf_smb2_cchunk_xfer_len = -1;
static int hf_smb2_cchunk_chunks_written = -1;
static int hf_smb2_cchunk_bytes_written = -1;
static int hf_smb2_cchunk_total_written = -1;
static int hf_smb2_reparse_data_buffer = -1;
static int hf_smb2_reparse_tag = -1;
static int hf_smb2_reparse_guid = -1;
static int hf_smb2_reparse_data_length = -1;
static int hf_smb2_nfs_type = -1;
static int hf_smb2_nfs_symlink_target = -1;
static int hf_smb2_nfs_chr_major = -1;
static int hf_smb2_nfs_chr_minor = -1;
static int hf_smb2_nfs_blk_major = -1;
static int hf_smb2_nfs_blk_minor = -1;
static int hf_smb2_symlink_error_response = -1;
static int hf_smb2_symlink_length = -1;
static int hf_smb2_symlink_error_tag = -1;
static int hf_smb2_unparsed_path_length = -1;
static int hf_smb2_symlink_substitute_name = -1;
static int hf_smb2_symlink_print_name = -1;
static int hf_smb2_symlink_flags = -1;
static int hf_smb2_bad_signature = -1;
static int hf_smb2_good_signature = -1;
static int hf_smb2_fscc_file_attr = -1;
static int hf_smb2_fscc_file_attr_archive = -1;
static int hf_smb2_fscc_file_attr_compressed = -1;
static int hf_smb2_fscc_file_attr_directory = -1;
static int hf_smb2_fscc_file_attr_encrypted = -1;
static int hf_smb2_fscc_file_attr_hidden = -1;
static int hf_smb2_fscc_file_attr_normal = -1;
static int hf_smb2_fscc_file_attr_not_content_indexed = -1;
static int hf_smb2_fscc_file_attr_offline = -1;
static int hf_smb2_fscc_file_attr_read_only = -1;
static int hf_smb2_fscc_file_attr_reparse_point = -1;
static int hf_smb2_fscc_file_attr_sparse_file = -1;
static int hf_smb2_fscc_file_attr_system = -1;
static int hf_smb2_fscc_file_attr_temporary = -1;
static int hf_smb2_fscc_file_attr_integrity_stream = -1;
static int hf_smb2_fscc_file_attr_no_scrub_data = -1;
static int hf_smb2_tree_connect_flags = -1;
static int hf_smb2_tc_cluster_reconnect = -1;
static int hf_smb2_tc_redirect_to_owner = -1;
static int hf_smb2_tc_extension_present = -1;
static int hf_smb2_tc_reserved = -1;

static gint ett_smb2 = -1;
static gint ett_smb2_olb = -1;
static gint ett_smb2_ea = -1;
static gint ett_smb2_header = -1;
static gint ett_smb2_encrypted = -1;
static gint ett_smb2_compressed = -1;
static gint ett_smb2_decompressed = -1;
static gint ett_smb2_command = -1;
static gint ett_smb2_secblob = -1;
static gint ett_smb2_negotiate_context_element = -1;
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
static gint ett_smb2_file_full_ea_info = -1;
static gint ett_smb2_file_normalized_name_info = -1;
static gint ett_smb2_fs_info_01 = -1;
static gint ett_smb2_fs_info_03 = -1;
static gint ett_smb2_fs_info_04 = -1;
static gint ett_smb2_fs_info_05 = -1;
static gint ett_smb2_fs_info_06 = -1;
static gint ett_smb2_fs_info_07 = -1;
static gint ett_smb2_fs_objectid_info = -1;
static gint ett_smb2_sec_info_00 = -1;
static gint ett_smb2_additional_information_sec_mask = -1;
static gint ett_smb2_quota_info = -1;
static gint ett_smb2_query_quota_info = -1;
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
static gint ett_smb2_comp_alg_flags = -1;
static gint ett_smb2_ioctl_flags = -1;
static gint ett_smb2_ioctl_network_interface = -1;
static gint ett_smb2_ioctl_sqos_opeations = -1;
static gint ett_smb2_fsctl_range_data = -1;
static gint ett_windows_sockaddr = -1;
static gint ett_smb2_close_flags = -1;
static gint ett_smb2_notify_info = -1;
static gint ett_smb2_notify_flags = -1;
static gint ett_smb2_write_flags = -1;
static gint ett_smb2_rdma_v1 = -1;
static gint ett_smb2_DH2Q_buffer = -1;
static gint ett_smb2_DH2C_buffer = -1;
static gint ett_smb2_dh2x_flags = -1;
static gint ett_smb2_APP_INSTANCE_buffer = -1;
static gint ett_smb2_svhdx_open_device_context = -1;
static gint ett_smb2_app_instance_version_buffer = -1;
static gint ett_smb2_app_instance_version_buffer_version = -1;
static gint ett_smb2_aapl_create_context_request = -1;
static gint ett_smb2_aapl_server_query_bitmask = -1;
static gint ett_smb2_aapl_server_query_caps = -1;
static gint ett_smb2_aapl_create_context_response = -1;
static gint ett_smb2_aapl_server_query_volume_caps = -1;
static gint ett_smb2_integrity_flags = -1;
static gint ett_smb2_find_flags = -1;
static gint ett_smb2_file_directory_info = -1;
static gint ett_smb2_both_directory_info = -1;
static gint ett_smb2_id_both_directory_info = -1;
static gint ett_smb2_full_directory_info = -1;
static gint ett_smb2_posix_info = -1;
static gint ett_smb2_file_name_info = -1;
static gint ett_smb2_lock_info = -1;
static gint ett_smb2_lock_flags = -1;
static gint ett_smb2_buffercode = -1;
static gint ett_smb2_ioctl_network_interface_capabilities = -1;
static gint ett_smb2_tree_connect_flags = -1;
static gint ett_qfr_entry = -1;
static gint ett_smb2_pipe_fragment = -1;
static gint ett_smb2_pipe_fragments = -1;
static gint ett_smb2_cchunk_entry = -1;
static gint ett_smb2_fsctl_odx_token = -1;
static gint ett_smb2_symlink_error_response = -1;
static gint ett_smb2_reparse_data_buffer = -1;
static gint ett_smb2_error_data = -1;
static gint ett_smb2_error_context = -1;
static gint ett_smb2_error_redir_context = -1;
static gint ett_smb2_error_redir_ip_list = -1;
static gint ett_smb2_read_flags = -1;
static gint ett_smb2_signature = -1;
static gint ett_smb2_transform_flags = -1;
static gint ett_smb2_fscc_file_attributes = -1;
static gint ett_smb2_comp_payload = -1;
static gint ett_smb2_comp_pattern_v1 = -1;

static expert_field ei_smb2_invalid_length = EI_INIT;
static expert_field ei_smb2_bad_response = EI_INIT;
static expert_field ei_smb2_invalid_getinfo_offset = EI_INIT;
static expert_field ei_smb2_invalid_getinfo_size = EI_INIT;
static expert_field ei_smb2_empty_getinfo_buffer = EI_INIT;
static expert_field ei_smb2_invalid_signature = EI_INIT;

static int smb2_tap = -1;
static int smb2_eo_tap = -1;

static dissector_handle_t gssapi_handle  = NULL;
static dissector_handle_t ntlmssp_handle = NULL;
static dissector_handle_t rsvd_handle = NULL;

static heur_dissector_list_t smb2_pipe_subdissector_list;

static const fragment_items smb2_pipe_frag_items = {
	&ett_smb2_pipe_fragment,
	&ett_smb2_pipe_fragments,
	&hf_smb2_pipe_fragments,
	&hf_smb2_pipe_fragment,
	&hf_smb2_pipe_fragment_overlap,
	&hf_smb2_pipe_fragment_overlap_conflict,
	&hf_smb2_pipe_fragment_multiple_tails,
	&hf_smb2_pipe_fragment_too_long_fragment,
	&hf_smb2_pipe_fragment_error,
	&hf_smb2_pipe_fragment_count,
	&hf_smb2_pipe_reassembled_in,
	&hf_smb2_pipe_reassembled_length,
	&hf_smb2_pipe_reassembled_data,
	"Fragments"
};

#define FILE_BYTE_ALIGNMENT 0x00
#define FILE_WORD_ALIGNMENT 0x01
#define FILE_LONG_ALIGNMENT 0x03
#define FILE_QUAD_ALIGNMENT 0x07
#define FILE_OCTA_ALIGNMENT 0x0f
#define FILE_32_BYTE_ALIGNMENT 0x1f
#define FILE_64_BYTE_ALIGNMENT 0x3f
#define FILE_128_BYTE_ALIGNMENT 0x7f
#define FILE_256_BYTE_ALIGNMENT 0xff
#define FILE_512_BYTE_ALIGNMENT 0x1ff
static const value_string smb2_alignment_vals[] = {
	{ FILE_BYTE_ALIGNMENT,     "FILE_BYTE_ALIGNMENT" },
	{ FILE_WORD_ALIGNMENT,     "FILE_WORD_ALIGNMENT" },
	{ FILE_LONG_ALIGNMENT,     "FILE_LONG_ALIGNMENT" },
	{ FILE_OCTA_ALIGNMENT,     "FILE_OCTA_ALIGNMENT" },
	{ FILE_32_BYTE_ALIGNMENT,  "FILE_32_BYTE_ALIGNMENT" },
	{ FILE_64_BYTE_ALIGNMENT,  "FILE_64_BYTE_ALIGNMENT" },
	{ FILE_128_BYTE_ALIGNMENT, "FILE_128_BYTE_ALIGNMENT" },
	{ FILE_256_BYTE_ALIGNMENT, "FILE_256_BYTE_ALIGNMENT" },
	{ FILE_512_BYTE_ALIGNMENT, "FILE_512_BYTE_ALIGNMENT" },
	{ 0, NULL }
};


#define SMB2_CLASS_FILE_INFO	0x01
#define SMB2_CLASS_FS_INFO	0x02
#define SMB2_CLASS_SEC_INFO	0x03
#define SMB2_CLASS_QUOTA_INFO	0x04
static const value_string smb2_class_vals[] = {
	{ SMB2_CLASS_FILE_INFO,	"FILE_INFO"},
	{ SMB2_CLASS_FS_INFO,	"FS_INFO"},
	{ SMB2_CLASS_SEC_INFO,	"SEC_INFO"},
	{ SMB2_CLASS_QUOTA_INFO, "QUOTA_INFO"},
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


#define SMB2_FILE_BASIC_INFO          0x04
#define SMB2_FILE_STANDARD_INFO       0x05
#define SMB2_FILE_INTERNAL_INFO       0x06
#define SMB2_FILE_EA_INFO             0x07
#define SMB2_FILE_ACCESS_INFO         0x08
#define SMB2_FILE_RENAME_INFO         0x0a
#define SMB2_FILE_DISPOSITION_INFO    0x0d
#define SMB2_FILE_POSITION_INFO       0x0e
#define SMB2_FILE_FULL_EA_INFO        0x0f
#define SMB2_FILE_MODE_INFO           0x10
#define SMB2_FILE_ALIGNMENT_INFO      0x11
#define SMB2_FILE_ALL_INFO            0x12
#define SMB2_FILE_ALLOCATION_INFO     0x13
#define SMB2_FILE_ENDOFFILE_INFO      0x14
#define SMB2_FILE_ALTERNATE_NAME_INFO 0x15
#define SMB2_FILE_STREAM_INFO	      0x16
#define SMB2_FILE_PIPE_INFO	      0x17
#define SMB2_FILE_COMPRESSION_INFO    0x1c
#define SMB2_FILE_NETWORK_OPEN_INFO   0x22
#define SMB2_FILE_ATTRIBUTE_TAG_INFO  0x23
#define SMB2_FILE_NORMALIZED_NAME_INFO 0x30
#define SMB2_FILE_POSIX_INFO          0x64

static const value_string smb2_file_info_levels[] = {
	{SMB2_FILE_BASIC_INFO,		"SMB2_FILE_BASIC_INFO" },
	{SMB2_FILE_STANDARD_INFO,	"SMB2_FILE_STANDARD_INFO" },
	{SMB2_FILE_INTERNAL_INFO,	"SMB2_FILE_INTERNAL_INFO" },
	{SMB2_FILE_EA_INFO,		"SMB2_FILE_EA_INFO" },
	{SMB2_FILE_ACCESS_INFO,		"SMB2_FILE_ACCESS_INFO" },
	{SMB2_FILE_RENAME_INFO,		"SMB2_FILE_RENAME_INFO" },
	{SMB2_FILE_DISPOSITION_INFO,	"SMB2_FILE_DISPOSITION_INFO" },
	{SMB2_FILE_POSITION_INFO,	"SMB2_FILE_POSITION_INFO" },
	{SMB2_FILE_FULL_EA_INFO,	"SMB2_FILE_FULL_EA_INFO" },
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
	{SMB2_FILE_NORMALIZED_NAME_INFO,"SMB2_FILE_NORMALIZED_NAME_INFO" },
	{SMB2_FILE_POSIX_INFO,		"SMB2_FILE_POSIX_INFO" },
	{ 0, NULL }
};
static value_string_ext smb2_file_info_levels_ext = VALUE_STRING_EXT_INIT(smb2_file_info_levels);



#define SMB2_FS_INFO_01			0x01
#define SMB2_FS_LABEL_INFO		0x02
#define SMB2_FS_INFO_03			0x03
#define SMB2_FS_INFO_04			0x04
#define SMB2_FS_INFO_05			0x05
#define SMB2_FS_INFO_06			0x06
#define SMB2_FS_INFO_07			0x07
#define SMB2_FS_OBJECTID_INFO		0x08
#define SMB2_FS_DRIVER_PATH_INFO	0x09
#define SMB2_FS_VOLUME_FLAGS_INFO	0x0a
#define SMB2_FS_SECTOR_SIZE_INFO	0x0b

static const value_string smb2_fs_info_levels[] = {
	{SMB2_FS_INFO_01,		"FileFsVolumeInformation" },
	{SMB2_FS_LABEL_INFO,		"FileFsLabelInformation" },
	{SMB2_FS_INFO_03,		"FileFsSizeInformation" },
	{SMB2_FS_INFO_04,		"FileFsDeviceInformation" },
	{SMB2_FS_INFO_05,		"FileFsAttributeInformation" },
	{SMB2_FS_INFO_06,		"FileFsControlInformation" },
	{SMB2_FS_INFO_07,		"FileFsFullSizeInformation" },
	{SMB2_FS_OBJECTID_INFO,		"FileFsObjectIdInformation" },
	{SMB2_FS_DRIVER_PATH_INFO,	"FileFsDriverPathInformation" },
	{SMB2_FS_VOLUME_FLAGS_INFO,	"FileFsVolumeFlagsInformation" },
	{SMB2_FS_SECTOR_SIZE_INFO,	"FileFsSectorSizeInformation" },
	{ 0, NULL }
};
static value_string_ext smb2_fs_info_levels_ext = VALUE_STRING_EXT_INIT(smb2_fs_info_levels);

#define SMB2_SEC_INFO_00	0x00
static const value_string smb2_sec_info_levels[] = {
	{SMB2_SEC_INFO_00,	"SMB2_SEC_INFO_00" },
	{ 0, NULL }
};
static value_string_ext smb2_sec_info_levels_ext = VALUE_STRING_EXT_INIT(smb2_sec_info_levels);

#define SMB2_FIND_DIRECTORY_INFO         0x01
#define SMB2_FIND_FULL_DIRECTORY_INFO    0x02
#define SMB2_FIND_BOTH_DIRECTORY_INFO    0x03
#define SMB2_FIND_INDEX_SPECIFIED        0x04
#define SMB2_FIND_NAME_INFO              0x0C
#define SMB2_FIND_ID_BOTH_DIRECTORY_INFO 0x25
#define SMB2_FIND_ID_FULL_DIRECTORY_INFO 0x26
#define SMB2_FIND_POSIX_INFO             0x64
static const value_string smb2_find_info_levels[] = {
	{ SMB2_FIND_DIRECTORY_INFO,		"SMB2_FIND_DIRECTORY_INFO" },
	{ SMB2_FIND_FULL_DIRECTORY_INFO,	"SMB2_FIND_FULL_DIRECTORY_INFO" },
	{ SMB2_FIND_BOTH_DIRECTORY_INFO,	"SMB2_FIND_BOTH_DIRECTORY_INFO" },
	{ SMB2_FIND_INDEX_SPECIFIED,		"SMB2_FIND_INDEX_SPECIFIED" },
	{ SMB2_FIND_NAME_INFO,			"SMB2_FIND_NAME_INFO" },
	{ SMB2_FIND_ID_BOTH_DIRECTORY_INFO,	"SMB2_FIND_ID_BOTH_DIRECTORY_INFO" },
	{ SMB2_FIND_ID_FULL_DIRECTORY_INFO,	"SMB2_FIND_ID_FULL_DIRECTORY_INFO" },
	{ SMB2_FIND_POSIX_INFO,			"SMB2_FIND_POSIX_INFO" },
	{ 0, NULL }
};

#define SMB2_PREAUTH_INTEGRITY_CAPABILITIES 0x0001
#define SMB2_ENCRYPTION_CAPABILITIES        0x0002
#define SMB2_COMPRESSION_CAPABILITIES       0x0003
#define SMB2_NETNAME_NEGOTIATE_CONTEXT_ID   0x0005
#define SMB2_TRANSPORT_CAPABILITIES         0x0006
#define SMB2_RDMA_TRANSFORM_CAPABILITIES    0x0007
#define SMB2_SIGNING_CAPABILITIES           0x0008
#define SMB2_POSIX_EXTENSIONS_CAPABILITIES  0x0100
static const value_string smb2_negotiate_context_types[] = {
	{ SMB2_PREAUTH_INTEGRITY_CAPABILITIES,  "SMB2_PREAUTH_INTEGRITY_CAPABILITIES" },
	{ SMB2_ENCRYPTION_CAPABILITIES,	"SMB2_ENCRYPTION_CAPABILITIES" },
	{ SMB2_COMPRESSION_CAPABILITIES, "SMB2_COMPRESSION_CAPABILITIES" },
	{ SMB2_NETNAME_NEGOTIATE_CONTEXT_ID, "SMB2_NETNAME_NEGOTIATE_CONTEXT_ID" },
	{ SMB2_TRANSPORT_CAPABILITIES, "SMB2_TRANSPORT_CAPABILITIES" },
	{ SMB2_RDMA_TRANSFORM_CAPABILITIES, "SMB2_RDMA_TRANSFORM_CAPABILITIES" },
	{ SMB2_SIGNING_CAPABILITIES, "SMB2_SIGNING_CAPABILITIES" },
	{ SMB2_POSIX_EXTENSIONS_CAPABILITIES, "SMB2_POSIX_EXTENSIONS_CAPABILITIES" },
	{ 0, NULL }
};

#define SMB2_HASH_ALGORITHM_SHA_512    0x0001
static const value_string smb2_hash_algorithm_types[] = {
	{ SMB2_HASH_ALGORITHM_SHA_512, "SHA-512" },
	{ 0, NULL }
};

#define SMB2_SIGNING_ALG_HMAC_SHA256 0x0000
#define SMB2_SIGNING_ALG_AES_CMAC    0x0001
#define SMB2_SIGNING_ALG_AES_GMAC    0x0002
static const value_string smb2_signing_alg_types[] = {
	{ SMB2_SIGNING_ALG_HMAC_SHA256, "HMAC-SHA256" },
	{ SMB2_SIGNING_ALG_AES_CMAC,    "AES-CMAC" },
	{ SMB2_SIGNING_ALG_AES_GMAC,    "AES-GMAC" },
	{ 0, NULL },
};

#define SMB2_CIPHER_AES_128_CCM        0x0001
#define SMB2_CIPHER_AES_128_GCM        0x0002
#define SMB2_CIPHER_AES_256_CCM        0x0003
#define SMB2_CIPHER_AES_256_GCM        0x0004
static const value_string smb2_cipher_types[] = {
	{ SMB2_CIPHER_AES_128_CCM, "AES-128-CCM" },
	{ SMB2_CIPHER_AES_128_GCM, "AES-128-GCM" },
	{ SMB2_CIPHER_AES_256_CCM, "AES-256-CCM" },
	{ SMB2_CIPHER_AES_256_GCM, "AES-256-GCM" },
	{ 0, NULL }
};

#define SMB2_TRANSFORM_FLAGS_ENCRYPTED        0x0001
static int * const smb2_transform_flags[] = {
	&hf_smb2_transform_flags_encrypted,
	NULL,
};

#define SMB2_COMP_ALG_FLAGS_CHAINED  0x00000001

#define SMB2_COMP_ALG_NONE        0x0000
#define SMB2_COMP_ALG_LZNT1       0x0001
#define SMB2_COMP_ALG_LZ77        0x0002
#define SMB2_COMP_ALG_LZ77HUFF    0x0003
#define SMB2_COMP_ALG_PATTERN_V1  0x0004
static const value_string smb2_comp_alg_types[] = {
	{ SMB2_COMP_ALG_NONE, "None" },
	{ SMB2_COMP_ALG_LZNT1, "LZNT1" },
	{ SMB2_COMP_ALG_LZ77, "LZ77" },
	{ SMB2_COMP_ALG_LZ77HUFF, "LZ77+Huffman" },
	{ SMB2_COMP_ALG_PATTERN_V1, "Pattern_V1" },
	{ 0, NULL }
};

#define SMB2_COMP_FLAG_NONE    0x0000
#define SMB2_COMP_FLAG_CHAINED 0x0001
static const value_string smb2_comp_transform_flags_vals[] = {
	{ SMB2_COMP_FLAG_NONE, "None" },
	{ SMB2_COMP_FLAG_CHAINED, "Chained" },
	{ 0, NULL }
};

#define SMB2_RDMA_TRANSFORM_NONE       0x0000
#define SMB2_RDMA_TRANSFORM_ENCRYPTION 0x0001
#define SMB2_RDMA_TRANSFORM_SIGNING    0x0002
static const value_string smb2_rdma_transform_types[] = {
	{ SMB2_RDMA_TRANSFORM_NONE, "None" },
	{ SMB2_RDMA_TRANSFORM_ENCRYPTION, "Encryption" },
	{ SMB2_RDMA_TRANSFORM_SIGNING, "Signing" },
	{ 0, NULL }
};

#define OPLOCK_BREAK_OPLOCK_STRUCTURE_SIZE 24               /* [MS-SMB2] 2.2.23.1, 2.2.24.1 and 2.2.25.1 */
#define OPLOCK_BREAK_LEASE_NOTIFICATION_STRUCTURE_SIZE 44   /* [MS-SMB2] 2.2.23.2 Lease Break Notification */
#define OPLOCK_BREAK_LEASE_ACKNOWLEDGMENT_STRUCTURE_SIZE 36 /* [MS-SMB2] 2.2.24.2 Lease Break Acknowledgment */
#define OPLOCK_BREAK_LEASE_RESPONSE_STRUCTURE_SIZE 36       /* [MS-SMB2] 2.2.25.2 Lease Break Response */

static const val64_string unique_unsolicited_response[] = {
	{ 0xffffffffffffffff, "unsolicited response" },
	{ 0, NULL }
};

#define SMB2_ERROR_ID_DEFAULT 0x00000000
#define SMB2_ERROR_ID_SHARE_REDIRECT 0x72645253
static const value_string smb2_error_id_vals[] = {
	{ SMB2_ERROR_ID_DEFAULT, "ERROR_ID_DEFAULT" },
	{ SMB2_ERROR_ID_SHARE_REDIRECT, "ERROR_ID_SHARE_REDIRECT" },
	{ 0, NULL }
};

#define SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY 0x00000001
static const value_string smb2_transport_ctx_flags_vals[] = {
	{ SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY, "SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY" },
	{ 0, NULL }
};

#define REPARSE_TAG_RESERVED_ZERO      0x00000000 /* Reserved reparse tag value. */
#define REPARSE_TAG_RESERVED_ONE       0x00000001 /* Reserved reparse tag value. */
#define REPARSE_TAG_MOUNT_POINT        0xA0000003 /* Used for mount point */
#define REPARSE_TAG_HSM                0xC0000004 /* Obsolete. Used by legacy Hierarchical Storage Manager Product. */
#define REPARSE_TAG_DRIVER_EXTENDER    0x80000005 /* Home server drive extender. */
#define REPARSE_TAG_HSM2               0x80000006 /* Obsolete. Used by legacy Hierarchical Storage Manager Product. */
#define REPARSE_TAG_SIS                0x80000007 /* Used by single-instance storage (SIS) filter driver. */
#define REPARSE_TAG_DFS                0x8000000A /* Used by the DFS filter. */
#define REPARSE_TAG_FILTER_MANAGER     0x8000000B /* Used by filter manager test harness */
#define REPARSE_TAG_SYMLINK            0xA000000C /* Used for symbolic link support. */
#define REPARSE_TAG_DFSR               0x80000012 /* Used by the DFS filter. */
#define REPARSE_TAG_NFS                0x80000014 /* Used by the Network File System (NFS) component. */
#define REPARSE_TAG_LX_SYMLINK         0xA000001D /* WSL symbolic link */
#define REPARSE_TAG_AF_UNIX            0x80000023 /* WSL unix socket */
#define REPARSE_TAG_LX_FIFO            0x80000024 /* WSL fifo pipe */
#define REPARSE_TAG_LX_CHR             0x80000025 /* WSL char device */
#define REPARSE_TAG_LX_BLK             0x80000026 /* WSL block device */
static const value_string reparse_tag_vals[] = {
	{ REPARSE_TAG_RESERVED_ZERO,   "REPARSE_TAG_RESERVED_ZERO"},
	{ REPARSE_TAG_RESERVED_ONE,    "REPARSE_TAG_RESERVED_ONE"},
	{ REPARSE_TAG_MOUNT_POINT,     "REPARSE_TAG_MOUNT_POINT"},
	{ REPARSE_TAG_HSM,             "REPARSE_TAG_HSM"},
	{ REPARSE_TAG_DRIVER_EXTENDER, "REPARSE_TAG_DRIVER_EXTENDER"},
	{ REPARSE_TAG_HSM2,            "REPARSE_TAG_HSM2"},
	{ REPARSE_TAG_SIS,             "REPARSE_TAG_SIS"},
	{ REPARSE_TAG_DFS,             "REPARSE_TAG_DFS"},
	{ REPARSE_TAG_FILTER_MANAGER,  "REPARSE_TAG_FILTER_MANAGER"},
	{ REPARSE_TAG_SYMLINK,         "REPARSE_TAG_SYMLINK"},
	{ REPARSE_TAG_DFSR,            "REPARSE_TAG_DFSR"},
	{ REPARSE_TAG_NFS,             "REPARSE_TAG_NFS"},
	{ REPARSE_TAG_LX_SYMLINK,      "REPARSE_TAG_LX_SYMLINK"},
	{ REPARSE_TAG_AF_UNIX,         "REPARSE_TAG_AF_UNIX"},
	{ REPARSE_TAG_LX_FIFO,         "REPARSE_TAG_LX_FIFO"},
	{ REPARSE_TAG_LX_CHR,          "REPARSE_TAG_LX_CHR"},
	{ REPARSE_TAG_LX_BLK,          "REPARSE_TAG_LX_BLK"},
	{ 0, NULL }
};

#define NFS_SPECFILE_LNK 0x00000000014B4E4C
#define NFS_SPECFILE_CHR 0x0000000000524843
#define NFS_SPECFILE_BLK 0x00000000004B4C42
#define NFS_SPECFILE_FIFO 0x000000004F464946
#define NFS_SPECFILE_SOCK 0x000000004B434F53
static const val64_string nfs_type_vals[] = {
	{ NFS_SPECFILE_LNK,  "Symbolic Link" },
	{ NFS_SPECFILE_CHR,  "Character Device" },
	{ NFS_SPECFILE_BLK,  "Block Device" },
	{ NFS_SPECFILE_FIFO, "FIFO" },
	{ NFS_SPECFILE_SOCK, "UNIX Socket" },
	{ 0, NULL }
};

#define SMB2_NUM_PROCEDURES     256
#define MAX_UNCOMPRESSED_SIZE (1<<24) /* 16MB */

#define SMB2_DIALECT_202  0x0202
#define SMB2_DIALECT_210  0x0210
#define SMB2_DIALECT_2FF  0x02FF
#define SMB2_DIALECT_222  0x0222
#define SMB2_DIALECT_224  0x0224
#define SMB2_DIALECT_300  0x0300
#define SMB2_DIALECT_302  0x0302
#define SMB2_DIALECT_310  0x0310
#define SMB2_DIALECT_311  0x0311

static const value_string smb2_dialect_vals[] = {
	{ SMB2_DIALECT_202, "SMB 2.0.2" },
	{ SMB2_DIALECT_210, "SMB 2.1" },
	{ SMB2_DIALECT_2FF, "SMB2 wildcard" },
	{ SMB2_DIALECT_222, "SMB 2.2.2 (deprecated; should be 3.0)" },
	{ SMB2_DIALECT_224, "SMB 2.2.4 (deprecated; should be 3.0)" },
	{ SMB2_DIALECT_300, "SMB 3.0" },
	{ SMB2_DIALECT_302, "SMB 3.0.2" },
	{ SMB2_DIALECT_310, "SMB 3.1.0 (deprecated; should be 3.1.1)" },
	{ SMB2_DIALECT_311, "SMB 3.1.1" },
	{ 0, NULL }
};

static int dissect_windows_sockaddr_storage(tvbuff_t *, packet_info *, proto_tree *, int, int);
static void dissect_smb2_error_data(tvbuff_t *, packet_info *, proto_tree *, int, int, smb2_info_t *);
static guint smb2_eo_files_hash(gconstpointer k);
static gint smb2_eo_files_equal(gconstpointer k1, gconstpointer k2);

static void update_preauth_hash(void *buf, packet_info *pinfo, tvbuff_t *tvb)
{
	gcry_error_t err;
	gcry_md_hd_t md;
	void *pkt;

	err = gcry_md_open(&md, GCRY_MD_SHA512, 0);
	if (err)
		return;

	/* we dup in case of non-contiguous packet */
	pkt = tvb_memdup(pinfo->pool, tvb, 0, tvb_captured_length(tvb));
	gcry_md_write(md, buf, SMB2_PREAUTH_HASH_SIZE);
	gcry_md_write(md, pkt, tvb_captured_length(tvb));
	gcry_md_final(md);
	memcpy(buf, gcry_md_read(md, 0), SMB2_PREAUTH_HASH_SIZE);
	gcry_md_close(md);
}

static void
smb2stat_init(struct register_srt* srt _U_, GArray* srt_array)
{
	srt_stat_table *smb2_srt_table;
	guint32 i;

	smb2_srt_table = init_srt_table("SMB2", NULL, srt_array, SMB2_NUM_PROCEDURES, "Commands", "smb2.cmd", NULL);
	for (i = 0; i < SMB2_NUM_PROCEDURES; i++)
	{
		init_srt_table_row(smb2_srt_table, i, val_to_str_ext_const(i, &smb2_cmd_vals_ext, "<unknown>"));
	}
}

static tap_packet_status
smb2stat_packet(void *pss, packet_info *pinfo, epan_dissect_t *edt _U_, const void *prv, tap_flags_t flags _U_)
{
	guint i = 0;
	srt_stat_table *smb2_srt_table;
	srt_data_t *data = (srt_data_t *)pss;
	const smb2_info_t *si=(const smb2_info_t *)prv;

	/* we are only interested in response packets */
	if(!(si->flags&SMB2_FLAGS_RESPONSE)){
		return TAP_PACKET_DONT_REDRAW;
	}
	/* We should not include cancel and oplock break requests either */
	if (si->opcode == SMB2_COM_CANCEL || si->opcode == SMB2_COM_BREAK) {
		return TAP_PACKET_DONT_REDRAW;
	}

	/* if we haven't seen the request, just ignore it */
	if(!si->saved){
		return TAP_PACKET_DONT_REDRAW;
	}

	/* SMB2 SRT can be very inaccurate in the presence of retransmissions. Retransmitted responses
	 * not only add additional (bogus) transactions but also the latency associated with them.
	 * This can greatly inflate the maximum and average SRT stats especially in the case of
	 * retransmissions triggered by the expiry of the rexmit timer (RTOs). Only calculating SRT
	 * for the last received response accomplishes this goal without requiring the TCP pref
	 * "Do not call subdissectors for error packets" to be set. */
	if ((si->saved->frame_req == 0) || (si->saved->frame_res != pinfo->num))
		return TAP_PACKET_DONT_REDRAW;

	smb2_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);
	add_srt_table_data(smb2_srt_table, si->opcode, &si->saved->req_time, pinfo);
	return TAP_PACKET_REDRAW;
}

/* Structure for SessionID <=> SessionKey mapping for decryption. */
typedef struct _smb2_seskey_field_t {
	/* session id */
	guchar *id;		/* *little-endian* - not necessarily host-endian! */
	guint id_len;
	/* session key */
	guchar *seskey;
	guint seskey_len;
	/* server to client key */
	guchar *s2ckey;
	guint s2ckey_len;
	/* client to server key */
	guchar *c2skey;
	guint c2skey_len;
} smb2_seskey_field_t;

static smb2_seskey_field_t *seskey_list = NULL;
static guint num_seskey_list = 0;

static const gint8 zeros[NTLMSSP_KEY_LEN] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

/* Callbacks for SessionID <=> SessionKey mapping. */
UAT_BUFFER_CB_DEF(seskey_list, id, smb2_seskey_field_t, id, id_len)
UAT_BUFFER_CB_DEF(seskey_list, seskey, smb2_seskey_field_t, seskey, seskey_len)
UAT_BUFFER_CB_DEF(seskey_list, s2ckey, smb2_seskey_field_t, s2ckey, s2ckey_len)
UAT_BUFFER_CB_DEF(seskey_list, c2skey, smb2_seskey_field_t, c2skey, c2skey_len)

#define SMB_SESSION_ID_SIZE 8

static gboolean seskey_list_update_cb(void *r, char **err)
{
	smb2_seskey_field_t *rec = (smb2_seskey_field_t *)r;
	gboolean has_seskey = rec->seskey_len != 0;
	gboolean has_s2ckey = rec->s2ckey_len != 0;
	gboolean has_c2skey = rec->c2skey_len != 0;

	*err = NULL;

	if (rec->id_len != SMB_SESSION_ID_SIZE) {
		*err = g_strdup("Session ID must be " G_STRINGIFY(SMB_SESSION_ID_SIZE) " bytes long and in hexadecimal");
		return FALSE;
	}

	if (!has_seskey && !(has_c2skey || has_s2ckey)) {
		*err = g_strdup("Decryption requires either the Session Key or at least one of the client-server AES keys");
		return FALSE;
	}


	if (rec->seskey_len > NTLMSSP_KEY_LEN) {
		*err = g_strdup("Session Key must be a hexadecimal string representing at most " G_STRINGIFY(NTLMSSP_KEY_LEN) " bytes");
		return FALSE;
	}

	if (has_s2ckey && ((rec->s2ckey_len != AES_KEY_SIZE) && (rec->s2ckey_len != AES_KEY_SIZE*2))) {
		*err = g_strdup("Server-to-Client key must be a hexadecimal string representing "
				G_STRINGIFY(AES_KEY_SIZE) " or " G_STRINGIFY(AES_KEY_SIZE*2));
		return FALSE;
	}

	if (has_c2skey && ((rec->c2skey_len != AES_KEY_SIZE) && (rec->c2skey_len != AES_KEY_SIZE*2))) {
		*err = g_strdup("Client-to-Server key must be a hexadecimal string representing "
				G_STRINGIFY(AES_KEY_SIZE) " or " G_STRINGIFY(AES_KEY_SIZE*2));
		return FALSE;
	}

	return TRUE;
}

static void* seskey_list_copy_cb(void *n, const void *o, size_t siz _U_)
{
	smb2_seskey_field_t *new_rec = (smb2_seskey_field_t *)n;
	const smb2_seskey_field_t *old_rec = (const smb2_seskey_field_t *)o;

	new_rec->id_len = old_rec->id_len;
	new_rec->id = old_rec->id ? (guchar *)g_memdup2(old_rec->id, old_rec->id_len) : NULL;
	new_rec->seskey_len = old_rec->seskey_len;
	new_rec->seskey = old_rec->seskey ? (guchar *)g_memdup2(old_rec->seskey, old_rec->seskey_len) : NULL;
	new_rec->s2ckey_len = old_rec->s2ckey_len;
	new_rec->s2ckey = old_rec->s2ckey ? (guchar *)g_memdup2(old_rec->s2ckey, old_rec->s2ckey_len) : NULL;
	new_rec->c2skey_len = old_rec->c2skey_len;
	new_rec->c2skey = old_rec->c2skey ? (guchar *)g_memdup2(old_rec->c2skey, old_rec->c2skey_len) : NULL;

	return new_rec;
}

static void seskey_list_free_cb(void *r)
{
	smb2_seskey_field_t *rec = (smb2_seskey_field_t *)r;

	g_free(rec->id);
	g_free(rec->seskey);
	g_free(rec->s2ckey);
	g_free(rec->c2skey);
}

static gboolean seskey_find_sid_key(guint64 sesid, guint8 *out_seskey,
				    guint8 *out_s2ckey16,
				    guint8 *out_c2skey16,
				    guint8 *out_s2ckey32,
				    guint8 *out_c2skey32)
{
	guint i;
	guint64 sesid_le;

	/*
	 * The session IDs in the UAT are octet arrays, in little-endian
	 * byte order (as it appears on the wire); they have been
	 * checked to make sure they're 8 bytes (SMB_SESSION_ID_SIZE)
	 * long.  They're *probably* aligned on an appropriate boundary,
	 * but let's not assume that - let's just use memcmp().
	 *
	 * The session ID passed to us, however, is in *host* byte order.
	 * This is *NOT* necessarily little-endian; it's big-endian on,
	 * for example, System/390 and z/Architecture ("s390" and "s390x"
	 * in Linuxland), SPARC, and most PowerPC systems.  We must,
	 * therefore, put it into little-endian byte order before
	 * comparing it with the IDs in the UAT values.
	 */
	sesid_le = GUINT64_TO_LE(sesid);

	for (i = 0; i < num_seskey_list; i++) {
		const smb2_seskey_field_t *p = &seskey_list[i];
		if (memcmp(&sesid_le, p->id, SMB_SESSION_ID_SIZE) == 0) {
			memset(out_seskey, 0, NTLMSSP_KEY_LEN);
			memset(out_s2ckey16, 0, AES_KEY_SIZE);
			memset(out_c2skey16, 0, AES_KEY_SIZE);
			memset(out_s2ckey32, 0, AES_KEY_SIZE*2);
			memset(out_c2skey32, 0, AES_KEY_SIZE*2);

			if (p->seskey_len != 0)
				memcpy(out_seskey, p->seskey, p->seskey_len);
			if (p->s2ckey_len == AES_KEY_SIZE)
				memcpy(out_s2ckey16, p->s2ckey, p->s2ckey_len);
			if (p->s2ckey_len == AES_KEY_SIZE*2)
				memcpy(out_s2ckey32, p->s2ckey, p->s2ckey_len);
			if (p->c2skey_len == AES_KEY_SIZE)
				memcpy(out_c2skey16, p->c2skey, p->c2skey_len);
			if (p->c2skey_len == AES_KEY_SIZE*2)
				memcpy(out_c2skey32, p->c2skey, p->c2skey_len);

			return TRUE;
		}
	}

	return FALSE;
}

/* ExportObject preferences variable */
gboolean eosmb2_take_name_as_fid = FALSE ;

/* unmatched smb_saved_info structures.
   For unmatched smb_saved_info structures we store the smb_saved_info
   structure using the msg_id field.
*/
static gint
smb2_saved_info_equal_unmatched(gconstpointer k1, gconstpointer k2)
{
	const smb2_saved_info_t *key1 = (const smb2_saved_info_t *)k1;
	const smb2_saved_info_t *key2 = (const smb2_saved_info_t *)k2;
	return key1->msg_id == key2->msg_id;
}
static guint
smb2_saved_info_hash_unmatched(gconstpointer k)
{
	const smb2_saved_info_t *key = (const smb2_saved_info_t *)k;
	guint32 hash;

	hash = (guint32) (key->msg_id&0xffffffff);
	return hash;
}

/* matched smb_saved_info structures.
   For matched smb_saved_info structures we store the smb_saved_info
   structure using the msg_id field.
*/
static gint
smb2_saved_info_equal_matched(gconstpointer k1, gconstpointer k2)
{
	const smb2_saved_info_t *key1 = (const smb2_saved_info_t *)k1;
	const smb2_saved_info_t *key2 = (const smb2_saved_info_t *)k2;
	return key1->msg_id == key2->msg_id;
}
static guint
smb2_saved_info_hash_matched(gconstpointer k)
{
	const smb2_saved_info_t *key = (const smb2_saved_info_t *)k;
	guint32 hash;

	hash = (guint32) (key->msg_id&0xffffffff);
	return hash;
}

/* For Tids of a specific conversation.
   This keeps track of tid->sharename mappings and other information about the
   tid.
   qqq
   We might need to refine this if it occurs that tids are reused on a single
   conversation.   we don't worry about that yet for simplicity
*/
static gint
smb2_tid_info_equal(gconstpointer k1, gconstpointer k2)
{
	const smb2_tid_info_t *key1 = (const smb2_tid_info_t *)k1;
	const smb2_tid_info_t *key2 = (const smb2_tid_info_t *)k2;
	return key1->tid == key2->tid;
}
static guint
smb2_tid_info_hash(gconstpointer k)
{
	const smb2_tid_info_t *key = (const smb2_tid_info_t *)k;
	guint32 hash;

	hash = key->tid;
	return hash;
}

/* For Uids of a specific conversation.
   This keeps track of uid->acct_name mappings and other information about the
   uid.
   qqq
   We might need to refine this if it occurs that uids are reused on a single
   conversation.   we don't worry about that yet for simplicity
*/
static gint
smb2_sesid_info_equal(gconstpointer k1, gconstpointer k2)
{
	const smb2_sesid_info_t *key1 = (const smb2_sesid_info_t *)k1;
	const smb2_sesid_info_t *key2 = (const smb2_sesid_info_t *)k2;
	return key1->sesid == key2->sesid;
}
static guint
smb2_sesid_info_hash(gconstpointer k)
{
	const smb2_sesid_info_t *key = (const smb2_sesid_info_t *)k;
	guint32 hash;

	hash = (guint32)( ((key->sesid>>32)&0xffffffff)+((key->sesid)&0xffffffff) );
	return hash;
}

/*
 * For File IDs of a specific conversation.
 * This keeps track of fid to name mapping and application level conversations
 * over named pipes.
 *
 * This handles implementation bugs, where the fid_persitent is 0 or
 * the fid_persitent/fid_volative is not unique per conversation.
 */
static gint
smb2_fid_info_equal(gconstpointer k1, gconstpointer k2)
{
	const smb2_fid_info_t *key = (const smb2_fid_info_t *)k1;
	const smb2_fid_info_t *val = (const smb2_fid_info_t *)k2;

	if (!key->frame_key) {
		key = (const smb2_fid_info_t *)k2;
		val = (const smb2_fid_info_t *)k1;
	}

	if (key->fid_persistent != val->fid_persistent) {
		return 0;
	}

	if (key->fid_volatile != val->fid_volatile) {
		return 0;
	}

	if (key->sesid != val->sesid) {
		return 0;
	}

	if (key->tid != val->tid) {
		return 0;
	}

	if (!(val->frame_beg <= key->frame_key && key->frame_key <= val->frame_end)) {
		return 0;
	}

	return 1;
}

static guint
smb2_fid_info_hash(gconstpointer k)
{
	const smb2_fid_info_t *key = (const smb2_fid_info_t *)k;
	guint32 hash;

	if (key->fid_persistent != 0) {
		hash = (guint32)( ((key->fid_persistent>>32)&0xffffffff)+((key->fid_persistent)&0xffffffff) );
	} else {
		hash = (guint32)( ((key->fid_volatile>>32)&0xffffffff)+((key->fid_volatile)&0xffffffff) );
	}

	return hash;
}

/* Callback for destroying the glib hash tables associated with a conversation
 * struct. */
static gboolean
smb2_conv_destroy(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_,
	          void *user_data)
{
	smb2_conv_info_t *conv = (smb2_conv_info_t *)user_data;

	g_hash_table_destroy(conv->matched);
	g_hash_table_destroy(conv->unmatched);

	/* This conversation is gone, return FALSE to indicate we don't
	 * want to be called again for this conversation. */
	return FALSE;
}

static smb2_sesid_info_t *
smb2_get_session(smb2_conv_info_t *conv _U_, guint64 id, packet_info *pinfo, smb2_info_t *si)
{
	smb2_sesid_info_t key = {.sesid = id};
	smb2_sesid_info_t *ses = (smb2_sesid_info_t *)wmem_map_lookup(smb2_sessions, &key);

	if (!ses) {
		ses = wmem_new0(wmem_file_scope(), smb2_sesid_info_t);
		ses->sesid = id;
		ses->auth_frame = (guint32)-1;
		ses->tids = wmem_map_new(wmem_file_scope(), smb2_tid_info_hash, smb2_tid_info_equal);
		ses->fids = wmem_map_new(wmem_file_scope(), smb2_fid_info_hash, smb2_fid_info_equal);
		ses->files = wmem_map_new(wmem_file_scope(), smb2_eo_files_hash, smb2_eo_files_equal);

		seskey_find_sid_key(id, ses->session_key,
				    ses->client_decryption_key16,
				    ses->server_decryption_key16,
				    ses->client_decryption_key32,
				    ses->server_decryption_key32);
		if (pinfo && si) {
			if (si->flags & SMB2_FLAGS_RESPONSE) {
				ses->server_port = pinfo->srcport;
			} else {
				ses->server_port = pinfo->destport;
			}
		}
		wmem_map_insert(smb2_sessions, ses, ses);
	}

	return ses;
}

static void
smb2_add_session_info(proto_tree *ses_tree, proto_item *ses_item, tvbuff_t *tvb, gint start, smb2_sesid_info_t *ses)
{
	proto_item  *new_item;
	if (!ses)
		return;

	if (ses->acct_name) {
		new_item = proto_tree_add_string(ses_tree, hf_smb2_acct_name, tvb, start, 0, ses->acct_name);
		proto_item_set_generated(new_item);
		proto_item_append_text(ses_item, " Acct:%s", ses->acct_name);
	}

	if (ses->domain_name) {
		new_item = proto_tree_add_string(ses_tree, hf_smb2_domain_name, tvb, start, 0, ses->domain_name);
		proto_item_set_generated(new_item);
		proto_item_append_text(ses_item, " Domain:%s", ses->domain_name);
	}

	if (ses->host_name) {
		new_item = proto_tree_add_string(ses_tree, hf_smb2_host_name, tvb, start, 0, ses->host_name);
		proto_item_set_generated(new_item);
		proto_item_append_text(ses_item, " Host:%s", ses->host_name);
	}

	if (ses->auth_frame != (guint32)-1) {
		new_item = proto_tree_add_uint(ses_tree, hf_smb2_auth_frame, tvb, start, 0, ses->auth_frame);
		proto_item_set_generated(new_item);
	}
}

static void smb2_key_derivation(const guint8 *KI, guint32 KI_len,
			 const guint8 *Label, guint32 Label_len,
			 const guint8 *Context, guint32 Context_len,
			 guint8 KO[16], guint32 KO_len)
{
	gcry_md_hd_t  hd     = NULL;
	guint8        buf[4];
	guint8       *digest = NULL;
	guint32       L;

	/*
	 * a simplified version of
	 * "NIST Special Publication 800-108" section 5.1
	 * using hmac-sha256.
	 */
	gcry_md_open(&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
	gcry_md_setkey(hd, KI, KI_len);

	memset(buf, 0, sizeof(buf));
	buf[3] = 1;
	gcry_md_write(hd, buf, sizeof(buf));
	gcry_md_write(hd, Label, Label_len);
	gcry_md_write(hd, buf, 1);
	gcry_md_write(hd, Context, Context_len);
	L = KO_len * 8;
	memset(buf, 0, sizeof(buf));
	buf[3] = ((L) >> (0)) & 0xff;
	buf[2] = ((L) >> (8)) & 0xff;
	gcry_md_write(hd, buf, sizeof(buf));

	digest = gcry_md_read(hd, GCRY_MD_SHA256);

	memcpy(KO, digest, KO_len);

	gcry_md_close(hd);
}

/* for export-object-smb2 */
static gchar *policy_hnd_to_file_id(wmem_allocator_t *pool, const e_ctx_hnd *hnd) {
	return guid_to_str(pool, &hnd->uuid);
}
static guint smb2_eo_files_hash(gconstpointer k) {
	return g_str_hash(policy_hnd_to_file_id(wmem_packet_scope(), (const e_ctx_hnd *)k));
}
static gint smb2_eo_files_equal(gconstpointer k1, gconstpointer k2) {
int	are_equal;
	const e_ctx_hnd *key1 = (const e_ctx_hnd *)k1;
	const e_ctx_hnd *key2 = (const e_ctx_hnd *)k2;

	are_equal = (key1->uuid.data1==key2->uuid.data1 &&
		key1->uuid.data2==key2->uuid.data2 &&
		key1->uuid.data3==key2->uuid.data3 &&
		key1->uuid.data4[0]==key2->uuid.data4[0] &&
		key1->uuid.data4[1]==key2->uuid.data4[1] &&
		key1->uuid.data4[2]==key2->uuid.data4[2] &&
		key1->uuid.data4[3]==key2->uuid.data4[3] &&
		key1->uuid.data4[4]==key2->uuid.data4[4] &&
		key1->uuid.data4[5]==key2->uuid.data4[5] &&
		key1->uuid.data4[6]==key2->uuid.data4[6] &&
		key1->uuid.data4[7]==key2->uuid.data4[7]);

	return are_equal;
}

static void
feed_eo_smb2(tvbuff_t * tvb,packet_info *pinfo,smb2_info_t * si, guint16 dataoffset,guint32 length, guint64 file_offset) {

	char       *fid_name = NULL;
	guint32     open_frame = 0, close_frame = 0;
	tvbuff_t        *data_tvb = NULL;
	smb_eo_t        *eo_info;
	gchar           *file_id;
	gchar		*auxstring;
	gchar		**aux_string_v;

	/* Create a new tvb to point to the payload data */
	data_tvb = tvb_new_subset_length(tvb, dataoffset, length);
	/* Create the eo_info to pass to the listener */
	eo_info = wmem_new(pinfo->pool, smb_eo_t);
	/* Fill in eo_info */
	eo_info->smbversion=2;
	/* cmd == opcode */
	eo_info->cmd=si->opcode;
	/* We don't keep track of uid in SMB v2 */
	eo_info->uid=0;

	/* Try to get file id and filename */
	file_id=policy_hnd_to_file_id(pinfo->pool, &si->saved->policy_hnd);
	dcerpc_fetch_polhnd_data(&si->saved->policy_hnd, &fid_name, NULL, &open_frame, &close_frame, pinfo->num);
	if (fid_name && g_strcmp0(fid_name,"File: ")!=0) {
		auxstring=fid_name;
		/* Remove "File: " from filename */
		if (g_str_has_prefix(auxstring, "File: ")) {
			aux_string_v = g_strsplit(auxstring, "File: ", -1);
			eo_info->filename = wmem_strdup_printf(pinfo->pool, "\\%s",aux_string_v[g_strv_length(aux_string_v)-1]);
			g_strfreev(aux_string_v);
		} else {
			if (g_str_has_prefix(auxstring, "\\")) {
				eo_info->filename = wmem_strdup(pinfo->pool, auxstring);
			} else {
				eo_info->filename = wmem_strdup_printf(pinfo->pool, "\\%s",auxstring);
			}
		}
	} else {
		auxstring=wmem_strdup_printf(pinfo->pool, "File_Id_%s", file_id);
		eo_info->filename=auxstring;
	}



	if (eosmb2_take_name_as_fid) {
		eo_info->fid = g_str_hash(eo_info->filename);
	} else {
		eo_info->fid = g_str_hash(file_id);
	}

	/* tid, hostname, tree_id */
	if (si->tree) {
		eo_info->tid=si->tree->tid;
		if (strlen(si->tree->name)>0 && strlen(si->tree->name)<=256) {
			eo_info->hostname = wmem_strdup(pinfo->pool, si->tree->name);
		} else {
			eo_info->hostname = wmem_strdup_printf(pinfo->pool, "\\\\%s\\TREEID_%i",tree_ip_str(pinfo,si->opcode),si->tree->tid);
		}
	} else {
		eo_info->tid=0;
		eo_info->hostname = wmem_strdup_printf(pinfo->pool, "\\\\%s\\TREEID_UNKNOWN",tree_ip_str(pinfo,si->opcode));
	}

	/* packet number */
	eo_info->pkt_num = pinfo->num;

	/* fid type */
	if (si->eo_file_info->attr_mask & SMB2_FLAGS_ATTR_DIRECTORY) {
		eo_info->fid_type=SMB2_FID_TYPE_DIR;
	} else {
		if (si->eo_file_info->attr_mask &
			(SMB2_FLAGS_ATTR_ARCHIVE | SMB2_FLAGS_ATTR_NORMAL |
			 SMB2_FLAGS_ATTR_HIDDEN | SMB2_FLAGS_ATTR_READONLY |
			 SMB2_FLAGS_ATTR_SYSTEM) ) {
			eo_info->fid_type=SMB2_FID_TYPE_FILE;
		} else {
			eo_info->fid_type=SMB2_FID_TYPE_OTHER;
		}
	}

	/* end_of_file */
	eo_info->end_of_file=si->eo_file_info->end_of_file;

	/* data offset and chunk length */
	eo_info->smb_file_offset=file_offset;
	eo_info->smb_chunk_len=length;
	/* XXX is this right? */
	if (length<si->saved->bytes_moved) {
		si->saved->file_offset=si->saved->file_offset+length;
		si->saved->bytes_moved=si->saved->bytes_moved-length;
	}

	/* Payload */
	eo_info->payload_len = length;
	eo_info->payload_data = tvb_get_ptr(data_tvb, 0, length);

	tap_queue_packet(smb2_eo_tap, pinfo, eo_info);

}

static int dissect_smb2_file_full_ea_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset, smb2_info_t *si);


/* This is a helper to dissect the common string type
 * uint16 offset
 * uint16 length
 * ...
 * char *string
 *
 * This function is called twice, first to decode the offset/length and
 * second time to dissect the actual string.
 * It is done this way since there is no guarantee that we have the full packet and we don't
 * want to abort dissection too early if the packet ends somewhere between the
 * length/offset and the actual buffer.
 *
 */
enum offset_length_buffer_offset_size {
	OLB_O_UINT16_S_UINT16,
	OLB_O_UINT16_S_UINT32,
	OLB_O_UINT8_P_UINT8_S_UINT32,
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
	olb->hfindex = hfindex;
	olb->offset_size = offset_size;
	switch (offset_size) {
	case OLB_O_UINT16_S_UINT16:
		olb->off = tvb_get_letohs(tvb, offset);
		olb->off_offset = offset;
		offset += 2;
		olb->len = tvb_get_letohs(tvb, offset);
		olb->len_offset = offset;
		offset += 2;
		break;
	case OLB_O_UINT16_S_UINT32:
		olb->off = tvb_get_letohs(tvb, offset);
		olb->off_offset = offset;
		offset += 2;
		olb->len = tvb_get_letohl(tvb, offset);
		olb->len_offset = offset;
		offset += 4;
		break;
	case OLB_O_UINT8_P_UINT8_S_UINT32:
		olb->off = tvb_get_guint8(tvb, offset);
		olb->off_offset = offset;
		offset += 1;
		/* 1 byte reserved */
		offset += 1;
		olb->len = tvb_get_letohl(tvb, offset);
		olb->len_offset = offset;
		offset += 4;
		break;
	case OLB_O_UINT32_S_UINT32:
		olb->off = tvb_get_letohl(tvb, offset);
		olb->off_offset = offset;
		offset += 4;
		olb->len = tvb_get_letohl(tvb, offset);
		olb->len_offset = offset;
		offset += 4;
		break;
	case OLB_S_UINT32_O_UINT32:
		olb->len = tvb_get_letohl(tvb, offset);
		olb->len_offset = offset;
		offset += 4;
		olb->off = tvb_get_letohl(tvb, offset);
		olb->off_offset = offset;
		offset += 4;
		break;
	}

	return offset;
}

#define OLB_TYPE_UNICODE_STRING		0x01
#define OLB_TYPE_ASCII_STRING		0x02
static const guint8 *
dissect_smb2_olb_off_string(packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, offset_length_buffer_t *olb, int base, int type)
{
	int           len, off;
	proto_item   *item = NULL;
	proto_tree   *tree = NULL;
	const guint8 *name = NULL;

	olb->off += base;

	len = olb->len;
	off = olb->off;


	/* sanity check */
	tvb_ensure_bytes_exist(tvb, off, len);
	if (((off+len)<off)
	|| ((off+len)>(off+tvb_reported_length_remaining(tvb, off)))) {
		proto_tree_add_expert_format(tree, pinfo, &ei_smb2_invalid_length, tvb, off, -1,
				    "Invalid offset/length. Malformed packet");

		col_append_str(pinfo->cinfo, COL_INFO, " [Malformed packet]");

		return NULL;
	}


	switch (type) {
	case OLB_TYPE_UNICODE_STRING:
		item = proto_tree_add_item_ret_string(parent_tree,
		    olb->hfindex, tvb, off, len, ENC_UTF_16|ENC_LITTLE_ENDIAN,
		    pinfo->pool, &name);
		tree = proto_item_add_subtree(item, ett_smb2_olb);
		break;
	case OLB_TYPE_ASCII_STRING:
		item = proto_tree_add_item_ret_string(parent_tree,
		    olb->hfindex, tvb, off, len, ENC_ASCII|ENC_NA,
		    pinfo->pool, &name);
		tree = proto_item_add_subtree(item, ett_smb2_olb);
		break;
	}

	switch (olb->offset_size) {
	case OLB_O_UINT16_S_UINT16:
		proto_tree_add_item(tree, hf_smb2_olb_offset, tvb, olb->off_offset, 2, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_smb2_olb_length, tvb, olb->len_offset, 2, ENC_LITTLE_ENDIAN);
		break;
	case OLB_O_UINT16_S_UINT32:
		proto_tree_add_item(tree, hf_smb2_olb_offset, tvb, olb->off_offset, 2, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_smb2_olb_length, tvb, olb->len_offset, 4, ENC_LITTLE_ENDIAN);
		break;
	case OLB_O_UINT8_P_UINT8_S_UINT32:
		proto_tree_add_item(tree, hf_smb2_olb_offset, tvb, olb->off_offset, 1, ENC_NA);
		proto_tree_add_item(tree, hf_smb2_reserved, tvb, olb->off_offset+1, 1, ENC_NA);
		proto_tree_add_item(tree, hf_smb2_olb_length, tvb, olb->len_offset, 4, ENC_LITTLE_ENDIAN);
		break;
	case OLB_O_UINT32_S_UINT32:
		proto_tree_add_item(tree, hf_smb2_olb_offset, tvb, olb->off_offset, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_smb2_olb_length, tvb, olb->len_offset, 4, ENC_LITTLE_ENDIAN);
		break;
	case OLB_S_UINT32_O_UINT32:
		proto_tree_add_item(tree, hf_smb2_olb_length, tvb, olb->len_offset, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_smb2_olb_offset, tvb, olb->off_offset, 4, ENC_LITTLE_ENDIAN);
		break;
	}

	return name;
}

static const guint8 *
dissect_smb2_olb_string(packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, offset_length_buffer_t *olb, int type)
{
	return dissect_smb2_olb_off_string(pinfo, parent_tree, tvb, olb, 0, type);
}

static void
dissect_smb2_olb_buffer(packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb,
			offset_length_buffer_t *olb, smb2_info_t *si,
			void (*dissector)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si))
{
	int         len, off;
	proto_item *sub_item = NULL;
	proto_tree *sub_tree = NULL;
	tvbuff_t   *sub_tvb  = NULL;
	int         offset;

	offset = olb->off;
	len    = olb->len;
	off    = olb->off;

	/* sanity check */
	tvb_ensure_bytes_exist(tvb, off, len);
	if (((off+len)<off)
	    || ((off+len)>(off+tvb_reported_length_remaining(tvb, off)))) {
		proto_tree_add_expert_format(parent_tree, pinfo, &ei_smb2_invalid_length, tvb, offset, -1,
				    "Invalid offset/length. Malformed packet");

		col_append_str(pinfo->cinfo, COL_INFO, " [Malformed packet]");

		return;
	}

	switch (olb->offset_size) {
	case OLB_O_UINT16_S_UINT16:
		proto_tree_add_item(parent_tree, hf_smb2_olb_offset, tvb, olb->off_offset, 2, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(parent_tree, hf_smb2_olb_length, tvb, olb->len_offset, 2, ENC_LITTLE_ENDIAN);
		break;
	case OLB_O_UINT16_S_UINT32:
		proto_tree_add_item(parent_tree, hf_smb2_olb_offset, tvb, olb->off_offset, 2, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(parent_tree, hf_smb2_olb_length, tvb, olb->len_offset, 4, ENC_LITTLE_ENDIAN);
		break;
	case OLB_O_UINT8_P_UINT8_S_UINT32:
		proto_tree_add_item(parent_tree, hf_smb2_olb_offset, tvb, olb->off_offset, 1, ENC_NA);
		proto_tree_add_item(parent_tree, hf_smb2_reserved, tvb, olb->off_offset+1, 1, ENC_NA);
		proto_tree_add_item(parent_tree, hf_smb2_olb_length, tvb, olb->len_offset, 4, ENC_LITTLE_ENDIAN);
		break;
	case OLB_O_UINT32_S_UINT32:
		proto_tree_add_item(parent_tree, hf_smb2_olb_offset, tvb, olb->off_offset, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(parent_tree, hf_smb2_olb_length, tvb, olb->len_offset, 4, ENC_LITTLE_ENDIAN);
		break;
	case OLB_S_UINT32_O_UINT32:
		proto_tree_add_item(parent_tree, hf_smb2_olb_length, tvb, olb->len_offset, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(parent_tree, hf_smb2_olb_offset, tvb, olb->off_offset, 4, ENC_LITTLE_ENDIAN);
		break;
	}

	/* if we don't want/need a subtree */
	if (olb->hfindex == -1) {
		sub_item = parent_tree;
		sub_tree = parent_tree;
	} else {
		if (parent_tree) {
			sub_item = proto_tree_add_item(parent_tree, olb->hfindex, tvb, offset, len, ENC_NA);
			sub_tree = proto_item_add_subtree(sub_item, ett_smb2_olb);
		}
	}

	if (off == 0 || len == 0) {
		proto_item_append_text(sub_item, ": NO DATA");
		return;
	}

	if (!dissector) {
		return;
	}

	sub_tvb = tvb_new_subset_length_caplen(tvb, off, MIN((int)len, tvb_captured_length_remaining(tvb, off)), len);

	dissector(sub_tvb, pinfo, sub_tree, si);
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
	int (*request) (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si);
	int (*response)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si);
} smb2_function;

static const true_false_string tfs_smb2_svhdx_has_initiator_id = {
	"Has an initiator id",
	"Does not have an initiator id"
};

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
	"This pdu is a CHAINED command",
	"This pdu is NOT a chained command"
};

static const true_false_string tfs_flags_signature = {
	"This pdu is SIGNED",
	"This pdu is NOT signed"
};

static const true_false_string tfs_flags_replay_operation = {
	"This is a REPLAY OPERATION",
	"This is NOT a replay operation"
};

static const true_false_string tfs_flags_priority_mask = {
	"This pdu contains a PRIORITY",
	"This pdu does NOT contain a PRIORITY"
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

static const true_false_string tfs_cap_encryption = {
	"This host supports ENCRYPTION",
	"This host does NOT support ENCRYPTION"
};

static const true_false_string tfs_smb2_ioctl_network_interface_capability_rss = {
	"This interface supports RSS",
	"This interface does not support RSS"
};

static const true_false_string tfs_smb2_ioctl_network_interface_capability_rdma = {
	"This interface supports RDMA",
	"This interface does not support RDMA"
};

static const value_string file_region_usage_vals[] = {
	{ 0x00000001, "FILE_REGION_USAGE_VALID_CACHED_DATA" },
	{ 0, NULL }
};

static const value_string originator_flags_vals[] = {
	{ 1, "SVHDX_ORIGINATOR_PVHDPARSER" },
	{ 4, "SVHDX_ORIGINATOR_VHDMP" },
	{ 0, NULL }
};

static const value_string compression_format_vals[] = {
	{ 0, "COMPRESSION_FORMAT_NONE" },
	{ 1, "COMPRESSION_FORMAT_DEFAULT" },
	{ 2, "COMPRESSION_FORMAT_LZNT1" },
	{ 0, NULL }
};

static const value_string checksum_algorithm_vals[] = {
	{ 0x0000, "CHECKSUM_TYPE_NONE" },
	{ 0x0002, "CHECKSUM_TYPE_CRC64" },
	{ 0xFFFF, "CHECKSUM_TYPE_UNCHANGED" },
	{ 0, NULL }
};

/* Note: All uncommented are "dissector not implemented" */
static const value_string smb2_ioctl_vals[] = {
	{0x00060194, "FSCTL_DFS_GET_REFERRALS"},		      /* dissector implemented */
	{0x000601B0, "FSCTL_DFS_GET_REFERRALS_EX"},
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
	{0x0009003C, "FSCTL_GET_COMPRESSION"},			      /* dissector implemented */
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
	{0x0009009C, "FSCTL_GET_OBJECT_ID"},			      /* dissector implemented */
	{0x000900A4, "FSCTL_SET_REPARSE_POINT"}, 		      /* dissector implemented */
	{0x000900A8, "FSCTL_GET_REPARSE_POINT"}, 		      /* dissector implemented */
	{0x000900C0, "FSCTL_CREATE_OR_GET_OBJECT_ID"},		      /* dissector implemented */
	{0x000900C4, "FSCTL_SET_SPARSE"},			      /* dissector implemented */
	{0x000900D4, "FSCTL_SET_ENCRYPTION"},
	{0x000900DB, "FSCTL_ENCRYPTION_FSCTL_IO"},
	{0x000900DF, "FSCTL_WRITE_RAW_ENCRYPTED"},
	{0x000900E3, "FSCTL_READ_RAW_ENCRYPTED"},
	{0x000900F0, "FSCTL_EXTEND_VOLUME"},
	{0x00090244, "FSCTL_CSV_TUNNEL_REQUEST"},
	{0x0009027C, "FSCTL_GET_INTEGRITY_INFORMATION"},
	{0x00090284, "FSCTL_QUERY_FILE_REGIONS"},                     /* dissector implemented */
	{0x000902c8, "FSCTL_CSV_SYNC_TUNNEL_REQUEST"},
	{0x00090300, "FSCTL_QUERY_SHARED_VIRTUAL_DISK_SUPPORT"},      /* dissector implemented */
	{0x00090304, "FSCTL_SVHDX_SYNC_TUNNEL_REQUEST"},              /* dissector implemented */
	{0x00090308, "FSCTL_SVHDX_SET_INITIATOR_INFORMATION"},
	{0x0009030C, "FSCTL_SET_EXTERNAL_BACKING"},
	{0x00090310, "FSCTL_GET_EXTERNAL_BACKING"},
	{0x00090314, "FSCTL_DELETE_EXTERNAL_BACKING"},
	{0x00090318, "FSCTL_ENUM_EXTERNAL_BACKING"},
	{0x0009031F, "FSCTL_ENUM_OVERLAY"},
	{0x00090350, "FSCTL_STORAGE_QOS_CONTROL"},                    /* dissector implemented */
	{0x00090364, "FSCTL_SVHDX_ASYNC_TUNNEL_REQUEST"},             /* dissector implemented */
	{0x000940B3, "FSCTL_ENUM_USN_DATA"},
	{0x000940B7, "FSCTL_SECURITY_ID_CHECK"},
	{0x000940BB, "FSCTL_READ_USN_JOURNAL"},
	{0x000940CF, "FSCTL_QUERY_ALLOCATED_RANGES"},		      /* dissector implemented */
	{0x000940E7, "FSCTL_CREATE_USN_JOURNAL"},
	{0x000940EB, "FSCTL_READ_FILE_USN_DATA"},
	{0x000940EF, "FSCTL_WRITE_USN_CLOSE_RECORD"},
	{0x00094264, "FSCTL_OFFLOAD_READ"},			      /* dissector implemented */
	{0x00098098, "FSCTL_SET_OBJECT_ID"},			      /* dissector implemented */
	{0x000980A0, "FSCTL_DELETE_OBJECT_ID"}, /* no data in/out */
	{0x000980A4, "FSCTL_SET_REPARSE_POINT"},
	{0x000980AC, "FSCTL_DELETE_REPARSE_POINT"},
	{0x000980BC, "FSCTL_SET_OBJECT_ID_EXTENDED"},		      /* dissector implemented */
	{0x000980C8, "FSCTL_SET_ZERO_DATA"},			      /* dissector implemented */
	{0x000980D0, "FSCTL_ENABLE_UPGRADE"},
	{0x00098208, "FSCTL_FILE_LEVEL_TRIM"},
	{0x00098268, "FSCTL_OFFLOAD_WRITE"},			      /* dissector implemented */
	{0x0009C040, "FSCTL_SET_COMPRESSION"},			      /* dissector implemented */
	{0x0009C280, "FSCTL_SET_INTEGRITY_INFORMATION"},	      /* dissector implemented */
	{0x00110018, "FSCTL_PIPE_WAIT"},			      /* dissector implemented */
	{0x0011400C, "FSCTL_PIPE_PEEK"},
	{0x0011C017, "FSCTL_PIPE_TRANSCEIVE"},			      /* dissector implemented */
	{0x00140078, "FSCTL_SRV_REQUEST_RESUME_KEY"},
	{0x001401D4, "FSCTL_LMR_REQUEST_RESILIENCY"},		      /* dissector implemented */
	{0x001401FC, "FSCTL_QUERY_NETWORK_INTERFACE_INFO"},	      /* dissector implemented */
	{0x00140200, "FSCTL_VALIDATE_NEGOTIATE_INFO_224"},	      /* dissector implemented */
	{0x00140204, "FSCTL_VALIDATE_NEGOTIATE_INFO"},		      /* dissector implemented */
	{0x00144064, "FSCTL_SRV_ENUMERATE_SNAPSHOTS"},		      /* dissector implemented */
	{0x001440F2, "FSCTL_SRV_COPYCHUNK"},
	{0x001441bb, "FSCTL_SRV_READ_HASH"},
	{0x001480F2, "FSCTL_SRV_COPYCHUNK_WRITE"},
	{ 0, NULL }
};
static value_string_ext smb2_ioctl_vals_ext = VALUE_STRING_EXT_INIT(smb2_ioctl_vals);

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
static value_string_ext smb2_ioctl_device_vals_ext = VALUE_STRING_EXT_INIT(smb2_ioctl_device_vals);

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

static const value_string smb2_ioctl_shared_virtual_disk_vals[] = {
	{ 0x01, "SharedVirtualDisksSupported" },
	{ 0x07, "SharedVirtualDiskCDPSnapshotsSupported" },
	{ 0, NULL }
};

static const value_string smb2_ioctl_shared_virtual_disk_hstate_vals[] = {
	{ 0x00, "HandleStateNone" },
	{ 0x01, "HandleStateFileShared" },
	{ 0x03, "HandleStateShared" },
	{ 0, NULL }
};

/* this is called from both smb and smb2. */
int
dissect_smb2_ioctl_function(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset, guint32 *ioctlfunc)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint32     ioctl_function;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_ioctl_function, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		tree = proto_item_add_subtree(item, ett_smb2_ioctl_function);
	}

	ioctl_function = tvb_get_letohl(tvb, offset);
	if (ioctlfunc)
		*ioctlfunc = ioctl_function;
	if (ioctl_function) {
		const gchar *unknown = "unknown";
		const gchar *ioctl_name = val_to_str_ext_const(ioctl_function,
							       &smb2_ioctl_vals_ext,
							       unknown);

		/*
		 * val_to_str_const() doesn't work with a unknown == NULL
		 */
		if (ioctl_name == unknown) {
			ioctl_name = NULL;
		}

		if (ioctl_name != NULL) {
			col_append_fstr(
				pinfo->cinfo, COL_INFO, " %s", ioctl_name);
		}

		/* device */
		proto_tree_add_item(tree, hf_smb2_ioctl_function_device, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		if (ioctl_name == NULL) {
			col_append_fstr(
				pinfo->cinfo, COL_INFO, " %s",
				val_to_str_ext((ioctl_function>>16)&0xffff, &smb2_ioctl_device_vals_ext,
				"Unknown (0x%08X)"));
		}

		/* access */
		proto_tree_add_item(tree, hf_smb2_ioctl_function_access, tvb, offset, 4, ENC_LITTLE_ENDIAN);

		/* function */
		proto_tree_add_item(tree, hf_smb2_ioctl_function_function, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		if (ioctl_name == NULL) {
			col_append_fstr(
				pinfo->cinfo, COL_INFO, " Function:0x%04x",
				(ioctl_function>>2)&0x0fff);
		}

		/* method */
		proto_tree_add_item(tree, hf_smb2_ioctl_function_method, tvb, offset, 4, ENC_LITTLE_ENDIAN);
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
	static dcerpc_info        di; /* fake dcerpc_info struct */
	static dcerpc_call_value  call_data;
	e_ctx_hnd   policy_hnd;
	e_ctx_hnd   *policy_hnd_hashtablekey;
	proto_item *hnd_item   = NULL;
	char       *fid_name;
	guint32     open_frame = 0, close_frame = 0;
	smb2_eo_file_info_t	*eo_file_info;
	smb2_fid_info_t sfi_key;
	smb2_fid_info_t *sfi = NULL;

	memset(&sfi_key, 0, sizeof(sfi_key));
	sfi_key.fid_persistent = tvb_get_letoh64(tvb, offset);
	sfi_key.fid_volatile = tvb_get_letoh64(tvb, offset+8);
	sfi_key.sesid = si->sesid;
	sfi_key.tid = si->tid;
	sfi_key.frame_key = pinfo->num;
	sfi_key.name = NULL;

	di.conformant_run = 0;
	/* we need di->call_data->flags.NDR64 == 0 */
	di.call_data = &call_data;

	switch (mode) {
	case FID_MODE_OPEN:
		offset = dissect_nt_guid_hnd(tvb, offset, pinfo, tree, &di, drep, hf_smb2_fid, &policy_hnd, &hnd_item, TRUE, FALSE);
		if (!pinfo->fd->visited) {
			sfi = wmem_new(wmem_file_scope(), smb2_fid_info_t);
			*sfi = sfi_key;
			sfi->frame_key = 0;
			sfi->frame_beg = si->saved ? si->saved->frame_req : pinfo->num;
			sfi->frame_end = G_MAXUINT32;

			if (si->saved && si->saved->extra_info_type == SMB2_EI_FILENAME) {
				sfi->name = wmem_strdup(wmem_file_scope(), (char *)si->saved->extra_info);
			} else {
				sfi->name = wmem_strdup_printf(wmem_file_scope(), "[unknown]");
			}

			if (si->saved && si->saved->extra_info_type == SMB2_EI_FILENAME) {
				fid_name = wmem_strdup_printf(wmem_file_scope(), "File: %s", (char *)si->saved->extra_info);
			} else {
				fid_name = wmem_strdup_printf(wmem_file_scope(), "File: ");
			}
			dcerpc_store_polhnd_name(&policy_hnd, pinfo,
						  fid_name);

			wmem_map_insert(si->session->fids, sfi, sfi);
			si->file = sfi;

			/* If needed, create the file entry and save the policy hnd */
			if (si->saved) {
				si->saved->file = sfi;
				si->saved->policy_hnd = policy_hnd;
			}

			if (si->conv) {
				eo_file_info = (smb2_eo_file_info_t *)wmem_map_lookup(si->session->files,&policy_hnd);
				if (!eo_file_info) {
					eo_file_info = wmem_new(wmem_file_scope(), smb2_eo_file_info_t);
					policy_hnd_hashtablekey = wmem_new(wmem_file_scope(), e_ctx_hnd);
					memcpy(policy_hnd_hashtablekey, &policy_hnd, sizeof(e_ctx_hnd));
					eo_file_info->end_of_file=0;
					wmem_map_insert(si->session->files,policy_hnd_hashtablekey,eo_file_info);
				}
				si->eo_file_info=eo_file_info;
			}
		}
		break;
	case FID_MODE_CLOSE:
		if (!pinfo->fd->visited) {
			smb2_fid_info_t *fid = (smb2_fid_info_t *)wmem_map_lookup(si->session->fids, &sfi_key);
			if (fid) {
				/* set last frame */
				fid->frame_end = pinfo->num;
			}
		}
		offset = dissect_nt_guid_hnd(tvb, offset, pinfo, tree, &di, drep, hf_smb2_fid, &policy_hnd, &hnd_item, FALSE, TRUE);
		break;
	case FID_MODE_USE:
	case FID_MODE_DHNQ:
	case FID_MODE_DHNC:
		offset = dissect_nt_guid_hnd(tvb, offset, pinfo, tree, &di, drep, hf_smb2_fid, &policy_hnd, &hnd_item, FALSE, FALSE);
		break;
	}

	si->file = (smb2_fid_info_t *)wmem_map_lookup(si->session->fids, &sfi_key);
	if (si->file) {
		if (si->saved) {
			si->saved->file = si->file;
		}
		if (si->file->name) {
			if (hnd_item) {
				proto_item_append_text(hnd_item, " File: %s", si->file->name);
			}
			col_append_fstr(pinfo->cinfo, COL_INFO, " File: %s", si->file->name);
		}
	}

	if (dcerpc_fetch_polhnd_data(&policy_hnd, &fid_name, NULL, &open_frame, &close_frame, pinfo->num)) {
		/* look for the eo_file_info */
		if (!si->eo_file_info) {
			if (si->saved) { si->saved->policy_hnd = policy_hnd; }
			if (si->conv) {
				eo_file_info = (smb2_eo_file_info_t *)wmem_map_lookup(si->session->files,&policy_hnd);
				if (eo_file_info) {
					si->eo_file_info=eo_file_info;
				} else { /* XXX This should never happen */
					eo_file_info = wmem_new(wmem_file_scope(), smb2_eo_file_info_t);
					policy_hnd_hashtablekey = wmem_new(wmem_file_scope(), e_ctx_hnd);
					memcpy(policy_hnd_hashtablekey, &policy_hnd, sizeof(e_ctx_hnd));
					eo_file_info->end_of_file=0;
					wmem_map_insert(si->session->files,policy_hnd_hashtablekey,eo_file_info);
				}
			}

		}
	}

	return offset;
}

#define SMB2_FSCC_FILE_ATTRIBUTE_READ_ONLY			0x00000001
#define SMB2_FSCC_FILE_ATTRIBUTE_HIDDEN				0x00000002
#define SMB2_FSCC_FILE_ATTRIBUTE_SYSTEM				0x00000004
#define SMB2_FSCC_FILE_ATTRIBUTE_DIRECTORY			0x00000010
#define SMB2_FSCC_FILE_ATTRIBUTE_ARCHIVE			0x00000020
#define SMB2_FSCC_FILE_ATTRIBUTE_NORMAL				0x00000080
#define SMB2_FSCC_FILE_ATTRIBUTE_TEMPORARY			0x00000100
#define SMB2_FSCC_FILE_ATTRIBUTE_SPARSE_FILE			0x00000200
#define SMB2_FSCC_FILE_ATTRIBUTE_REPARSE_POINT			0x00000400
#define SMB2_FSCC_FILE_ATTRIBUTE_COMPRESSED			0x00000800
#define SMB2_FSCC_FILE_ATTRIBUTE_OFFLINE			0x00001000
#define SMB2_FSCC_FILE_ATTRIBUTE_NOT_CONTENT_INDEXED		0x00002000
#define SMB2_FSCC_FILE_ATTRIBUTE_ENCRYPTED			0x00004000
#define SMB2_FSCC_FILE_ATTRIBUTE_INTEGRITY_STREAM		0x00008000
#define SMB2_FSCC_FILE_ATTRIBUTE_NO_SCRUB_DATA			0x00020000


static const true_false_string tfs_fscc_file_attribute_reparse = {
	"Has an associated REPARSE POINT",
	"Does NOT have an associated reparse point"
};
static const true_false_string tfs_fscc_file_attribute_compressed = {
	"COMPRESSED",
	"Uncompressed"
};
static const true_false_string tfs_fscc_file_attribute_offline = {
	"OFFLINE",
	"Online"
};
static const true_false_string tfs_fscc_file_attribute_not_content_indexed = {
	"Is not indexed by the content indexing service",
	"Is indexed by the content indexing service"
};
static const true_false_string tfs_fscc_file_attribute_integrity_stream = {
	"Has Integrity Support",
	"Does NOT have Integrity Support"
};
static const true_false_string tfs_fscc_file_attribute_no_scrub_data = {
	"Is excluded from the data integrity scan",
	"Is not excluded from the data integrity scan"
};

/*
 * File Attributes, section 2.6 in the [MS-FSCC] spec
 */
static int
dissect_fscc_file_attr(tvbuff_t* tvb, proto_tree* parent_tree, int offset, guint32* attr)
{
	guint32 mask = tvb_get_letohl(tvb, offset);
	static int* const mask_fields[] = {
		&hf_smb2_fscc_file_attr_read_only,
		&hf_smb2_fscc_file_attr_hidden,
		&hf_smb2_fscc_file_attr_system,
		&hf_smb2_fscc_file_attr_directory,
		&hf_smb2_fscc_file_attr_archive,
		&hf_smb2_fscc_file_attr_normal,
		&hf_smb2_fscc_file_attr_temporary,
		&hf_smb2_fscc_file_attr_sparse_file,
		&hf_smb2_fscc_file_attr_reparse_point,
		&hf_smb2_fscc_file_attr_compressed,
		&hf_smb2_fscc_file_attr_offline,
		&hf_smb2_fscc_file_attr_not_content_indexed,
		&hf_smb2_fscc_file_attr_encrypted,
		&hf_smb2_fscc_file_attr_integrity_stream,
		&hf_smb2_fscc_file_attr_no_scrub_data,
		NULL
	};

	proto_tree_add_bitmask_value_with_flags(parent_tree, tvb, offset, hf_smb2_fscc_file_attr, ett_smb2_fscc_file_attributes, mask_fields, mask, BMT_NO_APPEND);

	offset += 4;

	if (attr)
		*attr = mask;

	return offset;
}

/* this info level is unique to SMB2 and differst from the corresponding
 * SMB_FILE_ALL_INFO in SMB
 */
static int
dissect_smb2_file_all_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int         length;
	static int * const mode_fields[] = {
		&hf_smb2_mode_file_write_through,
		&hf_smb2_mode_file_sequential_only,
		&hf_smb2_mode_file_no_intermediate_buffering,
		&hf_smb2_mode_file_synchronous_io_alert,
		&hf_smb2_mode_file_synchronous_io_nonalert,
		&hf_smb2_mode_file_delete_on_close,
		NULL,
	};

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_file_all_info, tvb, offset, -1, ENC_NA);
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
	offset = dissect_fscc_file_attr(tvb, tree, offset, NULL);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 4, ENC_NA);
	offset += 4;

	/* allocation size */
	proto_tree_add_item(tree, hf_smb2_allocation_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;

	/* end of file */
	proto_tree_add_item(tree, hf_smb2_end_of_file, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;

	/* number of links */
	proto_tree_add_item(tree, hf_smb2_nlinks, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* delete pending */
	proto_tree_add_item(tree, hf_smb2_delete_pending, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	/* is directory */
	proto_tree_add_item(tree, hf_smb2_is_directory, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	/* padding */
	offset += 2;

	/* file id */
	proto_tree_add_item(tree, hf_smb2_file_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;

	/* ea size */
	proto_tree_add_item(tree, hf_smb2_ea_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* access mask */
	offset = dissect_smb_access_mask(tvb, tree, offset);

	/* Position Information */
	proto_tree_add_item(tree, hf_smb2_position_information, tvb, offset, 8, ENC_NA);
	offset += 8;

	/* Mode Information */
	proto_tree_add_bitmask(tree, tvb, offset, hf_smb2_mode_information, ett_smb2_file_mode_info, mode_fields, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* Alignment Information */
	proto_tree_add_item(tree, hf_smb2_alignment_information, tvb, offset, 4, ENC_NA);
	offset +=4;

	/* file name length */
	length = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_filename_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* file name */
	if (length) {
		proto_tree_add_item(tree, hf_smb2_filename,
		    tvb, offset, length, ENC_UTF_16|ENC_LITTLE_ENDIAN);
		offset += length;
	}

	return offset;
}


static int
dissect_smb2_file_allocation_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint16     bc;
	gboolean    trunc;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_file_allocation_info, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_file_allocation_info);
	}

	bc = tvb_captured_length_remaining(tvb, offset);
	offset = dissect_qsfi_SMB_FILE_ALLOCATION_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}

static int
dissect_smb2_file_endoffile_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint16     bc;
	gboolean    trunc;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_file_endoffile_info, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_file_endoffile_info);
	}

	bc = tvb_captured_length_remaining(tvb, offset);
	offset = dissect_qsfi_SMB_FILE_ENDOFFILE_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}

static int
dissect_smb2_file_alternate_name_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint16     bc;
	gboolean    trunc;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_file_alternate_name_info, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_file_alternate_name_info);
	}

	bc = tvb_captured_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_NAME_INFO(tvb, pinfo, tree, offset, &bc, &trunc, /* XXX assumption hack */ TRUE);

	return offset;
}

static int
dissect_smb2_file_normalized_name_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint16     bc;
	gboolean    trunc;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_file_normalized_name_info, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_file_normalized_name_info);
	}

	bc = tvb_captured_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_NAME_INFO(tvb, pinfo, tree, offset, &bc, &trunc, /* XXX assumption hack */ TRUE);

	return offset;
}

static int
dissect_smb2_file_basic_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_file_basic_info, tvb, offset, -1, ENC_NA);
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
	offset = dissect_fscc_file_attr(tvb, tree, offset, NULL);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 4, ENC_NA);
	offset += 4;

	return offset;
}

static int
dissect_smb2_file_standard_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint16     bc;
	gboolean    trunc;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_file_standard_info, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_file_standard_info);
	}

	bc = tvb_captured_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_STANDARD_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}
static int
dissect_smb2_file_internal_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint16     bc;
	gboolean    trunc;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_file_internal_info, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_file_internal_info);
	}

	bc = tvb_captured_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_INTERNAL_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}
static int
dissect_smb2_file_mode_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint16     bc;
	gboolean    trunc;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_file_mode_info, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_file_mode_info);
	}

	bc = tvb_captured_length_remaining(tvb, offset);
	offset = dissect_qsfi_SMB_FILE_MODE_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}
static int
dissect_smb2_file_alignment_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint16     bc;
	gboolean    trunc;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_file_alignment_info, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_file_alignment_info);
	}

	bc = tvb_captured_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_ALIGNMENT_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}
static int
dissect_smb2_file_position_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint16     bc;
	gboolean    trunc;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_file_position_info, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_file_position_info);
	}

	bc = tvb_captured_length_remaining(tvb, offset);
	offset = dissect_qsfi_SMB_FILE_POSITION_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}

static int
dissect_smb2_file_access_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_file_access_info, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_file_access_info);
	}

	/* access mask */
	offset = dissect_smb_access_mask(tvb, tree, offset);

	return offset;
}

static int
dissect_smb2_file_ea_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint16     bc;
	gboolean    trunc;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_file_ea_info, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_file_ea_info);
	}

	bc = tvb_captured_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_EA_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}

static int
dissect_smb2_file_stream_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint16     bc;
	gboolean    trunc;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_file_stream_info, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_file_stream_info);
	}

	bc = tvb_captured_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_STREAM_INFO(tvb, pinfo, tree, offset, &bc, &trunc, TRUE);

	return offset;
}

static int
dissect_smb2_file_pipe_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint16     bc;
	gboolean    trunc;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_file_pipe_info, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_file_pipe_info);
	}

	bc = tvb_captured_length_remaining(tvb, offset);
	offset = dissect_sfi_SMB_FILE_PIPE_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}

static int
dissect_smb2_file_compression_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint16     bc;
	gboolean    trunc;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_file_compression_info, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_file_compression_info);
	}

	bc = tvb_captured_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_COMPRESSION_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}

static int
dissect_smb2_file_network_open_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint16     bc;
	gboolean    trunc;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_file_network_open_info, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_file_network_open_info);
	}


	bc = tvb_captured_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_NETWORK_OPEN_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}

static int
dissect_smb2_file_attribute_tag_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint16     bc;
	gboolean    trunc;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_file_attribute_tag_info, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_file_attribute_tag_info);
	}


	bc = tvb_captured_length_remaining(tvb, offset);
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
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_file_disposition_info, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_file_disposition_info);
	}

	/* file disposition */
	proto_tree_add_item(tree, hf_smb2_disposition_delete_on_close, tvb, offset, 1, ENC_LITTLE_ENDIAN);

	return offset;
}

static int
dissect_smb2_file_full_ea_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint32     next_offset;
	guint8      ea_name_len;
	guint16     ea_data_len;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_file_full_ea_info, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_file_full_ea_info);
	}

	while (1) {
		char *name = NULL;
		char *data = NULL;
		int start_offset = offset;
		proto_item *ea_item;
		proto_tree *ea_tree;

		ea_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_smb2_ea, &ea_item, "EA:");

		/* next offset */
		next_offset = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(ea_tree, hf_smb2_next_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* EA flags */
		proto_tree_add_item(ea_tree, hf_smb2_ea_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		/* EA Name Length */
		ea_name_len = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(ea_tree, hf_smb2_ea_name_len, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		/* EA Data Length */
		ea_data_len = tvb_get_letohs(tvb, offset);
		proto_tree_add_item(ea_tree, hf_smb2_ea_data_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		/* ea name */
		if (ea_name_len) {
			proto_tree_add_item_ret_display_string(ea_tree, hf_smb2_ea_name,
				tvb, offset, ea_name_len, ENC_ASCII|ENC_NA,
				pinfo->pool, &name);
		}

		/* The name is terminated with a NULL */
		offset += ea_name_len + 1;

		/* ea data */
		if (ea_data_len) {
			proto_tree_add_item_ret_display_string(ea_tree, hf_smb2_ea_data,
				tvb, offset, ea_data_len, ENC_NA,
				pinfo->pool, &data);
		}
		offset += ea_data_len;


		if (ea_item) {
			proto_item_append_text(ea_item, " %s := %s",
			    name ? name : "",
			    data ? data : "");
		}
		proto_item_set_len(ea_item, offset-start_offset);


		if (!next_offset) {
			break;
		}

		offset = start_offset+next_offset;
	}

	return offset;
}

static const true_false_string tfs_replace_if_exists = {
	"Replace the target if it exists",
	"Fail if the target exists"
};

static int
dissect_smb2_file_rename_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int         length;


	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_file_rename_info, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_file_rename_info);
	}

	/* ReplaceIfExists */
	proto_tree_add_item(tree, hf_smb2_replace_if, tvb, offset, 1, ENC_NA);
	offset += 1;

	/* reserved */
	proto_tree_add_item(tree, hf_smb2_reserved_random, tvb, offset, 7, ENC_NA);
	offset += 7;

	/* Root Directory Handle, MBZ */
	proto_tree_add_item(tree, hf_smb2_root_directory_mbz, tvb, offset, 8, ENC_NA);
	offset += 8;

	/* file name length */
	length = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_filename_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* file name */
	if (length) {
		char *display_string;

		proto_tree_add_item_ret_display_string(tree, hf_smb2_filename,
		    tvb, offset, length, ENC_UTF_16|ENC_LITTLE_ENDIAN,
		    pinfo->pool, &display_string);
		col_append_fstr(pinfo->cinfo, COL_INFO, " NewName:%s",
		    display_string);
		offset += length;
	}

	return offset;
}

static int
dissect_smb2_sec_info_00(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_sec_info_00, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_sec_info_00);
	}

	/* security descriptor */
	offset = dissect_nt_sec_desc(tvb, offset, pinfo, tree, NULL, TRUE, tvb_captured_length_remaining(tvb, offset), NULL);

	return offset;
}

static int
dissect_smb2_quota_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint16 bcp;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_quota_info, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_quota_info);
	}

	bcp = tvb_captured_length_remaining(tvb, offset);
	offset = dissect_nt_user_quota(tvb, tree, offset, &bcp);

	return offset;
}

static int
dissect_smb2_fs_info_05(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint16     bc;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_fs_info_05, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_fs_info_05);
	}

	bc = tvb_captured_length_remaining(tvb, offset);
	offset = dissect_qfsi_FS_ATTRIBUTE_INFO(tvb, pinfo, tree, offset, &bc);

	return offset;
}

static int
dissect_smb2_fs_info_06(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint16     bc;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_fs_info_06, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_fs_info_06);
	}

	bc = tvb_captured_length_remaining(tvb, offset);
	offset = dissect_nt_quota(tvb, tree, offset, &bc);

	return offset;
}

static int
dissect_smb2_FS_OBJECTID_INFO(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_fs_objectid_info, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_fs_objectid_info);
	}

	/* FILE_OBJECTID_BUFFER */
	offset = dissect_smb2_FILE_OBJECTID_BUFFER(tvb, pinfo, tree, offset);

	return offset;
}

static int
dissect_smb2_fs_info_07(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint16     bc;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_fs_info_07, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_fs_info_07);
	}

	bc = tvb_captured_length_remaining(tvb, offset);
	offset = dissect_qfsi_FS_FULL_SIZE_INFO(tvb, pinfo, tree, offset, &bc);

	return offset;
}

static int
dissect_smb2_fs_info_01(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint16     bc;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_fs_info_01, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_fs_info_01);
	}


	bc = tvb_captured_length_remaining(tvb, offset);
	offset = dissect_qfsi_FS_VOLUME_INFO(tvb, pinfo, tree, offset, &bc, TRUE);

	return offset;
}

static int
dissect_smb2_fs_info_03(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint16     bc;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_fs_info_03, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_fs_info_03);
	}


	bc = tvb_captured_length_remaining(tvb, offset);
	offset = dissect_qfsi_FS_SIZE_INFO(tvb, pinfo, tree, offset, &bc);

	return offset;
}

static int
dissect_smb2_fs_info_04(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint16     bc;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_fs_info_04, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_fs_info_04);
	}


	bc = tvb_captured_length_remaining(tvb, offset);
	offset = dissect_qfsi_FS_DEVICE_INFO(tvb, pinfo, tree, offset, &bc);

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
	proto_tree_add_item(parent_tree, hf_smb2_oplock, tvb, offset, 1, ENC_LITTLE_ENDIAN);

	offset += 1;
	return offset;
}

static int
dissect_smb2_buffercode(proto_tree *parent_tree, tvbuff_t *tvb, int offset, guint16 *length)
{
	proto_tree *tree;
	proto_item *item;
	guint16 buffer_code;

	/* dissect the first 2 bytes of the command PDU */
	buffer_code = tvb_get_letohs(tvb, offset);
	item = proto_tree_add_uint(parent_tree, hf_smb2_buffer_code, tvb, offset, 2, buffer_code);
	tree = proto_item_add_subtree(item, ett_smb2_buffercode);
	proto_tree_add_item(tree, hf_smb2_buffer_code_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_smb2_buffer_code_flags_dyn, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	if (length) {
		*length = buffer_code; /*&0xfffe don't mask it here, mask it on caller side */
	}

	return offset;
}

#define NEGPROT_CAP_DFS		0x00000001
#define NEGPROT_CAP_LEASING	0x00000002
#define NEGPROT_CAP_LARGE_MTU	0x00000004
#define NEGPROT_CAP_MULTI_CHANNEL	0x00000008
#define NEGPROT_CAP_PERSISTENT_HANDLES	0x00000010
#define NEGPROT_CAP_DIRECTORY_LEASING	0x00000020
#define NEGPROT_CAP_ENCRYPTION		0x00000040
static int
dissect_smb2_capabilities(proto_tree *parent_tree, tvbuff_t *tvb, int offset)
{
	static int * const flags[] = {
		&hf_smb2_cap_dfs,
		&hf_smb2_cap_leasing,
		&hf_smb2_cap_large_mtu,
		&hf_smb2_cap_multi_channel,
		&hf_smb2_cap_persistent_handles,
		&hf_smb2_cap_directory_leasing,
		&hf_smb2_cap_encryption,
		NULL
	};

	proto_tree_add_bitmask(parent_tree, tvb, offset, hf_smb2_capabilities, ett_smb2_capabilities, flags, ENC_LITTLE_ENDIAN);
	offset += 4;

	return offset;
}



#define NEGPROT_SIGN_REQ	0x0002
#define NEGPROT_SIGN_ENABLED	0x0001

static int
dissect_smb2_secmode(proto_tree *parent_tree, tvbuff_t *tvb, int offset)
{
	static int * const flags[] = {
		&hf_smb2_secmode_flags_sign_enabled,
		&hf_smb2_secmode_flags_sign_required,
		NULL
	};

	proto_tree_add_bitmask(parent_tree, tvb, offset, hf_smb2_security_mode, ett_smb2_sec_mode, flags, ENC_LITTLE_ENDIAN);
	offset += 1;

	return offset;
}

#define SES_REQ_FLAGS_SESSION_BINDING		0x01

static int
dissect_smb2_ses_req_flags(proto_tree *parent_tree, tvbuff_t *tvb, int offset)
{
	static int * const flags[] = {
		&hf_smb2_ses_req_flags_session_binding,
		NULL
	};

	proto_tree_add_bitmask(parent_tree, tvb, offset, hf_smb2_ses_req_flags, ett_smb2_ses_req_flags, flags, ENC_LITTLE_ENDIAN);
	offset += 1;

	return offset;
}

#define SES_FLAGS_GUEST		0x0001
#define SES_FLAGS_NULL		0x0002
#define SES_FLAGS_ENCRYPT	0x0004

static int
dissect_smb2_ses_flags(proto_tree *parent_tree, tvbuff_t *tvb, int offset)
{
	static int * const flags[] = {
		&hf_smb2_ses_flags_guest,
		&hf_smb2_ses_flags_null,
		&hf_smb2_ses_flags_encrypt,
		NULL
	};

	proto_tree_add_bitmask(parent_tree, tvb, offset, hf_smb2_session_flags, ett_smb2_ses_flags, flags, ENC_LITTLE_ENDIAN);
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
#define SHARE_FLAGS_encryption_required		0x00008000
#define SHARE_FLAGS_identity_remoting		0x00040000
#define SHARE_FLAGS_compress_data		0x00100000

static int
dissect_smb2_share_flags(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	static int * const sf_fields[] = {
		&hf_smb2_share_flags_dfs,
		&hf_smb2_share_flags_dfs_root,
		&hf_smb2_share_flags_restrict_exclusive_opens,
		&hf_smb2_share_flags_force_shared_delete,
		&hf_smb2_share_flags_allow_namespace_caching,
		&hf_smb2_share_flags_access_based_dir_enum,
		&hf_smb2_share_flags_force_levelii_oplock,
		&hf_smb2_share_flags_enable_hash_v1,
		&hf_smb2_share_flags_enable_hash_v2,
		&hf_smb2_share_flags_encrypt_data,
		&hf_smb2_share_flags_identity_remoting,
		&hf_smb2_share_flags_compress_data,
		NULL
	};
	proto_item *item;
	guint32 cp;

	item = proto_tree_add_bitmask(tree, tvb, offset, hf_smb2_share_flags, ett_smb2_share_flags, sf_fields, ENC_LITTLE_ENDIAN);

	cp = tvb_get_letohl(tvb, offset);
	cp &= 0x00000030;
	proto_tree_add_uint_format(item, hf_smb2_share_caching, tvb, offset, 4, cp, "Caching policy: %s (%08x)", val_to_str(cp, share_cache_vals, "Unknown:%u"), cp);


	offset += 4;

	return offset;
}

#define SHARE_CAPS_DFS				0x00000008
#define SHARE_CAPS_CONTINUOUS_AVAILABILITY	0x00000010
#define SHARE_CAPS_SCALEOUT			0x00000020
#define SHARE_CAPS_CLUSTER			0x00000040
#define SHARE_CAPS_ASSYMETRIC			0x00000080
#define SHARE_CAPS_REDIRECT_TO_OWNER		0x00000100

static int
dissect_smb2_share_caps(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	static int * const sc_fields[] = {
		&hf_smb2_share_caps_dfs,
		&hf_smb2_share_caps_continuous_availability,
		&hf_smb2_share_caps_scaleout,
		&hf_smb2_share_caps_cluster,
		&hf_smb2_share_caps_assymetric,
		&hf_smb2_share_caps_redirect_to_owner,
		NULL
	};

	proto_tree_add_bitmask(tree, tvb, offset, hf_smb2_share_caps, ett_smb2_share_caps, sc_fields, ENC_LITTLE_ENDIAN);

	offset += 4;

	return offset;
}

static void
dissect_smb2_secblob(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si _U_)
{
	if ((tvb_captured_length(tvb)>=7)
	&&  (!tvb_memeql(tvb, 0, "NTLMSSP", 7))) {
		call_dissector(ntlmssp_handle, tvb, pinfo, tree);
	} else {
		call_dissector(gssapi_handle, tvb, pinfo, tree);
	}
}

/*
 * Derive client and server decryption keys from the secret session key
 * and set them in the session object.
 */
static void smb2_generate_decryption_keys(smb2_conv_info_t *conv, smb2_sesid_info_t *ses)
{
	gboolean has_seskey = memcmp(ses->session_key, zeros, NTLMSSP_KEY_LEN) != 0;
	gboolean has_signkey = memcmp(ses->signing_key, zeros, NTLMSSP_KEY_LEN) != 0;
	gboolean has_client_key = memcmp(ses->client_decryption_key16, zeros, AES_KEY_SIZE) != 0;
	gboolean has_server_key = memcmp(ses->server_decryption_key16, zeros, AES_KEY_SIZE) != 0;

	/* if all decryption keys are provided, nothing to do */
	if (has_client_key && has_server_key && has_signkey)
		return;

	/* otherwise, generate them from session key, if it's there */
	if (!has_seskey)
		return;

	/* generate decryption keys */
	if (conv->dialect <= SMB2_DIALECT_210) {
		if (!has_signkey)
			memcpy(ses->signing_key, ses->session_key,
			       NTLMSSP_KEY_LEN);
	} else if (conv->dialect < SMB2_DIALECT_311) {
		if (!has_server_key)
			smb2_key_derivation(ses->session_key,
					    NTLMSSP_KEY_LEN,
					    "SMB2AESCCM", 11,
					    "ServerIn ", 10,
					    ses->server_decryption_key16, 16);
		if (!has_client_key)
			smb2_key_derivation(ses->session_key,
					    NTLMSSP_KEY_LEN,
					    "SMB2AESCCM", 11,
					    "ServerOut", 10,
					    ses->client_decryption_key16, 16);
		if (!has_signkey)
			smb2_key_derivation(ses->session_key,
					    NTLMSSP_KEY_LEN,
					    "SMB2AESCMAC", 12,
					    "SmbSign", 8,
					    ses->signing_key, 16);
	} else if (conv->dialect >= SMB2_DIALECT_311) {
		if (!has_server_key) {
			smb2_key_derivation(ses->session_key,
					    NTLMSSP_KEY_LEN,
					    "SMBC2SCipherKey", 16,
					    ses->preauth_hash, SMB2_PREAUTH_HASH_SIZE,
					    ses->server_decryption_key16, 16);
			smb2_key_derivation(ses->session_key,
					    NTLMSSP_KEY_LEN,
					    "SMBC2SCipherKey", 16,
					    ses->preauth_hash, SMB2_PREAUTH_HASH_SIZE,
					    ses->server_decryption_key32, 32);
		}
		if (!has_client_key) {
			smb2_key_derivation(ses->session_key,
					    NTLMSSP_KEY_LEN,
					    "SMBS2CCipherKey", 16,
					    ses->preauth_hash, SMB2_PREAUTH_HASH_SIZE,
					    ses->client_decryption_key16, 16);
			smb2_key_derivation(ses->session_key,
					    NTLMSSP_KEY_LEN,
					    "SMBS2CCipherKey", 16,
					    ses->preauth_hash, SMB2_PREAUTH_HASH_SIZE,
					    ses->client_decryption_key32, 32);
		}
		if (!has_signkey)
			smb2_key_derivation(ses->session_key,
					    NTLMSSP_KEY_LEN,
					    "SMBSigningKey", 14,
					    ses->preauth_hash, SMB2_PREAUTH_HASH_SIZE,
					    ses->signing_key, 16);
	}

	DEBUG("Generated Sign key");
	HEXDUMP(ses->signing_key, NTLMSSP_KEY_LEN)
	DEBUG("Generated S2C key16");
	HEXDUMP(ses->client_decryption_key16, AES_KEY_SIZE);
	DEBUG("Generated S2C key32");
	HEXDUMP(ses->client_decryption_key32, AES_KEY_SIZE*2);
	DEBUG("Generated C2S key16");
	HEXDUMP(ses->server_decryption_key16, AES_KEY_SIZE);
	DEBUG("Generated C2S key32");
	HEXDUMP(ses->server_decryption_key32, AES_KEY_SIZE*2);
}

static int
dissect_smb2_session_setup_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	offset_length_buffer_t  s_olb;
	const ntlmssp_header_t *ntlmssph;
	static int ntlmssp_tap_id = 0;
	smb2_saved_info_t *ssi = si->saved;
	proto_item *hash_item;
	int        idx;

	if (!ntlmssp_tap_id) {
		GString *error_string;
		/* We don't specify any callbacks at all.
		 * Instead we manually fetch the tapped data after the
		 * security blob has been fully dissected and before
		 * we exit from this dissector.
		 */
		error_string = register_tap_listener("ntlmssp", NULL, NULL,
		    TL_IS_DISSECTOR_HELPER, NULL, NULL, NULL, NULL);
		if (!error_string) {
			ntlmssp_tap_id = find_tap_id("ntlmssp");
		} else {
			g_string_free(error_string, TRUE);
		}
	}

	if (!pinfo->fd->visited && ssi) {
		/* compute preauth hash on first pass */

		/* start from last preauth hash of the connection if 1st request */
		if (si->sesid == 0)
			memcpy(si->conv->preauth_hash_ses, si->conv->preauth_hash_con, SMB2_PREAUTH_HASH_SIZE);

		ssi->preauth_hash_req = (guint8*)wmem_alloc0(wmem_file_scope(), SMB2_PREAUTH_HASH_SIZE);
		update_preauth_hash(si->conv->preauth_hash_current, pinfo, tvb);
		memcpy(ssi->preauth_hash_req, si->conv->preauth_hash_current, SMB2_PREAUTH_HASH_SIZE);
	}

	if (ssi && ssi->preauth_hash_req) {
		hash_item = proto_tree_add_bytes_with_length(tree, hf_smb2_preauth_hash, tvb,
							     0, tvb_captured_length(tvb),
							     ssi->preauth_hash_req, SMB2_PREAUTH_HASH_SIZE);
		proto_item_set_generated(hash_item);
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
	proto_tree_add_item(tree, hf_smb2_channel, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* security blob offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &s_olb, OLB_O_UINT16_S_UINT16, hf_smb2_security_blob);

	/* previous session id */
	proto_tree_add_item(tree, hf_smb2_previous_sesid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;


	/* the security blob itself */
	dissect_smb2_olb_buffer(pinfo, tree, tvb, &s_olb, si, dissect_smb2_secblob);

	offset = dissect_smb2_olb_tvb_max_offset(offset, &s_olb);

	/* If we have found a uid->acct_name mapping, store it */
	if (!pinfo->fd->visited) {
		idx = 0;
		while ((ntlmssph = (const ntlmssp_header_t *)fetch_tapped_data(ntlmssp_tap_id, idx++)) != NULL) {
			if (ntlmssph && ntlmssph->type == NTLMSSP_AUTH) {
				si->session = smb2_get_session(si->conv, si->sesid, pinfo, si);
				si->session->acct_name = wmem_strdup(wmem_file_scope(), ntlmssph->acct_name);
				si->session->domain_name = wmem_strdup(wmem_file_scope(), ntlmssph->domain_name);
				si->session->host_name = wmem_strdup(wmem_file_scope(), ntlmssph->host_name);
				/* don't overwrite session key from preferences */
				if (memcmp(si->session->session_key, zeros, SMB_SESSION_ID_SIZE) == 0) {
					memcpy(si->session->session_key, ntlmssph->session_key, NTLMSSP_KEY_LEN);
				}
				si->session->auth_frame = pinfo->num;
			}
		}
	}

	return offset;
}

static void
dissect_smb2_share_redirect_error(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_tree *tree;
	proto_item *item;
	proto_tree *ips_tree;
	proto_item *ips_item;

	offset_length_buffer_t res_olb;
	guint32 i, ip_count;

	item = proto_tree_add_item(parent_tree, hf_smb2_error_redir_context, tvb, offset, 0, ENC_NA);
	tree = proto_item_add_subtree(item, ett_smb2_error_redir_context);

	/* structure size */
	proto_tree_add_item(tree, hf_smb2_error_redir_struct_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* notification type */
	proto_tree_add_item(tree, hf_smb2_error_redir_notif_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* resource name offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &res_olb, OLB_O_UINT32_S_UINT32, hf_smb2_error_redir_res_name);

	/* flags */
	proto_tree_add_item(tree, hf_smb2_error_redir_flags, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	/* target type */
	proto_tree_add_item(tree, hf_smb2_error_redir_target_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	/* ip addr count */
	proto_tree_add_item_ret_uint(tree, hf_smb2_error_redir_ip_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &ip_count);
	offset += 4;

	/* ip addr list */
	ips_item = proto_tree_add_item(tree, hf_smb2_error_redir_ip_list, tvb, offset, 0, ENC_NA);
	ips_tree = proto_item_add_subtree(ips_item, ett_smb2_error_redir_ip_list);
	for (i = 0; i < ip_count; i++)
		offset += dissect_windows_sockaddr_storage(tvb, pinfo, ips_tree, offset, -1);

	/* resource name */
	dissect_smb2_olb_off_string(pinfo, tree, tvb, &res_olb, offset, OLB_TYPE_UNICODE_STRING);
}

static void
dissect_smb2_STATUS_STOPPED_ON_SYMLINK(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_tree *tree;
	proto_item *item;

	offset_length_buffer_t  s_olb, p_olb;

	item = proto_tree_add_item(parent_tree, hf_smb2_symlink_error_response, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_smb2_symlink_error_response);

	/* symlink length */
	proto_tree_add_item(tree, hf_smb2_symlink_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* symlink error tag */
	proto_tree_add_item(tree, hf_smb2_symlink_error_tag, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* reparse tag */
	proto_tree_add_item(tree, hf_smb2_reparse_tag, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_smb2_reparse_data_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_smb2_unparsed_path_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	/* substitute name  offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &s_olb, OLB_O_UINT16_S_UINT16, hf_smb2_symlink_substitute_name);

	/* print name offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &p_olb, OLB_O_UINT16_S_UINT16, hf_smb2_symlink_print_name);

	/* flags */
	proto_tree_add_item(tree, hf_smb2_symlink_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* substitute name string */
	dissect_smb2_olb_off_string(pinfo, tree, tvb, &s_olb, offset, OLB_TYPE_UNICODE_STRING);

	/* print name string */
	dissect_smb2_olb_off_string(pinfo, tree, tvb, &p_olb, offset, OLB_TYPE_UNICODE_STRING);
}

static int
dissect_smb2_error_context(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_tree *tree;
	proto_item *item;
	tvbuff_t *sub_tvb;
	guint32 length;
	guint32 id;

	item = proto_tree_add_item(parent_tree, hf_smb2_error_context, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_smb2_error_context);

	proto_tree_add_item_ret_uint(tree, hf_smb2_error_context_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &length);
	offset += 4;

	proto_tree_add_item_ret_uint(tree, hf_smb2_error_context_id, tvb, offset, 4, ENC_LITTLE_ENDIAN, &id);
	offset += 4;

	sub_tvb = tvb_new_subset_length(tvb, offset, length);
	dissect_smb2_error_data(sub_tvb, pinfo, tree, 0, id, si);
	offset += length;

	return offset;
}

/*
 * Assumes it is being called with a sub-tvb (dissects at offsets 0)
 */
static void
dissect_smb2_error_data(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree,
			int error_context_count, int error_id,
			smb2_info_t *si _U_)
{
	proto_tree *tree;
	proto_item *item;

	int offset = 0;
	int i;

	item = proto_tree_add_item(parent_tree, hf_smb2_error_data, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_smb2_error_data);

	if (error_context_count == 0) {
		if (tvb_captured_length_remaining(tvb, offset) <= 1)
			return;
		switch (si->status) {
		case NT_STATUS_STOPPED_ON_SYMLINK:
			dissect_smb2_STATUS_STOPPED_ON_SYMLINK(tvb, pinfo, tree, offset, si);
			break;
		case NT_STATUS_BUFFER_TOO_SMALL:
			proto_tree_add_item(tree, hf_smb2_error_min_buf_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			break;
		case NT_STATUS_BAD_NETWORK_NAME:
			if (error_id == SMB2_ERROR_ID_SHARE_REDIRECT)
				dissect_smb2_share_redirect_error(tvb, pinfo, tree, offset, si);
		default:
			break;
		}
	} else {
		for (i = 0; i < error_context_count; i++)
			offset += dissect_smb2_error_context(tvb, pinfo, tree, offset, si);
	}
}

/*
 * SMB2 Error responses are a bit convoluted. Error data can be a list
 * of error contexts which themselves can hold an error data field.
 * See [MS-SMB2] 2.2.2.1.
 *
 * ERROR_RESP := ERROR_DATA
 *
 * ERROR_DATA := ( ERROR_CONTEXT + )
 *             | ERROR_STATUS_STOPPED_ON_SYMLINK
 *             | ERROR_ID_SHARE_REDIRECT
 *             | ERROR_BUFFER_TOO_SMALL
 *
 * ERROR_CONTEXT := ... + ERROR_DATA
 *                | ERROR_ID_SHARE_REDIRECT
 *
 * This needs more fixes for cases when the original header had also the constant value of 9.
 * This should be fixed on caller side where it decides if it has to call this or not.
 *
 */
static int
dissect_smb2_error_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si,
							gboolean* continue_dissection)
{
	gint byte_count;
	guint8 error_context_count;
	guint16 length;
	tvbuff_t *sub_tvb;

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, &length);

	/* FIX: error response uses this constant, if not then it is not an error response */
	if(length != 9)
	{
		if(continue_dissection)
			*continue_dissection = TRUE;
	} else {
		if(continue_dissection)
			*continue_dissection = FALSE;

		/* ErrorContextCount (1 bytes) */
		error_context_count = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_error_context_count, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		/* Reserved (1 bytes) */
		proto_tree_add_item(tree, hf_smb2_error_reserved, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		/* ByteCount (4 bytes): The number of bytes of data contained in ErrorData[]. */
		byte_count = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_error_byte_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* If the ByteCount field is zero then the server MUST supply an ErrorData field
		   that is one byte in length */
		if (byte_count == 0) byte_count = 1;

		/* ErrorData (variable): A variable-length data field that contains extended
		   error information.*/
		sub_tvb = tvb_new_subset_length(tvb, offset, byte_count);
		offset += byte_count;

		dissect_smb2_error_data(sub_tvb, pinfo, tree, error_context_count, 0, si);
	}

	return offset;
}

static int
dissect_smb2_session_setup_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	offset_length_buffer_t s_olb;
	proto_item *hash_item;
	smb2_saved_info_t *ssi = si->saved;

	si->session = smb2_get_session(si->conv, si->sesid, pinfo, si);
	if (si->status == 0) {
		si->session->auth_frame = pinfo->num;
	}

	/* compute preauth hash on first pass */
	if (!pinfo->fd->visited && ssi) {
		ssi->preauth_hash_res = (guint8*)wmem_alloc0(wmem_file_scope(), SMB2_PREAUTH_HASH_SIZE);
		/*
		 * Preauth hash can only be used if the session is
		 * established i.e. last session setup response has a
		 * success status. As per the specification, the last
		 * response is NOT hashed.
		 */
		if (si->status != 0) {
			/*
			 * Not sucessful means either more req/rsp
			 * processing is required or we reached an
			 * error, so update hash.
			 */
			update_preauth_hash(si->conv->preauth_hash_current, pinfo, tvb);
		} else {
			/*
			 * Session is established, we can generate the keys
			 */
			memcpy(si->session->preauth_hash, si->conv->preauth_hash_current, SMB2_PREAUTH_HASH_SIZE);
			smb2_generate_decryption_keys(si->conv, si->session);
		}

		/* In all cases, stash the preauth hash */
		memcpy(ssi->preauth_hash_res, si->conv->preauth_hash_current, SMB2_PREAUTH_HASH_SIZE);
	}

	if (ssi && ssi->preauth_hash_res) {
		hash_item = proto_tree_add_bytes_with_length(tree, hf_smb2_preauth_hash, tvb,
							     0, tvb_captured_length(tvb),
							     ssi->preauth_hash_res, SMB2_PREAUTH_HASH_SIZE);
		proto_item_set_generated(hash_item);
	}

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

	/* If we have found a uid->acct_name mapping, store it */
#ifdef HAVE_KERBEROS
	if (!pinfo->fd->visited && si->status == 0) {
		enc_key_t *ek;

		if (krb_decrypt) {
			read_keytab_file_from_preferences();
		}

		for (ek=enc_key_list;ek;ek=ek->next) {
			if (ek->fd_num == (int)pinfo->num) {
				break;
			}
		}

		if (ek != NULL) {
			/* TODO: fill in the correct user/dom/host information */
		}
	}
#endif

	return offset;
}

static int
dissect_smb2_tree_connect_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	offset_length_buffer_t olb;
	const guint8 *buf;
	guint16       flags;
	proto_item *item;
	static int * const connect_flags[] = {
		&hf_smb2_tc_cluster_reconnect,
		&hf_smb2_tc_redirect_to_owner,
		&hf_smb2_tc_extension_present,
		&hf_smb2_tc_reserved,
		NULL
	};

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* flags */
	item = proto_tree_get_parent(tree);
	flags = tvb_get_letohs(tvb, offset);
	proto_tree_add_bitmask(tree, tvb, offset, hf_smb2_tree_connect_flags, ett_smb2_tree_connect_flags, connect_flags, ENC_LITTLE_ENDIAN);

	if (flags != 0) {
		proto_item_append_text(item, "%s%s%s",
			       (flags & 0x0001)?", CLUSTER_RECONNECT":"",
			       (flags & 0x0002)?", REDIRECT_TO_OWNER":"",
			       (flags & 0x0004)?", EXTENSION_PRESENT":"");
	}
	offset += 2;

	/* tree  offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &olb, OLB_O_UINT16_S_UINT16, hf_smb2_tree);

	/* tree string */
	buf = dissect_smb2_olb_string(pinfo, tree, tvb, &olb, OLB_TYPE_UNICODE_STRING);

	offset = dissect_smb2_olb_tvb_max_offset(offset, &olb);

	/* treelen  +1 is overkill here if the string is unicode,
	 * but who ever has more than a handful of TCON in a trace anyways
	 */
	if (!pinfo->fd->visited && si->saved && buf && olb.len) {
		si->saved->extra_info_type = SMB2_EI_TREENAME;
		si->saved->extra_info = wmem_alloc(wmem_file_scope(), olb.len+1);
		snprintf((char *)si->saved->extra_info,olb.len+1,"%s",buf);
	}

	if (buf) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " Tree: %s",
		    format_text(pinfo->pool, buf, strlen(buf)));
	}

	return offset;
}
static int
dissect_smb2_tree_connect_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	guint8 share_type;
	gboolean continue_dissection;

	switch (si->status) {
	/* buffer code */
	case 0x00000000: offset = dissect_smb2_buffercode(tree, tvb, offset, NULL); break;
	default: offset = dissect_smb2_error_response(tvb, pinfo, tree, offset, si, &continue_dissection);
		if (!continue_dissection) return offset;
	}

	/* share type */
	share_type = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_share_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	/* byte is reserved and must be set to zero */
	proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 1, ENC_NA);
	offset += 1;

	if (!pinfo->fd->visited && si->saved && si->saved->extra_info_type == SMB2_EI_TREENAME && si->session) {
		smb2_tid_info_t *tid, tid_key;

		tid_key.tid = si->tid;
		tid = (smb2_tid_info_t *)wmem_map_lookup(si->session->tids, &tid_key);
		if (tid) {
			wmem_map_remove(si->session->tids, &tid_key);
		}
		tid = wmem_new(wmem_file_scope(), smb2_tid_info_t);
		tid->tid = si->tid;
		tid->name = (char *)si->saved->extra_info;
		tid->connect_frame = pinfo->num;
		tid->share_type = share_type;

		wmem_map_insert(si->session->tids, tid, tid);

		si->saved->extra_info_type = SMB2_EI_NONE;
		si->saved->extra_info = NULL;
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
	proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 2, ENC_NA);
	offset += 2;

	return offset;
}

static int
dissect_smb2_tree_disconnect_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	gboolean continue_dissection;

	switch (si->status) {
	/* buffer code */
	case 0x00000000: offset = dissect_smb2_buffercode(tree, tvb, offset, NULL); break;
	default: offset = dissect_smb2_error_response(tvb, pinfo, tree, offset, si, &continue_dissection);
		if (!continue_dissection) return offset;
	}

	/* reserved */
	proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 2, ENC_NA);
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
	gboolean continue_dissection;

	switch (si->status) {
	/* buffer code */
	case 0x00000000: offset = dissect_smb2_buffercode(tree, tvb, offset, NULL); break;
	default: offset = dissect_smb2_error_response(tvb, pinfo, tree, offset, si, &continue_dissection);
		if (!continue_dissection) return offset;
	}

	/* reserved bytes */
	proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 2, ENC_NA);
	offset += 2;

	return offset;
}

static int
dissect_smb2_keepalive_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, ENC_NA);
	offset += 2;

	return offset;
}

static int
dissect_smb2_keepalive_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	gboolean continue_dissection;

	switch (si->status) {
	/* buffer code */
	case 0x00000000: offset = dissect_smb2_buffercode(tree, tvb, offset, NULL); break;
	default: offset = dissect_smb2_error_response(tvb, pinfo, tree, offset, si, &continue_dissection);
		if (!continue_dissection) return offset;
	}

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, ENC_NA);
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
		flags_item = proto_tree_add_item(tree, hf_smb2_notify_flags, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		flags_tree = proto_item_add_subtree(flags_item, ett_smb2_notify_flags);
	}
	proto_tree_add_item(flags_tree, hf_smb2_notify_watch_tree, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	/* output buffer length */
	proto_tree_add_item(tree, hf_smb2_output_buffer_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

	/* completion filter */
	offset = dissect_nt_notify_completion_filter(tvb, tree, offset);

	/* reserved */
	proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 4, ENC_NA);
	offset += 4;

	return offset;
}

static const value_string notify_action_vals[] = {
	{0x01, "FILE_ACTION_ADDED"},
	{0x02, "FILE_ACTION_REMOVED"},
	{0x03, "FILE_ACTION_MODIFIED"},
	{0x04, "FILE_ACTION_RENAMED_OLD_NAME"},
	{0x05, "FILE_ACTION_RENAMED_NEW_NAME"},
	{0x06, "FILE_ACTION_ADDED_STREAM"},
	{0x07, "FILE_ACTION_REMOVED_STREAM"},
	{0x08, "FILE_ACTION_MODIFIED_STREAM"},
	{0x09, "FILE_ACTION_REMOVED_BY_DELETE"},
	{0, NULL}
};

static void
dissect_smb2_notify_data_out(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, smb2_info_t *si _U_)
{
	proto_tree *tree = NULL;
	proto_item *item = NULL;
	int offset = 0;

	while (tvb_reported_length_remaining(tvb, offset) > 4) {
		guint32 start_offset = offset;
		guint32 next_offset;
		guint32 length;

		if (parent_tree) {
			item = proto_tree_add_item(parent_tree, hf_smb2_notify_info, tvb, offset, -1, ENC_NA);
			tree = proto_item_add_subtree(item, ett_smb2_notify_info);
		}

		/* next offset */
		proto_tree_add_item_ret_uint(tree, hf_smb2_notify_next_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &next_offset);
		offset += 4;

		proto_tree_add_item(tree, hf_smb2_notify_action, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* file name length */
		proto_tree_add_item_ret_uint(tree, hf_smb2_filename_len, tvb, offset, 4, ENC_LITTLE_ENDIAN, &length);
		offset += 4;

		/* file name */
		if (length) {
			proto_tree_add_item(tree, hf_smb2_filename,
			    tvb, offset, length, ENC_UTF_16|ENC_LITTLE_ENDIAN);
		}

		if (!next_offset) {
			break;
		}

		offset = start_offset+next_offset;
	}
}

static int
dissect_smb2_notify_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si)
{
	offset_length_buffer_t olb;
	gboolean continue_dissection;

	switch (si->status) {
	/* MS-SMB2 3.3.4.4 says STATUS_NOTIFY_ENUM_DIR is not treated as an error */
	case 0x0000010c: /* STATUS_NOTIFY_ENUM_DIR */
	case 0x00000000: /* buffer code */
	 offset = dissect_smb2_buffercode(tree, tvb, offset, NULL); break;
	default: offset = dissect_smb2_error_response(tvb, pinfo, tree, offset, si, &continue_dissection);
		if (!continue_dissection) return offset;
	}

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
	const guint8 *buf;
	guint8      il;
	static int * const f_fields[] = {
		&hf_smb2_find_flags_restart_scans,
		&hf_smb2_find_flags_single_entry,
		&hf_smb2_find_flags_index_specified,
		&hf_smb2_find_flags_reopen,
		NULL
	};

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	il = tvb_get_guint8(tvb, offset);
	if (si->saved) {
		si->saved->infolevel = il;
	}

	/* infolevel */
	proto_tree_add_uint(tree, hf_smb2_find_info_level, tvb, offset, 1, il);
	offset += 1;

	/* find flags */
	proto_tree_add_bitmask(tree, tvb, offset, hf_smb2_find_flags, ett_smb2_find_flags, f_fields, ENC_LITTLE_ENDIAN);
	offset += 1;

	/* file index */
	proto_tree_add_item(tree, hf_smb2_file_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

	/* search pattern  offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &olb, OLB_O_UINT16_S_UINT16, hf_smb2_find_pattern);

	/* output buffer length */
	proto_tree_add_item(tree, hf_smb2_output_buffer_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* search pattern */
	buf = dissect_smb2_olb_string(pinfo, tree, tvb, &olb, OLB_TYPE_UNICODE_STRING);

	offset = dissect_smb2_olb_tvb_max_offset(offset, &olb);

	if (!pinfo->fd->visited && si->saved && olb.len) {
		si->saved->extra_info_type = SMB2_EI_FINDPATTERN;
		si->saved->extra_info = wmem_alloc(wmem_file_scope(), olb.len+1);
		snprintf((char *)si->saved->extra_info,olb.len+1,"%s",buf);
	}

	col_append_fstr(pinfo->cinfo, COL_INFO, " %s Pattern: %s",
			val_to_str(il, smb2_find_info_levels, "(Level:0x%02x)"),
			buf);

	return offset;
}

static void dissect_smb2_file_directory_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, smb2_info_t *si _U_)
{
	int         offset = 0;
	proto_item *item   = NULL;
	proto_tree *tree   = NULL;

	while (tvb_reported_length_remaining(tvb, offset) > 4) {
		int old_offset = offset;
		int next_offset;
		int file_name_len;

		if (parent_tree) {
			item = proto_tree_add_item(parent_tree, hf_smb2_file_directory_info, tvb, offset, -1, ENC_NA);
			tree = proto_item_add_subtree(item, ett_smb2_file_directory_info);
		}

		/* next offset */
		next_offset = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_next_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* file index */
		proto_tree_add_item(tree, hf_smb2_file_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
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
		proto_tree_add_item(tree, hf_smb2_end_of_file, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		/* allocation size */
		proto_tree_add_item(tree, hf_smb2_allocation_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		/* File Attributes */
		offset = dissect_fscc_file_attr(tvb, tree, offset, NULL);

		/* file name length */
		file_name_len = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_filename_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* file name */
		if (file_name_len) {
			char *display_string;

			proto_tree_add_item_ret_display_string(tree, hf_smb2_filename,
			    tvb, offset, file_name_len, ENC_UTF_16|ENC_LITTLE_ENDIAN,
			    pinfo->pool, &display_string);
			proto_item_append_text(item, ": %s", display_string);
			offset += file_name_len;
		}

		proto_item_set_len(item, offset-old_offset);

		if (next_offset == 0) {
			return;
		}

		offset = old_offset+next_offset;
		if (offset < old_offset) {
			proto_tree_add_expert_format(tree, pinfo, &ei_smb2_invalid_length, tvb, offset, -1,
				    "Invalid offset/length. Malformed packet");
			return;
		}
	}
}

static void dissect_smb2_full_directory_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, smb2_info_t *si _U_)
{
	int         offset = 0;
	proto_item *item   = NULL;
	proto_tree *tree   = NULL;

	while (tvb_reported_length_remaining(tvb, offset) > 4) {
		int old_offset = offset;
		int next_offset;
		int file_name_len;
		guint32 attr;

		if (parent_tree) {
			item = proto_tree_add_item(parent_tree, hf_smb2_full_directory_info, tvb, offset, -1, ENC_NA);
			tree = proto_item_add_subtree(item, ett_smb2_full_directory_info);
		}

		/* next offset */
		next_offset = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_next_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* file index */
		proto_tree_add_item(tree, hf_smb2_file_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
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
		proto_tree_add_item(tree, hf_smb2_end_of_file, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		/* allocation size */
		proto_tree_add_item(tree, hf_smb2_allocation_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		/* File Attributes */
		offset = dissect_fscc_file_attr(tvb, tree, offset, &attr);

		/* file name length */
		file_name_len = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_filename_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* ea size or reparse tag */
		if (attr & SMB2_FSCC_FILE_ATTRIBUTE_REPARSE_POINT)
			proto_tree_add_item(tree, hf_smb2_reparse_tag, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		else
			proto_tree_add_item(tree, hf_smb2_ea_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* file name */
		if (file_name_len) {
			char *display_string;

			proto_tree_add_item_ret_display_string(tree, hf_smb2_filename,
			    tvb, offset, file_name_len, ENC_UTF_16|ENC_LITTLE_ENDIAN,
			    pinfo->pool, &display_string);
			proto_item_append_text(item, ": %s", display_string);
			offset += file_name_len;
		}

		proto_item_set_len(item, offset-old_offset);

		if (next_offset == 0) {
			return;
		}

		offset = old_offset+next_offset;
		if (offset < old_offset) {
			proto_tree_add_expert_format(tree, pinfo, &ei_smb2_invalid_length, tvb, offset, -1,
				    "Invalid offset/length. Malformed packet");
			return;
		}
	}
}

static void dissect_smb2_both_directory_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, smb2_info_t *si _U_)
{
	int         offset = 0;
	proto_item *item   = NULL;
	proto_tree *tree   = NULL;

	while (tvb_reported_length_remaining(tvb, offset) > 4) {
		int old_offset = offset;
		int next_offset;
		int file_name_len;
		int short_name_len;
		guint32 attr;

		if (parent_tree) {
			item = proto_tree_add_item(parent_tree, hf_smb2_both_directory_info, tvb, offset, -1, ENC_NA);
			tree = proto_item_add_subtree(item, ett_smb2_both_directory_info);
		}

		/* next offset */
		next_offset = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_next_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* file index */
		proto_tree_add_item(tree, hf_smb2_file_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
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
		proto_tree_add_item(tree, hf_smb2_end_of_file, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		/* allocation size */
		proto_tree_add_item(tree, hf_smb2_allocation_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		/* File Attributes */
		offset = dissect_fscc_file_attr(tvb, tree, offset, &attr);

		/* file name length */
		file_name_len = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_filename_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* ea size or reparse tag */
		if (attr & SMB2_FSCC_FILE_ATTRIBUTE_REPARSE_POINT)
			proto_tree_add_item(tree, hf_smb2_reparse_tag, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		else
			proto_tree_add_item(tree, hf_smb2_ea_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* short name length */
		short_name_len = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_short_name_len, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		/* reserved */
		proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 1, ENC_NA);
		offset += 1;

		/* short name */
		if (short_name_len) {
			proto_tree_add_item(tree, hf_smb2_short_name,
			    tvb, offset, short_name_len, ENC_UTF_16|ENC_LITTLE_ENDIAN);
		}
		offset += 24;

		/* file name */
		if (file_name_len) {
			char *display_string;

			proto_tree_add_item_ret_display_string(tree, hf_smb2_filename,
			    tvb, offset, file_name_len, ENC_UTF_16|ENC_LITTLE_ENDIAN,
			    pinfo->pool, &display_string);
			proto_item_append_text(item, ": %s", display_string);
			offset += file_name_len;
		}

		proto_item_set_len(item, offset-old_offset);

		if (next_offset == 0) {
			return;
		}

		offset = old_offset+next_offset;
		if (offset < old_offset) {
			proto_tree_add_expert_format(tree, pinfo, &ei_smb2_invalid_length, tvb, offset, -1,
				    "Invalid offset/length. Malformed packet");
			return;
		}
	}
}

static void dissect_smb2_file_name_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, smb2_info_t *si _U_)
{
	int         offset = 0;
	proto_item *item   = NULL;
	proto_tree *tree   = NULL;

	while (tvb_reported_length_remaining(tvb, offset) > 4) {
		int old_offset = offset;
		int next_offset;
		int file_name_len;

		if (parent_tree) {
			item = proto_tree_add_item(parent_tree, hf_smb2_both_directory_info, tvb, offset, -1, ENC_NA);
			tree = proto_item_add_subtree(item, ett_smb2_both_directory_info);
		}

		/* next offset */
		next_offset = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_next_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* file index */
		proto_tree_add_item(tree, hf_smb2_file_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* file name length */
		file_name_len = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_filename_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* file name */
		if (file_name_len) {
			char *display_string;

			proto_tree_add_item_ret_display_string(tree, hf_smb2_filename,
			    tvb, offset, file_name_len, ENC_UTF_16|ENC_LITTLE_ENDIAN,
			    pinfo->pool, &display_string);
			proto_item_append_text(item, ": %s", display_string);
			offset += file_name_len;
		}

		proto_item_set_len(item, offset-old_offset);

		if (next_offset == 0) {
			return;
		}

		offset = old_offset+next_offset;
		if (offset < old_offset) {
			proto_tree_add_expert_format(tree, pinfo, &ei_smb2_invalid_length, tvb, offset, -1,
				    "Invalid offset/length. Malformed packet");
			return;
		}
	}
}

static void dissect_smb2_id_both_directory_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, smb2_info_t *si _U_)
{
	int         offset = 0;
	proto_item *item   = NULL;
	proto_tree *tree   = NULL;

	while (tvb_reported_length_remaining(tvb, offset) > 4) {
		int old_offset = offset;
		int next_offset;
		int file_name_len;
		int short_name_len;
		guint32 attr;

		if (parent_tree) {
			item = proto_tree_add_item(parent_tree, hf_smb2_id_both_directory_info, tvb, offset, -1, ENC_NA);
			tree = proto_item_add_subtree(item, ett_smb2_id_both_directory_info);
		}

		/* next offset */
		next_offset = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_next_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* file index */
		proto_tree_add_item(tree, hf_smb2_file_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
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
		proto_tree_add_item(tree, hf_smb2_end_of_file, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		/* allocation size */
		proto_tree_add_item(tree, hf_smb2_allocation_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		/* File Attributes */
		offset = dissect_fscc_file_attr(tvb, tree, offset, &attr);

		/* file name length */
		file_name_len = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_filename_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* ea size or reparse tag */
		if (attr & SMB2_FSCC_FILE_ATTRIBUTE_REPARSE_POINT)
			proto_tree_add_item(tree, hf_smb2_reparse_tag, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		else
			proto_tree_add_item(tree, hf_smb2_ea_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* short name length */
		short_name_len = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_short_name_len, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		/* reserved */
		proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 1, ENC_NA);
		offset += 1;

		/* short name */
		if (short_name_len) {
			proto_tree_add_item(tree, hf_smb2_short_name,
			    tvb, offset, short_name_len, ENC_UTF_16|ENC_LITTLE_ENDIAN);
		}
		offset += 24;

		/* reserved */
		proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 2, ENC_NA);
		offset += 2;

		/* file id */
		proto_tree_add_item(tree, hf_smb2_file_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		/* file name */
		if (file_name_len) {
			char *display_string;

			proto_tree_add_item_ret_display_string(tree, hf_smb2_filename,
			    tvb, offset, file_name_len, ENC_UTF_16|ENC_LITTLE_ENDIAN,
			    pinfo->pool, &display_string);
			proto_item_append_text(item, ": %s", display_string);
			offset += file_name_len;
		}

		proto_item_set_len(item, offset-old_offset);

		if (next_offset == 0) {
			return;
		}

		offset = old_offset+next_offset;
		if (offset < old_offset) {
			proto_tree_add_expert_format(tree, pinfo, &ei_smb2_invalid_length, tvb, offset, -1,
				    "Invalid offset/length. Malformed packet");
			return;
		}
	}
}


static void dissect_smb2_id_full_directory_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, smb2_info_t *si _U_)
{
	int         offset = 0;
	proto_item *item   = NULL;
	proto_tree *tree   = NULL;

	while (tvb_reported_length_remaining(tvb, offset) > 4) {
		int old_offset = offset;
		int next_offset;
		int file_name_len;
		guint32 attr;

		if (parent_tree) {
			item = proto_tree_add_item(parent_tree, hf_smb2_id_both_directory_info, tvb, offset, -1, ENC_NA);
			tree = proto_item_add_subtree(item, ett_smb2_id_both_directory_info);
		}

		/* next offset */
		next_offset = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_next_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* file index */
		proto_tree_add_item(tree, hf_smb2_file_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
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
		proto_tree_add_item(tree, hf_smb2_end_of_file, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		/* allocation size */
		proto_tree_add_item(tree, hf_smb2_allocation_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		/* File Attributes */
		offset = dissect_fscc_file_attr(tvb, tree, offset, &attr);

		/* file name length */
		file_name_len = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_filename_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* ea size or reparse tag */
		if (attr & SMB2_FSCC_FILE_ATTRIBUTE_REPARSE_POINT)
			proto_tree_add_item(tree, hf_smb2_reparse_tag, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		else
			proto_tree_add_item(tree, hf_smb2_ea_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* reserved */
		proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 4, ENC_NA);
		offset += 4;

		/* file id */
		proto_tree_add_item(tree, hf_smb2_file_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		/* file name */
		if (file_name_len) {
			char *display_string;

			proto_tree_add_item_ret_display_string(tree, hf_smb2_filename,
			    tvb, offset, file_name_len, ENC_UTF_16|ENC_LITTLE_ENDIAN,
			    pinfo->pool, &display_string);
			proto_item_append_text(item, ": %s", display_string);
			offset += file_name_len;
		}

		proto_item_set_len(item, offset-old_offset);

		if (next_offset == 0) {
			return;
		}

		offset = old_offset+next_offset;
		if (offset < old_offset) {
			proto_tree_add_expert_format(tree, pinfo, &ei_smb2_invalid_length, tvb, offset, -1,
				    "Invalid offset/length. Malformed packet");
			return;
		}
	}
}

static int dissect_smb2_posix_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	/* create time */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_create_timestamp);

	/* last access */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_access_timestamp);

	/* last write */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_write_timestamp);

	/* last change */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_change_timestamp);

	/* allocation size */
	proto_tree_add_item(tree, hf_smb2_allocation_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;

	/* end of file */
	proto_tree_add_item(tree, hf_smb2_end_of_file, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;

	/* File Attributes */
	offset = dissect_fscc_file_attr(tvb, tree, offset, NULL);

	/* file index */
	proto_tree_add_item(tree, hf_smb2_inode, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;

	/* dev id */
	proto_tree_add_item(tree, hf_smb2_file_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* zero */
	proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 4, ENC_NA);
	offset += 4;

	/* Hardlinks */
	proto_tree_add_item(tree, hf_smb2_nlinks, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* Reparse tag */
	proto_tree_add_item(tree, hf_smb2_reparse_tag, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* POSIX mode bits */
	proto_tree_add_item(tree, hf_smb2_posix_perms, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* Owner and Group SID */
	offset = dissect_nt_sid(tvb, offset, tree, "Owner SID", NULL, -1);
	offset = dissect_nt_sid(tvb, offset, tree, "Group SID", NULL, -1);

	return offset;
}

static void dissect_smb2_posix_directory_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, smb2_info_t *si _U_)
{
	int offset = 0;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	while (tvb_reported_length_remaining(tvb, offset) > 4) {
		int old_offset = offset;
		int next_offset;
		int file_name_len;

		if (parent_tree) {
			item = proto_tree_add_item(parent_tree, hf_smb2_posix_info, tvb, offset, -1, ENC_NA);
			tree = proto_item_add_subtree(item, ett_smb2_posix_info);
		}

		/* next offset */
		next_offset = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_next_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		offset += 4;

		offset = dissect_smb2_posix_info(tvb, pinfo, tree, offset, si);

		/* file name length */
		proto_tree_add_item_ret_uint(tree, hf_smb2_filename_len, tvb, offset, 4, ENC_LITTLE_ENDIAN, &file_name_len);
		offset += 4;

		/* file name */
		if (file_name_len) {
			proto_tree_add_item(tree, hf_smb2_filename, tvb, offset, file_name_len, ENC_UTF_16|ENC_LITTLE_ENDIAN);
			offset += file_name_len;
		}

		proto_item_set_len(item, offset-old_offset);

		if (next_offset == 0) {
			return;
		}

		offset = old_offset+next_offset;
		if (offset < old_offset) {
			proto_tree_add_expert_format(tree, pinfo, &ei_smb2_invalid_length, tvb, offset, -1,
				    "Invalid offset/length. Malformed packet");
			return;
		}
	}
}


typedef struct _smb2_find_dissector_t {
	guint32	level;
	void (*dissector)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si);
} smb2_find_dissector_t;

static smb2_find_dissector_t smb2_find_dissectors[] = {
	{SMB2_FIND_DIRECTORY_INFO,	dissect_smb2_file_directory_info},
	{SMB2_FIND_FULL_DIRECTORY_INFO, dissect_smb2_full_directory_info},
	{SMB2_FIND_BOTH_DIRECTORY_INFO,	dissect_smb2_both_directory_info},
	{SMB2_FIND_NAME_INFO,		dissect_smb2_file_name_info},
	{SMB2_FIND_ID_BOTH_DIRECTORY_INFO,dissect_smb2_id_both_directory_info},
	{SMB2_FIND_ID_FULL_DIRECTORY_INFO,dissect_smb2_id_full_directory_info},
	{SMB2_FIND_POSIX_INFO,		dissect_smb2_posix_directory_info},
	{0, NULL}
};

static void
dissect_smb2_find_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si)
{
	smb2_find_dissector_t *dis = smb2_find_dissectors;

	while (dis->dissector) {
		if (si && si->saved) {
			if (dis->level == si->saved->infolevel) {
				dis->dissector(tvb, pinfo, tree, si);
				return;
			}
		}
		dis++;
	}

	proto_tree_add_item(tree, hf_smb2_unknown, tvb, 0, tvb_captured_length(tvb), ENC_NA);
}

static int
dissect_smb2_find_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	offset_length_buffer_t olb;
	proto_item *item = NULL;
	gboolean continue_dissection;

	if (si->saved) {
		/* infolevel */
		item = proto_tree_add_uint(tree, hf_smb2_find_info_level, tvb, offset, 0, si->saved->infolevel);
		proto_item_set_generated(item);
	}

	if (!pinfo->fd->visited && si->saved && si->saved->extra_info_type == SMB2_EI_FINDPATTERN) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " %s Pattern: %s",
				val_to_str(si->saved->infolevel, smb2_find_info_levels, "(Level:0x%02x)"),
				(const char *)si->saved->extra_info);

		wmem_free(wmem_file_scope(), si->saved->extra_info);
		si->saved->extra_info_type = SMB2_EI_NONE;
		si->saved->extra_info = NULL;
	}

	switch (si->status) {
	/* buffer code */
	case 0x00000000: offset = dissect_smb2_buffercode(tree, tvb, offset, NULL); break;
	default: offset = dissect_smb2_error_response(tvb, pinfo, tree, offset, si, &continue_dissection);
		if (!continue_dissection) return offset;
	}

	/* findinfo offset */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &olb, OLB_O_UINT16_S_UINT32, hf_smb2_find_info_blob);

	/* the buffer */
	dissect_smb2_olb_buffer(pinfo, tree, tvb, &olb, si, dissect_smb2_find_data);

	offset = dissect_smb2_olb_tvb_max_offset(offset, &olb);

	return offset;
}

static int
dissect_smb2_negotiate_context(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	guint16 type;
	const gchar *type_str;
	guint32 i, data_length, salt_length, hash_count, cipher_count, comp_count, transform_count;
	guint32 signing_count;
	proto_item *sub_item;
	proto_tree *sub_tree;
	static int * const comp_alg_flags_fields[] = {
		&hf_smb2_comp_alg_flags_chained,
		&hf_smb2_comp_alg_flags_reserved,
		NULL
	};

	sub_tree = proto_tree_add_subtree(parent_tree, tvb, offset, -1, ett_smb2_negotiate_context_element, &sub_item, "Negotiate Context");

	/* type */
	type = tvb_get_letohl(tvb, offset);
	type_str = val_to_str(type, smb2_negotiate_context_types, "Unknown Type: (0x%0x)");
	proto_item_append_text(sub_item, ": %s ", type_str);
	proto_tree_add_item(sub_tree, hf_smb2_negotiate_context_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	/* data length */
	proto_tree_add_item_ret_uint(sub_tree, hf_smb2_negotiate_context_data_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, &data_length);
	proto_item_set_len(sub_item, data_length + 8);
	offset += 2;

	/* reserved */
	proto_tree_add_item(sub_tree, hf_smb2_reserved, tvb, offset, 4, ENC_NA);
	offset += 4;

	switch (type)
	{
		case SMB2_PREAUTH_INTEGRITY_CAPABILITIES:
			proto_tree_add_item_ret_uint(sub_tree, hf_smb2_hash_alg_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &hash_count);
			offset += 2;
			proto_tree_add_item_ret_uint(sub_tree, hf_smb2_salt_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, &salt_length);
			offset += 2;

			for (i = 0; i < hash_count; i++)
			{
				proto_tree_add_item(sub_tree, hf_smb2_hash_algorithm, tvb, offset, 2, ENC_LITTLE_ENDIAN);
				offset += 2;
			}

			if (salt_length)
			{
				proto_tree_add_item(sub_tree, hf_smb2_salt, tvb, offset, salt_length, ENC_NA);
				offset += salt_length;
			}
			break;

		case SMB2_ENCRYPTION_CAPABILITIES:
			proto_tree_add_item_ret_uint(sub_tree, hf_smb2_cipher_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &cipher_count);
			offset += 2;

			for (i = 0; i < cipher_count; i ++)
			{
				/* in SMB3.1.1 the first cipher returned by the server session encryption algorithm */
				if (i == 0 && si && si->conv && (si->flags & SMB2_FLAGS_RESPONSE)) {
					guint16 first_cipher = tvb_get_letohs(tvb, offset);
					si->conv->enc_alg = first_cipher;
				}
				proto_tree_add_item(sub_tree, hf_smb2_cipher_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
				offset += 2;
			}
			break;

		case SMB2_COMPRESSION_CAPABILITIES:
			proto_tree_add_item_ret_uint(sub_tree, hf_smb2_comp_alg_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &comp_count);
			offset += 2;

			/* padding */
			offset += 2;

			/* flags */
			proto_tree_add_bitmask(sub_tree, tvb, offset, hf_smb2_comp_alg_flags, ett_smb2_comp_alg_flags, comp_alg_flags_fields, ENC_LITTLE_ENDIAN);
			offset += 4;

			for (i = 0; i < comp_count; i ++) {
				proto_tree_add_item(sub_tree, hf_smb2_comp_alg_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
				offset += 2;
			}
			break;

		case SMB2_NETNAME_NEGOTIATE_CONTEXT_ID:
			proto_tree_add_item(sub_tree, hf_smb2_netname_neg_id, tvb, offset,
					    data_length, ENC_UTF_16|ENC_LITTLE_ENDIAN);
			offset += data_length;
			break;

		case SMB2_TRANSPORT_CAPABILITIES:
			proto_tree_add_item(sub_tree, hf_smb2_transport_ctx_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			break;

		case SMB2_RDMA_TRANSFORM_CAPABILITIES:
			proto_tree_add_item_ret_uint(sub_tree, hf_smb2_rdma_transform_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &transform_count);
			offset += 2;

			proto_tree_add_item(sub_tree, hf_smb2_rdma_transform_reserved1, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
			proto_tree_add_item(sub_tree, hf_smb2_rdma_transform_reserved2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			for (i = 0; i < transform_count; i++) {
				proto_tree_add_item(sub_tree, hf_smb2_rdma_transform_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
				offset += 2;
			}
			break;

		case SMB2_SIGNING_CAPABILITIES:
			proto_tree_add_item_ret_uint(sub_tree, hf_smb2_signing_alg_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &signing_count);
			offset += 2;

			for (i = 0; i < signing_count; i++) {
				/* in SMB3.1.1 the first cipher returned by the server session encryption algorithm */
				if (i == 0 && si && si->conv && (si->flags & SMB2_FLAGS_RESPONSE)) {
					guint16 first_sign_alg = tvb_get_letohs(tvb, offset);
					si->conv->sign_alg = first_sign_alg;
				}
				proto_tree_add_item(sub_tree, hf_smb2_signing_alg_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
				offset += 2;
			}
			break;

		case SMB2_POSIX_EXTENSIONS_CAPABILITIES:
			proto_tree_add_item(sub_tree, hf_smb2_posix_reserved, tvb, offset, data_length, ENC_NA);
			offset += data_length;
			break;

		default:
			proto_tree_add_item(sub_tree, hf_smb2_unknown, tvb, offset, data_length, ENC_NA);
			offset += data_length;
			break;
	}

	return offset;
}

static int
dissect_smb2_negotiate_protocol_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	guint16 dc;
	guint16 i;
	gboolean supports_smb_3_10 = FALSE;
	guint32 nco;
	guint16 ncc;
	proto_item *hash_item = NULL;
	smb2_saved_info_t *ssi = si->saved;

	/* compute preauth hash on first pass */
	if (!pinfo->fd->visited && ssi) {
		ssi->preauth_hash_req = (guint8*)wmem_alloc0(wmem_file_scope(), SMB2_PREAUTH_HASH_SIZE);
		memset(si->conv->preauth_hash_ses, 0, SMB2_PREAUTH_HASH_SIZE);
		memset(si->conv->preauth_hash_con, 0, SMB2_PREAUTH_HASH_SIZE);
		si->conv->preauth_hash_current = si->conv->preauth_hash_con;
		update_preauth_hash(si->conv->preauth_hash_current, pinfo, tvb);
		memcpy(ssi->preauth_hash_req, si->conv->preauth_hash_current, SMB2_PREAUTH_HASH_SIZE);
	}

	if (ssi && ssi->preauth_hash_req) {
		hash_item = proto_tree_add_bytes_with_length(tree,
							     hf_smb2_preauth_hash, tvb,
							     0, tvb_captured_length(tvb),
							     ssi->preauth_hash_req, SMB2_PREAUTH_HASH_SIZE);
		proto_item_set_generated(hash_item);
	}

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* dialect count */
	dc = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_dialect_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	/* security mode, skip second byte */
	offset = dissect_smb2_secmode(tree, tvb, offset);
	offset++;


	/* reserved */
	proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 2, ENC_NA);
	offset += 2;

	/* capabilities */
	offset = dissect_smb2_capabilities(tree, tvb, offset);

	/* client guid */
	proto_tree_add_item(tree, hf_smb2_client_guid, tvb, offset, 16, ENC_LITTLE_ENDIAN);
	offset += 16;

	/* negotiate context offset */
	nco = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_negotiate_context_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* negotiate context count */
	ncc = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_negotiate_context_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	/* reserved */
	proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 2, ENC_NA);
	offset += 2;

	for (i = 0 ; i < dc; i++) {
		guint16 d = tvb_get_letohs(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_dialect, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		if (d >= SMB2_DIALECT_310) {
			supports_smb_3_10 = TRUE;
		}
	}

	if (!supports_smb_3_10) {
		ncc = 0;
	}

	if (nco != 0) {
		guint32 tmp = 0x40 + 36 + dc * 2;

		if (nco >= tmp) {
			offset += nco - tmp;
		} else {
			ncc = 0;
		}
	}

	for (i = 0; i < ncc; i++) {
		offset = WS_ROUNDUP_8(offset);
		offset = dissect_smb2_negotiate_context(tvb, pinfo, tree, offset, si);
	}

	return offset;
}

static int
dissect_smb2_negotiate_protocol_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	offset_length_buffer_t s_olb;
	guint16 i;
	guint32 nco;
	guint16 ncc;
	gboolean continue_dissection;
	proto_item *hash_item = NULL;
	smb2_saved_info_t *ssi = si->saved;

	/* compute preauth hash on first pass */
	if (!pinfo->fd->visited && ssi) {
		ssi->preauth_hash_res = (guint8*)wmem_alloc0(wmem_file_scope(), SMB2_PREAUTH_HASH_SIZE);
		update_preauth_hash(si->conv->preauth_hash_current, pinfo, tvb);
		memcpy(ssi->preauth_hash_res, si->conv->preauth_hash_current, SMB2_PREAUTH_HASH_SIZE);

		/*
		 * All new sessions on this conversation must reuse
		 * the preauth hash value at the time of the negprot
		 * response, so we stash it and switch buffers
		 */
		memcpy(si->conv->preauth_hash_ses, si->conv->preauth_hash_current, SMB2_PREAUTH_HASH_SIZE);
		si->conv->preauth_hash_current = si->conv->preauth_hash_ses;
	}

	if (ssi && ssi->preauth_hash_res) {
		hash_item = proto_tree_add_bytes_with_length(tree,
							     hf_smb2_preauth_hash, tvb,
							     0, tvb_captured_length(tvb),
							     ssi->preauth_hash_res, SMB2_PREAUTH_HASH_SIZE);
		proto_item_set_generated(hash_item);
	}

	switch (si->status) {
	/* buffer code */
	case 0x00000000: offset = dissect_smb2_buffercode(tree, tvb, offset, NULL); break;
	default: offset = dissect_smb2_error_response(tvb, pinfo, tree, offset, si, &continue_dissection);
		if (!continue_dissection) return offset;
	}

	/* security mode, skip second byte */
	offset = dissect_smb2_secmode(tree, tvb, offset);
	offset++;

	/* dialect picked */
	si->conv->dialect = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_dialect, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	/* negotiate context count */
	ncc = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_negotiate_context_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	/* server GUID */
	proto_tree_add_item(tree, hf_smb2_server_guid, tvb, offset, 16, ENC_LITTLE_ENDIAN);
	offset += 16;

	/* capabilities */
	offset = dissect_smb2_capabilities(tree, tvb, offset);

	/* max trans size */
	proto_tree_add_item(tree, hf_smb2_max_trans_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* max read size */
	proto_tree_add_item(tree, hf_smb2_max_read_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* max write size */
	proto_tree_add_item(tree, hf_smb2_max_write_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
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

	/* negotiate context offset */
	nco = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_negotiate_context_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	offset = dissect_smb2_olb_tvb_max_offset(offset, &s_olb);

	if (si->conv->dialect == SMB2_DIALECT_300 || si->conv->dialect == SMB2_DIALECT_302) {
		/* If we know we are decrypting SMB3.0, it must be CCM */
		si->conv->enc_alg = SMB2_CIPHER_AES_128_CCM;
	}

	if (si->conv->dialect >= SMB2_DIALECT_300) {
		/* If we know we are decrypting SMB3.0, it's CMAC by default */
		si->conv->sign_alg = SMB2_SIGNING_ALG_AES_CMAC;
	} else {
		si->conv->sign_alg = SMB2_SIGNING_ALG_HMAC_SHA256;
	}

	if (si->conv->dialect < SMB2_DIALECT_310) {
		ncc = 0;
	}

	if (nco != 0) {
		guint32 tmp = 0x40 + 64 + s_olb.len;

		if (nco >= tmp) {
			offset += nco - tmp;
		} else {
			ncc = 0;
		}
	}

	for (i = 0; i < ncc; i++) {
		offset = WS_ROUNDUP_8(offset);
		offset = dissect_smb2_negotiate_context(tvb, pinfo, tree, offset, si);
	}

	return offset;
}

static const true_false_string tfs_additional_owner = {
	"Requesting OWNER security information",
	"NOT requesting owner security information",
};

static const true_false_string tfs_additional_group = {
	"Requesting GROUP security information",
	"NOT requesting group security information",
};

static const true_false_string tfs_additional_dacl = {
	"Requesting DACL security information",
	"NOT requesting DACL security information",
};

static const true_false_string tfs_additional_sacl = {
	"Requesting SACL security information",
	"NOT requesting SACL security information",
};

static const true_false_string tfs_additional_label = {
	"Requesting integrity label security information",
	"NOT requesting integrity label security information",
};

static const true_false_string tfs_additional_attribute = {
	"Requesting resource attribute security information",
	"NOT requesting resource attribute security information",
};

static const true_false_string tfs_additional_scope = {
	"Requesting central access policy security information",
	"NOT requesting central access policy security information",
};

static const true_false_string tfs_additional_backup = {
	"Requesting backup operation security information",
	"NOT requesting backup operation security information",
};

static int
dissect_additional_information_sec_mask(tvbuff_t *tvb, proto_tree *parent_tree, int offset)
{
	/*	Note that in SMB1 protocol some security flags were not defined yet - see dissect_security_information_mask()
		So for SMB2 we have to use own dissector */
	static int * const flags[] = {
		&hf_smb2_getsetinfo_additional_owner,
		&hf_smb2_getsetinfo_additional_group,
		&hf_smb2_getsetinfo_additional_dacl,
		&hf_smb2_getsetinfo_additional_sacl,
		&hf_smb2_getsetinfo_additional_label,
		&hf_smb2_getsetinfo_additional_attribute,
		&hf_smb2_getsetinfo_additional_scope,
		&hf_smb2_getsetinfo_additional_backup,
		NULL
	};

	proto_tree_add_bitmask(parent_tree, tvb, offset, hf_smb2_getsetinfo_additionals,
		ett_smb2_additional_information_sec_mask, flags, ENC_LITTLE_ENDIAN);
	offset += 4;

	return offset;
}

static int
dissect_smb2_getinfo_parameters(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si)
{
	/* Additional Info */
	switch (si->saved->smb2_class) {
	case SMB2_CLASS_SEC_INFO:
		dissect_additional_information_sec_mask(tvb, tree, offset);
		break;
	default:
		proto_tree_add_item(tree, hf_smb2_getsetinfo_additional, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	}
	offset += 4;

	/* Flags */
	proto_tree_add_item(tree, hf_smb2_getinfo_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	return offset;
}


static int
dissect_smb2_getinfo_buffer_quota(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	guint32 sidlist_len = 0;
	guint32 startsid_len = 0;
	guint32 startsid_offset = 0;

	proto_item *item = NULL;
	proto_tree *tree = NULL;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_query_quota_info, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_query_quota_info);
	}

	proto_tree_add_item(tree, hf_smb2_qq_single, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_smb2_qq_restart, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	/* reserved */
	proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 2, ENC_NA);
	offset += 2;

	proto_tree_add_item_ret_uint(tree, hf_smb2_qq_sidlist_len, tvb, offset, 4, ENC_LITTLE_ENDIAN, &sidlist_len);
	offset += 4;

	proto_tree_add_item_ret_uint(tree, hf_smb2_qq_start_sid_len, tvb, offset, 4, ENC_LITTLE_ENDIAN, &startsid_len);
	offset += 4;

	proto_tree_add_item_ret_uint(tree, hf_smb2_qq_start_sid_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &startsid_offset);
	offset += 4;

	if (sidlist_len != 0) {
		offset = dissect_nt_get_user_quota(tvb, tree, offset, &sidlist_len);
	} else if (startsid_len != 0) {
		offset = dissect_nt_sid(tvb, offset + startsid_offset, tree, "Start SID", NULL, -1);
	}

	return offset;
}

static int
dissect_smb2_class_infolevel(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree, smb2_info_t *si)
{
	guint8		  cl, il;
	proto_item	 *item;
	int		  hfindex;
	value_string_ext *vsx;

	if (si->flags & SMB2_FLAGS_RESPONSE) {
		if (!si->saved) {
			return offset;
		}
		cl = si->saved->smb2_class;
		il = si->saved->infolevel;
	} else {
		cl = tvb_get_guint8(tvb, offset);
		il = tvb_get_guint8(tvb, offset+1);
		if (si->saved) {
			si->saved->smb2_class = cl;
			si->saved->infolevel = il;
		}
	}


	switch (cl) {
	case SMB2_CLASS_FILE_INFO:
		hfindex = hf_smb2_infolevel_file_info;
		vsx = &smb2_file_info_levels_ext;
		break;
	case SMB2_CLASS_FS_INFO:
		hfindex = hf_smb2_infolevel_fs_info;
		vsx = &smb2_fs_info_levels_ext;
		break;
	case SMB2_CLASS_SEC_INFO:
		hfindex = hf_smb2_infolevel_sec_info;
		vsx = &smb2_sec_info_levels_ext;
		break;
	case SMB2_CLASS_QUOTA_INFO:
		/* infolevel is not being used for quota */
		hfindex = hf_smb2_infolevel;
		vsx = NULL;
		break;
	default:
		hfindex = hf_smb2_infolevel;
		vsx = NULL;  /* allowed arg to val_to_str_ext() */
	}


	/* class */
	item = proto_tree_add_uint(tree, hf_smb2_class, tvb, offset, 1, cl);
	if (si->flags & SMB2_FLAGS_RESPONSE) {
		proto_item_set_generated(item);
	}
	/* infolevel */
	item = proto_tree_add_uint(tree, hfindex, tvb, offset+1, 1, il);
	if (si->flags & SMB2_FLAGS_RESPONSE) {
		proto_item_set_generated(item);
	}
	offset += 2;

	if (!(si->flags & SMB2_FLAGS_RESPONSE)) {
		/* Only update COL_INFO for requests. It clutters the
		 * display a bit too much if we do it for replies
		 * as well.
		 */
		col_append_fstr(pinfo->cinfo, COL_INFO, " %s/%s",
				val_to_str(cl, smb2_class_vals, "(Class:0x%02x)"),
				val_to_str_ext(il, vsx, "(Level:0x%02x)"));
	}

	return offset;
}

static int
dissect_smb2_getinfo_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	guint32 getinfo_size = 0;
	guint32 getinfo_offset = 0;
	proto_item *offset_item;

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* class and info level */
	offset = dissect_smb2_class_infolevel(pinfo, tvb, offset, tree, si);

	/* max response size */
	proto_tree_add_item(tree, hf_smb2_max_response_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* offset */
	offset_item = proto_tree_add_item_ret_uint(tree, hf_smb2_getinfo_input_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN, &getinfo_offset);
	offset += 2;

	/* reserved */
	proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 2, ENC_NA);
	offset += 2;

	/* size */
	proto_tree_add_item_ret_uint(tree, hf_smb2_getinfo_input_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &getinfo_size);
	offset += 4;

	/* parameters */
	if (si->saved) {
		offset = dissect_smb2_getinfo_parameters(tvb, pinfo, tree, offset, si);
	} else {
		/* some unknown bytes */
		proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 8, ENC_NA);
		offset += 8;
	}

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

	/* buffer */
	if (si->saved) {
		if (getinfo_size != 0) {
			/*
			 * 2.2.37 says "For quota requests, this MUST be
			 * the length of the contained SMB2_QUERY_QUOTA_INFO
			 * embedded in the request. For FileFullEaInformation
			 * requests, this MUST be set to the length of the
			 * user supplied EA list specified in [MS-FSCC]
			 * section 2.4.15.1. For other information queries,
			 * this field SHOULD be set to 0 and the server MUST
			 * ignore it on receipt.
			 *
			 * This seems to imply that, for requests other
			 * than those to types, we should either completely
			 * ignore a non-zero getinfo_size or should, at
			 * most, add a warning-level expert info at the
			 * protocol level saying that it should be zero,
			 * but not try and interpret it or check its
			 * validity.
			 */
			if (si->saved->smb2_class == SMB2_CLASS_QUOTA_INFO ||
			    (si->saved->smb2_class == SMB2_CLASS_FILE_INFO &&
			     si->saved->infolevel == SMB2_FILE_FULL_EA_INFO)) {
				/*
				 * According to 2.2.37 SMB2 QUERY_INFO
				 * Request in the current MS-SMB2 spec,
				 * these are the only info requests that
				 * have an input buffer.
				 */

				/*
				 * Make sure that the input buffer is after
				 * the fixed-length part of the message.
				 */
				if (getinfo_offset < (guint)offset) {
					expert_add_info(pinfo, offset_item, &ei_smb2_invalid_getinfo_offset);
					return offset;
				}

				/*
				 * Make sure the input buffer is within the
				 * message, i.e. that it's within the tvbuff.
				 *
				 * We check for offset+length overflowing and
				 * for offset+length being beyond the reported
				 * length of the tvbuff.
				 */
				if (getinfo_offset + getinfo_size < getinfo_offset ||
				    getinfo_offset + getinfo_size > tvb_reported_length(tvb)) {
					expert_add_info(pinfo, offset_item, &ei_smb2_invalid_getinfo_size);
					return offset;
				}

				if (si->saved->smb2_class == SMB2_CLASS_QUOTA_INFO) {
					dissect_smb2_getinfo_buffer_quota(tvb, pinfo, tree, getinfo_offset, si);
				} else {
					/*
					 * XXX - handle user supplied EA info.
					 */
					proto_tree_add_item(tree, hf_smb2_unknown, tvb, getinfo_offset, getinfo_size, ENC_NA);
				}
				offset = getinfo_offset + getinfo_size;
			}
		} else {
			/*
			 * The buffer size is 0, meaning it's not present.
			 *
			 * 2.2.37 says "For FileFullEaInformation requests,
			 * the input buffer MUST contain the user supplied
			 * EA list with zero or more FILE_GET_EA_INFORMATION
			 * structures, specified in [MS-FSCC] section
			 * 2.4.15.1.", so it seems that, for a "get full
			 * EA information" request, the size can be zero -
			 * there's no other obvious way for the list to
			 * have zero structures.
			 *
			 * 2.2.37 also says "For quota requests, the input
			 * buffer MUST contain an SMB2_QUERY_QUOTA_INFO,
			 * as specified in section 2.2.37.1."; that seems
			 * to imply that the input buffer must not be empty
			 * in that case.
			 */
			if (si->saved->smb2_class == SMB2_CLASS_QUOTA_INFO)
				expert_add_info(pinfo, offset_item, &ei_smb2_empty_getinfo_buffer);
		}
	}

	return offset;
}

static int
dissect_smb2_infolevel(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si, guint8 smb2_class, guint8 infolevel)
{
	int old_offset = offset;

	switch (smb2_class) {
	case SMB2_CLASS_FILE_INFO:
		switch (infolevel) {
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
		case SMB2_FILE_FULL_EA_INFO:
			offset = dissect_smb2_file_full_ea_info(tvb, pinfo, tree, offset, si);
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
		case SMB2_FILE_NORMALIZED_NAME_INFO:
			offset = dissect_smb2_file_normalized_name_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_POSIX_INFO:
			offset = dissect_smb2_posix_info(tvb, pinfo, tree, offset, si);
			break;
		default:
			/* we don't handle this infolevel yet */
			proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA);
			offset += tvb_captured_length_remaining(tvb, offset);
		}
		break;
	case SMB2_CLASS_FS_INFO:
		switch (infolevel) {
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
			/* we don't handle this infolevel yet */
			proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA);
			offset += tvb_captured_length_remaining(tvb, offset);
		}
		break;
	case SMB2_CLASS_SEC_INFO:
		switch (infolevel) {
		case SMB2_SEC_INFO_00:
			offset = dissect_smb2_sec_info_00(tvb, pinfo, tree, offset, si);
			break;
		default:
			/* we don't handle this infolevel yet */
			proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA);
			offset += tvb_captured_length_remaining(tvb, offset);
		}
		break;
	case SMB2_CLASS_QUOTA_INFO:
		offset = dissect_smb2_quota_info(tvb, pinfo, tree, offset, si);
		break;
	default:
		/* we don't handle this class yet */
		proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_NA);
		offset += tvb_captured_length_remaining(tvb, offset);
	}

	/* if we get BUFFER_OVERFLOW there will be truncated data */
	if (si->status == 0x80000005) {
		proto_item *item;
		item = proto_tree_add_item(tree, hf_smb2_truncated, tvb, old_offset, 0, ENC_NA);
		proto_item_set_generated(item);
	}
	return offset;
}

static void
dissect_smb2_getinfo_response_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si)
{
	/* data */
	if (si->saved) {
		dissect_smb2_infolevel(tvb, pinfo, tree, 0, si, si->saved->smb2_class, si->saved->infolevel);
	} else {
		/* some unknown bytes */
		proto_tree_add_item(tree, hf_smb2_unknown, tvb, 0, tvb_captured_length(tvb), ENC_NA);
	}

}


static int
dissect_smb2_getinfo_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	offset_length_buffer_t olb;
	gboolean continue_dissection;

	/* class/infolevel */
	dissect_smb2_class_infolevel(pinfo, tvb, offset, tree, si);

	switch (si->status) {
	case 0x00000000:
	/* if we get BUFFER_OVERFLOW there will be truncated data */
	case 0x80000005:
	/* if we get BUFFER_TOO_SMALL there will not be any data there, only
	 * a guin32 specifying how big the buffer needs to be
	 */
		/* buffer code */
		offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);
		break;
	case 0xc0000023:
		offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);
		offset = dissect_smb2_olb_length_offset(tvb, offset, &olb, OLB_O_UINT16_S_UINT32, -1);
		proto_tree_add_item(tree, hf_smb2_required_buffer_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		return offset;
	default: offset = dissect_smb2_error_response(tvb, pinfo, tree, offset, si, &continue_dissection);
		if (!continue_dissection) return offset;
	}

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
		flags_item = proto_tree_add_item(tree, hf_smb2_close_flags, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		flags_tree = proto_item_add_subtree(flags_item, ett_smb2_close_flags);
	}
	proto_tree_add_item(flags_tree, hf_smb2_close_pq_attrib, tvb, offset, 2, ENC_LITTLE_ENDIAN);
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
	gboolean continue_dissection;

	switch (si->status) {
	/* buffer code */
	case 0x00000000: offset = dissect_smb2_buffercode(tree, tvb, offset, NULL); break;
	default: offset = dissect_smb2_error_response(tvb, pinfo, tree, offset, si, &continue_dissection);
		if (!continue_dissection) return offset;
	}

	/* close flags */
	if (tree) {
		flags_item = proto_tree_add_item(tree, hf_smb2_close_flags, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		flags_tree = proto_item_add_subtree(flags_item, ett_smb2_close_flags);
	}
	proto_tree_add_item(flags_tree, hf_smb2_close_pq_attrib, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	/* reserved */
	proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 4, ENC_NA);
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
	proto_tree_add_item(tree, hf_smb2_allocation_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;

	/* end of file */
	proto_tree_add_item(tree, hf_smb2_end_of_file, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;

	/* File Attributes */
	offset = dissect_fscc_file_attr(tvb, tree, offset, NULL);

	return offset;
}

static int
dissect_smb2_flush_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 6, ENC_NA);
	offset += 6;

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

	return offset;
}

static int
dissect_smb2_flush_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	gboolean continue_dissection;

	switch (si->status) {
	/* buffer code */
	case 0x00000000: offset = dissect_smb2_buffercode(tree, tvb, offset, NULL); break;
	default: offset = dissect_smb2_error_response(tvb, pinfo, tree, offset, si, &continue_dissection);
		if (!continue_dissection) return offset;
	}

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, ENC_NA);
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
	proto_tree_add_item(tree, hf_smb2_lock_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	/* reserved */
	proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 4, ENC_NA);
	offset += 4;

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

	while (lock_count--) {
		proto_item *lock_item = NULL;
		proto_tree *lock_tree = NULL;
		static int * const lf_fields[] = {
			&hf_smb2_lock_flags_shared,
			&hf_smb2_lock_flags_exclusive,
			&hf_smb2_lock_flags_unlock,
			&hf_smb2_lock_flags_fail_immediately,
			NULL
		};

		if (tree) {
			lock_item = proto_tree_add_item(tree, hf_smb2_lock_info, tvb, offset, 24, ENC_NA);
			lock_tree = proto_item_add_subtree(lock_item, ett_smb2_lock_info);
		}

		/* offset */
		proto_tree_add_item(tree, hf_smb2_file_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		/* count */
		proto_tree_add_item(lock_tree, hf_smb2_lock_length, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		/* flags */
		proto_tree_add_bitmask(lock_tree, tvb, offset, hf_smb2_lock_flags, ett_smb2_lock_flags, lf_fields, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* reserved */
		proto_tree_add_item(lock_tree, hf_smb2_reserved, tvb, offset, 4, ENC_NA);
		offset += 4;
	}

	return offset;
}

static int
dissect_smb2_lock_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	gboolean continue_dissection;

	switch (si->status) {
	/* buffer code */
	case 0x00000000: offset = dissect_smb2_buffercode(tree, tvb, offset, NULL); break;
	default: offset = dissect_smb2_error_response(tvb, pinfo, tree, offset, si, &continue_dissection);
		if (!continue_dissection) return offset;
	}

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, ENC_NA);
	offset += 2;

	return offset;
}
static int
dissect_smb2_cancel_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, ENC_NA);
	offset += 2;

	return offset;
}

static const smb2_fid_info_t *
smb2_pipe_get_fid_info(const smb2_info_t *si)
{
	smb2_fid_info_t *file = NULL;

	if (si == NULL) {
		return NULL;
	}
	if (si->file != NULL) {
		file = si->file;
	} else if (si->saved != NULL) {
		file = si->saved->file;
	}
	if (file == NULL) {
		return NULL;
	}

	return file;
}

static void
smb2_pipe_set_file_id(packet_info *pinfo, smb2_info_t *si)
{
	guint64 persistent;
	const smb2_fid_info_t *file = NULL;

	file = smb2_pipe_get_fid_info(si);
	if (file == NULL) {
		return;
	}

	persistent = GPOINTER_TO_UINT(file);

	dcerpc_set_transport_salt(persistent, pinfo);
}

static gboolean smb2_pipe_reassembly = TRUE;
static gboolean smb2_verify_signatures = FALSE;
static reassembly_table smb2_pipe_reassembly_table;

static int
dissect_file_data_smb2_pipe(tvbuff_t *raw_tvb, packet_info *pinfo, proto_tree *tree _U_, int offset, guint32 datalen, proto_tree *top_tree, void *data)
{
	/*
	 * Note: si is NULL for some callers from packet-smb.c
	 */
	const smb2_info_t *si = (const smb2_info_t *)data;
	gboolean result=0;
	gboolean save_fragmented;
	gint remaining;
	guint reported_len;
	const smb2_fid_info_t *file = NULL;
	guint32 id;
	fragment_head *fd_head;
	tvbuff_t *tvb;
	tvbuff_t *new_tvb;
	proto_item *frag_tree_item;
	heur_dtbl_entry_t *hdtbl_entry;

	file = smb2_pipe_get_fid_info(si);
	id = (guint32)(GPOINTER_TO_UINT(file) & G_MAXUINT32);

	remaining = tvb_captured_length_remaining(raw_tvb, offset);

	tvb = tvb_new_subset_length_caplen(raw_tvb, offset,
			     MIN((int)datalen, remaining),
			     datalen);

	/*
	 * Offer desegmentation service to Named Pipe subdissectors (e.g. DCERPC)
	 * if we have all the data.  Otherwise, reassembly is (probably) impossible.
	 */
	pinfo->can_desegment = 0;
	pinfo->desegment_offset = 0;
	pinfo->desegment_len = 0;
	reported_len = tvb_reported_length(tvb);
	if (smb2_pipe_reassembly && tvb_captured_length(tvb) >= reported_len) {
		pinfo->can_desegment = 2;
	}

	save_fragmented = pinfo->fragmented;

	/*
	 * if we are not offering desegmentation, just try the heuristics
	 *and bail out
	 */
	if (!pinfo->can_desegment) {
		result = dissector_try_heuristic(smb2_pipe_subdissector_list,
						 tvb, pinfo, top_tree,
						 &hdtbl_entry, data);
		goto clean_up_and_exit;
	}

	/* below this line, we know we are doing reassembly */

	/*
	 * this is a new packet, see if we are already reassembling this
	 * pdu and if not, check if the dissector wants us
	 * to reassemble it
	 */
	if (!pinfo->fd->visited) {
		/*
		 * This is the first pass.
		 *
		 * Check if we are already reassembling this PDU or not;
		 * we check for an in-progress reassembly for this FID
		 * in this direction, by searching for its reassembly
		 * structure.
		 */
		fd_head = fragment_get(&smb2_pipe_reassembly_table,
				       pinfo, id, NULL);
		if (!fd_head) {
			/*
			 * No reassembly, so this is a new pdu. check if the
			 * dissector wants us to reassemble it or if we
			 * already got the full pdu in this tvb.
			 */

			/*
			 * Try the heuristic dissectors and see if we
			 * find someone that recognizes this payload.
			 */
			result = dissector_try_heuristic(smb2_pipe_subdissector_list,
							 tvb, pinfo, top_tree,
							 &hdtbl_entry, data);

			/* no this didn't look like something we know */
			if (!result) {
				goto clean_up_and_exit;
			}

			/* did the subdissector want us to reassemble any
			   more data ?
			*/
			if (pinfo->desegment_len) {
				fragment_add_check(&smb2_pipe_reassembly_table,
					tvb, 0, pinfo, id, NULL,
					0, reported_len, TRUE);
				fragment_set_tot_len(&smb2_pipe_reassembly_table,
					pinfo, id, NULL,
					pinfo->desegment_len+reported_len);
			}
			goto clean_up_and_exit;
		}

		/* OK, we're already doing a reassembly for this FID.
		   skip to last segment in the existing reassembly structure
		   and add this fragment there

		   XXX we might add code here to use any offset values
		   we might pick up from the Read/Write calls instead of
		   assuming we always get them in the correct order
		*/
		while (fd_head->next) {
			fd_head = fd_head->next;
		}
		fd_head = fragment_add_check(&smb2_pipe_reassembly_table,
			tvb, 0, pinfo, id, NULL,
			fd_head->offset+fd_head->len,
			reported_len, TRUE);

		/* if we completed reassembly */
		if (fd_head) {
			new_tvb = tvb_new_chain(tvb, fd_head->tvb_data);
			add_new_data_source(pinfo, new_tvb,
				  "Named Pipe over SMB2");
			pinfo->fragmented=FALSE;

			tvb = new_tvb;

			/* list what segments we have */
			show_fragment_tree(fd_head, &smb2_pipe_frag_items,
					   tree, pinfo, tvb, &frag_tree_item);

			/* dissect the full PDU */
			result = dissector_try_heuristic(smb2_pipe_subdissector_list,
							 tvb, pinfo, top_tree,
							 &hdtbl_entry, data);
		}
		goto clean_up_and_exit;
	}

	/*
	 * This is not the first pass; see if it's in the table of
	 * reassembled packets.
	 *
	 * XXX - we know that several of the arguments aren't going to
	 * be used, so we pass bogus variables.  Can we clean this
	 * up so that we don't have to distinguish between the first
	 * pass and subsequent passes?
	 */
	fd_head = fragment_add_check(&smb2_pipe_reassembly_table,
				     tvb, 0, pinfo, id, NULL, 0, 0, TRUE);
	if (!fd_head) {
		/* we didn't find it, try any of the heuristic dissectors
		   and bail out
		*/
		result = dissector_try_heuristic(smb2_pipe_subdissector_list,
						 tvb, pinfo, top_tree,
						 &hdtbl_entry, data);
		goto clean_up_and_exit;
	}
	if (!(fd_head->flags&FD_DEFRAGMENTED)) {
		/* we don't have a fully reassembled frame */
		result = dissector_try_heuristic(smb2_pipe_subdissector_list,
						 tvb, pinfo, top_tree,
						 &hdtbl_entry, data);
		goto clean_up_and_exit;
	}

	/* it is reassembled but it was reassembled in a different frame */
	if (pinfo->num != fd_head->reassembled_in) {
		proto_item *item;
		item = proto_tree_add_uint(top_tree, hf_smb2_pipe_reassembled_in,
					   tvb, 0, 0, fd_head->reassembled_in);
		proto_item_set_generated(item);
		goto clean_up_and_exit;
	}

	/* display the reassembled pdu */
	new_tvb = tvb_new_chain(tvb, fd_head->tvb_data);
	add_new_data_source(pinfo, new_tvb,
		  "Named Pipe over SMB2");
	pinfo->fragmented = FALSE;

	tvb = new_tvb;

	/* list what segments we have */
	show_fragment_tree(fd_head, &smb2_pipe_frag_items,
			   top_tree, pinfo, tvb, &frag_tree_item);

	/* dissect the full PDU */
	result = dissector_try_heuristic(smb2_pipe_subdissector_list,
					 tvb, pinfo, top_tree,
					 &hdtbl_entry, data);

clean_up_and_exit:
	/* clear out the variables */
	pinfo->can_desegment=0;
	pinfo->desegment_offset = 0;
	pinfo->desegment_len = 0;

	if (!result) {
		call_data_dissector(tvb, pinfo, top_tree);
	}

	pinfo->fragmented = save_fragmented;

	offset += datalen;
	return offset;
}

#define SMB2_CHANNEL_NONE		0x00000000
#define SMB2_CHANNEL_RDMA_V1		0x00000001
#define SMB2_CHANNEL_RDMA_V1_INVALIDATE	0x00000002
#define SMB2_CHANNEL_RDMA_TRANSFORM	0x00000003

static const value_string smb2_channel_vals[] = {
	{ SMB2_CHANNEL_NONE,	"None" },
	{ SMB2_CHANNEL_RDMA_V1,	"RDMA V1" },
	{ SMB2_CHANNEL_RDMA_V1_INVALIDATE,	"RDMA V1_INVALIDATE" },
	{ SMB2_CHANNEL_RDMA_TRANSFORM,	"RDMA TRANSFORM" },
	{ 0, NULL }
};

static void
dissect_smb2_rdma_v1_blob(tvbuff_t *tvb, packet_info *pinfo _U_,
			  proto_tree *parent_tree, smb2_info_t *si _U_)
{
	int         offset      = 0;
	int         len;
	int         i;
	int         num;
	proto_tree *sub_tree;
	proto_item *parent_item;

	parent_item = proto_tree_get_parent(parent_tree);

	len = tvb_reported_length(tvb);

	num = len / 16;

	if (parent_item) {
		proto_item_append_text(parent_item, ": SMBDirect Buffer Descriptor V1: (%d elements)", num);
	}

	for (i = 0; i < num; i++) {
		sub_tree = proto_tree_add_subtree(parent_tree, tvb, offset, 8, ett_smb2_rdma_v1, NULL, "RDMA V1");

		proto_tree_add_item(sub_tree, hf_smb2_rdma_v1_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(sub_tree, hf_smb2_rdma_v1_token, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(sub_tree, hf_smb2_rdma_v1_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
	}
}

#define SMB2_WRITE_FLAG_WRITE_THROUGH		0x00000001
#define SMB2_WRITE_FLAG_WRITE_UNBUFFERED	0x00000002

static const true_false_string tfs_write_through = {
	"Client is asking for WRITE_THROUGH",
	"Client is NOT asking for WRITE_THROUGH"
};

static const true_false_string tfs_write_unbuffered = {
	"Client is asking for UNBUFFERED write",
	"Client is NOT asking for UNBUFFERED write"
};

static int
dissect_smb2_write_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	guint16 dataoffset = 0;
	guint32 data_tvb_len;
	offset_length_buffer_t c_olb;
	guint32 channel;
	guint32 length;
	guint64 off;
	static int * const f_fields[] = {
		&hf_smb2_write_flags_write_through,
		&hf_smb2_write_flags_write_unbuffered,
		NULL
	};

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* data offset */
	dataoffset=tvb_get_letohs(tvb,offset);
	proto_tree_add_item(tree, hf_smb2_data_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	/* length */
	length = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_write_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* offset */
	off = tvb_get_letoh64(tvb, offset);
	if (si->saved) si->saved->file_offset=off;
	proto_tree_add_item(tree, hf_smb2_file_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;

	col_append_fstr(pinfo->cinfo, COL_INFO, " Len:%d Off:%" PRIu64, length, off);

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

	/* channel */
	channel = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_channel, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* remaining bytes */
	proto_tree_add_item(tree, hf_smb2_remaining_bytes, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* write channel info blob offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &c_olb, OLB_O_UINT16_S_UINT16, hf_smb2_channel_info_blob);

	/* flags */
	proto_tree_add_bitmask(tree, tvb, offset, hf_smb2_write_flags, ett_smb2_write_flags, f_fields, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* the write channel info blob itself */
	switch (channel) {
	case SMB2_CHANNEL_RDMA_V1:
	case SMB2_CHANNEL_RDMA_V1_INVALIDATE:
		dissect_smb2_olb_buffer(pinfo, tree, tvb, &c_olb, si, dissect_smb2_rdma_v1_blob);
		break;
	case SMB2_CHANNEL_NONE:
	default:
		dissect_smb2_olb_buffer(pinfo, tree, tvb, &c_olb, si, NULL);
		break;
	}

	data_tvb_len=(guint32)tvb_captured_length_remaining(tvb, offset);

	/* data or namedpipe ?*/
	if (length) {
		int oldoffset = offset;
		smb2_pipe_set_file_id(pinfo, si);
		offset = dissect_file_data_smb2_pipe(tvb, pinfo, tree, offset, length, si->top_tree, si);
		if (offset != oldoffset) {
			/* managed to dissect pipe data */
			goto out;
		}
	}

	/* just ordinary data */
	proto_tree_add_item(tree, hf_smb2_write_data, tvb, offset, length, ENC_NA);

	offset += MIN(length,(guint32)tvb_captured_length_remaining(tvb, offset));

	offset = dissect_smb2_olb_tvb_max_offset(offset, &c_olb);

out:
	if (have_tap_listener(smb2_eo_tap) && (data_tvb_len == length)) {
		if (si->saved && si->eo_file_info) { /* without this data we don't know wich file this belongs to */
			feed_eo_smb2(tvb,pinfo,si,dataoffset,length,off);
		}
	}

	return offset;
}


static int
dissect_smb2_write_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	gboolean continue_dissection;

	switch (si->status) {
	/* buffer code */
	case 0x00000000: offset = dissect_smb2_buffercode(tree, tvb, offset, NULL); break;
	default: offset = dissect_smb2_error_response(tvb, pinfo, tree, offset, si, &continue_dissection);
		if (!continue_dissection) return offset;
	}

	/* reserved */
	proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 2, ENC_NA);
	offset += 2;

	/* count */
	proto_tree_add_item(tree, hf_smb2_write_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* remaining, must be set to 0 */
	proto_tree_add_item(tree, hf_smb2_write_remaining, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* write channel info offset */
	proto_tree_add_item(tree, hf_smb2_channel_info_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	/* write channel info length */
	proto_tree_add_item(tree, hf_smb2_channel_info_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	return offset;
}

/* The STORAGE_OFFLOAD_TOKEN is used for "Offload Data Transfer" (ODX) operations,
   including FSCTL_OFFLOAD_READ, FSCTL_OFFLOAD_WRITE.  Ref: MS-FSCC 2.3.79
   Note: Unlike most of SMB2, the token fields are BIG-endian! */
static int
dissect_smb2_STORAGE_OFFLOAD_TOKEN(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_tree *sub_tree;
	proto_item *sub_item;
	guint32 idlen = 0;
	guint32 idtype = 0;

	sub_tree = proto_tree_add_subtree(tree, tvb, offset, 512, ett_smb2_fsctl_odx_token, &sub_item, "Token");

	proto_tree_add_item_ret_uint(sub_tree, hf_smb2_fsctl_odx_token_type, tvb, offset, 4, ENC_BIG_ENDIAN, &idtype);
	offset += 4;

	proto_item_append_text(sub_item, " (IdType 0x%x)", idtype);

	/* reserved */
	proto_tree_add_item(sub_tree, hf_smb2_reserved, tvb, offset, 2, ENC_NA);
	offset += 2;

	/* TokenIdLength */
	proto_tree_add_item_ret_uint(sub_tree, hf_smb2_fsctl_odx_token_idlen, tvb, offset, 2, ENC_BIG_ENDIAN, &idlen);
	offset += 2;

	/* idlen is what the server says is the "meaningful" part of the token.
		However, token ID is always 504 bytes */
	proto_tree_add_bytes_format_value(sub_tree, hf_smb2_fsctl_odx_token_idraw, tvb,
					  offset, idlen, NULL, "Opaque Data");
	offset += 504;

	return (offset);
}

/* MS-FSCC 2.3.77, 2.3.78 */
static void
dissect_smb2_FSCTL_OFFLOAD_READ(tvbuff_t *tvb,
				packet_info *pinfo _U_,
				proto_tree *tree,
				int offset,
				gboolean in)
{
	proto_tree_add_item(tree, hf_smb2_fsctl_odx_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_smb2_fsctl_odx_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	if (in) {
		proto_tree_add_item(tree, hf_smb2_fsctl_odx_token_ttl, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 4, ENC_NA);
		offset += 4;

		proto_tree_add_item(tree, hf_smb2_fsctl_odx_file_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(tree, hf_smb2_fsctl_odx_copy_length, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		/* offset += 8; */
	} else {
		proto_tree_add_item(tree, hf_smb2_fsctl_odx_xfer_length, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		(void) dissect_smb2_STORAGE_OFFLOAD_TOKEN(tvb, pinfo, tree, offset);
	}
}

/* MS-FSCC 2.3.80, 2.3.81 */
static void
dissect_smb2_FSCTL_OFFLOAD_WRITE(tvbuff_t *tvb,
				packet_info *pinfo _U_,
				proto_tree *tree,
				int offset,
				gboolean in)
{
	proto_tree_add_item(tree, hf_smb2_fsctl_odx_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_smb2_fsctl_odx_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	if (in) {
		proto_tree_add_item(tree, hf_smb2_fsctl_odx_file_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(tree, hf_smb2_fsctl_odx_copy_length, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(tree, hf_smb2_fsctl_odx_token_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		dissect_smb2_STORAGE_OFFLOAD_TOKEN(tvb, pinfo, tree, offset);

	} else {
		proto_tree_add_item(tree, hf_smb2_fsctl_odx_xfer_length, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		/* offset += 8; */
	}
}

static void
dissect_smb2_FSCTL_PIPE_TRANSCEIVE(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *top_tree, gboolean data_in _U_, void *data)
{
	dissect_file_data_smb2_pipe(tvb, pinfo, tree, offset, tvb_captured_length_remaining(tvb, offset), top_tree, data);
}

static void
dissect_smb2_FSCTL_PIPE_WAIT(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, int offset, proto_tree *top_tree, gboolean data_in _U_)
{
	int timeout_offset;
	guint32 name_len;
	guint8 timeout_specified;
	char *display_string;

	/* Timeout */
	timeout_offset = offset;
	offset += 8;

	/* Name length */
	/* XXX - put the name length into the tree */
	name_len = tvb_get_letohl(tvb, offset);
	offset += 4;

	/* Timeout specified */
	timeout_specified = tvb_get_guint8(tvb, offset);
	if (timeout_specified) {
		proto_tree_add_item(top_tree, hf_smb2_fsctl_pipe_wait_timeout,
		    tvb, timeout_offset, 8, ENC_LITTLE_ENDIAN);
	}
	offset += 1;

	/* Padding */
	offset += 1;

	/* Name */
	proto_tree_add_item_ret_display_string(top_tree, hf_smb2_fsctl_pipe_wait_name,
	    tvb, offset, name_len, ENC_UTF_16|ENC_LITTLE_ENDIAN,
	    pinfo->pool, &display_string);

	col_append_fstr(pinfo->cinfo, COL_INFO, " Pipe: %s", display_string);
}

static int
dissect_smb2_FSCTL_SET_SPARSE(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean data_in)
{

	/* There is no out data */
	if (!data_in) {
		return offset;
	}

	/* sparse flag (optional) */
	if (tvb_reported_length_remaining(tvb, offset) >= 1) {
		proto_tree_add_item(tree, hf_smb2_fsctl_sparse_flag, tvb, offset, 1, ENC_NA);
		offset += 1;
	}

	return offset;
}

static int
dissect_smb2_FSCTL_SET_ZERO_DATA(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean data_in)
{
	proto_tree *sub_tree;
	proto_item *sub_item;

	/* There is no out data */
	if (!data_in) {
		return offset;
	}

	sub_tree = proto_tree_add_subtree(tree, tvb, offset, 16, ett_smb2_fsctl_range_data, &sub_item, "Range");

	proto_tree_add_item(sub_tree, hf_smb2_fsctl_range_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;

	proto_tree_add_item(sub_tree, hf_smb2_fsctl_range_length, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;

	return offset;
}

static void
dissect_smb2_FSCTL_QUERY_ALLOCATED_RANGES(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int offset _U_, gboolean data_in)
{
	proto_tree *sub_tree;
	proto_item *sub_item;

	if (data_in) {
		sub_tree = proto_tree_add_subtree(tree, tvb, offset, 16, ett_smb2_fsctl_range_data, &sub_item, "Range");

		proto_tree_add_item(sub_tree, hf_smb2_fsctl_range_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(sub_tree, hf_smb2_fsctl_range_length, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;
	} else {
		/* Zero or more allocated ranges may be reported. */
		while (tvb_reported_length_remaining(tvb, offset) >= 16) {

			sub_tree = proto_tree_add_subtree(tree, tvb, offset, 16, ett_smb2_fsctl_range_data, &sub_item, "Range");

			proto_tree_add_item(sub_tree, hf_smb2_fsctl_range_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;

			proto_tree_add_item(sub_tree, hf_smb2_fsctl_range_length, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;
		}
	}
}


static void
dissect_smb2_FSCTL_QUERY_FILE_REGIONS(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int offset _U_, gboolean data_in)
{

	if (data_in) {
		proto_tree_add_item(tree, hf_smb2_file_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(tree, hf_smb2_qfr_length, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(tree, hf_smb2_qfr_usage, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 4, ENC_NA);
		offset += 4;
	} else {
		guint32 entry_count = 0;

		proto_tree_add_item(tree, hf_smb2_qfr_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(tree, hf_smb2_qfr_total_region_entry_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item_ret_uint(tree, hf_smb2_qfr_region_entry_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &entry_count);
		offset += 4;

		proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 4, ENC_NA);
		offset += 4;

		while (entry_count && tvb_reported_length_remaining(tvb, offset)) {
			proto_tree *sub_tree;
			proto_item *sub_item;

			sub_tree = proto_tree_add_subtree(tree, tvb, offset, 24, ett_qfr_entry, &sub_item, "Entry");

			proto_tree_add_item(sub_tree, hf_smb2_file_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;

			proto_tree_add_item(sub_tree, hf_smb2_qfr_length, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;

			proto_tree_add_item(sub_tree, hf_smb2_qfr_usage, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_tree_add_item(sub_tree, hf_smb2_reserved, tvb, offset, 4, ENC_NA);
			offset += 4;

			entry_count--;
		}
	}
}

static void
dissect_smb2_FSCTL_LMR_REQUEST_RESILIENCY(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean data_in)
{
	/* There is no out data */
	if (!data_in) {
		return;
	}

	/* timeout */
	proto_tree_add_item(tree, hf_smb2_ioctl_resiliency_timeout, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* reserved */
	proto_tree_add_item(tree, hf_smb2_ioctl_resiliency_reserved, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

static void
dissect_smb2_FSCTL_QUERY_SHARED_VIRTUAL_DISK_SUPPORT(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean data_in)
{
	/* There is no in data */
	if (data_in) {
		return;
	}

	proto_tree_add_item(tree, hf_smb2_ioctl_shared_virtual_disk_support, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_smb2_ioctl_shared_virtual_disk_handle_state, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

#define STORAGE_QOS_CONTROL_FLAG_SET_LOGICAL_FLOW_ID 0x00000001
#define STORAGE_QOS_CONTROL_FLAG_SET_POLICY 0x00000002
#define STORAGE_QOS_CONTROL_FLAG_PROBE_POLICY 0x00000004
#define STORAGE_QOS_CONTROL_FLAG_GET_STATUS 0x00000008
#define STORAGE_QOS_CONTROL_FLAG_UPDATE_COUNTERS 0x00000010

static const value_string smb2_ioctl_sqos_protocol_version_vals[] = {
	{ 0x0100, "Storage QoS Protocol Version 1.0" },
	{ 0x0101, "Storage QoS Protocol Version 1.1" },
	{ 0, NULL }
};

static const value_string smb2_ioctl_sqos_status_vals[] = {
	{ 0x00, "StorageQoSStatusOk" },
	{ 0x01, "StorageQoSStatusInsufficientThroughput" },
	{ 0x02, "StorageQoSUnknownPolicyId" },
	{ 0x04, "StorageQoSStatusConfigurationMismatch" },
	{ 0x05, "StorageQoSStatusNotAvailable" },
	{ 0, NULL }
};

static void
dissect_smb2_FSCTL_STORAGE_QOS_CONTROL(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, gboolean data_in)
{
	static int * const operations[] = {
		&hf_smb2_ioctl_sqos_op_set_logical_flow_id,
		&hf_smb2_ioctl_sqos_op_set_policy,
		&hf_smb2_ioctl_sqos_op_probe_policy,
		&hf_smb2_ioctl_sqos_op_get_status,
		&hf_smb2_ioctl_sqos_op_update_counters,
		NULL
	};

	gint proto_ver;

	/* Both request and reply have the same common header */

	proto_ver = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_ioctl_sqos_protocol_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_smb2_ioctl_sqos_reserved, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_bitmask(tree, tvb, offset, hf_smb2_ioctl_sqos_options,
							ett_smb2_ioctl_sqos_opeations, operations, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_smb2_ioctl_sqos_logical_flow_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
	offset += 16;

	proto_tree_add_item(tree, hf_smb2_ioctl_sqos_policy_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
	offset += 16;

	proto_tree_add_item(tree, hf_smb2_ioctl_sqos_initiator_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
	offset += 16;

	if (data_in) {
		offset_length_buffer_t host_olb, node_olb;

		proto_tree_add_item(tree, hf_smb2_ioctl_sqos_limit, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(tree, hf_smb2_ioctl_sqos_reservation, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		offset = dissect_smb2_olb_length_offset(tvb, offset, &host_olb, OLB_O_UINT16_S_UINT16, hf_smb2_ioctl_sqos_initiator_name);

		offset = dissect_smb2_olb_length_offset(tvb, offset, &node_olb, OLB_O_UINT16_S_UINT16, hf_smb2_ioctl_sqos_initiator_node_name);

		proto_tree_add_item(tree, hf_smb2_ioctl_sqos_io_count_increment, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(tree, hf_smb2_ioctl_sqos_normalized_io_count_increment, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(tree, hf_smb2_ioctl_sqos_latency_increment, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(tree, hf_smb2_ioctl_sqos_lower_latency_increment, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		if (proto_ver > 0x0100) {
			proto_tree_add_item(tree, hf_smb2_ioctl_sqos_bandwidth_limit, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;

			proto_tree_add_item(tree, hf_smb2_ioctl_sqos_kilobyte_count_increment, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			/*offset += 8;*/
		}

		dissect_smb2_olb_string(pinfo, tree, tvb, &host_olb, OLB_TYPE_UNICODE_STRING);

		dissect_smb2_olb_string(pinfo, tree, tvb, &node_olb, OLB_TYPE_UNICODE_STRING);
	} else {
		proto_tree_add_item(tree, hf_smb2_ioctl_sqos_time_to_live, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(tree, hf_smb2_ioctl_sqos_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(tree, hf_smb2_ioctl_sqos_maximum_io_rate, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(tree, hf_smb2_ioctl_sqos_minimum_io_rate, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(tree, hf_smb2_ioctl_sqos_base_io_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(tree, hf_smb2_ioctl_sqos_reserved2, tvb, offset, 4, ENC_LITTLE_ENDIAN);

		if (proto_ver > 0x0100) {
			offset += 4;
			proto_tree_add_item(tree, hf_smb2_ioctl_sqos_maximum_bandwidth, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		}
	}
}

static int
dissect_windows_sockaddr_in(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, int len)
{
	proto_item *sub_item;
	proto_tree *sub_tree;
	proto_item *parent_item;

	if (len == -1) {
		len = 8;
	}

	sub_tree = proto_tree_add_subtree(parent_tree, tvb, offset, len, ett_windows_sockaddr, &sub_item, "Socket Address");
	parent_item = proto_tree_get_parent(parent_tree);

	/* family */
	proto_tree_add_item(sub_tree, hf_windows_sockaddr_family, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	/* port */
	proto_tree_add_item(sub_tree, hf_windows_sockaddr_port, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	/* IPv4 address */
	proto_tree_add_item(sub_tree, hf_windows_sockaddr_in_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
	proto_item_append_text(sub_item, ", IPv4: %s", tvb_ip_to_str(pinfo->pool, tvb, offset));
	proto_item_append_text(parent_item, ", IPv4: %s", tvb_ip_to_str(pinfo->pool, tvb, offset));
	offset += 4;
	return offset;
}

static int
dissect_windows_sockaddr_in6(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, int len)
{
	proto_item        *sub_item;
	proto_tree        *sub_tree;
	proto_item        *parent_item;

	if (len == -1) {
		len = 26;
	}

	sub_tree = proto_tree_add_subtree(parent_tree, tvb, offset, len, ett_windows_sockaddr, &sub_item, "Socket Address");
	parent_item = proto_tree_get_parent(parent_tree);

	/* family */
	proto_tree_add_item(sub_tree, hf_windows_sockaddr_family, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	/* port */
	proto_tree_add_item(sub_tree, hf_windows_sockaddr_port, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	/* sin6_flowinfo */
	proto_tree_add_item(sub_tree, hf_windows_sockaddr_in6_flowinfo, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* IPv6 address */
	proto_tree_add_item(sub_tree, hf_windows_sockaddr_in6_addr, tvb, offset, 16, ENC_NA);
	proto_item_append_text(sub_item, ", IPv6: %s", tvb_ip6_to_str(pinfo->pool, tvb, offset));
	proto_item_append_text(parent_item, ", IPv6: %s", tvb_ip6_to_str(pinfo->pool, tvb, offset));
	offset += 16;

	/* sin6_scope_id */
	proto_tree_add_item(sub_tree, hf_windows_sockaddr_in6_scope_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	return offset;
}

static int
dissect_windows_sockaddr_storage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset, int len)
{
	proto_item *sub_item;
	proto_tree *sub_tree;
	proto_item *parent_item;
	guint16     family;

	family = tvb_get_letohs(tvb, offset);
	switch (family) {
	case WINSOCK_AF_INET:
		return dissect_windows_sockaddr_in(tvb, pinfo, parent_tree, offset, len);
	case WINSOCK_AF_INET6:
		return dissect_windows_sockaddr_in6(tvb, pinfo, parent_tree, offset, len);
	}

	sub_tree = proto_tree_add_subtree(parent_tree, tvb, offset, len, ett_windows_sockaddr, &sub_item, "Socket Address");
	parent_item = proto_tree_get_parent(parent_tree);

	/* ss_family */
	proto_tree_add_item(sub_tree, hf_windows_sockaddr_family, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	proto_item_append_text(sub_item, ", Family: %d (0x%04x)", family, family);
	proto_item_append_text(parent_item, ", Family: %d (0x%04x)", family, family);
	return offset + len;
}

#define NETWORK_INTERFACE_CAP_RSS 0x00000001
#define NETWORK_INTERFACE_CAP_RDMA 0x00000002

static void
dissect_smb2_NETWORK_INTERFACE_INFO(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	guint32     next_offset;
	int         offset   = 0;
	int         len      = -1;
	proto_item *sub_item;
	proto_tree *sub_tree;
	proto_item *item;
	guint32     capabilities;
	guint64     link_speed;
	gfloat      val      = 0;
	const char *unit     = NULL;
	static int * const capability_flags[] = {
		&hf_smb2_ioctl_network_interface_capability_rdma,
		&hf_smb2_ioctl_network_interface_capability_rss,
		NULL
	};

	next_offset = tvb_get_letohl(tvb, offset);
	if (next_offset) {
		len = next_offset;
	}

	sub_tree = proto_tree_add_subtree(parent_tree, tvb, offset, len, ett_smb2_ioctl_network_interface, &sub_item, "Network Interface");
	item = proto_tree_get_parent(parent_tree);

	/* next offset */
	proto_tree_add_item(sub_tree, hf_smb2_ioctl_network_interface_next_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* interface index */
	proto_tree_add_item(sub_tree, hf_smb2_ioctl_network_interface_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* capabilities */
	capabilities = tvb_get_letohl(tvb, offset);
	proto_tree_add_bitmask(sub_tree, tvb, offset, hf_smb2_ioctl_network_interface_capabilities, ett_smb2_ioctl_network_interface_capabilities, capability_flags, ENC_LITTLE_ENDIAN);

	if (capabilities != 0) {
		proto_item_append_text(item, "%s%s",
				       (capabilities & NETWORK_INTERFACE_CAP_RDMA)?", RDMA":"",
				       (capabilities & NETWORK_INTERFACE_CAP_RSS)?", RSS":"");
		proto_item_append_text(sub_item, "%s%s",
				       (capabilities & NETWORK_INTERFACE_CAP_RDMA)?", RDMA":"",
				       (capabilities & NETWORK_INTERFACE_CAP_RSS)?", RSS":"");
	}
	offset += 4;

	/* rss queue count */
	proto_tree_add_item(sub_tree, hf_smb2_ioctl_network_interface_rss_queue_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* link speed */
	link_speed = tvb_get_letoh64(tvb, offset);
	item = proto_tree_add_item(sub_tree, hf_smb2_ioctl_network_interface_link_speed, tvb, offset, 8, ENC_LITTLE_ENDIAN);
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
	proto_item_append_text(sub_item, ", %.1f %sBits/s", val, unit);

	offset += 8;

	/* socket address */
	dissect_windows_sockaddr_storage(tvb, pinfo, sub_tree, offset, -1);

	if (next_offset) {
		tvbuff_t *next_tvb;
		next_tvb = tvb_new_subset_remaining(tvb, next_offset);

		/* next extra info */
		dissect_smb2_NETWORK_INTERFACE_INFO(next_tvb, pinfo, parent_tree);
	}
}

static void
dissect_smb2_FSCTL_QUERY_NETWORK_INTERFACE_INFO(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset _U_, gboolean data_in)
{
	/* There is no in data */
	if (data_in) {
		return;
	}

	dissect_smb2_NETWORK_INTERFACE_INFO(tvb, pinfo, tree);
}

static void
dissect_smb2_FSCTL_VALIDATE_NEGOTIATE_INFO_224(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset _U_, gboolean data_in)
{
	/*
	 * This is only used by Windows 8 beta
	 */
	if (data_in) {
		/* capabilities */
		offset = dissect_smb2_capabilities(tree, tvb, offset);

		/* client guid */
		proto_tree_add_item(tree, hf_smb2_client_guid, tvb, offset, 16, ENC_LITTLE_ENDIAN);
		offset += 16;

		/* security mode, skip second byte */
		offset = dissect_smb2_secmode(tree, tvb, offset);
		offset++;

		/* dialect */
		proto_tree_add_item(tree, hf_smb2_dialect, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
	} else {
		/* capabilities */
		offset = dissect_smb2_capabilities(tree, tvb, offset);

		/* server guid */
		proto_tree_add_item(tree, hf_smb2_server_guid, tvb, offset, 16, ENC_LITTLE_ENDIAN);
		offset += 16;

		/* security mode, skip second byte */
		offset = dissect_smb2_secmode(tree, tvb, offset);
		offset++;

		/* dialect */
		proto_tree_add_item(tree, hf_smb2_dialect, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
	}
}

static void
dissect_smb2_FSCTL_VALIDATE_NEGOTIATE_INFO(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset _U_, gboolean data_in)
{
	if (data_in) {
		guint16 dc;

		/* capabilities */
		offset = dissect_smb2_capabilities(tree, tvb, offset);

		/* client guid */
		proto_tree_add_item(tree, hf_smb2_client_guid, tvb, offset, 16, ENC_LITTLE_ENDIAN);
		offset += 16;

		/* security mode, skip second byte */
		offset = dissect_smb2_secmode(tree, tvb, offset);
		offset++;

		/* dialect count */
		dc = tvb_get_letohs(tvb, offset);
		proto_tree_add_item(tree, hf_smb2_dialect_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		for ( ; dc>0; dc--) {
			proto_tree_add_item(tree, hf_smb2_dialect, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
	} else {
		/* capabilities */
		offset = dissect_smb2_capabilities(tree, tvb, offset);

		/* server guid */
		proto_tree_add_item(tree, hf_smb2_server_guid, tvb, offset, 16, ENC_LITTLE_ENDIAN);
		offset += 16;

		/* security mode, skip second byte */
		offset = dissect_smb2_secmode(tree, tvb, offset);
		offset++;

		/* dialect */
		proto_tree_add_item(tree, hf_smb2_dialect, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
	}
}

static void
dissect_smb2_FSCTL_SRV_ENUMERATE_SNAPSHOTS(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean data_in)
{
	guint32 num_snapshots;

	/* There is no in data */
	if (data_in) {
		return;
	}

	/* NumberOfSnapShots */
	proto_tree_add_item(tree, hf_smb2_ioctl_enumerate_snapshots_num_snapshots, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* NumberOfSnapshotsReturned */
	proto_tree_add_item_ret_uint(tree, hf_smb2_ioctl_enumerate_snapshots_num_snapshots_returned, tvb, offset, 4, ENC_LITTLE_ENDIAN, &num_snapshots);
	offset += 4;

	/* SnapShotArraySize */
	proto_tree_add_item(tree, hf_smb2_ioctl_enumerate_snapshots_snapshot_array_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	while (num_snapshots--) {
		gint len;
		int old_offset = offset;

		proto_tree_add_item_ret_length(tree, hf_smb2_ioctl_enumerate_snapshots_snapshot,
			tvb, offset, -1, ENC_UTF_16|ENC_LITTLE_ENDIAN, &len);

		offset = old_offset+len;
	}
}

int
dissect_smb2_FILE_OBJECTID_BUFFER(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	/* FILE_OBJECTID_BUFFER */
	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_FILE_OBJECTID_BUFFER, tvb, offset, 64, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_FILE_OBJECTID_BUFFER);
	}

	/* Object ID */
	proto_tree_add_item(tree, hf_smb2_object_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
	offset += 16;

	/* Birth Volume ID */
	proto_tree_add_item(tree, hf_smb2_birth_volume_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
	offset += 16;

	/* Birth Object ID */
	proto_tree_add_item(tree, hf_smb2_birth_object_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
	offset += 16;

	/* Domain ID */
	proto_tree_add_item(tree, hf_smb2_domain_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
	offset += 16;

	return offset;
}

static int
dissect_smb2_FSCTL_CREATE_OR_GET_OBJECT_ID(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean data_in)
{

	/* There is no in data */
	if (data_in) {
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
	if (data_in) {
		return offset;
	}

	/* compression format */
	proto_tree_add_item(tree, hf_smb2_compression_format, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	return offset;
}

static int
dissect_smb2_FSCTL_SET_COMPRESSION(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean data_in)
{

	/* There is no out data */
	if (!data_in) {
		return offset;
	}

	/* compression format */
	proto_tree_add_item(tree, hf_smb2_compression_format, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	return offset;
}

static int
dissect_smb2_FSCTL_SET_INTEGRITY_INFORMATION(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean data_in)
{
	static int * const integrity_flags[] = {
		&hf_smb2_integrity_flags_enforcement_off,
		NULL
	};

	/* There is no out data */
	if (!data_in) {
		return offset;
	}

	proto_tree_add_item(tree, hf_smb2_checksum_algorithm, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_smb2_integrity_reserved, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_bitmask(tree, tvb, offset, hf_smb2_integrity_flags, ett_smb2_integrity_flags, integrity_flags, ENC_LITTLE_ENDIAN);
	offset += 4;

	return offset;
}

static int
dissect_smb2_FSCTL_SET_OBJECT_ID(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean data_in)
{

	/* There is no out data */
	if (!data_in) {
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
	if (!data_in) {
		return offset;
	}

	/* FILE_OBJECTID_BUFFER->ExtendedInfo */

	/* Birth Volume ID */
	proto_tree_add_item(tree, hf_smb2_birth_volume_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
	offset += 16;

	/* Birth Object ID */
	proto_tree_add_item(tree, hf_smb2_birth_object_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
	offset += 16;

	/* Domain ID */
	proto_tree_add_item(tree, hf_smb2_domain_id, tvb, offset, 16, ENC_LITTLE_ENDIAN);
	offset += 16;

	return offset;
}

static int
dissect_smb2_cchunk_RESUME_KEY(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{

	proto_tree_add_bytes_format_value(tree, hf_smb2_cchunk_resume_key, tvb,
					  offset, 24, NULL, "Opaque Data");
	offset += 24;

	return (offset);
}

static void
dissect_smb2_FSCTL_SRV_REQUEST_RESUME_KEY(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean data_in)
{

	/* There is no in data */
	if (data_in) {
		return;
	}

	offset = dissect_smb2_cchunk_RESUME_KEY(tvb, pinfo, tree, offset);

	proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 4, ENC_NA);
}

static void
dissect_smb2_FSCTL_SRV_COPYCHUNK(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean data_in)
{
	proto_tree *sub_tree;
	proto_item *sub_item;
	guint32 chunk_count = 0;

	/* Output is simpler - handle that first. */
	if (!data_in) {
		proto_tree_add_item(tree, hf_smb2_cchunk_chunks_written, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_smb2_cchunk_bytes_written, tvb, offset+4, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_smb2_cchunk_total_written, tvb, offset+8, 4, ENC_LITTLE_ENDIAN);
		return;
	}

	/* Input data, fixed part */
	offset = dissect_smb2_cchunk_RESUME_KEY(tvb, pinfo, tree, offset);
	proto_tree_add_item_ret_uint(tree, hf_smb2_cchunk_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &chunk_count);
	offset += 4;

	proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 4, ENC_NA);
	offset += 4;

	/* Zero or more allocated ranges may be reported. */
	while (chunk_count && tvb_reported_length_remaining(tvb, offset) >= 24) {
		sub_tree = proto_tree_add_subtree(tree, tvb, offset, 24, ett_smb2_cchunk_entry, &sub_item, "Chunk");

		proto_tree_add_item(sub_tree, hf_smb2_cchunk_src_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(sub_tree, hf_smb2_cchunk_dst_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(sub_tree, hf_smb2_cchunk_xfer_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(sub_tree, hf_smb2_reserved, tvb, offset, 4, ENC_NA);
		offset += 4;

		chunk_count--;
	}
}

static void
dissect_smb2_reparse_nfs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint32 length)
{
	guint64 type;
	int symlink_length;

	type = tvb_get_letoh64(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_nfs_type, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;

	switch (type) {
	case NFS_SPECFILE_LNK:
		/*
		 * According to [MS-FSCC] 2.1.2.6 "length" contains
		 * the 8-byte type plus the symlink target in Unicode
		 * non-NULL terminated.
		 */
		if (length < 8) {
			THROW(ReportedBoundsError);
		}
		symlink_length = length - 8;
		proto_tree_add_item(tree, hf_smb2_nfs_symlink_target, tvb, offset,
				      symlink_length, ENC_UTF_16|ENC_LITTLE_ENDIAN);
		break;
	case NFS_SPECFILE_CHR:
		proto_tree_add_item(tree, hf_smb2_nfs_chr_major, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_smb2_nfs_chr_minor, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		break;
	case NFS_SPECFILE_BLK:
		proto_tree_add_item(tree, hf_smb2_nfs_blk_major, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_smb2_nfs_blk_minor, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		break;
	case NFS_SPECFILE_FIFO:
	case NFS_SPECFILE_SOCK:
		/* no data */
		break;
	}
}

static void
dissect_smb2_FSCTL_REPARSE_POINT(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	guint32 tag;
	guint32 length;
	offset_length_buffer_t  s_olb, p_olb;

	/* REPARSE_DATA_BUFFER */
	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_smb2_reparse_data_buffer, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb2_reparse_data_buffer);
	}

	/* reparse tag */
	tag = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_reparse_tag, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* reparse data length */
	length = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_reparse_data_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	/* reserved */
	proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 2, ENC_NA);
	offset += 2;

	if (!(tag & 0x80000000)) {
		/* if high bit is not set, this buffer has a GUID field */
		/* reparse guid */
		proto_tree_add_item(tree, hf_smb2_reparse_guid, tvb, offset, 16, ENC_NA);
		offset += 16;
	}

	switch (tag) {
	case REPARSE_TAG_SYMLINK:
		/* substitute name  offset/length */
		offset = dissect_smb2_olb_length_offset(tvb, offset, &s_olb, OLB_O_UINT16_S_UINT16, hf_smb2_symlink_substitute_name);

		/* print name offset/length */
		offset = dissect_smb2_olb_length_offset(tvb, offset, &p_olb, OLB_O_UINT16_S_UINT16, hf_smb2_symlink_print_name);

		/* flags */
		proto_tree_add_item(tree, hf_smb2_symlink_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* substitute name string */
		dissect_smb2_olb_off_string(pinfo, tree, tvb, &s_olb, offset, OLB_TYPE_UNICODE_STRING);

		/* print name string */
		dissect_smb2_olb_off_string(pinfo, tree, tvb, &p_olb, offset, OLB_TYPE_UNICODE_STRING);
		break;
	case REPARSE_TAG_NFS:
		dissect_smb2_reparse_nfs(tvb, pinfo, tree, offset, length);
		break;
	default:
		proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, length, ENC_NA);
	}
}

static void
dissect_smb2_FSCTL_SET_REPARSE_POINT(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, gboolean data_in)
{
	if (!data_in) {
		return;
	}

	dissect_smb2_FSCTL_REPARSE_POINT(tvb, pinfo, parent_tree, offset);
}

static void
dissect_smb2_FSCTL_GET_REPARSE_POINT(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, gboolean data_in)
{
	if (data_in) {
		return;
	}

	dissect_smb2_FSCTL_REPARSE_POINT(tvb, pinfo, parent_tree, offset);
}

void
dissect_smb2_ioctl_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *top_tree, guint32 ioctl_function, gboolean data_in, void *private_data _U_)
{
	guint16 dc;

	dc = tvb_reported_length(tvb);

	switch (ioctl_function) {
	case 0x00060194: /* FSCTL_DFS_GET_REFERRALS */
		if (data_in) {
			dissect_get_dfs_request_data(tvb, pinfo, tree, 0, &dc, TRUE);
		} else {
			dissect_get_dfs_referral_data(tvb, pinfo, tree, 0, &dc, TRUE);
		}
		break;
	case 0x000940CF: /* FSCTL_QUERY_ALLOCATED_RANGES */
		dissect_smb2_FSCTL_QUERY_ALLOCATED_RANGES(tvb, pinfo, tree, 0, data_in);
		break;
	case 0x00094264: /* FSCTL_OFFLOAD_READ */
		dissect_smb2_FSCTL_OFFLOAD_READ(tvb, pinfo, tree, 0, data_in);
		break;
	case 0x00098268: /* FSCTL_OFFLOAD_WRITE */
		dissect_smb2_FSCTL_OFFLOAD_WRITE(tvb, pinfo, tree, 0, data_in);
		break;
	case 0x0011c017: /* FSCTL_PIPE_TRANSCEIVE */
		dissect_smb2_FSCTL_PIPE_TRANSCEIVE(tvb, pinfo, tree, 0, top_tree, data_in, private_data);
		break;
	case 0x00110018: /* FSCTL_PIPE_WAIT */
		dissect_smb2_FSCTL_PIPE_WAIT(tvb, pinfo, tree, 0, top_tree, data_in);
		break;
	case 0x00140078: /* FSCTL_SRV_REQUEST_RESUME_KEY */
		dissect_smb2_FSCTL_SRV_REQUEST_RESUME_KEY(tvb, pinfo, tree, 0, data_in);
		break;
	case 0x001401D4: /* FSCTL_LMR_REQUEST_RESILIENCY */
		dissect_smb2_FSCTL_LMR_REQUEST_RESILIENCY(tvb, pinfo, tree, 0, data_in);
		break;
	case 0x001401FC: /* FSCTL_QUERY_NETWORK_INTERFACE_INFO */
		dissect_smb2_FSCTL_QUERY_NETWORK_INTERFACE_INFO(tvb, pinfo, tree, 0, data_in);
		break;
	case 0x00140200: /* FSCTL_VALIDATE_NEGOTIATE_INFO_224 */
		dissect_smb2_FSCTL_VALIDATE_NEGOTIATE_INFO_224(tvb, pinfo, tree, 0, data_in);
		break;
	case 0x00140204: /* FSCTL_VALIDATE_NEGOTIATE_INFO */
		dissect_smb2_FSCTL_VALIDATE_NEGOTIATE_INFO(tvb, pinfo, tree, 0, data_in);
		break;
	case 0x00144064: /* FSCTL_SRV_ENUMERATE_SNAPSHOTS */
		dissect_smb2_FSCTL_SRV_ENUMERATE_SNAPSHOTS(tvb, pinfo, tree, 0, data_in);
		break;
	case 0x001440F2: /* FSCTL_SRV_COPYCHUNK */
	case 0x001480F2: /* FSCTL_SRV_COPYCHUNK_WRITE */
		dissect_smb2_FSCTL_SRV_COPYCHUNK(tvb, pinfo, tree, 0, data_in);
		break;
	case 0x000900A4: /* FSCTL_SET_REPARSE_POINT */
		dissect_smb2_FSCTL_SET_REPARSE_POINT(tvb, pinfo, tree, 0, data_in);
		break;
	case 0x000900A8: /* FSCTL_GET_REPARSE_POINT */
		dissect_smb2_FSCTL_GET_REPARSE_POINT(tvb, pinfo, tree, 0, data_in);
		break;
	case 0x0009009C: /* FSCTL_GET_OBJECT_ID */
	case 0x000900c0: /* FSCTL_CREATE_OR_GET_OBJECT_ID */
		dissect_smb2_FSCTL_CREATE_OR_GET_OBJECT_ID(tvb, pinfo, tree, 0, data_in);
		break;
	case 0x000900c4: /* FSCTL_SET_SPARSE */
		dissect_smb2_FSCTL_SET_SPARSE(tvb, pinfo, tree, 0, data_in);
		break;
	case 0x00098098: /* FSCTL_SET_OBJECT_ID */
		dissect_smb2_FSCTL_SET_OBJECT_ID(tvb, pinfo, tree, 0, data_in);
		break;
	case 0x000980BC: /* FSCTL_SET_OBJECT_ID_EXTENDED */
		dissect_smb2_FSCTL_SET_OBJECT_ID_EXTENDED(tvb, pinfo, tree, 0, data_in);
		break;
	case 0x000980C8: /* FSCTL_SET_ZERO_DATA */
		dissect_smb2_FSCTL_SET_ZERO_DATA(tvb, pinfo, tree, 0, data_in);
		break;
	case 0x0009003C: /* FSCTL_GET_COMPRESSION */
		dissect_smb2_FSCTL_GET_COMPRESSION(tvb, pinfo, tree, 0, data_in);
		break;
	case 0x00090300: /* FSCTL_QUERY_SHARED_VIRTUAL_DISK_SUPPORT */
		dissect_smb2_FSCTL_QUERY_SHARED_VIRTUAL_DISK_SUPPORT(tvb, pinfo, tree, 0, data_in);
		break;
	case 0x00090304: /* FSCTL_SVHDX_SYNC_TUNNEL or response */
	case 0x00090364: /* FSCTL_SVHDX_ASYNC_TUNNEL or response */
		call_dissector_with_data(rsvd_handle, tvb, pinfo, top_tree, &data_in);
		break;
	case 0x00090350: /* FSCTL_STORAGE_QOS_CONTROL */
		dissect_smb2_FSCTL_STORAGE_QOS_CONTROL(tvb, pinfo, tree, 0, data_in);
		break;
	case 0x0009C040: /* FSCTL_SET_COMPRESSION */
		dissect_smb2_FSCTL_SET_COMPRESSION(tvb, pinfo, tree, 0, data_in);
		break;
	case 0x00090284: /* FSCTL_QUERY_FILE_REGIONS */
		dissect_smb2_FSCTL_QUERY_FILE_REGIONS(tvb, pinfo, tree, 0, data_in);
		break;
	case 0x0009C280: /* FSCTL_SET_INTEGRITY_INFORMATION request or response */
		dissect_smb2_FSCTL_SET_INTEGRITY_INFORMATION(tvb, pinfo, tree, 0, data_in);
		break;
	default:
		proto_tree_add_item(tree, hf_smb2_unknown, tvb, 0, tvb_captured_length(tvb), ENC_NA);
	}
}

static void
dissect_smb2_ioctl_data_in(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si)
{
	smb2_pipe_set_file_id(pinfo, si);
	dissect_smb2_ioctl_data(tvb, pinfo, tree, si->top_tree, si->ioctl_function, TRUE, si);
}

static void
dissect_smb2_ioctl_data_out(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si)
{
	smb2_pipe_set_file_id(pinfo, si);
	dissect_smb2_ioctl_data(tvb, pinfo, tree, si->top_tree, si->ioctl_function, FALSE, si);
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
	proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 2, ENC_NA);
	offset += 2;

	/* ioctl function */
	offset = dissect_smb2_ioctl_function(tvb, pinfo, tree, offset, &si->ioctl_function);

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

	/* in buffer offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &i_olb, OLB_O_UINT32_S_UINT32, hf_smb2_ioctl_in_data);

	/* max ioctl in size */
	proto_tree_add_item(tree, hf_smb2_max_ioctl_in_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* out buffer offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &o_olb, OLB_O_UINT32_S_UINT32, hf_smb2_ioctl_out_data);

	/* max ioctl out size */
	proto_tree_add_item(tree, hf_smb2_max_ioctl_out_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* flags */
	if (tree) {
		flags_item = proto_tree_add_item(tree, hf_smb2_ioctl_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		flags_tree = proto_item_add_subtree(flags_item, ett_smb2_ioctl_flags);
	}
	proto_tree_add_item(flags_tree, hf_smb2_ioctl_is_fsctl, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* reserved */
	proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 4, ENC_NA);
	offset += 4;

	/* try to decode these blobs in the order they were encoded
	 * so that for "short" packets we will dissect as much as possible
	 * before aborting with "short packet"
	 */
	if (i_olb.off>o_olb.off) {
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
	gboolean continue_dissection;

	switch (si->status) {
	/* buffer code */
	/* if we get BUFFER_OVERFLOW there will be truncated data */
	case 0x80000005:
	case 0x00000000: offset = dissect_smb2_buffercode(tree, tvb, offset, NULL); break;
	default: offset = dissect_smb2_error_response(tvb, pinfo, tree, offset, si, &continue_dissection);
		if (!continue_dissection) return offset;
	}

	/* reserved */
	proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 2, ENC_NA);
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
	proto_tree_add_item(tree, hf_smb2_flags, tvb, offset, 4, ENC_NA);
	offset += 4;

	/* reserved */
	proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 4, ENC_NA);
	offset += 4;

	/* try to decode these blobs in the order they were encoded
	 * so that for "short" packets we will dissect as much as possible
	 * before aborting with "short packet"
	 */
	if (i_olb.off>o_olb.off) {
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


#define SMB2_READFLAG_READ_UNBUFFERED 0x01
#define SMB2_READFLAG_READ_COMPRESSED 0x02

static const true_false_string tfs_read_unbuffered = {
	"Client is asking for UNBUFFERED read",
	"Client is NOT asking for UNBUFFERED read"
};

static const true_false_string tfs_read_compressed = {
	"Client is asking for COMPRESSED data",
	"Client is NOT asking for COMPRESSED data"
};

static int
dissect_smb2_read_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	offset_length_buffer_t c_olb;
	guint32 channel;
	guint32 len;
	guint64 off;

	static int * const flags[] = {
	     &hf_smb2_read_flags_unbuffered,
	     &hf_smb2_read_flags_compressed,
	     NULL
	};

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* padding */
	proto_tree_add_item(tree, hf_smb2_read_padding, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	/* flags */
	proto_tree_add_bitmask(tree, tvb, offset, hf_smb2_read_flags,
			       ett_smb2_read_flags, flags, ENC_LITTLE_ENDIAN);
	offset += 1;

	/* length */
	len = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_read_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* offset */
	off = tvb_get_letoh64(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_file_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;

	col_append_fstr(pinfo->cinfo, COL_INFO, " Len:%d Off:%" PRIu64, len, off);

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

	/* minimum count */
	proto_tree_add_item(tree, hf_smb2_min_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* channel */
	channel = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_channel, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* remaining bytes */
	proto_tree_add_item(tree, hf_smb2_remaining_bytes, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* read channel info blob offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &c_olb, OLB_O_UINT16_S_UINT16, hf_smb2_channel_info_blob);

	/* the read channel info blob itself */
	switch (channel) {
	case SMB2_CHANNEL_RDMA_V1:
	case SMB2_CHANNEL_RDMA_V1_INVALIDATE:
		dissect_smb2_olb_buffer(pinfo, tree, tvb, &c_olb, si, dissect_smb2_rdma_v1_blob);
		break;
	case SMB2_CHANNEL_NONE:
	default:
		dissect_smb2_olb_buffer(pinfo, tree, tvb, &c_olb, si, NULL);
		break;
	}

	offset = dissect_smb2_olb_tvb_max_offset(offset, &c_olb);

	/* Store len and offset */
	if (si->saved) {
		si->saved->file_offset=off;
		si->saved->bytes_moved=len;
	}

	return offset;
}

static void
dissect_smb2_read_blob(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si)
{
	gint offset = 0;
	gint length = tvb_captured_length_remaining(tvb, offset);

	smb2_pipe_set_file_id(pinfo, si);

	offset = dissect_file_data_smb2_pipe(tvb, pinfo, tree, offset, length, si->top_tree, si);
	if (offset != 0) {
		/* managed to dissect pipe data */
		return;
	}

	/* data */
	proto_tree_add_item(tree, hf_smb2_read_data, tvb, offset, length, ENC_NA);
}

static int
dissect_smb2_read_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	offset_length_buffer_t olb;
	guint32 data_tvb_len;
	gboolean continue_dissection;

	switch (si->status) {
	/* buffer code */
	case 0x00000000: offset = dissect_smb2_buffercode(tree, tvb, offset, NULL); break;
	default: offset = dissect_smb2_error_response(tvb, pinfo, tree, offset, si, &continue_dissection);
		if (!continue_dissection) return offset;
	}

	/* data offset 8 bit, 8 bit reserved, length 32bit */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &olb,
						OLB_O_UINT8_P_UINT8_S_UINT32,
						hf_smb2_read_blob);

	/* remaining */
	proto_tree_add_item(tree, hf_smb2_read_remaining, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* reserved */
	proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 4, ENC_NA);
	offset += 4;

	data_tvb_len=(guint32)tvb_captured_length_remaining(tvb, offset);

	dissect_smb2_olb_buffer(pinfo, tree, tvb, &olb, si, dissect_smb2_read_blob);

	offset += MIN(olb.len, data_tvb_len);

	if (have_tap_listener(smb2_eo_tap) && (data_tvb_len == olb.len)) {
		if (si->saved && si->eo_file_info) { /* without this data we don't know wich file this belongs to */
			feed_eo_smb2(tvb,pinfo,si,olb.off,olb.len,si->saved->file_offset);
		}
	}

	return offset;
}

static void
report_create_context_malformed_buffer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const char *buffer_desc)
{
	proto_tree_add_expert_format(tree, pinfo, &ei_smb2_bad_response, tvb, 0, -1,
			    "%s SHOULD NOT be generated", buffer_desc);
}
static void
dissect_smb2_ExtA_buffer_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si)
{
	proto_item *item = NULL;
	if (tree) {
		item = proto_tree_get_parent(tree);
		proto_item_append_text(item, ": SMB2_FILE_FULL_EA_INFO");
	}
	dissect_smb2_file_full_ea_info(tvb, pinfo, tree, 0, si);
}

static void
dissect_smb2_ExtA_buffer_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si _U_)
{
	report_create_context_malformed_buffer(tvb, pinfo, tree, "ExtA Response");
}

static void
dissect_smb2_SecD_buffer_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si)
{
	proto_item *item = NULL;
	if (tree) {
		item = proto_tree_get_parent(tree);
		proto_item_append_text(item, ": SMB2_SEC_INFO_00");
	}
	dissect_smb2_sec_info_00(tvb, pinfo, tree, 0, si);
}

static void
dissect_smb2_SecD_buffer_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si _U_)
{
	report_create_context_malformed_buffer(tvb, pinfo, tree, "SecD Response");
}

/*
 * Add the timestamp to the info column and to the name of the file if
 * we have not visited this packet before.
 */
static void
add_timestamp_to_info_col(tvbuff_t *tvb, packet_info *pinfo, smb2_info_t *si,
			  int offset)
{
	guint32 filetime_high, filetime_low;
	guint64 ft;
	nstime_t ts;

	filetime_low = tvb_get_letohl(tvb, offset);
	filetime_high = tvb_get_letohl(tvb, offset + 4);

	ft = ((guint64)filetime_high << 32) | filetime_low;
	if (!filetime_to_nstime(&ts, ft)) {
		return;
	}

	col_append_fstr(pinfo->cinfo, COL_INFO, "@%s",
            abs_time_to_str(pinfo->pool, &ts, ABSOLUTE_TIME_UTC,
		            FALSE));

	/* Append the timestamp */
	if (!pinfo->fd->visited) {
		if (si->saved && si->saved->extra_info_type == SMB2_EI_FILENAME) {
			gchar *saved_name = (gchar *)si->saved->extra_info;
			gulong len = (gulong)strlen(saved_name);

			si->saved->extra_info = (gchar *)wmem_alloc(wmem_file_scope(), len + 32 + 1);
			snprintf((gchar *)si->saved->extra_info,
				   len + 32 + 1 , "%s@%s", (char *)saved_name,
				   abs_time_to_str(pinfo->pool, &ts,
					           ABSOLUTE_TIME_UTC, FALSE));
			wmem_free(wmem_file_scope(), saved_name);
		}
	}
}

static void
dissect_smb2_TWrp_buffer_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, smb2_info_t *si _U_)
{
	proto_item *item = NULL;
	if (tree) {
		item = proto_tree_get_parent(tree);
		proto_item_append_text(item, ": Timestamp");
	}
	add_timestamp_to_info_col(tvb, pinfo, si, 0);
	dissect_nt_64bit_time(tvb, tree, 0, hf_smb2_twrp_timestamp);
}

static void
dissect_smb2_TWrp_buffer_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, smb2_info_t *si _U_)
{
	report_create_context_malformed_buffer(tvb, pinfo, tree, "TWrp Response");
}

static void
dissect_smb2_QFid_buffer_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, smb2_info_t *si _U_)
{
	proto_item *item = NULL;

	if (tree) {
		item = proto_tree_get_parent(tree);
	}

	if (item) {
		if (tvb_reported_length(tvb) == 0) {
			proto_item_append_text(item, ": NO DATA");
		} else {
			proto_item_append_text(item, ": QFid request should have no data, malformed packet");
		}
	}
}

static void
dissect_smb2_QFid_buffer_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, smb2_info_t *si _U_)
{
	int         offset   = 0;
	proto_item *item;
	proto_item *sub_tree;

	item = proto_tree_get_parent(tree);

	proto_item_append_text(item, ": QFid INFO");
	sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_smb2_QFid_buffer, NULL, "QFid INFO");

	proto_tree_add_item(sub_tree, hf_smb2_qfid_fid, tvb, offset, 32, ENC_NA);
}

static void
dissect_smb2_AlSi_buffer_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, smb2_info_t *si _U_)
{
	proto_tree_add_item(tree, hf_smb2_allocation_size, tvb, 0, 8, ENC_LITTLE_ENDIAN);
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
	proto_tree_add_item(tree, hf_smb2_dhnq_buffer_reserved, tvb, 0, 8, ENC_LITTLE_ENDIAN);
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
	static int * const dh2x_flags_fields[] = {
		&hf_smb2_dh2x_buffer_flags_persistent_handle,
		NULL
	};
	int         offset   = 0;
	proto_item *item;
	proto_item *sub_tree;

	item = proto_tree_get_parent(tree);

	proto_item_append_text(item, ": DH2Q Request");
	sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_smb2_DH2Q_buffer, NULL, "DH2Q Request");

	/* timeout */
	proto_tree_add_item(sub_tree, hf_smb2_dh2x_buffer_timeout, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* flags */
	proto_tree_add_bitmask(sub_tree, tvb, offset, hf_smb2_dh2x_buffer_flags,
				ett_smb2_dh2x_flags, dh2x_flags_fields, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* reserved */
	proto_tree_add_item(sub_tree, hf_smb2_dh2x_buffer_reserved, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;

	/* create guid */
	proto_tree_add_item(sub_tree, hf_smb2_dh2x_buffer_create_guid, tvb, offset, 16, ENC_LITTLE_ENDIAN);
}

static void
dissect_smb2_DH2Q_buffer_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, smb2_info_t *si _U_)
{
	int         offset   = 0;
	proto_item *item;
	proto_item *sub_tree;

	item = proto_tree_get_parent(tree);

	proto_item_append_text(item, ": DH2Q Response");
	sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_smb2_DH2Q_buffer, NULL, "DH2Q Response");

	/* timeout */
	proto_tree_add_item(sub_tree, hf_smb2_dh2x_buffer_timeout, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* flags */
	proto_tree_add_item(sub_tree, hf_smb2_dh2x_buffer_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

static void
dissect_smb2_DH2C_buffer_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si)
{
	int         offset   = 0;
	proto_item *item;
	proto_item *sub_tree;

	item = proto_tree_get_parent(tree);

	proto_item_append_text(item, ": DH2C Request");
	sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_smb2_DH2C_buffer, NULL, "DH2C Request");

	/* file id */
	dissect_smb2_fid(tvb, pinfo, sub_tree, offset, si, FID_MODE_DHNC);
	offset += 16;

	/* create guid */
	proto_tree_add_item(sub_tree, hf_smb2_dh2x_buffer_create_guid, tvb, offset, 16, ENC_LITTLE_ENDIAN);
	offset += 16;

	/* flags */
	proto_tree_add_item(sub_tree, hf_smb2_dh2x_buffer_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

static void
dissect_smb2_DH2C_buffer_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si _U_)
{
	report_create_context_malformed_buffer(tvb, pinfo, tree, "DH2C Response");
}

static void
dissect_smb2_MxAc_buffer_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, smb2_info_t *si _U_)
{
	int	    offset = 0;
	proto_item *item   = NULL;

	if (tree) {
		item = proto_tree_get_parent(tree);
	}

	if (tvb_reported_length(tvb) == 0) {
		if (item) {
			proto_item_append_text(item, ": NO DATA");
		}
		return;
	}

	if (item) {
		proto_item_append_text(item, ": Timestamp");
	}

	dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_mxac_timestamp);
}

static void
dissect_smb2_MxAc_buffer_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, smb2_info_t *si _U_)
{
	int         offset   = 0;
	proto_item *item;
	proto_tree *sub_tree;

	item = proto_tree_get_parent(tree);

	if (tvb_reported_length(tvb) == 0) {
		proto_item_append_text(item, ": NO DATA");
		return;
	}

	proto_item_append_text(item, ": MxAc INFO");
	sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_smb2_MxAc_buffer, NULL, "MxAc INFO");

	proto_tree_add_item(sub_tree, hf_smb2_mxac_status, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	dissect_smb_access_mask(tvb, sub_tree, offset);
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
 * 16 - parent lease key
 *  2 - epoch
 *  2 - reserved
 */
#define SMB2_LEASE_STATE_READ_CACHING   0x00000001
#define SMB2_LEASE_STATE_HANDLE_CACHING 0x00000002
#define SMB2_LEASE_STATE_WRITE_CACHING  0x00000004

#define SMB2_LEASE_FLAGS_BREAK_ACK_REQUIRED    0x00000001
#define SMB2_LEASE_FLAGS_BREAK_IN_PROGRESS     0x00000002
#define SMB2_LEASE_FLAGS_PARENT_LEASE_KEY_SET  0x00000004

static int * const lease_state_fields[] = {
	&hf_smb2_lease_state_read_caching,
	&hf_smb2_lease_state_handle_caching,
	&hf_smb2_lease_state_write_caching,
	NULL
};
static int * const lease_flags_fields[] = {
	&hf_smb2_lease_flags_break_ack_required,
	&hf_smb2_lease_flags_break_in_progress,
	&hf_smb2_lease_flags_parent_lease_key_set,
	NULL
};

static void
dissect_SMB2_CREATE_LEASE_VX(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, smb2_info_t *si _U_)
{
	int         offset      = 0;
	int         len;
	proto_tree *sub_tree    = NULL;
	proto_item *parent_item;

	parent_item = proto_tree_get_parent(parent_tree);

	len = tvb_reported_length(tvb);

	switch (len) {
	case 32: /* SMB2_CREATE_REQUEST/RESPONSE_LEASE */
		proto_item_append_text(parent_item, ": LEASE_V1");
		sub_tree = proto_tree_add_subtree(parent_tree, tvb, offset, -1, ett_smb2_RqLs_buffer, NULL, "LEASE_V1");
		break;
	case 52: /* SMB2_CREATE_REQUEST/RESPONSE_LEASE_V2 */
		proto_item_append_text(parent_item, ": LEASE_V2");
		sub_tree = proto_tree_add_subtree(parent_tree, tvb, offset, -1, ett_smb2_RqLs_buffer, NULL, "LEASE_V2");
		break;
	default:
		report_create_context_malformed_buffer(tvb, pinfo, parent_tree, "RqLs");
		break;
	}

	proto_tree_add_item(sub_tree, hf_smb2_lease_key, tvb, offset, 16, ENC_LITTLE_ENDIAN);
	offset += 16;

	proto_tree_add_bitmask(sub_tree, tvb, offset, hf_smb2_lease_state,
			       ett_smb2_lease_state, lease_state_fields, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_bitmask(sub_tree, tvb, offset, hf_smb2_lease_flags,
			       ett_smb2_lease_flags, lease_flags_fields, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(sub_tree, hf_smb2_lease_duration, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;

	if (len < 52) {
		return;
	}

	proto_tree_add_item(sub_tree, hf_smb2_parent_lease_key, tvb, offset, 16, ENC_LITTLE_ENDIAN);
	offset += 16;

	proto_tree_add_item(sub_tree, hf_smb2_lease_epoch, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(sub_tree, hf_smb2_lease_reserved, tvb, offset, 2, ENC_LITTLE_ENDIAN);
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
	int         offset   = 0;
	proto_item *item;
	proto_item *sub_tree;

	item = proto_tree_get_parent(tree);

	proto_item_append_text(item, ": CREATE APP INSTANCE ID");
	sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_smb2_APP_INSTANCE_buffer, NULL, "APP INSTANCE ID");

	/* struct size */
	proto_tree_add_item(sub_tree, hf_smb2_APP_INSTANCE_buffer_struct_size,
			    tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	/* reserved */
	proto_tree_add_item(sub_tree, hf_smb2_APP_INSTANCE_buffer_reserved,
			    tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	/* create guid */
	proto_tree_add_item(sub_tree, hf_smb2_APP_INSTANCE_buffer_app_guid, tvb, offset, 16, ENC_LITTLE_ENDIAN);
}

static void
dissect_smb2_APP_INSTANCE_buffer_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, smb2_info_t *si _U_)
{
	report_create_context_malformed_buffer(tvb, pinfo, tree, "APP INSTANCE Response");
}

/*
 * Dissect the MS-RSVD stuff that turns up when HyperV uses SMB3.x
 */
static void
dissect_smb2_svhdx_open_device_context(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, smb2_info_t *si _U_)
{
	int offset = 0;
	guint32 version;
	proto_item *item;
	proto_item *sub_tree;

	item = proto_tree_get_parent(tree);

	proto_item_append_text(item, ": SVHDX OPEN DEVICE CONTEXT");
	sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_smb2_svhdx_open_device_context, NULL, "SVHDX OPEN DEVICE CONTEXT");

	/* Version */
	proto_tree_add_item_ret_uint(sub_tree, hf_smb2_svhdx_open_device_context_version,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN, &version);
	offset += 4;

	/* HasInitiatorId */
	proto_tree_add_item(sub_tree, hf_smb2_svhdx_open_device_context_has_initiator_id,
			    tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	/* Reserved */
	proto_tree_add_item(sub_tree, hf_smb2_svhdx_open_device_context_reserved,
			    tvb, offset, 3, ENC_NA);
	offset += 3;

	/* InitiatorId */
	proto_tree_add_item(sub_tree, hf_smb2_svhdx_open_device_context_initiator_id,
			    tvb, offset, 16, ENC_LITTLE_ENDIAN);
	offset += 16;

	/* Flags TODO: Dissect these*/
	proto_tree_add_item(sub_tree, hf_smb2_svhdx_open_device_context_flags,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* OriginatorFlags */
	proto_tree_add_item(sub_tree, hf_smb2_svhdx_open_device_context_originator_flags,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* OpenRequestId */
	proto_tree_add_item(sub_tree, hf_smb2_svhdx_open_device_context_open_request_id,
			    tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;

	/* InitiatorHostNameLength */
	proto_tree_add_item(sub_tree, hf_smb2_svhdx_open_device_context_initiator_host_name_len,
			    tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	/* InitiatorHostName */
	proto_tree_add_item(sub_tree, hf_smb2_svhdx_open_device_context_initiator_host_name,
			    tvb, offset, 126, ENC_ASCII | ENC_NA);
	offset += 126;

	if (version == 2) {
		/* VirtualDiskPropertiesInitialized */
		proto_tree_add_item(sub_tree, hf_smb2_svhdx_open_device_context_virtual_disk_properties_initialized,
					tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* ServerServiceVersion */
		proto_tree_add_item(sub_tree, hf_smb2_svhdx_open_device_context_server_service_version,
					tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* VirtualSectorSize */
		proto_tree_add_item(sub_tree, hf_smb2_svhdx_open_device_context_virtual_sector_size,
					tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* PhysicalSectorSize */
		proto_tree_add_item(sub_tree, hf_smb2_svhdx_open_device_context_physical_sector_size,
					tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* VirtualSize */
		proto_tree_add_item(sub_tree, hf_smb2_svhdx_open_device_context_virtual_size,
					tvb, offset, 8, ENC_LITTLE_ENDIAN);
	}
}

/*
 * SMB2_CREATE_APP_INSTANCE_VERSION
 *  2 - structure size - 24
 *  2 - reserved
 *  4 - padding
 *  8 - AppInstanceVersionHigh
 *  8 - AppInstanceVersionHigh
 */

static void
dissect_smb2_app_instance_version_buffer_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, smb2_info_t *si _U_)
{
	int         offset   = 0;
	proto_item *item;
	proto_item *sub_tree;
	proto_item *version_sub_tree;
	guint64 	version_high;
	guint64 	version_low;

	item = proto_tree_get_parent(tree);

	proto_item_append_text(item, ": CREATE APP INSTANCE VERSION");
	sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_smb2_app_instance_version_buffer, NULL, "APP INSTANCE VERSION");

	/* struct size */
	proto_tree_add_item(sub_tree, hf_smb2_app_instance_version_struct_size,
			    tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	/* reserved */
	proto_tree_add_item(sub_tree, hf_smb2_app_instance_version_reserved,
			    tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	/* padding */
	proto_tree_add_item(sub_tree, hf_smb2_app_instance_version_padding,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	version_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_smb2_app_instance_version_buffer_version, NULL, "version");

	/* version high */
	proto_tree_add_item_ret_uint64(version_sub_tree, hf_smb2_app_instance_version_high,
			    tvb, offset, 8, ENC_LITTLE_ENDIAN, &version_high);
	offset += 8;

	/* version low */
	proto_tree_add_item_ret_uint64(version_sub_tree, hf_smb2_app_instance_version_low,
			    tvb, offset, 8, ENC_LITTLE_ENDIAN, &version_low);

	proto_item_append_text(version_sub_tree, " : %" PRIu64 ".%" PRIu64, version_high, version_low);
	proto_item_append_text(sub_tree, ", version: %" PRIu64 ".%" PRIu64, version_high, version_low);
}

static void
dissect_smb2_app_instance_version_buffer_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, smb2_info_t *si _U_)
{
	report_create_context_malformed_buffer(tvb, pinfo, tree, "APP INSTANCE Version Response");
}

static void
dissect_smb2_posix_buffer_request(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, smb2_info_t *si _U_)
{
	int offset = 0;
	proto_item *item;

	item = proto_tree_get_parent(tree);
	proto_item_append_text(item, ": POSIX Create Context request");

	/* POSIX mode bits */
	proto_tree_add_item(tree, hf_smb2_posix_perms, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

static void
dissect_smb2_posix_buffer_response(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, smb2_info_t *si _U_)
{
	int offset = 0;
	proto_item *item;

	item = proto_tree_get_parent(tree);
	proto_item_append_text(item, ": POSIX Create Context response");

	/* Hardlinks */
	proto_tree_add_item(tree, hf_smb2_nlinks, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* Reparse tag */
	proto_tree_add_item(tree, hf_smb2_reparse_tag, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* POSIX mode bits */
	proto_tree_add_item(tree, hf_smb2_posix_perms, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* Owner and Group SID */
	offset = dissect_nt_sid(tvb, offset, tree, "Owner SID", NULL, -1);
	dissect_nt_sid(tvb, offset, tree, "Group SID", NULL, -1);
}

#define SMB2_AAPL_SERVER_QUERY	1
#define SMB2_AAPL_RESOLVE_ID	2

static const value_string aapl_command_code_vals[] = {
	{ SMB2_AAPL_SERVER_QUERY,	"Server query"},
	{ SMB2_AAPL_RESOLVE_ID,		"Resolve ID"},
	{ 0, NULL }
};

#define SMB2_AAPL_SERVER_CAPS		0x00000001
#define SMB2_AAPL_VOLUME_CAPS		0x00000002
#define SMB2_AAPL_MODEL_INFO		0x00000004

static int * const aapl_server_query_bitmap_fields[] = {
	&hf_smb2_aapl_server_query_bitmask_server_caps,
	&hf_smb2_aapl_server_query_bitmask_volume_caps,
	&hf_smb2_aapl_server_query_bitmask_model_info,
	NULL
};

#define SMB2_AAPL_SUPPORTS_READ_DIR_ATTR	0x00000001
#define SMB2_AAPL_SUPPORTS_OSX_COPYFILE		0x00000002
#define SMB2_AAPL_UNIX_BASED			0x00000004
#define SMB2_AAPL_SUPPORTS_NFS_ACE		0x00000008

static int * const aapl_server_query_caps_fields[] = {
	&hf_smb2_aapl_server_query_caps_supports_read_dir_attr,
	&hf_smb2_aapl_server_query_caps_supports_osx_copyfile,
	&hf_smb2_aapl_server_query_caps_unix_based,
	&hf_smb2_aapl_server_query_caps_supports_nfs_ace,
	NULL
};

static void
dissect_smb2_AAPL_buffer_request(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, smb2_info_t *si _U_)
{
	int         offset   = 0;
	proto_item *item;
	proto_item *sub_tree;
	guint32     command_code;

	item = proto_tree_get_parent(tree);

	proto_item_append_text(item, ": AAPL Create Context request");
	sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_smb2_aapl_create_context_request, NULL, "AAPL Create Context request");

	/* Command code */
	proto_tree_add_item_ret_uint(sub_tree, hf_smb2_aapl_command_code,
	    tvb, offset, 4, ENC_LITTLE_ENDIAN, &command_code);
	offset += 4;

	/* Reserved */
	proto_tree_add_item(sub_tree, hf_smb2_aapl_reserved,
	    tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	switch (command_code) {

	case SMB2_AAPL_SERVER_QUERY:
		/* Request bitmap */
		proto_tree_add_bitmask(sub_tree, tvb, offset,
				       hf_smb2_aapl_server_query_bitmask,
				       ett_smb2_aapl_server_query_bitmask,
				       aapl_server_query_bitmap_fields,
				       ENC_LITTLE_ENDIAN);
		offset += 8;

		/* Client capabilities */
		proto_tree_add_bitmask(sub_tree, tvb, offset,
				       hf_smb2_aapl_server_query_caps,
				       ett_smb2_aapl_server_query_caps,
				       aapl_server_query_caps_fields,
				       ENC_LITTLE_ENDIAN);
		break;

	case SMB2_AAPL_RESOLVE_ID:
		/* file ID */
		proto_tree_add_item(sub_tree, hf_smb2_file_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		break;

	default:
		break;
	}
}

#define SMB2_AAPL_SUPPORTS_RESOLVE_ID	0x00000001
#define SMB2_AAPL_CASE_SENSITIVE		0x00000002
#define SMB2_AAPL_SUPPORTS_FULL_SYNC	0x00000004

static int * const aapl_server_query_volume_caps_fields[] = {
	&hf_smb2_aapl_server_query_volume_caps_support_resolve_id,
	&hf_smb2_aapl_server_query_volume_caps_case_sensitive,
	&hf_smb2_aapl_server_query_volume_caps_supports_full_sync,
	NULL
};

static void
dissect_smb2_AAPL_buffer_response(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, smb2_info_t *si _U_)
{
	int         offset   = 0;
	proto_item *item;
	proto_item *sub_tree;
	guint32     command_code;
	guint64     server_query_bitmask;

	item = proto_tree_get_parent(tree);

	proto_item_append_text(item, ": AAPL Create Context response");
	sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_smb2_aapl_create_context_response, NULL, "AAPL Create Context response");

	/* Command code */
	proto_tree_add_item_ret_uint(sub_tree, hf_smb2_aapl_command_code,
	    tvb, offset, 4, ENC_LITTLE_ENDIAN, &command_code);
	offset += 4;

	/* Reserved */
	proto_tree_add_item(sub_tree, hf_smb2_aapl_reserved,
	    tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	switch (command_code) {

	case SMB2_AAPL_SERVER_QUERY:
		/* Reply bitmap */
		proto_tree_add_bitmask_ret_uint64(sub_tree, tvb, offset,
						  hf_smb2_aapl_server_query_bitmask,
						  ett_smb2_aapl_server_query_bitmask,
						  aapl_server_query_bitmap_fields,
						  ENC_LITTLE_ENDIAN,
						  &server_query_bitmask);
		offset += 8;

		if (server_query_bitmask & SMB2_AAPL_SERVER_CAPS) {
			/* Server capabilities */
			proto_tree_add_bitmask(sub_tree, tvb, offset,
					       hf_smb2_aapl_server_query_caps,
					       ett_smb2_aapl_server_query_caps,
					       aapl_server_query_caps_fields,
					       ENC_LITTLE_ENDIAN);
			offset += 8;
		}
		if (server_query_bitmask & SMB2_AAPL_VOLUME_CAPS) {
			/* Volume capabilities */
			proto_tree_add_bitmask(sub_tree, tvb, offset,
					       hf_smb2_aapl_server_query_volume_caps,
					       ett_smb2_aapl_server_query_volume_caps,
					       aapl_server_query_volume_caps_fields,
					       ENC_LITTLE_ENDIAN);
			offset += 8;
		}
		if (server_query_bitmask & SMB2_AAPL_MODEL_INFO) {
			/* Padding */
			offset += 4;

			/* Model string */
			proto_tree_add_item(sub_tree, hf_smb2_aapl_server_query_model_string,
					    tvb, offset, 4,
					    ENC_UTF_16|ENC_LITTLE_ENDIAN);
		}
		break;

	case SMB2_AAPL_RESOLVE_ID:
		/* NT status */
		proto_tree_add_item(sub_tree, hf_smb2_nt_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* Server path */
		proto_tree_add_item(sub_tree, hf_smb2_aapl_server_query_server_path,
				    tvb, offset, 4,
				    ENC_UTF_16|ENC_LITTLE_ENDIAN);
		break;

	default:
		break;
	}
}

typedef void (*create_context_data_dissector_t)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si);

typedef struct create_context_data_dissectors {
	create_context_data_dissector_t request;
	create_context_data_dissector_t response;
} create_context_data_dissectors_t;

struct create_context_data_tag_dissectors {
	const char *tag;
	const char *val;
	create_context_data_dissectors_t dissectors;
};

static struct create_context_data_tag_dissectors create_context_dissectors_array[] = {
	{ "ExtA", "SMB2_CREATE_EA_BUFFER",
	  { dissect_smb2_ExtA_buffer_request, dissect_smb2_ExtA_buffer_response } },
	{ "SecD", "SMB2_CREATE_SD_BUFFER",
	  { dissect_smb2_SecD_buffer_request, dissect_smb2_SecD_buffer_response } },
	{ "AlSi", "SMB2_CREATE_ALLOCATION_SIZE",
	  { dissect_smb2_AlSi_buffer_request, dissect_smb2_AlSi_buffer_response } },
	{ "MxAc", "SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST",
	  { dissect_smb2_MxAc_buffer_request, dissect_smb2_MxAc_buffer_response } },
	{ "DHnQ", "SMB2_CREATE_DURABLE_HANDLE_REQUEST",
	  { dissect_smb2_DHnQ_buffer_request, dissect_smb2_DHnQ_buffer_response } },
	{ "DHnC", "SMB2_CREATE_DURABLE_HANDLE_RECONNECT",
	  { dissect_smb2_DHnC_buffer_request, dissect_smb2_DHnC_buffer_response } },
	{ "DH2Q", "SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2",
	  { dissect_smb2_DH2Q_buffer_request, dissect_smb2_DH2Q_buffer_response } },
	{ "DH2C", "SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2",
	  { dissect_smb2_DH2C_buffer_request, dissect_smb2_DH2C_buffer_response } },
	{ "TWrp", "SMB2_CREATE_TIMEWARP_TOKEN",
	  { dissect_smb2_TWrp_buffer_request, dissect_smb2_TWrp_buffer_response } },
	{ "QFid", "SMB2_CREATE_QUERY_ON_DISK_ID",
	  { dissect_smb2_QFid_buffer_request, dissect_smb2_QFid_buffer_response } },
	{ "RqLs", "SMB2_CREATE_REQUEST_LEASE",
	  { dissect_smb2_RqLs_buffer_request, dissect_smb2_RqLs_buffer_response } },
	{ "744D142E-46FA-0890-4AF7-A7EF6AA6BC45", "SMB2_CREATE_APP_INSTANCE_ID",
	  { dissect_smb2_APP_INSTANCE_buffer_request, dissect_smb2_APP_INSTANCE_buffer_response } },
	{ "6aa6bc45-a7ef-4af7-9008-fa462e144d74", "SMB2_CREATE_APP_INSTANCE_ID",
	  { dissect_smb2_APP_INSTANCE_buffer_request, dissect_smb2_APP_INSTANCE_buffer_response } },
	{ "9ecfcb9c-c104-43e6-980e-158da1f6ec83", "SVHDX_OPEN_DEVICE_CONTEXT",
	  { dissect_smb2_svhdx_open_device_context, dissect_smb2_svhdx_open_device_context} },
	{ "b7d082b9-563b-4f07-a07b-524a8116a010", "SMB2_CREATE_APP_INSTANCE_VERSION",
	   { dissect_smb2_app_instance_version_buffer_request, dissect_smb2_app_instance_version_buffer_response } },
	{ "5025ad93-b49c-e711-b423-83de968bcd7c", "SMB2_POSIX_CREATE_CONTEXT",
	  { dissect_smb2_posix_buffer_request, dissect_smb2_posix_buffer_response } },
	{ "AAPL", "SMB2_AAPL_CREATE_CONTEXT",
	  { dissect_smb2_AAPL_buffer_request, dissect_smb2_AAPL_buffer_response } },
};

static struct create_context_data_tag_dissectors*
get_create_context_data_tag_dissectors(const char *tag)
{
	static struct create_context_data_tag_dissectors INVALID = {
		NULL, "<invalid>", { NULL, NULL }
	};

	size_t i;

	for (i = 0; i<array_length(create_context_dissectors_array); i++) {
		if (!strcmp(tag, create_context_dissectors_array[i].tag))
			return &create_context_dissectors_array[i];
	}
	return &INVALID;
}

static void
dissect_smb2_create_extra_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, smb2_info_t *si)
{
	offset_length_buffer_t  tag_olb;
	offset_length_buffer_t  data_olb;
	const guint8 *tag;
	guint16     chain_offset;
	int         offset      = 0;
	int         len         = -1;
	proto_item *sub_item;
	proto_tree *sub_tree;
	proto_item *parent_item = NULL;
	create_context_data_dissectors_t *dissectors = NULL;
	create_context_data_dissector_t   dissector  = NULL;
	struct create_context_data_tag_dissectors *tag_dissectors;

	chain_offset = tvb_get_letohl(tvb, offset);
	if (chain_offset) {
		len = chain_offset;
	}

	sub_tree = proto_tree_add_subtree(parent_tree, tvb, offset, len, ett_smb2_create_chain_element, &sub_item, "Chain Element");
	parent_item = proto_tree_get_parent(parent_tree);

	/* chain offset */
	proto_tree_add_item(sub_tree, hf_smb2_create_chain_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* tag  offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &tag_olb, OLB_O_UINT16_S_UINT32, hf_smb2_tag);

	/* data  offset/length */
	dissect_smb2_olb_length_offset(tvb, offset, &data_olb, OLB_O_UINT16_S_UINT32, hf_smb2_create_chain_data);

	/*
	 * These things are all either 4-char strings, like DH2C, or GUIDs,
	 * however, at least one of them appears to be a GUID as a string and
	 * one appears to be a binary guid. So, check if the length is
	 * 16, and if so, pull the GUID and convert it to a string. Otherwise
	 * call dissect_smb2_olb_string.
	 */
	if (tag_olb.len == 16) {
		e_guid_t tag_guid;
		proto_item *tag_item;
		proto_tree *tag_tree;

		tvb_get_letohguid(tvb, tag_olb.off, &tag_guid);
		tag = guid_to_str(pinfo->pool, &tag_guid);

		tag_item = proto_tree_add_string(sub_tree, tag_olb.hfindex, tvb, tag_olb.off, tag_olb.len, tag);
		tag_tree = proto_item_add_subtree(tag_item, ett_smb2_olb);
		proto_tree_add_item(tag_tree, hf_smb2_olb_offset, tvb, tag_olb.off_offset, 2, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tag_tree, hf_smb2_olb_length, tvb, tag_olb.len_offset, 2, ENC_LITTLE_ENDIAN);

	} else {
		/* tag string */
		tag = dissect_smb2_olb_string(pinfo, sub_tree, tvb, &tag_olb, OLB_TYPE_ASCII_STRING);
	}

	tag_dissectors = get_create_context_data_tag_dissectors(tag);

	proto_item_append_text(parent_item, " %s", tag_dissectors->val);
	proto_item_append_text(sub_item, ": %s \"%s\"", tag_dissectors->val, tag);

	/* data */
	dissectors = &tag_dissectors->dissectors;
	if (dissectors)
		dissector = (si->flags & SMB2_FLAGS_RESPONSE) ? dissectors->response : dissectors->request;

	dissect_smb2_olb_buffer(pinfo, sub_tree, tvb, &data_olb, si, dissector);

	if (chain_offset) {
		tvbuff_t *chain_tvb;
		chain_tvb = tvb_new_subset_remaining(tvb, chain_offset);

		/* next extra info */
		dissect_smb2_create_extra_info(chain_tvb, pinfo, parent_tree, si);
	}
}

static int
dissect_smb2_create_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	offset_length_buffer_t  f_olb, e_olb;
	const guint8           *fname;

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* security flags */
	offset++;

	/* oplock */
	offset = dissect_smb2_oplock(tree, tvb, offset);

	/* impersonation level */
	proto_tree_add_item(tree, hf_smb2_impersonation_level, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* create flags */
	proto_tree_add_item(tree, hf_smb2_create_flags, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;

	/* reserved */
	proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 8, ENC_NA);
	offset += 8;

	/* access mask */
	offset = dissect_smb_access_mask(tvb, tree, offset);

	/* File Attributes */
	offset = dissect_fscc_file_attr(tvb, tree, offset, NULL);

	/* share access */
	offset = dissect_nt_share_access(tvb, tree, offset);

	/* create disposition */
	proto_tree_add_item(tree, hf_smb2_create_disposition, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* create options */
	offset = dissect_nt_create_options(tvb, tree, offset);

	/* filename  offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &f_olb, OLB_O_UINT16_S_UINT16, hf_smb2_filename);

	/* extrainfo offset */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &e_olb, OLB_O_UINT32_S_UINT32, hf_smb2_extrainfo);

	/* filename string */
	fname = dissect_smb2_olb_string(pinfo, tree, tvb, &f_olb, OLB_TYPE_UNICODE_STRING);
	col_append_fstr(pinfo->cinfo, COL_INFO, " File: %s",
	    format_text(pinfo->pool, fname, strlen(fname)));

	/* save the name if it looks sane */
	if (!pinfo->fd->visited) {
		if (si->saved && si->saved->extra_info_type == SMB2_EI_FILENAME) {
			wmem_free(wmem_file_scope(), si->saved->extra_info);
			si->saved->extra_info = NULL;
			si->saved->extra_info_type = SMB2_EI_NONE;
		}
		if (si->saved && f_olb.len < 1024) {
			si->saved->extra_info_type = SMB2_EI_FILENAME;
			si->saved->extra_info = (gchar *)wmem_alloc(wmem_file_scope(), f_olb.len+1);
			snprintf((gchar *)si->saved->extra_info, f_olb.len+1, "%s", fname);
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
	guint64 end_of_file;
	guint32	attr_mask;
	offset_length_buffer_t e_olb;
	static int * const create_rep_flags_fields[] = {
		&hf_smb2_create_rep_flags_reparse_point,
		NULL
	};
	gboolean continue_dissection;

	switch (si->status) {
	/* buffer code */
	case 0x00000000: offset = dissect_smb2_buffercode(tree, tvb, offset, NULL); break;
	default: offset = dissect_smb2_error_response(tvb, pinfo, tree, offset, si, &continue_dissection);
		if (!continue_dissection) return offset;
	}

	/* oplock */
	offset = dissect_smb2_oplock(tree, tvb, offset);

	/* reserved */
	proto_tree_add_bitmask(tree, tvb, offset, hf_smb2_create_rep_flags,
			       ett_smb2_create_rep_flags, create_rep_flags_fields, ENC_LITTLE_ENDIAN);
	offset += 1;

	/* create action */
	proto_tree_add_item(tree, hf_smb2_create_action, tvb, offset, 4, ENC_LITTLE_ENDIAN);
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
	proto_tree_add_item(tree, hf_smb2_allocation_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;

	/* end of file */
	end_of_file = tvb_get_letoh64(tvb, offset);
	if (si->eo_file_info) {
		si->eo_file_info->end_of_file = tvb_get_letoh64(tvb, offset);
	}
	proto_tree_add_item(tree, hf_smb2_end_of_file, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;

	/* File Attributes */
	offset = dissect_fscc_file_attr(tvb, tree, offset, &attr_mask);

	/* reserved */
	proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 4, ENC_NA);
	offset += 4;

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_OPEN);

	/* We save this after dissect_smb2_fid just because it would be
	possible to have this response without having the mathing request.
	In that case the entry in the file info hash table has been created
	in dissect_smb2_fid */
	if (si->eo_file_info) {
		si->eo_file_info->end_of_file = end_of_file;
		si->eo_file_info->attr_mask = attr_mask;
	}

	/* extrainfo offset */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &e_olb, OLB_O_UINT32_S_UINT32, hf_smb2_extrainfo);

	/* If extrainfo_offset is non-null then this points to another
	 * buffer. The offset is relative to the start of the smb packet
	 */
	dissect_smb2_olb_buffer(pinfo, tree, tvb, &e_olb, si, dissect_smb2_create_extra_info);

	offset = dissect_smb2_olb_tvb_max_offset(offset, &e_olb);

	/* free si->saved->extra_info   we don't need it any more */
	if (si->saved && si->saved->extra_info_type == SMB2_EI_FILENAME) {
		wmem_free(wmem_file_scope(), si->saved->extra_info);
		si->saved->extra_info = NULL;
		si->saved->extra_info_type = SMB2_EI_NONE;
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
	setinfo_size = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_setinfo_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* offset */
	setinfo_offset = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_setinfo_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	/* reserved */
	proto_tree_add_item(tree, hf_smb2_setinfo_reserved, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	if (si->saved && si->saved->smb2_class == SMB2_CLASS_SEC_INFO) {
		/* AdditionalInformation (4 bytes): Provides additional information to the server.
			If security information is being set, this value MUST contain a 4-byte bit field
			of flags indicating what security attributes MUST be applied.  */
		offset = dissect_additional_information_sec_mask(tvb, tree, offset);
	} else {
		/* For all other set requests, this field MUST be 0. */
		proto_tree_add_item(tree, hf_smb2_getsetinfo_additional, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
	}

	/* fid */
	dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

	/* data */
	if (si->saved)
		dissect_smb2_infolevel(tvb, pinfo, tree, setinfo_offset, si, si->saved->smb2_class, si->saved->infolevel);
	offset = setinfo_offset + setinfo_size;

	return offset;
}

static int
dissect_smb2_setinfo_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	gboolean continue_dissection;
	/* class/infolevel */
	dissect_smb2_class_infolevel(pinfo, tvb, offset, tree, si);

	switch (si->status) {
	/* buffer code */
	case 0x00000000: offset = dissect_smb2_buffercode(tree, tvb, offset, NULL); break;
	default: offset = dissect_smb2_error_response(tvb, pinfo, tree, offset, si, &continue_dissection);
		if (!continue_dissection) return offset;
	}

	return offset;
}

static int
dissect_smb2_break_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	guint16 buffer_code;

	/* buffer code */
	buffer_code = tvb_get_letohs(tvb, offset);
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	if (buffer_code == OPLOCK_BREAK_OPLOCK_STRUCTURE_SIZE) {
		/* OPLOCK Break */

		/* oplock */
		offset = dissect_smb2_oplock(tree, tvb, offset);

		/* reserved */
		proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 1, ENC_NA);
		offset += 1;

		/* reserved */
		proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 4, ENC_NA);
		offset += 4;

		/* fid */
		offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

		return offset;
	}

	if (buffer_code == OPLOCK_BREAK_LEASE_ACKNOWLEDGMENT_STRUCTURE_SIZE) {
		/* Lease Break Acknowledgment */

		/* reserved */
		proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 2, ENC_NA);
		offset +=2;

		/* lease flags */
		proto_tree_add_bitmask(tree, tvb, offset, hf_smb2_lease_flags,
				       ett_smb2_lease_flags, lease_flags_fields, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* lease key */
		proto_tree_add_item(tree, hf_smb2_lease_key, tvb, offset, 16, ENC_LITTLE_ENDIAN);
		offset += 16;

		/* lease state */
		proto_tree_add_bitmask(tree, tvb, offset, hf_smb2_lease_state,
				       ett_smb2_lease_state, lease_state_fields, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(tree, hf_smb2_lease_duration, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		return offset;
	}

	return offset;
}

static int
dissect_smb2_break_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	guint16 buffer_code;
	gboolean continue_dissection;

	/* buffer code */
	buffer_code = tvb_get_letohs(tvb, offset);
	switch (si->status) {
	case 0x00000000: offset = dissect_smb2_buffercode(tree, tvb, offset, NULL); break;
	default: offset = dissect_smb2_error_response(tvb, pinfo, tree, offset, si, &continue_dissection);
		if (!continue_dissection) return offset;
	}

	if (buffer_code == OPLOCK_BREAK_OPLOCK_STRUCTURE_SIZE) {
		/* OPLOCK Break Notification */

		/* oplock */
		offset = dissect_smb2_oplock(tree, tvb, offset);

		/* reserved */
		proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 1, ENC_NA);
		offset += 1;

		/* reserved */
		proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 4, ENC_NA);
		offset += 4;

		/* fid */
		offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

		/* in break requests from server to client here're 24 byte zero bytes
		 * which are likely a bug in windows (they may use 2* 24 bytes instead of just
		 * 1 *24 bytes
		 */
		return offset;
	}

	if (buffer_code == OPLOCK_BREAK_LEASE_NOTIFICATION_STRUCTURE_SIZE) {
		proto_item *item;

		/* Lease Break Notification */

		/* new lease epoch */
		proto_tree_add_item(tree, hf_smb2_lease_epoch, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		/* lease flags */
		proto_tree_add_bitmask(tree, tvb, offset, hf_smb2_lease_flags,
				       ett_smb2_lease_flags, lease_flags_fields, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* lease key */
		proto_tree_add_item(tree, hf_smb2_lease_key, tvb, offset, 16, ENC_LITTLE_ENDIAN);
		offset += 16;

		/* current lease state */
		item = proto_tree_add_bitmask(tree, tvb, offset, hf_smb2_lease_state,
					      ett_smb2_lease_state, lease_state_fields, ENC_LITTLE_ENDIAN);
		if (item) {
			proto_item_prepend_text(item, "Current ");
		}
		offset += 4;

		/* new lease state */
		item = proto_tree_add_bitmask(tree, tvb, offset, hf_smb2_lease_state,
					      ett_smb2_lease_state, lease_state_fields, ENC_LITTLE_ENDIAN);
		if (item) {
			proto_item_prepend_text(item, "New ");
		}
		offset += 4;

		/* break reason - reserved */
		proto_tree_add_item(tree, hf_smb2_lease_break_reason, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* access mask hint - reserved */
		proto_tree_add_item(tree, hf_smb2_lease_access_mask_hint, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* share mask hint - reserved */
		proto_tree_add_item(tree, hf_smb2_lease_share_mask_hint, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		return offset;
	}

	if (buffer_code == OPLOCK_BREAK_LEASE_RESPONSE_STRUCTURE_SIZE) {
		/* Lease Break Response */

		/* reserved */
		proto_tree_add_item(tree, hf_smb2_reserved, tvb, offset, 2, ENC_NA);
		offset +=2;

		/* lease flags */
		proto_tree_add_bitmask(tree, tvb, offset, hf_smb2_lease_flags,
				       ett_smb2_lease_flags, lease_flags_fields, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* lease key */
		proto_tree_add_item(tree, hf_smb2_lease_key, tvb, offset, 16, ENC_LITTLE_ENDIAN);
		offset += 16;

		/* lease state */
		proto_tree_add_bitmask(tree, tvb, offset, hf_smb2_lease_state,
				       ett_smb2_lease_state, lease_state_fields, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(tree, hf_smb2_lease_duration, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		return offset;
	}

	return offset;
}

/* names here are just until we find better names for these functions */
static const value_string smb2_cmd_vals[] = {
	{ 0x00, "Negotiate Protocol" },
	{ 0x01, "Session Setup" },
	{ 0x02, "Session Logoff" },
	{ 0x03, "Tree Connect" },
	{ 0x04, "Tree Disconnect" },
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


#define SMB3_AES128CCM_NONCE	11
#define SMB3_AES128GCM_NONCE	12

static gboolean is_decrypted_header_ok(guint8 *p, size_t size)
{
	if (size < 4)
		return FALSE;

	if ((p[0] == SMB2_COMP_HEADER || p[0] == SMB2_NORM_HEADER)
	    && (p[1] == 'S' || p[2] == 'M' || p[3] == 'B')) {
		return TRUE;
	}

	DEBUG("decrypt: bad SMB header");
	return FALSE;
}

static gboolean
do_decrypt(guint8 *data,
	   size_t data_size,
	   const guint8 *key,
	   const guint8 *aad,
	   int aad_size,
	   const guint8 *nonce,
	   int alg)
{
	gcry_error_t err;
	gcry_cipher_hd_t cipher_hd = NULL;
	int algo;
	size_t keylen;
	int mode;
	int iv_size;
	guint64 lengths[3];

	switch (alg) {
	case SMB2_CIPHER_AES_128_CCM:
		algo = GCRY_CIPHER_AES128;
		keylen = AES_KEY_SIZE;
		mode = GCRY_CIPHER_MODE_CCM;
		iv_size = SMB3_AES128CCM_NONCE;
		break;
	case SMB2_CIPHER_AES_128_GCM:
		algo = GCRY_CIPHER_AES128;
		keylen = AES_KEY_SIZE;
		mode = GCRY_CIPHER_MODE_GCM;
		iv_size = SMB3_AES128GCM_NONCE;
		break;
	case SMB2_CIPHER_AES_256_CCM:
		algo = GCRY_CIPHER_AES256;
		keylen = AES_KEY_SIZE*2;
		mode = GCRY_CIPHER_MODE_CCM;
		iv_size = SMB3_AES128CCM_NONCE;
		break;
	case SMB2_CIPHER_AES_256_GCM:
		algo = GCRY_CIPHER_AES256;
		keylen = AES_KEY_SIZE*2;
		mode = GCRY_CIPHER_MODE_GCM;
		iv_size = SMB3_AES128GCM_NONCE;
		break;
	default:
		return FALSE;
	}

	/* Open the cipher */
	err = gcry_cipher_open(&cipher_hd, algo, mode, 0);
	if (err != GPG_ERR_NO_ERROR) {
		DEBUG("GCRY: open %s/%s", gcry_strsource(err), gcry_strerror(err));
		return FALSE;
	}

	/* Set the key */
	err = gcry_cipher_setkey(cipher_hd, key, keylen);
	if (err != GPG_ERR_NO_ERROR) {
		DEBUG("GCRY: setkey %s/%s", gcry_strsource(err), gcry_strerror(err));
		gcry_cipher_close(cipher_hd);
		return FALSE;
	}

	/* Set the initial value */
	err = gcry_cipher_setiv(cipher_hd, nonce, iv_size);
	if (err != GPG_ERR_NO_ERROR) {
		DEBUG("GCRY: setiv %s/%s", gcry_strsource(err), gcry_strerror(err));
		gcry_cipher_close(cipher_hd);
		return FALSE;
	}

	lengths[0] = data_size; /* encrypted length */
	lengths[1] = aad_size; /* AAD length */
	lengths[2] = 16; /* tag length (signature size) */

	if (mode == GCRY_CIPHER_MODE_CCM) {
		err = gcry_cipher_ctl(cipher_hd, GCRYCTL_SET_CCM_LENGTHS, lengths, sizeof(lengths));
		if (err != GPG_ERR_NO_ERROR) {
			DEBUG("GCRY: ctl %s/%s", gcry_strsource(err), gcry_strerror(err));
			gcry_cipher_close(cipher_hd);
			return FALSE;
		}
	}

	err = gcry_cipher_authenticate(cipher_hd, aad, aad_size);
	if (err != GPG_ERR_NO_ERROR) {
		DEBUG("GCRY: auth %s/%s", gcry_strsource(err), gcry_strerror(err));
		gcry_cipher_close(cipher_hd);
		return FALSE;
	}

	err = gcry_cipher_decrypt(cipher_hd, data, data_size, NULL, 0);
	if (err != GPG_ERR_NO_ERROR) {
		DEBUG("GCRY: decrypt %s/%s", gcry_strsource(err), gcry_strerror(err));
		gcry_cipher_close(cipher_hd);
		return FALSE;
	}

	/* Done with the cipher */
	gcry_cipher_close(cipher_hd);
	return is_decrypted_header_ok(data, data_size);
}

static guint8*
decrypt_smb_payload(packet_info *pinfo,
		    tvbuff_t *tvb, int offset,
		    int offset_aad,
		    smb2_transform_info_t *sti)
{
	const guint8 *aad = NULL;
	guint8 *data = NULL;
	guint8 *key16 = NULL;
	guint8 *keys16[2];
	guint8 *key32 = NULL;
	guint8 *keys32[2];
	gboolean ok;
	int aad_size;
	int alg;

	/* AAD is the rest of transform header after the ProtocolID and Signature */
	aad_size = 32;

	if ((unsigned)tvb_captured_length_remaining(tvb, offset) < sti->size)
		return NULL;

	if (tvb_captured_length_remaining(tvb, offset_aad) < aad_size)
		return NULL;

	if (pinfo->destport == sti->session->server_port) {
		keys16[0] = sti->session->server_decryption_key16;
		keys16[1] = sti->session->client_decryption_key16;
		keys32[0] = sti->session->server_decryption_key32;
		keys32[1] = sti->session->client_decryption_key32;
	} else {
		keys16[1] = sti->session->server_decryption_key16;
		keys16[0] = sti->session->client_decryption_key16;
		keys32[1] = sti->session->server_decryption_key32;
		keys32[0] = sti->session->client_decryption_key32;
	}

	aad = tvb_get_ptr(tvb, offset_aad, aad_size);
	data = (guint8 *)tvb_memdup(pinfo->pool, tvb, offset, sti->size);

	/*
	 * In SMB3.0 the transform header had a Algorithm field to
	 * know which type of encryption was used but only CCM was
	 * supported.
	 *
	 * SMB3.1.1 turned that field into a generic "Encrypted" flag
	 * which cannot be used to determine the encryption
	 * type. Instead the type is decided in the NegProt response,
	 * within the Encryption Capability context which should only
	 * have one element. That element is saved in the conversation
	 * struct (si->conv) and checked here.
	 *
	 * If the trace didn't contain NegProt packets, we have to
	 * guess the encryption type by trying them all.
	 *
	 * Similarly, if we don't have unencrypted packets telling us
	 * which host is the server and which host is the client, we
	 * have to guess by trying both keys.
	 */

	DEBUG("dialect 0x%x alg 0x%x conv alg 0x%x", sti->conv->dialect, sti->alg, sti->conv->enc_alg);

	for (guint i = 0; i < G_N_ELEMENTS(keys16); i++) {
		gboolean try_ccm16, try_gcm16;
		gboolean try_ccm32, try_gcm32;
		try_ccm16 = try_gcm16 = FALSE;
		try_ccm32 = try_gcm32 = FALSE;
		ok = FALSE;

		key16 = keys16[i];
		key32 = keys32[i];

		switch (sti->conv->enc_alg) {
		case SMB2_CIPHER_AES_128_CCM:
			try_ccm16 = TRUE;
			break;
		case SMB2_CIPHER_AES_128_GCM:
			try_gcm16 = TRUE;
			break;
		case SMB2_CIPHER_AES_256_CCM:
			try_ccm32 = TRUE;
			break;
		case SMB2_CIPHER_AES_256_GCM:
			try_gcm32 = TRUE;
			break;
		default:
			/* we don't know, try all */
			try_gcm16 = TRUE;
			try_ccm16 = TRUE;
			try_gcm32 = TRUE;
			try_ccm32 = TRUE;
		}

		if (try_gcm16) {
			guint8 *key = key16;
			DEBUG("trying AES-128-GCM decryption");
			alg = SMB2_CIPHER_AES_128_GCM;
			tvb_memcpy(tvb, data, offset, sti->size);
			ok = do_decrypt(data, sti->size, key, aad, aad_size, sti->nonce, alg);
			if (ok)
				break;
			DEBUG("bad decrypted buffer with AES-128-GCM");
		}
		if (try_ccm16) {
			guint8 *key = key16;
			DEBUG("trying AES-128-CCM decryption");
			alg = SMB2_CIPHER_AES_128_CCM;
			ok = do_decrypt(data, sti->size, key, aad, aad_size, sti->nonce, alg);
			if (ok)
				break;
			DEBUG("bad decrypted buffer with AES-128-CCM");
		}
		if (try_gcm32) {
			guint8 *key = key32;
			DEBUG("trying AES-256-GCM decryption");
			alg = SMB2_CIPHER_AES_256_GCM;
			tvb_memcpy(tvb, data, offset, sti->size);
			ok = do_decrypt(data, sti->size, key, aad, aad_size, sti->nonce, alg);
			if (ok)
				break;
			DEBUG("bad decrypted buffer with AES-256-GCM");
		}
		if (try_ccm32) {
			guint8 *key = key32;
			DEBUG("trying AES-256-CCM decryption");
			alg = SMB2_CIPHER_AES_256_CCM;
			ok = do_decrypt(data, sti->size, key, aad, aad_size, sti->nonce, alg);
			if (ok)
				break;
			DEBUG("bad decrypted buffer with AES-256-CCM");
		}
		DEBUG("trying to decrypt with swapped client/server keys");
		tvb_memcpy(tvb, data, offset, sti->size);
	}

	if (!ok)
		return NULL;

	/* Remember what worked */
	sti->conv->enc_alg = alg;
	if (key16 == sti->session->server_decryption_key16)
		sti->session->server_port = pinfo->destport;
	else
		sti->session->server_port = pinfo->srcport;
	return data;
}

/*
  Append tvb[offset:offset+length] to out
*/
static void
append_uncompress_data(wmem_array_t *out, tvbuff_t *tvb, int offset, guint length)
{
	wmem_array_append(out, tvb_get_ptr(tvb, offset, length), length);
}

static int
dissect_smb2_compression_pattern_v1(proto_tree *tree,
				    tvbuff_t *tvb, int offset, int length,
				    wmem_array_t *out)
{
	proto_item *pat_item;
	proto_tree *pat_tree;
	guint pattern, times;

	pat_tree = proto_tree_add_subtree_format(tree, tvb, offset, length,
						 ett_smb2_comp_pattern_v1, &pat_item,
						 "Pattern");

	proto_tree_add_item_ret_uint(pat_tree, hf_smb2_comp_pattern_v1_pattern, tvb, offset, 1, ENC_LITTLE_ENDIAN, &pattern);
	offset += 1;

	proto_tree_add_item(pat_tree, hf_smb2_comp_pattern_v1_reserved1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(pat_tree, hf_smb2_comp_pattern_v1_reserved2, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item_ret_uint(pat_tree, hf_smb2_comp_pattern_v1_repetitions, tvb, offset, 4, ENC_LITTLE_ENDIAN, &times);
	offset += 4;

	proto_item_append_text(pat_item, " 0x%02x repeated %u times", pattern, times);

	if (out && times < MAX_UNCOMPRESSED_SIZE) {
		guint8 v = (guint8)pattern;

		for (guint i = 0; i < times; i++)
			wmem_array_append(out, &v, 1);
	}

	return offset;
}

static int
dissect_smb2_chained_comp_payload(packet_info *pinfo, proto_tree *tree,
				  tvbuff_t *tvb, int offset,
				  wmem_array_t *out,
				  gboolean *ok)
{
	proto_tree *subtree;
	proto_item *subitem;
	guint alg, length, flags, orig_size = 0;
	tvbuff_t *uncomp_tvb = NULL;
	gboolean lz_based = FALSE;

	*ok = TRUE;

	subtree = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_smb2_comp_payload, &subitem, "COMPRESSION_PAYLOAD_HEADER");
	proto_tree_add_item_ret_uint(subtree, hf_smb2_comp_transform_comp_alg, tvb, offset, 2, ENC_LITTLE_ENDIAN, &alg);
	offset += 2;

	proto_tree_add_item_ret_uint(subtree, hf_smb2_comp_transform_flags, tvb, offset, 2, ENC_LITTLE_ENDIAN, &flags);
	offset += 2;

	proto_tree_add_item_ret_uint(subtree, hf_smb2_comp_transform_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &length);
	offset += 4;

	proto_item_set_len(subitem, length);

	lz_based = (SMB2_COMP_ALG_LZNT1 <= alg && alg <= SMB2_COMP_ALG_LZ77HUFF);
	if (lz_based) {
		proto_tree_add_item_ret_uint(subtree, hf_smb2_comp_transform_orig_payload_size,
					     tvb, offset, 4, ENC_LITTLE_ENDIAN, &orig_size);
		offset += 4;
		length -= 4;
	}

	if (length > MAX_UNCOMPRESSED_SIZE) {
		/* decompression error */
		col_append_str(pinfo->cinfo, COL_INFO, "Comp. SMB3 (invalid)");
		*ok = FALSE;
		goto out;
	}

	switch (alg) {
	case SMB2_COMP_ALG_NONE:
		append_uncompress_data(out, tvb, offset, length);
		break;
	case SMB2_COMP_ALG_LZ77:
		uncomp_tvb = tvb_uncompress_lz77(tvb, offset, length);
		break;
	case SMB2_COMP_ALG_LZ77HUFF:
		uncomp_tvb = tvb_uncompress_lz77huff(tvb, offset, length);
		break;
	case SMB2_COMP_ALG_LZNT1:
		uncomp_tvb = tvb_uncompress_lznt1(tvb, offset, length);
		break;
	case SMB2_COMP_ALG_PATTERN_V1:
		dissect_smb2_compression_pattern_v1(subtree, tvb, offset, length, out);
		break;
	default:
		col_append_str(pinfo->cinfo, COL_INFO, "Comp. SMB3 (unknown)");
		uncomp_tvb = NULL;
		break;
	}

	if (lz_based) {
		if (!uncomp_tvb || tvb_reported_length(uncomp_tvb) != orig_size) {
			/* decompression error */
			col_append_str(pinfo->cinfo, COL_INFO, "Comp. SMB3 (invalid)");
			*ok = FALSE;
			goto out;
		}
		append_uncompress_data(out, uncomp_tvb, 0, tvb_reported_length(uncomp_tvb));
	}

 out:
	if (uncomp_tvb)
		tvb_free(uncomp_tvb);
	proto_tree_add_item(subtree, hf_smb2_comp_transform_data, tvb, offset, length, ENC_NA);
	offset += length;

	return offset;
}

static int
dissect_smb2_comp_transform_header(packet_info *pinfo, proto_tree *tree,
				   tvbuff_t *tvb, int offset,
				   smb2_comp_transform_info_t *scti,
				   tvbuff_t **comp_tvb,
				   tvbuff_t **plain_tvb)
{
	gint in_size;
	tvbuff_t *uncomp_tvb = NULL;
	guint flags;
	wmem_array_t *uncomp_data;

	*comp_tvb = NULL;
	*plain_tvb = NULL;

	/*
	  "old" compressed method:

	  [COMPRESS_TRANSFORM_HEADER with Flags=0]
	    [OPTIONAL UNCOMPRESSED DATA]
	    [COMPRESSED DATA]

	  new "chained" compressed method:

	  [fist 8 bytes of COMPRESS_TRANSFORM_HEADER with Flags=CHAINED]
	    [ sequence of
               [ COMPRESSION_PAYLOAD_HEADER ]
               [ COMPRESSED PAYLOAD ]
	    ]
	 */

	/* SMB2_COMPRESSION_TRANSFORM marker */
	proto_tree_add_item(tree, hf_smb2_protocol_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item_ret_uint(tree, hf_smb2_comp_transform_orig_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &scti->orig_size);
	offset += 4;

	uncomp_data = wmem_array_sized_new(pinfo->pool, 1, 1024);

	flags = tvb_get_letohs(tvb, offset+2);
	if (flags & SMB2_COMP_FLAG_CHAINED) {
		gboolean all_ok = TRUE;

		*comp_tvb = tvb_new_subset_length(tvb, offset, tvb_reported_length_remaining(tvb, offset));
		do {
			gboolean ok = FALSE;

			offset = dissect_smb2_chained_comp_payload(pinfo, tree, tvb, offset, uncomp_data, &ok);
			if (!ok)
				all_ok = FALSE;
		} while (tvb_reported_length_remaining(tvb, offset) > 8);
		if (all_ok)
			goto decompression_ok;
		else
			goto out;

	}

	proto_tree_add_item_ret_uint(tree, hf_smb2_comp_transform_comp_alg, tvb, offset, 2, ENC_LITTLE_ENDIAN, &scti->alg);
	offset += 2;

	proto_tree_add_item_ret_uint(tree, hf_smb2_comp_transform_flags, tvb, offset, 2, ENC_LITTLE_ENDIAN, &flags);
	offset += 2;

	proto_tree_add_item_ret_uint(tree, hf_smb2_comp_transform_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &scti->comp_offset);
	offset += 4;

	*comp_tvb = tvb_new_subset_length(tvb, offset, tvb_reported_length_remaining(tvb, offset));

	if (scti->orig_size > MAX_UNCOMPRESSED_SIZE || scti->comp_offset > MAX_UNCOMPRESSED_SIZE) {
		col_append_str(pinfo->cinfo, COL_INFO, "Comp. SMB3 (too big)");
		goto out;
	}

	/*
	 *  final uncompressed size is the partial normal packet + uncompressed segment
         *  final_size = scti->orig_size + scti->comp_offset
	 */

	append_uncompress_data(uncomp_data, tvb, offset, scti->comp_offset);
	in_size = tvb_reported_length_remaining(tvb, offset + scti->comp_offset);

	/* decompress compressed segment */
	switch (scti->alg) {
	case SMB2_COMP_ALG_LZ77:
		uncomp_tvb = tvb_uncompress_lz77(tvb, offset + scti->comp_offset, in_size);
		break;
	case SMB2_COMP_ALG_LZ77HUFF:
		uncomp_tvb = tvb_uncompress_lz77huff(tvb, offset + scti->comp_offset, in_size);
		break;
	case SMB2_COMP_ALG_LZNT1:
		uncomp_tvb = tvb_uncompress_lznt1(tvb, offset + scti->comp_offset, in_size);
		break;
	default:
		col_append_str(pinfo->cinfo, COL_INFO, "Comp. SMB3 (unknown)");
		uncomp_tvb = NULL;
		goto out;
	}

	if (!uncomp_tvb || tvb_reported_length(uncomp_tvb) != scti->orig_size) {
		/* decompression error */
		col_append_str(pinfo->cinfo, COL_INFO, "Comp. SMB3 (invalid)");
		goto out;
	}

	/* write decompressed segment at the end of partial packet */
	append_uncompress_data(uncomp_data, uncomp_tvb, 0, scti->orig_size);

 decompression_ok:
	col_append_str(pinfo->cinfo, COL_INFO, "Decomp. SMB3");
	*plain_tvb = tvb_new_child_real_data(tvb,
					     (guint8 *)wmem_array_get_raw(uncomp_data),
					     wmem_array_get_count(uncomp_data),
					     wmem_array_get_count(uncomp_data));
	add_new_data_source(pinfo, *plain_tvb, "Decomp. SMB3");

 out:
	if (uncomp_tvb)
		tvb_free(uncomp_tvb);
	return offset;
}

static int
dissect_smb2_transform_header(packet_info *pinfo, proto_tree *tree,
			      tvbuff_t *tvb, int offset,
			      smb2_transform_info_t *sti,
			      tvbuff_t **enc_tvb, tvbuff_t **plain_tvb)
{
	proto_item        *sesid_item     = NULL;
	proto_tree        *sesid_tree     = NULL;
	int                sesid_offset;
	guint8            *plain_data     = NULL;
	int                offset_aad;

	*enc_tvb = NULL;
	*plain_tvb = NULL;

	/* signature */
	proto_tree_add_item(tree, hf_smb2_transform_signature, tvb, offset, 16, ENC_NA);
	offset += 16;

	offset_aad = offset;

	/* nonce */
	proto_tree_add_item(tree, hf_smb2_transform_nonce, tvb, offset, 16, ENC_NA);
	tvb_memcpy(tvb, sti->nonce, offset, 16);
	offset += 16;

	/* size */
	proto_tree_add_item(tree, hf_smb2_transform_msg_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	sti->size = tvb_get_letohl(tvb, offset);
	offset += 4;

	/* reserved */
	proto_tree_add_item(tree, hf_smb2_transform_reserved, tvb, offset, 2, ENC_NA);
	offset += 2;

	/* flags */
	proto_tree_add_bitmask(tree, tvb, offset, hf_smb2_transform_flags,
			       ett_smb2_transform_flags,
			       smb2_transform_flags, ENC_LITTLE_ENDIAN);
	sti->flags = tvb_get_letohs(tvb, offset);
	offset += 2;

	/* session ID */
	sesid_offset = offset;
	sti->sesid = tvb_get_letoh64(tvb, offset);
	sesid_item = proto_tree_add_item(tree, hf_smb2_sesid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	sesid_tree = proto_item_add_subtree(sesid_item, ett_smb2_sesid_tree);
	offset += 8;

	/* now we need to first lookup the uid session */
	sti->session = smb2_get_session(sti->conv, sti->sesid, NULL, NULL);
	smb2_add_session_info(sesid_tree, sesid_item, tvb, sesid_offset, sti->session);

	if (sti->flags & SMB2_TRANSFORM_FLAGS_ENCRYPTED) {
		plain_data = decrypt_smb_payload(pinfo, tvb, offset, offset_aad, sti);
	}
	*enc_tvb = tvb_new_subset_length(tvb, offset, sti->size);

	if (plain_data != NULL) {
		*plain_tvb = tvb_new_child_real_data(*enc_tvb, plain_data, sti->size, sti->size);
		add_new_data_source(pinfo, *plain_tvb, "Decrypted SMB3");
	}

	offset += sti->size;
	return offset;
}

static const char *
get_special_packet_title(guint16 cmd, guint32 flags, guint64 msg_id, tvbuff_t *tvb, int offset)
{
	/*  for some types of packets we don't have request/response packets but something else
	 *  to show more correct names while displaying them we use this logic to override standard naming convention
	 */

	guint16 buffer_code;
	/* detect oplock/lease break packets */
	if (cmd != SMB2_COM_BREAK) {
		return NULL;
	}

	buffer_code = tvb_get_letohs(tvb, offset);
	if (flags & SMB2_FLAGS_RESPONSE) {
		switch (buffer_code) {
		case OPLOCK_BREAK_OPLOCK_STRUCTURE_SIZE:
			/* note - Notification and Response packets for Oplock Break are equivalent,
			 * we can distinguish them only via msg_id value */
			if (msg_id == 0xFFFFFFFFFFFFFFFF)	/* see [MS-SMB2] 3.3.4.6 Object Store Indicates an Oplock Break */
				return "Oplock Break Notification";
			else
				return "Oplock Break Response";
		case OPLOCK_BREAK_LEASE_NOTIFICATION_STRUCTURE_SIZE:
			return "Lease Break Notification";
		case OPLOCK_BREAK_LEASE_RESPONSE_STRUCTURE_SIZE:
			return "Lease Break Response";
		}
	} else {
		switch (buffer_code) {
		case OPLOCK_BREAK_OPLOCK_STRUCTURE_SIZE:
			return "Oplock Break Acknowledgment";
		case OPLOCK_BREAK_LEASE_ACKNOWLEDGMENT_STRUCTURE_SIZE:
			return "Lease Break Acknowledgment";
		}
	}
	/* return back to standard notation if we can't detect packet type of break packet */
	return NULL;
}

static int
dissect_smb2_command(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, smb2_info_t *si)
{
	int (*cmd_dissector)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si);
	proto_item *cmd_item;
	proto_tree *cmd_tree;
	int         old_offset = offset;
	const char *packet_title = get_special_packet_title(si->opcode, si->flags, si->msg_id, tvb, offset);

	if (packet_title) {
		cmd_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1,
				ett_smb2_command, &cmd_item, "%s (0x%02x)",
				packet_title,
				si->opcode);
	} else {
		cmd_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1,
				ett_smb2_command, &cmd_item, "%s %s (0x%02x)",
				decode_smb2_name(si->opcode),
				(si->flags & SMB2_FLAGS_RESPONSE)?"Response":"Request",
				si->opcode);
	}

	cmd_dissector = (si->flags & SMB2_FLAGS_RESPONSE)?
		smb2_dissector[si->opcode&0xff].response:
		smb2_dissector[si->opcode&0xff].request;
	if (cmd_dissector) {
		offset = (*cmd_dissector)(tvb, pinfo, cmd_tree, offset, si);
	} else {
		proto_tree_add_item(cmd_tree, hf_smb2_unknown, tvb, offset, -1, ENC_NA);
		offset = tvb_captured_length(tvb);
	}

	proto_item_set_len(cmd_item, offset-old_offset);

	return offset;
}

static int
dissect_smb2_tid_sesid(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, smb2_info_t *si)
{
	proto_item        *tid_item   = NULL;
	proto_tree        *tid_tree   = NULL;
	smb2_tid_info_t    tid_key;
	int                tid_offset = 0;
	proto_item        *sesid_item = NULL;
	proto_tree        *sesid_tree = NULL;
	smb2_sesid_info_t  sesid_key;
	int                sesid_offset;
	proto_item        *item;


	if (si->flags&SMB2_FLAGS_ASYNC_CMD) {
		proto_tree_add_item(tree, hf_smb2_aid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;
	} else {
		/* Process ID */
		proto_tree_add_item(tree, hf_smb2_pid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* Tree ID */
		tid_offset = offset;
		si->tid = tvb_get_letohl(tvb, offset);
		tid_item = proto_tree_add_item(tree, hf_smb2_tid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		tid_tree = proto_item_add_subtree(tid_item, ett_smb2_tid_tree);
		offset += 4;
	}

	/* Session ID */
	sesid_offset = offset;
	si->sesid = tvb_get_letoh64(tvb, offset);
	sesid_item = proto_tree_add_item(tree, hf_smb2_sesid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	sesid_tree = proto_item_add_subtree(sesid_item, ett_smb2_sesid_tree);
	offset += 8;

	/* now we need to first lookup the uid session */
	sesid_key.sesid = si->sesid;
	si->session = (smb2_sesid_info_t *)wmem_map_lookup(smb2_sessions, &sesid_key);
	if (!si->session) {
		si->session = smb2_get_session(si->conv, si->sesid, pinfo, si);
		return offset;
	}

	smb2_add_session_info(sesid_tree, sesid_item, tvb, sesid_offset, si->session);

	if (!(si->flags&SMB2_FLAGS_ASYNC_CMD)) {
		/* see if we can find the name for this tid */
		tid_key.tid = si->tid;
		si->tree = (smb2_tid_info_t *)wmem_map_lookup(si->session->tids, &tid_key);
		if (!si->tree) return offset;

		item = proto_tree_add_string(tid_tree, hf_smb2_tree, tvb, tid_offset, 4, si->tree->name);
		proto_item_set_generated(item);
		proto_item_append_text(tid_item, "  %s", si->tree->name);

		item = proto_tree_add_uint(tid_tree, hf_smb2_share_type, tvb, tid_offset, 0, si->tree->share_type);
		proto_item_set_generated(item);

		item = proto_tree_add_uint(tid_tree, hf_smb2_tcon_frame, tvb, tid_offset, 0, si->tree->connect_frame);
		proto_item_set_generated(item);
	}

	return offset;
}

static void
dissect_smb2_signature(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree, smb2_info_t *si)
{
	proto_item   *item = NULL;
	proto_tree   *stree = NULL;
	gcry_error_t err;
	gcry_mac_hd_t md;
	guint8 mac[NTLMSSP_KEY_LEN] = { 0, };
	size_t len = NTLMSSP_KEY_LEN;
	int i, remaining;
	gboolean use_mac = FALSE;

	item = proto_tree_add_item(tree, hf_smb2_signature, tvb, offset, 16, ENC_NA);

	if (!si || !si->session ||!si->conv)
		return;

	if (!smb2_verify_signatures || !(si->flags & SMB2_FLAGS_SIGNATURE))
		return;

	if (memcmp(si->session->signing_key, zeros, NTLMSSP_KEY_LEN) == 0) {
		return;
	}

	if (tvb_reported_length(tvb) > tvb_captured_length(tvb))
		return;

	remaining = tvb_reported_length_remaining(tvb, offset + NTLMSSP_KEY_LEN);

	if (si->conv->sign_alg == SMB2_SIGNING_ALG_HMAC_SHA256) {
		err = gcry_mac_open(&md, GCRY_MAC_HMAC_SHA256, 0, NULL);
		if (err)
			return;
		use_mac = TRUE;
	} else if (si->conv->sign_alg == SMB2_SIGNING_ALG_AES_CMAC) {
		err = gcry_mac_open(&md, GCRY_MAC_CMAC_AES, 0, NULL);
		if (err)
			return;
		use_mac = TRUE;
	}

	if (use_mac) {
		gcry_mac_setkey(md, si->session->signing_key, len);
		gcry_mac_write(md, tvb_get_ptr(tvb, 0, 48), 48);
		gcry_mac_write(md, zeros, NTLMSSP_KEY_LEN);
		gcry_mac_write(md, tvb_get_ptr(tvb, offset + NTLMSSP_KEY_LEN, remaining), remaining);
		gcry_mac_read(md, &mac[0], &len);
		gcry_mac_close(md);
	}

	stree = proto_item_add_subtree(item, ett_smb2_signature);

	if (memcmp(&mac[0], tvb_get_ptr(tvb, offset, NTLMSSP_KEY_LEN), NTLMSSP_KEY_LEN) == 0) {
		proto_tree_add_item(stree, hf_smb2_good_signature, tvb, offset, 16, ENC_NA);
		return; /* signature matched */
	}

	item = proto_tree_add_item(stree, hf_smb2_bad_signature, tvb, offset, 16, ENC_NA);
	proto_item_append_text(item, " ");
	for (i = 0; i < NTLMSSP_KEY_LEN; i++)
		proto_item_append_text(item, "%02x", mac[i]);
	proto_item_set_generated(item);
	expert_add_info(pinfo, item, &ei_smb2_invalid_signature);

	return;
}

static int
dissect_smb2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, gboolean first_in_chain)
{
	int msg_type;
	proto_item *item		  = NULL;
	proto_tree *tree		  = NULL;
	proto_item *header_item		  = NULL;
	proto_tree *header_tree		  = NULL;
	int         offset		  = 0;
	int         chain_offset	  = 0;
	const char *label		  = smb_header_label;
	conversation_t    *conversation;
	smb2_saved_info_t *ssi          = NULL, ssi_key;
	smb2_info_t       *si;
	smb2_transform_info_t *sti;
	smb2_comp_transform_info_t *scti;
	char		    *fid_name;
	guint32		     open_frame,close_frame;
	smb2_eo_file_info_t *eo_file_info;
	e_ctx_hnd	    *policy_hnd_hashtablekey;
	const char	    *packet_title;

	sti = wmem_new(pinfo->pool, smb2_transform_info_t);
	scti = wmem_new(pinfo->pool, smb2_comp_transform_info_t);
	si  = wmem_new0(pinfo->pool, smb2_info_t);
	si->top_tree = parent_tree;

	msg_type = tvb_get_guint8(tvb, 0);

	switch (msg_type) {
	case SMB2_COMP_HEADER:
		label = smb_comp_transform_header_label;
		break;
	case SMB2_ENCR_HEADER:
		label = smb_transform_header_label;
		break;
	case SMB2_NORM_HEADER:
		label = smb_header_label;
		break;
	default:
		label = smb_bad_header_label;
		break;
	}

	/* find which conversation we are part of and get the data for that
	 * conversation
	 */
	conversation = find_or_create_conversation(pinfo);
	si->conv = (smb2_conv_info_t *)conversation_get_proto_data(conversation, proto_smb2);
	if (!si->conv) {
		/* no smb2_into_t structure for this conversation yet,
		 * create it.
		 */
		si->conv = wmem_new0(wmem_file_scope(), smb2_conv_info_t);
		/* qqq this leaks memory for now since we never free
		   the hashtables */
		si->conv->matched = g_hash_table_new(smb2_saved_info_hash_matched,
			smb2_saved_info_equal_matched);
		si->conv->unmatched = g_hash_table_new(smb2_saved_info_hash_unmatched,
			smb2_saved_info_equal_unmatched);
		si->conv->preauth_hash_current = si->conv->preauth_hash_con;

		/* Bit of a hack to avoid leaking the hash tables - register a
		 * callback to free them. Ideally wmem would implement a simple
		 * hash table so we wouldn't have to do this. */
		wmem_register_callback(wmem_file_scope(), smb2_conv_destroy,
				si->conv);

		conversation_add_proto_data(conversation, proto_smb2, si->conv);
	}

	sti->conv = si->conv;
	scti->conv = si->conv;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SMB2");
	if (first_in_chain) {
		/* first packet */
		col_clear(pinfo->cinfo, COL_INFO);
	} else {
		col_append_str(pinfo->cinfo, COL_INFO, ";");
	}

	item = proto_tree_add_item(parent_tree, proto_smb2, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_smb2);

	header_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_smb2_header, &header_item, label);

	/* Decode the header */

	if (msg_type == SMB2_NORM_HEADER) {
		/* SMB2 marker */
		proto_tree_add_item(header_tree, hf_smb2_protocol_id, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		/* we need the flags before we know how to parse the credits field */
		si->flags = tvb_get_letohl(tvb, offset+12);

		/* header length */
		proto_tree_add_item(header_tree, hf_smb2_header_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		/* credit charge (previously "epoch" (unused) which has been deprecated as of "SMB 2.1") */
		proto_tree_add_item(header_tree, hf_smb2_credit_charge, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		/* Status Code */
		if (si->flags & SMB2_FLAGS_RESPONSE) {
			si->status = tvb_get_letohl(tvb, offset);
			proto_tree_add_item(header_tree, hf_smb2_nt_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
		} else {
			si->status = 0;
			proto_tree_add_item(header_tree, hf_smb2_channel_sequence, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
			proto_tree_add_item(header_tree, hf_smb2_reserved, tvb, offset, 2, ENC_NA);
			offset += 2;
		}

		/* opcode */
		si->opcode = tvb_get_letohs(tvb, offset);
		proto_tree_add_item(header_tree, hf_smb2_cmd, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		/* credits */
		if (si->flags & SMB2_FLAGS_RESPONSE) {
			proto_tree_add_item(header_tree, hf_smb2_credits_granted, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		} else {
			proto_tree_add_item(header_tree, hf_smb2_credits_requested, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		}
		offset += 2;

		/* flags */
		if (header_tree) {
			static int * const  flags[] = {
				&hf_smb2_flags_response,
				&hf_smb2_flags_async_cmd,
				&hf_smb2_flags_chained,
				&hf_smb2_flags_signature,
				&hf_smb2_flags_priority_mask,
				&hf_smb2_flags_dfs_op,
				&hf_smb2_flags_replay_operation,
				NULL
			};

			proto_tree_add_bitmask(header_tree, tvb, offset, hf_smb2_flags,
									ett_smb2_flags, flags, ENC_LITTLE_ENDIAN);
		}

		offset += 4;

		/* Next Command */
		chain_offset = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(header_tree, hf_smb2_chain_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		/* Message ID */
		si->msg_id = tvb_get_letoh64(tvb, offset);
		ssi_key.msg_id = si->msg_id;
		proto_tree_add_item(header_tree, hf_smb2_msg_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		/* Tree ID and Session ID */
		offset = dissect_smb2_tid_sesid(pinfo, header_tree, tvb, offset, si);

		/* Signature */
		dissect_smb2_signature(pinfo, tvb, offset, header_tree, si);
		offset += 16;
		proto_item_set_len(header_item, offset);

		/* Check if this is a special packet type and it has non-regular title */
		packet_title = get_special_packet_title(si->opcode, si->flags, si->msg_id, tvb, offset);
		if (packet_title) {
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s", packet_title);
		} else {
			/* Regular packets have standard title */
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s %s",
					decode_smb2_name(si->opcode),
					(si->flags & SMB2_FLAGS_RESPONSE)?"Response":"Request");
		}
		if (si->status) {
			col_append_fstr(
					pinfo->cinfo, COL_INFO, ", Error: %s",
					val_to_str_ext(si->status, &NT_errors_ext,
						       "Unknown (0x%08X)"));
		}


		if (!pinfo->fd->visited) {
			/* see if we can find this msg_id in the unmatched table */
			ssi = (smb2_saved_info_t *)g_hash_table_lookup(si->conv->unmatched, &ssi_key);

			if (!(si->flags & SMB2_FLAGS_RESPONSE)) {
				/* This is a request */
				if (ssi) {
					/* this is a request and we already found
					* an older ssi so just delete the previous
					* one
					*/
					g_hash_table_remove(si->conv->unmatched, ssi);
					ssi = NULL;
				}

				if (!ssi) {
					/* no we couldn't find it, so just add it then
					* if was a request we are decoding
					*/
					ssi                  = wmem_new0(wmem_file_scope(), smb2_saved_info_t);
					ssi->msg_id          = ssi_key.msg_id;
					ssi->frame_req       = pinfo->num;
					ssi->req_time        = pinfo->abs_ts;
					ssi->extra_info_type = SMB2_EI_NONE;
					g_hash_table_insert(si->conv->unmatched, ssi, ssi);
				}
			} else {
				/* This is a response */
				if (!((si->flags & SMB2_FLAGS_ASYNC_CMD)
					&& si->status == NT_STATUS_PENDING)
					&& ssi) {
					/* just  set the response frame and move it to the matched table */
					ssi->frame_res = pinfo->num;
					g_hash_table_remove(si->conv->unmatched, ssi);
					g_hash_table_insert(si->conv->matched, ssi, ssi);
				}
			}
		} else {
			/* see if we can find this msg_id in the matched table */
			ssi = (smb2_saved_info_t *)g_hash_table_lookup(si->conv->matched, &ssi_key);
			/* if we couldn't find it in the matched table, it might still
			* be in the unmatched table
			*/
			if (!ssi) {
				ssi = (smb2_saved_info_t *)g_hash_table_lookup(si->conv->unmatched, &ssi_key);
			}
		}

		if (ssi) {
			if (dcerpc_fetch_polhnd_data(&ssi->policy_hnd, &fid_name, NULL, &open_frame, &close_frame, pinfo->num)) {
				/* If needed, create the file entry and save the policy hnd */
				if (!si->eo_file_info) {
					if (si->conv) {
						eo_file_info = (smb2_eo_file_info_t *)wmem_map_lookup(si->session->files,&ssi->policy_hnd);
						if (!eo_file_info) { /* XXX This should never happen */
							/* assert(1==0); */
							eo_file_info = wmem_new(wmem_file_scope(), smb2_eo_file_info_t);
							policy_hnd_hashtablekey = wmem_new(wmem_file_scope(), e_ctx_hnd);
							memcpy(policy_hnd_hashtablekey, &ssi->policy_hnd, sizeof(e_ctx_hnd));
							eo_file_info->end_of_file=0;
							wmem_map_insert(si->session->files,policy_hnd_hashtablekey,eo_file_info);
						}
						si->eo_file_info=eo_file_info;
					}
				}
			}

			if (!(si->flags & SMB2_FLAGS_RESPONSE)) {
				if (ssi->frame_res) {
					proto_item *tmp_item;
					tmp_item = proto_tree_add_uint(header_tree, hf_smb2_response_in, tvb, 0, 0, ssi->frame_res);
					proto_item_set_generated(tmp_item);
				}
			} else {
				if (ssi->frame_req) {
					proto_item *tmp_item;
					nstime_t    t, deltat;

					tmp_item = proto_tree_add_uint(header_tree, hf_smb2_response_to, tvb, 0, 0, ssi->frame_req);
					proto_item_set_generated(tmp_item);
					t = pinfo->abs_ts;
					nstime_delta(&deltat, &t, &ssi->req_time);
					tmp_item = proto_tree_add_time(header_tree, hf_smb2_time, tvb,
					0, 0, &deltat);
					proto_item_set_generated(tmp_item);
				}
			}
			if (si->file != NULL) {
				ssi->file = si->file;
			} else {
				si->file = ssi->file;
			}
		}
		/* if we don't have ssi yet we must fake it */
		/*qqq*/
		si->saved = ssi;

		tap_queue_packet(smb2_tap, pinfo, si);

		/* Decode the payload */
		offset                = dissect_smb2_command(pinfo, tree, tvb, offset, si);
	} else if (msg_type == SMB2_ENCR_HEADER) {
		proto_tree *enc_tree;
		tvbuff_t   *enc_tvb   = NULL;
		tvbuff_t   *plain_tvb = NULL;

		/* SMB2_TRANSFORM marker */
		proto_tree_add_item(header_tree, hf_smb2_protocol_id, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		offset = dissect_smb2_transform_header(pinfo, header_tree, tvb, offset, sti,
						       &enc_tvb, &plain_tvb);

		enc_tree = proto_tree_add_subtree(tree, enc_tvb, 0, sti->size, ett_smb2_encrypted, NULL, "Encrypted SMB3 data");
		if (plain_tvb != NULL) {
			col_append_str(pinfo->cinfo, COL_INFO, "Decrypted SMB3");
			dissect_smb2(plain_tvb, pinfo, enc_tree, FALSE);
		} else {
			col_append_str(pinfo->cinfo, COL_INFO, "Encrypted SMB3");
			proto_tree_add_item(enc_tree, hf_smb2_transform_encrypted_data,
					    enc_tvb, 0, sti->size, ENC_NA);
		}

		if (tvb_reported_length_remaining(tvb, offset) > 0) {
			chain_offset = offset;
		}
	} else if (msg_type == SMB2_COMP_HEADER) {
		proto_tree *comp_tree;
		proto_item *decomp_item;
		tvbuff_t   *plain_tvb = NULL;
		tvbuff_t   *comp_tvb = NULL;

		offset = dissect_smb2_comp_transform_header(pinfo, header_tree, tvb, offset,
							    scti, &comp_tvb, &plain_tvb);

		if (plain_tvb) {
			comp_tree = proto_tree_add_subtree(header_tree, plain_tvb, 0,
							   tvb_reported_length_remaining(plain_tvb, 0),
							   ett_smb2_decompressed, &decomp_item,
							   "Decompressed SMB3 data");
			proto_item_set_generated(decomp_item);
			dissect_smb2(plain_tvb, pinfo, comp_tree, FALSE);
		} else {
			comp_tree = proto_tree_add_subtree(header_tree, tvb, offset,
							   tvb_reported_length_remaining(tvb, offset),
							   ett_smb2_compressed, NULL,
							   "Compressed SMB3 data");
			/* show the compressed payload only if we cant uncompress it */
			proto_tree_add_item(comp_tree, hf_smb2_comp_transform_data,
					    tvb, offset,
					    tvb_reported_length_remaining(tvb, offset),
					    ENC_NA);
		}

		offset += tvb_reported_length_remaining(tvb, offset);
	} else {
		col_append_str(pinfo->cinfo, COL_INFO, "Invalid header");

		/* bad packet after decompressing/decrypting */
		offset += tvb_reported_length_remaining(tvb, offset);
	}

	if (chain_offset > 0) {
		tvbuff_t *next_tvb;

		proto_item_set_len(item, chain_offset);

		next_tvb = tvb_new_subset_remaining(tvb, chain_offset);
		offset   = dissect_smb2(next_tvb, pinfo, parent_tree, FALSE);
	}

	return offset;
}

static gboolean
dissect_smb2_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	guint8 b;

	/* must check that this really is a smb2 packet */
	if (tvb_captured_length(tvb) < 4)
		return FALSE;

	b = tvb_get_guint8(tvb, 0);
	if (((b != SMB2_COMP_HEADER) && (b != SMB2_ENCR_HEADER) && (b != SMB2_NORM_HEADER))
	    || (tvb_get_guint8(tvb, 1) != 'S')
	    || (tvb_get_guint8(tvb, 2) != 'M')
	    || (tvb_get_guint8(tvb, 3) != 'B') ) {
		return FALSE;
	}

	dissect_smb2(tvb, pinfo, parent_tree, TRUE);

	return TRUE;
}

void
proto_register_smb2(void)
{
	module_t *smb2_module;
	static hf_register_info hf[] = {
		{ &hf_smb2_cmd,
			{ "Command", "smb2.cmd", FT_UINT16, BASE_DEC | BASE_EXT_STRING,
			&smb2_cmd_vals_ext, 0, "SMB2 Command Opcode", HFILL }
		},

		{ &hf_smb2_response_to,
			{ "Response to", "smb2.response_to", FT_FRAMENUM, BASE_NONE,
			FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0, "This packet is a response to the packet in this frame", HFILL }
		},

		{ &hf_smb2_response_in,
			{ "Response in", "smb2.response_in", FT_FRAMENUM, BASE_NONE,
			FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0, "The response to this packet is in this packet", HFILL }
		},

		{ &hf_smb2_time,
			{ "Time from request", "smb2.time", FT_RELATIVE_TIME, BASE_NONE,
			NULL, 0, "Time between Request and Response for SMB2 cmds", HFILL }
		},

		{ &hf_smb2_preauth_hash,
			{ "Preauth Hash", "smb2.preauth_hash", FT_BYTES, BASE_NONE,
			NULL, 0, "SMB3.1.1 pre-authentication SHA512 hash after hashing the packet", HFILL }
		},

		{ &hf_smb2_header_len,
			{ "Header Length", "smb2.header_len", FT_UINT16, BASE_DEC,
			NULL, 0, "SMB2 Size of Header", HFILL }
		},

		{ &hf_smb2_nt_status,
			{ "NT Status", "smb2.nt_status", FT_UINT32, BASE_HEX | BASE_EXT_STRING,
			&NT_errors_ext, 0, "NT Status code", HFILL }
		},

		{ &hf_smb2_msg_id,
			{ "Message ID", "smb2.msg_id", FT_UINT64, BASE_DEC|BASE_VAL64_STRING|BASE_SPECIAL_VALS,
			VALS64(unique_unsolicited_response), 0, NULL, HFILL }
		},

		{ &hf_smb2_tid,
			{ "Tree Id", "smb2.tid", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_aid,
			{ "Async Id", "smb2.aid", FT_UINT64, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_sesid,
			{ "Session Id", "smb2.sesid", FT_UINT64, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_previous_sesid,
			{ "Previous Session Id", "smb2.previous_sesid", FT_UINT64, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_chain_offset,
			{ "Chain Offset", "smb2.chain_offset", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_end_of_file,
			{ "End Of File", "smb2.eof", FT_UINT64, BASE_DEC,
			NULL, 0, "SMB2 End Of File/File size", HFILL }
		},

		{ &hf_smb2_nlinks,
			{ "Number of Links", "smb2.nlinks", FT_UINT32, BASE_DEC,
			NULL, 0, "Number of links to this object", HFILL }
		},

		{ &hf_smb2_file_id,
			{ "File Id", "smb2.file_id", FT_UINT64, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_allocation_size,
			{ "Allocation Size", "smb2.allocation_size", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_max_response_size,
			{ "Max Response Size", "smb2.max_response_size", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_getinfo_input_size,
			{ "Getinfo Input Size", "smb2.getinfo_input_size", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_getinfo_input_offset,
			{ "Getinfo Input Offset", "smb2.getinfo_input_offset", FT_UINT16, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_getsetinfo_additional,
			{ "Additional Info", "smb2.getsetinfo_additional", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_getsetinfo_additionals,
			{ "Additional Info", "smb2.getsetinfo_additionals", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_getsetinfo_additional_owner,
			{ "Owner", "smb2.getsetinfo_additional_secinfo.owner", FT_BOOLEAN, 32,
			TFS(&tfs_additional_owner), OWNER_SECURITY_INFORMATION, "Is owner security information being queried?", HFILL }},

		{ &hf_smb2_getsetinfo_additional_group,
			{ "Group", "smb2.getsetinfo_additional_secinfo.group", FT_BOOLEAN, 32,
			TFS(&tfs_additional_group), GROUP_SECURITY_INFORMATION, "Is group security information being queried?", HFILL }},

		{ &hf_smb2_getsetinfo_additional_dacl,
			{ "DACL", "smb2.getsetinfo_additional_secinfo.dacl", FT_BOOLEAN, 32,
			TFS(&tfs_additional_dacl), DACL_SECURITY_INFORMATION, "Is DACL security information being queried?", HFILL }},

		{ &hf_smb2_getsetinfo_additional_sacl,
			{ "SACL", "smb2.getsetinfo_additional_secinfo.sacl", FT_BOOLEAN, 32,
			TFS(&tfs_additional_sacl), SACL_SECURITY_INFORMATION, "Is SACL security information being queried?", HFILL }},

		{ &hf_smb2_getsetinfo_additional_label,
			{ "Integrity label", "smb2.getsetinfo_additional_secinfo.label", FT_BOOLEAN, 32,
			TFS(&tfs_additional_label), LABEL_SECURITY_INFORMATION, "Is integrity label security information being queried?", HFILL }},

		{ &hf_smb2_getsetinfo_additional_attribute,
			{ "Resource attribute", "smb2.getsetinfo_additional_secinfo.attribute", FT_BOOLEAN, 32,
			TFS(&tfs_additional_attribute), ATTRIBUTE_SECURITY_INFORMATION, "Is resource attribute security information being queried?", HFILL }},

		{ &hf_smb2_getsetinfo_additional_scope,
			{ "Central access policy", "smb2.getsetinfo_additional_secinfo.scope", FT_BOOLEAN, 32,
			TFS(&tfs_additional_scope), SCOPE_SECURITY_INFORMATION, "Is central access policy security information being queried?", HFILL }},

		{ &hf_smb2_getsetinfo_additional_backup,
			{ "Backup operation", "smb2.getsetinfo_additional_secinfo.backup", FT_BOOLEAN, 32,
			TFS(&tfs_additional_backup), BACKUP_SECURITY_INFORMATION, "Is backup operation security information being queried?", HFILL }},

		{ &hf_smb2_getinfo_flags,
			{ "Flags", "smb2.getinfo_flags", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_setinfo_size,
			{ "Setinfo Size", "smb2.setinfo_size", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_setinfo_offset,
			{ "Setinfo Offset", "smb2.setinfo_offset", FT_UINT16, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_setinfo_reserved,
			{ "Reserved", "smb2.setinfo_reserved", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_max_ioctl_out_size,
			{ "Max Ioctl Out Size", "smb2.max_ioctl_out_size", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_max_ioctl_in_size,
			{ "Max Ioctl In Size", "smb2.max_ioctl_in_size", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_required_buffer_size,
			{ "Required Buffer Size", "smb2.required_size", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_pid,
			{ "Process Id", "smb2.pid", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},


		/* SMB2 header flags  */
		{ &hf_smb2_flags,
			{ "Flags", "smb2.flags", FT_UINT32, BASE_HEX,
			NULL, 0, "SMB2 flags", HFILL }
		},

		{ &hf_smb2_flags_response,
			{ "Response", "smb2.flags.response", FT_BOOLEAN, 32,
			TFS(&tfs_flags_response), SMB2_FLAGS_RESPONSE, "Whether this is an SMB2 Request or Response", HFILL }
		},

		{ &hf_smb2_flags_async_cmd,
			{ "Async command", "smb2.flags.async", FT_BOOLEAN, 32,
			TFS(&tfs_flags_async_cmd), SMB2_FLAGS_ASYNC_CMD, NULL, HFILL }
		},

		{ &hf_smb2_flags_dfs_op,
			{ "DFS operation", "smb2.flags.dfs", FT_BOOLEAN, 32,
			TFS(&tfs_flags_dfs_op), SMB2_FLAGS_DFS_OP, NULL, HFILL }
		},

		{ &hf_smb2_flags_chained,
			{ "Chained", "smb2.flags.chained", FT_BOOLEAN, 32,
			TFS(&tfs_flags_chained), SMB2_FLAGS_CHAINED, "Whether the pdu continues a chain or not", HFILL }
		},
		{ &hf_smb2_flags_signature,
			{ "Signing", "smb2.flags.signature", FT_BOOLEAN, 32,
			TFS(&tfs_flags_signature), SMB2_FLAGS_SIGNATURE, "Whether the pdu is signed or not", HFILL }
		},

		{ &hf_smb2_flags_replay_operation,
			{ "Replay operation", "smb2.flags.replay", FT_BOOLEAN, 32,
			TFS(&tfs_flags_replay_operation), SMB2_FLAGS_REPLAY_OPERATION, "Whether this is a replay operation", HFILL }
		},

		{ &hf_smb2_flags_priority_mask,
			{ "Priority", "smb2.flags.priority_mask", FT_BOOLEAN, 32,
			TFS(&tfs_flags_priority_mask), SMB2_FLAGS_PRIORITY_MASK, "Priority Mask", HFILL }
		},

		{ &hf_smb2_tree,
			{ "Tree", "smb2.tree", FT_STRING, BASE_NONE,
			NULL, 0, "Name of the Tree/Share", HFILL }
		},

		{ &hf_smb2_filename,
			{ "Filename", "smb2.filename", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_filename_len,
			{ "Filename Length", "smb2.filename.len", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_replace_if,
			{ "Replace If", "smb2.rename.replace_if", FT_BOOLEAN, 8,
			TFS(&tfs_replace_if_exists), 0xFF, "Whether to replace if the target exists", HFILL }
		},

		{ &hf_smb2_data_offset,
			{ "Data Offset", "smb2.data_offset", FT_UINT16, BASE_HEX,
			NULL, 0, "Offset to data", HFILL }
		},

		{ &hf_smb2_find_info_level,
			{ "Info Level", "smb2.find.infolevel", FT_UINT32, BASE_DEC,
			VALS(smb2_find_info_levels), 0, "Find_Info Infolevel", HFILL }
		},
		{ &hf_smb2_find_flags,
			{ "Find Flags", "smb2.find.flags", FT_UINT8, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_find_pattern,
			{ "Search Pattern", "smb2.find.pattern", FT_STRING, BASE_NONE,
			NULL, 0, "Find pattern", HFILL }
		},

		{ &hf_smb2_find_info_blob,
			{ "Info", "smb2.find.info_blob", FT_BYTES, BASE_NONE,
			NULL, 0, "Find Info", HFILL }
		},

		{ &hf_smb2_ea_size,
			{ "EA Size", "smb2.ea_size", FT_UINT32, BASE_DEC,
			NULL, 0, "Size of EA data", HFILL }
		},

		{ &hf_smb2_position_information,
			{ "Position Information", "smb2.position_info", FT_UINT64, BASE_DEC,
			NULL, 0, "Current file position", HFILL }
		},

		{ &hf_smb2_mode_information,
			{ "Mode Information", "smb2.mode_info", FT_UINT32, BASE_HEX,
			NULL, 0, "File mode information", HFILL }
		},

		{ &hf_smb2_mode_file_write_through,
			{ "FILE_WRITE_THROUGH", "smb2.mode.file_write_through", FT_UINT32, BASE_HEX,
			NULL, 0x02, NULL, HFILL }
		},

		{ &hf_smb2_mode_file_sequential_only,
			{ "FILE_SEQUENTIAL_ONLY", "smb2.mode.file_sequential_only", FT_UINT32, BASE_HEX,
			NULL, 0x04, NULL, HFILL }
		},

		{ &hf_smb2_mode_file_no_intermediate_buffering,
			{ "FILE_NO_INTERMEDIATE_BUFFERING", "smb2.mode.file_no_intermediate_buffering", FT_UINT32, BASE_HEX,
			NULL, 0x08, NULL, HFILL }
		},

		{ &hf_smb2_mode_file_synchronous_io_alert,
			{ "FILE_SYNCHRONOUS_IO_ALERT", "smb2.mode.file_synchronous_io_alert", FT_UINT32, BASE_HEX,
			NULL, 0x10, NULL, HFILL }
		},

		{ &hf_smb2_mode_file_synchronous_io_nonalert,
			{ "FILE_SYNCHRONOUS_IO_NONALERT", "smb2.mode.file_synchronous_io_nonalert", FT_UINT32, BASE_HEX,
			NULL, 0x20, NULL, HFILL }
		},

		{ &hf_smb2_mode_file_delete_on_close,
			{ "FILE_DELETE_ON_CLOSE", "smb2.mode.file_delete_on_close", FT_UINT32, BASE_HEX,
			NULL, 0x1000, NULL, HFILL }
		},

		{ &hf_smb2_alignment_information,
			{ "Alignment Information", "smb2.alignment_info", FT_UINT32, BASE_HEX,
			VALS(smb2_alignment_vals), 0, "File alignment", HFILL}
		},

		{ &hf_smb2_class,
			{ "Class", "smb2.class", FT_UINT8, BASE_HEX,
			VALS(smb2_class_vals), 0, "Info class", HFILL }
		},

		{ &hf_smb2_infolevel,
			{ "InfoLevel", "smb2.infolevel", FT_UINT8, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_infolevel_file_info,
			{ "InfoLevel", "smb2.file_info.infolevel", FT_UINT8, BASE_HEX | BASE_EXT_STRING,
			&smb2_file_info_levels_ext, 0, "File_Info Infolevel", HFILL }
		},

		{ &hf_smb2_infolevel_fs_info,
			{ "InfoLevel", "smb2.fs_info.infolevel", FT_UINT8, BASE_HEX | BASE_EXT_STRING,
			&smb2_fs_info_levels_ext, 0, "Fs_Info Infolevel", HFILL }
		},

		{ &hf_smb2_infolevel_sec_info,
			{ "InfoLevel", "smb2.sec_info.infolevel", FT_UINT8, BASE_HEX | BASE_EXT_STRING,
			&smb2_sec_info_levels_ext, 0, "Sec_Info Infolevel", HFILL }
		},

		{ &hf_smb2_write_length,
			{ "Write Length", "smb2.write_length", FT_UINT32, BASE_DEC,
			NULL, 0, "Amount of data to write", HFILL }
		},

		{ &hf_smb2_read_blob,
			{ "Info", "smb2.read.blob", FT_BYTES, BASE_NONE,
			NULL, 0, "Read Blob", HFILL }
		},

		{ &hf_smb2_read_length,
			{ "Read Length", "smb2.read_length", FT_UINT32, BASE_DEC,
			NULL, 0, "Amount of data to read", HFILL }
		},

		{ &hf_smb2_read_remaining,
			{ "Read Remaining", "smb2.read_remaining", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_read_padding,
			{ "Padding", "smb2.read_padding", FT_UINT8, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_read_flags,
			{ "Flags", "smb2.read_flags", FT_UINT8, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_read_flags_unbuffered,
			{ "Unbuffered", "smb2.read_flags.unbuffered", FT_BOOLEAN, 8,
			TFS(&tfs_read_unbuffered), SMB2_READFLAG_READ_UNBUFFERED, "If client requests unbuffered read", HFILL }
		},

		{ &hf_smb2_read_flags_compressed,
			{ "Compressed", "smb2.read_flags.compressed", FT_BOOLEAN, 8,
			TFS(&tfs_read_compressed), SMB2_READFLAG_READ_COMPRESSED, "If client requests compressed response", HFILL }
		},

		{ &hf_smb2_create_flags,
			{ "Create Flags", "smb2.create_flags", FT_UINT64, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_file_offset,
			{ "File Offset", "smb2.file_offset", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_fsctl_range_offset,
			{ "File Offset", "smb2.fsctl.range_offset", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_fsctl_range_length,
			{ "Length", "smb2.fsctl.range_length", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_qfr_length,
			{ "Length", "smb2.qfr_length", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_qfr_usage,
			{ "Desired Usage", "smb2.qfr_usage", FT_UINT32, BASE_HEX,
			VALS(file_region_usage_vals), 0, NULL, HFILL }
		},

		{ &hf_smb2_qfr_flags,
			{ "Flags", "smb2.qfr_flags", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_qfr_total_region_entry_count,
			{ "Total Region Entry Count", "smb2.qfr_tot_region_entry_count", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_qfr_region_entry_count,
			{ "Region Entry Count", "smb2.qfr_region_entry_count", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_security_blob,
			{ "Security Blob", "smb2.security_blob", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_ioctl_out_data,
			{ "Out Data", "smb2.ioctl.out", FT_NONE, BASE_NONE,
			NULL, 0, "Ioctl Out", HFILL }
		},

		{ &hf_smb2_ioctl_in_data,
			{ "In Data", "smb2.ioctl.in", FT_NONE, BASE_NONE,
			NULL, 0, "Ioctl In", HFILL }
		},

		{ &hf_smb2_server_guid,
			{ "Server Guid", "smb2.server_guid", FT_GUID, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_client_guid,
			{ "Client Guid", "smb2.client_guid", FT_GUID, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_object_id,
			{ "ObjectId", "smb2.object_id", FT_GUID, BASE_NONE,
			NULL, 0, "ObjectID for this FID", HFILL }
		},

		{ &hf_smb2_birth_volume_id,
			{ "BirthVolumeId", "smb2.birth_volume_id", FT_GUID, BASE_NONE,
			NULL, 0, "ObjectID for the volume where this FID was originally created", HFILL }
		},

		{ &hf_smb2_birth_object_id,
			{ "BirthObjectId", "smb2.birth_object_id", FT_GUID, BASE_NONE,
			NULL, 0, "ObjectID for this FID when it was originally created", HFILL }
		},

		{ &hf_smb2_domain_id,
			{ "DomainId", "smb2.domain_id", FT_GUID, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_create_timestamp,
			{ "Create", "smb2.create.time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
			NULL, 0, "Time when this object was created", HFILL }
		},

		{ &hf_smb2_fid,
			{ "File Id", "smb2.fid", FT_GUID, BASE_NONE,
			NULL, 0, "SMB2 File Id", HFILL }
		},

		{ &hf_smb2_write_data,
			{ "Write Data", "smb2.write_data", FT_BYTES, BASE_NONE,
			NULL, 0, "SMB2 Data to be written", HFILL }
		},

		{ &hf_smb2_write_flags,
			{ "Write Flags", "smb2.write.flags", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_write_flags_write_through,
			{ "Write through", "smb2.write.flags.write_through", FT_BOOLEAN, 32,
			TFS(&tfs_write_through), SMB2_WRITE_FLAG_WRITE_THROUGH, "If the client requests WRITE_THROUGH", HFILL }
		},

		{ &hf_smb2_write_flags_write_unbuffered,
			{ "Unbuffered", "smb2.write.flags.unbuffered", FT_BOOLEAN, 32,
			TFS(&tfs_write_unbuffered), SMB2_WRITE_FLAG_WRITE_UNBUFFERED, "If client requests UNBUFFERED read", HFILL }
		},

		{ &hf_smb2_write_count,
			{ "Write Count", "smb2.write.count", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_write_remaining,
			{ "Write Remaining", "smb2.write.remaining", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_read_data,
			{ "Read Data", "smb2.read_data", FT_BYTES, BASE_NONE,
			NULL, 0, "SMB2 Data that is read", HFILL }
		},

		{ &hf_smb2_last_access_timestamp,
			{ "Last Access", "smb2.last_access.time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
			NULL, 0, "Time when this object was last accessed", HFILL }
		},

		{ &hf_smb2_last_write_timestamp,
			{ "Last Write", "smb2.last_write.time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
			NULL, 0, "Time when this object was last written to", HFILL }
		},

		{ &hf_smb2_last_change_timestamp,
			{ "Last Change", "smb2.last_change.time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
			NULL, 0, "Time when this object was last changed", HFILL }
		},

		{ &hf_smb2_file_all_info,
			{ "SMB2_FILE_ALL_INFO", "smb2.file_all_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_file_allocation_info,
			{ "SMB2_FILE_ALLOCATION_INFO", "smb2.file_allocation_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_file_endoffile_info,
			{ "SMB2_FILE_ENDOFFILE_INFO", "smb2.file_endoffile_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_good_signature,
			{ "Good signature", "smb2.good_signature", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_bad_signature,
			{ "Bad signature. Should be", "smb2.bad_signature", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_file_alternate_name_info,
			{ "SMB2_FILE_ALTERNATE_NAME_INFO", "smb2.file_alternate_name_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_file_normalized_name_info,
			{ "SMB2_FILE_NORMALIZED_NAME_INFO", "smb2.file_normalized_name_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_file_stream_info,
			{ "SMB2_FILE_STREAM_INFO", "smb2.file_stream_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_file_pipe_info,
			{ "SMB2_FILE_PIPE_INFO", "smb2.file_pipe_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_file_compression_info,
			{ "SMB2_FILE_COMPRESSION_INFO", "smb2.file_compression_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_file_basic_info,
			{ "SMB2_FILE_BASIC_INFO", "smb2.file_basic_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_file_standard_info,
			{ "SMB2_FILE_STANDARD_INFO", "smb2.file_standard_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_file_internal_info,
			{ "SMB2_FILE_INTERNAL_INFO", "smb2.file_internal_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_file_mode_info,
			{ "SMB2_FILE_MODE_INFO", "smb2.file_mode_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_file_alignment_info,
			{ "SMB2_FILE_ALIGNMENT_INFO", "smb2.file_alignment_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_file_position_info,
			{ "SMB2_FILE_POSITION_INFO", "smb2.file_position_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_file_access_info,
			{ "SMB2_FILE_ACCESS_INFO", "smb2.file_access_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_file_ea_info,
			{ "SMB2_FILE_EA_INFO", "smb2.file_ea_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_file_network_open_info,
			{ "SMB2_FILE_NETWORK_OPEN_INFO", "smb2.file_network_open_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_file_attribute_tag_info,
			{ "SMB2_FILE_ATTRIBUTE_TAG_INFO", "smb2.file_attribute_tag_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_file_disposition_info,
			{ "SMB2_FILE_DISPOSITION_INFO", "smb2.file_disposition_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_file_full_ea_info,
			{ "SMB2_FILE_FULL_EA_INFO", "smb2.file_full_ea_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_file_rename_info,
			{ "SMB2_FILE_RENAME_INFO", "smb2.file_rename_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_fs_info_01,
			{ "FileFsVolumeInformation", "smb2.fs_volume_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_fs_info_03,
			{ "FileFsSizeInformation", "smb2.fs_size_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_fs_info_04,
			{ "FileFsDeviceInformation", "smb2.fs_device_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_fs_info_05,
			{ "FileFsAttributeInformation", "smb2.fs_attribute_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_fs_info_06,
			{ "FileFsControlInformation", "smb2.fs_control_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_fs_info_07,
			{ "FileFsFullSizeInformation", "smb2.fs_full_size_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_fs_objectid_info,
			{ "FileFsObjectIdInformation", "smb2.fs_objectid_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_sec_info_00,
			{ "SMB2_SEC_INFO_00", "smb2.sec_info_00", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_quota_info,
			{ "SMB2_QUOTA_INFO", "smb2.quota_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_query_quota_info,
			{ "SMB2_QUERY_QUOTA_INFO", "smb2.query_quota_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_qq_single,
			{ "ReturnSingle", "smb2.query_quota_info.single", FT_BOOLEAN, 8,
			NULL, 0xff, NULL, HFILL }
		},

		{ &hf_smb2_qq_restart,
			{ "RestartScan", "smb2.query_quota_info.restart", FT_BOOLEAN, 8,
			NULL, 0xff, NULL, HFILL }
		},

		{ &hf_smb2_qq_sidlist_len,
			{ "SidListLength", "smb2.query_quota_info.sidlistlen", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_qq_start_sid_len,
			{ "StartSidLength", "smb2.query_quota_info.startsidlen", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_qq_start_sid_offset,
			{ "StartSidOffset", "smb2.query_quota_info.startsidoffset", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_disposition_delete_on_close,
			{ "Delete on close", "smb2.disposition.delete_on_close", FT_BOOLEAN, 8,
			TFS(&tfs_disposition_delete_on_close), 0x01, NULL, HFILL }
		},


		{ &hf_smb2_create_disposition,
			{ "Disposition", "smb2.create.disposition", FT_UINT32, BASE_DEC,
			VALS(create_disposition_vals), 0, "Create disposition, what to do if the file does/does not exist", HFILL }
		},

		{ &hf_smb2_create_action,
			{ "Create Action", "smb2.create.action", FT_UINT32, BASE_DEC,
			VALS(oa_open_vals), 0, NULL, HFILL }
		},

		{ &hf_smb2_create_rep_flags,
			{ "Response Flags", "smb2.create.rep_flags", FT_UINT8, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_create_rep_flags_reparse_point,
			{ "ReparsePoint", "smb2.create.rep_flags.reparse_point", FT_BOOLEAN, 8,
			NULL, SMB2_CREATE_REP_FLAGS_REPARSE_POINT, NULL, HFILL }
		},

		{ &hf_smb2_extrainfo,
			{ "ExtraInfo", "smb2.create.extrainfo", FT_NONE, BASE_NONE,
			NULL, 0, "Create ExtraInfo", HFILL }
		},

		{ &hf_smb2_create_chain_offset,
			{ "Chain Offset", "smb2.create.chain_offset", FT_UINT32, BASE_HEX,
			NULL, 0, "Offset to next entry in chain or 0", HFILL }
		},

		{ &hf_smb2_create_chain_data,
			{ "Data", "smb2.create.chain_data", FT_NONE, BASE_NONE,
			NULL, 0, "Chain Data", HFILL }
		},

		{ &hf_smb2_FILE_OBJECTID_BUFFER,
			{ "FILE_OBJECTID_BUFFER", "smb2.FILE_OBJECTID_BUFFER", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_lease_key,
			{ "Lease Key", "smb2.lease.lease_key", FT_GUID, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_lease_state,
			{ "Lease State", "smb2.lease.lease_state", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_lease_state_read_caching,
			{ "Read Caching", "smb2.lease.lease_state.read_caching", FT_BOOLEAN, 32,
			NULL, SMB2_LEASE_STATE_READ_CACHING, NULL, HFILL }
		},

		{ &hf_smb2_lease_state_handle_caching,
			{ "Handle Caching", "smb2.lease.lease_state.handle_caching", FT_BOOLEAN, 32,
			NULL, SMB2_LEASE_STATE_HANDLE_CACHING, NULL, HFILL }
		},

		{ &hf_smb2_lease_state_write_caching,
			{ "Write Caching", "smb2.lease.lease_state.write_caching", FT_BOOLEAN, 32,
			NULL, SMB2_LEASE_STATE_WRITE_CACHING, NULL, HFILL }
		},

		{ &hf_smb2_lease_flags,
			{ "Lease Flags", "smb2.lease.lease_flags", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_lease_flags_break_ack_required,
			{ "Break Ack Required", "smb2.lease.lease_state.break_ack_required", FT_BOOLEAN, 32,
			NULL, SMB2_LEASE_FLAGS_BREAK_ACK_REQUIRED, NULL, HFILL }
		},

		{ &hf_smb2_lease_flags_break_in_progress,
			{ "Break In Progress", "smb2.lease.lease_state.break_in_progress", FT_BOOLEAN, 32,
			NULL, SMB2_LEASE_FLAGS_BREAK_IN_PROGRESS, NULL, HFILL }
		},

		{ &hf_smb2_lease_flags_parent_lease_key_set,
			{ "Parent Lease Key Set", "smb2.lease.lease_state.parent_lease_key_set", FT_BOOLEAN, 32,
			NULL, SMB2_LEASE_FLAGS_PARENT_LEASE_KEY_SET, NULL, HFILL }
		},

		{ &hf_smb2_lease_duration,
			{ "Lease Duration", "smb2.lease.lease_duration", FT_UINT64, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_parent_lease_key,
			{ "Parent Lease Key", "smb2.lease.parent_lease_key", FT_GUID, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_lease_epoch,
			{ "Lease Epoch", "smb2.lease.lease_oplock", FT_UINT16, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_lease_reserved,
			{ "Lease Reserved", "smb2.lease.lease_reserved", FT_UINT16, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_lease_break_reason,
			{ "Lease Break Reason", "smb2.lease.lease_break_reason", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_lease_access_mask_hint,
			{ "Access Mask Hint", "smb2.lease.access_mask_hint", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_lease_share_mask_hint,
			{ "Share Mask Hint", "smb2.lease.share_mask_hint", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_next_offset,
			{ "Next Offset", "smb2.next_offset", FT_UINT32, BASE_DEC,
			NULL, 0, "Offset to next buffer or 0", HFILL }
		},

		{ &hf_smb2_negotiate_context_type,
			{ "Type", "smb2.negotiate_context.type", FT_UINT16, BASE_HEX,
			VALS(smb2_negotiate_context_types), 0, NULL, HFILL }
		},

		{ &hf_smb2_negotiate_context_data_length,
			{ "DataLength", "smb2.negotiate_context.data_length", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_negotiate_context_offset,
			{ "NegotiateContextOffset", "smb2.negotiate_context.offset", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_negotiate_context_count,
			{ "NegotiateContextCount", "smb2.negotiate_context.count", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_hash_alg_count,
			{ "HashAlgorithmCount", "smb2.negotiate_context.hash_alg_count", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_smb2_hash_algorithm,
			{ "HashAlgorithm", "smb2.negotiate_context.hash_algorithm", FT_UINT16, BASE_HEX,
			VALS(smb2_hash_algorithm_types), 0, NULL, HFILL }},

		{ &hf_smb2_salt_length,
			{ "SaltLength", "smb2.negotiate_context.salt_length", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_smb2_salt,
			{ "Salt", "smb2.negotiate_context.salt", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_smb2_signing_alg_count,
			{ "SigningAlgorithmCount", "smb2.negotiate_context.signing_alg_count", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_smb2_signing_alg_id,
			{ "SigningAlgorithmId", "smb2.negotiate_context.signing_id", FT_UINT16, BASE_HEX,
			VALS(smb2_signing_alg_types), 0, NULL, HFILL }},

		{ &hf_smb2_cipher_count,
			{ "CipherCount", "smb2.negotiate_context.cipher_count", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_smb2_cipher_id,
			{ "CipherId", "smb2.negotiate_context.cipher_id", FT_UINT16, BASE_HEX,
			VALS(smb2_cipher_types), 0, NULL, HFILL }},

		{ &hf_smb2_posix_reserved,
			{ "POSIX Reserved", "smb2.negotiate_context.posix_reserved", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_inode,
			{ "Inode", "smb2.inode", FT_UINT64, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_comp_alg_count,
			{ "CompressionAlgorithmCount", "smb2.negotiate_context.comp_alg_count", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_smb2_comp_alg_id,
			{ "CompressionAlgorithmId", "smb2.negotiate_context.comp_alg_id", FT_UINT16, BASE_HEX,
			VALS(smb2_comp_alg_types), 0, NULL, HFILL }},

		{ &hf_smb2_comp_alg_flags,
			{ "Flags", "smb2.negotiate_context.comp_alg_flags", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_comp_alg_flags_chained,
			{ "Chained", "smb2.negotiate_context.comp_alg_flags.chained", FT_BOOLEAN, 32,
			NULL, SMB2_COMP_ALG_FLAGS_CHAINED, "Chained compression is supported on this connection", HFILL }
		},

		{ &hf_smb2_comp_alg_flags_reserved,
			{ "Reserved", "smb2.negotiate_context.comp_alg_flags.reserved", FT_UINT32, BASE_HEX,
			NULL, 0xFFFFFFFE, "Must be zero", HFILL }
		},

		{ &hf_smb2_netname_neg_id,
			{ "Netname", "smb2.negotiate_context.netname", FT_STRING,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		{ &hf_smb2_transport_ctx_flags,
			{ "Flags", "smb2.negotiate_context.transport_flags", FT_UINT32, BASE_HEX,
			  VALS(smb2_transport_ctx_flags_vals), 0, NULL, HFILL }
		},

		{ &hf_smb2_rdma_transform_count,
			{ "TransformCount", "smb2.negotiate_context.rdma_transform_count", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_rdma_transform_reserved1,
			{ "Reserved1", "smb2.negotiate_context.rdma_transform_reserved1", FT_UINT16, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_rdma_transform_reserved2,
			{ "Reserved2", "smb2.negotiate_context.rdma_transform_reserved2", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_rdma_transform_id,
			{ "RDMATransformId", "smb2.negotiate_context.rdma_transform_id", FT_UINT16, BASE_HEX,
			VALS(smb2_rdma_transform_types), 0, NULL, HFILL }
		},

		{ &hf_smb2_current_time,
			{ "Current Time", "smb2.current_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
			NULL, 0, "Current Time at server", HFILL }
		},

		{ &hf_smb2_boot_time,
			{ "Boot Time", "smb2.boot_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
			NULL, 0, "Boot Time at server", HFILL }
		},

		{ &hf_smb2_ea_flags,
			{ "EA Flags", "smb2.ea.flags", FT_UINT8, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_ea_name_len,
			{ "EA Name Length", "smb2.ea.name_len", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_ea_data_len,
			{ "EA Data Length", "smb2.ea.data_len", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_delete_pending,
			{ "Delete Pending", "smb2.delete_pending", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_is_directory,
			{ "Is Directory", "smb2.is_directory", FT_UINT8, BASE_DEC,
			NULL, 0, "Is this a directory?", HFILL }
		},

		{ &hf_smb2_oplock,
			{ "Oplock", "smb2.create.oplock", FT_UINT8, BASE_HEX,
			VALS(oplock_vals), 0, "Oplock type", HFILL }
		},

		{ &hf_smb2_close_flags,
			{ "Close Flags", "smb2.close.flags", FT_UINT16, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_notify_flags,
			{ "Notify Flags", "smb2.notify.flags", FT_UINT16, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_buffer_code,
			{ "StructureSize", "smb2.buffer_code", FT_UINT16, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_buffer_code_len,
			{ "Fixed Part Length", "smb2.buffer_code.length", FT_UINT16, BASE_DEC,
			NULL, 0xFFFE, "Length of fixed portion of PDU", HFILL }
		},

		{ &hf_smb2_olb_length,
			{ "Blob Length", "smb2.olb.length", FT_UINT32, BASE_DEC,
			NULL, 0, "Length of the buffer", HFILL }
		},

		{ &hf_smb2_olb_offset,
			{ "Blob Offset", "smb2.olb.offset", FT_UINT32, BASE_HEX,
			NULL, 0, "Offset to the buffer", HFILL }
		},

		{ &hf_smb2_buffer_code_flags_dyn,
			{ "Dynamic Part", "smb2.buffer_code.dynamic", FT_BOOLEAN, 16,
			NULL, 0x0001, "Whether a dynamic length blob follows", HFILL }
		},

		{ &hf_smb2_ea_data,
			{ "EA Data", "smb2.ea.data", FT_BYTES, BASE_NONE|BASE_SHOW_ASCII_PRINTABLE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_ea_name,
			{ "EA Name", "smb2.ea.name", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_impersonation_level,
			{ "Impersonation level", "smb2.impersonation.level", FT_UINT32, BASE_DEC,
			VALS(impersonation_level_vals), 0, NULL, HFILL }
		},

		{ &hf_smb2_ioctl_function,
			{ "Function", "smb2.ioctl.function", FT_UINT32, BASE_HEX | BASE_EXT_STRING,
			&smb2_ioctl_vals_ext, 0, "Ioctl function", HFILL }
		},

		{ &hf_smb2_ioctl_function_device,
			{ "Device", "smb2.ioctl.function.device", FT_UINT32, BASE_HEX | BASE_EXT_STRING,
			&smb2_ioctl_device_vals_ext, 0xffff0000, "Device for Ioctl", HFILL }
		},

		{ &hf_smb2_ioctl_function_access,
			{ "Access", "smb2.ioctl.function.access", FT_UINT32, BASE_HEX,
			VALS(smb2_ioctl_access_vals), 0x0000c000, "Access for Ioctl", HFILL }
		},

		{ &hf_smb2_ioctl_function_function,
			{ "Function", "smb2.ioctl.function.function", FT_UINT32, BASE_HEX,
			NULL, 0x00003ffc, "Function for Ioctl", HFILL }
		},

		{ &hf_smb2_ioctl_function_method,
			{ "Method", "smb2.ioctl.function.method", FT_UINT32, BASE_HEX,
			VALS(smb2_ioctl_method_vals), 0x00000003, "Method for Ioctl", HFILL }
		},

		{ &hf_smb2_fsctl_pipe_wait_timeout,
			{ "Timeout", "smb2.fsctl.wait.timeout", FT_INT64, BASE_DEC,
			NULL, 0, "Wait timeout", HFILL }
		},

		{ &hf_smb2_fsctl_pipe_wait_name,
			{ "Name", "smb2.fsctl.wait.name", FT_STRING, BASE_NONE,
			NULL, 0, "Pipe name", HFILL }
		},

		{ &hf_smb2_fsctl_odx_token_type,
			{ "TokenType", "smb2.fsctl.odx.token.type", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_fsctl_odx_token_idlen,
			{ "TokenIdLength", "smb2.fsctl.odx.token.idlen", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_fsctl_odx_token_idraw,
			{ "TokenId", "smb2.fsctl.odx.token.id", FT_BYTES, BASE_NONE,
			NULL, 0, "Token ID (opaque)", HFILL }
		},

		{ &hf_smb2_fsctl_odx_token_ttl,
			{ "TokenTimeToLive", "smb2.fsctl.odx.token_ttl", FT_UINT32, BASE_DEC,
			NULL, 0, "TTL requested for the token (in milliseconds)", HFILL }
		},

		{ &hf_smb2_fsctl_odx_size,
			{ "Size", "smb2.fsctl.odx.size", FT_UINT32, BASE_DEC,
			NULL, 0, "Size of this data element", HFILL }
		},

		{ &hf_smb2_fsctl_odx_flags,
			{ "Flags", "smb2.fsctl.odx.flags", FT_UINT32, BASE_HEX,
			NULL, 0, "Flags for this operation", HFILL }
		},

		{ &hf_smb2_fsctl_odx_file_offset,
			{ "FileOffset", "smb2.fsctl.odx.file_offset", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_fsctl_odx_copy_length,
			{ "CopyLength", "smb2.fsctl.odx.copy_length", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_fsctl_odx_xfer_length,
			{ "TransferLength", "smb2.fsctl.odx.xfer_length", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_fsctl_odx_token_offset,
			{ "TokenOffset", "smb2.fsctl.odx.token_offset", FT_UINT64, BASE_DEC,
			NULL, 0, "Token Offset (relative to start of token)", HFILL }
		},

		{ &hf_smb2_fsctl_sparse_flag,
			{ "SetSparse", "smb2.fsctl.set_sparse", FT_BOOLEAN, 8,
			NULL, 0xFF, NULL, HFILL }
		},

		{ &hf_smb2_ioctl_resiliency_timeout,
			{ "Timeout", "smb2.ioctl.resiliency.timeout", FT_UINT32, BASE_DEC,
			NULL, 0, "Resiliency timeout", HFILL }
		},

		{ &hf_smb2_ioctl_resiliency_reserved,
			{ "Reserved", "smb2.ioctl.resiliency.reserved", FT_UINT32, BASE_DEC,
			NULL, 0, "Resiliency reserved", HFILL }
		},

		{ &hf_smb2_ioctl_shared_virtual_disk_support,
			{ "SharedVirtualDiskSupport", "smb2.ioctl.shared_virtual_disk.support", FT_UINT32, BASE_HEX,
			VALS(smb2_ioctl_shared_virtual_disk_vals), 0, "Supported shared capabilities", HFILL }
		},

		{ &hf_smb2_ioctl_shared_virtual_disk_handle_state,
			{ "SharedVirtualDiskHandleState", "smb2.ioctl.shared_virtual_disk.handle_state", FT_UINT32, BASE_HEX,
			VALS(smb2_ioctl_shared_virtual_disk_hstate_vals), 0, NULL, HFILL }
		},

		{ &hf_smb2_ioctl_sqos_protocol_version,
			{ "ProtocolVersion", "smb2.ioctl.sqos.protocol_version", FT_UINT16, BASE_HEX,
			VALS(smb2_ioctl_sqos_protocol_version_vals), 0, NULL, HFILL }
		},

		{ &hf_smb2_ioctl_sqos_reserved,
			{ "Reserved", "smb2.ioctl.sqos.reserved", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_ioctl_sqos_options,
			{ "Operations", "smb2.ioctl.sqos.operations", FT_UINT32, BASE_HEX,
			NULL, 0, "SQOS operations", HFILL }
		},

		{ &hf_smb2_ioctl_sqos_op_set_logical_flow_id,
			{ "Set Logical Flow ID", "smb2.ioctl.sqos.operations.set_logical_flow_id", FT_BOOLEAN, 32,
			NULL, STORAGE_QOS_CONTROL_FLAG_SET_LOGICAL_FLOW_ID, "Whether Set Logical Flow ID operation is performed", HFILL }
		},

		{ &hf_smb2_ioctl_sqos_op_set_policy,
			{ "Set Policy", "smb2.ioctl.sqos.operations.set_policy", FT_BOOLEAN, 32,
			NULL, STORAGE_QOS_CONTROL_FLAG_SET_POLICY, "Whether Set Policy operation is performed", HFILL }
		},

		{ &hf_smb2_ioctl_sqos_op_probe_policy,
			{ "Probe Policy", "smb2.ioctl.sqos.operations.probe_policy", FT_BOOLEAN, 32,
			NULL, STORAGE_QOS_CONTROL_FLAG_PROBE_POLICY, "Whether Probe Policy operation is performed", HFILL }
		},

		{ &hf_smb2_ioctl_sqos_op_get_status,
			{ "Get Status", "smb2.ioctl.sqos.operations.get_status", FT_BOOLEAN, 32,
			NULL, STORAGE_QOS_CONTROL_FLAG_GET_STATUS, "Whether Get Status operation is performed", HFILL }
		},

		{ &hf_smb2_ioctl_sqos_op_update_counters,
			{ "Update Counters", "smb2.ioctl.sqos.operations.update_counters", FT_BOOLEAN, 32,
			NULL, STORAGE_QOS_CONTROL_FLAG_UPDATE_COUNTERS, "Whether Update Counters operation is performed", HFILL }
		},

		{ &hf_smb2_ioctl_sqos_logical_flow_id,
			{ "LogicalFlowID", "smb2.ioctl.sqos.logical_flow_id", FT_GUID, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_ioctl_sqos_policy_id,
			{ "PolicyID", "smb2.ioctl.sqos.policy_id", FT_GUID, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_ioctl_sqos_initiator_id,
			{ "InitiatorID", "smb2.ioctl.sqos.initiator_id", FT_GUID, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_ioctl_sqos_limit,
			{ "Limit", "smb2.ioctl.sqos.limit", FT_UINT64, BASE_DEC,
			NULL, 0, "Desired maximum throughput for the logical flow, in normalized IOPS", HFILL }
		},

		{ &hf_smb2_ioctl_sqos_reservation,
			{ "Reservation", "smb2.ioctl.sqos.reservation", FT_UINT64, BASE_DEC,
			NULL, 0, "Desired minimum throughput for the logical flow, in normalized 8KB IOPS", HFILL }
		},

		{ &hf_smb2_ioctl_sqos_initiator_name,
			{ "InitiatorName", "smb2.ioctl.sqos.initiator_name", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},

		{ &hf_smb2_ioctl_sqos_initiator_node_name,
			{ "InitiatorNodeName", "smb2.ioctl.sqos.initiator_node_name", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},

		{ &hf_smb2_ioctl_sqos_io_count_increment,
			{ "IoCountIncrement", "smb2.ioctl.sqos.io_count_increment", FT_UINT64, BASE_DEC,
			NULL, 0, "The total number of I/O requests issued by the initiator on the logical flow", HFILL }
		},

		{ &hf_smb2_ioctl_sqos_normalized_io_count_increment,
			{ "NormalizedIoCountIncrement", "smb2.ioctl.sqos.normalized_io_count_increment", FT_UINT64, BASE_DEC,
			NULL, 0, "The total number of normalized 8-KB I/O requests issued by the initiator on the logical flow", HFILL }
		},

		{ &hf_smb2_ioctl_sqos_latency_increment,
			{ "LatencyIncrement", "smb2.ioctl.sqos.latency_increment", FT_UINT64, BASE_DEC,
			NULL, 0, "The total latency (including initiator's queues delays) measured by the initiator", HFILL }
		},

		{ &hf_smb2_ioctl_sqos_lower_latency_increment,
			{ "LowerLatencyIncrement", "smb2.ioctl.sqos.lower_latency_increment", FT_UINT64, BASE_DEC,
			NULL, 0, "The total latency (excluding initiator's queues delays) measured by the initiator", HFILL }
		},

		{ &hf_smb2_ioctl_sqos_bandwidth_limit,
			{ "BandwidthLimit", "smb2.ioctl.sqos.bandwidth_limit", FT_UINT64, BASE_DEC,
			NULL, 0, "Desired maximum bandwidth for the logical flow, in kilobytes per second", HFILL }
		},

		{ &hf_smb2_ioctl_sqos_kilobyte_count_increment,
			{ "KilobyteCountIncrement", "smb2.ioctl.sqos.kilobyte_count_increment", FT_UINT64, BASE_DEC,
			NULL, 0, "The total data transfer length of all I/O requests, in kilobyte units, issued by the initiator on the logical flow", HFILL }
		},

		{ &hf_smb2_ioctl_sqos_time_to_live,
			{ "TimeToLive", "smb2.ioctl.sqos.time_to_live", FT_UINT32, BASE_DEC,
			NULL, 0, "The expected period of validity of the Status, MaximumIoRate and MinimumIoRate fields, expressed in milliseconds", HFILL }
		},

		{ &hf_smb2_ioctl_sqos_status,
			{ "Status", "smb2.ioctl.sqos.status", FT_UINT32, BASE_HEX,
			VALS(smb2_ioctl_sqos_status_vals), 0, "The current status of the logical flow", HFILL }
		},

		{ &hf_smb2_ioctl_sqos_maximum_io_rate,
			{ "MaximumIoRate", "smb2.ioctl.sqos.maximum_io_rate", FT_UINT64, BASE_DEC,
			NULL, 0, "The maximum I/O initiation rate currently assigned to the logical flow, expressed in normalized input/output operations per second (normalized IOPS)", HFILL }
		},

		{ &hf_smb2_ioctl_sqos_minimum_io_rate,
			{ "MinimumIoRate", "smb2.ioctl.sqos.minimum_io_rate", FT_UINT64, BASE_DEC,
			NULL, 0, "The minimum I/O completion rate currently assigned to the logical flow, expressed in normalized IOPS", HFILL }
		},

		{ &hf_smb2_ioctl_sqos_base_io_size,
			{ "BaseIoSize", "smb2.ioctl.sqos.base_io_size", FT_UINT32, BASE_DEC,
			NULL, 0, "The base I/O size used to compute the normalized size of an I/O request for the logical flow", HFILL }
		},

		{ &hf_smb2_ioctl_sqos_reserved2,
			{ "Reserved", "smb2.ioctl.sqos.reserved2", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_ioctl_sqos_maximum_bandwidth,
			{ "MaximumBandwidth", "smb2.ioctl.sqos.maximum_bandwidth", FT_UINT64, BASE_DEC,
			NULL, 0, "The maximum bandwidth currently assigned to the logical flow, expressed in kilobytes per second", HFILL }
		},


		{ &hf_windows_sockaddr_family,
			{ "Socket Family", "smb2.windows.sockaddr.family", FT_UINT16, BASE_DEC,
			NULL, 0, "The socket address family (on windows)", HFILL }
		},

		{ &hf_windows_sockaddr_port,
			{ "Socket Port", "smb2.windows.sockaddr.port", FT_UINT16, BASE_DEC,
			NULL, 0, "The socket address port", HFILL }
		},

		{ &hf_windows_sockaddr_in_addr,
			{ "Socket IPv4", "smb2.windows.sockaddr.in.addr", FT_IPv4, BASE_NONE,
			NULL, 0, "The IPv4 address", HFILL }
		},

		{ &hf_windows_sockaddr_in6_flowinfo,
			{ "IPv6 Flow Info", "smb2.windows.sockaddr.in6.flow_info", FT_UINT32, BASE_HEX,
			NULL, 0, "The socket IPv6 flow info", HFILL }
		},

		{ &hf_windows_sockaddr_in6_addr,
			{ "Socket IPv6", "smb2.windows.sockaddr.in6.addr", FT_IPv6, BASE_NONE,
			NULL, 0, "The IPv6 address", HFILL }
		},

		{ &hf_windows_sockaddr_in6_scope_id,
			{ "IPv6 Scope ID", "smb2.windows.sockaddr.in6.scope_id", FT_UINT32, BASE_DEC,
			NULL, 0, "The socket IPv6 scope id", HFILL }
		},

		{ &hf_smb2_ioctl_network_interface_next_offset,
			{ "Next Offset", "smb2.ioctl.network_interfaces.next_offset", FT_UINT32, BASE_HEX,
			NULL, 0, "Offset to next entry in chain or 0", HFILL }
		},

		{ &hf_smb2_ioctl_network_interface_index,
			{ "Interface Index", "smb2.ioctl.network_interfaces.index", FT_UINT32, BASE_DEC,
			NULL, 0, "The index of the interface", HFILL }
		},

		{ &hf_smb2_ioctl_network_interface_rss_queue_count,
			{ "RSS Queue Count", "smb2.ioctl.network_interfaces.rss_queue_count", FT_UINT32, BASE_DEC,
			NULL, 0, "The RSS queue count", HFILL }
		},

		{ &hf_smb2_ioctl_network_interface_capabilities,
			{ "Interface Cababilities", "smb2.ioctl.network_interfaces.capabilities", FT_UINT32, BASE_HEX,
			NULL, 0, "The capabilities of the network interface", HFILL }
		},

		{ &hf_smb2_ioctl_network_interface_capability_rss,
			{ "RSS", "smb2.ioctl.network_interfaces.capabilities.rss", FT_BOOLEAN, 32,
			TFS(&tfs_smb2_ioctl_network_interface_capability_rss), NETWORK_INTERFACE_CAP_RSS, "If the host supports RSS", HFILL }
		},

		{ &hf_smb2_ioctl_network_interface_capability_rdma,
			{ "RDMA", "smb2.ioctl.network_interfaces.capabilities.rdma", FT_BOOLEAN, 32,
			TFS(&tfs_smb2_ioctl_network_interface_capability_rdma), NETWORK_INTERFACE_CAP_RDMA, "If the host supports RDMA", HFILL }
		},

		{ &hf_smb2_ioctl_network_interface_link_speed,
			{ "Link Speed", "smb2.ioctl.network_interfaces.link_speed", FT_UINT64, BASE_DEC,
			NULL, 0, "The link speed of the interface", HFILL }
		},

		{ &hf_smb2_ioctl_enumerate_snapshots_num_snapshots,
			{ "Number of snapshots", "smb2.ioctl.enumerate_snapshots.num_snapshots", FT_UINT32, BASE_DEC,
			NULL, 0, "Number of previous versions associated with the volume", HFILL }
		},

		{ &hf_smb2_ioctl_enumerate_snapshots_num_snapshots_returned,
			{ "Number of snapshots returned", "smb2.ioctl.enumerate_snapshots.num_snapshots_returned", FT_UINT32, BASE_DEC,
			NULL, 0, "Number of previous version time stamps returned", HFILL }
		},

		{ &hf_smb2_ioctl_enumerate_snapshots_snapshot_array_size,
			{ "Array size", "smb2.ioctl.enumerate_snapshots.array_size", FT_UINT32, BASE_DEC,
			NULL, 0, "Number of bytes for snapshot time stamp strings", HFILL }
		},

		{ &hf_smb2_ioctl_enumerate_snapshots_snapshot,
			{ "Snapshot", "smb2.ioctl.enumerate_snapshots.snapshot", FT_STRINGZ, BASE_NONE,
			NULL, 0, "Time stamp of previous version", HFILL }
		},

		{ &hf_smb2_tree_connect_flags,
			{ "Flags", "smb2.tc.flags", FT_UINT16, BASE_HEX,
			NULL, 0, "Tree Connect flags", HFILL }
		},

		{ &hf_smb2_tc_cluster_reconnect,
			{ "Cluster Reconnect", "smb2.tc.cluster_reconnect", FT_BOOLEAN, 16,
			TFS(&tfs_set_notset), 0x0001, "If this is a Cluster Reconnect", HFILL }
		},

		{ &hf_smb2_tc_redirect_to_owner,
			{ "Redirect To Owner", "smb2.tc.redirect_to_owner", FT_BOOLEAN, 16,
			TFS(&tfs_set_notset), 0x0002, "Set if the client can handle Share Redirects", HFILL }
		},

		{ &hf_smb2_tc_extension_present,
			{ "Extension Present", "smb2.tc.extension_present", FT_BOOLEAN, 16,
			TFS(&tfs_set_notset), 0x0004, "Set if an extension structure is present", HFILL }
		},

		{ &hf_smb2_tc_reserved,
			{ "Reserved", "smb2.tc.reserved", FT_UINT16, BASE_HEX,
			NULL, 0xFFF8, "Must be zero", HFILL }
		},

		{ &hf_smb2_compression_format,
			{ "Compression Format", "smb2.compression_format", FT_UINT16, BASE_DEC,
			VALS(compression_format_vals), 0, NULL, HFILL }
		},

		{ &hf_smb2_checksum_algorithm,
			{ "Checksum Algorithm", "smb2.checksum_algorithm", FT_UINT16, BASE_HEX,
			VALS(checksum_algorithm_vals), 0, NULL, HFILL }
		},

		{ &hf_smb2_integrity_reserved,
			{ "Reserved", "smb2.integrity_reserved", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_integrity_flags,
			{ "Flags", "smb2.integrity_flags", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_integrity_flags_enforcement_off,
			{ "FSCTL_INTEGRITY_FLAG_CHECKSUM_ENFORCEMENT_OFF", "smb2.integrity_flags_enforcement", FT_BOOLEAN, 32,
			NULL, 0x1, "If checksum error enforcement is off", HFILL }
		},

		{ &hf_smb2_share_type,
			{ "Share Type", "smb2.share_type", FT_UINT8, BASE_HEX,
			VALS(smb2_share_type_vals), 0, "Type of share", HFILL }
		},

		{ &hf_smb2_credit_charge,
			{ "Credit Charge", "smb2.credit.charge", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_credits_requested,
			{ "Credits requested", "smb2.credits.requested", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_credits_granted,
			{ "Credits granted", "smb2.credits.granted", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_channel_sequence,
			{ "Channel Sequence", "smb2.channel_sequence", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_dialect_count,
			{ "Dialect count", "smb2.dialect_count", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_dialect,
			{ "Dialect", "smb2.dialect", FT_UINT16, BASE_HEX,
			VALS(smb2_dialect_vals), 0, NULL, HFILL }
		},

		{ &hf_smb2_security_mode,
			{ "Security mode", "smb2.sec_mode", FT_UINT8, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_session_flags,
			{ "Session Flags", "smb2.session_flags", FT_UINT16, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_lock_count,
			{ "Lock Count", "smb2.lock_count", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_capabilities,
			{ "Capabilities", "smb2.capabilities", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_auth_frame,
			{ "Authenticated in Frame", "smb2.auth_frame", FT_UINT32, BASE_DEC,
			NULL, 0, "Which frame this user was authenticated in", HFILL }
		},

		{ &hf_smb2_tcon_frame,
			{ "Connected in Frame", "smb2.tcon_frame", FT_UINT32, BASE_DEC,
			NULL, 0, "Which frame this share was connected in", HFILL }
		},

		{ &hf_smb2_tag,
			{ "Tag", "smb2.tag", FT_STRING, BASE_NONE,
			NULL, 0, "Tag of chain entry", HFILL }
		},

		{ &hf_smb2_acct_name,
			{ "Account", "smb2.acct", FT_STRING, BASE_NONE,
			NULL, 0, "Account Name", HFILL }
		},

		{ &hf_smb2_domain_name,
			{ "Domain", "smb2.domain", FT_STRING, BASE_NONE,
			NULL, 0, "Domain Name", HFILL }
		},

		{ &hf_smb2_host_name,
			{ "Host", "smb2.host", FT_STRING, BASE_NONE,
			NULL, 0, "Host Name", HFILL }
		},

		{ &hf_smb2_signature,
			{ "Signature", "smb2.signature", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_unknown,
			{ "Unknown", "smb2.unknown", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_twrp_timestamp,
			{ "Timestamp", "smb2.twrp_timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
			NULL, 0, "TWrp timestamp", HFILL }
		},

		{ &hf_smb2_mxac_timestamp,
			{ "Timestamp", "smb2.mxac_timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
			NULL, 0, "MxAc timestamp", HFILL }
		},

		{ &hf_smb2_mxac_status,
			{ "Query Status", "smb2.mxac_status", FT_UINT32, BASE_HEX | BASE_EXT_STRING,
			&NT_errors_ext, 0, "NT Status code", HFILL }
		},

		{ &hf_smb2_qfid_fid,
			{ "Opaque File ID", "smb2.qfid_fid", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_ses_flags_guest,
			{ "Guest", "smb2.ses_flags.guest", FT_BOOLEAN, 16,
			NULL, SES_FLAGS_GUEST, NULL, HFILL }
		},

		{ &hf_smb2_ses_flags_null,
			{ "Null", "smb2.ses_flags.null", FT_BOOLEAN, 16,
			NULL, SES_FLAGS_NULL, NULL, HFILL }
		},

		{ &hf_smb2_ses_flags_encrypt,
			{ "Encrypt", "smb2.ses_flags.encrypt", FT_BOOLEAN, 16,
			NULL, SES_FLAGS_ENCRYPT, NULL, HFILL }},

		{ &hf_smb2_secmode_flags_sign_required,
			{ "Signing required", "smb2.sec_mode.sign_required", FT_BOOLEAN, 8,
			NULL, NEGPROT_SIGN_REQ, "Is signing required", HFILL }
		},

		{ &hf_smb2_secmode_flags_sign_enabled,
			{ "Signing enabled", "smb2.sec_mode.sign_enabled", FT_BOOLEAN, 8,
			NULL, NEGPROT_SIGN_ENABLED, "Is signing enabled", HFILL }
		},

		{ &hf_smb2_ses_req_flags,
			{ "Flags", "smb2.ses_req_flags", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_ses_req_flags_session_binding,
			{ "Session Binding Request", "smb2.ses_req_flags.session_binding", FT_BOOLEAN, 8,
			NULL, SES_REQ_FLAGS_SESSION_BINDING, "The client wants to bind to an existing session", HFILL }
		},

		{ &hf_smb2_cap_dfs,
			{ "DFS", "smb2.capabilities.dfs", FT_BOOLEAN, 32,
			TFS(&tfs_cap_dfs), NEGPROT_CAP_DFS, "If the host supports dfs", HFILL }
		},

		{ &hf_smb2_cap_leasing,
			{ "LEASING", "smb2.capabilities.leasing", FT_BOOLEAN, 32,
			TFS(&tfs_cap_leasing), NEGPROT_CAP_LEASING, "If the host supports leasing", HFILL }
		},

		{ &hf_smb2_cap_large_mtu,
			{ "LARGE MTU", "smb2.capabilities.large_mtu", FT_BOOLEAN, 32,
			TFS(&tfs_cap_large_mtu), NEGPROT_CAP_LARGE_MTU, "If the host supports LARGE MTU", HFILL }
		},

		{ &hf_smb2_cap_multi_channel,
			{ "MULTI CHANNEL", "smb2.capabilities.multi_channel", FT_BOOLEAN, 32,
			TFS(&tfs_cap_multi_channel), NEGPROT_CAP_MULTI_CHANNEL, "If the host supports MULTI CHANNEL", HFILL }
		},

		{ &hf_smb2_cap_persistent_handles,
			{ "PERSISTENT HANDLES", "smb2.capabilities.persistent_handles", FT_BOOLEAN, 32,
			TFS(&tfs_cap_persistent_handles), NEGPROT_CAP_PERSISTENT_HANDLES, "If the host supports PERSISTENT HANDLES", HFILL }
		},

		{ &hf_smb2_cap_directory_leasing,
			{ "DIRECTORY LEASING", "smb2.capabilities.directory_leasing", FT_BOOLEAN, 32,
			TFS(&tfs_cap_directory_leasing), NEGPROT_CAP_DIRECTORY_LEASING, "If the host supports DIRECTORY LEASING", HFILL }
		},

		{ &hf_smb2_cap_encryption,
			{ "ENCRYPTION", "smb2.capabilities.encryption", FT_BOOLEAN, 32,
			TFS(&tfs_cap_encryption), NEGPROT_CAP_ENCRYPTION, "If the host supports ENCRYPTION", HFILL }
		},

		{ &hf_smb2_max_trans_size,
			{ "Max Transaction Size", "smb2.max_trans_size", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_max_read_size,
			{ "Max Read Size", "smb2.max_read_size", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_max_write_size,
			{ "Max Write Size", "smb2.max_write_size", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_channel,
			{ "Channel", "smb2.channel", FT_UINT32, BASE_HEX,
			VALS(smb2_channel_vals), 0, NULL, HFILL }
		},

		{ &hf_smb2_rdma_v1_offset,
			{ "Offset", "smb2.buffer_descriptor.offset", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_rdma_v1_token,
			{ "Token", "smb2.buffer_descriptor.token", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_rdma_v1_length,
			{ "Length", "smb2.buffer_descriptor.length", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_share_flags,
			{ "Share flags", "smb2.share_flags", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_share_flags_dfs,
			{ "DFS", "smb2.share_flags.dfs", FT_BOOLEAN, 32,
			NULL, SHARE_FLAGS_dfs, "The specified share is present in a Distributed File System (DFS) tree structure", HFILL }
		},

		{ &hf_smb2_share_flags_dfs_root,
			{ "DFS root", "smb2.share_flags.dfs_root", FT_BOOLEAN, 32,
			NULL, SHARE_FLAGS_dfs_root, "The specified share is present in a Distributed File System (DFS) tree structure", HFILL }
		},

		{ &hf_smb2_share_flags_restrict_exclusive_opens,
			{ "Restrict exclusive opens", "smb2.share_flags.restrict_exclusive_opens", FT_BOOLEAN, 32,
			NULL, SHARE_FLAGS_restrict_exclusive_opens, "The specified share disallows exclusive file opens that deny reads to an open file", HFILL }
		},

		{ &hf_smb2_share_flags_force_shared_delete,
			{ "Force shared delete", "smb2.share_flags.force_shared_delete", FT_BOOLEAN, 32,
			NULL, SHARE_FLAGS_force_shared_delete, "Shared files in the specified share can be forcibly deleted", HFILL }
		},

		{ &hf_smb2_share_flags_allow_namespace_caching,
			{ "Allow namespace caching", "smb2.share_flags.allow_namespace_caching", FT_BOOLEAN, 32,
			NULL, SHARE_FLAGS_allow_namespace_caching, "Clients are allowed to cache the namespace of the specified share", HFILL }
		},

		{ &hf_smb2_share_flags_access_based_dir_enum,
			{ "Access based directory enum", "smb2.share_flags.access_based_dir_enum", FT_BOOLEAN, 32,
			NULL, SHARE_FLAGS_access_based_dir_enum, "The server will filter directory entries based on the access permissions of the client", HFILL }
		},

		{ &hf_smb2_share_flags_force_levelii_oplock,
			{ "Force level II oplock", "smb2.share_flags.force_levelii_oplock", FT_BOOLEAN, 32,
			NULL, SHARE_FLAGS_force_levelii_oplock, "The server will not issue exclusive caching rights on this share", HFILL }
		},

		{ &hf_smb2_share_flags_enable_hash_v1,
			{ "Enable hash V1", "smb2.share_flags.enable_hash_v1", FT_BOOLEAN, 32,
			NULL, SHARE_FLAGS_enable_hash_v1, "The share supports hash generation V1 for branch cache retrieval of data (see also section 2.2.31.2 of MS-SMB2)", HFILL }
		},

		{ &hf_smb2_share_flags_enable_hash_v2,
			{ "Enable hash V2", "smb2.share_flags.enable_hash_v2", FT_BOOLEAN, 32,
			NULL, SHARE_FLAGS_enable_hash_v2, "The share supports hash generation V2 for branch cache retrieval of data (see also section 2.2.31.2 of MS-SMB2)", HFILL }
		},

		{ &hf_smb2_share_flags_encrypt_data,
			{ "Encrypted data required", "smb2.share_flags.encrypt_data", FT_BOOLEAN, 32,
			NULL, SHARE_FLAGS_encryption_required, "The share require data encryption", HFILL }
		},

		{ &hf_smb2_share_flags_identity_remoting,
			{ "Identity Remoting", "smb2.share_flags.identity_remoting", FT_BOOLEAN, 32,
			NULL, SHARE_FLAGS_identity_remoting, "The specified share supports Identity Remoting", HFILL }
		},

		{ &hf_smb2_share_flags_compress_data,
			{ "Compressed IO", "smb2.share_flags.compress_data", FT_BOOLEAN, 32,
			NULL, SHARE_FLAGS_compress_data, "The share supports compression of read/write messages", HFILL }
		},

		{ &hf_smb2_share_caching,
			{ "Caching policy", "smb2.share.caching", FT_UINT32, BASE_HEX,
			VALS(share_cache_vals), 0, NULL, HFILL }
		},

		{ &hf_smb2_share_caps,
			{ "Share Capabilities", "smb2.share_caps", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_share_caps_dfs,
			{ "DFS", "smb2.share_caps.dfs", FT_BOOLEAN, 32,
			NULL, SHARE_CAPS_DFS, "The specified share is present in a DFS tree structure", HFILL }
		},

		{ &hf_smb2_share_caps_continuous_availability,
			{ "CONTINUOUS AVAILABILITY", "smb2.share_caps.continuous_availability", FT_BOOLEAN, 32,
			NULL, SHARE_CAPS_CONTINUOUS_AVAILABILITY, "The specified share is continuously available", HFILL }
		},

		{ &hf_smb2_share_caps_scaleout,
			{ "SCALEOUT", "smb2.share_caps.scaleout", FT_BOOLEAN, 32,
			NULL, SHARE_CAPS_SCALEOUT, "The specified share is a scaleout share", HFILL }
		},

		{ &hf_smb2_share_caps_cluster,
			{ "CLUSTER", "smb2.share_caps.cluster", FT_BOOLEAN, 32,
			NULL, SHARE_CAPS_CLUSTER, "The specified share is a cluster share", HFILL }
		},

		{ &hf_smb2_share_caps_assymetric,
			{ "ASSYMETRIC", "smb2.share_caps.assymetric", FT_BOOLEAN, 32,
			NULL, SHARE_CAPS_ASSYMETRIC, "The specified share allows dynamic changes in ownership of the share", HFILL }
		},

		{ &hf_smb2_share_caps_redirect_to_owner,
			{ "REDIRECT_TO_OWNER", "smb2.share_caps.redirect_to_owner", FT_BOOLEAN, 32,
			NULL, SHARE_CAPS_REDIRECT_TO_OWNER, "The specified share supports synchronous share level redirection", HFILL }
		},

		{ &hf_smb2_ioctl_flags,
			{ "Flags", "smb2.ioctl.flags", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_min_count,
			{ "Min Count", "smb2.min_count", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_remaining_bytes,
			{ "Remaining Bytes", "smb2.remaining_bytes", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_channel_info_offset,
			{ "Channel Info Offset", "smb2.channel_info_offset", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_channel_info_length,
			{ "Channel Info Length", "smb2.channel_info_length", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_channel_info_blob,
			{ "Channel Info Blob", "smb2.channel_info_blob", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_ioctl_is_fsctl,
			{ "Is FSCTL", "smb2.ioctl.is_fsctl", FT_BOOLEAN, 32,
			NULL, 0x00000001, NULL, HFILL }
		},

		{ &hf_smb2_output_buffer_len,
			{ "Output Buffer Length", "smb2.output_buffer_len", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_close_pq_attrib,
			{ "PostQuery Attrib", "smb2.close.pq_attrib", FT_BOOLEAN, 16,
			NULL, 0x0001, NULL, HFILL }
		},

		{ &hf_smb2_notify_watch_tree,
			{ "Watch Tree", "smb2.notify.watch_tree", FT_BOOLEAN, 16,
			NULL, 0x0001, NULL, HFILL }
		},

		{ &hf_smb2_notify_out_data,
			{ "Out Data", "smb2.notify.out", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_notify_info,
			{ "Notify Info", "smb2.notify.info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_notify_next_offset,
			{ "Next Offset", "smb2.notify.next_offset", FT_UINT32, BASE_HEX,
			NULL, 0, "Offset to next entry in chain or 0", HFILL }
		},

		{ &hf_smb2_notify_action,
			{ "Action", "smb2.notify.action", FT_UINT32, BASE_HEX,
			VALS(notify_action_vals), 0, "Notify Action", HFILL }
		},


		{ &hf_smb2_find_flags_restart_scans,
			{ "Restart Scans", "smb2.find.restart_scans", FT_BOOLEAN, 8,
			NULL, SMB2_FIND_FLAG_RESTART_SCANS, NULL, HFILL }
		},

		{ &hf_smb2_find_flags_single_entry,
			{ "Single Entry", "smb2.find.single_entry", FT_BOOLEAN, 8,
			NULL, SMB2_FIND_FLAG_SINGLE_ENTRY, NULL, HFILL }
		},

		{ &hf_smb2_find_flags_index_specified,
			{ "Index Specified", "smb2.find.index_specified", FT_BOOLEAN, 8,
			NULL, SMB2_FIND_FLAG_INDEX_SPECIFIED, NULL, HFILL }
		},

		{ &hf_smb2_find_flags_reopen,
			{ "Reopen", "smb2.find.reopen", FT_BOOLEAN, 8,
			NULL, SMB2_FIND_FLAG_REOPEN, NULL, HFILL }
		},

		{ &hf_smb2_file_index,
			{ "File Index", "smb2.file_index", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_file_directory_info,
			{ "FileDirectoryInfo", "smb2.find.file_directory_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_full_directory_info,
			{ "FullDirectoryInfo", "smb2.find.full_directory_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_both_directory_info,
			{ "FileBothDirectoryInfo", "smb2.find.both_directory_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_id_both_directory_info,
			{ "FileIdBothDirectoryInfo", "smb2.find.id_both_directory_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_posix_info,
			{ "FilePosixInfo", "smb2.find.posix_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_short_name_len,
			{ "Short Name Length", "smb2.short_name_len", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_short_name,
			{ "Short Name", "smb2.shortname", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_lock_info,
			{ "Lock Info", "smb2.lock_info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_lock_length,
			{ "Length", "smb2.lock_length", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_lock_flags,
			{ "Flags", "smb2.lock_flags", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_lock_flags_shared,
			{ "Shared", "smb2.lock_flags.shared", FT_BOOLEAN, 32,
			NULL, 0x00000001, NULL, HFILL }
		},

		{ &hf_smb2_lock_flags_exclusive,
			{ "Exclusive", "smb2.lock_flags.exclusive", FT_BOOLEAN, 32,
			NULL, 0x00000002, NULL, HFILL }
		},

		{ &hf_smb2_lock_flags_unlock,
			{ "Unlock", "smb2.lock_flags.unlock", FT_BOOLEAN, 32,
			NULL, 0x00000004, NULL, HFILL }
		},

		{ &hf_smb2_lock_flags_fail_immediately,
			{ "Fail Immediately", "smb2.lock_flags.fail_immediately", FT_BOOLEAN, 32,
			NULL, 0x00000010, NULL, HFILL }
		},

		{ &hf_smb2_error_context_count,
			{ "Error Context Count", "smb2.error.context_count", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_error_reserved,
			{ "Reserved", "smb2.error.reserved", FT_UINT8, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_error_byte_count,
			{ "Byte Count", "smb2.error.byte_count", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_error_data,
			{ "Error Data", "smb2.error.data", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_error_context,
			{ "Error Context", "smb2.error.context", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_error_context_id,
			{ "Type", "smb2.error.context.id", FT_UINT32, BASE_HEX,
			VALS(smb2_error_id_vals), 0, NULL, HFILL }
		},

		{ &hf_smb2_error_context_length,
			{ "Type", "smb2.error.context.length", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_error_min_buf_length,
			{ "Minimum required buffer length", "smb2.error.min_buf_length", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_error_redir_context,
			{ "Share Redirect", "smb2.error.share_redirect", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_error_redir_struct_size,
			{ "Struct Size", "smb2.error.share_redirect.struct_size", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_error_redir_notif_type,
			{ "Notification Type", "smb2.error.share_redirect.notif_type", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_error_redir_flags,
			{ "Flags", "smb2.error.share_redirect.flags", FT_UINT16, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_error_redir_target_type,
			{ "Target Type", "smb2.error.share_redirect.target_type", FT_UINT16, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_error_redir_ip_count,
			{ "IP Addr Count", "smb2.error.share_redirect.ip_count", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_error_redir_ip_list,
			{ "IP Addr List", "smb2.error.share_redirect.ip_list", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_error_redir_res_name,
			{ "Resource Name", "smb2.error.share_redirect.res_name", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_reserved,
			{ "Reserved", "smb2.reserved", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_reserved_random,
			{ "Reserved (Random)", "smb2.reserved.random", FT_BYTES, BASE_NONE,
			NULL, 0, "Reserved bytes, random data", HFILL }
		},

		{ &hf_smb2_root_directory_mbz,
			{ "Root Dir Handle (MBZ)", "smb2.root_directory", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_dhnq_buffer_reserved,
			{ "Reserved", "smb2.dhnq_buffer_reserved", FT_UINT64, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_dh2x_buffer_timeout,
			{ "Timeout", "smb2.dh2x.timeout", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_dh2x_buffer_flags,
			{ "Flags", "smb2.dh2x.flags", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_dh2x_buffer_flags_persistent_handle,
			{ "Persistent Handle", "smb2.dh2x.flags.persistent_handle", FT_BOOLEAN, 32,
			NULL, SMB2_DH2X_FLAGS_PERSISTENT_HANDLE, NULL, HFILL }
		},

		{ &hf_smb2_dh2x_buffer_reserved,
			{ "Reserved", "smb2.dh2x.reserved", FT_UINT64, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_dh2x_buffer_create_guid,
			{ "Create Guid", "smb2.dh2x.create_guid", FT_GUID, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_APP_INSTANCE_buffer_struct_size,
			{ "Struct Size", "smb2.app_instance.struct_size", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_APP_INSTANCE_buffer_reserved,
			{ "Reserved", "smb2.app_instance.reserved", FT_UINT16, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_APP_INSTANCE_buffer_app_guid,
			{ "Application Guid", "smb2.app_instance.app_guid", FT_GUID, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_svhdx_open_device_context_version,
			{ "Version", "smb2.svhdx_open_device_context.version", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_svhdx_open_device_context_has_initiator_id,
			{ "HasInitiatorId", "smb2.svhdx_open_device_context.initiator_has_id", FT_BOOLEAN, 8,
			TFS(&tfs_smb2_svhdx_has_initiator_id), 0, "Whether the host has an initiator", HFILL }
		},

		{ &hf_smb2_svhdx_open_device_context_reserved,
			{ "Reserved", "smb2.svhdx_open_device_context.reserved", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_svhdx_open_device_context_initiator_id,
			{ "InitiatorId", "smb2.svhdx_open_device_context.initiator_id", FT_GUID, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_svhdx_open_device_context_flags,
			{ "Flags", "smb2.svhdx_open_device_context.flags", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_svhdx_open_device_context_originator_flags,
			{ "OriginatorFlags", "smb2.svhdx_open_device_context.originator_flags", FT_UINT32, BASE_HEX,
			VALS(originator_flags_vals), 0, NULL, HFILL }
		},

		{ &hf_smb2_svhdx_open_device_context_open_request_id,
			{ "OpenRequestId","smb2.svhxd_open_device_context.open_request_id", FT_UINT64, BASE_HEX,
			 NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_svhdx_open_device_context_initiator_host_name_len,
			{ "HostNameLength", "smb2.svhxd_open_device_context.initiator_host_name_len", FT_UINT16, BASE_DEC,
			 NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_svhdx_open_device_context_initiator_host_name,
			{ "HostName", "smb2.svhdx_open_device_context.host_name", FT_STRING, BASE_NONE,
			 NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_svhdx_open_device_context_virtual_disk_properties_initialized,
			{ "VirtualDiskPropertiesInitialized", "smb2.svhdx_open_device_context.virtual_disk_properties_initialized", FT_BOOLEAN, 32,
			NULL, 0, "Whether VirtualSectorSize, PhysicalSectorSize, and VirtualSize fields are filled", HFILL }
		},

		{ &hf_smb2_svhdx_open_device_context_server_service_version,
			{ "ServerServiceVersion", "smb2.svhdx_open_device_context.server_service_version", FT_UINT32, BASE_DEC,
			NULL, 0, "The current version of the protocol running on the server", HFILL }
		},

		{ &hf_smb2_svhdx_open_device_context_virtual_sector_size,
			{ "VirtualSectorSize", "smb2.svhdx_open_device_context.virtual_sector_size", FT_UINT32, BASE_DEC,
			NULL, 0, "The virtual sector size of the virtual disk", HFILL }
		},

		{ &hf_smb2_svhdx_open_device_context_physical_sector_size,
			{ "PhysicalSectorSize", "smb2.svhdx_open_device_context.physical_sector_size", FT_UINT32, BASE_DEC,
			NULL, 0, "The physical sector size of the virtual disk", HFILL }
		},

		{ &hf_smb2_svhdx_open_device_context_virtual_size,
			{ "VirtualSize", "smb2.svhdx_open_device_context.virtual_size", FT_UINT64, BASE_DEC,
			NULL, 0, "The current length of the virtual disk, in bytes", HFILL }
		},

		{ &hf_smb2_app_instance_version_struct_size,
			{ "Struct Size", "smb2.app_instance_version.struct_size", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_app_instance_version_reserved,
			{ "Reserved", "smb2.app_instance_version.reserved", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_app_instance_version_padding,
			{ "Padding", "smb2.app_instance_version.padding", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_app_instance_version_high,
			{ "AppInstanceVersionHigh", "smb2.app_instance_version.version.high", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_app_instance_version_low,
			{ "AppInstanceVersionLow", "smb2.app_instance_version.version.low", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_posix_perms,
			{ "POSIX perms", "smb2.posix_perms", FT_UINT32, BASE_OCT,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_aapl_command_code,
			{ "Command code", "smb2.aapl.command_code", FT_UINT32, BASE_DEC,
			VALS(aapl_command_code_vals), 0, NULL, HFILL }
		},

		{ &hf_smb2_aapl_reserved,
			{ "Reserved", "smb2.aapl.reserved", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_aapl_server_query_bitmask,
			{ "Query bitmask", "smb2.aapl.query_bitmask", FT_UINT64, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_aapl_server_query_bitmask_server_caps,
			{ "Server capabilities", "smb2.aapl.bitmask.server_caps", FT_BOOLEAN, 64,
			NULL, SMB2_AAPL_SERVER_CAPS, NULL, HFILL }
		},

		{ &hf_smb2_aapl_server_query_bitmask_volume_caps,
			{ "Volume capabilities", "smb2.aapl.bitmask.volume_caps", FT_BOOLEAN, 64,
			NULL, SMB2_AAPL_VOLUME_CAPS, NULL, HFILL }
		},

		{ &hf_smb2_aapl_server_query_bitmask_model_info,
			{ "Model information", "smb2.aapl.bitmask.model_info", FT_BOOLEAN, 64,
			NULL, SMB2_AAPL_MODEL_INFO, NULL, HFILL }
		},

		{ &hf_smb2_aapl_server_query_caps,
			{ "Client/Server capabilities", "smb2.aapl.caps", FT_UINT64, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_aapl_server_query_caps_supports_read_dir_attr,
			{ "Supports READDIRATTR", "smb2.aapl.caps.supports_read_dir_addr", FT_BOOLEAN, 64,
			NULL, SMB2_AAPL_SUPPORTS_READ_DIR_ATTR, NULL, HFILL }
		},

		{ &hf_smb2_aapl_server_query_caps_supports_osx_copyfile,
			{ "Supports macOS copyfile", "smb2.aapl.caps.supports_osx_copyfile", FT_BOOLEAN, 64,
			NULL, SMB2_AAPL_SUPPORTS_OSX_COPYFILE, NULL, HFILL }
		},

		{ &hf_smb2_aapl_server_query_caps_unix_based,
			{ "UNIX-based", "smb2.aapl.caps.unix_based", FT_BOOLEAN, 64,
			NULL, SMB2_AAPL_UNIX_BASED, NULL, HFILL }
		},

		{ &hf_smb2_aapl_server_query_caps_supports_nfs_ace,
			{ "Supports NFS ACE", "smb2.aapl.supports_nfs_ace", FT_BOOLEAN, 64,
			NULL, SMB2_AAPL_SUPPORTS_NFS_ACE, NULL, HFILL }
		},

		{ &hf_smb2_aapl_server_query_volume_caps,
			{ "Volume capabilities", "smb2.aapl.volume_caps", FT_UINT64, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_aapl_server_query_volume_caps_support_resolve_id,
			{ "Supports Resolve ID", "smb2.aapl.volume_caps.supports_resolve_id", FT_BOOLEAN, 64,
			NULL, SMB2_AAPL_SUPPORTS_RESOLVE_ID, NULL, HFILL }
		},

		{ &hf_smb2_aapl_server_query_volume_caps_case_sensitive,
			{ "Case sensitive", "smb2.aapl.volume_caps.case_sensitive", FT_BOOLEAN, 64,
			NULL, SMB2_AAPL_CASE_SENSITIVE, NULL, HFILL }
		},

		{ &hf_smb2_aapl_server_query_volume_caps_supports_full_sync,
			{ "Supports full sync", "smb2.aapl.volume_caps.supports_full_sync", FT_BOOLEAN, 64,
			NULL, SMB2_AAPL_SUPPORTS_FULL_SYNC, NULL, HFILL }
		},

		{ &hf_smb2_aapl_server_query_model_string,
			{ "Model string", "smb2.aapl.model_string", FT_UINT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_aapl_server_query_server_path,
			{ "Server path", "smb2.aapl.server_path", FT_UINT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_transform_signature,
			{ "Signature", "smb2.header.transform.signature", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_transform_nonce,
			{ "Nonce", "smb2.header.transform.nonce", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_transform_msg_size,
			{ "Message size", "smb2.header.transform.msg_size", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_transform_reserved,
			{ "Reserved", "smb2.header.transform.reserved", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		/* SMB2 header flags  */
		{ &hf_smb2_transform_flags,
			{ "Flags", "smb2.header.transform.flags", FT_UINT16, BASE_HEX,
			NULL, 0, "SMB2 transform flags", HFILL }
		},

		{ &hf_smb2_transform_flags_encrypted,
			{ "Encrypted", "smb2.header.transform.flags.encrypted", FT_BOOLEAN, 16,
			NULL, SMB2_TRANSFORM_FLAGS_ENCRYPTED,
			"Whether the payload is encrypted", HFILL }
		},

		{ &hf_smb2_transform_encrypted_data,
			{ "Data", "smb2.header.transform.enc_data", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_comp_transform_orig_size,
			{ "OriginalSize", "smb2.header.comp_transform.original_size", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_comp_transform_comp_alg,
			{ "CompressionAlgorithm", "smb2.header.comp_transform.comp_alg", FT_UINT16, BASE_HEX,
			VALS(smb2_comp_alg_types), 0, NULL, HFILL }
		},

		{ &hf_smb2_comp_transform_flags,
			{ "Flags", "smb2.header.comp_transform.flags", FT_UINT16, BASE_HEX,
			  VALS(smb2_comp_transform_flags_vals), 0, NULL, HFILL }
		},

		{ &hf_smb2_comp_transform_offset,
			{ "Offset", "smb2.header.comp_transform.offset", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_comp_transform_length,
			{ "Length", "smb2.header.comp_transform.length", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_comp_transform_data,
		  { "CompressedData", "smb2.header.comp_transform.data", FT_BYTES, BASE_NONE,
		    NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_comp_transform_orig_payload_size,
		  { "OriginalPayloadSize", "smb2.header.comp_transform.orig_payload_size", FT_UINT32, BASE_DEC,
		    NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_comp_pattern_v1_pattern,
		  { "Pattern", "smb2.pattern_v1.pattern", FT_UINT8, BASE_HEX,
		    NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_comp_pattern_v1_reserved1,
		  { "Reserved1", "smb2.pattern_v1.reserved1", FT_UINT8, BASE_HEX,
		    NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_comp_pattern_v1_reserved2,
		  { "Reserved2", "smb2.pattern_v1.reserved2", FT_UINT16, BASE_HEX,
		    NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_comp_pattern_v1_repetitions,
		  { "Repetitions", "smb2.pattern_v1.repetitions", FT_UINT32, BASE_DEC,
		    NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_protocol_id,
			{ "ProtocolId", "smb2.protocol_id", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_truncated,
			{ "Truncated...", "smb2.truncated", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},

		{ &hf_smb2_pipe_fragment_overlap,
			{ "Fragment overlap", "smb2.pipe.fragment.overlap", FT_BOOLEAN, BASE_NONE,
			NULL, 0x0, "Fragment overlaps with other fragments", HFILL }
		},

		{ &hf_smb2_pipe_fragment_overlap_conflict,
			{ "Conflicting data in fragment overlap", "smb2.pipe.fragment.overlap.conflict", FT_BOOLEAN, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},

		{ &hf_smb2_pipe_fragment_multiple_tails,
			{ "Multiple tail fragments found", "smb2.pipe.fragment.multipletails", FT_BOOLEAN, BASE_NONE,
			NULL, 0x0, "Several tails were found when defragmenting the packet", HFILL }
		},

		{ &hf_smb2_pipe_fragment_too_long_fragment,
			{ "Fragment too long", "smb2.pipe.fragment.toolongfragment", FT_BOOLEAN, BASE_NONE,
			NULL, 0x0, "Fragment contained data past end of packet", HFILL }
		},

		{ &hf_smb2_pipe_fragment_error,
			{ "Defragmentation error", "smb2.pipe.fragment.error", FT_FRAMENUM, BASE_NONE,
			NULL, 0x0, "Defragmentation error due to illegal fragments", HFILL }
		},

		{ &hf_smb2_pipe_fragment_count,
			{ "Fragment count", "smb2.pipe.fragment.count", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},

		{ &hf_smb2_pipe_fragment,
			{ "Fragment SMB2 Named Pipe", "smb2.pipe.fragment", FT_FRAMENUM, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},

		{ &hf_smb2_pipe_fragments,
			{ "Reassembled SMB2 Named Pipe fragments", "smb2.pipe.fragments", FT_NONE, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},

		{ &hf_smb2_pipe_reassembled_in,
			{ "This SMB2 Named Pipe payload is reassembled in frame", "smb2.pipe.reassembled_in", FT_FRAMENUM, BASE_NONE,
			NULL, 0x0, "The Named Pipe PDU is completely reassembled in this frame", HFILL }
		},

		{ &hf_smb2_pipe_reassembled_length,
			{ "Reassembled SMB2 Named Pipe length", "smb2.pipe.reassembled.length", FT_UINT32, BASE_DEC,
			NULL, 0x0, "The total length of the reassembled payload", HFILL }
		},

		{ &hf_smb2_pipe_reassembled_data,
			{ "Reassembled SMB2 Named Pipe Data", "smb2.pipe.reassembled.data", FT_BYTES, BASE_NONE,
			NULL, 0x0, "The reassembled payload", HFILL }
		},

		{ &hf_smb2_cchunk_resume_key,
			{ "ResumeKey", "smb2.fsctl.cchunk.resume_key", FT_BYTES, BASE_NONE,
			NULL, 0x0, "Opaque data representing source of copy", HFILL }
		},

		{ &hf_smb2_cchunk_count,
			{ "Chunk Count", "smb2.fsctl.cchunk.count", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},

		{ &hf_smb2_cchunk_src_offset,
			{ "Source Offset", "smb2.fsctl.cchunk.src_offset", FT_UINT64, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},

		{ &hf_smb2_cchunk_dst_offset,
			{ "Target Offset", "smb2.fsctl.cchunk.dst_offset", FT_UINT64, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},

		{ &hf_smb2_cchunk_xfer_len,
			{ "Transfer Length", "smb2.fsctl.cchunk.xfer_len", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},

		{ &hf_smb2_cchunk_chunks_written,
			{ "Chunks Written", "smb2.fsctl.cchunk.chunks_written", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},

		{ &hf_smb2_cchunk_bytes_written,
			{ "Chunk Bytes Written", "smb2.fsctl.cchunk.bytes_written", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},

		{ &hf_smb2_cchunk_total_written,
			{ "Total Bytes Written", "smb2.fsctl.cchunk.total_written", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_smb2_reparse_tag,
			{ "Reparse Tag", "smb2.reparse_tag", FT_UINT32, BASE_HEX,
			VALS(reparse_tag_vals), 0x0, NULL, HFILL }
		},
		{ &hf_smb2_reparse_guid,
			{ "Reparse GUID", "smb2.reparse_guid", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_smb2_reparse_data_length,
			{ "Reparse Data Length", "smb2.reparse_data_length", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_smb2_reparse_data_buffer,
			{ "Reparse Data Buffer", "smb2.reparse_data_buffer", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_smb2_nfs_type,
			{ "NFS file type", "smb2.nfs.type", FT_UINT64, BASE_HEX|BASE_VAL64_STRING,
			VALS64(nfs_type_vals), 0x0, NULL, HFILL }
		},
		{ &hf_smb2_nfs_symlink_target,
			{ "Symlink Target", "smb2.nfs.symlink.target", FT_STRING,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_smb2_nfs_chr_major,
			{ "Major", "smb2.nfs.char.major", FT_UINT32,
			BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_smb2_nfs_chr_minor,
			{ "Minor", "smb2.nfs.char.minor", FT_UINT32,
			BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_smb2_nfs_blk_major,
			{ "Major", "smb2.nfs.block.major", FT_UINT32,
			BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_smb2_nfs_blk_minor,
			{ "Minor", "smb2.nfs.block.minor", FT_UINT32,
			BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_smb2_symlink_error_response,
			{ "Symbolic Link Error Response", "smb2.symlink_error_response", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_smb2_symlink_length,
			{ "SymLink Length", "smb2.symlink.length", FT_UINT32,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_smb2_symlink_error_tag,
			{ "SymLink Error Tag", "smb2.symlink.error_tag", FT_UINT32,
			BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_smb2_unparsed_path_length,
			{ "Unparsed Path Length", "smb2.symlink.unparsed_path_length", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_smb2_symlink_substitute_name,
			{ "Substitute Name", "smb2.symlink.substitute_name", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_smb2_symlink_print_name,
			{ "Print Name", "smb2.symlink.print_name", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_smb2_symlink_flags,
			{ "Flags", "smb2.symlink.flags", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_smb2_fscc_file_attr,
			{ "File Attributes", "smb2.file_attribute", FT_UINT32, BASE_HEX,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_smb2_fscc_file_attr_read_only,
			{ "Read Only", "smb2.file_attribute.read_only", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), SMB2_FSCC_FILE_ATTRIBUTE_READ_ONLY, "READ ONLY file attribute", HFILL } },

		{ &hf_smb2_fscc_file_attr_hidden,
			{ "Hidden", "smb2.file_attribute.hidden", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), SMB2_FSCC_FILE_ATTRIBUTE_HIDDEN, "HIDDEN file attribute", HFILL } },

		{ &hf_smb2_fscc_file_attr_system,
			{ "System", "smb2.file_attribute.system", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), SMB2_FSCC_FILE_ATTRIBUTE_SYSTEM, "SYSTEM file attribute", HFILL } },

		{ &hf_smb2_fscc_file_attr_directory,
			{ "Directory", "smb2.file_attribute.directory", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), SMB2_FSCC_FILE_ATTRIBUTE_DIRECTORY, "DIRECTORY file attribute", HFILL } },

		{ &hf_smb2_fscc_file_attr_archive,
			{ "Requires archived", "smb2.file_attribute.archive", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), SMB2_FSCC_FILE_ATTRIBUTE_ARCHIVE, "ARCHIVE file attribute", HFILL } },

		{ &hf_smb2_fscc_file_attr_normal,
			{ "Normal", "smb2.file_attribute.normal", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), SMB2_FSCC_FILE_ATTRIBUTE_NORMAL, "Is this a normal file?", HFILL } },

		{ &hf_smb2_fscc_file_attr_temporary,
			{ "Temporary", "smb2.file_attribute.temporary", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), SMB2_FSCC_FILE_ATTRIBUTE_TEMPORARY, "Is this a temporary file?", HFILL } },

		{ &hf_smb2_fscc_file_attr_sparse_file,
			{ "Sparse", "smb2.file_attribute.sparse", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), SMB2_FSCC_FILE_ATTRIBUTE_SPARSE_FILE, "Is this a sparse file?", HFILL } },

		{ &hf_smb2_fscc_file_attr_reparse_point,
			{ "Reparse Point", "smb2.file_attribute.reparse", FT_BOOLEAN, 32,
			TFS(&tfs_fscc_file_attribute_reparse), SMB2_FSCC_FILE_ATTRIBUTE_REPARSE_POINT, "Does this file have an associated reparse point?", HFILL } },

		{ &hf_smb2_fscc_file_attr_compressed,
			{ "Compressed", "smb2.file_attribute.compressed", FT_BOOLEAN, 32,
			TFS(&tfs_fscc_file_attribute_compressed), SMB2_FSCC_FILE_ATTRIBUTE_COMPRESSED, "Is this file compressed?", HFILL } },

		{ &hf_smb2_fscc_file_attr_offline,
			{ "Offline", "smb2.file_attribute.offline", FT_BOOLEAN, 32,
			TFS(&tfs_fscc_file_attribute_offline), SMB2_FSCC_FILE_ATTRIBUTE_OFFLINE, "Is this file offline?", HFILL } },

		{ &hf_smb2_fscc_file_attr_not_content_indexed,
			{ "Not Content Indexed", "smb2.file_attribute.not_content_indexed", FT_BOOLEAN, 32,
			TFS(&tfs_fscc_file_attribute_not_content_indexed), SMB2_FSCC_FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, "May this file be indexed by the content indexing service", HFILL } },

		{ &hf_smb2_fscc_file_attr_encrypted,
			{ "Encrypted", "smb2.file_attribute.encrypted", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), SMB2_FSCC_FILE_ATTRIBUTE_ENCRYPTED, "Is this file encrypted?", HFILL } },

		{ &hf_smb2_fscc_file_attr_integrity_stream,
			{ "Integrity Stream", "smb2.file_attribute.integrity_stream", FT_BOOLEAN, 32,
			TFS(&tfs_fscc_file_attribute_integrity_stream), SMB2_FSCC_FILE_ATTRIBUTE_INTEGRITY_STREAM, "Is this file configured with integrity support?", HFILL } },

		{ &hf_smb2_fscc_file_attr_no_scrub_data,
			{ "No Scrub Data", "smb2.file_attribute.no_scrub_data", FT_BOOLEAN, 32,
			TFS(&tfs_fscc_file_attribute_no_scrub_data), SMB2_FSCC_FILE_ATTRIBUTE_NO_SCRUB_DATA, "Is this file configured to be excluded from the data integrity scan?", HFILL } },
	};

	static gint *ett[] = {
		&ett_smb2,
		&ett_smb2_ea,
		&ett_smb2_olb,
		&ett_smb2_header,
		&ett_smb2_encrypted,
		&ett_smb2_compressed,
		&ett_smb2_decompressed,
		&ett_smb2_command,
		&ett_smb2_secblob,
		&ett_smb2_negotiate_context_element,
		&ett_smb2_file_basic_info,
		&ett_smb2_file_standard_info,
		&ett_smb2_file_internal_info,
		&ett_smb2_file_ea_info,
		&ett_smb2_file_access_info,
		&ett_smb2_file_rename_info,
		&ett_smb2_file_disposition_info,
		&ett_smb2_file_position_info,
		&ett_smb2_file_full_ea_info,
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
		&ett_smb2_file_normalized_name_info,
		&ett_smb2_fs_info_01,
		&ett_smb2_fs_info_03,
		&ett_smb2_fs_info_04,
		&ett_smb2_fs_info_05,
		&ett_smb2_fs_info_06,
		&ett_smb2_fs_info_07,
		&ett_smb2_fs_objectid_info,
		&ett_smb2_sec_info_00,
		&ett_smb2_additional_information_sec_mask,
		&ett_smb2_quota_info,
		&ett_smb2_query_quota_info,
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
		&ett_smb2_comp_alg_flags,
		&ett_smb2_ioctl_flags,
		&ett_smb2_ioctl_network_interface,
		&ett_smb2_ioctl_sqos_opeations,
		&ett_smb2_fsctl_range_data,
		&ett_windows_sockaddr,
		&ett_smb2_close_flags,
		&ett_smb2_notify_info,
		&ett_smb2_notify_flags,
		&ett_smb2_rdma_v1,
		&ett_smb2_write_flags,
		&ett_smb2_find_flags,
		&ett_smb2_file_directory_info,
		&ett_smb2_both_directory_info,
		&ett_smb2_id_both_directory_info,
		&ett_smb2_full_directory_info,
		&ett_smb2_posix_info,
		&ett_smb2_file_name_info,
		&ett_smb2_lock_info,
		&ett_smb2_lock_flags,
		&ett_smb2_DH2Q_buffer,
		&ett_smb2_DH2C_buffer,
		&ett_smb2_dh2x_flags,
		&ett_smb2_APP_INSTANCE_buffer,
		&ett_smb2_svhdx_open_device_context,
		&ett_smb2_app_instance_version_buffer,
		&ett_smb2_app_instance_version_buffer_version,
		&ett_smb2_aapl_create_context_request,
		&ett_smb2_aapl_server_query_bitmask,
		&ett_smb2_aapl_server_query_caps,
		&ett_smb2_aapl_create_context_response,
		&ett_smb2_aapl_server_query_volume_caps,
		&ett_smb2_integrity_flags,
		&ett_smb2_buffercode,
		&ett_smb2_ioctl_network_interface_capabilities,
		&ett_smb2_tree_connect_flags,
		&ett_qfr_entry,
		&ett_smb2_pipe_fragment,
		&ett_smb2_pipe_fragments,
		&ett_smb2_cchunk_entry,
		&ett_smb2_fsctl_odx_token,
		&ett_smb2_symlink_error_response,
		&ett_smb2_reparse_data_buffer,
		&ett_smb2_error_data,
		&ett_smb2_error_context,
		&ett_smb2_error_redir_context,
		&ett_smb2_error_redir_ip_list,
		&ett_smb2_read_flags,
		&ett_smb2_signature,
		&ett_smb2_transform_flags,
		&ett_smb2_fscc_file_attributes,
		&ett_smb2_comp_pattern_v1,
		&ett_smb2_comp_payload,
	};

	static ei_register_info ei[] = {
		{ &ei_smb2_invalid_length, { "smb2.invalid_length", PI_MALFORMED, PI_ERROR, "Invalid length", EXPFILL }},
		{ &ei_smb2_bad_response, { "smb2.bad_response", PI_MALFORMED, PI_ERROR, "Bad response", EXPFILL }},
		{ &ei_smb2_invalid_getinfo_offset, { "smb2.invalid_getinfo_offset", PI_MALFORMED, PI_ERROR, "Input buffer offset isn't past the fixed data in the message", EXPFILL }},
		{ &ei_smb2_invalid_getinfo_size, { "smb2.invalid_getinfo_size", PI_MALFORMED, PI_ERROR, "Input buffer length goes past the end of the message", EXPFILL }},
		{ &ei_smb2_empty_getinfo_buffer, { "smb2.empty_getinfo_buffer", PI_PROTOCOL, PI_WARN, "Input buffer length is empty for a quota request", EXPFILL }},
		{ &ei_smb2_invalid_signature, { "smb2.invalid_signature", PI_MALFORMED, PI_ERROR, "Invalid Signature", EXPFILL }},
	};

	expert_module_t* expert_smb2;

	/* SessionID <=> SessionKey mappings for decryption */
	uat_t *seskey_uat;

	static uat_field_t seskey_uat_fields[] = {
		UAT_FLD_BUFFER(seskey_list, id, "Session ID", "The session ID buffer, coded as hex string, as it appears on the wire (LE)."),
		UAT_FLD_BUFFER(seskey_list, seskey, "Session Key", "The secret session key buffer, coded as 16-byte hex string."),
		UAT_FLD_BUFFER(seskey_list, s2ckey, "Server-to-Client", "The AES-128 key used by the client to decrypt server messages, coded as 16-byte hex string."),
		UAT_FLD_BUFFER(seskey_list, c2skey, "Client-to-Server", "The AES-128 key used by the server to decrypt client messages, coded as 16-byte hex string."),
		UAT_END_FIELDS
	};

	proto_smb2 = proto_register_protocol("SMB2 (Server Message Block Protocol version 2)",
					     "SMB2", "smb2");
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_smb2, hf, array_length(hf));
	expert_smb2 = expert_register_protocol(proto_smb2);
	expert_register_field_array(expert_smb2, ei, array_length(ei));

	smb2_module = prefs_register_protocol(proto_smb2, NULL);
	prefs_register_bool_preference(smb2_module, "eosmb2_take_name_as_fid",
				       "Use the full file name as File ID when exporting an SMB2 object",
				       "Whether the export object functionality will take the full path file name as file identifier",
				       &eosmb2_take_name_as_fid);

	prefs_register_bool_preference(smb2_module, "pipe_reassembly",
		"Reassemble Named Pipes over SMB2",
		"Whether the dissector should reassemble Named Pipes over SMB2 commands",
		&smb2_pipe_reassembly);

	prefs_register_bool_preference(smb2_module, "verify_signatures",
		"Verify SMB2 Signatures",
		"Whether the dissector should try to verify SMB2 signatures",
		&smb2_verify_signatures);

	seskey_uat = uat_new("Secret session key to use for decryption",
			     sizeof(smb2_seskey_field_t),
			     "smb2_seskey_list",
			     TRUE,
			     &seskey_list,
			     &num_seskey_list,
			     (UAT_AFFECTS_DISSECTION | UAT_AFFECTS_FIELDS),
			     NULL,
			     seskey_list_copy_cb,
			     seskey_list_update_cb,
			     seskey_list_free_cb,
			     NULL,
			     NULL,
			     seskey_uat_fields);

	prefs_register_uat_preference(smb2_module,
				      "seskey_list",
				      "Secret session keys for decryption",
				      "A table of Session ID to Session keys mappings used to decrypt traffic.",
				      seskey_uat);

	smb2_pipe_subdissector_list = register_heur_dissector_list("smb2_pipe_subdissectors", proto_smb2);
	/*
	 * XXX - addresses_ports_reassembly_table_functions?
	 * Probably correct for SMB-over-NBT and SMB-over-TCP,
	 * as stuff from two different connections should
	 * probably not be combined, but what about other
	 * transports for SMB, e.g. NBF or Netware?
	 */
	reassembly_table_register(&smb2_pipe_reassembly_table,
	    &addresses_reassembly_table_functions);

	smb2_tap = register_tap("smb2");
	smb2_eo_tap = register_tap("smb_eo"); /* SMB Export Object tap */

	register_srt_table(proto_smb2, NULL, 1, smb2stat_packet, smb2stat_init, NULL);
	smb2_sessions = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), smb2_sesid_info_hash, smb2_sesid_info_equal);
}

void
proto_reg_handoff_smb2(void)
{
	gssapi_handle  = find_dissector_add_dependency("gssapi", proto_smb2);
	ntlmssp_handle = find_dissector_add_dependency("ntlmssp", proto_smb2);
	rsvd_handle    = find_dissector_add_dependency("rsvd", proto_smb2);
	heur_dissector_add("netbios", dissect_smb2_heur, "SMB2 over Netbios", "smb2_netbios", proto_smb2, HEURISTIC_ENABLE);
	heur_dissector_add("smb_direct", dissect_smb2_heur, "SMB2 over SMB Direct", "smb2_smb_direct", proto_smb2, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
