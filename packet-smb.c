/* packet-smb.c
 * Routines for smb packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id: packet-smb.c,v 1.176 2001/11/29 09:05:22 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
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

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <time.h>
#include <string.h>
#include <glib.h>
#include <ctype.h>
#include "packet.h"
#include "conversation.h"
#include "smb.h"
#include "alignment.h"
#include "strutil.h"
#include "prefs.h"
#include "reassemble.h"

#include "packet-smb-mailslot.h"
#include "packet-smb-pipe.h"

/*
 * Various specifications and documents about SMB can be found in
 *
 *	ftp://ftp.microsoft.com/developr/drg/CIFS/
 *
 * and a CIFS draft from the Storage Networking Industry Association
 * can be found on a link from the page at
 *
 *	http://www.snia.org/English/Work_Groups/NAS/CIFS/WG_CIFS_Docs.html
 *
 * (it supercedes the document at
 *
 *	ftp://ftp.microsoft.com/developr/drg/CIFS/draft-leach-cifs-v1-spec-01.txt
 *
 * ).
 *
 * There are also some Open Group publications documenting CIFS for sale;
 * catalog entries for them are at:
 *
 *	http://www.opengroup.org/products/publications/catalog/c209.htm
 *
 *	http://www.opengroup.org/products/publications/catalog/c195.htm
 *
 * The document "NT LAN Manager SMB File Sharing Protocol Extensions"
 * can be found at
 *
 *	http://www.samba.org/samba/ftp/specs/smb-nt01.doc
 *
 * (or, presumably a similar path under the Samba mirrors).  As the
 * ".doc" indicates, it's a Word document.  Some of the specs from the
 * Microsoft FTP site can be found in the
 *
 *	http://www.samba.org/samba/ftp/specs/
 *
 * directory as well.
 *
 * Beware - these specs may have errors.
 */
static int proto_smb = -1;
static int hf_smb_cmd = -1;
static int hf_smb_pid = -1;
static int hf_smb_tid = -1;
static int hf_smb_uid = -1;
static int hf_smb_mid = -1;
static int hf_smb_response_to = -1;
static int hf_smb_response_in = -1;
static int hf_smb_continuation_to = -1;
static int hf_smb_nt_status = -1;
static int hf_smb_error_class = -1;
static int hf_smb_error_code = -1;
static int hf_smb_reserved = -1;
static int hf_smb_flags_lock = -1;
static int hf_smb_flags_receive_buffer = -1;
static int hf_smb_flags_caseless = -1;
static int hf_smb_flags_canon = -1;
static int hf_smb_flags_oplock = -1;
static int hf_smb_flags_notify = -1;
static int hf_smb_flags_response = -1;
static int hf_smb_flags2_long_names_allowed = -1;
static int hf_smb_flags2_ea = -1;
static int hf_smb_flags2_sec_sig = -1;
static int hf_smb_flags2_long_names_used = -1;
static int hf_smb_flags2_esn = -1;
static int hf_smb_flags2_dfs = -1;
static int hf_smb_flags2_roe = -1;
static int hf_smb_flags2_nt_error = -1;
static int hf_smb_flags2_string = -1;
static int hf_smb_word_count = -1;
static int hf_smb_byte_count = -1;
static int hf_smb_buffer_format = -1;
static int hf_smb_dialect_name = -1;
static int hf_smb_dialect_index = -1;
static int hf_smb_max_trans_buf_size = -1;
static int hf_smb_max_mpx_count = -1;
static int hf_smb_max_vcs_num = -1;
static int hf_smb_session_key = -1;
static int hf_smb_server_timezone = -1;
static int hf_smb_encryption_key_length = -1;
static int hf_smb_encryption_key = -1;
static int hf_smb_primary_domain = -1;
static int hf_smb_max_raw_buf_size = -1;
static int hf_smb_server_guid = -1;
static int hf_smb_security_blob_len = -1;
static int hf_smb_security_blob = -1;
static int hf_smb_sm_mode16 = -1;
static int hf_smb_sm_password16 = -1;
static int hf_smb_sm_mode = -1;
static int hf_smb_sm_password = -1;
static int hf_smb_sm_signatures = -1;
static int hf_smb_sm_sig_required = -1;
static int hf_smb_rm_read = -1;
static int hf_smb_rm_write = -1;
static int hf_smb_server_date_time = -1;
static int hf_smb_server_smb_date = -1;
static int hf_smb_server_smb_time = -1;
static int hf_smb_server_cap_raw_mode = -1;
static int hf_smb_server_cap_mpx_mode = -1;
static int hf_smb_server_cap_unicode = -1;
static int hf_smb_server_cap_large_files = -1;
static int hf_smb_server_cap_nt_smbs = -1;
static int hf_smb_server_cap_rpc_remote_apis = -1;
static int hf_smb_server_cap_nt_status = -1;
static int hf_smb_server_cap_level_ii_oplocks = -1;
static int hf_smb_server_cap_lock_and_read = -1;
static int hf_smb_server_cap_nt_find = -1;
static int hf_smb_server_cap_dfs = -1;
static int hf_smb_server_cap_infolevel_passthru = -1;
static int hf_smb_server_cap_large_readx = -1;
static int hf_smb_server_cap_large_writex = -1;
static int hf_smb_server_cap_unix = -1;
static int hf_smb_server_cap_reserved = -1;
static int hf_smb_server_cap_bulk_transfer = -1;
static int hf_smb_server_cap_compressed_data = -1;
static int hf_smb_server_cap_extended_security = -1;
static int hf_smb_system_time = -1;
static int hf_smb_unknown = -1;
static int hf_smb_dir_name = -1;
static int hf_smb_echo_count = -1;
static int hf_smb_echo_data = -1;
static int hf_smb_echo_seq_num = -1;
static int hf_smb_max_buf_size = -1;
static int hf_smb_password = -1;
static int hf_smb_password_len = -1;
static int hf_smb_ansi_password = -1;
static int hf_smb_ansi_password_len = -1;
static int hf_smb_unicode_password = -1;
static int hf_smb_unicode_password_len = -1;
static int hf_smb_path = -1;
static int hf_smb_service = -1;
static int hf_smb_move_flags_file = -1;
static int hf_smb_move_flags_dir = -1;
static int hf_smb_move_flags_verify = -1;
static int hf_smb_move_files_moved = -1;
static int hf_smb_count = -1;
static int hf_smb_file_name = -1;
static int hf_smb_open_function_open = -1;
static int hf_smb_open_function_create = -1;
static int hf_smb_fid = -1;
static int hf_smb_file_attr_read_only_16bit = -1;
static int hf_smb_file_attr_read_only_8bit = -1;
static int hf_smb_file_attr_hidden_16bit = -1;
static int hf_smb_file_attr_hidden_8bit = -1;
static int hf_smb_file_attr_system_16bit = -1;
static int hf_smb_file_attr_system_8bit = -1;
static int hf_smb_file_attr_volume_16bit = -1;
static int hf_smb_file_attr_volume_8bit = -1;
static int hf_smb_file_attr_directory_16bit = -1;
static int hf_smb_file_attr_directory_8bit = -1;
static int hf_smb_file_attr_archive_16bit = -1;
static int hf_smb_file_attr_archive_8bit = -1;
static int hf_smb_file_attr_device = -1;
static int hf_smb_file_attr_normal = -1;
static int hf_smb_file_attr_temporary = -1;
static int hf_smb_file_attr_sparse = -1;
static int hf_smb_file_attr_reparse = -1;
static int hf_smb_file_attr_compressed = -1;
static int hf_smb_file_attr_offline = -1;
static int hf_smb_file_attr_not_content_indexed = -1;
static int hf_smb_file_attr_encrypted = -1;
static int hf_smb_file_size = -1;
static int hf_smb_search_attribute_read_only = -1;
static int hf_smb_search_attribute_hidden = -1;
static int hf_smb_search_attribute_system = -1;
static int hf_smb_search_attribute_volume = -1;
static int hf_smb_search_attribute_directory = -1;
static int hf_smb_search_attribute_archive = -1;
static int hf_smb_access_mode = -1;
static int hf_smb_access_sharing = -1;
static int hf_smb_access_locality = -1;
static int hf_smb_access_caching = -1;
static int hf_smb_access_writetru = -1;
static int hf_smb_create_time = -1;
static int hf_smb_create_dos_date = -1;
static int hf_smb_create_dos_time = -1;
static int hf_smb_last_write_time = -1;
static int hf_smb_last_write_dos_date = -1;
static int hf_smb_last_write_dos_time = -1;
static int hf_smb_access_time = -1;
static int hf_smb_access_dos_date = -1;
static int hf_smb_access_dos_time = -1;
static int hf_smb_old_file_name = -1;
static int hf_smb_offset = -1;
static int hf_smb_remaining = -1;
static int hf_smb_padding = -1;
static int hf_smb_file_data = -1;
static int hf_smb_total_data_len = -1;
static int hf_smb_data_len = -1;
static int hf_smb_seek_mode = -1;
static int hf_smb_data_size = -1;
static int hf_smb_alloc_size = -1;
static int hf_smb_alloc_size64 = -1;
static int hf_smb_max_count = -1;
static int hf_smb_min_count = -1;
static int hf_smb_timeout = -1;
static int hf_smb_high_offset = -1;
static int hf_smb_units = -1;
static int hf_smb_bpu = -1;
static int hf_smb_blocksize = -1;
static int hf_smb_freeunits = -1;
static int hf_smb_data_offset = -1;
static int hf_smb_dcm = -1;
static int hf_smb_request_mask = -1;
static int hf_smb_response_mask = -1;
static int hf_smb_sid = -1;
static int hf_smb_write_mode_write_through = -1;
static int hf_smb_write_mode_return_remaining = -1;
static int hf_smb_write_mode_raw = -1;
static int hf_smb_write_mode_message_start = -1;
static int hf_smb_write_mode_connectionless = -1;
static int hf_smb_resume_key_len = -1;
static int hf_smb_resume_server_cookie = -1;
static int hf_smb_resume_client_cookie = -1;
static int hf_smb_andxoffset = -1;
static int hf_smb_lock_type_large = -1;
static int hf_smb_lock_type_cancel = -1;
static int hf_smb_lock_type_change = -1;
static int hf_smb_lock_type_oplock = -1;
static int hf_smb_lock_type_shared = -1;
static int hf_smb_locking_ol = -1;
static int hf_smb_number_of_locks = -1;
static int hf_smb_number_of_unlocks = -1;
static int hf_smb_lock_long_offset = -1;
static int hf_smb_lock_long_length = -1;
static int hf_smb_file_type = -1;
static int hf_smb_ipc_state_nonblocking = -1;
static int hf_smb_ipc_state_endpoint = -1;
static int hf_smb_ipc_state_pipe_type = -1;
static int hf_smb_ipc_state_read_mode = -1;
static int hf_smb_ipc_state_icount = -1;
static int hf_smb_server_fid = -1;
static int hf_smb_open_flags_add_info = -1;
static int hf_smb_open_flags_ex_oplock = -1;
static int hf_smb_open_flags_batch_oplock = -1;
static int hf_smb_open_flags_ealen = -1;
static int hf_smb_open_action_open = -1;
static int hf_smb_open_action_lock = -1;
static int hf_smb_vc_num = -1;
static int hf_smb_account = -1;
static int hf_smb_os = -1;
static int hf_smb_lanman = -1;
static int hf_smb_setup_action_guest = -1;
static int hf_smb_fs = -1;
static int hf_smb_connect_flags_dtid = -1;
static int hf_smb_connect_support_search = -1;
static int hf_smb_connect_support_in_dfs = -1;
static int hf_smb_max_setup_count = -1;
static int hf_smb_total_param_count = -1;
static int hf_smb_total_data_count = -1;
static int hf_smb_max_param_count = -1;
static int hf_smb_max_data_count = -1;
static int hf_smb_param_disp16 = -1;
static int hf_smb_param_count16 = -1;
static int hf_smb_param_offset16 = -1;
static int hf_smb_param_disp32 = -1;
static int hf_smb_param_count32 = -1;
static int hf_smb_param_offset32 = -1;
static int hf_smb_data_disp16 = -1;
static int hf_smb_data_count16 = -1;
static int hf_smb_data_offset16 = -1;
static int hf_smb_data_disp32 = -1;
static int hf_smb_data_count32 = -1;
static int hf_smb_data_offset32 = -1;
static int hf_smb_setup_count = -1;
static int hf_smb_nt_trans_subcmd = -1;
static int hf_smb_nt_ioctl_function_code = -1;
static int hf_smb_nt_ioctl_isfsctl = -1;
static int hf_smb_nt_ioctl_flags_root_handle = -1;
static int hf_smb_nt_ioctl_data = -1;
static int hf_smb_nt_security_information = -1;
static int hf_smb_nt_notify_action = -1;
static int hf_smb_nt_notify_watch_tree = -1;
static int hf_smb_nt_notify_stream_write = -1;
static int hf_smb_nt_notify_stream_size = -1;
static int hf_smb_nt_notify_stream_name = -1;
static int hf_smb_nt_notify_security = -1;
static int hf_smb_nt_notify_ea = -1;
static int hf_smb_nt_notify_creation = -1;
static int hf_smb_nt_notify_last_access = -1;
static int hf_smb_nt_notify_last_write = -1;
static int hf_smb_nt_notify_size = -1;
static int hf_smb_nt_notify_attributes = -1;
static int hf_smb_nt_notify_dir_name = -1;
static int hf_smb_nt_notify_file_name = -1;
static int hf_smb_root_dir_fid = -1;
static int hf_smb_nt_create_disposition = -1;
static int hf_smb_sd_length = -1;
static int hf_smb_ea_length = -1;
static int hf_smb_file_name_len = -1;
static int hf_smb_nt_impersonation_level = -1;
static int hf_smb_nt_security_flags_context_tracking = -1;
static int hf_smb_nt_security_flags_effective_only = -1;
static int hf_smb_nt_access_mask_generic_read = -1;
static int hf_smb_nt_access_mask_generic_write = -1;
static int hf_smb_nt_access_mask_generic_execute = -1;
static int hf_smb_nt_access_mask_generic_all = -1;
static int hf_smb_nt_access_mask_maximum_allowed = -1;
static int hf_smb_nt_access_mask_system_security = -1;
static int hf_smb_nt_access_mask_synchronize = -1;
static int hf_smb_nt_access_mask_write_owner = -1;
static int hf_smb_nt_access_mask_write_dac = -1;
static int hf_smb_nt_access_mask_read_control = -1;
static int hf_smb_nt_access_mask_delete = -1;
static int hf_smb_nt_access_mask_write_attributes = -1;
static int hf_smb_nt_access_mask_read_attributes = -1;
static int hf_smb_nt_access_mask_delete_child = -1;
static int hf_smb_nt_access_mask_execute = -1;
static int hf_smb_nt_access_mask_write_ea = -1;
static int hf_smb_nt_access_mask_read_ea = -1;
static int hf_smb_nt_access_mask_append = -1;
static int hf_smb_nt_access_mask_write = -1;
static int hf_smb_nt_access_mask_read = -1;
static int hf_smb_nt_create_bits_oplock = -1;
static int hf_smb_nt_create_bits_boplock = -1;
static int hf_smb_nt_create_bits_dir = -1;
static int hf_smb_nt_create_options_directory_file = -1;
static int hf_smb_nt_create_options_write_through = -1;
static int hf_smb_nt_create_options_sequential_only = -1;
static int hf_smb_nt_create_options_sync_io_alert = -1;
static int hf_smb_nt_create_options_sync_io_nonalert = -1;
static int hf_smb_nt_create_options_non_directory_file = -1;
static int hf_smb_nt_create_options_no_ea_knowledge = -1;
static int hf_smb_nt_create_options_eight_dot_three_only = -1;
static int hf_smb_nt_create_options_random_access = -1;
static int hf_smb_nt_create_options_delete_on_close = -1;
static int hf_smb_nt_share_access_read = -1;
static int hf_smb_nt_share_access_write = -1;
static int hf_smb_nt_share_access_delete = -1;
static int hf_smb_file_eattr_read_only = -1;
static int hf_smb_file_eattr_hidden = -1;
static int hf_smb_file_eattr_system = -1;
static int hf_smb_file_eattr_volume = -1;
static int hf_smb_file_eattr_directory = -1;
static int hf_smb_file_eattr_archive = -1;
static int hf_smb_file_eattr_device = -1;
static int hf_smb_file_eattr_normal = -1;
static int hf_smb_file_eattr_temporary = -1;
static int hf_smb_file_eattr_sparse = -1;
static int hf_smb_file_eattr_reparse = -1;
static int hf_smb_file_eattr_compressed = -1;
static int hf_smb_file_eattr_offline = -1;
static int hf_smb_file_eattr_not_content_indexed = -1;
static int hf_smb_file_eattr_encrypted = -1;
static int hf_smb_file_eattr_write_through = -1;
static int hf_smb_file_eattr_no_buffering = -1;
static int hf_smb_file_eattr_random_access = -1;
static int hf_smb_file_eattr_sequential_scan = -1;
static int hf_smb_file_eattr_delete_on_close = -1;
static int hf_smb_file_eattr_backup_semantics = -1;
static int hf_smb_file_eattr_posix_semantics = -1;
static int hf_smb_security_descriptor_len = -1;
static int hf_smb_security_descriptor = -1;
static int hf_smb_nt_qsd_owner = -1;
static int hf_smb_nt_qsd_group = -1;
static int hf_smb_nt_qsd_dacl = -1;
static int hf_smb_nt_qsd_sacl = -1;
static int hf_smb_extended_attributes = -1;
static int hf_smb_oplock_level = -1;
static int hf_smb_create_action = -1;
static int hf_smb_ea_error_offset = -1;
static int hf_smb_end_of_file = -1;
static int hf_smb_device_type = -1;
static int hf_smb_is_directory = -1;
static int hf_smb_next_entry_offset = -1;
static int hf_smb_change_time = -1;
static int hf_smb_setup_len = -1;
static int hf_smb_print_mode = -1;
static int hf_smb_print_identifier = -1;
static int hf_smb_restart_index = -1;
static int hf_smb_print_queue_date = -1;
static int hf_smb_print_queue_dos_date = -1;
static int hf_smb_print_queue_dos_time = -1;
static int hf_smb_print_status = -1;
static int hf_smb_print_spool_file_number = -1;
static int hf_smb_print_spool_file_size = -1;
static int hf_smb_print_spool_file_name = -1;
static int hf_smb_start_index = -1;
static int hf_smb_cancel_to = -1;
static int hf_smb_trans2_subcmd = -1;
static int hf_smb_trans_name = -1;
static int hf_smb_transaction_flags_dtid = -1;
static int hf_smb_transaction_flags_owt = -1;
static int hf_smb_search_count = -1;
static int hf_smb_search_pattern = -1;
static int hf_smb_ff2_backup = -1;
static int hf_smb_ff2_continue = -1;
static int hf_smb_ff2_resume = -1;
static int hf_smb_ff2_close_eos = -1;
static int hf_smb_ff2_close = -1;
static int hf_smb_ff2_information_level = -1;
static int hf_smb_qpi_loi = -1;
static int hf_smb_storage_type = -1;
static int hf_smb_resume = -1;
static int hf_smb_max_referral_level = -1;
static int hf_smb_qfsi_information_level = -1;
static int hf_smb_ea_size = -1;
static int hf_smb_list_length = -1;
static int hf_smb_number_of_links = -1;
static int hf_smb_delete_pending = -1;
static int hf_smb_index_number = -1;
static int hf_smb_current_offset = -1;
static int hf_smb_t2_alignment = -1;
static int hf_smb_t2_stream_name_length = -1;
static int hf_smb_t2_stream_size = -1;
static int hf_smb_t2_stream_name = -1;
static int hf_smb_t2_compressed_file_size = -1;
static int hf_smb_t2_compressed_format = -1;
static int hf_smb_t2_compressed_unit_shift = -1;
static int hf_smb_t2_compressed_chunk_shift = -1;
static int hf_smb_t2_compressed_cluster_shift = -1;
static int hf_smb_dfs_path_consumed = -1;
static int hf_smb_dfs_num_referrals = -1;
static int hf_smb_get_dfs_server_hold_storage = -1;
static int hf_smb_get_dfs_fielding = -1;
static int hf_smb_dfs_referral_version = -1;
static int hf_smb_dfs_referral_size = -1;
static int hf_smb_dfs_referral_server_type = -1;
static int hf_smb_dfs_referral_flags_strip = -1;
static int hf_smb_dfs_referral_node_offset = -1;
static int hf_smb_dfs_referral_node = -1;
static int hf_smb_dfs_referral_proximity = -1;
static int hf_smb_dfs_referral_ttl = -1;
static int hf_smb_dfs_referral_path_offset = -1;
static int hf_smb_dfs_referral_path = -1;
static int hf_smb_dfs_referral_alt_path_offset = -1;
static int hf_smb_dfs_referral_alt_path = -1;
static int hf_smb_end_of_search = -1;
static int hf_smb_last_name_offset = -1;
static int hf_smb_file_index = -1;
static int hf_smb_short_file_name = -1;
static int hf_smb_short_file_name_len = -1;
static int hf_smb_fs_id = -1;
static int hf_smb_sector_unit = -1;
static int hf_smb_fs_units = -1;
static int hf_smb_fs_sector = -1;
static int hf_smb_avail_units = -1;
static int hf_smb_volume_serial_num = -1;
static int hf_smb_volume_label_len = -1;
static int hf_smb_volume_label = -1;
static int hf_smb_free_alloc_units64 = -1;
static int hf_smb_max_name_len = -1;
static int hf_smb_fs_name_len = -1;
static int hf_smb_fs_name = -1;
static int hf_smb_device_char_removable = -1;
static int hf_smb_device_char_read_only = -1;
static int hf_smb_device_char_floppy = -1;
static int hf_smb_device_char_write_once = -1;
static int hf_smb_device_char_remote = -1;
static int hf_smb_device_char_mounted = -1;
static int hf_smb_device_char_virtual = -1;
static int hf_smb_fs_attr_css = -1;
static int hf_smb_fs_attr_cpn = -1;
static int hf_smb_fs_attr_pacls = -1;
static int hf_smb_fs_attr_fc = -1;
static int hf_smb_fs_attr_vq = -1;
static int hf_smb_fs_attr_dim = -1;
static int hf_smb_fs_attr_vic = -1;

static gint ett_smb = -1;
static gint ett_smb_hdr = -1;
static gint ett_smb_command = -1;
static gint ett_smb_fileattributes = -1;
static gint ett_smb_capabilities = -1;
static gint ett_smb_aflags = -1;
static gint ett_smb_dialect = -1;
static gint ett_smb_dialects = -1;
static gint ett_smb_mode = -1;
static gint ett_smb_rawmode = -1;
static gint ett_smb_flags = -1;
static gint ett_smb_flags2 = -1;
static gint ett_smb_desiredaccess = -1;
static gint ett_smb_search = -1;
static gint ett_smb_file = -1;
static gint ett_smb_openfunction = -1;
static gint ett_smb_filetype = -1;
static gint ett_smb_openaction = -1;
static gint ett_smb_writemode = -1;
static gint ett_smb_lock_type = -1;
static gint ett_smb_ssetupandxaction = -1;
static gint ett_smb_optionsup = -1;
static gint ett_smb_time_date = -1;
static gint ett_smb_64bit_time = -1;
static gint ett_smb_move_flags = -1;
static gint ett_smb_file_attributes = -1;
static gint ett_smb_search_resume_key = -1;
static gint ett_smb_search_dir_info = -1;
static gint ett_smb_unlocks = -1;
static gint ett_smb_unlock = -1;
static gint ett_smb_locks = -1;
static gint ett_smb_lock = -1;
static gint ett_smb_open_flags = -1;
static gint ett_smb_ipc_state = -1;
static gint ett_smb_open_action = -1;
static gint ett_smb_setup_action = -1;
static gint ett_smb_connect_flags = -1;
static gint ett_smb_connect_support_bits = -1;
static gint ett_smb_nt_access_mask = -1;
static gint ett_smb_nt_create_bits = -1;
static gint ett_smb_nt_create_options = -1;
static gint ett_smb_nt_share_access = -1;
static gint ett_smb_nt_security_flags = -1;
static gint ett_smb_nt_trans_setup = -1;
static gint ett_smb_nt_notify_completion_filter = -1;
static gint ett_smb_nt_ioctl_flags = -1;
static gint ett_smb_security_information_mask = -1;
static gint ett_smb_print_queue_entry = -1;
static gint ett_smb_transaction_flags = -1;
static gint ett_smb_transaction_params = -1;
static gint ett_smb_find_first2_flags = -1;
static gint ett_smb_transaction_data = -1;
static gint ett_smb_stream_info = -1;
static gint ett_smb_dfs_referrals = -1;
static gint ett_smb_dfs_referral = -1;
static gint ett_smb_dfs_referral_flags = -1;
static gint ett_smb_get_dfs_flags = -1;
static gint ett_smb_ff2_data = -1;
static gint ett_smb_device_characteristics = -1;
static gint ett_smb_fs_attributes = -1;
static gint ett_smb_segments = -1;

proto_tree *top_tree=NULL;     /* ugly */

static char *decode_smb_name(unsigned char);
static int dissect_smb_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree, guint8 cmd);
static const gchar *get_unicode_or_ascii_string(tvbuff_t *tvb,
    int *offsetp, packet_info *pinfo, int *len, gboolean nopad,
    gboolean exactlen, guint16 *bcp);

/*
 * Macros for use in the main dissector routines for an SMB.
 */

#define WORD_COUNT	\
	/* Word Count */				\
	wc = tvb_get_guint8(tvb, offset);		\
	proto_tree_add_uint(tree, hf_smb_word_count,	\
		tvb, offset, 1, wc);			\
	offset += 1;					\
	if(wc==0) goto bytecount;

#define BYTE_COUNT	\
	bytecount:					\
	bc = tvb_get_letohs(tvb, offset);		\
	proto_tree_add_uint(tree, hf_smb_byte_count,	\
			tvb, offset, 2, bc);		\
	offset += 2;					\
	if(bc==0) goto endofcommand;

#define CHECK_BYTE_COUNT(len)	\
	if (bc < len) goto endofcommand;

#define COUNT_BYTES(len)   {\
        int tmp;            \
        tmp=len;            \
	offset += tmp;	    \
	bc -= tmp;          \
        }

#define END_OF_SMB	\
	if (bc != 0) { \
		proto_tree_add_text(tree, tvb, offset, bc, \
		    "Extra byte parameters");		\
		offset += bc;				\
	}						\
	endofcommand:

/*
 * Macros for use in routines called by them.
 */
#define CHECK_BYTE_COUNT_SUBR(len)	\
	if (*bcp < len) {		\
		*trunc = TRUE;		\
		return offset;		\
	}

#define CHECK_STRING_SUBR(fn)	\
	if (fn == NULL) {	\
		*trunc = TRUE;	\
		return offset;	\
	}

#define COUNT_BYTES_SUBR(len)	\
	offset += len;		\
	*bcp -= len;

/*
 * Macros for use when dissecting transaction parameters and data
 */
#define CHECK_BYTE_COUNT_TRANS(len)	\
	if (bc < len) return offset;

#define CHECK_STRING_TRANS(fn)	\
	if (fn == NULL) return offset;

#define COUNT_BYTES_TRANS(len)	\
	offset += len;		\
	bc -= len;

/*
 * Macros for use in subrroutines dissecting transaction parameters or data
 */
#define CHECK_BYTE_COUNT_TRANS_SUBR(len)	\
	if (*bcp < len) return offset;

#define CHECK_STRING_TRANS_SUBR(fn)	\
	if (fn == NULL) return offset;

#define COUNT_BYTES_TRANS_SUBR(len)	\
	offset += len;			\
	*bcp -= len;


/* XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   These are needed by the reassembly of SMB Transaction payload
   XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX */
/* Reassembly of SMB Transaction calls */
static gboolean smb_trans_reassembly = FALSE;

static GHashTable *smb_trans_fragment_table = NULL;

static void
smb_trans_reassembly_init(void)
{
	fragment_table_init(&smb_trans_fragment_table);
}


static fragment_data *
smb_trans_defragment(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
		     int offset, int count, int pos, int totlen)
{
	fragment_data *fd_head=NULL;
	smb_info_t *si;
	int more_frags;

	more_frags=totlen>(pos+count);

	si = (smb_info_t *)pinfo->private_data;
	if (si->sip == NULL) {
		/*
		 * We don't have the frame number of the request.
		 *
		 * XXX - is there truly nothing we can do here?
		 * Can we not separately keep track of the original
		 * transaction and its continuations, as we did
		 * at one time?
		 *
		 * It is probably not much point in even trying to do something here
		 * if we have never seen the initial request. Without the initial 
		 * request we probably miss all parameters and the begining of data
		 * so we cant even call a subdissector since we can not determine
		 * which type of transaction call this is.
		 */
		return NULL;
	}

	if(!pinfo->fd->flags.visited){
		fd_head = fragment_add(tvb, offset, pinfo,
				       si->sip->frame_req, smb_trans_fragment_table,
				       pos, count, more_frags);
	} else {
		fd_head = fragment_get(pinfo, si->sip->frame_req, smb_trans_fragment_table);
	}

	/* we only show the defragmented packet for the first fragment,
	   or else we might end up with dissecting one HUGE transaction PDU
	   a LOT of times. (first fragment is the only one containing the setup
	   bytes)
	   I have seen ONE Transaction PDU that is ~60kb, spanning many Transaction 
	   SMBs. Takes a LOT of time dissecting and is not fun.
	*/
	if( (pos==0) && fd_head && fd_head->flags&FD_DEFRAGMENTED){
		return fd_head;
	} else {
		return NULL;
	}
}
		




/* XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   These variables and functions are used to match
   responses with calls
   XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX */
/*
 * The information we need to save about a request in order to show the
 * frame number of the request in the dissection of the reply.
 */
static GMemChunk *smb_saved_info_chunk = NULL;
static int smb_saved_info_init_count = 200;

/* matched smb_saved_info structures.
  For matched smb_saved_info structures we store the smb_saved_info
  structure twice in the table using the frame number as the key.
  The frame number is guaranteed to be unique but if ever someone makes
  some change that will renumber the frames in a capture we are in BIG trouble.
  This is not likely though since that would break (among other things) all the
  reassembly routines as well.

  Oh, yes, the key is really a pointer, but we use it as if it was an integer.
  Ugly, yes. Not portable to DEC-20 Yes. But it saves a few bytes.
*/
static gint
smb_saved_info_equal_matched(gconstpointer k1, gconstpointer k2)
{
	register int key1 = (int)k1;
	register int key2 = (int)k2;
	return key1==key2;
}
static guint
smb_saved_info_hash_matched(gconstpointer k)
{
	register int key = (int)k;
	return key;
}

/*
 * The information we need to save about an NT Transaction request in order
 * to dissect the reply.
 */
typedef struct {
	int subcmd;
} smb_nt_transact_info_t;

static GMemChunk *smb_nt_transact_info_chunk = NULL;
static int smb_nt_transact_info_init_count = 200;

/*
 * The information we need to save about a Transaction2 request in order
 * to dissect the reply.
 */
typedef struct {
	int subcmd;
	int info_level;
} smb_transact2_info_t;

static GMemChunk *smb_transact2_info_chunk = NULL;
static int smb_transact2_info_init_count = 200;

/*
 * The information we need to save about a Transaction request in order
 * to dissect the reply; this includes information for use by the
 * Remote API dissector.
 */
static GMemChunk *smb_transact_info_chunk = NULL;
static int smb_transact_info_init_count = 200;

typedef struct conv_tables {
	GHashTable *unmatched;
	GHashTable *matched;
} conv_tables_t;
static GMemChunk *conv_tables_chunk = NULL;
static int conv_tables_count = 10;


/* XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   End of request/response matching functions
   XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX */

static const value_string buffer_format_vals[] = {
	{1,     "Data Block"},
	{2,     "Dialect"},
	{3,     "Pathname"},
	{4,     "ASCII"},
	{5,     "Variable Block"},
	{0,     NULL}
};

/*
 * UTIME - this is *almost* like a UNIX time stamp, except that it's
 * in seconds since January 1, 1970, 00:00:00 *local* time, not since
 * January 1, 1970, 00:00:00 GMT.
 *
 * This means we have to do some extra work to convert it.  This code is
 * based on the Samba code:
 *
 *	Unix SMB/Netbios implementation.
 *	Version 1.9.
 *	time handling functions
 *	Copyright (C) Andrew Tridgell 1992-1998
 */

/*
 * Yield the difference between *A and *B, in seconds, ignoring leap
 * seconds.
 */
#define TM_YEAR_BASE 1900

static int
tm_diff(struct tm *a, struct tm *b)
{
	int ay = a->tm_year + (TM_YEAR_BASE - 1);
	int by = b->tm_year + (TM_YEAR_BASE - 1);
	int intervening_leap_days =
	    (ay/4 - by/4) - (ay/100 - by/100) + (ay/400 - by/400);
	int years = ay - by;
	int days =
	    365*years + intervening_leap_days + (a->tm_yday - b->tm_yday);
	int hours = 24*days + (a->tm_hour - b->tm_hour);
	int minutes = 60*hours + (a->tm_min - b->tm_min);
	int seconds = 60*minutes + (a->tm_sec - b->tm_sec);

	return seconds;
}

/*
 * Return the UTC offset in seconds west of UTC, or 0 if it cannot be
 * determined.
 */
static int
TimeZone(time_t t)
{
	struct tm *tm = gmtime(&t);
	struct tm tm_utc;

	if (tm == NULL)
		return 0;
	tm_utc = *tm;
	tm = localtime(&t);
	if (tm == NULL)
		return 0;
	return tm_diff(&tm_utc,tm);
}

/*
 * Return the same value as TimeZone, but it should be more efficient.
 *
 * We keep a table of DST offsets to prevent calling localtime() on each 
 * call of this function. This saves a LOT of time on many unixes.
 *
 * Updated by Paul Eggert <eggert@twinsun.com>
 */
#ifndef CHAR_BIT
#define CHAR_BIT 8
#endif

#ifndef TIME_T_MIN
#define TIME_T_MIN ((time_t)0 < (time_t) -1 ? (time_t) 0 \
		    : ~ (time_t) 0 << (sizeof (time_t) * CHAR_BIT - 1))
#endif
#ifndef TIME_T_MAX
#define TIME_T_MAX (~ (time_t) 0 - TIME_T_MIN)
#endif

static int
TimeZoneFaster(time_t t)
{
	static struct dst_table {time_t start,end; int zone;} *tdt;
	static struct dst_table *dst_table = NULL;
	static int table_size = 0;
	int i;
	int zone = 0;

	if (t == 0)
		t = time(NULL);

	/* Tunis has a 8 day DST region, we need to be careful ... */
#define MAX_DST_WIDTH (365*24*60*60)
#define MAX_DST_SKIP (7*24*60*60)

	for (i = 0; i < table_size; i++) {
		if (t >= dst_table[i].start && t <= dst_table[i].end)
			break;
	}

	if (i < table_size) {
		zone = dst_table[i].zone;
	} else {
		time_t low,high;

		zone = TimeZone(t);
		if (dst_table == NULL)
			tdt = g_malloc(sizeof(dst_table[0])*(i+1));
		else
			tdt = g_realloc(dst_table, sizeof(dst_table[0])*(i+1));
		if (tdt == NULL) {
			if (dst_table)
				free(dst_table);
			table_size = 0;
		} else {
			dst_table = tdt;
			table_size++;
    
			dst_table[i].zone = zone; 
			dst_table[i].start = dst_table[i].end = t;
    
			/* no entry will cover more than 6 months */
			low = t - MAX_DST_WIDTH/2;
			if (t < low)
				low = TIME_T_MIN;
      
			high = t + MAX_DST_WIDTH/2;
			if (high < t)
				high = TIME_T_MAX;
      
			/*
			 * Widen the new entry using two bisection searches.
			 */
			while (low+60*60 < dst_table[i].start) {
				if (dst_table[i].start - low > MAX_DST_SKIP*2)
					t = dst_table[i].start - MAX_DST_SKIP;
				else
					t = low + (dst_table[i].start-low)/2;
				if (TimeZone(t) == zone)
					dst_table[i].start = t;
				else
					low = t;
			}

			while (high-60*60 > dst_table[i].end) {
				if (high - dst_table[i].end > MAX_DST_SKIP*2)
					t = dst_table[i].end + MAX_DST_SKIP;
				else
					t = high - (high-dst_table[i].end)/2;
				if (TimeZone(t) == zone)
					dst_table[i].end = t;
				else
					high = t;
			}
		}
	}
	return zone;
}

/*
 * Return the UTC offset in seconds west of UTC, adjusted for extra time
 * offset, for a local time value.  If ut = lt + LocTimeDiff(lt), then
 * lt = ut - TimeDiff(ut), but the converse does not necessarily hold near
 * daylight savings transitions because some local times are ambiguous.
 * LocTimeDiff(t) equals TimeDiff(t) except near daylight savings transitions.
 */
static int
LocTimeDiff(time_t lt)
{
	int d = TimeZoneFaster(lt);
	time_t t = lt + d;

	/* if overflow occurred, ignore all the adjustments so far */
	if (((t < lt) ^ (d < 0)))
		t = lt;

	/*
	 * Now t should be close enough to the true UTC to yield the
	 * right answer.
	 */
	return TimeZoneFaster(t);
}

static int
dissect_smb_UTIME(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int hf_date)
{
	guint32 timeval;
	nstime_t ts;
 
	timeval = tvb_get_letohl(tvb, offset);
	if (timeval == 0xffffffff) {
		proto_tree_add_text(tree, tvb, offset, 4,
		    "%s: No time specified (0xffffffff)",
		    proto_registrar_get_name(hf_date));
		offset += 4;
		return offset;
	}

	/*
	 * We add the local time offset.
	 */
	ts.secs = timeval + LocTimeDiff(timeval);
	ts.nsecs = 0;

	proto_tree_add_time(tree, hf_date, tvb, offset, 4, &ts);
	offset += 4;
 
	return offset;
}

static int
dissect_smb_64bit_time(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset, char *str, int hf_date)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	nstime_t tv;

	/* XXXX we need some way to represent this as a time
	   properly. For now we display everything as 8 bytes*/

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 8,
			str);
		tree = proto_item_add_subtree(item, ett_smb_64bit_time);
	}

	proto_tree_add_bytes_format(tree, hf_smb_unknown, tvb, offset, 8, tvb_get_ptr(tvb, offset, 8), "%s: can't decode this yet", str);

	offset += 8;
	return offset;
}

static int
dissect_smb_datetime(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *parent_tree, int offset, int hf_date, int hf_dos_date,
    int hf_dos_time, gboolean time_first)
{
	guint16 dos_time, dos_date;
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	struct tm tm;
	time_t t;
	static const int mday_noleap[12] = {
		31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
	};
	static const int mday_leap[12] = {
		31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
	};
#define ISLEAP(y) (((y) % 4) == 0 && (((y) % 100) != 0 || ((y) % 400) == 0))
	nstime_t tv;

	if (time_first) {
		dos_time = tvb_get_letohs(tvb, offset);
		dos_date = tvb_get_letohs(tvb, offset+2);
	} else {
		dos_date = tvb_get_letohs(tvb, offset);
		dos_time = tvb_get_letohs(tvb, offset+2);
	}

	if ((dos_time == 0xffff && dos_time == 0xffff) ||
	    (dos_time == 0 && dos_time == 0)) {
		/*
		 * No date/time specified.
		 */
		if(parent_tree){
			proto_tree_add_text(parent_tree, tvb, offset, 4,
			    "%s: No time specified (0x%08x)",
			    proto_registrar_get_name(hf_date),
			    (dos_date << 16) | dos_time);
		}
		offset += 4;
		return offset;
	}

	tm.tm_sec = (dos_time&0x1f)*2;
	tm.tm_min = (dos_time>>5)&0x3f;
	tm.tm_hour = (dos_time>>11)&0x1f;
	tm.tm_mday = dos_date&0x1f;
	tm.tm_mon = ((dos_date>>5)&0x0f) - 1;
	tm.tm_year = ((dos_date>>9)&0x7f) + 1980 - 1900;
	tm.tm_isdst = -1;

	/*
	 * Do some sanity checks before calling "mktime()";
	 * "mktime()" doesn't do them, it "normalizes" out-of-range
	 * values.
	 */
	if (tm.tm_sec > 59 || tm.tm_min > 59 || tm.tm_hour > 23 ||
	   tm.tm_mon < 0 || tm.tm_mon > 11 ||
	   (ISLEAP(tm.tm_year + 1900) ?
	     tm.tm_mday > mday_leap[tm.tm_mon] :
	     tm.tm_mday > mday_noleap[tm.tm_mon]) ||
	     (t = mktime(&tm)) == -1) {
		/*
		 * Invalid date/time.
		 */
		if (parent_tree) {
			item = proto_tree_add_text(parent_tree, tvb, offset, 4,
			    "%s: Invalid time",
			    proto_registrar_get_name(hf_date));
			tree = proto_item_add_subtree(item, ett_smb_time_date);
			if (time_first) {
				proto_tree_add_uint_format(tree, hf_dos_time, tvb, offset, 2, dos_time, "DOS Time: %02d:%02d:%02d (0x%04x)", tm.tm_hour, tm.tm_min, tm.tm_sec, dos_time);
				proto_tree_add_uint_format(tree, hf_dos_date, tvb, offset+2, 2, dos_date, "DOS Date: %04d-%02d-%02d (0x%04x)", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, dos_date);
			} else {
				proto_tree_add_uint_format(tree, hf_dos_date, tvb, offset, 2, dos_date, "DOS Date: %04d-%02d-%02d (0x%04x)", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, dos_date);
				proto_tree_add_uint_format(tree, hf_dos_time, tvb, offset+2, 2, dos_time, "DOS Time: %02d:%02d:%02d (0x%04x)", tm.tm_hour, tm.tm_min, tm.tm_sec, dos_time);
			}
		}
		offset += 4;
		return offset;
	}

	tv.secs = t;
	tv.nsecs = 0;

	if(parent_tree){
		item = proto_tree_add_time(parent_tree, hf_date, tvb, offset, 4, &tv);
		tree = proto_item_add_subtree(item, ett_smb_time_date);
		if (time_first) {
			proto_tree_add_uint_format(tree, hf_dos_time, tvb, offset, 2, dos_time, "DOS Time: %02d:%02d:%02d (0x%04x)", tm.tm_hour, tm.tm_min, tm.tm_sec, dos_time);
			proto_tree_add_uint_format(tree, hf_dos_date, tvb, offset+2, 2, dos_date, "DOS Date: %04d-%02d-%02d (0x%04x)", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, dos_date);
		} else {
			proto_tree_add_uint_format(tree, hf_dos_date, tvb, offset, 2, dos_date, "DOS Date: %04d-%02d-%02d (0x%04x)", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, dos_date);
			proto_tree_add_uint_format(tree, hf_dos_time, tvb, offset+2, 2, dos_time, "DOS Time: %02d:%02d:%02d (0x%04x)", tm.tm_hour, tm.tm_min, tm.tm_sec, dos_time);
		}
	}

	offset += 4;

	return offset;
}


static const value_string da_access_vals[] = {
	{ 0,		"Open for reading"},
	{ 1,		"Open for writing"},
	{ 2,		"Open for reading and writing"},
	{ 3,		"Open for execute"},
	{0, NULL}
};
static const value_string da_sharing_vals[] = {
	{ 0,		"Compatibility mode"},
	{ 1,		"Deny read/write/execute (exclusive)"},
	{ 2,		"Deny write"},
	{ 3,		"Deny read/execute"},
	{ 4,		"Deny none"},
	{0, NULL}
};
static const value_string da_locality_vals[] = {
	{ 0,		"Locality of reference unknown"},
	{ 1,		"Mainly sequential access"},
	{ 2,		"Mainly random access"},
	{ 3,		"Random access with some locality"},
	{0, NULL}
};
static const true_false_string tfs_da_caching = {
	"Do not cache this file",
	"Caching permitted on this file"
};
static const true_false_string tfs_da_writetru = {
	"Write through enabled",
	"Write through disabled"
};
static int
dissect_access(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset, char *type)
{
	guint16 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohs(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 2,
			"%s Access: 0x%04x", type, mask);
		tree = proto_item_add_subtree(item, ett_smb_desiredaccess);
	}

	proto_tree_add_boolean(tree, hf_smb_access_writetru,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_access_caching,
		tvb, offset, 2, mask);
	proto_tree_add_uint(tree, hf_smb_access_locality,
		tvb, offset, 2, mask);
	proto_tree_add_uint(tree, hf_smb_access_sharing,
		tvb, offset, 2, mask);
	proto_tree_add_uint(tree, hf_smb_access_mode,
		tvb, offset, 2, mask);

	offset += 2;

	return offset;
}

#define FILE_ATTRIBUTE_READ_ONLY		0x00000001
#define FILE_ATTRIBUTE_HIDDEN			0x00000002
#define FILE_ATTRIBUTE_SYSTEM			0x00000004
#define FILE_ATTRIBUTE_VOLUME			0x00000008
#define FILE_ATTRIBUTE_DIRECTORY		0x00000010
#define FILE_ATTRIBUTE_ARCHIVE			0x00000020
#define FILE_ATTRIBUTE_DEVICE			0x00000040
#define FILE_ATTRIBUTE_NORMAL			0x00000080
#define FILE_ATTRIBUTE_TEMPORARY		0x00000100
#define FILE_ATTRIBUTE_SPARSE			0x00000200
#define FILE_ATTRIBUTE_REPARSE			0x00000400
#define FILE_ATTRIBUTE_COMPRESSED		0x00000800
#define FILE_ATTRIBUTE_OFFLINE			0x00001000
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED	0x00002000
#define FILE_ATTRIBUTE_ENCRYPTED		0x00004000

/*
 * These are flags to be used in NT Create operations.
 */
#define FILE_ATTRIBUTE_WRITE_THROUGH		0x80000000
#define FILE_ATTRIBUTE_NO_BUFFERING		0x20000000
#define FILE_ATTRIBUTE_RANDOM_ACCESS		0x10000000
#define FILE_ATTRIBUTE_SEQUENTIAL_SCAN		0x08000000
#define FILE_ATTRIBUTE_DELETE_ON_CLOSE		0x04000000
#define FILE_ATTRIBUTE_BACKUP_SEMANTICS		0x02000000
#define FILE_ATTRIBUTE_POSIX_SEMANTICS		0x01000000

static const true_false_string tfs_file_attribute_write_through = {
	"This object requires WRITE THROUGH",
	"This object does NOT require write through",
};
static const true_false_string tfs_file_attribute_no_buffering = {
	"This object requires NO BUFFERING",
	"This object can be buffered",
};
static const true_false_string tfs_file_attribute_random_access = {
	"This object will be RANDOM ACCESSed",
	"Random access is NOT requested",
};
static const true_false_string tfs_file_attribute_sequential_scan = {
	"This object is optimized for SEQUENTIAL SCAN",
	"This object is NOT optimized for sequential scan",
};
static const true_false_string tfs_file_attribute_delete_on_close = {
	"This object will be DELETED ON CLOSE",
	"This object will not be deleted on close",
};
static const true_false_string tfs_file_attribute_backup_semantics = {
	"This object supports BACKUP SEMANTICS",
	"This object does NOT support backup semantics",
};
static const true_false_string tfs_file_attribute_posix_semantics = {
	"This object supports POSIX SEMANTICS",
	"This object does NOT support POSIX semantics",
};
static const true_false_string tfs_file_attribute_read_only = {
	"This file is READ ONLY",
	"This file is NOT read only",
};
static const true_false_string tfs_file_attribute_hidden = {
	"This is a HIDDEN file",
	"This is NOT a hidden file"
};
static const true_false_string tfs_file_attribute_system = {
	"This is a SYSTEM file",
	"This is NOT a system file"
};
static const true_false_string tfs_file_attribute_volume = {
	"This is a VOLUME ID",
	"This is NOT a volume ID"
};
static const true_false_string tfs_file_attribute_directory = {
	"This is a DIRECTORY",
	"This is NOT a directory"
};
static const true_false_string tfs_file_attribute_archive = {
	"This is an ARCHIVE file",
	"This is NOT an archive file"
};
static const true_false_string tfs_file_attribute_device = {
	"This is a DEVICE",
	"This is NOT a device"
};
static const true_false_string tfs_file_attribute_normal = {
	"This file is an ordinary file",
	"This file has some attribute set"
};
static const true_false_string tfs_file_attribute_temporary = {
	"This is a TEMPORARY file",
	"This is NOT a temporary file"
};
static const true_false_string tfs_file_attribute_sparse = {
	"This is a SPARSE file",
	"This is NOT a sparse file"
};
static const true_false_string tfs_file_attribute_reparse = {
	"This file has an associated REPARSE POINT",
	"This file does NOT have an associated reparse point"
};
static const true_false_string tfs_file_attribute_compressed = {
	"This is a COMPRESSED file",
	"This is NOT a compressed file"
};
static const true_false_string tfs_file_attribute_offline = {
	"This file is OFFLINE",
	"This file is NOT offline"
};
static const true_false_string tfs_file_attribute_not_content_indexed = {
	"This file MAY NOT be indexed by the CONTENT INDEXING service",
	"This file MAY be indexed by the content indexing service"
};
static const true_false_string tfs_file_attribute_encrypted = {
	"This is an ENCRYPTED file",
	"This is NOT an encrypted file"
};

static int
dissect_file_attributes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint16 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohs(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 2,
			"File Attributes: 0x%04x", mask);
		tree = proto_item_add_subtree(item, ett_smb_file_attributes);
	}
	proto_tree_add_boolean(tree, hf_smb_file_attr_read_only_16bit,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_hidden_16bit,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_system_16bit,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_volume_16bit,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_directory_16bit,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_archive_16bit,
		tvb, offset, 2, mask);

	offset += 2;

	return offset;
}

/* 3.11 */
static int
dissect_file_ext_attr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint32 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohl(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 4,
			"File Attributes: 0x%08x", mask);
		tree = proto_item_add_subtree(item, ett_smb_file_attributes);
	}

	/*
	 * XXX - Network Monitor disagrees on some of the
	 * bits, e.g. the bits above temporary are "atomic write"
	 * and "transaction write", and it says nothing about the
	 * bits above that.
	 *
	 * Does the Win32 API documentation, or the NT Native API book,
	 * suggest anything?
	 */
	proto_tree_add_boolean(tree, hf_smb_file_eattr_write_through,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_file_eattr_no_buffering,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_file_eattr_random_access,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_file_eattr_sequential_scan,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_file_eattr_delete_on_close,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_file_eattr_backup_semantics,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_file_eattr_posix_semantics,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_file_eattr_encrypted,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_file_eattr_not_content_indexed,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_file_eattr_offline,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_file_eattr_compressed,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_file_eattr_reparse,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_file_eattr_sparse,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_file_eattr_temporary,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_file_eattr_normal,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_file_eattr_device,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_file_eattr_archive,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_file_eattr_directory,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_file_eattr_volume,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_file_eattr_system,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_file_eattr_hidden,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_file_eattr_read_only,
		tvb, offset, 4, mask);

	offset += 4;

	return offset;
}

static int
dissect_dir_info_file_attributes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint8 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_guint8(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 1,
			"File Attributes: 0x%02x", mask);
		tree = proto_item_add_subtree(item, ett_smb_file_attributes);
	}
	proto_tree_add_boolean(tree, hf_smb_file_attr_read_only_8bit,
		tvb, offset, 1, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_hidden_8bit,
		tvb, offset, 1, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_system_8bit,
		tvb, offset, 1, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_volume_8bit,
		tvb, offset, 1, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_directory_8bit,
		tvb, offset, 1, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_archive_8bit,
		tvb, offset, 1, mask);

	offset += 1;

	return offset;
}

static const true_false_string tfs_search_attribute_read_only = {
	"Include READ ONLY files in search results",
	"Do NOT include read only files in search results",
};
static const true_false_string tfs_search_attribute_hidden = {
	"Include HIDDEN files in search results",
	"Do NOT include hidden files in search results"
};
static const true_false_string tfs_search_attribute_system = {
	"Include SYSTEM files in search results",
	"Do NOT include system files in search results"
};
static const true_false_string tfs_search_attribute_volume = {
	"Include VOLUME IDs in search results",
	"Do NOT include volume IDs in search results"
};
static const true_false_string tfs_search_attribute_directory = {
	"Include DIRECTORIES in search results",
	"Do NOT include directories in search results"
};
static const true_false_string tfs_search_attribute_archive = {
	"Include ARCHIVE files in search results",
	"Do NOT include archive files in search results"
};

static int
dissect_search_attributes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint16 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohs(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 2,
			"Search Attributes: 0x%04x", mask);
		tree = proto_item_add_subtree(item, ett_smb_search);
	}

	proto_tree_add_boolean(tree, hf_smb_search_attribute_read_only,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_search_attribute_hidden,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_search_attribute_system,
		tvb, offset, 2, mask);	
	proto_tree_add_boolean(tree, hf_smb_search_attribute_volume,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_search_attribute_directory,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_search_attribute_archive,
		tvb, offset, 2, mask);

	offset += 2;
	return offset;
}

#if 0
/*
 * XXX - this isn't used.
 * Is this used for anything?  NT Create AndX doesn't use it.
 * Is there some 16-bit attribute field with more bits than Read Only,
 * Hidden, System, Volume ID, Directory, and Archive?
 */
static int
dissect_extended_file_attributes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint32 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohl(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 2,
			"File Attributes: 0x%08x", mask);
		tree = proto_item_add_subtree(item, ett_smb_file_attributes);
	}
	proto_tree_add_boolean(tree, hf_smb_file_attr_read_only_16bit,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_hidden_16bit,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_system_16bit,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_volume_16bit,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_directory_16bit,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_archive_16bit,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_device,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_normal,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_temporary,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_sparse,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_reparse,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_compressed,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_offline,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_not_content_indexed,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_encrypted,
		tvb, offset, 2, mask);

	offset += 2;

	return offset;
}
#endif


#define SERVER_CAP_RAW_MODE            0x00000001
#define SERVER_CAP_MPX_MODE            0x00000002
#define SERVER_CAP_UNICODE             0x00000004
#define SERVER_CAP_LARGE_FILES         0x00000008
#define SERVER_CAP_NT_SMBS             0x00000010
#define SERVER_CAP_RPC_REMOTE_APIS     0x00000020
#define SERVER_CAP_STATUS32            0x00000040
#define SERVER_CAP_LEVEL_II_OPLOCKS    0x00000080
#define SERVER_CAP_LOCK_AND_READ       0x00000100
#define SERVER_CAP_NT_FIND             0x00000200
#define SERVER_CAP_DFS                 0x00001000
#define SERVER_CAP_INFOLEVEL_PASSTHRU  0x00002000
#define SERVER_CAP_LARGE_READX         0x00004000
#define SERVER_CAP_LARGE_WRITEX        0x00008000
#define SERVER_CAP_UNIX                0x00800000
#define SERVER_CAP_RESERVED            0x02000000
#define SERVER_CAP_BULK_TRANSFER       0x20000000
#define SERVER_CAP_COMPRESSED_DATA     0x40000000
#define SERVER_CAP_EXTENDED_SECURITY   0x80000000
static const true_false_string tfs_server_cap_raw_mode = {
	"Read Raw and Write Raw are supported",
	"Read Raw and Write Raw are not supported"
};
static const true_false_string tfs_server_cap_mpx_mode = {
	"Read Mpx and Write Mpx are supported",
	"Read Mpx and Write Mpx are not supported"
};
static const true_false_string tfs_server_cap_unicode = {
	"Unicode strings are supported",
	"Unicode strings are not supported"
};
static const true_false_string tfs_server_cap_large_files = {
	"Large files are supported",
	"Large files are not supported",
};
static const true_false_string tfs_server_cap_nt_smbs = {
	"NT SMBs are supported",
	"NT SMBs are not supported"
};
static const true_false_string tfs_server_cap_rpc_remote_apis = {
	"RPC remote APIs are supported",
	"RPC remote APIs are not supported"
};
static const true_false_string tfs_server_cap_nt_status = {
	"NT status codes are supported",
	"NT status codes are not supported"
};
static const true_false_string tfs_server_cap_level_ii_oplocks = {
	"Level 2 oplocks are supported",
	"Level 2 oplocks are not supported"
};
static const true_false_string tfs_server_cap_lock_and_read = {
	"Lock and Read is supported",
	"Lock and Read is not supported"
};
static const true_false_string tfs_server_cap_nt_find = {
	"NT Find is supported",
	"NT Find is not supported"
};
static const true_false_string tfs_server_cap_dfs = {
	"Dfs is supported",
	"Dfs is not supported"
};
static const true_false_string tfs_server_cap_infolevel_passthru = {
	"NT information level request passthrough is supported",
	"NT information level request passthrough is not supported"
};
static const true_false_string tfs_server_cap_large_readx = {
	"Large Read andX is supported",
	"Large Read andX is not supported"
};
static const true_false_string tfs_server_cap_large_writex = {
	"Large Write andX is supported",
	"Large Write andX is not supported"
};
static const true_false_string tfs_server_cap_unix = {
	"UNIX extensions are supported",
	"UNIX extensions are not supported"
};
static const true_false_string tfs_server_cap_reserved = {
	"Reserved",
	"Reserved"
};
static const true_false_string tfs_server_cap_bulk_transfer = {
	"Bulk Read and Bulk Write are supported",
	"Bulk Read and Bulk Write are not supported"
};
static const true_false_string tfs_server_cap_compressed_data = {
	"Compressed data transfer is supported",
	"Compressed data transfer is not supported"
};
static const true_false_string tfs_server_cap_extended_security = {
	"Extended security exchanges are supported",
	"Extended security exchanges are not supported"
};
static int
dissect_negprot_capabilities(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint32 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohl(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 4, "Capabilities: 0x%08x", mask);
		tree = proto_item_add_subtree(item, ett_smb_capabilities);
	}

	proto_tree_add_boolean(tree, hf_smb_server_cap_raw_mode,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_mpx_mode,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_unicode,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_large_files,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_nt_smbs,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_rpc_remote_apis,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_nt_status,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_level_ii_oplocks,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_lock_and_read,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_nt_find,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_dfs,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_infolevel_passthru,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_large_readx,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_large_writex,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_unix,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_reserved,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_bulk_transfer,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_compressed_data,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_extended_security,
		tvb, offset, 4, mask);

	return mask;
}

#define RAWMODE_READ   0x01
#define RAWMODE_WRITE  0x02
static const true_false_string tfs_rm_read = {
	"Read Raw is supported",
	"Read Raw is not supported"
};
static const true_false_string tfs_rm_write = {
	"Write Raw is supported",
	"Write Raw is not supported"
};

static int
dissect_negprot_rawmode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint16 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohs(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 2, "Raw Mode: 0x%04x", mask);
		tree = proto_item_add_subtree(item, ett_smb_rawmode);
	}

	proto_tree_add_boolean(tree, hf_smb_rm_read, tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_rm_write, tvb, offset, 2, mask);

	offset += 2;

	return offset;
}

#define SECURITY_MODE_MODE             0x01
#define SECURITY_MODE_PASSWORD         0x02
#define SECURITY_MODE_SIGNATURES       0x04
#define SECURITY_MODE_SIG_REQUIRED     0x08
static const true_false_string tfs_sm_mode = {
	"USER security mode",
	"SHARE security mode"
};
static const true_false_string tfs_sm_password = {
	"ENCRYPTED password. Use challenge/response",
	"PLAINTEXT password"
};
static const true_false_string tfs_sm_signatures = {
	"Security signatures ENABLED",
	"Security signatures NOT enabled"
};
static const true_false_string tfs_sm_sig_required = {
	"Security signatures REQUIRED",
	"Security signatures NOT required"
};

static int
dissect_negprot_security_mode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset, int wc)
{
	guint16 mask = 0;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	switch(wc){
	case 13:
		mask = tvb_get_letohs(tvb, offset);
		item = proto_tree_add_text(parent_tree, tvb, offset, 2,
				"Security Mode: 0x%04x", mask);
		tree = proto_item_add_subtree(item, ett_smb_mode);
		proto_tree_add_boolean(tree, hf_smb_sm_mode16, tvb, offset, 2, mask);
		proto_tree_add_boolean(tree, hf_smb_sm_password16, tvb, offset, 2, mask);
		offset += 2;
		break;

	case 17:
		mask = tvb_get_guint8(tvb, offset);
		item = proto_tree_add_text(parent_tree, tvb, offset, 1,
				"Security Mode: 0x%02x", mask);
		tree = proto_item_add_subtree(item, ett_smb_mode);
		proto_tree_add_boolean(tree, hf_smb_sm_mode, tvb, offset, 1, mask);
		proto_tree_add_boolean(tree, hf_smb_sm_password, tvb, offset, 1, mask);
		proto_tree_add_boolean(tree, hf_smb_sm_signatures, tvb, offset, 1, mask);
		proto_tree_add_boolean(tree, hf_smb_sm_sig_required, tvb, offset, 1, mask);
		offset += 1;
		break;
	}

	return offset;
}

static int
dissect_negprot_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	proto_item *it = NULL;
	proto_tree *tr = NULL;
	guint16 bc;
	guint8 wc;

	WORD_COUNT;

	BYTE_COUNT;

	if(tree){
		it = proto_tree_add_text(tree, tvb, offset, bc,
				"Requested Dialects");
		tr = proto_item_add_subtree(it, ett_smb_dialects);
	}

	while(bc){
		int len;
		const guint8 *str;
		proto_item *dit = NULL;
		proto_tree *dtr = NULL;

		/* XXX - what if this runs past bc? */
		len = tvb_strsize(tvb, offset+1);
		str = tvb_get_ptr(tvb, offset+1, len);

		if(tr){
			dit = proto_tree_add_text(tr, tvb, offset, len+1,
					"Dialect: %s", str);
			dtr = proto_item_add_subtree(dit, ett_smb_dialect);
		}

		/* Buffer Format */
		CHECK_BYTE_COUNT(1);
		proto_tree_add_item(dtr, hf_smb_buffer_format, tvb, offset, 1,
			TRUE);
		COUNT_BYTES(1);

		/*Dialect Name */
		CHECK_BYTE_COUNT(len);
		proto_tree_add_string(dtr, hf_smb_dialect_name, tvb, offset,
			len, str);
		COUNT_BYTES(len);
	}

	END_OF_SMB

	return offset;
}

static int
dissect_negprot_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 dialect;
	const char *dn;
	int dn_len;
	guint16 bc;
	guint16 ekl=0;
	guint32 caps=0;
	gint16 tz;

	WORD_COUNT;

	/* Dialect Index */
	dialect = tvb_get_letohs(tvb, offset);
	switch(wc){
	case 1:
		if(dialect==0xffff){
			proto_tree_add_uint_format(tree, hf_smb_dialect_index,
				tvb, offset, 2, dialect,
				"Selected Index: -1, PC NETWORK PROGRAM 1.0 choosen");
		} else {
			proto_tree_add_uint(tree, hf_smb_dialect_index,
				tvb, offset, 2, dialect);
		}
		break;
	case 13:
		proto_tree_add_uint_format(tree, hf_smb_dialect_index,
			tvb, offset, 2, dialect,
			"Dialect Index: %u, Greater than CORE PROTOCOL and up to LANMAN2.1", dialect);
		break;
	case 17:
		proto_tree_add_uint_format(tree, hf_smb_dialect_index,
			tvb, offset, 2, dialect,
			"Dialect Index: %u, greater than LANMAN2.1", dialect);
		break;
	default:
		proto_tree_add_text(tree, tvb, offset, wc*2,
			"Words for unknown response format");
		offset += wc*2;
		goto bytecount;
	}
	offset += 2;

	switch(wc){
	case 13:
		/* Security Mode */
		offset = dissect_negprot_security_mode(tvb, pinfo, tree, offset,
				wc);

		/* Maximum Transmit Buffer Size */
		proto_tree_add_item(tree, hf_smb_max_trans_buf_size,
			tvb, offset, 2, TRUE);
		offset += 2;

		/* Maximum Multiplex Count */
		proto_tree_add_item(tree, hf_smb_max_mpx_count,
			tvb, offset, 2, TRUE);
		offset += 2;

		/* Maximum Vcs Number */
		proto_tree_add_item(tree, hf_smb_max_vcs_num,
			tvb, offset, 2, TRUE);
		offset += 2;

		/* raw mode */
		offset = dissect_negprot_rawmode(tvb, pinfo, tree, offset);

		/* session key */
		proto_tree_add_item(tree, hf_smb_session_key,
			tvb, offset, 4, TRUE);
		offset += 4;

		/* current time and date at server */
		offset = dissect_smb_datetime(tvb, pinfo, tree, offset, hf_smb_server_date_time, hf_smb_server_smb_date, hf_smb_server_smb_time,
		    TRUE);

		/* time zone */
		tz = tvb_get_letohs(tvb, offset);
		proto_tree_add_int_format(tree, hf_smb_server_timezone, tvb, offset, 2, tz, "Server Time Zone: %d min from UTC", tz);
		offset += 2;

		/* encryption key length */
		ekl = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_encryption_key_length, tvb, offset, 2, ekl);
		offset += 2;

		/* 2 reserved bytes */
		proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 2, TRUE);
		offset += 2;

		break;

	case 17:
		/* Security Mode */
		offset = dissect_negprot_security_mode(tvb, pinfo, tree, offset, wc);

		/* Maximum Multiplex Count */
		proto_tree_add_item(tree, hf_smb_max_mpx_count,
			tvb, offset, 2, TRUE);
		offset += 2;

		/* Maximum Vcs Number */
		proto_tree_add_item(tree, hf_smb_max_vcs_num,
			tvb, offset, 2, TRUE);
		offset += 2;

		/* Maximum Transmit Buffer Size */
		proto_tree_add_item(tree, hf_smb_max_trans_buf_size,
			tvb, offset, 4, TRUE);
		offset += 4;

		/* maximum raw buffer size */
		proto_tree_add_item(tree, hf_smb_max_raw_buf_size,
			tvb, offset, 4, TRUE);
		offset += 4;

		/* session key */
		proto_tree_add_item(tree, hf_smb_session_key,
			tvb, offset, 4, TRUE);
		offset += 4;

		/* server capabilities */
		caps = dissect_negprot_capabilities(tvb, pinfo, tree, offset);
		offset += 4;

		/* system time */
		offset = dissect_smb_64bit_time(tvb, pinfo, tree, offset,
			       	"System Time", hf_smb_system_time);

		/* time zone */
		tz = tvb_get_letohs(tvb, offset);
		proto_tree_add_int_format(tree, hf_smb_server_timezone,
			tvb, offset, 2, tz,
			"Server Time Zone: %d min from UTC", tz);
		offset += 2;

		/* encryption key length */
		ekl = tvb_get_guint8(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_encryption_key_length,
			tvb, offset, 1, ekl);
		offset += 1;

		break;
	}

	BYTE_COUNT;

	switch(wc){
	case 13:
		/* challenge/response encryption key */
		if(ekl){
			CHECK_BYTE_COUNT(ekl);
			proto_tree_add_item(tree, hf_smb_encryption_key, tvb, offset, ekl, TRUE);
			COUNT_BYTES(ekl);
		}

		/* domain */
		dn = get_unicode_or_ascii_string(tvb, &offset,
			pinfo, &dn_len, FALSE, FALSE, &bc);
		if (dn == NULL)
			goto endofcommand;
		proto_tree_add_string(tree, hf_smb_primary_domain, tvb,
			offset, dn_len,dn);
		COUNT_BYTES(dn_len);
		break;

	case 17:
		if(!(caps&SERVER_CAP_EXTENDED_SECURITY)){
			smb_info_t *si;

			/* challenge/response encryption key */
			/* XXX - is this aligned on an even boundary? */
			if(ekl){
				CHECK_BYTE_COUNT(ekl);
				proto_tree_add_item(tree, hf_smb_encryption_key,
					tvb, offset, ekl, TRUE);
				COUNT_BYTES(ekl);
			}

			/* domain */
			/* this string is special, unicode is flagged in caps */
			/* This string is NOT padded to be 16bit aligned. (seen in actual capture) */
			si = pinfo->private_data;
			si->unicode = (caps&SERVER_CAP_UNICODE);
			dn = get_unicode_or_ascii_string(tvb,
				&offset, pinfo, &dn_len, TRUE, FALSE,
				&bc);
			if (dn == NULL)
				goto endofcommand;
			proto_tree_add_string(tree, hf_smb_primary_domain,
				tvb, offset, dn_len, dn);
			COUNT_BYTES(dn_len);
		} else {
			/* guid */
			/* XXX - show it in the standard Microsoft format
			   for GUIDs? */
			CHECK_BYTE_COUNT(16);
			proto_tree_add_item(tree, hf_smb_server_guid,
				tvb, offset, 16, TRUE);
			COUNT_BYTES(16);

			/* security blob */
			/* XXX - is this ASN.1-encoded?  Is it a Kerberos
			   data structure, at least in NT 5.0-and-later
			   server replies? */
			if(bc){
				proto_tree_add_item(tree, hf_smb_security_blob,
					tvb, offset, bc, TRUE);
				COUNT_BYTES(bc);
			}
		}
		break;
	}

	END_OF_SMB

	return offset;
}


static int
dissect_old_dir_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	int dn_len;
	const char *dn;
	guint8 wc;
	guint16 bc;

	WORD_COUNT;
 
	BYTE_COUNT;

	/* buffer format */
	CHECK_BYTE_COUNT(1);
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	COUNT_BYTES(1);

	/* dir name */
	dn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &dn_len,
		FALSE, FALSE, &bc);
	if (dn == NULL)
		goto endofcommand;
	proto_tree_add_string(tree, hf_smb_dir_name, tvb, offset, dn_len,
		dn);
	COUNT_BYTES(dn_len);

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, ", Directory: %s", dn);
	}

	END_OF_SMB

	return offset;
}

static int
dissect_empty(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;
 
	WORD_COUNT;
 
	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

static int
dissect_echo_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint16 ec, bc;
	guint8 wc;

	WORD_COUNT;

	/* echo count */
	ec = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_echo_count, tvb, offset, 2, ec);
	offset += 2;

	BYTE_COUNT;

	if (bc != 0) {
		/* echo data */
		proto_tree_add_item(tree, hf_smb_echo_data, tvb, offset, bc, TRUE);
		COUNT_BYTES(bc);
	}

	END_OF_SMB

	return offset;
}

static int
dissect_echo_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint16 bc;
	guint8 wc;

	WORD_COUNT;

	/* echo sequence number */
	proto_tree_add_item(tree, hf_smb_echo_seq_num, tvb, offset, 2, TRUE);
	offset += 2;

	BYTE_COUNT;

	if (bc != 0) {
		/* echo data */
		proto_tree_add_item(tree, hf_smb_echo_data, tvb, offset, bc, TRUE);
		COUNT_BYTES(bc);
	}

	END_OF_SMB

	return offset;
}

static int
dissect_tree_connect_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	int an_len, pwlen;
	const char *an;
	guint8 wc;
	guint16 bc;

	WORD_COUNT;
 
	BYTE_COUNT;

	/* buffer format */
	CHECK_BYTE_COUNT(1);
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	COUNT_BYTES(1);

	/* Path */
	an = get_unicode_or_ascii_string(tvb, &offset,
		pinfo, &an_len, FALSE, FALSE, &bc);
	if (an == NULL)
		goto endofcommand;
	proto_tree_add_string(tree, hf_smb_path, tvb,
		offset, an_len, an);
	COUNT_BYTES(an_len);

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, ", Path: %s", an);
	}

	/* buffer format */
	CHECK_BYTE_COUNT(1);
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	COUNT_BYTES(1);

	/* password, ANSI */
	/* XXX - what if this runs past bc? */
	pwlen = tvb_strsize(tvb, offset);
	CHECK_BYTE_COUNT(pwlen);
	proto_tree_add_item(tree, hf_smb_password,
		tvb, offset, pwlen, TRUE);
	COUNT_BYTES(pwlen);

	/* buffer format */
	CHECK_BYTE_COUNT(1);
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	COUNT_BYTES(1);

	/* Service */
	an = get_unicode_or_ascii_string(tvb, &offset,
		pinfo, &an_len, FALSE, FALSE, &bc);
	if (an == NULL)
		goto endofcommand;
	proto_tree_add_string(tree, hf_smb_service, tvb,
		offset, an_len, an);
	COUNT_BYTES(an_len);

	END_OF_SMB

	return offset;
}

static int
dissect_tree_connect_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;

	WORD_COUNT;
 
	/* Maximum Buffer Size */
	proto_tree_add_item(tree, hf_smb_max_buf_size, tvb, offset, 2, TRUE);
	offset += 2;

	/* tid */
	proto_tree_add_item(tree, hf_smb_tid, tvb, offset, 2, TRUE);
	offset += 2;

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}
 

static const true_false_string tfs_of_create = {
	"Create file if it does not exist",
	"Fail if file does not exist"
};
static const value_string of_open[] = {
	{ 0,		"Fail if file exists"},
	{ 1,		"Open file if it exists"},
	{ 2,		"Truncate file if it exists"},
	{0, NULL}
};
static int
dissect_open_function(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint16 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohs(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 2,
			"Open Function: 0x%04x", mask);
		tree = proto_item_add_subtree(item, ett_smb_openfunction);
	}

	proto_tree_add_boolean(tree, hf_smb_open_function_create,
		tvb, offset, 2, mask);
	proto_tree_add_uint(tree, hf_smb_open_function_open,
		tvb, offset, 2, mask);

	offset += 2;

	return offset;
}


static const true_false_string tfs_mf_file = {
	"Target must be a file",
	"Target needn't be a file"
 };
static const true_false_string tfs_mf_dir = {
	"Target must be a directory",
	"Target needn't be a directory"
};
static const true_false_string tfs_mf_verify = {
	"MUST verify all writes",
	"Don't have to verify writes"
};
static int
dissect_move_flags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint16 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohs(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 2,
			"Flags: 0x%04x", mask);
		tree = proto_item_add_subtree(item, ett_smb_move_flags);
	}
 
	proto_tree_add_boolean(tree, hf_smb_move_flags_verify,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_move_flags_dir,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_move_flags_file,
		tvb, offset, 2, mask);

	offset += 2;

	return offset;
}

static int
dissect_move_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	int fn_len;
	guint16 tid;
	guint16 bc;
	guint8 wc;
	const char *fn;

	WORD_COUNT;

	/* tid */
	tid = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint_format(tree, hf_smb_tid, tvb, offset, 2, tid,
		"TID (target): 0x%04x", tid);
	offset += 2;

	/* open function */
	offset = dissect_open_function(tvb, pinfo, tree, offset);

	/* move flags */
	offset = dissect_move_flags(tvb, pinfo, tree, offset);

	BYTE_COUNT;

	/* buffer format */
	CHECK_BYTE_COUNT(1);
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	COUNT_BYTES(1);

	/* file name */
	fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len,
		FALSE, FALSE, &bc);
	if (fn == NULL)
		goto endofcommand;
	proto_tree_add_string_format(tree, hf_smb_file_name, tvb, offset,
		fn_len,	fn, "Old File Name: %s", fn);
	COUNT_BYTES(fn_len);

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, ", Old Name: %s", fn);
	}

	/* buffer format */
	CHECK_BYTE_COUNT(1);
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	COUNT_BYTES(1);

	/* file name */
	fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len,
		FALSE, FALSE, &bc);
	if (fn == NULL)
		goto endofcommand;
	proto_tree_add_string_format(tree, hf_smb_file_name, tvb, offset,
		fn_len,	fn, "New File Name: %s", fn);
	COUNT_BYTES(fn_len);

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, ", New Name: %s", fn);
	}

	END_OF_SMB

	return offset;
}

static int
dissect_move_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	int fn_len;
	const char *fn;
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* # of files moved */
	proto_tree_add_item(tree, hf_smb_move_files_moved, tvb, offset, 2, TRUE);
	offset += 2;

	BYTE_COUNT;

	/* buffer format */
	CHECK_BYTE_COUNT(1);
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	COUNT_BYTES(1);

	/* file name */
	fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len,
		FALSE, FALSE, &bc);
	if (fn == NULL)
		goto endofcommand;
	proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
		fn);
	COUNT_BYTES(fn_len);

	END_OF_SMB

	return offset;
}

static int
dissect_open_file_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	int fn_len;
	const char *fn;
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* desired access */
	offset = dissect_access(tvb, pinfo, tree, offset, "Desired");

	/* Search Attributes */
	offset = dissect_search_attributes(tvb, pinfo, tree, offset);

	BYTE_COUNT;

	/* buffer format */
	CHECK_BYTE_COUNT(1);
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	COUNT_BYTES(1);

	/* file name */
	fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len,
		FALSE, FALSE, &bc);
	if (fn == NULL)
		goto endofcommand;
	proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
		fn);
	COUNT_BYTES(fn_len);

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, ", Path: %s", fn);
	}

	END_OF_SMB

	return offset;
}

void
add_fid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
    int len, guint16 fid)
{
	proto_tree_add_uint(tree, hf_smb_fid, tvb, offset, len, fid);
	if (check_col(pinfo->fd, COL_INFO))
		col_append_fstr(pinfo->fd, COL_INFO, ", FID: 0x%04x", fid);
}

static int
dissect_open_file_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;
	guint16 fid;

	WORD_COUNT;

	/* fid */
	fid = tvb_get_letohs(tvb, offset);
	add_fid(tvb, pinfo, tree, offset, 2, fid);
	offset += 2;

	/* File Attributes */
	offset = dissect_file_attributes(tvb, pinfo, tree, offset);

	/* last write time */
	offset = dissect_smb_UTIME(tvb, pinfo, tree, offset, hf_smb_last_write_time);
	
	/* File Size */
	proto_tree_add_item(tree, hf_smb_file_size, tvb, offset, 4, TRUE);
	offset += 4;

	/* granted access */
	offset = dissect_access(tvb, pinfo, tree, offset, "Granted");

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

static int
dissect_fid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;
	guint16 fid;

	WORD_COUNT;

	/* fid */
	fid = tvb_get_letohs(tvb, offset);
	add_fid(tvb, pinfo, tree, offset, 2, fid);
	offset += 2;

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

static int
dissect_create_file_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	int fn_len;
	const char *fn;
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* file attributes */
	offset = dissect_file_attributes(tvb, pinfo, tree, offset);

	/* creation time */
	offset = dissect_smb_UTIME(tvb, pinfo, tree, offset, hf_smb_create_time);

	BYTE_COUNT;

	/* buffer format */
	CHECK_BYTE_COUNT(1);
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	COUNT_BYTES(1);

	/* File Name */
	fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len,
		FALSE, FALSE, &bc);
	if (fn == NULL)
		goto endofcommand;
	proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
		fn);
	COUNT_BYTES(fn_len);

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, ", Path: %s", fn);
	}

	END_OF_SMB

	return offset;
}

static int
dissect_close_file_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* fid */
	proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
	offset += 2;

	/* last write time */
	offset = dissect_smb_UTIME(tvb, pinfo, tree, offset, hf_smb_last_write_time);

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

static int
dissect_delete_file_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	int fn_len;
	const char *fn;
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* search attributes */
	offset = dissect_search_attributes(tvb, pinfo, tree, offset);

	BYTE_COUNT;

	/* buffer format */
	CHECK_BYTE_COUNT(1);
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	COUNT_BYTES(1);

	/* file name */
	fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len,
		FALSE, FALSE, &bc);
	if (fn == NULL)
		goto endofcommand;
	proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
		fn);
	COUNT_BYTES(fn_len);

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, ", Path: %s", fn);
	}

	END_OF_SMB

	return offset;
}

static int
dissect_rename_file_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	int fn_len;
	const char *fn;
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* search attributes */
	offset = dissect_search_attributes(tvb, pinfo, tree, offset);

	BYTE_COUNT;

	/* buffer format */
	CHECK_BYTE_COUNT(1);
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	COUNT_BYTES(1);

	/* old file name */
	fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len,
		FALSE, FALSE, &bc);
	if (fn == NULL)
		goto endofcommand;
	proto_tree_add_string(tree, hf_smb_old_file_name, tvb, offset, fn_len,
		fn);
	COUNT_BYTES(fn_len);

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, ", Old Name: %s", fn);
	}

	/* buffer format */
	CHECK_BYTE_COUNT(1);
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	COUNT_BYTES(1);

	/* file name */
	fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len,
		FALSE, FALSE, &bc);
	if (fn == NULL)
		goto endofcommand;
	proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
		fn);
	COUNT_BYTES(fn_len);

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, ", New Name: %s", fn);
	}

	END_OF_SMB

	return offset;
}

static int
dissect_query_information_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint16 bc;
	guint8 wc;
	const char *fn;
	int fn_len;

	WORD_COUNT;

	BYTE_COUNT;

	/* Buffer Format */
	CHECK_BYTE_COUNT(1);
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	COUNT_BYTES(1);

	/* File Name */
	fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len,
		FALSE, FALSE, &bc);
	if (fn == NULL)
		goto endofcommand;
	proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
		fn);
	COUNT_BYTES(fn_len);

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, ", Path: %s", fn);
	}

	END_OF_SMB

	return offset;
}
 
static int
dissect_query_information_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint16 bc;
	guint8 wc;

	WORD_COUNT;

	/* File Attributes */
	offset = dissect_file_attributes(tvb, pinfo, tree, offset);

	/* Last Write Time */
	offset = dissect_smb_UTIME(tvb, pinfo, tree, offset, hf_smb_last_write_time);

	/* File Size */
	proto_tree_add_item(tree, hf_smb_file_size, tvb, offset, 4, TRUE);
	offset += 4;

	/* 10 reserved bytes */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 10, TRUE);
	offset += 10;

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

static int
dissect_set_information_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	int fn_len;
	const char *fn;
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* file attributes */
	offset = dissect_file_attributes(tvb, pinfo, tree, offset);

	/* last write time */
	offset = dissect_smb_UTIME(tvb, pinfo, tree, offset, hf_smb_last_write_time);

	/* 10 reserved bytes */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 10, TRUE);
	offset += 10;

	BYTE_COUNT;

	/* buffer format */
	CHECK_BYTE_COUNT(1);
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	COUNT_BYTES(1);

	/* file name */
	fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len,
		FALSE, FALSE, &bc);
	if (fn == NULL)
		goto endofcommand;
	proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
		fn);
	COUNT_BYTES(fn_len);

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, ", Path: %s", fn);
	}

	END_OF_SMB

	return offset;
}

static int
dissect_read_file_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* fid */
	proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
	offset += 2;

	/* read count */
	proto_tree_add_item(tree, hf_smb_count, tvb, offset, 2, TRUE);
	offset += 2;

	/* offset */
	proto_tree_add_item(tree, hf_smb_offset, tvb, offset, 4, TRUE);
	offset += 4;

	/* remaining */
	proto_tree_add_item(tree, hf_smb_remaining, tvb, offset, 2, TRUE);
	offset += 2;

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

int
dissect_file_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint16 bc, guint16 datalen)
{
	int tvblen;

	if(bc>datalen){
		/* We have some initial padding bytes. */
		/* XXX - use the data offset here instead? */
		proto_tree_add_item(tree, hf_smb_padding, tvb, offset, bc-datalen,
			TRUE);
		offset += bc-datalen;
		bc = datalen;
	}
	tvblen = tvb_length_remaining(tvb, offset);
	if(bc>tvblen){
		proto_tree_add_bytes_format(tree, hf_smb_file_data, tvb, offset, tvblen, tvb_get_ptr(tvb, offset, tvblen),"File Data: Incomplete. Only %d of %u bytes", tvblen, bc);
		offset += tvblen;
	} else {
		proto_tree_add_item(tree, hf_smb_file_data, tvb, offset, bc, TRUE);
		offset += bc;
	}
	return offset;
}

static int
dissect_read_file_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint16 cnt=0, bc;
	guint8 wc;

	WORD_COUNT;

	/* read count */
	cnt = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_count, tvb, offset, 2, cnt);
	offset += 2;

	/* 8 reserved bytes */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 8, TRUE);
	offset += 8;

	BYTE_COUNT;

	/* buffer format */
	CHECK_BYTE_COUNT(1);
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	COUNT_BYTES(1);

	/* data len */
	CHECK_BYTE_COUNT(2);
	proto_tree_add_item(tree, hf_smb_data_len, tvb, offset, 2, TRUE);
	COUNT_BYTES(2);

	if (bc != 0) {
		/* file data */
		offset = dissect_file_data(tvb, pinfo, tree, offset, bc, bc);
		bc = 0;
	}

	END_OF_SMB

	return offset;
}

static int
dissect_lock_and_read_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint16 cnt, bc;
	guint8 wc;

	WORD_COUNT;

	/* read count */
	cnt = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_count, tvb, offset, 2, cnt);
	offset += 2;

	/* 8 reserved bytes */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 8, TRUE);
	offset += 8;

	BYTE_COUNT;

	/* buffer format */
	CHECK_BYTE_COUNT(1);
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	COUNT_BYTES(1);

	/* data len */
	CHECK_BYTE_COUNT(2);
	proto_tree_add_item(tree, hf_smb_data_len, tvb, offset, 2, TRUE);
	COUNT_BYTES(2);

	END_OF_SMB

	return offset;
}


static int
dissect_write_file_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint16 cnt=0, bc;
	guint8 wc;

	WORD_COUNT;

	/* fid */
	proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
	offset += 2;

	/* write count */
	cnt = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_count, tvb, offset, 2, cnt);
	offset += 2;

	/* offset */
	proto_tree_add_item(tree, hf_smb_offset, tvb, offset, 4, TRUE);
	offset += 4;

	/* remaining */
	proto_tree_add_item(tree, hf_smb_remaining, tvb, offset, 2, TRUE);
	offset += 2;

	BYTE_COUNT;

	/* buffer format */
	CHECK_BYTE_COUNT(1);
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	COUNT_BYTES(1);

	/* data len */
	CHECK_BYTE_COUNT(2);
	proto_tree_add_item(tree, hf_smb_data_len, tvb, offset, 2, TRUE);
	COUNT_BYTES(2);

	if (bc != 0) {
		/* file data */
		offset = dissect_file_data(tvb, pinfo, tree, offset, bc, bc);
		bc = 0;
	}

	END_OF_SMB

	return offset;
}
 
static int
dissect_write_file_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* write count */
	proto_tree_add_item(tree, hf_smb_count, tvb, offset, 2, TRUE);
	offset += 2;

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

static int
dissect_lock_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* fid */
	proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
	offset += 2;

	/* lock count */
	proto_tree_add_item(tree, hf_smb_count, tvb, offset, 4, TRUE);
	offset += 4;

	/* offset */
	proto_tree_add_item(tree, hf_smb_offset, tvb, offset, 4, TRUE);
	offset += 4;

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

static int
dissect_create_temporary_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	int fn_len;
	const char *fn;
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* 2 reserved bytes */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 2, TRUE);
	offset += 2;

	/* Creation time */
	offset = dissect_smb_UTIME(tvb, pinfo, tree, offset, hf_smb_create_time);

	BYTE_COUNT;

	/* buffer format */
	CHECK_BYTE_COUNT(1);
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	COUNT_BYTES(1);

	/* directory name */
	fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len,
		FALSE, FALSE, &bc);
	if (fn == NULL)
		goto endofcommand;
	proto_tree_add_string(tree, hf_smb_dir_name, tvb, offset, fn_len,
		fn);
	COUNT_BYTES(fn_len);

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, ", Path: %s", fn);
	}

	END_OF_SMB

	return offset;
}

static int
dissect_create_temporary_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	int fn_len;
	const char *fn;
	guint8 wc;
	guint16 bc;
	guint16 fid;

	WORD_COUNT;

	/* fid */
	fid = tvb_get_letohs(tvb, offset);
	add_fid(tvb, pinfo, tree, offset, 2, fid);
	offset += 2;

	BYTE_COUNT;

	/* buffer format */
	CHECK_BYTE_COUNT(1);
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	COUNT_BYTES(1);

	/* file name */
	fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len,
		FALSE, FALSE, &bc);
	if (fn == NULL)
		goto endofcommand;
	proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
		fn);
	COUNT_BYTES(fn_len);

	END_OF_SMB

	return offset;
}

static const value_string seek_mode_vals[] = {
	{0,	"From Start Of File"},
	{1,	"From Current Position"},
	{2,	"From End Of File"},
	{0,	NULL}
};

static int
dissect_seek_file_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* fid */
	proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
	offset += 2;

	/* Seek Mode */
	proto_tree_add_item(tree, hf_smb_seek_mode, tvb, offset, 2, TRUE);
	offset += 2;

	/* offset */
	proto_tree_add_item(tree, hf_smb_offset, tvb, offset, 4, TRUE);
	offset += 4;

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

static int
dissect_seek_file_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* offset */
	proto_tree_add_item(tree, hf_smb_offset, tvb, offset, 4, TRUE);
	offset += 4;

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}
 
static int
dissect_set_information2_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* fid */
	proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
	offset += 2;

	/* create time */
	offset = dissect_smb_datetime(tvb, pinfo, tree, offset,
		hf_smb_create_time,
		hf_smb_create_dos_date, hf_smb_create_dos_time, FALSE);

	/* access time */
	offset = dissect_smb_datetime(tvb, pinfo, tree, offset,
		hf_smb_access_time,
		hf_smb_access_dos_date, hf_smb_access_dos_time, FALSE);

	/* last write time */
	offset = dissect_smb_datetime(tvb, pinfo, tree, offset,
		hf_smb_last_write_time,
		hf_smb_last_write_dos_date, hf_smb_last_write_dos_time, FALSE);

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

static int
dissect_query_information2_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* create time */
	offset = dissect_smb_datetime(tvb, pinfo, tree, offset,
		hf_smb_create_time,
		hf_smb_create_dos_date, hf_smb_create_dos_time, FALSE);

	/* access time */
	offset = dissect_smb_datetime(tvb, pinfo, tree, offset,
		hf_smb_access_time,
		hf_smb_access_dos_date, hf_smb_access_dos_time, FALSE);

	/* last write time */
	offset = dissect_smb_datetime(tvb, pinfo, tree, offset,
		hf_smb_last_write_time,
		hf_smb_last_write_dos_date, hf_smb_last_write_dos_time, FALSE);

	/* data size */
	proto_tree_add_item(tree, hf_smb_data_size, tvb, offset, 4, TRUE);
	offset += 4;

	/* allocation size */
	proto_tree_add_item(tree, hf_smb_alloc_size, tvb, offset, 4, TRUE);
	offset += 4;

	/* File Attributes */
	offset = dissect_file_attributes(tvb, pinfo, tree, offset);

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

static int
dissect_write_and_close_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 cnt=0;
	guint16 bc;

	WORD_COUNT;

	/* fid */
	proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
	offset += 2;

	/* write count */
	cnt = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_count, tvb, offset, 2, cnt);
	offset += 2;

	/* offset */
	proto_tree_add_item(tree, hf_smb_offset, tvb, offset, 4, TRUE);
	offset += 4;

	/* last write time */
	offset = dissect_smb_UTIME(tvb, pinfo, tree, offset, hf_smb_last_write_time);
	
	if(wc==12){
		/* 12 reserved bytes */
		proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 12, TRUE);
		offset += 12;
	}

	BYTE_COUNT;

	/* 1 pad byte */
	CHECK_BYTE_COUNT(1);
	proto_tree_add_item(tree, hf_smb_padding, tvb, offset, 1, TRUE);
	COUNT_BYTES(1);
	
	offset = dissect_file_data(tvb, pinfo, tree, offset, cnt, cnt);
	bc = 0;	/* XXX */

	END_OF_SMB

	return offset;
}
 
static int
dissect_write_and_close_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* write count */
	proto_tree_add_item(tree, hf_smb_count, tvb, offset, 2, TRUE);
	offset += 2;

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

static int
dissect_read_raw_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;
	guint32 to;

	WORD_COUNT;

	/* fid */
	proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
	offset += 2;

	/* offset */
	proto_tree_add_item(tree, hf_smb_offset, tvb, offset, 4, TRUE);
	offset += 4;

	/* max count */
	proto_tree_add_item(tree, hf_smb_max_count, tvb, offset, 2, TRUE);
	offset += 2;

	/* min count */
	proto_tree_add_item(tree, hf_smb_min_count, tvb, offset, 2, TRUE);
	offset += 2;

	/* timeout */
	to = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint_format(tree, hf_smb_timeout, tvb, offset, 4, to, "Timeout: %s", time_msecs_to_str(to));
	offset += 4;

	/* 2 reserved bytes */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 2, TRUE);
	offset += 2;

	if(wc==10){
		/* high offset */
		proto_tree_add_item(tree, hf_smb_high_offset, tvb, offset, 4, TRUE);
		offset += 4;
	}

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

static int
dissect_query_information_disk_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* units */
	proto_tree_add_item(tree, hf_smb_units, tvb, offset, 2, TRUE);
	offset += 2;

	/* bpu */
	proto_tree_add_item(tree, hf_smb_bpu, tvb, offset, 2, TRUE);
	offset += 2;

	/* block size */
	proto_tree_add_item(tree, hf_smb_blocksize, tvb, offset, 2, TRUE);
	offset += 2;

	/* free units */
	proto_tree_add_item(tree, hf_smb_freeunits, tvb, offset, 2, TRUE);
	offset += 2;

	/* 2 reserved bytes */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 2, TRUE);
	offset += 2;

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

static int
dissect_read_mpx_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* fid */
	proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
	offset += 2;

	/* offset */
	proto_tree_add_item(tree, hf_smb_offset, tvb, offset, 4, TRUE);
	offset += 4;

	/* max count */
	proto_tree_add_item(tree, hf_smb_max_count, tvb, offset, 2, TRUE);
	offset += 2;

	/* min count */
	proto_tree_add_item(tree, hf_smb_min_count, tvb, offset, 2, TRUE);
	offset += 2;

	/* 6 reserved bytes */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 6, TRUE);
	offset += 6;

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

static int
dissect_read_mpx_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint16 datalen=0, bc;
	guint8 wc;

	WORD_COUNT;

	/* offset */
	proto_tree_add_item(tree, hf_smb_offset, tvb, offset, 4, TRUE);
	offset += 4;

	/* count */
	proto_tree_add_item(tree, hf_smb_count, tvb, offset, 2, TRUE);
	offset += 2;

	/* 2 reserved bytes */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 2, TRUE);
	offset += 2;

	/* data compaction mode */
	proto_tree_add_item(tree, hf_smb_dcm, tvb, offset, 2, TRUE);
	offset += 2;

	/* 2 reserved bytes */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 2, TRUE);
	offset += 2;

	/* data len */
	datalen = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_data_len, tvb, offset, 2, datalen);
	offset += 2;

	/* data offset */
	proto_tree_add_item(tree, hf_smb_data_offset, tvb, offset, 2, TRUE);
	offset += 2;

	BYTE_COUNT;

	/* file data */
	offset = dissect_file_data(tvb, pinfo, tree, offset, bc, datalen);
	bc = 0;

	END_OF_SMB

	return offset;
}


static const true_false_string tfs_write_mode_write_through = {
	"WRITE THROUGH requested",
	"Write through not requested"
};
static const true_false_string tfs_write_mode_return_remaining = {
	"RETURN REMAINING (pipe/dev) requested",
	"DON'T return remaining (pipe/dev)"
};
static const true_false_string tfs_write_mode_raw = {
	"Use WriteRawNamedPipe (pipe)",
	"DON'T use WriteRawNamedPipe (pipe)"
};
static const true_false_string tfs_write_mode_message_start = {
	"This is the START of a MESSAGE (pipe)",
	"This is NOT the start of a message (pipe)"
};
static const true_false_string tfs_write_mode_connectionless = {
	"CONNECTIONLESS mode requested",
	"Connectionless mode NOT requested"
};
static int
dissect_write_mode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset, int bm)
{
	guint16 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohs(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 2,
			"Write Mode: 0x%04x", mask);
		tree = proto_item_add_subtree(item, ett_smb_rawmode);
	}

	if(bm&0x0080){
		proto_tree_add_boolean(tree, hf_smb_write_mode_connectionless,
			tvb, offset, 2, mask);
	}
	if(bm&0x0008){
		proto_tree_add_boolean(tree, hf_smb_write_mode_message_start,
			tvb, offset, 2, mask);
	}
	if(bm&0x0004){
		proto_tree_add_boolean(tree, hf_smb_write_mode_raw,
			tvb, offset, 2, mask);
	}
	if(bm&0x0002){
		proto_tree_add_boolean(tree, hf_smb_write_mode_return_remaining,
			tvb, offset, 2, mask);
	}
	if(bm&0x0001){
		proto_tree_add_boolean(tree, hf_smb_write_mode_write_through,
			tvb, offset, 2, mask);
	}

	offset += 2;
	return offset;
}

static int
dissect_write_raw_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint32 to;
	guint16 datalen=0, bc;
	guint8 wc;

	WORD_COUNT;

	/* fid */
	proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
	offset += 2;

	/* total data length */
	proto_tree_add_item(tree, hf_smb_total_data_len, tvb, offset, 2, TRUE);
	offset += 2;

	/* 2 reserved bytes */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 2, TRUE);
	offset += 2;

	/* offset */
	proto_tree_add_item(tree, hf_smb_offset, tvb, offset, 4, TRUE);
	offset += 4;

	/* timeout */
	to = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint_format(tree, hf_smb_timeout, tvb, offset, 4, to, "Timeout: %s", time_msecs_to_str(to));
	offset += 4;

	/* mode */
	offset = dissect_write_mode(tvb, pinfo, tree, offset, 0x0003);

	/* 4 reserved bytes */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 4, TRUE);
	offset += 4;

	/* data len */
	datalen = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_data_len, tvb, offset, 2, datalen);
	offset += 2;

	/* data offset */
	proto_tree_add_item(tree, hf_smb_data_offset, tvb, offset, 2, TRUE);
	offset += 2;

	BYTE_COUNT;

	/* file data */
	/* XXX - use the data offset to determine where the data starts? */
	offset = dissect_file_data(tvb, pinfo, tree, offset, bc, datalen);
	bc = 0;

	END_OF_SMB

	return offset;
}
 
static int
dissect_write_raw_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* remaining */
	proto_tree_add_item(tree, hf_smb_remaining, tvb, offset, 2, TRUE);
	offset += 2;

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

static int
dissect_write_mpx_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint32 to;
	guint16 datalen=0, bc;
	guint8 wc;

	WORD_COUNT;

	/* fid */
	proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
	offset += 2;

	/* total data length */
	proto_tree_add_item(tree, hf_smb_total_data_len, tvb, offset, 2, TRUE);
	offset += 2;

	/* 2 reserved bytes */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 2, TRUE);
	offset += 2;

	/* offset */
	proto_tree_add_item(tree, hf_smb_offset, tvb, offset, 4, TRUE);
	offset += 4;

	/* timeout */
	to = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint_format(tree, hf_smb_timeout, tvb, offset, 4, to, "Timeout: %s", time_msecs_to_str(to));
	offset += 4;

	/* mode */
	offset = dissect_write_mode(tvb, pinfo, tree, offset, 0x0083);

	/* request mask */
	proto_tree_add_item(tree, hf_smb_request_mask, tvb, offset, 4, TRUE);
	offset += 4;
	
	/* data len */
	datalen = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_data_len, tvb, offset, 2, datalen);
	offset += 2;

	/* data offset */
	proto_tree_add_item(tree, hf_smb_data_offset, tvb, offset, 2, TRUE);
	offset += 2;

	BYTE_COUNT;

	/* file data */
	/* XXX - use the data offset to determine where the data starts? */
	offset = dissect_file_data(tvb, pinfo, tree, offset, bc, datalen);
	bc = 0;

	END_OF_SMB

	return offset;
}
 
static int
dissect_write_mpx_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* response mask */
	proto_tree_add_item(tree, hf_smb_response_mask, tvb, offset, 4, TRUE);
	offset += 4;
	
	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

static int
dissect_sid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* sid */
	proto_tree_add_item(tree, hf_smb_sid, tvb, offset, 2, TRUE);
	offset += 2;

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

static int
dissect_search_resume_key(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *parent_tree, int offset, guint16 *bcp, gboolean *trunc)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int fn_len;
	const char *fn;
	char fname[11+1];

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 21,
			"Resume Key");
		tree = proto_item_add_subtree(item, ett_smb_search_resume_key);
	}

	/* reserved byte */
	CHECK_BYTE_COUNT_SUBR(1);
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 1, TRUE);
	COUNT_BYTES_SUBR(1);

	/* file name */
	fn_len = 11;
	fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len,
		TRUE, TRUE, bcp);
	CHECK_STRING_SUBR(fn);
	/* ensure that it's null-terminated */
	strncpy(fname, fn, 11);
	fname[11] = '\0';
	proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, 11,
		fname);
	COUNT_BYTES_SUBR(fn_len);

	/* server cookie */
	CHECK_BYTE_COUNT_SUBR(5);
	proto_tree_add_item(tree, hf_smb_resume_server_cookie, tvb, offset, 5, TRUE);
	COUNT_BYTES_SUBR(5);

	/* client cookie */
	CHECK_BYTE_COUNT_SUBR(4);
	proto_tree_add_item(tree, hf_smb_resume_client_cookie, tvb, offset, 4, TRUE);
	COUNT_BYTES_SUBR(4);

	*trunc = FALSE;
	return offset;
}

static int
dissect_search_dir_info(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *parent_tree, int offset, guint16 *bcp, gboolean *trunc)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int fn_len;
	const char *fn;
	char fname[13+1];

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 46,
			"Directory Information");
		tree = proto_item_add_subtree(item, ett_smb_search_dir_info);
	}

	/* resume key */
	offset = dissect_search_resume_key(tvb, pinfo, tree, offset, bcp, trunc);
	if (*trunc)
		return offset;

	/* File Attributes */
	CHECK_BYTE_COUNT_SUBR(1);
	offset = dissect_dir_info_file_attributes(tvb, pinfo, tree, offset);
	*bcp -= 1;

	/* last write time */
	CHECK_BYTE_COUNT_SUBR(4);
	offset = dissect_smb_datetime(tvb, pinfo, tree, offset,
		hf_smb_last_write_time,
		hf_smb_last_write_dos_date, hf_smb_last_write_dos_time,
		TRUE);
	*bcp -= 4;

	/* File Size */
	CHECK_BYTE_COUNT_SUBR(4);
	proto_tree_add_item(tree, hf_smb_file_size, tvb, offset, 4, TRUE);
	COUNT_BYTES_SUBR(4);

	/* file name */
	fn_len = 13;
	fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len,
		TRUE, TRUE, bcp);
	CHECK_STRING_SUBR(fn);
	/* ensure that it's null-terminated */
	strncpy(fname, fn, 13);
	fname[13] = '\0';
	proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
		fname);
	COUNT_BYTES_SUBR(fn_len);

	*trunc = FALSE;
	return offset;
}


static int
dissect_search_dir_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	int fn_len;
	const char *fn;
	guint16 rkl;
	guint8 wc;
	guint16 bc;
	gboolean trunc;

	WORD_COUNT;

	/* max count */
	proto_tree_add_item(tree, hf_smb_max_count, tvb, offset, 2, TRUE);
	offset += 2;

	/* Search Attributes */
	offset = dissect_search_attributes(tvb, pinfo, tree, offset);

	BYTE_COUNT;

	/* buffer format */
	CHECK_BYTE_COUNT(1);
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	COUNT_BYTES(1);

	/* file name */
	fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len,
		TRUE, FALSE, &bc);
	if (fn == NULL)
		goto endofcommand;
	proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
		fn);
	COUNT_BYTES(fn_len);

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, ", File: %s", fn);
	}

	/* buffer format */
	CHECK_BYTE_COUNT(1);
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	COUNT_BYTES(1);

	/* resume key length */
	CHECK_BYTE_COUNT(2);
	rkl = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_resume_key_len, tvb, offset, 2, rkl);
	COUNT_BYTES(2);

	/* resume key */
	if(rkl){
		offset = dissect_search_resume_key(tvb, pinfo, tree, offset,
		    &bc, &trunc);
		if (trunc)
			goto endofcommand;
	}

	END_OF_SMB

	return offset;
}

static int
dissect_search_dir_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint16 count=0;
	guint8 wc;
	guint16 bc;
	gboolean trunc;

	WORD_COUNT;

	/* count */
	count = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_count, tvb, offset, 2, count);
	offset += 2;

	BYTE_COUNT;

	/* buffer format */
	CHECK_BYTE_COUNT(1);
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	COUNT_BYTES(1);

	/* data len */
	CHECK_BYTE_COUNT(2);
	proto_tree_add_item(tree, hf_smb_data_len, tvb, offset, 2, TRUE);
	COUNT_BYTES(2);

	while(count--){
		offset = dissect_search_dir_info(tvb, pinfo, tree, offset,
		    &bc, &trunc);
		if (trunc)
			goto endofcommand;
	}

	END_OF_SMB

	return offset;
}

static const value_string locking_ol_vals[] = {
	{0,	"Client is not holding oplock on this file"},
	{1,	"Level 2 oplock currently held by client"},
	{0, NULL}
};

static const true_false_string tfs_lock_type_large = {
	"Large file locking format requested",
	"Large file locking format not requested"
};
static const true_false_string tfs_lock_type_cancel = {
	"Cancel outstanding lock request",
	"Don't cancel outstanding lock request"
};
static const true_false_string tfs_lock_type_change = {
	"Change lock type",
	"Don't change lock type"
};
static const true_false_string tfs_lock_type_oplock = {
	"This is an oplock break notification/response",
	"This is not an oplock break notification/response"
};
static const true_false_string tfs_lock_type_shared = {
	"This is a shared lock",
	"This is an exclusive lock"
};
static int
dissect_locking_andx_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8	wc, cmd=0xff, lt=0;
	guint16 andxoffset=0, un=0, ln=0, bc;
	guint32 to;
	proto_item *litem = NULL;
	proto_tree *ltree = NULL;
	proto_item *it = NULL;
	proto_tree *tr = NULL;
	int old_offset = offset;

	WORD_COUNT;

	/* next smb command */
	cmd = tvb_get_guint8(tvb, offset);
	if(cmd!=0xff){
		proto_tree_add_uint_format(tree, hf_smb_cmd, tvb, offset, 1, cmd, "AndXCommand: %s (0x%02x)", decode_smb_name(cmd), cmd);
	} else {
		proto_tree_add_uint_format(tree, hf_smb_cmd, tvb, offset, 1, cmd, "AndXCommand: No further commands (0xff)");
	}
	offset += 1;

	/* reserved byte */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 1, TRUE);
	offset += 1;

	/* andxoffset */
	andxoffset = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_andxoffset, tvb, offset, 2, andxoffset);
	offset += 2;

	/* fid */
	proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
	offset += 2;

	/* lock type */
	lt = tvb_get_guint8(tvb, offset);
	if(tree){
		litem = proto_tree_add_text(tree, tvb, offset, 1,
			"Lock Type: 0x%02x", lt);
		ltree = proto_item_add_subtree(litem, ett_smb_lock_type);
	}
	proto_tree_add_boolean(ltree, hf_smb_lock_type_large,
		tvb, offset, 1, lt);
	proto_tree_add_boolean(ltree, hf_smb_lock_type_cancel,
		tvb, offset, 1, lt);
	proto_tree_add_boolean(ltree, hf_smb_lock_type_change,
		tvb, offset, 1, lt);
	proto_tree_add_boolean(ltree, hf_smb_lock_type_oplock,
		tvb, offset, 1, lt);
	proto_tree_add_boolean(ltree, hf_smb_lock_type_shared,
		tvb, offset, 1, lt);
	offset += 1;

	/* oplock level */
	proto_tree_add_item(tree, hf_smb_locking_ol, tvb, offset, 1, TRUE);
	offset += 1;

	/* timeout */
	to = tvb_get_letohl(tvb, offset);
	if (to == 0)
		proto_tree_add_uint_format(tree, hf_smb_timeout, tvb, offset, 4, to, "Timeout: Return immediately (0)");
	else if (to == 0xffffffff)
		proto_tree_add_uint_format(tree, hf_smb_timeout, tvb, offset, 4, to, "Timeout: Wait indefinitely (-1)");
	else
		proto_tree_add_uint_format(tree, hf_smb_timeout, tvb, offset, 4, to, "Timeout: %s", time_msecs_to_str(to));
	offset += 4;

	/* number of unlocks */
	un = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_number_of_unlocks, tvb, offset, 2, un);
	offset += 2;

	/* number of locks */
	ln = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_number_of_locks, tvb, offset, 2, ln);
	offset += 2;

	BYTE_COUNT;

	/* unlocks */
	if(un){
		old_offset = offset;

		it = proto_tree_add_text(tree, tvb, offset, 0,
			"Unlocks");
		tr = proto_item_add_subtree(it, ett_smb_unlocks);
		while(un--){
			proto_item *litem = NULL;
			proto_tree *ltree = NULL;
			if(lt&0x10){
				/* large lock format */
				litem = proto_tree_add_text(tr, tvb, offset, 20,
					"Unlock");
				ltree = proto_item_add_subtree(litem, ett_smb_unlock);
				
				/* PID */
				CHECK_BYTE_COUNT(2);
				proto_tree_add_item(ltree, hf_smb_pid, tvb, offset, 2, TRUE);
				COUNT_BYTES(2);

				/* 2 reserved bytes */
				CHECK_BYTE_COUNT(2);
				proto_tree_add_item(ltree, hf_smb_reserved, tvb, offset, 2, TRUE);
				COUNT_BYTES(2);

				/* offset */
				CHECK_BYTE_COUNT(8);
				proto_tree_add_item(ltree, hf_smb_lock_long_offset, tvb, offset, 8, TRUE);
				COUNT_BYTES(8);

				/* length */
				CHECK_BYTE_COUNT(8);
				proto_tree_add_item(ltree, hf_smb_lock_long_length, tvb, offset, 8, TRUE);
				COUNT_BYTES(8);
			} else {
				/* normal lock format */
				litem = proto_tree_add_text(tr, tvb, offset, 10,
					"Unlock");
				ltree = proto_item_add_subtree(litem, ett_smb_unlock);
				
				/* PID */
				CHECK_BYTE_COUNT(2);
				proto_tree_add_item(ltree, hf_smb_pid, tvb, offset, 2, TRUE);
				COUNT_BYTES(2);

				/* offset */
				CHECK_BYTE_COUNT(4);
				proto_tree_add_item(ltree, hf_smb_offset, tvb, offset, 4, TRUE);
				COUNT_BYTES(4);

				/* lock count */
				CHECK_BYTE_COUNT(4);
				proto_tree_add_item(ltree, hf_smb_count, tvb, offset, 4, TRUE);
				COUNT_BYTES(4);
			}
		}
		proto_item_set_len(it, offset-old_offset);
		it = NULL;
	}

	/* locks */
	if(ln){
		old_offset = offset;

		it = proto_tree_add_text(tree, tvb, offset, 0,
			"Locks");
		tr = proto_item_add_subtree(it, ett_smb_locks);
		while(ln--){
			proto_item *litem = NULL;
			proto_tree *ltree = NULL;
			if(lt&0x10){
				/* large lock format */
				litem = proto_tree_add_text(tr, tvb, offset, 20,
					"Lock");
				ltree = proto_item_add_subtree(litem, ett_smb_lock);
				
				/* PID */
				CHECK_BYTE_COUNT(2);
				proto_tree_add_item(ltree, hf_smb_pid, tvb, offset, 2, TRUE);
				COUNT_BYTES(2);

				/* 2 reserved bytes */
				CHECK_BYTE_COUNT(2);
				proto_tree_add_item(ltree, hf_smb_reserved, tvb, offset, 2, TRUE);
				COUNT_BYTES(2);

				/* offset */
				CHECK_BYTE_COUNT(8);
				proto_tree_add_item(ltree, hf_smb_lock_long_offset, tvb, offset, 8, TRUE);
				COUNT_BYTES(8);

				/* length */
				CHECK_BYTE_COUNT(8);
				proto_tree_add_item(ltree, hf_smb_lock_long_length, tvb, offset, 8, TRUE);
				COUNT_BYTES(8);
			} else {
				/* normal lock format */
				litem = proto_tree_add_text(tr, tvb, offset, 10,
					"Unlock");
				ltree = proto_item_add_subtree(litem, ett_smb_unlock);
				
				/* PID */
				CHECK_BYTE_COUNT(2);
				proto_tree_add_item(ltree, hf_smb_pid, tvb, offset, 2, TRUE);
				COUNT_BYTES(2);

				/* offset */
				CHECK_BYTE_COUNT(4);
				proto_tree_add_item(ltree, hf_smb_offset, tvb, offset, 4, TRUE);
				COUNT_BYTES(4);

				/* lock count */
				CHECK_BYTE_COUNT(4);
				proto_tree_add_item(ltree, hf_smb_count, tvb, offset, 4, TRUE);
				COUNT_BYTES(4);
			}
		}
		proto_item_set_len(it, offset-old_offset);
		it = NULL;
	}

	END_OF_SMB

	if (it != NULL) {
		/*
		 * We ran out of byte count in the middle of dissecting
		 * the locks or the unlocks; set the site of the item
		 * we were dissecting.
		 */
		proto_item_set_len(it, offset-old_offset);
	}

	/* call AndXCommand (if there are any) */
	dissect_smb_command(tvb, pinfo, tree, andxoffset, smb_tree, cmd);

	return offset;
}

static int
dissect_locking_andx_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8	wc, cmd=0xff;
	guint16 andxoffset=0;
	guint16 bc;

	WORD_COUNT;

	/* next smb command */
	cmd = tvb_get_guint8(tvb, offset);
	if(cmd!=0xff){
		proto_tree_add_uint_format(tree, hf_smb_cmd, tvb, offset, 1, cmd, "AndXCommand: %s (0x%02x)", decode_smb_name(cmd), cmd);
	} else {
		proto_tree_add_uint_format(tree, hf_smb_cmd, tvb, offset, 1, cmd, "AndXCommand: No further commands (0xff)");
	}
	offset += 1;

	/* reserved byte */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 1, TRUE);
	offset += 1;

	/* andxoffset */
	andxoffset = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_andxoffset, tvb, offset, 2, andxoffset);
	offset += 2;

	BYTE_COUNT;

	END_OF_SMB

	/* call AndXCommand (if there are any) */
	dissect_smb_command(tvb, pinfo, tree, andxoffset, smb_tree, cmd);

	return offset;
}


static const value_string oa_open_vals[] = {
	{ 0,		"No action taken?"},
	{ 1,		"The file existed and was opened"},
	{ 2,		"The file did not exist but was created"},
	{ 3,		"The file existed and was truncated"},
	{0,	NULL}
};
static const true_false_string tfs_oa_lock = {
	"File is currently opened only by this user",
	"File is opened by another user (or mode not supported by server)"
};
static int
dissect_open_action(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint16 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohs(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 2,
			"Action: 0x%04x", mask);
		tree = proto_item_add_subtree(item, ett_smb_open_action);
	}

	proto_tree_add_boolean(tree, hf_smb_open_action_lock,
		tvb, offset, 2, mask);
	proto_tree_add_uint(tree, hf_smb_open_action_open,
		tvb, offset, 2, mask);

	offset += 2;

	return offset;
}

static const true_false_string tfs_open_flags_add_info = {
	"Additional information requested",
	"Additional information not requested"
};
static const true_false_string tfs_open_flags_ex_oplock = {
	"Exclusive oplock requested",
	"Exclusive oplock not requested"
};
static const true_false_string tfs_open_flags_batch_oplock = {
	"Batch oplock requested",
	"Batch oplock not requested"
};
static const true_false_string tfs_open_flags_ealen = {
	"Total length of EAs requested",
	"Total length of EAs not requested"
};
static int
dissect_open_flags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset, int bm)
{
	guint16 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohs(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 2,
			"Flags: 0x%04x", mask);
		tree = proto_item_add_subtree(item, ett_smb_open_flags);
	}

	if(bm&0x0001){
		proto_tree_add_boolean(tree, hf_smb_open_flags_add_info,
			tvb, offset, 2, mask);
	}
	if(bm&0x0002){
		proto_tree_add_boolean(tree, hf_smb_open_flags_ex_oplock,
			tvb, offset, 2, mask);
	}
	if(bm&0x0004){
		proto_tree_add_boolean(tree, hf_smb_open_flags_batch_oplock,
			tvb, offset, 2, mask);
	}
	if(bm&0x0008){
		proto_tree_add_boolean(tree, hf_smb_open_flags_ealen,
			tvb, offset, 2, mask);
	}

	offset += 2;

	return offset;
}

static const value_string filetype_vals[] = {
	{ 0,		"Disk file or directory"},
	{ 1,		"Named pipe in byte mode"},
	{ 2,		"Named pipe in message mode"},
	{ 3,		"Spooled printer"},
	{0, NULL}
};
static int
dissect_open_andx_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8	wc, cmd=0xff;
	guint16 andxoffset=0, bc;
	int fn_len;
	const char *fn;

	WORD_COUNT;

	/* next smb command */
	cmd = tvb_get_guint8(tvb, offset);
	if(cmd!=0xff){
		proto_tree_add_uint_format(tree, hf_smb_cmd, tvb, offset, 1, cmd, "AndXCommand: %s (0x%02x)", decode_smb_name(cmd), cmd);
	} else {
		proto_tree_add_uint_format(tree, hf_smb_cmd, tvb, offset, 1, cmd, "AndXCommand: No further commands (0xff)");
	}
	offset += 1;

	/* reserved byte */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 1, TRUE);
	offset += 1;

	/* andxoffset */
	andxoffset = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_andxoffset, tvb, offset, 2, andxoffset);
	offset += 2;

	/* open flags */
	offset = dissect_open_flags(tvb, pinfo, tree, offset, 0x0007);

	/* desired access */
	offset = dissect_access(tvb, pinfo, tree, offset, "Desired");

	/* Search Attributes */
	offset = dissect_search_attributes(tvb, pinfo, tree, offset);

	/* File Attributes */
	offset = dissect_file_attributes(tvb, pinfo, tree, offset);

	/* creation time */
	offset = dissect_smb_UTIME(tvb, pinfo, tree, offset, hf_smb_create_time);
	
	/* open function */
	offset = dissect_open_function(tvb, pinfo, tree, offset);

	/* allocation size */
	proto_tree_add_item(tree, hf_smb_alloc_size, tvb, offset, 4, TRUE);
	offset += 4;

	/* 8 reserved bytes */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 8, TRUE);
	offset += 8;

	BYTE_COUNT;

	/* file name */
	fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len,
		FALSE, FALSE, &bc);
	if (fn == NULL)
		goto endofcommand;
	proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
		fn);
	COUNT_BYTES(fn_len);

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, ", Path: %s", fn);
	}

	END_OF_SMB

	/* call AndXCommand (if there are any) */
	dissect_smb_command(tvb, pinfo, tree, andxoffset, smb_tree, cmd);

	return offset;
}

static const true_false_string tfs_ipc_state_nonblocking = {
	"Reads/writes return immediately if no data available",
	"Reads/writes block if no data available"
};
static const value_string ipc_state_endpoint_vals[] = {
	{ 0,		"Consumer end of pipe"},
	{ 1,		"Server end of pipe"},
	{0,	NULL}
};
static const value_string ipc_state_pipe_type_vals[] = {
	{ 0,		"Byte stream pipe"},
	{ 1,		"Message pipe"},
	{0,	NULL}
};
static const value_string ipc_state_read_mode_vals[] = {
	{ 0,		"Read pipe as a byte stream"},
	{ 1,		"Read messages from pipe"},
	{0,	NULL}
};

int
dissect_ipc_state(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
    int offset, gboolean setstate)
{
	guint16 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohs(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 2,
			"IPC State: 0x%04x", mask);
		tree = proto_item_add_subtree(item, ett_smb_ipc_state);
	}

	proto_tree_add_boolean(tree, hf_smb_ipc_state_nonblocking,
		tvb, offset, 2, mask);
	if (!setstate) {
		proto_tree_add_uint(tree, hf_smb_ipc_state_endpoint,
			tvb, offset, 2, mask);
		proto_tree_add_uint(tree, hf_smb_ipc_state_pipe_type,
			tvb, offset, 2, mask);
	}
	proto_tree_add_uint(tree, hf_smb_ipc_state_read_mode,
		tvb, offset, 2, mask);
	if (!setstate) {
		proto_tree_add_uint(tree, hf_smb_ipc_state_icount,
			tvb, offset, 2, mask);
	}

	offset += 2;

	return offset;
}

static int
dissect_open_andx_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8	wc, cmd=0xff;
	guint16 andxoffset=0, bc;
	guint16 fid;

	WORD_COUNT;

	/* next smb command */
	cmd = tvb_get_guint8(tvb, offset);
	if(cmd!=0xff){
		proto_tree_add_uint_format(tree, hf_smb_cmd, tvb, offset, 1, cmd, "AndXCommand: %s (0x%02x)", decode_smb_name(cmd), cmd);
	} else {
		proto_tree_add_uint_format(tree, hf_smb_cmd, tvb, offset, 1, cmd, "AndXCommand: No further commands (0xff)");
	}
	offset += 1;

	/* reserved byte */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 1, TRUE);
	offset += 1;

	/* andxoffset */
	andxoffset = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_andxoffset, tvb, offset, 2, andxoffset);
	offset += 2;

	/* fid */
	fid = tvb_get_letohs(tvb, offset);
	add_fid(tvb, pinfo, tree, offset, 2, fid);
	offset += 2;

	/* File Attributes */
	offset = dissect_file_attributes(tvb, pinfo, tree, offset);

	/* last write time */
	offset = dissect_smb_UTIME(tvb, pinfo, tree, offset, hf_smb_last_write_time);
	
	/* File Size */
	proto_tree_add_item(tree, hf_smb_file_size, tvb, offset, 4, TRUE);
	offset += 4;

	/* granted access */
	offset = dissect_access(tvb, pinfo, tree, offset, "Granted");

	/* File Type */
	proto_tree_add_item(tree, hf_smb_file_type, tvb, offset, 2, TRUE);
	offset += 2;

	/* IPC State */
	offset = dissect_ipc_state(tvb, pinfo, tree, offset, FALSE);

	/* open_action */
	offset = dissect_open_action(tvb, pinfo, tree, offset);

	/* server fid */
	proto_tree_add_item(tree, hf_smb_server_fid, tvb, offset, 4, TRUE);
	offset += 4;

	/* 2 reserved bytes */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 2, TRUE);
	offset += 2;

	BYTE_COUNT;

	END_OF_SMB

	/* call AndXCommand (if there are any) */
	dissect_smb_command(tvb, pinfo, tree, andxoffset, smb_tree, cmd);

	return offset;
}

static int
dissect_read_andx_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8	wc, cmd=0xff;
	guint16 andxoffset=0, bc;
	smb_info_t *si;
	unsigned int fid;

	WORD_COUNT;

	/* next smb command */
	cmd = tvb_get_guint8(tvb, offset);
	if(cmd!=0xff){
		proto_tree_add_uint_format(tree, hf_smb_cmd, tvb, offset, 1, cmd, "AndXCommand: %s (0x%02x)", decode_smb_name(cmd), cmd);
	} else {
		proto_tree_add_uint_format(tree, hf_smb_cmd, tvb, offset, 1, cmd, "AndXCommand: No further commands (0xff)");
	}
	offset += 1;

	/* reserved byte */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 1, TRUE);
	offset += 1;

	/* andxoffset */
	andxoffset = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_andxoffset, tvb, offset, 2, andxoffset);
	offset += 2;

	/* fid */
	fid = tvb_get_letohs(tvb, offset);
	add_fid(tvb, pinfo, tree, offset, 2, fid);
	offset += 2;
	if (!pinfo->fd->flags.visited) {
		/* remember the FID for the processing of the response */
		si = (smb_info_t *)pinfo->private_data;
		si->sip->extra_info=(void *)fid;
	}

	/* offset */
	proto_tree_add_item(tree, hf_smb_offset, tvb, offset, 4, TRUE);
	offset += 4;

	/* max count */
	proto_tree_add_item(tree, hf_smb_max_count, tvb, offset, 2, TRUE);
	offset += 2;

	/* min count */
	proto_tree_add_item(tree, hf_smb_min_count, tvb, offset, 2, TRUE);
	offset += 2;

	/* XXX - max count high */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 4, TRUE);
	offset += 4;

	/* remaining */
	proto_tree_add_item(tree, hf_smb_remaining, tvb, offset, 2, TRUE);
	offset += 2;

	if(wc==12){
		/* high offset */
		proto_tree_add_item(tree, hf_smb_high_offset, tvb, offset, 4, TRUE);
		offset += 4;
	}

	BYTE_COUNT;

	END_OF_SMB

	/* call AndXCommand (if there are any) */
	dissect_smb_command(tvb, pinfo, tree, andxoffset, smb_tree, cmd);

	return offset;
}

static int
dissect_read_andx_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8	wc, cmd=0xff;
	guint16 andxoffset=0, bc, datalen=0;
	smb_info_t *si;

	WORD_COUNT;

	/* next smb command */
	cmd = tvb_get_guint8(tvb, offset);
	if(cmd!=0xff){
		proto_tree_add_uint_format(tree, hf_smb_cmd, tvb, offset, 1, cmd, "AndXCommand: %s (0x%02x)", decode_smb_name(cmd), cmd);
	} else {
		proto_tree_add_uint_format(tree, hf_smb_cmd, tvb, offset, 1, cmd, "AndXCommand: No further commands (0xff)");
	}
	offset += 1;
 
	/* reserved byte */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 1, TRUE);
	offset += 1;

	/* andxoffset */
	andxoffset = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_andxoffset, tvb, offset, 2, andxoffset);
	offset += 2;

	/* If we have seen the request, then print which FID this refers to */
	si = (smb_info_t *)pinfo->private_data;
	/* first check if we have seen the request */
	if(si->sip != NULL && si->sip->frame_req>0){
		add_fid(tvb, pinfo, tree, 0, 0, (int)si->sip->extra_info);
	}

	/* remaining */
	proto_tree_add_item(tree, hf_smb_remaining, tvb, offset, 2, TRUE);
	offset += 2;

	/* data compaction mode */
	proto_tree_add_item(tree, hf_smb_dcm, tvb, offset, 2, TRUE);
	offset += 2;

	/* 2 reserved bytes */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 2, TRUE);
	offset += 2;

	/* data len */
	datalen = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_data_len, tvb, offset, 2, datalen);
	offset += 2;

	/* data offset */
	proto_tree_add_item(tree, hf_smb_data_offset, tvb, offset, 2, TRUE);
	offset += 2;

	/* 10 reserved bytes */
	/* XXX - first 2 bytes are data length high, not reserved */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 10, TRUE);
	offset += 10;

	BYTE_COUNT;

	/* file data */
	offset = dissect_file_data(tvb, pinfo, tree, offset, bc, datalen);
	bc = 0;

	END_OF_SMB

	/* call AndXCommand (if there are any) */
	dissect_smb_command(tvb, pinfo, tree, andxoffset, smb_tree, cmd);

	return offset;
}

static int
dissect_write_andx_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8	wc, cmd=0xff;
	guint16 andxoffset=0, bc, datalen=0;
	smb_info_t *si;
	unsigned int fid;

	WORD_COUNT;

	/* next smb command */
	cmd = tvb_get_guint8(tvb, offset);
	if(cmd!=0xff){
		proto_tree_add_uint_format(tree, hf_smb_cmd, tvb, offset, 1, cmd, "AndXCommand: %s (0x%02x)", decode_smb_name(cmd), cmd);
	} else {
		proto_tree_add_uint_format(tree, hf_smb_cmd, tvb, offset, 1, cmd, "AndXCommand: No further commands (0xff)");
	}
	offset += 1;

	/* reserved byte */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 1, TRUE);
	offset += 1;

	/* andxoffset */
	andxoffset = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_andxoffset, tvb, offset, 2, andxoffset);
	offset += 2;

	/* fid */
	fid = tvb_get_letohs(tvb, offset);
	add_fid(tvb, pinfo, tree, offset, 2, fid);
	offset += 2;
	if (!pinfo->fd->flags.visited) {
		/* remember the FID for the processing of the response */
		si = (smb_info_t *)pinfo->private_data;
		si->sip->extra_info=(void *)fid;
	}

	/* offset */
	proto_tree_add_item(tree, hf_smb_offset, tvb, offset, 4, TRUE);
	offset += 4;

	/* reserved */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 4, TRUE);
	offset += 4;

	/* mode */
	offset = dissect_write_mode(tvb, pinfo, tree, offset, 0x000f);

	/* remaining */
	proto_tree_add_item(tree, hf_smb_remaining, tvb, offset, 2, TRUE);
	offset += 2;

	/* XXX - data length high */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 2, TRUE);
	offset += 2;

	/* data len */
	datalen = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_data_len, tvb, offset, 2, datalen);
	offset += 2;

	/* data offset */
	proto_tree_add_item(tree, hf_smb_data_offset, tvb, offset, 2, TRUE);
	offset += 2;

	if(wc==14){
		/* high offset */
		proto_tree_add_item(tree, hf_smb_high_offset, tvb, offset, 4, TRUE);
		offset += 4;
	}

	BYTE_COUNT;

	/* file data */
	offset = dissect_file_data(tvb, pinfo, tree, offset, bc, datalen);
	bc = 0;

	END_OF_SMB

	/* call AndXCommand (if there are any) */
	dissect_smb_command(tvb, pinfo, tree, andxoffset, smb_tree, cmd);

	return offset;
}

static int
dissect_write_andx_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8	wc, cmd=0xff;
	guint16 andxoffset=0, bc;
	smb_info_t *si;

	WORD_COUNT;

	/* next smb command */
	cmd = tvb_get_guint8(tvb, offset);
	if(cmd!=0xff){
		proto_tree_add_uint_format(tree, hf_smb_cmd, tvb, offset, 1, cmd, "AndXCommand: %s (0x%02x)", decode_smb_name(cmd), cmd);
	} else {
		proto_tree_add_uint_format(tree, hf_smb_cmd, tvb, offset, 1, cmd, "AndXCommand: No further commands (0xff)");
	}
	offset += 1;
 
	/* reserved byte */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 1, TRUE);
	offset += 1;

	/* andxoffset */
	andxoffset = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_andxoffset, tvb, offset, 2, andxoffset);
	offset += 2;

	/* If we have seen the request, then print which FID this refers to */
	si = (smb_info_t *)pinfo->private_data;
	/* first check if we have seen the request */
	if(si->sip != NULL && si->sip->frame_req>0){
		add_fid(tvb, pinfo, tree, 0, 0, (int)si->sip->extra_info);
	}

	/* write count */
	proto_tree_add_item(tree, hf_smb_count, tvb, offset, 2, TRUE);
	offset += 2;

	/* remaining */
	proto_tree_add_item(tree, hf_smb_remaining, tvb, offset, 2, TRUE);
	offset += 2;

	/* 4 reserved bytes */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 4, TRUE);
	offset += 4;

	BYTE_COUNT;

	END_OF_SMB

	/* call AndXCommand (if there are any) */
	dissect_smb_command(tvb, pinfo, tree, andxoffset, smb_tree, cmd);

	return offset;
}


static const true_false_string tfs_setup_action_guest = {
	"Logged in as GUEST",
	"Not logged in as GUEST"
};
static int
dissect_setup_action(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint16 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohs(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 2,
			"Action: 0x%04x", mask);
		tree = proto_item_add_subtree(item, ett_smb_setup_action);
	}

	proto_tree_add_boolean(tree, hf_smb_setup_action_guest,
		tvb, offset, 2, mask);

	offset += 2;

	return offset;
}
 

static int
dissect_session_setup_andx_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8	wc, cmd=0xff;
	guint16 bc;
	guint16 andxoffset=0;
	int an_len;
	const char *an;
	int dn_len;
	const char *dn;
	guint16 pwlen=0;
	guint16 sbloblen=0;
	guint16 apwlen=0, upwlen=0;

	WORD_COUNT;

	/* next smb command */
	cmd = tvb_get_guint8(tvb, offset);
	if(cmd!=0xff){
		proto_tree_add_uint_format(tree, hf_smb_cmd, tvb, offset, 1, cmd, "AndXCommand: %s (0x%02x)", decode_smb_name(cmd), cmd);
	} else {
		proto_tree_add_uint_format(tree, hf_smb_cmd, tvb, offset, 1, cmd, "AndXCommand: No further commands (0xff)");
	}
	offset += 1;

	/* reserved byte */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 1, TRUE);
	offset += 1;

	/* andxoffset */
	andxoffset = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_andxoffset, tvb, offset, 2, andxoffset);
	offset += 2;

	/* Maximum Buffer Size */
	proto_tree_add_item(tree, hf_smb_max_buf_size, tvb, offset, 2, TRUE);
	offset += 2;

	/* Maximum Multiplex Count */
	proto_tree_add_item(tree, hf_smb_max_mpx_count, tvb, offset, 2, TRUE);
	offset += 2;

	/* VC Number */
	proto_tree_add_item(tree, hf_smb_vc_num, tvb, offset, 2, TRUE);
	offset += 2;

	/* session key */
	proto_tree_add_item(tree, hf_smb_session_key, tvb, offset, 4, TRUE);
	offset += 4;

	switch (wc) {
	case 10:
		/* password length, ASCII*/
		pwlen = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_password_len,
			tvb, offset, 2, pwlen);
		offset += 2;

		/* 4 reserved bytes */
		proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 4, TRUE);
		offset += 4;

		break;

	case 12:
		/* security blob length */
		sbloblen = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_security_blob_len, tvb, offset, 2, sbloblen);
		offset += 2;

		/* 4 reserved bytes */
		proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 4, TRUE);
		offset += 4;

		/* capabilities */
		dissect_negprot_capabilities(tvb, pinfo, tree, offset);
		offset += 4;

		break;

	case 13:
		/* password length, ANSI*/
		apwlen = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_ansi_password_len,
			tvb, offset, 2, apwlen);
		offset += 2;

		/* password length, Unicode*/
		upwlen = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_unicode_password_len,
			tvb, offset, 2, upwlen);
		offset += 2;

		/* 4 reserved bytes */
		proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 4, TRUE);
		offset += 4;

		/* capabilities */
		dissect_negprot_capabilities(tvb, pinfo, tree, offset);
		offset += 4;

		break;
	}

	BYTE_COUNT;

	if (wc==12) {
		/* security blob */
		/* XXX - is this ASN.1-encoded?  Is it a Kerberos
		   data structure, at least in NT 5.0-and-later
		   server replies? */
		if(sbloblen){
			CHECK_BYTE_COUNT(sbloblen);
			proto_tree_add_item(tree, hf_smb_security_blob,
				tvb, offset, sbloblen, TRUE);
			COUNT_BYTES(sbloblen);
		}

		/* OS */
		an = get_unicode_or_ascii_string(tvb, &offset,
			pinfo, &an_len, FALSE, FALSE, &bc);
		if (an == NULL)
			goto endofcommand;
		proto_tree_add_string(tree, hf_smb_os, tvb,
			offset, an_len, an);
		COUNT_BYTES(an_len);

		/* LANMAN */
		/* XXX - pre-W2K NT systems appear to stick an extra 2 bytes of
		 * padding/null string/whatever in front of this. W2K doesn't
		 * appear to. I suspect that's a bug that got fixed; I also
		 * suspect that, in practice, nobody ever looks at that field
		 * because the bug didn't appear to get fixed until NT 5.0....
		 */
		an = get_unicode_or_ascii_string(tvb, &offset,
			pinfo, &an_len, FALSE, FALSE, &bc);
		if (an == NULL)
			goto endofcommand;
		proto_tree_add_string(tree, hf_smb_lanman, tvb,
			offset, an_len, an);
		COUNT_BYTES(an_len);

		/* Primary domain */
		/* XXX - pre-W2K NT systems sometimes appear to stick an extra
		 * byte in front of this, at least if all the strings are
		 * ASCII and the account name is empty. Another bug?
		 */
		dn = get_unicode_or_ascii_string(tvb, &offset,
			pinfo, &dn_len, FALSE, FALSE, &bc);
		if (dn == NULL)
			goto endofcommand;
		proto_tree_add_string(tree, hf_smb_primary_domain, tvb,
			offset, dn_len, dn);
		COUNT_BYTES(dn_len);
	} else {
		switch (wc) {

		case 10:
			if(pwlen){
				/* password, ASCII */
				CHECK_BYTE_COUNT(pwlen);
				proto_tree_add_item(tree, hf_smb_password, 
					tvb, offset, pwlen, TRUE);
				COUNT_BYTES(pwlen);
			}

			break;

		case 13:
			if(apwlen){
				/* password, ANSI */
				CHECK_BYTE_COUNT(apwlen);
				proto_tree_add_item(tree, hf_smb_ansi_password, 
					tvb, offset, apwlen, TRUE);
				COUNT_BYTES(apwlen);
			}

			if(upwlen){
				/* password, Unicode */
				CHECK_BYTE_COUNT(upwlen);
				proto_tree_add_item(tree, hf_smb_unicode_password, 
					tvb, offset, upwlen, TRUE);
				COUNT_BYTES(upwlen);
			}

			break;
		}

		/* Account Name */
		an = get_unicode_or_ascii_string(tvb, &offset,
			pinfo, &an_len, FALSE, FALSE, &bc);
		if (an == NULL)
			goto endofcommand;
		proto_tree_add_string(tree, hf_smb_account, tvb, offset, an_len,
			an);
		COUNT_BYTES(an_len);

		/* Primary domain */
		/* XXX - pre-W2K NT systems sometimes appear to stick an extra
		 * byte in front of this, at least if all the strings are
		 * ASCII and the account name is empty. Another bug?
		 */
		dn = get_unicode_or_ascii_string(tvb, &offset,
			pinfo, &dn_len, FALSE, FALSE, &bc);
		if (dn == NULL)
			goto endofcommand;
		proto_tree_add_string(tree, hf_smb_primary_domain, tvb,
			offset, dn_len, dn);
		COUNT_BYTES(dn_len);

		if (check_col(pinfo->fd, COL_INFO)) {
			col_append_fstr(pinfo->fd, COL_INFO, ", User: %s@%s",
			an,dn);
		}

		/* OS */
		an = get_unicode_or_ascii_string(tvb, &offset,
			pinfo, &an_len, FALSE, FALSE, &bc);
		if (an == NULL)
			goto endofcommand;
		proto_tree_add_string(tree, hf_smb_os, tvb,
			offset, an_len, an);
		COUNT_BYTES(an_len);

		/* LANMAN */
		/* XXX - pre-W2K NT systems appear to stick an extra 2 bytes of
		 * padding/null string/whatever in front of this. W2K doesn't
		 * appear to. I suspect that's a bug that got fixed; I also
		 * suspect that, in practice, nobody ever looks at that field
		 * because the bug didn't appear to get fixed until NT 5.0....
		 */
		an = get_unicode_or_ascii_string(tvb, &offset,
			pinfo, &an_len, FALSE, FALSE, &bc);
		if (an == NULL)
			goto endofcommand;
		proto_tree_add_string(tree, hf_smb_lanman, tvb,
			offset, an_len, an);
		COUNT_BYTES(an_len);
	}

	END_OF_SMB

	/* call AndXCommand (if there are any) */
	dissect_smb_command(tvb, pinfo, tree, andxoffset, smb_tree, cmd);

	return offset;
}

static int
dissect_session_setup_andx_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8	wc, cmd=0xff;
	guint16 andxoffset=0, bc;
	guint16 sbloblen=0;
	int an_len;
	const char *an;

	WORD_COUNT;

	/* next smb command */
	cmd = tvb_get_guint8(tvb, offset);
	if(cmd!=0xff){
		proto_tree_add_uint_format(tree, hf_smb_cmd, tvb, offset, 1, cmd, "AndXCommand: %s (0x%02x)", decode_smb_name(cmd), cmd);
	} else {
		proto_tree_add_uint_format(tree, hf_smb_cmd, tvb, offset, 1, cmd, "AndXCommand: No further commands (0xff)");
	}
	offset += 1;

	/* reserved byte */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 1, TRUE);
	offset += 1;

	/* andxoffset */
	andxoffset = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_andxoffset, tvb, offset, 2, andxoffset);
	offset += 2;

	/* flags */
	offset = dissect_setup_action(tvb, pinfo, tree, offset);

	if(wc==4){
		/* security blob length */
		sbloblen = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_security_blob_len, tvb, offset, 2, sbloblen);
		offset += 2;
	}

	BYTE_COUNT;

	if(wc==4) {
		/* security blob */
		/* XXX - is this ASN.1-encoded?  Is it a Kerberos
		   data structure, at least in NT 5.0-and-later
		   server replies? */
		if(sbloblen){
			CHECK_BYTE_COUNT(sbloblen);
			proto_tree_add_item(tree, hf_smb_security_blob,
				tvb, offset, sbloblen, TRUE);
			COUNT_BYTES(sbloblen);
		}
	}

	/* OS */
	an = get_unicode_or_ascii_string(tvb, &offset,
		pinfo, &an_len, FALSE, FALSE, &bc);
	if (an == NULL)
		goto endofcommand;
	proto_tree_add_string(tree, hf_smb_os, tvb,
		offset, an_len, an);
	COUNT_BYTES(an_len);

	/* LANMAN */
	an = get_unicode_or_ascii_string(tvb, &offset,
		pinfo, &an_len, FALSE, FALSE, &bc);
	if (an == NULL)
		goto endofcommand;
	proto_tree_add_string(tree, hf_smb_lanman, tvb,
		offset, an_len, an);
	COUNT_BYTES(an_len);

	if(wc==3) {
		/* Primary domain */
		an = get_unicode_or_ascii_string(tvb, &offset,
			pinfo, &an_len, FALSE, FALSE, &bc);
		if (an == NULL)
			goto endofcommand;
		proto_tree_add_string(tree, hf_smb_primary_domain, tvb,
			offset, an_len, an);
		COUNT_BYTES(an_len);
	}

	END_OF_SMB

	/* call AndXCommand (if there are any) */
	dissect_smb_command(tvb, pinfo, tree, andxoffset, smb_tree, cmd);

	return offset;
}

 
static int
dissect_empty_andx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8	wc, cmd=0xff;
	guint16 andxoffset=0;
	guint16 bc;

	WORD_COUNT;

	/* next smb command */
	cmd = tvb_get_guint8(tvb, offset);
	if(cmd!=0xff){
		proto_tree_add_uint_format(tree, hf_smb_cmd, tvb, offset, 1, cmd, "AndXCommand: %s (0x%02x)", decode_smb_name(cmd), cmd);
	} else {
		proto_tree_add_uint_format(tree, hf_smb_cmd, tvb, offset, 1, cmd, "AndXCommand: No further commands (0xff)");
	}
	offset += 1;

	/* reserved byte */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 1, TRUE);
	offset += 1;

	/* andxoffset */
	andxoffset = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_andxoffset, tvb, offset, 2, andxoffset);
	offset += 2;

	BYTE_COUNT;

	END_OF_SMB

	/* call AndXCommand (if there are any) */
	dissect_smb_command(tvb, pinfo, tree, andxoffset, smb_tree, cmd);

	return offset;
}

 
static const true_false_string tfs_connect_support_search = {
	"Exclusive search bits supported",
	"Exclusive search bits not supported"
};
static const true_false_string tfs_connect_support_in_dfs = {
	"Share is in Dfs",
	"Share isn't in Dfs"
};

static int
dissect_connect_support_bits(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint16 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohs(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 2,
			"Optional Support: 0x%04x", mask);
		tree = proto_item_add_subtree(item, ett_smb_connect_support_bits);
	}

	proto_tree_add_boolean(tree, hf_smb_connect_support_search,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_connect_support_in_dfs,
		tvb, offset, 2, mask);

	offset += 2;

	return offset;
}

static const true_false_string tfs_disconnect_tid = {
	"DISCONNECT TID",
	"Do NOT disconnect TID"
};

static int
dissect_connect_flags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint16 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohs(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 2,
			"Flags: 0x%04x", mask);
		tree = proto_item_add_subtree(item, ett_smb_connect_flags);
	}

	proto_tree_add_boolean(tree, hf_smb_connect_flags_dtid,
		tvb, offset, 2, mask);

	offset += 2;

	return offset;
}

static int
dissect_tree_connect_andx_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8	wc, cmd=0xff;
	guint16 bc;
	guint16 andxoffset=0, pwlen=0;
	int an_len;
	const char *an;

	WORD_COUNT;

	/* next smb command */
	cmd = tvb_get_guint8(tvb, offset);
	if(cmd!=0xff){
		proto_tree_add_uint_format(tree, hf_smb_cmd, tvb, offset, 1, cmd, "AndXCommand: %s (0x%02x)", decode_smb_name(cmd), cmd);
	} else {
		proto_tree_add_uint_format(tree, hf_smb_cmd, tvb, offset, 1, cmd, "AndXCommand: No further commands");
	}
	offset += 1;

	/* reserved byte */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 1, TRUE);
	offset += 1;

	/* andxoffset */
	andxoffset = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_andxoffset, tvb, offset, 2, andxoffset);
	offset += 2;

	/* flags */
	offset = dissect_connect_flags(tvb, pinfo, tree, offset);

	/* password length*/
	pwlen = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_password_len, tvb, offset, 2, pwlen);
	offset += 2;

	BYTE_COUNT;

	/* password */
	CHECK_BYTE_COUNT(pwlen);
	proto_tree_add_item(tree, hf_smb_password, 
		tvb, offset, pwlen, TRUE);
	COUNT_BYTES(pwlen);

	/* Path */
	an = get_unicode_or_ascii_string(tvb, &offset,
		pinfo, &an_len, FALSE, FALSE, &bc);
	if (an == NULL)
		goto endofcommand;
	proto_tree_add_string(tree, hf_smb_path, tvb,
		offset, an_len, an);
	COUNT_BYTES(an_len);

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, ", Path: %s", an);
	}

	/*
	 * NOTE: the Service string is always ASCII, even if the
	 * "strings are Unicode" bit is set in the flags2 field
	 * of the SMB.
	 */

	/* Service */
	/* XXX - what if this runs past bc? */
	an_len = tvb_strsize(tvb, offset);
	CHECK_BYTE_COUNT(an_len);
	an = tvb_get_ptr(tvb, offset, an_len);
	proto_tree_add_string(tree, hf_smb_service, tvb,
		offset, an_len, an);
	COUNT_BYTES(an_len);

	END_OF_SMB

	/* call AndXCommand (if there are any) */
	dissect_smb_command(tvb, pinfo, tree, andxoffset, smb_tree, cmd);

	return offset;
}


static int
dissect_tree_connect_andx_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8	wc, wleft, cmd=0xff;
	guint16 andxoffset=0;
	guint16 bc;
	int an_len;
	const char *an;

	WORD_COUNT;

	wleft = wc;	/* this is at least 1 */

	/* next smb command */
	cmd = tvb_get_guint8(tvb, offset);
	if(cmd!=0xff){
		proto_tree_add_uint_format(tree, hf_smb_cmd, tvb, offset, 1, cmd, "AndXCommand: %s (0x%02x)", decode_smb_name(cmd), cmd);
	} else {
		proto_tree_add_uint_format(tree, hf_smb_cmd, tvb, offset, 1, cmd, "AndXCommand: No further commands");
	}
	offset += 1;

	/* reserved byte */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 1, TRUE);
	offset += 1;

	wleft--;
	if (wleft == 0)
		goto bytecount;

	/* andxoffset */
	andxoffset = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_andxoffset, tvb, offset, 2, andxoffset);
	offset += 2;
	wleft--;
	if (wleft == 0)
		goto bytecount;

	/* flags */
	offset = dissect_connect_support_bits(tvb, pinfo, tree, offset);
	wleft--;

	/* XXX - I've seen captures where this is 7, but I have no
	   idea how to dissect it.  I'm guessing the third word
	   contains connect support bits, which looks plausible
	   from the values I've seen. */

	while (wleft != 0) {
		proto_tree_add_text(tree, tvb, offset, 2,
		    "Word parameter: 0x%04x", tvb_get_letohs(tvb, offset));
		offset += 2;
		wleft--;
	}

	BYTE_COUNT;

	/*
	 * NOTE: even though the SNIA CIFS spec doesn't say there's
	 * a "Service" string if there's a word count of 2, the
	 * document at
	 *
	 *	ftp://ftp.microsoft.com/developr/drg/CIFS/dosextp.txt
	 *
	 * (it's in an ugly format - text intended to be sent to a
	 * printer, with backspaces and overstrikes used for boldfacing
	 * and underlining; UNIX "col -b" can be used to strip the
	 * overstrikes out) says there's a "Service" string there, and
	 * some network traffic has it.
	 */

	/*
	 * NOTE: the Service string is always ASCII, even if the
	 * "strings are Unicode" bit is set in the flags2 field
	 * of the SMB.
	 */

	/* Service */
	/* XXX - what if this runs past bc? */
	an_len = tvb_strsize(tvb, offset);
	CHECK_BYTE_COUNT(an_len);
	an = tvb_get_ptr(tvb, offset, an_len);
	proto_tree_add_string(tree, hf_smb_service, tvb,
		offset, an_len, an);
	COUNT_BYTES(an_len);

	if(wc==3){
		if (bc != 0) {
			/*
			 * Sometimes this isn't present.
			 */

			/* Native FS */
			an = get_unicode_or_ascii_string(tvb, &offset,
				pinfo, &an_len, /*TRUE*/FALSE, FALSE, &bc);
			if (an == NULL)
				goto endofcommand;
			proto_tree_add_string(tree, hf_smb_fs, tvb,
				offset, an_len, an);
			COUNT_BYTES(an_len);
		}
	}

	END_OF_SMB

	/* call AndXCommand (if there are any) */
	dissect_smb_command(tvb, pinfo, tree, andxoffset, smb_tree, cmd);

	return offset;
}



/* XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   NT Transaction command  begins here
   XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX */
#define NT_TRANS_CREATE		1
#define NT_TRANS_IOCTL		2
#define NT_TRANS_SSD		3
#define NT_TRANS_NOTIFY		4
#define NT_TRANS_RENAME		5
#define NT_TRANS_QSD		6
static const value_string nt_cmd_vals[] = {
	{NT_TRANS_CREATE,	"NT CREATE"},
	{NT_TRANS_IOCTL,	"NT IOCTL"},
	{NT_TRANS_SSD,		"NT SET SECURITY DESC"},
	{NT_TRANS_NOTIFY,	"NT NOTIFY"},
	{NT_TRANS_RENAME,	"NT RENAME"},
	{NT_TRANS_QSD,		"NT QUERY SECURITY DESC"},
	{0, NULL}
};

static const value_string nt_ioctl_isfsctl_vals[] = {
	{0,	"Device IOCTL"},
	{1,	"FS control : FSCTL"},
	{0, NULL}
};

#define NT_IOCTL_FLAGS_ROOT_HANDLE	0x01
static const true_false_string tfs_nt_ioctl_flags_root_handle = {
	"Apply the command to share root handle (MUST BE Dfs)",
	"Apply to this share",
};

static const value_string nt_notify_action_vals[] = {
	{1,	"ADDED (object was added"},
	{2,	"REMOVED (object was removed)"},
	{3,	"MODIFIED (object was modified)"},
	{4,	"RENAMED_OLD_NAME (this is the old name of object)"},
	{5,	"RENAMED_NEW_NAME (this is the new name of object)"},
	{6,	"ADDED_STREAM (a stream was added)"},
	{7,	"REMOVED_STREAM (a stream was removed)"},
	{8,	"MODIFIED_STREAM (a stream was modified)"},
	{0, NULL}
};

static const value_string watch_tree_vals[] = {
	{0,	"Current directory only"},
	{1,	"Subdirectories also"},
	{0, NULL}
};

#define NT_NOTIFY_STREAM_WRITE	0x00000800
#define NT_NOTIFY_STREAM_SIZE	0x00000400
#define NT_NOTIFY_STREAM_NAME	0x00000200
#define NT_NOTIFY_SECURITY	0x00000100
#define NT_NOTIFY_EA		0x00000080
#define NT_NOTIFY_CREATION	0x00000040
#define NT_NOTIFY_LAST_ACCESS	0x00000020
#define NT_NOTIFY_LAST_WRITE	0x00000010
#define NT_NOTIFY_SIZE		0x00000008
#define NT_NOTIFY_ATTRIBUTES	0x00000004
#define NT_NOTIFY_DIR_NAME	0x00000002
#define NT_NOTIFY_FILE_NAME	0x00000001
static const true_false_string tfs_nt_notify_stream_write = {
	"Notify on changes to STREAM WRITE",
	"Do NOT notify on changes to stream write",
};
static const true_false_string tfs_nt_notify_stream_size = {
	"Notify on changes to STREAM SIZE",
	"Do NOT notify on changes to stream size",
};
static const true_false_string tfs_nt_notify_stream_name = {
	"Notify on changes to STREAM NAME",
	"Do NOT notify on changes to stream name",
};
static const true_false_string tfs_nt_notify_security = {
	"Notify on changes to SECURITY",
	"Do NOT notify on changes to security",
};
static const true_false_string tfs_nt_notify_ea = {
	"Notify on changes to EA",
	"Do NOT notify on changes to EA",
};
static const true_false_string tfs_nt_notify_creation = {
	"Notify on changes to CREATION TIME",
	"Do NOT notify on changes to creation time",
};
static const true_false_string tfs_nt_notify_last_access = {
	"Notify on changes to LAST ACCESS TIME",
	"Do NOT notify on changes to last access time",
};
static const true_false_string tfs_nt_notify_last_write = {
	"Notify on changes to LAST WRITE TIME",
	"Do NOT notify on changes to last write time",
};
static const true_false_string tfs_nt_notify_size = {
	"Notify on changes to SIZE",
	"Do NOT notify on changes to size",
};
static const true_false_string tfs_nt_notify_attributes = {
	"Notify on changes to ATTRIBUTES",
	"Do NOT notify on changes to attributes",
};
static const true_false_string tfs_nt_notify_dir_name = {
	"Notify on changes to DIR NAME",
	"Do NOT notify on changes to dir name",
};
static const true_false_string tfs_nt_notify_file_name = {
	"Notify on changes to FILE NAME",
	"Do NOT notify on changes to file name",
};

static const value_string create_disposition_vals[] = {
	{0,	"Supersede (supersede existing file (if it exists))"},
	{1,	"Open (if file exists open it, else fail)"},
	{2,	"Create (if file exists fail, else create it)"},
	{3,	"Open If (if file exists open it, else create it)"},
	{4,	"Overwrite (if file exists overwrite, else fail)"},
	{5,	"Overwrite If (if file exists overwrite, else create it)"},
	{0, NULL}
};

static const value_string impersonation_level_vals[] = {
	{0,	"Anonymous"},
	{1,	"Identification"},
	{2,	"Impersonation"},
	{3,	"Delegation"},
	{0, NULL}
};

static const true_false_string tfs_nt_security_flags_context_tracking = {
	"Security tracking mode is DYNAMIC",
	"Security tracking mode is STATIC",
};

static const true_false_string tfs_nt_security_flags_effective_only = {
	"ONLY ENABLED aspects of the client's security context are available",
	"ALL aspects of the client's security context are available",
};

static const true_false_string tfs_nt_create_bits_oplock = {
	"Requesting OPLOCK",
	"Does NOT request oplock"
};

static const true_false_string tfs_nt_create_bits_boplock = {
	"Requesting BATCH OPLOCK",
	"Does NOT request batch oplock"
};

/*
 * XXX - must be a directory, and can be a file, or can be a directory,
 * and must be a file?
 */
static const true_false_string tfs_nt_create_bits_dir = {
	"Target of open MUST be a DIRECTORY",
	"Target of open can be a file"
};

static const true_false_string tfs_nt_access_mask_generic_read = {
	"GENERIC READ is set",
	"Generic read is NOT set"
};
static const true_false_string tfs_nt_access_mask_generic_write = {
	"GENERIC WRITE is set",
	"Generic write is NOT set"
};
static const true_false_string tfs_nt_access_mask_generic_execute = {
	"GENERIC EXECUTE is set",
	"Generic execute is NOT set"
};
static const true_false_string tfs_nt_access_mask_generic_all = {
	"GENERIC ALL is set",
	"Generic all is NOT set"
};
static const true_false_string tfs_nt_access_mask_maximum_allowed = {
	"MAXIMUM ALLOWED is set",
	"Maximum allowed is NOT set"
};
static const true_false_string tfs_nt_access_mask_system_security = {
	"SYSTEM SECURITY is set",
	"System security is NOT set"
};
static const true_false_string tfs_nt_access_mask_synchronize = {
	"Can wait on handle to SYNCHRONIZE on completion of I/O",
	"Can NOT wait on handle to synchronize on completion of I/O"
};
static const true_false_string tfs_nt_access_mask_write_owner = {
	"Can WRITE OWNER (take ownership)",
	"Can NOT write owner (take ownership)"
};
static const true_false_string tfs_nt_access_mask_write_dac = {
	"OWNER may WRITE the DAC",
	"Owner may NOT write to the DAC"
};
static const true_false_string tfs_nt_access_mask_read_control = {
	"READ ACCESS to owner, group and ACL of the SID",
	"Read access is NOT granted to owner, group and ACL of the SID"
};
static const true_false_string tfs_nt_access_mask_delete = {
	"DELETE access",
	"NO delete access"
};
static const true_false_string tfs_nt_access_mask_write_attributes = {
	"WRITE ATTRIBUTES access",
	"NO write attributes access"
};
static const true_false_string tfs_nt_access_mask_read_attributes = {
	"READ ATTRIBUTES access",
	"NO read attributes access"
};
static const true_false_string tfs_nt_access_mask_delete_child = {
	"DELETE CHILD access",
	"NO delete child access"
};
static const true_false_string tfs_nt_access_mask_execute = {
	"EXECUTE access",
	"NO execute access"
};
static const true_false_string tfs_nt_access_mask_write_ea = {
	"WRITE EXTENDED ATTRIBUTES access",
	"NO write extended attributes access"
};
static const true_false_string tfs_nt_access_mask_read_ea = {
	"READ EXTENDED ATTRIBUTES access",
	"NO read extended attributes access"
};
static const true_false_string tfs_nt_access_mask_append = {
	"APPEND access",
	"NO append access"
};
static const true_false_string tfs_nt_access_mask_write = {
	"WRITE access",
	"NO write access"
};
static const true_false_string tfs_nt_access_mask_read = {
	"READ access",
	"NO read access"
};

static const true_false_string tfs_nt_share_access_delete = {
	"Object can be shared for DELETE",
	"Object can NOT be shared for delete"
};
static const true_false_string tfs_nt_share_access_write = {
	"Object can be shared for WRITE",
	"Object can NOT be shared for write"
};
static const true_false_string tfs_nt_share_access_read = {
	"Object can be shared for READ",
	"Object can NOT be shared for delete"
};

static const value_string oplock_level_vals[] = {
	{0,	"No oplock granted"},
	{1,	"Exclusive oplock granted"},
	{2,	"Batch oplock granted"},
	{3,	"Level II oplock granted"},
	{0, NULL}
};

static const value_string device_type_vals[] = {
	{0x00000001,	"Beep"},
	{0x00000002,	"CDROM"},
	{0x00000003,	"CDROM Filesystem"},
	{0x00000004,	"Controller"},
	{0x00000005,	"Datalink"},
	{0x00000006,	"Dfs"},
	{0x00000007,	"Disk"},
	{0x00000008,	"Disk Filesystem"},
	{0x00000009,	"Filesystem"},
	{0x0000000a,	"Inport Port"},
	{0x0000000b,	"Keyboard"},
	{0x0000000c,	"Mailslot"},
	{0x0000000d,	"MIDI-In"},
	{0x0000000e,	"MIDI-Out"},
	{0x0000000f,	"Mouse"},
	{0x00000010,	"Multi UNC Provider"},
	{0x00000011,	"Named Pipe"},
	{0x00000012,	"Network"},
	{0x00000013,	"Network Browser"},
	{0x00000014,	"Network Filesystem"},
	{0x00000015,	"NULL"},
	{0x00000016,	"Parallel Port"},
	{0x00000017,	"Physical card"},
	{0x00000018,	"Printer"},
	{0x00000019,	"Scanner"},
	{0x0000001a,	"Serial Mouse port"},
	{0x0000001b,	"Serial port"},
	{0x0000001c,	"Screen"},
	{0x0000001d,	"Sound"},
	{0x0000001e,	"Streams"},
	{0x0000001f,	"Tape"},
	{0x00000020,	"Tape Filesystem"},
	{0x00000021,	"Transport"},
	{0x00000022,	"Unknown"},
	{0x00000023,	"Video"},
	{0x00000024,	"Virtual Disk"},
	{0x00000025,	"WAVE-In"},
	{0x00000026,	"WAVE-Out"},
	{0x00000027,	"8042 Port"},
	{0x00000028,	"Network Redirector"},
	{0x00000029,	"Battery"},
	{0x0000002a,	"Bus Extender"},
	{0x0000002b,	"Modem"},
	{0x0000002c,	"VDM"},
	{0,	NULL}
};

static const value_string is_directory_vals[] = {
	{0,	"This is NOT a directory"},
	{1,	"This is a DIRECTORY"},
	{0, NULL}
};

typedef struct _nt_trans_data {
	int subcmd;
	guint32 sd_len;
	guint32 ea_len;
} nt_trans_data;



static int
dissect_nt_security_flags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint8 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_guint8(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 1,
			"Security Flags: 0x%02x", mask);
		tree = proto_item_add_subtree(item, ett_smb_nt_security_flags);
	}

	proto_tree_add_boolean(tree, hf_smb_nt_security_flags_context_tracking,
		tvb, offset, 1, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_security_flags_effective_only,
		tvb, offset, 1, mask);

	offset += 1;

	return offset;
}

static int
dissect_nt_share_access(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint32 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohl(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 4,
			"Share Access: 0x%08x", mask);
		tree = proto_item_add_subtree(item, ett_smb_nt_share_access);
	}

	proto_tree_add_boolean(tree, hf_smb_nt_share_access_delete,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_share_access_write,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_share_access_read,
		tvb, offset, 4, mask);

	offset += 4;

	return offset;
}


static int
dissect_nt_access_mask(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint32 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohl(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 4,
			"Access Mask: 0x%08x", mask);
		tree = proto_item_add_subtree(item, ett_smb_nt_access_mask);
	}

	/*
	 * Some of these bits come from 
	 *
	 *	http://www.samba.org/samba/ftp/specs/smb-nt01.doc
	 *
	 * and others come from the section on ZwOpenFile in "Windows(R)
	 * NT(R)/2000 Native API Reference".
	 */
	proto_tree_add_boolean(tree, hf_smb_nt_access_mask_generic_read,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_access_mask_generic_write,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_access_mask_generic_execute,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_access_mask_generic_all,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_access_mask_maximum_allowed,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_access_mask_system_security,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_access_mask_synchronize,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_access_mask_write_owner,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_access_mask_write_dac,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_access_mask_read_control,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_access_mask_delete,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_access_mask_write_attributes,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_access_mask_read_attributes,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_access_mask_delete_child,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_access_mask_execute,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_access_mask_write_ea,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_access_mask_read_ea,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_access_mask_append,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_access_mask_write,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_access_mask_read,
		tvb, offset, 4, mask);

	offset += 4;

	return offset;
}

static int
dissect_nt_create_bits(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint32 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohl(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 4,
			"Create Flags: 0x%08x", mask);
		tree = proto_item_add_subtree(item, ett_smb_nt_create_bits);
	}

	/*
	 * XXX - it's 0x00000016 in at least one capture, but
	 * Network Monitor doesn't say what the 0x00000010 bit is.
	 * Does the Win32 API documentation, or NT Native API book,
	 * suggest anything?
	 */
	proto_tree_add_boolean(tree, hf_smb_nt_create_bits_dir,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_create_bits_boplock,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_create_bits_oplock,
		tvb, offset, 4, mask);

	offset += 4;

	return offset;
}

/*
 * XXX - there are some more flags in the description of "ZwOpenFile()"
 * in "Windows(R) NT(R)/2000 Native API Reference"; do those go over
 * the wire as well?  (The spec at
 *
 *	http://www.samba.org/samba/ftp/specs/smb-nt01.doc
 *
 * says that "the FILE_NO_INTERMEDIATE_BUFFERING option is not exported
 * via the SMB protocol.  The NT redirector should convert this option
 * to FILE_WRITE_THROUGH."
 *
 * The "Sync I/O Alert" and "Sync I/O Nonalert" are given the bit
 * values one would infer from their position in the list of flags for
 * "ZwOpenFile()".  Most of the others probably have those values
 * as well, although "8.3 only" would collide with FILE_OPEN_FOR_RECOVERY,
 * which might go over the wire (for the benefit of backup/restore software).
 */
static const true_false_string tfs_nt_create_options_directory = {
	"File being created/opened must be a directory",
	"File being created/opened must not be a directory"
};
static const true_false_string tfs_nt_create_options_write_through = {
	"Writes should flush buffered data before completing",
	"Writes need not flush buffered data before completing"
};
static const true_false_string tfs_nt_create_options_sequential_only = {
	"The file will only be accessed sequentially",
	"The file might not only be accessed sequentially"
};
static const true_false_string tfs_nt_create_options_sync_io_alert = {
	"All operations SYNCHRONOUS, waits subject to termination from alert",
	"Operations NOT necessarily synchronous"
};
static const true_false_string tfs_nt_create_options_sync_io_nonalert = {
	"All operations SYNCHRONOUS, waits not subject to alert",
	"Operations NOT necessarily synchronous"
};
static const true_false_string tfs_nt_create_options_non_directory = {
	"File being created/opened must not be a directory",
	"File being created/opened must be a directory"
};
static const true_false_string tfs_nt_create_options_no_ea_knowledge = {
	"The client does not understand extended attributes",
	"The client understands extended attributes"
};
static const true_false_string tfs_nt_create_options_eight_dot_three_only = {
	"The client understands only 8.3 file names",
	"The client understands long file names"
};
static const true_false_string tfs_nt_create_options_random_access = {
	"The file will be accessed randomly",
	"The file will not be accessed randomly"
};
static const true_false_string tfs_nt_create_options_delete_on_close = {
	"The file should be deleted when it is closed",
	"The file should not be deleted when it is closed"
};

static int
dissect_nt_create_options(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint32 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohl(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 4,
			"Create Options: 0x%08x", mask);
		tree = proto_item_add_subtree(item, ett_smb_nt_create_options);
	}

	/*
	 * From
	 *
	 *	http://www.samba.org/samba/ftp/specs/smb-nt01.doc
	 */
	proto_tree_add_boolean(tree, hf_smb_nt_create_options_directory_file,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_create_options_write_through,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_create_options_sequential_only,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_create_options_sync_io_alert,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_create_options_sync_io_nonalert,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_create_options_non_directory_file,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_create_options_no_ea_knowledge,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_create_options_eight_dot_three_only,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_create_options_random_access,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_create_options_delete_on_close,
		tvb, offset, 4, mask);

	offset += 4;

	return offset;
}
 
static int
dissect_nt_notify_completion_filter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint32 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohl(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 4,
			"Completion Filter: 0x%08x", mask);
		tree = proto_item_add_subtree(item, ett_smb_nt_notify_completion_filter);
	}
 
	proto_tree_add_boolean(tree, hf_smb_nt_notify_stream_write,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_notify_stream_size,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_notify_stream_name,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_notify_security,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_notify_ea,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_notify_creation,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_notify_last_access,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_notify_last_write,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_notify_size,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_notify_attributes,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_notify_dir_name,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_notify_file_name,
		tvb, offset, 4, mask);

	offset += 4;
	return offset;
}
 
static int
dissect_nt_ioctl_flags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint8 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_guint8(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 1,
			"Completion Filter: 0x%02x", mask);
		tree = proto_item_add_subtree(item, ett_smb_nt_ioctl_flags);
	}

	proto_tree_add_boolean(tree, hf_smb_nt_ioctl_flags_root_handle,
		tvb, offset, 1, mask);

	offset += 1;
	return offset;
}

/*
 * From the section on ZwQuerySecurityObject in "Windows(R) NT(R)/2000
 * Native API Reference".
 */
static const true_false_string tfs_nt_qsd_owner = {
	"Requesting OWNER security information",
	"NOT requesting owner security information",
};

static const true_false_string tfs_nt_qsd_group = {
	"Requesting GROUP security information",
	"NOT requesting group security information",
};

static const true_false_string tfs_nt_qsd_dacl = {
	"Requesting DACL security information",
	"NOT requesting DACL security information",
};

static const true_false_string tfs_nt_qsd_sacl = {
	"Requesting SACL security information",
	"NOT requesting SACL security information",
};

#define NT_QSD_OWNER	0x00000001
#define NT_QSD_GROUP	0x00000002
#define NT_QSD_DACL	0x00000004
#define NT_QSD_SACL	0x00000008

static int
dissect_security_information_mask(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint32 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohl(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 4,
			"Security Information: 0x%08x", mask);
		tree = proto_item_add_subtree(item, ett_smb_security_information_mask);
	}

	proto_tree_add_boolean(tree, hf_smb_nt_qsd_owner,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_qsd_group,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_qsd_dacl,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_nt_qsd_sacl,
		tvb, offset, 4, mask);

	offset += 4;

	return offset;
}


static int
dissect_nt_trans_data_request(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *parent_tree, int len, nt_trans_data *ntd)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	smb_info_t *si;

	si = (smb_info_t *)pinfo->private_data;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, len,
				"%s Data",
				val_to_str(ntd->subcmd, nt_cmd_vals, "Unknown NT transaction (%u)"));
		tree = proto_item_add_subtree(item, ett_smb_nt_trans_setup);
	}

	switch(ntd->subcmd){
	case NT_TRANS_CREATE:
		/* security descriptor */
		if(ntd->sd_len){
			proto_tree_add_item(tree, hf_smb_security_descriptor, tvb, offset, ntd->sd_len, TRUE);
			offset += ntd->sd_len;
		}

		/* extended attributes */
		if(ntd->ea_len){
			proto_tree_add_item(tree, hf_smb_extended_attributes, tvb, offset, ntd->ea_len, TRUE);
			offset += ntd->ea_len;
		}

		break;
	case NT_TRANS_IOCTL:
		/* ioctl data */
		proto_tree_add_item(tree, hf_smb_nt_ioctl_data, tvb, offset, len, TRUE);
		offset += len;

		break;
	case NT_TRANS_SSD:
		proto_tree_add_item(tree, hf_smb_security_descriptor, tvb, offset, len, TRUE);
		offset += len;
		break;
	case NT_TRANS_NOTIFY:
		break;
	case NT_TRANS_RENAME:
		/* XXX not documented */
		break;
	case NT_TRANS_QSD:
		break;
	}

	return offset;
}

static int
dissect_nt_trans_param_request(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *parent_tree, int len, nt_trans_data *ntd, guint16 bc)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	smb_info_t *si;
	guint32 fn_len;
	const char *fn;

	si = (smb_info_t *)pinfo->private_data;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, len,
				"%s Parameters",
				val_to_str(ntd->subcmd, nt_cmd_vals, "Unknown NT transaction (%u)"));
		tree = proto_item_add_subtree(item, ett_smb_nt_trans_setup);
	}

	switch(ntd->subcmd){
	case NT_TRANS_CREATE:
		/* Create flags */
		offset = dissect_nt_create_bits(tvb, pinfo, tree, offset);
		bc -= 4;

		/* root directory fid */
		proto_tree_add_item(tree, hf_smb_root_dir_fid, tvb, offset, 4, TRUE);
		COUNT_BYTES(4);

		/* nt access mask */
		offset = dissect_nt_access_mask(tvb, pinfo, tree, offset);
		bc -= 4;
	
		/* allocation size */
		proto_tree_add_item(tree, hf_smb_alloc_size64, tvb, offset, 8, TRUE);
		COUNT_BYTES(8);
	
		/* Extended File Attributes */
		offset = dissect_file_ext_attr(tvb, pinfo, tree, offset);
		bc -= 4;

		/* share access */
		offset = dissect_nt_share_access(tvb, pinfo, tree, offset);
		bc -= 4;
	
		/* create disposition */
		proto_tree_add_item(tree, hf_smb_nt_create_disposition, tvb, offset, 4, TRUE);
		COUNT_BYTES(4);

		/* create options */
		offset = dissect_nt_create_options(tvb, pinfo, tree, offset);
		bc -= 4;

		/* sd length */
		ntd->sd_len = tvb_get_letohl(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_sd_length, tvb, offset, 4, ntd->sd_len);
		COUNT_BYTES(4);

		/* ea length */
		ntd->ea_len = tvb_get_letohl(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_ea_length, tvb, offset, 4, ntd->ea_len);
		COUNT_BYTES(4);

		/* file name len */
		fn_len = (guint32)tvb_get_letohl(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_file_name_len, tvb, offset, 4, fn_len);
		COUNT_BYTES(4);

		/* impersonation level */
		proto_tree_add_item(tree, hf_smb_nt_impersonation_level, tvb, offset, 4, TRUE);
		COUNT_BYTES(4);
	
		/* security flags */
		offset = dissect_nt_security_flags(tvb, pinfo, tree, offset);
		bc -= 1;

		/* file name */
		fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len, TRUE, TRUE, &bc);
		if (fn != NULL) {
			proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
				fn);
			COUNT_BYTES(fn_len);
		}

		break;
	case NT_TRANS_IOCTL:
		break;
	case NT_TRANS_SSD:
		/* fid */
		proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
		offset += 2;

		/* 2 reserved bytes */
		proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 2, TRUE);
		offset += 2;

		/* security information */
		offset = dissect_security_information_mask(tvb, pinfo, tree, offset);
		break;
	case NT_TRANS_NOTIFY:
		break;
	case NT_TRANS_RENAME:
		/* XXX not documented */
		break;
	case NT_TRANS_QSD:
		/* fid */
		proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
		offset += 2;

		/* 2 reserved bytes */
		proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 2, TRUE);
		offset += 2;

		/* security information */
		offset = dissect_security_information_mask(tvb, pinfo, tree, offset);
		break;
	}

	return offset;
}

static int
dissect_nt_trans_setup_request(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *parent_tree, int len, nt_trans_data *ntd)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	smb_info_t *si;
	int old_offset = offset;

	si = (smb_info_t *)pinfo->private_data;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, len,
				"%s Setup",
				val_to_str(ntd->subcmd, nt_cmd_vals, "Unknown NT transaction (%u)"));
		tree = proto_item_add_subtree(item, ett_smb_nt_trans_setup);
	}
 
	switch(ntd->subcmd){
	case NT_TRANS_CREATE:
		break;
	case NT_TRANS_IOCTL:
		/* function code */
		proto_tree_add_item(tree, hf_smb_nt_ioctl_function_code, tvb, offset, 4, TRUE);
		offset += 4;

		/* fid */
		proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
		offset += 2;

		/* isfsctl */
		proto_tree_add_item(tree, hf_smb_nt_ioctl_isfsctl, tvb, offset, 1, TRUE);
		offset += 1;

		/* isflags */
		offset = dissect_nt_ioctl_flags(tvb, pinfo, tree, offset);

		break;
	case NT_TRANS_SSD:
		break;
	case NT_TRANS_NOTIFY:
		/* completion filter */
		offset = dissect_nt_notify_completion_filter(tvb, pinfo, tree, offset);

		/* fid */
		proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
		offset += 2;

		/* watch tree */
		proto_tree_add_item(tree, hf_smb_nt_notify_watch_tree, tvb, offset, 1, TRUE);
		offset += 1;

		/* reserved byte */
		proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 1, TRUE);
		offset += 1;

		break;
	case NT_TRANS_RENAME:
		/* XXX not documented */
		break;
	case NT_TRANS_QSD:
		break;
	}
 
	return old_offset+len;
}


static int
dissect_nt_transaction_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc, sc;
	guint32 pc=0, po=0, pd, dc=0, od=0, dd;
	smb_info_t *si;
	smb_saved_info_t *sip;
	int subcmd;
	nt_trans_data ntd;
	guint16 bc;
	int padcnt;
	smb_nt_transact_info_t *nti;

	si = (smb_info_t *)pinfo->private_data;
	sip = si->sip;

	WORD_COUNT;

	if(wc>=19){
		/* primary request */
		/* max setup count */
		proto_tree_add_item(tree, hf_smb_max_setup_count, tvb, offset, 1, TRUE);
		offset += 1;

		/* 2 reserved bytes */
		proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 2, TRUE);
		offset += 2;
	} else {
		/* secondary request */
		/* 3 reserved bytes */
		proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 3, TRUE);
		offset += 3;
	}


	/* total param count */
	proto_tree_add_item(tree, hf_smb_total_param_count, tvb, offset, 4, TRUE);
	offset += 4;
	
	/* total data count */
	proto_tree_add_item(tree, hf_smb_total_data_count, tvb, offset, 4, TRUE);
	offset += 4;

	if(wc>=19){
		/* primary request */
		/* max param count */
		proto_tree_add_item(tree, hf_smb_max_param_count, tvb, offset, 4, TRUE);
		offset += 4;

		/* max data count */
		proto_tree_add_item(tree, hf_smb_max_data_count, tvb, offset, 4, TRUE);
		offset += 4;
	}

	/* param count */
	pc = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_param_count32, tvb, offset, 4, pc);
	offset += 4;
	
	/* param offset */
	po = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_param_offset32, tvb, offset, 4, po);
	offset += 4;

	/* param displacement */
	if(wc>=19){
		/* primary request*/
		pd = 0;
	} else {
		/* secondary request */
		pd = tvb_get_letohl(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_param_disp32, tvb, offset, 4, pd);
		offset += 4;
	}

	/* data count */
	dc = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_data_count32, tvb, offset, 4, dc);
	offset += 4;

	/* data offset */
	od = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_data_offset32, tvb, offset, 4, od);
	offset += 4;

	/* data displacement */
	if(wc>=19){
		/* primary request */
		dd = 0;
	} else {
		/* secondary request */
		dd = tvb_get_letohl(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_data_disp32, tvb, offset, 4, dd);
		offset += 4;
	}

	/* setup count */
	if(wc>=19){
		/* primary request */
		sc = tvb_get_guint8(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_setup_count, tvb, offset, 1, sc);
		offset += 1;
	} else {
		/* secondary request */
		sc = 0;
	}

	/* function */
	if(wc>=19){
		/* primary request */
		subcmd = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_nt_trans_subcmd, tvb, offset, 2, subcmd);
		if(check_col(pinfo->fd, COL_INFO)){
			col_append_fstr(pinfo->fd, COL_INFO, ", %s",
				val_to_str(subcmd, nt_cmd_vals, "<unknown>"));
		}
		ntd.subcmd = subcmd;
		if (!si->unidir) {
			if(!pinfo->fd->flags.visited){
				/* 
				 * Allocate a new smb_nt_transact_info_t
				 * structure.
				 */
				nti = g_mem_chunk_alloc(smb_nt_transact_info_chunk);
				nti->subcmd = subcmd;
				sip->extra_info = nti;
			}
		}
	} else {
		/* secondary request */
		if(check_col(pinfo->fd, COL_INFO)){
			col_append_fstr(pinfo->fd, COL_INFO, " (secondary request)");
		}
	}
	offset += 2;

	/* this is a padding byte */
	if(offset%1){
		/* pad byte */
	        proto_tree_add_item(tree, hf_smb_padding, tvb, offset, 1, TRUE);
		offset += 1;
	}

	/* if there were any setup bytes, decode them */
	if(sc){
		dissect_nt_trans_setup_request(tvb, pinfo, offset, tree, sc*2, &ntd);
		offset += sc*2;
	}

	BYTE_COUNT;
	
	/* parameters */
	if(po>(guint32)offset){
		/* We have some initial padding bytes.
		*/
		padcnt = po-offset;
		if (padcnt > bc)
			padcnt = bc;
	        proto_tree_add_item(tree, hf_smb_padding, tvb, offset, padcnt, TRUE);
		COUNT_BYTES(padcnt);
	}
	if(pc){
		CHECK_BYTE_COUNT(pc);
		dissect_nt_trans_param_request(tvb, pinfo, offset, tree, pc, &ntd, bc);
		COUNT_BYTES(pc);
	}

	/* data */
	if(od>(guint32)offset){
		/* We have some initial padding bytes.
		*/
		padcnt = od-offset;
		if (padcnt > bc)
			padcnt = bc;
	        proto_tree_add_item(tree, hf_smb_padding, tvb, offset, padcnt, TRUE);
		COUNT_BYTES(padcnt);
	}
	if(dc){
		CHECK_BYTE_COUNT(dc);
		dissect_nt_trans_data_request(tvb, pinfo, offset, tree, dc, &ntd);
		COUNT_BYTES(dc);
	}

	END_OF_SMB

	return offset;
}



static int
dissect_nt_trans_data_response(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *parent_tree, int len, nt_trans_data *ntd)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	smb_info_t *si;
	smb_nt_transact_info_t *nti;

	si = (smb_info_t *)pinfo->private_data;
	if (si->sip != NULL)
		nti = si->sip->extra_info;
	else
		nti = NULL;

	if(parent_tree){
		if(nti != NULL){
			item = proto_tree_add_text(parent_tree, tvb, offset, len,
				"%s Data",
				val_to_str(nti->subcmd, nt_cmd_vals, "Unknown NT Transaction (%u)"));
		} else {
			/*
			 * We never saw the request to which this is a
			 * response.
			 */
			item = proto_tree_add_text(parent_tree, tvb, offset, len,
				"Unknown NT Transaction Data (matching request not seen)");
		}
		tree = proto_item_add_subtree(item, ett_smb_nt_trans_setup);
	}

	if (nti == NULL) {
		offset += len;
		return offset;
	}
	switch(nti->subcmd){
	case NT_TRANS_CREATE:
		break;
	case NT_TRANS_IOCTL:
		/* ioctl data */
		proto_tree_add_item(tree, hf_smb_nt_ioctl_data, tvb, offset, len, TRUE);
		offset += len;

		break;
	case NT_TRANS_SSD:
		break;
	case NT_TRANS_NOTIFY:
		break;
	case NT_TRANS_RENAME:
		/* XXX not documented */
		break;
	case NT_TRANS_QSD:
		/*
		 * XXX - this is probably a SECURITY_DESCRIPTOR structure,
		 * which may be documented in the Win32 documentation
		 * somewhere.
		 */
		proto_tree_add_item(tree, hf_smb_security_descriptor, tvb, offset, len, TRUE);
		offset += len;
		break;
	}

	return offset;
}
 
static int
dissect_nt_trans_param_response(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *parent_tree, int len, nt_trans_data *ntd, guint16 bc)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint32 fn_len;
	const char *fn;
	smb_info_t *si;
	smb_nt_transact_info_t *nti;
	guint16 fid;

	si = (smb_info_t *)pinfo->private_data;
	if (si->sip != NULL)
		nti = si->sip->extra_info;
	else
		nti = NULL;

	if(parent_tree){
		if(nti != NULL){
			item = proto_tree_add_text(parent_tree, tvb, offset, len,
				"%s Parameters",
				val_to_str(nti->subcmd, nt_cmd_vals, "Unknown NT Transaction (%u)"));
		} else {
			/*
			 * We never saw the request to which this is a
			 * response.
			 */
			item = proto_tree_add_text(parent_tree, tvb, offset, len,
				"Unknown NT Transaction Parameters (matching request not seen)");
		}
		tree = proto_item_add_subtree(item, ett_smb_nt_trans_setup);
	}

	if (nti == NULL) {
		offset += len;
		return offset;
	}
	switch(nti->subcmd){
	case NT_TRANS_CREATE:
		/* oplock level */
	        proto_tree_add_item(tree, hf_smb_oplock_level, tvb, offset, 1, TRUE);
		offset += 1;

		/* reserved byte */
	        proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 1, TRUE);
		offset += 1;
		
		/* fid */
		fid = tvb_get_letohs(tvb, offset);
		add_fid(tvb, pinfo, tree, offset, 2, fid);
		offset += 2;

		/* create action */
		proto_tree_add_item(tree, hf_smb_create_action, tvb, offset, 4, TRUE);
		offset += 4;

		/* ea error offset */
		proto_tree_add_item(tree, hf_smb_ea_error_offset, tvb, offset, 4, TRUE);
		offset += 4;

		/* create time */
		offset = dissect_smb_64bit_time(tvb, pinfo, tree, offset,
			"Create Time", hf_smb_create_time);
	
		/* access time */
		offset = dissect_smb_64bit_time(tvb, pinfo, tree, offset,
			"Access Time", hf_smb_access_time);
	
		/* last write time */
		offset = dissect_smb_64bit_time(tvb, pinfo, tree, offset,
			"Write Time", hf_smb_last_write_time);
	
		/* last change time */
		offset = dissect_smb_64bit_time(tvb, pinfo, tree, offset,
			"Change Time", hf_smb_change_time);
	
		/* Extended File Attributes */
		offset = dissect_file_ext_attr(tvb, pinfo, tree, offset);

		/* allocation size */
		proto_tree_add_item(tree, hf_smb_alloc_size64, tvb, offset, 8, TRUE);
		offset += 8;

		/* end of file */
		proto_tree_add_item(tree, hf_smb_end_of_file, tvb, offset, 8, TRUE);
		offset += 8;

		/* File Type */
		proto_tree_add_item(tree, hf_smb_file_type, tvb, offset, 2, TRUE);
		offset += 2;

		/* device state */
		offset = dissect_ipc_state(tvb, pinfo, tree, offset, FALSE);

		/* is directory */
		proto_tree_add_item(tree, hf_smb_is_directory, tvb, offset, 1, TRUE);
		offset += 1;
		break;
	case NT_TRANS_IOCTL:
		break;
	case NT_TRANS_SSD:
		break;
	case NT_TRANS_NOTIFY:
		while(len){
			/* next entry offset */
			proto_tree_add_item(tree, hf_smb_next_entry_offset, tvb, offset, 4, TRUE);
			COUNT_BYTES(4);
			len -= 4;
			/* broken implementations */
			if(len<0)break;
	
			/* action */
			proto_tree_add_item(tree, hf_smb_nt_notify_action, tvb, offset, 4, TRUE);
			COUNT_BYTES(4);
			len -= 4;
			/* broken implementations */
			if(len<0)break;

			/* file name len */
			fn_len = (guint32)tvb_get_letohl(tvb, offset);
			proto_tree_add_uint(tree, hf_smb_file_name_len, tvb, offset, 4, fn_len);
			COUNT_BYTES(4);
			len -= 4;
			/* broken implementations */
			if(len<0)break;

			/* file name */
			fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len, TRUE, TRUE, &bc);
			if (fn == NULL)
				break;
			proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
				fn);
			COUNT_BYTES(fn_len);
			len -= fn_len;
			/* broken implementations */
			if(len<0)break;

		}
		break;
	case NT_TRANS_RENAME:
		/* XXX not documented */
		break;
	case NT_TRANS_QSD:
		/*
		 * This appears to be the size of the security
		 * descriptor; the calling sequence of
		 * "ZwQuerySecurityObject()" suggests that it would
		 * be.  The actual security descriptor wouldn't
		 * follow if the max data count in the request
		 * was smaller; this lets the client know how
		 * big a buffer it needs to provide.
		 */
		proto_tree_add_item(tree, hf_smb_security_descriptor_len, tvb, offset, 4, TRUE);
		offset += 4;
		break;
	}

	return offset;
}
 
static int
dissect_nt_trans_setup_response(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *parent_tree, int len, nt_trans_data *ntd)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	smb_info_t *si;
	smb_nt_transact_info_t *nti;

	si = (smb_info_t *)pinfo->private_data;
	if (si->sip != NULL)
		nti = si->sip->extra_info;
	else
		nti = NULL;

	if(parent_tree){
		if(nti != NULL){
			item = proto_tree_add_text(parent_tree, tvb, offset, len,
				"%s Setup",
				val_to_str(nti->subcmd, nt_cmd_vals, "Unknown NT Transaction (%u)"));
		} else {
			/*
			 * We never saw the request to which this is a
			 * response.
			 */
			item = proto_tree_add_text(parent_tree, tvb, offset, len,
				"Unknown NT Transaction Setup (matching request not seen)");
		}
		tree = proto_item_add_subtree(item, ett_smb_nt_trans_setup);
	}

	if (nti == NULL) {
		offset += len;
		return offset;
	}
	switch(nti->subcmd){
	case NT_TRANS_CREATE:
		break;
	case NT_TRANS_IOCTL:
		break;
	case NT_TRANS_SSD:
		break;
	case NT_TRANS_NOTIFY:
		break;
	case NT_TRANS_RENAME:
		/* XXX not documented */
		break;
	case NT_TRANS_QSD:
		break;
	}

	return offset;
}

static int
dissect_nt_transaction_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc, sc;
	guint32 pc=0, po=0, pd, dc=0, od=0, dd;
	smb_info_t *si;
	smb_nt_transact_info_t *nti;
	static nt_trans_data ntd;
	guint16 bc;
	int padcnt;

	si = (smb_info_t *)pinfo->private_data;
	if (si->sip != NULL)
		nti = si->sip->extra_info;
	else
		nti = NULL;

	/* primary request */
	if(nti != NULL){
		proto_tree_add_uint(tree, hf_smb_nt_trans_subcmd, tvb, 0, 0, nti->subcmd);
		if(check_col(pinfo->fd, COL_INFO)){
			col_append_fstr(pinfo->fd, COL_INFO, ", %s",
				val_to_str(nti->subcmd, nt_cmd_vals, "<unknown (%u)>"));
		}
	} else {
		proto_tree_add_text(tree, tvb, offset, 0,
			"Function: <unknown function - could not find matching request>");
		if(check_col(pinfo->fd, COL_INFO)){
			col_append_fstr(pinfo->fd, COL_INFO, ", <unknown>");
		}
	}

	WORD_COUNT;

	/* 3 reserved bytes */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 3, TRUE);
	offset += 3;

	/* total param count */
	proto_tree_add_item(tree, hf_smb_total_param_count, tvb, offset, 4, TRUE);
	offset += 4;
	
	/* total data count */
	proto_tree_add_item(tree, hf_smb_total_data_count, tvb, offset, 4, TRUE);
	offset += 4;

	/* param count */
	pc = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_param_count32, tvb, offset, 4, pc);
	offset += 4;
	
	/* param offset */
	po = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_param_offset32, tvb, offset, 4, po);
	offset += 4;

	/* param displacement */
	pd = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_param_disp32, tvb, offset, 4, pd);
	offset += 4;

	/* data count */
	dc = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_data_count32, tvb, offset, 4, dc);
	offset += 4;

	/* data offset */
	od = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_data_offset32, tvb, offset, 4, od);
	offset += 4;

	/* data displacement */
	dd = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_data_disp32, tvb, offset, 4, dd);
	offset += 4;

	/* setup count */
	sc = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_setup_count, tvb, offset, 1, sc);
	offset += 1;

	/* setup data */	
	if(sc){
		dissect_nt_trans_setup_response(tvb, pinfo, offset, tree, sc*2, &ntd);
		offset += sc*2;
	}

	BYTE_COUNT;
	
	/* parameters */
	if(po>(guint32)offset){
		/* We have some initial padding bytes.
		*/
		padcnt = po-offset;
		if (padcnt > bc)
			padcnt = bc;
	        proto_tree_add_item(tree, hf_smb_padding, tvb, offset, padcnt, TRUE);
		COUNT_BYTES(padcnt);
	}
	if(pc){
		CHECK_BYTE_COUNT(pc);
		dissect_nt_trans_param_response(tvb, pinfo, offset, tree, pc, &ntd, bc);
		COUNT_BYTES(pc);
	}

	/* data */
	if(od>(guint32)offset){
		/* We have some initial padding bytes.
		*/
		padcnt = od-offset;
		if (padcnt > bc)
			padcnt = bc;
	        proto_tree_add_item(tree, hf_smb_padding, tvb, offset, padcnt, TRUE);
		COUNT_BYTES(padcnt);
	}
	if(dc){
		CHECK_BYTE_COUNT(dc);
		dissect_nt_trans_data_response(tvb, pinfo, offset, tree, dc, &ntd);
		COUNT_BYTES(dc);
	}

	END_OF_SMB

	return offset;
}

/* XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   NT Transaction command  ends here
   XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX */

static const value_string print_mode_vals[] = {
	{0,	"Text Mode"},
	{1,	"Graphics Mode"},
	{0, NULL}
};
 
static int
dissect_open_print_file_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	int fn_len;
	const char *fn;
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* setup len */
        proto_tree_add_item(tree, hf_smb_setup_len, tvb, offset, 2, TRUE);
	offset += 2;

	/* print mode */
        proto_tree_add_item(tree, hf_smb_print_mode, tvb, offset, 2, TRUE);
	offset += 2;

	BYTE_COUNT;

	/* buffer format */
	CHECK_BYTE_COUNT(1);
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	COUNT_BYTES(1);

	/* print identifier */
	fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len, TRUE, FALSE, &bc);
	if (fn == NULL)
		goto endofcommand;
	proto_tree_add_string(tree, hf_smb_print_identifier, tvb, offset, fn_len,
		fn);
	COUNT_BYTES(fn_len);

	END_OF_SMB

	return offset;
}


static int
dissect_write_print_file_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	int cnt;
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* fid */
	proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
	offset += 2;

	BYTE_COUNT;

	/* buffer format */
	CHECK_BYTE_COUNT(1);
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	COUNT_BYTES(1);

	/* data len */
	CHECK_BYTE_COUNT(2);
	cnt = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_data_len, tvb, offset, 2, cnt);
	COUNT_BYTES(2);

	/* file data */
	offset = dissect_file_data(tvb, pinfo, tree, offset, cnt, cnt);

	END_OF_SMB

	return offset;
}


static const value_string print_status_vals[] = {
	{1,	"Held or Stopped"},
	{2,	"Printing"},
	{3,	"Awaiting print"},
	{4,	"In intercept"},
	{5,	"File had error"},
	{6,	"Printer error"},
	{0, NULL}
};
 
static int
dissect_get_print_queue_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* max count */
	proto_tree_add_item(tree, hf_smb_max_count, tvb, offset, 2, TRUE);
	offset += 2;

	/* start index */
	proto_tree_add_item(tree, hf_smb_start_index, tvb, offset, 2, TRUE);
	offset += 2;

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

static int
dissect_print_queue_element(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *parent_tree, int offset, guint16 *bcp, gboolean *trunc)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int fn_len;
	const char *fn;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 28,
			"Queue entry");
		tree = proto_item_add_subtree(item, ett_smb_print_queue_entry);
	}

	/* queued time */
	CHECK_BYTE_COUNT_SUBR(4);
	offset = dissect_smb_datetime(tvb, pinfo, tree, offset,
		hf_smb_print_queue_date,
		hf_smb_print_queue_dos_date, hf_smb_print_queue_dos_time, FALSE);
	*bcp -= 4;

	/* status */
	CHECK_BYTE_COUNT_SUBR(1);
	proto_tree_add_item(tree, hf_smb_print_status, tvb, offset, 1, TRUE);
	COUNT_BYTES_SUBR(1);

	/* spool file number */
	CHECK_BYTE_COUNT_SUBR(2);
	proto_tree_add_item(tree, hf_smb_print_spool_file_number, tvb, offset, 2, TRUE);
	COUNT_BYTES_SUBR(2);

	/* spool file size */
	CHECK_BYTE_COUNT_SUBR(4);
	proto_tree_add_item(tree, hf_smb_print_spool_file_size, tvb, offset, 4, TRUE);
	COUNT_BYTES_SUBR(4);

	/* reserved byte */
	CHECK_BYTE_COUNT_SUBR(1);
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 1, TRUE);
	COUNT_BYTES_SUBR(1);

	/* file name */
	fn_len = 16;
	fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len, TRUE, TRUE, bcp);
	CHECK_STRING_SUBR(fn);
	proto_tree_add_string(tree, hf_smb_print_spool_file_name, tvb, offset, 16,
		fn);
	COUNT_BYTES_SUBR(fn_len);

	*trunc = FALSE;
	return offset;
}

static int
dissect_get_print_queue_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint16 cnt=0, len;
	guint8 wc;
	guint16 bc;
	gboolean trunc;

	WORD_COUNT;

	/* count */
	cnt = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_count, tvb, offset, 2, cnt);
	offset += 2;

	/* restart index */
	proto_tree_add_item(tree, hf_smb_restart_index, tvb, offset, 2, TRUE);
	offset += 2;

	BYTE_COUNT;

	/* buffer format */
	CHECK_BYTE_COUNT(1);
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	COUNT_BYTES(1);

	/* data len */
	CHECK_BYTE_COUNT(2);
	len = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_data_len, tvb, offset, 2, len);
	COUNT_BYTES(2);

	/* queue elements */
	while(cnt--){
		offset = dissect_print_queue_element(tvb, pinfo, tree, offset,
		    &bc, &trunc);
		if (trunc)
			goto endofcommand;
	}

	END_OF_SMB

	return offset;
}


static int
dissect_nt_create_andx_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8	wc, cmd=0xff;
	guint16 andxoffset=0;
	guint16 bc;
	int fn_len;
	const char *fn;

	WORD_COUNT;

	/* next smb command */
	cmd = tvb_get_guint8(tvb, offset);
	if(cmd!=0xff){
		proto_tree_add_uint_format(tree, hf_smb_cmd, tvb, offset, 1, cmd, "AndXCommand: %s (0x%02x)", decode_smb_name(cmd), cmd);
	} else {
		proto_tree_add_uint_format(tree, hf_smb_cmd, tvb, offset, 1, cmd, "AndXCommand: No further commands (0xff)");
	}
	offset += 1;

	/* reserved byte */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 1, TRUE);
	offset += 1;

	/* andxoffset */
	andxoffset = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_andxoffset, tvb, offset, 2, andxoffset);
	offset += 2;

	/* reserved byte */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 1, TRUE);
	offset += 1;

	/* file name len */
	fn_len = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_file_name_len, tvb, offset, 2, fn_len);
	offset += 2;

	/* Create flags */
	offset = dissect_nt_create_bits(tvb, pinfo, tree, offset);

	/* root directory fid */
	proto_tree_add_item(tree, hf_smb_root_dir_fid, tvb, offset, 4, TRUE);
	offset += 4;

	/* nt access mask */
	offset = dissect_nt_access_mask(tvb, pinfo, tree, offset);

	/* allocation size */
	proto_tree_add_item(tree, hf_smb_alloc_size64, tvb, offset, 8, TRUE);
	offset += 8;

	/* Extended File Attributes */
	offset = dissect_file_ext_attr(tvb, pinfo, tree, offset);

	/* share access */
	offset = dissect_nt_share_access(tvb, pinfo, tree, offset);

	/* create disposition */
	proto_tree_add_item(tree, hf_smb_nt_create_disposition, tvb, offset, 4, TRUE);
	offset += 4;

	/* create options */
	offset = dissect_nt_create_options(tvb, pinfo, tree, offset);

	/* impersonation level */
	proto_tree_add_item(tree, hf_smb_nt_impersonation_level, tvb, offset, 4, TRUE);
	offset += 4;

	/* security flags */
	offset = dissect_nt_security_flags(tvb, pinfo, tree, offset);

	BYTE_COUNT;

	/* file name */
	fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len, FALSE, FALSE, &bc);
	if (fn == NULL)
		goto endofcommand;
	proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
		fn);
	COUNT_BYTES(fn_len);

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, ", Path: %s", fn);
	}

	END_OF_SMB

	/* call AndXCommand (if there are any) */
	dissect_smb_command(tvb, pinfo, tree, andxoffset, smb_tree, cmd);

	return offset;
}
 

static int
dissect_nt_create_andx_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8	wc, cmd=0xff;
	guint16 andxoffset=0;
	guint16 bc;
	guint16 fid;

	WORD_COUNT;

	/* next smb command */
	cmd = tvb_get_guint8(tvb, offset);
	if(cmd!=0xff){
		proto_tree_add_uint_format(tree, hf_smb_cmd, tvb, offset, 1, cmd, "AndXCommand: %s (0x%02x)", decode_smb_name(cmd), cmd);
	} else {
		proto_tree_add_uint_format(tree, hf_smb_cmd, tvb, offset, 1, cmd, "AndXCommand: No further commands");
	}
	offset += 1;

	/* reserved byte */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 1, TRUE);
	offset += 1;

	/* andxoffset */
	andxoffset = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_andxoffset, tvb, offset, 2, andxoffset);
	offset += 2;

	/* oplock level */
	proto_tree_add_item(tree, hf_smb_oplock_level, tvb, offset, 1, TRUE);
	offset += 1;

	/* fid */
	fid = tvb_get_letohs(tvb, offset);
	add_fid(tvb, pinfo, tree, offset, 2, fid);
	offset += 2;

	/* create action */
	/*XXX is this really the same as create disposition in the request? it looks so*/
	proto_tree_add_item(tree, hf_smb_create_action, tvb, offset, 4, TRUE);
	offset += 4;

	/* create time */
	offset = dissect_smb_64bit_time(tvb, pinfo, tree, offset,
		"Create Time", hf_smb_create_time);
	
	/* access time */
	offset = dissect_smb_64bit_time(tvb, pinfo, tree, offset,
		"Access Time", hf_smb_access_time);
	
	/* last write time */
	offset = dissect_smb_64bit_time(tvb, pinfo, tree, offset,
		"Write Time", hf_smb_last_write_time);
	
	/* last change time */
	offset = dissect_smb_64bit_time(tvb, pinfo, tree, offset,
		"Change Time", hf_smb_change_time);
	
	/* Extended File Attributes */
	offset = dissect_file_ext_attr(tvb, pinfo, tree, offset);

	/* allocation size */
	proto_tree_add_item(tree, hf_smb_alloc_size64, tvb, offset, 8, TRUE);
	offset += 8;

	/* end of file */
	proto_tree_add_item(tree, hf_smb_end_of_file, tvb, offset, 8, TRUE);
	offset += 8;

	/* File Type */
	proto_tree_add_item(tree, hf_smb_file_type, tvb, offset, 2, TRUE);
	offset += 2;

	/* IPC State */
	offset = dissect_ipc_state(tvb, pinfo, tree, offset, FALSE);

	/* is directory */
	proto_tree_add_item(tree, hf_smb_is_directory, tvb, offset, 1, TRUE);
	offset += 1;

	BYTE_COUNT;

	END_OF_SMB

	/* call AndXCommand (if there are any) */
	dissect_smb_command(tvb, pinfo, tree, andxoffset, smb_tree, cmd);

	return offset;
}


static int
dissect_nt_cancel_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;

	WORD_COUNT;
 
	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

/* XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   BEGIN Transaction/Transaction2 Primary and secondary requests
   XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX */


static const value_string trans2_cmd_vals[] = {
	{ 0x00,		"OPEN2" },
	{ 0x01,		"FIND_FIRST2" },
	{ 0x02,		"FIND_NEXT2" },
	{ 0x03,		"QUERY_FS_INFORMATION" },
	{ 0x05,		"QUERY_PATH_INFORMATION" },
	{ 0x06,		"SET_PATH_INFORMATION" },
	{ 0x07,		"QUERY_FILE_INFORMATION" },
	{ 0x08,		"SET_FILE_INFORMATION" },
	{ 0x09,		"FSCTL" },
	{ 0x0A,		"IOCTL2" },
	{ 0x0B,		"FIND_NOTIFY_FIRST" },
	{ 0x0C,		"FIND_NOTIFY_NEXT" },
	{ 0x0D,		"CREATE_DIRECTORY" },
	{ 0x0E,		"SESSION_SETUP" },
	{ 0x10,		"GET_DFS_REFERRAL" },
	{ 0x11,		"REPORT_DFS_INCONSISTENCY" },
	{ 0,    NULL }
};

static const true_false_string tfs_tf_dtid = {
	"Also DISCONNECT TID",
	"Do NOT disconnect TID"
};
static const true_false_string tfs_tf_owt = {
	"One Way Transaction (NO RESPONSE)",
	"Two way transaction"
};

static const true_false_string tfs_ff2_backup = {
	"Find WITH backup intent",
	"No backup intent"
};
static const true_false_string tfs_ff2_continue = {
	"CONTINUE search from previous position",
	"New search, do NOT continue from previous position"
};
static const true_false_string tfs_ff2_resume = {
	"Return RESUME keys",
	"Do NOT return resume keys"
};
static const true_false_string tfs_ff2_close_eos = {
	"CLOSE search if END OF SEARCH is reached",
	"Do NOT close search if end of search reached"
};
static const true_false_string tfs_ff2_close = {
	"CLOSE search after this request",
	"Do NOT close search after this request"
};

/* used by
   TRANS2_FIND_FIRST2
*/
static const value_string ff2_il_vals[] = {
	{ 1,		"Info Standard  (4.3.4.1)"},
	{ 2,		"Info Query EA Size  (4.3.4.2)"},
	{ 3,		"Info Query EAs From List  (4.3.4.2)"},
	{ 0x0101,	"Find File Directory Info  (4.3.4.4)"},
	{ 0x0102,	"Find File Full Directory Info  (4.3.4.5)"},
	{ 0x0103,	"Find File Names Info  (4.3.4.7)"},
	{ 0x0104,	"Find File Both Directory Info  (4.3.4.6)"},
	{ 0x0202,	"Find File UNIX  (4.3.4.8)"},
	{0, NULL}
};

/* values used by :
	TRANS2_QUERY_PATH_INFORMATION
	TRANS2_SET_PATH_INFORMATION
*/
static const value_string qpi_loi_vals[] = {
	{ 1,		"Info Standard  (4.2.14.1)"},
	{ 2,		"Info Query EA Size  (4.2.14.1)"},
	{ 3,		"Info Query EAs From List  (4.2.14.2)"},
	{ 4,		"Info Query All EAs  (4.2.14.2)"},
	{ 6,		"Info Is Name Valid  (4.2.14.3)"},
	{ 0x0101,	"Query File Basic Info  (4.2.14.4)"},
	{ 0x0102,	"Query File Standard Info  (4.2.14.5)"},
	{ 0x0103,	"Query File EA Info  (4.2.14.6)"},
	{ 0x0104,	"Query File Name Info  (4.2.14.7)"},
	{ 0x0107,	"Query File All Info  (4.2.14.8)"},
	{ 0x0108,	"Query File Alt File Info  (4.2.14.7)"},
	{ 0x0109,	"Query File Stream Info  (4.2.14.10)"},
	{ 0x010b,	"Query File Compression Info  (4.2.14.11)"},
	{ 0x0200,	"Set File Unix Basic"},
	{ 0x0201,	"Set File Unix Link"},
	{ 0x0202,	"Set File Unix HardLink"},
	{0, NULL}
};

static const value_string qfsi_vals[] = {
	{ 1,		"Info Allocation"},
	{ 2,		"Info Volume"},
	{ 0x0102,	"Query FS Volume Info"},
	{ 0x0103,	"Query FS Size Info"},
	{ 0x0104,	"Query FS Device Info"},
	{ 0x0105,	"Query FS Attribute Info"},
	{0, NULL}
};

static const value_string delete_pending_vals[] = {
	{0,	"Normal, no pending delete"},
	{1,	"This object has DELETE PENDING"},
	{0, NULL}
};

static const value_string alignment_vals[] = {
	{0,	"Byte alignment"},
	{1,	"Word (16bit) alignment"},
	{3,	"Long (32bit) alignment"},
	{7,	"8 byte boundary alignment"},
	{0x0f,	"16 byte boundary alignment"},
	{0x1f,	"32 byte boundary alignment"},
	{0x3f,	"64 byte boundary alignment"},
	{0x7f,	"128 byte boundary alignment"},
	{0xff,	"256 byte boundary alignment"},
	{0x1ff,	"512 byte boundary alignment"},
	{0, NULL}
};


static const true_false_string tfs_get_dfs_server_hold_storage = {
	"Referral SERVER HOLDS STORAGE for the file",
	"Referral server does NOT hold storage for the file"
};
static const true_false_string tfs_get_dfs_fielding = {
	"The server in referral is FIELDING CAPABLE",
	"The server in referrals is NOT fielding capable"
};

static const true_false_string tfs_dfs_referral_flags_strip = {
	"STRIP off pathconsumed characters before submitting",
	"Do NOT strip off any characters"
};

static const value_string dfs_referral_server_type_vals[] = {
	{0,	"Don't know"},
	{1,	"SMB Server"},
	{2,	"Netware Server"},
	{3,	"Domain Server"},
	{0, NULL}
};


static const true_false_string tfs_device_char_removable = {
	"This is a REMOVABLE device",
	"This is NOT a removable device"
};
static const true_false_string tfs_device_char_read_only = {
	"This is a READ-ONLY device",
	"This is NOT a read-only device"
};
static const true_false_string tfs_device_char_floppy = {
	"This is a FLOPPY DISK device",
	"This is NOT a floppy disk device"
};
static const true_false_string tfs_device_char_write_once = {
	"This is a WRITE-ONCE device",
	"This is NOT a write-once device"
};
static const true_false_string tfs_device_char_remote = {
	"This is a REMOTE device",
	"This is NOT a remote device"
};
static const true_false_string tfs_device_char_mounted = {
	"This device is MOUNTED",
	"This device is NOT mounted"
};
static const true_false_string tfs_device_char_virtual = {
	"This is a VIRTUAL device",
	"This is NOT a virtual device"
};


static const true_false_string tfs_fs_attr_css = {
	"This FS supports CASE SENSITIVE SEARCHes",
	"This FS does NOT support case sensitive searches"
};
static const true_false_string tfs_fs_attr_cpn = {
	"This FS supports CASE PRESERVED NAMES",
	"This FS does NOT support case preserved names"
};
static const true_false_string tfs_fs_attr_pacls = {
	"This FS supports PERSISTENT ACLs",
	"This FS does NOT support persistent acls"
};
static const true_false_string tfs_fs_attr_fc = {
	"This FS supports COMPRESSED FILES",
	"This FS does NOT support compressed files"
};
static const true_false_string tfs_fs_attr_vq = {
	"This FS supports VOLUME QUOTAS",
	"This FS does NOT support volume quotas"
};
static const true_false_string tfs_fs_attr_dim = {
	"This FS is on a MOUNTED DEVICE",
	"This FS is NOT on a mounted device"
};
static const true_false_string tfs_fs_attr_vic = {
	"This FS is on a COMPRESSED VOLUME",
	"This FS is NOT on a compressed volume"
};



static int
dissect_ff2_flags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint16 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohs(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 2,
			"Flags: 0x%04x", mask);
		tree = proto_item_add_subtree(item, ett_smb_find_first2_flags);
	}

	proto_tree_add_boolean(tree, hf_smb_ff2_backup,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_ff2_continue,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_ff2_resume,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_ff2_close_eos,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_ff2_close,
		tvb, offset, 2, mask);

	offset += 2;

	return offset;
}

static int
dissect_transaction2_request_parameters(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *parent_tree, int offset, int subcmd, guint16 bc)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	smb_info_t *si;
	smb_transact2_info_t *t2i;
	int fn_len;
	const char *fn;
	int old_offset = offset;

	si = (smb_info_t *)pinfo->private_data;
	if (si->sip != NULL)
		t2i = si->sip->extra_info;
	else
		t2i = NULL;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, bc,
				"%s Parameters",
				val_to_str(subcmd, trans2_cmd_vals, 
					   "Unknown (0x%02x)"));
		tree = proto_item_add_subtree(item, ett_smb_transaction_params);
	}

	switch(subcmd){
	case 0x00:	/*TRANS2_OPEN2*/
		/* open flags */
		CHECK_BYTE_COUNT_TRANS(2);
		offset = dissect_open_flags(tvb, pinfo, tree, offset, 0x000f);
		bc -= 2;

		/* desired access */
		CHECK_BYTE_COUNT_TRANS(2);
		offset = dissect_access(tvb, pinfo, tree, offset, "Desired");
		bc -= 2;

		/* 2 reserved bytes */
		CHECK_BYTE_COUNT_TRANS(2);
		proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 2, TRUE);
		COUNT_BYTES_TRANS(2);

		/* File Attributes */
		CHECK_BYTE_COUNT_TRANS(2);
		offset = dissect_file_attributes(tvb, pinfo, tree, offset);
		bc -= 2;

		/* create time */
		CHECK_BYTE_COUNT_TRANS(4);
		offset = dissect_smb_datetime(tvb, pinfo, tree, offset,
			hf_smb_create_time,
			hf_smb_create_dos_date, hf_smb_create_dos_time,
			TRUE);
		bc -= 4;

		/* open function */
		CHECK_BYTE_COUNT_TRANS(2);
		offset = dissect_open_function(tvb, pinfo, tree, offset);
		bc -= 2;

		/* allocation size */
		CHECK_BYTE_COUNT_TRANS(4);
		proto_tree_add_item(tree, hf_smb_alloc_size, tvb, offset, 4, TRUE);
		COUNT_BYTES_TRANS(4);

		/* 10 reserved bytes */
		CHECK_BYTE_COUNT_TRANS(10);
		proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 10, TRUE);
		COUNT_BYTES_TRANS(10);

		/* file name */
		fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len, FALSE, FALSE, &bc);
		CHECK_STRING_TRANS(fn);
		proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
			fn);
		COUNT_BYTES_TRANS(fn_len);

		if (check_col(pinfo->fd, COL_INFO)) {
			col_append_fstr(pinfo->fd, COL_INFO, ", Path: %s",
			fn);
		}

		/* XXX dont know how to decode FEAList */
		break;
	case 0x01:	/*TRANS2_FIND_FIRST2*/
		/* Search Attributes */
		CHECK_BYTE_COUNT_TRANS(2);
		offset = dissect_search_attributes(tvb, pinfo, tree, offset);
		bc -= 2;

		/* search count */
		CHECK_BYTE_COUNT_TRANS(2);
		proto_tree_add_item(tree, hf_smb_search_count, tvb, offset, 2, TRUE);
		COUNT_BYTES_TRANS(2);

		/* Find First2 flags */
		CHECK_BYTE_COUNT_TRANS(2);
		offset = dissect_ff2_flags(tvb, pinfo, tree, offset);
		bc -= 2;

		/* Find First2 information level */
		CHECK_BYTE_COUNT_TRANS(2);
		si->info_level = tvb_get_letohs(tvb, offset);
		if (!pinfo->fd->flags.visited)
			t2i->info_level = si->info_level;
		proto_tree_add_uint(tree, hf_smb_ff2_information_level, tvb, offset, 2, si->info_level);
		COUNT_BYTES_TRANS(2);

		/* storage type */
		CHECK_BYTE_COUNT_TRANS(4);
		proto_tree_add_item(tree, hf_smb_storage_type, tvb, offset, 4, TRUE);
		COUNT_BYTES_TRANS(4);

		/* search pattern */
		fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len, FALSE, FALSE, &bc);
		CHECK_STRING_TRANS(fn);
		proto_tree_add_string(tree, hf_smb_search_pattern, tvb, offset, fn_len,
			fn);
		COUNT_BYTES_TRANS(fn_len);

		if (check_col(pinfo->fd, COL_INFO)) {
			col_append_fstr(pinfo->fd, COL_INFO, ", Pattern: %s",
			fn);
		}

		/* XXX dont know how to decode FEAList */

		break;
	case 0x02:	/*TRANS2_FIND_NEXT2*/
		/* sid */
		CHECK_BYTE_COUNT_TRANS(2);
		proto_tree_add_item(tree, hf_smb_sid, tvb, offset, 2, TRUE);
		COUNT_BYTES_TRANS(2);

		/* search count */
		CHECK_BYTE_COUNT_TRANS(2);
		proto_tree_add_item(tree, hf_smb_search_count, tvb, offset, 2, TRUE);
		COUNT_BYTES_TRANS(2);

		/* Find First2 information level */
		CHECK_BYTE_COUNT_TRANS(2);
		si->info_level = tvb_get_letohs(tvb, offset);
		if (!pinfo->fd->flags.visited)
			t2i->info_level = si->info_level;
		proto_tree_add_uint(tree, hf_smb_ff2_information_level, tvb, offset, 2, si->info_level);
		COUNT_BYTES_TRANS(2);

		/* resume key */
		CHECK_BYTE_COUNT_TRANS(4);
		proto_tree_add_item(tree, hf_smb_resume, tvb, offset, 4, TRUE);
		COUNT_BYTES_TRANS(4);

		/* Find First2 flags */
		CHECK_BYTE_COUNT_TRANS(2);
		offset = dissect_ff2_flags(tvb, pinfo, tree, offset);
		bc -= 2;

		/* file name */
		fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len, FALSE, FALSE, &bc);
		CHECK_STRING_TRANS(fn);
		proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
			fn);
		COUNT_BYTES_TRANS(fn_len);

		if (check_col(pinfo->fd, COL_INFO)) {
			col_append_fstr(pinfo->fd, COL_INFO, ", Continue: %s",
			fn);
		}

		break;
	case 0x03:	/*TRANS2_QUERY_FS_INFORMATION*/
		/* level of interest */
		CHECK_BYTE_COUNT_TRANS(2);
		si->info_level = tvb_get_letohs(tvb, offset);
		if (!pinfo->fd->flags.visited)
			t2i->info_level = si->info_level;
		proto_tree_add_uint(tree, hf_smb_qfsi_information_level, tvb, offset, 2, si->info_level);
		COUNT_BYTES_TRANS(2);

		break;
	case 0x05:	/*TRANS2_QUERY_PATH_INFORMATION*/
		/* level of interest */
		CHECK_BYTE_COUNT_TRANS(2);
		si->info_level = tvb_get_letohs(tvb, offset);
		if (!pinfo->fd->flags.visited)
			t2i->info_level = si->info_level;
		proto_tree_add_uint(tree, hf_smb_qpi_loi, tvb, offset, 2, si->info_level);
		COUNT_BYTES_TRANS(2);
		
		/* 4 reserved bytes */
		CHECK_BYTE_COUNT_TRANS(4);
		proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 4, TRUE);
		COUNT_BYTES_TRANS(4);

		/* file name */
		fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len, FALSE, FALSE, &bc);
		CHECK_STRING_TRANS(fn);
		proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
			fn);
		COUNT_BYTES_TRANS(fn_len);

		if (check_col(pinfo->fd, COL_INFO)) {
			col_append_fstr(pinfo->fd, COL_INFO, ", Path: %s",
			fn);
		}

		break;
	case 0x06:	/*TRANS2_SET_PATH_INFORMATION*/
		/* level of interest */
		CHECK_BYTE_COUNT_TRANS(2);
		si->info_level = tvb_get_letohs(tvb, offset);
		if (!pinfo->fd->flags.visited)
			t2i->info_level = si->info_level;
		proto_tree_add_uint(tree, hf_smb_qpi_loi, tvb, offset, 2, si->info_level);
		COUNT_BYTES_TRANS(2);
		
		/* 4 reserved bytes */
		CHECK_BYTE_COUNT_TRANS(4);
		proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 4, TRUE);
		COUNT_BYTES_TRANS(4);

		/* file name */
		fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len, FALSE, FALSE, &bc);
		CHECK_STRING_TRANS(fn);
		proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
			fn);
		COUNT_BYTES_TRANS(fn_len);

		if (check_col(pinfo->fd, COL_INFO)) {
			col_append_fstr(pinfo->fd, COL_INFO, ", Path: %s",
			fn);
		}

		break;
	case 0x07:	/*TRANS2_QUERY_FILE_INFORMATION*/
		/* fid */
		CHECK_BYTE_COUNT_TRANS(2);
		proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
		COUNT_BYTES_TRANS(2);

		/* level of interest */
		CHECK_BYTE_COUNT_TRANS(2);
		si->info_level = tvb_get_letohs(tvb, offset);
		if (!pinfo->fd->flags.visited)
			t2i->info_level = si->info_level;
		proto_tree_add_uint(tree, hf_smb_qpi_loi, tvb, offset, 2, si->info_level);
		COUNT_BYTES_TRANS(2);
		
		break;
	case 0x08:	/*TRANS2_SET_FILE_INFORMATION*/
		/* fid */
		CHECK_BYTE_COUNT_TRANS(2);
		proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
		COUNT_BYTES_TRANS(2);

		/* level of interest */
		CHECK_BYTE_COUNT_TRANS(2);
		si->info_level = tvb_get_letohs(tvb, offset);
		if (!pinfo->fd->flags.visited)
			t2i->info_level = si->info_level;
		proto_tree_add_uint(tree, hf_smb_qpi_loi, tvb, offset, 2, si->info_level);
		COUNT_BYTES_TRANS(2);
		
		/* 2 reserved bytes */
		CHECK_BYTE_COUNT_TRANS(2);
		proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 2, TRUE);
		COUNT_BYTES_TRANS(2);

		break;
	case 0x09:	/*TRANS2_FSCTL*/
	case 0x0a:	/*TRANS2_IOCTL2*/
		/* these calls have no parameter block in the request */
		break;
	case 0x0b:	/*TRANS2_FIND_NOTIFY_FIRST*/
	case 0x0c:	/*TRANS2_FIND_NOTIFY_NEXT*/
		/* XXX unknown structure*/
		break;
	case 0x0d:	/*TRANS2_CREATE_DIRECTORY*/
		/* 4 reserved bytes */
		CHECK_BYTE_COUNT_TRANS(4);
		proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 4, TRUE);
		COUNT_BYTES_TRANS(4);

		/* dir name */
		fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len,
			FALSE, FALSE, &bc);
		CHECK_STRING_TRANS(fn);
		proto_tree_add_string(tree, hf_smb_dir_name, tvb, offset, fn_len,
			fn);
		COUNT_BYTES_TRANS(fn_len);

		if (check_col(pinfo->fd, COL_INFO)) {
			col_append_fstr(pinfo->fd, COL_INFO, ", Dir: %s",
			fn);
		}

		/* XXX optional FEAList, unknown what FEAList looks like*/
		break;
	case 0x0e:	/*TRANS2_SESSION_SETUP*/
		/* XXX unknown structure*/
		break;
	case 0x10:	/*TRANS2_GET_DFS_REFERRAL*/
		/* referral level */
		CHECK_BYTE_COUNT_TRANS(2);
		proto_tree_add_item(tree, hf_smb_max_referral_level, tvb, offset, 2, TRUE);
		COUNT_BYTES_TRANS(2);
		
		/* file name */
		fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len, FALSE, FALSE, &bc);
		CHECK_STRING_TRANS(fn);
		proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
			fn);
		COUNT_BYTES_TRANS(fn_len);

		if (check_col(pinfo->fd, COL_INFO)) {
			col_append_fstr(pinfo->fd, COL_INFO, ", File: %s",
			fn);
		}

		break;
	case 0x11:	/*TRANS2_REPORT_DFS_INCONSISTENCY*/
		/* file name */
		fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len, FALSE, FALSE, &bc);
		CHECK_STRING_TRANS(fn);
		proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
			fn);
		COUNT_BYTES_TRANS(fn_len);

		if (check_col(pinfo->fd, COL_INFO)) {
			col_append_fstr(pinfo->fd, COL_INFO, ", File: %s",
			fn);
		}

		break;
	}

	/* ooops there were data we didnt know how to process */
	if((offset-old_offset) < bc){
		proto_tree_add_bytes(tree, hf_smb_unknown, tvb, offset, bc - (offset-old_offset), tvb_get_ptr(tvb, offset, 1));
		offset += bc - (offset-old_offset);
	}

	return offset;
}

/*
 * XXX - just use "dissect_connect_flags()" here?
 */
static guint16
dissect_transaction_flags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint16 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohs(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 2,
			"Flags: 0x%04x", mask);
		tree = proto_item_add_subtree(item, ett_smb_transaction_flags);
	}

	proto_tree_add_boolean(tree, hf_smb_transaction_flags_owt,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_transaction_flags_dtid,
		tvb, offset, 2, mask);

	return mask;
}
 

static int
dissect_get_dfs_flags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint16 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohs(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 2,
			"Flags: 0x%04x", mask);
		tree = proto_item_add_subtree(item, ett_smb_get_dfs_flags);
	}

	proto_tree_add_boolean(tree, hf_smb_get_dfs_server_hold_storage,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_get_dfs_fielding,
		tvb, offset, 2, mask);

	offset += 2;
	return offset;
}

static int
dissect_dfs_referral_flags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint16 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohs(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 2,
			"Flags: 0x%04x", mask);
		tree = proto_item_add_subtree(item, ett_smb_dfs_referral_flags);
	}

	proto_tree_add_boolean(tree, hf_smb_dfs_referral_flags_strip,
		tvb, offset, 2, mask);

	offset += 2;

	return offset;
}


/* dfs inconsistency data  (4.4.2)
*/
static int
dissect_dfs_inconsistency_data(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, int offset, guint16 *bcp)
{
	int fn_len;
	const char *fn;

	/*XXX shouldn this data hold version and size? unclear from doc*/
	/* referral version */
	CHECK_BYTE_COUNT_TRANS_SUBR(2);
	proto_tree_add_item(tree, hf_smb_dfs_referral_version, tvb, offset, 2, TRUE);
	COUNT_BYTES_TRANS_SUBR(2);

	/* referral size */
	CHECK_BYTE_COUNT_TRANS_SUBR(2);
	proto_tree_add_item(tree, hf_smb_dfs_referral_size, tvb, offset, 2, TRUE);
	COUNT_BYTES_TRANS_SUBR(2);

	/* referral server type */
	CHECK_BYTE_COUNT_TRANS_SUBR(2);
	proto_tree_add_item(tree, hf_smb_dfs_referral_server_type, tvb, offset, 2, TRUE);
	COUNT_BYTES_TRANS_SUBR(2);

	/* referral flags */
	CHECK_BYTE_COUNT_TRANS_SUBR(2);
	offset = dissect_dfs_referral_flags(tvb, pinfo, tree, offset);
	*bcp -= 2;

	/* node name */
	fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len, FALSE, FALSE, bcp);
	CHECK_STRING_TRANS_SUBR(fn);
	proto_tree_add_string(tree, hf_smb_dfs_referral_node, tvb, offset, fn_len,
		fn);
	COUNT_BYTES_TRANS_SUBR(fn_len);

	return offset;
}

/* get dfs referral data  (4.4.1)
*/
static int
dissect_get_dfs_referral_data(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, int offset, guint16 *bcp)
{
	guint16 numref;
	guint16 refsize;
	guint16 pathoffset;
	guint16 altpathoffset;
	guint16 nodeoffset;
	int fn_len;
	int stroffset;
	int offsetoffset;
	guint16 save_bc;
	const char *fn;
	int unklen;
	int ucstring_end;
	int ucstring_len;

	/* path consumed */
	CHECK_BYTE_COUNT_TRANS_SUBR(2);
	proto_tree_add_item(tree, hf_smb_dfs_path_consumed, tvb, offset, 2, TRUE);
	COUNT_BYTES_TRANS_SUBR(2);

	/* num referrals */
	CHECK_BYTE_COUNT_TRANS_SUBR(2);
	numref = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_dfs_num_referrals, tvb, offset, 2, numref);
	COUNT_BYTES_TRANS_SUBR(2);

	/* get dfs flags */
	CHECK_BYTE_COUNT_TRANS_SUBR(2);
	offset = dissect_get_dfs_flags(tvb, pinfo, tree, offset);
	*bcp -= 2;

	/* XXX - in at least one capture there appears to be 2 bytes
	   of stuff after the Dfs flags, perhaps so that the header
	   in front of the referral list is a multiple of 4 bytes long. */
	CHECK_BYTE_COUNT_TRANS_SUBR(2);
	proto_tree_add_item(tree, hf_smb_padding, tvb, offset, 2, TRUE);
	COUNT_BYTES_TRANS_SUBR(2);

	/* if there are any referrals */
	if(numref){
		proto_item *ref_item = NULL;
		proto_tree *ref_tree = NULL;
		int old_offset=offset;

		if(tree){
			ref_item = proto_tree_add_text(tree,
				tvb, offset, *bcp, "Referrals");
			ref_tree = proto_item_add_subtree(ref_item,
				ett_smb_dfs_referrals);
		}
		ucstring_end = -1;

		while(numref--){
			proto_item *ri = NULL;
			proto_tree *rt = NULL;
			int old_offset=offset;
			guint16 version;

			if(tree){
				ri = proto_tree_add_text(ref_tree,
					tvb, offset, *bcp, "Referral");
				rt = proto_item_add_subtree(ri,
					ett_smb_dfs_referral);
			}
		
			/* referral version */
			CHECK_BYTE_COUNT_TRANS_SUBR(2);
			version = tvb_get_letohs(tvb, offset);
			proto_tree_add_uint(rt, hf_smb_dfs_referral_version,
				tvb, offset, 2, version);
			COUNT_BYTES_TRANS_SUBR(2);

			/* referral size */
			CHECK_BYTE_COUNT_TRANS_SUBR(2);
			refsize = tvb_get_letohs(tvb, offset);
			proto_tree_add_uint(rt, hf_smb_dfs_referral_size, tvb, offset, 2, refsize);
			COUNT_BYTES_TRANS_SUBR(2);

			/* referral server type */
			CHECK_BYTE_COUNT_TRANS_SUBR(2);
			proto_tree_add_item(rt, hf_smb_dfs_referral_server_type, tvb, offset, 2, TRUE);
			COUNT_BYTES_TRANS_SUBR(2);

			/* referral flags */
			CHECK_BYTE_COUNT_TRANS_SUBR(2);
			offset = dissect_dfs_referral_flags(tvb, pinfo, rt, offset);
			*bcp -= 2;

			switch(version){

			case 1:
				/* node name */
				fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len, FALSE, FALSE, bcp);
				CHECK_STRING_TRANS_SUBR(fn);
				proto_tree_add_string(rt, hf_smb_dfs_referral_node, tvb, offset, fn_len,
					fn);
				COUNT_BYTES_TRANS_SUBR(fn_len);
				break;

			case 2:
			case 3:	/* XXX - like version 2, but not identical;
				   seen in a capture, but the format isn't
				   documented */
				/* proximity */
				CHECK_BYTE_COUNT_TRANS_SUBR(2);
				proto_tree_add_item(rt, hf_smb_dfs_referral_proximity, tvb, offset, 2, TRUE);
				COUNT_BYTES_TRANS_SUBR(2);

				/* ttl */
				CHECK_BYTE_COUNT_TRANS_SUBR(2);
				proto_tree_add_item(rt, hf_smb_dfs_referral_ttl, tvb, offset, 2, TRUE);
				COUNT_BYTES_TRANS_SUBR(2);

				/* path offset */
				CHECK_BYTE_COUNT_TRANS_SUBR(2);
				pathoffset = tvb_get_letohs(tvb, offset);
				proto_tree_add_uint(rt, hf_smb_dfs_referral_path_offset, tvb, offset, 2, pathoffset);
				COUNT_BYTES_TRANS_SUBR(2);

				/* alt path offset */
				CHECK_BYTE_COUNT_TRANS_SUBR(2);
				altpathoffset = tvb_get_letohs(tvb, offset);
				proto_tree_add_uint(rt, hf_smb_dfs_referral_alt_path_offset, tvb, offset, 2, altpathoffset);
				COUNT_BYTES_TRANS_SUBR(2);

				/* node offset */
				CHECK_BYTE_COUNT_TRANS_SUBR(2);
				nodeoffset = tvb_get_letohs(tvb, offset);
				proto_tree_add_uint(rt, hf_smb_dfs_referral_node_offset, tvb, offset, 2, nodeoffset);
				COUNT_BYTES_TRANS_SUBR(2);

				/* path */
				if (pathoffset != 0) {
					stroffset = old_offset + pathoffset;
					offsetoffset = stroffset - offset;
					if (offsetoffset > 0 &&
					    *bcp > offsetoffset) {
						save_bc = *bcp;
						*bcp -= offsetoffset;
						fn = get_unicode_or_ascii_string(tvb, &stroffset, pinfo, &fn_len, FALSE, FALSE, bcp);
						CHECK_STRING_TRANS_SUBR(fn);
						proto_tree_add_string(rt, hf_smb_dfs_referral_path, tvb, stroffset, fn_len,
							fn);
						stroffset += fn_len;
						if (ucstring_end < stroffset)
							ucstring_end = stroffset;
						*bcp = save_bc;
					}
				}
			
				/* alt path */
				if (altpathoffset != 0) {
					stroffset = old_offset + altpathoffset;
					offsetoffset = stroffset - offset;
					if (offsetoffset > 0 &&
					    *bcp > offsetoffset) {
						save_bc = *bcp;
						*bcp -= offsetoffset;
						fn = get_unicode_or_ascii_string(tvb, &stroffset, pinfo, &fn_len, FALSE, FALSE, bcp);
						CHECK_STRING_TRANS_SUBR(fn);
						proto_tree_add_string(rt, hf_smb_dfs_referral_alt_path, tvb, stroffset, fn_len,
							fn);
						stroffset += fn_len;
						if (ucstring_end < stroffset)
							ucstring_end = stroffset;
						*bcp = save_bc;
					}
				}
			
				/* node */
				if (nodeoffset != 0) {
					stroffset = old_offset + nodeoffset;
					offsetoffset = stroffset - offset;
					if (offsetoffset > 0 &&
					    *bcp > offsetoffset) {
						save_bc = *bcp;
						*bcp -= offsetoffset;
						fn = get_unicode_or_ascii_string(tvb, &stroffset, pinfo, &fn_len, FALSE, FALSE, bcp);
						CHECK_STRING_TRANS_SUBR(fn);
						proto_tree_add_string(rt, hf_smb_dfs_referral_node, tvb, stroffset, fn_len,
							fn);
						stroffset += fn_len;
						if (ucstring_end < stroffset)
							ucstring_end = stroffset;
						*bcp = save_bc;
					}
				}
				break;
			}

			/*
			 * Show anything beyond the length of the referral
			 * as unknown data.
			 */
			unklen = (old_offset + refsize) - offset;
			if (unklen < 0) {
				/*
				 * XXX - the length is bogus.
				 */
				unklen = 0;
			}
			if (unklen != 0) {
				CHECK_BYTE_COUNT_TRANS_SUBR(unklen);
				proto_tree_add_item(rt, hf_smb_unknown, tvb,
				    offset, unklen, TRUE);
				COUNT_BYTES_TRANS_SUBR(unklen);
			}

			proto_item_set_len(ri, offset-old_offset);
		}

		/*
		 * Treat the offset past the end of the last Unicode
		 * string after the referrals (if any) as the last
		 * offset.
		 */
		if (ucstring_end > offset) {
			ucstring_len = ucstring_end - offset;
			if (*bcp < ucstring_len)
				ucstring_len = *bcp;
			offset += ucstring_len;
			*bcp -= ucstring_len;
		}
		proto_item_set_len(ref_item, offset-old_offset);
	}

	return offset;
}


/* this dissects the SMB_INFO_STANDARD and SMB_INFO_QUERY_EA_SIZE
   as described in 4.2.14.1
*/
static int
dissect_4_2_14_1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int offset, guint16 *bcp, gboolean *trunc)
{
	/* create time */
	CHECK_BYTE_COUNT_SUBR(4);
	offset = dissect_smb_datetime(tvb, pinfo, tree, offset,
		hf_smb_create_time, hf_smb_create_dos_date, hf_smb_create_dos_time,
		FALSE);
	*bcp -= 4;

	/* access time */
	CHECK_BYTE_COUNT_SUBR(4);
	offset = dissect_smb_datetime(tvb, pinfo, tree, offset,
		hf_smb_access_time, hf_smb_access_dos_date, hf_smb_access_dos_time,
		FALSE);
	*bcp -= 4;

	/* last write time */
	CHECK_BYTE_COUNT_SUBR(4);
	offset = dissect_smb_datetime(tvb, pinfo, tree, offset,
		hf_smb_last_write_time, hf_smb_last_write_dos_date, hf_smb_last_write_dos_time,
		FALSE);
	*bcp -= 4;

	/* data size */
	CHECK_BYTE_COUNT_SUBR(4);
	proto_tree_add_item(tree, hf_smb_data_size, tvb, offset, 4, TRUE);
	COUNT_BYTES_SUBR(4);

	/* allocation size */
	CHECK_BYTE_COUNT_SUBR(4);
	proto_tree_add_item(tree, hf_smb_alloc_size, tvb, offset, 4, TRUE);
	COUNT_BYTES_SUBR(4);

	/* File Attributes */
	CHECK_BYTE_COUNT_SUBR(2);
	offset = dissect_file_attributes(tvb, pinfo, tree, offset);
	*bcp -= 2;

	/* ea size */
	CHECK_BYTE_COUNT_SUBR(4);
	proto_tree_add_item(tree, hf_smb_ea_size, tvb, offset, 4, TRUE);
	COUNT_BYTES_SUBR(4);

	*trunc = FALSE;
	return offset;
}

/* this dissects the SMB_INFO_QUERY_EAS_FROM_LIST and SMB_INFO_QUERY_ALL_EAS
   as described in 4.2.14.2
*/
static int
dissect_4_2_14_2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int offset, guint16 *bcp, gboolean *trunc)
{
	/* list length */
	CHECK_BYTE_COUNT_SUBR(4);
	proto_tree_add_item(tree, hf_smb_list_length, tvb, offset, 4, TRUE);
	COUNT_BYTES_SUBR(4);

	*trunc = FALSE;
	return offset;
}

/* this dissects the SMB_INFO_IS_NAME_VALID
   as described in 4.2.14.3
*/
static int
dissect_4_2_14_3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int offset, guint16 *bcp, gboolean *trunc)
{
	int fn_len;
	const char *fn;

	/* file name */
	fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len, FALSE, FALSE, bcp);
	CHECK_STRING_SUBR(fn);
	proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
		fn);
	COUNT_BYTES_SUBR(fn_len);

	*trunc = FALSE;
	return offset;
}

/* this dissects the SMB_QUERY_FILE_BASIC_INFO
   as described in 4.2.14.4
*/
static int
dissect_4_2_14_4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int offset, guint16 *bcp, gboolean *trunc)
{
	/* create time */
	CHECK_BYTE_COUNT_SUBR(8);
	offset = dissect_smb_64bit_time(tvb, pinfo, tree, offset,
		"Create", hf_smb_create_time);
	*bcp -= 8;
	
	/* access time */
	CHECK_BYTE_COUNT_SUBR(8);
	offset = dissect_smb_64bit_time(tvb, pinfo, tree, offset,
		"Access Time", hf_smb_access_time);
	*bcp -= 8;
	
	/* last write time */
	CHECK_BYTE_COUNT_SUBR(8);
	offset = dissect_smb_64bit_time(tvb, pinfo, tree, offset,
		"Write Time", hf_smb_last_write_time);
	*bcp -= 8;
	
	/* last change time */
	CHECK_BYTE_COUNT_SUBR(8);
	offset = dissect_smb_64bit_time(tvb, pinfo, tree, offset,
		"Change Time", hf_smb_change_time);
	*bcp -= 8;
	
	/* File Attributes */
	CHECK_BYTE_COUNT_SUBR(2);
	offset = dissect_file_attributes(tvb, pinfo, tree, offset);
	*bcp -= 2;

	*trunc = FALSE;
	return offset;
}

/* this dissects the SMB_QUERY_FILE_STANDARD_INFO
   as described in 4.2.14.5
*/
static int
dissect_4_2_14_5(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int offset, guint16 *bcp, gboolean *trunc)
{
	/* allocation size */
	CHECK_BYTE_COUNT_SUBR(8);
	proto_tree_add_item(tree, hf_smb_alloc_size64, tvb, offset, 8, TRUE);
	COUNT_BYTES_SUBR(8);

	/* end of file */
	CHECK_BYTE_COUNT_SUBR(8);
	proto_tree_add_item(tree, hf_smb_end_of_file, tvb, offset, 8, TRUE);
	COUNT_BYTES_SUBR(8);

	/* number of links */
	CHECK_BYTE_COUNT_SUBR(4);
	proto_tree_add_item(tree, hf_smb_number_of_links, tvb, offset, 4, TRUE);
	COUNT_BYTES_SUBR(4);

	/* delete pending */
	CHECK_BYTE_COUNT_SUBR(2);
	proto_tree_add_item(tree, hf_smb_delete_pending, tvb, offset, 2, TRUE);
	COUNT_BYTES_SUBR(2);

	/* is directory */
	CHECK_BYTE_COUNT_SUBR(1);
	proto_tree_add_item(tree, hf_smb_is_directory, tvb, offset, 1, TRUE);
	COUNT_BYTES_SUBR(1);

	*trunc = FALSE;
	return offset;
}

/* this dissects the SMB_QUERY_FILE_EA_INFO
   as described in 4.2.14.6
*/
static int
dissect_4_2_14_6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int offset, guint16 *bcp, gboolean *trunc)
{
	/* ea size */
	CHECK_BYTE_COUNT_SUBR(4);
	proto_tree_add_item(tree, hf_smb_ea_size, tvb, offset, 4, TRUE);
	COUNT_BYTES_SUBR(4);

	*trunc = FALSE;
	return offset;
}

/* this dissects the SMB_QUERY_FILE_NAME_INFO
   as described in 4.2.14.7
   this is the same as SMB_QUERY_FILE_ALT_NAME_INFO
   as described in 4.2.14.9
*/
static int
dissect_4_2_14_7(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int offset, guint16 *bcp, gboolean *trunc)
{
	int fn_len;
	const char *fn;

	/* file name len */
	CHECK_BYTE_COUNT_SUBR(4);
	proto_tree_add_item(tree, hf_smb_file_name_len, tvb, offset, 4, TRUE);
	COUNT_BYTES_SUBR(4);

	/* file name */
	fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len, FALSE, FALSE, bcp);
	CHECK_STRING_SUBR(fn);
	proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
		fn);
	COUNT_BYTES_SUBR(fn_len);

	*trunc = FALSE;
	return offset;
}

/* this dissects the SMB_QUERY_FILE_ALL_INFO
   as described in 4.2.14.8
*/
static int
dissect_4_2_14_8(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int offset, guint16 *bcp, gboolean *trunc)
{

	offset = dissect_4_2_14_4(tvb, pinfo, tree, offset, bcp, trunc);
	if (trunc)
		return offset;
	offset = dissect_4_2_14_5(tvb, pinfo, tree, offset, bcp, trunc);
	if (trunc)
		return offset;

	/* index number */
	CHECK_BYTE_COUNT_SUBR(8);
	proto_tree_add_item(tree, hf_smb_index_number, tvb, offset, 8, TRUE);
	COUNT_BYTES_SUBR(8);

	offset = dissect_4_2_14_6(tvb, pinfo, tree, offset, bcp, trunc);
	if (trunc)
		return offset;

	/* access flags */
	CHECK_BYTE_COUNT_SUBR(4);
	offset = dissect_nt_access_mask(tvb, pinfo, tree, offset);
	COUNT_BYTES_SUBR(4);

	/* index number */
	CHECK_BYTE_COUNT_SUBR(8);
	proto_tree_add_item(tree, hf_smb_index_number, tvb, offset, 8, TRUE);
	COUNT_BYTES_SUBR(8);

	/* current offset */
	CHECK_BYTE_COUNT_SUBR(8);
	proto_tree_add_item(tree, hf_smb_current_offset, tvb, offset, 8, TRUE);
	COUNT_BYTES_SUBR(8);

	/* mode */
	CHECK_BYTE_COUNT_SUBR(4);
	offset = dissect_nt_create_options(tvb, pinfo, tree, offset);
	*bcp -= 4;

	/* alignment */
	CHECK_BYTE_COUNT_SUBR(4);
	proto_tree_add_item(tree, hf_smb_t2_alignment, tvb, offset, 4, TRUE);
	COUNT_BYTES_SUBR(4);
	
	offset = dissect_4_2_14_6(tvb, pinfo, tree, offset, bcp, trunc);

	return offset;
}

/* this dissects the SMB_QUERY_FILE_STREAM_INFO
   as described in 4.2.14.10
*/
static int
dissect_4_2_14_10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
    int offset, guint16 *bcp, gboolean *trunc)
{
	proto_item *item;
	proto_tree *tree;
	int old_offset;
	guint32 neo;
	int fn_len;
	const char *fn;
	int padcnt;

	for (;;) {
		old_offset = offset;

		/* next entry offset */
		CHECK_BYTE_COUNT_SUBR(4);
		if(parent_tree){
			item = proto_tree_add_text(parent_tree, tvb, offset, *bcp, "Stream Info");
			tree = proto_item_add_subtree(item, ett_smb_ff2_data);
		} else {
			item = NULL;
			tree = NULL;
		}

		neo = tvb_get_letohl(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_next_entry_offset, tvb, offset, 4, neo);
		COUNT_BYTES_SUBR(4);
	
		/* stream name len */
		CHECK_BYTE_COUNT_SUBR(4);
		fn_len = tvb_get_letohl(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_t2_stream_name_length, tvb, offset, 4, fn_len);
		COUNT_BYTES_SUBR(4);
	
		/* stream size */
		CHECK_BYTE_COUNT_SUBR(8);
		proto_tree_add_item(tree, hf_smb_t2_stream_size, tvb, offset, 8, TRUE);
		COUNT_BYTES_SUBR(8);

		/* allocation size */
		CHECK_BYTE_COUNT_SUBR(8);
		proto_tree_add_item(tree, hf_smb_alloc_size64, tvb, offset, 8, TRUE);
		COUNT_BYTES_SUBR(8);

		/* stream name */
		fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len, FALSE, TRUE, bcp);
		CHECK_STRING_SUBR(fn);
		proto_tree_add_string(tree, hf_smb_t2_stream_name, tvb, offset, fn_len,
			fn);
		COUNT_BYTES_SUBR(fn_len);
 
		proto_item_append_text(item, ": %s", fn);
		proto_item_set_len(item, offset-old_offset);

		if (neo == 0)
			break;	/* no more structures */

		/* skip to next structure */
		padcnt = (old_offset + neo) - offset;
		if (padcnt < 0) {
			/*
			 * XXX - this is bogus; flag it?
			 */
			padcnt = 0;
		}
		if (padcnt != 0) {
			CHECK_BYTE_COUNT_SUBR(padcnt);
			COUNT_BYTES_SUBR(padcnt);
		}
	}

	*trunc = FALSE;
	return offset;
}

/* this dissects the SMB_QUERY_FILE_COMPRESSION_INFO
   as described in 4.2.14.11
*/
static int
dissect_4_2_14_11(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int offset, guint16 *bcp, gboolean *trunc)
{
	/* compressed file size */
	CHECK_BYTE_COUNT_SUBR(8);
	proto_tree_add_item(tree, hf_smb_t2_compressed_file_size, tvb, offset, 8, TRUE);
	COUNT_BYTES_SUBR(8);

	/* compression format */
	CHECK_BYTE_COUNT_SUBR(2);
	proto_tree_add_item(tree, hf_smb_t2_compressed_format, tvb, offset, 2, TRUE);
	COUNT_BYTES_SUBR(2);
	
	/* compression unit shift */
	CHECK_BYTE_COUNT_SUBR(1);
	proto_tree_add_item(tree, hf_smb_t2_compressed_unit_shift,tvb, offset, 1, TRUE);
	COUNT_BYTES_SUBR(1);
	
	/* compression chunk shift */
	CHECK_BYTE_COUNT_SUBR(1);
	proto_tree_add_item(tree, hf_smb_t2_compressed_chunk_shift, tvb, offset, 1, TRUE);
	COUNT_BYTES_SUBR(1);
	
	/* compression cluster shift */
	CHECK_BYTE_COUNT_SUBR(1);
	proto_tree_add_item(tree, hf_smb_t2_compressed_cluster_shift, tvb, offset, 1, TRUE);
	COUNT_BYTES_SUBR(1);
	
	/* 3 reserved bytes */
	CHECK_BYTE_COUNT_SUBR(3);
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 3, TRUE);
	COUNT_BYTES_SUBR(3);

	*trunc = FALSE;
	return offset;
}



/*dissect the data block for TRANS2_QUERY_PATH_INFORMATION*/
static int
dissect_qpi_loi_vals(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree,
    int offset, guint16 *bcp)
{
	smb_info_t *si;
	gboolean trunc;

	if(!*bcp){
		return offset;
	}
	
	si = (smb_info_t *)pinfo->private_data;
	switch(si->info_level){
	case 1:		/*Info Standard*/
	case 2:		/*Info Query EA Size*/
		offset = dissect_4_2_14_1(tvb, pinfo, tree, offset, bcp,
		    &trunc);
		break;
	case 3:		/*Info Query EAs From List*/
	case 4:		/*Info Query All EAs*/
		offset = dissect_4_2_14_2(tvb, pinfo, tree, offset, bcp,
		    &trunc);
		break;
	case 6:		/*Info Is Name Valid*/
		offset = dissect_4_2_14_3(tvb, pinfo, tree, offset, bcp,
		    &trunc);
		break;
	case 0x0101:	/*Query File Basic Info*/
		offset = dissect_4_2_14_4(tvb, pinfo, tree, offset, bcp,
		    &trunc);
		break;
	case 0x0102:	/*Query File Standard Info*/
		offset = dissect_4_2_14_5(tvb, pinfo, tree, offset, bcp,
		    &trunc);
		break;
	case 0x0103:	/*Query File EA Info*/
		offset = dissect_4_2_14_6(tvb, pinfo, tree, offset, bcp,
		    &trunc);
		break;
	case 0x0104:	/*Query File Name Info*/
		offset = dissect_4_2_14_7(tvb, pinfo, tree, offset, bcp,
		    &trunc);
		break;
	case 0x0107:	/*Query File All Info*/
		offset = dissect_4_2_14_8(tvb, pinfo, tree, offset, bcp,
		    &trunc);
		break;
	case 0x0108:	/*Query File Alt File Info*/
		offset = dissect_4_2_14_7(tvb, pinfo, tree, offset, bcp,
		    &trunc);
		break;
	case 0x0109:	/*Query File Stream Info*/
		offset = dissect_4_2_14_10(tvb, pinfo, tree, offset, bcp,
		    &trunc);
		break;
	case 0x010b:	/*Query File Compression Info*/
		offset = dissect_4_2_14_11(tvb, pinfo, tree, offset, bcp,
		    &trunc);
		break;
	case 0x0200:	/*Set File Unix Basic*/
		/* XXX add this from the SNIA doc */
		break;
	case 0x0201:	/*Set File Unix Link*/
		/* XXX add this from the SNIA doc */
		break;
	case 0x0202:	/*Set File Unix HardLink*/
		/* XXX add this from the SNIA doc */
		break;
	}
	
	return offset;
}


static int
dissect_transaction2_request_data(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *parent_tree, int offset, int subcmd, guint16 dc)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	smb_info_t *si;

	si = (smb_info_t *)pinfo->private_data;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, dc,
				"%s Data",
				val_to_str(subcmd, trans2_cmd_vals, 
						"Unknown (0x%02x)"));
		tree = proto_item_add_subtree(item, ett_smb_transaction_data);
	}

	switch(subcmd){
	case 0x00:	/*TRANS2_OPEN2*/
		/* XXX FAEList here?*/
		break;
	case 0x01:	/*TRANS2_FIND_FIRST2*/
		/* XXX FAEList here?*/
		break;
	case 0x02:	/*TRANS2_FIND_NEXT2*/
		/* no data field in this request */
		break;
	case 0x03:	/*TRANS2_QUERY_FS_INFORMATION*/
		/* no data field in this request */
		break;
	case 0x05:	/*TRANS2_QUERY_PATH_INFORMATION*/
		/* no data field in this request */
		break;
	case 0x06:	/*TRANS2_SET_PATH_INFORMATION*/
		offset = dissect_qpi_loi_vals(tvb, pinfo, tree, offset, &dc);
		break;
	case 0x07:	/*TRANS2_QUERY_FILE_INFORMATION*/
		/* no data field in this request */
		break;
	case 0x08:	/*TRANS2_SET_FILE_INFORMATION*/
		offset = dissect_qpi_loi_vals(tvb, pinfo, tree, offset, &dc);
		break;
	case 0x09:	/*TRANS2_FSCTL*/
		/*XXX dont know how to decode this yet */
		break;
	case 0x0a:	/*TRANS2_IOCTL2*/
		/*XXX dont know how to decode this yet */
		break;
	case 0x0b:	/*TRANS2_FIND_NOTIFY_FIRST*/
		/*XXX dont know how to decode this yet */
		break;
	case 0x0c:	/*TRANS2_FIND_NOTIFY_NEXT*/
		/*XXX dont know how to decode this yet */
		break;
	case 0x0d:	/*TRANS2_CREATE_DIRECTORY*/
		/* no data block for this one */
		break;
	case 0x0e:	/*TRANS2_SESSION_SETUP*/
		/*XXX dont know how to decode this yet */
		break;
	case 0x10:	/*TRANS2_GET_DFS_REFERRAL*/
		/* no data field in this request */
		break;
	case 0x11:	/*TRANS2_REPORT_DFS_INCONSISTENCY*/
		offset = dissect_dfs_inconsistency_data(tvb, pinfo, tree, offset, &dc);
		break;
	}

	/* ooops there were data we didnt know how to process */
	if(dc != 0){
		proto_tree_add_item(tree, hf_smb_unknown, tvb, offset, dc, TRUE);
		offset += dc;
	}

	return offset;
}


static void
dissect_trans_data(tvbuff_t *s_tvb, tvbuff_t *p_tvb, tvbuff_t *d_tvb,
    packet_info *pinfo, proto_tree *tree)
{
	int i;
	int offset;
	guint length;

	/*
	 * Show the setup words.
	 */
	if (s_tvb != NULL) {
		length = tvb_reported_length(s_tvb);
		for (i = 0, offset = 0; length >= 2;
		    i++, offset += 2, length -= 2) {
			/*
			 * XXX - add a setup word filterable field?
			 */
			proto_tree_add_text(tree, s_tvb, offset, 2,
			    "Setup Word %d: 0x%04x", i,
			    tvb_get_letohs(s_tvb, offset));
		}
	}

	/*
	 * Show the parameters, if any.
	 */
	if (p_tvb != NULL) {
		length = tvb_reported_length(p_tvb);
		if (length != 0) {
			proto_tree_add_text(tree, p_tvb, 0, length,
			    "Parameters: %s",
			    tvb_bytes_to_str(p_tvb, 0, length));
		}
	}

	/*
	 * Show the data, if any.
	 */
	if (d_tvb != NULL) {
		length = tvb_reported_length(d_tvb);
		if (length != 0) {
			proto_tree_add_text(tree, d_tvb, 0, length,
			    "Data: %s", tvb_bytes_to_str(d_tvb, 0, length));
		}
	}
}

/* This routine handles the following 4 calls
   Transaction  0x25
   Transaction Secondary 0x26
   Transaction2 0x32
   Transaction2 Secondary 0x33
*/
static int
dissect_transaction_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc, sc=0;
	int so=offset;
	int sl=0;
	int spo=offset;
	int spc=0;
	guint16 od=0, tf, po=0, pc=0, dc=0, pd, dd=0;
	int subcmd = -1;
	guint32 to;
	int an_len;
	const char *an = NULL;
	smb_info_t *si;
	smb_transact2_info_t *t2i;
	smb_transact_info_t *tri;
	guint16 bc;
	int padcnt;
	gboolean dissected_trans;

	si = (smb_info_t *)pinfo->private_data;

	WORD_COUNT;

	if(wc==8){
		/*secondary client request*/

		/* total param count, only a 16bit integer here*/
		proto_tree_add_uint(tree, hf_smb_total_param_count, tvb, offset, 2, tvb_get_letohs(tvb, offset));
		offset += 2;
	
		/* total data count , only 16bit integer here*/
		proto_tree_add_uint(tree, hf_smb_total_data_count, tvb, offset, 2, tvb_get_letohs(tvb, offset));
		offset += 2;

		/* param count */
		pc = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_param_count16, tvb, offset, 2, pc);
		offset += 2;

		/* param offset */
		po = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_param_offset16, tvb, offset, 2, po);
		offset += 2;

		/* param disp */
		pd = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_param_disp16, tvb, offset, 2, pd);
		offset += 2;
	
		/* data count */
		dc = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_data_count16, tvb, offset, 2, dc);
		offset += 2;

		/* data offset */
		od = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_data_offset16, tvb, offset, 2, od);
		offset += 2;
	
		/* data disp */
		dd = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_data_disp16, tvb, offset, 2, dd);
		offset += 2;

		if(si->cmd==SMB_COM_TRANSACTION2){
			/* fid */
			proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
			offset += 2;
		}

		/* There are no setup words. */
		so = offset;
		sc = 0;
		sl = 0;
	} else {
		/* it is not a secondary request */

		/* total param count , only a 16 bit integer here*/
		proto_tree_add_uint(tree, hf_smb_total_param_count, tvb, offset, 2, tvb_get_letohs(tvb, offset));
		offset += 2;

		/* total data count , only 16bit integer here*/
		proto_tree_add_uint(tree, hf_smb_total_data_count, tvb, offset, 2, tvb_get_letohs(tvb, offset));
		offset += 2;

		/* max param count , only 16bit integer here*/
		proto_tree_add_uint(tree, hf_smb_max_param_count, tvb, offset, 2, tvb_get_letohs(tvb, offset));
		offset += 2;

		/* max data count, only 16bit integer here*/
		proto_tree_add_uint(tree, hf_smb_max_data_count, tvb, offset, 2, tvb_get_letohs(tvb, offset));
		offset += 2;

		/* max setup count, only 16bit integer here*/
		proto_tree_add_uint(tree, hf_smb_max_setup_count, tvb, offset, 1, tvb_get_guint8(tvb, offset));
		offset += 1;

		/* reserved byte */
		proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 1, TRUE);
		offset += 1;

		/* transaction flags */
		tf = dissect_transaction_flags(tvb, pinfo, tree, offset);
		offset += 2;

		/* timeout */
		to = tvb_get_letohl(tvb, offset);
		if (to == 0)
			proto_tree_add_uint_format(tree, hf_smb_timeout, tvb, offset, 4, to, "Timeout: Return immediately (0)");
		else if (to == 0xffffffff)
			proto_tree_add_uint_format(tree, hf_smb_timeout, tvb, offset, 4, to, "Timeout: Wait indefinitely (-1)");
		else
			proto_tree_add_uint_format(tree, hf_smb_timeout, tvb, offset, 4, to, "Timeout: %s", time_msecs_to_str(to));
		offset += 4;

		/* 2 reserved bytes */
		proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 2, TRUE);
		offset += 2;

		/* param count */
		pc = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_param_count16, tvb, offset, 2, pc);
		offset += 2;
	
		/* param offset */
		po = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_param_offset16, tvb, offset, 2, po);
		offset += 2;

		/* param displacement is zero here */
		pd = 0;

		/* data count */
		dc = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_data_count16, tvb, offset, 2, dc);
		offset += 2;

		/* data offset */
		od = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_data_offset16, tvb, offset, 2, od);
		offset += 2;

		/* data displacement is zero here */
		dd = 0;

		/* setup count */
		sc = tvb_get_guint8(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_setup_count, tvb, offset, 1, sc);
		offset += 1;

		/* reserved byte */
		proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 1, TRUE);
		offset += 1;
		
		/* this is where the setup bytes, if any start */	
		so = offset;
		sl = sc*2;

		/* if there were any setup bytes, decode them */
		if(sc){
			switch(si->cmd){

			case SMB_COM_TRANSACTION2:
				/* TRANSACTION2 only has one setup word and
				   that is the subcommand code. */
				subcmd = tvb_get_letohs(tvb, offset);
				proto_tree_add_uint(tree, hf_smb_trans2_subcmd,
				    tvb, offset, 2, subcmd);
				if (check_col(pinfo->fd, COL_INFO)) {
					col_append_fstr(pinfo->fd, COL_INFO, " %s",
 					    val_to_str(subcmd, trans2_cmd_vals, 
						"Unknown (0x%02x)"));
				}
				if (!si->unidir) {
					if(!pinfo->fd->flags.visited){
						/* 
						 * Allocate a new
						 * smb_transact2_info_t
						 * structure.
						 */
						t2i = g_mem_chunk_alloc(smb_transact2_info_chunk);
						t2i->subcmd = subcmd;
						t2i->info_level = -1;
						si->sip->extra_info = t2i;
					}
				}     
				break;

			case SMB_COM_TRANSACTION:
				/* TRANSACTION setup words processed below */
				break;
			}

			offset += sl;
		}
	}

	BYTE_COUNT;
	
	if(wc!=8){
		/* primary request */
		/* name is NULL if transaction2 */
		if(si->cmd == SMB_COM_TRANSACTION){
			/* Transaction Name */
			an = get_unicode_or_ascii_string(tvb, &offset,
				pinfo, &an_len, FALSE, FALSE, &bc);
			if (an == NULL)
				goto endofcommand;
			proto_tree_add_string(tree, hf_smb_trans_name, tvb,
				offset, an_len, an);
			COUNT_BYTES(an_len);
		}
	}

	/*
	 * The pipe or mailslot arguments for Transaction start with
	 * the first setup word (or where the first setup word would
	 * be if there were any setup words), and run to the current
	 * offset (which could mean that there aren't any).
	 */
	spo = so;
	spc = offset - spo;

	/* parameters */
	if(po>offset){
		/* We have some initial padding bytes.
		*/
		padcnt = po-offset;
		if (padcnt > bc)
			padcnt = bc;
		proto_tree_add_item(tree, hf_smb_padding, tvb, offset, padcnt, TRUE);
		COUNT_BYTES(padcnt);
	}
	if(pc){
		CHECK_BYTE_COUNT(pc);
		switch(si->cmd) {

		case SMB_COM_TRANSACTION2:
			/* TRANSACTION2 parameters*/
			offset = dissect_transaction2_request_parameters(tvb,
			    pinfo, tree, offset, subcmd, pc);
			bc -= pc;
			break;

		case SMB_COM_TRANSACTION:
			/* TRANSACTION parameters processed below */
			COUNT_BYTES(pc);
			break;
		}
	}

	/* data */
	if(od>offset){
		/* We have some initial padding bytes.
		*/
		padcnt = od-offset;
		if (padcnt > bc)
			padcnt = bc;
		proto_tree_add_item(tree, hf_smb_padding, tvb, offset, padcnt, TRUE);
		COUNT_BYTES(padcnt);
	}
	if(dc){
		CHECK_BYTE_COUNT(dc);
		switch(si->cmd){

		case SMB_COM_TRANSACTION2:
			/* TRANSACTION2 data*/
			offset = dissect_transaction2_request_data(tvb, pinfo,
			    tree, offset, subcmd, dc);
			bc -= dc;
			break;

		case SMB_COM_TRANSACTION:
			/* TRANSACTION data processed below */
			COUNT_BYTES(dc);
			break;
		}
	}

	/*TRANSACTION request parameters */
	if(si->cmd==SMB_COM_TRANSACTION){
		/*XXX replace this block with a function and use that one 
		     for both requests/responses*/
		if(dd==0){
			tvbuff_t *p_tvb, *d_tvb, *s_tvb;
			tvbuff_t *sp_tvb, *pd_tvb;

			if(pc>0){
				if(pc>tvb_length_remaining(tvb, po)){
					p_tvb = tvb_new_subset(tvb, po, tvb_length_remaining(tvb, po), pc);
				} else {
					p_tvb = tvb_new_subset(tvb, po, pc, pc);
				}
			} else {
				p_tvb = NULL;
			}
			if(dc>0){
				if(dc>tvb_length_remaining(tvb, od)){
					d_tvb = tvb_new_subset(tvb, od, tvb_length_remaining(tvb, od), dc);
				} else {
					d_tvb = tvb_new_subset(tvb, od, dc, dc);
				}
			} else {
				d_tvb = NULL;
			}
			if(sl){
				if(sl>tvb_length_remaining(tvb, so)){
					s_tvb = tvb_new_subset(tvb, so, tvb_length_remaining(tvb, so), sl);
				} else {
					s_tvb = tvb_new_subset(tvb, so, sl, sl);
				}
			} else {
				s_tvb = NULL;
			}

			if (!si->unidir) {
				if(!pinfo->fd->flags.visited){
					/* 
					 * Allocate a new smb_transact_info_t
					 * structure.
					 */
					tri = g_mem_chunk_alloc(smb_transact_info_chunk);
					tri->subcmd = -1;
					tri->trans_subcmd = -1;
					tri->function = -1;
					tri->fid = -1;
					tri->lanman_cmd = 0;
					tri->param_descrip = NULL;
					tri->data_descrip = NULL;
					tri->aux_data_descrip = NULL;
					tri->info_level = -1;
					si->sip->extra_info = tri;
				} else {
					/*
					 * We already filled the structure
					 * in; don't bother doing so again.
					 */
					tri = NULL;
				}
			} else {
				/*
				 * This is a unidirectional message, for
				 * which there will be no reply; don't
				 * bother allocating an "smb_transact_info_t"
				 * structure for it.
				 */
				tri = NULL;
			}
			dissected_trans = FALSE;
			if(strncmp("\\PIPE\\", an, 6) == 0){
				if (tri != NULL)
					tri->subcmd=TRANSACTION_PIPE;

				/*
				 * A tvbuff containing the setup words and
				 * the pipe path.
				 */
				sp_tvb = tvb_new_subset(tvb, spo, spc, spc);

				/*
				 * A tvbuff containing the parameters and the
				 * data.
				 */
				pd_tvb = tvb_new_subset(tvb, po, -1, -1);

				dissected_trans = dissect_pipe_smb(sp_tvb,
				    s_tvb, pd_tvb, p_tvb, d_tvb, an+6, pinfo,
				    top_tree);
			} else if(strncmp("\\MAILSLOT\\", an, 10) == 0){
				if (tri != NULL)
					tri->subcmd=TRANSACTION_MAILSLOT;

				/*
				 * A tvbuff containing the setup words and
				 * the mailslot path.
				 */
				sp_tvb = tvb_new_subset(tvb, spo, spc, spc);
				dissected_trans = dissect_mailslot_smb(sp_tvb,
				    s_tvb, d_tvb, an+10, pinfo, top_tree);
			}
			if (!dissected_trans) {
				dissect_trans_data(s_tvb, p_tvb, d_tvb,
				    pinfo, tree);
			}
		} else {
			if(check_col(pinfo->fd, COL_INFO)){
				col_append_str(pinfo->fd, COL_INFO,
					"[transact continuation]");
			}
		}
	}

	END_OF_SMB

	return offset;
}

 

static int
dissect_4_3_4_1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
    int offset, guint16 *bcp, gboolean *trunc)
{
	int fn_len;
	const char *fn;
	int old_offset = offset;
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	smb_info_t *si;

	si = (smb_info_t *)pinfo->private_data;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, *bcp, "%s",
		    val_to_str(si->info_level, ff2_il_vals, "Unknown (0x%02x)"));
		tree = proto_item_add_subtree(item, ett_smb_ff2_data);
	}

	/* create time */
	CHECK_BYTE_COUNT_SUBR(4);
	offset = dissect_smb_datetime(tvb, pinfo, tree, offset,
		hf_smb_create_time,
		hf_smb_create_dos_date, hf_smb_create_dos_time, FALSE);
	*bcp -= 4;

	/* access time */
	CHECK_BYTE_COUNT_SUBR(4);
	offset = dissect_smb_datetime(tvb, pinfo, tree, offset,
		hf_smb_access_time,
		hf_smb_access_dos_date, hf_smb_access_dos_time, FALSE);
	*bcp -= 4;

	/* last write time */
	CHECK_BYTE_COUNT_SUBR(4);
	offset = dissect_smb_datetime(tvb, pinfo, tree, offset,
		hf_smb_last_write_time,
		hf_smb_last_write_dos_date, hf_smb_last_write_dos_time, FALSE);
	*bcp -= 4;

	/* data size */
	CHECK_BYTE_COUNT_SUBR(4);
	proto_tree_add_item(tree, hf_smb_data_size, tvb, offset, 4, TRUE);
	COUNT_BYTES_SUBR(4);

	/* allocation size */
	CHECK_BYTE_COUNT_SUBR(4);
	proto_tree_add_item(tree, hf_smb_alloc_size, tvb, offset, 4, TRUE);
	COUNT_BYTES_SUBR(4);

	/* File Attributes */
	CHECK_BYTE_COUNT_SUBR(2);
	offset = dissect_file_attributes(tvb, pinfo, tree, offset);
	*bcp -= 2;

	/* file name len */
	CHECK_BYTE_COUNT_SUBR(1);
	fn_len = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_file_name_len, tvb, offset, 1, fn_len);
	COUNT_BYTES_SUBR(1);

	/* file name */
	fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len, FALSE, TRUE, bcp);
	CHECK_STRING_SUBR(fn);
	proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
		fn);
	COUNT_BYTES_SUBR(fn_len);

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, " %s",
		fn);
	}
 
	proto_item_append_text(item, " File: %s", fn);
	proto_item_set_len(item, offset-old_offset);

	*trunc = FALSE;
	return offset;
}

static int
dissect_4_3_4_2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
    int offset, guint16 *bcp, gboolean *trunc)
{
	int fn_len;
	const char *fn;
	int old_offset = offset;
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	smb_info_t *si;

	si = (smb_info_t *)pinfo->private_data;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, *bcp, "%s",
		    val_to_str(si->info_level, ff2_il_vals, "Unknown (0x%02x)"));
		tree = proto_item_add_subtree(item, ett_smb_ff2_data);
	}
 
	/* create time */
	CHECK_BYTE_COUNT_SUBR(4);
	offset = dissect_smb_datetime(tvb, pinfo, tree, offset,
		hf_smb_create_time,
		hf_smb_create_dos_date, hf_smb_create_dos_time, FALSE);
	*bcp -= 4;

	/* access time */
	CHECK_BYTE_COUNT_SUBR(4);
	offset = dissect_smb_datetime(tvb, pinfo, tree, offset,
		hf_smb_access_time,
		hf_smb_access_dos_date, hf_smb_access_dos_time, FALSE);
	*bcp -= 4;

	/* last write time */
	CHECK_BYTE_COUNT_SUBR(4);
	offset = dissect_smb_datetime(tvb, pinfo, tree, offset,
		hf_smb_last_write_time,
		hf_smb_last_write_dos_date, hf_smb_last_write_dos_time, FALSE);
	*bcp -= 4;

	/* data size */
	CHECK_BYTE_COUNT_SUBR(4);
	proto_tree_add_item(tree, hf_smb_data_size, tvb, offset, 4, TRUE);
	COUNT_BYTES_SUBR(4);

	/* allocation size */
	CHECK_BYTE_COUNT_SUBR(4);
	proto_tree_add_item(tree, hf_smb_alloc_size, tvb, offset, 4, TRUE);
	COUNT_BYTES_SUBR(4);

	/* File Attributes */
	CHECK_BYTE_COUNT_SUBR(2);
	offset = dissect_file_attributes(tvb, pinfo, tree, offset);
	*bcp -= 2;

	/* ea size */
	CHECK_BYTE_COUNT_SUBR(4);
	proto_tree_add_item(tree, hf_smb_ea_size, tvb, offset, 4, TRUE);
	COUNT_BYTES_SUBR(4);

	/* file name len */
	CHECK_BYTE_COUNT_SUBR(1);
	fn_len = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_file_name_len, tvb, offset, 1, fn_len);
	COUNT_BYTES_SUBR(1);

	/* file name */
	fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len, FALSE, TRUE, bcp);
	CHECK_STRING_SUBR(fn);
	proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
		fn);
	COUNT_BYTES_SUBR(fn_len);

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, " %s",
		fn);
	}

	proto_item_append_text(item, " File: %s", fn);
	proto_item_set_len(item, offset-old_offset);

	*trunc = FALSE;
	return offset;
}

static int
dissect_4_3_4_4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
    int offset, guint16 *bcp, gboolean *trunc)
{
	int fn_len;
	const char *fn;
	int old_offset = offset;
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	smb_info_t *si;
	guint32 neo;
	int padcnt;

	si = (smb_info_t *)pinfo->private_data;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, *bcp, "%s",
		    val_to_str(si->info_level, ff2_il_vals, "Unknown (0x%02x)"));
		tree = proto_item_add_subtree(item, ett_smb_ff2_data);
	}

	/* next entry offset */
	CHECK_BYTE_COUNT_SUBR(4);
	neo = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_next_entry_offset, tvb, offset, 4, neo);
	COUNT_BYTES_SUBR(4);
	
	/* file index */
	CHECK_BYTE_COUNT_SUBR(4);
	proto_tree_add_item(tree, hf_smb_file_index, tvb, offset, 4, TRUE);
	COUNT_BYTES_SUBR(4);

	/* create time */
	CHECK_BYTE_COUNT_SUBR(8);
	offset = dissect_smb_64bit_time(tvb, pinfo, tree, offset,
		"Create Time", hf_smb_create_time);
	*bcp -= 8;
	
	/* access time */
	CHECK_BYTE_COUNT_SUBR(8);
	offset = dissect_smb_64bit_time(tvb, pinfo, tree, offset,
		"Access Time", hf_smb_access_time);
	*bcp -= 8;
	
	/* last write time */
	CHECK_BYTE_COUNT_SUBR(8);
	offset = dissect_smb_64bit_time(tvb, pinfo, tree, offset,
		"Write Time", hf_smb_last_write_time);
	*bcp -= 8;
	
	/* last change time */
	CHECK_BYTE_COUNT_SUBR(8);
	offset = dissect_smb_64bit_time(tvb, pinfo, tree, offset,
		"Change Time", hf_smb_change_time);
	*bcp -= 8;
	
	/* end of file */
	CHECK_BYTE_COUNT_SUBR(8);
	proto_tree_add_item(tree, hf_smb_end_of_file, tvb, offset, 8, TRUE);
	COUNT_BYTES_SUBR(8);

	/* allocation size */
	CHECK_BYTE_COUNT_SUBR(8);
	proto_tree_add_item(tree, hf_smb_alloc_size64, tvb, offset, 8, TRUE);
	COUNT_BYTES_SUBR(8);

	/* Extended File Attributes */
	CHECK_BYTE_COUNT_SUBR(4);
	offset = dissect_file_ext_attr(tvb, pinfo, tree, offset);
	*bcp -= 4;

	/* file name len */
	CHECK_BYTE_COUNT_SUBR(4);
	fn_len = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_file_name_len, tvb, offset, 4, fn_len);
	COUNT_BYTES_SUBR(4);

	/* file name */
	fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len, FALSE, TRUE, bcp);
	CHECK_STRING_SUBR(fn);
	proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
		fn);
	COUNT_BYTES_SUBR(fn_len);

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, " %s",
		fn);
	}

	/* skip to next structure */
	if(neo){
		padcnt = (old_offset + neo) - offset;
		if (padcnt < 0) {
			/*
			 * XXX - this is bogus; flag it?
			 */
			padcnt = 0;
		}
		if (padcnt != 0) {
			CHECK_BYTE_COUNT_SUBR(padcnt);
			COUNT_BYTES_SUBR(padcnt);
		}
	}

	proto_item_append_text(item, " File: %s", fn);
	proto_item_set_len(item, offset-old_offset);

	*trunc = FALSE;
	return offset;
}

static int
dissect_4_3_4_5(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
    int offset, guint16 *bcp, gboolean *trunc)
{
	int fn_len;
	const char *fn;
	int old_offset = offset;
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	smb_info_t *si;
	guint32 neo;
	int padcnt;

	si = (smb_info_t *)pinfo->private_data;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, *bcp, "%s",
		    val_to_str(si->info_level, ff2_il_vals, "Unknown (0x%02x)"));
		tree = proto_item_add_subtree(item, ett_smb_ff2_data);
	}

	/* next entry offset */
	CHECK_BYTE_COUNT_SUBR(4);
	neo = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_next_entry_offset, tvb, offset, 4, neo);
	COUNT_BYTES_SUBR(4);
	
	/* file index */
	CHECK_BYTE_COUNT_SUBR(4);
	proto_tree_add_item(tree, hf_smb_file_index, tvb, offset, 4, TRUE);
	COUNT_BYTES_SUBR(4);

	/* create time */
	CHECK_BYTE_COUNT_SUBR(8);
	offset = dissect_smb_64bit_time(tvb, pinfo, tree, offset,
		"Create Time", hf_smb_create_time);
	*bcp -= 8;
	
	/* access time */
	CHECK_BYTE_COUNT_SUBR(8);
	offset = dissect_smb_64bit_time(tvb, pinfo, tree, offset,
		"Access Time", hf_smb_access_time);
	*bcp -= 8;
	
	/* last write time */
	CHECK_BYTE_COUNT_SUBR(8);
	offset = dissect_smb_64bit_time(tvb, pinfo, tree, offset,
		"Write Time", hf_smb_last_write_time);
	*bcp -= 8;
	
	/* last change time */
	CHECK_BYTE_COUNT_SUBR(8);
	offset = dissect_smb_64bit_time(tvb, pinfo, tree, offset,
		"Change Time", hf_smb_change_time);
	*bcp -= 8;
	
	/* end of file */
	CHECK_BYTE_COUNT_SUBR(8);
	proto_tree_add_item(tree, hf_smb_end_of_file, tvb, offset, 8, TRUE);
	COUNT_BYTES_SUBR(8);

	/* allocation size */
	CHECK_BYTE_COUNT_SUBR(8);
	proto_tree_add_item(tree, hf_smb_alloc_size64, tvb, offset, 8, TRUE);
	COUNT_BYTES_SUBR(8);

	/* Extended File Attributes */
	CHECK_BYTE_COUNT_SUBR(4);
	offset = dissect_file_ext_attr(tvb, pinfo, tree, offset);
	*bcp -= 4;

	/* file name len */
	CHECK_BYTE_COUNT_SUBR(4);
	fn_len = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_file_name_len, tvb, offset, 4, fn_len);
	COUNT_BYTES_SUBR(4);

	/* ea size */
	CHECK_BYTE_COUNT_SUBR(4);
	proto_tree_add_item(tree, hf_smb_ea_size, tvb, offset, 4, TRUE);
	COUNT_BYTES_SUBR(4);

	/* file name */
	fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len, FALSE, TRUE, bcp);
	CHECK_STRING_SUBR(fn);
	proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
		fn);
	COUNT_BYTES_SUBR(fn_len);

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, " %s",
		fn);
	}

	/* skip to next structure */
	if(neo){
		padcnt = (old_offset + neo) - offset;
		if (padcnt < 0) {
			/*
			 * XXX - this is bogus; flag it?
			 */
			padcnt = 0;
		}
		if (padcnt != 0) {
			CHECK_BYTE_COUNT_SUBR(padcnt);
			COUNT_BYTES_SUBR(padcnt);
		}
	}

	proto_item_append_text(item, " File: %s", fn);
	proto_item_set_len(item, offset-old_offset);

	*trunc = FALSE;
	return offset;
}

static int
dissect_4_3_4_6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
    int offset, guint16 *bcp, gboolean *trunc)
{
	int fn_len, sfn_len;
	const char *fn, *sfn;
	int old_offset = offset;
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	smb_info_t *si;
	guint32 neo;
	int padcnt;

	si = (smb_info_t *)pinfo->private_data;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, *bcp, "%s",
		    val_to_str(si->info_level, ff2_il_vals, "Unknown (0x%02x)"));
		tree = proto_item_add_subtree(item, ett_smb_ff2_data);
	}

	/* next entry offset */
	CHECK_BYTE_COUNT_SUBR(4);
	neo = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_next_entry_offset, tvb, offset, 4, neo);
	COUNT_BYTES_SUBR(4);
	
	/* file index */
	CHECK_BYTE_COUNT_SUBR(4);
	proto_tree_add_item(tree, hf_smb_file_index, tvb, offset, 4, TRUE);
	COUNT_BYTES_SUBR(4);

	/* create time */
	CHECK_BYTE_COUNT_SUBR(8);
	offset = dissect_smb_64bit_time(tvb, pinfo, tree, offset,
		"Create Time", hf_smb_create_time);
	*bcp -= 8;
	
	/* access time */
	CHECK_BYTE_COUNT_SUBR(8);
	offset = dissect_smb_64bit_time(tvb, pinfo, tree, offset,
		"Access Time", hf_smb_access_time);
	*bcp -= 8;
	
	/* last write time */
	CHECK_BYTE_COUNT_SUBR(8);
	offset = dissect_smb_64bit_time(tvb, pinfo, tree, offset,
		"Write Time", hf_smb_last_write_time);
	*bcp -= 8;
	
	/* last change time */
	CHECK_BYTE_COUNT_SUBR(8);
	offset = dissect_smb_64bit_time(tvb, pinfo, tree, offset,
		"Change Time", hf_smb_change_time);
	*bcp -= 8;
	
	/* end of file */
	CHECK_BYTE_COUNT_SUBR(8);
	proto_tree_add_item(tree, hf_smb_end_of_file, tvb, offset, 8, TRUE);
	COUNT_BYTES_SUBR(8);

	/* allocation size */
	CHECK_BYTE_COUNT_SUBR(8);
	proto_tree_add_item(tree, hf_smb_alloc_size64, tvb, offset, 8, TRUE);
	COUNT_BYTES_SUBR(8);

	/* Extended File Attributes */
	CHECK_BYTE_COUNT_SUBR(4);
	offset = dissect_file_ext_attr(tvb, pinfo, tree, offset);
	*bcp -= 4;

	/* file name len */
	CHECK_BYTE_COUNT_SUBR(4);
	fn_len = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_file_name_len, tvb, offset, 4, fn_len);
	COUNT_BYTES_SUBR(4);

	/* ea size */
	CHECK_BYTE_COUNT_SUBR(4);
	proto_tree_add_item(tree, hf_smb_ea_size, tvb, offset, 4, TRUE);
	COUNT_BYTES_SUBR(4);

	/* short file name len */
	CHECK_BYTE_COUNT_SUBR(1);
	sfn_len = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_short_file_name_len, tvb, offset, 1, sfn_len);
	COUNT_BYTES_SUBR(1);

	/* reserved byte */
	CHECK_BYTE_COUNT_SUBR(1);
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 1, TRUE);
	COUNT_BYTES_SUBR(1);
 
	/* short file name */
	sfn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &sfn_len, FALSE, TRUE, bcp);
	CHECK_STRING_SUBR(sfn);
	proto_tree_add_string(tree, hf_smb_short_file_name, tvb, offset, 24,
		sfn);
	COUNT_BYTES_SUBR(24);

	/* file name */
	fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len, FALSE, TRUE, bcp);
	CHECK_STRING_SUBR(fn);
	proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
		fn);
	COUNT_BYTES_SUBR(fn_len);

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, " %s",
		fn);
	}

	/* skip to next structure */
	if(neo){
		padcnt = (old_offset + neo) - offset;
		if (padcnt < 0) {
			/*
			 * XXX - this is bogus; flag it?
			 */
			padcnt = 0;
		}
		if (padcnt != 0) {
			CHECK_BYTE_COUNT_SUBR(padcnt);
			COUNT_BYTES_SUBR(padcnt);
		}
	}

	proto_item_append_text(item, " File: %s", fn);
	proto_item_set_len(item, offset-old_offset);

	*trunc = FALSE;
	return offset;
}

static int
dissect_4_3_4_7(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
    int offset, guint16 *bcp, gboolean *trunc)
{
	int fn_len;
	const char *fn;
	int old_offset = offset;
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	smb_info_t *si;
	guint32 neo;
	int padcnt;

	si = (smb_info_t *)pinfo->private_data;

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, *bcp, "%s",
		    val_to_str(si->info_level, ff2_il_vals, "Unknown (0x%02x)"));
		tree = proto_item_add_subtree(item, ett_smb_ff2_data);
	}
 
	/* next entry offset */
	CHECK_BYTE_COUNT_SUBR(4);
	neo = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_next_entry_offset, tvb, offset, 4, neo);
	COUNT_BYTES_SUBR(4);
	
	/* file index */
	CHECK_BYTE_COUNT_SUBR(4);
	proto_tree_add_item(tree, hf_smb_file_index, tvb, offset, 4, TRUE);
	COUNT_BYTES_SUBR(4);

	/* file name len */
	CHECK_BYTE_COUNT_SUBR(4);
	fn_len = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_file_name_len, tvb, offset, 4, fn_len);
	COUNT_BYTES_SUBR(4);

	/* file name */
	fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len, FALSE, TRUE, bcp);
	CHECK_STRING_SUBR(fn);
	proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
		fn);
	COUNT_BYTES_SUBR(fn_len);

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, " %s",
		fn);
	}

	/* skip to next structure */
	if(neo){
		padcnt = (old_offset + neo) - offset;
		if (padcnt < 0) {
			/*
			 * XXX - this is bogus; flag it?
			 */
			padcnt = 0;
		}
		if (padcnt != 0) {
			CHECK_BYTE_COUNT_SUBR(padcnt);
			COUNT_BYTES_SUBR(padcnt);
		}
	}

	proto_item_append_text(item, " File: %s", fn);
	proto_item_set_len(item, offset-old_offset);

	*trunc = FALSE;
	return offset;
}
 
static int
dissect_4_3_4_8(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
    int offset, guint16 *bcp, gboolean *trunc)
{
/*XXX im lazy. i havnt implemented this */
	offset += *bcp;
	*bcp = 0;
	*trunc = FALSE;
	return offset;
}

/*dissect the data block for TRANS2_FIND_FIRST2*/
static int
dissect_ff2_response_data(tvbuff_t * tvb, packet_info * pinfo,
    proto_tree * tree, int offset, guint16 *bcp, gboolean *trunc)
{
	smb_info_t *si;

	if(!*bcp){
		return offset;
	}
	
	si = (smb_info_t *)pinfo->private_data;
	switch(si->info_level){
	case 1:		/*Info Standard*/
		offset = dissect_4_3_4_1(tvb, pinfo, tree, offset, bcp,
		    trunc);
		break;
	case 2:		/*Info Query EA Size*/
		offset = dissect_4_3_4_2(tvb, pinfo, tree, offset, bcp,
		    trunc);
		break;
	case 3:		/*Info Query EAs From List same as 
				InfoQueryEASize*/
		offset = dissect_4_3_4_2(tvb, pinfo, tree, offset, bcp,
		    trunc);
		break;
	case 0x0101:	/*Find File Directory Info*/
		offset = dissect_4_3_4_4(tvb, pinfo, tree, offset, bcp,
		    trunc);
		break;
	case 0x0102:	/*Find File Full Directory Info*/
		offset = dissect_4_3_4_5(tvb, pinfo, tree, offset, bcp,
		    trunc);
		break;
	case 0x0103:	/*Find File Names Info*/
		offset = dissect_4_3_4_7(tvb, pinfo, tree, offset, bcp,
		    trunc);
		break;
	case 0x0104:	/*Find File Both Directory Info*/
		offset = dissect_4_3_4_6(tvb, pinfo, tree, offset, bcp,
		    trunc);
		break;
	case 0x0202:	/*Find File UNIX*/
		offset = dissect_4_3_4_8(tvb, pinfo, tree, offset, bcp,
		    trunc);
		break;
	default:	/* unknown info level */
		*trunc = FALSE;
		break;
	}
	return offset;
}


static int
dissect_fs_attributes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint32 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohl(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 4,
			"FS Attributes: 0x%08x", mask);
		tree = proto_item_add_subtree(item, ett_smb_fs_attributes);
	}

	proto_tree_add_boolean(tree, hf_smb_fs_attr_css,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_fs_attr_cpn,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_fs_attr_pacls,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_fs_attr_fc,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_fs_attr_vq,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_fs_attr_dim,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_fs_attr_vic,
		tvb, offset, 4, mask);

	offset += 4;
	return offset;
}
 

static int
dissect_device_characteristics(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint32 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohl(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 4,
			"Device Characteristics: 0x%08x", mask);
		tree = proto_item_add_subtree(item, ett_smb_device_characteristics);
	}

	proto_tree_add_boolean(tree, hf_smb_device_char_removable,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_device_char_read_only,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_device_char_floppy,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_device_char_write_once,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_device_char_remote,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_device_char_mounted,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_device_char_virtual,
		tvb, offset, 4, mask);

	offset += 4;
	return offset;
}


/*dissect the data block for TRANS2_QUERY_FS_INFORMATION*/
static int
dissect_qfsi_vals(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree,
    int offset, guint16 *bcp)
{
	smb_info_t *si;
	int fn_len, vll, fnl;
	const char *fn;

	if(!*bcp){
		return offset;
	}
	
	si = (smb_info_t *)pinfo->private_data;
	switch(si->info_level){
	case 1:		/* SMB_INFO_ALLOCATION */
		/* filesystem id */
		CHECK_BYTE_COUNT_TRANS_SUBR(4);
		proto_tree_add_item(tree, hf_smb_fs_id, tvb, offset, 4, TRUE);
		COUNT_BYTES_TRANS_SUBR(4);

		/* sectors per unit */
		CHECK_BYTE_COUNT_TRANS_SUBR(4);
		proto_tree_add_item(tree, hf_smb_sector_unit, tvb, offset, 4, TRUE);
		COUNT_BYTES_TRANS_SUBR(4);

		/* units */
		CHECK_BYTE_COUNT_TRANS_SUBR(4);
		proto_tree_add_item(tree, hf_smb_fs_units, tvb, offset, 4, TRUE);
		COUNT_BYTES_TRANS_SUBR(4);

		/* avail units */
		CHECK_BYTE_COUNT_TRANS_SUBR(4);
		proto_tree_add_item(tree, hf_smb_avail_units, tvb, offset, 4, TRUE);
		COUNT_BYTES_TRANS_SUBR(4);

		/* bytes per sector, only 16bit integer here */
		CHECK_BYTE_COUNT_TRANS_SUBR(2);
		proto_tree_add_uint(tree, hf_smb_fs_sector, tvb, offset, 2, tvb_get_letohs(tvb, offset));
		COUNT_BYTES_TRANS_SUBR(2);

		break;
	case 2:		/* SMB_INFO_VOLUME */
		/* volume serial number */
		CHECK_BYTE_COUNT_TRANS_SUBR(4);
		proto_tree_add_item(tree, hf_smb_volume_serial_num, tvb, offset, 4, TRUE);
		COUNT_BYTES_TRANS_SUBR(4);

		/* volume label length, only one byte here */
		CHECK_BYTE_COUNT_TRANS_SUBR(1);
		proto_tree_add_uint(tree, hf_smb_volume_label_len, tvb, offset, 1, tvb_get_guint8(tvb, offset));
		COUNT_BYTES_TRANS_SUBR(1);

		/* label */
		fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len, FALSE, FALSE, bcp);
		CHECK_STRING_TRANS_SUBR(fn);
		proto_tree_add_string(tree, hf_smb_volume_label, tvb, offset, fn_len,
			fn);
		COUNT_BYTES_TRANS_SUBR(fn_len);

		break;
	case 0x0102:	/* SMB_QUERY_FS_VOLUME_INFO */
		/* create time */
		CHECK_BYTE_COUNT_TRANS_SUBR(8);
		offset = dissect_smb_64bit_time(tvb, pinfo, tree, offset,
			"Create Time", hf_smb_create_time);
		*bcp -= 8;
	
		/* volume serial number */
		CHECK_BYTE_COUNT_TRANS_SUBR(4);
		proto_tree_add_item(tree, hf_smb_volume_serial_num, tvb, offset, 4, TRUE);
		COUNT_BYTES_TRANS_SUBR(4);

		/* volume label length */
		CHECK_BYTE_COUNT_TRANS_SUBR(4);
		vll = tvb_get_letohl(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_volume_label_len, tvb, offset, 4, vll);
		COUNT_BYTES_TRANS_SUBR(4);

		/* 2 reserved bytes */
		CHECK_BYTE_COUNT_TRANS_SUBR(2);
		proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 2, TRUE);
		COUNT_BYTES_TRANS_SUBR(2);

		/* label */
		fn_len = vll;
		fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len, FALSE, TRUE, bcp);
		CHECK_STRING_TRANS_SUBR(fn);
		proto_tree_add_string(tree, hf_smb_volume_label, tvb, offset, fn_len,
			fn);
		COUNT_BYTES_TRANS_SUBR(fn_len);

		break;
	case 0x0103:	/* SMB_QUERY_FS_SIZE_INFO */
		/* allocation size */
		CHECK_BYTE_COUNT_TRANS_SUBR(8);
		proto_tree_add_item(tree, hf_smb_alloc_size64, tvb, offset, 8, TRUE);
		COUNT_BYTES_TRANS_SUBR(8);

		/* free allocation units */
		CHECK_BYTE_COUNT_TRANS_SUBR(8);
		proto_tree_add_item(tree, hf_smb_free_alloc_units64, tvb, offset, 8, TRUE);
		COUNT_BYTES_TRANS_SUBR(8);

		/* sectors per unit */
		CHECK_BYTE_COUNT_TRANS_SUBR(4);
		proto_tree_add_item(tree, hf_smb_sector_unit, tvb, offset, 4, TRUE);
		COUNT_BYTES_TRANS_SUBR(4);

		/* bytes per sector */
		CHECK_BYTE_COUNT_TRANS_SUBR(4);
		proto_tree_add_item(tree, hf_smb_fs_sector, tvb, offset, 4, TRUE);
		COUNT_BYTES_TRANS_SUBR(4);

		break;
	case 0x0104:	/* SMB_QUERY_FS_DEVICE_INFO */
		/* device type */
		CHECK_BYTE_COUNT_TRANS_SUBR(4);
		proto_tree_add_item(tree, hf_smb_device_type, tvb, offset, 4, TRUE);
		COUNT_BYTES_TRANS_SUBR(4);
 
		/* device characteristics */
		CHECK_BYTE_COUNT_TRANS_SUBR(4);
		offset = dissect_device_characteristics(tvb, pinfo, tree, offset);
		*bcp -= 4;
	
		break;
	case 0x0105:	/* SMB_QUERY_FS_ATTRIBUTE_INFO */
		/* FS attributes */
		CHECK_BYTE_COUNT_TRANS_SUBR(4);
		offset = dissect_fs_attributes(tvb, pinfo, tree, offset);
		*bcp -= 4;
	
		/* max name len */
		CHECK_BYTE_COUNT_TRANS_SUBR(4);
		proto_tree_add_item(tree, hf_smb_max_name_len, tvb, offset, 4, TRUE);
		COUNT_BYTES_TRANS_SUBR(4);

		/* fs name length */
		CHECK_BYTE_COUNT_TRANS_SUBR(4);
		fnl = tvb_get_letohl(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_fs_name_len, tvb, offset, 4, fnl);
		COUNT_BYTES_TRANS_SUBR(4);

		/* label */
		fn_len = fnl;
		fn = get_unicode_or_ascii_string(tvb, &offset, pinfo, &fn_len, FALSE, TRUE, bcp);
		CHECK_STRING_TRANS_SUBR(fn);
		proto_tree_add_string(tree, hf_smb_fs_name, tvb, offset, fn_len,
			fn);
		COUNT_BYTES_TRANS_SUBR(fn_len);

		break;
	}
 
	return offset;
}
 
static int
dissect_transaction2_response_data(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *parent_tree)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	smb_info_t *si;
	smb_transact2_info_t *t2i;
	int count;
	gboolean trunc;
	int offset = 0;
	guint16 dc;

	dc = tvb_reported_length(tvb);

	si = (smb_info_t *)pinfo->private_data;
	if (si->sip != NULL)
		t2i = si->sip->extra_info;
	else
		t2i = NULL;

	if(parent_tree){
		if (t2i != NULL && t2i->subcmd != -1) {
			item = proto_tree_add_text(parent_tree, tvb, offset, dc,
				"%s Data",
				val_to_str(t2i->subcmd, trans2_cmd_vals, 
					"Unknown (0x%02x)"));
			tree = proto_item_add_subtree(item, ett_smb_transaction_data);
		} else {
			item = proto_tree_add_text(parent_tree, tvb, offset, dc,
				"Unknown Transaction2 Data");
		}
	}

	if (t2i == NULL) {
		offset += dc;
		return offset;
	}
	switch(t2i->subcmd){
	case 0x00:	/*TRANS2_OPEN2*/
		/* XXX not implemented yet. See SNIA doc */
		break;
	case 0x01:	/*TRANS2_FIND_FIRST2*/
		/* returned data */
		count = si->info_count;

		if (count && check_col(pinfo->fd, COL_INFO)) {
			col_append_fstr(pinfo->fd, COL_INFO,
			", Files:");
		}

		while(count--){
			offset = dissect_ff2_response_data(tvb, pinfo, tree,
				offset, &dc, &trunc);
			if (trunc)
				break;
		}
		break;
	case 0x02:	/*TRANS2_FIND_NEXT2*/
		/* returned data */
		count = si->info_count;

		if (count && check_col(pinfo->fd, COL_INFO)) {
			col_append_fstr(pinfo->fd, COL_INFO,
			", Files:");
		}

		while(count--){
			offset = dissect_ff2_response_data(tvb, pinfo, tree,
				offset, &dc, &trunc);
			if (trunc)
				break;
		}
		break;
	case 0x03:	/*TRANS2_QUERY_FS_INFORMATION*/
		offset = dissect_qfsi_vals(tvb, pinfo, tree, offset, &dc);
		break;
	case 0x05:	/*TRANS2_QUERY_PATH_INFORMATION*/
		offset = dissect_qpi_loi_vals(tvb, pinfo, tree, offset, &dc);
		break;
	case 0x06:	/*TRANS2_SET_PATH_INFORMATION*/
		/* no data in this response */
		break;
	case 0x07:	/*TRANS2_QUERY_FILE_INFORMATION*/
		/* identical to QUERY_PATH_INFO */
		offset = dissect_qpi_loi_vals(tvb, pinfo, tree, offset, &dc);
		break;
	case 0x08:	/*TRANS2_SET_FILE_INFORMATION*/
		/* no data in this response */
		break;
	case 0x09:	/*TRANS2_FSCTL*/
		/* XXX dont know how to dissect this one (yet)*/
		break;
	case 0x0a:	/*TRANS2_IOCTL2*/
		/* XXX dont know how to dissect this one (yet)*/
		break;
	case 0x0b:	/*TRANS2_FIND_NOTIFY_FIRST*/
		/* XXX dont know how to dissect this one (yet)*/
		break;
	case 0x0c:	/*TRANS2_FIND_NOTIFY_NEXT*/
		/* XXX dont know how to dissect this one (yet)*/
		break;
	case 0x0d:	/*TRANS2_CREATE_DIRECTORY*/
		/* no data in this response */
		break;
	case 0x0e:	/*TRANS2_SESSION_SETUP*/
		/* XXX dont know how to dissect this one (yet)*/
		break;
	case 0x10:	/*TRANS2_GET_DFS_REFERRAL*/
		offset = dissect_get_dfs_referral_data(tvb, pinfo, tree, offset, &dc);
		break;
	case 0x11:	/*TRANS2_REPORT_DFS_INCONSISTENCY*/
		/* the SNIA spec appears to say the response has no data */
		break;
	case -1:
		/*
		 * We don't know what the matching request was; don't
		 * bother putting anything else into the tree for the data.
		 */
		offset += dc;
		dc = 0;
		break;
	}

	/* ooops there were data we didnt know how to process */
	if(dc != 0){
		proto_tree_add_item(tree, hf_smb_unknown, tvb, offset, dc, TRUE);
		offset += dc;
	}

	return offset;
}


static void
dissect_transaction2_response_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	smb_info_t *si;
	smb_transact2_info_t *t2i;
	guint16 fid;
	int lno;
	int offset = 0;
	int pc;

	pc = tvb_reported_length(tvb);

	si = (smb_info_t *)pinfo->private_data;
	if (si->sip != NULL)
		t2i = si->sip->extra_info;
	else
		t2i = NULL;

	if(parent_tree){
		if (t2i != NULL && t2i->subcmd != -1) {
			item = proto_tree_add_text(parent_tree, tvb, offset, pc,
				"%s Parameters",
				val_to_str(t2i->subcmd, trans2_cmd_vals, 
						"Unknown (0x%02x)"));
			tree = proto_item_add_subtree(item, ett_smb_transaction_params);
		} else {
			item = proto_tree_add_text(parent_tree, tvb, offset, pc,
				"Unknown Transaction2 Parameters");
		}
	}

	if (t2i == NULL) {
		offset += pc;
		return;
	}
	switch(t2i->subcmd){
	case 0x00:	/*TRANS2_OPEN2*/
		/* fid */
		fid = tvb_get_letohs(tvb, offset);
		add_fid(tvb, pinfo, tree, offset, 2, fid);
		offset += 2;

		/* File Attributes */
		offset = dissect_file_attributes(tvb, pinfo, tree, offset);

		/* create time */
		offset = dissect_smb_datetime(tvb, pinfo, tree, offset,
			hf_smb_create_time, 
			hf_smb_create_dos_date, hf_smb_create_dos_time, TRUE);

		/* data size */
		proto_tree_add_item(tree, hf_smb_data_size, tvb, offset, 4, TRUE);
		offset += 4;

		/* granted access */
		offset = dissect_access(tvb, pinfo, tree, offset, "Granted");

		/* File Type */
		proto_tree_add_item(tree, hf_smb_file_type, tvb, offset, 2, TRUE);
		offset += 2;

		/* IPC State */
		offset = dissect_ipc_state(tvb, pinfo, tree, offset, FALSE);

		/* open_action */
		offset = dissect_open_action(tvb, pinfo, tree, offset);

		/* 4 reserved bytes */
		proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 4, TRUE);
		offset += 4;

		/* ea error offset, only a 16 bit integer here */
		proto_tree_add_uint(tree, hf_smb_ea_error_offset, tvb, offset, 2, tvb_get_letohs(tvb, offset));
		offset += 2;

		/* ea length */
		proto_tree_add_item(tree, hf_smb_ea_length, tvb, offset, 4, TRUE);
		offset += 4;

		break;
	case 0x01:	/*TRANS2_FIND_FIRST2*/
		/* Find First2 information level */
		proto_tree_add_uint(tree, hf_smb_ff2_information_level, tvb, 0, 0, si->info_level);

		/* sid */
		proto_tree_add_item(tree, hf_smb_sid, tvb, offset, 2, TRUE);
		offset += 2;

		/* search count */
		si->info_count = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_search_count, tvb, offset, 2, si->info_count);
		offset += 2;

		/* end of search */
		proto_tree_add_item(tree, hf_smb_end_of_search, tvb, offset, 2, TRUE);
		offset += 2;

		/* ea error offset, only a 16 bit integer here */
		proto_tree_add_uint(tree, hf_smb_ea_error_offset, tvb, offset, 2, tvb_get_letohs(tvb, offset));
		offset += 2;

		/* last name offset */
		lno = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_last_name_offset, tvb, offset, 2, lno);
		offset += 2;

		break;
	case 0x02:	/*TRANS2_FIND_NEXT2*/
		/* search count */
		si->info_count = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_search_count, tvb, offset, 2, si->info_count);
		offset += 2;

		/* end of search */
		proto_tree_add_item(tree, hf_smb_end_of_search, tvb, offset, 2, TRUE);
		offset += 2;

		/* ea error offset , only a 16 bit integer here*/
		proto_tree_add_uint(tree, hf_smb_ea_error_offset, tvb, offset, 2, tvb_get_letohs(tvb, offset));
		offset += 2;

		/* last name offset */
		lno = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_last_name_offset, tvb, offset, 2, lno);
		offset += 2;

		break;
	case 0x03:	/*TRANS2_QUERY_FS_INFORMATION*/
		/* no parameter block here */
		break;
	case 0x05:	/*TRANS2_QUERY_PATH_INFORMATION*/
		/* no parameter block here */
		break;
	case 0x06:	/*TRANS2_SET_PATH_INFORMATION*/
		/* no parameter block here */
		break;
	case 0x07:	/*TRANS2_QUERY_FILE_INFORMATION*/
		/* no parameter block here */
		break;
	case 0x08:	/*TRANS2_SET_FILE_INFORMATION*/
		/* no parameter block here */
		break;
	case 0x09:	/*TRANS2_FSCTL*/
		/* XXX dont know how to dissect this one (yet)*/
		break;
	case 0x0a:	/*TRANS2_IOCTL2*/
		/* XXX dont know how to dissect this one (yet)*/
		break;
	case 0x0b:	/*TRANS2_FIND_NOTIFY_FIRST*/
		/* XXX dont know how to dissect this one (yet)*/
		break;
	case 0x0c:	/*TRANS2_FIND_NOTIFY_NEXT*/
		/* XXX dont know how to dissect this one (yet)*/
		break;
	case 0x0d:	/*TRANS2_CREATE_DIRECTORY*/
		/* ea error offset, only a 16 bit integer here */
		proto_tree_add_uint(tree, hf_smb_ea_error_offset, tvb, offset, 2, tvb_get_letohs(tvb, offset));
		offset += 2;

		break;
	case 0x0e:	/*TRANS2_SESSION_SETUP*/
		/* XXX dont know how to dissect this one (yet)*/
		break;
	case 0x10:	/*TRANS2_GET_DFS_REFERRAL*/
		/* XXX dont know how to dissect this one (yet) see SNIA doc*/
		break;
	case 0x11:	/*TRANS2_REPORT_DFS_INCONSISTENCY*/
		/* XXX dont know how to dissect this one (yet) see SNIA doc*/
		break;
	case -1:
		/*
		 * We don't know what the matching request was; don't
		 * bother putting anything else into the tree for the data.
		 */
		offset += pc;
		break;
	}

	/* ooops there were data we didnt know how to process */
	if(offset<pc){
		proto_tree_add_item(tree, hf_smb_unknown, tvb, offset, pc-offset, TRUE);
		offset += pc-offset;
	}
}


static int
dissect_transaction_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 sc, wc;
	guint16 od=0, po=0, pc=0, pd=0, dc=0, dd=0, td=0, tp=0;
	gboolean reassembled = FALSE;
	smb_info_t *si;
	smb_transact2_info_t *t2i = NULL;
	guint16 bc;
	int padcnt;
	gboolean dissected_trans;
	fragment_data *r_fd = NULL;
	tvbuff_t *pd_tvb=NULL, *d_tvb=NULL, *p_tvb=NULL;
	tvbuff_t *s_tvb=NULL, *sp_tvb=NULL;

	si = (smb_info_t *)pinfo->private_data;

	switch(si->cmd){
	case SMB_COM_TRANSACTION2:
		/* transaction2 */
		if (si->sip != NULL) {
			t2i = si->sip->extra_info;
			si->info_level = t2i->info_level;
		} else
			t2i = NULL;
		if (t2i == NULL) {
			/*
			 * We didn't see the matching request, so we don't
			 * know what type of transaction this is.
			 */
			proto_tree_add_text(tree, tvb, 0, 0,
				"Subcommand: <UNKNOWN> since request packet wasn't seen");
			if (check_col(pinfo->fd, COL_INFO)) {
				col_append_fstr(pinfo->fd, COL_INFO, "<unknown>");
			}
		} else if (t2i->subcmd == -1) {
			/*
			 * We didn't manage to extract the subcommand
			 * from the matching request (perhaps because
			 * the frame was short), so we don't know what
			 * type of transaction this is.
			 */
			proto_tree_add_text(tree, tvb, 0, 0,
				"Subcommand: <UNKNOWN> since transaction code wasn't found in request packet");
			if (check_col(pinfo->fd, COL_INFO)) {
				col_append_fstr(pinfo->fd, COL_INFO, "<unknown>");
			}
		} else {
			proto_tree_add_uint(tree, hf_smb_trans2_subcmd, tvb, 0, 0, t2i->subcmd);
			if (check_col(pinfo->fd, COL_INFO)) {
				col_append_fstr(pinfo->fd, COL_INFO, " %s",
					val_to_str(t2i->subcmd,
						trans2_cmd_vals, 
						"<unknown (0x%02x)>"));
			}
		}
		break;
	}

	WORD_COUNT;

	/* total param count, only a 16bit integer here */
	tp = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_total_param_count, tvb, offset, 2, tp);
	offset += 2;

	/* total data count, only a 16 bit integer here */
	td = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_total_data_count, tvb, offset, 2, td);
	offset += 2;

	/* 2 reserved bytes */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 2, TRUE);
	offset += 2;

	/* param count */
	pc = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_param_count16, tvb, offset, 2, pc);
	offset += 2;

	/* param offset */
	po = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_param_offset16, tvb, offset, 2, po);
	offset += 2;

	/* param disp */
	pd = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_param_disp16, tvb, offset, 2, pd);
	offset += 2;

	/* data count */
	dc = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_data_count16, tvb, offset, 2, dc);
	offset += 2;

	/* data offset */
	od = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_data_offset16, tvb, offset, 2, od);
	offset += 2;

	/* data disp */
	dd = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_data_disp16, tvb, offset, 2, dd);
	offset += 2;

	/* setup count */
	sc = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_setup_count, tvb, offset, 1, sc);
	offset += 1;

	/* reserved byte */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 1, TRUE);
	offset += 1;


	/* if there were any setup bytes, put them in a tvb for later */
	if(sc){
		if((2*sc)>tvb_length_remaining(tvb, offset)){
			s_tvb = tvb_new_subset(tvb, offset, tvb_length_remaining(tvb, offset), 2*sc);
		} else {
			s_tvb = tvb_new_subset(tvb, offset, 2*sc, 2*sc);
		}
		sp_tvb = tvb_new_subset(tvb, offset, -1, -1);
	} else {
		s_tvb = NULL;
		sp_tvb=NULL;
	}
	offset += 2*sc;


	BYTE_COUNT;


	/* reassembly of SMB Transaction data payload.
	   In this section we do reassembly of both the data and parameters
	   blocks of the SMB transaction command.
	*/
	if(smb_trans_reassembly){
		/* do we need reassembly? */
		if( (td!=dc) || (tp!=pc) ){
			/* oh yeah, either data or parameter section needs 
			   reassembly
			*/
			if(pc && (tvb_length_remaining(tvb, po)>=pc) ){
				r_fd = smb_trans_defragment(tree, pinfo, tvb, 
							     po, pc, pd, td+tp);
				
			}
			if((r_fd==NULL) && dc && (tvb_length_remaining(tvb, od)>=dc) ){
				r_fd = smb_trans_defragment(tree, pinfo, tvb, 
							     od, dc, dd+tp, td+tp);
			}
		}
	}

	/* if we got a reassembled fd structure from the reassembly routine we must
	   create pd_tvb from it 
	*/
	if(r_fd){
		proto_tree *tr;
		proto_item *it;
		fragment_data *fd;
		
		it = proto_tree_add_text(tree, tvb, 0, 0, "Fragments");
		tr = proto_item_add_subtree(it, ett_smb_segments);
		for(fd=r_fd->next;fd;fd=fd->next){
			proto_tree_add_text(tr, tvb, 0, 0, "Frame:%d Data:%d-%d",
					    fd->frame, fd->offset, fd->offset+fd->len-1);
		}
		
		pd_tvb = tvb_new_real_data(r_fd->data, r_fd->datalen,
					     r_fd->datalen, "Reassembled SMB");
		tvb_set_child_real_data_tvbuff(tvb, pd_tvb);
		pinfo->fd->data_src = g_slist_append(pinfo->fd->data_src, pd_tvb);
		pinfo->fragmented = FALSE;
	}


	if(pd_tvb){
		/* OK we have reassembled data, extract d_tvb and p_tvb from it */
		if(tp){
			p_tvb = tvb_new_subset(pd_tvb, 0, tp, tp);
		}
		if(td){
			d_tvb = tvb_new_subset(pd_tvb, tp, td, td);
		}
	} else {
		/* It was not reassembled. Do as best as we can.
		 * in this case we always try to dissect the stuff if 
		 * data and param displacement is 0. i.e. for the first
		 * (and maybe only) packet.
		 */
		if( (pd==0) && (dd==0) ){
			int min;
			int reported_min;
			min = MIN(pc,tvb_length_remaining(tvb,po));
			reported_min = MIN(pc,tvb_reported_length_remaining(tvb,po));
			if(min && reported_min) {
				p_tvb = tvb_new_subset(tvb, po, min, reported_min);
			}
			min = MIN(dc,tvb_length_remaining(tvb,od));
			reported_min = MIN(dc,tvb_reported_length_remaining(tvb,od));
			if(min && reported_min) {
				d_tvb = tvb_new_subset(tvb, od, min, reported_min);
			}
			/*
			 * A tvbuff containing the parameters
			 * and the data.
			 * XXX - check pc and dc as well?
			 */
			if (tvb_length_remaining(tvb, po)){
				pd_tvb = tvb_new_subset(tvb, po, -1, -1);
			}
		}
	}



	/* parameters */
	if(po>offset){
		/* We have some padding bytes.
		*/
		padcnt = po-offset;
		if (padcnt > bc)
			padcnt = bc;
		proto_tree_add_item(tree, hf_smb_padding, tvb, offset, padcnt, TRUE);
		COUNT_BYTES(padcnt);
	}
	if(si->cmd==SMB_COM_TRANSACTION2 && p_tvb){
		/* TRANSACTION2 parameters*/
		dissect_transaction2_response_parameters(p_tvb, pinfo, tree);
	}
	COUNT_BYTES(pc);


	/* data */
	if(od>offset){
		/* We have some initial padding bytes.
		*/
		padcnt = od-offset;
		if (padcnt > bc)
			padcnt = bc;
		proto_tree_add_item(tree, hf_smb_padding, tvb, offset, padcnt, TRUE);
		COUNT_BYTES(padcnt);
	}
	/*
	 * If the data count is bigger than the count of bytes
	 * remaining, clamp it so that the count of bytes remaining
	 * doesn't go negative.
	 */
	if (dc > bc)
		dc = bc;
	COUNT_BYTES(dc);



	/* from now on, everything is in separate tvbuffs so we dont count
	   the bytes with COUNT_BYTES any more.
	   neither do we reference offset any more (which by now points to the
	   first byte AFTER this PDU */


	if(si->cmd==SMB_COM_TRANSACTION2 && d_tvb){
		/* TRANSACTION2 parameters*/
		dissect_transaction2_response_data(d_tvb, pinfo, tree);
	}


	if(si->cmd==SMB_COM_TRANSACTION){
		smb_transact_info_t *tri;

		dissected_trans = FALSE;
		if (si->sip != NULL)
			tri = si->sip->extra_info;
		else
			tri = NULL;
		if (tri != NULL) {
			switch(tri->subcmd){

			case TRANSACTION_PIPE:
				/* This function is safe to call for 
				   s_tvb==sp_tvb==NULL, i.e. if we don't
				   know them at this point.
				   It's also safe to call if "p_tvb"
				   or "d_tvb" are null.
				*/
				if( pd_tvb) {
					dissected_trans = dissect_pipe_smb(
						sp_tvb, s_tvb, pd_tvb, p_tvb,
						d_tvb, NULL, pinfo, top_tree);
				}
				break;
				
			case TRANSACTION_MAILSLOT:
				/* This one should be safe to call
				   even if s_tvb and sp_tvb is NULL
				*/
				if(d_tvb){
					dissected_trans = dissect_mailslot_smb(
						sp_tvb, s_tvb, d_tvb, NULL, pinfo,
						top_tree);
				}
				break;
			}
		}
		if (!dissected_trans) {
			/* This one is safe to call for s_tvb==p_tvb==d_tvb==NULL */
			dissect_trans_data(s_tvb, p_tvb, d_tvb,
					   pinfo, tree);
		}
	}


	if( (p_tvb==0) && (d_tvb==0) ){
		if(check_col(pinfo->fd, COL_INFO)){
			col_append_str(pinfo->fd, COL_INFO,
				       "[transact continuation]");
		}
	}

	END_OF_SMB

	return offset;
}


/* XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   END Transaction/Transaction2 Primary and secondary requests
   XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX */


static int
dissect_unknown(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;

	WORD_COUNT;
 
	if (wc != 0)
		proto_tree_add_text(tree, tvb, offset, wc*2, "Word parameters");

	BYTE_COUNT;

	if (bc != 0)
		proto_tree_add_text(tree, tvb, offset, bc, "Byte parameters");

	END_OF_SMB

	return offset;
}

typedef struct _smb_function {
       int (*request)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree);
       int (*response)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree);
} smb_function;

smb_function smb_dissector[256] = {
  /* 0x00 Create Dir*/  {dissect_old_dir_request, dissect_empty},
  /* 0x01 Delete Dir*/  {dissect_old_dir_request, dissect_empty},
  /* 0x02 Open File*/  {dissect_open_file_request, dissect_open_file_response},
  /* 0x03 Create File*/  {dissect_create_file_request, dissect_fid},
  /* 0x04 Close File*/  {dissect_close_file_request, dissect_empty},
  /* 0x05 Flush File*/  {dissect_fid, dissect_empty},
  /* 0x06 Delete File*/  {dissect_delete_file_request, dissect_empty},
  /* 0x07 Rename File*/  {dissect_rename_file_request, dissect_empty},
  /* 0x08 Query Info*/  {dissect_query_information_request, dissect_query_information_response},
  /* 0x09 Set Info*/  {dissect_set_information_request, dissect_empty},
  /* 0x0a Read File*/  {dissect_read_file_request, dissect_read_file_response},
  /* 0x0b Write File*/  {dissect_write_file_request, dissect_write_file_response},
  /* 0x0c Lock Byte Range*/  {dissect_lock_request, dissect_empty},
  /* 0x0d Unlock Byte Range*/  {dissect_lock_request, dissect_empty},
  /* 0x0e Create Temp*/  {dissect_create_temporary_request, dissect_create_temporary_response},
  /* 0x0f Create New*/  {dissect_create_file_request, dissect_fid},

  /* 0x10 Check Dir*/  {dissect_old_dir_request, dissect_empty},
  /* 0x11 Process Exit*/  {dissect_empty, dissect_empty},
  /* 0x12 Seek File*/  {dissect_seek_file_request, dissect_seek_file_response},
  /* 0x13 Lock And Read*/  {dissect_read_file_request, dissect_lock_and_read_response},
  /* 0x14 Write And Unlock*/  {dissect_write_file_request, dissect_write_file_response},
  /* 0x15 */  {dissect_unknown, dissect_unknown},
  /* 0x16 */  {dissect_unknown, dissect_unknown},
  /* 0x17 */  {dissect_unknown, dissect_unknown},
  /* 0x18 */  {dissect_unknown, dissect_unknown},
  /* 0x19 */  {dissect_unknown, dissect_unknown},
  /* 0x1a Read Raw*/  {dissect_read_raw_request, dissect_unknown},
  /* 0x1b Read MPX*/  {dissect_read_mpx_request, dissect_read_mpx_response},
  /* 0x1c */  {dissect_unknown, dissect_unknown},
  /* 0x1d Write Raw*/  {dissect_write_raw_request, dissect_write_raw_response},
  /* 0x1e Write MPX*/  {dissect_write_mpx_request, dissect_write_mpx_response},
  /* 0x1f */  {dissect_unknown, dissect_unknown},

  /* 0x20 Write Complete*/  {dissect_unknown, dissect_write_and_close_response},
  /* 0x21 */  {dissect_unknown, dissect_unknown},
  /* 0x22 Set Info2*/  {dissect_set_information2_request, dissect_empty},
  /* 0x23 Query Info2*/  {dissect_fid, dissect_query_information2_response},
  /* 0x24 Locking And X*/  {dissect_locking_andx_request, dissect_locking_andx_response},
  /* 0x25 Transaction*/		{dissect_transaction_request, dissect_transaction_response},
  /* 0x26 Transaction Secondary */  {dissect_transaction_request, dissect_unknown}, /*This SMB has no response */
  /* 0x27 */  {dissect_unknown, dissect_unknown},
  /* 0x28 */  {dissect_unknown, dissect_unknown},
  /* 0x29 */  {dissect_unknown, dissect_unknown},
  /* 0x2a Move File*/  {dissect_move_request, dissect_move_response},
  /* 0x2b Echo*/  {dissect_echo_request, dissect_echo_response},
  /* 0x2c Write And Close*/  {dissect_write_and_close_request, dissect_write_and_close_response},
  /* 0x2d Open And X*/  {dissect_open_andx_request, dissect_open_andx_response},
  /* 0x2e Read And X*/  {dissect_read_andx_request, dissect_read_andx_response},
  /* 0x2f Write And X*/  {dissect_write_andx_request, dissect_write_andx_response},

  /* 0x30 */  {dissect_unknown, dissect_unknown},
  /* 0x31 */  {dissect_unknown, dissect_unknown},
  /* 0x32 Transaction2*/		{dissect_transaction_request, dissect_transaction_response},
  /* 0x33 Transaction2 Secondary*/  {dissect_transaction_request, dissect_unknown}, /*This SMB has no response */
  /* 0x34 Find Close2*/  {dissect_sid, dissect_empty},
  /* 0x35 */  {dissect_unknown, dissect_unknown},
  /* 0x36 */  {dissect_unknown, dissect_unknown},
  /* 0x37 */  {dissect_unknown, dissect_unknown},
  /* 0x38 */  {dissect_unknown, dissect_unknown},
  /* 0x39 */  {dissect_unknown, dissect_unknown},
  /* 0x3a */  {dissect_unknown, dissect_unknown},
  /* 0x3b */  {dissect_unknown, dissect_unknown},
  /* 0x3c */  {dissect_unknown, dissect_unknown},
  /* 0x3d */  {dissect_unknown, dissect_unknown},
  /* 0x3e */  {dissect_unknown, dissect_unknown},
  /* 0x3f */  {dissect_unknown, dissect_unknown},

  /* 0x40 */  {dissect_unknown, dissect_unknown},
  /* 0x41 */  {dissect_unknown, dissect_unknown},
  /* 0x42 */  {dissect_unknown, dissect_unknown},
  /* 0x43 */  {dissect_unknown, dissect_unknown},
  /* 0x44 */  {dissect_unknown, dissect_unknown},
  /* 0x45 */  {dissect_unknown, dissect_unknown},
  /* 0x46 */  {dissect_unknown, dissect_unknown},
  /* 0x47 */  {dissect_unknown, dissect_unknown},
  /* 0x48 */  {dissect_unknown, dissect_unknown},
  /* 0x49 */  {dissect_unknown, dissect_unknown},
  /* 0x4a */  {dissect_unknown, dissect_unknown},
  /* 0x4b */  {dissect_unknown, dissect_unknown},
  /* 0x4c */  {dissect_unknown, dissect_unknown},
  /* 0x4d */  {dissect_unknown, dissect_unknown},
  /* 0x4e */  {dissect_unknown, dissect_unknown},
  /* 0x4f */  {dissect_unknown, dissect_unknown},

  /* 0x50 */  {dissect_unknown, dissect_unknown},
  /* 0x51 */  {dissect_unknown, dissect_unknown},
  /* 0x52 */  {dissect_unknown, dissect_unknown},
  /* 0x53 */  {dissect_unknown, dissect_unknown},
  /* 0x54 */  {dissect_unknown, dissect_unknown},
  /* 0x55 */  {dissect_unknown, dissect_unknown},
  /* 0x56 */  {dissect_unknown, dissect_unknown},
  /* 0x57 */  {dissect_unknown, dissect_unknown},
  /* 0x58 */  {dissect_unknown, dissect_unknown},
  /* 0x59 */  {dissect_unknown, dissect_unknown},
  /* 0x5a */  {dissect_unknown, dissect_unknown},
  /* 0x5b */  {dissect_unknown, dissect_unknown},
  /* 0x5c */  {dissect_unknown, dissect_unknown},
  /* 0x5d */  {dissect_unknown, dissect_unknown},
  /* 0x5e */  {dissect_unknown, dissect_unknown},
  /* 0x5f */  {dissect_unknown, dissect_unknown},

  /* 0x60 */  {dissect_unknown, dissect_unknown},
  /* 0x61 */  {dissect_unknown, dissect_unknown},
  /* 0x62 */  {dissect_unknown, dissect_unknown},
  /* 0x63 */  {dissect_unknown, dissect_unknown},
  /* 0x64 */  {dissect_unknown, dissect_unknown},
  /* 0x65 */  {dissect_unknown, dissect_unknown},
  /* 0x66 */  {dissect_unknown, dissect_unknown},
  /* 0x67 */  {dissect_unknown, dissect_unknown},
  /* 0x68 */  {dissect_unknown, dissect_unknown},
  /* 0x69 */  {dissect_unknown, dissect_unknown},
  /* 0x6a */  {dissect_unknown, dissect_unknown},
  /* 0x6b */  {dissect_unknown, dissect_unknown},
  /* 0x6c */  {dissect_unknown, dissect_unknown},
  /* 0x6d */  {dissect_unknown, dissect_unknown},
  /* 0x6e */  {dissect_unknown, dissect_unknown},
  /* 0x6f */  {dissect_unknown, dissect_unknown},

  /* 0x70 Tree Connect*/  {dissect_tree_connect_request, dissect_tree_connect_response},
  /* 0x71 Tree Disconnect*/  {dissect_empty, dissect_empty},
  /* 0x72 Negotiate Protocol*/	{dissect_negprot_request, dissect_negprot_response},
  /* 0x73 Session Setup And X*/  {dissect_session_setup_andx_request, dissect_session_setup_andx_response},
  /* 0x74 Logoff And X*/  {dissect_empty_andx, dissect_empty_andx},
  /* 0x75 Tree Connect And X*/  {dissect_tree_connect_andx_request, dissect_tree_connect_andx_response},
  /* 0x76 */  {dissect_unknown, dissect_unknown},
  /* 0x77 */  {dissect_unknown, dissect_unknown},
  /* 0x78 */  {dissect_unknown, dissect_unknown},
  /* 0x79 */  {dissect_unknown, dissect_unknown},
  /* 0x7a */  {dissect_unknown, dissect_unknown},
  /* 0x7b */  {dissect_unknown, dissect_unknown},
  /* 0x7c */  {dissect_unknown, dissect_unknown},
  /* 0x7d */  {dissect_unknown, dissect_unknown},
  /* 0x7e */  {dissect_unknown, dissect_unknown},
  /* 0x7f */  {dissect_unknown, dissect_unknown},

  /* 0x80 Query Info Disk*/  {dissect_empty, dissect_query_information_disk_response},
  /* 0x81 Search Dir*/  {dissect_search_dir_request, dissect_search_dir_response},
  /* 0x82 */  {dissect_unknown, dissect_unknown},
  /* 0x83 */  {dissect_unknown, dissect_unknown},
  /* 0x84 */  {dissect_unknown, dissect_unknown},
  /* 0x85 */  {dissect_unknown, dissect_unknown},
  /* 0x86 */  {dissect_unknown, dissect_unknown},
  /* 0x87 */  {dissect_unknown, dissect_unknown},
  /* 0x88 */  {dissect_unknown, dissect_unknown},
  /* 0x89 */  {dissect_unknown, dissect_unknown},
  /* 0x8a */  {dissect_unknown, dissect_unknown},
  /* 0x8b */  {dissect_unknown, dissect_unknown},
  /* 0x8c */  {dissect_unknown, dissect_unknown},
  /* 0x8d */  {dissect_unknown, dissect_unknown},
  /* 0x8e */  {dissect_unknown, dissect_unknown},
  /* 0x8f */  {dissect_unknown, dissect_unknown},

  /* 0x90 */  {dissect_unknown, dissect_unknown},
  /* 0x91 */  {dissect_unknown, dissect_unknown},
  /* 0x92 */  {dissect_unknown, dissect_unknown},
  /* 0x93 */  {dissect_unknown, dissect_unknown},
  /* 0x94 */  {dissect_unknown, dissect_unknown},
  /* 0x95 */  {dissect_unknown, dissect_unknown},
  /* 0x96 */  {dissect_unknown, dissect_unknown},
  /* 0x97 */  {dissect_unknown, dissect_unknown},
  /* 0x98 */  {dissect_unknown, dissect_unknown},
  /* 0x99 */  {dissect_unknown, dissect_unknown},
  /* 0x9a */  {dissect_unknown, dissect_unknown},
  /* 0x9b */  {dissect_unknown, dissect_unknown},
  /* 0x9c */  {dissect_unknown, dissect_unknown},
  /* 0x9d */  {dissect_unknown, dissect_unknown},
  /* 0x9e */  {dissect_unknown, dissect_unknown},
  /* 0x9f */  {dissect_unknown, dissect_unknown},
  /* 0xa0 NT Transaction*/  	{dissect_nt_transaction_request, dissect_nt_transaction_response},
  /* 0xa1 NT Trans secondary*/	{dissect_nt_transaction_request, dissect_nt_transaction_response},
  /* 0xa2 NT CreateAndX*/		{dissect_nt_create_andx_request, dissect_nt_create_andx_response},
  /* 0xa3 */  {dissect_unknown, dissect_unknown},
  /* 0xa4 NT Cancel*/		{dissect_nt_cancel_request, dissect_unknown}, /*no response to this one*/
  /* 0xa5 */  {dissect_unknown, dissect_unknown},
  /* 0xa6 */  {dissect_unknown, dissect_unknown},
  /* 0xa7 */  {dissect_unknown, dissect_unknown},
  /* 0xa8 */  {dissect_unknown, dissect_unknown},
  /* 0xa9 */  {dissect_unknown, dissect_unknown},
  /* 0xaa */  {dissect_unknown, dissect_unknown},
  /* 0xab */  {dissect_unknown, dissect_unknown},
  /* 0xac */  {dissect_unknown, dissect_unknown},
  /* 0xad */  {dissect_unknown, dissect_unknown},
  /* 0xae */  {dissect_unknown, dissect_unknown},
  /* 0xaf */  {dissect_unknown, dissect_unknown},

  /* 0xb0 */  {dissect_unknown, dissect_unknown},
  /* 0xb1 */  {dissect_unknown, dissect_unknown},
  /* 0xb2 */  {dissect_unknown, dissect_unknown},
  /* 0xb3 */  {dissect_unknown, dissect_unknown},
  /* 0xb4 */  {dissect_unknown, dissect_unknown},
  /* 0xb5 */  {dissect_unknown, dissect_unknown},
  /* 0xb6 */  {dissect_unknown, dissect_unknown},
  /* 0xb7 */  {dissect_unknown, dissect_unknown},
  /* 0xb8 */  {dissect_unknown, dissect_unknown},
  /* 0xb9 */  {dissect_unknown, dissect_unknown},
  /* 0xba */  {dissect_unknown, dissect_unknown},
  /* 0xbb */  {dissect_unknown, dissect_unknown},
  /* 0xbc */  {dissect_unknown, dissect_unknown},
  /* 0xbd */  {dissect_unknown, dissect_unknown},
  /* 0xbe */  {dissect_unknown, dissect_unknown},
  /* 0xbf */  {dissect_unknown, dissect_unknown},
  /* 0xc0 Open Print File*/	{dissect_open_print_file_request, dissect_fid},
  /* 0xc1 Write Print File*/	{dissect_write_print_file_request, dissect_empty},
  /* 0xc2 Close Print File*/  {dissect_fid, dissect_empty},
  /* 0xc3 Get Print Queue*/	{dissect_get_print_queue_request, dissect_get_print_queue_response},
  /* 0xc4 */  {dissect_unknown, dissect_unknown},
  /* 0xc5 */  {dissect_unknown, dissect_unknown},
  /* 0xc6 */  {dissect_unknown, dissect_unknown},
  /* 0xc7 */  {dissect_unknown, dissect_unknown},
  /* 0xc8 */  {dissect_unknown, dissect_unknown},
  /* 0xc9 */  {dissect_unknown, dissect_unknown},
  /* 0xca */  {dissect_unknown, dissect_unknown},
  /* 0xcb */  {dissect_unknown, dissect_unknown},
  /* 0xcc */  {dissect_unknown, dissect_unknown},
  /* 0xcd */  {dissect_unknown, dissect_unknown},
  /* 0xce */  {dissect_unknown, dissect_unknown},
  /* 0xcf */  {dissect_unknown, dissect_unknown},

  /* 0xd0 */  {dissect_unknown, dissect_unknown},
  /* 0xd1 */  {dissect_unknown, dissect_unknown},
  /* 0xd2 */  {dissect_unknown, dissect_unknown},
  /* 0xd3 */  {dissect_unknown, dissect_unknown},
  /* 0xd4 */  {dissect_unknown, dissect_unknown},
  /* 0xd5 */  {dissect_unknown, dissect_unknown},
  /* 0xd6 */  {dissect_unknown, dissect_unknown},
  /* 0xd7 */  {dissect_unknown, dissect_unknown},
  /* 0xd8 */  {dissect_unknown, dissect_unknown},
  /* 0xd9 */  {dissect_unknown, dissect_unknown},
  /* 0xda */  {dissect_unknown, dissect_unknown},
  /* 0xdb */  {dissect_unknown, dissect_unknown},
  /* 0xdc */  {dissect_unknown, dissect_unknown},
  /* 0xdd */  {dissect_unknown, dissect_unknown},
  /* 0xde */  {dissect_unknown, dissect_unknown},
  /* 0xdf */  {dissect_unknown, dissect_unknown},

  /* 0xe0 */  {dissect_unknown, dissect_unknown},
  /* 0xe1 */  {dissect_unknown, dissect_unknown},
  /* 0xe2 */  {dissect_unknown, dissect_unknown},
  /* 0xe3 */  {dissect_unknown, dissect_unknown},
  /* 0xe4 */  {dissect_unknown, dissect_unknown},
  /* 0xe5 */  {dissect_unknown, dissect_unknown},
  /* 0xe6 */  {dissect_unknown, dissect_unknown},
  /* 0xe7 */  {dissect_unknown, dissect_unknown},
  /* 0xe8 */  {dissect_unknown, dissect_unknown},
  /* 0xe9 */  {dissect_unknown, dissect_unknown},
  /* 0xea */  {dissect_unknown, dissect_unknown},
  /* 0xeb */  {dissect_unknown, dissect_unknown},
  /* 0xec */  {dissect_unknown, dissect_unknown},
  /* 0xed */  {dissect_unknown, dissect_unknown},
  /* 0xee */  {dissect_unknown, dissect_unknown},
  /* 0xef */  {dissect_unknown, dissect_unknown},

  /* 0xf0 */  {dissect_unknown, dissect_unknown},
  /* 0xf1 */  {dissect_unknown, dissect_unknown},
  /* 0xf2 */  {dissect_unknown, dissect_unknown},
  /* 0xf3 */  {dissect_unknown, dissect_unknown},
  /* 0xf4 */  {dissect_unknown, dissect_unknown},
  /* 0xf5 */  {dissect_unknown, dissect_unknown},
  /* 0xf6 */  {dissect_unknown, dissect_unknown},
  /* 0xf7 */  {dissect_unknown, dissect_unknown},
  /* 0xf8 */  {dissect_unknown, dissect_unknown},
  /* 0xf9 */  {dissect_unknown, dissect_unknown},
  /* 0xfa */  {dissect_unknown, dissect_unknown},
  /* 0xfb */  {dissect_unknown, dissect_unknown},
  /* 0xfc */  {dissect_unknown, dissect_unknown},
  /* 0xfd */  {dissect_unknown, dissect_unknown},
  /* 0xfe */  {dissect_unknown, dissect_unknown},
  /* 0xff */  {dissect_unknown, dissect_unknown},
};

static int
dissect_smb_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *top_tree, int offset, proto_tree *smb_tree, guint8 cmd)
{
	int old_offset = offset;
	smb_info_t *si;
 
	si = pinfo->private_data;
	if(cmd!=0xff){
		proto_item *cmd_item;
		proto_tree *cmd_tree;
		int (*dissector)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree);

		if (check_col(pinfo->fd, COL_INFO)) {
			col_add_fstr(pinfo->fd, COL_INFO, "%s %s",
				decode_smb_name(cmd),
				(si->request)? "Request" : "Response");
		}

		cmd_item = proto_tree_add_text(smb_tree, tvb, offset,
			0, "%s %s (0x%02x)",
			decode_smb_name(cmd), 
			(si->request)?"Request":"Response",
			cmd);

		cmd_tree = proto_item_add_subtree(cmd_item, ett_smb_command);

		dissector = (si->request)?
			smb_dissector[cmd].request:smb_dissector[cmd].response;

		offset = (*dissector)(tvb, pinfo, cmd_tree, offset, smb_tree);
		proto_item_set_len(cmd_item, offset-old_offset);
	}
	return offset;
}


/* NOTE: this value_string array will also be used to access data directly by
 * index instead of val_to_str() since 
 * 1, the array will always span every value from 0x00 to 0xff and
 * 2, smb_cmd_vals[i].strptr  is much cheaper than  val_to_str(i, smb_cmd_vals,)
 * This means that this value_string array MUST always
 * 1, contain all entries 0x00 to 0xff
 * 2, all entries must be in order.
 */
static const value_string smb_cmd_vals[] = {
  { 0x00, "Create Directory" },
  { 0x01, "Delete Directory" },
  { 0x02, "Open" },
  { 0x03, "Create" },
  { 0x04, "Close" },
  { 0x05, "Flush" },
  { 0x06, "Delete" },
  { 0x07, "Rename" },
  { 0x08, "Query Information" },
  { 0x09, "Set Information" },
  { 0x0A, "Read" },
  { 0x0B, "Write" },
  { 0x0C, "Lock Byte Range" },
  { 0x0D, "Unlock Byte Range" },
  { 0x0E, "Create Temp" },
  { 0x0F, "Create New" },
  { 0x10, "Check Directory" },
  { 0x11, "Process Exit" },
  { 0x12, "Seek" },
  { 0x13, "Lock And Read" },
  { 0x14, "Write And Unlock" },
  { 0x15, "unknown-0x15" },
  { 0x16, "unknown-0x16" },
  { 0x17, "unknown-0x17" },
  { 0x18, "unknown-0x18" },
  { 0x19, "unknown-0x19" },
  { 0x1A, "Read Raw" },
  { 0x1B, "Read MPX" },
  { 0x1C, "Read MPX Secondary" },
  { 0x1D, "Write Raw" },
  { 0x1E, "Write MPX" },
  { 0x1F, "SMBwriteBs" },
  { 0x20, "Write Complete" },
  { 0x21, "unknown-0x21" },
  { 0x22, "Set Information2" },
  { 0x23, "Query Information2" },
  { 0x24, "Locking AndX" },
  { 0x25, "Transaction" },
  { 0x26, "Transaction Secondary" },
  { 0x27, "IOCTL" },
  { 0x28, "IOCTL Secondary" },
  { 0x29, "Copy" },
  { 0x2A, "Move" },
  { 0x2B, "Echo" },
  { 0x2C, "Write And Close" },
  { 0x2D, "Open AndX" },
  { 0x2E, "Read AndX" },
  { 0x2F, "Write AndX" },
  { 0x30, "unknown-0x30" },
  { 0x31, "Close And Tree Discover" },
  { 0x32, "Transaction2" },
  { 0x33, "Transaction2 Secondary" },
  { 0x34, "Find Close2" },
  { 0x35, "Find Notify Close" },
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
  { 0x70, "Tree Connect" },
  { 0x71, "Tree Disconnect" },
  { 0x72, "Negotiate Protocol" },
  { 0x73, "Session Setup AndX" },
  { 0x74, "Logoff AndX" },
  { 0x75, "Tree Connect AndX" },
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
  { 0x80, "Query Information Disk" },
  { 0x81, "Search" },
  { 0x82, "Find" },
  { 0x83, "Find Unique" },
  { 0x84, "SMBfclose" },
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
  { 0xA0, "NT Transact" },
  { 0xA1, "NT Transact Secondary" },
  { 0xA2, "NT Create AndX" },
  { 0xA3, "unknown-0xA3" },
  { 0xA4, "NT Cancel" },
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
  { 0xC0, "Open Print File" },
  { 0xC1, "Write Print File" },
  { 0xC2, "Close Print File" },
  { 0xC3, "Get Print Queue" },
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
  { 0xD0, "SMBsends" },
  { 0xD1, "SMBsendb" },
  { 0xD2, "SMBfwdname" },
  { 0xD3, "SMBcancelf" },
  { 0xD4, "SMBgetmac" },
  { 0xD5, "SMBsendstrt" },
  { 0xD6, "SMBsendend" },
  { 0xD7, "SMBsendtxt" },
  { 0xD8, "SMBreadbulk" },
  { 0xD9, "SMBwritebulk" },
  { 0xDA, "SMBwritebulkdata" },
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
  { 0xFE, "SMBinvalid" },
  { 0xFF, "unknown-0xFF" },
  { 0x00, NULL },
};

static char *decode_smb_name(unsigned char cmd)
{
  return(smb_cmd_vals[cmd].strptr);
}
 


/* XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
 * Everything TVBUFFIFIED above this line
 * XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX */


/*
 * Struct passed to each SMB decode routine of info it may need
 */

static void
smb_init_protocol(void)
{
	if (smb_saved_info_chunk)
		g_mem_chunk_destroy(smb_saved_info_chunk);
	if (smb_nt_transact_info_chunk)
		g_mem_chunk_destroy(smb_nt_transact_info_chunk);
	if (smb_transact2_info_chunk)
		g_mem_chunk_destroy(smb_transact2_info_chunk);
	if (smb_transact_info_chunk)
		g_mem_chunk_destroy(smb_transact_info_chunk);
	if (conv_tables_chunk)
		g_mem_chunk_destroy(conv_tables_chunk);

	smb_saved_info_chunk = g_mem_chunk_new("smb_saved_info_chunk",
	    sizeof(smb_saved_info_t),
	    smb_saved_info_init_count * sizeof(smb_saved_info_t),
	    G_ALLOC_ONLY);
	smb_nt_transact_info_chunk = g_mem_chunk_new("smb_nt_transact_info_chunk",
	    sizeof(smb_nt_transact_info_t),
	    smb_nt_transact_info_init_count * sizeof(smb_nt_transact_info_t),
	    G_ALLOC_ONLY);
	smb_transact2_info_chunk = g_mem_chunk_new("smb_transact2_info_chunk",
	    sizeof(smb_transact2_info_t),
	    smb_transact2_info_init_count * sizeof(smb_transact2_info_t),
	    G_ALLOC_ONLY);
	smb_transact_info_chunk = g_mem_chunk_new("smb_transact_info_chunk",
	    sizeof(smb_transact_info_t),
	    smb_transact_info_init_count * sizeof(smb_transact_info_t),
	    G_ALLOC_ONLY);
	conv_tables_chunk = g_mem_chunk_new("conv_tables_chunk",
	    sizeof(conv_tables_t),
	    conv_tables_count * sizeof(conv_tables_t),
	    G_ALLOC_ONLY);
}

/* Max string length for displaying Unicode strings.  */
#define	MAX_UNICODE_STR_LEN	256


/* Turn a little-endian Unicode '\0'-terminated string into a string we
   can display.
   XXX - for now, we just handle the ISO 8859-1 characters.
   If exactlen==TRUE then us_lenp contains the exact len of the string in
   bytes. It might not be null terminated !
   bc specifies the number of bytes in the byte parameters; Windows 2000,
   at least, appears, in some cases, to put only 1 byte of 0 at the end
   of a Unicode string if the byte count
*/
static gchar *
unicode_to_str(tvbuff_t *tvb, int offset, int *us_lenp, gboolean exactlen,
		   guint16 bc)
{
  static gchar  str[3][MAX_UNICODE_STR_LEN+3+1];
  static gchar *cur;
  gchar        *p;
  guint16       uchar;
  int           len;
  int           us_len;
  int           overflow = 0;

  if (cur == &str[0][0]) {
    cur = &str[1][0];
  } else if (cur == &str[1][0]) {  
    cur = &str[2][0];
  } else {  
    cur = &str[0][0];
  }
  p = cur;
  len = MAX_UNICODE_STR_LEN;
  us_len = 0;
  for (;;) {
    if (bc == 0)
      break;
    if (bc == 1) {
      /* XXX - explain this */
      if (!exactlen)
        us_len += 1;	/* this is a one-byte null terminator */
      break;
    }
    uchar = tvb_get_letohs(tvb, offset);
    if (uchar == 0) {
      us_len += 2;	/* this is a two-byte null terminator */
      break;
    }
    if (len > 0) {
      if ((uchar & 0xFF00) == 0)
        *p++ = uchar;	/* ISO 8859-1 */
      else
        *p++ = '?';	/* not 8859-1 */
      len--;
    } else
      overflow = 1;
    offset += 2;
    bc -= 2;
    us_len += 2;
    if(exactlen){
      if(us_len>= *us_lenp){
        break;
      }
    }
  }
  if (overflow) {
    /* Note that we're not showing the full string.  */
    *p++ = '.';
    *p++ = '.';
    *p++ = '.';
  }
  *p = '\0';
  *us_lenp = us_len;
  return cur;
}
 

/* nopad == TRUE : Do not add any padding before this string
 * exactlen == TRUE : len contains the exact len of the string in bytes.
 * bc: pointer to variable with amount of data left in the byte parameters
 *   region
 */
static const gchar *
get_unicode_or_ascii_string(tvbuff_t *tvb, int *offsetp,
    packet_info *pinfo, int *len, gboolean nopad, gboolean exactlen,
    guint16 *bcp)
{
  static gchar  str[3][MAX_UNICODE_STR_LEN+3+1];
  static gchar *cur;
  const gchar *string;
  int string_len;
  smb_info_t *si;
  int copylen;

  if (*bcp == 0) {
    /* Not enough data in buffer */
    return NULL;
  }
  si = pinfo->private_data;
  if (si->unicode) {
    if ((!nopad) && (*offsetp % 2)) {
      /*
       * XXX - this should be an offset relative to the beginning of the SMB,
       * not an offset relative to the beginning of the frame; if the stuff
       * before the SMB has an odd number of bytes, an offset relative to
       * the beginning of the frame will give the wrong answer.
       */
      (*offsetp)++;   /* Looks like a pad byte there sometimes */
      (*bcp)--;
      if (*bcp == 0) {
        /* Not enough data in buffer */
        return NULL;
      }
    }
    if(exactlen){
      string_len = *len;
      string = unicode_to_str(tvb, *offsetp, &string_len, exactlen, *bcp);
    } else {
      string = unicode_to_str(tvb, *offsetp, &string_len, exactlen, *bcp);
    }
  } else {
    if(exactlen){
      /*
       * The string we return must be null-terminated.
       */
      if (cur == &str[0][0]) {
        cur = &str[1][0];
      } else if (cur == &str[1][0]) {  
        cur = &str[2][0];
      } else {  
        cur = &str[0][0];
      }
      copylen = *len;
      if (copylen > MAX_UNICODE_STR_LEN)
        copylen = MAX_UNICODE_STR_LEN;
      tvb_memcpy(tvb, (guint8 *)cur, *offsetp, copylen);
      cur[copylen] = '\0';
      if (copylen > MAX_UNICODE_STR_LEN)
        strcat(cur, "...");
      string_len = *len;
      string = cur;
    } else {
      string_len = tvb_strsize(tvb, *offsetp);
      string = tvb_get_ptr(tvb, *offsetp, string_len);
    }
  }
  *len = string_len;
  return string;
}



static const value_string errcls_types[] = {
  { SMB_SUCCESS, "Success"},
  { SMB_ERRDOS, "DOS Error"},
  { SMB_ERRSRV, "Server Error"},
  { SMB_ERRHRD, "Hardware Error"},
  { SMB_ERRCMD, "Command Error - Not an SMB format command"},
  { 0, NULL }
};

static const value_string DOS_errors[] = {
  {SMBE_badfunc, "Invalid function (or system call)"},
  {SMBE_badfile, "File not found (pathname error)"},
  {SMBE_badpath, "Directory not found"},
  {SMBE_nofids, "Too many open files"},
  {SMBE_noaccess, "Access denied"},
  {SMBE_badfid, "Invalid fid"},
  {SMBE_nomem,  "Out of memory"},
  {SMBE_badmem, "Invalid memory block address"},
  {SMBE_badenv, "Invalid environment"},
  {SMBE_badaccess, "Invalid open mode"},
  {SMBE_baddata, "Invalid data (only from ioctl call)"},
  {SMBE_res, "Reserved error code?"}, 
  {SMBE_baddrive, "Invalid drive"},
  {SMBE_remcd, "Attempt to delete current directory"},
  {SMBE_diffdevice, "Rename/move across different filesystems"},
  {SMBE_nofiles, "No more files found in file search"},
  {SMBE_badshare, "Share mode on file conflict with open mode"},
  {SMBE_lock, "Lock request conflicts with existing lock"},
  {SMBE_unsup, "Request unsupported, returned by Win 95"},
  {SMBE_nosuchshare, "Requested share does not exist"},
  {SMBE_filexists, "File in operation already exists"},
  {SMBE_cannotopen, "Cannot open the file specified"},
  {SMBE_unknownlevel, "Unknown level??"},
  {SMBE_badpipe, "Named pipe invalid"},
  {SMBE_pipebusy, "All instances of pipe are busy"},
  {SMBE_pipeclosing, "Named pipe close in progress"},
  {SMBE_notconnected, "No process on other end of named pipe"},
  {SMBE_moredata, "More data to be returned"},
  {SMBE_baddirectory,  "Invalid directory name in a path."},
  {SMBE_eas_didnt_fit, "Extended attributes didn't fit"},
  {SMBE_eas_nsup, "Extended attributes not supported"},
  {SMBE_notify_buf_small, "Buffer too small to return change notify."},
  {SMBE_unknownipc, "Unknown IPC Operation"},
  {SMBE_noipc, "Don't support ipc"},
  {0, NULL}
  };

/* Error codes for the ERRSRV class */

static const value_string SRV_errors[] = {
  {SMBE_error, "Non specific error code"},
  {SMBE_badpw, "Bad password"},
  {SMBE_badtype, "Reserved"},
  {SMBE_access, "No permissions to perform the requested operation"},
  {SMBE_invnid, "TID invalid"},
  {SMBE_invnetname, "Invalid network name. Service not found"},
  {SMBE_invdevice, "Invalid device"},
  {SMBE_unknownsmb, "Unknown SMB, from NT 3.5 response"},
  {SMBE_qfull, "Print queue full"},
  {SMBE_qtoobig, "Queued item too big"},
  {SMBE_qeof, "EOF on print queue dump"},
  {SMBE_invpfid, "Invalid print file in smb_fid"},
  {SMBE_smbcmd, "Unrecognised command"},
  {SMBE_srverror, "SMB server internal error"},
  {SMBE_filespecs, "Fid and pathname invalid combination"},
  {SMBE_badlink, "Bad link in request ???"},
  {SMBE_badpermits, "Access specified for a file is not valid"},
  {SMBE_badpid, "Bad process id in request"},
  {SMBE_setattrmode, "Attribute mode invalid"},
  {SMBE_paused, "Message server paused"},
  {SMBE_msgoff, "Not receiving messages"},
  {SMBE_noroom, "No room for message"},
  {SMBE_rmuns, "Too many remote usernames"},
  {SMBE_timeout, "Operation timed out"},
  {SMBE_noresource, "No resources currently available for request."},
  {SMBE_toomanyuids, "Too many userids"},
  {SMBE_baduid, "Bad userid"},
  {SMBE_useMPX, "Temporarily unable to use raw mode, use MPX mode"},
  {SMBE_useSTD, "Temporarily unable to use raw mode, use standard mode"},
  {SMBE_contMPX, "Resume MPX mode"},
  {SMBE_badPW, "Bad Password???"},
  {SMBE_nosupport, "Operation not supported"},
  { 0, NULL}
};

/* Error codes for the ERRHRD class */

static const value_string HRD_errors[] = {
  {SMBE_nowrite, "Read only media"},
  {SMBE_badunit, "Unknown device"},
  {SMBE_notready, "Drive not ready"},
  {SMBE_badcmd, "Unknown command"},
  {SMBE_data, "Data (CRC) error"},
  {SMBE_badreq, "Bad request structure length"},
  {SMBE_seek, "Seek error???"},
  {SMBE_badmedia, "Bad media???"},
  {SMBE_badsector, "Bad sector???"},
  {SMBE_nopaper, "No paper in printer???"},
  {SMBE_write, "Write error???"},
  {SMBE_read, "Read error???"},
  {SMBE_general, "General error???"},
  {SMBE_badshare, "A open conflicts with an existing open"},
  {SMBE_lock, "Lock/unlock error"},
  {SMBE_wrongdisk,  "Wrong disk???"},
  {SMBE_FCBunavail, "FCB unavailable???"},
  {SMBE_sharebufexc, "Share buffer excluded???"},
  {SMBE_diskfull, "Disk full???"},
  {0, NULL}
};

static char *decode_smb_error(guint8 errcls, guint16 errcode)
{

  switch (errcls) {

  case SMB_SUCCESS:

    return("No Error");   /* No error ??? */
    break;

  case SMB_ERRDOS:

    return(val_to_str(errcode, DOS_errors, "Unknown DOS error (%x)"));
    break;

  case SMB_ERRSRV:

    return(val_to_str(errcode, SRV_errors, "Unknown SRV error (%x)"));
    break;

  case SMB_ERRHRD:

    return(val_to_str(errcode, HRD_errors, "Unknown HRD error (%x)"));
    break;

  default:

    return("Unknown error class!");

  }

}

/*
 * NT error codes.
 *
 * From
 *
 *	http://www.wildpackets.com/elements/SMB_NT_Status_Codes.txt
 */
static const value_string NT_errors[] = {
  { 0x00000000, "STATUS_SUCCESS" },
  { 0x00000000, "STATUS_WAIT_0" },
  { 0x00000001, "STATUS_WAIT_1" },
  { 0x00000002, "STATUS_WAIT_2" },
  { 0x00000003, "STATUS_WAIT_3" },
  { 0x0000003F, "STATUS_WAIT_63" },
  { 0x00000080, "STATUS_ABANDONED" },
  { 0x00000080, "STATUS_ABANDONED_WAIT_0" },
  { 0x000000BF, "STATUS_ABANDONED_WAIT_63" },
  { 0x000000C0, "STATUS_USER_APC" },
  { 0x00000100, "STATUS_KERNEL_APC" },
  { 0x00000101, "STATUS_ALERTED" },
  { 0x00000102, "STATUS_TIMEOUT" },
  { 0x00000103, "STATUS_PENDING" },
  { 0x00000104, "STATUS_REPARSE" },
  { 0x00000105, "STATUS_MORE_ENTRIES" },
  { 0x00000106, "STATUS_NOT_ALL_ASSIGNED" },
  { 0x00000107, "STATUS_SOME_NOT_MAPPED" },
  { 0x00000108, "STATUS_OPLOCK_BREAK_IN_PROGRESS" },
  { 0x00000109, "STATUS_VOLUME_MOUNTED" },
  { 0x0000010A, "STATUS_RXACT_COMMITTED" },
  { 0x0000010B, "STATUS_NOTIFY_CLEANUP" },
  { 0x0000010C, "STATUS_NOTIFY_ENUM_DIR" },
  { 0x0000010D, "STATUS_NO_QUOTAS_FOR_ACCOUNT" },
  { 0x0000010E, "STATUS_PRIMARY_TRANSPORT_CONNECT_FAILED" },
  { 0x00000110, "STATUS_PAGE_FAULT_TRANSITION" },
  { 0x00000111, "STATUS_PAGE_FAULT_DEMAND_ZERO" },
  { 0x00000112, "STATUS_PAGE_FAULT_COPY_ON_WRITE" },
  { 0x00000113, "STATUS_PAGE_FAULT_GUARD_PAGE" },
  { 0x00000114, "STATUS_PAGE_FAULT_PAGING_FILE" },
  { 0x00000115, "STATUS_CACHE_PAGE_LOCKED" },
  { 0x00000116, "STATUS_CRASH_DUMP" },
  { 0x00000117, "STATUS_BUFFER_ALL_ZEROS" },
  { 0x00000118, "STATUS_REPARSE_OBJECT" },
  { 0x40000000, "STATUS_OBJECT_NAME_EXISTS" },
  { 0x40000001, "STATUS_THREAD_WAS_SUSPENDED" },
  { 0x40000002, "STATUS_WORKING_SET_LIMIT_RANGE" },
  { 0x40000003, "STATUS_IMAGE_NOT_AT_BASE" },
  { 0x40000004, "STATUS_RXACT_STATE_CREATED" },
  { 0x40000005, "STATUS_SEGMENT_NOTIFICATION" },
  { 0x40000006, "STATUS_LOCAL_USER_SESSION_KEY" },
  { 0x40000007, "STATUS_BAD_CURRENT_DIRECTORY" },
  { 0x40000008, "STATUS_SERIAL_MORE_WRITES" },
  { 0x40000009, "STATUS_REGISTRY_RECOVERED" },
  { 0x4000000A, "STATUS_FT_READ_RECOVERY_FROM_BACKUP" },
  { 0x4000000B, "STATUS_FT_WRITE_RECOVERY" },
  { 0x4000000C, "STATUS_SERIAL_COUNTER_TIMEOUT" },
  { 0x4000000D, "STATUS_NULL_LM_PASSWORD" },
  { 0x4000000E, "STATUS_IMAGE_MACHINE_TYPE_MISMATCH" },
  { 0x4000000F, "STATUS_RECEIVE_PARTIAL" },
  { 0x40000010, "STATUS_RECEIVE_EXPEDITED" },
  { 0x40000011, "STATUS_RECEIVE_PARTIAL_EXPEDITED" },
  { 0x40000012, "STATUS_EVENT_DONE" },
  { 0x40000013, "STATUS_EVENT_PENDING" },
  { 0x40000014, "STATUS_CHECKING_FILE_SYSTEM" },
  { 0x40000015, "STATUS_FATAL_APP_EXIT" },
  { 0x40000016, "STATUS_PREDEFINED_HANDLE" },
  { 0x40000017, "STATUS_WAS_UNLOCKED" },
  { 0x40000018, "STATUS_SERVICE_NOTIFICATION" },
  { 0x40000019, "STATUS_WAS_LOCKED" },
  { 0x4000001A, "STATUS_LOG_HARD_ERROR" },
  { 0x4000001B, "STATUS_ALREADY_WIN32" },
  { 0x4000001C, "STATUS_WX86_UNSIMULATE" },
  { 0x4000001D, "STATUS_WX86_CONTINUE" },
  { 0x4000001E, "STATUS_WX86_SINGLE_STEP" },
  { 0x4000001F, "STATUS_WX86_BREAKPOINT" },
  { 0x40000020, "STATUS_WX86_EXCEPTION_CONTINUE" },
  { 0x40000021, "STATUS_WX86_EXCEPTION_LASTCHANCE" },
  { 0x40000022, "STATUS_WX86_EXCEPTION_CHAIN" },
  { 0x40000023, "STATUS_IMAGE_MACHINE_TYPE_MISMATCH_EXE" },
  { 0x40000024, "STATUS_NO_YIELD_PERFORMED" },
  { 0x40000025, "STATUS_TIMER_RESUME_IGNORED" },
  { 0x80000001, "STATUS_GUARD_PAGE_VIOLATION" },
  { 0x80000002, "STATUS_DATATYPE_MISALIGNMENT" },
  { 0x80000003, "STATUS_BREAKPOINT" },
  { 0x80000004, "STATUS_SINGLE_STEP" },
  { 0x80000005, "STATUS_BUFFER_OVERFLOW" },
  { 0x80000006, "STATUS_NO_MORE_FILES" },
  { 0x80000007, "STATUS_WAKE_SYSTEM_DEBUGGER" },
  { 0x8000000A, "STATUS_HANDLES_CLOSED" },
  { 0x8000000B, "STATUS_NO_INHERITANCE" },
  { 0x8000000C, "STATUS_GUID_SUBSTITUTION_MADE" },
  { 0x8000000D, "STATUS_PARTIAL_COPY" },
  { 0x8000000E, "STATUS_DEVICE_PAPER_EMPTY" },
  { 0x8000000F, "STATUS_DEVICE_POWERED_OFF" },
  { 0x80000010, "STATUS_DEVICE_OFF_LINE" },
  { 0x80000011, "STATUS_DEVICE_BUSY" },
  { 0x80000012, "STATUS_NO_MORE_EAS" },
  { 0x80000013, "STATUS_INVALID_EA_NAME" },
  { 0x80000014, "STATUS_EA_LIST_INCONSISTENT" },
  { 0x80000015, "STATUS_INVALID_EA_FLAG" },
  { 0x80000016, "STATUS_VERIFY_REQUIRED" },
  { 0x80000017, "STATUS_EXTRANEOUS_INFORMATION" },
  { 0x80000018, "STATUS_RXACT_COMMIT_NECESSARY" },
  { 0x8000001A, "STATUS_NO_MORE_ENTRIES" },
  { 0x8000001B, "STATUS_FILEMARK_DETECTED" },
  { 0x8000001C, "STATUS_MEDIA_CHANGED" },
  { 0x8000001D, "STATUS_BUS_RESET" },
  { 0x8000001E, "STATUS_END_OF_MEDIA" },
  { 0x8000001F, "STATUS_BEGINNING_OF_MEDIA" },
  { 0x80000020, "STATUS_MEDIA_CHECK" },
  { 0x80000021, "STATUS_SETMARK_DETECTED" },
  { 0x80000022, "STATUS_NO_DATA_DETECTED" },
  { 0x80000023, "STATUS_REDIRECTOR_HAS_OPEN_HANDLES" },
  { 0x80000024, "STATUS_SERVER_HAS_OPEN_HANDLES" },
  { 0x80000025, "STATUS_ALREADY_DISCONNECTED" },
  { 0x80000026, "STATUS_LONGJUMP" },
  { 0xC0000001, "STATUS_UNSUCCESSFUL" },
  { 0xC0000002, "STATUS_NOT_IMPLEMENTED" },
  { 0xC0000003, "STATUS_INVALID_INFO_CLASS" },
  { 0xC0000004, "STATUS_INFO_LENGTH_MISMATCH" },
  { 0xC0000005, "STATUS_ACCESS_VIOLATION" },
  { 0xC0000006, "STATUS_IN_PAGE_ERROR" },
  { 0xC0000007, "STATUS_PAGEFILE_QUOTA" },
  { 0xC0000008, "STATUS_INVALID_HANDLE" },
  { 0xC0000009, "STATUS_BAD_INITIAL_STACK" },
  { 0xC000000A, "STATUS_BAD_INITIAL_PC" },
  { 0xC000000B, "STATUS_INVALID_CID" },
  { 0xC000000C, "STATUS_TIMER_NOT_CANCELED" },
  { 0xC000000D, "STATUS_INVALID_PARAMETER" },
  { 0xC000000E, "STATUS_NO_SUCH_DEVICE" },
  { 0xC000000F, "STATUS_NO_SUCH_FILE" },
  { 0xC0000010, "STATUS_INVALID_DEVICE_REQUEST" },
  { 0xC0000011, "STATUS_END_OF_FILE" },
  { 0xC0000012, "STATUS_WRONG_VOLUME" },
  { 0xC0000013, "STATUS_NO_MEDIA_IN_DEVICE" },
  { 0xC0000014, "STATUS_UNRECOGNIZED_MEDIA" },
  { 0xC0000015, "STATUS_NONEXISTENT_SECTOR" },
  { 0xC0000016, "STATUS_MORE_PROCESSING_REQUIRED" },
  { 0xC0000017, "STATUS_NO_MEMORY" },
  { 0xC0000018, "STATUS_CONFLICTING_ADDRESSES" },
  { 0xC0000019, "STATUS_NOT_MAPPED_VIEW" },
  { 0xC000001A, "STATUS_UNABLE_TO_FREE_VM" },
  { 0xC000001B, "STATUS_UNABLE_TO_DELETE_SECTION" },
  { 0xC000001C, "STATUS_INVALID_SYSTEM_SERVICE" },
  { 0xC000001D, "STATUS_ILLEGAL_INSTRUCTION" },
  { 0xC000001E, "STATUS_INVALID_LOCK_SEQUENCE" },
  { 0xC000001F, "STATUS_INVALID_VIEW_SIZE" },
  { 0xC0000020, "STATUS_INVALID_FILE_FOR_SECTION" },
  { 0xC0000021, "STATUS_ALREADY_COMMITTED" },
  { 0xC0000022, "STATUS_ACCESS_DENIED" },
  { 0xC0000023, "STATUS_BUFFER_TOO_SMALL" },
  { 0xC0000024, "STATUS_OBJECT_TYPE_MISMATCH" },
  { 0xC0000025, "STATUS_NONCONTINUABLE_EXCEPTION" },
  { 0xC0000026, "STATUS_INVALID_DISPOSITION" },
  { 0xC0000027, "STATUS_UNWIND" },
  { 0xC0000028, "STATUS_BAD_STACK" },
  { 0xC0000029, "STATUS_INVALID_UNWIND_TARGET" },
  { 0xC000002A, "STATUS_NOT_LOCKED" },
  { 0xC000002B, "STATUS_PARITY_ERROR" },
  { 0xC000002C, "STATUS_UNABLE_TO_DECOMMIT_VM" },
  { 0xC000002D, "STATUS_NOT_COMMITTED" },
  { 0xC000002E, "STATUS_INVALID_PORT_ATTRIBUTES" },
  { 0xC000002F, "STATUS_PORT_MESSAGE_TOO_LONG" },
  { 0xC0000030, "STATUS_INVALID_PARAMETER_MIX" },
  { 0xC0000031, "STATUS_INVALID_QUOTA_LOWER" },
  { 0xC0000032, "STATUS_DISK_CORRUPT_ERROR" },
  { 0xC0000033, "STATUS_OBJECT_NAME_INVALID" },
  { 0xC0000034, "STATUS_OBJECT_NAME_NOT_FOUND" },
  { 0xC0000035, "STATUS_OBJECT_NAME_COLLISION" },
  { 0xC0000037, "STATUS_PORT_DISCONNECTED" },
  { 0xC0000038, "STATUS_DEVICE_ALREADY_ATTACHED" },
  { 0xC0000039, "STATUS_OBJECT_PATH_INVALID" },
  { 0xC000003A, "STATUS_OBJECT_PATH_NOT_FOUND" },
  { 0xC000003B, "STATUS_OBJECT_PATH_SYNTAX_BAD" },
  { 0xC000003C, "STATUS_DATA_OVERRUN" },
  { 0xC000003D, "STATUS_DATA_LATE_ERROR" },
  { 0xC000003E, "STATUS_DATA_ERROR" },
  { 0xC000003F, "STATUS_CRC_ERROR" },
  { 0xC0000040, "STATUS_SECTION_TOO_BIG" },
  { 0xC0000041, "STATUS_PORT_CONNECTION_REFUSED" },
  { 0xC0000042, "STATUS_INVALID_PORT_HANDLE" },
  { 0xC0000043, "STATUS_SHARING_VIOLATION" },
  { 0xC0000044, "STATUS_QUOTA_EXCEEDED" },
  { 0xC0000045, "STATUS_INVALID_PAGE_PROTECTION" },
  { 0xC0000046, "STATUS_MUTANT_NOT_OWNED" },
  { 0xC0000047, "STATUS_SEMAPHORE_LIMIT_EXCEEDED" },
  { 0xC0000048, "STATUS_PORT_ALREADY_SET" },
  { 0xC0000049, "STATUS_SECTION_NOT_IMAGE" },
  { 0xC000004A, "STATUS_SUSPEND_COUNT_EXCEEDED" },
  { 0xC000004B, "STATUS_THREAD_IS_TERMINATING" },
  { 0xC000004C, "STATUS_BAD_WORKING_SET_LIMIT" },
  { 0xC000004D, "STATUS_INCOMPATIBLE_FILE_MAP" },
  { 0xC000004E, "STATUS_SECTION_PROTECTION" },
  { 0xC000004F, "STATUS_EAS_NOT_SUPPORTED" },
  { 0xC0000050, "STATUS_EA_TOO_LARGE" },
  { 0xC0000051, "STATUS_NONEXISTENT_EA_ENTRY" },
  { 0xC0000052, "STATUS_NO_EAS_ON_FILE" },
  { 0xC0000053, "STATUS_EA_CORRUPT_ERROR" },
  { 0xC0000054, "STATUS_FILE_LOCK_CONFLICT" },
  { 0xC0000055, "STATUS_LOCK_NOT_GRANTED" },
  { 0xC0000056, "STATUS_DELETE_PENDING" },
  { 0xC0000057, "STATUS_CTL_FILE_NOT_SUPPORTED" },
  { 0xC0000058, "STATUS_UNKNOWN_REVISION" },
  { 0xC0000059, "STATUS_REVISION_MISMATCH" },
  { 0xC000005A, "STATUS_INVALID_OWNER" },
  { 0xC000005B, "STATUS_INVALID_PRIMARY_GROUP" },
  { 0xC000005C, "STATUS_NO_IMPERSONATION_TOKEN" },
  { 0xC000005D, "STATUS_CANT_DISABLE_MANDATORY" },
  { 0xC000005E, "STATUS_NO_LOGON_SERVERS" },
  { 0xC000005F, "STATUS_NO_SUCH_LOGON_SESSION" },
  { 0xC0000060, "STATUS_NO_SUCH_PRIVILEGE" },
  { 0xC0000061, "STATUS_PRIVILEGE_NOT_HELD" },
  { 0xC0000062, "STATUS_INVALID_ACCOUNT_NAME" },
  { 0xC0000063, "STATUS_USER_EXISTS" },
  { 0xC0000064, "STATUS_NO_SUCH_USER" },
  { 0xC0000065, "STATUS_GROUP_EXISTS" },
  { 0xC0000066, "STATUS_NO_SUCH_GROUP" },
  { 0xC0000067, "STATUS_MEMBER_IN_GROUP" },
  { 0xC0000068, "STATUS_MEMBER_NOT_IN_GROUP" },
  { 0xC0000069, "STATUS_LAST_ADMIN" },
  { 0xC000006A, "STATUS_WRONG_PASSWORD" },
  { 0xC000006B, "STATUS_ILL_FORMED_PASSWORD" },
  { 0xC000006C, "STATUS_PASSWORD_RESTRICTION" },
  { 0xC000006D, "STATUS_LOGON_FAILURE" },
  { 0xC000006E, "STATUS_ACCOUNT_RESTRICTION" },
  { 0xC000006F, "STATUS_INVALID_LOGON_HOURS" },
  { 0xC0000070, "STATUS_INVALID_WORKSTATION" },
  { 0xC0000071, "STATUS_PASSWORD_EXPIRED" },
  { 0xC0000072, "STATUS_ACCOUNT_DISABLED" },
  { 0xC0000073, "STATUS_NONE_MAPPED" },
  { 0xC0000074, "STATUS_TOO_MANY_LUIDS_REQUESTED" },
  { 0xC0000075, "STATUS_LUIDS_EXHAUSTED" },
  { 0xC0000076, "STATUS_INVALID_SUB_AUTHORITY" },
  { 0xC0000077, "STATUS_INVALID_ACL" },
  { 0xC0000078, "STATUS_INVALID_SID" },
  { 0xC0000079, "STATUS_INVALID_SECURITY_DESCR" },
  { 0xC000007A, "STATUS_PROCEDURE_NOT_FOUND" },
  { 0xC000007B, "STATUS_INVALID_IMAGE_FORMAT" },
  { 0xC000007C, "STATUS_NO_TOKEN" },
  { 0xC000007D, "STATUS_BAD_INHERITANCE_ACL" },
  { 0xC000007E, "STATUS_RANGE_NOT_LOCKED" },
  { 0xC000007F, "STATUS_DISK_FULL" },
  { 0xC0000080, "STATUS_SERVER_DISABLED" },
  { 0xC0000081, "STATUS_SERVER_NOT_DISABLED" },
  { 0xC0000082, "STATUS_TOO_MANY_GUIDS_REQUESTED" },
  { 0xC0000083, "STATUS_GUIDS_EXHAUSTED" },
  { 0xC0000084, "STATUS_INVALID_ID_AUTHORITY" },
  { 0xC0000085, "STATUS_AGENTS_EXHAUSTED" },
  { 0xC0000086, "STATUS_INVALID_VOLUME_LABEL" },
  { 0xC0000087, "STATUS_SECTION_NOT_EXTENDED" },
  { 0xC0000088, "STATUS_NOT_MAPPED_DATA" },
  { 0xC0000089, "STATUS_RESOURCE_DATA_NOT_FOUND" },
  { 0xC000008A, "STATUS_RESOURCE_TYPE_NOT_FOUND" },
  { 0xC000008B, "STATUS_RESOURCE_NAME_NOT_FOUND" },
  { 0xC000008C, "STATUS_ARRAY_BOUNDS_EXCEEDED" },
  { 0xC000008D, "STATUS_FLOAT_DENORMAL_OPERAND" },
  { 0xC000008E, "STATUS_FLOAT_DIVIDE_BY_ZERO" },
  { 0xC000008F, "STATUS_FLOAT_INEXACT_RESULT" },
  { 0xC0000090, "STATUS_FLOAT_INVALID_OPERATION" },
  { 0xC0000091, "STATUS_FLOAT_OVERFLOW" },
  { 0xC0000092, "STATUS_FLOAT_STACK_CHECK" },
  { 0xC0000093, "STATUS_FLOAT_UNDERFLOW" },
  { 0xC0000094, "STATUS_INTEGER_DIVIDE_BY_ZERO" },
  { 0xC0000095, "STATUS_INTEGER_OVERFLOW" },
  { 0xC0000096, "STATUS_PRIVILEGED_INSTRUCTION" },
  { 0xC0000097, "STATUS_TOO_MANY_PAGING_FILES" },
  { 0xC0000098, "STATUS_FILE_INVALID" },
  { 0xC0000099, "STATUS_ALLOTTED_SPACE_EXCEEDED" },
  { 0xC000009A, "STATUS_INSUFFICIENT_RESOURCES" },
  { 0xC000009B, "STATUS_DFS_EXIT_PATH_FOUND" },
  { 0xC000009C, "STATUS_DEVICE_DATA_ERROR" },
  { 0xC000009D, "STATUS_DEVICE_NOT_CONNECTED" },
  { 0xC000009E, "STATUS_DEVICE_POWER_FAILURE" },
  { 0xC000009F, "STATUS_FREE_VM_NOT_AT_BASE" },
  { 0xC00000A0, "STATUS_MEMORY_NOT_ALLOCATED" },
  { 0xC00000A1, "STATUS_WORKING_SET_QUOTA" },
  { 0xC00000A2, "STATUS_MEDIA_WRITE_PROTECTED" },
  { 0xC00000A3, "STATUS_DEVICE_NOT_READY" },
  { 0xC00000A4, "STATUS_INVALID_GROUP_ATTRIBUTES" },
  { 0xC00000A5, "STATUS_BAD_IMPERSONATION_LEVEL" },
  { 0xC00000A6, "STATUS_CANT_OPEN_ANONYMOUS" },
  { 0xC00000A7, "STATUS_BAD_VALIDATION_CLASS" },
  { 0xC00000A8, "STATUS_BAD_TOKEN_TYPE" },
  { 0xC00000A9, "STATUS_BAD_MASTER_BOOT_RECORD" },
  { 0xC00000AA, "STATUS_INSTRUCTION_MISALIGNMENT" },
  { 0xC00000AB, "STATUS_INSTANCE_NOT_AVAILABLE" },
  { 0xC00000AC, "STATUS_PIPE_NOT_AVAILABLE" },
  { 0xC00000AD, "STATUS_INVALID_PIPE_STATE" },
  { 0xC00000AE, "STATUS_PIPE_BUSY" },
  { 0xC00000AF, "STATUS_ILLEGAL_FUNCTION" },
  { 0xC00000B0, "STATUS_PIPE_DISCONNECTED" },
  { 0xC00000B1, "STATUS_PIPE_CLOSING" },
  { 0xC00000B2, "STATUS_PIPE_CONNECTED" },
  { 0xC00000B3, "STATUS_PIPE_LISTENING" },
  { 0xC00000B4, "STATUS_INVALID_READ_MODE" },
  { 0xC00000B5, "STATUS_IO_TIMEOUT" },
  { 0xC00000B6, "STATUS_FILE_FORCED_CLOSED" },
  { 0xC00000B7, "STATUS_PROFILING_NOT_STARTED" },
  { 0xC00000B8, "STATUS_PROFILING_NOT_STOPPED" },
  { 0xC00000B9, "STATUS_COULD_NOT_INTERPRET" },
  { 0xC00000BA, "STATUS_FILE_IS_A_DIRECTORY" },
  { 0xC00000BB, "STATUS_NOT_SUPPORTED" },
  { 0xC00000BC, "STATUS_REMOTE_NOT_LISTENING" },
  { 0xC00000BD, "STATUS_DUPLICATE_NAME" },
  { 0xC00000BE, "STATUS_BAD_NETWORK_PATH" },
  { 0xC00000BF, "STATUS_NETWORK_BUSY" },
  { 0xC00000C0, "STATUS_DEVICE_DOES_NOT_EXIST" },
  { 0xC00000C1, "STATUS_TOO_MANY_COMMANDS" },
  { 0xC00000C2, "STATUS_ADAPTER_HARDWARE_ERROR" },
  { 0xC00000C3, "STATUS_INVALID_NETWORK_RESPONSE" },
  { 0xC00000C4, "STATUS_UNEXPECTED_NETWORK_ERROR" },
  { 0xC00000C5, "STATUS_BAD_REMOTE_ADAPTER" },
  { 0xC00000C6, "STATUS_PRINT_QUEUE_FULL" },
  { 0xC00000C7, "STATUS_NO_SPOOL_SPACE" },
  { 0xC00000C8, "STATUS_PRINT_CANCELLED" },
  { 0xC00000C9, "STATUS_NETWORK_NAME_DELETED" },
  { 0xC00000CA, "STATUS_NETWORK_ACCESS_DENIED" },
  { 0xC00000CB, "STATUS_BAD_DEVICE_TYPE" },
  { 0xC00000CC, "STATUS_BAD_NETWORK_NAME" },
  { 0xC00000CD, "STATUS_TOO_MANY_NAMES" },
  { 0xC00000CE, "STATUS_TOO_MANY_SESSIONS" },
  { 0xC00000CF, "STATUS_SHARING_PAUSED" },
  { 0xC00000D0, "STATUS_REQUEST_NOT_ACCEPTED" },
  { 0xC00000D1, "STATUS_REDIRECTOR_PAUSED" },
  { 0xC00000D2, "STATUS_NET_WRITE_FAULT" },
  { 0xC00000D3, "STATUS_PROFILING_AT_LIMIT" },
  { 0xC00000D4, "STATUS_NOT_SAME_DEVICE" },
  { 0xC00000D5, "STATUS_FILE_RENAMED" },
  { 0xC00000D6, "STATUS_VIRTUAL_CIRCUIT_CLOSED" },
  { 0xC00000D7, "STATUS_NO_SECURITY_ON_OBJECT" },
  { 0xC00000D8, "STATUS_CANT_WAIT" },
  { 0xC00000D9, "STATUS_PIPE_EMPTY" },
  { 0xC00000DA, "STATUS_CANT_ACCESS_DOMAIN_INFO" },
  { 0xC00000DB, "STATUS_CANT_TERMINATE_SELF" },
  { 0xC00000DC, "STATUS_INVALID_SERVER_STATE" },
  { 0xC00000DD, "STATUS_INVALID_DOMAIN_STATE" },
  { 0xC00000DE, "STATUS_INVALID_DOMAIN_ROLE" },
  { 0xC00000DF, "STATUS_NO_SUCH_DOMAIN" },
  { 0xC00000E0, "STATUS_DOMAIN_EXISTS" },
  { 0xC00000E1, "STATUS_DOMAIN_LIMIT_EXCEEDED" },
  { 0xC00000E2, "STATUS_OPLOCK_NOT_GRANTED" },
  { 0xC00000E3, "STATUS_INVALID_OPLOCK_PROTOCOL" },
  { 0xC00000E4, "STATUS_INTERNAL_DB_CORRUPTION" },
  { 0xC00000E5, "STATUS_INTERNAL_ERROR" },
  { 0xC00000E6, "STATUS_GENERIC_NOT_MAPPED" },
  { 0xC00000E7, "STATUS_BAD_DESCRIPTOR_FORMAT" },
  { 0xC00000E8, "STATUS_INVALID_USER_BUFFER" },
  { 0xC00000E9, "STATUS_UNEXPECTED_IO_ERROR" },
  { 0xC00000EA, "STATUS_UNEXPECTED_MM_CREATE_ERR" },
  { 0xC00000EB, "STATUS_UNEXPECTED_MM_MAP_ERROR" },
  { 0xC00000EC, "STATUS_UNEXPECTED_MM_EXTEND_ERR" },
  { 0xC00000ED, "STATUS_NOT_LOGON_PROCESS" },
  { 0xC00000EE, "STATUS_LOGON_SESSION_EXISTS" },
  { 0xC00000EF, "STATUS_INVALID_PARAMETER_1" },
  { 0xC00000F0, "STATUS_INVALID_PARAMETER_2" },
  { 0xC00000F1, "STATUS_INVALID_PARAMETER_3" },
  { 0xC00000F2, "STATUS_INVALID_PARAMETER_4" },
  { 0xC00000F3, "STATUS_INVALID_PARAMETER_5" },
  { 0xC00000F4, "STATUS_INVALID_PARAMETER_6" },
  { 0xC00000F5, "STATUS_INVALID_PARAMETER_7" },
  { 0xC00000F6, "STATUS_INVALID_PARAMETER_8" },
  { 0xC00000F7, "STATUS_INVALID_PARAMETER_9" },
  { 0xC00000F8, "STATUS_INVALID_PARAMETER_10" },
  { 0xC00000F9, "STATUS_INVALID_PARAMETER_11" },
  { 0xC00000FA, "STATUS_INVALID_PARAMETER_12" },
  { 0xC00000FB, "STATUS_REDIRECTOR_NOT_STARTED" },
  { 0xC00000FC, "STATUS_REDIRECTOR_STARTED" },
  { 0xC00000FD, "STATUS_STACK_OVERFLOW" },
  { 0xC00000FE, "STATUS_NO_SUCH_PACKAGE" },
  { 0xC00000FF, "STATUS_BAD_FUNCTION_TABLE" },
  { 0xC0000100, "STATUS_VARIABLE_NOT_FOUND" },
  { 0xC0000101, "STATUS_DIRECTORY_NOT_EMPTY" },
  { 0xC0000102, "STATUS_FILE_CORRUPT_ERROR" },
  { 0xC0000103, "STATUS_NOT_A_DIRECTORY" },
  { 0xC0000104, "STATUS_BAD_LOGON_SESSION_STATE" },
  { 0xC0000105, "STATUS_LOGON_SESSION_COLLISION" },
  { 0xC0000106, "STATUS_NAME_TOO_LONG" },
  { 0xC0000107, "STATUS_FILES_OPEN" },
  { 0xC0000108, "STATUS_CONNECTION_IN_USE" },
  { 0xC0000109, "STATUS_MESSAGE_NOT_FOUND" },
  { 0xC000010A, "STATUS_PROCESS_IS_TERMINATING" },
  { 0xC000010B, "STATUS_INVALID_LOGON_TYPE" },
  { 0xC000010C, "STATUS_NO_GUID_TRANSLATION" },
  { 0xC000010D, "STATUS_CANNOT_IMPERSONATE" },
  { 0xC000010E, "STATUS_IMAGE_ALREADY_LOADED" },
  { 0xC000010F, "STATUS_ABIOS_NOT_PRESENT" },
  { 0xC0000110, "STATUS_ABIOS_LID_NOT_EXIST" },
  { 0xC0000111, "STATUS_ABIOS_LID_ALREADY_OWNED" },
  { 0xC0000112, "STATUS_ABIOS_NOT_LID_OWNER" },
  { 0xC0000113, "STATUS_ABIOS_INVALID_COMMAND" },
  { 0xC0000114, "STATUS_ABIOS_INVALID_LID" },
  { 0xC0000115, "STATUS_ABIOS_SELECTOR_NOT_AVAILABLE" },
  { 0xC0000116, "STATUS_ABIOS_INVALID_SELECTOR" },
  { 0xC0000117, "STATUS_NO_LDT" },
  { 0xC0000118, "STATUS_INVALID_LDT_SIZE" },
  { 0xC0000119, "STATUS_INVALID_LDT_OFFSET" },
  { 0xC000011A, "STATUS_INVALID_LDT_DESCRIPTOR" },
  { 0xC000011B, "STATUS_INVALID_IMAGE_NE_FORMAT" },
  { 0xC000011C, "STATUS_RXACT_INVALID_STATE" },
  { 0xC000011D, "STATUS_RXACT_COMMIT_FAILURE" },
  { 0xC000011E, "STATUS_MAPPED_FILE_SIZE_ZERO" },
  { 0xC000011F, "STATUS_TOO_MANY_OPENED_FILES" },
  { 0xC0000120, "STATUS_CANCELLED" },
  { 0xC0000121, "STATUS_CANNOT_DELETE" },
  { 0xC0000122, "STATUS_INVALID_COMPUTER_NAME" },
  { 0xC0000123, "STATUS_FILE_DELETED" },
  { 0xC0000124, "STATUS_SPECIAL_ACCOUNT" },
  { 0xC0000125, "STATUS_SPECIAL_GROUP" },
  { 0xC0000126, "STATUS_SPECIAL_USER" },
  { 0xC0000127, "STATUS_MEMBERS_PRIMARY_GROUP" },
  { 0xC0000128, "STATUS_FILE_CLOSED" },
  { 0xC0000129, "STATUS_TOO_MANY_THREADS" },
  { 0xC000012A, "STATUS_THREAD_NOT_IN_PROCESS" },
  { 0xC000012B, "STATUS_TOKEN_ALREADY_IN_USE" },
  { 0xC000012C, "STATUS_PAGEFILE_QUOTA_EXCEEDED" },
  { 0xC000012D, "STATUS_COMMITMENT_LIMIT" },
  { 0xC000012E, "STATUS_INVALID_IMAGE_LE_FORMAT" },
  { 0xC000012F, "STATUS_INVALID_IMAGE_NOT_MZ" },
  { 0xC0000130, "STATUS_INVALID_IMAGE_PROTECT" },
  { 0xC0000131, "STATUS_INVALID_IMAGE_WIN_16" },
  { 0xC0000132, "STATUS_LOGON_SERVER_CONFLICT" },
  { 0xC0000133, "STATUS_TIME_DIFFERENCE_AT_DC" },
  { 0xC0000134, "STATUS_SYNCHRONIZATION_REQUIRED" },
  { 0xC0000135, "STATUS_DLL_NOT_FOUND" },
  { 0xC0000136, "STATUS_OPEN_FAILED" },
  { 0xC0000137, "STATUS_IO_PRIVILEGE_FAILED" },
  { 0xC0000138, "STATUS_ORDINAL_NOT_FOUND" },
  { 0xC0000139, "STATUS_ENTRYPOINT_NOT_FOUND" },
  { 0xC000013A, "STATUS_CONTROL_C_EXIT" },
  { 0xC000013B, "STATUS_LOCAL_DISCONNECT" },
  { 0xC000013C, "STATUS_REMOTE_DISCONNECT" },
  { 0xC000013D, "STATUS_REMOTE_RESOURCES" },
  { 0xC000013E, "STATUS_LINK_FAILED" },
  { 0xC000013F, "STATUS_LINK_TIMEOUT" },
  { 0xC0000140, "STATUS_INVALID_CONNECTION" },
  { 0xC0000141, "STATUS_INVALID_ADDRESS" },
  { 0xC0000142, "STATUS_DLL_INIT_FAILED" },
  { 0xC0000143, "STATUS_MISSING_SYSTEMFILE" },
  { 0xC0000144, "STATUS_UNHANDLED_EXCEPTION" },
  { 0xC0000145, "STATUS_APP_INIT_FAILURE" },
  { 0xC0000146, "STATUS_PAGEFILE_CREATE_FAILED" },
  { 0xC0000147, "STATUS_NO_PAGEFILE" },
  { 0xC0000148, "STATUS_INVALID_LEVEL" },
  { 0xC0000149, "STATUS_WRONG_PASSWORD_CORE" },
  { 0xC000014A, "STATUS_ILLEGAL_FLOAT_CONTEXT" },
  { 0xC000014B, "STATUS_PIPE_BROKEN" },
  { 0xC000014C, "STATUS_REGISTRY_CORRUPT" },
  { 0xC000014D, "STATUS_REGISTRY_IO_FAILED" },
  { 0xC000014E, "STATUS_NO_EVENT_PAIR" },
  { 0xC000014F, "STATUS_UNRECOGNIZED_VOLUME" },
  { 0xC0000150, "STATUS_SERIAL_NO_DEVICE_INITED" },
  { 0xC0000151, "STATUS_NO_SUCH_ALIAS" },
  { 0xC0000152, "STATUS_MEMBER_NOT_IN_ALIAS" },
  { 0xC0000153, "STATUS_MEMBER_IN_ALIAS" },
  { 0xC0000154, "STATUS_ALIAS_EXISTS" },
  { 0xC0000155, "STATUS_LOGON_NOT_GRANTED" },
  { 0xC0000156, "STATUS_TOO_MANY_SECRETS" },
  { 0xC0000157, "STATUS_SECRET_TOO_LONG" },
  { 0xC0000158, "STATUS_INTERNAL_DB_ERROR" },
  { 0xC0000159, "STATUS_FULLSCREEN_MODE" },
  { 0xC000015A, "STATUS_TOO_MANY_CONTEXT_IDS" },
  { 0xC000015B, "STATUS_LOGON_TYPE_NOT_GRANTED" },
  { 0xC000015C, "STATUS_NOT_REGISTRY_FILE" },
  { 0xC000015D, "STATUS_NT_CROSS_ENCRYPTION_REQUIRED" },
  { 0xC000015E, "STATUS_DOMAIN_CTRLR_CONFIG_ERROR" },
  { 0xC000015F, "STATUS_FT_MISSING_MEMBER" },
  { 0xC0000160, "STATUS_ILL_FORMED_SERVICE_ENTRY" },
  { 0xC0000161, "STATUS_ILLEGAL_CHARACTER" },
  { 0xC0000162, "STATUS_UNMAPPABLE_CHARACTER" },
  { 0xC0000163, "STATUS_UNDEFINED_CHARACTER" },
  { 0xC0000164, "STATUS_FLOPPY_VOLUME" },
  { 0xC0000165, "STATUS_FLOPPY_ID_MARK_NOT_FOUND" },
  { 0xC0000166, "STATUS_FLOPPY_WRONG_CYLINDER" },
  { 0xC0000167, "STATUS_FLOPPY_UNKNOWN_ERROR" },
  { 0xC0000168, "STATUS_FLOPPY_BAD_REGISTERS" },
  { 0xC0000169, "STATUS_DISK_RECALIBRATE_FAILED" },
  { 0xC000016A, "STATUS_DISK_OPERATION_FAILED" },
  { 0xC000016B, "STATUS_DISK_RESET_FAILED" },
  { 0xC000016C, "STATUS_SHARED_IRQ_BUSY" },
  { 0xC000016D, "STATUS_FT_ORPHANING" },
  { 0xC000016E, "STATUS_BIOS_FAILED_TO_CONNECT_INTERRUPT" },
  { 0xC0000172, "STATUS_PARTITION_FAILURE" },
  { 0xC0000173, "STATUS_INVALID_BLOCK_LENGTH" },
  { 0xC0000174, "STATUS_DEVICE_NOT_PARTITIONED" },
  { 0xC0000175, "STATUS_UNABLE_TO_LOCK_MEDIA" },
  { 0xC0000176, "STATUS_UNABLE_TO_UNLOAD_MEDIA" },
  { 0xC0000177, "STATUS_EOM_OVERFLOW" },
  { 0xC0000178, "STATUS_NO_MEDIA" },
  { 0xC000017A, "STATUS_NO_SUCH_MEMBER" },
  { 0xC000017B, "STATUS_INVALID_MEMBER" },
  { 0xC000017C, "STATUS_KEY_DELETED" },
  { 0xC000017D, "STATUS_NO_LOG_SPACE" },
  { 0xC000017E, "STATUS_TOO_MANY_SIDS" },
  { 0xC000017F, "STATUS_LM_CROSS_ENCRYPTION_REQUIRED" },
  { 0xC0000180, "STATUS_KEY_HAS_CHILDREN" },
  { 0xC0000181, "STATUS_CHILD_MUST_BE_VOLATILE" },
  { 0xC0000182, "STATUS_DEVICE_CONFIGURATION_ERROR" },
  { 0xC0000183, "STATUS_DRIVER_INTERNAL_ERROR" },
  { 0xC0000184, "STATUS_INVALID_DEVICE_STATE" },
  { 0xC0000185, "STATUS_IO_DEVICE_ERROR" },
  { 0xC0000186, "STATUS_DEVICE_PROTOCOL_ERROR" },
  { 0xC0000187, "STATUS_BACKUP_CONTROLLER" },
  { 0xC0000188, "STATUS_LOG_FILE_FULL" },
  { 0xC0000189, "STATUS_TOO_LATE" },
  { 0xC000018A, "STATUS_NO_TRUST_LSA_SECRET" },
  { 0xC000018B, "STATUS_NO_TRUST_SAM_ACCOUNT" },
  { 0xC000018C, "STATUS_TRUSTED_DOMAIN_FAILURE" },
  { 0xC000018D, "STATUS_TRUSTED_RELATIONSHIP_FAILURE" },
  { 0xC000018E, "STATUS_EVENTLOG_FILE_CORRUPT" },
  { 0xC000018F, "STATUS_EVENTLOG_CANT_START" },
  { 0xC0000190, "STATUS_TRUST_FAILURE" },
  { 0xC0000191, "STATUS_MUTANT_LIMIT_EXCEEDED" },
  { 0xC0000192, "STATUS_NETLOGON_NOT_STARTED" },
  { 0xC0000193, "STATUS_ACCOUNT_EXPIRED" },
  { 0xC0000194, "STATUS_POSSIBLE_DEADLOCK" },
  { 0xC0000195, "STATUS_NETWORK_CREDENTIAL_CONFLICT" },
  { 0xC0000196, "STATUS_REMOTE_SESSION_LIMIT" },
  { 0xC0000197, "STATUS_EVENTLOG_FILE_CHANGED" },
  { 0xC0000198, "STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT" },
  { 0xC0000199, "STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT" },
  { 0xC000019A, "STATUS_NOLOGON_SERVER_TRUST_ACCOUNT" },
  { 0xC000019B, "STATUS_DOMAIN_TRUST_INCONSISTENT" },
  { 0xC000019C, "STATUS_FS_DRIVER_REQUIRED" },
  { 0xC0000202, "STATUS_NO_USER_SESSION_KEY" },
  { 0xC0000203, "STATUS_USER_SESSION_DELETED" },
  { 0xC0000204, "STATUS_RESOURCE_LANG_NOT_FOUND" },
  { 0xC0000205, "STATUS_INSUFF_SERVER_RESOURCES" },
  { 0xC0000206, "STATUS_INVALID_BUFFER_SIZE" },
  { 0xC0000207, "STATUS_INVALID_ADDRESS_COMPONENT" },
  { 0xC0000208, "STATUS_INVALID_ADDRESS_WILDCARD" },
  { 0xC0000209, "STATUS_TOO_MANY_ADDRESSES" },
  { 0xC000020A, "STATUS_ADDRESS_ALREADY_EXISTS" },
  { 0xC000020B, "STATUS_ADDRESS_CLOSED" },
  { 0xC000020C, "STATUS_CONNECTION_DISCONNECTED" },
  { 0xC000020D, "STATUS_CONNECTION_RESET" },
  { 0xC000020E, "STATUS_TOO_MANY_NODES" },
  { 0xC000020F, "STATUS_TRANSACTION_ABORTED" },
  { 0xC0000210, "STATUS_TRANSACTION_TIMED_OUT" },
  { 0xC0000211, "STATUS_TRANSACTION_NO_RELEASE" },
  { 0xC0000212, "STATUS_TRANSACTION_NO_MATCH" },
  { 0xC0000213, "STATUS_TRANSACTION_RESPONDED" },
  { 0xC0000214, "STATUS_TRANSACTION_INVALID_ID" },
  { 0xC0000215, "STATUS_TRANSACTION_INVALID_TYPE" },
  { 0xC0000216, "STATUS_NOT_SERVER_SESSION" },
  { 0xC0000217, "STATUS_NOT_CLIENT_SESSION" },
  { 0xC0000218, "STATUS_CANNOT_LOAD_REGISTRY_FILE" },
  { 0xC0000219, "STATUS_DEBUG_ATTACH_FAILED" },
  { 0xC000021A, "STATUS_SYSTEM_PROCESS_TERMINATED" },
  { 0xC000021B, "STATUS_DATA_NOT_ACCEPTED" },
  { 0xC000021C, "STATUS_NO_BROWSER_SERVERS_FOUND" },
  { 0xC000021D, "STATUS_VDM_HARD_ERROR" },
  { 0xC000021E, "STATUS_DRIVER_CANCEL_TIMEOUT" },
  { 0xC000021F, "STATUS_REPLY_MESSAGE_MISMATCH" },
  { 0xC0000220, "STATUS_MAPPED_ALIGNMENT" },
  { 0xC0000221, "STATUS_IMAGE_CHECKSUM_MISMATCH" },
  { 0xC0000222, "STATUS_LOST_WRITEBEHIND_DATA" },
  { 0xC0000223, "STATUS_CLIENT_SERVER_PARAMETERS_INVALID" },
  { 0xC0000224, "STATUS_PASSWORD_MUST_CHANGE" },
  { 0xC0000225, "STATUS_NOT_FOUND" },
  { 0xC0000226, "STATUS_NOT_TINY_STREAM" },
  { 0xC0000227, "STATUS_RECOVERY_FAILURE" },
  { 0xC0000228, "STATUS_STACK_OVERFLOW_READ" },
  { 0xC0000229, "STATUS_FAIL_CHECK" },
  { 0xC000022A, "STATUS_DUPLICATE_OBJECTID" },
  { 0xC000022B, "STATUS_OBJECTID_EXISTS" },
  { 0xC000022C, "STATUS_CONVERT_TO_LARGE" },
  { 0xC000022D, "STATUS_RETRY" },
  { 0xC000022E, "STATUS_FOUND_OUT_OF_SCOPE" },
  { 0xC000022F, "STATUS_ALLOCATE_BUCKET" },
  { 0xC0000230, "STATUS_PROPSET_NOT_FOUND" },
  { 0xC0000231, "STATUS_MARSHALL_OVERFLOW" },
  { 0xC0000232, "STATUS_INVALID_VARIANT" },
  { 0xC0000233, "STATUS_DOMAIN_CONTROLLER_NOT_FOUND" },
  { 0xC0000234, "STATUS_ACCOUNT_LOCKED_OUT" },
  { 0xC0000235, "STATUS_HANDLE_NOT_CLOSABLE" },
  { 0xC0000236, "STATUS_CONNECTION_REFUSED" },
  { 0xC0000237, "STATUS_GRACEFUL_DISCONNECT" },
  { 0xC0000238, "STATUS_ADDRESS_ALREADY_ASSOCIATED" },
  { 0xC0000239, "STATUS_ADDRESS_NOT_ASSOCIATED" },
  { 0xC000023A, "STATUS_CONNECTION_INVALID" },
  { 0xC000023B, "STATUS_CONNECTION_ACTIVE" },
  { 0xC000023C, "STATUS_NETWORK_UNREACHABLE" },
  { 0xC000023D, "STATUS_HOST_UNREACHABLE" },
  { 0xC000023E, "STATUS_PROTOCOL_UNREACHABLE" },
  { 0xC000023F, "STATUS_PORT_UNREACHABLE" },
  { 0xC0000240, "STATUS_REQUEST_ABORTED" },
  { 0xC0000241, "STATUS_CONNECTION_ABORTED" },
  { 0xC0000242, "STATUS_BAD_COMPRESSION_BUFFER" },
  { 0xC0000243, "STATUS_USER_MAPPED_FILE" },
  { 0xC0000244, "STATUS_AUDIT_FAILED" },
  { 0xC0000245, "STATUS_TIMER_RESOLUTION_NOT_SET" },
  { 0xC0000246, "STATUS_CONNECTION_COUNT_LIMIT" },
  { 0xC0000247, "STATUS_LOGIN_TIME_RESTRICTION" },
  { 0xC0000248, "STATUS_LOGIN_WKSTA_RESTRICTION" },
  { 0xC0000249, "STATUS_IMAGE_MP_UP_MISMATCH" },
  { 0xC0000250, "STATUS_INSUFFICIENT_LOGON_INFO" },
  { 0xC0000251, "STATUS_BAD_DLL_ENTRYPOINT" },
  { 0xC0000252, "STATUS_BAD_SERVICE_ENTRYPOINT" },
  { 0xC0000253, "STATUS_LPC_REPLY_LOST" },
  { 0xC0000254, "STATUS_IP_ADDRESS_CONFLICT1" },
  { 0xC0000255, "STATUS_IP_ADDRESS_CONFLICT2" },
  { 0xC0000256, "STATUS_REGISTRY_QUOTA_LIMIT" },
  { 0xC0000257, "STATUS_PATH_NOT_COVERED" },
  { 0xC0000258, "STATUS_NO_CALLBACK_ACTIVE" },
  { 0xC0000259, "STATUS_LICENSE_QUOTA_EXCEEDED" },
  { 0xC000025A, "STATUS_PWD_TOO_SHORT" },
  { 0xC000025B, "STATUS_PWD_TOO_RECENT" },
  { 0xC000025C, "STATUS_PWD_HISTORY_CONFLICT" },
  { 0xC000025E, "STATUS_PLUGPLAY_NO_DEVICE" },
  { 0xC000025F, "STATUS_UNSUPPORTED_COMPRESSION" },
  { 0xC0000260, "STATUS_INVALID_HW_PROFILE" },
  { 0xC0000261, "STATUS_INVALID_PLUGPLAY_DEVICE_PATH" },
  { 0xC0000262, "STATUS_DRIVER_ORDINAL_NOT_FOUND" },
  { 0xC0000263, "STATUS_DRIVER_ENTRYPOINT_NOT_FOUND" },
  { 0xC0000264, "STATUS_RESOURCE_NOT_OWNED" },
  { 0xC0000265, "STATUS_TOO_MANY_LINKS" },
  { 0xC0000266, "STATUS_QUOTA_LIST_INCONSISTENT" },
  { 0xC0000267, "STATUS_FILE_IS_OFFLINE" },
  { 0xC0000268, "STATUS_EVALUATION_EXPIRATION" },
  { 0xC0000269, "STATUS_ILLEGAL_DLL_RELOCATION" },
  { 0xC000026A, "STATUS_LICENSE_VIOLATION" },
  { 0xC000026B, "STATUS_DLL_INIT_FAILED_LOGOFF" },
  { 0xC000026C, "STATUS_DRIVER_UNABLE_TO_LOAD" },
  { 0xC000026D, "STATUS_DFS_UNAVAILABLE" },
  { 0xC000026E, "STATUS_VOLUME_DISMOUNTED" },
  { 0xC000026F, "STATUS_WX86_INTERNAL_ERROR" },
  { 0xC0000270, "STATUS_WX86_FLOAT_STACK_CHECK" },
  { 0xC0009898, "STATUS_WOW_ASSERTION" },
  { 0xC0020001, "RPC_NT_INVALID_STRING_BINDING" },
  { 0xC0020002, "RPC_NT_WRONG_KIND_OF_BINDING" },
  { 0xC0020003, "RPC_NT_INVALID_BINDING" },
  { 0xC0020004, "RPC_NT_PROTSEQ_NOT_SUPPORTED" },
  { 0xC0020005, "RPC_NT_INVALID_RPC_PROTSEQ" },
  { 0xC0020006, "RPC_NT_INVALID_STRING_UUID" },
  { 0xC0020007, "RPC_NT_INVALID_ENDPOINT_FORMAT" },
  { 0xC0020008, "RPC_NT_INVALID_NET_ADDR" },
  { 0xC0020009, "RPC_NT_NO_ENDPOINT_FOUND" },
  { 0xC002000A, "RPC_NT_INVALID_TIMEOUT" },
  { 0xC002000B, "RPC_NT_OBJECT_NOT_FOUND" },
  { 0xC002000C, "RPC_NT_ALREADY_REGISTERED" },
  { 0xC002000D, "RPC_NT_TYPE_ALREADY_REGISTERED" },
  { 0xC002000E, "RPC_NT_ALREADY_LISTENING" },
  { 0xC002000F, "RPC_NT_NO_PROTSEQS_REGISTERED" },
  { 0xC0020010, "RPC_NT_NOT_LISTENING" },
  { 0xC0020011, "RPC_NT_UNKNOWN_MGR_TYPE" },
  { 0xC0020012, "RPC_NT_UNKNOWN_IF" },
  { 0xC0020013, "RPC_NT_NO_BINDINGS" },
  { 0xC0020014, "RPC_NT_NO_PROTSEQS" },
  { 0xC0020015, "RPC_NT_CANT_CREATE_ENDPOINT" },
  { 0xC0020016, "RPC_NT_OUT_OF_RESOURCES" },
  { 0xC0020017, "RPC_NT_SERVER_UNAVAILABLE" },
  { 0xC0020018, "RPC_NT_SERVER_TOO_BUSY" },
  { 0xC0020019, "RPC_NT_INVALID_NETWORK_OPTIONS" },
  { 0xC002001A, "RPC_NT_NO_CALL_ACTIVE" },
  { 0xC002001B, "RPC_NT_CALL_FAILED" },
  { 0xC002001C, "RPC_NT_CALL_FAILED_DNE" },
  { 0xC002001D, "RPC_NT_PROTOCOL_ERROR" },
  { 0xC002001F, "RPC_NT_UNSUPPORTED_TRANS_SYN" },
  { 0xC0020021, "RPC_NT_UNSUPPORTED_TYPE" },
  { 0xC0020022, "RPC_NT_INVALID_TAG" },
  { 0xC0020023, "RPC_NT_INVALID_BOUND" },
  { 0xC0020024, "RPC_NT_NO_ENTRY_NAME" },
  { 0xC0020025, "RPC_NT_INVALID_NAME_SYNTAX" },
  { 0xC0020026, "RPC_NT_UNSUPPORTED_NAME_SYNTAX" },
  { 0xC0020028, "RPC_NT_UUID_NO_ADDRESS" },
  { 0xC0020029, "RPC_NT_DUPLICATE_ENDPOINT" },
  { 0xC002002A, "RPC_NT_UNKNOWN_AUTHN_TYPE" },
  { 0xC002002B, "RPC_NT_MAX_CALLS_TOO_SMALL" },
  { 0xC002002C, "RPC_NT_STRING_TOO_LONG" },
  { 0xC002002D, "RPC_NT_PROTSEQ_NOT_FOUND" },
  { 0xC002002E, "RPC_NT_PROCNUM_OUT_OF_RANGE" },
  { 0xC002002F, "RPC_NT_BINDING_HAS_NO_AUTH" },
  { 0xC0020030, "RPC_NT_UNKNOWN_AUTHN_SERVICE" },
  { 0xC0020031, "RPC_NT_UNKNOWN_AUTHN_LEVEL" },
  { 0xC0020032, "RPC_NT_INVALID_AUTH_IDENTITY" },
  { 0xC0020033, "RPC_NT_UNKNOWN_AUTHZ_SERVICE" },
  { 0xC0020034, "EPT_NT_INVALID_ENTRY" },
  { 0xC0020035, "EPT_NT_CANT_PERFORM_OP" },
  { 0xC0020036, "EPT_NT_NOT_REGISTERED" },
  { 0xC0020037, "RPC_NT_NOTHING_TO_EXPORT" },
  { 0xC0020038, "RPC_NT_INCOMPLETE_NAME" },
  { 0xC0020039, "RPC_NT_INVALID_VERS_OPTION" },
  { 0xC002003A, "RPC_NT_NO_MORE_MEMBERS" },
  { 0xC002003B, "RPC_NT_NOT_ALL_OBJS_UNEXPORTED" },
  { 0xC002003C, "RPC_NT_INTERFACE_NOT_FOUND" },
  { 0xC002003D, "RPC_NT_ENTRY_ALREADY_EXISTS" },
  { 0xC002003E, "RPC_NT_ENTRY_NOT_FOUND" },
  { 0xC002003F, "RPC_NT_NAME_SERVICE_UNAVAILABLE" },
  { 0xC0020040, "RPC_NT_INVALID_NAF_ID" },
  { 0xC0020041, "RPC_NT_CANNOT_SUPPORT" },
  { 0xC0020042, "RPC_NT_NO_CONTEXT_AVAILABLE" },
  { 0xC0020043, "RPC_NT_INTERNAL_ERROR" },
  { 0xC0020044, "RPC_NT_ZERO_DIVIDE" },
  { 0xC0020045, "RPC_NT_ADDRESS_ERROR" },
  { 0xC0020046, "RPC_NT_FP_DIV_ZERO" },
  { 0xC0020047, "RPC_NT_FP_UNDERFLOW" },
  { 0xC0020048, "RPC_NT_FP_OVERFLOW" },
  { 0xC0030001, "RPC_NT_NO_MORE_ENTRIES" },
  { 0xC0030002, "RPC_NT_SS_CHAR_TRANS_OPEN_FAIL" },
  { 0xC0030003, "RPC_NT_SS_CHAR_TRANS_SHORT_FILE" },
  { 0xC0030004, "RPC_NT_SS_IN_NULL_CONTEXT" },
  { 0xC0030005, "RPC_NT_SS_CONTEXT_MISMATCH" },
  { 0xC0030006, "RPC_NT_SS_CONTEXT_DAMAGED" },
  { 0xC0030007, "RPC_NT_SS_HANDLES_MISMATCH" },
  { 0xC0030008, "RPC_NT_SS_CANNOT_GET_CALL_HANDLE" },
  { 0xC0030009, "RPC_NT_NULL_REF_POINTER" },
  { 0xC003000A, "RPC_NT_ENUM_VALUE_OUT_OF_RANGE" },
  { 0xC003000B, "RPC_NT_BYTE_COUNT_TOO_SMALL" },
  { 0xC003000C, "RPC_NT_BAD_STUB_DATA" },
  { 0xC0020049, "RPC_NT_CALL_IN_PROGRESS" },
  { 0xC002004A, "RPC_NT_NO_MORE_BINDINGS" },
  { 0xC002004B, "RPC_NT_GROUP_MEMBER_NOT_FOUND" },
  { 0xC002004C, "EPT_NT_CANT_CREATE" },
  { 0xC002004D, "RPC_NT_INVALID_OBJECT" },
  { 0xC002004F, "RPC_NT_NO_INTERFACES" },
  { 0xC0020050, "RPC_NT_CALL_CANCELLED" },
  { 0xC0020051, "RPC_NT_BINDING_INCOMPLETE" },
  { 0xC0020052, "RPC_NT_COMM_FAILURE" },
  { 0xC0020053, "RPC_NT_UNSUPPORTED_AUTHN_LEVEL" },
  { 0xC0020054, "RPC_NT_NO_PRINC_NAME" },
  { 0xC0020055, "RPC_NT_NOT_RPC_ERROR" },
  { 0x40020056, "RPC_NT_UUID_LOCAL_ONLY" },
  { 0xC0020057, "RPC_NT_SEC_PKG_ERROR" },
  { 0xC0020058, "RPC_NT_NOT_CANCELLED" },
  { 0xC0030059, "RPC_NT_INVALID_ES_ACTION" },
  { 0xC003005A, "RPC_NT_WRONG_ES_VERSION" },
  { 0xC003005B, "RPC_NT_WRONG_STUB_VERSION" },
  { 0xC003005C, "RPC_NT_INVALID_PIPE_OBJECT" },
  { 0xC003005D, "RPC_NT_INVALID_PIPE_OPERATION" },
  { 0xC003005E, "RPC_NT_WRONG_PIPE_VERSION" },
  { 0x400200AF, "RPC_NT_SEND_INCOMPLETE" },
  { 0,          NULL }
};



static const true_false_string tfs_smb_flags_lock = {
	"Lock&Read, Write&Unlock are supported",
	"Lock&Read, Write&Unlock are not supported"
};
static const true_false_string tfs_smb_flags_receive_buffer = {
	"Receive buffer has been posted",
	"Receive buffer has not been posted"
};
static const true_false_string tfs_smb_flags_caseless = {
	"Path names are caseless",
	"Path names are case sensitive"
};
static const true_false_string tfs_smb_flags_canon = {
	"Pathnames are canonicalized",
	"Pathnames are not canonicalized"
};
static const true_false_string tfs_smb_flags_oplock = {
	"OpLock requested/granted",
	"OpLock not requested/granted"
};
static const true_false_string tfs_smb_flags_notify = {
	"Notify client on all modifications",
	"Notify client only on open"
};
static const true_false_string tfs_smb_flags_response = {
	"Message is a response to the client/redirector",
	"Message is a request to the server"
};

static int
dissect_smb_flags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint8 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_guint8(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 1,
			"Flags: 0x%02x", mask);
		tree = proto_item_add_subtree(item, ett_smb_flags);
 	}
	proto_tree_add_boolean(tree, hf_smb_flags_response,
		tvb, offset, 1, mask);
	proto_tree_add_boolean(tree, hf_smb_flags_notify,
		tvb, offset, 1, mask);
	proto_tree_add_boolean(tree, hf_smb_flags_oplock,
		tvb, offset, 1, mask);
	proto_tree_add_boolean(tree, hf_smb_flags_canon,
		tvb, offset, 1, mask);
	proto_tree_add_boolean(tree, hf_smb_flags_caseless,
		tvb, offset, 1, mask);
	proto_tree_add_boolean(tree, hf_smb_flags_receive_buffer,
		tvb, offset, 1, mask);
	proto_tree_add_boolean(tree, hf_smb_flags_lock,
		tvb, offset, 1, mask);
	offset += 1;
	return offset;
}


 
static const true_false_string tfs_smb_flags2_long_names_allowed = {
	"Long file names are allowed in the response",
	"Long file names are not allowed in the response"
};
static const true_false_string tfs_smb_flags2_ea = {
	"Extended attributes are supported",
	"Extended attributes are not supported"
};
static const true_false_string tfs_smb_flags2_sec_sig = {
	"Security signatures are supported",
	"Security signatures are not supported"
};
static const true_false_string tfs_smb_flags2_long_names_used = {
	"Path names in request are long file names",
	"Path names in request are not long file names"
};
static const true_false_string tfs_smb_flags2_esn = {
	"Extended security negotiation is supported",
	"Extended security negotiation is not supported"
};
static const true_false_string tfs_smb_flags2_dfs = {
	"Resolve pathnames with Dfs",
	"Don't resolve pathnames with Dfs"
};
static const true_false_string tfs_smb_flags2_roe = {
	"Permit reads if execute-only",
	"Don't permit reads if execute-only"
};
static const true_false_string tfs_smb_flags2_nt_error = {
	"Error codes are NT error codes",
	"Error codes are DOS error codes"
};
static const true_false_string tfs_smb_flags2_string = {
	"Strings are Unicode",
	"Strings are ASCII"
};
static int
dissect_smb_flags2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint16 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohs(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 2,
			"Flags2: 0x%04x", mask);
		tree = proto_item_add_subtree(item, ett_smb_flags2);
	}

	proto_tree_add_boolean(tree, hf_smb_flags2_string,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_flags2_nt_error,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_flags2_roe,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_flags2_dfs,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_flags2_esn,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_flags2_long_names_used,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_flags2_sec_sig,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_flags2_ea,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_flags2_long_names_allowed,
		tvb, offset, 2, mask);

	offset += 2;
	return offset;
}



#define SMB_FLAGS_DIRN 0x80


static gboolean
dissect_smb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	proto_item *item = NULL, *hitem = NULL;
	proto_tree *tree = NULL, *htree = NULL;
	guint8          flags;
	guint16         flags2;
	smb_info_t 	si;
	smb_saved_info_t	*sip = NULL;
        guint32 nt_status = 0;
        guint8 errclass = 0;
        guint16 errcode = 0;
	guint16 uid, pid, tid;

	top_tree=parent_tree;

	/* must check that this really is a smb packet */
	if (!tvb_bytes_exist(tvb, 0, 4))
		return FALSE;

	if( (tvb_get_guint8(tvb, 0) != 0xff)
	    || (tvb_get_guint8(tvb, 1) != 'S')
	    || (tvb_get_guint8(tvb, 2) != 'M')
	    || (tvb_get_guint8(tvb, 3) != 'B') ){
		return FALSE;
	}
	 
	if (check_col(pinfo->fd, COL_PROTOCOL)){
		col_set_str(pinfo->fd, COL_PROTOCOL, "SMB");
	}
	if (check_col(pinfo->fd, COL_INFO)){
		col_clear(pinfo->fd, COL_INFO);
	}

	/* start off using the local variable, we will allocate a new one if we
	   need to*/
	si.mid = tvb_get_letohs(tvb, offset+30);
	uid = tvb_get_letohs(tvb, offset+28);
	pid = tvb_get_letohs(tvb, offset+26);
	tid = tvb_get_letohs(tvb, offset+24);
	flags2 = tvb_get_letohs(tvb, offset+10);
	if(flags2 & 0x8000){
		si.unicode = TRUE; /* Mark them as Unicode */
	} else {
		si.unicode = FALSE;
	}
	flags = tvb_get_guint8(tvb, offset+9);
	si.request = !(flags&SMB_FLAGS_DIRN);
	si.cmd = tvb_get_guint8(tvb, offset+4);
	si.info_level = -1;
	si.info_count = -1;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, proto_smb, tvb, offset, 
			tvb_length_remaining(tvb, 0), FALSE);
		tree = proto_item_add_subtree(item, ett_smb);

		hitem = proto_tree_add_text(tree, tvb, offset, 32, 
			"SMB Header");

		htree = proto_item_add_subtree(hitem, ett_smb_hdr);
	}

	proto_tree_add_text(htree, tvb, offset, 4, "Server Component: SMB");
	offset += 4;  /* Skip the marker */


	if( (si.request)
	    &&  (si.mid==0)
	    &&  (uid==0)
	    &&  (pid==0)
	    &&  (tid==0) ){
		/* this is a broadcast SMB packet, there will not be a reply.
		   We dont need to do anything 
		*/
		si.unidir = TRUE;
	} else if( (si.cmd==SMB_COM_NT_CANCEL)     /* NT Cancel */
		   ||(si.cmd==SMB_COM_TRANSACTION_SECONDARY)   /* Transaction Secondary */
		   ||(si.cmd==SMB_COM_TRANSACTION2_SECONDARY)   /* Transaction2 Secondary */
		   ||(si.cmd==SMB_COM_NT_TRANSACT_SECONDARY)){ /* NT Transaction Secondary */
		/* Ok, we got a special request type. This request is either
		   an NT Cancel or a continuation relative to a real request
		   in an earlier packet.  In either case, we don't expect any
		   responses to this packet.  For continuations, any later
		   responses we see really just belong to the original request.
		   Anyway, we want to remember this packet somehow and
		   remember which original request it is associated with so
		   we can say nice things such as "This is a Cancellation to
		   the request in frame x", but we don't want the
		   request/response matching to get messed up.

		   The only thing we do in this case is trying to find which original
		   request we match with and insert an entry for this "special" 
		   request for later reference. We continue to reference the original
		   requests smb_saved_info_t but we dont touch it or change anything
		   in it.
		*/
		conversation_t *conversation;
		conv_tables_t *ct;

		si.unidir = TRUE;  /*we dont expect an answer to this one*/
		
		/* find which conversation we are part of and get the tables for that 
		   conversation*/
		conversation = find_conversation(&pinfo->src, &pinfo->dst,
			 pinfo->ptype,  pinfo->srcport, pinfo->destport, 0);
		if(conversation){
			ct=conversation_get_proto_data(conversation, proto_smb);

			if(!pinfo->fd->flags.visited){
				/* try to find which original call we match and if we 
				   find it add us to the matched table. Dont touch
				   anything else since we dont want this one to mess
				   up the request/response matching. We still consider
				   the initial call the real request and this is only
				   some sort of continuation.
				*/
				/* we only check the unmatched table and assume that the
				   last seen MID matching ours is the right one.
				   This can fail but is better than nothing
				*/
				sip=g_hash_table_lookup(ct->unmatched, (void *)si.mid);
				if(sip!=NULL){
					g_hash_table_insert(ct->matched, (void *)pinfo->fd->num, sip);
				}
			} else {
				/* we have seen this packet before; check the
				   matching table
				*/
				sip=g_hash_table_lookup(ct->matched, (void *)pinfo->fd->num);
				if(sip==NULL){
				/*
				  We didn't find it.
				  Too bad, unfortunately there is not really much we can
				  do now since this means that we never saw the initial
				  request.
				 */
				}
			}
		}


		if(sip && sip->frame_req){
			switch(si.cmd){
			case SMB_COM_NT_CANCEL:
				proto_tree_add_uint(htree, hf_smb_cancel_to, 
						    tvb, 0, 0, sip->frame_req);
				break;
			case SMB_COM_TRANSACTION_SECONDARY:
			case SMB_COM_TRANSACTION2_SECONDARY:
			case SMB_COM_NT_TRANSACT_SECONDARY:
				proto_tree_add_uint(htree, hf_smb_continuation_to, 
						    tvb, 0, 0, sip->frame_req);
				break;
			}
		} else {
			switch(si.cmd){
			case SMB_COM_NT_CANCEL:
				proto_tree_add_text(htree, tvb, 0, 0,
						    "Cancellation to: <unknown frame>");
				break;
			case SMB_COM_TRANSACTION_SECONDARY:
			case SMB_COM_TRANSACTION2_SECONDARY:
			case SMB_COM_NT_TRANSACT_SECONDARY:
				proto_tree_add_text(htree, tvb, 0, 0,
						    "Continuation to: <unknown frame>");
				break;
			}
		}
	} else { /* normal bidirectional request or response */
		conversation_t *conversation;
		conv_tables_t *ct;

		si.unidir = FALSE;

		/* first we try to find which conversation this packet is 
		   part of 
		*/
		conversation = find_conversation(&pinfo->src, &pinfo->dst,
			 pinfo->ptype,  pinfo->srcport, pinfo->destport, 0);
		if(conversation==NULL){
			/* OK this is a new conversation, we must create it
			   and attach appropriate data (matched and unmatched 
			   table for this conversation)
			*/
			conversation = conversation_new(&pinfo->src, &pinfo->dst, 
				pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
			ct = g_mem_chunk_alloc(conv_tables_chunk);
			ct->matched= g_hash_table_new(smb_saved_info_hash_matched, 
				smb_saved_info_equal_matched);		
			ct->unmatched= g_hash_table_new(smb_saved_info_hash_matched, 
				smb_saved_info_equal_matched);		
			conversation_add_proto_data(conversation, proto_smb, ct);
		} else {
			/* this is an old conversation, just get the tables */
			ct=conversation_get_proto_data(conversation, proto_smb);
		}
		if(!pinfo->fd->flags.visited){
			/* first see if we find an unmatched smb "equal" to 
			   the current one 
			*/
			sip=g_hash_table_lookup(ct->unmatched, (void *)si.mid);
			if(sip!=NULL){
				if(si.request){
					/* ok, we are processing an SMB
					   request but there was already
					   another "identical" smb resuest
					   we had not matched yet.
					   This must mean that either we have
					   a retransmission or that the
					   response to the previous one was
					   lost and the client has reused
					   the MID for this conversation.
					   In either case it's not much more
					   we can do than forget the old
					   request and concentrate on the 
					   present one instead.
					*/
					g_hash_table_remove(ct->unmatched, (void *)si.mid);
				} else {
					/* we have found a response to some request we have seen earlier.
					   What we do now depends on whether this is the first response
					   to that request we see (id frame_res==0) or not. 
					*/
					if(sip->frame_res==0){
						/* ok it is the first response we have seen to this packet */
						sip->frame_res = pinfo->fd->num;
						g_hash_table_insert(ct->matched, (void *)sip->frame_req, sip);
						g_hash_table_insert(ct->matched, (void *)sip->frame_res, sip);
					} else {
						/* we have already seen another response to this one, but
						   register it anyway so we see which request it matches 
						*/
						g_hash_table_insert(ct->matched, (void *)pinfo->fd->num, sip);
					}
				}
			}
			if(si.request){
				sip = g_mem_chunk_alloc(smb_saved_info_chunk);
				sip->frame_req = pinfo->fd->num;
				sip->frame_res = 0;
				sip->extra_info = NULL;
				g_hash_table_insert(ct->unmatched, (void *)si.mid, sip);
			}
		} else {
			/* we have seen this packet before; check the
			   matching table.
			   If we haven't yet seen the reply, we won't
			   find the info for it; we don't need it, as
			   we only use it to save information, and, as
			   we've seen this packet before, we've already
			   saved the information.
			*/
			sip=g_hash_table_lookup(ct->matched, (void *)pinfo->fd->num);
		}
	}

	/*
	 * Pass the "sip" on to subdissectors through "si".
	 */
	si.sip = sip;

	if (sip != NULL) {
		/*
		 * Put in fields for the frame number of the frame to which
		 * this is a response or the frame with the response to this
		 * frame - if we know the frame number (i.e., it's not 0).
		 */
		if(si.request){
			if (sip->frame_res != 0)
				proto_tree_add_uint(htree, hf_smb_response_in, tvb, 0, 0, sip->frame_res);
		} else {
			if (sip->frame_req != 0)
				proto_tree_add_uint(htree, hf_smb_response_to, tvb, 0, 0, sip->frame_req);
		}
	}

	/* smb command */
	proto_tree_add_uint_format(htree, hf_smb_cmd, tvb, offset, 1, si.cmd, "SMB Command: %s (0x%02x)", decode_smb_name(si.cmd), si.cmd);
	offset += 1;

	if(flags2 & 0x4000){
		/* handle NT 32 bit error code */

                nt_status = tvb_get_letohl(tvb, offset);

		proto_tree_add_item(htree, hf_smb_nt_status, tvb, offset, 4,
			TRUE);
		offset += 4;

	} else {
		/* handle DOS error code & class */
		errclass = tvb_get_guint8(tvb, offset);
		proto_tree_add_uint(htree, hf_smb_error_class, tvb, offset, 1,
			errclass);
		offset += 1;

		/* reserved byte */
		proto_tree_add_item(htree, hf_smb_reserved, tvb, offset, 1, TRUE);
		offset += 1;

		/* error code */
		/* XXX - the type of this field depends on the value of
		 * "errcls", so there is isn't a single value_string array
		 * fo it, so there can't be a single field for it.
		 */
		errcode = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint_format(htree, hf_smb_error_code, tvb,
			offset, 2, errcode, "Error Code: %s",
			decode_smb_error(errclass, errcode));
		offset += 2;
	}

	/* flags */
	offset = dissect_smb_flags(tvb, pinfo, htree, offset);

	/* flags2 */
	offset = dissect_smb_flags2(tvb, pinfo, htree, offset);

	/*
	 * The document at
	 *
	 *	http://www.samba.org/samba/ftp/specs/smbpub.txt
	 *
	 * (a text version of "Microsoft Networks SMB FILE SHARING
	 * PROTOCOL, Document Version 6.0p") says that:
	 *
	 *	the first 2 bytes of these 12 bytes are, for NT Create and X,
	 *	the "High Part of PID";
	 *
	 *	the next four bytes are reserved;
	 *
	 *	the next four bytes are, for SMB-over-IPX (with no
	 *	NetBIOS involved) two bytes of Session ID and two bytes
	 *	of SequenceNumber.
	 *
	 * If we ever implement SMB-over-IPX (which I suspect goes over
	 * IPX sockets 0x0550, 0x0552, and maybe 0x0554, as per the
	 * document in question), we'd probably want to have some way
	 * to determine whether this is SMB-over-IPX or not (which could
	 * be done by adding a PT_IPXSOCKET port type, having the
	 * IPX dissector set "pinfo->srcport" and "pinfo->destport",
	 * and having the SMB dissector check for a port type of
	 * PT_IPXSOCKET and for "pinfo->match_port" being either
	 * IPX_SOCKET_NWLINK_SMB_SERVER or IPX_SOCKET_NWLINK_SMB_REDIR
	 * or, if it also uses 0x0554, IPX_SOCKET_NWLINK_SMB_MESSENGER).
	 */

	/* 12 reserved bytes */
	proto_tree_add_item(htree, hf_smb_reserved, tvb, offset, 12, TRUE);
	offset += 12;

	/* TID */
	proto_tree_add_uint(htree, hf_smb_tid, tvb, offset, 2, tid);
	offset += 2;

	/* PID */
	proto_tree_add_uint(htree, hf_smb_pid, tvb, offset, 2, pid);
	offset += 2;

	/* UID */
	proto_tree_add_uint(htree, hf_smb_uid, tvb, offset, 2, uid);
	offset += 2;

	/* MID */
	proto_tree_add_uint(htree, hf_smb_mid, tvb, offset, 2, si.mid);
	offset += 2;

	pinfo->private_data = &si;
        dissect_smb_command(tvb, pinfo, parent_tree, offset, tree, si.cmd);

	/* Append error info from this packet to info string. */
	if (!si.request && check_col(pinfo->fd, COL_INFO)) {
		if (flags2 & 0x4000) {
			/*
			 * The status is an NT status code; was there
			 * an error?
			 */
			if (nt_status != 0) {
				/*
				 * Yes.
				 */
				col_append_fstr(
					pinfo->fd, COL_INFO, ", Error: %s",
					val_to_str(nt_status, NT_errors, "%s"));
			}
		} else {
			/*
			 * The status is a DOS error class and code; was
			 * there an error?
			 */
			if (errclass != SMB_SUCCESS) {
				/*
				 * Yes.
				 */
				col_append_fstr(
					pinfo->fd, COL_INFO, ", Error: %s",
					decode_smb_error(errclass, errcode));
			}
		}
	}

	return TRUE;
}

void
proto_register_smb(void)
{
	static hf_register_info hf[] = {
	{ &hf_smb_cmd,
		{ "SMB Command", "smb.cmd", FT_UINT8, BASE_HEX,
		VALS(smb_cmd_vals), 0x0, "SMB Command", HFILL }},

	{ &hf_smb_word_count,
		{ "Word Count (WCT)", "smb.wct", FT_UINT8, BASE_DEC,
		NULL, 0x0, "Word Count, count of parameter words", HFILL }},

	{ &hf_smb_byte_count,
		{ "Byte Count (BCC)", "smb.bcc", FT_UINT16, BASE_DEC,
		NULL, 0x0, "Byte Count, count of data bytes", HFILL }},

	{ &hf_smb_response_to,
		{ "Response to", "smb.response_to", FT_UINT32, BASE_DEC,
		NULL, 0, "This packet is a response to the packet in this frame", HFILL }},

	{ &hf_smb_response_in,
		{ "Response in", "smb.response_in", FT_UINT32, BASE_DEC,
		NULL, 0, "The response to this packet is in this packet", HFILL }},

	{ &hf_smb_continuation_to,
		{ "Continuation to", "smb.continuation_to", FT_UINT32, BASE_DEC,
		NULL, 0, "This packet is a continuation to the packet in this frame", HFILL }},

	{ &hf_smb_nt_status,
		{ "NT Status", "smb.nt_status", FT_UINT32, BASE_HEX,
		VALS(NT_errors), 0, "NT Status code", HFILL }},

	{ &hf_smb_error_class,
		{ "Error Class", "smb.error_class", FT_UINT8, BASE_HEX,
		VALS(errcls_types), 0, "DOS Error Class", HFILL }},

	{ &hf_smb_error_code,
		{ "Error Code", "smb.error_code", FT_UINT16, BASE_HEX,
		NULL, 0, "DOS Error Code", HFILL }},

	{ &hf_smb_reserved,
		{ "Reserved", "smb.reserved", FT_BYTES, BASE_HEX,
		NULL, 0, "Reserved bytes, must be zero", HFILL }},

	{ &hf_smb_pid,
		{ "Process ID", "smb.pid", FT_UINT16, BASE_DEC,
		NULL, 0, "Process ID", HFILL }},

	{ &hf_smb_tid,
		{ "Tree ID", "smb.tid", FT_UINT16, BASE_DEC,
		NULL, 0, "Tree ID", HFILL }},

	{ &hf_smb_uid,
		{ "User ID", "smb.uid", FT_UINT16, BASE_DEC,
		NULL, 0, "User ID", HFILL }},

	{ &hf_smb_mid,
		{ "Multiplex ID", "smb.mid", FT_UINT16, BASE_DEC,
		NULL, 0, "Multiplex ID", HFILL }},

	{ &hf_smb_flags_lock,
		{ "Lock and Read", "smb.flags.lock", FT_BOOLEAN, 8,
		TFS(&tfs_smb_flags_lock), 0x01, "Are Lock&Read and Write&Unlock operations supported?", HFILL }},

	{ &hf_smb_flags_receive_buffer,
		{ "Receive Buffer Posted", "smb.flags.receive_buffer", FT_BOOLEAN, 8,
		TFS(&tfs_smb_flags_receive_buffer), 0x02, "Have receive buffers been reported?", HFILL }},

	{ &hf_smb_flags_caseless,
		{ "Case Sensitivity", "smb.flags.caseless", FT_BOOLEAN, 8,
		TFS(&tfs_smb_flags_caseless), 0x08, "Are pathnames caseless or casesensitive?", HFILL }},

	{ &hf_smb_flags_canon,
		{ "Canonicalized Pathnames", "smb.flags.canon", FT_BOOLEAN, 8,
		TFS(&tfs_smb_flags_canon), 0x10, "Are pathnames canonicalized?", HFILL }},

	{ &hf_smb_flags_oplock,
		{ "Oplocks", "smb.flags.oplock", FT_BOOLEAN, 8,
		TFS(&tfs_smb_flags_oplock), 0x20, "Is an oplock requested/granted?", HFILL }},

	{ &hf_smb_flags_notify,
		{ "Notify", "smb.flags.notify", FT_BOOLEAN, 8,
		TFS(&tfs_smb_flags_notify), 0x40, "Notify on open or all?", HFILL }},

	{ &hf_smb_flags_response,
		{ "Request/Response", "smb.flags.response", FT_BOOLEAN, 8,
		TFS(&tfs_smb_flags_response), 0x80, "Is this a request or a response?", HFILL }},

	{ &hf_smb_flags2_long_names_allowed,
		{ "Long Names Allowed", "smb.flags2.long_names_allowed", FT_BOOLEAN, 16,
		TFS(&tfs_smb_flags2_long_names_allowed), 0x0001, "Are long file names allowed in the response?", HFILL }},

	{ &hf_smb_flags2_ea,
		{ "Extended Attributes", "smb.flags2.ea", FT_BOOLEAN, 16,
		TFS(&tfs_smb_flags2_ea), 0x0002, "Are extended attributes supported?", HFILL }},

	{ &hf_smb_flags2_sec_sig,
		{ "Security Signatures", "smb.flags2.sec_sig", FT_BOOLEAN, 16,
		TFS(&tfs_smb_flags2_sec_sig), 0x0004, "Are security signatures supported?", HFILL }},

	{ &hf_smb_flags2_long_names_used,
		{ "Long Names Used", "smb.flags2.long_names_used", FT_BOOLEAN, 16,
		TFS(&tfs_smb_flags2_long_names_used), 0x0040, "Are pathnames in this request long file names?", HFILL }},

	{ &hf_smb_flags2_esn,
		{ "Extended Security Negotiation", "smb.flags2.esn", FT_BOOLEAN, 16,
		TFS(&tfs_smb_flags2_esn), 0x0800, "Is extended security negotiation supported?", HFILL }},

	{ &hf_smb_flags2_dfs,
		{ "Dfs", "smb.flags2.dfs", FT_BOOLEAN, 16,
		TFS(&tfs_smb_flags2_dfs), 0x1000, "Can pathnames be resolved using Dfs?", HFILL }},

	{ &hf_smb_flags2_roe,
		{ "Execute-only Reads", "smb.flags2.roe", FT_BOOLEAN, 16,
		TFS(&tfs_smb_flags2_roe), 0x2000, "Will reads be allowed for execute-only files?", HFILL }},

	{ &hf_smb_flags2_nt_error,
		{ "Error Code Type", "smb.flags2.nt_error", FT_BOOLEAN, 16,
		TFS(&tfs_smb_flags2_nt_error), 0x4000, "Are error codes NT or DOS format?", HFILL }},

	{ &hf_smb_flags2_string,
		{ "Unicode Strings", "smb.flags2.string", FT_BOOLEAN, 16,
		TFS(&tfs_smb_flags2_string), 0x8000, "Are strings ASCII or Unicode?", HFILL }},

	{ &hf_smb_buffer_format,
		{ "Buffer Format", "smb.buffer_format", FT_UINT8, BASE_DEC,
		VALS(buffer_format_vals), 0x0, "Buffer Format, type of buffer", HFILL }},

	{ &hf_smb_dialect_name,
		{ "Name", "smb.dialect.name", FT_STRING, BASE_NONE,
		NULL, 0, "Name of dialect", HFILL }},

	{ &hf_smb_dialect_index,
		{ "Selected Index", "smb.dialect.index", FT_UINT16, BASE_DEC,
		NULL, 0, "Index of selected dialect", HFILL }},

	{ &hf_smb_max_trans_buf_size,
		{ "Max Buffer Size", "smb.max_bufsize", FT_UINT32, BASE_DEC,
		NULL, 0, "Maximum transmit buffer size", HFILL }},

	{ &hf_smb_max_mpx_count,
		{ "Max Mpx Count", "smb.max_mpx_count", FT_UINT16, BASE_DEC,
		NULL, 0, "Maximum pending multiplexed requests", HFILL }},

	{ &hf_smb_max_vcs_num,
		{ "Max VCs", "smb.max_vcs", FT_UINT16, BASE_DEC,
		NULL, 0, "Maximum VCs between client and server", HFILL }},

	{ &hf_smb_session_key,
		{ "Session Key", "smb.session_key", FT_UINT32, BASE_HEX,
		NULL, 0, "Unique token identifying this session", HFILL }},

	{ &hf_smb_server_timezone,
		{ "Time Zone", "smb.server.timezone", FT_INT16, BASE_DEC,
		NULL, 0, "Current timezone at server.", HFILL }},

	{ &hf_smb_encryption_key_length,
		{ "Key Length", "smb.encryption_key_length", FT_UINT16, BASE_DEC,
		NULL, 0, "Encryption key length (must be 0 if not LM2.1 dialect)", HFILL }},

	{ &hf_smb_encryption_key,
		{ "Encryption Key", "smb.encryption_key", FT_BYTES, BASE_HEX,
		NULL, 0, "Challenge/Response Encryption Key (for LM2.1 dialect)", HFILL }},

	{ &hf_smb_primary_domain,
		{ "Primary Domain", "smb.primary_domain", FT_STRING, BASE_NONE,
		NULL, 0, "The server's primary domain", HFILL }},

	{ &hf_smb_max_raw_buf_size,
		{ "Max Raw Buffer", "smb.max_raw", FT_UINT32, BASE_DEC,
		NULL, 0, "Maximum raw buffer size", HFILL }},

	{ &hf_smb_server_guid,
		{ "Server GUID", "smb.server.guid", FT_BYTES, BASE_HEX,
		NULL, 0, "Globally unique identifier for this server", HFILL }},

	{ &hf_smb_security_blob_len,
		{ "Security Blob Length", "smb.security_blob_len", FT_UINT16, BASE_DEC,
		NULL, 0, "Security blob length", HFILL }},

	{ &hf_smb_security_blob,
		{ "Security Blob", "smb.security_blob", FT_BYTES, BASE_HEX,
		NULL, 0, "Security blob", HFILL }},

	{ &hf_smb_sm_mode16,
		{ "Mode", "smb.sm.mode", FT_BOOLEAN, 16,
		TFS(&tfs_sm_mode), SECURITY_MODE_MODE, "User or Share security mode?", HFILL }},

	{ &hf_smb_sm_password16,
		{ "Password", "smb.sm.password", FT_BOOLEAN, 16,
		TFS(&tfs_sm_password), SECURITY_MODE_PASSWORD, "Encrypted or plaintext passwords?", HFILL }},

	{ &hf_smb_sm_mode,
		{ "Mode", "smb.sm.mode", FT_BOOLEAN, 8,
		TFS(&tfs_sm_mode), SECURITY_MODE_MODE, "User or Share security mode?", HFILL }},

	{ &hf_smb_sm_password,
		{ "Password", "smb.sm.password", FT_BOOLEAN, 8,
		TFS(&tfs_sm_password), SECURITY_MODE_PASSWORD, "Encrypted or plaintext passwords?", HFILL }},

	{ &hf_smb_sm_signatures,
		{ "Signatures", "smb.sm.signatures", FT_BOOLEAN, 8,
		TFS(&tfs_sm_signatures), SECURITY_MODE_SIGNATURES, "Are security signatures enabled?", HFILL }},

	{ &hf_smb_sm_sig_required,
		{ "Sig Req", "smb.sm.sig_required", FT_BOOLEAN, 8,
		TFS(&tfs_sm_sig_required), SECURITY_MODE_SIG_REQUIRED, "Are security signatures required?", HFILL }},

	{ &hf_smb_rm_read,
		{ "Read Raw", "smb.rm.read", FT_BOOLEAN, 16,
		TFS(&tfs_rm_read), RAWMODE_READ, "Is Read Raw supported?", HFILL }},

	{ &hf_smb_rm_write,
		{ "Write Raw", "smb.rm.write", FT_BOOLEAN, 16,
		TFS(&tfs_rm_write), RAWMODE_WRITE, "Is Write Raw supported?", HFILL }},

	{ &hf_smb_server_date_time,
		{ "Server Date and Time", "smb.server_date_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Current date and time at server", HFILL }},

	{ &hf_smb_server_smb_date,
		{ "Server Date", "smb.server_date_time.smb_date", FT_UINT16, BASE_HEX,
		NULL, 0, "Current date at server, SMB_DATE format", HFILL }},

	{ &hf_smb_server_smb_time,
		{ "Server Time", "smb.server_date_time.smb_time", FT_UINT16, BASE_HEX,
		NULL, 0, "Current time at server, SMB_TIME format", HFILL }},

	{ &hf_smb_server_cap_raw_mode,
		{ "Raw Mode", "smb.server.cap.raw_mode", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_raw_mode), SERVER_CAP_RAW_MODE, "Are Raw Read and Raw Write supported?", HFILL }},

	{ &hf_smb_server_cap_mpx_mode,
		{ "MPX Mode", "smb.server.cap.mpx_mode", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_mpx_mode), SERVER_CAP_MPX_MODE, "Are Read Mpx and Write Mpx supported?", HFILL }},

	{ &hf_smb_server_cap_unicode,
		{ "Unicode", "smb.server.cap.unicode", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_unicode), SERVER_CAP_UNICODE, "Are Unicode strings supported?", HFILL }},

	{ &hf_smb_server_cap_large_files,
		{ "Large Files", "smb.server.cap.large_files", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_large_files), SERVER_CAP_LARGE_FILES, "Are large files (>4GB) supported?", HFILL }},

	{ &hf_smb_server_cap_nt_smbs,
		{ "NT SMBs", "smb.server.cap.nt_smbs", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_nt_smbs), SERVER_CAP_NT_SMBS, "Are NT SMBs supported?", HFILL }},

	{ &hf_smb_server_cap_rpc_remote_apis,
		{ "RPC Remote APIs", "smb.server.cap.rpc_remote_apis", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_rpc_remote_apis), SERVER_CAP_RPC_REMOTE_APIS, "Are RPC Remote APIs supported?", HFILL }},

	{ &hf_smb_server_cap_nt_status,
		{ "NT Status Codes", "smb.server.cap.nt_status", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_nt_status), SERVER_CAP_STATUS32, "Are NT Status Codes supported?", HFILL }},

	{ &hf_smb_server_cap_level_ii_oplocks,
		{ "Level 2 Oplocks", "smb.server.cap.level_2_oplocks", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_level_ii_oplocks), SERVER_CAP_LEVEL_II_OPLOCKS, "Are Level 2 oplocks supported?", HFILL }},

	{ &hf_smb_server_cap_lock_and_read,
		{ "Lock and Read", "smb.server.cap.lock_and_read", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_lock_and_read), SERVER_CAP_LOCK_AND_READ, "Is Lock and Read supported?", HFILL }},

	{ &hf_smb_server_cap_nt_find,
		{ "NT Find", "smb.server.cap.nt_find", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_nt_find), SERVER_CAP_NT_FIND, "Is NT Find supported?", HFILL }},

	{ &hf_smb_server_cap_dfs,
		{ "Dfs", "smb.server.cap.dfs", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_dfs), SERVER_CAP_DFS, "Is Dfs supported?", HFILL }},

	{ &hf_smb_server_cap_infolevel_passthru,
		{ "Infolevel Passthru", "smb.server.cap.infolevel_passthru", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_infolevel_passthru), SERVER_CAP_INFOLEVEL_PASSTHRU, "Is NT information level request passthrough supported?", HFILL }},

	{ &hf_smb_server_cap_large_readx,
		{ "Large ReadX", "smb.server.cap.large_readx", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_large_readx), SERVER_CAP_LARGE_READX, "Is Large Read andX supported?", HFILL }},

	{ &hf_smb_server_cap_large_writex,
		{ "Large WriteX", "smb.server.cap.large_writex", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_large_writex), SERVER_CAP_LARGE_WRITEX, "Is Large Write andX supported?", HFILL }},

	{ &hf_smb_server_cap_unix,
		{ "UNIX", "smb.server.cap.unix", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_unix), SERVER_CAP_UNIX , "Are UNIX extensions supported?", HFILL }},

	{ &hf_smb_server_cap_reserved,
		{ "Reserved", "smb.server.cap.reserved", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_reserved), SERVER_CAP_RESERVED, "RESERVED", HFILL }},

	{ &hf_smb_server_cap_bulk_transfer,
		{ "Bulk Transfer", "smb.server.cap.bulk_transfer", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_bulk_transfer), SERVER_CAP_BULK_TRANSFER, "Are Bulk Read and Bulk Write supported?", HFILL }},

	{ &hf_smb_server_cap_compressed_data,
		{ "Compressed Data", "smb.server.cap.compressed_data", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_compressed_data), SERVER_CAP_COMPRESSED_DATA, "Is compressed data transfer supported?", HFILL }},

	{ &hf_smb_server_cap_extended_security,
		{ "Extended Security", "smb.server.cap.extended_security", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_extended_security), SERVER_CAP_EXTENDED_SECURITY, "Are Extended security exchanges supported?", HFILL }},

	{ &hf_smb_system_time,
		{ "System Time", "smb.system.time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "System Time", HFILL }},

	{ &hf_smb_unknown,
		{ "Unknown Data", "smb.unknown", FT_BYTES, BASE_HEX,
		NULL, 0, "Unknown Data. Should be implemented by someone", HFILL }},

	{ &hf_smb_dir_name,
		{ "Directory", "smb.dir_name", FT_STRING, BASE_NONE,
		NULL, 0, "SMB Directory Name", HFILL }},

	{ &hf_smb_echo_count,
		{ "Echo Count", "smb.echo.count", FT_UINT16, BASE_DEC,
		NULL, 0, "Number of times to echo data back", HFILL }},

	{ &hf_smb_echo_data,
		{ "Echo Data", "smb.echo.data", FT_BYTES, BASE_HEX,
		NULL, 0, "Data for SMB Echo Request/Response", HFILL }},

	{ &hf_smb_echo_seq_num,
		{ "Echo Seq Num", "smb.echo.seq_num", FT_UINT16, BASE_DEC,
		NULL, 0, "Sequence number for this echo response", HFILL }},

	{ &hf_smb_max_buf_size,
		{ "Max Buffer", "smb.max_buf", FT_UINT16, BASE_DEC,
		NULL, 0, "Max client buffer size", HFILL }},

	{ &hf_smb_path,
		{ "Path", "smb.path", FT_STRING, BASE_NONE,
		NULL, 0, "Path. Server name and share name", HFILL }},

	{ &hf_smb_service,
		{ "Service", "smb.service", FT_STRING, BASE_NONE,
		NULL, 0, "Service name", HFILL }},

	{ &hf_smb_password,
		{ "Password", "smb.password", FT_BYTES, BASE_NONE,
		NULL, 0, "Password", HFILL }},

	{ &hf_smb_ansi_password,
		{ "ANSI Password", "smb.ansi_password", FT_BYTES, BASE_NONE,
		NULL, 0, "ANSI Password", HFILL }},

	{ &hf_smb_unicode_password,
		{ "Unicode Password", "smb.unicode_password", FT_BYTES, BASE_NONE,
		NULL, 0, "Unicode Password", HFILL }},

	{ &hf_smb_move_flags_file,
		{ "Must be file", "smb.move.flags.file", FT_BOOLEAN, 16,
		TFS(&tfs_mf_file), 0x0001, "Must target be a file?", HFILL }},

	{ &hf_smb_move_flags_dir,
		{ "Must be directory", "smb.move.flags.dir", FT_BOOLEAN, 16,
		TFS(&tfs_mf_dir), 0x0002, "Must target be a directory?", HFILL }},

	{ &hf_smb_move_flags_verify,
		{ "Verify writes", "smb.move.flags.verify", FT_BOOLEAN, 16,
		TFS(&tfs_mf_verify), 0x0010, "Verify all writes?", HFILL }},

	{ &hf_smb_move_files_moved,
		{ "Files Moved", "smb.move.files_moved", FT_UINT16, BASE_DEC,
		NULL, 0, "Number of files moved", HFILL }},

	{ &hf_smb_count,
		{ "Count", "smb.count", FT_UINT32, BASE_DEC,
		NULL, 0, "Count number of items/bytes", HFILL }},

	{ &hf_smb_file_name,
		{ "File Name", "smb.file", FT_STRING, BASE_NONE,
		NULL, 0, "File Name", HFILL }},

	{ &hf_smb_open_function_create,
		{ "Create", "smb.open.function.create", FT_BOOLEAN, 16,
		TFS(&tfs_of_create), 0x0010, "Create file if it doesn't exist?", HFILL }},

	{ &hf_smb_open_function_open,
		{ "Open", "smb.open.function.open", FT_UINT16, BASE_DEC,
		VALS(of_open), 0x0003, "Action to be taken on open if file exists", HFILL }},

	{ &hf_smb_fid,
		{ "FID", "smb.fid", FT_UINT16, BASE_HEX,
		NULL, 0, "FID: File ID", HFILL }},

	{ &hf_smb_file_attr_read_only_16bit,
		{ "Read Only", "smb.file.attribute.read_only", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_read_only), FILE_ATTRIBUTE_READ_ONLY, "READ ONLY file attribute", HFILL }},

	{ &hf_smb_file_attr_read_only_8bit,
		{ "Read Only", "smb.file.attribute.read_only", FT_BOOLEAN, 8,
		TFS(&tfs_file_attribute_read_only), FILE_ATTRIBUTE_READ_ONLY, "READ ONLY file attribute", HFILL }},

	{ &hf_smb_file_attr_hidden_16bit,
		{ "Hidden", "smb.file.attribute.hidden", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_hidden), FILE_ATTRIBUTE_HIDDEN, "HIDDEN file attribute", HFILL }},

	{ &hf_smb_file_attr_hidden_8bit,
		{ "Hidden", "smb.file.attribute.hidden", FT_BOOLEAN, 8,
		TFS(&tfs_file_attribute_hidden), FILE_ATTRIBUTE_HIDDEN, "HIDDEN file attribute", HFILL }},

	{ &hf_smb_file_attr_system_16bit,
		{ "System", "smb.file.attribute.system", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_system), FILE_ATTRIBUTE_SYSTEM, "SYSTEM file attribute", HFILL }},

	{ &hf_smb_file_attr_system_8bit,
		{ "System", "smb.file.attribute.system", FT_BOOLEAN, 8,
		TFS(&tfs_file_attribute_system), FILE_ATTRIBUTE_SYSTEM, "SYSTEM file attribute", HFILL }},

	{ &hf_smb_file_attr_volume_16bit,
		{ "Volume ID", "smb.file.attribute.volume", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_volume), FILE_ATTRIBUTE_VOLUME, "VOLUME file attribute", HFILL }},

	{ &hf_smb_file_attr_volume_8bit,
		{ "Volume ID", "smb.file.attribute.volume", FT_BOOLEAN, 8,
		TFS(&tfs_file_attribute_volume), FILE_ATTRIBUTE_VOLUME, "VOLUME ID file attribute", HFILL }},

	{ &hf_smb_file_attr_directory_16bit,
		{ "Directory", "smb.file.attribute.directory", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_directory), FILE_ATTRIBUTE_DIRECTORY, "DIRECTORY file attribute", HFILL }},

	{ &hf_smb_file_attr_directory_8bit,
		{ "Directory", "smb.file.attribute.directory", FT_BOOLEAN, 8,
		TFS(&tfs_file_attribute_directory), FILE_ATTRIBUTE_DIRECTORY, "DIRECTORY file attribute", HFILL }},

	{ &hf_smb_file_attr_archive_16bit,
		{ "Archive", "smb.file.attribute.archive", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_archive), FILE_ATTRIBUTE_ARCHIVE, "ARCHIVE file attribute", HFILL }},

	{ &hf_smb_file_attr_archive_8bit,
		{ "Archive", "smb.file.attribute.archive", FT_BOOLEAN, 8,
		TFS(&tfs_file_attribute_archive), FILE_ATTRIBUTE_ARCHIVE, "ARCHIVE file attribute", HFILL }},

	{ &hf_smb_file_attr_device,
		{ "Device", "smb.file.attribute.device", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_device), FILE_ATTRIBUTE_DEVICE, "Is this file a device?", HFILL }},

	{ &hf_smb_file_attr_normal,
		{ "Normal", "smb.file.attribute.normal", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_normal), FILE_ATTRIBUTE_NORMAL, "Is this a normal file?", HFILL }},

	{ &hf_smb_file_attr_temporary,
		{ "Temporary", "smb.file.attribute.temporary", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_temporary), FILE_ATTRIBUTE_TEMPORARY, "Is this a temporary file?", HFILL }},

	{ &hf_smb_file_attr_sparse,
		{ "Sparse", "smb.file.attribute.sparse", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_sparse), FILE_ATTRIBUTE_SPARSE, "Is this a sparse file?", HFILL }},

	{ &hf_smb_file_attr_reparse,
		{ "Reparse Point", "smb.file.attribute.reparse", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_reparse), FILE_ATTRIBUTE_REPARSE, "Does this file have an associated reparse point?", HFILL }},

	{ &hf_smb_file_attr_compressed,
		{ "Compressed", "smb.file.attribute.compressed", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_compressed), FILE_ATTRIBUTE_COMPRESSED, "Is this file compressed?", HFILL }},

	{ &hf_smb_file_attr_offline,
		{ "Offline", "smb.file.attribute.offline", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_offline), FILE_ATTRIBUTE_OFFLINE, "Is this file offline?", HFILL }},

	{ &hf_smb_file_attr_not_content_indexed,
		{ "Content Indexed", "smb.file.attribute.not_content_indexed", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_not_content_indexed), FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, "May this file be indexed by the content indexing service", HFILL }},

	{ &hf_smb_file_attr_encrypted,
		{ "Encrypted", "smb.file.attribute.encrypted", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_encrypted), FILE_ATTRIBUTE_ENCRYPTED, "Is this file encrypted?", HFILL }},

	{ &hf_smb_file_size,
		{ "File Size", "smb.file.size", FT_UINT32, BASE_DEC,
		NULL, 0, "File Size", HFILL }},

	{ &hf_smb_search_attribute_read_only,
		{ "Read Only", "smb.search.attribute.read_only", FT_BOOLEAN, 16,
		TFS(&tfs_search_attribute_read_only), FILE_ATTRIBUTE_READ_ONLY, "READ ONLY search attribute", HFILL }},

	{ &hf_smb_search_attribute_hidden,
		{ "Hidden", "smb.search.attribute.hidden", FT_BOOLEAN, 16,
		TFS(&tfs_search_attribute_hidden), FILE_ATTRIBUTE_HIDDEN, "HIDDEN search attribute", HFILL }},

	{ &hf_smb_search_attribute_system,
		{ "System", "smb.search.attribute.system", FT_BOOLEAN, 16,
		TFS(&tfs_search_attribute_system), FILE_ATTRIBUTE_SYSTEM, "SYSTEM search attribute", HFILL }},

	{ &hf_smb_search_attribute_volume,
		{ "Volume ID", "smb.search.attribute.volume", FT_BOOLEAN, 16,
		TFS(&tfs_search_attribute_volume), FILE_ATTRIBUTE_VOLUME, "VOLUME ID search attribute", HFILL }},

	{ &hf_smb_search_attribute_directory,
		{ "Directory", "smb.search.attribute.directory", FT_BOOLEAN, 16,
		TFS(&tfs_search_attribute_directory), FILE_ATTRIBUTE_DIRECTORY, "DIRECTORY search attribute", HFILL }},

	{ &hf_smb_search_attribute_archive,
		{ "Archive", "smb.search.attribute.archive", FT_BOOLEAN, 16,
		TFS(&tfs_search_attribute_archive), FILE_ATTRIBUTE_ARCHIVE, "ARCHIVE search attribute", HFILL }},

	{ &hf_smb_access_mode,
		{ "Access Mode", "smb.access.mode", FT_UINT16, BASE_DEC,
		VALS(da_access_vals), 0x0007, "Access Mode", HFILL }},

	{ &hf_smb_access_sharing,
		{ "Sharing Mode", "smb.access.sharing", FT_UINT16, BASE_DEC,
		VALS(da_sharing_vals), 0x0070, "Sharing Mode", HFILL }},

	{ &hf_smb_access_locality,
		{ "Locality", "smb.access.locality", FT_UINT16, BASE_DEC,
		VALS(da_locality_vals), 0x0700, "Locality of reference", HFILL }},

	{ &hf_smb_access_caching,
		{ "Caching", "smb.access.caching", FT_BOOLEAN, 16,
		TFS(&tfs_da_caching), 0x1000, "Caching mode?", HFILL }},

	{ &hf_smb_access_writetru,
		{ "Writethrough", "smb.access.writethrough", FT_BOOLEAN, 16,
		TFS(&tfs_da_writetru), 0x4000, "Writethrough mode?", HFILL }},

	{ &hf_smb_create_time,
		{ "Created", "smb.create.time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Creation Time", HFILL }},

	{ &hf_smb_create_dos_date,
		{ "Create Date", "smb.create.smb.date", FT_UINT16, BASE_HEX,
		NULL, 0, "Create Date, SMB_DATE format", HFILL }},

	{ &hf_smb_create_dos_time,
		{ "Create Time", "smb.create.smb.time", FT_UINT16, BASE_HEX,
		NULL, 0, "Create Time, SMB_TIME format", HFILL }},

	{ &hf_smb_last_write_time,
		{ "Last Write", "smb.last_write.time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Time this file was last written to", HFILL }},

	{ &hf_smb_last_write_dos_date,
		{ "Last Write Date", "smb.last_write.smb.date", FT_UINT16, BASE_HEX,
		NULL, 0, "Last Write Date, SMB_DATE format", HFILL }},

	{ &hf_smb_last_write_dos_time,
		{ "Last Write Time", "smb.last_write.smb.time", FT_UINT16, BASE_HEX,
		NULL, 0, "Last Write Time, SMB_TIME format", HFILL }},

	{ &hf_smb_old_file_name,
		{ "Old File Name", "smb.file", FT_STRING, BASE_NONE,
		NULL, 0, "Old File Name (When renaming a file)", HFILL }},

	{ &hf_smb_offset,
		{ "Offset", "smb.offset", FT_UINT32, BASE_DEC,
		NULL, 0, "Offset in file", HFILL }},

	{ &hf_smb_remaining,
		{ "Remaining", "smb.remaining", FT_UINT32, BASE_DEC,
		NULL, 0, "Remaining number of bytes", HFILL }},

	{ &hf_smb_padding,
		{ "Padding", "smb.padding", FT_BYTES, BASE_HEX,
		NULL, 0, "Padding or unknown data", HFILL }},

	{ &hf_smb_file_data,
		{ "File Data", "smb.file.data", FT_BYTES, BASE_HEX,
		NULL, 0, "Data read/written to the file", HFILL }},

	{ &hf_smb_total_data_len,
		{ "Total Data Length", "smb.total_data_len", FT_UINT16, BASE_DEC,
		NULL, 0, "Total length of data", HFILL }},

	{ &hf_smb_data_len,
		{ "Data Length", "smb.data_len", FT_UINT16, BASE_DEC,
		NULL, 0, "Length of data", HFILL }},

	{ &hf_smb_seek_mode,
		{ "Seek Mode", "smb.seek_mode", FT_UINT16, BASE_DEC,
		VALS(seek_mode_vals), 0, "Seek Mode, what type of seek", HFILL }},

	{ &hf_smb_access_time,
		{ "Last Access", "smb.access.time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Last Access Time", HFILL }},

	{ &hf_smb_access_dos_date,
		{ "Last Access Date", "smb.access.smb.date", FT_UINT16, BASE_HEX,
		NULL, 0, "Last Access Date, SMB_DATE format", HFILL }},

	{ &hf_smb_access_dos_time,
		{ "Last Access Time", "smb.access.smb.time", FT_UINT16, BASE_HEX,
		NULL, 0, "Last Access Time, SMB_TIME format", HFILL }},

	{ &hf_smb_data_size,
		{ "Data Size", "smb.data_size", FT_UINT32, BASE_DEC,
		NULL, 0, "Data Size", HFILL }},

	{ &hf_smb_alloc_size,
		{ "Allocation Size", "smb.alloc_size", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of bytes to reserve on create or truncate", HFILL }},

	{ &hf_smb_max_count,
		{ "Max Count", "smb.maxcount", FT_UINT16, BASE_DEC,
		NULL, 0, "Maximum Count", HFILL }},

	{ &hf_smb_min_count,
		{ "Min Count", "smb.mincount", FT_UINT16, BASE_DEC,
		NULL, 0, "Minimum Count", HFILL }},

	{ &hf_smb_timeout,
		{ "Timeout", "smb.timeout", FT_UINT32, BASE_DEC,
		NULL, 0, "Timeout in miliseconds", HFILL }},

	{ &hf_smb_high_offset,
		{ "High Offset", "smb.offset_high", FT_UINT32, BASE_DEC,
		NULL, 0, "High 32 Bits Of File Offset", HFILL }},

	{ &hf_smb_units,
		{ "Total Units", "smb.units", FT_UINT16, BASE_DEC,
		NULL, 0, "Total number of units at server", HFILL }},

	{ &hf_smb_bpu,
		{ "Blocks Per Unit", "smb.bpu", FT_UINT16, BASE_DEC,
		NULL, 0, "Blocks per unit at server", HFILL }},

	{ &hf_smb_blocksize,
		{ "Block Size", "smb.blocksize", FT_UINT16, BASE_DEC,
		NULL, 0, "Block size (in bytes) at server", HFILL }},

	{ &hf_smb_freeunits,
		{ "Free Units", "smb.free_units", FT_UINT16, BASE_DEC,
		NULL, 0, "Number of free units at server", HFILL }},

	{ &hf_smb_data_offset,
		{ "Data Offset", "smb.data_offset", FT_UINT16, BASE_DEC,
		NULL, 0, "Data Offset", HFILL }},

	{ &hf_smb_dcm,
		{ "Data Compaction Mode", "smb.dcm", FT_UINT16, BASE_DEC,
		NULL, 0, "Data Compaction Mode", HFILL }},

	{ &hf_smb_request_mask,
		{ "Request Mask", "smb.request.mask", FT_UINT32, BASE_HEX,
		NULL, 0, "Connectionless mode mask", HFILL }},

	{ &hf_smb_response_mask,
		{ "Response Mask", "smb.response.mask", FT_UINT32, BASE_HEX,
		NULL, 0, "Connectionless mode mask", HFILL }},

	{ &hf_smb_sid,
		{ "SID", "smb.sid", FT_UINT16, BASE_HEX,
		NULL, 0, "SID: Search ID, handle for find operations", HFILL }},

	{ &hf_smb_write_mode_write_through,
		{ "Write Through", "smb.write.mode.write_through", FT_BOOLEAN, 16,
		TFS(&tfs_write_mode_write_through), 0x0001, "Write through mode requested?", HFILL }},

	{ &hf_smb_write_mode_return_remaining,
		{ "Return Remaining", "smb.write.mode.return_remaining", FT_BOOLEAN, 16,
		TFS(&tfs_write_mode_return_remaining), 0x0002, "Return remaining data responses?", HFILL }},

	{ &hf_smb_write_mode_raw,
		{ "Write Raw", "smb.write.mode.raw", FT_BOOLEAN, 16,
		TFS(&tfs_write_mode_raw), 0x0004, "Use WriteRawNamedPipe?", HFILL }},

	{ &hf_smb_write_mode_message_start,
		{ "Message Start", "smb.write.mode.message_start", FT_BOOLEAN, 16,
		TFS(&tfs_write_mode_message_start), 0x0008, "Is this the start of a message?", HFILL }},

	{ &hf_smb_write_mode_connectionless,
		{ "Connectionless", "smb.write.mode.connectionless", FT_BOOLEAN, 16,
		TFS(&tfs_write_mode_connectionless), 0x0080, "Connectionless mode requested?", HFILL }},

	{ &hf_smb_resume_key_len,
		{ "Resume Key Length", "smb.resume.key_len", FT_UINT16, BASE_DEC,
		NULL, 0, "Resume Key length", HFILL }},

	{ &hf_smb_resume_server_cookie,
		{ "Server Cookie", "smb.resume.server.cookie", FT_BYTES, BASE_HEX,
		NULL, 0, "Cookie, must not be modified by the client", HFILL }},

	{ &hf_smb_resume_client_cookie,
		{ "Client Cookie", "smb.resume.client.cookie", FT_BYTES, BASE_HEX,
		NULL, 0, "Cookie, must not be modified by the server", HFILL }},

	{ &hf_smb_andxoffset,
		{ "AndXOffset", "smb.andxoffset", FT_UINT16, BASE_DEC,
		NULL, 0, "Offset to next command in this SMB packet", HFILL }},

	{ &hf_smb_lock_type_large,
		{ "Large Files", "smb.lock.type.large", FT_BOOLEAN, 8,
		TFS(&tfs_lock_type_large), 0x10, "Large file locking requested?", HFILL }},

	{ &hf_smb_lock_type_cancel,
		{ "Cancel", "smb.lock.type.cancel", FT_BOOLEAN, 8,
		TFS(&tfs_lock_type_cancel), 0x08, "Cancel outstanding lock requests?", HFILL }},

	{ &hf_smb_lock_type_change,
		{ "Change", "smb.lock.type.change", FT_BOOLEAN, 8,
		TFS(&tfs_lock_type_change), 0x04, "Change type of lock?", HFILL }},

	{ &hf_smb_lock_type_oplock,
		{ "Oplock Break", "smb.lock.type.oplock_release", FT_BOOLEAN, 8,
		TFS(&tfs_lock_type_oplock), 0x02, "Is this a notification of, or a response to, an oplock break?", HFILL }},

	{ &hf_smb_lock_type_shared,
		{ "Shared", "smb.lock.type.shared", FT_BOOLEAN, 8,
		TFS(&tfs_lock_type_shared), 0x01, "Shared or exclusive lock requested?", HFILL }},

	{ &hf_smb_locking_ol,
		{ "Oplock Level", "smb.locking.oplock.level", FT_UINT8, BASE_DEC,
		VALS(locking_ol_vals), 0, "Level of existing oplock at client (if any)", HFILL }},

	{ &hf_smb_number_of_locks,
		{ "Number of Locks", "smb.locking.num_locks", FT_UINT16, BASE_DEC,
		NULL, 0, "Number of lock requests in this request", HFILL }},

	{ &hf_smb_number_of_unlocks,
		{ "Number of Unlocks", "smb.locking.num_unlocks", FT_UINT16, BASE_DEC,
		NULL, 0, "Number of unlock requests in this request", HFILL }},

	{ &hf_smb_lock_long_length,
		{ "Length", "smb.lock.length", FT_UINT64, BASE_DEC,
		NULL, 0, "Length of lock/unlock region", HFILL }},

	{ &hf_smb_lock_long_offset,
		{ "Offset", "smb.lock.offset", FT_UINT64, BASE_DEC,
		NULL, 0, "Offset in the file of lock/unlock region", HFILL }},

	{ &hf_smb_file_type,
		{ "File Type", "smb.file_type", FT_UINT16, BASE_DEC,
		VALS(filetype_vals), 0, "Type of file", HFILL }},

	{ &hf_smb_ipc_state_nonblocking,
		{ "Nonblocking", "smb.ipc_state.nonblocking", FT_BOOLEAN, 16,
		TFS(&tfs_ipc_state_nonblocking), 0x8000, "Is I/O to this pipe nonblocking?", HFILL }},

	{ &hf_smb_ipc_state_endpoint,
		{ "Endpoint", "smb.ipc_state.endpoint", FT_UINT16, BASE_DEC,
		VALS(ipc_state_endpoint_vals), 0x4000, "Which end of the pipe this is", HFILL }},

	{ &hf_smb_ipc_state_pipe_type,
		{ "Pipe Type", "smb.ipc_state.pipe_type", FT_UINT16, BASE_DEC,
		VALS(ipc_state_pipe_type_vals), 0x0c00, "What type of pipe this is", HFILL }},

	{ &hf_smb_ipc_state_read_mode,
		{ "Read Mode", "smb.ipc_state.read_mode", FT_UINT16, BASE_DEC,
		VALS(ipc_state_read_mode_vals), 0x0300, "How this pipe should be read", HFILL }},

	{ &hf_smb_ipc_state_icount,
		{ "Icount", "smb.ipc_state.icount", FT_UINT16, BASE_DEC,
		NULL, 0x00FF, "Count to control pipe instancing", HFILL }},

	{ &hf_smb_server_fid,
		{ "Server FID", "smb.server_fid", FT_UINT32, BASE_HEX,
		NULL, 0, "Server unique File ID", HFILL }},

	{ &hf_smb_open_flags_add_info,
		{ "Additional Info", "smb.open.flags.add_info", FT_BOOLEAN, 16,
		TFS(&tfs_open_flags_add_info), 0x0001, "Additional Information Requested?", HFILL }},

	{ &hf_smb_open_flags_ex_oplock,
		{ "Exclusive Oplock", "smb.open.flags.ex_oplock", FT_BOOLEAN, 16,
		TFS(&tfs_open_flags_ex_oplock), 0x0002, "Exclusive Oplock Requested?", HFILL }},

	{ &hf_smb_open_flags_batch_oplock,
		{ "Batch Oplock", "smb.open.flags.batch_oplock", FT_BOOLEAN, 16,
		TFS(&tfs_open_flags_batch_oplock), 0x0004, "Batch Oplock Requested?", HFILL }},

	{ &hf_smb_open_flags_ealen,
		{ "Total EA Len", "smb.open.flags.ealen", FT_BOOLEAN, 16,
		TFS(&tfs_open_flags_ealen), 0x0008, "Total EA Len Requested?", HFILL }},

	{ &hf_smb_open_action_open,
		{ "Open Action", "smb.open.action.open", FT_UINT16, BASE_DEC,
		VALS(oa_open_vals), 0x0003, "Open Action, how the file was opened", HFILL }},

	{ &hf_smb_open_action_lock,
		{ "Exclusive Open", "smb.open.action.lock", FT_BOOLEAN, 16,
		TFS(&tfs_oa_lock), 0x8000, "Is this file opened by another user?", HFILL }},

	{ &hf_smb_vc_num,
		{ "VC Number", "smb.vc", FT_UINT16, BASE_DEC,
		NULL, 0, "VC Number", HFILL }},

	{ &hf_smb_password_len,
		{ "Password Length", "smb.pwlen", FT_UINT16, BASE_DEC,
		NULL, 0, "Length of password", HFILL }},

	{ &hf_smb_ansi_password_len,
		{ "ANSI Password Length", "smb.ansi_pwlen", FT_UINT16, BASE_DEC,
		NULL, 0, "Length of ANSI password", HFILL }},

	{ &hf_smb_unicode_password_len,
		{ "Unicode Password Length", "smb.unicode_pwlen", FT_UINT16, BASE_DEC,
		NULL, 0, "Length of Unicode password", HFILL }},

	{ &hf_smb_account,
		{ "Account", "smb.account", FT_STRING, BASE_NONE,
		NULL, 0, "Account, username", HFILL }},

	{ &hf_smb_os,
		{ "Native OS", "smb.native_os", FT_STRING, BASE_NONE,
		NULL, 0, "Which OS we are running", HFILL }},

	{ &hf_smb_lanman,
		{ "Native LAN Manager", "smb.native_lanman", FT_STRING, BASE_NONE,
		NULL, 0, "Which LANMAN protocol we are running", HFILL }},

	{ &hf_smb_setup_action_guest,
		{ "Guest", "smb.setup.action.guest", FT_BOOLEAN, 16,
		TFS(&tfs_setup_action_guest), 0x0001, "Client logged in as GUEST?", HFILL }},

	{ &hf_smb_fs,
		{ "Native File System", "smb.native_fs", FT_STRING, BASE_NONE,
		NULL, 0, "Native File System", HFILL }},

	{ &hf_smb_connect_flags_dtid,
		{ "Disconnect TID", "smb.connect.flags.dtid", FT_BOOLEAN, 16,
		TFS(&tfs_disconnect_tid), 0x0001, "Disconnect TID?", HFILL }},

	{ &hf_smb_connect_support_search,
		{ "Search Bits", "smb.connect.support.search", FT_BOOLEAN, 16,
		TFS(&tfs_connect_support_search), 0x0001, "Exclusive Search Bits supported?", HFILL }},

	{ &hf_smb_connect_support_in_dfs,
		{ "In Dfs", "smb.connect.support.dfs", FT_BOOLEAN, 16,
		TFS(&tfs_connect_support_in_dfs), 0x0002, "Is this in a Dfs tree?", HFILL }},

	{ &hf_smb_max_setup_count,
		{ "Max Setup Count", "smb.msc", FT_UINT8, BASE_DEC,
		NULL, 0, "Maximum number of setup words to return", HFILL }},

	{ &hf_smb_total_param_count,
		{ "Total Parameter Count", "smb.tpc", FT_UINT32, BASE_DEC,
		NULL, 0, "Total number of parameter bytes", HFILL }},

	{ &hf_smb_total_data_count,
		{ "Total Data Count", "smb.tdc", FT_UINT32, BASE_DEC,
		NULL, 0, "Total number of data bytes", HFILL }},

	{ &hf_smb_max_param_count,
		{ "Max Parameter Count", "smb.mpc", FT_UINT32, BASE_DEC,
		NULL, 0, "Maximum number of parameter bytes to return", HFILL }},

	{ &hf_smb_max_data_count,
		{ "Max Data Count", "smb.mdc", FT_UINT32, BASE_DEC,
		NULL, 0, "Maximum number of data bytes to return", HFILL }},

	{ &hf_smb_param_disp16,
		{ "Parameter Displacement", "smb.pd", FT_UINT16, BASE_DEC,
		NULL, 0, "Displacement of these parameter bytes", HFILL }},

	{ &hf_smb_param_count16,
		{ "Parameter Count", "smb.pc", FT_UINT16, BASE_DEC,
		NULL, 0, "Number of parameter bytes in this buffer", HFILL }},

	{ &hf_smb_param_offset16,
		{ "Parameter Offset", "smb.po", FT_UINT16, BASE_DEC,
		NULL, 0, "Offset (from header start) to parameters", HFILL }},

	{ &hf_smb_param_disp32,
		{ "Parameter Displacement", "smb.pd", FT_UINT32, BASE_DEC,
		NULL, 0, "Displacement of these parameter bytes", HFILL }},

	{ &hf_smb_param_count32,
		{ "Parameter Count", "smb.pc", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of parameter bytes in this buffer", HFILL }},

	{ &hf_smb_param_offset32,
		{ "Parameter Offset", "smb.po", FT_UINT32, BASE_DEC,
		NULL, 0, "Offset (from header start) to parameters", HFILL }},

	{ &hf_smb_data_count16,
		{ "Data Count", "smb.dc", FT_UINT16, BASE_DEC,
		NULL, 0, "Number of data bytes in this buffer", HFILL }},

	{ &hf_smb_data_disp16,
		{ "Data Displacement", "smb.data_disp", FT_UINT16, BASE_DEC,
		NULL, 0, "Data Displacement", HFILL }},

	{ &hf_smb_data_offset16,
		{ "Data Offset", "smb.data_offset", FT_UINT16, BASE_DEC,
		NULL, 0, "Data Offset", HFILL }},

	{ &hf_smb_data_count32,
		{ "Data Count", "smb.dc", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of data bytes in this buffer", HFILL }},

	{ &hf_smb_data_disp32,
		{ "Data Displacement", "smb.data_disp", FT_UINT32, BASE_DEC,
		NULL, 0, "Data Displacement", HFILL }},

	{ &hf_smb_data_offset32,
		{ "Data Offset", "smb.data_offset", FT_UINT32, BASE_DEC,
		NULL, 0, "Data Offset", HFILL }},

	{ &hf_smb_setup_count,
		{ "Setup Count", "smb.sc", FT_UINT8, BASE_DEC,
		NULL, 0, "Number of setup words in this buffer", HFILL }},

	{ &hf_smb_nt_trans_subcmd,
		{ "Function", "smb.nt.function", FT_UINT16, BASE_DEC,
		VALS(nt_cmd_vals), 0, "Function for NT Transaction", HFILL }},

	{ &hf_smb_nt_ioctl_function_code,
		{ "Function", "smb.nt.ioctl.function", FT_UINT32, BASE_HEX,
		NULL, 0, "NT IOCTL function code", HFILL }},

	{ &hf_smb_nt_ioctl_isfsctl,
		{ "IsFSctl", "smb.nt.ioctl.isfsctl", FT_UINT8, BASE_DEC,
		VALS(nt_ioctl_isfsctl_vals), 0, "Is this a device IOCTL (FALSE) or FS Control (TRUE)", HFILL }},

	{ &hf_smb_nt_ioctl_flags_root_handle,
		{ "Root Handle", "smb.nt.ioctl.flags.root_handle", FT_BOOLEAN, 8,
		TFS(&tfs_nt_ioctl_flags_root_handle), NT_IOCTL_FLAGS_ROOT_HANDLE, "Apply to this share or root Dfs share", HFILL }},

	{ &hf_smb_nt_ioctl_data,
		{ "IOCTL Data", "smb.nt.ioctl.data", FT_BYTES, BASE_HEX,
		NULL, 0, "Data for the IOCTL call", HFILL }},

	{ &hf_smb_nt_notify_action,
		{ "Action", "smb.nt.notify.action", FT_UINT32, BASE_DEC,
		VALS(nt_notify_action_vals), 0, "Which action caused this notify response", HFILL }},

	{ &hf_smb_nt_notify_watch_tree,
		{ "Watch Tree", "smb.nt.notify.watch_tree", FT_UINT8, BASE_DEC,
		VALS(watch_tree_vals), 0, "Should Notify watch subdirectories also?", HFILL }},

	{ &hf_smb_nt_notify_stream_write,
		{ "Stream Write", "smb.nt.notify.stream_write", FT_BOOLEAN, 32,
		TFS(&tfs_nt_notify_stream_write), NT_NOTIFY_STREAM_WRITE, "Notify on stream write?", HFILL }},

	{ &hf_smb_nt_notify_stream_size,
		{ "Stream Size Change", "smb.nt.notify.stream_size", FT_BOOLEAN, 32,
		TFS(&tfs_nt_notify_stream_size), NT_NOTIFY_STREAM_SIZE, "Notify on changes of stream size", HFILL }},

	{ &hf_smb_nt_notify_stream_name,
		{ "Stream Name Change", "smb.nt.notify.stream_name", FT_BOOLEAN, 32,
		TFS(&tfs_nt_notify_stream_name), NT_NOTIFY_STREAM_NAME, "Notify on changes to stream name?", HFILL }},

	{ &hf_smb_nt_notify_security,
		{ "Security Change", "smb.nt.notify.security", FT_BOOLEAN, 32,
		TFS(&tfs_nt_notify_security), NT_NOTIFY_SECURITY, "Notify on changes to security settings", HFILL }},

	{ &hf_smb_nt_notify_ea,
		{ "EA Change", "smb.nt.notify.ea", FT_BOOLEAN, 32,
		TFS(&tfs_nt_notify_ea), NT_NOTIFY_EA, "Notify on changes to Extended Attributes", HFILL }},

	{ &hf_smb_nt_notify_creation,
		{ "Created Change", "smb.nt.notify.creation", FT_BOOLEAN, 32,
		TFS(&tfs_nt_notify_creation), NT_NOTIFY_CREATION, "Notify on changes to creation time", HFILL }},

	{ &hf_smb_nt_notify_last_access,
		{ "Last Access Change", "smb.nt.notify.last_access", FT_BOOLEAN, 32,
		TFS(&tfs_nt_notify_last_access), NT_NOTIFY_LAST_ACCESS, "Notify on changes to last access", HFILL }},

	{ &hf_smb_nt_notify_last_write,
		{ "Last Write Change", "smb.nt.notify.last_write", FT_BOOLEAN, 32,
		TFS(&tfs_nt_notify_last_write), NT_NOTIFY_LAST_WRITE, "Notify on changes to last write", HFILL }},

	{ &hf_smb_nt_notify_size,
		{ "Size Change", "smb.nt.notify.size", FT_BOOLEAN, 32,
		TFS(&tfs_nt_notify_size), NT_NOTIFY_SIZE, "Notify on changes to size", HFILL }},

	{ &hf_smb_nt_notify_attributes,
		{ "Attribute Change", "smb.nt.notify.attributes", FT_BOOLEAN, 32,
		TFS(&tfs_nt_notify_attributes), NT_NOTIFY_ATTRIBUTES, "Notify on changes to attributes", HFILL }},

	{ &hf_smb_nt_notify_dir_name,
		{ "Directory Name Change", "smb.nt.notify.dir_name", FT_BOOLEAN, 32,
		TFS(&tfs_nt_notify_dir_name), NT_NOTIFY_DIR_NAME, "Notify on changes to directory name", HFILL }},

	{ &hf_smb_nt_notify_file_name,
		{ "File Name Change", "smb.nt.notify.file_name", FT_BOOLEAN, 32,
		TFS(&tfs_nt_notify_file_name), NT_NOTIFY_FILE_NAME, "Notify on changes to file name", HFILL }},

	{ &hf_smb_root_dir_fid,
		{ "Root FID", "smb.rfid", FT_UINT32, BASE_HEX,
		NULL, 0, "Open is relative to this FID (if nonzero)", HFILL }},

	{ &hf_smb_alloc_size64,
		{ "Allocation Size", "smb.alloc_size", FT_UINT64, BASE_DEC,
		NULL, 0, "Number of bytes to reserve on create or truncate", HFILL }},

	{ &hf_smb_nt_create_disposition,
		{ "Disposition", "smb.create.disposition", FT_UINT32, BASE_DEC,
		VALS(create_disposition_vals), 0, "Create disposition, what to do if the file does/does not exist", HFILL }},

	{ &hf_smb_sd_length,
		{ "SD Length", "smb.sd.length", FT_UINT32, BASE_DEC,
		NULL, 0, "Total length of security descriptor", HFILL }},

	{ &hf_smb_ea_length,
		{ "EA Length", "smb.ea.length", FT_UINT32, BASE_DEC,
		NULL, 0, "Total EA length for opened file", HFILL }},

	{ &hf_smb_file_name_len,
		{ "File Name Len", "smb.file_name_len", FT_UINT32, BASE_DEC,
		NULL, 0, "Length of File Name", HFILL }},

	{ &hf_smb_nt_impersonation_level,
		{ "Impersonation", "smb.impersonation.level", FT_UINT32, BASE_DEC,
		VALS(impersonation_level_vals), 0, "Impersonation level", HFILL }},

	{ &hf_smb_nt_security_flags_context_tracking,
		{ "Context Tracking", "smb.security.flags.context_tracking", FT_BOOLEAN, 8,
		TFS(&tfs_nt_security_flags_context_tracking), 0x01, "Is security tracking static or dynamic?", HFILL }},

	{ &hf_smb_nt_security_flags_effective_only,
		{ "Effective Only", "smb.security.flags.effective_only", FT_BOOLEAN, 8,
		TFS(&tfs_nt_security_flags_effective_only), 0x02, "Are only enabled or all aspects uf the users SID available?", HFILL }},

	{ &hf_smb_nt_access_mask_generic_read,
		{ "Generic Read", "smb.access.generic_read", FT_BOOLEAN, 32,
		TFS(&tfs_nt_access_mask_generic_read), 0x80000000, "Is generic read allowed for this object?", HFILL }},

	{ &hf_smb_nt_access_mask_generic_write,
		{ "Generic Write", "smb.access.generic_write", FT_BOOLEAN, 32,
		TFS(&tfs_nt_access_mask_generic_write), 0x40000000, "Is generic write allowed for this object?", HFILL }},

	{ &hf_smb_nt_access_mask_generic_execute,
		{ "Generic Execute", "smb.access.generic_execute", FT_BOOLEAN, 32,
		TFS(&tfs_nt_access_mask_generic_execute), 0x20000000, "Is generic execute allowed for this object?", HFILL }},

	{ &hf_smb_nt_access_mask_generic_all,
		{ "Generic All", "smb.access.generic_all", FT_BOOLEAN, 32,
		TFS(&tfs_nt_access_mask_generic_all), 0x10000000, "Is generic all allowed for this attribute", HFILL }},

	{ &hf_smb_nt_access_mask_maximum_allowed,
		{ "Maximum Allowed", "smb.access.maximum_allowed", FT_BOOLEAN, 32,
		TFS(&tfs_nt_access_mask_maximum_allowed), 0x02000000, "?", HFILL }},

	{ &hf_smb_nt_access_mask_system_security,
		{ "System Security", "smb.access.system_security", FT_BOOLEAN, 32,
		TFS(&tfs_nt_access_mask_system_security), 0x01000000, "Access to a system ACL?", HFILL }},

	{ &hf_smb_nt_access_mask_synchronize,
		{ "Synchronize", "smb.access.synchronize", FT_BOOLEAN, 32,
		TFS(&tfs_nt_access_mask_synchronize), 0x00100000, "Windows NT: synchronize access", HFILL }},

	{ &hf_smb_nt_access_mask_write_owner,
		{ "Write Owner", "smb.access.write_owner", FT_BOOLEAN, 32,
		TFS(&tfs_nt_access_mask_write_owner), 0x00080000, "Can owner write to the object?", HFILL }},

	{ &hf_smb_nt_access_mask_write_dac,
		{ "Write DAC", "smb.access.write_dac", FT_BOOLEAN, 32,
		TFS(&tfs_nt_access_mask_write_dac), 0x00040000, "Is write allowed to the owner group or ACLs?", HFILL }},

	{ &hf_smb_nt_access_mask_read_control,
		{ "Read Control", "smb.access.read_control", FT_BOOLEAN, 32,
		TFS(&tfs_nt_access_mask_read_control), 0x00020000, "Are reads allowed of owner, group and ACL data of the SID?", HFILL }},

	{ &hf_smb_nt_access_mask_delete,
		{ "Delete", "smb.access.delete", FT_BOOLEAN, 32,
		TFS(&tfs_nt_access_mask_delete), 0x00010000, "Can object be deleted", HFILL }},

	{ &hf_smb_nt_access_mask_write_attributes,
		{ "Write Attributes", "smb.access.write_attributes", FT_BOOLEAN, 32,
		TFS(&tfs_nt_access_mask_write_attributes), 0x00000100, "Can object's attributes be written", HFILL }},

	{ &hf_smb_nt_access_mask_read_attributes,
		{ "Read Attributes", "smb.access.read_attributes", FT_BOOLEAN, 32,
		TFS(&tfs_nt_access_mask_read_attributes), 0x00000080, "Can object's attributes be read", HFILL }},

	{ &hf_smb_nt_access_mask_delete_child,
		{ "Delete Child", "smb.access.delete_child", FT_BOOLEAN, 32,
		TFS(&tfs_nt_access_mask_delete_child), 0x00000040, "Can object's subdirectories be deleted", HFILL }},

	/*
	 * "Execute" for files, "traverse" for directories.
	 */
	{ &hf_smb_nt_access_mask_execute,
		{ "Execute", "smb.access.execute", FT_BOOLEAN, 32,
		TFS(&tfs_nt_access_mask_execute), 0x00000020, "Can object be executed (if file) or traversed (if directory)", HFILL }},

	{ &hf_smb_nt_access_mask_write_ea,
		{ "Write EA", "smb.access.write_ea", FT_BOOLEAN, 32,
		TFS(&tfs_nt_access_mask_write_ea), 0x00000010, "Can object's extended attributes be written", HFILL }},

	{ &hf_smb_nt_access_mask_read_ea,
		{ "Read EA", "smb.access.read_ea", FT_BOOLEAN, 32,
		TFS(&tfs_nt_access_mask_read_ea), 0x00000008, "Can object's extended attributes be read", HFILL }},

	/*
	 * "Append data" for files, "add subdirectory" for directories,
	 * "create pipe instance" for named pipes.
	 */
	{ &hf_smb_nt_access_mask_append,
		{ "Append", "smb.access.append", FT_BOOLEAN, 32,
		TFS(&tfs_nt_access_mask_append), 0x00000004, "Can object's contents be appended to", HFILL }},

	/*
	 * "Write data" for files and pipes, "add file" for directory.
	 */
	{ &hf_smb_nt_access_mask_write,
		{ "Write", "smb.access.write", FT_BOOLEAN, 32,
		TFS(&tfs_nt_access_mask_write), 0x00000002, "Can object's contents be written", HFILL }},

	/*
	 * "Read data" for files and pipes, "list directory" for directory.
	 */
	{ &hf_smb_nt_access_mask_read,
		{ "Read", "smb.access.read", FT_BOOLEAN, 32,
		TFS(&tfs_nt_access_mask_read), 0x00000001, "Can object's contents be read", HFILL }},

	{ &hf_smb_nt_create_bits_oplock,
		{ "Exclusive Oplock", "smb.nt.create.oplock", FT_BOOLEAN, 32,
		TFS(&tfs_nt_create_bits_oplock), 0x00000002, "Is an oplock requested", HFILL }},

	{ &hf_smb_nt_create_bits_boplock,
		{ "Batch Oplock", "smb.nt.create.batch_oplock", FT_BOOLEAN, 32,
		TFS(&tfs_nt_create_bits_boplock), 0x00000004, "Is a batch oplock requested?", HFILL }},

	{ &hf_smb_nt_create_bits_dir,
		{ "Create Directory", "smb.nt.create.dir", FT_BOOLEAN, 32,
		TFS(&tfs_nt_create_bits_dir), 0x00000008, "Must target of open be a directory?", HFILL }},

	{ &hf_smb_nt_create_options_directory_file,
		{ "Directory", "smb.nt.create_options.directory", FT_BOOLEAN, 32,
		TFS(&tfs_nt_create_options_directory), 0x00000001, "Should file being opened/created be a directory?", HFILL }},

	{ &hf_smb_nt_create_options_write_through,
		{ "Write Through", "smb.nt.create_options.write_through", FT_BOOLEAN, 32,
		TFS(&tfs_nt_create_options_write_through), 0x00000002, "Should writes to the file write buffered data out before completing?", HFILL }},

	{ &hf_smb_nt_create_options_sequential_only,
		{ "Sequential Only", "smb.nt.create_options.sequential_only", FT_BOOLEAN, 32,
		TFS(&tfs_nt_create_options_sequential_only), 0x00000004, "Will accees to thsis file only be sequential?", HFILL }},

	{ &hf_smb_nt_create_options_sync_io_alert,
		{ "Sync I/O Alert", "smb.nt.create_options.sync_io_alert", FT_BOOLEAN, 32,
		TFS(&tfs_nt_create_options_sync_io_alert), 0x00000010, "All operations are performed synchronous", HFILL}},

	{ &hf_smb_nt_create_options_sync_io_nonalert,
		{ "Sync I/O Nonalert", "smb.nt.create_options.sync_io_nonalert", FT_BOOLEAN, 32,
		TFS(&tfs_nt_create_options_sync_io_nonalert), 0x00000020, "All operations are synchronous and may block", HFILL}},

	{ &hf_smb_nt_create_options_non_directory_file,
		{ "Non-Directory", "smb.nt.create_options.non_directory", FT_BOOLEAN, 32,
		TFS(&tfs_nt_create_options_non_directory), 0x00000040, "Should file being opened/created be a non-directory?", HFILL }},

	/* 0x00000080 is "tree connect", at least in "NtCreateFile()"
	   and "NtOpenFile()"; is that sent over the wire?  Network
	   Monitor thinks so, but its author may just have grabbed
	   the flag bits from a system header file. */

	/* 0x00000100 is "complete if oplocked", at least in "NtCreateFile()"
	   and "NtOpenFile()"; is that sent over the wire?  NetMon
	   thinks so, but see previous comment. */

	{ &hf_smb_nt_create_options_no_ea_knowledge,
		{ "No EA Knowledge", "smb.nt.create_options.no_ea_knowledge", FT_BOOLEAN, 32,
		TFS(&tfs_nt_create_options_no_ea_knowledge), 0x00000200, "Does the client not understand extended attributes?", HFILL }},

	{ &hf_smb_nt_create_options_eight_dot_three_only,
		{ "8.3 Only", "smb.nt.create_options.eight_dot_three_only", FT_BOOLEAN, 32,
		TFS(&tfs_nt_create_options_eight_dot_three_only), 0x00000400, "Does the client understand only 8.3 filenames?", HFILL }},

	{ &hf_smb_nt_create_options_random_access,
		{ "Random Access", "smb.nt.create_options.random_access", FT_BOOLEAN, 32,
		TFS(&tfs_nt_create_options_random_access), 0x00000800, "Will the client be accessing the file randomly?", HFILL }},

	{ &hf_smb_nt_create_options_delete_on_close,
		{ "Delete On Close", "smb.nt.create_options.delete_on_close", FT_BOOLEAN, 32,
		TFS(&tfs_nt_create_options_delete_on_close), 0x00001000, "Should the file be deleted when closed?", HFILL }},

	/* 0x00002000 is "open by FID", or something such as that (which
	   I suspect is like "open by inumber" on UNIX), at least in
	   "NtCreateFile()" and "NtOpenFile()"; is that sent over the
	   wire?  NetMon thinks so, but see previous comment. */

	/* 0x00004000 is "open for backup", at least in "NtCreateFile()"
	   and "NtOpenFile()"; is that sent over the wire?  NetMon
	   thinks so, but see previous comment. */

	{ &hf_smb_nt_share_access_read,
		{ "Read", "smb.share.access.read", FT_BOOLEAN, 32,
		TFS(&tfs_nt_share_access_read), 0x00000001, "Can the object be shared for reading?", HFILL }},

	{ &hf_smb_nt_share_access_write,
		{ "Write", "smb.share.access.write", FT_BOOLEAN, 32,
		TFS(&tfs_nt_share_access_write), 0x00000002, "Can the object be shared for write?", HFILL }},

	{ &hf_smb_nt_share_access_delete,
		{ "Delete", "smb.share.access.delete", FT_BOOLEAN, 32,
		TFS(&tfs_nt_share_access_delete), 0x00000004, "", HFILL }},

	{ &hf_smb_file_eattr_read_only,
		{ "Read Only", "smb.file.attribute.read_only", FT_BOOLEAN, 32,
		TFS(&tfs_file_attribute_read_only), FILE_ATTRIBUTE_READ_ONLY, "READ ONLY file attribute", HFILL }},

	{ &hf_smb_file_eattr_hidden,
		{ "Hidden", "smb.file.attribute.hidden", FT_BOOLEAN, 32,
		TFS(&tfs_file_attribute_hidden), FILE_ATTRIBUTE_HIDDEN, "HIDDEN file attribute", HFILL }},

	{ &hf_smb_file_eattr_system,
		{ "System", "smb.file.attribute.system", FT_BOOLEAN, 32,
		TFS(&tfs_file_attribute_system), FILE_ATTRIBUTE_SYSTEM, "SYSTEM file attribute", HFILL }},

	{ &hf_smb_file_eattr_volume,
		{ "Volume ID", "smb.file.attribute.volume", FT_BOOLEAN, 32,
		TFS(&tfs_file_attribute_volume), FILE_ATTRIBUTE_VOLUME, "VOLUME file attribute", HFILL }},

	{ &hf_smb_file_eattr_directory,
		{ "Directory", "smb.file.attribute.directory", FT_BOOLEAN, 32,
		TFS(&tfs_file_attribute_directory), FILE_ATTRIBUTE_DIRECTORY, "DIRECTORY file attribute", HFILL }},

	{ &hf_smb_file_eattr_archive,
		{ "Archive", "smb.file.attribute.archive", FT_BOOLEAN, 32,
		TFS(&tfs_file_attribute_archive), FILE_ATTRIBUTE_ARCHIVE, "ARCHIVE file attribute", HFILL }},

	{ &hf_smb_file_eattr_device,
		{ "Device", "smb.file.attribute.device", FT_BOOLEAN, 32,
		TFS(&tfs_file_attribute_device), FILE_ATTRIBUTE_DEVICE, "Is this file a device?", HFILL }},

	{ &hf_smb_file_eattr_normal,
		{ "Normal", "smb.file.attribute.normal", FT_BOOLEAN, 32,
		TFS(&tfs_file_attribute_normal), FILE_ATTRIBUTE_NORMAL, "Is this a normal file?", HFILL }},

	{ &hf_smb_file_eattr_temporary,
		{ "Temporary", "smb.file.attribute.temporary", FT_BOOLEAN, 32,
		TFS(&tfs_file_attribute_temporary), FILE_ATTRIBUTE_TEMPORARY, "Is this a temporary file?", HFILL }},

	{ &hf_smb_file_eattr_sparse,
		{ "Sparse", "smb.file.attribute.sparse", FT_BOOLEAN, 32,
		TFS(&tfs_file_attribute_sparse), FILE_ATTRIBUTE_SPARSE, "Is this a sparse file?", HFILL }},

	{ &hf_smb_file_eattr_reparse,
		{ "Reparse Point", "smb.file.attribute.reparse", FT_BOOLEAN, 32,
		TFS(&tfs_file_attribute_reparse), FILE_ATTRIBUTE_REPARSE, "Does this file have an associated reparse point?", HFILL }},

	{ &hf_smb_file_eattr_compressed,
		{ "Compressed", "smb.file.attribute.compressed", FT_BOOLEAN, 32,
		TFS(&tfs_file_attribute_compressed), FILE_ATTRIBUTE_COMPRESSED, "Is this file compressed?", HFILL }},

	{ &hf_smb_file_eattr_offline,
		{ "Offline", "smb.file.attribute.offline", FT_BOOLEAN, 32,
		TFS(&tfs_file_attribute_offline), FILE_ATTRIBUTE_OFFLINE, "Is this file offline?", HFILL }},

	{ &hf_smb_file_eattr_not_content_indexed,
		{ "Content Indexed", "smb.file.attribute.not_content_indexed", FT_BOOLEAN, 32,
		TFS(&tfs_file_attribute_not_content_indexed), FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, "May this file be indexed by the content indexing service", HFILL }},

	{ &hf_smb_file_eattr_encrypted,
		{ "Encrypted", "smb.file.attribute.encrypted", FT_BOOLEAN, 32,
		TFS(&tfs_file_attribute_encrypted), FILE_ATTRIBUTE_ENCRYPTED, "Is this file encrypted?", HFILL }},

	{ &hf_smb_file_eattr_write_through,
		{ "Write Through", "smb.file.attribute.write_through", FT_BOOLEAN, 32,
		TFS(&tfs_file_attribute_write_through), FILE_ATTRIBUTE_WRITE_THROUGH, "Does this object need write through?", HFILL }},

	{ &hf_smb_file_eattr_no_buffering,
		{ "No Buffering", "smb.file.attribute.no_buffering", FT_BOOLEAN, 32,
		TFS(&tfs_file_attribute_no_buffering), FILE_ATTRIBUTE_NO_BUFFERING, "May the server buffer this object?", HFILL }},

	{ &hf_smb_file_eattr_random_access,
		{ "Random Access", "smb.file.attribute.random_access", FT_BOOLEAN, 32,
		TFS(&tfs_file_attribute_random_access), FILE_ATTRIBUTE_RANDOM_ACCESS, "Optimize for random access", HFILL }},

	{ &hf_smb_file_eattr_sequential_scan,
		{ "Sequential Scan", "smb.file.attribute.sequential_scan", FT_BOOLEAN, 32,
		TFS(&tfs_file_attribute_sequential_scan), FILE_ATTRIBUTE_SEQUENTIAL_SCAN, "Optimize for sequential scan", HFILL }},

	{ &hf_smb_file_eattr_delete_on_close,
		{ "Delete on Close", "smb.file.attribute.delete_on_close", FT_BOOLEAN, 32,
		TFS(&tfs_file_attribute_delete_on_close), FILE_ATTRIBUTE_DELETE_ON_CLOSE, "Should this object be deleted on close?", HFILL }},

	{ &hf_smb_file_eattr_backup_semantics,
		{ "Backup", "smb.file.attribute.backup_semantics", FT_BOOLEAN, 32,
		TFS(&tfs_file_attribute_backup_semantics), FILE_ATTRIBUTE_BACKUP_SEMANTICS, "Does this object need/support backup semantics", HFILL }},

	{ &hf_smb_file_eattr_posix_semantics,
		{ "Posix", "smb.file.attribute.posix_semantics", FT_BOOLEAN, 32,
		TFS(&tfs_file_attribute_posix_semantics), FILE_ATTRIBUTE_POSIX_SEMANTICS, "Does this object need/support POSIX semantics?", HFILL }},

	{ &hf_smb_security_descriptor_len,
		{ "Security Descriptor Length", "smb.sec_desc_len", FT_UINT32, BASE_DEC,
		NULL, 0, "Security Descriptor Length", HFILL }},

	{ &hf_smb_security_descriptor,
		{ "Security Descriptor", "smb.sec_desc", FT_BYTES, BASE_HEX,
		NULL, 0, "Security Descriptor", HFILL }},

	{ &hf_smb_nt_qsd_owner,
		{ "Owner", "smb.nt_qsd.owner", FT_BOOLEAN, 32,
		TFS(&tfs_nt_qsd_owner), NT_QSD_OWNER, "Is owner security informaton being queried?", HFILL }},

	{ &hf_smb_nt_qsd_group,
		{ "Group", "smb.nt_qsd.group", FT_BOOLEAN, 32,
		TFS(&tfs_nt_qsd_group), NT_QSD_GROUP, "Is group security informaton being queried?", HFILL }},

	{ &hf_smb_nt_qsd_dacl,
		{ "DACL", "smb.nt_qsd.dacl", FT_BOOLEAN, 32,
		TFS(&tfs_nt_qsd_dacl), NT_QSD_DACL, "Is DACL security informaton being queried?", HFILL }},

	{ &hf_smb_nt_qsd_sacl,
		{ "SACL", "smb.nt_qsd.sacl", FT_BOOLEAN, 32,
		TFS(&tfs_nt_qsd_sacl), NT_QSD_SACL, "Is SACL security informaton being queried?", HFILL }},

	{ &hf_smb_extended_attributes,
		{ "Extended Attributes", "smb.ext_attr", FT_BYTES, BASE_HEX,
		NULL, 0, "Extended Attributes", HFILL }},

	{ &hf_smb_oplock_level,
		{ "Oplock level", "smb.oplock.level", FT_UINT8, BASE_DEC,
		VALS(oplock_level_vals), 0, "Level of oplock granted", HFILL }},

	{ &hf_smb_create_action,
		{ "Create action", "smb.create.action", FT_UINT32, BASE_DEC,
		VALS(create_disposition_vals), 0, "Type of action taken", HFILL }},

	{ &hf_smb_ea_error_offset,
		{ "EA Error offset", "smb.ea.error_offset", FT_UINT32, BASE_DEC,
		NULL, 0, "Offset into EA list if EA error", HFILL }},

	{ &hf_smb_end_of_file,
		{ "End Of File", "smb.end_of_file", FT_UINT64, BASE_DEC,
		NULL, 0, "Offset to the first free byte in the file", HFILL }},

	{ &hf_smb_device_type,
		{ "Device Type", "smb.device.type", FT_UINT32, BASE_HEX,
		VALS(device_type_vals), 0, "Type of device", HFILL }},

	{ &hf_smb_is_directory,
		{ "Is Directory", "smb.is_directory", FT_UINT8, BASE_DEC,
		VALS(is_directory_vals), 0, "Is this object a directory?", HFILL }},

	{ &hf_smb_next_entry_offset,
		{ "Next Entry Offset", "smb.next_entry_offset", FT_UINT32, BASE_DEC,
		NULL, 0, "Offset to next entry", HFILL }},

	{ &hf_smb_change_time,
		{ "Change", "smb.change.time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Last Change Time", HFILL }},

	{ &hf_smb_setup_len,
		{ "Setup Len", "smb.print.setup.len", FT_UINT16, BASE_DEC,
		NULL, 0, "Length of prionter setup data", HFILL }},

	{ &hf_smb_print_mode,
		{ "Mode", "smb.print.mode", FT_UINT16, BASE_DEC,
		VALS(print_mode_vals), 0, "Text or Graphics mode", HFILL }},

	{ &hf_smb_print_identifier,
		{ "Identifier", "smb.print.identifier", FT_STRING, BASE_NONE,
		NULL, 0, "Identifier string for this print job", HFILL }},

	{ &hf_smb_restart_index,
		{ "Restart Index", "smb.print.restart_index", FT_UINT16, BASE_DEC,
		NULL, 0, "Index of entry after last returned", HFILL }},

	{ &hf_smb_print_queue_date,
		{ "Queued", "smb.print.queued.date", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Date when this entry was queued", HFILL }},

	{ &hf_smb_print_queue_dos_date,
		{ "Queued Date", "smb.print.queued.smb.date", FT_UINT16, BASE_HEX,
		NULL, 0, "Date when this print job was queued, SMB_DATE format", HFILL }},

	{ &hf_smb_print_queue_dos_time,
		{ "Queued Time", "smb.print.queued.smb.time", FT_UINT16, BASE_HEX,
		NULL, 0, "Time when this print job was queued, SMB_TIME format", HFILL }},

	{ &hf_smb_print_status,
		{ "Status", "smb.print.status", FT_UINT8, BASE_HEX,
		VALS(print_status_vals), 0, "Status of this entry", HFILL }},

	{ &hf_smb_print_spool_file_number,
		{ "Spool File Number", "smb.print.spool.file_number", FT_UINT16, BASE_DEC,
		NULL, 0, "Spool File Number, assigned by the spooler", HFILL }},

	{ &hf_smb_print_spool_file_size,
		{ "Spool File Size", "smb.print.spool.file_size", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of bytes in spool file", HFILL }},

	{ &hf_smb_print_spool_file_name,
		{ "Name", "smb.print.spool.name", FT_BYTES, BASE_HEX,
		NULL, 0, "Name of client that submitted this job", HFILL }},

	{ &hf_smb_start_index,
		{ "Start Index", "smb.print.start_index", FT_UINT16, BASE_DEC,
		NULL, 0, "First queue entry to return", HFILL }},

	{ &hf_smb_cancel_to,
		{ "Cancel to", "smb.cancel_to", FT_UINT32, BASE_DEC,
		NULL, 0, "This packet is a cancellation of the packet in this frame", HFILL }},

	{ &hf_smb_trans2_subcmd,
		{ "Subcommand", "smb.trans2.cmd", FT_UINT16, BASE_HEX,
		VALS(trans2_cmd_vals), 0, "Subcommand for TRANSACTION2", HFILL }},

	{ &hf_smb_trans_name,
		{ "Transaction Name", "smb.trans_name", FT_STRING, BASE_NONE,
		NULL, 0, "Name of transaction", HFILL }},

	{ &hf_smb_transaction_flags_dtid,
		{ "Disconnect TID", "smb.transaction.flags.dtid", FT_BOOLEAN, 16,
		TFS(&tfs_tf_dtid), 0x0001, "Disconnect TID?", HFILL }},

	{ &hf_smb_transaction_flags_owt,
		{ "One Way Transaction", "smb.transaction.flags.owt", FT_BOOLEAN, 16,
		TFS(&tfs_tf_owt), 0x0002, "One Way Transaction (no response)?", HFILL }},

	{ &hf_smb_search_count,
		{ "Search Count", "smb.search_count", FT_UINT16, BASE_DEC,
		NULL, 0, "Maximum number of search entries to return", HFILL }},

	{ &hf_smb_search_pattern,
		{ "Search Pattern", "smb.search_pattern", FT_STRING, BASE_NONE,
		NULL, 0, "Search Pattern", HFILL }},

	{ &hf_smb_ff2_backup,
		{ "Backup Intent", "smb.find_first2.flags.backup", FT_BOOLEAN, 16,
		TFS(&tfs_ff2_backup), 0x0010, "Find with backup intent", HFILL }},

	{ &hf_smb_ff2_continue,
		{ "Continue", "smb.find_first2.flags.continue", FT_BOOLEAN, 16,
		TFS(&tfs_ff2_continue), 0x0008, "Continue search from previous ending place", HFILL }},

	{ &hf_smb_ff2_resume,
		{ "Resume", "smb.find_first2.flags.resume", FT_BOOLEAN, 16,
		TFS(&tfs_ff2_resume), 0x0004, "Return resume keys for each entry found", HFILL }},

	{ &hf_smb_ff2_close_eos,
		{ "Close on EOS", "smb.find_first2.flags.eos", FT_BOOLEAN, 16,
		TFS(&tfs_ff2_close_eos), 0x0002, "Close search if end of search reached", HFILL }},

	{ &hf_smb_ff2_close,
		{ "Close", "smb.find_first2.flags.close", FT_BOOLEAN, 16,
		TFS(&tfs_ff2_close), 0x0001, "Close search after this request", HFILL }},

	{ &hf_smb_ff2_information_level,
		{ "Level of Interest", "smb.ff2_loi", FT_UINT16, BASE_DEC,
		VALS(ff2_il_vals), 0, "Level of interest for FIND_FIRST2 command", HFILL }},

	{ &hf_smb_qpi_loi,
		{ "Level of Interest", "smb.loi", FT_UINT16, BASE_DEC,
		VALS(qpi_loi_vals), 0, "Level of interest for TRANSACTION[2] commands", HFILL }},

	{ &hf_smb_storage_type,
		{ "Storage Type", "smb.storage_type", FT_UINT32, BASE_DEC,
		NULL, 0, "Type of storage", HFILL }},

	{ &hf_smb_resume,
		{ "Resume Key", "smb.resume", FT_UINT32, BASE_DEC,
		NULL, 0, "Resume Key", HFILL }},

	{ &hf_smb_max_referral_level,
		{ "Max Referral Level", "smb.max_referral_level", FT_UINT16, BASE_DEC,
		NULL, 0, "Latest referral version number understood", HFILL }},

	{ &hf_smb_qfsi_information_level,
		{ "Level of Interest", "smb.qfi_loi", FT_UINT16, BASE_DEC,
		VALS(qfsi_vals), 0, "Level of interest for QUERY_FS_INFORMATION2 command", HFILL }},

	{ &hf_smb_ea_size,
		{ "EA Size", "smb.ea_size", FT_UINT32, BASE_DEC,
		NULL, 0, "Size of file's EA information", HFILL }},

	{ &hf_smb_list_length,
		{ "ListLength", "smb.list_len", FT_UINT32, BASE_DEC,
		NULL, 0, "Length of the remaining data", HFILL }},

	{ &hf_smb_number_of_links,
		{ "Link Count", "smb.link_count", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of hard links to the file", HFILL }},

	{ &hf_smb_delete_pending,
		{ "Delete Pending", "smb.delete_pending", FT_UINT16, BASE_DEC,
		VALS(delete_pending_vals), 0, "Is this object about to be deleted?", HFILL }},

	{ &hf_smb_index_number,
		{ "Index Number", "smb.index_number", FT_UINT64, BASE_DEC,
		NULL, 0, "File system unique identifier", HFILL }},

	{ &hf_smb_current_offset,
		{ "Current Offset", "smb.offset", FT_UINT64, BASE_DEC,
		NULL, 0, "Current offset in the file", HFILL }},

	{ &hf_smb_t2_alignment,
		{ "Alignment", "smb.alignment", FT_UINT32, BASE_DEC,
		VALS(alignment_vals), 0, "What alignment do we require for buffers", HFILL }},

	{ &hf_smb_t2_stream_name_length,
		{ "Stream Name Length", "smb.stream_name_len", FT_UINT32, BASE_DEC,
		NULL, 0, "Length of stream name", HFILL }},

	{ &hf_smb_t2_stream_size,
		{ "Stream Size", "smb.stream_size", FT_UINT64, BASE_DEC,
		NULL, 0, "Size of the stream in number of bytes", HFILL }},

	{ &hf_smb_t2_stream_name,
		{ "Stream Name", "smb.stream_name", FT_STRING, BASE_NONE,
		NULL, 0, "Name of the stream", HFILL }},

	{ &hf_smb_t2_compressed_file_size,
		{ "Compressed Size", "smb.compressed.file_size", FT_UINT64, BASE_DEC,
		NULL, 0, "Size of the compressed file", HFILL }},

	{ &hf_smb_t2_compressed_format,
		{ "Compression Format", "smb.compressed.format", FT_UINT16, BASE_DEC,
		NULL, 0, "Compression algorithm used", HFILL }},

	{ &hf_smb_t2_compressed_unit_shift,
		{ "Unit Shift", "smb.compressed.unit_shift", FT_UINT8, BASE_DEC,
		NULL, 0, "Size of the stream in number of bytes", HFILL }},

	{ &hf_smb_t2_compressed_chunk_shift,
		{ "Chunk Shift", "smb.compressed.chunk_shift", FT_UINT8, BASE_DEC,
		NULL, 0, "Allocated size of the stream in number of bytes", HFILL }},

	{ &hf_smb_t2_compressed_cluster_shift,
		{ "Cluster Shift", "smb.compressed.cluster_shift", FT_UINT8, BASE_DEC,
		NULL, 0, "Allocated size of the stream in number of bytes", HFILL }},

	{ &hf_smb_dfs_path_consumed,
		{ "Path Consumed", "smb.dfs.path_consumed", FT_UINT16, BASE_DEC,
		NULL, 0, "Number of RequestFilename bytes client", HFILL }},

	{ &hf_smb_dfs_num_referrals,
		{ "Num Referrals", "smb.dfs.num_referrals", FT_UINT16, BASE_DEC,
		NULL, 0, "Number of referrals in this pdu", HFILL }},

	{ &hf_smb_get_dfs_server_hold_storage,
		{ "Hold Storage", "smb.dfs.flags.server_hold_storage", FT_BOOLEAN, 16,
		TFS(&tfs_get_dfs_server_hold_storage), 0x02, "The servers in referrals should hold storage for the file", HFILL }},

	{ &hf_smb_get_dfs_fielding,
		{ "Fielding", "smb.dfs.flags.fielding", FT_BOOLEAN, 16,
		TFS(&tfs_get_dfs_fielding), 0x01, "The servers in referrals are capable of fielding", HFILL }},

	{ &hf_smb_dfs_referral_version,
		{ "Version", "smb.dfs.referral.version", FT_UINT16, BASE_DEC,
		NULL, 0, "Version of referral element", HFILL }},

	{ &hf_smb_dfs_referral_size,
		{ "Size", "smb.dfs.referral.size", FT_UINT16, BASE_DEC,
		NULL, 0, "Size of referral element", HFILL }},

	{ &hf_smb_dfs_referral_server_type,
		{ "Server Type", "smb.dfs.referral.server.type", FT_UINT16, BASE_DEC,
		VALS(dfs_referral_server_type_vals), 0, "Type of referral server", HFILL }},

	{ &hf_smb_dfs_referral_flags_strip,
		{ "Strip", "smb.dfs.referral.flags.strip", FT_BOOLEAN, 16,
		TFS(&tfs_dfs_referral_flags_strip), 0x01, "Should we strip off pathconsumed characters before submitting?", HFILL }},

	{ &hf_smb_dfs_referral_node_offset,
		{ "Node Offset", "smb.dfs.referral.node_offset", FT_UINT16, BASE_DEC,
		NULL, 0, "Offset of name of entity to visit next", HFILL }},

	{ &hf_smb_dfs_referral_node,
		{ "Node", "smb.dfs.referral.node", FT_STRING, BASE_NONE,
		NULL, 0, "Name of entity to visit next", HFILL }},

	{ &hf_smb_dfs_referral_proximity,
		{ "Proximity", "smb.dfs.referral.proximity", FT_UINT16, BASE_DEC,
		NULL, 0, "Hint describing proximity of this server to the client", HFILL }},

	{ &hf_smb_dfs_referral_ttl,
		{ "TTL", "smb.dfs.referral.ttl", FT_UINT16, BASE_DEC,
		NULL, 0, "Number of seconds the client can cache this referral", HFILL }},

	{ &hf_smb_dfs_referral_path_offset,
		{ "Path Offset", "smb.dfs.referral.path_offset", FT_UINT16, BASE_DEC,
		NULL, 0, "Offset of Dfs Path that matched pathconsumed", HFILL }},

	{ &hf_smb_dfs_referral_path,
		{ "Path", "smb.dfs.referral.path", FT_STRING, BASE_NONE,
		NULL, 0, "Dfs Path that matched pathconsumed", HFILL }},

	{ &hf_smb_dfs_referral_alt_path_offset,
		{ "Alt Path Offset", "smb.dfs.referral.alt_path_offset", FT_UINT16, BASE_DEC,
		NULL, 0, "Offset of alternative(8.3) Path that matched pathconsumed", HFILL }},

	{ &hf_smb_dfs_referral_alt_path,
		{ "Alt Path", "smb.dfs.referral.alt_path", FT_STRING, BASE_NONE,
		NULL, 0, "Alternative(8.3) Path that matched pathconsumed", HFILL }},

	{ &hf_smb_end_of_search,
		{ "End Of Search", "smb.end_of_search", FT_UINT16, BASE_DEC,
		NULL, 0, "Was last entry returned?", HFILL }},

	{ &hf_smb_last_name_offset,
		{ "Last Name Offset", "smb.last_name_offset", FT_UINT16, BASE_DEC,
		NULL, 0, "If non-0 this is the offset into the datablock for the file name of the last entry", HFILL }},

	{ &hf_smb_file_index,
		{ "File Index", "smb.file_index", FT_UINT32, BASE_DEC,
		NULL, 0, "File index", HFILL }},

	{ &hf_smb_short_file_name,
		{ "Short File Name", "smb.short_file", FT_STRING, BASE_NONE,
		NULL, 0, "Short (8.3) File Name", HFILL }},

	{ &hf_smb_short_file_name_len,
		{ "Short File Name Len", "smb.short_file_name_len", FT_UINT32, BASE_DEC,
		NULL, 0, "Length of Short (8.3) File Name", HFILL }},

	{ &hf_smb_fs_id,
		{ "FS Id", "smb.fs.id", FT_UINT32, BASE_DEC,
		NULL, 0, "File System ID (NT Server always returns 0)", HFILL }},

	{ &hf_smb_sector_unit,
		{ "Sectors/Unit", "smb.fs.sector_per_unit", FT_UINT32, BASE_DEC,
		NULL, 0, "Sectors per allocation unit", HFILL }},

	{ &hf_smb_fs_units,
		{ "Total Units", "smb.fs.units", FT_UINT32, BASE_DEC,
		NULL, 0, "Total number of units on this filesystem", HFILL }},

	{ &hf_smb_fs_sector,
		{ "Bytes per Sector", "smb.fs.bytes_per_sector", FT_UINT32, BASE_DEC,
		NULL, 0, "Bytes per sector", HFILL }},

	{ &hf_smb_avail_units,
		{ "Available Units", "smb.avail.units", FT_UINT32, BASE_DEC,
		NULL, 0, "Total number of available units on this filesystem", HFILL }},

	{ &hf_smb_volume_serial_num,
		{ "Volume Serial Number", "smb.volume.serial", FT_UINT32, BASE_HEX,
		NULL, 0, "Volume serial number", HFILL }},

	{ &hf_smb_volume_label_len,
		{ "Label Length", "smb.volume.label.len", FT_UINT32, BASE_DEC,
		NULL, 0, "Length of volume label", HFILL }},

	{ &hf_smb_volume_label,
		{ "Label", "smb.volume.label", FT_STRING, BASE_DEC,
		NULL, 0, "Volume label", HFILL }},

	{ &hf_smb_free_alloc_units64,
		{ "Free Units", "smb.free_alloc_units", FT_UINT64, BASE_DEC,
		NULL, 0, "Number of free allocation units", HFILL }},

	{ &hf_smb_max_name_len,
		{ "Max name length", "smb.fs.max_name_len", FT_UINT32, BASE_DEC,
		NULL, 0, "Maximum length of each file name component in number of bytes", HFILL }},

	{ &hf_smb_fs_name_len,
		{ "Label Length", "smb.fs.name.len", FT_UINT32, BASE_DEC,
		NULL, 0, "Length of filesystem name in bytes", HFILL }},

	{ &hf_smb_fs_name,
		{ "FS Name", "smb.fs.name", FT_STRING, BASE_DEC,
		NULL, 0, "Name of filesystem", HFILL }},

	{ &hf_smb_device_char_removable,
		{ "Removable", "smb.device.removable", FT_BOOLEAN, 32,
		TFS(&tfs_device_char_removable), 0x00000001, "Is this a removable device", HFILL }},

	{ &hf_smb_device_char_read_only,
		{ "Read Only", "smb.device.read_only", FT_BOOLEAN, 32,
		TFS(&tfs_device_char_read_only), 0x00000002, "Is this a read-only device", HFILL }},

	{ &hf_smb_device_char_floppy,
		{ "Floppy", "smb.device.floppy", FT_BOOLEAN, 32,
		TFS(&tfs_device_char_floppy), 0x00000004, "Is this a floppy disk", HFILL }},

	{ &hf_smb_device_char_write_once,
		{ "Write Once", "smb.device.write_once", FT_BOOLEAN, 32,
		TFS(&tfs_device_char_write_once), 0x00000008, "Is this a write-once device", HFILL }},

	{ &hf_smb_device_char_remote,
		{ "Remote", "smb.device.remote", FT_BOOLEAN, 32,
		TFS(&tfs_device_char_remote), 0x00000010, "Is this a remote device", HFILL }},

	{ &hf_smb_device_char_mounted,
		{ "Mounted", "smb.device.mounted", FT_BOOLEAN, 32,
		TFS(&tfs_device_char_mounted), 0x00000020, "Is this a mounted device", HFILL }},

	{ &hf_smb_device_char_virtual,
		{ "Virtual", "smb.device.virtual", FT_BOOLEAN, 32,
		TFS(&tfs_device_char_virtual), 0x00000040, "Is this a virtual device", HFILL }},

	{ &hf_smb_fs_attr_css,
		{ "Case Sensitive Search", "smb.fs.attr.css", FT_BOOLEAN, 32,
		TFS(&tfs_fs_attr_css), 0x00000001, "Does this FS support Case Sensitive Search?", HFILL }},

	{ &hf_smb_fs_attr_cpn,
		{ "Case Preserving", "smb.fs.attr.cpn", FT_BOOLEAN, 32,
		TFS(&tfs_fs_attr_cpn), 0x00000002, "Will this FS Preserve Name Case?", HFILL }},

	{ &hf_smb_fs_attr_pacls,
		{ "Persistent ACLs", "smb.fs.attr.pacls", FT_BOOLEAN, 32,
		TFS(&tfs_fs_attr_pacls), 0x00000004, "Does this FS support Persistent ACLs?", HFILL }},

	{ &hf_smb_fs_attr_fc,
		{ "Compression", "smb.fs.attr.fc", FT_BOOLEAN, 32,
		TFS(&tfs_fs_attr_fc), 0x00000008, "Does this FS support File Compression?", HFILL }},

	{ &hf_smb_fs_attr_vq,
		{ "Volume Quotas", "smb.fs.attr.vq", FT_BOOLEAN, 32,
		TFS(&tfs_fs_attr_vq), 0x00000010, "Does this FS support Volume Quotas?", HFILL }},

	{ &hf_smb_fs_attr_dim,
		{ "Mounted", "smb.fs.attr.dim", FT_BOOLEAN, 32,
		TFS(&tfs_fs_attr_dim), 0x00000020, "Is this FS a Mounted Device?", HFILL }},

	{ &hf_smb_fs_attr_vic,
		{ "Compressed", "smb.fs.attr.vic", FT_BOOLEAN, 32,
		TFS(&tfs_fs_attr_vic), 0x00008000, "Is this FS Compressed?", HFILL }},
	};
	static gint *ett[] = {
		&ett_smb,
		&ett_smb_hdr,
		&ett_smb_command,
		&ett_smb_fileattributes,
		&ett_smb_capabilities,
		&ett_smb_aflags,
		&ett_smb_dialect,
		&ett_smb_dialects,
		&ett_smb_mode,
		&ett_smb_rawmode,
		&ett_smb_flags,
		&ett_smb_flags2,
		&ett_smb_desiredaccess,
		&ett_smb_search,
		&ett_smb_file,
		&ett_smb_openfunction,
		&ett_smb_filetype,
		&ett_smb_openaction,
		&ett_smb_writemode,
		&ett_smb_lock_type,
		&ett_smb_ssetupandxaction,
		&ett_smb_optionsup,
		&ett_smb_time_date,
		&ett_smb_64bit_time,
		&ett_smb_move_flags,
		&ett_smb_file_attributes,
		&ett_smb_search_resume_key,
		&ett_smb_search_dir_info,
		&ett_smb_unlocks,
		&ett_smb_unlock,
		&ett_smb_locks,
		&ett_smb_lock,
		&ett_smb_open_flags,
		&ett_smb_ipc_state,
		&ett_smb_open_action,
		&ett_smb_setup_action,
		&ett_smb_connect_flags,
		&ett_smb_connect_support_bits,
		&ett_smb_nt_access_mask,
		&ett_smb_nt_create_bits,
		&ett_smb_nt_create_options,
		&ett_smb_nt_share_access,
		&ett_smb_nt_security_flags,
		&ett_smb_nt_trans_setup,
		&ett_smb_nt_notify_completion_filter,
		&ett_smb_nt_ioctl_flags,
		&ett_smb_security_information_mask,
		&ett_smb_print_queue_entry,
		&ett_smb_transaction_flags,
		&ett_smb_transaction_params,
		&ett_smb_find_first2_flags,
		&ett_smb_transaction_data,
		&ett_smb_stream_info,
		&ett_smb_dfs_referrals,
		&ett_smb_dfs_referral,
		&ett_smb_dfs_referral_flags,
		&ett_smb_get_dfs_flags,
		&ett_smb_ff2_data,
		&ett_smb_device_characteristics,
		&ett_smb_fs_attributes,
		&ett_smb_segments,
	};
	module_t *smb_module;

	proto_smb = proto_register_protocol("SMB (Server Message Block Protocol)",
	    "SMB", "smb");
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_smb, hf, array_length(hf));
	register_init_routine(&smb_init_protocol);
	smb_module = prefs_register_protocol(proto_smb, NULL);
	prefs_register_bool_preference(smb_module, "smb.trans.reassembly",
		"Reassemble SMB Transaction payload",
		"Whether the dissector should do reassembly the payload of SMB Transaction commands spanning multiple SMB PDUs",
		&smb_trans_reassembly);
	register_init_routine(smb_trans_reassembly_init);
}

void
proto_reg_handoff_smb(void)
{
	heur_dissector_add("netbios", dissect_smb, proto_smb);
}
