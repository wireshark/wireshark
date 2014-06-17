/* packet-nfs.c
 * Routines for nfs dissection
 * Copyright 1999, Uwe Girlich <Uwe.Girlich@philosys.de>
 * Copyright 2000-2004, Mike Frisch <frisch@hummingbird.com> (NFSv4 decoding)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-smb.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdio.h>
#include <glib.h>
#include "packet-rpc.h"
#include "packet-nfs.h"
#include <epan/prefs.h>
#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/wmem/wmem.h>
#include <wsutil/crc16.h>
#include <wsutil/crc32.h>
#include <epan/expert.h>
#include <epan/to_str.h>

void proto_register_nfs(void);
void proto_reg_handoff_nfs(void);

/* NON-NFS-version-specific hf variables */
static int proto_nfs = -1;
static int hf_nfs_access_check  = -1;
static int hf_nfs_access_supported  = -1;
static int hf_nfs_access_rights = -1;
static int hf_nfs_access_supp_read = -1;
static int hf_nfs_access_supp_lookup = -1;
static int hf_nfs_access_supp_modify = -1;
static int hf_nfs_access_supp_extend = -1;
static int hf_nfs_access_supp_delete = -1;
static int hf_nfs_access_supp_execute = -1;
static int hf_nfs_access_read = -1;
static int hf_nfs_access_lookup = -1;
static int hf_nfs_access_modify = -1;
static int hf_nfs_access_extend = -1;
static int hf_nfs_access_delete = -1;
static int hf_nfs_access_execute = -1;
static int hf_nfs_access_denied = -1;
static int hf_nfs_fh_length = -1;
static int hf_nfs_fh_hash = -1;
static int hf_nfs_fh_fhandle_data = -1;
static int hf_nfs_fh_mount_fileid = -1;
static int hf_nfs_fh_mount_generation = -1;
static int hf_nfs_fh_snapid = -1;
static int hf_nfs_fh_unused = -1;
static int hf_nfs_fh_flags = -1;
static int hf_nfs_fh_fileid = -1;
static int hf_nfs_fh_generation = -1;
static int hf_nfs_fh_fsid = -1;
static int hf_nfs_fh_export_fileid = -1;
static int hf_nfs_fh_export_generation = -1;
static int hf_nfs_fh_export_snapid = -1;
static int hf_nfs_fh_exportid = -1;
static int hf_nfs_fh_file_flag_mntpoint = -1;
static int hf_nfs_fh_file_flag_snapdir = -1;
static int hf_nfs_fh_file_flag_snapdir_ent = -1;
static int hf_nfs_fh_file_flag_empty = -1;
static int hf_nfs_fh_file_flag_vbn_access = -1;
static int hf_nfs_fh_file_flag_multivolume = -1;
static int hf_nfs_fh_file_flag_metadata = -1;
static int hf_nfs_fh_file_flag_orphan = -1;
static int hf_nfs_fh_file_flag_foster = -1;
static int hf_nfs_fh_file_flag_named_attr = -1;
static int hf_nfs_fh_file_flag_exp_snapdir = -1;
static int hf_nfs_fh_file_flag_vfiler = -1;
static int hf_nfs_fh_file_flag_aggr = -1;
static int hf_nfs_fh_file_flag_striped = -1;
static int hf_nfs_fh_file_flag_private = -1;
static int hf_nfs_fh_file_flag_next_gen = -1;
static int hf_nfs_fh_gfid = -1;
static int hf_nfs_fh_handle_type = -1;
static int hf_nfs_fh_fsid_major = -1;
static int hf_nfs_fh_fsid_minor = -1;
static int hf_nfs_fh_fsid_inode = -1;
static int hf_nfs_fh_xfsid_major = -1;
static int hf_nfs_fh_xfsid_minor = -1;
static int hf_nfs_fh_fstype = -1;
static int hf_nfs_fh_fn = -1;
static int hf_nfs_fh_fn_len = -1;
static int hf_nfs_fh_fn_inode = -1;
static int hf_nfs_fh_fn_generation = -1;
static int hf_nfs_fh_xfn = -1;
static int hf_nfs_fh_xfn_len = -1;
static int hf_nfs_fh_xfn_inode = -1;
static int hf_nfs_fh_xfn_generation = -1;
static int hf_nfs_fh_dentry = -1;
/* static int hf_nfs_fh_dev = -1; */
/* static int hf_nfs_fh_xdev = -1; */
static int hf_nfs_fh_dirinode = -1;
static int hf_nfs_fh_pinode = -1;
static int hf_nfs_fh_hp_len = -1;
static int hf_nfs_fh_version = -1;
static int hf_nfs_fh_auth_type = -1;
static int hf_nfs_fh_fsid_type = -1;
static int hf_nfs_fh_fileid_type = -1;
static int hf_nfs_fh_obj_id = -1;
static int hf_nfs_fh_ro_node = -1;
static int hf_nfs_fh_obj = -1;
static int hf_nfs_fh_obj_fsid = -1;
static int hf_nfs_fh_obj_treeid = -1;
static int hf_nfs_fh_obj_kindid = -1;
static int hf_nfs_fh_obj_inode = -1;
static int hf_nfs_fh_obj_gen = -1;
static int hf_nfs_fh_ex = -1;
static int hf_nfs_fh_ex_fsid = -1;
static int hf_nfs_fh_ex_treeid = -1;
static int hf_nfs_fh_ex_kindid = -1;
static int hf_nfs_fh_ex_inode = -1;
static int hf_nfs_fh_ex_gen = -1;
static int hf_nfs_fh_flag = -1;
static int hf_nfs_fh_endianness = -1;
static int hf_nfs_full_name = -1;
static int hf_nfs_name = -1;
static int hf_nfs_data = -1;
static int hf_nfs_symlink_to = -1;
static int hf_nfs_readdir_eof = -1;
static int hf_nfs_readdir_entry = -1;
static int hf_nfs_atime = -1;
static int hf_nfs_atime_sec = -1;
static int hf_nfs_atime_nsec = -1;
static int hf_nfs_atime_usec = -1;
static int hf_nfs_mtime = -1;
static int hf_nfs_mtime_sec = -1;
static int hf_nfs_mtime_nsec = -1;
static int hf_nfs_mtime_usec = -1;
static int hf_nfs_ctime = -1;
static int hf_nfs_ctime_sec = -1;
static int hf_nfs_ctime_nsec = -1;
static int hf_nfs_ctime_usec = -1;
static int hf_nfs_dtime = -1;
static int hf_nfs_dtime_sec = -1;
static int hf_nfs_dtime_nsec = -1;

/* Hidden field for v2, v3, and v4 status; also used in dissect-nfsacl.c */
int hf_nfs_status = -1;

/* NFSv2 RFC 1094 hf variables */
static int hf_nfs2_procedure = -1;
static int hf_nfs2_status = -1;
static int hf_nfs2_readlink_data = -1;
/* static int hf_nfs2_fattr_type = -1; */
static int hf_nfs2_fattr_nlink = -1;
static int hf_nfs2_fattr_uid = -1;
static int hf_nfs2_fattr_gid = -1;
static int hf_nfs2_fattr_size = -1;
static int hf_nfs2_fattr_blocksize = -1;
static int hf_nfs2_fattr_rdev = -1;
static int hf_nfs2_fattr_blocks = -1;
static int hf_nfs2_fattr_fsid = -1;
static int hf_nfs2_fattr_fileid = -1;
static int hf_nfs2_mode_name = -1;
static int hf_nfs2_mode_set_user_id = -1;
static int hf_nfs2_mode_set_group_id = -1;
static int hf_nfs2_mode_save_swap_text = -1;
static int hf_nfs2_mode_read_owner = -1;
static int hf_nfs2_mode_write_owner = -1;
static int hf_nfs2_mode_exec_owner = -1;
static int hf_nfs2_mode_read_group = -1;
static int hf_nfs2_mode_write_group = -1;
static int hf_nfs2_mode_exec_group = -1;
static int hf_nfs2_mode_read_other = -1;
static int hf_nfs2_mode_write_other = -1;
static int hf_nfs2_mode_exec_other = -1;
static int hf_nfs2_read_offset = -1;
static int hf_nfs2_read_count = -1;
static int hf_nfs2_read_totalcount = -1;
static int hf_nfs2_write_beginoffset = -1;
static int hf_nfs2_write_offset = -1;
static int hf_nfs2_write_totalcount = -1;
static int hf_nfs2_readdir_cookie = -1;
static int hf_nfs2_readdir_count = -1;
static int hf_nfs2_readdir_entry_fileid = -1;
static int hf_nfs2_readdir_entry_name = -1;
static int hf_nfs2_readdir_entry_cookie = -1;
static int hf_nfs2_statfs_tsize = -1;
static int hf_nfs2_statfs_bsize = -1;
static int hf_nfs2_statfs_blocks = -1;
static int hf_nfs2_statfs_bfree = -1;
static int hf_nfs2_statfs_bavail = -1;

/* NFSv3 RFC 1813 header format variables */
static int hf_nfs3_procedure = -1;
static int hf_nfs3_fattr_type = -1;
static int hf_nfs3_fattr_nlink = -1;
static int hf_nfs3_fattr_uid = -1;
static int hf_nfs3_fattr_gid = -1;
static int hf_nfs3_fattr_size = -1;
static int hf_nfs3_fattr_used = -1;
/* static int hf_nfs3_fattr_rdev = -1; */
static int hf_nfs3_fattr_fsid = -1;
static int hf_nfs3_fattr_fileid = -1;
static int hf_nfs3_wcc_attr_size = -1;
static int hf_nfs3_set_size = -1;
static int hf_nfs3_cookie = -1;
static int hf_nfs3_fsstat_resok_tbytes = -1;
static int hf_nfs3_fsstat_resok_fbytes = -1;
static int hf_nfs3_fsstat_resok_abytes = -1;
static int hf_nfs3_fsstat_resok_tfiles = -1;
static int hf_nfs3_fsstat_resok_ffiles = -1;
static int hf_nfs3_fsstat_resok_afiles = -1;
static int hf_nfs3_uid = -1;
static int hf_nfs3_gid = -1;
static int hf_nfs3_offset = -1;
static int hf_nfs3_count = -1;
static int hf_nfs3_count_maxcount = -1;
static int hf_nfs3_count_dircount= -1;
static int hf_nfs3_mode = -1;
static int hf_nfs3_mode_suid = -1;
static int hf_nfs3_mode_sgid = -1;
static int hf_nfs3_mode_sticky = -1;
static int hf_nfs3_mode_rusr = -1;
static int hf_nfs3_mode_wusr = -1;
static int hf_nfs3_mode_xusr = -1;
static int hf_nfs3_mode_rgrp = -1;
static int hf_nfs3_mode_wgrp = -1;
static int hf_nfs3_mode_xgrp = -1;
static int hf_nfs3_mode_roth = -1;
static int hf_nfs3_mode_woth = -1;
static int hf_nfs3_mode_xoth = -1;
static int hf_nfs3_readdir_entry_fileid = -1;
static int hf_nfs3_readdir_entry_name = -1;
static int hf_nfs3_readdir_entry_cookie = -1;
static int hf_nfs3_readdirplus_entry_fileid = -1;
static int hf_nfs3_readdirplus_entry_name = -1;
static int hf_nfs3_readdirplus_entry_cookie = -1;
static int hf_nfs3_ftype = -1;
static int hf_nfs3_status = -1;
static int hf_nfs3_read_eof = -1;
static int hf_nfs3_write_stable = -1;
static int hf_nfs3_write_committed = -1;
static int hf_nfs3_createmode = -1;
static int hf_nfs3_fsstat_invarsec = -1;
static int hf_nfs3_fsinfo_rtmax = -1;
static int hf_nfs3_fsinfo_rtpref = -1;
static int hf_nfs3_fsinfo_rtmult = -1;
static int hf_nfs3_fsinfo_wtmax = -1;
static int hf_nfs3_fsinfo_wtpref = -1;
static int hf_nfs3_fsinfo_wtmult = -1;
static int hf_nfs3_fsinfo_dtpref = -1;
static int hf_nfs3_fsinfo_maxfilesize = -1;
static int hf_nfs3_fsinfo_properties = -1;
static int hf_nfs3_fsinfo_properties_setattr = -1;
static int hf_nfs3_fsinfo_properties_pathconf = -1;
static int hf_nfs3_fsinfo_properties_symlinks = -1;
static int hf_nfs3_fsinfo_properties_hardlinks = -1;
static int hf_nfs3_pathconf_linkmax = -1;
static int hf_nfs3_pathconf_name_max = -1;
static int hf_nfs3_pathconf_no_trunc = -1;
static int hf_nfs3_pathconf_chown_restricted = -1;
static int hf_nfs3_pathconf_case_insensitive = -1;
static int hf_nfs3_pathconf_case_preserving = -1;
static int hf_nfs3_gxfh_utlfield = -1;
static int hf_nfs3_gxfh_utlfield_tree_r = -1;
static int hf_nfs3_gxfh_utlfield_tree_w = -1;
static int hf_nfs3_gxfh_utlfield_jun = -1;
static int hf_nfs3_gxfh_utlfield_jun_not = -1;
static int hf_nfs3_gxfh_utlfield_ver = -1;
static int hf_nfs3_gxfh_volcnt = -1;
static int hf_nfs3_gxfh_epoch = -1;
static int hf_nfs3_gxfh_ldsid = -1;
static int hf_nfs3_gxfh_cid = -1;
static int hf_nfs3_gxfh_resv = -1;
static int hf_nfs3_gxfh_sfhflags = -1;
static int hf_nfs3_gxfh_sfhflags_resv1 = -1;
static int hf_nfs3_gxfh_sfhflags_resv2 = -1;
static int hf_nfs3_gxfh_sfhflags_ontap7G = -1;
static int hf_nfs3_gxfh_sfhflags_ontapGX = -1;
static int hf_nfs3_gxfh_sfhflags_striped = -1;
static int hf_nfs3_gxfh_sfhflags_empty = -1;
static int hf_nfs3_gxfh_sfhflags_snapdirent = -1;
static int hf_nfs3_gxfh_sfhflags_snapdir = -1;
static int hf_nfs3_gxfh_sfhflags_streamdir = -1;
static int hf_nfs3_gxfh_spinfid = -1;
static int hf_nfs3_gxfh_spinfuid = -1;
static int hf_nfs3_gxfh_exportptid = -1;
static int hf_nfs3_gxfh_exportptuid = -1;


/* NFSv4 RFC 5661 header format variables */
static int hf_nfs4_procedure = -1;
static int hf_nfs4_status = -1;
static int hf_nfs4_op = -1;
static int hf_nfs4_main_opcode = -1;
static int hf_nfs4_linktext = -1;
static int hf_nfs4_tag = -1;
static int hf_nfs4_ops_count = -1;
static int hf_nfs4_component = -1;
static int hf_nfs4_clientid = -1;
/* static int hf_nfs4_ace = -1; */
static int hf_nfs4_recall = -1;
static int hf_nfs4_open_claim_type = -1;
static int hf_nfs4_opentype = -1;
static int hf_nfs4_state_protect_how = -1;
static int hf_nfs4_limit_by = -1;
static int hf_nfs4_open_delegation_type = -1;
static int hf_nfs4_why_no_delegation = -1;
static int hf_nfs4_ftype = -1;
static int hf_nfs4_change_info_atomic = -1;
static int hf_nfs4_open_share_access = -1;
static int hf_nfs4_open_share_deny = -1;
static int hf_nfs4_want_flags = -1;
static int hf_nfs4_want_notify_flags = -1;
static int hf_nfs4_want_signal_deleg_when_resrc_avail = -1;
static int hf_nfs4_want_push_deleg_when_uncontended = -1;
static int hf_nfs4_seqid = -1;
static int hf_nfs4_lock_seqid = -1;
static int hf_nfs4_reqd_attr = -1;
static int hf_nfs4_reco_attr = -1;
static int hf_nfs4_attr_mask = -1;
static int hf_nfs4_time_how = -1;
static int hf_nfs4_fattr_link_support = -1;
static int hf_nfs4_fattr_symlink_support = -1;
static int hf_nfs4_fattr_named_attr = -1;
static int hf_nfs4_fattr_unique_handles = -1;
static int hf_nfs4_fattr_archive = -1;
static int hf_nfs4_fattr_cansettime = -1;
static int hf_nfs4_fattr_case_insensitive = -1;
static int hf_nfs4_fattr_case_preserving = -1;
static int hf_nfs4_fattr_chown_restricted = -1;
static int hf_nfs4_fattr_hidden = -1;
static int hf_nfs4_fattr_homogeneous = -1;
static int hf_nfs4_fattr_mimetype = -1;
static int hf_nfs4_fattr_no_trunc = -1;
static int hf_nfs4_fattr_system = -1;
static int hf_nfs4_fattr_owner = -1;
static int hf_nfs4_fattr_owner_group = -1;
static int hf_nfs4_fattr_size = -1;
static int hf_nfs4_fattr_aclsupport = -1;
static int hf_nfs4_fattr_lease_time = -1;
static int hf_nfs4_fattr_fileid = -1;
static int hf_nfs4_fattr_files_avail = -1;
static int hf_nfs4_fattr_files_free = -1;
static int hf_nfs4_fattr_files_total = -1;
static int hf_nfs4_fattr_maxfilesize = -1;
static int hf_nfs4_fattr_maxlink = -1;
static int hf_nfs4_fattr_maxname = -1;
static int hf_nfs4_fattr_numlinks = -1;
static int hf_nfs4_fattr_maxread = -1;
static int hf_nfs4_fattr_maxwrite = -1;
static int hf_nfs4_fattr_quota_hard = -1;
static int hf_nfs4_fattr_quota_soft = -1;
static int hf_nfs4_fattr_quota_used = -1;
static int hf_nfs4_fattr_space_avail = -1;
static int hf_nfs4_fattr_space_free = -1;
static int hf_nfs4_fattr_space_total = -1;
static int hf_nfs4_fattr_space_used = -1;
static int hf_nfs4_fattr_mounted_on_fileid = -1;
static int hf_nfs4_fattr_layout_blksize = -1;
static int hf_nfs4_fattr_security_label_lfs = -1;
static int hf_nfs4_fattr_security_label_pi = -1;
static int hf_nfs4_fattr_security_label_context = -1;
static int hf_nfs4_who = -1;
static int hf_nfs4_server = -1;
static int hf_nfs4_fslocation = -1;
static int hf_nfs4_stable_how = -1;
static int hf_nfs4_dirlist_eof = -1;
/* static int hf_nfs4_stateid = -1; */
static int hf_nfs4_offset = -1;
static int hf_nfs4_specdata1 = -1;
static int hf_nfs4_specdata2 = -1;
static int hf_nfs4_lock_type = -1;
static int hf_nfs4_open_rflags = -1;
static int hf_nfs4_open_rflags_mlock = -1;
static int hf_nfs4_open_rflags_confirm = -1;
static int hf_nfs4_reclaim = -1;
static int hf_nfs4_length = -1;
static int hf_nfs4_changeid = -1;
static int hf_nfs4_changeid_before = -1;
static int hf_nfs4_changeid_after = -1;
static int hf_nfs4_time_seconds = -1;
static int hf_nfs4_time_nseconds = -1;
static int hf_nfs4_fsid_major = -1;
static int hf_nfs4_fsid_minor = -1;
static int hf_nfs4_acetype = -1;
static int hf_nfs4_aceflags = -1;
static int hf_nfs4_aceflag = -1;
static int hf_nfs4_acemask = -1;
static int hf_nfs4_ace_permission = -1;
static int hf_nfs4_delegate_type = -1;
static int hf_nfs4_secinfo_flavor = -1;
static int hf_nfs4_secinfo_arr = -1;
static int hf_nfs4_num_blocks = -1;
static int hf_nfs4_bytes_per_block = -1;
static int hf_nfs4_eof = -1;
static int hf_nfs4_verifier = -1;
static int hf_nfs4_value_follows = -1;
static int hf_nfs4_cookie = -1;
static int hf_nfs4_dir_entry_name = -1;
static int hf_nfs4_cookie_verf = -1;
static int hf_nfs4_cb_program = -1;
/* static int hf_nfs4_cb_location = -1; */
static int hf_nfs4_recall4 = -1;
static int hf_nfs4_filesize = -1;
static int hf_nfs4_count = -1;
static int hf_nfs4_count_dircount = -1;
static int hf_nfs4_count_maxcount = -1;
static int hf_nfs4_minorversion = -1;
static int hf_nfs4_open_owner = -1;
/* static int hf_nfs4_lock_owner = -1; */
static int hf_nfs4_new_lock_owner = -1;
static int hf_nfs4_sec_oid = -1;
static int hf_nfs4_qop = -1;
static int hf_nfs4_secinfo_rpcsec_gss_info_service = -1;
static int hf_nfs4_attr_dir_create = -1;
static int hf_nfs4_client_id = -1;
static int hf_nfs4_stateid_other = -1;
static int hf_nfs4_stateid_hash = -1;
static int hf_nfs4_lock_reclaim = -1;
static int hf_nfs4_acl = -1;
static int hf_nfs4_num_aces = -1;
static int hf_nfs4_callback_ident = -1;
static int hf_nfs4_r_netid = -1;
static int hf_nfs4_gsshandle = -1;
static int hf_nfs4_r_addr = -1;
static int hf_nfs4_createmode = -1;
static int hf_nfs4_op_mask = -1;
static int hf_nfs4_read_data_length = -1;
static int hf_nfs4_write_data_length = -1;
static int hf_nfs4_length_minlength = -1;
static int hf_nfs4_layout_type = -1;
static int hf_nfs4_layout_return_type = -1;
static int hf_nfs4_iomode = -1;
/* static int hf_nfs4_stripetype = -1; */
/* static int hf_nfs4_mdscommit = -1; */
/* static int hf_nfs4_stripeunit = -1; */
static int hf_nfs4_newtime = -1;
static int hf_nfs4_newoffset = -1;
static int hf_nfs4_layout_avail = -1;
static int hf_nfs4_newsize = -1;
static int hf_nfs4_layoutupdate = -1;
static int hf_nfs4_deviceid = -1;
static int hf_nfs4_devicenum = -1;
static int hf_nfs4_deviceidx = -1;
static int hf_nfs4_layout = -1;
/* static int hf_nfs4_stripedevs = -1; */
/* static int hf_nfs4_devaddr = -1; */
static int hf_nfs4_return_on_close = -1;
static int hf_nfs4_slotid = -1;
static int hf_nfs4_high_slotid = -1;
static int hf_nfs4_target_high_slotid = -1;
static int hf_nfs4_serverscope4 = -1;
static int hf_nfs4_minorid = -1;
static int hf_nfs4_majorid = -1;
static int hf_nfs4_padsize = -1;
/* static int hf_nfs4_cbrenforce = -1; */
/* static int hf_nfs4_hashalg = -1; */
/* static int hf_nfs4_ssvlen = -1; */
static int hf_nfs4_maxreqsize = -1;
static int hf_nfs4_maxrespsize = -1;
static int hf_nfs4_maxrespsizecached = -1;
static int hf_nfs4_maxops = -1;
static int hf_nfs4_maxreqs = -1;
static int hf_nfs4_rdmachanattrs = -1;
static int hf_nfs4_machinename = -1;
static int hf_nfs4_flavor = -1;
static int hf_nfs4_stamp = -1;
static int hf_nfs4_uid = -1;
static int hf_nfs4_gid = -1;
static int hf_nfs4_service = -1;
static int hf_nfs4_sessionid = -1;
static int hf_nfs4_exchid_call_flags = -1;
static int hf_nfs4_exchid_reply_flags = -1;
static int hf_nfs4_exchid_flags_moved_refer = -1;
static int hf_nfs4_exchid_flags_moved_migr = -1;
static int hf_nfs4_exchid_flags_bind_princ = -1;
static int hf_nfs4_exchid_flags_non_pnfs = -1;
static int hf_nfs4_exchid_flags_pnfs_mds = -1;
static int hf_nfs4_exchid_flags_pnfs_ds = -1;
static int hf_nfs4_exchid_flags_upd_conf_rec_a = -1;
static int hf_nfs4_exchid_flags_confirmed_r = -1;
static int hf_nfs4_state_protect_window = -1;
static int hf_nfs4_state_protect_num_gss_handles = -1;
static int hf_nfs4_prot_info_spi_window = -1;
static int hf_nfs4_prot_info_svv_length = -1;
static int hf_nfs4_prot_info_encr_alg = -1;
static int hf_nfs4_prot_info_hash_alg = -1;
static int hf_nfs4_nii_domain = -1;
static int hf_nfs4_nii_name = -1;
static int hf_nfs4_create_session_flags_csa = -1;
static int hf_nfs4_create_session_flags_csr = -1;
static int hf_nfs4_create_session_flags_persist = -1;
static int hf_nfs4_create_session_flags_conn_back_chan = -1;
static int hf_nfs4_create_session_flags_conn_rdma = -1;
static int hf_nfs4_cachethis = -1;
/* static int hf_nfs4_util = -1; */
/* static int hf_nfs4_first_stripe_idx = -1; */
/* static int hf_nfs4_layout_count = -1; */
/* static int hf_nfs4_pattern_offset = -1; */
static int hf_nfs4_notification_bitmap = -1;
static int hf_nfs4_lrs_present = -1;
static int hf_nfs4_nfl_util = -1;
static int hf_nfs4_nfl_first_stripe_index = -1;
static int hf_nfs4_lrf_body_content = -1;
static int hf_nfs4_reclaim_one_fs = -1;
static int hf_nfs4_bctsa_dir = -1;
static int hf_nfs4_bctsa_use_conn_in_rdma_mode = -1;
static int hf_nfs4_bctsr_dir = -1;
static int hf_nfs4_bctsr_use_conn_in_rdma_mode = -1;
static int hf_nfs4_sequence_status_flags = -1;
static int hf_nfs4_sequence_status_flags_cb_path_down = -1;
static int hf_nfs4_sequence_status_flags_cb_gss_contexts_expiring = -1;
static int hf_nfs4_sequence_status_flags_cb_gss_contexts_expired = -1;
static int hf_nfs4_sequence_status_flags_expired_all_state_revoked = -1;
static int hf_nfs4_sequence_status_flags_expired_some_state_revoked = -1;
static int hf_nfs4_sequence_status_flags_admin_state_revoked = -1;
static int hf_nfs4_sequence_status_flags_recallable_state_revoked = -1;
static int hf_nfs4_sequence_status_flags_lease_moved = -1;
static int hf_nfs4_sequence_status_flags_restart_reclaim_needed = -1;
static int hf_nfs4_sequence_status_flags_cb_path_down_session = -1;
static int hf_nfs4_sequence_status_flags_backchannel_fault = -1;
static int hf_nfs4_sequence_status_flags_devid_changed = -1;
static int hf_nfs4_sequence_status_flags_devid_deleted = -1;
static int hf_nfs4_secinfo_style = -1;
static int hf_nfs4_test_stateid_arg = -1;
static int hf_nfs4_test_stateid_res = -1;
/* static int hf_nfs4_impl_id_len = -1; */


static gint ett_nfs = -1;
static gint ett_nfs_fh_encoding = -1;
static gint ett_nfs_fh_mount = -1;
static gint ett_nfs_fh_file = -1;
static gint ett_nfs_fh_export = -1;
static gint ett_nfs_fh_fsid = -1;
static gint ett_nfs_fh_xfsid = -1;
static gint ett_nfs_fh_fn = -1;
static gint ett_nfs_fh_xfn = -1;
static gint ett_nfs_fh_hp = -1;
static gint ett_nfs_fh_auth = -1;
static gint ett_nfs_fhandle = -1;
static gint ett_nfs_timeval = -1;
static gint ett_nfs_fattr = -1;
static gint ett_nfs_readdir_entry = -1;
static gint ett_nfs_fh_obj = -1;
static gint ett_nfs_fh_ex = -1;
static gint ett_nfs_utf8string = -1;

static gint ett_nfs2_mode = -1;
static gint ett_nfs2_sattr = -1;
static gint ett_nfs2_diropargs = -1;

static gint ett_nfs3_mode = -1;
static gint ett_nfs3_specdata = -1;
static gint ett_nfs3_fh = -1;
static gint ett_nfs3_nfstime = -1;
static gint ett_nfs3_fattr = -1;
static gint ett_nfs3_post_op_fh = -1;
static gint ett_nfs3_sattr = -1;
static gint ett_nfs3_diropargs = -1;
static gint ett_nfs3_sattrguard = -1;
static gint ett_nfs3_set_mode = -1;
static gint ett_nfs3_set_uid = -1;
static gint ett_nfs3_set_gid = -1;
static gint ett_nfs3_set_size = -1;
static gint ett_nfs3_set_atime = -1;
static gint ett_nfs3_set_mtime = -1;
static gint ett_nfs3_pre_op_attr = -1;
static gint ett_nfs3_post_op_attr = -1;
static gint ett_nfs3_wcc_attr = -1;
static gint ett_nfs3_wcc_data = -1;
static gint ett_nfs3_access = -1;
static gint ett_nfs3_fsinfo_properties = -1;
static gint ett_nfs3_gxfh_utlfield = -1;
static gint ett_nfs3_gxfh_sfhfield = -1;
static gint ett_nfs3_gxfh_sfhflags = -1;

static gint ett_nfs4_compound_call = -1;
static gint ett_nfs4_request_op = -1;
static gint ett_nfs4_response_op = -1;
static gint ett_nfs4_access = -1;
static gint ett_nfs4_access_supp = -1;
static gint ett_nfs4_close = -1;
static gint ett_nfs4_commit = -1;
static gint ett_nfs4_create = -1;
static gint ett_nfs4_delegpurge = -1;
static gint ett_nfs4_delegreturn = -1;
static gint ett_nfs4_getattr = -1;
static gint ett_nfs4_getattr_args = -1;
static gint ett_nfs4_getattr_resp = -1;
static gint ett_nfs4_resok4 = -1;
static gint ett_nfs4_obj_attrs = -1;
static gint ett_nfs4_fattr_new_attr_vals = -1;
static gint ett_nfs4_fattr4_attrmask = -1;
static gint ett_nfs4_attribute = -1;
static gint ett_nfs4_getfh = -1;
static gint ett_nfs4_link = -1;
static gint ett_nfs4_lock = -1;
static gint ett_nfs4_lockt = -1;
static gint ett_nfs4_locku = -1;
static gint ett_nfs4_lookup = -1;
static gint ett_nfs4_lookupp = -1;
static gint ett_nfs4_nverify = -1;
static gint ett_nfs4_open = -1;
static gint ett_nfs4_openattr = -1;
static gint ett_nfs4_open_confirm = -1;
static gint ett_nfs4_open_downgrade = -1;
static gint ett_nfs4_putfh = -1;
static gint ett_nfs4_putpubfh = -1;
static gint ett_nfs4_putrootfh = -1;
static gint ett_nfs4_read = -1;
static gint ett_nfs4_readdir = -1;
static gint ett_nfs4_readlink = -1;
static gint ett_nfs4_remove = -1;
static gint ett_nfs4_rename = -1;
static gint ett_nfs4_renew = -1;
static gint ett_nfs4_restorefh = -1;
static gint ett_nfs4_savefh = -1;
static gint ett_nfs4_secinfo = -1;
static gint ett_nfs4_setattr = -1;
static gint ett_nfs4_setclientid = -1;
static gint ett_nfs4_setclientid_confirm = -1;
static gint ett_nfs4_verify = -1;
static gint ett_nfs4_write = -1;
static gint ett_nfs4_release_lockowner = -1;
static gint ett_nfs4_backchannel_ctl = -1;
static gint ett_nfs4_illegal = -1;
static gint ett_nfs4_verifier = -1;
static gint ett_nfs4_dirlist = -1;
static gint ett_nfs4_dir_entry = -1;
static gint ett_nfs4_pathname = -1;
static gint ett_nfs4_change_info = -1;
static gint ett_nfs4_open_delegation = -1;
static gint ett_nfs4_open_claim = -1;
static gint ett_nfs4_opentype = -1;
static gint ett_nfs4_lock_owner = -1;
static gint ett_nfs4_cb_client = -1;
static gint ett_nfs4_client_id = -1;
static gint ett_nfs4_clientowner = -1;
static gint ett_nfs4_exchangeid_call_flags = -1;
static gint ett_nfs4_exchangeid_reply_flags = -1;
static gint ett_nfs4_server_owner = -1;
static gint ett_nfs4_bitmap = -1;
static gint ett_nfs4_attr_request = -1;
static gint ett_nfs4_fattr = -1;
static gint ett_nfs4_fsid = -1;
static gint ett_nfs4_fs_locations = -1;
static gint ett_nfs4_fs_location = -1;
static gint ett_nfs4_open_result_flags = -1;
static gint ett_nfs4_secinfo_flavor_info = -1;
static gint ett_nfs4_stateid = -1;
static gint ett_nfs4_fattr_fh_expire_type = -1;
static gint ett_nfs4_ace = -1;
static gint ett_nfs4_clientaddr = -1;
static gint ett_nfs4_aceflag = -1;
static gint ett_nfs4_acemask = -1;
static gint ett_nfs4_create_session_flags = -1;
static gint ett_nfs4_sequence_status_flags = -1;
static gint ett_nfs4_fh_file   = -1;
static gint ett_nfs4_fh_file_flags = -1;
static gint ett_nfs4_fh_export = -1;
static gint ett_nfs4_layoutget = -1;
static gint ett_nfs4_layoutcommit = -1;
static gint ett_nfs4_layoutreturn = -1;
static gint ett_nfs4_getdevinfo = -1;
static gint ett_nfs4_getdevlist = -1;
static gint ett_nfs4_bind_conn_to_session = -1;
static gint ett_nfs4_exchange_id = -1;
static gint ett_nfs4_create_session = -1;
static gint ett_nfs4_destroy_session = -1;
static gint ett_nfs4_free_stateid = -1;
static gint ett_nfs4_secinfo_no_name = -1;
static gint ett_nfs4_sequence = -1;
static gint ett_nfs4_slotid = -1;
static gint ett_nfs4_sr_status = -1;
static gint ett_nfs4_serverscope = -1;
static gint ett_nfs4_minorid = -1;
static gint ett_nfs4_majorid = -1;
static gint ett_nfs4_persist = -1;
static gint ett_nfs4_backchan = -1;
static gint ett_nfs4_rdmamode = -1;
static gint ett_nfs4_padsize = -1;
static gint ett_nfs4_cbrenforce = -1;
static gint ett_nfs4_hashalg = -1;
static gint ett_nfs4_ssvlen = -1;
static gint ett_nfs4_maxreqsize = -1;
static gint ett_nfs4_maxrespsize = -1;
static gint ett_nfs4_maxrespsizecached = -1;
static gint ett_nfs4_maxops = -1;
static gint ett_nfs4_maxreqs = -1;
static gint ett_nfs4_streamchanattrs = -1;
static gint ett_nfs4_rdmachanattrs = -1;
static gint ett_nfs4_machinename = -1;
static gint ett_nfs4_flavor = -1;
static gint ett_nfs4_stamp = -1;
static gint ett_nfs4_uid = -1;
static gint ett_nfs4_gid = -1;
static gint ett_nfs4_service = -1;
static gint ett_nfs4_sessionid = -1;
static gint ett_nfs4_layoutseg = -1;
static gint ett_nfs4_layoutseg_fh = -1;
static gint ett_nfs4_test_stateid = -1;
static gint ett_nfs4_destroy_clientid = -1;
static gint ett_nfs4_reclaim_complete = -1;
static gint ett_nfs4_chan_attrs = -1;
static gint ett_nfs4_want_notify_flags = -1;

static expert_field ei_nfs_too_many_ops = EI_INIT;
static expert_field ei_nfs_not_vnx_file = EI_INIT;


/* Types of fhandles we can dissect */
static dissector_table_t nfs_fhandle_table;

#define FHT_UNKNOWN          0
#define FHT_SVR4             1
#define FHT_LINUX_KNFSD_LE   2
#define FHT_LINUX_NFSD_LE    3
#define FHT_LINUX_KNFSD_NEW  4
#define FHT_NETAPP           5
#define FHT_NETAPP_V4        6
#define FHT_NETAPP_GX_V3     7
#define FHT_CELERRA_VNX      8
#define FHT_GLUSTER          9

static const enum_val_t nfs_fhandle_types[] = {
	{ "unknown",     "Unknown",     FHT_UNKNOWN },
	{ "svr4",        "SVR4",        FHT_SVR4 },
	{ "knfsd_le",    "KNFSD_LE",    FHT_LINUX_KNFSD_LE },
	{ "nfsd_le",     "NFSD_LE",     FHT_LINUX_NFSD_LE },
	{ "knfsd_new",   "KNFSD_NEW",   FHT_LINUX_KNFSD_NEW },
	{ "ontap_v3",    "ONTAP_V3",    FHT_NETAPP },
	{ "ontap_v4",    "ONTAP_V4",    FHT_NETAPP_V4},
	{ "ontap_gx_v3", "ONTAP_GX_V3", FHT_NETAPP_GX_V3},
	{ "celerra_vnx", "CELERRA_VNX", FHT_CELERRA_VNX },
	{ "gluster",     "GLUSTER",     FHT_GLUSTER },
	{ NULL, NULL, 0 }
};
/* decode all nfs filehandles as this type */
static gint default_nfs_fhandle_type = FHT_UNKNOWN;

typedef struct nfs_fhandle_data {
	int len;
	const unsigned char *fh;
} nfs_fhandle_data_t;

/* For dissector helpers which take a "levels" argument to indicate how
 * many expansions up they should populate the expansion items with
 * text to enhance useability, this flag to "levels" specify that the
 * text should also be appended to COL_INFO
 */
#define COL_INFO_LEVEL 0x80000000


/* fhandle displayfilters to match also corresponding request/response
   packet in addition to the one containing the actual filehandle */
gboolean nfs_fhandle_reqrep_matching = FALSE;
static wmem_tree_t *nfs_fhandle_frame_table = NULL;


/* file name snooping */
gboolean nfs_file_name_snooping = FALSE;
static gboolean nfs_file_name_full_snooping = FALSE;
typedef struct nfs_name_snoop {
	int	       fh_length;
	unsigned char *fh;
	int	       name_len;
	char	      *name;
	int	       parent_len;
	unsigned char *parent;
	int	       full_name_len;
	char	      *full_name;
} nfs_name_snoop_t;

typedef struct nfs_name_snoop_key {
	int key;
	int fh_length;
	const unsigned char *fh;
} nfs_name_snoop_key_t;

static GHashTable *nfs_name_snoop_unmatched = NULL;

static GHashTable *nfs_name_snoop_matched = NULL;

static wmem_tree_t *nfs_name_snoop_known = NULL;
static wmem_tree_t *nfs_file_handles = NULL;

static gboolean nfs_display_v4_tag = TRUE;
static gboolean display_major_nfs4_ops = TRUE;

static int dissect_nfs4_stateid(tvbuff_t *tvb, int offset, proto_tree *tree, guint16 *hash);

static void reg_callback(int cbprog);

/* This function will store one nfs filehandle in our global tree of
 * filehandles.
 * We store all filehandles we see in this tree so that every unique
 * filehandle is only stored once with a unique pointer.
 * We need to store pointers to filehandles in several of our other
 * structures and this is a way to make sure we don't keep any redundant
 * copies around for a specific filehandle.
 *
 * If this is the first time this filehandle has been seen an se block
 * is allocated to store the filehandle in.
 * If this filehandle has already been stored in the tree this function returns
 * a pointer to the original copy.
 */
static nfs_fhandle_data_t *
store_nfs_file_handle(nfs_fhandle_data_t *nfs_fh)
{
	guint32		    fhlen;
	guint32		   *fhdata;
	wmem_tree_key_t	    fhkey[3];
	nfs_fhandle_data_t *new_nfs_fh;

	fhlen = nfs_fh->len/4;
	/* align the file handle data */
	fhdata = (guint32 *)g_memdup(nfs_fh->fh, fhlen*4);
	fhkey[0].length = 1;
	fhkey[0].key	= &fhlen;
	fhkey[1].length = fhlen;
	fhkey[1].key	= fhdata;
	fhkey[2].length = 0;

	new_nfs_fh = (nfs_fhandle_data_t *)wmem_tree_lookup32_array(nfs_file_handles, &fhkey[0]);
	if (new_nfs_fh) {
		g_free(fhdata);
		return new_nfs_fh;
	}

	new_nfs_fh = wmem_new(wmem_file_scope(), nfs_fhandle_data_t);
	new_nfs_fh->len = nfs_fh->len;
	new_nfs_fh->fh = (const unsigned char *)wmem_alloc(wmem_file_scope(), sizeof(guint32)*(nfs_fh->len/4));
	memcpy((void *)new_nfs_fh->fh, nfs_fh->fh, nfs_fh->len);
	fhlen = nfs_fh->len/4;
	fhkey[0].length = 1;
	fhkey[0].key	= &fhlen;
	fhkey[1].length = fhlen;
	fhkey[1].key	= fhdata;
	fhkey[2].length = 0;
	wmem_tree_insert32_array(nfs_file_handles, &fhkey[0], new_nfs_fh);

	g_free(fhdata);
	return new_nfs_fh;
}


static gint
nfs_name_snoop_matched_equal(gconstpointer k1, gconstpointer k2)
{
	const nfs_name_snoop_key_t *key1 = (const nfs_name_snoop_key_t *)k1;
	const nfs_name_snoop_key_t *key2 = (const nfs_name_snoop_key_t *)k2;

	return (key1->key == key2->key)
	     &&(key1->fh_length == key2->fh_length)
	     &&(!memcmp(key1->fh, key2->fh, key1->fh_length));
}


static guint
nfs_name_snoop_matched_hash(gconstpointer k)
{
	const nfs_name_snoop_key_t *key = (const nfs_name_snoop_key_t *)k;
	int i;
	guint hash;

	hash = key->key;
	for (i=0; i<key->fh_length; i++)
		hash ^= key->fh[i];

	return hash;
}


static gint
nfs_name_snoop_unmatched_equal(gconstpointer k1, gconstpointer k2)
{
	guint32 key1 = GPOINTER_TO_UINT(k1);
	guint32 key2 = GPOINTER_TO_UINT(k2);

	return key1 == key2;
}


static guint
nfs_name_snoop_unmatched_hash(gconstpointer k)
{
	guint32 key = GPOINTER_TO_UINT(k);

	return key;
}


static gboolean
nfs_name_snoop_unmatched_free_all(gpointer key_arg _U_, gpointer value, gpointer user_data _U_)
{
	nfs_name_snoop_t *nns = (nfs_name_snoop_t *)value;

	if (nns->name) {
		g_free((gpointer)nns->name);
		nns->name = NULL;
		nns->name_len = 0;
	}
	if (nns->full_name) {
		g_free((gpointer)nns->full_name);
		nns->full_name = NULL;
		nns->full_name_len = 0;
	}
	if (nns->parent) {
		g_free((gpointer)nns->parent);
		nns->parent = NULL;
		nns->parent_len = 0;
	}
	if (nns->fh) {
		g_free((gpointer)nns->fh);
		nns->fh = NULL;
		nns->fh_length = 0;
	}
	g_free(nns);
	return TRUE;
}


static void
nfs_name_snoop_init(void)
{
	if (nfs_name_snoop_unmatched != NULL) {
		g_hash_table_foreach_remove(nfs_name_snoop_unmatched,
				nfs_name_snoop_unmatched_free_all, NULL);
	} else {
		/* The fragment table does not exist. Create it */
		nfs_name_snoop_unmatched = g_hash_table_new(nfs_name_snoop_unmatched_hash,
			nfs_name_snoop_unmatched_equal);
	}
	if (nfs_name_snoop_matched != NULL) {
		g_hash_table_foreach_remove(nfs_name_snoop_matched,
				nfs_name_snoop_unmatched_free_all, NULL);
	} else {
		/* The fragment table does not exist. Create it */
		nfs_name_snoop_matched = g_hash_table_new(nfs_name_snoop_matched_hash,
			nfs_name_snoop_matched_equal);
	}
}


void
nfs_name_snoop_add_name(int xid, tvbuff_t *tvb, int name_offset, int name_len, int parent_offset,
			int parent_len, const char *name)
{
	nfs_name_snoop_t *nns, *old_nns;
	const char	 *ptr;

	if (name_len <= 0) {
		/* Do we need some way to signal an error here? This could be
		 * programmatic or just a corrupt packet, depending on the
		 * caller... */
		return;
	}

	/* filter out all '.' and '..' names */
	if (!name) {
		ptr = (const char *)tvb_get_ptr(tvb, name_offset, name_len);
	} else {
		ptr = name;
	}
	if (ptr[0] == '.') {
		if (name_len <= 1 || ptr[1] == 0) {
			return;
		}
		if (ptr[1] == '.') {
			if (name_len <= 2 || ptr[2] == 0) {
				return;
			}
		}
	}

	nns = g_new(nfs_name_snoop_t, 1);

	nns->fh_length = 0;
	nns->fh = NULL;

	if (parent_len) {
		nns->parent_len = parent_len;
		nns->parent = (unsigned char *)tvb_memdup(NULL, tvb, parent_offset, parent_len);
	} else {
		nns->parent_len = 0;
		nns->parent = NULL;
	}

	if (name) {
		nns->name_len = (int)strlen(name);
		nns->name = g_strdup(name);
	} else {
		nns->name_len = name_len;
		nns->name = (char *)g_malloc(name_len+1);
		memcpy(nns->name, ptr, name_len);
	}
	nns->name[nns->name_len] = 0;

	nns->full_name_len = 0;
	nns->full_name = NULL;

	/* remove any old entry for this */
	old_nns = (nfs_name_snoop_t *)g_hash_table_lookup(nfs_name_snoop_unmatched, GINT_TO_POINTER(xid));
	if (old_nns) {
		/* if we haven't seen the reply yet, then there are no
		   matched entries for it, thus we can dealloc the arrays*/
		if (!old_nns->fh) {
			g_free(old_nns->name);
			old_nns->name = NULL;
			old_nns->name_len = 0;

			g_free(old_nns->parent);
			old_nns->parent = NULL;
			old_nns->parent_len = 0;
		}
		g_free(old_nns);
		g_hash_table_remove(nfs_name_snoop_unmatched, GINT_TO_POINTER(xid));
	}

	g_hash_table_insert(nfs_name_snoop_unmatched, GINT_TO_POINTER(xid), nns);
}


static void
nfs_name_snoop_add_fh(int xid, tvbuff_t *tvb, int fh_offset, int fh_length)
{
	unsigned char	     *fh;
	nfs_name_snoop_t     *nns, *old_nns;
	nfs_name_snoop_key_t *key;

	/* find which request we correspond to */
	nns = (nfs_name_snoop_t *)g_hash_table_lookup(nfs_name_snoop_unmatched, GINT_TO_POINTER(xid));
	if (!nns) {
		/* oops couldnt find matching request, bail out */
		return;
	}

	/* if we have already seen this response earlier */
	if (nns->fh) {
		return;
	}

	/* oki, we have a new entry */
	fh = (unsigned char *)tvb_memdup(NULL, tvb, fh_offset, fh_length);
	nns->fh = fh;
	nns->fh_length = fh_length;

	key = wmem_new(wmem_file_scope(), nfs_name_snoop_key_t);
	key->key = 0;
	key->fh_length = nns->fh_length;
	key->fh = nns->fh;

	/* already have something matched for this fh, remove it from
	   the table */
	old_nns = (nfs_name_snoop_t *)g_hash_table_lookup(nfs_name_snoop_matched, key);
	if (old_nns) {
		g_hash_table_remove(nfs_name_snoop_matched, key);
	}

	g_hash_table_remove(nfs_name_snoop_unmatched, GINT_TO_POINTER(xid));
	g_hash_table_insert(nfs_name_snoop_matched, key, nns);
}


static void
nfs_full_name_snoop(nfs_name_snoop_t *nns, int *len, char **name, char **pos)
{
	nfs_name_snoop_t     *parent_nns = NULL;
	nfs_name_snoop_key_t  key;

	/* check if the nns component ends with a '/' else we just allocate
	   an extra byte to len to accommodate for it later */
	if (nns->name[nns->name_len-1] != '/') {
		(*len)++;
	}

	(*len) += nns->name_len;

	if (nns->parent == NULL) {
		*name = (char *)g_malloc((*len)+1);
		*pos = *name;

		*pos += g_snprintf(*pos, (*len)+1, "%s", nns->name);
		DISSECTOR_ASSERT((*pos-*name) <= *len);
		return;
	}

	key.key = 0;
	key.fh_length = nns->parent_len;
	key.fh = nns->parent;

	parent_nns = (nfs_name_snoop_t *)g_hash_table_lookup(nfs_name_snoop_matched, &key);

	if (parent_nns) {
		nfs_full_name_snoop(parent_nns, len, name, pos);
		if (*name) {
			/* make sure components are '/' separated */
			*pos += g_snprintf(*pos, (*len+1) - (gulong)(*pos-*name), "%s%s",
					   ((*pos)[-1] != '/')?"/":"", nns->name);
			DISSECTOR_ASSERT((*pos-*name) <= *len);
		}
		return;
	}

	return;
}


static void
nfs_name_snoop_fh(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int fh_offset,
				  int fh_length, gboolean hidden)
{
	nfs_name_snoop_key_t  key;
	nfs_name_snoop_t     *nns = NULL;

	/* if this is a new packet, see if we can register the mapping */
	if (!pinfo->fd->flags.visited) {
		key.key = 0;
		key.fh_length = fh_length;
		key.fh = (const unsigned char *)tvb_get_ptr(tvb, fh_offset, fh_length);

		nns = (nfs_name_snoop_t *)g_hash_table_lookup(nfs_name_snoop_matched, &key);
		if (nns) {
			guint32 fhlen;
			guint32 *fhdata;
			wmem_tree_key_t fhkey[3];

			fhlen = nns->fh_length;
			/* align it */
			fhdata = (guint32 *)g_memdup(nns->fh, fhlen);
			fhkey[0].length = 1;
			fhkey[0].key	= &fhlen;
			fhkey[1].length = fhlen/4;
			fhkey[1].key	= fhdata;
			fhkey[2].length = 0;
			wmem_tree_insert32_array(nfs_name_snoop_known, &fhkey[0], nns);
			g_free(fhdata);

			if (nfs_file_name_full_snooping) {
				char *name = NULL, *pos = NULL;
				int len = 0;

				nfs_full_name_snoop(nns, &len, &name, &pos);
				if (name) {
					nns->full_name = name;
					nns->full_name_len = len;
				}
			}
		}
	}

	/* see if we know this mapping */
	if (!nns) {
		guint32 fhlen;
		guint32 *fhdata;
		wmem_tree_key_t fhkey[3];

		fhlen = fh_length;
		/* align it */
		fhdata = (guint32 *)tvb_memdup(NULL, tvb, fh_offset, fh_length);
		fhkey[0].length = 1;
		fhkey[0].key	= &fhlen;
		fhkey[1].length = fhlen/4;
		fhkey[1].key	= fhdata;
		fhkey[2].length = 0;

		nns = (nfs_name_snoop_t *)wmem_tree_lookup32_array(nfs_name_snoop_known, &fhkey[0]);
		g_free(fhdata);
	}

	/* if we know the mapping, print the filename */
	if (nns) {
		proto_item *fh_item = NULL;

		if (hidden) {
			fh_item = proto_tree_add_string(tree, hf_nfs_name, NULL,
				0, 0, nns->name);
			PROTO_ITEM_SET_HIDDEN(fh_item);
		} else {
			fh_item = proto_tree_add_string_format_value(tree, hf_nfs_name, tvb,
				fh_offset, 0, nns->name, "%s", nns->name);
		}
		PROTO_ITEM_SET_GENERATED(fh_item);

		if (nns->full_name) {
			if (hidden) {
				fh_item = proto_tree_add_string(tree, hf_nfs_full_name, NULL,
					0, 0, nns->full_name);
				PROTO_ITEM_SET_HIDDEN(fh_item);
			} else {
				fh_item = proto_tree_add_string_format_value(tree, hf_nfs_full_name, tvb,
					fh_offset, 0, nns->full_name, "%s", nns->full_name);
			}
			PROTO_ITEM_SET_GENERATED(fh_item);
		}
	}
}


/* file handle dissection */

static const value_string names_fhtype[] =
{
	{	FHT_UNKNOWN,		"unknown"				},
	{	FHT_SVR4,		"System V R4"				},
	{	FHT_LINUX_KNFSD_LE,	"Linux knfsd (little-endian)"		},
	{	FHT_LINUX_NFSD_LE,	"Linux user-land nfsd (little-endian)"	},
	{	FHT_LINUX_KNFSD_NEW,	"Linux knfsd (new)"			},
	{	FHT_NETAPP,		"ONTAP 7G nfs v3 file handle"		},
	{	FHT_NETAPP_V4,	 	"ONTAP 7G nfs v4 file handle"		},
	{	FHT_NETAPP_GX_V3,	"ONTAP GX nfs v3 file handle"		},
	{	FHT_CELERRA_VNX,	"Celerra|VNX NFS file handle"		},
	{	FHT_GLUSTER,		"GlusterFS/NFS file handle"		},
	{	0,			NULL					}
};
static value_string_ext names_fhtype_ext = VALUE_STRING_EXT_INIT(names_fhtype);


static const true_false_string tfs_endianness = { "Little Endian", "Big Endian" };

/* SVR4: checked with ReliantUNIX (5.43, 5.44, 5.45), OpenSolaris (build 101a) */
static void
dissect_fhandle_data_SVR4(tvbuff_t* tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	gboolean little_endian;	/* We support little endian and big endian. */
	gboolean have_flag;	/* The flag field at the end is optional. */
	gboolean found;		/* Did we really detect the file handle format? */
	guint32	 nof = 0;
	guint32	 len1;
	guint32	 len2;
	guint32	 fhlen;		/* File handle length. */

	/* By default we assume big endianness. */
	little_endian = FALSE;

	/* By default, we aassume, that the flag is no there. */
	have_flag = FALSE;

	/* Not detected yet. */
	found = FALSE;

	/* Somehow this is no calling argument, so we have to re-calculate it. */
	fhlen = tvb_reported_length(tvb);

	/* Check for little endianness. */
	len1 = tvb_get_letohs(tvb, 8);
	if (tvb_bytes_exist(tvb, 10+len1, 2)) {
		len2 = tvb_get_letohs(tvb, 10+len1);

		if (12+len1+len2 == fhlen) {
			little_endian = TRUE;
			have_flag = FALSE;
			found = TRUE;
		}
		if (16+len1+len2 == fhlen) {
			little_endian = TRUE;
			have_flag = TRUE;
			found = TRUE;
		}
	}

	if (!found) {
		/* Check for big endianness. */
		len1 = tvb_get_ntohs(tvb, 8);
		if (tvb_bytes_exist(tvb, 10+len1, 2)) {
			len2 = tvb_get_ntohs(tvb, 10+len1);

			if (12+len1+len2 == fhlen) {
				little_endian = FALSE;
				have_flag = FALSE;
			}
			if (16+len1+len2 == fhlen) {
				little_endian = FALSE;
				have_flag = TRUE;
			}
		}
	}

	if (tree)
		proto_tree_add_boolean(tree, hf_nfs_fh_endianness, tvb,	0, fhlen, little_endian);

	/* We are fairly sure, that when found == FALSE, the following code will
	throw an exception. */

	/* file system id */
	{
	guint32 fsid_O;
	guint32 fsid_L;
	guint32 temp;
	guint32 fsid_major;
	guint32 fsid_minor;

	fsid_O = nof;
	fsid_L = 4;
	if (little_endian)
		temp = tvb_get_letohl(tvb, fsid_O);
	else
		temp = tvb_get_ntohl(tvb, fsid_O);
	fsid_major = ( temp>>18 ) &  0x3fff; /* 14 bits */
	fsid_minor = ( temp     ) & 0x3ffff; /* 18 bits */

	if (tree) {
		proto_item *fsid_item = NULL;
		proto_tree *fsid_tree = NULL;

		fsid_item = proto_tree_add_text(tree, tvb,
			fsid_O, fsid_L,
			"file system ID: %d,%d", fsid_major, fsid_minor);
		fsid_tree = proto_item_add_subtree(fsid_item,
					ett_nfs_fh_fsid);
		if (little_endian) {
			proto_tree_add_uint(fsid_tree, hf_nfs_fh_fsid_major,
					tvb, fsid_O+2, 2, fsid_major);
			proto_tree_add_uint(fsid_tree, hf_nfs_fh_fsid_minor,
					tvb, fsid_O,   3, fsid_minor);
		}
		else {
			proto_tree_add_uint(fsid_tree, hf_nfs_fh_fsid_major,
					tvb, fsid_O,   2, fsid_major);
			proto_tree_add_uint(fsid_tree, hf_nfs_fh_fsid_minor,
					tvb, fsid_O+1, 3, fsid_minor);
		}
	}
	nof = fsid_O + fsid_L;
	}

	/* file system type */
	{
	guint32 fstype_O;
	guint32 fstype_L;
	guint32 fstype;

	fstype_O = nof;
	fstype_L = 4;
	if (little_endian)
		fstype = tvb_get_letohl(tvb, fstype_O);
	else
		fstype = tvb_get_ntohl(tvb, fstype_O);
	if (tree) {
		proto_tree_add_uint(tree, hf_nfs_fh_fstype, tvb,
			fstype_O, fstype_L, fstype);
	}
	nof = fstype_O + fstype_L;
	}

	/* file number */
	{
	guint32 fn_O;
	guint32 fn_len_O;
	guint32 fn_len_L;
	guint32 fn_len;
	guint32 fn_data_O;
	guint32 fn_data_inode_O;
	guint32 fn_data_inode_L;
	guint32 inode;
	guint32 fn_data_gen_O;
	guint32 fn_data_gen_L;
	guint32 gen;
	guint32 fn_L;

	fn_O = nof;
	fn_len_O = fn_O;
	fn_len_L = 2;
	if (little_endian)
		fn_len = tvb_get_letohs(tvb, fn_len_O);
	else
		fn_len = tvb_get_ntohs(tvb, fn_len_O);
	fn_data_O = fn_O + fn_len_L;
	fn_data_inode_O = fn_data_O + 2;
	fn_data_inode_L = 4;
	if (little_endian)
		inode = tvb_get_letohl(tvb, fn_data_inode_O);
	else
		inode = tvb_get_ntohl(tvb, fn_data_inode_O);
	if (little_endian)
		fn_data_gen_O = fn_data_inode_O + fn_data_inode_L;
	else
		fn_data_gen_O = fn_data_inode_O + fn_data_inode_L;
	fn_data_gen_L = 4;
	if (little_endian)
		gen = tvb_get_letohl(tvb, fn_data_gen_O);
	else
		gen = tvb_get_ntohl(tvb, fn_data_gen_O);
	fn_L = fn_len_L + fn_len;
	if (tree) {
		proto_item *fn_item = NULL;
		proto_tree *fn_tree = NULL;

		fn_item = proto_tree_add_uint(tree, hf_nfs_fh_fn, tvb,
			fn_O, fn_L, inode);
		fn_tree = proto_item_add_subtree(fn_item,
					ett_nfs_fh_fn);
		proto_tree_add_uint(fn_tree, hf_nfs_fh_fn_len,
				tvb, fn_len_O, fn_len_L, fn_len);
		proto_tree_add_uint(fn_tree, hf_nfs_fh_fn_inode,
				tvb, fn_data_inode_O, fn_data_inode_L, inode);
		proto_tree_add_uint(fn_tree, hf_nfs_fh_fn_generation,
				tvb, fn_data_gen_O, fn_data_gen_L, gen);
	}
	nof = fn_O + fn_len_L + fn_len;
	}

	/* exported file number */
	{
	guint32 xfn_O;
	guint32 xfn_len_O;
	guint32 xfn_len_L;
	guint32 xfn_len;
	guint32 xfn_data_O;
	guint32 xfn_data_inode_O;
	guint32 xfn_data_inode_L;
	guint32 xinode;
	guint32 xfn_data_gen_O;
	guint32 xfn_data_gen_L;
	guint32 xgen;
	guint32 xfn_L;

	xfn_O = nof;
	xfn_len_O = xfn_O;
	xfn_len_L = 2;
	if (little_endian)
		xfn_len = tvb_get_letohs(tvb, xfn_len_O);
	else
		xfn_len = tvb_get_ntohs(tvb, xfn_len_O);
	xfn_data_O = xfn_O + xfn_len_L;
	xfn_data_inode_O = xfn_data_O + 2;
	xfn_data_inode_L = 4;
	if (little_endian)
		xinode = tvb_get_letohl(tvb, xfn_data_inode_O);
	else
		xinode = tvb_get_ntohl(tvb, xfn_data_inode_O);
	xfn_data_gen_O = xfn_data_inode_O + xfn_data_inode_L;
	xfn_data_gen_L = 4;
	if (little_endian)
		xgen = tvb_get_letohl(tvb, xfn_data_gen_O);
	else
		xgen = tvb_get_ntohl(tvb, xfn_data_gen_O);
	xfn_L = xfn_len_L + xfn_len;
	if (tree) {
		proto_item *xfn_item = NULL;
		proto_tree *xfn_tree = NULL;

		xfn_item = proto_tree_add_uint(tree, hf_nfs_fh_xfn, tvb,
			xfn_O, xfn_L, xinode);
		xfn_tree = proto_item_add_subtree(xfn_item,
					ett_nfs_fh_xfn);
		proto_tree_add_uint(xfn_tree, hf_nfs_fh_xfn_len,
				tvb, xfn_len_O, xfn_len_L, xfn_len);
		proto_tree_add_uint(xfn_tree, hf_nfs_fh_xfn_inode,
				tvb, xfn_data_inode_O, xfn_data_inode_L, xinode);
		proto_tree_add_uint(xfn_tree, hf_nfs_fh_xfn_generation,
				tvb, xfn_data_gen_O, xfn_data_gen_L, xgen);
	}
	nof = xfn_O + xfn_len_L + xfn_len;
	}

	/* flag */
	if (have_flag) {
		guint32	flag_O;
		guint32	flag_L;
		guint32	flag_value;

		flag_O = nof;
		flag_L = 4;
		if (little_endian)
			flag_value = tvb_get_letohl(tvb, flag_O);
		else
			flag_value = tvb_get_ntohl(tvb, flag_O);
		if (tree) {
			proto_tree_add_uint(tree, hf_nfs_fh_flag, tvb,
					    flag_O, flag_L, flag_value);
		}
	}
}


/* Checked with RedHat Linux 6.2 (kernel 2.2.14 knfsd) */

static void
dissect_fhandle_data_LINUX_KNFSD_LE(tvbuff_t* tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	if (tree) {
		int	offset = 0;
		guint32 dentry;
		guint32 inode;
		guint32 dirinode;
		guint32 temp;
		guint32 fsid_major;
		guint32 fsid_minor;
		guint32 xfsid_major;
		guint32 xfsid_minor;
		guint32 xinode;
		guint32 gen;

		dentry	    = tvb_get_letohl(tvb, offset+0);
		inode	    = tvb_get_letohl(tvb, offset+4);
		dirinode    = tvb_get_letohl(tvb, offset+8);
		temp	    = tvb_get_letohs (tvb, offset+12);
		fsid_major  = (temp >> 8) & 0xff;
		fsid_minor  = (temp     ) & 0xff;
		temp	    = tvb_get_letohs(tvb, offset+16);
		xfsid_major = (temp >> 8) & 0xff;
		xfsid_minor = (temp     ) & 0xff;
		xinode	    = tvb_get_letohl(tvb, offset+20);
		gen	    = tvb_get_letohl(tvb, offset+24);

		proto_tree_add_uint(tree, hf_nfs_fh_dentry,
				    tvb, offset+0, 4, dentry);
		proto_tree_add_uint(tree, hf_nfs_fh_fn_inode,
				    tvb, offset+4, 4, inode);
		proto_tree_add_uint(tree, hf_nfs_fh_dirinode,
				    tvb, offset+8, 4, dirinode);

		/* file system id (device) */
		{
			proto_item *fsid_item;
			proto_tree *fsid_tree;

			fsid_item = proto_tree_add_text(tree, tvb,
							offset+12, 4,
							"file system ID: %d,%d",
							fsid_major, fsid_minor);
			fsid_tree = proto_item_add_subtree(fsid_item,
							   ett_nfs_fh_fsid);
			proto_tree_add_uint(fsid_tree, hf_nfs_fh_fsid_major,
					    tvb, offset+13, 1, fsid_major);
			proto_tree_add_uint(fsid_tree, hf_nfs_fh_fsid_minor,
					    tvb, offset+12, 1, fsid_minor);
		}

		/* exported file system id (device) */
		{
			proto_item *xfsid_item;
			proto_tree *xfsid_tree;

			xfsid_item = proto_tree_add_text(tree, tvb,
							 offset+16, 4,
							 "exported file system ID: %d,%d", xfsid_major, xfsid_minor);
			xfsid_tree = proto_item_add_subtree(xfsid_item,
							    ett_nfs_fh_xfsid);
			proto_tree_add_uint(xfsid_tree, hf_nfs_fh_xfsid_major,
					    tvb, offset+17, 1, xfsid_major);
			proto_tree_add_uint(xfsid_tree, hf_nfs_fh_xfsid_minor,
					    tvb, offset+16, 1, xfsid_minor);
		}

		proto_tree_add_uint(tree, hf_nfs_fh_xfn_inode,
				    tvb, offset+20, 4, xinode);
		proto_tree_add_uint(tree, hf_nfs_fh_fn_generation,
				    tvb, offset+24, 4, gen);
	}
}


/* Checked with RedHat Linux 5.2 (nfs-server 2.2beta47 user-land nfsd) */

static void
dissect_fhandle_data_LINUX_NFSD_LE(tvbuff_t* tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset = 0;

	/* pseudo inode */
	{
		guint32 pinode;
		pinode   = tvb_get_letohl(tvb, offset+0);
		if (tree) {
			proto_tree_add_uint(tree, hf_nfs_fh_pinode,
					    tvb, offset+0, 4, pinode);
		}
	}

	/* hash path */
	{
		guint32 hashlen;

		hashlen  = tvb_get_guint8(tvb, offset+4);
		if (tree) {
			proto_item *hash_item = NULL;
			proto_tree *hash_tree = NULL;

			hash_item = proto_tree_add_text(tree, tvb, offset+4,
							hashlen + 1,
							"hash path: %s",
							tvb_bytes_to_ep_str(tvb, offset+5, hashlen));
			hash_tree = proto_item_add_subtree(hash_item,
							   ett_nfs_fh_hp);
			proto_tree_add_uint(hash_tree,
					    hf_nfs_fh_hp_len, tvb, offset+4, 1,
					    hashlen);
			proto_tree_add_text(hash_tree, tvb, offset+5,
					    hashlen,
					    "key: %s",
					    tvb_bytes_to_ep_str(tvb, offset+5, hashlen));
		}
	}
}


static void
dissect_fhandle_data_NETAPP(tvbuff_t* tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset = 0;

	if (tree) {
		guint32 mount	       = tvb_get_letohl(tvb, offset +  0);
		guint32 mount_gen      = tvb_get_letohl(tvb, offset +  4);
		guint16 flags	       = tvb_get_letohs(tvb, offset +  8);
		guint8	snapid	       = tvb_get_guint8(tvb, offset + 10);
		guint8	unused	       = tvb_get_guint8(tvb, offset + 11);
		guint32 inum	       = tvb_get_ntohl( tvb, offset + 12);
		guint32 generation     = tvb_get_letohl(tvb, offset + 16);
		guint32 fsid	       = tvb_get_letohl(tvb, offset + 20);
		guint32 nfsexport      = tvb_get_letohl(tvb, offset + 24);
		guint32 export_snapgen = tvb_get_letohl(tvb, offset + 28);

		proto_item *item = NULL;
		proto_tree *subtree = NULL;
		char *flag_string;
		static const char *strings[] = { " MNT_PNT", " SNAPDIR", " SNAPDIR_ENT",
				    " EMPTY", " VBN_ACCESS", " MULTIVOLUME",
				    " METADATA" };
		guint16 bit = sizeof(strings) / sizeof(strings[0]);

		flag_string = (char *)wmem_alloc(wmem_packet_scope(), 512);
		flag_string[0] = 0;
		while (bit--) {
			if (flags & (1<<bit)) {
				g_strlcat(flag_string, strings[bit], 512);
			}
		}
		item = proto_tree_add_text(tree, tvb, offset + 0, 8,
					   "mount (inode %u)", mount);
		subtree = proto_item_add_subtree(item, ett_nfs_fh_mount);
		proto_tree_add_uint(subtree, hf_nfs_fh_mount_fileid,
					   tvb, offset + 0, 4, mount);
		proto_tree_add_uint(subtree, hf_nfs_fh_mount_generation,
					   tvb, offset + 4, 4, mount_gen);
		item = proto_tree_add_text(tree, tvb, offset + 8, 16,
					   "file (inode %u)", inum);
		subtree = proto_item_add_subtree(item, ett_nfs_fh_file);
		proto_tree_add_uint_format(subtree, hf_nfs_fh_flags,
						  tvb, offset + 8, 2, flags,
						  "Flags: %#02x%s", flags,
						  flag_string);
		proto_tree_add_uint(subtree, hf_nfs_fh_snapid, tvb,
					   offset + 10, 1, snapid);
		proto_tree_add_uint(subtree, hf_nfs_fh_unused, tvb,
					   offset + 11, 1, unused);
		proto_tree_add_uint(subtree, hf_nfs_fh_fileid, tvb,
					   offset + 12, 4, inum);
		proto_tree_add_uint(subtree, hf_nfs_fh_generation, tvb,
					   offset + 16, 4, generation);
		proto_tree_add_uint(subtree, hf_nfs_fh_fsid, tvb,
					   offset + 20, 4, fsid);
		item = proto_tree_add_text(tree, tvb, offset + 24, 8,
					   "export (inode %u)", nfsexport);
		subtree = proto_item_add_subtree(item, ett_nfs_fh_export);
		proto_tree_add_uint(subtree, hf_nfs_fh_export_fileid,
					   tvb, offset + 24, 4, nfsexport);
		proto_tree_add_uint(subtree,
					   hf_nfs_fh_export_generation,
					   tvb, offset + 28, 3,
					   export_snapgen & 0xffffff);
		proto_tree_add_uint(subtree, hf_nfs_fh_export_snapid,
					   tvb, offset + 31, 1,
					   export_snapgen >> 24);
	}
}

static const value_string netapp_file_flag_vals[] =  {
	{ 0x0000,	"Not set"},
	{ 0x0001,	"Set"},
	{ 0,		NULL}
};

static void
dissect_fhandle_data_NETAPP_V4(tvbuff_t* tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	static const char *handle_type_strings [] = { "NORMAL",
						      "UNEXP",
						      "VOLDIR",
						      "ROOT",
						      "ABSENT",
						      "INVALID"
	};

	static const char *strings[] = { " MNT_PNT",
					 " SNAPDIR",
					 " SNAPDIR_ENT",
					 " EMPTY",
					 " VBN_ACCESS",
					 " MULTIVOLUME",
					 " METADATA",
					 " ORPHAN",
					 " FOSTER",
					 " NAMED_ATTR",
					 " EXP_SNAPDIR",
					 " VFILER",
					 " NS_AGGR",
					 " STRIPED",
					 " NS_PRIVATE",
					 " NEXT_GEN_FH"
	};

	if (tree == NULL)
		return;

	{
		int	    offset = 0;
		proto_item *item;
		proto_tree *subtree;
		guint8	    snapid, unused;
		guint16	    flags;
		guint32	    fileid, snapgen, generation, fsid;
		guint32	    handle_type;
		guint32	    inum;
		char	   *flag_string;
		guint16	    bit    = sizeof(strings) / sizeof(strings[0]);
		proto_tree *flag_tree;
		const char *handle_string;

		handle_type = tvb_get_ntohl(tvb, offset + 24);
		inum	    = tvb_get_ntohl(tvb, offset + 12);

		flag_string = (char *)wmem_alloc(wmem_packet_scope(), 512);
		flag_string[0] = '\0';

		if ( handle_type != 0 && handle_type <= 255) {
			fileid	    = tvb_get_ntohl( tvb, offset +  0);
			snapgen	    = tvb_get_ntohl( tvb, offset +  4);
			flags	    = tvb_get_ntohs( tvb, offset +  8);
			snapid	    = tvb_get_guint8(tvb, offset + 10);
			unused	    = tvb_get_guint8(tvb, offset + 11);
			generation  = tvb_get_ntohl( tvb, offset + 16);
			fsid	    = tvb_get_ntohl( tvb, offset + 20);
		} else {
			fileid	    = tvb_get_letohl(tvb, offset +  0);
			snapgen	    = tvb_get_letohl(tvb, offset +  4);
			flags	    = tvb_get_letohs(tvb, offset +  8);
			snapid	    = tvb_get_guint8(tvb, offset + 10);
			unused	    = tvb_get_guint8(tvb, offset + 11);
			generation  = tvb_get_letohl(tvb, offset + 16);
			fsid	    = tvb_get_letohl(tvb, offset + 20);
			handle_type = tvb_get_letohl(tvb, offset + 24);
		}

		if (handle_type <= 4) {
			handle_string = handle_type_strings[handle_type];
		} else {
			handle_string = handle_type_strings[5];
		}

		while (bit--) {
			if (flags & (1<<bit)) {
				g_strlcat(flag_string, strings[bit], 512);
			}
		}
		item = proto_tree_add_text(tree, tvb, offset + 0, 8, "export (inode %u)", fileid);
		subtree = proto_item_add_subtree(item, ett_nfs4_fh_export);

		proto_tree_add_uint(subtree, hf_nfs_fh_export_fileid,
				    tvb, offset + 0, 4, fileid);
		proto_tree_add_uint(subtree, hf_nfs_fh_export_generation,
				    tvb, offset + 4, 4, snapgen);
		item = proto_tree_add_text(tree, tvb, offset + 8, 16, "file (inode %u)", inum);
		subtree = proto_item_add_subtree(item, ett_nfs4_fh_file);
		item = proto_tree_add_uint_format_value(subtree, hf_nfs_fh_flags,
							tvb, offset + 8, 2, flags, "%#02x%s", flags, flag_string);
		flag_tree = proto_item_add_subtree(item, ett_nfs4_fh_file_flags);
		proto_tree_add_uint(flag_tree, hf_nfs_fh_file_flag_mntpoint, tvb, offset+8, 2, flags);
		proto_tree_add_uint(flag_tree, hf_nfs_fh_file_flag_snapdir, tvb, offset+8, 2, flags);
		proto_tree_add_uint(flag_tree, hf_nfs_fh_file_flag_snapdir_ent, tvb, offset+8, 2, flags);
		proto_tree_add_uint(flag_tree, hf_nfs_fh_file_flag_empty, tvb, offset+8, 2, flags);
		proto_tree_add_uint(flag_tree, hf_nfs_fh_file_flag_vbn_access, tvb, offset+8, 2, flags);
		proto_tree_add_uint(flag_tree, hf_nfs_fh_file_flag_multivolume, tvb, offset+8, 2, flags);
		proto_tree_add_uint(flag_tree, hf_nfs_fh_file_flag_metadata, tvb, offset+8, 2, flags);
		proto_tree_add_uint(flag_tree, hf_nfs_fh_file_flag_orphan, tvb, offset+8, 2, flags);
		proto_tree_add_uint(flag_tree, hf_nfs_fh_file_flag_foster, tvb, offset+8, 2, flags);
		proto_tree_add_uint(flag_tree, hf_nfs_fh_file_flag_named_attr, tvb, offset+8, 2, flags);
		proto_tree_add_uint(flag_tree, hf_nfs_fh_file_flag_exp_snapdir, tvb, offset+8, 2, flags);
		proto_tree_add_uint(flag_tree, hf_nfs_fh_file_flag_vfiler, tvb, offset+8, 2, flags);
		proto_tree_add_uint(flag_tree, hf_nfs_fh_file_flag_aggr, tvb, offset+8, 2, flags);
		proto_tree_add_uint(flag_tree, hf_nfs_fh_file_flag_striped, tvb, offset+8, 2, flags);
		proto_tree_add_uint(flag_tree, hf_nfs_fh_file_flag_private, tvb, offset+8, 2, flags);
		proto_tree_add_uint(flag_tree, hf_nfs_fh_file_flag_next_gen, tvb, offset+8, 2, flags);
		proto_tree_add_uint(subtree, hf_nfs_fh_snapid, tvb,
				    offset + 10, 1, snapid);
		proto_tree_add_uint(subtree, hf_nfs_fh_unused, tvb,
				    offset + 11, 1, unused);
		proto_tree_add_uint(subtree, hf_nfs_fh_fileid, tvb,
				    offset + 12, 4, inum);
		proto_tree_add_uint(subtree, hf_nfs_fh_generation, tvb,
				    offset + 16, 4, generation);
		proto_tree_add_uint(subtree, hf_nfs_fh_fsid, tvb,
				    offset + 20, 4, fsid);
		proto_tree_add_uint_format_value(tree, hf_nfs_fh_handle_type,
						 tvb, offset+24, 4, handle_type,
						 "%s(%#02x)", handle_string, handle_type);
	}
}

#define NETAPP_GX_FH3_LENGTH		44
#define NFS3GX_FH_TREE_MASK		0x80
#define NFS3GX_FH_JUN_MASK		0x40
#define NFS3GX_FH_VER_MASK		0x3F
#define SPINNP_FH_FLAG_RESV1            0x80
#define SPINNP_FH_FLAG_RESV2            0x40
#define SPINNP_FH_FLAG_ONTAP_MASK	0x20
#define SPINNP_FH_FLAG_STRIPED_MASK	0x10
#define SPINNP_FH_FLAG_EMPTY_MASK	0x08
#define SPINNP_FH_FLAG_SNAPDIR_ENT_MASK 0x04
#define SPINNP_FH_FLAG_SNAPDIR_MASK	0x02
#define SPINNP_FH_FLAG_STREAMDIR_MASK	0x01

static void
dissect_fhandle_data_NETAPP_GX_v3(tvbuff_t* tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	if (tree) {
		proto_item *tf;
		proto_tree *field_tree;
		guint16     epoch;
		guint32     export_id;
		guint32     export_uid;
		guint8      flags;
		guint32     spinfile_id;
		guint32     spinfile_uid;
		guint8      utility;
		guint8      volcnt;
		guint32	    offset = 0;

		/* = utility = */
		utility = tvb_get_guint8(tvb, offset);
		tf = proto_tree_add_uint_format_value(tree, hf_nfs3_gxfh_utlfield, tvb,
						offset, 1, utility,
						"0x%02x", utility);

		field_tree = proto_item_add_subtree(tf, ett_nfs3_gxfh_utlfield);
		if (utility & NFS3GX_FH_TREE_MASK) {
			proto_tree_add_uint(field_tree, hf_nfs3_gxfh_utlfield_tree_w, tvb,
					    offset, 1, utility);
		}
		else {
			proto_tree_add_uint(field_tree, hf_nfs3_gxfh_utlfield_tree_r, tvb,
					    offset, 1, utility);
		}
		if (utility & NFS3GX_FH_JUN_MASK) {
			proto_tree_add_uint(field_tree, hf_nfs3_gxfh_utlfield_jun, tvb,
					    offset, 1, utility);
		}
		else {
			proto_tree_add_uint(field_tree, hf_nfs3_gxfh_utlfield_jun_not, tvb,
					    offset, 1, utility);
		}
		proto_tree_add_uint(field_tree, hf_nfs3_gxfh_utlfield_ver, tvb,
	                            offset, 1, utility);

		/* = volume count== */
		volcnt = tvb_get_guint8(tvb, offset+1);
		proto_tree_add_uint(tree, hf_nfs3_gxfh_volcnt, tvb, offset+1, 1, volcnt);
		/* = epoch = */
		epoch = tvb_get_letohs(tvb, offset+2);
		proto_tree_add_uint(tree, hf_nfs3_gxfh_epoch, tvb, offset+2, 2, epoch);
		/* = spin file handle = */
		flags        = tvb_get_guint8(tvb, offset+11);
		spinfile_id  = tvb_get_letohl(tvb, offset+12);
		spinfile_uid = tvb_get_letohl(tvb, offset+16);

		tf = proto_tree_add_text(tree, tvb, offset+4, 16,
					 "  spin file handle");
		field_tree = proto_item_add_subtree(tf, ett_nfs3_gxfh_sfhfield);

		proto_tree_add_item(field_tree, hf_nfs3_gxfh_ldsid, tvb, offset+4, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(field_tree, hf_nfs3_gxfh_cid, tvb, offset+8, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(field_tree, hf_nfs3_gxfh_resv, tvb, offset+10, 1, ENC_BIG_ENDIAN);

		tf = proto_tree_add_uint_format(field_tree, hf_nfs3_gxfh_sfhflags, tvb,
						offset+11, 1, utility,
						" flags: 0x%02x", flags);
		field_tree = proto_item_add_subtree(tf, ett_nfs3_gxfh_sfhflags);
		proto_tree_add_uint(field_tree, hf_nfs3_gxfh_sfhflags_resv1, tvb,
				    offset+11, 1, flags);
		proto_tree_add_uint(field_tree, hf_nfs3_gxfh_sfhflags_resv2, tvb,
				    offset+11, 1, flags);

		if (flags & SPINNP_FH_FLAG_ONTAP_MASK) {
			proto_tree_add_uint(field_tree, hf_nfs3_gxfh_sfhflags_ontap7G, tvb,
					    offset+11, 1, flags);
		}
		else {
			proto_tree_add_uint(field_tree, hf_nfs3_gxfh_sfhflags_ontapGX, tvb,
					    offset+11, 1, flags);
		}
		proto_tree_add_boolean(field_tree, hf_nfs3_gxfh_sfhflags_striped, tvb,
				       offset+11, 1, flags);
		proto_tree_add_boolean(field_tree, hf_nfs3_gxfh_sfhflags_empty, tvb,
				       offset+11, 1, flags);
		proto_tree_add_boolean(field_tree, hf_nfs3_gxfh_sfhflags_snapdirent, tvb,
				       offset+11, 1, flags);
		proto_tree_add_boolean(field_tree, hf_nfs3_gxfh_sfhflags_snapdir, tvb,
				       offset+11, 1, flags);
		proto_tree_add_boolean(field_tree, hf_nfs3_gxfh_sfhflags_streamdir, tvb,
				       offset+11, 1, flags);
		proto_tree_add_uint(field_tree, hf_nfs3_gxfh_spinfid, tvb,
					   offset+12, 4, spinfile_id);
		proto_tree_add_uint(field_tree, hf_nfs3_gxfh_spinfuid, tvb,
					   offset+16, 4, spinfile_uid);

		/* = spin file handle (mount point) = */
		flags        = tvb_get_guint8(tvb, offset+27);
		spinfile_id  = tvb_get_letohl(tvb, offset+28);
		spinfile_uid = tvb_get_letohl(tvb, offset+32);

		tf = proto_tree_add_text(tree, tvb, offset+20, 16,
					 "  spin (mount point) file handle");
		field_tree = proto_item_add_subtree(tf, ett_nfs3_gxfh_sfhfield);

		proto_tree_add_item(field_tree, hf_nfs3_gxfh_ldsid, tvb, offset+20, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(field_tree, hf_nfs3_gxfh_cid, tvb, offset+24, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(field_tree, hf_nfs3_gxfh_resv, tvb, offset+26, 1, ENC_BIG_ENDIAN);

		tf = proto_tree_add_uint_format(field_tree, hf_nfs3_gxfh_sfhflags, tvb,
						offset+27, 1, utility,
						" flags: 0x%02x", flags);
		field_tree = proto_item_add_subtree(tf, ett_nfs3_gxfh_sfhflags);
		proto_tree_add_uint(field_tree, hf_nfs3_gxfh_sfhflags_resv1, tvb,
				    offset+27, 1, flags);
		proto_tree_add_uint(field_tree, hf_nfs3_gxfh_sfhflags_resv2, tvb,
				    offset+27, 1, flags);

		if (flags & SPINNP_FH_FLAG_ONTAP_MASK) {
			proto_tree_add_uint(field_tree, hf_nfs3_gxfh_sfhflags_ontap7G, tvb,
					    offset+27, 1, flags);
		}
		else {
			proto_tree_add_uint(field_tree, hf_nfs3_gxfh_sfhflags_ontapGX, tvb,
					    offset+27, 1, flags);
		}
		proto_tree_add_boolean(field_tree, hf_nfs3_gxfh_sfhflags_striped, tvb,
				       offset+27, 1, flags);
		proto_tree_add_boolean(field_tree, hf_nfs3_gxfh_sfhflags_empty, tvb,
				       offset+27, 1, flags);
		proto_tree_add_boolean(field_tree, hf_nfs3_gxfh_sfhflags_snapdirent, tvb,
				       offset+27, 1, flags);
		proto_tree_add_boolean(field_tree, hf_nfs3_gxfh_sfhflags_snapdir, tvb,
				       offset+27, 1, flags);
		proto_tree_add_boolean(field_tree, hf_nfs3_gxfh_sfhflags_streamdir, tvb,
				       offset+27, 1, flags);
		proto_tree_add_uint(field_tree, hf_nfs3_gxfh_spinfid, tvb,
					   offset+28, 4, spinfile_id);
		proto_tree_add_uint(field_tree, hf_nfs3_gxfh_spinfuid, tvb,
					   offset+32, 4, spinfile_uid);
		/* = export point id  = */
		export_id  = tvb_get_letohl(tvb, offset+36);
		proto_tree_add_uint_format_value(tree, hf_nfs3_gxfh_exportptid, tvb,
					   offset+36, 4, spinfile_id,
					   "0x%08x (%u)", export_id, export_id);
		/* = export point unique id  = */
		export_uid = tvb_get_letohl(tvb, offset+40);
		proto_tree_add_uint_format_value(tree, hf_nfs3_gxfh_exportptuid, tvb,
					   offset+40, 4, spinfile_id,
					   "0x%08x (%u)", export_uid, export_uid);

	}  /* end of (tree) */
}

/* Checked with SuSE 7.1 (kernel 2.4.0 knfsd) */
/* read linux-2.4.5/include/linux/nfsd/nfsfh.h for more details */

#define AUTH_TYPE_NONE 0
static const value_string auth_type_names[] = {
	{	AUTH_TYPE_NONE,				"no authentication"		},
	{	0,	NULL}
};

#define FSID_TYPE_MAJOR_MINOR_INODE 0
static const value_string fsid_type_names[] = {
	{	FSID_TYPE_MAJOR_MINOR_INODE,		"major/minor/inode"		},
	{	0,	NULL}
};

#define FILEID_TYPE_ROOT			0
#define FILEID_TYPE_INODE_GENERATION		1
#define FILEID_TYPE_INODE_GENERATION_PARENT	2
static const value_string fileid_type_names[] = {
	{	FILEID_TYPE_ROOT,			"root"				},
	{	FILEID_TYPE_INODE_GENERATION,		"inode/generation"		},
	{	FILEID_TYPE_INODE_GENERATION_PARENT,	"inode/generation/parent"	},
	{	0,	NULL}
};

static void
dissect_fhandle_data_LINUX_KNFSD_NEW(tvbuff_t* tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int    offset = 0;
	guint8 version;
	guint8 auth_type;
	guint8 fsid_type;
	guint8 fileid_type;

	version     = tvb_get_guint8(tvb, offset + 0);
	if (tree) {
		proto_tree_add_uint(tree, hf_nfs_fh_version,
			tvb, offset+0, 1, version);
	}

	switch (version) {
		case 1: {
			auth_type   = tvb_get_guint8(tvb, offset + 1);
			fsid_type   = tvb_get_guint8(tvb, offset + 2);
			fileid_type = tvb_get_guint8(tvb, offset + 3);
			if (tree) {
				proto_item *encoding_item = proto_tree_add_text(tree, tvb,
					offset + 1, 3,
					"encoding: %u %u %u",
					auth_type, fsid_type, fileid_type);
				{
					proto_tree *encoding_tree = proto_item_add_subtree(encoding_item,
						ett_nfs_fh_encoding);

					proto_tree_add_uint(encoding_tree, hf_nfs_fh_auth_type,
							tvb, offset+1, 1, auth_type);
					proto_tree_add_uint(encoding_tree, hf_nfs_fh_fsid_type,
							tvb, offset+2, 1, fsid_type);
					proto_tree_add_uint(encoding_tree, hf_nfs_fh_fileid_type,
							tvb, offset+3, 1, fileid_type);
				}
			}
			offset += 4;
		} break;
		default: {
			/* unknown version */
			goto out;
		}
	}

	switch (auth_type) {
		case 0: {
			/* no authentication */
			if (tree) {
				proto_tree_add_text(tree, tvb,
					offset + 0, 0,
					"authentication: none");
			}
		} break;
		default: {
			/* unknown authentication type */
			goto out;
		}
	}

	switch (fsid_type) {
		case 0: {
			guint16 fsid_major;
			guint16 fsid_minor;
			guint32 fsid_inode;

			fsid_major = tvb_get_ntohs(tvb, offset + 0);
			fsid_minor = tvb_get_ntohs(tvb, offset + 2);
			fsid_inode = tvb_get_letohl(tvb, offset + 4);
			if (tree) {
				proto_item *fsid_item = proto_tree_add_text(tree, tvb,
					offset+0, 8,
					"file system ID: %u,%u (inode %u)",
					fsid_major, fsid_minor, fsid_inode);
				{
					proto_tree *fsid_tree = proto_item_add_subtree(fsid_item,
						ett_nfs_fh_fsid);

					proto_tree_add_uint(fsid_tree, hf_nfs_fh_fsid_major,
							tvb, offset+0, 2, fsid_major);
					proto_tree_add_uint(fsid_tree, hf_nfs_fh_fsid_minor,
							tvb, offset+2, 2, fsid_minor);
					proto_tree_add_uint(fsid_tree, hf_nfs_fh_fsid_inode,
							tvb, offset+4, 4, fsid_inode);
				}
			}
			offset += 8;
		} break;
		default: {
			/* unknown fsid type */
			goto out;
		}
	}

	switch (fileid_type) {
		case 0: {
			if (tree) {
				proto_tree_add_text(tree, tvb,
					offset+0, 0,
					"file ID: root inode");
			}
		} break;
		case 1: {
			guint32 inode;
			guint32 generation;

			inode = tvb_get_letohl(tvb, offset + 0);
			generation = tvb_get_letohl(tvb, offset + 4);

			if (tree) {
				proto_item *fileid_item = proto_tree_add_text(tree, tvb,
					offset+0, 8,
					"file ID: %u (%u)",
					inode, generation);
				{
					proto_tree *fileid_tree = proto_item_add_subtree(
						fileid_item, ett_nfs_fh_fn);

					proto_tree_add_uint(fileid_tree, hf_nfs_fh_fn_inode,
						tvb, offset+0, 4, inode);
					proto_tree_add_uint(fileid_tree, hf_nfs_fh_fn_generation,
						tvb, offset+4, 4, generation);
				}
			}

			/*offset += 8;*/
		} break;
		case 2: {
			guint32 inode;
			guint32 generation;
			guint32 parent_inode;

			inode = tvb_get_letohl(tvb, offset + 0);
			generation = tvb_get_letohl(tvb, offset + 4);
			parent_inode = tvb_get_letohl(tvb, offset + 8);

			if (tree) {
				 proto_item *fileid_item = proto_tree_add_text(tree, tvb,
					offset+0, 8,
					"file ID: %u (%u)",
					inode, generation);
				 {
					proto_tree *fileid_tree = proto_item_add_subtree(
						fileid_item, ett_nfs_fh_fn);

					proto_tree_add_uint(fileid_tree, hf_nfs_fh_fn_inode,
						tvb, offset+0, 4, inode);
					proto_tree_add_uint(fileid_tree, hf_nfs_fh_fn_generation,
						tvb, offset+4, 4, generation);
					proto_tree_add_uint(fileid_tree, hf_nfs_fh_dirinode,
						tvb, offset+8, 4, parent_inode);
				}
			}

			/*offset += 12;*/
		} break;
		default: {
			/* unknown fileid type */
			goto out;
		}
	}

out:
	;
}


/*
 * Dissect GlusterFS/NFS NFSv3 File Handle - glusterfs-3.3+
 * The filehandle is alway 32 bytes and first 4 bytes of ident ":OGL"
 */
static void
dissect_fhandle_data_GLUSTER(tvbuff_t* tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	guint16 offset=0;
	guint16	fhlen;
	char *ident;

	if (!tree)
		return;

	fhlen = tvb_reported_length(tvb);
	if (fhlen != 36)
		return;

	ident = tvb_get_string_enc(NULL, tvb, offset, 4, ENC_ASCII);
	if (strncmp(":OGL", ident, 4))
		return;
	offset += 4;

	proto_tree_add_item(tree, hf_nfs_fh_exportid, tvb, offset, 16, ENC_NA);
	offset += 16;
	proto_tree_add_item(tree, hf_nfs_fh_gfid, tvb, offset, 16, ENC_NA);
	/*offset += 16;*/
}


/* Dissect EMC Celerra or VNX NFSv3/v4 File Handle */
static void
dissect_fhandle_data_CELERRA_VNX(tvbuff_t* tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	guint16 offset = 0;
	guint16	fhlen;
	guint32 obj_fsid;
	guint16	obj_kindid;
	guint16	obj_treeid;
	guint32 obj_inode;
	guint32 obj_gen;
	guint32 ex_fsid;
	guint16	ex_kindid;
	guint16	ex_treeid;
	guint32 ex_inode;
	guint32 ex_gen;
	guint32	obj_id;
	guint32	ro_node;

	if (!tree)
		return;

	fhlen = tvb_reported_length(tvb);

	/* Display the entire file handle */
	proto_tree_add_item(tree, hf_nfs_fh_fhandle_data, tvb, 0, fhlen, ENC_NA);

	/* 	If fhlen = 32, it's an NFSv3 file handle */
	if (fhlen == 32) {
		/* Create a "File/Dir" subtree: bytes 0 thru 15 of the 32-byte file handle 	 */
		{
		proto_item *obj_item = NULL;
		proto_tree *obj_tree = NULL;
		obj_item = proto_tree_add_item(tree, hf_nfs_fh_obj, tvb, offset+0, 16, ENC_NA );
		obj_tree = proto_item_add_subtree(obj_item, ett_nfs_fh_obj);

		obj_fsid   = tvb_get_letohl(tvb, offset+0);
		proto_tree_add_uint(obj_tree, hf_nfs_fh_obj_fsid,   tvb,  offset+0, 4, obj_fsid);
		obj_kindid = tvb_get_letohs(tvb, offset+4);
		proto_tree_add_uint(obj_tree, hf_nfs_fh_obj_kindid, tvb,  offset+4, 2, obj_kindid);
		obj_treeid = tvb_get_letohs(tvb, offset+6);
		proto_tree_add_uint(obj_tree, hf_nfs_fh_obj_treeid, tvb,  offset+6, 2, obj_treeid);
		obj_inode  = tvb_get_letohl(tvb, offset+8);
		proto_tree_add_uint(obj_tree, hf_nfs_fh_obj_inode,  tvb,  offset+8, 4, obj_inode);
		obj_gen	  = tvb_get_letohl(tvb, offset+12);
		proto_tree_add_uint(obj_tree, hf_nfs_fh_obj_gen,    tvb, offset+12, 4, obj_gen);
		}
		{
		/* Create "Export" subtree (NFSv3: Bytes 16 thru 31 of the 32-byte file handle  */
		proto_item *ex_item = NULL;
		proto_tree *ex_tree = NULL;
		ex_item = proto_tree_add_item(tree, hf_nfs_fh_ex, tvb,  offset+16, 16, ENC_NA );
		ex_tree = proto_item_add_subtree(ex_item, ett_nfs_fh_ex);

		ex_fsid   = tvb_get_letohl(tvb, offset+16);
		proto_tree_add_uint(ex_tree, hf_nfs_fh_ex_fsid,     tvb, offset+16, 4, ex_fsid);
		ex_kindid = tvb_get_letohs(tvb, offset+20);
		proto_tree_add_uint(ex_tree, hf_nfs_fh_ex_kindid,   tvb, offset+20, 2, ex_kindid);
		ex_treeid = tvb_get_letohs(tvb, offset+22);
		proto_tree_add_uint(ex_tree, hf_nfs_fh_ex_treeid,   tvb, offset+22, 2, ex_treeid);
		ex_inode  = tvb_get_letohl(tvb, offset+24);
		proto_tree_add_uint(ex_tree, hf_nfs_fh_ex_inode,    tvb, offset+24, 4, ex_inode);
		ex_gen    = tvb_get_letohl(tvb, offset+28);
		proto_tree_add_uint(ex_tree, hf_nfs_fh_ex_gen,      tvb, offset+28, 4, ex_gen);
		}
	} else if (fhlen == 40) {
		/*
		If fhlen = 40, it's an NFSv4 file handle).  In Celerra|VNX NFSv4 file handles,
		the first 4 bytes hold the Named Attribute ID, and the next 4 bytes hold the
		RO_Node boolean which if true, the file/dir is Read Only. Unlike NFSv3 file
		handles where the file/dir info precedes the export info, the next 16 bytes contain
		the *export* info followed by 16 bytes containing the *file/dir* info.
		*/

		/* "Named Attribute ID" or "Object ID" (bytes 0 thru 3) */
		obj_id = tvb_get_letohl(tvb, offset+0);
		if (obj_id <= 0 || obj_id > 9) obj_id = 1;
		proto_tree_add_uint(tree, hf_nfs_fh_obj_id,         tvb,  offset+0, 4, obj_id);

		/* "RO_Node" boolean (bytes 4 thru 7) */
		ro_node = tvb_get_letohl(tvb, offset+4);
		proto_tree_add_boolean(tree, hf_nfs_fh_ro_node,     tvb,  offset+4, 4, ro_node);

		/* Create "Export" subtree (bytes 8 thru 23 of the 40-byte file handle  */
		{
		proto_item *ex_item = NULL;
		proto_tree *ex_tree = NULL;
		ex_item = proto_tree_add_item(tree, hf_nfs_fh_ex,  tvb,  offset+8, 16, ENC_NA );
		ex_tree = proto_item_add_subtree(ex_item, ett_nfs_fh_ex);

		ex_fsid   = tvb_get_letohl(tvb, offset+8);
		proto_tree_add_uint(ex_tree, hf_nfs_fh_ex_fsid,    tvb,  offset+8,  4, ex_fsid);
		ex_kindid = tvb_get_letohs(tvb, offset+12);
		proto_tree_add_uint(ex_tree, hf_nfs_fh_ex_kindid,  tvb, offset+12,  2, ex_kindid);
		ex_treeid = tvb_get_letohs(tvb, offset+14);
		proto_tree_add_uint(ex_tree, hf_nfs_fh_ex_treeid,  tvb, offset+14,  2, ex_treeid);
		ex_inode  = tvb_get_letohl(tvb, offset+16);
		proto_tree_add_uint(ex_tree, hf_nfs_fh_ex_inode,   tvb, offset+16,  4, ex_inode);
		ex_gen    = tvb_get_letohl(tvb, offset+20);
		proto_tree_add_uint(ex_tree, hf_nfs_fh_ex_gen,     tvb, offset+20,  4, ex_gen);
		}
		/* Create a "File/Dir/Object" subtree (bytes 24 thru 39 of the 40-byte file handle) */
		{
		proto_item *obj_item = NULL;
		proto_tree *obj_tree = NULL;
		obj_item = proto_tree_add_item(tree, hf_nfs_fh_obj, tvb, offset+24, 16, ENC_NA);
		obj_tree = proto_item_add_subtree(obj_item, ett_nfs_fh_obj);

		obj_fsid   = tvb_get_letohl(tvb, offset+24);
		proto_tree_add_uint(obj_tree, hf_nfs_fh_obj_fsid,   tvb, offset+24,  4, obj_fsid);
		obj_kindid = tvb_get_letohs(tvb, offset+28);
		proto_tree_add_uint(obj_tree, hf_nfs_fh_obj_kindid, tvb, offset+28,  2, obj_kindid);
		obj_treeid = tvb_get_letohs(tvb, offset+30);
		proto_tree_add_uint(obj_tree, hf_nfs_fh_obj_treeid, tvb, offset+30,  2, obj_treeid);
		obj_inode  = tvb_get_letohl(tvb, offset+32);
		proto_tree_add_uint(obj_tree, hf_nfs_fh_obj_inode,  tvb, offset+32,  4, obj_inode);
		obj_gen	  = tvb_get_letohl(tvb, offset+36);
		proto_tree_add_uint(obj_tree, hf_nfs_fh_obj_gen,    tvb, offset+36,  4, obj_gen);
		}
	} else {
		/* This is not a Celerra|VNX file handle.  Display a warning. */
		expert_add_info_format(pinfo, tree, &ei_nfs_not_vnx_file,
			"Celerra|VNX file handles are 32 (NFSv3) or 40 (NFSv4) but the length is %u.\n"
			"Change the 'Decode NFS file handles as' pref to the correct type or 'Unknown'.",
			fhlen);
	}
}


static void
dissect_fhandle_data_unknown(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	guint fhlen = tvb_length(tvb);

	proto_tree_add_item(tree, hf_nfs_fh_fhandle_data, tvb, 0, fhlen, ENC_NA);
}


static void
dissect_fhandle_data(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree,
		     unsigned int fhlen, gboolean hidden, guint32 *hash)
{
	/* this is to set up fhandle display filters to find both packets
	   of an RPC call */
	if (nfs_fhandle_reqrep_matching && (!hidden) ) {
		nfs_fhandle_data_t *old_fhd = NULL;

		if ( !pinfo->fd->flags.visited ) {
			nfs_fhandle_data_t fhd;

			/* first check if we have seen this fhandle before */
			fhd.len = fhlen;
			fhd.fh = (const unsigned char *)tvb_get_ptr(tvb, offset, fhlen);
			old_fhd = store_nfs_file_handle(&fhd);

			/* XXX here we should really check that we haven't stored
			   this fhandle for this frame number already.
		   	   We should also make sure we can handle when we have multiple
		   	   fhandles seen for the same frame, which WILL happen for certain
		   	   nfs calls. For now, we don't handle this and those calls will
		   	   not work properly with this feature
			*/
			wmem_tree_insert32(nfs_fhandle_frame_table, pinfo->fd->num, old_fhd);
		}
	}

	/* Create a unique hash value for the filehandle using CRC32 */
	{
		guint32 fhhash;
		guint8 *fh_array;
		proto_item *fh_item = NULL;

		fh_array = tvb_get_string_enc(NULL, tvb, offset, fhlen, ENC_ASCII);
		fhhash = crc32_ccitt(fh_array, fhlen);
		g_free(fh_array);

		if (hidden) {
			fh_item = proto_tree_add_uint(tree, hf_nfs_fh_hash, NULL, 0,
				0, fhhash);
			PROTO_ITEM_SET_HIDDEN(fh_item);
		} else {
			fh_item = proto_tree_add_uint(tree, hf_nfs_fh_hash, tvb, offset,
				fhlen, fhhash);
		}
		PROTO_ITEM_SET_GENERATED(fh_item);
		if (hash) {
			*hash = fhhash;
		}
	}
	if (nfs_file_name_snooping) {
		nfs_name_snoop_fh(pinfo, tree, tvb, offset, fhlen, hidden);
	}

	if (!hidden) {
		tvbuff_t *fh_tvb;
		int real_length;

		proto_tree_add_text(tree, tvb, offset, 0, "decode type as: %s",
			val_to_str_ext_const(default_nfs_fhandle_type, &names_fhtype_ext, "Unknown"));

		real_length = fhlen;
		if (default_nfs_fhandle_type != FHT_UNKNOWN && real_length < tvb_length_remaining(tvb, offset))
			real_length = tvb_length_remaining(tvb, offset);

		fh_tvb = tvb_new_subset(tvb, offset, real_length, fhlen);
		if (!dissector_try_uint(nfs_fhandle_table, default_nfs_fhandle_type, fh_tvb, pinfo, tree))
			dissect_fhandle_data_unknown(fh_tvb, pinfo, tree);
	}
}


void
dissect_fhandle_hidden(packet_info *pinfo, proto_tree *tree, int frame)
{
	nfs_fhandle_data_t *nfd;

	nfd = (nfs_fhandle_data_t *)wmem_tree_lookup32(nfs_fhandle_frame_table, frame);
	if (nfd && nfd->len) {
		tvbuff_t *tvb;
		tvb = tvb_new_real_data(nfd->fh, nfd->len, nfd->len);
		/* There's no need to call add_new_data_source() since
		   dissect_fhandle(), in the the 'hidden' case, never refers
		   to the tvb when displaying a field based on the tvb */
		dissect_fhandle_data(tvb, 0, pinfo, tree, nfd->len, TRUE, NULL);
		tvb_free(tvb);
	}
}


/***************************/
/* NFS Version 2, RFC 1094 */
/***************************/

/* NFSv2 RFC 1094, Page 12..14 */
static const value_string names_nfs2_stat[] =
{
	{	0,	"NFS_OK" },
	{	1,	"NFS2ERR_PERM" },
	{	2,	"NFS2ERR_NOENT" },
	{	5,	"NFS2ERR_IO" },
	{	6,	"NFS2ERR_NXIO" },
	{	11,	"NFS2ERR_EAGAIN" },
	{	13,	"NFS2ERR_ACCES" },
	{	17,	"NFS2ERR_EXIST" },
	{	18,	"NFS2ERR_XDEV" },	/* not in spec, but can happen */
	{	19,	"NFS2ERR_NODEV" },
	{	20,	"NFS2ERR_NOTDIR" },
	{	21,	"NFS2ERR_ISDIR" },
	{	22,	"NFS2ERR_INVAL" },	/* not in spec, but I think it can happen */
	{	26,	"NFS2ERR_TXTBSY" },	/* not in spec, but I think it can happen */
	{	27,	"NFS2ERR_FBIG" },
	{	28,	"NFS2ERR_NOSPC" },
	{	30,	"NFS2ERR_ROFS" },
	{	31,	"NFS2ERR_MLINK" },	/* not in spec, but can happen */
	{	45,	"NFS2ERR_OPNOTSUPP" },	/* not in spec, but I think it can happen */
	{	63,	"NFS2ERR_NAMETOOLONG" },
	{	66,	"NFS2ERR_NOTEMPTY" },
	{	69,	"NFS2ERR_DQUOT" },
	{	70,	"NFS2ERR_STALE" },
	{	71,	"NFS2ERR_REMOTE" },
	{	99,	"NFS2ERR_WFLUSH" },
	{	10001,	"NFS2ERR_BADHANDLE" },
	{	10002,	"NFS2ERR_NOT_SYNC" },
	{	10003,	"NFS2ERR_BAD_COOKIE" },
	{	10004,	"NFS2ERR_NOTSUPP" },
	{	10005,	"NFS2ERR_TOOSMALL" },
	{	10006,	"NFS2ERR_SERVERFAULT" },
	{	10007,	"NFS2ERR_BADTYPE" },
	{	10008,	"NFS2ERR_JUKEBOX" },
	{	10009,	"NFS2ERR_SAME" },
	{	10010,	"NFS2ERR_DENIED" },
	{	10011,	"NFS2ERR_EXPIRED" },
	{	10012,	"NFS2ERR_LOCKED" },
	{	10013,	"NFS2ERR_GRACE" },
	{	10014,	"NFS2ERR_FHEXPIRED" },
	{	10015,	"NFS2ERR_SHARE_DENIED" },
	{	10016,	"NFS2ERR_WRONGSEC" },
	{	10017,	"NFS2ERR_CLID_INUSE" },
	{	10018,	"NFS2ERR_RESOURCE" },
	{	10019,	"NFS2ERR_MOVED" },
	{	10020,	"NFS2ERR_NOFILEHANDLE" },
	{	10021,	"NFS2ERR_MINOR_VERS_MISMATCH" },
	{	10022,	"NFS2ERR_STALE_CLIENTID" },
	{	10023,	"NFS2ERR_STALE_STATEID" },
	{	10024,	"NFS2ERR_OLD_STATEID" },
	{	10025,	"NFS2ERR_BAD_STATEID" },
	{	10026,	"NFS2ERR_BAD_SEQID" },
	{	10027,	"NFS2ERR_NOT_SAME" },
	{	10028,	"NFS2ERR_LOCK_RANGE" },
	{	10029,	"NFS2ERR_SYMLINK" },
	{	10030,	"NFS2ERR_RESTOREFH" },
	{	10031,	"NFS2ERR_LEASE_MOVED" },
	{	10032,	"NFS2ERR_ATTRNOTSUPP" },
	{	10033,	"NFS2ERR_NO_GRACE" },
	{	10034,	"NFS2ERR_RECLAIM_BAD" },
	{	10035,	"NFS2ERR_RECLAIM_CONFLICT" },
	{	10036,	"NFS2ERR_BAD_XDR" },
	{	10037,	"NFS2ERR_LOCKS_HELD" },
	{	10038,	"NFS2ERR_OPENMODE" },
	{	10039,	"NFS2ERR_BADOWNER" },
	{	10040,	"NFS2ERR_BADCHAR" },
	{	10041,	"NFS2ERR_BADNAME" },
	{	10042,	"NFS2ERR_BAD_RANGE" },
	{	10043,	"NFS2ERR_LOCK_NOTSUPP" },
	{	10044,	"NFS2ERR_OP_ILLEGAL" },
	{	10045,	"NFS2ERR_DEADLOCK" },
	{	10046,	"NFS2ERR_FILE_OPEN" },
	{	10047,	"NFS2ERR_ADMIN_REVOKED" },
	{	10048,	"NFS2ERR_CB_PATH_DOWN" },
	{	10049,	"NFS2ERR_REPLAY_ME" },
	{	0,	NULL }
};
static value_string_ext names_nfs2_stat_ext = VALUE_STRING_EXT_INIT(names_nfs2_stat);

/* NFSv2 RFC 1094, Page 12..14 */
static int
dissect_nfs2_status(tvbuff_t *tvb, int offset, proto_tree *tree, guint32 *status)
{
	guint32	    stat;

	stat = tvb_get_ntohl(tvb, offset+0);

	if (tree) {
		proto_item *stat_item;

		proto_tree_add_uint(tree, hf_nfs2_status, tvb, offset+0, 4, stat);
		stat_item = proto_tree_add_uint(tree, hf_nfs_status, tvb, offset+0, 4, stat);
		PROTO_ITEM_SET_HIDDEN(stat_item);
	}

	offset += 4;

	if (status)
		*status = stat;

	return offset;
}


/* NFSv2 RFC 1094, Page 12..14 */
static int
dissect_nfs2_rmdir_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
	guint32	    status;
	const char *err;

	offset = dissect_nfs2_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			proto_item_append_text(tree, ", RMDIR Reply");
			break;
		default:
			err = val_to_str_ext(status, &names_nfs2_stat_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, ", RMDIR Reply  Error: %s", err);
	}

	return offset;
}


static int
dissect_nfs2_symlink_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
	guint32	    status;
	const char *err;

	offset = dissect_nfs2_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			proto_item_append_text(tree, ", SYMLINK Reply");
			break;
		default:
			err = val_to_str_ext(status, &names_nfs2_stat_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, ", SYMLINK Reply  Error: %s", err);
	}

	return offset;
}


static int
dissect_nfs2_link_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
	guint32	    status;
	const char *err;

	offset = dissect_nfs2_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			proto_item_append_text(tree, ", LINK Reply");
			break;
		default:
			err = val_to_str_ext(status, &names_nfs2_stat_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, ", LINK Reply  Error: %s", err);
	}

	return offset;
}


static int
dissect_nfs2_rename_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
	guint32	    status;
	const char *err;

	offset = dissect_nfs2_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			proto_item_append_text(tree, ", RENAME Reply");
			break;
		default:
			err = val_to_str_ext(status, &names_nfs2_stat_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, ", RENAME Reply  Error: %s", err);
	}

	return offset;
}


static int
dissect_nfs2_remove_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
	guint32	    status;
	const char *err;

	offset = dissect_nfs2_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			proto_item_append_text(tree, ", REMOVE Reply");
			break;
		default:
			err = val_to_str_ext(status, &names_nfs2_stat_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, ", REMOVE Reply  Error: %s", err);
	}

	return offset;
}


/* NFSv2 RFC 1094, Page 15 */
static const value_string nfs2_ftype[] =
{
	{	0,	"Non-File" },
	{	1,	"Regular File" },
	{	2,	"Directory" },
	{	3,	"Block Special Device" },
	{	4,	"Character Special Device" },
	{	5,	"Symbolic Link" },
	{	0,	NULL }
};
static value_string_ext nfs2_ftype_ext = VALUE_STRING_EXT_INIT(nfs2_ftype);

static int
dissect_nfs2_ftype(tvbuff_t *tvb, int offset, proto_tree *tree, const char *name)
{
	guint32	    ftype;

	ftype = tvb_get_ntohl(tvb, offset+0);

	if (tree) {
		const char *ftype_name_p;

		ftype_name_p = val_to_str_ext(ftype, &nfs2_ftype_ext, "%u");

		proto_tree_add_text(tree, tvb, offset, 4,
			"%s: %s (%u)", name, ftype_name_p, ftype);
	}

	offset += 4;
	return offset;
}


/* NFSv2 RFC 1094, Page 15 */
int
dissect_fhandle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree,
	        const char *name, guint32 *hash, rpc_call_info_value *civ)
{
	proto_item *fitem = NULL;
	proto_tree *ftree = NULL;

	if (tree) {
		fitem = proto_tree_add_text(tree, tvb, offset, FHSIZE,
			"%s", name);

		ftree = proto_item_add_subtree(fitem, ett_nfs_fhandle);
	}

	/* are we snooping fh to filenames ?*/
	if ((!pinfo->fd->flags.visited) && nfs_file_name_snooping) {

		/* NFS v2 LOOKUP, CREATE, MKDIR calls might give us a mapping*/
		if ( (civ->prog == 100003)
		  &&(civ->vers == 2)
		  &&(!civ->request)
		  &&((civ->proc == 4)||(civ->proc == 9)||(civ->proc == 14))
		) {
			nfs_name_snoop_add_fh(civ->xid, tvb,
				offset, 32);
		}

		/* MOUNT v1,v2 MNT replies might give us a filehandle*/
		if ( (civ->prog == 100005)
		  &&(civ->proc == 1)
		  &&((civ->vers == 1)||(civ->vers == 2))
		  &&(!civ->request)
		) {
			nfs_name_snoop_add_fh(civ->xid, tvb,
				offset, 32);
		}
	}

	dissect_fhandle_data(tvb, offset, pinfo, ftree, FHSIZE, FALSE, hash);

	offset += FHSIZE;
	return offset;
}


/* NFSv2 RFC 1094, Page 15 */
static int
dissect_nfs2_statfs_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, void *data)
{
	guint32 hash;

	offset = dissect_fhandle(tvb, offset, pinfo, tree, "object", &hash, (rpc_call_info_value*)data);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", FH: 0x%08x", hash);
	proto_item_append_text(tree, ", STATFS Call FH: 0x%08x", hash);

	return offset;
}


static int
dissect_nfs2_readlink_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, void *data)
{
	guint32 hash;

	offset = dissect_fhandle(tvb, offset, pinfo, tree, "object", &hash, (rpc_call_info_value*)data);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", FH: 0x%08x", hash);
	proto_item_append_text(tree, ", READLINK Call FH: 0x%08x", hash);

	return offset;
}


static int
dissect_nfs2_getattr_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, void *data)
{
	guint32 hash;

	offset = dissect_fhandle(tvb, offset, pinfo, tree, "object", &hash, (rpc_call_info_value*)data);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", FH: 0x%08x", hash);
	proto_item_append_text(tree, ", GETATTR Call FH: 0x%08x", hash);

	return offset;
}


/* NFSv2 RFC 1094, Page 15 */
static int
dissect_timeval(tvbuff_t *tvb, int offset, proto_tree *tree, int hf_time, int hf_time_sec,
			    int hf_time_usec)
{

	if (tree) {
		proto_item *time_item;
		proto_tree *time_tree;
		guint32	    seconds;
		guint32	    useconds;
		nstime_t    ts;

		seconds	 = tvb_get_ntohl(tvb, offset+0);
		useconds = tvb_get_ntohl(tvb, offset+4);
		ts.secs	 = seconds;
		ts.nsecs = useconds * 1000;

		time_item = proto_tree_add_time(tree, hf_time, tvb, offset, 8,
				&ts);

		time_tree = proto_item_add_subtree(time_item, ett_nfs_timeval);

		proto_tree_add_uint(time_tree, hf_time_sec, tvb, offset, 4,
				    seconds);
		proto_tree_add_uint(time_tree, hf_time_usec, tvb, offset+4, 4,
				    useconds);
	}
	offset += 8;
	return offset;
}

/* NFSv2 RFC 1094, Page 16 */
static const value_string nfs2_mode_names[] = {
	{	0040000,	"Directory"	},
	{	0020000,	"Character Special Device"	},
	{	0060000,	"Block Special Device"	},
	{	0100000,	"Regular File"	},
	{	0120000,	"Symbolic Link"	},
	{	0140000,	"Named Socket"	},
	{	0000000,	NULL		}
};

static int
dissect_nfs2_mode(tvbuff_t *tvb, int offset, proto_tree *tree, const char *label)
{


	if (tree) {
		guint32	    mode;
		proto_item *mode_item;
		proto_tree *mode_tree;

		mode = tvb_get_ntohl(tvb, offset+0);
		mode_item = proto_tree_add_text(tree, tvb, offset, 4, "%s: 0%o", label, mode);
		mode_tree = proto_item_add_subtree(mode_item, ett_nfs2_mode);

		proto_tree_add_item(mode_tree, hf_nfs2_mode_name, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(mode_tree, hf_nfs2_mode_set_user_id, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(mode_tree, hf_nfs2_mode_set_group_id, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(mode_tree, hf_nfs2_mode_save_swap_text, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(mode_tree, hf_nfs2_mode_read_owner, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(mode_tree, hf_nfs2_mode_write_owner, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(mode_tree, hf_nfs2_mode_exec_owner, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(mode_tree, hf_nfs2_mode_read_group, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(mode_tree, hf_nfs2_mode_write_group, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(mode_tree, hf_nfs2_mode_exec_group, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(mode_tree, hf_nfs2_mode_read_other, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(mode_tree, hf_nfs2_mode_write_other, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(mode_tree, hf_nfs2_mode_exec_other, tvb, offset, 4, ENC_BIG_ENDIAN);
	}

	offset += 4;
	return offset;
}


/* NFSv2 RFC 1094, Page 15 */
int
dissect_nfs2_fattr(tvbuff_t *tvb, int offset, proto_tree *tree, const char *name)
{
	proto_item *fattr_item = NULL;
	proto_tree *fattr_tree = NULL;
	int	    old_offset = offset;

	if (tree) {
		fattr_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s", name);
		fattr_tree = proto_item_add_subtree(fattr_item, ett_nfs_fattr);
	}

	offset = dissect_nfs2_ftype(tvb, offset, fattr_tree, "type");
	offset = dissect_nfs2_mode(tvb, offset, fattr_tree, "mode");
	offset = dissect_rpc_uint32(tvb, fattr_tree, hf_nfs2_fattr_nlink, offset);
	offset = dissect_rpc_uint32(tvb, fattr_tree, hf_nfs2_fattr_uid, offset);
	offset = dissect_rpc_uint32(tvb, fattr_tree, hf_nfs2_fattr_gid, offset);
	offset = dissect_rpc_uint32(tvb, fattr_tree, hf_nfs2_fattr_size, offset);
	offset = dissect_rpc_uint32(tvb, fattr_tree, hf_nfs2_fattr_blocksize, offset);
	offset = dissect_rpc_uint32(tvb, fattr_tree, hf_nfs2_fattr_rdev, offset);
	offset = dissect_rpc_uint32(tvb, fattr_tree, hf_nfs2_fattr_blocks, offset);
	offset = dissect_rpc_uint32(tvb, fattr_tree, hf_nfs2_fattr_fsid, offset);
	offset = dissect_rpc_uint32(tvb, fattr_tree, hf_nfs2_fattr_fileid, offset);

	offset = dissect_timeval(tvb, offset, fattr_tree,
		hf_nfs_atime, hf_nfs_atime_sec, hf_nfs_atime_usec);
	offset = dissect_timeval(tvb, offset, fattr_tree,
		hf_nfs_mtime, hf_nfs_mtime_sec, hf_nfs_mtime_usec);
	offset = dissect_timeval(tvb, offset, fattr_tree,
		hf_nfs_ctime, hf_nfs_ctime_sec, hf_nfs_ctime_usec);

	/* now we know, that fattr is shorter */
	if (fattr_item) {
		proto_item_set_len(fattr_item, offset - old_offset);
	}

	return offset;
}


/* NFSv2 RFC 1094, Page 17 */
static int
dissect_nfs2_sattr(tvbuff_t *tvb, int offset, proto_tree *tree, const char *name)
{
	proto_item *sattr_item = NULL;
	proto_tree *sattr_tree = NULL;
	int	    old_offset = offset;

	if (tree) {
		sattr_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s", name);
		sattr_tree = proto_item_add_subtree(sattr_item, ett_nfs2_sattr);
	}

	if (tvb_get_ntohl(tvb, offset+0) != 0xffffffff)
		offset = dissect_nfs2_mode(tvb, offset, sattr_tree, "mode");
	else {
		proto_tree_add_text(sattr_tree, tvb, offset, 4, "mode: no value");
		offset += 4;
	}

	if (tvb_get_ntohl(tvb, offset+0) != 0xffffffff)
		offset = dissect_rpc_uint32(tvb, sattr_tree, hf_nfs2_fattr_uid,
			offset);
	else {
		proto_tree_add_text(sattr_tree, tvb, offset, 4, "uid: no value");
		offset += 4;
	}

	if (tvb_get_ntohl(tvb, offset+0) != 0xffffffff)
		offset = dissect_rpc_uint32(tvb, sattr_tree, hf_nfs2_fattr_gid,
			offset);
	else {
		proto_tree_add_text(sattr_tree, tvb, offset, 4, "gid: no value");
		offset += 4;
	}

	if (tvb_get_ntohl(tvb, offset+0) != 0xffffffff)
		offset = dissect_rpc_uint32(tvb, sattr_tree, hf_nfs2_fattr_size,
			offset);
	else {
		proto_tree_add_text(sattr_tree, tvb, offset, 4, "size: no value");
		offset += 4;
	}

	if (tvb_get_ntohl(tvb, offset+0) != 0xffffffff) {
		offset = dissect_timeval(tvb, offset, sattr_tree,
			hf_nfs_atime, hf_nfs_atime_sec, hf_nfs_atime_usec);
	} else {
		proto_tree_add_text(sattr_tree, tvb, offset, 8, "atime: no value");
		offset += 8;
	}

	if (tvb_get_ntohl(tvb, offset+0) != 0xffffffff) {
		offset = dissect_timeval(tvb, offset, sattr_tree,
			hf_nfs_mtime, hf_nfs_mtime_sec, hf_nfs_mtime_usec);
	} else {
		proto_tree_add_text(sattr_tree, tvb, offset, 8, "mtime: no value");
		offset += 8;
	}

	/* now we know, that sattr is shorter */
	if (sattr_item) {
		proto_item_set_len(sattr_item, offset - old_offset);
	}

	return offset;
}


/* NFSv2 RFC 1094, Page 17 */
static int
dissect_filename(tvbuff_t *tvb, int offset, proto_tree *tree, int hf, const char **string_ret)
{
	offset = dissect_rpc_string(tvb, tree, hf, offset, string_ret);
	return offset;
}


/* NFSv2 RFC 1094, Page 17 */
static int
dissect_path(tvbuff_t *tvb, int offset, proto_tree *tree, int hf, const char **name)
{
	offset = dissect_rpc_string(tvb, tree, hf, offset, name);
	return offset;
}


/* NFSv2 RFC 1094, Page 17,18 */
static int
dissect_attrstat(tvbuff_t *tvb, int offset, proto_tree *tree, packet_info *pinfo, const char *funcname)
{
	guint32	    status;
	const char *err;

	offset = dissect_nfs2_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_nfs2_fattr(tvb, offset, tree, "attributes");
			proto_item_append_text(tree, ", %s Reply", funcname);
		break;
		default:
			err = val_to_str_ext(status, &names_nfs2_stat_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, ", %s Reply  Error: %s", funcname, err);
		break;
	}

	return offset;
}


/* NFSv2 RFC 1094, Page 17,18 */
static int
dissect_nfs2_write_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
	offset = dissect_attrstat(tvb, offset, tree, pinfo, "WRITE");

	return offset;
}


/* NFSv2 RFC 1094, Page 18 */
static int
dissect_nfs2_setattr_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
	offset = dissect_attrstat(tvb, offset, tree, pinfo, "SETATTR");

	return offset;
}


/* NFSv2 RFC 1094, Page 18 */
static int
dissect_nfs2_getattr_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
	offset = dissect_attrstat(tvb, offset, tree, pinfo, "GETATTR");

	return offset;
}


/* NFSv2 RFC 1094, Page 18 */
static int
dissect_diropargs(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree,
				  const char *label, guint32 *hash, const char **name, rpc_call_info_value *civ)
{
	proto_item *diropargs_item = NULL;
	proto_tree *diropargs_tree = NULL;
	int	    old_offset	   = offset;

	if (tree) {
		diropargs_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s", label);
		diropargs_tree = proto_item_add_subtree(diropargs_item, ett_nfs2_diropargs);
	}

	/* are we snooping fh to filenames ?*/
	if ((!pinfo->fd->flags.visited) && nfs_file_name_snooping) {
		/* v2 LOOKUP, CREATE, MKDIR calls might give us a mapping*/

		if ( (civ->prog == 100003)
		  &&(civ->vers == 2)
		  &&(civ->request)
		  &&((civ->proc == 4)||(civ->proc == 9)||(civ->proc == 14))
		) {
			nfs_name_snoop_add_name(civ->xid, tvb,
				offset+36, tvb_get_ntohl(tvb, offset+32),
				offset, 32, NULL);
		}
	}

	offset = dissect_fhandle(tvb, offset, pinfo, diropargs_tree, "dir", hash, civ);
	offset = dissect_filename(tvb, offset, diropargs_tree, hf_nfs_name, name);

	/* now we know, that diropargs is shorter */
	if (diropargs_item) {
		proto_item_set_len(diropargs_item, offset - old_offset);
	}

	return offset;
}


/* NFSv2 RFC 1094, Page 18 */
static int
dissect_nfs2_rmdir_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, void *data)
{
	guint32	    hash;
	const char *name = NULL;

	offset = dissect_diropargs(tvb, offset, pinfo, tree, "where", &hash, &name, (rpc_call_info_value*)data);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", DH: 0x%08x/%s", hash, name);
	proto_item_append_text(tree, ", RMDIR Call DH: 0x%08x/%s", hash, name);

	return offset;
}


/* NFSv2 RFC 1094, Page 18 */
static int
dissect_nfs2_remove_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, void *data)
{
	guint32	    hash;
	const char *name = NULL;

	offset = dissect_diropargs(tvb, offset, pinfo, tree, "where", &hash, &name, (rpc_call_info_value*)data);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", DH: 0x%08x/%s", hash, name);
	proto_item_append_text(tree, ", REMOVE Call DH: 0x%08x/%s", hash, name);

	return offset;
}


/* NFSv2 RFC 1094, Page 18 */
static int
dissect_nfs2_lookup_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, void *data)
{
	guint32	    hash;
	const char *name = NULL;

	offset = dissect_diropargs(tvb, offset, pinfo, tree, "where", &hash, &name, (rpc_call_info_value*)data);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", DH: 0x%08x/%s", hash, name);
	proto_item_append_text(tree, ", LOOKUP Call DH: 0x%08x/%s", hash, name);

	return offset;
}


/* NFSv2 RFC 1094, Page 18 */
static int
dissect_diropres(tvbuff_t *tvb, int offset, packet_info *pinfo,
		 proto_tree *tree, const char *funcname, rpc_call_info_value* civ)
{
	guint32	    status;
	guint32	    hash;
	const char *err;

	offset = dissect_nfs2_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_fhandle(tvb, offset, pinfo, tree, "file", &hash, civ);
			offset = dissect_nfs2_fattr  (tvb, offset, tree, "attributes");
			col_append_fstr(pinfo->cinfo, COL_INFO, ", FH: 0x%08x", hash);
			proto_item_append_text(tree, ", %s Reply FH: 0x%08x", funcname, hash);
		break;
		default:
			err = val_to_str_ext(status, &names_nfs2_stat_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, ", %s Reply  Error: %s", funcname, err);
		break;
	}

	return offset;
}


/* nfsdata is simply a chunk of RPC opaque data (length, data, fill bytes) */
static int
dissect_nfsdata(tvbuff_t *tvb, int offset, proto_tree *tree, int hf)
{
	offset = dissect_rpc_data(tvb, tree, hf, offset);
	return offset;
}


/* NFSv2 RFC 1094, Page 18 */
static int
dissect_nfs2_mkdir_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
			 proto_tree *tree, void *data)
{
	offset = dissect_diropres(tvb, offset, pinfo, tree, "MKDIR", (rpc_call_info_value*)data);
	return offset;
}


static int
dissect_nfs2_create_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
			  proto_tree *tree, void *data _U_)
{
	offset = dissect_diropres(tvb, offset, pinfo, tree, "CREATE", (rpc_call_info_value*)data);
	return offset;
}


static int
dissect_nfs2_lookup_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
			  proto_tree *tree, void *data _U_)
{
	offset = dissect_diropres(tvb, offset, pinfo, tree, "LOOKUP", (rpc_call_info_value*)data);
	return offset;
}


/* RFC 1094, Page 6 */
static int
dissect_nfs2_setattr_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
			  proto_tree *tree, void *data)
{
	guint32 hash;

	offset = dissect_fhandle(tvb, offset, pinfo, tree, "file", &hash, (rpc_call_info_value*)data);
	offset = dissect_nfs2_sattr  (tvb, offset,        tree, "attributes");

	col_append_fstr(pinfo->cinfo, COL_INFO, ", FH: 0x%08x", hash);
	proto_item_append_text(tree, ", SETATTR Call FH: 0x%08x", hash);
	return offset;
}


/* NFSv2 RFC 1094, Page 6 */
static int
dissect_nfs2_readlink_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			    proto_tree *tree, void *data _U_)
{
	guint32	    status;
	const char *err;
	const char *name = NULL;

	offset = dissect_nfs2_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_path(tvb, offset, tree, hf_nfs2_readlink_data, &name);
			col_append_fstr(pinfo->cinfo, COL_INFO, " Path: %s", name);
			proto_item_append_text(tree, ", READLINK Reply Path: %s", name);
		break;
		default:
			err = val_to_str_ext(status, &names_nfs2_stat_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, ", READLINK Reply  Error: %s", err);
		break;
	}

	return offset;
}


/* NFSv2 RFC 1094, Page 7 */
static int
dissect_nfs2_read_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
		       proto_tree *tree, void *data)
{
	guint32 offset_value;
	guint32 count;
	guint32 totalcount;
	guint32 hash;

	offset = dissect_fhandle(tvb, offset, pinfo, tree, "file", &hash, (rpc_call_info_value*)data);
	offset_value = tvb_get_ntohl(tvb, offset+0);
	count        = tvb_get_ntohl(tvb, offset+4);
	totalcount   = tvb_get_ntohl(tvb, offset+8);
	if (tree) {
		proto_tree_add_uint(tree, hf_nfs2_read_offset, tvb,
		offset+0, 4, offset_value);
		proto_tree_add_uint(tree, hf_nfs2_read_count, tvb,
		offset+4, 4, count);
		proto_tree_add_uint(tree, hf_nfs2_read_totalcount, tvb,
		offset+8, 4, totalcount);
	}
	offset += 12;

	col_append_fstr(pinfo->cinfo, COL_INFO,	", FH: 0x%08x Offset: %d Count: %d TotalCount: %d",
		hash, offset_value, count, totalcount);
	proto_item_append_text(tree, ", READ Call FH: 0x%08x Offset: %d Count: %d TotalCount: %d",
		hash, offset_value, count, totalcount);

	return offset;
}


/* NFSv2 RFC 1094, Page 7 */
static int
dissect_nfs2_read_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			proto_tree *tree, void *data _U_)
{
	guint32	    status;
	const char *err;

	offset = dissect_nfs2_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_nfs2_fattr(tvb, offset, tree, "attributes");
			proto_item_append_text(tree, ", READ Reply");
			offset = dissect_nfsdata(tvb, offset, tree, hf_nfs_data);
		break;
		default:
			err = val_to_str_ext(status, &names_nfs2_stat_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, ", READ Reply  Error: %s", err);
		break;
	}

	return offset;
}


/* NFSv2 RFC 1094, Page 8 */
static int
dissect_nfs2_write_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *tree, void *data)
{
	guint32 beginoffset;
	guint32 offset_value;
	guint32 totalcount;
	guint32 hash;

	offset = dissect_fhandle(tvb, offset, pinfo, tree, "file", &hash, (rpc_call_info_value*)data);
	beginoffset  = tvb_get_ntohl(tvb, offset+0);
	offset_value = tvb_get_ntohl(tvb, offset+4);
	totalcount   = tvb_get_ntohl(tvb, offset+8);
	if (tree) {
		proto_tree_add_uint(tree, hf_nfs2_write_beginoffset, tvb,
		offset+0, 4, beginoffset);
		proto_tree_add_uint(tree, hf_nfs2_write_offset, tvb,
		offset+4, 4, offset_value);
		proto_tree_add_uint(tree, hf_nfs2_write_totalcount, tvb,
		offset+8, 4, totalcount);
	}
	offset += 12;

	col_append_fstr(pinfo->cinfo, COL_INFO, ", FH: 0x%08x BeginOffset: %d Offset: %d TotalCount: %d",
		hash, beginoffset, offset_value, totalcount);
	proto_item_append_text(tree, ", WRITE Call FH: 0x%08x BeginOffset: %d Offset: %d TotalCount: %d",
		hash, beginoffset, offset_value, totalcount);

	offset = dissect_nfsdata(tvb, offset, tree, hf_nfs_data);

	return offset;
}


/* NFSv2 RFC 1094, Page 8 */
static int
dissect_nfs2_mkdir_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *tree, void *data)
{
	guint32	    hash;
	const char *name = NULL;

	offset = dissect_diropargs(tvb, offset, pinfo, tree, "where", &hash, &name, (rpc_call_info_value*)data);
	offset = dissect_nfs2_sattr    (tvb, offset,        tree, "attributes");

	col_append_fstr(pinfo->cinfo, COL_INFO, ", DH: 0x%08x/%s", hash, name);
	proto_item_append_text(tree, ", MKDIR Call DH: 0x%08x/%s", hash, name);

	return offset;
}

static int
dissect_nfs2_create_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
			 proto_tree *tree, void *data)
{
	guint32	    hash;
	const char *name = NULL;

	offset = dissect_diropargs(tvb, offset, pinfo, tree, "where", &hash, &name, (rpc_call_info_value*)data);
	offset = dissect_nfs2_sattr    (tvb, offset,        tree, "attributes");

	col_append_fstr(pinfo->cinfo, COL_INFO, ", DH: 0x%08x/%s", hash, name);
	proto_item_append_text(tree, ", CREATE Call DH: 0x%08x/%s", hash, name);

	return offset;
}


/* NFSv2 RFC 1094, Page 9 */
static int
dissect_nfs2_rename_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
			 proto_tree *tree, void *data)
{
	guint32	    from_hash;
	const char *from_name = NULL;
	guint32	    to_hash;
	const char *to_name   = NULL;

	offset = dissect_diropargs(tvb, offset, pinfo, tree, "from", &from_hash, &from_name, (rpc_call_info_value*)data);
	offset = dissect_diropargs(tvb, offset, pinfo, tree, "to", &to_hash, &to_name, (rpc_call_info_value*)data);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", From DH: 0x%08x/%s To DH: 0x%08x/%s",
		from_hash, from_name, to_hash, to_name);
	proto_item_append_text(tree, ", RENAME Call From DH: 0x%08x/%s To DH: 0x%08x/%s",
		from_hash, from_name, to_hash, to_name);

	return offset;
}


/* NFSv2 RFC 1094, Page 9 */
static int
dissect_nfs2_link_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
		       proto_tree *tree, void *data)
{
	guint32	    from_hash;
	guint32	    to_hash;
	const char *to_name = NULL;

	offset = dissect_fhandle(tvb, offset, pinfo, tree, "from", &from_hash, (rpc_call_info_value*)data);
	offset = dissect_diropargs(tvb, offset, pinfo, tree, "to", &to_hash, &to_name, (rpc_call_info_value*)data);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", From DH: 0x%08x To DH: 0x%08x/%s",
		from_hash, to_hash, to_name);
	proto_item_append_text(tree, ", LINK Call From DH: 0x%08x To DH: 0x%08x/%s",
		from_hash, to_hash, to_name);

	return offset;
}


/* NFSv2 RFC 1094, Page 10 */
static int
dissect_nfs2_symlink_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
			  proto_tree *tree, void *data)
{
	guint32	    from_hash;
	const char *from_name = NULL;
	const char *to_name   = NULL;

	offset = dissect_diropargs(tvb, offset, pinfo, tree, "from", &from_hash, &from_name, (rpc_call_info_value*)data);
	offset = dissect_path(tvb, offset, tree, hf_nfs_symlink_to, &to_name);
	offset = dissect_nfs2_sattr(tvb, offset, tree, "attributes");

	col_append_fstr(pinfo->cinfo, COL_INFO, ", From DH: 0x%08x/%s To %s",
		from_hash, from_name, to_name);
	proto_item_append_text(tree, ", SYMLINK Call From DH: 0x%08x/%s To %s",
		from_hash, from_name, to_name);

	return offset;
}


/* NFSv2 RFC 1094, Page 11 */
static int
dissect_nfs2_readdir_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
			  proto_tree *tree, void *data)
{
	guint32	cookie;
	guint32	count;
	guint32 hash;

	offset = dissect_fhandle(tvb, offset, pinfo, tree, "dir", &hash, (rpc_call_info_value*)data);
	cookie  = tvb_get_ntohl(tvb, offset+ 0);
	count = tvb_get_ntohl(tvb, offset+ 4);
	if (tree) {
		proto_tree_add_uint(tree, hf_nfs2_readdir_cookie, tvb,
			offset+ 0, 4, cookie);
		proto_tree_add_uint(tree, hf_nfs2_readdir_count, tvb,
			offset+ 4, 4, count);
	}
	offset += 8;

	col_append_fstr(pinfo->cinfo, COL_INFO, ", FH: 0x%08x", hash);
	proto_item_append_text(tree, ", READDIR Call FH: 0x%08x", hash);

	return offset;
}


/* NFSv2 RFC 1094, Page 11 */
static int
dissect_readdir_entry(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		      proto_tree *tree, void *data _U_)
{
	proto_item *entry_item = NULL;
	proto_tree *entry_tree = NULL;
	int	    old_offset = offset;
	guint32	    fileid;
	guint32	    cookie;
	const char *name;

	if (tree) {
		entry_item = proto_tree_add_item(tree, hf_nfs_readdir_entry, tvb,
			offset+0, -1, ENC_NA);
		entry_tree = proto_item_add_subtree(entry_item, ett_nfs_readdir_entry);
	}

	fileid = tvb_get_ntohl(tvb, offset + 0);
	if (entry_tree)
		proto_tree_add_uint(entry_tree, hf_nfs2_readdir_entry_fileid, tvb,
			offset+0, 4, fileid);
	offset += 4;

	offset = dissect_filename(tvb, offset, entry_tree,
		hf_nfs2_readdir_entry_name, &name);
	if (entry_item)
		proto_item_set_text(entry_item, "Entry: file ID %u, name %s",
		fileid, name);

	cookie = tvb_get_ntohl(tvb, offset + 0);
	if (entry_tree)
		proto_tree_add_uint(entry_tree, hf_nfs2_readdir_entry_cookie, tvb,
			offset+0, 4, cookie);
	offset += 4;

	/* now we know, that a readdir entry is shorter */
	if (entry_item) {
		proto_item_set_len(entry_item, offset - old_offset);
	}

	return offset;
}


/* NFSv2 RFC 1094, Page 11 */
static int
dissect_nfs2_readdir_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, void *data _U_)
{
	guint32	    status;
	guint32	    eof_value;
	const char *err;

	offset = dissect_nfs2_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			proto_item_append_text(tree, ", READDIR Reply");

			offset = dissect_rpc_list(tvb, pinfo, tree, offset,
				dissect_readdir_entry, NULL);
			eof_value = tvb_get_ntohl(tvb, offset+0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs_readdir_eof, tvb,
					offset+ 0, 4, eof_value);
			offset += 4;
		break;
		default:
			err = val_to_str_ext(status, &names_nfs2_stat_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, ", READDIR Reply  Error: %s", err);
		break;
	}

	return offset;
}


/* NFSv2 RFC 1094, Page 12 */
static int
dissect_nfs2_statfs_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			  proto_tree *tree, void *data _U_)
{
	guint32	    status;
	guint32	    tsize;
	guint32	    bsize;
	guint32	    blocks;
	guint32	    bfree;
	guint32	    bavail;
	const char *err;

	offset = dissect_nfs2_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			tsize  = tvb_get_ntohl(tvb, offset+ 0);
			bsize  = tvb_get_ntohl(tvb, offset+ 4);
			blocks = tvb_get_ntohl(tvb, offset+ 8);
			bfree  = tvb_get_ntohl(tvb, offset+12);
			bavail = tvb_get_ntohl(tvb, offset+16);
			if (tree) {
				proto_tree_add_uint(tree, hf_nfs2_statfs_tsize, tvb,
					offset+ 0, 4, tsize);
				proto_tree_add_uint(tree, hf_nfs2_statfs_bsize, tvb,
					offset+ 4, 4, bsize);
				proto_tree_add_uint(tree, hf_nfs2_statfs_blocks, tvb,
					offset+ 8, 4, blocks);
				proto_tree_add_uint(tree, hf_nfs2_statfs_bfree, tvb,
					offset+12, 4, bfree);
				proto_tree_add_uint(tree, hf_nfs2_statfs_bavail, tvb,
					offset+16, 4, bavail);
			}
			offset += 20;
			proto_item_append_text(tree, ", STATFS Reply");
		break;
		default:
			err = val_to_str_ext(status, &names_nfs2_stat_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, ", STATFS Reply  Error: %s", err);
		break;
	}

	return offset;
}


/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: type of arguments is "void". */
static const vsff nfs2_proc[] = {
	{ 0,	"NULL",		/* OK */
	NULL,				NULL },
	{ 1,	"GETATTR",	/* OK */
	dissect_nfs2_getattr_call,	dissect_nfs2_getattr_reply },
	{ 2,	"SETATTR",	/* OK */
	dissect_nfs2_setattr_call,	dissect_nfs2_setattr_reply },
	{ 3,	"ROOT",		/* OK */
	NULL,				NULL },
	{ 4,	"LOOKUP",	/* OK */
	dissect_nfs2_lookup_call,	dissect_nfs2_lookup_reply },
	{ 5,	"READLINK",	/* OK */
	dissect_nfs2_readlink_call,	dissect_nfs2_readlink_reply },
	{ 6,	"READ",		/* OK */
	dissect_nfs2_read_call,		dissect_nfs2_read_reply },
	{ 7,	"WRITECACHE",	/* OK */
	NULL,				NULL },
	{ 8,	"WRITE",	/* OK */
	dissect_nfs2_write_call,	dissect_nfs2_write_reply },
	{ 9,	"CREATE",	/* OK */
	dissect_nfs2_create_call,	dissect_nfs2_create_reply },
	{ 10,	"REMOVE",	/* OK */
	dissect_nfs2_remove_call,	dissect_nfs2_remove_reply },
	{ 11,	"RENAME",	/* OK */
	dissect_nfs2_rename_call,	dissect_nfs2_rename_reply },
	{ 12,	"LINK",		/* OK */
	dissect_nfs2_link_call,		dissect_nfs2_link_reply },
	{ 13,	"SYMLINK",	/* OK */
	dissect_nfs2_symlink_call,	dissect_nfs2_symlink_reply },
	{ 14,	"MKDIR",	/* OK */
	dissect_nfs2_mkdir_call,	dissect_nfs2_mkdir_reply },
	{ 15,	"RMDIR",	/* OK */
	dissect_nfs2_rmdir_call,	dissect_nfs2_rmdir_reply },
	{ 16,	"READDIR",	/* OK */
	dissect_nfs2_readdir_call,	dissect_nfs2_readdir_reply },
	{ 17,	"STATFS",	/* OK */
	dissect_nfs2_statfs_call,	dissect_nfs2_statfs_reply },
	{ 0,	NULL,	NULL,	NULL }
};

static const value_string nfs2_proc_vals[] = {
	{ 0,	"NULL" },
	{ 1,	"GETATTR" },
	{ 2,	"SETATTR" },
	{ 3,	"ROOT" },
	{ 4,	"LOOKUP" },
	{ 5,	"READLINK" },
	{ 6,	"READ" },
	{ 7,	"WRITECACHE" },
	{ 8,	"WRITE" },
	{ 9,	"CREATE" },
	{ 10,	"REMOVE" },
	{ 11,	"RENAME" },
	{ 12,	"LINK" },
	{ 13,	"SYMLINK" },
	{ 14,	"MKDIR" },
	{ 15,	"RMDIR" },
	{ 16,	"READDIR" },
	{ 17,	"STATFS" },
	{ 0,	NULL }
};
static value_string_ext nfs2_proc_vals_ext = VALUE_STRING_EXT_INIT(nfs2_proc_vals);

/* end of NFS Version 2 */


/***************************/
/* NFS Version 3, RFC 1813 */
/***************************/

/* NFSv3 RFC 1813, Page 15 */
static int
dissect_nfs3_filename(tvbuff_t *tvb, int offset, proto_tree *tree, int hf, const char **string_ret)
{
	offset = dissect_rpc_string(tvb, tree, hf, offset, string_ret);
	return offset;
}


/* NFSv3 RFC 1813, Page 15 */
static int
dissect_nfs3_path(tvbuff_t *tvb, int offset, proto_tree *tree, int hf, const char **name)
{
	offset = dissect_rpc_string(tvb, tree, hf, offset, name);
	return offset;
}


/* NFSv3 RFC 1813, Page 15 */
static int
dissect_nfs3_cookie_verf(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_tree_add_text(tree, tvb, offset, NFS3_COOKIEVERFSIZE,
		"Verifier: Opaque Data");
	offset += NFS3_COOKIEVERFSIZE;
	return offset;
}


/* NFSv3 RFC 1813, Page 16 */
static int
dissect_nfs3_create_verf(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_tree_add_text(tree, tvb, offset, NFS3_CREATEVERFSIZE,
		"Verifier: Opaque Data");
	offset += NFS3_CREATEVERFSIZE;
	return offset;
}


/* NFSv3 RFC 1813, Page 16 */
static int
dissect_nfs3_write_verf(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_tree_add_text(tree, tvb, offset, NFS3_WRITEVERFSIZE,
		"Verifier: Opaque Data");
	offset += NFS3_WRITEVERFSIZE;
	return offset;
}


/* RFC 1813, Page 16 */
static int
dissect_nfs3_mode(tvbuff_t *tvb, int offset, proto_tree *tree, guint32 *mode)
{
	static const int *mode_bits[] = {
		&hf_nfs3_mode_suid,
		&hf_nfs3_mode_sgid,
		&hf_nfs3_mode_sticky,
		&hf_nfs3_mode_rusr,
		&hf_nfs3_mode_wusr,
		&hf_nfs3_mode_xusr,
		&hf_nfs3_mode_rgrp,
		&hf_nfs3_mode_wgrp,
		&hf_nfs3_mode_xgrp,
		&hf_nfs3_mode_roth,
		&hf_nfs3_mode_woth,
		&hf_nfs3_mode_xoth,
		NULL
	};


	if (mode) {
		*mode = tvb_get_ntohl(tvb, offset+0);
	}

	proto_tree_add_bitmask(tree, tvb, offset, hf_nfs3_mode, ett_nfs3_mode, mode_bits, ENC_BIG_ENDIAN);

	offset += 4;
	return offset;
}


/* NFSv3 RFC 1813, Page 16,17 */
static const value_string names_nfs_nfsstat3[] =
{
	{	0,	"NFS3_OK" },
	{	1,	"NFS3ERR_PERM" },
	{	2,	"NFS3ERR_NOENT" },
	{	5,	"NFS3ERR_IO" },
	{	6,	"NFS3ERR_NXIO" },
	{	13,	"NFS3ERR_ACCES" },
	{	17,	"NFS3ERR_EXIST" },
	{	18,	"NFS3ERR_XDEV" },
	{	19,	"NFS3ERR_NODEV" },
	{	20,	"NFS3ERR_NOTDIR" },
	{	21,	"NFS3ERR_ISDIR" },
	{	22,	"NFS3ERR_INVAL" },
	{	27,	"NFS3ERR_FBIG" },
	{	28,	"NFS3ERR_NOSPC" },
	{	30,	"NFS3ERR_ROFS" },
	{	31,	"NFS3ERR_MLINK" },
	{	63,	"NFS3ERR_NAMETOOLONG" },
	{	66,	"NFS3ERR_NOTEMPTY" },
	{	69,	"NFS3ERR_DQUOT" },
	{	70,	"NFS3ERR_STALE" },
	{	71,	"NFS3ERR_REMOTE" },
	{	10001,	"NFS3ERR_BADHANDLE" },
	{	10002,	"NFS3ERR_NOT_SYNC" },
	{	10003,	"NFS3ERR_BAD_COOKIE" },
	{	10004,	"NFS3ERR_NOTSUPP" },
	{	10005,	"NFS3ERR_TOOSMALL" },
	{	10006,	"NFS3ERR_SERVERFAULT" },
	{	10007,	"NFS3ERR_BADTYPE" },
	{	10008,	"NFS3ERR_JUKEBOX" },
	{	0,	NULL }
};
static value_string_ext names_nfs3_status_ext = VALUE_STRING_EXT_INIT(names_nfs_nfsstat3);

/* NFSv3 RFC 1813, Page 16 */
static int
dissect_nfs3_status(tvbuff_t *tvb, int offset, proto_tree *tree, guint32 *status)
{
	guint32	    nfsstat3;

	nfsstat3 = tvb_get_ntohl(tvb, offset+0);

	if (tree) {
		proto_item *stat_item;
		proto_tree_add_uint(tree, hf_nfs3_status, tvb, offset+0, 4, nfsstat3);
		stat_item = proto_tree_add_uint(tree, hf_nfs_status, tvb, offset+0, 4, nfsstat3);
		PROTO_ITEM_SET_HIDDEN(stat_item);
	}

	offset += 4;
	*status = nfsstat3;
	return offset;
}


static const value_string names_nfs_ftype3[] =
{
	{	NF3REG,	 "Regular File" },
	{	NF3DIR,	 "Directory" },
	{	NF3BLK,	 "Block Special Device" },
	{	NF3CHR,	 "Character Special Device" },
	{	NF3LNK,	 "Symbolic Link" },
	{	NF3SOCK, "Socket" },
	{	NF3FIFO, "Named Pipe" },
	{	0,	NULL }
};
static value_string_ext names_nfs_ftype3_ext = VALUE_STRING_EXT_INIT(names_nfs_ftype3);

/* NFSv3 RFC 1813, Page 20 */
static int
dissect_ftype3(tvbuff_t *tvb, int offset, proto_tree *tree, int hf,
	       guint32* ftype3)
{
	guint32 type;

	type = tvb_get_ntohl(tvb, offset+0);

	if (tree) {
		proto_tree_add_uint(tree, hf, tvb, offset, 4, type);
	}

	offset += 4;
	*ftype3 = type;
	return offset;
}


/* NFSv3 RFC 1813, Page 20 */
static int
dissect_nfs3_specdata(tvbuff_t *tvb, int offset, proto_tree *tree, const char *name)
{
	guint32	    specdata1;
	guint32	    specdata2;

	specdata1 = tvb_get_ntohl(tvb, offset+0);
	specdata2 = tvb_get_ntohl(tvb, offset+4);

	if (tree) {
		proto_item *specdata3_item;
		proto_tree *specdata3_tree;

		specdata3_item = proto_tree_add_text(tree, tvb, offset, 8,
			"%s: %u,%u", name, specdata1, specdata2);

		specdata3_tree = proto_item_add_subtree(specdata3_item,
					ett_nfs3_specdata);

		proto_tree_add_text(specdata3_tree, tvb, offset+0, 4,
				    "specdata1: %u", specdata1);
		proto_tree_add_text(specdata3_tree, tvb, offset+4, 4,
				    "specdata2: %u", specdata2);
	}

	offset += 8;
	return offset;
}


/* NFSv3 RFC 1813, Page 21 */
int
dissect_nfs3_fh(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree,
		const char *name, guint32 *hash, rpc_call_info_value *civ)
{
	guint	    fh3_len;
	guint	    fh3_len_full;
	/*guint       fh3_fill;*/
	proto_item *fitem = NULL;
	proto_tree *ftree = NULL;
	int	    fh_offset, fh_length;

	fh3_len = tvb_get_ntohl(tvb, offset+0);
	fh3_len_full = rpc_roundup(fh3_len);
	/*fh3_fill = fh3_len_full - fh3_len;*/

	if (tree) {
		fitem = proto_tree_add_text(tree, tvb, offset, 4+fh3_len_full,
			"%s", name);

		ftree = proto_item_add_subtree(fitem, ett_nfs3_fh);
	}

	/* are we snooping fh to filenames ?*/
	if ((!pinfo->fd->flags.visited) && nfs_file_name_snooping) {
		/* NFS v3 LOOKUP, CREATE, MKDIR, READDIRPLUS
			calls might give us a mapping*/
		if ( ((civ->prog == 100003)
		  &&((civ->vers == 3)
		  &&(!civ->request)
		  &&((civ->proc == 3)||(civ->proc == 8)||(civ->proc == 9)||(civ->proc == 17))))
		|| civ->vers == 4
		) {
			fh_length = tvb_get_ntohl(tvb, offset);
			fh_offset = offset+4;
			nfs_name_snoop_add_fh(civ->xid, tvb, fh_offset,
					      fh_length);
		}

		/* MOUNT v3 MNT replies might give us a filehandle */
		if ( (civ->prog == 100005)
		  &&(civ->vers == 3)
		  &&(!civ->request)
		  &&(civ->proc == 1)
		) {
			fh_length = tvb_get_ntohl(tvb, offset);
			fh_offset = offset+4;
			nfs_name_snoop_add_fh(civ->xid, tvb, fh_offset,
					      fh_length);
		}
	}

	proto_tree_add_uint(ftree, hf_nfs_fh_length, tvb, offset+0, 4,
			fh3_len);

	/* Handle WebNFS requests where filehandle may be 0 length */
	if (fh3_len > 0)
	{
		dissect_fhandle_data(tvb, offset+4, pinfo, ftree, fh3_len, FALSE, hash);

		offset += fh3_len_full;
	}
	else if (hash) {
		/* Make sure hash is set regardless, as our caller expects it
		 * to be initialized */
		*hash = 0;
	}

	offset += 4;

	return offset;
}


/* NFSv3 RFC 1813, Page 21 */
static int
dissect_nfstime3(tvbuff_t *tvb, int offset, proto_tree *tree, int hf_time,
		 int hf_time_sec, int hf_time_nsec)
{
	guint32	 seconds;
	guint32	 nseconds;
	nstime_t ts;

	seconds = tvb_get_ntohl(tvb, offset+0);
	nseconds = tvb_get_ntohl(tvb, offset+4);
	ts.secs = seconds;
	ts.nsecs = nseconds;

	if (tree) {
		proto_item *time_item;
		proto_tree *time_tree;

		time_item = proto_tree_add_time(tree, hf_time, tvb, offset, 8,
				&ts);

		time_tree = proto_item_add_subtree(time_item, ett_nfs3_nfstime);

		proto_tree_add_uint(time_tree, hf_time_sec, tvb, offset, 4,
					seconds);
		proto_tree_add_uint(time_tree, hf_time_nsec, tvb, offset+4, 4,
					nseconds);
	}
	offset += 8;
	return offset;
}


/* NFSv3 RFC 1813, Page 22
 * The levels parameter tells this helper how many levels up in the tree it
 * should display useful info such as type,mode,uid,gid
 * If level has the COL_INFO_LEVEL flag set it will also display
 * this info in the info column.
 */
static int
dissect_nfs_fattr3(packet_info *pinfo, tvbuff_t *tvb, int offset,
		   proto_tree *tree, const char *name, guint32 levels)
{
	proto_item *fattr3_item = NULL;
	proto_tree *fattr3_tree = NULL;
	int	    old_offset	= offset;
	guint32	    type, mode, uid, gid;

	if (tree) {
		fattr3_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s", name);
		fattr3_tree = proto_item_add_subtree(fattr3_item, ett_nfs3_fattr);
	}

	/* ftype */
	offset = dissect_ftype3(tvb, offset, fattr3_tree, hf_nfs3_fattr_type, &type);

	/* mode */
	offset = dissect_nfs3_mode(tvb, offset, fattr3_tree, &mode);

	/* nlink */
	offset = dissect_rpc_uint32(tvb, fattr3_tree, hf_nfs3_fattr_nlink,
		offset);

	/* uid */
	uid = tvb_get_ntohl(tvb, offset);
	offset = dissect_rpc_uint32(tvb, fattr3_tree, hf_nfs3_fattr_uid,
		offset);

	/* gid */
	gid = tvb_get_ntohl(tvb, offset);
	offset = dissect_rpc_uint32(tvb, fattr3_tree, hf_nfs3_fattr_gid,
		offset);

	/* size*/
	offset = dissect_rpc_uint64(tvb, fattr3_tree, hf_nfs3_fattr_size,
		offset);

	/* used */
	offset = dissect_rpc_uint64(tvb, fattr3_tree, hf_nfs3_fattr_used,
		offset);

	/* rdev */
	offset = dissect_nfs3_specdata(tvb, offset, fattr3_tree, "rdev");

	/* fsid */
	offset = dissect_rpc_uint64(tvb, fattr3_tree, hf_nfs3_fattr_fsid,
		offset);

	/* fileid */
	offset = dissect_rpc_uint64(tvb, fattr3_tree, hf_nfs3_fattr_fileid,
		offset);

	/* atime */
	offset = dissect_nfstime3 (tvb, offset, fattr3_tree, hf_nfs_atime, hf_nfs_atime_sec, hf_nfs_atime_nsec);

	/* mtime */
	offset = dissect_nfstime3 (tvb, offset, fattr3_tree, hf_nfs_mtime, hf_nfs_mtime_sec, hf_nfs_mtime_nsec);

	/* ctime */
	offset = dissect_nfstime3 (tvb, offset, fattr3_tree, hf_nfs_ctime, hf_nfs_ctime_sec, hf_nfs_ctime_nsec);

	/* now we know, that fattr3 is shorter */
	if (fattr3_item) {
		proto_item_set_len(fattr3_item, offset - old_offset);
	}


	/* put some nice info in COL_INFO for GETATTR replies */
	if (levels & COL_INFO_LEVEL) {
		levels &= (~COL_INFO_LEVEL);
		col_append_fstr(pinfo->cinfo, COL_INFO,
				"  %s mode: %04o uid: %d gid: %d",
				val_to_str_ext(type, &names_nfs_ftype3_ext, "Unknown Type: 0x%x"),
				mode&0x0fff, uid, gid);
	}
	/* populate the expansion lines with some nice useable info */
	while ( fattr3_tree && levels-- ) {
		proto_item_append_text(fattr3_tree, "  %s mode: %04o uid: %d gid: %d",
				val_to_str_ext(type, &names_nfs_ftype3_ext, "Unknown Type: 0x%x"),
				mode&0x0fff, uid, gid);
		fattr3_tree = fattr3_tree->parent;
	}

	return offset;
}


static const value_string value_follows[] =
{
	{ 0, "no value" },
	{ 1, "value follows" },
	{ 0, NULL }
};


/* NFSv3 RFC 1813, Page 23 */
int
dissect_nfs3_post_op_attr(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree,
			 const char *name)
{
	proto_item *post_op_attr_item = NULL;
	proto_tree *post_op_attr_tree = NULL;
	int	    old_offset	      = offset;
	guint32	    attributes_follow = 0;

	attributes_follow = tvb_get_ntohl(tvb, offset+0);

	if (tree) {
		post_op_attr_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s", name);
		post_op_attr_tree = proto_item_add_subtree(post_op_attr_item,
			ett_nfs3_post_op_attr);

		proto_tree_add_text(post_op_attr_tree, tvb, offset, 4,
			"attributes_follow: %s (%u)",
		val_to_str_const(attributes_follow, value_follows, "Unknown"), attributes_follow);
	}
	offset += 4;
	switch (attributes_follow) {
		case TRUE:
			offset = dissect_nfs_fattr3(pinfo, tvb, offset,
						    post_op_attr_tree,
						    "attributes", 2);
		break;
		case FALSE:
			/* void */
		break;
	}

	/* now we know, that post_op_attr_tree is shorter */
	if (tree && post_op_attr_item) {
		proto_item_set_len(post_op_attr_item, offset - old_offset);
	}

	return offset;
}


/* NFSv3 RFC 1813, Page 24 */
static int
dissect_wcc_attr(tvbuff_t *tvb, int offset, proto_tree *tree, const char *name)
{
	proto_item *wcc_attr_item = NULL;
	proto_tree *wcc_attr_tree = NULL;
	int	    old_offset	  = offset;

	if (tree) {
		wcc_attr_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s", name);
		wcc_attr_tree = proto_item_add_subtree(wcc_attr_item,
			ett_nfs3_wcc_attr);
	}

	offset = dissect_rpc_uint64(tvb, wcc_attr_tree, hf_nfs3_wcc_attr_size,
		offset);
	offset = dissect_nfstime3(tvb, offset, wcc_attr_tree, hf_nfs_mtime,
		hf_nfs_mtime_sec, hf_nfs_mtime_nsec);
	offset = dissect_nfstime3(tvb, offset, wcc_attr_tree, hf_nfs_ctime,
		hf_nfs_ctime_sec, hf_nfs_ctime_nsec);
	/* now we know, that wcc_attr_tree is shorter */
	if (wcc_attr_item) {
		proto_item_set_len(wcc_attr_item, offset - old_offset);
	}

	return offset;
}


/* NFSv3 RFC 1813, Page 24 */
static int
dissect_pre_op_attr(tvbuff_t *tvb, int offset, proto_tree *tree, const char *name)
{
	proto_item *pre_op_attr_item = NULL;
	proto_tree *pre_op_attr_tree = NULL;
	int	    old_offset	     = offset;
	guint32	    attributes_follow;

	if (tree) {
		pre_op_attr_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s", name);
		pre_op_attr_tree = proto_item_add_subtree(pre_op_attr_item,
			ett_nfs3_pre_op_attr);
	}

	attributes_follow = tvb_get_ntohl(tvb, offset+0);
	proto_tree_add_text(pre_op_attr_tree, tvb, offset, 4,
		"attributes_follow: %s (%u)",
		val_to_str_const(attributes_follow, value_follows, "Unknown"), attributes_follow);
	offset += 4;
	switch (attributes_follow) {
		case TRUE:
			offset = dissect_wcc_attr(tvb, offset, pre_op_attr_tree,
					"attributes");
		break;
		case FALSE:
			/* void */
		break;
	}

	/* now we know, that pre_op_attr_tree is shorter */
	if (pre_op_attr_item) {
		proto_item_set_len(pre_op_attr_item, offset - old_offset);
	}

	return offset;
}


/* NFSv3 RFC 1813, Page 24 */
static int
dissect_wcc_data(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, const char *name)
{
	proto_item *wcc_data_item = NULL;
	proto_tree *wcc_data_tree = NULL;
	int	    old_offset	  = offset;

	if (tree) {
		wcc_data_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s", name);
		wcc_data_tree = proto_item_add_subtree(wcc_data_item,
			ett_nfs3_wcc_data);
	}

	offset = dissect_pre_op_attr (tvb, offset, wcc_data_tree, "before");
	offset = dissect_nfs3_post_op_attr(tvb, offset, pinfo, wcc_data_tree, "after" );

	/* now we know, that wcc_data is shorter */
	if (wcc_data_item) {
		proto_item_set_len(wcc_data_item, offset - old_offset);
	}

	return offset;
}


/* NFSv3 RFC 1813, Page 25 */
static int
dissect_nfs3_post_op_fh(tvbuff_t *tvb, int offset, packet_info *pinfo,
		    proto_tree *tree, const char *name, rpc_call_info_value *civ)
{
	proto_item *post_op_fh3_item = NULL;
	proto_tree *post_op_fh3_tree = NULL;
	int	    old_offset	     = offset;
	guint32	    handle_follows;

	if (tree) {
		post_op_fh3_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s", name);
		post_op_fh3_tree = proto_item_add_subtree(post_op_fh3_item,
			ett_nfs3_post_op_fh);
	}

	handle_follows = tvb_get_ntohl(tvb, offset+0);
	proto_tree_add_text(post_op_fh3_tree, tvb, offset, 4,
		"handle_follows: %s (%u)",
		val_to_str_const(handle_follows, value_follows, "Unknown"), handle_follows);
	offset += 4;
	switch (handle_follows) {
		case TRUE:
			offset = dissect_nfs3_fh(tvb, offset, pinfo, post_op_fh3_tree,
					"handle", NULL, civ);
		break;
		case FALSE:
			/* void */
		break;
	}

	/* now we know, that post_op_fh3_tree is shorter */
	if (post_op_fh3_item) {
		proto_item_set_len(post_op_fh3_item, offset - old_offset);
	}

	return offset;
}


/* NFSv3 RFC 1813, Page 25 */
static int
dissect_set_mode3(tvbuff_t *tvb, int offset, proto_tree *tree, const char *name)
{
	proto_item *set_mode3_item = NULL;
	proto_tree *set_mode3_tree = NULL;
	int	    old_offset	   = offset;
	guint32	    set_it;
	const char *set_it_name;

	set_it = tvb_get_ntohl(tvb, offset+0);

	if (tree) {
		set_it_name = val_to_str_const(set_it, value_follows, "Unknown");

		set_mode3_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s: %s", name, set_it_name);
		set_mode3_tree = proto_item_add_subtree(set_mode3_item,
			ett_nfs3_set_mode);

		proto_tree_add_text(set_mode3_tree, tvb, offset, 4,
			"set_it: %s (%u)", set_it_name, set_it);
	}

	offset += 4;

	switch (set_it) {
		case 1:
			offset = dissect_nfs3_mode(tvb, offset, set_mode3_tree, NULL);
		break;
		default:
			/* void */
		break;
	}

	/* now we know, that set_mode3 is shorter */
	if (set_mode3_item) {
		proto_item_set_len(set_mode3_item, offset - old_offset);
	}

	return offset;
}


/* NFSv3 RFC 1813, Page 26 */
static int
dissect_set_uid3(tvbuff_t *tvb, int offset, proto_tree *tree, const char *name)
{
	proto_item *set_uid3_item = NULL;
	proto_tree *set_uid3_tree = NULL;
	int	    old_offset	  = offset;
	guint32	    set_it;
	const char *set_it_name;

	set_it = tvb_get_ntohl(tvb, offset+0);

	if (tree) {
		set_it_name = val_to_str_const(set_it, value_follows, "Unknown");

		set_uid3_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s: %s", name, set_it_name);
		set_uid3_tree = proto_item_add_subtree(set_uid3_item,
			ett_nfs3_set_uid);

		proto_tree_add_text(set_uid3_tree, tvb, offset, 4,
			"set_it: %s (%u)", set_it_name, set_it);
	}
	offset += 4;

	switch (set_it) {
		case 1:
			offset = dissect_rpc_uint32(tvb, set_uid3_tree,
						    hf_nfs3_uid, offset);
		break;
		default:
			/* void */
		break;
	}

	/* now we know, that set_uid3 is shorter */
	if (set_uid3_item) {
		proto_item_set_len(set_uid3_item, offset - old_offset);
	}

	return offset;
}


/* NFSv3 RFC 1813, Page 26 */
static int
dissect_set_gid3(tvbuff_t *tvb, int offset, proto_tree *tree, const char *name)
{
	proto_item *set_gid3_item = NULL;
	proto_tree *set_gid3_tree = NULL;
	int	    old_offset	  = offset;
	guint32	    set_it;
	const char *set_it_name;

	set_it = tvb_get_ntohl(tvb, offset+0);

	if (tree) {
		set_it_name = val_to_str_const(set_it, value_follows, "Unknown");
		set_gid3_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s: %s", name, set_it_name);
		set_gid3_tree = proto_item_add_subtree(set_gid3_item,
			ett_nfs3_set_gid);
		proto_tree_add_text(set_gid3_tree, tvb, offset, 4,
			"set_it: %s (%u)", set_it_name, set_it);
	}

	offset += 4;

	switch (set_it) {
		case 1:
			offset = dissect_rpc_uint32(tvb, set_gid3_tree,
				hf_nfs3_gid, offset);
		break;
		default:
			/* void */
		break;
	}

	/* now we know, that set_gid3 is shorter */
	if (set_gid3_item) {
		proto_item_set_len(set_gid3_item, offset - old_offset);
	}

	return offset;
}


/* NFSv3 RFC 1813, Page 26 */
static int
dissect_set_size3(tvbuff_t *tvb, int offset, proto_tree *tree, const char *name)
{
	proto_item *set_size3_item = NULL;
	proto_tree *set_size3_tree = NULL;
	int	    old_offset	   = offset;
	guint32	    set_it;
	const char *set_it_name;

	set_it = tvb_get_ntohl(tvb, offset+0);

	if (tree) {
		set_it_name = val_to_str_const(set_it, value_follows, "Unknown");

		set_size3_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s: %s", name, set_it_name);
		set_size3_tree = proto_item_add_subtree(set_size3_item,
			ett_nfs3_set_size);
		proto_tree_add_text(set_size3_tree, tvb, offset, 4,
			"set_it: %s (%u)", set_it_name, set_it);
	}

	offset += 4;

	switch (set_it) {
		case 1:
			offset = dissect_rpc_uint64(tvb, set_size3_tree,
				hf_nfs3_set_size, offset);
		break;
		default:
			/* void */
		break;
	}

	/* now we know, that set_size3 is shorter */
	if (set_size3_item) {
		proto_item_set_len(set_size3_item, offset - old_offset);
	}

	return offset;
}


/* NFSv3 RFC 1813, Page 25 */
#define DONT_CHANGE 0
#define SET_TO_SERVER_TIME 1
#define SET_TO_CLIENT_TIME 2

static const value_string time_how[] =
{
	{ DONT_CHANGE,		"don't change" },
	{ SET_TO_SERVER_TIME,	"set to server time" },
	{ SET_TO_CLIENT_TIME,	"set to client time" },
	{ 0, NULL }
};


/* NFSv3 RFC 1813, Page 26 */
static int
dissect_set_atime(tvbuff_t *tvb, int offset, proto_tree *tree, const char *name)
{
	proto_item *set_atime_item = NULL;
	proto_tree *set_atime_tree = NULL;
	int	    old_offset	   = offset;
	guint32	    set_it;
	const char *set_it_name;

	set_it = tvb_get_ntohl(tvb, offset+0);

	if (tree) {
		set_it_name = val_to_str_const(set_it, time_how, "Unknown");

		set_atime_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s: %s", name, set_it_name);
		set_atime_tree = proto_item_add_subtree(set_atime_item,
			ett_nfs3_set_atime);

		proto_tree_add_text(set_atime_tree, tvb, offset, 4,
			"set_it: %s (%u)", set_it_name, set_it);
	}
	offset += 4;

	switch (set_it) {
		case SET_TO_CLIENT_TIME:
			if (set_atime_item) {
				offset = dissect_nfstime3(tvb, offset, set_atime_tree,
					hf_nfs_atime, hf_nfs_atime_sec, hf_nfs_atime_nsec);
			}
		break;
		default:
			/* void */
		break;
	}

	/* now we know, that set_atime is shorter */
	if (set_atime_item) {
		proto_item_set_len(set_atime_item, offset - old_offset);
	}

	return offset;
}


/* NFSv3 RFC 1813, Page 26 */
static int
dissect_set_mtime(tvbuff_t *tvb, int offset, proto_tree *tree, const char *name)
{
	proto_item *set_mtime_item = NULL;
	proto_tree *set_mtime_tree = NULL;
	int	    old_offset	   = offset;
	guint32	    set_it;
	const char *set_it_name;

	set_it = tvb_get_ntohl(tvb, offset+0);

	if (tree) {
		set_it_name = val_to_str_const(set_it, time_how, "Unknown");

		set_mtime_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s: %s", name, set_it_name);
		set_mtime_tree = proto_item_add_subtree(set_mtime_item,
			ett_nfs3_set_mtime);
		proto_tree_add_text(set_mtime_tree, tvb, offset, 4,
				"set_it: %s (%u)", set_it_name, set_it);
	}

	offset += 4;

	switch (set_it) {
		case SET_TO_CLIENT_TIME:
			if (set_mtime_item) {
				offset = dissect_nfstime3(tvb, offset, set_mtime_tree,
					hf_nfs_atime, hf_nfs_atime_sec, hf_nfs_atime_nsec);
			}
		break;
		default:
			/* void */
		break;
	}

	/* now we know, that set_mtime is shorter */
	if (set_mtime_item) {
		proto_item_set_len(set_mtime_item, offset - old_offset);
	}

	return offset;
}


/* NFSv3 RFC 1813, Page 25..27 */
static int
dissect_nfs3_sattr(tvbuff_t *tvb, int offset, proto_tree *tree, const char *name)
{
	proto_item *sattr3_item = NULL;
	proto_tree *sattr3_tree = NULL;
	int	    old_offset	= offset;

	if (tree) {
		sattr3_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s", name);
		sattr3_tree = proto_item_add_subtree(sattr3_item, ett_nfs3_sattr);
	}

	offset = dissect_set_mode3(tvb, offset, sattr3_tree, "mode");
	offset = dissect_set_uid3 (tvb, offset, sattr3_tree, "uid");
	offset = dissect_set_gid3 (tvb, offset, sattr3_tree, "gid");
	offset = dissect_set_size3(tvb, offset, sattr3_tree, "size");
	offset = dissect_set_atime(tvb, offset, sattr3_tree, "atime");
	offset = dissect_set_mtime(tvb, offset, sattr3_tree, "mtime");

	/* now we know, that sattr3 is shorter */
	if (sattr3_item) {
		proto_item_set_len(sattr3_item, offset - old_offset);
	}

	return offset;
}


/* NFSv3 RFC 1813, Page 27 */
static int
dissect_diropargs3(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree,
				   const char *label, guint32 *hash, const char **name, rpc_call_info_value *civ)
{
	proto_item *diropargs3_item = NULL;
	proto_tree *diropargs3_tree = NULL;
	int	    old_offset	    = offset;
	int	    parent_offset, parent_len;
	int	    name_offset, name_len;

	if (tree) {
		diropargs3_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s", label);
		diropargs3_tree = proto_item_add_subtree(diropargs3_item,
			ett_nfs3_diropargs);
	}

	parent_offset = offset+4;
	parent_len = tvb_get_ntohl(tvb, offset);
	offset = dissect_nfs3_fh(tvb, offset, pinfo, diropargs3_tree, "dir", hash, civ);
	name_offset = offset+4;
	name_len = tvb_get_ntohl(tvb, offset);
	offset = dissect_nfs3_filename(tvb, offset, diropargs3_tree,
		hf_nfs_name, name);

	/* are we snooping fh to filenames ?*/
	if ((!pinfo->fd->flags.visited) && nfs_file_name_snooping) {
		/* v3 LOOKUP, CREATE, MKDIR calls might give us a mapping*/
		if ( (civ->prog == 100003)
		  &&(civ->vers == 3)
		  &&(civ->request)
		  &&((civ->proc == 3)||(civ->proc == 8)||(civ->proc == 9))
		) {
			nfs_name_snoop_add_name(civ->xid, tvb,
				name_offset, name_len,
				parent_offset, parent_len, NULL);
		}
	}


	/* now we know, that diropargs3 is shorter */
	if (diropargs3_item) {
		proto_item_set_len(diropargs3_item, offset - old_offset);
	}

	return offset;
}


static int
dissect_nfs3_remove_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
			 proto_tree *tree, void *data)
{
	guint32	    hash = 0;
	const char *name = NULL;

	offset = dissect_diropargs3(tvb, offset, pinfo, tree, "object", &hash, &name, (rpc_call_info_value*)data);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", DH: 0x%08x/%s", hash, name);
	proto_item_append_text(tree, ", REMOVE Call DH: 0x%08x/%s", hash, name);

	return offset;
}


static int
dissect_nfs3_null_call(tvbuff_t *tvb _U_, int offset, packet_info *pinfo _U_,
		       proto_tree *tree, void *data _U_)
{
	proto_item_append_text(tree, ", NULL Call");

	return offset;
}


static int
dissect_nfs3_null_reply(tvbuff_t *tvb _U_, int offset, packet_info *pinfo _U_,
			proto_tree *tree, void *data _U_)
{
	proto_item_append_text(tree, ", NULL Reply");

	return offset;
}


static int
dissect_nfs3_rmdir_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree, void *data)
{
	guint32	    hash = 0;
	const char *name = NULL;

	offset = dissect_diropargs3(tvb, offset, pinfo, tree, "object", &hash, &name, (rpc_call_info_value*)data);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", DH: 0x%08x/%s", hash, name);
	proto_item_append_text(tree, ", RMDIR Call DH: 0x%08x/%s", hash, name);

	return offset;
}


/* NFSv3 RFC 1813, Page 32,33 */
static int
dissect_nfs3_getattr_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
			  proto_tree *tree, void *data)
{
	guint32 hash = 0;

	offset = dissect_nfs3_fh(tvb, offset, pinfo, tree, "object", &hash, (rpc_call_info_value*)data);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", FH: 0x%08x", hash);
	proto_item_append_text(tree, ", GETATTR Call FH: 0x%08x", hash);

	return offset;
}


/* NFSv3 RFC 1813, Page 32,33 */
static int
dissect_nfs3_getattr_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			   proto_tree *tree, void *data _U_)
{
	guint32	    status;
	const char *err;

	proto_item_append_text(tree, ", GETATTR Reply");

	offset = dissect_nfs3_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_nfs_fattr3(pinfo, tvb, offset, tree, "obj_attributes", 2|COL_INFO_LEVEL);
		break;
		default:
			err = val_to_str_ext(status, &names_nfs3_status_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, "  Error: %s", err);
		break;
	}

	return offset;
}


/* NFSv3 RFC 1813, Page 33 */
static int
dissect_sattrguard3(tvbuff_t *tvb, int offset, proto_tree *tree, const char *name)
{
	proto_item *sattrguard3_item = NULL;
	proto_tree *sattrguard3_tree = NULL;
	int	    old_offset	     = offset;
	guint32	    check;
	const char *check_name;

	check = tvb_get_ntohl(tvb, offset+0);

	if (tree) {
		check_name = val_to_str_const(check, value_follows, "Unknown");

		sattrguard3_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s: %s", name, check_name);
		sattrguard3_tree = proto_item_add_subtree(sattrguard3_item,
			ett_nfs3_sattrguard);

		proto_tree_add_text(sattrguard3_tree, tvb, offset, 4,
			"check: %s (%u)", check_name, check);
	}


	offset += 4;

	switch (check) {
		case TRUE:
			offset = dissect_nfstime3(tvb, offset, sattrguard3_tree,
					hf_nfs_ctime, hf_nfs_ctime_sec, hf_nfs_ctime_nsec);
		break;
		case FALSE:
			/* void */
		break;
	}

	/* now we know, that sattrguard3 is shorter */
	if (sattrguard3_item) {
		proto_item_set_len(sattrguard3_item, offset - old_offset);
	}

	return offset;
}


/* NFSv3 RFC 1813, Page 33..36 */
static int
dissect_nfs3_setattr_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
			  proto_tree *tree, void *data)
{
	guint32 hash = 0;

	offset = dissect_nfs3_fh    (tvb, offset, pinfo, tree, "object", &hash, (rpc_call_info_value*)data);
	offset = dissect_nfs3_sattr     (tvb, offset,        tree, "new_attributes");
	offset = dissect_sattrguard3(tvb, offset,        tree, "guard");

	col_append_fstr(pinfo->cinfo, COL_INFO, ", FH: 0x%08x", hash);
	proto_item_append_text(tree, ", SETATTR Call FH: 0x%08x", hash);

	return offset;
}


/* NFSv3 RFC 1813, Page 33..36 */
static int
dissect_nfs3_setattr_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			   proto_tree *tree, void *data _U_)
{
	guint32	    status;
	const char *err;

	offset = dissect_nfs3_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "obj_wcc");
			proto_item_append_text(tree, ", SETATTR Reply");
		break;
		default:
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "obj_wcc");

			err = val_to_str_ext(status, &names_nfs3_status_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, ", SETATTR Reply  Error: %s", err);
		break;
	}

	return offset;
}


/* NFSv3 RFC 1813, Page 37..39 */
static int
dissect_nfs3_lookup_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
			 proto_tree *tree, void *data)
{
	guint32	    hash = 0;
	const char *name = NULL;

	offset = dissect_diropargs3 (tvb, offset, pinfo, tree, "what", &hash, &name, (rpc_call_info_value*)data);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", DH: 0x%08x/%s", hash, name);
	proto_item_append_text(tree, ", LOOKUP Call DH: 0x%08x/%s", hash, name);

	return offset;
}


/* NFSv3 RFC 1813, Page 37..39 */
static int
dissect_nfs3_lookup_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
			  proto_tree *tree, void *data)
{
	guint32	    status;
	const char *err;
	guint32	    hash = 0;

	offset = dissect_nfs3_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_nfs3_fh(tvb, offset, pinfo, tree, "object", &hash, (rpc_call_info_value*)data);
			offset = dissect_nfs3_post_op_attr(tvb, offset, pinfo, tree,
				"obj_attributes");
			offset = dissect_nfs3_post_op_attr(tvb, offset, pinfo, tree,
				"dir_attributes");

			col_append_fstr(pinfo->cinfo, COL_INFO, ", FH: 0x%08x", hash);
			proto_item_append_text(tree, ", LOOKUP Reply FH: 0x%08x", hash);
		break;
		default:
			offset = dissect_nfs3_post_op_attr(tvb, offset, pinfo, tree,
				"dir_attributes");

			err = val_to_str_ext(status, &names_nfs3_status_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, ", LOOKUP Reply  Error: %s", err);
		break;
	}

	return offset;
}


static const value_string accvs[] = {
	{ 0x01,	"RD" },
	{ 0x02,	"LU" },
	{ 0x04,	"MD" },
	{ 0x08,	"XT" },
	{ 0x10,	"DL" },
	{ 0x20,	"XE" },
	{ 0,	NULL }
};

static const true_false_string tfs_access_supp	 = { "supported",	"!NOT Supported!"};
static const true_false_string tfs_access_rights = {"allowed", "*Access Denied*"};

proto_tree*
display_access_items(tvbuff_t* tvb, int offset, packet_info* pinfo, proto_tree *tree,
		     guint32 amask, char mtype, int version, GString* optext, const char *label)
{
	gboolean    nfsv3	   = ((version == 3) ? TRUE : FALSE);
	proto_item *access_item	   = NULL;
	proto_tree *access_subtree = NULL;
	proto_item *access_subitem = NULL;
	guint32	    itype;

	/* XXX Legend (delete if desired)

	   'C' CHECK access:      append label to both headers and create subtree and list
	   'N' NOT SUPPORTED:     append label to both headers
	   'S' SUPPORTED or not:  create subtree and list
	   'D' DENIED:            append label to both headers
	   'A' ALLOWED:           append label to both headers
	   'R' RIGHTS:            create subtree and list */

	switch (mtype) {
		case 'C':
			access_item = proto_tree_add_item(tree, hf_nfs_access_check, tvb,
				offset, 4, ENC_BIG_ENDIAN);
			access_subtree = proto_item_add_subtree(access_item,
				(nfsv3 ? ett_nfs3_access : ett_nfs4_access));
			break;
		case 'S':
			access_item = proto_tree_add_item(tree, hf_nfs_access_supported, tvb,
				offset, 4, ENC_BIG_ENDIAN);
			access_subtree = proto_item_add_subtree(access_item, ett_nfs4_access_supp);
			break;
		case 'R':
			access_item = proto_tree_add_item(tree, hf_nfs_access_rights, tvb,
				offset, 4, ENC_BIG_ENDIAN);
			access_subtree = proto_item_add_subtree(access_item,
				(nfsv3 ? ett_nfs3_access : ett_nfs4_access));
			break;
	}
	/* Append label to the Info column and tree */
	if (mtype != 'S' && mtype != 'R') {
		if (nfsv3) {
			col_append_fstr(pinfo->cinfo, COL_INFO, ", [%s:", label);
		} else {
			g_string_append_printf (optext, ", [%s:", label);
		}
		proto_item_append_text(tree, ", [%s:", label);
	}

	for (itype=0; itype < 6; itype++) {
		if (amask & accvs[itype].value) {
			if (mtype != 'S' && mtype != 'R')	{
				/* List access type in Info column and tree */
				if (nfsv3) {
					col_append_fstr(pinfo->cinfo, COL_INFO, " %s", accvs[itype].strptr);
				} else {
					g_string_append_printf (optext, " %s", accvs[itype].strptr);
				}
				proto_item_append_text(tree, " %s", accvs[itype].strptr);
			}
			if (mtype == 'C' || mtype == 'S' || mtype == 'R') {

				switch (itype) {
					case 0:
						access_subitem = proto_tree_add_item (access_subtree,
							(mtype == 'S' ? hf_nfs_access_supp_read : hf_nfs_access_read),
							tvb, offset, 4, ENC_BIG_ENDIAN);
						break;
					case 1:
						access_subitem = proto_tree_add_item (access_subtree,
							(mtype == 'S' ? hf_nfs_access_supp_lookup : hf_nfs_access_lookup),
							tvb, offset, 4, ENC_BIG_ENDIAN);
						break;
					case 2:
						access_subitem = proto_tree_add_item (access_subtree,
							(mtype == 'S' ? hf_nfs_access_supp_modify : hf_nfs_access_modify),
							tvb, offset, 4, ENC_BIG_ENDIAN);
						break;
					case 3:
						access_subitem = proto_tree_add_item (access_subtree,
							(mtype == 'S' ? hf_nfs_access_supp_extend : hf_nfs_access_extend),
							tvb, offset, 4, ENC_BIG_ENDIAN);
						break;
					case 4:
						access_subitem = proto_tree_add_item (access_subtree,
							(mtype == 'S' ? hf_nfs_access_supp_delete : hf_nfs_access_delete),
							tvb, offset, 4, ENC_BIG_ENDIAN);
						break;
					case 5:
						access_subitem = proto_tree_add_item (access_subtree,
							(mtype == 'S' ? hf_nfs_access_supp_execute : hf_nfs_access_execute),
							tvb, offset, 4, ENC_BIG_ENDIAN);
						break;
				}
				if (mtype == 'C') proto_item_append_text(access_subitem, "?" );
			}
		}
	}
	if (mtype != 'S' && mtype != 'R') {
		if (nfsv3) {
			col_append_str(pinfo->cinfo, COL_INFO, "]");
		} else {
			g_string_append_printf (optext, "]");
		}
		proto_item_append_text(tree, "]");
	}
	return access_subtree = NULL;
}

/* NFSv3 RFC 1813, Page 40..43 */
/* NFSv4 RFC 3530, Page 140..142 */
int
dissect_access_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree,
		     int version, GString *optext, rpc_call_info_value *civ)
{
	guint32	   *acc_req;
	guint32	    acc_supp;
	guint32	    acc_rights;
	guint32	    mask_not_supp;
	guint32	    mask_denied;
	guint32	    mask_allowed;
	guint32	    e_check, e_rights;
	gboolean    nfsv3	  = ((version == 3) ? TRUE : FALSE);
	gboolean    nfsv4	  = ((version == 4) ? TRUE : FALSE);
	proto_tree *access_tree;
	proto_item *ditem;

	/* Retrieve the access mask from the call */
	acc_req = (guint32 *)civ->private_data;
	/* Should never happen because ONC-RPC requires the call in order to dissect the reply. */
	if (acc_req == NULL) {
		/* XXX, when nfsv4 return offset+8? */
		return offset+4;
	}
	if (nfsv4) {
		acc_supp = tvb_get_ntohl(tvb, offset+0);
	} else {
		acc_supp = *acc_req;
	}
	/*  V3/V4 - Get access rights mask and create a subtree for it */
	acc_rights = tvb_get_ntohl(tvb, (nfsv3 ? offset+0: offset+4));

	/* Create access masks: not_supported, denied, and allowed */
	mask_not_supp = *acc_req ^ acc_supp;
	e_check = acc_supp;
	e_rights = acc_supp & acc_rights;  /* guard against broken implementations */
	mask_denied =  e_check ^ e_rights;
	mask_allowed = e_check & e_rights;

	if (nfsv4) {
		if (mask_not_supp > 0) {
			display_access_items(tvb, offset, pinfo, tree, mask_not_supp, 'N', 4,
				optext, "NOT Supported") ;
		}
		display_access_items(tvb, offset, pinfo, tree, acc_supp, 'S', 4,
			optext, "Supported");
		offset+=4;
	}
	if (mask_denied > 0) {
		display_access_items(tvb, offset, pinfo, tree, mask_denied, 'D', version,
			optext, "Access Denied") ;
	}
	if (mask_allowed > 0) {
		display_access_items(tvb, offset, pinfo, tree, mask_allowed, 'A', version,
			optext, "Allowed") ;
	}
	/* Pass the OR'd masks rather than acc_rights so that display_access_items will
	   process types that have been denied access. Since proto_tree_add_item uses the
	   mask in the tvb (not the passed mask), the correct (denied) access is displayed. */
	access_tree = display_access_items(tvb, offset, pinfo, tree,
		(mask_allowed | mask_denied), 'R', version, optext, NULL) ;

	ditem = proto_tree_add_boolean(access_tree, hf_nfs_access_denied, tvb,
				offset, 4, (mask_denied > 0 ? TRUE : FALSE ));
	PROTO_ITEM_SET_GENERATED(ditem);

	return offset+4;
}


/* NFSv3 RFC 1813, Page 40..43 */
static int
dissect_nfs3_access_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, void *data)
{
	guint32 fhhash = 0, *acc_request, amask;
	rpc_call_info_value *civ = (rpc_call_info_value*)data;

	offset = dissect_nfs3_fh(tvb, offset, pinfo, tree, "object", &fhhash, civ);

	/* Get access mask to check and save it for comparison to the access reply. */
	amask = tvb_get_ntohl(tvb, offset);
	acc_request = (guint32 *)wmem_memdup(wmem_file_scope(),  &amask, sizeof(guint32));
	civ->private_data = acc_request;

	/* Append filehandle to Info column and main tree header */
	col_append_fstr(pinfo->cinfo, COL_INFO, ", FH: 0x%08x", fhhash);
	proto_item_append_text(tree, ", ACCESS Call, FH: 0x%08x", fhhash);

	display_access_items(tvb, offset, pinfo, tree, amask, 'C', 3, NULL, "Check") ;

	offset+=4;
	return offset;
}


/* NFSv3 RFC 1813, Page 40..43 */
static int
dissect_nfs3_access_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			  proto_tree *tree, void *data _U_)
{
	guint32	    status;
	const char *err;

	offset = dissect_nfs3_status(tvb, offset, tree, &status);
	offset = dissect_nfs3_post_op_attr(tvb, offset, pinfo, tree,
					"obj_attributes");

	if (status == 0) {
		proto_item_append_text(tree, ", ACCESS Reply");
		offset = dissect_access_reply(tvb, offset, pinfo, tree, 3, NULL, (rpc_call_info_value*)data);
	} else {
		err = val_to_str_ext(status, &names_nfs3_status_ext, "Unknown error: %u");
		col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
		proto_item_append_text(tree, ", ACCESS Reply  Error: %s", err);
	}
	return offset;
}


/* NFSv3 RFC 1813, Page 44,45 */
static int
dissect_nfs3_readlink_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, void *data)
{
	guint32 hash = 0;

	offset = dissect_nfs3_fh(tvb, offset, pinfo, tree, "object", &hash, (rpc_call_info_value*)data);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", FH: 0x%08x", hash);
	proto_item_append_text(tree, ", READLINK Call FH: 0x%08x", hash);

	return offset;
}


static int
dissect_nfs3_readlink_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			    proto_tree *tree, void *data _U_)
{
	guint32	    status;
	const char *err;
	const char *name = NULL;

	offset = dissect_nfs3_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_nfs3_post_op_attr(tvb, offset, pinfo, tree,
				"symlink_attributes");
			offset = dissect_nfs3_path(tvb, offset, tree,
				hf_nfs2_readlink_data, &name);

			col_append_fstr(pinfo->cinfo, COL_INFO, " Path: %s", name);
			proto_item_append_text(tree, ", READLINK Reply Path: %s", name);
		break;
		default:
			offset = dissect_nfs3_post_op_attr(tvb, offset, pinfo, tree,
				"symlink_attributes");

			err = val_to_str_ext(status, &names_nfs3_status_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, ", READLINK Reply  Error: %s", err);
		break;
	}

	return offset;
}


/* NFSv3 RFC 1813, Page 46..48 */
static int
dissect_nfs3_read_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
		       proto_tree *tree, void *data)
{
	guint64 off;
	guint32 len;
	guint32 hash = 0;

	offset = dissect_nfs3_fh(tvb, offset, pinfo, tree, "file", &hash, (rpc_call_info_value*)data);

	off = tvb_get_ntoh64(tvb, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_nfs3_offset, offset);

	len = tvb_get_ntohl(tvb, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs3_count, offset);


	col_append_fstr(pinfo->cinfo, COL_INFO,
		", FH: 0x%08x Offset: %" G_GINT64_MODIFIER "u Len: %u", hash, off, len);
	proto_item_append_text(tree,
		", READ Call FH: 0x%08x Offset: %" G_GINT64_MODIFIER "u Len: %u", hash, off, len);

	return offset;
}


/* NFSv3 RFC 1813, Page 46..48 */
static int
dissect_nfs3_read_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			proto_tree *tree, void *data _U_)
{
	guint32	    status;
	guint32	    len;
	const char *err;

	offset = dissect_nfs3_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_nfs3_post_op_attr(tvb, offset, pinfo, tree,
				"file_attributes");
			len = tvb_get_ntohl(tvb, offset);
			offset = dissect_rpc_uint32(tvb, tree, hf_nfs3_count,
				offset);
			offset = dissect_rpc_bool(tvb, tree, hf_nfs3_read_eof,
				offset);
			col_append_fstr(pinfo->cinfo, COL_INFO, " Len: %d", len);
			proto_item_append_text(tree, ", READ Reply Len: %d", len);
			offset = dissect_nfsdata(tvb, offset, tree, hf_nfs_data);
		break;
		default:
			offset = dissect_nfs3_post_op_attr(tvb, offset, pinfo, tree,
				"file_attributes");

			err = val_to_str_ext(status, &names_nfs3_status_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, ", READ Reply  Error: %s", err);
		break;
	}

	return offset;
}


/* NFSv3 RFC 1813, Page 49 */
static const value_string names_stable_how[] = {
	{	UNSTABLE,  "UNSTABLE"  },
	{	DATA_SYNC, "DATA_SYNC" },
	{	FILE_SYNC, "FILE_SYNC" },
	{	0, NULL }
};

/* NFSv3 RFC 1813, Page 49 */
static int
dissect_stable_how(tvbuff_t *tvb, int offset, proto_tree *tree, int hfindex)
{
	guint32 stable_how;

	stable_how = tvb_get_ntohl(tvb, offset+0);
	if (tree)
		proto_tree_add_uint(tree, hfindex, tvb,	offset, 4, stable_how);
	offset += 4;

	return offset;
}


/* NFSv3 RFC 1813, Page 49..54 */
static int
dissect_nfs3_write_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *tree, void *data)
{
	guint64 off;
	guint32 len;
	guint32 stable;
	guint32 hash = 0;

	offset = dissect_nfs3_fh(tvb, offset, pinfo, tree, "file", &hash, (rpc_call_info_value*)data);

	off = tvb_get_ntoh64(tvb, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_nfs3_offset, offset);

	len = tvb_get_ntohl(tvb, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs3_count, offset);

	stable = tvb_get_ntohl(tvb, offset);
	offset = dissect_stable_how(tvb, offset, tree, hf_nfs3_write_stable);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", FH: 0x%08x Offset: %" G_GINT64_MODIFIER "u Len: %u %s",
		hash, off, len, val_to_str(stable, names_stable_how, "Stable: %u"));
	proto_item_append_text(tree, ", WRITE Call FH: 0x%08x Offset: %" G_GINT64_MODIFIER "u Len: %u %s",
		hash, off, len, val_to_str(stable, names_stable_how, "Stable: %u"));

	offset = dissect_nfsdata   (tvb, offset, tree, hf_nfs_data);

	return offset;
}


/* NFSv3 RFC 1813, Page 49..54 */
static int
dissect_nfs3_write_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			 proto_tree *tree, void *data _U_)
{
	guint32	    status;
	guint32	    len;
	guint32	    stable;
	const char *err;

	offset = dissect_nfs3_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "file_wcc");
			len = tvb_get_ntohl(tvb, offset);
			offset = dissect_rpc_uint32(tvb, tree, hf_nfs3_count,
				offset);
			stable = tvb_get_ntohl(tvb, offset);
			offset = dissect_stable_how(tvb, offset, tree,
				hf_nfs3_write_committed);
			offset = dissect_nfs3_write_verf(tvb, offset, tree);

			col_append_fstr(pinfo->cinfo, COL_INFO,
				" Len: %d %s", len, val_to_str(stable, names_stable_how, "Stable: %u"));
			proto_item_append_text(tree, ", WRITE Reply Len: %d %s",
				len, val_to_str(stable, names_stable_how, "Stable: %u"));
		break;
		default:
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "file_wcc");

			err = val_to_str_ext(status, &names_nfs3_status_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, ", WRITE Reply  Error: %s", err);
		break;
	}

	return offset;
}


/* NFSv3 RFC 1813, Page 54 */
static const value_string names_createmode3[] = {
	{	UNCHECKED, "UNCHECKED" },
	{	GUARDED,   "GUARDED" },
	{	EXCLUSIVE, "EXCLUSIVE" },
	{	0, NULL }
};

/* NFSv3 RFC 1813, Page 54 */
static int
dissect_createmode3(tvbuff_t *tvb, int offset, proto_tree *tree, guint32* mode)
{
	guint32 mode_value;

	mode_value = tvb_get_ntohl(tvb, offset + 0);
	if (tree)
		proto_tree_add_uint(tree, hf_nfs3_createmode, tvb, offset+0, 4, mode_value);
	offset += 4;

	*mode = mode_value;
	return offset;
}


/* NFSv3 RFC 1813, Page 54..58 */
static int
dissect_nfs3_create_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
			 proto_tree *tree, void *data)
{
	guint32	    mode;
	guint32	    hash = 0;
	const char *name = NULL;

	offset = dissect_diropargs3 (tvb, offset, pinfo, tree, "where", &hash, &name, (rpc_call_info_value*)data);
	offset = dissect_createmode3(tvb, offset, tree, &mode);
	switch (mode) {
		case UNCHECKED:
		case GUARDED:
			offset = dissect_nfs3_sattr(tvb, offset, tree, "obj_attributes");
		break;
		case EXCLUSIVE:
			offset = dissect_nfs3_create_verf(tvb, offset, tree);
		break;
	}

	col_append_fstr(pinfo->cinfo, COL_INFO, ", DH: 0x%08x/%s Mode: %s", hash, name,
		val_to_str(mode, names_createmode3, "Unknown Mode: %u"));
	proto_item_append_text(tree, ", CREATE Call DH: 0x%08x/%s Mode: %s", hash, name,
		val_to_str(mode, names_createmode3, "Unknown Mode: %u"));

	return offset;
}


/* NFSv3 RFC 1813, Page 54..58 */
static int
dissect_nfs3_create_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
			  proto_tree *tree, void *data)
{
	guint32	    status;
	const char *err;

	offset = dissect_nfs3_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_nfs3_post_op_fh (tvb, offset, pinfo, tree, "obj", (rpc_call_info_value*)data);
			offset = dissect_nfs3_post_op_attr(tvb, offset, pinfo, tree,
				"obj_attributes");
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "dir_wcc");
			proto_item_append_text(tree, ", CREATE Reply");
		break;
		default:
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "dir_wcc");

			err = val_to_str_ext(status, &names_nfs3_status_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, ", CREATE Reply  Error: %s", err);
		break;
	}

	return offset;
}


/* NFSv3 RFC 1813, Page 58..60 */
static int
dissect_nfs3_mkdir_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *tree, void *data)
{
	guint32	    hash = 0;
	const char *name = NULL;

	offset = dissect_diropargs3(tvb, offset, pinfo, tree, "where", &hash, &name, (rpc_call_info_value*)data);
	offset = dissect_nfs3_sattr    (tvb, offset, tree, "attributes");

	col_append_fstr(pinfo->cinfo, COL_INFO, ", DH: 0x%08x/%s", hash, name);
	proto_item_append_text(tree, ", MKDIR Call DH: 0x%08x/%s", hash, name);

	return offset;
}


static int
dissect_nfs3_mkdir_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
			 proto_tree *tree, void *data)
{
	guint32	    status;
	const char *err;

	offset = dissect_nfs3_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_nfs3_post_op_fh (tvb, offset, pinfo, tree, "obj", (rpc_call_info_value*)data);
			offset = dissect_nfs3_post_op_attr(tvb, offset, pinfo, tree,
				"obj_attributes");
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "dir_wcc");
			proto_item_append_text(tree, ", MKDIR Reply");
		break;
		default:
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "dir_wcc");

			err = val_to_str_ext(status, &names_nfs3_status_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, ", MKDIR Reply  Error: %s", err);
		break;
	}

	return offset;
}


/* NFSv3 RFC 1813, Page 61..63 */
static int
dissect_nfs3_symlink_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
			  proto_tree *tree, void *data)
{
	guint32	    from_hash = 0;
	const char *from_name =	NULL;
	const char *to_name   =	NULL;

	offset = dissect_diropargs3(tvb, offset, pinfo, tree, "where", &from_hash, &from_name, (rpc_call_info_value*)data);
	offset = dissect_nfs3_sattr    (tvb, offset,        tree, "symlink_attributes");
	offset = dissect_nfs3_path  (tvb, offset,        tree, hf_nfs_symlink_to, &to_name);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", From DH: 0x%08x/%s To %s",
		from_hash, from_name, to_name);
	proto_item_append_text(tree, ", SYMLINK Call From DH: 0x%08x/%s To %s",
		from_hash, from_name, to_name);

	return offset;
}


static int
dissect_nfs3_symlink_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, void *data)
{
	guint32	    status;
	const char *err;

	offset = dissect_nfs3_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_nfs3_post_op_fh (tvb, offset, pinfo, tree, "obj", (rpc_call_info_value*)data);
			offset = dissect_nfs3_post_op_attr(tvb, offset, pinfo, tree,
				"obj_attributes");
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "dir_wcc");
			proto_item_append_text(tree, ", SYMLINK Reply");
		break;
		default:
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "dir_wcc");

			err = val_to_str_ext(status, &names_nfs3_status_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, ", SYMLINK Reply  Error: %s", err);
		break;
	}

	return offset;
}


/* NFSv3 RFC 1813, Page 63..66 */
static int
dissect_nfs3_mknod_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *tree, void *data)
{
	guint32	    type;
	guint32	    hash = 0;
	const char *name = NULL;
	const char *type_str;

	offset = dissect_diropargs3(tvb, offset, pinfo, tree, "where", &hash, &name, (rpc_call_info_value*)data);
	offset = dissect_ftype3(tvb, offset, tree, hf_nfs3_ftype, &type);
	switch (type) {
		case NF3CHR:
		case NF3BLK:
			offset = dissect_nfs3_sattr(tvb, offset, tree, "dev_attributes");
			offset = dissect_nfs3_specdata(tvb, offset, tree, "spec");
		break;
		case NF3SOCK:
		case NF3FIFO:
			offset = dissect_nfs3_sattr(tvb, offset, tree, "pipe_attributes");
		break;
		default:
			/* nothing to do */
		break;
	}

	type_str = val_to_str_ext(type, &names_nfs_ftype3_ext, "Unknown type: %u");
	col_append_fstr(pinfo->cinfo, COL_INFO, ", FH: 0x%08x/%s %s", hash, name, type_str);
	proto_item_append_text(tree, ", MKNOD Call FH: 0x%08x/%s %s", hash, name, type_str);

	return offset;
}


static int
dissect_nfs3_mknod_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
			 proto_tree *tree, void *data)
{
	guint32	    status;
	const char *err;

	offset = dissect_nfs3_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_nfs3_post_op_fh (tvb, offset, pinfo, tree, "obj", (rpc_call_info_value*)data);
			offset = dissect_nfs3_post_op_attr(tvb, offset, pinfo, tree,
				"obj_attributes");
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "dir_wcc");
			proto_item_append_text(tree, ", MKNOD Reply");
		break;
		default:
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "dir_wcc");

			err = val_to_str_ext(status, &names_nfs3_status_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, ", MKNOD Reply  Error: %s", err);
		break;
	}

	return offset;
}


/* NFSv3 RFC 1813, Page 67..69 */
static int
dissect_nfs3_remove_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			  proto_tree *tree, void *data _U_)
{
	guint32	    status;
	const char *err;

	offset = dissect_nfs3_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "dir_wcc");
			proto_item_append_text(tree, ", REMOVE Reply");
		break;
		default:
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "dir_wcc");
			err = val_to_str_ext(status, &names_nfs3_status_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, ", REMOVE Reply  Error: %s", err);
		break;
	}

	return offset;
}


static int
dissect_nfs3_rmdir_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			 proto_tree *tree, void *data _U_)
{
	guint32	    status;
	const char *err;

	offset = dissect_nfs3_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "dir_wcc");
			proto_item_append_text(tree, ", RMDIR Reply");
		break;
		default:
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "dir_wcc");
			err = val_to_str_ext(status, &names_nfs3_status_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, ", RMDIR Reply  Error: %s", err);
		break;
	}

	return offset;
}


/* NFSv3 RFC 1813, Page 71..74 */
static int
dissect_nfs3_rename_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
			 proto_tree *tree, void *data)
{
	guint32	    from_hash = 0;
	const char *from_name =	NULL;
	guint32	    to_hash   = 0;
	const char *to_name   =	NULL;

	offset = dissect_diropargs3(tvb, offset, pinfo, tree, "from", &from_hash, &from_name, (rpc_call_info_value*)data);
	offset = dissect_diropargs3(tvb, offset, pinfo, tree, "to", &to_hash, &to_name, (rpc_call_info_value*)data);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", From DH: 0x%08x/%s To DH: 0x%08x/%s",
		from_hash, from_name, to_hash, to_name);
	proto_item_append_text(tree, ", RENAME Call From DH: 0x%08x/%s To DH: 0x%08x/%s",
		from_hash, from_name, to_hash, to_name);

	return offset;
}


/* NFSv3 RFC 1813, Page 71..74 */
static int
dissect_nfs3_rename_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			  proto_tree *tree, void *data _U_)
{
	guint32	    status;
	const char *err;

	offset = dissect_nfs3_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "fromdir_wcc");
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "todir_wcc");
			proto_item_append_text(tree, ", RENAME Reply");
		break;
		default:
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "fromdir_wcc");
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "todir_wcc");

			err = val_to_str_ext(status, &names_nfs3_status_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, ", RENAME Reply  Error: %s", err);
		break;
	}

	return offset;
}


/* NFSv3 RFC 1813, Page 74..76 */
static int
dissect_nfs3_link_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
		       proto_tree *tree, void *data)
{
	guint32	    from_hash = 0;
	guint32	    to_hash   = 0;
	const char *to_name   =	NULL;

	offset = dissect_nfs3_fh(tvb, offset, pinfo, tree, "file", &from_hash, (rpc_call_info_value*)data);
	offset = dissect_diropargs3(tvb, offset, pinfo, tree, "link", &to_hash, &to_name, (rpc_call_info_value*)data);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", From DH: 0x%08x To DH: 0x%08x/%s",
		from_hash, to_hash, to_name);
	proto_item_append_text(tree, ", LINK Call From DH: 0x%08x To DH: 0x%08x/%s",
		from_hash, to_hash, to_name);

	return offset;
}


/* NFSv3 RFC 1813, Page 74..76 */
static int
dissect_nfs3_link_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			proto_tree *tree, void *data _U_)
{
	guint32	    status;
	const char *err;

	offset = dissect_nfs3_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_nfs3_post_op_attr(tvb, offset, pinfo, tree,
				"file_attributes");
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "linkdir_wcc");
			proto_item_append_text(tree, ", LINK Reply");
		break;
		default:
			offset = dissect_nfs3_post_op_attr(tvb, offset, pinfo, tree,
				"file_attributes");
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "linkdir_wcc");

			err = val_to_str_ext(status, &names_nfs3_status_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, ", LINK Reply  Error: %s", err);
		break;
	}

	return offset;
}


/* NFSv3 RFC 1813, Page 76..80 */
static int
dissect_nfs3_readdir_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
			  proto_tree *tree, void *data)
{
	guint32 hash = 0;

	offset = dissect_nfs3_fh(tvb, offset, pinfo, tree, "dir", &hash, (rpc_call_info_value*)data);
	offset = dissect_rpc_uint64(tvb, tree, hf_nfs3_cookie, offset);
	offset = dissect_nfs3_cookie_verf(tvb, offset, tree);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs3_count, offset);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", FH: 0x%08x", hash);
	proto_item_append_text(tree, ", READDIR Call FH: 0x%08x", hash);

	return offset;
}


/* NFSv3 RFC 1813, Page 76..80 */
static int
dissect_entry3(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	       proto_tree *tree, void *data _U_)
{
	proto_item *entry_item = NULL;
	proto_tree *entry_tree = NULL;
	int	    old_offset = offset;
	const char *name       = NULL;

	if (tree) {
		entry_item = proto_tree_add_item(tree, hf_nfs_readdir_entry, tvb,
			offset+0, -1, ENC_NA);
		entry_tree = proto_item_add_subtree(entry_item, ett_nfs_readdir_entry);
	}

	offset = dissect_rpc_uint64(tvb, entry_tree, hf_nfs3_readdir_entry_fileid, offset);

	offset = dissect_nfs3_filename(tvb, offset, entry_tree,	hf_nfs3_readdir_entry_name, &name);
	if (entry_item)
		proto_item_set_text(entry_item, "Entry: name %s", name);

	col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name);

	offset = dissect_rpc_uint64(tvb, entry_tree, hf_nfs3_readdir_entry_cookie, offset);

	/* now we know, that a readdir entry is shorter */
	if (entry_item)
		proto_item_set_len(entry_item, offset - old_offset);

	return offset;
}


/* NFSv3 RFC 1813, Page 76..80 */
static int
dissect_nfs3_readdir_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, void *data _U_)
{
	guint32	    status;
	guint32	    eof_value;
	const char *err;

	offset = dissect_nfs3_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			proto_item_append_text(tree, ", READDIR Reply");

			offset = dissect_nfs3_post_op_attr(tvb, offset, pinfo, tree,
				"dir_attributes");
			offset = dissect_nfs3_cookie_verf(tvb, offset, tree);
			offset = dissect_rpc_list(tvb, pinfo, tree, offset,
				dissect_entry3, NULL);
			eof_value = tvb_get_ntohl(tvb, offset+0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs_readdir_eof, tvb,
					offset+ 0, 4, eof_value);
			offset += 4;
		break;
		default:
			offset = dissect_nfs3_post_op_attr(tvb, offset, pinfo, tree,
				"dir_attributes");

			err = val_to_str_ext(status, &names_nfs3_status_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, ", READDIR Reply  Error: %s", err);
		break;
	}

	return offset;
}


/* NFSv3 RFC 1813, Page 80..83 */
static int
dissect_nfs3_readdirplus_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
			      proto_tree *tree, void *data)
{
	guint32 hash = 0;

	offset = dissect_nfs3_fh(tvb, offset, pinfo, tree, "dir", &hash, (rpc_call_info_value*)data);
	offset = dissect_rpc_uint64(tvb, tree, hf_nfs3_cookie, offset);
	offset = dissect_nfs3_cookie_verf(tvb, offset, tree);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs3_count_dircount,
		offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs3_count_maxcount,
		offset);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", FH: 0x%08x", hash);
	proto_item_append_text(tree, ", READDIRPLUS Call FH: 0x%08x", hash);

	return offset;
}


/* NFSv3 RFC 1813, Page 80..83 */
static int
dissect_nfs3_entryplus(tvbuff_t *tvb, int offset, packet_info *pinfo,
		   proto_tree *tree, void *data)
{
	proto_item *entry_item = NULL;
	proto_tree *entry_tree = NULL;
	int	    old_offset = offset;
	const char *name       = NULL;
	rpc_call_info_value *civ = (rpc_call_info_value *)data;

	if (tree) {
		entry_item = proto_tree_add_item(tree, hf_nfs_readdir_entry, tvb,
			offset+0, -1, ENC_NA);
		entry_tree = proto_item_add_subtree(entry_item, ett_nfs_readdir_entry);
	}

	offset = dissect_rpc_uint64(tvb, entry_tree, hf_nfs3_readdirplus_entry_fileid, offset);

	offset = dissect_nfs3_filename(tvb, offset, entry_tree,	hf_nfs3_readdirplus_entry_name, &name);

	/* are we snooping fh to filenames ?*/
	if ((!pinfo->fd->flags.visited) && nfs_file_name_snooping) {
		/* v3 READDIRPLUS replies will give us a mapping */
		if ( (civ->prog == 100003)
		  &&(civ->vers == 3)
		  &&(!civ->request)
		  &&((civ->proc == 17))
		) {
			nfs_name_snoop_add_name(civ->xid, tvb, 0, 0,
				0/*parent offset*/, 0/*parent len*/,
				name);
		}
	}

	if (entry_item)
		proto_item_set_text(entry_item, "Entry: name %s", name);

	col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name);

	offset = dissect_rpc_uint64(tvb, entry_tree, hf_nfs3_readdirplus_entry_cookie,
		offset);

	offset = dissect_nfs3_post_op_attr(tvb, offset, pinfo, entry_tree, "name_attributes");

	offset = dissect_nfs3_post_op_fh(tvb, offset, pinfo, entry_tree, "name_handle", civ);

	/* now we know, that a readdirplus entry is shorter */
	if (entry_item)
		proto_item_set_len(entry_item, offset - old_offset);

	return offset;
}


/* NFSv3 RFC 1813, Page 80..83 */
static int
dissect_nfs3_readdirplus_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
			       proto_tree *tree, void *data)
{
	guint32	    status;
	guint32	    eof_value;
	const char *err;

	offset = dissect_nfs3_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			proto_item_append_text(tree, ", READDIRPLUS Reply");

			offset = dissect_nfs3_post_op_attr(tvb, offset, pinfo, tree,
				"dir_attributes");
			offset = dissect_nfs3_cookie_verf(tvb, offset, tree);
			offset = dissect_rpc_list(tvb, pinfo, tree, offset,
				dissect_nfs3_entryplus, data);
			eof_value = tvb_get_ntohl(tvb, offset+0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs_readdir_eof, tvb,
					offset+ 0, 4, eof_value);
			offset += 4;
		break;
		default:
			offset = dissect_nfs3_post_op_attr(tvb, offset, pinfo, tree,
				"dir_attributes");

			err = val_to_str_ext(status, &names_nfs3_status_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, ", READDIRPLUS Reply  Error: %s", err);
		break;
	}

	return offset;
}


/* NFSv3 RFC 1813, Page 84..86 */
static int
dissect_nfs3_fsstat_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
			 proto_tree *tree, void *data)
{
	guint32 hash = 0;

	offset = dissect_nfs3_fh(tvb, offset, pinfo, tree, "object", &hash, (rpc_call_info_value*)data);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", FH: 0x%08x", hash);
	proto_item_append_text(tree, ", FSSTAT Call DH: 0x%08x", hash);
	return offset;
}


static int
dissect_nfs3_fsstat_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			  proto_tree *tree, void *data _U_)
{
	guint32	    status;
	guint32	    invarsec;
	const char *err;

	offset = dissect_nfs3_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_nfs3_post_op_attr(tvb, offset, pinfo, tree,
				"obj_attributes");
			offset = dissect_rpc_uint64(tvb, tree, hf_nfs3_fsstat_resok_tbytes,
				offset);
			offset = dissect_rpc_uint64(tvb, tree, hf_nfs3_fsstat_resok_fbytes,
				offset);
			offset = dissect_rpc_uint64(tvb, tree, hf_nfs3_fsstat_resok_abytes,
				offset);
			offset = dissect_rpc_uint64(tvb, tree, hf_nfs3_fsstat_resok_tfiles,
				offset);
			offset = dissect_rpc_uint64(tvb, tree, hf_nfs3_fsstat_resok_ffiles,
				offset);
			offset = dissect_rpc_uint64(tvb, tree, hf_nfs3_fsstat_resok_afiles,
				offset);
			invarsec = tvb_get_ntohl(tvb, offset + 0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs3_fsstat_invarsec, tvb,
				offset+0, 4, invarsec);
			offset += 4;

			proto_item_append_text(tree, ", FSSTAT Reply");
		break;
		default:
			offset = dissect_nfs3_post_op_attr(tvb, offset, pinfo, tree,
				"obj_attributes");

			err = val_to_str_ext(status, &names_nfs3_status_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, ", FSSTAT Reply  Error: %s", err);
		break;
	}

	return offset;
}


#define FSF3_LINK        0x0001
#define FSF3_SYMLINK     0x0002
#define FSF3_HOMOGENEOUS 0x0008
#define FSF3_CANSETTIME  0x0010

static const true_false_string tfs_nfs_pathconf =
	{ "is valid for all files", "should be get for every single file" };


/* NFSv3 RFC 1813, Page 86..90 */
static int
dissect_nfs3_fsinfo_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
			 proto_tree *tree, void *data)
{
	guint32 hash = 0;

	offset = dissect_nfs3_fh(tvb, offset, pinfo, tree, "object", &hash, (rpc_call_info_value*)data);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", FH: 0x%08x", hash);
	proto_item_append_text(tree, ", FSINFO Call DH: 0x%08x", hash);
	return offset;
}


static int
dissect_nfs3_fsinfo_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			  proto_tree *tree, void *data _U_)
{
	guint32	    status;

	offset = dissect_nfs3_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_nfs3_post_op_attr(tvb, offset, pinfo, tree,
				"obj_attributes");
			proto_tree_add_item(tree, hf_nfs3_fsinfo_rtmax, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(tree, hf_nfs3_fsinfo_rtpref, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(tree, hf_nfs3_fsinfo_rtmult, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(tree, hf_nfs3_fsinfo_wtmax, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(tree, hf_nfs3_fsinfo_wtpref, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(tree, hf_nfs3_fsinfo_wtmult, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(tree, hf_nfs3_fsinfo_dtpref, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			offset = dissect_rpc_uint64(tvb, tree,	hf_nfs3_fsinfo_maxfilesize, offset);
			offset = dissect_nfstime3(tvb, offset, tree, hf_nfs_dtime, hf_nfs_dtime_sec,
				hf_nfs_dtime_nsec);

			if (tree) {
				proto_item *properties_item;
				proto_tree *properties_tree;

				properties_item = proto_tree_add_item(tree, hf_nfs3_fsinfo_properties,
				    tvb, offset, 4, ENC_BIG_ENDIAN);

				properties_tree = proto_item_add_subtree(properties_item, ett_nfs3_fsinfo_properties);

				proto_tree_add_item(properties_tree, hf_nfs3_fsinfo_properties_setattr, tvb,
					offset, 4, ENC_BIG_ENDIAN);
				proto_tree_add_item(properties_tree, hf_nfs3_fsinfo_properties_pathconf, tvb,
					offset, 4, ENC_BIG_ENDIAN);
				proto_tree_add_item(properties_tree, hf_nfs3_fsinfo_properties_symlinks, tvb,
					offset, 4, ENC_BIG_ENDIAN);
				proto_tree_add_item(properties_tree, hf_nfs3_fsinfo_properties_hardlinks, tvb,
					offset, 4, ENC_BIG_ENDIAN);
			}
			offset += 4;

			proto_item_append_text(tree, ", FSINFO Reply");
			break;
		default:
		{
			const char *err;

			offset = dissect_nfs3_post_op_attr(tvb, offset, pinfo, tree,
				"obj_attributes");

			err = val_to_str_ext(status, &names_nfs3_status_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, ", FSINFO Reply  Error: %s", err);
			break;
		}
	}

	return offset;
}


/* NFSv3 RFC 1813, Page 90..92 */
static int
dissect_nfs3_pathconf_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
			   proto_tree *tree, void *data)
{
	guint32 hash = 0;

	offset = dissect_nfs3_fh(tvb, offset, pinfo, tree, "object", &hash, (rpc_call_info_value*)data);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", FH: 0x%08x", hash);
	proto_item_append_text(tree, ", PATHCONF Call DH: 0x%08x", hash);
	return offset;
}


static int
dissect_nfs3_pathconf_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			    proto_tree *tree, void *data _U_)
{
	guint32	    status;
	guint32	    linkmax;
	guint32	    name_max;
	const char *err;

	offset = dissect_nfs3_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_nfs3_post_op_attr(tvb, offset, pinfo, tree,
				"obj_attributes");
			linkmax = tvb_get_ntohl(tvb, offset + 0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs3_pathconf_linkmax, tvb,
				offset+0, 4, linkmax);
			offset += 4;
			name_max = tvb_get_ntohl(tvb, offset + 0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs3_pathconf_name_max, tvb,
				offset+0, 4, name_max);
			offset += 4;
			offset = dissect_rpc_bool(tvb, tree,
				hf_nfs3_pathconf_no_trunc, offset);
			offset = dissect_rpc_bool(tvb, tree,
				hf_nfs3_pathconf_chown_restricted, offset);
			offset = dissect_rpc_bool(tvb, tree,
				hf_nfs3_pathconf_case_insensitive, offset);
			offset = dissect_rpc_bool(tvb, tree,
				hf_nfs3_pathconf_case_preserving, offset);

			proto_item_append_text(tree, ", PATHCONF Reply");
		break;
		default:
			offset = dissect_nfs3_post_op_attr(tvb, offset, pinfo, tree,
				"obj_attributes");

			err = val_to_str_ext(status, &names_nfs3_status_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, ", PATHCONF Reply  Error: %s", err);
		break;
	}

	return offset;
}


/* NFSv3 RFC 1813, Page 92..95 */
static int
dissect_nfs3_commit_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
			 proto_tree *tree, void *data)
{
	guint32 hash = 0;

	offset = dissect_nfs3_fh(tvb, offset, pinfo, tree, "file", &hash, (rpc_call_info_value*)data);
	offset = dissect_rpc_uint64(tvb, tree, hf_nfs3_offset, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs3_count, offset);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", FH: 0x%08x", hash);
	proto_item_append_text(tree, ", COMMIT Call FH: 0x%08x", hash);

	return offset;
}


/* NFSv3 RFC 1813, Page 92..95 */
static int
dissect_nfs3_commit_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			  proto_tree *tree, void *data _U_)
{
	guint32	    status;
	const char *err;

	offset = dissect_nfs3_status(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_wcc_data  (tvb, offset, pinfo, tree, "file_wcc");
			offset = dissect_nfs3_write_verf(tvb, offset, tree);

			proto_item_append_text(tree, ", COMMIT Reply");
		break;
		default:
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "file_wcc");

			err = val_to_str_ext(status, &names_nfs3_status_ext, "Unknown error: %u");
			col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", err);
			proto_item_append_text(tree, ", COMMIT Reply  Error: %s", err);
		break;
	}

	return offset;
}

/*************************************************************************************
*  NFS Version 4.1, RFC 5661.  Note that error 19 NFS4ERR_NOTDIR defined in RFC 3010
*  was eliminated in RFC 3530 (NFSv4) which replaced RFC 3010 and remains so in
*  RFC 5661. Nevertheless, it has been included in this table in the event that some
*  RFC 3010 implementations still exist out there.**************************************************************************************/
static const value_string names_nfs4_status[] = {
	{	0,	"NFS4_OK"			    },
	{	1,	"NFS4ERR_PERM"			    },
	{	2,	"NFS4ERR_NOENT"			    },
	{	5,	"NFS4ERR_IO"			    },
	{	6,	"NFS4ERR_NXIO"			    },
	{	13,	"NFS4ERR_ACCESS"		    },
	{	17,	"NFS4ERR_EXIST"			    },
	{	18,	"NFS4ERR_XDEV"			    },
	{	19,	"NFS4ERR_DQUOT"			    },
	{	20,	"NFS4ERR_NOTDIR"		    },
	{	21,	"NFS4ERR_ISDIR"			    },
	{	22,	"NFS4ERR_INVAL"			    },
	{	27,	"NFS4ERR_FBIG"			    },
	{	28,	"NFS4ERR_NOSPC"			    },
	{	30,	"NFS4ERR_ROFS"			    },
	{	31,	"NFS4ERR_MLINK"			    },
	{	63,	"NFS4ERR_NAMETOOLONG"		    },
	{	66,	"NFS4ERR_NOTEMPTY"		    },
	{	69,	"NFS4ERR_DQUOT"			    },
	{	70,	"NFS4ERR_STALE"			    },
	{	10001,	"NFS4ERR_BADHANDLE"		    },
	{	10003,	"NFS4ERR_BAD_COOKIE"		    },
	{	10004,	"NFS4ERR_NOTSUPP"		    },
	{	10005,	"NFS4ERR_TOOSMALL"		    },
	{	10006,	"NFS4ERR_SERVERFAULT"		    },
	{	10007,	"NFS4ERR_BADTYPE"		    },
	{	10008,	"NFS4ERR_DELAY"			    },
	{	10009,	"NFS4ERR_SAME"			    },
	{	10010,	"NFS4ERR_DENIED"		    },
	{	10011,	"NFS4ERR_EXPIRED"		    },
	{	10012,	"NFS4ERR_LOCKED"		    },
	{	10013,	"NFS4ERR_GRACE"			    },
	{	10014,	"NFS4ERR_FHEXPIRED"		    },
	{	10015,	"NFS4ERR_SHARE_DENIED"		    },
	{	10016,	"NFS4ERR_WRONGSEC"		    },
	{	10017,	"NFS4ERR_CLID_INUSE"		    },
	{	10018,	"NFS4ERR_RESOURCE"		    },
	{	10019,	"NFS4ERR_MOVED"			    },
	{	10020,	"NFS4ERR_NOFILEHANDLE"		    },
	{	10021,	"NFS4ERR_MINOR_VERS_MISMATCH"	    },
	{	10022,	"NFS4ERR_STALE_CLIENTID"	    },
	{	10023,	"NFS4ERR_STALE_STATEID"		    },
	{	10024,	"NFS4ERR_OLD_STATEID"		    },
	{	10025,	"NFS4ERR_BAD_STATEID"		    },
	{	10026,	"NFS4ERR_BAD_SEQID"		    },
	{	10027,	"NFS4ERR_NOT_SAME"		    },
	{	10028,	"NFS4ERR_LOCK_RANGE"		    },
	{	10029,	"NFS4ERR_SYMLINK"		    },
	{	10030,	"NFS4ERR_READDIR_NOSPC"		    },
	{	10031,	"NFS4ERR_LEASE_MOVED"		    },
	{	10032,	"NFS4ERR_ATTRNOTSUPP"		    },
	{	10033,	"NFS4ERR_NO_GRACE"		    },
	{	10034,	"NFS4ERR_RECLAIM_BAD"		    },
	{	10035,	"NFS4ERR_RECLAIM_CONFLICT"	    },
	{	10036,	"NFS4ERR_BADXDR"		    },
	{	10037,	"NFS4ERR_LOCKS_HELD"		    },
	{	10038,	"NFS4ERR_OPENMODE"		    },
	{	10039,	"NFS4ERR_BADOWNER"		    },
	{	10040,	"NFS4ERR_BADCHAR"		    },
	{	10041,	"NFS4ERR_BADNAME"		    },
	{	10042,	"NFS4ERR_BAD_RANGE"		    },
	{	10043,	"NFS4ERR_LOCK_NOTSUPP"		    },
	{	10044,	"NFS4ERR_OP_ILLEGAL"		    },
	{	10045,	"NFS4ERR_DEADLOCK"		    },
	{	10046,	"NFS4ERR_FILE_OPEN"		    },
	{	10047,	"NFS4ERR_ADMIN_REVOKED"		    },
	{	10048,	"NFS4ERR_CB_PATH_DOWN"		    },
	{	10049,	"NFS4ERR_BADIOMODE"		    },
	{	10050,	"NFS4ERR_BADLAYOUT"		    },
	{	10051,	"NFS4ERR_BAD_SESSION_DIGEST"	    },
	{	10052,	"NFS4ERR_BADSESSION"		    },
	{	10053,	"NFS4ERR_BADSLOT"		    },
	{	10054,	"NFS4ERR_COMPLETE_ALREADY"	    },
	{	10055,	"NFS4ERR_CONN_NOT_BOUND_TO_SESSION" },
	{	10056,	"NFS4ERR_DELEG_ALREADY_WANTED"	    },
	{	10057,	"NFS4ERR_DIRDELEG_UNAVAIL"	    },
	{	10058,	"NFS4ERR_LAYOUTTRYLATER"	    },
	{	10059,	"NFS4ERR_LAYOUTUNAVAILABLE"	    },
	{	10060,	"NFS4ERR_NOMATCHING_LAYOUT"	    },
	{	10061,	"NFS4ERR_RECALLCONFLICT"	    },
	{	10062,	"NFS4ERR_UNKNOWN_LAYOUTTYPE"	    },
	{	10063,	"NFS4ERR_SEQ_MISORDERED"	    },
	{	10064,	"NFS4ERR_SEQUENCE_POS"		    },
	{	10065,	"NFS4ERR_REQ_TOO_BIG"		    },
	{	10066,	"NFS4ERR_REP_TOO_BIG"		    },
	{	10067,	"NFS4ERR_REP_TOO_BIG_TO_CACHE"	    },
	{	10068,	"NFS4ERR_RETRY_UNCACHED_REP"	    },
	{	10069,	"NFS4ERR_UNSAFE_COMPOUND"	    },
	{	10070,	"NFS4ERR_TOO_MANY_OPS"		    },
	{	10071,	"NFS4ERR_OP_NOT_IN_SESSION"	    },
	{	10072,	"NFS4ERR_HASH_ALG_UNSUPP"	    },
	{	10073,	"NFS4ERR_CONN_BINDING_NOT_ENFORCED" },
	{	10074,	"NFS4ERR_CLIENTID_BUSY"		    },
	{	10075,	"NFS4ERR_PNFS_IO_HOLE"		    },
	{	10076,	"NFS4ERR_SEQ_FALSE_RETRY"	    },
	{	10077,	"NFS4ERR_BAD_HIGH_SLOT"		    },
	{	10078,	"NFS4ERR_DEADSESSION"		    },
	{	10079,	"NFS4ERR_ENCR_ALG_UNSUPP"	    },
	{	10080,	"NFS4ERR_PNFS_NO_LAYOUT"	    },
	{	10081,	"NFS4ERR_NOT_ONLY_OP"		    },
	{	10082,	"NFS4ERR_WRONG_CRED"		    },
	{	10083,	"NFS4ERR_WRONG_TYPE"		    },
	{	10084,	"NFS4ERR_DIRDELEG_UNAVAIL"	    },
	{	10085,	"NFS4ERR_REJECT_DELEG"		    },
	{	10086,	"NFS4ERR_RETURNCONFLICT"	    },
	{	10087,	"NFS4ERR_DELEG_REVOKED"		    },
	{	0,	NULL }
};
static value_string_ext names_nfs4_status_ext = VALUE_STRING_EXT_INIT(names_nfs4_status);

static int
dissect_nfs4_status(tvbuff_t *tvb, int offset, proto_tree *tree, guint32 *status)
{
	guint32	    stat;
	proto_item *stat_item;

	stat = tvb_get_ntohl(tvb, offset+0);

	proto_tree_add_uint(tree, hf_nfs4_status, tvb, offset+0, 4, stat);
	stat_item = proto_tree_add_uint(tree, hf_nfs_status, tvb, offset+0, 4, stat);
	PROTO_ITEM_SET_HIDDEN(stat_item);

	if (status)
		*status = stat;

	return offset + 4;
}


static int
dissect_nfs_utf8string(tvbuff_t *tvb, int offset,
		       proto_tree *tree, int hf, const char **string_ret)
{
	/* TODO: this dissector is subject to change; do not remove */
	return dissect_rpc_string(tvb, tree, hf, offset, string_ret);
}


static int
dissect_nfs4_deviceid(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_nfs4_deviceid, tvb, offset, 16, ENC_NA);
	offset += 16;
	return offset;
}


static int
dissect_nfs4_sessionid(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_nfs4_sessionid, tvb, offset, 16, ENC_NA);
	offset += 16;
	return offset;
}


static int
dissect_nfs4_specdata(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_specdata1, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_specdata2, offset);
	return offset;
}

static const value_string names_ftype4[] = {
	{	NF4REG,		"NF4REG"	},
	{	NF4DIR,		"NF4DIR"	},
	{	NF4BLK,		"NF4BLK"	},
	{	NF4CHR,		"NF4CHR"	},
	{	NF4LNK,		"NF4LNK"	},
	{	NF4SOCK,	"NF4SOCK"	},
	{	NF4FIFO,	"NF4FIFO"	},
	{	NF4ATTRDIR,	"NF4ATTRDIR"	},
	{	NF4NAMEDATTR,	"NF4NAMEDATTR"	},
	{	0,	NULL }
};


static int
dissect_nfs4_lock_owner(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_tree *newftree;
	proto_item *fitem;

	fitem = proto_tree_add_text(tree, tvb, offset, 4, "Owner");
	newftree = proto_item_add_subtree(fitem, ett_nfs4_lock_owner);
	offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_clientid, offset);
	offset = dissect_nfsdata(tvb, offset, newftree, hf_nfs_data);

	return offset;
}


static int
dissect_nfs4_pathname(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint32	    comp_count, i;
	proto_item *fitem;
	proto_tree *newftree;

	comp_count = tvb_get_ntohl(tvb, offset);
	fitem = proto_tree_add_text(tree, tvb, offset, 4,
		"pathname components (%u)", comp_count);
	offset += 4;

	newftree = proto_item_add_subtree(fitem, ett_nfs4_pathname);

	for (i = 0; i < comp_count; i++)
		offset = dissect_nfs_utf8string(tvb, offset, newftree, hf_nfs4_component, NULL);
	return offset;
}


static int
dissect_nfs4_nfstime(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	offset = dissect_rpc_uint64(tvb, tree, hf_nfs4_time_seconds, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_time_nseconds, offset);

	return offset;
}


static const value_string names_time_how4[] = {
#define SET_TO_SERVER_TIME4 0
	{	SET_TO_SERVER_TIME4,	"SET_TO_SERVER_TIME4"	},
#define SET_TO_CLIENT_TIME4 1
	{	SET_TO_CLIENT_TIME4,	"SET_TO_CLIENT_TIME4"	},
	{	0,	NULL	}
};

static int
dissect_nfs4_settime(tvbuff_t *tvb, int offset,
		     proto_tree *tree, const char *name _U_)
{
	guint32 set_it;

	set_it = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint(tree, hf_nfs4_time_how, tvb, offset+0, 4, set_it);
	offset += 4;

	if (set_it == SET_TO_CLIENT_TIME4)
		offset = dissect_nfs4_nfstime(tvb, offset, tree);

	return offset;
}


static int
dissect_nfs4_fsid(tvbuff_t *tvb, int offset, proto_tree *tree, const char *name)
{
	proto_tree *newftree;
	proto_item *fitem;

	fitem = proto_tree_add_text(tree, tvb, offset, 0, "%s", name);
	newftree = proto_item_add_subtree(fitem, ett_nfs4_fsid);
	offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_fsid_major, offset);
	offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_fsid_minor, offset);
	return offset;
}

/* ACE type values  */
static const value_string names_acetype4[] = {
#define ACE4_TYPE_ACCESS_ALLOWED  0x00000000
	{	ACE4_TYPE_ACCESS_ALLOWED, "Access_Allowed"  },
#define ACE4_TYPE_ACCESS_DENIED   0x00000001
	{	ACE4_TYPE_ACCESS_DENIED,  "access_denied" },
#define ACE4_TYPE_SYSTEM_AUDIT    0x00000002
	{	ACE4_TYPE_SYSTEM_AUDIT,   "system_audit" },
#define ACE4_TYPE_SYSTEM_ALARM    0x00000003
	{	ACE4_TYPE_SYSTEM_ALARM,   "system_alarm" },
	{	0,	NULL }
};

/* ACE flag values */
static const value_string aceflag_names4[] = {
#define ACE4_FLAG_FILE_INHERIT             0x00000001
	{	ACE4_FLAG_FILE_INHERIT,            "File_Inherit"  },
#define ACE4_FLAG_DIRECTORY_INHERIT        0x00000002
	{	ACE4_FLAG_DIRECTORY_INHERIT,       "Directory_Inherit"  },
#define ACE4_FLAG_NO_PROPAGATE_INHERIT     0x00000004
	{	ACE4_FLAG_NO_PROPAGATE_INHERIT,    "No_Propagate_Inherit"  },
#define ACE4_FLAG_INHERIT_ONLY             0x00000008
	{	ACE4_FLAG_INHERIT_ONLY,            "Inherit_Only"  },
#define ACE4_FLAG_SUCCESSFUL_ACCESS        0x00000010
	{	ACE4_FLAG_SUCCESSFUL_ACCESS,       "Successful_Access"  },
#define ACE4_FLAG_FAILED_ACCESS            0x00000020
	{	ACE4_FLAG_FAILED_ACCESS,           "Failed_access"  },
#define ACE4_FLAG_IDENTIFIER_GROUP         0x00000040
	{	ACE4_FLAG_IDENTIFIER_GROUP,        "Identifier_Group"  },
#define ACE4_FLAG_INHERITED_ACE            0x00000080
	{	ACE4_FLAG_INHERITED_ACE,           "Inherited_ACE"  },
	{	0,	NULL }
};

static int
dissect_nfs_aceflags4(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *ace_tree)
{
	guint32	    aceflags   = tvb_get_ntohl(tvb, offset);
	guint32	    flag_bit   = 1;
	gboolean    first_flag = TRUE;
	proto_item *aceflag_item;
	proto_tree *aceflag_tree;

	aceflag_item = proto_tree_add_uint(ace_tree, hf_nfs4_aceflags, tvb, offset, 4, aceflags);	proto_item_append_text(aceflag_item, "  (");
	aceflag_tree = proto_item_add_subtree(aceflag_item, ett_nfs4_aceflag);

	while (flag_bit && flag_bit <= aceflags) {
		if (flag_bit & aceflags) {
			proto_tree_add_uint(aceflag_tree, hf_nfs4_aceflag, tvb, offset, 4, flag_bit);
			proto_item_append_text(aceflag_item,
				first_flag ? "%s" : ", %s",
				val_to_str(flag_bit, aceflag_names4, "Unknown: %u"));
			first_flag = FALSE;
		}
		flag_bit <<= 1;
	}
	proto_item_append_text(aceflag_item, ")");
	return offset += 4;
}


/* ACE4 permissions for files */
static const value_string  acemask4_perms_file[] = {
#define ACE4_READ_DATA             0x00000001
	{	ACE4_READ_DATA,            "Read_Data"  },
#define ACE4_WRITE_DATA            0x00000002
	{	ACE4_WRITE_DATA,           "Write_Data" },
#define ACE4_APPEND_DATA           0x00000004
	{	ACE4_APPEND_DATA,          "Append_Data"  },
	{	0, NULL }
};
/* Abbreviated ACE4 permissions for files */
static const value_string  acemask4_abbrev_perms_file[] = {
	{	ACE4_READ_DATA,            "RdData"  },
	{	ACE4_WRITE_DATA,           "WrData" },
	{	ACE4_APPEND_DATA,          "AppData"  },
	{	0, NULL }
};

/* ACE4 permissions for dirs */
static const value_string  acemask4_perms_dir[] = {
#define ACE4_LIST_DIRECTORY        0x00000001
	{	ACE4_LIST_DIRECTORY,       "List_Dir" },
#define ACE4_ADD_FILE              0x00000002
	{	ACE4_ADD_FILE,             "Add_File" },
#define ACE4_ADD_SUBDIRECTORY      0x00000004
	{	ACE4_ADD_SUBDIRECTORY,     "Add_Subdir" },
	{	0, NULL }
};
/* Abbreviated ACE4 permissions for dirs */
static const value_string  acemask4_abbrev_perms_dir[] = {
	{	ACE4_LIST_DIRECTORY,       "LstDir" },
	{	ACE4_ADD_FILE,             "AddFile" },
	{	ACE4_ADD_SUBDIRECTORY,     "AddSubD" },
	{	0, NULL }
};

/* ACE4 permissions for objects of unknown type */
static const value_string  acemask4_perms_unkwn[] = {
	{	ACE4_READ_DATA,            "Read_Data / List_Dir" },
	{	ACE4_WRITE_DATA,           "Write_Data / Add_File" },
	{	ACE4_APPEND_DATA,          "Append_Data / Add_SubDir" },
	{	0, NULL }
};
/* Abbreviated ACE4 permissions for objects of unknown type */
static const value_string  acemask4_abbrev_perms_unkwn[] = {
	{	ACE4_READ_DATA,            "RdData/LstDir" },
	{	ACE4_WRITE_DATA,           "WrData/AddFile" },
	{	ACE4_APPEND_DATA,          "AppData/AddSubD" },
	{	0, NULL }
};

/* ACE4 permissions for object types 0x8 and above */
static const value_string  acemask4_perms_8_and_above[] = {
#define ACE4_READ_NAMED_ATTRS      0x00000008
	{	ACE4_READ_NAMED_ATTRS,     "Read_Named_Attrs" },
#define ACE4_WRITE_NAMED_ATTRS     0x00000010
	{	ACE4_WRITE_NAMED_ATTRS,    "Write_Named_Attrs" },
#define ACE4_EXECUTE               0x00000020
	{	ACE4_EXECUTE,              "Execute" },
#define ACE4_DELETE_CHILD          0x00000040
	{	ACE4_DELETE_CHILD,         "Delete_Child" },
#define ACE4_READ_ATTRIBUTES       0x00000080
	{	ACE4_READ_ATTRIBUTES,      "Read_Attributes" },
#define ACE4_WRITE_ATTRIBUTES      0x00000100
	{	ACE4_WRITE_ATTRIBUTES,     "Write_Attributes" },
#define ACE4_WRITE_RETENTION       0x00000200
	{	ACE4_WRITE_RETENTION,      "Write_Retention" },
#define ACE4_WRITE_RETENTION_HOLD  0x00000400
	{	ACE4_WRITE_RETENTION_HOLD, "Write_Retention_Hold" },
#define ACE4_DELETE                0x00010000
	{	ACE4_DELETE,               "Delete" },
#define ACE4_READ_ACL              0x00020000
	{	ACE4_READ_ACL,             "Read_ACL" },
#define ACE4_WRITE_ACL             0x00040000
	{	ACE4_WRITE_ACL,            "Write_ACL" },
#define ACE4_WRITE_OWNER           0x00080000
	{	ACE4_WRITE_OWNER,          "Write_Owner" },
#define ACE4_SYNCHRONIZE           0x00100000
	{	ACE4_SYNCHRONIZE,          "Synchronize" },
	{	0, NULL }
};
static value_string_ext acemask4_perms_8_and_above_ext = VALUE_STRING_EXT_INIT(acemask4_perms_8_and_above);

/* Abbreviated ACE4 permissions for object types 0x8 and above */
static const value_string  acemask4_abbrev_perms_8_and_above[] = {
	{	ACE4_READ_NAMED_ATTRS,     "RdNamAt" },
	{	ACE4_WRITE_NAMED_ATTRS,    "WrNamAt" },
	{	ACE4_EXECUTE,              "Exec" },
	{	ACE4_DELETE_CHILD,         "DelChld" },
	{	ACE4_READ_ATTRIBUTES,      "RdAttrs" },
	{	ACE4_WRITE_ATTRIBUTES,     "WrAttrs" },
	{	ACE4_WRITE_RETENTION,      "WrRet" },
	{	ACE4_WRITE_RETENTION_HOLD, "WrRetHld" },
	{	ACE4_DELETE,               "Del" },
	{	ACE4_READ_ACL,             "RdACL" },
	{	ACE4_WRITE_ACL,            "WrACL" },
	{	ACE4_WRITE_OWNER,          "WrOwn" },
	{	ACE4_SYNCHRONIZE,          "Sync" },
	{	0, NULL }
};
static value_string_ext acemask4_abbrev_perms_8_and_above_ext = VALUE_STRING_EXT_INIT(acemask4_abbrev_perms_8_and_above);

static int
dissect_nfs4_acemask(tvbuff_t *tvb, int offset, proto_tree *ace_tree, guint32 acetype4, guint32 obj_type)
{
	const gchar *type	 = NULL;
	const gchar *atype	 = NULL;
	guint32	     acemask	 = tvb_get_ntohl(tvb, offset);
	guint32	     acemask_bit = 1;
	gboolean     first_perm	 = TRUE;
	proto_item  *acemask_item;
	proto_tree  *acemask_tree;

	acemask_item = proto_tree_add_uint(ace_tree, hf_nfs4_acemask, tvb, offset, 4, acemask);
	acemask_tree = proto_item_add_subtree(acemask_item, ett_nfs4_acemask);
	proto_item_append_text(acemask_item, "  (");

	while (acemask_bit <= ACE4_SYNCHRONIZE)
	{
		if (acemask_bit & acemask) {
			if (acemask_bit <= 0x4) {
				if (obj_type) {
					if  (obj_type == NF4REG) {
						type = val_to_str(acemask_bit, acemask4_perms_file, "Unknown: %u");
						atype = val_to_str(acemask_bit, acemask4_abbrev_perms_file, "Unknown: %u");
					} else if (obj_type == NF4DIR) {
						type = val_to_str(acemask_bit, acemask4_perms_dir, "Unknown: %u");
						atype = val_to_str(acemask_bit, acemask4_abbrev_perms_dir, "Unknown: %u");
					}
				} else {
					type = val_to_str(acemask_bit, acemask4_perms_unkwn, "Unknown: %u");
					atype = val_to_str(acemask_bit, acemask4_abbrev_perms_unkwn, "Unknown: %u");
				}
			} else {
				type = val_to_str_ext(acemask_bit, &acemask4_perms_8_and_above_ext, "Unknown: %u");
				atype = val_to_str_ext(acemask_bit, &acemask4_abbrev_perms_8_and_above_ext, "Unknown: %u");
			}
			proto_tree_add_uint_format(acemask_tree, hf_nfs4_ace_permission, tvb, offset, 4,
				acemask_bit, "%s: %s (0x%08x)", val_to_str(acetype4, names_acetype4, "Unknown: %u"), type, acemask_bit);
			proto_item_append_text(acemask_item, first_perm ? "%s" : ", %s", atype);
			first_perm = FALSE;
		}
		acemask_bit <<= 1;
	}
	proto_item_append_text(acemask_item, ")");

	return offset += 4;
}

/* Decode exactly one ACE (type, flags, mask, permissions, and who) */
static int
dissect_nfs4_ace(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,	proto_tree *tree, int ace_number,
				 guint32 obj_type)
{
	guint32	    acetype4 = 0;
	const char *acetype4_str;
	proto_tree *ace_tree = NULL;

	if (tree) {
		proto_item *ace_item = NULL;

		acetype4 = tvb_get_ntohl(tvb, offset);
		acetype4_str = val_to_str(acetype4, names_acetype4, "Unknown: %u");

		/* Display the ACE type and create a subtree for this ACE */
		if (ace_number == 0) {
			ace_item = proto_tree_add_uint_format(tree, hf_nfs4_acetype, tvb, offset, 4,
				acetype4, "ACE Type: %s (%u)", acetype4_str, acetype4);
		} else {
			ace_item = proto_tree_add_uint_format(tree, hf_nfs4_acetype, tvb, offset, 4,
				acetype4, "%u. ACE Type: %s (%u)", ace_number, acetype4_str, acetype4);
		}
		ace_tree = proto_item_add_subtree(ace_item, ett_nfs4_ace);
	}

	offset += 4;

	if (tree) {
		offset = dissect_nfs_aceflags4(tvb, offset, pinfo, ace_tree);
		offset = dissect_nfs4_acemask(tvb, offset, ace_tree, acetype4, obj_type);
	} else {
		offset += 8;
	}

	offset = dissect_nfs_utf8string(tvb, offset, ace_tree, hf_nfs4_who, NULL);

	return offset;
}


static int
dissect_nfs4_fattr_acl(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_item *attr_item,
		       proto_tree *tree, guint32 obj_type)
{
	guint32 num_aces;
	guint32 ace_number;

	if (tree) {
		proto_item *acl_item;
		acl_item = proto_tree_add_none_format(tree, hf_nfs4_acl, tvb, 0, 0, "ACL");
		PROTO_ITEM_SET_HIDDEN(acl_item);
	}

	num_aces = tvb_get_ntohl(tvb, offset);
	if (tree && num_aces > 0) {
		proto_tree_add_uint(tree, hf_nfs4_num_aces, tvb, offset, 4, num_aces);
		proto_item_append_text(attr_item, " (%u ACEs)", num_aces);
	}
	offset += 4;

	/* Tree or not, this for loop is required due dissect_nfs_utf8string() call */
	for (ace_number = 1; ace_number<=num_aces; ace_number++)
		offset = dissect_nfs4_ace(tvb, offset, pinfo, tree, ace_number, obj_type);

	return offset;
}

static int
dissect_nfs4_fh(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, const char *name, guint32 *hash, rpc_call_info_value *civ)
{
	return dissect_nfs3_fh(tvb, offset, pinfo, tree, name, hash, civ);
}


static int
dissect_nfs4_server(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
	return dissect_nfs_utf8string(tvb, offset, tree, hf_nfs4_server, NULL);
}


static int
dissect_nfs4_fs_location(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			 proto_tree *tree, void *data _U_)
{
	proto_tree *newftree;
	proto_item *fitem;

	fitem = proto_tree_add_text(tree, tvb, offset, 0, "fs_location4");

	newftree = proto_item_add_subtree(fitem, ett_nfs4_fs_location);

	offset = dissect_rpc_array(tvb, pinfo, newftree, offset, dissect_nfs4_server, hf_nfs4_server);
	offset = dissect_nfs4_pathname(tvb, offset, newftree);

	return offset;
}


static int
dissect_nfs4_fs_locations(tvbuff_t *tvb, packet_info *pinfo, int offset,
			  proto_tree *tree, const char *name)
{
	proto_tree *newftree;
	proto_item *fitem;

	fitem = proto_tree_add_text(tree, tvb, offset, 0, "%s", name);
	newftree = proto_item_add_subtree(fitem, ett_nfs4_fs_locations);

	offset = dissect_nfs4_pathname(tvb, offset, newftree);

	offset = dissect_rpc_array(tvb, pinfo, newftree, offset,
		dissect_nfs4_fs_location, hf_nfs4_fslocation);

	return offset;
}


static int
dissect_nfs4_mode(tvbuff_t *tvb, int offset,
		  proto_tree *tree, const char *name)
{
	return dissect_nfs2_mode(tvb, offset, tree, name);
}


static const value_string nfs4_fattr4_fh_expire_type_names[] = {
#define FH4_PERSISTENT 0x00000000
	{	FH4_PERSISTENT,	"FH4_PERSISTENT"	},
#define FH4_NOEXPIRE_WITH_OPEN 0x00000001
	{	FH4_NOEXPIRE_WITH_OPEN,	"FH4_NOEXPIRE_WITH_OPEN"	},
#define FH4_VOLATILE_ANY 0x00000002
	{	FH4_VOLATILE_ANY,	"FH4_VOLATILE_ANY"	},
#define FH4_VOL_MIGRATION 0x00000004
	{	FH4_VOL_MIGRATION,	"FH4_VOL_MIGRATION"	},
#define FH4_VOL_RENAME 0x00000008
	{	FH4_VOL_RENAME,	"FH4_VOL_RENAME"	},
	{	0,	NULL	}
};


static int
dissect_nfs4_fattr_fh_expire_type(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint32	    expire_type;
	proto_tree *expire_type_tree = NULL;

	expire_type = tvb_get_ntohl(tvb, offset + 0);

	if (tree)
	{
		proto_item *expire_type_item;
		expire_type_item = proto_tree_add_text(tree, tvb, offset, 4,
			"fattr4_fh_expire_type: 0x%08x", expire_type);

		expire_type_tree = proto_item_add_subtree(expire_type_item,
				ett_nfs4_fattr_fh_expire_type);
	}

	if (expire_type_tree)
	{
		if (expire_type == FH4_PERSISTENT)
		{
			char *p, *buf;

			/* TODO: this should be replaced with a named field and
			 * proto_tree_add_item */
			buf = (char *)wmem_alloc(wmem_packet_scope(), 1025);
			p = decode_bitfield_value(buf, expire_type, 0xFFFFFFFF, 32);
			g_snprintf(p, (gulong) (1024-(p-buf)), "%s",
				val_to_str_const(expire_type,
					nfs4_fattr4_fh_expire_type_names,
					"Unknown"));
			proto_tree_add_text(expire_type_tree, tvb, offset, 4, "%s", buf);
		}
		else
		{
			if (expire_type & FH4_NOEXPIRE_WITH_OPEN)
				proto_tree_add_text(expire_type_tree, tvb, offset, 4,
						"FH4_NOEXPIRE_WITH_OPEN (0x%08x)", FH4_NOEXPIRE_WITH_OPEN);

			if (expire_type & FH4_VOLATILE_ANY)
				proto_tree_add_text(expire_type_tree, tvb, offset, 4,
						"FH4_VOLATILE_ANY (0x%08x)", FH4_VOLATILE_ANY);

			if (expire_type & FH4_VOL_MIGRATION)
				proto_tree_add_text(expire_type_tree, tvb, offset, 4,
						"FH4_VOL_MIGRATION (0x%08x)", FH4_VOL_MIGRATION);

			if (expire_type & FH4_VOL_RENAME)
				proto_tree_add_text(expire_type_tree, tvb, offset, 4,
						"FH4_VOL_RENAME (0x%08x)", FH4_VOL_RENAME);
		}
	}

	offset += 4;

	return offset;
}


static int
dissect_nfs_fs_layout_type(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	guint count, i;

	count = tvb_get_ntohl(tvb, offset);
	offset +=4;

	for (i = 0; i < count; i++)
		offset += dissect_rpc_uint32(tvb, tree, hf_nfs4_layout_type, offset);

	return offset;
}


static int
dissect_nfs4_security_label(tvbuff_t *tvb, proto_tree *tree, int offset)
{

	offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_fattr_security_label_lfs, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_fattr_security_label_pi, offset);
	offset = dissect_nfs_utf8string(tvb, offset, tree,
		hf_nfs4_fattr_security_label_context, NULL);

	return offset;
}

static const value_string fattr4_names[] = {
#define FATTR4_SUPPORTED_ATTRS     0
	{	FATTR4_SUPPORTED_ATTRS,    "Supported_Attrs"	},
#define FATTR4_TYPE                1
	{	FATTR4_TYPE,               "Type"},
#define FATTR4_FH_EXPIRE_TYPE      2
	{	FATTR4_FH_EXPIRE_TYPE,     "FH_Expire_Type"	},
#define FATTR4_CHANGE              3
	{	FATTR4_CHANGE,             "Change"},
#define FATTR4_SIZE                4
	{	FATTR4_SIZE,	           "Size"	},
#define FATTR4_LINK_SUPPORT        5
	{	FATTR4_LINK_SUPPORT,       "Link_Support"	},
#define FATTR4_SYMLINK_SUPPORT     6
	{	FATTR4_SYMLINK_SUPPORT,    "Symlink_Support"	},
#define FATTR4_NAMED_ATTR          7
	{	FATTR4_NAMED_ATTR,         "Named_Attr"	},
#define FATTR4_FSID                8
	{	FATTR4_FSID,               "FSID"	},
#define FATTR4_UNIQUE_HANDLES      9
	{	FATTR4_UNIQUE_HANDLES,     "Unique_Handles"	},
#define FATTR4_LEASE_TIME          10
	{	FATTR4_LEASE_TIME,         "Lease_Time"	},
#define FATTR4_RDATTR_ERROR        11
	{	FATTR4_RDATTR_ERROR,       "RDAttr_Error"	},
#define FATTR4_ACL                 12
	{	FATTR4_ACL,                "ACL"	},
#define FATTR4_ACLSUPPORT          13
	{	FATTR4_ACLSUPPORT,         "ACLSupport"	},
#define FATTR4_ARCHIVE             14
	{	FATTR4_ARCHIVE,            "Archive"	},
#define FATTR4_CANSETTIME          15
	{	FATTR4_CANSETTIME,         "CanSetTime"	},
#define FATTR4_CASE_INSENSITIVE    16
	{	FATTR4_CASE_INSENSITIVE,   "Case_Insensitive"	},
#define FATTR4_CASE_PRESERVING     17
	{	FATTR4_CASE_PRESERVING,    "Case_Preserving"	},
#define FATTR4_CHOWN_RESTRICTED    18
	{	FATTR4_CHOWN_RESTRICTED,   "Chown_Restricted"	},
#define FATTR4_FILEHANDLE          19
	{	FATTR4_FILEHANDLE,         "Filehandle"	},
#define FATTR4_FILEID              20
	{	FATTR4_FILEID,             "FileId"	},
#define FATTR4_FILES_AVAIL         21
	{	FATTR4_FILES_AVAIL,        "Files_Avail"	},
#define FATTR4_FILES_FREE          22
	{	FATTR4_FILES_FREE,         "Files_Free"	},
#define FATTR4_FILES_TOTAL         23
	{	FATTR4_FILES_TOTAL,        "Files_Total"	},
#define FATTR4_FS_LOCATIONS        24
	{	FATTR4_FS_LOCATIONS,       "FS_Locations"	},
#define FATTR4_HIDDEN              25
	{	FATTR4_HIDDEN,             "Hidden"	},
#define FATTR4_HOMOGENEOUS         26
	{	FATTR4_HOMOGENEOUS,        "Homogeneous"	},
#define FATTR4_MAXFILESIZE         27
	{	FATTR4_MAXFILESIZE,        "MaxFileSize"	},
#define FATTR4_MAXLINK             28
	{	FATTR4_MAXLINK,            "MaxLink"	},
#define FATTR4_MAXNAME             29
	{	FATTR4_MAXNAME,            "MaxName"	},
#define FATTR4_MAXREAD             30
	{	FATTR4_MAXREAD,            "MaxRead"	},
#define FATTR4_MAXWRITE            31
	{	FATTR4_MAXWRITE,           "MaxWrite"	},
#define FATTR4_MIMETYPE            32
	{	FATTR4_MIMETYPE,           "MimeType"	},
#define FATTR4_MODE                33
	{	FATTR4_MODE,               "Mode"	},
#define FATTR4_NO_TRUNC            34
	{	FATTR4_NO_TRUNC,           "No_Trunc"	},
#define FATTR4_NUMLINKS            35
	{	FATTR4_NUMLINKS,           "NumLinks"	},
#define FATTR4_OWNER               36
	{	FATTR4_OWNER,              "Owner"	},
#define FATTR4_OWNER_GROUP         37
	{	FATTR4_OWNER_GROUP,        "Owner_Group"	},
#define FATTR4_QUOTA_AVAIL_HARD    38
	{	FATTR4_QUOTA_AVAIL_HARD,   "Quota_Avail_Hard"	},
#define FATTR4_QUOTA_AVAIL_SOFT    39
	{	FATTR4_QUOTA_AVAIL_SOFT,   "Quota_Avail_Soft"	},
#define FATTR4_QUOTA_USED          40
	{	FATTR4_QUOTA_USED,         "Quota_Used"	},
#define FATTR4_RAWDEV              41
	{	FATTR4_RAWDEV,             "RawDev"	},
#define FATTR4_SPACE_AVAIL         42
	{	FATTR4_SPACE_AVAIL,        "Space_Avail"	},
#define FATTR4_SPACE_FREE          43
	{	FATTR4_SPACE_FREE,         "Space_Free"	},
#define FATTR4_SPACE_TOTAL         44
	{	FATTR4_SPACE_TOTAL,        "Space_Total"	},
#define FATTR4_SPACE_USED          45
	{	FATTR4_SPACE_USED,         "Space_Used"	},
#define FATTR4_SYSTEM              46
	{	FATTR4_SYSTEM,             "System"	},
#define FATTR4_TIME_ACCESS         47
	{	FATTR4_TIME_ACCESS,        "Time_Access"	},
#define FATTR4_TIME_ACCESS_SET     48
	{	FATTR4_TIME_ACCESS_SET,    "Time_Access_Set"	},
#define FATTR4_TIME_BACKUP         49
	{	FATTR4_TIME_BACKUP,        "Time_Backup"	},
#define FATTR4_TIME_CREATE         50
	{	FATTR4_TIME_CREATE,        "Time_Create"	},
#define FATTR4_TIME_DELTA          51
	{	FATTR4_TIME_DELTA,         "Time_Delta"	},
#define FATTR4_TIME_METADATA       52
	{	FATTR4_TIME_METADATA,      "Time_Metadata"	},
#define FATTR4_TIME_MODIFY         53
	{	FATTR4_TIME_MODIFY,        "Time_Modify"	},
#define FATTR4_TIME_MODIFY_SET     54
	{	FATTR4_TIME_MODIFY_SET,    "Time_Modify_Set"	},
#define FATTR4_MOUNTED_ON_FILEID   55
	{	FATTR4_MOUNTED_ON_FILEID,  "Mounted_on_FileId"	},
#define FATTR4_DIR_NOTIF_DELAY     56
	{	FATTR4_DIR_NOTIF_DELAY,    "Dir_Notif_Delay"	},
#define FATTR4_DIRENT_NOTIF_DELAY  57
#define FATTR4_DACL                58
	{	FATTR4_DACL,               "DACL"                },
#define FATTR4_SACL                59
	{	FATTR4_SACL,               "SACL"                },
#define FATTR4_CHANGE_POLICY       60
	{	FATTR4_CHANGE_POLICY,      "Change_Policy"		},
#define FATTR4_FS_STATUS           61
	{	FATTR4_FS_STATUS,          "FS_Status"			},
#define FATTR4_FS_LAYOUT_TYPE      62
	{	FATTR4_FS_LAYOUT_TYPE,     "FS_Layout_Type"		},
#define FATTR4_LAYOUT_HINT         63
	{	FATTR4_LAYOUT_HINT,        "Layout_hint"		},
#define FATTR4_LAYOUT_TYPE         64
	{	FATTR4_LAYOUT_TYPE,        "Layout_type"		},
#define FATTR4_LAYOUT_BLKSIZE      65
	{	FATTR4_LAYOUT_BLKSIZE,     "Layout_blksize"		},
#define FATTR4_LAYOUT_ALIGNMENT    66
	{	FATTR4_LAYOUT_ALIGNMENT,   "Layout_alignment"	},
#define FATTR4_FS_LOCATIONS_INFO   67
	{	FATTR4_FS_LOCATIONS_INFO,  "FS_Locations_info"	},
#define FATTR4_MDSTHRESHOLD        68
	{	FATTR4_MDSTHRESHOLD,       "MDS_Threshold"		},
#define FATTR4_RETENTION_GET       69
	{	FATTR4_RETENTION_GET,      "Retention_Get"		},
#define FATTR4_RETENTION_SET       70
	{	FATTR4_RETENTION_SET,      "Retention_Set"		},
#define FATTR4_RETENTEVT_GET       71
	{	FATTR4_RETENTEVT_GET,      "RetentEvt_Get"		},
#define FATTR4_RETENTEVT_SET       72
	{	FATTR4_RETENTEVT_SET,      "RetentEvt_Set"		},
#define FATTR4_RETENTION_HOLD      73
	{	FATTR4_RETENTION_HOLD,     "Retention_Hold"		},
#define FATTR4_MODE_SET_MASKED     74
	{	FATTR4_MODE_SET_MASKED,    "Mode_Set_Masked"	},
#define FATTR4_SUPPATTR_EXCLCREAT  75
	{	FATTR4_SUPPATTR_EXCLCREAT, "Suppattr_ExclCreat"	},
#define FATTR4_FS_CHARSET_CAP      76
	{	FATTR4_FS_CHARSET_CAP,     "FS_Charset_Cap"		},
#define FATTR4_SECURITY_LABEL      80
	{	FATTR4_SECURITY_LABEL,     "Security_Label"		},
	{	0,	NULL	}
};
static value_string_ext fattr4_names_ext = VALUE_STRING_EXT_INIT(fattr4_names);

#define FATTR4_BITMAP_ONLY 0
#define FATTR4_DISSECT_VALUES 1

/* As of NFSv4.1 (RFC 5661) The maximum number of attribute bitmaps is 3 in that NFSv4.1 introduced
*  attribute numbers in excess of 63 (e.g., FATTR4_FS_CHARSET_CAP = 76):
 *
 *                      1          2          3
 *  +-------------+----------+----------+----------+
 *  | num_bitmaps | 31 .. 0  | 63 .. 32 | 95 .. 64 |
 *  +-------------+----------+----------+----------+
 */
#define MAX_BITMAPS 3

/* Display each attrmask bitmap and optionally dissect the value.
*/
static int
dissect_nfs4_fattrs(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int type, rpc_call_info_value *civ)
{
	int	  attr_mask_offset = 0;
	guint8	  i, j;
	guint8	  num_bitmaps;
	guint8	  count		   = 0;
	guint32	  attr_num;
	guint32	 *bitmaps	   = NULL;
	guint32	  bitmap, sl;
	guint32	  obj_type	   = 0;
	gboolean  first_attr	   = TRUE;
	gboolean  no_idx	   = FALSE;

	proto_item *bitmap_item = NULL;
	proto_tree *bitmap_tree = NULL;
	proto_item *hitem	= NULL;
	proto_item *attr_item	= NULL;
	proto_tree *attr_tree	= NULL;

	num_bitmaps = tvb_get_ntohl(tvb, offset);
	offset += 4;

	if (num_bitmaps > MAX_BITMAPS) {
		if (tree)
			proto_tree_add_text(tree, tvb, offset, 4, "Huge bitmap length: %u", num_bitmaps);
		THROW(ReportedBoundsError);
	}
	tvb_ensure_bytes_exist(tvb, offset, num_bitmaps * 4);

	if (num_bitmaps) {
		bitmaps = (guint32 *)wmem_alloc(wmem_packet_scope(), num_bitmaps * sizeof(guint32));
		attr_mask_offset = offset;

		/* Load the array with the bitmap(s) */
		for (i = 0; i < num_bitmaps; i++) {
			bitmaps[i] = tvb_get_ntohl(tvb, attr_mask_offset + (i*4));
			if (bitmaps[i] > 0)
				count++;
		}
		/* If there is only one non-zero bitmap, don't display the bitmap index "[x]". */
		if (count <= 1)
			no_idx = TRUE;

		/* If FATTR4_DISSECT_VALUES, set offset to the first value field by skipping the
		*  attr_bitmap fields and the 4-byte 'total bytes in the values section field';
		*  otherwise, just skip the bitmaps and offset will be returned. */
		offset += (num_bitmaps * 4) + (type == FATTR4_DISSECT_VALUES ? 4 : 0);
	}

	if (!tree
	&& type == FATTR4_BITMAP_ONLY)
		return offset;

	for (i = 0; i < num_bitmaps; i++)
	{
		bitmap = bitmaps[i];

		if (bitmap) {
			if (tree) {
				/*
				* Display the current Attr_mask bitmap (as of RFC 5661 NVSv4.1, there are up to 3) */
				if (no_idx)
					bitmap_item = proto_tree_add_uint_format_value(tree, hf_nfs4_attr_mask, tvb,
						attr_mask_offset, 4, bitmap, "0x%08x", bitmap);
				else
					bitmap_item = proto_tree_add_uint_format(tree, hf_nfs4_attr_mask, tvb,
						attr_mask_offset, 4, bitmap, "Attr mask[%u]: 0x%08x", i, bitmap);

				bitmap_tree = proto_item_add_subtree(bitmap_item, ett_nfs4_bitmap);
				first_attr = TRUE;

				/* Count the number of attribute bits set */
				for (count=0; bitmap; bitmap >>= 1)
					count += (bitmap & 1);
				bitmap = bitmaps[i];
				hitem = proto_tree_add_text(bitmap_tree, tvb, attr_mask_offset, 4, "[%u attribute%s]", count,
					plurality(count, "", "s"));
				PROTO_ITEM_SET_HIDDEN(hitem);
			}
		} else {
			attr_mask_offset += 4;
			continue;
		}

		sl = 0x00000001;

		for (j = 0; j < 32; j++) {
			attr_num = 32*i + j;

			if (bitmap & sl) {
				if (bitmap_tree) {
					/*
					* Append this attribute name to the 'Attr mask' header line */
					proto_item_append_text (bitmap_tree, (first_attr ? " (%s" : ", %s"),
						val_to_str_ext(attr_num, &fattr4_names_ext, "Unknown: %u"));
					first_attr = FALSE;

					/* Display label: reqd_attr: or reco_attr: */
					attr_item = proto_tree_add_uint(bitmap_tree,
						((attr_num <= 11 || attr_num == 19 || attr_num == 75) ? hf_nfs4_reqd_attr: hf_nfs4_reco_attr),
						tvb, attr_mask_offset, 4, attr_num);
				}
				if (type == FATTR4_DISSECT_VALUES)
				{
					/* Decode the value of this attribute */
					if (attr_item)
						attr_tree = proto_item_add_subtree(attr_item, ett_nfs4_bitmap);

					switch (attr_num)
					{
					case FATTR4_SUPPORTED_ATTRS:
						offset = dissect_nfs4_fattrs(tvb, offset, pinfo, attr_tree, FATTR4_BITMAP_ONLY, civ);
						break;

					case FATTR4_TYPE:
						obj_type = tvb_get_ntohl(tvb, offset);
						if (attr_tree)
							proto_tree_add_item(attr_tree, hf_nfs4_ftype, tvb, offset, 4,
								ENC_BIG_ENDIAN);
						offset += 4;
						break;

					case FATTR4_FH_EXPIRE_TYPE:
						offset = dissect_nfs4_fattr_fh_expire_type(tvb,	offset, attr_tree);
						break;

					case FATTR4_CHANGE:
						offset = dissect_rpc_uint64(tvb, attr_tree,	hf_nfs4_changeid, offset);
						break;

					case FATTR4_SIZE:
						offset = dissect_rpc_uint64(tvb, attr_tree, hf_nfs4_fattr_size, offset);
						break;

					case FATTR4_LINK_SUPPORT:
						offset = dissect_rpc_bool(tvb,
							attr_tree, hf_nfs4_fattr_link_support, offset);
						break;

					case FATTR4_SYMLINK_SUPPORT:
						offset = dissect_rpc_bool(tvb, attr_tree, hf_nfs4_fattr_symlink_support, offset);
						break;

					case FATTR4_NAMED_ATTR:
						offset = dissect_rpc_bool(tvb, attr_tree, hf_nfs4_fattr_named_attr, offset);
						break;

					case FATTR4_FSID:
						offset = dissect_nfs4_fsid(tvb, offset,	attr_tree, "fattr4_fsid");
						break;

					case FATTR4_UNIQUE_HANDLES:
						offset = dissect_rpc_bool(tvb, attr_tree, hf_nfs4_fattr_unique_handles,	offset);
						break;

					case FATTR4_LEASE_TIME:
						offset = dissect_rpc_uint32(tvb, attr_tree, hf_nfs4_fattr_lease_time, offset);
						break;

					case FATTR4_RDATTR_ERROR:
						offset = dissect_nfs4_status(tvb, offset, attr_tree, NULL);
						break;

					case FATTR4_ACL:
						offset = dissect_nfs4_fattr_acl(tvb, offset, pinfo, attr_item, attr_tree,
							obj_type);
						break;

					case FATTR4_ACLSUPPORT:
						offset = dissect_rpc_uint32(tvb, attr_tree, hf_nfs4_fattr_aclsupport, offset);
						break;

					case FATTR4_ARCHIVE:
						offset = dissect_rpc_bool(tvb, attr_tree, hf_nfs4_fattr_archive, offset);
						break;

					case FATTR4_CANSETTIME:
						offset = dissect_rpc_bool(tvb, attr_tree, hf_nfs4_fattr_cansettime, offset);
						break;

					case FATTR4_CASE_INSENSITIVE:
						offset = dissect_rpc_bool(tvb, attr_tree, hf_nfs4_fattr_case_insensitive, offset);
						break;

					case FATTR4_CASE_PRESERVING:
						offset = dissect_rpc_bool(tvb, attr_tree, hf_nfs4_fattr_case_preserving, offset);
						break;

					case FATTR4_CHOWN_RESTRICTED:
						offset = dissect_rpc_bool(tvb, attr_tree, hf_nfs4_fattr_chown_restricted, offset);
						break;

					case FATTR4_FILEID:
						offset = dissect_rpc_uint64(tvb, attr_tree, hf_nfs4_fattr_fileid, offset);
						break;

					case FATTR4_FILES_AVAIL:
						offset = dissect_rpc_uint64(tvb, attr_tree, hf_nfs4_fattr_files_avail, offset);
						break;

					case FATTR4_FILEHANDLE:
						offset = dissect_nfs4_fh(tvb, offset, pinfo, attr_tree, "fattr4_filehandle", NULL, civ);
						break;

					case FATTR4_FILES_FREE:
						offset = dissect_rpc_uint64(tvb, attr_tree, hf_nfs4_fattr_files_free, offset);
						break;

					case FATTR4_FILES_TOTAL:
						offset = dissect_rpc_uint64(tvb, attr_tree, hf_nfs4_fattr_files_total, offset);
						break;

					case FATTR4_FS_LOCATIONS:
						offset = dissect_nfs4_fs_locations(tvb, pinfo, offset, attr_tree,
							"fattr4_fs_locations");
						break;

					case FATTR4_HIDDEN:
						offset = dissect_rpc_bool(tvb, attr_tree, hf_nfs4_fattr_hidden, offset);
						break;

					case FATTR4_HOMOGENEOUS:
						offset = dissect_rpc_bool(tvb, attr_tree, hf_nfs4_fattr_homogeneous, offset);
						break;

					case FATTR4_MAXFILESIZE:
						offset = dissect_rpc_uint64(tvb, attr_tree, hf_nfs4_fattr_maxfilesize, offset);
						break;

					case FATTR4_MAXLINK:
						offset = dissect_rpc_uint32(tvb, attr_tree, hf_nfs4_fattr_maxlink, offset);
						break;

					case FATTR4_MAXNAME:
						offset = dissect_rpc_uint32(tvb, attr_tree, hf_nfs4_fattr_maxname, offset);
						break;

					case FATTR4_MAXREAD:
						offset = dissect_rpc_uint64(tvb, attr_tree, hf_nfs4_fattr_maxread, offset);
						break;

					case FATTR4_MAXWRITE:
						offset = dissect_rpc_uint64(tvb, attr_tree, hf_nfs4_fattr_maxwrite, offset);
						break;

					case FATTR4_MIMETYPE:
						offset = dissect_nfs_utf8string(tvb, offset, attr_tree,	hf_nfs4_fattr_mimetype,
							NULL);
						break;

					case FATTR4_MODE:
						offset = dissect_nfs4_mode(tvb,	offset, attr_tree, "fattr4_mode");
						break;

					case FATTR4_NO_TRUNC:
						offset = dissect_rpc_bool(tvb, attr_tree, hf_nfs4_fattr_no_trunc, offset);
						break;

					case FATTR4_NUMLINKS:
						offset = dissect_rpc_uint32(tvb, attr_tree, hf_nfs4_fattr_numlinks, offset);
						break;

					case FATTR4_OWNER:
						offset = dissect_nfs_utf8string(tvb, offset, attr_tree,	hf_nfs4_fattr_owner,
							NULL);
						break;

					case FATTR4_OWNER_GROUP:
						offset = dissect_nfs_utf8string(tvb, offset, attr_tree,
							hf_nfs4_fattr_owner_group, NULL);
						break;

					case FATTR4_QUOTA_AVAIL_HARD:
						offset = dissect_rpc_uint64(tvb, attr_tree, hf_nfs4_fattr_quota_hard, offset);
						break;

					case FATTR4_QUOTA_AVAIL_SOFT:
						offset = dissect_rpc_uint64(tvb, attr_tree, hf_nfs4_fattr_quota_soft, offset);
						break;

					case FATTR4_QUOTA_USED:
						offset = dissect_rpc_uint64(tvb, attr_tree, hf_nfs4_fattr_quota_used, offset);
						break;

					case FATTR4_RAWDEV:
						offset = dissect_nfs4_specdata(tvb, offset, attr_tree);
						break;

					case FATTR4_SPACE_AVAIL:
						offset = dissect_rpc_uint64(tvb, attr_tree, hf_nfs4_fattr_space_avail, offset);
						break;

					case FATTR4_SPACE_FREE:
						offset = dissect_rpc_uint64(tvb, attr_tree, hf_nfs4_fattr_space_free, offset);
						break;

					case FATTR4_SPACE_TOTAL:
						offset = dissect_rpc_uint64(tvb, attr_tree, hf_nfs4_fattr_space_total, offset);
						break;

					case FATTR4_SPACE_USED:
						offset = dissect_rpc_uint64(tvb, attr_tree, hf_nfs4_fattr_space_used, offset);
						break;

					case FATTR4_SYSTEM:
						if (attr_tree)
							dissect_rpc_bool(tvb, attr_tree, hf_nfs4_fattr_system, offset);
						offset += 4;
						break;

					case FATTR4_TIME_ACCESS:
					case FATTR4_TIME_BACKUP:
					case FATTR4_TIME_CREATE:
					case FATTR4_TIME_DELTA:
					case FATTR4_TIME_METADATA:
					case FATTR4_TIME_MODIFY:
					case FATTR4_DIR_NOTIF_DELAY:
					case FATTR4_DIRENT_NOTIF_DELAY:
						if (attr_tree)
							dissect_nfs4_nfstime(tvb, offset, attr_tree);
						offset += 12;
						break;

					case FATTR4_TIME_ACCESS_SET:
					case FATTR4_TIME_MODIFY_SET:
						offset = dissect_nfs4_settime(tvb, offset, attr_tree, "settime4");
						break;

					case FATTR4_MOUNTED_ON_FILEID:
						offset = dissect_rpc_uint64(tvb, attr_tree, hf_nfs4_fattr_mounted_on_fileid,
									 offset);
						break;

					case FATTR4_FS_LAYOUT_TYPE:
						offset = dissect_nfs_fs_layout_type(tvb, attr_tree, offset);
						break;

					case FATTR4_LAYOUT_BLKSIZE:
						offset = dissect_rpc_uint32(tvb, attr_tree, hf_nfs4_fattr_layout_blksize,
									offset);
						break;

					case FATTR4_SECURITY_LABEL:
						offset = dissect_nfs4_security_label(tvb, attr_tree, offset);
						break;

					default:
						break;
					}
				}
			}
			sl <<= 1;
		} /* End of inner loop: test the next bit in this mask */

		if (bitmap_tree)
			proto_item_append_text(bitmap_tree, ")");
		attr_mask_offset += 4;
	} /* End of outer loop, read the next mask */

	return offset;
}

static const value_string names_open4_share_access[] = {
#define  OPEN4_SHARE_ACCESS_WANT_NO_PREFERENCE     0x0000
	{ OPEN4_SHARE_ACCESS_WANT_NO_PREFERENCE, "OPEN4_SHARE_ACCESS_WANT_NO_PREFERENCE" },
#define OPEN4_SHARE_ACCESS_READ 0x00000001
	{ OPEN4_SHARE_ACCESS_READ, "OPEN4_SHARE_ACCESS_READ" },
#define OPEN4_SHARE_ACCESS_WRITE 0x00000002
	{ OPEN4_SHARE_ACCESS_WRITE, "OPEN4_SHARE_ACCESS_WRITE" },
#define OPEN4_SHARE_ACCESS_BOTH 0x00000003
	{ OPEN4_SHARE_ACCESS_BOTH, "OPEN4_SHARE_ACCESS_BOTH" },
#define  OPEN4_SHARE_ACCESS_WANT_READ_DELEG        0x0100
	{ OPEN4_SHARE_ACCESS_WANT_READ_DELEG, "OPEN4_SHARE_ACCESS_WANT_READ_DELEG" },
#define  OPEN4_SHARE_ACCESS_WANT_WRITE_DELEG       0x0200
	{ OPEN4_SHARE_ACCESS_WANT_WRITE_DELEG, "OPEN4_SHARE_ACCESS_WANT_WRITE_DELEG" },
#define  OPEN4_SHARE_ACCESS_WANT_ANY_DELEG         0x0300
	{ OPEN4_SHARE_ACCESS_WANT_ANY_DELEG, "OPEN4_SHARE_ACCESS_WANT_ANY_DELEG" },
#define  OPEN4_SHARE_ACCESS_WANT_NO_DELEG          0x0400
	{ OPEN4_SHARE_ACCESS_WANT_NO_DELEG, "OPEN4_SHARE_ACCESS_WANT_NO_DELEG" },
#define  OPEN4_SHARE_ACCESS_WANT_CANCEL            0x0500
	{ OPEN4_SHARE_ACCESS_WANT_CANCEL, "OPEN4_SHARE_ACCESS_WANT_CANCEL" },
#define OPEN4_SHARE_ACCESS_WANT_SIGNAL_DELEG_WHEN_RESRC_AVAIL 0x10000
	{ OPEN4_SHARE_ACCESS_WANT_SIGNAL_DELEG_WHEN_RESRC_AVAIL,
	  "OPEN4_SHARE_ACCESS_WANT_SIGNAL_DELEG_WHEN_RESRC_AVAIL"},
#define OPEN4_SHARE_ACCESS_WANT_PUSH_DELEG_WHEN_UNCONTENDED  0x20000
	{ OPEN4_SHARE_ACCESS_WANT_PUSH_DELEG_WHEN_UNCONTENDED,
	 "OPEN4_SHARE_ACCESS_WANT_PUSH_DELEG_WHEN_UNCONTENDED"},
	{ 0, NULL }
};
static value_string_ext names_open4_share_access_ext = VALUE_STRING_EXT_INIT(names_open4_share_access);

static int
dissect_nfs4_open_share_access(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_item *notify_item;
	proto_tree *notify_tree;
	guint	    share_access;
	guint	    want_flags;
	guint	    want_notify_flags;

	want_notify_flags = tvb_get_ntohl(tvb, offset);
	share_access = want_notify_flags & 0x3;
	want_flags = want_notify_flags & 0xff00;
	want_notify_flags &= ~share_access & ~want_flags;
	proto_tree_add_uint(tree, hf_nfs4_open_share_access, tvb, offset, 4, share_access);
	if (want_flags)
		proto_tree_add_uint(tree, hf_nfs4_want_flags, tvb, offset, 4, want_flags);
	if (want_notify_flags) {
		notify_item = proto_tree_add_uint(tree, hf_nfs4_want_notify_flags, tvb, offset, 4, want_notify_flags);

		notify_tree = proto_item_add_subtree(notify_item, ett_nfs4_want_notify_flags);
		proto_tree_add_item(notify_tree, hf_nfs4_want_signal_deleg_when_resrc_avail, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(notify_tree, hf_nfs4_want_push_deleg_when_uncontended, tvb, offset, 4, ENC_BIG_ENDIAN);
	}
	offset += 4;

	return offset;
}

static const value_string names_open4_share_deny[] = {
#define OPEN4_SHARE_DENY_NONE 0x00000000
	{ OPEN4_SHARE_DENY_NONE, "OPEN4_SHARE_DENY_NONE" },
#define OPEN4_SHARE_DENY_READ 0x00000001
	{ OPEN4_SHARE_DENY_READ, "OPEN4_SHARE_DENY_READ" },
#define OPEN4_SHARE_DENY_WRITE 0x00000002
	{ OPEN4_SHARE_DENY_WRITE, "OPEN4_SHARE_DENY_WRITE" },
#define OPEN4_SHARE_DENY_BOTH 0x00000003
	{ OPEN4_SHARE_DENY_BOTH, "OPEN4_SHARE_DENY_BOTH" },
	{ 0, NULL }
};


static int
dissect_nfs4_open_share_deny(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint deny_access;

	deny_access = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint(tree, hf_nfs4_open_share_deny, tvb, offset, 4,
		deny_access);
	offset += 4;

	return offset;
}


static int
dissect_nfs4_open_owner(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	offset = dissect_rpc_uint64(tvb, tree, hf_nfs4_clientid, offset);
	offset = dissect_nfsdata(tvb, offset, tree, hf_nfs4_open_owner);

	return offset;
}


static int
dissect_nfs4_open_claim_delegate_cur(tvbuff_t *tvb, int offset,
				     proto_tree *tree)
{
	offset = dissect_nfs4_stateid(tvb, offset, tree, NULL);
	offset = dissect_nfs_utf8string(tvb, offset, tree, hf_nfs4_component, NULL);

	return offset;
}

#define CLAIM_NULL		0
#define CLAIM_PREVIOUS		1
#define CLAIM_DELEGATE_CUR	2
#define CLAIM_DELEGATE_PREV	3
#define CLAIM_FH		4
#define CLAIM_DELEG_CUR_FH	5
#define CLAIM_DELEG_CUR_PREV_FH	6

static const value_string names_claim_type4[] = {
	{	CLAIM_NULL,		 "CLAIM_NULL"  },
	{	CLAIM_PREVIOUS,		 "CLAIM_PREVIOUS" },
	{	CLAIM_DELEGATE_CUR,	 "CLAIM_DELEGATE_CUR" },
	{	CLAIM_DELEGATE_PREV,	 "CLAIM_DELEGATE_PREV" },
	{	CLAIM_FH,		 "CLAIM_FH" },
	{	CLAIM_DELEG_CUR_FH,	 "CLAIM_DELEG_CUR_FH"},
	{	CLAIM_DELEG_CUR_PREV_FH, "CLAIN_DELEG_CUR_PREV_FH"},
	{	0, NULL }
};

/* XXX - need a better place to populate name than here, maybe? */
static int
dissect_nfs4_open_claim(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree, const char **name, rpc_call_info_value *civ)
{
	guint	    open_claim_type4;
	proto_item *fitem;
	proto_tree *newftree = NULL;
	guint32	    name_offset, name_len;

	open_claim_type4 = tvb_get_ntohl(tvb, offset);
	fitem = proto_tree_add_uint(tree, hf_nfs4_open_claim_type, tvb,
				    offset+0, 4, open_claim_type4);
	offset += 4;

	if (open_claim_type4 == CLAIM_NULL) {
		dissect_nfs_utf8string(tvb, offset, newftree, hf_nfs4_component, name);
		if (nfs_file_name_snooping) {

			name_offset = offset+4;
			name_len = tvb_get_ntohl(tvb, offset);

			nfs_name_snoop_add_name(civ->xid, tvb,
				name_offset, name_len, 0, 0, NULL);
		}
	}

	newftree = proto_item_add_subtree(fitem, ett_nfs4_open_claim);

	switch (open_claim_type4)
	{
		case CLAIM_NULL:
			offset = dissect_nfs_utf8string(tvb, offset, newftree, hf_nfs4_component, name);
			break;

		case CLAIM_PREVIOUS:
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_delegate_type, offset);
			break;

		case CLAIM_DELEGATE_CUR:
			offset = dissect_nfs4_open_claim_delegate_cur(tvb, offset, newftree);
			break;

		case CLAIM_DELEGATE_PREV:
			offset = dissect_nfs_utf8string(tvb, offset, newftree, hf_nfs4_component, NULL);
			break;

		default:
			break;
	}

	return offset;
}

static const value_string names_createmode4[] = {
	{	UNCHECKED4,	"UNCHECKED4" },
	{	GUARDED4,	"GUARDED4" },
	{	EXCLUSIVE4,	"EXCLUSIVE4" },
	{	EXCLUSIVE4_1,	"EXCLUSIVE4_1" },
	{	0, NULL }
};


static int
dissect_nfs4_createhow(tvbuff_t *tvb, int offset, packet_info *pinfo,
		       proto_tree *tree, rpc_call_info_value *civ)
{
	guint mode;

	mode = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint(tree, hf_nfs4_createmode, tvb, offset, 4, mode);
	offset += 4;

	switch (mode)
	{
	case UNCHECKED4:
	case GUARDED4:
		offset = dissect_nfs4_fattrs(tvb, offset, pinfo, tree, FATTR4_DISSECT_VALUES, civ);
		break;

	case EXCLUSIVE4:
		offset = dissect_rpc_uint64(tvb, tree, hf_nfs4_verifier, offset);
		break;

	case EXCLUSIVE4_1:
		offset = dissect_rpc_uint64(tvb, tree, hf_nfs4_verifier, offset);
		offset = dissect_nfs4_fattrs(tvb, offset, pinfo, tree, FATTR4_DISSECT_VALUES, civ);
		break;

	default:
		break;
	}

	return offset;
}


#define OPEN4_NOCREATE				0
#define OPEN4_CREATE				1
static const value_string names_opentype4[] = {
	{	OPEN4_NOCREATE,	"OPEN4_NOCREATE"  },
	{	OPEN4_CREATE,	"OPEN4_CREATE" },
	{	0, NULL }
};

static int
dissect_nfs4_openflag(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree, rpc_call_info_value *civ)
{
	guint	    opentype4;
	proto_item *fitem;
	proto_tree *newftree;

	opentype4 = tvb_get_ntohl(tvb, offset);
	fitem = proto_tree_add_uint(tree, hf_nfs4_opentype, tvb,
		offset+0, 4, opentype4);
	offset += 4;

	newftree = proto_item_add_subtree(fitem, ett_nfs4_opentype);

	switch (opentype4)
	{
		case OPEN4_CREATE:
			offset = dissect_nfs4_createhow(tvb, offset, pinfo, newftree, civ);
			break;

		default:
			break;
	}

	return offset;
}


static int
dissect_nfs4_clientaddr(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	const char *universal_ip_address = NULL;
	const char *protocol		 = NULL;
	guint	b1, b2, b3, b4, b5, b6, b7, b8, b9, b10;
	guint16 port;
	int	addr_offset;

	offset = dissect_rpc_string(tvb, tree, hf_nfs4_r_netid, offset, &protocol);
	addr_offset = offset;
	offset = dissect_rpc_string(tvb, tree, hf_nfs4_r_addr, offset, &universal_ip_address);

	if (strlen(protocol) == 3 && strncmp(protocol, "tcp", 3) == 0) {
		if (universal_ip_address && sscanf(universal_ip_address, "%u.%u.%u.%u.%u.%u",
						   &b1, &b2, &b3, &b4, &b5, &b6) == 6) {
			/* IPv4: h1.h2.h3.h4.p1.p2 */
			port = (b5<<8) | b6;
			proto_tree_add_text(tree, tvb, addr_offset, offset-addr_offset,
				"[callback IPv4 address %u.%u.%u.%u, protocol=%s, port=%u]",
				b1, b2, b3, b4, protocol, port);
		} else if (universal_ip_address && sscanf(universal_ip_address, "%u.%u",
						   &b1, &b2) == 2) {
			/* Some clients (linux) sometimes send only the port. */
			port = (b1<<8) | b2;
			proto_tree_add_text(tree, tvb, addr_offset, offset-addr_offset,
				"[callback ip address NOT SPECIFIED, protocol=%s, port=%u]", protocol, port);
		} else if (universal_ip_address && sscanf(universal_ip_address,
						"%2x:%2x:%2x:%2x:%2x:%2x:%2x:%2x.%u.%u",
						&b1, &b2, &b3, &b4, &b5, &b6, &b7, &b8, &b9, &b10) == 10) {
			port = (b9<<8) | b10;
			proto_tree_add_text(tree, tvb, addr_offset, offset-addr_offset,
				"[callback IPv6 address %2x:%2x:%2x:%2x:%2x:%2x:%2x:%2x, protocol=%s, port=%u]",
				b1, b2, b3, b4, b5, b6, b7, b8, protocol, port);
		} else {
			proto_tree_add_text(tree, tvb, addr_offset, offset-addr_offset, "[Invalid address]");
		}
	}
	return offset;
}


static int
dissect_nfs4_cb_client4(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_tree *cb_location;
	proto_item *fitem;
	int	    cbprog;

	cbprog = tvb_get_ntohl(tvb, offset);
	reg_callback(cbprog);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_cb_program, offset);
	fitem = proto_tree_add_text(tree, tvb, offset, 0, "cb_location");

	cb_location = proto_item_add_subtree(fitem, ett_nfs4_clientaddr);
	offset = dissect_nfs4_clientaddr(tvb, offset, cb_location);

	return offset;
}


static const value_string names_stable_how4[] = {
#define UNSTABLE4 0
	{	UNSTABLE4,	"UNSTABLE4"	},
#define DATA_SYNC4 1
	{	DATA_SYNC4,	"DATA_SYNC4"	},
#define FILE_SYNC4 2
	{	FILE_SYNC4,	"FILE_SYNC4"	},
	{	0,	NULL	}
};

static int
dissect_nfs4_stable_how(tvbuff_t *tvb, int offset, proto_tree *tree, const char *name)
{
	guint stable_how4;

	stable_how4 = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint_format(tree, hf_nfs4_stable_how, tvb,
			offset+0, 4, stable_how4, "%s: %s (%u)", name,
			val_to_str(stable_how4, names_stable_how4, "%u"), stable_how4);
	offset += 4;

	return offset;
}


/* NFSv4 Operations  */
static const value_string names_nfs4_operation[] = {
	{	NFS4_OP_ACCESS,                "ACCESS"  },
	{	NFS4_OP_CLOSE,                 "CLOSE"  },
	{	NFS4_OP_COMMIT,                "COMMIT"  },
	{	NFS4_OP_CREATE,                "CREATE"  },
	{	NFS4_OP_DELEGPURGE,            "DELEGPURGE"  },
	{	NFS4_OP_DELEGRETURN,           "DELEGRETURN"  },
	{	NFS4_OP_GETATTR,               "GETATTR"  },
	{	NFS4_OP_GETFH,                 "GETFH"  },
	{	NFS4_OP_LINK,                  "LINK"  },
	{	NFS4_OP_LOCK,                  "LOCK"  },
	{	NFS4_OP_LOCKT,                 "LOCKT"  },
	{	NFS4_OP_LOCKU,                 "LOCKU"  },
	{	NFS4_OP_LOOKUP,                "LOOKUP"  },
	{	NFS4_OP_LOOKUPP,               "LOOKUPP"  },
	{	NFS4_OP_NVERIFY,               "NVERIFY"  },
	{	NFS4_OP_OPEN,                  "OPEN"  },
	{	NFS4_OP_OPENATTR,              "OPENATTR"  },
	{	NFS4_OP_OPEN_CONFIRM,          "OPEN_CONFIRM"  },
	{	NFS4_OP_OPEN_DOWNGRADE,        "OPEN_DOWNGRADE"  },
	{	NFS4_OP_PUTFH,                 "PUTFH"  },
	{	NFS4_OP_PUTPUBFH,              "PUTPUBFH"  },
	{	NFS4_OP_PUTROOTFH,             "PUTROOTFH"  },
	{	NFS4_OP_READ,                  "READ"  },
	{	NFS4_OP_READDIR,               "READDIR"  },
	{	NFS4_OP_READLINK,              "READLINK"  },
	{	NFS4_OP_REMOVE,                "REMOVE"  },
	{	NFS4_OP_RENAME,                "RENAME"  },
	{	NFS4_OP_RENEW,                 "RENEW"  },
	{	NFS4_OP_RESTOREFH,             "RESTOREFH"  },
	{	NFS4_OP_SAVEFH,                "SAVEFH"  },
	{	NFS4_OP_SECINFO,               "SECINFO"  },
	{	NFS4_OP_SETATTR,               "SETATTR"  },
	{	NFS4_OP_SETCLIENTID,           "SETCLIENTID"  },
	{	NFS4_OP_SETCLIENTID_CONFIRM,   "SETCLIENTID_CONFIRM"  },
	{	NFS4_OP_VERIFY,                "VERIFY"  },
	{	NFS4_OP_WRITE,                 "WRITE"  },
	{	NFS4_OP_RELEASE_LOCKOWNER,     "RELEASE_LOCKOWNER"  },
	{	NFS4_OP_BACKCHANNEL_CTL,       "BACKCHANNEL_CTL"  },
	{	NFS4_OP_BIND_CONN_TO_SESSION,  "BIND_CONN_TO_SESSION"  },
	{	NFS4_OP_EXCHANGE_ID,           "EXCHANGE_ID"  },
	{	NFS4_OP_CREATE_SESSION,        "CREATE_SESSION"  },
	{	NFS4_OP_DESTROY_SESSION,       "DESTROY_SESSION"  },
	{	NFS4_OP_FREE_STATEID,          "FREE_STATEID"  },
	{	NFS4_OP_GET_DIR_DELEGATION,    "GET_DIR_DELEGATION"  },
	{	NFS4_OP_GETDEVINFO,            "GETDEVINFO"  },
	{	NFS4_OP_GETDEVLIST,            "GETDEVLIST"  },
	{	NFS4_OP_LAYOUTCOMMIT,          "LAYOUTCOMMIT"  },
	{	NFS4_OP_LAYOUTGET,             "LAYOUTGET"  },
	{	NFS4_OP_LAYOUTRETURN,          "LAYOUTRETURN"  },
	{	NFS4_OP_SECINFO_NO_NAME,       "SECINFO_NO_NAME"  },
	{	NFS4_OP_SEQUENCE,              "SEQUENCE"  },
	{	NFS4_OP_SET_SSV,               "SET_SSV"  },
	{	NFS4_OP_TEST_STATEID,          "TEST_STATEID"  },
	{	NFS4_OP_WANT_DELEGATION,       "WANT_DELEG"  },
	{	NFS4_OP_DESTROY_CLIENTID,      "DESTROY_CLIENTID"  },
	{	NFS4_OP_RECLAIM_COMPLETE,      "RECLAIM_COMPLETE"  },
	{	NFS4_OP_ILLEGAL,               "ILLEGAL"  },
	{	0, NULL  }
};

static value_string_ext names_nfs4_operation_ext = VALUE_STRING_EXT_INIT(names_nfs4_operation);

/* Each subtree number in this array corresponds to the associated item in the above
*  'names_nfs4_operation array[]' array. */
static gint *nfs4_operation_ett[] =
{
	 &ett_nfs4_access ,
	 &ett_nfs4_close ,
	 &ett_nfs4_commit ,
	 &ett_nfs4_create ,
	 &ett_nfs4_delegpurge ,
	 &ett_nfs4_delegreturn ,
	 &ett_nfs4_getattr ,
	 &ett_nfs4_getfh ,
	 &ett_nfs4_link ,
	 &ett_nfs4_lock ,
	 &ett_nfs4_lockt ,
	 &ett_nfs4_locku ,
	 &ett_nfs4_lookup ,
	 &ett_nfs4_lookupp ,
	 &ett_nfs4_nverify ,
	 &ett_nfs4_open ,
	 &ett_nfs4_openattr ,
	 &ett_nfs4_open_confirm ,
	 &ett_nfs4_open_downgrade ,
	 &ett_nfs4_putfh ,
	 &ett_nfs4_putpubfh ,
	 &ett_nfs4_putrootfh ,
	 &ett_nfs4_read ,
	 &ett_nfs4_readdir ,
	 &ett_nfs4_readlink ,
	 &ett_nfs4_remove ,
	 &ett_nfs4_rename ,
	 &ett_nfs4_renew ,
	 &ett_nfs4_restorefh ,
	 &ett_nfs4_savefh ,
	 &ett_nfs4_secinfo ,
	 &ett_nfs4_setattr ,
	 &ett_nfs4_setclientid ,
	 &ett_nfs4_setclientid_confirm ,
	 &ett_nfs4_verify ,
	 &ett_nfs4_write,
	 &ett_nfs4_release_lockowner,
	 &ett_nfs4_backchannel_ctl,
	 &ett_nfs4_bind_conn_to_session,
	 &ett_nfs4_exchange_id,
	 &ett_nfs4_create_session,
	 &ett_nfs4_destroy_session,
	 &ett_nfs4_free_stateid,
	 NULL, /* get dir delegation */
	 &ett_nfs4_getdevinfo,
	 &ett_nfs4_getdevlist,
	 &ett_nfs4_layoutcommit,
	 &ett_nfs4_layoutget,
	 &ett_nfs4_layoutreturn,
	 &ett_nfs4_secinfo_no_name,
	 &ett_nfs4_sequence,
	 NULL, /* set ssv */
	 &ett_nfs4_test_stateid,
	 NULL, /* want delegation */
	 &ett_nfs4_destroy_clientid,
	 &ett_nfs4_reclaim_complete
};


static int
dissect_nfs4_dirlist(tvbuff_t *tvb, int offset, packet_info *pinfo,
		     proto_tree *tree, rpc_call_info_value *civ)
{
	guint32	    val_follows;
	guint32	    name_len;
	char	   *name;
	proto_item *ditem;
	proto_tree *dirlist_tree;
	proto_item *eitem;
	proto_tree *entry_tree;

	ditem = proto_tree_add_text(tree, tvb, offset, 0, "Directory Listing");
	dirlist_tree = proto_item_add_subtree(ditem, ett_nfs4_dirlist);

	while (1)
	{
		val_follows = tvb_get_ntohl(tvb, offset);
		if (val_follows) {
			int start_off = offset;

			/* Make sure we have 16 bytes (value follows + cookie + name length) */
			tvb_ensure_bytes_exist(tvb, offset, 16);
			name_len = tvb_get_ntohl(tvb, offset + 12);
			tvb_ensure_bytes_exist(tvb, offset, 16 + name_len);
			/*
			* Get the entry name and create subtree of field nfs.name
			*/
			name = (char *)tvb_memcpy(tvb, wmem_alloc(wmem_packet_scope(), name_len+1), offset + 16, name_len);
			name[name_len] = '\0';

			eitem = proto_tree_add_string_format(
				dirlist_tree, hf_nfs_name, tvb, offset, -1, name, "Entry: %s", name);
			entry_tree = proto_item_add_subtree(eitem, ett_nfs4_dir_entry);

			/* Value Follows: <Yes|No> */
			if (entry_tree)
				proto_tree_add_boolean(entry_tree, hf_nfs4_value_follows, tvb, offset, 4, val_follows);
			offset += 4;

			/* Directory entry cookie */
			if (entry_tree)
				dissect_rpc_uint64(tvb, entry_tree, hf_nfs4_cookie, offset);
			offset += 8;

			/* Directory entry name (nfs.entry_name) */
			offset = dissect_nfs_utf8string(tvb, offset, entry_tree, hf_nfs4_dir_entry_name, NULL);

			/* Attrmask(s) */
			offset = dissect_nfs4_fattrs(tvb, offset, pinfo, entry_tree, FATTR4_DISSECT_VALUES, civ);
			proto_item_set_len(eitem, offset - start_off);
		} else {
			break;
		}
	}
	if (dirlist_tree) {
		proto_tree_add_boolean(dirlist_tree, hf_nfs4_value_follows, tvb, offset, 4, val_follows);
		offset += 4;
		/* The last entry in this packet has been reached but do more follow? */
		offset = dissect_rpc_bool(tvb, dirlist_tree, hf_nfs4_dirlist_eof, offset);
	} else {
		offset += 8;
	}
	return offset;
}


static int
dissect_nfs4_change_info(tvbuff_t *tvb, int offset,
			 proto_tree *tree, const char *name)
{
	proto_tree *newftree;
	proto_tree *fitem;

	fitem = proto_tree_add_text(tree, tvb, offset, 0, "%s", name);
	newftree = proto_item_add_subtree(fitem, ett_nfs4_change_info);

	offset = dissect_rpc_bool(  tvb, newftree, hf_nfs4_change_info_atomic, offset);
	offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_changeid_before,    offset);
	offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_changeid_after,     offset);

	return offset;
}


static const value_string names_nfs_lock_type4[] =
{
#define READ_LT 1
	{	READ_LT,	"READ_LT"	},
#define WRITE_LT 2
	{	WRITE_LT,	"WRITE_LT"	},
#define READW_LT 3
	{	READW_LT,	"READW_LT"	},
#define WRITEW_LT 4
	{	WRITEW_LT,	"WRITEW_LT"	},
#define RELEASE_STATE 5
	{	RELEASE_STATE,	"RELEASE_STATE"	},
	{	0,	NULL	}
};

static int
dissect_nfs4_lockdenied(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	offset = dissect_rpc_uint64(tvb, tree, hf_nfs4_offset, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_nfs4_length, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_lock_type, offset);
	offset = dissect_nfs4_lock_owner(tvb, offset, tree);
	return offset;
}


static const value_string names_open4_result_flags[] = {
#define OPEN4_RESULT_MLOCK 0x00000001
	{ OPEN4_RESULT_MLOCK, "OPEN4_RESULT_MLOCK" },
#define OPEN4_RESULT_CONFIRM 0x00000002
	{ OPEN4_RESULT_CONFIRM, "OPEN4_RESULT_CONFIRM" },
#define OPEN4_RESULT_LOCKTYPE_POSIX 0x00000004
	{ OPEN4_RESULT_LOCKTYPE_POSIX, "OPEN4_RESULT_LOCKTYPE_POSIX" },
	{ 0, NULL }
};

static int
dissect_nfs4_open_rflags(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	if (tree)
	{
		proto_item *rflags_item;
		proto_item *rflags_tree;

		rflags_item = proto_tree_add_item(tree, hf_nfs4_open_rflags, tvb, offset, 4, ENC_BIG_ENDIAN);
		rflags_tree = proto_item_add_subtree(rflags_item, ett_nfs4_open_result_flags);
		proto_tree_add_item(rflags_tree, hf_nfs4_open_rflags_mlock, tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(rflags_tree, hf_nfs4_open_rflags_confirm, tvb, offset, 4, ENC_BIG_ENDIAN);
	}

	offset += 4;

	return offset;
}


static int
dissect_nfs4_stateid(tvbuff_t *tvb, int offset, proto_tree *tree, guint16 *hash)
{
	proto_item *sh_item;
	proto_tree *newftree = NULL;
	guint16	    sid_hash;
	guint8	   *sidh_array;

	if (tree) {
		proto_item *fitem;
		fitem = proto_tree_add_text(tree, tvb, offset, 4, "stateid");
		newftree = proto_item_add_subtree(fitem, ett_nfs4_stateid);
	}

	sidh_array = tvb_get_string_enc(NULL, tvb, offset, 16, ENC_ASCII);
	sid_hash = crc16_ccitt(sidh_array, 16);
	g_free(sidh_array);

	sh_item = proto_tree_add_uint(newftree, hf_nfs4_stateid_hash, tvb, offset, 16, sid_hash);
	PROTO_ITEM_SET_GENERATED(sh_item);
	offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_seqid, offset);
	proto_tree_add_item(newftree, hf_nfs4_stateid_other, tvb, offset, 12, ENC_NA);
	offset+=12;

	if (hash)
		*hash = sid_hash;

	return offset;
}


static int
dissect_nfs4_open_read_delegation(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree)
{
	offset = dissect_nfs4_stateid(tvb, offset, tree, NULL);
	offset = dissect_rpc_bool(tvb, tree, hf_nfs4_recall4, offset);
	offset = dissect_nfs4_ace(tvb, offset, pinfo, tree, 0, 0);

	return offset;
}


static int
dissect_nfs4_modified_limit(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_num_blocks, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_bytes_per_block, offset);

	return offset;
}


/*
 * No FULL DISSECT yet.
 */
static int
dissect_nfs4_state_protect_bitmap(tvbuff_t *tvb, int offset,
				  proto_tree *tree)
{
	guint32 num_bitmaps;
	proto_item *fitem = NULL;
	proto_tree *newftree = NULL;
	guint32 *bitmap = NULL;
	guint32 op;
	guint32 i;
	gint j;
	guint32 sl;

	num_bitmaps = tvb_get_ntohl(tvb, offset);
	if (num_bitmaps > MAX_BITMAPS) {
		proto_tree_add_text(tree, tvb, offset, 4,
				"Huge bitmap length: %u", num_bitmaps);
		THROW(ReportedBoundsError);
	}
	tvb_ensure_bytes_exist(tvb, offset, 4 + num_bitmaps * 4);
	fitem = proto_tree_add_text(tree, tvb, offset, 4 + num_bitmaps * 4,
				    "%s", "operation mask");
	offset += 4;

	newftree = proto_item_add_subtree(fitem, ett_nfs4_bitmap);

	if (num_bitmaps)
		bitmap = (guint32 *)wmem_alloc(wmem_packet_scope(), num_bitmaps * sizeof(guint32));

	for (i = 0; i < num_bitmaps; i++) {
		bitmap[i] = tvb_get_ntohl(tvb, offset);
		sl = 0x00000001;
		for (j = 0; j < 32; j++) {
			op = 32 * i + j;
			if (bitmap[i] & sl) {
				proto_tree_add_uint(newftree, hf_nfs4_op_mask,
						    tvb, offset, 4, op);
			}
			sl <<= 1;
		}
		offset += 4;
	}
	return offset;
}

#define SP4_NONE                                0
#define SP4_MACH_CRED                           1
#define SP4_SSV                                 2
static const value_string names_state_protect_how4[] = {
	{	SP4_NONE,	"SP4_NONE"  },
	{	SP4_MACH_CRED,	"SP4_MACH_CRED" },
	{	SP4_SSV,	"SP4_SSV" },
	{	0,		NULL }
};

static int
dissect_nfs4_state_protect_ops(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	offset = dissect_nfs4_state_protect_bitmap(tvb, offset, tree);
	offset = dissect_nfs4_state_protect_bitmap(tvb, offset, tree);
	return offset;
}


static int
dissect_nfs4_ssv_sp_parms(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	offset = dissect_nfs4_state_protect_ops(tvb, offset, tree);
	offset = dissect_rpc_opaque_data(tvb, offset, tree, NULL,
				hf_nfs4_sec_oid, FALSE, 0, FALSE, NULL, NULL);
	offset = dissect_rpc_opaque_data(tvb, offset, tree, NULL,
				hf_nfs4_sec_oid, FALSE, 0, FALSE, NULL, NULL);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_state_protect_window, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_state_protect_num_gss_handles, offset);
	return offset;
}


static int
dissect_nfs4_ssv_prot_info(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	offset = dissect_nfs4_state_protect_ops(tvb, offset, tree);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_prot_info_hash_alg, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_prot_info_encr_alg, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_prot_info_svv_length, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_prot_info_spi_window, offset);
	offset = dissect_nfsdata(tvb, offset, tree, hf_nfs4_gsshandle);
	return offset;
}


static int
dissect_nfs4_state_protect_a(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint stateprotect;

	stateprotect = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint(tree, hf_nfs4_state_protect_how, tvb, offset+0, 4, stateprotect);
	offset += 4;

	switch (stateprotect) {
		case SP4_NONE:
			break;
		case SP4_MACH_CRED:
			offset = dissect_nfs4_state_protect_ops(tvb, offset, tree);
			break;
		case SP4_SSV:
			offset = dissect_nfs4_ssv_sp_parms(tvb, offset, tree);
			break;
		default:
			break;
	}
	return offset;
}


static int
dissect_nfs4_state_protect_r(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint stateprotect;

	stateprotect = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint(tree, hf_nfs4_state_protect_how, tvb, offset+0, 4,
			    stateprotect);
	offset += 4;

	switch (stateprotect) {
		case SP4_NONE:
			break;
		case SP4_MACH_CRED:
			offset = dissect_nfs4_state_protect_ops(tvb, offset, tree);
			break;
		case SP4_SSV:
			offset = dissect_nfs4_ssv_prot_info(tvb, offset, tree);
			break;
		default:
			break;
	}
	return offset;
}


#define NFS_LIMIT_SIZE						1
#define NFS_LIMIT_BLOCKS					2
static const value_string names_limit_by4[] = {
	{	NFS_LIMIT_SIZE,		"NFS_LIMIT_SIZE"  },
	{	NFS_LIMIT_BLOCKS,	"NFS_LIMIT_BLOCKS" },
	{	0,			NULL }
};

static int
dissect_nfs4_space_limit(tvbuff_t *tvb, int offset,
			 proto_tree *tree)
{
	guint limitby;

	limitby = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint(tree, hf_nfs4_limit_by, tvb, offset+0, 4, limitby);
	offset += 4;

	switch (limitby)
	{
	case NFS_LIMIT_SIZE:
		offset = dissect_rpc_uint64(tvb, tree, hf_nfs4_filesize,
			offset);
		break;

	case NFS_LIMIT_BLOCKS:
		offset = dissect_nfs4_modified_limit(tvb, offset, tree);
		break;

	default:
		break;
	}

	return offset;
}


static int
dissect_nfs4_open_write_delegation(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree)
{
	offset = dissect_nfs4_stateid(tvb, offset, tree, NULL);
	offset = dissect_rpc_bool(tvb, tree, hf_nfs4_recall, offset);
	offset = dissect_nfs4_space_limit(tvb, offset, tree);
	offset = dissect_nfs4_ace(tvb, offset, pinfo, tree, 0, 0);

	return offset;
}


#define OPEN_DELEGATE_NONE 0
#define OPEN_DELEGATE_READ 1
#define OPEN_DELEGATE_WRITE 2
#define OPEN_DELEGATE_NONE_EXT 3 /* new to v4.1 */
static const value_string names_open_delegation_type4[] = {
	{	OPEN_DELEGATE_NONE,	"OPEN_DELEGATE_NONE" },
	{	OPEN_DELEGATE_READ, 	"OPEN_DELEGATE_READ" },
	{	OPEN_DELEGATE_WRITE,	"OPEN_DELEGATE_WRITE" },
	{	OPEN_DELEGATE_NONE_EXT, "OPEN_DELEGATE_NONE_EXT"},
	{	0,	NULL }
};

#define WND4_NOT_WANTED 0
#define WND4_CONTENTION 1
#define WND4_RESOURCE 2
#define WND4_NOT_SUPP_FTYPE 3
#define WND4_WRITE_DELEG_NOT_SUPP_FTYPE 4
#define WND4_NOT_SUPP_UPGRADE 5
#define WND4_NOT_SUPP_DOWNGRADE 6
#define WND4_CANCELLED 7
#define WND4_IS_DIR 8
static const value_string names_why_no_delegation4[] = {
	{	WND4_NOT_WANTED,		 "WND4_NOT_WANTED" },
	{	WND4_CONTENTION,		 "WND4_CONTENTION" },
	{	WND4_RESOURCE,			 "WND4_RESOURCE" },
	{	WND4_NOT_SUPP_FTYPE,		 "WND4_NOT_SUPP_FTYPE" },
	{	WND4_WRITE_DELEG_NOT_SUPP_FTYPE, "WND4_WRITE_DELEG_NOT_SUPP_FTYPE" },
	{	WND4_NOT_SUPP_UPGRADE,		 "WND4_NOT_SUPP_UPGRADE" },
	{	WND4_NOT_SUPP_DOWNGRADE,	 "WND4_NOT_SUPP_DOWNGRADE" },
	{	WND4_CANCELLED,			 "WND4_CANCELLED" },
	{	WND4_IS_DIR,			 "WND4_IS_DIR" },
	{	0,				NULL }
};

static int
dissect_nfs4_open_delegation(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree)
{
	guint delegation_type;
	proto_tree *newftree = NULL;
	proto_item *fitem = NULL;

	delegation_type = tvb_get_ntohl(tvb, offset);
	fitem = proto_tree_add_uint(tree, hf_nfs4_open_delegation_type, tvb,
		offset+0, 4, delegation_type);
	offset += 4;

	newftree = proto_item_add_subtree(fitem, ett_nfs4_open_delegation);

	switch (delegation_type)
	{
		case OPEN_DELEGATE_NONE:
			break;

		case OPEN_DELEGATE_READ:
			offset = dissect_nfs4_open_read_delegation(tvb, offset, pinfo, newftree);
			break;

		case OPEN_DELEGATE_WRITE:
			offset = dissect_nfs4_open_write_delegation(tvb, offset, pinfo, newftree);
			break;
		case OPEN_DELEGATE_NONE_EXT:
			proto_tree_add_item(tree, hf_nfs4_why_no_delegation, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			break;
		default:
			break;
	}

	return offset;
}


static int
dissect_nfs_rpcsec_gss_info(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	offset = dissect_rpc_opaque_data(tvb, offset, tree, NULL,
		hf_nfs4_sec_oid, FALSE, 0, FALSE, NULL, NULL);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_qop, offset);
	offset = dissect_rpc_uint32(tvb, tree,
		hf_nfs4_secinfo_rpcsec_gss_info_service, offset);

	return offset;
}


static int
dissect_nfs4_open_to_lock_owner(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_seqid, offset);
	offset = dissect_nfs4_stateid(tvb, offset, tree, NULL);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_lock_seqid, offset);
	offset = dissect_nfs4_lock_owner(tvb, offset, tree);

	return offset;
}


static int
dissect_nfs4_exist_lock_owner(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	offset = dissect_nfs4_stateid(tvb, offset, tree, NULL);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_lock_seqid, offset);

	return offset;
}


static int
dissect_nfs4_locker(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint new_lock_owner;

	new_lock_owner = tvb_get_ntohl(tvb, offset);
	offset = dissect_rpc_bool(tvb, tree, hf_nfs4_new_lock_owner, offset);

	if (new_lock_owner)
		offset = dissect_nfs4_open_to_lock_owner(tvb, offset, tree);
	else
		offset = dissect_nfs4_exist_lock_owner(tvb, offset, tree);

	return offset;
}


static int
dissect_nfs4_client_id(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	offset = dissect_rpc_uint64(tvb, tree, hf_nfs4_verifier, offset);
	offset = dissect_rpc_data(tvb, tree, hf_nfs4_client_id, offset);

	return offset;
}


static int
dissect_nfs4_newtime(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint new_time;

	new_time = tvb_get_ntohl(tvb, offset);
	offset = dissect_rpc_bool(tvb, tree, hf_nfs4_newtime, offset);

	if (new_time) {
		offset = dissect_nfs4_nfstime(tvb, offset, tree);
	}

	return offset;
}


static int
dissect_nfs4_newsize(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint new_size;

	new_size = tvb_get_ntohl(tvb, offset);
	offset = dissect_rpc_bool(tvb, tree, hf_nfs4_newsize, offset);

	if (new_size) {
		offset = dissect_rpc_uint64(tvb, tree, hf_nfs4_length, offset);
	}

	return offset;
}


static int
dissect_nfs4_newoffset(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint new_offset;

	new_offset = tvb_get_ntohl(tvb, offset);
	offset = dissect_rpc_bool(tvb, tree, hf_nfs4_newoffset, offset);

	if (new_offset) {
		offset = dissect_rpc_uint64(tvb, tree, hf_nfs4_offset, offset);
	}

	return offset;
}


static int
dissect_nfs4_layoutreturn(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint returntype;

	returntype = tvb_get_ntohl(tvb, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_layout_return_type, offset);
	if (returntype == 1) { /* RETURN_FILE */
		offset = dissect_rpc_uint64(tvb, tree, hf_nfs4_offset, offset);
		offset = dissect_rpc_uint64(tvb, tree, hf_nfs4_length, offset);
		offset = dissect_nfs4_stateid(tvb, offset, tree, NULL);
		offset = dissect_nfsdata(tvb, offset, tree, hf_nfs4_lrf_body_content);
	}

	return offset;
}


static int
dissect_nfs_layoutreturn_stateid(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	guint lrs_present;

	lrs_present = tvb_get_ntohl(tvb, offset);
	offset = dissect_rpc_bool(tvb, tree, hf_nfs4_lrs_present, offset);

	if (lrs_present) {
		offset = dissect_nfs4_stateid(tvb, offset, tree, NULL);
	}

	return offset;
}


static int
dissect_nfs4_notification_bitmap(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	guint32 bitmap_num;
	guint i;

	bitmap_num = tvb_get_ntohl(tvb, offset);
	offset += 4;

	/* https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8611 */
	if (!tree) {
		if ((guint)offset > offset + (bitmap_num * 4)) {
			return tvb_reported_length(tvb);
		}
		else {
			return offset + (bitmap_num * 4);
		}
	}

	for (i = 0; i < bitmap_num; i++) {
		offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_notification_bitmap, offset);
	}

	return offset;
}


static int
dissect_nfs4_devices(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint i, j;
	guint32 num_indices, num_multipath, num_addr;

	/* No layout type - argh */

	/* Assume file layout for now */

	/* disect indices */
	num_indices = tvb_get_ntohl(tvb, offset);
	offset += 4;
	for (i = 0; i < num_indices; i++) {
		offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_deviceidx, offset);
	}

	num_multipath = tvb_get_ntohl(tvb, offset);
	offset += 4;
	for (i = 0; i < num_multipath; i++) {
		num_addr = tvb_get_ntohl(tvb, offset);
		offset += 4;
		for (j = 0; j < num_addr; j++) {
			offset = dissect_rpc_string(tvb, tree, hf_nfs4_r_netid, offset, NULL);
			offset = dissect_rpc_string(tvb, tree, hf_nfs4_r_addr, offset, NULL);
		}
	}

	return offset;
}


static int
dissect_nfs4_test_stateid_arg(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
	return dissect_nfs4_stateid(tvb, offset, tree, NULL);
}


static int
dissect_nfs4_test_stateid_res(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
	return dissect_nfs4_status(tvb, offset, tree, NULL);
}


static int
dissect_nfs4_deviceaddr(tvbuff_t *tvb, int offset, proto_tree *tree)
{

	/* layout type */
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_layout_type, offset);

	/* skip da_addr_body size */
	offset+=4;

	offset = dissect_nfs4_devices(tvb, offset, tree);

	return offset;
}


static int
dissect_nfs4_devicelist(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint count;
	guint i;

	count = tvb_get_ntohl(tvb, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_devicenum, offset);
	for (i = 0; i < count; i++)
		offset = dissect_nfs4_deviceid(tvb, offset, tree);

	return offset;
}


static int
dissect_rpc_serverowner4(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	offset = dissect_rpc_uint64(tvb, tree, hf_nfs4_minorid, offset);
	offset = dissect_nfsdata(tvb, offset, tree, hf_nfs4_majorid);
	return offset;
}


static int
dissect_rpc_chanattrs4(tvbuff_t *tvb, int offset, proto_tree *tree, const char *name)
{
	proto_item *chan_attrs_item;
	proto_tree *chan_attrs_tree;
	guint i, count, rdma_ird_len;

	rdma_ird_len = tvb_get_ntohl(tvb, offset + 24);
	count = 28 + rdma_ird_len * 4;

	chan_attrs_item = proto_tree_add_text(tree, tvb, offset, count, name, count);
	chan_attrs_tree = proto_item_add_subtree(chan_attrs_item, ett_nfs4_chan_attrs);

	offset = dissect_rpc_uint32(tvb, chan_attrs_tree, hf_nfs4_padsize, offset);
	offset = dissect_rpc_uint32(tvb, chan_attrs_tree, hf_nfs4_maxreqsize, offset);
	offset = dissect_rpc_uint32(tvb, chan_attrs_tree, hf_nfs4_maxrespsize, offset);
	offset = dissect_rpc_uint32(tvb, chan_attrs_tree, hf_nfs4_maxrespsizecached, offset);
	offset = dissect_rpc_uint32(tvb, chan_attrs_tree, hf_nfs4_maxops, offset);
	offset = dissect_rpc_uint32(tvb, chan_attrs_tree, hf_nfs4_maxreqs, offset);
	offset += 4;
	for (i = 0; i < rdma_ird_len; i++) {
		offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_rdmachanattrs, offset);
	}
	return offset;
}


static int
dissect_rpc_nfs_impl_id4(tvbuff_t *tvb, int offset, proto_tree *tree, const char *name)
{
	proto_item *impl_id_item;
	proto_tree *impl_id_tree;
	guint i, count;

	count = tvb_get_ntohl(tvb, offset);
	impl_id_item = proto_tree_add_text(tree, tvb, offset, 4, name, count);
	impl_id_tree = proto_item_add_subtree(impl_id_item, ett_nfs4_clientowner);
	offset += 4;

	for (i = 0; i < count; i++) {
		proto_item *date_item;
		proto_tree *date_tree;

		offset = dissect_nfs_utf8string(tvb, offset, impl_id_tree, hf_nfs4_nii_domain, NULL);
		offset = dissect_nfs_utf8string(tvb, offset, impl_id_tree, hf_nfs4_nii_name, NULL);

		date_item = proto_tree_add_text(impl_id_tree, tvb, offset, 12, "Build timestamp(nii_date)");
		date_tree = proto_item_add_subtree(date_item, ett_nfs4_clientowner);
		offset = dissect_nfs4_nfstime(tvb, offset, date_tree);
	}
	return offset;
}


static int
dissect_rpc_secparms4(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint count, i;

	count = tvb_get_ntohl(tvb, offset);
	offset += 4;

	for (i = 0; i < count; i++) {
		guint j, flavor = tvb_get_ntohl(tvb, offset);
		offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_flavor, offset);

		switch (flavor) {
		case 1: { /* AUTH_SYS */
			guint count2;
			offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_stamp, offset);
			offset = dissect_nfs_utf8string(tvb, offset, tree, hf_nfs4_machinename, NULL);
			offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_uid, offset);
			offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_gid, offset);
			count2 = tvb_get_ntohl(tvb, offset);
			offset += 4;
			for (j = 0; j < count2; j++) {
				offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_gid, offset);
			}
			break;
		}
		case 6: /* RPCSEC_GSS */
			offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_service, offset);
			proto_item_append_text(tree, ", Handle from server");
			offset = dissect_nfsdata(tvb, offset, tree, hf_nfs_data);
			proto_item_append_text(tree, ", Handle from client");
			offset = dissect_nfsdata(tvb, offset, tree, hf_nfs_data);
			break;
		default:
			break;
		}
	}
	return offset;
}


static int
dissect_nfs4_layout(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, rpc_call_info_value *civ)
{
	guint	    layout_type;
	guint	    fh_num;
	guint	    lo_seg_count;
	guint	    i, lo_seg;
	proto_item *fitem;
	proto_item *fh_fitem;
	proto_tree *newtree;
	proto_tree *fh_tree;

	lo_seg_count = tvb_get_ntohl(tvb, offset);

	fitem = proto_tree_add_text(tree, tvb, offset, 4, "Layout Segment (count: %u)", lo_seg_count);
	offset += 4;

	newtree = proto_item_add_subtree(fitem, ett_nfs4_layoutseg);

	for (lo_seg = 0; lo_seg < lo_seg_count; lo_seg++) {
		offset = dissect_rpc_uint64(tvb, newtree, hf_nfs4_offset, offset);
		offset = dissect_rpc_uint64(tvb, newtree, hf_nfs4_length, offset);

		offset = dissect_rpc_uint32(tvb, newtree, hf_nfs4_iomode, offset);

		layout_type = tvb_get_ntohl(tvb, offset);
		offset = dissect_rpc_uint32(tvb, newtree, hf_nfs4_layout_type, offset);

		/* If not files layout type eat the rest and move on.. */
		if (layout_type != LAYOUT4_NFSV4_1_FILES) {
			offset = dissect_nfsdata(tvb, offset, newtree, hf_nfs4_layout);
			continue;
		}

		/* NFS Files */
		offset += 4; /* Skip past opaque count */

		offset = dissect_nfs4_deviceid(tvb, offset, newtree);

		offset = dissect_rpc_uint32(tvb, newtree, hf_nfs4_nfl_util, offset);
		offset = dissect_rpc_uint32(tvb, newtree, hf_nfs4_nfl_first_stripe_index, offset);
		offset = dissect_rpc_uint64(tvb, newtree, hf_nfs4_offset, offset);

		fh_num = tvb_get_ntohl(tvb, offset); /* Len of FH list */

		fh_fitem = proto_tree_add_text(newtree, tvb, offset, 4, "File Handles (count: %u)", fh_num);
		offset += 4;

		fh_tree = proto_item_add_subtree(fh_fitem, ett_nfs4_layoutseg_fh);
		for (i = 0; i < fh_num; i++)
			offset = dissect_nfs4_fh(tvb, offset, pinfo, fh_tree, "lo_filehandle", NULL, civ);
	}
	return offset;
}


static int
dissect_nfs_create_session_flags(tvbuff_t *tvb, int offset, proto_tree *tree, int hf_csa)
{
	proto_tree *csa_flags_item;
	proto_tree *csa_flags_tree;

	csa_flags_item = proto_tree_add_item(tree, hf_csa, tvb, offset, 4, ENC_BIG_ENDIAN);
	csa_flags_tree = proto_item_add_subtree(csa_flags_item, ett_nfs4_create_session_flags);
	proto_tree_add_item(csa_flags_tree, hf_nfs4_create_session_flags_persist, tvb, offset, 4,
		ENC_BIG_ENDIAN);
	proto_tree_add_item(csa_flags_tree, hf_nfs4_create_session_flags_conn_back_chan, tvb, offset, 4,
		ENC_BIG_ENDIAN);
	proto_tree_add_item(csa_flags_tree, hf_nfs4_create_session_flags_conn_rdma, tvb, offset, 4,
		ENC_BIG_ENDIAN);
	offset += 4;

	return offset;
}


enum channel_dir_from_client4 {
	CDFC4_FORE = 0x1,
	CDFC4_BACK = 0x2,
	CDFC4_FORE_OR_BOTH = 0x3,
	CDFC4_BACK_OR_BOTH = 0x7
};

static const value_string names_channel_dir_from_client[] = {
	{ CDFC4_FORE,			"CDFC4_FORE" },
	{ CDFC4_BACK,			"CDFC4_BACK" },
	{ CDFC4_FORE_OR_BOTH,	"CDFC4_FORE_OR_BOTH" },
	{ CDFC4_BACK_OR_BOTH,	"CDFC4_BACK_OR_BOTH" },
	{ 0, NULL }
};

enum channel_dir_from_server4 {
	CDFS4_FORE = 0x1,
	CDFS4_BACK = 0x2,
	CDFS4_BOTH = 0x3
};

static const value_string names_channel_dir_from_server[] = {
	{ CDFS4_FORE,	"CDFS4_FORE" },
	{ CDFS4_BACK,	"CDFS4_BACK" },
	{ CDFS4_BOTH,	"CDFS4_BOTH" },
	{ 0, NULL }
};

#define SECINFO_STYLE4_CURRENT_FH 0
#define SECINFO_STYLE4_PARENT 1
static const value_string names_secinfo_style4[] = {
	{ SECINFO_STYLE4_CURRENT_FH,	"SECINFO_STYLE4_CURRENT_FH" },
	{ SECINFO_STYLE4_PARENT,		"SECINFO_STYLE4_PARENT"     },
	{ 0, NULL }
};

typedef struct _nfs4_operation_summary {
		guint32 opcode;
		gboolean iserror;
		GString *optext;
} nfs4_operation_summary;


/*
 To try to determine which NFSv4 operations are most important in a
  request, we categorize the operations into different "tiers".

 All operations falling into the highest tier (where 1 is highest, 5
  is lowest) are considered to be the "most significant" operations.
  This information is useful for display purposes, filtering, and for
  response time calculations.

 For example, virtually all NFSv4 requests include a GETATTR.  But in
  a request with PUTFH; CLOSE; GETATTR operations, CLOSE is the
  significant operation.

 In a request with PUTFH; GETATTR operations, GETATTR is the
  significant operation.  CLOSE has higher tier than GETATTR, which is
  in a higher tier than PUTFH.

 In practice this seems to be a very reliable method of determining
  the most significant operation(s).
 */

static int nfs4_operation_tiers[] = {
		 1 /* 0 */ ,
		 1 /* 1 */ ,
	 	 1 /* 2 */ ,
		 2 /* 3, NFS4_OP_ACCESS */ ,
		 1 /* 4, NFS4_OP_CLOSE */,
		 1 /* 5, NFS4_OP_COMMIT	*/,
		 1 /* 6, NFS4_OP_CREATE	*/,
		 1 /* 7, NFS4_OP_DELEGPURGE	*/,
		 1 /* 8, NFS4_OP_DELEGRETURN */,
		 3 /* 9, NFS4_OP_GETATTR */,
		 4 /* 10, NFS4_OP_GETFH	*/,
		 1 /* 11, NFS4_OP_LINK	*/,
		 1 /* 12, NFS4_OP_LOCK */,
		 1 /* 13, NFS4_OP_LOCKT	*/,
		 1 /* 14, NFS4_OP_LOCKU	*/,
		 1 /* 15, NFS4_OP_LOOKUP */,
		 1 /* 16, NFS4_OP_LOOKUPP */,
		 2 /* 17, NFS4_OP_NVERIFY */,
		 1 /* 18, NFS4_OP_OPEN */,
		 1 /* 19, NFS4_OP_OPENATTR */,
		 1 /* 20, NFS4_OP_OPEN_CONFIRM */,
		 1 /* 21, NFS4_OP_OPEN_DOWNGRADE */,
		 4 /* 22, NFS4_OP_PUTFH	*/,
		 3 /* 23, NFS4_OP_PUTPUBFH	*/,
		 3 /* 24, NFS4_OP_PUTROOTFH	*/,
		 1 /* 25, NFS4_OP_READ	*/,
		 1 /* 26, NFS4_OP_READDIR */,
		 1 /* 27, NFS4_OP_READLINK	*/,
		 1 /* 28, NFS4_OP_REMOVE */,
		 1 /* 29, NFS4_OP_RENAME */,
		 1 /* 30, NFS4_OP_RENEW	*/,
		 4 /* 31, NFS4_OP_RESTOREFH	*/,
		 4 /* 32, NFS4_OP_SAVEFH */,
		 1 /* 33, NFS4_OP_SECINFO */,
		 1 /* 34, NFS4_OP_SETATTR */,
		 1 /* 35, NFS4_OP_SETCLIENTID */,
		 1 /* 36, NFS4_OP_SETCLIENTID_CONFIRM */,
		 1 /* 37, NFS4_OP_VERIFY */,
		 1 /* 38, NFS4_OP_WRITE	*/,
		 1 /* 39, NFS4_OP_RELEASE_LOCKOWNER	*/,
			/* Minor version 1 */
		 1 /* 40, NFS4_OP_BACKCHANNEL_CTL */,
		 1 /* 41, NFS4_OP_BIND_CONN_TO_SESSION */,
		 1 /* 42, NFS4_OP_EXCHANGE_ID */,
		 1 /* 43, NFS4_OP_CREATE_SESSION */,
		 1 /* 44, NFS4_OP_DESTROY_SESSION */,
		 1 /* 45, NFS4_OP_FREE_STATEID */,
		 1 /* 46, NFS4_OP_GET_DIR_DELEGATION */,
		 1 /* 47, NFS4_OP_GETDEVINFO */,
		 1 /* 48, NFS4_OP_GETDEVLIST */,
		 1 /* 49, NFS4_OP_LAYOUTCOMMIT */,
		 1 /* 50, NFS4_OP_LAYOUTGET */,
		 1 /* 51, NFS4_OP_LAYOUTRETURN */,
		 1 /* 52, NFS4_OP_SECINFO_NO_NAME */,
		 4 /* 53, NFS4_OP_SEQUENCE */,
		 1 /* 54, NFS4_OP_SET_SSV */,
		 1 /* 55, NFS4_OP_TEST_STATEID */,
		 1 /* 56, NFS4_OP_WANT_DELEGATION  */,
		 1 /* 57, NFS4_OP_DESTROY_CLIENTID  */,
		 1 /* 58, NFS4_OP_RECLAIM_COMPLETE */
};

#define NFS4_OPERATION_TIER(op) \
	((op) < G_N_ELEMENTS(nfs4_operation_tiers) ? nfs4_operation_tiers[(op)] : 0)

static int
dissect_nfs4_request_op(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, rpc_call_info_value *civ)
{
	const char *name	    = NULL;
	const char *source_name	    = NULL;
	const char *dest_name	    = NULL;
	const char *opname	    = NULL;
	int	    cbprog;
	guint	    opcode;
	guint	    highest_tier    = 5;
	guint	    current_tier    = 5;
	guint	    first_operation = 1;
	/*guint name_offset = 0;*/
	guint8	   *clientid_array;
	guint16	    sid_hash;
	guint16	    clientid_hash   = 0;
	guint32	    ops;
	guint32	    ops_counter;
	guint32	    summary_counter;
	guint32	    string_length;
	guint32	    last_fh_hash    = 0;
	guint32	    saved_fh_hash   = 0;
	guint32	    length;
	guint64	    lock_length;
	guint64	    file_offset;
	proto_item *fitem	    = NULL;
	proto_tree *ftree	    = NULL;
	proto_tree *newftree	    = NULL;
	nfs4_operation_summary *op_summary;

	ops = tvb_get_ntohl(tvb, offset+0);

	fitem = proto_tree_add_uint_format(tree, hf_nfs4_ops_count, tvb, offset+0, 4, ops,
		"Operations (count: %u)", ops);
	offset += 4;

#define MAX_NFSV4_OPS 128
	if (ops > MAX_NFSV4_OPS) {
		/*  Limit the number of operations to something "reasonable."
		 *  This is an arbitrary number to keep us from attempting to
		 *  allocate too much memory below.
		 */
		expert_add_info(pinfo, fitem, &ei_nfs_too_many_ops);
		ops = MAX_NFSV4_OPS;
	}

	op_summary = (nfs4_operation_summary *)g_malloc0(sizeof(nfs4_operation_summary) * ops);

	if (fitem) {
		ftree = proto_item_add_subtree(fitem, ett_nfs4_request_op);
	}

	if (ops)
		proto_item_append_text(proto_tree_get_parent(tree), ", Ops(%d):", ops);

	for (ops_counter=0; ops_counter<ops; ops_counter++)
	{
		op_summary[ops_counter].optext = g_string_new("");
		opcode = tvb_get_ntohl(tvb, offset);
		op_summary[ops_counter].opcode = opcode;

		fitem = proto_tree_add_uint(ftree, hf_nfs4_op, tvb, offset, 4, opcode);

		/* the opcodes are not contiguous */
		if ((opcode < NFS4_OP_ACCESS || opcode > NFS4_OP_RECLAIM_COMPLETE)
		&&  opcode != NFS4_OP_ILLEGAL)
			break;

		/* all of the V4 ops are contiguous, except for NFS4_OP_ILLEGAL */
		if (opcode == NFS4_OP_ILLEGAL) {
			newftree = proto_item_add_subtree(fitem, ett_nfs4_illegal);
		} else if (nfs4_operation_ett[opcode - 3]) {
			newftree = proto_item_add_subtree(fitem, *nfs4_operation_ett[opcode - 3]);
		} else {
			break;
		}

		opname = val_to_str_ext_const(opcode, &names_nfs4_operation_ext, "Unknown");
		offset += 4;

		g_string_append_printf (op_summary[ops_counter].optext, "%s", opname);
		g_string_printf (op_summary[ops_counter].optext, "%s",
			val_to_str_ext_const(opcode, &names_nfs4_operation_ext, "Unknown"));

		proto_item_append_text(proto_tree_get_parent(tree),
			"%s%s", ops_counter ? ", " : " ", opname);
		proto_item_append_text(proto_tree_get_parent(ftree),
			"%s%s", ops_counter ? ", " : ": ", opname);

		switch (opcode)
		{
		case NFS4_OP_ACCESS:
			{
				guint32 *acc_request, amask;

				/* Get access mask to check and save it for comparison in the reply. */
				amask = tvb_get_ntohl(tvb, offset);
				acc_request = (guint32 *)wmem_memdup(wmem_file_scope(),  &amask, sizeof(guint32));
				civ->private_data = acc_request;

				g_string_append_printf (op_summary[ops_counter].optext, " FH: 0x%08x", last_fh_hash);
				display_access_items(tvb, offset, pinfo, fitem, amask, 'C', 4,
					op_summary[ops_counter].optext, "Check") ;
				offset+=4;
			}
			break;

		case NFS4_OP_CLOSE:
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_seqid, offset);
			offset = dissect_nfs4_stateid(tvb, offset, newftree, &sid_hash);
			g_string_append_printf (op_summary[ops_counter].optext, " StateID: 0x%04x", sid_hash);
			break;

		case NFS4_OP_COMMIT:
			file_offset = tvb_get_ntoh64(tvb, offset);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_offset, offset);
			length = tvb_get_ntohl(tvb, offset);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_count, offset);
			g_string_append_printf (op_summary[ops_counter].optext,
				" FH: 0x%08x Offset: %"G_GINT64_MODIFIER"u Len: %u",
				last_fh_hash, file_offset, length);

			break;

		case NFS4_OP_CREATE:
			{
				guint create_type;

				create_type = tvb_get_ntohl(tvb, offset);
				offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_ftype, offset);

				switch (create_type)
				{
				case NF4LNK:
					offset = dissect_nfs_utf8string(tvb, offset, newftree, hf_nfs4_linktext, NULL);
					break;

				case NF4BLK:
				case NF4CHR:
					offset = dissect_nfs4_specdata(tvb, offset, newftree);
					break;

				case NF4SOCK:
				case NF4FIFO:
				case NF4DIR:
					break;

				default:
					break;
				}

				offset = dissect_nfs_utf8string(tvb, offset, newftree, hf_nfs4_component, NULL);
				offset = dissect_nfs4_fattrs(tvb, offset, pinfo, newftree, FATTR4_DISSECT_VALUES, civ);
			}
			break;

		case NFS4_OP_DELEGPURGE:
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_clientid, offset);
			break;

		case NFS4_OP_DELEGRETURN:
			offset = dissect_nfs4_stateid(tvb, offset, newftree, &sid_hash);
			g_string_append_printf (op_summary[ops_counter].optext, " StateID: 0x%04x", sid_hash);
			break;

		case NFS4_OP_GETATTR:
			offset = dissect_nfs4_fattrs(tvb, offset, pinfo, newftree, FATTR4_BITMAP_ONLY, civ);

			if (last_fh_hash != 0)
				g_string_append_printf (op_summary[ops_counter].optext, " FH: 0x%08x", last_fh_hash);

			break;

		case NFS4_OP_GETFH:
			last_fh_hash = 0;
			break;

		case NFS4_OP_LINK:
			offset = dissect_nfs_utf8string(tvb, offset, newftree, hf_nfs4_component, NULL);
			break;

		case NFS4_OP_LOCK:
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_lock_type, offset);
			offset = dissect_rpc_bool(tvb, newftree, hf_nfs4_lock_reclaim, offset);
			file_offset = tvb_get_ntoh64(tvb, offset);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_offset, offset);
			lock_length = tvb_get_ntoh64(tvb, offset);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_length, offset);
			offset = dissect_nfs4_locker(tvb, offset, newftree);
			if (lock_length == G_GUINT64_CONSTANT(0xffffffffffffffff))
				g_string_append_printf (op_summary[ops_counter].optext,
					" FH: 0x%08x Offset: %"G_GINT64_MODIFIER"u Length: <End of File>",
					last_fh_hash, file_offset);
			else
				g_string_append_printf (op_summary[ops_counter].optext,
					" FH: 0x%08x Offset: %"G_GINT64_MODIFIER"u Length: %"G_GINT64_MODIFIER"u ",
					last_fh_hash, file_offset, lock_length);
			break;

		case NFS4_OP_LOCKT:
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_lock_type, offset);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_offset, offset);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_length, offset);
			offset = dissect_nfs4_lock_owner(tvb, offset, newftree);
			break;

		case NFS4_OP_LOCKU:
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_lock_type, offset);
			offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_seqid, offset);
			offset = dissect_nfs4_stateid(tvb, offset, newftree, NULL);
			file_offset = tvb_get_ntoh64(tvb, offset);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_offset, offset);
			lock_length = tvb_get_ntoh64(tvb, offset);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_length, offset);
			if (lock_length == G_GUINT64_CONSTANT(0xffffffffffffffff))
				g_string_append_printf (op_summary[ops_counter].optext,
					" FH: 0x%08x Offset: %"G_GINT64_MODIFIER"u Length: <End of File>",
					last_fh_hash, file_offset);
			else
				g_string_append_printf (op_summary[ops_counter].optext,
					" FH: 0x%08x Offset: %"G_GINT64_MODIFIER"u Length: %"G_GINT64_MODIFIER"u ",
					last_fh_hash, file_offset, lock_length);
			break;

		case NFS4_OP_LOOKUP:
			/*name_offset = offset;*/
			offset = dissect_nfs_utf8string(tvb, offset, newftree, hf_nfs4_component, &name);
			if (nfs_file_name_snooping) {
				nfs_name_snoop_add_name(civ->xid, tvb,
										/*name_offset, strlen(name), */
										0, 0,
										0, 0, name);
			}
			g_string_append_printf (op_summary[ops_counter].optext, " ");
			if (last_fh_hash != 0)
				g_string_append_printf (op_summary[ops_counter].optext, "DH: 0x%08x/", last_fh_hash);
			if (name != NULL)
				g_string_append_printf (op_summary[ops_counter].optext, "%s", name);
			break;

		case NFS4_OP_LOOKUPP:
			break;

		case NFS4_OP_NVERIFY:
			offset = dissect_nfs4_fattrs(tvb, offset, pinfo, newftree, FATTR4_DISSECT_VALUES, civ);
			if (last_fh_hash != 0)
				g_string_append_printf (op_summary[ops_counter].optext, " FH: 0x%08x", last_fh_hash);
			break;

		case NFS4_OP_OPEN:
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_seqid, offset);
			offset = dissect_nfs4_open_share_access(tvb, offset, newftree);
			offset = dissect_nfs4_open_share_deny(tvb, offset, newftree);
			offset = dissect_nfs4_open_owner(tvb, offset, newftree);
			offset = dissect_nfs4_openflag(tvb, offset, pinfo, newftree, civ);
			offset = dissect_nfs4_open_claim(tvb, offset, pinfo, newftree, &name, civ);
			g_string_append_printf (op_summary[ops_counter].optext, " ");
			if (last_fh_hash != 0)
				g_string_append_printf (op_summary[ops_counter].optext, "DH: 0x%08x/", last_fh_hash);
			if (name != NULL)
				g_string_append_printf (op_summary[ops_counter].optext, "%s", name);
			break;

		case NFS4_OP_OPENATTR:
			offset = dissect_rpc_bool(tvb, newftree, hf_nfs4_attr_dir_create, offset);
			break;

		case NFS4_OP_OPEN_CONFIRM:
			offset = dissect_nfs4_stateid(tvb, offset, newftree, NULL);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_seqid, offset);
			break;

		case NFS4_OP_OPEN_DOWNGRADE:
			offset = dissect_nfs4_stateid(tvb, offset, newftree, NULL);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_seqid, offset);
			offset = dissect_nfs4_open_share_access(tvb, offset, newftree);
			offset = dissect_nfs4_open_share_deny(tvb, offset, newftree);
			break;

		case NFS4_OP_PUTFH:
			offset = dissect_nfs4_fh(tvb, offset, pinfo, newftree, "filehandle", &last_fh_hash, civ);
			break;

		case NFS4_OP_PUTPUBFH:
		case NFS4_OP_PUTROOTFH:
			break;

		case NFS4_OP_READ:
			offset = dissect_nfs4_stateid(tvb, offset, newftree, &sid_hash);
			file_offset = tvb_get_ntoh64(tvb, offset);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_offset, offset);
			length = tvb_get_ntohl(tvb, offset);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_count, offset);
			if (sid_hash != 0)
				g_string_append_printf (op_summary[ops_counter].optext,
					" StateID: 0x%04x Offset: %" G_GINT64_MODIFIER "u Len: %u",
					sid_hash, file_offset, length);
			break;

		case NFS4_OP_READDIR:
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_cookie, offset);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_cookie_verf,	offset);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_count_dircount, offset);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_count_maxcount, offset);
			offset = dissect_nfs4_fattrs(tvb, offset, pinfo, newftree, FATTR4_BITMAP_ONLY, civ);
			if (last_fh_hash != 0)
				g_string_append_printf (op_summary[ops_counter].optext, " FH: 0x%08x", last_fh_hash);
			break;

		case NFS4_OP_READLINK:
			break;

		case NFS4_OP_TEST_STATEID:
			offset = dissect_rpc_array(tvb, pinfo, newftree, offset, dissect_nfs4_test_stateid_arg, hf_nfs4_test_stateid_arg);
			break;

		case NFS4_OP_DESTROY_CLIENTID:
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_clientid, offset);
			break;
		case NFS4_OP_RECLAIM_COMPLETE:
			offset = dissect_rpc_bool(tvb, newftree, hf_nfs4_reclaim_one_fs, offset);
			break;

		case NFS4_OP_REMOVE:
			offset = dissect_nfs_utf8string(tvb, offset, newftree, hf_nfs4_component, &name);
			g_string_append_printf (op_summary[ops_counter].optext, " ");
			if (last_fh_hash != 0)
				g_string_append_printf (op_summary[ops_counter].optext, "DH: 0x%08x/", last_fh_hash);
			if (name != NULL)
				g_string_append_printf (op_summary[ops_counter].optext, "%s", name);
			break;

		case NFS4_OP_RENAME:
			offset = dissect_nfs_utf8string(tvb, offset, newftree, hf_nfs4_component, &source_name);
			offset = dissect_nfs_utf8string(tvb, offset, newftree, hf_nfs4_component, &dest_name);
			g_string_append_printf (op_summary[ops_counter].optext, " From: %s To: %s",
				source_name ? source_name : "Unknown", dest_name ? dest_name : "Unknown");
			break;

		case NFS4_OP_RENEW:
			clientid_array = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 8, ENC_ASCII);
			clientid_hash = crc16_ccitt(clientid_array, 8);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_clientid, offset);
			g_string_append_printf (op_summary[ops_counter].optext, " CID: 0x%04x", clientid_hash);

			break;

		case NFS4_OP_RESTOREFH:
			last_fh_hash = saved_fh_hash;
			break;

		case NFS4_OP_SAVEFH:
			saved_fh_hash = last_fh_hash;
			break;

		case NFS4_OP_SECINFO:
			offset = dissect_nfs_utf8string(tvb, offset, newftree,
				hf_nfs4_component, NULL);
			break;

		case NFS4_OP_SECINFO_NO_NAME:
			proto_tree_add_item(newftree, hf_nfs4_secinfo_style, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			break;

		case NFS4_OP_SETATTR:
			offset = dissect_nfs4_stateid(tvb, offset, newftree, NULL);
			offset = dissect_nfs4_fattrs(tvb, offset, pinfo, newftree, FATTR4_DISSECT_VALUES, civ);
			g_string_append_printf (op_summary[ops_counter].optext, " FH: 0x%08x", last_fh_hash);
			break;

		case NFS4_OP_SETCLIENTID:
			{
				proto_tree *client_tree = NULL;
				proto_tree *callback_tree = NULL;

				fitem = proto_tree_add_text(newftree, tvb, offset, 0, "client");

				client_tree = proto_item_add_subtree(fitem, ett_nfs4_client_id);

				offset = dissect_nfs4_client_id(tvb, offset, client_tree);

				fitem = proto_tree_add_text(newftree, tvb, offset, 0, "callback");
				callback_tree = proto_item_add_subtree(fitem,
						ett_nfs4_cb_client);

				offset = dissect_nfs4_cb_client4(tvb, offset, callback_tree);

				offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_callback_ident,
					offset);
			}
			break;

		case NFS4_OP_SETCLIENTID_CONFIRM:
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_clientid, offset);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_verifier, offset);
			break;

		case NFS4_OP_VERIFY:
			offset = dissect_nfs4_fattrs(tvb, offset, pinfo, newftree, FATTR4_DISSECT_VALUES, civ);
			break;

		case NFS4_OP_WRITE:
			offset = dissect_nfs4_stateid(tvb, offset, newftree, &sid_hash);
			file_offset = tvb_get_ntoh64(tvb, offset);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_offset, offset);
			offset = dissect_nfs4_stable_how(tvb, offset, newftree, "stable");
			string_length = tvb_get_ntohl(tvb, offset+0);
			dissect_rpc_uint32(tvb, newftree, hf_nfs4_write_data_length, offset); /* don't change offset */
			offset = dissect_nfsdata(tvb, offset, newftree, hf_nfs_data);
			if (sid_hash != 0)
				g_string_append_printf (op_summary[ops_counter].optext,
					" StateID: 0x%04x Offset: %"G_GINT64_MODIFIER"u Len: %u",
					sid_hash, file_offset, string_length);
			break;

		case NFS4_OP_RELEASE_LOCKOWNER:
			offset = dissect_nfs4_lock_owner(tvb, offset, newftree);
			break;

			/* Minor Version 1 */
		case NFS4_OP_BACKCHANNEL_CTL:
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_cb_program, offset);
			offset = dissect_rpc_secparms4(tvb, offset, newftree);
			break;
		case NFS4_OP_BIND_CONN_TO_SESSION:
			offset = dissect_nfs4_sessionid(tvb, offset, newftree);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_bctsa_dir, offset);
			offset = dissect_rpc_bool(tvb, newftree, hf_nfs4_bctsa_use_conn_in_rdma_mode, offset);
			break;

		case NFS4_OP_EXCHANGE_ID:
			{
			proto_tree *eia_clientowner_tree = NULL;
			proto_tree *eia_flags_tree = NULL;

			fitem = proto_tree_add_text(newftree, tvb, offset, 0, "eia_clientowner");
			eia_clientowner_tree = proto_item_add_subtree(fitem, ett_nfs4_clientowner);
			offset = dissect_rpc_uint64(tvb, eia_clientowner_tree, hf_nfs4_verifier, offset);
			offset = dissect_nfsdata(tvb, offset, eia_clientowner_tree, hf_nfs_data);

			fitem = proto_tree_add_item(newftree, hf_nfs4_exchid_call_flags, tvb, offset, 4,
				ENC_BIG_ENDIAN);
			eia_flags_tree = proto_item_add_subtree(fitem, ett_nfs4_exchangeid_call_flags);
			proto_tree_add_item(eia_flags_tree, hf_nfs4_exchid_flags_confirmed_r, tvb, offset, 4,
				ENC_BIG_ENDIAN);
			proto_tree_add_item(eia_flags_tree, hf_nfs4_exchid_flags_upd_conf_rec_a, tvb, offset, 4,
				ENC_BIG_ENDIAN);
			proto_tree_add_item(eia_flags_tree, hf_nfs4_exchid_flags_pnfs_ds, tvb, offset, 4,
				ENC_BIG_ENDIAN);
			proto_tree_add_item(eia_flags_tree, hf_nfs4_exchid_flags_pnfs_mds, tvb, offset, 4,
				ENC_BIG_ENDIAN);
			proto_tree_add_item(eia_flags_tree, hf_nfs4_exchid_flags_non_pnfs, tvb, offset, 4,
				ENC_BIG_ENDIAN);
			proto_tree_add_item(eia_flags_tree, hf_nfs4_exchid_flags_bind_princ, tvb, offset, 4,
				ENC_BIG_ENDIAN);
			proto_tree_add_item(eia_flags_tree, hf_nfs4_exchid_flags_moved_migr, tvb, offset, 4,
				ENC_BIG_ENDIAN);
			proto_tree_add_item(eia_flags_tree, hf_nfs4_exchid_flags_moved_refer, tvb, offset, 4,
				ENC_BIG_ENDIAN);
			offset += 4;

			offset = dissect_nfs4_state_protect_a(tvb, offset, newftree);
			offset = dissect_rpc_nfs_impl_id4(tvb, offset, newftree, "eia_client_impl_id");
			}
			break;

		case NFS4_OP_CREATE_SESSION:
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_clientid, offset);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_seqid, offset);
			offset = dissect_nfs_create_session_flags(tvb, offset, newftree,
				hf_nfs4_create_session_flags_csa);
			offset = dissect_rpc_chanattrs4(tvb, offset, newftree, "csa_fore_chan_attrs");
			offset = dissect_rpc_chanattrs4(tvb, offset, newftree, "csa_back_chan_attrs");
			cbprog = tvb_get_ntohl(tvb, offset);
			reg_callback(cbprog);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_cb_program, offset);
			offset = dissect_rpc_secparms4(tvb, offset, newftree);
			break;

		case NFS4_OP_DESTROY_SESSION:
			offset = dissect_nfs4_sessionid(tvb, offset, newftree);
			break;
		case NFS4_OP_FREE_STATEID:
			offset = dissect_nfs4_stateid(tvb, offset, newftree, &sid_hash);
			g_string_append_printf(op_summary[ops_counter].optext, " StateID: 0x%04x", sid_hash);
			break;

			/* pNFS */
		case NFS4_OP_LAYOUTGET:
			offset = dissect_rpc_bool(tvb, newftree, hf_nfs4_layout_avail, offset);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_layout_type, offset);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_iomode, offset);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_offset, offset);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_length, offset);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_length_minlength, offset);
			offset = dissect_nfs4_stateid(tvb, offset, newftree, NULL);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_count_maxcount,
										offset);
			break;

		case NFS4_OP_LAYOUTCOMMIT:
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_offset, offset);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_length, offset);
			offset = dissect_rpc_bool(tvb, newftree, hf_nfs4_reclaim, offset);
			offset = dissect_nfs4_stateid(tvb, offset, newftree, NULL);
			offset = dissect_nfs4_newoffset(tvb, offset, newftree);
			offset = dissect_nfs4_newtime(tvb, offset, newftree);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_layout_type, offset);
			offset = dissect_nfsdata(tvb, offset, newftree, hf_nfs4_layoutupdate);
			break;

		case NFS4_OP_LAYOUTRETURN:
			offset = dissect_rpc_bool(tvb, newftree, hf_nfs4_reclaim, offset);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_layout_type, offset);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_iomode, offset);
			offset = dissect_nfs4_layoutreturn(tvb, offset, newftree);
			break;

		case NFS4_OP_GETDEVINFO:
			offset = dissect_nfs4_deviceid(tvb, offset, newftree);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_layout_type, offset);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_count_maxcount, offset);
			offset = dissect_nfs4_notification_bitmap(tvb, newftree, offset);
			break;

		case NFS4_OP_GETDEVLIST:
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_layout_type, offset);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_count_maxcount, offset);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_cookie, offset);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_cookie_verf,	offset);
			break;

		case NFS4_OP_SEQUENCE:
			offset = dissect_nfs4_sessionid(tvb, offset, newftree);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_seqid, offset);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_slotid, offset);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_high_slotid, offset);
			offset = dissect_rpc_bool(tvb, newftree, hf_nfs4_cachethis, offset);
			break;

		/* In theory, it's possible to get this opcode */
		case NFS4_OP_ILLEGAL:
			break;

		default:
			break;
		}
	}

	/* Detect which tiers are present in this packet */
	for (summary_counter=0; summary_counter < ops_counter; summary_counter++)
	{
		current_tier = NFS4_OPERATION_TIER(op_summary[summary_counter].opcode);
		if (current_tier < highest_tier)
			highest_tier = current_tier;
	}

	/* Display packet summary */
	for (summary_counter=0; summary_counter < ops_counter; summary_counter++)
	{
		guint main_opcode;
		proto_item *main_op_item = NULL;

		main_opcode = op_summary[summary_counter].opcode;
		current_tier = NFS4_OPERATION_TIER(op_summary[summary_counter].opcode);

		/* Display summary info only for operations that are "most significant".
		   Controlled by a user option. */
		if (current_tier == highest_tier || !display_major_nfs4_ops) {
			if (current_tier == highest_tier) {
				const char *main_opname = NULL;

				/* Display a filterable field of the most significant operations in all cases. */
				main_opname = val_to_str_ext_const(main_opcode, &names_nfs4_operation_ext, "Unknown");
				main_op_item = proto_tree_add_uint_format_value(tree, hf_nfs4_main_opcode, tvb, 0, 0,
							      main_opcode, "%s (%u)", main_opname, main_opcode);
				PROTO_ITEM_SET_GENERATED(main_op_item);
			}

			if (first_operation == 0)
				/* Seperator between operation text */
				col_append_str(pinfo->cinfo, COL_INFO, " |");

			if (op_summary[summary_counter].optext->len > 0)
				col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
					op_summary[summary_counter].optext->str);

			first_operation = 0;
		}
	}

	for (ops_counter=0; ops_counter<ops; ops_counter++)
	{
		if (op_summary[ops_counter].optext)
			g_string_free(op_summary[ops_counter].optext, TRUE);
	}

	g_free(op_summary);

	return offset;
}


static int
dissect_nfs4_compound_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, void *data)
{
	const char *tag = NULL;

	offset = dissect_nfs_utf8string(tvb, offset, tree, hf_nfs4_tag, &tag);
	/*
	 * Display the NFSv4 tag.  If it is empty, string generator will have returned "<EMPTY>",
	 * in which case don't display anything */
	if (nfs_display_v4_tag && strncmp(tag, "<EMPTY>", 7) != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, " %s", tag);

	offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_minorversion, offset);
	offset = dissect_nfs4_request_op(tvb, offset, pinfo, tree, (rpc_call_info_value*)data);

	return offset;
}


static int
dissect_nfs4_secinfo_res(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree, void *data _U_)
{
	guint flavor;
	proto_item *fitem;
	proto_tree *secftree;

	flavor = tvb_get_ntohl(tvb, offset);
	fitem = proto_tree_add_uint(tree, hf_nfs4_secinfo_flavor, tvb, offset, 4,
		flavor);
	offset += 4;

	switch (flavor)
	{
		case RPCSEC_GSS:
			secftree = proto_item_add_subtree(fitem, ett_nfs4_secinfo_flavor_info);
			offset = dissect_nfs_rpcsec_gss_info(tvb, offset, secftree);
			break;

		default:
			break;
	}

	return offset;
}


static int
dissect_nfs4_response_op(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, rpc_call_info_value *civ)
{
	guint	    highest_tier    = 5;
	guint	    current_tier    = 5;
	guint	    first_operation = 1;
	guint16	    sid_hash	    = 0;
	guint32	    last_fh_hash    = 0;
	guint32	    ops, ops_counter;
	guint32	    summary_counter;
	guint32	    opcode, status;
	const char *opname;
	proto_item *fitem;
	proto_tree *ftree	    = NULL;
	proto_tree *newftree	    = NULL;
	nfs4_operation_summary *op_summary;

	ops = tvb_get_ntohl(tvb, offset+0);

	fitem = proto_tree_add_uint_format(tree, hf_nfs4_ops_count, tvb, offset+0, 4, ops,
		"Operations (count: %u)", ops);
	offset += 4;

	if (ops > MAX_NFSV4_OPS) {
		expert_add_info(pinfo, fitem, &ei_nfs_too_many_ops);
		ops = MAX_NFSV4_OPS;
	}

	op_summary = (nfs4_operation_summary *)g_malloc0(sizeof(nfs4_operation_summary) * ops);

	if (fitem) {
		ftree = proto_item_add_subtree(fitem, ett_nfs4_response_op);
	}

	proto_item_append_text(tree, ", Ops(%d):", ops);

	for (ops_counter = 0; ops_counter < ops; ops_counter++)
	{
		op_summary[ops_counter].optext = g_string_new("");
		opcode = tvb_get_ntohl(tvb, offset);
		op_summary[ops_counter].iserror = FALSE;
		op_summary[ops_counter].opcode = opcode;

		/* sanity check for bogus packets */
		if ((opcode < NFS4_OP_ACCESS || opcode > NFS4_OP_RECLAIM_COMPLETE) &&
			(opcode != NFS4_OP_ILLEGAL))
			break;

		fitem = proto_tree_add_uint(ftree, hf_nfs4_op, tvb, offset, 4, opcode);

		/* all of the V4 ops are contiguous, except for NFS4_OP_ILLEGAL */
		if (opcode == NFS4_OP_ILLEGAL) {
			newftree = proto_item_add_subtree(fitem, ett_nfs4_illegal);
		} else if (nfs4_operation_ett[opcode - 3]) {
			newftree = proto_item_add_subtree(fitem, *nfs4_operation_ett[opcode - 3]);
		} else {
			break;
		}

		opname = val_to_str_ext_const(opcode, &names_nfs4_operation_ext, "Unknown");
		offset += 4;
		g_string_append_printf (op_summary[ops_counter].optext, "%s", opname);

		offset = dissect_nfs4_status(tvb, offset, newftree, &status);
		if (status != NFS4_OK) {
			proto_item_append_text(tree, " %s(%s)", opname,
				val_to_str_ext(status, &names_nfs4_status_ext, "Unknown error: %u"));
		} else {
			proto_item_append_text(tree, " %s", opname);
		}

		/*
		 * With the exception of NFS4_OP_LOCK, NFS4_OP_LOCKT, and
		 * NFS4_OP_SETATTR, all other ops do *not* return data with the
		 * failed status code.
		 */
		if (status != NFS4_OK
		&& opcode != NFS4_OP_LOCK
		&& opcode != NFS4_OP_LOCKT
		&& opcode != NFS4_OP_SETATTR) {
			op_summary[ops_counter].iserror = TRUE;
			continue;
		}

		/* These parsing routines are only executed if the status is NFS4_OK */
		switch (opcode)
		{
		case NFS4_OP_ACCESS:
			offset = dissect_access_reply(tvb, offset, pinfo, fitem, 4,	op_summary[ops_counter].optext, civ);
			break;

		case NFS4_OP_CLOSE:
			offset = dissect_nfs4_stateid(tvb, offset, newftree, NULL);
			break;

		case NFS4_OP_COMMIT:
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_verifier, offset);
			break;

		case NFS4_OP_CREATE:
			offset = dissect_nfs4_change_info(tvb, offset, newftree, "change_info");
			offset = dissect_nfs4_fattrs(tvb, offset, pinfo, newftree, FATTR4_BITMAP_ONLY, civ);
			break;

		case NFS4_OP_GETATTR:
			offset = dissect_nfs4_fattrs(tvb, offset, pinfo, newftree, FATTR4_DISSECT_VALUES, civ);
			break;

		case NFS4_OP_GETFH:
			offset = dissect_nfs4_fh(tvb, offset, pinfo, newftree, "Filehandle", &last_fh_hash, civ);
			break;

		case NFS4_OP_LINK:
			offset = dissect_nfs4_change_info(tvb, offset, newftree, "change_info");
			break;

		case NFS4_OP_LOCK:
		case NFS4_OP_LOCKT:
			if (status == NFS4_OK)
			{
				if (opcode == NFS4_OP_LOCK)
					offset = dissect_nfs4_stateid(tvb, offset, newftree, NULL);
			}
			else
			if (status == NFS4ERR_DENIED)
				offset = dissect_nfs4_lockdenied(tvb, offset, newftree);
			break;

		case NFS4_OP_LOCKU:
			offset = dissect_nfs4_stateid(tvb, offset, newftree, NULL);
			break;

		case NFS4_OP_OPEN:
			offset = dissect_nfs4_stateid(tvb, offset, newftree, &sid_hash);
			offset = dissect_nfs4_change_info(tvb, offset, newftree,
				"change_info");
			offset = dissect_nfs4_open_rflags(tvb, offset, newftree);
			offset = dissect_nfs4_fattrs(tvb, offset, pinfo, newftree, FATTR4_BITMAP_ONLY, civ);
			offset = dissect_nfs4_open_delegation(tvb, offset, pinfo, newftree);
			g_string_append_printf (op_summary[ops_counter].optext, " StateID: 0x%04x", sid_hash);
			break;

		case NFS4_OP_OPEN_CONFIRM:
		case NFS4_OP_OPEN_DOWNGRADE:
			offset = dissect_nfs4_stateid(tvb, offset, newftree, NULL);
			break;

		case NFS4_OP_RESTOREFH:
		case NFS4_OP_SAVEFH:
		case NFS4_OP_PUTFH:
			break;

		case NFS4_OP_READ:
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_eof, offset);
			dissect_rpc_uint32(tvb, newftree, hf_nfs4_read_data_length, offset); /* don't change offset */
			offset = dissect_nfsdata(tvb, offset, newftree, hf_nfs_data);
			break;

		case NFS4_OP_READDIR:
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_verifier, offset);
			offset = dissect_nfs4_dirlist(tvb, offset, pinfo, newftree, civ);
			break;

		case NFS4_OP_READLINK:
			offset = dissect_nfs_utf8string(tvb, offset, newftree, hf_nfs4_linktext, NULL);
			break;

		case NFS4_OP_RECLAIM_COMPLETE:
			break;

		case NFS4_OP_REMOVE:
			offset = dissect_nfs4_change_info(tvb, offset, newftree, "change_info");
			break;

		case NFS4_OP_RENAME:
			offset = dissect_nfs4_change_info(tvb, offset, newftree, "source_cinfo");
			offset = dissect_nfs4_change_info(tvb, offset, newftree, "target_cinfo");
			break;

		case NFS4_OP_SECINFO:
		case NFS4_OP_SECINFO_NO_NAME:
			offset = dissect_rpc_array(tvb, pinfo, newftree, offset,
				dissect_nfs4_secinfo_res, hf_nfs4_secinfo_arr);
			break;

		case NFS4_OP_SETATTR:
			offset = dissect_nfs4_fattrs(tvb, offset, pinfo, newftree, FATTR4_BITMAP_ONLY, civ);
			break;

		case NFS4_OP_SETCLIENTID:
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_clientid,
				offset);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_verifier,
				offset);
			break;

		case NFS4_OP_WRITE:
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_count, offset);
			offset = dissect_nfs4_stable_how(tvb, offset, newftree,	"committed");
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_verifier, offset);
			break;

			/* Minor Version 1 */
		case NFS4_OP_BIND_CONN_TO_SESSION:
			offset = dissect_nfs4_sessionid(tvb, offset, newftree);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_bctsr_dir, offset);
			offset = dissect_rpc_bool(tvb, newftree, hf_nfs4_bctsr_use_conn_in_rdma_mode, offset);
			break;

		case NFS4_OP_EXCHANGE_ID: {
				proto_tree *eir_flags_tree = NULL;
				proto_tree *eir_server_owner_tree = NULL;

				offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_clientid, offset);
				offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_seqid, offset);

				fitem = proto_tree_add_item(newftree, hf_nfs4_exchid_reply_flags, tvb, offset, 4,
					ENC_BIG_ENDIAN);
				eir_flags_tree = proto_item_add_subtree(fitem, ett_nfs4_exchangeid_reply_flags);
				proto_tree_add_item(eir_flags_tree, hf_nfs4_exchid_flags_confirmed_r, tvb, offset, 4,
					ENC_BIG_ENDIAN);
				proto_tree_add_item(eir_flags_tree, hf_nfs4_exchid_flags_upd_conf_rec_a, tvb, offset, 4,
					ENC_BIG_ENDIAN);
				proto_tree_add_item(eir_flags_tree, hf_nfs4_exchid_flags_pnfs_ds, tvb, offset, 4,
					ENC_BIG_ENDIAN);
				proto_tree_add_item(eir_flags_tree, hf_nfs4_exchid_flags_pnfs_mds, tvb, offset, 4,
					ENC_BIG_ENDIAN);
				proto_tree_add_item(eir_flags_tree, hf_nfs4_exchid_flags_non_pnfs, tvb, offset, 4,
					ENC_BIG_ENDIAN);
				proto_tree_add_item(eir_flags_tree, hf_nfs4_exchid_flags_bind_princ, tvb, offset, 4,
					ENC_BIG_ENDIAN);
				proto_tree_add_item(eir_flags_tree, hf_nfs4_exchid_flags_moved_migr, tvb, offset, 4,
					ENC_BIG_ENDIAN);
				proto_tree_add_item(eir_flags_tree, hf_nfs4_exchid_flags_moved_refer, tvb, offset, 4,
					ENC_BIG_ENDIAN);
				offset += 4;

				offset = dissect_nfs4_state_protect_r(tvb, offset, newftree);

				fitem = proto_tree_add_text(newftree, tvb, offset, 0, "eir_server_owner");
				eir_server_owner_tree = proto_item_add_subtree(fitem, ett_nfs4_server_owner);
				offset = dissect_rpc_serverowner4(tvb, offset, eir_server_owner_tree);
				offset = dissect_nfsdata(tvb, offset, newftree, hf_nfs4_serverscope4);
				offset = dissect_rpc_nfs_impl_id4(tvb, offset, newftree, "eir_server_impl_id");
			}
			break;
		case NFS4_OP_CREATE_SESSION:
			offset = dissect_nfs4_sessionid(tvb, offset, newftree);
			offset = dissect_rpc_uint32(tvb, newftree,
					hf_nfs4_seqid, offset);
			offset = dissect_nfs_create_session_flags(tvb, offset, newftree,
				hf_nfs4_create_session_flags_csr);
			offset = dissect_rpc_chanattrs4(tvb, offset, newftree, "csr_fore_chan_attrs");
			offset = dissect_rpc_chanattrs4(tvb, offset, newftree, "csr_back_chan_attrs");
			break;

		case NFS4_OP_DESTROY_SESSION:
			break;
		case NFS4_OP_FREE_STATEID:
			break;
		case NFS4_OP_TEST_STATEID:
			offset = dissect_rpc_array(tvb, pinfo, newftree, offset, dissect_nfs4_test_stateid_res, hf_nfs4_test_stateid_res);
			break;

		case NFS4_OP_LAYOUTGET:
			offset = dissect_rpc_bool(tvb, newftree, hf_nfs4_return_on_close,
									  offset);
			offset = dissect_nfs4_stateid(tvb, offset, newftree, NULL);
			offset = dissect_nfs4_layout(tvb, offset, pinfo, newftree, civ);
			break;

		case NFS4_OP_LAYOUTCOMMIT:
			offset = dissect_nfs4_newsize(tvb, offset, newftree);
			break;

		case NFS4_OP_LAYOUTRETURN:
			offset = dissect_nfs_layoutreturn_stateid(tvb, newftree, offset);
			break;

		case NFS4_OP_GETDEVINFO:
			offset = dissect_nfs4_deviceaddr(tvb, offset, newftree);
			offset = dissect_nfs4_notification_bitmap(tvb, newftree, offset);
			break;

		case NFS4_OP_GETDEVLIST:
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_cookie, offset);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs4_cookie_verf,	offset);
			offset = dissect_nfs4_devicelist(tvb, offset, newftree);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_eof, offset);
			break;

		case NFS4_OP_SEQUENCE:
			{
			proto_tree *sf_tree = NULL;

			offset = dissect_nfs4_sessionid(tvb, offset, newftree);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_seqid, offset);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_slotid, offset);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_high_slotid, offset);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_target_high_slotid, offset);
			fitem = proto_tree_add_item(newftree, hf_nfs4_sequence_status_flags,
						tvb, offset, 4,	ENC_BIG_ENDIAN);
			sf_tree = proto_item_add_subtree(fitem, ett_nfs4_sequence_status_flags);
			proto_tree_add_item(sf_tree, hf_nfs4_sequence_status_flags_cb_path_down,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(sf_tree, hf_nfs4_sequence_status_flags_cb_gss_contexts_expiring,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(sf_tree, hf_nfs4_sequence_status_flags_cb_gss_contexts_expired,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(sf_tree, hf_nfs4_sequence_status_flags_expired_all_state_revoked,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(sf_tree, hf_nfs4_sequence_status_flags_expired_some_state_revoked,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(sf_tree, hf_nfs4_sequence_status_flags_admin_state_revoked,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(sf_tree, hf_nfs4_sequence_status_flags_recallable_state_revoked,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(sf_tree, hf_nfs4_sequence_status_flags_lease_moved,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(sf_tree, hf_nfs4_sequence_status_flags_restart_reclaim_needed,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(sf_tree, hf_nfs4_sequence_status_flags_cb_path_down_session,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(sf_tree, hf_nfs4_sequence_status_flags_backchannel_fault,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(sf_tree, hf_nfs4_sequence_status_flags_devid_changed,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(sf_tree, hf_nfs4_sequence_status_flags_devid_deleted,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			}
			break;

		default:
			break;
		}
	}

	/* Detect which tiers are present in this packet */
	for (summary_counter = 0; summary_counter < ops_counter; summary_counter++)
	{
		current_tier = NFS4_OPERATION_TIER(op_summary[summary_counter].opcode);
		if (current_tier < highest_tier)
			highest_tier = current_tier;
	}

	/* Display packet summary */
	for (summary_counter = 0; summary_counter < ops_counter; summary_counter++)
	{
		guint main_opcode;
		proto_item *main_op_item = NULL;

		main_opcode = op_summary[summary_counter].opcode;
		current_tier = NFS4_OPERATION_TIER(op_summary[summary_counter].opcode);

		/* Display summary info only for operations that are "most significant".
		 Controlled by a user option.
		 Display summary info for operations that return an error as well.  */
		if (current_tier == highest_tier
		|| !display_major_nfs4_ops
		|| op_summary[summary_counter].iserror == TRUE)
		{
			if (current_tier == highest_tier) {
				const char *main_opname = NULL;

				/* Display a filterable field of the most significant operations in all cases. */
				main_opname = val_to_str_ext_const(main_opcode, &names_nfs4_operation_ext, "Unknown");
				main_op_item = proto_tree_add_uint_format_value(tree, hf_nfs4_main_opcode, tvb, 0, 0,
									main_opcode, "%s (%u)", main_opname, main_opcode);
				PROTO_ITEM_SET_GENERATED(main_op_item);
			}

			if (first_operation == 0)
				/* Seperator between operation text */
				col_append_str(pinfo->cinfo, COL_INFO, " |");

			if (op_summary[summary_counter].optext->len > 0)
				col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
					op_summary[summary_counter].optext->str);
			first_operation = 0;
		}
	}

	for (ops_counter=0; ops_counter<ops; ops_counter++)
	{
		if (op_summary[ops_counter].optext)
			g_string_free(op_summary[ops_counter].optext, TRUE);
	}

	g_free(op_summary);

	return offset;
}


static int
dissect_nfs4_compound_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree, void *data)
{
	guint32	    status;
	const char *tag = NULL;

	offset = dissect_nfs4_status(tvb, offset, tree, &status);
	offset = dissect_nfs_utf8string(tvb, offset, tree, hf_nfs4_tag, &tag);
	/*
	* Display the NFSv4 tag. If it is empty, string generator will have returned "<EMPTY>", in
	* which case don't display anything */
	if (nfs_display_v4_tag && strncmp(tag, "<EMPTY>", 7) != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, " %s", tag);

	offset = dissect_nfs4_response_op(tvb, offset, pinfo, tree, (rpc_call_info_value*)data);

	if (status != NFS4_OK)
		col_append_fstr(pinfo->cinfo, COL_INFO, " Status: %s",
				val_to_str_ext(status, &names_nfs4_status_ext, "Unknown error: %u"));

	return offset;
}


/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: type of arguments is "void". */
static const vsff nfs3_proc[] = {
	{ 0,	"NULL",		/* OK */
	dissect_nfs3_null_call,		dissect_nfs3_null_reply },
	{ 1,	"GETATTR",	/* OK */
	dissect_nfs3_getattr_call,	dissect_nfs3_getattr_reply },
	{ 2,	"SETATTR",	/* OK */
	dissect_nfs3_setattr_call,	dissect_nfs3_setattr_reply },
	{ 3,	"LOOKUP",	/* OK */
	dissect_nfs3_lookup_call,	dissect_nfs3_lookup_reply },
	{ 4,	"ACCESS",	/* OK */
	dissect_nfs3_access_call,	dissect_nfs3_access_reply },
	{ 5,	"READLINK",	/* OK */
	dissect_nfs3_readlink_call,	dissect_nfs3_readlink_reply },
	{ 6,	"READ",		/* OK */
	dissect_nfs3_read_call,		dissect_nfs3_read_reply },
	{ 7,	"WRITE",	/* OK */
	dissect_nfs3_write_call,	dissect_nfs3_write_reply },
	{ 8,	"CREATE",	/* OK */
	dissect_nfs3_create_call,	dissect_nfs3_create_reply },
	{ 9,	"MKDIR",	/* OK */
	dissect_nfs3_mkdir_call,	dissect_nfs3_mkdir_reply },
	{ 10,	"SYMLINK",	/* OK */
	dissect_nfs3_symlink_call,	dissect_nfs3_symlink_reply },
	{ 11,	"MKNOD",	/* OK */
	dissect_nfs3_mknod_call,	dissect_nfs3_mknod_reply },
	{ 12,	"REMOVE",	/* OK */
	dissect_nfs3_remove_call,	dissect_nfs3_remove_reply },
	{ 13,	"RMDIR",	/* OK */
	dissect_nfs3_rmdir_call,	dissect_nfs3_rmdir_reply },
	{ 14,	"RENAME",	/* OK */
	dissect_nfs3_rename_call,	dissect_nfs3_rename_reply },
	{ 15,	"LINK",		/* OK */
	dissect_nfs3_link_call,		dissect_nfs3_link_reply },
	{ 16,	"READDIR",	/* OK */
	dissect_nfs3_readdir_call,	dissect_nfs3_readdir_reply },
	{ 17,	"READDIRPLUS",	/* OK */
	dissect_nfs3_readdirplus_call,	dissect_nfs3_readdirplus_reply },
	{ 18,	"FSSTAT",	/* OK */
	dissect_nfs3_fsstat_call,	dissect_nfs3_fsstat_reply },
	{ 19,	"FSINFO",	/* OK */
	dissect_nfs3_fsinfo_call,	dissect_nfs3_fsinfo_reply },
	{ 20,	"PATHCONF",	/* OK */
	dissect_nfs3_pathconf_call,	dissect_nfs3_pathconf_reply },
	{ 21,	"COMMIT",	/* OK */
	dissect_nfs3_commit_call,	dissect_nfs3_commit_reply },
	{ 0,	NULL,	NULL,	NULL }
};

static const value_string nfs3_proc_vals[] = {
	{ 0,	"NULL" },
	{ 1,	"GETATTR" },
	{ 2,	"SETATTR" },
	{ 3,	"LOOKUP" },
	{ 4,	"ACCESS" },
	{ 5,	"READLINK" },
	{ 6,	"READ" },
	{ 7,	"WRITE" },
	{ 8,	"CREATE" },
	{ 9,	"MKDIR" },
	{ 10,	"SYMLINK" },
	{ 11,	"MKNOD" },
	{ 12,	"REMOVE" },
	{ 13,	"RMDIR" },
	{ 14,	"RENAME" },
	{ 15,	"LINK" },
	{ 16,	"READDIR" },
	{ 17,	"READDIRPLUS" },
	{ 18,	"FSSTAT" },
	{ 19,	"FSINFO" },
	{ 20,	"PATHCONF" },
	{ 21,	"COMMIT" },
	{ 0,	NULL }
};
static value_string_ext nfs3_proc_vals_ext = VALUE_STRING_EXT_INIT(nfs3_proc_vals);

/* End of NFS Version 3 */


/* the call to dissect_nfs3_null_call & dissect_nfs3_null_reply is
 * intentional.  The V4 NULLPROC is the same as V3.
 */
static const vsff nfs4_proc[] = {
	{ 0, "NULL",
	dissect_nfs3_null_call,		dissect_nfs3_null_reply },
	{ 1, "COMPOUND",
	dissect_nfs4_compound_call, dissect_nfs4_compound_reply },
	{ 0, NULL, NULL, NULL }
};

static const value_string nfs4_proc_vals[] = {
	{ 0, "NULL" },
	{ 1, "COMPOUND" },
	{ 0, NULL }
};

/*
 * Union of the NFSv2, NFSv3, and NFSv4 status codes.
 * Used for the "nfs.status" hidden field and in packet-nfsacl.c.
 */
static const value_string names_nfs_nfsstat[] = {
	{    0,	 "OK"				     },
	{    1,	 "ERR_PERM"			     },
	{    2,	 "ERR_NOENT"			     },
	{    5,	 "ERR_IO"			     },
	{    6,	 "ERR_NXIO"			     },
	{    11, "ERR_EAGAIN"			     },
	{    13, "ERR_ACCESS"			     },
	{    17, "ERR_EXIST"			     },
	{    18, "ERR_XDEV"			     },
	{    19, "ERR_NODEV"			     },
	{    20, "ERR_NOTDIR"			     },
	{    21, "ERR_ISDIR"			     },
	{    22, "ERR_INVAL"			     },
	{    26, "ERR_TXTBSY"			     },
	{    27, "ERR_FBIG"			     },
	{    28, "ERR_NOSPC"			     },
	{    30, "ERR_ROFS"			     },
	{    31, "ERR_MLINK"			     },
	{    45, "ERR_OPNOTSUPP"		     },
	{    63, "ERR_NAMETOOLONG"		     },
	{    66, "ERR_NOTEMPTY"			     },
	{    69, "ERR_DQUOT"			     },
	{    70, "ERR_STALE"			     },
	{    71, "ERR_REMOTE"			     },
	{    99, "ERR_WFLUSH"			     },
	{ 10001, "ERR_BADHANDLE"		     },
	{ 10002, "ERR_NOT_SYNC"			     },
	{ 10003, "ERR_BAD_COOKIE"		     },
	{ 10004, "ERR_NOTSUPP"			     },
	{ 10005, "ERR_TOOSMALL"			     },
	{ 10006, "ERR_SERVERFAULT"		     },
	{ 10007, "ERR_BADTYPE"			     },
	{ 10008, "ERR_DELAY"			     },
	{ 10009, "ERR_SAME"			     },
	{ 10010, "ERR_DENIED"			     },
	{ 10011, "ERR_EXPIRED"			     },
	{ 10012, "ERR_LOCKED"			     },
	{ 10013, "ERR_GRACE"			     },
	{ 10014, "ERR_FHEXPIRED"		     },
	{ 10015, "ERR_SHARE_DENIED"		     },
	{ 10016, "ERR_WRONGSEC"			     },
	{ 10017, "ERR_CLID_INUSE"		     },
	{ 10018, "ERR_RESOURCE"			     },
	{ 10019, "ERR_MOVED"			     },
	{ 10020, "ERR_NOFILEHANDLE"		     },
	{ 10021, "ERR_MINOR_VERS_MISMATCH"	     },
	{ 10022, "ERR_STALE_CLIENTID"		     },
	{ 10023, "ERR_STALE_STATEID"		     },
	{ 10024, "ERR_OLD_STATEID"		     },
	{ 10025, "ERR_BAD_STATEID"		     },
	{ 10026, "ERR_BAD_SEQID"		     },
	{ 10027, "ERR_NOT_SAME"			     },
	{ 10028, "ERR_LOCK_RANGE"		     },
	{ 10029, "ERR_SYMLINK"			     },
	{ 10030, "ERR_READDIR_NOSPC"		     },
	{ 10031, "ERR_LEASE_MOVED"		     },
	{ 10032, "ERR_ATTRNOTSUPP"		     },
	{ 10033, "ERR_NO_GRACE"			     },
	{ 10034, "ERR_RECLAIM_BAD"		     },
	{ 10035, "ERR_RECLAIM_CONFLICT"		     },
	{ 10036, "ERR_BADXDR"			     },
	{ 10037, "ERR_LOCKS_HELD"		     },
	{ 10038, "ERR_OPENMODE"			     },
	{ 10039, "ERR_BADOWNER"			     },
	{ 10040, "ERR_BADCHAR"			     },
	{ 10041, "ERR_BADNAME"			     },
	{ 10042, "ERR_BAD_RANGE"		     },
	{ 10043, "ERR_LOCK_NOTSUPP"		     },
	{ 10044, "ERR_OP_ILLEGAL"		     },
	{ 10045, "ERR_DEADLOCK"			     },
	{ 10046, "ERR_FILE_OPEN"		     },
	{ 10047, "ERR_ADMIN_REVOKED"		     },
	{ 10048, "ERR_CB_PATH_DOWN"		     },
	{ 10049, "ERR_REPLAY_ME_or_BADIOMODE"	     },
	{ 10050, "ERR_BADLAYOUT"		     },
	{ 10051, "ERR_BAD_SESSION_DIGEST"	     },
	{ 10052, "ERR_BADSESSION"		     },
	{ 10053, "ERR_BADSLOT"			     },
	{ 10054, "ERR_COMPLETE_ALREADY"		     },
	{ 10055, "ERR_CONN_NOT_BOUND_TO_SESSION"     },
	{ 10056, "ERR_DELEG_ALREADY_WANTED"	     },
	{ 10057, "ERR_BACK_CHAN_BUSY"		     },
	{ 10058, "ERR_LAYOUTTRYLATER"		     },
	{ 10059, "ERR_LAYOUTUNAVAILABLE"	     },
	{ 10060, "ERR_NOMATCHING_LAYOUT"	     },
	{ 10061, "ERR_RECALLCONFLICT"		     },
	{ 10062, "ERR_UNKNOWN_LAYOUTTYPE"	     },
	{ 10063, "ERR_SEQ_MISORDERED"		     },
	{ 10064, "ERR_SEQUENCE_POS"		     },
	{ 10065, "ERR_REQ_TOO_BIG"		     },
	{ 10066, "ERR_REP_TOO_BIG"		     },
	{ 10067, "ERR_REP_TOO_BIG_TO_CACHE"	     },
	{ 10068, "ERR_RETRY_UNCACHED_REP"	     },
	{ 10069, "ERR_UNSAFE_COMPOUND"		     },
	{ 10070, "ERR_TOO_MANY_OPS"		     },
	{ 10071, "ERR_OP_NOT_IN_SESSION"	     },
	{ 10072, "ERR_HASH_ALG_UNSUPP"		     },
	{ 10073, "NFS4ERR_CONN_BINDING_NOT_ENFORCED" },
	{ 10074, "ERR_CLIENTID_BUSY"		     },
	{ 10075, "ERR_PNFS_IO_HOLE"		     },
	{ 10076, "ERR_SEQ_FALSE_RETRY"		     },
	{ 10077, "ERR_BAD_HIGH_SLOT"		     },
	{ 10078, "ERR_DEADSESSION"		     },
	{ 10079, "ERR_ENCR_ALG_UNSUPP"		     },
	{ 10080, "ERR_PNFS_NO_LAYOUT"		     },
	{ 10081, "ERR_NOT_ONLY_OP"		     },
	{ 10082, "ERR_WRONG_CRED"		     },
	{ 10083, "ERR_WRONG_TYPE"		     },
	{ 10084, "ERR_DIRDELEG_UNAVAIL"		     },
	{ 10085, "ERR_REJECT_DELEG"		     },
	{ 10086, "ERR_RETURNCONFLICT"		     },
	{ 10087, "ERR_DELEG_REVOKED"		     },
	{ 0,	NULL }
};
static value_string_ext names_nfs_nfsstat_ext = VALUE_STRING_EXT_INIT(names_nfs_nfsstat);

static const value_string iomode_names[] = {
	{ 1, "IOMODE_READ" },
	{ 2, "IOMODE_RW"   },
	{ 3, "IOMODE_ANY"  },
	{ 0, NULL }
};

#if 0
static const value_string stripetype_names[] = {
	{ 1, "STRIPE_SPARSE" },
	{ 2, "STRIPE_DENSE"  },
	{ 0, NULL }
};
#endif

static const value_string layouttype_names[] = {
	{ 1, "LAYOUT4_NFSV4_1_FILES" },
	{ 2, "LAYOUT4_OSD2_OBJECTS"  },
	{ 3, "LAYOUT4_BLOCK_VOLUME"  },
	{ 0, NULL }
};

static const value_string layoutreturn_names[] = {
	{ 1, "RETURN_FILE" },
	{ 2, "RETURN_FSID" },
	{ 3, "RETURN_ALL"  },
	{ 0, NULL }
};

static const value_string nfs_fh_obj_id[] = {
	{ 1, "NF4REG"      },
	{ 2, "NF4DIR"      },
	{ 3, "NF4BLK"      },
	{ 4, "NF4CHR"      },
	{ 5, "NF4LNK"      },
	{ 6, "NF4SOCK"     },
	{ 7, "NF4FIFO"     },
	{ 8, "NF4ATTRDIR"  },
	{ 9, "NF4NAMEDATTR"},
	{ 0, NULL }
};

static const true_false_string nfs4_ro_boolean = {
	"object is read only",
	"object is *not* read-only"
};

static const value_string layoutrecall_names[] = {
	{ 1, "RECALL_FILE" },
	{ 2, "RECALL_FSID" },
	{ 3, "RECALL_ALL"  },
	{ 0, NULL }
};

/* NFS Callback */
static int hf_nfs4_cb_procedure = -1;
static int hf_nfs4_cb_op = -1;
static int hf_nfs4_cb_truncate = -1;
static int hf_nfs4_cb_layoutrecall_type = -1;
static int hf_nfs4_cb_clorachanged = -1;

static gint ett_nfs4_cb_request_op = -1;
static gint ett_nfs4_cb_resop = -1;
static gint ett_nfs4_cb_getattr = -1;
static gint ett_nfs4_cb_recall = -1;
static gint ett_nfs4_cb_layoutrecall = -1;
static gint ett_nfs4_cb_pushdeleg = -1;
static gint ett_nfs4_cb_recallany = -1;
static gint ett_nfs4_cb_recallableobjavail = -1;
static gint ett_nfs4_cb_recallslot = -1;
static gint ett_nfs4_cb_sequence = -1;
static gint ett_nfs4_cb_wantscancelled = -1;
static gint ett_nfs4_cb_notifylock = -1;
static gint ett_nfs4_cb_notifydeviceid = -1;
static gint ett_nfs4_cb_notify = -1;
static gint ett_nfs4_cb_reflists = -1;
static gint ett_nfs4_cb_refcalls = -1;
static gint ett_nfs4_cb_illegal = -1;

static const value_string names_nfs_cb_operation[] = {
	{ NFS4_OP_CB_GETATTR,		   "CB_GETATTR" },
	{ NFS4_OP_CB_RECALL,		   "CB_RECALL"	},
	{ NFS4_OP_CB_LAYOUTRECALL,	   "CB_LAYOUTRECALL" },
	{ NFS4_OP_CB_NOTIFY,		   "CB_NOTIFY" },
	{ NFS4_OP_CB_PUSH_DELEG,	   "CB_PUSH_DELEG" },
	{ NFS4_OP_CB_RECALL_ANY,	   "CB_RECALL_ANY" },
	{ NFS4_OP_CB_RECALLABLE_OBJ_AVAIL, "CB_RECALLABLE_OBJ_AVAIL" },
	{ NFS4_OP_CB_RECALL_SLOT,	   "CB_RECALL_SLOT"},
	{ NFS4_OP_CB_SEQUENCE,		   "CB_SEQUENCE" },
	{ NFS4_OP_CB_WANTS_CANCELLED,	   "CB_WANTS_CANCELLED" },
	{ NFS4_OP_CB_NOTIFY_LOCK,	   "CB_NOTIFY_LOCK" },
	{ NFS4_OP_CB_NOTIFY_DEVICEID,	   "CB_NOTIFY_DEVICEID" },
	{ NFS4_OP_CB_ILLEGAL,		   "CB_ILLEGAL"},
	{ 0,	NULL }
};
static value_string_ext names_nfs_cb_operation_ext = VALUE_STRING_EXT_INIT(names_nfs_cb_operation);

static gint *nfs4_cb_operation_ett[] =
{
	&ett_nfs4_cb_getattr,
	&ett_nfs4_cb_recall,
	&ett_nfs4_cb_layoutrecall,
	&ett_nfs4_cb_notify,
	&ett_nfs4_cb_pushdeleg,
	&ett_nfs4_cb_recallany,
	&ett_nfs4_cb_recallableobjavail,
	&ett_nfs4_cb_recallslot,
	&ett_nfs4_cb_sequence,
	&ett_nfs4_cb_wantscancelled,
	&ett_nfs4_cb_notifylock,
	&ett_nfs4_cb_notifydeviceid,
	&ett_nfs4_cb_illegal
};

static int
dissect_nfs4_cb_referring_calls(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint	    num_reflists, num_refcalls, i, j;
	proto_item *rl_item, *rc_item;
	proto_tree *rl_tree, *rc_tree;

	num_reflists = tvb_get_ntohl(tvb, offset);
	rl_item = proto_tree_add_text(tree, tvb, offset, 4,
			"referring call lists (count: %u)", num_reflists);
	offset += 4;
	if (num_reflists == 0)
		return offset;

	rl_tree = proto_item_add_subtree(rl_item, ett_nfs4_cb_reflists);

	for (i = 0; i < num_reflists; i++) {
		offset = dissect_nfs4_sessionid(tvb, offset, rl_tree);
		num_refcalls = tvb_get_ntohl(tvb, offset);
		rc_item = proto_tree_add_text(rl_tree, tvb, offset, 4,
				"referring calls (count: %u)", num_refcalls);
		offset += 4;
		for (j = 0; j < num_refcalls; j++) {
			rc_tree = proto_item_add_subtree(rc_item, ett_nfs4_cb_refcalls);
			offset = dissect_rpc_uint32(tvb, rc_tree, hf_nfs4_seqid, offset);
			offset = dissect_rpc_uint32(tvb, rc_tree, hf_nfs4_slotid, offset);
		}
	}

	return offset;
}


static int
dissect_nfs4_cb_layoutrecall(tvbuff_t *tvb, int offset, proto_tree *tree, packet_info *pinfo, rpc_call_info_value *civ)
{
	guint recall_type;

	offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_layout_type, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_iomode, offset);
	offset = dissect_rpc_bool(tvb, tree, hf_nfs4_cb_clorachanged, offset);

	recall_type = tvb_get_ntohl(tvb, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_cb_layoutrecall_type, offset);

	if (recall_type == 1) { /* RECALL_FILE */
		offset = dissect_nfs4_fh(tvb, offset, pinfo, tree, "filehandle", NULL, civ);
		offset = dissect_rpc_uint64(tvb, tree, hf_nfs4_offset, offset);
		offset = dissect_rpc_uint64(tvb, tree, hf_nfs4_length, offset);
		offset = dissect_nfs4_stateid(tvb, offset, tree, NULL);
	} else if (recall_type == 2) { /* RECALL_FSID */
		offset = dissect_nfs4_fsid(tvb, offset, tree, "fsid");
	}

	return offset;
}


static int
dissect_nfs4_cb_request(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, rpc_call_info_value *civ)
{
	guint32	    ops, ops_counter;
	guint	    opcode;
	proto_item *fitem;
	proto_tree *ftree    = NULL;
	proto_tree *newftree = NULL;

	ops = tvb_get_ntohl(tvb, offset+0);

	fitem = proto_tree_add_text(tree, tvb, offset, 4, "Operations (count: %u)", ops);
	offset += 4;

	if (fitem)
	  	ftree = proto_item_add_subtree(fitem, ett_nfs4_cb_request_op);

	for (ops_counter=0; ops_counter<ops; ops_counter++)
	{
		opcode = tvb_get_ntohl(tvb, offset);
		col_append_fstr(pinfo->cinfo, COL_INFO, "%c%s", ops_counter == 0?' ':';',
				val_to_str_ext_const(opcode, &names_nfs_cb_operation_ext, "Unknown"));

		fitem = proto_tree_add_uint(ftree, hf_nfs4_cb_op, tvb, offset, 4, opcode);
		offset += 4;

	/* the opcodes are not contiguous */
		if ((opcode < NFS4_OP_CB_GETATTR || opcode > NFS4_OP_CB_NOTIFY_DEVICEID) &&
		    (opcode != NFS4_OP_CB_ILLEGAL))
		  	break;

	/* all of the V4 ops are contiguous, except for NFS4_OP_ILLEGAL */
		if (opcode == NFS4_OP_CB_ILLEGAL)
		  	newftree = proto_item_add_subtree(fitem, ett_nfs4_cb_illegal);
		else if (nfs4_cb_operation_ett[opcode - 3])
		  	newftree = proto_item_add_subtree(fitem, *nfs4_cb_operation_ett[opcode - 3]);
		else
		  	break;

		switch (opcode)
		{
		case NFS4_OP_CB_RECALL:
		  	offset = dissect_nfs4_stateid(tvb, offset, newftree, NULL);
			offset = dissect_rpc_bool(tvb, newftree, hf_nfs4_cb_truncate, offset);
			offset = dissect_nfs4_fh(tvb, offset, pinfo, newftree, "filehandle", NULL, civ);
			break;
		case NFS4_OP_CB_GETATTR:
		case NFS4_OP_CB_LAYOUTRECALL:
			offset = dissect_nfs4_cb_layoutrecall(tvb, offset, newftree, pinfo, civ);
			break;
		case NFS4_OP_CB_NOTIFY:
		case NFS4_OP_CB_PUSH_DELEG:
		case NFS4_OP_CB_RECALL_ANY:
		case NFS4_OP_CB_RECALLABLE_OBJ_AVAIL:
		case NFS4_OP_CB_RECALL_SLOT:
		  break;
		case NFS4_OP_CB_SEQUENCE:
			offset = dissect_nfs4_sessionid(tvb, offset, newftree);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_seqid, offset);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_slotid, offset);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_high_slotid, offset);
			offset = dissect_rpc_bool(tvb, newftree, hf_nfs4_cachethis, offset);
			offset = dissect_nfs4_cb_referring_calls(tvb, offset, newftree);
			break;
		case NFS4_OP_CB_WANTS_CANCELLED:
		case NFS4_OP_CB_NOTIFY_LOCK:
		case NFS4_OP_CB_NOTIFY_DEVICEID:
		  	break;
		case NFS4_OP_ILLEGAL:
		  	break;
		default:
		  	break;
		}
	}

	return offset;
}


static int
dissect_nfs4_cb_compound_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, void *data)
{
	const char *tag = NULL;

	offset = dissect_nfs_utf8string(tvb, offset, tree, hf_nfs4_tag, &tag);

	col_append_fstr(pinfo->cinfo, COL_INFO, " %s", tag);

	offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_minorversion, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs4_callback_ident, offset);
	offset = dissect_nfs4_cb_request(tvb, offset, pinfo, tree, (rpc_call_info_value*)data);

	return offset;
}


static int
dissect_nfs4_cb_resp_op(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
 	guint32	    ops, ops_counter;
	guint32	    opcode;
	proto_item *fitem;
	proto_tree *ftree    = NULL;
	proto_tree *newftree = NULL;
	guint32	    status;

	ops   = tvb_get_ntohl(tvb, offset+0);
	fitem = proto_tree_add_text(tree, tvb, offset, 4, "Operations (count: %u)", ops);
	offset += 4;

	if (fitem)
	  	ftree = proto_item_add_subtree(fitem, ett_nfs4_cb_resop);

	for (ops_counter = 0; ops_counter < ops; ops_counter++)
	{
		opcode = tvb_get_ntohl(tvb, offset);

		/* sanity check for bogus packets */
		if ((opcode < NFS4_OP_CB_GETATTR || opcode > NFS4_OP_CB_NOTIFY_DEVICEID) &&
			(opcode != NFS4_OP_ILLEGAL))
			break;

		col_append_fstr(pinfo->cinfo, COL_INFO, "%c%s",	ops_counter == 0?' ':';',
				val_to_str_ext_const(opcode, &names_nfs_cb_operation_ext, "Unknown"));

		fitem = proto_tree_add_uint(ftree, hf_nfs4_cb_op, tvb, offset, 4, opcode);
		offset += 4;

		/* all of the V4 ops are contiguous, except for NFS4_OP_ILLEGAL */
		if (opcode == NFS4_OP_ILLEGAL)
			newftree = proto_item_add_subtree(fitem, ett_nfs4_illegal);
		else if (nfs4_cb_operation_ett[opcode - 3])
			newftree = proto_item_add_subtree(fitem, *nfs4_cb_operation_ett[opcode - 3]);
		else
			break;

		offset = dissect_nfs4_status(tvb, offset, newftree, &status);

		/* are there any ops that return data with a failure (?) */
		if (status != NFS4_OK)
			continue;

		/* These parsing routines are only executed if the status is NFS4_OK */
		switch (opcode)
		{
		case NFS4_OP_CB_RECALL:
			break;
		case NFS4_OP_CB_GETATTR:
		case NFS4_OP_CB_LAYOUTRECALL:
		   	break;
		case NFS4_OP_CB_NOTIFY:
		case NFS4_OP_CB_PUSH_DELEG:
		case NFS4_OP_CB_RECALL_ANY:
		case NFS4_OP_CB_RECALLABLE_OBJ_AVAIL:
		case NFS4_OP_CB_RECALL_SLOT:
			break;
		case NFS4_OP_CB_SEQUENCE:
			offset = dissect_nfs4_sessionid(tvb, offset, newftree);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_seqid, offset);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_slotid, offset);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_high_slotid, offset);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs4_target_high_slotid, offset);
			break;
		case NFS4_OP_CB_WANTS_CANCELLED:
		case NFS4_OP_CB_NOTIFY_LOCK:
		case NFS4_OP_CB_NOTIFY_DEVICEID:
		   	break;
		case NFS4_OP_ILLEGAL:
			break;
		default:
		   	break;
		  }
	}

	return offset;
}


static int
dissect_nfs4_cb_compound_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
			      proto_tree *tree, void *data _U_)
{
	guint32	    status;
	const char *tag	= NULL;

	offset = dissect_nfs4_status(tvb, offset, tree, &status);
	offset = dissect_nfs_utf8string(tvb, offset, tree, hf_nfs4_tag, &tag);
	col_append_fstr(pinfo->cinfo, COL_INFO, " %s", tag);

	offset = dissect_nfs4_cb_resp_op(tvb, offset, pinfo, tree);

	return offset;
}


static const vsff nfs_cb_proc[] = {
	{ 0, "CB_NULL",
	  dissect_nfs3_null_call, dissect_nfs3_null_reply },
	{ 1, "CB_COMPOUND",
	  dissect_nfs4_cb_compound_call, dissect_nfs4_cb_compound_reply },
	{ 0, NULL, NULL, NULL }
};

static const value_string nfs_cb_proc_vals[] = {
	{ 0, "CB_NULL" },
	{ 1, "CB_COMPOUND" },
	{ 0, NULL }
};

void reg_callback(int cbprog)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_nfs, cbprog, ett_nfs);

	/*
	 * Register the procedure tables.  The version should be 4,
	 * but some Linux kernels set this field to 1.  "Temporarily",
	 * accomodate these servers.
	 */
	rpc_init_proc_table(cbprog, 1, nfs_cb_proc, hf_nfs4_cb_procedure);
	rpc_init_proc_table(cbprog, 4, nfs_cb_proc, hf_nfs4_cb_procedure);
}

void
proto_register_nfs(void)
{
	static hf_register_info hf[] = {
		{ &hf_nfs2_procedure, {
			"V2 Procedure", "nfs.procedure_v2", FT_UINT32, BASE_DEC | BASE_EXT_STRING,
			&nfs2_proc_vals_ext, 0, NULL, HFILL }},
		{ &hf_nfs3_procedure, {
			"V3 Procedure", "nfs.procedure_v3", FT_UINT32, BASE_DEC | BASE_EXT_STRING,
			&nfs3_proc_vals_ext, 0, NULL, HFILL }},
		{ &hf_nfs4_procedure, {
			"V4 Procedure", "nfs.procedure_v4", FT_UINT32, BASE_DEC,
			VALS(nfs4_proc_vals), 0, NULL, HFILL }},
#if 0
		{ &hf_nfs4_impl_id_len, {
			"Implementation ID length", "nfs.impl_id4.length", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
#endif
		{ &hf_nfs_fh_length, {
			"length", "nfs.fh.length", FT_UINT32, BASE_DEC,
			NULL, 0, "file handle length", HFILL }},
		{ &hf_nfs_fh_hash, {
			"hash (CRC-32)", "nfs.fh.hash", FT_UINT32, BASE_HEX,
			NULL, 0, "file handle hash", HFILL }},
		{ &hf_nfs_fh_mount_fileid, {
			"fileid", "nfs.fh.mount.fileid", FT_UINT32, BASE_DEC,
			NULL, 0, "mount point fileid", HFILL }},
		{ &hf_nfs_fh_mount_generation, {
			"generation", "nfs.fh.mount.generation", FT_UINT32, BASE_HEX,
			NULL, 0, "mount point generation", HFILL }},
		{ &hf_nfs_fh_flags, {
			"Flags", "nfs.fh.flags", FT_UINT16, BASE_HEX,
			NULL, 0, "file handle flags", HFILL }},
		{ &hf_nfs_fh_snapid, {
			"snapid", "nfs.fh.snapid", FT_UINT8, BASE_DEC,
			NULL, 0, "snapshot ID", HFILL }},
		{ &hf_nfs_fh_unused, {
			"unused", "nfs.fh.unused", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfs_fh_fileid, {
			"fileid", "nfs.fh.fileid", FT_UINT32, BASE_DEC,
			NULL, 0, "file ID", HFILL }},
		{ &hf_nfs_fh_generation, {
			"generation", "nfs.fh.generation", FT_UINT32, BASE_HEX,
			NULL, 0, "inode generation", HFILL }},
		{ &hf_nfs_fh_fsid, {
			"fsid", "nfs.fh.fsid", FT_UINT32, BASE_HEX,
			NULL, 0, "file system ID", HFILL }},
		{ &hf_nfs_fh_export_fileid, {
			"fileid", "nfs.fh.export.fileid", FT_UINT32, BASE_DEC,
			NULL, 0, "export point fileid", HFILL }},
		{ &hf_nfs_fh_export_generation, {
			"generation", "nfs.fh.export.generation", FT_UINT32, BASE_HEX,
			NULL, 0, "export point generation", HFILL }},
		{ &hf_nfs_fh_export_snapid, {
			"snapid", "nfs.fh.export.snapid", FT_UINT8, BASE_DEC,
			NULL, 0, "export point snapid", HFILL }},
		{ &hf_nfs_fh_exportid, {
			"exportid", "nfs.fh.exportid", FT_GUID, BASE_NONE,
			NULL, 0, "Gluster/NFS exportid", HFILL }},
		{ &hf_nfs_fh_handle_type, {
			"Handle type", "nfs.fh.handletype", FT_UINT32, BASE_DEC,
			NULL, 0, "v4 handle type", HFILL }},
		{ &hf_nfs_fh_file_flag_mntpoint, {
			"mount point", "nfs.fh.file.flag.mntpoint", FT_UINT16, BASE_HEX,
			VALS(netapp_file_flag_vals), 0x0001, "file flag: mountpoint", HFILL }},
		{ &hf_nfs_fh_file_flag_snapdir, {
			"snapdir", "nfs.fh.file.flag.snapdir", FT_UINT16, BASE_HEX,
			VALS(netapp_file_flag_vals), 0x0002, "file flag: snapdir", HFILL }},
		{ &hf_nfs_fh_file_flag_snapdir_ent, {
			"snapdir_ent", "nfs.fh.file.flag.snadir_ent", FT_UINT16, BASE_HEX,
			VALS(netapp_file_flag_vals), 0x0004, "file flag: snapdir_ent", HFILL }},
		{ &hf_nfs_fh_file_flag_empty, {
			"empty", "nfs.fh.file.flag.empty", FT_UINT16, BASE_HEX,
			VALS(netapp_file_flag_vals), 0x0008, "file flag: empty", HFILL }},
		{ &hf_nfs_fh_file_flag_vbn_access, {
			"vbn_access", "nfs.fh.file.flag.vbn_access", FT_UINT16, BASE_HEX,
			VALS(netapp_file_flag_vals), 0x0010, "file flag: vbn_access", HFILL }},
		{ &hf_nfs_fh_file_flag_multivolume, {
			"multivolume", "nfs.fh.file.flag.multivolume", FT_UINT16, BASE_HEX,
			VALS(netapp_file_flag_vals), 0x0020, "file flag: multivolume", HFILL }},
		{ &hf_nfs_fh_file_flag_metadata, {
			"metadata", "nfs.fh.file.flag.metadata", FT_UINT16, BASE_HEX,
			VALS(netapp_file_flag_vals), 0x0040, "file flag: metadata", HFILL }},
		{ &hf_nfs_fh_file_flag_orphan, {
			"orphan", "nfs.fh.file.flag.orphan", FT_UINT16, BASE_HEX,
			VALS(netapp_file_flag_vals), 0x0080, "file flag: orphan", HFILL }},
		{ &hf_nfs_fh_file_flag_foster, {
			"foster", "nfs.fh.file.flag.foster", FT_UINT16, BASE_HEX,
			VALS(netapp_file_flag_vals), 0x0100, "file flag: foster", HFILL }},
		{ &hf_nfs_fh_file_flag_named_attr, {
			"named_attr", "nfs.fh.file.flag.named_attr", FT_UINT16, BASE_HEX,
			VALS(netapp_file_flag_vals), 0x0200, "file flag: named_attr", HFILL }},
		{ &hf_nfs_fh_file_flag_exp_snapdir, {
			"exp_snapdir", "nfs.fh.file.flag.exp_snapdir", FT_UINT16, BASE_HEX,
			VALS(netapp_file_flag_vals), 0x0400, "file flag: exp_snapdir", HFILL }},
		{ &hf_nfs_fh_file_flag_vfiler, {
			"vfiler", "nfs.fh.file.flag.vfiler", FT_UINT16, BASE_HEX,
			VALS(netapp_file_flag_vals), 0x0800, "file flag: vfiler", HFILL }},
		{ &hf_nfs_fh_file_flag_aggr, {
			"aggr", "nfs.fh.file.flag.aggr", FT_UINT16, BASE_HEX,
			VALS(netapp_file_flag_vals), 0x1000, "file flag: aggr", HFILL }},
		{ &hf_nfs_fh_file_flag_striped, {
			"striped", "nfs.fh.file.flag.striped", FT_UINT16, BASE_HEX,
			VALS(netapp_file_flag_vals), 0x2000, "file flag: striped", HFILL }},
		{ &hf_nfs_fh_file_flag_private, {
			"private", "nfs.fh.file.flag.private", FT_UINT16, BASE_HEX,
			VALS(netapp_file_flag_vals), 0x4000, "file flag: private", HFILL }},
		{ &hf_nfs_fh_file_flag_next_gen, {
			"next_gen", "nfs.fh.file.flag.next_gen", FT_UINT16, BASE_HEX,
			VALS(netapp_file_flag_vals), 0x8000, "file flag: next_gen", HFILL }},
		{ &hf_nfs_fh_fsid_major, {
			"major", "nfs.fh.fsid.major", FT_UINT32, BASE_DEC,
			NULL, 0, "major file system ID", HFILL }},
		{ &hf_nfs_fh_fsid_minor, {
			"minor", "nfs.fh.fsid.minor", FT_UINT32, BASE_DEC,
			NULL, 0, "minor file system ID", HFILL }},
		{ &hf_nfs_fh_fsid_inode, {
			"inode", "nfs.fh.fsid.inode", FT_UINT32, BASE_DEC,
			NULL, 0, "file system inode", HFILL }},
		{ &hf_nfs_fh_gfid, {
			"gfid", "nfs.fh.gfid", FT_GUID, BASE_NONE,
			NULL, 0, "Gluster/NFS GFID", HFILL }},
		{ &hf_nfs_fh_xfsid_major, {
			"exported major", "nfs.fh.xfsid.major", FT_UINT32, BASE_DEC,
			NULL, 0, "exported major file system ID", HFILL }},
		{ &hf_nfs_fh_xfsid_minor, {
			"exported minor", "nfs.fh.xfsid.minor", FT_UINT32, BASE_DEC,
			NULL, 0, "exported minor file system ID", HFILL }},
		{ &hf_nfs_fh_fstype, {
			"file system type", "nfs.fh.fstype", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfs_fh_fn, {
			"file number", "nfs.fh.fn", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfs_fh_fn_len, {
			"length", "nfs.fh.fn.len", FT_UINT32, BASE_DEC,
			NULL, 0, "file number length", HFILL }},
		{ &hf_nfs_fh_fn_inode, {
			"inode", "nfs.fh.fn.inode", FT_UINT32, BASE_DEC,
			NULL, 0, "file number inode", HFILL }},
		{ &hf_nfs_fh_fn_generation, {
			"generation", "nfs.fh.fn.generation", FT_UINT32, BASE_DEC,
			NULL, 0, "file number generation", HFILL }},
		{ &hf_nfs_fh_xfn, {
			"exported file number", "nfs.fh.xfn", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfs_fh_xfn_len, {
			"length", "nfs.fh.xfn.len", FT_UINT32, BASE_DEC,
			NULL, 0, "exported file number length", HFILL }},
		{ &hf_nfs_fh_xfn_inode, {
			"exported inode", "nfs.fh.xfn.inode", FT_UINT32, BASE_DEC,
			NULL, 0, "exported file number inode", HFILL }},
		{ &hf_nfs_fh_xfn_generation, {
			"generation", "nfs.fh.xfn.generation", FT_UINT32, BASE_DEC,
			NULL, 0, "exported file number generation", HFILL }},
		{ &hf_nfs_fh_dentry, {
			"dentry", "nfs.fh.dentry", FT_UINT32, BASE_HEX,
			NULL, 0, "dentry (cookie)", HFILL }},
#if 0
		{ &hf_nfs_fh_dev, {
			"device", "nfs.fh.dev", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
#endif
#if 0
		{ &hf_nfs_fh_xdev, {
			"exported device", "nfs.fh.xdev", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
#endif
		{ &hf_nfs_fh_dirinode, {
			"directory inode", "nfs.fh.dirinode", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfs_fh_pinode, {
			"pseudo inode", "nfs.fh.pinode", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfs_fh_hp_len, {
			"length", "nfs.fh.hp.len", FT_UINT32, BASE_DEC,
			NULL, 0, "hash path length", HFILL }},
		{ &hf_nfs_fh_version, {
			"version", "nfs.fh.version", FT_UINT8, BASE_DEC,
			NULL, 0, "file handle layout version", HFILL }},
		{ &hf_nfs_fh_auth_type, {
			"auth_type", "nfs.fh.auth_type", FT_UINT8, BASE_DEC,
			VALS(auth_type_names), 0, "authentication type", HFILL }},
		{ &hf_nfs_fh_fsid_type, {
			"fsid_type", "nfs.fh.fsid_type", FT_UINT8, BASE_DEC,
			VALS(fsid_type_names), 0, "file system ID type", HFILL }},
		{ &hf_nfs_fh_fileid_type, {
			"fileid_type", "nfs.fh.fileid_type", FT_UINT8, BASE_DEC,
			VALS(fileid_type_names), 0, "file ID type", HFILL }},
		{ &hf_nfs_fh_obj_id, {
			"Object type", "nfs.fh.obj.id", FT_UINT32, BASE_DEC,
			VALS(nfs_fh_obj_id), 0, "Object ID", HFILL }},
		{ &hf_nfs_fh_ro_node, {
			"RO_node", "nfs.fh.ro.node", FT_BOOLEAN, BASE_NONE,
			TFS(&nfs4_ro_boolean), 0, "Read Only Node", HFILL }},
		{ &hf_nfs_fh_obj, {
			"Object info", "nfs.fh.obj.info", FT_BYTES, BASE_NONE,
			NULL, 0, "File/Dir/Object Info", HFILL }},
		{ &hf_nfs_fh_obj_fsid, {
			"obj_fsid", "nfs.fh.obj.fsid", FT_UINT32, BASE_DEC,
			NULL, 0, "File system ID of the object", HFILL }},
		{ &hf_nfs_fh_obj_kindid, {
			"obj_kindid", "nfs.fh.obj.kindid", FT_UINT16, BASE_DEC,
			NULL, 0, "KindID of the object", HFILL }},
		{ &hf_nfs_fh_obj_treeid, {
			"obj_treeid", "nfs.fh.obj.treeid", FT_UINT16, BASE_DEC,
			NULL, 0, "TreeID of the object", HFILL }},
		{ &hf_nfs_fh_obj_inode, {
			"obj_inode", "nfs.fh.obj.inode", FT_UINT32, BASE_DEC,
			NULL, 0, "Inode of the object", HFILL }},
		{ &hf_nfs_fh_obj_gen, {
			"obj_gen", "nfs.fh.obj.gen", FT_UINT32, BASE_DEC,
			NULL, 0, "Generation ID of the object", HFILL }},
		{ &hf_nfs_fh_ex, {
			"Export info", "nfs.fh.ex.info", FT_BYTES, BASE_NONE,
			NULL, 0, "Export Info (16 bytes)", HFILL }},
		{ &hf_nfs_fh_ex_fsid, {
			"ex_fsid", "nfs.fh.ex.fsid", FT_UINT32, BASE_DEC,
			NULL, 0, "File system ID of the object", HFILL }},
		{ &hf_nfs_fh_ex_kindid, {
			"ex_kindid", "nfs.fh.ex.kindid", FT_UINT16, BASE_DEC,
			NULL, 0, "KindID of the object", HFILL }},
		{ &hf_nfs_fh_ex_treeid, {
			"ex_treeid", "nfs.fh.ex.treeid", FT_UINT16, BASE_DEC,
			NULL, 0, "TreeID of the object", HFILL }},
		{ &hf_nfs_fh_ex_inode, {
			"ex_inode", "nfs.fh.ex.inode", FT_UINT32, BASE_DEC,
			NULL, 0, "Inode of the object", HFILL }},
		{ &hf_nfs_fh_ex_gen, {
			"ex_gen", "nfs.fh.ex.gen", FT_UINT32, BASE_DEC,
			NULL, 0, "Generation ID of the object", HFILL }},
		{ &hf_nfs_fh_flag, {
			"flag", "nfs.fh.flag", FT_UINT32, BASE_HEX,
			NULL, 0, "file handle flag", HFILL }},
		{ &hf_nfs_fh_endianness, {
			"endianness", "nfs.fh.endianness", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_endianness), 0x0, "server native endianness", HFILL }},
		{ &hf_nfs2_status, {
			"Status", "nfs.status2", FT_UINT32, BASE_DEC|BASE_EXT_STRING,
			&names_nfs2_stat_ext, 0, "Reply status", HFILL }},
		{ &hf_nfs_full_name, {
			"Full Name", "nfs.full_name", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfs_name, {
			"Name", "nfs.name", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfs2_readlink_data, {
			"Data", "nfs.readlink.data", FT_STRING, BASE_NONE,
			NULL, 0, "Symbolic Link Data", HFILL }},
		{ &hf_nfs2_read_offset, {
			"Offset", "nfs.read.offset", FT_UINT32, BASE_DEC,
			NULL, 0, "Read Offset", HFILL }},
		{ &hf_nfs2_read_count, {
			"Count", "nfs.read.count", FT_UINT32, BASE_DEC,
			NULL, 0, "Read Count", HFILL }},
		{ &hf_nfs2_read_totalcount, {
			"Total Count", "nfs.read.totalcount", FT_UINT32, BASE_DEC,
			NULL, 0, "Total Count (obsolete)", HFILL }},
		{ &hf_nfs_data, {
			"Data", "nfs.data", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfs4_read_data_length, {
			"Read length", "nfs.read.data_length", FT_UINT32, BASE_DEC,
			NULL, 0, "Length of read response", HFILL }},
		{ &hf_nfs4_write_data_length, {
			"Write length", "nfs.write.data_length", FT_UINT32, BASE_DEC,
			NULL, 0, "Length of write request", HFILL }},
		{ &hf_nfs2_write_beginoffset, {
			"Begin Offset", "nfs.write.beginoffset", FT_UINT32, BASE_DEC,
			NULL, 0, "Begin offset (obsolete)", HFILL }},
		{ &hf_nfs2_write_offset, {
			"Offset", "nfs.write.offset", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfs2_write_totalcount, {
			"Total Count", "nfs.write.totalcount", FT_UINT32, BASE_DEC,
			NULL, 0, "Total Count (obsolete)", HFILL }},
		{ &hf_nfs_symlink_to, {
			"To", "nfs.symlink.to", FT_STRING, BASE_NONE,
			NULL, 0, "Symbolic link destination name", HFILL }},
		{ &hf_nfs2_readdir_cookie, {
			"Cookie", "nfs.readdir.cookie", FT_UINT32, BASE_DEC,
			NULL, 0, "Directory Cookie", HFILL }},
		{ &hf_nfs2_readdir_count, {
			"Count", "nfs.readdir.count", FT_UINT32, BASE_DEC,
			NULL, 0, "Directory Count", HFILL }},

		{ &hf_nfs_readdir_entry, {
			"Entry", "nfs.readdir.entry", FT_NONE, BASE_NONE,
			NULL, 0, "Directory Entry", HFILL }},

		{ &hf_nfs2_readdir_entry_fileid, {
			"File ID", "nfs.readdir.entry.fileid", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs2_readdir_entry_name, {
			"Name", "nfs.readdir.entry.name", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs2_readdir_entry_cookie, {
			"Cookie", "nfs.readdir.entry.cookie", FT_UINT32, BASE_DEC,
			NULL, 0, "Directory Cookie", HFILL }},

		{ &hf_nfs3_readdir_entry_fileid, {
			"File ID", "nfs.readdir.entry3.fileid", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_readdir_entry_name, {
			"Name", "nfs.readdir.entry3.name", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_readdir_entry_cookie, {
			"Cookie", "nfs.readdir.entry3.cookie", FT_UINT64, BASE_DEC,
			NULL, 0, "Directory Cookie", HFILL }},

		{ &hf_nfs3_readdirplus_entry_fileid, {
			"File ID", "nfs.readdirplus.entry.fileid", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_readdirplus_entry_name, {
			"Name", "nfs.readdirplus.entry.name", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_readdirplus_entry_cookie, {
			"Cookie", "nfs.readdirplus.entry.cookie", FT_UINT64, BASE_DEC,
			NULL, 0, "Directory Cookie", HFILL }},

		{ &hf_nfs_readdir_eof, {
			"EOF", "nfs.readdir.eof", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs2_statfs_tsize, {
			"Transfer Size", "nfs.statfs.tsize", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfs2_statfs_bsize, {
			"Block Size", "nfs.statfs.bsize", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfs2_statfs_blocks, {
			"Total Blocks", "nfs.statfs.blocks", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfs2_statfs_bfree, {
			"Free Blocks", "nfs.statfs.bfree", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfs2_statfs_bavail, {
			"Available Blocks", "nfs.statfs.bavail", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfs3_ftype, {
			"Type", "nfs.type", FT_UINT32, BASE_DEC|BASE_EXT_STRING,
			&names_nfs_ftype3_ext, 0, "File Type", HFILL }},
		{ &hf_nfs3_status, {
			"Status", "nfs.status3", FT_UINT32, BASE_DEC|BASE_EXT_STRING,
			&names_nfs3_status_ext, 0, "Reply status", HFILL }},
		{ &hf_nfs3_read_eof, {
			"EOF", "nfs.read.eof", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},
		{ &hf_nfs3_write_stable, {
			"Stable", "nfs.write.stable", FT_UINT32, BASE_DEC,
			VALS(names_stable_how), 0, NULL, HFILL }},
		{ &hf_nfs3_write_committed, {
			"Committed", "nfs.write.committed", FT_UINT32, BASE_DEC,
			VALS(names_stable_how), 0, NULL, HFILL }},
		{ &hf_nfs3_createmode, {
			"Create Mode", "nfs.createmode", FT_UINT32, BASE_DEC,
			VALS(names_createmode3), 0, NULL, HFILL }},
		{ &hf_nfs3_fsstat_invarsec, {
			"invarsec", "nfs.fsstat.invarsec", FT_UINT32, BASE_DEC,
			NULL, 0, "probable number of seconds of file system invariance", HFILL }},
		{ &hf_nfs3_fsinfo_rtmax, {
			"rtmax", "nfs.fsinfo.rtmax", FT_UINT32, BASE_DEC,
			NULL, 0, "maximum READ request", HFILL }},
		{ &hf_nfs3_fsinfo_rtpref, {
			"rtpref", "nfs.fsinfo.rtpref", FT_UINT32, BASE_DEC,
			NULL, 0, "Preferred READ request size", HFILL }},
		{ &hf_nfs3_fsinfo_rtmult, {
			"rtmult", "nfs.fsinfo.rtmult", FT_UINT32, BASE_DEC,
			NULL, 0, "Suggested READ multiple", HFILL }},
		{ &hf_nfs3_fsinfo_wtmax, {
			"wtmax", "nfs.fsinfo.wtmax", FT_UINT32, BASE_DEC,
			NULL, 0, "Maximum WRITE request size", HFILL }},
		{ &hf_nfs3_fsinfo_wtpref, {
			"wtpref", "nfs.fsinfo.wtpref", FT_UINT32, BASE_DEC,
			NULL, 0, "Preferred WRITE request size", HFILL }},
		{ &hf_nfs3_fsinfo_wtmult, {
			"wtmult", "nfs.fsinfo.wtmult", FT_UINT32, BASE_DEC,
			NULL, 0, "Suggested WRITE multiple", HFILL }},
		{ &hf_nfs3_fsinfo_dtpref, {
			"dtpref", "nfs.fsinfo.dtpref", FT_UINT32, BASE_DEC,
			NULL, 0, "Preferred READDIR request", HFILL }},
		{ &hf_nfs3_fsinfo_maxfilesize, {
			"maxfilesize", "nfs.fsinfo.maxfilesize", FT_UINT64, BASE_DEC,
			NULL, 0, "Maximum file size", HFILL }},
		{ &hf_nfs3_fsinfo_properties, {
			"Properties", "nfs.fsinfo.properties", FT_UINT32, BASE_HEX,
			NULL, 0, "File System Properties", HFILL }},
		{ &hf_nfs3_fsinfo_properties_setattr, {
			"SETATTR can set time on server", "nfs.fsinfo.properties.setattr", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), FSF3_CANSETTIME, NULL, HFILL }},
		{ &hf_nfs3_fsinfo_properties_pathconf, {
			"PATHCONF", "nfs.fsinfo.properties.pathconf", FT_BOOLEAN, 32,
			TFS(&tfs_nfs_pathconf), FSF3_HOMOGENEOUS, NULL, HFILL }},
		{ &hf_nfs3_fsinfo_properties_symlinks, {
			"File System supports symbolic links", "nfs.fsinfo.properties.symlinks", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), FSF3_SYMLINK, NULL, HFILL }},
		{ &hf_nfs3_fsinfo_properties_hardlinks, {
			"File System supports hard links", "nfs.fsinfo.properties.hardlinks", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), FSF3_LINK, NULL, HFILL }},
		{ &hf_nfs3_pathconf_linkmax, {
			"linkmax", "nfs.pathconf.linkmax", FT_UINT32, BASE_DEC,
			NULL, 0, "Maximum number of hard links", HFILL }},
		{ &hf_nfs3_pathconf_name_max, {
			"name_max", "nfs.pathconf.name_max", FT_UINT32, BASE_DEC,
			NULL, 0, "Maximum file name length", HFILL }},
		{ &hf_nfs3_pathconf_no_trunc, {
			"no_trunc", "nfs.pathconf.no_trunc", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, "No long file name truncation", HFILL }},
		{ &hf_nfs3_pathconf_chown_restricted, {
			"chown_restricted", "nfs.pathconf.chown_restricted", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, "chown is restricted to root", HFILL }},
		{ &hf_nfs3_pathconf_case_insensitive, {
			"case_insensitive", "nfs.pathconf.case_insensitive", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, "file names are treated case insensitive", HFILL }},
		{ &hf_nfs3_pathconf_case_preserving, {
			"case_preserving", "nfs.pathconf.case_preserving", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, "file name cases are preserved", HFILL }},

#if 0
		{ &hf_nfs2_fattr_type, {
			"type", "nfs.fattr.type", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
#endif

		{ &hf_nfs2_fattr_nlink, {
			"nlink", "nfs.fattr.nlink", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs2_fattr_uid, {
			"uid", "nfs.fattr.uid", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs2_fattr_gid, {
			"gid", "nfs.fattr.gid", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs2_fattr_size, {
			"size", "nfs.fattr.size", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs2_fattr_blocksize, {
			"blocksize", "nfs.fattr.blocksize", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs2_fattr_rdev, {
			"rdev", "nfs.fattr.rdev", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs2_fattr_blocks, {
			"blocks", "nfs.fattr.blocks", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs2_fattr_fsid, {
			"fsid", "nfs.fattr.fsid", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs2_fattr_fileid, {
			"fileid", "nfs.fattr.fileid", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_fattr_type, {
			"Type", "nfs.fattr3.type", FT_UINT32, BASE_DEC|BASE_EXT_STRING,
			&names_nfs_ftype3_ext, 0, NULL, HFILL }},

		{ &hf_nfs3_fattr_nlink, {
			"nlink", "nfs.fattr3.nlink", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_fattr_uid, {
			"uid", "nfs.fattr3.uid", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_fattr_gid, {
			"gid", "nfs.fattr3.gid", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_fattr_size, {
			"size", "nfs.fattr3.size", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_fattr_used, {
			"used", "nfs.fattr3.used", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

#if 0
		{ &hf_nfs3_fattr_rdev, {
			"rdev", "nfs.fattr3.rdev", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
#endif

		{ &hf_nfs3_fattr_fsid, {
			"fsid", "nfs.fattr3.fsid", FT_UINT64, BASE_HEX_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_fattr_fileid, {
			"fileid", "nfs.fattr3.fileid", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_wcc_attr_size, {
			"size", "nfs.wcc_attr.size", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_set_size, {
			"size", "nfs.set_size", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_uid, {
			"uid", "nfs.uid3", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_gid, {
			"gid", "nfs.gid3", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_cookie, {
			"cookie", "nfs.cookie3", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_offset, {
			"offset", "nfs.offset3", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_count, {
			"count", "nfs.count3", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_count_maxcount, {
			"maxcount", "nfs.count3_maxcount", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_count_dircount, {
			"dircount", "nfs.count3_dircount", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_fsstat_resok_tbytes, {
			"Total bytes", "nfs.fsstat3_resok.tbytes", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_fsstat_resok_fbytes, {
			"Free bytes", "nfs.fsstat3_resok.fbytes", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_fsstat_resok_abytes, {
			"Available free bytes", "nfs.fsstat3_resok.abytes", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_fsstat_resok_tfiles, {
			"Total file slots", "nfs.fsstat3_resok.tfiles", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_fsstat_resok_ffiles, {
			"Free file slots", "nfs.fsstat3_resok.ffiles", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_fsstat_resok_afiles, {
			"Available free file slots", "nfs.fsstat3_resok.afiles", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		/* NFSv4 */

		{ &hf_nfs4_status, {
			"Status", "nfs.nfsstat4", FT_UINT32, BASE_DEC|BASE_EXT_STRING,
			&names_nfs4_status_ext, 0, "Reply status", HFILL }},

		{ &hf_nfs4_op, {
			"Opcode", "nfs.opcode", FT_UINT32, BASE_DEC|BASE_EXT_STRING,
			&names_nfs4_operation_ext, 0, NULL, HFILL }},

		{ &hf_nfs4_main_opcode, {
			"Main Opcode", "nfs.main_opcode", FT_UINT32, BASE_DEC|BASE_EXT_STRING,
			&names_nfs4_operation_ext, 0, "Main Operation number", HFILL }},

		{ &hf_nfs4_linktext, {
			"Name", "nfs.symlink.linktext", FT_STRING, BASE_NONE,
			NULL, 0, "Symbolic link contents", HFILL }},

		{ &hf_nfs4_dir_entry_name, {
			"Name", "nfs.entry_name", FT_STRING, BASE_NONE,
			NULL, 0, "Directory entry name", HFILL }},

		{ &hf_nfs4_component, {
			"Name", "nfs.pathname.component", FT_STRING, BASE_NONE,
			NULL, 0, "Pathname component", HFILL }},

		{ &hf_nfs4_tag, {
			"Tag", "nfs.tag", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_ops_count, {
			"Operations", "nfs.ops.count", FT_UINT32, BASE_DEC,
			NULL, 0, "Number of Operations", HFILL }},

		{ &hf_nfs4_clientid, {
			"clientid", "nfs.clientid", FT_UINT64, BASE_HEX,
			NULL, 0, "Client ID", HFILL }},

#if 0
		{ &hf_nfs4_ace, {
			"ace", "nfs.ace", FT_STRING, BASE_NONE,
			NULL, 0, "Access Control Entry", HFILL }},
#endif

		{ &hf_nfs4_recall, {
			"Recall", "nfs.recall", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},

		{ &hf_nfs4_open_claim_type, {
			"Claim Type", "nfs.open.claim_type", FT_UINT32, BASE_DEC,
			VALS(names_claim_type4), 0, NULL, HFILL }},

		{ &hf_nfs4_opentype, {
			"Open Type", "nfs.open.opentype", FT_UINT32, BASE_DEC,
			VALS(names_opentype4), 0, NULL, HFILL }},

		{ &hf_nfs4_state_protect_how, {
			"eia_state_protect", "nfs.exchange_id.state_protect", FT_UINT32, BASE_DEC,
			VALS(names_state_protect_how4), 0, "State Protect How", HFILL }},

		{ &hf_nfs4_limit_by, {
			"Space Limit", "nfs.open.limit_by", FT_UINT32, BASE_DEC,
			VALS(names_limit_by4), 0, "Limit By", HFILL }},

		{ &hf_nfs4_open_delegation_type, {
			"Delegation Type", "nfs.open.delegation_type", FT_UINT32, BASE_DEC,
			VALS(names_open_delegation_type4), 0, NULL, HFILL }},

		{ &hf_nfs4_why_no_delegation, {
			"why no delegation", "nfs.open.why_no_delegation", FT_UINT32, BASE_DEC,
			VALS(names_why_no_delegation4), 0, NULL, HFILL }},

		{ &hf_nfs4_secinfo_style, {
			"Secinfo Style", "nfs.secinfo.style", FT_UINT32, BASE_DEC,
			VALS(names_secinfo_style4), 0, NULL, HFILL }},

		{ &hf_nfs4_ftype, {
			"ftype4", "nfs.nfs_ftype4", FT_UINT32, BASE_DEC,
			VALS(names_ftype4), 0, NULL, HFILL }},

		{ &hf_nfs4_change_info_atomic, {
			"Atomic", "nfs.change_info.atomic", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},

		{ &hf_nfs4_open_share_access, {
			"share_access", "nfs.open4.share_access", FT_UINT32, BASE_DEC | BASE_EXT_STRING,
			&names_open4_share_access_ext, 0, NULL, HFILL }},

		{ &hf_nfs4_open_share_deny, {
			"share_deny", "nfs.open4.share_deny", FT_UINT32, BASE_DEC,
			VALS(names_open4_share_deny), 0, NULL, HFILL }},

		{ &hf_nfs4_want_flags, {
			"wants", "nfs.want", FT_UINT32, BASE_HEX | BASE_EXT_STRING,
			&names_open4_share_access_ext, 0, NULL, HFILL }},

		{ &hf_nfs4_want_notify_flags, {
			"want notification", "nfs.want_notification", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_want_signal_deleg_when_resrc_avail, {
			"want_signal_deleg_when_resrc_avail",
			"nfs.want_notification.when_resrc_avail", FT_BOOLEAN, 32,
			TFS(&tfs_set_notset), OPEN4_SHARE_ACCESS_WANT_SIGNAL_DELEG_WHEN_RESRC_AVAIL, NULL, HFILL }},

		{ &hf_nfs4_want_push_deleg_when_uncontended, {
			"want_push_deleg_when_uncontended",
			"nfs.want_push_deleg_when_uncontended", FT_BOOLEAN, 32,
			TFS(&tfs_set_notset), OPEN4_SHARE_ACCESS_WANT_PUSH_DELEG_WHEN_UNCONTENDED, NULL, HFILL }},

		{ &hf_nfs4_seqid, {
			"seqid", "nfs.seqid", FT_UINT32, BASE_HEX,
			NULL, 0, "Sequence ID", HFILL }},

		{ &hf_nfs4_lock_seqid, {
			"lock_seqid", "nfs.lock_seqid", FT_UINT32, BASE_HEX,
			NULL, 0, "Lock Sequence ID", HFILL }},

		{ &hf_nfs4_reqd_attr, {
			"reqd_attr", "nfs.attr", FT_UINT32, BASE_DEC | BASE_EXT_STRING,
			&fattr4_names_ext, 0, "Required Attribute", HFILL }},

		{ &hf_nfs4_reco_attr, {
			"reco_attr", "nfs.attr", FT_UINT32, BASE_DEC | BASE_EXT_STRING,
			&fattr4_names_ext, 0, "Recommended Attribute", HFILL }},

		{ &hf_nfs4_attr_mask, {
			"Attr mask", "nfs.attr_mask", FT_UINT32, BASE_HEX,
			NULL, 0, "ACL attribute mask", HFILL }},

		{ &hf_nfs4_time_how,	{
			"set_it", "nfs.set_it", FT_UINT32, BASE_DEC,
			VALS(names_time_how4), 0, "How To Set Time", HFILL }},

		{ &hf_nfs4_fattr_link_support, {
			"fattr4_link_support", "nfs.fattr4_link_support", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},

		{ &hf_nfs4_fattr_symlink_support, {
			"fattr4_symlink_support", "nfs.fattr4_symlink_support", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},

		{ &hf_nfs4_fattr_named_attr, {
			"fattr4_named_attr", "nfs.fattr4_named_attr", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},

		{ &hf_nfs4_fattr_unique_handles, {
			"fattr4_unique_handles", "nfs.fattr4_unique_handles", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},

		{ &hf_nfs4_fattr_archive, {
			"fattr4_archive", "nfs.fattr4_archive", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},

		{ &hf_nfs4_fattr_cansettime, {
			"fattr4_cansettime", "nfs.fattr4_cansettime", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},

		{ &hf_nfs4_fattr_case_insensitive, {
			"fattr4_case_insensitive", "nfs.fattr4_case_insensitive", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},

		{ &hf_nfs4_fattr_case_preserving, {
			"fattr4_case_preserving", "nfs.fattr4_case_preserving", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},

		{ &hf_nfs4_fattr_chown_restricted, {
			"fattr4_chown_restricted", "nfs.fattr4_chown_restricted", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},

		{ &hf_nfs4_fattr_hidden, {
			"fattr4_hidden", "nfs.fattr4_hidden", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},

		{ &hf_nfs4_fattr_homogeneous, {
			"fattr4_homogeneous", "nfs.fattr4_homogeneous", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},

		{ &hf_nfs4_fattr_mimetype, {
			"fattr4_mimetype", "nfs.fattr4_mimetype", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_fattr_no_trunc, {
			"fattr4_no_trunc", "nfs.fattr4_no_trunc", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},

		{ &hf_nfs4_fattr_system, {
			"fattr4_system", "nfs.fattr4_system", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},

		{ &hf_nfs4_who, {
			"Who", "nfs.who", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_server, {
			"server", "nfs.server", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_fslocation, {
			"fs_location4", "nfs.fattr4.fs_location", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_fattr_owner, {
			"fattr4_owner", "nfs.fattr4_owner", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_fattr_owner_group, {
			"fattr4_owner_group", "nfs.fattr4_owner_group", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_stable_how, {
			"stable_how4", "nfs.stable_how4", FT_UINT32, BASE_DEC,
			VALS(names_stable_how4), 0, NULL, HFILL }},

		{ &hf_nfs4_dirlist_eof, {
			"EOF", "nfs.dirlist4.eof", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, "There are no more entries", HFILL }},

#if 0
		{ &hf_nfs4_stateid, {
			"stateid", "nfs.stateid4", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},
#endif

		{ &hf_nfs4_offset, {
			"offset", "nfs.offset4", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_specdata1, {
			"specdata1", "nfs.specdata1", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_specdata2, {
			"specdata2", "nfs.specdata2", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_lock_type, {
			"locktype", "nfs.locktype4", FT_UINT32, BASE_DEC,
			VALS(names_nfs_lock_type4), 0, NULL, HFILL }},

		{ &hf_nfs4_open_rflags, {
			"results_flags", "nfs.open_rflags", FT_UINT32, BASE_HEX,
			VALS(names_nfs_lock_type4), 0, NULL, HFILL }},

		{ &hf_nfs4_open_rflags_mlock, {
			"mlock", "nfs.open_rflags.mlock", FT_UINT32, BASE_DEC,
			VALS(names_open4_result_flags), OPEN4_RESULT_MLOCK, NULL, HFILL }},

		{ &hf_nfs4_open_rflags_confirm, {
			"confirm", "nfs.open_rflags.confirm", FT_UINT32, BASE_DEC,
			VALS(names_open4_result_flags), OPEN4_RESULT_CONFIRM, NULL, HFILL }},

		{ &hf_nfs4_reclaim, {
			"reclaim", "nfs.reclaim4", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},

		{ &hf_nfs4_length, {
			"length", "nfs.length4", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_changeid, {
			"changeid", "nfs.changeid4", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_changeid_before, {
			"changeid (before)", "nfs.changeid4.before", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_changeid_after, {
			"changeid (after)", "nfs.changeid4.after", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_time_seconds, {
			"seconds", "nfs.nfstime4.seconds", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_time_nseconds, {
			"nseconds", "nfs.nfstime4.nseconds", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_fsid_major, {
			"fsid4.major", "nfs.fsid4.major", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_fsid_minor, {
			"fsid4.minor", "nfs.fsid4.minor", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_acetype, {
			"acetype", "nfs.acetype4", FT_UINT32, BASE_DEC,
			VALS(names_acetype4), 0, NULL, HFILL }},

		{ &hf_nfs4_aceflags, {
			"ACE flags", "nfs.aceflags4", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_aceflag, {
			"flag", "nfs.aceflag4", FT_UINT32, BASE_HEX,
			VALS(aceflag_names4), 0, NULL, HFILL }},

		{ &hf_nfs4_acemask, {
			"ACE mask", "nfs.acemask4", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_ace_permission, {
			"perm", "nfs.ace_perm4", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_fattr_size, {
			"size", "nfs.fattr4.size", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_fattr_lease_time, {
			"lease_time", "nfs.fattr4.lease_time", FT_UINT32, BASE_DEC,
			NULL, 0, "Duration of the lease at server in seconds", HFILL }},

		{ &hf_nfs4_fattr_aclsupport, {
			"aclsupport", "nfs.fattr4.aclsupport", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_fattr_fileid, {
			"fileid", "nfs.fattr4.fileid", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_fattr_files_avail, {
			"files_avail", "nfs.fattr4.files_avail", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_fattr_files_free, {
			"files_free", "nfs.fattr4.files_free", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_fattr_files_total, {
			"files_total", "nfs.fattr4.files_total", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_fattr_maxfilesize, {
			"maxfilesize", "nfs.fattr4.maxfilesize", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_fattr_maxlink, {
			"maxlink", "nfs.fattr4.maxlink", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_fattr_maxname, {
			"maxname", "nfs.fattr4.maxname", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_fattr_numlinks, {
			"numlinks", "nfs.fattr4.numlinks", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_delegate_type, {
			"delegate_type", "nfs.delegate_type", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_secinfo_flavor, {
			"flavor", "nfs.secinfo.flavor", FT_UINT32, BASE_DEC,
			VALS(rpc_auth_flavor), 0, NULL, HFILL }},

		{ &hf_nfs4_num_blocks, {
			"num_blocks", "nfs.num_blocks", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_bytes_per_block, {
			"bytes_per_block", "nfs.bytes_per_block", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_eof, {
			"eof", "nfs.eof", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_fattr_maxread, {
			"maxread", "nfs.fattr4.maxread", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_fattr_maxwrite, {
			"maxwrite", "nfs.fattr4.maxwrite", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_fattr_quota_hard, {
			"quota_hard", "nfs.fattr4.quota_hard", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_fattr_quota_soft, {
			"quota_soft", "nfs.fattr4.quota_soft", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_fattr_quota_used, {
			"quota_used", "nfs.fattr4.quota_used", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_fattr_space_avail, {
			"space_avail", "nfs.fattr4.space_avail", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_fattr_space_free, {
			"space_free", "nfs.fattr4.space_free", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_fattr_space_total, {
			"space_total", "nfs.fattr4.space_total", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_fattr_space_used, {
			"space_used", "nfs.fattr4.space_used", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_fattr_mounted_on_fileid, {
			"fileid", "nfs.fattr4.mounted_on_fileid", FT_UINT64, BASE_HEX,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_fattr_layout_blksize, {
			"fileid", "nfs.fattr4.layout_blksize", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_fattr_security_label_lfs, {
			"label_format", "nfs.fattr4.security_label.lfs", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_fattr_security_label_pi, {
			"policy_id", "nfs.fattr4.security_label.pi", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_fattr_security_label_context, {
			"context", "nfs.fattr4.security_label.context", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_verifier, {
			"verifier", "nfs.verifier4", FT_UINT64, BASE_HEX,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_value_follows, {
			"Value Follows", "nfs.value_follows", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},

		{ &hf_nfs4_cookie, {
			"cookie", "nfs.cookie4", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_cookie_verf, {
			"cookie_verf", "nfs.cookie_verf4", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

#if 0
		{ &hf_nfs4_cb_location, {
			"cb_location", "nfs.cb_location", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
#endif

		{ &hf_nfs4_cb_program, {
			"cb_program", "nfs.cb_program", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_recall4, {
			"recall", "nfs.recall4", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},

		{ &hf_nfs4_filesize, {
			"filesize", "nfs.filesize", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_count, {
			"count", "nfs.count4", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_count_dircount, {
			"dircount", "nfs.dircount", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_count_maxcount, {
			"maxcount", "nfs.maxcount", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_minorversion, {
			"minorversion", "nfs.minorversion", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs_atime, {
			"atime", "nfs.atime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
			NULL, 0, "Access Time", HFILL }},

		{ &hf_nfs_atime_sec, {
			"seconds", "nfs.atime.sec", FT_UINT32, BASE_DEC,
			NULL, 0, "Access Time, Seconds", HFILL }},

		{ &hf_nfs_atime_nsec, {
			"nano seconds", "nfs.atime.nsec", FT_UINT32, BASE_DEC,
			NULL, 0, "Access Time, Nano-seconds", HFILL }},

		{ &hf_nfs_atime_usec, {
			"micro seconds", "nfs.atime.usec", FT_UINT32, BASE_DEC,
			NULL, 0, "Access Time, Micro-seconds", HFILL }},

		{ &hf_nfs_mtime, {
			"mtime", "nfs.mtime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
			NULL, 0, "Modify Time", HFILL }},

		{ &hf_nfs_mtime_sec, {
			"seconds", "nfs.mtime.sec", FT_UINT32, BASE_DEC,
			NULL, 0, "Modify Seconds", HFILL }},

		{ &hf_nfs_mtime_nsec, {
			"nano seconds", "nfs.mtime.nsec", FT_UINT32, BASE_DEC,
			NULL, 0, "Modify Time, Nano-seconds", HFILL }},

		{ &hf_nfs_mtime_usec, {
			"micro seconds", "nfs.mtime.usec", FT_UINT32, BASE_DEC,
			NULL, 0, "Modify Time, Micro-seconds", HFILL }},

		{ &hf_nfs_ctime, {
			"ctime", "nfs.ctime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
			NULL, 0, "Creation Time", HFILL }},

		{ &hf_nfs_ctime_sec, {
			"seconds", "nfs.ctime.sec", FT_UINT32, BASE_DEC,
			NULL, 0, "Creation Time, Seconds", HFILL }},

		{ &hf_nfs_ctime_nsec, {
			"nano seconds", "nfs.ctime.nsec", FT_UINT32, BASE_DEC,
			NULL, 0, "Creation Time, Nano-seconds", HFILL }},

		{ &hf_nfs_ctime_usec, {
			"micro seconds", "nfs.ctime.usec", FT_UINT32, BASE_DEC,
			NULL, 0, "Creation Time, Micro-seconds", HFILL }},

		{ &hf_nfs_dtime, {
			"time delta", "nfs.dtime", FT_RELATIVE_TIME, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs_dtime_sec, {
			"seconds", "nfs.dtime.sec", FT_UINT32, BASE_DEC,
			NULL, 0, "Time Delta, Seconds", HFILL }},

		{ &hf_nfs_dtime_nsec, {
			"nano seconds", "nfs.dtime.nsec", FT_UINT32, BASE_DEC,
			NULL, 0, "Time Delta, Nano-seconds", HFILL }},

		{ &hf_nfs4_open_owner, {
			"owner", "nfs.open_owner4", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},

#if 0
		{ &hf_nfs4_lock_owner, {
			"owner", "nfs.lock_owner4", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},
#endif

		{ &hf_nfs4_createmode, {
			"Create Mode", "nfs.createmode4", FT_UINT32, BASE_DEC,
			VALS(names_createmode4), 0, NULL, HFILL }},

		{ &hf_nfs4_secinfo_rpcsec_gss_info_service, {
			"service", "nfs.secinfo.rpcsec_gss_info.service", FT_UINT32, BASE_DEC,
			VALS(rpc_authgss_svc), 0, NULL, HFILL }},

		{ &hf_nfs4_attr_dir_create, {
			"attribute dir create", "nfs.openattr4.createdir", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},

		{ &hf_nfs4_new_lock_owner, {
			"new lock owner?", "nfs.lock.locker.new_lock_owner", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},

		{ &hf_nfs4_lock_reclaim, {
			"reclaim?", "nfs.lock.reclaim", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},

		{ &hf_nfs4_sec_oid, {
			"oid", "nfs.secinfo.flavor_info.rpcsec_gss_info.oid", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_qop, {
			"qop", "nfs.secinfo.flavor_info.rpcsec_gss_info.qop", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_client_id, {
			"id", "nfs.nfs_client_id4.id", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_stateid_other, {
			"Data", "nfs.stateid4.other", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_stateid_hash, {
			"StateID Hash", "nfs.stateid4.hash", FT_UINT16, BASE_HEX,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_acl, {
			"ACL", "nfs.acl", FT_NONE, BASE_NONE, NULL, 0, "Access Control List", HFILL }},

		{ &hf_nfs4_num_aces, {
			"ACE count", "nfs.num_aces", FT_UINT32, BASE_DEC,
			NULL, 0, "Number of ACEs", HFILL }},

		{ &hf_nfs4_callback_ident, {
			"callback_ident", "nfs.callback.ident", FT_UINT32, BASE_HEX,
			NULL, 0, "Callback Identifier", HFILL }},

		{ &hf_nfs4_gsshandle, {
			"gsshandle4", "nfs.gsshandle4", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_r_netid, {
			"r_netid", "nfs.r_netid", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_r_addr, {
			"r_addr", "nfs.r_addr", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs_fh_fhandle_data, {
			"filehandle", "nfs.fhandle", FT_BYTES, BASE_NONE,
			NULL, 0, "Opaque nfs filehandle", HFILL }},

		{ &hf_nfs4_secinfo_arr, {
			"Flavors Info", "nfs.flavors.info", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_gxfh_utlfield, {
			"utility", "nfs.gxfh3.utility", FT_UINT8, BASE_HEX,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_gxfh_utlfield_tree_r, {
			"tree R", "nfs.gxfh3.utlfield.treeR", FT_UINT8, BASE_HEX,
			NULL, NFS3GX_FH_TREE_MASK, NULL, HFILL }},

		{ &hf_nfs3_gxfh_utlfield_tree_w, {
			"tree W", "nfs.gxfh3.utlfield.treeW", FT_UINT8, BASE_HEX,
			NULL, NFS3GX_FH_TREE_MASK, NULL, HFILL }},

		{ &hf_nfs3_gxfh_utlfield_jun, {
			"broken junction", "nfs.gxfh3.utlfield.junction", FT_UINT8, BASE_HEX,
			NULL, NFS3GX_FH_JUN_MASK, NULL, HFILL }},

		{ &hf_nfs3_gxfh_utlfield_jun_not, {
			"not broken junction", "nfs.gxfh3.utlfield.notjunction", FT_UINT8, BASE_HEX,
			NULL, NFS3GX_FH_JUN_MASK, NULL, HFILL }},

		{ &hf_nfs3_gxfh_utlfield_ver, {
			"file handle version", "nfs.gxfh3.utlfield.version", FT_UINT8, BASE_HEX,
			NULL, NFS3GX_FH_VER_MASK, NULL, HFILL }},

		{ &hf_nfs3_gxfh_volcnt, {
			"volume count", "nfs.gxfh3.volcnt", FT_UINT8, BASE_HEX_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_gxfh_epoch, {
			"epoch", "nfs.gxfh3.epoch", FT_UINT16, BASE_HEX_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_gxfh_ldsid, {
			"local dsid", "nfs.gxfh3.ldsid", FT_UINT32, BASE_HEX_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_gxfh_cid, {
			"cluster id", "nfs.gxfh3.cid", FT_UINT16, BASE_HEX_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_gxfh_resv, {
			"reserved", "nfs.gxfh3.reserved", FT_UINT16, BASE_HEX_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_gxfh_sfhflags, {
			"flags", "nfs.gxfh3.sfhflags", FT_UINT8, BASE_HEX,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_gxfh_sfhflags_resv1, {
			"reserved", "nfs.gxfh3.sfhflags.reserve1", FT_UINT8, BASE_HEX,
			NULL, SPINNP_FH_FLAG_RESV1, NULL, HFILL }},

		{ &hf_nfs3_gxfh_sfhflags_resv2, {
			"reserved", "nfs.gxfh3.sfhflags.reserv2", FT_UINT8, BASE_HEX,
			NULL, SPINNP_FH_FLAG_RESV2, NULL, HFILL }},

		{ &hf_nfs3_gxfh_sfhflags_ontap7G, {
			"ontap-7g", "nfs.gxfh3.sfhflags.ontap7g", FT_UINT8, BASE_HEX,
			NULL, SPINNP_FH_FLAG_ONTAP_MASK, NULL, HFILL }},

		{ &hf_nfs3_gxfh_sfhflags_ontapGX, {
			"ontap-gx", "nfs.gxfh3.sfhflags.ontapgx", FT_UINT8, BASE_HEX,
			NULL, SPINNP_FH_FLAG_ONTAP_MASK, NULL, HFILL }},

		{ &hf_nfs3_gxfh_sfhflags_striped, {
			"striped", "nfs.gxfh3.sfhflags.striped", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), SPINNP_FH_FLAG_STRIPED_MASK, NULL, HFILL }},

		{ &hf_nfs3_gxfh_sfhflags_empty, {
			"empty", "nfs.gxfh3.sfhflags.empty", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), SPINNP_FH_FLAG_EMPTY_MASK, NULL, HFILL }},

		{ &hf_nfs3_gxfh_sfhflags_snapdirent, {
			"snap dir ent", "nfs.gxfh3.sfhflags.snapdirent", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), SPINNP_FH_FLAG_SNAPDIR_ENT_MASK, NULL, HFILL }},

		{ &hf_nfs3_gxfh_sfhflags_snapdir, {
			"snap dir", "nfs.gxfh3.sfhflags.snapdir", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), SPINNP_FH_FLAG_SNAPDIR_MASK, NULL, HFILL }},

		{ &hf_nfs3_gxfh_sfhflags_streamdir, {
			"stream dir", "nfs.gxfh3.sfhflags.streamdir", FT_BOOLEAN, 8,
			TFS(&tfs_set_notset), SPINNP_FH_FLAG_STREAMDIR_MASK, NULL, HFILL }},

		{ &hf_nfs3_gxfh_spinfid, {
			"spin file id", "nfs.gxfh3.spinfid", FT_UINT32, BASE_HEX_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_gxfh_spinfuid, {
			"spin file unique id", "nfs.gxfh3.spinfuid", FT_UINT32, BASE_HEX_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_gxfh_exportptid, {
			"export point id", "nfs.gxfh3.exportptid", FT_UINT32, BASE_HEX_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_gxfh_exportptuid, {
			"export point unique id", "nfs.gxfh3.exportptuid", FT_UINT32, BASE_HEX_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_length_minlength, {
			"min length", "nfs.minlength4", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_layout_type, {
			"layout type", "nfs.layouttype", FT_UINT32, BASE_DEC,
			VALS(layouttype_names), 0, NULL, HFILL }},

		{ &hf_nfs4_layout_return_type, {
			"return type", "nfs.returntype", FT_UINT32, BASE_DEC,
			VALS(layoutreturn_names), 0, NULL, HFILL }},

		{ &hf_nfs4_lrf_body_content, {
			"lrf_body_content", "nfs.lrf_body_content", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_iomode, {
			"IO mode", "nfs.iomode", FT_UINT32, BASE_DEC,
			VALS(iomode_names), 0, NULL, HFILL }},

#if 0
		{ &hf_nfs4_stripetype, {
			"stripe type", "nfs.stripetype", FT_UINT32, BASE_DEC,
			VALS(stripetype_names), 0, NULL, HFILL }},
#endif

#if 0
		{ &hf_nfs4_stripeunit, {
			"stripe unit", "nfs.stripeunit", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},
#endif

#if 0
		{ &hf_nfs4_util, {
			"util", "nfs.util", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
#endif

#if 0
		{ &hf_nfs4_first_stripe_idx, {
			"first stripe index", "nfs.stripeindex", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
#endif

#if 0
		{ &hf_nfs4_pattern_offset, {
			"layout pattern offset", "nfs.patternoffset", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},
#endif

		{ &hf_nfs4_notification_bitmap, {
			"notification bitmap", "nfs.notificationbitmap", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_newtime, {
			"new time?", "nfs.newtime", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},

		{ &hf_nfs4_newoffset, {
			"new offset?", "nfs.newoffset", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},

		{ &hf_nfs4_newsize, {
			"new size?", "nfs.newsize", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},

		{ &hf_nfs4_layout_avail, {
			"layout available?", "nfs.layoutavail", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},

#if 0
		{ &hf_nfs4_mdscommit, {
			"MDS commit?", "nfs.mdscommit", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},
#endif

		{ &hf_nfs4_layoutupdate, {
			"layout update", "nfs.layoutupdate", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_deviceid, {
			"device ID", "nfs.deviceid", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_devicenum, {
			"num devices", "nfs.devicenum4", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_deviceidx, {
			"device index", "nfs.deviceidx", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_layout, {
			"layout", "nfs.layout", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},

#if 0
		{ &hf_nfs4_layout_count, {
			"layout", "nfs.layoutcount", FT_UINT32, BASE_DEC,
			NULL, 0, "layout count", HFILL }},
#endif


#if 0
		{ &hf_nfs4_stripedevs, {
			"stripe devs", "nfs.stripedevs", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
#endif

#if 0
		{ &hf_nfs4_devaddr, {
			"device addr", "nfs.devaddr", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},
#endif

		{ &hf_nfs4_return_on_close, {
			"return on close?", "nfs.retclose4", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},

		{ &hf_nfs4_nfl_util, {
			"nfl_util", "nfs.nfl_util", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_nfl_first_stripe_index, {
			"first stripe to use index", "nfs.nfl_first_stripe_index", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_slotid, {
			"slot id", "nfs.slotid", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_high_slotid, {
			"high slot id", "nfs.high_slotid", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfs4_target_high_slotid, {
			"target high slot id", "nfs.target_high_slotid", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_serverscope4, {
			"server scope", "nfs.scope", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_minorid, {
			"minor ID", "nfs.minorid4", FT_UINT64, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_majorid, {
			"major ID", "nfs.majorid4", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_padsize, {
			"hdr pad size", "nfs.padsize4", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

#if 0
		{ &hf_nfs4_cbrenforce, {
			"binding enforce?", "nfs.cbrenforce4", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},
#endif

#if 0
		{ &hf_nfs4_hashalg, {
			"hash alg", "nfs.hashalg4", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
#endif

#if 0
		{ &hf_nfs4_ssvlen, {
			"ssv len", "nfs.ssvlen4", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
#endif

		{ &hf_nfs4_maxreqsize, {
			"max req size", "nfs.maxreqsize4", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_maxrespsize, {
			"max resp size", "nfs.maxrespsize4", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_maxrespsizecached, {
			"max resp size cached", "nfs.maxrespsizecached4", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_maxops, {
			"max ops", "nfs.maxops4", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_maxreqs, {
			"max reqs", "nfs.maxreqs4", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_rdmachanattrs, {
			"RDMA chan attrs", "nfs.rdmachanattrs4", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_machinename, {
			"machine name", "nfs.machinename4", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_flavor, {
			"flavor", "nfs.flavor4", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_stamp, {
			"stamp", "nfs.stamp4", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_uid, {
			"uid", "nfs.uid4", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_gid, {
			"gid", "nfs.gid4", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_service, {
			"gid", "nfs.service4", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs_access_check,
			{ "Check access", "nfs.access_check",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			"Access type(s) to be checked", HFILL }
		},
		{ &hf_nfs_access_supported,
			{ "Supported types (of requested)", "nfs.access_supported",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			"Access types (of those requested) that the server can reliably verify", HFILL }
		},
		{ &hf_nfs_access_rights,
			{ "Access rights (of requested)", "nfs.access_rights",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			"Access rights for the types requested", HFILL }
		},
		{ &hf_nfs_access_supp_read,
			{ "0x01 READ", "nfs.access_supp_read",
			FT_BOOLEAN, 8,
			TFS(&tfs_access_supp), NFS_ACCESS_MASK_READ,
			NULL, HFILL }
		},
		{ &hf_nfs_access_supp_lookup,
			{ "0x02 LOOKUP", "nfs.access_supp_lookup",
			FT_BOOLEAN, 8,
			TFS(&tfs_access_supp), NFS_ACCESS_MASK_LOOKUP,
			NULL, HFILL }
		},
		{ &hf_nfs_access_supp_modify,
			{ "0x04 MODIFY", "nfs.access_supp_modify",
			FT_BOOLEAN, 8,
			TFS(&tfs_access_supp), NFS_ACCESS_MASK_MODIFY,
			NULL, HFILL }
		},
		{ &hf_nfs_access_supp_extend,
			{ "0x08 EXTEND", "nfs.access_supp_extend",
			FT_BOOLEAN, 8,
			TFS(&tfs_access_supp), NFS_ACCESS_MASK_EXTEND,
			NULL, HFILL }
		},
		{ &hf_nfs_access_supp_delete,
			{ "0x10 DELETE", "nfs.access_supp_delete",
			FT_BOOLEAN, 8,
			TFS(&tfs_access_supp), NFS_ACCESS_MASK_DELETE,
			NULL, HFILL }
		},
		{ &hf_nfs_access_supp_execute,
			{ "0x20 EXECUTE", "nfs.access_supp_execute",
			FT_BOOLEAN, 8,
			TFS(&tfs_access_supp), NFS_ACCESS_MASK_EXECUTE,
			NULL, HFILL }
		},
		{ &hf_nfs_access_read,
			{ "0x01 READ", "nfs.access_read",
			FT_BOOLEAN, 8,
			TFS(&tfs_access_rights), NFS_ACCESS_MASK_READ,
			NULL, HFILL }
		},
		{ &hf_nfs_access_lookup,
			{ "0x02 LOOKUP", "nfs.access_lookup",
			FT_BOOLEAN, 8,
			TFS(&tfs_access_rights), NFS_ACCESS_MASK_LOOKUP,
			NULL, HFILL }
		},
		{ &hf_nfs_access_modify,
			{ "0x04 MODIFY", "nfs.access_modify",
			FT_BOOLEAN, 8,
			TFS(&tfs_access_rights), NFS_ACCESS_MASK_MODIFY,
			NULL, HFILL }
		},
		{ &hf_nfs_access_extend,
			{ "0x08 EXTEND", "nfs.access_extend",
			FT_BOOLEAN, 8,
			TFS(&tfs_access_rights), NFS_ACCESS_MASK_EXTEND,
			NULL, HFILL }
		},
		{ &hf_nfs_access_delete,
			{ "0x10 DELETE", "nfs.access_delete",
			FT_BOOLEAN, 8,
			TFS(&tfs_access_rights), NFS_ACCESS_MASK_DELETE,
			NULL, HFILL }
		},
		{ &hf_nfs_access_execute,
			{ "0x20 EXECUTE", "nfs.access_execute",
			FT_BOOLEAN, 8,
			TFS(&tfs_access_rights), NFS_ACCESS_MASK_EXECUTE,
			NULL, HFILL }
		},
		{ &hf_nfs_access_denied,
			{ "Access Denied", "nfs.access_denied",
			FT_BOOLEAN, BASE_NONE,
			NULL, 0x0,
			"True if access has been denied to one or more of the requested types", HFILL }
		},
		{ &hf_nfs4_sessionid, {
			"sessionid", "nfs.session_id4", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfs4_exchid_call_flags, {
			"flags", "nfs.exchange_id.call_flags", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL}},
		{ &hf_nfs4_exchid_reply_flags, {
			"flags", "nfs.exchange_id.reply_flags", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL}},
		{ &hf_nfs4_exchid_flags_moved_refer, {
			"EXCHGID4_FLAG_SUPP_MOVED_REFER", "nfs.exchange_id.flags.moved_refer", FT_BOOLEAN, 32,
			TFS(&tfs_set_notset), 0x00000001, NULL, HFILL}},
		{ &hf_nfs4_exchid_flags_moved_migr, {
			"EXCHGID4_FLAG_SUPP_MOVED_MIGR", "nfs.exchange_id.flags.moved_migr", FT_BOOLEAN, 32,
			TFS(&tfs_set_notset), 0x00000002, NULL, HFILL}},
		{ &hf_nfs4_exchid_flags_bind_princ, {
			"EXCHGID4_FLAG_BIND_PRINC_STATEID", "nfs.exchange_id.flags.bind_princ", FT_BOOLEAN, 32,
			TFS(&tfs_set_notset), 0x00000100, NULL, HFILL}},
		{ &hf_nfs4_exchid_flags_non_pnfs, {
			"EXCHGID4_FLAG_USE_NON_PNFS", "nfs.exchange_id.flags.non_pnfs", FT_BOOLEAN, 32,
			TFS(&tfs_set_notset), 0x00010000, NULL, HFILL}},
		{ &hf_nfs4_exchid_flags_pnfs_mds, {
			"EXCHGID4_FLAG_USE_PNFS_MDS", "nfs.exchange_id.flags.pnfs_mds", FT_BOOLEAN, 32,
			TFS(&tfs_set_notset), 0x00020000, NULL, HFILL}},
		{ &hf_nfs4_exchid_flags_pnfs_ds, {
			"EXCHGID4_FLAG_USE_PNFS_DS", "nfs.exchange_id.flags.pnfs_ds", FT_BOOLEAN, 32,
			TFS(&tfs_set_notset), 0x00040000, NULL, HFILL}},
		{ &hf_nfs4_exchid_flags_upd_conf_rec_a, {
			"EXCHGID4_FLAG_UPD_CONFIRMED_REC_A", "nfs.exchange_id.flags.confirmed_rec_a",
			FT_BOOLEAN, 32,	TFS(&tfs_set_notset), 0x40000000, NULL, HFILL}},
		{ &hf_nfs4_exchid_flags_confirmed_r, {
			"EXCHGID4_FLAG_CONFIRMED_R", "nfs.exchange_id.flags.confirmed_r", FT_BOOLEAN, 32,
			TFS(&tfs_set_notset), 0x80000000, NULL, HFILL}},
		{ &hf_nfs4_prot_info_hash_alg, {
			"Prot Info hash algorithm", "nfs.prot_info4_hash_alg", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfs4_prot_info_encr_alg, {
			"Prot Info encryption algorithm", "nfs.prot_info4_encr_alg", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfs4_prot_info_svv_length, {
			"Prot Info svv_length", "nfs.prot_info4_svv_length", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfs4_prot_info_spi_window, {
			"Prot Info spi window", "nfs.prot_info4_spi_window", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfs4_state_protect_window, {
			"State Protect window", "nfs.state_protect_window", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfs4_state_protect_num_gss_handles, {
			"State Protect num gss handles", "nfs.state_protect_num_gss_handles", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfs4_nii_domain, {
			"Implementor DNS domain name(nii_domain)", "nfs.nii_domain4", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfs4_nii_name, {
			"Implementation product name(nii_name)", "nfs.nii_name4", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfs4_create_session_flags_csa, {
			"csa_flags", "nfs.create_session_flags", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfs4_create_session_flags_csr, {
			"csr_flags", "nfs.create_session_flags", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfs4_create_session_flags_persist, {
			"CREATE_SESSION4_FLAG_PERSIST", "nfs.create_session.flags.persist", FT_BOOLEAN, 32,
			TFS(&tfs_set_notset), 0x00000001, NULL, HFILL}},
		{ &hf_nfs4_create_session_flags_conn_back_chan, {
			"CREATE_SESSION4_FLAG_CONN_BACK_CHAN", "nfs.create_session.flags.conn_back_chan",
			FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000002, NULL, HFILL}},
		{ &hf_nfs4_create_session_flags_conn_rdma, {
			"CREATE_SESSION4_FLAG_CONN_RDMA", "nfs.create_session.flags.conn_rdma",
			FT_BOOLEAN, 32,	TFS(&tfs_set_notset), 0x00000004, NULL, HFILL}},
		{ &hf_nfs4_cachethis, {
			"cache this?", "nfs.cachethis4", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},
		{ &hf_nfs4_reclaim_one_fs, {
			"reclaim one fs?", "nfs.reclaim_one_fs4", FT_BOOLEAN,
			BASE_NONE, TFS(&tfs_yes_no), 0x0, NULL, HFILL }},
		{ &hf_nfs4_cb_procedure, {
		   "CB Procedure", "nfs.cb_procedure", FT_UINT32, BASE_DEC,
			VALS(nfs_cb_proc_vals), 0, NULL, HFILL }},
		{ &hf_nfs4_cb_op, {
		    "Opcode", "nfs.cb.operation", FT_UINT32, BASE_DEC|BASE_EXT_STRING,
		    &names_nfs_cb_operation_ext, 0, NULL, HFILL }},
		{ &hf_nfs4_lrs_present, {
			"Stateid present?", "nfs.lrs_present", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0x0, NULL, HFILL }},
		{ &hf_nfs4_cb_truncate, {
		    "Truncate?", "nfs.truncate", FT_BOOLEAN, BASE_NONE,
		    TFS(&tfs_yes_no), 0, NULL, HFILL }},
		{ &hf_nfs4_cb_layoutrecall_type, {
			"recall type", "nfs.recalltype", FT_UINT32, BASE_DEC,
			VALS(layoutrecall_names), 0, NULL, HFILL }},
		{ &hf_nfs4_cb_clorachanged, {
			"Clora changed", "nfs.clorachanged", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_yes_no), 0, NULL, HFILL }},

		{ &hf_nfs4_bctsa_dir, {
			"bctsa_dir", "nfs.bctsa_dir", FT_UINT32, BASE_HEX,
			VALS(names_channel_dir_from_client), 0, NULL, HFILL }},
		{ &hf_nfs4_bctsa_use_conn_in_rdma_mode, {
			"bctsa_use_conn_in_rdma_mode", "nfs.bctsa_use_conn_in_rdma_mode", FT_BOOLEAN, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_nfs4_bctsr_dir, {
			"bctsr_dir", "nfs.bctsr_dir", FT_UINT32, BASE_HEX,
			VALS(names_channel_dir_from_server), 0, NULL, HFILL }},
		{ &hf_nfs4_bctsr_use_conn_in_rdma_mode, {
			"bctsr_use_conn_in_rdma_mode", "nfs.bctsr_use_conn_in_rdma_mode", FT_BOOLEAN, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_mode, {
			"Mode", "nfs.mode3", FT_UINT32, BASE_OCT,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs3_mode_suid, {
			"S_ISUID", "nfs.mode3.suid", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), 0x800, NULL, HFILL }},

		{ &hf_nfs3_mode_sgid, {
			"S_ISGID", "nfs.mode3.sgid", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), 0x400, NULL, HFILL }},

		{ &hf_nfs3_mode_sticky, {
			"S_ISVTX", "nfs.mode3.sticky", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), 0x200, NULL, HFILL }},

		{ &hf_nfs3_mode_rusr, {
			"S_IRUSR", "nfs.mode3.rusr", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), 0x100, NULL, HFILL }},

		{ &hf_nfs3_mode_wusr, {
			"S_IWUSR", "nfs.mode3.wusr", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), 0x080, NULL, HFILL }},

		{ &hf_nfs3_mode_xusr, {
			"S_IXUSR", "nfs.mode3.xusr", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), 0x040, NULL, HFILL }},

		{ &hf_nfs3_mode_rgrp, {
			"S_IRGRP", "nfs.mode3.rgrp", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), 0x020, NULL, HFILL }},

		{ &hf_nfs3_mode_wgrp, {
			"S_IWGRP", "nfs.mode3.wgrp", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), 0x010, NULL, HFILL }},

		{ &hf_nfs3_mode_xgrp, {
			"S_IXGRP", "nfs.mode3.xgrp", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), 0x008, NULL, HFILL }},

		{ &hf_nfs3_mode_roth, {
			"S_IROTH", "nfs.mode3.roth", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), 0x004, NULL, HFILL }},

		{ &hf_nfs3_mode_woth, {
			"S_IWOTH", "nfs.mode3.woth", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), 0x002, NULL, HFILL }},

		{ &hf_nfs3_mode_xoth, {
			"S_IXOTH", "nfs.mode3.xoth", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), 0x001, NULL, HFILL }},

		{ &hf_nfs2_mode_name, {
			"Name", "nfs.mode.name", FT_UINT32, BASE_DEC,
			VALS(nfs2_mode_names), 0160000, NULL, HFILL }},

		{ &hf_nfs2_mode_set_user_id, {
			"Set user id on exec", "nfs.mode.set_user_id", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), 04000, NULL, HFILL }},

		{ &hf_nfs2_mode_set_group_id, {
			"Set group id on exec", "nfs.mode.set_group_id", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), 02000, NULL, HFILL }},

		{ &hf_nfs2_mode_save_swap_text, {
			"Save swapped text even after use", "nfs.mode.save_swap_text", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), 01000, NULL, HFILL }},

		{ &hf_nfs2_mode_read_owner, {
			"Read permission for owner", "nfs.mode.read_owner", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), 0400, NULL, HFILL }},

		{ &hf_nfs2_mode_write_owner, {
			"Write permission for owner", "nfs.mode.write_owner", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), 0200, NULL, HFILL }},

		{ &hf_nfs2_mode_exec_owner, {
			"Execute permission for owner", "nfs.mode.exec_owner", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), 0100, NULL, HFILL }},

		{ &hf_nfs2_mode_read_group, {
			"Read permission for group", "nfs.mode.read_group", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), 040, NULL, HFILL }},

		{ &hf_nfs2_mode_write_group, {
			"Write permission for group", "nfs.mode.write_group", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), 020, NULL, HFILL }},

		{ &hf_nfs2_mode_exec_group, {
			"Execute permission for group", "nfs.mode.exec_group", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), 010, NULL, HFILL }},

		{ &hf_nfs2_mode_read_other, {
			"Read permission for others", "nfs.mode.read_other", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), 04, NULL, HFILL }},

		{ &hf_nfs2_mode_write_other, {
			"Write permission for others", "nfs.mode.write_other", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), 02, NULL, HFILL }},

		{ &hf_nfs2_mode_exec_other, {
			"Execute permission for others", "nfs.mode.exec_other", FT_BOOLEAN, 32,
			TFS(&tfs_yes_no), 01, NULL, HFILL }},

		{ &hf_nfs4_op_mask, {
			"op_mask", "nfs.op_mask", FT_UINT32, BASE_DEC,
			VALS(names_nfs4_operation), 0, "Operation Mask", HFILL }},

		{ &hf_nfs4_sequence_status_flags, {
			"status flags", "nfs.sequence.flags", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }},

		{ &hf_nfs4_sequence_status_flags_cb_path_down, {
			"SEQ4_STATUS_CB_PATH_DOWN", "nfs.sequence.flags.cb_path_down", FT_BOOLEAN, 32,
			TFS(&tfs_set_notset), 0x00000001, NULL, HFILL}},

		{ &hf_nfs4_sequence_status_flags_cb_gss_contexts_expiring, {
			"SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRING", "nfs.sequence.flags.cb_gss_contexts_expiring",
			FT_BOOLEAN, 32,	TFS(&tfs_set_notset), 0x00000002, NULL, HFILL}},

		{ &hf_nfs4_sequence_status_flags_cb_gss_contexts_expired, {
			"SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRED", "nfs.sequence.flags.cb_gss_contexts_expired",
			FT_BOOLEAN, 32,	TFS(&tfs_set_notset), 0x00000004, NULL, HFILL}},

		{ &hf_nfs4_sequence_status_flags_expired_all_state_revoked, {
			"SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED", "nfs.sequence.flags.expired_all_state_revoked",
			FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000008, NULL, HFILL}},

		{ &hf_nfs4_sequence_status_flags_expired_some_state_revoked, {
			"SEQ4_STATUS_EXPIRED_SOME_STATE_REVOKED", "nfs.sequence.flags.expired_some_state_revoked",
			FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000010, NULL, HFILL}},

		{ &hf_nfs4_sequence_status_flags_admin_state_revoked, {
			"SEQ4_STATUS_ADMIN_STATE_REVOKED", "nfs.sequence.flags.admin_state_revoked",
			FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000020, NULL, HFILL}},

		{ &hf_nfs4_sequence_status_flags_recallable_state_revoked, {
			"SEQ4_STATUS_RECALLABLE_STATE_REVOKED", "nfs.sequence.flags.recallable_state_revoked",
			FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000040, NULL, HFILL}},

		{ &hf_nfs4_sequence_status_flags_lease_moved, {
			"SEQ4_STATUS_LEASE_MOVED", "nfs.sequence.flags.lease_moved", FT_BOOLEAN, 32,
			TFS(&tfs_set_notset), 0x00000080, NULL, HFILL}},

		{ &hf_nfs4_sequence_status_flags_restart_reclaim_needed, {
			"SEQ4_STATUS_RESTART_RECLAIM_NEEDED", "nfs.sequence.flags.restart_reclaim_needed",
			FT_BOOLEAN, 32,	TFS(&tfs_set_notset), 0x00000100, NULL, HFILL}},

		{ &hf_nfs4_sequence_status_flags_cb_path_down_session, {
			"SEQ4_STATUS_CB_PATH_DOWN_SESSION", "nfs.sequence.flags.cb_path_down_session",
			FT_BOOLEAN, 32,	TFS(&tfs_set_notset), 0x00000200, NULL, HFILL}},

		{ &hf_nfs4_sequence_status_flags_backchannel_fault, {
			"SEQ4_STATUS_BACKCHANNEL_FAULT", "nfs.sequence.flags.backchannel_fault", FT_BOOLEAN, 32,
			TFS(&tfs_set_notset), 0x00000400, NULL, HFILL}},

		{ &hf_nfs4_sequence_status_flags_devid_changed, {
			"SEQ4_STATUS_DEVID_CHANGED", "nfs.sequence.flags.devid_changed", FT_BOOLEAN, 32,
			TFS(&tfs_set_notset), 0x00000800, NULL, HFILL}},

		{ &hf_nfs4_sequence_status_flags_devid_deleted, {
			"SEQ4_STATUS_DEVID_DELETED", "nfs.sequence.flags.devid_deleted", FT_BOOLEAN, 32,
			TFS(&tfs_set_notset), 0x00001000, NULL, HFILL}},

		{ &hf_nfs4_test_stateid_arg, {
			"Stateid List", "nfs.test_stateid.stateids",
			FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL}},

		{ &hf_nfs4_test_stateid_res, {
			"Stateid Result List", "nfs.test_stateid.results",
			FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL}},

	/* Hidden field for v2, v3, and v4 status */
		{ &hf_nfs_status, {
			"Status", "nfs.status", FT_UINT32, BASE_DEC | BASE_EXT_STRING,
			&names_nfs_nfsstat_ext, 0, "Reply status", HFILL }}
	};

	static gint *ett[] = {
		&ett_nfs,
		&ett_nfs_fh_encoding,
		&ett_nfs_fh_fsid,
		&ett_nfs_fh_file,
		&ett_nfs_fh_mount,
		&ett_nfs_fh_export,
		&ett_nfs_fh_xfsid,
		&ett_nfs_fh_fn,
		&ett_nfs_fh_xfn,
		&ett_nfs_fh_hp,
		&ett_nfs_fh_auth,
		&ett_nfs_fhandle,
		&ett_nfs_timeval,
		&ett_nfs_fattr,
		&ett_nfs_fh_obj,
		&ett_nfs_fh_ex,
		&ett_nfs_readdir_entry,
		&ett_nfs_utf8string,

		&ett_nfs2_mode,
		&ett_nfs2_sattr,
		&ett_nfs2_diropargs,

		&ett_nfs3_gxfh_utlfield,
		&ett_nfs3_gxfh_sfhfield,
		&ett_nfs3_gxfh_sfhflags,
		&ett_nfs3_mode,
		&ett_nfs3_specdata,
		&ett_nfs3_fh,
		&ett_nfs3_nfstime,
		&ett_nfs3_fattr,
		&ett_nfs3_post_op_fh,
		&ett_nfs3_sattr,
		&ett_nfs3_diropargs,
		&ett_nfs3_sattrguard,
		&ett_nfs3_set_mode,
		&ett_nfs3_set_uid,
		&ett_nfs3_set_gid,
		&ett_nfs3_set_size,
		&ett_nfs3_set_atime,
		&ett_nfs3_set_mtime,
		&ett_nfs3_pre_op_attr,
		&ett_nfs3_post_op_attr,
		&ett_nfs3_wcc_attr,
		&ett_nfs3_wcc_data,
		&ett_nfs3_access,
		&ett_nfs3_fsinfo_properties,

		&ett_nfs4_fh_file,
		&ett_nfs4_fh_file_flags,
		&ett_nfs4_fh_export,
		&ett_nfs4_compound_call,
		&ett_nfs4_request_op,
		&ett_nfs4_response_op,
		&ett_nfs4_access,
		&ett_nfs4_access_supp,
		&ett_nfs4_close,
		&ett_nfs4_commit,
		&ett_nfs4_create,
		&ett_nfs4_delegpurge,
		&ett_nfs4_delegreturn,
		&ett_nfs4_getattr,
		&ett_nfs4_getattr_args,
		&ett_nfs4_getattr_resp,
		&ett_nfs4_resok4,
		&ett_nfs4_obj_attrs,
		&ett_nfs4_fattr_new_attr_vals,
		&ett_nfs4_fattr4_attrmask,
		&ett_nfs4_attribute,
		&ett_nfs4_getfh,
		&ett_nfs4_link,
		&ett_nfs4_lock,
		&ett_nfs4_lockt,
		&ett_nfs4_locku,
		&ett_nfs4_lookup,
		&ett_nfs4_lookupp,
		&ett_nfs4_nverify,
		&ett_nfs4_open,
		&ett_nfs4_openattr,
		&ett_nfs4_open_confirm,
		&ett_nfs4_open_downgrade,
		&ett_nfs4_putfh,
		&ett_nfs4_putpubfh,
		&ett_nfs4_putrootfh,
		&ett_nfs4_read,
		&ett_nfs4_readdir,
		&ett_nfs4_readlink,
		&ett_nfs4_test_stateid,
		&ett_nfs4_destroy_clientid,
		&ett_nfs4_reclaim_complete,
		&ett_nfs4_remove,
		&ett_nfs4_rename,
		&ett_nfs4_renew,
		&ett_nfs4_restorefh,
		&ett_nfs4_savefh,
		&ett_nfs4_setattr,
		&ett_nfs4_setclientid,
		&ett_nfs4_setclientid_confirm,
		&ett_nfs4_verify,
		&ett_nfs4_write,
		&ett_nfs4_release_lockowner,
		&ett_nfs4_backchannel_ctl,
		&ett_nfs4_bind_conn_to_session,
		&ett_nfs4_exchange_id,
		&ett_nfs4_create_session,
		&ett_nfs4_destroy_session,
		&ett_nfs4_free_stateid,
		&ett_nfs4_secinfo_no_name,
		&ett_nfs4_sequence,
		&ett_nfs4_layoutget,
		&ett_nfs4_layoutcommit,
		&ett_nfs4_layoutreturn,
		&ett_nfs4_getdevinfo,
		&ett_nfs4_getdevlist,
		&ett_nfs4_illegal,
		&ett_nfs4_verifier,
		&ett_nfs4_dirlist,
		&ett_nfs4_dir_entry,
		&ett_nfs4_pathname,
		&ett_nfs4_change_info,
		&ett_nfs4_open_delegation,
		&ett_nfs4_open_claim,
		&ett_nfs4_opentype,
		&ett_nfs4_lock_owner,
		&ett_nfs4_cb_client,
		&ett_nfs4_client_id,
		&ett_nfs4_clientowner,
		&ett_nfs4_exchangeid_call_flags,
		&ett_nfs4_exchangeid_reply_flags,
		&ett_nfs4_server_owner,
		&ett_nfs4_bitmap,
		&ett_nfs4_attr_request,
		&ett_nfs4_fattr,
		&ett_nfs4_fsid,
		&ett_nfs4_fs_locations,
		&ett_nfs4_fs_location,
		&ett_nfs4_open_result_flags,
		&ett_nfs4_secinfo,
		&ett_nfs4_secinfo_flavor_info,
		&ett_nfs4_stateid,
		&ett_nfs4_fattr_fh_expire_type,
		&ett_nfs4_ace,
		&ett_nfs4_clientaddr,
		&ett_nfs4_aceflag,
		&ett_nfs4_acemask,
		&ett_nfs4_slotid,
		&ett_nfs4_sr_status,
		&ett_nfs4_serverscope,
		&ett_nfs4_minorid,
		&ett_nfs4_majorid,
		&ett_nfs4_persist,
		&ett_nfs4_backchan,
		&ett_nfs4_rdmamode,
		&ett_nfs4_padsize,
		&ett_nfs4_cbrenforce,
		&ett_nfs4_hashalg,
		&ett_nfs4_ssvlen,
		&ett_nfs4_maxreqsize,
		&ett_nfs4_maxrespsize,
		&ett_nfs4_maxrespsizecached,
		&ett_nfs4_maxops,
		&ett_nfs4_maxreqs,
		&ett_nfs4_streamchanattrs,
		&ett_nfs4_rdmachanattrs,
		&ett_nfs4_machinename,
		&ett_nfs4_flavor,
		&ett_nfs4_stamp,
		&ett_nfs4_uid,
		&ett_nfs4_gid,
		&ett_nfs4_service,
		&ett_nfs4_sessionid,
		&ett_nfs4_layoutseg,
		&ett_nfs4_layoutseg_fh,
		&ett_nfs4_cb_request_op,
		&ett_nfs4_cb_resop,
		&ett_nfs4_cb_getattr,
		&ett_nfs4_cb_recall,
		&ett_nfs4_cb_layoutrecall,
		&ett_nfs4_cb_pushdeleg,
		&ett_nfs4_cb_recallany,
		&ett_nfs4_cb_recallableobjavail,
		&ett_nfs4_cb_recallslot,
		&ett_nfs4_cb_sequence,
		&ett_nfs4_cb_wantscancelled,
		&ett_nfs4_cb_notifylock,
		&ett_nfs4_cb_notifydeviceid,
		&ett_nfs4_cb_notify,
		&ett_nfs4_cb_reflists,
		&ett_nfs4_cb_refcalls,
		&ett_nfs4_cb_illegal,
		&ett_nfs4_chan_attrs,
		&ett_nfs4_create_session_flags,
		&ett_nfs4_sequence_status_flags,
		&ett_nfs4_want_notify_flags
	};

  	static ei_register_info ei[] = {
  	  	{ &ei_nfs_too_many_ops, { "nfs.too_many_ops", PI_PROTOCOL, PI_NOTE, "Too many operations", EXPFILL }},
  	  	{ &ei_nfs_not_vnx_file, { "nfs.not_vnx_file", PI_UNDECODED, PI_WARN, "Not a Celerra|VNX file handle", EXPFILL }},
  	};

  	module_t *nfs_module;
	expert_module_t* expert_nfs;

	proto_nfs = proto_register_protocol("Network File System", "NFS", "nfs");
	proto_register_field_array(proto_nfs, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_nfs = expert_register_protocol(proto_nfs);
	expert_register_field_array(expert_nfs, ei, array_length(ei));

	nfs_module = prefs_register_protocol(proto_nfs, NULL);
	prefs_register_bool_preference(nfs_module, "file_name_snooping",
				       "Snoop FH to filename mappings",
				       "Whether the dissector should snoop the FH to"
				       " filename mappings by looking inside certain packets",
				       &nfs_file_name_snooping);
	prefs_register_bool_preference(nfs_module, "file_full_name_snooping",
				       "Snoop full path to filenames",
				       "Whether the dissector should snoop the full pathname"
				       " for files for matching FH's",
				       &nfs_file_name_full_snooping);
	prefs_register_bool_preference(nfs_module, "fhandle_find_both_reqrep",
				       "Fhandle filters finds both request/response",
				       "With this option display filters for nfs fhandles"
				       " (nfs.fh.{name|full_name|hash}) will find both the request"
				       " and response packets for a RPC call, even if the actual"
				       " fhandle is only present in one of the packets",
				       &nfs_fhandle_reqrep_matching);
	prefs_register_bool_preference(nfs_module, "display_nfsv4_tag",
				       "Display NFSv4 tag in info Column",
				       "When enabled, this option will print the NFSv4 tag"
				       " (if one exists) in the Info column in the Summary pane",
					&nfs_display_v4_tag);
	prefs_register_bool_preference(nfs_module, "display_major_nfsv4_ops",
				       "Display only 'significant' NFSv4 Operations in info Column",
				       "When enabled, shows only the significant NFSv4 Operations"
				       " in the info column.  Others (like GETFH, PUTFH, etc) are not displayed",
					&display_major_nfs4_ops);

	nfs_fhandle_table = register_dissector_table("nfs_fhandle.type",
	    "NFS Filehandle types", FT_UINT8, BASE_HEX);

	prefs_register_enum_preference(nfs_module,
		"default_fhandle_type",
		"Decode NFS file handles as",
		"Decode all NFS file handles as if they are of this type",
		&default_nfs_fhandle_type,
		nfs_fhandle_types,
		FALSE);

	nfs_name_snoop_known    = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
	nfs_file_handles        = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
	nfs_fhandle_frame_table = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
	register_init_routine(nfs_name_snoop_init);
}


void
proto_reg_handoff_nfs(void)
{
	dissector_handle_t fhandle_handle;

	/* Register the protocol as RPC */
	rpc_init_prog(proto_nfs, NFS_PROGRAM, ett_nfs);

	/* Register the procedure tables */
	rpc_init_proc_table(NFS_PROGRAM, 2, nfs2_proc, hf_nfs2_procedure);
	rpc_init_proc_table(NFS_PROGRAM, 3, nfs3_proc, hf_nfs3_procedure);
	rpc_init_proc_table(NFS_PROGRAM, 4, nfs4_proc, hf_nfs4_procedure);

	fhandle_handle = create_dissector_handle(dissect_fhandle_data_SVR4, proto_nfs);
	dissector_add_uint("nfs_fhandle.type", FHT_SVR4, fhandle_handle);

	fhandle_handle = create_dissector_handle(dissect_fhandle_data_LINUX_KNFSD_LE, proto_nfs);
	dissector_add_uint("nfs_fhandle.type", FHT_LINUX_KNFSD_LE, fhandle_handle);

	fhandle_handle = create_dissector_handle(dissect_fhandle_data_LINUX_NFSD_LE, proto_nfs);
	dissector_add_uint("nfs_fhandle.type", FHT_LINUX_NFSD_LE, fhandle_handle);

	fhandle_handle = create_dissector_handle(dissect_fhandle_data_LINUX_KNFSD_NEW, proto_nfs);
	dissector_add_uint("nfs_fhandle.type", FHT_LINUX_KNFSD_NEW, fhandle_handle);

	fhandle_handle = create_dissector_handle(dissect_fhandle_data_NETAPP, proto_nfs);
	dissector_add_uint("nfs_fhandle.type", FHT_NETAPP, fhandle_handle);

	fhandle_handle = create_dissector_handle(dissect_fhandle_data_NETAPP_V4, proto_nfs);
	dissector_add_uint("nfs_fhandle.type", FHT_NETAPP_V4, fhandle_handle);

	fhandle_handle = create_dissector_handle(dissect_fhandle_data_NETAPP_GX_v3, proto_nfs);
	dissector_add_uint("nfs_fhandle.type", FHT_NETAPP_GX_V3, fhandle_handle);

	fhandle_handle = create_dissector_handle(dissect_fhandle_data_CELERRA_VNX, proto_nfs);
	dissector_add_uint("nfs_fhandle.type", FHT_CELERRA_VNX, fhandle_handle);

	fhandle_handle = create_dissector_handle(dissect_fhandle_data_GLUSTER, proto_nfs);
	dissector_add_uint("nfs_fhandle.type", FHT_GLUSTER, fhandle_handle);

	fhandle_handle = create_dissector_handle(dissect_fhandle_data_unknown, proto_nfs);
	dissector_add_uint("nfs_fhandle.type", FHT_UNKNOWN, fhandle_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
