/* packet-nfs.c
 * Routines for nfs dissection
 * Copyright 1999, Uwe Girlich <Uwe.Girlich@philosys.de>
 * Copyright 2000-2004, Mike Frisch <frisch@hummingbird.com> (NFSv4 decoding)
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include <string.h>


#include "packet-rpc.h"
#include "packet-nfs.h"
#include <epan/prefs.h>
#include <epan/emem.h>

static int proto_nfs = -1;

static int hf_nfs_procedure_v2 = -1;
static int hf_nfs_procedure_v3 = -1;
static int hf_nfs_procedure_v4 = -1;
static int hf_nfs_fh_length = -1;
static int hf_nfs_fh_hash = -1;
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
static int hf_nfs_fh_dev = -1;
static int hf_nfs_fh_xdev = -1;
static int hf_nfs_fh_dirinode = -1;
static int hf_nfs_fh_pinode = -1;
static int hf_nfs_fh_hp_len = -1;
static int hf_nfs_fh_version = -1;
static int hf_nfs_fh_auth_type = -1;
static int hf_nfs_fh_fsid_type = -1;
static int hf_nfs_fh_fileid_type = -1;
static int hf_nfs_stat = -1;
static int hf_nfs_full_name = -1;
static int hf_nfs_name = -1;
static int hf_nfs_readlink_data = -1;
static int hf_nfs_read_offset = -1;
static int hf_nfs_read_count = -1;
static int hf_nfs_read_totalcount = -1;
static int hf_nfs_data = -1;
static int hf_nfs_write_beginoffset = -1;
static int hf_nfs_write_offset = -1;
static int hf_nfs_write_totalcount = -1;
static int hf_nfs_symlink_to = -1;
static int hf_nfs_readdir_cookie = -1;
static int hf_nfs_readdir_count = -1;
static int hf_nfs_readdir_entry = -1;
static int hf_nfs_readdir_entry_fileid = -1;
static int hf_nfs_readdir_entry_name = -1;
static int hf_nfs_readdir_entry_cookie = -1;
static int hf_nfs_readdir_entry3_fileid = -1;
static int hf_nfs_readdir_entry3_name = -1;
static int hf_nfs_readdir_entry3_cookie = -1;
static int hf_nfs_readdirplus_entry_fileid = -1;
static int hf_nfs_readdirplus_entry_name = -1;
static int hf_nfs_readdirplus_entry_cookie = -1;
static int hf_nfs_readdir_eof = -1;
static int hf_nfs_statfs_tsize = -1;
static int hf_nfs_statfs_bsize = -1;
static int hf_nfs_statfs_blocks = -1;
static int hf_nfs_statfs_bfree = -1;
static int hf_nfs_statfs_bavail = -1;
static int hf_nfs_ftype3 = -1;
static int hf_nfs_nfsstat3 = -1;
static int hf_nfs_read_eof = -1;
static int hf_nfs_write_stable = -1;
static int hf_nfs_write_committed = -1;
static int hf_nfs_createmode3 = -1;
static int hf_nfs_fsstat_invarsec = -1;
static int hf_nfs_fsinfo_rtmax = -1;
static int hf_nfs_fsinfo_rtpref = -1;
static int hf_nfs_fsinfo_rtmult = -1;
static int hf_nfs_fsinfo_wtmax = -1;
static int hf_nfs_fsinfo_wtpref = -1;
static int hf_nfs_fsinfo_wtmult = -1;
static int hf_nfs_fsinfo_dtpref = -1;
static int hf_nfs_fsinfo_maxfilesize = -1;
static int hf_nfs_fsinfo_properties = -1;
static int hf_nfs_pathconf_linkmax = -1;
static int hf_nfs_pathconf_name_max = -1;
static int hf_nfs_pathconf_no_trunc = -1;
static int hf_nfs_pathconf_chown_restricted = -1;
static int hf_nfs_pathconf_case_insensitive = -1;
static int hf_nfs_pathconf_case_preserving = -1;

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

static int hf_nfs_fattr_type = -1;
static int hf_nfs_fattr_nlink = -1;
static int hf_nfs_fattr_uid = -1;
static int hf_nfs_fattr_gid = -1;
static int hf_nfs_fattr_size = -1;
static int hf_nfs_fattr_blocksize = -1;
static int hf_nfs_fattr_rdev = -1;
static int hf_nfs_fattr_blocks = -1;
static int hf_nfs_fattr_fsid = -1;
static int hf_nfs_fattr_fileid = -1;
static int hf_nfs_fattr3_type = -1;
static int hf_nfs_fattr3_nlink = -1;
static int hf_nfs_fattr3_uid = -1;
static int hf_nfs_fattr3_gid = -1;
static int hf_nfs_fattr3_size = -1;
static int hf_nfs_fattr3_used = -1;
static int hf_nfs_fattr3_rdev = -1;
static int hf_nfs_fattr3_fsid = -1;
static int hf_nfs_fattr3_fileid = -1;
static int hf_nfs_wcc_attr_size = -1;
static int hf_nfs_set_size3_size = -1;
static int hf_nfs_cookie3 = -1;
static int hf_nfs_fsstat3_resok_tbytes = -1;
static int hf_nfs_fsstat3_resok_fbytes = -1;
static int hf_nfs_fsstat3_resok_abytes = -1;
static int hf_nfs_fsstat3_resok_tfiles = -1;
static int hf_nfs_fsstat3_resok_ffiles = -1;
static int hf_nfs_fsstat3_resok_afiles = -1;
static int hf_nfs_uid3 = -1;
static int hf_nfs_gid3 = -1;
static int hf_nfs_offset3 = -1;
static int hf_nfs_count3 = -1;
static int hf_nfs_count3_maxcount = -1;
static int hf_nfs_count3_dircount= -1;

/* NFSv4 */
static int hf_nfs_nfsstat4 = -1;
static int hf_nfs_argop4 = -1;
static int hf_nfs_resop4 = -1;
static int hf_nfs_linktext4 = -1;
static int hf_nfs_tag4 = -1;
static int hf_nfs_component4 = -1;
static int hf_nfs_clientid4 = -1;
static int hf_nfs_ace4 = -1;
static int hf_nfs_recall = -1;
static int hf_nfs_open_claim_type4 = -1;
static int hf_nfs_opentype4 = -1;
static int hf_nfs_limit_by4 = -1;
static int hf_nfs_open_delegation_type4 = -1;
static int hf_nfs_ftype4 = -1;
static int hf_nfs_change_info4_atomic = -1;
static int hf_nfs_open4_share_access = -1;
static int hf_nfs_open4_share_deny = -1;
static int hf_nfs_seqid4 = -1;
static int hf_nfs_lock_seqid4 = -1;
static int hf_nfs_mand_attr = -1;
static int hf_nfs_recc_attr = -1;
static int hf_nfs_time_how4 = -1;
static int hf_nfs_attrlist4 = -1;
static int hf_nfs_fattr4_link_support = -1;
static int hf_nfs_fattr4_symlink_support = -1;
static int hf_nfs_fattr4_named_attr = -1;
static int hf_nfs_fattr4_unique_handles = -1;
static int hf_nfs_fattr4_archive = -1;
static int hf_nfs_fattr4_cansettime = -1;
static int hf_nfs_fattr4_case_insensitive = -1;
static int hf_nfs_fattr4_case_preserving = -1;
static int hf_nfs_fattr4_chown_restricted = -1;
static int hf_nfs_fattr4_hidden = -1;
static int hf_nfs_fattr4_homogeneous = -1;
static int hf_nfs_fattr4_mimetype = -1;
static int hf_nfs_fattr4_no_trunc = -1;
static int hf_nfs_fattr4_system = -1;
static int hf_nfs_fattr4_owner = -1;
static int hf_nfs_fattr4_owner_group = -1;
static int hf_nfs_fattr4_size = -1;
static int hf_nfs_fattr4_aclsupport = -1;
static int hf_nfs_fattr4_lease_time = -1;
static int hf_nfs_fattr4_fileid = -1;
static int hf_nfs_fattr4_files_avail = -1;
static int hf_nfs_fattr4_files_free = -1;
static int hf_nfs_fattr4_files_total = -1;
static int hf_nfs_fattr4_maxfilesize = -1;
static int hf_nfs_fattr4_maxlink = -1;
static int hf_nfs_fattr4_maxname = -1;
static int hf_nfs_fattr4_numlinks = -1;
static int hf_nfs_fattr4_maxread = -1;
static int hf_nfs_fattr4_maxwrite = -1;
static int hf_nfs_fattr4_quota_hard = -1;
static int hf_nfs_fattr4_quota_soft = -1;
static int hf_nfs_fattr4_quota_used = -1;
static int hf_nfs_fattr4_space_avail = -1;
static int hf_nfs_fattr4_space_free = -1;
static int hf_nfs_fattr4_space_total = -1;
static int hf_nfs_fattr4_space_used = -1;
static int hf_nfs_who = -1;
static int hf_nfs_server = -1;
static int hf_nfs_stable_how4 = -1;
static int hf_nfs_dirlist4_eof = -1;
static int hf_nfs_stateid4 = -1;
static int hf_nfs_offset4 = -1;
static int hf_nfs_specdata1 = -1;
static int hf_nfs_specdata2 = -1;
static int hf_nfs_lock_type4 = -1;
static int hf_nfs_reclaim4 = -1;
static int hf_nfs_length4 = -1;
static int hf_nfs_changeid4 = -1;
static int hf_nfs_changeid4_before = -1;
static int hf_nfs_changeid4_after = -1;
static int hf_nfs_nfstime4_seconds = -1;
static int hf_nfs_nfstime4_nseconds = -1;
static int hf_nfs_fsid4_major = -1;
static int hf_nfs_fsid4_minor = -1;
static int hf_nfs_acetype4 = -1;
static int hf_nfs_aceflag4 = -1;
static int hf_nfs_acemask4 = -1;
static int hf_nfs_delegate_type = -1;
static int hf_nfs_secinfo_flavor = -1;
static int hf_nfs_secinfo_arr4 = -1;
static int hf_nfs_num_blocks = -1;
static int hf_nfs_bytes_per_block = -1;
static int hf_nfs_eof = -1;
static int hf_nfs_stateid4_delegate_stateid = -1;
static int hf_nfs_verifier4 = -1;
static int hf_nfs_cookie4 = -1;
static int hf_nfs_cookieverf4 = -1;
static int hf_nfs_cb_program = -1;
static int hf_nfs_cb_location = -1;
static int hf_nfs_recall4 = -1;
static int hf_nfs_filesize = -1;
static int hf_nfs_count4 = -1;
static int hf_nfs_count4_dircount = -1;
static int hf_nfs_count4_maxcount = -1;
static int hf_nfs_minorversion = -1;
static int hf_nfs_open_owner4 = -1;
static int hf_nfs_lock_owner4 = -1;
static int hf_nfs_new_lock_owner = -1;
static int hf_nfs_sec_oid4 = -1;
static int hf_nfs_qop4 = -1;
static int hf_nfs_secinfo_rpcsec_gss_info_service = -1;
static int hf_nfs_attrdircreate = -1;
static int hf_nfs_client_id4_id = -1;
static int hf_nfs_stateid4_other = -1;
static int hf_nfs_lock4_reclaim = -1;
static int hf_nfs_acl4 = -1;
static int hf_nfs_callback_ident = -1;
static int hf_nfs_r_netid = -1;
static int hf_nfs_r_addr = -1;

/* Hidden field for v2, v3, and v4 status */
static int hf_nfs_nfsstat = -1;

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
static gint ett_nfs_mode = -1;
static gint ett_nfs_fattr = -1;
static gint ett_nfs_sattr = -1;
static gint ett_nfs_diropargs = -1;
static gint ett_nfs_readdir_entry = -1;
static gint ett_nfs_mode3 = -1;
static gint ett_nfs_specdata3 = -1;
static gint ett_nfs_fh3 = -1;
static gint ett_nfs_nfstime3 = -1;
static gint ett_nfs_fattr3 = -1;
static gint ett_nfs_post_op_fh3 = -1;
static gint ett_nfs_sattr3 = -1;
static gint ett_nfs_diropargs3 = -1;
static gint ett_nfs_sattrguard3 = -1;
static gint ett_nfs_set_mode3 = -1;
static gint ett_nfs_set_uid3 = -1;
static gint ett_nfs_set_gid3 = -1;
static gint ett_nfs_set_size3 = -1;
static gint ett_nfs_set_atime = -1;
static gint ett_nfs_set_mtime = -1;
static gint ett_nfs_pre_op_attr = -1;
static gint ett_nfs_post_op_attr = -1;
static gint ett_nfs_wcc_attr = -1;
static gint ett_nfs_wcc_data = -1;
static gint ett_nfs_access = -1;
static gint ett_nfs_fsinfo_properties = -1;

/* NFSv4 */
static gint ett_nfs_compound_call4 = -1;
static gint ett_nfs_utf8string = -1;
static gint ett_nfs_argop4 = -1;
static gint ett_nfs_resop4 = -1;
static gint ett_nfs_access4 = -1;
static gint ett_nfs_close4 = -1;
static gint ett_nfs_commit4 = -1;
static gint ett_nfs_create4 = -1;
static gint ett_nfs_delegpurge4 = -1;
static gint ett_nfs_delegreturn4 = -1;
static gint ett_nfs_getattr4 = -1;
static gint ett_nfs_getfh4 = -1;
static gint ett_nfs_link4 = -1;
static gint ett_nfs_lock4 = -1;
static gint ett_nfs_lockt4 = -1;
static gint ett_nfs_locku4 = -1;
static gint ett_nfs_lookup4 = -1;
static gint ett_nfs_lookupp4 = -1;
static gint ett_nfs_nverify4 = -1;
static gint ett_nfs_open4 = -1;
static gint ett_nfs_openattr4 = -1;
static gint ett_nfs_open_confirm4 = -1;
static gint ett_nfs_open_downgrade4 = -1;
static gint ett_nfs_putfh4 = -1;
static gint ett_nfs_putpubfh4 = -1;
static gint ett_nfs_putrootfh4 = -1;
static gint ett_nfs_read4 = -1;
static gint ett_nfs_readdir4 = -1;
static gint ett_nfs_readlink4 = -1;
static gint ett_nfs_remove4 = -1;
static gint ett_nfs_rename4 = -1;
static gint ett_nfs_renew4 = -1;
static gint ett_nfs_restorefh4 = -1;
static gint ett_nfs_savefh4 = -1;
static gint ett_nfs_secinfo4 = -1;
static gint ett_nfs_setattr4 = -1;
static gint ett_nfs_setclientid4 = -1;
static gint ett_nfs_setclientid_confirm4 = -1;
static gint ett_nfs_verify4 = -1;
static gint ett_nfs_write4 = -1;
static gint ett_nfs_release_lockowner4 = -1;
static gint ett_nfs_illegal4 = -1;
static gint ett_nfs_verifier4 = -1;
static gint ett_nfs_opaque = -1;
static gint ett_nfs_dirlist4 = -1;
static gint ett_nfs_pathname4 = -1;
static gint ett_nfs_change_info4 = -1;
static gint ett_nfs_open_delegation4 = -1;
static gint ett_nfs_open_claim4 = -1;
static gint ett_nfs_opentype4 = -1;
static gint ett_nfs_lock_owner4 = -1;
static gint ett_nfs_cb_client4 = -1;
static gint ett_nfs_client_id4 = -1;
static gint ett_nfs_bitmap4 = -1;
static gint ett_nfs_fattr4 = -1;
static gint ett_nfs_fsid4 = -1;
static gint ett_nfs_fs_locations4 = -1;
static gint ett_nfs_fs_location4 = -1;
static gint ett_nfs_open4_result_flags = -1;
static gint ett_nfs_secinfo4_flavor_info = -1;
static gint ett_nfs_stateid4 = -1;
static gint ett_nfs_fattr4_fh_expire_type = -1;
static gint ett_nfs_ace4 = -1;
static gint ett_nfs_clientaddr4 = -1;
static gint ett_nfs_aceflag4 = -1;
static gint ett_nfs_acemask4 = -1;


/* For dissector helpers which take a "levels" argument to indicate how
 * many expansions up they should populate the expansion items with
 * text to enhance useability, this flag to "levels" specify that the
 * text should also be appended to COL_INFO
 */
#define COL_INFO_LEVEL 0x80000000


/* fhandle displayfilters to match also corresponding request/response
   packet in addition to the one containing the actual filehandle */
gboolean nfs_fhandle_reqrep_matching = FALSE;
static se_tree_t *nfs_fhandle_frame_table = NULL;


/* file name snooping */
gboolean nfs_file_name_snooping = FALSE;
gboolean nfs_file_name_full_snooping = FALSE;
typedef struct nfs_name_snoop {
	int fh_length;
	unsigned char *fh;
	int name_len;
	unsigned char *name;
	int parent_len;
	unsigned char *parent;
	int full_name_len;
	unsigned char *full_name;
} nfs_name_snoop_t;

typedef struct nfs_name_snoop_key {
	int key;
	int fh_length;
	const unsigned char *fh;
} nfs_name_snoop_key_t;

static GHashTable *nfs_name_snoop_unmatched = NULL;

static GHashTable *nfs_name_snoop_matched = NULL;

static se_tree_t *nfs_name_snoop_known = NULL;
static se_tree_t *nfs_file_handles = NULL;

/* This function will store one nfs filehandle in our global tree of 
 * filehandles.
 * We store all filehandles we see in this tree so that every unique
 * filehandle is only stored once with a unique pointer.
 * We need to store pointers to filehandles in several of our other
 * structures and this is a way to make sure we dont keep any redundant
 * copiesd around for a specific filehandle.
 *
 * If this is the first time this filehandle has been seen an se block
 * is allocated to store the filehandle in.
 * If this filehandle has already been stored in the tree this function returns
 * a pointer to the original copy.
 */
static nfs_fhandle_data_t *
store_nfs_file_handle(nfs_fhandle_data_t *nfs_fh)
{
	guint32 fhlen;
	se_tree_key_t fhkey[3];
	nfs_fhandle_data_t *new_nfs_fh;

	fhlen=nfs_fh->len/4;
	fhkey[0].length=1;
	fhkey[0].key=&fhlen;
	fhkey[1].length=fhlen;
	fhkey[1].key=nfs_fh->fh;
	fhkey[2].length=0;

	new_nfs_fh=se_tree_lookup32_array(nfs_file_handles, &fhkey[0]);
	if(new_nfs_fh){
		return new_nfs_fh;
	}

	new_nfs_fh=se_alloc(sizeof(nfs_fhandle_data_t));
	new_nfs_fh->len=nfs_fh->len;
	new_nfs_fh->fh=se_alloc(sizeof(guint32)*(nfs_fh->len/4));
	memcpy(new_nfs_fh->fh, nfs_fh->fh, nfs_fh->len);
	new_nfs_fh->tvb=tvb_new_real_data(new_nfs_fh->fh, new_nfs_fh->len, new_nfs_fh->len);
	fhlen=nfs_fh->len/4;
	fhkey[0].length=1;
	fhkey[0].key=&fhlen;
	fhkey[1].length=fhlen;
	fhkey[1].key=nfs_fh->fh;
	fhkey[2].length=0;
	se_tree_insert32_array(nfs_file_handles, &fhkey[0], new_nfs_fh);

	return new_nfs_fh;
} 

static gint
nfs_name_snoop_matched_equal(gconstpointer k1, gconstpointer k2)
{
	const nfs_name_snoop_key_t *key1 = (const nfs_name_snoop_key_t *)k1;
	const nfs_name_snoop_key_t *key2 = (const nfs_name_snoop_key_t *)k2;

	return (key1->key==key2->key)
	     &&(key1->fh_length==key2->fh_length)
	     &&(!memcmp(key1->fh, key2->fh, key1->fh_length));
}
static guint
nfs_name_snoop_matched_hash(gconstpointer k)
{
	const nfs_name_snoop_key_t *key = (const nfs_name_snoop_key_t *)k;
	int i;
	guint hash;

	hash=key->key;
	for(i=0;i<key->fh_length;i++)
		hash ^= key->fh[i];

	return hash;
}
static gint
nfs_name_snoop_unmatched_equal(gconstpointer k1, gconstpointer k2)
{
	guint32 key1 = GPOINTER_TO_UINT(k1);
	guint32 key2 = GPOINTER_TO_UINT(k2);

	return key1==key2;
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

	if(nns->name){
		g_free((gpointer)nns->name);
		nns->name=NULL;
		nns->name_len=0;
	}
	if(nns->full_name){
		g_free((gpointer)nns->full_name);
		nns->full_name=NULL;
		nns->full_name_len=0;
	}
	if(nns->parent){
		g_free((gpointer)nns->parent);
		nns->parent=NULL;
		nns->parent_len=0;
	}
	if(nns->fh){
		g_free((gpointer)nns->fh);
		nns->fh=NULL;
		nns->fh_length=0;
	}
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
		nfs_name_snoop_unmatched=g_hash_table_new(nfs_name_snoop_unmatched_hash,
			nfs_name_snoop_unmatched_equal);
	}
	if (nfs_name_snoop_matched != NULL) {
		g_hash_table_foreach_remove(nfs_name_snoop_matched,
				nfs_name_snoop_unmatched_free_all, NULL);
	} else {
		/* The fragment table does not exist. Create it */
		nfs_name_snoop_matched=g_hash_table_new(nfs_name_snoop_matched_hash,
			nfs_name_snoop_matched_equal);
	}
}

void
nfs_name_snoop_add_name(int xid, tvbuff_t *tvb, int name_offset, int name_len, int parent_offset, int parent_len, unsigned char *name)
{
	nfs_name_snoop_t *nns, *old_nns;
	const unsigned char *ptr=NULL;

	/* filter out all '.' and '..' names */
	if(!name){
		ptr=(const unsigned char *)tvb_get_ptr(tvb, name_offset, name_len);
		if(ptr[0]=='.'){
			if(ptr[1]==0){
				return;
			}
			if(ptr[1]=='.'){
				if(ptr[2]==0){
					return;
				}
			}
		}
	}

	nns=se_alloc(sizeof(nfs_name_snoop_t));

	nns->fh_length=0;
	nns->fh=NULL;

	if(parent_len){
		nns->parent_len=parent_len;
		nns->parent=tvb_memdup(tvb, parent_offset, parent_len);
	} else {
		nns->parent_len=0;
		nns->parent=NULL;
	}

	if(name){
		nns->name_len=strlen(name);
		nns->name=g_strdup(name);
	} else {
		nns->name_len=name_len;
		nns->name=g_malloc(name_len+1);
		memcpy(nns->name, ptr, name_len);
	}
	nns->name[nns->name_len]=0;

	nns->full_name_len=0;
	nns->full_name=NULL;

	/* remove any old entry for this */
	old_nns=g_hash_table_lookup(nfs_name_snoop_unmatched, GINT_TO_POINTER(xid));
	if(old_nns){
		/* if we haven't seen the reply yet, then there are no
		   matched entries for it, thus we can dealloc the arrays*/
		if(!old_nns->fh){
			g_free(old_nns->name);
			old_nns->name=NULL;
			old_nns->name_len=0;

			g_free(old_nns->parent);
			old_nns->parent=NULL;
			old_nns->parent_len=0;
		}
		g_hash_table_remove(nfs_name_snoop_unmatched, GINT_TO_POINTER(xid));
	}

	g_hash_table_insert(nfs_name_snoop_unmatched, GINT_TO_POINTER(xid), nns);
}

static void
nfs_name_snoop_add_fh(int xid, tvbuff_t *tvb, int fh_offset, int fh_length)
{
	unsigned char *fh;
	nfs_name_snoop_t *nns, *old_nns;
	nfs_name_snoop_key_t *key;

	/* find which request we correspond to */
	nns=g_hash_table_lookup(nfs_name_snoop_unmatched, GINT_TO_POINTER(xid));
	if(!nns){
		/* oops couldnt find matching request, bail out */
		return;
	}

	/* if we have already seen this response earlier */
	if(nns->fh){
		return;
	}

	/* oki, we have a new entry */
	fh=tvb_memdup(tvb, fh_offset, fh_length);
	nns->fh=fh;
	nns->fh_length=fh_length;

	key=se_alloc(sizeof(nfs_name_snoop_key_t));
	key->key=0;
	key->fh_length=nns->fh_length;
	key->fh    =nns->fh;

	/* already have something matched for this fh, remove it from
	   the table */
	old_nns=g_hash_table_lookup(nfs_name_snoop_matched, key);
	if(old_nns){
		g_hash_table_remove(nfs_name_snoop_matched, key);
	}

	g_hash_table_remove(nfs_name_snoop_unmatched, GINT_TO_POINTER(xid));
	g_hash_table_insert(nfs_name_snoop_matched, key, nns);
}

static void
nfs_full_name_snoop(nfs_name_snoop_t *nns, int *len, unsigned char **name, unsigned char **pos)
{
	nfs_name_snoop_t *parent_nns = NULL;
	nfs_name_snoop_key_t key;

	/* check if the nns component ends with a '/' else we just allocate
	   an extra byte to len to accommodate for it later */
	if(nns->name[nns->name_len-1]!='/'){
		(*len)++;
	}

	(*len) += nns->name_len;

	if(nns->parent==NULL){
		*name = g_malloc((*len)+1);
		*pos = *name;

		*pos += g_snprintf(*pos, (*len)+1, "%s", nns->name);
		return;
	}

	key.key=0;
	key.fh_length=nns->parent_len;
	key.fh=nns->parent;

	parent_nns=g_hash_table_lookup(nfs_name_snoop_matched, &key);

	if(parent_nns){
		nfs_full_name_snoop(parent_nns, len, name, pos);
		if(*name){
			/* make sure components are '/' separated */
			*pos += g_snprintf(*pos, (*len)+1, "%s%s", ((*pos)[-1]!='/')?"/":"", nns->name);
		}
		return;
	}

	return;
}

static void
nfs_name_snoop_fh(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int fh_offset, int fh_length, gboolean hidden)
{
	nfs_name_snoop_key_t key;
	nfs_name_snoop_t *nns = NULL;

	/* if this is a new packet, see if we can register the mapping */
	if(!pinfo->fd->flags.visited){
		key.key=0;
		key.fh_length=fh_length;
		key.fh=(const unsigned char *)tvb_get_ptr(tvb, fh_offset, fh_length);

		nns=g_hash_table_lookup(nfs_name_snoop_matched, &key);
		if(nns){
			guint32 fhlen;
			se_tree_key_t fhkey[3];

			fhlen=nns->fh_length;
			fhkey[0].length=1;
			fhkey[0].key=&fhlen;
			fhkey[1].length=fhlen/4;
			fhkey[1].key=nns->fh;
			fhkey[2].length=0;
			se_tree_insert32_array(nfs_name_snoop_known, &fhkey[0], nns);

			if(nfs_file_name_full_snooping){
				unsigned char *name=NULL, *pos=NULL;
				int len=0;

				nfs_full_name_snoop(nns, &len, &name, &pos);
				if(name){
					nns->full_name=name;
					nns->full_name_len=len;
				}
			}
		}
	}

	/* see if we know this mapping */
	if(!nns){
		guint32 fhlen;
		se_tree_key_t fhkey[3];

		fhlen=fh_length;
		fhkey[0].length=1;
		fhkey[0].key=&fhlen;
		fhkey[1].length=fhlen/4;
		fhkey[1].key=tvb_get_ptr(tvb, fh_offset, fh_length);
		fhkey[2].length=0;
		
		nns=se_tree_lookup32_array(nfs_name_snoop_known, &fhkey[0]);
	}

	/* if we know the mapping, print the filename */
	if(nns){
		if(hidden){
			proto_tree_add_string_hidden(tree, hf_nfs_name, tvb,
				fh_offset, 0, nns->name);
		}else {
			proto_tree_add_string_format(tree, hf_nfs_name, tvb,
				fh_offset, 0, nns->name, "Name: %s", nns->name);
		}
		if(nns->full_name){
			if(hidden){
				proto_tree_add_string_hidden(tree, hf_nfs_full_name, tvb,
					fh_offset, 0, nns->name);
			} else {
				proto_tree_add_string_format(tree, hf_nfs_full_name, tvb,
					fh_offset, 0, nns->name, "Full Name: %s", nns->full_name);
			}
		}
	}
}

/* file handle dissection */

#define FHT_UNKNOWN		0
#define FHT_SVR4		1
#define FHT_LINUX_KNFSD_LE	2
#define FHT_LINUX_NFSD_LE	3
#define FHT_LINUX_KNFSD_NEW	4
#define FHT_NETAPP		5

static const value_string names_fhtype[] =
{
	{	FHT_UNKNOWN,		"unknown"				},
	{	FHT_SVR4,		"System V R4"				},
	{	FHT_LINUX_KNFSD_LE,	"Linux knfsd (little-endian)"		},
	{	FHT_LINUX_NFSD_LE,	"Linux user-land nfsd (little-endian)"	},
	{	FHT_LINUX_KNFSD_NEW,	"Linux knfsd (new)"			},
	{	FHT_NETAPP,		"NetApp file handle"			},
	{	0,	NULL	}
};


/* SVR4: checked with ReliantUNIX (5.43, 5.44, 5.45) */

static void
dissect_fhandle_data_SVR4(tvbuff_t* tvb, int offset, proto_tree *tree,
    int fhlen _U_)
{
	guint32 nof = offset;

	/* file system id */
	{
	guint32 fsid_O;
	guint32 fsid_L;
	guint32 temp;
	guint32 fsid_major;
	guint32 fsid_minor;

	fsid_O = nof;
	fsid_L = 4;
	temp = tvb_get_ntohl(tvb, fsid_O);
	fsid_major = ( temp>>18 ) &  0x3fff; /* 14 bits */
	fsid_minor = ( temp     ) & 0x3ffff; /* 18 bits */
	if (tree) {
		proto_item* fsid_item = NULL;
		proto_tree* fsid_tree = NULL;

		fsid_item = proto_tree_add_text(tree, tvb,
			fsid_O, fsid_L,
			"file system ID: %d,%d", fsid_major, fsid_minor);
		if (fsid_item) {
			fsid_tree = proto_item_add_subtree(fsid_item,
					ett_nfs_fh_fsid);
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
	fn_len = tvb_get_ntohs(tvb, fn_len_O);
	fn_data_O = fn_O + fn_len_L;
	fn_data_inode_O = fn_data_O + 2;
	fn_data_inode_L = 4;
	inode = tvb_get_ntohl(tvb, fn_data_inode_O);
	fn_data_gen_O = fn_data_inode_O + fn_data_inode_L;
	fn_data_gen_L = 4;
	gen = tvb_get_ntohl(tvb, fn_data_gen_O);
	fn_L = fn_len_L + fn_len;
	if (tree) {
		proto_item* fn_item = NULL;
		proto_tree* fn_tree = NULL;

		fn_item = proto_tree_add_uint(tree, hf_nfs_fh_fn, tvb,
			fn_O, fn_L, inode);
		if (fn_item) {
			fn_tree = proto_item_add_subtree(fn_item,
					ett_nfs_fh_fn);
			proto_tree_add_uint(fn_tree, hf_nfs_fh_fn_len,
				tvb, fn_len_O, fn_len_L, fn_len);
			proto_tree_add_uint(fn_tree, hf_nfs_fh_fn_inode,
				tvb, fn_data_inode_O, fn_data_inode_L, inode);
			proto_tree_add_uint(fn_tree, hf_nfs_fh_fn_generation,
				tvb, fn_data_gen_O, fn_data_gen_L, gen);
		}
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
	xfn_len = tvb_get_ntohs(tvb, xfn_len_O);
	xfn_data_O = xfn_O + xfn_len_L;
	xfn_data_inode_O = xfn_data_O + 2;
	xfn_data_inode_L = 4;
	xinode = tvb_get_ntohl(tvb, xfn_data_inode_O);
	xfn_data_gen_O = xfn_data_inode_O + xfn_data_inode_L;
	xfn_data_gen_L = 4;
	xgen = tvb_get_ntohl(tvb, xfn_data_gen_O);
	xfn_L = xfn_len_L + xfn_len;
	if (tree) {
		proto_item* xfn_item = NULL;
		proto_tree* xfn_tree = NULL;

		xfn_item = proto_tree_add_uint(tree, hf_nfs_fh_xfn, tvb,
			xfn_O, xfn_L, xinode);
		if (xfn_item) {
			xfn_tree = proto_item_add_subtree(xfn_item,
					ett_nfs_fh_xfn);
			proto_tree_add_uint(xfn_tree, hf_nfs_fh_xfn_len,
				tvb, xfn_len_O, xfn_len_L, xfn_len);
			proto_tree_add_uint(xfn_tree, hf_nfs_fh_xfn_inode,
				tvb, xfn_data_inode_O, xfn_data_inode_L, xinode);
			proto_tree_add_uint(xfn_tree, hf_nfs_fh_xfn_generation,
				tvb, xfn_data_gen_O, xfn_data_gen_L, xgen);
		}
	}
	}
}


/* Checked with RedHat Linux 6.2 (kernel 2.2.14 knfsd) */

static void
dissect_fhandle_data_LINUX_KNFSD_LE(tvbuff_t* tvb, int offset, proto_tree *tree,
    int fhlen _U_)
{
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

	dentry   = tvb_get_letohl(tvb, offset+0);
	inode    = tvb_get_letohl(tvb, offset+4);
	dirinode = tvb_get_letohl(tvb, offset+8);
	temp     = tvb_get_letohs (tvb,offset+12);
	fsid_major = (temp >> 8) & 0xff;
	fsid_minor = (temp     ) & 0xff;
	temp     = tvb_get_letohs(tvb,offset+16);
	xfsid_major = (temp >> 8) & 0xff;
	xfsid_minor = (temp     ) & 0xff;
	xinode   = tvb_get_letohl(tvb,offset+20);
	gen      = tvb_get_letohl(tvb,offset+24);

	if (tree) {
		proto_tree_add_uint(tree, hf_nfs_fh_dentry,
			tvb, offset+0, 4, dentry);
		proto_tree_add_uint(tree, hf_nfs_fh_fn_inode,
			tvb, offset+4, 4, inode);
		proto_tree_add_uint(tree, hf_nfs_fh_dirinode,
			tvb, offset+8, 4, dirinode);

		/* file system id (device) */
		{
		proto_item* fsid_item = NULL;
		proto_tree* fsid_tree = NULL;

		fsid_item = proto_tree_add_text(tree, tvb,
			offset+12, 4,
			"file system ID: %d,%d", fsid_major, fsid_minor);
		if (fsid_item) {
			fsid_tree = proto_item_add_subtree(fsid_item,
					ett_nfs_fh_fsid);
			proto_tree_add_uint(fsid_tree, hf_nfs_fh_fsid_major,
				tvb, offset+13, 1, fsid_major);
			proto_tree_add_uint(fsid_tree, hf_nfs_fh_fsid_minor,
				tvb, offset+12, 1, fsid_minor);
		}
		}

		/* exported file system id (device) */
		{
		proto_item* xfsid_item = NULL;
		proto_tree* xfsid_tree = NULL;

		xfsid_item = proto_tree_add_text(tree, tvb,
			offset+16, 4,
			"exported file system ID: %d,%d", xfsid_major, xfsid_minor);
		if (xfsid_item) {
			xfsid_tree = proto_item_add_subtree(xfsid_item,
					ett_nfs_fh_xfsid);
			proto_tree_add_uint(xfsid_tree, hf_nfs_fh_xfsid_major,
				tvb, offset+17, 1, xfsid_major);
			proto_tree_add_uint(xfsid_tree, hf_nfs_fh_xfsid_minor,
				tvb, offset+16, 1, xfsid_minor);
		}
		}

		proto_tree_add_uint(tree, hf_nfs_fh_xfn_inode,
			tvb, offset+20, 4, xinode);
		proto_tree_add_uint(tree, hf_nfs_fh_fn_generation,
			tvb, offset+24, 4, gen);
	}
}


/* Checked with RedHat Linux 5.2 (nfs-server 2.2beta47 user-land nfsd) */

static void
dissect_fhandle_data_LINUX_NFSD_LE(tvbuff_t* tvb, int offset, proto_tree *tree,
    int fhlen _U_)
{
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
		proto_item* hash_item = NULL;
		proto_tree* hash_tree = NULL;

		hash_item = proto_tree_add_text(tree, tvb, offset+4,
				hashlen + 1,
				"hash path: %s",
				tvb_bytes_to_str(tvb,offset+5,hashlen));
		if (hash_item) {
			hash_tree = proto_item_add_subtree(hash_item,
					ett_nfs_fh_hp);
			if (hash_tree) {
		 		proto_tree_add_uint(hash_tree,
					hf_nfs_fh_hp_len, tvb, offset+4, 1,
					hashlen);
				proto_tree_add_text(hash_tree, tvb, offset+5,
					hashlen,
					"key: %s",
					tvb_bytes_to_str(tvb,offset+5,hashlen));
			}
		}
	}
	}
}


/* Checked with SuSE 7.1 (kernel 2.4.0 knfsd) */
/* read linux-2.4.5/include/linux/nfsd/nfsfh.h for more details */

#define AUTH_TYPE_NONE 0
static const value_string auth_type_names[] = {
	{	AUTH_TYPE_NONE,				"no authentication"		},
	{0,NULL}
};

#define FSID_TYPE_MAJOR_MINOR_INODE 0
static const value_string fsid_type_names[] = {
	{	FSID_TYPE_MAJOR_MINOR_INODE,		"major/minor/inode"		},
	{0,NULL}
};

#define FILEID_TYPE_ROOT			0
#define FILEID_TYPE_INODE_GENERATION		1
#define FILEID_TYPE_INODE_GENERATION_PARENT	2
static const value_string fileid_type_names[] = {
	{	FILEID_TYPE_ROOT,			"root"				},
	{	FILEID_TYPE_INODE_GENERATION,		"inode/generation"		},
	{	FILEID_TYPE_INODE_GENERATION_PARENT,	"inode/generation/parent"	},
	{0,NULL}
};

static void
dissect_fhandle_data_NETAPP(tvbuff_t* tvb, int offset, proto_tree *tree,
    int fhlen _U_)
{
	if (tree) {
		guint32 mount = tvb_get_letohl(tvb, offset + 0);
		guint32 mount_gen = tvb_get_letohl(tvb, offset + 4);
		guint16 flags = tvb_get_letohs(tvb, offset + 8);
		guint8 snapid = tvb_get_guint8(tvb, offset + 10);
		guint8 unused = tvb_get_guint8(tvb, offset + 11);
		guint32 inum = tvb_get_ntohl(tvb, offset + 12);
		guint32 generation = tvb_get_letohl(tvb, offset + 16);
		guint32 fsid = tvb_get_letohl(tvb, offset + 20);
		guint32 export = tvb_get_letohl(tvb, offset + 24);
		guint32 export_snapgen = tvb_get_letohl(tvb, offset + 28);
		proto_item *item;
		proto_tree *subtree;
		char flag_string[128] = "";
		const char *strings[] = { " MNT_PNT", " SNAPDIR", " SNAPDIR_ENT",
				    " EMPTY", " VBN_ACCESS", " MULTIVOLUME",
				    " METADATA" };
		guint16 bit = sizeof(strings) / sizeof(strings[0]);
		while (bit--)
			if (flags & (1<<bit))
				strcat(flag_string, strings[bit]);
		item = proto_tree_add_text(tree, tvb, offset + 0, 8,
					   "mount (inode %u)", mount);
		subtree = proto_item_add_subtree(item, ett_nfs_fh_mount);
		item = proto_tree_add_uint(subtree, hf_nfs_fh_mount_fileid,
					   tvb, offset + 0, 4, mount);
		item = proto_tree_add_uint(subtree, hf_nfs_fh_mount_generation,
					   tvb, offset + 4, 4, mount_gen);
		item = proto_tree_add_text(tree, tvb, offset + 8, 16,
					   "file (inode %u)", inum);
		subtree = proto_item_add_subtree(item, ett_nfs_fh_file);
		item = proto_tree_add_uint_format(subtree, hf_nfs_fh_flags,
						  tvb, offset + 8, 2, flags,
						  "Flags: %#02x%s", flags,
						  flag_string);
		item = proto_tree_add_uint(subtree, hf_nfs_fh_snapid, tvb,
					   offset + 10, 1, snapid);
		item = proto_tree_add_uint(subtree, hf_nfs_fh_unused, tvb,
					   offset + 11, 1, unused);
		item = proto_tree_add_uint(subtree, hf_nfs_fh_fileid, tvb,
					   offset + 12, 4, inum);
		item = proto_tree_add_uint(subtree, hf_nfs_fh_generation, tvb,
					   offset + 16, 4, generation);
		item = proto_tree_add_uint(subtree, hf_nfs_fh_fsid, tvb,
					   offset + 20, 4, fsid);
		item = proto_tree_add_text(tree, tvb, offset + 24, 8,
					   "export (inode %u)", export);
		subtree = proto_item_add_subtree(item, ett_nfs_fh_export);
		item = proto_tree_add_uint(subtree, hf_nfs_fh_export_fileid,
					   tvb, offset + 24, 4, export);
		item = proto_tree_add_uint(subtree,
					   hf_nfs_fh_export_generation,
					   tvb, offset + 28, 3,
					   export_snapgen & 0xffffff);
		item = proto_tree_add_uint(subtree, hf_nfs_fh_export_snapid,
					   tvb, offset + 31, 1,
					   export_snapgen >> 24);
	}
}

static void
dissect_fhandle_data_LINUX_KNFSD_NEW(tvbuff_t* tvb, int offset, proto_tree *tree,
    int fhlen _U_)
{
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
				proto_item* encoding_item = proto_tree_add_text(tree, tvb,
					offset + 1, 3,
					"encoding: %u %u %u",
					auth_type, fsid_type, fileid_type);
				if (encoding_item) {
					proto_tree* encoding_tree = proto_item_add_subtree(encoding_item,
						ett_nfs_fh_encoding);
					if (encoding_tree) {
						proto_tree_add_uint(encoding_tree, hf_nfs_fh_auth_type,
							tvb, offset+1, 1, auth_type);
						proto_tree_add_uint(encoding_tree, hf_nfs_fh_fsid_type,
							tvb, offset+2, 1, fsid_type);
						proto_tree_add_uint(encoding_tree, hf_nfs_fh_fileid_type,
							tvb, offset+3, 1, fileid_type);
					}
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
				proto_item* fsid_item = proto_tree_add_text(tree, tvb,
					offset+0, 8,
					"file system ID: %u,%u (inode %u)",
					fsid_major, fsid_minor, fsid_inode);
				if (fsid_item) {
					proto_tree* fsid_tree = proto_item_add_subtree(fsid_item,
						ett_nfs_fh_fsid);
					if (fsid_tree) {
						proto_tree_add_uint(fsid_tree, hf_nfs_fh_fsid_major,
							tvb, offset+0, 2, fsid_major);
						proto_tree_add_uint(fsid_tree, hf_nfs_fh_fsid_minor,
							tvb, offset+2, 2, fsid_minor);
						proto_tree_add_uint(fsid_tree, hf_nfs_fh_fsid_inode,
							tvb, offset+4, 4, fsid_inode);
					}
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
				proto_item* fileid_item = proto_tree_add_text(tree, tvb,
					offset+0, 8,
					"file ID: %u (%u)",
					inode, generation);
				if (fileid_item) {
					proto_tree* fileid_tree = proto_item_add_subtree(
						fileid_item, ett_nfs_fh_fn);
					if (fileid_tree) {
						proto_tree_add_uint(fileid_tree, hf_nfs_fh_fn_inode,
						tvb, offset+0, 4, inode);
						proto_tree_add_uint(fileid_tree, hf_nfs_fh_fn_generation,
						tvb, offset+4, 4, generation);
					}
				}
			}

			offset += 8;
		} break;
		case 2: {
			guint32 inode;
			guint32 generation;
			guint32 parent_inode;

			inode = tvb_get_letohl(tvb, offset + 0);
			generation = tvb_get_letohl(tvb, offset + 4);
			parent_inode = tvb_get_letohl(tvb, offset + 8);

			if (tree) {
				 proto_item* fileid_item = proto_tree_add_text(tree, tvb,
					offset+0, 8,
					"file ID: %u (%u)",
					inode, generation);
				if (fileid_item) {
					proto_tree* fileid_tree = proto_item_add_subtree(
						fileid_item, ett_nfs_fh_fn);
					if (fileid_tree) {
						proto_tree_add_uint(fileid_tree, hf_nfs_fh_fn_inode,
						tvb, offset+0, 4, inode);
						proto_tree_add_uint(fileid_tree, hf_nfs_fh_fn_generation,
						tvb, offset+4, 4, generation);
						proto_tree_add_uint(fileid_tree, hf_nfs_fh_dirinode,
						tvb, offset+8, 4, parent_inode);
					}
				}
			}

			offset += 12;
		} break;
		default: {
			/* unknown fileid type */
			goto out;
		}
	}

out:
	;
}


static void
dissect_fhandle_data_unknown(tvbuff_t *tvb, int offset, proto_tree *tree,
    guint fhlen)
{
	guint sublen;
	guint bytes_left;
	gboolean first_line;

	bytes_left = fhlen;
	first_line = TRUE;
	while (bytes_left != 0) {
		sublen = 16;
		if (sublen > bytes_left)
			sublen = bytes_left;
		proto_tree_add_text(tree, tvb, offset, sublen,
					"%s%s",
					first_line ? "data: " :
					             "      ",
					tvb_bytes_to_str(tvb,offset,sublen));
		bytes_left -= sublen;
		offset += sublen;
		first_line = FALSE;
	}
}


static void
dissect_fhandle_data(tvbuff_t *tvb, int offset, packet_info *pinfo,
    proto_tree *tree, unsigned int fhlen, gboolean hidden, guint32 *hash)
{
	unsigned int fhtype = FHT_UNKNOWN;

	/* filehandle too long */
	if (fhlen>64) goto type_ready;
	/* Not all bytes there. Any attempt to deduce the type would be
	   senseless. */
	if (!tvb_bytes_exist(tvb,offset,fhlen)) goto type_ready;

	/* this is to set up fhandle display filters to find both packets
	   of an RPC call */
	if(nfs_fhandle_reqrep_matching && (!hidden) ){
		nfs_fhandle_data_t *old_fhd=NULL;

		if( !pinfo->fd->flags.visited ){
			nfs_fhandle_data_t fhd;

			/* first check if we have seen this fhandle before */
			fhd.len=fhlen;
			fhd.fh=(const unsigned char *)tvb_get_ptr(tvb, offset, fhlen);
			old_fhd=store_nfs_file_handle(&fhd);

			/* XXX here we should really check that we havent stored
			   this fhandle for this frame number already.
		   	   We should also make sure we can handle when we have multiple
		   	   fhandles seen for the same frame, which WILL happen for certain
		   	   nfs calls. For now, we dont handle this and those calls will
		   	   not work properly with this feature
			*/
			se_tree_insert32(nfs_fhandle_frame_table, pinfo->fd->num, old_fhd);
		}
	}

	/* create a semiunique hash value for the filehandle */
	{
		guint32 fhhash;
		guint32 i;

		for(fhhash=0,i=0;i<(fhlen-3);i+=4){
			guint32 val;
			val = tvb_get_ntohl(tvb, offset+i);
			fhhash ^= val;
			fhhash += val;
		}
		if(hidden){
			proto_tree_add_uint_hidden(tree, hf_nfs_fh_hash, tvb, offset,
				fhlen, fhhash);
		} else {
			proto_tree_add_uint(tree, hf_nfs_fh_hash, tvb, offset,
				fhlen, fhhash);
		}
		if(hash){
			*hash=fhhash;
		}
	}
	if(nfs_file_name_snooping){
		nfs_name_snoop_fh(pinfo, tree, tvb, offset, fhlen, hidden);
	}

	if(!hidden){
		/* calculate (heuristically) fhtype */
		switch (fhlen) {
		case 12:
			if (tvb_get_ntohl(tvb,offset) == 0x01000000) {
					fhtype=FHT_LINUX_KNFSD_NEW;
				}
			break;
		case 20:
			if (tvb_get_ntohl(tvb,offset) == 0x01000001) {
				fhtype=FHT_LINUX_KNFSD_NEW;
			}
			break;
		case 24:
			if (tvb_get_ntohl(tvb,offset) == 0x01000002) {
				fhtype=FHT_LINUX_KNFSD_NEW;
			}
			break;
		case 32: {
			guint32 len1;
			guint32 len2;
			if (tvb_get_ntohs(tvb,offset+4) == 0) {
				len1=tvb_get_ntohs(tvb,offset+8);
				if (tvb_bytes_exist(tvb,offset+10+len1,2)) {
					len2=tvb_get_ntohs(tvb,
					    offset+10+len1);
					if (fhlen==12+len1+len2) {
						fhtype=FHT_SVR4;
						goto type_ready;
					}
				}
			}
			/* For a NetApp filehandle, the flag bits must
			   include WAFL_FH_MULTIVOLUME, and the fileid
			   and generation number need to be nonzero in
			   the mount point, file, and export. */
			if ((tvb_get_ntohl(tvb,offset+8) & 0x20000000)
			    && tvb_get_ntohl(tvb,offset+0)
			    && tvb_get_ntohl(tvb,offset+4)
			    && tvb_get_ntohl(tvb,offset+12)
			    && tvb_get_ntohl(tvb,offset+16)
			    && tvb_get_ntohl(tvb,offset+24)
			    && tvb_get_ntohl(tvb,offset+28)) {
				fhtype=FHT_NETAPP;
				goto type_ready;
			}
			len1 = tvb_get_guint8(tvb,offset+4);
			if (len1<28 && tvb_bytes_exist(tvb,offset+5,len1)) {
				int wrong=0;
				for (len2=5+len1;len2<32;len2++) {
					if (tvb_get_guint8(tvb,offset+len2)) {
						wrong=1;
						break;
					}
				}
				if (!wrong) {
					fhtype=FHT_LINUX_NFSD_LE;
					goto type_ready;
				}
			}
			if (tvb_get_ntohl(tvb,offset+28) == 0) {
				if (tvb_get_ntohs(tvb,offset+14) == 0) {
					if (tvb_get_ntohs(tvb,offset+18) == 0) {
						fhtype=FHT_LINUX_KNFSD_LE;
						goto type_ready;
					}
				}
			}
			} break;
		}
	}

type_ready:

	if(!hidden){
		proto_tree_add_text(tree, tvb, offset, 0,
			"type: %s", val_to_str(fhtype, names_fhtype, "Unknown"));


		switch (fhtype) {
		case FHT_SVR4:
			dissect_fhandle_data_SVR4          (tvb, offset, tree,
			    fhlen);
		break;
		case FHT_LINUX_KNFSD_LE:
			dissect_fhandle_data_LINUX_KNFSD_LE(tvb, offset, tree,
			    fhlen);
		break;
		case FHT_LINUX_NFSD_LE:
			dissect_fhandle_data_LINUX_NFSD_LE (tvb, offset, tree,
			    fhlen);
		break;
		case FHT_LINUX_KNFSD_NEW:
			dissect_fhandle_data_LINUX_KNFSD_NEW (tvb, offset, tree,
			    fhlen);
		break;
		case FHT_NETAPP:
			dissect_fhandle_data_NETAPP (tvb, offset, tree,
			    fhlen);
		break;
		case FHT_UNKNOWN:
		default:
			dissect_fhandle_data_unknown(tvb, offset, tree, fhlen);
		break;
		}
	}
}

void
dissect_fhandle_hidden(packet_info *pinfo, proto_tree *tree, int frame)
{
	nfs_fhandle_data_t *nfd;

	nfd=se_tree_lookup32(nfs_fhandle_frame_table, frame);
	if(nfd && nfd->len){
		dissect_fhandle_data(nfd->tvb, 0, pinfo, tree, nfd->len, TRUE, NULL);
	}
}


/***************************/
/* NFS Version 2, RFC 1094 */
/***************************/


/* RFC 1094, Page 12..14 */
static const value_string names_nfs_stat[] =
{
	{	0,	"NFS_OK" },
	{	1,	"NFSERR_PERM" },
	{	2,	"NFSERR_NOENT" },
	{	5,	"NFSERR_IO" },
	{	6,	"NFSERR_NXIO" },
	{	13,	"NFSERR_ACCES" },
	{	17,	"NFSERR_EXIST" },
	{	18,	"NFSERR_XDEV" },	/* not in spec, but can happen */
	{	19,	"NFSERR_NODEV" },
	{	20,	"NFSERR_NOTDIR" },
	{	21,	"NFSERR_ISDIR" },
	{	22,	"NFSERR_INVAL" },	/* not in spec, but I think it can happen */
	{	26,	"NFSERR_TXTBSY" },	/* not in spec, but I think it can happen */
	{	27,	"NFSERR_FBIG" },
	{	28,	"NFSERR_NOSPC" },
	{	30,	"NFSERR_ROFS" },
	{	31,	"NFSERR_MLINK" },	/* not in spec, but can happen */
	{	45,	"NFSERR_OPNOTSUPP" }, /* not in spec, but I think it can happen */
	{	63,	"NFSERR_NAMETOOLONG" },
	{	66,	"NFSERR_NOTEMPTY" },
	{	69,	"NFSERR_DQUOT" },
	{	70,	"NFSERR_STALE" },
	{	99,	"NFSERR_WFLUSH" },
	{	0,	NULL }
};

/* RFC 1094, Page 12..14 */
static int
dissect_stat(tvbuff_t *tvb, int offset, proto_tree *tree,
	guint32 *status)
{
	guint32 stat;
	proto_item *stat_item;

	stat = tvb_get_ntohl(tvb, offset+0);

	if (tree) {
		proto_tree_add_uint(tree, hf_nfs_stat, tvb, offset+0, 4,
			stat);
		stat_item = proto_tree_add_uint(tree, hf_nfs_nfsstat, tvb,
			offset+0, 4, stat);
		PROTO_ITEM_SET_HIDDEN(stat_item);
	}

	offset += 4;

	if (status) *status = stat;

	return offset;
}


/* RFC 1094, Page 12..14 */
static int
dissect_nfs2_rmdir_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree* tree)
{
	guint32 status;
	const char *err;

	offset = dissect_stat(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			proto_item_append_text(tree, ", RMDIR Reply");
			break;
		default:
			err=val_to_str(status, names_nfs_stat, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", RMDIR Reply  Error:%s", err);
	}

	return offset;
}

static int
dissect_nfs2_symlink_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree* tree)
{
	guint32 status;
	const char *err;

	offset = dissect_stat(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			proto_item_append_text(tree, ", SYMLINK Reply");
			break;
		default:
			err=val_to_str(status, names_nfs_stat, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", SYMLINK Reply  Error:%s", err);
	}

	return offset;
}

static int
dissect_nfs2_link_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree* tree)
{
	guint32 status;
	const char *err;

	offset = dissect_stat(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			proto_item_append_text(tree, ", LINK Reply");
			break;
		default:
			err=val_to_str(status, names_nfs_stat, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", LINK Reply  Error:%s", err);
	}

	return offset;
}

static int
dissect_nfs2_rename_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree* tree)
{
	guint32 status;
	const char *err;

	offset = dissect_stat(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			proto_item_append_text(tree, ", RENAME Reply");
			break;
		default:
			err=val_to_str(status, names_nfs_stat, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", RENAME Reply  Error:%s", err);
	}

	return offset;
}

static int
dissect_nfs2_remove_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree* tree)
{
	guint32 status;
	const char *err;

	offset = dissect_stat(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			proto_item_append_text(tree, ", REMOVE Reply");
			break;
		default:
			err=val_to_str(status, names_nfs_stat, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", REMOVE Reply  Error:%s", err);
	}

	return offset;
}


/* RFC 1094, Page 15 */
static int
dissect_ftype(tvbuff_t *tvb, int offset, proto_tree *tree, const char* name)
{
	guint32 ftype;
	const char* ftype_name = NULL;

	const value_string nfs2_ftype[] =
	{
		{	0,	"Non-File" },
		{	1,	"Regular File" },
		{	2,	"Directory" },
		{	3,	"Block Special Device" },
		{	4,	"Character Special Device" },
		{	5,	"Symbolic Link" },
		{	0,	NULL }
	};

	ftype = tvb_get_ntohl(tvb, offset+0);
	ftype_name = val_to_str(ftype, nfs2_ftype, "%u");

	if (tree) {
		proto_tree_add_text(tree, tvb, offset, 4,
			"%s: %s (%u)", name, ftype_name, ftype);
	}

	offset += 4;
	return offset;
}


/* RFC 1094, Page 15 */
int
dissect_fhandle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree,
    const char *name, guint32 *hash)
{
	proto_item* fitem;
	proto_tree* ftree = NULL;

	if (tree) {
		fitem = proto_tree_add_text(tree, tvb, offset, FHSIZE,
			"%s", name);
		if (fitem)
			ftree = proto_item_add_subtree(fitem, ett_nfs_fhandle);
	}

	/* are we snooping fh to filenames ?*/
	if((!pinfo->fd->flags.visited) && nfs_file_name_snooping){
		rpc_call_info_value *civ=pinfo->private_data;

		/* NFS v2 LOOKUP, CREATE, MKDIR calls might give us a mapping*/
		if( (civ->prog==100003)
		  &&(civ->vers==2)
		  &&(!civ->request)
		  &&((civ->proc==4)||(civ->proc==9)||(civ->proc==14))
		) {
			nfs_name_snoop_add_fh(civ->xid, tvb,
				offset, 32);
		}

		/* MOUNT v1,v2 MNT replies might give us a filehandle*/
		if( (civ->prog==100005)
		  &&(civ->proc==1)
		  &&((civ->vers==1)||(civ->vers==2))
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

/* RFC 1094, Page 15 */
static int
dissect_nfs2_statfs_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	guint32 hash;

	offset = dissect_fhandle(tvb, offset, pinfo, tree, "object", &hash);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", FH:0x%08x", hash);
	}
	proto_item_append_text(tree, ", STATFS Call FH:0x%08x", hash);

	return offset;
}

static int
dissect_nfs2_readlink_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	guint32 hash;

	offset = dissect_fhandle(tvb, offset, pinfo, tree, "object", &hash);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", FH:0x%08x", hash);
	}
	proto_item_append_text(tree, ", READLINK Call FH:0x%08x", hash);

	return offset;
}

static int
dissect_nfs2_getattr_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	guint32 hash;

	offset = dissect_fhandle(tvb, offset, pinfo, tree, "object", &hash);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", FH:0x%08x", hash);
	}
	proto_item_append_text(tree, ", GETATTR Call FH:0x%08x", hash);

	return offset;
}


/* RFC 1094, Page 15 */
static int
dissect_timeval(tvbuff_t *tvb, int offset, proto_tree *tree, int hf_time, int hf_time_sec, int hf_time_usec)
{
	guint32	seconds;
	guint32 useconds;
	nstime_t ts;

	proto_item* time_item;
	proto_tree* time_tree = NULL;

	seconds = tvb_get_ntohl(tvb, offset+0);
	useconds = tvb_get_ntohl(tvb, offset+4);
	ts.secs = seconds;
	ts.nsecs = useconds*1000;

	if (tree) {
		time_item = proto_tree_add_time(tree, hf_time, tvb, offset, 8,
				&ts);
		if (time_item)
			time_tree = proto_item_add_subtree(time_item, ett_nfs_timeval);
	}

	if (time_tree) {
		proto_tree_add_uint(time_tree, hf_time_sec, tvb, offset, 4,
					seconds);
		proto_tree_add_uint(time_tree, hf_time_usec, tvb, offset+4, 4,
					useconds);
	}
	offset += 8;
	return offset;
}


/* RFC 1094, Page 16 */
static const value_string nfs2_mode_names[] = {
	{	0040000,	"Directory"	},
	{	0020000,	"Character Special Device"	},
	{	0060000,	"Block Special Device"	},
	{	0100000,	"Regular File"	},
	{	0120000,	"Symbolic Link"	},
	{	0140000,	"Named Socket"	},
	{	0000000,	NULL		},
};

static int
dissect_mode(tvbuff_t *tvb, int offset, proto_tree *tree, const char* name)
{
	guint32 mode;
	proto_item* mode_item = NULL;
	proto_tree* mode_tree = NULL;

	mode = tvb_get_ntohl(tvb, offset+0);

	if (tree) {
		mode_item = proto_tree_add_text(tree, tvb, offset, 4,
			"%s: 0%o", name, mode);
		if (mode_item)
			mode_tree = proto_item_add_subtree(mode_item, ett_nfs_mode);
	}

	if (mode_tree) {
		proto_tree_add_text(mode_tree, tvb, offset, 4, "%s",
			decode_enumerated_bitfield(mode,  0160000, 16,
			nfs2_mode_names, "%s"));
		proto_tree_add_text(mode_tree, tvb, offset, 4, "%s",
		decode_boolean_bitfield(mode,   04000, 16, "Set user id on exec", "not SUID"));
		proto_tree_add_text(mode_tree, tvb, offset, 4, "%s",
		decode_boolean_bitfield(mode,   02000, 16, "Set group id on exec", "not SGID"));
		proto_tree_add_text(mode_tree, tvb, offset, 4, "%s",
		decode_boolean_bitfield(mode,   01000, 16, "Save swapped text even after use", "not save swapped text"));
		proto_tree_add_text(mode_tree, tvb, offset, 4, "%s",
		decode_boolean_bitfield(mode,    0400, 16, "Read permission for owner", "no Read permission for owner"));
		proto_tree_add_text(mode_tree, tvb, offset, 4, "%s",
		decode_boolean_bitfield(mode,    0200, 16, "Write permission for owner", "no Write permission for owner"));
		proto_tree_add_text(mode_tree, tvb, offset, 4, "%s",
		decode_boolean_bitfield(mode,    0100, 16, "Execute permission for owner", "no Execute permission for owner"));
		proto_tree_add_text(mode_tree, tvb, offset, 4, "%s",
		decode_boolean_bitfield(mode,     040, 16, "Read permission for group", "no Read permission for group"));
		proto_tree_add_text(mode_tree, tvb, offset, 4, "%s",
		decode_boolean_bitfield(mode,     020, 16, "Write permission for group", "no Write permission for group"));
		proto_tree_add_text(mode_tree, tvb, offset, 4, "%s",
		decode_boolean_bitfield(mode,     010, 16, "Execute permission for group", "no Execute permission for group"));
		proto_tree_add_text(mode_tree, tvb, offset, 4, "%s",
		decode_boolean_bitfield(mode,      04, 16, "Read permission for others", "no Read permission for others"));
		proto_tree_add_text(mode_tree, tvb, offset, 4, "%s",
		decode_boolean_bitfield(mode,      02, 16, "Write permission for others", "no Write permission for others"));
		proto_tree_add_text(mode_tree, tvb, offset, 4, "%s",
		decode_boolean_bitfield(mode,      01, 16, "Execute permission for others", "no Execute permission for others"));
	}

	offset += 4;
	return offset;
}


/* RFC 1094, Page 15 */
int
dissect_fattr(tvbuff_t *tvb, int offset, proto_tree *tree, const char* name)
{
	proto_item* fattr_item = NULL;
	proto_tree* fattr_tree = NULL;
	int old_offset = offset;

	if (tree) {
		fattr_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s", name);
		fattr_tree = proto_item_add_subtree(fattr_item, ett_nfs_fattr);
	}

	offset = dissect_ftype(tvb, offset, fattr_tree, "type");
	offset = dissect_mode(tvb, offset, fattr_tree, "mode");
	offset = dissect_rpc_uint32(tvb, fattr_tree, hf_nfs_fattr_nlink, offset);
	offset = dissect_rpc_uint32(tvb, fattr_tree, hf_nfs_fattr_uid, offset);
	offset = dissect_rpc_uint32(tvb, fattr_tree, hf_nfs_fattr_gid, offset);
	offset = dissect_rpc_uint32(tvb, fattr_tree, hf_nfs_fattr_size, offset);
	offset = dissect_rpc_uint32(tvb, fattr_tree, hf_nfs_fattr_blocksize, offset);
	offset = dissect_rpc_uint32(tvb, fattr_tree, hf_nfs_fattr_rdev, offset);
	offset = dissect_rpc_uint32(tvb, fattr_tree, hf_nfs_fattr_blocks, offset);
	offset = dissect_rpc_uint32(tvb, fattr_tree, hf_nfs_fattr_fsid, offset);
	offset = dissect_rpc_uint32(tvb, fattr_tree, hf_nfs_fattr_fileid, offset);

	offset = dissect_timeval(tvb, offset, fattr_tree, hf_nfs_atime, hf_nfs_atime_sec, hf_nfs_atime_usec);
	offset = dissect_timeval(tvb, offset, fattr_tree, hf_nfs_mtime, hf_nfs_mtime_sec, hf_nfs_mtime_usec);
	offset = dissect_timeval(tvb, offset, fattr_tree, hf_nfs_ctime, hf_nfs_ctime_sec, hf_nfs_ctime_usec);

	/* now we know, that fattr is shorter */
	if (fattr_item) {
		proto_item_set_len(fattr_item, offset - old_offset);
	}

	return offset;
}


/* RFC 1094, Page 17 */
static int
dissect_sattr(tvbuff_t *tvb, int offset, proto_tree *tree, const char* name)
{
	proto_item* sattr_item = NULL;
	proto_tree* sattr_tree = NULL;
	int old_offset = offset;

	if (tree) {
		sattr_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s", name);
		sattr_tree = proto_item_add_subtree(sattr_item, ett_nfs_sattr);
	}

	if (tvb_get_ntohl(tvb, offset+0) != 0xffffffff)
		offset = dissect_mode(tvb, offset, sattr_tree, "mode");
	else {
		proto_tree_add_text(sattr_tree, tvb, offset, 4, "mode: no value");
		offset += 4;
	}

	if (tvb_get_ntohl(tvb, offset+0) != 0xffffffff)
		offset = dissect_rpc_uint32(tvb, sattr_tree, hf_nfs_fattr_uid,
			offset);
	else {
		proto_tree_add_text(sattr_tree, tvb, offset, 4, "uid: no value");
		offset += 4;
	}

	if (tvb_get_ntohl(tvb, offset+0) != 0xffffffff)
		offset = dissect_rpc_uint32(tvb, sattr_tree, hf_nfs_fattr_gid,
			offset);
	else {
		proto_tree_add_text(sattr_tree, tvb, offset, 4, "gid: no value");
		offset += 4;
	}

	if (tvb_get_ntohl(tvb, offset+0) != 0xffffffff)
		offset = dissect_rpc_uint32(tvb, sattr_tree, hf_nfs_fattr_size,
			offset);
	else {
		proto_tree_add_text(sattr_tree, tvb, offset, 4, "size: no value");
		offset += 4;
	}

	if (tvb_get_ntohl(tvb, offset+0) != 0xffffffff) {
		offset = dissect_timeval(tvb, offset, sattr_tree, hf_nfs_atime, hf_nfs_atime_sec, hf_nfs_atime_usec);
	} else {
		proto_tree_add_text(sattr_tree, tvb, offset, 8, "atime: no value");
		offset += 8;
	}

	if (tvb_get_ntohl(tvb, offset+0) != 0xffffffff) {
		offset = dissect_timeval(tvb, offset, sattr_tree, hf_nfs_mtime, hf_nfs_mtime_sec, hf_nfs_mtime_usec);
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


/* RFC 1094, Page 17 */
static int
dissect_filename(tvbuff_t *tvb, int offset,
    proto_tree *tree, int hf, char **string_ret)
{
	offset = dissect_rpc_string(tvb, tree, hf, offset, string_ret);
	return offset;
}


/* RFC 1094, Page 17 */
static int
dissect_path(tvbuff_t *tvb, int offset, proto_tree *tree, int hf, char **name)
{
	offset = dissect_rpc_string(tvb, tree, hf, offset, name);
	return offset;
}


/* RFC 1094, Page 17,18 */
static int
dissect_attrstat(tvbuff_t *tvb, int offset, proto_tree *tree, packet_info *pinfo, const char *funcname)
{
	guint32 status;
	const char *err;

	offset = dissect_stat(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_fattr(tvb, offset, tree, "attributes");
			proto_item_append_text(tree, ", %s Reply", funcname);
		break;
		default:
			err=val_to_str(status, names_nfs_stat, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", %s Reply  Error:%s", funcname, err);
		break;
	}

	return offset;
}


/* RFC 1094, Page 17,18 */
static int
dissect_nfs2_write_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree* tree)
{
	offset = dissect_attrstat(tvb, offset, tree, pinfo, "WRITE");

	return offset;
}

static int
dissect_nfs2_setattr_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree* tree)
{
	offset = dissect_attrstat(tvb, offset, tree, pinfo, "SETATTR");

	return offset;
}

static int
dissect_nfs2_getattr_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree* tree)
{
	offset = dissect_attrstat(tvb, offset, tree, pinfo, "GETATTR");

	return offset;
}


/* RFC 1094, Page 18 */
static int
dissect_diropargs(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, const char* label, guint32 *hash, char **name)
{
	proto_item* diropargs_item = NULL;
	proto_tree* diropargs_tree = NULL;
	int old_offset = offset;

	if (tree) {
		diropargs_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s", label);
		diropargs_tree = proto_item_add_subtree(diropargs_item, ett_nfs_diropargs);
	}

	/* are we snooping fh to filenames ?*/
	if((!pinfo->fd->flags.visited) && nfs_file_name_snooping){
		/* v2 LOOKUP, CREATE, MKDIR calls might give us a mapping*/
		rpc_call_info_value *civ=pinfo->private_data;

		if( (civ->prog==100003)
		  &&(civ->vers==2)
		  &&(civ->request)
		  &&((civ->proc==4)||(civ->proc==9)||(civ->proc==14))
		) {
			nfs_name_snoop_add_name(civ->xid, tvb,
				offset+36, tvb_get_ntohl(tvb, offset+32),
				offset, 32, NULL);
		}
	}

	offset = dissect_fhandle(tvb, offset, pinfo, diropargs_tree, "dir", hash);
	offset = dissect_filename(tvb, offset, diropargs_tree, hf_nfs_name, name);

	/* now we know, that diropargs is shorter */
	if (diropargs_item) {
		proto_item_set_len(diropargs_item, offset - old_offset);
	}

	return offset;
}


/* RFC 1094, Page 18 */
static int
dissect_nfs2_rmdir_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	guint32 hash;
	char *name=NULL;

	offset = dissect_diropargs(tvb, offset, pinfo, tree, "where", &hash, &name);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", DH:0x%08x/%s", hash, name);
	}
	proto_item_append_text(tree, ", RMDIR Call DH:0x%08x/%s", hash, name);

	return offset;
}

static int
dissect_nfs2_remove_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	guint32 hash;
	char *name=NULL;

	offset = dissect_diropargs(tvb, offset, pinfo, tree, "where", &hash, &name);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", DH:0x%08x/%s", hash, name);
	}
	proto_item_append_text(tree, ", REMOVE Call DH:0x%08x/%s", hash, name);

	return offset;
}

static int
dissect_nfs2_lookup_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	guint32 hash;
	char *name=NULL;

	offset = dissect_diropargs(tvb, offset, pinfo, tree, "where", &hash, &name);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", DH:0x%08x/%s", hash, name);
	}
	proto_item_append_text(tree, ", LOOKUP Call DH:0x%08x/%s", hash, name);

	return offset;
}


/* RFC 1094, Page 18 */
static int
dissect_diropres(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, const char *funcname)
{
	guint32	status;
	guint32 hash;
	const char *err;

	offset = dissect_stat(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_fhandle(tvb, offset, pinfo, tree, "file", &hash);
			offset = dissect_fattr  (tvb, offset, tree, "attributes");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO,", FH:0x%08x", hash);
			}
			proto_item_append_text(tree, ", %s Reply FH:0x%08x", funcname, hash);
		break;
		default:
			err=val_to_str(status, names_nfs_stat, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", %s Reply  Error:%s", funcname, err);
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


/* RFC 1094, Page 18 */
static int
dissect_nfs2_mkdir_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	offset = dissect_diropres(tvb, offset, pinfo, tree, "MKDIR");
	return offset;
}

static int
dissect_nfs2_create_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	offset = dissect_diropres(tvb, offset, pinfo, tree, "CREATE");
	return offset;
}

static int
dissect_nfs2_lookup_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	offset = dissect_diropres(tvb, offset, pinfo, tree, "LOOKUP");
	return offset;
}


/* RFC 1094, Page 6 */
static int
dissect_nfs2_setattr_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree)
{
	guint32 hash;

	offset = dissect_fhandle(tvb, offset, pinfo, tree, "file", &hash);
	offset = dissect_sattr  (tvb, offset,        tree, "attributes");

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", FH:0x%08x", hash);
	}
	proto_item_append_text(tree, ", SETATTR Call FH:0x%08x", hash);
	return offset;
}


/* RFC 1094, Page 6 */
static int
dissect_nfs2_readlink_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	guint32	status;
	const char *err;
	char *name=NULL;

	offset = dissect_stat(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_path(tvb, offset, tree, hf_nfs_readlink_data, &name);
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Path:%s", name);
			}
			proto_item_append_text(tree, ", READLINK Reply Path:%s", name);
		break;
		default:
			err=val_to_str(status, names_nfs_stat, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", READLINK Reply  Error:%s", err);
		break;
	}

	return offset;
}


/* RFC 1094, Page 7 */
static int
dissect_nfs2_read_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree)
{
	guint32 offset_value;
	guint32 count;
	guint32 totalcount;
	guint32 hash;

	offset = dissect_fhandle(tvb, offset, pinfo, tree, "file", &hash);
	offset_value = tvb_get_ntohl(tvb, offset+0);
	count        = tvb_get_ntohl(tvb, offset+4);
	totalcount   = tvb_get_ntohl(tvb, offset+8);
	if (tree) {
		proto_tree_add_uint(tree, hf_nfs_read_offset, tvb,
		offset+0, 4, offset_value);
		proto_tree_add_uint(tree, hf_nfs_read_count, tvb,
		offset+4, 4, count);
		proto_tree_add_uint(tree, hf_nfs_read_totalcount, tvb,
		offset+8, 4, totalcount);
	}
	offset += 12;

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", FH:0x%08x Offset:%d Count:%d TotalCount:%d", hash, offset_value, count, totalcount);
	}
	proto_item_append_text(tree, ", READ Call FH:0x%08x Offset:%d Count:%d TotalCount:%d", hash, offset_value, count, totalcount);

	return offset;
}


/* RFC 1094, Page 7 */
static int
dissect_nfs2_read_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree* tree)
{
	guint32 status;
	const char *err;

	offset = dissect_stat(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_fattr(tvb, offset, tree, "attributes");
			proto_item_append_text(tree, ", READ Reply");
			offset = dissect_nfsdata(tvb, offset, tree, hf_nfs_data);
		break;
		default:
			err=val_to_str(status, names_nfs_stat, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", READ Reply  Error:%s", err);
		break;
	}

	return offset;
}


/* RFC 1094, Page 8 */
static int
dissect_nfs2_write_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree)
{
	guint32 beginoffset;
	guint32 offset_value;
	guint32 totalcount;
	guint32 hash;

	offset = dissect_fhandle(tvb, offset, pinfo, tree, "file", &hash);
	beginoffset  = tvb_get_ntohl(tvb, offset+0);
	offset_value = tvb_get_ntohl(tvb, offset+4);
	totalcount   = tvb_get_ntohl(tvb, offset+8);
	if (tree) {
		proto_tree_add_uint(tree, hf_nfs_write_beginoffset, tvb,
		offset+0, 4, beginoffset);
		proto_tree_add_uint(tree, hf_nfs_write_offset, tvb,
		offset+4, 4, offset_value);
		proto_tree_add_uint(tree, hf_nfs_write_totalcount, tvb,
		offset+8, 4, totalcount);
	}
	offset += 12;

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", FH:0x%08x BeginOffset:%d Offset:%d TotalCount:%d", hash, beginoffset, offset_value, totalcount);
	}
	proto_item_append_text(tree, ", WRITE Call FH:0x%08x BeginOffset:%d Offset:%d TotalCount:%d", hash, beginoffset, offset_value, totalcount);

	offset = dissect_nfsdata(tvb, offset, tree, hf_nfs_data);

	return offset;
}


/* RFC 1094, Page 8 */
static int
dissect_nfs2_mkdir_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree)
{
	guint32 hash;
	char *name=NULL;

	offset = dissect_diropargs(tvb, offset, pinfo, tree, "where", &hash, &name);
	offset = dissect_sattr    (tvb, offset,        tree, "attributes");

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", DH:0x%08x/%s", hash, name);
	}
	proto_item_append_text(tree, ", MKDIR Call DH:0x%08x/%s", hash, name);

	return offset;
}

static int
dissect_nfs2_create_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree)
{
	guint32 hash;
	char *name=NULL;

	offset = dissect_diropargs(tvb, offset, pinfo, tree, "where", &hash, &name);
	offset = dissect_sattr    (tvb, offset,        tree, "attributes");

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", DH:0x%08x/%s", hash, name);
	}
	proto_item_append_text(tree, ", CREATE Call DH:0x%08x/%s", hash, name);

	return offset;
}


/* RFC 1094, Page 9 */
static int
dissect_nfs2_rename_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree)
{
	guint32 from_hash;
	char *from_name=NULL;
	guint32 to_hash;
	char *to_name=NULL;

	offset = dissect_diropargs(tvb, offset, pinfo, tree, "from", &from_hash, &from_name);
	offset = dissect_diropargs(tvb, offset, pinfo, tree, "to", &to_hash, &to_name);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", From DH:0x%08x/%s To DH:0x%08x/%s", from_hash, from_name, to_hash, to_name);
	}
	proto_item_append_text(tree, ", RENAME Call From DH:0x%08x/%s To DH:0x%08x/%s", from_hash, from_name, to_hash, to_name);

	return offset;
}


/* RFC 1094, Page 9 */
static int
dissect_nfs2_link_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree)
{
	guint32 from_hash;
	guint32 to_hash;
	char *to_name=NULL;

	offset = dissect_fhandle(tvb, offset, pinfo, tree, "from", &from_hash);
	offset = dissect_diropargs(tvb, offset, pinfo, tree, "to", &to_hash, &to_name);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", From DH:0x%08x To DH:0x%08x/%s", from_hash, to_hash, to_name);
	}
	proto_item_append_text(tree, ", LINK Call From DH:0x%08x To DH:0x%08x/%s", from_hash, to_hash, to_name);

	return offset;
}


/* RFC 1094, Page 10 */
static int
dissect_nfs2_symlink_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree)
{
	guint32 from_hash;
	char *from_name=NULL;
	char *to_name=NULL;

	offset = dissect_diropargs(tvb, offset, pinfo, tree, "from", &from_hash, &from_name);
	offset = dissect_path(tvb, offset, tree, hf_nfs_symlink_to, &to_name);
	offset = dissect_sattr(tvb, offset, tree, "attributes");

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", From DH:0x%08x/%s To %s", from_hash, from_name, to_name);
	}
	proto_item_append_text(tree, ", SYMLINK Call From DH:0x%08x/%s To %s", from_hash, from_name, to_name);

	return offset;
}


/* RFC 1094, Page 11 */
static int
dissect_nfs2_readdir_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree)
{
	guint32	cookie;
	guint32	count;
	guint32 hash;

	offset = dissect_fhandle(tvb, offset, pinfo, tree, "dir", &hash);
	cookie  = tvb_get_ntohl(tvb, offset+ 0);
	count = tvb_get_ntohl(tvb, offset+ 4);
	if (tree) {
		proto_tree_add_uint(tree, hf_nfs_readdir_cookie, tvb,
			offset+ 0, 4, cookie);
		proto_tree_add_uint(tree, hf_nfs_readdir_count, tvb,
			offset+ 4, 4, count);
	}
	offset += 8;

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", FH:0x%08x", hash);
	}
	proto_item_append_text(tree, ", READDIR Call FH:0x%08x", hash);

	return offset;
}


/* RFC 1094, Page 11 */
static int
dissect_readdir_entry(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree* tree)
{
	proto_item* entry_item = NULL;
	proto_tree* entry_tree = NULL;
	int old_offset = offset;
	guint32 fileid;
	guint32 cookie;
	char *name;

	if (tree) {
		entry_item = proto_tree_add_item(tree, hf_nfs_readdir_entry, tvb,
			offset+0, -1, FALSE);
		entry_tree = proto_item_add_subtree(entry_item, ett_nfs_readdir_entry);
	}

	fileid = tvb_get_ntohl(tvb, offset + 0);
	if (entry_tree)
		proto_tree_add_uint(entry_tree, hf_nfs_readdir_entry_fileid, tvb,
			offset+0, 4, fileid);
	offset += 4;

	offset = dissect_filename(tvb, offset, entry_tree,
		hf_nfs_readdir_entry_name, &name);
	if (entry_item)
		proto_item_set_text(entry_item, "Entry: file ID %u, name %s",
		fileid, name);

	cookie = tvb_get_ntohl(tvb, offset + 0);
	if (entry_tree)
		proto_tree_add_uint(entry_tree, hf_nfs_readdir_entry_cookie, tvb,
			offset+0, 4, cookie);
	offset += 4;

	/* now we know, that a readdir entry is shorter */
	if (entry_item) {
		proto_item_set_len(entry_item, offset - old_offset);
	}

	return offset;
}

/* RFC 1094, Page 11 */
static int
dissect_nfs2_readdir_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	guint32 status;
	guint32 eof_value;
	const char *err;

	offset = dissect_stat(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			proto_item_append_text(tree, ", READDIR Reply");

			offset = dissect_rpc_list(tvb, pinfo, tree, offset,
				dissect_readdir_entry);
			eof_value = tvb_get_ntohl(tvb, offset+0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs_readdir_eof, tvb,
					offset+ 0, 4, eof_value);
			offset += 4;
		break;
		default:
			err=val_to_str(status, names_nfs_stat, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", READDIR Reply  Error:%s", err);
		break;
	}

	return offset;
}


/* RFC 1094, Page 12 */
static int
dissect_nfs2_statfs_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree* tree)
{
	guint32 status;
	guint32 tsize;
	guint32 bsize;
	guint32 blocks;
	guint32 bfree;
	guint32 bavail;
	const char *err;

	offset = dissect_stat(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			tsize  = tvb_get_ntohl(tvb, offset+ 0);
			bsize  = tvb_get_ntohl(tvb, offset+ 4);
			blocks = tvb_get_ntohl(tvb, offset+ 8);
			bfree  = tvb_get_ntohl(tvb, offset+12);
			bavail = tvb_get_ntohl(tvb, offset+16);
			if (tree) {
				proto_tree_add_uint(tree, hf_nfs_statfs_tsize, tvb,
					offset+ 0, 4, tsize);
				proto_tree_add_uint(tree, hf_nfs_statfs_bsize, tvb,
					offset+ 4, 4, bsize);
				proto_tree_add_uint(tree, hf_nfs_statfs_blocks, tvb,
					offset+ 8, 4, blocks);
				proto_tree_add_uint(tree, hf_nfs_statfs_bfree, tvb,
					offset+12, 4, bfree);
				proto_tree_add_uint(tree, hf_nfs_statfs_bavail, tvb,
					offset+16, 4, bavail);
			}
			offset += 20;
			proto_item_append_text(tree, ", STATFS Reply");
		break;
		default:
			err=val_to_str(status, names_nfs_stat, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", STATFS Reply  Error:%s", err);
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
	{ 0,NULL,NULL,NULL }
};

static const value_string nfsv2_proc_vals[] = {
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

/* end of NFS Version 2 */


/***************************/
/* NFS Version 3, RFC 1813 */
/***************************/


/* RFC 1813, Page 15 */
static int
dissect_filename3(tvbuff_t *tvb, int offset,
    proto_tree *tree, int hf, char **string_ret)
{
	offset = dissect_rpc_string(tvb, tree, hf, offset, string_ret);
	return offset;
}


/* RFC 1813, Page 15 */
static int
dissect_nfspath3(tvbuff_t *tvb, int offset, proto_tree *tree, int hf, char **name)
{
	offset = dissect_rpc_string(tvb, tree, hf, offset, name);
	return offset;
}

/* RFC 1813, Page 15 */
static int
dissect_cookieverf3(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_tree_add_text(tree, tvb, offset, NFS3_COOKIEVERFSIZE,
		"Verifier: Opaque Data");
	offset += NFS3_COOKIEVERFSIZE;
	return offset;
}


/* RFC 1813, Page 16 */
static int
dissect_createverf3(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_tree_add_text(tree, tvb, offset, NFS3_CREATEVERFSIZE,
		"Verifier: Opaque Data");
	offset += NFS3_CREATEVERFSIZE;
	return offset;
}


/* RFC 1813, Page 16 */
static int
dissect_writeverf3(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_tree_add_text(tree, tvb, offset, NFS3_WRITEVERFSIZE,
		"Verifier: Opaque Data");
	offset += NFS3_WRITEVERFSIZE;
	return offset;
}

/* RFC 1813, Page 16 */
static int
dissect_mode3(tvbuff_t *tvb, int offset, proto_tree *tree, const char* name, guint32 *mode)
{
	guint32 mode3;
	proto_item* mode3_item = NULL;
	proto_tree* mode3_tree = NULL;

	mode3 = tvb_get_ntohl(tvb, offset+0);
	if(mode){
		*mode=mode3;
	}

	if (tree) {
		mode3_item = proto_tree_add_text(tree, tvb, offset, 4,
			"%s: 0%o", name, mode3);
		if (mode3_item)
			mode3_tree = proto_item_add_subtree(mode3_item, ett_nfs_mode3);
	}

	/* RFC 1813, Page 23 */
	if (mode3_tree) {
		proto_tree_add_text(mode3_tree, tvb, offset, 4, "%s",
		decode_boolean_bitfield(mode3,   0x800, 12, "Set user id on exec", "not SUID"));
		proto_tree_add_text(mode3_tree, tvb, offset, 4, "%s",
		decode_boolean_bitfield(mode3,   0x400, 12, "Set group id on exec", "not SGID"));
		proto_tree_add_text(mode3_tree, tvb, offset, 4, "%s",
		decode_boolean_bitfield(mode3,   0x200, 12, "Save swapped text even after use", "not save swapped text"));
		proto_tree_add_text(mode3_tree, tvb, offset, 4, "%s",
		decode_boolean_bitfield(mode3,   0x100, 12, "Read permission for owner", "no Read permission for owner"));
		proto_tree_add_text(mode3_tree, tvb, offset, 4, "%s",
		decode_boolean_bitfield(mode3,    0x80, 12, "Write permission for owner", "no Write permission for owner"));
		proto_tree_add_text(mode3_tree, tvb, offset, 4, "%s",
		decode_boolean_bitfield(mode3,    0x40, 12, "Execute permission for owner", "no Execute permission for owner"));
		proto_tree_add_text(mode3_tree, tvb, offset, 4, "%s",
		decode_boolean_bitfield(mode3,    0x20, 12, "Read permission for group", "no Read permission for group"));
		proto_tree_add_text(mode3_tree, tvb, offset, 4, "%s",
		decode_boolean_bitfield(mode3,    0x10, 12, "Write permission for group", "no Write permission for group"));
		proto_tree_add_text(mode3_tree, tvb, offset, 4, "%s",
		decode_boolean_bitfield(mode3,     0x8, 12, "Execute permission for group", "no Execute permission for group"));
		proto_tree_add_text(mode3_tree, tvb, offset, 4, "%s",
		decode_boolean_bitfield(mode3,     0x4, 12, "Read permission for others", "no Read permission for others"));
		proto_tree_add_text(mode3_tree, tvb, offset, 4, "%s",
		decode_boolean_bitfield(mode3,     0x2, 12, "Write permission for others", "no Write permission for others"));
		proto_tree_add_text(mode3_tree, tvb, offset, 4, "%s",
		decode_boolean_bitfield(mode3,     0x1, 12, "Execute permission for others", "no Execute permission for others"));
	}

	offset += 4;
	return offset;
}

/* RFC 1813, Page 16,17 */
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


/* RFC 1813, Page 16 */
static int
dissect_nfsstat3(tvbuff_t *tvb, int offset,
	proto_tree *tree,guint32 *status)
{
	guint32 nfsstat3;
	proto_item *stat_item;

	nfsstat3 = tvb_get_ntohl(tvb, offset+0);

	if (tree) {
		proto_tree_add_uint(tree, hf_nfs_nfsstat3, tvb,
			offset+0, 4, nfsstat3);
		stat_item = proto_tree_add_uint(tree, hf_nfs_nfsstat, tvb,
			offset+0, 4, nfsstat3);
		PROTO_ITEM_SET_HIDDEN(stat_item);
	}

	offset += 4;
	*status = nfsstat3;
	return offset;
}


static const value_string names_nfs_ftype3[] =
{
	{	NF3REG,	"Regular File" },
	{	NF3DIR,	"Directory" },
	{	NF3BLK,	"Block Special Device" },
	{	NF3CHR,	"Character Special Device" },
	{	NF3LNK,	"Symbolic Link" },
	{	NF3SOCK,"Socket" },
	{	NF3FIFO,"Named Pipe" },
	{	0,	NULL }
};


/* RFC 1813, Page 20 */
static int
dissect_ftype3(tvbuff_t *tvb, int offset, proto_tree *tree,
	int hf, guint32* ftype3)
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


/* RFC 1813, Page 20 */
static int
dissect_specdata3(tvbuff_t *tvb, int offset, proto_tree *tree, const char* name)
{
	guint32	specdata1;
	guint32	specdata2;

	proto_item* specdata3_item;
	proto_tree* specdata3_tree = NULL;

	specdata1 = tvb_get_ntohl(tvb, offset+0);
	specdata2 = tvb_get_ntohl(tvb, offset+4);

	if (tree) {
		specdata3_item = proto_tree_add_text(tree, tvb, offset, 8,
			"%s: %u,%u", name, specdata1, specdata2);
		if (specdata3_item)
			specdata3_tree = proto_item_add_subtree(specdata3_item,
					ett_nfs_specdata3);
	}

	if (specdata3_tree) {
		proto_tree_add_text(specdata3_tree, tvb,offset+0,4,
					"specdata1: %u", specdata1);
		proto_tree_add_text(specdata3_tree, tvb,offset+4,4,
					"specdata2: %u", specdata2);
	}

	offset += 8;
	return offset;
}


/* RFC 1813, Page 21 */
int
dissect_nfs_fh3(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree, const char *name, guint32 *hash)
{
	guint fh3_len;
	guint fh3_len_full;
	guint fh3_fill;
	proto_item* fitem = NULL;
	proto_tree* ftree = NULL;
	int fh_offset,fh_length;

	fh3_len = tvb_get_ntohl(tvb, offset+0);
	fh3_len_full = rpc_roundup(fh3_len);
	fh3_fill = fh3_len_full - fh3_len;

	if (tree) {
		fitem = proto_tree_add_text(tree, tvb, offset, 4+fh3_len_full,
			"%s", name);
		if (fitem)
			ftree = proto_item_add_subtree(fitem, ett_nfs_fh3);
	}

	/* are we snooping fh to filenames ?*/
	if((!pinfo->fd->flags.visited) && nfs_file_name_snooping){
		rpc_call_info_value *civ=pinfo->private_data;

		/* NFS v3 LOOKUP, CREATE, MKDIR, READDIRPLUS 
			calls might give us a mapping*/
		if( (civ->prog==100003)
		  &&(civ->vers==3)
		  &&(!civ->request)
		  &&((civ->proc==3)||(civ->proc==8)||(civ->proc==9)||(civ->proc==17))
		) {
			fh_length=tvb_get_ntohl(tvb, offset);
			fh_offset=offset+4;
			nfs_name_snoop_add_fh(civ->xid, tvb,
				fh_offset, fh_length);
		}

		/* MOUNT v3 MNT replies might give us a filehandle */
		if( (civ->prog==100005)
		  &&(civ->vers==3)
		  &&(!civ->request)
		  &&(civ->proc==1)
		) {
			fh_length=tvb_get_ntohl(tvb, offset);
			fh_offset=offset+4;
			nfs_name_snoop_add_fh(civ->xid, tvb,
				fh_offset, fh_length);
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

	offset += 4;

	return offset;
}


/* RFC 1813, Page 21 */
static int
dissect_nfstime3(tvbuff_t *tvb, int offset,
	proto_tree *tree, int hf_time, int hf_time_sec, int hf_time_nsec)
{
	guint32	seconds;
	guint32 nseconds;
	nstime_t ts;

	proto_item* time_item;
	proto_tree* time_tree = NULL;

	seconds = tvb_get_ntohl(tvb, offset+0);
	nseconds = tvb_get_ntohl(tvb, offset+4);
	ts.secs = seconds;
	ts.nsecs = nseconds;

	if (tree) {
		time_item = proto_tree_add_time(tree, hf_time, tvb, offset, 8,
				&ts);
		if (time_item)
			time_tree = proto_item_add_subtree(time_item, ett_nfs_nfstime3);
	}

	if (time_tree) {
		proto_tree_add_uint(time_tree, hf_time_sec, tvb, offset, 4,
					seconds);
		proto_tree_add_uint(time_tree, hf_time_nsec, tvb, offset+4, 4,
					nseconds);
	}
	offset += 8;
	return offset;
}


/* RFC 1813, Page 22 
 * The levels parameter tells this helper how many levels up in the tree it 
 * should display useful info such as type,mode,uid,gid
 * If level has the COL_INFO_LEVEL flag set it will also display
 * this info in the info column.
 */
static int
dissect_nfs_fattr3(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree, const char* name, guint32 levels)
{
	proto_item* fattr3_item = NULL;
	proto_tree* fattr3_tree = NULL;
	int old_offset = offset;
	guint32 type, mode, uid, gid;

	if (tree) {
		fattr3_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s", name);
		fattr3_tree = proto_item_add_subtree(fattr3_item, ett_nfs_fattr3);
	}

	/* ftype */
	offset = dissect_ftype3(tvb,offset,fattr3_tree,hf_nfs_fattr3_type,&type);

	/* mode */
	offset = dissect_mode3(tvb,offset,fattr3_tree,"mode",&mode);

	/* nlink */
	offset = dissect_rpc_uint32(tvb, fattr3_tree, hf_nfs_fattr3_nlink,
		offset);

	/* uid */
	uid=tvb_get_ntohl(tvb, offset);
	offset = dissect_rpc_uint32(tvb, fattr3_tree, hf_nfs_fattr3_uid,
		offset);

	/* gid */
	gid=tvb_get_ntohl(tvb, offset);
	offset = dissect_rpc_uint32(tvb, fattr3_tree, hf_nfs_fattr3_gid,
		offset);

	/* size*/
	offset = dissect_rpc_uint64(tvb, fattr3_tree, hf_nfs_fattr3_size,
		offset);

	/* used */
	offset = dissect_rpc_uint64(tvb, fattr3_tree, hf_nfs_fattr3_used,
		offset);

	/* rdev */
	offset = dissect_specdata3(tvb,offset,fattr3_tree,"rdev");

	/* fsid */
	offset = dissect_rpc_uint64(tvb, fattr3_tree, hf_nfs_fattr3_fsid,
		offset);

	/* fileid */
	offset = dissect_rpc_uint64(tvb, fattr3_tree, hf_nfs_fattr3_fileid,
		offset);

	/* atime */
	offset = dissect_nfstime3 (tvb,offset,fattr3_tree,hf_nfs_atime,hf_nfs_atime_sec,hf_nfs_atime_nsec);

	/* mtime */
	offset = dissect_nfstime3 (tvb,offset,fattr3_tree,hf_nfs_mtime,hf_nfs_mtime_sec,hf_nfs_mtime_nsec);

	/* ctime */
	offset = dissect_nfstime3 (tvb,offset,fattr3_tree,hf_nfs_ctime,hf_nfs_ctime_sec,hf_nfs_ctime_nsec);

	/* now we know, that fattr3 is shorter */
	if (fattr3_item) {
		proto_item_set_len(fattr3_item, offset - old_offset);
	}


	/* put some nice info in COL_INFO for GETATTR replies */
	if(levels&COL_INFO_LEVEL){
		levels&=(~COL_INFO_LEVEL);
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_append_fstr(pinfo->cinfo, COL_INFO,
				"  %s mode:%04o uid:%d gid:%d",
				val_to_str(type, names_nfs_ftype3,"Unknown Type:0x%x"),
				mode&0x0fff,
				uid,
				gid
			);
		}
	}
	/* populate the expansion lines with some nice useable info */
	while( fattr3_tree && levels-- ){
		if(fattr3_tree){
			proto_item_append_text(fattr3_tree, "  %s mode:%04o uid:%d gid:%d",
				val_to_str(type, names_nfs_ftype3,"Unknown Type:0x%x"),
				mode&0x0fff,
				uid,
				gid
			);
		}
		fattr3_tree=fattr3_tree->parent;
	}

	return offset;
}


static const value_string value_follows[] =
	{
		{ 0, "no value" },
		{ 1, "value follows"},
		{ 0, NULL }
	};


/* RFC 1813, Page 23 */
int
dissect_nfs_post_op_attr(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, 
		const char* name)
{
	proto_item* post_op_attr_item = NULL;
	proto_tree* post_op_attr_tree = NULL;
	int old_offset = offset;
	guint32 attributes_follow;

	if (tree) {
		post_op_attr_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s", name);
		post_op_attr_tree = proto_item_add_subtree(post_op_attr_item,
			ett_nfs_post_op_attr);
	}

	attributes_follow = tvb_get_ntohl(tvb, offset+0);
	proto_tree_add_text(post_op_attr_tree, tvb, offset, 4,
		"attributes_follow: %s (%u)",
		val_to_str(attributes_follow,value_follows,"Unknown"), attributes_follow);
	offset += 4;
	switch (attributes_follow) {
		case TRUE:
			offset = dissect_nfs_fattr3(pinfo, tvb, offset, post_op_attr_tree,
					"attributes",2);
		break;
		case FALSE:
			/* void */
		break;
	}

	/* now we know, that post_op_attr_tree is shorter */
	if (post_op_attr_item) {
		proto_item_set_len(post_op_attr_item, offset - old_offset);
	}

	return offset;
}


/* RFC 1813, Page 24 */
static int
dissect_wcc_attr(tvbuff_t *tvb, int offset, proto_tree *tree, const char* name)
{
	proto_item* wcc_attr_item = NULL;
	proto_tree* wcc_attr_tree = NULL;
	int old_offset = offset;

	if (tree) {
		wcc_attr_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s", name);
		wcc_attr_tree = proto_item_add_subtree(wcc_attr_item,
			ett_nfs_wcc_attr);
	}

	offset = dissect_rpc_uint64(tvb, wcc_attr_tree, hf_nfs_wcc_attr_size,
		offset);
	offset = dissect_nfstime3(tvb, offset, wcc_attr_tree, hf_nfs_mtime, hf_nfs_mtime_sec, hf_nfs_mtime_nsec);
	offset = dissect_nfstime3(tvb, offset, wcc_attr_tree, hf_nfs_ctime, hf_nfs_ctime_sec, hf_nfs_ctime_nsec);
	/* now we know, that wcc_attr_tree is shorter */
	if (wcc_attr_item) {
		proto_item_set_len(wcc_attr_item, offset - old_offset);
	}

	return offset;
}


/* RFC 1813, Page 24 */
static int
dissect_pre_op_attr(tvbuff_t *tvb, int offset, proto_tree *tree, const char* name)
{
	proto_item* pre_op_attr_item = NULL;
	proto_tree* pre_op_attr_tree = NULL;
	int old_offset = offset;
	guint32 attributes_follow;

	if (tree) {
		pre_op_attr_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s", name);
		pre_op_attr_tree = proto_item_add_subtree(pre_op_attr_item,
			ett_nfs_pre_op_attr);
	}

	attributes_follow = tvb_get_ntohl(tvb, offset+0);
	proto_tree_add_text(pre_op_attr_tree, tvb, offset, 4,
		"attributes_follow: %s (%u)",
		val_to_str(attributes_follow,value_follows,"Unknown"), attributes_follow);
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


/* RFC 1813, Page 24 */
static int
dissect_wcc_data(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, const char* name)
{
	proto_item* wcc_data_item = NULL;
	proto_tree* wcc_data_tree = NULL;
	int old_offset = offset;

	if (tree) {
		wcc_data_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s", name);
		wcc_data_tree = proto_item_add_subtree(wcc_data_item,
			ett_nfs_wcc_data);
	}

	offset = dissect_pre_op_attr (tvb, offset, wcc_data_tree, "before");
	offset = dissect_nfs_post_op_attr(tvb, offset, pinfo, wcc_data_tree, "after" );

	/* now we know, that wcc_data is shorter */
	if (wcc_data_item) {
		proto_item_set_len(wcc_data_item, offset - old_offset);
	}

	return offset;
}


/* RFC 1813, Page 25 */
static int
dissect_post_op_fh3(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree, const char* name)
{
	proto_item* post_op_fh3_item = NULL;
	proto_tree* post_op_fh3_tree = NULL;
	int old_offset = offset;
	guint32 handle_follows;

	if (tree) {
		post_op_fh3_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s", name);
		post_op_fh3_tree = proto_item_add_subtree(post_op_fh3_item,
			ett_nfs_post_op_fh3);
	}

	handle_follows = tvb_get_ntohl(tvb, offset+0);
	proto_tree_add_text(post_op_fh3_tree, tvb, offset, 4,
		"handle_follows: %s (%u)",
		val_to_str(handle_follows,value_follows,"Unknown"), handle_follows);
	offset += 4;
	switch (handle_follows) {
		case TRUE:
			offset = dissect_nfs_fh3(tvb, offset, pinfo, post_op_fh3_tree,
					"handle", NULL);
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


/* RFC 1813, Page 25 */
static int
dissect_set_mode3(tvbuff_t *tvb, int offset, proto_tree *tree, const char* name)
{
	proto_item* set_mode3_item = NULL;
	proto_tree* set_mode3_tree = NULL;
	int old_offset = offset;
	guint32 set_it;
	const char* set_it_name;

	set_it = tvb_get_ntohl(tvb, offset+0);
	set_it_name = val_to_str(set_it,value_follows,"Unknown");

	if (tree) {
		set_mode3_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s: %s", name, set_it_name);
		set_mode3_tree = proto_item_add_subtree(set_mode3_item,
			ett_nfs_set_mode3);
	}

	if (set_mode3_tree)
		proto_tree_add_text(set_mode3_tree, tvb, offset, 4,
			"set_it: %s (%u)", set_it_name, set_it);

	offset += 4;

	switch (set_it) {
		case 1:
			offset = dissect_mode3(tvb, offset, set_mode3_tree,
					"mode", NULL);
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


/* RFC 1813, Page 26 */
static int
dissect_set_uid3(tvbuff_t *tvb, int offset, proto_tree *tree, const char* name)
{
	proto_item* set_uid3_item = NULL;
	proto_tree* set_uid3_tree = NULL;
	int old_offset = offset;
	guint32 set_it;
	const char* set_it_name;

	set_it = tvb_get_ntohl(tvb, offset+0);
	set_it_name = val_to_str(set_it,value_follows,"Unknown");

	if (tree) {
		set_uid3_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s: %s", name, set_it_name);
		set_uid3_tree = proto_item_add_subtree(set_uid3_item,
			ett_nfs_set_uid3);
	}

	if (set_uid3_tree)
		proto_tree_add_text(set_uid3_tree, tvb, offset, 4,
			"set_it: %s (%u)", set_it_name, set_it);

	offset += 4;

	switch (set_it) {
		case 1:
			offset = dissect_rpc_uint32(tvb, set_uid3_tree,
								 hf_nfs_uid3, offset);
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


/* RFC 1813, Page 26 */
static int
dissect_set_gid3(tvbuff_t *tvb, int offset, proto_tree *tree, const char* name)
{
	proto_item* set_gid3_item = NULL;
	proto_tree* set_gid3_tree = NULL;
	int old_offset = offset;
	guint32 set_it;
	const char* set_it_name;

	set_it = tvb_get_ntohl(tvb, offset+0);
	set_it_name = val_to_str(set_it,value_follows,"Unknown");

	if (tree) {
		set_gid3_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s: %s", name, set_it_name);
		set_gid3_tree = proto_item_add_subtree(set_gid3_item,
			ett_nfs_set_gid3);
	}

	if (set_gid3_tree)
		proto_tree_add_text(set_gid3_tree, tvb, offset, 4,
			"set_it: %s (%u)", set_it_name, set_it);

	offset += 4;

	switch (set_it) {
		case 1:
			offset = dissect_rpc_uint32(tvb, set_gid3_tree,
				hf_nfs_gid3, offset);
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


/* RFC 1813, Page 26 */
static int
dissect_set_size3(tvbuff_t *tvb, int offset, proto_tree *tree, const char* name)
{
	proto_item* set_size3_item = NULL;
	proto_tree* set_size3_tree = NULL;
	int old_offset = offset;
	guint32 set_it;
	const char* set_it_name;

	set_it = tvb_get_ntohl(tvb, offset+0);
	set_it_name = val_to_str(set_it,value_follows,"Unknown");

	if (tree) {
		set_size3_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s: %s", name, set_it_name);
		set_size3_tree = proto_item_add_subtree(set_size3_item,
			ett_nfs_set_size3);
	}

	if (set_size3_tree)
		proto_tree_add_text(set_size3_tree, tvb, offset, 4,
			"set_it: %s (%u)", set_it_name, set_it);

	offset += 4;

	switch (set_it) {
		case 1:
			offset = dissect_rpc_uint64(tvb, set_size3_tree,
				hf_nfs_set_size3_size, offset);
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


/* RFC 1813, Page 25 */
#define DONT_CHANGE 0
#define SET_TO_SERVER_TIME 1
#define SET_TO_CLIENT_TIME 2

static const value_string time_how[] =
	{
		{ DONT_CHANGE,	"don't change" },
		{ SET_TO_SERVER_TIME, "set to server time" },
		{ SET_TO_CLIENT_TIME, "set to client time" },
		{ 0, NULL }
	};


/* RFC 1813, Page 26 */
static int
dissect_set_atime(tvbuff_t *tvb, int offset, proto_tree *tree, const char* name)
{
	proto_item* set_atime_item = NULL;
	proto_tree* set_atime_tree = NULL;
	int old_offset = offset;
	guint32 set_it;
	const char* set_it_name;

	set_it = tvb_get_ntohl(tvb, offset+0);
	set_it_name = val_to_str(set_it,time_how,"Unknown");

	if (tree) {
		set_atime_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s: %s", name, set_it_name);
		set_atime_tree = proto_item_add_subtree(set_atime_item,
			ett_nfs_set_atime);
	}

	if (set_atime_tree)
		proto_tree_add_text(set_atime_tree, tvb, offset, 4,
			"set_it: %s (%u)", set_it_name, set_it);

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


/* RFC 1813, Page 26 */
static int
dissect_set_mtime(tvbuff_t *tvb, int offset, proto_tree *tree, const char* name)
{
	proto_item* set_mtime_item = NULL;
	proto_tree* set_mtime_tree = NULL;
	int old_offset = offset;
	guint32 set_it;
	const char* set_it_name;

	set_it = tvb_get_ntohl(tvb, offset+0);
	set_it_name = val_to_str(set_it,time_how,"Unknown");

	if (tree) {
		set_mtime_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s: %s", name, set_it_name);
		set_mtime_tree = proto_item_add_subtree(set_mtime_item,
			ett_nfs_set_mtime);
	}

	if (set_mtime_tree)
		proto_tree_add_text(set_mtime_tree, tvb, offset, 4,
				"set_it: %s (%u)", set_it_name, set_it);

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


/* RFC 1813, Page 25..27 */
static int
dissect_sattr3(tvbuff_t *tvb, int offset, proto_tree *tree, const char* name)
{
	proto_item* sattr3_item = NULL;
	proto_tree* sattr3_tree = NULL;
	int old_offset = offset;

	if (tree) {
		sattr3_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s", name);
		sattr3_tree = proto_item_add_subtree(sattr3_item, ett_nfs_sattr3);
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


/* RFC 1813, Page 27 */
static int
dissect_diropargs3(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree, const char* label, guint32 *hash, char **name)
{
	proto_item* diropargs3_item = NULL;
	proto_tree* diropargs3_tree = NULL;
	int old_offset = offset;
	int parent_offset, parent_len;
	int name_offset, name_len;

	if (tree) {
		diropargs3_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s", label);
		diropargs3_tree = proto_item_add_subtree(diropargs3_item,
			ett_nfs_diropargs3);
	}

	parent_offset=offset+4;
	parent_len=tvb_get_ntohl(tvb, offset);
	offset = dissect_nfs_fh3(tvb, offset, pinfo, diropargs3_tree, "dir", hash);
	name_offset=offset+4;
	name_len=tvb_get_ntohl(tvb, offset);
	offset = dissect_filename3(tvb, offset, diropargs3_tree,
		hf_nfs_name, name);

	/* are we snooping fh to filenames ?*/
	if((!pinfo->fd->flags.visited) && nfs_file_name_snooping){
		/* v3 LOOKUP, CREATE, MKDIR calls might give us a mapping*/
		rpc_call_info_value *civ=pinfo->private_data;

		if( (civ->prog==100003)
		  &&(civ->vers==3)
		  &&(civ->request)
		  &&((civ->proc==3)||(civ->proc==8)||(civ->proc==9))
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
	proto_tree *tree)
{
	guint32 hash;
	char *name=NULL;

	offset = dissect_diropargs3(tvb, offset, pinfo, tree, "object", &hash, &name);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", DH:0x%08x/%s", hash, name);
	}
	proto_item_append_text(tree, ", REMOVE Call DH:0x%08x/%s", hash, name);

	return offset;
}

static int
dissect_nfs3_null_call(tvbuff_t *tvb _U_, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	proto_item_append_text(tree, ", NULL Call");

	return offset;
}

static int
dissect_nfs3_null_reply(tvbuff_t *tvb _U_, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	proto_item_append_text(tree, ", NULL Reply");

	return offset;
}

static int
dissect_nfs3_rmdir_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree)
{
	guint32 hash;
	char *name=NULL;

	offset = dissect_diropargs3(tvb, offset, pinfo, tree, "object", &hash, &name);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", DH:0x%08x/%s", hash, name);
	}
	proto_item_append_text(tree, ", RMDIR Call DH:0x%08x/%s", hash, name);

	return offset;
}


/* RFC 1813, Page 40 */
int
dissect_access(tvbuff_t *tvb, int offset, proto_tree *tree,
	const char* name)
{
	guint32 access;
	proto_item* access_item = NULL;
	proto_tree* access_tree = NULL;

	access = tvb_get_ntohl(tvb, offset+0);

	if (tree) {
		access_item = proto_tree_add_text(tree, tvb, offset, 4,
			"%s: 0x%02x", name, access);
		if (access_item)
			access_tree = proto_item_add_subtree(access_item, ett_nfs_access);
	}

	if (access_tree) {
		proto_tree_add_text(access_tree, tvb, offset, 4, "%s READ",
		decode_boolean_bitfield(access,  0x001, 6, "allow", "not allow"));
		proto_tree_add_text(access_tree, tvb, offset, 4, "%s LOOKUP",
		decode_boolean_bitfield(access,  0x002, 6, "allow", "not allow"));
		proto_tree_add_text(access_tree, tvb, offset, 4, "%s MODIFY",
		decode_boolean_bitfield(access,  0x004, 6, "allow", "not allow"));
		proto_tree_add_text(access_tree, tvb, offset, 4, "%s EXTEND",
		decode_boolean_bitfield(access,  0x008, 6, "allow", "not allow"));
		proto_tree_add_text(access_tree, tvb, offset, 4, "%s DELETE",
		decode_boolean_bitfield(access,  0x010, 6, "allow", "not allow"));
		proto_tree_add_text(access_tree, tvb, offset, 4, "%s EXECUTE",
		decode_boolean_bitfield(access,  0x020, 6, "allow", "not allow"));
	}

	offset += 4;
	return offset;
}


/* RFC 1813, Page 32,33 */
static int
dissect_nfs3_getattr_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	guint32 hash;

	offset = dissect_nfs_fh3(tvb, offset, pinfo, tree, "object", &hash);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", FH:0x%08x", hash);
	}
	proto_item_append_text(tree, ", GETATTR Call FH:0x%08x", hash);

	return offset;
}


/* RFC 1813, Page 32,33 */
static int
dissect_nfs3_getattr_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree* tree)
{
	guint32 status;
	const char *err;

	proto_item_append_text(tree, ", GETATTR Reply");

	offset = dissect_nfsstat3(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_nfs_fattr3(pinfo, tvb, offset, tree, "obj_attributes",2|COL_INFO_LEVEL);
		break;
		default:
			err=val_to_str(status, names_nfs_nfsstat3, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, "  Error:%s", err);
		break;
	}

	return offset;
}


/* RFC 1813, Page 33 */
static int
dissect_sattrguard3(tvbuff_t *tvb, int offset, proto_tree* tree, const char *name)
{
	proto_item* sattrguard3_item = NULL;
	proto_tree* sattrguard3_tree = NULL;
	int old_offset = offset;
	guint32 check;
	const char* check_name;

	check = tvb_get_ntohl(tvb, offset+0);
	check_name = val_to_str(check,value_follows,"Unknown");

	if (tree) {
		sattrguard3_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s: %s", name, check_name);
		sattrguard3_tree = proto_item_add_subtree(sattrguard3_item,
			ett_nfs_sattrguard3);
	}

	if (sattrguard3_tree)
		proto_tree_add_text(sattrguard3_tree, tvb, offset, 4,
			"check: %s (%u)", check_name, check);

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


/* RFC 1813, Page 33..36 */
static int
dissect_nfs3_setattr_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	guint32 hash;

	offset = dissect_nfs_fh3    (tvb, offset, pinfo, tree, "object", &hash);
	offset = dissect_sattr3     (tvb, offset,        tree, "new_attributes");
	offset = dissect_sattrguard3(tvb, offset,        tree, "guard");

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", FH:0x%08x", hash);
	}
	proto_item_append_text(tree, ", SETATTR Call FH:0x%08x", hash);

	return offset;
}


/* RFC 1813, Page 33..36 */
static int
dissect_nfs3_setattr_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree* tree)
{
	guint32 status;
	const char *err;

	offset = dissect_nfsstat3(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "obj_wcc");
			proto_item_append_text(tree, ", SETATTR Reply");
		break;
		default:
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "obj_wcc");

			err=val_to_str(status, names_nfs_nfsstat3, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", SETATTR Reply  Error:%s", err);
		break;
	}

	return offset;
}


/* RFC 1813, Page 37..39 */
static int
dissect_nfs3_lookup_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	guint32 hash;
	char *name=NULL;

	offset = dissect_diropargs3 (tvb, offset, pinfo, tree, "what", &hash, &name);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", DH:0x%08x/%s", hash, name);
	}
	proto_item_append_text(tree, ", LOOKUP Call DH:0x%08x/%s", hash, name);

	return offset;
}


/* RFC 1813, Page 37..39 */
static int
dissect_nfs3_lookup_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	guint32 status;
	const char *err;
	guint32 hash;

	offset = dissect_nfsstat3(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_nfs_fh3(tvb, offset, pinfo, tree, "object", &hash);
			offset = dissect_nfs_post_op_attr(tvb, offset, pinfo, tree,
				"obj_attributes");
			offset = dissect_nfs_post_op_attr(tvb, offset, pinfo, tree,
				"dir_attributes");

			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO,", FH:0x%08x", hash);
			}
			proto_item_append_text(tree, ", LOOKUP Reply FH:0x%08x", hash);
		break;
		default:
			offset = dissect_nfs_post_op_attr(tvb, offset, pinfo, tree,
				"dir_attributes");

			err=val_to_str(status, names_nfs_nfsstat3, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", LOOKUP Reply  Error:%s", err);
		break;
	}

	return offset;
}


/* RFC 1813, Page 40..43 */
static int
dissect_nfs3_access_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	guint32 hash;

	offset = dissect_nfs_fh3(tvb, offset, pinfo, tree, "object", &hash);
	offset = dissect_access (tvb, offset,        tree, "access");

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", FH:0x%08x", hash);
	}
	proto_item_append_text(tree, ", ACCESS Call FH:0x%08x", hash);

	return offset;
}


/* RFC 1813, Page 40..43 */
static int
dissect_nfs3_access_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree* tree)
{
	guint32 status;
	const char *err;

	offset = dissect_nfsstat3(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_nfs_post_op_attr(tvb, offset, pinfo, tree,
				"obj_attributes");
			offset = dissect_access(tvb, offset, tree, "access");

			proto_item_append_text(tree, ", ACCESS Reply");
		break;
		default:
			offset = dissect_nfs_post_op_attr(tvb, offset, pinfo, tree,
				"obj_attributes");

			err=val_to_str(status, names_nfs_nfsstat3, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", ACCESS Reply  Error:%s", err);
		break;
	}

	return offset;
}


/* RFC 1813, Page 44,45 */
static int
dissect_nfs3_readlink_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	guint32 hash;

	offset = dissect_nfs_fh3(tvb, offset, pinfo, tree, "object", &hash);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", FH:0x%08x", hash);
	}
	proto_item_append_text(tree, ", READLINK Call FH:0x%08x", hash);

	return offset;
}
static int
dissect_nfs3_readlink_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree* tree)
{
	guint32 status;
	const char *err;
	char *name=NULL;

	offset = dissect_nfsstat3(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_nfs_post_op_attr(tvb, offset, pinfo, tree,
				"symlink_attributes");
			offset = dissect_nfspath3(tvb, offset, tree,
				hf_nfs_readlink_data, &name);

			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Path:%s", name);
			}
			proto_item_append_text(tree, ", READLINK Reply Path:%s", name);
		break;
		default:
			offset = dissect_nfs_post_op_attr(tvb, offset, pinfo, tree,
				"symlink_attributes");

			err=val_to_str(status, names_nfs_nfsstat3, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", READLINK Reply  Error:%s", err);
		break;
	}

	return offset;
}


/* RFC 1813, Page 46..48 */
static int
dissect_nfs3_read_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	guint64 off;
	guint32 len;
	guint32 hash;

	offset = dissect_nfs_fh3(tvb, offset, pinfo, tree, "file", &hash);

	off=tvb_get_ntoh64(tvb, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_nfs_offset3, offset);

	len=tvb_get_ntohl(tvb, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs_count3, offset);

	
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", FH:0x%08x Offset:%" PRIu64 " Len:%u", hash, off, len);
	}
	proto_item_append_text(tree, ", READ Call FH:0x%08x Offset:%" PRIu64 " Len:%u", hash, off, len);

	return offset;
}


/* RFC 1813, Page 46..48 */
static int
dissect_nfs3_read_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree* tree)
{
	guint32 status;
	guint32 len;
	const char *err;

	offset = dissect_nfsstat3(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_nfs_post_op_attr(tvb, offset, pinfo, tree,
				"file_attributes");
			len=tvb_get_ntohl(tvb, offset);
			offset = dissect_rpc_uint32(tvb, tree, hf_nfs_count3,
				offset);
			offset = dissect_rpc_bool(tvb, tree, hf_nfs_read_eof,
				offset);
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Len:%d", len);
			}
			proto_item_append_text(tree, ", READ Reply Len:%d", len);
			offset = dissect_nfsdata(tvb, offset, tree, hf_nfs_data);
		break;
		default:
			offset = dissect_nfs_post_op_attr(tvb, offset, pinfo, tree,
				"file_attributes");

			err=val_to_str(status, names_nfs_nfsstat3, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", READ Reply  Error:%s", err);
		break;
	}

	return offset;
}


/* RFC 1813, Page 49 */
static const value_string names_stable_how[] = {
	{	UNSTABLE,  "UNSTABLE"  },
	{	DATA_SYNC, "DATA_SYNC" },
	{	FILE_SYNC, "FILE_SYNC" },
	{ 0, NULL }
};


/* RFC 1813, Page 49 */
static int
dissect_stable_how(tvbuff_t *tvb, int offset, proto_tree* tree, int hfindex)
{
	guint32 stable_how;

	stable_how = tvb_get_ntohl(tvb,offset+0);
	if (tree) {
		proto_tree_add_uint(tree, hfindex, tvb,
			offset, 4, stable_how);
	}
	offset += 4;

	return offset;
}


/* RFC 1813, Page 49..54 */
static int
dissect_nfs3_write_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	guint64 off;
	guint32 len;
	guint32 stable;
	guint32 hash;

	offset = dissect_nfs_fh3   (tvb, offset, pinfo, tree, "file", &hash);

	off=tvb_get_ntoh64(tvb, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_nfs_offset3, offset);

	len=tvb_get_ntohl(tvb, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs_count3, offset);

	stable=tvb_get_ntohl(tvb, offset);
	offset = dissect_stable_how(tvb, offset, tree, hf_nfs_write_stable);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", FH:0x%08x Offset:%" PRIu64 " Len:%u %s", hash, off, len, val_to_str(stable, names_stable_how, "Stable:%u"));
	}
	proto_item_append_text(tree, ", WRITE Call FH:0x%08x Offset:%" PRIu64 " Len:%u %s", hash, off, len, val_to_str(stable, names_stable_how, "Stable:%u"));

	offset = dissect_nfsdata   (tvb, offset, tree, hf_nfs_data);

	return offset;
}


/* RFC 1813, Page 49..54 */
static int
dissect_nfs3_write_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree* tree)
{
	guint32 status;
	guint32 len;
	guint32 stable;
	const char *err;

	offset = dissect_nfsstat3(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "file_wcc");
			len=tvb_get_ntohl(tvb, offset);
			offset = dissect_rpc_uint32(tvb, tree, hf_nfs_count3,
				offset);
			stable=tvb_get_ntohl(tvb, offset);
			offset = dissect_stable_how(tvb, offset, tree,
				hf_nfs_write_committed);
			offset = dissect_writeverf3(tvb, offset, tree);

			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Len:%d %s", len, val_to_str(stable, names_stable_how, "Stable:%u"));
			}
			proto_item_append_text(tree, ", WRITE Reply Len:%d %s", len, val_to_str(stable, names_stable_how, "Stable:%u"));
		break;
		default:
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "file_wcc");

			err=val_to_str(status, names_nfs_nfsstat3, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", WRITE Reply  Error:%s", err);
		break;
	}

	return offset;
}


/* RFC 1813, Page 54 */
static const value_string names_createmode3[] = {
	{	UNCHECKED, "UNCHECKED" },
	{	GUARDED,   "GUARDED" },
	{	EXCLUSIVE, "EXCLUSIVE" },
	{ 0, NULL }
};


/* RFC 1813, Page 54 */
static int
dissect_createmode3(tvbuff_t *tvb, int offset, proto_tree* tree, guint32* mode)
{
	guint32 mode_value;

	mode_value = tvb_get_ntohl(tvb, offset + 0);
	if (tree) {
		proto_tree_add_uint(tree, hf_nfs_createmode3, tvb,
		offset+0, 4, mode_value);
	}
	offset += 4;

	*mode = mode_value;
	return offset;
}


/* RFC 1813, Page 54..58 */
static int
dissect_nfs3_create_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	guint32 mode;
	guint32 hash;
	char *name=NULL;

	offset = dissect_diropargs3 (tvb, offset, pinfo, tree, "where", &hash, &name);
	offset = dissect_createmode3(tvb, offset, tree, &mode);
	switch (mode) {
		case UNCHECKED:
		case GUARDED:
			offset = dissect_sattr3(tvb, offset, tree, "obj_attributes");
		break;
		case EXCLUSIVE:
			offset = dissect_createverf3(tvb, offset, tree);
		break;
	}

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", DH:0x%08x/%s Mode:%s", hash, name, val_to_str(mode, names_createmode3, "Unknown Mode:%u"));
	}
	proto_item_append_text(tree, ", CREATE Call DH:0x%08x/%s Mode:%s", hash, name, val_to_str(mode, names_createmode3, "Unknown Mode:%u"));

	return offset;
}


/* RFC 1813, Page 54..58 */
static int
dissect_nfs3_create_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	guint32 status;
	const char *err;

	offset = dissect_nfsstat3(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_post_op_fh3 (tvb, offset, pinfo, tree, "obj");
			offset = dissect_nfs_post_op_attr(tvb, offset, pinfo, tree,
				"obj_attributes");
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "dir_wcc");
			proto_item_append_text(tree, ", CREATE Reply");
		break;
		default:
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "dir_wcc");

			err=val_to_str(status, names_nfs_nfsstat3, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", CREATE Reply  Error:%s", err);
		break;
	}

	return offset;
}


/* RFC 1813, Page 58..60 */
static int
dissect_nfs3_mkdir_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	guint32 hash;
	char *name=NULL;

	offset = dissect_diropargs3(tvb, offset, pinfo, tree, "where", &hash, &name);
	offset = dissect_sattr3    (tvb, offset, tree, "attributes");

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", DH:0x%08x/%s", hash, name);
	}
	proto_item_append_text(tree, ", MKDIR Call DH:0x%08x/%s", hash, name);

	return offset;
}

static int
dissect_nfs3_mkdir_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	guint32 status;
	const char *err;

	offset = dissect_nfsstat3(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_post_op_fh3 (tvb, offset, pinfo, tree, "obj");
			offset = dissect_nfs_post_op_attr(tvb, offset, pinfo, tree,
				"obj_attributes");
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "dir_wcc");
			proto_item_append_text(tree, ", MKDIR Reply");
		break;
		default:
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "dir_wcc");

			err=val_to_str(status, names_nfs_nfsstat3, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", MKDIR Reply  Error:%s", err);
		break;
	}

	return offset;
}


/* RFC 1813, Page 61..63 */
static int
dissect_nfs3_symlink_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	guint32 from_hash;
	char *from_name=NULL;
	char *to_name=NULL;

	offset = dissect_diropargs3(tvb, offset, pinfo, tree, "where", &from_hash, &from_name);
	offset = dissect_sattr3    (tvb, offset,        tree, "symlink_attributes");
	offset = dissect_nfspath3  (tvb, offset,        tree, hf_nfs_symlink_to, &to_name);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", From DH:0x%08x/%s To %s", from_hash, from_name, to_name);
	}
	proto_item_append_text(tree, ", SYMLINK Call From DH:0x%08x/%s To %s", from_hash, from_name, to_name);

	return offset;
}
static int
dissect_nfs3_symlink_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	guint32 status;
	const char *err;

	offset = dissect_nfsstat3(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_post_op_fh3 (tvb, offset, pinfo, tree, "obj");
			offset = dissect_nfs_post_op_attr(tvb, offset, pinfo, tree,
				"obj_attributes");
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "dir_wcc");
			proto_item_append_text(tree, ", SYMLINK Reply");
		break;
		default:
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "dir_wcc");

			err=val_to_str(status, names_nfs_nfsstat3, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", SYMLINK Reply  Error:%s", err);
		break;
	}

	return offset;
}


/* RFC 1813, Page 63..66 */
static int
dissect_nfs3_mknod_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	guint32 type;
	guint32 hash;
	char *name=NULL;
	const char *type_str;

	offset = dissect_diropargs3(tvb, offset, pinfo, tree, "where", &hash, &name);
	offset = dissect_ftype3(tvb, offset, tree, hf_nfs_ftype3, &type);
	switch (type) {
		case NF3CHR:
		case NF3BLK:
			offset = dissect_sattr3(tvb, offset, tree, "dev_attributes");
			offset = dissect_specdata3(tvb, offset, tree, "spec");
		break;
		case NF3SOCK:
		case NF3FIFO:
			offset = dissect_sattr3(tvb, offset, tree, "pipe_attributes");
		break;
		default:
			/* nothing to do */
		break;
	}

	type_str=val_to_str(type, names_nfs_ftype3, "Unknown type:%u");
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", FH:0x%08x/%s %s", hash, name, type_str);
	}
	proto_item_append_text(tree, ", MKNOD Call FH:0x%08x/%s %s", hash, name, type_str);

	return offset;
}
static int
dissect_nfs3_mknod_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	guint32 status;
	const char *err;

	offset = dissect_nfsstat3(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_post_op_fh3 (tvb, offset, pinfo, tree, "obj");
			offset = dissect_nfs_post_op_attr(tvb, offset, pinfo, tree,
				"obj_attributes");
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "dir_wcc");
			proto_item_append_text(tree, ", MKNOD Reply");
		break;
		default:
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "dir_wcc");

			err=val_to_str(status, names_nfs_nfsstat3, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", MKNOD Reply  Error:%s", err);
		break;
	}

	return offset;
}


/* RFC 1813, Page 67..69 */
static int
dissect_nfs3_remove_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree* tree)
{
	guint32 status;
	const char *err;

	offset = dissect_nfsstat3(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "dir_wcc");
			proto_item_append_text(tree, ", REMOVE Reply");
		break;
		default:
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "dir_wcc");
			err=val_to_str(status, names_nfs_nfsstat3, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", REMOVE Reply  Error:%s", err);
		break;
	}

	return offset;
}
static int
dissect_nfs3_rmdir_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree* tree)
{
	guint32 status;
	const char *err;

	offset = dissect_nfsstat3(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "dir_wcc");
			proto_item_append_text(tree, ", RMDIR Reply");
		break;
		default:
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "dir_wcc");
			err=val_to_str(status, names_nfs_nfsstat3, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", RMDIR Reply  Error:%s", err);
		break;
	}

	return offset;
}


/* RFC 1813, Page 71..74 */
static int
dissect_nfs3_rename_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	guint32 from_hash;
	char *from_name=NULL;
	guint32 to_hash;
	char *to_name=NULL;

	offset = dissect_diropargs3(tvb, offset, pinfo, tree, "from", &from_hash, &from_name);
	offset = dissect_diropargs3(tvb, offset, pinfo, tree, "to", &to_hash, &to_name);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", From DH:0x%08x/%s To DH:0x%08x/%s", from_hash, from_name, to_hash, to_name);
	}
	proto_item_append_text(tree, ", RENAME Call From DH:0x%08x/%s To DH:0x%08x/%s", from_hash, from_name, to_hash, to_name);

	return offset;
}


/* RFC 1813, Page 71..74 */
static int
dissect_nfs3_rename_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree* tree)
{
	guint32 status;
	const char *err;

	offset = dissect_nfsstat3(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "fromdir_wcc");
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "todir_wcc");
			proto_item_append_text(tree, ", RENAME Reply");
		break;
		default:
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "fromdir_wcc");
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "todir_wcc");

			err=val_to_str(status, names_nfs_nfsstat3, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", RENAME Reply  Error:%s", err);
		break;
	}

	return offset;
}


/* RFC 1813, Page 74..76 */
static int
dissect_nfs3_link_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	guint32 from_hash;
	guint32 to_hash;
	char *to_name=NULL;

	offset = dissect_nfs_fh3   (tvb, offset, pinfo, tree, "file", &from_hash);
	offset = dissect_diropargs3(tvb, offset, pinfo, tree, "link", &to_hash, &to_name);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", From DH:0x%08x To DH:0x%08x/%s", from_hash, to_hash, to_name);
	}
	proto_item_append_text(tree, ", LINK Call From DH:0x%08x To DH:0x%08x/%s", from_hash, to_hash, to_name);

	return offset;
}


/* RFC 1813, Page 74..76 */
static int
dissect_nfs3_link_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree* tree)
{
	guint32 status;
	const char *err;

	offset = dissect_nfsstat3(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_nfs_post_op_attr(tvb, offset, pinfo, tree,
				"file_attributes");
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "linkdir_wcc");
			proto_item_append_text(tree, ", LINK Reply");
		break;
		default:
			offset = dissect_nfs_post_op_attr(tvb, offset, pinfo, tree,
				"file_attributes");
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "linkdir_wcc");

			err=val_to_str(status, names_nfs_nfsstat3, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", LINK Reply  Error:%s", err);
		break;
	}

	return offset;
}


/* RFC 1813, Page 76..80 */
static int
dissect_nfs3_readdir_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	guint32 hash;

	offset = dissect_nfs_fh3    (tvb, offset, pinfo, tree, "dir", &hash);
	offset = dissect_rpc_uint64(tvb, tree, hf_nfs_cookie3, offset);
	offset = dissect_cookieverf3(tvb, offset, tree);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs_count3, offset);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", FH:0x%08x", hash);
	}
	proto_item_append_text(tree, ", READDIR Call FH:0x%08x", hash);

	return offset;
}


/* RFC 1813, Page 76..80 */
static int
dissect_entry3(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree* tree)
{
	proto_item* entry_item = NULL;
	proto_tree* entry_tree = NULL;
	int old_offset = offset;
	char *name=NULL;

	if (tree) {
		entry_item = proto_tree_add_item(tree, hf_nfs_readdir_entry, tvb,
			offset+0, -1, FALSE);
		entry_tree = proto_item_add_subtree(entry_item, ett_nfs_readdir_entry);
	}

	offset = dissect_rpc_uint64(tvb, entry_tree, hf_nfs_readdir_entry3_fileid,
		offset);

	offset = dissect_filename3(tvb, offset, entry_tree,
		hf_nfs_readdir_entry3_name, &name);
	if (entry_item)
		proto_item_set_text(entry_item, "Entry: name %s", name);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO," %s", name);
	}

	offset = dissect_rpc_uint64(tvb, entry_tree, hf_nfs_readdir_entry3_cookie,
		offset);

	/* now we know, that a readdir entry is shorter */
	if (entry_item) {
		proto_item_set_len(entry_item, offset - old_offset);
	}

	return offset;
}


/* RFC 1813, Page 76..80 */
static int
dissect_nfs3_readdir_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	guint32 status;
	guint32 eof_value;
	const char *err;

	offset = dissect_nfsstat3(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			proto_item_append_text(tree, ", READDIR Reply");

			offset = dissect_nfs_post_op_attr(tvb, offset, pinfo, tree,
				"dir_attributes");
			offset = dissect_cookieverf3(tvb, offset, tree);
			offset = dissect_rpc_list(tvb, pinfo, tree, offset,
				dissect_entry3);
			eof_value = tvb_get_ntohl(tvb, offset+0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs_readdir_eof, tvb,
					offset+ 0, 4, eof_value);
			offset += 4;
		break;
		default:
			offset = dissect_nfs_post_op_attr(tvb, offset, pinfo, tree,
				"dir_attributes");

			err=val_to_str(status, names_nfs_nfsstat3, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", READDIR Reply  Error:%s", err);
		break;
	}

	return offset;
}


/* RFC 1813, Page 80..83 */
static int
dissect_nfs3_readdirplus_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	guint32 hash;

	offset = dissect_nfs_fh3    (tvb, offset, pinfo, tree, "dir", &hash);
	offset = dissect_rpc_uint64(tvb, tree, hf_nfs_cookie3, offset);
	offset = dissect_cookieverf3(tvb, offset, tree);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs_count3_dircount,
		offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs_count3_maxcount,
		offset);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", FH:0x%08x", hash);
	}
	proto_item_append_text(tree, ", READDIRPLUS Call FH:0x%08x", hash);

	return offset;
}


/* RFC 1813, Page 80..83 */
static int
dissect_entryplus3(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	proto_item* entry_item = NULL;
	proto_tree* entry_tree = NULL;
	int old_offset = offset;
	char *name=NULL;

	if (tree) {
		entry_item = proto_tree_add_item(tree, hf_nfs_readdir_entry, tvb,
			offset+0, -1, FALSE);
		entry_tree = proto_item_add_subtree(entry_item, ett_nfs_readdir_entry);
	}

	offset = dissect_rpc_uint64(tvb, entry_tree,
		hf_nfs_readdirplus_entry_fileid, offset);

	offset = dissect_filename3(tvb, offset, entry_tree,
		hf_nfs_readdirplus_entry_name, &name);

	/* are we snooping fh to filenames ?*/
	if((!pinfo->fd->flags.visited) && nfs_file_name_snooping){
		rpc_call_info_value *civ=pinfo->private_data;
		/* v3 READDIRPLUS replies will give us a mapping */
		if( (civ->prog==100003)
		  &&(civ->vers==3)
		  &&(!civ->request)
		  &&((civ->proc==17))
		) {
			nfs_name_snoop_add_name(civ->xid, tvb, 0, 0, 
				0/*parent offset*/, 0/*parent len*/, 
				name);
		}
	}

	if (entry_item)
		proto_item_set_text(entry_item, "Entry: name %s", name);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO," %s", name);
	}

	offset = dissect_rpc_uint64(tvb, entry_tree, hf_nfs_readdirplus_entry_cookie,
		offset);

	offset = dissect_nfs_post_op_attr(tvb, offset, pinfo, entry_tree,
		"name_attributes");

	offset = dissect_post_op_fh3(tvb, offset, pinfo, entry_tree, "name_handle");

	/* now we know, that a readdirplus entry is shorter */
	if (entry_item) {
		proto_item_set_len(entry_item, offset - old_offset);
	}

	return offset;
}


/* RFC 1813, Page 80..83 */
static int
dissect_nfs3_readdirplus_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	guint32 status;
	guint32 eof_value;
	const char *err;

	offset = dissect_nfsstat3(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			proto_item_append_text(tree, ", READDIRPLUS Reply");

			offset = dissect_nfs_post_op_attr(tvb, offset, pinfo, tree,
				"dir_attributes");
			offset = dissect_cookieverf3(tvb, offset, tree);
			offset = dissect_rpc_list(tvb, pinfo, tree, offset,
				dissect_entryplus3);
			eof_value = tvb_get_ntohl(tvb, offset+0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs_readdir_eof, tvb,
					offset+ 0, 4, eof_value);
			offset += 4;
		break;
		default:
			offset = dissect_nfs_post_op_attr(tvb, offset, pinfo, tree,
				"dir_attributes");

			err=val_to_str(status, names_nfs_nfsstat3, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", READDIRPLUS Reply  Error:%s", err);
		break;
	}

	return offset;
}


/* RFC 1813, Page 84..86 */
static int
dissect_nfs3_fsstat_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	guint32 hash;

	offset = dissect_nfs_fh3(tvb, offset, pinfo, tree, "object", &hash);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", FH:0x%08x", hash);
	}
	proto_item_append_text(tree, ", FSSTAT Call DH:0x%08x", hash);
	return offset;
}


static int
dissect_nfs3_fsstat_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree* tree)
{
	guint32 status;
	guint32 invarsec;
	const char *err;

	offset = dissect_nfsstat3(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_nfs_post_op_attr(tvb, offset, pinfo, tree,
				"obj_attributes");
			offset = dissect_rpc_uint64(tvb, tree, hf_nfs_fsstat3_resok_tbytes,
				offset);
			offset = dissect_rpc_uint64(tvb, tree, hf_nfs_fsstat3_resok_fbytes,
				offset);
			offset = dissect_rpc_uint64(tvb, tree, hf_nfs_fsstat3_resok_abytes,
				offset);
			offset = dissect_rpc_uint64(tvb, tree, hf_nfs_fsstat3_resok_tfiles,
				offset);
			offset = dissect_rpc_uint64(tvb, tree, hf_nfs_fsstat3_resok_ffiles,
				offset);
			offset = dissect_rpc_uint64(tvb, tree, hf_nfs_fsstat3_resok_afiles,
				offset);
			invarsec = tvb_get_ntohl(tvb, offset + 0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs_fsstat_invarsec, tvb,
				offset+0, 4, invarsec);
			offset += 4;

			proto_item_append_text(tree, ", FSSTAT Reply");
		break;
		default:
			offset = dissect_nfs_post_op_attr(tvb, offset, pinfo, tree,
				"obj_attributes");

			err=val_to_str(status, names_nfs_nfsstat3, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", FSSTAT Reply  Error:%s", err);
		break;
	}

	return offset;
}


#define FSF3_LINK        0x0001
#define FSF3_SYMLINK     0x0002
#define FSF3_HOMOGENEOUS 0x0008
#define FSF3_CANSETTIME  0x0010


/* RFC 1813, Page 86..90 */
static int
dissect_nfs3_fsinfo_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	guint32 hash;

	offset = dissect_nfs_fh3(tvb, offset, pinfo, tree, "object", &hash);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", FH:0x%08x", hash);
	}
	proto_item_append_text(tree, ", FSINFO Call DH:0x%08x", hash);
	return offset;
}
static int
dissect_nfs3_fsinfo_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree* tree)
{
	guint32 status;
	guint32 rtmax;
	guint32 rtpref;
	guint32 rtmult;
	guint32 wtmax;
	guint32 wtpref;
	guint32 wtmult;
	guint32 dtpref;
	guint32 properties;
	proto_item*	properties_item = NULL;
	proto_tree*	properties_tree = NULL;
	const char *err;

	offset = dissect_nfsstat3(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_nfs_post_op_attr(tvb, offset, pinfo, tree,
				"obj_attributes");
			rtmax = tvb_get_ntohl(tvb, offset+0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs_fsinfo_rtmax, tvb,
				offset+0, 4, rtmax);
			offset += 4;
			rtpref = tvb_get_ntohl(tvb, offset+0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs_fsinfo_rtpref, tvb,
				offset+0, 4, rtpref);
			offset += 4;
			rtmult = tvb_get_ntohl(tvb, offset+0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs_fsinfo_rtmult, tvb,
				offset+0, 4, rtmult);
			offset += 4;
			wtmax = tvb_get_ntohl(tvb, offset+0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs_fsinfo_wtmax, tvb,
				offset+0, 4, wtmax);
			offset += 4;
			wtpref = tvb_get_ntohl(tvb, offset+0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs_fsinfo_wtpref, tvb,
				offset+0, 4, wtpref);
			offset += 4;
			wtmult = tvb_get_ntohl(tvb, offset+0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs_fsinfo_wtmult, tvb,
				offset+0, 4, wtmult);
			offset += 4;
			dtpref = tvb_get_ntohl(tvb, offset+0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs_fsinfo_dtpref, tvb,
				offset+0, 4, dtpref);
			offset += 4;

			offset = dissect_rpc_uint64(tvb, tree,
				hf_nfs_fsinfo_maxfilesize, offset);
			offset = dissect_nfstime3(tvb, offset, tree, hf_nfs_dtime, hf_nfs_dtime_sec, hf_nfs_dtime_nsec);
			properties = tvb_get_ntohl(tvb, offset+0);
			if (tree) {
				properties_item = proto_tree_add_uint(tree,
				hf_nfs_fsinfo_properties,
				tvb, offset+0, 4, properties);
				if (properties_item)
					properties_tree = proto_item_add_subtree(properties_item,
						ett_nfs_fsinfo_properties);
				if (properties_tree) {
					proto_tree_add_text(properties_tree, tvb,
					offset, 4, "%s",
					decode_boolean_bitfield(properties,
					FSF3_CANSETTIME,5,
					"SETATTR can set time on server",
					"SETATTR can't set time on server"));

					proto_tree_add_text(properties_tree, tvb,
					offset, 4, "%s",
					decode_boolean_bitfield(properties,
					FSF3_HOMOGENEOUS,5,
					"PATHCONF is valid for all files",
					"PATHCONF should be get for every single file"));

					proto_tree_add_text(properties_tree, tvb,
					offset, 4, "%s",
					decode_boolean_bitfield(properties,
					FSF3_SYMLINK,5,
					"File System supports symbolic links",
					"File System does not symbolic hard links"));

					proto_tree_add_text(properties_tree, tvb,
					offset, 4, "%s",
					decode_boolean_bitfield(properties,
					FSF3_LINK,5,
					"File System supports hard links",
					"File System does not support hard links"));
				}
			}
			offset += 4;

			proto_item_append_text(tree, ", FSINFO Reply");
		break;
		default:
			offset = dissect_nfs_post_op_attr(tvb, offset, pinfo, tree,
				"obj_attributes");

			err=val_to_str(status, names_nfs_nfsstat3, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", FSINFO Reply  Error:%s", err);
		break;
	}

	return offset;
}


/* RFC 1813, Page 90..92 */
static int
dissect_nfs3_pathconf_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	guint32 hash;

	offset = dissect_nfs_fh3(tvb, offset, pinfo, tree, "object", &hash);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", FH:0x%08x", hash);
	}
	proto_item_append_text(tree, ", PATHCONF Call DH:0x%08x", hash);
	return offset;
}
static int
dissect_nfs3_pathconf_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree* tree)
{
	guint32 status;
	guint32 linkmax;
	guint32 name_max;
	const char *err;

	offset = dissect_nfsstat3(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_nfs_post_op_attr(tvb, offset, pinfo, tree,
				"obj_attributes");
			linkmax = tvb_get_ntohl(tvb, offset + 0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs_pathconf_linkmax, tvb,
				offset+0, 4, linkmax);
			offset += 4;
			name_max = tvb_get_ntohl(tvb, offset + 0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs_pathconf_name_max, tvb,
				offset+0, 4, name_max);
			offset += 4;
			offset = dissect_rpc_bool(tvb, tree,
				hf_nfs_pathconf_no_trunc, offset);
			offset = dissect_rpc_bool(tvb, tree,
				hf_nfs_pathconf_chown_restricted, offset);
			offset = dissect_rpc_bool(tvb, tree,
				hf_nfs_pathconf_case_insensitive, offset);
			offset = dissect_rpc_bool(tvb, tree,
				hf_nfs_pathconf_case_preserving, offset);

			proto_item_append_text(tree, ", PATHCONF Reply");
		break;
		default:
			offset = dissect_nfs_post_op_attr(tvb, offset, pinfo, tree,
				"obj_attributes");

			err=val_to_str(status, names_nfs_nfsstat3, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", PATHCONF Reply  Error:%s", err);
		break;
	}

	return offset;
}


/* RFC 1813, Page 92..95 */
static int
dissect_nfs3_commit_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	guint32 hash;

	offset = dissect_nfs_fh3(tvb, offset, pinfo, tree, "file", &hash);
	offset = dissect_rpc_uint64(tvb, tree, hf_nfs_offset3, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs_count3, offset);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,", FH:0x%08x", hash);
	}
	proto_item_append_text(tree, ", COMMIT Call FH:0x%08x", hash);

	return offset;
}


/* RFC 1813, Page 92..95 */
static int
dissect_nfs3_commit_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree* tree)
{
	guint32 status;
	const char *err;

	offset = dissect_nfsstat3(tvb, offset, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_wcc_data  (tvb, offset, pinfo, tree, "file_wcc");
			offset = dissect_writeverf3(tvb, offset, tree);

			proto_item_append_text(tree, ", COMMIT Reply");
		break;
		default:
			offset = dissect_wcc_data(tvb, offset, pinfo, tree, "file_wcc");

			err=val_to_str(status, names_nfs_nfsstat3, "Unknown error:%u");
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO," Error:%s", err);
			}
			proto_item_append_text(tree, ", COMMIT Reply  Error:%s", err);
		break;
	}

	return offset;
}

/**********************************************************/
/* NFS Version 4, RFC 3010 with nfs4_prot.x 1.103 changes */
/**********************************************************/

/* NFSv4 Draft Specification, Page 198-199 */
static const value_string names_nfs_nfsstat4[] = {
	{	0,	"NFS4_OK"					},
	{	1,	"NFS4ERR_PERM"					},
	{	2,	"NFS4ERR_NOENT"					},
	{	5,	"NFS4ERR_IO"					},
	{	6,	"NFS4ERR_NXIO"					},
	{	13,	"NFS4ERR_ACCES"					},
	{	17,	"NFS4ERR_EXIST"					},
	{	18,	"NFS4ERR_XDEV"					},
	{	19,	"NFS4ERR_NODEV"					},
	{	20,	"NFS4ERR_NOTDIR"				},
	{	21,	"NFS4ERR_ISDIR"					},
	{	22,	"NFS4ERR_INVAL"					},
	{	27,	"NFS4ERR_FBIG"					},
	{	28,	"NFS4ERR_NOSPC"					},
	{	30,	"NFS4ERR_ROFS"					},
	{	31,	"NFS4ERR_MLINK"					},
	{	63,	"NFS4ERR_NAMETOOLONG"				},
	{	66,	"NFS4ERR_NOTEMPTY"				},
	{	69,	"NFS4ERR_DQUOT"					},
	{	70,	"NFS4ERR_STALE"					},
	{	10001,	"NFS4ERR_BADHANDLE"				},
	{	10003,	"NFS4ERR_BAD_COOKIE"				},
	{	10004,	"NFS4ERR_NOTSUPP"				},
	{	10005,	"NFS4ERR_TOOSMALL"				},
	{	10006,	"NFS4ERR_SERVERFAULT"				},
	{	10007,	"NFS4ERR_BADTYPE"				},
	{	10008,	"NFS4ERR_DELAY"					},
	{	10009,	"NFS4ERR_SAME"					},
	{	10010,	"NFS4ERR_DENIED"				},
	{	10011,	"NFS4ERR_EXPIRED"				},
	{	10012,	"NFS4ERR_LOCKED"				},
	{	10013,	"NFS4ERR_GRACE"					},
	{	10014,	"NFS4ERR_FHEXPIRED"				},
	{	10015,	"NFS4ERR_SHARE_DENIED"				},
	{	10016,	"NFS4ERR_WRONGSEC"				},
	{	10017,	"NFS4ERR_CLID_INUSE"				},
	{	10018,	"NFS4ERR_RESOURCE"				},
	{	10019,	"NFS4ERR_MOVED"					},
	{	10020,	"NFS4ERR_NOFILEHANDLE"				},
	{	10021,	"NFS4ERR_MINOR_VERS_MISMATCH"			},
	{	10022,	"NFS4ERR_STALE_CLIENTID"			},
	{	10023,	"NFS4ERR_STALE_STATEID"				},
	{	10024,	"NFS4ERR_OLD_STATEID"				},
	{	10025,	"NFS4ERR_BAD_STATEID"				},
	{	10026,	"NFS4ERR_BAD_SEQID"				},
	{	10027,	"NFS4ERR_NOT_SAME"				},
	{	10028,	"NFS4ERR_LOCK_RANGE"				},
	{	10029,	"NFS4ERR_SYMLINK"				},
	{	10030,	"NFS4ERR_READDIR_NOSPC"				},
	{	10031,	"NFS4ERR_LEASE_MOVED"				},
	{	10032,	"NFS4ERR_ATTRNOTSUPP"				},
	{	10033,	"NFS4ERR_NO_GRACE"				},
	{	10034,	"NFS4ERR_RECLAIM_BAD"				},
	{	10035,	"NFS4ERR_RECLAIM_CONFLICT"			},
	{	10036,	"NFS4ERR_BADXDR"				},
	{	10037,	"NFS4ERR_LOCKS_HELD"				},
	{	10038,	"NFS4ERR_OPENMODE"	},
	{	10039,	"NFS4ERR_BADOWNER"	},
	{	10040,	"NFS4ERR_BADCHAR"		},
	{	10041,	"NFS4ERR_BADNAME"    },
	{	10042,	"NFS4ERR_BAD_RANGE"	},
	{	10043,	"NFS4ERR_LOCK_NOTSUPP"	},
	{	10044,	"NFS4ERR_OP_ILLEGAL"	},
	{	10045,	"NFS4ERR_DEADLOCK"	},
	{	10046,	"NFS4ERR_FILE_OPEN"	},
	{	10047,	"NFS4ERR_ADMIN_REVOKED"	},
	{	10048,	"NFS4ERR_CB_PATH_DOWN"	},
	{ 0, NULL }
};


static int
dissect_nfs_nfsstat4(tvbuff_t *tvb, int offset,
	proto_tree *tree, guint32 *status)
{
	guint32 stat;
	proto_item *stat_item;

	stat = tvb_get_ntohl(tvb, offset+0);

	if (tree) {
		proto_tree_add_uint(tree, hf_nfs_nfsstat4, tvb, offset+0, 4,
			stat);
		stat_item = proto_tree_add_uint(tree, hf_nfs_nfsstat, tvb,
			offset+0, 4, stat);
		PROTO_ITEM_SET_HIDDEN(stat_item);
	}

	offset += 4;

	if (status) *status = stat;

	return offset;
}


static int
dissect_nfs_utf8string(tvbuff_t *tvb, int offset,
	proto_tree *tree, int hf, char **string_ret)
{
	/* TODO: this dissector is subject to change; do not remove */
	return dissect_rpc_string(tvb, tree, hf, offset, string_ret);
}

static int
dissect_nfs_specdata4(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs_specdata1, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs_specdata2, offset);

	return offset;
}

static const value_string names_ftype4[] = {
	{	NF4REG,	"NF4REG"	},
	{	NF4DIR,	"NF4DIR"	},
	{	NF4BLK,	"NF4BLK"  },
	{	NF4CHR,	"NF4CHR"  },
	{	NF4LNK,  "NF4LNK"  },
	{	NF4SOCK,	"NF4SOCK"  },
	{	NF4FIFO,	"NF4FIFO"  },
	{	NF4ATTRDIR,	"NF4ATTRDIR"	},
	{	NF4NAMEDATTR,	"NF4NAMEDATTR"	},
	{ 0, NULL }
};

static int
dissect_nfs_lock_owner4(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_tree *newftree = NULL;
	proto_item *fitem = NULL;

	fitem = proto_tree_add_text(tree, tvb, offset, 4, "Owner");

	if (fitem)
	{
		newftree = proto_item_add_subtree(fitem, ett_nfs_lock_owner4);

		if (newftree)
		{
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs_clientid4, offset);
			offset = dissect_nfsdata(tvb, offset, newftree, hf_nfs_data);
		}
	}

	return offset;
}

static int
dissect_nfs_pathname4(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint32 comp_count, i;
	proto_item *fitem = NULL;
	proto_tree *newftree = NULL;

	comp_count=tvb_get_ntohl(tvb, offset);
	fitem = proto_tree_add_text(tree, tvb, offset, 4,
		"pathname components (%u)", comp_count);
	offset += 4;

	if (fitem)
	{
		newftree = proto_item_add_subtree(fitem, ett_nfs_pathname4);

		if (newftree)
		{
			for (i = 0; i < comp_count; i++)
				offset = dissect_nfs_utf8string(tvb, offset, newftree,
					hf_nfs_component4, NULL);
		}
	}

	return offset;
}

static int
dissect_nfs_nfstime4(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	offset = dissect_rpc_uint64(tvb, tree, hf_nfs_nfstime4_seconds, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs_nfstime4_nseconds, offset);

	return offset;
}

static const value_string names_time_how4[] = {
#define SET_TO_SERVER_TIME4 0
	{	SET_TO_SERVER_TIME4,	"SET_TO_SERVER_TIME4"	},
#define SET_TO_CLIENT_TIME4 1
	{	SET_TO_CLIENT_TIME4,	"SET_TO_CLIENT_TIME4"	},
	{	0,	NULL	},
};

static int
dissect_nfs_settime4(tvbuff_t *tvb, int offset,
	proto_tree *tree, const char *name _U_)
{
	guint32 set_it;

	set_it = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint(tree, hf_nfs_time_how4, tvb, offset+0,
		4, set_it);
	offset += 4;

	if (set_it == SET_TO_CLIENT_TIME4)
		offset = dissect_nfs_nfstime4(tvb, offset, tree);

	return offset;
}

static int
dissect_nfs_fsid4(tvbuff_t *tvb, int offset, proto_tree *tree, const char *name)
{
	proto_tree *newftree = NULL;
	proto_item *fitem = NULL;

	fitem = proto_tree_add_text(tree, tvb, offset, 0, "%s", name);

	if (fitem == NULL) return offset;

	newftree = proto_item_add_subtree(fitem, ett_nfs_fsid4);

	if (newftree == NULL) return offset;

	offset = dissect_rpc_uint64(tvb, newftree, hf_nfs_fsid4_major,
		offset);
	offset = dissect_rpc_uint64(tvb, newftree, hf_nfs_fsid4_minor,
		offset);

	return offset;
}

static const value_string names_acetype4[] = {
#define ACE4_ACCESS_ALLOWED_ACE_TYPE	0x00000000
	{	ACE4_ACCESS_ALLOWED_ACE_TYPE, "ACE4_ACCESS_ALLOWED_ACE_TYPE"  },
#define ACE4_ACCESS_DENIED_ACE_TYPE		0x00000001
	{	ACE4_ACCESS_DENIED_ACE_TYPE, "ACE4_ACCESS_DENIED_ACE_TYPE" },
#define ACE4_SYSTEM_AUDIT_ACE_TYPE		0x00000002
	{	ACE4_SYSTEM_AUDIT_ACE_TYPE, "ACE4_SYSTEM_AUDIT_ACE_TYPE" },
#define ACE4_SYSTEM_ALARM_ACE_TYPE		0x00000003
	{	ACE4_SYSTEM_ALARM_ACE_TYPE, "ACE4_SYSTEM_ALARM_ACE_TYPE"	},
	{ 0, NULL }
};

/* ACE mask values */
#define ACE4_READ_DATA				0x00000001
#define ACE4_LIST_DIRECTORY		0x00000001
#define ACE4_WRITE_DATA				0x00000002
#define ACE4_ADD_FILE				0x00000002
#define ACE4_APPEND_DATA			0x00000004
#define ACE4_ADD_SUBDIRECTORY		0x00000004
#define ACE4_READ_NAMED_ATTRS		0x00000008
#define ACE4_WRITE_NAMED_ATTRS	0x00000010
#define ACE4_EXECUTE					0x00000020
#define ACE4_DELETE_CHILD			0x00000040
#define ACE4_READ_ATTRIBUTES		0x00000080
#define ACE4_WRITE_ATTRIBUTES		0x00000100
#define ACE4_DELETE					0x00010000
#define ACE4_READ_ACL				0x00020000
#define ACE4_WRITE_ACL				0x00040000
#define ACE4_WRITE_OWNER			0x00080000
#define ACE4_SYNCHRONIZE			0x00100000

static int
dissect_nfs_acemask4(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint32 acemask;
	proto_item *acemask_item = NULL;
	proto_tree *acemask_tree = NULL;

	acemask = tvb_get_ntohl(tvb, offset);

	acemask_item = proto_tree_add_text(tree, tvb, offset, 4,
		"acemask: 0x%08x", acemask);

	if (acemask_item)
		acemask_tree = proto_item_add_subtree(acemask_item, ett_nfs_acemask4);

	if (acemask_tree)
	{
		if (acemask & ACE4_READ_DATA)
			proto_tree_add_text(acemask_tree, tvb, offset, 4,
				"ACE4_READ_DATA/ACE4_LIST_DIRECTORY (0x%08x)",
				ACE4_READ_DATA);

		if (acemask & ACE4_WRITE_DATA)
			proto_tree_add_text(acemask_tree, tvb, offset, 4,
				"ACE4_WRITE_DATA/ACE4_ADD_FILE (0x%08x)",
				ACE4_WRITE_DATA);

		if (acemask & ACE4_APPEND_DATA)
			proto_tree_add_text(acemask_tree, tvb, offset, 4,
				"ACE4_ADD_FILE/ACE4_ADD_SUBDIRECTORY (0x%08x)",
				ACE4_APPEND_DATA);

		if (acemask & ACE4_READ_NAMED_ATTRS)
			proto_tree_add_text(acemask_tree, tvb, offset, 4,
				"ACE4_READ_NAMED_ATTRS (0x%08x)",
				ACE4_READ_NAMED_ATTRS);

		if (acemask & ACE4_WRITE_NAMED_ATTRS)
			proto_tree_add_text(acemask_tree, tvb, offset, 4,
				"ACE4_WRITE_NAMED_ATTRS (0x%08x)",
				ACE4_WRITE_NAMED_ATTRS);

		if (acemask & ACE4_EXECUTE)
			proto_tree_add_text(acemask_tree, tvb, offset, 4,
				"ACE4_EXECUTE (0x%08x)",
				ACE4_EXECUTE);

		if (acemask & ACE4_DELETE_CHILD)
			proto_tree_add_text(acemask_tree, tvb, offset, 4,
				"ACE4_DELETE_CHILD (0x%08x)",
				ACE4_DELETE_CHILD);

		if (acemask & ACE4_READ_ATTRIBUTES)
			proto_tree_add_text(acemask_tree, tvb, offset, 4,
				"ACE4_READ_ATTRIBUTES (0x%08x)",
				ACE4_READ_ATTRIBUTES);

		if (acemask & ACE4_WRITE_ATTRIBUTES)
			proto_tree_add_text(acemask_tree, tvb, offset, 4,
				"ACE4_WRITE_ATTRIBUTES (0x%08x)",
				ACE4_WRITE_ATTRIBUTES);

		if (acemask & ACE4_DELETE)
			proto_tree_add_text(acemask_tree, tvb, offset, 4,
				"ACE4_DELETE (0x%08x)",
				ACE4_DELETE);

		if (acemask & ACE4_READ_ACL)
			proto_tree_add_text(acemask_tree, tvb, offset, 4,
				"ACE4_READ_ACL (0x%08x)",
				ACE4_READ_ACL);

		if (acemask & ACE4_WRITE_ACL)
			proto_tree_add_text(acemask_tree, tvb, offset, 4,
				"ACE4_WRITE_ACL (0x%08x)",
				ACE4_WRITE_ACL);

		if (acemask & ACE4_WRITE_OWNER)
			proto_tree_add_text(acemask_tree, tvb, offset, 4,
				"ACE4_WRITE_OWNER (0x%08x)",
				ACE4_WRITE_OWNER);

		if (acemask & ACE4_SYNCHRONIZE)
			proto_tree_add_text(acemask_tree, tvb, offset, 4,
				"ACE4_SYNCHRONIZE (0x%08x)",
				ACE4_SYNCHRONIZE);
	}

	offset += 4;

	return offset;
}

/* ACE flag values */
#define ACE4_FILE_INHERIT_ACE					0x00000001
#define ACE4_DIRECTORY_INHERIT_ACE			0x00000002
#define ACE4_NO_PROPAGATE_INHERIT_ACE		0x00000004
#define ACE4_INHERIT_ONLY_ACE					0x00000008
#define ACE4_SUCCESSFUL_ACCESS_ACE_FLAG	0x00000010
#define ACE4_FAILED_ACCESS_ACE_FLAG			0x00000020
#define ACE4_IDENTIFIER_GROUP					0x00000040


static int
dissect_nfs_ace4(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	proto_item* ace_item = NULL;
	proto_tree* ace_tree = NULL;
	proto_item *aceflag_item = NULL;
	proto_tree *aceflag_tree = NULL;
	guint32 aceflag4;

	if (tree) {
		ace_item = proto_tree_add_text(tree, tvb, offset, 4,
			"ACE");

		if (ace_item)
			ace_tree = proto_item_add_subtree(ace_item, ett_nfs_ace4);
	}

	if (ace_tree) {
		offset = dissect_rpc_uint32(tvb, ace_tree, hf_nfs_acetype4, offset);

		aceflag4 = tvb_get_ntohl(tvb, offset);

		aceflag_item = proto_tree_add_text(ace_tree, tvb, offset, 4,
			"aceflag: 0x%08x", aceflag4);

		if (aceflag_item)
		{
			aceflag_tree = proto_item_add_subtree(aceflag_item, ett_nfs_aceflag4);

			if (aceflag_tree)
			{
				if (aceflag4 & ACE4_FILE_INHERIT_ACE)
					proto_tree_add_text(aceflag_tree, tvb, offset, 4,
						"ACE4_FILE_INHERIT_ACE (0x%08x)", ACE4_FILE_INHERIT_ACE);

				if (aceflag4 & ACE4_DIRECTORY_INHERIT_ACE)
					proto_tree_add_text(aceflag_tree, tvb, offset, 4,
						"ACE4_DIRECTORY_INHERIT_ACE (0x%08x)",
						 ACE4_DIRECTORY_INHERIT_ACE);

				if (aceflag4 & ACE4_INHERIT_ONLY_ACE)
					proto_tree_add_text(aceflag_tree, tvb, offset, 4,
						"ACE4_INHERIT_ONLY_ACE (0x%08x)",
						ACE4_INHERIT_ONLY_ACE);

				if (aceflag4 & ACE4_SUCCESSFUL_ACCESS_ACE_FLAG)
					proto_tree_add_text(aceflag_tree, tvb, offset, 4,
						"ACE4_SUCCESSFUL_ACCESS_ACE_FLAG (0x%08x)",
						ACE4_SUCCESSFUL_ACCESS_ACE_FLAG);

				if (aceflag4 & ACE4_FAILED_ACCESS_ACE_FLAG)
					proto_tree_add_text(aceflag_tree, tvb, offset, 4,
						"ACE4_FAILED_ACCESS_ACE_FLAG (0x%08x)",
						ACE4_FAILED_ACCESS_ACE_FLAG);

				if (aceflag4 & ACE4_IDENTIFIER_GROUP)
					proto_tree_add_text(aceflag_tree, tvb, offset, 4,
						"ACE4_IDENTIFIER_GROUP (0x%08x)",
						ACE4_IDENTIFIER_GROUP);
			}
		}

		offset += 4;

		offset = dissect_nfs_acemask4(tvb, offset, ace_tree);

		offset = dissect_nfs_utf8string(tvb, offset, ace_tree, hf_nfs_who, NULL);
	}

	return offset;
}

static int
dissect_nfs_fattr4_acl(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree)
{
	return dissect_rpc_array(tvb, pinfo, tree, offset, dissect_nfs_ace4,
		hf_nfs_acl4);
}

static int
dissect_nfs_fh4(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree, const char *name)
{
	return dissect_nfs_fh3(tvb, offset, pinfo, tree, name, NULL);
}

static int
dissect_nfs_fs_location4(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	proto_tree *newftree = NULL;
	proto_item *fitem = NULL;

	fitem = proto_tree_add_text(tree, tvb, offset, 0, "rootpath");

	if (fitem == NULL) return offset;

	newftree = proto_item_add_subtree(fitem, ett_nfs_fs_location4);

	if (newftree == NULL) return offset;

	offset = dissect_nfs_utf8string(tvb, offset, tree, hf_nfs_server, NULL);

	return offset;
}

static int
dissect_nfs_fs_locations4(tvbuff_t *tvb, packet_info *pinfo, int offset,
	proto_tree *tree, const char *name)
{
	proto_tree *newftree = NULL;
	proto_item *fitem = NULL;

	fitem = proto_tree_add_text(tree, tvb, offset, 0, "%s", name);

	if (fitem == NULL) return offset;

	newftree = proto_item_add_subtree(fitem, ett_nfs_fs_locations4);

	if (newftree == NULL) return offset;

	offset = dissect_nfs_pathname4(tvb, offset, newftree);

	offset = dissect_rpc_list(tvb, pinfo, tree, offset,
		dissect_nfs_fs_location4);

	return offset;
}

static int
dissect_nfs_mode4(tvbuff_t *tvb, int offset,
	proto_tree *tree, const char *name)
{
	return dissect_mode(tvb, offset, tree, name);
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
dissect_nfs_fattr4_fh_expire_type(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint32 expire_type;
	proto_item *expire_type_item = NULL;
	proto_tree *expire_type_tree = NULL;

	expire_type = tvb_get_ntohl(tvb, offset + 0);

	if (tree)
	{
		expire_type_item = proto_tree_add_text(tree, tvb, offset, 4,
			"fattr4_fh_expire_type: 0x%08x", expire_type);
		if (expire_type_item)
			expire_type_tree = proto_item_add_subtree(expire_type_item,
				ett_nfs_fattr4_fh_expire_type);
	}

	if (expire_type_tree)
	{
		if (expire_type == FH4_PERSISTENT)
		{
			proto_tree_add_text(expire_type_tree, tvb, offset, 4, "%s",
				decode_enumerated_bitfield(expire_type, FH4_PERSISTENT, 8,
				nfs4_fattr4_fh_expire_type_names, "%s"));
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

static const value_string names_fattr4[] = {
#define FATTR4_SUPPORTED_ATTRS     0
	{	FATTR4_SUPPORTED_ATTRS,	"FATTR4_SUPPORTED_ATTRS"	},
#define FATTR4_TYPE                1
	{	FATTR4_TYPE,	"FATTR4_TYPE"	},
#define FATTR4_FH_EXPIRE_TYPE      2
	{	FATTR4_FH_EXPIRE_TYPE,	"FATTR4_FH_EXPIRE_TYPE"	},
#define FATTR4_CHANGE              3
	{	FATTR4_CHANGE,	"FATTR4_CHANGE"	},
#define FATTR4_SIZE                4
	{	FATTR4_SIZE,	"FATTR4_SIZE"	},
#define FATTR4_LINK_SUPPORT        5
	{	FATTR4_LINK_SUPPORT,	"FATTR4_LINK_SUPPORT"	},
#define FATTR4_SYMLINK_SUPPORT     6
	{	FATTR4_SYMLINK_SUPPORT,	"FATTR4_SYMLINK_SUPPORT"	},
#define FATTR4_NAMED_ATTR          7
	{	FATTR4_NAMED_ATTR,	"FATTR4_NAMED_ATTR"	},
#define FATTR4_FSID                8
	{	FATTR4_FSID,	"FATTR4_FSID"	},
#define FATTR4_UNIQUE_HANDLES      9
	{	FATTR4_UNIQUE_HANDLES,	"FATTR4_UNIQUE_HANDLES"	},
#define FATTR4_LEASE_TIME          10
	{	FATTR4_LEASE_TIME,	"FATTR4_LEASE_TIME"	},
#define FATTR4_RDATTR_ERROR        11
	{	FATTR4_RDATTR_ERROR,	"FATTR4_RDATTR_ERROR"	},
#define FATTR4_ACL                 12
	{	FATTR4_ACL,	"FATTR4_ACL"	},
#define FATTR4_ACLSUPPORT          13
	{	FATTR4_ACLSUPPORT,	"FATTR4_ACLSUPPORT"	},
#define FATTR4_ARCHIVE             14
	{	FATTR4_ARCHIVE, "FATTR4_ARCHIVE"	},
#define FATTR4_CANSETTIME          15
	{	FATTR4_CANSETTIME, "FATTR4_CANSETTIME"	},
#define FATTR4_CASE_INSENSITIVE    16
	{	FATTR4_CASE_INSENSITIVE, "FATTR4_CASE_INSENSITIVE"	},
#define FATTR4_CASE_PRESERVING     17
	{	FATTR4_CASE_PRESERVING, "FATTR4_CASE_PRESERVING"	},
#define FATTR4_CHOWN_RESTRICTED    18
	{	FATTR4_CHOWN_RESTRICTED, "FATTR4_CHOWN_RESTRICTED"	},
#define FATTR4_FILEHANDLE          19
	{	FATTR4_FILEHANDLE, "FATTR4_FILEHANDLE"	},
#define FATTR4_FILEID              20
	{	FATTR4_FILEID, "FATTR4_FILEID"	},
#define FATTR4_FILES_AVAIL         21
	{	FATTR4_FILES_AVAIL, "FATTR4_FILES_AVAIL"	},
#define FATTR4_FILES_FREE          22
	{	FATTR4_FILES_FREE, "FATTR4_FILES_FREE"	},
#define FATTR4_FILES_TOTAL         23
	{	FATTR4_FILES_TOTAL, "FATTR4_FILES_TOTAL"	},
#define FATTR4_FS_LOCATIONS        24
	{	FATTR4_FS_LOCATIONS, "FATTR4_FS_LOCATIONS"	},
#define FATTR4_HIDDEN              25
	{	FATTR4_HIDDEN, "FATTR4_HIDDEN"	},
#define FATTR4_HOMOGENEOUS         26
	{	FATTR4_HOMOGENEOUS, "FATTR4_HOMOGENEOUS"	},
#define FATTR4_MAXFILESIZE         27
	{	FATTR4_MAXFILESIZE, "FATTR4_MAXFILESIZE"	},
#define FATTR4_MAXLINK             28
	{	FATTR4_MAXLINK, "FATTR4_MAXLINK"	},
#define FATTR4_MAXNAME             29
	{	FATTR4_MAXNAME, "FATTR4_MAXNAME"	},
#define FATTR4_MAXREAD             30
	{	FATTR4_MAXREAD, "FATTR4_MAXREAD"	},
#define FATTR4_MAXWRITE            31
	{	FATTR4_MAXWRITE, "FATTR4_MAXWRITE"	},
#define FATTR4_MIMETYPE            32
	{	FATTR4_MIMETYPE, "FATTR4_MIMETYPE"	},
#define FATTR4_MODE                33
	{	FATTR4_MODE, "FATTR4_MODE"	},
#define FATTR4_NO_TRUNC            34
	{	FATTR4_NO_TRUNC, "FATTR4_NO_TRUNC"	},
#define FATTR4_NUMLINKS            35
	{	FATTR4_NUMLINKS, "FATTR4_NUMLINKS"	},
#define FATTR4_OWNER               36
	{	FATTR4_OWNER, "FATTR4_OWNER"	},
#define FATTR4_OWNER_GROUP         37
	{	FATTR4_OWNER_GROUP, "FATTR4_OWNER_GROUP"	},
#define FATTR4_QUOTA_AVAIL_HARD    38
	{	FATTR4_QUOTA_AVAIL_HARD, "FATTR4_QUOTA_AVAIL_HARD"	},
#define FATTR4_QUOTA_AVAIL_SOFT    39
	{	FATTR4_QUOTA_AVAIL_SOFT, "FATTR4_QUOTA_AVAIL_SOFT"	},
#define FATTR4_QUOTA_USED          40
	{	FATTR4_QUOTA_USED, "FATTR4_QUOTA_USED"	},
#define FATTR4_RAWDEV              41
	{	FATTR4_RAWDEV, "FATTR4_RAWDEV"	},
#define FATTR4_SPACE_AVAIL         42
	{	FATTR4_SPACE_AVAIL, "FATTR4_SPACE_AVAIL"	},
#define FATTR4_SPACE_FREE          43
	{	FATTR4_SPACE_FREE, "FATTR4_SPACE_FREE"	},
#define FATTR4_SPACE_TOTAL         44
	{	FATTR4_SPACE_TOTAL, "FATTR4_SPACE_TOTAL"	},
#define FATTR4_SPACE_USED          45
	{	FATTR4_SPACE_USED, "FATTR4_SPACE_USED"	},
#define FATTR4_SYSTEM              46
	{	FATTR4_SYSTEM, "FATTR4_SYSTEM"	},
#define FATTR4_TIME_ACCESS         47
	{	FATTR4_TIME_ACCESS, "FATTR4_TIME_ACCESS"	},
#define FATTR4_TIME_ACCESS_SET     48
	{	FATTR4_TIME_ACCESS_SET, "FATTR4_TIME_ACCESS_SET"	},
#define FATTR4_TIME_BACKUP         49
	{	FATTR4_TIME_BACKUP, "FATTR4_TIME_BACKUP"	},
#define FATTR4_TIME_CREATE         50
	{	FATTR4_TIME_CREATE, "FATTR4_TIME_CREATE"	},
#define FATTR4_TIME_DELTA          51
	{	FATTR4_TIME_DELTA, "FATTR4_TIME_DELTA"	},
#define FATTR4_TIME_METADATA       52
	{	FATTR4_TIME_METADATA, "FATTR4_TIME_METADATA"	},
#define FATTR4_TIME_MODIFY         53
	{	FATTR4_TIME_MODIFY, "FATTR4_TIME_MODIFY"	},
#define FATTR4_TIME_MODIFY_SET     54
	{	FATTR4_TIME_MODIFY_SET, "FATTR4_TIME_MODIFY_SET"	},
#define FATTR4_MOUNTED_ON_FILEID   55
	{	FATTR4_MOUNTED_ON_FILEID, "FATTR4_MOUNTED_ON_FILEID"	},
	{	0,	NULL	}
};

#define FATTR4_BITMAP_ONLY 0
#define FATTR4_FULL_DISSECT 1

static int
dissect_nfs_attributes(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree, int type)
{
	guint32 bitmap_len;
	proto_item *fitem = NULL;
	proto_tree *newftree = NULL;
	proto_item *attr_fitem = NULL;
	proto_tree *attr_newftree = NULL;
	guint32 i;
	gint j;
	guint32 fattr;
	guint32 *bitmap=NULL;
	guint32 sl;
	int attr_vals_offset;

	bitmap_len = tvb_get_ntohl(tvb, offset);
        tvb_ensure_bytes_exist(tvb, offset, 4 + bitmap_len * 4);
	fitem = proto_tree_add_text(tree, tvb, offset, 4 + bitmap_len * 4,
		"%s", "attrmask");
	offset += 4;

	if (fitem == NULL) return offset;

	newftree = proto_item_add_subtree(fitem, ett_nfs_bitmap4);

	if (newftree == NULL) return offset;

	attr_vals_offset = offset + 4 + bitmap_len * 4;

	if(bitmap_len)
		bitmap = ep_alloc(bitmap_len * sizeof(guint32));

	if (bitmap == NULL) return offset;

	for (i = 0; i < bitmap_len; i++)
	{
		bitmap[i] = tvb_get_ntohl(tvb, offset);

		sl = 0x00000001;

		for (j = 0; j < 32; j++)
		{
			fattr = 32 * i + j;

			if (bitmap[i] & sl)
			{
				/* switch label if attribute is recommended vs. mandatory */
				attr_fitem = proto_tree_add_uint(newftree,
					(fattr < FATTR4_ACL)? hf_nfs_mand_attr: hf_nfs_recc_attr,
					tvb, offset, 4, fattr);

				if (attr_fitem == NULL) break;

				attr_newftree = proto_item_add_subtree(attr_fitem, ett_nfs_bitmap4);

				if (attr_newftree == NULL) break;

				if (type == FATTR4_FULL_DISSECT)
				{
					/* do a full decode of the arguments for the set flag */
					switch(fattr)
					{
					case FATTR4_SUPPORTED_ATTRS:
						attr_vals_offset = dissect_nfs_attributes(tvb,
							attr_vals_offset, pinfo, attr_newftree,
							FATTR4_BITMAP_ONLY);
						break;

					case FATTR4_TYPE:
						attr_vals_offset = dissect_rpc_uint32(tvb,
							attr_newftree, hf_nfs_ftype4, attr_vals_offset);
						break;

					case FATTR4_FH_EXPIRE_TYPE:
						attr_vals_offset = dissect_nfs_fattr4_fh_expire_type(tvb,
							attr_vals_offset, attr_newftree);
						break;

					case FATTR4_CHANGE:
						attr_vals_offset = dissect_rpc_uint64(tvb, attr_newftree,
							hf_nfs_changeid4, attr_vals_offset);
						break;

					case FATTR4_SIZE:
						attr_vals_offset = dissect_rpc_uint64(tvb,
							attr_newftree, hf_nfs_fattr4_size, attr_vals_offset);
						break;

					case FATTR4_LINK_SUPPORT:
						attr_vals_offset = dissect_rpc_bool(tvb,
							attr_newftree, hf_nfs_fattr4_link_support,
							attr_vals_offset);
						break;

					case FATTR4_SYMLINK_SUPPORT:
						attr_vals_offset = dissect_rpc_bool(tvb,
							attr_newftree, hf_nfs_fattr4_symlink_support,
							attr_vals_offset);
						break;

					case FATTR4_NAMED_ATTR:
						attr_vals_offset = dissect_rpc_bool(tvb,
							attr_newftree, hf_nfs_fattr4_named_attr, attr_vals_offset);
						break;

					case FATTR4_FSID:
						attr_vals_offset = dissect_nfs_fsid4(tvb, attr_vals_offset,
							attr_newftree, "fattr4_fsid");
						break;

					case FATTR4_UNIQUE_HANDLES:
						attr_vals_offset = dissect_rpc_bool(tvb,
							attr_newftree, hf_nfs_fattr4_unique_handles,
							attr_vals_offset);
						break;

					case FATTR4_LEASE_TIME:
						attr_vals_offset = dissect_rpc_uint32(tvb,
							attr_newftree, hf_nfs_fattr4_lease_time,
							attr_vals_offset);
						break;

					case FATTR4_RDATTR_ERROR:
						attr_vals_offset = dissect_nfs_nfsstat4(tvb,
							attr_vals_offset, attr_newftree, NULL);
						break;

					case FATTR4_ACL:
						attr_vals_offset = dissect_nfs_fattr4_acl(tvb,
							attr_vals_offset, pinfo, attr_newftree);
						break;

					case FATTR4_ACLSUPPORT:
						attr_vals_offset = dissect_rpc_uint32(tvb,
							attr_newftree, hf_nfs_fattr4_aclsupport,
							attr_vals_offset);
						break;

					case FATTR4_ARCHIVE:
						attr_vals_offset = dissect_rpc_bool(tvb,
							attr_newftree, hf_nfs_fattr4_archive,
							attr_vals_offset);
						break;

					case FATTR4_CANSETTIME:
						attr_vals_offset = dissect_rpc_bool(tvb,
							attr_newftree, hf_nfs_fattr4_cansettime, attr_vals_offset);
						break;

					case FATTR4_CASE_INSENSITIVE:
						attr_vals_offset = dissect_rpc_bool(tvb,
							attr_newftree, hf_nfs_fattr4_case_insensitive,
							attr_vals_offset);
						break;

					case FATTR4_CASE_PRESERVING:
						attr_vals_offset = dissect_rpc_bool(tvb,
							attr_newftree, hf_nfs_fattr4_case_preserving,
							attr_vals_offset);
						break;

					case FATTR4_CHOWN_RESTRICTED:
						attr_vals_offset = dissect_rpc_bool(tvb,
							attr_newftree, hf_nfs_fattr4_chown_restricted,
							attr_vals_offset);
						break;

					case FATTR4_FILEID:
						attr_vals_offset = dissect_rpc_uint64(tvb,
							attr_newftree, hf_nfs_fattr4_fileid, attr_vals_offset);
						break;

					case FATTR4_FILES_AVAIL:
						attr_vals_offset = dissect_rpc_uint64(tvb,
							attr_newftree, hf_nfs_fattr4_files_avail,
							attr_vals_offset);
						break;

					case FATTR4_FILEHANDLE:
						attr_vals_offset = dissect_nfs_fh4(tvb, attr_vals_offset,
							pinfo, attr_newftree, "fattr4_filehandle");
						break;

					case FATTR4_FILES_FREE:
						attr_vals_offset = dissect_rpc_uint64(tvb,
							attr_newftree, hf_nfs_fattr4_files_free, attr_vals_offset);
						break;

					case FATTR4_FILES_TOTAL:
						attr_vals_offset = dissect_rpc_uint64(tvb,
							attr_newftree, hf_nfs_fattr4_files_total,
							attr_vals_offset);
						break;

					case FATTR4_FS_LOCATIONS:
						attr_vals_offset = dissect_nfs_fs_locations4(tvb, pinfo,
							attr_vals_offset, attr_newftree,
							"fattr4_fs_locations");
						break;

					case FATTR4_HIDDEN:
						attr_vals_offset = dissect_rpc_bool(tvb,
							attr_newftree, hf_nfs_fattr4_hidden, attr_vals_offset);
						break;

					case FATTR4_HOMOGENEOUS:
						attr_vals_offset = dissect_rpc_bool(tvb,
							attr_newftree, hf_nfs_fattr4_homogeneous,
							attr_vals_offset);
						break;

					case FATTR4_MAXFILESIZE:
						attr_vals_offset = dissect_rpc_uint64(tvb,
							attr_newftree, hf_nfs_fattr4_maxfilesize,
							attr_vals_offset);
						break;

					case FATTR4_MAXLINK:
						attr_vals_offset = dissect_rpc_uint32(tvb,
							attr_newftree, hf_nfs_fattr4_maxlink, attr_vals_offset);
						break;

					case FATTR4_MAXNAME:
						attr_vals_offset = dissect_rpc_uint32(tvb,
							attr_newftree, hf_nfs_fattr4_maxname, attr_vals_offset);
						break;

					case FATTR4_MAXREAD:
						attr_vals_offset = dissect_rpc_uint64(tvb,
							attr_newftree, hf_nfs_fattr4_maxread, attr_vals_offset);
						break;

					case FATTR4_MAXWRITE:
						attr_vals_offset = dissect_rpc_uint64(tvb,
							attr_newftree, hf_nfs_fattr4_maxwrite, attr_vals_offset);
						break;

					case FATTR4_MIMETYPE:
						attr_vals_offset = dissect_nfs_utf8string(tvb,
							attr_vals_offset, attr_newftree,
							hf_nfs_fattr4_mimetype, NULL);
						break;

					case FATTR4_MODE:
						attr_vals_offset = dissect_nfs_mode4(tvb,
							attr_vals_offset, attr_newftree, "fattr4_mode");
						break;

					case FATTR4_NO_TRUNC:
						attr_vals_offset = dissect_rpc_bool(tvb,
							attr_newftree, hf_nfs_fattr4_no_trunc, attr_vals_offset);
						break;

					case FATTR4_NUMLINKS:
						attr_vals_offset = dissect_rpc_uint32(tvb,
							attr_newftree, hf_nfs_fattr4_numlinks, attr_vals_offset);
						break;

					case FATTR4_OWNER:
						attr_vals_offset = dissect_nfs_utf8string(tvb,
							attr_vals_offset, attr_newftree,
							hf_nfs_fattr4_owner,
							NULL);
						break;

					case FATTR4_OWNER_GROUP:
						attr_vals_offset = dissect_nfs_utf8string(tvb,
							attr_vals_offset, attr_newftree,
							hf_nfs_fattr4_owner_group, NULL);
						break;

					case FATTR4_QUOTA_AVAIL_HARD:
						attr_vals_offset = dissect_rpc_uint64(tvb,
							attr_newftree, hf_nfs_fattr4_quota_hard, attr_vals_offset);
						break;

					case FATTR4_QUOTA_AVAIL_SOFT:
						attr_vals_offset = dissect_rpc_uint64(tvb,
							attr_newftree, hf_nfs_fattr4_quota_soft, attr_vals_offset);
						break;

					case FATTR4_QUOTA_USED:
						attr_vals_offset = dissect_rpc_uint64(tvb,
							attr_newftree, hf_nfs_fattr4_quota_used, attr_vals_offset);
						break;

					case FATTR4_RAWDEV:
						attr_vals_offset = dissect_nfs_specdata4(tvb,
							attr_vals_offset, attr_newftree);
						break;

					case FATTR4_SPACE_AVAIL:
						attr_vals_offset = dissect_rpc_uint64(tvb,
							attr_newftree, hf_nfs_fattr4_space_avail,
							attr_vals_offset);
						break;

					case FATTR4_SPACE_FREE:
						attr_vals_offset = dissect_rpc_uint64(tvb,
							attr_newftree, hf_nfs_fattr4_space_free, attr_vals_offset);
						break;

					case FATTR4_SPACE_TOTAL:
						attr_vals_offset = dissect_rpc_uint64(tvb,
							attr_newftree, hf_nfs_fattr4_space_total,
							attr_vals_offset);
						break;

					case FATTR4_SPACE_USED:
						attr_vals_offset = dissect_rpc_uint64(tvb,
							attr_newftree, hf_nfs_fattr4_space_used, attr_vals_offset);
						break;

					case FATTR4_SYSTEM:
						attr_vals_offset = dissect_rpc_bool(tvb,
							attr_newftree, hf_nfs_fattr4_system, attr_vals_offset);
						break;

					case FATTR4_TIME_ACCESS:
					case FATTR4_TIME_BACKUP:
					case FATTR4_TIME_CREATE:
					case FATTR4_TIME_DELTA:
					case FATTR4_TIME_METADATA:
					case FATTR4_TIME_MODIFY:
						attr_vals_offset = dissect_nfs_nfstime4(tvb, attr_vals_offset,
							attr_newftree);
						break;

					case FATTR4_TIME_ACCESS_SET:
					case FATTR4_TIME_MODIFY_SET:
						attr_vals_offset = dissect_nfs_settime4(tvb,
							attr_vals_offset, attr_newftree, "settime4");
						break;

					default:
						break;
					}
				}
			}

			sl <<= 1;
		}

		offset += 4;
	}

	return offset;
}

static int
dissect_nfs_fattr4(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree)
{
	proto_tree *newftree = NULL;
	proto_item *fitem = NULL;

	fitem = proto_tree_add_text(tree, tvb, offset, 4, "obj_attributes");

	if (fitem == NULL) return offset;

	newftree = proto_item_add_subtree(fitem, ett_nfs_fattr4);

	if (newftree == NULL) return offset;

	offset = dissect_nfs_attributes(tvb, offset, pinfo, newftree,
		FATTR4_FULL_DISSECT);

	offset = dissect_nfsdata(tvb, offset, tree, hf_nfs_attrlist4);

	return offset;
}

static const value_string names_open4_share_access[] = {
#define OPEN4_SHARE_ACCESS_READ 0x00000001
	{ OPEN4_SHARE_ACCESS_READ, "OPEN4_SHARE_ACCESS_READ" },
#define OPEN4_SHARE_ACCESS_WRITE 0x00000002
	{ OPEN4_SHARE_ACCESS_WRITE, "OPEN4_SHARE_ACCESS_WRITE" },
#define OPEN4_SHARE_ACCESS_BOTH 0x00000003
	{ OPEN4_SHARE_ACCESS_BOTH, "OPEN4_SHARE_ACCESS_BOTH" },
	{ 0, NULL }
};

static int
dissect_nfs_open4_share_access(tvbuff_t *tvb, int offset,
	proto_tree *tree)
{
	guint share_access;

	share_access = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint(tree, hf_nfs_open4_share_access, tvb, offset, 4,
		share_access);
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
dissect_nfs_open4_share_deny(tvbuff_t *tvb, int offset,
	proto_tree *tree)
{
	guint deny_access;

	deny_access = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint(tree, hf_nfs_open4_share_deny, tvb, offset, 4,
		deny_access);
	offset += 4;

	return offset;
}

static int
dissect_nfs_open_owner4(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	offset = dissect_rpc_uint64(tvb, tree, hf_nfs_clientid4, offset);
	offset = dissect_nfsdata(tvb, offset, tree, hf_nfs_open_owner4);

	return offset;
}

static int
dissect_nfs_open_claim_delegate_cur4(tvbuff_t *tvb, int offset,
	proto_tree *tree)
{
	offset = dissect_rpc_uint64(tvb, tree,
		hf_nfs_stateid4_delegate_stateid, offset);
	offset = dissect_nfs_utf8string(tvb, offset, tree, hf_nfs_component4, NULL);

	return offset;
}

#define CLAIM_NULL				0
#define CLAIM_PREVIOUS			1
#define CLAIM_DELEGATE_CUR		2
#define CLAIM_DELEGATE_PREV	3

static const value_string names_claim_type4[] = {
	{	CLAIM_NULL,  		"CLAIM_NULL"  },
	{	CLAIM_PREVIOUS, 	"CLAIM_PREVIOUS" },
	{	CLAIM_DELEGATE_CUR, 	"CLAIM_DELEGATE_CUR" },
	{	CLAIM_DELEGATE_PREV,	"CLAIM_DELEGATE_PREV" },
	{	0, NULL }
};

static int
dissect_nfs_open_claim4(tvbuff_t *tvb, int offset,
	proto_tree *tree)
{
	guint open_claim_type4;
	proto_item *fitem = NULL;
	proto_tree *newftree = NULL;

	open_claim_type4 = tvb_get_ntohl(tvb, offset);
	fitem = proto_tree_add_uint(tree, hf_nfs_open_claim_type4, tvb,
		offset+0, 4, open_claim_type4);
	offset += 4;

	if (fitem) {
		newftree = proto_item_add_subtree(fitem, ett_nfs_open_claim4);

		if (newftree) {

			switch(open_claim_type4)
			{
			case CLAIM_NULL:
				offset = dissect_nfs_utf8string(tvb, offset, newftree, hf_nfs_component4, NULL);
				break;

			case CLAIM_PREVIOUS:
				offset = dissect_rpc_uint32(tvb, newftree,
					hf_nfs_delegate_type, offset);
				break;

			case CLAIM_DELEGATE_CUR:
				offset = dissect_nfs_open_claim_delegate_cur4(tvb, offset,
					newftree);
				break;

			case CLAIM_DELEGATE_PREV:
				offset = dissect_nfs_utf8string(tvb, offset, newftree, hf_nfs_component4, NULL);
				break;

			default:
				break;
			}
		}
	}

	return offset;
}

static int
dissect_nfs_createhow4(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree)
{
	guint mode;

	/* This is intentional; we're using the same flags as NFSv3 */
	mode = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint(tree, hf_nfs_createmode3, tvb, offset, 4, mode);
	offset += 4;

	switch(mode)
	{
	case UNCHECKED:		/* UNCHECKED4 */
	case GUARDED:		/* GUARDED4 */
		offset = dissect_nfs_fattr4(tvb, offset, pinfo, tree);
		break;

	case EXCLUSIVE:		/* EXCLUSIVE4 */
		offset = dissect_rpc_uint64(tvb, tree, hf_nfs_verifier4, offset);
		break;

	default:
		break;
	}

	return offset;
}

#define OPEN4_NOCREATE				0
#define OPEN4_CREATE					1
static const value_string names_opentype4[] = {
	{	OPEN4_NOCREATE,  "OPEN4_NOCREATE"  },
	{	OPEN4_CREATE, "OPEN4_CREATE" },
	{ 0, NULL }
};

static int
dissect_nfs_openflag4(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree)
{
	guint opentype4;
	proto_item *fitem = NULL;
	proto_tree *newftree = NULL;

	opentype4 = tvb_get_ntohl(tvb, offset);
	fitem = proto_tree_add_uint(tree, hf_nfs_opentype4, tvb,
		offset+0, 4, opentype4);
	offset += 4;

	if (fitem) {
		newftree = proto_item_add_subtree(fitem, ett_nfs_opentype4);

		if (newftree) {

			switch(opentype4)
			{
			case OPEN4_CREATE:
				offset = dissect_nfs_createhow4(tvb, offset, pinfo, newftree);
				break;

			default:
				break;
			}
		}
	}

	return offset;
}

static int
dissect_nfs_clientaddr4(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	offset = dissect_nfsdata(tvb, offset, tree, hf_nfs_r_netid);
	offset = dissect_nfsdata(tvb, offset, tree, hf_nfs_r_addr);

	return offset;
}


static int
dissect_nfs_cb_client4(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_tree *cb_location = NULL;
	proto_item *fitem = NULL;

	offset = dissect_rpc_uint32(tvb, tree, hf_nfs_cb_program, offset);

	fitem = proto_tree_add_text(tree, tvb, offset, 0, "cb_location");

	if (fitem)
	{
		cb_location = proto_item_add_subtree(fitem, ett_nfs_clientaddr4);

		offset = dissect_nfs_clientaddr4(tvb, offset, cb_location);
	}

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
dissect_nfs_stable_how4(tvbuff_t *tvb, int offset,
	proto_tree *tree, const char *name)
{
	guint stable_how4;

	stable_how4 = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint_format(tree, hf_nfs_stable_how4, tvb,
			offset+0, 4, stable_how4, "%s: %s (%u)", name,
			val_to_str(stable_how4, names_stable_how4, "%u"), stable_how4);
	offset += 4;

	return offset;
}

static const value_string names_nfsv4_operation[] = {
	{	NFS4_OP_ACCESS,					"ACCESS"	},
	{	NFS4_OP_CLOSE,						"CLOSE"	},
	{	NFS4_OP_COMMIT,					"COMMIT"	},
	{	NFS4_OP_CREATE,					"CREATE"	},
	{	NFS4_OP_DELEGPURGE,				"DELEGPURGE"	},
	{	NFS4_OP_DELEGRETURN,				"DELEGRETURN"	},
	{	NFS4_OP_GETATTR,					"GETATTR"	},
	{	NFS4_OP_GETFH,						"GETFH"	},
	{	NFS4_OP_LINK,						"LINK"	},
	{	NFS4_OP_LOCK,						"LOCK"	},
	{	NFS4_OP_LOCKT,						"LOCKT"	},
	{	NFS4_OP_LOCKU,						"LOCKU"	},
	{	NFS4_OP_LOOKUP,					"LOOKUP"	},
	{	NFS4_OP_LOOKUPP,					"LOOKUPP" },
	{	NFS4_OP_NVERIFY,					"NVERIFY"	},
	{	NFS4_OP_OPEN,						"OPEN"	},
	{	NFS4_OP_OPENATTR,					"OPENATTR"	},
	{	NFS4_OP_OPEN_CONFIRM,			"OPEN_CONFIRM"	},
	{	NFS4_OP_OPEN_DOWNGRADE,			"OPEN_DOWNGRADE"	},
	{	NFS4_OP_PUTFH,						"PUTFH"	},
	{	NFS4_OP_PUTPUBFH,					"PUTPUBFH"	},
	{	NFS4_OP_PUTROOTFH,				"PUTROOTFH"	},
	{	NFS4_OP_READ,						"READ"	},
	{	NFS4_OP_READDIR,					"READDIR"	},
	{	NFS4_OP_READLINK,					"READLINK"	},
	{	NFS4_OP_REMOVE,					"REMOVE"	},
	{	NFS4_OP_RENAME,					"RENAME"	},
	{	NFS4_OP_RENEW,						"RENEW"	},
	{	NFS4_OP_RESTOREFH,				"RESTOREFH"	},
	{	NFS4_OP_SAVEFH,					"SAVEFH"	},
	{	NFS4_OP_SECINFO,					"SECINFO"	},
	{	NFS4_OP_SETATTR,					"SETATTR"	},
	{	NFS4_OP_SETCLIENTID,				"SETCLIENTID"	},
	{	NFS4_OP_SETCLIENTID_CONFIRM,	"SETCLIENTID_CONFIRM"	},
	{	NFS4_OP_VERIFY,					"VERIFY"	},
	{	NFS4_OP_WRITE,						"WRITE"	},
	{	NFS4_OP_RELEASE_LOCKOWNER,		"RELEASE_LOCKOWNER"	},
	{	NFS4_OP_ILLEGAL,					"ILLEGAL"	},
	{ 0, NULL }
};

gint *nfsv4_operation_ett[] =
{
	 &ett_nfs_access4 ,
	 &ett_nfs_close4 ,
	 &ett_nfs_commit4 ,
	 &ett_nfs_create4 ,
	 &ett_nfs_delegpurge4 ,
	 &ett_nfs_delegreturn4 ,
	 &ett_nfs_getattr4 ,
	 &ett_nfs_getfh4 ,
	 &ett_nfs_link4 ,
	 &ett_nfs_lock4 ,
	 &ett_nfs_lockt4 ,
	 &ett_nfs_locku4 ,
	 &ett_nfs_lookup4 ,
	 &ett_nfs_lookupp4 ,
	 &ett_nfs_nverify4 ,
	 &ett_nfs_open4 ,
	 &ett_nfs_openattr4 ,
	 &ett_nfs_open_confirm4 ,
	 &ett_nfs_open_downgrade4 ,
	 &ett_nfs_putfh4 ,
	 &ett_nfs_putpubfh4 ,
	 &ett_nfs_putrootfh4 ,
	 &ett_nfs_read4 ,
	 &ett_nfs_readdir4 ,
	 &ett_nfs_readlink4 ,
	 &ett_nfs_remove4 ,
	 &ett_nfs_rename4 ,
	 &ett_nfs_renew4 ,
	 &ett_nfs_restorefh4 ,
	 &ett_nfs_savefh4 ,
	 &ett_nfs_secinfo4 ,
	 &ett_nfs_setattr4 ,
	 &ett_nfs_setclientid4 ,
	 &ett_nfs_setclientid_confirm4 ,
	 &ett_nfs_verify4 ,
	 &ett_nfs_write4,
    &ett_nfs_release_lockowner4,
};

static int
dissect_nfs_entry4(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	offset = dissect_rpc_uint64(tvb, tree, hf_nfs_cookie4, offset);
	offset = dissect_nfs_utf8string(tvb, offset, tree, hf_nfs_component4, NULL);
	offset = dissect_nfs_fattr4(tvb, offset, pinfo, tree);

	return offset;
}

static int
dissect_nfs_dirlist4(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree)
{
	proto_tree *newftree = NULL;

	newftree = proto_item_add_subtree(tree, ett_nfs_dirlist4);
	if (newftree==NULL) return offset;

	offset = dissect_rpc_list(tvb, pinfo, tree, offset, dissect_nfs_entry4);
	offset = dissect_rpc_bool(tvb, newftree, hf_nfs_dirlist4_eof, offset);

	return offset;
}

static int
dissect_nfs_change_info4(tvbuff_t *tvb, int offset,
	proto_tree *tree, const char *name)
{
	proto_tree *newftree = NULL;
	proto_tree *fitem = NULL;

	fitem = proto_tree_add_text(tree, tvb, offset, 0, "%s", name);

	if (fitem) {
		newftree = proto_item_add_subtree(fitem, ett_nfs_change_info4);

		if (newftree) {
			offset = dissect_rpc_bool(tvb, newftree,
				hf_nfs_change_info4_atomic, offset);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs_changeid4_before,
				offset);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs_changeid4_after,
				offset);
		}
	}

	return offset;
}

static const value_string names_nfs_lock_type4[] =
{
#define READ_LT 1
	{	READ_LT,		"READ_LT"				},
#define WRITE_LT 2
	{	WRITE_LT,		"WRITE_LT"				},
#define READW_LT 3
	{	READW_LT,	"READW_LT"	},
#define WRITEW_LT 4
	{	WRITEW_LT,	"WRITEW_LT"	},
#define RELEASE_STATE 5
	{	RELEASE_STATE,	"RELEASE_STATE"	},
	{	0,	NULL	}
};

static int
dissect_nfs_lock4denied(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	offset = dissect_rpc_uint64(tvb, tree, hf_nfs_offset4, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_nfs_length4, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs_lock_type4, offset);
	offset = dissect_nfs_lock_owner4(tvb, offset, tree);

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
dissect_nfs_open4_rflags(tvbuff_t *tvb, int offset,
	proto_tree *tree, const char *name)
{
	guint rflags;
	proto_item *rflags_item = NULL;
	proto_item *rflags_tree = NULL;

	rflags = tvb_get_ntohl(tvb, offset);

	if (tree)
	{
		rflags_item = proto_tree_add_text(tree, tvb, offset, 4,
			"%s: 0x%08x", name, rflags);

		if (rflags_item)
		{
			rflags_tree = proto_item_add_subtree(rflags_item,
				ett_nfs_open4_result_flags);

			if (rflags_tree)
			{
				proto_tree_add_text(rflags_tree, tvb, offset, 4, "%s",
					decode_enumerated_bitfield(rflags, OPEN4_RESULT_MLOCK, 2,
					names_open4_result_flags, "%s"));

				proto_tree_add_text(rflags_tree, tvb, offset, 4, "%s",
					decode_enumerated_bitfield(rflags, OPEN4_RESULT_CONFIRM, 2,
					names_open4_result_flags, "%s"));
			}
		}
	}

	offset += 4;

	return offset;
}

static int
dissect_nfs_stateid4(tvbuff_t *tvb, int offset,
		proto_tree *tree)
{
	proto_item *fitem = NULL;
	proto_tree *newftree = NULL;
	int sublen;
	int bytes_left;
	gboolean first_line;

	fitem = proto_tree_add_text(tree, tvb, offset, 4, "stateid");

	if (fitem) {
		newftree = proto_item_add_subtree(fitem, ett_nfs_stateid4);
		if (newftree) {
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs_seqid4,
				offset);

			bytes_left = 12;
			first_line = TRUE;

			while (bytes_left != 0)
			{
				sublen = 12;
				if (sublen > bytes_left)
					sublen = bytes_left;

				proto_tree_add_text(newftree, tvb, offset, sublen, "%s%s",
					first_line ? "other: " : "      ",
					tvb_bytes_to_str(tvb, offset, sublen));

				bytes_left -= sublen;
				offset += sublen;
				first_line = FALSE;
			}
		}
	}

	return offset;
}

static int
dissect_nfs_open_read_delegation4(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree)
{
	offset = dissect_nfs_stateid4(tvb, offset, tree);
	offset = dissect_rpc_bool(tvb, tree, hf_nfs_recall4, offset);
	offset = dissect_nfs_ace4(tvb, offset, pinfo, tree);

	return offset;
}

static int
dissect_nfs_modified_limit4(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs_num_blocks, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs_bytes_per_block, offset);

	return offset;
}

#define NFS_LIMIT_SIZE						1
#define NFS_LIMIT_BLOCKS					2
static const value_string names_limit_by4[] = {
	{	NFS_LIMIT_SIZE,  "NFS_LIMIT_SIZE"  },
	{	NFS_LIMIT_BLOCKS, "NFS_LIMIT_BLOCKS" },
	{ 0, NULL }
};

static int
dissect_nfs_space_limit4(tvbuff_t *tvb, int offset,
	proto_tree *tree)
{
	guint limitby;

	limitby = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint(tree, hf_nfs_limit_by4, tvb, offset+0, 4, limitby);
	offset += 4;

	switch(limitby)
	{
	case NFS_LIMIT_SIZE:
		offset = dissect_rpc_uint64(tvb, tree, hf_nfs_filesize,
			offset);
		break;

	case NFS_LIMIT_BLOCKS:
		offset = dissect_nfs_modified_limit4(tvb, offset, tree);
		break;

	default:
		break;
	}

	return offset;
}

static int
dissect_nfs_open_write_delegation4(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree)
{
	offset = dissect_nfs_stateid4(tvb, offset, tree);
	offset = dissect_rpc_bool(tvb, tree, hf_nfs_recall, offset);
	offset = dissect_nfs_space_limit4(tvb, offset, tree);
	offset = dissect_nfs_ace4(tvb, offset, pinfo, tree);

	return offset;
}

#define OPEN_DELEGATE_NONE 0
#define OPEN_DELEGATE_READ 1
#define OPEN_DELEGATE_WRITE 2
static const value_string names_open_delegation_type4[] = {
	{	OPEN_DELEGATE_NONE,  "OPEN_DELEGATE_NONE"  },
	{	OPEN_DELEGATE_READ, 	"OPEN_DELEGATE_READ" },
	{	OPEN_DELEGATE_WRITE,	"OPEN_DELEGATE_WRITE" },
	{ 0, NULL }
};

static int
dissect_nfs_open_delegation4(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree)
{
	guint delegation_type;
	proto_tree *newftree = NULL;
	proto_item *fitem = NULL;

	delegation_type = tvb_get_ntohl(tvb, offset);
	fitem = proto_tree_add_uint(tree, hf_nfs_open_delegation_type4, tvb, 
		offset+0, 4, delegation_type);
	offset += 4;

	if (fitem) {
		newftree = proto_item_add_subtree(fitem, ett_nfs_open_delegation4);

		switch(delegation_type)
		{
		case OPEN_DELEGATE_NONE:
			break;

		case OPEN_DELEGATE_READ:
			offset = dissect_nfs_open_read_delegation4(tvb, offset, pinfo,
				newftree);
			break;

		case OPEN_DELEGATE_WRITE:
			offset = dissect_nfs_open_write_delegation4(tvb, offset, pinfo,
				newftree);
			break;

		default:
			break;
		}
	}

	return offset;
}

static int
dissect_nfs_rpcsec_gss_info(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	offset = dissect_rpc_opaque_data(tvb, offset, tree, NULL,
            hf_nfs_sec_oid4, FALSE, 0, FALSE, NULL, NULL);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs_qop4, offset);
	offset = dissect_rpc_uint32(tvb, tree,
		hf_nfs_secinfo_rpcsec_gss_info_service, offset);

	return offset;
}

static int
dissect_nfs_open_to_lock_owner4(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs_seqid4, offset);
	offset = dissect_nfs_stateid4(tvb, offset, tree);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs_lock_seqid4, offset);
	offset = dissect_nfs_lock_owner4(tvb, offset, tree);

	return offset;
}

static int
dissect_nfs_exist_lock_owner4(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	offset = dissect_nfs_stateid4(tvb, offset, tree);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs_lock_seqid4, offset);

	return offset;
}

static int
dissect_nfs_locker4(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint new_lock_owner;

	new_lock_owner = tvb_get_ntohl(tvb, offset);
	offset = dissect_rpc_bool(tvb, tree, hf_nfs_new_lock_owner, offset);

	if (new_lock_owner)
		offset = dissect_nfs_open_to_lock_owner4(tvb, offset, tree);
	else
		offset = dissect_nfs_exist_lock_owner4(tvb, offset, tree);

	return offset;
}

static int
dissect_nfs_client_id4(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	offset = dissect_rpc_uint64(tvb, tree, hf_nfs_verifier4, offset);
	offset = dissect_rpc_data(tvb, tree, hf_nfs_client_id4_id, offset);

	return offset;
}

static int
dissect_nfs_argop4(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree)
{
	guint32 ops, ops_counter;
	guint opcode;
	proto_item *fitem;
	proto_tree *ftree = NULL;
	proto_tree *newftree = NULL;

	ops = tvb_get_ntohl(tvb, offset+0);

	fitem = proto_tree_add_text(tree, tvb, offset, 4,
		"Operations (count: %u)", ops);
	offset += 4;

	if (fitem == NULL) return offset;

	ftree = proto_item_add_subtree(fitem, ett_nfs_argop4);

	if (ftree == NULL) return offset;

	for (ops_counter=0; ops_counter<ops; ops_counter++)
	{
		opcode = tvb_get_ntohl(tvb, offset);

		fitem = proto_tree_add_uint(ftree, hf_nfs_argop4, tvb, offset, 4,
			opcode);
		offset += 4;

		/* the opcodes are not contiguous */
		if ((opcode < NFS4_OP_ACCESS || opcode > NFS4_OP_RELEASE_LOCKOWNER)	&&
			(opcode != NFS4_OP_ILLEGAL))
			break;

		if (fitem == NULL)	break;

		/* all of the V4 ops are contiguous, except for NFS4_OP_ILLEGAL */
		if (opcode == NFS4_OP_ILLEGAL)
			newftree = proto_item_add_subtree(fitem, ett_nfs_illegal4);
		else
			newftree = proto_item_add_subtree(fitem, 
				*nfsv4_operation_ett[opcode - 3]);

		if (newftree == NULL)	break;

		switch(opcode)
		{
		case NFS4_OP_ACCESS:
			offset = dissect_access(tvb, offset, newftree, "access");
			break;

		case NFS4_OP_CLOSE:
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs_seqid4,
				offset);
			offset = dissect_nfs_stateid4(tvb, offset, newftree);
			break;

		case NFS4_OP_COMMIT:
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs_offset4,
				offset);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs_count4,
				offset);
			break;

		case NFS4_OP_CREATE:
			{
				guint create_type;

				create_type = tvb_get_ntohl(tvb, offset);
				offset = dissect_rpc_uint32(tvb, newftree, hf_nfs_ftype4,
					offset);

				switch(create_type)
				{
				case NF4LNK:
					offset = dissect_nfs_utf8string(tvb, offset, newftree,
						hf_nfs_linktext4, NULL);
					break;

				case NF4BLK:
				case NF4CHR:
					offset = dissect_nfs_specdata4(tvb, offset, newftree);
					break;

				case NF4SOCK:
				case NF4FIFO:
				case NF4DIR:
					break;

				default:
					break;
				}

				offset = dissect_nfs_utf8string(tvb, offset, newftree, hf_nfs_component4, NULL);

				offset = dissect_nfs_fattr4(tvb, offset, pinfo, newftree);
			}
			break;

		case NFS4_OP_DELEGPURGE:
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs_clientid4, offset);
			break;

		case NFS4_OP_DELEGRETURN:
			offset = dissect_nfs_stateid4(tvb, offset, newftree);
			break;

		case NFS4_OP_GETATTR:
			offset = dissect_nfs_attributes(tvb, offset, pinfo, newftree,
				FATTR4_BITMAP_ONLY);
			break;

		case NFS4_OP_GETFH:
			break;

		case NFS4_OP_LINK:
			offset = dissect_nfs_utf8string(tvb, offset, newftree,
				hf_nfs_component4, NULL);
			break;

		case NFS4_OP_LOCK:
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs_lock_type4, offset);
			offset = dissect_rpc_bool(tvb, newftree, hf_nfs_lock4_reclaim, offset);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs_offset4, offset);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs_length4, offset);
			offset = dissect_nfs_locker4(tvb, offset, newftree);
			break;

		case NFS4_OP_LOCKT:
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs_lock_type4, offset);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs_offset4, offset);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs_length4, offset);
			offset = dissect_nfs_lock_owner4(tvb, offset, newftree);
			break;

		case NFS4_OP_LOCKU:
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs_lock_type4, offset);
			offset = dissect_rpc_uint32(tvb, tree, hf_nfs_seqid4, offset);
			offset = dissect_nfs_stateid4(tvb, offset, newftree);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs_offset4, offset);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs_length4, offset);
			break;

		case NFS4_OP_LOOKUP:
			offset = dissect_nfs_utf8string(tvb, offset, newftree,
				hf_nfs_component4, NULL);
			break;

		case NFS4_OP_LOOKUPP:
			break;

		case NFS4_OP_NVERIFY:
			offset = dissect_nfs_fattr4(tvb, offset, pinfo, newftree);
			break;

		case NFS4_OP_OPEN:
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs_seqid4,
				offset);
			offset = dissect_nfs_open4_share_access(tvb, offset, newftree);
			offset = dissect_nfs_open4_share_deny(tvb, offset, newftree);
			offset = dissect_nfs_open_owner4(tvb, offset, newftree);
			offset = dissect_nfs_openflag4(tvb, offset, pinfo, newftree);
			offset = dissect_nfs_open_claim4(tvb, offset, newftree);
			break;

		case NFS4_OP_OPENATTR:
			offset = dissect_rpc_bool(tvb, newftree, hf_nfs_attrdircreate,
				offset);
			break;

		case NFS4_OP_OPEN_CONFIRM:
			offset = dissect_nfs_stateid4(tvb, offset, newftree);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs_seqid4,
				offset);
			break;

		case NFS4_OP_OPEN_DOWNGRADE:
			offset = dissect_nfs_stateid4(tvb, offset, newftree);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs_seqid4,
				offset);
			offset = dissect_nfs_open4_share_access(tvb, offset, newftree);
			offset = dissect_nfs_open4_share_deny(tvb, offset, newftree);
			break;

		case NFS4_OP_PUTFH:
			offset = dissect_nfs_fh4(tvb, offset, pinfo, newftree, "filehandle");
			break;

		case NFS4_OP_PUTPUBFH:
		case NFS4_OP_PUTROOTFH:
			break;

		case NFS4_OP_READ:
			offset = dissect_nfs_stateid4(tvb, offset, newftree);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs_offset4,
				offset);
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs_count4,
				offset);
			break;

		case NFS4_OP_READDIR:
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs_cookie4,
				offset);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs_cookieverf4,
				offset);
			offset = dissect_rpc_uint32(tvb, newftree,
				hf_nfs_count4_dircount, offset);
			offset = dissect_rpc_uint32(tvb, newftree,
				hf_nfs_count4_maxcount, offset);
			offset = dissect_nfs_attributes(tvb, offset, pinfo, newftree,
				FATTR4_BITMAP_ONLY);
			break;

		case NFS4_OP_READLINK:
			break;

		case NFS4_OP_REMOVE:
			offset = dissect_nfs_utf8string(tvb, offset, newftree,
				hf_nfs_component4, NULL);
			break;

		case NFS4_OP_RENAME:
			offset = dissect_nfs_utf8string(tvb, offset, newftree,
				hf_nfs_component4, NULL);
			offset = dissect_nfs_utf8string(tvb, offset, newftree,
				hf_nfs_component4, NULL);
			break;

		case NFS4_OP_RENEW:
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs_clientid4, offset);
			break;

		case NFS4_OP_RESTOREFH:
		case NFS4_OP_SAVEFH:
			break;

		case NFS4_OP_SECINFO:
			offset = dissect_nfs_utf8string(tvb, offset, newftree,
				hf_nfs_component4, NULL);
			break;

		case NFS4_OP_SETATTR:
			offset = dissect_nfs_stateid4(tvb, offset, newftree);
			offset = dissect_nfs_fattr4(tvb, offset, pinfo, newftree);
			break;

		case NFS4_OP_SETCLIENTID:
			{
				proto_tree *client_tree = NULL;
				proto_tree *callback_tree = NULL;

				fitem = proto_tree_add_text(newftree, tvb, offset, 0, "client");
				if (fitem)
				{
					client_tree = proto_item_add_subtree(fitem, ett_nfs_client_id4);

					if (client_tree)
						offset = dissect_nfs_client_id4(tvb, offset, client_tree);
				}

				fitem = proto_tree_add_text(newftree, tvb, offset, 0, "callback");
				if (fitem)
				{
					callback_tree = proto_item_add_subtree(fitem,
						ett_nfs_cb_client4);

					if (callback_tree)
						offset = dissect_nfs_cb_client4(tvb, offset, callback_tree);
				}

				offset = dissect_rpc_uint32(tvb, newftree, hf_nfs_callback_ident,
					offset);
			}
			break;

		case NFS4_OP_SETCLIENTID_CONFIRM:
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs_clientid4, offset);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs_verifier4, offset);
			break;

		case NFS4_OP_VERIFY:
			offset = dissect_nfs_fattr4(tvb, offset, pinfo, newftree);
			break;

		case NFS4_OP_WRITE:
			offset = dissect_nfs_stateid4(tvb, offset, newftree);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs_offset4, offset);
			offset = dissect_nfs_stable_how4(tvb, offset, newftree, "stable");
			offset = dissect_nfsdata(tvb, offset, newftree, hf_nfs_data);
			break;

		case NFS4_OP_RELEASE_LOCKOWNER:
			offset = dissect_nfs_lock_owner4(tvb, offset, newftree);
			break;

		/* In theory, it's possible to get this opcode */
		case NFS4_OP_ILLEGAL:
			break;

		default:
			break;
		}
	}

	return offset;
}

static int
dissect_nfs4_compound_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	offset = dissect_nfs_utf8string(tvb, offset, tree, hf_nfs_tag4, NULL);
	offset = dissect_rpc_uint32(tvb, tree, hf_nfs_minorversion, offset);
	offset = dissect_nfs_argop4(tvb, offset, pinfo, tree);

	return offset;
}

static int
dissect_nfs_secinfo4_res(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	guint flavor;
	proto_item *fitem;
	proto_tree *secftree;

	flavor = tvb_get_ntohl(tvb, offset);
	fitem = proto_tree_add_uint(tree, hf_nfs_secinfo_flavor, tvb, offset, 4,
		flavor);
	offset += 4;

	if (fitem)
	{
		switch(flavor)
		{
		case RPCSEC_GSS:
			secftree = proto_item_add_subtree(fitem, ett_nfs_secinfo4_flavor_info);
			if (secftree)
				offset = dissect_nfs_rpcsec_gss_info(tvb, offset, secftree);
			break;

		default:
			break;
		}
	}

	return offset;
}

static int
dissect_nfs_resop4(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree)
{
	guint32 ops, ops_counter;
	guint32 opcode;
	proto_item *fitem;
	proto_tree *ftree = NULL;
	proto_tree *newftree = NULL;
	guint32 status;

	ops = tvb_get_ntohl(tvb, offset+0);

	fitem = proto_tree_add_text(tree, tvb, offset, 4,
		"Operations (count: %u)", ops);
	offset += 4;

	if (fitem == NULL)	return offset;

	ftree = proto_item_add_subtree(fitem, ett_nfs_resop4);

	if (ftree == NULL)	return offset;		/* error adding new subtree */

	for (ops_counter = 0; ops_counter < ops; ops_counter++)
	{
		opcode = tvb_get_ntohl(tvb, offset);

		/* sanity check for bogus packets */
		if ((opcode < NFS4_OP_ACCESS || opcode > NFS4_OP_WRITE) &&
			(opcode != NFS4_OP_ILLEGAL))
			break;

		fitem = proto_tree_add_uint(ftree, hf_nfs_resop4, tvb, offset, 4,
			opcode);
		offset += 4;

		if (fitem == NULL)	break;		/* error adding new item to tree */

		/* all of the V4 ops are contiguous, except for NFS4_OP_ILLEGAL */
		if (opcode == NFS4_OP_ILLEGAL)
			newftree = proto_item_add_subtree(fitem, ett_nfs_illegal4);
		else
			newftree = proto_item_add_subtree(fitem, 
				*nfsv4_operation_ett[opcode - 3]);

		if (newftree == NULL)
			break;		/* error adding new subtree to operation item */

		offset = dissect_nfs_nfsstat4(tvb, offset, newftree, &status);

		/*
		 * With the exception of NFS4_OP_LOCK, NFS4_OP_LOCKT, and
		 * NFS4_OP_SETATTR, all other ops do *not* return data with the
		 * failed status code. 
		 */
		if ((status != NFS4_OK) &&
			((opcode != NFS4_OP_LOCK) && (opcode != NFS4_OP_LOCKT) &&
			(opcode != NFS4_OP_SETATTR)))
			continue;

		/* These parsing routines are only executed if the status is NFS4_OK */
		switch(opcode)
		{
		case NFS4_OP_ACCESS:
			offset = dissect_access(tvb, offset, newftree, "Supported");
			offset = dissect_access(tvb, offset, newftree, "Access");
			break;

		case NFS4_OP_CLOSE:
			offset = dissect_nfs_stateid4(tvb, offset, newftree);
			break;

		case NFS4_OP_COMMIT:
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs_verifier4,
				offset);
			break;

		case NFS4_OP_CREATE:
			offset = dissect_nfs_change_info4(tvb, offset, newftree,
				"change_info");
			offset = dissect_nfs_attributes(tvb, offset, pinfo, newftree,
				FATTR4_BITMAP_ONLY);
			break;

		case NFS4_OP_GETATTR:
			offset = dissect_nfs_fattr4(tvb, offset, pinfo, newftree);
			break;

		case NFS4_OP_GETFH:
			offset = dissect_nfs_fh4(tvb, offset, pinfo, newftree, "Filehandle");
			break;

		case NFS4_OP_LINK:
			offset = dissect_nfs_change_info4(tvb, offset, newftree,
				"change_info");
			break;

		case NFS4_OP_LOCK:
		case NFS4_OP_LOCKT:
			if (status == NFS4_OK)
			{
				if (opcode == NFS4_OP_LOCK)
					offset = dissect_nfs_stateid4(tvb, offset, newftree);
			}
			else
			if (status == NFS4ERR_DENIED)
				offset = dissect_nfs_lock4denied(tvb, offset, newftree);
			break;

		case NFS4_OP_LOCKU:
			offset = dissect_nfs_stateid4(tvb, offset, newftree);
			break;

		case NFS4_OP_OPEN:
			offset = dissect_nfs_stateid4(tvb, offset, newftree);
			offset = dissect_nfs_change_info4(tvb, offset, newftree,
				"change_info");
			offset = dissect_nfs_open4_rflags(tvb, offset, newftree,
				"result_flags");
			offset = dissect_nfs_attributes(tvb, offset, pinfo, newftree,
				FATTR4_BITMAP_ONLY);
			offset = dissect_nfs_open_delegation4(tvb, offset, pinfo, newftree);
			break;

		case NFS4_OP_OPEN_CONFIRM:
		case NFS4_OP_OPEN_DOWNGRADE:
			offset = dissect_nfs_stateid4(tvb, offset, newftree);
			break;

		case NFS4_OP_READ:
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs_eof, offset);
			offset = dissect_nfsdata(tvb, offset, newftree, hf_nfs_data);
			break;

		case NFS4_OP_READDIR:
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs_verifier4, offset);
			offset = dissect_nfs_dirlist4(tvb, offset, pinfo, newftree);
			break;

		case NFS4_OP_READLINK:
			offset = dissect_nfs_utf8string(tvb, offset, newftree,
				hf_nfs_linktext4, NULL);
			break;

		case NFS4_OP_REMOVE:
			offset = dissect_nfs_change_info4(tvb, offset, newftree,
				"change_info");
			break;

		case NFS4_OP_RENAME:
			offset = dissect_nfs_change_info4(tvb, offset, newftree,
				"source_cinfo");
			offset = dissect_nfs_change_info4(tvb, offset, newftree,
				"target_cinfo");
			break;

		case NFS4_OP_SECINFO:
			offset = dissect_rpc_array(tvb, pinfo, newftree, offset,
				dissect_nfs_secinfo4_res, hf_nfs_secinfo_arr4);
			break;

		case NFS4_OP_SETATTR:
			offset = dissect_nfs_attributes(tvb, offset, pinfo, newftree,
				FATTR4_BITMAP_ONLY);
			break;

		case NFS4_OP_SETCLIENTID:
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs_clientid4,
				offset);
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs_verifier4,
				offset);
			break;

		case NFS4_OP_WRITE:
			offset = dissect_rpc_uint32(tvb, newftree, hf_nfs_count4,
				offset);
			offset = dissect_nfs_stable_how4(tvb, offset, newftree,
				"committed");
			offset = dissect_rpc_uint64(tvb, newftree, hf_nfs_verifier4,
				offset);
			break;

		default:
			break;
		}
	}

	return offset;
}

static int
dissect_nfs4_compound_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree* tree)
{
	guint32 status;

	offset = dissect_nfs_nfsstat4(tvb, offset, tree, &status);
	offset = dissect_nfs_utf8string(tvb, offset, tree, hf_nfs_tag4, NULL);
	offset = dissect_nfs_resop4(tvb, offset, pinfo, tree);

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
	{ 0,NULL,NULL,NULL }
};

static const value_string nfsv3_proc_vals[] = {
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

/* end of NFS Version 3 */

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

static const value_string nfsv4_proc_vals[] = {
	{ 0, "NULL" },
	{ 1, "COMPOUND" },
	{ 0, NULL }
};

static struct true_false_string yesno = { "Yes", "No" };

/*
 * Union of the NFSv2, NFSv3, and NFSv4 status codes.
 * Use for the "nfs.status" hidden field.
 */
static const value_string names_nfs_nfsstat[] = {
	{	0,	"OK"						},
	{	1,	"ERR_PERM"					},
	{	2,	"ERR_NOENT"					},
	{	5,	"ERR_IO"					},
	{	6,	"ERR_NXIO"					},
	{	13,	"ERR_ACCES"					},
	{	17,	"ERR_EXIST"					},
	{	18,	"ERR_XDEV"					},
	{	19,	"ERR_NODEV"					},
	{	20,	"ERR_NOTDIR"					},
	{	21,	"ERR_ISDIR"					},
	{	22,	"ERR_INVAL"					},
	{	26,	"ERR_TXTBSY"					},
	{	27,	"ERR_FBIG"					},
	{	28,	"ERR_NOSPC"					},
	{	30,	"ERR_ROFS"					},
	{	31,	"ERR_MLINK"					},
	{	45,	"ERR_OPNOTSUPP"					},
	{	63,	"ERR_NAMETOOLONG"				},
	{	66,	"ERR_NOTEMPTY"					},
	{	69,	"ERR_DQUOT"					},
	{	70,	"ERR_STALE"					},
	{	71,	"ERR_REMOTE"					},
	{	99,	"ERR_WFLUSH"					},
	{	10001,	"ERR_BADHANDLE"					},
	{	10002,	"ERR_NOT_SYNC"					},
	{	10003,	"ERR_BAD_COOKIE"				},
	{	10004,	"ERR_NOTSUPP"					},
	{	10005,	"ERR_TOOSMALL"					},
	{	10006,	"ERR_SERVERFAULT"				},
	{	10007,	"ERR_BADTYPE"					},
	{	10008,	"ERR_DELAY"					},
	{	10009,	"ERR_SAME"					},
	{	10010,	"ERR_DENIED"					},
	{	10011,	"ERR_EXPIRED"					},
	{	10012,	"ERR_LOCKED"					},
	{	10013,	"ERR_GRACE"					},
	{	10014,	"ERR_FHEXPIRED"					},
	{	10015,	"ERR_SHARE_DENIED"				},
	{	10016,	"ERR_WRONGSEC"					},
	{	10017,	"ERR_CLID_INUSE"				},
	{	10018,	"ERR_RESOURCE"					},
	{	10019,	"ERR_MOVED"					},
	{	10020,	"ERR_NOFILEHANDLE"				},
	{	10021,	"ERR_MINOR_VERS_MISMATCH"			},
	{	10022,	"ERR_STALE_CLIENTID"				},
	{	10023,	"ERR_STALE_STATEID"				},
	{	10024,	"ERR_OLD_STATEID"				},
	{	10025,	"ERR_BAD_STATEID"				},
	{	10026,	"ERR_BAD_SEQID"					},
	{	10027,	"ERR_NOT_SAME"					},
	{	10028,	"ERR_LOCK_RANGE"				},
	{	10029,	"ERR_SYMLINK"					},
	{	10030,	"ERR_READDIR_NOSPC"				},
	{	10031,	"ERR_LEASE_MOVED"				},
	{	10032,	"ERR_ATTRNOTSUPP"				},
	{	10033,	"ERR_NO_GRACE"					},
	{	10034,	"ERR_RECLAIM_BAD"				},
	{	10035,	"ERR_RECLAIM_CONFLICT"				},
	{	10036,	"ERR_BADXDR"					},
	{	10037,	"ERR_LOCKS_HELD"				},
	{	10038,	"ERR_OPENMODE"					},
	{	10039,	"ERR_BADOWNER"					},
	{	10040,	"ERR_BADCHAR"					},
	{	10041,	"ERR_BADNAME"					},
	{	10042,	"ERR_BAD_RANGE"					},
	{	10043,	"ERR_LOCK_NOTSUPP"				},
	{	10044,	"ERR_OP_ILLEGAL"				},
	{	10045,	"ERR_DEADLOCK"					},
	{	10046,	"ERR_FILE_OPEN"					},
	{	10047,	"ERR_ADMIN_REVOKED"				},
	{	10048,	"ERR_CB_PATH_DOWN"				},
	{	0,	NULL }
};

void
proto_register_nfs(void)
{
	static hf_register_info hf[] = {
		{ &hf_nfs_procedure_v2, {
			"V2 Procedure", "nfs.procedure_v2", FT_UINT32, BASE_DEC,
			VALS(nfsv2_proc_vals), 0, "V2 Procedure", HFILL }},
		{ &hf_nfs_procedure_v3, {
			"V3 Procedure", "nfs.procedure_v3", FT_UINT32, BASE_DEC,
			VALS(nfsv3_proc_vals), 0, "V3 Procedure", HFILL }},
		{ &hf_nfs_procedure_v4, {
			"V4 Procedure", "nfs.procedure_v4", FT_UINT32, BASE_DEC,
			VALS(nfsv4_proc_vals), 0, "V4 Procedure", HFILL }},
		{ &hf_nfs_fh_length, {
			"length", "nfs.fh.length", FT_UINT32, BASE_DEC,
			NULL, 0, "file handle length", HFILL }},
		{ &hf_nfs_fh_hash, {
			"hash", "nfs.fh.hash", FT_UINT32, BASE_HEX,
			NULL, 0, "file handle hash", HFILL }},
		{ &hf_nfs_fh_mount_fileid, {
			"fileid", "nfs.fh.mount.fileid", FT_UINT32, BASE_DEC,
			NULL, 0, "mount point fileid", HFILL }},
		{ &hf_nfs_fh_mount_generation, {
			"generation", "nfs.fh.mount.generation", FT_UINT32, BASE_HEX,
			NULL, 0, "mount point generation", HFILL }},
		{ &hf_nfs_fh_flags, {
			"flags", "nfs.fh.flags", FT_UINT16, BASE_HEX,
			NULL, 0, "file handle flags", HFILL }},
		{ &hf_nfs_fh_snapid, {
			"snapid", "nfs.fh.snapid", FT_UINT8, BASE_DEC,
			NULL, 0, "snapshot ID", HFILL }},
		{ &hf_nfs_fh_unused, {
			"unused", "nfs.fh.unused", FT_UINT8, BASE_DEC,
			NULL, 0, "unused", HFILL }},
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
		{ &hf_nfs_fh_fsid_major, {
			"major", "nfs.fh.fsid.major", FT_UINT32, BASE_DEC,
			NULL, 0, "major file system ID", HFILL }},
		{ &hf_nfs_fh_fsid_minor, {
			"minor", "nfs.fh.fsid.minor", FT_UINT32, BASE_DEC,
			NULL, 0, "minor file system ID", HFILL }},
		{ &hf_nfs_fh_fsid_inode, {
			"inode", "nfs.fh.fsid.inode", FT_UINT32, BASE_DEC,
			NULL, 0, "file system inode", HFILL }},
		{ &hf_nfs_fh_xfsid_major, {
			"exported major", "nfs.fh.xfsid.major", FT_UINT32, BASE_DEC,
			NULL, 0, "exported major file system ID", HFILL }},
		{ &hf_nfs_fh_xfsid_minor, {
			"exported minor", "nfs.fh.xfsid.minor", FT_UINT32, BASE_DEC,
			NULL, 0, "exported minor file system ID", HFILL }},
		{ &hf_nfs_fh_fstype, {
			"file system type", "nfs.fh.fstype", FT_UINT32, BASE_DEC,
			NULL, 0, "file system type", HFILL }},
		{ &hf_nfs_fh_fn, {
			"file number", "nfs.fh.fn", FT_UINT32, BASE_DEC,
			NULL, 0, "file number", HFILL }},
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
			NULL, 0, "exported file number", HFILL }},
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
		{ &hf_nfs_fh_dev, {
			"device", "nfs.fh.dev", FT_UINT32, BASE_DEC,
			NULL, 0, "device", HFILL }},
		{ &hf_nfs_fh_xdev, {
			"exported device", "nfs.fh.xdev", FT_UINT32, BASE_DEC,
			NULL, 0, "exported device", HFILL }},
		{ &hf_nfs_fh_dirinode, {
			"directory inode", "nfs.fh.dirinode", FT_UINT32, BASE_DEC,
			NULL, 0, "directory inode", HFILL }},
		{ &hf_nfs_fh_pinode, {
			"pseudo inode", "nfs.fh.pinode", FT_UINT32, BASE_HEX,
			NULL, 0, "pseudo inode", HFILL }},
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
		{ &hf_nfs_stat, {
			"Status", "nfs.stat", FT_UINT32, BASE_DEC,
			VALS(names_nfs_stat), 0, "Reply status", HFILL }},
		{ &hf_nfs_full_name, {
			"Full Name", "nfs.full_name", FT_STRING, BASE_DEC,
			NULL, 0, "Full Name", HFILL }},
		{ &hf_nfs_name, {
			"Name", "nfs.name", FT_STRING, BASE_DEC,
			NULL, 0, "Name", HFILL }},
		{ &hf_nfs_readlink_data, {
			"Data", "nfs.readlink.data", FT_STRING, BASE_DEC,
			NULL, 0, "Symbolic Link Data", HFILL }},
		{ &hf_nfs_read_offset, {
			"Offset", "nfs.read.offset", FT_UINT32, BASE_DEC,
			NULL, 0, "Read Offset", HFILL }},
		{ &hf_nfs_read_count, {
			"Count", "nfs.read.count", FT_UINT32, BASE_DEC,
			NULL, 0, "Read Count", HFILL }},
		{ &hf_nfs_read_totalcount, {
			"Total Count", "nfs.read.totalcount", FT_UINT32, BASE_DEC,
			NULL, 0, "Total Count (obsolete)", HFILL }},
		{ &hf_nfs_data, {
			"Data", "nfs.data", FT_BYTES, BASE_DEC,
			NULL, 0, "Data", HFILL }},
		{ &hf_nfs_write_beginoffset, {
			"Begin Offset", "nfs.write.beginoffset", FT_UINT32, BASE_DEC,
			NULL, 0, "Begin offset (obsolete)", HFILL }},
		{ &hf_nfs_write_offset, {
			"Offset", "nfs.write.offset", FT_UINT32, BASE_DEC,
			NULL, 0, "Offset", HFILL }},
		{ &hf_nfs_write_totalcount, {
			"Total Count", "nfs.write.totalcount", FT_UINT32, BASE_DEC,
			NULL, 0, "Total Count (obsolete)", HFILL }},
		{ &hf_nfs_symlink_to, {
			"To", "nfs.symlink.to", FT_STRING, BASE_DEC,
			NULL, 0, "Symbolic link destination name", HFILL }},
		{ &hf_nfs_readdir_cookie, {
			"Cookie", "nfs.readdir.cookie", FT_UINT32, BASE_DEC,
			NULL, 0, "Directory Cookie", HFILL }},
		{ &hf_nfs_readdir_count, {
			"Count", "nfs.readdir.count", FT_UINT32, BASE_DEC,
			NULL, 0, "Directory Count", HFILL }},

		{ &hf_nfs_readdir_entry, {
			"Entry", "nfs.readdir.entry", FT_NONE, 0,
			NULL, 0, "Directory Entry", HFILL }},

		{ &hf_nfs_readdir_entry_fileid, {
			"File ID", "nfs.readdir.entry.fileid", FT_UINT32, BASE_DEC,
			NULL, 0, "File ID", HFILL }},

		{ &hf_nfs_readdir_entry_name, {
			"Name", "nfs.readdir.entry.name", FT_STRING, BASE_DEC,
			NULL, 0, "Name", HFILL }},

		{ &hf_nfs_readdir_entry_cookie, {
			"Cookie", "nfs.readdir.entry.cookie", FT_UINT32, BASE_DEC,
			NULL, 0, "Directory Cookie", HFILL }},

		{ &hf_nfs_readdir_entry3_fileid, {
			"File ID", "nfs.readdir.entry3.fileid", FT_UINT64, BASE_DEC,
			NULL, 0, "File ID", HFILL }},

		{ &hf_nfs_readdir_entry3_name, {
			"Name", "nfs.readdir.entry3.name", FT_STRING, BASE_DEC,
			NULL, 0, "Name", HFILL }},

		{ &hf_nfs_readdir_entry3_cookie, {
			"Cookie", "nfs.readdir.entry3.cookie", FT_UINT64, BASE_DEC,
			NULL, 0, "Directory Cookie", HFILL }},

		{ &hf_nfs_readdirplus_entry_fileid, {
			"File ID", "nfs.readdirplus.entry.fileid", FT_UINT64, BASE_DEC,
			NULL, 0, "Name", HFILL }},

		{ &hf_nfs_readdirplus_entry_name, {
			"Name", "nfs.readdirplus.entry.name", FT_STRING, BASE_DEC,
			NULL, 0, "Name", HFILL }},

		{ &hf_nfs_readdirplus_entry_cookie, {
			"Cookie", "nfs.readdirplus.entry.cookie", FT_UINT64, BASE_DEC,
			NULL, 0, "Directory Cookie", HFILL }},

		{ &hf_nfs_readdir_eof, {
			"EOF", "nfs.readdir.eof", FT_UINT32, BASE_DEC,
			NULL, 0, "EOF", HFILL }},

		{ &hf_nfs_statfs_tsize, {
			"Transfer Size", "nfs.statfs.tsize", FT_UINT32, BASE_DEC,
			NULL, 0, "Transfer Size", HFILL }},
		{ &hf_nfs_statfs_bsize, {
			"Block Size", "nfs.statfs.bsize", FT_UINT32, BASE_DEC,
			NULL, 0, "Block Size", HFILL }},
		{ &hf_nfs_statfs_blocks, {
			"Total Blocks", "nfs.statfs.blocks", FT_UINT32, BASE_DEC,
			NULL, 0, "Total Blocks", HFILL }},
		{ &hf_nfs_statfs_bfree, {
			"Free Blocks", "nfs.statfs.bfree", FT_UINT32, BASE_DEC,
			NULL, 0, "Free Blocks", HFILL }},
		{ &hf_nfs_statfs_bavail, {
			"Available Blocks", "nfs.statfs.bavail", FT_UINT32, BASE_DEC,
			NULL, 0, "Available Blocks", HFILL }},
		{ &hf_nfs_ftype3, {
			"Type", "nfs.type", FT_UINT32, BASE_DEC,
			VALS(names_nfs_ftype3), 0, "File Type", HFILL }},
		{ &hf_nfs_nfsstat3, {
			"Status", "nfs.nfsstat3", FT_UINT32, BASE_DEC,
			VALS(names_nfs_nfsstat3), 0, "Reply status", HFILL }},
		{ &hf_nfs_read_eof, {
			"EOF", "nfs.read.eof", FT_BOOLEAN, BASE_NONE,
			&yesno, 0, "EOF", HFILL }},
		{ &hf_nfs_write_stable, {
			"Stable", "nfs.write.stable", FT_UINT32, BASE_DEC,
			VALS(names_stable_how), 0, "Stable", HFILL }},
		{ &hf_nfs_write_committed, {
			"Committed", "nfs.write.committed", FT_UINT32, BASE_DEC,
			VALS(names_stable_how), 0, "Committed", HFILL }},
		{ &hf_nfs_createmode3, {
			"Create Mode", "nfs.createmode", FT_UINT32, BASE_DEC,
			VALS(names_createmode3), 0, "Create Mode", HFILL }},
		{ &hf_nfs_fsstat_invarsec, {
			"invarsec", "nfs.fsstat.invarsec", FT_UINT32, BASE_DEC,
			NULL, 0, "probable number of seconds of file system invariance", HFILL }},
		{ &hf_nfs_fsinfo_rtmax, {
			"rtmax", "nfs.fsinfo.rtmax", FT_UINT32, BASE_DEC,
			NULL, 0, "maximum READ request", HFILL }},
		{ &hf_nfs_fsinfo_rtpref, {
			"rtpref", "nfs.fsinfo.rtpref", FT_UINT32, BASE_DEC,
			NULL, 0, "Preferred READ request size", HFILL }},
		{ &hf_nfs_fsinfo_rtmult, {
			"rtmult", "nfs.fsinfo.rtmult", FT_UINT32, BASE_DEC,
			NULL, 0, "Suggested READ multiple", HFILL }},
		{ &hf_nfs_fsinfo_wtmax, {
			"wtmax", "nfs.fsinfo.wtmax", FT_UINT32, BASE_DEC,
			NULL, 0, "Maximum WRITE request size", HFILL }},
		{ &hf_nfs_fsinfo_wtpref, {
			"wtpref", "nfs.fsinfo.wtpref", FT_UINT32, BASE_DEC,
			NULL, 0, "Preferred WRITE request size", HFILL }},
		{ &hf_nfs_fsinfo_wtmult, {
			"wtmult", "nfs.fsinfo.wtmult", FT_UINT32, BASE_DEC,
			NULL, 0, "Suggested WRITE multiple", HFILL }},
		{ &hf_nfs_fsinfo_dtpref, {
			"dtpref", "nfs.fsinfo.dtpref", FT_UINT32, BASE_DEC,
			NULL, 0, "Preferred READDIR request", HFILL }},
		{ &hf_nfs_fsinfo_maxfilesize, {
			"maxfilesize", "nfs.fsinfo.maxfilesize", FT_UINT64, BASE_DEC,
			NULL, 0, "Maximum file size", HFILL }},
		{ &hf_nfs_fsinfo_properties, {
			"Properties", "nfs.fsinfo.properties", FT_UINT32, BASE_HEX,
			NULL, 0, "File System Properties", HFILL }},
		{ &hf_nfs_pathconf_linkmax, {
			"linkmax", "nfs.pathconf.linkmax", FT_UINT32, BASE_DEC,
			NULL, 0, "Maximum number of hard links", HFILL }},
		{ &hf_nfs_pathconf_name_max, {
			"name_max", "nfs.pathconf.name_max", FT_UINT32, BASE_DEC,
			NULL, 0, "Maximum file name length", HFILL }},
		{ &hf_nfs_pathconf_no_trunc, {
			"no_trunc", "nfs.pathconf.no_trunc", FT_BOOLEAN, BASE_NONE,
			&yesno, 0, "No long file name truncation", HFILL }},
		{ &hf_nfs_pathconf_chown_restricted, {
			"chown_restricted", "nfs.pathconf.chown_restricted", FT_BOOLEAN,
			BASE_NONE, &yesno, 0, "chown is restricted to root", HFILL }},
		{ &hf_nfs_pathconf_case_insensitive, {
			"case_insensitive", "nfs.pathconf.case_insensitive", FT_BOOLEAN,
			BASE_NONE, &yesno, 0, "file names are treated case insensitive", HFILL }},
		{ &hf_nfs_pathconf_case_preserving, {
			"case_preserving", "nfs.pathconf.case_preserving", FT_BOOLEAN,
			BASE_NONE, &yesno, 0, "file name cases are preserved", HFILL }},

		{ &hf_nfs_fattr_type, {
			"type", "nfs.fattr.type", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.fattr.type", HFILL }},

		{ &hf_nfs_fattr_nlink, {
			"nlink", "nfs.fattr.nlink", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.fattr.nlink", HFILL }},

		{ &hf_nfs_fattr_uid, {
			"uid", "nfs.fattr.uid", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.fattr.uid", HFILL }},

		{ &hf_nfs_fattr_gid, {
			"gid", "nfs.fattr.gid", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.fattr.gid", HFILL }},

		{ &hf_nfs_fattr_size, {
			"size", "nfs.fattr.size", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.fattr.size", HFILL }},

		{ &hf_nfs_fattr_blocksize, {
			"blocksize", "nfs.fattr.blocksize", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.fattr.blocksize", HFILL }},

		{ &hf_nfs_fattr_rdev, {
			"rdev", "nfs.fattr.rdev", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.fattr.rdev", HFILL }},

		{ &hf_nfs_fattr_blocks, {
			"blocks", "nfs.fattr.blocks", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.fattr.blocks", HFILL }},

		{ &hf_nfs_fattr_fsid, {
			"fsid", "nfs.fattr.fsid", FT_UINT32, BASE_HEX,
			NULL, 0, "nfs.fattr.fsid", HFILL }},

		{ &hf_nfs_fattr_fileid, {
			"fileid", "nfs.fattr.fileid", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.fattr.fileid", HFILL }},

		{ &hf_nfs_fattr3_type, {
			"Type", "nfs.fattr3.type", FT_UINT32, BASE_DEC,
			VALS(names_nfs_ftype3), 0, "nfs.fattr3.type", HFILL }},

		{ &hf_nfs_fattr3_nlink, {
			"nlink", "nfs.fattr3.nlink", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.fattr3.nlink", HFILL }},

		{ &hf_nfs_fattr3_uid, {
			"uid", "nfs.fattr3.uid", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.fattr3.uid", HFILL }},

		{ &hf_nfs_fattr3_gid, {
			"gid", "nfs.fattr3.gid", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.fattr3.gid", HFILL }},

		{ &hf_nfs_fattr3_size, {
			"size", "nfs.fattr3.size", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.fattr3.size", HFILL }},

		{ &hf_nfs_fattr3_used, {
			"used", "nfs.fattr3.used", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.fattr3.used", HFILL }},

		{ &hf_nfs_fattr3_rdev, {
			"rdev", "nfs.fattr3.rdev", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.fattr3.rdev", HFILL }},

		{ &hf_nfs_fattr3_fsid, {
			"fsid", "nfs.fattr3.fsid", FT_UINT64, BASE_HEX,
			NULL, 0, "nfs.fattr3.fsid", HFILL }},

		{ &hf_nfs_fattr3_fileid, {
			"fileid", "nfs.fattr3.fileid", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.fattr3.fileid", HFILL }},

		{ &hf_nfs_wcc_attr_size, {
			"size", "nfs.wcc_attr.size", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.wcc_attr.size", HFILL }},

		{ &hf_nfs_set_size3_size, {
			"size", "nfs.set_size3.size", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.set_size3.size", HFILL }},

		{ &hf_nfs_uid3, {
			"uid", "nfs.uid3", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.uid3", HFILL }},

		{ &hf_nfs_gid3, {
			"gid", "nfs.gid3", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.gid3", HFILL }},

		{ &hf_nfs_cookie3, {
			"cookie", "nfs.cookie3", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.cookie3", HFILL }},

		{ &hf_nfs_offset3, {
			"offset", "nfs.offset3", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.offset3", HFILL }},

		{ &hf_nfs_count3, {
			"count", "nfs.count3", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.count3", HFILL }},

		{ &hf_nfs_count3_maxcount, {
			"maxcount", "nfs.count3_maxcount", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.count3_maxcount", HFILL }},

		{ &hf_nfs_count3_dircount, {
			"dircount", "nfs.count3_dircount", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.count3_dircount", HFILL }},

		{ &hf_nfs_fsstat3_resok_tbytes, {
			"Total bytes", "nfs.fsstat3_resok.tbytes", FT_UINT64, BASE_DEC,
			NULL, 0, "Total bytes", HFILL }},

		{ &hf_nfs_fsstat3_resok_fbytes, {
			"Free bytes", "nfs.fsstat3_resok.fbytes", FT_UINT64, BASE_DEC,
			NULL, 0, "Free bytes", HFILL }},

		{ &hf_nfs_fsstat3_resok_abytes, {
			"Available free bytes", "nfs.fsstat3_resok.abytes", FT_UINT64, BASE_DEC,
			NULL, 0, "Available free bytes", HFILL }},

		{ &hf_nfs_fsstat3_resok_tfiles, {
			"Total file slots", "nfs.fsstat3_resok.tfiles", FT_UINT64, BASE_DEC,
			NULL, 0, "Total file slots", HFILL }},

		{ &hf_nfs_fsstat3_resok_ffiles, {
			"Free file slots", "nfs.fsstat3_resok.ffiles", FT_UINT64, BASE_DEC,
			NULL, 0, "Free file slots", HFILL }},

		{ &hf_nfs_fsstat3_resok_afiles, {
			"Available free file slots", "nfs.fsstat3_resok.afiles", FT_UINT64, BASE_DEC,
			NULL, 0, "Available free file slots", HFILL }},

		/* NFSv4 */

		{ &hf_nfs_nfsstat4, {
			"Status", "nfs.nfsstat4", FT_UINT32, BASE_DEC,
			VALS(names_nfs_nfsstat4), 0, "Reply status", HFILL }},

		{ &hf_nfs_argop4, {
			"Opcode", "nfs.call.operation", FT_UINT32, BASE_DEC,
			VALS(names_nfsv4_operation), 0, "Opcode", HFILL }},

		{ &hf_nfs_resop4,	{
			"Opcode", "nfs.reply.operation", FT_UINT32, BASE_DEC,
			VALS(names_nfsv4_operation), 0, "Opcode", HFILL }},

		{ &hf_nfs_linktext4, {
			"Name", "nfs.symlink.linktext", FT_STRING, BASE_DEC,
			NULL, 0, "Symbolic link contents", HFILL }},

		{ &hf_nfs_component4, {
			"Filename", "nfs.pathname.component", FT_STRING, BASE_DEC,
			NULL, 0, "Pathname component", HFILL }},

		{ &hf_nfs_tag4, {
			"Tag", "nfs.tag", FT_STRING, BASE_DEC,
			NULL, 0, "Tag", HFILL }},

		{ &hf_nfs_clientid4, {
			"clientid", "nfs.clientid", FT_UINT64, BASE_HEX,
			NULL, 0, "Client ID", HFILL }},

		{ &hf_nfs_ace4, {
			"ace", "nfs.ace", FT_STRING, BASE_DEC,
			NULL, 0, "Access Control Entry", HFILL }},

		{ &hf_nfs_recall, {
			"EOF", "nfs.recall", FT_BOOLEAN, BASE_NONE,
			&yesno, 0, "Recall", HFILL }},

		{ &hf_nfs_open_claim_type4, {
			"Claim Type", "nfs.open.claim_type", FT_UINT32, BASE_DEC,
			VALS(names_claim_type4), 0, "Claim Type", HFILL }},

		{ &hf_nfs_opentype4, {
			"Open Type", "nfs.open.opentype", FT_UINT32, BASE_DEC,
			VALS(names_opentype4), 0, "Open Type", HFILL }},

		{ &hf_nfs_limit_by4, {
			"Space Limit", "nfs.open.limit_by", FT_UINT32, BASE_DEC,
			VALS(names_limit_by4), 0, "Limit By", HFILL }},

		{ &hf_nfs_open_delegation_type4, {
			"Delegation Type", "nfs.open.delegation_type", FT_UINT32, BASE_DEC,
			VALS(names_open_delegation_type4), 0, "Delegation Type", HFILL }},

		{ &hf_nfs_ftype4, {
			"nfs_ftype4", "nfs.nfs_ftype4", FT_UINT32, BASE_DEC,
			VALS(names_ftype4), 0, "nfs.nfs_ftype4", HFILL }},

		{ &hf_nfs_change_info4_atomic, {
			"Atomic", "nfs.change_info.atomic", FT_BOOLEAN, BASE_NONE,
			&yesno, 0, "Atomic", HFILL }},

		{ &hf_nfs_open4_share_access, {
			"share_access", "nfs.open4.share_access", FT_UINT32, BASE_DEC,
			VALS(names_open4_share_access), 0, "Share Access", HFILL }},

		{ &hf_nfs_open4_share_deny, {
			"share_deny", "nfs.open4.share_deny", FT_UINT32, BASE_DEC,
			VALS(names_open4_share_deny), 0, "Share Deny", HFILL }},

		{ &hf_nfs_seqid4, {
			"seqid", "nfs.seqid", FT_UINT32, BASE_HEX,
			NULL, 0, "Sequence ID", HFILL }},

		{ &hf_nfs_lock_seqid4, {
			"lock_seqid", "nfs.lock_seqid", FT_UINT32, BASE_HEX,
			NULL, 0, "Lock Sequence ID", HFILL }},

		{ &hf_nfs_mand_attr, {
			"mand_attr",	"nfs.attr", FT_UINT32, BASE_DEC,
			VALS(names_fattr4), 0, "Mandatory Attribute", HFILL }},

		{ &hf_nfs_recc_attr, {
			"recc_attr",	"nfs.attr", FT_UINT32, BASE_DEC,
			VALS(names_fattr4), 0, "Recommended Attribute", HFILL }},

		{ &hf_nfs_time_how4,	{
			"set_it", "nfs.set_it", FT_UINT32, BASE_DEC,
			VALS(names_time_how4), 0, "How To Set Time", HFILL }},

		{ &hf_nfs_attrlist4, {
			"attr_vals", "nfs.fattr4.attr_vals", FT_BYTES, BASE_DEC,
			NULL, 0, "attr_vals", HFILL }},

		{ &hf_nfs_fattr4_link_support, {
			"fattr4_link_support", "nfs.fattr4_link_support", FT_BOOLEAN,
			BASE_NONE, &yesno, 0, "nfs.fattr4_link_support", HFILL }},

		{ &hf_nfs_fattr4_symlink_support, {
			"fattr4_symlink_support", "nfs.fattr4_symlink_support", FT_BOOLEAN,
			BASE_NONE, &yesno, 0, "nfs.fattr4_symlink_support", HFILL }},

		{ &hf_nfs_fattr4_named_attr, {
			"fattr4_named_attr", "nfs.fattr4_named_attr", FT_BOOLEAN, BASE_NONE,
			&yesno, 0, "nfs.fattr4_named_attr", HFILL }},

		{ &hf_nfs_fattr4_unique_handles, {
			"fattr4_unique_handles", "nfs.fattr4_unique_handles", FT_BOOLEAN,
			BASE_NONE, &yesno, 0, "nfs.fattr4_unique_handles", HFILL }},

		{ &hf_nfs_fattr4_archive, {
			"fattr4_archive", "nfs.fattr4_archive", FT_BOOLEAN,
			BASE_NONE, &yesno, 0, "nfs.fattr4_archive", HFILL }},

		{ &hf_nfs_fattr4_cansettime, {
			"fattr4_cansettime", "nfs.fattr4_cansettime", FT_BOOLEAN,
			BASE_NONE, &yesno, 0, "nfs.fattr4_cansettime", HFILL }},

		{ &hf_nfs_fattr4_case_insensitive, {
			"fattr4_case_insensitive", "nfs.fattr4_case_insensitive", FT_BOOLEAN,
			BASE_NONE, &yesno, 0, "nfs.fattr4_case_insensitive", HFILL }},

		{ &hf_nfs_fattr4_case_preserving, {
			"fattr4_case_preserving", "nfs.fattr4_case_preserving", FT_BOOLEAN,
			BASE_NONE, &yesno, 0, "nfs.fattr4_case_preserving", HFILL }},

		{ &hf_nfs_fattr4_chown_restricted, {
			"fattr4_chown_restricted", "nfs.fattr4_chown_restricted", FT_BOOLEAN,
			BASE_NONE, &yesno, 0, "nfs.fattr4_chown_restricted", HFILL }},

		{ &hf_nfs_fattr4_hidden, {
			"fattr4_hidden", "nfs.fattr4_hidden", FT_BOOLEAN,
			BASE_NONE, &yesno, 0, "nfs.fattr4_hidden", HFILL }},

		{ &hf_nfs_fattr4_homogeneous, {
			"fattr4_homogeneous", "nfs.fattr4_homogeneous", FT_BOOLEAN,
			BASE_NONE, &yesno, 0, "nfs.fattr4_homogeneous", HFILL }},

		{ &hf_nfs_fattr4_mimetype, {
			"fattr4_mimetype", "nfs.fattr4_mimetype", FT_STRING, BASE_DEC,
			NULL, 0, "nfs.fattr4_mimetype", HFILL }},

		{ &hf_nfs_fattr4_no_trunc, {
			"fattr4_no_trunc", "nfs.fattr4_no_trunc", FT_BOOLEAN,
			BASE_NONE, &yesno, 0, "nfs.fattr4_no_trunc", HFILL }},

		{ &hf_nfs_fattr4_system, {
			"fattr4_system", "nfs.fattr4_system", FT_BOOLEAN,
			BASE_NONE, &yesno, 0, "nfs.fattr4_system", HFILL }},

		{ &hf_nfs_who, {
			"who", "nfs.who", FT_STRING, BASE_DEC,
			NULL, 0, "nfs.who", HFILL }},

		{ &hf_nfs_server, {
			"server", "nfs.server", FT_STRING, BASE_DEC,
			NULL, 0, "nfs.server", HFILL }},

		{ &hf_nfs_fattr4_owner, {
			"fattr4_owner", "nfs.fattr4_owner", FT_STRING, BASE_DEC,
			NULL, 0, "nfs.fattr4_owner", HFILL }},

		{ &hf_nfs_fattr4_owner_group, {
			"fattr4_owner_group", "nfs.fattr4_owner_group", FT_STRING, BASE_DEC,
			NULL, 0, "nfs.fattr4_owner_group", HFILL }},

		{ &hf_nfs_stable_how4, {
			"stable_how4", "nfs.stable_how4", FT_UINT32, BASE_DEC,
			VALS(names_stable_how4), 0, "nfs.stable_how4", HFILL }},

		{ &hf_nfs_dirlist4_eof, {
			"eof", "nfs.dirlist4.eof", FT_BOOLEAN,
			BASE_NONE, &yesno, 0, "nfs.dirlist4.eof", HFILL }},

		{ &hf_nfs_stateid4, {
			"stateid", "nfs.stateid4", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.stateid4", HFILL }},

		{ &hf_nfs_offset4, {
			"offset", "nfs.offset4", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.offset4", HFILL }},

		{ &hf_nfs_specdata1, {
			"specdata1", "nfs.specdata1", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.specdata1", HFILL }},

		{ &hf_nfs_specdata2, {
			"specdata2", "nfs.specdata2", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.specdata2", HFILL }},

		{ &hf_nfs_lock_type4, {
			"locktype", "nfs.locktype4", FT_UINT32, BASE_DEC,
			VALS(names_nfs_lock_type4), 0, "nfs.locktype4", HFILL }},

		{ &hf_nfs_reclaim4, {
			"reclaim", "nfs.reclaim4", FT_BOOLEAN,
			BASE_NONE, &yesno, 0, "Reclaim", HFILL }},

		{ &hf_nfs_length4, {
			"length", "nfs.length4", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.length4", HFILL }},

		{ &hf_nfs_changeid4, {
			"changeid", "nfs.changeid4", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.changeid4", HFILL }},

		{ &hf_nfs_changeid4_before, {
			"changeid (before)", "nfs.changeid4.before", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.changeid4.before", HFILL }},

		{ &hf_nfs_changeid4_after, {
			"changeid (after)", "nfs.changeid4.after", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.changeid4.after", HFILL }},

		{ &hf_nfs_nfstime4_seconds, {
			"seconds", "nfs.nfstime4.seconds", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.nfstime4.seconds", HFILL }},

		{ &hf_nfs_nfstime4_nseconds, {
			"nseconds", "nfs.nfstime4.nseconds", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.nfstime4.nseconds", HFILL }},

		{ &hf_nfs_fsid4_major, {
			"fsid4.major", "nfs.fsid4.major", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.nfstime4.fsid4.major", HFILL }},

		{ &hf_nfs_fsid4_minor, {
			"fsid4.minor", "nfs.fsid4.minor", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.fsid4.minor", HFILL }},

		{ &hf_nfs_acetype4, {
			"acetype", "nfs.acetype4", FT_UINT32, BASE_DEC,
			VALS(names_acetype4), 0, "nfs.acetype4", HFILL }},

		{ &hf_nfs_aceflag4, {
			"aceflag", "nfs.aceflag4", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.aceflag4", HFILL }},

		{ &hf_nfs_acemask4, {
			"acemask", "nfs.acemask4", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.acemask4", HFILL }},

		{ &hf_nfs_fattr4_size, {
			"size", "nfs.fattr4.size", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.fattr4.size", HFILL }},

		{ &hf_nfs_fattr4_lease_time, {
			"lease_time", "nfs.fattr4.lease_time", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.fattr4.lease_time", HFILL }},

		{ &hf_nfs_fattr4_aclsupport, {
			"aclsupport", "nfs.fattr4.aclsupport", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.fattr4.aclsupport", HFILL }},

		{ &hf_nfs_fattr4_fileid, {
			"fileid", "nfs.fattr4.fileid", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.fattr4.fileid", HFILL }},

		{ &hf_nfs_fattr4_files_avail, {
			"files_avail", "nfs.fattr4.files_avail", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.fattr4.files_avail", HFILL }},

		{ &hf_nfs_fattr4_files_free, {
			"files_free", "nfs.fattr4.files_free", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.fattr4.files_free", HFILL }},

		{ &hf_nfs_fattr4_files_total, {
			"files_total", "nfs.fattr4.files_total", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.fattr4.files_total", HFILL }},

		{ &hf_nfs_fattr4_maxfilesize, {
			"maxfilesize", "nfs.fattr4.maxfilesize", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.fattr4.maxfilesize", HFILL }},

		{ &hf_nfs_fattr4_maxlink, {
			"maxlink", "nfs.fattr4.maxlink", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.fattr4.maxlink", HFILL }},

		{ &hf_nfs_fattr4_maxname, {
			"maxname", "nfs.fattr4.maxname", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.fattr4.maxname", HFILL }},

		{ &hf_nfs_fattr4_numlinks, {
			"numlinks", "nfs.fattr4.numlinks", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.fattr4.numlinks", HFILL }},

		{ &hf_nfs_delegate_type, {
			"delegate_type", "nfs.delegate_type", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.delegate_type", HFILL }},

		{ &hf_nfs_secinfo_flavor, {
			"flavor", "nfs.secinfo.flavor", FT_UINT32, BASE_DEC,
			VALS(rpc_auth_flavor), 0, "nfs.secinfo.flavor", HFILL }},

		{ &hf_nfs_num_blocks, {
			"num_blocks", "nfs.num_blocks", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.num_blocks", HFILL }},

		{ &hf_nfs_bytes_per_block, {
			"bytes_per_block", "nfs.bytes_per_block", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.bytes_per_block", HFILL }},

		{ &hf_nfs_eof, {
			"eof", "nfs.eof", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.eof", HFILL }},

		{ &hf_nfs_fattr4_maxread, {
			"maxread", "nfs.fattr4.maxread", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.fattr4.maxread", HFILL }},

		{ &hf_nfs_fattr4_maxwrite, {
			"maxwrite", "nfs.fattr4.maxwrite", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.fattr4.maxwrite", HFILL }},

		{ &hf_nfs_fattr4_quota_hard, {
			"quota_hard", "nfs.fattr4.quota_hard", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.fattr4.quota_hard", HFILL }},

		{ &hf_nfs_fattr4_quota_soft, {
			"quota_soft", "nfs.fattr4.quota_soft", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.fattr4.quota_soft", HFILL }},

		{ &hf_nfs_fattr4_quota_used, {
			"quota_used", "nfs.fattr4.quota_used", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.fattr4.quota_used", HFILL }},

		{ &hf_nfs_fattr4_space_avail, {
			"space_avail", "nfs.fattr4.space_avail", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.fattr4.space_avail", HFILL }},

		{ &hf_nfs_fattr4_space_free, {
			"space_free", "nfs.fattr4.space_free", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.fattr4.space_free", HFILL }},

		{ &hf_nfs_fattr4_space_total, {
			"space_total", "nfs.fattr4.space_total", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.fattr4.space_total", HFILL }},

		{ &hf_nfs_fattr4_space_used, {
			"space_used", "nfs.fattr4.space_used", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.fattr4.space_used", HFILL }},

		{ &hf_nfs_stateid4_delegate_stateid, {
			"delegate_stateid", "nfs.delegate_stateid", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.delegate_stateid", HFILL }},

		{ &hf_nfs_verifier4, {
			"verifier", "nfs.verifier4", FT_UINT64, BASE_HEX,
			NULL, 0, "nfs.verifier4", HFILL }},

		{ &hf_nfs_cookie4, {
			"cookie", "nfs.cookie4", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.cookie4", HFILL }},

		{ &hf_nfs_cookieverf4, {
			"cookieverf", "nfs.cookieverf4", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.cookieverf4", HFILL }},

		{ &hf_nfs_cb_location, {
			"cb_location", "nfs.cb_location", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.cb_location", HFILL }},

		{ &hf_nfs_cb_program, {
			"cb_program", "nfs.cb_program", FT_UINT32, BASE_HEX,
			NULL, 0, "nfs.cb_program", HFILL }},

		{ &hf_nfs_recall4, {
			"recall", "nfs.recall4", FT_BOOLEAN,
			BASE_NONE, &yesno, 0, "nfs.recall4", HFILL }},

		{ &hf_nfs_filesize, {
			"filesize", "nfs.filesize", FT_UINT64, BASE_DEC,
			NULL, 0, "nfs.filesize", HFILL }},

		{ &hf_nfs_count4, {
			"count", "nfs.count4", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.count4", HFILL }},

		{ &hf_nfs_count4_dircount, {
			"dircount", "nfs.dircount", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.dircount", HFILL }},

		{ &hf_nfs_count4_maxcount, {
			"maxcount", "nfs.maxcount", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.maxcount", HFILL }},

		{ &hf_nfs_minorversion, {
			"minorversion", "nfs.minorversion", FT_UINT32, BASE_DEC,
			NULL, 0, "nfs.minorversion", HFILL }},

		{ &hf_nfs_atime, {
			"atime", "nfs.atime", FT_ABSOLUTE_TIME, BASE_NONE,
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
			"mtime", "nfs.mtime", FT_ABSOLUTE_TIME, BASE_NONE,
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
			"ctime", "nfs.ctime", FT_ABSOLUTE_TIME, BASE_NONE,
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
			NULL, 0, "Time Delta", HFILL }},

		{ &hf_nfs_dtime_sec, {
			"seconds", "nfs.dtime.sec", FT_UINT32, BASE_DEC,
			NULL, 0, "Time Delta, Seconds", HFILL }},

		{ &hf_nfs_dtime_nsec, {
			"nano seconds", "nfs.dtime.nsec", FT_UINT32, BASE_DEC,
			NULL, 0, "Time Delta, Nano-seconds", HFILL }},

		{ &hf_nfs_open_owner4, {
			"owner", "nfs.open_owner4", FT_BYTES, BASE_DEC,
			NULL, 0, "owner", HFILL }},

		{ &hf_nfs_lock_owner4, {
			"owner", "nfs.lock_owner4", FT_BYTES, BASE_DEC,
			NULL, 0, "owner", HFILL }},

		{ &hf_nfs_secinfo_rpcsec_gss_info_service, {
			"service", "nfs.secinfo.rpcsec_gss_info.service", FT_UINT32,
			BASE_DEC, VALS(rpc_authgss_svc), 0, "service", HFILL }},

		{ &hf_nfs_attrdircreate, {
			"attribute dir create", "nfs.openattr4.createdir", FT_BOOLEAN,
			BASE_NONE, &yesno, 0, "nfs.openattr4.createdir", HFILL }},

		{ &hf_nfs_new_lock_owner, {
			"new lock owner?", "nfs.lock.locker.new_lock_owner", FT_BOOLEAN,
			BASE_NONE, &yesno, 0, "nfs.lock.locker.new_lock_owner", HFILL }},

		{ &hf_nfs_lock4_reclaim, {
			"reclaim?", "nfs.lock.reclaim", FT_BOOLEAN,
			BASE_NONE, &yesno, 0, "nfs.lock.reclaim", HFILL }},

		{ &hf_nfs_sec_oid4, {
			"oid", "nfs.secinfo.flavor_info.rpcsec_gss_info.oid", FT_BYTES,
			BASE_DEC, NULL, 0, "oid", HFILL }},

		{ &hf_nfs_qop4, {
			"qop", "nfs.secinfo.flavor_info.rpcsec_gss_info.qop", FT_UINT32,
			BASE_DEC, NULL, 0, "qop", HFILL }},

		{ &hf_nfs_client_id4_id, {
			"id", "nfs.nfs_client_id4.id", FT_BYTES, BASE_DEC,
			NULL, 0, "nfs.nfs_client_id4.id", HFILL }},

		{ &hf_nfs_stateid4_other, {
			"Data", "nfs.stateid4.other", FT_BYTES, BASE_DEC,
			NULL, 0, "Data", HFILL }},

		{ &hf_nfs_acl4, {
			"ACL", "nfs.acl", FT_NONE, BASE_NONE,
			NULL, 0, "Access Control List", HFILL }},

		{ &hf_nfs_callback_ident, {
			"callback_ident", "nfs.callback.ident", FT_UINT32, BASE_HEX,
			NULL, 0, "Callback Identifier", HFILL }},

		{ &hf_nfs_r_netid, {
			"r_netid", "nfs.r_netid", FT_BYTES, BASE_DEC, NULL, 0,
			"r_netid", HFILL }},

		{ &hf_nfs_r_addr, {
			"r_addr", "nfs.r_addr", FT_BYTES, BASE_DEC, NULL, 0,
			"r_addr", HFILL }},

		{ &hf_nfs_secinfo_arr4, {
			"Flavors Info", "nfs.flavors.info", FT_NONE, BASE_NONE,
			NULL, 0, "Flavors Info", HFILL }},

	/* Hidden field for v2, v3, and v4 status */
		{ &hf_nfs_nfsstat, {
			"Status", "nfs.status", FT_UINT32, BASE_DEC,
			VALS(names_nfs_nfsstat), 0, "Reply status", HFILL }},
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
		&ett_nfs_mode,
		&ett_nfs_fattr,
		&ett_nfs_sattr,
		&ett_nfs_diropargs,
		&ett_nfs_readdir_entry,
		&ett_nfs_mode3,
		&ett_nfs_specdata3,
		&ett_nfs_fh3,
		&ett_nfs_nfstime3,
		&ett_nfs_fattr3,
		&ett_nfs_post_op_fh3,
		&ett_nfs_sattr3,
		&ett_nfs_diropargs3,
		&ett_nfs_sattrguard3,
		&ett_nfs_set_mode3,
		&ett_nfs_set_uid3,
		&ett_nfs_set_gid3,
		&ett_nfs_set_size3,
		&ett_nfs_set_atime,
		&ett_nfs_set_mtime,
		&ett_nfs_pre_op_attr,
		&ett_nfs_post_op_attr,
		&ett_nfs_wcc_attr,
		&ett_nfs_wcc_data,
		&ett_nfs_access,
		&ett_nfs_fsinfo_properties,
		&ett_nfs_compound_call4,
		&ett_nfs_utf8string,
		&ett_nfs_argop4,
		&ett_nfs_resop4,
		&ett_nfs_access4,
		&ett_nfs_close4,
		&ett_nfs_commit4,
		&ett_nfs_create4,
		&ett_nfs_delegpurge4,
		&ett_nfs_delegreturn4,
		&ett_nfs_getattr4,
		&ett_nfs_getfh4,
		&ett_nfs_link4,
		&ett_nfs_lock4,
		&ett_nfs_lockt4,
		&ett_nfs_locku4,
		&ett_nfs_lookup4,
		&ett_nfs_lookupp4,
		&ett_nfs_nverify4,
		&ett_nfs_open4,
		&ett_nfs_openattr4,
		&ett_nfs_open_confirm4,
		&ett_nfs_open_downgrade4,
		&ett_nfs_putfh4,
		&ett_nfs_putpubfh4,
		&ett_nfs_putrootfh4,
		&ett_nfs_read4,
		&ett_nfs_readdir4,
		&ett_nfs_readlink4,
		&ett_nfs_remove4,
		&ett_nfs_rename4,
		&ett_nfs_renew4,
		&ett_nfs_restorefh4,
		&ett_nfs_savefh4,
		&ett_nfs_setattr4,
		&ett_nfs_setclientid4,
		&ett_nfs_setclientid_confirm4,
		&ett_nfs_verify4,
		&ett_nfs_write4,
		&ett_nfs_release_lockowner4,
		&ett_nfs_illegal4,
		&ett_nfs_verifier4,
		&ett_nfs_opaque,
		&ett_nfs_dirlist4,
		&ett_nfs_pathname4,
		&ett_nfs_change_info4,
		&ett_nfs_open_delegation4,
		&ett_nfs_open_claim4,
		&ett_nfs_opentype4,
		&ett_nfs_lock_owner4,
		&ett_nfs_cb_client4,
		&ett_nfs_client_id4,
		&ett_nfs_bitmap4,
		&ett_nfs_fattr4,
		&ett_nfs_fsid4,
		&ett_nfs_fs_locations4,
		&ett_nfs_fs_location4,
		&ett_nfs_open4_result_flags,
		&ett_nfs_secinfo4,
		&ett_nfs_secinfo4_flavor_info,
		&ett_nfs_stateid4,
		&ett_nfs_fattr4_fh_expire_type,
		&ett_nfs_ace4,
		&ett_nfs_clientaddr4,
		&ett_nfs_aceflag4,
		&ett_nfs_acemask4,
	};
	module_t *nfs_module;

	proto_nfs = proto_register_protocol("Network File System", "NFS", "nfs");
	proto_register_field_array(proto_nfs, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	nfs_module=prefs_register_protocol(proto_nfs, NULL);
	prefs_register_bool_preference(nfs_module, "file_name_snooping",
				       "Snoop FH to filename mappings",
				       "Whether the dissector should snoop the FH to filename mappings by looking inside certain packets",
				       &nfs_file_name_snooping);
	prefs_register_bool_preference(nfs_module, "file_full_name_snooping",
				       "Snoop full path to filenames",
				       "Whether the dissector should snoop the full pathname for files for matching FH's",
				       &nfs_file_name_full_snooping);
	prefs_register_bool_preference(nfs_module, "fhandle_find_both_reqrep",
				       "Fhandle filters finds both request/response",
				       "With this option display filters for nfs fhandles (nfs.fh.{name|full_name|hash}) will find both the request and response packets for a RPC call, even if the actual fhandle is only present in one of the packets",
					&nfs_fhandle_reqrep_matching);
	nfs_name_snoop_known=se_tree_create(SE_TREE_TYPE_RED_BLACK, "nfs_name_snoop_known");
	nfs_file_handles=se_tree_create(SE_TREE_TYPE_RED_BLACK, "nfs_file_handles");
	nfs_fhandle_frame_table=se_tree_create(SE_TREE_TYPE_RED_BLACK, "nfs_fhandle_frame_table");
	register_init_routine(nfs_name_snoop_init);
}

void
proto_reg_handoff_nfs(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_nfs, NFS_PROGRAM, ett_nfs);
	/* Register the procedure tables */
	rpc_init_proc_table(NFS_PROGRAM, 2, nfs2_proc, hf_nfs_procedure_v2);
	rpc_init_proc_table(NFS_PROGRAM, 3, nfs3_proc, hf_nfs_procedure_v3);
	rpc_init_proc_table(NFS_PROGRAM, 4, nfs4_proc, hf_nfs_procedure_v4);
}
