/* packet-nfs.c
 * Routines for nfs dissection
 * Copyright 1999, Uwe Girlich <Uwe.Girlich@philosys.de>
 * Copyright 2000, Mike Frisch <frisch@hummingbird.com> (NFSv4 decoding)
 *
 * $Id: packet-nfs.c,v 1.45 2001/02/09 18:26:04 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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


#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>


#include "packet-rpc.h"
#include "packet-nfs.h"


static int proto_nfs = -1;

static int hf_nfs_fh_fsid_major = -1;
static int hf_nfs_fh_fsid_minor = -1;
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
static int hf_nfs_stat = -1;
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
static int hf_nfs_readdirplus_entry_name = -1;
static int hf_nfs_readdir_entry_cookie = -1;
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
static int hf_nfs_fsinfo_properties = -1;
static int hf_nfs_pathconf_linkmax = -1;
static int hf_nfs_pathconf_name_max = -1;
static int hf_nfs_pathconf_no_trunc = -1;
static int hf_nfs_pathconf_chown_restricted = -1;
static int hf_nfs_pathconf_case_insensitive = -1;
static int hf_nfs_pathconf_case_preserving = -1;

/* NFSv4 */
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
static int hf_nfs_open4_result_flags = -1;
static int hf_nfs_seqid4 = -1;
static int hf_nfs_attr = -1;
static int hf_nfs_time_how4 = -1;
static int hf_nfs_attrlist4 = -1;
static int hf_nfs_fattr4_expire_type = -1;
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
static int hf_nfs_who = -1;
static int hf_nfs_server = -1;
static int hf_nfs_fattr4_owner = -1;
static int hf_nfs_fattr4_owner_group = -1;

static gint ett_nfs = -1;
static gint ett_nfs_fh_fsid = -1;
static gint ett_nfs_fh_xfsid = -1;
static gint ett_nfs_fh_fn = -1;
static gint ett_nfs_fh_xfn = -1;
static gint ett_nfs_fh_hp = -1;
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
static gint ett_nfs_verifier4 = -1;
static gint ett_nfs_opaque = -1;
static gint ett_nfs_dirlist4 = -1;
static gint ett_nfs_pathname4 = -1;
static gint ett_nfs_change_info4 = -1;
static gint ett_nfs_open_delegation4 = -1;
static gint ett_nfs_open_claim4 = -1;
static gint ett_nfs_opentype4 = -1;
static gint ett_nfs_lockowner4 = -1;
static gint ett_nfs_cb_client4 = -1;
static gint ett_nfs_client_id4 = -1;
static gint ett_nfs_bitmap4 = -1;
static gint ett_nfs_fattr4 = -1;
static gint ett_nfs_fsid4 = -1;
static gint ett_nfs_fs_locations4 = -1;
static gint ett_nfs_fs_location4 = -1;

/* file handle dissection */

#define FHT_UNKNOWN	0
#define FHT_SVR4	1
#define FHT_LINUX_KNFSD_LE	2
#define FHT_LINUX_NFSD_LE	3

const value_string names_fhtype[] =
{
	{	FHT_UNKNOWN,	"unknown"	},
	{	FHT_SVR4,	"System V R4"	},
	{	FHT_LINUX_KNFSD_LE,	"Linux knfsd (little-endian)"	},
	{	FHT_LINUX_NFSD_LE,	"Linux user-land nfsd (little-endian)"	},
	{		0,	NULL		}
};


/* SVR4: checked with ReliantUNIX (5.43, 5.44, 5.45) */

static void
dissect_fhandle_data_SVR4(tvbuff_t* tvb, int offset, proto_tree *tree,
    int fhlen)
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
    int fhlen)
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

void
dissect_fhandle_data_LINUX_NFSD_LE(tvbuff_t* tvb, int offset, proto_tree *tree,
    int fhlen)
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


static void
dissect_fhandle_data_unknown(tvbuff_t *tvb, int offset, proto_tree *tree,
    int fhlen)
{
	int sublen;
	int bytes_left;
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
    proto_tree *tree, int fhlen)
{
	int fhtype = FHT_UNKNOWN;

	/* filehandle too long */
	if (fhlen>64) goto type_ready;
	/* Not all bytes there. Any attempt to deduce the type would be
	   senseless. */
	if (!tvb_bytes_exist(tvb,offset,fhlen)) goto type_ready;
		
	/* calculate (heuristically) fhtype */
	switch (fhlen) {
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

type_ready:

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
		case FHT_UNKNOWN:
		default:
			dissect_fhandle_data_unknown(tvb, offset, tree, fhlen);
		break;
	}
}


/***************************/
/* NFS Version 2, RFC 1094 */
/***************************/


/* base 32 bit type for NFS v2 */
int
dissect_unsigned_int(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
char* name)
{
	offset = dissect_rpc_uint32(pd,offset,fd,tree,name);
	return offset;
}


/* RFC 1094, Page 12..14 */
const value_string names_nfs_stat[] =
{
	{	0,	"OK" },
	{	1,	"ERR_PERM" },
	{	2,	"ERR_NOENT" },
	{	5,	"ERR_IO" },
	{	6,	"ERR_NX_IO" },
	{	13,	"ERR_ACCES" },
	{	17,	"ERR_EXIST" },
	{	18,	"ERR_XDEV" },	/* not in spec, but can happen */
	{	19,	"ERR_NODEV" },
	{	20,	"ERR_NOTDIR" },
	{	21,	"ERR_ISDIR" },
	{	22,	"ERR_INVAL" },	/* not in spec, but I think it can happen */
	{	26,	"ERR_TXTBSY" },	/* not in spec, but I think it can happen */
	{	27,	"ERR_FBIG" },
	{	28,	"ERR_NOSPC" },
	{	30,	"ERR_ROFS" },
	{	31,	"ERR_MLINK" },	/* not in spec, but can happen */
	{	45,	"ERR_OPNOTSUPP" }, /* not in spec, but I think it can happen */
	{	63,	"ERR_NAMETOOLONG" },
	{	66,	"ERR_NOTEMPTY" },
	{	69,	"ERR_DQUOT" },
	{	70,	"ERR_STALE" },
	{	99,	"ERR_WFLUSH" },
	{	0,	NULL }
};

/* NFSv4 Draft Specification, Page 198-199 */
const value_string names_nfs_stat4[] = {
	{	0,			"NFS4_OK"							},
	{	1,			"NFS4ERR_PERM"						},
	{	2,			"NFS4ERR_NOENT"					},
	{	5,			"NFS4ERR_IO"						},
	{	6,			"NFS4ERR_NXIO"						},
	{	13,		"NFS4ERR_ACCES"					},
	{	17,		"NFS4ERR_EXIST"					},
	{	18,		"NFS4ERR_XDEV"						},
	{	19,		"NFS4ERR_NODEV"					},
	{	20,		"NFS4ERR_NOTDIR"					},
	{	21,		"NFS4ERR_ISDIR"					},
	{	22,		"NFS4ERR_INVAL"					},
	{	27,		"NFS4ERR_FBIG"						},
	{	28,		"NFS4ERR_NOSPC"					},
	{	30,		"NFS4ERR_ROFS"						},
	{	31,		"NFS4ERR_MLINK"					},
	{	63,		"NFS4ERR_NAMETOOLONG"			},
	{	66,		"NFS4ERR_NOTEMPTY"				},
	{	69,		"NFS4ERR_DQUOT"					},
	{	70,		"NFS4ERR_STALE"					},
	{	10001,	"NFS4ERR_BADHANDLE"				},
	{	10003,	"NFS4ERR_BAD_COOKIE"				},
	{	10004,	"NFS4ERR_NOTSUPP"					},
	{	10005,	"NFS4ERR_TOOSMALL"				},
	{	10006,	"NFS4ERR_SERVERFAULT"			},
	{	10007,	"NFS4ERR_BADTYPE"					},
	{	10008,	"NFS4ERR_DELAY"					},
	{	10009,	"NFS4ERR_SAME"						},
	{	10010,	"NFS4ERR_DENIED"					},
	{	10011,	"NFS4ERR_EXPIRED"					},
	{	10012,	"NFS4ERR_LOCKED"					},
	{	10013,	"NFS4ERR_GRACE"					},
	{	10014,	"NFS4ERR_FHEXPIRED"				},
	{	10015,	"NFS4ERR_SHARE_DENIED"			},
	{	10016,	"NFS4ERR_WRONGSEC"				},
	{	10017,	"NFS4ERR_CLID_INUSE"				},
	{	10018,	"NFS4ERR_RESOURCE"				},
	{	10019,	"NFS4ERR_MOVED"					},
	{	10020,	"NFS4ERR_NOFILEHANDLE"			},
	{	10021,	"NFS4ERR_MINOR_VERS_MISMATCH"	},
	{	10022,	"NFS4ERR_STALE_CLIENTID"		},
	{	10023,	"NFS4ERR_STALE_STATEID"			},
	{	10024,	"NFS4ERR_OLD_STATEID"			},
	{	10025,	"NFS4ERR_BAD_STATEID"			},
	{	10026,	"NFS4ERR_BAD_SEQID"				},
	{	10027,	"NFS4ERR_NOT_SAME"				},
	{	10028,	"NFS4ERR_LOCK_RANGE"				},
	{	10029,	"NFS4ERR_SYMLINK"					},
	{	10030,	"NFS4ERR_READDIR_NOSPC"			},
	{	10031,	"NFS4ERR_LEASE_MOVED"			},
	{ 0, NULL }
};


/* This function has been modified to support NFSv4 style error codes as
 * well as being backwards compatible with NFSv2 and NFSv3.
 */
int
dissect_stat_internal(const u_char *pd, int offset, frame_data *fd, 
	proto_tree *tree, guint32* status, int nfsvers)
{
	guint32 stat;

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	stat = EXTRACT_UINT(pd, offset+0);
	
	if (tree) {
		/* this gives the right NFSv2 number<->message relation */
		/* and makes it searchable via "nfs.status" */
		proto_tree_add_uint_format(tree, hf_nfs_nfsstat3, NullTVB,
			offset+0, 4, stat, "Status: %s (%u)", 
			val_to_str(stat, 
				(nfsvers != 4)? names_nfs_stat: names_nfs_stat4,"%u"), stat);
	}

	offset += 4;
	*status = stat;
	return offset;
}


/* RFC 1094, Page 12..14 */
int
dissect_stat(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
	guint32 *status)
{
	return dissect_stat_internal(pd, offset, fd, tree, status, !4);
}


/* RFC 1094, Page 12..14 */
int
dissect_nfs2_stat_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	guint32 status;

	offset = dissect_stat(pd, offset, fd, tree, &status);

	return offset;
}


int
dissect_nfs_nfsstat4(const u_char *pd, int offset, frame_data *fd, 
	proto_tree *tree, guint32 *status)
{
	return dissect_stat_internal(pd, offset, fd, tree, status, 4);
}


/* RFC 1094, Page 15 */
int
dissect_ftype(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
char* name)
{
	guint32 ftype;
	char* ftype_name = NULL;

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

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	ftype = EXTRACT_UINT(pd, offset+0);
	ftype_name = val_to_str(ftype, nfs2_ftype, "%u");
	
	if (tree) {
		proto_tree_add_text(tree, NullTVB, offset, 4,
			"%s: %s (%u)", name, ftype_name, ftype);
	}

	offset += 4;
	return offset;
}


/* RFC 1094, Page 15 */
int
old_dissect_fhandle(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name)
{
	tvbuff_t *tvb = tvb_create_from_top(offset);

	offset = dissect_fhandle(tvb, 0, &pi, tree, name);
	return tvb_raw_offset(tvb) + offset;
}

int
dissect_fhandle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree,
    char *name)
{
	proto_item* fitem;
	proto_tree* ftree = NULL;

	if (tree) {
		fitem = proto_tree_add_text(tree, tvb, offset, FHSIZE,
			"%s", name);
		if (fitem)
			ftree = proto_item_add_subtree(fitem, ett_nfs_fhandle);
	}

	if (ftree)
		dissect_fhandle_data(tvb, offset, pinfo, ftree, FHSIZE);

	offset += FHSIZE;
	return offset;
}

/* RFC 1094, Page 15 */
int
dissect_nfs2_fhandle_call(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	offset = old_dissect_fhandle(pd, offset, fd, tree, "object");

	return offset;
}


/* RFC 1094, Page 15 */
int
dissect_timeval(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name)
{
	guint32	seconds;
	guint32 mseconds;

	proto_item* time_item;
	proto_tree* time_tree = NULL;

	if (!BYTES_ARE_IN_FRAME(offset,8)) return offset;
	seconds = EXTRACT_UINT(pd, offset+0);
	mseconds = EXTRACT_UINT(pd, offset+4);
	
	if (tree) {
		time_item = proto_tree_add_text(tree, NullTVB, offset, 8,
			"%s: %u.%06u", name, seconds, mseconds);
		if (time_item)
			time_tree = proto_item_add_subtree(time_item, ett_nfs_timeval);
	}

	if (time_tree) {
		proto_tree_add_text(time_tree, NullTVB,offset+0,4,
					"seconds: %u", seconds);
		proto_tree_add_text(time_tree, NullTVB,offset+4,4,
					"micro seconds: %u", mseconds);
	}
	offset += 8;
	return offset;
}


/* RFC 1094, Page 16 */
const value_string nfs2_mode_names[] = {
	{	0040000,	"Directory"	},
	{	0020000,	"Character Special Device"	},
	{	0060000,	"Block Special Device"	},
	{	0100000,	"Regular File"	},
	{	0120000,	"Symbolic Link"	},
	{	0140000,	"Named Socket"	},
	{	0000000,	NULL		},
};

int
dissect_mode(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
char* name)
{
	guint32 mode;
	proto_item* mode_item = NULL;
	proto_tree* mode_tree = NULL;

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	mode = EXTRACT_UINT(pd, offset+0);
	
	if (tree) {
		mode_item = proto_tree_add_text(tree, NullTVB, offset, 4,
			"%s: 0%o", name, mode);
		if (mode_item)
			mode_tree = proto_item_add_subtree(mode_item, ett_nfs_mode);
	}

	if (mode_tree) {
		proto_tree_add_text(mode_tree, NullTVB, offset, 4, "%s",
			decode_enumerated_bitfield(mode,  0160000, 16,
			nfs2_mode_names, "%s"));
		proto_tree_add_text(mode_tree, NullTVB, offset, 4, "%s",
		decode_boolean_bitfield(mode,   04000, 16, "Set user id on exec", "not SUID"));
		proto_tree_add_text(mode_tree, NullTVB, offset, 4, "%s",
		decode_boolean_bitfield(mode,   02000, 16, "Set group id on exec", "not SGID"));
		proto_tree_add_text(mode_tree, NullTVB, offset, 4, "%s",
		decode_boolean_bitfield(mode,   01000, 16, "Save swapped text even after use", "not save swapped text"));
		proto_tree_add_text(mode_tree, NullTVB, offset, 4, "%s",
		decode_boolean_bitfield(mode,    0400, 16, "Read permission for owner", "no Read permission for owner"));
		proto_tree_add_text(mode_tree, NullTVB, offset, 4, "%s",
		decode_boolean_bitfield(mode,    0200, 16, "Write permission for owner", "no Write permission for owner"));
		proto_tree_add_text(mode_tree, NullTVB, offset, 4, "%s",
		decode_boolean_bitfield(mode,    0100, 16, "Execute permission for owner", "no Execute permission for owner"));
		proto_tree_add_text(mode_tree, NullTVB, offset, 4, "%s",
		decode_boolean_bitfield(mode,     040, 16, "Read permission for group", "no Read permission for group"));
		proto_tree_add_text(mode_tree, NullTVB, offset, 4, "%s",
		decode_boolean_bitfield(mode,     020, 16, "Write permission for group", "no Write permission for group"));
		proto_tree_add_text(mode_tree, NullTVB, offset, 4, "%s",
		decode_boolean_bitfield(mode,     010, 16, "Execute permission for group", "no Execute permission for group"));
		proto_tree_add_text(mode_tree, NullTVB, offset, 4, "%s",
		decode_boolean_bitfield(mode,      04, 16, "Read permission for others", "no Read permission for others"));
		proto_tree_add_text(mode_tree, NullTVB, offset, 4, "%s",
		decode_boolean_bitfield(mode,      02, 16, "Write permission for others", "no Write permission for others"));
		proto_tree_add_text(mode_tree, NullTVB, offset, 4, "%s",
		decode_boolean_bitfield(mode,      01, 16, "Execute permission for others", "no Execute permission for others"));
	}

	offset += 4;
	return offset;
}


/* RFC 1094, Page 15 */
int
dissect_fattr(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name)
{
	proto_item* fattr_item = NULL;
	proto_tree* fattr_tree = NULL;
	int old_offset = offset;

	if (tree) {
		fattr_item = proto_tree_add_text(tree, NullTVB, offset,
			END_OF_FRAME, "%s", name);
		if (fattr_item)
			fattr_tree = proto_item_add_subtree(fattr_item, ett_nfs_fattr);
	}

	offset = dissect_ftype        (pd,offset,fd,fattr_tree,"type");
	offset = dissect_mode         (pd,offset,fd,fattr_tree,"mode");
	offset = dissect_unsigned_int (pd,offset,fd,fattr_tree,"nlink");
	offset = dissect_unsigned_int (pd,offset,fd,fattr_tree,"uid");
	offset = dissect_unsigned_int (pd,offset,fd,fattr_tree,"gid");
	offset = dissect_unsigned_int (pd,offset,fd,fattr_tree,"size");
	offset = dissect_unsigned_int (pd,offset,fd,fattr_tree,"blocksize");
	offset = dissect_unsigned_int (pd,offset,fd,fattr_tree,"rdev");
	offset = dissect_unsigned_int (pd,offset,fd,fattr_tree,"blocks");
	offset = dissect_unsigned_int (pd,offset,fd,fattr_tree,"fsid");
	offset = dissect_unsigned_int (pd,offset,fd,fattr_tree,"fileid");
	offset = dissect_timeval      (pd,offset,fd,fattr_tree,"atime");
	offset = dissect_timeval      (pd,offset,fd,fattr_tree,"mtime");
	offset = dissect_timeval      (pd,offset,fd,fattr_tree,"ctime");

	/* now we know, that fattr is shorter */
	if (fattr_item) {
		proto_item_set_len(fattr_item, offset - old_offset);
	}

	return offset;
}


/* RFC 1094, Page 17 */
int
dissect_sattr(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name)
{
	proto_item* sattr_item = NULL;
	proto_tree* sattr_tree = NULL;
	int old_offset = offset;

	if (tree) {
		sattr_item = proto_tree_add_text(tree, NullTVB, offset,
			END_OF_FRAME, "%s", name);
		if (sattr_item)
			sattr_tree = proto_item_add_subtree(sattr_item, ett_nfs_sattr);
	}

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	if (EXTRACT_UINT(pd, offset+0) != 0xffffffff)
		offset = dissect_mode         (pd,offset,fd,sattr_tree,"mode");
	else {
		proto_tree_add_text(sattr_tree, NullTVB, offset, 4, "mode: no value");
		offset += 4;
	}

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	if (EXTRACT_UINT(pd, offset+0) != 0xffffffff)
		offset = dissect_unsigned_int (pd,offset,fd,sattr_tree,"uid");
	else {
		proto_tree_add_text(sattr_tree, NullTVB, offset, 4, "uid: no value");
		offset += 4;
	}

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	if (EXTRACT_UINT(pd, offset+0) != 0xffffffff)
		offset = dissect_unsigned_int (pd,offset,fd,sattr_tree,"gid");
	else {
		proto_tree_add_text(sattr_tree, NullTVB, offset, 4, "gid: no value");
		offset += 4;
	}

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	if (EXTRACT_UINT(pd, offset+0) != 0xffffffff)
		offset = dissect_unsigned_int (pd,offset,fd,sattr_tree,"size");
	else {
		proto_tree_add_text(sattr_tree, NullTVB, offset, 4, "size: no value");
		offset += 4;
	}

	if (!BYTES_ARE_IN_FRAME(offset,8)) return offset;
	if (EXTRACT_UINT(pd, offset+0) != 0xffffffff)
		offset = dissect_timeval      (pd,offset,fd,sattr_tree,"atime");
	else {
		proto_tree_add_text(sattr_tree, NullTVB, offset, 8, "atime: no value");
		offset += 8;
	}

	if (!BYTES_ARE_IN_FRAME(offset,8)) return offset;
	if (EXTRACT_UINT(pd, offset+0) != 0xffffffff)
		offset = dissect_timeval      (pd,offset,fd,sattr_tree,"mtime");
	else {
		proto_tree_add_text(sattr_tree, NullTVB, offset, 8, "mtime: no value");
		offset += 8;
	}

	/* now we know, that sattr is shorter */
	if (sattr_item) {
		proto_item_set_len(sattr_item, offset - old_offset);
	}

	return offset;
}


/* RFC 1094, Page 17 */
int
dissect_filename(const u_char *pd, int offset, frame_data *fd,
    proto_tree *tree, int hf, char **string_ret)
{
	offset = dissect_rpc_string(pd,offset,fd,tree,hf,string_ret);
	return offset;
}


/* RFC 1094, Page 17 */
int
dissect_path(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int hf)
{
	offset = dissect_rpc_string(pd,offset,fd,tree,hf,NULL);
	return offset;
}


/* RFC 1094, Page 17,18 */
int
dissect_attrstat(const u_char *pd, int offset, frame_data *fd, proto_tree *tree){
	guint32 status;

	offset = dissect_stat(pd, offset, fd, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_fattr(pd, offset, fd, tree, "attributes");
		break;
		default:
			/* do nothing */
		break;
	}

	return offset;
}


/* RFC 1094, Page 17,18 */
int
dissect_nfs2_attrstat_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	offset = dissect_attrstat(pd, offset, fd, tree);

	return offset;
}


/* RFC 1094, Page 18 */
int
dissect_diropargs(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name)
{
	proto_item* diropargs_item = NULL;
	proto_tree* diropargs_tree = NULL;
	int old_offset = offset;

	if (tree) {
		diropargs_item = proto_tree_add_text(tree, NullTVB, offset,
			END_OF_FRAME, "%s", name);
		if (diropargs_item)
			diropargs_tree = proto_item_add_subtree(diropargs_item, ett_nfs_diropargs);
	}

	offset = old_dissect_fhandle (pd,offset,fd,diropargs_tree,"dir");
	offset = dissect_filename(pd,offset,fd,diropargs_tree,hf_nfs_name,NULL);

	/* now we know, that diropargs is shorter */
	if (diropargs_item) {
		proto_item_set_len(diropargs_item, offset - old_offset);
	}

	return offset;
}


/* RFC 1094, Page 18 */
int
dissect_nfs2_diropargs_call(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	offset = dissect_diropargs(pd, offset, fd, tree, "where");

	return offset;
}


/* RFC 1094, Page 18 */
int
dissect_diropres(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	guint32	status;

	offset = dissect_stat(pd, offset, fd, tree, &status);
	switch (status) {
		case 0:
			offset = old_dissect_fhandle(pd, offset, fd, tree, "file");
			offset = dissect_fattr  (pd, offset, fd, tree, "attributes");
		break;
		default:
			/* do nothing */
		break;
	}

	return offset;
}


/* nfsdata is simply a RPC string (length, data, fill bytes) */
int
dissect_nfsdata(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
int hf)
{
	offset = dissect_rpc_data(pd,offset,fd,tree,hf);

	return offset;
}


/* RFC 1094, Page 18 */
int
dissect_nfs2_diropres_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	offset = dissect_diropres(pd, offset, fd, tree);

	return offset;
}


/* RFC 1094, Page 6 */
int
dissect_nfs2_setattr_call(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	offset = old_dissect_fhandle(pd, offset, fd, tree, "file"      );
	offset = dissect_sattr  (pd, offset, fd, tree, "attributes");

	return offset;
}


/* RFC 1094, Page 6 */
int
dissect_nfs2_readlink_reply(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	guint32	status;

	offset = dissect_stat(pd, offset, fd, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_path(pd, offset, fd, tree, hf_nfs_readlink_data);
		break;
		default:
			/* do nothing */
		break;
	}

	return offset;
}


/* RFC 1094, Page 7 */
int
dissect_nfs2_read_call(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	guint32 offset_value;
	guint32 count;
	guint32 totalcount;

	offset = old_dissect_fhandle(pd, offset, fd, tree, "file"      );
	if (!BYTES_ARE_IN_FRAME(offset,12)) return offset;
	offset_value = EXTRACT_UINT(pd, offset+0);
	count        = EXTRACT_UINT(pd, offset+4);
	totalcount   = EXTRACT_UINT(pd, offset+8);
	if (tree) {
		proto_tree_add_uint(tree, hf_nfs_read_offset, NullTVB, 
		offset+0, 4, offset_value);
		proto_tree_add_uint(tree, hf_nfs_read_count, NullTVB, 
		offset+4, 4, count);
		proto_tree_add_uint(tree, hf_nfs_read_totalcount, NullTVB, 
		offset+8, 4, totalcount);
	}
	offset += 12;

	return offset;
}


/* RFC 1094, Page 7 */
int
dissect_nfs2_read_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	guint32 status;

	offset = dissect_stat(pd, offset, fd, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_fattr(pd, offset, fd, tree, "attributes");
			offset = dissect_nfsdata(pd, offset, fd, tree, hf_nfs_data); 
		break;
		default:
			/* do nothing */
		break;
	}

	return offset;
}


/* RFC 1094, Page 8 */
int
dissect_nfs2_write_call(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	guint32 beginoffset;
	guint32 offset_value;
	guint32 totalcount;

	offset = old_dissect_fhandle(pd, offset, fd, tree, "file"      );
	if (!BYTES_ARE_IN_FRAME(offset,12)) return offset;
	beginoffset  = EXTRACT_UINT(pd, offset+0);
	offset_value = EXTRACT_UINT(pd, offset+4);
	totalcount   = EXTRACT_UINT(pd, offset+8);
	if (tree) {
		proto_tree_add_uint(tree, hf_nfs_write_beginoffset, NullTVB, 
		offset+0, 4, beginoffset);
		proto_tree_add_uint(tree, hf_nfs_write_offset, NullTVB, 
		offset+4, 4, offset_value);
		proto_tree_add_uint(tree, hf_nfs_write_totalcount, NullTVB, 
		offset+8, 4, totalcount);
	}
	offset += 12;

	offset = dissect_nfsdata(pd, offset, fd, tree, hf_nfs_data); 

	return offset;
}


/* RFC 1094, Page 8 */
int
dissect_nfs2_createargs_call(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	offset = dissect_diropargs(pd, offset, fd, tree, "where"     );
	offset = dissect_sattr    (pd, offset, fd, tree, "attributes");

	return offset;
}


/* RFC 1094, Page 9 */
int
dissect_nfs2_rename_call(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	offset = dissect_diropargs(pd, offset, fd, tree, "from");
	offset = dissect_diropargs(pd, offset, fd, tree, "to"  );

	return offset;
}


/* RFC 1094, Page 9 */
int
dissect_nfs2_link_call(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	offset = old_dissect_fhandle  (pd, offset, fd, tree, "from");
	offset = dissect_diropargs(pd, offset, fd, tree, "to"  );

	return offset;
}


/* RFC 1094, Page 10 */
int
dissect_nfs2_symlink_call(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	offset = dissect_diropargs(pd, offset, fd, tree, "from"           );
	offset = dissect_path     (pd, offset, fd, tree, hf_nfs_symlink_to);
	offset = dissect_sattr    (pd, offset, fd, tree, "attributes"     );

	return offset;
}


/* RFC 1094, Page 11 */
int
dissect_nfs2_readdir_call(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	guint32	cookie;
	guint32	count;

	offset = old_dissect_fhandle (pd, offset, fd, tree, "dir");
	if (!BYTES_ARE_IN_FRAME(offset,8)) return offset;
	cookie  = EXTRACT_UINT(pd, offset+ 0);
	count = EXTRACT_UINT(pd, offset+ 4);
	if (tree) {
		proto_tree_add_uint(tree, hf_nfs_readdir_cookie, NullTVB,
			offset+ 0, 4, cookie);
		proto_tree_add_uint(tree, hf_nfs_readdir_count, NullTVB,
			offset+ 4, 4, count);
	}
	offset += 8;

	return offset;
}


/* RFC 1094, Page 11 */
int
dissect_readdir_entry(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	proto_item* entry_item = NULL;
	proto_tree* entry_tree = NULL;
	int old_offset = offset;
	guint32 fileid;
	guint32 cookie;
	char *name;

	if (tree) {
		entry_item = proto_tree_add_item(tree, hf_nfs_readdir_entry, NullTVB,
			offset+0, END_OF_FRAME, FALSE);
		if (entry_item)
			entry_tree = proto_item_add_subtree(entry_item, ett_nfs_readdir_entry);
	}

	if (!BYTES_ARE_IN_FRAME(offset, 4)) {
		if (entry_item)
			proto_item_set_text(entry_item, "Entry: <TRUNCATED>");
		return offset;
	}
	fileid = EXTRACT_UINT(pd, offset + 0);
	if (entry_tree)
		proto_tree_add_uint(entry_tree, hf_nfs_readdir_entry_fileid, NullTVB,
			offset+0, 4, fileid);
	offset += 4;

	offset = dissect_filename(pd, offset, fd, entry_tree,
		hf_nfs_readdir_entry_name, &name);
	if (entry_item)
		proto_item_set_text(entry_item, "Entry: file ID %u, name %s",
		fileid, name);
	g_free(name);
	
	if (!BYTES_ARE_IN_FRAME(offset, 4)) return offset;
	cookie = EXTRACT_UINT(pd, offset + 0);
	if (entry_tree)
		proto_tree_add_uint(entry_tree, hf_nfs_readdir_entry_cookie, NullTVB,
			offset+0, 4, cookie);
	offset += 4;

	/* now we know, that a readdir entry is shorter */
	if (entry_item) {
		proto_item_set_len(entry_item, offset - old_offset);
	}

	return offset;
}

/* RFC 1094, Page 11 */
int
dissect_nfs2_readdir_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	guint32 status;
	guint32 eof_value;

	offset = dissect_stat(pd, offset, fd, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_rpc_list(pd, offset, fd, tree,
				dissect_readdir_entry);
			if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
			eof_value = EXTRACT_UINT(pd, offset+0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs_readdir_eof, NullTVB,
					offset+ 0, 4, eof_value);
			offset += 4;
		break;
		default:
			/* do nothing */
		break;
	}

	return offset;
}


/* RFC 1094, Page 12 */
int
dissect_nfs2_statfs_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	guint32 status;
	guint32 tsize;
	guint32 bsize;
	guint32 blocks;
	guint32 bfree;
	guint32 bavail;

	offset = dissect_stat(pd, offset, fd, tree, &status);
	switch (status) {
		case 0:
			if (!BYTES_ARE_IN_FRAME(offset,5 * 4)) return offset;
			tsize  = EXTRACT_UINT(pd, offset+ 0);
			bsize  = EXTRACT_UINT(pd, offset+ 4);
			blocks = EXTRACT_UINT(pd, offset+ 8);
			bfree  = EXTRACT_UINT(pd, offset+12);
			bavail = EXTRACT_UINT(pd, offset+16);
			if (tree) {
				proto_tree_add_uint(tree, hf_nfs_statfs_tsize, NullTVB,
					offset+ 0, 4, tsize);
				proto_tree_add_uint(tree, hf_nfs_statfs_bsize, NullTVB,
					offset+ 4, 4, bsize);
				proto_tree_add_uint(tree, hf_nfs_statfs_blocks, NullTVB,
					offset+ 8, 4, blocks);
				proto_tree_add_uint(tree, hf_nfs_statfs_bfree, NullTVB,
					offset+12, 4, bfree);
				proto_tree_add_uint(tree, hf_nfs_statfs_bavail, NullTVB,
					offset+16, 4, bavail);
			}
			offset += 20;
		break;
		default:
			/* do nothing */
		break;
	}

	return offset;
}


/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: type of arguments is "void". */
static const old_vsff nfs2_proc[] = {
	{ 0,	"NULL",		/* OK */
	NULL,				NULL },
	{ 1,	"GETATTR",	/* OK */
	dissect_nfs2_fhandle_call,	dissect_nfs2_attrstat_reply },
	{ 2,	"SETATTR",	/* OK */
	dissect_nfs2_setattr_call,	dissect_nfs2_attrstat_reply },
	{ 3,	"ROOT",		/* OK */
	NULL,				NULL },
	{ 4,	"LOOKUP",	/* OK */
	dissect_nfs2_diropargs_call,	dissect_nfs2_diropres_reply },
	{ 5,	"READLINK",	/* OK */
	dissect_nfs2_fhandle_call,	dissect_nfs2_readlink_reply },
	{ 6,	"READ",		/* OK */
	dissect_nfs2_read_call,		dissect_nfs2_read_reply },
	{ 7,	"WRITECACHE",	/* OK */
	NULL,				NULL },
	{ 8,	"WRITE",	/* OK */
	dissect_nfs2_write_call,	dissect_nfs2_attrstat_reply },
	{ 9,	"CREATE",	/* OK */
	dissect_nfs2_createargs_call,	dissect_nfs2_diropres_reply },
	{ 10,	"REMOVE",	/* OK */
	dissect_nfs2_diropargs_call,	dissect_nfs2_stat_reply },
	{ 11,	"RENAME",	/* OK */
	dissect_nfs2_rename_call,	dissect_nfs2_stat_reply },
	{ 12,	"LINK",		/* OK */
	dissect_nfs2_link_call,		dissect_nfs2_stat_reply },
	{ 13,	"SYMLINK",	/* OK */
	dissect_nfs2_symlink_call,	dissect_nfs2_stat_reply },
	{ 14,	"MKDIR",	/* OK */
	dissect_nfs2_createargs_call,	dissect_nfs2_diropres_reply },
	{ 15,	"RMDIR",	/* OK */
	dissect_nfs2_diropargs_call,	dissect_nfs2_stat_reply },
	{ 16,	"READDIR",	/* OK */
	dissect_nfs2_readdir_call,	dissect_nfs2_readdir_reply },
	{ 17,	"STATFS",	/* OK */
	dissect_nfs2_fhandle_call,	dissect_nfs2_statfs_reply },
	{ 0,NULL,NULL,NULL }
};
/* end of NFS Version 2 */


/***************************/
/* NFS Version 3, RFC 1813 */
/***************************/


/* RFC 1813, Page 15 */
int
dissect_uint64(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
char* name)
{
	offset = dissect_rpc_uint64(pd,offset,fd,tree,name);
	return offset;
}


/* RFC 1813, Page 15 */
int
dissect_uint32(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
char* name)
{
	offset = dissect_rpc_uint32(pd,offset,fd,tree,name);
	return offset;
}


/* RFC 1813, Page 15 */
int
dissect_filename3(const u_char *pd, int offset, frame_data *fd,
    proto_tree *tree, int hf, char **string_ret)
{
	offset = dissect_rpc_string(pd,offset,fd,tree,hf,string_ret);
	return offset;
}


/* RFC 1813, Page 15 */
int
dissect_nfspath3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int hf)
{
	offset = dissect_rpc_string(pd,offset,fd,tree,hf,NULL);
	return offset;
}


/* RFC 1813, Page 15 */
int
dissect_fileid3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
char* name)
{
	offset = dissect_rpc_uint64(pd,offset,fd,tree,name);
	return offset;
}


/* RFC 1813, Page 15 */
int
dissect_cookie3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
char* name)
{
	offset = dissect_rpc_uint64(pd,offset,fd,tree,name);
	return offset;
}


/* RFC 1813, Page 15 */
int
dissect_cookieverf3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	if (!BYTES_ARE_IN_FRAME(offset,8)) return offset;
	proto_tree_add_text(tree, NullTVB, offset, NFS3_COOKIEVERFSIZE,
		"Verifier: Opaque Data");
	offset += NFS3_COOKIEVERFSIZE;
	return offset;
}


/* RFC 1813, Page 16 */
int
dissect_createverf3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	if (!BYTES_ARE_IN_FRAME(offset,8)) return offset;
	proto_tree_add_text(tree, NullTVB, offset, NFS3_CREATEVERFSIZE,
		"Verifier: Opaque Data");
	offset += NFS3_CREATEVERFSIZE;
	return offset;
}


/* RFC 1813, Page 16 */
int
dissect_writeverf3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	if (!BYTES_ARE_IN_FRAME(offset,8)) return offset;
	proto_tree_add_text(tree, NullTVB, offset, NFS3_WRITEVERFSIZE,
		"Verifier: Opaque Data");
	offset += NFS3_WRITEVERFSIZE;
	return offset;
}


/* RFC 1813, Page 16 */
int
dissect_uid3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
char* name)
{
	offset = dissect_rpc_uint32(pd,offset,fd,tree,name); 
	return offset;
}


/* RFC 1813, Page 16 */
int
dissect_gid3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
char* name)
{
	offset = dissect_rpc_uint32(pd,offset,fd,tree,name); 
	return offset;
}


/* RFC 1813, Page 16 */
int
dissect_size3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
char* name)
{
	offset = dissect_rpc_uint64(pd,offset,fd,tree,name); 
	return offset;
}


/* RFC 1813, Page 16 */
int
dissect_offset3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
char* name)
{
	offset = dissect_rpc_uint64(pd,offset,fd,tree,name); 
	return offset;
}


/* RFC 1813, Page 16 */
int
dissect_mode3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
char* name)
{
	guint32 mode3;
	proto_item* mode3_item = NULL;
	proto_tree* mode3_tree = NULL;

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	mode3 = EXTRACT_UINT(pd, offset+0);
	
	if (tree) {
		mode3_item = proto_tree_add_text(tree, NullTVB, offset, 4,
			"%s: 0%o", name, mode3);
		if (mode3_item)
			mode3_tree = proto_item_add_subtree(mode3_item, ett_nfs_mode3);
	}

	/* RFC 1813, Page 23 */
	if (mode3_tree) {
		proto_tree_add_text(mode3_tree, NullTVB, offset, 4, "%s",
		decode_boolean_bitfield(mode3,   0x800, 12, "Set user id on exec", "not SUID"));
		proto_tree_add_text(mode3_tree, NullTVB, offset, 4, "%s",
		decode_boolean_bitfield(mode3,   0x400, 12, "Set group id on exec", "not SGID"));
		proto_tree_add_text(mode3_tree, NullTVB, offset, 4, "%s",
		decode_boolean_bitfield(mode3,   0x200, 12, "Save swapped text even after use", "not save swapped text"));
		proto_tree_add_text(mode3_tree, NullTVB, offset, 4, "%s",
		decode_boolean_bitfield(mode3,   0x100, 12, "Read permission for owner", "no Read permission for owner"));
		proto_tree_add_text(mode3_tree, NullTVB, offset, 4, "%s",
		decode_boolean_bitfield(mode3,    0x80, 12, "Write permission for owner", "no Write permission for owner"));
		proto_tree_add_text(mode3_tree, NullTVB, offset, 4, "%s",
		decode_boolean_bitfield(mode3,    0x40, 12, "Execute permission for owner", "no Execute permission for owner"));
		proto_tree_add_text(mode3_tree, NullTVB, offset, 4, "%s",
		decode_boolean_bitfield(mode3,    0x20, 12, "Read permission for group", "no Read permission for group"));
		proto_tree_add_text(mode3_tree, NullTVB, offset, 4, "%s",
		decode_boolean_bitfield(mode3,    0x10, 12, "Write permission for group", "no Write permission for group"));
		proto_tree_add_text(mode3_tree, NullTVB, offset, 4, "%s",
		decode_boolean_bitfield(mode3,     0x8, 12, "Execute permission for group", "no Execute permission for group"));
		proto_tree_add_text(mode3_tree, NullTVB, offset, 4, "%s",
		decode_boolean_bitfield(mode3,     0x4, 12, "Read permission for others", "no Read permission for others"));
		proto_tree_add_text(mode3_tree, NullTVB, offset, 4, "%s",
		decode_boolean_bitfield(mode3,     0x2, 12, "Write permission for others", "no Write permission for others"));
		proto_tree_add_text(mode3_tree, NullTVB, offset, 4, "%s",
		decode_boolean_bitfield(mode3,     0x1, 12, "Execute permission for others", "no Execute permission for others"));
	}

	offset += 4;
	return offset;
}


/* RFC 1813, Page 16 */
int
dissect_count3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
char* name)
{
	offset = dissect_rpc_uint32(pd,offset,fd,tree,name);
	return offset;
}


/* RFC 1813, Page 16,17 */
const value_string names_nfs_nfsstat3[] =
{
	{	0,	"OK" },
	{	1,	"ERR_PERM" },
	{	2,	"ERR_NOENT" },
	{	5,	"ERR_IO" },
	{	6,	"ERR_NX_IO" },
	{	13,	"ERR_ACCES" },
	{	17,	"ERR_EXIST" },
	{	18,	"ERR_XDEV" },
	{	19,	"ERR_NODEV" },
	{	20,	"ERR_NOTDIR" },
	{	21,	"ERR_ISDIR" },
	{	22,	"ERR_INVAL" },
	{	27,	"ERR_FBIG" },
	{	28,	"ERR_NOSPC" },
	{	30,	"ERR_ROFS" },
	{	31,	"ERR_MLINK" },
	{	63,	"ERR_NAMETOOLONG" },
	{	66,	"ERR_NOTEMPTY" },
	{	69,	"ERR_DQUOT" },
	{	70,	"ERR_STALE" },
	{	71,	"ERR_REMOTE" },
	{	10001,	"ERR_BADHANDLE" },
	{	10002,	"ERR_NOT_SYNC" },
	{	10003,	"ERR_BAD_COOKIE" },
	{	10004,	"ERR_NOTSUPP" },
	{	10005,	"ERR_TOOSMALL" },
	{	10006,	"ERR_SERVERFAULT" },
	{	10007,	"ERR_BADTYPE" },
	{	10008,	"ERR_JUKEBOX" },
	{	0,	NULL }
};


/* RFC 1813, Page 16 */
int
dissect_nfsstat3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,guint32 *status)
{
	guint32 nfsstat3;

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	nfsstat3 = EXTRACT_UINT(pd, offset+0);
	
	if (tree) {
		proto_tree_add_uint(tree, hf_nfs_nfsstat3, NullTVB,
			offset, 4, nfsstat3);
	}

	offset += 4;
	*status = nfsstat3;
	return offset;
}


const value_string names_nfs_ftype3[] =
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
int
dissect_ftype3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
int hf, guint32* ftype3)
{
	guint32 type;

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	type = EXTRACT_UINT(pd, offset+0);
	
	if (tree) {
		proto_tree_add_uint(tree, hf, NullTVB, offset, 4, type);
	}

	offset += 4;
	*ftype3 = type;
	return offset;
}


/* RFC 1813, Page 20 */
int
dissect_specdata3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name)
{
	guint32	specdata1;
	guint32	specdata2;

	proto_item* specdata3_item;
	proto_tree* specdata3_tree = NULL;

	if (!BYTES_ARE_IN_FRAME(offset,8)) return offset;
	specdata1 = EXTRACT_UINT(pd, offset+0);
	specdata2 = EXTRACT_UINT(pd, offset+4);
	
	if (tree) {
		specdata3_item = proto_tree_add_text(tree, NullTVB, offset, 8,
			"%s: %u,%u", name, specdata1, specdata2);
		if (specdata3_item)
			specdata3_tree = proto_item_add_subtree(specdata3_item,
					ett_nfs_specdata3);
	}

	if (specdata3_tree) {
		proto_tree_add_text(specdata3_tree, NullTVB,offset+0,4,
					"specdata1: %u", specdata1);
		proto_tree_add_text(specdata3_tree, NullTVB,offset+4,4,
					"specdata2: %u", specdata2);
	}

	offset += 8;
	return offset;
}


/* RFC 1813, Page 21 */
int
old_dissect_nfs_fh3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name)
{
	tvbuff_t *tvb = tvb_create_from_top(offset);

	offset = dissect_nfs_fh3(tvb, 0, &pi, tree, name);
	return tvb_raw_offset(tvb) + offset;
}

int
dissect_nfs_fh3(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree,
    char *name)
{
	guint fh3_len;
	guint fh3_len_full;
	guint fh3_fill;
	proto_item* fitem;
	proto_tree* ftree = NULL;

	fh3_len = tvb_get_ntohl(tvb, offset+0);
	fh3_len_full = rpc_roundup(fh3_len);
	fh3_fill = fh3_len_full - fh3_len;
	
	if (tree) {
		fitem = proto_tree_add_text(tree, tvb, offset, 4+fh3_len_full,
			"%s", name);
		if (fitem)
			ftree = proto_item_add_subtree(fitem, ett_nfs_fh3);
	}

	if (ftree) {
		proto_tree_add_text(ftree, tvb, offset+0, 4,
					"length: %u", fh3_len);
		dissect_fhandle_data(tvb, offset+4, pinfo, ftree, fh3_len);
	}
	offset += 4 + fh3_len_full;
	return offset;
}


/* RFC 1813, Page 21 */
int
dissect_nfstime3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,char* name)
{
	guint32	seconds;
	guint32 nseconds;

	proto_item* time_item;
	proto_tree* time_tree = NULL;

	if (!BYTES_ARE_IN_FRAME(offset,8)) return offset;
	seconds = EXTRACT_UINT(pd, offset+0);
	nseconds = EXTRACT_UINT(pd, offset+4);
	
	if (tree) {
		time_item = proto_tree_add_text(tree, NullTVB, offset, 8,
			"%s: %u.%09u", name, seconds, nseconds);
		if (time_item)
			time_tree = proto_item_add_subtree(time_item, ett_nfs_nfstime3);
	}

	if (time_tree) {
		proto_tree_add_text(time_tree, NullTVB,offset+0,4,
					"seconds: %u", seconds);
		proto_tree_add_text(time_tree, NullTVB,offset+4,4,
					"nano seconds: %u", nseconds);
	}
	offset += 8;
	return offset;
}


/* RFC 1813, Page 22 */
int
dissect_fattr3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name)
{
	proto_item* fattr3_item = NULL;
	proto_tree* fattr3_tree = NULL;
	int old_offset = offset;
	guint32 type;

	if (tree) {
		fattr3_item = proto_tree_add_text(tree, NullTVB, offset,
			END_OF_FRAME, "%s", name);
		if (fattr3_item)
			fattr3_tree = proto_item_add_subtree(fattr3_item, ett_nfs_fattr3);
	}

	offset = dissect_ftype3   (pd,offset,fd,fattr3_tree,hf_nfs_ftype3,&type);
	offset = dissect_mode3    (pd,offset,fd,fattr3_tree,"mode");
	offset = dissect_uint32   (pd,offset,fd,fattr3_tree,"nlink");
	offset = dissect_uid3     (pd,offset,fd,fattr3_tree,"uid");
	offset = dissect_gid3     (pd,offset,fd,fattr3_tree,"gid");
	offset = dissect_size3    (pd,offset,fd,fattr3_tree,"size");
	offset = dissect_size3    (pd,offset,fd,fattr3_tree,"used");
	offset = dissect_specdata3(pd,offset,fd,fattr3_tree,"rdev");
	offset = dissect_uint64   (pd,offset,fd,fattr3_tree,"fsid");
	offset = dissect_fileid3  (pd,offset,fd,fattr3_tree,"fileid");
	offset = dissect_nfstime3 (pd,offset,fd,fattr3_tree,"atime");
	offset = dissect_nfstime3 (pd,offset,fd,fattr3_tree,"mtime");
	offset = dissect_nfstime3 (pd,offset,fd,fattr3_tree,"ctime");

	/* now we know, that fattr3 is shorter */
	if (fattr3_item) {
		proto_item_set_len(fattr3_item, offset - old_offset);
	}

	return offset;
}


const value_string value_follows[] =
	{
		{ 0, "no value" },
		{ 1, "value follows"},
		{ 0, NULL }
	};


/* RFC 1813, Page 23 */
int
dissect_post_op_attr(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name)
{
	proto_item* post_op_attr_item = NULL;
	proto_tree* post_op_attr_tree = NULL;
	int old_offset = offset;
	guint32 attributes_follow;

	if (tree) {
		post_op_attr_item = proto_tree_add_text(tree, NullTVB, offset,
			END_OF_FRAME, "%s", name);
		if (post_op_attr_item)
			post_op_attr_tree = proto_item_add_subtree(post_op_attr_item, ett_nfs_post_op_attr);
	}

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	attributes_follow = EXTRACT_UINT(pd, offset+0);
	proto_tree_add_text(post_op_attr_tree, NullTVB, offset, 4,
		"attributes_follow: %s (%u)", 
		val_to_str(attributes_follow,value_follows,"Unknown"), attributes_follow);
	offset += 4;
	switch (attributes_follow) {
		case TRUE:
			offset = dissect_fattr3(pd, offset, fd, post_op_attr_tree,
					"attributes");
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
int
dissect_wcc_attr(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name)
{
	proto_item* wcc_attr_item = NULL;
	proto_tree* wcc_attr_tree = NULL;
	int old_offset = offset;

	if (tree) {
		wcc_attr_item = proto_tree_add_text(tree, NullTVB, offset,
			END_OF_FRAME, "%s", name);
		if (wcc_attr_item)
			wcc_attr_tree = proto_item_add_subtree(wcc_attr_item, ett_nfs_wcc_attr);
	}

	offset = dissect_size3   (pd, offset, fd, wcc_attr_tree, "size" );
	offset = dissect_nfstime3(pd, offset, fd, wcc_attr_tree, "mtime");
	offset = dissect_nfstime3(pd, offset, fd, wcc_attr_tree, "ctime");
	
	/* now we know, that wcc_attr_tree is shorter */
	if (wcc_attr_item) {
		proto_item_set_len(wcc_attr_item, offset - old_offset);
	}

	return offset;
}


/* RFC 1813, Page 24 */
int
dissect_pre_op_attr(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name)
{
	proto_item* pre_op_attr_item = NULL;
	proto_tree* pre_op_attr_tree = NULL;
	int old_offset = offset;
	guint32 attributes_follow;

	if (tree) {
		pre_op_attr_item = proto_tree_add_text(tree, NullTVB, offset,
			END_OF_FRAME, "%s", name);
		if (pre_op_attr_item)
			pre_op_attr_tree = proto_item_add_subtree(pre_op_attr_item, ett_nfs_pre_op_attr);
	}

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	attributes_follow = EXTRACT_UINT(pd, offset+0);
	proto_tree_add_text(pre_op_attr_tree, NullTVB, offset, 4,
		"attributes_follow: %s (%u)", 
		val_to_str(attributes_follow,value_follows,"Unknown"), attributes_follow);
	offset += 4;
	switch (attributes_follow) {
		case TRUE:
			offset = dissect_wcc_attr(pd, offset, fd, pre_op_attr_tree,
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
int
dissect_wcc_data(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name)
{
	proto_item* wcc_data_item = NULL;
	proto_tree* wcc_data_tree = NULL;
	int old_offset = offset;

	if (tree) {
		wcc_data_item = proto_tree_add_text(tree, NullTVB, offset,
			END_OF_FRAME, "%s", name);
		if (wcc_data_item)
			wcc_data_tree = proto_item_add_subtree(wcc_data_item, ett_nfs_wcc_data);
	}

	offset = dissect_pre_op_attr (pd, offset, fd, wcc_data_tree, "before");
	offset = dissect_post_op_attr(pd, offset, fd, wcc_data_tree, "after" );

	/* now we know, that wcc_data is shorter */
	if (wcc_data_item) {
		proto_item_set_len(wcc_data_item, offset - old_offset);
	}

	return offset;
}


/* RFC 1813, Page 25 */
int
dissect_post_op_fh3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name)
{
	proto_item* post_op_fh3_item = NULL;
	proto_tree* post_op_fh3_tree = NULL;
	int old_offset = offset;
	guint32 handle_follows;

	if (tree) {
		post_op_fh3_item = proto_tree_add_text(tree, NullTVB, offset,
			END_OF_FRAME, "%s", name);
		if (post_op_fh3_item)
			post_op_fh3_tree = proto_item_add_subtree(post_op_fh3_item, ett_nfs_post_op_fh3);
	}

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	handle_follows = EXTRACT_UINT(pd, offset+0);
	proto_tree_add_text(post_op_fh3_tree, NullTVB, offset, 4,
		"handle_follows: %s (%u)", 
		val_to_str(handle_follows,value_follows,"Unknown"), handle_follows);
	offset += 4;
	switch (handle_follows) {
		case TRUE:
			offset = old_dissect_nfs_fh3(pd, offset, fd, post_op_fh3_tree,
					"handle");
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
int
dissect_set_mode3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name)
{
	proto_item* set_mode3_item = NULL;
	proto_tree* set_mode3_tree = NULL;
	int old_offset = offset;
	guint32 set_it;
	char* set_it_name;

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	set_it = EXTRACT_UINT(pd, offset+0);
	set_it_name = val_to_str(set_it,value_follows,"Unknown");

	if (tree) {
		set_mode3_item = proto_tree_add_text(tree, NullTVB, offset,
			END_OF_FRAME, "%s: %s", name, set_it_name);
		if (set_mode3_item)
			set_mode3_tree = proto_item_add_subtree(set_mode3_item, ett_nfs_set_mode3);
	}

	if (set_mode3_tree)
		proto_tree_add_text(set_mode3_tree, NullTVB, offset, 4,
			"set_it: %s (%u)", set_it_name, set_it);

	offset += 4;

	switch (set_it) {
		case 1:
			offset = dissect_mode3(pd, offset, fd, set_mode3_tree,
					"mode");
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
int
dissect_set_uid3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name)
{
	proto_item* set_uid3_item = NULL;
	proto_tree* set_uid3_tree = NULL;
	int old_offset = offset;
	guint32 set_it;
	char* set_it_name;

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	set_it = EXTRACT_UINT(pd, offset+0);
	set_it_name = val_to_str(set_it,value_follows,"Unknown");

	if (tree) {
		set_uid3_item = proto_tree_add_text(tree, NullTVB, offset,
			END_OF_FRAME, "%s: %s", name, set_it_name);
		if (set_uid3_item)
			set_uid3_tree = proto_item_add_subtree(set_uid3_item, ett_nfs_set_uid3);
	}

	if (set_uid3_tree)
		proto_tree_add_text(set_uid3_tree, NullTVB, offset, 4,
			"set_it: %s (%u)", set_it_name, set_it);

	offset += 4;

	switch (set_it) {
		case 1:
			offset = dissect_uid3(pd, offset, fd, set_uid3_tree,
					"uid");
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
int
dissect_set_gid3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name)
{
	proto_item* set_gid3_item = NULL;
	proto_tree* set_gid3_tree = NULL;
	int old_offset = offset;
	guint32 set_it;
	char* set_it_name;

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	set_it = EXTRACT_UINT(pd, offset+0);
	set_it_name = val_to_str(set_it,value_follows,"Unknown");

	if (tree) {
		set_gid3_item = proto_tree_add_text(tree, NullTVB, offset,
			END_OF_FRAME, "%s: %s", name, set_it_name);
		if (set_gid3_item)
			set_gid3_tree = proto_item_add_subtree(set_gid3_item, ett_nfs_set_gid3);
	}

	if (set_gid3_tree)
		proto_tree_add_text(set_gid3_tree, NullTVB, offset, 4,
			"set_it: %s (%u)", set_it_name, set_it);

	offset += 4;

	switch (set_it) {
		case 1:
			offset = dissect_gid3(pd, offset, fd, set_gid3_tree,
					"gid");
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
int
dissect_set_size3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name)
{
	proto_item* set_size3_item = NULL;
	proto_tree* set_size3_tree = NULL;
	int old_offset = offset;
	guint32 set_it;
	char* set_it_name;

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	set_it = EXTRACT_UINT(pd, offset+0);
	set_it_name = val_to_str(set_it,value_follows,"Unknown");

	if (tree) {
		set_size3_item = proto_tree_add_text(tree, NullTVB, offset,
			END_OF_FRAME, "%s: %s", name, set_it_name);
		if (set_size3_item)
			set_size3_tree = proto_item_add_subtree(set_size3_item, ett_nfs_set_size3);
	}

	if (set_size3_tree)
		proto_tree_add_text(set_size3_tree, NullTVB, offset, 4,
			"set_it: %s (%u)", set_it_name, set_it);

	offset += 4;

	switch (set_it) {
		case 1:
			offset = dissect_size3(pd, offset, fd, set_size3_tree,
					"size");
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

const value_string time_how[] =
	{
		{ DONT_CHANGE,	"don't change" },
		{ SET_TO_SERVER_TIME, "set to server time" },
		{ SET_TO_CLIENT_TIME, "set to client time" },
		{ 0, NULL }
	};


/* RFC 1813, Page 26 */
int
dissect_set_atime(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name)
{
	proto_item* set_atime_item = NULL;
	proto_tree* set_atime_tree = NULL;
	int old_offset = offset;
	guint32 set_it;
	char* set_it_name;

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	set_it = EXTRACT_UINT(pd, offset+0);
	set_it_name = val_to_str(set_it,time_how,"Unknown");

	if (tree) {
		set_atime_item = proto_tree_add_text(tree, NullTVB, offset,
			END_OF_FRAME, "%s: %s",
			name, set_it_name);
		if (set_atime_item)
			set_atime_tree = proto_item_add_subtree(set_atime_item, ett_nfs_set_atime);
	}

	if (set_atime_tree)
		proto_tree_add_text(set_atime_tree, NullTVB, offset, 4,
			"set_it: %s (%u)", set_it_name, set_it);

	offset += 4;

	switch (set_it) {
		case SET_TO_CLIENT_TIME:
			if (set_atime_item)
			offset = dissect_nfstime3(pd, offset, fd, set_atime_tree,
					"atime");
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
int
dissect_set_mtime(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name)
{
	proto_item* set_mtime_item = NULL;
	proto_tree* set_mtime_tree = NULL;
	int old_offset = offset;
	guint32 set_it;
	char* set_it_name;

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	set_it = EXTRACT_UINT(pd, offset+0);
	set_it_name = val_to_str(set_it,time_how,"Unknown");

	if (tree) {
		set_mtime_item = proto_tree_add_text(tree, NullTVB, offset,
			END_OF_FRAME, "%s: %s",
			name, set_it_name);
		if (set_mtime_item)
			set_mtime_tree = proto_item_add_subtree(set_mtime_item, ett_nfs_set_mtime);
	}

	if (set_mtime_tree)
		proto_tree_add_text(set_mtime_tree, NullTVB, offset, 4,
				"set_it: %s (%u)", set_it_name, set_it);

	offset += 4;

	switch (set_it) {
		case SET_TO_CLIENT_TIME:
			if (set_mtime_item)
			offset = dissect_nfstime3(pd, offset, fd, set_mtime_tree,
					"atime");
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
int
dissect_sattr3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name)
{
	proto_item* sattr3_item = NULL;
	proto_tree* sattr3_tree = NULL;
	int old_offset = offset;

	if (tree) {
		sattr3_item = proto_tree_add_text(tree, NullTVB, offset,
			END_OF_FRAME, "%s", name);
		if (sattr3_item)
			sattr3_tree = proto_item_add_subtree(sattr3_item, ett_nfs_sattr3);
	}

	offset = dissect_set_mode3(pd, offset, fd, sattr3_tree, "mode");
	offset = dissect_set_uid3 (pd, offset, fd, sattr3_tree, "uid");
	offset = dissect_set_gid3 (pd, offset, fd, sattr3_tree, "gid");
	offset = dissect_set_size3(pd, offset, fd, sattr3_tree, "size");
	offset = dissect_set_atime(pd, offset, fd, sattr3_tree, "atime");
	offset = dissect_set_mtime(pd, offset, fd, sattr3_tree, "mtime");

	/* now we know, that sattr3 is shorter */
	if (sattr3_item) {
		proto_item_set_len(sattr3_item, offset - old_offset);
	}

	return offset;
}


/* RFC 1813, Page 27 */
int
dissect_diropargs3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name)
{
	proto_item* diropargs3_item = NULL;
	proto_tree* diropargs3_tree = NULL;
	int old_offset = offset;

	if (tree) {
		diropargs3_item = proto_tree_add_text(tree, NullTVB, offset,
			END_OF_FRAME, "%s", name);
		if (diropargs3_item)
			diropargs3_tree = proto_item_add_subtree(diropargs3_item, ett_nfs_diropargs3);
	}

	offset = old_dissect_nfs_fh3  (pd, offset, fd, diropargs3_tree, "dir");
	offset = dissect_filename3(pd, offset, fd, diropargs3_tree, hf_nfs_name,NULL);

	/* now we know, that diropargs3 is shorter */
	if (diropargs3_item) {
		proto_item_set_len(diropargs3_item, offset - old_offset);
	}

	return offset;
}


/* RFC 1813, Page 27 */
int
dissect_nfs3_diropargs3_call(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	offset = dissect_diropargs3(pd, offset, fd, tree, "object");

	return offset;
}


/* RFC 1813, Page 40 */
int
dissect_access(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name)
{
	guint32 access;
	proto_item* access_item = NULL;
	proto_tree* access_tree = NULL;

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	access = EXTRACT_UINT(pd, offset+0);
	
	if (tree) {
		access_item = proto_tree_add_text(tree, NullTVB, offset, 4,
			"%s: 0x%02x", name, access);
		if (access_item)
			access_tree = proto_item_add_subtree(access_item, ett_nfs_access);
	}

	if (access_tree) {
		proto_tree_add_text(access_tree, NullTVB, offset, 4, "%s READ",
		decode_boolean_bitfield(access,  0x001, 6, "allow", "not allow"));
		proto_tree_add_text(access_tree, NullTVB, offset, 4, "%s LOOKUP",
		decode_boolean_bitfield(access,  0x002, 6, "allow", "not allow"));
		proto_tree_add_text(access_tree, NullTVB, offset, 4, "%s MODIFY",
		decode_boolean_bitfield(access,  0x004, 6, "allow", "not allow"));
		proto_tree_add_text(access_tree, NullTVB, offset, 4, "%s EXTEND",
		decode_boolean_bitfield(access,  0x008, 6, "allow", "not allow"));
		proto_tree_add_text(access_tree, NullTVB, offset, 4, "%s DELETE",
		decode_boolean_bitfield(access,  0x010, 6, "allow", "not allow"));
		proto_tree_add_text(access_tree, NullTVB, offset, 4, "%s EXECUTE",
		decode_boolean_bitfield(access,  0x020, 6, "allow", "not allow"));
	}

	offset += 4;
	return offset;
}


/* NFS3 file handle dissector */
int
dissect_nfs3_nfs_fh3_call(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	offset = old_dissect_nfs_fh3(pd, offset, fd, tree, "object");
	return offset;
}


/* generic NFS3 reply dissector */
int
dissect_nfs3_any_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	guint32 status;

	offset = dissect_nfsstat3(pd, offset, fd, tree, &status);

	return offset;

}


/* RFC 1813, Page 32,33 */
int
dissect_nfs3_getattr_call(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	offset = old_dissect_nfs_fh3(pd, offset, fd, tree, "object");
	return offset;
}


/* RFC 1813, Page 32,33 */
int
dissect_nfs3_getattr_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	guint32 status;

	offset = dissect_nfsstat3(pd, offset, fd, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_fattr3(pd, offset, fd, tree, "obj_attributes");
		break;
		default:
			/* void */
		break;
	}
		
	return offset;
}


/* RFC 1813, Page 33 */
int
dissect_sattrguard3(const u_char* pd, int offset, frame_data* fd, proto_tree* tree, char *name)
{
	proto_item* sattrguard3_item = NULL;
	proto_tree* sattrguard3_tree = NULL;
	int old_offset = offset;
	guint32 check;
	char* check_name;

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	check = EXTRACT_UINT(pd, offset+0);
	check_name = val_to_str(check,value_follows,"Unknown");

	if (tree) {
		sattrguard3_item = proto_tree_add_text(tree, NullTVB, offset,
			END_OF_FRAME, "%s: %s", name, check_name);
		if (sattrguard3_item)
			sattrguard3_tree = proto_item_add_subtree(sattrguard3_item, ett_nfs_sattrguard3);
	}

	if (sattrguard3_tree)
		proto_tree_add_text(sattrguard3_tree, NullTVB, offset, 4,
			"check: %s (%u)", check_name, check);

	offset += 4;

	switch (check) {
		case TRUE:
			offset = dissect_nfstime3(pd, offset, fd, sattrguard3_tree,
					"obj_ctime");
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
int
dissect_nfs3_setattr_call(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	offset = old_dissect_nfs_fh3    (pd, offset, fd, tree, "object");
	offset = dissect_sattr3     (pd, offset, fd, tree, "new_attributes");
	offset = dissect_sattrguard3(pd, offset, fd, tree, "guard");
	return offset;
}


/* RFC 1813, Page 33..36 */
int
dissect_nfs3_setattr_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	guint32 status;

	offset = dissect_nfsstat3(pd, offset, fd, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_wcc_data(pd, offset, fd, tree, "obj_wcc");
		break;
		default:
			offset = dissect_wcc_data(pd, offset, fd, tree, "obj_wcc");
		break;
	}
		
	return offset;
}


/* RFC 1813, Page 37..39 */
int
dissect_nfs3_lookup_call(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	offset = dissect_diropargs3 (pd, offset, fd, tree, "what");
	return offset;
}


/* RFC 1813, Page 37..39 */
int
dissect_nfs3_lookup_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	guint32 status;

	offset = dissect_nfsstat3(pd, offset, fd, tree, &status);
	switch (status) {
		case 0:
			offset = old_dissect_nfs_fh3     (pd, offset, fd, tree, "object");
			offset = dissect_post_op_attr(pd, offset, fd, tree, "obj_attributes");
			offset = dissect_post_op_attr(pd, offset, fd, tree, "dir_attributes");
		break;
		default:
			offset = dissect_post_op_attr(pd, offset, fd, tree, "dir_attributes");
		break;
	}
		
	return offset;
}


/* RFC 1813, Page 40..43 */
int
dissect_nfs3_access_call(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	offset = old_dissect_nfs_fh3(pd, offset, fd, tree, "object");
	offset = dissect_access (pd, offset, fd, tree, "access");

	return offset;
}


/* RFC 1813, Page 40..43 */
int
dissect_nfs3_access_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	guint32 status;

	offset = dissect_nfsstat3(pd, offset, fd, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_post_op_attr(pd, offset, fd, tree, "obj_attributes");
			offset = dissect_access      (pd, offset, fd, tree, "access");
		break;
		default:
			offset = dissect_post_op_attr(pd, offset, fd, tree, "obj_attributes");
		break;
	}
		
	return offset;
}


/* RFC 1813, Page 44,45 */
int
dissect_nfs3_readlink_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	guint32 status;

	offset = dissect_nfsstat3(pd, offset, fd, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_post_op_attr(pd, offset, fd, tree, "symlink_attributes");
			offset = dissect_nfspath3    (pd, offset, fd, tree, hf_nfs_readlink_data);
		break;
		default:
			offset = dissect_post_op_attr(pd, offset, fd, tree, "symlink_attributes");
		break;
	}
		
	return offset;
}


/* RFC 1813, Page 46..48 */
int
dissect_nfs3_read_call(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	offset = old_dissect_nfs_fh3(pd, offset, fd, tree, "file");
	offset = dissect_offset3(pd, offset, fd, tree, "offset");
	offset = dissect_count3 (pd, offset, fd, tree, "count");

	return offset;
}


/* RFC 1813, Page 46..48 */
int
dissect_nfs3_read_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	guint32 status;

	offset = dissect_nfsstat3(pd, offset, fd, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_post_op_attr(pd, offset, fd, tree, "file_attributes");
			offset = dissect_count3      (pd, offset, fd, tree, "count");
			offset = dissect_rpc_bool    (pd, offset, fd, tree, hf_nfs_read_eof);
			offset = dissect_nfsdata     (pd, offset, fd, tree, hf_nfs_data);
		break;
		default:
			offset = dissect_post_op_attr(pd, offset, fd, tree, "file_attributes");
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
int
dissect_stable_how(const u_char* pd, int offset, frame_data* fd, proto_tree* tree, int hfindex)
{
	guint32 stable_how;

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	stable_how = EXTRACT_UINT(pd,offset+0);
	if (tree) {
		proto_tree_add_uint(tree, hfindex, NullTVB,
			offset, 4, stable_how); 
	}
	offset += 4;

	return offset;
}


/* RFC 1813, Page 49..54 */
int
dissect_nfs3_write_call(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	offset = old_dissect_nfs_fh3   (pd, offset, fd, tree, "file");
	offset = dissect_offset3   (pd, offset, fd, tree, "offset");
	offset = dissect_count3    (pd, offset, fd, tree, "count");
	offset = dissect_stable_how(pd, offset, fd, tree, hf_nfs_write_stable);
	offset = dissect_nfsdata   (pd, offset, fd, tree, hf_nfs_data);

	return offset;
}


/* RFC 1813, Page 49..54 */
int
dissect_nfs3_write_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	guint32 status;

	offset = dissect_nfsstat3(pd, offset, fd, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_wcc_data  (pd, offset, fd, tree, "file_wcc");
			offset = dissect_count3    (pd, offset, fd, tree, "count");
			offset = dissect_stable_how(pd, offset, fd, tree, hf_nfs_write_committed);
			offset = dissect_writeverf3(pd, offset, fd, tree);
		break;
		default:
			offset = dissect_wcc_data(pd, offset, fd, tree, "file_wcc");
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
int
dissect_createmode3(const u_char* pd, int offset, frame_data* fd, proto_tree* tree, guint32* mode)
{
	guint32 mode_value;
	
	if (!BYTES_ARE_IN_FRAME(offset, 4)) return offset;
	mode_value = EXTRACT_UINT(pd, offset + 0);
	if (tree) {
		proto_tree_add_uint(tree, hf_nfs_createmode3, NullTVB,
		offset+0, 4, mode_value);
	}
	offset += 4;

	*mode = mode_value;
	return offset;
}


/* RFC 1813, Page 54..58 */
int
dissect_nfs3_create_call(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	guint32 mode;

	offset = dissect_diropargs3 (pd, offset, fd, tree, "where");
	offset = dissect_createmode3(pd, offset, fd, tree, &mode);
	switch (mode) {
		case UNCHECKED:
		case GUARDED:
			offset = dissect_sattr3     (pd, offset, fd, tree, "obj_attributes");
		break;
		case EXCLUSIVE:
			offset = dissect_createverf3(pd, offset, fd, tree);
		break;
	}
	
	return offset;
}


/* RFC 1813, Page 54..58 */
int
dissect_nfs3_create_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	guint32 status;

	offset = dissect_nfsstat3(pd, offset, fd, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_post_op_fh3 (pd, offset, fd, tree, "obj");
			offset = dissect_post_op_attr(pd, offset, fd, tree, "obj_attributes");
			offset = dissect_wcc_data    (pd, offset, fd, tree, "dir_wcc");
		break;
		default:
			offset = dissect_wcc_data    (pd, offset, fd, tree, "dir_wcc");
		break;
	}
		
	return offset;
}


/* RFC 1813, Page 58..60 */
int
dissect_nfs3_mkdir_call(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	offset = dissect_diropargs3(pd, offset, fd, tree, "where");
	offset = dissect_sattr3    (pd, offset, fd, tree, "attributes");
	
	return offset;
}


/* RFC 1813, Page 61..63 */
int
dissect_nfs3_symlink_call(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	offset = dissect_diropargs3(pd, offset, fd, tree, "where");
	offset = dissect_sattr3    (pd, offset, fd, tree, "symlink_attributes");
	offset = dissect_nfspath3  (pd, offset, fd, tree, hf_nfs_symlink_to);
	
	return offset;
}


/* RFC 1813, Page 63..66 */
int
dissect_nfs3_mknod_call(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	guint32 type;

	offset = dissect_diropargs3(pd, offset, fd, tree, "where");
	offset = dissect_ftype3(pd, offset, fd, tree, hf_nfs_ftype3, &type);
	switch (type) {
		case NF3CHR:
		case NF3BLK:
			offset = dissect_sattr3(pd, offset, fd, tree, "dev_attributes");
			offset = dissect_specdata3(pd, offset, fd, tree, "spec");
		break;
		case NF3SOCK:
		case NF3FIFO:
			offset = dissect_sattr3(pd, offset, fd, tree, "pipe_attributes");
		break;
		default:
			/* nothing to do */
		break;
	}
	
	return offset;
}


/* RFC 1813, Page 67..69 */
int
dissect_nfs3_remove_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	guint32 status;

	offset = dissect_nfsstat3(pd, offset, fd, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_wcc_data    (pd, offset, fd, tree, "dir_wcc");
		break;
		default:
			offset = dissect_wcc_data    (pd, offset, fd, tree, "dir_wcc");
		break;
	}
		
	return offset;
}


/* RFC 1813, Page 71..74 */
int
dissect_nfs3_rename_call(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	offset = dissect_diropargs3(pd, offset, fd, tree, "from");
	offset = dissect_diropargs3(pd, offset, fd, tree, "to");
	
	return offset;
}


/* RFC 1813, Page 71..74 */
int
dissect_nfs3_rename_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	guint32 status;

	offset = dissect_nfsstat3(pd, offset, fd, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_wcc_data(pd, offset, fd, tree, "fromdir_wcc");
			offset = dissect_wcc_data(pd, offset, fd, tree, "todir_wcc");
		break;
		default:
			offset = dissect_wcc_data(pd, offset, fd, tree, "fromdir_wcc");
			offset = dissect_wcc_data(pd, offset, fd, tree, "todir_wcc");
		break;
	}
		
	return offset;
}


/* RFC 1813, Page 74..76 */
int
dissect_nfs3_link_call(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	offset = old_dissect_nfs_fh3   (pd, offset, fd, tree, "file");
	offset = dissect_diropargs3(pd, offset, fd, tree, "link");
	
	return offset;
}


/* RFC 1813, Page 74..76 */
int
dissect_nfs3_link_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	guint32 status;

	offset = dissect_nfsstat3(pd, offset, fd, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_post_op_attr(pd, offset, fd, tree, "file_attributes");
			offset = dissect_wcc_data    (pd, offset, fd, tree, "linkdir_wcc");
		break;
		default:
			offset = dissect_post_op_attr(pd, offset, fd, tree, "file_attributes");
			offset = dissect_wcc_data    (pd, offset, fd, tree, "linkdir_wcc");
		break;
	}
		
	return offset;
}


/* RFC 1813, Page 76..80 */
int
dissect_nfs3_readdir_call(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	offset = old_dissect_nfs_fh3    (pd, offset, fd, tree, "dir");
	offset = dissect_cookie3    (pd, offset, fd, tree, "cookie");
	offset = dissect_cookieverf3(pd, offset, fd, tree);
	offset = dissect_count3     (pd, offset, fd, tree, "count");
	
	return offset;
}


/* RFC 1813, Page 76..80 */
int
dissect_entry3(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	proto_item* entry_item = NULL;
	proto_tree* entry_tree = NULL;
	int old_offset = offset;
	char *name;

	if (tree) {
		entry_item = proto_tree_add_item(tree, hf_nfs_readdir_entry, NullTVB,
			offset+0, END_OF_FRAME, FALSE);
		if (entry_item)
			entry_tree = proto_item_add_subtree(entry_item, ett_nfs_readdir_entry);
	}

	offset = dissect_fileid3(pd, offset, fd, entry_tree, "fileid");

	offset = dissect_filename3(pd, offset, fd, entry_tree,
		hf_nfs_readdir_entry_name, &name);
	if (entry_item)
		proto_item_set_text(entry_item, "Entry: name %s", name);
	g_free(name);

	offset = dissect_cookie3(pd, offset, fd, entry_tree, "cookie");

	/* now we know, that a readdir entry is shorter */
	if (entry_item) {
		proto_item_set_len(entry_item, offset - old_offset);
	}

	return offset;
}


/* RFC 1813, Page 76..80 */
int
dissect_nfs3_readdir_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	guint32 status;
	guint32 eof_value;

	offset = dissect_stat(pd, offset, fd, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_post_op_attr(pd, offset, fd, tree, "dir_attributes");
			offset = dissect_cookieverf3(pd, offset, fd, tree);
			offset = dissect_rpc_list(pd, offset, fd, tree,
				dissect_entry3);
			if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
			eof_value = EXTRACT_UINT(pd, offset+0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs_readdir_eof, NullTVB,
					offset+ 0, 4, eof_value);
			offset += 4;
		break;
		default:
			offset = dissect_post_op_attr(pd, offset, fd, tree, "dir_attributes");
		break;
	}

	return offset;
}


/* RFC 1813, Page 80..83 */
int
dissect_nfs3_readdirplus_call(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	offset = old_dissect_nfs_fh3    (pd, offset, fd, tree, "dir");
	offset = dissect_cookie3    (pd, offset, fd, tree, "cookie");
	offset = dissect_cookieverf3(pd, offset, fd, tree);
	offset = dissect_count3     (pd, offset, fd, tree, "dircount");
	offset = dissect_count3     (pd, offset, fd, tree, "maxcount");
	
	return offset;
}


/* RFC 1813, Page 80..83 */
int
dissect_entryplus3(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	proto_item* entry_item = NULL;
	proto_tree* entry_tree = NULL;
	int old_offset = offset;
	char *name;

	if (tree) {
		entry_item = proto_tree_add_item(tree, hf_nfs_readdir_entry, NullTVB,
			offset+0, END_OF_FRAME, FALSE);
		if (entry_item)
			entry_tree = proto_item_add_subtree(entry_item, ett_nfs_readdir_entry);
	}

	offset = dissect_fileid3(pd, offset, fd, entry_tree, "fileid");

	offset = dissect_filename3(pd, offset, fd, entry_tree,
		hf_nfs_readdirplus_entry_name, &name);
	if (entry_item)
		proto_item_set_text(entry_item, "Entry: name %s", name);
	g_free(name);

	offset = dissect_cookie3(pd, offset, fd, entry_tree, "cookie");

	offset = dissect_post_op_attr(pd, offset, fd, entry_tree, "name_attributes");
	offset = dissect_post_op_fh3(pd, offset, fd, entry_tree, "name_handle");

	/* now we know, that a readdirplus entry is shorter */
	if (entry_item) {
		proto_item_set_len(entry_item, offset - old_offset);
	}

	return offset;
}


/* RFC 1813, Page 80..83 */
int
dissect_nfs3_readdirplus_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	guint32 status;
	guint32 eof_value;

	offset = dissect_stat(pd, offset, fd, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_post_op_attr(pd, offset, fd, tree, "dir_attributes");
			offset = dissect_cookieverf3(pd, offset, fd, tree);
			offset = dissect_rpc_list(pd, offset, fd, tree,
				dissect_entryplus3);
			if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
			eof_value = EXTRACT_UINT(pd, offset+0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs_readdir_eof, NullTVB,
					offset+ 0, 4, eof_value);
			offset += 4;
		break;
		default:
			offset = dissect_post_op_attr(pd, offset, fd, tree, "dir_attributes");
		break;
	}

	return offset;
}


/* RFC 1813, Page 84..86 */
int
dissect_nfs3_fsstat_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	guint32 status;
	guint32 invarsec;

	offset = dissect_nfsstat3(pd, offset, fd, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_post_op_attr(pd, offset, fd, tree, "obj_attributes");
			offset = dissect_size3 (pd, offset, fd, tree, "tbytes");
			offset = dissect_size3 (pd, offset, fd, tree, "fbytes");
			offset = dissect_size3 (pd, offset, fd, tree, "abytes");
			offset = dissect_size3 (pd, offset, fd, tree, "tfiles");
			offset = dissect_size3 (pd, offset, fd, tree, "ffiles");
			offset = dissect_size3 (pd, offset, fd, tree, "afiles");
			if (!BYTES_ARE_IN_FRAME(offset, 4)) return offset;
			invarsec = EXTRACT_UINT(pd, offset + 0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs_fsstat_invarsec, NullTVB,
				offset+0, 4, invarsec);
			offset += 4;
		break;
		default:
			offset = dissect_post_op_attr(pd, offset, fd, tree, "obj_attributes");
		break;
	}

	return offset;
}


#define FSF3_LINK        0x0001
#define FSF3_SYMLINK     0x0002
#define FSF3_HOMOGENEOUS 0x0008
#define FSF3_CANSETTIME  0x0010


/* RFC 1813, Page 86..90 */
int
dissect_nfs3_fsinfo_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
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

	offset = dissect_nfsstat3(pd, offset, fd, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_post_op_attr(pd, offset, fd, tree, "obj_attributes");
			if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
			rtmax = EXTRACT_UINT(pd, offset+0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs_fsinfo_rtmax, NullTVB,
				offset+0, 4, rtmax);
			offset += 4;
			if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
			rtpref = EXTRACT_UINT(pd, offset+0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs_fsinfo_rtpref, NullTVB,
				offset+0, 4, rtpref);
			offset += 4;
			if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
			rtmult = EXTRACT_UINT(pd, offset+0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs_fsinfo_rtmult, NullTVB,
				offset+0, 4, rtmult);
			offset += 4;
			if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
			wtmax = EXTRACT_UINT(pd, offset+0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs_fsinfo_wtmax, NullTVB,
				offset+0, 4, wtmax);
			offset += 4;
			if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
			wtpref = EXTRACT_UINT(pd, offset+0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs_fsinfo_wtpref, NullTVB,
				offset+0, 4, wtpref);
			offset += 4;
			if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
			wtmult = EXTRACT_UINT(pd, offset+0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs_fsinfo_wtmult, NullTVB,
				offset+0, 4, wtmult);
			offset += 4;
			if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
			dtpref = EXTRACT_UINT(pd, offset+0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs_fsinfo_dtpref, NullTVB,
				offset+0, 4, dtpref);
			offset += 4;

			offset = dissect_size3   (pd, offset, fd, tree, "maxfilesize");
			offset = dissect_nfstime3(pd, offset, fd, tree, "time_delta");
			if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
			properties = EXTRACT_UINT(pd, offset+0);
			if (tree) {
				properties_item = proto_tree_add_uint(tree,
				hf_nfs_fsinfo_properties,
				NullTVB, offset+0, 4, properties);
				if (properties_item) 
					properties_tree = proto_item_add_subtree(properties_item, ett_nfs_fsinfo_properties);
				if (properties_tree) {
					proto_tree_add_text(properties_tree, NullTVB,
					offset, 4, "%s",
					decode_boolean_bitfield(properties,
					FSF3_CANSETTIME,5,
					"SETATTR can set time on server",
					"SETATTR can't set time on server"));

					proto_tree_add_text(properties_tree, NullTVB,
					offset, 4, "%s",
					decode_boolean_bitfield(properties,
					FSF3_HOMOGENEOUS,5,
					"PATHCONF is valid for all files",
					"PATHCONF should be get for every single file"));

					proto_tree_add_text(properties_tree, NullTVB,
					offset, 4, "%s",
					decode_boolean_bitfield(properties,
					FSF3_SYMLINK,5,
					"File System supports symbolic links",
					"File System does not symbolic hard links"));

					proto_tree_add_text(properties_tree, NullTVB,
					offset, 4, "%s",
					decode_boolean_bitfield(properties,
					FSF3_LINK,5,
					"File System supports hard links",
					"File System does not support hard links"));
				}
			}
			offset += 4;
		break;
		default:
			offset = dissect_post_op_attr(pd, offset, fd, tree, "obj_attributes");
		break;
	}

	return offset;
}


/* RFC 1813, Page 90..92 */
int
dissect_nfs3_pathconf_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	guint32 status;
	guint32 linkmax;
	guint32 name_max;

	offset = dissect_nfsstat3(pd, offset, fd, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_post_op_attr(pd, offset, fd, tree, "obj_attributes");
			if (!BYTES_ARE_IN_FRAME(offset, 4)) return offset;
			linkmax = EXTRACT_UINT(pd, offset + 0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs_pathconf_linkmax, NullTVB,
				offset+0, 4, linkmax);
			offset += 4;
			if (!BYTES_ARE_IN_FRAME(offset, 4)) return offset;
			name_max = EXTRACT_UINT(pd, offset + 0);
			if (tree)
				proto_tree_add_uint(tree, hf_nfs_pathconf_name_max, NullTVB,
				offset+0, 4, name_max);
			offset += 4;
			offset = dissect_rpc_bool(pd, offset, fd, tree, hf_nfs_pathconf_no_trunc);
			offset = dissect_rpc_bool(pd, offset, fd, tree, hf_nfs_pathconf_chown_restricted);
			offset = dissect_rpc_bool(pd, offset, fd, tree, hf_nfs_pathconf_case_insensitive);
			offset = dissect_rpc_bool(pd, offset, fd, tree, hf_nfs_pathconf_case_preserving);
		break;
		default:
			offset = dissect_post_op_attr(pd, offset, fd, tree, "obj_attributes");
		break;
	}

	return offset;
}


/* RFC 1813, Page 92..95 */
int
dissect_nfs3_commit_call(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	offset = old_dissect_nfs_fh3(pd, offset, fd, tree, "file");
	offset = dissect_offset3(pd, offset, fd, tree, "offset");
	offset = dissect_count3 (pd, offset, fd, tree, "count");
	
	return offset;
}


/* RFC 1813, Page 92..95 */
int
dissect_nfs3_commit_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	guint32 status;

	offset = dissect_nfsstat3(pd, offset, fd, tree, &status);
	switch (status) {
		case 0:
			offset = dissect_wcc_data  (pd, offset, fd, tree, "file_wcc");
			offset = dissect_writeverf3(pd, offset, fd, tree);
		break;
		default:
			offset = dissect_wcc_data(pd, offset, fd, tree, "file_wcc");
		break;
	}
		
	return offset;
}

/* 1 missing functions */

/* NFS Version 4 Protocol Draft Specification 07 */

int
dissect_nfs_utf8string(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, int hf, char **string_ret)
{
	/* TODO: this needs to be fixed */
	return dissect_rpc_string(pd, offset, fd, tree, hf, string_ret);
}

int
dissect_nfs_seqid4(const u_char *pd, int offset, frame_data *fd, 
	proto_tree *tree)
{
	guint seqid;

	seqid = EXTRACT_UINT(pd, offset);
	proto_tree_add_uint(tree, hf_nfs_seqid4, NullTVB, offset, 4, seqid);
	offset += 4;

	return offset;
}

int
dissect_nfs_stateid4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	return dissect_rpc_uint64(pd, offset, fd, tree, name);
}

int
dissect_nfs_offset4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	return dissect_rpc_uint64(pd, offset, fd, tree, name);
}

int
dissect_nfs_count4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	return dissect_rpc_uint32(pd, offset, fd, tree, name);
}

int
dissect_nfs_type4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	return dissect_rpc_uint32(pd, offset, fd, tree, name);
}

int
dissect_nfs_linktext4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	return dissect_nfs_utf8string(pd, offset, fd, tree, hf_nfs_linktext4, NULL);
}

int
dissect_nfs_specdata4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	offset = dissect_rpc_uint32(pd, offset, fd, tree, "specdata1");
	offset = dissect_rpc_uint32(pd, offset, fd, tree, "specdata2");

	return offset;
}

int
dissect_nfs_clientid4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	return dissect_rpc_uint64(pd, offset, fd, tree, name);
}

int
dissect_nfs_client_id4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	offset = dissect_nfs_clientid4(pd, offset, fd, tree, "Verifier");
	offset = dissect_nfsdata(pd, offset, fd, tree, hf_nfs_data);

	return offset;
}

static const value_string names_ftype4[] = {
	{	NF4LNK,  "NF4LNK"  },
	{	NF4BLK,	"NF4BLK"  },
	{	NF4CHR,	"NF4CHR"  },
	{	NF4SOCK,	"NF4SOCK"  },
	{	NF4FIFO,	"NF4FIFO"  },
	{	NF4DIR,	"NF4DIR"  },
	{ 0, NULL }
};

int
dissect_nfs_ftype4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	guint ftype4;

	ftype4 = EXTRACT_UINT(pd, offset);
	proto_tree_add_uint(tree, hf_nfs_ftype4, NullTVB, offset, 4, ftype4);
	offset += 4;

	return offset;
}

int
dissect_nfs_component4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	return dissect_nfs_utf8string(pd, offset, fd, tree, hf_nfs_component4, 
		NULL);
}

int
dissect_nfs_lock_type4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	return dissect_rpc_uint32(pd, offset, fd, tree, name);
}

int
dissect_nfs_reclaim4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	return dissect_rpc_uint32(pd, offset, fd, tree, name);
}

int
dissect_nfs_length4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	return dissect_rpc_uint64(pd, offset, fd, tree, name);
}

int
dissect_nfs_opaque4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name);

int
dissect_nfs_lockowner4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	proto_tree *newftree = NULL;
	proto_item *fitem = NULL;

	fitem = proto_tree_add_text(tree, NullTVB, offset, 4, "Owner");

	if (fitem) {
		newftree = proto_item_add_subtree(fitem, ett_nfs_lockowner4);

		if (newftree) {
			offset = dissect_rpc_uint64(pd, offset, fd, newftree, "Client ID");
			offset = dissect_nfs_opaque4(pd, offset, fd, newftree, "Owner");
		}
	}

	return offset;
}

int
dissect_nfs_pathname4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	guint comp_count, i;
	proto_item *fitem = NULL;
	proto_tree *newftree = NULL;

	comp_count=EXTRACT_UINT(pd, offset);
	fitem = proto_tree_add_text(tree, NullTVB, offset, 4, 
		"pathname components (%d)", comp_count);
	offset += 4;

	if (fitem) {
		newftree = proto_item_add_subtree(fitem, ett_nfs_pathname4);

		if (newftree) {
			for (i=0; i<comp_count; i++)
				offset=dissect_nfs_component4(pd, offset, fd, newftree, "comp");
		}
	}

	return offset;
}

int
dissect_nfs_changeid4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	return dissect_rpc_uint64(pd, offset, fd, tree, name);
}

int
dissect_nfs_nfstime4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	offset = dissect_rpc_uint64(pd, offset, fd, tree, "seconds");
	offset = dissect_rpc_uint32(pd, offset, fd, tree, "nseconds");
	return offset;
}

static const value_string names_time_how4[] = {
#define SET_TO_SERVER_TIME4 0
	{	SET_TO_SERVER_TIME4,	"SET_TO_SERVER_TIME4"	},
#define SET_TO_CLIENT_TIME4 1
	{	SET_TO_CLIENT_TIME4,	"SET_TO_CLIENT_TIME4"	},
	{	0,	NULL	},
};

int
dissect_nfs_settime4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	guint32 set_it;

	if (!BYTES_ARE_IN_FRAME(offset, 4)) return offset;

	set_it = EXTRACT_UINT(pd, offset);
	proto_tree_add_uint(tree, hf_nfs_time_how4, NullTVB, offset+0, 
		4, set_it);
	offset += 4;

	if (set_it == SET_TO_CLIENT_TIME4)
		offset = dissect_nfs_nfstime4(pd, offset, fd, tree, NULL);
	
	return offset;
}

static const value_string names_fattr4_expire_type[] = {
#define FH4_PERSISTENT 0x00000000
	{	FH4_PERSISTENT,	"FH4_PERSISTENT"	},
#define FH4_NOEXPIRE_WITH_OPEN 0x00000001
	{	FH4_NOEXPIRE_WITH_OPEN,	"FH4_NOEXPIRE_WITH_OPEN"	},
#define FH4_VOLATILE_ANY 0x00000002
	{	FH4_NOEXPIRE_WITH_OPEN,	"FH4_NOEXPIRE_WITH_OPEN"	},
#define FH4_VOL_MIGRATION 0x00000004
	{	FH4_VOL_MIGRATION,	"FH4_VOL_MIGRATION"	},
#define FH4_VOL_RENAME 0x00000008
	{	FH4_VOL_RENAME,	"FH4_VOL_RENAME"	},
	{	0,	NULL	}
};

int
dissect_nfs_fh_expire_type(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree)
{
	guint32 fattr4_fh_expire_type;

	if (!BYTES_ARE_IN_FRAME(offset, 4)) return offset;

	fattr4_fh_expire_type = EXTRACT_UINT(pd, offset);
	proto_tree_add_uint(tree, hf_nfs_fattr4_expire_type, NullTVB, offset+0, 
		4, fattr4_fh_expire_type);
	offset += 4;

	return offset;
}

int
dissect_nfs_fsid4(const u_char *pd, int offset, frame_data *fd, 
	proto_tree *tree, char *name)
{
	proto_tree *newftree = NULL;
	proto_item *fitem = NULL;

	if (!BYTES_ARE_IN_FRAME(offset, 8)) return offset;

	fitem = proto_tree_add_text(tree, NullTVB, offset, 0, "%s", name);

	if (fitem == NULL) return offset;

	newftree = proto_item_add_subtree(fitem, ett_nfs_fsid4);

	if (newftree == NULL) return offset;

	offset = dissect_rpc_uint64(pd, offset, fd, newftree, "major");
	offset = dissect_rpc_uint64(pd, offset, fd, newftree, "minor");

	return offset;
}

int
dissect_nfs_acetype4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	return dissect_rpc_uint32(pd, offset, fd, tree, name);
}

int
dissect_nfs_aceflag4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	return dissect_rpc_uint32(pd, offset, fd, tree, name);
}

int
dissect_nfs_acemask4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	return dissect_rpc_uint32(pd, offset, fd, tree, name);
}

int
dissect_nfs_nfsace4(const u_char *pd, int offset, frame_data *fd, 
	proto_tree *tree, char *name)
{
	proto_tree *newftree = NULL;
	proto_item *fitem = NULL;
	int nextentry;

	if (!BYTES_ARE_IN_FRAME(offset, 4)) return offset;

	fitem = proto_tree_add_text(tree, NullTVB, offset, 0, "%s", name);

	if (fitem == NULL) return offset;

	newftree = proto_item_add_subtree(fitem, ett_nfs_fsid4);

	if (newftree == NULL) return offset;

	nextentry = EXTRACT_UINT(pd, offset);
	offset = dissect_rpc_uint32(pd, offset, fd, newftree, "data follows?");

	while (nextentry)
	{
		offset = dissect_nfs_acetype4(pd, offset, fd, newftree, "type");
		offset = dissect_nfs_aceflag4(pd, offset, fd, newftree, "flag");
		offset = dissect_nfs_acemask4(pd, offset, fd, newftree, "access_mask");
		offset = dissect_nfs_utf8string(pd, offset, fd, newftree, 
			hf_nfs_who, NULL);
		nextentry = EXTRACT_UINT(pd, offset);
		offset += 4;
	}

	return offset;
}

int
dissect_nfs_fh4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	return old_dissect_nfs_fh3(pd, offset, fd, tree, name);
}

int
dissect_nfs_fs_location4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	proto_tree *newftree = NULL;
	proto_item *fitem = NULL;

	fitem = proto_tree_add_text(tree, NullTVB, offset, 0, "%s", name);

	if (fitem == NULL) return offset;

	newftree = proto_item_add_subtree(fitem, ett_nfs_fs_location4);

	if (newftree == NULL) return offset;

	offset = dissect_nfs_utf8string(pd, offset, fd, tree, hf_nfs_server, NULL);

	return offset;
}

int
dissect_nfs_fs_locations4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	proto_tree *newftree = NULL;
	proto_item *fitem = NULL;
	int nextentry;

	if (!BYTES_ARE_IN_FRAME(offset, 4)) return offset;

	fitem = proto_tree_add_text(tree, NullTVB, offset, 0, "%s", name);

	if (fitem == NULL) return offset;

	newftree = proto_item_add_subtree(fitem, ett_nfs_fs_locations4);

	if (newftree == NULL) return offset;

	offset = dissect_nfs_pathname4(pd, offset, fd, newftree, "fs_root");

	nextentry = EXTRACT_UINT(pd, offset);
	offset = dissect_rpc_uint32(pd, offset, fd, newftree, "data follows?");

	while (nextentry)
	{
		offset = dissect_nfs_fs_location4(pd, offset, fd, newftree, "locations");
		nextentry = EXTRACT_UINT(pd, offset);
		offset += 4;
	}

	return offset;
}

int
dissect_nfs_mode4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	return dissect_mode(pd, offset, fd, tree, name);
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
	{	0,	NULL	}
};


int
dissect_nfs_attributes(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name, int type)
{
	guint32 bitmap_len;
	proto_item *fitem = NULL;
	proto_tree *newftree = NULL;
	proto_item *attr_fitem = NULL;
	proto_tree *attr_newftree = NULL;
	int i, j, fattr;
	guint32 *bitmap;
	guint32 sl;
	int attr_vals_offset;

	if (!BYTES_ARE_IN_FRAME(offset, 4)) return offset;

	bitmap_len = EXTRACT_UINT(pd, offset);
	fitem = proto_tree_add_text(tree, NullTVB, offset, 4 + bitmap_len * 4,
		"%s", "attrmask");
	offset += 4;

	if (fitem == NULL) return offset;

	newftree = proto_item_add_subtree(fitem, ett_nfs_bitmap4);

	if (newftree == NULL) return offset;

	attr_vals_offset = offset + 4 + bitmap_len * 4;

	bitmap = g_malloc(bitmap_len * sizeof(guint32));	
	if (bitmap == NULL) return offset;

	for (i = 0; i < bitmap_len; i++)
	{
		if (!BYTES_ARE_IN_FRAME(offset, 4))
		{
			g_free(bitmap);
			return offset;
		}

		bitmap[i] = EXTRACT_UINT(pd, offset);

		sl = 0x00000001;

		for (j = 0; j < 32; j++)
		{
			fattr = 32 * i + j;

			if (bitmap[i] & sl)
			{
				attr_fitem = proto_tree_add_uint(newftree, hf_nfs_attr, NullTVB, 
					offset, 4, fattr);

				if (attr_fitem == NULL)
					continue;

				attr_newftree = proto_item_add_subtree(attr_fitem, ett_nfs_bitmap4);

				if (attr_newftree == NULL)
					continue;

				if (type == 1)
				{
					/* do a full decode of the arguments for the set flag */
					switch(fattr)
					{
					case FATTR4_TYPE:
						attr_vals_offset = dissect_nfs_ftype4(pd, attr_vals_offset,
							fd, attr_newftree, "fattr4_type");
						break;

					case FATTR4_FH_EXPIRE_TYPE:
						attr_vals_offset = dissect_nfs_fh_expire_type(pd,
							attr_vals_offset, fd, attr_newftree);
						break;

					case FATTR4_CHANGE:
						attr_vals_offset = dissect_nfs_changeid4(pd, attr_vals_offset,
							fd, attr_newftree, "fattr4_change");
						break;

					case FATTR4_SIZE:
						attr_vals_offset = dissect_rpc_uint64(pd, attr_vals_offset,
							fd, attr_newftree, "size");
						break;

					case FATTR4_LINK_SUPPORT:
						attr_vals_offset = dissect_rpc_bool(pd, attr_vals_offset, 
							fd, attr_newftree, hf_nfs_fattr4_link_support);
						break;

					case FATTR4_SYMLINK_SUPPORT:
						attr_vals_offset = dissect_rpc_bool(pd, attr_vals_offset, 
							fd, attr_newftree, hf_nfs_fattr4_symlink_support);
						break;

					case FATTR4_NAMED_ATTR:
						attr_vals_offset = dissect_rpc_bool(pd, attr_vals_offset, 
							fd, attr_newftree, hf_nfs_fattr4_named_attr);
						break;

					case FATTR4_FSID:
						attr_vals_offset = dissect_nfs_fsid4(pd, attr_vals_offset,
							fd, attr_newftree, "fattr4_fsid");
						break;

					case FATTR4_UNIQUE_HANDLES:
						attr_vals_offset = dissect_rpc_bool(pd, attr_vals_offset,
							fd, attr_newftree, hf_nfs_fattr4_unique_handles);
						break;

					case FATTR4_LEASE_TIME:
						attr_vals_offset = dissect_rpc_uint32(pd, attr_vals_offset,
							fd, attr_newftree, "fattr4_lease_time");
						break;

					case FATTR4_RDATTR_ERROR:
						attr_vals_offset = dissect_nfs_nfsstat4(pd, attr_vals_offset,
							fd, attr_newftree, NULL);
						break;

					case FATTR4_ACL:
						attr_vals_offset = dissect_nfs_nfsace4(pd, attr_vals_offset,
							fd, attr_newftree, "fattr4_acl");
						break;

					case FATTR4_ACLSUPPORT:
						attr_vals_offset = dissect_rpc_uint32(pd, attr_vals_offset,
							fd, attr_newftree, "fattr4_aclsupport");
						break;

					case FATTR4_ARCHIVE:
						attr_vals_offset = dissect_rpc_bool(pd, attr_vals_offset,
							fd, attr_newftree, hf_nfs_fattr4_archive);
						break;

					case FATTR4_CANSETTIME:
						attr_vals_offset = dissect_rpc_bool(pd, attr_vals_offset,
							fd, attr_newftree, hf_nfs_fattr4_cansettime);
						break;

					case FATTR4_CASE_INSENSITIVE:
						attr_vals_offset = dissect_rpc_bool(pd, attr_vals_offset,
							fd, attr_newftree, hf_nfs_fattr4_case_insensitive);
						break;

					case FATTR4_CASE_PRESERVING:
						attr_vals_offset = dissect_rpc_bool(pd, attr_vals_offset,
							fd, attr_newftree, hf_nfs_fattr4_case_preserving);
						break;

					case FATTR4_CHOWN_RESTRICTED:
						attr_vals_offset = dissect_rpc_bool(pd, attr_vals_offset,
							fd, attr_newftree, hf_nfs_fattr4_chown_restricted);
						break;

					case FATTR4_FILEID:
						attr_vals_offset = dissect_rpc_uint64(pd, attr_vals_offset,
							fd, attr_newftree, "fattr4_fileid");
						break;

					case FATTR4_FILES_AVAIL:
						attr_vals_offset = dissect_rpc_uint64(pd, attr_vals_offset,
							fd, attr_newftree, "fattr4_files_avail");
						break;

					case FATTR4_FILEHANDLE:
						attr_vals_offset = dissect_nfs_fh4(pd, attr_vals_offset,
							fd, attr_newftree, "fattr4_filehandle");
						break;

					case FATTR4_FILES_FREE:
						attr_vals_offset = dissect_rpc_uint64(pd, attr_vals_offset,
							fd, attr_newftree, "fattr4_files_free");
						break;

					case FATTR4_FILES_TOTAL:
						attr_vals_offset = dissect_rpc_uint64(pd, attr_vals_offset,
							fd, attr_newftree, "fattr4_files_total");
						break;

					case FATTR4_FS_LOCATIONS:
						attr_vals_offset = dissect_nfs_fs_locations4(pd, 
							attr_vals_offset, fd, attr_newftree, 
							"fattr4_fs_locations");
						break;

					case FATTR4_HIDDEN:
						attr_vals_offset = dissect_rpc_bool(pd, attr_vals_offset,
							fd, attr_newftree, hf_nfs_fattr4_hidden);
						break;

					case FATTR4_HOMOGENEOUS:
						attr_vals_offset = dissect_rpc_bool(pd, attr_vals_offset,
							fd, attr_newftree, hf_nfs_fattr4_homogeneous);
						break;

					case FATTR4_MAXFILESIZE:
						attr_vals_offset = dissect_rpc_uint64(pd, attr_vals_offset,
							fd, attr_newftree, "fattr4_maxfilesize");
						break;

					case FATTR4_MAXLINK:
						attr_vals_offset = dissect_rpc_uint32(pd, attr_vals_offset,
							fd, attr_newftree, "fattr4_maxlink");
						break;

					case FATTR4_MAXNAME:
						attr_vals_offset = dissect_rpc_uint32(pd, attr_vals_offset,
							fd, attr_newftree, "fattr4_maxname");
						break;

					case FATTR4_MAXREAD:
						attr_vals_offset = dissect_rpc_uint64(pd, attr_vals_offset,
							fd, attr_newftree, "fattr4_maxread");
						break;

					case FATTR4_MAXWRITE:
						attr_vals_offset = dissect_rpc_uint64(pd, attr_vals_offset,
							fd, attr_newftree, "fattr4_maxwrite");
						break;

					case FATTR4_MIMETYPE:
						attr_vals_offset = dissect_nfs_utf8string(pd, 
							attr_vals_offset, fd, attr_newftree, 
							hf_nfs_fattr4_mimetype, NULL);
						break;
					
					case FATTR4_MODE:
						attr_vals_offset = dissect_nfs_mode4(pd,
							attr_vals_offset, fd, attr_newftree, "fattr4_mode");
						break;

					case FATTR4_NO_TRUNC:
						attr_vals_offset = dissect_rpc_bool(pd, attr_vals_offset,
							fd, attr_newftree, hf_nfs_fattr4_no_trunc);
						break;

					case FATTR4_NUMLINKS:
						attr_vals_offset = dissect_rpc_uint32(pd, attr_vals_offset,
							fd, attr_newftree, "fattr4_numlinks");
						break;

					case FATTR4_OWNER:
						attr_vals_offset = dissect_nfs_utf8string(pd, 
							attr_vals_offset, fd, attr_newftree, hf_nfs_fattr4_owner,
							NULL);
						break;

					case FATTR4_OWNER_GROUP:
						attr_vals_offset = dissect_nfs_utf8string(pd, 
							attr_vals_offset, fd, attr_newftree, 
							hf_nfs_fattr4_owner_group, NULL);
						break;

					case FATTR4_QUOTA_AVAIL_HARD:
						attr_vals_offset = dissect_rpc_uint64(pd, attr_vals_offset,
							fd, attr_newftree, "fattr4_quota_hard");
						break;

					case FATTR4_QUOTA_AVAIL_SOFT:
						attr_vals_offset = dissect_rpc_uint64(pd, attr_vals_offset,
							fd, attr_newftree, "fattr4_quota_soft");
						break;

					case FATTR4_QUOTA_USED:
						attr_vals_offset = dissect_rpc_uint64(pd, attr_vals_offset,
							fd, attr_newftree, "fattr4_quota_used");
						break;

					case FATTR4_RAWDEV:
						attr_vals_offset = dissect_nfs_specdata4(pd, attr_vals_offset,
							fd, attr_newftree, "fattr4_rawdev");
						break;

					case FATTR4_SPACE_AVAIL:
						attr_vals_offset = dissect_rpc_uint64(pd, attr_vals_offset,
							fd, attr_newftree, "fattr4_space_avail");
						break;

					case FATTR4_SPACE_FREE:
						attr_vals_offset = dissect_rpc_uint64(pd, attr_vals_offset,
							fd, attr_newftree, "fattr4_space_free");
						break;

					case FATTR4_SPACE_TOTAL:
						attr_vals_offset = dissect_rpc_uint64(pd, attr_vals_offset,
							fd, attr_newftree, "fattr4_space_total");
						break;

					case FATTR4_SPACE_USED:
						attr_vals_offset = dissect_rpc_uint64(pd, attr_vals_offset,
							fd, attr_newftree, "fattr4_space_used");
						break;
					
					case FATTR4_SYSTEM:
						attr_vals_offset = dissect_rpc_bool(pd, attr_vals_offset,
							fd, attr_newftree, hf_nfs_fattr4_system);
						break;

					case FATTR4_TIME_ACCESS:
					case FATTR4_TIME_BACKUP:
					case FATTR4_TIME_CREATE:
					case FATTR4_TIME_DELTA:
					case FATTR4_TIME_METADATA:
					case FATTR4_TIME_MODIFY:
						attr_vals_offset = dissect_nfs_nfstime4(pd, attr_vals_offset,
							fd, attr_newftree, "nfstime4");
						break;

					case FATTR4_TIME_ACCESS_SET:
					case FATTR4_TIME_MODIFY_SET:
						attr_vals_offset = dissect_nfs_settime4(pd, attr_vals_offset, 
							fd, attr_newftree, "settime4");
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

	g_free(bitmap);

	return offset;
}

int
dissect_nfs_attrlist4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree)
{
	return dissect_nfsdata(pd, offset, fd, tree, hf_nfs_attrlist4);
}

int
dissect_nfs_fattr4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	proto_tree *newftree = NULL;
	proto_item *fitem = NULL;

	fitem = proto_tree_add_text(tree, NullTVB, offset, 4, "obj_attributes");

	if (fitem == NULL) return offset;

	newftree = proto_item_add_subtree(fitem, ett_nfs_fattr4);

	if (newftree == NULL) return offset;

	offset = dissect_nfs_attributes(pd, offset, fd, newftree, name, 1);
	offset = dissect_nfs_attrlist4(pd, offset, fd, newftree);

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

int
dissect_nfs_open4_share_access(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree)
{
	guint share_access;

	share_access = EXTRACT_UINT(pd, offset);
	proto_tree_add_uint(tree, hf_nfs_open4_share_access, NullTVB, offset, 4, 
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

int
dissect_nfs_open4_share_deny(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree)
{
	guint deny_access;

	deny_access = EXTRACT_UINT(pd, offset);
	proto_tree_add_uint(tree, hf_nfs_open4_share_deny, NullTVB, offset, 4,
		deny_access);
	offset += 4;

	return offset;
}

int
dissect_nfs_open_claim_delegate_cur4(const u_char *pd, int offset,
	frame_data *fd, proto_tree *tree, char *name)
{
	offset = dissect_nfs_pathname4(pd, offset, fd, tree, "file");
	offset = dissect_nfs_stateid4(pd, offset, fd, tree, "delegate_stateid");
	return offset;
}

#define CLAIM_NULL			0
#define CLAIM_PREVIOUS			1
#define CLAIM_DELEGATE_CUR		2
#define CLAIM_DELEGATE_PREV		3

static const value_string names_claim_type4[] = {
	{	CLAIM_NULL,  		"CLAIM_NULL"  },
	{	CLAIM_PREVIOUS, 	"CLAIM_PREVIOUS" },
	{	CLAIM_DELEGATE_CUR, 	"CLAIM_DELEGATE_CUR" },
	{	CLAIM_DELEGATE_PREV,	"CLAIM_DELEGATE_PREV" },
	{ 0, NULL }
};

int
dissect_nfs_open_claim4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	guint open_claim_type4;
	proto_item *fitem = NULL;
	proto_tree *newftree = NULL;

	open_claim_type4 = EXTRACT_UINT(pd, offset);
	fitem = proto_tree_add_uint(tree, hf_nfs_open_claim_type4, NullTVB,
		offset+0, 4, open_claim_type4);
	offset += 4;

	if (fitem) {
		newftree = proto_item_add_subtree(fitem, ett_nfs_open_claim4);

		if (newftree) {

			switch(open_claim_type4)
			{
			case CLAIM_NULL:
				offset = dissect_nfs_pathname4(pd, offset, fd, newftree, "file");
				break;

			case CLAIM_PREVIOUS:
				offset = dissect_rpc_uint32(pd, offset, fd, newftree, 
					"delegate_type");
				break;

			case CLAIM_DELEGATE_CUR:
				offset = dissect_nfs_open_claim_delegate_cur4(pd, offset, fd, 
					newftree, "delegate_cur_info");
				break;

			case CLAIM_DELEGATE_PREV:
				offset = dissect_nfs_pathname4(pd, offset, fd, newftree, 
					"file_delegate_prev");
				break;

			default:
				break;
			}
		}
	}

	return offset;
}

int
dissect_nfs_verifier4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name);

int
dissect_nfs_createhow4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	guint mode;

	/* This is intentional; we're using the same flags as NFSv3 */
	mode = EXTRACT_UINT(pd, offset);
	proto_tree_add_uint(tree, hf_nfs_createmode3, NullTVB, offset, 4, mode);
	offset += 4;
	
	switch(mode)
	{
	case UNCHECKED:		/* UNCHECKED4 */
	case GUARDED:		/* GUARDED4 */
		offset = dissect_nfs_fattr4(pd, offset, fd, tree, "createattrs");
		break;

	case EXCLUSIVE:		/* EXCLUSIVE4 */
		offset = dissect_nfs_verifier4(pd, offset, fd, tree, "createverf");
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

int
dissect_nfs_openflag4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree)
{
	guint opentype4;
	proto_item *fitem = NULL;
	proto_tree *newftree = NULL;

	opentype4 = EXTRACT_UINT(pd, offset);
	fitem = proto_tree_add_uint(tree, hf_nfs_opentype4, NullTVB,
		offset+0, 4, opentype4);
	offset += 4;

	if (fitem) {
		newftree = proto_item_add_subtree(fitem, ett_nfs_opentype4);

		if (newftree) {

			switch(opentype4)
			{
			case OPEN4_CREATE:
				offset = dissect_nfs_createhow4(pd, offset, fd, newftree, "how");
				break;

			default:
				break;
			}
		}
	}

	return offset;
}

int
dissect_nfs_verifier4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	return dissect_rpc_uint64(pd, offset, fd, tree, name);
}


int
dissect_nfs_cookie4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	return dissect_rpc_uint64(pd, offset, fd, tree, name);
}

int
dissect_nfs_cookieverf4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	return dissect_rpc_uint64(pd, offset, fd, tree, name);
}


int
dissect_nfs_clientaddr4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	offset = dissect_nfs_opaque4(pd, offset, fd, tree, "network id");
	offset = dissect_nfs_opaque4(pd, offset, fd, tree, "universal address");

	return offset;
}
	

int
dissect_nfs_cb_client4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	offset = dissect_rpc_uint32(pd, offset, fd, tree, "cb_program");
	offset = dissect_nfs_clientaddr4(pd, offset, fd, tree, "cb_location");

	return offset;
}

int
dissect_nfs_stable_how4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	return dissect_rpc_uint32(pd, offset, fd, tree, "stable_how4");
}

int
dissect_nfs_opaque4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	return dissect_nfsdata(pd, offset, fd, tree, hf_nfs_data);
}

/* There is probably a better (built-in?) way to do this, but this works
 * for now.
 */

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
	{ 0, NULL }
};

guint *nfsv4_operation_ett[] =
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
	 &ett_nfs_write4 
};

int
dissect_nfs_dirlist4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	proto_tree *newftree = NULL;
	guint nextentry;

	newftree = proto_item_add_subtree(tree, ett_nfs_dirlist4);
	if (newftree==NULL) return offset;

	nextentry = EXTRACT_UINT(pd, offset);
	offset = dissect_rpc_uint32(pd, offset, fd, newftree, "data follows?");

	while (nextentry)
	{
		offset = dissect_nfs_cookie4(pd, offset, fd, newftree, "cookie");
		offset = dissect_nfs_component4(pd, offset, fd, newftree, "name");
		offset = dissect_nfs_fattr4(pd, offset, fd, newftree, "attrs");
		nextentry = EXTRACT_UINT(pd, offset);
		offset += 4;
	}

	return dissect_rpc_uint32(pd, offset, fd, newftree, "eof");
}

int
dissect_nfs_change_info4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	proto_tree *newftree = NULL;
	proto_tree *fitem = NULL;

	fitem = proto_tree_add_text(tree, NullTVB, offset, 0, "%s", name);

	if (fitem) {
		newftree=proto_item_add_subtree(fitem, ett_nfs_change_info4);

		if (newftree) {
			offset = dissect_rpc_bool(pd, offset, fd, newftree, 
				hf_nfs_change_info4_atomic);
			offset = dissect_nfs_changeid4(pd, offset, fd, newftree, "before");
			offset = dissect_nfs_changeid4(pd, offset, fd, newftree, "after");
		}
	}

	return offset;
}

int
dissect_nfs_lock4denied(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	offset = dissect_nfs_lockowner4(pd, offset, fd, tree, "owner");
	offset = dissect_nfs_offset4(pd, offset, fd, tree, "offset");
	return dissect_nfs_length4(pd, offset, fd, tree, "length");
}


int
dissect_nfs_ace4(const u_char *pd, int offset, frame_data *fd, 
	proto_tree *tree, char *name)
{
	offset = dissect_nfs_acetype4(pd, offset, fd, tree, "type");
	offset = dissect_nfs_aceflag4(pd, offset, fd, tree, "flag");
	offset = dissect_nfs_acemask4(pd, offset, fd, tree, "access_mask");
	return dissect_nfs_utf8string(pd, offset, fd, tree, hf_nfs_ace4, NULL);
}

static const value_string names_open4_result_flags[] = {
#define OPEN4_RESULT_MLOCK 0x00000001
	{ OPEN4_RESULT_MLOCK, "OPEN4_RESULT_MLOCK" }, 
#define OPEN4_RESULT_CONFIRM 0x00000002
	{ OPEN4_RESULT_CONFIRM, "OPEN4_RESULT_CONFIRM" },
	{ 0, NULL }
};

int 
dissect_nfs_open4_rflags(const u_char *pd, int offset, frame_data *fd, 
	proto_tree *tree)
{
	guint rflags;

	rflags = EXTRACT_UINT(pd, offset);
	proto_tree_add_uint(tree, hf_nfs_open4_result_flags, NullTVB, offset, 4,
		rflags);
	offset += 4;

	return offset;
}

int
dissect_nfs_open_read_delegation4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree)
{
	offset = dissect_nfs_stateid4(pd, offset, fd, tree, "stateid");
	offset = dissect_rpc_uint32(pd, offset, fd, tree, "recall?");
	return dissect_nfs_ace4(pd, offset, fd, tree, "permissions");
}

int
dissect_nfs_modified_limit4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	offset = dissect_rpc_uint32(pd, offset, fd, tree, "num_blocks");
	return dissect_rpc_uint32(pd, offset, fd, tree, "bytes_per_block");
}

#define NFS_LIMIT_SIZE						1
#define NFS_LIMIT_BLOCKS					2
static const value_string names_limit_by4[] = {
	{	NFS_LIMIT_SIZE,  "NFS_LIMIT_SIZE"  },
	{	NFS_LIMIT_BLOCKS, "NFS_LIMIT_BLOCKS" },
	{ 0, NULL }
};

int
dissect_nfs_space_limit4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	guint limitby;

	limitby = EXTRACT_UINT(pd, offset);
	proto_tree_add_uint(tree, hf_nfs_limit_by4, NullTVB, offset+0, 4, limitby);
	offset += 4;

	switch(limitby)
	{
	case NFS_LIMIT_SIZE:
		offset = dissect_rpc_uint64(pd, offset, fd, tree, "filesize");
		break;

	case NFS_LIMIT_BLOCKS:
		offset = dissect_nfs_modified_limit4(pd, offset, fd, tree, "mod_blocks");
		break;

	default:
		break;
	}

	return offset;
}

int
dissect_nfs_open_write_delegation4(const u_char *pd, int offset, 
	frame_data *fd, proto_tree *tree)
{
	offset = dissect_nfs_stateid4(pd, offset, fd, tree, "stateid");
	offset = dissect_rpc_bool(pd, offset, fd, tree, hf_nfs_recall);
	offset = dissect_nfs_space_limit4(pd, offset, fd, tree, "space_limit");
	return dissect_nfs_ace4(pd, offset, fd, tree, "permissions");
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

int
dissect_nfs_open_delegation4(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree, char *name)
{
	guint delegation_type;
	proto_tree *newftree = NULL;
	proto_item *fitem = NULL;

	delegation_type = EXTRACT_UINT(pd, offset);
	proto_tree_add_uint(tree, hf_nfs_open_delegation_type4, NullTVB, offset+0, 
		4, delegation_type);
	offset += 4;

	if (fitem) {
		newftree = proto_item_add_subtree(fitem, ett_nfs_open_delegation4);

		switch(delegation_type)
		{
		case OPEN_DELEGATE_NONE:
			break;

		case OPEN_DELEGATE_READ:
			offset = dissect_nfs_open_read_delegation4(pd, offset, fd, newftree);
			break;

		case OPEN_DELEGATE_WRITE:
			offset = dissect_nfs_open_write_delegation4(pd, offset, fd, newftree);
			break;

		default:
			break;
		}
	}

	return offset;
}


int
dissect_nfs_argop4(const u_char *pd, int offset, frame_data *fd, 
	proto_tree *tree, char *name)
{
	guint ops, ops_counter;
	guint opcode;
	proto_item *fitem;
	proto_tree *ftree = NULL;
	proto_tree *newftree = NULL;

	if (!BYTES_ARE_IN_FRAME(offset, 4)) return offset;

	ops = EXTRACT_UINT(pd, offset+0);

	fitem = proto_tree_add_text(tree, NullTVB, offset, 4, 
		"Operations (count: %d)", ops);
	offset += 4;

	if (fitem == NULL) return offset;

	ftree = proto_item_add_subtree(fitem, ett_nfs_argop4);

	if (ftree == NULL) return offset;

	for (ops_counter=0; ops_counter<ops; ops_counter++)
	{
		if (!BYTES_ARE_IN_FRAME(offset, 4)) return offset;

		opcode = EXTRACT_UINT(pd, offset);
		fitem = proto_tree_add_uint(ftree, hf_nfs_argop4, NullTVB, offset, 4, 
			opcode);
		offset += 4;

		if (opcode < NFS4_OP_ACCESS || opcode >NFS4_OP_WRITE)
			break;

		if (fitem == NULL)	break;

		newftree = proto_item_add_subtree(fitem, *nfsv4_operation_ett[opcode-3]);

		if (newftree == NULL)	break;


		switch(opcode)
		{
		case NFS4_OP_ACCESS:
			offset = dissect_access(pd, offset, fd, newftree, "access");
			break;

		case NFS4_OP_CLOSE:
			offset = dissect_nfs_seqid4(pd, offset, fd, newftree);
			offset = dissect_nfs_stateid4(pd, offset, fd, newftree, "stateid");
			break;

		case NFS4_OP_COMMIT:
			offset = dissect_nfs_offset4(pd, offset, fd, newftree, "offset");
			offset = dissect_nfs_count4(pd, offset, fd, newftree, "count");
			break;

		case NFS4_OP_CREATE:
			{
				guint create_type;

				offset = dissect_nfs_component4(pd, offset, fd, newftree, 
					"objname");

				create_type = EXTRACT_UINT(pd, offset);
				offset = dissect_nfs_ftype4(pd, offset, fd, newftree, "type");

				switch(create_type)
				{
				case NF4LNK:
					offset = dissect_nfs_linktext4(pd, offset, fd, newftree, 
						"linkdata");
					break;
				
				case NF4BLK:
				case NF4CHR:
					offset = dissect_nfs_specdata4(pd, offset, fd, 
						newftree, "devdata");
					break;

				case NF4SOCK:
				case NF4FIFO:
				case NF4DIR:
					break;

				default:
					break;
				}
			}
			break;

		case NFS4_OP_DELEGPURGE:
			offset = dissect_nfs_clientid4(pd, offset, fd, newftree, "Client ID");
			break;

		case NFS4_OP_DELEGRETURN:
			offset = dissect_nfs_stateid4(pd, offset, fd, newftree, "stateid");
			break;

		case NFS4_OP_GETATTR:
			offset = dissect_nfs_attributes(pd, offset, fd, newftree, "attr_request", 0);
			break;

		case NFS4_OP_GETFH:
			break;

		case NFS4_OP_LINK:
			offset = dissect_nfs_component4(pd, offset, fd, newftree, "newname");
			break;

		case NFS4_OP_LOCK:
			offset = dissect_nfs_lock_type4(pd, offset, fd, newftree, "locktype");
			offset = dissect_nfs_seqid4(pd, offset, fd, newftree);
			offset = dissect_nfs_reclaim4(pd, offset, fd, newftree, "reclaim");
			offset = dissect_nfs_stateid4(pd, offset, fd, newftree, "stateid");
			offset = dissect_nfs_offset4(pd, offset, fd, newftree, "offset");
			offset = dissect_nfs_length4(pd, offset, fd, newftree, "length");
			break;

		case NFS4_OP_LOCKT:
			offset = dissect_nfs_lock_type4(pd, offset, fd, newftree, "locktype");
			offset = dissect_nfs_lockowner4(pd, offset, fd, newftree, "owner");
			offset = dissect_nfs_offset4(pd, offset, fd, newftree, "offset");
			offset = dissect_nfs_length4(pd, offset, fd, newftree, "length");
			break;

		case NFS4_OP_LOCKU:
			offset = dissect_nfs_lock_type4(pd, offset, fd, newftree, "type");
			offset = dissect_nfs_seqid4(pd, offset, fd, newftree);
			offset = dissect_nfs_stateid4(pd, offset, fd, newftree, "stateid");
			offset =	dissect_nfs_offset4(pd, offset, fd, newftree, "offset");
			offset = dissect_nfs_length4(pd, offset, fd, newftree, "length");
			break;

		case NFS4_OP_LOOKUP:
			offset = dissect_nfs_pathname4(pd, offset, fd, newftree, "path");
			break;

		case NFS4_OP_LOOKUPP:
			break;

		case NFS4_OP_NVERIFY:
			offset = dissect_nfs_fattr4(pd, offset, fd, newftree, 
				"obj_attributes");
			break;

		case NFS4_OP_OPEN:
			offset = dissect_nfs_open_claim4(pd, offset, fd, newftree, "claim");
			offset = dissect_nfs_openflag4(pd, offset, fd, newftree);
			offset = dissect_nfs_lockowner4(pd, offset, fd, newftree, "Owner");
			offset = dissect_nfs_seqid4(pd, offset, fd, newftree);
			offset = dissect_nfs_open4_share_access(pd, offset, fd, newftree);
			offset = dissect_nfs_open4_share_deny(pd, offset, fd, newftree);
			break;

		case NFS4_OP_OPENATTR:
			break;

		case NFS4_OP_OPEN_CONFIRM:
			offset = dissect_nfs_seqid4(pd, offset, fd, newftree);
			offset = dissect_nfs_verifier4(pd, offset, fd, newftree, 
				"verifier");
			break;

		case NFS4_OP_OPEN_DOWNGRADE:
			offset = dissect_nfs_stateid4(pd, offset, fd, newftree, "stateid");
			offset = dissect_nfs_seqid4(pd, offset, fd, newftree);
			offset = dissect_nfs_open4_share_access(pd, offset, fd, newftree);
			offset = dissect_nfs_open4_share_deny(pd, offset, fd, newftree);
			break;

		case NFS4_OP_PUTFH:
			offset = dissect_nfs_fh4(pd, offset, fd, newftree, "filehandle");
			break;

		case NFS4_OP_PUTPUBFH:
		case NFS4_OP_PUTROOTFH:
			break;

		case NFS4_OP_READ:
			offset = dissect_nfs_stateid4(pd, offset, fd, newftree, "stateid");
			offset = dissect_nfs_offset4(pd, offset, fd, newftree, "offset");
			offset = dissect_nfs_count4(pd, offset, fd, newftree, "count");
			break;

		case NFS4_OP_READDIR:
			offset = dissect_nfs_cookie4(pd, offset, fd, newftree, "cookie");
			offset = dissect_nfs_cookieverf4(pd, offset, fd, newftree, 
				"cookieverf");
			offset = dissect_nfs_count4(pd, offset, fd, newftree, "dircount");
			offset = dissect_nfs_count4(pd, offset, fd, newftree, "maxcount");
			offset = dissect_nfs_attributes(pd, offset, fd, newftree, "attr", 0);
			break;

		case NFS4_OP_READLINK:
			break;

		case NFS4_OP_REMOVE:
			offset = dissect_nfs_component4(pd, offset, fd, newftree, "target");
			break;

		case NFS4_OP_RENAME:
			offset = dissect_nfs_component4(pd, offset, fd, newftree, "oldname");
			offset = dissect_nfs_component4(pd, offset, fd, newftree, "newname");
			break;

		case NFS4_OP_RENEW:
			offset = dissect_nfs_stateid4(pd, offset, fd, newftree, "stateid");
			break;
	
		case NFS4_OP_RESTOREFH:
		case NFS4_OP_SAVEFH:
			break;

		case NFS4_OP_SECINFO:
			offset = dissect_nfs_component4(pd, offset, fd, newftree, "name");
			break;

		case NFS4_OP_SETATTR:
			offset = dissect_nfs_stateid4(pd, offset, fd, newftree, "stateid");
			offset = dissect_nfs_fattr4(pd, offset, fd, newftree, 
				"obj_attributes");
			break;

		case NFS4_OP_SETCLIENTID:
			{
				proto_tree *client_tree = NULL;

				fitem = proto_tree_add_text(newftree, NullTVB, offset, 0, "Client");

				if (fitem) {
					client_tree = proto_item_add_subtree(fitem, 
						ett_nfs_client_id4);

					if (newftree)
						offset = dissect_nfs_client_id4(pd, offset, fd, 
							client_tree, "client");
				}

				fitem = proto_tree_add_text(newftree, NullTVB, offset, 0,
					"Callback");
				if (fitem) {
					newftree = proto_item_add_subtree(fitem, ett_nfs_cb_client4);
					if (newftree)
						offset = dissect_nfs_cb_client4(pd, offset, fd, newftree, 
							"callback");
				}
			}
			break;

		case NFS4_OP_SETCLIENTID_CONFIRM:
			offset = dissect_nfs_verifier4(pd, offset, fd, newftree,
						"setclientid_confirm");
			break;
		
		case NFS4_OP_VERIFY:
			offset = dissect_nfs_fattr4(pd, offset, fd, newftree, 
						"obj_attributes");
			break;

		case NFS4_OP_WRITE:
			offset = dissect_nfs_stateid4(pd, offset, fd, newftree, "stateid");
			offset = dissect_nfs_offset4(pd, offset, fd, newftree, "offset");
			offset = dissect_nfs_stable_how4(pd, offset, fd, newftree, "stable");
			offset = dissect_nfs_opaque4(pd, offset, fd, newftree, "data");
			break;
		
		default:
			break;
		}
	}

	return offset;
}

int
dissect_nfs4_compound_call(const u_char* pd, int offset, frame_data* fd, 
	proto_tree* tree)
{
	offset = dissect_nfs_utf8string(pd, offset, fd, tree, hf_nfs_tag4, NULL);
	offset = dissect_rpc_uint32(pd, offset, fd, tree, "minorversion");
	offset = dissect_nfs_argop4(pd, offset, fd, tree, "arguments");

	return offset;
}

int
dissect_nfs_resop4(const u_char *pd, int offset, frame_data *fd, 
	proto_tree *tree, char *name)
{
	guint ops, ops_counter;
	guint opcode;
	proto_item *fitem;
	proto_tree *ftree = NULL;
	proto_tree *newftree = NULL;
	guint32 status;

	ops = EXTRACT_UINT(pd, offset+0);

	fitem = proto_tree_add_text(tree, NullTVB, offset, 4, 
		"Operations (count: %d)", ops);
	offset += 4;

	if (fitem == NULL)	return offset;

	ftree = proto_item_add_subtree(fitem, ett_nfs_resop4);

	if (ftree == NULL)	return offset;		/* error adding new subtree */

	for (ops_counter = 0; ops_counter < ops; ops_counter++)
	{
		if (!BYTES_ARE_IN_FRAME(offset, 4)) return offset;

		opcode = EXTRACT_UINT(pd, offset);

		if (opcode < NFS4_OP_ACCESS || opcode > NFS4_OP_WRITE)	break;

		if (!BYTES_ARE_IN_FRAME(offset, 4)) return offset;

		fitem = proto_tree_add_uint(ftree, hf_nfs_resop4, NullTVB, offset, 4, 
			opcode);
		offset += 4;

		if (fitem == NULL)	break;		/* error adding new item to tree */

		newftree = proto_item_add_subtree(fitem, *nfsv4_operation_ett[opcode-3]);

		if (newftree == NULL)
			break;		/* error adding new subtree to operation item */

		offset = dissect_nfs_nfsstat4(pd, offset, fd, newftree, &status);

		if (status != NFS4_OK && 
			(opcode != NFS4_OP_LOCK || opcode != NFS4_OP_LOCKT))
			continue;

		/* These parsing routines are only executed if the status is NFS4_OK */
		switch(opcode)
		{
		case NFS4_OP_ACCESS:
			offset = dissect_access(pd, offset, fd, newftree, "Supported");
			offset = dissect_access(pd, offset, fd, newftree, "Access");
			break;

		case NFS4_OP_CLOSE:
			offset = dissect_nfs_stateid4(pd, offset, fd, newftree, "stateid");
			break;

		case NFS4_OP_COMMIT:
			offset = dissect_nfs_verifier4(pd, offset, fd, newftree, "writeverf");
			break;

		case NFS4_OP_CREATE:
			offset = dissect_nfs_change_info4(pd, offset, fd, newftree, 
				"change_info");
			break;

		case NFS4_OP_DELEGPURGE:
			/* void */
			break;

		case NFS4_OP_DELEGRETURN:
			/* void */
			break;

		case NFS4_OP_GETATTR:
			offset = dissect_nfs_fattr4(pd, offset, fd, newftree, 
				"obj_attributes");
			break;

		case NFS4_OP_GETFH:
			offset = dissect_nfs_fh4(pd, offset, fd, newftree, "Filehandle");
			break;

		case NFS4_OP_LINK:
			offset = dissect_nfs_change_info4(pd, offset, fd, newftree, 
				"change_info");
			break;

		case NFS4_OP_LOCK:
		case NFS4_OP_LOCKT:
			if (status==NFS4_OK)
				offset = dissect_nfs_stateid4(pd, offset, fd, newftree, 
					"stateid");
			else
			if (status==NFS4ERR_DENIED)
				offset = dissect_nfs_lock4denied(pd, offset, fd, newftree, 
					"denied");
			break;

		case NFS4_OP_LOCKU:
			offset = dissect_nfs_stateid4(pd, offset, fd, newftree, "stateid");
			break;

		case NFS4_OP_LOOKUP:
			/* void */
			break;

		case NFS4_OP_LOOKUPP:
			/* void */
			break;

		case NFS4_OP_NVERIFY:
			/* void */
			break;

		case NFS4_OP_OPEN:
			offset = dissect_nfs_stateid4(pd, offset, fd, newftree, "stateid");
			offset = dissect_nfs_change_info4(pd, offset, fd, newftree, 
				"change_info");
			offset = dissect_nfs_open4_rflags(pd, offset, fd, newftree);
			offset = dissect_nfs_verifier4(pd, offset, fd, newftree, 
				"verifier");
			offset = dissect_nfs_open_delegation4(pd, offset, fd, newftree, 
				"delegation");
			break;

		case NFS4_OP_OPENATTR:
			/* void */
			break;

		case NFS4_OP_OPEN_CONFIRM:
		case NFS4_OP_OPEN_DOWNGRADE:
			offset = dissect_nfs_stateid4(pd, offset, fd, newftree, "stateid");
			break;

		case NFS4_OP_PUTFH:
			/* void */
			break;

		case NFS4_OP_PUTPUBFH:
			/* void */
			break;
		
		case NFS4_OP_PUTROOTFH:
			/* void */
			break;

		case NFS4_OP_READ:
			offset = dissect_rpc_uint32(pd, offset, fd, newftree, "eof?");
			offset = dissect_nfs_opaque4(pd, offset, fd, newftree, "data");
			break;

		case NFS4_OP_READDIR:
			offset = dissect_nfs_verifier4(pd, offset, fd, newftree, 
				"cookieverf");
			offset = dissect_nfs_dirlist4(pd, offset, fd, newftree, "reply");
			break;

		case NFS4_OP_READLINK:
			offset = dissect_nfs_linktext4(pd, offset, fd, newftree, "link");	
			break;

		case NFS4_OP_REMOVE:
			offset = dissect_nfs_change_info4(pd, offset, fd, newftree, 
				"change_info");
			break;

		case NFS4_OP_RENAME:
			offset = dissect_nfs_change_info4(pd, offset, fd, newftree, 
				"source_cinfo");
			offset = dissect_nfs_change_info4(pd, offset, fd, newftree,
				"target_cinfo");
			break;

		case NFS4_OP_RENEW:
			/* void */
			break;

		case NFS4_OP_RESTOREFH:
			/* void */
			break;

		case NFS4_OP_SAVEFH:
			/* void */
			break;

		case NFS4_OP_SECINFO:
			offset = dissect_rpc_uint32(pd, offset, fd, newftree, "flavor");
			offset = dissect_nfs_opaque4(pd, offset, fd, newftree, "flavor_info");
			break;

		case NFS4_OP_SETATTR:
			offset = dissect_nfs_attributes(pd, offset, fd, newftree, "attrsset",
				0);
			break;

		case NFS4_OP_SETCLIENTID:
			if (status == NFS4_OK)
			{
				offset = dissect_nfs_clientid4(pd, offset, fd, newftree, 
					"Client ID");
				offset = dissect_nfs_verifier4(pd, offset, fd, newftree,
					"setclientid_confirm");
			}
			else
			if (status == NFS4ERR_CLID_INUSE)
			{
				offset = dissect_nfs_clientaddr4(pd, offset, fd, newftree,
					"client_using");
			}
			break;

		case NFS4_OP_SETCLIENTID_CONFIRM:
			/* void */
			break;

		case NFS4_OP_VERIFY:
			/* void */
			break;

		case NFS4_OP_WRITE:
			offset = dissect_nfs_count4(pd, offset, fd, newftree, "count");
			offset = dissect_nfs_stable_how4(pd, offset, fd, newftree, 
				"committed");
			offset = dissect_nfs_verifier4(pd, offset, fd, newftree,
				"writeverf");
			break;

		default:
			break;
		}
	}

	return offset;
}

int
dissect_nfs4_compound_reply(const u_char* pd, int offset, frame_data* fd, 
	proto_tree* tree)
{
	guint32 status;

	offset = dissect_nfs_nfsstat4(pd, offset, fd, tree, &status);
	offset = dissect_nfs_utf8string(pd, offset, fd, tree, hf_nfs_tag4, NULL);
	offset = dissect_nfs_resop4(pd, offset, fd, tree, "arguments");

	return offset;
}


/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: type of arguments is "void". */
static const old_vsff nfs3_proc[] = {
	{ 0,	"NULL",		/* OK */
	NULL,				NULL },
	{ 1,	"GETATTR",	/* OK */
	dissect_nfs3_getattr_call,	dissect_nfs3_getattr_reply },
	{ 2,	"SETATTR",	/* OK */
	dissect_nfs3_setattr_call,	dissect_nfs3_setattr_reply },
	{ 3,	"LOOKUP",	/* OK */
	dissect_nfs3_lookup_call,	dissect_nfs3_lookup_reply },
	{ 4,	"ACCESS",	/* OK */
	dissect_nfs3_access_call,	dissect_nfs3_access_reply },
	{ 5,	"READLINK",	/* OK */
	dissect_nfs3_nfs_fh3_call,	dissect_nfs3_readlink_reply },
	{ 6,	"READ",		/* OK */
	dissect_nfs3_read_call,		dissect_nfs3_read_reply },
	{ 7,	"WRITE",	/* OK */
	dissect_nfs3_write_call,	dissect_nfs3_write_reply },
	{ 8,	"CREATE",	/* OK */
	dissect_nfs3_create_call,	dissect_nfs3_create_reply },
	{ 9,	"MKDIR",	/* OK */
	dissect_nfs3_mkdir_call,	dissect_nfs3_create_reply },
	{ 10,	"SYMLINK",	/* OK */
	dissect_nfs3_symlink_call,	dissect_nfs3_create_reply },
	{ 11,	"MKNOD",	/* OK */
	dissect_nfs3_mknod_call,	dissect_nfs3_create_reply },
	{ 12,	"REMOVE",	/* OK */
	dissect_nfs3_diropargs3_call,	dissect_nfs3_remove_reply },
	{ 13,	"RMDIR",	/* OK */
	dissect_nfs3_diropargs3_call,	dissect_nfs3_remove_reply },
	{ 14,	"RENAME",	/* OK */
	dissect_nfs3_rename_call,	dissect_nfs3_rename_reply },
	{ 15,	"LINK",		/* OK */
	dissect_nfs3_link_call,		dissect_nfs3_link_reply },
	{ 16,	"READDIR",	/* OK */
	dissect_nfs3_readdir_call,	dissect_nfs3_readdir_reply },
	{ 17,	"READDIRPLUS",	/* OK */
	dissect_nfs3_readdirplus_call,	dissect_nfs3_readdirplus_reply },
	{ 18,	"FSSTAT",	/* OK */
	dissect_nfs3_nfs_fh3_call,	dissect_nfs3_fsstat_reply },
	{ 19,	"FSINFO",	/* OK */
	dissect_nfs3_nfs_fh3_call,	dissect_nfs3_fsinfo_reply },
	{ 20,	"PATHCONF",	/* OK */
	dissect_nfs3_nfs_fh3_call,	dissect_nfs3_pathconf_reply },
	{ 21,	"COMMIT",	/* OK */
	dissect_nfs3_commit_call,	dissect_nfs3_commit_reply },
	{ 0,NULL,NULL,NULL }
};
/* end of NFS Version 3 */

static const old_vsff nfs4_proc[] = {
	{ 0, "NULL",
	NULL, NULL },
	{ 1, "COMPOUND",
	dissect_nfs4_compound_call, dissect_nfs4_compound_reply },
	{ 0, NULL, NULL, NULL }
};


static struct true_false_string yesno = { "Yes", "No" };


void
proto_register_nfs(void)
{
	static hf_register_info hf[] = {
		{ &hf_nfs_fh_fsid_major, {
			"major", "nfs.fh.fsid.major", FT_UINT32, BASE_DEC,
			NULL, 0, "major file system ID" }},
		{ &hf_nfs_fh_fsid_minor, {
			"minor", "nfs.fh.fsid.minor", FT_UINT32, BASE_DEC,
			NULL, 0, "minor file system ID" }},
		{ &hf_nfs_fh_xfsid_major, {
			"exported major", "nfs.fh.xfsid.major", FT_UINT32, BASE_DEC,
			NULL, 0, "exported major file system ID" }},
		{ &hf_nfs_fh_xfsid_minor, {
			"exported minor", "nfs.fh.xfsid.minor", FT_UINT32, BASE_DEC,
			NULL, 0, "exported minor file system ID" }},
		{ &hf_nfs_fh_fstype, {
			"file system type", "nfs.fh.fstype", FT_UINT32, BASE_DEC,
			NULL, 0, "file system type" }},
		{ &hf_nfs_fh_fn, {
			"file number", "nfs.fh.fn", FT_UINT32, BASE_DEC,
			NULL, 0, "file number" }},
		{ &hf_nfs_fh_fn_len, {
			"length", "nfs.fh.fn.len", FT_UINT32, BASE_DEC,
			NULL, 0, "file number length" }},
		{ &hf_nfs_fh_fn_inode, {
			"inode", "nfs.fh.fn.inode", FT_UINT32, BASE_DEC,
			NULL, 0, "file number inode" }},
		{ &hf_nfs_fh_fn_generation, {
			"generation", "nfs.fh.fn.generation", FT_UINT32, BASE_DEC,
			NULL, 0, "file number generation" }},
		{ &hf_nfs_fh_xfn, {
			"exported file number", "nfs.fh.xfn", FT_UINT32, BASE_DEC,
			NULL, 0, "exported file number" }},
		{ &hf_nfs_fh_xfn_len, {
			"length", "nfs.fh.xfn.len", FT_UINT32, BASE_DEC,
			NULL, 0, "exported file number length" }},
		{ &hf_nfs_fh_xfn_inode, {
			"exported inode", "nfs.fh.xfn.inode", FT_UINT32, BASE_DEC,
			NULL, 0, "exported file number inode" }},
		{ &hf_nfs_fh_xfn_generation, {
			"generation", "nfs.fh.xfn.generation", FT_UINT32, BASE_DEC,
			NULL, 0, "exported file number generation" }},
		{ &hf_nfs_fh_dentry, {
			"dentry", "nfs.fh.dentry", FT_UINT32, BASE_HEX,
			NULL, 0, "dentry (cookie)" }},
		{ &hf_nfs_fh_dev, {
			"device", "nfs.fh.dev", FT_UINT32, BASE_DEC,
			NULL, 0, "device" }},
		{ &hf_nfs_fh_xdev, {
			"exported device", "nfs.fh.xdev", FT_UINT32, BASE_DEC,
			NULL, 0, "exported device" }},
		{ &hf_nfs_fh_dirinode, {
			"directory inode", "nfs.fh.dirinode", FT_UINT32, BASE_DEC,
			NULL, 0, "directory inode" }},
		{ &hf_nfs_fh_pinode, {
			"pseudo inode", "nfs.fh.pinode", FT_UINT32, BASE_HEX,
			NULL, 0, "pseudo inode" }},
		{ &hf_nfs_fh_hp_len, {
			"length", "nfs.fh.hp.len", FT_UINT32, BASE_DEC,
			NULL, 0, "hash path length" }},
		{ &hf_nfs_stat, {
			"Status", "nfs.status2", FT_UINT32, BASE_DEC,
			VALS(names_nfs_stat), 0, "Reply status" }},
		{ &hf_nfs_name, {
			"Name", "nfs.name", FT_STRING, BASE_DEC,
			NULL, 0, "Name" }},
		{ &hf_nfs_readlink_data, {
			"Data", "nfs.readlink.data", FT_STRING, BASE_DEC,
			NULL, 0, "Symbolic Link Data" }},
		{ &hf_nfs_read_offset, {
			"Offset", "nfs.read.offset", FT_UINT32, BASE_DEC,
			NULL, 0, "Read Offset" }},
		{ &hf_nfs_read_count, {
			"Count", "nfs.read.count", FT_UINT32, BASE_DEC,
			NULL, 0, "Read Count" }},
		{ &hf_nfs_read_totalcount, {
			"Total Count", "nfs.read.totalcount", FT_UINT32, BASE_DEC,
			NULL, 0, "Total Count (obsolete)" }},
		{ &hf_nfs_data, {
			"Data", "nfs.data", FT_STRING, BASE_DEC,
			NULL, 0, "Data" }},
		{ &hf_nfs_write_beginoffset, {
			"Begin Offset", "nfs.write.beginoffset", FT_UINT32, BASE_DEC,
			NULL, 0, "Begin offset (obsolete)" }},
		{ &hf_nfs_write_offset, {
			"Offset", "nfs.write.offset", FT_UINT32, BASE_DEC,
			NULL, 0, "Offset" }},
		{ &hf_nfs_write_totalcount, {
			"Total Count", "nfs.write.totalcount", FT_UINT32, BASE_DEC,
			NULL, 0, "Total Count (obsolete)" }},
		{ &hf_nfs_symlink_to, {
			"To", "nfs.symlink.to", FT_STRING, BASE_DEC,
			NULL, 0, "Symbolic link destination name" }},
		{ &hf_nfs_readdir_cookie, {
			"Cookie", "nfs.readdir.cookie", FT_UINT32, BASE_DEC,
			NULL, 0, "Directory Cookie" }},
		{ &hf_nfs_readdir_count, {
			"Count", "nfs.readdir.count", FT_UINT32, BASE_DEC,
			NULL, 0, "Directory Count" }},
		{ &hf_nfs_readdir_entry, {
			"Entry", "nfs.readdir.entry", FT_NONE, 0,
			NULL, 0, "Directory Entry" }},
		{ &hf_nfs_readdir_entry_fileid, {
			"File ID", "nfs.readdir.entry.fileid", FT_UINT32, BASE_DEC,
			NULL, 0, "File ID" }},
		{ &hf_nfs_readdir_entry_name, {
			"Name", "nfs.readdir.entry.name", FT_STRING, BASE_DEC,
			NULL, 0, "Name" }},
		{ &hf_nfs_readdirplus_entry_name, {
			"Name", "nfs.readdirplus.entry.name", FT_STRING, BASE_DEC,
			NULL, 0, "Name" }},
		{ &hf_nfs_readdir_entry_cookie, {
			"Cookie", "nfs.readdir.entry.cookie", FT_UINT32, BASE_DEC,
			NULL, 0, "Directory Cookie" }},
		{ &hf_nfs_readdir_eof, {
			"EOF", "nfs.readdir.eof", FT_UINT32, BASE_DEC,
			NULL, 0, "EOF" }},
		{ &hf_nfs_statfs_tsize, {
			"Transfer Size", "nfs.statfs.tsize", FT_UINT32, BASE_DEC,
			NULL, 0, "Transfer Size" }},
		{ &hf_nfs_statfs_bsize, {
			"Block Size", "nfs.statfs.bsize", FT_UINT32, BASE_DEC,
			NULL, 0, "Block Size" }},
		{ &hf_nfs_statfs_blocks, {
			"Total Blocks", "nfs.statfs.blocks", FT_UINT32, BASE_DEC,
			NULL, 0, "Total Blocks" }},
		{ &hf_nfs_statfs_bfree, {
			"Free Blocks", "nfs.statfs.bfree", FT_UINT32, BASE_DEC,
			NULL, 0, "Free Blocks" }},
		{ &hf_nfs_statfs_bavail, {
			"Available Blocks", "nfs.statfs.bavail", FT_UINT32, BASE_DEC,
			NULL, 0, "Available Blocks" }},
		{ &hf_nfs_ftype3, {
			"Type", "nfs.type", FT_UINT32, BASE_DEC,
			VALS(names_nfs_ftype3), 0, "File Type" }},
		{ &hf_nfs_nfsstat3, {
			"Status", "nfs.status", FT_UINT32, BASE_DEC,
			VALS(names_nfs_nfsstat3), 0, "Reply status" }},
		{ &hf_nfs_read_eof, {
			"EOF", "nfs.read.eof", FT_BOOLEAN, BASE_NONE,
			&yesno, 0, "EOF" }},
		{ &hf_nfs_write_stable, {
			"Stable", "nfs.write.stable", FT_UINT32, BASE_DEC,
			VALS(names_stable_how), 0, "Stable" }},
		{ &hf_nfs_write_committed, {
			"Committed", "nfs.write.committed", FT_UINT32, BASE_DEC,
			VALS(names_stable_how), 0, "Committed" }},
		{ &hf_nfs_createmode3, {
			"Create Mode", "nfs.createmode", FT_UINT32, BASE_DEC,
			VALS(names_createmode3), 0, "Create Mode" }},
		{ &hf_nfs_fsstat_invarsec, {
			"invarsec", "nfs.fsstat.invarsec", FT_UINT32, BASE_DEC,
			NULL, 0, "probable number of seconds of file system invariance" }},
		{ &hf_nfs_fsinfo_rtmax, {
			"rtmax", "nfs.fsinfo.rtmax", FT_UINT32, BASE_DEC,
			NULL, 0, "maximum READ request" }},
		{ &hf_nfs_fsinfo_rtpref, {
			"rtpref", "nfs.fsinfo.rtpref", FT_UINT32, BASE_DEC,
			NULL, 0, "preferred READ request" }},
		{ &hf_nfs_fsinfo_rtmult, {
			"rtmult", "nfs.fsinfo.rtmult", FT_UINT32, BASE_DEC,
			NULL, 0, "suggested READ multiple" }},
		{ &hf_nfs_fsinfo_wtmax, {
			"wtmax", "nfs.fsinfo.wtmax", FT_UINT32, BASE_DEC,
			NULL, 0, "maximum WRITE request" }},
		{ &hf_nfs_fsinfo_wtpref, {
			"wtpref", "nfs.fsinfo.wtpref", FT_UINT32, BASE_DEC,
			NULL, 0, "preferred WRITE request" }},
		{ &hf_nfs_fsinfo_wtmult, {
			"wtmult", "nfs.fsinfo.wtmult", FT_UINT32, BASE_DEC,
			NULL, 0, "suggested WRITE multiple" }},
		{ &hf_nfs_fsinfo_dtpref, {
			"dtpref", "nfs.fsinfo.dtpref", FT_UINT32, BASE_DEC,
			NULL, 0, "preferred READDIR request" }},
		{ &hf_nfs_fsinfo_properties, {
			"Properties", "nfs.fsinfo.propeties", FT_UINT32, BASE_HEX,
			NULL, 0, "File System Properties" }},
		{ &hf_nfs_pathconf_linkmax, {
			"linkmax", "nfs.pathconf.linkmax", FT_UINT32, BASE_DEC,
			NULL, 0, "Maximum number of hard links" }},
		{ &hf_nfs_pathconf_name_max, {
			"name_max", "nfs.pathconf.name_max", FT_UINT32, BASE_DEC,
			NULL, 0, "Maximum file name length" }},
		{ &hf_nfs_pathconf_no_trunc, {
			"no_trunc", "nfs.pathconf.no_trunc", FT_BOOLEAN, BASE_NONE,
			&yesno, 0, "No long file name truncation" }},
		{ &hf_nfs_pathconf_chown_restricted, {
			"chown_restricted", "nfs.pathconf.chown_restricted", FT_BOOLEAN, BASE_NONE,
			&yesno, 0, "chown is restricted to root" }},
		{ &hf_nfs_pathconf_case_insensitive, {
			"case_insensitive", "nfs.pathconf.case_insensitive", FT_BOOLEAN, BASE_NONE,
			&yesno, 0, "file names are treated case insensitive" }},
		{ &hf_nfs_pathconf_case_preserving, {
			"case_preserving", "nfs.pathconf.case_preserving", FT_BOOLEAN, BASE_NONE,
			&yesno, 0, "file name cases are preserved" }},

		/* NFSv4 */

		{ &hf_nfs_argop4, {
			"Opcode", "nfs.call.operation", FT_UINT32, BASE_DEC,
			VALS(names_nfsv4_operation), 0, "Opcode" }},

		{ &hf_nfs_resop4,	{
			"Opcode", "nfs.reply.operation", FT_UINT32, BASE_DEC,
			VALS(names_nfsv4_operation), 0, "Opcode" }},

		{ &hf_nfs_linktext4, {
			"Name", "nfs.symlink.linktext", FT_STRING, BASE_DEC,
			NULL, 0, "Symbolic link contents" }},

		{ &hf_nfs_component4, {
			"Filename", "nfs.pathname.component", FT_STRING, BASE_DEC,
			NULL, 0, "Pathname component" }},

		{ &hf_nfs_tag4, {
			"Tag", "nfs.tag", FT_STRING, BASE_DEC,
			NULL, 0, "Tag" }},

		{ &hf_nfs_clientid4, {
			"Client ID", "nfs.clientid", FT_STRING, BASE_DEC,
			NULL, 0, "Name" }},

		{ &hf_nfs_ace4, {
			"ace", "nfs.ace", FT_STRING, BASE_DEC,
			NULL, 0, "Access Control Entry" }},

		{ &hf_nfs_recall, {
			"EOF", "nfs.recall", FT_BOOLEAN, BASE_NONE,
			&yesno, 0, "Recall" }},

		{ &hf_nfs_open_claim_type4, {
			"Claim Type", "nfs.open.claim_type", FT_UINT32, BASE_DEC,
			VALS(names_claim_type4), 0, "Claim Type" }},

		{ &hf_nfs_opentype4, {
			"Open Type", "nfs.open.opentype", FT_UINT32, BASE_DEC,
			VALS(names_opentype4), 0, "Open Type" }},

		{ &hf_nfs_limit_by4, {
			"Space Limit", "nfs.open.limit_by", FT_UINT32, BASE_DEC,
			VALS(names_limit_by4), 0, "Limit By" }},

		{ &hf_nfs_open_delegation_type4, {
			"Delegation Type", "nfs.open.delegation_type", FT_UINT32, BASE_DEC,
			VALS(names_open_delegation_type4), 0, "Delegation Type" }},

		{ &hf_nfs_ftype4, {
			"nfs_ftype4", "nfs.nfs_ftype4", FT_UINT32, BASE_DEC,
			VALS(names_ftype4), 0, "nfs.nfs_ftype4" }},

		{ &hf_nfs_change_info4_atomic, {
			"Atomic", "nfs.change_info.atomic", FT_BOOLEAN, BASE_NONE,
			&yesno, 0, "Atomic" }},

		{ &hf_nfs_open4_share_access, {
			"share_access", "nfs.open4.share_access", FT_UINT32, BASE_DEC,
			VALS(names_open4_share_access), 0, "Share Access" }},

		{ &hf_nfs_open4_share_deny, {
			"share_deny", "nfs.open4.share_deny", FT_UINT32, BASE_DEC,
			VALS(names_open4_share_deny), 0, "Share Deny" }},

		{ &hf_nfs_open4_result_flags, {
			"result_flags", "nfs.open4.rflags", FT_UINT32, BASE_HEX,
			VALS(names_open4_result_flags), 0, "Result Flags" }},

		{ &hf_nfs_seqid4, {
			"seqid", "nfs.seqid", FT_UINT32, BASE_HEX,
			NULL, 0, "Sequence ID" }},

		{ &hf_nfs_attr, {
			"attr",	"nfs.attr", FT_UINT32, BASE_DEC,
			VALS(names_fattr4), 0, "File Attribute" }},

		{ &hf_nfs_time_how4,	{
			"set_it", "nfs.set_it", FT_UINT32, BASE_DEC,
			VALS(names_time_how4), 0, "How To Set Time" }},

		{ &hf_nfs_attrlist4, {
			"attr_vals", "nfs.fattr4.attr_vals", FT_STRING, BASE_DEC,
			NULL, 0, "attr_vals" }},

		{ &hf_nfs_fattr4_expire_type, {
			"fattr4_expire_type", "nfs.fattr4_expire_type", FT_UINT32, BASE_DEC,
			VALS(names_fattr4_expire_type), 0, "fattr4_expire_type" }},

		{ &hf_nfs_fattr4_link_support, {
			"fattr4_link_support", "nfs.fattr4_link_support", FT_BOOLEAN, 
			BASE_NONE, &yesno, 0, "nfs.fattr4_link_support" }},

		{ &hf_nfs_fattr4_symlink_support, {
			"fattr4_symlink_support", "nfs.fattr4_symlink_support", FT_BOOLEAN, 
			BASE_NONE, &yesno, 0, "nfs.fattr4_symlink_support" }},

		{ &hf_nfs_fattr4_named_attr, {
			"fattr4_named_attr", "nfs.fattr4_named_attr", FT_BOOLEAN, BASE_NONE,
			&yesno, 0, "nfs.fattr4_named_attr" }},

		{ &hf_nfs_fattr4_unique_handles, {
			"fattr4_unique_handles", "nfs.fattr4_unique_handles", FT_BOOLEAN, 
			BASE_NONE, &yesno, 0, "nfs.fattr4_unique_handles" }},

		{ &hf_nfs_fattr4_archive, {
			"fattr4_archive", "nfs.fattr4_archive", FT_BOOLEAN, 
			BASE_NONE, &yesno, 0, "nfs.fattr4_archive" }},

		{ &hf_nfs_fattr4_cansettime, {
			"fattr4_cansettime", "nfs.fattr4_cansettime", FT_BOOLEAN, 
			BASE_NONE, &yesno, 0, "nfs.fattr4_cansettime" }},

		{ &hf_nfs_fattr4_case_insensitive, {
			"fattr4_case_insensitive", "nfs.fattr4_case_insensitive", FT_BOOLEAN, 
			BASE_NONE, &yesno, 0, "nfs.fattr4_case_insensitive" }},

		{ &hf_nfs_fattr4_case_preserving, {
			"fattr4_case_preserving", "nfs.fattr4_case_preserving", FT_BOOLEAN, 
			BASE_NONE, &yesno, 0, "nfs.fattr4_case_preserving" }},

		{ &hf_nfs_fattr4_chown_restricted, {
			"fattr4_chown_restricted", "nfs.fattr4_chown_restricted", FT_BOOLEAN, 
			BASE_NONE, &yesno, 0, "nfs.fattr4_chown_restricted" }},

		{ &hf_nfs_fattr4_hidden, {
			"fattr4_hidden", "nfs.fattr4_hidden", FT_BOOLEAN, 
			BASE_NONE, &yesno, 0, "nfs.fattr4_hidden" }},

		{ &hf_nfs_fattr4_homogeneous, {
			"fattr4_homogeneous", "nfs.fattr4_homogeneous", FT_BOOLEAN, 
			BASE_NONE, &yesno, 0, "nfs.fattr4_homogeneous" }},

		{ &hf_nfs_fattr4_mimetype, {
			"fattr4_mimetype", "nfs.fattr4_mimetype", FT_STRING, BASE_DEC,
			NULL, 0, "nfs.fattr4_mimetype" }},

		{ &hf_nfs_fattr4_no_trunc, {
			"fattr4_no_trunc", "nfs.fattr4_no_trunc", FT_BOOLEAN, 
			BASE_NONE, &yesno, 0, "nfs.fattr4_no_trunc" }},

		{ &hf_nfs_fattr4_system, {
			"fattr4_system", "nfs.fattr4_system", FT_BOOLEAN, 
			BASE_NONE, &yesno, 0, "nfs.fattr4_system" }},

		{ &hf_nfs_who, {
			"who", "nfs.who", FT_STRING, BASE_DEC,
			NULL, 0, "nfs.who" }},

		{ &hf_nfs_server, {
			"server", "nfs.server", FT_STRING, BASE_DEC,
			NULL, 0, "nfs.server" }},

		{ &hf_nfs_fattr4_owner, {
			"fattr4_owner", "nfs.fattr4_owner", FT_STRING, BASE_DEC,
			NULL, 0, "nfs.fattr4_owner" }},

		{ &hf_nfs_fattr4_owner_group, {
			"fattr4_owner_group", "nfs.fattr4_owner_group", FT_STRING, BASE_DEC,
			NULL, 0, "nfs.fattr4_owner_group" }},
	};

	static gint *ett[] = {
		&ett_nfs,
		&ett_nfs_fh_fsid,
		&ett_nfs_fh_xfsid,
		&ett_nfs_fh_fn,
		&ett_nfs_fh_xfn,
		&ett_nfs_fh_hp,
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
		&ett_nfs_secinfo4,
		&ett_nfs_setattr4,
		&ett_nfs_setclientid4,
		&ett_nfs_setclientid_confirm4,
		&ett_nfs_verify4,
		&ett_nfs_write4,
		&ett_nfs_verifier4,
		&ett_nfs_opaque,
		&ett_nfs_dirlist4,
		&ett_nfs_pathname4,
		&ett_nfs_change_info4,
		&ett_nfs_open_delegation4,
		&ett_nfs_open_claim4,
		&ett_nfs_opentype4,
		&ett_nfs_lockowner4,
		&ett_nfs_cb_client4,
		&ett_nfs_client_id4,
		&ett_nfs_bitmap4,
		&ett_nfs_fattr4,
		&ett_nfs_fsid4,
		&ett_nfs_fs_locations4,
		&ett_nfs_fs_location4
	};
	proto_nfs = proto_register_protocol("Network File System", "NFS", "nfs");
	proto_register_field_array(proto_nfs, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_nfs(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_nfs, NFS_PROGRAM, ett_nfs);
	/* Register the procedure tables */
	old_rpc_init_proc_table(NFS_PROGRAM, 2, nfs2_proc);
	old_rpc_init_proc_table(NFS_PROGRAM, 3, nfs3_proc);
	old_rpc_init_proc_table(NFS_PROGRAM, 4, nfs4_proc);
}
