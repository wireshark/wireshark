/* packet-nfs.c
 * Routines for nfs dissection
 * Copyright 1999, Uwe Girlich <Uwe.Girlich@philosys.de>
 *
 * $Id: packet-nfs.c,v 1.33 2000/08/06 07:22:35 guy Exp $
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


/* file handle dissection */


const value_string names_fhtype[] =
{
#define FHT_UNKNOWN	0
	{	FHT_UNKNOWN,	"unknown"	},
#define FHT_SVR4	1
	{	FHT_SVR4,	"System V R4"	},
#define FHT_LINUX_KNFSD_LE	2
	{	FHT_LINUX_KNFSD_LE,	"Linux knfsd (little-endian)"	},
#define FHT_LINUX_NFSD_LE	3
	{	FHT_LINUX_NFSD_LE,	"Linux user-land nfsd (little-endian)"	},
	{		0,	NULL		}
};


/* SVR4: checked with ReliantUNIX (5.43, 5.44, 5.45) */

void
dissect_fhandle_data_SVR4(tvbuff_t* tvb, proto_tree *tree, int fhlen)
{
	guint32 nof = 0;

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

void
dissect_fhandle_data_LINUX_KNFSD_LE(tvbuff_t* tvb, proto_tree *tree, int fhlen)
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

	dentry   = tvb_get_letohl(tvb, 0);
	inode    = tvb_get_letohl(tvb, 4);
	dirinode = tvb_get_letohl(tvb, 8);
	temp     = tvb_get_letohs (tvb,12);
	fsid_major = (temp >> 8) & 0xff;
	fsid_minor = (temp     ) & 0xff;
	temp     = tvb_get_letohs(tvb,16);
	xfsid_major = (temp >> 8) & 0xff;
	xfsid_minor = (temp     ) & 0xff;
	xinode   = tvb_get_letohl(tvb,20);
	gen      = tvb_get_letohl(tvb,24);

	if (tree) {
		proto_tree_add_uint(tree, hf_nfs_fh_dentry,
			tvb, 0, 4, dentry);
		proto_tree_add_uint(tree, hf_nfs_fh_fn_inode,
			tvb, 4, 4, inode);
		proto_tree_add_uint(tree, hf_nfs_fh_dirinode,
			tvb, 8, 4, dirinode);

		/* file system id (device) */
		{
		proto_item* fsid_item = NULL;
		proto_tree* fsid_tree = NULL;

		fsid_item = proto_tree_add_text(tree, tvb,
			12, 4, 
			"file system ID: %d,%d", fsid_major, fsid_minor);
		if (fsid_item) {
			fsid_tree = proto_item_add_subtree(fsid_item, 
					ett_nfs_fh_fsid);
			proto_tree_add_uint(fsid_tree, hf_nfs_fh_fsid_major,
				tvb, 13, 1, fsid_major);
			proto_tree_add_uint(fsid_tree, hf_nfs_fh_fsid_minor,
				tvb, 12, 1, fsid_minor);
		}
		}

		/* exported file system id (device) */
		{
		proto_item* xfsid_item = NULL;
		proto_tree* xfsid_tree = NULL;

		xfsid_item = proto_tree_add_text(tree, tvb,
			16, 4, 
			"exported file system ID: %d,%d", xfsid_major, xfsid_minor);
		if (xfsid_item) {
			xfsid_tree = proto_item_add_subtree(xfsid_item, 
					ett_nfs_fh_xfsid);
			proto_tree_add_uint(xfsid_tree, hf_nfs_fh_xfsid_major,
				tvb, 17, 1, xfsid_major);
			proto_tree_add_uint(xfsid_tree, hf_nfs_fh_xfsid_minor,
				tvb, 16, 1, xfsid_minor);
		}
		}

		proto_tree_add_uint(tree, hf_nfs_fh_xfn_inode,
			tvb, 20, 4, xinode);
		proto_tree_add_uint(tree, hf_nfs_fh_fn_generation,
			tvb, 24, 4, gen);
	}
}


/* Checked with RedHat Linux 5.2 (nfs-server 2.2beta47 user-land nfsd) */

void
dissect_fhandle_data_LINUX_NFSD_LE(tvbuff_t* tvb, proto_tree *tree, int fhlen)
{
	/* pseudo inode */
	{
	guint32 pinode;
	pinode   = tvb_get_letohl(tvb, 0);
	if (tree) {
		proto_tree_add_uint(tree, hf_nfs_fh_pinode,
			tvb, 0, 4, pinode);
	}
	}

	/* hash path */
	{
	guint32 hashlen;

	hashlen  = tvb_get_guint8(tvb, 4);
	if (tree) {
		proto_item* hash_item = NULL;
		proto_tree* hash_tree = NULL;

		hash_item = proto_tree_add_text(tree, tvb, 4, hashlen + 1,
				"hash path: %s",
				bytes_to_str(tvb_get_ptr(tvb,5,hashlen),hashlen));
		if (hash_item) {
			hash_tree = proto_item_add_subtree(hash_item, 
					ett_nfs_fh_hp);
			if (hash_tree) {
		 		proto_tree_add_uint(hash_tree,
					hf_nfs_fh_hp_len, tvb, 4, 1, hashlen);
				proto_tree_add_text(hash_tree, tvb, 5, hashlen,
					"key: %s",
					bytes_to_str(tvb_get_ptr(tvb,5,hashlen),hashlen));
			}
		}
	}
	}
}


static void
dissect_fhandle_data_unknown(tvbuff_t *tvb, proto_tree *tree, int fhlen)
{
	int offset;

	int sublen;
	int bytes_left;
	gboolean first_line;

	offset = 0;

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
					bytes_to_str(tvb_get_ptr(tvb,offset,sublen),sublen));
		bytes_left -= sublen;
		offset += sublen;
		first_line = FALSE;
	}
}


static void
dissect_fhandle_data(const u_char *pd, int offset, frame_data* fd, proto_tree *tree, int fhlen)
{
	int fhtype = FHT_UNKNOWN;
	tvbuff_t *realtvb;
	tvbuff_t *tvb;

	/* Make use of the new tvbuf code.
	   There is no way to get the packet_info here. So  we have to
	   create a totally new tvbuf. */
	realtvb = tvb_new_real_data(pd, pi.captured_len, pi.len);
	tvb = tvb_new_subset(realtvb, offset, 
				pi.captured_len - offset,
				pi.len - offset);

	/* filehandle too long */
	if (fhlen>64) goto type_ready;
	/* Not all bytes there. Any attemtpt to decduce the type would be
	   senseless. */
	if (!tvb_bytes_exist(tvb,0,fhlen)) goto type_ready;
		
	/* calculate (heuristically) fhtype */
	switch (fhlen) {
		case 32: {
			guint32 len1;
			guint32 len2;
			if (tvb_get_ntohs(tvb,4) == 0) {
				len1= tvb_get_ntohs(tvb,8);
				if (tvb_bytes_exist(tvb,10+len1,2)) {
						len2 = tvb_get_ntohs(tvb,10+len1);
						if (fhlen==12+len1+len2) {
							fhtype=FHT_SVR4;
							goto type_ready;
						}
				}
			}
			len1 = tvb_get_guint8(tvb,4);
			if (len1<28 && tvb_bytes_exist(tvb,5,len1)) {
				int wrong=0;
				for (len2=5+len1;len2<32;len2++) {
					if (tvb_get_guint8(tvb,len2)) {
						wrong=1;	
						break;
					}
				}
				if (!wrong) {
					fhtype=FHT_LINUX_NFSD_LE;
					goto type_ready;
				}
			}
			if (tvb_get_ntohl(tvb,28) == 0) {
				if (tvb_get_ntohs(tvb,14) == 0) {
					if (tvb_get_ntohs(tvb,18) == 0) {
						fhtype=FHT_LINUX_KNFSD_LE;
						goto type_ready;
					}
				}
			}
		} break;
	}

type_ready:

	proto_tree_add_text(tree, tvb, 0, 0, 
		"type: %s", val_to_str(fhtype, names_fhtype, "Unknown"));

	switch (fhtype) {
		case FHT_SVR4:
			dissect_fhandle_data_SVR4          (tvb, tree, fhlen);
		break;
		case FHT_LINUX_KNFSD_LE:
			dissect_fhandle_data_LINUX_KNFSD_LE(tvb, tree, fhlen);
		break;
		case FHT_LINUX_NFSD_LE:
			dissect_fhandle_data_LINUX_NFSD_LE (tvb, tree, fhlen);
		break;
		case FHT_UNKNOWN:
		default:
			dissect_fhandle_data_unknown(tvb, tree, fhlen);
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
	offset = dissect_rpc_uint32(pd,offset,fd,tree,name,"unsigned int");
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


/* RFC 1094, Page 12..14 */
int
dissect_stat(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
guint32* status)
{
	guint32 stat;

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	stat = EXTRACT_UINT(pd, offset+0);
	
	if (tree) {
		/* this gives the right NFSv2 number<->message relation */
		/* and makes it searchable via "nfs.status" */
		proto_tree_add_uint_format(tree, hf_nfs_nfsstat3, NullTVB,
			offset+0, 4, stat, "Status: %s (%u)", 
			val_to_str(stat,names_nfs_stat,"%u"), stat);
	}

	offset += 4;
	*status = stat;
	return offset;
}


/* RFC 1094, Page 12..14 */
int
dissect_nfs2_stat_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	guint32 status;

	offset = dissect_stat(pd, offset, fd, tree, &status);

	return offset;
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
dissect_fhandle(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name)
{
	proto_item* fitem;
	proto_tree* ftree = NULL;

	if (tree) {
		fitem = proto_tree_add_text(tree, NullTVB, offset, FHSIZE,
			"%s", name);
		if (fitem)
			ftree = proto_item_add_subtree(fitem, ett_nfs_fhandle);
	}

	if (ftree)
		dissect_fhandle_data(pd, offset, fd, ftree, FHSIZE);

	offset += FHSIZE;
	return offset;
}

/* RFC 1094, Page 15 */
int
dissect_nfs2_fhandle_call(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	offset = dissect_fhandle(pd, offset, fd, tree, "object");

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

	offset = dissect_fhandle (pd,offset,fd,diropargs_tree,"dir");
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
			offset = dissect_fhandle(pd, offset, fd, tree, "file");
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
	offset = dissect_fhandle(pd, offset, fd, tree, "file"      );
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

	offset = dissect_fhandle(pd, offset, fd, tree, "file"      );
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

	offset = dissect_fhandle(pd, offset, fd, tree, "file"      );
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
	offset = dissect_fhandle  (pd, offset, fd, tree, "from");
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

	offset = dissect_fhandle (pd, offset, fd, tree, "dir");
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
/* NULL as function pointer means: take the generic one. */
const vsff nfs2_proc[] = {
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
	offset = dissect_rpc_uint64(pd,offset,fd,tree,name,"uint64");
	return offset;
}


/* RFC 1813, Page 15 */
int
dissect_uint32(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
char* name)
{
	offset = dissect_rpc_uint32(pd,offset,fd,tree,name,"uint32");
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
	offset = dissect_rpc_uint64(pd,offset,fd,tree,name,"fileid3");
	return offset;
}


/* RFC 1813, Page 15 */
int
dissect_cookie3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
char* name)
{
	offset = dissect_rpc_uint64(pd,offset,fd,tree,name,"cookie3");
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
	offset = dissect_rpc_uint32(pd,offset,fd,tree,name,"uid3"); 
	return offset;
}


/* RFC 1813, Page 16 */
int
dissect_gid3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
char* name)
{
	offset = dissect_rpc_uint32(pd,offset,fd,tree,name,"gid3"); 
	return offset;
}


/* RFC 1813, Page 16 */
int
dissect_size3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
char* name)
{
	offset = dissect_rpc_uint64(pd,offset,fd,tree,name,"size3"); 
	return offset;
}


/* RFC 1813, Page 16 */
int
dissect_offset3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
char* name)
{
	offset = dissect_rpc_uint64(pd,offset,fd,tree,name,"offset3"); 
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
	offset = dissect_rpc_uint32(pd,offset,fd,tree,name,"count3");
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
dissect_nfs_fh3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name)
{
	guint fh3_len;
	guint fh3_len_full;
	guint fh3_fill;
	proto_item* fitem;
	proto_tree* ftree = NULL;

	fh3_len = EXTRACT_UINT(pd, offset+0);
	fh3_len_full = rpc_roundup(fh3_len);
	fh3_fill = fh3_len_full - fh3_len;
	
	if (tree) {
		fitem = proto_tree_add_text(tree, NullTVB, offset, 4+fh3_len_full,
			"%s", name);
		if (fitem)
			ftree = proto_item_add_subtree(fitem, ett_nfs_fh3);
	}

	if (ftree) {
		proto_tree_add_text(ftree, NullTVB,offset+0,4,
					"length: %u", fh3_len);
		dissect_fhandle_data(pd, offset+4, fd, ftree, fh3_len);
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
			offset = dissect_nfs_fh3(pd, offset, fd, post_op_fh3_tree,
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

	offset = dissect_nfs_fh3  (pd, offset, fd, diropargs3_tree, "dir");
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
		decode_boolean_bitfield(access,  0x004, 6, "allowed", "not allow"));
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
	offset = dissect_nfs_fh3(pd, offset, fd, tree, "object");
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
	offset = dissect_nfs_fh3(pd, offset, fd, tree, "object");
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
	offset = dissect_nfs_fh3    (pd, offset, fd, tree, "object");
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
			offset = dissect_nfs_fh3     (pd, offset, fd, tree, "object");
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
	offset = dissect_nfs_fh3(pd, offset, fd, tree, "object");
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
	offset = dissect_nfs_fh3(pd, offset, fd, tree, "file");
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
	offset = dissect_nfs_fh3   (pd, offset, fd, tree, "file");
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
	offset = dissect_nfs_fh3   (pd, offset, fd, tree, "file");
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
	offset = dissect_nfs_fh3    (pd, offset, fd, tree, "dir");
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
	offset = dissect_nfs_fh3    (pd, offset, fd, tree, "dir");
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
	offset = dissect_nfs_fh3(pd, offset, fd, tree, "file");
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


/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: take the generic one. */
const vsff nfs3_proc[] = {
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
			&yesno, 0, "file name cases are preserved" }}
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
		&ett_nfs_fsinfo_properties
	};
	proto_nfs = proto_register_protocol("Network File System", "nfs");
	proto_register_field_array(proto_nfs, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_nfs(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_nfs, NFS_PROGRAM, ett_nfs);
	/* Register the procedure tables */
	rpc_init_proc_table(NFS_PROGRAM, 2, nfs2_proc);
	rpc_init_proc_table(NFS_PROGRAM, 3, nfs3_proc);
}
