/* packet-glusterfs.c
 * Routines for GlusterFS dissection
 * Copyright 2012, Niels de Vos <ndevos@redhat.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *
 * References to source files point in general to the glusterfs sources.
 * There is currently no RFC or other document where the protocol is
 * completely described. The glusterfs sources can be found at:
 * - http://git.gluster.com/?p=glusterfs.git
 * - https://github.com/gluster/glusterfs
 *
 * The coding-style is roughly the same as the one use in the Linux kernel,
 * see http://www.kernel.org/doc/Documentation/CodingStyle.
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/guid-utils.h>

#include "packet-rpc.h"
#include "packet-gluster.h"

/* Initialize the protocol and registered fields */
static gint proto_glusterfs = -1;

/* programs and procedures */
static gint hf_glusterfs_proc = -1;

/* fields used by multiple programs/procedures */
static gint hf_gluster_op_ret = -1;
static gint hf_gluster_op_errno = -1;

/* GlusterFS specific */
static gint hf_glusterfs_gfid = -1;
static gint hf_glusterfs_pargfid = -1;
static gint hf_glusterfs_oldgfid = -1;
static gint hf_glusterfs_newgfid = -1;
static gint hf_glusterfs_path = -1;
static gint hf_glusterfs_bname = -1;
static gint hf_glusterfs_dict = -1;
static gint hf_glusterfs_fd = -1;
static gint hf_glusterfs_offset = -1;
static gint hf_glusterfs_size = -1;
static gint hf_glusterfs_volume = -1;
static gint hf_glusterfs_cmd = -1;
static gint hf_glusterfs_type = -1;
static gint hf_glusterfs_entries = -1;
static gint hf_glusterfs_xflags = -1;
static gint hf_glusterfs_linkname = -1;
static gint hf_glusterfs_umask = -1;
static gint hf_glusterfs_mask = -1;
static gint hf_glusterfs_name = -1;
static gint hf_glusterfs_namelen = -1;

/* flags passed on to OPEN, CREATE etc.*/
static gint hf_glusterfs_flags = -1;
static gint hf_glusterfs_flags_rdonly = -1;
static gint hf_glusterfs_flags_wronly = -1;
static gint hf_glusterfs_flags_rdwr = -1;
static gint hf_glusterfs_flags_accmode = -1;
static gint hf_glusterfs_flags_append = -1;
static gint hf_glusterfs_flags_async = -1;
static gint hf_glusterfs_flags_cloexec = -1;
static gint hf_glusterfs_flags_creat = -1;
static gint hf_glusterfs_flags_direct = -1;
static gint hf_glusterfs_flags_directory = -1;
static gint hf_glusterfs_flags_excl = -1;
static gint hf_glusterfs_flags_largefile = -1;
static gint hf_glusterfs_flags_noatime = -1;
static gint hf_glusterfs_flags_noctty = -1;
static gint hf_glusterfs_flags_nofollow = -1;
static gint hf_glusterfs_flags_nonblock = -1;
static gint hf_glusterfs_flags_ndelay = -1;
static gint hf_glusterfs_flags_sync = -1;
static gint hf_glusterfs_flags_trunc = -1;
static gint hf_glusterfs_flags_reserved = -1;

/* access modes  */
static gint hf_glusterfs_mode = -1;
static gint hf_glusterfs_mode_suid = -1;
static gint hf_glusterfs_mode_sgid = -1;
static gint hf_glusterfs_mode_svtx = -1;
static gint hf_glusterfs_mode_rusr = -1;
static gint hf_glusterfs_mode_wusr = -1;
static gint hf_glusterfs_mode_xusr = -1;
static gint hf_glusterfs_mode_rgrp = -1;
static gint hf_glusterfs_mode_wgrp = -1;
static gint hf_glusterfs_mode_xgrp = -1;
static gint hf_glusterfs_mode_roth = -1;
static gint hf_glusterfs_mode_woth = -1;
static gint hf_glusterfs_mode_xoth = -1;
static gint hf_glusterfs_mode_reserved = -1;

/* dir-entry */
static gint hf_glusterfs_entry_ino = -1;
static gint hf_glusterfs_entry_off = -1;
static gint hf_glusterfs_entry_len = -1;
static gint hf_glusterfs_entry_type = -1;
static gint hf_glusterfs_entry_path = -1;

/* gf_iatt */
static gint hf_glusterfs_iatt = -1;
static gint hf_glusterfs_preparent_iatt = -1;
static gint hf_glusterfs_postparent_iatt = -1;
static gint hf_glusterfs_preop_iatt = -1;
static gint hf_glusterfs_postop_iatt = -1;
static gint hf_glusterfs_ia_ino = -1;
static gint hf_glusterfs_ia_dev = -1;
static gint hf_glusterfs_ia_mode = -1;
static gint hf_glusterfs_ia_nlink = -1;
static gint hf_glusterfs_ia_uid = -1;
static gint hf_glusterfs_ia_gid = -1;
static gint hf_glusterfs_ia_rdev = -1;
static gint hf_glusterfs_ia_size = -1;
static gint hf_glusterfs_ia_blksize = -1;
static gint hf_glusterfs_ia_blocks = -1;
static gint hf_glusterfs_ia_atime = -1;
static gint hf_glusterfs_ia_mtime = -1;
static gint hf_glusterfs_ia_ctime = -1;

/* gf_flock */
static gint hf_glusterfs_flock_type = -1;
static gint hf_glusterfs_flock_whence = -1;
static gint hf_glusterfs_flock_start = -1;
static gint hf_glusterfs_flock_len = -1;
static gint hf_glusterfs_flock_pid = -1;
static gint hf_glusterfs_flock_owner = -1;

/* statfs */
static gint hf_glusterfs_bsize = -1;
static gint hf_glusterfs_frsize = -1;
static gint hf_glusterfs_blocks = -1;
static gint hf_glusterfs_bfree = -1;
static gint hf_glusterfs_bavail = -1;
static gint hf_glusterfs_files = -1;
static gint hf_glusterfs_ffree = -1;
static gint hf_glusterfs_favail = -1;
static gint hf_glusterfs_id = -1;
static gint hf_glusterfs_mnt_flags = -1;
static gint hf_glusterfs_mnt_flag_rdonly = -1;
static gint hf_glusterfs_mnt_flag_nosuid = -1;
static gint hf_glusterfs_mnt_flag_nodev = -1;
static gint hf_glusterfs_mnt_flag_noexec = -1;
static gint hf_glusterfs_mnt_flag_synchronous = -1;
static gint hf_glusterfs_mnt_flag_mandlock = -1;
static gint hf_glusterfs_mnt_flag_write = -1;
static gint hf_glusterfs_mnt_flag_append = -1;
static gint hf_glusterfs_mnt_flag_immutable = -1;
static gint hf_glusterfs_mnt_flag_noatime = -1;
static gint hf_glusterfs_mnt_flag_nodiratime = -1;
static gint hf_glusterfs_mnt_flag_relatime = -1;
static gint hf_glusterfs_namemax = -1;

static gint hf_glusterfs_setattr_valid = -1;
/* flags for setattr.valid */
static gint hf_glusterfs_setattr_set_mode = -1;
static gint hf_glusterfs_setattr_set_uid = -1;
static gint hf_glusterfs_setattr_set_gid = -1;
static gint hf_glusterfs_setattr_set_size = -1;
static gint hf_glusterfs_setattr_set_atime = -1;
static gint hf_glusterfs_setattr_set_mtime = -1;
static gint hf_glusterfs_setattr_set_reserved = -1;

/* Rename */
static gint hf_glusterfs_oldbname = -1;
static gint hf_glusterfs_newbname = -1;

/* for FSYNCDIR */
static gint hf_glusterfs_yncdir_data = -1;

/* for entrylk */
static gint hf_glusterfs_entrylk_namelen = -1;

/* Initialize the subtree pointers */
static gint ett_glusterfs = -1;
static gint ett_glusterfs_flags = -1;
static gint ett_glusterfs_mnt_flags = -1;
static gint ett_glusterfs_mode = -1;
static gint ett_glusterfs_setattr_valid = -1;
static gint ett_glusterfs_parent_iatt = -1;
static gint ett_glusterfs_iatt = -1;
static gint ett_glusterfs_entry = -1;
static gint ett_glusterfs_flock = -1;
static gint ett_gluster_dict = -1;
static gint ett_gluster_dict_items = -1;

static int
glusterfs_rpc_dissect_gfid(proto_tree *tree, tvbuff_t *tvb, int hfindex, int offset)
{
	if (tree)
		proto_tree_add_item(tree, hfindex, tvb, offset, 16, ENC_NA);
	offset += 16;

	return offset;
}

static int
glusterfs_rpc_dissect_mode(proto_tree *tree, tvbuff_t *tvb, int hfindex,
								int offset)
{
	static const int *mode_bits[] = {
		&hf_glusterfs_mode_suid,
		&hf_glusterfs_mode_sgid,
		&hf_glusterfs_mode_svtx,
		&hf_glusterfs_mode_rusr,
		&hf_glusterfs_mode_wusr,
		&hf_glusterfs_mode_xusr,
		&hf_glusterfs_mode_rgrp,
		&hf_glusterfs_mode_wgrp,
		&hf_glusterfs_mode_xgrp,
		&hf_glusterfs_mode_roth,
		&hf_glusterfs_mode_woth,
		&hf_glusterfs_mode_xoth,
		&hf_glusterfs_mode_reserved,
		NULL
	};

	if (tree)
		proto_tree_add_bitmask(tree, tvb, offset, hfindex,
			ett_glusterfs_mode, mode_bits, ENC_LITTLE_ENDIAN);

	offset += 4;
	return offset;
}

/*
 * from rpc/xdr/src/glusterfs3-xdr.c:xdr_gf_iatt()
 */
static int
glusterfs_rpc_dissect_gf_iatt(proto_tree *tree, tvbuff_t *tvb, int hfindex,
								int offset)
{
	proto_item *iatt_item;
	proto_tree *iatt_tree;
	nstime_t timestamp;

	iatt_item = proto_tree_add_item(tree, hfindex, tvb, offset, -1,
								ENC_NA);
	iatt_tree = proto_item_add_subtree(iatt_item, ett_glusterfs_iatt);

	offset = glusterfs_rpc_dissect_gfid(iatt_tree, tvb, hf_glusterfs_gfid,
								offset);
	offset = dissect_rpc_uint64(tvb, iatt_tree, hf_glusterfs_ia_ino,
								offset);
	offset = dissect_rpc_uint64(tvb, iatt_tree, hf_glusterfs_ia_dev,
								offset);
	offset = glusterfs_rpc_dissect_mode(iatt_tree, tvb,
						hf_glusterfs_ia_mode, offset);
	offset = dissect_rpc_uint32(tvb, iatt_tree, hf_glusterfs_ia_nlink,
								offset);
	offset = dissect_rpc_uint32(tvb, iatt_tree, hf_glusterfs_ia_uid,
								offset);
	offset = dissect_rpc_uint32(tvb, iatt_tree, hf_glusterfs_ia_gid,
								offset);
	offset = dissect_rpc_uint64(tvb, iatt_tree, hf_glusterfs_ia_rdev,
								offset);
	offset = dissect_rpc_uint64(tvb, iatt_tree, hf_glusterfs_ia_size,
								offset);
	offset = dissect_rpc_uint32(tvb, iatt_tree, hf_glusterfs_ia_blksize,
								offset);
	offset = dissect_rpc_uint64(tvb, iatt_tree, hf_glusterfs_ia_blocks,
								offset);

	timestamp.secs = tvb_get_ntohl(tvb, offset);
	timestamp.nsecs = tvb_get_ntohl(tvb, offset + 4);
	if (tree)
		proto_tree_add_time(iatt_tree, hf_glusterfs_ia_atime, tvb,
							offset, 8, &timestamp);
	offset += 8;

	timestamp.secs = tvb_get_ntohl(tvb, offset);
	timestamp.nsecs = tvb_get_ntohl(tvb, offset + 4);
	if (tree)
		proto_tree_add_time(iatt_tree, hf_glusterfs_ia_mtime, tvb,
							offset, 8, &timestamp);
	offset += 8;

	timestamp.secs = tvb_get_ntohl(tvb, offset);
	timestamp.nsecs = tvb_get_ntohl(tvb, offset + 4);
	if (tree)
		proto_tree_add_time(iatt_tree, hf_glusterfs_ia_ctime, tvb,
							offset, 8, &timestamp);
	offset += 8;

	return offset;
}

static int
glusterfs_rpc_dissect_gf_flock(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_flock_type, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_flock_whence, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_flock_start, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_flock_len, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_flock_pid, offset);

	if (tree)
		proto_tree_add_item(tree, hf_glusterfs_flock_owner, tvb,
							offset, 8, ENC_NA);
	offset += 8;

	return offset;
}

static int
glusterfs_rpc_dissect_gf_2_flock(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	proto_item *flock_item;
	proto_tree *flock_tree;
	int len;

	flock_item = proto_tree_add_text(tree, tvb, offset, -1, "Flock");
	flock_tree = proto_item_add_subtree(flock_item, ett_glusterfs_flock);

	offset = dissect_rpc_uint32(tvb, flock_tree, hf_glusterfs_flock_type,
								offset);
	offset = dissect_rpc_uint32(tvb, flock_tree, hf_glusterfs_flock_whence,
								offset);
	offset = dissect_rpc_uint64(tvb, flock_tree, hf_glusterfs_flock_start,
								offset);
	offset = dissect_rpc_uint64(tvb, flock_tree, hf_glusterfs_flock_len,
								offset);
	offset = dissect_rpc_uint32(tvb, flock_tree, hf_glusterfs_flock_pid,
								offset);

	len = tvb_get_ntohl(tvb, offset);
	offset += 4;

	if (tree)
		proto_tree_add_item(flock_tree, hf_glusterfs_flock_owner, tvb,
							offset, len, ENC_NA);
	offset += len;

	return offset;
}

static const true_false_string glusterfs_notset_set = {
	"Not set",
	"Set"
};

static const value_string glusterfs_accmode_vals[] = {
	{ 0, "Not set"},
	{ 1, "Not set"},
	{ 2, "Not set"},
	{ 3, "Set"},
	{ 0, NULL}
};

static int
glusterfs_rpc_dissect_flags(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	gboolean rdonly;
	guint32 accmode;
	proto_item *flag_tree;
	header_field_info *rdonly_hf, *accmode_hf;

	static const int *flag_bits[] = {
		&hf_glusterfs_flags_wronly,
		&hf_glusterfs_flags_rdwr,
		&hf_glusterfs_flags_creat,
		&hf_glusterfs_flags_excl,
		&hf_glusterfs_flags_noctty,
		&hf_glusterfs_flags_trunc,
		&hf_glusterfs_flags_append,
		&hf_glusterfs_flags_nonblock,
		&hf_glusterfs_flags_ndelay,
		&hf_glusterfs_flags_sync,
		&hf_glusterfs_flags_async,
		&hf_glusterfs_flags_direct,
		&hf_glusterfs_flags_largefile,
		&hf_glusterfs_flags_directory,
		&hf_glusterfs_flags_nofollow,
		&hf_glusterfs_flags_noatime,
		&hf_glusterfs_flags_cloexec,
		&hf_glusterfs_flags_reserved,
		NULL
	};

	if (tree) {
		flag_tree = proto_tree_add_bitmask(tree, tvb, offset, hf_glusterfs_flags, ett_glusterfs_flags, flag_bits, ENC_LITTLE_ENDIAN);

		/* rdonly is TRUE only when no flags are set */
		rdonly = (tvb_get_ntohl(tvb, offset) == 0);
		proto_tree_add_item(flag_tree, hf_glusterfs_flags_rdonly, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		if (rdonly) {
			rdonly_hf = proto_registrar_get_nth(hf_glusterfs_flags_rdonly);
			proto_item_append_text(flag_tree, ", %s", rdonly_hf->name);
		}

		/* hf_glusterfs_flags_accmode is TRUE if bits 0 and 1 are set */
		accmode_hf = proto_registrar_get_nth(hf_glusterfs_flags_accmode);
		accmode = tvb_get_ntohl(tvb, offset);
		proto_tree_add_uint_format_value(flag_tree, hf_glusterfs_flags_accmode, tvb, offset, 4, accmode,
		                                 "%s", val_to_str_const((accmode & accmode_hf->bitmask), glusterfs_accmode_vals, "Unknown"));
		if ((accmode & accmode_hf->bitmask) == accmode_hf->bitmask)
			proto_item_append_text(flag_tree, ", %s", proto_registrar_get_nth(hf_glusterfs_flags_accmode)->name);
	}

	offset += 4;
	return offset;
}

static int
glusterfs_rpc_dissect_statfs(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	static const int *flag_bits[] = {
		&hf_glusterfs_mnt_flag_rdonly,
		&hf_glusterfs_mnt_flag_nosuid,
		&hf_glusterfs_mnt_flag_nodev,
		&hf_glusterfs_mnt_flag_noexec,
		&hf_glusterfs_mnt_flag_synchronous,
		&hf_glusterfs_mnt_flag_mandlock,
		&hf_glusterfs_mnt_flag_write,
		&hf_glusterfs_mnt_flag_append,
		&hf_glusterfs_mnt_flag_immutable,
		&hf_glusterfs_mnt_flag_noatime,
		&hf_glusterfs_mnt_flag_nodiratime,
		&hf_glusterfs_mnt_flag_relatime,
		NULL
	};

	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_bsize, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_frsize, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_blocks, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_bfree, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_bavail, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_files, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_ffree, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_favail, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_id, offset);

	/* hf_glusterfs_mnt_flags should be FT_UINT64, but that does not work
	 * with bitmasks, only the lower 32 bits are used anyway. */
	if (tree)
		proto_tree_add_bitmask(tree, tvb, offset + 4,
			hf_glusterfs_mnt_flags, ett_glusterfs_mnt_flags,
			flag_bits, ENC_LITTLE_ENDIAN);
	offset += 8;

	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_namemax, offset);

	return offset;
}

/* function for dissecting and adding a gluster dict_t to the tree */
int
gluster_rpc_dissect_dict(proto_tree *tree, tvbuff_t *tvb, int hfindex, int offset)
{
	gchar *key, *value, *name;
	gint items, i, len, roundup, value_len, key_len;

	proto_item *subtree_item;
	proto_tree *subtree;

	proto_item *dict_item = NULL;

	/* create a subtree for all the items in the dict */
	if (hfindex >= 0) {
		header_field_info *hfinfo = proto_registrar_get_nth(hfindex);
		name = (gchar*) hfinfo->name;
	} else
		name = "<NAMELESS DICT STRUCTURE>";

	subtree_item = proto_tree_add_text(tree, tvb, offset, -1, "%s", name);

	subtree = proto_item_add_subtree(subtree_item, ett_gluster_dict);

	len = tvb_get_ntohl(tvb, offset);
	roundup = rpc_roundup(len) - len;
	proto_tree_add_text(subtree, tvb, offset, 4, "[Size: %d (%d bytes inc. RPC-roundup)]", len, rpc_roundup(len));
	offset += 4;

	if (len == 0)
		items = 0;
	else
		items = tvb_get_ntohl(tvb, offset);

	proto_item_append_text(subtree_item, ", contains %d item%s", items, items == 1 ? "" : "s");
	proto_tree_add_text(subtree, tvb, offset, 4, "Items: %d", items);

	if (len == 0)
		return offset;

	offset += 4;

	for (i = 0; i < items; i++) {
		/* key_len is the length of the key without the terminating '\0' */
		/* key_len = tvb_get_ntohl(tvb, offset) + 1; // will be read later */
		offset += 4;
		value_len = tvb_get_ntohl(tvb, offset);
		offset += 4;

		/* read the key, '\0' terminated */
		key = tvb_get_ephemeral_stringz(tvb, offset, &key_len);
		if (tree)
			dict_item = proto_tree_add_text(subtree, tvb, offset, -1, "%s: ", key);
		offset += key_len;

		/* read the value, possibly '\0' terminated */
		value = tvb_get_ephemeral_string(tvb, offset, value_len);
		if (tree) {
			/* keys named "gfid-req" contain a GFID in hex */
			if (value_len == 16 && !strncmp("gfid-req", key, 8)) {
				char *gfid;
				gfid = guid_to_str((e_guid_t*) value);
				proto_item_append_text(dict_item, "%s", gfid);
			} else
				proto_item_append_text(dict_item, "%s", value);
		}
		offset += value_len;
	}

	if (roundup) {
		if (tree)
			proto_tree_add_text(subtree, tvb, offset, -1, "[RPC-roundup bytes: %d]", roundup);
		offset += roundup;
	}

	return offset;
}

int
gluster_dissect_common_reply(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item *errno_item;
	guint op_errno;

	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_ret, offset);

	if (tree) {
		op_errno = tvb_get_ntohl(tvb, offset);
		errno_item = proto_tree_add_int(tree, hf_gluster_op_errno, tvb,
					    offset, 4, op_errno);
		proto_item_append_text(errno_item, " (%s)",
							g_strerror(op_errno));
	}

	offset += 4;

	return offset;
}

static int
glusterfs_gfs3_op_unlink_reply(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb,
					hf_glusterfs_preparent_iatt, offset);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb,
					hf_glusterfs_postparent_iatt, offset);

	return offset;
}

static int
glusterfs_gfs3_op_unlink_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	gchar* path = NULL;
	gchar* bname = NULL;
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_pargfid, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_path, offset, &path);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_bname, offset, &bname);
	return offset;
}

static int
glusterfs_gfs3_op_statfs_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree)
{
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = glusterfs_rpc_dissect_statfs(tree, tvb, offset);
	return offset;
}

static int
glusterfs_gfs3_op_statfs_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	gchar *path = NULL;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_path, offset, &path);

	return offset;
}

static int
glusterfs_gfs3_op_flush_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	return offset;
}

static int
glusterfs_gfs3_op_setxattr_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	gchar *path = NULL;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_path, offset, &path);

	return offset;
}

static int
glusterfs_gfs3_op_opendir_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree)
{
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	return offset;
}

static int
glusterfs_gfs3_op_opendir_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	gchar *path = NULL;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_path, offset, &path);

	return offset;
}

/* rpc/xdr/src/glusterfs3-xdr.c:xdr_gfs3_create_rsp */
static int
glusterfs_gfs3_op_create_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree)
{
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb, hf_glusterfs_iatt,
								offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb,
					hf_glusterfs_preparent_iatt, offset);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb,
					hf_glusterfs_postparent_iatt, offset);

	return offset;
}

/* rpc/xdr/src/glusterfs3-xdr.c:xdr_gfs3_create_req */
static int
glusterfs_gfs3_op_create_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	gchar *path = NULL;
	gchar *bname = NULL;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_pargfid, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = glusterfs_rpc_dissect_mode(tree, tvb, hf_glusterfs_mode, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_path, offset, &path);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_bname, offset, &bname);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_op_lookup_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree)
{
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb, hf_glusterfs_iatt,
								offset);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb,
					hf_glusterfs_postparent_iatt, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_op_lookup_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	gchar *path = NULL;
	gchar *bname = NULL;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_pargfid, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_path, offset, &path);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_bname, offset, &bname);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_op_inodelk_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item *flock_item;
	proto_tree *flock_tree;
	gchar* path = NULL;
	gchar* volume = NULL;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_cmd, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_type, offset);

	flock_item = proto_tree_add_text(tree, tvb, offset, -1, "Flock");
	flock_tree = proto_item_add_subtree(flock_item, ett_glusterfs_flock);
	offset = glusterfs_rpc_dissect_gf_flock(flock_tree, tvb, offset);

	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_path, offset, &path);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_volume, offset, &volume);
	return offset;
}

static int
glusterfs_gfs3_op_readdirp_entry(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item *entry_item;
	proto_tree *entry_tree;
	gchar* path = NULL;

	entry_item = proto_tree_add_text(tree, tvb, offset, -1, "Entry");
	entry_tree = proto_item_add_subtree(entry_item, ett_glusterfs_entry);

	offset = dissect_rpc_uint64(tvb, entry_tree, hf_glusterfs_entry_ino, offset);
	offset = dissect_rpc_uint64(tvb, entry_tree, hf_glusterfs_entry_off, offset);
	offset = dissect_rpc_uint32(tvb, entry_tree, hf_glusterfs_entry_len, offset);
	offset = dissect_rpc_uint32(tvb, entry_tree, hf_glusterfs_entry_type, offset);
	offset = dissect_rpc_string(tvb, entry_tree, hf_glusterfs_entry_path, offset, &path);

	proto_item_append_text(entry_item, " Path:%s", path);

	offset = glusterfs_rpc_dissect_gf_iatt(entry_tree, tvb,
						hf_glusterfs_iatt, offset);

	return offset;
}

/* details in xlators/storage/posix/src/posix.c:posix_fill_readdir() */
static int
glusterfs_gfs3_op_readdirp_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree)
{
	proto_item *errno_item;
	guint op_errno;

	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_entries, offset);

	if (tree) {
		op_errno = tvb_get_ntohl(tvb, offset);
		errno_item = proto_tree_add_int(tree, hf_gluster_op_errno, tvb,
					    offset, 4, op_errno);
		if (op_errno == 0)
			proto_item_append_text(errno_item,
					    " (More READDIRP replies follow)");
		else if (op_errno == 2 /* ENOENT */)
			proto_item_append_text(errno_item,
					    " (Last READDIRP reply)");
	}
	offset += 4;

	offset = dissect_rpc_list(tvb, pinfo, tree, offset,
					    glusterfs_gfs3_op_readdirp_entry);

	return offset;
}

static int
glusterfs_gfs3_op_readdirp_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_size, offset);

	return offset;
}

static int
glusterfs_gfs3_op_setattr_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree)
{
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb,
					hf_glusterfs_preop_iatt, offset);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb,
					hf_glusterfs_postop_iatt, offset);

	return offset;
}

static int
glusterfs_rpc_dissect_setattr(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	static const int *flag_bits[] = {
		&hf_glusterfs_setattr_set_mode,
		&hf_glusterfs_setattr_set_uid,
		&hf_glusterfs_setattr_set_gid,
		&hf_glusterfs_setattr_set_size,
		&hf_glusterfs_setattr_set_atime,
		&hf_glusterfs_setattr_set_mtime,
		&hf_glusterfs_setattr_set_reserved,
		NULL
	};

	if (tree)
		proto_tree_add_bitmask(tree, tvb, offset,
			hf_glusterfs_setattr_valid,
			ett_glusterfs_setattr_valid, flag_bits, ENC_NA);
	offset += 4;

	return offset;
}

static int
glusterfs_gfs3_op_setattr_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	gchar *path = NULL;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid,
								offset);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb, hf_glusterfs_iatt,
								offset);
	offset = glusterfs_rpc_dissect_setattr(tree, tvb, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_path, offset, &path);

	return offset;
}

/*GlusterFS 3_3 fops */

static int
glusterfs_gfs3_3_op_stat_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	return offset;

}

static int
glusterfs_gfs3_3_op_stat_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							 proto_tree *tree)
{
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb, hf_glusterfs_iatt,
								offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict,
								offset);

	return offset;
}

/* glusterfs_gfs3_3_op_mknod_reply() is also used as a ..mkdir_reply() */
static int
glusterfs_gfs3_3_op_mknod_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree)
{
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb, hf_glusterfs_iatt,
								offset);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb,
					hf_glusterfs_preparent_iatt, offset);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb,
					hf_glusterfs_postparent_iatt, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict,
								offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_mknod_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	gchar *bname = NULL;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_pargfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);
	offset = glusterfs_rpc_dissect_mode(tree, tvb, hf_glusterfs_mode, offset);
	offset = glusterfs_rpc_dissect_mode(tree, tvb, hf_glusterfs_umask, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_bname, offset, &bname);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_mkdir_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	gchar *bname = NULL;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_pargfid, offset);
	offset = glusterfs_rpc_dissect_mode(tree, tvb, hf_glusterfs_mode, offset);
	offset = glusterfs_rpc_dissect_mode(tree, tvb, hf_glusterfs_umask, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_bname, offset, &bname);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_readlink_reply(tvbuff_t *tvb, int offset,
					packet_info *pinfo, proto_tree *tree)
{
	gchar* path = NULL;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb, hf_glusterfs_iatt,
								offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_path, offset,
									&path);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict,
								offset);
	return offset;
}

static int
glusterfs_gfs3_3_op_readlink_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_size, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

/* glusterfs_gfs3_3_op_unlink_reply() is also used for ...rmdir_reply() */
static int
glusterfs_gfs3_3_op_unlink_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree)
{
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb,
					hf_glusterfs_preparent_iatt, offset);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb,
					hf_glusterfs_postparent_iatt, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_unlink_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	guint xflags;
	gchar* bname = NULL;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_pargfid, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_bname, offset, &bname);
	xflags = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint_format(tree, hf_glusterfs_xflags, tvb, offset, 4, xflags, "Flags: 0%02o", xflags);
	offset += 4;
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_rmdir_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	gchar* bname = NULL;
	guint xflags;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_pargfid, offset);
	xflags = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint_format(tree, hf_glusterfs_xflags, tvb, offset, 4, xflags, "Flags: 0%02o", xflags);
	offset += 4;
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_bname, offset, &bname);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_symlink_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	gchar *bname    = NULL;
	gchar *linkname = NULL;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_pargfid, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_bname, offset, &bname);
	offset = glusterfs_rpc_dissect_mode(tree, tvb, hf_glusterfs_umask, offset);

	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_linkname, offset, &linkname);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_rename_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{

	gchar *oldbname = NULL;
	gchar *newbname = NULL;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_oldgfid, offset);
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_newgfid, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_oldbname, offset, &oldbname);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_newbname, offset, &newbname);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_rename_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree)
{
	proto_tree *old_tree, *new_tree;
	proto_item *old_item, *new_item;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb, hf_glusterfs_iatt,
								offset);

	old_item = proto_tree_add_text(tree, tvb, offset, -1, "Old parent");
	old_tree = proto_item_add_subtree(old_item, ett_glusterfs_parent_iatt);
	offset = glusterfs_rpc_dissect_gf_iatt(old_tree, tvb,
					hf_glusterfs_preparent_iatt, offset);
	offset = glusterfs_rpc_dissect_gf_iatt(old_tree, tvb,
					hf_glusterfs_postparent_iatt, offset);

	new_item = proto_tree_add_text(tree, tvb, offset, -1, "New parent");
	new_tree = proto_item_add_subtree(new_item, ett_glusterfs_parent_iatt);
	offset = glusterfs_rpc_dissect_gf_iatt(new_tree, tvb,
					hf_glusterfs_preparent_iatt, offset);
	offset = glusterfs_rpc_dissect_gf_iatt(new_tree, tvb,
					hf_glusterfs_postparent_iatt, offset);

	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_link_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	gchar *newbname = NULL;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_oldgfid, offset);
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_newgfid, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_newbname, offset, &newbname);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_truncate_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_open_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree)
{
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	return offset;
}

static int
glusterfs_gfs3_3_op_open_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_read_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree)
{
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb, hf_glusterfs_iatt,
								offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_size, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict,
								offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_read_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_size, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_write_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree)
{
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb,
					hf_glusterfs_preparent_iatt, offset);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb,
					hf_glusterfs_postparent_iatt, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_write_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_size, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_statfs_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree)
{
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = glusterfs_rpc_dissect_statfs(tree, tvb, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_statfs_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_flush_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_fsync_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}
static int
glusterfs_gfs3_3_op_setxattr_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_getxattr_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	gchar* name = NULL;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_namelen, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_name, offset, &name);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}


static int
glusterfs_gfs3_3_op_getxattr_reply(tvbuff_t *tvb, int offset,
					packet_info *pinfo, proto_tree *tree)
{
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_removexattr_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	gchar* name = NULL;
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_name, offset, &name);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_fsyncdir_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_yncdir_data, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_opendir_reply(tvbuff_t *tvb, int offset,
				packet_info *pinfo, proto_tree *tree)
{
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_opendir_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_create_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree)
{
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb, hf_glusterfs_iatt,
								offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb,
					hf_glusterfs_preparent_iatt, offset);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb,
					hf_glusterfs_postparent_iatt, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}


static int
glusterfs_gfs3_3_op_create_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	gchar *bname = NULL;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_pargfid, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = glusterfs_rpc_dissect_mode(tree, tvb, hf_glusterfs_mode, offset);
	offset = glusterfs_rpc_dissect_mode(tree, tvb, hf_glusterfs_umask, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_bname, offset, &bname);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_ftruncate_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_fstat_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_fstat_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree)
{
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb, hf_glusterfs_iatt,
								offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict,
								offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_lk_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_cmd, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_type, offset);
	offset = glusterfs_rpc_dissect_gf_2_flock(tree, tvb, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_lk_reply(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = glusterfs_rpc_dissect_gf_2_flock(tree, tvb, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_access_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_mask, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	return offset;
}

static int
glusterfs_gfs3_3_op_lookup_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	gchar *bname = NULL;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_pargfid, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_bname, offset, &bname);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_readdir_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_size, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_inodelk_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	gchar* volume = NULL;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_cmd, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_type, offset);
	offset = glusterfs_rpc_dissect_gf_2_flock(tree, tvb, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_volume, offset, &volume);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_finodelk_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	gchar* volume = NULL;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);

	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_cmd, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_type, offset);
	offset = glusterfs_rpc_dissect_gf_2_flock(tree, tvb, offset);

	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_volume, offset, &volume);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_entrylk_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	gchar* volume = NULL;
	gchar* name   = NULL;
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_cmd, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_type, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_entrylk_namelen, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_name, offset, &name);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_volume, offset, &volume);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_fentrylk_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	gchar* volume = NULL;
	gchar* name = NULL;
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_cmd, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_type, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_entrylk_namelen, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_name, offset, &name);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_volume, offset, &volume);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_xattrop_reply(tvbuff_t *tvb, int offset,
				packet_info *pinfo, proto_tree *tree)
{
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_xattrop_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_fxattrop_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_fgetxattr_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	gchar* name = NULL;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_namelen, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_name, offset, &name);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
gluter_gfs3_3_op_fsetxattr_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_setattr_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree)
{
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb,
					hf_glusterfs_preop_iatt, offset);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb,
					hf_glusterfs_postop_iatt, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_setattr_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid,
								offset);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb, hf_glusterfs_iatt,
								offset);
	offset = glusterfs_rpc_dissect_setattr(tree, tvb, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_readdirp_reply(tvbuff_t *tvb, int offset,
				packet_info *pinfo, proto_tree *tree)
{
	proto_item *errno_item;
        guint op_errno;

	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_entries, offset);

        if (tree) {
		op_errno = tvb_get_ntohl(tvb, offset);
		errno_item = proto_tree_add_int(tree, hf_gluster_op_errno, tvb,
					    offset, 4, op_errno);
		if (op_errno == 0)
			proto_item_append_text(errno_item,
					    " (More READDIRP replies follow)");
		else if (op_errno == 2 /* ENOENT */)
			proto_item_append_text(errno_item,
					    " (Last READDIRP reply)");
	}
	offset += 4;

	offset = dissect_rpc_list(tvb, pinfo, tree, offset,
					    glusterfs_gfs3_op_readdirp_entry);

        return offset;
}

static int
glusterfs_gfs3_3_op_readdirp_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_size, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_release_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_releasedir_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

/* This function is for common replay. RELEASE , RELEASEDIR and some other function use this method */

static int
glusterfs_gfs3_3_op_common_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree)
{
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

/*
 * GLUSTER3_1_FOP_PROGRAM
 * - xlators/protocol/client/src/client3_1-fops.c
 * - xlators/protocol/server/src/server3_1-fops.c
 */
static const vsff glusterfs3_1_fop_proc[] = {
	{ GFS3_OP_NULL,     "NULL",     NULL, NULL },
	{ GFS3_OP_STAT,     "STAT",     NULL, NULL },
	{ GFS3_OP_READLINK, "READLINK", NULL, NULL },
	{ GFS3_OP_MKNOD,    "MKNOD",    NULL, NULL },
	{ GFS3_OP_MKDIR,    "MKDIR",    NULL, NULL },
	{
		GFS3_OP_UNLINK, "UNLINK",
		glusterfs_gfs3_op_unlink_call, glusterfs_gfs3_op_unlink_reply
	},
	{ GFS3_OP_RMDIR,    "RMDIR",    NULL, NULL },
	{ GFS3_OP_SYMLINK,  "SYMLINK",  NULL, NULL },
	{ GFS3_OP_RENAME,   "RENAME",   NULL, NULL },
	{ GFS3_OP_LINK,     "LINK",     NULL, NULL },
	{ GFS3_OP_TRUNCATE, "TRUNCATE", NULL, NULL },
	{ GFS3_OP_OPEN,     "OPEN",     NULL, NULL },
	{ GFS3_OP_READ,     "READ",     NULL, NULL },
	{ GFS3_OP_WRITE,    "WRITE",    NULL, NULL },
	{
		GFS3_OP_STATFS, "STATFS",
		glusterfs_gfs3_op_statfs_call, glusterfs_gfs3_op_statfs_reply
	},
	{
		GFS3_OP_FLUSH, "FLUSH",
		glusterfs_gfs3_op_flush_call, gluster_dissect_common_reply
	},
	{ GFS3_OP_FSYNC, "FSYNC", NULL, NULL },
	{
		GFS3_OP_SETXATTR, "SETXATTR",
		glusterfs_gfs3_op_setxattr_call, gluster_dissect_common_reply
	},
	{ GFS3_OP_GETXATTR,    "GETXATTR",    NULL, NULL },
	{ GFS3_OP_REMOVEXATTR, "REMOVEXATTR", NULL, NULL },
	{
		GFS3_OP_OPENDIR, "OPENDIR",
		glusterfs_gfs3_op_opendir_call, glusterfs_gfs3_op_opendir_reply
	},
	{ GFS3_OP_FSYNCDIR, "FSYNCDIR", NULL, NULL },
	{ GFS3_OP_ACCESS,   "ACCESS",   NULL, NULL },
	{
		GFS3_OP_CREATE, "CREATE",
		glusterfs_gfs3_op_create_call, glusterfs_gfs3_op_create_reply
	},
	{ GFS3_OP_FTRUNCATE, "FTRUNCATE", NULL, NULL },
	{ GFS3_OP_FSTAT,     "FSTAT",     NULL, NULL },
	{ GFS3_OP_LK,        "LK",        NULL, NULL },
	{
		GFS3_OP_LOOKUP, "LOOKUP",
		glusterfs_gfs3_op_lookup_call, glusterfs_gfs3_op_lookup_reply
	},
	{ GFS3_OP_READDIR, "READDIR", NULL, NULL },
	{
		GFS3_OP_INODELK, "INODELK",
		glusterfs_gfs3_op_inodelk_call, gluster_dissect_common_reply
	},
	{ GFS3_OP_FINODELK,  "FINODELK",  NULL, NULL },
	{ GFS3_OP_ENTRYLK,   "ENTRYLK",   NULL, NULL },
	{ GFS3_OP_FENTRYLK,  "FENTRYLK",  NULL, NULL },
	{ GFS3_OP_XATTROP,   "XATTROP",   NULL, NULL },
	{ GFS3_OP_FXATTROP,  "FXATTROP",  NULL, NULL },
	{ GFS3_OP_FGETXATTR, "FGETXATTR", NULL, NULL },
	{ GFS3_OP_FSETXATTR, "FSETXATTR", NULL, NULL },
	{ GFS3_OP_RCHECKSUM, "RCHECKSUM", NULL, NULL },
	{
		GFS3_OP_SETATTR, "SETATTR",
		glusterfs_gfs3_op_setattr_call, glusterfs_gfs3_op_setattr_reply
	},
	{
		GFS3_OP_FSETATTR, "FSETATTR",
		/* SETATTR and SETFATTS calls and reply are encoded the same */
		glusterfs_gfs3_op_setattr_call, glusterfs_gfs3_op_setattr_reply
	},
	{
		GFS3_OP_READDIRP, "READDIRP",
		glusterfs_gfs3_op_readdirp_call, glusterfs_gfs3_op_readdirp_reply
	},
	{ GFS3_OP_RELEASE,    "RELEASE",    NULL, NULL },
	{ GFS3_OP_RELEASEDIR, "RELEASEDIR", NULL, NULL },
	{ 0, NULL, NULL, NULL }
};


/*
 * GLUSTER3_1_FOP_PROGRAM for 3_3
 * - xlators/protocol/client/src/client3_1-fops.c
 * - xlators/protocol/server/src/server3_1-fops.c
 */
static const vsff glusterfs3_3_fop_proc[] = {
	{ GFS3_OP_NULL, "NULL", NULL, NULL },
	{
	 	GFS3_OP_STAT, "STAT",
		glusterfs_gfs3_3_op_stat_call, glusterfs_gfs3_3_op_stat_reply
	},
	{
		GFS3_OP_READLINK, "READLINK",
		glusterfs_gfs3_3_op_readlink_call, glusterfs_gfs3_3_op_readlink_reply
	},
	{
		GFS3_OP_MKNOD, "MKNOD",
		glusterfs_gfs3_3_op_mknod_call, glusterfs_gfs3_3_op_mknod_reply
	},
	{
		GFS3_OP_MKDIR, "MKDIR",
		glusterfs_gfs3_3_op_mkdir_call, glusterfs_gfs3_3_op_mknod_reply
	},
	{
		GFS3_OP_UNLINK, "UNLINK",
		glusterfs_gfs3_3_op_unlink_call, glusterfs_gfs3_3_op_unlink_reply
	},
	{
		GFS3_OP_RMDIR, "RMDIR",
		glusterfs_gfs3_3_op_rmdir_call, glusterfs_gfs3_3_op_unlink_reply
	},
	{ 	GFS3_OP_SYMLINK, "SYMLINK",
		glusterfs_gfs3_3_op_symlink_call, glusterfs_gfs3_3_op_mknod_reply
	},
	{
		GFS3_OP_RENAME, "RENAME",
		glusterfs_gfs3_3_op_rename_call, glusterfs_gfs3_3_op_rename_reply
	},
	{
		GFS3_OP_LINK, "LINK",
		glusterfs_gfs3_3_op_link_call, glusterfs_gfs3_3_op_mknod_reply
	},
	{
		GFS3_OP_TRUNCATE, "TRUNCATE",
		glusterfs_gfs3_3_op_truncate_call, glusterfs_gfs3_3_op_unlink_reply
	},
	{
		GFS3_OP_OPEN, "OPEN",
		glusterfs_gfs3_3_op_open_call, glusterfs_gfs3_3_op_open_reply
	},
	{
		GFS3_OP_READ, "READ",
		glusterfs_gfs3_3_op_read_call, glusterfs_gfs3_3_op_read_reply
	},
	{
		GFS3_OP_WRITE, "WRITE",
		glusterfs_gfs3_3_op_write_call, glusterfs_gfs3_3_op_write_reply
	},
	{
		GFS3_OP_STATFS, "STATFS",
		glusterfs_gfs3_3_op_statfs_call, glusterfs_gfs3_3_op_statfs_reply
	},
	{
		GFS3_OP_FLUSH, "FLUSH",
		glusterfs_gfs3_3_op_flush_call, glusterfs_gfs3_3_op_common_reply
	},
	{
		GFS3_OP_FSYNC, "FSYNC",
		glusterfs_gfs3_3_op_fsync_call, glusterfs_gfs3_3_op_setattr_reply
	},
	{
		GFS3_OP_SETXATTR, "SETXATTR",
		glusterfs_gfs3_3_op_setxattr_call, glusterfs_gfs3_3_op_common_reply
	},
	{
		GFS3_OP_GETXATTR, "GETXATTR",
		glusterfs_gfs3_3_op_getxattr_call, glusterfs_gfs3_3_op_getxattr_reply
	},
	{
		GFS3_OP_REMOVEXATTR, "REMOVEXATTR",
		glusterfs_gfs3_3_op_removexattr_call, glusterfs_gfs3_3_op_common_reply
	},
	{
		GFS3_OP_OPENDIR, "OPENDIR",
		glusterfs_gfs3_3_op_opendir_call, glusterfs_gfs3_3_op_opendir_reply
	},
	{
		GFS3_OP_FSYNCDIR, "FSYNCDIR",
		glusterfs_gfs3_3_op_fsyncdir_call, glusterfs_gfs3_3_op_common_reply
	},
	{
		GFS3_OP_ACCESS, "ACCESS",
		glusterfs_gfs3_3_op_access_call, glusterfs_gfs3_3_op_common_reply
	},
	{
		GFS3_OP_CREATE, "CREATE",
		glusterfs_gfs3_3_op_create_call, glusterfs_gfs3_3_op_create_reply
	},
	{
		GFS3_OP_FTRUNCATE, "FTRUNCATE",
		glusterfs_gfs3_3_op_ftruncate_call, glusterfs_gfs3_3_op_unlink_reply
	},
	{
		GFS3_OP_FSTAT, "FSTAT",
		glusterfs_gfs3_3_op_fstat_call, glusterfs_gfs3_3_op_fstat_reply
	},
	{
		GFS3_OP_LK, "LK",
		glusterfs_gfs3_3_op_lk_call, glusterfs_gfs3_3_op_lk_reply
	},
	{
		GFS3_OP_LOOKUP, "LOOKUP",
		glusterfs_gfs3_3_op_lookup_call, glusterfs_gfs3_3_op_write_reply
	},
	{
		GFS3_OP_READDIR, "READDIR",
		glusterfs_gfs3_3_op_readdir_call, glusterfs_gfs3_3_op_common_reply
	},
	{
		GFS3_OP_INODELK, "INODELK",
		glusterfs_gfs3_3_op_inodelk_call, glusterfs_gfs3_3_op_common_reply
	},
	{
		GFS3_OP_FINODELK, "FINODELK",
		glusterfs_gfs3_3_op_finodelk_call, glusterfs_gfs3_3_op_common_reply
	},
	{
		GFS3_OP_ENTRYLK, "ENTRYLK",
		glusterfs_gfs3_3_op_entrylk_call, glusterfs_gfs3_3_op_common_reply
	},
	{
		GFS3_OP_FENTRYLK, "FENTRYLK",
		glusterfs_gfs3_3_op_fentrylk_call, glusterfs_gfs3_3_op_common_reply
	},
	{
		GFS3_OP_XATTROP, "XATTROP",
		glusterfs_gfs3_3_op_xattrop_call, glusterfs_gfs3_3_op_xattrop_reply
	},
	/*xattrop and fxattrop replay both are same */
	{
		GFS3_OP_FXATTROP, "FXATTROP",
		glusterfs_gfs3_3_op_fxattrop_call, glusterfs_gfs3_3_op_xattrop_reply
	},
	{
		GFS3_OP_FGETXATTR, "FGETXATTR",
		glusterfs_gfs3_3_op_fgetxattr_call, glusterfs_gfs3_3_op_xattrop_reply
	},
	{
		GFS3_OP_FSETXATTR, "FSETXATTR",
		gluter_gfs3_3_op_fsetxattr_call, glusterfs_gfs3_3_op_common_reply
	},
	{ GFS3_OP_RCHECKSUM, "RCHECKSUM", NULL, NULL },
	{
		GFS3_OP_SETATTR, "SETATTR",
		glusterfs_gfs3_3_op_setattr_call, glusterfs_gfs3_3_op_setattr_reply
	},
	{
		GFS3_OP_FSETATTR, "FSETATTR",
		/* SETATTR and SETFATTS calls and reply are encoded the same */
		glusterfs_gfs3_3_op_setattr_call, glusterfs_gfs3_3_op_setattr_reply
	},
	{
		GFS3_OP_READDIRP, "READDIRP",
		glusterfs_gfs3_3_op_readdirp_call, glusterfs_gfs3_3_op_readdirp_reply
	},
	{
		GFS3_OP_RELEASE, "RELEASE",
		glusterfs_gfs3_3_op_release_call, glusterfs_gfs3_3_op_common_reply
	},
	{
		GFS3_OP_RELEASEDIR, "RELEASEDIR",
 		glusterfs_gfs3_3_op_releasedir_call, glusterfs_gfs3_3_op_common_reply
	},
	{ 0, NULL, NULL, NULL }
};


static const value_string glusterfs3_1_fop_proc_vals[] = {
	{ GFS3_OP_NULL,        "NULL" },
	{ GFS3_OP_STAT,        "STAT" },
	{ GFS3_OP_READLINK,    "READLINK" },
	{ GFS3_OP_MKNOD,       "MKNOD" },
	{ GFS3_OP_MKDIR,       "MKDIR" },
	{ GFS3_OP_UNLINK,      "UNLINK" },
	{ GFS3_OP_RMDIR,       "RMDIR" },
	{ GFS3_OP_SYMLINK,     "SYMLINK" },
	{ GFS3_OP_RENAME,      "RENAME" },
	{ GFS3_OP_LINK,        "LINK" },
	{ GFS3_OP_TRUNCATE,    "TRUNCATE" },
	{ GFS3_OP_OPEN,        "OPEN" },
	{ GFS3_OP_READ,        "READ" },
	{ GFS3_OP_WRITE,       "WRITE" },
	{ GFS3_OP_STATFS,      "STATFS" },
	{ GFS3_OP_FLUSH,       "FLUSH" },
	{ GFS3_OP_FSYNC,       "FSYNC" },
	{ GFS3_OP_SETXATTR,    "SETXATTR" },
	{ GFS3_OP_GETXATTR,    "GETXATTR" },
	{ GFS3_OP_REMOVEXATTR, "REMOVEXATTR" },
	{ GFS3_OP_OPENDIR,     "OPENDIR" },
	{ GFS3_OP_FSYNCDIR,    "FSYNCDIR" },
	{ GFS3_OP_ACCESS,      "ACCESS" },
	{ GFS3_OP_CREATE,      "CREATE" },
	{ GFS3_OP_FTRUNCATE,   "FTRUNCATE" },
	{ GFS3_OP_FSTAT,       "FSTAT" },
	{ GFS3_OP_LK,          "LK" },
	{ GFS3_OP_LOOKUP,      "LOOKUP" },
	{ GFS3_OP_READDIR,     "READDIR" },
	{ GFS3_OP_INODELK,     "INODELK" },
	{ GFS3_OP_FINODELK,    "FINODELK" },
	{ GFS3_OP_ENTRYLK,     "ENTRYLK" },
	{ GFS3_OP_FENTRYLK,    "FENTRYLK" },
	{ GFS3_OP_XATTROP,     "XATTROP" },
	{ GFS3_OP_FXATTROP,    "FXATTROP" },
	{ GFS3_OP_FGETXATTR,   "FGETXATTR" },
	{ GFS3_OP_FSETXATTR,   "FSETXATTR" },
	{ GFS3_OP_RCHECKSUM,   "RCHECKSUM" },
	{ GFS3_OP_SETATTR,     "SETATTR" },
	{ GFS3_OP_FSETATTR,    "FSETATTR" },
	{ GFS3_OP_READDIRP,    "READDIRP" },
	{ GFS3_OP_RELEASE,     "RELEASE" },
	{ GFS3_OP_RELEASEDIR,  "RELEASEDIR" },
	{ 0, NULL }
};
static value_string_ext glusterfs3_1_fop_proc_vals_ext = VALUE_STRING_EXT_INIT(glusterfs3_1_fop_proc_vals);

/* dir-entry types */
static const value_string glusterfs_entry_type_names[] = {
	{ DT_UNKNOWN, "DT_UNKNOWN" },
	{ DT_FIFO,    "DT_FIFO" },
	{ DT_CHR,     "DT_CHR" },
	{ DT_DIR,     "DT_DIR" },
	{ DT_BLK,     "DT_BLK" },
	{ DT_REG,     "DT_REG" },
	{ DT_LNK,     "DT_LNK" },
	{ DT_SOCK,    "DT_SOCK" },
	{ DT_WHT,     "DT_WHT" },
	{ 0, NULL }
};
static value_string_ext glusterfs_entry_type_names_ext = VALUE_STRING_EXT_INIT(glusterfs_entry_type_names);

/* Normal locking commands */
static const value_string glusterfs_lk_cmd_names[] = {
	{ GF_LK_GETLK,       "GF_LK_GETLK" },
	{ GF_LK_SETLK,       "GF_LK_SETLK" },
	{ GF_LK_SETLKW,      "GF_LK_SETLKW" },
	{ GF_LK_RESLK_LCK,   "GF_LK_RESLK_LCK" },
	{ GF_LK_RESLK_LCKW,  "GF_LK_RESLK_LCKW" },
	{ GF_LK_RESLK_UNLCK, "GF_LK_RESLK_UNLCK" },
	{ GF_LK_GETLK_FD,    "GF_LK_GETLK_FD" },
	{ 0, NULL }
};
static value_string_ext glusterfs_lk_cmd_names_ext = VALUE_STRING_EXT_INIT(glusterfs_lk_cmd_names);

/* Different lock types */
static const value_string glusterfs_lk_type_names[] = {
	{ GF_LK_F_RDLCK, "GF_LK_F_RDLCK" },
	{ GF_LK_F_WRLCK, "GF_LK_F_WRLCK" },
	{ GF_LK_F_UNLCK, "GF_LK_F_UNLCK" },
	{ GF_LK_EOL,     "GF_LK_EOL" },
	{ 0, NULL }
};

static const value_string glusterfs_lk_whence[] = {
	{ GF_LK_SEEK_SET, "SEEK_SET" },
	{ GF_LK_SEEK_CUR, "SEEK_CUR" },
	{ GF_LK_SEEK_END, "SEEK_END" },
	{ 0, NULL }
};

void
proto_register_glusterfs(void)
{
	/* Setup list of header fields  See Section 1.6.1 for details */
	static hf_register_info hf[] = {
		/* programs */
		{ &hf_glusterfs_proc,
			{ "GlusterFS", "glusterfs.proc", FT_UINT32, BASE_DEC | BASE_EXT_STRING,
				&glusterfs3_1_fop_proc_vals_ext, 0, NULL, HFILL }
		},
		/* fields used by multiple programs/procedures and other
		 * Gluster dissectors with gluster_dissect_common_reply() */
		{ &hf_gluster_op_ret,
			{ "Return value", "gluster.op_ret", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_op_errno,
			{ "Errno", "gluster.op_errno", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		/* GlusterFS specific */
		{ &hf_glusterfs_gfid,
			{ "GFID", "glusterfs.gfid", FT_GUID,
				BASE_NONE, NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_pargfid,
			{ "Parent GFID", "glusterfs.pargfid", FT_GUID,
				BASE_NONE, NULL, 0,
				"GFID of the parent directory", HFILL }
		},
		{ &hf_glusterfs_oldgfid,
			{ "Old GFID", "glusterfs.oldgfid", FT_BYTES,
				BASE_NONE, NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_newgfid,
			{ "New GFID", "glusterfs.newgfid", FT_BYTES,
				BASE_NONE, NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_path,
			{ "Path", "glusterfs.path", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_bname,
			{ "Basename", "glusterfs.bname", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_dict,
			{ "Dict", "glusterfs.dict", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_fd,
			{ "File Descriptor", "glusterfs.fd", FT_UINT64, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_offset,
			{ "Offset", "glusterfs.offset", FT_UINT64, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_size,
			{ "Size", "glusterfs.size", FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_type,
			{ "Type", "glusterfs.type", FT_INT32, BASE_DEC,
				VALS(glusterfs_lk_type_names), 0, NULL, HFILL }
		},
		{ &hf_glusterfs_cmd,
			{ "Command", "glusterfs.cmd", FT_INT32, BASE_DEC | BASE_EXT_STRING,
				&glusterfs_lk_cmd_names_ext, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_volume,
			{ "Volume", "glusterfs.volume", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_namelen,
			{ "Name Lenth", "glusterfs.namelen", FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_linkname,
			{ "Linkname", "glusterfs.linkname", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_umask,
			{ "Umask", "glusterfs.umask", FT_UINT32, BASE_OCT,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_mask,
			{ "Mask", "glusterfs.mask", FT_UINT32, BASE_OCT,
				NULL, 0, NULL, HFILL }
		},

		{ &hf_glusterfs_entries, /* READDIRP returned <x> entries */
			{ "Entries returned", "glusterfs.entries", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		/* Flags passed on to OPEN, CREATE etc, based on */
		{ &hf_glusterfs_flags,
			{ "Flags", "glusterfs.flags", FT_UINT32, BASE_OCT,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_flags_rdonly,
			{ "O_RDONLY", "glusterfs.flags.rdonly", FT_BOOLEAN, 32,
				TFS(&glusterfs_notset_set), 0xffffffff, NULL, HFILL }
		},
		{ &hf_glusterfs_flags_wronly,
			{ "O_WRONLY", "glusterfs.flags.wronly", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), 00000001, NULL, HFILL }
		},
		{ &hf_glusterfs_flags_rdwr,
			{ "O_RDWR", "glusterfs.flags.rdwr", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), 00000002, NULL, HFILL }
		},
		{ &hf_glusterfs_flags_accmode,
			{ "O_ACCMODE", "glusterfs.flags.accmode", FT_UINT32, BASE_DEC,
				VALS(glusterfs_accmode_vals), 00000003, NULL, HFILL }
		},
		{ &hf_glusterfs_flags_append,
			{ "O_APPEND", "glusterfs.flags.append", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), 00002000, NULL, HFILL }
		},
		{ &hf_glusterfs_flags_async,
			{ "O_ASYNC", "glusterfs.flags.async", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), 00020000, NULL, HFILL }
		},
		{ &hf_glusterfs_flags_cloexec,
			{ "O_CLOEXEC", "glusterfs.flags.cloexec", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), 02000000, NULL, HFILL }
		},
		{ &hf_glusterfs_flags_creat,
			{ "O_CREAT", "glusterfs.flags.creat", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), 00000100, NULL, HFILL }
		},
		{ &hf_glusterfs_flags_direct,
			{ "O_DIRECT", "glusterfs.flags.direct", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), 00040000, NULL, HFILL }
		},
		{ &hf_glusterfs_flags_directory,
			{ "O_DIRECTORY", "glusterfs.flags.directory", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), 00200000, NULL, HFILL }
		},
		{ &hf_glusterfs_flags_excl,
			{ "O_EXCL", "glusterfs.flags.excl", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), 00000200, NULL, HFILL }
		},
		{ &hf_glusterfs_flags_largefile,
			{ "O_LARGEFILE", "glusterfs.flags.largefile", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), 00100000, NULL, HFILL }
		},
		{ &hf_glusterfs_flags_noatime,
			{ "O_NOATIME", "glusterfs.flags.noatime", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), 01000000, NULL, HFILL }
		},
		{ &hf_glusterfs_flags_noctty,
			{ "O_NOCTTY", "glusterfs.flags.noctty", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), 00000400, NULL, HFILL }
		},
		{ &hf_glusterfs_flags_nofollow,
			{ "O_NOFOLLOW", "glusterfs.flags.nofollow", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), 00400000, NULL, HFILL }
		},
		{ &hf_glusterfs_flags_nonblock,
			{ "O_NONBLOCK", "glusterfs.flags.nonblock", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), 00004000, NULL, HFILL }
		},
		{ &hf_glusterfs_flags_ndelay,
			{ "O_NDELAY", "glusterfs.flags.ndelay", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), 00004000, NULL, HFILL }
		},
		{ &hf_glusterfs_flags_sync,
			{ "O_SYNC", "glusterfs.flags.sync", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), 00010000, NULL, HFILL }
		},
		{ &hf_glusterfs_flags_trunc,
			{ "O_TRUNC", "glusterfs.flags.trunc", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), 00001000, NULL, HFILL }
		},
		{ &hf_glusterfs_flags_reserved,
			{ "Unused", "glusterfs.flags.reserved", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), 037774000074, NULL, HFILL }
		},
		/* access modes */
		{ &hf_glusterfs_mode,
			{ "Mode", "glusterfs.mode", FT_UINT32, BASE_OCT,
				NULL, 0, "Access Permissions", HFILL }
		},
		{ &hf_glusterfs_mode_suid,
			{ "S_ISUID", "glusterfs.mode.s_isuid", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), (04000), "set-user-ID", HFILL }
		},
		{ &hf_glusterfs_mode_sgid,
			{ "S_ISGID", "glusterfs.mode.s_isgid", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), (02000), "set-group-ID", HFILL }
		},
		{ &hf_glusterfs_mode_svtx,
			{ "S_ISVTX", "glusterfs.mode.s_isvtx", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), (01000), "sticky bit", HFILL }
		},
		{ &hf_glusterfs_mode_rusr,
			{ "S_IRUSR", "glusterfs.mode.s_irusr", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), (00400), "read by owner", HFILL }
		},
		{ &hf_glusterfs_mode_wusr,
			{ "S_IWUSR", "glusterfs.mode.s_iwusr", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), (00200), "write by owner", HFILL }
		},
		{ &hf_glusterfs_mode_xusr,
			{ "S_IXUSR", "glusterfs.mode.s_ixusr", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), (00100), "execute/search by owner", HFILL }
		},
		{ &hf_glusterfs_mode_rgrp,
			{ "S_IRGRP", "glusterfs.mode.s_irgrp", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), (00040), "read by group", HFILL }
		},
		{ &hf_glusterfs_mode_wgrp,
			{ "S_IWGRP", "glusterfs.mode.s_iwgrp", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), (00020), "write by group", HFILL }
		},
		{ &hf_glusterfs_mode_xgrp,
			{ "S_IXGRP", "glusterfs.mode.s_ixgrp", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), (00010), "execute/search by group", HFILL }
		},
		{ &hf_glusterfs_mode_roth,
			{ "S_IROTH", "glusterfs.mode.s_iroth", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), (00004), "read by others", HFILL }
		},
		{ &hf_glusterfs_mode_woth,
			{ "S_IWOTH", "glusterfs.mode.s_iwoth", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), (00002), "write by others", HFILL }
		},
		{ &hf_glusterfs_mode_xoth,
			{ "S_IXOTH", "glusterfs.mode.s_ixoth", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), (00001), "execute/search by others", HFILL }
		},
		{ &hf_glusterfs_mode_reserved,
			{ "Reserved", "glusterfs.mode.reserved", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), (~07777), "execute/search by others", HFILL }
		},
		/* the dir-entry structure */
		{ &hf_glusterfs_entry_ino,
			{ "Inode", "glusterfs.entry.ino", FT_UINT64, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_entry_off, /* like telldir() */
			{ "Offset", "glusterfs.entry.d_off", FT_UINT64, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_entry_len, /* length of the path string */
			{ "Path length", "glusterfs.entry.len", FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_entry_type,
		  { "Type", "glusterfs.entry.d_type", FT_UINT32, BASE_DEC | BASE_EXT_STRING,
				&glusterfs_entry_type_names_ext, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_entry_path,
			{ "Path", "glusterfs.entry.path", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		/* the IATT structure */
		{ &hf_glusterfs_iatt,
			{ "IATT", "glusterfs.iatt", FT_NONE, BASE_NONE, NULL,
				0, NULL, HFILL }
		},
		{ &hf_glusterfs_preparent_iatt,
			{ "Pre-operation parent IATT", "glusterfs.preparent_iatt", FT_NONE, BASE_NONE, NULL,
				0, NULL, HFILL }
		},
		{ &hf_glusterfs_postparent_iatt,
			{ "Post-operation parent IATT", "glusterfs.postparent_iatt", FT_NONE, BASE_NONE, NULL,
				0, NULL, HFILL }
		},
		{ &hf_glusterfs_preop_iatt,
			{ "Pre-operation IATT", "glusterfs.preop_iatt", FT_NONE, BASE_NONE, NULL,
				0, NULL, HFILL }
		},
		{ &hf_glusterfs_postop_iatt,
			{ "Post-operation IATT", "glusterfs.postop_iatt", FT_NONE, BASE_NONE, NULL,
				0, NULL, HFILL }
		},
		{ &hf_glusterfs_ia_ino,
			{ "Inode", "glusterfs.ia_ino", FT_UINT64, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_ia_dev,
			{ "Device", "glusterfs.ia_dev", FT_UINT64, BASE_HEX,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_ia_mode,
			{ "Mode", "glusterfs.ia_mode", FT_UINT32, BASE_OCT,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_ia_nlink,
			{ "Number of hard links", "glusterfs.ia_nlink",
				FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_ia_uid,
			{ "UID", "glusterfs.ia_uid", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_ia_gid,
			{ "GID", "glusterfs.ia_gid", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_ia_rdev,
			{ "Root device", "glusterfs.ia_rdev", FT_UINT64,
				BASE_HEX, NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_ia_size,
			{ "Size", "glusterfs.ia_size", FT_UINT64, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_ia_blksize,
			{ "Block size", "glusterfs.ia_blksize", FT_INT32,
				BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_ia_blocks,
			{ "Blocks", "glusterfs.ia_blocks", FT_UINT64,
				BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_ia_atime,
			{ "Time of last access", "glusterfs.ia_atime",
				FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
				NULL, HFILL }
		},
		{ &hf_glusterfs_ia_mtime,
			{ "Time of last modification", "glusterfs.ia_mtime",
				FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
				NULL, HFILL }
		},
		{ &hf_glusterfs_ia_ctime,
			{ "Time of last status change", "glusterfs.ia_ctime",
				FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
				NULL, HFILL }
		},

		/* gf_flock */
		{ &hf_glusterfs_flock_type,
			{ "Type", "glusterfs.flock.type", FT_UINT32, BASE_DEC,
				VALS(glusterfs_lk_type_names), 0, NULL, HFILL }
		},
		{ &hf_glusterfs_flock_whence,
			{ "Whence", "glusterfs.flock.whence", FT_UINT32,
				BASE_DEC, VALS(glusterfs_lk_whence), 0, NULL,
				HFILL }
		},
		{ &hf_glusterfs_flock_start,
			{ "Start", "glusterfs.flock.start", FT_UINT64,
				BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_flock_len,
			{ "Length", "glusterfs.flock.len", FT_UINT64, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_flock_pid,
			{ "PID", "glusterfs.flock.pid", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_flock_owner,
			{ "Owner", "glusterfs.flock.owner", FT_BYTES,
				BASE_NONE, NULL, 0, NULL, HFILL }
		},

		/* statvfs descriptions from 'man 2 statvfs' on Linix */
		{ &hf_glusterfs_bsize,
			{ "File system block size", "glusterfs.statfs.bsize",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_frsize,
			{ "Fragment size", "glusterfs.statfs.frsize",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_blocks,
			{ "Size of fs in f_frsize units",
				"glusterfs.statfs.blocks", FT_UINT64, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_bfree,
			{ "# free blocks", "glusterfs.statfs.bfree", FT_UINT64,
				BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_bavail,
			{ "# free blocks for non-root",
				"glusterfs.statfs.bavail", FT_UINT64, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_files,
			{ "# inodes", "glusterfs.statfs.files", FT_UINT64,
				BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_ffree,
			{ "# free inodes", "glusterfs.statfs.ffree", FT_UINT64,
				BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_favail,
			{ "# free inodes for non-root",
				"glusterfs.statfs.favail", FT_UINT64, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_id,
			{ "File system ID", "glusterfs.statfs.fsid", FT_UINT64,
				BASE_HEX, NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_mnt_flags,
			{ "Mount flags", "glusterfs.statfs.flags", FT_UINT32,
				BASE_HEX, NULL, 0, NULL, HFILL }
		},
		/* ST_* flags from /usr/include/bits/statvfs.h */
		{ &hf_glusterfs_mnt_flag_rdonly,
			{ "ST_RDONLY", "glusterfs.statfs.flag.rdonly",
				FT_BOOLEAN, 32, TFS(&tfs_set_notset), 1, NULL,
				HFILL }
		},
		{ &hf_glusterfs_mnt_flag_nosuid,
			{ "ST_NOSUID", "glusterfs.statfs.flag.nosuid",
				FT_BOOLEAN, 32, TFS(&tfs_set_notset), 2, NULL,
				HFILL }
		},
		{ &hf_glusterfs_mnt_flag_nodev,
			{ "ST_NODEV", "glusterfs.statfs.flag.nodev",
				FT_BOOLEAN, 32, TFS(&tfs_set_notset), 4, NULL,
				HFILL }
		},
		{ &hf_glusterfs_mnt_flag_noexec,
			{ "ST_EXEC", "glusterfs.statfs.flag.noexec",
				FT_BOOLEAN, 32, TFS(&tfs_set_notset), 8, NULL,
				HFILL }
		},
		{ &hf_glusterfs_mnt_flag_synchronous,
			{ "ST_SYNCHRONOUS",
				"glusterfs.statfs.flag.synchronous",
				FT_BOOLEAN, 32, TFS(&tfs_set_notset), 16, NULL,
				HFILL }
		},
		{ &hf_glusterfs_mnt_flag_mandlock,
			{ "ST_MANDLOCK", "glusterfs.statfs.flag.mandlock",
				FT_BOOLEAN, 32, TFS(&tfs_set_notset), 64, NULL,
				HFILL }
		},
		{ &hf_glusterfs_mnt_flag_write,
			{ "ST_WRITE", "glusterfs.statfs.flag.write",
				FT_BOOLEAN, 32, TFS(&tfs_set_notset), 128,
				NULL, HFILL }
		},
		{ &hf_glusterfs_mnt_flag_append,
			{ "ST_APPEND", "glusterfs.statfs.flag.append",
				FT_BOOLEAN, 32, TFS(&tfs_set_notset), 256,
				NULL, HFILL }
		},
		{ &hf_glusterfs_mnt_flag_immutable,
			{ "ST_IMMUTABLE", "glusterfs.statfs.flag.immutable",
				FT_BOOLEAN, 32, TFS(&tfs_set_notset), 512,
				NULL, HFILL }
		},
		{ &hf_glusterfs_mnt_flag_noatime,
			{ "ST_NOATIME", "glusterfs.statfs.flag.noatime",
				FT_BOOLEAN, 32, TFS(&tfs_set_notset), 1024,
				NULL, HFILL }
		},
		{ &hf_glusterfs_mnt_flag_nodiratime,
			{ "ST_NODIRATIME", "glusterfs.statfs.flag.nodiratime",
				FT_BOOLEAN, 32, TFS(&tfs_set_notset), 2048,
				NULL, HFILL }
		},
		{ &hf_glusterfs_mnt_flag_relatime,
			{ "ST_RELATIME", "glusterfs.statfs.flag.relatime",
				FT_BOOLEAN, 32, TFS(&tfs_set_notset), 4096,
				NULL, HFILL }
		},
		{ &hf_glusterfs_namemax,
			{ "Maximum filename length",
				"glusterfs.statfs.namemax", FT_UINT64,
				BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_setattr_valid,
			{ "Set attributes", "glusterfs.setattr.valid",
				FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
		},
		/* setattr.valid flags from libglusterfs/src/xlator.h */
		{ &hf_glusterfs_setattr_set_mode,
			{ "SET_ATTR_MODE", "glusterfs.setattr.set_mode",
				FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x1,
				NULL, HFILL }
		},
		{ &hf_glusterfs_setattr_set_uid,
			{ "SET_ATTR_UID", "glusterfs.setattr.set_uid",
				FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x2,
				NULL, HFILL }
		},
		{ &hf_glusterfs_setattr_set_gid,
			{ "SET_ATTR_GID", "glusterfs.setattr.set_gid",
				FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x4,
				NULL, HFILL }
		},
		{ &hf_glusterfs_setattr_set_size,
			{ "SET_ATTR_SIZE", "glusterfs.setattr.set_size",
				FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x8,
				NULL, HFILL }
		},
		{ &hf_glusterfs_setattr_set_atime,
			{ "SET_ATTR_ATIME", "glusterfs.setattr.set_atime",
				FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x10,
				NULL, HFILL }
		},
		{ &hf_glusterfs_setattr_set_mtime,
			{ "SET_ATTR_MTIME", "glusterfs.setattr.set_mtime",
				FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x20,
				NULL, HFILL }
		},
		{ &hf_glusterfs_setattr_set_reserved,
			{ "Reserved", "glusterfs.setattr.set_reserved",
				FT_BOOLEAN, 32, TFS(&tfs_set_notset), ~0x3f,
				NULL, HFILL }
		},
		{ &hf_glusterfs_xflags,
			{ "XFlags", "glusterfs.xflags", FT_UINT32, BASE_OCT,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_oldbname,
			{ "OldBasename", "glusterfs.oldbname", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_newbname,
			{ "NewBasename", "glusterfs.newbname", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_name,
			{ "Name", "glusterfs.name", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_yncdir_data,
			{ "Data", "glusterfs.fsyncdir.data", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		/* For entry an fentry lk */
		{ &hf_glusterfs_entrylk_namelen,
			{ "File Descriptor", "glusterfs.entrylk.namelen", FT_UINT64, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_glusterfs,
		&ett_glusterfs_flags,
		&ett_glusterfs_mnt_flags,
		&ett_glusterfs_mode,
		&ett_glusterfs_entry,
		&ett_glusterfs_setattr_valid,
		&ett_glusterfs_parent_iatt,
		&ett_glusterfs_iatt,
		&ett_glusterfs_flock,
		&ett_gluster_dict,
		&ett_gluster_dict_items
	};

	/* Register the protocol name and description */
	proto_glusterfs = proto_register_protocol("GlusterFS", "GlusterFS",
								"glusterfs");
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_glusterfs, hf, array_length(hf));
}

void
proto_reg_handoff_glusterfs(void)
{
	rpc_init_prog(proto_glusterfs, GLUSTER3_1_FOP_PROGRAM, ett_glusterfs);
	rpc_init_proc_table(GLUSTER3_1_FOP_PROGRAM, 310, glusterfs3_1_fop_proc,
							hf_glusterfs_proc);
	rpc_init_proc_table(GLUSTER3_1_FOP_PROGRAM, 330, glusterfs3_3_fop_proc,
							hf_glusterfs_proc);

}

