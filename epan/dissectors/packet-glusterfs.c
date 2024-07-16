/* packet-glusterfs.c
 * Routines for GlusterFS dissection
 * Copyright 2012, Niels de Vos <ndevos@redhat.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 *
 * References to source files point in general to the glusterfs sources.
 * There is currently no RFC or other document where the protocol is
 * completely described. The glusterfs sources can be found at:
 * - https://github.com/gluster/glusterfs
 *
 * The coding-style is roughly the same as the one use in the Linux kernel,
 * see http://www.kernel.org/doc/Documentation/CodingStyle.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/to_str.h>

#include "packet-rpc.h"
#include "packet-gluster.h"

void proto_register_glusterfs(void);
void proto_reg_handoff_glusterfs(void);

/* Initialize the protocol and registered fields */
static int proto_glusterfs;

/* programs and procedures */
static int hf_glusterfs_proc;

/* fields used by multiple programs/procedures */
static int hf_gluster_op_ret;
static int hf_gluster_op_errno;

/* GlusterFS specific */
static int hf_glusterfs_gfid;
static int hf_glusterfs_pargfid;
static int hf_glusterfs_oldgfid;
static int hf_glusterfs_newgfid;
static int hf_glusterfs_path;
static int hf_glusterfs_bname;
static int hf_glusterfs_dict;
static int hf_glusterfs_fd;
static int hf_glusterfs_offset;
static int hf_glusterfs_size;
static int hf_glusterfs_size64;
static int hf_glusterfs_volume;
static int hf_glusterfs_cmd;
static int hf_glusterfs_type;
static int hf_glusterfs_entries;
static int hf_glusterfs_xflags;
static int hf_glusterfs_linkname;
static int hf_glusterfs_umask;
static int hf_glusterfs_mask;
static int hf_glusterfs_name;
static int hf_glusterfs_namelen;
static int hf_glusterfs_whence;

/* flags passed on to OPEN, CREATE etc.*/
static int hf_glusterfs_flags;
static int hf_glusterfs_flags_rdonly;
static int hf_glusterfs_flags_wronly;
static int hf_glusterfs_flags_rdwr;
static int hf_glusterfs_flags_accmode;
static int hf_glusterfs_flags_append;
static int hf_glusterfs_flags_async;
static int hf_glusterfs_flags_cloexec;
static int hf_glusterfs_flags_creat;
static int hf_glusterfs_flags_direct;
static int hf_glusterfs_flags_directory;
static int hf_glusterfs_flags_excl;
static int hf_glusterfs_flags_largefile;
static int hf_glusterfs_flags_noatime;
static int hf_glusterfs_flags_noctty;
static int hf_glusterfs_flags_nofollow;
static int hf_glusterfs_flags_nonblock;
static int hf_glusterfs_flags_ndelay;
static int hf_glusterfs_flags_sync;
static int hf_glusterfs_flags_trunc;
static int hf_glusterfs_flags_reserved;

/* access modes  */
static int hf_glusterfs_mode;
static int hf_glusterfs_mode_suid;
static int hf_glusterfs_mode_sgid;
static int hf_glusterfs_mode_svtx;
static int hf_glusterfs_mode_rusr;
static int hf_glusterfs_mode_wusr;
static int hf_glusterfs_mode_xusr;
static int hf_glusterfs_mode_rgrp;
static int hf_glusterfs_mode_wgrp;
static int hf_glusterfs_mode_xgrp;
static int hf_glusterfs_mode_roth;
static int hf_glusterfs_mode_woth;
static int hf_glusterfs_mode_xoth;
static int hf_glusterfs_mode_reserved;

/* dir-entry */
static int hf_glusterfs_entry_ino;
static int hf_glusterfs_entry_off;
static int hf_glusterfs_entry_len;
static int hf_glusterfs_entry_type;
static int hf_glusterfs_entry_path;

/* gf_iatt */
static int hf_glusterfs_iatt;
static int hf_glusterfs_preparent_iatt;
static int hf_glusterfs_postparent_iatt;
static int hf_glusterfs_preop_iatt;
static int hf_glusterfs_postop_iatt;
static int hf_glusterfs_ia_ino;
static int hf_glusterfs_ia_dev;
static int hf_glusterfs_ia_mode;
static int hf_glusterfs_ia_nlink;
static int hf_glusterfs_ia_uid;
static int hf_glusterfs_ia_gid;
static int hf_glusterfs_ia_rdev;
static int hf_glusterfs_ia_size;
static int hf_glusterfs_ia_blksize;
static int hf_glusterfs_ia_blocks;
static int hf_glusterfs_ia_atime;
static int hf_glusterfs_ia_mtime;
static int hf_glusterfs_ia_ctime;

static int hf_glusterfs_iattx;
static int hf_glusterfs_preparent_iattx;
static int hf_glusterfs_postparent_iattx;
static int hf_glusterfs_preop_iattx;
static int hf_glusterfs_postop_iattx;
static int hf_glusterfs_iax_flags;
static int hf_glusterfs_iax_attributes;
static int hf_glusterfs_iax_attributes_mask;
static int hf_glusterfs_iax_atime;
static int hf_glusterfs_iax_mtime;
static int hf_glusterfs_iax_ctime;
static int hf_glusterfs_iax_btime;
static int hf_glusterfs_iax_atime_nsec;
static int hf_glusterfs_iax_mtime_nsec;
static int hf_glusterfs_iax_ctime_nsec;
static int hf_glusterfs_iax_btime_nsec;


/* gf_flock */
static int hf_glusterfs_flock_type;
static int hf_glusterfs_flock_whence;
static int hf_glusterfs_flock_start;
static int hf_glusterfs_flock_len;
static int hf_glusterfs_flock_pid;
static int hf_glusterfs_flock_owner;

/* statfs */
static int hf_glusterfs_bsize;
static int hf_glusterfs_frsize;
static int hf_glusterfs_blocks;
static int hf_glusterfs_bfree;
static int hf_glusterfs_bavail;
static int hf_glusterfs_files;
static int hf_glusterfs_ffree;
static int hf_glusterfs_favail;
static int hf_glusterfs_id;
static int hf_glusterfs_mnt_flags;
static int hf_glusterfs_mnt_flag_rdonly;
static int hf_glusterfs_mnt_flag_nosuid;
static int hf_glusterfs_mnt_flag_nodev;
static int hf_glusterfs_mnt_flag_noexec;
static int hf_glusterfs_mnt_flag_synchronous;
static int hf_glusterfs_mnt_flag_mandlock;
static int hf_glusterfs_mnt_flag_write;
static int hf_glusterfs_mnt_flag_append;
static int hf_glusterfs_mnt_flag_immutable;
static int hf_glusterfs_mnt_flag_noatime;
static int hf_glusterfs_mnt_flag_nodiratime;
static int hf_glusterfs_mnt_flag_relatime;
static int hf_glusterfs_namemax;

static int hf_glusterfs_setattr_valid;
/* flags for setattr.valid */
static int hf_glusterfs_setattr_set_mode;
static int hf_glusterfs_setattr_set_uid;
static int hf_glusterfs_setattr_set_gid;
static int hf_glusterfs_setattr_set_size;
static int hf_glusterfs_setattr_set_atime;
static int hf_glusterfs_setattr_set_mtime;
static int hf_glusterfs_setattr_set_reserved;

/* Rename */
static int hf_glusterfs_oldbname;
static int hf_glusterfs_newbname;

/* for FSYNC/FSYNCDIR */
static int hf_glusterfs_fsync_flags;
static int hf_glusterfs_fsync_flag_datasync;
static int hf_glusterfs_fsync_flag_unknown;

/* for entrylk */
static int hf_glusterfs_entrylk_namelen;

static int hf_gluster_dict_xdr_size;
static int hf_gluster_dict_size;
static int hf_gluster_num_dict_items;
static int hf_gluster_rpc_roundup_bytes;
static int hf_gluster_trusted_afr_key;
static int hf_gluster_dict_value;


/* Initialize the subtree pointers */
static int ett_glusterfs;
static int ett_glusterfs_flags;
static int ett_glusterfs_mnt_flags;
static int ett_glusterfs_mode;
static int ett_glusterfs_setattr_valid;
static int ett_glusterfs_parent_iatt;
static int ett_glusterfs_iatt;
static int ett_glusterfs_entry;
static int ett_glusterfs_flock;
static int ett_glusterfs_fsync_flags;
static int ett_gluster_dict;
static int ett_gluster_dict_items;

static int
glusterfs_rpc_dissect_gfid(proto_tree *tree, tvbuff_t *tvb, int hfindex, int offset)
{
	proto_tree_add_item(tree, hfindex, tvb, offset, 16, ENC_NA);
	offset += 16;

	return offset;
}

static int
glusterfs_rpc_dissect_mode(proto_tree *tree, tvbuff_t *tvb, int hfindex,
								int offset)
{
	static int * const mode_bits[] = {
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

	proto_tree_add_bitmask(tree, tvb, offset, hfindex,
			ett_glusterfs_mode, mode_bits, ENC_BIG_ENDIAN);

	offset += 4;
	return offset;
}

/*
 * from rpc/xdr/src/glusterfs3-xdr.c:xdr_gf_iatt()
 */
int
glusterfs_rpc_dissect_gf_iatt(proto_tree *tree, tvbuff_t *tvb, int hfindex,
								int offset)
{
	proto_item *iatt_item;
	proto_tree *iatt_tree;
	int start_offset = offset;

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

	proto_tree_add_item(iatt_tree, hf_glusterfs_ia_atime, tvb,
			offset, 8, ENC_TIME_SECS_NSECS|ENC_BIG_ENDIAN);
	offset += 8;

	proto_tree_add_item(iatt_tree, hf_glusterfs_ia_mtime, tvb,
			offset, 8, ENC_TIME_SECS_NSECS|ENC_BIG_ENDIAN);
	offset += 8;

	proto_tree_add_item(iatt_tree, hf_glusterfs_ia_ctime, tvb,
			offset, 8, ENC_TIME_SECS_NSECS|ENC_BIG_ENDIAN);
	offset += 8;

	proto_item_set_len (iatt_item, offset - start_offset);

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

	proto_tree_add_item(tree, hf_glusterfs_flock_owner, tvb, offset, 8, ENC_NA);
	offset += 8;

	return offset;
}

static int
glusterfs_rpc_dissect_gf_2_flock(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	proto_item *flock_item;
	proto_tree *flock_tree;
	int len;
	int start_offset = offset;

	flock_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_glusterfs_flock, &flock_item, "Flock");

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

	proto_tree_add_item(flock_tree, hf_glusterfs_flock_owner, tvb, offset, len, ENC_NA);
	offset += len;

	proto_item_set_len (flock_item, offset - start_offset);

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
	bool rdonly;
	uint32_t accmode;
	proto_item *flag_tree;
	header_field_info *rdonly_hf, *accmode_hf;

	static int * const flag_bits[] = {
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

	flag_tree = proto_tree_add_bitmask(tree, tvb, offset, hf_glusterfs_flags, ett_glusterfs_flags, flag_bits, ENC_BIG_ENDIAN);

	/* rdonly is true only when no flags are set */
	rdonly = (tvb_get_ntohl(tvb, offset) == 0);
	proto_tree_add_item(flag_tree, hf_glusterfs_flags_rdonly, tvb, offset, 4, ENC_BIG_ENDIAN);
	if (rdonly) {
		rdonly_hf = proto_registrar_get_nth(hf_glusterfs_flags_rdonly);
		proto_item_append_text(flag_tree, ", %s", rdonly_hf->name);
	}

	/* hf_glusterfs_flags_accmode is true if bits 0 and 1 are set */
	accmode_hf = proto_registrar_get_nth(hf_glusterfs_flags_accmode);
	accmode = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint_format_value(flag_tree, hf_glusterfs_flags_accmode, tvb, offset, 4, accmode,
			"%s", val_to_str_const((accmode & (uint32_t)(accmode_hf->bitmask)), glusterfs_accmode_vals, "Unknown"));
	if ((accmode & accmode_hf->bitmask) == accmode_hf->bitmask)
		proto_item_append_text(flag_tree, ", %s", proto_registrar_get_nth(hf_glusterfs_flags_accmode)->name);

	offset += 4;
	return offset;
}

static int
glusterfs_rpc_dissect_statfs(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	static int * const flag_bits[] = {
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

	proto_tree_add_bitmask(tree, tvb, offset,
			hf_glusterfs_mnt_flags, ett_glusterfs_mnt_flags,
			flag_bits, ENC_BIG_ENDIAN);
	offset += 8;

	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_namemax, offset);

	return offset;
}

/* function for dissecting and adding a gluster dict_t to the tree */
int
gluster_rpc_dissect_dict(proto_tree *tree, tvbuff_t *tvb, int hfindex, int offset)
{
	char *key, *value;
	const char *name;
	int roundup, value_len, key_len;
	uint32_t i, items, len;
	int start_offset, start_offset2;

	proto_item *subtree_item, *ti;
	proto_tree *subtree;

	proto_item *dict_item = NULL;

	/* create a subtree for all the items in the dict */
	if (hfindex >= 0) {
		header_field_info *hfinfo = proto_registrar_get_nth(hfindex);
		name = hfinfo->name;
	} else
		name = "<NAMELESS DICT STRUCTURE>";

	start_offset = offset;
	subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_gluster_dict, &subtree_item, name);

	len = tvb_get_ntohl(tvb, offset);
	roundup = rpc_roundup(len) - len;
	ti = proto_tree_add_item_ret_uint(subtree, hf_gluster_dict_size, tvb, offset, 4, ENC_BIG_ENDIAN, &len);
	proto_item_append_text(ti, " (%d bytes inc. RPC-roundup)", rpc_roundup(len));
	proto_item_set_generated(ti);
	offset += 4;

	if (len == 0)
		items = 0;
	else
		items = tvb_get_ntohl(tvb, offset);

	proto_item_append_text(subtree_item, ", contains %d item%s", items, items == 1 ? "" : "s");

	if (len == 0)
		return offset;

	proto_tree_add_uint(subtree, hf_gluster_num_dict_items, tvb, offset, 4, items);
	offset += 4;

	for (i = 0; i < items; i++) {
		/* key_len is the length of the key without the terminating '\0' */
		/* key_len = tvb_get_ntohl(tvb, offset) + 1; // will be read later */
		offset += 4;
		value_len = tvb_get_ntohl(tvb, offset);
		offset += 4;

		/* read the key, '\0' terminated */
		key = tvb_get_stringz_enc(wmem_packet_scope(), tvb, offset, &key_len, ENC_ASCII);
		start_offset2 = offset;
		offset += key_len;

		/* read the value, possibly '\0' terminated */

		/* keys named "gfid-req" contain a GFID in hex */
		if (value_len == 16 && (
					!strncmp("gfid-req", key, 8) ||
					!strncmp("transaction_id", key, 14) ||
					!strncmp("originator_uuid", key, 15))) {
			char *gfid_s;
			e_guid_t gfid;

			tvb_get_ntohguid(tvb, offset, &gfid);

			gfid_s = guid_to_str(wmem_packet_scope(), &gfid);
			dict_item = proto_tree_add_guid_format(subtree, hf_glusterfs_gfid,
					tvb, offset, 16, &gfid,
					"%s: %s", key, gfid_s);
			/* this is a changelog in binary format */
		} else if (value_len == 12 && !strncmp("trusted.afr.", key, 12)) {
			dict_item = proto_tree_add_bytes_format(subtree, hf_gluster_trusted_afr_key, tvb, offset, 12,
					NULL, "%s: 0x%.8x%.8x%.8x", key,
					tvb_get_letohl(tvb, offset + 0),
					tvb_get_letohl(tvb, offset + 4),
					tvb_get_letohl(tvb, offset + 8));
		} else {
			value = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, value_len, ENC_ASCII);
			dict_item = proto_tree_add_string_format(subtree, hf_gluster_dict_value, tvb, offset, value_len, value, "%s: %s",
					key, value);
		}

		offset += value_len;
		proto_item_set_len (dict_item, offset - start_offset2);
	}

	if (roundup) {
		ti = proto_tree_add_item(subtree, hf_gluster_rpc_roundup_bytes, tvb, offset, -1, ENC_NA);
		proto_item_set_generated(ti);
		offset += roundup;
	}

	proto_item_set_len (subtree_item, offset - start_offset);

	return offset;
}

/*
 * from rpc/xdr/src/glusterfs3-xdr.c:xdr_gf_iatt()
 */
static int
glusterfs_rpc_dissect_gfx_iatt(proto_tree *tree, tvbuff_t *tvb, int hfindex,
								int offset)
{
	proto_item *iatt_item;
	proto_tree *iatt_tree;
	int start_offset = offset;

	iatt_item = proto_tree_add_item(tree, hfindex, tvb, offset, -1,
								ENC_NA);
	iatt_tree = proto_item_add_subtree(iatt_item, ett_glusterfs_iatt);

	offset = glusterfs_rpc_dissect_gfid(iatt_tree, tvb, hf_glusterfs_gfid,
								offset);
	offset = dissect_rpc_uint64(tvb, iatt_tree, hf_glusterfs_iax_flags,
								offset);
	offset = dissect_rpc_uint64(tvb, iatt_tree, hf_glusterfs_ia_ino,
								offset);
	offset = dissect_rpc_uint64(tvb, iatt_tree, hf_glusterfs_ia_dev,
								offset);
	offset = dissect_rpc_uint64(tvb, iatt_tree, hf_glusterfs_ia_rdev,
								offset);
	offset = dissect_rpc_uint64(tvb, iatt_tree, hf_glusterfs_ia_size,
								offset);
	offset = dissect_rpc_uint64(tvb, iatt_tree, hf_glusterfs_ia_blocks,
								offset);
	offset = dissect_rpc_uint64(tvb, iatt_tree, hf_glusterfs_iax_attributes,
								offset);
	offset = dissect_rpc_uint64(tvb, iatt_tree, hf_glusterfs_iax_attributes_mask,
								offset);
	offset = dissect_rpc_uint64(tvb, iatt_tree, hf_glusterfs_iax_atime,
								offset);
	offset = dissect_rpc_uint64(tvb, iatt_tree, hf_glusterfs_iax_mtime,
								offset);
	offset = dissect_rpc_uint64(tvb, iatt_tree, hf_glusterfs_iax_ctime,
								offset);
	offset = dissect_rpc_uint64(tvb, iatt_tree, hf_glusterfs_iax_btime,
								offset);
	offset = dissect_rpc_uint32(tvb, iatt_tree, hf_glusterfs_iax_atime_nsec,
								offset);
	offset = dissect_rpc_uint32(tvb, iatt_tree, hf_glusterfs_iax_mtime_nsec,
								offset);
	offset = dissect_rpc_uint32(tvb, iatt_tree, hf_glusterfs_iax_ctime_nsec,
								offset);
	offset = dissect_rpc_uint32(tvb, iatt_tree, hf_glusterfs_iax_btime_nsec,
								offset);
	offset = dissect_rpc_uint32(tvb, iatt_tree, hf_glusterfs_ia_nlink,
								offset);
	offset = dissect_rpc_uint32(tvb, iatt_tree, hf_glusterfs_ia_uid,
								offset);
	offset = dissect_rpc_uint32(tvb, iatt_tree, hf_glusterfs_ia_gid,
								offset);
	offset = dissect_rpc_uint32(tvb, iatt_tree, hf_glusterfs_ia_blksize,
								offset);
	offset = glusterfs_rpc_dissect_mode(iatt_tree, tvb,
						hf_glusterfs_ia_mode, offset);

	proto_item_set_len (iatt_item, offset - start_offset);

	return offset;
}

/* function for dissecting and adding a gluster4_0 dict_t to the tree */
static int
gluster_rpc4_0_dissect_dict(proto_tree *tree, tvbuff_t *tvb, int hfindex, int offset)
{
	char *key, *value;
	const char *name;
	uint32_t i, items, len, val_type, val_len, key_len;
	int start_offset, start_offset2;
	char *gfid_s;
	e_guid_t gfid;

	proto_item *subtree_item;
	proto_tree *subtree;

	proto_item *dict_item = NULL;

	/* create a subtree for all the items in the dict */
	if (hfindex >= 0) {
		header_field_info *hfinfo = proto_registrar_get_nth(hfindex);
		name = hfinfo->name;
	} else
		name = "<NAMELESS DICT STRUCTURE>";

	start_offset = offset;
	subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_gluster_dict, &subtree_item, name);

	len = tvb_get_ntohl(tvb, offset);
	offset = dissect_rpc_uint32 (tvb, subtree, hf_gluster_dict_xdr_size, offset);

	offset += 4;

	if (len == 0)
		items = 0;
	else
		items = tvb_get_ntohl(tvb, offset);
	offset = dissect_rpc_uint32 (tvb, subtree, hf_gluster_num_dict_items, offset);

	if (len == 0)
		return offset;

	for (i = 0; i < items; i++) {
		val_len = 0;
		key_len = tvb_get_ntohl(tvb, offset);
		key_len = rpc_roundup(key_len);
		offset += 4;

		/* read the key, '\0' terminated */
		key = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, key_len, ENC_ASCII);
		start_offset2 = offset;
		offset += key_len;

		val_type = tvb_get_ntohl(tvb, offset);
		offset += 4;

		if (val_type == 2) {
			val_len = 8;
			dict_item = proto_tree_add_string_format(subtree, hf_gluster_dict_value, tvb, offset, val_len,
								NULL, "%s: %"PRId64, key,
								tvb_get_gint64(tvb, offset, ENC_BIG_ENDIAN));
		} else if (val_type == 3) {
			val_len = 8;
			dict_item = proto_tree_add_string_format(subtree, hf_gluster_dict_value, tvb, offset, val_len,
								NULL, "%s: %"PRIu64, key,
								tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN));
		} else if (val_type == 4) {
			val_len = 8;
			dict_item = proto_tree_add_string_format(subtree, hf_gluster_dict_value, tvb, offset, val_len,
								NULL, "%s: %f", key,
								tvb_get_ieee_double(tvb, offset, ENC_BIG_ENDIAN));
		} else if (val_type == 5) {
			val_len = tvb_get_ntohl(tvb, offset);
			val_len = rpc_roundup(val_len);
			offset += 4;
			value = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, val_len, ENC_ASCII);
			dict_item = proto_tree_add_string_format(subtree, hf_gluster_dict_value, tvb, offset, val_len, value, "%s: %s",
								key, value);
		} else if (val_type == 8) {
			offset = glusterfs_rpc_dissect_gfx_iatt(tree, tvb,
					hf_glusterfs_preparent_iatt, offset);
		} else if (val_type == 7) {
			val_len = 16;
			tvb_get_ntohguid(tvb, offset, &gfid);
			gfid_s = guid_to_str(wmem_packet_scope(), &gfid);
			dict_item = proto_tree_add_guid_format(subtree, hf_glusterfs_gfid,
								tvb, offset, val_len, &gfid,
								"%s: %s", key, gfid_s);
		} else if (val_type == 6) {
			val_len = tvb_get_ntohl(tvb, offset);
			offset += 4;

			/* read the value, possibly '\0' terminated */

			/* keys named "gfid-req" contain a GFID in hex */
			if (val_len == 16 && (
						!strncmp("gfid-req", key, 8) ||
						!strncmp("transaction_id", key, 14) ||
						!strncmp("originator_uuid", key, 15))) {
				tvb_get_ntohguid(tvb, offset, &gfid);

				gfid_s = guid_to_str(wmem_packet_scope(), &gfid);
				dict_item = proto_tree_add_guid_format(subtree, hf_glusterfs_gfid,
						tvb, offset, 16, &gfid,
						"%s: %s", key, gfid_s);
				/* this is a changelog in binary format */
			} else if (val_len == 12 && !strncmp("trusted.afr.", key, 12)) {
				dict_item = proto_tree_add_bytes_format(subtree, hf_gluster_trusted_afr_key, tvb, offset, 12,
						NULL, "%s: 0x%.8x%.8x%.8x", key,
						tvb_get_letohl(tvb, offset + 0),
						tvb_get_letohl(tvb, offset + 4),
						tvb_get_letohl(tvb, offset + 8));
			} else {
				value = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, val_len, ENC_ASCII);
				dict_item = proto_tree_add_string_format(subtree, hf_gluster_dict_value, tvb, offset, val_len, value, "%s: %s",
						key, value);
			}
		}

		offset += val_len;
		proto_item_set_len (dict_item, offset - start_offset2);
	}

	proto_item_set_len (subtree_item, offset - start_offset);

	return offset;
}

/*
  GlusterFS protocol error codes, from the GlusterFS source.

  The GlusterFS server maps system errno values to these codes,
  which is a Good Thing, because not only are some errno values
  different on different platforms, some errno values on some
  Linux platforms differ from the equivalent values on most
  Linux platforms, meaning that if a server sends one of its
  errno values to a client with a different operating system -
  or if a Linux server sends one of its errno values to a Linux
  client with different errno values - the errno might not be
  interpreted correctly.

  Copyright notice from the GlusterFS code's compat-errno.h,
  from which these codes, CF_ERROR_CODE_ names, and error
  message strings are taken:

  Copyright (c) 2008-2012 Red Hat, Inc. <http://www.redhat.com>
  This file is part of GlusterFS.

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.
*/

static const value_string glusterfs_error_codes[] = {
	{0, "Success"},				/* GF_ERROR_CODE_SUCCESS  */
	{1, "Operation not permitted"},		/* GF_ERROR_CODE_PERM */
	{2, "No such file or directory"},	/* GF_ERROR_CODE_NOENT */
	{3, "No such process"},			/* GF_ERROR_CODE_SRCH */
	{4, "Interrupted system call"},		/* GF_ERROR_CODE_INTR */
	{5, "I/O error"},			/* GF_ERROR_CODE_IO */
	{6, "No such device or address"},	/* GF_ERROR_CODE_NXIO */
	{7, "Argument list too long"},		/* GF_ERROR_CODE_2BIG */
	{8, "Exec format error"},		/* GF_ERROR_CODE_NOEXEC */
	{9, "Bad file number"},			/* GF_ERROR_CODE_BADF */
	{10, "No child processes"},		/* GF_ERROR_CODE_CHILD */
	{11, "Try again"},			/* GF_ERROR_CODE_AGAIN */
	{12, "Out of memory"},			/* GF_ERROR_CODE_NOMEM */
	{13, "Permission denied"},		/* GF_ERROR_CODE_ACCES */
	{14, "Bad address"},			/* GF_ERROR_CODE_FAULT */
	{15, "Block device required"},		/* GF_ERROR_CODE_NOTBLK */
	{16, "Device or resource busy"},	/* GF_ERROR_CODE_BUSY */
	{17, "File exists"},			/* GF_ERROR_CODE_EXIST */
	{18, "Cross-device link"},		/* GF_ERROR_CODE_XDEV */
	{19, "No such device"},			/* GF_ERROR_CODE_NODEV */
	{20, "Not a directory"},		/* GF_ERROR_CODE_NOTDIR */
	{21, "Is a directory"},			/* GF_ERROR_CODE_ISDIR */
	{22, "Invalid argument"},		/* GF_ERROR_CODE_INVAL */
	{23, "File table overflow"},		/* GF_ERROR_CODE_NFILE */
	{24, "Too many open files"},		/* GF_ERROR_CODE_MFILE */
	{25, "Not a typewriter"},		/* GF_ERROR_CODE_NOTTY */
	{26, "Text file busy"},			/* GF_ERROR_CODE_TXTBSY */
	{27, "File too large"},			/* GF_ERROR_CODE_FBIG */
	{28, "No space left on device"},	/* GF_ERROR_CODE_NOSPC */
	{29, "Illegal seek"},			/* GF_ERROR_CODE_SPIPE */
	{30, "Read-only file system"},		/* GF_ERROR_CODE_ROFS */
	{31, "Too many links"},			/* GF_ERROR_CODE_MLINK */
	{32, "Broken pipe"},			/* GF_ERROR_CODE_PIPE */
	{33, "Math argument out of domain of func"},	/* GF_ERROR_CODE_DOM */
	{34, "Math result not representable"},	/* GF_ERROR_CODE_RANGE */
	{35, "Resource deadlock would occur"},	/* GF_ERROR_CODE_DEADLK */
	{36, "File name too long"},		/* GF_ERROR_CODE_NAMETOOLONG */
	{37, "No record locks available"},	/* GF_ERROR_CODE_NOLCK */
	{38, "Function not implemented"},	/* GF_ERROR_CODE_NOSYS */
	{39, "Directory not empty"},		/* GF_ERROR_CODE_NOTEMPTY */
	{40, "Too many symbolic links encountered"},	/* GF_ERROR_CODE_LOOP */

	{42, "No message of desired type"},	/* GF_ERROR_CODE_NOMSG */
	{43, "Identifier removed"},		/* GF_ERROR_CODE_IDRM */
	{44, "Channel number out of range"},	/* GF_ERROR_CODE_CHRNG */
	{45, "Level 2 not synchronized"},	/* GF_ERROR_CODE_L2NSYNC */
	{46, "Level 3 halted"},			/* GF_ERROR_CODE_L3HLT */
	{47, "Level 3 reset"},			/* GF_ERROR_CODE_L3RST */
	{48, "Link number out of range"},	/* GF_ERROR_CODE_LNRNG */
	{49, "Protocol driver not attached"},	/* GF_ERROR_CODE_UNATCH */
	{50, "No CSI structure available"},	/* GF_ERROR_CODE_NOCSI */
	{51, "Level 2 halted"},			/* GF_ERROR_CODE_L2HLT */
	{52, "Invalid exchange"},		/* GF_ERROR_CODE_BADE */
	{53, "Invalid request descriptor"},	/* GF_ERROR_CODE_BADR */
	{54, "Exchange full"},			/* GF_ERROR_CODE_XFULL */
	{55, "No anode"},			/* GF_ERROR_CODE_NOANO */
	{56, "Invalid request code"},		/* GF_ERROR_CODE_BADRQC */
	{57, "Invalid slot"},			/* GF_ERROR_CODE_BADSLT */
	{59, "Bad font file format"},		/* GF_ERROR_CODE_BFONT */
	{60, "Device not a stream"},		/* GF_ERROR_CODE_NOSTR */
	{61, "No data available"},		/* GF_ERROR_CODE_NODATA */
	{62, "Timer expired"},			/* GF_ERROR_CODE_TIME */
	{63, "Out of streams resources"},	/* GF_ERROR_CODE_NOSR */
	{64, "Machine is not on the network"},	/* GF_ERROR_CODE_NONET */
	{65, "Package not installed"},		/* GF_ERROR_CODE_NOPKG */
	{66, "Object is remote"},		/* GF_ERROR_CODE_REMOTE */
	{67, "Link has been severed"},		/* GF_ERROR_CODE_NOLINK */
	{68, "Advertise error"},		/* GF_ERROR_CODE_ADV */
	{69, "Srmount error"},			/* GF_ERROR_CODE_SRMNT */
	{70, "Communication error on send"},	/* GF_ERROR_CODE_COMM */
	{71, "Protocol error"},			/* GF_ERROR_CODE_PROTO */
	{72, "Multihop attempted"},		/* GF_ERROR_CODE_MULTIHOP */
	{73, "RFS specific error"},		/* GF_ERROR_CODE_DOTDOT */
	{74, "Not a data message"},		/* GF_ERROR_CODE_BADMSG */
	{75, "Value too large for defined data type"},	/* GF_ERROR_CODE_OVERFLOW */
	{76, "Name not unique on network"},	/* GF_ERROR_CODE_NOTUNIQ */
	{77, "File descriptor in bad state"},	/* GF_ERROR_CODE_BADFD */
	{78, "Remote address changed"},	/* GF_ERROR_CODE_REMCHG */
	{79, "Can not access a needed shared library"},	/* GF_ERROR_CODE_LIBACC */
	{80, "Accessing a corrupted shared library"},	/* GF_ERROR_CODE_LIBBAD */
	{81, ".lib section in a.out corrupted"},	/* GF_ERROR_CODE_LIBSCN */
	{82, "Attempting to link in too many shared libraries"},	/* GF_ERROR_CODE_LIBMAX */
	{83, "Cannot exec a shared library directly"},	/* GF_ERROR_CODE_LIBEXEC */
	{84, "Illegal byte sequence"},		/* GF_ERROR_CODE_ILSEQ */
	{85, "Interrupted system call should be restarted"},	/* GF_ERROR_CODE_RESTART */
	{86, "Streams pipe error"},		/* GF_ERROR_CODE_STRPIPE */
	{87, "Too many users"},			/* GF_ERROR_CODE_USERS */
	{88, "Socket operation on non-socket"},	/* GF_ERROR_CODE_NOTSOCK */
	{89, "Destination address required"},	/* GF_ERROR_CODE_DESTADDRREQ */
	{90, "Message too long"},		/* GF_ERROR_CODE_MSGSIZE */
	{91, "Protocol wrong type for socket"},	/* GF_ERROR_CODE_PROTOTYPE */
	{92, "Protocol not available"},		/* GF_ERROR_CODE_NOPROTOOPT */
	{93, "Protocol not supported"},		/* GF_ERROR_CODE_PROTONOSUPPORT */
	{94, "Socket type not supported"},	/* GF_ERROR_CODE_SOCKTNOSUPPORT */
	{95, "Operation not supported on transport endpoint"}, /* GF_ERROR_CODE_OPNOTSUPP */
	{96, "Protocol family not supported"},	/* GF_ERROR_CODE_PFNOSUPPORT */
	{97, "Address family not supported by protocol"},	/* GF_ERROR_CODE_AFNOSUPPORT */
	{98, "Address already in use"},		/* GF_ERROR_CODE_ADDRINUSE */
	{99, "Cannot assign requested address"},	/* GF_ERROR_CODE_ADDRNOTAVAIL */
	{100, "Network is down"},		/* GF_ERROR_CODE_NETDOWN */
	{101, "Network is unreachable"},	/* GF_ERROR_CODE_NETUNREACH */
	{102, "Network dropped connection because of reset"},	/* GF_ERROR_CODE_NETRESET */
	{103, "Software caused connection abort"},	/* GF_ERROR_CODE_CONNABORTED */
	{104, "Connection reset by peer"},	/* GF_ERROR_CODE_CONNRESET */
	{105, "No buffer space available"},	/* GF_ERROR_CODE_NOBUFS */
	{106, "Transport endpoint is already connected"},	/* GF_ERROR_CODE_ISCONN */
	{107, "Transport endpoint is not connected"},	/* GF_ERROR_CODE_NOTCONN */
	{108, "Cannot send after transport endpoint shutdown"},	/* GF_ERROR_CODE_SHUTDOWN */
	{109, "Too many references: cannot splice"},	/* GF_ERROR_CODE_TOOMANYREFS */
	{110, "Connection timed out"},		/* GF_ERROR_CODE_TIMEDOUT */
	{111, "Connection refused"},		/* GF_ERROR_CODE_CONNREFUSED */
	{112, "Host is down"},			/* GF_ERROR_CODE_HOSTDOWN */
	{113, "No route to host"},		/* GF_ERROR_CODE_HOSTUNREACH */
	{114, "Operation already in progress"},	/* GF_ERROR_CODE_ALREADY */
	{115, "Operation now in progress"},	/* GF_ERROR_CODE_INPROGRESS */
	{116, "Stale NFS file handle"},		/* GF_ERROR_CODE_STALE */
	{117, "Structure needs cleaning"},	/* GF_ERROR_CODE_UCLEAN */
	{118, "Not a XENIX named type file"},	/* GF_ERROR_CODE_NOTNAM */
	{119, "No XENIX semaphores available"},	/* GF_ERROR_CODE_NAVAIL */
	{120, "Is a named type file"},		/* GF_ERROR_CODE_ISNAM */
	{121, "Remote I/O error"},		/* GF_ERROR_CODE_REMOTEIO */
	{122, "Quota exceeded"},		/* GF_ERROR_CODE_DQUOT */
	{123, "No medium found"},		/* GF_ERROR_CODE_NOMEDIUM */
	{124, "Wrong medium type"},		/* GF_ERROR_CODE_MEDIUMTYPE */
	{125, "Operation Canceled"},		/* GF_ERROR_CODE_CANCELED */
	{126, "Required key not available"},	/* GF_ERROR_CODE_NOKEY */
	{127, "Key has expired"},		/* GF_ERROR_CODE_KEYEXPIRED */
	{128, "Key has been revoked"},		/* GF_ERROR_CODE_KEYREVOKED */
	{129, "Key was rejected by service"},	/* GF_ERROR_CODE_KEYREJECTED */

	/* for robust mutexes */
	{130, "Owner died"},			/* GF_ERROR_CODE_OWNERDEAD */
	{131, "State not recoverable"},		/* GF_ERROR_CODE_NOTRECOVERABLE */

	/*
	 * "Should never be seen by user programs"
	 * These are internal system call returns (Linux?) used to
	 * indicate various internal conditions such as "restart
	 * this system call" indications.
	 */
	{512, "Restart system call"},		/* GF_ERROR_CODE_RESTARTSYS */
	{513, "Restart system call (no intr)"},	/* GF_ERROR_CODE_RESTARTNOINTR */
	{514, "Restart if no signal handler"},	/* GF_ERROR_CODE_RESTARTNOHAND */
	{515, "No ioctl command"},		/* GF_ERROR_CODE_NOIOCTLCMD */
	{516, "Restart system call by calling sys_restart_syscall"},	/* GF_ERROR_CODE_RESTART_RESTARTBLOCK */

	/* Defined for the NFSv3 protocol */
	{521, "Illegal NFS file handle"},	/* GF_ERROR_CODE_BADHANDLE */
	{522, "Update synchronization mismatch"},	/* GF_ERROR_CODE_NOTSYNC */
	{523, "Cookie is stale"},		/* GF_ERROR_CODE_BADCOOKIE */
	{524, "Operation is not supported"},	/* GF_ERROR_CODE_NOTSUPP */
	{525, "Buffer or request is too small"},	/* GF_ERROR_CODE_TOOSMALL */
	{526, "An untranslatable error occurred"},	/* GF_ERROR_CODE_SERVERFAULT */
	{527, "Type not supported by server"},	/* GF_ERROR_CODE_BADTYPE */
	{528, "Request initiated, but will not complete before timeout"},	/* GF_ERROR_CODE_JUKEBOX */
	{529, "iocb queued, will get completion event"},	/* GF_ERROR_CODE_IOCBQUEUED */
	{530, "iocb queued, will trigger a retry"},	/* GF_ERROR_CODE_IOCBRETRY */

	/* Darwin */
	{701, "No such policy registered"},	/* GF_ERROR_CODE_NOPOLICY */
	{702, "Malformed Mach-O file"},		/* GF_ERROR_CODE_BADMACHO */
	{703, "Device power is off"},		/* GF_ERROR_CODE_PWROFF */
	{704, "Device error" /* e.g., paper out */},	/* GF_ERROR_CODE_DEVERR */
	{705, "Bad CPU type in executable"},	/* GF_ERROR_CODE_BADARCH */
	{706, "Bad executable"},		/* GF_ERROR_CODE_BADEXEC */
	{707, "Shared library version mismatch"},	/* GF_ERROR_CODE_SHLIBVERS */

	/* Solaris */
	{801, "Facility is not active"},	/* GF_ERROR_CODE_NOTACTIVE */
	{802, "Locked lock was unmapped"},	/* GF_ERROR_CODE_LOCKUNMAPPED */

	/* BSD system */
	{901, "Too many processes"},	/* GF_ERROR_CODE_PROCLIM */
	{902, "RPC struct is bad"},	/* GF_ERROR_CODE_BADRPC */
	{903, "RPC version wrong"},	/* GF_ERROR_CODE_RPCMISMATCH */
	{904, "RPC prog. not avail"},	/* GF_ERROR_CODE_PROGUNAVAIL */
	{905, "Program version wrong"},	/* GF_ERROR_CODE_PROGMISMATCH */
	{905, "Bad procedure for program"},	/* GF_ERROR_CODE_PROCUNAVAIL */
	{906, "Inappropriate file type or format"},	/* GF_ERROR_CODE_FTYPE */
	{907, "Authentication error"},	/* GF_ERROR_CODE_AUTH */
	{908, "Need authenticator"},	/* GF_ERROR_CODE_NEEDAUTH */
	{909, "Programming error"},	/* GF_ERROR_CODE_DOOFUS */
	{1024, "Unknown"},		/* GF_ERROR_CODE_UNKNOWN */

	{0, NULL}
};
static value_string_ext glusterfs_error_codes_ext = VALUE_STRING_EXT_INIT(glusterfs_error_codes);

int
gluster_dissect_common_reply(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	proto_item *errno_item;
	unsigned op_errno;

	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_ret, offset);

	op_errno = tvb_get_ntohl(tvb, offset);
	errno_item = proto_tree_add_int(tree, hf_gluster_op_errno, tvb,
			offset, 4, op_errno);
	proto_item_append_text(errno_item, " (%s)", val_to_str_ext_const(op_errno, &glusterfs_error_codes_ext, "Unknown"));
	offset += 4;

	return offset;
}

static int
gluster_local_dissect_common_reply(tvbuff_t *tvb,
				packet_info *pinfo, proto_tree *tree, void* data)
{
	return gluster_dissect_common_reply(tvb, 0, pinfo, tree, data);
}

static int
_glusterfs_gfs3_common_readdir_reply(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	proto_item *errno_item;
	unsigned op_errno;

	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_entries, offset);

	op_errno = tvb_get_ntohl(tvb, offset);
	errno_item = proto_tree_add_int(tree, hf_gluster_op_errno, tvb,
			offset, 4, op_errno);
	if (op_errno == 0)
		proto_item_append_text(errno_item, " (More replies follow)");
	else if (op_errno == 2 /* GF_ERROR_CODE_NOENT */)
		proto_item_append_text(errno_item, " (Last reply)");
	offset += 4;

	return offset;
}

static int
glusterfs_gfs3_op_unlink_reply(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb,
					hf_glusterfs_preparent_iatt, offset);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb,
					hf_glusterfs_postparent_iatt, offset);

	return offset;
}

static int
glusterfs_gfs3_op_unlink_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_pargfid, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_path, offset, NULL);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_bname, offset, NULL);
	return offset;
}

static int
glusterfs_gfs3_op_statfs_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = glusterfs_rpc_dissect_statfs(tree, tvb, offset);
	return offset;
}

static int
glusterfs_gfs3_op_statfs_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_path, offset, NULL);

	return offset;
}

static int
glusterfs_gfs3_op_flush_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	return offset;
}

static int
glusterfs_gfs3_op_setxattr_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_path, offset, NULL);

	return offset;
}

static int
glusterfs_gfs3_op_opendir_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	return offset;
}

static int
glusterfs_gfs3_op_opendir_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_path, offset, NULL);

	return offset;
}

/* rpc/xdr/src/glusterfs3-xdr.c:xdr_gfs3_create_rsp */
static int
glusterfs_gfs3_op_create_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
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
glusterfs_gfs3_op_create_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_pargfid, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = glusterfs_rpc_dissect_mode(tree, tvb, hf_glusterfs_mode, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_path, offset, NULL);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_bname, offset, NULL);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_op_lookup_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data)
{
	int offset = 0;
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb, hf_glusterfs_iatt,
								offset);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb,
					hf_glusterfs_postparent_iatt, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_op_lookup_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_pargfid, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_path, offset, NULL);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_bname, offset, NULL);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_op_inodelk_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	proto_item *flock_item;
	proto_tree *flock_tree;
	int start_offset;
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_cmd, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_type, offset);

	start_offset = offset;
	flock_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_glusterfs_flock, &flock_item, "Flock");
	offset = glusterfs_rpc_dissect_gf_flock(flock_tree, tvb, offset);
	proto_item_set_len (flock_item, offset - start_offset);

	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_path, offset, NULL);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_volume, offset, NULL);
	return offset;
}

static int
_glusterfs_gfs_op_readdir_entry(tvbuff_t *tvb, int offset, proto_tree *tree,
				bool iatt, bool proto_4_0, bool dict)
{
	proto_item *entry_item;
	proto_tree *entry_tree;
	const char* path = NULL;
	int start_offset = offset;

	entry_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_glusterfs_entry, &entry_item, "Entry");

	offset = dissect_rpc_uint64(tvb, entry_tree, hf_glusterfs_entry_ino, offset);
	offset = dissect_rpc_uint64(tvb, entry_tree, hf_glusterfs_entry_off, offset);
	offset = dissect_rpc_uint32(tvb, entry_tree, hf_glusterfs_entry_len, offset);
	offset = dissect_rpc_uint32(tvb, entry_tree, hf_glusterfs_entry_type, offset);
	offset = dissect_rpc_string(tvb, entry_tree, hf_glusterfs_entry_path, offset, &path);

	proto_item_append_text(entry_item, " Path: %s", path);

	if (iatt) {
		if (proto_4_0)
			offset = glusterfs_rpc_dissect_gfx_iatt(entry_tree, tvb,
								hf_glusterfs_iattx, offset);
		else
			offset = glusterfs_rpc_dissect_gf_iatt(entry_tree, tvb,
								hf_glusterfs_iatt, offset);
	}
	if (dict) {
		if (proto_4_0)
			offset = gluster_rpc4_0_dissect_dict(entry_tree, tvb, hf_glusterfs_dict, offset);
		else
			offset = gluster_rpc_dissect_dict(entry_tree, tvb, hf_glusterfs_dict, offset);
	}

	proto_item_set_len (entry_item, offset - start_offset);

	return offset;
}

static int
glusterfs_gfs3_op_readdirp_entry(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	return _glusterfs_gfs_op_readdir_entry(tvb, offset, tree, true, false, false);
}

static int
glusterfs_gfs3_3_op_readdir_entry(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	return _glusterfs_gfs_op_readdir_entry(tvb, offset, tree, false, false, false);
}

static int
glusterfs_gfs3_3_op_readdirp_entry(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	return _glusterfs_gfs_op_readdir_entry(tvb, offset, tree, true, false, true);
}

static int
glusterfs_gfs4_0_op_readdir_entry(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	return _glusterfs_gfs_op_readdir_entry(tvb, offset, tree, false, true, false);
}

static int
glusterfs_gfs4_0_op_readdirp_entry(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	return _glusterfs_gfs_op_readdir_entry(tvb, offset, tree, true, true, true);
}

/* details in xlators/storage/posix/src/posix.c:posix_fill_readdir() */
static int
glusterfs_gfs3_op_readdirp_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data _U_)
{
	int offset = 0;
	offset = _glusterfs_gfs3_common_readdir_reply(tvb, tree, offset);
	offset = dissect_rpc_list(tvb, pinfo, tree, offset,
				  glusterfs_gfs3_op_readdirp_entry, NULL);

	return offset;
}

static int
glusterfs_gfs3_op_readdirp_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_size, offset);

	return offset;
}

static int
glusterfs_gfs3_op_setattr_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb,
					hf_glusterfs_preop_iatt, offset);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb,
					hf_glusterfs_postop_iatt, offset);

	return offset;
}

static int
glusterfs_rpc_dissect_setattr(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	static int * const flag_bits[] = {
		&hf_glusterfs_setattr_set_mode,
		&hf_glusterfs_setattr_set_uid,
		&hf_glusterfs_setattr_set_gid,
		&hf_glusterfs_setattr_set_size,
		&hf_glusterfs_setattr_set_atime,
		&hf_glusterfs_setattr_set_mtime,
		&hf_glusterfs_setattr_set_reserved,
		NULL
	};

	proto_tree_add_bitmask(tree, tvb, offset, hf_glusterfs_setattr_valid,
			ett_glusterfs_setattr_valid, flag_bits, ENC_NA);
	offset += 4;

	return offset;
}

static int
glusterfs_gfs3_op_setattr_call(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid,
								offset);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb, hf_glusterfs_iatt,
								offset);
	offset = glusterfs_rpc_dissect_setattr(tree, tvb, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_path, offset, NULL);

	return offset;
}

/*GlusterFS 3_3 fops */

static int
glusterfs_gfs3_3_op_stat_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	return offset;

}

static int
glusterfs_gfs3_3_op_stat_reply(tvbuff_t *tvb, packet_info *pinfo,
							 proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb, hf_glusterfs_iatt,
								offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict,
								offset);

	return offset;
}

/* glusterfs_gfs3_3_op_mknod_reply() is also used as a ..mkdir_reply() */
static int
glusterfs_gfs3_3_op_mknod_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
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
glusterfs_gfs3_3_op_mknod_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_pargfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);
	offset = glusterfs_rpc_dissect_mode(tree, tvb, hf_glusterfs_mode, offset);
	offset = glusterfs_rpc_dissect_mode(tree, tvb, hf_glusterfs_umask, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_bname, offset, NULL);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_mkdir_call(tvbuff_t *tvb,
				packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	int offset = 0;
	const char *name = NULL;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_pargfid, offset);
	offset = glusterfs_rpc_dissect_mode(tree, tvb, hf_glusterfs_mode, offset);
	offset = glusterfs_rpc_dissect_mode(tree, tvb, hf_glusterfs_umask, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_bname, offset, &name);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	col_append_fstr(pinfo->cinfo, COL_INFO, ", Filename: %s", name);

	return offset;
}

static int
glusterfs_gfs3_3_op_readlink_reply(tvbuff_t *tvb,
					packet_info *pinfo, proto_tree *tree, void* data)
{
	int offset = 0;
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb, hf_glusterfs_iatt,
								offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_path, offset,
									NULL);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict,
								offset);
	return offset;
}

static int
glusterfs_gfs3_3_op_readlink_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_size, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

/* glusterfs_gfs3_3_op_unlink_reply() is also used for ...rmdir_reply() */
static int
glusterfs_gfs3_3_op_unlink_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb,
					hf_glusterfs_preparent_iatt, offset);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb,
					hf_glusterfs_postparent_iatt, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_unlink_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	unsigned xflags;
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_pargfid, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_bname, offset, NULL);
	xflags = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint_format(tree, hf_glusterfs_xflags, tvb, offset, 4, xflags, "Flags: 0%02o", xflags);
	offset += 4;
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_rmdir_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	unsigned xflags;
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_pargfid, offset);
	xflags = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint_format(tree, hf_glusterfs_xflags, tvb, offset, 4, xflags, "Flags: 0%02o", xflags);
	offset += 4;
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_bname, offset, NULL);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_symlink_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_pargfid, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_bname, offset, NULL);
	offset = glusterfs_rpc_dissect_mode(tree, tvb, hf_glusterfs_umask, offset);

	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_linkname, offset, NULL);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_rename_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_oldgfid, offset);
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_newgfid, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_oldbname, offset, NULL);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_newbname, offset, NULL);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_rename_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data)
{
	proto_tree *old_tree, *new_tree;
	proto_item *old_item, *new_item;
	int start_offset;
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb, hf_glusterfs_iatt,
								offset);

	start_offset = offset;
	old_tree = proto_tree_add_subtree(tree, tvb, offset, -1,
				ett_glusterfs_parent_iatt, &old_item, "Old parent");
	offset = glusterfs_rpc_dissect_gf_iatt(old_tree, tvb,
					hf_glusterfs_preparent_iatt, offset);
	offset = glusterfs_rpc_dissect_gf_iatt(old_tree, tvb,
					hf_glusterfs_postparent_iatt, offset);
	proto_item_set_len (old_item, offset - start_offset);

	start_offset = offset;
	new_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_glusterfs_parent_iatt, &new_item, "New parent");
	offset = glusterfs_rpc_dissect_gf_iatt(new_tree, tvb,
					hf_glusterfs_preparent_iatt, offset);
	offset = glusterfs_rpc_dissect_gf_iatt(new_tree, tvb,
					hf_glusterfs_postparent_iatt, offset);
	proto_item_set_len (new_item, offset - start_offset);

	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_link_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_oldgfid, offset);
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_newgfid, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_newbname, offset, NULL);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_truncate_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_open_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	return offset;
}

static int
glusterfs_gfs3_3_op_open_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_read_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb, hf_glusterfs_iatt,
								offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_size, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict,
								offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_read_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_size, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_write_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_size, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_statfs_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = glusterfs_rpc_dissect_statfs(tree, tvb, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_statfs_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_flush_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_setxattr_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_getxattr_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_namelen, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_name, offset, NULL);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}


static int
glusterfs_gfs3_3_op_getxattr_reply(tvbuff_t *tvb,
					packet_info *pinfo, proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_removexattr_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_name, offset, NULL);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_fsync_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	static int * const flag_bits[] = {
		&hf_glusterfs_fsync_flag_datasync,
		&hf_glusterfs_fsync_flag_unknown,
		NULL
	};
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);

	proto_tree_add_bitmask(tree, tvb, offset,
			hf_glusterfs_fsync_flags,
			ett_glusterfs_fsync_flags, flag_bits, ENC_NA);
	offset += 4;

	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_opendir_reply(tvbuff_t *tvb,
				packet_info *pinfo, proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_opendir_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_create_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
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
glusterfs_gfs3_3_op_create_call(tvbuff_t *tvb,
				packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	const char *name = NULL;
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_pargfid, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = glusterfs_rpc_dissect_mode(tree, tvb, hf_glusterfs_mode, offset);
	offset = glusterfs_rpc_dissect_mode(tree, tvb, hf_glusterfs_umask, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_bname, offset, &name);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	col_append_fstr(pinfo->cinfo, COL_INFO, ", Filename: %s", name);

	return offset;
}

static int
glusterfs_gfs3_3_op_ftruncate_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_fstat_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_fstat_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb, hf_glusterfs_iatt,
								offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict,
								offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_lk_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_cmd, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_type, offset);
	offset = glusterfs_rpc_dissect_gf_2_flock(tree, tvb, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_lk_reply(tvbuff_t *tvb,
				packet_info *pinfo, proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = glusterfs_rpc_dissect_gf_2_flock(tree, tvb, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_access_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_mask, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	return offset;
}

static int
glusterfs_gfs3_3_op_lookup_call(tvbuff_t *tvb,
				packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	const char *name = NULL;
	int length;
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_pargfid, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	length = tvb_get_letohl(tvb, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_bname, offset, &name);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	if(length == 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Filename: (nameless, by GFID)");
	else
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Filename: %s", name);

	return offset;
}

static int
glusterfs_gfs3_3_op_readdir_reply(tvbuff_t *tvb,
				packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = _glusterfs_gfs3_common_readdir_reply(tvb, tree, offset);
	offset = dissect_rpc_list(tvb, pinfo, tree, offset,
				  glusterfs_gfs3_3_op_readdir_entry, NULL);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_readdir_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_size, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_inodelk_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_cmd, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_type, offset);
	offset = glusterfs_rpc_dissect_gf_2_flock(tree, tvb, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_volume, offset, NULL);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_finodelk_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);

	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_cmd, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_type, offset);
	offset = glusterfs_rpc_dissect_gf_2_flock(tree, tvb, offset);

	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_volume, offset, NULL);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_entrylk_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_cmd, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_type, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_entrylk_namelen, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_name, offset, NULL);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_volume, offset, NULL);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_fentrylk_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_cmd, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_type, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_entrylk_namelen, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_name, offset, NULL);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_volume, offset, NULL);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_xattrop_reply(tvbuff_t *tvb,
				packet_info *pinfo, proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_xattrop_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_fxattrop_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_fgetxattr_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_namelen, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_name, offset, NULL);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
gluter_gfs3_3_op_fsetxattr_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_setattr_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb,
					hf_glusterfs_preop_iatt, offset);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb,
					hf_glusterfs_postop_iatt, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_setattr_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid,
								offset);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb, hf_glusterfs_iatt,
								offset);
	offset = glusterfs_rpc_dissect_setattr(tree, tvb, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_readdirp_reply(tvbuff_t *tvb,
				packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = _glusterfs_gfs3_common_readdir_reply(tvb, tree, offset);
	offset = dissect_rpc_list(tvb, pinfo, tree, offset,
				  glusterfs_gfs3_3_op_readdirp_entry, NULL);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

/* READDIRP and DISCARD both use this */
static int
glusterfs_gfs3_3_op_readdirp_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_size, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_release_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_releasedir_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_fremovexattr_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_name, offset, NULL);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_fallocate_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_size, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_zerofill_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_size64, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_seek_reply(tvbuff_t *tvb, packet_info *pinfo,
			       proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs3_3_op_seek_call(tvbuff_t *tvb, packet_info *pinfo _U_,
			      proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_whence, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

/* This function is for common replay. RELEASE , RELEASEDIR and some other function use this method */

int
glusterfs_gfs3_3_op_common_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}


/*GlusterFS 4_0 fops */

static int
glusterfs_gfs4_0_op_stat_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	return offset;

}

static int
glusterfs_gfs4_0_op_common_iatt_reply(tvbuff_t *tvb, packet_info *pinfo,
							 proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = glusterfs_rpc_dissect_gfx_iatt(tree, tvb, hf_glusterfs_iattx,
								offset);
	return offset;
}

/* glusterfs_gfs4_0_op_mknod_reply() is also used as a ..mkdir_reply() */
static int
glusterfs_gfs4_0_op_common_3iatt_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict,
								offset);
	offset = glusterfs_rpc_dissect_gfx_iatt(tree, tvb, hf_glusterfs_iattx,
								offset);
	offset = glusterfs_rpc_dissect_gfx_iatt(tree, tvb,
					hf_glusterfs_preparent_iattx, offset);
	offset = glusterfs_rpc_dissect_gfx_iatt(tree, tvb,
					hf_glusterfs_postparent_iattx, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_mknod_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_pargfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);
	offset = glusterfs_rpc_dissect_mode(tree, tvb, hf_glusterfs_mode, offset);
	offset = glusterfs_rpc_dissect_mode(tree, tvb, hf_glusterfs_umask, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_bname, offset, NULL);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_mkdir_call(tvbuff_t *tvb,
				packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	int offset = 0;
	const char *name = NULL;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_pargfid, offset);
	offset = glusterfs_rpc_dissect_mode(tree, tvb, hf_glusterfs_mode, offset);
	offset = glusterfs_rpc_dissect_mode(tree, tvb, hf_glusterfs_umask, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_bname, offset, &name);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	col_append_fstr(pinfo->cinfo, COL_INFO, ", Filename: %s", name);

	return offset;
}

static int
glusterfs_gfs4_0_op_readlink_reply(tvbuff_t *tvb,
					packet_info *pinfo, proto_tree *tree, void* data)
{
	int offset = 0;
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict,
								offset);
	offset = glusterfs_rpc_dissect_gfx_iatt(tree, tvb, hf_glusterfs_iattx,
								offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_path, offset,
									NULL);
	return offset;
}

static int
glusterfs_gfs4_0_op_readlink_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_size, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

/* glusterfs_gfs4_0_op_unlink_reply() is also used for ...rmdir_reply() */
static int
glusterfs_gfs4_0_op_common_2parent_iatt_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = glusterfs_rpc_dissect_gfx_iatt(tree, tvb,
					hf_glusterfs_preparent_iattx, offset);
	offset = glusterfs_rpc_dissect_gfx_iatt(tree, tvb,
					hf_glusterfs_postparent_iattx, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_unlink_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	unsigned xflags;
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_pargfid, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_bname, offset, NULL);
	xflags = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint_format(tree, hf_glusterfs_xflags, tvb, offset, 4, xflags, "Flags: 0%02o", xflags);
	offset += 4;
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_rmdir_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	unsigned xflags;
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_pargfid, offset);
	xflags = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint_format(tree, hf_glusterfs_xflags, tvb, offset, 4, xflags, "Flags: 0%02o", xflags);
	offset += 4;
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_bname, offset, NULL);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_symlink_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_pargfid, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_bname, offset, NULL);
	offset = glusterfs_rpc_dissect_mode(tree, tvb, hf_glusterfs_umask, offset);

	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_linkname, offset, NULL);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_rename_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_oldgfid, offset);
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_newgfid, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_oldbname, offset, NULL);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_newbname, offset, NULL);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_rename_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data)
{
	proto_tree *old_tree, *new_tree;
	proto_item *old_item, *new_item;
	int start_offset;
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = glusterfs_rpc_dissect_gfx_iatt(tree, tvb, hf_glusterfs_iattx,
								offset);

	start_offset = offset;
	old_tree = proto_tree_add_subtree(tree, tvb, offset, -1,
				ett_glusterfs_parent_iatt, &old_item, "Old parent");
	offset = glusterfs_rpc_dissect_gfx_iatt(old_tree, tvb,
					hf_glusterfs_preparent_iattx, offset);
	offset = glusterfs_rpc_dissect_gfx_iatt(old_tree, tvb,
					hf_glusterfs_postparent_iattx, offset);
	proto_item_set_len (old_item, offset - start_offset);

	start_offset = offset;
	new_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_glusterfs_parent_iatt, &new_item, "New parent");
	offset = glusterfs_rpc_dissect_gfx_iatt(new_tree, tvb,
					hf_glusterfs_preparent_iattx, offset);
	offset = glusterfs_rpc_dissect_gfx_iatt(new_tree, tvb,
					hf_glusterfs_postparent_iattx, offset);
	proto_item_set_len (new_item, offset - start_offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_link_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_oldgfid, offset);
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_newgfid, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_newbname, offset, NULL);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_truncate_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_open_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	return offset;
}

static int
glusterfs_gfs4_0_op_open_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_read_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = glusterfs_rpc_dissect_gfx_iatt(tree, tvb, hf_glusterfs_iattx,
								offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_size, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict,
								offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_read_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_size, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_write_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_size, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_statfs_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = glusterfs_rpc_dissect_statfs(tree, tvb, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_statfs_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_flush_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_setxattr_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_getxattr_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_namelen, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_name, offset, NULL);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}


static int
glusterfs_gfs4_0_op_common_dict_reply(tvbuff_t *tvb,
					packet_info *pinfo, proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = glusterfs_rpc_dissect_gfx_iatt(tree, tvb,
					hf_glusterfs_preop_iattx, offset);
	offset = glusterfs_rpc_dissect_gfx_iatt(tree, tvb,
					hf_glusterfs_postop_iattx, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_removexattr_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_name, offset, NULL);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_fsync_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	static int * const flag_bits[] = {
		&hf_glusterfs_fsync_flag_datasync,
		&hf_glusterfs_fsync_flag_unknown,
		NULL
	};
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);

	proto_tree_add_bitmask(tree, tvb, offset,
			hf_glusterfs_fsync_flags,
			ett_glusterfs_fsync_flags, flag_bits, ENC_NA);
	offset += 4;

	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_opendir_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_create_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = glusterfs_rpc_dissect_gfx_iatt(tree, tvb, hf_glusterfs_iattx,
								offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = glusterfs_rpc_dissect_gfx_iatt(tree, tvb,
					hf_glusterfs_preparent_iattx, offset);
	offset = glusterfs_rpc_dissect_gfx_iatt(tree, tvb,
					hf_glusterfs_postparent_iattx, offset);

	return offset;
}


static int
glusterfs_gfs4_0_op_create_call(tvbuff_t *tvb,
				packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	const char *name = NULL;
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_pargfid, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = glusterfs_rpc_dissect_mode(tree, tvb, hf_glusterfs_mode, offset);
	offset = glusterfs_rpc_dissect_mode(tree, tvb, hf_glusterfs_umask, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_bname, offset, &name);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	col_append_fstr(pinfo->cinfo, COL_INFO, ", Filename: %s", name);

	return offset;
}

static int
glusterfs_gfs4_0_op_ftruncate_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_fstat_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_lk_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_cmd, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_type, offset);
	offset = glusterfs_rpc_dissect_gf_2_flock(tree, tvb, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_lk_reply(tvbuff_t *tvb,
				packet_info *pinfo, proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = glusterfs_rpc_dissect_gf_2_flock(tree, tvb, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_access_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_mask, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	return offset;
}

static int
glusterfs_gfs4_0_op_lookup_call(tvbuff_t *tvb,
				packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	const char *name = NULL;
	int length;
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_pargfid, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	length = tvb_get_letohl(tvb, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_bname, offset, &name);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	if(length == 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Filename: (nameless, by GFID)");
	else
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Filename: %s", name);

	return offset;
}

static int
glusterfs_gfs4_0_op_readdir_reply(tvbuff_t *tvb,
				packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = _glusterfs_gfs3_common_readdir_reply(tvb, tree, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = dissect_rpc_list(tvb, pinfo, tree, offset,
				  glusterfs_gfs4_0_op_readdir_entry, NULL);

	return offset;
}

static int
glusterfs_gfs4_0_op_readdir_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_size, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_inodelk_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_cmd, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_type, offset);
	offset = glusterfs_rpc_dissect_gf_2_flock(tree, tvb, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_volume, offset, NULL);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_finodelk_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);

	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_cmd, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_type, offset);
	offset = glusterfs_rpc_dissect_gf_2_flock(tree, tvb, offset);

	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_volume, offset, NULL);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_entrylk_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_cmd, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_type, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_entrylk_namelen, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_name, offset, NULL);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_volume, offset, NULL);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_fentrylk_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_cmd, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_type, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_entrylk_namelen, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_name, offset, NULL);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_volume, offset, NULL);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_xattrop_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_fxattrop_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_fgetxattr_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_namelen, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_name, offset, NULL);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
gluter_gfs4_0_op_fsetxattr_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_common_2iatt_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = glusterfs_rpc_dissect_gfx_iatt(tree, tvb,
					hf_glusterfs_preop_iattx, offset);
	offset = glusterfs_rpc_dissect_gfx_iatt(tree, tvb,
					hf_glusterfs_postop_iattx, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_setattr_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid,
								offset);
	offset = glusterfs_rpc_dissect_gfx_iatt(tree, tvb, hf_glusterfs_iattx,
								offset);
	offset = glusterfs_rpc_dissect_setattr(tree, tvb, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_fsetattr_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid,
								offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = glusterfs_rpc_dissect_gfx_iatt(tree, tvb, hf_glusterfs_iattx,
								offset);
	offset = glusterfs_rpc_dissect_setattr(tree, tvb, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_readdirp_reply(tvbuff_t *tvb,
				packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = _glusterfs_gfs3_common_readdir_reply(tvb, tree, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = dissect_rpc_list(tvb, pinfo, tree, offset,
				  glusterfs_gfs4_0_op_readdirp_entry, NULL);

	return offset;
}

/* READDIRP and DISCARD both use this */
static int
glusterfs_gfs4_0_op_readdirp_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_size, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_release_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_releasedir_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_fremovexattr_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterfs_name, offset, NULL);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_fallocate_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = glusterfs_rpc_dissect_flags(tree, tvb, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_size, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_zerofill_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_size64, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_seek_reply(tvbuff_t *tvb, packet_info *pinfo,
			       proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);

	return offset;
}

static int
glusterfs_gfs4_0_op_seek_call(tvbuff_t *tvb, packet_info *pinfo _U_,
			      proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = glusterfs_rpc_dissect_gfid(tree, tvb, hf_glusterfs_gfid, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_fd, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_glusterfs_offset, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterfs_whence, offset);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}

/* This function is for common replay. RELEASE , RELEASEDIR and some other function use this method */

static int
glusterfs_gfs4_0_op_common_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data)
{
	int offset = 0;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = gluster_rpc4_0_dissect_dict(tree, tvb, hf_glusterfs_dict, offset);

	return offset;
}


/*
 * GLUSTER3_1_FOP_PROGRAM
 * - xlators/protocol/client/src/client3_1-fops.c
 * - xlators/protocol/server/src/server3_1-fops.c
 */
static const vsff glusterfs3_1_fop_proc[] = {
	{
		GFS3_OP_NULL,     "NULL",
		dissect_rpc_void, dissect_rpc_void
	},
	{ GFS3_OP_STAT,     "STAT",     dissect_rpc_unknown, dissect_rpc_unknown },
	{ GFS3_OP_READLINK, "READLINK", dissect_rpc_unknown, dissect_rpc_unknown },
	{ GFS3_OP_MKNOD,    "MKNOD",    dissect_rpc_unknown, dissect_rpc_unknown },
	{ GFS3_OP_MKDIR,    "MKDIR",    dissect_rpc_unknown, dissect_rpc_unknown },
	{
		GFS3_OP_UNLINK, "UNLINK",
		glusterfs_gfs3_op_unlink_call, glusterfs_gfs3_op_unlink_reply
	},
	{ GFS3_OP_RMDIR,    "RMDIR",    dissect_rpc_unknown, dissect_rpc_unknown },
	{ GFS3_OP_SYMLINK,  "SYMLINK",  dissect_rpc_unknown, dissect_rpc_unknown },
	{ GFS3_OP_RENAME,   "RENAME",   dissect_rpc_unknown, dissect_rpc_unknown },
	{ GFS3_OP_LINK,     "LINK",     dissect_rpc_unknown, dissect_rpc_unknown },
	{ GFS3_OP_TRUNCATE, "TRUNCATE", dissect_rpc_unknown, dissect_rpc_unknown },
	{ GFS3_OP_OPEN,     "OPEN",     dissect_rpc_unknown, dissect_rpc_unknown },
	{ GFS3_OP_READ,     "READ",     dissect_rpc_unknown, dissect_rpc_unknown },
	{ GFS3_OP_WRITE,    "WRITE",    dissect_rpc_unknown, dissect_rpc_unknown },
	{
		GFS3_OP_STATFS, "STATFS",
		glusterfs_gfs3_op_statfs_call, glusterfs_gfs3_op_statfs_reply
	},
	{
		GFS3_OP_FLUSH, "FLUSH",
		glusterfs_gfs3_op_flush_call, gluster_local_dissect_common_reply
	},
	{ GFS3_OP_FSYNC, "FSYNC", dissect_rpc_unknown, dissect_rpc_unknown },
	{
		GFS3_OP_SETXATTR, "SETXATTR",
		glusterfs_gfs3_op_setxattr_call, gluster_local_dissect_common_reply
	},
	{ GFS3_OP_GETXATTR,    "GETXATTR",    dissect_rpc_unknown, dissect_rpc_unknown },
	{ GFS3_OP_REMOVEXATTR, "REMOVEXATTR", dissect_rpc_unknown, dissect_rpc_unknown },
	{
		GFS3_OP_OPENDIR, "OPENDIR",
		glusterfs_gfs3_op_opendir_call, glusterfs_gfs3_op_opendir_reply
	},
	{ GFS3_OP_FSYNCDIR, "FSYNCDIR", dissect_rpc_unknown, dissect_rpc_unknown },
	{ GFS3_OP_ACCESS,   "ACCESS",   dissect_rpc_unknown, dissect_rpc_unknown },
	{
		GFS3_OP_CREATE, "CREATE",
		glusterfs_gfs3_op_create_call, glusterfs_gfs3_op_create_reply
	},
	{ GFS3_OP_FTRUNCATE, "FTRUNCATE", dissect_rpc_unknown, dissect_rpc_unknown },
	{ GFS3_OP_FSTAT,     "FSTAT",     dissect_rpc_unknown, dissect_rpc_unknown },
	{ GFS3_OP_LK,	"LK",	dissect_rpc_unknown, dissect_rpc_unknown },
	{
		GFS3_OP_LOOKUP, "LOOKUP",
		glusterfs_gfs3_op_lookup_call, glusterfs_gfs3_op_lookup_reply
	},
	{ GFS3_OP_READDIR, "READDIR", dissect_rpc_unknown, dissect_rpc_unknown },
	{
		GFS3_OP_INODELK, "INODELK",
		glusterfs_gfs3_op_inodelk_call, gluster_local_dissect_common_reply
	},
	{ GFS3_OP_FINODELK,  "FINODELK",  dissect_rpc_unknown, dissect_rpc_unknown },
	{ GFS3_OP_ENTRYLK,   "ENTRYLK",   dissect_rpc_unknown, dissect_rpc_unknown },
	{ GFS3_OP_FENTRYLK,  "FENTRYLK",  dissect_rpc_unknown, dissect_rpc_unknown },
	{ GFS3_OP_XATTROP,   "XATTROP",   dissect_rpc_unknown, dissect_rpc_unknown },
	{ GFS3_OP_FXATTROP,  "FXATTROP",  dissect_rpc_unknown, dissect_rpc_unknown },
	{ GFS3_OP_FGETXATTR, "FGETXATTR", dissect_rpc_unknown, dissect_rpc_unknown },
	{ GFS3_OP_FSETXATTR, "FSETXATTR", dissect_rpc_unknown, dissect_rpc_unknown },
	{ GFS3_OP_RCHECKSUM, "RCHECKSUM", dissect_rpc_unknown, dissect_rpc_unknown },
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
	{ GFS3_OP_RELEASE,    "RELEASE",    dissect_rpc_unknown, dissect_rpc_unknown },
	{ GFS3_OP_RELEASEDIR, "RELEASEDIR", dissect_rpc_unknown, dissect_rpc_unknown },
	{ 0, NULL, NULL, NULL }
};


/*
 * GLUSTER3_1_FOP_PROGRAM for 3_3
 * - xlators/protocol/client/src/client3_1-fops.c
 * - xlators/protocol/server/src/server3_1-fops.c
 */
static const vsff glusterfs3_3_fop_proc[] = {
	{
		GFS3_OP_NULL, "NULL",
		dissect_rpc_void, dissect_rpc_void
	},
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
	{
		GFS3_OP_SYMLINK, "SYMLINK",
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
		glusterfs_gfs3_3_op_write_call, glusterfs_gfs3_3_op_setattr_reply
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
		glusterfs_gfs3_3_op_fsync_call, glusterfs_gfs3_3_op_common_reply
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
		glusterfs_gfs3_3_op_lookup_call, glusterfs_gfs3_3_op_setattr_reply
	},
	{
		GFS3_OP_READDIR, "READDIR",
		glusterfs_gfs3_3_op_readdir_call, glusterfs_gfs3_3_op_readdir_reply
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
	{ GFS3_OP_RCHECKSUM, "RCHECKSUM", dissect_rpc_unknown, dissect_rpc_unknown },
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
	{
		GFS3_OP_FREMOVEXATTR, "FREMOVEXATTR",
		glusterfs_gfs3_3_op_fremovexattr_call, glusterfs_gfs3_3_op_common_reply
	},
	{
		GFS3_OP_FALLOCATE, "FALLOCATE",
		glusterfs_gfs3_3_op_fallocate_call, glusterfs_gfs3_3_op_setattr_reply
	},
	{
		GFS3_OP_DISCARD, "DISCARD",
		glusterfs_gfs3_3_op_readdirp_call, glusterfs_gfs3_3_op_setattr_reply
	},
	{
		GFS3_OP_ZEROFILL, "ZEROFILL",
		glusterfs_gfs3_3_op_zerofill_call, glusterfs_gfs3_3_op_setattr_reply
	},
	{
		GFS3_OP_SEEK, "SEEK",
		glusterfs_gfs3_3_op_seek_call, glusterfs_gfs3_3_op_seek_reply
	},
	{ 0, NULL, NULL, NULL }
};


/*
 * GLUSTER4_0_FOP_PROGRAM for 4_0
 * - xlators/protocol/client/src/client-rpc-fops_v2.c
 * - xlators/protocol/server/src/server-rpc-fops_v2.c
 */
static const vsff glusterfs4_0_fop_proc[] = {
	{
		GFS3_OP_NULL, "NULL",
		dissect_rpc_void, dissect_rpc_void
	},
	{
		GFS3_OP_STAT, "STAT",
		glusterfs_gfs4_0_op_stat_call, glusterfs_gfs4_0_op_common_iatt_reply
	},
	{
		GFS3_OP_READLINK, "READLINK",
		glusterfs_gfs4_0_op_readlink_call, glusterfs_gfs4_0_op_readlink_reply
	},
	{
		GFS3_OP_MKNOD, "MKNOD",
		glusterfs_gfs4_0_op_mknod_call, glusterfs_gfs4_0_op_common_3iatt_reply
	},
	{
		GFS3_OP_MKDIR, "MKDIR",
		glusterfs_gfs4_0_op_mkdir_call, glusterfs_gfs4_0_op_common_3iatt_reply
	},
	{
		GFS3_OP_UNLINK, "UNLINK",
		glusterfs_gfs4_0_op_unlink_call, glusterfs_gfs4_0_op_common_2parent_iatt_reply
	},
	{
		GFS3_OP_RMDIR, "RMDIR",
		glusterfs_gfs4_0_op_rmdir_call, glusterfs_gfs4_0_op_common_2parent_iatt_reply
	},
	{
		GFS3_OP_SYMLINK, "SYMLINK",
		glusterfs_gfs4_0_op_symlink_call, glusterfs_gfs4_0_op_common_3iatt_reply
	},
	{
		GFS3_OP_RENAME, "RENAME",
		glusterfs_gfs4_0_op_rename_call, glusterfs_gfs4_0_op_rename_reply
	},
	{
		GFS3_OP_LINK, "LINK",
		glusterfs_gfs4_0_op_link_call, glusterfs_gfs4_0_op_common_3iatt_reply
	},
	{
		GFS3_OP_TRUNCATE, "TRUNCATE",
		glusterfs_gfs4_0_op_truncate_call, glusterfs_gfs4_0_op_common_2iatt_reply
	},
	{
		GFS3_OP_OPEN, "OPEN",
		glusterfs_gfs4_0_op_open_call, glusterfs_gfs4_0_op_open_reply
	},
	{
		GFS3_OP_READ, "READ",
		glusterfs_gfs4_0_op_read_call, glusterfs_gfs4_0_op_read_reply
	},
	{
		GFS3_OP_WRITE, "WRITE",
		glusterfs_gfs4_0_op_write_call, glusterfs_gfs4_0_op_common_2iatt_reply
	},
	{
		GFS3_OP_STATFS, "STATFS",
		glusterfs_gfs4_0_op_statfs_call, glusterfs_gfs4_0_op_statfs_reply
	},
	{
		GFS3_OP_FLUSH, "FLUSH",
		glusterfs_gfs4_0_op_flush_call, glusterfs_gfs4_0_op_common_reply
	},
	{
		GFS3_OP_FSYNC, "FSYNC",
		glusterfs_gfs4_0_op_fsync_call, glusterfs_gfs4_0_op_common_2iatt_reply
	},
	{
		GFS3_OP_SETXATTR, "SETXATTR",
		glusterfs_gfs4_0_op_setxattr_call, glusterfs_gfs4_0_op_common_reply
	},
	{
		GFS3_OP_GETXATTR, "GETXATTR",
		glusterfs_gfs4_0_op_getxattr_call, glusterfs_gfs4_0_op_common_dict_reply
	},
	{
		GFS3_OP_REMOVEXATTR, "REMOVEXATTR",
		glusterfs_gfs4_0_op_removexattr_call, glusterfs_gfs4_0_op_common_reply
	},
	{
		GFS3_OP_OPENDIR, "OPENDIR",
		glusterfs_gfs4_0_op_opendir_call, glusterfs_gfs4_0_op_open_reply
	},
	{
		GFS3_OP_FSYNCDIR, "FSYNCDIR",
		glusterfs_gfs4_0_op_fsync_call, glusterfs_gfs4_0_op_common_reply
	},
	{
		GFS3_OP_ACCESS, "ACCESS",
		glusterfs_gfs4_0_op_access_call, glusterfs_gfs4_0_op_common_reply
	},
	{
		GFS3_OP_CREATE, "CREATE",
		glusterfs_gfs4_0_op_create_call, glusterfs_gfs4_0_op_create_reply
	},
	{
		GFS3_OP_FTRUNCATE, "FTRUNCATE",
		glusterfs_gfs4_0_op_ftruncate_call, glusterfs_gfs4_0_op_common_2iatt_reply
	},
	{
		GFS3_OP_FSTAT, "FSTAT",
		glusterfs_gfs4_0_op_fstat_call, glusterfs_gfs4_0_op_common_iatt_reply
	},
	{
		GFS3_OP_LK, "LK",
		glusterfs_gfs4_0_op_lk_call, glusterfs_gfs4_0_op_lk_reply
	},
	{
		GFS3_OP_LOOKUP, "LOOKUP",
		glusterfs_gfs4_0_op_lookup_call, glusterfs_gfs4_0_op_common_2iatt_reply
	},
	{
		GFS3_OP_READDIR, "READDIR",
		glusterfs_gfs4_0_op_readdir_call, glusterfs_gfs4_0_op_readdir_reply
	},
	{
		GFS3_OP_INODELK, "INODELK",
		glusterfs_gfs4_0_op_inodelk_call, glusterfs_gfs4_0_op_common_reply
	},
	{
		GFS3_OP_FINODELK, "FINODELK",
		glusterfs_gfs4_0_op_finodelk_call, glusterfs_gfs4_0_op_common_reply
	},
	{
		GFS3_OP_ENTRYLK, "ENTRYLK",
		glusterfs_gfs4_0_op_entrylk_call, glusterfs_gfs4_0_op_common_reply
	},
	{
		GFS3_OP_FENTRYLK, "FENTRYLK",
		glusterfs_gfs4_0_op_fentrylk_call, glusterfs_gfs4_0_op_common_reply
	},
	{
		GFS3_OP_XATTROP, "XATTROP",
		glusterfs_gfs4_0_op_xattrop_call, glusterfs_gfs4_0_op_common_dict_reply
	},
	/*xattrop and fxattrop replay both are same */
	{
		GFS3_OP_FXATTROP, "FXATTROP",
		glusterfs_gfs4_0_op_fxattrop_call, glusterfs_gfs4_0_op_common_dict_reply
	},
	{
		GFS3_OP_FGETXATTR, "FGETXATTR",
		glusterfs_gfs4_0_op_fgetxattr_call, glusterfs_gfs4_0_op_common_dict_reply
	},
	{
		GFS3_OP_FSETXATTR, "FSETXATTR",
		gluter_gfs4_0_op_fsetxattr_call, glusterfs_gfs4_0_op_common_reply
	},
	{ GFS3_OP_RCHECKSUM, "RCHECKSUM", dissect_rpc_unknown, dissect_rpc_unknown },
	{
		GFS3_OP_SETATTR, "SETATTR",
		glusterfs_gfs4_0_op_setattr_call, glusterfs_gfs4_0_op_common_2iatt_reply
	},
	{
		GFS3_OP_FSETATTR, "FSETATTR",
		/* SETATTR and SETFATTS calls and reply are encoded the same */
		glusterfs_gfs4_0_op_fsetattr_call, glusterfs_gfs4_0_op_common_2iatt_reply
	},
	{
		GFS3_OP_READDIRP, "READDIRP",
		glusterfs_gfs4_0_op_readdirp_call, glusterfs_gfs4_0_op_readdirp_reply
	},
	{
		GFS3_OP_RELEASE, "RELEASE",
		glusterfs_gfs4_0_op_release_call, glusterfs_gfs4_0_op_common_reply
	},
	{
		GFS3_OP_RELEASEDIR, "RELEASEDIR",
		glusterfs_gfs4_0_op_releasedir_call, glusterfs_gfs4_0_op_common_reply
	},
	{
		GFS3_OP_FREMOVEXATTR, "FREMOVEXATTR",
		glusterfs_gfs4_0_op_fremovexattr_call, glusterfs_gfs4_0_op_common_reply
	},
	{
		GFS3_OP_FALLOCATE, "FALLOCATE",
		glusterfs_gfs4_0_op_fallocate_call, glusterfs_gfs4_0_op_common_2iatt_reply
	},
	{
		GFS3_OP_DISCARD, "DISCARD",
		glusterfs_gfs4_0_op_readdirp_call, glusterfs_gfs4_0_op_common_2iatt_reply
	},
	{
		GFS3_OP_ZEROFILL, "ZEROFILL",
		glusterfs_gfs4_0_op_zerofill_call, glusterfs_gfs4_0_op_common_2iatt_reply
	},
	{
		GFS3_OP_SEEK, "SEEK",
		glusterfs_gfs4_0_op_seek_call, glusterfs_gfs4_0_op_seek_reply
	},
	{ 0, NULL, NULL, NULL }
};


static const rpc_prog_vers_info glusterfs_vers_info[] = {
	{ 310, glusterfs3_1_fop_proc, &hf_glusterfs_proc },
	{ 330, glusterfs3_3_fop_proc, &hf_glusterfs_proc },
	{ 400, glusterfs4_0_fop_proc, &hf_glusterfs_proc },
};


static const value_string glusterfs3_1_fop_proc_vals[] = {
	{ GFS3_OP_NULL,	 "NULL" },
	{ GFS3_OP_STAT,	 "STAT" },
	{ GFS3_OP_READLINK,     "READLINK" },
	{ GFS3_OP_MKNOD,	"MKNOD" },
	{ GFS3_OP_MKDIR,	"MKDIR" },
	{ GFS3_OP_UNLINK,       "UNLINK" },
	{ GFS3_OP_RMDIR,	"RMDIR" },
	{ GFS3_OP_SYMLINK,      "SYMLINK" },
	{ GFS3_OP_RENAME,       "RENAME" },
	{ GFS3_OP_LINK,	 "LINK" },
	{ GFS3_OP_TRUNCATE,     "TRUNCATE" },
	{ GFS3_OP_OPEN,	 "OPEN" },
	{ GFS3_OP_READ,	 "READ" },
	{ GFS3_OP_WRITE,	"WRITE" },
	{ GFS3_OP_STATFS,       "STATFS" },
	{ GFS3_OP_FLUSH,	"FLUSH" },
	{ GFS3_OP_FSYNC,	"FSYNC" },
	{ GFS3_OP_SETXATTR,     "SETXATTR" },
	{ GFS3_OP_GETXATTR,     "GETXATTR" },
	{ GFS3_OP_REMOVEXATTR,  "REMOVEXATTR" },
	{ GFS3_OP_OPENDIR,      "OPENDIR" },
	{ GFS3_OP_FSYNCDIR,     "FSYNCDIR" },
	{ GFS3_OP_ACCESS,       "ACCESS" },
	{ GFS3_OP_CREATE,       "CREATE" },
	{ GFS3_OP_FTRUNCATE,    "FTRUNCATE" },
	{ GFS3_OP_FSTAT,	"FSTAT" },
	{ GFS3_OP_LK,	   "LK" },
	{ GFS3_OP_LOOKUP,       "LOOKUP" },
	{ GFS3_OP_READDIR,      "READDIR" },
	{ GFS3_OP_INODELK,      "INODELK" },
	{ GFS3_OP_FINODELK,     "FINODELK" },
	{ GFS3_OP_ENTRYLK,      "ENTRYLK" },
	{ GFS3_OP_FENTRYLK,     "FENTRYLK" },
	{ GFS3_OP_XATTROP,      "XATTROP" },
	{ GFS3_OP_FXATTROP,     "FXATTROP" },
	{ GFS3_OP_FGETXATTR,    "FGETXATTR" },
	{ GFS3_OP_FSETXATTR,    "FSETXATTR" },
	{ GFS3_OP_RCHECKSUM,    "RCHECKSUM" },
	{ GFS3_OP_SETATTR,      "SETATTR" },
	{ GFS3_OP_FSETATTR,     "FSETATTR" },
	{ GFS3_OP_READDIRP,     "READDIRP" },
	{ GFS3_OP_FORGET,       "FORGET" },
	{ GFS3_OP_RELEASE,      "RELEASE" },
	{ GFS3_OP_RELEASEDIR,   "RELEASEDIR" },
	{ GFS3_OP_FREMOVEXATTR, "FREMOVEXATTR" },
	{ GFS3_OP_FALLOCATE,    "FALLOCATE" },
	{ GFS3_OP_DISCARD,      "DISCARD" },
	{ GFS3_OP_ZEROFILL,     "ZEROFILL" },
	{ GFS3_OP_IPC,	  "IPC" },
	{ GFS3_OP_SEEK,	 "SEEK" },
	{ 0, NULL }
};
static value_string_ext glusterfs3_1_fop_proc_vals_ext = VALUE_STRING_EXT_INIT(glusterfs3_1_fop_proc_vals);

/* dir-entry types */
static const value_string glusterfs_entry_type_names[] = {
	{ GLUSTER_DT_UNKNOWN, "DT_UNKNOWN" },
	{ GLUSTER_DT_FIFO,    "DT_FIFO" },
	{ GLUSTER_DT_CHR,     "DT_CHR" },
	{ GLUSTER_DT_DIR,     "DT_DIR" },
	{ GLUSTER_DT_BLK,     "DT_BLK" },
	{ GLUSTER_DT_REG,     "DT_REG" },
	{ GLUSTER_DT_LNK,     "DT_LNK" },
	{ GLUSTER_DT_SOCK,    "DT_SOCK" },
	{ GLUSTER_DT_WHT,     "DT_WHT" },
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

static const value_string glusterfs_seek_whence[] = {
	{ GF_SEEK_DATA, "SEEK_DATA" },
	{ GF_SEEK_HOLE, "SEEK_HOLE" },
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
			{ "Old GFID", "glusterfs.oldgfid", FT_GUID,
				BASE_NONE, NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_newgfid,
			{ "New GFID", "glusterfs.newgfid", FT_GUID,
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
		{ &hf_glusterfs_size64,
			{ "Size", "glusterfs.size64", FT_UINT64, BASE_DEC,
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
			{ "Name Length", "glusterfs.namelen", FT_UINT32, BASE_DEC,
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
		{ &hf_glusterfs_whence,
			{ "Whence", "glusterfs.whence", FT_UINT32, BASE_DEC,
				VALS(glusterfs_seek_whence), 0, NULL, HFILL }
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
		/* TODO: These 2 have the same mask.  Which one is correct? */
		{ &hf_glusterfs_flags_nonblock,
			{ "O_NONBLOCK", "glusterfs.flags.nonblock", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), 00004000, NULL, HFILL }
		},
		{ &hf_glusterfs_flags_ndelay,
			{ "O_NDELAY", "glusterfs.flags.ndelay", FT_BOOLEAN, 32,
				TFS(&tfs_set_notset), 00004000, NULL, HFILL }
		},
		/* TODO: These 2 have the same mask.  Which one is correct? */
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

		/* the IATTx structure */
		{ &hf_glusterfs_iattx,
			{ "IATTX", "glusterfs.iattx", FT_NONE, BASE_NONE, NULL,
				0, NULL, HFILL }
		},
		{ &hf_glusterfs_preparent_iattx,
			{ "Pre-operation parent IATTX", "glusterfs.preparent_iattx", FT_NONE, BASE_NONE, NULL,
				0, NULL, HFILL }
		},
		{ &hf_glusterfs_postparent_iattx,
			{ "Post-operation parent IATTX", "glusterfs.postparent_iattx", FT_NONE, BASE_NONE, NULL,
				0, NULL, HFILL }
		},
		{ &hf_glusterfs_preop_iattx,
			{ "Pre-operation IATTX", "glusterfs.preop_iattx", FT_NONE, BASE_NONE, NULL,
				0, NULL, HFILL }
		},
		{ &hf_glusterfs_postop_iattx,
			{ "Post-operation IATTX", "glusterfs.postop_iattx", FT_NONE, BASE_NONE, NULL,
				0, NULL, HFILL }
		},
		{ &hf_glusterfs_iax_attributes,
			{ "IATT attributes", "glusterfs.iax_attributes", FT_UINT64,
				BASE_HEX, NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_iax_attributes_mask,
			{ "IATT attributes mask", "glusterfs.iax_attributes_mask", FT_UINT64,
				BASE_HEX, NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_iax_flags,
			{ "IATT flags", "glusterfs.iax_flags", FT_UINT64,
				BASE_HEX, NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_iax_atime,
			{ "Time of last access", "glusterfs.iax_atime",
				FT_UINT64, BASE_DEC, NULL, 0,
				NULL, HFILL }
		},
		{ &hf_glusterfs_iax_mtime,
			{ "Time of last modification", "glusterfs.iax_mtime",
				FT_UINT64, BASE_DEC, NULL, 0,
				NULL, HFILL }
		},
		{ &hf_glusterfs_iax_ctime,
			{ "Time of last status change", "glusterfs.iax_ctime",
				FT_UINT64, BASE_DEC, NULL, 0,
				NULL, HFILL }
		},
		{ &hf_glusterfs_iax_btime,
			{ "Creation time", "glusterfs.iax_btime",
				FT_UINT64, BASE_DEC, NULL, 0,
				NULL, HFILL }
		},
		{ &hf_glusterfs_iax_atime_nsec,
			{ "Time of last access(nsec)", "glusterfs.iax_atime_nsec",
				FT_UINT64, BASE_DEC, NULL, 0,
				NULL, HFILL }
		},
		{ &hf_glusterfs_iax_mtime_nsec,
			{ "Time of last modification(nsec)", "glusterfs.iax_mtime_nsec",
				FT_UINT64, BASE_DEC, NULL, 0,
				NULL, HFILL }
		},
		{ &hf_glusterfs_iax_ctime_nsec,
			{ "Time of last status change(nsec)", "glusterfs.iax_ctime_nsec",
				FT_UINT64, BASE_DEC, NULL, 0,
				NULL, HFILL }
		},
		{ &hf_glusterfs_iax_btime_nsec,
			{ "Creation time(nsec)", "glusterfs.iax_btime_nsec",
				FT_UINT64, BASE_DEC, NULL, 0,
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
			{ "Mount flags", "glusterfs.statfs.flags", FT_UINT64,
				BASE_HEX, NULL, 0, NULL, HFILL }
		},
		/* ST_* flags from /usr/include/bits/statvfs.h */
		{ &hf_glusterfs_mnt_flag_rdonly,
			{ "ST_RDONLY", "glusterfs.statfs.flag.rdonly",
				FT_BOOLEAN, 64, TFS(&tfs_set_notset), 1, NULL,
				HFILL }
		},
		{ &hf_glusterfs_mnt_flag_nosuid,
			{ "ST_NOSUID", "glusterfs.statfs.flag.nosuid",
				FT_BOOLEAN, 64, TFS(&tfs_set_notset), 2, NULL,
				HFILL }
		},
		{ &hf_glusterfs_mnt_flag_nodev,
			{ "ST_NODEV", "glusterfs.statfs.flag.nodev",
				FT_BOOLEAN, 64, TFS(&tfs_set_notset), 4, NULL,
				HFILL }
		},
		{ &hf_glusterfs_mnt_flag_noexec,
			{ "ST_EXEC", "glusterfs.statfs.flag.noexec",
				FT_BOOLEAN, 64, TFS(&tfs_set_notset), 8, NULL,
				HFILL }
		},
		{ &hf_glusterfs_mnt_flag_synchronous,
			{ "ST_SYNCHRONOUS",
				"glusterfs.statfs.flag.synchronous",
				FT_BOOLEAN, 64, TFS(&tfs_set_notset), 16, NULL,
				HFILL }
		},
		{ &hf_glusterfs_mnt_flag_mandlock,
			{ "ST_MANDLOCK", "glusterfs.statfs.flag.mandlock",
				FT_BOOLEAN, 64, TFS(&tfs_set_notset), 64, NULL,
				HFILL }
		},
		{ &hf_glusterfs_mnt_flag_write,
			{ "ST_WRITE", "glusterfs.statfs.flag.write",
				FT_BOOLEAN, 64, TFS(&tfs_set_notset), 128,
				NULL, HFILL }
		},
		{ &hf_glusterfs_mnt_flag_append,
			{ "ST_APPEND", "glusterfs.statfs.flag.append",
				FT_BOOLEAN, 64, TFS(&tfs_set_notset), 256,
				NULL, HFILL }
		},
		{ &hf_glusterfs_mnt_flag_immutable,
			{ "ST_IMMUTABLE", "glusterfs.statfs.flag.immutable",
				FT_BOOLEAN, 64, TFS(&tfs_set_notset), 512,
				NULL, HFILL }
		},
		{ &hf_glusterfs_mnt_flag_noatime,
			{ "ST_NOATIME", "glusterfs.statfs.flag.noatime",
				FT_BOOLEAN, 64, TFS(&tfs_set_notset), 1024,
				NULL, HFILL }
		},
		{ &hf_glusterfs_mnt_flag_nodiratime,
			{ "ST_NODIRATIME", "glusterfs.statfs.flag.nodiratime",
				FT_BOOLEAN, 64, TFS(&tfs_set_notset), 2048,
				NULL, HFILL }
		},
		{ &hf_glusterfs_mnt_flag_relatime,
			{ "ST_RELATIME", "glusterfs.statfs.flag.relatime",
				FT_BOOLEAN, 64, TFS(&tfs_set_notset), 4096,
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
				FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000001,
				NULL, HFILL }
		},
		{ &hf_glusterfs_setattr_set_uid,
			{ "SET_ATTR_UID", "glusterfs.setattr.set_uid",
				FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000002,
				NULL, HFILL }
		},
		{ &hf_glusterfs_setattr_set_gid,
			{ "SET_ATTR_GID", "glusterfs.setattr.set_gid",
				FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000004,
				NULL, HFILL }
		},
		{ &hf_glusterfs_setattr_set_size,
			{ "SET_ATTR_SIZE", "glusterfs.setattr.set_size",
				FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000008,
				NULL, HFILL }
		},
		{ &hf_glusterfs_setattr_set_atime,
			{ "SET_ATTR_ATIME", "glusterfs.setattr.set_atime",
				FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000010,
				NULL, HFILL }
		},
		{ &hf_glusterfs_setattr_set_mtime,
			{ "SET_ATTR_MTIME", "glusterfs.setattr.set_mtime",
				FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000020,
				NULL, HFILL }
		},
		{ &hf_glusterfs_setattr_set_reserved,
			{ "Reserved", "glusterfs.setattr.set_reserved",
				FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0xffffffcf,
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
		{ &hf_glusterfs_fsync_flags,
			{ "Flags", "glusterfs.fsync.flags", FT_UINT32, BASE_HEX,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterfs_fsync_flag_datasync,
			{ "DATASYNC", "glusterfs.fsync.datasync",
				FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x1,
				NULL, HFILL }
		},
		{ &hf_glusterfs_fsync_flag_unknown,
			{ "Unknown", "glusterfs.fsync.unknown",
				FT_BOOLEAN, 32, TFS(&tfs_set_notset), ~0x1,
				NULL, HFILL }
		},
		/* For entry an fentry lk */
		{ &hf_glusterfs_entrylk_namelen,
			{ "File Descriptor", "glusterfs.entrylk.namelen", FT_UINT64, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_dict_xdr_size,
			{ "XDR Size", "glusterfs.dict_xdr_size", FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_dict_size,
			{ "Size", "glusterfs.dict_size", FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_num_dict_items,
			{ "Items", "glusterfs.num_dict_items", FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_rpc_roundup_bytes,
			{ "RPC-roundup bytes", "glusterfs.rpc_roundup_bytes", FT_BYTES, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_trusted_afr_key,
			{ "Key", "glusterfs.trusted_afr_key", FT_BYTES, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_dict_value,
			{ "Value", "glusterfs.dict_value", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
	};

	/* Setup protocol subtree array */
	static int *ett[] = {
		&ett_glusterfs,
		&ett_glusterfs_flags,
		&ett_glusterfs_mnt_flags,
		&ett_glusterfs_mode,
		&ett_glusterfs_entry,
		&ett_glusterfs_setattr_valid,
		&ett_glusterfs_parent_iatt,
		&ett_glusterfs_iatt,
		&ett_glusterfs_flock,
		&ett_glusterfs_fsync_flags,
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
	rpc_init_prog(proto_glusterfs, GLUSTER3_1_FOP_PROGRAM, ett_glusterfs,
	    G_N_ELEMENTS(glusterfs_vers_info), glusterfs_vers_info);
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
