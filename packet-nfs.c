/* packet-nfs.c
 * Routines for nfs dissection
 * Copyright 1999, Uwe Girlich <Uwe.Girlich@philosys.de>
 *
 * $Id: packet-nfs.c,v 1.10 1999/11/29 13:16:57 girlich Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
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

static int hf_nfs_name = -1;

static gint ett_nfs = -1;
static gint ett_nfs_fhandle = -1;
static gint ett_nfs_timeval = -1;
static gint ett_nfs_mode = -1;
static gint ett_nfs_fattr = -1;
static gint ett_nfs_sattr = -1;
static gint ett_nfs_diropargs = -1;
static gint ett_nfs_mode3 = -1;
static gint ett_nfs_specdata3 = -1;
static gint ett_nfs_fh3 = -1;
static gint ett_nfs_nfstime3 = -1;
static gint ett_nfs_fattr3 = -1;
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


/* RFC 1094, Page 12 */
int
dissect_stat(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
char* name, guint32* status)
{
	guint32 stat;
	char* stat_name = NULL;

	const value_string nfs2_stat[] =
	{
		{	0,	"OK" },
		{	1,	"ERR_PERM" },
		{	2,	"ERR_NOENT" },
		{	5,	"ERR_IO" },
		{	6,	"ERR_NX_IO" },
		{	13,	"ERR_ACCES" },
		{	17,	"ERR_EXIST" },
		{	19,	"ERR_NODEV" },
		{	20,	"ERR_NOTDIR" },
		{	21,	"ERR_ISDIR" },
		{	27,	"ERR_FBIG" },
		{	28,	"ERR_NOSPC" },
		{	30,	"ERR_ROFS" },
		{	63,	"ERR_NAMETOOLONG" },
		{	66,	"ERR_NOTEMPTY" },
		{	69,	"ERR_DQUOT" },
		{	70,	"ERR_STALE" },
		{	99,	"ERR_WFLUSH" },
		{	0,	NULL }
	};

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	stat = EXTRACT_UINT(pd, offset+0);
	stat_name = val_to_str(stat, nfs2_stat, "%u");
	
	if (tree) {
		proto_tree_add_text(tree, offset, 4,
			"%s: %s (%u)", name, stat_name, stat);
	}

	offset += 4;
	*status = stat;
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
		proto_tree_add_text(tree, offset, 4,
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
		fitem = proto_tree_add_text(tree, offset, FHSIZE,
			"%s", name);
		if (fitem)
			ftree = proto_item_add_subtree(fitem, ett_nfs_fhandle);
	}

	if (ftree) {
		proto_tree_add_text(ftree,offset+0,FHSIZE,
					"file handle (opaque data)");
	}

	offset += FHSIZE;
	return offset;
}


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
		time_item = proto_tree_add_text(tree, offset, 8,
			"%s: %u.%06u", name, seconds, mseconds);
		if (time_item)
			time_tree = proto_item_add_subtree(time_item, ett_nfs_timeval);
	}

	if (time_tree) {
		proto_tree_add_text(time_tree,offset+0,4,
					"seconds: %u", seconds);
		proto_tree_add_text(time_tree,offset+4,4,
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
		mode_item = proto_tree_add_text(tree, offset, 4,
			"%s: 0%o", name, mode);
		if (mode_item)
			mode_tree = proto_item_add_subtree(mode_item, ett_nfs_mode);
	}

	if (mode_tree) {
		proto_tree_add_text(mode_tree, offset, 4, "%s",
			decode_enumerated_bitfield(mode,  0160000, 16,
			nfs2_mode_names, "%s"));
		proto_tree_add_text(mode_tree, offset, 4, "%s",
		decode_boolean_bitfield(mode,   04000, 16, "Set user id on exec", "not SUID"));
		proto_tree_add_text(mode_tree, offset, 4, "%s",
		decode_boolean_bitfield(mode,   02000, 16, "Set group id on exec", "not SGID"));
		proto_tree_add_text(mode_tree, offset, 4, "%s",
		decode_boolean_bitfield(mode,   01000, 16, "Save swapped text even after use", "not save swapped text"));
		proto_tree_add_text(mode_tree, offset, 4, "%s",
		decode_boolean_bitfield(mode,    0400, 16, "Read permission for owner", "no Read permission for owner"));
		proto_tree_add_text(mode_tree, offset, 4, "%s",
		decode_boolean_bitfield(mode,    0200, 16, "Write permission for owner", "no Write permission for owner"));
		proto_tree_add_text(mode_tree, offset, 4, "%s",
		decode_boolean_bitfield(mode,    0100, 16, "Execute permission for owner", "no Execute permission for owner"));
		proto_tree_add_text(mode_tree, offset, 4, "%s",
		decode_boolean_bitfield(mode,     040, 16, "Read permission for group", "no Read permission for group"));
		proto_tree_add_text(mode_tree, offset, 4, "%s",
		decode_boolean_bitfield(mode,     020, 16, "Write permission for group", "no Write permission for group"));
		proto_tree_add_text(mode_tree, offset, 4, "%s",
		decode_boolean_bitfield(mode,     010, 16, "Execute permission for group", "no Execute permission for group"));
		proto_tree_add_text(mode_tree, offset, 4, "%s",
		decode_boolean_bitfield(mode,      04, 16, "Read permission for others", "no Read permission for others"));
		proto_tree_add_text(mode_tree, offset, 4, "%s",
		decode_boolean_bitfield(mode,      02, 16, "Write permission for others", "no Write permission for others"));
		proto_tree_add_text(mode_tree, offset, 4, "%s",
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
		fattr_item = proto_tree_add_text(tree, offset,
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
		sattr_item = proto_tree_add_text(tree, offset,
			END_OF_FRAME, "%s", name);
		if (sattr_item)
			sattr_tree = proto_item_add_subtree(sattr_item, ett_nfs_sattr);
	}

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	if (EXTRACT_UINT(pd, offset+0) != 0xffffffff)
		offset = dissect_mode         (pd,offset,fd,sattr_tree,"mode");
	else {
		proto_tree_add_text(sattr_tree, offset, 4, "mode: no value");
		offset += 4;
	}

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	if (EXTRACT_UINT(pd, offset+0) != 0xffffffff)
		offset = dissect_unsigned_int (pd,offset,fd,sattr_tree,"uid");
	else {
		proto_tree_add_text(sattr_tree, offset, 4, "uid: no value");
		offset += 4;
	}

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	if (EXTRACT_UINT(pd, offset+0) != 0xffffffff)
		offset = dissect_unsigned_int (pd,offset,fd,sattr_tree,"gid");
	else {
		proto_tree_add_text(sattr_tree, offset, 4, "gid: no value");
		offset += 4;
	}

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	if (EXTRACT_UINT(pd, offset+0) != 0xffffffff)
		offset = dissect_unsigned_int (pd,offset,fd,sattr_tree,"size");
	else {
		proto_tree_add_text(sattr_tree, offset, 4, "size: no value");
		offset += 4;
	}

	if (!BYTES_ARE_IN_FRAME(offset,8)) return offset;
	if (EXTRACT_UINT(pd, offset+0) != 0xffffffff)
		offset = dissect_timeval      (pd,offset,fd,sattr_tree,"atime");
	else {
		proto_tree_add_text(sattr_tree, offset, 8, "atime: no value");
		offset += 8;
	}

	if (!BYTES_ARE_IN_FRAME(offset,8)) return offset;
	if (EXTRACT_UINT(pd, offset+0) != 0xffffffff)
		offset = dissect_timeval      (pd,offset,fd,sattr_tree,"mtime");
	else {
		proto_tree_add_text(sattr_tree, offset, 8, "mtime: no value");
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
dissect_filename(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int hf)
{
	offset = dissect_rpc_string(pd,offset,fd,tree,hf);
	return offset;
}


/* RFC 1094, Page 17 */
int
dissect_attrstat(const u_char *pd, int offset, frame_data *fd, proto_tree *tree){
	guint32 status;

	offset = dissect_stat(pd, offset, fd, tree, "status", &status);
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


/* RFC 1094, Page 18 */
int
dissect_diropargs(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name)
{
	proto_item* diropargs_item = NULL;
	proto_tree* diropargs_tree = NULL;
	int old_offset = offset;

	if (tree) {
		diropargs_item = proto_tree_add_text(tree, offset,
			END_OF_FRAME, "%s", name);
		if (diropargs_item)
			diropargs_tree = proto_item_add_subtree(diropargs_item, ett_nfs_diropargs);
	}

	offset = dissect_fhandle (pd,offset,fd,diropargs_tree,"dir");
	offset = dissect_filename(pd,offset,fd,diropargs_tree,hf_nfs_name);

	/* now we know, that diropargs is shorter */
	if (diropargs_item) {
		proto_item_set_len(diropargs_item, offset - old_offset);
	}

	return offset;
}


/* RFC 1094, Page 18 */
int
dissect_diropres(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	guint32	status;

	offset = dissect_stat(pd, offset, fd, tree, "status", &status);
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


/* generic NFS2 call dissector */
int
dissect_nfs2_any_call(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	offset = dissect_fhandle(pd, offset, fd, tree, "object");

	return offset;
}


/* generic NFS2 reply dissector */
int
dissect_nfs2_any_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	guint32 status;

	offset = dissect_stat(pd, offset, fd, tree, "status", &status);

	return offset;
}


/* RFC 1094, Page 5 */
int
dissect_nfs2_getattr_call(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	offset = dissect_fhandle(pd, offset, fd, tree, "object");

	return offset;
}


/* RFC 1094, Page 5 */
int
dissect_nfs2_getattr_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	offset = dissect_attrstat(pd, offset, fd, tree);

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
dissect_nfs2_setattr_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	offset = dissect_attrstat(pd, offset, fd, tree);

	return offset;
}


/* RFC 1094, Page 6 */
int
dissect_nfs2_lookup_call(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	offset = dissect_diropargs(pd, offset, fd, tree, "what");

	return offset;
}


/* RFC 1094, Page 6 */
int
dissect_nfs2_lookup_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	offset = dissect_diropres(pd, offset, fd, tree);

	return offset;
}


/* RFC 1094, Page 8 */
int
dissect_nfs2_write_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	offset = dissect_attrstat(pd, offset, fd, tree);

	return offset;
}


/* RFC 1094, Page 8 */
int
dissect_nfs2_create_call(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	offset = dissect_diropargs(pd, offset, fd, tree, "where");
	offset = dissect_sattr    (pd, offset, fd, tree, "attributes");

	return offset;
}


/* RFC 1094, Page 8 */
int
dissect_nfs2_create_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	offset = dissect_diropres(pd, offset, fd, tree);

	return offset;
}


/* RFC 1094, Page 8 */
int
dissect_nfs2_remove_call(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	offset = dissect_diropargs(pd, offset, fd, tree, "where");

	return offset;
}


/* more to come here */


/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: take the generic one. */
const vsff nfs2_proc[] = {
	{ 0,	"NULL",		NULL,				NULL },
	{ 1,	"GETATTR",	dissect_nfs2_getattr_call,	dissect_nfs2_getattr_reply },
	{ 2,	"SETATTR",	dissect_nfs2_setattr_call,	dissect_nfs2_setattr_reply },
	{ 3,	"ROOT",		NULL,				NULL },
	{ 4,	"LOOKUP",	dissect_nfs2_lookup_call,	dissect_nfs2_lookup_reply },
	{ 5,	"READLINK",	dissect_nfs2_any_call,		dissect_nfs2_any_reply },
	{ 6,	"READ",		dissect_nfs2_any_call,		dissect_nfs2_any_reply },
	{ 7,	"WRITECACHE",	NULL,				NULL },
	{ 8,	"WRITE",	dissect_nfs2_any_call,		dissect_nfs2_write_reply },
	{ 9,	"CREATE",	dissect_nfs2_create_call,	dissect_nfs2_create_reply },
	{ 10,	"REMOVE",	dissect_nfs2_remove_call,	dissect_nfs2_any_reply },
	{ 11,	"RENAME",	dissect_nfs2_any_call,		dissect_nfs2_any_reply },
	{ 12,	"LINK",		dissect_nfs2_any_call,		dissect_nfs2_any_reply },
	{ 13,	"SYMLINK",	dissect_nfs2_any_call,		dissect_nfs2_any_reply },
	{ 14,	"MKDIR",	dissect_nfs2_any_call,		dissect_nfs2_any_reply },
	{ 15,	"RMDIR",	dissect_nfs2_any_call,		dissect_nfs2_any_reply },
	{ 16,	"READDIR",	dissect_nfs2_any_call,		dissect_nfs2_any_reply },
	{ 17,	"STATFS",	dissect_nfs2_any_call,		dissect_nfs2_any_reply },
	{ 0,	NULL,		NULL,				NULL }
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
dissect_filename3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int hf)
{
	offset = dissect_rpc_string(pd,offset,fd,tree,hf);
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
dissect_mode3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
char* name)
{
	guint32 mode3;
	proto_item* mode3_item = NULL;
	proto_tree* mode3_tree = NULL;

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	mode3 = EXTRACT_UINT(pd, offset+0);
	
	if (tree) {
		mode3_item = proto_tree_add_text(tree, offset, 4,
			"%s: 0%o", name, mode3);
		if (mode3_item)
			mode3_tree = proto_item_add_subtree(mode3_item, ett_nfs_mode3);
	}

	/* RFC 1813, Page 23 */
	if (mode3_tree) {
		proto_tree_add_text(mode3_tree, offset, 4, "%s",
		decode_boolean_bitfield(mode3,   0x800, 12, "Set user id on exec", "not SUID"));
		proto_tree_add_text(mode3_tree, offset, 4, "%s",
		decode_boolean_bitfield(mode3,   0x400, 12, "Set group id on exec", "not SGID"));
		proto_tree_add_text(mode3_tree, offset, 4, "%s",
		decode_boolean_bitfield(mode3,   0x200, 12, "Save swapped text even after use", "not save swapped text"));
		proto_tree_add_text(mode3_tree, offset, 4, "%s",
		decode_boolean_bitfield(mode3,   0x100, 12, "Read permission for owner", "no Read permission for owner"));
		proto_tree_add_text(mode3_tree, offset, 4, "%s",
		decode_boolean_bitfield(mode3,    0x80, 12, "Write permission for owner", "no Write permission for owner"));
		proto_tree_add_text(mode3_tree, offset, 4, "%s",
		decode_boolean_bitfield(mode3,    0x40, 12, "Execute permission for owner", "no Execute permission for owner"));
		proto_tree_add_text(mode3_tree, offset, 4, "%s",
		decode_boolean_bitfield(mode3,    0x20, 12, "Read permission for group", "no Read permission for group"));
		proto_tree_add_text(mode3_tree, offset, 4, "%s",
		decode_boolean_bitfield(mode3,    0x10, 12, "Write permission for group", "no Write permission for group"));
		proto_tree_add_text(mode3_tree, offset, 4, "%s",
		decode_boolean_bitfield(mode3,     0x8, 12, "Execute permission for group", "no Execute permission for group"));
		proto_tree_add_text(mode3_tree, offset, 4, "%s",
		decode_boolean_bitfield(mode3,     0x4, 12, "Read permission for others", "no Read permission for others"));
		proto_tree_add_text(mode3_tree, offset, 4, "%s",
		decode_boolean_bitfield(mode3,     0x2, 12, "Write permission for others", "no Write permission for others"));
		proto_tree_add_text(mode3_tree, offset, 4, "%s",
		decode_boolean_bitfield(mode3,     0x1, 12, "Execute permission for others", "no Execute permission for others"));
	}

	offset += 4;
	return offset;
}


/* RFC 1813, Page 16 */
int
dissect_count3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
char* name, char* type)
{
	offset = dissect_rpc_uint32(pd,offset,fd,tree,name,"count");
	return offset;
}


/* RFC 1813, Page 16 */
int
dissect_nfsstat3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
char* name, guint32* status)
{
	guint32 nfsstat3;
	char* nfsstat3_name = NULL;

	const value_string nfs3_nfsstat3[] =
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
/* RFC 1813, Page 17 */
		{	10002,	"ERR_NOT_SYNC" },
		{	10003,	"ERR_BAD_COOKIE" },
		{	10004,	"ERR_NOTSUPP" },
		{	10005,	"ERR_TOOSMALL" },
		{	10006,	"ERR_SERVERFAULT" },
		{	10007,	"ERR_BADTYPE" },
		{	10008,	"ERR_JUKEBOX" },
		{	0,	NULL }
	};

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	nfsstat3 = EXTRACT_UINT(pd, offset+0);
	nfsstat3_name = val_to_str(nfsstat3, nfs3_nfsstat3, "%u");
	
	if (tree) {
		proto_tree_add_text(tree, offset, 4,
			"%s: %s (%u)", name, nfsstat3_name, nfsstat3);
	}

	offset += 4;
	*status = nfsstat3;
	return offset;
}


/* RFC 1813, Page 17, 18, 19, 20: error explanations */


/* RFC 1813, Page 20 */
int
dissect_ftype3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
char* name)
{
	guint32 ftype3;
	char* ftype3_name = NULL;

	const value_string nfs3_ftype3[] =
	{
		{	1,	"Regular File" },
		{	2,	"Directory" },
		{	3,	"Block Special Device" },
		{	4,	"Character Special Device" },
		{	5,	"Symbolic Link" },
		{	6,	"Socket" },
		{	7,	"Named Pipe" },
		{	0,	NULL }
	};

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	ftype3 = EXTRACT_UINT(pd, offset+0);
	ftype3_name = val_to_str(ftype3, nfs3_ftype3, "%u");
	
	if (tree) {
		proto_tree_add_text(tree, offset, 4,
			"%s: %s (%u)", name, ftype3_name, ftype3);
	}

	offset += 4;
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
		specdata3_item = proto_tree_add_text(tree, offset, 8,
			"%s: %u,%u", name, specdata1, specdata2);
		if (specdata3_item)
			specdata3_tree = proto_item_add_subtree(specdata3_item,
					ett_nfs_specdata3);
	}

	if (specdata3_tree) {
		proto_tree_add_text(specdata3_tree,offset+0,4,
					"specdata1: %u", specdata1);
		proto_tree_add_text(specdata3_tree,offset+4,4,
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
		fitem = proto_tree_add_text(tree, offset, 4+fh3_len_full,
			"%s", name);
		if (fitem)
			ftree = proto_item_add_subtree(fitem, ett_nfs_fh3);
	}

	if (ftree) {
		proto_tree_add_text(ftree,offset+0,4,
					"length: %u", fh3_len);
		proto_tree_add_text(ftree,offset+4,fh3_len,
					"file handle (opaque data)");
		if (fh3_fill)
			proto_tree_add_text(ftree,offset+4+fh3_len,fh3_fill,
				"fill bytes");
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
		time_item = proto_tree_add_text(tree, offset, 8,
			"%s: %u.%09u", name, seconds, nseconds);
		if (time_item)
			time_tree = proto_item_add_subtree(time_item, ett_nfs_nfstime3);
	}

	if (time_tree) {
		proto_tree_add_text(time_tree,offset+0,4,
					"seconds: %u", seconds);
		proto_tree_add_text(time_tree,offset+4,4,
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

	if (tree) {
		fattr3_item = proto_tree_add_text(tree, offset,
			END_OF_FRAME, "%s", name);
		if (fattr3_item)
			fattr3_tree = proto_item_add_subtree(fattr3_item, ett_nfs_fattr3);
	}

	offset = dissect_ftype3   (pd,offset,fd,fattr3_tree,"type");
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


const value_string value_follows[3] =
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
		post_op_attr_item = proto_tree_add_text(tree, offset,
			END_OF_FRAME, "%s", name);
		if (post_op_attr_item)
			post_op_attr_tree = proto_item_add_subtree(post_op_attr_item, ett_nfs_post_op_attr);
	}

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	attributes_follow = EXTRACT_UINT(pd, offset+0);
	proto_tree_add_text(post_op_attr_tree, offset, 4,
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
		wcc_attr_item = proto_tree_add_text(tree, offset,
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
		pre_op_attr_item = proto_tree_add_text(tree, offset,
			END_OF_FRAME, "%s", name);
		if (pre_op_attr_item)
			pre_op_attr_tree = proto_item_add_subtree(pre_op_attr_item, ett_nfs_pre_op_attr);
	}

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	attributes_follow = EXTRACT_UINT(pd, offset+0);
	proto_tree_add_text(pre_op_attr_tree, offset, 4,
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
		wcc_data_item = proto_tree_add_text(tree, offset,
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
		set_mode3_item = proto_tree_add_text(tree, offset,
			END_OF_FRAME, "%s: %s", name, set_it_name);
		if (set_mode3_item)
			set_mode3_tree = proto_item_add_subtree(set_mode3_item, ett_nfs_set_mode3);
	}

	if (set_mode3_tree)
		proto_tree_add_text(set_mode3_tree, offset, 4,
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
		set_uid3_item = proto_tree_add_text(tree, offset,
			END_OF_FRAME, "%s: %s", name, set_it_name);
		if (set_uid3_item)
			set_uid3_tree = proto_item_add_subtree(set_uid3_item, ett_nfs_set_uid3);
	}

	if (set_uid3_tree)
		proto_tree_add_text(set_uid3_tree, offset, 4,
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
		set_gid3_item = proto_tree_add_text(tree, offset,
			END_OF_FRAME, "%s: %s", name, set_it_name);
		if (set_gid3_item)
			set_gid3_tree = proto_item_add_subtree(set_gid3_item, ett_nfs_set_gid3);
	}

	if (set_gid3_tree)
		proto_tree_add_text(set_gid3_tree, offset, 4,
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
		set_size3_item = proto_tree_add_text(tree, offset,
			END_OF_FRAME, "%s: %s", name, set_it_name);
		if (set_size3_item)
			set_size3_tree = proto_item_add_subtree(set_size3_item, ett_nfs_set_size3);
	}

	if (set_size3_tree)
		proto_tree_add_text(set_size3_tree, offset, 4,
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
		set_atime_item = proto_tree_add_text(tree, offset,
			END_OF_FRAME, "%s: %s",
			name, set_it_name, set_it);
		if (set_atime_item)
			set_atime_tree = proto_item_add_subtree(set_atime_item, ett_nfs_set_atime);
	}

	if (set_atime_tree)
		proto_tree_add_text(set_atime_tree, offset, 4,
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
		set_mtime_item = proto_tree_add_text(tree, offset,
			END_OF_FRAME, "%s: %s",
			name, set_it_name, set_it);
		if (set_mtime_item)
			set_mtime_tree = proto_item_add_subtree(set_mtime_item, ett_nfs_set_mtime);
	}

	if (set_mtime_tree)
		proto_tree_add_text(set_mtime_tree, offset, 4,
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


/* RFC 1813, Page 26 */
int
dissect_sattr3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name)
{
	proto_item* sattr3_item = NULL;
	proto_tree* sattr3_tree = NULL;
	int old_offset = offset;

	if (tree) {
		sattr3_item = proto_tree_add_text(tree, offset,
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
		diropargs3_item = proto_tree_add_text(tree, offset,
			END_OF_FRAME, "%s", name);
		if (diropargs3_item)
			diropargs3_tree = proto_item_add_subtree(diropargs3_item, ett_nfs_diropargs3);
	}

	offset = dissect_nfs_fh3  (pd, offset, fd, diropargs3_tree, "dir");
	offset = dissect_filename3(pd, offset, fd, diropargs3_tree, hf_nfs_name);

	/* now we know, that diropargs3 is shorter */
	if (diropargs3_item) {
		proto_item_set_len(diropargs3_item, offset - old_offset);
	}

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
		access_item = proto_tree_add_text(tree, offset, 4,
			"%s: 0x%02x", name, access);
		if (access_item)
			access_tree = proto_item_add_subtree(access_item, ett_nfs_access);
	}

	if (access_tree) {
		proto_tree_add_text(access_tree, offset, 4, "%s READ",
		decode_boolean_bitfield(access,  0x001, 6, "allow", "not allow"));
		proto_tree_add_text(access_tree, offset, 4, "%s LOOKUP",
		decode_boolean_bitfield(access,  0x002, 6, "allow", "not allow"));
		proto_tree_add_text(access_tree, offset, 4, "%s MODIFY",
		decode_boolean_bitfield(access,  0x004, 6, "allowed", "not allow"));
		proto_tree_add_text(access_tree, offset, 4, "%s EXTEND",
		decode_boolean_bitfield(access,  0x008, 6, "allow", "not allow"));
		proto_tree_add_text(access_tree, offset, 4, "%s DELETE",
		decode_boolean_bitfield(access,  0x010, 6, "allow", "not allow"));
		proto_tree_add_text(access_tree, offset, 4, "%s EXECUTE",
		decode_boolean_bitfield(access,  0x020, 6, "allow", "not allow"));
	}

	offset += 4;
	return offset;
}


/* generic NFS3 call dissector */
int
dissect_nfs3_any_call(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	offset = dissect_nfs_fh3(pd, offset, fd, tree, "object");
	return offset;
}


/* generic NFS3 reply dissector */
int
dissect_nfs3_any_reply(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	guint32 status;

	offset = dissect_nfsstat3(pd, offset, fd, tree, "status", &status);

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

	offset = dissect_nfsstat3(pd, offset, fd, tree, "status", &status);
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
		sattrguard3_item = proto_tree_add_text(tree, offset,
			END_OF_FRAME, "%s: %s", name, check_name);
		if (sattrguard3_item)
			sattrguard3_tree = proto_item_add_subtree(sattrguard3_item, ett_nfs_sattrguard3);
	}

	if (sattrguard3_tree)
		proto_tree_add_text(sattrguard3_tree, offset, 4,
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

	offset = dissect_nfsstat3(pd, offset, fd, tree, "status", &status);
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

	offset = dissect_nfsstat3(pd, offset, fd, tree, "status", &status);
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

	offset = dissect_nfsstat3(pd, offset, fd, tree, "status", &status);
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


/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: take the generic one. */
const vsff nfs3_proc[] = {
	{ 0,	"NULL",		NULL,				NULL },
	{ 1,	"GETATTR",	dissect_nfs3_getattr_call,	dissect_nfs3_getattr_reply },
	{ 2,	"SETATTR",	dissect_nfs3_setattr_call,	dissect_nfs3_setattr_reply },
	{ 3,	"LOOKUP",	dissect_nfs3_lookup_call,	dissect_nfs3_lookup_reply },
	{ 4,	"ACCESS",	dissect_nfs3_access_call,	dissect_nfs3_access_reply },
	{ 5,	"READLINK",	dissect_nfs3_any_call,		dissect_nfs3_any_reply },
	{ 6,	"READ",		dissect_nfs3_any_call,		dissect_nfs3_any_reply },
	{ 7,	"WRITE",	dissect_nfs3_any_call,		dissect_nfs3_any_reply },
	{ 8,	"CREATE",	dissect_nfs3_any_call,		dissect_nfs3_any_reply },
	{ 9,	"MKDIR",	dissect_nfs3_any_call,		dissect_nfs3_any_reply },
	{ 10,	"SYMLINK",	dissect_nfs3_any_call,		dissect_nfs3_any_reply },
	{ 11,	"MKNOD",	dissect_nfs3_any_call,		dissect_nfs3_any_reply },
	{ 12,	"REMOVE",	dissect_nfs3_any_call,		dissect_nfs3_any_reply },
	{ 13,	"RMDIR",	dissect_nfs3_any_call,		dissect_nfs3_any_reply },
	{ 14,	"RENAME",	dissect_nfs3_any_call,		dissect_nfs3_any_reply },
	{ 15,	"LINK",		dissect_nfs3_any_call,		dissect_nfs3_any_reply },
	{ 16,	"READDIR",	dissect_nfs3_any_call,		dissect_nfs3_any_reply },
	{ 17,	"READDIRPLUS",	dissect_nfs3_any_call,		dissect_nfs3_any_reply },
	{ 18,	"FSSTAT",	dissect_nfs3_any_call,		dissect_nfs3_any_reply },
	{ 19,	"FSINFO",	dissect_nfs3_any_call,		dissect_nfs3_any_reply },
	{ 20,	"PATHCONF",	dissect_nfs3_any_call,		dissect_nfs3_any_reply },
	{ 21,	"COMMIT",	dissect_nfs3_any_call,		dissect_nfs3_any_reply },
	{ 0,	NULL,		NULL,				NULL }
};
/* end of NFS Version 3 */


void
proto_register_nfs(void)
{
	static hf_register_info hf[] = {
		{ &hf_nfs_name, {
			"Name", "nfs.name", FT_STRING, BASE_DEC,
			NULL, 0, "Name" }}
	};
	static gint *ett[] = {
		&ett_nfs,
		&ett_nfs_fhandle,
		&ett_nfs_timeval,
		&ett_nfs_mode,
		&ett_nfs_fattr,
		&ett_nfs_sattr,
		&ett_nfs_diropargs,
		&ett_nfs_mode3,
		&ett_nfs_specdata3,
		&ett_nfs_fh3,
		&ett_nfs_nfstime3,
		&ett_nfs_fattr3,
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
		&ett_nfs_access
	};
	proto_nfs = proto_register_protocol("Network File System", "nfs");
	proto_register_field_array(proto_nfs, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register the protocol as RPC */
	rpc_init_prog(proto_nfs, NFS_PROGRAM, ett_nfs);
	/* Register the procedure tables */
	rpc_init_proc_table(NFS_PROGRAM, 2, nfs2_proc);
	rpc_init_proc_table(NFS_PROGRAM, 3, nfs3_proc);
}
