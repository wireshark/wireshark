/* packet-nfs.c
 * Routines for nfs dissection
 * Copyright 1999, Uwe Girlich <Uwe.Girlich@philosys.de>
 *
 * $Id: packet-nfs.c,v 1.2 1999/11/05 07:16:23 guy Exp $
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
			"%s (stat): %s (%u)", name, stat_name, stat);
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
			"%s (ftype): %s (%u)", name, ftype_name, ftype);
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
			"%s (fhandle)", name);
		if (fitem)
			ftree = proto_item_add_subtree(fitem, ETT_NFS_FHANDLE);
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
			"%s (timeval): %u.%06u", name, seconds, mseconds);
		if (time_item)
			time_tree = proto_item_add_subtree(time_item, ETT_NFS_TIMEVAL);
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
			"%s (mode): 0%o", name, mode);
		if (mode_item)
			mode_tree = proto_item_add_subtree(mode_item, ETT_NFS_MODE);
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
			END_OF_FRAME, "%s (fattr)", name);
		if (fattr_item)
			fattr_tree = proto_item_add_subtree(fattr_item, ETT_NFS_FATTR);
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
	guint32 status;

	/* attrstat: RFC 1094, Page 17 */
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

/* more to come here */


/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: take the generic one. */
const vsff nfs2_proc[] = {
	{ 0,	"NULL",		NULL,				NULL },
	{ 1,	"GETATTR",	dissect_nfs2_getattr_call,	dissect_nfs2_getattr_reply },
	{ 2,	"SETATTR",	dissect_nfs2_any_call,		dissect_nfs2_any_reply },
	{ 3,	"ROOT",		NULL,				NULL },
	{ 4,	"LOOKUP",	dissect_nfs2_any_call,		dissect_nfs2_any_reply },
	{ 5,	"READLINK",	dissect_nfs2_any_call,		dissect_nfs2_any_reply },
	{ 6,	"READ",		dissect_nfs2_any_call,		dissect_nfs2_any_reply },
	{ 7,	"WRITECACHE",	NULL,				NULL },
	{ 8,	"WRITE",	dissect_nfs2_any_call,		dissect_nfs2_any_reply },
	{ 9,	"CREATE",	dissect_nfs2_any_call,		dissect_nfs2_any_reply },
	{ 10,	"REMOVE",	dissect_nfs2_any_call,		dissect_nfs2_any_reply },
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
			"%s (mode3): 0%o", name, mode3);
		if (mode3_item)
			mode3_tree = proto_item_add_subtree(mode3_item, ETT_NFS_MODE3);
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
			"%s (nfsstat3): %s (%u)", name, nfsstat3_name, nfsstat3);
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
			"%s (ftype3): %s (%u)", name, ftype3_name, ftype3);
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
			"%s (specdata3) : %u,%u", name, specdata1, specdata2);
		if (specdata3_item)
			specdata3_tree = proto_item_add_subtree(specdata3_item,
					ETT_NFS_SPECDATA3);
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
	guint fh_len;
	guint fh_len_full;
	guint fh_fill;
	proto_item* fitem;
	proto_tree* ftree = NULL;

	fh_len = EXTRACT_UINT(pd, offset+0);
	fh_len_full = roundup(fh_len);
	fh_fill = fh_len_full - fh_len;
	
	if (tree) {
		fitem = proto_tree_add_text(tree, offset, 4+fh_len_full,
			"%s (nfs_fh3)", name);
		if (fitem)
			ftree = proto_item_add_subtree(fitem, ETT_NFS_FH3);
	}

	if (ftree) {
		proto_tree_add_text(ftree,offset+0,4,
					"length: %u", fh_len);
		proto_tree_add_text(ftree,offset+4,fh_len,
					"file handle (opaque data)");
		if (fh_fill)
			proto_tree_add_text(ftree,offset+4+fh_len,fh_fill,
				"fill bytes");
	}
	offset += 4 + fh_len_full;
	return offset;
}


/* RFC 1813, Page 21 */
int
dissect_nfs3time(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,char* name)
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
			"%s (nfs3time): %u.%09u", name, seconds, nseconds);
		if (time_item)
			time_tree = proto_item_add_subtree(time_item, ETT_NFS_NFSTIME3);
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
			END_OF_FRAME, "%s (fattr3)", name);
		if (fattr3_item)
			fattr3_tree = proto_item_add_subtree(fattr3_item, ETT_NFS_FATTR3);
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
	offset = dissect_nfs3time (pd,offset,fd,fattr3_tree,"atime");
	offset = dissect_nfs3time (pd,offset,fd,fattr3_tree,"mtime");
	offset = dissect_nfs3time (pd,offset,fd,fattr3_tree,"ctime");

	/* now we know, that fattr3 is shorter */
	if (fattr3_item) {
		proto_item_set_len(fattr3_item, offset - old_offset);
	}

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


/* RFC 1813, Page 32 */
int
dissect_nfs3_getattr_call(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	offset = dissect_nfs_fh3(pd, offset, fd, tree, "object");
	return offset;
}


/* RFC 1813, Page 32 */
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


/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: take the generic one. */
const vsff nfs3_proc[] = {
	{ 0,	"NULL",		NULL,				NULL },
	{ 1,	"GETATTR",	dissect_nfs3_getattr_call,	dissect_nfs3_getattr_reply },
	{ 2,	"SETATTR",	dissect_nfs3_any_call,		dissect_nfs3_any_reply },
	{ 3,	"LOOKUP",	dissect_nfs3_any_call,		dissect_nfs3_any_reply },
	{ 4,	"ACCESS",	dissect_nfs3_any_call,		dissect_nfs3_any_reply },
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
	proto_nfs = proto_register_protocol("Network File System", "NFS");

	/* Register the protocol as RPC */
	rpc_init_prog(proto_nfs, NFS_PROGRAM, ETT_NFS);
	/* Register the procedure tables */
	rpc_init_proc_table(NFS_PROGRAM, 2, nfs2_proc);
	rpc_init_proc_table(NFS_PROGRAM, 3, nfs3_proc);
}

