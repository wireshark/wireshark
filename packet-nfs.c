/* packet-nfs.c
 * Routines for nfs dissection
 * Copyright 1999, Uwe Girlich <Uwe.Girlich@philosys.de>
 *
 * $Id: packet-nfs.c,v 1.1 1999/10/29 01:11:23 guy Exp $
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

int dissect_fh2(const u_char *pd, int offset, frame_data *fd, proto_tree *tree);

/*
This is the table with the dissector functions. As almost all functions
start with a file handle and I had no more time, this is all I did up to now.
The RPC layer will cope with any following data and interpret it as data.
I'm not sure, if all compilers fill undefined structure members with zeros,
so I give the NULL value in all cases.
*/

/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: take the generic one. */
const vsff nfs2_proc[] = {
	{ 0,	"NULL",		NULL,		NULL },
	{ 1,	"GETATTR",	dissect_fh2,	NULL },
	{ 2,	"SETATTR",	dissect_fh2,	NULL },
	{ 3,	"ROOT",		NULL,		NULL },
	{ 4,	"LOOKUP",	dissect_fh2,	NULL },
	{ 5,	"READLINK",	dissect_fh2,	NULL },
	{ 6,	"READ",		dissect_fh2,	NULL },
	{ 7,	"WRITECACHE",	dissect_fh2,	NULL },
	{ 8,	"WRITE",	dissect_fh2,	NULL },
	{ 9,	"CREATE",	dissect_fh2,	NULL },
	{ 10,	"REMOVE",	dissect_fh2,	NULL },
	{ 11,	"RENAME",	dissect_fh2,	NULL },
	{ 12,	"LINK",		dissect_fh2,	NULL },
	{ 13,	"SYMLINK",	dissect_fh2,	NULL },
	{ 14,	"MKDIR",	dissect_fh2,	NULL },
	{ 15,	"RMDIR",	dissect_fh2,	NULL },
	{ 16,	"READDIR",	dissect_fh2,	NULL },
	{ 17,	"STATFS",	dissect_fh2,	NULL },
	{ 0,	NULL,		NULL,		NULL }
};

int dissect_fh3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree);
int dissect_nfs3_getattr_call(const u_char *pd, int offset, frame_data *fd, proto_tree *tree);


const vsff nfs3_proc[] = {
	{ 0,	"NULL",		NULL,		NULL },
	{ 1,	"GETATTR",	dissect_nfs3_getattr_call,	NULL },
	{ 2,	"SETATTR",	dissect_fh3,	NULL },
	{ 3,	"LOOKUP",	dissect_fh3,	NULL },
	{ 4,	"ACCESS",	dissect_fh3,	NULL },
	{ 5,	"READLINK",	dissect_fh3,	NULL },
	{ 6,	"READ",		dissect_fh3,	NULL },
	{ 7,	"WRITE",	dissect_fh3,	NULL },
	{ 8,	"CREATE",	dissect_fh3,	NULL },
	{ 9,	"MKDIR",	dissect_fh3,	NULL },
	{ 10,	"SYMLINK",	dissect_fh3,	NULL },
	{ 11,	"MKNOD",	dissect_fh3,	NULL },
	{ 12,	"REMOVE",	dissect_fh3,	NULL },
	{ 13,	"RMDIR",	dissect_fh3,	NULL },
	{ 14,	"RENAME",	dissect_fh3,	NULL },
	{ 15,	"LINK",		dissect_fh3,	NULL },
	{ 16,	"READDIR",	dissect_fh3,	NULL },
	{ 17,	"READDIRPLUS",	dissect_fh3,	NULL },
	{ 18,	"FSSTAT",	dissect_fh3,	NULL },
	{ 19,	"FSINFO",	dissect_fh3,	NULL },
	{ 20,	"PATHCONF",	dissect_fh3,	NULL },
	{ 21,	"COMMIT",	dissect_fh3,	NULL },
	{ 0,	NULL,		NULL,		NULL }
};


int
dissect_fh2(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_item* fitem;
	proto_tree* ftree = NULL;

	if (tree) {
		fitem = proto_tree_add_text(tree, offset, FHSIZE,
			"file handle");
		if (fitem)
			ftree = proto_item_add_subtree(fitem, ETT_NFS2_FH);
	}

	if (ftree) {
		proto_tree_add_text(ftree,offset+0,FHSIZE,
					"opaque data");
	}
	offset += FHSIZE;
	return offset;
}

int
dissect_fh3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	guint fh_len;
	guint fh_len_full;
	proto_item* fitem;
	proto_tree* ftree = NULL;

	fh_len = EXTRACT_UINT(pd, offset+0);
	fh_len_full = roundup(fh_len);
	
	if (tree) {
		fitem = proto_tree_add_text(tree, offset, 4+fh_len_full,
			"file handle");
		if (fitem)
			ftree = proto_item_add_subtree(fitem, ETT_NFS3_FH);
	}

	if (ftree) {
		proto_tree_add_text(ftree,offset+0,4,
					"length: %d", fh_len);
		proto_tree_add_text(ftree,offset+4,fh_len,
					"opaque data");
	}
	offset += 4 + fh_len_full;
	return offset;
}


/* In fact, this routine serves only as a place to copy some ideas for
more complicated dissectors. */

int
dissect_nfs3_getattr_call(const u_char* pd, int offset, frame_data* fd, proto_tree* tree)
{
	offset = dissect_fh3(pd, offset, fd, tree);
	return offset;
}

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

