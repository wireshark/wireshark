/* packet-mount.c
 * Routines for mount dissection
 *
 * $Id: packet-mount.c,v 1.8 1999/11/29 11:52:40 girlich Exp $
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
#include "packet-mount.h"
#include "packet-nfs.h"


static int proto_mount = -1;
static int hf_mount_path = -1;
static int hf_mount_status = -1;
static int hf_mount_pathconf_link_max = -1;
static int hf_mount_pathconf_max_canon = -1;
static int hf_mount_pathconf_max_input = -1;
static int hf_mount_pathconf_name_max = -1;
static int hf_mount_pathconf_path_max = -1;
static int hf_mount_pathconf_pipe_buf = -1;
static int hf_mount_pathconf_vdisable = -1;
static int hf_mount_pathconf_mask = -1;
static int hf_mount_pathconf_error_all = -1;
static int hf_mount_pathconf_error_link_max = -1;
static int hf_mount_pathconf_error_max_canon = -1;
static int hf_mount_pathconf_error_max_input = -1;
static int hf_mount_pathconf_error_name_max = -1;
static int hf_mount_pathconf_error_path_max = -1;
static int hf_mount_pathconf_error_pipe_buf = -1;
static int hf_mount_pathconf_chown_restricted = -1;
static int hf_mount_pathconf_no_trunc = -1;
static int hf_mount_pathconf_error_vdisable = -1;
static int hf_mount_flavors = -1;
static int hf_mount_flavor = -1;

static gint ett_mount = -1;
static gint ett_mount_pathconf_mask = -1;


/* RFC 1094, Page 24 */
static int
dissect_fhstatus(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	guint32 status;

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	status = EXTRACT_UINT(pd, offset+0);
	if (tree) {
		proto_tree_add_item(tree, hf_mount_status, offset, 4, status);
	}
	offset += 4;

	switch (status) {
		case 0:
			offset = dissect_fhandle(pd,offset,fd,tree,"fhandle");
		break;
		default:
			/* void */
		break;
	}

	return offset;
}


static int
dissect_mount_dirpath_call(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree)
{
	if ( tree )
	{
		offset = dissect_rpc_string(pd,offset,fd,tree,hf_mount_path);
	}
	
	return offset;
}


/* RFC 1094, Page 25,26 */
static int
dissect_mount_mnt_reply(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree)
{
	offset = dissect_fhstatus(pd, offset, fd, tree);

	return offset;
}


#define	OFFS_MASK	32	/* offset of the "pc_mask" field */

#define	PC_ERROR_ALL		0x0001
#define	PC_ERROR_LINK_MAX	0x0002
#define	PC_ERROR_MAX_CANON	0x0004
#define	PC_ERROR_MAX_INPUT	0x0008
#define	PC_ERROR_NAME_MAX	0x0010
#define	PC_ERROR_PATH_MAX	0x0020
#define	PC_ERROR_PIPE_BUF	0x0040
#define	PC_CHOWN_RESTRICTED	0x0080
#define	PC_NO_TRUNC		0x0100
#define	PC_ERROR_VDISABLE	0x0200

static const true_false_string tos_error_all = {
  "All info invalid",
  "Some or all info valid"
};

static const true_false_string tos_error_link_max = {
  "LINK_MAX invalid",
  "LINK_MAX valid"
};

static const true_false_string tos_error_max_canon = {
  "MAX_CANON invalid",
  "MAX_CANON valid"
};

static const true_false_string tos_error_max_input = {
  "MAX_INPUT invalid",
  "MAX_INPUT valid"
};

static const true_false_string tos_error_name_max = {
  "NAME_MAX invalid",
  "NAME_MAX valid"
};

static const true_false_string tos_error_path_max = {
  "PATH_MAX invalid",
  "PATH_MAX valid"
};

static const true_false_string tos_error_pipe_buf = {
  "PIPE_BUF invalid",
  "PIPE_BUF valid"
};

static const true_false_string tos_chown_restricted = {
  "Only a privileged user can change the ownership of a file",
  "Users may give away their own files"
};

static const true_false_string tos_no_trunc = {
  "File names that are too long will get an error",
  "File names that are too long will be truncated"
};

static const true_false_string tos_error_vdisable = {
  "VDISABLE invalid",
  "VDISABLE valid"
};

static int
dissect_mount_pathconf_reply(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree)
{
	guint32 pc_mask;
	proto_item *ti;
	proto_tree *mask_tree;

	/*
	 * Extract the mask first, so we know which other fields the
	 * server was able to return to us.
	 */
	if (!BYTES_ARE_IN_FRAME(offset + OFFS_MASK, 4))
		return offset;
	pc_mask = EXTRACT_UINT(pd, offset+OFFS_MASK) & 0xFFFF;

	if (!BYTES_ARE_IN_FRAME(offset + 0,4))
		return offset;
	if (!(pc_mask & (PC_ERROR_LINK_MAX|PC_ERROR_ALL))) {
		if (tree) {
			proto_tree_add_item(tree,
			    hf_mount_pathconf_link_max, offset, 4,
			    EXTRACT_UINT(pd, offset+0));
		}
	}
	offset += 4;

	if (!BYTES_ARE_IN_FRAME(offset,4))
		return offset;
	if (!(pc_mask & (PC_ERROR_MAX_CANON|PC_ERROR_ALL))) {
		if (tree) {
			proto_tree_add_item(tree,
			    hf_mount_pathconf_max_canon, offset + 2, 2,
			    (EXTRACT_UINT(pd, offset+0)) & 0xFFFF);
		}
	}
	
	offset += 4;

	if (!BYTES_ARE_IN_FRAME(offset,4))
		return offset;
	if (!(pc_mask & (PC_ERROR_MAX_INPUT|PC_ERROR_ALL))) {
		if (tree) {
			proto_tree_add_item(tree,
			    hf_mount_pathconf_max_input, offset + 2, 2,
			    (EXTRACT_UINT(pd, offset+0)) & 0xFFFF);
		}
	}
	offset += 4;

	if (!BYTES_ARE_IN_FRAME(offset,4))
		return offset;
	if (!(pc_mask & (PC_ERROR_NAME_MAX|PC_ERROR_ALL))) {
		if (tree) {
			proto_tree_add_item(tree,
			    hf_mount_pathconf_name_max, offset + 2, 2,
			    (EXTRACT_UINT(pd, offset+0)) & 0xFFFF);
		}
	}
	offset += 4;

	if (!BYTES_ARE_IN_FRAME(offset,4))
		return offset;
	if (!(pc_mask & (PC_ERROR_PATH_MAX|PC_ERROR_ALL))) {
		if (tree) {
			proto_tree_add_item(tree,
			    hf_mount_pathconf_path_max, offset + 2, 2,
			    (EXTRACT_UINT(pd, offset+0)) & 0xFFFF);
		}
	}
	offset += 4;

	if (!BYTES_ARE_IN_FRAME(offset,4))
		return offset;
	if (!(pc_mask & (PC_ERROR_PIPE_BUF|PC_ERROR_ALL))) {
		if (tree) {
			proto_tree_add_item(tree,
			    hf_mount_pathconf_pipe_buf, offset + 2, 2,
			    (EXTRACT_UINT(pd, offset+0)) & 0xFFFF);
		}
	}
	offset += 4;

	offset += 4;	/* skip "pc_xxx" pad field */

	if (!BYTES_ARE_IN_FRAME(offset,4))
		return offset;
	if (!(pc_mask & (PC_ERROR_VDISABLE|PC_ERROR_ALL))) {
		if (tree) {
			proto_tree_add_item(tree,
			    hf_mount_pathconf_vdisable, offset + 3, 1,
			    (EXTRACT_UINT(pd, offset+0)) & 0xFF);
		}
	}
	offset += 4;

	if (tree) {
		ti = proto_tree_add_item(tree, hf_mount_pathconf_mask,
		    offset + 2, 2, pc_mask);
		mask_tree = proto_item_add_subtree(ti, ett_mount_pathconf_mask);
		proto_tree_add_item(mask_tree, hf_mount_pathconf_error_all,
		    offset + 2, 2, pc_mask);
		proto_tree_add_item(mask_tree, hf_mount_pathconf_error_link_max,
		    offset + 2, 2, pc_mask);
		proto_tree_add_item(mask_tree, hf_mount_pathconf_error_max_canon,
		    offset + 2, 2, pc_mask);
		proto_tree_add_item(mask_tree, hf_mount_pathconf_error_max_input,
		    offset + 2, 2, pc_mask);
		proto_tree_add_item(mask_tree, hf_mount_pathconf_error_name_max,
		    offset + 2, 2, pc_mask);
		proto_tree_add_item(mask_tree, hf_mount_pathconf_error_path_max,
		    offset + 2, 2, pc_mask);
		proto_tree_add_item(mask_tree, hf_mount_pathconf_error_pipe_buf,
		    offset + 2, 2, pc_mask);
		proto_tree_add_item(mask_tree, hf_mount_pathconf_chown_restricted,
		    offset + 2, 2, pc_mask);
		proto_tree_add_item(mask_tree, hf_mount_pathconf_no_trunc,
		    offset + 2, 2, pc_mask);
		proto_tree_add_item(mask_tree, hf_mount_pathconf_error_vdisable,
		    offset + 2, 2, pc_mask);
	}
	offset += 4;
	return offset;
}

/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: take the generic one. */

/* Mount protocol version 1, RFC 1094 */
static const vsff mount1_proc[] = {
    { 0, "NULL", NULL, NULL },
    { MOUNTPROC_MNT,        "MNT",      
		dissect_mount_dirpath_call, dissect_mount_mnt_reply },
    { MOUNTPROC_DUMP,       "DUMP",
		NULL, NULL },
    { MOUNTPROC_UMNT,      "UMNT",        
		dissect_mount_dirpath_call, NULL },
    { MOUNTPROC_UMNTALL,   "UMNTALL",
		NULL, NULL },
    { MOUNTPROC_EXPORT,    "EXPORT",
		NULL, NULL },
    { MOUNTPROC_EXPORTALL, "EXPORTALL",
		NULL, NULL },
    { 0, NULL, NULL, NULL }
};
/* end of mount version 1 */


/* Mount protocol version 2, private communication from somebody at Sun;
   mount V2 is V1 plus MOUNTPROC_PATHCONF to fetch information for the
   POSIX "pathconf()" call. */
static const vsff mount2_proc[] = {
    { 0, "NULL", NULL, NULL },
    { MOUNTPROC_MNT,        "MNT",      
		dissect_mount_dirpath_call, dissect_mount_mnt_reply },
    { MOUNTPROC_DUMP,       "DUMP",
		NULL, NULL },
    { MOUNTPROC_UMNT,      "UMNT",        
		dissect_mount_dirpath_call, NULL },
    { MOUNTPROC_UMNTALL,   "UMNTALL",
		NULL, NULL },
    { MOUNTPROC_EXPORT,    "EXPORT",
		NULL, NULL },
    { MOUNTPROC_EXPORTALL, "EXPORTALL",
		NULL, NULL },
    { MOUNTPROC_EXPORTALL, "EXPORTALL",
		NULL, NULL },
    { MOUNTPROC_PATHCONF,  "PATHCONF",
		dissect_mount_dirpath_call, dissect_mount_pathconf_reply },
    { 0, NULL, NULL, NULL }
};
/* end of mount version 2 */


/* RFC 1813, Page 107 */
static const value_string mount3_mountstat3[] = 
{
	{	0,	"OK" },
	{	1,	"ERR_PERM" },
	{	2,	"ERR_NOENT" },
	{	5,	"ERR_IO" },
	{	13,	"ERR_ACCESS" },
	{	20,	"ERR_NOTDIR" },
	{	22,	"ERR_INVAL" },
	{	63,	"ERR_NAMETOOLONG" },
	{	10004,	"ERR_NOTSUPP" },
	{	10006,	"ERR_SERVERFAULT" },
	{	0,	NULL }
};


/* RFC 1813, Page 107 */
static int
dissect_mountstat3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
	int hfindex, guint32* status)
{
	guint32 mountstat3;

	if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
	mountstat3 = EXTRACT_UINT(pd, offset+0);

	if (tree) {
		proto_tree_add_item(tree, hfindex, offset, 4, mountstat3);
	}
	
	offset += 4;
	*status = mountstat3;
	return offset;
}


/* RFC 1831, Page 109 */
static int
dissect_mount3_mnt_reply(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree)
{
	guint32 status;
	guint32 auth_flavors;
	guint32 auth_flavor;
	guint32 auth_flavor_i;
	
	offset = dissect_mountstat3(pd, offset, fd, tree, hf_mount_status, &status);
	switch (status) {
		case 0:
			offset = dissect_nfs_fh3(pd,offset,fd,tree,"fhandle");
			if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
			auth_flavors = EXTRACT_UINT(pd,offset+0);
			proto_tree_add_item(tree,hf_mount_flavors,
				offset, 4, auth_flavors);
			offset += 4;
			for (auth_flavor_i = 0 ; auth_flavor_i < hf_mount_flavors ; auth_flavor_i++) {
				if (!BYTES_ARE_IN_FRAME(offset,4)) return offset;
				auth_flavor = EXTRACT_UINT(pd,offset+0);
				proto_tree_add_item(tree,hf_mount_flavor,
					offset, 4, auth_flavor);
				offset += 4;
			}
		break;
		default:
			/* void */
		break;
	}
	
	return offset;
}

/* Mount protocol version 3, RFC 1813 */
static const vsff mount3_proc[] = {
	{ 0, "NULL", NULL, NULL },
	{ MOUNTPROC_MNT, "MNT",
		dissect_mount_dirpath_call, dissect_mount3_mnt_reply },
	{ MOUNTPROC_DUMP, "DUMP",
		NULL, NULL },
	{ MOUNTPROC_UMNT, "UMNT",
		dissect_mount_dirpath_call, NULL },
	{ MOUNTPROC_UMNTALL, "UMNTALL",
		NULL, NULL },
	{ MOUNTPROC_EXPORT, "EXPORT",
		NULL, NULL },
	{ 0, NULL, NULL, NULL }
};
/* end of Mount protocol version 3 */


void
proto_register_mount(void)
{
	static hf_register_info hf[] = {
		{ &hf_mount_path, {
			"Path", "mount.path", FT_STRING, BASE_DEC,
			NULL, 0, "Path" }},
		{ &hf_mount_status, {
			"Status", "mount.status", FT_UINT32, BASE_DEC,
			VALS(mount3_mountstat3), 0, "Status" }},
		{ &hf_mount_pathconf_link_max, {
			"Maximum number of links to a file", "mount.pathconf.link_max",
			FT_UINT32, BASE_DEC,
			NULL, 0, "Maximum number of links allowed to a file" }},
		{ &hf_mount_pathconf_max_canon, {
			"Maximum terminal input line length", "mount.pathconf.max_canon",
			FT_UINT16, BASE_DEC,
			NULL, 0, "Max tty input line length" }},
		{ &hf_mount_pathconf_max_input, {
			"Terminal input buffer size", "mount.pathconf.max_input",
			FT_UINT16, BASE_DEC,
			NULL, 0, "Terminal input buffer size" }},
		{ &hf_mount_pathconf_name_max, {
			"Maximum file name length", "mount.pathconf.name_max",
			FT_UINT16, BASE_DEC,
			NULL, 0, "Maximum file name length" }},
		{ &hf_mount_pathconf_path_max, {
			"Maximum path name length", "mount.pathconf.path_max",
			FT_UINT16, BASE_DEC,
			NULL, 0, "Maximum path name length" }},
		{ &hf_mount_pathconf_pipe_buf, {
			"Pipe buffer size", "mount.pathconf.pipe_buf",
			FT_UINT16, BASE_DEC,
			NULL, 0, "Maximum amount of data that can be written atomically to a pipe" }},
		{ &hf_mount_pathconf_vdisable, {
			"VDISABLE character", "mount.pathconf.pipe_buf",
			FT_UINT8, BASE_HEX,
			NULL, 0, "Character value to disable a terminal special character" }},
		{ &hf_mount_pathconf_mask, {
			"Reply error/status bits", "mount.pathconf.mask",
			FT_UINT16, BASE_HEX,
			NULL, 0, "Bit mask with error and status bits" }},
		{ &hf_mount_pathconf_error_all, {
			"ERROR_ALL",	"mount.pathconf.mask.error_all",
			FT_BOOLEAN, 16, TFS(&tos_error_all),
			PC_ERROR_ALL, "" }},
		{ &hf_mount_pathconf_error_link_max, {
			"ERROR_LINK_MAX", "mount.pathconf.mask.error_link_max",
			FT_BOOLEAN, 16, TFS(&tos_error_link_max),
			PC_ERROR_LINK_MAX, "" }},
		{ &hf_mount_pathconf_error_max_canon, {
			"ERROR_MAX_CANON", "mount.pathconf.mask.error_max_canon",
			FT_BOOLEAN, 16, TFS(&tos_error_max_canon),
			PC_ERROR_MAX_CANON, "" }},
		{ &hf_mount_pathconf_error_max_input, {
			"ERROR_MAX_INPUT", "mount.pathconf.mask.error_max_input",
			FT_BOOLEAN, 16, TFS(&tos_error_max_input),
			PC_ERROR_MAX_INPUT, "" }},
		{ &hf_mount_pathconf_error_name_max, {
			"ERROR_NAME_MAX", "mount.pathconf.mask.error_name_max",
			FT_BOOLEAN, 16, TFS(&tos_error_name_max),
			PC_ERROR_NAME_MAX, "" }},
		{ &hf_mount_pathconf_error_path_max, {
			"ERROR_PATH_MAX", "mount.pathconf.mask.error_path_max",
			FT_BOOLEAN, 16, TFS(&tos_error_path_max),
			PC_ERROR_PATH_MAX, "" }},
		{ &hf_mount_pathconf_error_pipe_buf, {
			"ERROR_PIPE_BUF", "mount.pathconf.mask.error_pipe_buf",
			FT_BOOLEAN, 16, TFS(&tos_error_pipe_buf),
			PC_ERROR_PIPE_BUF, "" }},
		{ &hf_mount_pathconf_chown_restricted, {
			"CHOWN_RESTRICTED", "mount.pathconf.mask.chown_restricted",
			FT_BOOLEAN, 16, TFS(&tos_chown_restricted),
			PC_CHOWN_RESTRICTED, "" }},
		{ &hf_mount_pathconf_no_trunc, {
			"NO_TRUNC", "mount.pathconf.mask.no_trunc",
			FT_BOOLEAN, 16, TFS(&tos_no_trunc),
			PC_NO_TRUNC, "" }},
		{ &hf_mount_pathconf_error_vdisable, {
			"ERROR_VDISABLE", "mount.pathconf.mask.error_vdisable",
			FT_BOOLEAN, 16, TFS(&tos_error_vdisable),
			PC_ERROR_VDISABLE, "" }},
		{ &hf_mount_flavors, {
			"Flavors", "mount.flavors", FT_UINT32, BASE_DEC,
			NULL, 0, "Flavors" }},
		{ &hf_mount_flavor, {
			"Flavor", "mount.flavor", FT_UINT32, BASE_DEC,
			VALS(rpc_auth_flavor), 0, "Flavor" }},
	};
	static gint *ett[] = {
		&ett_mount,
		&ett_mount_pathconf_mask,
	};

	proto_mount = proto_register_protocol("Mount Service", "mount");
	proto_register_field_array(proto_mount, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register the protocol as RPC */
	rpc_init_prog(proto_mount, MOUNT_PROGRAM, ett_mount);
	/* Register the procedure tables */
	rpc_init_proc_table(MOUNT_PROGRAM, 1, mount1_proc);
	rpc_init_proc_table(MOUNT_PROGRAM, 2, mount2_proc);
	rpc_init_proc_table(MOUNT_PROGRAM, 3, mount3_proc);
}
