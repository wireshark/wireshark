/* packet-mount.c
 * Routines for mount dissection
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

#include <string.h>

#include <epan/exceptions.h>
#include <epan/to_str.h>
#include "packet-rpc.h"
#include "packet-mount.h"
#include "packet-nfs.h"

void proto_register_mount(void);
void proto_reg_handoff_mount(void);

static int proto_mount = -1;
static int proto_sgi_mount = -1;
static int hf_mount_procedure_v1 = -1;
static int hf_mount_procedure_v2 = -1;
static int hf_mount_procedure_v3 = -1;
static int hf_sgi_mount_procedure_v1 = -1;
static int hf_mount_path = -1;
static int hf_mount3_status = -1;
static int hf_mount_mountlist_hostname = -1;
static int hf_mount_mountlist_directory = -1;
static int hf_mount_mountlist = -1;
static int hf_mount_groups_group = -1;
static int hf_mount_groups = -1;
static int hf_mount_exportlist_directory = -1;
static int hf_mount_exportlist = -1;
static int hf_mount_has_options = -1;
static int hf_mount_options = -1;
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
static int hf_mount_statvfs_bsize = -1;
static int hf_mount_statvfs_frsize = -1;
static int hf_mount_statvfs_blocks = -1;
static int hf_mount_statvfs_bfree = -1;
static int hf_mount_statvfs_bavail = -1;
static int hf_mount_statvfs_files = -1;
static int hf_mount_statvfs_ffree = -1;
static int hf_mount_statvfs_favail = -1;
static int hf_mount_statvfs_fsid = -1;
static int hf_mount_statvfs_basetype = -1;
static int hf_mount_statvfs_flag = -1;
static int hf_mount_statvfs_flag_rdonly = -1;
static int hf_mount_statvfs_flag_nosuid = -1;
static int hf_mount_statvfs_flag_notrunc = -1;
static int hf_mount_statvfs_flag_nodev = -1;
static int hf_mount_statvfs_flag_grpid = -1;
static int hf_mount_statvfs_flag_local = -1;
static int hf_mount_statvfs_namemax = -1;
static int hf_mount_statvfs_fstr = -1;
static int hf_mount_flavors = -1;
static int hf_mount_flavor = -1;

static gint ett_mount = -1;
static gint ett_mount_mountlist = -1;
static gint ett_mount_groups = -1;
static gint ett_mount_exportlist = -1;
static gint ett_mount_pathconf_mask = -1;
static gint ett_mount_statvfs_flag = -1;

#define MAX_GROUP_NAME_LIST 128
static char group_name_list[MAX_GROUP_NAME_LIST];
static int  group_names_len;

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


/* RFC 1094, Page 24 */
/* This function dissects fhstatus for v1 and v2 of the mount protocol.
 * Formally, hf_mount3_status only define the status codes returned by version
 * 3 of the protocol.
 * Though not formally defined in the standard, we use the same
 * value-to-string mappings as version 3 since we belive that this mapping
 * is consistant with most v1 and v2 implementations.
 */
static int
dissect_fhstatus(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, rpc_call_info_value* civ)
{
	gint32 status;

	status=tvb_get_ntohl(tvb,offset);
	offset = dissect_rpc_uint32(tvb,tree,hf_mount3_status,offset);

	switch (status) {
		case 0:
			offset = dissect_fhandle(tvb,offset,pinfo,tree,"fhandle", NULL, civ);
		break;
		default:
			/* void */
			col_append_fstr(
					pinfo->cinfo, COL_INFO, " Error:%s",
					val_to_str(status, mount3_mountstat3,
					    "Unknown (0x%08X)"));
		break;
	}

	return offset;
}


static int
dissect_mount_dirpath_call(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, void* data)
{
	const char *mountpoint=NULL;

	if((!pinfo->fd->flags.visited) && nfs_file_name_snooping){
		rpc_call_info_value *civ=(rpc_call_info_value *)data;

		if(civ->request && (civ->proc==1)){
			const gchar *host;
			unsigned char *name;
			guint32 len;
			unsigned char *ptr;

			host=ip_to_str((const guint8 *)pinfo->dst.data);
			len=tvb_get_ntohl(tvb, offset);
                        if (len >= ITEM_LABEL_LENGTH)
                                THROW(ReportedBoundsError);

			name=(unsigned char *)g_malloc(strlen(host)+1+len+1+200);
			ptr=name;
			memcpy(ptr, host, strlen(host));
			ptr+=strlen(host);
			*ptr++=':';
			tvb_memcpy(tvb, ptr, offset+4, len);
			ptr+=len;
			*ptr=0;

			nfs_name_snoop_add_name(civ->xid, tvb, -1, (gint)strlen(name), 0, 0, name);
		}
	}

	offset = dissect_rpc_string(tvb,tree,hf_mount_path,offset,&mountpoint);
	col_append_fstr(pinfo->cinfo, COL_INFO," %s", mountpoint);

	return offset;
}


/* RFC 1094, Page 25,26 */
static int
dissect_mount1_mnt_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, void* data)
{
	offset = dissect_fhstatus(tvb,offset,pinfo,tree,(rpc_call_info_value*)data);

	return offset;
}



/* RFC 1094, Page 26 */
/* RFC 1813, Page 110 */
static int
dissect_mountlist(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	proto_item* lock_item = NULL;
	proto_tree* lock_tree = NULL;
	int old_offset = offset;
	const char* hostname;
	const char* directory;

	if (tree) {
		lock_item = proto_tree_add_item(tree, hf_mount_mountlist, tvb,
					offset, -1, ENC_NA);
		if (lock_item)
			lock_tree = proto_item_add_subtree(lock_item, ett_mount_mountlist);
	}

	offset = dissect_rpc_string(tvb, lock_tree,
			hf_mount_mountlist_hostname, offset, &hostname);
	offset = dissect_rpc_string(tvb, lock_tree,
			hf_mount_mountlist_directory, offset, &directory);

	if (lock_item) {
		/* now we have a nicer string */
		proto_item_set_text(lock_item, "Mount List Entry: %s:%s", hostname, directory);
		/* now we know, that mountlist is shorter */
		proto_item_set_len(lock_item, offset - old_offset);
	}

	return offset;
}


/* RFC 1094, Page 26 */
/* RFC 1813, Page 110 */
static int
dissect_mount_dump_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	offset = dissect_rpc_list(tvb, pinfo, tree, offset,
		dissect_mountlist, NULL);

	return offset;
}



/* RFC 1094, Page 26 */
/* RFC 1813, Page 110 */
static int
dissect_group(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int str_len;

	if (group_names_len < MAX_GROUP_NAME_LIST - 5) {
		str_len=tvb_get_nstringz(tvb,offset+4,
			MAX_GROUP_NAME_LIST-5-group_names_len,
			group_name_list+group_names_len);
		if((group_names_len>=(MAX_GROUP_NAME_LIST-5))||(str_len<0)){
			g_snprintf(group_name_list+(MAX_GROUP_NAME_LIST-5), 5, "...");
			group_names_len=MAX_GROUP_NAME_LIST - 1;
		} else {
			group_names_len+=str_len;
			group_name_list[group_names_len++]=' ';
		}
		group_name_list[group_names_len]=0;
	}

	offset = dissect_rpc_string(tvb, tree,
			hf_mount_groups_group, offset, NULL);

	return offset;
}


/* RFC 1094, Page 26 */
/* RFC 1813, Page 113 */
static int
dissect_exportlist(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item* exportlist_item = NULL;
	proto_tree* exportlist_tree = NULL;
	int old_offset = offset;
	int groups_offset;
	proto_item* groups_item = NULL;
	proto_item* groups_tree = NULL;
	const char* directory;

	group_name_list[0]=0;
	group_names_len=0;
	if (tree) {
		exportlist_item = proto_tree_add_item(tree, hf_mount_exportlist, tvb, offset, -1, ENC_NA);
		exportlist_tree = proto_item_add_subtree(exportlist_item, ett_mount_exportlist);
	}

	offset = dissect_rpc_string(tvb, exportlist_tree,
			hf_mount_exportlist_directory, offset, &directory);
	groups_offset = offset;

	if (tree) {
		groups_item = proto_tree_add_item(exportlist_tree, hf_mount_groups, tvb,
					offset, -1, ENC_NA);
		if (groups_item)
			groups_tree = proto_item_add_subtree(groups_item, ett_mount_groups);
	}

	offset = dissect_rpc_list(tvb, pinfo, groups_tree, offset,
		dissect_group, NULL);
	if (groups_item) {
		/* mark empty lists */
		if (offset - groups_offset == 4) {
			proto_item_set_text(groups_item, "Groups: empty");
		}

		/* now we know, that groups is shorter */
		proto_item_set_len(groups_item, offset - groups_offset);
	}

	if (exportlist_item) {
		/* now we have a nicer string */
		proto_item_set_text(exportlist_item, "Export List Entry: %s -> %s", directory,group_name_list);
		/* now we know, that exportlist is shorter */
		proto_item_set_len(exportlist_item, offset - old_offset);
	}

	return offset;
}


/* RFC 1094, Page 26 */
/* RFC 1813, Page 113 */
static int
dissect_mount_export_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	offset = dissect_rpc_list(tvb, pinfo, tree, offset,
		dissect_exportlist, NULL);

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
dissect_mount_pathconf_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	guint32 pc_mask;
	proto_item *lock_item;
	proto_tree *lock_tree;

	/*
	 * Extract the mask first, so we know which other fields the
	 * server was able to return to us.
	 */
	pc_mask = tvb_get_ntohl(tvb, offset+OFFS_MASK) & 0xffff;
	if (!(pc_mask & (PC_ERROR_LINK_MAX|PC_ERROR_ALL))) {
		if (tree) {
			dissect_rpc_uint32(tvb,tree,hf_mount_pathconf_link_max,offset);
		}
	}
	offset += 4;

	if (!(pc_mask & (PC_ERROR_MAX_CANON|PC_ERROR_ALL))) {
		if (tree) {
			proto_tree_add_item(tree,
				hf_mount_pathconf_max_canon,tvb,offset+2,2,
				tvb_get_ntohs(tvb,offset)&0xffff);
		}
	}
	offset += 4;

	if (!(pc_mask & (PC_ERROR_MAX_INPUT|PC_ERROR_ALL))) {
		if (tree) {
			proto_tree_add_item(tree,
				hf_mount_pathconf_max_input,tvb,offset+2,2,
				tvb_get_ntohs(tvb,offset)&0xffff);
		}
	}
	offset += 4;

	if (!(pc_mask & (PC_ERROR_NAME_MAX|PC_ERROR_ALL))) {
		if (tree) {
			proto_tree_add_item(tree,
				hf_mount_pathconf_name_max,tvb,offset+2,2,
				tvb_get_ntohs(tvb,offset)&0xffff);
		}
	}
	offset += 4;

	if (!(pc_mask & (PC_ERROR_PATH_MAX|PC_ERROR_ALL))) {
		if (tree) {
			proto_tree_add_item(tree,
				hf_mount_pathconf_path_max,tvb,offset+2,2,
				tvb_get_ntohs(tvb,offset)&0xffff);
		}
	}
	offset += 4;

	if (!(pc_mask & (PC_ERROR_PIPE_BUF|PC_ERROR_ALL))) {
		if (tree) {
			proto_tree_add_item(tree,
				hf_mount_pathconf_pipe_buf,tvb,offset+2,2,
				tvb_get_ntohs(tvb,offset)&0xffff);
		}
	}
	offset += 4;

	offset += 4;	/* skip "pc_xxx" pad field */

	if (!(pc_mask & (PC_ERROR_VDISABLE|PC_ERROR_ALL))) {
		if (tree) {
			proto_tree_add_item(tree,
				hf_mount_pathconf_vdisable,tvb,offset+3,1,
				tvb_get_ntohs(tvb,offset)&0xffff);
		}
	}
	offset += 4;


	if (tree) {
		lock_item = proto_tree_add_item(tree, hf_mount_pathconf_mask, tvb,
					offset+2, 2, ENC_BIG_ENDIAN);

		lock_tree = proto_item_add_subtree(lock_item, ett_mount_pathconf_mask);
		proto_tree_add_boolean(lock_tree, hf_mount_pathconf_error_all, tvb,
		    offset + 2, 2, pc_mask);

		proto_tree_add_boolean(lock_tree, hf_mount_pathconf_error_link_max, tvb,
		    offset + 2, 2, pc_mask);
		proto_tree_add_boolean(lock_tree, hf_mount_pathconf_error_max_canon, tvb,
		    offset + 2, 2, pc_mask);
		proto_tree_add_boolean(lock_tree, hf_mount_pathconf_error_max_input, tvb,
		    offset + 2, 2, pc_mask);
		proto_tree_add_boolean(lock_tree, hf_mount_pathconf_error_name_max, tvb,
		    offset + 2, 2, pc_mask);
		proto_tree_add_boolean(lock_tree, hf_mount_pathconf_error_path_max, tvb,
		    offset + 2, 2, pc_mask);
		proto_tree_add_boolean(lock_tree, hf_mount_pathconf_error_pipe_buf, tvb,
		    offset + 2, 2, pc_mask);
		proto_tree_add_boolean(lock_tree, hf_mount_pathconf_chown_restricted, tvb,
		    offset + 2, 2, pc_mask);
		proto_tree_add_boolean(lock_tree, hf_mount_pathconf_no_trunc, tvb,
		    offset + 2, 2, pc_mask);
		proto_tree_add_boolean(lock_tree, hf_mount_pathconf_error_vdisable, tvb,
		    offset + 2, 2, pc_mask);
	}

	offset += 8;
	return offset;
}


/* RFC 1813, Page 107 */
static int
dissect_mountstat3(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree, int offset, int hfindex, guint32 *status)
{
	guint32 mountstat3;

	mountstat3 = tvb_get_ntohl(tvb, offset);
	if(mountstat3){
		col_append_fstr(
				pinfo->cinfo, COL_INFO, " Error:%s",
				val_to_str(mountstat3, mount3_mountstat3,
				    "Unknown (0x%08X)"));
	}

	offset = dissect_rpc_uint32(tvb,tree,hfindex,offset);
	*status = mountstat3;
	return offset;
}

/* RFC 1831, Page 109 */
static int
dissect_mount3_mnt_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, void* data)
{
	guint32 status;
	guint32 auth_flavors;
	guint32 auth_flavor;
	guint32 auth_flavor_i;

	offset = dissect_mountstat3(pinfo,tvb,tree,offset,hf_mount3_status,&status);

	switch (status) {
		case 0:
			offset = dissect_nfs3_fh(tvb,offset,pinfo,tree,"fhandle",NULL,(rpc_call_info_value*)data);

			auth_flavors = tvb_get_ntohl(tvb, offset);
			proto_tree_add_uint(tree,hf_mount_flavors, tvb,
				offset, 4, auth_flavors);
			offset += 4;
			for (auth_flavor_i = 0 ; auth_flavor_i < auth_flavors ; auth_flavor_i++) {
				auth_flavor = tvb_get_ntohl(tvb, offset);
				proto_tree_add_uint(tree,hf_mount_flavor, tvb,
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

static int
dissect_sgi_exportlist(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	proto_item* exportlist_item = NULL;
	proto_tree* exportlist_tree = NULL;
	int old_offset = offset;
	const char* directory, *options;

	if (tree) {
		exportlist_item = proto_tree_add_item(tree, hf_mount_exportlist,
					tvb, offset, -1, ENC_NA);
		if (exportlist_item)
			exportlist_tree = proto_item_add_subtree(exportlist_item,
						ett_mount_exportlist);
	}

	offset = dissect_rpc_string(tvb, exportlist_tree,
			hf_mount_exportlist_directory, offset, &directory);

	offset = dissect_rpc_bool(tvb, exportlist_tree,
			hf_mount_has_options, offset);

	offset = dissect_rpc_string(tvb, exportlist_tree, hf_mount_options,
			 offset, &options);

	if (exportlist_item) {
		/* now we have a nicer string */
		proto_item_set_text(exportlist_item,
			"Export List Entry: %s %s", directory,
			options);
		/* now we know, that exportlist is shorter */
		proto_item_set_len(exportlist_item, offset - old_offset);
	}

	return offset;
}

static int
dissect_mount_exportlist_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	offset = dissect_rpc_list(tvb, pinfo, tree, offset,
		dissect_sgi_exportlist, NULL);

	return offset;
}

#define ST_RDONLY	0x00000001
#define ST_NOSUID	0x00000002
#define ST_NOTRUNC	0x00000004
#define ST_NODEV	0x20000000
#define ST_GRPID	0x40000000
#define ST_LOCAL	0x80000000

static const true_false_string tos_st_rdonly = {
	"Read-only file system",
	"Read/Write file system"
};

static const true_false_string tos_st_nosuid = {
	"Does not support setuid/setgid semantics",
	"Supports setuid/setgid semantics"
};

static const true_false_string tos_st_notrunc = {
	"Does not truncate filenames longer than NAME_MAX",
	"Truncates filenames longer than NAME_MAX"
};

static const true_false_string tos_st_nodev = {
	"Disallows opening of device files",
	"Allows opening of device files"
};

static const true_false_string tos_st_grpid = {
	"Group ID assigned from directory",
	"Group ID not assigned from directory"
};

static const true_false_string tos_st_local = {
	"File system is local",
	"File system is not local"
};

static int
dissect_mount_statvfs_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	proto_item *flag_item;
	proto_tree *flag_tree;
 	guint32 statvfs_flags;

	statvfs_flags = tvb_get_ntohl(tvb, offset+52);
	if (tree) {
		dissect_rpc_uint32(tvb, tree, hf_mount_statvfs_bsize, offset);
	}
	offset += 4;
	if (tree) {
		dissect_rpc_uint32(tvb, tree, hf_mount_statvfs_frsize, offset);
	}
	offset += 4;
	if (tree) {
		dissect_rpc_uint32(tvb, tree, hf_mount_statvfs_blocks, offset);
	}
	offset += 4;
	if (tree) {
		dissect_rpc_uint32(tvb, tree, hf_mount_statvfs_bfree, offset);
	}
	offset += 4;
	if (tree) {
		dissect_rpc_uint32(tvb, tree, hf_mount_statvfs_bavail, offset);
	}
	offset += 4;
	if (tree) {
		dissect_rpc_uint32(tvb, tree, hf_mount_statvfs_files, offset);
	}
	offset += 4;
	if (tree) {
		dissect_rpc_uint32(tvb, tree, hf_mount_statvfs_ffree, offset);
	}
	offset += 4;
	if (tree) {
		dissect_rpc_uint32(tvb, tree, hf_mount_statvfs_favail, offset);
	}
	offset += 4;
	if (tree) {
		dissect_rpc_bytes(tvb, tree, hf_mount_statvfs_basetype, offset,
			16, TRUE, NULL);
	}
	offset += 16;
	if (tree) {
		dissect_rpc_bytes(tvb, tree, hf_mount_statvfs_fstr, offset,
			32, FALSE, NULL);
	}
	offset += 32;
	if (tree) {
		dissect_rpc_uint32(tvb, tree, hf_mount_statvfs_fsid, offset);
	}
	offset += 4;

	if (tree) {
		flag_item = proto_tree_add_item(tree, hf_mount_statvfs_flag,
				tvb, offset, 4, ENC_BIG_ENDIAN);
		if (flag_item) {
			flag_tree = proto_item_add_subtree(flag_item,
					ett_mount_statvfs_flag);
			proto_tree_add_boolean(flag_tree,
				hf_mount_statvfs_flag_rdonly, tvb, offset, 4,
				statvfs_flags);
			proto_tree_add_boolean(flag_tree,
				hf_mount_statvfs_flag_nosuid, tvb, offset, 4,
				statvfs_flags);
			proto_tree_add_boolean(flag_tree,
				hf_mount_statvfs_flag_notrunc, tvb, offset, 4,
				statvfs_flags);
			proto_tree_add_boolean(flag_tree,
				hf_mount_statvfs_flag_nodev, tvb, offset, 4,
				statvfs_flags);
			proto_tree_add_boolean(flag_tree,
				hf_mount_statvfs_flag_grpid, tvb, offset, 4,
				statvfs_flags);
			proto_tree_add_boolean(flag_tree,
				hf_mount_statvfs_flag_local, tvb, offset, 4,
				statvfs_flags);
		}
	}

	offset += 4;
	if (tree) {
		dissect_rpc_uint32(tvb, tree, hf_mount_statvfs_namemax, offset);
	}
	offset += 4;

	return offset;
}

/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: type of arguments is "void". */

/* Mount protocol version 1, RFC 1094 */
static const vsff mount1_proc[] = {
    { 0, "NULL", NULL, NULL },
    { MOUNTPROC_MNT,        "MNT",
		dissect_mount_dirpath_call, dissect_mount1_mnt_reply },
    { MOUNTPROC_DUMP,       "DUMP",
		NULL, dissect_mount_dump_reply },
    { MOUNTPROC_UMNT,      "UMNT",
		dissect_mount_dirpath_call, NULL },
    { MOUNTPROC_UMNTALL,   "UMNTALL",
		NULL, NULL },
    { MOUNTPROC_EXPORT,    "EXPORT",
		NULL, dissect_mount_export_reply },
    { MOUNTPROC_EXPORTALL, "EXPORTALL",
		NULL, dissect_mount_export_reply },
    { 0, NULL, NULL, NULL }
};
static const value_string mount1_proc_vals[] = {
    { 0, "NULL" },
    { MOUNTPROC_MNT,       "MNT" },
    { MOUNTPROC_DUMP,      "DUMP" },
    { MOUNTPROC_UMNT,      "UMNT" },
    { MOUNTPROC_UMNTALL,   "UMNTALL" },
    { MOUNTPROC_EXPORT,    "EXPORT" },
    { MOUNTPROC_EXPORTALL, "EXPORTALL" },
    { 0, NULL }
};
/* end of mount version 1 */


/* Mount protocol version 2, private communication from somebody at Sun;
   mount V2 is V1 plus MOUNTPROC_PATHCONF to fetch information for the
   POSIX "pathconf()" call. */
static const vsff mount2_proc[] = {
    { 0, "NULL", NULL, NULL },
    { MOUNTPROC_MNT,        "MNT",
		dissect_mount_dirpath_call, dissect_mount1_mnt_reply },
    { MOUNTPROC_DUMP,       "DUMP",
		NULL, dissect_mount_dump_reply },
    { MOUNTPROC_UMNT,      "UMNT",
		dissect_mount_dirpath_call, NULL },
    { MOUNTPROC_UMNTALL,   "UMNTALL",
		NULL, NULL },
    { MOUNTPROC_EXPORT,    "EXPORT",
		NULL, dissect_mount_export_reply },
    { MOUNTPROC_EXPORTALL, "EXPORTALL",
		NULL, dissect_mount_export_reply },
    { MOUNTPROC_PATHCONF,  "PATHCONF",
		dissect_mount_dirpath_call, dissect_mount_pathconf_reply },
    { 0, NULL, NULL, NULL }
};
static const value_string mount2_proc_vals[] = {
    { 0, "NULL" },
    { MOUNTPROC_MNT,       "MNT" },
    { MOUNTPROC_DUMP,      "DUMP" },
    { MOUNTPROC_UMNT,      "UMNT" },
    { MOUNTPROC_UMNTALL,   "UMNTALL" },
    { MOUNTPROC_EXPORT,    "EXPORT" },
    { MOUNTPROC_EXPORTALL, "EXPORTALL" },
    { MOUNTPROC_PATHCONF,  "PATHCONF" },
    { 0, NULL }
};
/* end of mount version 2 */


/* Mount protocol version 3, RFC 1813 */
static const vsff mount3_proc[] = {
	{ 0, "NULL", NULL, NULL },
	{ MOUNTPROC_MNT, "MNT",
		dissect_mount_dirpath_call, dissect_mount3_mnt_reply },
	{ MOUNTPROC_DUMP, "DUMP",
		NULL, dissect_mount_dump_reply },
	{ MOUNTPROC_UMNT, "UMNT",
		dissect_mount_dirpath_call, NULL },
	{ MOUNTPROC_UMNTALL, "UMNTALL",
		NULL, NULL },
	{ MOUNTPROC_EXPORT, "EXPORT",
		NULL, dissect_mount_export_reply },
	{ 0, NULL, NULL, NULL }
};
static const value_string mount3_proc_vals[] = {
	{ 0, "NULL" },
	{ MOUNTPROC_MNT, "MNT" },
	{ MOUNTPROC_DUMP, "DUMP" },
	{ MOUNTPROC_UMNT, "UMNT" },
	{ MOUNTPROC_UMNTALL, "UMNTALL" },
	{ MOUNTPROC_EXPORT, "EXPORT" },
	{ 0, NULL }
};
/* end of Mount protocol version 3 */

/* SGI mount protocol version 1; actually the same as v1 plus
   MOUNTPROC_EXPORTLIST and MOUNTPROC_STATVFS */

static const vsff sgi_mount1_proc[] = {
    { 0, "NULL", NULL, NULL },
    { MOUNTPROC_MNT,        "MNT",
		dissect_mount_dirpath_call, dissect_mount1_mnt_reply },
    { MOUNTPROC_DUMP,       "DUMP",
		NULL, dissect_mount_dump_reply },
    { MOUNTPROC_UMNT,      "UMNT",
		dissect_mount_dirpath_call, NULL },
    { MOUNTPROC_UMNTALL,   "UMNTALL",
		NULL, NULL },
    { MOUNTPROC_EXPORT,    "EXPORT",
		NULL, dissect_mount_export_reply },
    { MOUNTPROC_EXPORTALL, "EXPORTALL",
		NULL, dissect_mount_export_reply },
    { MOUNTPROC_EXPORTLIST,"EXPORTLIST",
		NULL, dissect_mount_exportlist_reply },
    { MOUNTPROC_STATVFS,   "STATVFS",
		dissect_mount_dirpath_call, dissect_mount_statvfs_reply },
    { 0, NULL, NULL, NULL }
};
static const value_string sgi_mount1_proc_vals[] = {
    { 0, "NULL" },
    { MOUNTPROC_MNT,        "MNT" },
    { MOUNTPROC_DUMP,       "DUMP" },
    { MOUNTPROC_UMNT,       "UMNT" },
    { MOUNTPROC_UMNTALL,    "UMNTALL" },
    { MOUNTPROC_EXPORT,     "EXPORT" },
    { MOUNTPROC_EXPORTALL,  "EXPORTALL" },
    { MOUNTPROC_EXPORTLIST, "EXPORTLIST" },
    { MOUNTPROC_STATVFS,    "STATVFS" },
    { 0, NULL }
};
/* end of SGI mount protocol version 1 */

void
proto_register_mount(void)
{
	static hf_register_info hf[] = {
		{ &hf_mount_procedure_v1, {
			"V1 Procedure", "mount.procedure_v1", FT_UINT32, BASE_DEC,
			VALS(mount1_proc_vals), 0, NULL, HFILL }},
		{ &hf_mount_procedure_v2, {
			"V2 Procedure", "mount.procedure_v2", FT_UINT32, BASE_DEC,
			VALS(mount2_proc_vals), 0, NULL, HFILL }},
		{ &hf_mount_procedure_v3, {
			"V3 Procedure", "mount.procedure_v3", FT_UINT32, BASE_DEC,
			VALS(mount3_proc_vals), 0, NULL, HFILL }},
		{ &hf_sgi_mount_procedure_v1, {
			"SGI V1 procedure", "mount.procedure_sgi_v1", FT_UINT32, BASE_DEC,
			VALS(sgi_mount1_proc_vals), 0, NULL, HFILL }},
		{ &hf_mount_path, {
			"Path", "mount.path", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_mount3_status, {
			"Status", "mount.status", FT_UINT32, BASE_DEC,
			VALS(mount3_mountstat3), 0, NULL, HFILL }},
		{ &hf_mount_mountlist_hostname, {
			"Hostname", "mount.dump.hostname", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_mount_mountlist_directory, {
			"Directory", "mount.dump.directory", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_mount_mountlist, {
			"Mount List Entry", "mount.dump.entry", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_mount_groups_group, {
			"Group", "mount.export.group", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_mount_groups, {
			"Groups", "mount.export.groups", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_mount_has_options, {
			"Has options", "mount.export.has_options", FT_UINT32,
			 BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_mount_options, {
			"Options", "mount.export.options", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_mount_exportlist_directory, {
			"Directory", "mount.export.directory", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_mount_exportlist, {
			"Export List Entry", "mount.export.entry", FT_NONE, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_mount_pathconf_link_max, {
			"Maximum number of links to a file", "mount.pathconf.link_max",
			FT_UINT32, BASE_DEC,
			NULL, 0, "Maximum number of links allowed to a file", HFILL }},
		{ &hf_mount_pathconf_max_canon, {
			"Maximum terminal input line length", "mount.pathconf.max_canon",
			FT_UINT16, BASE_DEC,
			NULL, 0, "Max tty input line length", HFILL }},
		{ &hf_mount_pathconf_max_input, {
			"Terminal input buffer size", "mount.pathconf.max_input",
			FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_mount_pathconf_name_max, {
			"Maximum file name length", "mount.pathconf.name_max",
			FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_mount_pathconf_path_max, {
			"Maximum path name length", "mount.pathconf.path_max",
			FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_mount_pathconf_pipe_buf, {
			"Pipe buffer size", "mount.pathconf.pipe_buf",
			FT_UINT16, BASE_DEC,
			NULL, 0, "Maximum amount of data that can be written atomically to a pipe", HFILL }},
		{ &hf_mount_pathconf_vdisable, {
			"VDISABLE character", "mount.pathconf.vdisable_char",
			FT_UINT8, BASE_HEX,
			NULL, 0, "Character value to disable a terminal special character", HFILL }},
		{ &hf_mount_pathconf_mask, {
			"Reply error/status bits", "mount.pathconf.mask",
			FT_UINT16, BASE_HEX,
			NULL, 0, "Bit mask with error and status bits", HFILL }},
		{ &hf_mount_pathconf_error_all, {
			"ERROR_ALL",	"mount.pathconf.mask.error_all",
			FT_BOOLEAN, 16, TFS(&tos_error_all),
			PC_ERROR_ALL, NULL, HFILL }},
		{ &hf_mount_pathconf_error_link_max, {
			"ERROR_LINK_MAX", "mount.pathconf.mask.error_link_max",
			FT_BOOLEAN, 16, TFS(&tos_error_link_max),
			PC_ERROR_LINK_MAX, NULL, HFILL }},
		{ &hf_mount_pathconf_error_max_canon, {
			"ERROR_MAX_CANON", "mount.pathconf.mask.error_max_canon",
			FT_BOOLEAN, 16, TFS(&tos_error_max_canon),
			PC_ERROR_MAX_CANON, NULL, HFILL }},
		{ &hf_mount_pathconf_error_max_input, {
			"ERROR_MAX_INPUT", "mount.pathconf.mask.error_max_input",
			FT_BOOLEAN, 16, TFS(&tos_error_max_input),
			PC_ERROR_MAX_INPUT, NULL, HFILL }},
		{ &hf_mount_pathconf_error_name_max, {
			"ERROR_NAME_MAX", "mount.pathconf.mask.error_name_max",
			FT_BOOLEAN, 16, TFS(&tos_error_name_max),
			PC_ERROR_NAME_MAX, NULL, HFILL }},
		{ &hf_mount_pathconf_error_path_max, {
			"ERROR_PATH_MAX", "mount.pathconf.mask.error_path_max",
			FT_BOOLEAN, 16, TFS(&tos_error_path_max),
			PC_ERROR_PATH_MAX, NULL, HFILL }},
		{ &hf_mount_pathconf_error_pipe_buf, {
			"ERROR_PIPE_BUF", "mount.pathconf.mask.error_pipe_buf",
			FT_BOOLEAN, 16, TFS(&tos_error_pipe_buf),
			PC_ERROR_PIPE_BUF, NULL, HFILL }},
		{ &hf_mount_pathconf_chown_restricted, {
			"CHOWN_RESTRICTED", "mount.pathconf.mask.chown_restricted",
			FT_BOOLEAN, 16, TFS(&tos_chown_restricted),
			PC_CHOWN_RESTRICTED, NULL, HFILL }},
		{ &hf_mount_pathconf_no_trunc, {
			"NO_TRUNC", "mount.pathconf.mask.no_trunc",
			FT_BOOLEAN, 16, TFS(&tos_no_trunc),
			PC_NO_TRUNC, NULL, HFILL }},
		{ &hf_mount_pathconf_error_vdisable, {
			"ERROR_VDISABLE", "mount.pathconf.mask.error_vdisable",
			FT_BOOLEAN, 16, TFS(&tos_error_vdisable),
			PC_ERROR_VDISABLE, NULL, HFILL }},
		{ &hf_mount_statvfs_bsize, {
			"Block size", "mount.statvfs.f_bsize",
			FT_UINT32, BASE_DEC, NULL, 0,
			"File system block size", HFILL }},
		{ &hf_mount_statvfs_frsize, {
			"Fragment size", "mount.statvfs.f_frsize",
			FT_UINT32, BASE_DEC, NULL, 0,
			"File system fragment size", HFILL }},
		{ &hf_mount_statvfs_blocks, {
			"Blocks", "mount.statvfs.f_blocks",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Total fragment sized blocks", HFILL }},
		{ &hf_mount_statvfs_bfree, {
			"Blocks Free", "mount.statvfs.f_bfree",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Free fragment sized blocks", HFILL }},
		{ &hf_mount_statvfs_bavail, {
			"Blocks Available", "mount.statvfs.f_bavail",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Available fragment sized blocks", HFILL }},
		{ &hf_mount_statvfs_files, {
			"Files", "mount.statvfs.f_files",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Total files/inodes", HFILL }},
		{ &hf_mount_statvfs_ffree, {
			"Files Free", "mount.statvfs.f_ffree",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Free files/inodes", HFILL }},
		{ &hf_mount_statvfs_favail, {
			"Files Available", "mount.statvfs.f_favail",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Available files/inodes",  HFILL }},
		{ &hf_mount_statvfs_fsid, {
			"File system ID", "mount.statvfs.f_fsid",
			FT_UINT32, BASE_DEC, NULL, 0,
			"File system identifier", HFILL }},
		{ &hf_mount_statvfs_basetype, {
			"Type", "mount.statvfs.f_basetype",
			FT_STRING, BASE_NONE, NULL, 0,
			"File system type", HFILL }},
		{ &hf_mount_statvfs_flag, {
			"Flags", "mount.statvfs.f_flag",
			FT_UINT32, BASE_HEX, NULL, 0,
			"Flags bit-mask", HFILL }},
		{ &hf_mount_statvfs_flag_rdonly, {
			"ST_RDONLY", "mount.statvfs.f_flag.st_rdonly",
			FT_BOOLEAN, 32, TFS(&tos_st_rdonly), ST_RDONLY,
			NULL, HFILL }},
		{ &hf_mount_statvfs_flag_nosuid, {
			"ST_NOSUID", "mount.statvfs.f_flag.st_nosuid",
			FT_BOOLEAN, 32, TFS(&tos_st_nosuid), ST_NOSUID,
			NULL, HFILL }},
		{ &hf_mount_statvfs_flag_notrunc, {
			"ST_NOTRUNC", "mount.statvfs.f_flag.st_notrunc",
			FT_BOOLEAN, 32, TFS(&tos_st_notrunc), ST_NOTRUNC,
			NULL, HFILL }},
		{ &hf_mount_statvfs_flag_nodev, {
			"ST_NODEV", "mount.statvfs.f_flag.st_nodev",
			 FT_BOOLEAN, 32, TFS(&tos_st_nodev), ST_NODEV,
			NULL, HFILL }},
		{ &hf_mount_statvfs_flag_grpid, {
			"ST_GRPID", "mount.statvfs.f_flag.st_grpid",
			FT_BOOLEAN, 32, TFS(&tos_st_grpid), ST_GRPID,
			NULL, HFILL }},
		{ &hf_mount_statvfs_flag_local, {
			"ST_LOCAL", "mount.statvfs.f_flag.st_local",
			FT_BOOLEAN, 32, TFS(&tos_st_local), ST_LOCAL,
			NULL, HFILL }},
		{ &hf_mount_statvfs_namemax, {
			"Maximum file name length", "mount.statvfs.f_namemax",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL }},
		{ &hf_mount_statvfs_fstr, {
			"File system specific string", "mount.statvfs.f_fstr",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL }},
		{ &hf_mount_flavors, {
			"Flavors", "mount.flavors", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_mount_flavor, {
			"Flavor", "mount.flavor", FT_UINT32, BASE_DEC,
			VALS(rpc_auth_flavor), 0, NULL, HFILL }},
	};
	static gint *ett[] = {
		&ett_mount,
		&ett_mount_mountlist,
		&ett_mount_groups,
		&ett_mount_exportlist,
		&ett_mount_pathconf_mask,
		&ett_mount_statvfs_flag,
	};

	proto_mount = proto_register_protocol("Mount Service", "MOUNT",
	    "mount");
	proto_sgi_mount = proto_register_protocol("SGI Mount Service",
	    "SGI MOUNT", "sgimount");
	proto_register_field_array(proto_mount, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_mount(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_mount, MOUNT_PROGRAM, ett_mount);
	rpc_init_prog(proto_sgi_mount, SGI_MOUNT_PROGRAM, ett_mount);
	/* Register the procedure tables */
	rpc_init_proc_table(MOUNT_PROGRAM, 1, mount1_proc, hf_mount_procedure_v1);
	rpc_init_proc_table(MOUNT_PROGRAM, 2, mount2_proc, hf_mount_procedure_v2);
	rpc_init_proc_table(MOUNT_PROGRAM, 3, mount3_proc, hf_mount_procedure_v3);
	rpc_init_proc_table(SGI_MOUNT_PROGRAM, 1, sgi_mount1_proc, hf_sgi_mount_procedure_v1);
}
