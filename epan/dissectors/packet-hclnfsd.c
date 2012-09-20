/* packet-hclnfsd.c
 * Routines for hclnfsd (Hummingbird NFS Daemon) dissection
 * Copyright 2001, Mike Frisch <frisch@hummingbird.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-ypserv.c
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

#include "packet-rpc.h"
#include "packet-nfs.h"
#include "packet-hclnfsd.h"

static int proto_hclnfsd = -1;
static int hf_hclnfsd_procedure_v1 = -1;
static int hf_hclnfsd_request_type = -1;
static int hf_hclnfsd_device = -1;
static int hf_hclnfsd_login = -1;
static int hf_hclnfsd_lockname = -1;
static int hf_hclnfsd_unknown_data = -1;
static int hf_hclnfsd_lockowner = -1;
static int hf_hclnfsd_printername = -1;
static int hf_hclnfsd_filename = -1;
static int hf_hclnfsd_fileext = -1;
static int hf_hclnfsd_grpname = -1;
static int hf_hclnfsd_hostname = -1;
static int hf_hclnfsd_username = -1;
static int hf_hclnfsd_queuename = -1;
static int hf_hclnfsd_queuecomment = -1;
static int hf_hclnfsd_queuestatus = -1;
static int hf_hclnfsd_numphysicalprinters = -1;
static int hf_hclnfsd_printqueuenumber = -1;
static int hf_hclnfsd_printparams = -1;
static int hf_hclnfsd_status = -1;
static int hf_hclnfsd_sequence = -1;
static int hf_hclnfsd_server_ip = -1;
static int hf_hclnfsd_host_ip = -1;
static int hf_hclnfsd_gid = -1;
static int hf_hclnfsd_uid = -1;
static int hf_hclnfsd_cookie = -1;
static int hf_hclnfsd_mode = -1;
static int hf_hclnfsd_access = -1;
static int hf_hclnfsd_exclusive = -1;
static int hf_hclnfsd_offset = -1;
static int hf_hclnfsd_length = -1;
static int hf_hclnfsd_jobstatus = -1;
static int hf_hclnfsd_timesubmitted = -1;
static int hf_hclnfsd_size = -1;
static int hf_hclnfsd_copies = -1;
static int hf_hclnfsd_auth_ident_obscure = -1;

static gint ett_hclnfsd = -1;
static gint ett_hclnfsd_gids = -1;
static gint ett_hclnfsd_groups = -1;
static gint ett_hclnfsd_uids = -1;
static gint ett_hclnfsd_usernames = -1;
static gint ett_hclnfsd_printqueues = -1;
static gint ett_hclnfsd_printjob = -1;
static gint ett_hclnfsd_auth_ident = -1;

static int
dissect_hclnfsd_gids(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	guint32 ngids, ngids_i, gid;
	proto_tree *gidtree = NULL;
	proto_item *giditem = NULL;


	ngids = tvb_get_ntohl(tvb, offset);
	if (tree)
	{
		giditem = proto_tree_add_text(tree, tvb, offset, 4, "GIDs: %d",
			ngids);
		if (giditem)
			gidtree = proto_item_add_subtree(giditem, ett_hclnfsd_gids);
	}
	offset += 4;

	if (gidtree)
	{
		for (ngids_i = 0; ngids_i < ngids; ngids_i++)
		{
			gid = tvb_get_ntohl(tvb, offset + (4 * ngids_i));
			proto_tree_add_text(gidtree, tvb, offset + (4 * ngids_i), 4,
				"GID: %d", gid);
		}
	}
	offset += 4 * ngids;

	return offset;
}

static int
dissect_hclnfsd_spool_inquire_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_hclnfsd_status, offset);

	offset = dissect_nfs_fh3(tvb, offset, pinfo, tree, "spool filehandle", NULL);

	return offset;
}


static int
dissect_hclnfsd_spool_file_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_string(tvb, tree, hf_hclnfsd_printername, offset, NULL);

	offset = dissect_rpc_string(tvb, tree, hf_hclnfsd_filename, offset, NULL);

	offset = dissect_rpc_uint32(tvb, tree, hf_hclnfsd_fileext, offset);

	return offset;
}


static const value_string names_request_type[] = {
#define HCLNFSD_DISK_REQUEST 4
	{ HCLNFSD_DISK_REQUEST, "DISK" },
#define HCLNFSD_PRINT_REQUEST 3
	{ HCLNFSD_PRINT_REQUEST, "PRINTER" },
	{ 0, NULL }
};

static void
hclnfsd_decode_obscure(char *ident, int ident_len)
{
	int j, x, y;

	for (x = -1, j = 0; j < ident_len; j++)
	{
		y = *ident;
		x ^= *ident;
		*ident++ = x;
		x = y;
	}
}


static int
dissect_hclnfsd_authorize_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	guint32 request_type;
	char *ident = NULL;
	char *username = NULL;
	char *password = NULL;
	int ident_len = 0;
	int newoffset;
	proto_item *ident_item = NULL;
	proto_tree *ident_tree = NULL;

	proto_tree_add_item(tree, hf_hclnfsd_server_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	request_type = tvb_get_ntohl(tvb, offset);
	if (tree)
		proto_tree_add_uint(tree, hf_hclnfsd_request_type, tvb, offset,
			4, request_type);
	offset += 4;

	offset = dissect_rpc_string(tvb, tree, hf_hclnfsd_device, offset,
		NULL);

	if (tree)
	{
		ident_item = proto_tree_add_text(tree, tvb, offset, -1,
			"Authentication Ident");

		if (ident_item)
		{
			ident_tree = proto_item_add_subtree(ident_item,
				ett_hclnfsd_auth_ident);

			if (ident_tree)
			{
				newoffset = dissect_rpc_string(tvb, ident_tree,
					hf_hclnfsd_auth_ident_obscure, offset, &ident);

				if (ident)
				{
					ident_len = (int)strlen(ident);

					proto_item_set_len(ident_item, ident_len);

					hclnfsd_decode_obscure(ident, ident_len);

					username = ident + 2;
					password = username + strlen(username) + 1;

					proto_tree_add_text(ident_tree, tvb, offset, ident_len,
						"Username: %s", username);

					proto_tree_add_text(ident_tree, tvb, offset, ident_len,
						"Password: %s", password);

					offset = newoffset;

					ident = NULL;
				}
			}
		}
	}

	return offset;
}


static int
dissect_hclnfsd_authorize_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	guint32 status;

	status = tvb_get_ntohl(tvb, offset);
	if (!tree)
		return offset;
	offset += 4;

	if (status != 0)
		return offset;

	proto_tree_add_uint(tree, hf_hclnfsd_status, tvb, offset, 4, status);

	offset = dissect_rpc_uint32(tvb, tree, hf_hclnfsd_uid, offset);

	offset = dissect_rpc_uint32(tvb, tree, hf_hclnfsd_gid, offset);

	offset = dissect_hclnfsd_gids(tvb, offset, pinfo, tree);

	return offset;
}

static int
dissect_hclnfsd_grp_name_to_numb_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_string(tvb, tree, hf_hclnfsd_grpname, offset, NULL);

	return offset;
}

static int
dissect_hclnfsd_grp_name_to_numb_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_hclnfsd_gid, offset);

	return offset;
}


static int
dissect_hclnfsd_grp_to_number_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{

	offset = dissect_hclnfsd_gids(tvb, offset, pinfo, tree);

	return offset;
}


static int
dissect_hclnfsd_grp_to_number_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	return dissect_rpc_string(tvb, tree, hf_hclnfsd_grpname, offset,
		NULL);
}


static int
dissect_hclnfsd_return_host_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_hclnfsd_host_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	return offset;
}


static int
dissect_hclnfsd_return_host_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_string(tvb, tree, hf_hclnfsd_hostname, offset, NULL);

	return offset;
}


static int
dissect_hclnfsd_uid_to_name_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	guint32 nuids, nuids_i;
	proto_tree *uidtree = NULL;
	proto_item *uiditem = NULL;

	nuids = tvb_get_ntohl(tvb, offset);
	if (tree)
	{
		uiditem = proto_tree_add_text(tree, tvb, offset, 4, "UIDs: %d",
			nuids);

		if (uiditem)
			uidtree = proto_item_add_subtree(uiditem, ett_hclnfsd_uids);
	}
	offset += 4;

	if (!uidtree)
		return offset;

	for (nuids_i = 0; nuids_i < nuids; nuids_i++)
		offset = dissect_rpc_uint32(tvb, uidtree, hf_hclnfsd_uid, offset);

	return offset;
}


static int
dissect_hclnfsd_uid_to_name_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	guint32 nusers, nusers_i;
	proto_tree *usertree = NULL;
	proto_item *useritem = NULL;

	nusers = tvb_get_ntohl(tvb, offset);
	if (tree)
	{
		useritem = proto_tree_add_text(tree, tvb, offset, 4, "UIDs: %d",
			nusers);

		if (useritem)
			usertree = proto_item_add_subtree(useritem, ett_hclnfsd_usernames);
	}
	offset += 4;

	if (!usertree)
		return offset;

	for (nusers_i = 0; nusers_i < nusers; nusers_i++)
		offset = dissect_rpc_string(tvb, usertree,
			hf_hclnfsd_username, offset, NULL);

	return offset;
}


static int
dissect_hclnfsd_name_to_uid_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_string(tvb, tree, hf_hclnfsd_username, offset, NULL);

	return offset;
}


static int
dissect_hclnfsd_name_to_uid_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_hclnfsd_uid, offset);

	return offset;
}


static int
dissect_hclnfsd_share_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	guint32 request_type;

	request_type = tvb_get_ntohl(tvb, offset);
	if (tree)
		proto_tree_add_uint(tree, hf_hclnfsd_request_type, tvb, offset,
			4, request_type);
	offset += 4;

	offset = dissect_rpc_uint32(tvb, tree, hf_hclnfsd_cookie, offset);

	offset = dissect_rpc_string(tvb, tree, hf_hclnfsd_lockname, offset, NULL);

	offset = dissect_nfs_fh3(tvb, offset, pinfo, tree, "Filehandle", NULL);

	offset = dissect_rpc_data(tvb, tree, hf_hclnfsd_unknown_data, offset);

	offset = dissect_rpc_uint32(tvb, tree, hf_hclnfsd_mode, offset);

	offset = dissect_rpc_uint32(tvb, tree, hf_hclnfsd_access, offset);

	offset += 4;	/* skip last 4 UNUSED bytes */

	return offset;
}


static int
dissect_hclnfsd_share_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	guint32 request_type;

	request_type = tvb_get_ntohl(tvb, offset);
	if (tree)
		proto_tree_add_uint(tree, hf_hclnfsd_request_type, tvb, offset,
			4, request_type);
	offset += 4;

	offset = dissect_rpc_uint32(tvb, tree, hf_hclnfsd_cookie, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_hclnfsd_status, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_hclnfsd_sequence, offset);

	return offset;
}


static int
dissect_hclnfsd_unshare_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	return dissect_hclnfsd_share_call(tvb, offset, pinfo, tree);
}


static int
dissect_hclnfsd_unshare_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	return dissect_hclnfsd_share_reply(tvb, offset, pinfo, tree);
}


static int
dissect_hclnfsd_lock_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_hclnfsd_status, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_hclnfsd_cookie, offset);
	offset += 4; /* skip unused uint */

	offset = dissect_rpc_uint32(tvb, tree, hf_hclnfsd_exclusive, offset);

	offset = dissect_rpc_string(tvb, tree, hf_hclnfsd_lockname, offset, NULL);

	offset = dissect_nfs_fh3(tvb, offset, pinfo, tree, "Filehandle", NULL);

	offset = dissect_rpc_data(tvb, tree, hf_hclnfsd_lockowner, offset);

	offset += 4;  /* unused, skip */

	offset = dissect_rpc_uint32(tvb, tree, hf_hclnfsd_offset, offset);

	offset = dissect_rpc_uint32(tvb, tree, hf_hclnfsd_length, offset);

	return offset;
}


static int
dissect_hclnfsd_lock_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	guint request_type;

	request_type = tvb_get_ntohl(tvb, offset);
	if (tree)
		proto_tree_add_uint(tree, hf_hclnfsd_request_type, tvb, offset,
			4, request_type);
	offset += 4;

	offset = dissect_rpc_uint32(tvb, tree, hf_hclnfsd_cookie, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_hclnfsd_status, offset);

	return offset;
}


static int
dissect_hclnfsd_remove_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_string(tvb, tree, hf_hclnfsd_lockname, offset, NULL);

	offset += 4;  /* skip unused */

	return offset;
}


static int
dissect_hclnfsd_unlock_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset += 4;  /* skip unused */

	offset = dissect_rpc_uint32(tvb, tree, hf_hclnfsd_cookie, offset);

	offset = dissect_rpc_string(tvb, tree, hf_hclnfsd_lockname, offset, NULL);

	offset = dissect_nfs_fh3(tvb, offset, pinfo, tree, "Filehandle", NULL);

	offset = dissect_rpc_data(tvb, tree, hf_hclnfsd_unknown_data, offset);

	offset += 4;  /* skip unused */

	offset = dissect_rpc_uint32(tvb, tree, hf_hclnfsd_offset, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_hclnfsd_length, offset);

	return offset;
}


static int
dissect_hclnfsd_unlock_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	return dissect_hclnfsd_lock_reply(tvb, offset, pinfo, tree);
}


static int
dissect_hclnfsd_get_printers_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	guint nqueues, nqueues_i;
	proto_item *queuesitem = NULL;
	proto_tree *queuestree = NULL;

	nqueues = tvb_get_ntohl(tvb, offset);
	if (tree)
	{
		queuesitem = proto_tree_add_text(tree, tvb, offset, 4,
			"Print Queues: %d", nqueues);

		if (queuesitem)
			queuestree = proto_item_add_subtree(queuesitem,
				ett_hclnfsd_printqueues);
	}
	offset += 4;

	if (!queuestree)
		return offset;

	for (nqueues_i = 0; nqueues_i < nqueues; nqueues_i++)
	{
		/* create new item for print queue */
		offset = dissect_rpc_string(tvb, tree,
			hf_hclnfsd_queuename, offset, NULL);

		/* create subtree on new item with print queue comment */
		offset = dissect_rpc_string(tvb, tree,
			hf_hclnfsd_queuecomment, offset, NULL);
	}

	return offset;
}


static int
dissect_hclnfsd_get_printq_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_string(tvb, tree, hf_hclnfsd_queuename, offset, NULL);

	offset = dissect_rpc_string(tvb, tree, hf_hclnfsd_username, offset, NULL);

	return offset;
}


static int
dissect_hclnfsd_get_printq_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	guint datafollows, jobid;
	proto_item *queueitem = NULL;
	proto_tree *queuetree = NULL;
	proto_item *jobitem;
	proto_tree *jobtree;

	offset = dissect_rpc_uint32(tvb, tree, hf_hclnfsd_printqueuenumber, offset);

	offset = dissect_rpc_string(tvb, tree, hf_hclnfsd_queuecomment, offset, NULL);

	offset = dissect_rpc_uint32(tvb, tree, hf_hclnfsd_queuestatus, offset);

	offset = dissect_rpc_uint32(tvb, tree, hf_hclnfsd_numphysicalprinters, offset);

	datafollows = tvb_get_ntohl(tvb, offset);
	if (tree)
	{
		queueitem = proto_tree_add_text(tree, tvb, offset, 4,
			"Print Jobs: %d", datafollows);
		if (queueitem)
			queuetree = proto_item_add_subtree(queueitem, ett_hclnfsd_printqueues);
	}
	offset += 4;

	if (!queuetree)
		return offset;

	while (datafollows)
	{
		jobid = tvb_get_ntohl(tvb, offset);
		jobitem = proto_tree_add_text(queuetree, tvb, offset, 4, "Job ID: %d",
			jobid);
		offset += 4;

		jobtree = proto_item_add_subtree(jobitem, ett_hclnfsd_printjob);

		offset = dissect_rpc_string(tvb, jobtree,
			hf_hclnfsd_username, offset, NULL);

		offset = dissect_rpc_string(tvb, jobtree,
			hf_hclnfsd_printparams, offset, NULL);

		offset = dissect_rpc_uint32(tvb, jobtree, hf_hclnfsd_queuestatus, offset);

		offset = dissect_rpc_uint32(tvb, jobtree, hf_hclnfsd_jobstatus, offset);
		offset = dissect_rpc_uint32(tvb, jobtree, hf_hclnfsd_timesubmitted, offset);
		offset = dissect_rpc_uint32(tvb, jobtree, hf_hclnfsd_size, offset);
		offset = dissect_rpc_uint32(tvb, jobtree, hf_hclnfsd_copies, offset);
		offset = dissect_rpc_string(tvb, jobtree,
			hf_hclnfsd_queuecomment, offset, NULL);

		datafollows = tvb_get_ntohl(tvb, offset);
		offset += 4;
	}

	return offset;
}


/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: take the generic one. */

static const vsff hclnfsd1_proc[] = {
    { HCLNFSDPROC_NULL, "NULL",
	 	NULL, NULL },
    { HCLNFSDPROC_SPOOL_INQUIRE, "SPOOL_INQUIRE",
		dissect_hclnfsd_spool_inquire_call, NULL },
    { HCLNFSDPROC_SPOOL_FILE, "SPOOL_FILE",
		dissect_hclnfsd_spool_file_call, NULL },
    { HCLNFSDPROC_AUTHORIZE, "AUTHORIZE",
		dissect_hclnfsd_authorize_call, dissect_hclnfsd_authorize_reply },
    { HCLNFSDPROC_GRP_NAME_TO_NUMB, "GRP_NAME_TO_NUMB",
		dissect_hclnfsd_grp_name_to_numb_call, dissect_hclnfsd_grp_name_to_numb_reply },
    { HCLNFSDPROC_GRP_TO_NUMBER, "GRP_TO_NUMBER",
		dissect_hclnfsd_grp_to_number_call, dissect_hclnfsd_grp_to_number_reply },
    { HCLNFSDPROC_RETURN_HOST, "RETURN_HOST",
		dissect_hclnfsd_return_host_call, dissect_hclnfsd_return_host_reply },
    { HCLNFSDPROC_UID_TO_NAME, "UID_TO_NAME",
		dissect_hclnfsd_uid_to_name_call, dissect_hclnfsd_uid_to_name_reply },
    { HCLNFSDPROC_NAME_TO_UID, "NAME_TO_UID",
		dissect_hclnfsd_name_to_uid_call, dissect_hclnfsd_name_to_uid_reply },
    { HCLNFSDPROC_SHARE, "SHARE",
		dissect_hclnfsd_share_call, dissect_hclnfsd_share_reply },
    { HCLNFSDPROC_UNSHARE, "UNSHARE",
		dissect_hclnfsd_unshare_call, dissect_hclnfsd_unshare_reply },
    { HCLNFSDPROC_LOCK, "LOCK",
		dissect_hclnfsd_lock_call, dissect_hclnfsd_lock_reply },
    { HCLNFSDPROC_REMOVE, "REMOVE",
		dissect_hclnfsd_remove_call, NULL },
    { HCLNFSDPROC_UNLOCK, "UNLOCK",
		dissect_hclnfsd_unlock_call, dissect_hclnfsd_unlock_reply },
    { HCLNFSDPROC_GET_PRINTERS, "GET_PRINTERS",
		NULL, dissect_hclnfsd_get_printers_reply },
    { HCLNFSDPROC_GET_PRINTQ, "GET_PRINTQ",
		dissect_hclnfsd_get_printq_call, dissect_hclnfsd_get_printq_reply },
    { HCLNFSDPROC_CANCEL_PRJOB, "CANCEL_PRJOB",
		NULL, NULL },
    { HCLNFSDPROC_ZAP_LOCKS, "ZAP_LOCKS",
		NULL, NULL },
    { 0, NULL, NULL, NULL }
};
static const value_string hclnfsd1_proc_vals[] = {
    { HCLNFSDPROC_NULL, "NULL" },
    { HCLNFSDPROC_SPOOL_INQUIRE, "SPOOL_INQUIRE" },
    { HCLNFSDPROC_SPOOL_FILE, "SPOOL_FILE" },
    { HCLNFSDPROC_AUTHORIZE, "AUTHORIZE" },
    { HCLNFSDPROC_GRP_NAME_TO_NUMB, "GRP_NAME_TO_NUMB" },
    { HCLNFSDPROC_GRP_TO_NUMBER, "GRP_TO_NUMBER" },
    { HCLNFSDPROC_RETURN_HOST, "RETURN_HOST" },
    { HCLNFSDPROC_UID_TO_NAME, "UID_TO_NAME" },
    { HCLNFSDPROC_NAME_TO_UID, "NAME_TO_UID" },
    { HCLNFSDPROC_SHARE, "SHARE" },
    { HCLNFSDPROC_UNSHARE, "UNSHARE" },
    { HCLNFSDPROC_LOCK, "LOCK" },
    { HCLNFSDPROC_REMOVE, "REMOVE" },
    { HCLNFSDPROC_UNLOCK, "UNLOCK" },
    { HCLNFSDPROC_GET_PRINTERS, "GET_PRINTERS" },
    { HCLNFSDPROC_GET_PRINTQ, "GET_PRINTQ" },
    { HCLNFSDPROC_CANCEL_PRJOB, "CANCEL_PRJOB" },
    { HCLNFSDPROC_ZAP_LOCKS, "ZAP_LOCKS" },
    { 0, NULL }
};
/* end of hclnfsd version 1 */


void
proto_register_hclnfsd(void)
{
	static hf_register_info hf[] = {
		{ &hf_hclnfsd_procedure_v1, {
			"V1 Procedure", "hclnfsd.procedure_v1", FT_UINT32, BASE_DEC,
			VALS(hclnfsd1_proc_vals), 0, NULL, HFILL }},
		{ &hf_hclnfsd_request_type, {
			"Request Type", "hclnfsd.request_type", FT_UINT32, BASE_DEC,
			VALS(names_request_type), 0, NULL, HFILL }},

		{ &hf_hclnfsd_device, {
			"Device", "hclnfsd.device", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_hclnfsd_login, {
			"Login Text", "hclnfsd.logintext", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_hclnfsd_lockname, {
			"Lockname", "hclnfsd.lockname", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_hclnfsd_unknown_data, {
			"Unknown", "hclnfsd.unknown_data", FT_BYTES, BASE_NONE,
			NULL, 0, "Data", HFILL }},

		{ &hf_hclnfsd_lockowner, {
			"Lockowner", "hclnfsd.lockowner", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_hclnfsd_printername, {
			"Printer Name", "hclnfsd.printername", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_hclnfsd_filename, {
			"Filename", "hclnfsd.filename", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_hclnfsd_fileext, {
			"File Extension", "hclnfsd.fileext", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_hclnfsd_grpname, {
			"Group", "hclnfsd.group", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_hclnfsd_hostname, {
			"Hostname", "hclnfsd.hostname", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_hclnfsd_username, {
			"Username", "hclnfsd.username", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_hclnfsd_queuename, {
			"Name", "hclnfsd.printqueuename", FT_STRING, BASE_NONE,
			NULL, 0, "Print Queue Name", HFILL }},

		{ &hf_hclnfsd_queuecomment, {
			"Comment", "hclnfsd.printqueuecomment", FT_STRING, BASE_NONE,
			NULL, 0, "Print Queue Comment", HFILL }},

		{ &hf_hclnfsd_printparams, {
			"Print Parameters", "hclnfsd.printparameters", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_hclnfsd_status, {
			"Status", "hclnfsd.status", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_hclnfsd_uid, {
			"UID", "hclnfsd.uid", FT_UINT32, BASE_DEC,
			NULL, 0, "User ID", HFILL }},

		{ &hf_hclnfsd_sequence, {
			"Sequence", "hclnfsd.sequence", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }},

		{ &hf_hclnfsd_cookie, {
			"Cookie", "hclnfsd.cookie", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }},

		{ &hf_hclnfsd_mode, {
			"Mode", "hclnfsd.mode", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_hclnfsd_access, {
			"Access", "hclnfsd.access", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_hclnfsd_exclusive, {
			"Exclusive", "hclnfsd.exclusive", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_hclnfsd_offset, {
			"Offset", "hclnfsd.offset", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_hclnfsd_length, {
			"Length", "hclnfsd.length", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_hclnfsd_queuestatus, {
			"Queue Status", "hclnfsd.queuestatus", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_hclnfsd_printqueuenumber, {
			"Print Queue Number", "hclnfsd.pqn", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_hclnfsd_numphysicalprinters, {
			"Number of Physical Printers", "hclnfsd.npp", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_hclnfsd_jobstatus, {
			"Job Status", "hclnfsd.jobstatus", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_hclnfsd_timesubmitted, {
			"Time Submitted", "hclnfsd.timesubmitted", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_hclnfsd_size, {
			"Size", "hclnfsd.size", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_hclnfsd_copies, {
			"Copies", "hclnfsd.copies", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_hclnfsd_gid, {
			"GID", "hclnfsd.gid", FT_UINT32, BASE_DEC,
			NULL, 0, "Group ID", HFILL }},

		{ &hf_hclnfsd_server_ip, {
			"Server IP", "hclnfsd.server_ip", FT_IPv4, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_hclnfsd_host_ip, {
			"Host IP", "hclnfsd.host_ip", FT_IPv4, BASE_NONE,
			NULL, 0, NULL, HFILL }},

		{ &hf_hclnfsd_auth_ident_obscure, {
			"Obscure Ident", "hclnfsd.authorize.ident.obscure", FT_STRING,
			BASE_NONE	, NULL, 0, "Authentication Obscure Ident", HFILL }},
	};
	static gint *ett[] = {
		&ett_hclnfsd,
		&ett_hclnfsd_gids,
		&ett_hclnfsd_groups,
		&ett_hclnfsd_uids,
		&ett_hclnfsd_usernames,
		&ett_hclnfsd_printqueues,
		&ett_hclnfsd_printjob,
		&ett_hclnfsd_auth_ident
	};

	proto_hclnfsd = proto_register_protocol("Hummingbird NFS Daemon",
		"HCLNFSD", "hclnfsd");
	proto_register_field_array(proto_hclnfsd, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_hclnfsd(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_hclnfsd, HCLNFSD_PROGRAM, ett_hclnfsd);

	/* Register the procedure tables */
	rpc_init_proc_table(HCLNFSD_PROGRAM, 1, hclnfsd1_proc, hf_hclnfsd_procedure_v1);
}
