/* packet-hclnfsd.c
 * Routines for hclnfsd (Hummingbird NFS Daemon) dissection
 * Copyright 2001, Mike Frisch <frisch@hummingbird.com>
 *
 * $Id: packet-hclnfsd.c,v 1.3 2001/02/06 18:43:24 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif


#include "packet-rpc.h"
#include "packet-hclnfsd.h"

static int proto_hclnfsd = -1;

static int hf_hclnfsd_request_type = -1;
static int hf_hclnfsd_device = -1;
static int hf_hclnfsd_login = -1;
static int hf_hclnfsd_lockname = -1;
static int hf_hclnfsd_unknown_data = -1;
static int hf_hclnfsd_lockowner = -1;
static int hf_hclnfsd_printername = -1;
static int hf_hclnfsd_filename = -1;
static int hf_hclnfsd_grpname = -1;
static int hf_hclnfsd_hostname = -1;
static int hf_hclnfsd_username = -1;
static int hf_hclnfsd_queuename = -1;
static int hf_hclnfsd_queuecomment = -1;
static int hf_hclnfsd_printparams = -1;
static int hf_hclnfsd_status = -1;

static gint ett_hclnfsd = -1;
static gint ett_hclnfsd_gids = -1;
static gint ett_hclnfsd_groups = -1;
static gint ett_hclnfsd_uids = -1;
static gint ett_hclnfsd_usernames = -1;
static gint ett_hclnfsd_printqueues = -1;
static gint ett_hclnfsd_printjob = -1;


/* defined in 'packet-nfs.c' */
extern int
dissect_nfs_fh3(const u_char *, int, frame_data *, proto_tree *, char *);


int
dissect_hclnfsd_gids(const u_char *pd, int offset, frame_data *fd, 
	proto_tree *tree)
{
	guint ngids, ngids_i, gid;
	proto_tree *gidtree = NULL;
	proto_item *giditem = NULL;

	if (!tree) return offset;

	ngids = EXTRACT_UINT(pd, offset);
	if (tree)
	{
		giditem = proto_tree_add_text(tree, NullTVB, offset, 4, "GIDs: %d", 
			ngids);
		if (giditem)
			gidtree = proto_item_add_subtree(giditem, ett_hclnfsd_gids);
	}
	offset += 4;

	if (gidtree)
	{
		for (ngids_i = 0; ngids_i < ngids; ngids_i++)
		{
			gid = EXTRACT_UINT(pd, offset + (4 * ngids_i));
			proto_tree_add_text(gidtree, NullTVB, offset + (4 * ngids_i), 4, 
				"GID: %d", gid);
		}
	}
	offset += 4 * ngids;

	return offset;
}
	
int
dissect_hclnfsd_spool_inquire_call(const u_char *pd, int offset, 
	frame_data *fd, proto_tree *tree)
{
	offset = dissect_rpc_uint32(pd, offset, fd, tree, "status");

	offset = dissect_nfs_fh3(pd, offset, fd, tree, "spool filehandle");

	return offset;
}


int
dissect_hclnfsd_spool_file_call(const u_char *pd, int offset,
	frame_data *fd, proto_tree *tree)
{
	offset = dissect_rpc_string(pd, offset, fd, tree, hf_hclnfsd_printername,
		NULL);

	offset = dissect_rpc_string(pd, offset, fd, tree, hf_hclnfsd_filename,
		NULL);

	offset = dissect_rpc_uint32(pd, offset, fd, tree, "File Extension");

	return offset;
}


static const value_string names_request_type[] = {
#define HCLNFSD_DISK_REQUEST 4
	{ HCLNFSD_DISK_REQUEST, "DISK" },
#define HCLNFSD_PRINT_REQUEST 3
	{ HCLNFSD_PRINT_REQUEST, "PRINTER" },
	{ 0, NULL }
};


int
dissect_hclnfsd_authorize_call(const u_char *pd, int offset,
	frame_data *fd, proto_tree *tree)
{
	guint request_type;

	offset = dissect_rpc_uint32(pd, offset, fd, tree, "Server IP");

	request_type = EXTRACT_UINT(pd, offset);
	if (tree)
		proto_tree_add_uint(tree, hf_hclnfsd_request_type, NullTVB, offset,
			4, request_type);
	offset += 4;

	offset = dissect_rpc_string(pd, offset, fd, tree, hf_hclnfsd_device, NULL);

	offset = dissect_rpc_string(pd, offset, fd, tree, hf_hclnfsd_login, NULL);

	return offset;
}


int
dissect_hclnfsd_authorize_reply(const u_char *pd, int offset,
	frame_data *fd, proto_tree *tree)
{
	guint status;

	status = EXTRACT_UINT(pd, offset);
	if (!tree) return offset;
	offset += 4;

	if (status != 0)
		return offset;

	proto_tree_add_uint(tree, hf_hclnfsd_status, NullTVB, offset, 4, status);

	offset = dissect_rpc_uint32(pd, offset, fd, tree, "UID");

	offset = dissect_rpc_uint32(pd, offset, fd, tree, "GID");

	offset = dissect_hclnfsd_gids(pd, offset, fd, tree);

	return offset;
}

int
dissect_hclnfsd_grp_name_to_numb_call(const u_char *pd, int offset,
	frame_data *fd, proto_tree *tree)
{
	offset = dissect_rpc_string(pd, offset, fd, tree, hf_hclnfsd_grpname,
		NULL);

	return offset;
}


int
dissect_hclnfsd_grp_name_to_numb_reply(const u_char *pd, int offset,
	frame_data *fd, proto_tree *tree)
{
	offset = dissect_rpc_uint32(pd, offset, fd, tree, "GID");
	
	return offset;
}


int
dissect_hclnfsd_grp_to_number_call(const u_char *pd, int offset,
	frame_data *fd, proto_tree *tree)
{

	offset = dissect_hclnfsd_gids(pd, offset, fd, tree);

	return offset;
}


int
dissect_hclnfsd_grp_to_number_reply(const u_char *pd, int offset,
	frame_data *fd, proto_tree *tree)
{
	guint ngrpnames, ngrpnames_i;
	proto_tree *grptree = NULL;
	proto_item *grpitem = NULL;

	ngrpnames = EXTRACT_UINT(pd, offset);
	if (tree)
	{
		grpitem = proto_tree_add_text(tree, NullTVB, offset, 4, "Groups: %d",
			ngrpnames);

		if (grpitem)
			grptree = proto_item_add_subtree(grpitem, ett_hclnfsd_groups);
	}
	offset += 4;

	if (!grptree)
		return offset;

	for (ngrpnames_i = 0; ngrpnames_i < ngrpnames ; ngrpnames_i++)
		offset = dissect_rpc_string(pd, offset, fd, grptree, 
			hf_hclnfsd_grpname, NULL);
	
	return offset;
}


int
dissect_hclnfsd_return_host_call(const u_char *pd, int offset,
	frame_data *fd, proto_tree *tree)
{
	offset = dissect_rpc_uint32(pd, offset, fd, tree, "IP");

	return offset;
}


int
dissect_hclnfsd_return_host_reply(const u_char *pd, int offset,
	frame_data *fd, proto_tree *tree)
{
	offset = dissect_rpc_string(pd, offset, fd, tree, hf_hclnfsd_hostname, NULL);

	return offset;
}


int
dissect_hclnfsd_uid_to_name_call(const u_char *pd, int offset,
	frame_data *fd, proto_tree *tree)
{
	guint nuids, nuids_i;
	proto_tree *uidtree = NULL;
	proto_item *uiditem = NULL;

	nuids = EXTRACT_UINT(pd, offset);
	if (tree)
	{
		uiditem = proto_tree_add_text(tree, NullTVB, offset, 4, "UIDs: %d",
			nuids);

		if (uiditem)
			uidtree = proto_item_add_subtree(uiditem, ett_hclnfsd_uids);
	}
	offset += 4;

	if (!uidtree)
		return offset;

	for (nuids_i = 0; nuids_i < nuids; nuids_i++)
		offset = dissect_rpc_uint32(pd, offset, fd, uidtree, "UID");

	return offset;
}


int
dissect_hclnfsd_uid_to_name_reply(const u_char *pd, int offset,
	frame_data *fd, proto_tree *tree)
{
	guint nusers, nusers_i;
	proto_tree *usertree = NULL;
	proto_item *useritem = NULL;

	nusers = EXTRACT_UINT(pd, offset);
	if (tree)
	{
		useritem = proto_tree_add_text(tree, NullTVB, offset, 4, "UIDs: %d",
			nusers);

		if (useritem)
			usertree = proto_item_add_subtree(useritem, ett_hclnfsd_usernames);
	}
	offset += 4;

	if (!usertree)
		return offset;

	for (nusers_i = 0; nusers_i < nusers; nusers_i++)
		offset = dissect_rpc_string(pd, offset, fd, usertree, 
			hf_hclnfsd_username, NULL);

	return offset;
}


int
dissect_hclnfsd_name_to_uid_call(const u_char *pd, int offset,
	frame_data *fd, proto_tree *tree)
{
	offset = dissect_rpc_string(pd, offset, fd, tree, hf_hclnfsd_username, NULL);

	return offset;
}


int
dissect_hclnfsd_name_to_uid_reply(const u_char *pd, int offset,
	frame_data *fd, proto_tree *tree)
{
	offset = dissect_rpc_uint32(pd, offset, fd, tree, "UID");

	return offset;
}


int
dissect_hclnfsd_share_call(const u_char *pd, int offset,
	frame_data *fd, proto_tree *tree)
{
	guint request_type;

	request_type = EXTRACT_UINT(pd, offset);
	if (tree)
		proto_tree_add_uint(tree, hf_hclnfsd_request_type, NullTVB, offset,
			4, request_type);
	offset += 4;

	offset = dissect_rpc_uint32(pd, offset, fd, tree, "Cookie");

	offset = dissect_rpc_string(pd, offset, fd, tree, hf_hclnfsd_lockname, NULL);

	offset = dissect_nfs_fh3(pd, offset, fd, tree, "Filehandle");

	offset = dissect_rpc_data(pd, offset, fd, tree, hf_hclnfsd_unknown_data);

	offset = dissect_rpc_uint32(pd, offset, fd, tree, "Mode");

	offset = dissect_rpc_uint32(pd, offset, fd, tree, "Access");

	offset = dissect_rpc_uint32(pd, offset, fd, tree, "unused");

	return offset;
}


int
dissect_hclnfsd_share_reply(const u_char *pd, int offset,
	frame_data *fd, proto_tree *tree)
{
	guint request_type;

	request_type = EXTRACT_UINT(pd, offset);
	if (tree)
		proto_tree_add_uint(tree, hf_hclnfsd_request_type, NullTVB, offset,
			4, request_type);
	offset += 4;

	offset = dissect_rpc_uint32(pd, offset, fd, tree, "Cookie");

	offset = dissect_rpc_uint32(pd, offset, fd, tree, "Stat");

	offset = dissect_rpc_uint32(pd, offset, fd, tree, "Sequence");

	return offset;
}


int
dissect_hclnfsd_unshare_call(const u_char *pd, int offset,
	frame_data *fd, proto_tree *tree)
{
	return dissect_hclnfsd_share_call(pd, offset, fd, tree);
}


int
dissect_hclnfsd_unshare_reply(const u_char *pd, int offset,
	frame_data *fd, proto_tree *tree)
{
	return dissect_hclnfsd_share_reply(pd, offset, fd, tree);
}


int
dissect_hclnfsd_lock_call(const u_char *pd, int offset,
	frame_data *fd, proto_tree *tree)
{
	offset = dissect_rpc_uint32(pd, offset, fd, tree, "Status");

	offset = dissect_rpc_uint32(pd, offset, fd, tree, "Cookie");

	offset = dissect_rpc_uint32(pd, offset, fd, tree, "unused");

	offset = dissect_rpc_uint32(pd, offset, fd, tree, "Exclusive");

	offset = dissect_rpc_string(pd, offset, fd, tree, hf_hclnfsd_lockname, NULL);

	offset = dissect_nfs_fh3(pd, offset, fd, tree, "Filehandle");

	offset = dissect_rpc_data(pd, offset, fd, tree, hf_hclnfsd_lockowner);

	offset = dissect_rpc_uint32(pd, offset, fd, tree, "unused");

	offset = dissect_rpc_uint32(pd, offset, fd, tree, "Offset");

	offset = dissect_rpc_uint32(pd, offset, fd, tree, "Length");

	return offset;
}


int
dissect_hclnfsd_lock_reply(const u_char *pd, int offset,
	frame_data *fd, proto_tree *tree)
{
	guint request_type;

	request_type = EXTRACT_UINT(pd, offset);
	if (tree)
		proto_tree_add_uint(tree, hf_hclnfsd_request_type, NullTVB, offset,
			4, request_type);
	offset += 4;

	offset = dissect_rpc_uint32(pd, offset, fd, tree, "Cookie");

	offset = dissect_rpc_uint32(pd, offset, fd, tree, "Stat");

	return offset;
}


int
dissect_hclnfsd_remove_call(const u_char *pd, int offset,
	frame_data *fd, proto_tree *tree)
{
	offset = dissect_rpc_string(pd, offset, fd, tree, hf_hclnfsd_lockname, NULL);

	offset = dissect_rpc_uint32(pd, offset, fd, tree, "unused");

	return offset;
}


int
dissect_hclnfsd_unlock_call(const u_char *pd, int offset,
	frame_data *fd, proto_tree *tree)
{
	offset = dissect_rpc_uint32(pd, offset, fd, tree, "unused");

	offset = dissect_rpc_uint32(pd, offset, fd, tree, "Cookie");

	offset = dissect_rpc_string(pd, offset, fd, tree, hf_hclnfsd_lockname, NULL);

	offset = dissect_nfs_fh3(pd, offset, fd, tree, "Filehandle");

	offset = dissect_rpc_data(pd, offset, fd, tree, hf_hclnfsd_unknown_data);

	offset = dissect_rpc_uint32(pd, offset, fd, tree, "unused");

	offset = dissect_rpc_uint32(pd, offset, fd, tree, "Offset");

	offset = dissect_rpc_uint32(pd, offset, fd, tree, "Length");
	
	return offset;
}


int
dissect_hclnfsd_unlock_reply(const u_char *pd, int offset,
	frame_data *fd, proto_tree *tree)
{
	return dissect_hclnfsd_lock_reply(pd, offset, fd, tree);
}


int
dissect_hclnfsd_get_printers_reply(const u_char *pd, int offset,
	frame_data *fd, proto_tree *tree)
{
	guint nqueues, nqueues_i;
	proto_item *queuesitem = NULL;
	proto_tree *queuestree = NULL;

	nqueues = EXTRACT_UINT(pd, offset);
	if (tree)
	{
		queuesitem = proto_tree_add_text(tree, NullTVB, offset, 4,
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
		offset = dissect_rpc_string(pd, offset, fd, queuestree,
			hf_hclnfsd_queuename, NULL);

		/* create subtree on new item with print queue comment */

		offset = dissect_rpc_string(pd, offset, fd, queuestree, 
			hf_hclnfsd_queuecomment, NULL);
	}

	return offset;
}


int
dissect_hclnfsd_get_printq_call(const u_char *pd, int offset,
	frame_data *fd, proto_tree *tree)
{
	offset = dissect_rpc_string(pd, offset, fd, tree, hf_hclnfsd_queuename, 
		NULL);

	offset = dissect_rpc_string(pd, offset, fd, tree, hf_hclnfsd_username, NULL);

	return offset;
}


int
dissect_hclnfsd_get_printq_reply(const u_char *pd, int offset,
	frame_data *fd, proto_tree *tree)
{
	guint datafollows, jobid;
	proto_item *queueitem = NULL;
	proto_tree *queuetree = NULL;
	proto_item *jobitem;
	proto_tree *jobtree;

	offset = dissect_rpc_uint32(pd, offset, fd, tree, "Print Queue Number");

	offset = dissect_rpc_string(pd, offset, fd, tree, hf_hclnfsd_queuecomment,
		NULL);

	offset = dissect_rpc_uint32(pd, offset, fd, tree, "Queue Status");

	offset = dissect_rpc_uint32(pd, offset, fd, tree, 
		"Number of Physical Printers");

	datafollows = EXTRACT_UINT(pd, offset);
	if (tree)
	{
		queueitem = proto_tree_add_text(tree, NullTVB, offset, 4, 
			"Print Jobs: %d", datafollows);
		if (queueitem)
			queuetree = proto_item_add_subtree(queueitem, ett_hclnfsd_printqueues);
	}
	offset += 4;

	if (!queuetree)
		return offset;
	
	while (datafollows)
	{
		jobid = EXTRACT_UINT(pd, offset);
		jobitem = proto_tree_add_text(queuetree, NullTVB, offset, 4, "Job ID: %d",
			jobid);
		offset += 4;

		jobtree = proto_item_add_subtree(jobitem, ett_hclnfsd_printjob);
			
		offset = dissect_rpc_string(pd, offset, fd, jobtree, 
			hf_hclnfsd_username, NULL);
		offset = dissect_rpc_string(pd, offset, fd, jobtree,
			hf_hclnfsd_printparams, NULL);
		offset = dissect_rpc_uint32(pd, offset, fd, jobtree, "Queue Position");
		offset = dissect_rpc_uint32(pd, offset, fd, jobtree, "Job Status");
		offset = dissect_rpc_uint32(pd, offset, fd, jobtree, "Time Submitted");
		offset = dissect_rpc_uint32(pd, offset, fd, jobtree, "Size");
		offset = dissect_rpc_uint32(pd, offset, fd, jobtree, "Copies");
		offset = dissect_rpc_string(pd, offset, fd, jobtree, 
			hf_hclnfsd_queuecomment, NULL);
		datafollows = EXTRACT_UINT(pd, offset);
		offset += 4;
	}

	return offset;
}


/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: take the generic one. */

static const old_vsff hclnfsd1_proc[] = {
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
/* end of hclnfsd version 1 */


void
proto_register_hclnfsd(void)
{
#if 0
	static struct true_false_string okfailed = { "Ok", "Failed" };
	static struct true_false_string yesno = { "Yes", "No" };
#endif
		
	static hf_register_info hf[] = {
		{ &hf_hclnfsd_request_type, {
			"Request Type", "hclnfsd.request_type", FT_UINT32, BASE_DEC,
			VALS(names_request_type), 0, "Request Type" }},

		{ &hf_hclnfsd_device, {
			"Device", "hclnfsd.device", FT_STRING, BASE_DEC,
			NULL, 0, "Device" }},

		{ &hf_hclnfsd_login, {
			"Login Text", "hclnfsd.logintext", FT_STRING, BASE_DEC,
			NULL, 0, "Login Text" }},

		{ &hf_hclnfsd_lockname, {
			"Lockname", "hclnfsd.lockname", FT_STRING, BASE_DEC,
			NULL, 0, "Lockname" }},

		{ &hf_hclnfsd_unknown_data, {
			"Unknown", "hclnfsd.unknown_data", FT_STRING, BASE_DEC,
			NULL, 0, "Data" }},

		{ &hf_hclnfsd_lockowner, {
			"Lockowner", "hclnfsd.lockowner", FT_STRING, BASE_DEC,
			NULL, 0, "Lockowner" }},

		{ &hf_hclnfsd_printername, {
			"Printer Name", "hclnfsd.printername", FT_STRING, BASE_DEC,
			NULL, 0, "Printer name" }},

		{ &hf_hclnfsd_filename, {
			"Filename", "hclnfsd.filename", FT_STRING, BASE_DEC,
			NULL, 0, "Filename" }},

		{ &hf_hclnfsd_grpname, {
			"Group", "hclnfsd.group", FT_STRING, BASE_DEC,
			NULL, 0, "Group" }},

		{ &hf_hclnfsd_hostname, {
			"Hostname", "hclnfsd.hostname", FT_STRING, BASE_DEC,
			NULL, 0, "Hostname" }},

		{ &hf_hclnfsd_username, {
			"Username", "hclnfsd.username", FT_STRING, BASE_DEC,
			NULL, 0, "Username" }},

		{ &hf_hclnfsd_queuename, {
			"Name", "hclnfsd.printqueuename", FT_STRING, BASE_DEC,
			NULL, 0, "Print Queue Name" }},

		{ &hf_hclnfsd_queuecomment, {
			"Comment", "hclnfsd.printqueuecomment", FT_STRING, BASE_DEC,
			NULL, 0, "Print Queue Comment" }},

		{ &hf_hclnfsd_printparams, {
			"Print Parameters", "hclnfsd.printparameters", FT_STRING, BASE_DEC,
			NULL, 0, "Print Parameters" }},

		{ &hf_hclnfsd_status, {
			"Status", "hclnfsd.status", FT_UINT32, BASE_DEC,
			NULL, 0, "Status" }}
	};
	static gint *ett[] = {
		&ett_hclnfsd,
		&ett_hclnfsd_gids,
		&ett_hclnfsd_groups,
		&ett_hclnfsd_uids,
		&ett_hclnfsd_usernames,
		&ett_hclnfsd_printqueues,
		&ett_hclnfsd_printjob,
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
	old_rpc_init_proc_table(HCLNFSD_PROGRAM, 1, hclnfsd1_proc);
}
