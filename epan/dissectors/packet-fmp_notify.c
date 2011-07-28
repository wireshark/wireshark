/* packet-fmp_notify.c
 * Routines for fmp dissection
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#include <glib.h>
#include <gmodule.h>

#include <epan/strutil.h>

#include "packet-rpc.h"
#include "packet-fmp.h"

#define FMP_NOTIFY_PROG 	1001912
#define FMP_NOTIFY_VERSION_2 	2

/*
 * FMP/NOTIFY Procedures
 */
#define FMP_NOTIFY_DownGrade		1
#define FMP_NOTIFY_RevokeList		2
#define FMP_NOTIFY_RevokeAll 		3
#define FMP_NOTIFY_FileSetEof 		4
#define FMP_NOTIFY_RequestDone 		5
#define FMP_NOTIFY_volFreeze 		6
#define FMP_NOTIFY_revokeHandleList	7

typedef enum {
	FMP_LIST_USER_QUOTA_EXCEEDED = 0,
	FMP_LIST_GROUP_QUOTA_EXCEEDED = 1,
	FMP_LIST_SERVER_RESOURCE_LOW = 2
} revokeHandleListReason;

static int proto_fmp_notify = -1;
static int hf_fmp_handleListLen = -1;
static int hf_fmp_notify_procedure = -1;
static int hf_fmp_fsID = -1;
static int hf_fmp_fsBlkSz = -1;
static int hf_fmp_sessionHandle = -1;
static int hf_fmp_fmpFHandle = -1;
static int hf_fmp_msgNum = -1;
static int hf_fmp_fileSize = -1;
static int hf_fmp_cookie = -1;
static int hf_fmp_firstLogBlk = -1;
static int hf_fmp_numBlksReq = -1;
static int hf_fmp_status = -1;
static int hf_fmp_extentList_len = -1;
static int hf_fmp_numBlks = -1;
static int hf_fmp_volID = -1;
static int hf_fmp_startOffset = -1;
static int hf_fmp_extent_state = -1;

static gint ett_fmp_notify = -1;
static gint ett_fmp_notify_hlist = -1;
static gint ett_fmp_extList = -1;
static gint ett_fmp_ext = -1;


static int dissect_fmp_notify_extentList(tvbuff_t *, int, packet_info *, proto_tree *);

static int
dissect_fmp_notify_status(tvbuff_t *tvb, int offset, proto_tree *tree, int *rval)
{
        fmpStat status;

        status = tvb_get_ntohl(tvb, offset);

        switch (status) {
        case FMP_OK:
                *rval = 0;
                break;
        case FMP_IOERROR:
                *rval = 1;
                break;
        case FMP_NOMEM:
                *rval = 1;
                break;
        case FMP_NOACCESS:
                *rval = 1;
                break;
	 case FMP_INVALIDARG:
                *rval = 1;
                break;
        case FMP_FSFULL:
                *rval = 0;
                break;
        case FMP_QUEUE_FULL:
                *rval = 1;
                break;
        case FMP_WRONG_MSG_NUM:
                *rval = 1;
                break;
        case FMP_SESSION_LOST:
                *rval = 1;
                break;
        case FMP_HOT_SESSION:
                *rval = 0;
                break;

	case FMP_COLD_SESSION:
                *rval = 0;
                break;
        case FMP_CLIENT_TERMINATED:
                *rval = 0;
                break;
        case FMP_WRITER_LOST_BLK:
                *rval = 1;
                break;
        case FMP_REQUEST_QUEUED:
                *rval = 0;
                break;
        case FMP_FALL_BACK:
                *rval = 0;
                break;
        case FMP_REQUEST_CANCELLED:
                *rval = 1;
                break;

	       case FMP_WRITER_ZEROED_BLK:
                *rval = 0;
                break;
        case FMP_NOTIFY_ERROR:
                *rval = 1;
                break;
        case FMP_WRONG_HANDLE:
                *rval = 0;
                break;
        case FMP_DUPLICATE_OPEN:
                *rval = 1;
                break;
        case FMP_PLUGIN_NOFUNC:
                *rval = 1;
                break;
        default:
                *rval = 1;
                break;
        }

        offset = dissect_rpc_uint32(tvb, tree, hf_fmp_status , offset);
        return offset;

}

static int
dissect_revokeHandleListReason(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	revokeHandleListReason reason;

  	if (tree) {
		reason  = tvb_get_ntohl(tvb, offset);
		switch (reason) {
		case FMP_LIST_USER_QUOTA_EXCEEDED:
			proto_tree_add_text(tree, tvb, offset, 4, "Reason: %s",
					    "LIST_USER_QUOTA_EXCEEDED");
			break;

		case FMP_LIST_GROUP_QUOTA_EXCEEDED:
			proto_tree_add_text(tree, tvb, offset, 4, "Reason: %s",
					    "LIST_GROUP_QUOTA_EXCEEDED");
			break;

		case FMP_LIST_SERVER_RESOURCE_LOW:
			proto_tree_add_text(tree, tvb, offset, 4, "Reason: %s",
					    "LIST_SERVER_RESOURCE_LOW");
			break;

		default:
			proto_tree_add_text(tree, tvb, offset, 4, "Reason: %s",
					    "Unknown Reason");
			break;
		}
	}
	offset += 4;
	return offset;
}

static int
dissect_handleList(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
                   proto_tree *tree)
{

	int numHandles;
	int listLength;
	int i;
	proto_item *handleListItem;
	proto_tree *handleListTree;

	numHandles = tvb_get_ntohl(tvb, offset);
	listLength = 4;

	for (i = 0; i < numHandles; i++) {
		listLength += (4 + tvb_get_ntohl(tvb, offset + listLength));
	}

	handleListItem =  proto_tree_add_text(tree, tvb, offset, listLength,
	                                      "Handle List");
	handleListTree = proto_item_add_subtree(handleListItem,
	                                        ett_fmp_notify_hlist);

	offset = dissect_rpc_uint32(tvb,  handleListTree,
	                            hf_fmp_handleListLen, offset);

	for (i = 0; i <= numHandles; i++) {
		offset = dissect_rpc_data(tvb, handleListTree,
		                          hf_fmp_fmpFHandle, offset);/*  changed */
	}

	return offset;
}

static int
dissect_FMP_NOTIFY_DownGrade_request(tvbuff_t *tvb, int offset,
                                     packet_info *pinfo _U_, proto_tree *tree)
{


	offset = dissect_rpc_data(tvb,  tree, hf_fmp_sessionHandle,
	                          offset);
	offset = dissect_rpc_data(tvb,  tree, hf_fmp_fmpFHandle, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_fmp_msgNum, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_fmp_firstLogBlk,
	                            offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_fmp_numBlksReq, offset);
	return offset;
}

static int
dissect_FMP_NOTIFY_DownGrade_reply(tvbuff_t *tvb, int offset,
                                   packet_info *pinfo _U_, proto_tree *tree)
{
	int rval;

	offset = dissect_fmp_notify_status(tvb, offset,tree, &rval);
	return offset;
}

static int
dissect_FMP_NOTIFY_RevokeList_request(tvbuff_t *tvb, int offset,
                                      packet_info *pinfo _U_, proto_tree *tree)
{

	offset = dissect_rpc_data(tvb,  tree, hf_fmp_sessionHandle,
                                  offset);
	offset = dissect_rpc_data(tvb, tree, hf_fmp_fmpFHandle, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_fmp_msgNum, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_fmp_firstLogBlk,
                                    offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_fmp_numBlksReq, offset);
	return offset;
}

static int
dissect_FMP_NOTIFY_RevokeList_reply(tvbuff_t *tvb, int offset,
                                    packet_info *pinfo _U_, proto_tree *tree)
{
	int rval;

	offset = dissect_fmp_notify_status(tvb, offset,tree, &rval);
	return offset;
}

static int
dissect_FMP_NOTIFY_RevokeAll_request(tvbuff_t *tvb, int offset,
                                     packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_data(tvb, tree, hf_fmp_sessionHandle,
	                          offset);
	offset = dissect_rpc_data(tvb, tree, hf_fmp_fmpFHandle, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_fmp_msgNum, offset);
	return offset;
}

static int
dissect_FMP_NOTIFY_RevokeAll_reply(tvbuff_t *tvb, int offset,
                                   packet_info *pinfo _U_, proto_tree *tree)
{
	int rval;

	offset = dissect_fmp_notify_status(tvb, offset,tree, &rval);
	return offset;
}

static int
dissect_FMP_NOTIFY_FileSetEof_request(tvbuff_t *tvb, int offset,
                                      packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_data(tvb, tree, hf_fmp_sessionHandle,
	                          offset);
	offset = dissect_rpc_data(tvb, tree, hf_fmp_fmpFHandle, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_fmp_msgNum, offset);
	offset = dissect_rpc_uint64(tvb, tree, hf_fmp_fileSize, offset);
	return offset;
}

static int
dissect_FMP_NOTIFY_FileSetEof_reply(tvbuff_t *tvb, int offset,
                                    packet_info *pinfo _U_, proto_tree *tree)
{
	int rval;

	offset = dissect_fmp_notify_status(tvb, offset,tree, &rval);
	return offset;
}

static int
dissect_FMP_NOTIFY_RequestDone_request(tvbuff_t *tvb, int offset,
                                       packet_info *pinfo, proto_tree *tree)
{
	int rval;

	offset = dissect_fmp_notify_status(tvb, offset,tree, &rval);
	if (rval == 0) {
		offset = dissect_rpc_data(tvb,  tree,
		                          hf_fmp_sessionHandle, offset);
		offset = dissect_rpc_data(tvb, tree, hf_fmp_fmpFHandle,
		                          offset);
		offset = dissect_rpc_uint32(tvb, tree, hf_fmp_msgNum,
		                            offset);
		offset = dissect_rpc_uint32(tvb, tree, hf_fmp_cookie,
		                            offset);
		offset = dissect_fmp_notify_extentList(tvb, offset, pinfo, tree);
	}
	return offset;
}

static int
dissect_FMP_NOTIFY_RequestDone_reply(tvbuff_t *tvb, int offset,
                                     packet_info *pinfo _U_, proto_tree *tree)
{
	int rval;

	offset = dissect_fmp_notify_status(tvb, offset,tree, &rval);
	return offset;
}

static int
dissect_FMP_NOTIFY_volFreeze_request(tvbuff_t *tvb, int offset,
                                     packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_data(tvb, tree, hf_fmp_sessionHandle,
	                          offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_fmp_fsID, offset);
	return offset;
}

static int
dissect_FMP_NOTIFY_volFreeze_reply(tvbuff_t *tvb, int offset,
                                   packet_info *pinfo _U_, proto_tree *tree)
{
	int rval;

	offset = dissect_fmp_notify_status(tvb, offset,tree, &rval);
	return offset;
}

static int
dissect_FMP_NOTIFY_revokeHandleList_request(tvbuff_t *tvb, int offset,
                                            packet_info *pinfo,
                                            proto_tree *tree)
{
	offset = dissect_rpc_data(tvb, tree, hf_fmp_sessionHandle,
							                          offset);
	offset = dissect_revokeHandleListReason(tvb, offset, tree);
	offset = dissect_handleList(tvb, offset, pinfo, tree);
	return offset;
}

static int
dissect_FMP_NOTIFY_revokeHandleList_reply(tvbuff_t *tvb, int offset,
                                          packet_info *pinfo _U_, proto_tree *tree)
{
	int rval;

	offset = dissect_fmp_notify_status(tvb, offset,tree, &rval);
	return offset;
}

/*
 * proc number, "proc name", dissect_request, dissect_reply
 * NULL as function pointer means: type of arguments is "void".
 */
static const vsff fmp_notify2_proc[] = {

	{ FMP_NOTIFY_DownGrade,				"DownGrade",
	  dissect_FMP_NOTIFY_DownGrade_request,
	  dissect_FMP_NOTIFY_DownGrade_reply },

	{ FMP_NOTIFY_RevokeList,			"RevokeList",
	  dissect_FMP_NOTIFY_RevokeList_request,
	  dissect_FMP_NOTIFY_RevokeList_reply },

	{ FMP_NOTIFY_RevokeAll,				"RevokeAll",
	  dissect_FMP_NOTIFY_RevokeAll_request,
	  dissect_FMP_NOTIFY_RevokeAll_reply },

	{ FMP_NOTIFY_FileSetEof,			"FileSetEof",
	  dissect_FMP_NOTIFY_FileSetEof_request,
	  dissect_FMP_NOTIFY_FileSetEof_reply },

	{ FMP_NOTIFY_RequestDone,			"RequestDone",
	  dissect_FMP_NOTIFY_RequestDone_request,
	  dissect_FMP_NOTIFY_RequestDone_reply },

	{ FMP_NOTIFY_volFreeze,				"volFreeze",
	  dissect_FMP_NOTIFY_volFreeze_request,
	  dissect_FMP_NOTIFY_volFreeze_reply },

	{ FMP_NOTIFY_revokeHandleList,			"revokeHandleList",
	  dissect_FMP_NOTIFY_revokeHandleList_request,
	  dissect_FMP_NOTIFY_revokeHandleList_reply },

	{ 0,		NULL,		NULL,		NULL }
};

static const value_string fmp_notify_proc_vals[] = {
        { 1,    "DownGrade" },
        { 2,    "RevokeList" },
        { 3,    "RevokeAll" },
        { 4,    "FileSetEof" },
        { 5,    "RequestDone" },
        { 6,    "VolFreeze" },
        { 7,    "RevokeHandleList" },
        { 0,    "NULL" },
        { 0,NULL}
};


static const value_string fmp_status_vals[] = {
        {0,"OK"},
        {5,"IOERROR"},
        {12,"NOMEM"},
        {13,"NOACCESS"},
        {22,"INVALIDARG"},
        {28,"FSFULL"},
        {79,"QUEUE_FULL"},
        {500,"WRONG_MSG_NUM"},
        {501,"SESSION_LOST"},
        {502,"HOT_SESSION"},
        {503,"COLD_SESSION"},
        {504,"CLIENT_TERMINATED"},
        {505,"WRITER_LOST_BLK"},
        {506,"FMP_REQUEST_QUEUED"},
        {507,"FMP_FALL_BACK"},
        {508,"REQUEST_CANCELLED"},
        {509,"WRITER_ZEROED_BLK"},
        {510,"NOTIFY_ERROR"},
        {511,"FMP_WRONG_HANDLE"},
        {512,"DUPLICATE_OPEN"},
        {600,"PLUGIN_NOFUNC"},
	{0,NULL}

};


void
proto_register_fmp_notify(void)
{
	static hf_register_info hf[] = {
		{ &hf_fmp_notify_procedure, {
                        "Procedure", "fmp_notify.notify_procedure", FT_UINT32, BASE_DEC,
                        VALS(fmp_notify_proc_vals) , 0, NULL, HFILL }},        /* New addition */

		{ &hf_fmp_status, {
                        "Status", "fmp_notify.status", FT_UINT32, BASE_DEC,
                        VALS(fmp_status_vals), 0, "Reply Status", HFILL }},


		{ &hf_fmp_handleListLen, {
			"Number File Handles", "fmp_notify.handleListLength",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Number of File Handles", HFILL }},


		{ &hf_fmp_sessionHandle, {
                        "Session Handle", "fmp_notify.sessHandle", FT_BYTES, BASE_NONE,
                        NULL, 0, "FMP Session Handle", HFILL }},


                { &hf_fmp_fsID, {
                        "File System ID", "fmp_notify.fsID", FT_UINT32, BASE_HEX,
                        NULL, 0, NULL, HFILL }},

                { &hf_fmp_fsBlkSz, {
                        "FS Block Size", "fmp_notify.fsBlkSz", FT_UINT32, BASE_DEC,
                        NULL, 0, "File System Block Size", HFILL }},


                { &hf_fmp_numBlksReq, {
                        "Number Blocks Requested", "fmp_notify.numBlksReq", FT_UINT32,
                        BASE_DEC, NULL, 0, NULL, HFILL }},


                { &hf_fmp_msgNum, {
                        "Message Number", "fmp_notify.msgNum", FT_UINT32, BASE_DEC,
                        NULL, 0, "FMP Message Number", HFILL }},

                { &hf_fmp_cookie, {
                        "Cookie", "fmp_notify.cookie", FT_UINT32, BASE_HEX,
                        NULL, 0, "Cookie for FMP_REQUEST_QUEUED Resp", HFILL }},


                { &hf_fmp_firstLogBlk, {
                        "First Logical Block", "fmp_notify.firstLogBlk", FT_UINT32,
                        BASE_DEC, NULL, 0, "First Logical File Block", HFILL }},


                { &hf_fmp_fileSize, {
                        "File Size", "fmp_notify.fileSize", FT_UINT64, BASE_DEC,
                        NULL, 0, NULL, HFILL }},

		 { &hf_fmp_fmpFHandle, {
                        "FMP File Handle", "fmp_notify.fmpFHandle",
                        FT_BYTES, BASE_NONE, NULL, 0, NULL,
                        HFILL }},



	};

	static gint *ett[] = {
		&ett_fmp_notify,
		&ett_fmp_notify_hlist,
		&ett_fmp_extList,
		&ett_fmp_ext
	};

	proto_fmp_notify =
		proto_register_protocol("File Mapping Protocol Nofity",
		                        "FMP/NOTIFY", "fmp_notify");
	proto_register_field_array(proto_fmp_notify, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}

void
proto_reg_handoff_fmp_notify(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_fmp_notify, FMP_NOTIFY_PROG, ett_fmp_notify);

	/* Register the procedure tables */
	rpc_init_proc_table(FMP_NOTIFY_PROG, FMP_NOTIFY_VERSION_2,
	                    fmp_notify2_proc,hf_fmp_notify_procedure);
}


static int
dissect_fmp_notify_extentState(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_fmp_extent_state,
	                            offset);

	return offset;
}

static int
dissect_fmp_notify_extent(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
                   proto_tree *tree, guint32 ext_num)
{
	proto_item *extItem;
	proto_tree *extTree;

	extItem = proto_tree_add_text(tree, tvb, offset, 20 ,
	                              "Extent (%u)", (guint32) ext_num);


	extTree = proto_item_add_subtree(extItem, ett_fmp_ext);

	offset = dissect_rpc_uint32(tvb,  extTree, hf_fmp_firstLogBlk,
	                            offset);
	offset = dissect_rpc_uint32(tvb, extTree, hf_fmp_numBlks,
	                            offset);
	offset = dissect_rpc_uint32(tvb, extTree, hf_fmp_volID, offset);
	offset = dissect_rpc_uint32(tvb, extTree, hf_fmp_startOffset,
	                            offset);
	offset = dissect_fmp_notify_extentState(tvb, offset, extTree);

	return offset;
}


static int
dissect_fmp_notify_extentList(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
                       proto_tree *tree)
{
	guint32 numExtents;
	guint32 totalLength;
	proto_item *extListItem;
	proto_tree *extListTree;
	guint32 i;

	numExtents = tvb_get_ntohl(tvb, offset);
	totalLength = 4 + (20 * numExtents);

	extListItem =  proto_tree_add_text(tree, tvb, offset, totalLength,
	                                   "Extent List");
	extListTree = proto_item_add_subtree(extListItem, ett_fmp_extList);

	offset = dissect_rpc_uint32(tvb, extListTree,
	                            hf_fmp_extentList_len, offset);

	for (i = 1; i <= numExtents; i++) {
		offset = dissect_fmp_notify_extent(tvb, offset, pinfo, extListTree, i);
	}

	return offset;
}
