/* packet-gluster_glusterd.c
 * Routines for Gluster Daemon Management dissection
 * Copyright 2012, Niels de Vos <ndevos@redhat.com>
 * With contributions from:
 *    Shreedhara LG <shreedharlg@gmail.com>
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

#include "packet-rpc.h"
#include "packet-gluster.h"

void proto_register_gluster_gd_mgmt(void);
void proto_reg_handoff_gluster_gd_mgmt(void);

/* Initialize the protocol and registered fields */
static gint proto_glusterd = -1;
static gint proto_gd_mgmt = -1;
static gint proto_gd_brick = -1;
static gint proto_gd_friend = -1;

/* programs and procedures */
static gint hf_gd_mgmt_proc = -1;
static gint hf_gd_mgmt_2_proc = -1;
static gint hf_gd_mgmt_3_proc = -1;
static gint hf_gd_mgmt_brick_2_proc = -1;
static gint hf_glusterd_friend_proc = -1;

/* fields used by multiple programs/procedures */
static gint hf_glusterd_dict = -1;
static gint hf_glusterd_op = -1;
static gint hf_glusterd_op_ret = -1;
static gint hf_glusterd_op_errstr = -1;
static gint hf_glusterd_uuid = -1;
static gint hf_glusterd_tnx_id = -1;
static gint hf_glusterd_hostname = -1;
static gint hf_glusterd_port = -1;
static gint hf_glusterd_vols = -1;
static gint hf_glusterd_buf = -1;
static gint hf_glusterd_name = -1;

/* Initialize the subtree pointers */
static gint ett_gd_mgmt = -1;
static gint ett_gd_brick = -1;
static gint ett_gd_friend = -1;

/* the UUID is the same as a GlusterFS GFID, except it's encoded per byte */
static int
gluster_gd_mgmt_dissect_uuid(tvbuff_t *tvb, proto_tree *tree, int hfindex,
								int offset)
{
	if (tree) {
		e_guid_t uuid;
		int start_offset = offset;

		uuid.data1 = (tvb_get_ntohl(tvb, offset)    & 0xff) << 24 |
		             (tvb_get_ntohl(tvb, offset+4)  & 0xff) << 16 |
		             (tvb_get_ntohl(tvb, offset+8)  & 0xff) <<  8 |
		             (tvb_get_ntohl(tvb, offset+12) & 0xff);
		offset += 16;
		uuid.data2 = (tvb_get_ntohl(tvb, offset)   & 0xff) << 8 |
		             (tvb_get_ntohl(tvb, offset+4) & 0xff);
		offset += 8;
		uuid.data3 = (tvb_get_ntohl(tvb, offset)   & 0xff) << 8 |
		             (tvb_get_ntohl(tvb, offset+4) & 0xff);
		offset += 8;
		uuid.data4[0] = tvb_get_ntohl(tvb, offset);
		offset += 4;
		uuid.data4[1] = tvb_get_ntohl(tvb, offset);
		offset += 4;
		uuid.data4[2] = tvb_get_ntohl(tvb, offset);
		offset += 4;
		uuid.data4[3] = tvb_get_ntohl(tvb, offset);
		offset += 4;
		uuid.data4[4] = tvb_get_ntohl(tvb, offset);
		offset += 4;
		uuid.data4[5] = tvb_get_ntohl(tvb, offset);
		offset += 4;
		uuid.data4[6] = tvb_get_ntohl(tvb, offset);
		offset += 4;
		uuid.data4[7] = tvb_get_ntohl(tvb, offset);
		offset += 4;
		proto_tree_add_guid(tree, hfindex, tvb, start_offset, 4*16, &uuid);
	} else
		offset += 16 * 4;

	return offset;
}

static int
gluster_gd_mgmt_probe_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree, void* data _U_)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_glusterd_uuid,
								offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterd_hostname, offset,
								NULL);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterd_port, offset);
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);

	return offset;
}

static int
gluster_gd_mgmt_probe_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
							proto_tree *tree, void* data _U_)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_glusterd_uuid,
								offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterd_hostname, offset,
								NULL);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterd_port, offset);

	return offset;
}

static int
gluster_gd_mgmt_friend_add_reply(tvbuff_t *tvb, int offset,
					packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_glusterd_uuid,
								offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterd_hostname, offset,
								NULL);
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterd_port, offset);

	return offset;
}

static int
gluster_gd_mgmt_friend_add_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_glusterd_uuid,
								offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterd_hostname, offset,
								NULL);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterd_port, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterd_vols, offset);

	return offset;
}

/* gluster_gd_mgmt_cluster_lock_reply is used for LOCK and UNLOCK */
static int
gluster_gd_mgmt_cluster_lock_reply(tvbuff_t *tvb, int offset,
					packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_glusterd_uuid,
								offset);
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);

	return offset;
}

/* gluster_gd_mgmt_cluster_lock_call is used for LOCK and UNLOCK */
static int
gluster_gd_mgmt_cluster_lock_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_glusterd_uuid,
								offset);

	return offset;
}

static int
gluster_gd_mgmt_stage_op_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree, void* data _U_)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_glusterd_uuid,
								offset);
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = dissect_rpc_string(tvb, tree, hf_glusterd_op_errstr, offset,
								NULL);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterd_dict, offset);
	return offset;
}

static int
gluster_gd_mgmt_stage_op_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_,	proto_tree *tree, void* data _U_)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_glusterd_uuid,
								offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterd_op, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterd_dict, offset);

	return offset;
}

static int
gluster_gd_mgmt_commit_op_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree, void* data _U_)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_glusterd_uuid,
								offset);
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterd_buf, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterd_op_errstr, offset,
								NULL);
	return offset;
}

static int
gluster_gd_mgmt_commit_op_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_glusterd_uuid,
								offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterd_op, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterd_buf,
								offset);

	return offset;
}

static int
gluster_gd_mgmt_friend_update_reply(tvbuff_t *tvb, int offset,
					packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_glusterd_uuid,
								offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterd_op, offset);
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);

	return offset;
}

static int
gluster_gd_mgmt_friend_update_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_glusterd_uuid,
								offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterd_vols,
								offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterd_port, offset);

	return offset;
}

/* Below procedure is used for version 2 */
static int
glusterd_mgmt_2_cluster_lock_reply(tvbuff_t *tvb, int offset,
					packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_glusterd_uuid,
								offset);
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);

	return offset;
}

/* glusterd__mgmt_2_cluster_lock_call is used for LOCK and UNLOCK */
static int
glusterd_mgmt_2_cluster_lock_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_glusterd_uuid,
								offset);

	return offset;
}

static int
glusterd_mgmt_2_stage_op_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree, void* data _U_)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_glusterd_uuid,
								offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterd_op, offset);
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = dissect_rpc_string(tvb, tree, hf_glusterd_op_errstr, offset,
								NULL);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterd_dict, offset);

	return offset;
}

static int
glusterd_mgmt_2_stage_op_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_glusterd_uuid,
								offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterd_op, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterd_dict, offset);

	return offset;
}

static int
glusterd_mgmt_2_commit_op_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree, void* data _U_)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_glusterd_uuid,
								offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterd_op, offset);
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterd_buf, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterd_op_errstr, offset,
								NULL);

	return offset;
}

static int
glusterd_mgmt_2_commit_op_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_glusterd_uuid,
								offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterd_op, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterd_buf, offset);

	return offset;
}

/* glusterd_mgmt_3_lock_call is used for LOCK and UNLOCK */
static int
glusterd_mgmt_3_lock_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
					proto_tree *tree, void* data _U_)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_glusterd_uuid,
								offset);
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_glusterd_tnx_id,
								offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterd_op, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterd_dict, offset);

	return offset;
}

static int
glusterd_mgmt_3_lock_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
					proto_tree *tree, void* data _U_)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_glusterd_uuid,
								offset);
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_glusterd_tnx_id,
								offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterd_dict, offset);
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	return offset;
}

static int
glusterd_mgmt_3_pre_val_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_,	proto_tree *tree, void* data _U_)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_glusterd_uuid,
								offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterd_op, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterd_dict, offset);

	return offset;
}

static int
glusterd_mgmt_3_pre_val_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree, void* data _U_)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_glusterd_uuid,
								offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterd_op, offset);
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = dissect_rpc_string(tvb, tree, hf_glusterd_op_errstr, offset,
								NULL);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterd_dict, offset);
	return offset;
}

static int
glusterd_mgmt_3_commit_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree, void* data _U_)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_glusterd_uuid,
								offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterd_op, offset);
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterd_dict, offset);
	offset = dissect_rpc_string(tvb, tree, hf_glusterd_op_errstr, offset,
								NULL);
	return offset;
}

static int
glusterd_mgmt_3_post_val_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_,	proto_tree *tree, void* data _U_)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_glusterd_uuid,
								offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterd_op, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterd_op_ret, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterd_dict, offset);

	return offset;
}


/* Brick management common function */

static int
glusterd_brick_2_common_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree, void* data _U_)
{
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = dissect_rpc_string(tvb, tree, hf_glusterd_op_errstr, offset,
								NULL);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterd_dict, offset);

	return offset;
}

static int
glusterd_brick_2_common_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	offset = dissect_rpc_string(tvb, tree, hf_glusterd_name, offset,
									NULL);
	offset = dissect_rpc_uint32(tvb, tree, hf_glusterd_op, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_glusterd_dict, offset);

	return offset;
}

/*
 * GD_MGMT_PROGRAM
 * - xlators/mgmt/glusterd/src/glusterd-handler.c: "GlusterD svc mgmt"
 * - xlators/mgmt/glusterd/src/glusterd-rpc-ops.c: "glusterd clnt mgmt"
 */
static const vsff gd_mgmt_proc[] = {
	{ GD_MGMT_NULL, "NULL", NULL, NULL },
	{
		GD_MGMT_PROBE_QUERY, "PROBE_QUERY",
		gluster_gd_mgmt_probe_call, gluster_gd_mgmt_probe_reply
	},
	{
		GD_MGMT_FRIEND_ADD, "FRIEND_ADD",
		gluster_gd_mgmt_friend_add_call,
		gluster_gd_mgmt_friend_add_reply
	},
	{
		GD_MGMT_CLUSTER_LOCK, "CLUSTER_LOCK",
		gluster_gd_mgmt_cluster_lock_call,
		gluster_gd_mgmt_cluster_lock_reply
	},
	{
		GD_MGMT_CLUSTER_UNLOCK, "CLUSTER_UNLOCK",
		/* UNLOCK seems to be the same a LOCK, re-use the function */
		gluster_gd_mgmt_cluster_lock_call,
		gluster_gd_mgmt_cluster_lock_reply
	},
	{
		GD_MGMT_STAGE_OP, "STAGE_OP",
		gluster_gd_mgmt_stage_op_call, gluster_gd_mgmt_stage_op_reply
	},
	{
		GD_MGMT_COMMIT_OP, "COMMIT_OP",
		gluster_gd_mgmt_commit_op_call, gluster_gd_mgmt_commit_op_reply
	},
	{ GD_MGMT_FRIEND_REMOVE, "FRIEND_REMOVE", NULL, NULL},
	{
		GD_MGMT_FRIEND_UPDATE, "FRIEND_UPDATE",
		gluster_gd_mgmt_friend_update_call,
		gluster_gd_mgmt_friend_update_reply
	},
	{ GD_MGMT_CLI_PROBE,          "CLI_PROBE",          NULL, NULL},
	{ GD_MGMT_CLI_DEPROBE,        "CLI_DEPROBE",        NULL, NULL},
	{ GD_MGMT_CLI_LIST_FRIENDS,   "CLI_LIST_FRIENDS",   NULL, NULL},
	{ GD_MGMT_CLI_CREATE_VOLUME,  "CLI_CREATE_VOLUME",  NULL, NULL},
	{ GD_MGMT_CLI_GET_VOLUME,     "CLI_GET_VOLUME",     NULL, NULL},
	{ GD_MGMT_CLI_DELETE_VOLUME,  "CLI_DELETE_VOLUME",  NULL, NULL},
	{ GD_MGMT_CLI_START_VOLUME,   "CLI_START_VOLUME",   NULL, NULL},
	{ GD_MGMT_CLI_STOP_VOLUME,    "CLI_STOP_VOLUME",    NULL, NULL},
	{ GD_MGMT_CLI_RENAME_VOLUME,  "CLI_RENAME_VOLUME",  NULL, NULL},
	{ GD_MGMT_CLI_DEFRAG_VOLUME,  "CLI_DEFRAG_VOLUME",  NULL, NULL},
	{ GD_MGMT_CLI_SET_VOLUME,     "CLI_DEFRAG_VOLUME",  NULL, NULL},
	{ GD_MGMT_CLI_ADD_BRICK,      "CLI_ADD_BRICK",      NULL, NULL},
	{ GD_MGMT_CLI_REMOVE_BRICK,   "CLI_REMOVE_BRICK",   NULL, NULL},
	{ GD_MGMT_CLI_REPLACE_BRICK,  "CLI_REPLACE_BRICK",  NULL, NULL},
	{ GD_MGMT_CLI_LOG_FILENAME,   "CLI_LOG_FILENAME",   NULL, NULL},
	{ GD_MGMT_CLI_LOG_LOCATE,     "CLI_LOG_LOCATE",     NULL, NULL},
	{ GD_MGMT_CLI_LOG_ROTATE,     "CLI_LOG_ROTATE",     NULL, NULL},
	{ GD_MGMT_CLI_SYNC_VOLUME,    "CLI_SYNC_VOLUME",    NULL, NULL},
	{ GD_MGMT_CLI_RESET_VOLUME,   "CLI_RESET_VOLUME",   NULL, NULL},
	{ GD_MGMT_CLI_FSM_LOG,        "CLI_FSM_LOG",        NULL, NULL},
	{ GD_MGMT_CLI_GSYNC_SET,      "CLI_GSYNC_SET",      NULL, NULL},
	{ GD_MGMT_CLI_PROFILE_VOLUME, "CLI_PROFILE_VOLUME", NULL, NULL},
	{ GD_MGMT_BRICK_OP,           "BRICK_OP",           NULL, NULL},
	{ GD_MGMT_CLI_LOG_LEVEL,      "CLI_LOG_LEVEL",      NULL, NULL},
	{ GD_MGMT_CLI_STATUS_VOLUME,  "CLI_STATUS_VOLUME",  NULL, NULL},
	{ 0, NULL, NULL, NULL}
};

static const vsff gd_mgmt_2_proc[] = {
	{ GLUSTERD_MGMT_2_NULL, "NULL", NULL, NULL},
	{
		GLUSTERD_MGMT_2_CLUSTER_LOCK, "CLUSTER_LOCK",
		glusterd_mgmt_2_cluster_lock_call,
		glusterd_mgmt_2_cluster_lock_reply
	},
	{
		GLUSTERD_MGMT_2_CLUSTER_UNLOCK, "CLUSTER_UNLOCK",
		/* UNLOCK seems to be the same a LOCK, re-use the function */
		glusterd_mgmt_2_cluster_lock_call,
		glusterd_mgmt_2_cluster_lock_reply
	},
	{
		GLUSTERD_MGMT_2_STAGE_OP, "STAGE_OP",
		glusterd_mgmt_2_stage_op_call, glusterd_mgmt_2_stage_op_reply
	},
	{
		GLUSTERD_MGMT_2_COMMIT_OP, "COMMIT_OP",
		glusterd_mgmt_2_commit_op_call, glusterd_mgmt_2_commit_op_reply
	},
	{ 0, NULL, NULL, NULL}
};

static const vsff gd_mgmt_3_proc[] = {
	{ GLUSTERD_MGMT_3_NULL, "NULL", NULL, NULL },
	{
		GLUSTERD_MGMT_3_LOCK, "LOCK",
		glusterd_mgmt_3_lock_call,
		glusterd_mgmt_3_lock_reply
	},
	{
		GLUSTERD_MGMT_3_PRE_VALIDATE, "PRE_VALIDATE",
		glusterd_mgmt_3_pre_val_call,
		glusterd_mgmt_3_pre_val_reply
	},
	{
		GLUSTERD_MGMT_3_BRICK_OP, "BRICK_OP",
		glusterd_mgmt_3_pre_val_call,
		glusterd_mgmt_3_pre_val_reply
	},
	{
		GLUSTERD_MGMT_3_COMMIT, "COMMIT",
		glusterd_mgmt_3_pre_val_call,
		glusterd_mgmt_3_commit_reply
	},
	{
		GLUSTERD_MGMT_3_POST_VALIDATE, "POST_VALIDATE",
		glusterd_mgmt_3_post_val_call,
		glusterd_mgmt_3_pre_val_reply
	},
	{
		GLUSTERD_MGMT_3_UNLOCK, "UNLOCK",
		/* UNLOCK seems to be the same a LOCK, re-use the function */
		glusterd_mgmt_3_lock_call,
		glusterd_mgmt_3_lock_reply
	},
	{ 0, NULL, NULL, NULL}
};

static const vsff gd_mgmt_brick_2_proc[] = {
	{ GLUSTERD_2_BRICK_NULL, "NULL", NULL , NULL },    /* 0 */
	{
		GLUSTERD_2_BRICK_TERMINATE, "TERMINATE",
		glusterd_brick_2_common_call, glusterd_brick_2_common_reply
	},
	{
		GLUSTERD_2_BRICK_XLATOR_INFO, "XLATOR_INFO",
		glusterd_brick_2_common_call, glusterd_brick_2_common_reply
	},
	{
		GLUSTERD_2_BRICK_XLATOR_OP, "XLATOR_OP" ,
		glusterd_brick_2_common_call, glusterd_brick_2_common_reply
	},
	{
		GLUSTERD_2_BRICK_STATUS, "STATUS",
		glusterd_brick_2_common_call, glusterd_brick_2_common_reply
	},
	{
		GLUSTERD_2_BRICK_OP, "OP",
		glusterd_brick_2_common_call, glusterd_brick_2_common_reply
	},
	{
		GLUSTERD_2_BRICK_XLATOR_DEFRAG, "XLATOR_DEFRAG",
		glusterd_brick_2_common_call, glusterd_brick_2_common_reply
	},
	{
		GLUSTERD_2_NODE_PROFILE, "NODE_PROFILE",
		glusterd_brick_2_common_call, glusterd_brick_2_common_reply
	},
	{
		GLUSTERD_2_NODE_STATUS, "NODE_STATUS",
		glusterd_brick_2_common_call, glusterd_brick_2_common_reply
	},
	{ 0, NULL, NULL, NULL }
};

static const vsff glusterd_friend_proc[] = {
	{ GLUSTERD_FRIEND_NULL,   "NULL" ,        NULL , NULL },
	{ GLUSTERD_PROBE_QUERY,   "PROBE_QUERY" , NULL , NULL },
	{ GLUSTERD_FRIEND_ADD,    "ADD" ,         NULL , NULL },
	{ GLUSTERD_FRIEND_REMOVE, "REMOVE",       NULL , NULL },
	{ GLUSTERD_FRIEND_UPDATE, "UPDATE" ,      NULL , NULL },
	{ 0, NULL, NULL, NULL }
};

static const value_string gd_mgmt_proc_vals[] = {
	{ GD_MGMT_NULL,               "NULL" },
	{ GD_MGMT_PROBE_QUERY,        "PROBE_QUERY" },
	{ GD_MGMT_FRIEND_ADD,         "FRIEND_ADD" },
	{ GD_MGMT_CLUSTER_LOCK,       "CLUSTER_LOCK" },
	{ GD_MGMT_CLUSTER_UNLOCK,     "CLUSTER_UNLOCK" },
	{ GD_MGMT_STAGE_OP,           "STAGE_OP" },
	{ GD_MGMT_COMMIT_OP,          "COMMIT_OP" },
	{ GD_MGMT_FRIEND_REMOVE,      "FRIEND_REMOVE" },
	{ GD_MGMT_FRIEND_UPDATE,      "FRIEND_UPDATE" },
	{ GD_MGMT_CLI_PROBE,          "CLI_PROBE" },
	{ GD_MGMT_CLI_DEPROBE,        "CLI_DEPROBE" },
	{ GD_MGMT_CLI_LIST_FRIENDS,   "CLI_LIST_FRIENDS" },
	{ GD_MGMT_CLI_CREATE_VOLUME,  "CLI_CREATE_VOLUME" },
	{ GD_MGMT_CLI_GET_VOLUME,     "CLI_GET_VOLUME" },
	{ GD_MGMT_CLI_DELETE_VOLUME,  "CLI_DELETE_VOLUME" },
	{ GD_MGMT_CLI_START_VOLUME,   "CLI_START_VOLUME" },
	{ GD_MGMT_CLI_STOP_VOLUME,    "CLI_STOP_VOLUME" },
	{ GD_MGMT_CLI_RENAME_VOLUME,  "CLI_RENAME_VOLUME" },
	{ GD_MGMT_CLI_DEFRAG_VOLUME,  "CLI_DEFRAG_VOLUME" },
	{ GD_MGMT_CLI_SET_VOLUME,     "CLI_DEFRAG_VOLUME" },
	{ GD_MGMT_CLI_ADD_BRICK,      "CLI_ADD_BRICK" },
	{ GD_MGMT_CLI_REMOVE_BRICK,   "CLI_REMOVE_BRICK" },
	{ GD_MGMT_CLI_REPLACE_BRICK,  "CLI_REPLACE_BRICK" },
	{ GD_MGMT_CLI_LOG_FILENAME,   "CLI_LOG_FILENAME" },
	{ GD_MGMT_CLI_LOG_LOCATE,     "CLI_LOG_LOCATE" },
	{ GD_MGMT_CLI_LOG_ROTATE,     "CLI_LOG_ROTATE" },
	{ GD_MGMT_CLI_SYNC_VOLUME,    "CLI_SYNC_VOLUME" },
	{ GD_MGMT_CLI_RESET_VOLUME,   "CLI_RESET_VOLUME" },
	{ GD_MGMT_CLI_FSM_LOG,        "CLI_FSM_LOG" },
	{ GD_MGMT_CLI_GSYNC_SET,      "CLI_GSYNC_SET" },
	{ GD_MGMT_CLI_PROFILE_VOLUME, "CLI_PROFILE_VOLUME" },
	{ GD_MGMT_BRICK_OP,           "BRICK_OP" },
	{ GD_MGMT_CLI_LOG_LEVEL,      "CLI_LOG_LEVEL" },
	{ GD_MGMT_CLI_STATUS_VOLUME,  "CLI_STATUS_VOLUME" },
	{ 0, NULL }
};
static value_string_ext gd_mgmt_proc_vals_ext = VALUE_STRING_EXT_INIT(gd_mgmt_proc_vals);

static const value_string gd_mgmt_2_proc_vals[] = {
	{ GLUSTERD_MGMT_2_NULL,           "NULL" },
	{ GLUSTERD_MGMT_2_CLUSTER_LOCK,   "CLUSTER_LOCK" },
	{ GLUSTERD_MGMT_2_CLUSTER_UNLOCK, "CLUSTER_UNLOCK" },
	{ GLUSTERD_MGMT_2_STAGE_OP,       "STAGE_OP"},
	{ GLUSTERD_MGMT_2_COMMIT_OP,      "COMMIT_OP"},
	{ 0, NULL }
};
static value_string_ext gd_mgmt_2_proc_vals_ext = VALUE_STRING_EXT_INIT(gd_mgmt_2_proc_vals);

static const value_string gd_mgmt_3_proc_vals[] = {
	{ GLUSTERD_MGMT_3_NULL,           "NULL" },
	{ GLUSTERD_MGMT_3_LOCK,           "LOCK" },
	{ GLUSTERD_MGMT_3_UNLOCK,         "UNLOCK" },
	{ 0, NULL }
};
static value_string_ext gd_mgmt_3_proc_vals_ext = VALUE_STRING_EXT_INIT(gd_mgmt_3_proc_vals);

static const value_string gd_mgmt_brick_2_proc_vals[] = {
	{ GLUSTERD_2_BRICK_NULL,          "NULL" },    /* 0 */
	{ GLUSTERD_2_BRICK_TERMINATE,     "TERMINATE" },
	{ GLUSTERD_2_BRICK_XLATOR_INFO,   "XLATOR_INFO" },
	{ GLUSTERD_2_BRICK_XLATOR_OP,     "XLATOR_OP" },
	{ GLUSTERD_2_BRICK_STATUS,        "STATUS" },
	{ GLUSTERD_2_BRICK_OP,            "OP" },
	{ GLUSTERD_2_BRICK_XLATOR_DEFRAG, "XLATOR_DEFRAG" },
	{ GLUSTERD_2_NODE_PROFILE,        "NODE_PROFILE" },
	{ GLUSTERD_2_NODE_STATUS,         "NODE_PROFILE" },
	{ 0, NULL }
};
static value_string_ext gd_mgmt_brick_2_proc_vals_ext = VALUE_STRING_EXT_INIT(gd_mgmt_brick_2_proc_vals);

static const value_string glusterd_op_vals[] = {
	{ GD_OP_NONE,                "NONE" },
	{ GD_OP_CREATE_VOLUME,       "CREATE_VOLUME" },
	{ GD_OP_START_BRICK,         "START_BRICK" },
	{ GD_OP_STOP_BRICK,          "STOP_BRICK" },
	{ GD_OP_DELETE_VOLUME,       "DELETE_VOLUME" },
	{ GD_OP_START_VOLUME,        "START_VOLUME" },
	{ GD_OP_STOP_VOLUME,         "STOP_VOLUME" },
	{ GD_OP_DEFRAG_VOLUME,       "DEFRAG_VOLUME" },
	{ GD_OP_ADD_BRICK,           "ADD_BRICK" },
	{ GD_OP_REMOVE_BRICK,        "REMOVE_BRICK" },
	{ GD_OP_REPLACE_BRICK,       "REPLACE_BRICK" },
	{ GD_OP_SET_VOLUME,          "SET_VOLUME" },
	{ GD_OP_RESET_VOLUME,        "RESET_VOLUME" },
	{ GD_OP_SYNC_VOLUME,         "SYNC_VOLUME" },
	{ GD_OP_LOG_ROTATE,          "LOG_ROTATE" },
	{ GD_OP_GSYNC_SET,           "GSYNC_SET" },
	{ GD_OP_PROFILE_VOLUME,      "PROFILE_VOLUME" },
	{ GD_OP_QUOTA,               "QUOTA" },
	{ GD_OP_STATUS_VOLUME,       "STATUS_VOLUME" },
	{ GD_OP_REBALANCE,           "REBALANCE" },
	{ GD_OP_HEAL_VOLUME,         "HEAL_VOLUME" },
	{ GD_OP_STATEDUMP_VOLUME,    "STATEDUMP_VOLUME" },
	{ GD_OP_LIST_VOLUME,         "LIST_VOLUME" },
	{ GD_OP_CLEARLOCKS_VOLUME,   "CLEARLOCKS_VOLUME" },
	{ GD_OP_DEFRAG_BRICK_VOLUME, "DEFRAG_BRICK_VOLUME" },
	{ GD_OP_COPY_FILE,           "Copy File" },
	{ GD_OP_SYS_EXEC,            "Execute system commands" },
	{ GD_OP_GSYNC_CREATE,        "Geo-replication Create" },
	{ GD_OP_SNAP,                "Snapshot" },
	{ 0, NULL }
};
static value_string_ext glusterd_op_vals_ext = VALUE_STRING_EXT_INIT(glusterd_op_vals);

static const value_string glusterd_friend_proc_vals[] = {
	{ GLUSTERD_FRIEND_NULL,   "NULL" },
	{ GLUSTERD_PROBE_QUERY,   "PROBE_QUERY" },
	{ GLUSTERD_FRIEND_ADD,    "ADD" },
	{ GLUSTERD_FRIEND_REMOVE, "REMOVE" },
	{ GLUSTERD_FRIEND_UPDATE, "UPDATE" },
	{ 0, NULL }
};
static value_string_ext glusterd_friend_proc_vals_ext = VALUE_STRING_EXT_INIT(glusterd_friend_proc_vals);

void
proto_register_gluster_gd_mgmt(void)
{
	/* Setup list of header fields  See Section 1.6.1 for details */
	static hf_register_info hf[] = {
		/* programs */
		{ &hf_gd_mgmt_proc,
			{ "Gluster Daemon Management", "glusterd.mgmt.proc",
				FT_UINT32, BASE_DEC | BASE_EXT_STRING, &gd_mgmt_proc_vals_ext,
				0, NULL, HFILL }
		},
		{ &hf_gd_mgmt_2_proc,
			{ "Gluster Daemon Management", "glusterd.mgmt.proc",
				FT_UINT32, BASE_DEC | BASE_EXT_STRING, &gd_mgmt_2_proc_vals_ext,
				0, NULL, HFILL }
		},
		{ &hf_gd_mgmt_3_proc,
			{ "Gluster Daemon Management", "glusterd.mgmt.proc",
				FT_UINT32, BASE_DEC | BASE_EXT_STRING, &gd_mgmt_3_proc_vals_ext,
				0, NULL, HFILL }
		},
		{ &hf_gd_mgmt_brick_2_proc,
			{ "Gluster Daemon Brick Operations",
				"glusterd.brick.proc", FT_UINT32, BASE_DEC | BASE_EXT_STRING,
				&gd_mgmt_brick_2_proc_vals_ext, 0, NULL,
				HFILL }
		},
		{ &hf_glusterd_friend_proc ,
			{ "Gluster Daemon Friend Operations",
				"glusterd.friend.proc", FT_UINT32, BASE_DEC | BASE_EXT_STRING,
				&glusterd_friend_proc_vals_ext, 0, NULL,
				HFILL }
		},
		{ &hf_glusterd_dict,
			{ "Dict", "glusterd.dict", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterd_op,
			{ "Operation", "glusterd.op", FT_UINT32, BASE_DEC | BASE_EXT_STRING,
				&glusterd_op_vals_ext, 0, NULL, HFILL }
		},
		{ &hf_glusterd_op_ret,
			{ "Return of previous operation", "glusterd.op_ret",
				FT_UINT32, BASE_DEC, NULL , 0, NULL, HFILL }
		},
		{ &hf_glusterd_op_errstr,
			{ "Error", "glusterd.op_errstr", FT_STRING,
				BASE_NONE, NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterd_uuid,
			{ "UUID", "glusterd.uuid", FT_GUID,
				BASE_NONE, NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterd_tnx_id,
			{ "Transaction ID", "glusterd.tnx_id", FT_GUID,
				BASE_NONE, NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterd_hostname,
			{ "Hostname", "glusterd.hostname", FT_STRING,
				BASE_NONE, NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterd_port,
			{ "Port", "glusterd.port", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterd_vols,
			{ "Volumes", "glusterd.vols", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterd_buf,
			{ "Buffer", "glusterd.buffer", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_glusterd_name,
			{ "Name", "glusterd.name", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_gd_mgmt,
		&ett_gd_brick,
		&ett_gd_friend
	};

	/* Register the protocol name and description */
	proto_glusterd = proto_register_protocol("Gluster Daemon", "GlusterD",
								"glusterd");
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_glusterd, hf, array_length(hf));

	proto_gd_mgmt = proto_register_protocol("Gluster Daemon Management",
					"GlusterD Management", "glusterd.mgmt");
	proto_gd_brick = proto_register_protocol(
					"Gluster Daemon Brick Operations",
					"GlusterD Brick", "glusterd.brick");
	proto_gd_friend = proto_register_protocol(
					"Gluster Daemon Friend Operations",
					"GlusterD Friend", "glusterd.friend");
}

void
proto_reg_handoff_gluster_gd_mgmt(void)
{
	rpc_init_prog(proto_gd_mgmt, GD_MGMT_PROGRAM, ett_gd_mgmt);
	rpc_init_proc_table(GD_MGMT_PROGRAM, 1, gd_mgmt_proc, hf_gd_mgmt_proc);
	rpc_init_proc_table(GD_MGMT_PROGRAM, 2, gd_mgmt_2_proc,
							hf_gd_mgmt_2_proc);
	rpc_init_proc_table(GD_MGMT_PROGRAM, 3, gd_mgmt_3_proc,
							hf_gd_mgmt_3_proc);

	rpc_init_prog(proto_gd_brick, GD_BRICK_PROGRAM, ett_gd_brick);
	rpc_init_proc_table(GD_BRICK_PROGRAM, 2, gd_mgmt_brick_2_proc,
						hf_gd_mgmt_brick_2_proc);
	rpc_init_prog(proto_gd_friend, GD_FRIEND_PROGRAM, ett_gd_friend);
	rpc_init_proc_table(GD_FRIEND_PROGRAM, 2,glusterd_friend_proc,
						hf_glusterd_friend_proc);
}
