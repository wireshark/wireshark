/* packet-gluster_cli.c
 * Routines for Gluster CLI dissection
 * Copyright 2012, Niels de Vos <ndevos@redhat.com>
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

void proto_register_gluster_cli(void);
void proto_reg_handoff_gluster_cli(void);

/* Initialize the protocol and registered fields */
static gint proto_gluster_cli = -1;

/* programs and procedures */
static gint hf_gluster_cli_proc = -1;
static gint hf_gluster_cli_2_proc = -1;
static gint hf_gluster_dict = -1;
static gint hf_gluster_path = -1;
static gint hf_gluster_lazy = -1;
static gint hf_gluster_label = -1;
static gint hf_gluster_unused = -1;
static gint hf_gluster_wd= -1;
static gint hf_gluster_op_errstr= -1;
static gint hf_gluster_hostname = -1;
static gint hf_gluster_port = -1;
static gint hf_gluster_flags = -1;

/* Initialize the subtree pointers */
static gint ett_gluster_cli = -1;

/* CLI Operations */
static int
gluster_cli_2_common_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_dict, offset);

	return offset;
}

static int
gluster_cli_2_common_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree, void* data _U_)
{
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_op_errstr, offset,
								NULL);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_dict, offset);

	return offset;
}

static int
gluster_cli_2_probe_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree, void* data _U_)
{
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_port, offset);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_hostname, offset,
								NULL);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_op_errstr, offset,
								NULL);

	return offset;
}

static int
gluster_cli_2_probe_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	offset = dissect_rpc_string(tvb, tree, hf_gluster_hostname, offset,
								NULL);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_port, offset);

	return offset;
}

static int
gluster_cli_2_deprobe_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree, void* data _U_)
{
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_hostname, offset,
								NULL);

	return offset;
}

static int
gluster_cli_2_deprobe_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	offset = dissect_rpc_string(tvb, tree, hf_gluster_hostname, offset,
								NULL);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_port, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_flags, offset);

	return offset;
}

static int
gluster_cli_2_fsm_log_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	offset = dissect_rpc_string(tvb, tree, hf_gluster_wd, offset, NULL);

	return offset;
}

static int
gluster_cli_2_getwd_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree, void* data _U_)
{
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_wd, offset, NULL);

	return offset;
}

static int
gluster_cli_2_getwd_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_unused, offset);

	return offset;
}

static int
gluster_cli_2_mount_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	offset = dissect_rpc_string(tvb, tree, hf_gluster_label, offset,
								NULL);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_dict, offset);

	return offset;
}

static int
gluster_cli_2_mount_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
							proto_tree *tree, void* data _U_)
{
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_path, offset, NULL);

	return offset;
}

static int
gluster_cli_2_umount_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_lazy, offset);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_path, offset, NULL);

	return offset;
}

/* procedures for GLUSTER_CLI_PROGRAM */
static const vsff gluster_cli_proc[] = {
	{ GLUSTER_CLI_NULL,             "NULL",             NULL, NULL },
	{ GLUSTER_CLI_PROBE,            "PROBE",            NULL, NULL },
	{ GLUSTER_CLI_DEPROBE,          "DEPROBE",          NULL, NULL },
	{ GLUSTER_CLI_LIST_FRIENDS,     "LIST_FRIENDS",     NULL, NULL },
	{ GLUSTER_CLI_CREATE_VOLUME,    "CREATE_VOLUME",    NULL, NULL },
	{ GLUSTER_CLI_GET_VOLUME,       "GET_VOLUME",       NULL, NULL },
	{ GLUSTER_CLI_GET_NEXT_VOLUME,  "GET_NEXT_VOLUME",  NULL, NULL },
	{ GLUSTER_CLI_DELETE_VOLUME,    "DELETE_VOLUME",    NULL, NULL },
	{ GLUSTER_CLI_START_VOLUME,     "START_VOLUME",     NULL, NULL },
	{ GLUSTER_CLI_STOP_VOLUME,      "STOP_VOLUME",      NULL, NULL },
	{ GLUSTER_CLI_RENAME_VOLUME,    "RENAME_VOLUME",    NULL, NULL },
	{ GLUSTER_CLI_DEFRAG_VOLUME,    "DEFRAG_VOLUME",    NULL, NULL },
	{ GLUSTER_CLI_SET_VOLUME,       "SET_VOLUME",       NULL, NULL },
	{ GLUSTER_CLI_ADD_BRICK,        "ADD_BRICK",        NULL, NULL },
	{ GLUSTER_CLI_REMOVE_BRICK,     "REMOVE_BRICK",     NULL, NULL },
	{ GLUSTER_CLI_REPLACE_BRICK,    "REPLACE_BRICK",    NULL, NULL },
	{ GLUSTER_CLI_LOG_FILENAME,     "LOG_FILENAME",     NULL, NULL },
	{ GLUSTER_CLI_LOG_LOCATE,       "LOG_LOCATE",       NULL, NULL },
	{ GLUSTER_CLI_LOG_ROTATE,       "LOG_ROTATE",       NULL, NULL },
	{ GLUSTER_CLI_GETSPEC,          "GETSPEC",          NULL, NULL },
	{ GLUSTER_CLI_PMAP_PORTBYBRICK, "PMAP_PORTBYBRICK", NULL, NULL },
	{ GLUSTER_CLI_SYNC_VOLUME,      "SYNC_VOLUME",      NULL, NULL },
	{ GLUSTER_CLI_RESET_VOLUME,     "RESET_VOLUME",     NULL, NULL },
	{ GLUSTER_CLI_FSM_LOG,          "FSM_LOG",          NULL, NULL },
	{ GLUSTER_CLI_GSYNC_SET,        "GSYNC_SET",        NULL, NULL },
	{ GLUSTER_CLI_PROFILE_VOLUME,   "PROFILE_VOLUME",   NULL, NULL },
	{ GLUSTER_CLI_QUOTA,            "QUOTA",            NULL, NULL },
	{ GLUSTER_CLI_TOP_VOLUME,       "TOP_VOLUME",       NULL, NULL },
	{ GLUSTER_CLI_GETWD,            "GETWD",            NULL, NULL },
	{ GLUSTER_CLI_LOG_LEVEL,        "LOG_LEVEL",        NULL, NULL },
	{ GLUSTER_CLI_STATUS_VOLUME,    "STATUS_VOLUME",    NULL, NULL },
	{ GLUSTER_CLI_MOUNT,            "MOUNT",            NULL, NULL },
	{ GLUSTER_CLI_UMOUNT,           "UMOUNT",           NULL, NULL },
	{ GLUSTER_CLI_HEAL_VOLUME,      "HEAL_VOLUME",      NULL, NULL },
	{ GLUSTER_CLI_STATEDUMP_VOLUME, "STATEDUMP_VOLUME", NULL, NULL },
	{ 0, NULL, NULL, NULL }
};

/* procedures for GLUSTER_CLI_PROGRAM  version 2*/
static const vsff gluster_cli_2_proc[] = {
	{
		GLUSTER_CLI_2_NULL, "NULL",
		gluster_cli_2_common_call, gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_PROBE, "PROBE",
		gluster_cli_2_probe_call, gluster_cli_2_probe_reply
	},
	{
		GLUSTER_CLI_2_DEPROBE, "DEPROBE",
		gluster_cli_2_deprobe_call, gluster_cli_2_deprobe_reply
	},
	{
		GLUSTER_CLI_2_LIST_FRIENDS, "LIST_FRIENDS",
		gluster_cli_2_common_call, gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_CREATE_VOLUME, "CREATE_VOLUME",
		gluster_cli_2_common_call, gluster_cli_2_common_reply
	},
	{
       		GLUSTER_CLI_2_GET_VOLUME, "GET_VOLUME",
		gluster_cli_2_common_call, gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_GET_NEXT_VOLUME, "GET_NEXT_VOLUME",
		gluster_cli_2_common_call, gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_DELETE_VOLUME, "DELETE_VOLUME",
		gluster_cli_2_common_call, gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_START_VOLUME, "START_VOLUME",
		gluster_cli_2_common_call, gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_STOP_VOLUME, "STOP_VOLUME",
		gluster_cli_2_common_call, gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_RENAME_VOLUME, "RENAME_VOLUME",
		gluster_cli_2_common_call, gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_DEFRAG_VOLUME, "DEFRAG_VOLUME" ,
		gluster_cli_2_common_call, gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_SET_VOLUME, "SET_VOLUME",
		gluster_cli_2_common_call, gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_ADD_BRICK, "ADD_BRICK",
		gluster_cli_2_common_call, gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_REMOVE_BRICK, "REMOVE_BRICK",
		gluster_cli_2_common_call, gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_REPLACE_BRICK, "REPLACE_BRICK",
		gluster_cli_2_common_call, gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_LOG_ROTATE, "LOG_ROTATE",
		gluster_cli_2_common_call, gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_GETSPEC, "GETSPEC",
		gluster_cli_2_common_call, gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_PMAP_PORTBYBRICK, "PMAP_PORTBYBRICK",
		gluster_cli_2_common_call, gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_SYNC_VOLUME, "SYNC_VOLUME",
		gluster_cli_2_common_call, gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_RESET_VOLUME, "RESET_VOLUME",
		gluster_cli_2_common_call, gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_FSM_LOG, "FSM_LOG",
		gluster_cli_2_fsm_log_call, gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_GSYNC_SET, "GSYNC_SET",
		gluster_cli_2_common_call, gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_PROFILE_VOLUME, "PROFILE_VOLUME",
		gluster_cli_2_common_call, gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_QUOTA, "QUOTA",
		gluster_cli_2_common_call, gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_TOP_VOLUME, "TOP_VOLUME",
		gluster_cli_2_common_call, gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_GETWD, "GETWD",
		gluster_cli_2_getwd_call, gluster_cli_2_getwd_reply
	},
	{
		GLUSTER_CLI_2_STATUS_VOLUME, "STATUS_VOLUME",
		gluster_cli_2_common_call, gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_STATUS_ALL, "STATUS_ALL",
		gluster_cli_2_common_call, gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_MOUNT, "MOUNT",
		gluster_cli_2_mount_call, gluster_cli_2_mount_reply
	},
	{
		GLUSTER_CLI_2_UMOUNT, "UMOUNT",
		gluster_cli_2_umount_call, gluster_dissect_common_reply
	},
	{
		GLUSTER_CLI_2_HEAL_VOLUME, "HEAL_VOLUME",
		gluster_cli_2_common_call, gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_STATEDUMP_VOLUME, "STATEDUMP_VOLUME",
		gluster_cli_2_common_call, gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_LIST_VOLUME, "LIST_VOLUME",
		gluster_cli_2_common_call, gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_CLRLOCKS_VOLUME, "CLRLOCKS_VOLUME",
		gluster_cli_2_common_call, gluster_cli_2_common_reply
	},
	{ 0, NULL , NULL, NULL}
};


static const value_string gluster_cli_proc_vals[] = {
	{ GLUSTER_CLI_NULL,             "NULL" },
	{ GLUSTER_CLI_PROBE,            "PROBE" },
	{ GLUSTER_CLI_DEPROBE,          "DEPROBE" },
	{ GLUSTER_CLI_LIST_FRIENDS,     "LIST_FRIENDS" },
	{ GLUSTER_CLI_CREATE_VOLUME,    "CREATE_VOLUME" },
	{ GLUSTER_CLI_GET_VOLUME,       "GET_VOLUME" },
	{ GLUSTER_CLI_GET_NEXT_VOLUME,  "GET_NEXT_VOLUME" },
	{ GLUSTER_CLI_DELETE_VOLUME,    "DELETE_VOLUME" },
	{ GLUSTER_CLI_START_VOLUME,     "START_VOLUME" },
	{ GLUSTER_CLI_STOP_VOLUME,      "STOP_VOLUME" },
	{ GLUSTER_CLI_RENAME_VOLUME,    "RENAME_VOLUME" },
	{ GLUSTER_CLI_DEFRAG_VOLUME,    "DEFRAG_VOLUME" },
	{ GLUSTER_CLI_SET_VOLUME,       "SET_VOLUME" },
	{ GLUSTER_CLI_ADD_BRICK,        "ADD_BRICK" },
	{ GLUSTER_CLI_REMOVE_BRICK,     "REMOVE_BRICK" },
	{ GLUSTER_CLI_REPLACE_BRICK,    "REPLACE_BRICK" },
	{ GLUSTER_CLI_LOG_FILENAME,     "LOG_FILENAME" },
	{ GLUSTER_CLI_LOG_LOCATE,       "LOG_LOCATE" },
	{ GLUSTER_CLI_LOG_ROTATE,       "LOG_ROTATE" },
	{ GLUSTER_CLI_GETSPEC,          "GETSPEC" },
	{ GLUSTER_CLI_PMAP_PORTBYBRICK, "PMAP_PORTBYBRICK" },
	{ GLUSTER_CLI_SYNC_VOLUME,      "SYNC_VOLUME" },
	{ GLUSTER_CLI_RESET_VOLUME,     "RESET_VOLUME" },
	{ GLUSTER_CLI_FSM_LOG,          "FSM_LOG" },
	{ GLUSTER_CLI_GSYNC_SET,        "GSYNC_SET" },
	{ GLUSTER_CLI_PROFILE_VOLUME,   "PROFILE_VOLUME" },
	{ GLUSTER_CLI_QUOTA,            "QUOTA" },
	{ GLUSTER_CLI_TOP_VOLUME,       "TOP_VOLUME" },
	{ GLUSTER_CLI_GETWD,            "GETWD" },
	{ GLUSTER_CLI_LOG_LEVEL,        "LOG_LEVEL" },
	{ GLUSTER_CLI_STATUS_VOLUME,    "STATUS_VOLUME" },
	{ GLUSTER_CLI_MOUNT,            "MOUNT" },
	{ GLUSTER_CLI_UMOUNT,           "UMOUNT" },
	{ GLUSTER_CLI_HEAL_VOLUME,      "HEAL_VOLUME" },
	{ GLUSTER_CLI_STATEDUMP_VOLUME, "STATEDUMP_VOLUME" },
	{ 0, NULL }
};
static value_string_ext gluster_cli_proc_vals_ext = VALUE_STRING_EXT_INIT(gluster_cli_proc_vals);

static const value_string gluster_cli_2_proc_vals[] = {
	{ GLUSTER_CLI_2_NULL,             "NULL" },
	{ GLUSTER_CLI_2_PROBE,            "PROBE" },
	{ GLUSTER_CLI_2_DEPROBE,          "DEPROBE" },
	{ GLUSTER_CLI_2_LIST_FRIENDS,     "LIST_FRIENDS" },
	{ GLUSTER_CLI_2_CREATE_VOLUME,    "CREATE_VOLUME" },
	{ GLUSTER_CLI_2_GET_VOLUME,       "GET_VOLUME" },
	{ GLUSTER_CLI_2_GET_NEXT_VOLUME,  "GET_NEXT_VOLUME" },
	{ GLUSTER_CLI_2_DELETE_VOLUME,    "DELETE_VOLUME" },
	{ GLUSTER_CLI_2_START_VOLUME,     "START_VOLUME" },
	{ GLUSTER_CLI_2_STOP_VOLUME,      "STOP_VOLUME" },
	{ GLUSTER_CLI_2_RENAME_VOLUME,    "RENAME_VOLUME" },
	{ GLUSTER_CLI_2_DEFRAG_VOLUME,    "DEFRAG_VOLUME" },
	{ GLUSTER_CLI_2_SET_VOLUME,       "SET_VOLUME" },
	{ GLUSTER_CLI_2_ADD_BRICK,        "ADD_BRICK" },
	{ GLUSTER_CLI_2_REMOVE_BRICK,     "REMOVE_BRICK" },
	{ GLUSTER_CLI_2_REPLACE_BRICK,    "REPLACE_BRICK" },
	{ GLUSTER_CLI_2_LOG_ROTATE,       "LOG_ROTATE" },
	{ GLUSTER_CLI_2_GETSPEC,          "GETSPEC" },
	{ GLUSTER_CLI_2_PMAP_PORTBYBRICK, "PMAP_PORTBYBRICK" },
	{ GLUSTER_CLI_2_SYNC_VOLUME,      "SYNC_VOLUME" },
	{ GLUSTER_CLI_2_RESET_VOLUME,     "RESET_VOLUME" },
	{ GLUSTER_CLI_2_FSM_LOG,          "FSM_LOG" },
	{ GLUSTER_CLI_2_GSYNC_SET,        "GSYNC_SET" },
	{ GLUSTER_CLI_2_PROFILE_VOLUME,   "PROFILE_VOLUME" },
	{ GLUSTER_CLI_2_QUOTA,            "QUOTA" },
	{ GLUSTER_CLI_2_TOP_VOLUME,       "TOP_VOLUME" },
	{ GLUSTER_CLI_2_GETWD,            "GETWD" },
	{ GLUSTER_CLI_2_STATUS_VOLUME,    "STATUS_VOLUME" },
	{ GLUSTER_CLI_2_STATUS_ALL,       "STATUS_ALL" },
 	{ GLUSTER_CLI_2_MOUNT,            "MOUNT" },
	{ GLUSTER_CLI_2_UMOUNT,           "UMOUNT" },
	{ GLUSTER_CLI_2_HEAL_VOLUME,      "HEAL_VOLUME" },
	{ GLUSTER_CLI_2_STATEDUMP_VOLUME, "STATEDUMP_VOLUME" },
	{ GLUSTER_CLI_2_LIST_VOLUME,      "LIST_VOLUME"},
	{ GLUSTER_CLI_2_CLRLOCKS_VOLUME,  "CLRLOCKS_VOLUME" },
	{ 0, NULL }
};
static value_string_ext gluster_cli_2_proc_vals_ext = VALUE_STRING_EXT_INIT(gluster_cli_2_proc_vals);

void
proto_register_gluster_cli(void)
{
	/* Setup list of header fields  See Section 1.6.1 for details */
	static hf_register_info hf[] = {
		/* programs */
		{ &hf_gluster_cli_proc,
			{ "Gluster CLI", "gluster.cli.proc", FT_UINT32,
				BASE_DEC | BASE_EXT_STRING, &gluster_cli_proc_vals_ext, 0, NULL,
				HFILL }
		},
		{ &hf_gluster_cli_2_proc,
			{ "Gluster CLI", "gluster.cli.proc", FT_UINT32,
				BASE_DEC | BASE_EXT_STRING, &gluster_cli_2_proc_vals_ext, 0,
				NULL, HFILL }
		},
		{ &hf_gluster_dict,
			{ "Dict", "gluster.dict", FT_STRING, BASE_NONE, NULL,
				0, NULL, HFILL }
		},
		{ &hf_gluster_path,
			{ "Path", "gluster.path", FT_STRING, BASE_NONE, NULL,
				0, NULL, HFILL }
		},
		{ &hf_gluster_lazy,
			{ "Lazy", "gluster.lazy", FT_UINT32, BASE_HEX, NULL,
				0, NULL, HFILL }
		},
		{ &hf_gluster_label,
			{ "Label", "gluster.label", FT_STRING, BASE_NONE, NULL,
				0, NULL, HFILL }
		},
		{ &hf_gluster_unused,
			{ "Unused", "gluster.unused", FT_UINT32, BASE_HEX,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_wd,
			{ "Path", "gluster.wd", FT_STRING, BASE_NONE, NULL, 0,
				NULL, HFILL }
		},
		{ &hf_gluster_op_errstr,
			{ "Error", "gluster.op_errstr", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_hostname,
			{ "Hostname", "gluster.hostname", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_port,
			{ "Port", "gluster.port", FT_UINT32, BASE_DEC, NULL, 0,
				NULL, HFILL }
		},
		{ &hf_gluster_flags,
			{ "Flags", "gluster.flag", FT_UINT32, BASE_HEX, NULL,
				0, NULL, HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_gluster_cli
	};

	/* Register the protocol name and description */
	proto_gluster_cli = proto_register_protocol("Gluster CLI",
					"Gluster CLI", "gluster.cli");
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_gluster_cli, hf, array_length(hf));
}

void
proto_reg_handoff_gluster_cli(void)
{
	rpc_init_prog(proto_gluster_cli, GLUSTER_CLI_PROGRAM, ett_gluster_cli);
	rpc_init_proc_table(GLUSTER_CLI_PROGRAM, 1, gluster_cli_proc,
							hf_gluster_cli_proc);
	rpc_init_proc_table(GLUSTER_CLI_PROGRAM, 2, gluster_cli_2_proc,
							hf_gluster_cli_2_proc);
}

