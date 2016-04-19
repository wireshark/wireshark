/* packet-gluster_hndsk.c
 * Routines for GlusterFS Handshake dissection
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

#include <epan/packet.h>

#include "packet-rpc.h"
#include "packet-gluster.h"

void proto_register_gluster_hndsk(void);
void proto_reg_handoff_gluster_hndsk(void);
void proto_register_gluster_cbk(void);
void proto_reg_handoff_gluster_cbk(void);

/* Initialize the protocol and registered fields */
static gint proto_gluster_cbk = -1;
static gint proto_gluster_hndsk = -1;

/* programs and procedures */
static gint hf_gluster_cbk_proc = -1;
static gint hf_gluster_hndsk_proc = -1;
static gint hf_gluster_hndsk_dict = -1;
static gint hf_gluster_hndsk_spec = -1;		/* GETSPEC Reply */
static gint hf_gluster_hndsk_key = -1;		/* GETSPEC Call */
static gint hf_gluster_hndsk_event_op = -1;	/* EVENT NOTIFY call */
static gint hf_gluster_hndsk_uid = -1;		/* LOCK VERSION*/
static gint hf_gluster_hndsk_lk_ver= -1;
static gint hf_gluster_hndsk_flags = -1;

/* Initialize the subtree pointers */
static gint ett_gluster_cbk = -1;
static gint ett_gluster_hndsk = -1;

/* CBK_CACHE_INVALIDATION */
static gint hf_gluster_cbk_gfid = -1;
static gint hf_gluster_cbk_upcall_event_type = -1;
static gint hf_gluster_cbk_ci_flags = -1;
static gint hf_gluster_cbk_ci_expire_time_attr = -1;
static gint hf_gluster_cbk_ci_stat = -1;
static gint hf_gluster_cbk_ci_parent_stat = -1;
static gint hf_gluster_cbk_ci_oldparent_stat = -1;
static gint hf_gluster_cbk_xdata = -1;

/* procedures for GLUSTER_HNDSK_PROGRAM */
static int
gluster_hndsk_setvolume_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data)
{
	int offset = 0;
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_hndsk_dict,
								offset);
	return offset;
}

static int
gluster_hndsk_setvolume_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	return gluster_rpc_dissect_dict(tree, tvb, hf_gluster_hndsk_dict, 0);
}

static int
gluster_hndsk_2_setvolume_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data)
{
	int offset = 0;
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_hndsk_dict,
								offset);
	return offset;
}

static int
gluster_hndsk_2_setvolume_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	return gluster_rpc_dissect_dict(tree, tvb, hf_gluster_hndsk_dict, 0);
}

static int
gluster_hndsk_2_getspec_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data)
{
	int offset = 0;
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_hndsk_spec, offset,
									NULL);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_hndsk_dict,
								offset);
	return offset;
}

static int
gluster_hndsk_2_getspec_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	proto_tree_add_item(tree, hf_gluster_hndsk_flags, tvb, offset,
								4, ENC_BIG_ENDIAN);
	offset += 4;
	offset = dissect_rpc_string(tvb, tree, hf_gluster_hndsk_key, offset,
								NULL);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_hndsk_dict,
								offset);
	return offset;
}

static int
gluster_hndsk_2_set_lk_ver_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data)
{
	int offset = 0;
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = dissect_rpc_uint32(tvb, tree,hf_gluster_hndsk_lk_ver, offset);
	return offset;
}

static int
gluster_hndsk_2_set_lk_ver_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = dissect_rpc_string(tvb, tree, hf_gluster_hndsk_uid, offset,
									NULL);
	offset = dissect_rpc_uint32(tvb, tree,hf_gluster_hndsk_lk_ver, offset);
	return offset;
}

static int
gluster_hndsk_2_event_notify_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_hndsk_event_op,
								offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_hndsk_dict,
								offset);
	return offset;
}

/* In  rpc/xdr/src/glusterfs3-xdr.c. xdr_gf_event_notify_rsp */

static int
gluster_hndsk_2_event_notify_reply(tvbuff_t *tvb,
					packet_info *pinfo, proto_tree *tree, void* data)
{
	int offset = 0;
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_hndsk_dict,
								offset);
	return offset;
}

/* In  rpc/xdr/src/glusterfs3-xdr.c. xdr_gfs3_cbk_cache_invalidation_req */
static int
gluster_cbk_cache_invalidation_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	int offset = 0;

	offset = dissect_rpc_string(tvb, tree, hf_gluster_cbk_gfid, offset, NULL);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_cbk_upcall_event_type, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_cbk_ci_flags, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_cbk_ci_expire_time_attr, offset);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb,
					hf_gluster_cbk_ci_stat, offset);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb,
					hf_gluster_cbk_ci_parent_stat, offset);
	offset = glusterfs_rpc_dissect_gf_iatt(tree, tvb,
					hf_gluster_cbk_ci_oldparent_stat, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_cbk_xdata, offset);
	return offset;
}

static int
gluster_hndsk_dissect_common_reply(tvbuff_t *tvb,
					packet_info *pinfo, proto_tree *tree, void* data)
{
	return gluster_dissect_common_reply(tvb, 0, pinfo, tree, data);
}

static const vsff gluster_hndsk_proc[] = {
	{
		GF_HNDSK_NULL, "NULL",
		dissect_rpc_void, dissect_rpc_void
	},
	{
		GF_HNDSK_SETVOLUME, "SETVOLUME",
		gluster_hndsk_setvolume_call, gluster_hndsk_setvolume_reply
	},
	{ GF_HNDSK_GETSPEC, "GETSPEC", dissect_rpc_unknown, dissect_rpc_unknown },
	{
		GF_HNDSK_PING, "PING",
		dissect_rpc_void, gluster_hndsk_dissect_common_reply
	},
	{ 0, NULL, NULL, NULL }
};

static const vsff gluster_hndsk_2_proc[] = {
	{
		GF_HNDSK_NULL, "NULL",
		dissect_rpc_void, dissect_rpc_void
	},
	{
		GF_HNDSK_SETVOLUME, "SETVOLUME",
		gluster_hndsk_2_setvolume_call, gluster_hndsk_2_setvolume_reply
	},
	{
		GF_HNDSK_GETSPEC, "GETSPEC",
		gluster_hndsk_2_getspec_call, gluster_hndsk_2_getspec_reply
	},
	{
		GF_HNDSK_PING, "PING",
		dissect_rpc_void, glusterfs_gfs3_3_op_common_reply
	},
	{
		GF_HNDSK_SET_LK_VER,"LOCK VERSION",
		gluster_hndsk_2_set_lk_ver_call, gluster_hndsk_2_set_lk_ver_reply
	},
	{
		GF_HNDSK_EVENT_NOTIFY, "EVENTNOTIFY",
		gluster_hndsk_2_event_notify_call,
		gluster_hndsk_2_event_notify_reply
	},
	{ 0, NULL, NULL, NULL }
};


static const rpc_prog_vers_info gluster_hndsk_vers_info[] = {
	{ 1, gluster_hndsk_proc, &hf_gluster_hndsk_proc },
	{ 2, gluster_hndsk_2_proc, &hf_gluster_hndsk_proc },
};


static const value_string gluster_hndsk_proc_vals[] = {
	{ GF_HNDSK_NULL,         "NULL" },
	{ GF_HNDSK_SETVOLUME,    "DUMP" },
	{ GF_HNDSK_GETSPEC,      "GETSPEC" },
	{ GF_HNDSK_PING,         "PING" },
	{ GF_HNDSK_SET_LK_VER,   "LOCK VERSION" },
	{ GF_HNDSK_EVENT_NOTIFY, "EVENTNOTIFY" },
	{ 0, NULL }
};

void
proto_register_gluster_hndsk(void)
{
	static hf_register_info hf[] = {
		{ &hf_gluster_hndsk_proc,
			{ "GlusterFS Handshake", "glusterfs.hndsk.proc",
				FT_UINT32, BASE_DEC,
				VALS(gluster_hndsk_proc_vals), 0, NULL, HFILL }
		},
		/* fields used by Gluster Handshake */
		{ &hf_gluster_hndsk_dict,
			{ "Dict", "glusterfs.hndsk.dict", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		/* For Gluster handshake event notify */
		{ &hf_gluster_hndsk_event_op,
		       { "Event Op", "glusterfs.hndsk.event_notify_op",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_hndsk_key,
			{ "Key", "glusterfs.hndsk.getspec.key", FT_STRING,
				BASE_NONE, NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_hndsk_spec,
			/* FIXME: rename spec to something clearer */
			{ "Spec", "glusterfs.hndsk.getspec", FT_STRING,
				BASE_NONE, NULL, 0, NULL, HFILL }
		},
		/* For hand shake set_lk_ver */
		{ &hf_gluster_hndsk_uid,
			{ "Name", "glusterfs.hndsk.uid", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_hndsk_lk_ver,
			{ "Event Op", "glusterfs.hndsk.lk_ver", FT_UINT32,
				BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_hndsk_flags,
			{ "Flags", "glusterfs.hndsk.flags", FT_UINT32, BASE_OCT,
				NULL, 0, NULL, HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_gluster_hndsk
	};

	/* Register the protocol name and description */
	proto_gluster_hndsk = proto_register_protocol("GlusterFS Handshake",
						"GlusterFS Handshake",
						"glusterfs.hndsk");
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_gluster_hndsk, hf, array_length(hf));

}

void
proto_reg_handoff_gluster_hndsk(void)
{
	rpc_init_prog(proto_gluster_hndsk, GLUSTER_HNDSK_PROGRAM,
	    ett_gluster_hndsk,
	    G_N_ELEMENTS(gluster_hndsk_vers_info), gluster_hndsk_vers_info);
}

/* Legacy GlusterFS Callback procedures, they don't contain any data. */
static const vsff gluster_cbk_proc[] = {
	{ GF_CBK_NULL,      "NULL",      dissect_rpc_void, dissect_rpc_void },
	{ GF_CBK_FETCHSPEC, "FETCHSPEC", dissect_rpc_unknown, dissect_rpc_unknown },
	{ GF_CBK_INO_FLUSH, "INO_FLUSH", dissect_rpc_unknown, dissect_rpc_unknown },
	{ GF_CBK_EVENT_NOTIFY, "EVENTNOTIFY", dissect_rpc_unknown, dissect_rpc_unknown },
	{ GF_CBK_GET_SNAPS, "GETSNAPS", dissect_rpc_unknown, dissect_rpc_unknown },
	{ GF_CBK_CACHE_INVALIDATION, "CACHE_INVALIDATION",
	  gluster_cbk_cache_invalidation_call, dissect_rpc_unknown },
	{ 0, NULL, NULL, NULL }
};
static const rpc_prog_vers_info gluster_cbk_vers_info[] = {
	{ 1, gluster_cbk_proc, &hf_gluster_cbk_proc },
};
static const value_string gluster_cbk_proc_vals[] = {
	{ GF_CBK_NULL,      "NULL" },
	{ GF_CBK_FETCHSPEC, "FETCHSPEC" },
	{ GF_CBK_INO_FLUSH, "INO_FLUSH" },
	{ GF_CBK_EVENT_NOTIFY, "EVENTNOTIFY" },
	{ GF_CBK_GET_SNAPS, "GETSNAPS" },
	{ GF_CBK_CACHE_INVALIDATION, "CACHE_INVALIDATION" },
	{ 0, NULL }
};

static const value_string gluster_cbk_upcall_event_type[] = {
	{ GF_UPCALL_EVENT_NULL,      "NULL" },
	{ GF_UPCALL_CACHE_INVALIDATION, "CACHE_INVALIDATION" },
	{ 0, NULL }
};
static value_string_ext gluster_cbk_upcall_event_type_ext = VALUE_STRING_EXT_INIT(gluster_cbk_upcall_event_type);

void
proto_register_gluster_cbk(void)
{
	/* Setup list of header fields  See Section 1.6.1 for details */
	static hf_register_info hf[] = {
		/* programs */
		{ &hf_gluster_cbk_proc,
			{ "GlusterFS Callback", "glusterfs.cbk.proc",
				FT_UINT32, BASE_DEC,
				VALS(gluster_cbk_proc_vals), 0, NULL, HFILL }
		},
		{ &hf_gluster_cbk_gfid,
			{ "GFID", "glusterfs.cbk.gfid", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_cbk_upcall_event_type,
			{ "Event Type", "glusterfs.cbk.upcall.event_type", FT_UINT32, BASE_DEC | BASE_EXT_STRING,
				&gluster_cbk_upcall_event_type_ext, 0, NULL, HFILL }
		},
		{ &hf_gluster_cbk_ci_flags,
			{ "Flags", "glusterfs.cbk.cache_invalidation.flags", FT_UINT32, BASE_DEC_HEX,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_cbk_ci_expire_time_attr,
			{ "Expire Time Attr", "glusterfs.cbk.cache_invalidation.expire_time_attr",
				FT_UINT32, BASE_OCT, NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_cbk_ci_stat,
			{ "Stat", "glusterfs.cbk.cache_invalidation.stat", FT_NONE, BASE_NONE, NULL,
				0, NULL, HFILL }
		},
		{ &hf_gluster_cbk_ci_parent_stat,
			{ "Parent Stat", "glusterfs.cbk.cache_invalidation.parent.stat", FT_NONE, BASE_NONE, NULL,
				0, NULL, HFILL }
		},
		{ &hf_gluster_cbk_ci_oldparent_stat,
			{ "Old Parent Stat", "glusterfs.cbk.cache_invalidation.oldparent.stat",
				FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_cbk_xdata,
			{ "Xdata", "glusterfs.cbk.xdata", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_gluster_cbk
	};

	/* Register the protocol name and description */
	proto_gluster_cbk = proto_register_protocol("GlusterFS Callback",
					"GlusterFS Callback", "glusterfs.cbk");
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_gluster_cbk, hf, array_length(hf));
}

void
proto_reg_handoff_gluster_cbk(void)
{
	rpc_init_prog(proto_gluster_cbk, GLUSTER_CBK_PROGRAM, ett_gluster_cbk,
	    G_N_ELEMENTS(gluster_cbk_vers_info), gluster_cbk_vers_info);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
