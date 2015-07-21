/* packet-yppasswd.c
 * Routines for yppasswd dissection
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include "packet-rpc.h"
#include "packet-yppasswd.h"

void proto_register_yppasswd(void);
void proto_reg_handoff_yppasswd(void);

static int proto_yppasswd = -1;
static int hf_yppasswd_procedure_v1 = -1;
static int hf_yppasswd_status = -1;
static int hf_yppasswd_oldpass = -1;
static int hf_yppasswd_newpw = -1;
static int hf_yppasswd_newpw_name = -1;
static int hf_yppasswd_newpw_passwd = -1;
static int hf_yppasswd_newpw_uid = -1;
static int hf_yppasswd_newpw_gid = -1;
static int hf_yppasswd_newpw_gecos = -1;
static int hf_yppasswd_newpw_dir = -1;
static int hf_yppasswd_newpw_shell = -1;

static gint ett_yppasswd = -1;
static gint ett_yppasswd_newpw = -1;

static int
dissect_yppasswd_call(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	proto_item *lock_item = NULL;
	proto_tree *lock_tree = NULL;
	int offset = 0;

	offset = dissect_rpc_string(tvb, tree, hf_yppasswd_oldpass,
			offset, NULL);

	lock_item = proto_tree_add_item(tree, hf_yppasswd_newpw, tvb,
			offset, -1, ENC_NA);

	lock_tree = proto_item_add_subtree(lock_item, ett_yppasswd_newpw);

	offset = dissect_rpc_string(tvb, lock_tree,
			hf_yppasswd_newpw_name, offset, NULL);
	offset = dissect_rpc_string(tvb, lock_tree,
			hf_yppasswd_newpw_passwd, offset, NULL);
	offset = dissect_rpc_uint32(tvb, lock_tree,
			hf_yppasswd_newpw_uid, offset);
	offset = dissect_rpc_uint32(tvb, lock_tree,
			hf_yppasswd_newpw_gid, offset);
	offset = dissect_rpc_string(tvb, lock_tree,
			hf_yppasswd_newpw_gecos, offset, NULL);
	offset = dissect_rpc_string(tvb, lock_tree,
			hf_yppasswd_newpw_dir, offset, NULL);
	offset = dissect_rpc_string(tvb, lock_tree,
			hf_yppasswd_newpw_shell, offset, NULL);

	return offset;
}

static int
dissect_yppasswd_reply(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	return dissect_rpc_uint32(tvb, tree, hf_yppasswd_status, 0);
}

/* proc number, "proc name", dissect_request, dissect_reply */
static const vsff yppasswd1_proc[] = {
	{ YPPASSWDPROC_NULL,	"NULL",
		dissect_rpc_void,	dissect_rpc_void },
	{ YPPASSWDPROC_UPDATE,	"UPDATE",
		dissect_yppasswd_call,	dissect_yppasswd_reply },
	{ 0,	NULL,		NULL,				NULL }
};
static const value_string yppasswd1_proc_vals[] = {
	{ YPPASSWDPROC_NULL,	"NULL" },
	{ YPPASSWDPROC_UPDATE,	"UPDATE" },
	{ 0,	NULL }
};

static const rpc_prog_vers_info yppasswd_vers_info[] = {
	{ 1, yppasswd1_proc, &hf_yppasswd_procedure_v1 },
};

void
proto_register_yppasswd(void)
{
	static hf_register_info hf[] = {
		{ &hf_yppasswd_procedure_v1, {
			"V1 Procedure", "yppasswd.procedure_v1", FT_UINT32, BASE_DEC,
			VALS(yppasswd1_proc_vals), 0, NULL, HFILL }},
		{ &hf_yppasswd_status, {
			"status", "yppasswd.status", FT_UINT32, BASE_DEC,
			NULL, 0, "YPPasswd update status", HFILL }},

		{ &hf_yppasswd_oldpass, {
			"oldpass", "yppasswd.oldpass", FT_STRING, BASE_NONE,
			NULL, 0, "Old encrypted password", HFILL }},

		{ &hf_yppasswd_newpw, {
			"newpw", "yppasswd.newpw", FT_NONE, BASE_NONE,
			NULL, 0, "New passwd entry", HFILL }},

		{ &hf_yppasswd_newpw_name, {
			"name", "yppasswd.newpw.name", FT_STRING, BASE_NONE,
			NULL, 0, "Username", HFILL }},

		{ &hf_yppasswd_newpw_passwd, {
			"passwd", "yppasswd.newpw.passwd", FT_STRING, BASE_NONE,
			NULL, 0, "Encrypted passwd", HFILL }},

		{ &hf_yppasswd_newpw_uid, {
			"uid", "yppasswd.newpw.uid", FT_UINT32, BASE_DEC,
			NULL, 0, "UserID", HFILL }},

		{ &hf_yppasswd_newpw_gid, {
			"gid", "yppasswd.newpw.gid", FT_UINT32, BASE_DEC,
			NULL, 0, "GroupID", HFILL }},

		{ &hf_yppasswd_newpw_gecos, {
			"gecos", "yppasswd.newpw.gecos", FT_STRING, BASE_NONE,
			NULL, 0, "In real life name", HFILL }},

		{ &hf_yppasswd_newpw_dir, {
			"dir", "yppasswd.newpw.dir", FT_STRING, BASE_NONE,
			NULL, 0, "Home Directory", HFILL }},

		{ &hf_yppasswd_newpw_shell, {
			"shell", "yppasswd.newpw.shell", FT_STRING, BASE_NONE,
			NULL, 0, "Default shell", HFILL }},

	};

	static gint *ett[] = {
		&ett_yppasswd,
		&ett_yppasswd_newpw,
	};

	proto_yppasswd = proto_register_protocol("Yellow Pages Passwd",
	    "YPPASSWD", "yppasswd");
	proto_register_field_array(proto_yppasswd, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_yppasswd(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_yppasswd, YPPASSWD_PROGRAM, ett_yppasswd,
	    G_N_ELEMENTS(yppasswd_vers_info), yppasswd_vers_info);
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
