/* packet-rquota.c
 * Routines for rquota dissection
 * Copyright 2001, Mike Frisch <frisch@hummingbird.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-ypxfr.c
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
#include "packet-rquota.h"

static int proto_rquota = -1;
static int hf_rquota_procedure_v1 = -1;
static int hf_rquota_procedure_v2 = -1;
static int hf_rquota_pathp = -1;
static int hf_rquota_uid = -1;
static int hf_rquota_type = -1;
static int hf_rquota_id = -1;
static int hf_rquota_status = -1;
static int hf_rquota_rquota = -1;
static int hf_rquota_bsize = -1;
static int hf_rquota_active = -1;
static int hf_rquota_bhardlimit = -1;
static int hf_rquota_bsoftlimit = -1;
static int hf_rquota_curblocks = -1;
static int hf_rquota_fhardlimit = -1;
static int hf_rquota_fsoftlimit = -1;
static int hf_rquota_curfiles = -1;
static int hf_rquota_btimeleft = -1;
static int hf_rquota_ftimeleft = -1;

static gint ett_rquota = -1;
static gint ett_rquota_rquota = -1;

static const value_string names_rquota_status[] =
{
#define Q_OK		1
	{	Q_OK,		"OK"	},
#define Q_NOQUOTA	2
	{	Q_NOQUOTA,	"NOQUOTA"	},
#define Q_EPERM		3
	{	Q_EPERM,	"EPERM"	},
	{	0,		NULL }
};


static int
dissect_rquota(tvbuff_t *tvb, int offset, proto_tree *tree)
{

	proto_item *lock_item = NULL;
	proto_tree *lock_tree = NULL;

	lock_item = proto_tree_add_item(tree, hf_rquota_rquota, tvb,
			offset, -1, ENC_NA);

	lock_tree = proto_item_add_subtree(lock_item, ett_rquota_rquota);

	offset = dissect_rpc_uint32(tvb, lock_tree,
			hf_rquota_bsize, offset);

	offset = dissect_rpc_bool(tvb, lock_tree,
			hf_rquota_active, offset);

	offset = dissect_rpc_uint32(tvb, lock_tree,
			hf_rquota_bhardlimit, offset);

	offset = dissect_rpc_uint32(tvb, lock_tree,
			hf_rquota_bsoftlimit, offset);

	offset = dissect_rpc_uint32(tvb, lock_tree,
			hf_rquota_curblocks, offset);

	offset = dissect_rpc_uint32(tvb, lock_tree,
			hf_rquota_fhardlimit, offset);

	offset = dissect_rpc_uint32(tvb, lock_tree,
			hf_rquota_fsoftlimit, offset);

	offset = dissect_rpc_uint32(tvb, lock_tree,
			hf_rquota_curfiles, offset);

	offset = dissect_rpc_uint32(tvb, lock_tree,
			hf_rquota_btimeleft, offset);

	offset = dissect_rpc_uint32(tvb, lock_tree,
			hf_rquota_ftimeleft, offset);

	return offset;
}

static int
dissect_getquota_result(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	gint32	status;

	status = tvb_get_ntohl(tvb, offset);

	offset = dissect_rpc_uint32(tvb, tree,
			hf_rquota_status, offset);

	if (status==Q_OK) {
		offset = dissect_rquota(tvb, offset, tree);
	}

	return offset;
}

static int
dissect_getquota_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_string(tvb, tree,
			hf_rquota_pathp, offset, NULL);

	offset = dissect_rpc_uint32(tvb, tree,
			hf_rquota_uid, offset);

	return offset;
}

/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: type of arguments is "void". */
static const vsff rquota1_proc[] = {
	{ RQUOTAPROC_NULL,		"NULL",
		NULL,				NULL },
	{ RQUOTAPROC_GETQUOTA,		"GETQUOTA",
		dissect_getquota_call,		dissect_getquota_result	},
	{ RQUOTAPROC_GETACTIVEQUOTA,	"GETACTIVEQUOTA",
		dissect_getquota_call,		dissect_getquota_result	},
	{ 0,				NULL,
		NULL,				NULL }
};
static const value_string rquota1_proc_vals[] = {
	{ RQUOTAPROC_NULL,		"NULL" },
	{ RQUOTAPROC_GETQUOTA,		"GETQUOTA" },
	{ RQUOTAPROC_GETACTIVEQUOTA,	"GETACTIVEQUOTA" },
	{ RQUOTAPROC_SETQUOTA,		"SETQUOTA" },
	{ RQUOTAPROC_SETACTIVEQUOTA,	"SETACTIVEQUOTA" },
	{ 0,				NULL }
};
/* end of RQUOTA version 1 */


static int
dissect_getquota2_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_string(tvb, tree,
			hf_rquota_pathp, offset, NULL);

	offset = dissect_rpc_uint32(tvb, tree,
			hf_rquota_type, offset);

	offset = dissect_rpc_uint32(tvb, tree,
			hf_rquota_id, offset);

	return offset;
}


static const vsff rquota2_proc[] = {
	{ RQUOTAPROC_NULL,		"NULL",
		NULL,				NULL },
	{ RQUOTAPROC_GETQUOTA,		"GETQUOTA",
		dissect_getquota2_call,		dissect_getquota_result	},
	{ RQUOTAPROC_GETACTIVEQUOTA,	"GETACTIVEQUOTA",
		dissect_getquota2_call,		dissect_getquota_result	},
	{ 0,				NULL,
		NULL,				NULL }
};
static const value_string rquota2_proc_vals[] = {
	{ RQUOTAPROC_NULL,		"NULL" },
	{ RQUOTAPROC_GETQUOTA,		"GETQUOTA" },
	{ RQUOTAPROC_GETACTIVEQUOTA,	"GETACTIVEQUOTA" },
	{ RQUOTAPROC_SETQUOTA,		"SETQUOTA" },
	{ RQUOTAPROC_SETACTIVEQUOTA,	"SETACTIVEQUOTA" },
	{ 0,				NULL }
};
/* end of RQUOTA version 2 */

void
proto_register_rquota(void)
{
	static struct true_false_string tfs_active = { "Quota is ACTIVE", "Quota is NOT active" };

	static hf_register_info hf[] = {
		{ &hf_rquota_procedure_v1, {
			"V1 Procedure", "rquota.procedure_v1", FT_UINT32, BASE_DEC,
			VALS(rquota1_proc_vals), 0, NULL, HFILL }},
		{ &hf_rquota_procedure_v2, {
			"V2 Procedure", "rquota.procedure_v2", FT_UINT32, BASE_DEC,
			VALS(rquota2_proc_vals), 0, NULL, HFILL }},
		{ &hf_rquota_uid, {
			"uid", "rquota.uid", FT_UINT32, BASE_DEC,
			NULL, 0, "User ID", HFILL }},
		{ &hf_rquota_type, {
			"type", "rquota.type", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_rquota_id, {
			"id", "rquota.id", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},

		{ &hf_rquota_pathp, {
			"pathp", "rquota.pathp", FT_STRING, BASE_NONE,
			NULL, 0, "Filesystem of interest", HFILL }},

		{ &hf_rquota_status, {
			"status", "rquota.status", FT_UINT32, BASE_DEC,
			VALS(names_rquota_status), 0, "Status code", HFILL }},

		{ &hf_rquota_rquota, {
			"rquota", "rquota.rquota", FT_NONE, BASE_NONE,
			NULL, 0, "Rquota structure", HFILL }},

		{ &hf_rquota_bsize, {
			"bsize", "rquota.bsize", FT_UINT32, BASE_DEC,
			NULL, 0, "Block size", HFILL }},

		{ &hf_rquota_active, {
			"active", "rquota.active", FT_BOOLEAN, BASE_NONE,
			TFS(&tfs_active), 0x0, "Indicates whether quota is active", HFILL }},

		{ &hf_rquota_bhardlimit, {
			"bhardlimit", "rquota.bhardlimit", FT_UINT32, BASE_DEC,
			NULL, 0, "Hard limit for blocks", HFILL }},

		{ &hf_rquota_bsoftlimit, {
			"bsoftlimit", "rquota.bsoftlimit", FT_UINT32, BASE_DEC,
			NULL, 0, "Soft limit for blocks", HFILL }},

		{ &hf_rquota_curblocks, {
			"curblocks", "rquota.curblocks", FT_UINT32, BASE_DEC,
			NULL, 0, "Current block count", HFILL }},

		{ &hf_rquota_fhardlimit, {
			"fhardlimit", "rquota.fhardlimit", FT_UINT32, BASE_DEC,
			NULL, 0, "Hard limit on allocated files", HFILL }},

		{ &hf_rquota_fsoftlimit, {
			"fsoftlimit", "rquota.fsoftlimit", FT_UINT32, BASE_DEC,
			NULL, 0, "Soft limit of allocated files", HFILL }},

		{ &hf_rquota_curfiles, {
			"curfiles", "rquota.curfiles", FT_UINT32, BASE_DEC,
			NULL, 0, "Current # allocated files", HFILL }},

		{ &hf_rquota_btimeleft, {
			"btimeleft", "rquota.btimeleft", FT_UINT32, BASE_DEC,
			NULL, 0, "Time left for excessive disk use", HFILL }},

		{ &hf_rquota_ftimeleft, {
			"ftimeleft", "rquota.ftimeleft", FT_UINT32, BASE_DEC,
			NULL, 0, "Time left for excessive files", HFILL }},

	};

	static gint *ett[] = {
		&ett_rquota,
		&ett_rquota_rquota,
	};

	proto_rquota = proto_register_protocol("Remote Quota",
	    "RQUOTA", "rquota");

	proto_register_field_array(proto_rquota, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_rquota(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_rquota, RQUOTA_PROGRAM, ett_rquota);
	/* Register the procedure tables */
	rpc_init_proc_table(RQUOTA_PROGRAM, 1, rquota1_proc, hf_rquota_procedure_v1);
	rpc_init_proc_table(RQUOTA_PROGRAM, 2, rquota2_proc, hf_rquota_procedure_v2);
}



