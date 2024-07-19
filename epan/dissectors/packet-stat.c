/* packet-stat.c
 * Routines for stat dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-smb.c
 *
 * 2001  Ronnie Sahlberg <See AUTHORS for email>
 *     Added the dissectors for STAT protocol
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include "packet-rpc.h"
#include "packet-stat.h"

void proto_register_stat(void);
void proto_reg_handoff_stat(void);

static const value_string stat1_proc_vals[] = {
	{ 0,                   "NULL" },
	{ STATPROC_STAT,       "STAT" },
	{ STATPROC_MON,        "MON" },
	{ STATPROC_UNMON,      "UNMON" },
	{ STATPROC_UNMON_ALL,  "UNMON_ALL" },
	{ STATPROC_SIMU_CRASH, "SIMU_CRASH" },
	{ STATPROC_NOTIFY,     "NOTIFY" },
	{ 0, NULL }
};

static const value_string stat_res[] =
{
	{ 0, "STAT_SUCC" },
	{ 1, "STAT_FAIL" },
	{ 0, NULL }
};

static int proto_stat;

static int hf_stat_mon;
static int hf_stat_mon_id_name;
static int hf_stat_mon_name;
static int hf_stat_my_id;
static int hf_stat_my_id_hostname;
static int hf_stat_my_id_proc;
static int hf_stat_my_id_prog;
static int hf_stat_my_id_vers;
static int hf_stat_priv;
static int hf_stat_procedure_v1;
static int hf_stat_stat_chge;
static int hf_stat_stat_res;
static int hf_stat_stat_res_res;
static int hf_stat_stat_res_state;
static int hf_stat_state;

static int ett_stat;
static int ett_stat_stat_res;
static int ett_stat_mon;
static int ett_stat_my_id;
static int ett_stat_stat_chge;

#define STAT_SUCC	0
#define STAT_FAIL	1

/* Calculate length (including padding) of my_id structure.
 * First read the length of the string and round it upwards to nearest
 * multiple of 4, then add 16 (4*uint32)
 */
static int
my_id_len(tvbuff_t *tvb, int offset)
{
	int len;

	len = tvb_get_ntohl(tvb, offset);
	if(len&0x03)
		len = (len&0xfc)+4;

	len += 16;

	return len;
}

/* Calculate length (including padding) of my_id structure.
 * First read the length of the string and round it upwards to nearest
 * multiple of 4, then add 4 (string len) and size of my_id struct.
 */
static int
mon_id_len(tvbuff_t *tvb, int offset)
{
	int len;

	len = tvb_get_ntohl(tvb, offset);
	if(len&0x03){
		len = (len&0xfc)+4;
	}

	len += 4;

	return len+my_id_len(tvb,offset+len);
}

static int
dissect_stat_stat(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
	return dissect_rpc_string(tvb,tree,hf_stat_mon_name,0,NULL);
}

static int
dissect_stat_stat_res(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
	proto_item *sub_item;
	proto_tree *sub_tree;
	int32_t res;
	int offset = 0;

	sub_item = proto_tree_add_item(tree, hf_stat_stat_res, tvb,
				offset, -1, ENC_NA);
	sub_tree = proto_item_add_subtree(sub_item, ett_stat_stat_res);

	res = tvb_get_ntohl(tvb, offset);
	offset = dissect_rpc_uint32(tvb,sub_tree,hf_stat_stat_res_res,offset);

	if (res==STAT_SUCC) {
		offset = dissect_rpc_uint32(tvb,sub_tree,hf_stat_stat_res_state,offset);
	} else {
		offset += 4;
	}

	return offset;
}

static int
dissect_stat_my_id(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_item *sub_item;
	proto_tree *sub_tree;

	sub_item = proto_tree_add_item(tree, hf_stat_my_id, tvb,
				offset, my_id_len(tvb,offset), ENC_NA);
	sub_tree = proto_item_add_subtree(sub_item, ett_stat_my_id);

	offset = dissect_rpc_string(tvb,sub_tree,hf_stat_my_id_hostname,offset,NULL);
	offset = dissect_rpc_uint32(tvb,sub_tree,hf_stat_my_id_prog,offset);
	offset = dissect_rpc_uint32(tvb,sub_tree,hf_stat_my_id_vers,offset);
	offset = dissect_rpc_uint32(tvb,sub_tree,hf_stat_my_id_proc,offset);

	return offset;
}

static int
dissect_stat_mon_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
	proto_item *sub_item;
	proto_tree *sub_tree;
	int offset = 0;

	sub_item = proto_tree_add_item(tree, hf_stat_mon, tvb,
				offset, mon_id_len(tvb,offset), ENC_NA);
	sub_tree = proto_item_add_subtree(sub_item, ett_stat_mon);

	offset = dissect_rpc_string(tvb,sub_tree,hf_stat_mon_id_name,offset,NULL);

	offset = dissect_stat_my_id(tvb,offset,sub_tree);

	return offset;
}

static int
dissect_stat_priv(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_stat_priv, tvb, offset, 16, ENC_NA);
	offset += 16;

	return offset;
}

static int
dissect_stat_mon(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	int offset = dissect_stat_mon_id(tvb,pinfo,tree,data);

	offset = dissect_stat_priv(tvb,offset,tree);
	return offset;
}

static int
dissect_stat_state(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
	return dissect_rpc_uint32(tvb,tree,hf_stat_state,0);
}

static int
dissect_stat_notify(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
	proto_item *sub_item;
	proto_tree *sub_tree;
	int offset = 0;
	int start_offset = offset;

	sub_item = proto_tree_add_item(tree, hf_stat_stat_chge, tvb,
				offset, -1, ENC_NA);
	sub_tree = proto_item_add_subtree(sub_item, ett_stat_stat_chge);

	offset = dissect_rpc_string(tvb,sub_tree,hf_stat_mon_id_name,offset,NULL);

	offset = dissect_rpc_uint32(tvb,tree,hf_stat_state,offset);

	if(sub_item)
		proto_item_set_len(sub_item, offset - start_offset);

	return offset;
}

static int
dissect_stat_umon_all(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
	return dissect_stat_my_id(tvb,0,tree);
}

/* proc number, "proc name", dissect_request, dissect_reply */

static const vsff stat1_proc[] = {
	{ 0, "NULL",
	  dissect_rpc_void, dissect_rpc_void },
	{ STATPROC_STAT,       "STAT",
	  dissect_stat_stat, dissect_stat_stat_res },
	{ STATPROC_MON,        "MON",
	  dissect_stat_mon, dissect_stat_stat_res },
	{ STATPROC_UNMON,      "UNMON",
	  dissect_stat_mon_id, dissect_stat_state },
	{ STATPROC_UNMON_ALL,  "UNMON_ALL",
	  dissect_stat_umon_all, dissect_stat_state },
	{ STATPROC_SIMU_CRASH, "SIMU_CRASH",
	  dissect_rpc_void, dissect_rpc_void },
	{ STATPROC_NOTIFY,     "NOTIFY",
	  dissect_stat_notify, dissect_rpc_void },
	{ 0, NULL, NULL, NULL }
};
/* end of stat version 1 */


static const rpc_prog_vers_info stat_vers_info[] = {
	{ 1, stat1_proc, &hf_stat_procedure_v1 },
};

void
proto_register_stat(void)
{
	static hf_register_info hf[] = {
		{ &hf_stat_procedure_v1,
			{ "V1 Procedure", "stat.procedure_v1",
			  FT_UINT32, BASE_DEC, VALS(stat1_proc_vals), 0,
			  NULL, HFILL }
		},
		{ &hf_stat_mon_name,
			{ "Name", "stat.name",
			  FT_STRING, BASE_NONE, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_stat_stat_res,
			{ "Status Result", "stat.stat_res",
			  FT_NONE, BASE_NONE, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_stat_stat_res_res,
			{ "Result", "stat.stat_res.res",
			  FT_UINT32, BASE_DEC, VALS(stat_res), 0,
			  NULL, HFILL }
		},
		{ &hf_stat_stat_res_state,
			{ "State", "stat.stat_res.state",
			  FT_UINT32, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_stat_state,
			{ "State", "stat.state",
			  FT_UINT32, BASE_DEC, NULL, 0,
			  "State of local NSM", HFILL }
		},
		{ &hf_stat_mon,
			{ "Monitor", "stat.mon",
			  FT_NONE, BASE_NONE, NULL, 0,
			  "Monitor Host", HFILL }
		},
		{ &hf_stat_mon_id_name,
			{ "Monitor ID Name", "stat.mon_id.name",
			  FT_STRING, BASE_NONE, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_stat_my_id,
			{ "My ID", "stat.my_id",
			  FT_NONE, BASE_NONE, NULL, 0,
			  "My_ID structure", HFILL }
		},
		{ &hf_stat_my_id_hostname,
			{ "Hostname", "stat.my_id.hostname",
			  FT_STRING, BASE_NONE, NULL, 0,
			  "My_ID Host to callback", HFILL }
		},
		{ &hf_stat_my_id_prog,
			{ "Program", "stat.my_id.prog",
			  FT_UINT32, BASE_DEC, NULL, 0,
			  "My_ID Program to callback", HFILL }
		},
		{ &hf_stat_my_id_vers,
			{ "Version", "stat.my_id.vers",
			  FT_UINT32, BASE_DEC, NULL, 0,
			  "My_ID Version of callback", HFILL }
		},
		{ &hf_stat_my_id_proc,
			{ "Procedure", "stat.my_id.proc",
			  FT_UINT32, BASE_DEC, NULL, 0,
			  "My_ID Procedure to callback", HFILL }
		},
		{ &hf_stat_priv,
			{ "Priv", "stat.priv",
			  FT_BYTES, BASE_NONE, NULL, 0,
			  "Private client supplied opaque data", HFILL }
		},
		{ &hf_stat_stat_chge,
			{ "Status Change", "stat.stat_chge",
			  FT_NONE, BASE_NONE, NULL, 0,
			  "Status Change structure", HFILL }
		},
	};

	static int *ett[] = {
		&ett_stat,
		&ett_stat_stat_res,
		&ett_stat_mon,
		&ett_stat_my_id,
		&ett_stat_stat_chge,
	};

	proto_stat = proto_register_protocol("Network Status Monitor Protocol", "STAT", "stat");
	proto_register_field_array(proto_stat, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_stat(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_stat, STAT_PROGRAM, ett_stat,
	    G_N_ELEMENTS(stat_vers_info), stat_vers_info);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
