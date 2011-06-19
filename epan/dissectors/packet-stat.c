/* packet-stat.c
 * Routines for stat dissection
 *
 * $Id$
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


#include "packet-rpc.h"
#include "packet-stat.h"

static int proto_stat = -1;
static int hf_stat_procedure_v1 = -1;
static int hf_stat_mon_name = -1;
static int hf_stat_stat_res = -1;
static int hf_stat_stat_res_res = -1;
static int hf_stat_stat_res_state = -1;
static int hf_stat_state = -1;
static int hf_stat_mon = -1;
static int hf_stat_mon_id_name = -1;
static int hf_stat_my_id = -1;
static int hf_stat_my_id_hostname = -1;
static int hf_stat_my_id_prog = -1;
static int hf_stat_my_id_vers = -1;
static int hf_stat_my_id_proc = -1;
static int hf_stat_priv = -1;
static int hf_stat_stat_chge = -1;

static gint ett_stat = -1;
static gint ett_stat_stat_res = -1;
static gint ett_stat_mon = -1;
static gint ett_stat_my_id = -1;
static gint ett_stat_stat_chge = -1;

#define STAT_SUCC	0
#define STAT_FAIL	1

static const value_string stat_res[] =
{
	{	0,	"STAT_SUCC" },
	{	1,	"STAT_FAIL" },
	{	0,	NULL }
};

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
dissect_stat_stat(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	if (tree)
	{
		offset = dissect_rpc_string(tvb,tree,hf_stat_mon_name,offset,NULL);
	}

	return offset;
}

static int
dissect_stat_stat_res(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item* sub_item = NULL;
	proto_tree* sub_tree = NULL;
	gint32 res;

	if (tree) {
		sub_item = proto_tree_add_item(tree, hf_stat_stat_res, tvb,
				offset, -1, FALSE);
		if (sub_item)
			sub_tree = proto_item_add_subtree(sub_item, ett_stat_stat_res);
	}

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
	proto_item* sub_item = NULL;
	proto_tree* sub_tree = NULL;

	if (tree) {
		sub_item = proto_tree_add_item(tree, hf_stat_my_id, tvb,
				offset, my_id_len(tvb,offset), FALSE);
		if (sub_item)
			sub_tree = proto_item_add_subtree(sub_item, ett_stat_my_id);
	}

	offset = dissect_rpc_string(tvb,sub_tree,hf_stat_my_id_hostname,offset,NULL);
	offset = dissect_rpc_uint32(tvb,sub_tree,hf_stat_my_id_prog,offset);
	offset = dissect_rpc_uint32(tvb,sub_tree,hf_stat_my_id_vers,offset);
	offset = dissect_rpc_uint32(tvb,sub_tree,hf_stat_my_id_proc,offset);

	return offset;
}

static int
dissect_stat_mon_id(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item* sub_item = NULL;
	proto_tree* sub_tree = NULL;

	if (tree) {
		sub_item = proto_tree_add_item(tree, hf_stat_mon, tvb,
				offset, mon_id_len(tvb,offset), FALSE);
		if (sub_item)
			sub_tree = proto_item_add_subtree(sub_item, ett_stat_mon);
	}


	offset = dissect_rpc_string(tvb,sub_tree,hf_stat_mon_id_name,offset,NULL);

	offset = dissect_stat_my_id(tvb,offset,sub_tree);

	return offset;
}

static int
dissect_stat_priv(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_stat_priv, tvb, offset, 16, FALSE);
	offset += 16;

	return offset;
}

static int
dissect_stat_mon(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{

	offset = dissect_stat_mon_id(tvb,offset,pinfo,tree);

	offset = dissect_stat_priv(tvb,offset,tree);
	return offset;
}

static int
dissect_stat_state(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb,tree,hf_stat_state,offset);

	return offset;
}

static int
dissect_stat_notify(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item* sub_item = NULL;
	proto_tree* sub_tree = NULL;
	int start_offset = offset;

	if (tree) {
		sub_item = proto_tree_add_item(tree, hf_stat_stat_chge, tvb,
				offset, -1, FALSE);
		if (sub_item)
			sub_tree = proto_item_add_subtree(sub_item, ett_stat_stat_chge);
	}

	offset = dissect_rpc_string(tvb,sub_tree,hf_stat_mon_id_name,offset,NULL);

	offset = dissect_rpc_uint32(tvb,tree,hf_stat_state,offset);

	if(sub_item)
		proto_item_set_len(sub_item, offset - start_offset);

	return offset;
}

static int
dissect_stat_umon_all(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_stat_my_id(tvb,offset,tree);

	return offset;
}

/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: type of arguments is "void". */

static const vsff stat1_proc[] = {
    { 0, "NULL", NULL, NULL },
    { STATPROC_STAT,   "STAT",
		dissect_stat_stat, dissect_stat_stat_res },
    { STATPROC_MON,   "MON",
		dissect_stat_mon, dissect_stat_stat_res },
    { STATPROC_UNMON, "UNMON",
		dissect_stat_mon_id, dissect_stat_state },
    { STATPROC_UNMON_ALL, "UNMON_ALL",
		dissect_stat_umon_all, dissect_stat_state },
    { STATPROC_SIMU_CRASH, "SIMU_CRASH",
		NULL, NULL },
    { STATPROC_NOTIFY, "NOTIFY",
		dissect_stat_notify, NULL },
    { 0, NULL, NULL, NULL }
};
static const value_string stat1_proc_vals[] = {
    { 0, "NULL" },
    { STATPROC_STAT,   "STAT" },
    { STATPROC_MON,   "MON" },
    { STATPROC_UNMON, "UNMON" },
    { STATPROC_UNMON_ALL, "UNMON_ALL" },
    { STATPROC_SIMU_CRASH, "SIMU_CRASH" },
    { STATPROC_NOTIFY, "NOTIFY" },
    { 0, NULL }
};
/* end of stat version 1 */


void
proto_register_stat(void)
{
	static hf_register_info hf[] = {
		{ &hf_stat_procedure_v1, {
			"V1 Procedure", "stat.procedure_v1", FT_UINT32, BASE_DEC,
			VALS(stat1_proc_vals), 0, NULL, HFILL }},
		{ &hf_stat_mon_name, {
			"Name", "stat.name", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_stat_stat_res, {
			"Status Result", "stat.stat_res", FT_NONE,BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_stat_stat_res_res, {
			"Result", "stat.stat_res.res", FT_UINT32, BASE_DEC,
			VALS(stat_res), 0, NULL, HFILL }},
		{ &hf_stat_stat_res_state, {
			"State", "stat.stat_res.state", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_stat_mon, {
			"Monitor", "stat.mon", FT_NONE, BASE_NONE,
			NULL, 0, "Monitor Host", HFILL }},
		{ &hf_stat_mon_id_name, {
			"Monitor ID Name", "stat.mon_id.name", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }},
		{ &hf_stat_my_id, {
			"My ID", "stat.my_id", FT_NONE,BASE_NONE,
			NULL, 0, "My_ID structure", HFILL }},
		{ &hf_stat_my_id_hostname, {
			"Hostname", "stat.my_id.hostname", FT_STRING, BASE_NONE,
			NULL, 0, "My_ID Host to callback", HFILL }},
		{ &hf_stat_my_id_prog, {
			"Program", "stat.my_id.prog", FT_UINT32, BASE_DEC,
			NULL, 0, "My_ID Program to callback", HFILL }},
		{ &hf_stat_my_id_vers, {
			"Version", "stat.my_id.vers", FT_UINT32, BASE_DEC,
			NULL, 0, "My_ID Version of callback", HFILL }},
		{ &hf_stat_my_id_proc, {
			"Procedure", "stat.my_id.proc", FT_UINT32, BASE_DEC,
			NULL, 0, "My_ID Procedure to callback", HFILL }},
		{ &hf_stat_priv, {
			"Priv", "stat.priv", FT_BYTES, BASE_NONE,
			NULL, 0, "Private client supplied opaque data", HFILL }},
		{ &hf_stat_state, {
			"State", "stat.state", FT_UINT32, BASE_DEC,
			NULL, 0, "State of local NSM", HFILL }},
		{ &hf_stat_stat_chge, {
			"Status Change", "stat.stat_chge", FT_NONE, BASE_NONE,
			NULL, 0, "Status Change structure", HFILL }},
	};

	static gint *ett[] = {
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
	rpc_init_prog(proto_stat, STAT_PROGRAM, ett_stat);
	/* Register the procedure tables */
	rpc_init_proc_table(STAT_PROGRAM, 1, stat1_proc, hf_stat_procedure_v1);
}
