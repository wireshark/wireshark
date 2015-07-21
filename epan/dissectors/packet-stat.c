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

#define NEW_PROTO_TREE_API

#include "config.h"

#include "packet-rpc.h"
#include "packet-stat.h"

void proto_register_stat(void);
void proto_reg_handoff_stat(void);

static header_field_info *hfi_stat = NULL;

#define STAT_HFI_INIT HFI_INIT(proto_stat)

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

static header_field_info hfi_stat_procedure_v1 STAT_HFI_INIT = {
	"V1 Procedure", "stat.procedure_v1", FT_UINT32, BASE_DEC,
	VALS(stat1_proc_vals), 0, NULL, HFILL };

static header_field_info hfi_stat_mon_name STAT_HFI_INIT = {
	"Name", "stat.name", FT_STRING, BASE_NONE,
	NULL, 0, NULL, HFILL };

static header_field_info hfi_stat_stat_res STAT_HFI_INIT = {
	"Status Result", "stat.stat_res", FT_NONE,BASE_NONE,
	NULL, 0, NULL, HFILL };

static const value_string stat_res[] =
{
	{ 0, "STAT_SUCC" },
	{ 1, "STAT_FAIL" },
	{ 0, NULL }
};

static header_field_info hfi_stat_stat_res_res STAT_HFI_INIT = {
	"Result", "stat.stat_res.res", FT_UINT32, BASE_DEC,
	VALS(stat_res), 0, NULL, HFILL };

static header_field_info hfi_stat_stat_res_state STAT_HFI_INIT = {
	"State", "stat.stat_res.state", FT_UINT32, BASE_DEC,
	NULL, 0, NULL, HFILL };

static header_field_info hfi_stat_state STAT_HFI_INIT = {
	"State", "stat.state", FT_UINT32, BASE_DEC,
	NULL, 0, "State of local NSM", HFILL };

static header_field_info hfi_stat_mon STAT_HFI_INIT = {
	"Monitor", "stat.mon", FT_NONE, BASE_NONE,
	NULL, 0, "Monitor Host", HFILL };

static header_field_info hfi_stat_mon_id_name STAT_HFI_INIT = {
	"Monitor ID Name", "stat.mon_id.name", FT_STRING, BASE_NONE,
	NULL, 0, NULL, HFILL };

static header_field_info hfi_stat_my_id STAT_HFI_INIT = {
	"My ID", "stat.my_id", FT_NONE,BASE_NONE,
	NULL, 0, "My_ID structure", HFILL };

static header_field_info hfi_stat_my_id_hostname STAT_HFI_INIT = {
	"Hostname", "stat.my_id.hostname", FT_STRING, BASE_NONE,
	NULL, 0, "My_ID Host to callback", HFILL };

static header_field_info hfi_stat_my_id_prog STAT_HFI_INIT = {
	"Program", "stat.my_id.prog", FT_UINT32, BASE_DEC,
	NULL, 0, "My_ID Program to callback", HFILL };

static header_field_info hfi_stat_my_id_vers STAT_HFI_INIT = {
	"Version", "stat.my_id.vers", FT_UINT32, BASE_DEC,
	NULL, 0, "My_ID Version of callback", HFILL };

static header_field_info hfi_stat_my_id_proc STAT_HFI_INIT = {
	"Procedure", "stat.my_id.proc", FT_UINT32, BASE_DEC,
	NULL, 0, "My_ID Procedure to callback", HFILL };

static header_field_info hfi_stat_priv STAT_HFI_INIT = {
	"Priv", "stat.priv", FT_BYTES, BASE_NONE,
	NULL, 0, "Private client supplied opaque data", HFILL };

static header_field_info hfi_stat_stat_chge STAT_HFI_INIT = {
	"Status Change", "stat.stat_chge", FT_NONE, BASE_NONE,
	NULL, 0, "Status Change structure", HFILL };


static gint ett_stat = -1;
static gint ett_stat_stat_res = -1;
static gint ett_stat_mon = -1;
static gint ett_stat_my_id = -1;
static gint ett_stat_stat_chge = -1;

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
	return dissect_rpc_string(tvb,tree,hfi_stat_mon_name.id,0,NULL);
}

static int
dissect_stat_stat_res(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
	proto_item *sub_item;
	proto_tree *sub_tree;
	gint32 res;
	int offset = 0;

	sub_item = proto_tree_add_item(tree, &hfi_stat_stat_res, tvb,
				offset, -1, ENC_NA);
	sub_tree = proto_item_add_subtree(sub_item, ett_stat_stat_res);

	res = tvb_get_ntohl(tvb, offset);
	offset = dissect_rpc_uint32(tvb,sub_tree,hfi_stat_stat_res_res.id,offset);

	if (res==STAT_SUCC) {
		offset = dissect_rpc_uint32(tvb,sub_tree,hfi_stat_stat_res_state.id,offset);
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

	sub_item = proto_tree_add_item(tree, &hfi_stat_my_id, tvb,
				offset, my_id_len(tvb,offset), ENC_NA);
	sub_tree = proto_item_add_subtree(sub_item, ett_stat_my_id);

	offset = dissect_rpc_string(tvb,sub_tree,hfi_stat_my_id_hostname.id,offset,NULL);
	offset = dissect_rpc_uint32(tvb,sub_tree,hfi_stat_my_id_prog.id,offset);
	offset = dissect_rpc_uint32(tvb,sub_tree,hfi_stat_my_id_vers.id,offset);
	offset = dissect_rpc_uint32(tvb,sub_tree,hfi_stat_my_id_proc.id,offset);

	return offset;
}

static int
dissect_stat_mon_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
	proto_item *sub_item;
	proto_tree *sub_tree;
	int offset = 0;

	sub_item = proto_tree_add_item(tree, &hfi_stat_mon, tvb,
				offset, mon_id_len(tvb,offset), ENC_NA);
	sub_tree = proto_item_add_subtree(sub_item, ett_stat_mon);

	offset = dissect_rpc_string(tvb,sub_tree,hfi_stat_mon_id_name.id,offset,NULL);

	offset = dissect_stat_my_id(tvb,offset,sub_tree);

	return offset;
}

static int
dissect_stat_priv(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_tree_add_item(tree, &hfi_stat_priv, tvb, offset, 16, ENC_NA);
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
	return dissect_rpc_uint32(tvb,tree,hfi_stat_state.id,0);
}

static int
dissect_stat_notify(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
	proto_item *sub_item;
	proto_tree *sub_tree;
	int offset = 0;
	int start_offset = offset;

	sub_item = proto_tree_add_item(tree, &hfi_stat_stat_chge, tvb,
				offset, -1, ENC_NA);
	sub_tree = proto_item_add_subtree(sub_item, ett_stat_stat_chge);

	offset = dissect_rpc_string(tvb,sub_tree,hfi_stat_mon_id_name.id,offset,NULL);

	offset = dissect_rpc_uint32(tvb,tree,hfi_stat_state.id,offset);

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
	{ 1, stat1_proc, &hfi_stat_procedure_v1.id },
};

void
proto_register_stat(void)
{
#ifndef HAVE_HFI_SECTION_INIT
	static header_field_info *hfi[] = {
		&hfi_stat_procedure_v1,
		&hfi_stat_mon_name,
		&hfi_stat_stat_res,
		&hfi_stat_stat_res_res,
		&hfi_stat_stat_res_state,
		&hfi_stat_mon,
		&hfi_stat_mon_id_name,
		&hfi_stat_my_id,
		&hfi_stat_my_id_hostname,
		&hfi_stat_my_id_prog,
		&hfi_stat_my_id_vers,
		&hfi_stat_my_id_proc,
		&hfi_stat_priv,
		&hfi_stat_state,
		&hfi_stat_stat_chge,
	};
#endif

	static gint *ett[] = {
		&ett_stat,
		&ett_stat_stat_res,
		&ett_stat_mon,
		&ett_stat_my_id,
		&ett_stat_stat_chge,
	};

	int proto_stat;

	proto_stat = proto_register_protocol("Network Status Monitor Protocol", "STAT", "stat");
	hfi_stat   = proto_registrar_get_nth(proto_stat);

	proto_register_fields(proto_stat, hfi, array_length(hfi));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_stat(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(hfi_stat->id, STAT_PROGRAM, ett_stat,
	    G_N_ELEMENTS(stat_vers_info), stat_vers_info);
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
