/* packet-dcerpc-rs_acct.c
 *
 * Routines for DFS/RS_ACCT
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/security.tar.gz security/idl/rs_acct.idl
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"


#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"


static int proto_rs_acct = -1;
static int hf_rs_acct_opnum = -1;
static int hf_rs_acct_lookup_rqst_var = -1;
static int hf_rs_acct_lookup_rqst_key_size = -1;
static int hf_rs_acct_lookup_rqst_key_t = -1;
static int hf_rs_acct_get_projlist_rqst_var1 = -1;
static int hf_rs_acct_get_projlist_rqst_key_size = -1;
static int hf_rs_acct_get_projlist_rqst_key_t = -1;


static gint ett_rs_acct = -1;



static e_uuid_t uuid_rs_acct = { 0x4c878280, 0x2000, 0x0000, { 0x0d, 0x00, 0x02, 0x87, 0x14, 0x00, 0x00, 0x00 } };
static guint16  ver_rs_acct = 1;


static int
rs_acct_dissect_lookup_rqst (tvbuff_t *tvb, int offset,
		packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint32 key_size;
	const char *keyx_t = NULL;

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_rs_acct_lookup_rqst_var, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_rs_acct_lookup_rqst_key_size, &key_size);

	if (key_size){ /* Not able to yet decipher the OTHER versions of this call just yet. */
		proto_tree_add_item (tree, hf_rs_acct_lookup_rqst_key_t, tvb, offset, key_size, ENC_ASCII|ENC_NA);
		keyx_t = tvb_get_ephemeral_string(tvb, offset, key_size);
		offset += key_size;

		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_append_fstr(pinfo->cinfo, COL_INFO,
				" Request for: %s ", keyx_t);
		}
	} else {
		col_append_str(pinfo->cinfo, COL_INFO,
				" Request (other)");
	}

	return offset;
}



static int
rs_acct_dissect_get_projlist_rqst (tvbuff_t *tvb, int offset,
		packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint32 key_size;
	const char *keyx_t = NULL;

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_rs_acct_get_projlist_rqst_var1, NULL);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_rs_acct_get_projlist_rqst_key_size, &key_size);

	proto_tree_add_item (tree, hf_rs_acct_get_projlist_rqst_key_t,
			     tvb, offset, key_size, ENC_ASCII|ENC_NA);
	keyx_t = tvb_get_ephemeral_string(tvb, offset, key_size);
	offset += key_size;

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,
			" Request for: %s", keyx_t);
	}

	return offset;
}


static dcerpc_sub_dissector rs_acct_dissectors[] = {
        { 0, "add", NULL, NULL},
        { 1, "delete", NULL, NULL},
        { 2, "rename", NULL, NULL},
        { 3, "lookup", rs_acct_dissect_lookup_rqst, NULL},
        { 4, "replace", NULL, NULL},
        { 5, "get_projlist", rs_acct_dissect_get_projlist_rqst, NULL},
        { 0, NULL, NULL, NULL }
};

void
proto_register_rs_acct (void)
{
	static hf_register_info hf[] = {
	{ &hf_rs_acct_opnum,
		{ "Operation", "rs_acct.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_rs_acct_lookup_rqst_var,
		{ "Var", "rs_acct.lookup_rqst_var", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_rs_acct_lookup_rqst_key_size,
		{ "Key Size", "rs_acct.lookup_rqst_key_size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_rs_acct_lookup_rqst_key_t,
		{ "Key", "rs_acct.lookup_rqst_key_t", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_rs_acct_get_projlist_rqst_var1,
		{ "Var1", "rs_acct.get_projlist_rqst_var1", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_rs_acct_get_projlist_rqst_key_size,
		{ "Var1", "rs_acct.get_projlist_rqst_key_size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_rs_acct_get_projlist_rqst_key_t,
		{ "Var1", "rs_acct.get_projlist_rqst_key_t", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_rs_acct,
	};
	proto_rs_acct = proto_register_protocol ("DCE/RPC RS_ACCT", "RS_ACCT", "rs_acct");
	proto_register_field_array (proto_rs_acct, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}



void
proto_reg_handoff_rs_acct (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_rs_acct, ett_rs_acct, &uuid_rs_acct, ver_rs_acct, rs_acct_dissectors, hf_rs_acct_opnum);
}
