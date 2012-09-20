/* packet-dcerpc-rpriv.c
 *
 * Routines for DCERPC Privilege Server operations
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/security.tar.gz  security/idl/rpriv.idl
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


static int proto_rpriv = -1;
static int hf_rpriv_opnum = -1;
static int hf_rpriv_get_eptgt_rqst_authn_svc = -1;
static int hf_rpriv_get_eptgt_rqst_authz_svc = -1;
static int hf_rpriv_get_eptgt_rqst_var1 = -1;
static int hf_rpriv_get_eptgt_rqst_key_size = -1;
static int hf_rpriv_get_eptgt_rqst_key_size2 = -1;
static int hf_rpriv_get_eptgt_rqst_key_t = -1;
static int hf_rpriv_get_eptgt_rqst_key_t2 = -1;

static gint ett_rpriv = -1;


static e_uuid_t uuid_rpriv = { 0xb1e338f8, 0x9533, 0x11c9, { 0xa3, 0x4a, 0x08, 0x00, 0x1e, 0x01, 0x9c, 0x1e } };
static guint16  ver_rpriv = 1;


static int
rpriv_dissect_get_eptgt_rqst (tvbuff_t *tvb, int offset,
			      packet_info *pinfo, proto_tree *tree,
			      guint8 *drep)
{
	/*        [in]        handle_t         handle,
	 *        [in]        unsigned32       authn_svc,
	 *        [in]        unsigned32       authz_svc,
	 *        [in]        rpriv_pickle_t   *ptgt_req,
	 *                    unsigned32          num_bytes;
	 *                    [size_is(num_bytes)]
	 *                    byte            bytes[];
	 */

	guint32 authn_svc, authz_svc, key_size, key_size2, var1;
	const char *key_t1 = NULL;
	const char *key_t2 = NULL;

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_rpriv_get_eptgt_rqst_authn_svc, &authn_svc);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_rpriv_get_eptgt_rqst_authz_svc, &authz_svc);
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_rpriv_get_eptgt_rqst_var1, &var1);
	offset += 276;
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_rpriv_get_eptgt_rqst_key_size2, &key_size);
	/* advance to get size of cell, and princ */

	proto_tree_add_item (tree, hf_rpriv_get_eptgt_rqst_key_t, tvb, offset, key_size, ENC_ASCII|ENC_NA);
	key_t1 = tvb_get_ephemeral_string(tvb, offset, key_size);
	offset += key_size;

	offset += 8;
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep, hf_rpriv_get_eptgt_rqst_key_size2, &key_size2);
	proto_tree_add_item (tree, hf_rpriv_get_eptgt_rqst_key_t2, tvb, offset, key_size2, ENC_ASCII|ENC_NA);
	key_t2 = tvb_get_ephemeral_string(tvb, offset, key_size2);
	offset += key_size2;


	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,
				" Request for: %s in %s ", key_t2, key_t1);
	}

	return offset;

}


static dcerpc_sub_dissector rpriv_dissectors[] = {
	{ 0, "get_ptgt", NULL,NULL},
	{ 1, "become_delegate", NULL, NULL},
	{ 2, "become_impersonator", NULL, NULL},
	{ 3, "get_eptgt", rpriv_dissect_get_eptgt_rqst , NULL},
	{ 0, NULL, NULL, NULL }
};

void
proto_register_rpriv (void)
{
	static hf_register_info hf[] = {
		{ &hf_rpriv_opnum,
		  { "Operation", "rpriv.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_rpriv_get_eptgt_rqst_authn_svc,
		  { "Authn_Svc", "rpriv.get_eptgt_rqst_authn_svc", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_rpriv_get_eptgt_rqst_authz_svc,
		  { "Authz_Svc", "rpriv.get_eptgt_rqst_authz_svc", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_rpriv_get_eptgt_rqst_key_size,
		  { "Key_Size", "rpriv.get_eptgt_rqst_key_size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_rpriv_get_eptgt_rqst_var1,
		  { "Var1", "rpriv.get_eptgt_rqst_var1", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_rpriv_get_eptgt_rqst_key_size2,
		  { "Key_Size", "rpriv.get_eptgt_rqst_key_size2", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_rpriv_get_eptgt_rqst_key_t,
		  { "Key_t", "rpriv.get_eptgt_rqst_key_t", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_rpriv_get_eptgt_rqst_key_t2,
		  { "Key_t2", "rpriv.get_eptgt_rqst_key_t2", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

	};

	static gint *ett[] = {
		&ett_rpriv,
	};
	proto_rpriv = proto_register_protocol ("Privilege Server operations", "rpriv", "rpriv");
	proto_register_field_array (proto_rpriv, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_rpriv (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_rpriv, ett_rpriv, &uuid_rpriv, ver_rpriv, rpriv_dissectors, hf_rpriv_opnum);
}
