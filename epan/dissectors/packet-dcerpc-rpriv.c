/* packet-dcerpc-rpriv.c
 *
 * Routines for DCERPC Privilege Server operations
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/security.tar.gz  security/idl/rpriv.idl
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"


#include <epan/packet.h>
#include "packet-dcerpc.h"

void proto_register_rpriv (void);
void proto_reg_handoff_rpriv (void);

static int proto_rpriv;
static int hf_rpriv_opnum;
static int hf_rpriv_get_eptgt_rqst_authn_svc;
static int hf_rpriv_get_eptgt_rqst_authz_svc;
static int hf_rpriv_get_eptgt_rqst_var1;
/* static int hf_rpriv_get_eptgt_rqst_key_size; */
static int hf_rpriv_get_eptgt_rqst_key_size2;
static int hf_rpriv_get_eptgt_rqst_key_t;
static int hf_rpriv_get_eptgt_rqst_key_t2;

static int ett_rpriv;


static e_guid_t uuid_rpriv = { 0xb1e338f8, 0x9533, 0x11c9, { 0xa3, 0x4a, 0x08, 0x00, 0x1e, 0x01, 0x9c, 0x1e } };
static uint16_t ver_rpriv = 1;


static int
rpriv_dissect_get_eptgt_rqst (tvbuff_t *tvb, int offset,
			      packet_info *pinfo, proto_tree *tree,
			      dcerpc_info *di, uint8_t *drep)
{
	/*        [in]        handle_t         handle,
	 *        [in]        unsigned32       authn_svc,
	 *        [in]        unsigned32       authz_svc,
	 *        [in]        rpriv_pickle_t   *ptgt_req,
	 *                    unsigned32          num_bytes;
	 *                    [size_is(num_bytes)]
	 *                    byte            bytes[];
	 */

	uint32_t authn_svc, authz_svc, key_size, key_size2, var1;
	const uint8_t *key_t1 = NULL;
	const uint8_t *key_t2 = NULL;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_rpriv_get_eptgt_rqst_authn_svc, &authn_svc);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_rpriv_get_eptgt_rqst_authz_svc, &authz_svc);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_rpriv_get_eptgt_rqst_var1, &var1);
	offset += 276;
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_rpriv_get_eptgt_rqst_key_size2, &key_size);
	/* advance to get size of cell, and princ */

	proto_tree_add_item_ret_string(tree, hf_rpriv_get_eptgt_rqst_key_t, tvb, offset, key_size, ENC_ASCII|ENC_NA, pinfo->pool, &key_t1);
	offset += key_size;

	offset += 8;
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_rpriv_get_eptgt_rqst_key_size2, &key_size2);
	proto_tree_add_item_ret_string(tree, hf_rpriv_get_eptgt_rqst_key_t2, tvb, offset, key_size2, ENC_ASCII|ENC_NA, pinfo->pool, &key_t2);
	offset += key_size2;


	col_append_fstr(pinfo->cinfo, COL_INFO,
				" Request for: %s in %s ", key_t2, key_t1);

	return offset;

}


static const dcerpc_sub_dissector rpriv_dissectors[] = {
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
#if 0
		{ &hf_rpriv_get_eptgt_rqst_key_size,
		  { "Key_Size", "rpriv.get_eptgt_rqst_key_size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
#endif
		{ &hf_rpriv_get_eptgt_rqst_var1,
		  { "Var1", "rpriv.get_eptgt_rqst_var1", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_rpriv_get_eptgt_rqst_key_size2,
		  { "Key_Size", "rpriv.get_eptgt_rqst_key_size2", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_rpriv_get_eptgt_rqst_key_t,
		  { "Key_t", "rpriv.get_eptgt_rqst_key_t", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_rpriv_get_eptgt_rqst_key_t2,
		  { "Key_t2", "rpriv.get_eptgt_rqst_key_t2", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

	};

	static int *ett[] = {
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
