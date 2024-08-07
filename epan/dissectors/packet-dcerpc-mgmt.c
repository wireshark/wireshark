/* packet-dcerpc-mgmt.c
 * Routines for dcerpc mgmt dissection
 * Copyright 2001, Todd Sabin <tas@webspan.net>
 * Copyright 2011, Matthieu Patou <mat@matws.net>
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
#include "packet-dcerpc-nt.h"

void proto_register_mgmt (void);
void proto_reg_handoff_mgmt (void);

static int proto_mgmt;
static int hf_mgmt_opnum;
static int hf_mgmt_proto;
static int hf_mgmt_rc;
static int hf_mgmt_princ_size;
static int hf_mgmt_princ_name;
static int ett_mgmt;


static e_guid_t uuid_mgmt = { 0xafa8bd80, 0x7d8a, 0x11c9, { 0xbe, 0xf4, 0x08, 0x00, 0x2b, 0x10, 0x29, 0x89 } };
static uint16_t ver_mgmt = 1;

static int
mgmtrpc_dissect_inq_princ_name_response(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep)
{

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, di, drep,
					sizeof(uint8_t), hf_mgmt_princ_name, true, NULL);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, di, drep, hf_mgmt_rc, NULL);


	return offset;
}
static int
mgmtrpc_dissect_inq_princ_name_request(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_mgmt_proto, NULL);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_mgmt_princ_size, NULL);
	return offset;
}



static const dcerpc_sub_dissector mgmt_dissectors[] = {
	{ 0, "rpc__mgmt_inq_if_ids", NULL, NULL },
	{ 1, "rpc__mgmt_inq_stats", NULL, NULL },
	{ 2, "rpc__mgmt_is_server_listening", NULL, NULL },
	{ 3, "rpc__mgmt_stop_server_listening", NULL, NULL },
	{ 4, "rpc__mgmt_inq_princ_name", mgmtrpc_dissect_inq_princ_name_request, mgmtrpc_dissect_inq_princ_name_response},
	{ 0, NULL, NULL, NULL }
};

void
proto_register_mgmt (void)
{
	static hf_register_info hf[] = {
		{ &hf_mgmt_opnum,
		  { "Operation", "mgmt.opnum", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_mgmt_proto,
		  {"Authn Proto", "mgmt.proto", FT_UINT32, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_mgmt_princ_name,
		  {"Principal name", "mgmt.princ_name", FT_STRING, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_mgmt_princ_size,
		  {"Principal size", "mgmt.princ_size", FT_UINT32, BASE_DEC,
		    NULL, 0x0, "Size of principal", HFILL }},
		{ &hf_mgmt_rc,
		  {"Status", "mgmt.rc", FT_UINT32, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
	};

	static int *ett[] = {
		&ett_mgmt
	};
	proto_mgmt = proto_register_protocol ("DCE/RPC Remote Management", "MGMT", "mgmt");
	proto_register_field_array (proto_mgmt, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_mgmt (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_mgmt, ett_mgmt, &uuid_mgmt, ver_mgmt, mgmt_dissectors, hf_mgmt_opnum);
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
