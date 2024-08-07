/* packet-dcerpc-frsapi.c
 * Routines for the frs API (File Replication Service) MSRPC interface
 * Copyright 2004 Jean-Baptiste Marchand <jbm@hsc.fr>
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
#include "packet-dcerpc-frsapi.h"

void proto_register_dcerpc_frsapi(void);
void proto_reg_handoff_dcerpc_frsapi(void);

static int proto_dcerpc_frsapi;

static int hf_frsapi_opnum;

static int ett_dcerpc_frsapi;

/*
IDL [ uuid(d049b186-814f-11d1-9a3c-00c04fc9b232),
IDL  version(1.1),
IDL  implicit_handle(handle_t rpc_binding)
IDL ] interface frsapi
*/

static e_guid_t uuid_dcerpc_frsapi = {
	0xd049b186, 0x814f, 0x11d1,
	{ 0x9a, 0x3c, 0x00, 0xc0, 0x4f, 0xc9, 0xb2, 0x32 }
};

static uint16_t ver_dcerpc_frsapi = 1;


static const dcerpc_sub_dissector dcerpc_frsapi_dissectors[] = {
	{  FRSAPI_VERIFY_PROMOTION,          "VerifyPromotion",        NULL, NULL },
	{  FRSAPI_PROMOTION_STATUS,          "PromotionStatus",        NULL, NULL },
	{  FRSAPI_START_DEMOTION,            "StartDemotion",          NULL, NULL },
	{  FRSAPI_COMMIT_DEMOTION,           "CommitDemotion",         NULL, NULL },
	{  FRSAPI_SET_DS_POLLING_INTERVAL_W, "Set_DsPollingIntervalW", NULL, NULL },
	{  FRSAPI_GET_DS_POLLING_INTERVAL_W, "Get_DsPollingIntervalW", NULL, NULL },
	{  FRSAPI_VERIFY_PROMOTION_W,        "VerifyPromotionW",       NULL, NULL },
	{  FRSAPI_INFO_W,                    "InfoW",                  NULL, NULL },
	{  FRSAPI_IS_PATH_REPLICATED,        "IsPathReplicated",       NULL, NULL },
	{  FRSAPI_WRITER_COMMAND,            "WriterCommand",          NULL, NULL },
	{ 0, NULL, NULL,  NULL }
};

void
proto_register_dcerpc_frsapi(void)
{

	static hf_register_info hf[] = {

		{ &hf_frsapi_opnum,
		  { "Operation", "frsapi.opnum", FT_UINT16, BASE_DEC,
		   NULL, 0x0, NULL, HFILL }},
	};


	static int *ett[] = {
		&ett_dcerpc_frsapi,
	};


	proto_dcerpc_frsapi = proto_register_protocol("Microsoft File Replication Service API", "FRSAPI", "frsapi");

	proto_register_field_array(proto_dcerpc_frsapi, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));

}


void
proto_reg_handoff_dcerpc_frsapi(void)
{
	/* register protocol as dcerpc */

	dcerpc_init_uuid(
		proto_dcerpc_frsapi, ett_dcerpc_frsapi, &uuid_dcerpc_frsapi,
		ver_dcerpc_frsapi, dcerpc_frsapi_dissectors, hf_frsapi_opnum);
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
