/* packet-dcerpc-frsapi.c
 * Routines for the frs API (File Replication Service) MSRPC interface
 * Copyright 2004 Jean-Baptiste Marchand <jbm@hsc.fr>
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
#include "packet-dcerpc-frsapi.h"

void proto_register_dcerpc_frsapi(void);
void proto_reg_handoff_dcerpc_frsapi(void);

static int proto_dcerpc_frsapi = -1;

static int hf_frsapi_opnum = -1;

static gint ett_dcerpc_frsapi = -1;

/*
IDL [ uuid(d049b186-814f-11d1-9a3c-00c04fc9b232),
IDL  version(1.1),
IDL  implicit_handle(handle_t rpc_binding)
IDL ] interface frsapi
*/

static e_uuid_t uuid_dcerpc_frsapi = {
	0xd049b186, 0x814f, 0x11d1,
	{ 0x9a, 0x3c, 0x00, 0xc0, 0x4f, 0xc9, 0xb2, 0x32 }
};

static guint16 ver_dcerpc_frsapi = 1;


static dcerpc_sub_dissector dcerpc_frsapi_dissectors[] = {
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


        static gint *ett[] = {
                &ett_dcerpc_frsapi,
        };


	proto_dcerpc_frsapi = proto_register_protocol(
		"Microsoft File Replication Service API", "FRSAPI", "frsapi");

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
