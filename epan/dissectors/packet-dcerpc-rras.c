/* packet-dcerpc-rras.c
 * Routines for the rras (Routing and Remote Access service) MSRPC interface
 * Copyright 2005 Jean-Baptiste Marchand <jbm@hsc.fr>
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

#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-rras.h"

void proto_register_dcerpc_rras(void);
void proto_reg_handoff_dcerpc_rras(void);

static int proto_dcerpc_rras = -1;

static int hf_rras_opnum = -1;

static gint ett_dcerpc_rras = -1;

/*
 * The rras MSRPC interface is typically reached using the ncacn_np transport
 * and the \pipe\ROUTER named pipe as endpoint.
 */

static e_guid_t uuid_dcerpc_rras = {
	0x8f09f000, 0xb7ed, 0x11ce,
	{ 0xbb, 0xd2, 0x00, 0x00, 0x1a, 0x18, 0x1c, 0xad }
};

static guint16 ver_dcerpc_rras = 0;


static dcerpc_sub_dissector dcerpc_rras_dissectors[] = {
	{ RRAS_ADMIN_SERVER_GETINFO,
		"MprAdminServerGetInfo", NULL, NULL },
	{ RRAS_ADMIN_CONNECTION_ENUM,
		"RasAdminConnectionEnum", NULL, NULL },
	{ RRAS_ADMIN_CONNECTION_GETINFO,
		"RasAdminConnectionGetInfo", NULL, NULL },
	{ RRAS_ADMIN_CONNECTION_CLEARSTATS,
		"RasAdminConnectionClearStats", NULL, NULL },
	{ RRAS_ADMIN_PORT_ENUM,
		"RasAdminPortEnum", NULL, NULL },
	{ RRAS_ADMIN_PORT_GETINFO,
		"RasAdminPortGetInfo", NULL, NULL },
	{ RRAS_ADMIN_PORT_CLEARSTATS,
		"RasAdminPortClearStats", NULL, NULL },
	{ RRAS_ADMIN_PORT_RESET,
		"RasAdminPortReset", NULL, NULL },
	{ RRAS_ADMIN_PORT_DISCONNECT,
		"RasAdminPortDisconnect", NULL, NULL },
	{ RRAS_RI_TRANS_SET_GLOBALINFO,
		"RouterInterfaceTransportSetGlobalInfo", NULL, NULL },
	{ RRAS_RI_TRANS_GET_GLOBALINFO,
		"RouterInterfaceTransportGetGlobalInfo", NULL, NULL },
	{ RRAS_RI_GET_HANDLE,
		"RouterInterfaceGetHandle", NULL, NULL },
	{ RRAS_RI_CREATE,
		"RouterInterfaceCreate", NULL, NULL },
	{ RRAS_RI_GETINFO,
		"RouterInterfaceGetInfo", NULL, NULL },
	{ RRAS_RI_SETINFO,
		"RouterInterfaceSetInfo", NULL, NULL },
	{ RRAS_RI_DELETE,
		"RouterInterfaceDelete", NULL, NULL },
	{ RRAS_TRANS_REMOVE,
		"RouterInterfaceTransportRemove", NULL, NULL },
	{ RRAS_TRANS_ADD,
		"RouterInterfaceTransportAdd", NULL, NULL },
	{ RRAS_TRANS_GETINFO,
		"RouterInterfaceTransportGetInfo", NULL, NULL },
	{ RRAS_TRANS_SETINFO,
		"RouterInterfaceTransportSetInfo", NULL, NULL },
	{ RRAS_RI_ENUM,
		"RouterInterfaceEnum", NULL, NULL },
	{ RRAS_RI_CONNECT,
		"RouterInterfaceConnect", NULL, NULL },
	{ RRAS_RI_DISCONNECT,
		"RouterInterfaceDisconnect", NULL, NULL },
	{ RRAS_RI_UPDATE_ROUTES,
		"RouterInterfaceUpdateRoutes", NULL, NULL },
	{ RRAS_RI_QUERY_UPDATE_RESULT,
		"RouterInterfaceQueryUpdateResult", NULL, NULL },
	{ RRAS_RI_UPDATE_PB_INFO,
		"RouterInterfaceUpdatePhonebookInfo", NULL, NULL },
	{ RRAS_MIB_ENTRY_CREATE, "MIBEntryCreate", NULL, NULL },
	{ RRAS_MIB_ENTRY_DELETE, "MIBEntryDelete", NULL, NULL },
	{ RRAS_MIB_ENTRY_SET, "MIBEntrySet", NULL, NULL },
	{ RRAS_MIB_ENTRY_GET, "MIBEntryGet", NULL, NULL },
	{ RRAS_MIB_GET_FIRST, "MIBEntryGetFirst", NULL, NULL },
	{ RRAS_MIB_GET_NEXT, "MIBEntryGetNext", NULL, NULL },
	{ RRAS_GET_TRAP_INFO, "MIBGetTrapInfo", NULL, NULL },
	{ RRAS_SET_TRAP_INFO, "MIBSetTrapInfo", NULL, NULL },
	{ RRAS_ADMIN_CONNECTION_NOTIFICATION,
		"RasAdminConnectionNotification", NULL, NULL },
	{ RRAS_ADMIN_SEND_USER_MSG, "RasAdminSendUserMessage", NULL, NULL },
	{ RRAS_ROUTER_DEVICE_ENUM, "RouterDeviceEnum", NULL, NULL },
	{ RRAS_RI_TRANSPORT_CREATE,
		"RouterInterfaceTransportCreate", NULL, NULL },
	{ RRAS_RI_DEV_GETINFO, "RouterInterfaceDeviceGetInfo", NULL, NULL },
	{ RRAS_RI_DEV_SETINFO, "RouterInterfaceDeviceSetInfo", NULL, NULL },
	{ RRAS_RI_SET_CRED_EX, "RouterInterfaceSetCredentialsEx", NULL, NULL },
	{ RRAS_RI_GET_CRED_EX, "RouterInterfaceGetCredentialsEx", NULL, NULL },
	{ RRAS_ADMIN_CONNECTION_REM_QUARANT,
		"RasAdminConnectionRemoveQuarantine", NULL, NULL },
	{ 0, NULL, NULL,  NULL }
};


void
proto_register_dcerpc_rras(void)
{

	static hf_register_info hf[] = {

		{ &hf_rras_opnum,
		  { "Operation", "rras.opnum", FT_UINT16, BASE_DEC,
		   NULL, 0x0, NULL, HFILL }},
	};


	static gint *ett[] = {
		&ett_dcerpc_rras,
	};


	proto_dcerpc_rras = proto_register_protocol(
		"Microsoft Routing and Remote Access Service", "RRAS", "rras");

	proto_register_field_array(proto_dcerpc_rras, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));

}


void
proto_reg_handoff_dcerpc_rras(void)
{
	/* register protocol as dcerpc */

	dcerpc_init_uuid(
		proto_dcerpc_rras, ett_dcerpc_rras, &uuid_dcerpc_rras,
		ver_dcerpc_rras, dcerpc_rras_dissectors, hf_rras_opnum);
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
