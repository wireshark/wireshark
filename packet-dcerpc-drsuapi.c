/* packet-dcerpc-drsuapi.c
 * Routines for the drsuapi (Directory Replication Service) MSRPC interface 
 * Copyright 2003 Jean-Baptiste Marchand <jbm@hsc.fr>
 *
 * $Id: packet-dcerpc-drsuapi.c,v 1.1 2003/09/20 08:56:56 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-drsuapi.h"

static int proto_dcerpc_drsuapi = -1;

static int hf_drsuapi_opnum = 0;

static gint ett_dcerpc_drsuapi = -1;

/* 
IDL [ uuid(e3514235-4b06-11d1-ab04-00c04fc2dcd2),
IDL  version(4.0),
IDL  implicit_handle(handle_t rpc_binding)
IDL ] interface drsuapi
*/

static e_uuid_t uuid_dcerpc_drsuapi = {
	0xe3514235, 0x4b06, 0x11d1,
	{ 0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2 }
};

static guint16 ver_dcerpc_drsuapi = 4; 


static dcerpc_sub_dissector dcerpc_drsuapi_dissectors[] = {
	{ DRSUAPI_BIND, "DRSBind", NULL, NULL},
	{ DRSUAPI_UNBIND, "DRSUnbind", NULL, NULL},
	{ DRSUAPI_REPLICA_SYNC, "DRSReplicaSync", NULL, NULL},
	{ DRSUAPI_GET_NC_CHANGES, "DRSGetNCChanges", NULL, NULL},
	{ DRSUAPI_UPDATE_REFS, "DRSUpdateRefs", NULL, NULL},
	{ DRSUAPI_REPLICA_ADD, "DRSReplicaAdd", NULL, NULL},
	{ DRSUAPI_REPLICA_DEL, "DRSReplicaDel", NULL, NULL},
	{ DRSUAPI_REPLICA_MODIFY, "DRSReplicaModify", NULL, NULL},
	{ DRSUAPI_VERIFY_NAMES, "DRSVerifyNames", NULL, NULL},
	{ DRSUAPI_GET_MEMBERSHIPS, "DRSGetMemberships", NULL, NULL},
	{ DRSUAPI_INTER_DOMAIN_MOVE, "DRSInterDomainMove", NULL, NULL},
	{ DRSUAPI_GET_NT4_CHANGELOG, "DRSGetNT4ChangeLog", NULL, NULL},
	{ DRSUAPI_CRACKNAMES, "DRSCrackNames", NULL, NULL},	
	{ DRSUAPI_WRITE_SPN, "DRSWriteSPN", NULL, NULL},
	{ DRSUAPI_REMOVE_DS_SERVER, "DRSRemoveDsServer", NULL, NULL},
	{ DRSUAPI_REMOVE_DS_DOMAIN, "DRSRemoveDsDomain", NULL, NULL},
	{ DRSUAPI_DOMAIN_CONTROLLER_INFO, "DRSDomainControllerInfo", NULL, NULL},
	{ DRSUAPI_ADD_ENTRY, "DRSAddEntry", NULL, NULL},
	{ DRSUAPI_EXECUTE_KCC, "DRSExecuteKCC", NULL, NULL},
	{ DRSUAPI_GET_REPL_INFO, "DRSGetReplInfo", NULL, NULL},
	{ DRSUAPI_ADD_SID_HISTORY, "DRSAddSidHistory", NULL, NULL},
	{ DRSUAPI_GET_MEMBERSHIPS2, "DRSGetMemberships2", NULL, NULL},
	{ DRSUAPI_REPLICA_VERIFY_OBJECTS, "DRSReplicaVerifyObjects", NULL, NULL},
	{ DRSUAPI_GET_OBJECT_EXISTENCE, "DRSGetObjectExistence", NULL, NULL},
	{ DRSUAPI_QUERY_SITES_BY_COST, "DRSQuerySitesByCost", NULL, NULL},
        { 0, NULL, NULL,  NULL }
};


void
proto_register_dcerpc_drsuapi(void)
{

        static hf_register_info hf[] = {

		{ &hf_drsuapi_opnum, 
		  { "Operation", "drsuapi.opnum", FT_UINT16, BASE_DEC,
		   NULL, 0x0, "Operation", HFILL }},	
	};


        static gint *ett[] = {
                &ett_dcerpc_drsuapi,
        };


	proto_dcerpc_drsuapi = proto_register_protocol(
		"Microsoft Directory Replication Service", "DRSUAPI", "drsuapi");

	proto_register_field_array(proto_dcerpc_drsuapi, hf, array_length(hf));

        proto_register_subtree_array(ett, array_length(ett));

}


void
proto_reg_handoff_dcerpc_drsuapi(void)
{
	/* register protocol as dcerpc */

	dcerpc_init_uuid(
		proto_dcerpc_drsuapi, ett_dcerpc_drsuapi, &uuid_dcerpc_drsuapi,
		ver_dcerpc_drsuapi, dcerpc_drsuapi_dissectors, hf_drsuapi_opnum);
}
