/* packet-dcerpc-frsrpc.c
 * Routines for the frs (File Replication Service) MSRPC interface 
 * Copyright 2004 Jean-Baptiste Marchand <jbm@hsc.fr>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-frsrpc.h"

static int proto_dcerpc_frsrpc = -1;

static int hf_frsrpc_opnum = 0;

static gint ett_dcerpc_frsrpc = -1;

/*
IDL [ uuid(f5cc59b4-4264-101a-8c59-08002b2f8426),
IDL  version(1.1),
IDL  implicit_handle(handle_t rpc_binding)
IDL ] interface frsrpc
*/


static e_uuid_t uuid_dcerpc_frsrpc = {
	0xf5cc59b4, 0x4264, 0x101a,
	{ 0x8c, 0x59, 0x08, 0x00, 0x2b, 0x2f, 0x84, 0x26 }
};

static guint16 ver_dcerpc_frsrpc = 1; 


static dcerpc_sub_dissector dcerpc_frsrpc_dissectors[] = {
	{ FRSRPC_SEND_COMM_PKT, "FrsRpcSendCommPkt", 
		NULL, NULL },
	{ FRSRPC_VERIFY_PROMOTION_PARENT, "FrsRpcVerifyPromotionParent", 
		NULL, NULL },
	{ FRSRPC_START_PROMOTION_PARENT, "FrsRpcStartPromotionParent", 
		NULL, NULL },
	{ FRSRPC_NOP, "FrsRpcNop", NULL, NULL },
/* operations 4 to 9 are apparently identical */
	{ FRSRPC_BACKUP_COMPLETE, "FrsRpcBackupComplete", NULL, NULL },
	{ FRSRPC_BACKUP_COMPLETE_5, "FrsRpcBackupComplete", NULL, NULL },
	{ FRSRPC_BACKUP_COMPLETE_6, "FrsRpcBackupComplete", NULL, NULL },
	{ FRSRPC_BACKUP_COMPLETE_7, "FrsRpcBackupComplete", NULL, NULL },
	{ FRSRPC_BACKUP_COMPLETE_8, "FrsRpcBackupComplete", NULL, NULL },
	{ FRSRPC_BACKUP_COMPLETE_9, "FrsRpcBackupComplete", NULL, NULL },
	{ FRSRPC_VERIFY_PROMOTION_PARENT_EX, "FrsRpcVerifyPromotionParentEx",
		NULL, NULL },
        { 0, NULL, NULL,  NULL }
};


void
proto_register_dcerpc_frsrpc(void)
{

        static hf_register_info hf[] = {

		{ &hf_frsrpc_opnum, 
		  { "Operation", "frsrpc.opnum", FT_UINT16, BASE_DEC,
		   NULL, 0x0, "Operation", HFILL }},	
	};


        static gint *ett[] = {
                &ett_dcerpc_frsrpc,
        };


	proto_dcerpc_frsrpc = proto_register_protocol(
		"Microsoft File Replication Service", "FRSRPC", "frsrpc");

	proto_register_field_array(proto_dcerpc_frsrpc, hf, array_length(hf));

        proto_register_subtree_array(ett, array_length(ett));

}


void
proto_reg_handoff_dcerpc_frsrpc(void)
{
	/* register protocol as dcerpc */

	dcerpc_init_uuid(
		proto_dcerpc_frsrpc, ett_dcerpc_frsrpc, &uuid_dcerpc_frsrpc,
		ver_dcerpc_frsrpc, dcerpc_frsrpc_dissectors, hf_frsrpc_opnum);
}
