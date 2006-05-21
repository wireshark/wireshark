/* packet-dcerpc-dfs.c
 * Routines for SMB \\PIPE\\netdfs packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
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
#include "packet-dcerpc-dfs.h"

static int proto_dcerpc_dfs = -1;
static gint ett_dcerpc_dfs = -1;

static int hf_dfs_opnum = -1;

static e_uuid_t uuid_dcerpc_dfs = {
        0x4fc742e0, 0x4a10, 0x11cf,
        { 0x82, 0x73, 0x00, 0xaa, 0x00, 0x4a, 0xe6, 0x73 }
};

static guint16 ver_dcerpc_dfs = 3;

static dcerpc_sub_dissector dcerpc_dfs_dissectors[] = {
        { DFS_MANAGER_GET_VERSION, "NetrDfsManagerGetVersion", NULL, NULL },
        { DFS_ADD, "NetrDfsAdd", NULL, NULL },
        { DFS_REMOVE, "NetrDfsRemove", NULL, NULL },
	{ DFS_SET_INFO, "NetrDfsSetInfo", NULL, NULL },
        { DFS_GET_INFO, "NetrDfsGetInfo", NULL, NULL },
        { DFS_ENUM, "NetrDfsEnum", NULL, NULL },
	{ DFS_RENAME, "NetrDfsRename", NULL, NULL },
	{ DFS_MOVE, "NetrDfsMove", NULL, NULL },			
	{ DFS_MANAGER_GET_CONFIG_INFO, "NetrDfsManagerGetConfigInfo", NULL, NULL },
	{ DFS_MANAGER_SEND_SITE_INFO, "NetrDfsManagerSendSiteInfo", NULL, NULL },	
	{ DFS_ADD_FT_ROOT, "NetrDfsAddFtRoot", NULL, NULL },		
	{ DFS_REMOVE_FT_ROOT, "NetrDfsRemoveFtRoot", NULL, NULL },
	{ DFS_ADD_STD_ROOT, "NetrDfsAddStdRoot", NULL, NULL },		
	{ DFS_REMOVE_STD_ROOT, "NetrDfsRemoveStdRoot", NULL, NULL },	
	{ DFS_MANAGER_INITIALIZE, "NetrDfsManagerInitialize", NULL, NULL },
	{ DFS_ADD_STD_ROOT_FORCED, "NetrDfsAddStdRootForced", NULL, NULL },		
	{ DFS_GET_DC_ADDRESS, "NetrDfsGetDcAddress", NULL, NULL },	
	{ DFS_SET_DC_ADDRESS, "NetrDfsSetDcAddress", NULL, NULL },
	{ DFS_FLUSH_FT_TABLE, "NetrDfsFlushFtTable", NULL, NULL },		
	{ DFS_ADD2, "NetrDfsAdd2", NULL, NULL },		
	{ DFS_REMOVE2, "NetrDfsRemove2", NULL, NULL },			
	{ DFS_ENUM_EX, "NetrDfsEnumEx", NULL, NULL },		
	{ DFS_SET_INFO_2, "NetrDfsSetInfo2 ", NULL, NULL },			
        {0, NULL, NULL,  NULL }
};

void
proto_register_dcerpc_dfs(void)
{
	static hf_register_info hf[] = {
		{ &hf_dfs_opnum,
		  { "Operation", "dfs.opnum", FT_UINT16, BASE_DEC,
		    NULL, 0x0, "Operation", HFILL }},
	};

        static gint *ett[] = {
                &ett_dcerpc_dfs
        };

        proto_dcerpc_dfs = proto_register_protocol(
                "Microsoft Distributed File System", "DFS", "dfs");

	proto_register_field_array(proto_dcerpc_dfs, hf, array_length(hf));

        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dcerpc_dfs(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_dfs, ett_dcerpc_dfs, &uuid_dcerpc_dfs,
                         ver_dcerpc_dfs, dcerpc_dfs_dissectors, hf_dfs_opnum);
}
