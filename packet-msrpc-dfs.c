/* packet-msrpc-dfs.c
 * Routines for SMB \\PIPE\\netdfs packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-msrpc-dfs.c,v 1.1 2001/11/12 08:58:43 guy Exp $
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
#include "packet.h"
#include "packet-dcerpc.h"
#include "packet-msrpc-dfs.h"

static int proto_msrpc_dfs = -1;
static gint ett_msrpc_dfs = -1;

static e_uuid_t uuid_msrpc_dfs = {
        0x4fc742e0, 0x4a10, 0x11cf,
        { 0x82, 0x73, 0x00, 0xaa, 0x00, 0x4a, 0xe6, 0x73 }
};

static guint16 ver_msrpc_dfs = 3;

static dcerpc_sub_dissector msrpc_dfs_dissectors[] = {
        { DFS_EXIST, "DFS_EXIST", NULL, NULL },
        { DFS_ADD, "DFS_ADD", NULL, NULL },
        { DFS_REMOVE, "DFS_REMOVE", NULL, NULL },
        { DFS_GET_INFO, "DFS_GET_INFO", NULL, NULL },
        { DFS_ENUM, "DFS_ENUM", NULL, NULL },

        {0, NULL, NULL,  NULL },
};

void 
proto_register_msrpc_dfs(void)
{
        static gint *ett[] = {
                &ett_msrpc_dfs,
        };

        proto_msrpc_dfs = proto_register_protocol(
                "Microsoft Distributed File System", "DFS", "dfs");

        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_msrpc_dfs(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_msrpc_dfs, ett_msrpc_dfs, &uuid_msrpc_dfs,
                         ver_msrpc_dfs, msrpc_dfs_dissectors);
}
