/* packet-dcerpc-netlogon.c
 * Routines for SMB \\PIPE\\NETLOGON packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-dcerpc-netlogon.c,v 1.1 2001/11/21 02:08:57 guy Exp $
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
#include "packet-dcerpc-netlogon.h"

static int proto_dcerpc_netlogon = -1;
static gint ett_dcerpc_netlogon = -1;

static e_uuid_t uuid_dcerpc_netlogon = {
        0x12345678, 0x1234, 0xabcd,
        { 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0xcf, 0xfb }
};

static guint16 ver_dcerpc_netlogon = 1;

static dcerpc_sub_dissector dcerpc_netlogon_dissectors[] = {
        { NET_SAMLOGON, "NET_SAMLOGON", NULL, NULL },
        { NET_SAMLOGOFF, "NET_SAMLOGOFF", NULL, NULL },
        { NET_REQCHAL, "NET_REQCHAL", NULL, NULL },
        { NET_AUTH, "NET_AUTH", NULL, NULL },
        { NET_SRVPWSET, "NET_SRVPWSET", NULL, NULL },
        { NET_SAM_DELTAS, "NET_SAM_DELTAS", NULL, NULL },
        { NET_LOGON_CTRL, "NET_LOGON_CTRL", NULL, NULL },
        { NET_AUTH2, "NET_AUTH2", NULL, NULL },
        { NET_LOGON_CTRL2, "NET_LOGON_CTRL2", NULL, NULL },
        { NET_SAM_SYNC, "NET_SAM_SYNC", NULL, NULL },
        { NET_TRUST_DOM_LIST, "NET_TRUST_DOM_LIST", NULL, NULL },

        {0, NULL, NULL,  NULL },
};

void 
proto_register_dcerpc_netlogon(void)
{
        static gint *ett[] = {
                &ett_dcerpc_netlogon,
        };

        proto_dcerpc_netlogon = proto_register_protocol(
                "Microsoft Network Logon", "NETLOGON", "rpc_netlogon");

        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dcerpc_netlogon(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_netlogon, ett_dcerpc_netlogon, 
                         &uuid_dcerpc_netlogon, ver_dcerpc_netlogon, 
                         dcerpc_netlogon_dissectors);
}
