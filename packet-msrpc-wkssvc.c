/* packet-msrpc-wkssvc.c
 * Routines for SMB \\PIPE\\wkssvc packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-msrpc-wkssvc.c,v 1.1 2001/11/12 08:58:43 guy Exp $
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
#include "packet-msrpc-wkssvc.h"

static int proto_msrpc_wkssvc = -1;
static gint ett_msrpc_wkssvc = -1;

static e_uuid_t uuid_msrpc_wkssvc = {
        0x6bffd098, 0xa112, 0x3610,
        { 0x98, 0x33, 0x46, 0xc3, 0xf8, 0x7e, 0x34, 0x5a }
};

static guint16 ver_msrpc_wkssvc = 1;

static dcerpc_sub_dissector msrpc_wkssvc_dissectors[] = {
        { WKS_QUERY_INFO, "WKS_QUERY_INFO", NULL, NULL },

        {0, NULL, NULL,  NULL },
};

void 
proto_register_msrpc_wkssvc(void)
{
        static gint *ett[] = {
                &ett_msrpc_wkssvc,
        };

        proto_msrpc_wkssvc = proto_register_protocol(
                "Microsoft Workstation Service", "WKSSVC", "wkssvc");

        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_msrpc_wkssvc(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_msrpc_wkssvc, ett_msrpc_wkssvc, 
                         &uuid_msrpc_wkssvc, ver_msrpc_wkssvc, 
                         msrpc_wkssvc_dissectors);
}
