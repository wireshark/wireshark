/* packet-dcerpc-srvsvc.c
 * Routines for SMB \\PIPE\\srvsvc packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-dcerpc-srvsvc.c,v 1.2 2002/01/21 07:36:33 guy Exp $
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
#include "packet-dcerpc-srvsvc.h"

static int proto_dcerpc_srvsvc = -1;
static gint ett_dcerpc_srvsvc = -1;

static e_uuid_t uuid_dcerpc_srvsvc = {
        0x4b324fc8, 0x1670, 0x01d3,
        { 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88 }
};

static guint16 ver_dcerpc_srvsvc = 3;

static dcerpc_sub_dissector dcerpc_srvsvc_dissectors[] = {
        { SRV_NETCONNENUM, "SRV_NETCONNENUM", NULL, NULL },
        { SRV_NETFILEENUM, "SRV_NETFILEENUM", NULL, NULL },
        { SRV_NETSESSENUM, "SRV_NETSESSENUM", NULL, NULL },
        { SRV_NET_SHARE_ADD, "SRV_NET_SHARE_ADD", NULL, NULL },
        { SRV_NETSHAREENUM_ALL, "SRV_NETSHAREENUM_ALL", NULL, NULL },
        { SRV_NET_SHARE_GET_INFO, "SRV_NET_SHARE_GET_INFO", NULL, NULL },
        { SRV_NET_SHARE_SET_INFO, "SRV_NET_SHARE_SET_INFO", NULL, NULL },
        { SRV_NET_SHARE_DEL, "SRV_NET_SHARE_DEL", NULL, NULL },
        { SRV_NET_SRV_GET_INFO, "SRV_NET_SRV_GET_INFO", NULL, NULL },
        { SRV_NET_SRV_SET_INFO, "SRV_NET_SRV_SET_INFO", NULL, NULL },
        { SRV_NET_DISK_ENUM, "SRV_NET_DISK_ENUM", NULL, NULL },
        { SRV_NET_REMOTE_TOD, "SRV_NET_REMOTE_TOD", NULL, NULL },
        { SRV_NET_NAME_VALIDATE, "SRV_NET_NAME_VALIDATE", NULL, NULL },
        { SRV_NETSHAREENUM, "SRV_NETSHAREENUM", NULL, NULL },
        { SRV_NETFILEQUERYSECDESC, "SRV_NETFILEQUERYSECDESC", NULL, NULL },
        { SRV_NETFILESETSECDESC, "SRV_NETFILESETSECDESC", NULL, NULL },

        {0, NULL, NULL,  NULL },
};

void 
proto_register_dcerpc_srvsvc(void)
{
        static gint *ett[] = {
                &ett_dcerpc_srvsvc,
        };

        proto_dcerpc_srvsvc = proto_register_protocol(
                "Microsoft Server Service", "SRVSVC", "srvsvc");

        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dcerpc_srvsvc(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_srvsvc, ett_dcerpc_srvsvc, 
                         &uuid_dcerpc_srvsvc, ver_dcerpc_srvsvc, 
                         dcerpc_srvsvc_dissectors);
}
