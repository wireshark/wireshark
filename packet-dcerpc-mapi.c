/* packet-dcerpc-mapi.c
 * Routines for MS Exchange MAPI
 * Copyright 2002, Ronnie Sahlberg
 *
 * $Id: packet-dcerpc-mapi.c,v 1.1 2002/05/23 10:00:19 sahlberg Exp $
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
#include "packet-dcerpc-mapi.h"

static int proto_dcerpc_mapi = -1;
static gint ett_dcerpc_mapi = -1;

static e_uuid_t uuid_dcerpc_mapi = {
        0xa4f1db00, 0xca47, 0x1067,
        { 0xb3, 0x1f, 0x00, 0xdd, 0x01, 0x06, 0x62, 0xda }
};

static guint16 ver_dcerpc_mapi = 0;

static dcerpc_sub_dissector dcerpc_mapi_dissectors[] = {
        { MAPI_LOGON,		"Logon", NULL, NULL },
        { MAPI_LOGOFF,		"Logoff", NULL, NULL },

        {0, NULL, NULL,  NULL },
};

void 
proto_register_dcerpc_mapi(void)
{
        static gint *ett[] = {
                &ett_dcerpc_mapi,
        };

        proto_dcerpc_mapi = proto_register_protocol(
                "Microsoft Exchange MAPI", "MAPI", "mapi");

        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dcerpc_mapi(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_mapi, ett_dcerpc_mapi, 
                         &uuid_dcerpc_mapi, ver_dcerpc_mapi, 
                         dcerpc_mapi_dissectors);
}
