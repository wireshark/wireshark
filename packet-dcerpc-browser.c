/* packet-dcerpc-browser.c
 * Routines for DCERPC Browser packet disassembly
 * Copyright 2001, Ronnie Sahlberg
 *
 * $Id: packet-dcerpc-browser.c,v 1.1 2002/05/28 12:07:59 sahlberg Exp $
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
#include "packet-dcerpc-browser.h"

static int proto_dcerpc_browser = -1;
static gint ett_dcerpc_browser = -1;

static e_uuid_t uuid_dcerpc_browser = {
        0x6bffd098, 0xa112, 0x3610,
        { 0x98, 0x33, 0x01, 0x28, 0x92, 0x02, 0x01, 0x62 }
};

static guint16 ver_dcerpc_browser = 0;

static dcerpc_sub_dissector dcerpc_browser_dissectors[] = {
        { BROWSER_UNKNOWN_00, "BROWSER_UNKNOWN_00", NULL, NULL },
        { BROWSER_UNKNOWN_01, "BROWSER_UNKNOWN_01", NULL, NULL },
        { BROWSER_UNKNOWN_02, "BROWSER_UNKNOWN_02", NULL, NULL },
        { BROWSER_UNKNOWN_03, "BROWSER_UNKNOWN_03", NULL, NULL },
        { BROWSER_UNKNOWN_04, "BROWSER_UNKNOWN_04", NULL, NULL },
        { BROWSER_UNKNOWN_05, "BROWSER_UNKNOWN_05", NULL, NULL },
        { BROWSER_UNKNOWN_06, "BROWSER_UNKNOWN_06", NULL, NULL },
        { BROWSER_UNKNOWN_07, "BROWSER_UNKNOWN_07", NULL, NULL },
        { BROWSER_UNKNOWN_08, "BROWSER_UNKNOWN_08", NULL, NULL },
        { BROWSER_UNKNOWN_09, "BROWSER_UNKNOWN_09", NULL, NULL },
        { BROWSER_UNKNOWN_0a, "BROWSER_UNKNOWN_0a", NULL, NULL },
        { BROWSER_UNKNOWN_0b, "BROWSER_UNKNOWN_0b", NULL, NULL },

        {0, NULL, NULL,  NULL },
};

void 
proto_register_dcerpc_browser(void)
{
        static gint *ett[] = {
                &ett_dcerpc_browser,
        };

        proto_dcerpc_browser = proto_register_protocol(
                "RPC Browser", "RPC_BROWSER", "rpc_browser");

        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dcerpc_browser(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_browser, ett_dcerpc_browser, 
                         &uuid_dcerpc_browser, ver_dcerpc_browser, 
                         dcerpc_browser_dissectors);
}
