/* packet-msrpc-reg.c
 * Routines for SMB \\PIPE\\winreg packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-msrpc-reg.c,v 1.1 2001/11/12 08:58:43 guy Exp $
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
#include "packet-msrpc-reg.h"

static int proto_msrpc_reg = -1;
static gint ett_msrpc_reg = -1;

static e_uuid_t uuid_msrpc_reg = {
        0x338cd001, 0x2244, 0x31f1,
        { 0xaa, 0xaa, 0x90, 0x00, 0x38, 0x00, 0x10, 0x03 }
};

static guint16 ver_msrpc_reg = 1;

static dcerpc_sub_dissector msrpc_reg_dissectors[] = {
        { REG_OPEN_HKCR, "REG_OPEN_HKCR", NULL, NULL },
        { _REG_UNK_01, "_REG_UNK_01", NULL, NULL },
        { REG_OPEN_HKLM, "REG_OPEN_HKLM", NULL, NULL },
        { _REG_UNK_03, "_REG_UNK_03", NULL, NULL },
        { REG_OPEN_HKU, "REG_OPEN_HKU", NULL, NULL },
        { REG_CLOSE, "REG_CLOSE", NULL, NULL },
        { REG_CREATE_KEY, "REG_CREATE_KEY", NULL, NULL },
        { REG_DELETE_KEY, "REG_DELETE_KEY", NULL, NULL },
        { REG_DELETE_VALUE, "REG_DELETE_VALUE", NULL, NULL },
        { REG_ENUM_KEY, "REG_ENUM_KEY", NULL, NULL },
        { REG_ENUM_VALUE, "REG_ENUM_VALUE", NULL, NULL },
        { REG_FLUSH_KEY, "REG_FLUSH_KEY", NULL, NULL },
        { REG_GET_KEY_SEC, "REG_GET_KEY_SEC", NULL, NULL },
        { _REG_UNK_0D, "_REG_UNK_0D", NULL, NULL },
        { _REG_UNK_0E, "_REG_UNK_0E", NULL, NULL },
        { REG_OPEN_ENTRY, "REG_OPEN_ENTRY", NULL, NULL },
        { REG_QUERY_KEY, "REG_QUERY_KEY", NULL, NULL },
        { REG_INFO, "REG_INFO", NULL, NULL },
        { _REG_UNK_12, "_REG_UNK_12", NULL, NULL },
        { _REG_UNK_13, "_REG_UNK_13", NULL, NULL },
        { _REG_UNK_14, "_REG_UNK_14", NULL, NULL },
        { REG_SET_KEY_SEC, "REG_SET_KEY_SEC", NULL, NULL },
        { REG_CREATE_VALUE, "REG_CREATE_VALUE", NULL, NULL },
        { _REG_UNK_17, "_REG_UNK_17", NULL, NULL },
        { REG_SHUTDOWN, "REG_SHUTDOWN", NULL, NULL },
        { REG_ABORT_SHUTDOWN, "REG_ABORT_SHUTDOWN", NULL, NULL },
        { REG_UNK_1A, "REG_UNK_1A", NULL, NULL },

        {0, NULL, NULL,  NULL },
};

void 
proto_register_msrpc_reg(void)
{
        static gint *ett[] = {
                &ett_msrpc_reg,
        };

        proto_msrpc_reg = proto_register_protocol(
                "Microsoft Registry", "REG", "reg");

        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_msrpc_reg(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_msrpc_reg, ett_msrpc_reg, &uuid_msrpc_reg,
                         ver_msrpc_reg, msrpc_reg_dissectors);
}
