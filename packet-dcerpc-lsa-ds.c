/* packet-dcerpc-lsa-ds.c
 * Routines for SMB \PIPE\lsarpc packet disassembly
 * Copyright 2002, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-dcerpc-lsa-ds.c,v 1.1 2002/11/01 00:42:00 tpot Exp $
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
#include <string.h>

#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"

static int proto_dcerpc_lsa_ds = -1;

static gint ett_dcerpc_lsa_ds = -1;

void
proto_register_dcerpc_lsa_ds(void)
{
        proto_dcerpc_lsa_ds = proto_register_protocol(
                "Microsoft Local Security Architecture (Directory Services)", 
		"LSA_DS", "lsa_ds");
}

/* Protocol handoff */

static e_uuid_t uuid_dcerpc_lsa_ds = {
        0x3919286a, 0xb10c, 0x11d0,
        { 0x9b, 0xa8, 0x00, 0xc0, 0x4f, 0xd9, 0x2e, 0xf5}
};

static guint16 ver_dcerpc_lsa_ds = 0;

static dcerpc_sub_dissector lsa_ds_dissectors[] = {
    { 0, NULL, NULL, NULL },
};

void
proto_reg_handoff_dcerpc_lsa_ds(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_lsa_ds, ett_dcerpc_lsa_ds, 
			 &uuid_dcerpc_lsa_ds, ver_dcerpc_lsa_ds, 
			 lsa_ds_dissectors, -1);
}
