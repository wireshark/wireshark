/* packet-dcerpc-oxid.c
 * Routines for DCOM OXID Resolver
 * Copyright 2001, Todd Sabin <tas@webspan.net>
 *
 * $Id: packet-dcerpc-oxid.c,v 1.1 2001/07/11 01:25:44 guy Exp $
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


#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>

#include <glib.h>
#include "packet.h"
#include "packet-dcerpc.h"


static int proto_oxid = -1;

static gint ett_oxid = -1;

static e_uuid_t uuid_oxid = { 0x99fcfec4, 0x5260, 0x101b, { 0xbb, 0xcb, 0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a } };
static guint16  ver_oxid = 0;


static dcerpc_sub_dissector oxid_dissectors[] = {
    { 0, "ResolveOxid", NULL, NULL },
    { 1, "SimplePing", NULL, NULL },
    { 2, "ComplexPing", NULL, NULL },
    { 3, "ServerAlive", NULL, NULL },
    { 0, NULL, NULL, NULL },
};


void
proto_register_oxid (void)
{
#if 0
	static hf_register_info hf[] = {
	};
#endif

	static gint *ett[] = {
		&ett_oxid,
	};
	proto_oxid = proto_register_protocol ("DCOM OXID Resolver", "OXID", "oxid");
#if 0
	proto_register_field_array (proto_oxid, hf, array_length (hf));
#endif
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_oxid (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_oxid, ett_oxid, &uuid_oxid, ver_oxid, oxid_dissectors);
}
