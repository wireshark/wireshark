/* packet-dcerpc-epm.c
 * Routines for dcerpc endpoint mapper dissection
 * Copyright 2001, Todd Sabin <tas@webspan.net>
 *
 * $Id: packet-dcerpc-epm.c,v 1.1 2001/07/11 01:25:44 guy Exp $
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


static int proto_epm = -1;

static gint ett_epm = -1;


static e_uuid_t uuid_epm = { 0xe1af8308, 0x5d1f, 0x11c9, { 0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa } };
static guint16  ver_epm = 3;


static dcerpc_sub_dissector epm_dissectors[] = {
    { 0, "ept_insert", NULL, NULL },
    { 1, "ept_delete", NULL, NULL },
    { 2, "ept_lookup", NULL, NULL },
    { 3, "ept_map", NULL, NULL },
    { 4, "ept_lookup_handle_free", NULL, NULL },
    { 5, "ept_inq_object", NULL, NULL },
    { 6, "ept_mgmt_delete", NULL, NULL },
    { 0, NULL, NULL, NULL },
};


void
proto_register_epm (void)
{
#if 0
	static hf_register_info hf[] = {
	};
#endif

	static gint *ett[] = {
		&ett_epm,
	};
	proto_epm = proto_register_protocol ("DCE/RPC Endpoint Mapper", "EPM", "epm");
#if 0
	proto_register_field_array (proto_epm, hf, array_length (hf));
#endif
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_epm (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_epm, ett_epm, &uuid_epm, ver_epm, epm_dissectors);
}
