/* packet-dcerpc-remact.c
 * Routines for DCOM Remote Activation
 * Copyright 2001, Todd Sabin <tas@webspan.net>
 *
 * $Id: packet-dcerpc-remact.c,v 1.1 2001/07/11 01:25:44 guy Exp $
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


static int proto_remact = -1;

static gint ett_remact = -1;


static e_uuid_t uuid_remact = { 0x4d9f4ab8, 0x7dac, 0x11cf, { 0x86, 0x1e, 0x00, 0x20, 0xaf, 0x6e, 0x7c, 0x57 } };
static guint16  ver_remact = 0;


static dcerpc_sub_dissector remact_dissectors[] = {
    { 0, "RemoteActivation", NULL, NULL },
    { 0, NULL, NULL, NULL },
};


void
proto_register_remact (void)
{
#if 0
	static hf_register_info hf[] = {
	};
#endif

	static gint *ett[] = {
		&ett_remact,
	};
	proto_remact = proto_register_protocol ("DCOM Remote Activation", "REMACT", "remact");
#if 0
	proto_register_field_array (proto_remact, hf, array_length (hf));
#endif
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_remact (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_remact, ett_remact, &uuid_remact, ver_remact, remact_dissectors);
}
