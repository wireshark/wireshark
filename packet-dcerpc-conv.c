/* packet-dcerpc-conv.c
 * Routines for dcerpc conv dissection
 * Copyright 2001, Todd Sabin <tas@webspan.net>
 *
 * $Id: packet-dcerpc-conv.c,v 1.2 2002/01/21 07:36:33 guy Exp $
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
#include <epan/packet.h>
#include "packet-dcerpc.h"


static int proto_conv = -1;

static gint ett_conv = -1;


static e_uuid_t uuid_conv = { 0x333a2276, 0x0000, 0x0000, { 0x0d, 0x00, 0x00, 0x80, 0x9c, 0x00, 0x00, 0x00 } };
static guint16  ver_conv = 3;


static dcerpc_sub_dissector conv_dissectors[] = {
    { 0, "conv_who_are_you", NULL, NULL },
    { 1, "conv_who_are_you2", NULL, NULL },
    { 2, "conv_are_you_there", NULL, NULL },
    { 3, "conv_who_are_you_auth", NULL, NULL },
    { 4, "conv_who_are_you_auth_more", NULL, NULL },
    { 0, NULL, NULL, NULL },
};


void
proto_register_conv (void)
{
#if 0
	static hf_register_info hf[] = {
	};
#endif

	static gint *ett[] = {
		&ett_conv,
	};
	proto_conv = proto_register_protocol ("DCE/RPC Conversation Manager", "CONV", "conv");
#if 0
	proto_register_field_array (proto_conv, hf, array_length (hf));
#endif
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_conv (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_conv, ett_conv, &uuid_conv, ver_conv, conv_dissectors);
}
