/* packet-dcerpc-messenger.c
 * Routines for SMB \PIPE\messenger packet disassembly
 * Copyright 2003 Ronnie Sahlberg
 *
 * $Id: packet-dcerpc-messenger.c,v 1.2 2003/06/26 04:30:28 tpot Exp $
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
#include "prefs.h"
#include "packet-dcerpc.h"


static int proto_dcerpc_messenger = -1;
static int hf_messenger_opnum = -1;

static gint ett_dcerpc_messenger = -1;

static e_uuid_t uuid_dcerpc_messenger = {
        0x5a7b91f8, 0xff00, 0x11d0,
        { 0xa9, 0xb2, 0x00, 0xc0, 0x4f, 0xb6, 0xe6, 0xfc}
};

static guint16 ver_dcerpc_messenger = 1;

static dcerpc_sub_dissector dcerpc_messenger_dissectors[] = {
        {0, NULL, NULL,  NULL }
};

void
proto_register_dcerpc_messenger(void)
{
        static hf_register_info hf[] = {

		{ &hf_messenger_opnum,
		  { "Operation", "messenger.opnum", FT_UINT16, BASE_DEC,
		    NULL, 0x0, "Operation", HFILL }}

        };

        static gint *ett[] = {
                &ett_dcerpc_messenger
        };

        proto_dcerpc_messenger = proto_register_protocol(
                "Microsoft Messenger Service", "Messenger", "messenger");

        proto_register_field_array (proto_dcerpc_messenger, hf, array_length (hf));
        proto_register_subtree_array(ett, array_length(ett));

}

void
proto_reg_handoff_dcerpc_messenger(void)
{
	header_field_info *hf_info;

        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_messenger, ett_dcerpc_messenger, &uuid_dcerpc_messenger,
                         ver_dcerpc_messenger, dcerpc_messenger_dissectors, hf_messenger_opnum);

	/* Set opnum strings from subdissector list */

	hf_info = proto_registrar_get_nth(hf_messenger_opnum);
	hf_info->strings = value_string_from_subdissectors(
		dcerpc_messenger_dissectors, array_length(dcerpc_messenger_dissectors));
}
