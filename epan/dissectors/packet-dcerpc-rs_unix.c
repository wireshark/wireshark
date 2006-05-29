/* packet-dcerpc-rs_unix.c
 *
 * Routines for dcerpc Unix ops
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/security.tar.gz security/idl/rs_unix.idl
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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


static int proto_rs_unix = -1;
static int hf_rs_unix_opnum = -1;

static gint ett_rs_unix = -1;


static e_uuid_t uuid_rs_unix = { 0x361993c0, 0xb000, 0x0000, { 0x0d, 0x00, 0x00, 0x87, 0x84, 0x00, 0x00, 0x00 } };
static guint16  ver_rs_unix = 1;


static dcerpc_sub_dissector rs_unix_dissectors[] = {
    { 0, "getpwents", NULL, NULL },
    { 0, NULL, NULL, NULL },
};

void
proto_register_rs_unix (void)
{
	static hf_register_info hf[] = {
	  { &hf_rs_unix_opnum,
	    { "Operation", "rs_unix.opnum", FT_UINT16, BASE_DEC,
	      NULL, 0x0, "Operation", HFILL }}
	};

	static gint *ett[] = {
		&ett_rs_unix,
	};
	proto_rs_unix = proto_register_protocol ("DCE/RPC RS_UNIX", "RS_UNIX", "rs_unix");
	proto_register_field_array (proto_rs_unix, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_rs_unix (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_rs_unix, ett_rs_unix, &uuid_rs_unix, ver_rs_unix, rs_unix_dissectors, hf_rs_unix_opnum);
}
