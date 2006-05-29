/* packet-dcerpc-cprpc_server.c
 * Routines for DNS Control Program Server dissection
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/directory.tar.gz directory/cds/stubs/cprpc_server.idl
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


static int proto_cprpc_server = -1;
static int hf_cprpc_server_opnum = -1;


static gint ett_cprpc_server = -1;


static e_uuid_t uuid_cprpc_server = { 0x4885772c, 0xc6d3, 0x11ca, { 0x84, 0xc6, 0x08, 0x00, 0x2b, 0x1c, 0x8f, 0x1f } };
static guint16  ver_cprpc_server = 1;


static dcerpc_sub_dissector cprpc_server_dissectors[] = {
    { 0, "dnscp_server", NULL, NULL},
    { 0, NULL, NULL, NULL }
};

void
proto_register_cprpc_server (void)
{
	static hf_register_info hf[] = {
	  { &hf_cprpc_server_opnum,
	    { "Operation", "cprpc_server.opnum", FT_UINT16, BASE_DEC,
	      NULL, 0x0, "Operation", HFILL }}
	};

	static gint *ett[] = {
		&ett_cprpc_server,
	};
	proto_cprpc_server = proto_register_protocol ("DNS Control Program Server", "cprpc_server", "cprpc_server");
	proto_register_field_array (proto_cprpc_server, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_cprpc_server (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_cprpc_server, ett_cprpc_server, &uuid_cprpc_server, ver_cprpc_server, cprpc_server_dissectors, hf_cprpc_server_opnum);
}
