/* packet-dcerpc-tkn4int.c
 *
 * Routines for dcerpc Token Server Calls
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/file.tar.gz file/fsint/tkn4int.idl
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


static int proto_tkn4int = -1;
static int hf_tkn4int_opnum = -1;


static gint ett_tkn4int = -1;


static e_uuid_t uuid_tkn4int = { 0x4d37f2dd, 0xed96, 0x0000, { 0x02, 0xc0, 0x37, 0xcf, 0x1e, 0x00, 0x00, 0x00 } };
static guint16  ver_tkn4int = 4;


static dcerpc_sub_dissector tkn4int_dissectors[] = {
    { 0, "Probe", NULL, NULL},
    { 1, "InitTokenState", NULL, NULL},
    { 2, "TokenRevoke", NULL, NULL},
    { 3, "GetCellName", NULL, NULL},
    { 4, "GetLock", NULL, NULL},
    { 5, "GetCE", NULL, NULL},
    { 6, "GetServerInterfaces", NULL, NULL},
    { 7, "SetParams", NULL, NULL},
    { 8, "AsyncGrant", NULL, NULL},
    { 0, NULL, NULL, NULL }

};

void
proto_register_tkn4int (void)
{
	static hf_register_info hf[] = {
	  { &hf_tkn4int_opnum,
	    { "Operation", "tkn4int.opnum", FT_UINT16, BASE_DEC,
	      NULL, 0x0, "Operation", HFILL }}
	};

	static gint *ett[] = {
		&ett_tkn4int,
	};
	proto_tkn4int = proto_register_protocol ("DCE/RPC TokenServer Calls", "TKN4Int", "tkn4int");
	proto_register_field_array (proto_tkn4int, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_tkn4int (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_tkn4int, ett_tkn4int, &uuid_tkn4int, ver_tkn4int, tkn4int_dissectors, hf_tkn4int_opnum);
}
