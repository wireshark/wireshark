/* packet-dcerpc-ubikvote.c
 *
 * Routines for DCE DFS Ubik Voting  routines.
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/file.tar.gz file/ncsubik/ubikvote_proc.idl
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"


#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"

void proto_register_ubikvote (void);
void proto_reg_handoff_ubikvote (void);

static int proto_ubikvote = -1;
static int hf_ubikvote_opnum = -1;


static gint ett_ubikvote = -1;


static e_uuid_t uuid_ubikvote = { 0x4d37f2dd, 0xed43, 0x0003, { 0x02, 0xc0, 0x37, 0xcf, 0x1e, 0x00, 0x00, 0x00 } };
static guint16  ver_ubikvote = 4;


static dcerpc_sub_dissector ubikvote_dissectors[] = {
	{ 0, "Beacon",              NULL, NULL},
	{ 1, "Debug",               NULL, NULL},
	{ 2, "SDebug",              NULL, NULL},
	{ 3, "GetServerInterfaces", NULL, NULL},
	{ 4, "GetSyncSite",         NULL, NULL},
	{ 5, "DebugV2",             NULL, NULL},
	{ 6, "SDebugV2",            NULL, NULL},
	{ 7, "GetSyncSiteIdentity", NULL, NULL},
        { 0, NULL, NULL, NULL }
};

void
proto_register_ubikvote (void)
{
	static hf_register_info hf[] = {
	  { &hf_ubikvote_opnum,
	    { "Operation", "ubikvote.opnum", FT_UINT16, BASE_DEC,
	      NULL, 0x0, NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_ubikvote,
	};
	proto_ubikvote = proto_register_protocol ("DCE DFS FLDB UBIKVOTE", "UBIKVOTE", "ubikvote");
	proto_register_field_array (proto_ubikvote, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_ubikvote (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_ubikvote, ett_ubikvote, &uuid_ubikvote, ver_ubikvote, ubikvote_dissectors, hf_ubikvote_opnum);
}
