/* packet-dcerpc-ubikvote.c
 *
 * Routines for dcerpc Ubik Voting  routines.
 * Copyright 2002, Jaime Fournier <jafour1@yahoo.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/file.tar.gz file/ncsubik/ubikvote_proc.idl
 *
 * $Id: packet-dcerpc-ubikvote.c,v 1.3 2003/06/26 04:30:30 tpot Exp $
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


static int proto_ubikvote = -1;
static int hf_ubikvote_opnum = -1;


static gint ett_ubikvote = -1;


static e_uuid_t uuid_ubikvote = { 0x4d37f2dd, 0xed43, 0x0003, { 0x02, 0xc0, 0x37, 0xcf, 0x1e, 0x00, 0x00, 0x00 } };
static guint16  ver_ubikvote = 4;


static dcerpc_sub_dissector ubikvote_dissectors[] = {
	{ 0, "Beacon", NULL, NULL},
	{ 1, "Debug", NULL, NULL},
	{ 2, "SDebug", NULL, NULL},
	{ 3, "GetServerInterfaces", NULL, NULL},
	{ 4, "GetSyncSite", NULL, NULL},
	{ 5, "DebugV2", NULL, NULL},
	{ 6, "SDebugV2", NULL, NULL},
	{ 7, "GetSyncSiteIdentity", NULL, NULL},
        { 0, NULL, NULL, NULL }
};

void
proto_register_ubikvote (void)
{
	static hf_register_info hf[] = {
	  { &hf_ubikvote_opnum,
	    { "Operation", "ubikvote.opnum", FT_UINT16, BASE_DEC,
	      NULL, 0x0, "Operation", HFILL }}
	};

	static gint *ett[] = {
		&ett_ubikvote,
	};
	proto_ubikvote = proto_register_protocol ("DCE/RPC FLDB UBIKVOTE", "UBIKVOTE", "ubikvote");
	proto_register_field_array (proto_ubikvote, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_ubikvote (void)
{
	header_field_info *hf_info;

	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_ubikvote, ett_ubikvote, &uuid_ubikvote, ver_ubikvote, ubikvote_dissectors, hf_ubikvote_opnum);

	/* Set opnum strings from subdissector list */

	hf_info = proto_registrar_get_nth(hf_ubikvote_opnum);
	hf_info->strings = value_string_from_subdissectors(
		ubikvote_dissectors, array_length(ubikvote_dissectors));
}
