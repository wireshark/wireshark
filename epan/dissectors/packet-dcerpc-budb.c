/* packet-dcerpc-budb.c
 * Routines for budb dissection
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/file.tar.gz bubasics/budb.idl
 *
 * $Id$
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

static int proto_budb = -1;
static int hf_budb_opnum = -1;


static gint ett_budb = -1;

static e_uuid_t uuid_budb = { 0xeb814e2a, 0x0099, 0x11ca, { 0x86, 0x78, 0x02, 0x60, 0x8c, 0x2e, 0xa9, 0x6e } };
static guint16  ver_budb = 4;


static dcerpc_sub_dissector budb_dissectors[] = {
{ 0, "AddVolume", NULL, NULL },
{ 1, "CreateDump", NULL, NULL },
{ 2, "DeleteDump", NULL, NULL },
{ 3, "DeleteTape", NULL, NULL },
{ 4, "DeleteVDP", NULL, NULL },
{ 5, "FindClone", NULL, NULL },
{ 6, "FindDump", NULL, NULL },
{ 7, "FindLatestDump", NULL, NULL },
{ 8, "FinishDump", NULL, NULL },
{ 9, "FinishTape", NULL, NULL },
{ 10, "GetDumps", NULL, NULL },
{ 11, "GetTapes", NULL, NULL },
{ 12, "GetVolumes", NULL, NULL },
{ 13, "UseTape", NULL, NULL },
{ 14, "GetText", NULL, NULL },
{ 15, "GetTextVersion", NULL, NULL },
{ 16, "SaveText", NULL, NULL },
{ 17, "FreeAllLocks", NULL, NULL },
{ 18, "FreeLock", NULL, NULL },
{ 19, "GetInstanceId", NULL, NULL },
{ 20, "GetLock", NULL, NULL },
{ 21, "DbVerify", NULL, NULL },
{ 22, "DumpDB", NULL, NULL },
{ 23, "RestoreDbHeader", NULL, NULL },
{ 24, "T_GetVersion", NULL, NULL },
{ 25, "T_DumpHashTable", NULL, NULL },
{ 26, "T_DumpDatabase", NULL, NULL },
{ 27, "GetServerInterfaces", NULL, NULL },
{ 28, "AddVolumes", NULL, NULL },
	{ 0, NULL, NULL, NULL }
};

void
proto_register_budb (void)
{
	static hf_register_info hf[] = {
	{ &hf_budb_opnum,
		{ "Operation", "budb.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, "Operation", HFILL }},
	};

	static gint *ett[] = {
		&ett_budb,
	};
	proto_budb = proto_register_protocol ("DCE/RPC BUDB", "BUDB", "budb");
	proto_register_field_array (proto_budb, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_budb (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_budb, ett_budb, &uuid_budb, ver_budb, budb_dissectors, hf_budb_opnum);
}
