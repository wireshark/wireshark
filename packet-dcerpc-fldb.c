/* packet-dcerpc-fldb.c
 *
 * Routines for dcerpc FLDB Calls
 * Copyright 2002, Jaime Fournier <jafour1@yahoo.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/file.tar.gz file/flserver/afsvl_proc.idl
 *
 * $Id: packet-dcerpc-fldb.c,v 1.3 2003/06/26 04:30:27 tpot Exp $
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


static int proto_fldb = -1;
static int hf_fldb_opnum = -1;


static gint ett_fldb = -1;


static e_uuid_t uuid_fldb = { 0x4d37f2dd, 0xed43, 0x0000, { 0x02, 0xc0, 0x37, 0xcf, 0x2e, 0x00, 0x00, 0x01 } };
static guint16  ver_fldb = 4;

		 
		 
static dcerpc_sub_dissector fldb_dissectors[] = {
	{  0, "GetEntryByID", NULL, NULL },
	{  1, "GetEntryByName", NULL, NULL },
	{  2, "Probe", NULL, NULL},
	{  3, "GetCellInfo", NULL, NULL},
	{  4, "GetNextServersByID", NULL, NULL},
	{  5, "GetNextServersByName", NULL, NULL},
	{  6, "GetSiteInfo", NULL, NULL },
	{  7, "GetCEntryByID", NULL, NULL},
	{  8, "GetCEntryByName", NULL, NULL},
	{  9, "GetCNextServersByID", NULL, NULL},
	{ 10, "GetCNextServersByName", NULL, NULL},
	{ 11, "ExpandSiteCookie", NULL, NULL},
	{ 12, "GetServerInterfaces", NULL, NULL},
	{ 13, "CreateEntry", NULL, NULL},
	{ 14, "DeleteEntry", NULL, NULL},
	{ 15, "GetNewVolumeId", NULL, NULL},
	{ 16, "ReplaceEntry", NULL, NULL},
	{ 17, "SetLock", NULL, NULL},
	{ 18, "ReleaseLock", NULL, NULL},
	{ 19, "ListEntry", NULL, NULL },
	{ 20, "ListByAttributes", NULL, NULL},
	{ 21, "GetStats", NULL, NULL},
	{ 22, "AddAddress", NULL, NULL},
	{ 23, "RemoveAddress", NULL, NULL},
	{ 24, "ChangeAddress", NULL, NULL},
	{ 25, "GenerateSites", NULL, NULL},
	{ 26, "GetNewVolumeIds", NULL, NULL},
	{ 27, "CreateServer", NULL, NULL},
	{ 28, "AlterServer", NULL, NULL},
        { 0, NULL, NULL, NULL }
};

void
proto_register_fldb (void)
{
	static hf_register_info hf[] = {
	  { &hf_fldb_opnum,
	    { "Operation", "fldb.opnum", FT_UINT16, BASE_DEC,
	      NULL, 0x0, "Operation", HFILL }}
	};

	static gint *ett[] = {
		&ett_fldb,
	};
	proto_fldb = proto_register_protocol ("DCE/RPC FLDB", "FLDB", "fldb");
	proto_register_field_array (proto_fldb, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_fldb (void)
{
	header_field_info *hf_info;

	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_fldb, ett_fldb, &uuid_fldb, ver_fldb, fldb_dissectors, hf_fldb_opnum);

	/* Set opnum strings from subdissector list */

	hf_info = proto_registrar_get_nth(hf_fldb_opnum);
	hf_info->strings = value_string_from_subdissectors(
		fldb_dissectors, array_length(fldb_dissectors));
}
