/* packet-dcerpc-ubikdisk.c
 *
 * Routines for DCE DFS UBIK Disk routines
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/file.tar.gz file/ncsubik/ubikdisk_proc.idl
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"


#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"


static int proto_ubikdisk = -1;
static int hf_ubikdisk_opnum = -1;


static gint ett_ubikdisk = -1;


static e_uuid_t uuid_ubikdisk = { 0x4d37f2dd, 0xed43, 0x0002, { 0x02, 0xc0, 0x37, 0xcf, 0x1e, 0x00, 0x00, 0x00 } };
static guint16  ver_ubikdisk = 4;


static dcerpc_sub_dissector ubikdisk_dissectors[] = {
	{  0, "Begin", NULL, NULL},
	{  1, "Commit", NULL, NULL},
	{  2, "Lock", NULL, NULL},
	{  3, "Write", NULL, NULL},
	{  4, "GetVersion", NULL, NULL},
	{  5, "GetFile", NULL, NULL},
	{  6, "SendFile", NULL, NULL},
	{  7, "Abort", NULL, NULL},
	{  8, "ReleaseLocks", NULL, NULL},
	{  9, "Truncate", NULL, NULL},
	{ 10, "Probe", NULL, NULL},
	{ 11, "GetServerInterfaces", NULL, NULL},
	{ 12, "BulkUpdate", NULL, NULL},
        { 0, NULL, NULL, NULL }
};

void
proto_register_ubikdisk (void)
{
	static hf_register_info hf[] = {
	  { &hf_ubikdisk_opnum,
	    { "Operation", "ubikdisk.opnum", FT_UINT16, BASE_DEC,
	      NULL, 0x0, NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_ubikdisk,
	};
	proto_ubikdisk = proto_register_protocol ("DCE DFS FLDB UBIK TRANSFER", "UBIKDISK", "ubikdisk");
	proto_register_field_array (proto_ubikdisk, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_ubikdisk (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_ubikdisk, ett_ubikdisk, &uuid_ubikdisk, ver_ubikdisk, ubikdisk_dissectors, hf_ubikdisk_opnum);
}
