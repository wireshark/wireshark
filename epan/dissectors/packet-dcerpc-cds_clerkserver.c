/* packet-dcerpc-cds_clerkserver.c
 *
 * Routines for cds_clerkserver  dissection
 * Routines for dcerpc Afs4Int dissection
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/directory.tar.gz directory/cds/stubs/cds_clerkserver.idl
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


static int proto_cds_clerkserver = -1;
static int hf_cds_clerkserver_opnum = -1;


static gint ett_cds_clerkserver = -1;


static e_uuid_t uuid_cds_clerkserver = { 0x257df1c9, 0xc6d3, 0x11ca, { 0x85, 0x54, 0x08, 0x00, 0x2b, 0x1c, 0x8f, 0x1f } };
static guint16  ver_cds_clerkserver = 1;



static dcerpc_sub_dissector cds_clerkserver_dissectors[] = {
	{  0, "AddReplica", NULL, NULL},
	{  1, "AllowClearinghouses", NULL, NULL},
	{  2, "Combine", NULL, NULL},
	{  3, "CreateChild", NULL, NULL},
	{  4, "CreateDirectory", NULL, NULL},
	{  5, "CreateSoftLink", NULL, NULL},
	{  6, "CreateObject", NULL, NULL},
	{  7, "DeleteChild", NULL, NULL},
	{  8, "DeleteObject", NULL, NULL},
	{  9, "DeleteSoftLink", NULL, NULL},
	{ 10, "DeleteDirectory", NULL, NULL},
	{ 11, "DisallowClearinghouses", NULL, NULL},
	{ 12, "DoUpdate", NULL, NULL},
	{ 13, "EnumerateAttributes", NULL, NULL},
	{ 14, "EnumerateChildren", NULL, NULL},
	{ 15, "EnumerateObjects", NULL, NULL},
	{ 16, "EnumerateSoftLinks", NULL, NULL},
	{ 17, "LinkReplica", NULL, NULL},
	{ 18, "ModifyAttribute", NULL, NULL},
	{ 19, "ModifyReplica", NULL, NULL},
	{ 20, "NewEpoch", NULL, NULL},
	{ 21, "ReadAttribute", NULL, NULL},
	{ 22, "RemoveReplica", NULL, NULL},
	{ 23, "ResolveName", NULL, NULL},
	{ 24, "Skulk", NULL, NULL},
	{ 25, "TestAttribute", NULL, NULL},
	{ 26, "TestGroup", NULL, NULL},
	{ 0, NULL, NULL, NULL }
};

void
proto_register_cds_clerkserver (void)
{
	static hf_register_info hf[] = {
	  { &hf_cds_clerkserver_opnum,
	    { "Operation", "cds_clerkserver.opnum", FT_UINT16, BASE_DEC,
	      NULL, 0x0, NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_cds_clerkserver,
	};
	proto_cds_clerkserver = proto_register_protocol ("CDS Clerk Server Calls", "CDS_CLERK", "cds_clerkserver");
	proto_register_field_array (proto_cds_clerkserver, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_cds_clerkserver (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_cds_clerkserver, ett_cds_clerkserver, &uuid_cds_clerkserver, ver_cds_clerkserver, cds_clerkserver_dissectors, hf_cds_clerkserver_opnum);
}
