/* packet-dcerpc-bossvr.c
 *
 * Routines for DCE DFS Basic Overseer Server dissection
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/file.tar.gz file/bosserver/bbos_ncs_interface.idl
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


static int proto_bossvr = -1;
static int hf_bossvr_opnum = -1;


static gint ett_bossvr = -1;


static e_uuid_t uuid_bossvr = { 0x4d37f2dd, 0xed43, 0x0000, { 0x02, 0xc0, 0x37, 0xcf, 0x1e, 0x00, 0x00, 0x01 } };
static guint16  ver_bossvr = 0;


static dcerpc_sub_dissector bossvr_dissectors[] = {
	{  0, "GetServerStatus", NULL, NULL},
	{  1, "CreateBnode", NULL, NULL},
	{  2, "DeleteBnode", NULL, NULL},
	{  3, "SetStatus", NULL, NULL},
	{  4, "GetStatus", NULL, NULL},
	{  5, "EnumerateInstance", NULL, NULL},
	{  6, "GetInstanceInfo", NULL, NULL},
	{  7, "GetInstanceParm", NULL, NULL},
	{  8, "AddSUser", NULL, NULL},
	{  9, "DeleteSUser", NULL, NULL},
	{ 10, "ListSUsers", NULL, NULL},
	{ 11, "ListKeys", NULL, NULL},
	{ 12, "AddKey", NULL, NULL},
	{ 13, "DeleteKey", NULL, NULL},
	{ 14, "GenerateKey", NULL, NULL},
	{ 15, "GarbageCollectKeys", NULL, NULL},
	{ 16, "GetCellName", NULL, NULL},
	{ 17, "SetTStatus", NULL, NULL},
	{ 18, "ShutdownAll", NULL, NULL},
	{ 19, "RestartAll", NULL, NULL},
	{ 20, "StartupAll", NULL, NULL},
	{ 21, "SetNoAuthFlag", NULL, NULL},
	{ 22, "ReBossvr", NULL, NULL},
	{ 23, "Restart", NULL, NULL},
	{ 24, "Install", NULL, NULL},
	{ 25, "UnInstall", NULL, NULL},
	{ 26, "GetDates", NULL, NULL},
	{ 27, "Prune", NULL, NULL},
	{ 28, "SetRestartTime", NULL, NULL},
	{ 29, "GetRestartTime", NULL, NULL},
	{ 30, "GetLog", NULL, NULL},
	{ 31, "WaitAll", NULL, NULL},
	{ 32, "SetDebug", NULL, NULL},
	{ 33, "GetServerInterfaces", NULL, NULL},
	{ 0, NULL, NULL, NULL }
};

void
proto_register_bossvr (void)
{
	static hf_register_info hf[] = {
		{ &hf_bossvr_opnum,
		  { "Operation", "bossvr.opnum", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_bossvr,
	};
	proto_bossvr = proto_register_protocol ("DCE DFS Basic Overseer Server", "BOSSVR", "bossvr");
	proto_register_field_array (proto_bossvr, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_bossvr (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_bossvr, ett_bossvr, &uuid_bossvr, ver_bossvr, bossvr_dissectors, hf_bossvr_opnum);
}
