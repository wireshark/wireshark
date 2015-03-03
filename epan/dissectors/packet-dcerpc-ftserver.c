/* packet-dcerpc-ftserver.c
 *
 * Routines for dcerpc ftserver dissection
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/file.tgz file/ftserver/ftserver_proc.idl
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


#include <epan/packet.h>
#include "packet-dcerpc.h"

void proto_register_ftserver (void);
void proto_reg_handoff_ftserver (void);

static int proto_ftserver = -1;
static int hf_ftserver_opnum = -1;



static gint ett_ftserver = -1;


static e_guid_t uuid_ftserver = { 0x4d37f2dd, 0xed43, 0x0004, { 0x02, 0xc0, 0x37, 0xcf, 0x1e, 0x00, 0x00, 0x00 } };
static guint16  ver_ftserver = 4;


static dcerpc_sub_dissector ftserver_dissectors[] = {
	{  0, "CreateTrans",         NULL, NULL },
	{  1, "AbortTrans",          NULL, NULL },
	{  2, "DeleteTrans",         NULL, NULL },
	{  3, "CreateVolume",        NULL, NULL },
	{  4, "DeleteVolume",        NULL, NULL },
	{  5, "Dump",                NULL, NULL },
	{  6, "Restore",             NULL, NULL },
	{  7, "Forward",             NULL, NULL },
	{  8, "Clone",               NULL, NULL },
	{  9, "ReClone",             NULL, NULL },
	{ 10, "GetFlags",            NULL, NULL },
	{ 11, "SetFlags",            NULL, NULL },
	{ 12, "GetStatus",           NULL, NULL },
	{ 13, "SetStatus",           NULL, NULL },
	{ 14, "ListVolumes",         NULL, NULL },
	{ 15, "ListAggregates",      NULL, NULL },
	{ 16, "AggregateInfo",       NULL, NULL },
	{ 17, "Monitor",             NULL, NULL },
	{ 18, "GetOneVolStatus",     NULL, NULL },
	{ 19, "GetServerInterfaces", NULL, NULL },
	{ 20, "SwapIDs",             NULL, NULL },
	{ 0, NULL, NULL, NULL }
};

void
proto_register_ftserver (void)
{
	static hf_register_info hf[] = {
	  { &hf_ftserver_opnum,
	    { "Operation", "ftserver.opnum", FT_UINT16, BASE_DEC,
	      NULL, 0x0, NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_ftserver,
	};
	proto_ftserver = proto_register_protocol ("FTServer Operations", "FTSERVER", "ftserver");
	proto_register_field_array (proto_ftserver, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_ftserver (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_ftserver, ett_ftserver, &uuid_ftserver, ver_ftserver, ftserver_dissectors, hf_ftserver_opnum);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
