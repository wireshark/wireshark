/* packet-dcerpc-icl_rpc.c
 * Routines for DCE DFS Scout dissection
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/file.tar.gz icl_rpc.idl
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

void proto_register_icl_rpc (void);
void proto_reg_handoff_icl_rpc (void);

static int proto_icl_rpc = -1;
static int hf_icl_rpc_opnum = -1;


static gint ett_icl_rpc = -1;

static e_uuid_t uuid_icl_rpc = { 0x003fd39c, 0x7feb, 0x1bbc, { 0xbe, 0xbe, 0x02, 0x60, 0x8c, 0x2e, 0xf4, 0xd2 } };
static guint16  ver_icl_rpc = 1;



static dcerpc_sub_dissector icl_rpc_dissectors[] = {
	{ 0, "DFSTRACE_GetSetInfo", NULL, NULL },
	{ 1, "DFSTRACE_SetSetInfo", NULL, NULL },
	{ 2, "DFSTRACE_GetLogInfo", NULL, NULL },
	{ 3, "DFSTRACE_SetLogInfo", NULL, NULL },
	{ 4, "DFSTRACE_ClearSet",   NULL, NULL },
	{ 5, "DFSTRACE_ClearLog",   NULL, NULL },
	{ 6, "DFSTRACE_DumpSet",    NULL, NULL },
	{ 0, NULL, NULL, NULL }
};

void
proto_register_icl_rpc (void)
{
	static hf_register_info hf[] = {
	{ &hf_icl_rpc_opnum,
		{ "Operation", "icl_rpc.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_icl_rpc,
	};
	proto_icl_rpc = proto_register_protocol ("DCE DFS ICL RPC", "ICL_RPC", "icl_rpc");
	proto_register_field_array (proto_icl_rpc, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_icl_rpc (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_icl_rpc, ett_icl_rpc, &uuid_icl_rpc, ver_icl_rpc, icl_rpc_dissectors, hf_icl_rpc_opnum);
}
