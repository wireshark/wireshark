/* packet-dcerpc-rs_prop_acct.c
 * Routines for rs_prop_acct dissection
 * Copyright 2003, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/file.tar.gz bubasics/rs_prop_acct.idl
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

void proto_register_rs_prop_acct (void);
void proto_reg_handoff_rs_prop_acct (void);

static int proto_rs_prop_acct = -1;
static int hf_rs_prop_acct_opnum = -1;


static gint ett_rs_prop_acct = -1;
static e_uuid_t uuid_rs_prop_acct = { 0x68097130, 0xde43, 0x11ca, { 0xa5, 0x54, 0x08, 0x00, 0x1e, 0x03, 0x94, 0xc7 } };
static guint16  ver_rs_prop_acct = 1;


static dcerpc_sub_dissector rs_prop_acct_dissectors[] = {
	{ 0, "rs_prop_acct_add",	     NULL, NULL },
	{ 1, "rs_prop_acct_delete",	     NULL, NULL },
	{ 2, "rs_prop_acct_rename",	     NULL, NULL },
	{ 3, "rs_prop_acct_replace",	     NULL, NULL },
	{ 4, "rs_prop_acct_add_key_version", NULL, NULL },
	{ 2, "rs_prop_acct_rename",	     NULL, NULL },
	{ 0, NULL, NULL, NULL }
};

void
proto_register_rs_prop_acct (void)
{
	static hf_register_info hf[] = {
	{ &hf_rs_prop_acct_opnum,
		{ "Operation", "rs_prop_acct.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_rs_prop_acct,
	};
	proto_rs_prop_acct = proto_register_protocol ("DCE/RPC RS_PROP_ACCT", "rs_prop_acct", "rs_prop_acct");
	proto_register_field_array (proto_rs_prop_acct, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_rs_prop_acct (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_rs_prop_acct, ett_rs_prop_acct, &uuid_rs_prop_acct, ver_rs_prop_acct, rs_prop_acct_dissectors, hf_rs_prop_acct_opnum);
}
