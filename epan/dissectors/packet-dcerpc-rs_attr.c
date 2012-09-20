/* packet-dcerpc-rs_attr.c
 *
 * Routines for dcerpc Registry Server Attributes Manipulation Interface
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/security.tar.gz security/idl/rs_attr.idl
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


static int proto_rs_attr = -1;
static int hf_rs_attr_opnum = -1;


static gint ett_rs_attr = -1;


static e_uuid_t uuid_rs_attr = { 0xa71fc1e8, 0x567f, 0x11cb, { 0x98, 0xa0, 0x08, 0x00, 0x1e, 0x04, 0xde, 0x8c } };
static guint16  ver_rs_attr = 0;


static dcerpc_sub_dissector rs_attr_dissectors[] = {
	{ 0, "rs_attr_cursor_init", NULL, NULL},
	{ 1, "rs_attr_lookup_by_id", NULL, NULL},
	{ 2, "rs_attr_lookup_no_expand", NULL, NULL},
	{ 3, "rs_attr_lookup_by_name", NULL, NULL},
	{ 4, "rs_attr_update", NULL, NULL},
	{ 5, "rs_attr_test_and_update", NULL, NULL},
	{ 6, "rs_attr_delete", NULL, NULL},
	{ 7, "rs_attr_get_referral", NULL, NULL},
	{ 8, "rs_attr_get_effective", NULL, NULL},
	{ 0, NULL, NULL, NULL }
};

void
proto_register_rs_attr (void)
{
	static hf_register_info hf[] = {
		{ &hf_rs_attr_opnum,
		  { "Operation", "rs_attr.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_rs_attr,
	};
	proto_rs_attr = proto_register_protocol ("Registry Server Attributes Manipulation Interface", "RS_ATTR", "rs_attr");
	proto_register_field_array (proto_rs_attr, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_rs_attr (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_rs_attr, ett_rs_attr, &uuid_rs_attr, ver_rs_attr, rs_attr_dissectors, hf_rs_attr_opnum);
}
