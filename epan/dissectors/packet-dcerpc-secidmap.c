/* packet-dcerpc-secidmap.c
 *
 * Routines for dcerpc  DCE Security ID Mapper
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/security.tar.gz security/idl/rsecidmap.idl
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

static int proto_secidmap = -1;
static int hf_secidmap_opnum = -1;


static gint ett_secidmap = -1;

static e_uuid_t uuid_secidmap = { 0x0d7c1e50, 0x113a, 0x11ca, { 0xb7, 0x1f, 0x08, 0x00, 0x1e, 0x01, 0xdc, 0x6c } };
static guint16  ver_secidmap = 1;



static dcerpc_sub_dissector secidmap_dissectors[] = {
        { 0, "parse_name", NULL, NULL},
        { 1, "gen_name", NULL, NULL},
        { 2, "avoid_cn_bug", NULL, NULL},
        { 3, "parse_name_cache", NULL, NULL},
        { 4, "gen_name_cache", NULL, NULL},

        { 0, NULL, NULL, NULL },
};

void
proto_register_secidmap (void)
{
	static hf_register_info hf[] = {
	  { &hf_secidmap_opnum,
	    { "Operation", "secidmap.opnum", FT_UINT16, BASE_DEC,
	      NULL, 0x0, NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_secidmap,
	};
	proto_secidmap = proto_register_protocol ("DCE Security ID Mapper", "SECIDMAP", "secidmap");
	proto_register_field_array (proto_secidmap, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_secidmap (void)
{
        /* Register the protocol as dcerpc */
        dcerpc_init_uuid (proto_secidmap, ett_secidmap, &uuid_secidmap, ver_secidmap, secidmap_dissectors, hf_secidmap_opnum);
}
