/* packet-dcerpc-iremunkn2.c
 * Routines for the IRemUnknown2 interface
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
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

#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-dcom.h"
#include "packet-smb-common.h"

static int proto_IRemUnknown2 = -1;

static int hf_opnum = -1;

static gint ett_IRemUnknown2 = -1;

static e_uuid_t uuid_IRemUnknown2 = { 0x00000143, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static guint16  ver_IRemUnknown2 = 0;

static dcerpc_sub_dissector IRemUnknown2_dissectors[] = {
	{ 0, "QueryInterface", NULL, NULL },
	{ 1, "AddRef", NULL, NULL },
	{ 2, "Release", NULL, NULL },
	{ 3, "RemQueryInterface", NULL, NULL },
	{ 4, "RemAddRef", NULL, NULL },
	{ 5, "RemRelease", NULL, NULL },
    { 6, "RemQueryInterface2", NULL, NULL },
    { 0, NULL, NULL, NULL },
};

void
proto_register_IRemUnknown2 (void)
{
	static hf_register_info hf[] = {
		{ &hf_opnum,
		  { "Operation", "IRemUnknown2.opnum", FT_UINT16, BASE_DEC,
		    NULL, 0x0, "", HFILL }},
	};
	static gint *ett[] = {
		&ett_IRemUnknown2
	};
	proto_IRemUnknown2 = proto_register_protocol ("IRemUnknown2 IRemUnknown2 Resolver", "IRemUnknown2", "IRemUnknown2");
	proto_register_field_array (proto_IRemUnknown2, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_IRemUnknown2 (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_IRemUnknown2, ett_IRemUnknown2, &uuid_IRemUnknown2, ver_IRemUnknown2, IRemUnknown2_dissectors, hf_opnum);
}
