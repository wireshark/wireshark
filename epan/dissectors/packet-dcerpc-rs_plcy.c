/* packet-dcerpc-rs_plcy.c
 *
 * Routines for dcerpc RS_PLCY dissection
 * Copyright 2003, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/security.tar.gz rs_plcy.idl
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

void proto_register_dcerpc_rs_plcy(void);
void proto_reg_handoff_dcerpc_rs_plcy(void);

/* Global hf index fields */

static int proto_dcerpc_rs_plcy = -1;
static int hf_rs_plcy_opnum = -1;
static gint ett_dcerpc_rs_plcy = -1;

static e_guid_t uuid_dcerpc_rs_plcy = {
	0x4c878280, 0x4000, 0x0000,
	{ 0x0D, 0x00, 0x02, 0x87, 0x14, 0x00, 0x00, 0x00 }
};

static guint16 ver_dcerpc_rs_plcy = 1;

static dcerpc_sub_dissector dcerpc_rs_plcy_dissectors[] = {
	{ 0,  "rs_properties_get_info",       NULL, NULL },
	{ 1,  "rs_properties_set_info ",      NULL, NULL },
	{ 2,  "rs_policy_get_info",           NULL, NULL },
	{ 3,  "rs_policy_set_info",           NULL, NULL },
	{ 4,  "rs_policy_get_effective",      NULL, NULL },
	{ 5,  "rs_policy_get_override_info",  NULL, NULL },
	{ 6,  "rs_policy_set_override_info",  NULL, NULL },
	{ 7,  "rs_auth_policy_get_info",      NULL, NULL },
	{ 8,  "rs_auth_policy_get_effective", NULL, NULL },
	{ 9,  "rs_auth_policy_set_info",      NULL, NULL },
	{ 0, NULL, NULL,  NULL }
};

void
proto_register_dcerpc_rs_plcy(void)
{
	static hf_register_info hf[] = {

		/* Global indexes */


		{ &hf_rs_plcy_opnum,
		  { "Operation", "rs_plcy.opnum", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},

	};

	static gint *ett[] = {
		&ett_dcerpc_rs_plcy
	};

	proto_dcerpc_rs_plcy = proto_register_protocol(
		"RS Interface properties", "RS_PLCY", "rs_plcy");

	proto_register_field_array(proto_dcerpc_rs_plcy, hf,
		array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dcerpc_rs_plcy(void)
{
	/* Register protocol as dcerpc */

	dcerpc_init_uuid(proto_dcerpc_rs_plcy, ett_dcerpc_rs_plcy,
			 &uuid_dcerpc_rs_plcy, ver_dcerpc_rs_plcy,
			 dcerpc_rs_plcy_dissectors, hf_rs_plcy_opnum);
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
