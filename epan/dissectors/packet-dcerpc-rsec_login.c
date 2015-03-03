/* packet-dcerpc-rsec_login.c
 *
 * Routines for dcerpc Remote sec_login preauth interface.
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/security.tar.gz  security/idl/rsec_login.idl
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

void proto_register_rsec_login (void);
void proto_reg_handoff_rsec_login (void);

static int proto_rsec_login = -1;
static int hf_rsec_login_opnum = -1;

static gint ett_rsec_login = -1;


static e_guid_t uuid_rsec_login = { 0xa76e832a, 0x10df, 0x11cd, { 0x90, 0x56, 0x08, 0x00, 0x09, 0x24, 0x24, 0x44 } };
static guint16  ver_rsec_login = 2;


static dcerpc_sub_dissector rsec_login_dissectors[] = {
	{ 0, "rsec_login_get_trusted_preauth", NULL, NULL},
	{ 0, NULL, NULL, NULL }
};

void
proto_register_rsec_login (void)
{
	static hf_register_info hf[] = {
		{ &hf_rsec_login_opnum,
		{ "Operation", "rsec_login.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_rsec_login,
	};
	proto_rsec_login = proto_register_protocol ("Remote sec_login preauth interface.", "rsec_login", "rsec_login");
	proto_register_field_array (proto_rsec_login, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_rsec_login (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_rsec_login, ett_rsec_login, &uuid_rsec_login, ver_rsec_login, rsec_login_dissectors, hf_rsec_login_opnum);
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
