/* packet-dcerpc-cds_solicit.c
 * Routines for cds_solicit dissection
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/directory.tar.gz directory/cds/stubs/cds_solicit.idl
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

void proto_register_cds_solicit (void);
void proto_reg_handoff_cds_solicit (void);

static int proto_cds_solicit = -1;
static int hf_cds_solicit_opnum = -1;


static gint ett_cds_solicit = -1;


static e_guid_t uuid_cds_solicit = { 0xd5579459, 0x8bca, 0x11ca, { 0xb7, 0x71, 0x08, 0x00, 0x2b, 0x1c, 0x8f, 0x1f } };
static guint16  ver_cds_solicit = 1;


static dcerpc_sub_dissector cds_solicit_dissectors[] = {
	{ 0, "cds_Solicit",       NULL, NULL},
	{ 1, "cds_Advertise",     NULL, NULL},
	{ 2, "cds_SolicitServer", NULL, NULL},
	{ 0, NULL, NULL, NULL }
};

void
proto_register_cds_solicit (void)
{
	static hf_register_info hf[] = {
	{ &hf_cds_solicit_opnum,
		{ "Operation", "cds_solicit.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_cds_solicit,
	};
	proto_cds_solicit = proto_register_protocol ("DCE/RPC CDS Solicitation", "cds_solicit", "cds_solicit");
	proto_register_field_array (proto_cds_solicit, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_cds_solicit (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_cds_solicit, ett_cds_solicit, &uuid_cds_solicit, ver_cds_solicit, cds_solicit_dissectors, hf_cds_solicit_opnum);
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
