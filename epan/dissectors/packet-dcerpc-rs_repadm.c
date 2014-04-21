/* packet-dcerpc-rs_repadm.c
 *
 * Routines for dcerpc Registry server administration operations.
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/security.tar.gz  security/idl/rs_repadm.idl
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

void proto_register_rs_repadm (void);
void proto_reg_handoff_rs_repadm (void);

static int proto_rs_repadm = -1;
static int hf_rs_repadm_opnum = -1;


static gint ett_rs_repadm = -1;


static e_uuid_t uuid_rs_repadm = { 0x5b8c2fa8, 0xb60b, 0x11c9, { 0xbe, 0x0f, 0x08, 0x00, 0x1e, 0x01, 0x8f, 0xa0 } };
static guint16  ver_rs_repadm = 1;




static dcerpc_sub_dissector rs_repadm_dissectors[] = {
	{ 0, "stop",              NULL, NULL},
	{ 1, "maint",             NULL, NULL},
	{ 2, "mkey",              NULL, NULL},
	{ 3, "info",              NULL, NULL},
	{ 4, "info_full",         NULL, NULL},
	{ 5, "destroy",           NULL, NULL},
	{ 6, "init_replica",      NULL, NULL},
	{ 7, "change_master",     NULL, NULL},
	{ 8, "become_master",     NULL, NULL},
	{ 9, "become_slave",      NULL, NULL},
	{ 10, "set_sw_rev",       NULL, NULL},
	{ 11, "get_sw_vers_info", NULL, NULL},
	{ 0, NULL, NULL, NULL }
};


void
proto_register_rs_repadm (void)
{
	static hf_register_info hf[] = {
	{ &hf_rs_repadm_opnum,
		{ "Operation", "rs_repadm.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_rs_repadm,
	};
	proto_rs_repadm = proto_register_protocol ("Registry server administration operations.", "RS_REPADM", "rs_repadm");
	proto_register_field_array (proto_rs_repadm, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_rs_repadm (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_rs_repadm, ett_rs_repadm, &uuid_rs_repadm, ver_rs_repadm, rs_repadm_dissectors, hf_rs_repadm_opnum);
}
