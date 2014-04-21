/* packet-dcerpc-dtsprovider.c
 * Routines for dcerpc Time server dissection
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/time.tar.gz time/service/dtsprovider.idl
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
#include "packet-dcerpc-dce122.h"

void proto_register_dtsprovider (void);
void proto_reg_handoff_dtsprovider (void);

static int proto_dtsprovider = -1;
static int hf_dtsprovider_opnum = -1;
/* static int hf_dtsprovider_status = -1; */


static gint ett_dtsprovider = -1;


static e_uuid_t uuid_dtsprovider = { 0xbfca1238, 0x628a, 0x11c9, { 0xa0, 0x73, 0x08, 0x00, 0x2b, 0x0d, 0xea, 0x7a } };
static guint16  ver_dtsprovider = 1;


static dcerpc_sub_dissector dtsprovider_dissectors[] = {
	{ 0, "ContactProvider", NULL, NULL},
	{ 1, "ServerRequestProviderTime", NULL, NULL},
	{ 0, NULL, NULL, NULL }
};

void
proto_register_dtsprovider (void)
{
	static hf_register_info hf[] = {
	  { &hf_dtsprovider_opnum,
	    { "Operation", "dtsprovider.opnum", FT_UINT16, BASE_DEC,
	      NULL, 0x0, NULL, HFILL }},
#if 0
	  { &hf_dtsprovider_status,
	    { "Status", "dtsprovider.status", FT_UINT32, BASE_DEC|BASE_EXT_STRING,
	      &dce_error_vals_ext, 0x0, "Return code, status of executed command", HFILL }}
#endif
	};

	static gint *ett[] = {
		&ett_dtsprovider,
	};
	proto_dtsprovider = proto_register_protocol ("DCE Distributed Time Service Provider", "DTSPROVIDER", "dtsprovider");
	proto_register_field_array (proto_dtsprovider, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_dtsprovider (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_dtsprovider, ett_dtsprovider, &uuid_dtsprovider, ver_dtsprovider, dtsprovider_dissectors, hf_dtsprovider_opnum);
}
