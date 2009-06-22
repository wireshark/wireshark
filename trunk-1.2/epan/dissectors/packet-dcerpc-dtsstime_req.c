/* packet-dcerpc-dtsstime_req.c
 * Routines for Time services stuff.     
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/time.tar.gz time/service/dtsstime_req.idl
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"


static int proto_dtsstime_req = -1;
static int hf_dtsstime_req_opnum = -1;


static gint ett_dtsstime_req = -1;


static e_uuid_t uuid_dtsstime_req = { 0x019ee420, 0x682d, 0x11c9, { 0xa6, 0x07, 0x08, 0x00, 0x2b, 0x0d, 0xea, 0x7a } };
static guint16  ver_dtsstime_req = 1;


static dcerpc_sub_dissector dtsstime_req_dissectors[] = {
    { 0, "ClerkRequestTime", NULL, NULL},
    { 1, "ServerRequestTime", NULL, NULL},
    { 0, NULL, NULL, NULL }
};

void
proto_register_dtsstime_req (void)
{
	static hf_register_info hf[] = {
	{ &hf_dtsstime_req_opnum,
		{ "Operation", "dtsstime_req.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, "Operation", HFILL }}
	};

	static gint *ett[] = {
		&ett_dtsstime_req,
	};
	proto_dtsstime_req = proto_register_protocol ("DCE Distributed Time Service Local Server", "DTSSTIME_REQ", "dtsstime_req");
	proto_register_field_array (proto_dtsstime_req, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_dtsstime_req (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_dtsstime_req, ett_dtsstime_req, &uuid_dtsstime_req, ver_dtsstime_req, dtsstime_req_dissectors, hf_dtsstime_req_opnum);
}
