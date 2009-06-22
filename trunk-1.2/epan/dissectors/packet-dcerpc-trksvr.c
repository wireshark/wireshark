/* packet-dcerpc-trksvr.c
 * Routines for DCERPC Distributed Link tracking Server packet disassembly
 * Copyright 2003, Ronnie Sahlberg
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
/* The IDL file for this interface can be extracted by grepping for idl
 * in capitals.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"
#include "packet-windows-common.h"

static int proto_dcerpc_trksvr = -1;
static int hf_trksvr_opnum = -1;
static int hf_trksvr_rc = -1;

static gint ett_dcerpc_trksvr = -1;

/*
  IDL [ uuid(4da1-943d-11d1-acae-00c0afc2aa3f),
  IDL   version(1.0),
  IDL   implicit_handle(handle_t rpc_binding)
  IDL ] interface trksvr
  IDL {
*/
static e_uuid_t uuid_dcerpc_trksvr = {
        0x4da1c422, 0x943d, 0x11d1,
        { 0xac, 0xae, 0x00, 0xc0, 0x4f, 0xc2, 0xaa, 0x3f }
};

static guint16 ver_dcerpc_trksvr = 1;

static dcerpc_sub_dissector dcerpc_trksvr_dissectors[] = {
        { 0, "LnkSvrMessage",
		NULL,
		NULL },
        {0, NULL, NULL,  NULL }
};

void
proto_register_dcerpc_trksvr(void)
{
static hf_register_info hf[] = {
	{ &hf_trksvr_opnum, { 
		"Operation", "trksvr.opnum", FT_UINT16, BASE_DEC,
		NULL, 0x0, "", HFILL }},
	{ &hf_trksvr_rc, {
		"Return code", "trksvr.rc", FT_UINT32, BASE_HEX,
		VALS(NT_errors), 0x0, "TRKSVR return code", HFILL }},
	};

        static gint *ett[] = {
                &ett_dcerpc_trksvr
        };

        proto_dcerpc_trksvr = proto_register_protocol(
                "Microsoft Distributed Link Tracking Server Service", "TRKSVR", "trksvr");

        proto_register_field_array(proto_dcerpc_trksvr, hf,
				   array_length(hf));

        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dcerpc_trksvr(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_trksvr, ett_dcerpc_trksvr,
                         &uuid_dcerpc_trksvr, ver_dcerpc_trksvr,
                         dcerpc_trksvr_dissectors, hf_trksvr_opnum);
}
