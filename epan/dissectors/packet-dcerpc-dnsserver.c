/* packet-dcerpc-dnsserver.c
 * Routines for SMB \PIPE\DNSSERVER packet disassembly
 * Copyright 2001, 2002 Tim Potter <tpot@samba.org>
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

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"
#include "packet-dcerpc-dnsserver.h"
#include "packet-windows-common.h"

/* Global hf index fields */

static int hf_rc = -1;

static int proto_dcerpc_dnsserver = -1;
static int hf_opnum = -1;

static gint ett_dnsserver = -1;

static e_uuid_t uuid_dcerpc_dnsserver = {
        0x50abc2a4, 0x574d, 0x40b3,
        { 0x9d, 0x66, 0xee, 0x4f, 0xd5, 0xfb, 0xa0, 0x76 }
};

static guint16 ver_dcerpc_dnsserver = 5;

static dcerpc_sub_dissector dcerpc_dnsserver_dissectors[] = {
	{ DNSSERVER_DNSSRV_OPERATION, "DnssrvOperation", 
	  NULL, NULL },
	{ DNSSERVER_DNSSRV_QUERY, "DnssrvQuery", 
	  NULL, NULL },
	{ DNSSERVER_DNSSRV_COMPLEX_OPERATION, "DnssrvComplexOperation", 
	  NULL, NULL },
	{ DNSSERVER_DNSSRV_ENUM_RECORDS, "DnssrvEnumRecords", 
	  NULL, NULL }, 
	{ DNSSERVER_DNSSRV_UPDATE_RECORD, "DnssrvUpdateRecord", 
	  NULL, NULL },
	{ DNSSERVER_DNSSRV_OPERATION_2, "DnssrvOperation2", 
	  NULL, NULL },
	{ DNSSERVER_DNSSRV_QUERY_2, "DnssrvQuery2", 
	  NULL, NULL },
	{ DNSSERVER_DNSSRV_COMPLEX_OPERATION_2, "DnssrvComplexOperation2", 
	  NULL, NULL },
	{ DNSSERVER_DNSSRV_ENUM_RECORDS_2, "DnssrvEnumRecords2", 
	  NULL, NULL },
	{ DNSSERVER_DNSSRV_UPDATE_RECORD_2, "DnssrvUpdateRecord2", 
	  NULL, NULL },
        { 0, NULL, NULL,  NULL }
};

void
proto_register_dcerpc_dnsserver(void)
{
	static hf_register_info hf[] = {

		/* Global indexes */

		{ &hf_rc,
		  { "Return code", "dnsserver.rc", FT_UINT32, BASE_HEX,
		    VALS(NT_errors), 0x0, "Return code", HFILL }},

		{ &hf_opnum,
		  { "Operation", "dnsserver.opnum", FT_UINT16, BASE_DEC,
		    NULL, 0x0, "Operation", HFILL }},
	};

        static gint *ett[] = {
                &ett_dnsserver
        };

        proto_dcerpc_dnsserver = proto_register_protocol(
                "Windows 2000 DNS", "DNSSERVER", "dnsserver");

	proto_register_field_array(proto_dcerpc_dnsserver, hf, array_length(hf));

        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dcerpc_dnsserver(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(
		proto_dcerpc_dnsserver, ett_dnsserver, &uuid_dcerpc_dnsserver,
		ver_dcerpc_dnsserver, dcerpc_dnsserver_dissectors, hf_opnum);
}
