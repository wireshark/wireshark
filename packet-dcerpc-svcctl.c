/* packet-dcerpc-svcctl.c
 * Routines for SMB \PIPE\svcctl packet disassembly
 * Copyright 2003, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-dcerpc-svcctl.c,v 1.1 2003/04/26 00:19:23 tpot Exp $
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

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-svcctl.h"

static int proto_dcerpc_svcctl = -1;
static int hf_svcctl_opnum = -1;

static gint ett_dcerpc_svcctl = -1;

static e_uuid_t uuid_dcerpc_svcctl = {
        0x367abb81, 0x9844, 0x35f1,
        { 0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03 }
};

static guint16 ver_dcerpc_svcctl = 2;

static dcerpc_sub_dissector dcerpc_svcctl_dissectors[] = {
	{ SVC_CLOSE, "Close", NULL, NULL },
	{ SVC_STOP_SERVICE, "Stop", NULL, NULL },
	{ SVC_DELETE, "Delete", NULL, NULL },
	{ SVC_UNKNOWN_3, "Unknown 0x03", NULL, NULL },
	{ SVC_GET_SVC_SEC, "Get security", NULL, NULL },
	{ SVC_CHANGE_SVC_CONFIG, "Change config", NULL, NULL },
	{ SVC_ENUM_SVCS_STATUS, "Enum status", NULL, NULL },
	{ SVC_OPEN_SC_MAN, "Open SC Manager", NULL, NULL },
	{ SVC_OPEN_SERVICE, "Open service", NULL, NULL },
	{ SVC_QUERY_SVC_CONFIG, "Query config", NULL, NULL },
	{ SVC_START_SERVICE, "Start", NULL, NULL },
	{ SVC_QUERY_DISP_NAME, "Query display name", NULL, NULL },
	{ SVC_OPEN_SC_MAN_A, "Open SC Manager A", NULL, NULL },
	{ SVC_OPEN_SERVICE_A, "Open Service A", NULL, NULL },
	{0, NULL, NULL, NULL}
};

static const value_string svcctl_opnum_vals[] = {
	{ SVC_CLOSE, "Close" },
	{ SVC_STOP_SERVICE, "Stop" },
	{ SVC_DELETE, "Delete" },
	{ SVC_UNKNOWN_3, "Unknown 0x03" },
	{ SVC_GET_SVC_SEC, "Get security" },
	{ SVC_CHANGE_SVC_CONFIG, "Change config" },
	{ SVC_ENUM_SVCS_STATUS, "Enum status" },
	{ SVC_OPEN_SC_MAN, "Open SC Manager" },
	{ SVC_OPEN_SERVICE, "Open service" },
	{ SVC_QUERY_SVC_CONFIG, "Query config" },
	{ SVC_START_SERVICE, "Start" },
	{ SVC_QUERY_DISP_NAME, "Query display name" },
	{ SVC_OPEN_SC_MAN_A, "Open SC Manager A" },
	{ SVC_OPEN_SERVICE_A, "Open Service A" },
	{ 0, NULL }
};

void
proto_register_dcerpc_svcctl(void)
{
        static hf_register_info hf[] = {
	  { &hf_svcctl_opnum,
	    { "Operation", "svcctl.opnum", FT_UINT16, BASE_DEC,
	      VALS(svcctl_opnum_vals), 0x0, "Operation", HFILL }},
	};

        static gint *ett[] = {
                &ett_dcerpc_svcctl,
        };

        proto_dcerpc_svcctl = proto_register_protocol(
                "Microsoft Service Control", "SVCCTL", "svcctl");

	proto_register_field_array(proto_dcerpc_svcctl, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dcerpc_svcctl(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_svcctl, ett_dcerpc_svcctl,
                         &uuid_dcerpc_svcctl, ver_dcerpc_svcctl,
                         dcerpc_svcctl_dissectors, hf_svcctl_opnum);
}
