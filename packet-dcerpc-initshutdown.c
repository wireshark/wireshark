/* packet-dcerpc-initshutdown.c
 * Routines for SMB \PIPE\initshutdown packet disassembly
 * Based on packet-dcerpc-winreg.c
 * Copyright 2001-2003 Tim Potter <tpot@samba.org>
 * as per a suggestion by Jim McDonough
 *
 * $Id: packet-dcerpc-initshutdown.c,v 1.1 2003/10/27 23:31:54 guy Exp $
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
#include "packet-dcerpc-nt.h"
#include "packet-dcerpc-initshutdown.h"
#include "smb.h"

/* Global hf index fields */

static int hf_rc = -1;
static int hf_shutdown_message = -1;
static int hf_shutdown_seconds = -1;
static int hf_shutdown_force = -1;
static int hf_shutdown_reboot = -1;
static int hf_shutdown_server = -1;
static int hf_shutdown_reason = -1;


/* Reg Shutdown functions */
static int
dissect_shutdown_server(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *tree, char *drep)
{
	offset = dissect_ndr_uint16(
		tvb, offset, pinfo, tree, drep, hf_shutdown_server, NULL);

	return offset;
}

static int
dissect_shutdown_message(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *tree, char *drep)
{
	offset = dissect_ndr_counted_string(
		tvb, offset, pinfo, tree, drep, hf_shutdown_message, 0);

	return offset;
}

static int
InitshutdownShutdown_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
	 proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, tree, drep,
		dissect_shutdown_server, NDR_POINTER_UNIQUE,
		"Server", -1);

	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, tree, drep,
		dissect_shutdown_message, NDR_POINTER_UNIQUE,
		"message", -1);

	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep, hf_shutdown_seconds, NULL);
	
	offset = dissect_ndr_uint8(
		tvb, offset, pinfo, tree, drep, hf_shutdown_force, NULL);
	offset = dissect_ndr_uint8(
		tvb, offset, pinfo, tree, drep, hf_shutdown_reboot, NULL);
		
	return offset;
}

static int
InitshutdownShutdown_r(tvbuff_t *tvb, int offset, packet_info *pinfo,
	 proto_tree *tree, char *drep)
{
	offset = dissect_ntstatus(
		tvb, offset, pinfo, tree, drep, hf_rc, NULL);

	return offset;
}

static int
InitshutdownAbortShutdown_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
		   proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(
		tvb, offset, pinfo, tree, drep,
		dissect_shutdown_server, NDR_POINTER_UNIQUE,
		"Server", -1);	
		
	return offset;
}

static int
InitshutdownShutdownEx_q(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, char *drep)
{
	offset = InitshutdownShutdown_q(tvb, offset, pinfo, tree, drep);
	offset = dissect_ndr_uint32(
		tvb, offset, pinfo, tree, drep, hf_shutdown_reason, NULL);
		
	return offset;
}

static int proto_dcerpc_initshutdown = -1;
static int hf_initshutdown_opnum = -1;
static gint ett_dcerpc_initshutdown = -1;

static e_uuid_t uuid_dcerpc_initshutdown = {
        0x894de0c0, 0x0d55, 0x11d3,
        { 0xa3, 0x22, 0x00, 0xc0, 0x4f, 0xa3, 0x21, 0xa1 }
};

static guint16 ver_dcerpc_initshutdown = 1;

static dcerpc_sub_dissector dcerpc_initshutdown_dissectors[] = {
        { INITSHUTDOWN_INITIATE_SYSTEM_SHUTDOWN, "InitiateSystemShutdown", 
	  InitshutdownShutdown_q, InitshutdownShutdown_r },
        { INITSHUTDOWN_ABORT_SYSTEM_SHUTDOWN, "AbortSystemShutdown", 
	  InitshutdownAbortShutdown_q, InitshutdownShutdown_r },
	{ INITSHUTDOWN_INITIATE_SYSTEM_SHUTDOWN_EX, "InitiateSystemShutdownEx", 
	  InitshutdownShutdownEx_q, InitshutdownShutdown_r },
        { 0, NULL, NULL,  NULL }
};

void
proto_register_dcerpc_initshutdown(void)
{
	static hf_register_info hf[] = {

		/* Global indexes */

		{ &hf_rc,
		  { "Return code", "initshutdown.rc", FT_UINT32, BASE_HEX,
		    VALS(NT_errors), 0x0, "Initshutdown return code", HFILL }},

		{ &hf_initshutdown_opnum,
		  { "Operation", "initshutdown.opnum", FT_UINT16, BASE_DEC,
		    NULL, 0x0, "Operation", HFILL }},

		{ &hf_shutdown_message,
		  { "Message", "initshutdown.message", FT_STRING, BASE_NONE,
		    NULL, 0x0, "Message", HFILL }},

		{ &hf_shutdown_seconds,
		  { "Seconds", "initshutdown.seconds", FT_UINT32, BASE_DEC,
		    NULL, 0x00, "Seconds", HFILL }},

		{ &hf_shutdown_force,
		  { "Force applications shut", "initshutdown.force", FT_UINT8,
		    BASE_DEC, NULL, 0x00, "Force applications shut", HFILL }},

		{ &hf_shutdown_reboot,
		  { "Reboot", "initshutdown.reboot", FT_UINT8, BASE_DEC, 
		    NULL, 0x00, "Reboot", HFILL }},

		{ &hf_shutdown_server,
		  { "Server", "initshutdown.server", FT_UINT16, BASE_HEX, 
		    NULL, 0x00, "Server", HFILL }},

		{ &hf_shutdown_reason,
		  { "Reason", "initshutdown.reason", FT_UINT32, BASE_HEX,
		    NULL, 0x00, "Reason", HFILL }}

	};

        static gint *ett[] = {
                &ett_dcerpc_initshutdown
        };

        proto_dcerpc_initshutdown = proto_register_protocol(
                "Remote Shutdown", "INITSHUTDOWN", "initshutdown");

	proto_register_field_array(proto_dcerpc_initshutdown, hf,
		array_length(hf));

        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dcerpc_initshutdown(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_initshutdown, ett_dcerpc_initshutdown,
        		&uuid_dcerpc_initshutdown, ver_dcerpc_initshutdown,
        		dcerpc_initshutdown_dissectors, hf_initshutdown_opnum);
}
