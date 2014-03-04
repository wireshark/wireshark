/* packet-iana-oui.c
 * Register an LLC dissector table for the IANA's OUI 00:00:5e
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
#include "packet-llc.h"
#include <epan/oui.h>
#include <epan/iana_snap_pid.h>

void proto_register_iana_oui(void);

static int hf_llc_iana_pid = -1;

static const value_string iana_pid_vals[] = {
	{ IANA_PID_MARS_DATA_SHORT,	"MARS Data Messages (short form)" },
	{ IANA_PID_NHRP_RESERVED,	"Reserved for future NHRP use" },
	{ IANA_PID_MARS_NHRP_CONTROL,	"MARS/NHRP Control Messages" },
	{ IANA_PID_MARS_DATA_LONG,	"MARS Data Messages (long form)" },
	{ IANA_PID_SCSP,		"SCSP" },
	{ IANA_PID_VRID,		"VRID" },
	{ IANA_PID_L2TP,		"L2TP" },
	{ IANA_PID_VPN_ID,		"VPN ID" },
	{ IANA_PID_MSDP_GRE_PROTO_TYPE,	"MSDP-GRE-Protocol Type" },
	{ 0,				NULL }
};

/*
 * NOTE: there's no dissector here, just registration routines to set
 * up the dissector table for the IANA OUI.
 */
void
proto_register_iana_oui(void)
{
	static hf_register_info hf[] = {
	  { &hf_llc_iana_pid,
		{ "PID",	"llc.iana_pid",  FT_UINT16, BASE_HEX,
		  VALS(iana_pid_vals), 0x0, NULL, HFILL }
	  }
	};

	llc_add_oui(OUI_IANA, "llc.iana_pid", "LLC IANA OUI PID", hf);
}
