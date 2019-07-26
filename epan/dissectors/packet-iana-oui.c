/* packet-iana-oui.c
 * Register an LLC dissector table for the IANA's OUI 00:00:5e
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-llc.h"
#include "packet-iana-oui.h"
#include <epan/oui.h>

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

	llc_add_oui(OUI_IANA, "llc.iana_pid", "LLC IANA OUI PID", hf, -1);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
