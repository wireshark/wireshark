/* packet-nt-oui.c
 * Register an LLC dissector table for Nortel's OUI 00:00:0c
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
#include <epan/oui.h>

void proto_register_nortel_oui(void);

static int hf_llc_nortel_pid = -1;

static const value_string nortel_pid_vals[] = {
	{ 0x01a1,	"NDP flatnet hello" },
	{ 0x01a2,	"NDP segment hello" },
	{ 0x01a3,	"NDP bridge hello" },
	{ 0,		NULL }
};

/*
 * NOTE: there's no dissector here, just registration routines to set
 * up the dissector table for the Nortel OUI.
 */
void
proto_register_nortel_oui(void)
{
	static hf_register_info hf[] = {
	  { &hf_llc_nortel_pid,
		{ "PID",	"llc.nortel_pid",  FT_UINT16, BASE_HEX,
		  VALS(nortel_pid_vals), 0x0, NULL, HFILL }
	  }
	};

	llc_add_oui(OUI_NORTEL, "llc.nortel_pid", "LLC Nortel OUI PID", hf, -1);
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
