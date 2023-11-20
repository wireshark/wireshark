/* packet-force10-oui.c
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

void proto_register_force10_oui(void);

static int hf_llc_force10_pid;

static const value_string force10_pid_vals[] = {
	{ 0x0111,	"FEFD" },	/* Far End Failure Detection */
	{ 0,		NULL }
};

/*
 * NOTE: there's no dissector here, just registration routines to set
 * up the dissector table for the Force10 OUI.
 */
void
proto_register_force10_oui(void)
{
	static hf_register_info hf[] = {
	  { &hf_llc_force10_pid,
		{ "PID",	"llc.force10_pid",  FT_UINT16, BASE_HEX,
		  VALS(force10_pid_vals), 0x0, NULL, HFILL }
	  }
	};

	llc_add_oui(OUI_FORCE10, "llc.force10_pid", "LLC FORCE10 OUI PID", hf, -1);
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
