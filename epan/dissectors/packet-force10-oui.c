/* packet-force10-oui.c
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

void proto_register_force10_oui(void);

static int hf_llc_force10_pid = -1;

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
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
