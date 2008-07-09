/* packet-bat.c
 * Routines for B.A.T.M.A.N. Layer 3 dissection
 * Copyright 2008, Sven Eckelmann <sven.eckelmann@gmx.de>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "packet-bat.h"

/* forward declaration */
void proto_register_bat(void);
void proto_reg_handoff_bat(void);

int proto_bat_plugin = -1;
module_t *bat_module = NULL;

/* tap */
int bat_tap = -1;
int bat_follow_tap = -1;

void proto_register_bat(void)
{

	proto_bat_plugin = proto_register_protocol(
	                           "B.A.T.M.A.N. Layer 3 Protocol",
	                           "BAT",          /* short name */
	                           "bat"           /* abbrev */
	                   );

	/* Register our configuration options for B.A.T.M.A.N. */
	bat_module = prefs_register_protocol(proto_bat_plugin, proto_reg_handoff_bat);

	register_bat_batman();
	register_bat_gw();
	register_bat_vis();
}

void proto_reg_handoff_bat(void)
{
	static gboolean inited = FALSE;

	if (!inited) {
		bat_tap = register_tap("batman");
		bat_follow_tap = register_tap("batman_follow");
		inited = TRUE;
	}

	reg_handoff_bat_batman();
	reg_handoff_bat_gw();
	reg_handoff_bat_vis();
}
