/* packet-ipmi-update.c
 * Sub-dissectors for IPMI messages (netFn=Firmware Update, PPS-specific)
 * Copyright 2007-2008, Alexey Neyman, Pigeon Point Systems <avn@pigeonpoint.com>
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

#include "config.h"

#include <epan/packet.h>

#include "packet-ipmi.h"

static ipmi_cmd_t cmd_update[] = {
	{ 0x00, IPMI_TBD,   NULL, NULL, "[PPS OEM] Upgrade Status", 0 },
	{ 0x01, IPMI_TBD,   NULL, NULL, "[PPS OEM] Upgrade Start", 0 },
	{ 0x02, IPMI_TBD,   NULL, NULL, "[PPS OEM] Upgrade Prepare", 0 },
	{ 0x03, IPMI_TBD,   NULL, NULL, "[PPS OEM] Upgrade Write", 0 },
	{ 0x04, IPMI_TBD,   NULL, NULL, "[PPS OEM] Upgrade Complete", 0 },
	{ 0x05, IPMI_TBD,   NULL, NULL, "[PPS OEM] Restore Backup", 0 },
	{ 0x06, IPMI_TBD,   NULL, NULL, "[PPS OEM] Query Backup Version", 0 }
};

void
proto_register_ipmi_update(void)
{
	ipmi_register_netfn_cmdtab(IPMI_UPDATE_REQ, IPMI_OEM_PPS, NULL, 0, NULL,
			cmd_update, array_length(cmd_update));
}
