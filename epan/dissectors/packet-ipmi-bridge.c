/* packet-ipmi-bridge.c
 * Sub-dissectors for IPMI messages (netFn=Bridge)
 * Copyright 2007-2008, Alexey Neyman, Pigeon Point Systems <avn@pigeonpoint.com>
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

#include "config.h"

#include <epan/packet.h>

#include "packet-ipmi.h"

/* Bridge commands are not implemented (yet) */


static ipmi_cmd_t cmd_bridge[] = {
  /* Bridge management commands (ICMB) */
  { 0x00, IPMI_TBD,   NULL, NULL, "[ICMB] Get Bridge State", 0 },
  { 0x01, IPMI_TBD,   NULL, NULL, "[ICMB] Set Bridge State", 0 },
  { 0x02, IPMI_TBD,   NULL, NULL, "[ICMB] Get ICMB Address", 0 },
  { 0x03, IPMI_TBD,   NULL, NULL, "[ICMB] Set ICMB Address", 0 },
  { 0x04, IPMI_TBD,   NULL, NULL, "[ICMB] Set Bridge Proxy Address", 0 },
  { 0x05, IPMI_TBD,   NULL, NULL, "[ICMB] Get Bridge Statistics", 0 },
  { 0x06, IPMI_TBD,   NULL, NULL, "[ICMB] Get ICMB Capabilities", 0 },
  { 0x08, IPMI_TBD,   NULL, NULL, "[ICMB] Clear Bridge Statistics", 0 },
  { 0x09, IPMI_TBD,   NULL, NULL, "[ICMB] Get Bridge Proxy Address", 0 },
  { 0x0a, IPMI_TBD,   NULL, NULL, "[ICMB] Get ICMB Connector Info", 0 },
  { 0x0b, IPMI_TBD,   NULL, NULL, "[ICMB] Get ICMB Connection ID", 0 },
  { 0x0c, IPMI_TBD,   NULL, NULL, "[ICMB] Send ICMB Connection ID", 0 },

  /* Discovery Commands (ICMB) */
  { 0x10, IPMI_TBD,   NULL, NULL, "[ICMB] Prepare For Discovery", 0 },
  { 0x11, IPMI_TBD,   NULL, NULL, "[ICMB] Get Addresses", 0 },
  { 0x12, IPMI_TBD,   NULL, NULL, "[ICMB] Set Discovered", 0 },
  { 0x13, IPMI_TBD,   NULL, NULL, "[ICMB] Get Chassis Device ID", 0 },
  { 0x14, IPMI_TBD,   NULL, NULL, "[ICMB] Set Chassis Device ID", 0 },

  /* Bridging Commands (ICMB) */
  { 0x20, IPMI_TBD,   NULL, NULL, "[ICMB] Bridge Request", 0 },
  { 0x21, IPMI_TBD,   NULL, NULL, "[ICMB] Bridge Message", 0 },

  /* Event Commands (ICMB) */
  { 0x30, IPMI_TBD,   NULL, NULL, "[ICMB] Get Event Count", 0 },
  { 0x31, IPMI_TBD,   NULL, NULL, "[ICMB] Set Event Destination", 0 },
  { 0x32, IPMI_TBD,   NULL, NULL, "[ICMB] Set Event Reception State", 0 },
  { 0x33, IPMI_TBD,   NULL, NULL, "[ICMB] Send ICMB Event Message", 0 },
  { 0x34, IPMI_TBD,   NULL, NULL, "[ICMB] Get Event Destination", 0 },
  { 0x35, IPMI_TBD,   NULL, NULL, "[ICMB] Get Event Reception State", 0 },

  /* OEM Commands for Bridge NetFn */
  { 0xc0, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xc1, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xc2, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xc3, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xc4, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xc5, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xc6, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xc7, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xc8, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xc9, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xca, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xcb, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xcc, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xcd, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xce, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xcf, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xd0, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xd1, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xd2, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xd3, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xd4, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xd5, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xd6, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xd7, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xd8, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xd9, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xda, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xdb, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xdc, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xdd, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xde, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xdf, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xe0, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xe1, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xe2, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xe3, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xe4, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xe5, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xe6, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xe7, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xe8, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xe9, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xea, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xeb, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xec, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xed, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xee, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xef, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xf0, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xf1, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xf2, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xf3, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xf4, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xf5, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xf6, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xf7, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xf8, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xf9, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xfa, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xfb, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xfc, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xfd, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },
  { 0xfe, IPMI_TBD,   NULL, NULL, "[ICMB] OEM Command", 0 },

  /* Other Bridge Commands */
  { 0xff, IPMI_TBD,   NULL, NULL, "[ICMB] Error Report", 0 },
};

void
ipmi_register_bridge(gint proto_ipmi _U_)
{
	ipmi_register_netfn_cmdtab(IPMI_BRIDGE_REQ, IPMI_OEM_NONE, NULL, 0, NULL,
			cmd_bridge, array_length(cmd_bridge));
}
