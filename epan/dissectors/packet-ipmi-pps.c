/* packet-ipmi-pps.c
 * Sub-dissectors for IPMI messages (netFn=OEM/Group, defining body = PPS)
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

static ipmi_cmd_t cmd_pps[] = {
  { 0x00, IPMI_TBD,   NULL, NULL, "[PPS OEM] Get Status", 0 },
  { 0x01, IPMI_TBD,   NULL, NULL, "[PPS OEM] Get Serial Interface Properties", 0 },
  { 0x02, IPMI_TBD,   NULL, NULL, "[PPS OEM] Set Serial Interface Properties", 0 },
  { 0x03, IPMI_TBD,   NULL, NULL, "[PPS OEM] Get Debug Level", 0 },
  { 0x04, IPMI_TBD,   NULL, NULL, "[PPS OEM] Set Debug Level", 0 },
  { 0x05, IPMI_TBD,   NULL, NULL, "[PPS OEM] Get Hardware Address", 0 },
  { 0x06, IPMI_TBD,   NULL, NULL, "[PPS OEM] Set Hardware Address", 0 },
  { 0x07, IPMI_TBD,   NULL, NULL, "[PPS OEM] Get Handle Switch", 0 },
  { 0x08, IPMI_TBD,   NULL, NULL, "[PPS OEM] Set Handle Switch", 0 },
  { 0x09, IPMI_TBD,   NULL, NULL, "[PPS OEM] Get Payload Communication Timeout", 0 },
  { 0x0a, IPMI_TBD,   NULL, NULL, "[PPS OEM] Set Payload Communication Timeout", 0 },
  { 0x0b, IPMI_TBD,   NULL, NULL, "[PPS OEM] Enable Payload Control", 0 },
  { 0x0c, IPMI_TBD,   NULL, NULL, "[PPS OEM] Disable Payload Control", 0 },
  { 0x0d, IPMI_TBD,   NULL, NULL, "[PPS OEM] Reset IPMC", 0 },
  { 0x0e, IPMI_TBD,   NULL, NULL, "[PPS OEM] Hang IPMC", 0 },
  { 0x0f, IPMI_TBD,   NULL, NULL, "[PPS OEM] Bused Resource Control", 0 },
  { 0x10, IPMI_TBD,   NULL, NULL, "[PPS OEM] Bused Resource Status", 0 },
  { 0x11, IPMI_TBD,   NULL, NULL, "[PPS OEM] Graceful Reset", 0 },
  { 0x12, IPMI_TBD,   NULL, NULL, "[PPS OEM] Diagnostic Interrupt Results", 0 },
  { 0x13, IPMI_TBD,   NULL, NULL, "[PPS OEM] Set/Clear Telco Alarm", 0 },
  { 0x14, IPMI_TBD,   NULL, NULL, "[PPS OEM] Get Telco Alarm Sensor Number", 0 },
  { 0x15, IPMI_TBD,   NULL, NULL, "[PPS OEM] Get Payload Shutdown Timeout", 0 },
  { 0x16, IPMI_TBD,   NULL, NULL, "[PPS OEM] Set Payload Shutdown Timeout", 0 },
  { 0x17, IPMI_TBD,   NULL, NULL, "[PPS OEM] Switch over Serial Debug", 0 },
  { 0x18, IPMI_TBD,   NULL, NULL, "[PPS OEM] Set Local FRU LED State", 0 },
  { 0x19, IPMI_TBD,   NULL, NULL, "[PPS OEM] Get Local FRU LED State", 0 },
  { 0x1a, IPMI_TBD,   NULL, NULL, "[PPS OEM] Update Discrete Sensor", 0 },
  { 0x1b, IPMI_TBD,   NULL, NULL, "[PPS OEM] Update Threshold Sensor", 0 },
  { 0x1c, IPMI_TBD,   NULL, NULL, "[PPS OEM] BTI Script Prepare", 0 },
  { 0x1d, IPMI_TBD,   NULL, NULL, "[PPS OEM] BTI Script Write", 0 },
  { 0x1e, IPMI_TBD,   NULL, NULL, "[PPS OEM] BTI Script Complete", 0 },
  { 0x1f, IPMI_TBD,   NULL, NULL, "[PPS OEM] BTI Script Start", 0 },
  { 0x20, IPMI_TBD,   NULL, NULL, "[PPS OEM] BTI Script Stop", 0 },
  { 0x21, IPMI_TBD,   NULL, NULL, "[PPS OEM] BTI Script Resume", 0 },
  { 0x22, IPMI_TBD,   NULL, NULL, "[PPS OEM] BTI Script Cease", 0 },
  { 0x23, IPMI_TBD,   NULL, NULL, "[PPS OEM] BTI Sensor Set", 0 },
  { 0x24, IPMI_TBD,   NULL, NULL, "[PPS OEM] BTI Notify", 0 },
  { 0x25, IPMI_TBD,   NULL, NULL, "[PPS OEM] BTI Get FRU State", 0 },
  { 0x26, IPMI_TBD,   NULL, NULL, "[PPS OEM] BTI Invalidate Hardware Address", 0 },
  { 0x27, IPMI_TBD,   NULL, NULL, "[PPS OEM] Get Module Status", 0 },
  { 0x28, IPMI_TBD,   NULL, NULL, "[PPS OEM] Enable AMC Site", 0 },
  { 0x29, IPMI_TBD,   NULL, NULL, "[PPS OEM] Disable AMC Site", 0 },
  { 0x2a, IPMI_TBD,   NULL, NULL, "[PPS OEM] BTI Wait for Payload Notify", 0 },
  { 0x2b, IPMI_TBD,   NULL, NULL, "[PPS OEM] Set Test Flags", 0 },
  { 0x2c, IPMI_TBD,   NULL, NULL, "[PPS OEM] Get Geographic Address", 0 },
  { 0x2d, IPMI_TBD,   NULL, NULL, "[PPS OEM] Set Geographic Address", 0 },
  { 0x30, IPMI_TBD,   NULL, NULL, "[PPS OEM] Set EEPROM Sensor Data", 0 },
  { 0x31, IPMI_TBD,   NULL, NULL, "[PPS OEM] Set EEPROM Sensor Hysteresis", 0 },
  { 0x32, IPMI_TBD,   NULL, NULL, "[PPS OEM] Set EEPROM Sensor Threshold", 0 },
  { 0x33, IPMI_TBD,   NULL, NULL, "[PPS OEM] Reset EEPROM SDR Repository", 0 },
  { 0x34, IPMI_TBD,   NULL, NULL, "[PPS OEM] Backend Power Control", 0 },
  { 0x35, IPMI_TBD,   NULL, NULL, "[PPS OEM] Read CPLD Register", 0 },
  { 0x36, IPMI_TBD,   NULL, NULL, "[PPS OEM] Write CPLD Register", 0 }
};

void
ipmi_register_pps(gint proto_ipmi _U_)
{
	static guint8 sig_pps[3] = { 0x0a, 0x40, 0x00 };
	static guint8 sig_pps_rev[3] = { 0x00, 0x40, 0x0a };

	ipmi_register_netfn_cmdtab(IPMI_OEM_REQ, IPMI_OEM_NONE, sig_pps, 3,
			"Pigeon Point Systems", cmd_pps, array_length(cmd_pps));
	ipmi_register_netfn_cmdtab(IPMI_OEM_REQ, IPMI_OEM_NONE, sig_pps_rev, 3,
			"Pigeon Point Systems (reversed)", cmd_pps, array_length(cmd_pps));
}
