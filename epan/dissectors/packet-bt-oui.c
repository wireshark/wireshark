/* packet-bt-oui.c
 * Dissector for Bluetooth High Speed over wireless
 * Copyright 2012 intel Corp.
 * Written by Andrei Emeltchenko at intel dot com
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

static int hf_llc_bluetooth_pid = -1;

/*
 * BLUETOOTH SPECIFICATION Version 4.0 [Vol 5] defines that
 * before transmission, the PAL shall remove the HCI header,
 * add LLC and SNAP headers and insert an 802.11 MAC header.
 * Protocol identifier are described in Table 5.2.
 */

#define AMP_U_L2CAP		0x0001
#define AMP_C_ACTIVITY_REPORT	0x0002
#define AMP_C_SECURITY_FRAME	0x0003
#define AMP_C_LINK_SUP_REQUEST	0x0004
#define AMP_C_LINK_SUP_REPLY	0x0005

static const value_string bluetooth_pid_vals[] = {
	{ AMP_U_L2CAP,			"AMP_U L2CAP ACL data" },
	{ AMP_C_ACTIVITY_REPORT,	"AMP-C Activity Report" },
	{ AMP_C_SECURITY_FRAME,		"AMP-C Security frames" },
	{ AMP_C_LINK_SUP_REQUEST,	"AMP-C Link supervision request" },
	{ AMP_C_LINK_SUP_REPLY,		"AMP-C Link supervision reply" },
	{ 0,	NULL }
};

void proto_register_bt_oui(void);
void proto_reg_handoff_bt_oui(void);

/*
 * NOTE: there's no dissector here, just registration routines to set
 * up the dissector table for the Bluetooth OUI
 */

void proto_reg_handoff_bt_oui(void)
{
	dissector_handle_t eapol_handle;
	dissector_handle_t btl2cap_handle;

	eapol_handle = find_dissector("eapol");
	btl2cap_handle = find_dissector("btl2cap");

	dissector_add_uint("llc.bluetooth_pid", AMP_C_SECURITY_FRAME, eapol_handle);
	dissector_add_uint("llc.bluetooth_pid", AMP_U_L2CAP, btl2cap_handle);
}


void proto_register_bt_oui(void)
{
	static hf_register_info hf[] = {
		{ &hf_llc_bluetooth_pid,
			{ "PID",	"llc.bluetooth_pid",  FT_UINT16, BASE_HEX,
				VALS(bluetooth_pid_vals), 0x0, "Protocol ID", HFILL }
		}
	};

	llc_add_oui(OUI_BLUETOOTH, "llc.bluetooth_pid", "LLC Bluetooth OUI PID", hf);
}

