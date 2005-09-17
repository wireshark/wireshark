/* packet-cisco-oui.c
 * Register an LLC dissector table for Cisco's OUI 00:00:0c
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-llc.h"
#include <epan/oui.h>

static int hf_llc_cisco_pid = -1;

/*
 * See various Cisco documents, including
 *
 *	http://www.cisco.com/univercd/cc/td/doc/product/lan/trsrb/vlan.htm
 *
 * and
 *
 *	http://www.cisco.com/en/US/products/hw/switches/ps663/products_tech_note09186a0080094713.shtml
 *
 * for various PID values - and for a DRIP frame format.
 */
static const value_string cisco_pid_vals[] = {
	{ 0x0102,	"DRIP" },
	{ 0x0104,	"PAgP" },	/* Port Aggregation Protocol */
	{ 0x0105,	"MLS Hello" },	/* from a mail message found on the Web */
	{ 0x010b,	"PVSTP+" },	/* Per-VLAN Spanning Tree Protocol */
	{ 0x010c,	"VLAN Bridge" },
	{ 0x0111,	"UDLD" },	/* Unidirectional Link Detection */
	{ 0x2000,	"CDP" },
	{ 0x2001,	"CGMP" },
	{ 0x2003,	"VTP" },
	{ 0x2004,	"DTP" },	/* Dynamic Trunking Protocol */
	{ 0x200a,	"STP Uplink Fast" },
	{ 0,		NULL }
};

/*
 * NOTE: there's no dissector here, just registration routines to set
 * up the dissector table for the Cisco OUI.
 */
void
proto_register_cisco_oui(void)
{
	static hf_register_info hf = {
	    &hf_llc_cisco_pid,
		{ "PID",	"llc.cisco_pid",  FT_UINT16, BASE_HEX,
		  VALS(cisco_pid_vals), 0x0, "", HFILL },
	};

	llc_add_oui(OUI_CISCO, "llc.cisco_pid", "Cisco OUI PID", &hf);
}
