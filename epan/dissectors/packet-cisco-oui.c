/* packet-cisco-oui.c
 * Register an LLC dissector table for Cisco's OUI 00:00:0c
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
#include <epan/cisco_pid.h>

void proto_register_cisco_pid(void);

static int hf_llc_cisco_pid;

/*
 * See various Cisco documents, including
 *
 *	http://docstore.mik.ua/univercd/cc/td/doc/product/lan/trsrb/vlan.htm
 *
 *	http://docstore.mik.ua/univercd/cc/td/doc/product/lan/trsrb/frames.htm
 *
 *	http://web.archive.org/web/20110407152854/http://www.cisco.com/en/US/products/hw/switches/ps663/products_tech_note09186a0080094713.shtml
 *
 * for various PID values - and for a DRIP frame format.
 */
static const value_string cisco_pid_vals[] = {
	{ CISCO_PID_DRIP,		"DRIP" },
	{ CISCO_PID_PAGP,		"PAgP" },       /* Port Aggregation Protocol */
	{ CISCO_PID_MLS_HELLO,		"MLS Hello" },  /* from a mail message found on the Web */
	{ CISCO_PID_RLQ_REQ,		"RLQ BPDUs (request)" }, /* Root Link Query, see Bug: 12772 */
	{ CISCO_PID_RLQ_RESP,		"RLQ BPDUs (response)" }, /* Root Link Query, see Bug: 12772 */
	{ CISCO_PID_PVSTPP,		"PVSTP+" },     /* Per-VLAN Spanning Tree Protocol */
	{ CISCO_PID_VLAN_BRIDGE,	"VLAN Bridge" },
	{ CISCO_PID_UDLD,		"UDLD" },       /* Unidirectional Link Detection */
	{ CISCO_PID_MCP,		"MCP" },        /* MisCabling Protocol */
	{ CISCO_PID_CDP,		"CDP" },
	{ CISCO_PID_CGMP,		"CGMP" },
	{ CISCO_PID_VTP,		"VTP" },
	{ CISCO_PID_DTP,		"DTP" },        /* Dynamic Trunking Protocol */
	{ CISCO_PID_STP_UL_FAST,	"STP Uplink Fast" },

	{ 0,    NULL }
};

/*
 * NOTE: there's no dissector here, just registration routines to set
 * up the dissector table for the Cisco OUI.
 */
void
proto_register_cisco_pid(void)
{
	static hf_register_info hf[] = {
	  { &hf_llc_cisco_pid,
		{ "PID",	"llc.cisco_pid",  FT_UINT16, BASE_HEX,
		  VALS(cisco_pid_vals), 0x0, "Protocol ID", HFILL }
	  }
	};

	llc_add_oui(OUI_CISCO, "llc.cisco_pid", "LLC Cisco OUI PID", hf, -1);
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
