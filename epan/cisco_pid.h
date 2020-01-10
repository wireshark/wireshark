/* packet-cisco-oui.h
 * Register an LLC dissector table for Cisco's OUI 00:00:0c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_CISCO_PID_H__
#define __PACKET_CISCO_PID_H__

#define CISCO_PID_DRIP		0x0102
#define CISCO_PID_PAGP		0x0104
#define CISCO_PID_MLS_HELLO	0x0105
#define CISCO_PID_RLQ_REQ	0x0108
#define CISCO_PID_RLQ_RESP	0x0109
#define CISCO_PID_PVSTPP	0x010B
#define CISCO_PID_VLAN_BRIDGE	0x010C
#define CISCO_PID_UDLD		0x0111
#define CISCO_PID_MCP		0x0139
#define CISCO_PID_CDP		0x2000
#define CISCO_PID_CGMP		0x2001
#define CISCO_PID_VTP		0x2003
#define CISCO_PID_DTP		0x2004
#define CISCO_PID_STP_UL_FAST	0x200A

#endif

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
