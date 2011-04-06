/* oui.h
 * Definitions of OUIs
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 - 2000 Gerald Combs
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

#ifndef __OUI_H__
#define __OUI_H__

/*
 * See
 *
 * http://standards.ieee.org/regauth/oui/oui.txt
 *
 * http://www.cisco.com/univercd/cc/td/doc/product/lan/trsrb/vlan.htm
 *
 * for the PIDs for VTP and DRiP that go with an OUI of OUI_CISCO.
 */

#define OUI_ENCAP_ETHER     0x000000    /* encapsulated Ethernet */
#define OUI_XEROX           0x000006    /* Xerox */
#define OUI_CISCO           0x00000C    /* Cisco (future use) */
#define OUI_IANA            0x00005E    /* the IANA */
#define OUI_NORTEL          0x000081    /* Nortel SONMP */
#define OUI_CISCO_90        0x0000F8    /* Cisco (IOS 9.0 and above?) */
#define OUI_CISCO_2         0x000142    /* Cisco */
#define OUI_CISCO_3         0x000143    /* Cisco */
#define OUI_FORCE10         0x0001E8    /* Force10 */
#define OUI_ERICSSON        0x0001EC    /* Ericsson Group */
#define OUI_CATENA          0x00025A    /* Catena Networks */
#define OUI_ATHEROS         0x00037F    /* Atheros Communications */
#define OUI_SONY_ERICSSON   0x000AD9    /* Sony Ericsson Mobile Communications AB */
#define OUI_SONY_ERICSSON_2 0x000E07    /* Sony Ericsson Mobile Communications AB */
#define OUI_PROFINET        0x000ECF    /* PROFIBUS Nutzerorganisation e.V. */
#define OUI_SONY_ERICSSON_3 0x000FDE    /* Sony Ericsson Mobile Communications AB */
#define OUI_CIMETRICS       0x001090    /* Cimetrics, Inc. */
#define OUI_IEEE_802_3      0x00120F    /* IEEE 802.3 */
#define OUI_MEDIA_ENDPOINT  0x0012BB    /* Media (TIA TR-41 Committee) */
#define OUI_SONY_ERICSSON_4 0x0012EE    /* Sony Ericsson Mobile Communications AB */
#define OUI_ERICSSON_MOBILE 0x0015E0    /* Ericsson Mobile Platforms */
#define OUI_SONY_ERICSSON_5 0x001620    /* Sony Ericsson Mobile Communications AB */
#define OUI_SONY_ERICSSON_6 0x0016B8    /* Sony Ericsson Mobile Communications AB */
#define OUI_SONY_ERICSSON_7 0x001813    /* Sony Ericsson Mobile Communications AB */
#define OUI_SONY_ERICSSON_8 0x001963    /* Sony Ericsson Mobile Communications AB */
#define OUI_TURBOCELL       0x0020F6    /* KarlNet, who brought you Turbocell */
#define OUI_CISCOWL         0x004096    /* Cisco Wireless (Aironet) */
#define OUI_MARVELL         0x005043    /* Marvell Semiconductor */
#define OUI_ERICSSON_2      0x008037    /* Ericsson Group */
#define OUI_BRIDGED         0x0080C2    /* Bridged Frame-Relay, RFC 2427 */
                                        /* and Bridged ATM, RFC 2684 */
#define OUI_IEEE_802_1      0x0080C2    /* IEEE 802.1 Committee */
#define OUI_ATM_FORUM       0x00A03E    /* ATM Forum */
#define OUI_EXTREME         0x00E02B    /* Extreme EDP/ESRP */
#define OUI_CABLE_BPDU      0x00E02F    /* DOCSIS spanning tree BPDU */
#define OUI_SIEMENS         0x080006    /* Siemens AG */
#define OUI_APPLE_ATALK     0x080007    /* Appletalk */
#define OUI_HP              0x080009    /* Hewlett-Packard */
#define OUI_HP_2            0x00805F    /* Hewlett-Packard */
#define OUI_WFA             0x506F9A    /* Wi-Fi Alliance */
#define OUI_3GPP2           0xCF0002    /* 3GPP2 */

/*
 * Defined in packet-llc.c
 */
extern const value_string oui_vals[];

#endif
