/* oui.h
 * Definitions of OUIs
 * Gilbert Ramirez <gram@xiexie.org>
 *
 * $Id: oui.h,v 1.7 2000/08/11 13:34:18 deniel Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 - 2000 Gerald Combs
 *
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

#define	OUI_ENCAP_ETHER	0x000000	/* encapsulated Ethernet */
#define	OUI_CISCO	0x00000C	/* Cisco (future use) */
#define	OUI_CISCO_90	0x0000F8	/* Cisco (IOS 9.0 and above?) */
#define OUI_BFR		0x0080C2	/* Bridged Frame-Relay, RFC 2427 */
#define	OUI_ATM_FORUM	0x00A03E	/* ATM Forum */
#define	OUI_APPLE_ATALK	0x080007	/* Appletalk */
#define OUI_CABLE_BPDU	0x00E02F	/* DOCSIS spanning tree BPDU */

extern const value_string oui_vals[];

#endif
