/* oui.h
 * Definitions of OUIs
 * Gilbert Ramirez <gramirez@tivoli.com>
 *
 * $Id: oui.h,v 1.2 2000/01/07 22:05:28 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
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

#define	OUI_ENCAP_ETHER	0x000000	/* encapsulated Ethernet */
#define	OUI_ATM_FORUM	0x00A03E	/* ATM Forum */
#define	OUI_APPLE_ATALK	0x080007	/* Appletalk */

extern const value_string oui_vals[];
