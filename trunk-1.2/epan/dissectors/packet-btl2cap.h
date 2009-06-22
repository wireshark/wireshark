/* packet-btl2cap.h
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __PACKET_BTL2CAP_H__
#define __PACKET_BTL2CAP_H__

#define BTL2CAP_PSM_SDP		0x0001
#define BTL2CAP_PSM_RFCOMM	0x0003
#define BTL2CAP_PSM_BNEP	0x000f

/* This structure is passed to higher layer protocols through 
 * pinfo->private_data so that they can track "conversations" based on
 * chandle, cid and direction
 */
typedef struct _btl2cap_data_t {
	guint16 chandle;  /* only low 12 bits used */
	guint16 cid;
} btl2cap_data_t;

#endif
