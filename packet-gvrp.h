/* packet-gvrp.h
 * Declarations of routines for GVRP (GARP VLAN Registration Protocol)
 * dissection
 * Copyright 2000, Kevin Shi <techishi@ms22.hinet.net>
 *
 * $Id: packet-gvrp.h,v 1.1 2000/11/30 09:31:50 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef __PACKET_GVRP_H__
#define __PACKET_GVRP_H__

void dissect_gvrp(tvbuff_t *, packet_info *, proto_tree *);

#endif /* packet-gvrp.h */

