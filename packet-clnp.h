/* packet-clnp.h
 * Defines and such for CLNP (and COTP) protocol decode.
 *
 * $Id: packet-clnp.h,v 1.2 2000/04/17 01:36:30 guy Exp $
 * Ralf Schneider <Ralf.Schneider@t-online.de>
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
 *
 *
 */

#ifndef _PACKET_CLNP_H
#define _PACKET_CLNP_H

/*
 * published API functions
 */

extern
void dissect_cotp(const u_char *, int, frame_data *, proto_tree *);

#endif /* _PACKET_CLNP_H */
