/* packet-rtp.h
 *
 * Routines for RTP dissection
 * RTP = Real time Transport Protocol
 *
 * $Id: packet-rtp.h,v 1.5 2001/09/03 10:33:06 guy Exp $
 * 
 * Copyright 2000, Philips Electronics N.V.
 * Written by Andreas Sikkema <andreas.sikkema@philips.com>
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

void     rtp_add_address   ( packet_info *pinfo, const unsigned char* ip_addr, int prt );
gboolean dissect_rtp_heur  ( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree );
void     dissect_rtp       ( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree );
void     proto_register_rtp( void );
