/* packet-tpkt.h
 *
 * Routines for TPKT dissection
 *
 * Copyright 2000, Philips Electronics N.V.
 * Andreas Sikkema <andreas.sikkema@philips.com>
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

/*
 * Check whether this could be a TPKT-encapsulated PDU.
 */
gboolean is_tpkt( tvbuff_t *tvb, unsigned int* offset );


/*
 * Dissect the TPKT header; called from the TPKT dissector, as well as
 * from dissectors such as the dissector for Q.931-over-TCP.
 *
 * Returns -1 if TPKT isn't enabled, otherwise returns the PDU length
 * from the TPKT header.
 *
 * Sets "*offset" to the offset following the TPKT header.
 */
int dissect_tpkt_header( tvbuff_t *tvb, unsigned int* offset,
    packet_info *pinfo, proto_tree *tree );
