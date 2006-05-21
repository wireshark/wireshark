/* packet-frame.h
 *
 * Top-most dissector. Decides dissector based on Wiretap Encapsulation Type.
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000 Gerald Combs
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
 * Routine used to add an indication of an arbitrary exception to the tree.
 */
void show_exception(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    unsigned long exception, const char *exception_message);

/*
 * Routine used to add an indication of a ReportedBoundsError exception
 * to the tree.
 */
void
show_reported_bounds_error(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* 
 * Routine used to register frame end routine.  The routine should only
 * be registred when the dissector is used in the frame, not in the
 * proto_register_XXX function.
 */
void
register_frame_end_routine(void (*func)(void));

/*
 * "Protocol" used for "malformed frame" errors (other than
 * ReportedBoundsError exceptions).
 */
extern int proto_malformed;

/* following variables are exported from libwireshark.dll. 
 * Thus we need a special declaration. 
 */
ETH_VAR_IMPORT int proto_frame;
ETH_VAR_IMPORT int hf_frame_arrival_time;
ETH_VAR_IMPORT int hf_frame_number;
ETH_VAR_IMPORT int hf_frame_packet_len;
ETH_VAR_IMPORT int hf_frame_capture_len;
