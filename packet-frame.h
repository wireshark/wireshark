/* packet-frame.h
 *
 * Top-most dissector. Decides dissector based on Wiretap Encapsulation Type.
 *
 * $Id: packet-frame.h,v 1.7 2003/12/06 06:09:10 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
    unsigned long exception);

/*
 * Routine used to add an indication of a ReportedBoundsError exception
 * to the tree.
 */
void
show_reported_bounds_error(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/*
 * "Protocol" used for "malformed frame" errors (other than
 * ReportedBoundsError exceptions).
 */
extern int proto_malformed;

extern int proto_frame;
extern int hf_frame_arrival_time;
extern int hf_frame_number;
extern int hf_frame_packet_len;
extern int hf_frame_capture_len;
