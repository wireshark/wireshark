/* follow_udp.h
 * UDP specific routines for following traffic streams
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
 * Foundation,  Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __FOLLOW_UDP_H__
#define __FOLLOW_UDP_H__

/* Follow the UDP stream, if any, to which the last packet that we called
   a dissection routine on belongs (this might be the most recently
   selected packet, or it might be the last packet in the file). */
void follow_udp_stream_cb(GtkWidget * w, gpointer data _U_);

#endif /* __FOLLOW_UDP_H__ */

