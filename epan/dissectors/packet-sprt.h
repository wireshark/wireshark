/* packet-sprt.h
 *
 * Routines for SPRT dissection
 * SPRT = Simple Packet Relay Transport
 *
 * Written by Jamison Adcock <jamison.adcock@cobham.com>
 * for Sparta Inc., dba Cobham Analytic Solutions
 * This code is largely based on the RTP parsing code
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _PACKET_SPRT_H
#define _PACKET_SPRT_H

void sprt_add_address(packet_info *pinfo,
                      address *addr,
                      int port,
                      int other_port,
                      const gchar *setup_method,
                      guint32 setup_frame_number);



#endif /* _PACKET_SPRT_H */
