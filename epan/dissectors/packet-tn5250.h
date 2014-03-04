/* packet-tn5250.h
 * Headers for tn5250.packet dissection
 *
 * Reference:
 *  5494 Remote Control Unit - Functions Reference
 *  Release 3.0 Document Number SC30-3533-04
 *  Chapters 12, 15, 16
 *
 * Copyright 2009, Robert Hogan <robert@roberthogan.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#ifndef TN5250_H_INCLUDED
#define TN5250_H_INCLUDED

void add_tn5250_conversation(packet_info *pinfo _U_, int tn5250e);
int find_tn5250_conversation(packet_info *pinfo _U_);
#endif
