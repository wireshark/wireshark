/* packet-tn3270.h
 * Headers for tn3270.packet dissection
 *
 * Reference:
 * 3270 Information Display System: Data Stream Programmer's Reference
 *  GA23-0059-07
 *
 * Copyright 2009, Robert Hogan <robert@roberthogan.net>
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

#ifndef TN3270_H_INCLUDED
#define TN3270_H_INCLUDED

void add_tn3270_conversation(packet_info *pinfo, int tn3270e, int model);
int find_tn3270_conversation(packet_info *pinfo);

#endif
