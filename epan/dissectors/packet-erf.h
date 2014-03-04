/* packet-erf.h
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

#ifndef __PACKET_ERF_H__
#define __PACKET_ERF_H__

/** Gets the ERF extension header of the specified type,
 *
 * Afterindex may be NULL, or set to a gint initialized to -1 and the function
 * re-called in a loop to iterate through extension headers of hdrtype type.
 *
 * Note: pinfo is assumed to be a pointer to an ERF pinfo.
 *
 * @param pinfo Packet info of ERF record to get extension header of.
 * @param hdrtype Type code of extension header. More headers bit is ignored.
 * @param afterinstance Pointer to header index to begin searching at,
 * exclusive.
 * Updated with index of extension header found. If NULL or initialized to -1
 * begin searching at the first extension header.
 *
 * @returns Pointer to extension header or NULL.
 * */
guint64* erf_get_ehdr(packet_info *pinfo, guint8 hdrtype, gint* afterinstance);
#endif /* packet-erf.h */
