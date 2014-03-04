/* conv_id.h
 * conv_id   2011 Robert Bullen
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

#ifndef __CONV_ID_H__
#define __CONV_ID_H__

/** conv_id_t is a type that can aid in conversation identification. When
 *  included in a "conversation key", whatever that may be, in addition to the
 *  typical { address, port, address, port } quadruple, it helps differentiate
 *  in case the quadruple is not sufficiently unique. For example, it is not
 *  uncommon to see a TCP quadruple reused these days, and employing a
 *  conv_id_t field ensures that each instance of a reused TCP conversation is
 *  tracked independently. Currently this type is used in both Wireshark's and
 *  tshark's conversation tables implementations (they are different, hence
 *  the need for a whole header file for this one silly type alias).
 *
 *  The "protocol" or "statistic" code responsible for instantiating the
 *  "conversation key" is also responsible for assigning its conv_id_t, and
 *  therefore its interpretation is specific to its assignor. For example, the
 *  TCP conversations tables in Wireshark and tshark assign the value of
 *  tcp.stream. If a conv_id_t field is not used, it should be assigned the
 *  value CONV_ID_UNSET.
 */
typedef guint32 conv_id_t;
#define CONV_ID_UNSET G_MAXUINT32

#endif /* __CONV_ID_H__ */
