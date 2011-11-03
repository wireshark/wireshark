/* crc8.h
 * Declaration of CRC-8 routine and tables
 *
 * 2011 Roland Knall <rknall@gmail.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef __CRC8_H__
#define __CRC8_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** Calculates a CRC8 checksum for the given buffer with the polynom
 *  0x2F using the precompiled CRC table
 * @param buf a pointer to a buffer of the given length
 * @param len the length of the given buffer
 * @param seed The seed to use.
 * @return the CRC8 checksum for the buffer
 */
extern guint8 crc8_0x2F(guint8 *buf, guint32 len, guint8 seed);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* crc8.h */
