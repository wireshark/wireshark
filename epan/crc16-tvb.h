/* crc16-tvb.h
 * Declaration of CRC-16 tvbuff routines
 *
 * 2004 Richard van der Hoff <richardv@mxtelecom.com>
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

#ifndef __CRC16_TVB_H__
#define __CRC16_TVB_H__

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** Compute CRC16 CCITT checksum of a tv buffer.
 @param tvb The tv buffer containing the data.
 @param len The number of bytes to include in the computation.
 @return The CRC16 CCITT checksum. */
WS_DLL_PUBLIC guint16 crc16_ccitt_tvb(tvbuff_t *tvb, guint len);

/** Compute CRC16 X.25 CCITT checksum of a tv buffer.
 @param tvb The tv buffer containing the data.
 @param len The number of bytes to include in the computation.
 @return The CRC16 X.25 CCITT checksum. */
WS_DLL_PUBLIC guint16 crc16_x25_ccitt_tvb(tvbuff_t *tvb, guint len);

/** Compute CRC16 CCITT checksum of a tv buffer.
 @param tvb The tv buffer containing the data.
 @param offset The offset into the tv buffer.
 @param len The number of bytes to include in the computation.
 @return The CRC16 CCITT checksum. */
WS_DLL_PUBLIC guint16 crc16_ccitt_tvb_offset(tvbuff_t *tvb, guint offset, guint len);

/** Compute CRC16 CCITT checksum of a tv buffer.  If computing the
 *  checksum over multiple tv buffers and you want to feed the partial CRC16
 *  back in, remember to take the 1's complement of the partial CRC16 first.
 @param tvb The tv buffer containing the data.
 @param len The number of bytes to include in the computation.
 @param seed The seed to use.
 @return The CRC16 CCITT checksum (using the given seed). */
WS_DLL_PUBLIC guint16 crc16_ccitt_tvb_seed(tvbuff_t *tvb, guint len, guint16 seed);

/** Compute CRC16 CCITT checksum of a tv buffer.  If computing the
 *  checksum over multiple tv buffers and you want to feed the partial CRC16
 *  back in, remember to take the 1's complement of the partial CRC16 first.
 @param tvb The tv buffer containing the data.
 @param offset The offset into the tv buffer.
 @param len The number of bytes to include in the computation.
 @param seed The seed to use.
 @return The CRC16 CCITT checksum (using the given seed). */
WS_DLL_PUBLIC guint16 crc16_ccitt_tvb_offset_seed(tvbuff_t *tvb, guint offset,
                                           guint len, guint16 seed);

/** Compute the "plain" CRC16 checksum of a tv buffer using the following
 * parameters:
 *    Width        = 16
 *    Poly         = 0x8005
 *    XorIn        = 0x0000
 *    ReflectIn    = True
 *    XorOut       = 0x0000
 *    ReflectOut   = True
 *    Algorithm    = table-driven
 *    Direct       = True
 @param tvb The tv buffer containing the data.
 @param offset The offset into the tv buffer.
 @param len The number of bytes to include in the computation.
 @return The CRC16 checksum. */
WS_DLL_PUBLIC guint16 crc16_plain_tvb_offset(tvbuff_t *tvb, guint offset, guint len);

/** Compute the "plain" CRC16 checksum of a tv buffer using the following
 * parameters:
 *    Width        = 16
 *    Poly         = 0x8005
 *    XorIn        = 0x0000
 *    ReflectIn    = True
 *    XorOut       = 0x0000
 *    ReflectOut   = True
 *    Algorithm    = table-driven
 *    Direct       = True
 @param tvb The tv buffer containing the data.
 @param offset The offset into the tv buffer.
 @param len The number of bytes to include in the computation.
 @param crc Starting CRC value
 @return The CRC16 checksum. */
WS_DLL_PUBLIC guint16 crc16_plain_tvb_offset_seed(tvbuff_t *tvb, guint offset, guint len, guint16 crc);

/** Compute CRC16 checksum of a tv buffer using the parameters
 *    Width        = 16 bits
 *    Poly         = 0x9949
 *    Reflection   = true
 *    Algorithm    = table-driven
 @param tvb The tv buffer containing the data.
 @param offset The offset into the tv buffer.
 @param len The number of bytes to include in the computation.
 @param seed The seed to use.
 @return The CRC16 checksum. */
WS_DLL_PUBLIC guint16 crc16_0x9949_tvb_offset_seed(tvbuff_t *tvb, guint offset, guint len, guint16 seed);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* crc16-tvb.h */
