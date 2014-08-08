/* crc32-tvb.h
 * Declaration of CRC-32 tvbuff routines
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

#ifndef __CRC32_TVB_H__
#define __CRC32_TVB_H__

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** Compute CRC32 CCITT checksum of a tv buffer.
 @param tvb The tv buffer containing the data.
 @param len The number of bytes to include in the computation.
 @return The CRC32 CCITT checksum. */
WS_DLL_PUBLIC guint32 crc32_ccitt_tvb(tvbuff_t *tvb, guint len);

/** Compute CRC32 CCITT checksum of a tv buffer.
 @param tvb The tv buffer containing the data.
 @param offset The offset into the tv buffer.
 @param len The number of bytes to include in the computation.
 @return The CRC32 CCITT checksum. */
WS_DLL_PUBLIC guint32 crc32_ccitt_tvb_offset(tvbuff_t *tvb, guint offset, guint len);

/** Compute CRC32 CCITT checksum of a tv buffer.  If computing the
 *  checksum over multiple tv buffers and you want to feed the partial CRC32
 *  back in, remember to take the 1's complement of the partial CRC32 first.
 @param tvb The tv buffer containing the data.
 @param len The number of bytes to include in the computation.
 @param seed The seed to use.
 @return The CRC32 CCITT checksum (using the given seed). */
WS_DLL_PUBLIC guint32 crc32_ccitt_tvb_seed(tvbuff_t *tvb, guint len, guint32 seed);

/** Compute CRC32C checksum of a tv buffer.  If computing the
 *  checksum over multiple tv buffers and you want to feed the partial CRC32
 *  back in, remember to take the 1's complement of the partial CRC32 first.
 @param tvb The tv buffer containing the data.
 @param offset The offset into the tv buffer.
 @param len The number of bytes to include in the computation.
 @param seed The seed to use.
 @return The CRC32C checksum (using the given seed). */
WS_DLL_PUBLIC guint32 crc32c_tvb_offset_calculate(tvbuff_t *tvb, guint offset,
                                           guint len, guint32 seed);

/** Compute CRC32 CCITT checksum of a tv buffer.  If computing the
 *  checksum over multiple tv buffers and you want to feed the partial CRC32
 *  back in, remember to take the 1's complement of the partial CRC32 first.
 @param tvb The tv buffer containing the data.
 @param offset The offset into the tv buffer.
 @param len The number of bytes to include in the computation.
 @param seed The seed to use.
 @return The CRC32 CCITT checksum (using the given seed). */
WS_DLL_PUBLIC guint32 crc32_ccitt_tvb_offset_seed(tvbuff_t *tvb, guint offset,
                                           guint len, guint32 seed);

/** Compute IEEE 802.x CRC32 checksum of a tv buffer.
 @param tvb The tv buffer containing the data.
 @param len The number of bytes to include in the computation.
 @return The IEEE 802.x CRC32 checksum. */
WS_DLL_PUBLIC guint32 crc32_802_tvb(tvbuff_t *tvb, guint len);


/** Compute MPEG-2 CRC32 checksum of a tv buffer.
 @param tvb The tv buffer containing the data.
 @param len The number of bytes to include in the computation.
 @return The MPEG-2 CRC32 checksum. */
WS_DLL_PUBLIC guint32 crc32_mpeg2_tvb(tvbuff_t *tvb, guint len);

/** Compute MPEG-2 CRC32 checksum of a tv buffer.
 @param tvb The tv buffer containing the data.
 @param offset The offset into the tv buffer.
 @param len The number of bytes to include in the computation.
 @return The MPEG-2 CRC32 checksum. */
WS_DLL_PUBLIC guint32 crc32_mpeg2_tvb_offset(tvbuff_t *tvb, guint offset, guint len);

/** Compute MPEG-2 CRC32 checksum of a buffer of data.
 @param tvb The tv buffer containing the data.
 @param len The number of bytes to include in the computation.
 @param seed The seed to use.
 @return The CRC32 MPEG-2 checksum (using the given seed). */
WS_DLL_PUBLIC guint32 crc32_mpeg2_tvb_seed(tvbuff_t *tvb, guint len, guint32 seed);

/** Compute MPEG-2 CRC32 checksum of a buffer of data.
 @param tvb The tv buffer containing the data.
 @param offset The offset into the tv buffer.
 @param len The number of bytes to include in the computation.
 @param seed The seed to use.
 @return The CRC32 MPEG-2 checksum (using the given seed). */
WS_DLL_PUBLIC guint32 crc32_mpeg2_tvb_offset_seed(tvbuff_t *tvb, guint offset,
                                           guint len, guint32 seed);

/** Compute CRC32 checksum of a tv buffer using the parameters
 *    Width        = 32 bits
 *    Poly         = 0x0AA725CF
 *    Reflection   = true
 *    Algorithm    = table-driven
 @param tvb The tv buffer containing the data.
 @param offset The offset into the tv buffer.
 @param len The number of bytes to include in the computation.
 @param seed The seed to use.
 @return The CRC32 checksum. */
WS_DLL_PUBLIC guint32 crc32_0x0AA725CF_tvb_offset_seed(tvbuff_t *tvb,
                                            guint offset, guint len, guint32 seed);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* crc32-tvb.h */
