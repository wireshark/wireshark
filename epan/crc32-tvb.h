/** @file
 * Declaration of CRC-32 tvbuff routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
WS_DLL_PUBLIC uint32_t crc32_ccitt_tvb(tvbuff_t *tvb, unsigned len);

/** Compute CRC32 CCITT checksum of a tv buffer.
 @param tvb The tv buffer containing the data.
 @param offset The offset into the tv buffer.
 @param len The number of bytes to include in the computation.
 @return The CRC32 CCITT checksum. */
WS_DLL_PUBLIC uint32_t crc32_ccitt_tvb_offset(tvbuff_t *tvb, unsigned offset, unsigned len);

/** Compute CRC32 CCITT checksum of a tv buffer.  If computing the
 *  checksum over multiple tv buffers and you want to feed the partial CRC32
 *  back in, remember to take the 1's complement of the partial CRC32 first.
 @param tvb The tv buffer containing the data.
 @param len The number of bytes to include in the computation.
 @param seed The seed to use.
 @return The CRC32 CCITT checksum (using the given seed). */
WS_DLL_PUBLIC uint32_t crc32_ccitt_tvb_seed(tvbuff_t *tvb, unsigned len, uint32_t seed);

/** Compute CRC32C checksum of a tv buffer.  If computing the
 *  checksum over multiple tv buffers and you want to feed the partial CRC32
 *  back in, remember to take the 1's complement of the partial CRC32 first.
 @param tvb The tv buffer containing the data.
 @param offset The offset into the tv buffer.
 @param len The number of bytes to include in the computation.
 @param seed The seed to use.
 @return The CRC32C checksum (using the given seed). */
WS_DLL_PUBLIC uint32_t crc32c_tvb_offset_calculate(tvbuff_t *tvb, unsigned offset,
                                           unsigned len, uint32_t seed);

/** Compute CRC32 CCITT checksum of a tv buffer.  If computing the
 *  checksum over multiple tv buffers and you want to feed the partial CRC32
 *  back in, remember to take the 1's complement of the partial CRC32 first.
 @param tvb The tv buffer containing the data.
 @param offset The offset into the tv buffer.
 @param len The number of bytes to include in the computation.
 @param seed The seed to use.
 @return The CRC32 CCITT checksum (using the given seed). */
WS_DLL_PUBLIC uint32_t crc32_ccitt_tvb_offset_seed(tvbuff_t *tvb, unsigned offset,
                                           unsigned len, uint32_t seed);

/** Compute IEEE 802.x CRC32 checksum of a tv buffer.
 @param tvb The tv buffer containing the data.
 @param len The number of bytes to include in the computation.
 @return The IEEE 802.x CRC32 checksum. */
WS_DLL_PUBLIC uint32_t crc32_802_tvb(tvbuff_t *tvb, unsigned len);


/** Compute MPEG-2 CRC32 checksum of a tv buffer.
 @param tvb The tv buffer containing the data.
 @param len The number of bytes to include in the computation.
 @return The MPEG-2 CRC32 checksum. */
WS_DLL_PUBLIC uint32_t crc32_mpeg2_tvb(tvbuff_t *tvb, unsigned len);

/** Compute MPEG-2 CRC32 checksum of a tv buffer.
 @param tvb The tv buffer containing the data.
 @param offset The offset into the tv buffer.
 @param len The number of bytes to include in the computation.
 @return The MPEG-2 CRC32 checksum. */
WS_DLL_PUBLIC uint32_t crc32_mpeg2_tvb_offset(tvbuff_t *tvb, unsigned offset, unsigned len);

/** Compute MPEG-2 CRC32 checksum of a buffer of data.
 @param tvb The tv buffer containing the data.
 @param len The number of bytes to include in the computation.
 @param seed The seed to use.
 @return The CRC32 MPEG-2 checksum (using the given seed). */
WS_DLL_PUBLIC uint32_t crc32_mpeg2_tvb_seed(tvbuff_t *tvb, unsigned len, uint32_t seed);

/** Compute MPEG-2 CRC32 checksum of a buffer of data.
 @param tvb The tv buffer containing the data.
 @param offset The offset into the tv buffer.
 @param len The number of bytes to include in the computation.
 @param seed The seed to use.
 @return The CRC32 MPEG-2 checksum (using the given seed). */
WS_DLL_PUBLIC uint32_t crc32_mpeg2_tvb_offset_seed(tvbuff_t *tvb, unsigned offset,
                                           unsigned len, uint32_t seed);

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
WS_DLL_PUBLIC uint32_t crc32_0x0AA725CF_tvb_offset_seed(tvbuff_t *tvb,
                                            unsigned offset, unsigned len, uint32_t seed);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* crc32-tvb.h */
