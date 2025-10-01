/** @file
 * Declaration of CRC-8 routine and tables
 *
 * 2011 Roland Knall <rknall@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __CRC8_H__
#define __CRC8_H__

#include <wireshark.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @brief Calculates a CRC8 checksum for the given buffer with the polynomial
 *  0x2F using the precompiled CRC table
 *
 * @param buf a pointer to a buffer of the given length
 * @param len the length of the given buffer
 * @param seed The seed to use.
 * @return the CRC8 checksum for the buffer
 */
WS_DLL_PUBLIC uint8_t crc8_0x2F(const uint8_t *buf, uint32_t len, uint8_t seed);

/** @brief Calculates a CRC8 checksum for the given buffer with the polynomial
 *  0x37 using the precompiled CRC table
 *
 * @param buf a pointer to a buffer of the given length
 * @param len the length of the given buffer
 * @param seed The seed to use.
 * @return the CRC8 checksum for the buffer
 */
WS_DLL_PUBLIC uint8_t crc8_0x37(const uint8_t *buf, uint32_t len, uint8_t seed);

/** @brief Calculates a CRC8 checksum for the given buffer with the polynomial
 *  0x3B using the precompiled CRC table
 *
 * @param buf a pointer to a buffer of the given length
 * @param len the length of the given buffer
 * @param seed The seed to use.
 * @return the CRC8 checksum for the buffer
 */
WS_DLL_PUBLIC uint8_t crc8_0x3B(const uint8_t *buf, uint32_t len, uint8_t seed);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* crc8.h */
