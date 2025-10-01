/** @file
 * Declaration of CRC-16 routines and table
 *
 * 2004 Richard van der Hoff <richardv@mxtelecom.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
*/

#ifndef __CRC16_H__
#define __CRC16_H__

#include <wireshark.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Calculate the CCITT/ITU/CRC-16 16-bit CRC

   (parameters for this CRC are:
       Polynomial: x^16 + x^12 + x^5 + 1  (0x1021);
       Start value 0xFFFF;
       XOR result with 0xFFFF;
       First bit is LSB)
*/

/**
 @brief Compute CRC16 CCITT checksum of a buffer of data.
 @param buf The buffer containing the data.
 @param len The number of bytes to include in the computation.
 @return The CRC16 CCITT checksum. */
WS_DLL_PUBLIC uint16_t crc16_ccitt(const uint8_t *buf, unsigned len);

/**
 @brief Compute CRC16 X.25 CCITT checksum of a buffer of data.
 @param buf The buffer containing the data.
 @param len The number of bytes to include in the computation.
 @return The CRC16 X.25 CCITT checksum. */
WS_DLL_PUBLIC uint16_t crc16_x25_ccitt_seed(const uint8_t *buf, unsigned len, uint16_t seed);

/**
 * @brief Compute CRC16 CCITT checksum of a buffer of data.
 *
 * If computing the
 *  checksum over multiple buffers and you want to feed the partial CRC16
 *  back in, remember to take the 1's complement of the partial CRC16 first.
 @param buf The buffer containing the data.
 @param len The number of bytes to include in the computation.
 @param seed The seed to use.
 @return The CRC16 CCITT checksum (using the given seed). */
WS_DLL_PUBLIC uint16_t crc16_ccitt_seed(const uint8_t *buf, unsigned len, uint16_t seed);

/**
 @brief Compute the 16bit CRC_A value of a buffer as defined in ISO14443-3.
 @param buf The buffer containing the data.
 @param len The number of bytes to include in the computation.
 @return the CRC16 checksum for the buffer */
WS_DLL_PUBLIC uint16_t crc16_iso14443a(const uint8_t *buf, unsigned len);

/**
 @brief Compute the 16bit CRC value of a buffer as defined in USB Specification.
 @param buf The buffer containing the data.
 @param len The number of bytes to include in the computation.
 @return the CRC16 checksum for the buffer */
WS_DLL_PUBLIC uint16_t crc16_usb(const uint8_t *buf, unsigned len);

/**
 * @brief Calculates a CRC16 checksum for the given buffer with the polynomial
 *  0x5935 using a precompiled CRC table.
 * @param buf a pointer to a buffer of the given length
 * @param len the length of the given buffer
 * @param seed The seed to use.
 * @return the CRC16 checksum for the buffer
 */
WS_DLL_PUBLIC uint16_t crc16_0x5935(const uint8_t *buf, uint32_t len, uint16_t seed);

/**
 * @brief Calculates a CRC16 checksum for the given buffer with the polynom
 *  0x755B using a precompiled CRC table
 * @param buf a pointer to a buffer of the given length
 * @param len the length of the given buffer
 * @param seed The seed to use.
 * @return the CRC16 checksum for the buffer
 */
WS_DLL_PUBLIC uint16_t crc16_0x755B(const uint8_t *buf, uint32_t len, uint16_t seed);

/**
 * @brief Computes CRC16 checksum for the given data with the polynom 0x9949 using
 *  precompiled CRC table
 * @param buf a pointer to a buffer of the given length
 * @param len the length of the given buffer
 * @param seed The seed to use.
 * @return the CRC16 checksum for the buffer
 */
WS_DLL_PUBLIC uint16_t crc16_0x9949_seed(const uint8_t *buf, unsigned len, uint16_t seed);

/**
 * @brief Computes CRC16 checksum for the given data with the polynom 0x3D65 using
 *  precompiled CRC table
 * @param buf a pointer to a buffer of the given length
 * @param len the length of the given buffer
 * @param seed The seed to use.
 * @return the CRC16 checksum for the buffer
 */
WS_DLL_PUBLIC uint16_t crc16_0x3D65_seed(const uint8_t *buf, unsigned len, uint16_t seed);

/**
 * @brief Computes CRC16 checksum for the given data with the polynom 0x080F using
 *  precompiled CRC table
 * @param buf a pointer to a buffer of the given length
 * @param len the length of the given buffer
 * @param seed The seed to use.
 * @return the CRC16 checksum for the buffer
 */
WS_DLL_PUBLIC uint16_t crc16_0x080F_seed(const uint8_t *buf, unsigned len, uint16_t seed);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* crc16.h */
