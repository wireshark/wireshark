/** @file
 * Declaration of CRC-5 routines and table
 *
 * 2019 Tomasz Mon <desowin@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
*/

#ifndef __CRC5_H__
#define __CRC5_H__

#include <wireshark.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Compute the 5-bit CRC value for a USB token using the CRC-5 polynomial.
 *
 * Implements the CRC-5 checksum algorithm as defined in the USB 2.0 Specification.
 * The calculation is performed on the lower 11 bits of the input value; any higher
 * bits are ignored. This function is typically used to validate USB token packets.
 *
 * @param input 11-bit input value (lower 11 bits of `input` are used).
 * @return      5-bit CRC checksum.
 */
WS_DLL_PUBLIC uint8_t crc5_usb_11bit_input(uint16_t input);

/**
 * @brief Compute the 5-bit CRC value for a USB token using the CRC-5 polynomial.
 *
 * Implements the CRC-5 checksum algorithm as defined in the USB 2.0 Specification.
 * The calculation is performed on the lower 19 bits of the input value; any higher
 * bits are ignored. This function is typically used to validate USB handshake packets
 * or other protocol elements that utilize extended bit-width tokens.
 *
 * @param input 19-bit input value (lower 19 bits of `input` are used).
 * @return      5-bit CRC checksum.
 */
WS_DLL_PUBLIC uint8_t crc5_usb_19bit_input(uint32_t input);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CRC5_H__ */
