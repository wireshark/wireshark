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

/** Compute the 5-bit CRC value of a input value matching the CRC-5
 defined in USB 2.0 Specification. This function calculates the CRC
 on low 11 bits of the input value. High bits are ignored.
 @param input Source data for which the CRC-5 should be calculated.
 @return the CRC5 checksum for input value */
WS_DLL_PUBLIC uint8_t crc5_usb_11bit_input(uint16_t input);

/** Compute the 5-bit CRC value of a input value matching the CRC-5
 defined in USB 2.0 Specification. This function calculates the CRC
 on low 19 bits of the input value. High bits are ignored.
 @param input Source data for which the CRC-5 should be calculated.
 @return the CRC5 checksum for input value */
WS_DLL_PUBLIC uint8_t crc5_usb_19bit_input(uint32_t input);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CRC5_H__ */
