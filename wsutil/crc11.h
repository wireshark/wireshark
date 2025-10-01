/** @file
 * http://www.tty1.net/pycrc/faq_en.html#code-ownership
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __CRC11_____H__

#include <stdint.h>

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif
/**
 * Functions and types for CRC checks.
 *
 * Generated on Tue Aug  7 15:45:57 2012,
 * by pycrc v0.7.10, http://www.tty1.net/pycrc/
 * using the configuration:
 *    Width        = 11
 *    Poly         = 0x307
 *    XorIn        = 0x000
 *    ReflectIn    = False
 *    XorOut       = 0x000
 *    ReflectOut   = False
 *    Algorithm    = table-driven
 *****************************************************************************/

/**
 * @brief Compute the CRC-11/UMTS checksum using polynomial 0x307 with no reflection or final XOR.
 *
 * This function calculates the 11-bit CRC value over the input byte stream
 * using the CRC-11 polynomial defined by ITU-T (0x307). It does not apply
 * input or output reflection, nor does it perform a final XOR. This variant
 * is commonly used in UMTS and other telecom protocols.
 *
 * Polynomial: x^11 + x^9 + x^8 + x^2 + 1 (0x307)
 * Initial value: 0x000
 * No input/output reflection
 * No final XOR
 *
 * @param data      Pointer to the input byte stream.
 * @param data_len  Length of the input data in bytes.
 * @return          11-bit CRC checksum.
 */
WS_DLL_PUBLIC
uint16_t crc11_307_noreflect_noxor(const uint8_t *data, uint64_t data_len);

#ifdef __cplusplus
}           /* closing brace for extern "C" */
#endif

#endif /*__CRC11_____H__*/
