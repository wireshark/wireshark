/** @file
 * Macro to bitswap a byte by looking it up in a table
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __BITSWAP_H__
#define __BITSWAP_H__

#include <wireshark.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Reverse the bit order of each byte in a buffer, in-place.
 *
 * Performs a bitwise reversal on every byte in the given buffer, modifying
 * the contents directly. For example, a byte `0b00000101` becomes `0b10100000`.
 *
 * @param buf Pointer to the buffer to modify.
 * @param len Number of bytes in the buffer.
 */
WS_DLL_PUBLIC void bitswap_buf_inplace(uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* bitswap.h */
