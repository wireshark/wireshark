/** @file
 * Declaration of CRC-10 tvbuff routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Update CRC-10 value based on bytes from a tvbuff.
 *
 * @param crc10 Current CRC-10 value.
 * @param tvb Pointer to the tvbuff containing the data.
 * @param offset Offset within the tvbuff where the data starts.
 * @param len Length of the data in bytes.
 * @return Updated CRC-10 value.
 */
WS_DLL_PUBLIC uint16_t update_crc10_by_bytes_tvb(uint16_t crc10, tvbuff_t *tvb, int offset, int len);

#ifdef __cplusplus
}
#endif /* __cplusplus */
