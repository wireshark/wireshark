/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __CRC6_H__
#define __CRC6_H__

#include <wireshark.h>

WS_DLL_PUBLIC uint16_t crc6_0X6F(uint16_t crc6, const uint8_t *data_blk_ptr, int data_blk_size);

#endif /* __CRC6_H__ */
