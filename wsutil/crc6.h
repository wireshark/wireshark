/*
 *  crc6.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef __CRC6_H__
#define __CRC6_H__

#include "ws_symbol_export.h"

WS_DLL_PUBLIC guint16 update_crc6_by_bytes(guint16 crc6, guint8 byte1, guint8 byte2);
WS_DLL_PUBLIC guint16 crc6_compute(const guint8 *data_blk_ptr, int data_blk_size);

#endif /* __CRC6_H__ */
