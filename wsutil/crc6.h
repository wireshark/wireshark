/*
 *  crc6.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __CRC6_H__
#define __CRC6_H__

#include "ws_symbol_export.h"

WS_DLL_PUBLIC guint16 crc6_0X6F(guint16 crc6, const guint8 *data_blk_ptr, int data_blk_size);

#endif /* __CRC6_H__ */
