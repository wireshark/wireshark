/*
 *  crc6.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef __CRC6_H__
#define __CRC6_H__

#include "ws_symbol_export.h"

WS_DLL_PUBLIC guint16 update_crc6_by_bytes(guint16 crc6, guint8 byte1, guint8 byte2);
WS_DLL_PUBLIC guint16 crc6_compute(const guint8 *data_blk_ptr, int data_blk_size);

#endif /* __CRC6_H__ */
