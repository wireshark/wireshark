/* crc8.h
 * Declaration of CRC-8 routine and tables
 *
 * 2011 Roland Knall <rknall@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __CRC8_H__
#define __CRC8_H__


#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** Calculates a CRC8 checksum for the given buffer with the polynom
 *  0x2F using the precompiled CRC table
 * @param buf a pointer to a buffer of the given length
 * @param len the length of the given buffer
 * @param seed The seed to use.
 * @return the CRC8 checksum for the buffer
 */
WS_DLL_PUBLIC guint8 crc8_0x2F(const guint8 *buf, guint32 len, guint8 seed);

/** Calculates a CRC8 checksum for the given buffer with the polynom
 *  0x37 using the precompiled CRC table
 * @param buf a pointer to a buffer of the given length
 * @param len the length of the given buffer
 * @param seed The seed to use.
 * @return the CRC8 checksum for the buffer
 */
WS_DLL_PUBLIC guint8 crc8_0x37(const guint8 *buf, guint32 len, guint8 seed);

/** Calculates a CRC8 checksum for the given buffer with the polynom
 *  0x3B using the precompiled CRC table
 * @param buf a pointer to a buffer of the given length
 * @param len the length of the given buffer
 * @param seed The seed to use.
 * @return the CRC8 checksum for the buffer
 */
WS_DLL_PUBLIC guint8 crc8_0x3B(const guint8 *buf, guint32 len, guint8 seed);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* crc8.h */
