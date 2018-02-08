/* crc10-tvb.h
 * Declaration of CRC-10 tvbuff routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
*/

#ifndef __CRC10_TVB_H__
#define __CRC10_TVB_H__

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

WS_DLL_PUBLIC guint16 update_crc10_by_bytes_tvb(guint16 crc10, tvbuff_t *tvb, int offset, int len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* crc10-tvb.h */
