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

WS_DLL_PUBLIC void bitswap_buf_inplace(uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* bitswap.h */
