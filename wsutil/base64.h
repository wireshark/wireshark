/* base64.h
 * Base-64 conversion
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __BASE64_H__
#define __BASE64_H__

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* In-place decoding of a base64 string. Resulting string is NULL terminated */
WS_DLL_PUBLIC
size_t ws_base64_decode_inplace(char *s);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __BASE64_H__ */
