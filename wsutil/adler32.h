/* adler32.h
 * Compute the Adler32 checksum (RFC 1950)
 * 2003 Tomas Kukosa
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef ADLER32_H
#define ADLER32_H

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C"{
#endif

WS_DLL_PUBLIC guint32 update_adler32(guint32 adler, const guint8 *buf, size_t len);
WS_DLL_PUBLIC guint32 adler32_bytes(const guint8 *buf, size_t len);
WS_DLL_PUBLIC guint32 adler32_str(const char *buf);

#ifdef __cplusplus
}
#endif

#endif  /* ADLER32_H */

