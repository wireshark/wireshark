/** @file
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

#include <wireshark.h>

#ifdef __cplusplus
extern "C"{
#endif

WS_DLL_PUBLIC uint32_t update_adler32(uint32_t adler, const uint8_t *buf, size_t len);
WS_DLL_PUBLIC uint32_t adler32_bytes(const uint8_t *buf, size_t len);
WS_DLL_PUBLIC uint32_t adler32_str(const char *buf);

#ifdef __cplusplus
}
#endif

#endif  /* ADLER32_H */

