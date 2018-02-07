/* base32.h
 * Base-32 conversion
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __BASE32_H__
#define __BASE32_H__

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** Returned by base32_decode() if the input is not valid base32. */
#define Base32_BAD_INPUT -1
/** Returned by base32_decode() if the output buffer is too small. */
#define Base32_TOO_BIG -2

/* Encoding of a base32 byte array */
WS_DLL_PUBLIC
int ws_base32_decode(guint8* output, const guint32 outputLength,
						const guint8* in, const guint32 inputLength);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __BASE32_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
