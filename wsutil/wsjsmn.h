/* wsjsmn.h
 * Utility to check if a payload is json using libjsmn
 *
 * Copyright 2016, Dario Lombardo
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef __WSJSMN_H__
#define __WSJSMN_H__

#include "ws_symbol_export.h"
#include <glib.h>

#include "jsmn.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Check if a buffer is json an returns true if it is.
 */
WS_DLL_PUBLIC gboolean jsmn_is_json(const guint8* buf, const size_t len);

WS_DLL_PUBLIC int wsjsmn_parse(const char *buf, jsmntok_t *tokens, unsigned int max_tokens);

/**
 * Try to unescape input JSON string. output can be the same pointer as input, or must have the same buffer size as input.
 */
WS_DLL_PUBLIC gboolean wsjsmn_unescape_json_string(const char *input, char *output);

#ifdef __cplusplus
}
#endif

#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 noexpandtab:
 * :indentSize=4:tabSize=8:noTabs=false:
 */
