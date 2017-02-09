/* wsjsmn.h
 * Utility to check if a payload is json using libjsmn
 *
 * Copyright 2016, Dario Lombardo
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
