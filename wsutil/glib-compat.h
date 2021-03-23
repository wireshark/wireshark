/* glib-compat.h
* Definitions to provide some functions that are not present in older
* GLIB versions (down to 2.22)
*
* Wireshark - Network traffic analyzer
* By Gerald Combs <gerald@wireshark.org>
* Copyright 1998 Gerald Combs
*
* SPDX-License-Identifier: GPL-2.0-or-later
*/
#ifndef GLIB_COMPAT_H
#define GLIB_COMPAT_H

#include "ws_symbol_export.h"
#include "ws_attributes.h"

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#if !GLIB_CHECK_VERSION(2, 68, 0)
WS_DLL_PUBLIC gpointer g_memdup2(gconstpointer mem, gsize byte_size);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* GLIB_COMPAT_H */
