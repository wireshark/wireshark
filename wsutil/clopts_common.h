/* clopts_common.h
 * Handle command-line arguments common to various programs
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSUTIL_CLOPTS_COMMON_H__
#define __WSUTIL_CLOPTS_COMMON_H__

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

WS_DLL_PUBLIC int
get_natural_int(const char *string, const char *name);

WS_DLL_PUBLIC int
get_positive_int(const char *string, const char *name);

WS_DLL_PUBLIC guint32
get_guint32(const char *string, const char *name);

WS_DLL_PUBLIC guint32
get_nonzero_guint32(const char *string, const char *name);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WSUTIL_CLOPTS_COMMON_H__ */
