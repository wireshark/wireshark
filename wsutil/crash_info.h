/** @file
 * Routines to try to provide more useful information in crash dumps.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2006 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __CRASH_INFO_H__
#define __CRASH_INFO_H__

#include <wireshark.h>

#ifdef __cplusplus
extern "C" {
#endif

WS_DLL_PUBLIC void ws_vadd_crash_info(const char *fmt, va_list ap);

WS_DLL_PUBLIC void ws_add_crash_info(const char *fmt, ...)
    G_GNUC_PRINTF(1,2);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CRASH_INFO_H__ */
