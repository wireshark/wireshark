/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WS_STRPTIME_H__
#define __WS_STRPTIME_H__

#include <wireshark.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * This is the NetBSD strptime(), modified to always use the "C" locale.
 */
WS_DLL_PUBLIC
char *
ws_strptime(const char *buf, const char *format, struct tm *tm);

/*
 * Portability wrapper around the system's strptime().
 */
WS_DLL_PUBLIC
char *
ws_strptime_p(const char *buf, const char *format, struct tm *tm);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WS_STRPTIME_H__ */
