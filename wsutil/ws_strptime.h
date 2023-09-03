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

/* Struct to pass the "tm_gmtoff" and "tm_zone" fields, for systems whose
 * libc struct tm type lacks these non-standard extensions. */
struct ws_timezone {
	long tm_gmtoff;
	const char *tm_zone;
};

/*
 * This is the NetBSD strptime(), modified to always use the "C" locale.
 */
WS_DLL_PUBLIC
char *
ws_strptime(const char *buf, const char *format, struct tm *tm,
						struct ws_timezone *zonep);

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
