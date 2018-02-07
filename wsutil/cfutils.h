/* cfutils.h
 * Declarations of routines to work around deficiencies in Core Foundation,
 * such as the lack of a routine to convert a CFString to a C string of
 * arbitrary size.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSUTIL_CFUTILS_H__
#define __WSUTIL_CFUTILS_H__

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Convert a CFString to a g_malloc()ated C string.
 */
WS_DLL_PUBLIC char *CFString_to_C_string(CFStringRef cfstring);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WSUTIL_CFUTILS_H__ */
