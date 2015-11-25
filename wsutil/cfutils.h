/* cfutils.h
 * Declarations of routines to work around deficiencies in Core Foundation,
 * such as the lack of a routine to convert a CFString to a C string of
 * arbitrary size.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
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
