/* win32-utils.h
 * Windows utility definitions
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2006 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef __WIN32UTIL_H__
#define __WIN32UTIL_H__

#include "ws_symbol_export.h"

#include <glib.h>
#include <windows.h>

/**
 * @file
 * Unicode convenience routines.
 */

#ifdef	__cplusplus
extern "C" {
#endif

/** Quote the argument element if necessary, so that it will get
 * reconstructed correctly in the C runtime startup code.  Note that
 * the unquoting algorithm in the C runtime is really weird, and
 * rather different than what Unix shells do. See stdargv.c in the C
 * runtime sources (in the Platform SDK, in src/crt).
 *
 * Stolen from GLib's protect_argv(), an internal routine that quotes
 * string in an argument list so that they arguments will be handled
 * correctly in the command-line string passed to CreateProcess()
 * if that string is constructed by gluing those strings together.
 *
 * @param argv The string to be quoted.  May be NULL.
 * @return The string quoted to be used by CreateProcess
 */
WS_DLL_PUBLIC
gchar * protect_arg (const gchar *argv);

/** Generate a string for a Win32 error.
 *
 * @param error The windows error code
 * @return a localized string containing the corresponding error message
 */
WS_DLL_PUBLIC
const char * win32strerror(DWORD error);

/** Generate a string for a Win32 exception code.
 *
 * @param exception The exception code
 * @return a non-localized string containing the error message
 */
WS_DLL_PUBLIC
const char * win32strexception(DWORD exception);

#ifdef	__cplusplus
}
#endif

#endif /* __WIN32UTIL_H__ */
