/* cmdarg_err.h
 * Declarations of routines to report command-line argument errors.
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

#ifndef __WSUTIL_CMDARG_ERR_H__
#define __WSUTIL_CMDARG_ERR_H__

#include <stdarg.h>

#include <glib.h>

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Set the reporting functions for error messages.
 */
WS_DLL_PUBLIC void
cmdarg_err_init(void (*err)(const char *, va_list),
                void (*err_cont)(const char *, va_list));

/*
 * Report an error in command-line arguments.
 */
WS_DLL_PUBLIC void
cmdarg_err(const char *fmt, ...)
    G_GNUC_PRINTF(1, 2);

/*
 * Report additional information for an error in command-line arguments.
 */
WS_DLL_PUBLIC void
cmdarg_err_cont(const char *fmt, ...)
    G_GNUC_PRINTF(1, 2);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WSUTIL_CMDARG_ERR_H__ */
