/** @file
 *
 * Declarations of routines to report command-line argument errors.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __CMDARG_ERR_H__
#define __CMDARG_ERR_H__

#include <wireshark.h>
#include <stdarg.h>

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
vcmdarg_err(const char *fmt, va_list ap)
    G_GNUC_PRINTF(1, 0);

WS_DLL_PUBLIC void
cmdarg_err(const char *fmt, ...)
    G_GNUC_PRINTF(1, 2);

/*
 * Report additional information for an error in command-line arguments.
 */
WS_DLL_PUBLIC void
cmdarg_err_cont(const char *fmt, ...)
    G_GNUC_PRINTF(1, 2);

/*
 * Error printing routines that report to the standard error.
 */
WS_DLL_PUBLIC void
stderr_cmdarg_err(const char *msg_format, va_list ap);

WS_DLL_PUBLIC void
stderr_cmdarg_err_cont(const char *msg_format, va_list ap);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CMDARG_ERR_H__ */
