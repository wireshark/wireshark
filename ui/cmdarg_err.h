/* cmdarg_err.h
 * Declarations of routines to report command-line argument errors.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __UI_CMDARG_ERR_H__
#define __UI_CMDARG_ERR_H__

#include <stdarg.h>

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Set the reporting functions for error messages.
 */
extern void
cmdarg_err_init(void (*err)(const char *, va_list),
                void (*err_cont)(const char *, va_list));

/*
 * Report an error in command-line arguments.
 */
extern void
cmdarg_err(const char *fmt, ...)
    G_GNUC_PRINTF(1, 2);

/*
 * Report additional information for an error in command-line arguments.
 */
extern void
cmdarg_err_cont(const char *fmt, ...)
    G_GNUC_PRINTF(1, 2);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UI_CMDARG_ERR_H__ */
