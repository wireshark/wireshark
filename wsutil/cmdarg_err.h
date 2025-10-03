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

/**
 * @brief Initialize error reporting callbacks for command-line argument handling.
 *
 * Sets the functions used to report fatal and non-fatal error messages during
 * command-line argument parsing or validation. The `err` function is called for
 * fatal errors, while `err_cont` is used for warnings or recoverable issues.
 *
 * Both callbacks accept a printf-style format string and a `va_list` of arguments.
 * This allows flexible integration with custom logging or UI systems.
 *
 * @param err       Callback for fatal error messages.
 * @param err_cont  Callback for non-fatal error messages.
 */
WS_DLL_PUBLIC void
cmdarg_err_init(void (*err)(const char *, va_list),
                void (*err_cont)(const char *, va_list));


/**
 * @brief Report an error in command-line arguments.
 *
 * Calls the `err` function passed to `cmdarg_err_init` to report an
 * report an error in command-line arguments.
 *
 * @param fmt Format string describing the error.
 * @param ap  va_list containing arguments for the format string.
 */
WS_DLL_PUBLIC void
vcmdarg_err(const char *fmt, va_list ap)
    G_GNUC_PRINTF(1, 0);

/**
 * @brief Report an error in command-line arguments.
 *
 * Calls the `err` function passed to `cmdarg_err_init` to report an
 * report an error in command-line arguments.
 *
 * @param fmt Format string describing the error.
 * @param ... Arguments for the format string.
 */
WS_DLL_PUBLIC void
cmdarg_err(const char *fmt, ...)
    G_GNUC_PRINTF(1, 2);

/**
 * @brief Report additional information for an error in command-line arguments.
 *
 * Calls the `print_err_cont` function passed to `cmdarg_err_init` to report an
 * report an error in command-line arguments.
 *
 * @param fmt Format string describing the error.
 * @param ... Arguments for the format string.
 */
WS_DLL_PUBLIC void
cmdarg_err_cont(const char *fmt, ...)
    G_GNUC_PRINTF(1, 2);

/**
 * @brief Print a formatted command-line error message to standard error.
 *
 * Outputs an error message using the provided `va_list` arguments, typically
 * during command-line parsing or validation. This variant writes directly to
 * `stderr`, bypassing any custom logging or UI systems.
 *
 * @param msg_format Format string (printf-style).
 * @param ap         va_list containing arguments for the format string.
 */
WS_DLL_PUBLIC void
stderr_cmdarg_err(const char *msg_format, va_list ap);

/**
 * @brief Print additional context for a command-line error to standard error.
 *
 * Appends a follow-up message to a previously reported error, using the
 * provided `va_list` arguments. This is useful for extending diagnostics
 * across multiple lines or clarifying the source of a failure.
 *
 * @param msg_format Format string (printf-style).
 * @param ap         va_list containing arguments for the format string.
 */
WS_DLL_PUBLIC void
stderr_cmdarg_err_cont(const char *msg_format, va_list ap);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CMDARG_ERR_H__ */
