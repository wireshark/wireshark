/** @file
 *
 * Copyright 2021, João Valverde <j@v6e.pt>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSLOG_H__
#define __WSLOG_H__

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <glib.h>

#include <ws_symbol_export.h>
#include <ws_attributes.h>
#include <ws_log_defs.h>
#include <ws_posix_compat.h>

#ifdef WS_LOG_DOMAIN
#define _LOG_DOMAIN WS_LOG_DOMAIN
#else
#define _LOG_DOMAIN ""
#endif

#ifdef WS_DEBUG
#define _LOG_DEBUG_ENABLED true
#else
#define _LOG_DEBUG_ENABLED false
#endif

/*
 * Define the macro WS_LOG_DOMAIN *before* including this header,
 * for example:
 *   #define WS_LOG_DOMAIN LOG_DOMAIN_MAIN
 */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Console open preference is stored in the Windows registry.
 *   HKEY_CURRENT_USER\Software\Wireshark\ConsoleOpen
 */
#define LOG_HKCU_CONSOLE_OPEN   "ConsoleOpen"

typedef enum {
    LOG_CONSOLE_OPEN_NEVER,
    LOG_CONSOLE_OPEN_AUTO, /* On demand. */
    LOG_CONSOLE_OPEN_ALWAYS, /* Open during startup. */
} ws_log_console_open_pref;

WSUTIL_EXPORT
ws_log_console_open_pref ws_log_console_open;

typedef struct {
    struct tm tstamp_secs;
    long nanosecs;
    intmax_t pid;
} ws_log_manifest_t;

/** Callback for registering a log writer. */
typedef void (ws_log_writer_cb)(const char *domain, enum ws_log_level level,
                            const char *file, long line, const char *func,
                            const char *fatal_msg, ws_log_manifest_t *mft,
                            const char *user_format, va_list user_ap,
                            void *user_data);


/** Callback for freeing a user data pointer. */
typedef void (ws_log_writer_free_data_cb)(void *user_data);


WS_DLL_PUBLIC
void ws_log_file_writer(FILE *fp, const char *domain, enum ws_log_level level,
                            const char *file, long line, const char *func,
                            ws_log_manifest_t *mft,
                            const char *user_format, va_list user_ap);


WS_DLL_PUBLIC
void ws_log_console_writer(const char *domain, enum ws_log_level level,
                            const char *file, long line, const char *func,
                            ws_log_manifest_t *mft,
                            const char *user_format, va_list user_ap);


/** Configure log levels "info" and below to use stdout.
 *
 * Normally all log messages are written to stderr. For backward compatibility
 * with GLib calling this function with true configures log levels "info",
 * "debug" and "noisy" to be written to stdout.
 */
WS_DLL_PUBLIC
void ws_log_console_writer_set_use_stdout(bool use_stdout);


/** Convert a numerical level to its string representation. */
WS_DLL_PUBLIC
WS_RETNONNULL
const char *ws_log_level_to_string(enum ws_log_level level);


/** Checks if a domain and level combination generate output.
 *
 * Returns true if a message will be printed for the domain/level combo.
 */
WS_DLL_PUBLIC
bool ws_log_msg_is_active(const char *domain, enum ws_log_level level);


/** Return the currently active log level. */
WS_DLL_PUBLIC
enum ws_log_level ws_log_get_level(void);


/** Set the active log level. Returns the active level or LOG_LEVEL_NONE
 * if level is invalid. */
WS_DLL_PUBLIC
enum ws_log_level ws_log_set_level(enum ws_log_level level);


/** Set the active log level from a string.
 *
 * String levels are "error", "critical", "warning", "message", "info",
 * "debug" and "noisy" (case insensitive).
 * Returns the new log level or LOG_LEVEL NONE if the string representation
 * is invalid.
 */
WS_DLL_PUBLIC
enum ws_log_level ws_log_set_level_str(const char *str_level);


/** Set a domain filter from a string.
 *
 * Domain filter is a case insensitive list separated by ',' or ';'. Only
 * the domains in the filter will generate output; the others will be muted.
 * Filter expressions can be preceded by '!' to invert the sense of the match.
 * In this case only non-matching domains will generate output.
 */
WS_DLL_PUBLIC
void ws_log_set_domain_filter(const char *domain_filter);

/** Set a fatal domain filter from a string.
 *
 * Domain filter is a case insensitive list separated by ',' or ';'. Domains
 * in the filter will cause the program to abort.
 */
WS_DLL_PUBLIC
void ws_log_set_fatal_domain_filter(const char *domain_filter);


/** Set a debug filter from a string.
 *
 * A debug filter lists all domains that should have debug level output turned
 * on, regardless of the global log level and domain filter. If negated
 * then debug (and below) will be disabled and the others unaffected by
 * the filter.
 */
WS_DLL_PUBLIC
void ws_log_set_debug_filter(const char *str_filter);


/** Set a noisy filter from a string.
 *
 * Same as ws_log_set_debug_filter() for "noisy" level.
 */
WS_DLL_PUBLIC
void ws_log_set_noisy_filter(const char *str_filter);


/** Set the fatal log level.
 *
 * Sets the log level at which calls to ws_log() will abort the program. The
 * argument can be LOG_LEVEL_ERROR, LOG_LEVEL_CRITICAL or LOG_LEVEL_WARNING.
 * Level LOG_LEVEL_ERROR is always fatal.
 */
WS_DLL_PUBLIC
enum ws_log_level ws_log_set_fatal_level(enum ws_log_level level);


/** Set the fatal log level from a string.
 *
 * Same as ws_log_set_fatal(), but accepts the strings "error", critical" or
 * "warning" instead as arguments.
 */
WS_DLL_PUBLIC
enum ws_log_level  ws_log_set_fatal_level_str(const char *str_level);


/** Set the active log writer.
 *
 * The parameter 'writer' can be NULL to use the default writer.
 */
WS_DLL_PUBLIC
void ws_log_set_writer(ws_log_writer_cb *writer);


/** Set the active log writer.
 *
 * The parameter 'writer' can be NULL to use the default writer.
 * Accepts an extra user_data parameter that will be passed to
 * the log writer.
 */
WS_DLL_PUBLIC
void ws_log_set_writer_with_data(ws_log_writer_cb *writer,
                        void *user_data,
                        ws_log_writer_free_data_cb *free_user_data);


#define LOG_ARGS_NOEXIT -1

/** Parses the command line arguments for log options.
 *
 * Returns zero for no error, non-zero for one or more invalid options.
 */
WS_DLL_PUBLIC
int ws_log_parse_args(int *argc_ptr, char *argv[],
                        void (*vcmdarg_err)(const char *, va_list ap),
                        int exit_failure);


/** Initializes the logging code.
 *
 * Must be called at startup before using the log API. If provided
 * vcmdarg_err is used to print initialization errors. This usually means
 * a misconfigured environment variable.
 */
WS_DLL_PUBLIC
void ws_log_init(const char *progname,
                        void (*vcmdarg_err)(const char *, va_list ap));


/** Initializes the logging code.
 *
 * Can be used instead of wslog_init(). Takes an extra writer argument.
 * If provided this callback will be used instead of the default writer.
 */
WS_DLL_PUBLIC
void ws_log_init_with_writer(const char *progname,
                        ws_log_writer_cb *writer,
                        void (*vcmdarg_err)(const char *, va_list ap));


/** Initializes the logging code.
 *
 * Accepts a user data pointer in addition to the writer. This pointer will
 * be provided to the writer with every invocation. If provided
 * free_user_data will be called during cleanup.
 */
WS_DLL_PUBLIC
void ws_log_init_with_writer_and_data(const char *progname,
                        ws_log_writer_cb *writer,
                        void *user_data,
                        ws_log_writer_free_data_cb *free_user_data,
                        void (*vcmdarg_err)(const char *, va_list ap));


/** This function is called to output a message to the log.
 *
 * Takes a format string and a variable number of arguments.
 */
WS_DLL_PUBLIC
void ws_log(const char *domain, enum ws_log_level level,
                    const char *format, ...) G_GNUC_PRINTF(3,4);


/** This function is called to output a message to the log.
 *
 * Takes a format string and a 'va_list'.
 */
WS_DLL_PUBLIC
void ws_logv(const char *domain, enum ws_log_level level,
                    const char *format, va_list ap);


/** This function is called to output a message to the log.
 *
 * In addition to the message this function accepts file/line/function
 * information.
 */
WS_DLL_PUBLIC
void ws_log_full(const char *domain, enum ws_log_level level,
                    const char *file, long line, const char *func,
                    const char *format, ...) G_GNUC_PRINTF(6,7);


/** This function is called to output a message to the log.
 *
 * In addition to the message this function accepts file/line/function
 * information.
 */
WS_DLL_PUBLIC
void ws_logv_full(const char *domain, enum ws_log_level level,
                    const char *file, long line, const char *func,
                    const char *format, va_list ap);


WS_DLL_PUBLIC
WS_NORETURN
void ws_log_fatal_full(const char *domain, enum ws_log_level level,
                    const char *file, long line, const char *func,
                    const char *format, ...) G_GNUC_PRINTF(6,7);


/*
 * The if condition avoids -Wunused warnings for variables used only with
 * WS_DEBUG, typically inside a ws_debug() call. The compiler will
 * optimize away the dead execution branch.
 */
#define _LOG_IF_ACTIVE(active, level, file, line, func, ...) \
        do {                                        \
            if (active) {                           \
                ws_log_full(_LOG_DOMAIN, level,     \
                            file, line, func,       \
                            __VA_ARGS__);           \
            }                                       \
        } while (0)

#define _LOG_FULL(active, level, ...) \
        _LOG_IF_ACTIVE(active, level, __FILE__, __LINE__, __func__, __VA_ARGS__)

#define _LOG_SIMPLE(active, level, ...) \
        _LOG_IF_ACTIVE(active, level, NULL, -1, NULL, __VA_ARGS__)

/** Logs with "error" level.
 *
 * Accepts a format string and includes the file and function name.
 *
 * "error" is always fatal and terminates the program with a coredump.
 */
#define ws_error(...) \
        ws_log_fatal_full(_LOG_DOMAIN, LOG_LEVEL_ERROR, \
                            __FILE__, __LINE__, __func__, __VA_ARGS__)

/** Logs with "critical" level.
 *
 * Accepts a format string and includes the file and function name.
 */
#define ws_critical(...) \
        _LOG_FULL(true, LOG_LEVEL_CRITICAL, __VA_ARGS__)

/** Logs with "warning" level.
 *
 * Accepts a format string and includes the file and function name.
 */
#define ws_warning(...) \
        _LOG_FULL(true, LOG_LEVEL_WARNING, __VA_ARGS__)

/** Logs with "message" level.
 *
 * Accepts a format string and does not include the file and function
 * name (use ws_log_full instead). This is the default log level.
 */
#define ws_message(...) \
        _LOG_SIMPLE(true, LOG_LEVEL_MESSAGE, __VA_ARGS__)

/** Logs with "info" level.
 *
 * Accepts a format string and does not include the file and function
 * name (use ws_log_full instead).
 */
#define ws_info(...) \
        _LOG_SIMPLE(true, LOG_LEVEL_INFO, __VA_ARGS__)

/** Logs with "debug" level.
 *
 * Accepts a format string and includes the file and function name.
 */
#define ws_debug(...) \
        _LOG_FULL(_LOG_DEBUG_ENABLED, LOG_LEVEL_DEBUG, __VA_ARGS__)

/** Logs with "noisy" level.
 *
 * Accepts a format string and includes the file and function name.
 */
#define ws_noisy(...) \
        _LOG_FULL(_LOG_DEBUG_ENABLED, LOG_LEVEL_NOISY, __VA_ARGS__)

/** Used for temporary debug print outs, always active. */
#define WS_DEBUG_HERE(...) \
        _LOG_FULL(true, LOG_LEVEL_ECHO, __VA_ARGS__)

#define WS_NOT_IMPLEMENTED() \
        ws_error("Not implemented yet")

WS_DLL_PUBLIC
void ws_log_utf8_full(const char *domain, enum ws_log_level level,
                    const char *file, long line, const char *func,
                    const char *string, ssize_t length, const char *endptr);


#define ws_log_utf8(str, len, endptr) \
    do {                                                        \
        if (_LOG_DEBUG_ENABLED) {                               \
            ws_log_utf8_full(LOG_DOMAIN_UTF_8, LOG_LEVEL_DEBUG, \
                                __FILE__, __LINE__, __func__,   \
                                str, len, endptr);              \
        }                                                       \
    } while (0)


/** This function is called to log a buffer (bytes array).
 *
 * Accepts an optional 'msg' argument to provide a description.
 */
WS_DLL_PUBLIC
void ws_log_buffer_full(const char *domain, enum ws_log_level level,
                    const char *file, long line, const char *func,
                    const uint8_t *buffer, size_t size,
                    size_t max_bytes_len, const char *msg);


#define ws_log_buffer(buf, size) \
        do {                                                        \
            if (_LOG_DEBUG_ENABLED) {                               \
                ws_log_buffer_full(_LOG_DOMAIN, LOG_LEVEL_DEBUG,    \
                        __FILE__, __LINE__, __func__,               \
                        buf, size, 36, #buf);                       \
            }                                                       \
        } while (0)


/** Auxiliary function to write custom logging functions.
 *
 * This function is the same as ws_log_full() but does not perform any
 * domain/level filtering to avoid a useless double activation check.
 * It should only be used in conjunction with a pre-check using
 * ws_log_msg_is_active().
 */
WS_DLL_PUBLIC
void ws_log_write_always_full(const char *domain, enum ws_log_level level,
                    const char *file, long line, const char *func,
                    const char *format, ...) G_GNUC_PRINTF(6,7);


/** Define an auxiliary file pointer where messages should be written.
 *
 * This file, if set, functions in addition to the registered or
 * default log writer.
 */
WS_DLL_PUBLIC
void ws_log_add_custom_file(FILE *fp);


WS_DLL_PUBLIC
void ws_log_print_usage(FILE *fp);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WSLOG_H__ */
