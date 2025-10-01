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
#include "ws_getopt.h"

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

/**
 * @brief Console open preference for logging output.
 *
 * Specifies when the console window should be opened for log messages.
 */
typedef enum {
    LOG_CONSOLE_OPEN_NEVER,   /**< Never open the console. */
    LOG_CONSOLE_OPEN_AUTO,    /**< Open on demand. */
    LOG_CONSOLE_OPEN_ALWAYS,  /**< Open during startup. */
} ws_log_console_open_pref;


WSUTIL_EXPORT
ws_log_console_open_pref ws_log_console_open;

/**
 * @brief Log manifest entry containing timestamp and process ID.
 *
 * Represents a single log event with second-level and nanosecond-level
 * timestamp precision, along with the originating process ID.
 */
typedef struct {
    struct tm   tstamp_secs;  /**< Timestamp (seconds resolution) */
    long        nanosecs;     /**< Nanoseconds component of the timestamp */
    intmax_t    pid;          /**< Process ID associated with the log entry */
} ws_log_manifest_t;

/** Callback for registering a log writer. */
typedef void (ws_log_writer_cb)(const char *domain, enum ws_log_level level,
                            const char *file, long line, const char *func,
                            const char *fatal_msg, ws_log_manifest_t *mft,
                            const char *user_format, va_list user_ap,
                            void *user_data);


/** Callback for freeing a user data pointer. */
typedef void (ws_log_writer_free_data_cb)(void *user_data);

/**
 * @brief Write a formatted log message to a file stream.
 *
 * @param fp            Output file stream to write the log message.
 * @param domain        Logging domain or subsystem name.
 * @param level         Log severity level.
 * @param file          Source file name where the log originated.
 * @param line          Line number in the source file.
 * @param func          Function name where the log was generated.
 * @param mft           Pointer to log manifest metadata (timestamp, PID).
 * @param user_format   User-supplied format string (printf-style).
 * @param user_ap       Variable argument list for the format string.
 */
WS_DLL_PUBLIC
void ws_log_file_writer(FILE *fp, const char *domain, enum ws_log_level level,
                            const char *file, long line, const char *func,
                            ws_log_manifest_t *mft,
                            const char *user_format, va_list user_ap);

/**
 * @brief Write a formatted log message to the console.
 *
 * @param domain        Logging domain or subsystem name.
 * @param level         Log severity level.
 * @param file          Source file name where the log originated.
 * @param line          Line number in the source file.
 * @param func          Function name where the log was generated.
 * @param mft           Pointer to log manifest metadata (timestamp, PID).
 * @param user_format   User-supplied format string (printf-style).
 * @param user_ap       Variable argument list for the format string.
 */
WS_DLL_PUBLIC
void ws_log_console_writer(const char *domain, enum ws_log_level level,
                            const char *file, long line, const char *func,
                            ws_log_manifest_t *mft,
                            const char *user_format, va_list user_ap);


/**
 * @brief Configure log levels "info" and below to use stdout.
 *
 * Normally, all log messages are written to stderr. For backward compatibility
 * with GLib, calling this function with true configures log levels "info",
 * "debug", and "noisy" to be written to stdout.
 *
 * @param use_stdout  If true, log levels "info" and below will be written to stdout.
 *                    Otherwise, all logs go to stderr.
 */
WS_DLL_PUBLIC
void ws_log_console_writer_set_use_stdout(bool use_stdout);


/**
 * @brief Convert a numerical log level to its string representation.
 *
 * @param level  Log level as an enum value.
 * @return       Corresponding string name for the log level (e.g., "info", "debug").
 */
WS_DLL_PUBLIC
WS_RETNONNULL
const char *ws_log_level_to_string(enum ws_log_level level);


/**
 * @brief Check if a log message will be output for a given domain and level.
 *
 * Returns true if a message with the specified domain and log level
 * will be printed according to the current logging configuration.
 *
 * @param domain  Logging domain or subsystem name.
 * @param level   Log severity level to check.
 * @return        True if the message would be logged; false otherwise.
 */
WS_DLL_PUBLIC
bool ws_log_msg_is_active(const char *domain, enum ws_log_level level);


/**
 * @brief Get the currently active global log level.
 *
 * This level determines the minimum severity of messages that will be logged.
 *
 * @return Current global log level.
 */
WS_DLL_PUBLIC
enum ws_log_level ws_log_get_level(void);


/**
 * @brief Set the active log level.
 *
 * Sets the global log level to the specified level.
 * Returns the active log level or LOG_LEVEL_NONE if the input level is invalid.
 *
 * @param level  Log level to activate.
 * @return       The active log level or LOG_LEVEL_NONE if invalid.
 */
WS_DLL_PUBLIC
enum ws_log_level ws_log_set_level(enum ws_log_level level);


/**
 * @brief Set the active log level from a string.
 *
 * Accepts string representations of log levels: "error", "critical", "warning",
 * "message", "info", "debug", and "noisy" (case insensitive).
 * Returns the new active log level or LOG_LEVEL_NONE if the string is invalid.
 *
 * @param str_level  Log level as a string.
 * @return           The active log level or LOG_LEVEL_NONE if invalid.
 */
WS_DLL_PUBLIC
enum ws_log_level ws_log_set_level_str(const char *str_level);


/**
 * @brief Set a domain filter from a string.
 *
 * The domain filter is a case-insensitive list separated by ',' or ';'.
 * Only domains matching the filter will generate output; all others are muted.
 * Filter expressions can be prefixed with '!' to invert the match,
 * causing only non-matching domains to generate output.
 *
 * @param domain_filter  String containing domain filter expressions.
 */
WS_DLL_PUBLIC
void ws_log_set_domain_filter(const char *domain_filter);

/**
 * @brief Set a fatal domain filter from a string.
 *
 * The domain filter is a case-insensitive list separated by ',' or ';'.
 * Domains included in the filter will cause the program to abort when logged.
 *
 * @param domain_filter  String containing fatal domain filter expressions.
 */
WS_DLL_PUBLIC
void ws_log_set_fatal_domain_filter(const char *domain_filter);


/**
 * @brief Set a debug filter from a string.
 *
 * Enables debug level output for all domains listed in the filter,
 * regardless of the global log level and domain filter.
 * If the filter is negated, debug (and below) output will be disabled
 * for the listed domains, while others remain unaffected.
 *
 * @param str_filter  String specifying domains for debug filtering.
 */
WS_DLL_PUBLIC
void ws_log_set_debug_filter(const char *str_filter);


/**
 * @brief Set a noisy filter from a string.
 *
 * Works like ws_log_set_debug_filter(), but applies to the "noisy" log level.
 *
 * @param str_filter  String specifying domains for noisy level filtering.
 */
WS_DLL_PUBLIC
void ws_log_set_noisy_filter(const char *str_filter);


/**
 * @brief Set the fatal log level.
 *
 * Sets the log level at which calls to ws_log() will abort the program.
 * The argument can be LOG_LEVEL_ERROR, LOG_LEVEL_CRITICAL, or LOG_LEVEL_WARNING.
 * LOG_LEVEL_ERROR is always treated as fatal.
 *
 * @param level  Log level to set as fatal.
 * @return       The active fatal log level, or LOG_LEVEL_NONE if invalid.
 */
WS_DLL_PUBLIC
enum ws_log_level ws_log_set_fatal_level(enum ws_log_level level);


/**
 * @brief Set the fatal log level from a string.
 *
 * Same as ws_log_set_fatal_level(), but accepts the strings "error", "critical",
 * or "warning" (case insensitive) as arguments.
 *
 * @param str_level  String representation of the fatal log level.
 * @return           The active fatal log level, or LOG_LEVEL_NONE if invalid.
 */
WS_DLL_PUBLIC
enum ws_log_level ws_log_set_fatal_level_str(const char *str_level);


/**
 * @brief Set the active log writer.
 *
 * The parameter 'writer' can be NULL to use the default writer.
 *
 * @param writer  Callback function to handle log output, or NULL for default.
 */
WS_DLL_PUBLIC
void ws_log_set_writer(ws_log_writer_cb *writer);


/**
 * @brief Set the active log writer with user data.
 *
 * The parameter 'writer' can be NULL to use the default writer.
 * Accepts an extra user_data parameter that will be passed to
 * the log writer.
 *
 * @param writer         Callback function to handle log output, or NULL for default.
 * @param user_data      Pointer to user-defined data passed to the writer.
 * @param free_user_data Optional callback to free user_data when no longer needed.
 */
WS_DLL_PUBLIC
void ws_log_set_writer_with_data(ws_log_writer_cb *writer,
                        void *user_data,
                        ws_log_writer_free_data_cb *free_user_data);


#define LOG_ARGS_NOEXIT -1

#define LONGOPT_WSLOG_LOG_LEVEL            LONGOPT_BASE_WSLOG+1
#define LONGOPT_WSLOG_LOG_DOMAIN           LONGOPT_BASE_WSLOG+2
#define LONGOPT_WSLOG_LOG_FILE             LONGOPT_BASE_WSLOG+3
#define LONGOPT_WSLOG_LOG_FATAL            LONGOPT_BASE_WSLOG+4
#define LONGOPT_WSLOG_LOG_FATAL_DOMAIN     LONGOPT_BASE_WSLOG+5
#define LONGOPT_WSLOG_LOG_DEBUG            LONGOPT_BASE_WSLOG+6
#define LONGOPT_WSLOG_LOG_NOISY            LONGOPT_BASE_WSLOG+7

/** Logging options for command line
*/
#define LONGOPT_WSLOG \
    {"log-level",             ws_required_argument, NULL, LONGOPT_WSLOG_LOG_LEVEL},  \
    {"log-domain",            ws_required_argument, NULL, LONGOPT_WSLOG_LOG_DOMAIN}, \
    /* Alias "domain" and "domains". */                                              \
    {"log-domains",           ws_required_argument, NULL, LONGOPT_WSLOG_LOG_DOMAIN}, \
    {"log-file",              ws_required_argument, NULL, LONGOPT_WSLOG_LOG_FILE},   \
    {"log-fatal",             ws_required_argument, NULL, LONGOPT_WSLOG_LOG_FATAL},  \
    /* Alias "domain" and "domains". */                                                    \
    {"log-fatal-domain",      ws_required_argument, NULL, LONGOPT_WSLOG_LOG_FATAL_DOMAIN}, \
    {"log-fatal-domains",     ws_required_argument, NULL, LONGOPT_WSLOG_LOG_FATAL_DOMAIN}, \
    {"log-debug",             ws_required_argument, NULL, LONGOPT_WSLOG_LOG_DEBUG}, \
    {"log-noisy",             ws_required_argument, NULL, LONGOPT_WSLOG_LOG_NOISY},

/**
 * @brief Parse command-line arguments for log options.
 *
 * Parses standard and extended command-line options related to logging.
 * Returns zero if all options are valid, or a non-zero value if one or more
 * invalid options are encountered.
 *
 * @param argc_ptr       Pointer to argument count (may be updated).
 * @param argv           Argument vector.
 * @param optstring      Short option string (as used by getopt).
 * @param long_options   Array of extended options.
 * @param vcmdarg_err    Callback for reporting invalid option errors.
 * @param exit_failure   Exit code to use if parsing fails fatally.
 * @return               0 on success, non-zero on error.
 */
WS_DLL_PUBLIC
int ws_log_parse_args(int *argc_ptr, char *argv[],
                        const char* optstring, const struct ws_option* long_options,
                        void (*vcmdarg_err)(const char *, va_list ap),
                        int exit_failure);


/**
 * @brief Determine if a command-line argument is used by wslog.
 *
 * Useful for applications that strictly validate command-line arguments but
 * should delegate logging-related options to wslog instead of handling them directly.
 *
 * @param arg  Argument index or identifier to check.
 * @return     True if the argument is recognized by wslog; false otherwise.
 */
WS_DLL_PUBLIC
bool ws_log_is_wslog_arg(int arg);


/**
 * @brief Initialize the logging system.
 *
 * Must be called at startup before using the log API. If provided,
 * vcmdarg_err is used to print initialization errors, typically caused
 * by misconfigured environment variables.
 *
 * @param vcmdarg_err  Optional callback for reporting initialization errors.
 */
WS_DLL_PUBLIC
void ws_log_init(void (*vcmdarg_err)(const char *, va_list ap));


/**
 * @brief Initialize the logging system with a custom writer.
 *
 * Can be used instead of ws_log_init(). Takes an extra writer argument.
 * If provided, this callback will be used instead of the default writer.
 *
 * @param writer        Callback function to handle log output, or NULL for default.
 * @param vcmdarg_err   Optional callback for reporting initialization errors.
 */
WS_DLL_PUBLIC
void ws_log_init_with_writer(ws_log_writer_cb *writer,
                        void (*vcmdarg_err)(const char *, va_list ap));


/**
 * @brief Initialize the logging system with a custom writer and user data.
 *
 * Accepts a user data pointer in addition to the writer. This pointer will
 * be provided to the writer with every invocation. If provided,
 * free_user_data will be called during cleanup.
 *
 * @param writer         Callback function to handle log output, or NULL for default.
 * @param user_data      Pointer to user-defined data passed to the writer.
 * @param free_user_data Optional callback to free user_data during cleanup.
 * @param vcmdarg_err    Optional callback for reporting initialization errors.
 */
WS_DLL_PUBLIC
void ws_log_init_with_writer_and_data(ws_log_writer_cb *writer,
                        void *user_data,
                        ws_log_writer_free_data_cb *free_user_data,
                        void (*vcmdarg_err)(const char *, va_list ap));


/**
 * @brief Output a formatted message to the log.
 *
 * This function emits a log message for the specified domain and level.
 * The message is constructed using a printf-style format string and
 * a variable number of arguments.
 *
 * @param domain  Logging domain or subsystem name.
 * @param level   Log severity level.
 * @param format  printf-style format string for the log message.
 * @param ...     Variable arguments matching the format string.
 */
WS_DLL_PUBLIC
void ws_log(const char *domain, enum ws_log_level level,
                    const char *format, ...) G_GNUC_PRINTF(3,4);


/**
 * @brief Output a formatted message to the log using a va_list.
 *
 * This function emits a log message for the specified domain and level,
 * using a printf-style format string and a va_list for arguments.
 *
 * @param domain  Logging domain or subsystem name.
 * @param level   Log severity level.
 * @param format  printf-style format string for the log message.
 * @param ap      va_list containing arguments for the format string.
 */
WS_DLL_PUBLIC
void ws_logv(const char *domain, enum ws_log_level level,
                    const char *format, va_list ap);


/**
 * @brief Output a formatted log message with source context.
 *
 * This function emits a log message for the specified domain and level,
 * including source file name, line number, and function name for context.
 * The message is constructed using a printf-style format string and
 * a variable number of arguments.
 *
 * @param domain  Logging domain or subsystem name.
 * @param level   Log severity level.
 * @param file    Source file name where the log originated.
 * @param line    Line number in the source file.
 * @param func    Function name where the log was generated.
 * @param format  printf-style format string for the log message.
 * @param ...     Variable arguments matching the format string.
 */
WS_DLL_PUBLIC
void ws_log_full(const char *domain, enum ws_log_level level,
                    const char *file, long line, const char *func,
                    const char *format, ...) G_GNUC_PRINTF(6,7);


/**
 * @brief Output a formatted log message with source context using a va_list.
 *
 * This function emits a log message for the specified domain and level,
 * including source file name, line number, and function name for context.
 * The message is constructed using a printf-style format string and a va_list.
 *
 * @param domain  Logging domain or subsystem name.
 * @param level   Log severity level.
 * @param file    Source file name where the log originated.
 * @param line    Line number in the source file.
 * @param func    Function name where the log was generated.
 * @param format  printf-style format string for the log message.
 * @param ap      va_list containing arguments for the format string.
 */
WS_DLL_PUBLIC
void ws_logv_full(const char *domain, enum ws_log_level level,
                    const char *file, long line, const char *func,
                    const char *format, va_list ap);


/**
 * @brief Output a fatal log message with source context and abort the program.
 *
 * Emits a log message for the specified domain and level, including source file name,
 * line number, and function name. This function does not return; it terminates the program
 * after logging the message.
 *
 * @param domain  Logging domain or subsystem name.
 * @param level   Log severity level.
 * @param file    Source file name where the log originated.
 * @param line    Line number in the source file.
 * @param func    Function name where the log was generated.
 * @param format  printf-style format string for the log message.
 * @param ...     Variable arguments matching the format string.
 */
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

/**
 * @def ws_error
 * @brief Log a fatal "error" level message and terminate the program.
 *
 * Emits a log message with "error" severity, including file name, line number,
 * and function name. This macro always results in program termination with a coredump.
 *
 * @param ...  printf-style format string and arguments for the log message.
 */
#define ws_error(...) \
        ws_log_fatal_full(_LOG_DOMAIN, LOG_LEVEL_ERROR, \
                            __FILE__, __LINE__, __func__, __VA_ARGS__)

/**
 * @def ws_critical
 * @brief Log a "critical" level message with source context.
 *
 * Emits a log message with "critical" severity, including file name,
 * line number, and function name. Used for serious issues that do not
 * terminate the program.
 *
 * @param ...  printf-style format string and arguments for the log message.
 */
#define ws_critical(...) \
        _LOG_FULL(true, LOG_LEVEL_CRITICAL, __VA_ARGS__)

/**
 * @def ws_warning
 * @brief Log a "warning" level message with source context.
 *
 * Emits a log message with "warning" severity, including file name,
 * line number, and function name. Used to report recoverable issues
 * or unexpected conditions.
 *
 * @param ...  printf-style format string and arguments for the log message.
 */
#define ws_warning(...) \
        _LOG_FULL(true, LOG_LEVEL_WARNING, __VA_ARGS__)

/**
 * @def ws_message
 * @brief Log a "message" level entry without source context.
 *
 * Emits a log message with "message" severity, the default log level.
 * Does not include file name, line number, or function name.
 * For full context, use ws_log_full instead.
 *
 * @param ...  printf-style format string and arguments for the log message.
 */
#define ws_message(...) \
        _LOG_SIMPLE(true, LOG_LEVEL_MESSAGE, __VA_ARGS__)

/**
 * @def ws_info
 * @brief Log an "info" level entry without source context.
 *
 * Emits a log message with "info" severity, typically used for general
 * informational output. Does not include file name, line number, or function name.
 * For full context, use ws_log_full instead.
 *
 * @param ...  printf-style format string and arguments for the log message.
 */
#define ws_info(...) \
        _LOG_SIMPLE(true, LOG_LEVEL_INFO, __VA_ARGS__)


/**
 * @def ws_debug
 * @brief Log a "debug" level message with source context.
 *
 * Emits a log message with "debug" severity, including file name,
 * line number, and function name. Logging occurs only if debugging
 * is enabled via _LOG_DEBUG_ENABLED.
 *
 * @param ...  printf-style format string and arguments for the log message.
 */
#define ws_debug(...) \
        _LOG_FULL(_LOG_DEBUG_ENABLED, LOG_LEVEL_DEBUG, __VA_ARGS__)

/**
 * @def ws_noisy
 * @brief Log a "noisy" level message with source context.
 *
 * Emits a log message with "noisy" severity, typically used for
 * verbose or low-level diagnostic output. Includes file name,
 * line number, and function name. Logging occurs only if debugging
 * is enabled via _LOG_DEBUG_ENABLED.
 *
 * @param ...  printf-style format string and arguments for the log message.
 */
#define ws_noisy(...) \
        _LOG_FULL(_LOG_DEBUG_ENABLED, LOG_LEVEL_NOISY, __VA_ARGS__)


/**
 * @def WS_DEBUG_HERE
 * @brief Emit a temporary debug message with source context.
 *
 * Used for ad-hoc or temporary debug printouts. Always active regardless of
 * log level settings. Includes file name, line number, and function name.
 *
 * @param ...  printf-style format string and arguments for the log message.
 */
#define WS_DEBUG_HERE(...) \
        _LOG_FULL(true, LOG_LEVEL_ECHO, __VA_ARGS__)

/**
 * @def WS_NOT_IMPLEMENTED
 * @brief Log a fatal error indicating unimplemented functionality.
 *
 * Emits an "error" level message and terminates the program with a coredump.
 * Used as a placeholder for unimplemented code paths.
 */
#define WS_NOT_IMPLEMENTED() \
        ws_error("Not implemented yet")


/**
 * @brief Output a UTF-8 encoded log message with source context.
 *
 * Emits a log message for the specified domain and level, including source file name,
 * line number, and function name. The message is provided as a UTF-8 string with
 * explicit length and optional end pointer for partial or bounded output.
 *
 * @param domain  Logging domain or subsystem name.
 * @param level   Log severity level.
 * @param file    Source file name where the log originated.
 * @param line    Line number in the source file.
 * @param func    Function name where the log was generated.
 * @param string  UTF-8 encoded message string.
 * @param length  Length of the message string in bytes.
 * @param endptr  Optional pointer to the end of the message range.
 */
WS_DLL_PUBLIC
void ws_log_utf8_full(const char *domain, enum ws_log_level level,
                    const char *file, long line, const char *func,
                    const char *string, ssize_t length, const char *endptr);


/**
 * @def ws_log_utf8
 * @brief Emit a UTF-8 debug log message with source context.
 *
 * Logs a UTF-8 encoded string at "debug" level, including file name,
 * line number, and function name. Logging occurs only if debugging
 * is enabled via _LOG_DEBUG_ENABLED.
 *
 * @param str      UTF-8 encoded message string.
 * @param len      Length of the message string in bytes.
 * @param endptr   Optional pointer to the end of the message range.
 */
#define ws_log_utf8(str, len, endptr) \
    do {                                                        \
        if (_LOG_DEBUG_ENABLED) {                               \
            ws_log_utf8_full(LOG_DOMAIN_UTF_8, LOG_LEVEL_DEBUG, \
                                __FILE__, __LINE__, __func__,   \
                                str, len, endptr);              \
        }                                                       \
    } while (0)


/**
 * @brief Output a formatted log message for a byte buffer with source context.
 *
 * Logs a buffer (byte array) at the specified domain and level, including
 * source file name, line number, and function name. An optional message
 * can be provided to describe the buffer contents.
 *
 * @param domain         Logging domain or subsystem name.
 * @param level          Log severity level.
 * @param file           Source file name where the log originated.
 * @param line           Line number in the source file.
 * @param func           Function name where the log was generated.
 * @param buffer         Pointer to the byte buffer to log.
 * @param size           Size of the buffer in bytes.
 * @param max_bytes_len  Maximum number of bytes to display in the log.
 * @param msg            Optional description of the buffer.
 */
WS_DLL_PUBLIC
void ws_log_buffer_full(const char *domain, enum ws_log_level level,
                    const char *file, long line, const char *func,
                    const uint8_t *buffer, size_t size,
                    size_t max_bytes_len, const char *msg);

/**
 * @def ws_log_buffer
 * @brief Log a byte buffer at debug level with source context.
 *
 * Emits a debug-level log message for a byte buffer, including file name,
 * line number, and function name. Displays up to 36 bytes. If no message
 * is provided, the buffer variable name is used as a fallback.
 *
 * @param buf    Pointer to the byte buffer.
 * @param size   Size of the buffer in bytes.
 * @param msg    Optional description of the buffer.
 */
#define ws_log_buffer(buf, size, msg) \
        do {                                                        \
            if (_LOG_DEBUG_ENABLED) {                               \
                ws_log_buffer_full(_LOG_DOMAIN, LOG_LEVEL_DEBUG,    \
                        __FILE__, __LINE__, __func__,               \
                        buf, size, 36, msg ? msg : #buf);           \
            }                                                       \
        } while (0)


/**
 * @brief Emit a log message unconditionally with full source context.
 *
 * This auxiliary function behaves like ws_log_full(), but skips domain/level
 * filtering to avoid redundant activation checks. It should only be used when
 * a prior call to ws_log_msg_is_active() confirms the message should be logged.
 *
 * @param domain  Logging domain or subsystem name.
 * @param level   Log severity level.
 * @param file    Source file name where the log originated.
 * @param line    Line number in the source file.
 * @param func    Function name where the log was generated.
 * @param format  printf-style format string for the log message.
 * @param ...     Variable arguments matching the format string.
 */
WS_DLL_PUBLIC
void ws_log_write_always_full(const char *domain, enum ws_log_level level,
                    const char *file, long line, const char *func,
                    const char *format, ...) G_GNUC_PRINTF(6,7);


/**
 * @brief Add an auxiliary file output for log messages.
 *
 * Defines an additional file pointer where log messages should be written.
 * This output is used in addition to the registered or default log writer.
 *
 * @param fp  File pointer to write log messages to.
 */
WS_DLL_PUBLIC
void ws_log_add_custom_file(FILE *fp);


/**
 * @brief Print usage information for logging-related command-line options.
 *
 * Writes a summary of supported logging options to the specified file,
 * typically used for help or diagnostic output.
 *
 * @param fp  File pointer to write usage information to.
 */
WS_DLL_PUBLIC
void ws_log_print_usage(FILE *fp);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WSLOG_H__ */
