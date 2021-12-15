/*
 * Copyright 2021, João Valverde <j@v6e.pt>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#if defined(WS_DISABLE_ASSERT) && !defined(NDEBUG)
#define NDEBUG
#endif

#include "wslog.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef _WIN32
#include <process.h>
#include <windows.h>
#endif

#include "file_util.h"
#include "time_util.h"
#include "to_str.h"
#include "strtoi.h"


/* Runtime log level. */
#define ENV_VAR_LEVEL       "WIRESHARK_LOG_LEVEL"

/* Log domains enabled/disabled. */
#define ENV_VAR_DOMAIN      "WIRESHARK_LOG_DOMAIN"

/* Alias "domain" and "domains". */
#define ENV_VAR_DOMAIN_S    "WIRESHARK_LOG_DOMAINS"

/* Log level that generates a trap and aborts. Can be "critical"
 * or "warning". */
#define ENV_VAR_FATAL       "WIRESHARK_LOG_FATAL"

/* Domains that will produce debug output, regardless of log level or
 * domain filter. */
#define ENV_VAR_DEBUG       "WIRESHARK_LOG_DEBUG"

/* Domains that will produce noisy output, regardless of log level or
 * domain filter. */
#define ENV_VAR_NOISY       "WIRESHARK_LOG_NOISY"

#define DEFAULT_LOG_LEVEL   LOG_LEVEL_MESSAGE

#define DEFAULT_PROGNAME    "PID"

#define DOMAIN_UNDEFED(domain)    ((domain) == NULL || *(domain) == '\0')
#define DOMAIN_DEFINED(domain)    (!DOMAIN_UNDEFED(domain))

#define VALID_FATAL_LEVEL(level) \
        (level >= LOG_LEVEL_WARNING && level <= LOG_LEVEL_ERROR)

/*
 * Note: I didn't measure it but I assume using a string array is faster than
 * a GHashTable for small number N of domains.
 */
typedef struct {
    char **domainv;
    gboolean positive;              /* positive or negative match */
    enum ws_log_level min_level;    /* for level filters */
} log_filter_t;


/* If the module is not initialized by calling ws_log_init() all messages
 * will be printed regardless of log level. This is a feature, not a bug. */
static enum ws_log_level current_log_level = LOG_LEVEL_NONE;

static gboolean stdout_color_enabled = FALSE;

static gboolean stderr_color_enabled = FALSE;

/* Use stdout for levels "info" and below, for backward compatibility
 * with GLib. */
static gboolean stdout_logging_enabled = FALSE;

static const char *registered_progname = DEFAULT_PROGNAME;

/* List of domains to filter. */
static log_filter_t *domain_filter = NULL;

/* List of domains to output debug level unconditionally. */
static log_filter_t *debug_filter = NULL;

/* List of domains to output noisy level unconditionally. */
static log_filter_t *noisy_filter = NULL;

static ws_log_writer_cb *registered_log_writer = NULL;

static void *registered_log_writer_data = NULL;

static ws_log_writer_free_data_cb *registered_log_writer_data_free = NULL;

static FILE *custom_log = NULL;

static enum ws_log_level fatal_log_level = LOG_LEVEL_ERROR;

#ifndef WS_DISABLE_DEBUG
static gboolean init_complete = FALSE;
#endif


static void print_err(void (*vcmdarg_err)(const char *, va_list ap),
                        int exit_failure,
                        const char *fmt, ...) G_GNUC_PRINTF(3,4);

static void ws_log_cleanup(void);


const char *ws_log_level_to_string(enum ws_log_level level)
{
    switch (level) {
        case LOG_LEVEL_NONE:
            return "(zero)";
        case LOG_LEVEL_ERROR:
            return "ERROR";
        case LOG_LEVEL_CRITICAL:
            return "CRITICAL";
        case LOG_LEVEL_WARNING:
            return "WARNING";
        case LOG_LEVEL_MESSAGE:
            return "MESSAGE";
        case LOG_LEVEL_INFO:
            return "INFO";
        case LOG_LEVEL_DEBUG:
            return "DEBUG";
        case LOG_LEVEL_NOISY:
            return "NOISY";
        default:
            return "(BOGUS LOG LEVEL)";
    }
}


static enum ws_log_level string_to_log_level(const char *str_level)
{
    if (!str_level)
        return LOG_LEVEL_NONE;

    if (g_ascii_strcasecmp(str_level, "noisy") == 0)
        return LOG_LEVEL_NOISY;
    else if (g_ascii_strcasecmp(str_level, "debug") == 0)
        return LOG_LEVEL_DEBUG;
    else if (g_ascii_strcasecmp(str_level, "info") == 0)
        return LOG_LEVEL_INFO;
    else if (g_ascii_strcasecmp(str_level, "message") == 0)
        return LOG_LEVEL_MESSAGE;
    else if (g_ascii_strcasecmp(str_level, "warning") == 0)
        return LOG_LEVEL_WARNING;
    else if (g_ascii_strcasecmp(str_level, "critical") == 0)
        return LOG_LEVEL_CRITICAL;
    else if (g_ascii_strcasecmp(str_level, "error") == 0)
        return LOG_LEVEL_ERROR;
    else
        return LOG_LEVEL_NONE;
}


WS_RETNONNULL
static inline const char *domain_to_string(const char *domain)
{
    return DOMAIN_UNDEFED(domain) ? "(none)" : domain;
}


static inline gboolean filter_contains(log_filter_t *filter,
                                            const char *domain)
{
    if (filter == NULL || DOMAIN_UNDEFED(domain))
        return FALSE;

    for (char **domv = filter->domainv; *domv != NULL; domv++) {
        if (g_ascii_strcasecmp(*domv, domain) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}


static inline gboolean level_filter_matches(log_filter_t *filter,
                                        const char *domain,
                                        enum ws_log_level level,
                                        gboolean *active_ptr)
{
    if (filter == NULL || DOMAIN_UNDEFED(domain))
        return FALSE;

    if (!filter_contains(filter, domain))
        return FALSE;

    if (filter->positive) {
        if (active_ptr)
            *active_ptr = level >= filter->min_level;
        return TRUE;
    }

    /* negative match */
    if (level <= filter->min_level) {
        if (active_ptr)
            *active_ptr = FALSE;
        return TRUE;
    }

    return FALSE;
}


gboolean ws_log_msg_is_active(const char *domain, enum ws_log_level level)
{
    /*
     * Higher numerical levels have higher priority. Critical and above
     * are always enabled.
     */
    if (level >= LOG_LEVEL_CRITICAL)
        return TRUE;

    /*
     * Check if the level has been configured as fatal.
     */
    if (level >= fatal_log_level)
        return TRUE;

    /*
     * The debug/noisy filter overrides the other parameters.
     */
    if (DOMAIN_DEFINED(domain)) {
        gboolean active;

        if (level_filter_matches(noisy_filter, domain, level, &active))
            return active;
        if (level_filter_matches(debug_filter, domain, level, &active))
            return active;
    }

    /*
     * If the priority is lower than the current minimum drop the
     * message.
     */
    if (level < current_log_level)
        return FALSE;

    /*
     * If we don't have domain filtering enabled we are done.
     */
    if (domain_filter == NULL)
        return TRUE;

    /*
     * We have a filter but we don't use it with the undefined domain,
     * pretty much every permanent call to ws_log should be using a
     * chosen domain.
     */
    if (DOMAIN_UNDEFED(domain))
        return TRUE;

    /* Check if the domain filter matches. */
    if (filter_contains(domain_filter, domain))
        return domain_filter->positive;

    /* We have a domain filter but it didn't match. */
    return !domain_filter->positive;
}


enum ws_log_level ws_log_get_level(void)
{
    return current_log_level;
}


void ws_log_set_level(enum ws_log_level level)
{
    if (level <= LOG_LEVEL_NONE || level >= _LOG_LEVEL_LAST)
        return;

    current_log_level = level;
}


enum ws_log_level ws_log_set_level_str(const char *str_level)
{
    enum ws_log_level level;

    level = string_to_log_level(str_level);
    if (level == LOG_LEVEL_NONE)
        return LOG_LEVEL_NONE;

    current_log_level = level;
    return current_log_level;
}


static const char *opt_level   = "--log-level";
/* Alias "domain" and "domains". */
static const char *opt_domain  = "--log-domain";
static const char *opt_file    = "--log-file";
static const char *opt_fatal   = "--log-fatal";
static const char *opt_debug   = "--log-debug";
static const char *opt_noisy   = "--log-noisy";


static void print_err(void (*vcmdarg_err)(const char *, va_list ap),
                        int exit_failure,
                        const char *fmt, ...)
{
    va_list ap;

    if (vcmdarg_err == NULL)
        return;

    va_start(ap, fmt);
    vcmdarg_err(fmt, ap);
    va_end(ap);
    if (exit_failure != LOG_ARGS_NOEXIT)
        exit(exit_failure);
}


/*
 * This tries to convert old log level preference to a wslog
 * configuration. The string must start with "console.log.level:"
 * It receives an argv for { '-o', 'console.log.level:nnn', ...} or
 * { '-oconsole.log.level:nnn', ...}.
 */
static void
parse_console_compat_option(char *argv[],
                        void (*vcmdarg_err)(const char *, va_list ap),
                        int exit_failure)
{
    const char *mask_str;
    guint32 mask;
    enum ws_log_level level;

    ws_assert(argv != NULL);

    if (argv[0] == NULL)
        return;

    if (strcmp(argv[0], "-o") == 0) {
        if (argv[1] == NULL ||
                    !g_str_has_prefix(argv[1], "console.log.level:")) {
            /* Not what we were looking for. */
            return;
        }
        mask_str = argv[1] + strlen("console.log.level:");
    }
    else if (g_str_has_prefix(argv[0], "-oconsole.log.level:")) {
        mask_str = argv[0] + strlen("-oconsole.log.level:");
    }
    else {
        /* Not what we were looking for. */
        return;
    }

    print_err(vcmdarg_err, LOG_ARGS_NOEXIT,
                "Option 'console.log.level' is deprecated, consult '--help' "
                "for diagnostic message options.");

    if (*mask_str == '\0') {
        print_err(vcmdarg_err, exit_failure,
                    "Missing value to 'console.log.level' option.");
        return;
    }

    if (!ws_basestrtou32(mask_str, NULL, &mask, 10)) {
        print_err(vcmdarg_err, exit_failure,
                    "%s is not a valid decimal number.", mask_str);
        return;
    }

    /*
     * The lowest priority bit in the mask defines the level.
     */
    if (mask & G_LOG_LEVEL_DEBUG)
        level = LOG_LEVEL_DEBUG;
    else if (mask & G_LOG_LEVEL_INFO)
        level = LOG_LEVEL_INFO;
    else if (mask & G_LOG_LEVEL_MESSAGE)
        level = LOG_LEVEL_MESSAGE;
    else if (mask & G_LOG_LEVEL_WARNING)
        level = LOG_LEVEL_WARNING;
    else if (mask & G_LOG_LEVEL_CRITICAL)
        level = LOG_LEVEL_CRITICAL;
    else if (mask & G_LOG_LEVEL_ERROR)
        level = LOG_LEVEL_ERROR;
    else
        level = LOG_LEVEL_NONE;

    if (level == LOG_LEVEL_NONE) {
        /* Some values (like zero) might not contain any meaningful bits.
         * Throwing an error in that case seems appropriate. */
        print_err(vcmdarg_err, exit_failure,
                    "Value %s is not a valid log mask.", mask_str);
        return;
    }

    ws_log_set_level(level);
}


int ws_log_parse_args(int *argc_ptr, char *argv[],
                        void (*vcmdarg_err)(const char *, va_list ap),
                        int exit_failure)
{
    char **ptr = argv;
    int count = *argc_ptr;
    int ret = 0;
    size_t optlen;
    const char *option, *value;
    int extra;

    if (argc_ptr == NULL || argv == NULL)
        return -1;

    /* Configure from command line. */

    while (*ptr != NULL) {
        if (g_str_has_prefix(*ptr, opt_level)) {
            option = opt_level;
            optlen = strlen(opt_level);
        }
        else if (g_str_has_prefix(*ptr, opt_domain)) {
            option = opt_domain;
            optlen = strlen(opt_domain);
            /* Alias "domain" and "domains". Last form wins. */
            if (*(*ptr + optlen) == 's') {
                optlen += 1;
            }
        }
        else if (g_str_has_prefix(*ptr, opt_file)) {
            option = opt_file;
            optlen = strlen(opt_file);
        }
        else if (g_str_has_prefix(*ptr, opt_fatal)) {
            option = opt_fatal;
            optlen = strlen(opt_fatal);
        }
        else if (g_str_has_prefix(*ptr, opt_debug)) {
            option = opt_debug;
            optlen = strlen(opt_debug);
        }
        else if (g_str_has_prefix(*ptr, opt_noisy)) {
            option = opt_noisy;
            optlen = strlen(opt_noisy);
        }
        else {
            /* Check is we have the old '-o console.log.level' flag,
             * or '-oconsole.log.level', for backward compatibility.
             * Then if we do ignore it after processing and let the
             * preferences module handle it later. */
            if (*(*ptr + 0) == '-' && *(*ptr + 1) == 'o') {
                parse_console_compat_option(ptr, vcmdarg_err, exit_failure);
            }
            ptr += 1;
            count -= 1;
            continue;
        }

        value = *ptr + optlen;
        /* Two possibilities:
         *      --<option> <value>
         * or
         *      --<option>=<value>
         */
        if (value[0] == '\0') {
            /* value is separated with blank space */
            value = *(ptr + 1);
            extra = 1;

            if (value == NULL || !*value || *value == '-') {
                /* If the option value after the blank starts with '-' assume
                 * it is another option. */
                print_err(vcmdarg_err, exit_failure,
                            "Option \"%s\" requires a value.\n", *ptr);
                option = NULL;
                extra = 0;
                ret += 1;
            }
        }
        else if (value[0] == '=') {
            /* value is after equals */
            value += 1;
            extra = 0;
        }
        else {
            /* Option isn't known. */
            ptr += 1;
            count -= 1;
            continue;
        }

        if (option == opt_level) {
            if (ws_log_set_level_str(value) == LOG_LEVEL_NONE) {
                print_err(vcmdarg_err, exit_failure,
                            "Invalid log level \"%s\".\n", value);
                ret += 1;
            }
        }
        else if (option == opt_domain) {
            ws_log_set_domain_filter(value);
        }
        else if (value && option == opt_file) {
            FILE *fp = ws_fopen(value, "w");
            if (fp == NULL) {
                print_err(vcmdarg_err, exit_failure,
                            "Error opening file '%s' for writing: %s.\n",
                            value, g_strerror(errno));
                ret += 1;
            }
            else {
                ws_log_add_custom_file(fp);
            }
        }
        else if (option == opt_fatal) {
            if (ws_log_set_fatal_str(value) == LOG_LEVEL_NONE) {
                print_err(vcmdarg_err, exit_failure,
                            "Fatal log level must be \"critical\" or "
                            "\"warning\", not \"%s\".\n", value);
                ret += 1;
            }
        }
        else if (option == opt_debug) {
            ws_log_set_debug_filter(value);
        }
        else if (option == opt_noisy) {
            ws_log_set_noisy_filter(value);
        }
        else {
            /* Option value missing or invalid, do nothing. */
        }

        /*
         * We found a log option. We will remove it from
         * the argv by moving up the other strings in the array. This is
         * so that it doesn't generate an unrecognized option
         * error further along in the initialization process.
         */
        /* Include the terminating NULL in the memmove. */
        memmove(ptr, ptr + 1 + extra, (count - extra) * sizeof(*ptr));
        /* No need to increment ptr here. */
        count -= (1 + extra);
        *argc_ptr -= (1 + extra);
    }

    return ret;
}


static void free_log_filter(log_filter_t **filter_ptr)
{
    if (filter_ptr == NULL || *filter_ptr == NULL)
        return;
    g_strfreev((*filter_ptr)->domainv);
    g_free(*filter_ptr);
    *filter_ptr = NULL;
}


static void tokenize_filter_str(log_filter_t **filter_ptr,
                                    const char *str_filter,
                                    enum ws_log_level min_level)
{
    char *tok, *str;
    const char *sep = ",;";
    GPtrArray *ptr;
    gboolean negated = FALSE;
    log_filter_t *filter;

    assert(filter_ptr);
    assert(*filter_ptr == NULL);

    if (str_filter == NULL)
        return;

    if (str_filter[0] == '!') {
        negated = TRUE;
        str_filter += 1;
    }
    if (*str_filter == '\0')
        return;

    ptr = g_ptr_array_new_with_free_func(g_free);
    str = g_strdup(str_filter);

    for (tok = strtok(str, sep); tok != NULL; tok = strtok(NULL, sep)) {
        g_ptr_array_add(ptr, g_strdup(tok));
    }

    g_free(str);
    if (ptr->len == 0) {
        g_ptr_array_free(ptr, TRUE);
        return;
    }
    g_ptr_array_add(ptr, NULL);

    filter = g_new(log_filter_t, 1);
    filter->domainv = (void *)g_ptr_array_free(ptr, FALSE);
    filter->positive = !negated;
    filter->min_level = min_level;
    *filter_ptr = filter;
}


void ws_log_set_domain_filter(const char *str_filter)
{
    free_log_filter(&domain_filter);
    tokenize_filter_str(&domain_filter, str_filter, LOG_LEVEL_NONE);
}


void ws_log_set_debug_filter(const char *str_filter)
{
    free_log_filter(&debug_filter);
    tokenize_filter_str(&debug_filter, str_filter, LOG_LEVEL_DEBUG);
}


void ws_log_set_noisy_filter(const char *str_filter)
{
    free_log_filter(&noisy_filter);
    tokenize_filter_str(&noisy_filter, str_filter, LOG_LEVEL_NOISY);
}


void ws_log_set_fatal(enum ws_log_level level)
{
    if (!VALID_FATAL_LEVEL(level))
        return;

    fatal_log_level = level;
}


enum ws_log_level ws_log_set_fatal_str(const char *str_level)
{
    enum ws_log_level level;

    level = string_to_log_level(str_level);
    if (!VALID_FATAL_LEVEL(level))
        return LOG_LEVEL_NONE;

    fatal_log_level = level;
    return fatal_log_level;
}


void ws_log_set_writer(ws_log_writer_cb *writer)
{
    if (registered_log_writer_data_free)
        registered_log_writer_data_free(registered_log_writer_data);

    registered_log_writer = writer;
    registered_log_writer_data = NULL;
    registered_log_writer_data_free = NULL;
}


void ws_log_set_writer_with_data(ws_log_writer_cb *writer,
                        void *user_data,
                        ws_log_writer_free_data_cb *free_user_data)
{
    if (registered_log_writer_data_free)
        registered_log_writer_data_free(registered_log_writer_data);

    registered_log_writer = writer;
    registered_log_writer_data = user_data;
    registered_log_writer_data_free = free_user_data;
}


static void glib_log_handler(const char *domain, GLogLevelFlags flags,
                        const char *message, gpointer user_data _U_)
{
    enum ws_log_level level;

    /*
     * The highest priority bit in the mask defines the level. We
     * ignore the GLib fatal log level mask and use our own fatal
     * log level setting instead.
     */

    if (flags & G_LOG_LEVEL_ERROR)
        level = LOG_LEVEL_ERROR;
    else if (flags & G_LOG_LEVEL_CRITICAL)
        level = LOG_LEVEL_CRITICAL;
    else if (flags & G_LOG_LEVEL_WARNING)
        level = LOG_LEVEL_WARNING;
    else if (flags & G_LOG_LEVEL_MESSAGE)
        level = LOG_LEVEL_MESSAGE;
    else if (flags & G_LOG_LEVEL_INFO)
        level = LOG_LEVEL_INFO;
    else if (flags & G_LOG_LEVEL_DEBUG)
        level = LOG_LEVEL_DEBUG;
    else
        level = LOG_LEVEL_NONE; /* Should not happen. */

    ws_log(domain, level, "%s", message);
}


/*
 * We can't write to stderr in ws_log_init() because dumpcap uses stderr
 * to communicate with the parent and it will block. We have to use
 * vcmdarg_err to report errors.
 */
void ws_log_init(const char *progname,
                            void (*vcmdarg_err)(const char *, va_list ap))
{
    const char *env;

    if (progname != NULL) {
        registered_progname = progname;
        g_set_prgname(progname);
    }

    current_log_level = DEFAULT_LOG_LEVEL;

#if GLIB_CHECK_VERSION(2,50,0)
    stdout_color_enabled = g_log_writer_supports_color(fileno(stdout));
    stderr_color_enabled = g_log_writer_supports_color(fileno(stderr));
#elif !defined(_WIN32)
    /* We assume every non-Windows console supports color. */
    stdout_color_enabled = (isatty(fileno(stdout)) == 1);
    stderr_color_enabled = (isatty(fileno(stderr)) == 1);
#else
     /* Our Windows build version of GLib is pretty recent, we are probably
      * fine here, unless we want to do better than GLib. */
    stdout_color_enabled = stderr_color_enabled = FALSE;
#endif

    /* Set the GLib log handler for the default domain. */
    g_log_set_handler(NULL, G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL,
                        glib_log_handler, NULL);

    /* Set the GLib log handler for GLib itself. */
    g_log_set_handler("GLib", G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL,
                        glib_log_handler, NULL);

    atexit(ws_log_cleanup);

    /* Configure from environment. */

    env = g_getenv(ENV_VAR_LEVEL);
    if (env != NULL) {
        if (ws_log_set_level_str(env) == LOG_LEVEL_NONE) {
            print_err(vcmdarg_err, LOG_ARGS_NOEXIT,
                        "Ignoring invalid environment value %s=\"%s\"",
                        ENV_VAR_LEVEL, env);
        }
    }

    env = g_getenv(ENV_VAR_FATAL);
    if (env != NULL) {
        if (ws_log_set_fatal_str(env) == LOG_LEVEL_NONE) {
            print_err(vcmdarg_err, LOG_ARGS_NOEXIT,
                        "Ignoring invalid environment value %s=\"%s\"",
                        ENV_VAR_FATAL, env);
        }
    }

    /* Alias "domain" and "domains". The plural form wins. */
    if ((env = g_getenv(ENV_VAR_DOMAIN_S)) != NULL)
        ws_log_set_domain_filter(env);
    else if ((env = g_getenv(ENV_VAR_DOMAIN)) != NULL)
        ws_log_set_domain_filter(env);

    env = g_getenv(ENV_VAR_DEBUG);
    if (env != NULL)
        ws_log_set_debug_filter(env);

    env = g_getenv(ENV_VAR_NOISY);
    if (env != NULL)
        ws_log_set_noisy_filter(env);

#ifndef WS_DISABLE_DEBUG
    init_complete = TRUE;
#endif
}


void ws_log_init_with_writer(const char *progname,
                            ws_log_writer_cb *writer,
                            void (*vcmdarg_err)(const char *, va_list ap))
{
    registered_log_writer = writer;
    ws_log_init(progname, vcmdarg_err);
}


void ws_log_init_with_writer_and_data(const char *progname,
                            ws_log_writer_cb *writer,
                            void *user_data,
                            ws_log_writer_free_data_cb *free_user_data,
                            void (*vcmdarg_err)(const char *, va_list ap))
{
    registered_log_writer_data = user_data;
    registered_log_writer_data_free = free_user_data;
    ws_log_init_with_writer(progname, writer, vcmdarg_err);
}


#define MAGENTA "\033[35m"
#define BLUE    "\033[34m"
#define CYAN    "\033[36m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define RED     "\033[31m"
#define RESET   "\033[0m"

static inline const char *level_color_on(gboolean enable,
                                            enum ws_log_level level)
{
    if (!enable)
        return "";

    if (level <= LOG_LEVEL_DEBUG)
        return GREEN;
    else if (level <= LOG_LEVEL_MESSAGE)
        return CYAN;
    else if (level <= LOG_LEVEL_WARNING)
        return YELLOW;
    else if (level <= LOG_LEVEL_CRITICAL)
        return MAGENTA;
    else if (level <= LOG_LEVEL_ERROR)
        return RED;
    else
        return "";
}

static inline const char *color_off(gboolean enable)
{
    return enable ? RESET : "";
}

#define NANOSECS_IN_MICROSEC 1000

/*
 * We must not call anything that might log a message
 * in the log handler context (GLib might log a message if we register
 * our own handler for the GLib domain).
 */
static void log_write_do_work(FILE *fp, gboolean use_color,
                                struct tm *when, long nanosecs,
                                const char *domain,  enum ws_log_level level,
                                const char *file, int line, const char *func,
                                const char *user_format, va_list user_ap)
{
#ifndef WS_DISABLE_DEBUG
    if (!init_complete)
        fputs(" ** (noinit)", fp);
#endif

    /* Process */
    fprintf(fp, " ** (%s:%ld) ", registered_progname, (long)getpid());

    /* Timestamp */
    if (when != NULL && nanosecs >= 0)
        fprintf(fp, "%02d:%02d:%02d.%06ld ",
                            when->tm_hour, when->tm_min, when->tm_sec,
                            nanosecs / NANOSECS_IN_MICROSEC);
    else if (when != NULL)
        fprintf(fp, "%02d:%02d:%02d ",
                            when->tm_hour, when->tm_min, when->tm_sec);
    else
        fputs("(notime) ", fp);

    /* Domain/level */
    fprintf(fp, "[%s %s%s%s] ", domain_to_string(domain),
                                level_color_on(use_color, level),
                                ws_log_level_to_string(level),
                                color_off(use_color));

    /* File/line */
    if (file != NULL && line >= 0)
        fprintf(fp, "%s:%d ", file, line);
    else if (file != NULL)
        fprintf(fp, "%s ", file);

    fputs("-- ", fp);

    /* Function name */
    if (func != NULL)
        fprintf(fp, "%s(): ", func);

    /* User message */
    vfprintf(fp, user_format, user_ap);
    fputc('\n', fp);
    fflush(fp);
}


static inline struct tm *get_localtime(time_t unix_time, struct tm **cookie)
{
    if (unix_time == (time_t)-1)
        return NULL;
    if (cookie && *cookie)
        return *cookie;
    struct tm *when = localtime(&unix_time);
    if (cookie)
        *cookie = when;
    return when;
}


static inline FILE *console_file(enum ws_log_level level)
{
    if (level <= LOG_LEVEL_INFO && stdout_logging_enabled)
        return stdout;
    return stderr;
}


static inline bool console_color_enabled(enum ws_log_level level)
{
    if (level <= LOG_LEVEL_INFO && stdout_logging_enabled)
        return stdout_color_enabled;
    return stderr_color_enabled;
}


/*
 * We must not call anything that might log a message
 * in the log handler context (GLib might log a message if we register
 * our own handler for the GLib domain).
 */
static void log_write_dispatch(const char *domain, enum ws_log_level level,
                            const char *file, int line, const char *func,
                            const char *user_format, va_list user_ap)
{
    struct timespec tstamp;
    struct tm *cookie = NULL;

    ws_clock_get_realtime(&tstamp);

    if (custom_log) {
        va_list user_ap_copy;

        va_copy(user_ap_copy, user_ap);
        log_write_do_work(custom_log, FALSE,
                            get_localtime(tstamp.tv_sec, &cookie),
                            tstamp.tv_nsec,
                            domain, level, file, line, func,
                            user_format, user_ap_copy);
        va_end(user_ap_copy);
    }

    if (registered_log_writer) {
        registered_log_writer(domain, level, tstamp, file, line, func,
                        user_format, user_ap, registered_log_writer_data);
    }
    else {
        log_write_do_work(console_file(level), console_color_enabled(level),
                            get_localtime(tstamp.tv_sec, &cookie),
                            tstamp.tv_nsec,
                            domain, level, file, line, func,
                            user_format, user_ap);
    }

    if (level >= fatal_log_level) {
        abort();
    }
}


void ws_logv(const char *domain, enum ws_log_level level,
                    const char *format, va_list ap)
{
    if (!ws_log_msg_is_active(domain, level))
        return;

    log_write_dispatch(domain, level, NULL, -1, NULL, format, ap);
}


void ws_logv_full(const char *domain, enum ws_log_level level,
                    const char *file, int line, const char *func,
                    const char *format, va_list ap)
{
    if (!ws_log_msg_is_active(domain, level))
        return;

    log_write_dispatch(domain, level, file, line, func, format, ap);
}


void ws_log(const char *domain, enum ws_log_level level,
                    const char *format, ...)
{
    if (!ws_log_msg_is_active(domain, level))
        return;

    va_list ap;

    va_start(ap, format);
    log_write_dispatch(domain, level, NULL, -1, NULL, format, ap);
    va_end(ap);
}


void ws_log_full(const char *domain, enum ws_log_level level,
                    const char *file, int line, const char *func,
                    const char *format, ...)
{
    if (!ws_log_msg_is_active(domain, level))
        return;

    va_list ap;

    va_start(ap, format);
    log_write_dispatch(domain, level, file, line, func, format, ap);
    va_end(ap);
}


void ws_log_write_always_full(const char *domain, enum ws_log_level level,
                    const char *file, int line, const char *func,
                    const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    log_write_dispatch(domain, level, file, line, func, format, ap);
    va_end(ap);
}


void ws_log_buffer_full(const char *domain, enum ws_log_level level,
                    const char *file, int line, const char *func,
                    const guint8 *ptr, size_t size,  size_t max_bytes_len,
                    const char *msg)
{
    if (!ws_log_msg_is_active(domain, level))
        return;

    char *bufstr = bytes_to_str_maxlen(NULL, ptr, size, max_bytes_len);

    if (G_UNLIKELY(msg == NULL))
        ws_log_write_always_full(domain, level, file, line, func,
                                "<buffer:%p>: %s (%zu bytes)",
                                ptr, bufstr, size);
    else
        ws_log_write_always_full(domain, level, file, line, func,
                                "%s: %s (%zu bytes)",
                                msg, bufstr, size);
    wmem_free(NULL, bufstr);
}


void ws_log_file_writer(FILE *fp, const char *domain, enum ws_log_level level,
                            struct timespec timestamp,
                            const char *file, int line, const char *func,
                            const char *user_format, va_list user_ap)
{
    log_write_do_work(fp, FALSE,
                        get_localtime(timestamp.tv_sec, NULL),
                        timestamp.tv_nsec,
                        domain, level, file, line, func,
                        user_format, user_ap);
}


void ws_log_console_writer(const char *domain, enum ws_log_level level,
                            struct timespec timestamp,
                            const char *file, int line, const char *func,
                            const char *user_format, va_list user_ap)
{
    log_write_do_work(console_file(level), console_color_enabled(level),
                        get_localtime(timestamp.tv_sec, NULL),
                        timestamp.tv_nsec,
                        domain, level, file, line, func,
                        user_format, user_ap);
}


WS_DLL_PUBLIC
void ws_log_console_writer_set_use_stdout(bool use_stdout)
{
    stdout_logging_enabled = use_stdout;
}


static void ws_log_cleanup(void)
{
    if (registered_log_writer_data_free) {
        registered_log_writer_data_free(registered_log_writer_data);
        registered_log_writer_data = NULL;
    }
    if (custom_log) {
        fclose(custom_log);
        custom_log = NULL;
    }
    free_log_filter(&domain_filter);
    free_log_filter(&debug_filter);
    free_log_filter(&noisy_filter);
}


void ws_log_add_custom_file(FILE *fp)
{
    if (custom_log != NULL) {
        fclose(custom_log);
    }
    custom_log = fp;
}


#define USAGE_LEVEL \
    "sets the active log level (\"critical\", \"warning\", etc.)"

#define USAGE_FATAL \
    "sets level to abort the program (\"critical\" or \"warning\")"

#define USAGE_DOMAINS \
    "comma separated list of the active log domains"

#define USAGE_DEBUG \
    "comma separated list of domains with \"debug\" level"

#define USAGE_NOISY \
    "comma separated list of domains with \"noisy\" level"

#define USAGE_FILE \
    "file to output messages to (in addition to stderr)"

void ws_log_print_usage(FILE *fp)
{
    fprintf(fp, "Diagnostic output:\n");
    fprintf(fp, "  --log-level <level>      " USAGE_LEVEL "\n");
    fprintf(fp, "  --log-fatal <level>      " USAGE_FATAL "\n");
    fprintf(fp, "  --log-domains <[!]list>  " USAGE_DOMAINS "\n");
    fprintf(fp, "  --log-debug <[!]list>    " USAGE_DEBUG "\n");
    fprintf(fp, "  --log-noisy <[!]list>    " USAGE_NOISY "\n");
    fprintf(fp, "  --log-file <path>        " USAGE_FILE "\n");
}
