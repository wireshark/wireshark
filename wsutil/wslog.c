/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2021 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
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
#endif

#include "file_util.h"


/* Runtime log level. */
#define ENV_VAR_LEVEL       "WIRESHARK_LOG_LEVEL"

/* Log domains enabled/disabled. */
#define ENV_VAR_DOMAINS     "WIRESHARK_LOG_DOMAINS"

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

/*
 * Note: I didn't measure it but I assume using a string array is faster than
 * a GHashTable for small number N of domains.
 */
typedef struct {
    char **domainv;
    gboolean positive;              /* positive or negative match */
    enum ws_log_level min_level;    /* for level filters */
} log_filter_t;


static enum ws_log_level current_log_level = LOG_LEVEL_NONE;

static gboolean color_enabled = FALSE;

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
    return (domain == NULL) ? "(none)" : domain;
}


static inline gboolean filter_contains(log_filter_t *filter, const char *domain)
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

    if (filter_contains(filter, domain) == FALSE)
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


enum ws_log_level ws_log_set_level(enum ws_log_level log_level)
{
    if (log_level > LOG_LEVEL_NONE && log_level < _LOG_LEVEL_LAST)
        current_log_level = log_level;

    return current_log_level;
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
static const char *opt_domains = "--log-domains";
static const char *opt_file    = "--log-file";
static const char *opt_fatal   = "--log-fatal";
static const char *opt_debug   = "--log-debug";
static const char *opt_noisy   = "--log-noisy";


static void print_err(void (*log_args_print_err)(const char *, va_list ap),
                        int log_args_exit_failure,
                        const char *fmt, ...)
{
    va_list ap;

    if (log_args_print_err == NULL)
        return;

    va_start(ap, fmt);
    log_args_print_err(fmt, ap);
    va_end(ap);
    if (log_args_exit_failure >= 0)
        exit(log_args_exit_failure);
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
    int prune_extra;

    while (*ptr != NULL) {
        if (g_str_has_prefix(*ptr, opt_level)) {
            option = opt_level;
            optlen = strlen(opt_level);
        }
        else if (g_str_has_prefix(*ptr, opt_domains)) {
            option = opt_domains;
            optlen = strlen(opt_domains);
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
            prune_extra = 1;

            if (value == NULL || !*value || *value == '-') {
                /* If the option value after the blank starts with '-' assume
                 * it is another option. */
                print_err(vcmdarg_err, exit_failure,
                            "Option \"%s\" requires a value.\n", *ptr);
                option = NULL;
                prune_extra = 0;
                ret += 1;
            }
        }
        else if (value[0] == '=') {
            /* value is after equals */
            value += 1;
            prune_extra = 0;
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
        else if (option == opt_domains) {
            ws_log_set_domain_filter(value);
        }
        else if (option == opt_file) {
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
        memmove(ptr, ptr + 1 + prune_extra, (count - prune_extra) * sizeof(*ptr));
        /* No need to increment ptr here. */
        count -= (1 + prune_extra);
        *argc_ptr -= (1 + prune_extra);
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


static void tokenize_filter_str(log_filter_t **filter_ptr, const char *str_filter,
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


enum ws_log_level ws_log_set_fatal(enum ws_log_level log_level)
{
    /* Not possible to set lower priority than "warning" to fatal. */
    if (log_level < LOG_LEVEL_WARNING)
        return LOG_LEVEL_NONE;

    fatal_log_level = log_level;
    return fatal_log_level;
}


enum ws_log_level ws_log_set_fatal_str(const char *str_level)
{
    enum ws_log_level level = string_to_log_level(str_level);
    return ws_log_set_fatal(level);
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
 * to communicate with the parent and it will block. Any failures are
 * therefore ignored.
 */
void ws_log_init(const char *progname, ws_log_writer_cb *writer)
{
    const char *env;

    if (progname != NULL) {
        registered_progname = progname;
        g_set_prgname(progname);
    }

    if (writer)
        registered_log_writer = writer;

#if GLIB_CHECK_VERSION(2,50,0)
    color_enabled = g_log_writer_supports_color(fileno(stderr));
#elif !defined(_WIN32)
    /* We assume every non-Windows console supports color. */
    color_enabled = (isatty(fileno(stderr)) == 1);
#else
     /* Our Windows build version of GLib is pretty recent, we are probably
      * fine here, unless we want to do better than GLib. */
    color_enabled = FALSE;
#endif

    current_log_level = DEFAULT_LOG_LEVEL;

    env = g_getenv(ENV_VAR_LEVEL);
    if (env != NULL)
        ws_log_set_level_str(env);

    env = g_getenv(ENV_VAR_FATAL);
    if (env != NULL)
        ws_log_set_fatal_str(env);

    env = g_getenv(ENV_VAR_DOMAINS);
    if (env != NULL)
        ws_log_set_domain_filter(env);

    env = g_getenv(ENV_VAR_DEBUG);
    if (env != NULL)
        ws_log_set_debug_filter(env);

    env = g_getenv(ENV_VAR_NOISY);
    if (env != NULL)
        ws_log_set_noisy_filter(env);

    /* Set the GLib log handler for the default domain. */
    g_log_set_handler(NULL, G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL,
                        glib_log_handler, NULL);

    /* Set the GLib log handler for GLib itself. */
    g_log_set_handler("GLib", G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL,
                        glib_log_handler, NULL);

    atexit(ws_log_cleanup);

#ifndef WS_DISABLE_DEBUG
    init_complete = TRUE;
#endif
}


void ws_log_init_with_data(const char *progname, ws_log_writer_cb *writer,
                            void *user_data,
                            ws_log_writer_free_data_cb *free_user_data)
{
    registered_log_writer_data = user_data;
    registered_log_writer_data_free = free_user_data;
    ws_log_init(progname, writer);
}


#define MAGENTA "\033[35m"
#define BLUE    "\033[34m"
#define CYAN    "\033[36m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define RED     "\033[31m"
#define RESET   "\033[0m"

static inline const char *msg_color_on(gboolean enable, enum ws_log_level level)
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

static void log_write_do_work(FILE *fp, gboolean use_color, const char *timestamp,
                                const char *domain,  enum ws_log_level level,
                                const char *file, int line, const char *func,
                                const char *user_format, va_list user_ap)
{
    const char *domain_str = domain_to_string(domain);
    const char *level_str = ws_log_level_to_string(level);
    gboolean doextra = (level != DEFAULT_LOG_LEVEL);

#ifndef WS_DISABLE_DEBUG
    if (!init_complete) {
        fprintf(fp, " ** (noinit)");
    }
#endif

    /* Process name */
    fprintf(fp, " ** (%s:%ld) ", registered_progname, (long)getpid());

    /* Timestamp */
    if (timestamp != NULL) {
        fputs(timestamp, fp);
        fputc(' ', fp);
    }

    /* Message priority (domain/level) */
    fprintf(fp, "[%s %s%s%s] ", domain_str,
                                msg_color_on(use_color, level),
                                level_str,
                                color_off(use_color));

    /* File/line */
    if (doextra && file != NULL && line >= 0)
        fprintf(fp, "%s:%d ", file, line);
    else if (doextra && file != NULL)
        fprintf(fp, "%s ", file);

    fputs("-- ", fp);

    /* Function name */
    if (doextra && func != NULL)
        fprintf(fp, "%s(): ", func);

    /* User message */
    vfprintf(fp, user_format, user_ap);
    fputc('\n', fp);
    fflush(fp);
}


static void log_write_dispatch(const char *domain, enum ws_log_level level,
                            const char *file, int line, const char *func,
                            const char *user_format, va_list user_ap)
{
    GDateTime *now;
    char *tstamp = NULL;

    now = g_date_time_new_now_local();
    if (now) {
        tstamp = g_date_time_format(now, "%H:%M:%S.%f");
        g_date_time_unref(now);
    }

    if (custom_log) {
        va_list user_ap_copy;

        G_VA_COPY(user_ap_copy, user_ap);
        log_write_do_work(custom_log, FALSE,
                            tstamp, domain, level,
                            file, line, func,
                            user_format, user_ap_copy);
        va_end(user_ap_copy);
    }

    if (registered_log_writer) {
        registered_log_writer(domain, level, tstamp, file, line, func,
                        user_format, user_ap, registered_log_writer_data);
    }
    else {
        log_write_do_work(stderr, color_enabled, tstamp, domain, level, file, line, func,
                        user_format, user_ap);
    }

    g_free(tstamp);

    if (level >= fatal_log_level) {
        abort();
    }
}


void ws_logv(const char *domain, enum ws_log_level level,
                    const char *format, va_list ap)
{

    if (ws_log_msg_is_active(domain, level) == FALSE)
        return;

    log_write_dispatch(domain, level, NULL, -1, NULL, format, ap);
}


void ws_logv_full(const char *domain, enum ws_log_level level,
                    const char *file, int line, const char *func,
                    const char *format, va_list ap)
{
    if (ws_log_msg_is_active(domain, level) == FALSE)
        return;

    log_write_dispatch(domain, level, file, line, func, format, ap);
}


void ws_log(const char *domain, enum ws_log_level level,
                    const char *format, ...)
{
    va_list ap;

    if (ws_log_msg_is_active(domain, level) == FALSE)
        return;

    va_start(ap, format);
    log_write_dispatch(domain, level, NULL, -1, NULL, format, ap);
    va_end(ap);
}


void ws_log_full(const char *domain, enum ws_log_level level,
                    const char *file, int line, const char *func,
                    const char *format, ...)
{
    va_list ap;

    if (ws_log_msg_is_active(domain, level) == FALSE)
        return;

    va_start(ap, format);
    log_write_dispatch(domain, level, file, line, func, format, ap);
    va_end(ap);
}


void ws_log_default_writer(const char *domain, enum ws_log_level level,
                            const char *timestamp,
                            const char *file, int line, const char *func,
                            const char *user_format, va_list user_ap,
                            void *user_data _U_)
{
    log_write_do_work(stderr, color_enabled, timestamp, domain, level, file, line, func, user_format, user_ap);
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


void ws_log_print_usage(FILE *fp)
{
    fprintf(fp, "Diagnostic output:\n");
    fprintf(fp, "  --log-level <level>      one of \"critical\", \"warning\", \"message\", "
                                            "\"info\", \"debug\" or \"noisy\"\n");
    fprintf(fp, "  --log-fatal <level>      one of \"critical\" or \"warning\", causes level "
                                            "to abort the program\n");
    fprintf(fp, "  --log-domains <[!]list>  comma separated list of the active log domains\n");
    fprintf(fp, "  --log-debug <[!]list>    comma separated list of domains with \"debug\" level\n");
    fprintf(fp, "  --log-noisy <[!]list>    comma separated list of domains with \"noisy\" level\n");
    fprintf(fp, "  --log-file <path>        path of file to output messages to (in addition to stderr)\n");
}
