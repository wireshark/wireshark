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
#include <stdarg.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef _WIN32
#include <process.h>
#endif
#include <ws_attributes.h>

#include <wsutil/ws_assert.h>
#include <wsutil/file_util.h>


#define ENV_VAR_LEVEL       "WIRESHARK_LOG_LEVEL"
#define ENV_VAR_DOMAINS     "WIRESHARK_LOG_DOMAINS"

#define DEFAULT_LOG_LEVEL   LOG_LEVEL_MESSAGE


static enum ws_log_level current_log_level = LOG_LEVEL_NONE;

static gboolean color_enabled = FALSE;

static const char *registered_appname = NULL;

static GPtrArray *domain_filter = NULL;

static ws_log_writer_cb *registered_log_writer = NULL;

static void *registered_log_writer_data = NULL;

static ws_log_writer_free_data_cb *registered_log_writer_data_free = NULL;

static FILE *custom_log = NULL;


static void ws_log_cleanup(void);


const char *ws_log_level_to_string(enum ws_log_level level)
{
    switch (level) {
        case LOG_LEVEL_NONE:
            return "(none)";
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
        default:
            return "(BOGUS LOG LEVEL)";
    }
}


gboolean ws_log_level_is_active(enum ws_log_level level)
{
    return level <= current_log_level;
}


gboolean ws_log_domain_is_active(const char *domain)
{
    if (domain_filter == NULL)
        return TRUE;

    /* We don't filter the default domain. Default means undefined, pretty much
     * every permanent call to ws_log should be using a chosen domain. */
    if (strcmp(domain, LOG_DOMAIN_DEFAULT) == 0)
        return TRUE;

    for (guint i = 0; i < domain_filter->len; i++) {
        if (g_ascii_strcasecmp(domain_filter->pdata[i], domain) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}


static gboolean log_drop_message(const char *domain, enum ws_log_level level)
{
    if (level <= LOG_LEVEL_CRITICAL)
        return FALSE;

    return !ws_log_level_is_active(level) || !ws_log_domain_is_active(domain);
}


enum ws_log_level ws_log_get_level(void)
{
    return current_log_level;
}


enum ws_log_level ws_log_set_level(enum ws_log_level log_level)
{
    ws_assert(log_level > LOG_LEVEL_NONE && log_level < _LOG_LEVEL_LAST);

    current_log_level = log_level;
    return current_log_level;
}


enum ws_log_level ws_log_set_level_str(const char *str_level)
{
    enum ws_log_level level;

    if (!str_level)
        return LOG_LEVEL_NONE;

    if (g_ascii_strcasecmp(str_level, "debug") == 0)
        level = LOG_LEVEL_DEBUG;
    else if (g_ascii_strcasecmp(str_level, "info") == 0)
        level = LOG_LEVEL_INFO;
    else if (g_ascii_strcasecmp(str_level, "message") == 0)
        level = LOG_LEVEL_MESSAGE;
    else if (g_ascii_strcasecmp(str_level, "warning") == 0)
        level = LOG_LEVEL_WARNING;
    else if (g_ascii_strcasecmp(str_level, "critical") == 0)
        level = LOG_LEVEL_CRITICAL;
    else if (g_ascii_strcasecmp(str_level, "error") == 0)
        level = LOG_LEVEL_ERROR;
    else
        return LOG_LEVEL_NONE;

    current_log_level = level;
    return current_log_level;
}


static const char *opt_level   = "--log-level";
static const char *opt_domains = "--log-domains";
static const char *opt_file    = "--log-file";


int ws_log_parse_args(int *argc_ptr, char *argv[], void (*print_err)(const char *, ...))
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
                print_err("Option \"%s\" requires a value.\n", *ptr);
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
                print_err("Invalid log level \"%s\"\n", value);
                ret += 1;
            }
        }
        else if (option == opt_domains) {
            ws_log_set_domain_filter_str(value);
        }
        else if (option == opt_file) {
            FILE *fp = ws_fopen(value, "w");
            if (fp == NULL) {
                print_err("Error opening file '%s' for writing: %s\n", value, g_strerror(errno));
                ret += 1;
            }
            else {
                ws_log_add_custom_file(fp);
            }
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


void ws_log_set_domain_filter_str(const char *str_filter)
{
    char *tok;
    const char *sep = ",;";
    char *str;

    if (domain_filter != NULL)
        g_ptr_array_free(domain_filter, TRUE);

    domain_filter = g_ptr_array_new_with_free_func(g_free);

    str = g_strdup(str_filter);

    for (tok = strtok(str, sep); tok != NULL; tok = strtok(NULL, sep)) {
        g_ptr_array_add(domain_filter, g_strdup(tok));
    }

    g_free(str);
}


void ws_log_init(ws_log_writer_cb *writer)
{
    const char *env;

    registered_appname = g_get_prgname();

    if (writer)
        registered_log_writer = writer;

#if GLIB_CHECK_VERSION(2,50,0)
    color_enabled = g_log_writer_supports_color(ws_fileno(stderr));
#elif !defined(_WIN32)
    /* We assume every non-Windows console supports color. */
    color_enabled = (ws_isatty(ws_fileno(stderr)) == 1);
#else
     /* Our Windows build version of GLib is pretty recent, we are probably
      * fine here, unless we want to do better than GLib. */
    color_enabled = FALSE;
#endif

    current_log_level = DEFAULT_LOG_LEVEL;

    env = g_getenv(ENV_VAR_LEVEL);
    if (env != NULL && ws_log_set_level_str(env) == LOG_LEVEL_NONE) {
        fprintf(stderr, "Ignoring invalid environment value %s=\"%s\"\n", ENV_VAR_LEVEL, env);
    }

    env = g_getenv(ENV_VAR_DOMAINS);
    if (env != NULL)
        ws_log_set_domain_filter_str(env);

    atexit(ws_log_cleanup);
}


void ws_log_init_with_data(ws_log_writer_cb *writer, void *user_data,
                              ws_log_writer_free_data_cb *free_user_data)
{
    registered_log_writer_data = user_data;
    registered_log_writer_data_free = free_user_data;
    ws_log_init(writer);
}


static inline const char *color_on(gboolean enable)
{
    return enable ? "\033[34m" : ""; /* blue */
}

static inline const char *color_off(gboolean enable)
{
    return enable ? "\033[0m" : "";
}

static void log_write_do_work(FILE *fp, gboolean use_color, const char *timestamp,
                                const char *domain,  enum ws_log_level level,
                                const char *file, int line, const char *func,
                                const char *user_format, va_list user_ap)
{
    const char *level_str = ws_log_level_to_string(level);
    gboolean doextra = (level != LOG_LEVEL_MESSAGE);

    if (doextra) {
        fprintf(fp, " ** (%s:%ld) ", registered_appname ?
                        registered_appname : "PID", (long)getpid());
    }
    else {
        fputs(" ** ", fp);
    }

    if (timestamp) {
        fputs(timestamp, fp);
        fputc(' ', fp);
    }

    if (strcmp(domain, LOG_DOMAIN_DEFAULT) != 0) {
        fprintf(fp, "[%s-%s] ", domain, level_str);
    }
    else {
        fprintf(fp, "[%s] ", level_str);
    }

    if (doextra) {
        if (file && line >= 0) {
            fprintf(fp, "%s:%d ", file, line);
        }
        else if (file) {
            fprintf(fp, "%s ", file);
        }
        fputs("-- ", fp);
        if (func) {
            fprintf(fp, "%s%s()%s: " , color_on(use_color), func, color_off(use_color));
        }
    }

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

    if (registered_log_writer) {
        registered_log_writer(domain, level, tstamp, file, line, func,
                        user_format, user_ap, registered_log_writer_data);
    }
    else {
        log_write_do_work(stderr, color_enabled, tstamp, domain, level, file, line, func,
                        user_format, user_ap);
    }

    if (custom_log) {
        log_write_do_work(custom_log, FALSE, tstamp, domain, level, file, line, func,
                        user_format, user_ap);
    }

    g_free(tstamp);

    if (level == LOG_LEVEL_ERROR) {
        G_BREAKPOINT();
        ws_assert_not_reached();
    }
}


void ws_logv(const char *domain, enum ws_log_level level,
                    const char *format, va_list ap)
{
    if (domain == NULL || domain[0] == '\0')
        domain = LOG_DOMAIN_DEFAULT;

    if (log_drop_message(domain, level))
        return;

    log_write_dispatch(domain, level, NULL, -1, NULL, format, ap);
}


void ws_logv_full(const char *domain, enum ws_log_level level,
                    const char *file, int line, const char *func,
                    const char *format, va_list ap)
{
    if (domain == NULL || domain[0] == '\0')
        domain = LOG_DOMAIN_DEFAULT;

    if (log_drop_message(domain, level))
        return;

    log_write_dispatch(domain, level, file, line, func, format, ap);
}


void ws_log(const char *domain, enum ws_log_level level,
                    const char *format, ...)
{
    va_list ap;

    if (domain == NULL || domain[0] == '\0')
        domain = LOG_DOMAIN_DEFAULT;

    if (log_drop_message(domain, level))
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

    if (domain == NULL || domain[0] == '\0')
        domain = LOG_DOMAIN_DEFAULT;

    if (log_drop_message(domain, level))
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
    if (domain_filter) {
        g_ptr_array_free(domain_filter, TRUE);
        domain_filter = NULL;
    }
}


void ws_log_add_custom_file(FILE *fp)
{
        if (custom_log != NULL) {
            fclose(custom_log);
        }
        custom_log = fp;
}
