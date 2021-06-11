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
#include <time.h>
#include <stdarg.h>
#include <ws_attributes.h>

#include <wsutil/ws_assert.h>
#include <wsutil/time_util.h>

#define PREFIX_BUFSIZE  128

#define _ENV_LEVEL "WIRESHARK_LOG_LEVEL"
#define _ENV_DOMAINS "WIRESHARK_LOG_DOMAINS"


/* TODO: Add filtering by domain. */

static enum ws_log_level current_log_level = LOG_LEVEL_MESSAGE;

GPtrArray *domain_filter = NULL;

static ws_log_writer_cb *registered_log_writer = NULL;

static void *registered_log_writer_data = NULL;

static ws_log_writer_free_data_cb *registered_log_writer_data_free = NULL;

static FILE *custom_log = NULL;


static void ws_log_cleanup(void);


void
ws_log_fprint(FILE *fp, const char *format, va_list ap,
                                const char *prefix)
{
    fputs(prefix, fp);
    vfprintf(fp, format, ap);
    fputc('\n', fp);
    fflush(fp);
}


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

    for (guint i = 0; i < domain_filter->len; i++) {
        if (g_ascii_strcasecmp(domain_filter->pdata[i], domain) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}


static gboolean log_drop_message(const char *domain, enum ws_log_level level)
{
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


static const char *log_prune_argv(int count, char **ptr, int prune_extra,
                                const char *optarg, int *ret_argc)
{
    /*
     * We found a log option. We will remove it from
     * the argv by moving up the other strings in the array. This is
     * so that it doesn't generate an unrecognized option
     * error further along in the initialization process.
     */

    /* Include the terminating NULL in the memmove. */
    memmove(ptr, ptr + 1 + prune_extra, (count - prune_extra) * sizeof(*ptr));
    *ret_argc -= (1 + prune_extra);
    return optarg;
}

const char *log_parse_args(int *argc_ptr, char *argv[], const char *optstr)
{
    char **p;
    int c;
    size_t optlen = strlen(optstr);
    const char *optarg;

    for (p = argv, c = *argc_ptr; *p != NULL; p++, c--) {
        if (strncmp(*p, optstr, optlen) == 0) {
            optarg = *p + optlen;
            /* Two possibilities:
             *      --<option> <value>
             * or
             *      --<option>=<value>
             */
            if (optarg[0] == '\0') {
                /* value is separated with blank space */
                optarg = *(p + 1);

                /* If the option value after the blank is missing or stars with '-' just ignore it.
                 * But we should probably signal an error (missing required value). */
                if (optarg == NULL || !*optarg || *optarg == '-') {
                    return log_prune_argv(c, p, 0, NULL, argc_ptr);
                }
                return log_prune_argv(c, p, 1, optarg, argc_ptr);
            }
            else if (optarg[0] == '=') {
                /* value is after equals */
                optarg += 1;
                return log_prune_argv(c, p, 0, optarg, argc_ptr);
            }
            /* we didn't find what we want */
        }
    }
    return NULL; /* No log-level option, ignore and return success. */
}


const char *ws_log_set_level_args(int *argc_ptr, char *argv[])
{
    const char *optval = NULL;
    enum ws_log_level level;

    optval = log_parse_args(argc_ptr, argv, "--log-level");
    if (optval == NULL)
        return NULL;

    level = ws_log_set_level_str(optval);
    if (level == LOG_LEVEL_NONE)
        return optval;

    return NULL;
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

void ws_log_set_domain_filter_args(int *argc_ptr, char *argv[])
{
    const char *optval = NULL;

    optval = log_parse_args(argc_ptr, argv, "--log-domains");
    if (optval == NULL)
        return;

    ws_log_set_domain_filter_str(optval);
}


void ws_log_init(ws_log_writer_cb *_writer)
{
    if (_writer) {
        registered_log_writer = _writer;
    }

    const char *env;

    env = g_getenv(_ENV_LEVEL);
    if (env && ws_log_set_level_str(env) == LOG_LEVEL_NONE) {
        fprintf(stderr, "Ignoring invalid environment value %s=\"%s\"\n", _ENV_LEVEL, env);
    }

    env = g_getenv(_ENV_DOMAINS);
    if (env)
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


static inline const char *_lvl_to_str(enum ws_log_level level)
{
    switch (level) {
        case LOG_LEVEL_NONE:       return "(NONE)";
        case LOG_LEVEL_ERROR:      return "ERROR";
        case LOG_LEVEL_CRITICAL:   return "CRITICAL";
        case LOG_LEVEL_WARNING:    return "WARNING";
        case LOG_LEVEL_MESSAGE:    return "MESSAGE";
        case LOG_LEVEL_INFO:       return "INFO";
        case LOG_LEVEL_DEBUG:      return "DEBUG";
        default:
            return "(BOGUS LOG LEVEL)";
    }
}


struct logstr {
    char buffer[PREFIX_BUFSIZE];
    char *ptr;
    int free;
};


static inline void logstr_init(struct logstr *str)
{
    str->free = (int)(sizeof(str->buffer) - 1);
    str->buffer[sizeof(str->buffer) - 1] = '\0';
    str->ptr = str->buffer;

#ifndef WS_DISABLE_ASSERT
    memset(str->buffer, 0, sizeof(str->buffer));
#endif
}


static inline int logstr_snprintf(struct logstr *str, const char *fmt, ...)
{
    int write;
    va_list ap;

    if (str->free <= 0)
        return -1;

    va_start(ap, fmt);
    write = vsnprintf(str->ptr, str->free, fmt, ap);
    va_end(ap);

    if (write < 0 || write >= str->free) {
        str->ptr = NULL;
        str->free = -1;
        return -1;
    }

    str->ptr += write;
    ws_assert(str->ptr < str->buffer + sizeof(str->buffer));
    str->free -= write;
    ws_assert(str->free > 0);
    return 0;
}


static void create_log_time(struct logstr *str)
{
    time_t curr;
    struct tm *today;
    guint64 microseconds;

    time(&curr);
    today = localtime(&curr);
    microseconds = create_timestamp();

    if (G_UNLIKELY(today == NULL)) {
        logstr_snprintf(str, " ** ");
        return;
    }

    logstr_snprintf(str, " ** %02d:%02d:%02d.%03" G_GUINT64_FORMAT,
                today->tm_hour, today->tm_min, today->tm_sec,
                microseconds % 1000000 / 1000);
}


static void logstr_prefix_print(struct logstr *str,
                                const char *domain,  enum ws_log_level level,
                                const char *file, int line, const char *func)
{
    create_log_time(str);

    logstr_snprintf(str, " [%s-%s]", domain, _lvl_to_str(level));

    if (func)
        logstr_snprintf(str, " %s()", func);
    else if (file && line >= 0)
        logstr_snprintf(str, " (%d)%s", file, line);
    else if (file)
        logstr_snprintf(str, " %s", file);

    logstr_snprintf(str, " -- ");
}


static void log_internal_write(const char *domain, enum ws_log_level level,
                            const char *file, int line, const char *func,
                            const char *user_format, va_list user_ap)
{
    struct logstr prefix;

    logstr_init(&prefix);

    logstr_prefix_print(&prefix, domain, level, file, line, func);

    /* Call the registered writer, or the default if one wasn't registered. */
    if (registered_log_writer) {
        registered_log_writer(user_format, user_ap, prefix.buffer,
                                domain, level, registered_log_writer_data);
    }
    else {
        ws_log_fprint(stderr, user_format, user_ap, prefix.buffer);
    }

    /* If we have a custom file, write to it _also_. */
    if (custom_log) {
        ws_log_fprint(custom_log, user_format, user_ap, prefix.buffer);
    }

    if (level == LOG_LEVEL_ERROR) {
        G_BREAKPOINT();
        ws_assert_not_reached();
    }
}


void ws_logv(const char *domain, enum ws_log_level level,
                    const char *format, va_list ap)
{
    if (log_drop_message(domain, level))
        return;

    log_internal_write(domain, level, NULL, -1, NULL, format, ap);
}


void ws_log(const char *domain, enum ws_log_level level,
                    const char *format, ...)
{
    va_list ap;

    if (log_drop_message(domain, level))
        return;

    va_start(ap, format);
    log_internal_write(domain, level, NULL, -1, NULL, format, ap);
    va_end(ap);
}


void ws_log_full(const char *domain, enum ws_log_level level,
                    const char *file, int line, const char *func,
                    const char *format, ...)
{
    va_list ap;

    if (log_drop_message(domain, level))
        return;

    va_start(ap, format);
    log_internal_write(domain, level, file, line, func, format, ap);
    va_end(ap);
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
            custom_log = NULL;
        }
        if (fp != NULL) {
            custom_log = fp;
        }
}
