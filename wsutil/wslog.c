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

#include "wslog.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
/* Because ws_assert() dependes on ws_error() we do not use it
 * here and fall back on assert() instead. */
#include <assert.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef _WIN32
#include <process.h>
#include <windows.h>
#include <conio.h>
#endif

#include "file_util.h"
#include "time_util.h"
#include "to_str.h"
#include "strtoi.h"
#ifdef _WIN32
#include "console_win32.h"
#endif

#define ASSERT(expr)    assert(expr)

/* Runtime log level. */
#define ENV_VAR_LEVEL       "WIRESHARK_LOG_LEVEL"

/* Log domains enabled/disabled. */
#define ENV_VAR_DOMAIN      "WIRESHARK_LOG_DOMAIN"

/* Alias "domain" and "domains". */
#define ENV_VAR_DOMAIN_S    "WIRESHARK_LOG_DOMAINS"

/* Log level that generates a trap and aborts. Can be "critical"
 * or "warning". */
#define ENV_VAR_FATAL       "WIRESHARK_LOG_FATAL"

/* Log domains that are fatal. */
#define ENV_VAR_FATAL_DOMAIN    "WIRESHARK_LOG_FATAL_DOMAIN"

/* Alias "domain" and "domains". */
#define ENV_VAR_FATAL_DOMAIN_S  "WIRESHARK_LOG_FATAL_DOMAINS"

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
    bool positive;                  /* positive or negative match */
    enum ws_log_level min_level;    /* for level filters */
} log_filter_t;


/* If the module is not initialized by calling ws_log_init() all messages
 * will be printed regardless of log level. This is a feature, not a bug. */
static enum ws_log_level current_log_level = LOG_LEVEL_NONE;

static bool stdout_color_enabled;

static bool stderr_color_enabled;

/* Use stdout for levels "info" and below, for backward compatibility
 * with GLib. */
static bool stdout_logging_enabled;

static const char *registered_progname = DEFAULT_PROGNAME;

/* List of domains to filter. */
static log_filter_t *domain_filter;

/* List of domains to output debug level unconditionally. */
static log_filter_t *debug_filter;

/* List of domains to output noisy level unconditionally. */
static log_filter_t *noisy_filter;

/* List of domains that are fatal. */
static log_filter_t *fatal_filter;

static ws_log_writer_cb *registered_log_writer;

static void *registered_log_writer_data;

static ws_log_writer_free_data_cb *registered_log_writer_data_free;

static FILE *custom_log;

static enum ws_log_level fatal_log_level = LOG_LEVEL_ERROR;

#ifdef WS_DEBUG
static bool init_complete;
#endif

ws_log_console_open_pref ws_log_console_open = LOG_CONSOLE_OPEN_NEVER;


static void print_err(void (*vcmdarg_err)(const char *, va_list ap),
                        int exit_failure,
                        const char *fmt, ...) G_GNUC_PRINTF(3,4);

static void ws_log_cleanup(void);


const char *ws_log_level_to_string(enum ws_log_level level)
{
    switch (level) {
        case LOG_LEVEL_NONE:
            return "(zero)";
        case LOG_LEVEL_ECHO:
            return "ECHO";
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
    else if (g_ascii_strcasecmp(str_level, "echo") == 0)
        return LOG_LEVEL_ECHO;
    else
        return LOG_LEVEL_NONE;
}


WS_RETNONNULL
static inline const char *domain_to_string(const char *domain)
{
    return DOMAIN_UNDEFED(domain) ? "(none)" : domain;
}


static inline bool filter_contains(log_filter_t *filter,
                                            const char *domain)
{
    if (filter == NULL || DOMAIN_UNDEFED(domain))
        return false;

    for (char **domv = filter->domainv; *domv != NULL; domv++) {
        if (g_ascii_strcasecmp(*domv, domain) == 0) {
            return true;
        }
    }
    return false;
}


static inline bool level_filter_matches(log_filter_t *filter,
                                        const char *domain,
                                        enum ws_log_level level,
                                        bool *active_ptr)
{
    if (filter == NULL || DOMAIN_UNDEFED(domain))
        return false;

    if (!filter_contains(filter, domain))
        return false;

    if (filter->positive) {
        if (active_ptr)
            *active_ptr = level >= filter->min_level;
        return true;
    }

    /* negative match */
    if (level <= filter->min_level) {
        if (active_ptr)
            *active_ptr = false;
        return true;
    }

    return false;
}


static inline void
get_timestamp(struct timespec *ts)
{
    bool ok = false;

#if defined(HAVE_CLOCK_GETTIME)
    ok = (clock_gettime(CLOCK_REALTIME, ts) == 0);
#elif defined(HAVE_TIMESPEC_GET)
    ok = (timespec_get(ts, TIME_UTC) == TIME_UTC);
#endif
    if (ok)
        return;

    /* Fall back on time(). */
    ts->tv_sec = time(NULL);
    ts->tv_nsec = -1;
}


static inline void fill_manifest(ws_log_manifest_t *mft)
{
    struct timespec ts;
    get_timestamp(&ts);
    ws_localtime_r(&ts.tv_sec, &mft->tstamp_secs);
    mft->nanosecs = ts.tv_nsec;
    mft->pid = getpid();
}


static inline bool msg_is_active(const char *domain, enum ws_log_level level,
                                    ws_log_manifest_t *mft)
{
    bool is_active = ws_log_msg_is_active(domain, level);
    if (is_active)
        fill_manifest(mft);
    return is_active;
}


bool ws_log_msg_is_active(const char *domain, enum ws_log_level level)
{
    /*
     * Higher numerical levels have higher priority. Critical and above
     * are always enabled.
     */
    if (level >= LOG_LEVEL_CRITICAL)
        return true;

    /*
     * Check if the level has been configured as fatal.
     */
    if (level >= fatal_log_level)
        return true;

    /*
     * Check if the domain has been configured as fatal.
     */
    if (DOMAIN_DEFINED(domain) && fatal_filter != NULL) {
        if (filter_contains(fatal_filter, domain) && fatal_filter->positive) {
            return true;
        }
    }

    /*
     * The debug/noisy filter overrides the other parameters.
     */
    if (DOMAIN_DEFINED(domain)) {
        bool active;

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
        return false;

    /*
     * If we don't have domain filtering enabled we are done.
     */
    if (domain_filter == NULL)
        return true;

    /*
     * We have a filter but we don't use it with the undefined domain,
     * pretty much every permanent call to ws_log should be using a
     * chosen domain.
     */
    if (DOMAIN_UNDEFED(domain))
        return true;

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


enum ws_log_level ws_log_set_level(enum ws_log_level level)
{
    if (level <= LOG_LEVEL_NONE || level >= _LOG_LEVEL_LAST)
        return LOG_LEVEL_NONE;
    if (level > LOG_LEVEL_CRITICAL)
        level = LOG_LEVEL_CRITICAL;

    current_log_level = level;
    return current_log_level;
}


enum ws_log_level ws_log_set_level_str(const char *str_level)
{
    enum ws_log_level level;

    level = string_to_log_level(str_level);
    return ws_log_set_level(level);
}


static const char *opt_level   = "--log-level";
static const char *opt_domain  = "--log-domain";
/* Alias "domain" and "domains". */
static const char *opt_domain_s = "--log-domains";
static const char *opt_file    = "--log-file";
static const char *opt_fatal   = "--log-fatal";
static const char *opt_fatal_domain = "--log-fatal-domain";
/* Alias "domain" and "domains". */
static const char *opt_fatal_domain_s = "--log-fatal-domains";
static const char *opt_debug   = "--log-debug";
static const char *opt_noisy   = "--log-noisy";


static void print_err(void (*vcmdarg_err)(const char *, va_list ap),
                        int exit_failure,
                        const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    if (vcmdarg_err)
        vcmdarg_err(fmt, ap);
    else
        vfprintf(stderr, fmt, ap);
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
    uint32_t mask;
    enum ws_log_level level;

    ASSERT(argv != NULL);

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

/* Match "arg_name=value" or "arg_name value" to opt_name. */
static bool optequal(const char *arg, const char *opt)
{
    ASSERT(arg);
    ASSERT(opt);
#define ARGEND(arg) (*(arg) == '\0' || *(arg) == ' ' || *(arg) == '=')

    while (!ARGEND(arg) && *opt != '\0') {
        if (*arg != *opt) {
            return false;
        }
        arg += 1;
        opt += 1;
    }
    if (ARGEND(arg) && *opt == '\0') {
        return true;
    }
    return false;
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

#ifdef WS_DEBUG
    /* Assert ws_log_init() was called before ws_log_parse_args(). */
    ASSERT(init_complete);
#endif

    /* Configure from command line. */

    while (*ptr != NULL) {
        if (optequal(*ptr, opt_level)) {
            option = opt_level;
            optlen = strlen(opt_level);
        }
        else if (optequal(*ptr, opt_domain)) {
            option = opt_domain;
            optlen = strlen(opt_domain);
        }
        else if (optequal(*ptr, opt_domain_s)) {
            option = opt_domain; /* Alias */
            optlen = strlen(opt_domain_s);
        }
        else if (optequal(*ptr, opt_fatal_domain)) {
            option = opt_fatal_domain;
            optlen = strlen(opt_fatal_domain);
        }
        else if (optequal(*ptr, opt_fatal_domain_s)) {
            option = opt_fatal_domain; /* Alias */
            optlen = strlen(opt_fatal_domain_s);
        }
        else if (optequal(*ptr, opt_file)) {
            option = opt_file;
            optlen = strlen(opt_file);
        }
        else if (optequal(*ptr, opt_fatal)) {
            option = opt_fatal;
            optlen = strlen(opt_fatal);
        }
        else if (optequal(*ptr, opt_debug)) {
            option = opt_debug;
            optlen = strlen(opt_debug);
        }
        else if (optequal(*ptr, opt_noisy)) {
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
        else if (option == opt_fatal_domain) {
            ws_log_set_fatal_domain_filter(value);
        }
        else if (option == opt_file) {
            if (value == NULL) {
                print_err(vcmdarg_err, exit_failure,
                            "Option '%s' requires an argument.\n",
                            option);
                ret += 1;
            }
            else {
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
        }
        else if (option == opt_fatal) {
            if (ws_log_set_fatal_level_str(value) == LOG_LEVEL_NONE) {
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
    const char *sep = ",;";
    bool negated = false;
    log_filter_t *filter;

    ASSERT(filter_ptr);
    ASSERT(*filter_ptr == NULL);

    if (str_filter == NULL)
        return;

    if (str_filter[0] == '!') {
        negated = true;
        str_filter += 1;
    }
    if (*str_filter == '\0')
        return;

    filter = g_new(log_filter_t, 1);
    filter->domainv = g_strsplit_set(str_filter, sep, -1);
    filter->positive = !negated;
    filter->min_level = min_level;
    *filter_ptr = filter;
}


void ws_log_set_domain_filter(const char *str_filter)
{
    free_log_filter(&domain_filter);
    tokenize_filter_str(&domain_filter, str_filter, LOG_LEVEL_NONE);
}


void ws_log_set_fatal_domain_filter(const char *str_filter)
{
    free_log_filter(&fatal_filter);
    tokenize_filter_str(&fatal_filter, str_filter, LOG_LEVEL_NONE);
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


enum ws_log_level ws_log_set_fatal_level(enum ws_log_level level)
{
    if (level <= LOG_LEVEL_NONE || level >= _LOG_LEVEL_LAST)
        return LOG_LEVEL_NONE;
    if (level > LOG_LEVEL_ERROR)
        level = LOG_LEVEL_ERROR;
    if (level < LOG_LEVEL_WARNING)
        level = LOG_LEVEL_WARNING;

    fatal_log_level = level;
    return fatal_log_level;
}


enum ws_log_level ws_log_set_fatal_level_str(const char *str_level)
{
    enum ws_log_level level;

    level = string_to_log_level(str_level);
    return ws_log_set_fatal_level(level);
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
                        const char *message, void * user_data _U_)
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


#ifdef _WIN32
static void load_registry(void)
{
    LONG lResult;
    DWORD ptype;
    DWORD data;
    DWORD data_size = sizeof(DWORD);

    lResult = RegGetValueA(HKEY_CURRENT_USER,
                            "Software\\Wireshark",
                            LOG_HKCU_CONSOLE_OPEN,
                            RRF_RT_REG_DWORD,
                            &ptype,
                            &data,
                            &data_size);
    if (lResult != ERROR_SUCCESS || ptype != REG_DWORD) {
        return;
    }

    ws_log_console_open = (ws_log_console_open_pref)data;
}
#endif


/*
 * We can't write to stderr in ws_log_init() because dumpcap uses stderr
 * to communicate with the parent and it will block. We have to use
 * vcmdarg_err to report errors.
 */
void ws_log_init(const char *progname,
                            void (*vcmdarg_err)(const char *, va_list ap))
{
    const char *env;
    int fd;

    if (progname != NULL) {
        registered_progname = progname;
        g_set_prgname(progname);
    }

    ws_tzset();

    current_log_level = DEFAULT_LOG_LEVEL;

    if ((fd = fileno(stdout)) >= 0)
        stdout_color_enabled = g_log_writer_supports_color(fd);
    if ((fd = fileno(stderr)) >= 0)
        stderr_color_enabled = g_log_writer_supports_color(fd);

    /* Set ourselves as the default log handler for all GLib domains. */
    g_log_set_default_handler(glib_log_handler, NULL);

#ifdef _WIN32
    load_registry();

    /* if the user wants a console to be always there, well, we should open one for him */
    if (ws_log_console_open == LOG_CONSOLE_OPEN_ALWAYS) {
        create_console();
    }
#endif

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
        if (ws_log_set_fatal_level_str(env) == LOG_LEVEL_NONE) {
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

    /* Alias "domain" and "domains". The plural form wins. */
    if ((env = g_getenv(ENV_VAR_FATAL_DOMAIN_S)) != NULL)
        ws_log_set_fatal_domain_filter(env);
    else if ((env = g_getenv(ENV_VAR_FATAL_DOMAIN)) != NULL)
        ws_log_set_fatal_domain_filter(env);

    env = g_getenv(ENV_VAR_DEBUG);
    if (env != NULL)
        ws_log_set_debug_filter(env);

    env = g_getenv(ENV_VAR_NOISY);
    if (env != NULL)
        ws_log_set_noisy_filter(env);

#ifdef WS_DEBUG
    init_complete = true;
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

static inline const char *level_color_on(bool enable, enum ws_log_level level)
{
    if (!enable)
        return "";

    switch (level) {
        case LOG_LEVEL_NOISY:
        case LOG_LEVEL_DEBUG:
            return GREEN;
        case LOG_LEVEL_INFO:
        case LOG_LEVEL_MESSAGE:
            return CYAN;
        case LOG_LEVEL_WARNING:
            return YELLOW;
        case LOG_LEVEL_CRITICAL:
            return MAGENTA;
        case LOG_LEVEL_ERROR:
            return RED;
        case LOG_LEVEL_ECHO:
            return YELLOW;
        default:
            break;
    }
    return "";
}

static inline const char *color_off(bool enable)
{
    return enable ? RESET : "";
}

#define NANOSECS_IN_MICROSEC 1000

/*
 * We must not call anything that might log a message
 * in the log handler context (GLib might log a message if we register
 * our own handler for the GLib domain).
 */
static void log_write_do_work(FILE *fp, bool use_color,
                                struct tm *when, long nanosecs, intmax_t pid,
                                const char *domain, enum ws_log_level level,
                                const char *file, long line, const char *func,
                                const char *user_format, va_list user_ap)
{
    fputs(" **", fp);

#ifdef WS_DEBUG
    if (!init_complete)
        fputs(" no init!", fp);
#endif

    /* Process */
    fprintf(fp, " (%s:%"PRIdMAX")", registered_progname, pid);

    /* Timestamp */
    if (when != NULL) {
        fprintf(fp, " %02d:%02d:%02d",
                            when->tm_hour, when->tm_min, when->tm_sec);
        if (nanosecs >= 0) {
            fprintf(fp, ".%06ld", nanosecs / NANOSECS_IN_MICROSEC);
        }
    }

    /* Domain/level */
    fprintf(fp, " [%s %s%s%s]", domain_to_string(domain),
                                level_color_on(use_color, level),
                                ws_log_level_to_string(level),
                                color_off(use_color));

    /* File/line */
    if (file != NULL) {
        fprintf(fp, " %s", file);
        if (line >= 0) {
            fprintf(fp, ":%ld", line);
        }
    }

    /* Any formatting changes here need to be synced with ui/capture.c:capture_input_closed. */
    fputs(" --", fp);

    /* Function name */
    if (func != NULL)
        fprintf(fp, " %s():", func);

    /* User message */
    fputc(' ', fp);
    vfprintf(fp, user_format, user_ap);
    fputc('\n', fp);
    fflush(fp);
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


static void log_write_fatal_msg(FILE *fp, intmax_t pid, const char *msg)
{
    /* Process */
    fprintf(fp, " ** (%s:%"PRIdMAX") %s", registered_progname, pid, msg);
}


/*
 * We must not call anything that might log a message
 * in the log handler context (GLib might log a message if we register
 * our own handler for the GLib domain).
 */
static void log_write_dispatch(const char *domain, enum ws_log_level level,
                            const char *file, long line, const char *func,
                            ws_log_manifest_t *mft,
                            const char *user_format, va_list user_ap)
{
    bool fatal_event = false;
    const char *fatal_msg = NULL;
    va_list user_ap_copy;

    if (level >= fatal_log_level && level != LOG_LEVEL_ECHO) {
        fatal_event = true;
        fatal_msg = "Aborting on fatal log level exception\n";
    }
    else if (fatal_filter != NULL) {
        if (filter_contains(fatal_filter, domain) && fatal_filter->positive) {
            fatal_event = true;
            fatal_msg = "Aborting on fatal log domain exception\n";
        }
    }

#ifdef _WIN32
    if (ws_log_console_open != LOG_CONSOLE_OPEN_NEVER) {
        create_console();
    }
#endif /* _WIN32 */

    if (custom_log) {
        va_copy(user_ap_copy, user_ap);
        log_write_do_work(custom_log, false,
                            &mft->tstamp_secs, mft->nanosecs, mft->pid,
                            domain, level, file, line, func,
                            user_format, user_ap_copy);
        va_end(user_ap_copy);
        if (fatal_msg) {
            log_write_fatal_msg(custom_log, mft->pid, fatal_msg);
        }
    }

    if (registered_log_writer) {
        registered_log_writer(domain, level, file, line, func, fatal_msg, mft,
                        user_format, user_ap, registered_log_writer_data);
    }
    else {
        log_write_do_work(console_file(level), console_color_enabled(level),
                            &mft->tstamp_secs, mft->nanosecs, mft->pid,
                            domain, level, file, line, func,
                            user_format, user_ap);
        if (fatal_msg) {
            log_write_fatal_msg(console_file(level), mft->pid, fatal_msg);
        }
    }

#ifdef _WIN32
    if (fatal_event && ws_log_console_open != LOG_CONSOLE_OPEN_NEVER) {
        /* wait for a key press before the following error handler will terminate the program
            this way the user at least can read the error message */
        printf("\n\nPress any key to exit\n");
        _getch();
    }
#endif /* _WIN32 */

    if (fatal_event) {
        abort();
    }
}


void ws_logv(const char *domain, enum ws_log_level level,
                    const char *format, va_list ap)
{
    ws_log_manifest_t mft;
    if (!msg_is_active(domain, level, &mft))
        return;

    log_write_dispatch(domain, level, NULL, -1, NULL, &mft, format, ap);
}


void ws_logv_full(const char *domain, enum ws_log_level level,
                    const char *file, long line, const char *func,
                    const char *format, va_list ap)
{
    ws_log_manifest_t mft;
    if (!msg_is_active(domain, level, &mft))
        return;

    log_write_dispatch(domain, level, file, line, func, &mft, format, ap);
}


void ws_log(const char *domain, enum ws_log_level level,
                    const char *format, ...)
{
    ws_log_manifest_t mft;
    if (!msg_is_active(domain, level, &mft))
        return;

    va_list ap;

    va_start(ap, format);
    log_write_dispatch(domain, level, NULL, -1, NULL, &mft, format, ap);
    va_end(ap);
}


void ws_log_full(const char *domain, enum ws_log_level level,
                    const char *file, long line, const char *func,
                    const char *format, ...)
{
    ws_log_manifest_t mft;
    if (!msg_is_active(domain, level, &mft))
        return;

    va_list ap;

    va_start(ap, format);
    log_write_dispatch(domain, level, file, line, func, &mft, format, ap);
    va_end(ap);
}


void ws_log_fatal_full(const char *domain, enum ws_log_level level,
                    const char *file, long line, const char *func,
                    const char *format, ...)
{
    ws_log_manifest_t mft;
    va_list ap;

    fill_manifest(&mft);
    va_start(ap, format);
    log_write_dispatch(domain, level, file, line, func, &mft, format, ap);
    va_end(ap);
    abort();
}


void ws_log_write_always_full(const char *domain, enum ws_log_level level,
                    const char *file, long line, const char *func,
                    const char *format, ...)
{
    ws_log_manifest_t mft;
    va_list ap;

    fill_manifest(&mft);
    va_start(ap, format);
    log_write_dispatch(domain, level, file, line, func, &mft, format, ap);
    va_end(ap);
}


static void
append_trailer(const char *src, size_t src_length, wmem_strbuf_t *display, wmem_strbuf_t *underline)
{
    gunichar ch;
    size_t hex_len;

    while (src_length > 0) {
        ch = g_utf8_get_char_validated(src, src_length);
        if (ch == (gunichar)-1 || ch == (gunichar)-2) {
            wmem_strbuf_append_hex(display, *src);
            wmem_strbuf_append_c_count(underline, '^', 4);
            src += 1;
            src_length -= 1;
        }
        else {
            if (g_unichar_isprint(ch)) {
                wmem_strbuf_append_unichar(display, ch);
                wmem_strbuf_append_c_count(underline, ' ', 1);
            }
            else {
                hex_len = wmem_strbuf_append_hex_unichar(display, ch);
                wmem_strbuf_append_c_count(underline, ' ', hex_len);
            }
            const char *tmp = g_utf8_next_char(src);
            src_length -= tmp - src;
            src = tmp;
        }
    }
}


static char *
make_utf8_display(const char *src, size_t src_length, size_t good_length)
{
    wmem_strbuf_t *display;
    wmem_strbuf_t *underline;
    gunichar ch;
    size_t hex_len;

    display = wmem_strbuf_create(NULL);
    underline = wmem_strbuf_create(NULL);

    for (const char *s = src; s < src + good_length; s = g_utf8_next_char(s)) {
        ch = g_utf8_get_char(s);

        if (g_unichar_isprint(ch)) {
            wmem_strbuf_append_unichar(display, ch);
            wmem_strbuf_append_c(underline, ' ');
        }
        else {
            hex_len = wmem_strbuf_append_hex_unichar(display, ch);
            wmem_strbuf_append_c_count(underline, ' ', hex_len);
        }
    }

    append_trailer(&src[good_length], src_length - good_length, display, underline);

    wmem_strbuf_append_c(display, '\n');
    wmem_strbuf_append(display, underline->str);
    wmem_strbuf_destroy(underline);

    return wmem_strbuf_finalize(display);
}


void ws_log_utf8_full(const char *domain, enum ws_log_level level,
                    const char *file, long line, const char *func,
                    const char *string, ssize_t _length, const char *endptr)
{
    if (!ws_log_msg_is_active(domain, level))
        return;

    char *display;
    size_t length;
    size_t good_length;

    if (_length < 0)
        length = strlen(string);
    else
        length = _length;

    if (endptr == NULL || endptr < string) {
        /* Find the pointer to the first invalid byte. */
        if (g_utf8_validate(string, length, &endptr)) {
            /* Valid string - should not happen. */
            return;
        }
    }
    good_length = endptr - string;

    display = make_utf8_display(string, length, good_length);

    ws_log_write_always_full(domain, level, file, line, func,
            "Invalid UTF-8 at address %p offset %zu (length = %zu):\n%s",
            string, good_length, length, display);

    g_free(display);
}


void ws_log_buffer_full(const char *domain, enum ws_log_level level,
                    const char *file, long line, const char *func,
                    const uint8_t *ptr, size_t size,  size_t max_bytes_len,
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
                            const char *file, long line, const char *func,
                            ws_log_manifest_t *mft,
                            const char *user_format, va_list user_ap)
{
    log_write_do_work(fp, false,
                        &mft->tstamp_secs, mft->nanosecs, mft->pid,
                        domain, level, file, line, func,
                        user_format, user_ap);
}


void ws_log_console_writer(const char *domain, enum ws_log_level level,
                            const char *file, long line, const char *func,
                            ws_log_manifest_t *mft,
                            const char *user_format, va_list user_ap)
{
    log_write_do_work(console_file(level), console_color_enabled(level),
                        &mft->tstamp_secs, mft->nanosecs, mft->pid,
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
    free_log_filter(&fatal_filter);
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
    "comma-separated list of the active log domains"

#define USAGE_FATAL_DOMAINS \
    "list of domains that cause the program to abort"

#define USAGE_DEBUG \
    "list of domains with \"debug\" level"

#define USAGE_NOISY \
    "list of domains with \"noisy\" level"

#define USAGE_FILE \
    "file to output messages to (in addition to stderr)"

void ws_log_print_usage(FILE *fp)
{
    fprintf(fp, "Diagnostic output:\n");
    fprintf(fp, "  --log-level <level>      " USAGE_LEVEL "\n");
    fprintf(fp, "  --log-fatal <level>      " USAGE_FATAL "\n");
    fprintf(fp, "  --log-domains <[!]list>  " USAGE_DOMAINS "\n");
    fprintf(fp, "  --log-fatal-domains <list>\n");
    fprintf(fp, "                           " USAGE_FATAL_DOMAINS "\n");
    fprintf(fp, "  --log-debug <[!]list>    " USAGE_DEBUG "\n");
    fprintf(fp, "  --log-noisy <[!]list>    " USAGE_NOISY "\n");
    fprintf(fp, "  --log-file <path>        " USAGE_FILE "\n");
}
