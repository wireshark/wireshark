/* dftest.c
 * Shows display filter byte-code, for debugging dfilter routines.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>
#define WS_LOG_DOMAIN  LOG_DOMAIN_MAIN

#include <stdlib.h>
#include <stdio.h>
#include <locale.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#include <ws_exit_codes.h>

#include <epan/epan.h>
#include <epan/timestamp.h>
#include <epan/prefs.h>
#include <epan/dfilter/dfilter.h>
#include <epan/dfilter/dfilter-macro.h>

#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <wsutil/report_message.h>
#include <wsutil/wslog.h>
#include <wsutil/ws_getopt.h>
#include <wsutil/utf8_entities.h>

#include <wiretap/wtap.h>

#include "ui/util.h"
#include "wsutil/cmdarg_err.h"
#include "ui/failure_message.h"
#include "wsutil/version_info.h"

static int opt_verbose;
static int opt_debug_level; /* currently up to 2 */
static int opt_flex;
static int opt_lemon;
static int opt_syntax_tree;
static int opt_return_vals;
static int opt_timer;
static long opt_optimize = 1;
static int opt_show_types;
static int opt_dump_refs;
static int opt_dump_macros;

static int64_t elapsed_expand;
static int64_t elapsed_compile;

/*
 * Report an error in command-line arguments.
 */
static void
dftest_cmdarg_err(const char *fmt, va_list ap)
{
    fprintf(stderr, "dftest: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
}

/*
 * Report additional information for an error in command-line arguments.
 */
static void
dftest_cmdarg_err_cont(const char *fmt, va_list ap)
{
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
}

static void
putloc(FILE *fp, df_loc_t loc)
{
    for (long i = 0; i < loc.col_start; i++) {
        fputc(' ', fp);
    }
    fputc('^', fp);

    for (size_t l = loc.col_len; l > 1; l--) {
        fputc('~', fp);
    }
    fputc('\n', fp);
}

WS_NORETURN static void
print_usage(int status)
{
    FILE *fp = stdout;
    fprintf(fp, "\n");
    fprintf(fp, "Usage: dftest [OPTIONS] -- EXPRESSION\n");
    fprintf(fp, "Options:\n");
    fprintf(fp, "  -V, --verbose       enable verbose mode\n");
    fprintf(fp, "  -d, --debug[=N]     increase or set debug level\n");
    fprintf(fp, "  -D                  set maximum debug level\n");
    fprintf(fp, "  -f, --flex          enable Flex debug trace\n");
    fprintf(fp, "  -l, --lemon         enable Lemon debug trace\n");
    fprintf(fp, "  -s, --syntax        print syntax tree\n");
    fprintf(fp, "  -m  --macros        print saved macros\n");
    fprintf(fp, "  -t, --timer         print elapsed compilation time\n");
    fprintf(fp, "  -r  --return-vals   return field values for the tree root\n");
    fprintf(fp, "  -0, --optimize=0    do not optimize (check syntax)\n");
    fprintf(fp, "      --types         show field value types\n");
    /* NOTE: References are loaded during runtime and dftest only does compilation.
     * Unless some static reference data is hard-coded at compile time during
     * development the --refs option to dftest is useless because it will just
     * print empty reference vectors. */
    fprintf(fp, "      --refs          dump some runtime data structures\n");
    fprintf(fp, "  -h, --help          display this help and exit\n");
    fprintf(fp, "  -v, --version       print version\n");
    fprintf(fp, "\n");
    ws_log_print_usage(fp);
    exit(status);
}

static void
print_syntax_tree(dfilter_t *df)
{
    printf("Syntax tree:\n%s\n\n", dfilter_syntax_tree(df));
}

static void
print_macros(void)
{
    if (dfilter_macro_table_count() == 0) {
        printf("Macros: (empty)\n\n");
        return;
    }

    struct dfilter_macro_table_iter iter;
    const char *name, *text;

    dfilter_macro_table_iter_init(&iter);
    printf("Macros:\n");
    while (dfilter_macro_table_iter_next(&iter, &name, &text)) {
        printf(" "UTF8_BULLET" %s:\n", name);
        printf("      %s\n", text);
    }
    printf("\n");
}

static void
print_warnings(dfilter_t *df)
{
    unsigned i;
    GPtrArray *deprecated;
    int count = 0;

    for (GSList *l = dfilter_get_warnings(df); l != NULL; l = l->next) {
        printf("\nWarning: %s.", (char *)l->data);
        count++;
    }

    deprecated = dfilter_deprecated_tokens(df);
    if (deprecated && deprecated->len) {
        for (i = 0; i < deprecated->len; i++) {
            const char *token = g_ptr_array_index(deprecated, i);
            printf("\nWarning: Deprecated token \"%s\".", token);
            count++;
        }
    }

    if (count) {
        printf("\n");
    }
}

static void
print_elapsed(void)
{
    printf("\nElapsed: %"PRId64" µs (%"PRId64" µs + %"PRId64" µs)\n",
            elapsed_expand + elapsed_compile,
            elapsed_expand,
            elapsed_compile);
}

static char *
expand_filter(const char *text)
{
    char *expanded = NULL;
    df_error_t *err = NULL;
    int64_t start;

    start = g_get_monotonic_time();
    expanded = dfilter_expand(text, &err);
    if (expanded == NULL) {
        fprintf(stderr, "Error: %s\n", err->msg);
        df_error_free(&err);
    }
    elapsed_expand = g_get_monotonic_time() - start;
    return expanded;
}

static bool
compile_filter(const char *text, dfilter_t **dfp)
{
    unsigned df_flags = 0;
    bool ok;
    df_error_t *df_err = NULL;
    int64_t start;

    if (opt_optimize > 0)
        df_flags |= DF_OPTIMIZE;
    if (opt_syntax_tree)
        df_flags |= DF_SAVE_TREE;
    if (opt_flex)
        df_flags |= DF_DEBUG_FLEX;
    if (opt_lemon)
        df_flags |= DF_DEBUG_LEMON;
    if (opt_return_vals)
        df_flags |= DF_RETURN_VALUES;

    start = g_get_monotonic_time();
    ok = dfilter_compile_full(text, dfp, &df_err, df_flags, "dftest");
    if (!ok) {
        fprintf(stderr, "Error: %s\n", df_err->msg);
        if (df_err->loc.col_start >= 0) {
            fprintf(stderr, "  %s\n  ", text);
            putloc(stderr, df_err->loc);
        }
        df_error_free(&df_err);
    }
    elapsed_compile = g_get_monotonic_time() - start;
    return ok;
}

static int
optarg_to_digit(const char *arg)
{
    if (strlen(arg) > 1 || !g_ascii_isdigit(*arg)) {
        printf("Error: \"%s\" is not a valid number 0-9\n", arg);
        print_usage(WS_EXIT_INVALID_OPTION);
    }
    errno = 0;
    int digit = (int)strtol(ws_optarg, NULL, 10);
    if (errno) {
        printf("Error: %s\n", g_strerror(errno));
        print_usage(WS_EXIT_INVALID_OPTION);
    }
    return digit;
}

int
main(int argc, char **argv)
{
    char		*configuration_init_error;
    char        *text = NULL;
    char        *expanded_text = NULL;
    dfilter_t   *df = NULL;
    int          exit_status = EXIT_FAILURE;

    /*
     * Set the C-language locale to the native environment and set the
     * code page to UTF-8 on Windows.
     */
#ifdef _WIN32
    setlocale(LC_ALL, ".UTF-8");
#else
    setlocale(LC_ALL, "");
#endif

    cmdarg_err_init(dftest_cmdarg_err, dftest_cmdarg_err_cont);

    /* Initialize log handler early for startup. */
    ws_log_init("dftest", vcmdarg_err);

    /* Early logging command-line initialization. */
    ws_log_parse_args(&argc, argv, vcmdarg_err, 1);

    ws_noisy("Finished log init and parsing command line log arguments");

    ws_init_version_info("DFTest", NULL, NULL);

    const char *optstring = "hvdDflsmrtV0";
    static struct ws_option long_options[] = {
        { "help",     ws_no_argument,   0,  'h' },
        { "version",  ws_no_argument,   0,  'v' },
        { "debug",    ws_optional_argument, 0, 'd' },
        { "flex",     ws_no_argument,   0,  'f' },
        { "lemon",    ws_no_argument,   0,  'l' },
        { "syntax",   ws_no_argument,   0,  's' },
        { "macros",   ws_no_argument,   0,  'm' },
        { "timer",    ws_no_argument,   0,  't' },
        { "verbose",  ws_no_argument,   0,  'V' },
        { "return-vals", ws_no_argument,   0,  'r' },
        { "optimize", ws_required_argument, 0, 1000 },
        { "types",    ws_no_argument,   0, 2000 },
        { "refs",     ws_no_argument,   0, 3000 },
        { NULL,       0,                0,  0   }
    };
    int opt;

    for (;;) {
        opt = ws_getopt_long(argc, argv, optstring, long_options, NULL);
        if (opt == -1)
            break;

        switch (opt) {
            case 'V':
                opt_verbose = 1;
                break;
            case 'd':
                if (ws_optarg) {
                    opt_debug_level = optarg_to_digit(ws_optarg);
                }
                else {
                    opt_debug_level++;
                }
                opt_show_types = 1;
                break;
            case 'D':
                opt_debug_level = 9;
                opt_lemon = 1;
                opt_flex = 1;
                opt_show_types = 1;
                break;
            case 'f':
                opt_flex = 1;
                break;
            case 'l':
                opt_lemon = 1;
                break;
            case 's':
                opt_syntax_tree = 1;
                break;
            case 'm':
                opt_dump_macros = 1;
                break;
            case 't':
                opt_timer = 1;
                break;
            case 'r':
                opt_return_vals = 1;
                break;
            case '0':
                opt_optimize = 0;
                break;
            case 1000:
                opt_optimize = optarg_to_digit(ws_optarg);
                break;
            case 2000:
                opt_show_types = 1;
                break;
            case 3000:
                opt_dump_refs = 1;
                break;
            case 'v':
                show_version();
                exit(EXIT_SUCCESS);
                break;
            case 'h':
                show_help_header(NULL);
                print_usage(EXIT_SUCCESS);
                break;
            case '?':
                print_usage(EXIT_FAILURE);
            default:
                ws_assert_not_reached();
        }
    }

    /* Check for filter on command line. */
    if (argv[ws_optind] == NULL) {
        /* If not printing macros we need a filter expression to compile. */
        if (!opt_dump_macros) {
            printf("Error: Missing argument.\n");
            print_usage(EXIT_FAILURE);
        }
    }

    /* Set dfilter domain logging. */
    if (opt_debug_level > 1) {
        ws_log_set_noisy_filter(LOG_DOMAIN_DFILTER);
    }
    else if (opt_debug_level > 0 || opt_flex || opt_lemon) {
        /* Also enable some dfilter logs with flex/lemon traces for context. */
        ws_log_set_debug_filter(LOG_DOMAIN_DFILTER);
    }

    /*
     * Get credential information for later use.
     */
    init_process_policies();

    /*
     * Attempt to get the pathname of the directory containing the
     * executable file.
     */
    configuration_init_error = configuration_init(argv[0], NULL);
    if (configuration_init_error != NULL) {
        fprintf(stderr, "Error: Can't get pathname of directory containing "
                        "the dftest program: %s.\n",
            configuration_init_error);
        g_free(configuration_init_error);
    }

    static const struct report_message_routines dftest_report_routines = {
        failure_message,
        failure_message,
        open_failure_message,
        read_failure_message,
        write_failure_message,
        cfile_open_failure_message,
        cfile_dump_open_failure_message,
        cfile_read_failure_message,
        cfile_write_failure_message,
        cfile_close_failure_message
    };

    init_report_message("dftest", &dftest_report_routines);

    timestamp_set_type(TS_RELATIVE);
    timestamp_set_seconds_type(TS_SECONDS_DEFAULT);

    /*
     * Libwiretap must be initialized before libwireshark is, so that
     * dissection-time handlers for file-type-dependent blocks can
     * register using the file type/subtype value for the file type.
     */
    wtap_init(true);

    /* Register all dissectors; we must do this before checking for the
       "-g" flag, as the "-g" flag dumps a list of fields registered
       by the dissectors, and we must do it before we read the preferences,
       in case any dissectors register preferences. */
    if (!epan_init(NULL, NULL, true))
        goto out;

    /* Load libwireshark settings from the current profile. */
    epan_load_settings();

    /* notify all registered modules that have had any of their preferences
       changed either from one of the preferences file or from the command
       line that its preferences have changed. */
    prefs_apply_all();

    if (opt_dump_macros) {
        print_macros();
        if (argv[ws_optind] == NULL) {
            /* No filter expression, we're done. */
            exit(EXIT_SUCCESS);
        }
    }

    /* Check again for filter on command line */
    if (argv[ws_optind] == NULL) {
        printf("Error: Missing argument.\n");
        print_usage(EXIT_FAILURE);
    }

    /* This is useful to prevent confusion with option parsing.
     * Skips printing options and argv[0]. */
    if (opt_verbose) {
        for (int i = ws_optind; i < argc; i++) {
            fprintf(stderr, "argv[%d]: %s\n", i, argv[i]);
        }
        fprintf(stderr, "\n");
    }

    /* Get filter text */
    text = get_args_as_string(argc, argv, ws_optind);

    printf("Filter:\n %s\n\n", text);

    /* Expand macros. */
    expanded_text = expand_filter(text);
    if (expanded_text == NULL) {
        exit_status = WS_EXIT_INVALID_FILTER;
        goto out;
    }

    if (strcmp(text, expanded_text) != 0)
        printf("Filter (after expansion):\n %s\n\n", expanded_text);

    /* Compile it */
    if (!compile_filter(expanded_text, &df)) {
        exit_status = WS_EXIT_INVALID_FILTER;
        goto out;
    }

    /* If logging is enabled add an empty line. */
    if (opt_debug_level > 0) {
        printf("\n");
    }

    if (df == NULL) {
        printf("Filter is empty.\n");
        exit_status = WS_EXIT_INVALID_FILTER;
        goto out;
    }

    if (opt_syntax_tree)
        print_syntax_tree(df);

    uint16_t dump_flags = 0;
    if (opt_show_types)
        dump_flags |= DF_DUMP_SHOW_FTYPE;
    if (opt_dump_refs)
        dump_flags |= DF_DUMP_REFERENCES;

    dfilter_dump(stdout, df, dump_flags);

    print_warnings(df);

    if (opt_timer)
        print_elapsed();

    exit_status = 0;

out:
    epan_cleanup();
    dfilter_free(df);
    g_free(text);
    g_free(expanded_text);
    exit(exit_status);
}
