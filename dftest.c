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
#include <wsutil/file_util.h>
#include <wsutil/privileges.h>
#include <wsutil/clopts_common.h>
#include <wsutil/wslog.h>
#include <wsutil/ws_getopt.h>
#include <wsutil/utf8_entities.h>
#include <wsutil/application_flavor.h>

#include <wiretap/wtap.h>

#include "ui/util.h"
#include "ui/failure_message.h"
#include "wsutil/cmdarg_err.h"
#include "wsutil/report_message.h"
#include "wsutil/version_info.h"
#include "cli_main.h"

static int opt_verbose;
static int opt_debug_level; /* currently up to 2 */
static int opt_flex;
static int opt_lemon;
static int opt_syntax_tree;
static int opt_return_vals;
static int opt_timer;
static int opt_optimize = 1;
static int opt_show_types;
static int opt_dump_refs;
static int opt_dump_macros;

static int64_t elapsed_expand;
static int64_t elapsed_compile;

#ifndef HAVE_GETLINE
/* Maximum supported line length of a filter. */
#define MAX_LINELEN     4096

/** Read a line without trailing (CR)LF. Returns -1 on failure.  */
static int
fgetline(char *buf, int size, FILE *fp)
{
    if (fgets(buf, size, fp)) {
        int len = (int)strcspn(buf, "\r\n");
        buf[len] = '\0';
        return len;
    }
    return -1;

} /* fgetline */
#endif /* HAVE_GETLINE */

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

static void
print_usage(void)
{
    FILE *fp = stdout;
    fprintf(fp, "\n");
    fprintf(fp, "Usage: dftest [OPTIONS] -- EXPRESSION\n");
    fprintf(fp, "Options:\n");
    fprintf(fp, "  -V, --verbose       enable verbose mode\n");
    fprintf(fp, "  -C <config profile> run with specified configuration profile\n");
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
    fprintf(fp, "      --file <path>   read filters line-by-line from a file (use '-' for stdin)\n");
    fprintf(fp, "  -h, --help          display this help and exit\n");
    fprintf(fp, "  -v, --version       print version\n");
    fprintf(fp, "\n");
    ws_log_print_usage(fp);
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

static bool
optarg_to_digit(const char *arg, int* digit)
{
    if (strlen(arg) > 1 || !g_ascii_isdigit(*arg)) {
        printf("Error: \"%s\" is not a valid number 0-9\n", arg);
        print_usage();
        return false;
    }
    errno = 0;
    *digit = (int)strtol(ws_optarg, NULL, 10);
    if (errno) {
        printf("Error: %s\n", g_strerror(errno));
        print_usage();
        return false;
    }
    return true;
}

static int
test_filter(const char *text)
{
    char        *expanded_text = NULL;
    dfilter_t   *df = NULL;

    printf("Filter:\n %s\n\n", text);

    /* Expand macros. */
    expanded_text = expand_filter(text);
    if (expanded_text == NULL) {
        goto fail;
    }

    if (strcmp(text, expanded_text) != 0)
        printf("Filter (after expansion):\n %s\n\n", expanded_text);

    /* Compile it */
    if (!compile_filter(expanded_text, &df)) {
        goto fail;
    }

    /* If logging is enabled add an empty line. */
    if (opt_debug_level > 0) {
        printf("\n");
    }

    if (df == NULL) {
        printf("Filter is empty.\n");
        goto fail;
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

    g_free(expanded_text);
    dfilter_free(df);

    return EXIT_SUCCESS;

fail:
    g_free(expanded_text);
    dfilter_free(df);
    return WS_EXIT_INVALID_FILTER;
}

int
main(int argc, char **argv)
{
    char		*configuration_init_error;
    char        *path = NULL;
    char        *text = NULL;
    int          exit_status = EXIT_FAILURE;

    const char* optstring = "hvC:dDflsmrtV0";
    static const struct ws_option long_options[] = {
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
        { "file",     ws_required_argument, 0, 4000 },
        LONGOPT_WSLOG
        { NULL,       0,                0,  0   }
    };
    int opt;
    const struct file_extension_info* file_extensions;
    unsigned num_extensions;
    epan_app_data_t app_data;

    /* Future proof by zeroing out all data */
    memset(&app_data, 0, sizeof(app_data));

    /* Set the program name. */
    g_set_prgname("dftest");

    /*
     * Set the C-language locale to the native environment and set the
     * code page to UTF-8 on Windows.
     */
#ifdef _WIN32
    setlocale(LC_ALL, ".UTF-8");
#else
    setlocale(LC_ALL, "");
#endif

    cmdarg_err_init(stderr_cmdarg_err, stderr_cmdarg_err_cont);

    /* Initialize log handler early for startup. */
    ws_log_init(vcmdarg_err, "DFTest Debug Console");

    /* Early logging command-line initialization. */
    ws_log_parse_args(&argc, argv, optstring, long_options, vcmdarg_err, WS_EXIT_INVALID_OPTION);

    ws_noisy("Finished log init and parsing command line log arguments");

    /*
     * Get credential information for later use.
     */
    init_process_policies();

    /*
     * Attempt to get the pathname of the directory containing the
     * executable file.
     */
    configuration_init_error = configuration_init(argv[0], "wireshark");
    if (configuration_init_error != NULL) {
        fprintf(stderr, "Error: Can't get pathname of directory containing "
                        "the dftest program: %s.\n",
            configuration_init_error);
        g_free(configuration_init_error);
    }

    ws_init_version_info("DFTest", NULL, get_ws_vcs_version_info, NULL, NULL);

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
                    if (!optarg_to_digit(ws_optarg, &opt_debug_level))
                        return WS_EXIT_INVALID_OPTION;
                }
                else {
                    opt_debug_level++;
                }
                opt_show_types = 1;
                break;
            case 'C':   /* Configuration Profile */
                if (profile_exists (application_configuration_environment_prefix(), ws_optarg, false)) {
                    set_profile_name (ws_optarg);
                } else {
                    cmdarg_err("Configuration Profile \"%s\" does not exist", ws_optarg);
                    print_usage();
                    return WS_EXIT_INVALID_OPTION;
                }
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
                if (!optarg_to_digit(ws_optarg, &opt_optimize))
                    return WS_EXIT_INVALID_OPTION;
                break;
            case 2000:
                opt_show_types = 1;
                break;
            case 3000:
                opt_dump_refs = 1;
                break;
            case 4000:
                path = ws_optarg;
                break;
            case 'v':
                show_version();
                return EXIT_SUCCESS;
            case 'h':
                show_help_header(NULL);
                print_usage();
                return EXIT_SUCCESS;
            case '?':
                print_usage();
                return EXIT_FAILURE;
                break;
            default:
                /* wslog arguments are okay */
                if (ws_log_is_wslog_arg(opt))
                    break;

                ws_assert_not_reached();
                break;
        }
    }

    /* Check for filter on command line. */
    if (argv[ws_optind] == NULL) {
        /* If not printing macros we need a filter expression to compile. */
        if (!opt_dump_macros && !path) {
            printf("Error: Missing argument.\n");
            print_usage();
            return EXIT_FAILURE;
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

    init_report_failure_message("dftest");

    timestamp_set_type(TS_RELATIVE);
    timestamp_set_seconds_type(TS_SECONDS_DEFAULT);

    /*
     * Libwiretap must be initialized before libwireshark is, so that
     * dissection-time handlers for file-type-dependent blocks can
     * register using the file type/subtype value for the file type.
     */
    application_file_extensions(&file_extensions, &num_extensions);
    wtap_init(true, application_configuration_environment_prefix(), file_extensions, num_extensions);


    /* Register all dissectors; we must do this before checking for the
       "-g" flag, as the "-g" flag dumps a list of fields registered
       by the dissectors, and we must do it before we read the preferences,
       in case any dissectors register preferences. */
    app_data.env_var_prefix = application_configuration_environment_prefix();
    app_data.col_fmt = application_columns();
    app_data.num_cols = application_num_columns();
    app_data.register_func = register_all_protocols;
    app_data.handoff_func = register_all_protocol_handoffs;
    if (!epan_init(NULL, NULL, true, &app_data))
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
            return EXIT_SUCCESS;
        }
    }

    /* This is useful to prevent confusion with option parsing.
     * Skips printing options and argv[0]. */
    if (opt_verbose) {
        for (int i = ws_optind; i < argc; i++) {
            fprintf(stderr, "argv[%d]: %s\n", i, argv[i]);
        }
        fprintf(stderr, "\n");
    }

    if (path) {
        FILE *filter_p;
        if (strcmp(path, "-") == 0) {
            filter_p = stdin;
        } else {
            filter_p = ws_fopen(path, "r");
            if (filter_p == NULL) {
                report_open_failure(path, errno, false);
                exit_status = WS_EXIT_INVALID_FILE;
                goto out;
            }
        }
        bool first = true;
#ifdef HAVE_GETLINE
        char *line = NULL;
        size_t len = 0;
        while (getline(&line, &len, filter_p) >= 0) {
#else
        char line[MAX_LINELEN];
        while (fgetline(line, sizeof(line), filter_p) >= 0) {
#endif
            if (first) {
                first = false;
            } else {
                printf("\n");
            }
            exit_status = test_filter(line);
            /* A keep going option could be added. */
            if (exit_status != EXIT_SUCCESS)
                break;
        }
#ifdef HAVE_GETLINE
        g_free(line);
#endif
        fclose(filter_p);
    } else {

        /* Check again for filter on command line */
        if (argv[ws_optind] != NULL) {
            /* Get filter text */
            text = get_args_as_string(argc, argv, ws_optind);

            exit_status = test_filter(text);
        } else {
            printf("Error: Missing argument.\n");
            print_usage();
            exit_status = EXIT_FAILURE;
        }
    }

out:
    epan_cleanup();
    g_free(text);
    return exit_status;
}
