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

#include <epan/epan.h>
#include <epan/timestamp.h>
#include <epan/prefs.h>
#include <epan/dfilter/dfilter.h>

#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <wsutil/report_message.h>
#include <wsutil/wslog.h>
#include <wsutil/ws_getopt.h>

#include <wiretap/wtap.h>

#include "ui/util.h"
#include "ui/cmdarg_err.h"
#include "ui/failure_message.h"
#include "ui/version_info.h"

static void dftest_cmdarg_err(const char *fmt, va_list ap);
static void dftest_cmdarg_err_cont(const char *fmt, va_list ap);

static int opt_verbose = 0;
static int opt_noisy = 0;
static int opt_flex = 0;
static int opt_lemon = 0;
static int opt_syntax_tree = 0;

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
    fprintf(stderr, "Usage: dftest [OPTIONS] -- <EXPR>\n");
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -v       verbose mode\n");
    fprintf(stderr, "  -d       enable noisy display filter logs\n");
    fprintf(stderr, "  -f       enable Flex debug trace\n");
    fprintf(stderr, "  -l       enable Lemon debug trace\n");
    fprintf(stderr, "  -s       print syntax tree\n");
    fprintf(stderr, "  -h       display this help and exit\n");
}

static void
print_syntax_tree(dfilter_t *df)
{
    printf("Syntax tree:\n%s\n\n", dfilter_syntax_tree(df));
}

static void
print_warnings(dfilter_t *df)
{
    guint i;
    GSList *warnings;
    GPtrArray *deprecated;

    warnings = dfilter_get_warnings(df);
    for (GSList *l = warnings; l != NULL; l = l->next) {
        printf("Warning: %s.\n", (char *)l->data);
    }

    deprecated = dfilter_deprecated_tokens(df);
    if (deprecated && deprecated->len) {
        for (i = 0; i < deprecated->len; i++) {
            printf("Warning: Deprecated token \"%s\".\n", (char *) g_ptr_array_index(deprecated, i));
        }
    }

    if (warnings || (deprecated && deprecated->len > 0)) {
        printf("\n");
    }
}

static void
print_elapsed(gdouble expand_secs, gdouble compile_secs)
{
    printf("Elapsed time: %.f µs (%.f µs + %.f µs)\n",
            (expand_secs + compile_secs) * 1000 * 1000,
            expand_secs * 1000 * 1000,
            compile_secs * 1000 * 1000);
}

int
main(int argc, char **argv)
{
    char		*configuration_init_error;
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
    char        *text = NULL;
    char        *expanded_text = NULL;
    dfilter_t   *df = NULL;
    gchar       *err_msg = NULL;
    df_error_t  *df_err = NULL;
    unsigned     df_flags = 0;
    GTimer      *timer = NULL;
    gdouble elapsed_expand, elapsed_compile;
    gboolean ok;
    int exit_status = 0;
    int opt;

    cmdarg_err_init(dftest_cmdarg_err, dftest_cmdarg_err_cont);

    /* Initialize log handler early so we can have proper logging during startup. */
    ws_log_init("dftest", vcmdarg_err);

    /* Early logging command-line initialization. */
    ws_log_parse_args(&argc, argv, vcmdarg_err, 1);

    ws_noisy("Finished log init and parsing command line log arguments");

    /*
     * Set the C-language locale to the native environment and set the
     * code page to UTF-8 on Windows.
     */
#ifdef _WIN32
    setlocale(LC_ALL, ".UTF-8");
#else
    setlocale(LC_ALL, "");
#endif

    ws_init_version_info("DFTest", NULL, NULL);

    while ((opt = ws_getopt(argc, argv, "vdflsh")) != -1) {
        switch (opt) {
            case 'v':
                opt_verbose = 1;
                break;
            case 'd':
                opt_noisy = 1;
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
            case 'h':
                /* fall-through */
            default: /* '?' */
                show_help_header(NULL);
                printf("\n");
                print_usage();
                exit(EXIT_FAILURE);
        }
    }

    if (opt_noisy)
        ws_log_set_noisy_filter(LOG_DOMAIN_DFILTER);

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
        fprintf(stderr, "dftest: Can't get pathname of directory containing the dftest program: %s.\n",
            configuration_init_error);
        g_free(configuration_init_error);
    }

    init_report_message("dftest", &dftest_report_routines);

    timestamp_set_type(TS_RELATIVE);
    timestamp_set_seconds_type(TS_SECONDS_DEFAULT);

    /*
     * Libwiretap must be initialized before libwireshark is, so that
     * dissection-time handlers for file-type-dependent blocks can
     * register using the file type/subtype value for the file type.
     */
    wtap_init(TRUE);

    /* Register all dissectors; we must do this before checking for the
       "-g" flag, as the "-g" flag dumps a list of fields registered
       by the dissectors, and we must do it before we read the preferences,
       in case any dissectors register preferences. */
    if (!epan_init(NULL, NULL, FALSE))
        return 2;

    /* Load libwireshark settings from the current profile. */
    epan_load_settings();

    /* notify all registered modules that have had any of their preferences
       changed either from one of the preferences file or from the command
       line that its preferences have changed. */
    prefs_apply_all();

    /* Check for filter on command line */
    if (argv[ws_optind] == NULL) {
        print_usage();
        exit(1);
    }

    /* This is useful to prevent confusion with option parsing.
     * Skips printing options and argv[0]. */
    if (opt_verbose) {
        for (int i = ws_optind; i < argc; i++) {
            printf("argv[%d]: %s\n", i, argv[i]);
        }
        printf("\n");
    }

    /* Get filter text */
    text = get_args_as_string(argc, argv, ws_optind);

    printf("Filter:\n %s\n\n", text);

    timer = g_timer_new();

    /* Expand macros. */
    g_timer_start(timer);
    expanded_text = dfilter_expand(text, &err_msg);
    g_timer_stop(timer);
    elapsed_expand = g_timer_elapsed(timer, NULL);
    if (expanded_text == NULL) {
        fprintf(stderr, "Error: %s\n", err_msg);
        g_free(err_msg);
        exit_status = 2;
        goto out;
    }

    if (strcmp(text, expanded_text) != 0)
        printf("Filter (after expansion):\n %s\n\n", expanded_text);

    /* Compile it */
    if (opt_syntax_tree)
        df_flags |= DF_SAVE_TREE;
    if (opt_flex)
        df_flags |= DF_DEBUG_FLEX;
    if (opt_lemon)
        df_flags |= DF_DEBUG_LEMON;
    g_timer_start(timer);
    ok = dfilter_compile_real(expanded_text, &df, &df_err, df_flags, "dftest");
    g_timer_stop(timer);
    elapsed_compile = g_timer_elapsed(timer, NULL);
    if (!ok) {
        fprintf(stderr, "Error: %s\n", df_err->msg);
        if (df_err->loc.col_start >= 0) {
            fprintf(stderr, "  %s\n  ", expanded_text);
            putloc(stderr, df_err->loc);
        }
        dfilter_error_free(df_err);
        exit_status = 2;
        goto out;
    }

    if (df == NULL) {
        printf("Filter is empty.\n");
        goto out;
    }

    if (opt_syntax_tree)
        print_syntax_tree(df);

    dfilter_dump(stdout, df);
    printf("\n");

    print_warnings(df);

    print_elapsed(elapsed_expand, elapsed_compile);

out:
    epan_cleanup();
    if (df != NULL)
        dfilter_free(df);
    if (text != NULL)
        g_free(text);
    if (expanded_text != NULL)
        g_free(expanded_text);
    if (timer != NULL)
        g_timer_destroy(timer);
    exit(exit_status);
}

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
