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

#include <wiretap/wtap.h>

#include "ui/util.h"
#include "ui/cmdarg_err.h"
#include "ui/failure_message.h"

static void dftest_cmdarg_err(const char *fmt, va_list ap);
static void dftest_cmdarg_err_cont(const char *fmt, va_list ap);

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
    GTimer      *timer = NULL;
    gdouble elapsed_expand, elapsed_compile;
    gboolean ok;
    int exit_status = 0;

    cmdarg_err_init(dftest_cmdarg_err, dftest_cmdarg_err_cont);

    /* Initialize log handler early so we can have proper logging during startup. */
    ws_log_init("dftest", vcmdarg_err);

    /* Early logging command-line initialization. */
    ws_log_parse_args(&argc, argv, vcmdarg_err, 1);

    ws_noisy("Finished log init and parsing command line log arguments");

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

    /*
     * Set the C-language locale to the native environment and set the
     * code page to UTF-8 on Windows.
     */
#ifdef _WIN32
    setlocale(LC_ALL, ".UTF-8");
#else
    setlocale(LC_ALL, "");
#endif

    /* Load libwireshark settings from the current profile. */
    epan_load_settings();

    /* notify all registered modules that have had any of their preferences
       changed either from one of the preferences file or from the command
       line that its preferences have changed. */
    prefs_apply_all();

    /* Check for filter on command line */
    if (argc <= 1) {
        fprintf(stderr, "Usage: dftest <filter>\n");
        exit(1);
    }

    timer = g_timer_new();

    /* Get filter text */
    text = get_args_as_string(argc, argv, 1);

    /* Expand macros. */
    g_timer_start(timer);
    expanded_text = dfilter_expand(text, &err_msg);
    g_timer_stop(timer);
    elapsed_expand = g_timer_elapsed(timer, NULL);
    if (expanded_text == NULL) {
        fprintf(stderr, "dftest: %s\n", err_msg);
        g_free(err_msg);
        exit_status = 2;
        goto out;
    }

    printf("Filter: %s\n", expanded_text);

    /* Compile it */
    g_timer_start(timer);
    ok = dfilter_compile_real(expanded_text, &df, &df_err,
                                DF_SAVE_TREE, "dftest");
    g_timer_stop(timer);
    elapsed_compile = g_timer_elapsed(timer, NULL);
    if (!ok) {
        fprintf(stderr, "dftest: %s\n", df_err->msg);
        if (df_err->loc.col_start >= 0) {
            fprintf(stderr, "\t%s\n", expanded_text);
            fputc('\t', stderr);
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

    for (GSList *l = dfilter_get_warnings(df); l != NULL; l = l->next) {
        printf("\nWarning: %s.\n", (char *)l->data);
    }

    printf("\nSyntax tree:\n%s\n\n", dfilter_syntax_tree(df));
    dfilter_dump(df);
    printf("\nElapsed time: %.f µs (%.f µs + %.f µs)\n",
            (elapsed_expand + elapsed_compile) * 1000 * 1000,
            elapsed_expand * 1000 * 1000, elapsed_compile * 1000 * 1000);

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
