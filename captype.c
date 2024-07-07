/* captype.c
 * Reports capture file type
 *
 * Based on capinfos.c
 * Copyright 2004 Ian Schorr
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>
#define WS_LOG_DOMAIN  LOG_DOMAIN_MAIN

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <locale.h>

#include <wsutil/ws_getopt.h>

#include <glib.h>

#include <wiretap/wtap.h>

#include <wsutil/cmdarg_err.h>
#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <cli_main.h>
#include <wsutil/version_info.h>

#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif

#include <wsutil/report_message.h>
#include <wsutil/str_util.h>
#include <wsutil/wslog.h>

#include "ui/failure_message.h"

static void
print_usage(FILE *output)
{
    fprintf(output, "\n");
    fprintf(output, "Usage: captype [options] <infile> ...\n");
    fprintf(output, "\n");
    fprintf(output, "Miscellaneous:\n");
    fprintf(output, "  -h, --help               display this help and exit\n");
    fprintf(output, "  -v, --version            display version info and exit\n");
}

/*
 * Report an error in command-line arguments.
 */
static void
captype_cmdarg_err(const char *msg_format, va_list ap)
{
    fprintf(stderr, "captype: ");
    vfprintf(stderr, msg_format, ap);
    fprintf(stderr, "\n");
}

/*
 * Report additional information for an error in command-line arguments.
 */
static void
captype_cmdarg_err_cont(const char *msg_format, va_list ap)
{
    vfprintf(stderr, msg_format, ap);
    fprintf(stderr, "\n");
}

int
main(int argc, char *argv[])
{
    char  *configuration_init_error;
    static const struct report_message_routines captype_report_routines = {
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
    wtap  *wth;
    int    err;
    char *err_info;
    int    i;
    int    opt;
    int    overall_error_status;
    static const struct ws_option long_options[] = {
        {"help", ws_no_argument, NULL, 'h'},
        {"version", ws_no_argument, NULL, 'v'},
        {0, 0, 0, 0 }
    };

    /*
     * Set the C-language locale to the native environment and set the
     * code page to UTF-8 on Windows.
     */
#ifdef _WIN32
    setlocale(LC_ALL, ".UTF-8");
#else
    setlocale(LC_ALL, "");
#endif

    cmdarg_err_init(captype_cmdarg_err, captype_cmdarg_err_cont);

    /* Initialize log handler early so we can have proper logging during startup. */
    ws_log_init("captype", vcmdarg_err);

    /* Early logging command-line initialization. */
    ws_log_parse_args(&argc, argv, vcmdarg_err, 1);

    ws_noisy("Finished log init and parsing command line log arguments");

    /* Initialize the version information. */
    ws_init_version_info("Captype", NULL, NULL);

#ifdef _WIN32
    create_app_running_mutex();
#endif /* _WIN32 */

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
        fprintf(stderr,
                "captype: Can't get pathname of directory containing the captype program: %s.\n",
                configuration_init_error);
        g_free(configuration_init_error);
    }

    init_report_message("captype", &captype_report_routines);

    wtap_init(true);

    /* Process the options */
    while ((opt = ws_getopt_long(argc, argv, "hv", long_options, NULL)) !=-1) {

        switch (opt) {

            case 'h':
                show_help_header("Print the file types of capture files.");
                print_usage(stdout);
                exit(0);
                break;

            case 'v':
                show_version();
                exit(0);
                break;

            case '?':              /* Bad flag - print usage message */
                print_usage(stderr);
                exit(1);
                break;
        }
    }

    if (argc < 2) {
        print_usage(stderr);
        return 1;
    }

    overall_error_status = 0;

    for (i = 1; i < argc; i++) {
        wth = wtap_open_offline(argv[i], WTAP_TYPE_AUTO, &err, &err_info, false);

        if(wth) {
            printf("%s: %s\n", argv[i], wtap_file_type_subtype_name(wtap_file_type_subtype(wth)));
            wtap_close(wth);
        } else {
            if (err == WTAP_ERR_FILE_UNKNOWN_FORMAT)
                printf("%s: unknown\n", argv[i]);
            else {
                cfile_open_failure_message(argv[i], err, err_info);
                overall_error_status = 2; /* remember that an error has occurred */
            }
        }

    }

    wtap_cleanup();
    free_progdirs();
    return overall_error_status;
}
