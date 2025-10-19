/*
 * randpkt.c
 * ---------
 * Creates random packet traces. Useful for debugging sniffers by testing
 * assumptions about the veracity of the data found in the packet.
 *
 * Copyright (C) 1999 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>
#define WS_LOG_DOMAIN  LOG_DOMAIN_MAIN

#include <glib.h>

#include <stdio.h>
#include <stdlib.h>

#include <ws_exit_codes.h>
#include <wsutil/clopts_common.h>
#include <ui/failure_message.h>
#include <wsutil/cmdarg_err.h>
#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <app/application_flavor.h>
#include <wsutil/privileges.h>
#include <cli_main.h>

#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif

#include <wsutil/wslog.h>

#include <wsutil/ws_getopt.h>
#include <wsutil/version_info.h>

#include "randpkt_core/randpkt_core.h"

/* Additional exit codes */
#define INVALID_TYPE 2
#define CLOSE_ERROR  2

static void
list_capture_types(void) {
    GArray *writable_type_subtypes;

    cmdarg_err("The available capture file types for the \"-F\" flag are:\n");
    writable_type_subtypes = wtap_get_writable_file_types_subtypes(FT_SORT_BY_NAME);
    for (unsigned i = 0; i < writable_type_subtypes->len; i++) {
        int ft = g_array_index(writable_type_subtypes, int, i);
        fprintf(stderr, "    %s - %s\n", wtap_file_type_subtype_name(ft),
            wtap_file_type_subtype_description(ft));
    }
    g_array_free(writable_type_subtypes, TRUE);
}

/* Print usage statement and exit program */
static void
usage(bool is_error)
{
    FILE *output;
    char** abbrev_list;
    char** longname_list;
    unsigned i = 0;

    if (!is_error) {
        output = stdout;
    }
    else {
        output = stderr;
    }

    fprintf(output, "Usage: randpkt [options] <outfile>\n");
    fprintf(output, "\n");
    fprintf(output, "Options:\n");
    fprintf(output, "  -b                maximum bytes per packet (default: 5000)\n");
    fprintf(output, "  -c                packet count (default: 1000)\n");
    fprintf(output, "  -F                output file type (default: pcapng)\n");
    fprintf(output, "                    an empty \"-F\" option will list the file types\n");
    fprintf(output, "  -r                select a different random type for each packet\n");
    fprintf(output, "  -t                packet type\n");
    fprintf(output, "  -h, --help        display this help and exit.\n");
    fprintf(output, "  -v, --version     print version information and exit.\n");
    fprintf(output, "\n");
    fprintf(output, "Types:\n");

    /* Get the examples list */
    randpkt_example_list(&abbrev_list, &longname_list);
    while (abbrev_list[i] && longname_list[i]) {
        fprintf(output, "\t%-16s%s\n", abbrev_list[i], longname_list[i]);
        i++;
    }

    g_strfreev(abbrev_list);
    g_strfreev(longname_list);

    fprintf(output, "\nIf type is not specified, a random packet type will be chosen\n\n");
}

int
main(int argc, char *argv[])
{
    char *configuration_init_error;
    int opt;
    int produce_type = -1;
    char *produce_filename = NULL;
    int produce_max_bytes = 5000;
    int produce_count = 1000;
    int file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_UNKNOWN;
    randpkt_example *example;
    char* type = NULL;
    bool allrandom = false;
    wtap_dumper *savedump;
    int ret = EXIT_SUCCESS;
    static const struct ws_option long_options[] = {
        {"help", ws_no_argument, NULL, 'h'},
        {"version", ws_no_argument, NULL, 'v'},
        LONGOPT_WSLOG
        {0, 0, 0, 0 }
    };
#define OPTSTRING "b:c:F:ht:rv"
    static const char optstring[] = OPTSTRING;
    const struct file_extension_info* file_extensions;
    unsigned num_extensions;

    /* Set the program name. */
    g_set_prgname("randpkt");

    cmdarg_err_init(stderr_cmdarg_err, stderr_cmdarg_err_cont);

    /* Initialize log handler early so we can have proper logging during startup. */
    ws_log_init(vcmdarg_err, "Randpkt Debug Console");

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
        fprintf(stderr,
            "capinfos: Can't get pathname of directory containing the capinfos program: %s.\n",
            configuration_init_error);
        g_free(configuration_init_error);
    }

    init_report_failure_message("randpkt");

    application_file_extensions(&file_extensions, &num_extensions);
    wtap_init(true, application_configuration_environment_prefix(), file_extensions, num_extensions);

#ifdef _WIN32
    create_app_running_mutex();
#endif /* _WIN32 */

    ws_init_version_info("Randpkt", NULL, get_ws_vcs_version_info, NULL, NULL);

    while ((opt = ws_getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
        switch (opt) {
            case 'b':	/* max bytes */
                if (!get_positive_int(ws_optarg, "max bytes", &produce_max_bytes)) {
                    ret = WS_EXIT_INVALID_OPTION;
                    goto clean_exit;
                }
                if (produce_max_bytes > 65536) {
                    cmdarg_err("max bytes is > 65536");
                    ret = WS_EXIT_INVALID_OPTION;
                    goto clean_exit;
                }
                break;

            case 'c':	/* count */
                if (!get_positive_int(ws_optarg, "count", &produce_count)) {
                    ret = WS_EXIT_INVALID_OPTION;
                    goto clean_exit;
                }
                break;

            case 'F':
                file_type_subtype = wtap_name_to_file_type_subtype(ws_optarg);
                if (file_type_subtype < 0) {
                    cmdarg_err("\"%s\" isn't a valid capture file type", ws_optarg);
                    list_capture_types();
                    return WS_EXIT_INVALID_OPTION;
                }
                break;

            case 't':	/* type of packet to produce */
                type = g_strdup(ws_optarg);
                break;

            case 'h':
                show_help_header(NULL);
                usage(false);
                goto clean_exit;
                break;

            case 'r':
                allrandom = true;
                break;

            case 'v':
                show_version();
                goto clean_exit;
                break;

            case '?':
                switch(ws_optopt) {
                    case 'F':
                        list_capture_types();
                        return WS_EXIT_INVALID_OPTION;
                }
                /* FALLTHROUGH */

            default:
                /* wslog arguments are okay */
                if (ws_log_is_wslog_arg(opt))
                    break;

                usage(true);
                ret = WS_EXIT_INVALID_OPTION;
                goto clean_exit;
                break;
        }
    }

    /* any more command line parameters? */
    if (argc > ws_optind) {
        produce_filename = argv[ws_optind];
    } else {
        usage(true);
        ret = WS_EXIT_INVALID_OPTION;
        goto clean_exit;
    }

    if (file_type_subtype == WTAP_FILE_TYPE_SUBTYPE_UNKNOWN) {
        file_type_subtype = wtap_pcapng_file_type_subtype();
    }

    if (!allrandom) {
        produce_type = randpkt_parse_type(type);
        g_free(type);

        example = randpkt_find_example(produce_type);
        if (!example) {
            ret = WS_EXIT_INVALID_OPTION;
            goto clean_exit;
        }

        ret = randpkt_example_init(example, produce_filename, produce_max_bytes, file_type_subtype);
        if (ret != EXIT_SUCCESS)
            goto clean_exit;
        randpkt_loop(example, produce_count, 0);
    } else {
        if (type) {
            fprintf(stderr, "Can't set type in random mode\n");
            ret = INVALID_TYPE;
            goto clean_exit;
        }

        produce_type = randpkt_parse_type(NULL);
        example = randpkt_find_example(produce_type);
        if (!example) {
            ret = WS_EXIT_INVALID_OPTION;
            goto clean_exit;
        }
        ret = randpkt_example_init(example, produce_filename, produce_max_bytes, file_type_subtype);
        if (ret != EXIT_SUCCESS)
            goto clean_exit;

        while (produce_count-- > 0) {
            randpkt_loop(example, 1, 0);
            produce_type = randpkt_parse_type(NULL);

            savedump = example->dump;

            example = randpkt_find_example(produce_type);
            if (!example) {
                ret = WS_EXIT_INVALID_OPTION;
                goto clean_exit;
            }
            example->dump = savedump;
            example->filename = produce_filename;
        }
    }
    if (!randpkt_example_close(example)) {
        ret = CLOSE_ERROR;
    }

clean_exit:
    wtap_cleanup();
    return ret;
}
