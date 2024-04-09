/* etwdump.c
 * etwdump is an extcap tool used to dump etw to pcapng
 *
 * Copyright 2020, Odysseus Yang
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN "etwdump"

#include "extcap-base.h"

#include <wsutil/strtoi.h>
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <wsutil/please_report_bug.h>
#include <wsutil/wslog.h>

#include <cli_main.h>
#include <wsutil/cmdarg_err.h>
#include "etl.h"

#include <signal.h>

/* extcap-interface has to be unique, or it may use wrong option output by a different extcapbin */
#define ETW_EXTCAP_INTERFACE "etwdump"
#define ETWDUMP_VERSION_MAJOR "1"
#define ETWDUMP_VERSION_MINOR "0"
#define ETWDUMP_VERSION_RELEASE "0"

enum {
    EXTCAP_BASE_OPTIONS_ENUM,
    OPT_HELP,
    OPT_VERSION,
    OPT_INCLUDE_UNDECIDABLE_EVENT,
    OPT_ETLFILE,
    OPT_PARAMS
};

static const struct ws_option longopts[] = {
    EXTCAP_BASE_OPTIONS,
    { "help",    ws_no_argument,       NULL, OPT_HELP},
    { "version", ws_no_argument,       NULL, OPT_VERSION},
    { "iue",     ws_optional_argument, NULL, OPT_INCLUDE_UNDECIDABLE_EVENT},
    { "etlfile", ws_required_argument, NULL, OPT_ETLFILE},
    { "params",  ws_required_argument, NULL, OPT_PARAMS},
    { 0, 0, 0, 0 }
};

int g_include_undecidable_event;

void SignalHandler(_U_ int signal)
{
    SUPER_EVENT_TRACE_PROPERTIES super_trace_properties = { 0 };
    super_trace_properties.prop.Wnode.BufferSize = sizeof(SUPER_EVENT_TRACE_PROPERTIES);
    super_trace_properties.prop.Wnode.ClientContext = 2;
    super_trace_properties.prop.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    super_trace_properties.prop.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    super_trace_properties.prop.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    /* Close trace when press CONTROL+C when running this console alone */
    ControlTrace((TRACEHANDLE)NULL, LOGGER_NAME, &super_trace_properties.prop, EVENT_TRACE_CONTROL_STOP);
}

static void help(extcap_parameters* extcap_conf)
{
    extcap_help_print(extcap_conf);
}

static int list_config(char* interface)
{
    unsigned inc = 0;

    if (!interface) {
        ws_warning("No interface specified.");
        return EXIT_FAILURE;
    }

    if (g_strcmp0(interface, ETW_EXTCAP_INTERFACE)) {
        ws_warning("Interface must be %s", ETW_EXTCAP_INTERFACE);
        return EXIT_FAILURE;
    }
    /*
     * required=true agu will be displayed before required=false on UI
     *
     * Empty etlfile and unempty params, read etw events from a live session with the params as the filter
     * Unempty etlfile and empty params, read etw events from the etl file without filter
     * Unempty etlfile and unemtpy params, read etw events from the etl file with the params as the filter
     * Empty eltfile and empty params, invalid
     */
    printf("arg {number=%u}{call=--etlfile}{display=etl file}"
        "{type=fileselect}{tooltip=Select etl file to display in Wireshark}{required=false}{group=Capture}\n",
        inc++);
    printf("arg {number=%u}{call=--params}{display=filter parameters}"
        "{type=string}{tooltip=Input providers, keyword and level filters for the etl file and live session}{group=Capture}\n",
        inc++);
    /*
    * The undecidable events are those that either don't have sub-dissector or don't have anthing meaningful to display except for the EVENT_HEADER.
    */
    printf("arg {number=%u}{call=--iue}{display=Should undecidable events be included}"
        "{type=boolflag}{default=false}{tooltip=Choose if the undecidable event is included}{group=Capture}\n",
        inc++);

    extcap_config_debug(&inc);
    return EXIT_SUCCESS;
}

int main(int argc, char* argv[])
{
    char* err_msg;
    int option_idx = 0;
    int result;
    int ret = EXIT_FAILURE;

    char* etlfile = NULL;
    char* params = NULL;

    extcap_parameters* extcap_conf = g_new0(extcap_parameters, 1);
    char* help_url;
    char* help_header = NULL;

    /* Initialize log handler early so we can have proper logging during startup. */
    extcap_log_init("etwdump");

    /*
     * Get credential information for later use.
     */
    init_process_policies();

    /*
     * Attempt to get the pathname of the directory containing the
     * executable file.
     */
    err_msg = configuration_init(argv[0], NULL);
    if (err_msg != NULL) {
        ws_warning("Can't get pathname of directory containing the extcap program: %s.",
            err_msg);
        g_free(err_msg);
    }

    help_url = data_file_url("etwdump.html");
    extcap_base_set_util_info(extcap_conf, argv[0], ETWDUMP_VERSION_MAJOR, ETWDUMP_VERSION_MINOR,
        ETWDUMP_VERSION_RELEASE, help_url);
    g_free(help_url);
    extcap_base_register_interface(extcap_conf, ETW_EXTCAP_INTERFACE, "Event Tracing for Windows (ETW) reader", 290, "DLT_ETW");

    help_header = ws_strdup_printf(
        " %s --extcap-interfaces\n"
        " %s --extcap-interface=%s --extcap-dlts\n"
        " %s --extcap-interface=%s --extcap-config\n"
        " %s --extcap-interface=%s --etlfile c:\\wwansvc.etl \n"
        "--fifo=FILENAME --capture\n", argv[0], argv[0], ETW_EXTCAP_INTERFACE, argv[0], ETW_EXTCAP_INTERFACE,
        argv[0], ETW_EXTCAP_INTERFACE);
    extcap_help_add_header(extcap_conf, help_header);
    g_free(help_header);

    extcap_help_add_option(extcap_conf, "--help", "print this help");
    extcap_help_add_option(extcap_conf, "--version", "print the version");
    extcap_help_add_option(extcap_conf, "--etlfile <filename>", "A etl filename");
    extcap_help_add_option(extcap_conf, "--iue", "Choose if undecidable event is included");

    if (argc == 1) {
        help(extcap_conf);
        goto end;
    }

    while ((result = ws_getopt_long(argc, argv, ":", longopts, &option_idx)) != -1) {
        switch (result) {
        case OPT_VERSION:
            extcap_version_print(extcap_conf);
            ret = EXIT_SUCCESS;
            goto end;

        case OPT_HELP:
            help(extcap_conf);
            ret = EXIT_SUCCESS;
            goto end;

        case OPT_ETLFILE:
            etlfile = g_strdup(ws_optarg);
            break;

        case OPT_PARAMS:
            /* Add params as the prefix since getopt_long will ignore the first argument always */
            params = ws_strdup_printf("params %s", ws_optarg);
            break;

        case OPT_INCLUDE_UNDECIDABLE_EVENT:
            g_include_undecidable_event = true;
            break;

        case ':':
            /* missing option argument */
            ws_warning("Option '%s' requires an argument", argv[ws_optind - 1]);
            break;

        default:
            /* Handle extcap specific options */
            if (!extcap_base_parse_options(extcap_conf, result - EXTCAP_OPT_LIST_INTERFACES, ws_optarg))
            {
                ws_warning("Invalid option: %s", argv[ws_optind - 1]);
                goto end;
            }
        }
    }

    extcap_cmdline_debug(argv, argc);

    if (extcap_base_handle_interface(extcap_conf)) {
        ret = EXIT_SUCCESS;
        goto end;
    }

    if (extcap_conf->show_config) {
        ret = list_config(extcap_conf->interface);
        goto end;
    }

    if (extcap_conf->capture) {

        if (g_strcmp0(extcap_conf->interface, ETW_EXTCAP_INTERFACE)) {
            ws_warning("ERROR: invalid interface");
            goto end;
        }

        if (etlfile == NULL && params == NULL)
        {
            ws_warning("ERROR: Both --etlfile and --params arguments are empty");
            goto end;
        }

        wtap_init(false);

        signal(SIGINT, SignalHandler);

        switch(etw_dump(etlfile, extcap_conf->fifo, params, &ret, &err_msg))
        {
        case WTAP_OPEN_ERROR:
            if (err_msg != NULL) {
                ws_warning("etw_dump failed: %s.",
                    err_msg);
                g_free(err_msg);
            }
            else
            {
                ws_warning("etw_dump failed");
            }
            break;
        case WTAP_OPEN_NOT_MINE:
            if (etlfile == NULL)
            {
                if (err_msg != NULL) {
                    ws_warning("The live session didn't capture any event. Error message: %s.",
                        err_msg);
                    g_free(err_msg);
                }
                else
                {
                    ws_warning("The live session didn't capture any event");
                }
            }
            else
            {
                if (err_msg != NULL) {
                    ws_warning("The file %s is not etl format. Error message: %s.",
                        etlfile, err_msg);
                    g_free(err_msg);
                }
                else
                {
                    ws_warning("The file %s is not etl format", etlfile);
                }
            }
            break;
        case WTAP_OPEN_MINE:
            ret = EXIT_SUCCESS;
            break;
        }
    }

end:
    /* clean up stuff */
    extcap_base_cleanup(&extcap_conf);

    if (etlfile != NULL)
    {
        g_free(etlfile);
    }
    if (params != NULL)
    {
        g_free(params);
    }

    return ret;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
