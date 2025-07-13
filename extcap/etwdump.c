/* etwdump.c
 * etwdump is an extcap tool used to dump etw to pcapng
 *
 * Copyright 2020, Odysseus Yang
 *           2025, Gabriel Potter
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

#include <combaseapi.h>
#undef interface

/* extcap-interface has to be unique, or it may use wrong option output by a different extcapbin */
#define ETW_EXTCAP_INTERFACE "etwdump"
#define ETWDUMP_VERSION_MAJOR "1"
#define ETWDUMP_VERSION_MINOR "0"
#define ETWDUMP_VERSION_RELEASE "0"

#define MAX_GUID_SIZE 39

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

static void SignalHandler(_U_ int signal)
{
    SUPER_EVENT_TRACE_PROPERTIES super_trace_properties = { 0 };
    // "you only need to set the Wnode.BufferSize, Wnode.Guid, LoggerNameOffset, and LogFileNameOffset"
    super_trace_properties.prop.Wnode.BufferSize = sizeof(SUPER_EVENT_TRACE_PROPERTIES);
    super_trace_properties.prop.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    super_trace_properties.prop.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    /* Close trace when press CONTROL+C when running this console alone */
    ControlTrace((TRACEHANDLE)NULL, LOGGER_NAME, &super_trace_properties.prop, EVENT_TRACE_CONTROL_STOP);
}

static void help(extcap_parameters* extcap_conf)
{
    extcap_help_print(extcap_conf);
}


/// <summary>
/// List ETW providers like in https://learn.microsoft.com/en-us/windows/win32/etw/enumerating-providers
/// </summary>
/// <param name="ctx"></param>
/// <returns></returns>
static DWORD list_providers(unsigned inc)
{
    int res = 0;

    HRESULT hr = S_OK;                          // Return value for StringFromGUID2
    DWORD status = ERROR_SUCCESS;
    DWORD BufferSize = 0;                       // Size of the penum buffer
    PROVIDER_ENUMERATION_INFO* penum = NULL;    // Buffer that contains provider information
    PROVIDER_ENUMERATION_INFO* ptemp = NULL;
    WCHAR StringGuid[MAX_GUID_SIZE];

    // Retrieve the required buffer size.
    status = TdhEnumerateProviders(penum, &BufferSize);

    // Allocate the required buffer and call TdhEnumerateProviders. The list of 
    // providers can change between the time you retrieved the required buffer 
    // size and the time you enumerated the providers, so call TdhEnumerateProviders
    // in a loop until the function does not return ERROR_INSUFFICIENT_BUFFER.

    while (ERROR_INSUFFICIENT_BUFFER == status)
    {
        ptemp = (PROVIDER_ENUMERATION_INFO*)realloc(penum, BufferSize);
        if (NULL == ptemp)
        {
            res = GetLastError();
            goto cleanup;
        }

        penum = ptemp;
        ptemp = NULL;

        status = TdhEnumerateProviders(penum, &BufferSize);
    }

    if (ERROR_SUCCESS != status || penum == NULL)
    {
        res = GetLastError();
        goto cleanup;
    }
    else
    {
        // 1. First we output a group of "scenario" providers.
        // Those scenario are partially taken from Microsoft Message Analyser, partially from other documentation.
        printf("value {arg=%u}{value=SCENARIO}{display=Scenarios}{enabled=false}\n", inc);

        printf("value {arg=%u}{value=Microsoft-Windows-NDIS-PacketCapture}{display=Local Network Interfaces (Microsoft-Windows-NDIS-PacketCapture)}{parent=SCENARIO}\n", inc);
        printf("value {arg=%u}{value=Microsoft-Windows-Ras-NdisWanPacketCapture}{display=VPN traffic (Microsoft-Windows-Ras-NdisWanPacketCapture)}{parent=SCENARIO}\n", inc);
        printf("value {arg=%u}{value=Microsoft-Windows-Wmbclass-Opn}{display=Mobile Broadband (Microsoft-Windows-Wmbclass-Opn)}{parent=SCENARIO}\n", inc);
        printf("value {arg=%u}{value=Microsoft-Windows-LDAP-Client}{display=SASL LDAP pre-encryption (Microsoft-Windows-LDAP-Client)}{parent=SCENARIO}\n", inc);
        printf("value {arg=%u}{value=Microsoft-Windows-WinINet-Capture}{display=WinInet HTTPS pre-encryption (Microsoft-Windows-WinINet-Capture)}{parent=SCENARIO}\n", inc);
        printf("value {arg=%u}{value=Microsoft-Windows-Wmbclass-Opn}{display=Mobile Broadband (Microsoft-Windows-Wmbclass-Opn)}{parent=SCENARIO}\n", inc);
        printf("value {arg=%u}{value=Microsoft-Windows-RPC}{display=RPC (Microsoft-Windows-RPC)}{parent=SCENARIO}\n", inc);
        printf("value {arg=%u}{value=SMB}{display=SMB}{parent=SCENARIO}{enabled=false}\n", inc);
        printf("value {arg=%u}{value=Microsoft-Windows-SMBClient}{display=SMB Client Payloads (Microsoft-Windows-SMBClient)}{parent=SMB}\n", inc);
        printf("value {arg=%u}{value=Microsoft-Windows-SMBServer}{display=SMB Server Payloads (Microsoft-Windows-SMBServer)}{parent=SMB}\n", inc);
        printf("value {arg=%u}{value=BLUETOOTH}{display=Bluetooth}{parent=SCENARIO}{enabled=false}\n", inc);
        printf("value {arg=%u}{value=Microsoft-Windows-BTH-BTHPORT}{display=Bluetooth Host Radio (Microsoft-Windows-BTH-BTHPORT)}{parent=BLUETOOTH}\n", inc);
        printf("value {arg=%u}{value=Microsoft-Windows-BTH-BTHUSB}{display=Bluetooth USB (Microsoft-Windows-BTH-BTHUSB)}{parent=BLUETOOTH}\n", inc);
        printf("value {arg=%u}{value=Microsoft-Windows-Bluetooth-Bthmini}{display=Bluetooth HCI (Microsoft-Windows-Bluetooth-Bthmini)}{parent=BLUETOOTH}\n", inc);

        // 2. Then we output all the providers
        printf("value {arg=%u}{value=ALL}{display=All}{enabled=false}\n", inc);

        // Loop through the list of providers and print the provider's name, GUID,
        // and the source of the information (MOF class or instrumentation manifest).

        for (DWORD i = 0; i < penum->NumberOfProviders; i++)
        {
            hr = StringFromGUID2(&penum->TraceProviderInfoArray[i].ProviderGuid, StringGuid, ARRAYSIZE(StringGuid));
            if (FAILED(hr))
            {
                res = hr;
                goto cleanup;
            }

            // Remove last character }
            StringGuid[37] = 0;

            printf(
                "value {arg=%u}{value=%ls}{display=%ls}{parent=ALL}\n",
                inc,
                StringGuid + 1,  // Remove first character {
                (LPWSTR)((PBYTE)(penum)+penum->TraceProviderInfoArray[i].ProviderNameOffset)
            );
        }
    }

cleanup:

    if (penum)
    {
        free(penum);
        penum = NULL;
    }

    return res;
}

/**
 * Lists the configuration parameters for this extcap interface.
 * @param interface The interface name.
 */
static int list_config(char* interface)
{
    unsigned inc = 0;
    unsigned etwselector;

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
    printf("arg {number=%u}{call=--etlfile}{display=ETL file (source)}"
        "{type=fileselect}{tooltip=If provided, uses an ETL file as source}{required=sufficient}{group=Capture}\n",
        inc++);
    etwselector = inc;
    printf("arg {number=%u}{call=--params}{display=Providers}{configurable=true}{prefix=--p}"
        "{type=table}{tooltip=Should contain the list of provider GUIDs, keyword and level filters for the etl file or live session.}{required=sufficient}{group=Capture}\n",
        inc++);
    /*
    * The undecidable events are those that either don't have sub-dissector or don't have anthing meaningful to display except for the EVENT_HEADER.
    */
    printf("arg {number=%u}{call=--iue}{display=Should undecidable events be included}"
        "{type=boolflag}{default=false}{tooltip=Choose if the undecidable event is included}{group=Capture}\n",
        inc++);

    /*
     * Display known providers.
     */
    if (FAILED(list_providers(etwselector)))
    {
        ws_warning("Failed to list ETW providers.");
        return EXIT_FAILURE;
    }

    extcap_config_debug(&inc);
    return EXIT_SUCCESS;
}

/**
 * Lists the sub-configuration parameters for the 'params' values.
 * @param interface The interface name.
 * @param option_name The value of the option queried (only 'params' supported)
 * @param option_value The value of the provider we're getting sub-options for.
 */
static int list_config_option(char* interface, char* option_name, char* option_value)
{
    unsigned inc = 0;
    unsigned loglevelselector = 0;

    if (!interface) {
        ws_warning("No interface specified.");
        return EXIT_FAILURE;
    }

    if (g_strcmp0(interface, ETW_EXTCAP_INTERFACE)) {
        ws_warning("Interface must be %s", ETW_EXTCAP_INTERFACE);
        return EXIT_FAILURE;
    }

    if (g_strcmp0(option_name, "params")) {
        /* Nothing to show for parameters != 'params' */
        return EXIT_SUCCESS;
    }

    /*
     * There's always at least the keyword and the level argument to offer.
     */
    printf("arg {number=%u}{call=--k}{display=Keywords}"
        "{type=string}{tooltip=What keywords to select for this provider. Defaults to ALL}{default=0xffffffffffffffff}\n",
        inc++);
    loglevelselector = inc;
    printf("arg {number=%u}{call=--l}{display=Level}"
        "{type=selector}{tooltip=What log level to apply to this provider}\n",
        inc++);

    /* The 6 possible log levels (from traceview) */
    printf("value {arg=%u}{value=0}{display=0 Log always}{default=false}\n", loglevelselector);
    printf("value {arg=%u}{value=1}{display=1 Critical}{default=false}\n", loglevelselector);
    printf("value {arg=%u}{value=2}{display=2 Error}{default=false}\n", loglevelselector);
    printf("value {arg=%u}{value=3}{display=3 Warning}{default=false}\n", loglevelselector);
    printf("value {arg=%u}{value=4}{display=4 Information}{default=false}\n", loglevelselector);
    printf("value {arg=%u}{value=5}{display=5 Verbose}{default=true}\n", loglevelselector);

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

    /* Set the program name. */
    g_set_prgname("etwdump");

    /* Initialize log handler early so we can have proper logging during startup. */
    extcap_log_init();

    /*
     * Get credential information for later use.
     */
    init_process_policies();

    /*
     * Attempt to get the pathname of the directory containing the
     * executable file.
     */
    err_msg = configuration_init(argv[0]);
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

    if (extcap_conf->show_config_option) {
        ret = list_config_option(extcap_conf->interface, extcap_conf->config_option_name,
            extcap_conf->config_option_value);
        goto end;
    }

    if (extcap_conf->capture) {

        if (g_strcmp0(extcap_conf->interface, ETW_EXTCAP_INTERFACE)) {
            ws_warning("ERROR: invalid interface");
            goto end;
        }

        if (etlfile == NULL && params == NULL)
        {
            ws_warning("ERROR: You should select at least either one provider (--params) or a file (--etlfile).");
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
