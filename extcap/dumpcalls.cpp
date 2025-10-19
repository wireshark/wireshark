/* dumpcalls.cpp
 * Dumpcalls is an extcap tool which dumps system calls on Linux.
 * https://github.com/falcosecurity/libs/
 *
 * Adapted from sdjournal.
 * Copyright 2022, Gerald Combs and Dario Lombardo
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * To do:
 * - Exit more cleanly (see MRs 2063 and 7673).
 */

#include "config.h"

#include <libsinsp/sinsp.h>

#include <libscap/scap_engines.h>

#define WS_LOG_DOMAIN "dumpcalls"

#include <extcap/extcap-base.h>

#include <app/application_flavor.h>     //Stratoshark only
#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <wsutil/json_dumper.h>
#include <wsutil/privileges.h>
#include <wsutil/utf8_entities.h>
#include <wsutil/wsjson.h>
#include <wsutil/wslog.h>

#define DUMPCALLS_VERSION_MAJOR "1"
#define DUMPCALLS_VERSION_MINOR "0"
#define DUMPCALLS_VERSION_RELEASE "0"

#define DUMPCALLS_PLUGIN_PLACEHOLDER "<modern_bpf or kmod>"

#define SINSP_CHECK_VERSION(major, minor, micro) \
    (((SINSP_VERSION_MAJOR << 16) + (SINSP_VERSION_MINOR << 8) + SINSP_VERSION_MICRO) >= ((major << 16) + (minor << 8) + micro))

enum {
    EXTCAP_BASE_OPTIONS_ENUM,
    OPT_HELP,
    OPT_VERSION,
#if defined(HAS_ENGINE_KMOD) || defined(HAS_ENGINE_MODERN_BPF)
    OPT_INCLUDE_CAPTURE_PROCESSES,
    OPT_INCLUDE_SWITCH_CALLS,
#endif
};

#if defined(HAS_ENGINE_KMOD) || defined(HAS_ENGINE_MODERN_BPF)
struct syscall_configuration {
    bool include_capture_processes;
    bool include_switch_calls;
};
#endif

// Given a key, try to find its value in a JSON object.
// Returns (value, true) on success, or (err_str, false) on failure.
const std::pair<const std::string,bool> find_json_object_value(const std::string &object_blob, const std::string &key, int value_type) {
    std::vector<jsmntok_t> tokens;
    int num_tokens = json_parse(object_blob.c_str(), NULL, 0);

    switch (num_tokens) {
    case JSMN_ERROR_INVAL:
        return std::pair<std::string,bool>("invalid", false);
    case JSMN_ERROR_PART:
        return std::pair<std::string,bool>("incomplete", false);
    default:
        break;
    }

    tokens.resize(num_tokens);
    json_parse(object_blob.c_str(), tokens.data(), num_tokens);
    for (int idx = 0; idx < num_tokens - 1; idx++) {
        jsmntok_t &k_tok = tokens[idx];
        jsmntok_t &v_tok = tokens[idx+1];
        std::string cur_key = object_blob.substr(k_tok.start, k_tok.end - k_tok.start);
        if (cur_key == key && k_tok.type == JSMN_STRING && v_tok.type == value_type) {
            std::string value = object_blob.substr(v_tok.start, v_tok.end - v_tok.start);
            return std::pair<std::string,bool>(value, true);
        }
#ifdef DEBUG_JSON_PARSING
        else if (cur_key == key) ws_warning("|%s(%d): %s(%d)|\n", cur_key.c_str(), k_tok.type, object_blob.substr(v_tok.start, v_tok.end - v_tok.start).c_str(), v_tok.type);
#endif
    }
    return std::pair<const std::string,bool>("", false);
}

// Given an RFC 6901-style JSON pointer, try to find its value in a JSON object.
// Returns (value, true) on success, or (err_str, false) on failure.
const std::pair<const std::string,bool> find_json_pointer_value(const std::string &object_blob, const std::string &pointer, int value_type) {
    std::string blob = object_blob;
    std::istringstream ob_stream(pointer);
    std::string token;
    while (std::getline(ob_stream, token, '/')) {
        if (token == "#" || token.empty()) {
            continue;
        }
        std::pair<std::string,bool> jv = find_json_object_value(blob, token, value_type);
        if (!jv.second) {
#ifdef DEBUG_JSON_PARSING
            ws_warning("JSON pointer %s not found at %s", blob.c_str(), token.c_str());
#endif
            return std::pair<std::string,bool>("", false);
        }
        blob = jv.first;
    }
#ifdef DEBUG_JSON_PARSING
    ws_warning("JSON pointer %s = %s ... %s", pointer.c_str(), blob.substr(0, 10).c_str(), blob.substr(blob.size() - 10, 10).c_str());
#endif
    return std::pair<const std::string,bool>(blob, true);
}

// Convert a JSON array to a string vector.
// Returns (vector, true) on success, or (err_str, false) on failure.
const std::pair<std::vector<std::string>,bool> get_json_array(const std::string &array_blob) {
    std::vector<jsmntok_t> tokens;
    int num_tokens = json_parse(array_blob.c_str(), NULL, 0);

    switch (num_tokens) {
    case JSMN_ERROR_INVAL:
        return std::pair<std::vector<std::string>,bool>(std::vector<std::string>{"invalid"}, false);
    case JSMN_ERROR_PART:
    {
        return std::pair<std::vector<std::string>,bool>(std::vector<std::string>{"incomplete"}, false);
    }
    default:
        break;
    }

    tokens.resize(num_tokens);
    json_parse(array_blob.c_str(), tokens.data(), num_tokens);
    std::vector<std::string> elements;
    // First token is the full array.
    for (int idx = 1; idx < num_tokens; idx++) {
        jsmntok_t &el_tok = tokens[idx];
        elements.push_back(array_blob.substr(el_tok.start, el_tok.end - el_tok.start));
    }
#ifdef DEBUG_JSON_PARSING
    ws_warning("%s: %d", array_blob.c_str(), (int)elements.size());
#endif
    return std::pair<std::vector<std::string>,bool>(elements, true);
}

// Build our command line options.
static const std::vector<ws_option> get_longopts(void) {
    std::vector<ws_option> longopts;
    struct ws_option base_longopts[] = {
        EXTCAP_BASE_OPTIONS,
        { "help", ws_no_argument, NULL, OPT_HELP},
        { "version", ws_no_argument, NULL, OPT_VERSION},
#if defined(HAS_ENGINE_KMOD) || defined(HAS_ENGINE_MODERN_BPF)
        { "include-capture-processes", ws_required_argument, NULL, OPT_INCLUDE_CAPTURE_PROCESSES },
        { "include-switch-calls", ws_required_argument, NULL, OPT_INCLUDE_SWITCH_CALLS },
#endif
        { 0, 0, 0, 0}
    };
    int idx;
    for (idx = 0; base_longopts[idx].name; idx++) {
        longopts.push_back(base_longopts[idx]);
    }
    longopts.push_back(base_longopts[idx]);
    return longopts;
}

#if defined(HAS_ENGINE_KMOD) || defined(HAS_ENGINE_MODERN_BPF)
static bool
get_bool_value(const char *bool_str)
{
    if (!bool_str) {
        return false;
    }
    switch (bool_str[0]) {
        case 'f':
        case 'F':
        case '0':
            return false;
        default:
            return true;
    }
}

// Show the configuration for a given interface.
static int show_syscall_config(void)
{
    printf(
        "arg {number=0}"
        "{call=--include-capture-processes}"
        "{display=Include capture processes}"
        "{type=boolean}"
        "{tooltip=Include system calls made by any capture processes (dumpcalls, dumpcap, and Stratoshark)}"
        "{required=false}"
        "{group=Capture}\n"

        "arg {number=1}"
        "{call=--include-switch-calls}"
        "{display=Include \"switch\" calls}"
        "{type=boolean}"
        "{tooltip=Include \"switch\" system calls}"
        "{required=false}"
        "{group=Capture}\n"

        "value {arg=0}{value=1}\n"
        );

    return EXIT_SUCCESS;
}

#include <fstream>
#include <iostream>
static const std::string syscall_capture_filter(const struct syscall_configuration &syscall_config, const char *capture_filter)
{
    if (syscall_config.include_capture_processes && syscall_config.include_switch_calls) {
        if (capture_filter) {
            return std::string(capture_filter);
        } else {
            return std::string();
        }
    }

    std::string filter;

    if (capture_filter) {
        filter = "(" + std::string(capture_filter) + ") and (";
    }

    if (!syscall_config.include_capture_processes) {
        // We want to exclude Stratoshark and any of its children, including
        // this one (dumpcalls).

        std::string pid, comm, _s, ppid;

        // Exclude this process only at a minimum.
        std::ifstream stat_stream("/proc/self/stat");
        stat_stream >> pid >> comm >> _s >> ppid;
        std::string process_filter = "proc.pid != " + pid;
        if (comm != "(dumpcalls)") {
            ws_warning("Our process is named %s, not dumpcalls", comm.c_str());
        }
        stat_stream.close();

        // If our parent is Stratoshark, exclude it and its direct children.
        std::ifstream pstat_stream("/proc/" + ppid + "/stat");
        pstat_stream >> _s >> comm;
        if (comm == "(stratoshark)") {
            // XXX Use proc.apid instead?
            process_filter = "proc.pid != " + ppid + " and proc.ppid != " + ppid;
        }
        pstat_stream.close();

        filter += process_filter;
    }

    if (!syscall_config.include_switch_calls) {
        if (!syscall_config.include_capture_processes) {
            filter += " and ";
        }
        filter += "evt.type != switch";
    }

    if (capture_filter) {
        filter += ")";
    }

    return filter;
}
#endif // HAS_ENGINE_KMOD || HAS_ENGINE_MODERN_BPF

int main(int argc, char **argv)
{
    char* configuration_init_error;
    int result;
    int option_idx = 0;
    int ret = EXIT_FAILURE;
    extcap_parameters* extcap_conf = g_new0(extcap_parameters, 1);
#if defined(HAS_ENGINE_KMOD) || defined(HAS_ENGINE_MODERN_BPF)
    struct syscall_configuration syscall_config = {};
#endif
    char* help_url;
    char* help_header = NULL;
    sinsp inspector;

    /* Set the program name. */
    g_set_prgname("dumpcalls");

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
    configuration_init_error = configuration_init(argv[0], "stratoshark");
    if (configuration_init_error != NULL) {
        ws_warning("Can't get pathname of directory containing the extcap program: %s.",
                configuration_init_error);
        g_free(configuration_init_error);
    }

    // Plain eBPF requires extra configuration, so probe for kmod and modern BPF support only for now.
#ifdef HAS_ENGINE_KMOD
    try {
        inspector.open_kmod();
        extcap_base_register_interface(extcap_conf, KMOD_ENGINE, "System calls via kernel module", 147, "USER0");
    } catch (sinsp_exception &e) {
        ws_debug("Unable to probe " KMOD_ENGINE ": %s", e.what());
    }
    inspector.close();
#endif
#ifdef HAS_ENGINE_MODERN_BPF
    try {
        inspector.open_modern_bpf();
        extcap_base_register_interface(extcap_conf, MODERN_BPF_ENGINE, "System calls via modern eBPF", 147, "USER0");
    } catch (sinsp_exception &e) {
        ws_debug("Unable to probe " MODERN_BPF_ENGINE ": %s", e.what());
    }
    inspector.close();
#endif

    if (g_list_length(extcap_conf->interfaces) < 1) {
        ws_warning("No interfaces found. Are you running on Linux, and was libscap built with kmod or modern_bpf support?");
        // This should maybe be WS_EXIT_NO_INTERFACES from ws_exit_codes.h,
        // if we updated the tests to allow that as a valid exit code.
        // ret = WS_EXIT_NO_INTERFACES;
        goto end;
    }

    help_url = data_file_url("dumpcalls.html", application_configuration_environment_prefix());
    extcap_base_set_util_info(extcap_conf, argv[0], DUMPCALLS_VERSION_MAJOR, DUMPCALLS_VERSION_MINOR,
            DUMPCALLS_VERSION_RELEASE, help_url);
    g_free(help_url);

    help_header = ws_strdup_printf(
            " %s --extcap-interfaces\n"
            " %s --extcap-interface=%s --extcap-capture-filter=<filter>\n"
            " %s --extcap-interface=%s --extcap-dlts\n"
            " %s --extcap-interface=%s --extcap-config\n"
            " %s --extcap-interface=%s --fifo=<filename> --capture [--extcap-capture-filter=<filter>]\n",
            argv[0],
            argv[0], DUMPCALLS_PLUGIN_PLACEHOLDER,
            argv[0], DUMPCALLS_PLUGIN_PLACEHOLDER,
            argv[0], DUMPCALLS_PLUGIN_PLACEHOLDER,
            argv[0], DUMPCALLS_PLUGIN_PLACEHOLDER);
    extcap_help_add_header(extcap_conf, help_header);
    g_free(help_header);
    extcap_help_add_option(extcap_conf, "--help", "print this help");
    extcap_help_add_option(extcap_conf, "--version", "print the version");
    extcap_help_add_option(extcap_conf, "--include-capture-processes", "Include capture processes");
    extcap_help_add_option(extcap_conf, "--include-switch-calls", "Include \"switch\" calls");

    ws_opterr = 0;
    ws_optind = 0;

    if (argc == 1) {
        extcap_help_print(extcap_conf);
        goto end;
    }

    static const std::vector<ws_option> longopts = get_longopts();
    while ((result = ws_getopt_long(argc, argv, ":", longopts.data(), &option_idx)) != -1) {

        switch (result) {

            case OPT_HELP:
                extcap_help_print(extcap_conf);
                ret = EXIT_SUCCESS;
                goto end;

            case OPT_VERSION:
                extcap_version_print(extcap_conf);
                ret = EXIT_SUCCESS;
                goto end;

#if defined(HAS_ENGINE_KMOD) || defined(HAS_ENGINE_MODERN_BPF)
            case OPT_INCLUDE_CAPTURE_PROCESSES:
                syscall_config.include_capture_processes = get_bool_value(ws_optarg);
                break;

            case OPT_INCLUDE_SWITCH_CALLS:
                syscall_config.include_switch_calls = get_bool_value(ws_optarg);
                break;
#endif

            case ':':
                /* missing option argument */
                ws_warning("Option '%s' requires an argument", argv[ws_optind - 1]);
                break;

            default:
                if (!extcap_base_parse_options(extcap_conf, result - EXTCAP_OPT_LIST_INTERFACES, ws_optarg)) {
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
#ifdef HAS_ENGINE_KMOD
        if (strcmp(extcap_conf->interface, KMOD_ENGINE) == 0)
        {
            ret = show_syscall_config();
        }
        else
#endif
#ifdef HAS_ENGINE_MODERN_BPF
        if (strcmp(extcap_conf->interface, MODERN_BPF_ENGINE) == 0)
        {
            ret = show_syscall_config();
        }
#endif
        goto end;
    }

    if (extcap_conf->capture || extcap_conf->capture_filter) {
        bool builtin_capture = false;

#ifdef DEBUG_SINSP
        inspector.set_debug_mode(true);
        inspector.set_log_stderr();
#endif

#ifdef HAS_ENGINE_KMOD
        if (strcmp(extcap_conf->interface, KMOD_ENGINE) == 0)
        {
            try {
                inspector.open_kmod();
                builtin_capture = true;
            } catch (sinsp_exception &e) {
                ws_warning("Unable to open " KMOD_ENGINE ": %s", e.what());
            }
        }
        else
#endif
#ifdef HAS_ENGINE_MODERN_BPF
        if (strcmp(extcap_conf->interface, MODERN_BPF_ENGINE) == 0)
        {
            try {
                inspector.open_modern_bpf();
                builtin_capture = true;
            } catch (sinsp_exception &e) {
                ws_warning("Unable to open " MODERN_BPF_ENGINE ": %s", e.what());
            }
        }
#endif

        if (!extcap_conf->capture) {
            // Check our filter syntax
            try {
                sinsp_filter_compiler compiler(&inspector, extcap_conf->capture_filter);
                compiler.compile();
            } catch (sinsp_exception &e) {
                fprintf(stdout, "%s", e.what());
                goto end;
            }
            ret = EXIT_SUCCESS;
            goto end;
        }

        sinsp_dumper dumper;
        try {
            dumper.open(&inspector, extcap_conf->fifo, false);
        } catch (sinsp_exception &e) {
            dumper.close();
            ws_warning("%s", e.what());
            goto end;
        }

#if defined(HAS_ENGINE_KMOD) || defined(HAS_ENGINE_MODERN_BPF)
        std::string capture_filter = syscall_capture_filter(syscall_config, extcap_conf->capture_filter);
        if (!capture_filter.empty()) {
            ws_debug("Setting filter %s\n", capture_filter.c_str());
            try {
                inspector.set_filter(capture_filter);
            } catch (sinsp_exception &e) {
                fprintf(stdout, "%s", e.what());
                goto end;
            }
        }
#endif

        if (builtin_capture) {
            inspector.start_capture();
        }

        sinsp_evt *evt;
        ws_noisy("Starting capture loop.");
        while (!extcap_end_application) {
            try {
                int32_t res = inspector.next(&evt);
                switch (res) {
                case SCAP_TIMEOUT:
                case SCAP_FILTERED_EVENT:
                    break;
                case SCAP_SUCCESS:
                    dumper.dump(evt);
                    dumper.flush();
                    break;
                default:
                    ws_noisy("Inspector exited with %d", res);
                    extcap_end_application = true;
                    break;
                }
            } catch (sinsp_exception &e) {
                ws_warning("%s", e.what());
                goto end;
            }
        }
        ws_noisy("Closing dumper and inspector.");
        if (builtin_capture) {
            inspector.stop_capture();
        }
        dumper.close();
        inspector.close();
        ret = EXIT_SUCCESS;
    } else {
        ws_debug("You should not be here... maybe some parameter missing?");
    }

end:
    /* clean up stuff */
    extcap_base_cleanup(&extcap_conf);
    return ret;
}
