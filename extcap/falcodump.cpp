/* falcodump.cpp
 * Falcodump is an extcap tool which dumps logs using Falco source plugins.
 * https://falco.org/docs/plugins/
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
 * - Pull plugin source description from list_open_params?
 * - Paste in environment variables?
 * - Add filtering.
 *   - Add an option to dump plugin fields.
 * - Add options for credentials.
 * - Let the user create preconfigured interfaces.
 * - Exit more cleanly (see MRs 2063 and 7673).
 * - Proper config schema parsing? We've hardcoded #/definitions/PluginConfig/properties.
 * - Better config schema property names in the UI (requires schema change).
 * - Better config schema default value parsing? Would likely require a schema change.
 * - Make sure all types are handled in parse_schema_properties.
 * - Handle "required" config schema annotation (Okta).
 */

#include "config.h"

#include <sinsp.h>
#include <plugin_manager.h>

#define WS_LOG_DOMAIN "falcodump"

#include <extcap/extcap-base.h>

#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <wsutil/json_dumper.h>
#include <wsutil/privileges.h>
#include <wsutil/utf8_entities.h>
#include <wsutil/wsjson.h>
#include <wsutil/wslog.h>

#define FALCODUMP_VERSION_MAJOR "1"
#define FALCODUMP_VERSION_MINOR "0"
#define FALCODUMP_VERSION_RELEASE "0"

#define FALCODUMP_PLUGIN_PLACEHOLDER "<plugin name>"

// #define DEBUG_JSON_PARSING
// #define DEBUG_SINSP

enum {
    EXTCAP_BASE_OPTIONS_ENUM,
    OPT_HELP,
    OPT_VERSION,
    OPT_PLUGIN_API_VERSION,
    OPT_PLUGIN_SOURCE,
    OPT_SCHEMA_PROPERTIES_START,
};

//        "s3DownloadConcurrency": {
//          "type": "integer",
//          "description": "Controls the number of background goroutines used to download S3 files (Default: 1)"
//        },
struct config_schema_properties {
    std::string name;
    std::string display;        // "title" property || name
    std::string option;         // Command line option including leading dashes (lowercase display name)
    int option_index;           // Starts from OPT_SCHEMA_PROPERTIES_START
    std::string type;           // "boolean", "integer", "string"
    std::string description;
    std::string default_value;
    std::string current_value;
};

struct plugin_configuration {
    std::vector<struct config_schema_properties> properties;
    std::string json_config() {
        json_dumper dumper = {
            .output_string = g_string_new(NULL),
        };

        json_dumper_begin_object(&dumper);
        for (const auto &prop : properties) {
            if (prop.current_value == prop.default_value) {
                continue;
            }
            json_dumper_set_member_name(&dumper, prop.name.c_str());
            if (prop.type == "string") {
                json_dumper_value_string(&dumper, prop.current_value.c_str());
            } else {
                json_dumper_value_anyf(&dumper, "%s", prop.current_value.c_str());
            }
        }
        json_dumper_end_object(&dumper);
        json_dumper_finish(&dumper);
        std::string config_blob = dumper.output_string->str;
        ws_debug("configuration: %s", dumper.output_string->str);
        g_string_free(dumper.output_string, TRUE);
        return config_blob;
    }
};

// Load our plugins. This should match the behavior of the Falco Bridge dissector.
static void load_plugins(sinsp &inspector) {
    WS_DIR *dir;
    WS_DIRENT *file;
    char *plugin_path = g_build_filename(get_plugins_dir_with_version(), "falco", NULL);

    if ((dir = ws_dir_open(plugin_path, 0, NULL)) != NULL) {
        while ((file = ws_dir_read_name(dir)) != NULL) {
            char *libname = g_build_filename(plugin_path, ws_dir_get_name(file), NULL);
            inspector.register_plugin(libname);
            g_free(libname);
        }
        ws_dir_close(dir);
    }
    g_free(plugin_path);
}

// Given a key, try to find its value in a JSON blob.
// Returns (value, true) on success, or (err_str, false) on failure.
const std::pair<std::string,bool> find_json_value(const std::string blob, const std::string key, int key_type, int value_type) {
    std::vector<jsmntok_t> tokens;
    int num_tokens = json_parse(blob.c_str(), NULL, 0);

    switch (num_tokens) {
    case JSMN_ERROR_INVAL:
        return std::pair<std::string,bool>("invalid", false);
    case JSMN_ERROR_PART:
        return std::pair<std::string,bool>("incomplete", false);
    default:
        break;
    }

    tokens.resize(num_tokens);
    json_parse(blob.c_str(), tokens.data(), num_tokens);
    for (int idx = 0; idx < num_tokens - 1; idx++) {
        jsmntok_t &k_tok = tokens[idx];
        jsmntok_t &v_tok = tokens[idx+1];
        std::string cur_key = blob.substr(k_tok.start, k_tok.end - k_tok.start);
        if (cur_key == key && k_tok.type == key_type && v_tok.type == value_type) {
            std::string value = blob.substr(v_tok.start, v_tok.end - v_tok.start);
            return std::pair<std::string,bool>(value, true);
        }
#ifdef DEBUG_JSON_PARSING
        else if (cur_key == key) ws_debug("|%s(%d): %s(%d)|\n", cur_key.c_str(), k_tok.type, blob.substr(v_tok.start, v_tok.end - v_tok.start).c_str(), v_tok.type);
#endif
    }
    return std::pair<std::string,bool>("", false);
}

// Given a JSON blob containing a schema properties map, add each property to the
// given plugin config.
const std::pair<std::string,bool> parse_schema_properties(const std::string props_blob, const std::string plugin_name, plugin_configuration &plugin_config) {
    std::vector<jsmntok_t> tokens;
    int num_tokens = json_parse(props_blob.c_str(), NULL, 0);

    switch (num_tokens) {
    case JSMN_ERROR_INVAL:
        return std::pair<std::string,bool>("invalid", false);
    case JSMN_ERROR_PART:
        return std::pair<std::string,bool>("incomplete", false);
    default:
        break;
    }

    tokens.resize(num_tokens);
    json_parse(props_blob.c_str(), tokens.data(), num_tokens);

    if (tokens[0].type != JSMN_OBJECT) {
        return std::pair<std::string,bool>("malformed", false);
    }

    char *plugin_name_lower = g_ascii_strdown(plugin_name.c_str(), -1);

    int idx = 1; // Skip over { ... }
    int opt_idx = OPT_SCHEMA_PROPERTIES_START;
    while (idx < num_tokens - 1) {
        jsmntok_t &n_tok = tokens[idx];
        std::string name = props_blob.substr(n_tok.start, n_tok.end - n_tok.start);
        std::string display = name;
        jsmntok_t &p_tok = tokens[idx+1];
        std::string property_blob = props_blob.substr(p_tok.start, p_tok.end - p_tok.start);

        std::pair<std::string,bool> jv = find_json_value(property_blob, "title", JSMN_OBJECT|JSMN_ARRAY, JSMN_OBJECT|JSMN_ARRAY);
        if (jv.second) {
            display = jv.first;
        }
        // else split+capitalize "name"?

        jv = find_json_value(property_blob, "type", JSMN_OBJECT|JSMN_ARRAY, JSMN_OBJECT|JSMN_ARRAY);
        if (!jv.second) {
            return std::pair<std::string,bool>(jv.first, false);
        }
        std::string type = jv.first;
        jv = find_json_value(property_blob, "description", JSMN_OBJECT|JSMN_ARRAY, JSMN_OBJECT|JSMN_ARRAY);
        if (!jv.second) {
            return std::pair<std::string,bool>(jv.first, false);
        }
        std::string description = jv.first;
        std::string default_value;
        jv = find_json_value(property_blob, "default", JSMN_OBJECT|JSMN_ARRAY, JSMN_OBJECT|JSMN_ARRAY);
        if (jv.second) {
            default_value = jv.first;
        } else {
            std::string default_pfx = "(Default: ";
            size_t pfx_pos = description.rfind(default_pfx);
            if (pfx_pos != std::string::npos) {
                default_value = description.substr(pfx_pos + default_pfx.size());
                pfx_pos = default_value.rfind(")");
                default_value = default_value.erase(pfx_pos);
            }
        }
#ifdef DEBUG_JSON_PARSING
        ws_debug("%s: %s, %s\n", name.c_str(), type.c_str(), description.c_str());
#endif
        const char *call = g_ascii_strdown(name.c_str(), -1);
        config_schema_properties properties = {
            name,
            display,
            std::string() + plugin_name_lower + "-" + call, // Command line option (lowercase plugin + display name)
            opt_idx,
            type,
            description,
            default_value,
            default_value
        };
        plugin_config.properties.push_back(properties);
        g_free((gpointer)call);
        idx++;
        opt_idx++;
        // Skip to the next "name: { ... }" pair.
        for ( ; idx < num_tokens - 1 && tokens[idx+1].type != JSMN_OBJECT ; idx++);
    }
    g_free(plugin_name_lower);
    return std::pair<std::string,bool>("",true);
}

// Given a plugin config schema like the following:
//{
//  "$schema": "http://json-schema.org/draft-04/schema#",
//  "$ref": "#/definitions/PluginConfig",
//  "definitions": {
//    "PluginConfig": {
//      "properties": {
//        "s3DownloadConcurrency": {
//          "type": "integer",
//          "description": "Controls the number of background goroutines used to download S3 files (Default: 1)"
//        },
//        "sqsDelete": {
//          "type": "boolean",
//          "description": "If true then the plugin will delete sqs messages from the queue immediately after receiving them (Default: true)"
//        },
//        "useAsync": {
//          "type": "boolean",
//          "description": "If true then async extraction optimization is enabled (Default: true)"
//        }
//      },
//      "additionalProperties": true,
//      "type": "object"
//    }
//  }
//}
// find the plugin properties and parse them using parse_schema_properties.
// https://json-schema.org/draft/2020-12/json-schema-validation.html#name-a-vocabulary-for-basic-meta

static bool get_plugin_config_schema(const std::shared_ptr<sinsp_plugin> &plugin, plugin_configuration &plugin_config)
{
    ss_plugin_schema_type schema_type = SS_PLUGIN_SCHEMA_JSON;
    std::string init_schema = plugin->get_init_schema(schema_type);

    std::pair<std::string,bool> jv = find_json_value(init_schema, "definitions", JSMN_OBJECT|JSMN_ARRAY, JSMN_OBJECT);
    if (!jv.second) {
        ws_warning("ERROR: Interface \"%s\" has an %s configuration schema.", plugin->name().c_str(), jv.first.c_str());
        return false;
    }
#ifdef DEBUG_JSON_PARSING
    ws_debug("%s\n", jv.first.c_str());
#endif
    std::string definitions = jv.first;
    jv = find_json_value(definitions, "PluginConfig", JSMN_OBJECT|JSMN_ARRAY, JSMN_OBJECT);
    if (!jv.second) {
        ws_warning("ERROR: Interface \"%s\" has an %s configuration schema.", plugin->name().c_str(), jv.first.c_str());
        return false;
    }
    std::string pluginconfig = jv.first;
    jv = find_json_value(pluginconfig, "properties", JSMN_OBJECT|JSMN_ARRAY, JSMN_OBJECT);
    if (!jv.second) {
        ws_warning("ERROR: Interface \"%s\" has an %s configuration schema.", plugin->name().c_str(), jv.first.c_str());
        return false;
    }
#ifdef DEBUG_JSON_PARSING
    ws_debug("properties: %s\n", jv.first.c_str());
#endif
    jv = parse_schema_properties(jv.first, plugin->name(), plugin_config);
    if (!jv.second) {
        ws_warning("ERROR: Interface \"%s\" has an %s configuration schema.", plugin->name().c_str(), jv.first.c_str());
        return false;
    }

    return true;
}

// For each loaded plugin, get its name and properties.
static bool get_source_plugins(sinsp &inspector, std::map<std::string, struct plugin_configuration> &plugin_configs) {
    const sinsp_plugin_manager *plugin_manager = inspector.get_plugin_manager();

    // XXX sinsp_plugin_manager::sources() can return different names, e.g. aws_cloudtrail vs cloudtrail.
    for (const auto &plugin : plugin_manager->plugins()) {
        if (plugin->caps() & CAP_SOURCING) {
            plugin_configuration plugin_config = {};
            if (!get_plugin_config_schema(plugin, plugin_config)) {
                return false;
            }
            plugin_configs[plugin->name()] = plugin_config;
        }
    }
    return true;
}

// Build our command line options based on our source plugins.
static const std::vector<ws_option> get_longopts(const std::map<std::string, struct plugin_configuration> &plugin_configs) {
    std::vector<ws_option> longopts;
    struct ws_option base_longopts[] = {
        EXTCAP_BASE_OPTIONS,
        { "help", ws_no_argument, NULL, OPT_HELP},
        { "version", ws_no_argument, NULL, OPT_VERSION},
        { "plugin-api-version", ws_no_argument, NULL, OPT_PLUGIN_API_VERSION},
        { "plugin-source", ws_required_argument, NULL, OPT_PLUGIN_SOURCE },
        { 0, 0, 0, 0}
    };
    int idx;
    for (idx = 0; base_longopts[idx].name; idx++) {
        longopts.push_back(base_longopts[idx]);
    }
    for (const auto &it : plugin_configs) {
        const struct plugin_configuration plugin_configs = it.second;
        for (const auto &prop : plugin_configs.properties) {
            ws_option option = { g_strdup(prop.option.c_str()), ws_required_argument, NULL, prop.option_index };
            longopts.push_back(option);
        }
    }
    longopts.push_back(base_longopts[idx]);
    return longopts;
}

// Show the configuration for a given plugin/interface.
static int show_config(const std::string &interface, const struct plugin_configuration &plugin_config)
{
    unsigned arg_num = 0;
//    char* plugin_filter;

    if (interface.empty()) {
        ws_warning("ERROR: No interface specified.");
        return EXIT_FAILURE;
    }

    printf(
        "arg {number=%u}"
        "{call=--plugin-source}"
        "{display=Plugin source}"
        "{type=string}"
        "{tooltip=The plugin data source. This us usually a URL.}"
        "{placeholder=Enter a source URL" UTF8_HORIZONTAL_ELLIPSIS "}"
        "{required=true}"
        "{group=Capture}\n",
        arg_num++);
//    if (plugin_filter)
//        printf("{default=%s}", plugin_filter);
//    printf("{group=Capture}\n");
    for (const auto &properties : plugin_config.properties) {
        std::string default_value;
        if (!properties.default_value.empty()) {
            default_value = "{default=" + properties.default_value + "}";
        }
        const char *cfg_line = g_strdup_printf(
            "arg {number=%d}"
            "{call=--%s}"
            "{display=%s}"
            "{type=%s}"
            "%s"
            "{tooltip=%s}"
            "{group=Capture}",
            arg_num++, properties.option.c_str(), properties.display.c_str(), properties.type.c_str(), default_value.c_str(), properties.description.c_str());
        puts(cfg_line);
        g_free((gpointer)cfg_line);
    }
    extcap_config_debug(&arg_num);

    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    char* configuration_init_error;
    int result;
    int option_idx = 0;
    int ret = EXIT_FAILURE;
    extcap_parameters* extcap_conf = g_new0(extcap_parameters, 1);
    std::map<std::string, struct plugin_configuration> plugin_configs;
    char* help_url;
    char* help_header = NULL;
    sinsp inspector;
    std::string plugin_source;

    /* Initialize log handler early so we can have proper logging during startup. */
    extcap_log_init("falcodump");

    /*
     * Get credential information for later use.
     */
    init_process_policies();

    /*
     * Attempt to get the pathname of the directory containing the
     * executable file.
     */
    configuration_init_error = configuration_init(argv[0], "Logray");
    if (configuration_init_error != NULL) {
        ws_warning("Can't get pathname of directory containing the extcap program: %s.",
                configuration_init_error);
        g_free(configuration_init_error);
    }

    load_plugins(inspector);

    if (!get_source_plugins(inspector, plugin_configs)) {
        goto end;
    }

    for (auto iter = plugin_configs.begin(); iter != plugin_configs.end(); ++iter) {
        // We don't have a Falco source plugins DLT, so use USER0 (147).
        // Additional info available via plugin->description() and plugin->event_source().
        extcap_base_register_interface(extcap_conf, iter->first.c_str(), "Falco plugin", 147, "USER0");
    }

    help_url = data_file_url("falcodump.html");
    extcap_base_set_util_info(extcap_conf, argv[0], FALCODUMP_VERSION_MAJOR, FALCODUMP_VERSION_MINOR,
            FALCODUMP_VERSION_RELEASE, help_url);
    g_free(help_url);

    help_header = ws_strdup_printf(
            " %s --extcap-interfaces\n"
            " %s --extcap-interface=%s --extcap-dlts\n"
            " %s --extcap-interface=%s --extcap-config\n"
            " %s --extcap-interface=%s --fifo=<filename> --capture --plugin-source=<source url>\n",
            argv[0],
            argv[0], FALCODUMP_PLUGIN_PLACEHOLDER,
            argv[0], FALCODUMP_PLUGIN_PLACEHOLDER,
            argv[0], FALCODUMP_PLUGIN_PLACEHOLDER);
    extcap_help_add_header(extcap_conf, help_header);
    g_free(help_header);
    extcap_help_add_option(extcap_conf, "--help", "print this help");
    extcap_help_add_option(extcap_conf, "--version", "print the version");
    extcap_help_add_option(extcap_conf, "--plugin-api-version", "print the Falco plugin API version");
    extcap_help_add_option(extcap_conf, "--plugin-source", "plugin source URL");

    for (const auto &it : plugin_configs) {
        const struct plugin_configuration plugin_configs = it.second;
        for (const auto &prop : plugin_configs.properties) {
            extcap_help_add_option(extcap_conf, g_strdup_printf("%s", prop.option.c_str()), g_strdup(prop.description.c_str()));
        }
    }

    ws_opterr = 0;
    ws_optind = 0;

    if (argc == 1) {
        extcap_help_print(extcap_conf);
        goto end;
    }

    static const std::vector<ws_option> longopts = get_longopts(plugin_configs);
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

            case OPT_PLUGIN_API_VERSION:
                fprintf(stdout, "Falco plugin API version %s\n", inspector.get_plugin_api_version());
                ret = EXIT_SUCCESS;
                goto end;

            case OPT_PLUGIN_SOURCE:
                plugin_source = ws_optarg;
                break;

            case ':':
                /* missing option argument */
                ws_warning("Option '%s' requires an argument", argv[ws_optind - 1]);
                break;

            default:
                if (result >= OPT_SCHEMA_PROPERTIES_START) {
                    bool found = false;
                    for (auto &it : plugin_configs) {
                        struct plugin_configuration *plugin_config = &it.second;
                        for (auto &prop : plugin_config->properties) {
                            if (prop.option_index == result) {
                                prop.current_value = ws_optarg;
                                found = true;
                                break;
                            }
                        }
                        if (found) {
                            break;
                        }
                    }
                    if (!found) {
                        ws_warning("Invalid option: %s", argv[ws_optind - 1]);
                        goto end;
                    }
                } else if (!extcap_base_parse_options(extcap_conf, result - EXTCAP_OPT_LIST_INTERFACES, ws_optarg)) {
                    ws_warning("Invalid option: %s", argv[ws_optind - 1]);
                    goto end;
                }
        }
    }

    extcap_cmdline_debug(argv, argc);

    if (plugin_configs.size() < 1) {
        ws_warning("No source plugins found.");
        goto end;
    }

    if (extcap_base_handle_interface(extcap_conf)) {
        ret = EXIT_SUCCESS;
        goto end;
    }

    if (extcap_conf->show_config) {
        ret = show_config(extcap_conf->interface, plugin_configs.at(extcap_conf->interface));
        goto end;
    }

    if (extcap_conf->capture) {
        if (plugin_source.empty()) {
            ws_warning("Missing or invalid parameter: --plugin-source");
            goto end;
        }

        std::shared_ptr<sinsp_plugin> plugin_interface;
        const sinsp_plugin_manager *pm = inspector.get_plugin_manager();
        for (auto &plugin : pm->plugins()) {
            if (plugin->name() == extcap_conf->interface) {
                plugin_interface = plugin;
            }
        }

        if (plugin_interface == nullptr) {
            ws_warning("Unable to find interface %s", extcap_conf->interface);
            goto end;
        }

        int fifo_fd = ws_open(extcap_conf->fifo, O_WRONLY|O_BINARY, 0);
        sinsp_dumper dumper = (&inspector);
#ifdef DEBUG_SINSP
        inspector.set_debug_mode(true);
        inspector.set_log_stderr();
#endif
        try {
            std::string init_err;
            plugin_interface->init(plugin_configs[extcap_conf->interface].json_config().c_str(), init_err);
            if (!init_err.empty()) {
                ws_warning("%s", init_err.c_str());
                goto end;
            }
            inspector.set_input_plugin(extcap_conf->interface, plugin_source);
            inspector.open();
            dumper.fdopen(fifo_fd, false);
        } catch (sinsp_exception e) {
            if (dumper.is_open()) {
                dumper.close();
            } else {
                ws_close(fifo_fd);
            }
            ws_warning("%s", e.what());
            goto end;
        }
        sinsp_evt *evt;
        ws_noisy("Starting capture loop.");
        while (!extcap_end_application) {
            try {
                int32_t res = inspector.next(&evt);
                if (res != SCAP_SUCCESS) {
                    break;
                }
                dumper.dump(evt);
                dumper.flush();
            } catch (sinsp_exception e) {
                ws_warning("%s", e.what());
                goto end;
            }
        }
        ws_noisy("Closing dumper and inspector.");
        dumper.close();
        inspector.close();
        ret = EXIT_SUCCESS;
    } else {
        ws_debug("You should not come here... maybe some parameter missing?");
    }

end:
    /* clean up stuff */
    extcap_base_cleanup(&extcap_conf);
    return ret;
}
