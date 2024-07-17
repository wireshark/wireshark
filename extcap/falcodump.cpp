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
 * - Add filtering.
 *   - Add an option to dump plugin fields.
 * - Add options for credentials.
 * - Let the user create preconfigured interfaces.
 * - Exit more cleanly (see MRs 2063 and 7673).
 * - Better config schema default value parsing? Would likely require a schema change.
 * - Make sure all types are handled in parse_schema_properties.
 * - Handle "required" config schema annotation (Okta).
 */

#include "config.h"

#include <libsinsp/sinsp.h>
#include <plugin_manager.h>

#include <scap_engines.h>

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

// We load our plugins and fetch their configs before we set our log level.
// #define DEBUG_JSON_PARSING
// #define DEBUG_SINSP

enum {
    EXTCAP_BASE_OPTIONS_ENUM,
    OPT_HELP,
    OPT_VERSION,
    OPT_PLUGIN_API_VERSION,
#if defined(HAS_ENGINE_KMOD) || defined(HAS_ENGINE_MODERN_BPF)
    OPT_INCLUDE_CAPTURE_PROCESSES,
    OPT_INCLUDE_SWITCH_CALLS,
#endif
    OPT_PLUGIN_SOURCE,
    OPT_SCHEMA_PROPERTIES_START,
};

//        "s3DownloadConcurrency": {
//          "type": "integer",
//          "description": "Controls the number of background goroutines used to download S3 files (Default: 1)"
//        },
struct config_properties {
    std::string name;
    std::string display;        // "title" property || name
    std::string option;         // Command line option including leading dashes (lowercase display name)
    int option_index;           // Starts from OPT_SCHEMA_PROPERTIES_START
    std::string type;           // "boolean", "integer", "string", "enum", "BEGIN_CONFIG_PROPERTIES", or "END_CONFIG_PROPERTIES"
    std::string description;
    std::string default_value;
    std::vector<std::string>enum_values;
    std::string current_value;
};

#if defined(HAS_ENGINE_KMOD) || defined(HAS_ENGINE_MODERN_BPF)
struct syscall_configuration {
    bool include_capture_processes;
    bool include_switch_calls;
};
#endif

struct plugin_configuration {
    std::vector<struct config_properties> property_list;

    std::string json_config() {
        json_dumper dumper = {};
        dumper.output_string = g_string_new(NULL);

        json_dumper_begin_object(&dumper);

        for (const auto &prop : property_list) {
            if (prop.type == "BEGIN_CONFIG_PROPERTIES") {
                json_dumper_set_member_name(&dumper, prop.name.c_str());
                json_dumper_begin_object(&dumper);
                continue;
            } else if (prop.type == "END_CONFIG_PROPERTIES") {
                json_dumper_end_object(&dumper);
                continue;
            }

            if (prop.current_value == prop.default_value) {
                continue;
            }

            json_dumper_set_member_name(&dumper, prop.name.c_str());
            if (prop.type == "string" || prop.type == "selector") {
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

// Read a line without trailing (CR)LF. Returns -1 on failure. Copied from addr_resolv.c.
// XXX Use g_file_get_contents or GMappedFile instead?
static int
fgetline(char *buf, int size, FILE *fp)
{
    if (fgets(buf, size, fp)) {
        int len = (int)strcspn(buf, "\r\n");
        buf[len] = '\0';
        return len;
    }
    return -1;
}

static const size_t MAX_AWS_LINELEN = 2048;
void print_cloudtrail_aws_profile_config(int arg_num, const char *display, const char *description) {
    char buf[MAX_AWS_LINELEN];
    char profile_name[MAX_AWS_LINELEN];
    FILE *aws_fp;
    std::set<std::string>profiles;

    // Look in files as specified in https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html
    char *cred_path = g_strdup(g_getenv("AWS_SHARED_CREDENTIALS_FILE"));
    if (cred_path == NULL) {
        cred_path = g_build_filename(g_get_home_dir(), ".aws", "credentials", (char *)NULL);
    }

    aws_fp = ws_fopen(cred_path, "r");
    g_free(cred_path);

    if (aws_fp != NULL) {
        while (fgetline(buf, sizeof(buf), aws_fp) >= 0) {
            if (sscanf(buf, "[%2047[^]]s]", profile_name) == 1) {
                if (strcmp(profile_name, "default") == 0) {
                    continue;
                }
                profiles.insert(profile_name);
            }
        }
        fclose(aws_fp);
    }

    char *conf_path = g_strdup(g_getenv("AWS_CONFIG_FILE"));
    if (conf_path == NULL) {
        conf_path = g_build_filename(g_get_home_dir(), ".aws", "config", (char *)NULL);
    }

    aws_fp = ws_fopen(conf_path, "r");
    g_free(conf_path);

    if (aws_fp != NULL) {
        while (fgetline(buf, sizeof(buf), aws_fp) >= 0) {
            if (sscanf(buf, "[profile %2047[^]]s]", profile_name) == 1) {
                if (strcmp(profile_name, "default") == 0) {
                    continue;
                }
                profiles.insert(profile_name);
            }
        }
        fclose(aws_fp);
    }

    const char *aws_profile_env = g_getenv("AWS_PROFILE");
    for (auto &profile : profiles) {
        if (aws_profile_env && profile == aws_profile_env) {
            aws_profile_env = nullptr;
        }
    }
    if (aws_profile_env) {
        profiles.insert(aws_profile_env);
    }

    printf(
        "arg {number=%d}"
        "{call=--cloudtrail-aws-profile}"
        "{display=%s}"
        "{type=editselector}"
        "{tooltip=%s}"
        "{group=Capture}"
        "\n",
        arg_num, display, description);
    printf ("value {arg=%d}{value=}{display=Default}{default=true}\n", arg_num);
    for (auto &profile : profiles) {
        printf(
            "value {arg=%d}"
            "{value=%s}"
            "{display=%s}"
            "\n",
            arg_num, profile.c_str(), profile.c_str());
    }
}

void print_cloudtrail_aws_region_config(int arg_num, const char *display, const char *description) {
    // printf '        "%s",\n' $(aws ec2 describe-regions --all-regions --query "Regions[].{Name:RegionName}" --output text) | sort
    std::set<std::string> regions = {
        "af-south-1",
        "ap-east-1",
        "ap-northeast-1",
        "ap-northeast-2",
        "ap-northeast-3",
        "ap-south-1",
        "ap-south-2",
        "ap-southeast-1",
        "ap-southeast-2",
        "ap-southeast-3",
        "ap-southeast-4",
        "ca-central-1",
        "ca-west-1",
        "eu-central-1",
        "eu-central-2",
        "eu-north-1",
        "eu-south-1",
        "eu-south-2",
        "eu-west-1",
        "eu-west-2",
        "eu-west-3",
        "il-central-1",
        "me-central-1",
        "me-south-1",
        "sa-east-1",
        "us-east-1",
        "us-east-2",
        "us-west-1",
        "us-west-2",
    };

    const char *aws_region_env = g_getenv("AWS_REGION");
    for (auto &region : regions) {
        if (aws_region_env && region == aws_region_env) {
            aws_region_env = nullptr;
        }
    }
    if (aws_region_env) {
        regions.insert(aws_region_env);
    }

    printf(
        "arg {number=%d}"
        "{call=--cloudtrail-aws-region}"
        "{display=%s}"
        "{type=editselector}"
        "{tooltip=%s}"
        "{group=Capture}"
        "\n",
        arg_num, display, description);
    printf ("value {arg=%d}{value=}{display=From profile}{default=true}\n", arg_num);

    for (auto &region : regions) {
        printf(
            "value {arg=%d}"
            "{value=%s}"
            "{display=%s}"
            "\n",
            arg_num, region.c_str(), region.c_str());
    }
}


// Load our plugins. This should match the behavior of the Falco Bridge dissector.
static void load_plugins(sinsp &inspector) {
    WS_DIR *dir;
    WS_DIRENT *file;
    char *plugin_paths[] = {
        // XXX Falco plugins should probably be installed in a path that reflects
        // the Falco version or its plugin API version.
        g_build_filename(get_plugins_dir(), "falco", NULL),
        g_build_filename(get_plugins_pers_dir(), "falco", NULL)
    };

    for (size_t idx = 0; idx < 2; idx++) {
        char *plugin_path = plugin_paths[idx];
        if ((dir = ws_dir_open(plugin_path, 0, NULL)) != NULL) {
            while ((file = ws_dir_read_name(dir)) != NULL) {
                char *libname = g_build_filename(plugin_path, ws_dir_get_name(file), NULL);
                try {
                    auto plugin = inspector.register_plugin(libname);
                    ws_debug("Registered plugin %s via %s", plugin->name().c_str(), libname);
                } catch (sinsp_exception &e) {
                    ws_warning("%s", e.what());
                }
                g_free(libname);
            }
            ws_dir_close(dir);
        }
        g_free(plugin_path);
    }
}

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

// Given a JSON blob containing a schema properties object, add each property to the
// given plugin config.
const std::pair<const std::string,bool> get_schema_properties(const std::string props_blob, int &opt_idx, const std::string option_prefix, const std::string plugin_name, std::vector<struct config_properties> &property_list) {
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

    // We have an object blob which contains a list of properties and property blobs, e.g.
    // { "property_1": { "type": ... }, "prob_blob_1": { "properties": { "prop_blob_2": { "type": ... } } }
    // Skip over the outer { ... } and process the contents as pairs.
    for (int idx = 1; idx < num_tokens - 2; idx++) {
        jsmntok_t &n_tok = tokens[idx];
        jsmntok_t &p_tok = tokens[idx+1];

        std::string name = props_blob.substr(n_tok.start, n_tok.end - n_tok.start);
        std::string display = name;
        std::string property_blob = props_blob.substr(p_tok.start, p_tok.end - p_tok.start);
        std::vector<std::string> enum_values;

        // XXX Check for errors?
        int prop_tokens = json_parse(property_blob.c_str(), NULL, 0);
        switch (prop_tokens) {
        case JSMN_ERROR_INVAL:
            return std::pair<std::string,bool>("invalid property", false);
        case JSMN_ERROR_PART:
            return std::pair<std::string,bool>("incomplete property", false);
        default:
            break;
        }
#ifdef DEBUG_JSON_PARSING
        ws_warning("property %s [%d]\n", name.c_str(), prop_tokens);
#endif

        std::pair<std::string,bool> jv = find_json_object_value(property_blob, "properties", JSMN_OBJECT);
        if (jv.second) {
            config_properties properties = {
                name,
                display,
                "",
                -1,
                "BEGIN_CONFIG_PROPERTIES",
                "",
                "",
                enum_values,
                "",
            };
            property_list.push_back(properties);
            get_schema_properties(jv.first, opt_idx, option_prefix + "-" + name, plugin_name, property_list);
            properties = {
                name,
                display,
                "",
                -1,
                "END_CONFIG_PROPERTIES",
                "",
                "",
                enum_values,
                "",
            };
            property_list.push_back(properties);
            idx += prop_tokens;
            continue;
        }

        jv = find_json_object_value(property_blob, "title", JSMN_STRING);
        if (jv.second) {
            display = jv.first;
        }
        // else split+capitalize "name"?

        jv = find_json_object_value(property_blob, "type", JSMN_STRING);
        if (!jv.second) {
            return std::pair<std::string,bool>("missing type", false);
        }
        std::string type = jv.first;
        jv = find_json_object_value(property_blob, "description", JSMN_STRING);
        if (!jv.second) {
            return std::pair<std::string,bool>("missing description", false);
        }
        std::string description = jv.first;
        std::string default_value;
        jv = find_json_object_value(property_blob, "default", JSMN_STRING);
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
        jv = find_json_object_value(property_blob, "enum", JSMN_ARRAY);
        if (jv.second) {
            const std::pair<std::vector<std::string>,bool> ja = get_json_array(jv.first);
            if (ja.second) {
                enum_values = ja.first;
                type = "selector";
            }
        }
#ifdef DEBUG_JSON_PARSING
        ws_warning("%s: %s, %s, [%d]\n", name.c_str(), type.c_str(), description.c_str(), (int)enum_values.size());
#endif
        const char *call = g_ascii_strdown(name.c_str(), -1);
        config_properties properties = {
            name,
            display,
            std::string() + plugin_name_lower + option_prefix + "-" + call, // Command line option (lowercase plugin + display name)
            opt_idx,
            type,
            description,
            default_value,
            enum_values,
            default_value,
        };
        property_list.push_back(properties);
        g_free((void *)call);
        idx += prop_tokens;
        opt_idx++;
    }
    g_free(plugin_name_lower);
    return std::pair<std::string,bool>("",true);
}

// Wherein we try to implement a sufficiently complete JSON Schema parser.
// Given a plugin config schema like the following:
//{
//  "$schema": "http://json-schema.org/draft-04/schema#",
//  "$ref": "#/definitions/PluginConfig",
//  "definitions": {
//    "PluginConfig": {
//      "properties": {
//        "s3DownloadConcurrency": {
//          "type": "integer",
//          "title": "S3 download concurrency",
//          "description": "Controls the number of background goroutines used to download S3 files (Default: 1)",
//          "default": 1
//        },
// [ ... ]
//        "aws": {
//          "$schema": "http://json-schema.org/draft-04/schema#",
//          "$ref": "#/definitions/PluginConfigAWS"
//        }
//      },
//      "additionalProperties": true,
//      "type": "object"
//    },
//    "PluginConfigAWS": {
//      "properties": {
//        "profile": {
//          "type": "string",
//          "title": "Shared AWS Config Profile",
//          "description": "If non-empty",
//          "default": "''"
//        },
// [ ... ]
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
    std::string schema_blob = plugin->get_init_schema(schema_type);
    std::string config_name;
    std::pair<std::string,bool> jv;

#ifdef DEBUG_JSON_PARSING
    ws_warning("raw schema: %s\n", schema_blob.c_str());
#endif

    int ref_cnt = 0;
    std::string::size_type ref_pos = 0;
    while ((ref_pos = schema_blob.find("\"$ref\"", ref_pos)) != std::string::npos) {
        ref_cnt++;
        ref_pos += 5;
    }

    // Dereference all of our $ref pairs.
    // This is kind of janky, but makes subsequent parsing more simple.
    for (int ref_idx = 0; ref_idx < ref_cnt; ref_idx++) {
        jv = find_json_object_value(schema_blob, "$ref", JSMN_STRING);
        if (!jv.second) {
            break;
        }
        const std::string ref_pointer = jv.first;
        jv = find_json_pointer_value(schema_blob, ref_pointer, JSMN_OBJECT);
        if (!jv.second) {
            ws_warning("Unable to find $ref %s.", ref_pointer.c_str());
            return false;
        }
        const std::string ref_body = jv.first.substr(1, jv.first.size() - 2);

        std::vector<jsmntok_t> tokens;
        int num_tokens = json_parse(schema_blob.c_str(), NULL, 0);

        switch (num_tokens) {
        case JSMN_ERROR_INVAL:
            ws_warning("Invalid schema.");
            return false;
        case JSMN_ERROR_PART:
        {
            ws_warning("Incomplete schema.");
            return false;
        }
        default:
            break;
        }

#ifdef DEBUG_JSON_PARSING
        ws_warning("searching for $ref: %s\n", ref_pointer.c_str());
#endif
        tokens.resize(num_tokens);
        json_parse(schema_blob.c_str(), tokens.data(), num_tokens);
        std::vector<std::string> elements;
        // First token is the full array.
        for (int idx = 0; idx < num_tokens - 1; idx++) {
            if (tokens[idx].type != JSMN_STRING && tokens[idx+1].type != JSMN_STRING) {
                continue;
            }
            auto key_tok = &tokens[idx];
            auto val_tok = &tokens[idx+1];
            std::string key = schema_blob.substr(key_tok->start, key_tok->end - key_tok->start);
            std::string value = schema_blob.substr(val_tok->start, val_tok->end - val_tok->start);
            if (key != "$ref" || value != ref_pointer) {
                continue;
            }
            try {
#ifdef DEBUG_JSON_PARSING
                ws_warning("replacing: %s\n", schema_blob.substr(key_tok->start - 1, val_tok->end - key_tok->start + 2).c_str());
#endif
                schema_blob.replace(key_tok->start - 1, val_tok->end - key_tok->start + 2, ref_body);
            } catch (std::out_of_range const&) {
                ws_warning("Unknown reference %s.", key.c_str());
                return false;
            }
        }
    }

#ifdef DEBUG_JSON_PARSING
    ws_warning("cooked schema: %s\n", schema_blob.c_str());
#endif

    // XXX Should each sub-schema ref be in its own category?
    jv = find_json_object_value(schema_blob, "properties", JSMN_OBJECT);
    if (!jv.second) {
        ws_warning("ERROR: Interface \"%s\" has an %s configuration schema.", plugin->name().c_str(), schema_blob.c_str());
        return false;
    }
    int opt_idx = OPT_SCHEMA_PROPERTIES_START;
    jv = get_schema_properties(jv.first, opt_idx, "", plugin->name(), plugin_config.property_list);
    if (!jv.second) {
        ws_warning("ERROR: Interface \"%s\" has an unsupported or invalid configuration schema: %s", plugin->name().c_str(), jv.first.c_str());
        return false;
    }

    return true;
}

// For each loaded plugin, get its name and properties.
static bool get_source_plugins(sinsp &inspector, std::map<std::string, struct plugin_configuration> &plugin_configs) {
    const auto plugin_manager = inspector.get_plugin_manager();

    // XXX sinsp_plugin_manager::sources() can return different names, e.g. aws_cloudtrail vs cloudtrail.
    try {
        for (auto &plugin : plugin_manager->plugins()) {
            if (plugin->caps() & CAP_SOURCING) {
                plugin_configuration plugin_config = {};
                if (!get_plugin_config_schema(plugin, plugin_config)) {
                    return false;
                }
                plugin_configs[plugin->name()] = plugin_config;
            }
        }
    } catch (sinsp_exception &e) {
        ws_warning("%s", e.what());
        return false;
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
#if defined(HAS_ENGINE_KMOD) || defined(HAS_ENGINE_MODERN_BPF)
        { "include-capture-processes", ws_required_argument, NULL, OPT_INCLUDE_CAPTURE_PROCESSES },
        { "include-switch-calls", ws_required_argument, NULL, OPT_INCLUDE_SWITCH_CALLS },
#endif
        { "plugin-source", ws_required_argument, NULL, OPT_PLUGIN_SOURCE },
        { 0, 0, 0, 0}
    };
    int idx;
    for (idx = 0; base_longopts[idx].name; idx++) {
        longopts.push_back(base_longopts[idx]);
    }
    for (const auto &it : plugin_configs) {
        const struct plugin_configuration plugin_config = it.second;
        for (const auto &prop : plugin_config.property_list) {
            ws_option option = { g_strdup(prop.option.c_str()), ws_required_argument, NULL, prop.option_index };
            longopts.push_back(option);
        }
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

// Show the configuration for a given plugin/interface.
static int show_syscall_config(void)
{
    printf(
        "arg {number=0}"
        "{call=--include-capture-processes}"
        "{display=Include capture processes}"
        "{type=boolean}"
        "{tooltip=Include system calls made by any capture processes (falcodump, dumpcap, and Logray)}"
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
        // We want to exclude Logray and any of its children, including
        // this one (falcodump).

        std::string pid, comm, _s, ppid;

        // Exclude this process only at a minimum.
        std::ifstream stat_stream("/proc/self/stat");
        stat_stream >> pid >> comm >> _s >> ppid;
        std::string process_filter = "proc.pid != " + pid;
        if (comm != "(falcodump)") {
            ws_warning("Our process is named %s, not falcodump", comm.c_str());
        }
        stat_stream.close();

        // If our parent is Logray, exclude it and its direct children.
        std::ifstream pstat_stream("/proc/" + ppid + "/stat");
        pstat_stream >> _s >> comm;
        if (comm == "(logray)") {
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

// Show the configuration for a given plugin/interface.
static int show_plugin_config(const std::string &interface, const struct plugin_configuration &plugin_config)
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
        "{display=Log data URL}"
        "{type=string}"
        "{tooltip=The plugin data source. This is usually a URL.}"
        "{placeholder=Enter a source URL" UTF8_HORIZONTAL_ELLIPSIS "}"
        "{required=true}"
        "{group=Capture}\n",
        arg_num++);
//    if (plugin_filter)
//        printf("{default=%s}", plugin_filter);
    for (const auto &properties : plugin_config.property_list) {
        if (properties.option_index < OPT_SCHEMA_PROPERTIES_START) {
            continue;
        }
        std::string default_value;
        if (!properties.default_value.empty()) {
            default_value = "{default=" + properties.default_value + "}";
        }
        if (properties.option == "cloudtrail-aws-profile") {
            print_cloudtrail_aws_profile_config(arg_num, properties.display.c_str(), properties.description.c_str());
        } else if (properties.option == "cloudtrail-aws-region") {
            print_cloudtrail_aws_region_config(arg_num, properties.display.c_str(), properties.description.c_str());
        } else {
            printf(
                "arg {number=%u}"
                "{call=--%s}"
                "{display=%s}"
                "{type=%s}"
                "%s"
                "{tooltip=%s}"
                "{group=Capture}"
                "\n",
                arg_num, properties.option.c_str(), properties.display.c_str(), properties.type.c_str(), default_value.c_str(), properties.description.c_str());
            if (properties.enum_values.size() > 0) {
                for (const auto &enum_val : properties.enum_values) {
                    printf(
                      "value {arg=%u}"
                      "{value=%s}"
                      "{display=%s}"
                      "%s"
                      "\n",
                      arg_num, enum_val.c_str(), enum_val.c_str(), enum_val == default_value ? "{default=true}" : "");
                }
            }
        }
        arg_num++;
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
#if defined(HAS_ENGINE_KMOD) || defined(HAS_ENGINE_MODERN_BPF)
    struct syscall_configuration syscall_config = {};
#endif
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

    // Plain eBPF requires extra configuration, so probe for kmod and modern BPF support only for now.
#ifdef HAS_ENGINE_KMOD
    try {
        inspector.open_kmod();
        extcap_base_register_interface(extcap_conf, KMOD_ENGINE, "System calls via kernel module", 147, "USER0");
    } catch (sinsp_exception &e) {
        ws_warning("Unable to open kmod: %s", e.what());
    }
    inspector.close();
#endif
#ifdef HAS_ENGINE_MODERN_BPF
    try {
        inspector.open_modern_bpf();
        extcap_base_register_interface(extcap_conf, MODERN_BPF_ENGINE, "System calls via modern eBPF", 147, "USER0");
    } catch (sinsp_exception &e) {
        ws_warning("Unable to open kmod: %s", e.what());
    }
    inspector.close();
#endif

    load_plugins(inspector);

    if (get_source_plugins(inspector, plugin_configs)) {
        for (auto iter = plugin_configs.begin(); iter != plugin_configs.end(); ++iter) {
            // Where we're going we don't need DLTs, so use USER0 (147).
            // Additional info available via plugin->description() and plugin->event_source().
            extcap_base_register_interface(extcap_conf, iter->first.c_str(), "Falco plugin", 147, "USER0");
        }
    } else {
        ws_warning("Unable to load plugins.");
    }

    if (g_list_length(extcap_conf->interfaces) < 1) {
        ws_debug("No source plugins found.");
        goto end;
    }

    help_url = data_file_url("falcodump.html");
    extcap_base_set_util_info(extcap_conf, argv[0], FALCODUMP_VERSION_MAJOR, FALCODUMP_VERSION_MINOR,
            FALCODUMP_VERSION_RELEASE, help_url);
    g_free(help_url);

    help_header = ws_strdup_printf(
            " %s --extcap-interfaces\n"
            " %s --extcap-interface=%s --extcap-capture-filter=<filter>\n"
            " %s --extcap-interface=%s --extcap-dlts\n"
            " %s --extcap-interface=%s --extcap-config\n"
            " %s --extcap-interface=%s --fifo=<filename> --capture --plugin-source=<source url> [--extcap-capture-filter=<filter>]\n",
            argv[0],
            argv[0], FALCODUMP_PLUGIN_PLACEHOLDER,
            argv[0], FALCODUMP_PLUGIN_PLACEHOLDER,
            argv[0], FALCODUMP_PLUGIN_PLACEHOLDER,
            argv[0], FALCODUMP_PLUGIN_PLACEHOLDER);
    extcap_help_add_header(extcap_conf, help_header);
    g_free(help_header);
    extcap_help_add_option(extcap_conf, "--help", "print this help");
    extcap_help_add_option(extcap_conf, "--version", "print the version");
    extcap_help_add_option(extcap_conf, "--plugin-api-version", "print the Falco plugin API version");
    extcap_help_add_option(extcap_conf, "--plugin-source", "plugin source URL");
    extcap_help_add_option(extcap_conf, "--include-capture-processes", "Include capture processes");
    extcap_help_add_option(extcap_conf, "--include-switch-calls", "Include \"switch\" calls");

    for (const auto &it : plugin_configs) {
        const struct plugin_configuration plugin_config = it.second;
        for (const auto &prop : plugin_config.property_list) {
            if (prop.option_index < OPT_SCHEMA_PROPERTIES_START) {
                continue;
            }
            extcap_help_add_option(extcap_conf, g_strdup_printf("--%s", prop.option.c_str()), g_strdup(prop.description.c_str()));
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

#if defined(HAS_ENGINE_KMOD) || defined(HAS_ENGINE_MODERN_BPF)
            case OPT_INCLUDE_CAPTURE_PROCESSES:
                syscall_config.include_capture_processes = get_bool_value(ws_optarg);
                break;

            case OPT_INCLUDE_SWITCH_CALLS:
                syscall_config.include_switch_calls = get_bool_value(ws_optarg);
                break;
#endif

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
                        for (auto &prop : plugin_config->property_list) {
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
        else
#endif
        {
            ret = show_plugin_config(extcap_conf->interface, plugin_configs.at(extcap_conf->interface));
        }
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
        else
#endif
        {
            if (plugin_source.empty()) {
                if (extcap_conf->capture) {
                    ws_warning("Missing or invalid parameter: --plugin-source");
                } else {
                    // XXX Can we bypass this somehow?
                    fprintf(stdout, "Validating a capture filter requires a plugin source");
                }
                goto end;
            }

            std::shared_ptr<sinsp_plugin> plugin_interface;
            const auto plugin_manager = inspector.get_plugin_manager();
            for (auto &plugin : plugin_manager->plugins()) {
                if (plugin->name() == extcap_conf->interface) {
                    plugin_interface = plugin;
                }
            }

            if (plugin_interface == nullptr) {
                ws_warning("Unable to find interface %s", extcap_conf->interface);
                goto end;
            }

            try {
                std::string init_err;
                plugin_interface->init(plugin_configs[extcap_conf->interface].json_config().c_str(), init_err);
                if (!init_err.empty()) {
                    ws_warning("%s", init_err.c_str());
                    goto end;
                }
                inspector.open_plugin(extcap_conf->interface, plugin_source);
                // scap_dump_open handles "-"
            } catch (sinsp_exception &e) {
                ws_warning("%s", e.what());
                goto end;
            }
        }

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
        ws_debug("You should not come here... maybe some parameter missing?");
    }

end:
    /* clean up stuff */
    extcap_base_cleanup(&extcap_conf);
    return ret;
}
