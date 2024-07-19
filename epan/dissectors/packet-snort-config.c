/* packet-snort-config.c
 *
 * Copyright 2016, Martin Mathieson
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include <wsutil/file_util.h>
#include <wsutil/strtoi.h>
#include <wsutil/report_message.h>

#include "packet-snort-config.h"
#include "ws_attributes.h"

/* Forward declaration */
static void parse_config_file(SnortConfig_t *snort_config, FILE *config_file_fd, const char *filename, const char *dirname, int recursion_level);

/* Skip white space from 'source', return pointer to first non-whitespace char */
static const char *skipWhiteSpace(const char *source, int *accumulated_offset)
{
    int offset = 0;

    /* Skip any leading whitespace */
    while ((source[offset] == ' ') || (source[offset] == '\t')) {
        offset++;
    }

    *accumulated_offset += offset;
    return source + offset;
}

/* Read a token from source, stop when get to end of string or delimiter. */
/* - source: input string
 * - delimiter:  char to stop at
 * - length: out param set to delimiter or end-of-string offset
 * - accumulated_Length: out param that gets length added to it
 * - copy: whether or an allocated string should be returned
 * - returns: requested string.  Returns from static buffer when copy is false */
static char* read_token(const char* source, char delimeter, int *length, int *accumulated_length, bool copy)
{
    static char static_buffer[1024];
    int offset = 0;

    const char *source_proper = skipWhiteSpace(source, accumulated_length);

    while (source_proper[offset] != '\0' && source_proper[offset] != delimeter) {
        offset++;
    }

    *length = offset;
    *accumulated_length += offset;
    if (copy) {
        /* Copy into new string */
        char *new_string = g_strndup(source_proper, offset+1);
        new_string[offset] = '\0';
        return new_string;
    }
    else {
        /* Return in static buffer */
        memcpy(&static_buffer, source_proper, offset);
        static_buffer[offset] = '\0';
        return static_buffer;
    }
}

/* Add a new content field to the rule */
static bool rule_add_content(Rule_t *rule, const char *content_string, bool negated)
{
    if (rule->number_contents < MAX_CONTENT_ENTRIES) {
        content_t *new_content = &(rule->contents[rule->number_contents++]);
        new_content->str = g_strdup(content_string);
        new_content->negation = negated;
        rule->last_added_content = new_content;
        return true;
    }
    return false;
}

/* Set the nocase property for a rule */
static void rule_set_content_nocase(Rule_t *rule)
{
    if (rule->last_added_content) {
        rule->last_added_content->nocase = true;
    }
}

/* Set the offset property of a content field */
static void rule_set_content_offset(Rule_t *rule, int value)
{
    if (rule->last_added_content) {
        rule->last_added_content->offset = value;
        rule->last_added_content->offset_set = true;
    }
}

/* Set the depth property of a content field */
static void rule_set_content_depth(Rule_t *rule, unsigned value)
{
    if (rule->last_added_content) {
        rule->last_added_content->depth = value;
    }
}

/* Set the distance property of a content field */
static void rule_set_content_distance(Rule_t *rule, int value)
{
    if (rule->last_added_content) {
        rule->last_added_content->distance = value;
        rule->last_added_content->distance_set = true;
    }
}

/* Set the distance property of a content field */
static void rule_set_content_within(Rule_t *rule, unsigned value)
{
    if (rule->last_added_content) {
        /* Assuming won't be 0... */
        rule->last_added_content->within = value;
    }
}

/* Set the fastpattern property of a content field */
static void rule_set_content_fast_pattern(Rule_t *rule)
{
    if (rule->last_added_content) {
        rule->last_added_content->fastpattern = true;
    }
}

/* Set the rawbytes property of a content field */
static void rule_set_content_rawbytes(Rule_t *rule)
{
    if (rule->last_added_content) {
        rule->last_added_content->rawbytes = true;
    }
}

/* Set the http_method property of a content field */
static void rule_set_content_http_method(Rule_t *rule)
{
    if (rule->last_added_content) {
        rule->last_added_content->http_method = true;
    }
}

/* Set the http_client property of a content field */
static void rule_set_content_http_client_body(Rule_t *rule)
{
    if (rule->last_added_content) {
        rule->last_added_content->http_client_body = true;
    }
}

/* Set the http_cookie property of a content field */
static void rule_set_content_http_cookie(Rule_t *rule)
{
    if (rule->last_added_content) {
        rule->last_added_content->http_cookie = true;
    }
}

/* Set the http_UserAgent property of a content field */
static void rule_set_content_http_user_agent(Rule_t *rule)
{
    if (rule->last_added_content) {
        rule->last_added_content->http_user_agent = true;
    }
}

/* Add a uricontent field to the rule */
static bool rule_add_uricontent(Rule_t *rule, const char *uricontent_string, bool negated)
{
    if (rule_add_content(rule, uricontent_string, negated)) {
        rule->last_added_content->content_type = UriContent;
        return true;
    }
    return false;
}

/* This content field now becomes a uricontent after seeing modifier  */
static void rule_set_http_uri(Rule_t *rule)
{
    if (rule->last_added_content != NULL) {
        rule->last_added_content->content_type = UriContent;
    }
}

/* Add a pcre field to the rule */
static bool rule_add_pcre(Rule_t *rule, const char *pcre_string)
{
    if (rule_add_content(rule, pcre_string, false)) {
        rule->last_added_content->content_type = Pcre;
        return true;
    }
    return false;
}

/* Set the rule's classtype field */
static bool rule_set_classtype(Rule_t *rule, const char *classtype)
{
    rule->classtype = g_strdup(classtype);
    return true;
}

/* Add a reference string to the rule */
static void rule_add_reference(Rule_t *rule, const char *reference_string)
{
    if (rule->number_references < MAX_REFERENCE_ENTRIES) {
        rule->references[rule->number_references++] = g_strdup(reference_string);
    }
}

/* Check to see if the ip 'field' corresponds to an entry in the ipvar dictionary.
 * If it is add entry to rule */
static void rule_check_ip_vars(SnortConfig_t *snort_config, Rule_t *rule, char *field)
{
    void *original_key = NULL;
    void *value = NULL;

    /* Make sure field+1 not NULL. */
    if (strlen(field) < 2) {
        return;
    }

    /* Make sure there is room for another entry */
    if (rule->relevant_vars.num_ip_vars >= MAX_RULE_IP_VARS) {
        return;
    }

    /* TODO: a loop re-looking up the answer until its not just another ipvar! */
    if (g_hash_table_lookup_extended(snort_config->ipvars, field+1, &original_key, &value)) {

        rule->relevant_vars.ip_vars[rule->relevant_vars.num_ip_vars].name = (char*)original_key;
        rule->relevant_vars.ip_vars[rule->relevant_vars.num_ip_vars].value = (char*)value;

        rule->relevant_vars.num_ip_vars++;
    }
}

/* Check to see if the port 'field' corresponds to an entry in the portvar dictionary.
 * If it is add entry to rule */
static void rule_check_port_vars(SnortConfig_t *snort_config, Rule_t *rule, char *field)
{
    void *original_key = NULL;
    void *value = NULL;

    /* Make sure field+1 not NULL. */
    if (strlen(field) < 2) {
        return;
    }

    /* Make sure there is room for another entry */
    if (rule->relevant_vars.num_port_vars >= MAX_RULE_PORT_VARS) {
        return;
    }

    /* TODO: a loop re-looking up the answer until its not just another portvar! */
    if (g_hash_table_lookup_extended(snort_config->portvars, field+1, &original_key, &value)) {
        rule->relevant_vars.port_vars[rule->relevant_vars.num_port_vars].name = (char*)original_key;
        rule->relevant_vars.port_vars[rule->relevant_vars.num_port_vars].value = (char*)value;

        rule->relevant_vars.num_port_vars++;
    }
}

/* Look over the IP addresses and ports, and work out which variables/values are being used */
void rule_set_relevant_vars(SnortConfig_t *snort_config, Rule_t *rule)
{
    int length;
    int accumulated_length = 0;
    char *field;

    /* No need to do this twice */
    if (rule->relevant_vars.relevant_vars_set) {
        return;
    }

    /* Walk tokens up to the options, and look up ones that are addresses or ports. */

    /* Skip "alert" */
    read_token(rule->rule_string+accumulated_length, ' ', &length, &accumulated_length, false);

    /* Skip protocol. */
    read_token(rule->rule_string+accumulated_length, ' ', &length, &accumulated_length, false);

    /* Read source address */
    field = read_token(rule->rule_string+accumulated_length, ' ', &length, &accumulated_length, false);
    rule_check_ip_vars(snort_config, rule, field);

    /* Read source port */
    field = read_token(rule->rule_string+accumulated_length, ' ', &length, &accumulated_length, false);
    rule_check_port_vars(snort_config, rule, field);

    /* Read direction */
    read_token(rule->rule_string+accumulated_length, ' ', &length, &accumulated_length, false);

    /* Dest address */
    field = read_token(rule->rule_string+accumulated_length, ' ', &length, &accumulated_length, false);
    rule_check_ip_vars(snort_config, rule, field);

    /* Dest port */
    field = read_token(rule->rule_string+accumulated_length, ' ', &length, &accumulated_length, false);
    rule_check_port_vars(snort_config, rule, field);

    /* Set flag so won't do again for this rule */
    rule->relevant_vars.relevant_vars_set = true;
}


typedef enum vartype_e { var, ipvar, portvar, unknownvar } vartype_e;

/* Look for a "var", "ipvar" or "portvar" entry in this line */
static bool parse_variables_line(SnortConfig_t *snort_config, const char *line)
{
    vartype_e var_type = unknownvar;

    const char*  variable_type;
    char *  variable_name;
    char *  value;

    int length;
    int accumulated_length = 0;

    /* Get variable type */
    variable_type = read_token(line, ' ', &length, &accumulated_length, false);
    if (variable_type == NULL) {
        return false;
    }

    if (strncmp(variable_type, "var", 3) == 0) {
        var_type = var;
    }
    else if (strncmp(variable_type, "ipvar", 5) == 0) {
        var_type = ipvar;
    }
    else if (strncmp(variable_type, "portvar", 7) == 0) {
        var_type = portvar;
    }
    else {
        return false;
    }

    /* Get variable name */
    variable_name = read_token(line+ accumulated_length, ' ', &length, &accumulated_length, true);
    if (variable_name == NULL) {
        return false;
    }

    /* Now value */
    value = read_token(line + accumulated_length, ' ', &length, &accumulated_length, true);
    if (value == NULL) {
        return false;
    }

    /* Add (name->value) to table according to variable type. */
    switch (var_type) {
        case var:
            if (strcmp(variable_name, "RULE_PATH") == 0) {
                /* This can be relative or absolute. */
                snort_config->rule_path = value;
                snort_config->rule_path_is_absolute = g_path_is_absolute(value);
                snort_debug_printf("rule_path set to %s (is_absolute=%d)\n",
                                   snort_config->rule_path, snort_config->rule_path_is_absolute);
            }
            g_hash_table_insert(snort_config->vars, variable_name, value);
            break;
        case ipvar:
            g_hash_table_insert(snort_config->ipvars, variable_name, value);
            break;
        case portvar:
            g_hash_table_insert(snort_config->portvars, variable_name, value);
            break;

        default:
            return false;
    }

    return false;
}

/* Hash function for where key is a string. Just add up the value of each character and return that.. */
static unsigned string_hash(const void *key)
{
    unsigned total=0, n=0;
    const char *key_string = (const char *)key;
    char c = key_string[n];

    while (c != '\0') {
        total += (int)c;
        c = key_string[++n];
    }
    return total;
}

/* Comparison function for where key is a string. Simple comparison using strcmp() */
static gboolean string_equal(const void *a, const void *b)
{
    const char *stringa = (const char*)a;
    const char *stringb = (const char*)b;

    return (strcmp(stringa, stringb) == 0);
}

/* Process a line that configures a reference line (invariably from 'reference.config') */
static bool parse_references_prefix_file_line(SnortConfig_t *snort_config, const char *line)
{
    char *prefix_name, *prefix_value;
    int length=0, accumulated_length=0;
    int n;

    if (strncmp(line, "config reference: ", 18) != 0) {
        return false;
    }

    /* Read the prefix and value */
    const char *source = line+18;
    prefix_name = read_token(source, ' ', &length, &accumulated_length, true);
    /* Store all name chars in lower case. */
    for (n=0; prefix_name[n] != '\0'; n++) {
        prefix_name[n] = g_ascii_tolower(prefix_name[n]);
    }

    prefix_value = read_token(source+accumulated_length, ' ', &length, &accumulated_length, true);

    /* Add entry into table */
    g_hash_table_insert(snort_config->references_prefixes, prefix_name, prefix_value);

    return false;
}

/* Try to expand the reference using the prefixes stored in the config */
char *expand_reference(SnortConfig_t *snort_config, char *reference)
{
    static char expanded_reference[512];
    int length = (int)strlen(reference);
    int accumulated_length = 0;

    /* Extract up to ',', then substitute prefix! */
    snort_debug_printf("expand_reference(%s)\n", reference);
    char *prefix = read_token(reference, ',', &length, &accumulated_length, false);

    if (*prefix != '\0') {
        /* Convert to lowercase before lookup */
        unsigned n;
        for (n=0; prefix[n] != '\0'; n++) {
            prefix[n] = g_ascii_tolower(prefix[n]);
        }

        /* Look up prefix in table. */
        const char* prefix_replacement;
        prefix_replacement = (char*)g_hash_table_lookup(snort_config->references_prefixes, prefix);

        /* Append prefix and remainder, and return!!!! */
        if (prefix_replacement) {
            snprintf(expanded_reference, 512, "%s%s", prefix_replacement, reference+length+1);
            return expanded_reference;
        }
        else {
            /* Just return the original reference */
            return reference;
        }

    }
    return "ERROR: Reference didn't contain prefix and ','!";
}

/* The rule has been matched with an alert, so update global config stats */
void rule_set_alert(SnortConfig_t *snort_config, Rule_t *rule,
                    unsigned *global_match_number,
                    unsigned *rule_match_number)
{
    snort_config->stat_alerts_detected++;
    *global_match_number = snort_config->stat_alerts_detected;
    if (rule != NULL) {
        *rule_match_number = ++rule->matches_seen;
    }
}



/* Delete an individual entry from a string table. */
static gboolean delete_string_entry(void *key,
                                    void *value,
                                    void *user_data _U_)
{
    char *key_string = (char*)key;
    char *value_string = (char*)value;

    g_free(key_string);
    g_free(value_string);

    return TRUE;
}

/* See if this is an include line, if it is open the file and call parse_config_file() */
// NOLINTNEXTLINE(misc-no-recursion)
static bool parse_include_file(SnortConfig_t *snort_config, const char *line, const char *config_directory, int recursion_level)
{
    int length;
    int accumulated_length = 0;
    char *include_filename;

    /* Look for "include " */
    const char *include_token = read_token(line, ' ', &length, &accumulated_length, false);
    if (strlen(include_token) == 0) {
        return false;
    }
    if (strncmp(include_token, "include", 7) != 0) {
        return false;
    }

    /* Read the filename */
    include_filename = read_token(line+accumulated_length, ' ', &length, &accumulated_length, false);
    if (*include_filename != '\0') {
        FILE *new_config_fd;
        char *substituted_filename;
        bool is_rule_file = false;

        /* May need to substitute variables into include path. */
        if (strncmp(include_filename, "$RULE_PATH", 10) == 0) {
            /* Write rule path variable value */
            /* Don't assume $RULE_PATH will end in a file separator */
            if (snort_config->rule_path_is_absolute) {
                /* Rule path is absolute, so it can go at start */
                substituted_filename = g_build_path(G_DIR_SEPARATOR_S,
                           snort_config->rule_path,
                           include_filename + 11,
                           NULL);
            }
            else {
                /* Rule path is relative to config directory, so it goes first */
                substituted_filename = g_build_path(G_DIR_SEPARATOR_S,
                           config_directory,
                           snort_config->rule_path,
                           include_filename + 11,
                           NULL);
            }
            is_rule_file = true;
        }
        else {
            /* No $RULE_PATH, just use directory and filename */
            /* But may not even need directory if included_folder is absolute! */
            if (!g_path_is_absolute(include_filename)) {
                substituted_filename = g_build_path(G_DIR_SEPARATOR_S,
                            config_directory, include_filename, NULL);
            }
            else {
                substituted_filename = g_strdup(include_filename);
            }
        }

        /* Try to open the file. */
        new_config_fd = ws_fopen(substituted_filename, "r");
        if (new_config_fd == NULL) {
            snort_debug_printf("Failed to open config file %s\n", substituted_filename);
            report_failure("Snort dissector: Failed to open config file %s\n", substituted_filename);
            g_free(substituted_filename);
            return false;
        }

        /* Parse the file */
        if (is_rule_file) {
            snort_config->stat_rules_files++;
        }
        parse_config_file(snort_config, new_config_fd, substituted_filename, config_directory, recursion_level + 1);
        g_free(substituted_filename);

        /* Close the file */
        fclose(new_config_fd);

        return true;
    }
    return false;
}

/* Process an individual option - i.e. the elements found between '(' and ')' */
static void process_rule_option(Rule_t *rule, char *options, int option_start_offset, int options_end_offset, int colon_offset)
{
    static char name[1024], value[1024];
    name[0] = '\0';
    value[0] = '\0';
    int value_length = 0;
    uint32_t value32 = 0;
    int spaces_after_colon = 0;

    if (colon_offset != 0) {
        /* Name and value */
        (void) g_strlcpy(name, options+option_start_offset, colon_offset-option_start_offset);
        if (options[colon_offset] == ' ') {
            spaces_after_colon = 1;
        }
        (void) g_strlcpy(value, options+colon_offset+spaces_after_colon, options_end_offset-spaces_after_colon-colon_offset);
        value_length = (int)strlen(value);
    }
    else {
        /* Just name */
        (void) g_strlcpy(name, options+option_start_offset, options_end_offset-option_start_offset);
    }

    /* Some rule options expect a number, parse it now. Note that any space
     * after the value will currently result in the number being ignored. */
    ws_strtoi32(value, NULL, &value32);

    /* Think this is space at end of all options - don't compare with option names */
    if (name[0] == '\0') {
        return;
    }

    /* Process the rule options that we are interested in */
    if (strcmp(name, "msg") == 0) {
        rule->msg = g_strdup(value);
    }
    else if (strcmp(name, "sid") == 0) {
        rule->sid = value32;
    }
    else if (strcmp(name, "rev") == 0) {
        rule->rev = value32;
    }
    else if (strcmp(name, "content") == 0) {
        int value_start = 0;

        if (value_length < 3) {
            return;
        }

        /* Need to trim off " ", but first check for ! */
        if (value[0] == '!') {
            value_start = 1;
            if (value_length < 4) {
                /* i.e. also need quotes + at least one character */
                return;
            }
        }

        value[options_end_offset-colon_offset-spaces_after_colon-2] = '\0';
        rule_add_content(rule, value+value_start+1, value_start == 1);
    }
    else if (strcmp(name, "uricontent") == 0) {
        int value_start = 0;

        if (value_length < 3) {
            return;
        }

        /* Need to trim off " ", but first check for ! */
        if (value[0] == '!') {
            value_start = 1;
            if (value_length < 4) {
                return;
            }
        }

        value[options_end_offset-colon_offset-spaces_after_colon-2] = '\0';
        rule_add_uricontent(rule, value+value_start+1, value_start == 1);
    }
    else if (strcmp(name, "http_uri") == 0) {
        rule_set_http_uri(rule);
    }
    else if (strcmp(name, "pcre") == 0) {
        int value_start = 0;

        /* Need at least opening and closing / */
        if (value_length < 3) {
            return;
        }

        /* Not expecting negation (!)... */

        value[options_end_offset-colon_offset-spaces_after_colon-2] = '\0';
        rule_add_pcre(rule, value+value_start+1);
    }
    else if (strcmp(name, "nocase") == 0) {
        rule_set_content_nocase(rule);
    }
    else if (strcmp(name, "offset") == 0) {
        rule_set_content_offset(rule, value32);
    }
    else if (strcmp(name, "depth") == 0) {
        rule_set_content_depth(rule, value32);
    }
    else if (strcmp(name, "within") == 0) {
        rule_set_content_within(rule, value32);
    }
    else if (strcmp(name, "distance") == 0) {
        rule_set_content_distance(rule, value32);
    }
    else if (strcmp(name, "fast_pattern") == 0) {
        rule_set_content_fast_pattern(rule);
    }
    else if (strcmp(name, "http_method") == 0) {
        rule_set_content_http_method(rule);
    }
    else if (strcmp(name, "http_client_body") == 0) {
        rule_set_content_http_client_body(rule);
    }
    else if (strcmp(name, "http_cookie") == 0) {
        rule_set_content_http_cookie(rule);
    }
    else if (strcmp(name, "http_user_agent") == 0) {
        rule_set_content_http_user_agent(rule);
    }
    else if (strcmp(name, "rawbytes") == 0) {
        rule_set_content_rawbytes(rule);
    }
    else if (strcmp(name, "classtype") == 0) {
        rule_set_classtype(rule, value);
    }
    else if (strcmp(name, "reference") == 0) {
        rule_add_reference(rule, value);
    }
    else {
        /* Ignore an option we don't currently handle */
    }
}

/* Parse a Snort alert, return true if successful */
static bool parse_rule(SnortConfig_t *snort_config, char *line, const char *filename, int line_number, int line_length)
{
    const char* options_start;
    char *options;
    bool in_quotes = false;
    int options_start_index = 0, options_index = 0, colon_offset = 0;
    char c;
    int length = 0; /*  CID 1398227 (bogus - read_token() always sets it) */
    Rule_t *rule = NULL;

    /* Rule will begin with alert */
    if (strncmp(line, "alert ", 6) != 0) {
        return false;
    }

    /* Allocate the rule itself */
    rule = g_new(Rule_t, 1);

    snort_debug_printf("looks like a rule: %s\n", line);
    memset(rule, 0, sizeof(Rule_t));

    rule->rule_string = g_strdup(line);
    rule->file = g_strdup(filename);
    rule->line_number = line_number;

    /* Next token is the protocol */
    rule->protocol = read_token(line+6, ' ', &length, &length, true);

    /* Find start of options. */
    options_start = strstr(line, "(");
    if (options_start == NULL) {
        snort_debug_printf("start of options not found\n");
        g_free(rule);
        return false;
    }
    options_index = (int)(options_start-line) + 1;

    /* To make parsing simpler, replace final ')' with ';' */
    if (line[line_length-1] != ')') {
        g_free(rule);
        return false;
    }
    else {
        line[line_length-1] = ';';
    }

    /* Skip any spaces before next option */
    while (line[options_index] == ' ') options_index++;

    /* Now look for next ';', process one option at a time */
    options = &line[options_index];
    options_index = 0;

    while ((c = options[options_index++])) {
        /* Keep track of whether inside quotes */
        if (c == '"') {
            in_quotes = !in_quotes;
        }
        /* Ignore ';' while inside quotes */
        if (!in_quotes) {
            if (c == ':') {
                colon_offset = options_index;
            }
            if (c == ';') {
                /* End of current option - add to rule. */
                process_rule_option(rule, options, options_start_index, options_index, colon_offset);

                /* Skip any spaces before next option */
                while (options[options_index] == ' ') options_index++;

                /* Next rule will start here */
                options_start_index = options_index;
                colon_offset = 0;
                in_quotes = false;
            }
        }
    }

    /* Add rule to map of rules. */
    g_hash_table_insert(snort_config->rules, GUINT_TO_POINTER((unsigned)rule->sid), rule);
    snort_debug_printf("Snort rule with SID=%u added to table\n", rule->sid);

    return true;
}

/* Delete an individual rule */
static gboolean delete_rule(void *    key _U_,
                            void *    value,
                            void *    user_data _U_)
{
    Rule_t *rule = (Rule_t*)value;
    unsigned int n;

    /* Delete strings on heap. */
    g_free(rule->rule_string);
    g_free(rule->file);
    g_free(rule->msg);
    g_free(rule->classtype);
    g_free(rule->protocol);

    for (n=0; n < rule->number_contents; n++) {
        g_free(rule->contents[n].str);
        g_free(rule->contents[n].translated_str);
    }

    for (n=0; n < rule->number_references; n++) {
        g_free(rule->references[n]);
    }

    snort_debug_printf("Freeing rule at :%p\n", rule);
    g_free(rule);
    return TRUE;
}


/* Parse this file, adding details to snort_config. */
/* N.B. using recursion_level to limit stack depth. */
#define MAX_CONFIG_FILE_RECURSE_DEPTH 8
// NOLINTNEXTLINE(misc-no-recursion)
static void parse_config_file(SnortConfig_t *snort_config, FILE *config_file_fd,
                              const char *filename, const char *dirname, int recursion_level)
{
    #define MAX_LINE_LENGTH 4096
    char line[MAX_LINE_LENGTH];
    int  line_number = 0;

    snort_debug_printf("parse_config_file(filename=%s, recursion_level=%d)\n", filename, recursion_level);

    if (recursion_level > MAX_CONFIG_FILE_RECURSE_DEPTH) {
        return;
    }

    /* Read each line of the file in turn, and see if we want any info from it. */
    while (fgets(line, MAX_LINE_LENGTH, config_file_fd)) {

        int line_length;
        ++line_number;

        /* Nothing interesting to parse */
        if ((line[0] == '\0') || (line[0] == '#')) {
            continue;
        }

        /* Trim newline from end */
        line_length = (int)strlen(line);
        while (line_length && ((line[line_length - 1] == '\n') || (line[line_length - 1] == '\r'))) {
            --line_length;
        }
        line[line_length] = '\0';
        if (line_length == 0) {
            continue;
        }

        /* Offer line to the various parsing functions.  Could optimise order.. */
        if (parse_variables_line(snort_config, line)) {
            continue;
        }
        if (parse_references_prefix_file_line(snort_config, line)) {
            continue;
        }
        if (parse_include_file(snort_config, line, dirname, recursion_level)) {
            continue;
        }
        if (parse_rule(snort_config, line, filename, line_number, line_length)) {
            snort_config->stat_rules++;
            continue;
        }
    }
}



/* Create the global ConfigParser */
void create_config(SnortConfig_t **snort_config, const char *snort_config_file)
{
    char* dirname;
    char* basename;
    FILE *config_file_fd;

    snort_debug_printf("create_config (%s)\n", snort_config_file);

    *snort_config = g_new(SnortConfig_t, 1);
    memset(*snort_config, 0, sizeof(SnortConfig_t));

    /* Create rule table */
    (*snort_config)->rules = g_hash_table_new(g_direct_hash, g_direct_equal);

    /* Create reference prefix table */
    (*snort_config)->references_prefixes = g_hash_table_new(string_hash, string_equal);

    /* Vars tables */
    (*snort_config)->vars = g_hash_table_new(string_hash, string_equal);
    (*snort_config)->ipvars = g_hash_table_new(string_hash, string_equal);
    (*snort_config)->portvars = g_hash_table_new(string_hash, string_equal);

    /* Extract separate directory and filename. */
    dirname =  g_path_get_dirname(snort_config_file);
    basename =  g_path_get_basename(snort_config_file);

    /* Attempt to open the config file */
    config_file_fd = ws_fopen(snort_config_file, "r");
    if (config_file_fd == NULL) {
        snort_debug_printf("Failed to open config file %s\n", snort_config_file);
        report_failure("Snort dissector: Failed to open config file %s\n", snort_config_file);
    }
    else {
        /* Start parsing from the top-level config file. */
        parse_config_file(*snort_config, config_file_fd, snort_config_file, dirname, 1 /* recursion level */);
        fclose(config_file_fd);
    }

    g_free(dirname);
    g_free(basename);
}


/* Delete the entire config */
void delete_config(SnortConfig_t **snort_config)
{
    snort_debug_printf("delete_config()\n");

    /* Iterate over all rules, freeing each one! */
    g_hash_table_foreach_remove((*snort_config)->rules, delete_rule, NULL);
    g_hash_table_destroy((*snort_config)->rules);

    /* References table */
    g_hash_table_foreach_remove((*snort_config)->references_prefixes, delete_string_entry, NULL);
    g_hash_table_destroy((*snort_config)->references_prefixes);

    /* Free up variable tables */
    g_hash_table_foreach_remove((*snort_config)->vars, delete_string_entry, NULL);
    g_hash_table_destroy((*snort_config)->vars);
    g_hash_table_foreach_remove((*snort_config)->ipvars, delete_string_entry, NULL);
    g_hash_table_destroy((*snort_config)->ipvars);
    g_hash_table_foreach_remove((*snort_config)->portvars, delete_string_entry, NULL);
    g_hash_table_destroy((*snort_config)->portvars);

    g_free(*snort_config);

    *snort_config = NULL;
}

/* Look for a rule corresponding to the given SID */
Rule_t *get_rule(SnortConfig_t *snort_config, uint32_t sid)
{
    if ((snort_config == NULL) || (snort_config->rules == NULL)) {
        return NULL;
    }
    else {
        return (Rule_t*)g_hash_table_lookup(snort_config->rules, GUINT_TO_POINTER(sid));
    }
}

/* Fetch some statistics. */
void get_global_rule_stats(SnortConfig_t *snort_config, unsigned int sid,
                           unsigned int *number_rules_files, unsigned int *number_rules,
                           unsigned int *alerts_detected, unsigned int *this_rule_alerts_detected)
{
    *number_rules_files = snort_config->stat_rules_files;
    *number_rules = snort_config->stat_rules;
    *alerts_detected = snort_config->stat_alerts_detected;
    const Rule_t *rule;

    /* Look up rule and get current/total matches */
    rule = get_rule(snort_config, sid);
    if (rule) {
        *this_rule_alerts_detected = rule->matches_seen;
    }
    else {
        *this_rule_alerts_detected = 0;
    }
}

/* Reset stats on individual rule */
static void reset_rule_stats(void *    key _U_,
                             void *    value,
                             void *    user_data _U_)
{
    Rule_t *rule = (Rule_t*)value;
    rule->matches_seen = 0;
}

/* Reset stats on all rules */
void reset_global_rule_stats(SnortConfig_t *snort_config)
{
    /* Reset global stats */
    if (snort_config == NULL) {
        return;
    }
    snort_config->stat_alerts_detected = 0;

    /* Iterate over all rules, resetting the stats of each */
    g_hash_table_foreach(snort_config->rules, reset_rule_stats, NULL);
}


/*************************************************************************************/
/* Dealing with content fields and trying to find where it matches within the packet */
/* Parse content strings to interpret binary and escaped characters. Do this         */
/* so we can look for in frame using memcmp().                                       */
static unsigned char content_get_nibble_value(char c)
{
    static unsigned char values[256];
    static bool values_set = false;

    if (!values_set) {
        /* Set table once and for all */
        unsigned char ch;
        for (ch='a'; ch <= 'f'; ch++) {
            values[ch] = 0xa + (ch-'a');
        }
        for (ch='A'; ch <= 'F'; ch++) {
            values[ch] = 0xa + (ch-'A');
        }
        for (ch='0'; ch <= '9'; ch++) {
            values[ch] = (ch-'0');
        }
        values_set = true;
    }

    return values[(unsigned char)c];
}

/* Go through string, converting hex digits into uint8_t, and removing escape characters. */
unsigned content_convert_to_binary(content_t *content)
{
    int output_idx = 0;
    bool in_binary_mode = false;    /* Are we in a binary region of the string?   */
    bool have_one_nibble = false;   /* Do we have the first nibble of the pair needed to make a byte? */
    unsigned char one_nibble = 0;       /* Value of first nibble if we have it */
    char c;
    int n;
    bool have_backslash = false;
    static char binary_str[1024];

    /* Just return length if have previously translated in binary string. */
    if (content->translated) {
        return content->translated_length;
    }

    /* Walk over each character, work out what needs to be written into output */
    for (n=0; content->str[n] != '\0'; n++) {
        c = content->str[n];
        if (c == '|') {
            /* Flip binary mode */
            in_binary_mode = !in_binary_mode;
            continue;
        }

        if (!in_binary_mode) {
            /* Not binary mode. Copying characters into output buffer, but watching out for escaped chars. */
            if (!have_backslash) {
                if (c == '\\') {
                    /* Just note that we have a backslash */
                    have_backslash = true;
                    continue;
                }
                else {
                    /* Just copy the character straight into output. */
                    binary_str[output_idx++] = (unsigned char)c;
                }
            }
            else {
                /* Currently have a backslash. Reset flag. */
                have_backslash = 0;
                /* Just copy the character into output. Really, the only characters that should be escaped
                   are ';' and  '\'  and '"' */
                binary_str[output_idx++] = (unsigned char)c;
            }
        }
        else {
            /* Binary mode. Handle pairs of hex digits and translate into uint8_t */
            if (c == ' ') {
                /* Ignoring inside binary mode */
                continue;
            }
            else {
                unsigned char nibble = content_get_nibble_value(c);
                if (!have_one_nibble) {
                    /* Store first nibble of a pair */
                    one_nibble = nibble;
                    have_one_nibble = true;
                }
                else {
                    /* Combine both nibbles into a byte */
                    binary_str[output_idx++] = (one_nibble << 4) + nibble;
                    /* Reset flag - looking for new pair of nibbles */
                    have_one_nibble = false;
                }
            }
        }
    }

    /* Store result for next time. */
    content->translated_str = (unsigned char*)g_malloc(output_idx+1);
    memcpy(content->translated_str, binary_str, output_idx+1);
    content->translated = true;
    content->translated_length = output_idx;

    return output_idx;
}

/* In order to use glib's regex library, need to trim
  '/' delimiters and any modifiers from the end of the string */
bool content_convert_pcre_for_regex(content_t *content)
{
    unsigned pcre_length, i, end_delimiter_offset = 0;

    /* Return if already converted */
    if (content->translated_str) {
        return true;
    }

    pcre_length = (unsigned)strlen(content->str);

    /* Start with content->str */
    if (pcre_length < 3) {
        /* Can't be valid.  Expect /regex/[modifiers] */
        return false;
    }

    if (pcre_length >= 512) {
        /* Have seen regex library crash on very long expressions
         * (830 bytes) as seen in SID=2019326, REV=6 */
        return false;
    }

    /* Verify that string starts with / */
    if (content->str[0] != '/') {
        return false;
    }

    /* Next, look for closing / near end of string */
    for (i=pcre_length-1; i > 2; i--) {
        if (content->str[i] == '/') {
            end_delimiter_offset = i;
            break;
        }
        else {
            switch (content->str[i]) {
                case 'i':
                    content->pcre_case_insensitive = true;
                    break;
                case 's':
                    content->pcre_dot_includes_newline = true;
                    break;
                case 'B':
                    content->pcre_raw = true;
                    break;
                case 'm':
                    content->pcre_multiline = true;
                    break;

                default:
                    /* TODO: handle other modifiers that will get seen? */
                    /* N.B. 'U' (match in decoded URI buffers) can't be handled, so don't store in flag. */
                    /* N.B. not sure if/how to handle 'R' (effectively distance:0) */
                    snort_debug_printf("Unhandled pcre modifier '%c'\n", content->str[i]);
                    break;
            }
        }
    }
    if (end_delimiter_offset == 0) {
        /* Didn't find it */
        return false;
    }

    /* Store result for next time. */
    content->translated_str = (unsigned char*)g_malloc(end_delimiter_offset);
    memcpy(content->translated_str, content->str+1, end_delimiter_offset - 1);
    content->translated_str[end_delimiter_offset-1] = '\0';
    content->translated = true;
    content->translated_length = end_delimiter_offset - 1;

    return true;
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
