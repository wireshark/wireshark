/* packet-snort-config.h
 *
 * Copyright 2016, Martin Mathieson
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_SNORT_CONFIG_H__
#define __PACKET_SNORT_CONFIG_H__

#include <glib.h>

/* #define SNORT_CONFIG_DEBUG */
#ifdef  SNORT_CONFIG_DEBUG
#define snort_debug_printf printf
#else
#define snort_debug_printf(...)
#endif

/************************************************************************/
/* Rule related data types                                              */

typedef enum content_type_t {
    Content,
    UriContent,
    Pcre
} content_type_t;

/* Content (within an alert/rule) */
typedef struct content_t {
    /* Details as parsed from rule */
    content_type_t content_type;

    char     *str;
    gboolean negation;        /* i.e. pattern must not appear */
    gboolean nocase;          /* when set, do case insensitive match */

    gboolean offset_set;  /* Where to start looking within packet. -65535 -> 65535 */
    gint     offset;

    guint    depth;       /* How far to look into packet.  Can't be 0 */

    gboolean distance_set;
    gint     distance;    /* Same as offset but relative to last match. -65535 -> 65535 */

    guint    within;      /* Most bytes from end of previous match. Max 65535 */

    gboolean fastpattern; /* Is most distinctive content in rule */

    gboolean rawbytes;    /* Match should be done against raw bytes (which we do anyway) */

    /* http preprocessor modifiers */
    gboolean http_method;
    gboolean http_client_body;
    gboolean http_cookie;
    gboolean http_user_agent;

    /* Pattern converted into bytes for matching against packet.
       Used for regular patterns and PCREs alike. */
    guchar   *translated_str;
    gboolean translated;
    guint    translated_length;

    gboolean pcre_case_insensitive;
    gboolean pcre_dot_includes_newline;
    gboolean pcre_raw;
    gboolean pcre_multiline;
} content_t;

/* This is to keep track of a variable referenced by a rule */
typedef struct used_variable_t {
    char *name;
    char *value;
} used_variable_t;

/* The collection of variables referenced by a rule */
typedef struct relevant_vars_t {
    gboolean relevant_vars_set;

    #define MAX_RULE_PORT_VARS 6
    guint num_port_vars;
    used_variable_t port_vars[MAX_RULE_PORT_VARS];

    #define MAX_RULE_IP_VARS 6
    guint num_ip_vars;
    used_variable_t ip_vars[MAX_RULE_IP_VARS];

} relevant_vars_t;


/* This is purely the information parsed from the config */
typedef struct Rule_t {

    char *rule_string;             /* The whole rule as read from the rule file */
    char *file;                    /* Name of the rule file */
    guint line_number;             /* Line number of rule within rule file */

    char *msg;                     /* Description of the rule */
    char *classtype;
    guint32 sid, rev;

    char *protocol;

    /* content strings to match on */
    unsigned int number_contents;
#define MAX_CONTENT_ENTRIES 30
    content_t    contents[MAX_CONTENT_ENTRIES];

    /* Keep this pointer so can update attributes as parse modifier options */
    content_t    *last_added_content;

    /* References describing the rule */
    unsigned int number_references;
#define MAX_REFERENCE_ENTRIES 20
    char         *references[MAX_REFERENCE_ENTRIES];

    relevant_vars_t relevant_vars;

    /* Statistics */
    guint matches_seen;
} Rule_t;



/* Whole global snort config as learned by parsing config files */
typedef struct SnortConfig_t
{
    /* Variables (var, ipvar, portvar) */
    GHashTable *vars;
    GHashTable *ipvars;
    GHashTable *portvars;

    char     *rule_path;
    gboolean rule_path_is_absolute;

    /* (sid -> Rule_t*) table */
    GHashTable *rules;
    /* Reference (web .link) prefixes */
    GHashTable *references_prefixes;

    /* Statistics (that may be reset) */
    guint stat_rules_files;
    guint stat_rules;
    guint stat_alerts_detected;

} SnortConfig_t;


/*************************************************************************************/
/* API functions                                                                     */

void create_config(SnortConfig_t **snort_config, const char *snort_config_file);
void delete_config(SnortConfig_t **snort_config);

/* Look up rule by SID */
Rule_t *get_rule(SnortConfig_t *snort_config, guint32 sid);
void rule_set_alert(SnortConfig_t *snort_config, Rule_t *rule, guint *global_match_number, guint *rule_match_number);

/* IP and port vars */
void rule_set_relevant_vars(SnortConfig_t *snort_config, Rule_t *rule);

/* Substitute prefix (from reference.config) into reference string */
char *expand_reference(SnortConfig_t *snort_config, char *reference);

/* Rule stats */
void get_global_rule_stats(SnortConfig_t *snort_config, unsigned int sid,
                           unsigned int *number_rules_files, unsigned int *number_rules,
                           unsigned int *alerts_detected, unsigned int *this_rule_alerts_detected);
void reset_global_rule_stats(SnortConfig_t *snort_config);

/* Expanding a content field string to the expected binary bytes */
guint content_convert_to_binary(content_t *content);

gboolean content_convert_pcre_for_regex(content_t *content);

#endif

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
