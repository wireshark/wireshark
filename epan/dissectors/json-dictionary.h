/* json-dictionary.h
 * JSON dictionary parsing for JSON protocol dissector
 * Copyright 2026, Mark Stout <mark.stout@markstout.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __JSON_DICTIONARY_H__
#define __JSON_DICTIONARY_H__

#include <glib.h>
#include <libxml/parser.h>
#include <epan/wmem_scopes.h>
#include <epan/packet.h>
#include <wsutil/value_string.h>
#include <wsutil/wsjson.h>

// Field type enumeration
typedef enum {
	JSON_FIELD_STRING,
	JSON_FIELD_INTEGER,
	JSON_FIELD_UNSIGNED,
	JSON_FIELD_FLOAT,
	JSON_FIELD_BOOLEAN,
	JSON_FIELD_OBJECT,
	JSON_FIELD_ARRAY,
	JSON_FIELD_NULL
} json_field_type_t;

// Display type enumeration for special formatting
typedef enum {
	JSON_DISPLAY_NONE,
	JSON_DISPLAY_IPV4,
	JSON_DISPLAY_IPV6,
	JSON_DISPLAY_ETHER,
	JSON_DISPLAY_ABSOLUTE_TIME,
	JSON_DISPLAY_RELATIVE_TIME,
	JSON_DISPLAY_HEX2DEC
} json_display_type_t;

typedef struct _json_field_t json_field_t;

/* Field definition structure */
struct _json_field_t {
	char *name;                 /* Display name */
	char *path;                 /* JSON path (e.g., "user.profile.age") */
	unsigned path_hash;         /* Hash for O(1) lookup */
	json_field_type_t type;     /* Field type */
	json_display_type_t display_type; /* Special display formatting */
	int hf_value;               /* Wireshark header field index */
	int *ett;                   /* Pointer to subtree index (for objects/arrays) */
	value_string *enum_values;  /* For enumerated fields */
	wmem_tree_t *child_fields;  /* Child fields (for objects/arrays) */
	void *type_data;            /* Type-specific data */
	char *info_label;           /* Custom label for Info column (NULL = don't show) */
	char *parser;               /* External parser script path (relative to parsers/ dir) */
	char *parser_args;          /* Additional arguments for parser */
	wmem_tree_t *parser_child_hf; /* Dynamic header fields from parser (filter → hf_index) */
	bool case_insensitive;      /* Enable case-insensitive path matching */
	GSList *wildcard_fields;    /* Ordered list of json_wildcard_field_t* (NULL if none) */
};

// Forward declaration to keep wsutil/regex.h optional for callers
struct _ws_regex;

/* Runtime wildcard field — one per <wildcardfield> element */
typedef struct _json_wildcard_field_t json_wildcard_field_t;
struct _json_wildcard_field_t {
	char   *name;                    /* display name */
	char   *path;                    /* full path string */
	char   *alias;                   /* last segment of path — substituted for runtime key */
	char   *display_value;           /* label for key-value string field */
	struct _ws_regex *match_re;      /* compiled PCRE2 regex */
	wmem_tree_t *child_fields;       /* child json_field_t entries keyed by path */
	GSList      *child_wildcards;    /* nested json_wildcard_field_t entries (ordered) */
	int     hf_key_value;            /* hf index for the auto key-value string field */
	int    *ett;                     /* subtree index */
};

// Dictionary structure
typedef struct _json_dictionary_t {
	wmem_tree_t *fields;        // Field definitions (path hash → json_field_t)
	wmem_tree_t *protocols;     // Protocol definitions (port → json_protocol_t)
	value_string_ext *types;    // Type name → type enum mapping
	bool has_case_insensitive_fields; // Optimization flag: true if any field is case-insensitive
	GSList *path_matchers;      // List of json_protocol_t* with non-NULL path_regex (HTTP/2 :path dispatch)
	GSList *all_protocols;      // List of every json_protocol_t* loaded. Used at cleanup to free
	                            // heap-allocated fields (path_regex, port_list nodes) that aren't
	                            // wmem-managed.
	bool has_any_protocol;      // True if at least one <protocol> with port= or path= was loaded.
	                            //   When true, field-level dictionary parsing is gated on a
	                            //   per-packet protocol match. When false (no protocols defined),
	                            //   dictionary fields are applied globally for backward compat.
	GSList *wildcard_regexes;   // List of struct _ws_regex* compiled for <wildcardfield> match= attrs.
	                            // Freed at shutdown by json_dictionary_cleanup().
} json_dictionary_t;

/* Protocol definition */
typedef struct _json_protocol_t {
	char *name;                 // Protocol nam
	char *display_name;         // Custom display name for Protocol column
	unsigned port;              // Default port
	char *transport;            // tcp or udp
	char **content_types;       // Array of content-type strings
	struct _ws_regex *path_regex; // Compiled regex (NULL if no path= or compile failed)
	bool path_case_sensitive;   // True if path matching is case-sensitive
	bool require_all;           // condition="and": when BOTH port and path are set, both must match.
	                            // When only one is set, this is a no-op (the single condition is checked).
	GSList *port_list;          // List of unsigned* port numbers this protocol is bound to.
	                            // Stored on the protocol so dispatch can verify port membership when
	                            // checking the AND condition. Owned via wmem_epan_scope().
	wmem_tree_t *fields;        // Protocol-scoped field tree (path → json_field_t*). NULL when
	                            // this protocol's file defined no <field> elements, or when the
	                            // file had no <protocol> at all. Populated by parse_dictionary_file()
	                            // after all fields are created. Shares json_field_t* pointers with
	                            // the global dict->fields — no duplication.
	bool has_case_insensitive_fields; // True if any field in this protocol's tree is case_insensitive.
	int hf_proto_present;       // FT_BOOLEAN hf index for "json.<sanitized-name>". Set to -1
	                            // until registration; used to mark matched packets filterable.
} json_protocol_t;

/* Dictionary XML element names */
#define XML_ELEMENT_DICTIONARY     "json-dictionary"
#define XML_ELEMENT_BASE           "base"
#define XML_ELEMENT_TYPEDEFN       "typedefn"
#define XML_ELEMENT_PROTOCOL       "protocol"
#define XML_ELEMENT_FIELD          "field"
#define XML_ELEMENT_ARRAY_ELEMENT  "array-element"
#define XML_ELEMENT_ENUM           "enum"
#define XML_ELEMENT_CONTENT_TYPE   "content-type"
#define XML_ELEMENT_WILDCARDFIELD  "wildcardfield"

/* XML attribute names */
#define XML_ATTR_NAME              "name"
#define XML_ATTR_VERSION           "version"
#define XML_ATTR_TYPE_NAME         "type-name"
#define XML_ATTR_BASE_TYPE         "base-type"
#define XML_ATTR_DISPLAY           "display"
#define XML_ATTR_DISPLAY_NAME      "displayName"
#define XML_ATTR_PORT              "port"
#define XML_ATTR_TRANSPORT         "transport"
#define XML_ATTR_PATH              "path"
#define XML_ATTR_TYPE              "type"
#define XML_ATTR_DESCRIPTION       "description"
#define XML_ATTR_VALUE             "value"
#define XML_ATTR_CODE              "code"
#define XML_ATTR_INFO              "info"
#define XML_ATTR_DF                "df"
#define XML_ATTR_PARSER            "parser"
#define XML_ATTR_PARSER_ARGS       "parser-args"
#define XML_ATTR_CASE              "case"
#define XML_ATTR_CONDITION         "condition"
#define XML_ATTR_DISPLAY_VALUE     "displayvalue"
#define XML_ATTR_MATCH             "match"

// Temporary structures for XML parsing
typedef struct _dict_type_def {
	xmlChar *type_name;
	xmlChar *base_type;
	xmlChar *display;
} dict_type_def_t;

typedef struct _dict_enum_def {
	xmlChar *value;
	unsigned code;
	xmlChar *description;
} dict_enum_def_t;

typedef struct _dict_wildcardfield_def_t dict_wildcardfield_def_t;
struct _dict_wildcardfield_def_t {
	xmlChar *name;             // display name
	xmlChar *path;             // full path (e.g. "dnnConfigurations.apn")
	xmlChar *alias;            // last segment of path (e.g. "apn") — derived at parse time
	xmlChar *display_value;    // label for the key-value string field (default "key")
	xmlChar *match;            // PCRE2 regex string matched against runtime key
	GSList  *child_fields;     // List of dict_field_def_t (regular children)
	GSList  *child_wildcards;  // List of dict_wildcardfield_def_t (nested wildcards)
};

typedef struct _dict_field_def {
	xmlChar *name;
	xmlChar *path;
	xmlChar *type;
	xmlChar *description;
	GSList *child_fields;      // List of dict_field_def_t
	GSList *enum_values;       // List of dict_enum_def_t
	GSList *wildcard_children; // List of dict_wildcardfield_def_t
	bool is_array_element;
	xmlChar *info_label;       // Custom label for Info column (NULL = don't show)
	xmlChar *display_filter;   // Custom display filter name (NULL = use path-based name)
	xmlChar *parser;           // External parser script path
	xmlChar *parser_args;      // Additional arguments for parser
	xmlChar *case_attr;        // "sensitive" or "insensitive" - case sensitivity for path matching
} dict_field_def_t;

typedef struct _dict_protocol_def {
	xmlChar *name;
	xmlChar *display_name;     // Custom display name for Protocol column
	GSList *ports;             // List of unsigned port numbers - supports comma-separated ports
	xmlChar *transport;
	GSList *content_types;     // List of xmlChar*
	GSList *fields;            // List of dict_field_def_t
	xmlChar *path;             // Regex pattern matched against HTTP/2 :path (NULL if none)
	xmlChar *case_attr;        // "sensitive" or "insensitive" — default sensitive
	xmlChar *condition_attr;   // "and" (default) or "or" — combines port and path conditions
} dict_protocol_def_t;

/* Free regex objects and port-list nodes owned by the dictionary. Walks
 * dict->path_matchers to release each ws_regex_t, then dict->all_protocols to
 * release each port_list, then frees both lists. Called from packet-json.c via
 * register_shutdown_routine at program exit. */
void json_dictionary_cleanup(json_dictionary_t *dict);

/* Load dictionary from XML files
 * Returns true if successful, false otherwise
 */
bool load_json_dictionary(wmem_array_t *hf_array, GPtrArray *ett_array,
			  json_dictionary_t *dict);

// Cleanup functions for temporary structures
void dict_type_def_free(dict_type_def_t *type_def);
void dict_enum_def_free(dict_enum_def_t *enum_def);
void dict_field_def_free(dict_field_def_t *field_def);
void dict_protocol_def_free(dict_protocol_def_t *proto_def);

#endif /* __JSON_DICTIONARY_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
