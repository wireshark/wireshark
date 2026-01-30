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
};

// Dictionary structure
typedef struct _json_dictionary_t {
	wmem_tree_t *fields;        // Field definitions (path hash → json_field_t)
	wmem_tree_t *protocols;     // Protocol definitions (port → json_protocol_t)
	value_string_ext *types;    // Type name → type enum mapping
	bool has_case_insensitive_fields; // Optimization flag: true if any field is case-insensitive
} json_dictionary_t;

/* Protocol definition */
typedef struct _json_protocol_t {
	char *name;                 // Protocol nam
	char *display_name;         // Custom display name for Protocol column
	unsigned port;              // Default port
	char *transport;            // tcp or udp
	char **content_types;       // Array of content-type strings
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

typedef struct _dict_field_def {
	xmlChar *name;
	xmlChar *path;
	xmlChar *type;
	xmlChar *description;
	GSList *child_fields;      // List of dict_field_def_t
	GSList *enum_values;       // List of dict_enum_def_t
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
} dict_protocol_def_t;

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
