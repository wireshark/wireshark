/* json-dictionary.c
 * JSON dictionary parsing for JSON protocol dissector
 * Copyright 2026, Mark Stout <mark.stout@markstout.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * JSON Dictionary XML Parser
 *
 * Loads dictionary files that define JSON field mappings, similar to
 * how the Diameter dissector loads AVP definitions.
 */

#include "config.h"

#include <string.h>
#include <stdio.h>

#include <glib.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <wsutil/regex.h>
#include <wsutil/wslog.h>
#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/report_message.h>

#include "json-dictionary.h"

/* Base type mapping */
typedef struct _base_type_mapping {
	const char *name;
	json_field_type_t type;
	enum ftenum ft_type;
	int display_base;
} base_type_mapping_t;

static const base_type_mapping_t base_type_mappings[] = {
	{ "string",    JSON_FIELD_STRING,   FT_STRING,  BASE_NONE },
	{ "int64",     JSON_FIELD_INTEGER,  FT_INT64,   BASE_DEC },
	{ "uint64",    JSON_FIELD_UNSIGNED, FT_UINT64,  BASE_DEC },
	{ "int32",     JSON_FIELD_INTEGER,  FT_INT32,   BASE_DEC },
	{ "uint32",    JSON_FIELD_UNSIGNED, FT_UINT32,  BASE_DEC },
	{ "double",    JSON_FIELD_FLOAT,    FT_DOUBLE,  BASE_NONE },
	{ "float",     JSON_FIELD_FLOAT,    FT_FLOAT,   BASE_NONE },
	{ "boolean",   JSON_FIELD_BOOLEAN,  FT_BOOLEAN, BASE_NONE },
	{ "object",    JSON_FIELD_OBJECT,   FT_NONE,    BASE_NONE },
	{ "array",     JSON_FIELD_ARRAY,    FT_NONE,    BASE_NONE },
	{ NULL,        JSON_FIELD_STRING,   FT_STRING,  BASE_NONE }
};

// Type definition storage passed as parameter

void
dict_type_def_free(dict_type_def_t *type_def)
{
	if (!type_def) return;

	xmlFree(type_def->type_name);
	xmlFree(type_def->base_type);
	xmlFree(type_def->display);
	g_free(type_def);
}

// Free enum definition
void
dict_enum_def_free(dict_enum_def_t *enum_def)
{
	if (!enum_def) return;

	xmlFree(enum_def->value);
	xmlFree(enum_def->description);
	g_free(enum_def);
}

/* Forward declaration — dict_wildcardfield_def_free and dict_field_def_free are mutually recursive */
static void dict_wildcardfield_def_free(dict_wildcardfield_def_t *wf);

// Free field definition recursively
void
dict_field_def_free(dict_field_def_t *field_def)
{
	if (!field_def) return;

	xmlFree(field_def->name);
	xmlFree(field_def->path);
	xmlFree(field_def->type);
	xmlFree(field_def->description);
	xmlFree(field_def->info_label);
	xmlFree(field_def->display_filter);
	xmlFree(field_def->parser);
	xmlFree(field_def->parser_args);
	xmlFree(field_def->case_attr);

	g_slist_free_full(field_def->child_fields, (GDestroyNotify)dict_field_def_free);
	g_slist_free_full(field_def->enum_values, (GDestroyNotify)dict_enum_def_free);
	g_slist_free_full(field_def->wildcard_children, (GDestroyNotify)dict_wildcardfield_def_free);

	g_free(field_def);
}

static void
dict_wildcardfield_def_free(dict_wildcardfield_def_t *wf)
{
	if (!wf) return;
	xmlFree(wf->name);
	xmlFree(wf->path);
	xmlFree(wf->alias);
	xmlFree(wf->display_value);
	xmlFree(wf->match);
	g_slist_free_full(wf->child_fields, (GDestroyNotify)dict_field_def_free);
	g_slist_free_full(wf->child_wildcards, (GDestroyNotify)dict_wildcardfield_def_free);
	g_free(wf);
}

// Free protocol definition
void
dict_protocol_def_free(dict_protocol_def_t *proto_def)
{
	if (!proto_def) return;

	xmlFree(proto_def->name);
	xmlFree(proto_def->display_name);
	xmlFree(proto_def->transport);
	xmlFree(proto_def->path);
	xmlFree(proto_def->case_attr);
	xmlFree(proto_def->condition_attr);

	g_slist_free_full(proto_def->content_types, (GDestroyNotify)xmlFree);
	g_slist_free_full(proto_def->fields, (GDestroyNotify)dict_field_def_free);
	g_slist_free_full(proto_def->ports, (GDestroyNotify)g_free);

	g_free(proto_def);
}

// Walk path_matchers and free the heap-allocated regex objects + pattern
// strings. The json_protocol_t structs themselves live in wmem_epan_scope and
// are released by wmem; only the ws_regex_t and the g_strdup'd pattern need
// explicit cleanup. Safe to call when path_matchers is NULL.
void
json_dictionary_cleanup(json_dictionary_t *dict)
{
	if (!dict) return;

	/* Free regex objects (only protocols with a path regex are in
	 * path_matchers). */
	for (GSList *m = dict->path_matchers; m; m = m->next) {
		json_protocol_t *p = (json_protocol_t *)m->data;
		if (p->path_regex) {
			ws_regex_free(p->path_regex);
			p->path_regex = NULL;
		}
	}
	g_slist_free(dict->path_matchers);
	dict->path_matchers = NULL;

	/* Free the port_list GSList nodes on every protocol (the unsigned*
	 * entries themselves are wmem-managed so we don't free them, just the
	 * linked-list scaffolding). */
	for (GSList *e = dict->all_protocols; e; e = e->next) {
		json_protocol_t *p = (json_protocol_t *)e->data;
		if (p->port_list) {
			g_slist_free(p->port_list);
			p->port_list = NULL;
		}
	}
	g_slist_free(dict->all_protocols);
	dict->all_protocols = NULL;

	/* Free compiled regexes for <wildcardfield> match= attributes */
	for (GSList *wr = dict->wildcard_regexes; wr; wr = wr->next) {
		ws_regex_free((struct _ws_regex *)wr->data);
	}
	g_slist_free(dict->wildcard_regexes);
	dict->wildcard_regexes = NULL;
}

// Look up base type mapping
static const base_type_mapping_t *
lookup_base_type(const char *type_name)
{
	int i;

	if (!type_name) {
		return &base_type_mappings[0];  /* Default to string */
	}

	for (i = 0; base_type_mappings[i].name != NULL; i++) {
		if (strcmp(type_name, base_type_mappings[i].name) == 0) {
			return &base_type_mappings[i];
		}
	}

	return &base_type_mappings[0];  /* Default to string */
}

// Process typedefn element
static dict_type_def_t *
process_typedefn(xmlNodePtr node)
{
	dict_type_def_t *type_def;
	xmlChar *type_name, *base_type, *display;

	type_name = xmlGetProp(node, (const xmlChar *)XML_ATTR_TYPE_NAME);
	base_type = xmlGetProp(node, (const xmlChar *)XML_ATTR_BASE_TYPE);
	display = xmlGetProp(node, (const xmlChar *)XML_ATTR_DISPLAY);

	if (!type_name || !base_type) {
		xmlFree(type_name);
		xmlFree(base_type);
		xmlFree(display);
		return NULL;
	}

	type_def = g_new0(dict_type_def_t, 1);
	type_def->type_name = type_name;
	type_def->base_type = base_type;
	type_def->display = display;

	return type_def;
}

// Process enum element
static dict_enum_def_t *
process_enum(xmlNodePtr node)
{
	dict_enum_def_t *enum_def;
	xmlChar *name, *code_str, *description;
	unsigned code = 0;

	name = xmlGetProp(node, (const xmlChar *)XML_ATTR_NAME);
	code_str = xmlGetProp(node, (const xmlChar *)XML_ATTR_CODE);
	description = xmlGetProp(node, (const xmlChar *)XML_ATTR_DESCRIPTION);

	if (!name || !code_str) {
		xmlFree(name);
		xmlFree(code_str);
		xmlFree(description);
		return NULL;
	}

	sscanf((const char *)code_str, "%u", &code);
	xmlFree(code_str);

	enum_def = g_new0(dict_enum_def_t, 1);
	enum_def->value = name;  // Store enum name in value field
	enum_def->code = code;
	enum_def->description = description;

	return enum_def;
}

/* Forward declarations for mutual recursion */
// NOLINTNEXTLINE(misc-no-recursion)
static dict_field_def_t *process_field(xmlNodePtr node, const char *parent_path, bool is_array_element);
// NOLINTNEXTLINE(misc-no-recursion)
static dict_wildcardfield_def_t *process_wildcardfield(xmlNodePtr node, const char *parent_path);

// NOLINTNEXTLINE(misc-no-recursion)
static dict_wildcardfield_def_t *process_wildcardfield(xmlNodePtr node, const char *parent_path)
{
	xmlChar *name = xmlGetProp(node, (const xmlChar *)XML_ATTR_NAME);
	xmlChar *path = xmlGetProp(node, (const xmlChar *)XML_ATTR_PATH);
	xmlChar *display_value = xmlGetProp(node, (const xmlChar *)XML_ATTR_DISPLAY_VALUE);
	xmlChar *match = xmlGetProp(node, (const xmlChar *)XML_ATTR_MATCH);

	if (!path || !match) {
		ws_warning("JSON Dictionary: <wildcardfield> missing required 'path' or 'match' attribute");
		if (name) xmlFree(name);
		if (path) xmlFree(path);
		if (display_value) xmlFree(display_value);
		if (match) xmlFree(match);
		return NULL;
	}

	/* Extract alias as last segment of path */
	const char *last_dot = strrchr((const char *)path, '.');
	xmlChar *alias = last_dot ?
		xmlStrdup((const xmlChar *)(last_dot + 1)) :
		xmlStrdup(path);

	dict_wildcardfield_def_t *wf = g_new0(dict_wildcardfield_def_t, 1);
	wf->name          = name ? name : xmlStrdup(path);
	wf->path          = path;
	wf->alias         = alias;
	wf->display_value = display_value ? display_value : xmlStrdup((const xmlChar *)"key");
	wf->match         = match;
	wf->child_fields  = NULL;
	wf->child_wildcards = NULL;

	/* Process child nodes */
	for (xmlNodePtr child = node->children; child != NULL; child = child->next) {
		if (child->type != XML_ELEMENT_NODE)
			continue;

		if (xmlStrcmp(child->name, (const xmlChar *)XML_ELEMENT_FIELD) == 0) {
			dict_field_def_t *cf = process_field(child, parent_path, false);
			if (cf)
				wf->child_fields = g_slist_append(wf->child_fields, cf);
		}
		else if (xmlStrcmp(child->name, (const xmlChar *)XML_ELEMENT_ARRAY_ELEMENT) == 0) {
			/* Treat like process_field does: iterate <field> children of <array-element> */
			xmlChar *elem_type = xmlGetProp(child, (const xmlChar *)XML_ATTR_TYPE);
			for (xmlNodePtr ec = child->children; ec != NULL; ec = ec->next) {
				if (ec->type != XML_ELEMENT_NODE) continue;
				if (xmlStrcmp(ec->name, (const xmlChar *)XML_ELEMENT_FIELD) == 0) {
					dict_field_def_t *ef = process_field(ec, parent_path, true);
					if (ef)
						wf->child_fields = g_slist_append(wf->child_fields, ef);
				}
			}
			if (elem_type) xmlFree(elem_type);
		}
		else if (xmlStrcmp(child->name, (const xmlChar *)XML_ELEMENT_WILDCARDFIELD) == 0) {
			dict_wildcardfield_def_t *cwf = process_wildcardfield(child, parent_path);
			if (cwf)
				wf->child_wildcards = g_slist_append(wf->child_wildcards, cwf);
		}
	}

	return wf;
}

// Process field element (recursive for nested fields)
// NOLINTNEXTLINE(misc-no-recursion)
static dict_field_def_t *process_field(xmlNodePtr node, const char *parent_path, bool is_array_element)
{
	dict_field_def_t *field_def;
	xmlChar *name, *path, *type, *description, *info_attr, *df_attr;
	xmlChar *parser_attr, *parser_args_attr, *case_attr;
	xmlNodePtr child;

	name = xmlGetProp(node, (const xmlChar *)XML_ATTR_NAME);
	path = xmlGetProp(node, (const xmlChar *)XML_ATTR_PATH);

	// Path is required
	if (!path) {
		// If no path specified, try to construct from parent + name
		if (name && parent_path) {
			if (is_array_element) {
				path = xmlStrdup((const xmlChar *)wmem_strdup_printf(
					wmem_epan_scope(), "%s[].%s", parent_path, name));
			} else {
				path = xmlStrdup((const xmlChar *)wmem_strdup_printf(
					wmem_epan_scope(), "%s.%s", parent_path, name));
			}
		} else if (name) {
			path = xmlStrdup(name);
		} else {
			return NULL;
		}
	}

	type = xmlGetProp(node, (const xmlChar *)XML_ATTR_TYPE);
	description = xmlGetProp(node, (const xmlChar *)XML_ATTR_DESCRIPTION);
	info_attr = xmlGetProp(node, (const xmlChar *)XML_ATTR_INFO);
	df_attr = xmlGetProp(node, (const xmlChar *)XML_ATTR_DF);
	parser_attr = xmlGetProp(node, (const xmlChar *)XML_ATTR_PARSER);
	parser_args_attr = xmlGetProp(node, (const xmlChar *)XML_ATTR_PARSER_ARGS);
	case_attr = xmlGetProp(node, (const xmlChar *)XML_ATTR_CASE);

	field_def = g_new0(dict_field_def_t, 1);
	field_def->name = name ? name : xmlStrdup(path);
	field_def->path = path;
	field_def->type = type;
	field_def->description = description;
	field_def->is_array_element = is_array_element;
	field_def->child_fields = NULL;
	field_def->enum_values = NULL;
	field_def->info_label = info_attr;  // Store the info label string (NULL if not present)
	field_def->display_filter = df_attr;  // Store custom display filter name (NULL if not present)
	field_def->parser = parser_attr;  // parser  path
	field_def->parser_args = parser_args_attr;  // Additional parser arguments
	field_def->case_attr = case_attr;  // Store case sensitivity attribute

	/* Process child nodes */
	for (child = node->children; child != NULL; child = child->next) {
		if (child->type != XML_ELEMENT_NODE) {
			continue;
		}

		if (xmlStrcmp(child->name, (const xmlChar *)XML_ELEMENT_FIELD) == 0) {
			// Nested field
			dict_field_def_t *child_field = process_field(child,
				(const char *)path, false);
			if (child_field) {
				field_def->child_fields = g_slist_append(
					field_def->child_fields, child_field);
			}
		}
		else if (xmlStrcmp(child->name, (const xmlChar *)XML_ELEMENT_ARRAY_ELEMENT) == 0) {
			/* Array element definition */
			xmlChar *elem_type = xmlGetProp(child,
				(const xmlChar *)XML_ATTR_TYPE);
			xmlChar *elem_info = xmlGetProp(child,
				(const xmlChar *)XML_ATTR_INFO);
			xmlNodePtr elem_child;
			bool has_child_fields = false;

			// Process fields within array element
			for (elem_child = child->children; elem_child != NULL;
			     elem_child = elem_child->next) {
				if (elem_child->type != XML_ELEMENT_NODE) {
					continue;
				}

				if (xmlStrcmp(elem_child->name,
					(const xmlChar *)XML_ELEMENT_FIELD) == 0) {
					dict_field_def_t *elem_field = process_field(
						elem_child, (const char *)path, true);
					if (elem_field) {
						field_def->child_fields = g_slist_append(
							field_def->child_fields, elem_field);
						has_child_fields = true;
					}
				}
			}

			/* Register a field at <path>[] for primitive array elements so values
			 * are filterable (e.g. json.allowedSscModes[] == "SSC_MODE_1"). */
			if (!has_child_fields) {
				dict_field_def_t *elem_field = g_new0(dict_field_def_t, 1);
				elem_field->name = xmlStrdup(field_def->name);
				elem_field->path = xmlStrdup((const xmlChar *)wmem_strdup_printf(
					wmem_epan_scope(), "%s[]", (const char *)path));
				elem_field->type = elem_type ? xmlStrdup(elem_type) : NULL;
				elem_field->description = xmlStrdup((const xmlChar *)"Array element");
				elem_field->is_array_element = true;
				elem_field->child_fields = NULL;
				elem_field->enum_values = NULL;
				elem_field->info_label = xmlStrdup(elem_info);

				field_def->child_fields = g_slist_append(
					field_def->child_fields, elem_field);
			}

			xmlFree(elem_type);
			if (elem_info) xmlFree(elem_info);
		}
		else if (xmlStrcmp(child->name, (const xmlChar *)XML_ELEMENT_ENUM) == 0) {
			// Enum value
			dict_enum_def_t *enum_def = process_enum(child);
			if (enum_def) {
				field_def->enum_values = g_slist_append(
					field_def->enum_values, enum_def);
			}
		}
		else if (xmlStrcmp(child->name, (const xmlChar *)XML_ELEMENT_WILDCARDFIELD) == 0) {
			dict_wildcardfield_def_t *wf = process_wildcardfield(child,
				(const char *)path);
			if (wf) {
				field_def->wildcard_children = g_slist_append(
					field_def->wildcard_children, wf);
			}
		}
	}

	return field_def;
}

// Process protocol element
static dict_protocol_def_t *
process_protocol(xmlNodePtr node)
{
	dict_protocol_def_t *proto_def;
	xmlChar *name, *display_name, *port_str, *transport;
	xmlNodePtr child;
	GSList *ports = NULL;

	name = xmlGetProp(node, (const xmlChar *)XML_ATTR_NAME);
	display_name = xmlGetProp(node, (const xmlChar *)XML_ATTR_DISPLAY_NAME);
	port_str = xmlGetProp(node, (const xmlChar *)XML_ATTR_PORT);
	transport = xmlGetProp(node, (const xmlChar *)XML_ATTR_TRANSPORT);
	/* path= and case= are optional. path is a regex matched against the
	 * HTTP/2 :path pseudo-header for dispatch in 5G SBI / HTTP-multiplexed
	 * deployments where one TCP port carries many JSON services. */
	xmlChar *path_attr = xmlGetProp(node, (const xmlChar *)XML_ATTR_PATH);
	xmlChar *case_attr = xmlGetProp(node, (const xmlChar *)XML_ATTR_CASE);
	xmlChar *condition_attr = xmlGetProp(node, (const xmlChar *)XML_ATTR_CONDITION);

	// Parse comma-separated port numbers
	if (port_str) {
		char *port_str_copy = g_strdup((const char *)port_str);
		char *token = strtok(port_str_copy, ",");
		while (token != NULL) {
			unsigned port = 0;
			// Trim leading/trailing whitespace
			while (*token == ' ' || *token == '\t') token++;
			if (sscanf(token, "%u", &port) == 1 && port > 0) {
				unsigned *port_ptr = g_new(unsigned, 1);
				*port_ptr = port;
				ports = g_slist_append(ports, port_ptr);
			}
			token = strtok(NULL, ",");
		}
		g_free(port_str_copy);
		xmlFree(port_str);
	}

	proto_def = g_new0(dict_protocol_def_t, 1);
	proto_def->name = name;
	proto_def->display_name = display_name;
	proto_def->ports = ports;
	proto_def->transport = transport;
	proto_def->content_types = NULL;
	proto_def->fields = NULL;
	proto_def->path = path_attr;
	proto_def->case_attr = case_attr;
	proto_def->condition_attr = condition_attr;

	/* Process child nodes */
	for (child = node->children; child != NULL; child = child->next) {
		if (child->type != XML_ELEMENT_NODE) {
			continue;
		}

		if (xmlStrcmp(child->name, (const xmlChar *)XML_ELEMENT_CONTENT_TYPE) == 0) {
			// Content-type
			xmlChar *content_type = xmlNodeGetContent(child);
			if (content_type) {
				proto_def->content_types = g_slist_append(
					proto_def->content_types, content_type);
			}
		}
	}

	return proto_def;
}

// Parse display type hint from string
static json_display_type_t
parse_display_type(const char *display_str)
{
	if (!display_str) {
		return JSON_DISPLAY_NONE;
	}

	if (strcmp(display_str, "ipv4") == 0) {
		return JSON_DISPLAY_IPV4;
	} else if (strcmp(display_str, "ipv6") == 0) {
		return JSON_DISPLAY_IPV6;
	} else if (strcmp(display_str, "ether") == 0) {
		return JSON_DISPLAY_ETHER;
	} else if (strcmp(display_str, "absolute_time") == 0) {
		return JSON_DISPLAY_ABSOLUTE_TIME;
	} else if (strcmp(display_str, "relative_time") == 0) {
		return JSON_DISPLAY_RELATIVE_TIME;
	} else if (strcmp(display_str, "hex2dec") == 0) {
		return JSON_DISPLAY_HEX2DEC;
	}

	return JSON_DISPLAY_NONE;
}

/* Forward declaration for mutual recursion between create_wildcardfield and create_json_field */
// NOLINTNEXTLINE(misc-no-recursion)
static json_field_t *create_json_field(dict_field_def_t *field_def, wmem_array_t *hf_array,
		  GPtrArray *ett_array, json_dictionary_t *dict, GHashTable *type_definitions);

// NOLINTNEXTLINE(misc-no-recursion)
static json_wildcard_field_t *create_wildcardfield(dict_wildcardfield_def_t *wf_def, wmem_array_t *hf_array,
		     GPtrArray *ett_array, json_dictionary_t *dict, GHashTable *type_definitions)
{
	if (!wf_def || !wf_def->match)
		return NULL;

	/* Compile the match regex */
	char *regex_err = NULL;
	struct _ws_regex *re = ws_regex_compile((const char *)wf_def->match, &regex_err);
	if (!re) {
		ws_warning("JSON Dictionary: wildcardfield match='%s' regex compile failed: %s",
			   (const char *)wf_def->match, regex_err ? regex_err : "unknown");
		g_free(regex_err);
		return NULL;
	}

	json_wildcard_field_t *jwf = wmem_new0(wmem_epan_scope(), json_wildcard_field_t);
	jwf->name          = wmem_strdup(wmem_epan_scope(), (const char *)wf_def->name);
	jwf->path          = wmem_strdup(wmem_epan_scope(), (const char *)wf_def->path);
	jwf->alias         = wmem_strdup(wmem_epan_scope(), (const char *)wf_def->alias);
	jwf->display_value = wmem_strdup(wmem_epan_scope(),
		wf_def->display_value ? (const char *)wf_def->display_value : "key");
	jwf->match_re      = re;
	jwf->hf_key_value  = -1;
	/* Track regex for cleanup at shutdown */
	dict->wildcard_regexes = g_slist_append(dict->wildcard_regexes, re);
	jwf->child_fields  = NULL;
	jwf->child_wildcards = NULL;

	/* Register the auto key-value string field: json.<path>.<displayvalue> */
	char *kv_filter = wmem_strdup_printf(wmem_epan_scope(), "json.%s.%s",
		jwf->path, jwf->display_value);
	/* Sanitize: strip brackets, collapse leading dots */
	{
		char *rp = kv_filter, *wp = kv_filter;
		while (*rp) {
			if (*rp != '[' && *rp != ']') *wp++ = *rp;
			rp++;
		}
		*wp = '\0';
		char *suffix = kv_filter + strlen("json.");
		while (*suffix == '.') memmove(suffix, suffix + 1, strlen(suffix + 1) + 1);
	}

	int *ett_ptr = wmem_new(wmem_epan_scope(), int);
	*ett_ptr = -1;
	jwf->ett = ett_ptr;
	g_ptr_array_add(ett_array, ett_ptr);

	hf_register_info kv_hf = {
		&jwf->hf_key_value,
		{ jwf->display_value, kv_filter,
		  FT_STRING, BASE_NONE, NULL, 0, "", HFILL }
	};
	wmem_array_append_one(hf_array, kv_hf);

	/* Register child <field> entries into jwf->child_fields tree */
	if (wf_def->child_fields) {
		jwf->child_fields = wmem_tree_new(wmem_epan_scope());
		for (GSList *elem = wf_def->child_fields; elem; elem = elem->next) {
			dict_field_def_t *cf = (dict_field_def_t *)elem->data;
			json_field_t *jf = create_json_field(cf, hf_array, ett_array, dict, type_definitions);
			if (jf)
				wmem_tree_insert_string(jwf->child_fields, jf->path, jf, 0);
		}
	}

	/* Register nested <wildcardfield> entries */
	for (GSList *wc = wf_def->child_wildcards; wc; wc = wc->next) {
		json_wildcard_field_t *cwf = create_wildcardfield(
			(dict_wildcardfield_def_t *)wc->data, hf_array, ett_array, dict, type_definitions);
		if (cwf)
			jwf->child_wildcards = g_slist_append(jwf->child_wildcards, cwf);
	}

	return jwf;
}

// Create json_field_t from dict_field_def_t and register header fields
// NOLINTNEXTLINE(misc-no-recursion)
static json_field_t *create_json_field(dict_field_def_t *field_def, wmem_array_t *hf_array,
		  GPtrArray *ett_array, json_dictionary_t *dict, GHashTable *type_definitions)
{
	json_field_t *field;
	const base_type_mapping_t *base_type;
	const char *type_name;
	hf_register_info hf;
	int *ett_ptr;
	char *filter_name;
	json_display_type_t display_type = JSON_DISPLAY_NONE;

	if (!field_def) {
		return NULL;
	}

	// Resolve type
	type_name = (const char *)field_def->type;
	if (!type_name) {
		type_name = "string";  // Default
	}

	// Look up type in custom type definitions first
	dict_type_def_t *type_def = NULL;
	if (type_definitions) {
		type_def = g_hash_table_lookup(type_definitions, type_name);
	}

	if (type_def) {
		type_name = (const char *)type_def->base_type;
		/* Check for display hint in type definition */
		if (type_def->display) {
			display_type = parse_display_type((const char *)type_def->display);
		}
	}

	base_type = lookup_base_type(type_name);

	// Override field type for special displays
	enum ftenum ft_type = base_type->ft_type;
	int display_base = base_type->display_base;

	// Handle special display types first
	if (display_type == JSON_DISPLAY_IPV4) {
		ft_type = FT_IPv4;
		display_base = BASE_NONE;
	} else if (display_type == JSON_DISPLAY_IPV6) {
		ft_type = FT_IPv6;
		display_base = BASE_NONE;
	} else if (display_type == JSON_DISPLAY_ETHER) {
		ft_type = FT_ETHER;
		display_base = BASE_NONE;
	} else if (display_type == JSON_DISPLAY_ABSOLUTE_TIME) {
		ft_type = FT_ABSOLUTE_TIME;
		display_base = ABSOLUTE_TIME_LOCAL;
	} else if (display_type == JSON_DISPLAY_RELATIVE_TIME) {
		ft_type = FT_RELATIVE_TIME;
		display_base = BASE_NONE;
	} else if (display_type == JSON_DISPLAY_HEX2DEC) {
		ft_type = FT_UINT64;
		display_base = BASE_DEC_HEX;
	} else if (field_def->enum_values) {
		/* If field has enums and no special display type, use 32bit integer type
		 * (value_string only supports 32-bit) */
		if (ft_type == FT_INT64) {
			ft_type = FT_INT32;
		} else if (ft_type == FT_UINT64) {
			ft_type = FT_UINT32;
		}
	}

	// If hex2dec has enums, downgrade to 32-bit
	if (display_type == JSON_DISPLAY_HEX2DEC && field_def->enum_values) {
		ft_type = FT_UINT32;
	}

	/* Last-loaded wins. When the same path is defined by multiple
	 * dictionary files, the later one overrides the earlier one (matches
	 * the existing rule for <protocol> ports and the "Field Collision
	 * Example" already documented in resources/protocols/json/config.txt).
	 *
	 * This is what lets a personal dictionary in ~/.config/wireshark/json/
	 * override a system field of the same path: personal loads after
	 * system, so wmem_tree_insert_string() below overwrites the mapping.
	 *
	 * Note: the prior field's hf registration stays in the protocol's hf
	 * array (Wireshark does not support deregistering individual fields
	 * after proto_register_field_array). The tree-level override is what
	 * matters for dispatch; the orphaned hf entry is bounded by the
	 * number of overridden fields and released with wmem_epan_scope at
	 * program exit. */

	/* Create field structure */
	field = wmem_new0(wmem_epan_scope(), json_field_t);

	// Append ** to field name
	if (field_def->parser) {
		field->name = wmem_strdup_printf(wmem_epan_scope(), "%s**",
			(const char *)field_def->name);
	} else {
		field->name = wmem_strdup(wmem_epan_scope(), (const char *)field_def->name);
	}

	field->path = wmem_strdup(wmem_epan_scope(), (const char *)field_def->path);
	field->path_hash = 0;
	field->type = base_type->type;
	field->display_type = display_type;
	field->hf_value = -1;
	field->ett = NULL;
	field->enum_values = NULL;
	field->child_fields = NULL;
	field->type_data = NULL;
	field->info_label = field_def->info_label ?
		wmem_strdup(wmem_epan_scope(), (const char *)field_def->info_label) : NULL;
	field->parser = field_def->parser ?
		wmem_strdup(wmem_epan_scope(), (const char *)field_def->parser) : NULL;
	field->parser_args = field_def->parser_args ?
		wmem_strdup(wmem_epan_scope(), (const char *)field_def->parser_args) : NULL;
	field->parser_child_hf = NULL;  // Will be populated dynamically during parsing

	// Parse case attribute (default to case-sensitive)
	field->case_insensitive = false;
	if (field_def->case_attr) {
		if (g_ascii_strcasecmp((const char *)field_def->case_attr, "insensitive") == 0) {
			field->case_insensitive = true;
			dict->has_case_insensitive_fields = true;
		} else if (g_ascii_strcasecmp((const char *)field_def->case_attr, "sensitive") == 0) {
			field->case_insensitive = false;
		} else {
			// Invalid value - log warning and use default
			ws_warning("JSON Dictionary: Invalid case attribute value '%s' for field '%s', using 'sensitive'",
				   (const char *)field_def->case_attr, field->path);
			field->case_insensitive = false;
		}
	}

	// Use custom display filter name if specified, otherwise use pathbased name
	if (field_def->display_filter) {
		filter_name = wmem_strdup_printf(wmem_epan_scope(), "json.%s",
			(const char *)field_def->display_filter);
	} else {
		filter_name = wmem_strdup_printf(wmem_epan_scope(), "json.%s",
			field->path);

		// Remove brackets from filter name for array notation
		char *read_ptr = filter_name;
		char *write_ptr = filter_name;
		while (*read_ptr) {
			if (*read_ptr != '[' && *read_ptr != ']') {
				*write_ptr++ = *read_ptr;
			}
			read_ptr++;
		}
		*write_ptr = '\0';

		// Bracket removal can leave invalid dots: "[]" -> "json." (trailing dot)
		// and "[].foo" -> "json..foo" (doubled dot). Collapse any dots immediately
		// after the "json." prefix so the filter name stays valid.
		char *suffix = filter_name + strlen("json.");
		while (*suffix == '.') {
			memmove(suffix, suffix + 1, strlen(suffix + 1) + 1);
		}
		// If the path was purely "[]", suffix is now empty — use the field name.
		if (*suffix == '\0') {
			filter_name = wmem_strdup_printf(wmem_epan_scope(), "json.%s",
				(const char *)field_def->name);
			for (char *p = filter_name + strlen("json."); *p; p++) {
				*p = (*p == ' ') ? '_' : g_ascii_tolower(*p);
			}
		}

		/* Array container fields (type=Array, FT_NONE) get a "_array" suffix so
		 * their filter name doesn't collide with the auto-generated element field
		 * at the same path (which gets the clean natural filter name). This prevents
		 * a crash when "apply as filter" is used on the array container node. */
		if (field->type == JSON_FIELD_ARRAY && !field_def->is_array_element) {
			filter_name = wmem_strdup_printf(wmem_epan_scope(), "%s_array", filter_name);
		}
	}

	/* Build enum value_string array if present */
	if (field_def->enum_values) {
		int enum_count = g_slist_length(field_def->enum_values);
		value_string *vs = wmem_alloc_array(wmem_epan_scope(), value_string,
			enum_count + 1);
		int idx = 0;

		for (GSList *elem = field_def->enum_values; elem; elem = elem->next) {
			dict_enum_def_t *enum_def = (dict_enum_def_t *)elem->data;
			vs[idx].value = enum_def->code;
			vs[idx].strptr = wmem_strdup(wmem_epan_scope(),
				(const char *)enum_def->value);
			idx++;
		}
		// Terminator
		vs[enum_count].value = 0;
		vs[enum_count].strptr = NULL;

		field->enum_values = vs;
	}

	hf.p_id = &field->hf_value;
	hf.hfinfo.name = field->name;
	hf.hfinfo.abbrev = filter_name;
	hf.hfinfo.type = ft_type;
	hf.hfinfo.display = display_base;
	hf.hfinfo.strings = field->enum_values ? VALS(field->enum_values) : NULL;
	hf.hfinfo.bitmask = 0;
	hf.hfinfo.blurb = field_def->description ?
		wmem_strdup(wmem_epan_scope(), (const char *)field_def->description) :
		"";
	HFILL_INIT(hf);

	wmem_array_append_one(hf_array, hf);

	// Register subtree for objects and arrays
	if (field->type == JSON_FIELD_OBJECT || field->type == JSON_FIELD_ARRAY) {
		ett_ptr = wmem_new(wmem_epan_scope(), int);
		*ett_ptr = -1;
		field->ett = ett_ptr;  // Store pointer, not value
		g_ptr_array_add(ett_array, ett_ptr);
	}

	// Insert into dictionary using stringbased lookup to avoid hash collisions
	wmem_tree_insert_string(dict->fields, field->path, field, 0);

	// Process child fields recursively
	if (field_def->child_fields) {
		field->child_fields = wmem_tree_new(wmem_epan_scope());

		for (GSList *elem = field_def->child_fields; elem; elem = elem->next) {
			dict_field_def_t *child_def = (dict_field_def_t *)elem->data;
			json_field_t *child_field = create_json_field(child_def,
				hf_array, ett_array, dict, type_definitions);
			if (child_field) {
				// Insert into parent's child_fields tree for hierarchical access
				wmem_tree_insert_string(field->child_fields,
					child_field->path, child_field, 0);
			}
		}
	}

	/* Process <wildcardfield> children */
	if (field_def->wildcard_children) {
		for (GSList *wc = field_def->wildcard_children; wc; wc = wc->next) {
			json_wildcard_field_t *jwf = create_wildcardfield(
				(dict_wildcardfield_def_t *)wc->data,
				hf_array, ett_array, dict, type_definitions);
			if (jwf)
				field->wildcard_fields = g_slist_append(field->wildcard_fields, jwf);
		}
	}

	return field;
}

/* Forward declaration — mutually recursive with populate_protocol_field_trees. */
// NOLINTNEXTLINE(misc-no-recursion)
static void populate_protocol_wildcard_trees(dict_wildcardfield_def_t *wdef, GSList *proto_list,
					     json_dictionary_t *dict);

/* Recursively walk a field_def tree and insert each already-created
 * json_field_t* (fetched from dict->fields) into every protocol's scoped
 * field tree.  Also recurses into wildcard_children so alias-path fields
 * (e.g. dnnConfigurations.apn.5gQosProfile) are included.
 * Called once per file after all json_field_t objects have been created.
 * Shares pointers — no duplication. */
// NOLINTNEXTLINE(misc-no-recursion)
static void populate_protocol_field_trees(dict_field_def_t *fdef, GSList *proto_list,
			      json_dictionary_t *dict)
{
	if (!fdef || !fdef->path)
		return;
	json_field_t *jf = (json_field_t *)wmem_tree_lookup_string(
		dict->fields, (const char *)fdef->path, 0);
	if (jf) {
		for (GSList *pe = proto_list; pe; pe = pe->next) {
			json_protocol_t *proto = (json_protocol_t *)pe->data;
			wmem_tree_insert_string(proto->fields, jf->path, jf, 0);
			if (jf->case_insensitive)
				proto->has_case_insensitive_fields = true;
		}
	}
	for (GSList *ce = fdef->child_fields; ce; ce = ce->next)
		populate_protocol_field_trees(
			(dict_field_def_t *)ce->data, proto_list, dict);
	for (GSList *wc = fdef->wildcard_children; wc; wc = wc->next)
		populate_protocol_wildcard_trees(
			(dict_wildcardfield_def_t *)wc->data, proto_list, dict);
}

/* Recurse into a wildcardfield def's child_fields and child_wildcards,
 * inserting their already-created json_field_t* into every protocol tree. */
// NOLINTNEXTLINE(misc-no-recursion)
static void populate_protocol_wildcard_trees(dict_wildcardfield_def_t *wdef,
				 GSList *proto_list,
				 json_dictionary_t *dict)
{
	if (!wdef)
		return;
	for (GSList *ce = wdef->child_fields; ce; ce = ce->next)
		populate_protocol_field_trees(
			(dict_field_def_t *)ce->data, proto_list, dict);
	for (GSList *wc = wdef->child_wildcards; wc; wc = wc->next)
		populate_protocol_wildcard_trees(
			(dict_wildcardfield_def_t *)wc->data, proto_list, dict);
}

/* Sanitize a protocol name= value into a valid Wireshark filter suffix:
 * lowercase, spaces→'_', non-[a-z0-9_]→'_', collapse runs of '_',
 * strip trailing '_', prefix '_' if result starts with a digit. */
static char *
sanitize_protocol_filter_name(const char *name)
{
	if (!name || *name == '\0')
		return NULL;

	size_t len = strlen(name);
	char *buf = (char *)wmem_alloc(wmem_epan_scope(), len + 2); /* +2: possible '_' prefix + NUL */
	size_t out = 0;

	for (size_t i = 0; i < len; i++) {
		unsigned char c = (unsigned char)name[i];
		char mapped;
		if (c >= 'A' && c <= 'Z')
			mapped = (char)(c + ('a' - 'A'));
		else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))
			mapped = (char)c;
		else
			mapped = '_';

		/* Collapse consecutive underscores */
		if (mapped == '_' && out > 0 && buf[out - 1] == '_')
			continue;
		buf[out++] = mapped;
	}

	/* Strip trailing underscores */
	while (out > 0 && buf[out - 1] == '_')
		out--;

	buf[out] = '\0';

	if (out == 0)
		return NULL;

	/* Prefix '_' if first char is a digit */
	if (buf[0] >= '0' && buf[0] <= '9') {
		memmove(buf + 1, buf, out + 1);
		buf[0] = '_';
	}

	return buf;
}

// Parse dictionary XML file
static bool
parse_dictionary_file(const char *filename, wmem_array_t *hf_array,
		      GPtrArray *ett_array, json_dictionary_t *dict)
{
	xmlDocPtr doc;
	xmlNodePtr root, node, child;
	GSList *field_defs = NULL;
	GSList *protocol_defs = NULL;
	bool success = false;
	GHashTable *type_definitions = NULL;  /* Local to this dictionary file */

	// Initialize dictionary fields tree if not already done
	if (!dict->fields) {
		dict->fields = wmem_tree_new(wmem_epan_scope());
	}

	// Initialize dictionary protocols tree if not already done
	if (!dict->protocols) {
		dict->protocols = wmem_tree_new(wmem_epan_scope());
	}

	// Parse XML file
	doc = xmlReadFile(filename, NULL, 0);
	if (!doc) {
		report_failure("JSON Dictionary: Could not parse file: %s\n", filename);
		return false;
	}

	/* Get root element */
	root = xmlDocGetRootElement(doc);
	if (!root) {
		report_failure("JSON Dictionary: Empty document: %s\n", filename);
		xmlFreeDoc(doc);
		return false;
	}

	// Check root element name
	if (xmlStrcmp(root->name, (const xmlChar *)XML_ELEMENT_DICTIONARY) != 0) {
		report_failure("JSON Dictionary: Root element is not '%s': %s\n",
			XML_ELEMENT_DICTIONARY, filename);
		xmlFreeDoc(doc);
		return false;
	}

	// Find <base> element
	for (node = root->children; node != NULL; node = node->next) {
		if (node->type != XML_ELEMENT_NODE) {
			continue;
		}

		if (xmlStrcmp(node->name, (const xmlChar *)XML_ELEMENT_BASE) != 0) {
			continue;
		}

		// Process elements within <base>
		for (child = node->children; child != NULL; child = child->next) {
			if (child->type != XML_ELEMENT_NODE) {
				continue;
			}

			if (xmlStrcmp(child->name, (const xmlChar *)XML_ELEMENT_TYPEDEFN) == 0) {
				// Type definition
				dict_type_def_t *type_def = process_typedefn(child);
				if (type_def) {
					if (!type_definitions) {
						type_definitions = g_hash_table_new_full(
							g_str_hash, g_str_equal,
							NULL, (GDestroyNotify)dict_type_def_free);
					}
					g_hash_table_insert(type_definitions,
						(void *)type_def->type_name, type_def);
				}
			}
			else if (xmlStrcmp(child->name, (const xmlChar *)XML_ELEMENT_PROTOCOL) == 0) {
				/* Protocol definition */
				dict_protocol_def_t *proto_def = process_protocol(child);
				if (proto_def) {
					protocol_defs = g_slist_append(protocol_defs, proto_def);
				}
			}
			else if (xmlStrcmp(child->name, (const xmlChar *)XML_ELEMENT_FIELD) == 0) {
				/* Field definition */
				dict_field_def_t *field_def = process_field(child, NULL, false);
				if (field_def) {
					field_defs = g_slist_append(field_defs, field_def);
				}
			}
		}

		break;  // Only process first <base> element
	}

	/* Create json_field_t structures and register header fields */
	for (GSList *elem = field_defs; elem; elem = elem->next) {
		dict_field_def_t *field_def = (dict_field_def_t *)elem->data;
		create_json_field(field_def, hf_array, ett_array, dict, type_definitions);
	}

	// Process protocol definitions
	for (GSList *elem = protocol_defs; elem; elem = elem->next) {
		dict_protocol_def_t *proto_def = (dict_protocol_def_t *)elem->data;
		json_protocol_t *proto;

		proto = wmem_new(wmem_epan_scope(), json_protocol_t);
		proto->name = proto_def->name ? wmem_strdup(wmem_epan_scope(), (const char *)proto_def->name) : NULL;
		proto->display_name = proto_def->display_name ? wmem_strdup(wmem_epan_scope(), (const char *)proto_def->display_name) : NULL;
		proto->port = 0;
		proto->transport = proto_def->transport ? wmem_strdup(wmem_epan_scope(), (const char *)proto_def->transport) : NULL;
		proto->content_types = NULL;
		proto->path_regex = NULL;
		proto->path_case_sensitive = false;
		proto->port_list = NULL;
		proto->fields = NULL;
		proto->has_case_insensitive_fields = false;
		proto->hf_proto_present = -1;

		/* Register a filterable FT_BOOLEAN field "json.<sanitized-name>"
		 * so users can filter packets by matched protocol. */
		if (proto->name) {
			char *suffix = sanitize_protocol_filter_name(proto->name);
			if (suffix) {
				char *abbrev = wmem_strdup_printf(wmem_epan_scope(),
								  "json.%s", suffix);
				char *label = wmem_strdup_printf(wmem_epan_scope(),
								 "JSON+ Protocol: %s", proto->name);
				hf_register_info proto_hf = {
					&proto->hf_proto_present,
					{ label, abbrev,
					  FT_BOOLEAN, BASE_NONE, NULL, 0,
					  "Set when this JSON+ protocol matched dispatch", HFILL }
				};
				wmem_array_append_one(hf_array, proto_hf);
			}
		}

		/* condition= defaults to "or"; require_all=true only when the user
		 * explicitly sets condition="and". */
		proto->require_all =
			(proto_def->condition_attr &&
			 xmlStrcasecmp(proto_def->condition_attr,
				       (const xmlChar *)"and") == 0);

		// Any protocol entry (even one with no port and a failed regex) signals
		// "the user wants protocol-gated dispatch" → enable gating.
		dict->has_any_protocol = true;

		// Track every protocol for shutdown cleanup of non-wmem fields.
		dict->all_protocols = g_slist_prepend(dict->all_protocols, proto);

		// Store protocol in dictionary under all specified ports, and also
		// record the port list on the protocol itself so dispatch can verify
		// "is this protocol bound to port N?" in AND mode.
		for (GSList *port_elem = proto_def->ports; port_elem; port_elem = port_elem->next) {
			unsigned *port_ptr = (unsigned *)port_elem->data;
			if (port_ptr && *port_ptr > 0) {
				wmem_tree_insert32(dict->protocols, *port_ptr, proto);
				unsigned *p = wmem_new(wmem_epan_scope(), unsigned);
				*p = *port_ptr;
				proto->port_list = g_slist_prepend(proto->port_list, p);
			}
		}

		// Compile path regex and register for HTTP/2 :path-based dispatch.
		// path_regex is heap-allocated (not wmem) and is freed by
		// json_dictionary_cleanup() at shutdown.
		if (proto_def->path) {
			/* Default to case-sensitive, matching the existing <field>
			 * behavior at lines 558-559 ("default to case-sensitive").
			 * Only an explicit case="insensitive" flips it. */
			proto->path_case_sensitive =
				!(proto_def->case_attr &&
				  xmlStrcasecmp(proto_def->case_attr,
						(const xmlChar *)"insensitive") == 0);
			unsigned re_flags = WS_REGEX_NEVER_UTF;
			if (!proto->path_case_sensitive) {
				re_flags |= WS_REGEX_CASELESS;
			}
			char *errmsg = NULL;
			proto->path_regex = ws_regex_compile_ex(
				(const char *)proto_def->path, -1, &errmsg, re_flags);
			if (proto->path_regex) {
				dict->path_matchers = g_slist_append(dict->path_matchers, proto);
			} else {
				ws_warning("JSON dictionary: failed to compile path regex "
					   "for protocol \"%s\" (pattern=\"%s\"): %s",
					   proto->name ? proto->name : "(unnamed)",
					   (const char *)proto_def->path,
					   errmsg ? errmsg : "unknown error");
				g_free(errmsg);
			}
		}
	}

	/* Populate per-protocol scoped field trees for this file.
	 * Only runs when the file defined both protocols and fields.
	 * Fields from files with no <protocol> stay global-only (strict isolation). */
	if (protocol_defs && field_defs) {
		int n_protos = g_slist_length(protocol_defs);
		GSList *file_protocols = NULL;
		GSList *ap = dict->all_protocols;
		for (int i = 0; i < n_protos && ap; i++, ap = ap->next)
			file_protocols = g_slist_prepend(file_protocols, ap->data);

		for (GSList *pe = file_protocols; pe; pe = pe->next) {
			json_protocol_t *proto = (json_protocol_t *)pe->data;
			proto->fields = wmem_tree_new(wmem_epan_scope());
			proto->has_case_insensitive_fields = false;
		}

		for (GSList *fe = field_defs; fe; fe = fe->next)
			populate_protocol_field_trees(
				(dict_field_def_t *)fe->data, file_protocols, dict);

		g_slist_free(file_protocols);
	}

	success = true;

	// Cleanup
	g_slist_free_full(field_defs, (GDestroyNotify)dict_field_def_free);
	g_slist_free_full(protocol_defs, (GDestroyNotify)dict_protocol_def_free);

	// Free local type definitions
	if (type_definitions) {
		g_hash_table_destroy(type_definitions);
	}

	xmlFreeDoc(doc);

	return success;
}

// Load JSON dictionaries from a single directory: read config.txt and the
// XML files it lists, falling back to jsonmain.xml when there is no
// config.txt. Returns true if any file loaded (or if the dir was empty,
// in which case the loader is operating in "generic mode" for that dir).
// Returns false if the directory itself does not exist or could not be
// resolved — callers can treat that as "nothing to load here".
static bool
load_json_dictionary_from_dir(const char *dict_dir,
			      wmem_array_t *hf_array, GPtrArray *ett_array,
			      json_dictionary_t *dict)
{
	char *config_file;
	char *dict_file;
	FILE *fp;
	char line[1024];
	bool success = false;
	int loaded_count = 0;

	if (!dict_dir) {
		return false;
	}

	// Try to load config file
	config_file = wmem_strdup_printf(NULL, "%s%c%s",
		dict_dir, G_DIR_SEPARATOR, "config.txt");

	if (file_exists(config_file)) {
		fp = ws_fopen(config_file, "r");
		if (fp) {
			while (fgets(line, sizeof(line), fp)) {
				char *trimmed = line;
				char *end;

				// Trim leading whitespace
				while (*trimmed == ' ' || *trimmed == '\t' || *trimmed == '\r' || *trimmed == '\n') {
					trimmed++;
				}

				// Skip comments and empty lines
				if (*trimmed == '#' || *trimmed == '\0') {
					continue;
				}

				// Trim trailing whitespace and newline
				end = trimmed + strlen(trimmed) - 1;
				while (end > trimmed && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
					*end = '\0';
					end--;
				}

				// Skip if empty after trimming
				if (*trimmed == '\0') {
					continue;
				}

				// Build full path to dictionary file
				dict_file = wmem_strdup_printf(NULL, "%s%c%s",
					dict_dir, G_DIR_SEPARATOR, trimmed);

				if (file_exists(dict_file)) {
					if (parse_dictionary_file(dict_file, hf_array, ett_array, dict)) {
						loaded_count++;
						success = true;
					} else {
						ws_message("JSON Dictionary: Failed to parse %s", trimmed);
					}
				} else {
					ws_message("JSON Dictionary: File not found: %s", trimmed);
				}

				wmem_free(NULL, dict_file);
			}

			fclose(fp);

			if (loaded_count == 0) {
				ws_message("JSON Dictionary: No dictionary files loaded from %s (using generic mode)", dict_dir);
				success = true;  // just means generic mode
			}
		} else {
			ws_message("JSON Dictionary: Could not open config file: %s", config_file);
		}
	} else {
		// No config file try jsonmain.xml
		dict_file = wmem_strdup_printf(NULL, "%s%c%s",
			dict_dir, G_DIR_SEPARATOR, "jsonmain.xml");

		if (file_exists(dict_file)) {
			success = parse_dictionary_file(dict_file, hf_array, ett_array, dict);
		} else {
			ws_message("JSON Dictionary: No config.txt or jsonmain.xml in %s (using generic mode)", dict_dir);
			success = true;  // generic mode
		}

		wmem_free(NULL, dict_file);
	}

	wmem_free(NULL, config_file);
	return success;
}

// Load JSON dictionary from XML files
// Main entry point called during protocol registration.
//
// Reads from two directories:
//   1. System data dir (e.g. /usr/share/wireshark/json/) — shipped with
//      Wireshark, overwritten on install/upgrade.
//   2. Personal config dir (e.g. ~/.config/wireshark/json/) — opt-in,
//      created by the user, survives upgrades.
//
// The personal dir is loaded second so its entries take precedence on
// collisions (last-loaded-wins for ports, via wmem_tree_insert32).
// The personal dir is silently skipped when it does not exist.
//
// Mirrors the pattern used by packet-radius.c (see lines around 2802).
bool
load_json_dictionary(wmem_array_t *hf_array, GPtrArray *ett_array,
		     json_dictionary_t *dict)
{
	bool any_loaded = false;

	/* System dictionary directory. */
	char *system_dir = get_datafile_path("json", NULL);
	if (system_dir) {
		any_loaded |= load_json_dictionary_from_dir(system_dir,
			hf_array, ett_array, dict);
		g_free(system_dir);
	} else {
		report_failure("JSON Dictionary: Could not get system dictionary directory\n");
	}

	/* Personal dictionary directory. Opt-in — silently skipped when the
	 * user has not created it. */
	char *personal_dir = get_persconffile_path("json", false, NULL);
	if (personal_dir) {
		if (file_exists(personal_dir)) {
			any_loaded |= load_json_dictionary_from_dir(personal_dir,
				hf_array, ett_array, dict);
		}
		g_free(personal_dir);
	}

	return any_loaded;
}

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
