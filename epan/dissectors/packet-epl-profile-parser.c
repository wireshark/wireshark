/* packet-epl-profile-parser.c
 * Routines for reading in Ethernet POWERLINK XDD and CANopen EDS profiles
 * (Ethernet POWERLINK XML Device Description (DS301) Draft Standard v1.2.0)
 *
 * Copyright (c) 2017: Karlsruhe Institute of Technology (KIT)
 *                     Institute for Anthropomatics and Robotics (IAR)
 *                     Intelligent Process Control and Robotics (IPR)
 *                     http://rob.ipr.kit.edu/
 *
 *                     - Ahmad Fatoum <ahmad[AT]a3f.at>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "packet-epl.h"
#include "ws_attributes.h"

#include <wsutil/ws_printf.h>
#include <epan/range.h>

#include <string.h>
#include <stdlib.h>

#include <wsutil/strtoi.h>
#include <wsutil/str_util.h>
#include <epan/wmem/wmem.h>

#if defined HAVE_LIBXML2
#include <libxml/xmlversion.h>

#if defined LIBXML_XPATH_ENABLED \
&&  defined LIBXML_SAX1_ENABLED  \
&&  defined LIBXML_TREE_ENABLED
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#define PARSE_XDD 1

typedef int xpath_handler(xmlNodeSetPtr, void*);
static xpath_handler populate_object_list, populate_datatype_list, populate_profile_name;

static struct xpath_namespace {
	const xmlChar *prefix, *href;
} namespaces[] = {
	{ BAD_CAST "x",   BAD_CAST "http://www.ethernet-powerlink.org" },
	{ BAD_CAST "xsi", BAD_CAST "http://www.w3.org/2001/XMLSchema-instance" },
	{ NULL, NULL }
};

static struct xpath {
	const xmlChar *expr;
	xpath_handler *handler;
} xpaths[] = {
	{
		BAD_CAST "//x:ISO15745Profile[x:ProfileHeader/x:ProfileIdentification='Powerlink_Communication_Profile']/x:ProfileHeader/x:ProfileName",
		populate_profile_name
	},
	{
		BAD_CAST "//x:ProfileBody[@xsi:type='ProfileBody_CommunicationNetwork_Powerlink']/x:ApplicationLayers/x:DataTypeList/x:defType",
		populate_datatype_list
	},
	{
		BAD_CAST "//x:ProfileBody[@xsi:type='ProfileBody_CommunicationNetwork_Powerlink']/x:ApplicationLayers/x:ObjectList/x:Object",
		populate_object_list
	},
	{ NULL, NULL }
};


#endif /* LIBXML_XPATH_ENABLED && LIBXML_SAX1_ENABLED && LIBXML_TREE_ENABLED */

#endif /* HAVE_LIBXML2 */

struct datatype {
	guint16 id;
	const struct epl_datatype *ptr;
};

static struct typemap_entry {
	guint16 id;
	const char *name;
	struct epl_datatype *type;
} epl_datatypes[] = {
	{0x0001, "Boolean",        NULL},
	{0x0002, "Integer8",       NULL},
	{0x0003, "Integer16",      NULL},
	{0x0004, "Integer32",      NULL},
	{0x0005, "Unsigned8",      NULL},
	{0x0006, "Unsigned16",     NULL},
	{0x0007, "Unsigned32",     NULL},
	{0x0008, "Real32",         NULL},
	{0x0009, "Visible_String", NULL},
	{0x0010, "Integer24",      NULL},
	{0x0011, "Real64",         NULL},
	{0x0012, "Integer40",      NULL},
	{0x0013, "Integer48",      NULL},
	{0x0014, "Integer56",      NULL},
	{0x0015, "Integer64",      NULL},
	{0x000A, "Octet_String",   NULL},
	{0x000B, "Unicode_String", NULL},
	{0x000C, "Time_of_Day",    NULL},
	{0x000D, "Time_Diff",      NULL},
	{0x000F, "Domain",         NULL},
	{0x0016, "Unsigned24",     NULL},
	{0x0018, "Unsigned40",     NULL},
	{0x0019, "Unsigned48",     NULL},
	{0x001A, "Unsigned56",     NULL},
	{0x001B, "Unsigned64",     NULL},
	{0x0401, "MAC_ADDRESS",    NULL},
	{0x0402, "IP_ADDRESS",     NULL},
	{0x0403, "NETTIME",        NULL},
	{0x0000, NULL,		   NULL}
};

static wmem_map_t *eds_typemap;

struct epl_wmem_iarray {
	GEqualFunc equal;
	wmem_allocator_t *scope;
	GArray *arr;
	guint cb_id;
	guint8 is_sorted :1;
};

static epl_wmem_iarray_t *epl_wmem_iarray_new(wmem_allocator_t *allocator, const guint elem_size, GEqualFunc cmp) G_GNUC_MALLOC;
static void epl_wmem_iarray_insert(epl_wmem_iarray_t *iarr, guint32 where, range_admin_t *data);
static void epl_wmem_iarray_sort_and_compact(epl_wmem_iarray_t *iarr);

static gboolean
epl_ishex(const char *num)
{
	if (g_str_has_prefix(num, "0x"))
		return TRUE;

	for (; g_ascii_isxdigit(*num); num++)
		;

	if (g_ascii_tolower(*num) == 'h')
		return TRUE;

	return FALSE;
}

static guint16
epl_g_key_file_get_uint16(GKeyFile *gkf, const gchar *group_name, const gchar *key, GError **error)
{
	guint16 ret = 0;
	const char *endptr;
	char *val = g_key_file_get_string(gkf, group_name, key, error);

	if (!val)
		return 0;

	if (epl_ishex(val)) /* We need to support XXh, but no octals (is that right?) */
		ws_hexstrtou16(val, &endptr, &ret);
	else
		ws_strtou16(val, &endptr, &ret);

	g_free(val);
	return ret;
}

static void
sort_subindices(void *key _U_, void *value, void *user_data _U_)
{
	epl_wmem_iarray_t *subindices = ((struct object*)value)->subindices;
	if (subindices)
		epl_wmem_iarray_sort_and_compact(subindices);
}

void
epl_eds_init(void)
{
	struct typemap_entry *entry;
	eds_typemap = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);
	for (entry = epl_datatypes; entry->name; entry++)
	{
		const struct epl_datatype *type = epl_type_to_hf(entry->name);
		wmem_map_insert(eds_typemap, GUINT_TO_POINTER(entry->id), (void*)type);
	}
}

struct profile *
epl_eds_load(struct profile *profile, const char *eds_file)
{
	GKeyFile* gkf;
	GError *err;
	char **group, **groups;
	char *val;
	gsize groups_count;

	gkf = g_key_file_new();

	/* Load EDS document */
	if (!g_key_file_load_from_file(gkf, eds_file, G_KEY_FILE_NONE, &err)){
		g_log(NULL, G_LOG_LEVEL_WARNING, "Error: unable to parse file \"%s\"\n", eds_file);
		profile = NULL;
		goto cleanup;
	}

	profile->path = wmem_strdup(profile->scope, eds_file);

	val = g_key_file_get_string(gkf, "FileInfo", "Description", NULL);
	/* This leaves a trailing space, but that's ok */
	profile->name = wmem_strndup(profile->scope, val, strcspn(val, "#"));
	g_free(val);

	groups = g_key_file_get_groups(gkf, &groups_count);
	for (group = groups; *group; group++)
	{
		char *name;
		const char *endptr;
		guint16 idx = 0, datatype;
		struct object *obj = NULL;
		struct od_entry tmpobj = OD_ENTRY_INITIALIZER;
		gboolean is_object = TRUE;

		if (!g_ascii_isxdigit(**group))
			continue;

		ws_hexstrtou16(*group, &endptr, &idx);
		if (*endptr == '\0')
		{ /* index */
			tmpobj.idx = idx;
		}
		else if (g_str_has_prefix(endptr, "sub"))
		{ /* subindex */
			if (!ws_hexstrtou16(endptr + 3, &endptr, &tmpobj.idx)
			|| tmpobj.idx > 0xFF)
				continue;

			is_object = FALSE;
		}
		else continue;

		tmpobj.type_class = epl_g_key_file_get_uint16(gkf, *group, "ObjectType", NULL);
		if (!tmpobj.type_class)
			continue;

		datatype = epl_g_key_file_get_uint16(gkf, *group, "DataType", NULL);
		if (datatype)
			tmpobj.type = (const struct epl_datatype*)wmem_map_lookup(eds_typemap, GUINT_TO_POINTER(datatype));

		if ((name = g_key_file_get_string(gkf, *group, "ParameterName", NULL)))
		{
			gsize count = strcspn(name, "#") + 1;
			g_strlcpy(
				tmpobj.name,
				name,
				count > sizeof tmpobj.name ? sizeof tmpobj.name : count
			);
			g_free(name);
		}

		obj = epl_profile_object_lookup_or_add(profile, idx);

		if (is_object)
		{ /* Let's add a new object! Exciting! */
			obj->info = tmpobj;
		}
		else
		{ /* Object already there, let's add subindices */
			struct subobject subobj = SUBOBJECT_INITIALIZER;

			if (!obj->subindices)
			{
				obj->subindices = epl_wmem_iarray_new(
							profile->scope,
							sizeof (struct subobject),
							subobject_equal
				);
			}

			subobj.info = tmpobj;
			epl_wmem_iarray_insert(obj->subindices, subobj.info.idx, &subobj.range);
		}
	}

	/* Unlike with XDDs, subindices might interleave with others, so let's sort them now */
	wmem_map_foreach(profile->objects, sort_subindices, NULL);

	/* We don't read object mappings from EDS files */
	/* epl_profile_object_mappings_update(profile); */

cleanup:
	g_key_file_free(gkf);
	return profile;
}

#ifdef PARSE_XDD

struct profile *
epl_xdd_load(struct profile *profile, const char *xml_file)
{
	xmlXPathContextPtr xpathCtx = NULL;
	xmlDoc *doc = NULL;
	struct xpath_namespace *ns = NULL;
	struct xpath *xpath = NULL;
	GHashTable *typemap = NULL;

	/* Load XML document */
	doc = xmlParseFile(xml_file);
	if (!doc)
	{
		g_log(NULL, G_LOG_LEVEL_WARNING, "Error: unable to parse file \"%s\"\n", xml_file);
		profile = NULL;
		goto cleanup;
	}


	/* Create xpath evaluation context */
	xpathCtx = xmlXPathNewContext(doc);
	if(!xpathCtx)
	{
		g_log(NULL, G_LOG_LEVEL_WARNING, "Error: unable to create new XPath context\n");
		profile = NULL;
		goto cleanup;
	}

	/* Register namespaces from list */
	for (ns = namespaces; ns->href; ns++)
	{
		if(xmlXPathRegisterNs(xpathCtx, ns->prefix, ns->href) != 0)
		{
			g_log(NULL, G_LOG_LEVEL_WARNING, "Error: unable to register NS with prefix=\"%s\" and href=\"%s\"\n", ns->prefix, ns->href);
			profile = NULL;
			goto cleanup;
		}
	}

	profile->path = wmem_strdup(profile->scope, xml_file);

	/* mapping type ids to &hf_s */
	profile->data = typemap = (GHashTable*)g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);

	/* Evaluate xpath expressions */
	for (xpath = xpaths; xpath->expr; xpath++)
	{
		xmlXPathObjectPtr xpathObj = xmlXPathEvalExpression(xpath->expr, xpathCtx);
		if (!xpathObj || !xpathObj->nodesetval)
		{
			g_log(NULL, G_LOG_LEVEL_WARNING, "Error: unable to evaluate xpath expression \"%s\"\n", xpath->expr);
			xmlXPathFreeObject(xpathObj);
			profile = NULL;
			goto cleanup;
		}

		/* run handler */
		if (xpath->handler && xpathObj->nodesetval->nodeNr)
			xpath->handler(xpathObj->nodesetval, profile);
		xmlXPathFreeObject(xpathObj);
	}

	/* We create ObjectMappings while reading the XML, this is makes it likely,
	 * that we won't be able to reference a mapped object in the ObjectMapping
	 * as we didn't reach its XML tag yet. Therefore, after reading the XDD
	 * completely, we update mappings in the profile
	 */
	epl_profile_object_mappings_update(profile);

cleanup:
	if (typemap)
		g_hash_table_destroy(typemap);

	if (xpathCtx)
		xmlXPathFreeContext(xpathCtx);
	if (doc)
		xmlFreeDoc(doc);

	return profile;
}

static int
populate_profile_name(xmlNodeSetPtr nodes, void *_profile)
{
	struct profile *profile = (struct profile*)_profile;
	if (nodes->nodeNr == 1
	&&  nodes->nodeTab[0]->type == XML_ELEMENT_NODE
	&&  nodes->nodeTab[0]->children)
	{
		profile->name = wmem_strdup(profile->scope, (char*)nodes->nodeTab[0]->children->content);
		return 0;
	}

	return -1;
}

static int
populate_datatype_list(xmlNodeSetPtr nodes, void *_profile)
{
	xmlNodePtr cur;
	int i;
	struct profile *profile = (struct profile*)_profile;

	for(i = 0; i < nodes->nodeNr; ++i)
	{
		xmlAttrPtr attr;

		if(!nodes->nodeTab[i] || nodes->nodeTab[i]->type != XML_ELEMENT_NODE)
			return -1;

		cur = nodes->nodeTab[i];


		for(attr = cur->properties; attr; attr = attr->next)
		{
			const char *endptr;
			const char *key = (const char*)attr->name;
			const char *val = (const char*)attr->children->content;

			if (g_str_equal("dataType", key))
			{
				xmlNode *subnode;
				guint16 idx = 0;

				if (!ws_hexstrtou16(val, &endptr, &idx))
					continue;

				for (subnode = cur->children; subnode; subnode = subnode->next)
				{
					if (subnode->type == XML_ELEMENT_NODE)
					{
						struct datatype *type;
						const struct epl_datatype *ptr = epl_type_to_hf((const char*)subnode->name);
						if (!ptr)
						{
							g_log(NULL, G_LOG_LEVEL_INFO, "Skipping unknown type '%s'\n", subnode->name);
							continue;
						}
						type = g_new(struct datatype, 1);
						type->id = idx;
						type->ptr = ptr;
						g_hash_table_insert((GHashTable*)profile->data, GUINT_TO_POINTER(type->id), type);
						continue;
					}
				}

			}
		}
	}

	return 0;
}

static gboolean
parse_obj_tag(xmlNode *cur, struct od_entry *out, struct profile *profile) {
		xmlAttrPtr attr;
		const char *defaultValue = NULL, *actualValue = NULL;
		const char *endptr;

		for(attr = cur->properties; attr; attr = attr->next)
		{
			const char *key = (const char*)attr->name,
			           *val = (const char*)attr->children->content;

			if (g_str_equal("index", key))
			{
				if (!ws_hexstrtou16(val, &endptr, &out->idx))
					return FALSE;

			} else if (g_str_equal("subIndex", key)) {
				if (!ws_hexstrtou16(val, &endptr, &out->idx))
					return FALSE;

			} else if (g_str_equal("name", key)) {
				g_strlcpy(out->name, val, sizeof out->name);

			} else if (g_str_equal("objectType", key)) {
				out->type_class = 0;
				ws_hexstrtou16(val, &endptr, &out->type_class);

			} else if (g_str_equal("dataType", key)) {
				guint16 id;
				if (ws_hexstrtou16(val, &endptr, &id))
				{
					struct datatype *type = (struct datatype*)g_hash_table_lookup((GHashTable*)profile->data, GUINT_TO_POINTER(id));
					if (type) out->type = type->ptr;
				}

			} else if (g_str_equal("defaultValue", key)) {
				defaultValue = val;

			} else if (g_str_equal("actualValue", key)) {
				actualValue = val;
			}
#if 0
			else if (g_str_equal("PDOmapping", key)) {
			  obj.PDOmapping = get_index(ObjectPDOmapping_tostr, val);
			  assert(obj.PDOmapping >= 0);
			}
#endif
		}

		if (actualValue)
			out->value =  g_ascii_strtoull(actualValue, NULL, 0);
		else if (defaultValue)
			out->value =  g_ascii_strtoull(defaultValue, NULL, 0);
		else
			out->value = 0;


		return TRUE;
}

static int
populate_object_list(xmlNodeSetPtr nodes, void *_profile)
{
	int i;
	struct profile *profile = (struct profile*)_profile;

	for(i = 0; i < nodes->nodeNr; ++i)
	{
		xmlNodePtr cur = nodes->nodeTab[i];
		struct od_entry tmpobj = OD_ENTRY_INITIALIZER;

		if (!nodes->nodeTab[i] || nodes->nodeTab[i]->type != XML_ELEMENT_NODE)
			continue;

		parse_obj_tag(cur, &tmpobj, profile);

		if (tmpobj.idx)
		{
			struct object *obj = epl_profile_object_add(profile, tmpobj.idx);
			obj->info = tmpobj;

			if (tmpobj.type_class == OD_ENTRY_ARRAY || tmpobj.type_class == OD_ENTRY_RECORD)
			{
				xmlNode *subcur;
				struct subobject subobj = SUBOBJECT_INITIALIZER;

				obj->subindices = epl_wmem_iarray_new(profile->scope, sizeof (struct subobject), subobject_equal);

				for (subcur = cur->children; subcur; subcur = subcur->next)
				{
					if (subcur->type != XML_ELEMENT_NODE)
						continue;

					if (parse_obj_tag(subcur, &subobj.info, profile))
					{
						epl_wmem_iarray_insert(obj->subindices,
									subobj.info.idx, &subobj.range);
					}
					if (subobj.info.value && epl_profile_object_mapping_add(
					    profile, obj->info.idx, (guint8)subobj.info.idx, subobj.info.value))
					{
						g_log(NULL, G_LOG_LEVEL_INFO,
						"Loaded mapping from XDC %s:%s", obj->info.name, subobj.info.name);
					}
				}
				epl_wmem_iarray_sort_and_compact(obj->subindices);
			}
		}
	}

	return 0;
}


#else  /* ! PARSE_XDD */

#ifdef HAVE_LIBXML2
struct profile *
epl_xdd_load(struct profile *profile _U_, const char *xml_file _U_)
{
	return NULL;
}
#endif  /* HAVE_LIBXML2 */

#endif  /* ! PARSE_XDD */

/**
 * A sorted array keyed by intervals
 * You keep inserting items, then sort the array.
 * sorting also combines items that compare equal into one and adjusts
 * the interval accordingly. find uses binary search to find the item
 *
 * This is particularly useful, if many similar items exist adjacent to each other
 * e.g. ObjectMapping subindices in EPL XDD (packet-epl-profile-parser.c)
 *
 * Interval Trees wouldn't work for this scenario, because they don't allow
 * expansion of existing intervals. Using an array instead of a tree,
 * may additionally offer a possible performance advantage

 * Much room for optimization in the creation process of the array,
 * but we assume this to be an infrequent operation, with space utilization and
 * finding speed being more important.
 */


static gboolean
free_garray(wmem_allocator_t *scope _U_, wmem_cb_event_t event _U_, void *data)
{
	GArray *arr = (GArray*)data;
	g_array_free(arr, TRUE);
	return FALSE;
}

/**
 * \param scope wmem pool to use
 * \param elem_size size of elements to add into the iarray
 * \param equal establishes whether two adjacent elements are equal and thus
 *            shall be combined at sort-time
 *
 * \returns a new interval array or NULL on failure
 *
 * Creates a new interval array.
 * Elements must have a range_admin_t as their first element,
 * which will be managed by the implementation.
 * \NOTE The cmp parameter can be used to free resources. When combining,
 * it's always the second argument that's getting removed.
 */

static epl_wmem_iarray_t *
epl_wmem_iarray_new(wmem_allocator_t *scope, const guint elem_size, GEqualFunc equal)
{
	epl_wmem_iarray_t *iarr;

	if (elem_size < sizeof(range_t)) return NULL;

	iarr = wmem_new(scope, epl_wmem_iarray_t);
	if (!iarr) return NULL;

	iarr->equal = equal;
	iarr->scope = scope;
	iarr->arr = g_array_new(FALSE, FALSE, elem_size);
	iarr->is_sorted = TRUE;

	wmem_register_callback(scope, free_garray, iarr->arr);

	return iarr;
}


/** Returns true if the iarr is empty. */
gboolean
epl_wmem_iarray_is_empty(epl_wmem_iarray_t *iarr)
{
	return iarr->arr->len == 0;
}

/** Returns true if the iarr is sorted. */
gboolean
epl_wmem_iarray_is_sorted(epl_wmem_iarray_t *iarr)
{
	return iarr->is_sorted;
}

/** Inserts an element */
static void
epl_wmem_iarray_insert(epl_wmem_iarray_t *iarr, guint32 where, range_admin_t *data)
{
	if (iarr->arr->len)
		iarr->is_sorted = FALSE;

	data->high = data->low = where;
	g_array_append_vals(iarr->arr, data, 1);
}

static int u32cmp(guint32 a, guint32 b)
{
	if (a < b) return -1;
	if (a > b) return +1;

	return 0;
}

static int
epl_wmem_iarray_cmp(const void *a, const void *b)
{
	return u32cmp(*(const guint32*)a, *(const guint32*)b);
}

/** Makes array suitable for searching */
static void
epl_wmem_iarray_sort_and_compact(epl_wmem_iarray_t *iarr)
{
	range_admin_t *elem, *prev = NULL;
	guint i, len;
	len = iarr->arr->len;
	if (iarr->is_sorted)
		return;

	g_array_sort(iarr->arr, epl_wmem_iarray_cmp);
	prev = elem = (range_admin_t*)iarr->arr->data;

	for (i = 1; i < len; i++) {
		elem = (range_admin_t*)((char*)elem + g_array_get_element_size(iarr->arr));

		/* neighbours' range must be within one of each other and their content equal */
		while (i < len && elem->low - prev->high <= 1 && iarr->equal(elem, prev)) {
			prev->high = elem->high;

			g_array_remove_index(iarr->arr, i);
			len--;
		}
		prev = elem;
	}

	iarr->is_sorted = 1;
}

static int
find_in_range(const void *_a, const void *_b)
{
	const range_admin_t *a = (const range_admin_t*)_a,
	                    *b = (const range_admin_t*)_b;

	if (a->low <= b->high && b->low <= a->high) /* overlap */
		return 0;

	return u32cmp(a->low, b->low);
}

static void*
bsearch_garray(const void *key, GArray *arr, int (*cmp)(const void*, const void*))
{
	return bsearch(key, arr->data, arr->len, g_array_get_element_size(arr), cmp);
}

/*
 * Finds an element in the interval array. Returns NULL if it doesn't exist
 * Calling this is unspecified if the array wasn't sorted before
 */
range_admin_t *
epl_wmem_iarray_find(epl_wmem_iarray_t *iarr, guint32 value) {
	epl_wmem_iarray_sort_and_compact(iarr);

	range_admin_t needle;
	needle.low  = value;
	needle.high = value;
	return (range_admin_t*)bsearch_garray(&needle, iarr->arr, find_in_range);
}

#if 0
void
epl_wmem_print_iarr(epl_wmem_iarray_t *iarr)
{
	range_admin_t *elem;
	guint i, len;
	elem = (range_admin_t*)iarr->arr->data;
	len = iarr->arr->len;
	for (i = 0; i < len; i++)
	{

		ws_debug_printf("Range: low=%" G_GUINT32_FORMAT " high=%" G_GUINT32_FORMAT "\n", elem->low, elem->high);

		elem = (range_admin_t*)((char*)elem + g_array_get_element_size(iarr->arr));
	}
}
#endif

/*
 * Editor modelines  -	https://www.wireshark.org/tools/modelines.html
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
