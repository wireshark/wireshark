/* protobuf_lang_tree.c
 *
 * Routines of building and reading Protocol Buffers Language grammar tree.
 * Copyright 2019, Huang Qiangxiong <qiangxiong.huang@qq.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include "protobuf_lang_tree.h"
#include "protobuf-helper.h" /* only for PROTOBUF_TYPE_XXX enumeration */

extern int
pbl_get_current_lineno(void* scanner);

extern void
pbl_parser_error(protobuf_lang_state_t *state, const char *fmt, ...);

/**
 Reinitialize the protocol buffers pool according to proto files directories.
 @param ppool The output descriptor_pool will be created. If *pool is not NULL, it will free it first.
 @param directories  The root directories containing proto files. Must end with NULL element.
 @param error_cb The error reporter callback function.
 */
void
pbl_reinit_descriptor_pool(pbl_descriptor_pool_t** ppool, const char** directories, pbl_report_error_cb_t error_cb)
{
    guint i;

    pbl_free_pool(*ppool);
    pbl_descriptor_pool_t* p = g_new0(pbl_descriptor_pool_t, 1);

    for (i = 0; directories[i] != NULL; i++) {
        p->source_paths = g_slist_append(p->source_paths, g_strdup(directories[i]));
    }

    p->error_cb = error_cb ? error_cb : pbl_printf;
    p->packages = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, pbl_free_node);
    p->proto_files = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    p->proto_files_to_be_parsed = NULL;

    *ppool = p;
}

/* free all memory used by this protocol buffers languange pool */
void
pbl_free_pool(pbl_descriptor_pool_t* pool)
{
    if (pool == NULL) return;

    g_slist_free_full(pool->source_paths, g_free);
    g_hash_table_destroy(pool->packages);
    g_slist_free(pool->proto_files_to_be_parsed); /* elements will be removed in p->proto_files */
    g_hash_table_destroy(pool->proto_files);

    g_free(pool);
}

/* Canonicalize absolute file path. We only accept path like:
 *     /home/test/protos/example.proto
 *     D:/mydir/test/example.proto
 *     d:\mydir\test\example.proto
 * This function will replace all '\' to '/', and change '//' to '/'.
 * May use _fullpath() in windows or realpath() in *NIX.
 * Return a newly-allocated path, NULL if failed (file
 * does not exist, or file path contains '/../').
 */
static char*
pbl_canonicalize_absolute_filepath(const char* path)
{
    int i, j;
    char* canon_path = g_new(char, strlen(path) + 1);
    /* replace all '\' to '/', and change '//' to '/' */
    for (i = 0, j = 0; path[i] != '\0'; i++) {
        if (path[i] == '\\' || path[i] == '/') {
            if (j > 0 && canon_path[j-1] == '/') {
                /* ignore redundant slash */
            } else {
                canon_path[j++] = '/';
            }
        } else {
#ifdef _WIN32
            canon_path[j++] = g_ascii_tolower(path[i]);
#else
            canon_path[j++] = path[i];
#endif
        }
    }
    canon_path[j] = '\0';

    if (g_path_is_absolute(canon_path)
        && g_file_test(canon_path, G_FILE_TEST_IS_REGULAR)
        && strstr(canon_path, "/../") == NULL) {
        return canon_path;
    } else {
        g_free(canon_path);
        return NULL;
    }
}

/* Add a file into to do list */
gboolean
pbl_add_proto_file_to_be_parsed(pbl_descriptor_pool_t* pool, const char* filepath)
{
    char* path = NULL;
    GSList* it = NULL;
    char* concat_path = NULL;

    /* Try to get the absolute path of the file */
    if (g_path_is_absolute(filepath)) {
        path = pbl_canonicalize_absolute_filepath(filepath);
    }

    if (path == NULL) {
        /* try to concat with source directories */
        for (it = pool->source_paths; it; it = it->next) {
            concat_path = g_build_filename((char*)it->data, filepath, NULL);
            path = pbl_canonicalize_absolute_filepath(concat_path);
            g_free(concat_path);
            if (path) break;
        }
    }

    if (path == NULL) {
        if (pool->parser_state) {
            /* only happened during parsing an 'import' line of a .proto file */
            pbl_parser_error(pool->parser_state, "file [%s] does not exist!\n", filepath);
        } else {
            /* normally happened during initializing a pool by adding files that need be loaded */
            pool->error_cb("Protobuf: file [%s] does not exist!\n", filepath);
        }
        return FALSE;
    }

    if (!g_hash_table_lookup(pool->proto_files, path)) {
        /* create file descriptor info */
        pbl_file_descriptor_t* file = g_new0(pbl_file_descriptor_t, 1);
        file->filename = path;
        file->syntax_version = 2;
        file->package_name = PBL_DEFAULT_PACKAGE_NAME;
        file->pool = pool;

        /* store in hash table and list */
        g_hash_table_insert(pool->proto_files, path, file);
        pool->proto_files_to_be_parsed = g_slist_append(pool->proto_files_to_be_parsed, path);
    } else {
        /* The file is already in the proto_files */
        g_free(path);
    }
    return TRUE;
}

/* find node according to full_name */
static pbl_node_t*
pbl_find_node_in_pool(const pbl_descriptor_pool_t* pool, const char* full_name, pbl_node_type_t nodetype)
{
    char* full_name_buf;
    int len, i;
    pbl_node_t* package;
    pbl_node_t* node = NULL;
    GSList* names = NULL; /* NULL terminated name retrieved from full_name */
    GSList* it = NULL;

    if (pool == NULL || full_name == NULL || pool->packages == NULL) {
        return NULL;
    }

    if (full_name[0] == '.') {
        full_name++; /* skip leading dot */
    }

    full_name_buf = g_strdup(full_name);
    len = (int)strlen(full_name_buf);
    /* scan from end to begin, and replace '.' to '\0' */
    for (i = len-1; i >= 0; i--) {
        if (full_name_buf[i] == '.' || i == 0) {
            if (i == 0) {
                /* no dot any more, we search in default package */
                names = g_slist_prepend(names, full_name_buf);
                package = (pbl_node_t*) g_hash_table_lookup(pool->packages, PBL_DEFAULT_PACKAGE_NAME);
            } else { /* replace middle dot with '\0' */
                /* push name at top of names */
                names = g_slist_prepend(names, full_name_buf + i + 1);
                full_name_buf[i] = 0;
                /* take 0~i of full_name_buf as package name */
                package = (pbl_node_t*) g_hash_table_lookup(pool->packages, full_name_buf);
            }
            if (package) {
                node = package;
                /* search node in this package */
                for (it = names; (it && node && node->children_by_name); it = it->next) {
                    node = (pbl_node_t*) g_hash_table_lookup(node->children_by_name, it->data);
                }

                if (it == NULL && node && node->nodetype == nodetype) {
                    break; /* found */
                }
                node = NULL;
            }
        }
    }

    if (names) {
        g_slist_free(names);
    }
    g_free(full_name_buf);
    return node;
}

/* get the full name of node. if it is NULL, it will be built. */
const char*
pbl_get_node_full_name(pbl_node_t* node)
{
    const char* parent_full_name;
    if (node == NULL
        || node->nodetype == PBL_UNKNOWN
        || node->nodetype == PBL_OPTIONS
        || node->nodetype == PBL_OPTION) {
        return NULL;
    }

    if (node->full_name) {
        return node->full_name;
    }

    if (node->nodetype == PBL_ONEOF) {
        return pbl_get_node_full_name(node->parent);
    }

    if (node->nodetype == PBL_PACKAGE) {
        node->full_name = g_strdup(node->name);
    } else {
        parent_full_name = pbl_get_node_full_name(node->parent);
        if (parent_full_name && parent_full_name[0] != 0) {
            node->full_name = g_strconcat(parent_full_name, ".", node->name, NULL);
        } else {
            node->full_name = g_strdup(node->name);
        }
    }

    return node->full_name;
}

/* try to find node globally or in the context or parents (message or package) of the context */
static const pbl_node_t*
pbl_find_node_in_context(const pbl_node_t* context, const char* name, pbl_node_type_t nodetype)
{
    const pbl_node_t* node = NULL;
    pbl_descriptor_pool_t* pool = NULL;
    char* parent_name;
    char* full_name;

    if (context == NULL || name == NULL) {
        return NULL;
    }

    if (name[0] == '.') {
        /* A leading '.' (for example, .foo.bar.Baz) means to start from the outermost scope. */
        if (context->file && context->file->pool) {
            return pbl_find_node_in_pool(context->file->pool, name, nodetype);
        } else {
            return NULL;
        }
    }

    /* find pool */
    if (context->file) {
        pool = context->file->pool;
    }

    /* try find node in the context or parents (message or package) of the context */
    if (pool) {
        int remaining;
        parent_name = g_strdup(pbl_get_node_full_name((pbl_node_t*) context));
        remaining = (int)strlen(parent_name);
        while (remaining > 0) {
            full_name = g_strconcat(parent_name, ".", name, NULL);
            node = pbl_find_node_in_pool(pool, full_name, nodetype);
            g_free(full_name);
            if (node) {
                g_free(parent_name);
                return node;
            }
            /* scan from end to begin, and replace first '.' to '\0' */
            for (remaining--; remaining > 0; remaining--) {
                if (parent_name[remaining] == '.') {
                    /* found a potential parent node name */
                    parent_name[remaining] = '\0';
                    break; /* break from the 'for' loop, continue 'while' loop */
                }
            }
        }
        g_free(parent_name);

        /* try find node in pool directly */
        return pbl_find_node_in_pool(pool, name, nodetype);
    }

    return NULL;
}

/* like descriptor_pool::FindMethodByName */
const pbl_method_descriptor_t*
pbl_message_descriptor_pool_FindMethodByName(const pbl_descriptor_pool_t* pool, const char* full_name)
{
    pbl_node_t* n = pbl_find_node_in_pool(pool, full_name, PBL_METHOD);
    return n ? (pbl_method_descriptor_t*)n : NULL;
}

/* like MethodDescriptor::name() */
const char*
pbl_method_descriptor_name(const pbl_method_descriptor_t* method)
{
    return pbl_get_node_name((pbl_node_t*)method);
}

/* like MethodDescriptor::full_name() */
const char*
pbl_method_descriptor_full_name(const pbl_method_descriptor_t* method)
{
    return pbl_get_node_full_name((pbl_node_t*)method);
}

/* like MethodDescriptor::input_type() */
const pbl_message_descriptor_t*
pbl_method_descriptor_input_type(const pbl_method_descriptor_t* method)
{
    const pbl_node_t* n = pbl_find_node_in_context((pbl_node_t*)method, method->in_msg_type, PBL_MESSAGE);
    return n ? (const pbl_message_descriptor_t*)n : NULL;
}

/* like MethodDescriptor::output_type() */
const pbl_message_descriptor_t*
pbl_method_descriptor_output_type(const pbl_method_descriptor_t* method)
{
    const pbl_node_t* n = pbl_find_node_in_context((pbl_node_t*)method, method->out_msg_type, PBL_MESSAGE);
    return n ? (const pbl_message_descriptor_t*)n : NULL;
}

/* like descriptor_pool::FindMessageTypeByName() */
const pbl_message_descriptor_t*
pbl_message_descriptor_pool_FindMessageTypeByName(const pbl_descriptor_pool_t* pool, const char* name)
{
    pbl_node_t* n = pbl_find_node_in_pool(pool, name, PBL_MESSAGE);
    return n ? (pbl_message_descriptor_t*)n : NULL;
}

/* like Descriptor::name() */
const char*
pbl_message_descriptor_name(const pbl_message_descriptor_t* message)
{
    return pbl_get_node_name((pbl_node_t*)message);
}

/* like Descriptor::full_name() */
const char*
pbl_message_descriptor_full_name(const pbl_message_descriptor_t* message)
{
    return pbl_get_node_full_name((pbl_node_t*)message);
}

/* like Descriptor::field_count() */
int
pbl_message_descriptor_field_count(const pbl_message_descriptor_t* message)
{
    return (message && message->fields) ? g_slist_length(message->fields) : 0;
}

/* like Descriptor::field() */
const pbl_field_descriptor_t*
pbl_message_descriptor_field(const pbl_message_descriptor_t* message, int field_index)
{
    return (message && message->fields) ? (pbl_field_descriptor_t*) g_slist_nth_data(message->fields, field_index) : NULL;
}

/* like Descriptor::FindFieldByNumber() */
const pbl_field_descriptor_t*
pbl_message_descriptor_FindFieldByNumber(const pbl_message_descriptor_t* message, int number)
{
    if (message && message->fields_by_number) {
        return (pbl_field_descriptor_t*) g_hash_table_lookup(message->fields_by_number, GINT_TO_POINTER(number));
    } else {
        return NULL;
    }
}

/* like Descriptor::FindFieldByName() */
const pbl_field_descriptor_t*
pbl_message_descriptor_FindFieldByName(const pbl_message_descriptor_t* message, const char* name)
{
    if (message && ((pbl_node_t*)message)->children_by_name) {
        return (pbl_field_descriptor_t*) g_hash_table_lookup(((pbl_node_t*)message)->children_by_name, name);
    } else {
        return NULL;
    }
}

/* like FieldDescriptor::full_name() */
const char*
pbl_field_descriptor_full_name(const pbl_field_descriptor_t* field)
{
    return pbl_get_node_full_name((pbl_node_t*)field);
}

/* like FieldDescriptor::name() */
const char*
pbl_field_descriptor_name(const pbl_field_descriptor_t* field)
{
    return pbl_get_node_name((pbl_node_t*)field);
}

/* like FieldDescriptor::number() */
int
pbl_field_descriptor_number(const pbl_field_descriptor_t* field)
{
    return GPOINTER_TO_INT(field->number);
}

/* like FieldDescriptor::type() */
int
pbl_field_descriptor_type(const pbl_field_descriptor_t* field)
{
    const pbl_node_t* node;
    if (field->type == PROTOBUF_TYPE_NONE) {
        /* try to lookup as ENUM */
        node = pbl_find_node_in_context(((pbl_node_t*)field)->parent, field->type_name, PBL_ENUM);
        if (node) {
            ((pbl_field_descriptor_t*)field)->type = PROTOBUF_TYPE_ENUM;
        } else {
            /* try to lookup as MESSAGE */
            node = pbl_find_node_in_context(((pbl_node_t*)field)->parent, field->type_name, PBL_MESSAGE);
            if (node) {
                ((pbl_field_descriptor_t*)field)->type = PROTOBUF_TYPE_MESSAGE;
            }
        }
    }
    return field->type;
}

/* like FieldDescriptor::is_repeated() */
int
pbl_field_descriptor_is_repeated(const pbl_field_descriptor_t* field)
{
    return field->is_repeated ? 1 : 0;
}

/* like FieldDescriptor::is_packed() */
int
pbl_field_descriptor_is_packed(const pbl_field_descriptor_t* field)
{
    gboolean has_packed_option;
    gboolean packed_option_value;
    int syntax_version = ((pbl_node_t*)field)->file->syntax_version;

    /* determine packed flag */
    if (field->is_repeated == FALSE) {
        return FALSE;
    }
    /* note: field->type may be undetermined until calling pbl_field_descriptor_type() */
    switch (pbl_field_descriptor_type(field)) {
    case PROTOBUF_TYPE_STRING:
    case PROTOBUF_TYPE_GROUP:
    case PROTOBUF_TYPE_MESSAGE:
    case PROTOBUF_TYPE_BYTES:
        return FALSE;
    default: /* only repeated fields of primitive numeric types can be declared "packed". */
        has_packed_option = field->options_node
            && field->options_node->children_by_name
            && g_hash_table_lookup(field->options_node->children_by_name, "packed");

        packed_option_value = (has_packed_option ?
            g_strcmp0(
              ((pbl_option_descriptor_t*)g_hash_table_lookup(
                field->options_node->children_by_name, "packed"))->value, "true") == 0
            : FALSE);

        if (syntax_version == 2) {
            return packed_option_value;
        } else { /* packed default in syntax_version = 3 */
            return has_packed_option ? packed_option_value : TRUE;
        }
    }
}

/* like FieldDescriptor::TypeName() */
const char*
pbl_field_descriptor_TypeName(int field_type)
{
    return val_to_str(field_type, protobuf_field_type, "UNKNOWN_FIELD_TYPE(%d)");
}

/* like FieldDescriptor::message_type()  type = TYPE_MESSAGE or TYPE_GROUP */
const pbl_message_descriptor_t*
pbl_field_descriptor_message_type(const pbl_field_descriptor_t* field)
{
    const pbl_node_t* n;
    if (field->type == PROTOBUF_TYPE_MESSAGE || field->type == PROTOBUF_TYPE_GROUP) {
        n = pbl_find_node_in_context(((pbl_node_t*)field)->parent, field->type_name, PBL_MESSAGE);
        return n ? (const pbl_message_descriptor_t*)n : NULL;
    }
    return NULL;
}

/* like FieldDescriptor::enum_type() type = TYPE_ENUM */
const pbl_enum_descriptor_t*
pbl_field_descriptor_enum_type(const pbl_field_descriptor_t* field)
{
    const pbl_node_t* n;
    if (field->type == PROTOBUF_TYPE_ENUM) {
        n = pbl_find_node_in_context(((pbl_node_t*)field)->parent, field->type_name, PBL_ENUM);
        return n ? (const pbl_enum_descriptor_t*)n : NULL;
    }
    return NULL;
}

/* like EnumDescriptor::name() */
const char*
pbl_enum_descriptor_name(const pbl_enum_descriptor_t* anEnum)
{
    return pbl_get_node_name((pbl_node_t*)anEnum);
}

/* like EnumDescriptor::full_name() */
const char*
pbl_enum_descriptor_full_name(const pbl_enum_descriptor_t* anEnum)
{
    return pbl_get_node_full_name((pbl_node_t*)anEnum);
}

/* like EnumDescriptor::value_count() */
int
pbl_enum_descriptor_value_count(const pbl_enum_descriptor_t* anEnum)
{
    return (anEnum && anEnum->values) ? g_slist_length(anEnum->values) : 0;
}

/* like EnumDescriptor::value() */
const pbl_enum_value_descriptor_t*
pbl_enum_descriptor_value(const pbl_enum_descriptor_t* anEnum, int value_index)
{
    return (anEnum && anEnum->values) ? (pbl_enum_value_descriptor_t*) g_slist_nth_data(anEnum->values, value_index) : NULL;
}

/* like EnumDescriptor::FindValueByNumber() */
const pbl_enum_value_descriptor_t*
pbl_enum_descriptor_FindValueByNumber(const pbl_enum_descriptor_t* anEnum, int number)
{
    if (anEnum && anEnum->values_by_number) {
        return (pbl_enum_value_descriptor_t*) g_hash_table_lookup(anEnum->values_by_number, GINT_TO_POINTER(number));
    } else {
        return NULL;
    }
}

/* like EnumValueDescriptor::name() */
const char*
pbl_enum_value_descriptor_name(const pbl_enum_value_descriptor_t* enumValue)
{
    return pbl_get_node_name((pbl_node_t*)enumValue);
}

/* like EnumValueDescriptor::full_name() */
const char*
pbl_enum_value_descriptor_full_name(const pbl_enum_value_descriptor_t* enumValue)
{
    return pbl_get_node_full_name((pbl_node_t*)enumValue);
}

/* like EnumValueDescriptor::number() */
int
pbl_enum_value_descriptor_number(const pbl_enum_value_descriptor_t* enumValue)
{
    return GPOINTER_TO_INT(enumValue->number);
}

static void
pbl_traverse_sub_tree(const pbl_node_t* node, void (*cb)(const pbl_message_descriptor_t*, void*), void* userdata)
{
    GSList* it;
    if (node == NULL) {
        return;
    }

    if (node->nodetype == PBL_MESSAGE) {
        (*cb)((const pbl_message_descriptor_t*) node, userdata);
    }

    if (node->children) {
        for (it = node->children; it; it = it->next) {
            pbl_traverse_sub_tree((const pbl_node_t*) it->data, cb, userdata);
        }
    }
}

/* visit all message in this pool */
void
pbl_foreach_message(const pbl_descriptor_pool_t* pool, void (*cb)(const pbl_message_descriptor_t*, void*), void* userdata)
{
    GHashTableIter it;
    gpointer key, value;
    g_hash_table_iter_init (&it, pool->packages);
    while (g_hash_table_iter_next (&it, &key, &value)) {
        pbl_traverse_sub_tree((const pbl_node_t*)value, cb, userdata);
    }
}


/*
 * Following are tree building functions that should only be invoked by protobuf_lang parser.
 */

static void
pbl_init_node(pbl_node_t* node, pbl_file_descriptor_t* file, pbl_node_type_t nodetype, const char* name)
{
    node->nodetype = nodetype;
    node->name = g_strdup(name);
    node->file = file;
    node->lineno = (file && file->pool && file->pool->parser_state && file->pool->parser_state->scanner) ?
                    pbl_get_current_lineno(file->pool->parser_state->scanner) : -1;
}

/* create a normal node */
pbl_node_t*
pbl_create_node(pbl_file_descriptor_t* file, pbl_node_type_t nodetype, const char* name)
{
    pbl_node_t* node = NULL;

    switch (nodetype) {
    case PBL_METHOD:     /* should use pbl_create_method_node() */
    case PBL_FIELD:      /* should use pbl_create_field_node() */
    case PBL_MAP_FIELD:  /* should use pbl_create_map_field_node() */
    case PBL_ENUM_VALUE: /* should use pbl_create_enum_value_node() */
    case PBL_OPTION:     /* should use pbl_create_option_node() */
        return NULL;
    case PBL_MESSAGE:
        node = (pbl_node_t*) g_malloc0(sizeof(pbl_message_descriptor_t));
        break;
    case PBL_ENUM:
        node = (pbl_node_t*) g_malloc0(sizeof(pbl_enum_descriptor_t));
        break;
    default:
        node = g_new0(pbl_node_t, 1);
    }
    pbl_init_node(node, file, nodetype, name);
    return node;
}

pbl_node_t*
pbl_set_node_name(pbl_node_t* node, const char* newname)
{
    g_free(node->name);
    node->name = g_strdup(newname);
    return node;
}

/* create a method (rpc or stream of service) node */
pbl_node_t* pbl_create_method_node(pbl_file_descriptor_t* file,
    const char* name, const char* in_msg_type,
    gboolean in_is_stream, const char* out_msg_type, gboolean out_is_stream)
{
    pbl_method_descriptor_t* node = g_new0(pbl_method_descriptor_t, 1);
    pbl_init_node(&node->basic_info, file, PBL_METHOD, name);

    node->in_msg_type = g_strdup(in_msg_type);
    node->in_is_stream = in_is_stream;
    node->out_msg_type = g_strdup(out_msg_type);
    node->out_is_stream = out_is_stream;

    return (pbl_node_t*)node;
}

/* Get type simple type enum value according to the type name.
   Return 0 means undetermined. */
static int
pbl_get_simple_type_enum_value_by_typename(const char* type_name)
{
    int i = str_to_val(type_name, protobuf_field_type, 0);
    if (i == PROTOBUF_TYPE_GROUP || i == PROTOBUF_TYPE_MESSAGE || i == PROTOBUF_TYPE_ENUM) {
        i = PROTOBUF_TYPE_NONE; /* complex type will find after parsing */
    }

    return i;
}

/* create a field node */
pbl_node_t* pbl_create_field_node(pbl_file_descriptor_t* file, const char* label,
    const char* type_name, const char* name, int number, pbl_node_t* options)
{
    pbl_field_descriptor_t* node = g_new0(pbl_field_descriptor_t, 1);
    pbl_init_node(&node->basic_info, file, PBL_FIELD, name);

    node->number = number;
    node->options_node = options;
    node->is_repeated = (g_strcmp0(label, "repeated") == 0);
    node->type_name = g_strdup(type_name);
    /* type 0 means undetermined, it will be determined on
       calling pbl_field_descriptor_type() later */
    node->type = pbl_get_simple_type_enum_value_by_typename(type_name);

    return (pbl_node_t*)node;
}

/* create a map field node */
pbl_node_t* pbl_create_map_field_node(pbl_file_descriptor_t* file,
    const char* name, int number, pbl_node_t* options)
{
    pbl_field_descriptor_t* node = g_new0(pbl_field_descriptor_t, 1);
    pbl_init_node(&node->basic_info, file, PBL_MAP_FIELD, name);

    node->number = number;
    node->type_name = g_strconcat(name, "MapEntry", NULL);
    node->type = PROTOBUF_TYPE_MESSAGE;
    node->is_repeated = TRUE;
    node->options_node = options;

    return (pbl_node_t*)node;
}

/* create an enumeration field node */
pbl_node_t*
pbl_create_enum_value_node(pbl_file_descriptor_t* file, const char* name, int number)
{
    pbl_enum_value_descriptor_t* node = g_new0(pbl_enum_value_descriptor_t, 1);
    pbl_init_node(&node->basic_info, file, PBL_ENUM_VALUE, name);

    node->number = number;
    return (pbl_node_t*)node;
}

/* create an option node */
pbl_node_t* pbl_create_option_node(pbl_file_descriptor_t* file,
    const char* name, const char* value)
{
    pbl_option_descriptor_t* node = g_new0(pbl_option_descriptor_t, 1);
    pbl_init_node(&node->basic_info, file, PBL_OPTION, name);

    if (value)
        node->value = g_strdup(value);
    return (pbl_node_t*)node;
}

/* add a node as a child of parent node, and return the parent pointer */
pbl_node_t*
pbl_add_child(pbl_node_t* parent, pbl_node_t* child)
{
    pbl_node_t* node = NULL;
    if (child == NULL || parent == NULL) {
        return parent;
    }

    /* add a message node for mapField first */
    if (child->nodetype == PBL_MAP_FIELD) {
        node = pbl_create_node(child->file, PBL_MESSAGE, ((pbl_field_descriptor_t*)child)->type_name);
        pbl_merge_children(node, child);
        pbl_add_child(parent, node);
    }

    child->parent = parent;

    /* add child to children list */
    parent->children = g_slist_append(parent->children, child);

    /* add child to children_by_name table */
    if (parent->children_by_name == NULL) {
        parent->children_by_name = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
    }

    node = (pbl_node_t*) g_hash_table_lookup(parent->children_by_name, child->name);
    if (node && child->file && parent->file
        && child->file->pool && child->file->pool->error_cb) {
        child->file->pool->error_cb(
            "Protobuf: Warning: \"%s\" of [%s:%d] is already defined in file [%s:%d].\n",
            child->name, child->file->filename, child->lineno, node->file->filename, node->lineno);
    }

    g_hash_table_insert(parent->children_by_name, child->name, child);

    if (parent->nodetype == PBL_MESSAGE) {
        pbl_message_descriptor_t* msg = (pbl_message_descriptor_t*) parent;
        /* add child to fields_by_number table */
        if (child->nodetype == PBL_FIELD || child->nodetype == PBL_MAP_FIELD) {
            msg->fields = g_slist_append(msg->fields, child);
            if (msg->fields_by_number == NULL) {
                msg->fields_by_number = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
            }
            g_hash_table_insert(msg->fields_by_number,
                                GINT_TO_POINTER(((pbl_field_descriptor_t*)child)->number), child);
        }
    } else if (parent->nodetype == PBL_ENUM && child->nodetype == PBL_ENUM_VALUE) {
        pbl_enum_descriptor_t* anEnum = (pbl_enum_descriptor_t*) parent;
        anEnum->values = g_slist_append(anEnum->values, child);
        /* add child to values_by_number table */
        if (anEnum->values_by_number == NULL) {
            anEnum->values_by_number = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
        }
        g_hash_table_insert(anEnum->values_by_number,
                            GINT_TO_POINTER(((pbl_enum_value_descriptor_t*)child)->number), child);
    }

    return parent;
}

/* merge one('from') node's children to another('to') node, and return the 'to' pointer */
pbl_node_t*
pbl_merge_children(pbl_node_t* to, pbl_node_t* from)
{
    GSList* it;
    pbl_node_t* child;

    if (to == NULL || from == NULL) {
        return to;
    }

    if (from->children) {
        for (it = from->children; it; it = it->next) {
            child = (pbl_node_t*)it->data;
            pbl_add_child(to, child);
        }

        g_slist_free(from->children);
        from->children = NULL;
        if (from->children_by_name) {
            g_hash_table_destroy(from->children_by_name);
        }
        from->children_by_name = NULL;

        if (from->nodetype == PBL_MESSAGE) {
            pbl_message_descriptor_t* msg = (pbl_message_descriptor_t*) from;
            if (msg->fields) {
                g_slist_free(msg->fields);
                msg->fields = NULL;
            }
            if (msg->fields_by_number) {
                g_hash_table_destroy(msg->fields_by_number);
                msg->fields_by_number = NULL;
            }
        } else if (from->nodetype == PBL_ENUM) {
            pbl_enum_descriptor_t* anEnum = (pbl_enum_descriptor_t*) from;
            if (anEnum->values) {
                g_slist_free(anEnum->values);
                anEnum->values = NULL;
            }
            if (anEnum->values_by_number) {
                g_hash_table_destroy(anEnum->values_by_number);
                anEnum->values_by_number = NULL;
            }
        }
    }

    return to;
}

/* free a pbl_node_t and its children. */
void
pbl_free_node(gpointer anode)
{
    pbl_method_descriptor_t* method_node;
    pbl_message_descriptor_t* message_node;
    pbl_field_descriptor_t* field_node;
    pbl_enum_descriptor_t* enum_node;
    pbl_option_descriptor_t* option_node;
    pbl_node_t* node = (pbl_node_t*) anode;

    if (node == NULL) return;

    switch (node->nodetype) {
    case PBL_METHOD:
        method_node = (pbl_method_descriptor_t*) node;
        g_free(method_node->in_msg_type);
        g_free(method_node->out_msg_type);
        break;
    case PBL_MESSAGE:
        message_node = (pbl_message_descriptor_t*) node;
        if (message_node->fields) {
            g_slist_free(message_node->fields);
        }
        if (message_node->fields_by_number) {
            g_hash_table_destroy(message_node->fields_by_number);
        }
        break;
    case PBL_FIELD:
    case PBL_MAP_FIELD:
        field_node = (pbl_field_descriptor_t*) node;
        g_free(field_node->type_name);
        if (field_node->options_node) {
            pbl_free_node(field_node->options_node);
        }
        break;
    case PBL_ENUM:
        enum_node = (pbl_enum_descriptor_t*) node;
        if (enum_node->values) {
            g_slist_free(enum_node->values);
        }
        if (enum_node->values_by_number) {
            g_hash_table_destroy(enum_node->values_by_number);
        }
        break;
    case PBL_OPTION:
        option_node = (pbl_option_descriptor_t*) node;
        g_free(option_node->value);
        break;
    default:
        /* do nothing */
        break;
    }

    g_free(node->name);
    g_free(node->full_name);
    if (node->children) {
        g_slist_free_full(node->children, pbl_free_node);
    }
    if (node->children_by_name) {
        g_hash_table_destroy(node->children_by_name);
    }
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
