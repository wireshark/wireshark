/** @file
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

#ifndef __PROTOBUF_LANG_TREE_H__
#define __PROTOBUF_LANG_TREE_H__

#include <wireshark.h>

#include <stdio.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define PBL_DEFAULT_PACKAGE_NAME ""

typedef void(*pbl_report_error_cb_t)(const char *msg_format, ...);

/* Node types of protocol buffers language */
typedef enum {
    PBL_UNKNOWN = 0,
    PBL_PACKAGE,
    PBL_MESSAGE,
    PBL_FIELD,
    PBL_ONEOF,
    PBL_MAP_FIELD,
    PBL_ENUM,
    PBL_ENUM_VALUE,
    PBL_SERVICE,
    PBL_METHOD, /* contains the rpc and stream node of service */
    PBL_OPTIONS,
    PBL_OPTION
} pbl_node_type_t;

/* like google::protobuf::descriptor_pool of protobuf cpp library */
typedef struct {
    GQueue* source_paths; /* the directories in which to search for proto file */
    pbl_report_error_cb_t error_cb; /* error call back function */
    GHashTable* packages; /* all packages parsed from proto files */
    GHashTable* proto_files; /* all proto files that are parsed or to be parsed */
    GQueue* proto_files_to_be_parsed; /* files is to be parsed */
    struct _protobuf_lang_state_t *parser_state; /* current parser state */
} pbl_descriptor_pool_t;

/* file descriptor */
typedef struct {
    const char* filename;
    int syntax_version;
    const char* package_name;
    int package_name_lineno;
    pbl_descriptor_pool_t* pool;
} pbl_file_descriptor_t;

/* Basic information of node */
typedef struct pbl_node_t{
    pbl_node_type_t nodetype;
    char* name;
    char* full_name; /* constructed during first access */
    struct pbl_node_t* parent;
    GQueue* children; /* child is a pbl_node_t */
    GHashTable* children_by_name; /* take children names as keys */
    pbl_file_descriptor_t* file;
    int lineno;
} pbl_node_t;

/* like google::protobuf::MethodDescriptor of protobuf cpp library */
typedef struct {
    pbl_node_t basic_info;
    char* in_msg_type;
    bool in_is_stream;
    char* out_msg_type;
    bool out_is_stream;
} pbl_method_descriptor_t;

/* like google::protobuf::Descriptor of protobuf cpp library */
typedef struct {
    pbl_node_t basic_info;
    GQueue* fields;
    GHashTable* fields_by_number;
} pbl_message_descriptor_t;

/* like google::protobuf::EnumValueDescriptor of protobuf cpp library */
typedef struct {
    pbl_node_t basic_info;
    int number;
} pbl_enum_value_descriptor_t;

/* like google::protobuf::FieldDescriptor of protobuf cpp library */
typedef struct {
    pbl_node_t basic_info;
    int number;
    int type; /* refer to PROTOBUF_TYPE_XXX of protobuf-helper.h */
    char* type_name;
    pbl_node_t* options_node;
    bool is_repeated;
    bool is_required;
    bool has_default_value; /* Does this field have an explicitly-declared default value? */
    char* orig_default_value;
    int string_or_bytes_default_value_length;
    union {
        int32_t i32;
        int64_t i64;
        uint32_t u32;
        uint64_t u64;
        float f;
        double d;
        bool b;
        char* s;
        const pbl_enum_value_descriptor_t* e;
    } default_value;
} pbl_field_descriptor_t;

/* like google::protobuf::EnumDescriptor of protobuf cpp library */
typedef struct {
    pbl_node_t basic_info;
    GQueue* values;
    GHashTable* values_by_number;
} pbl_enum_descriptor_t;

/* Option node. The name of basic_info is optionName.
   Now, we only care about fieldOption. */
typedef struct {
    pbl_node_t basic_info;
    char* value;
} pbl_option_descriptor_t;

/* the struct of token used by the parser */
typedef struct _protobuf_lang_token_t {
    char* v; /* token string value */
    int ln; /* line number of this token in the .proto file */
} protobuf_lang_token_t;

/* parser state */
typedef struct _protobuf_lang_state_t {
    pbl_descriptor_pool_t* pool; /* pool will keep the parsing result */
    pbl_file_descriptor_t* file; /* info of current parsing file */
    GSList* lex_string_tokens;
    GSList* lex_struct_tokens;
    void* scanner;
    void* pParser;
    bool grammar_error;
    protobuf_lang_token_t* tmp_token; /* just for passing token value from protobuf_lang_lex() to ProtobufLangParser() */
} protobuf_lang_state_t;

/* Store chars created by strdup or g_strconcat into protobuf_lang_state_t temporarily,
   and return back the input chars pointer.
   It will be freed when protobuf_lang_state_t is released */
static inline char*
pbl_store_string_token(protobuf_lang_state_t* parser_state, char* dupstr)
{
    parser_state->lex_string_tokens = g_slist_prepend(parser_state->lex_string_tokens, dupstr);
    return dupstr;
}

/* Store a protobuf_lang_token_t in protobuf_lang_state_t temporarily, and return back
   the input pointer. It will be freed when protobuf_lang_state_t is released */
static inline protobuf_lang_token_t*
pbl_store_struct_token(protobuf_lang_state_t* parser_state, protobuf_lang_token_t* newtoken)
{
    parser_state->lex_struct_tokens = g_slist_prepend(parser_state->lex_struct_tokens, newtoken);
    return newtoken;
}

/* default error_cb */
static inline void
pbl_printf(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

/**
 Reinitialize the protocol buffers pool according to proto files directories.
 @param ppool The output descriptor_pool will be created. If *pool is not NULL, it will free it first.
 @param directories  The root directories containing proto files. Must end with NULL element.
 @param error_cb The error reporter callback function. */
void
pbl_reinit_descriptor_pool(pbl_descriptor_pool_t** ppool, const char** directories, pbl_report_error_cb_t error_cb);

/* free all memory used by this protocol buffers language pool */
void
pbl_free_pool(pbl_descriptor_pool_t* pool);

/* add a proto file to pool. this file will not be parsed until run_pbl_parser function is invoked. */
bool
pbl_add_proto_file_to_be_parsed(pbl_descriptor_pool_t* pool, const char* filepath);

/* run C protocol buffers language parser, return 0 if success */
int run_pbl_parser(pbl_descriptor_pool_t* pool);

/* like descriptor_pool::FindMethodByName */
const pbl_method_descriptor_t*
pbl_message_descriptor_pool_FindMethodByName(const pbl_descriptor_pool_t* pool, const char* name);

/* like MethodDescriptor::name() */
const char*
pbl_method_descriptor_name(const pbl_method_descriptor_t* method);

/* like MethodDescriptor::full_name() */
const char*
pbl_method_descriptor_full_name(const pbl_method_descriptor_t* method);

/* like MethodDescriptor::input_type() */
const pbl_message_descriptor_t*
pbl_method_descriptor_input_type(const pbl_method_descriptor_t* method);

/* like MethodDescriptor::output_type() */
const pbl_message_descriptor_t*
pbl_method_descriptor_output_type(const pbl_method_descriptor_t* method);

/* like descriptor_pool::FindMessageTypeByName() */
const pbl_message_descriptor_t*
pbl_message_descriptor_pool_FindMessageTypeByName(const pbl_descriptor_pool_t* pool, const char* name);

/* like Descriptor::name() */
const char*
pbl_message_descriptor_name(const pbl_message_descriptor_t* message);

/* like Descriptor::full_name() */
const char*
pbl_message_descriptor_full_name(const pbl_message_descriptor_t* message);

/* like Descriptor::field_count() */
int
pbl_message_descriptor_field_count(const pbl_message_descriptor_t* message);

/* like Descriptor::field() */
const pbl_field_descriptor_t*
pbl_message_descriptor_field(const pbl_message_descriptor_t* message, int field_index);

/* like Descriptor::FindFieldByNumber() */
const pbl_field_descriptor_t*
pbl_message_descriptor_FindFieldByNumber(const pbl_message_descriptor_t* message, int number);

/* like Descriptor::FindFieldByName() */
const pbl_field_descriptor_t*
pbl_message_descriptor_FindFieldByName(const pbl_message_descriptor_t* message, const char* name);

/* like FieldDescriptor::full_name() */
const char*
pbl_field_descriptor_full_name(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::name() */
const char*
pbl_field_descriptor_name(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::number() */
int
pbl_field_descriptor_number(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::type() */
int
pbl_field_descriptor_type(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::is_repeated() */
int
pbl_field_descriptor_is_repeated(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::is_packed() */
int
pbl_field_descriptor_is_packed(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::TypeName() */
const char*
pbl_field_descriptor_TypeName(int field_type);

/* like FieldDescriptor::message_type() */
const pbl_message_descriptor_t*
pbl_field_descriptor_message_type(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::enum_type() */
const pbl_enum_descriptor_t*
pbl_field_descriptor_enum_type(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::is_required() */
bool
pbl_field_descriptor_is_required(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::has_default_value().
 * Does this field have an explicitly-declared default value? */
bool
pbl_field_descriptor_has_default_value(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::default_value_int32() */
int32_t
pbl_field_descriptor_default_value_int32(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::default_value_int64() */
int64_t
pbl_field_descriptor_default_value_int64(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::default_value_uint32() */
uint32_t
pbl_field_descriptor_default_value_uint32(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::default_value_uint64() */
uint64_t
pbl_field_descriptor_default_value_uint64(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::default_value_float() */
float
pbl_field_descriptor_default_value_float(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::default_value_double() */
double
pbl_field_descriptor_default_value_double(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::default_value_bool() */
bool
pbl_field_descriptor_default_value_bool(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::default_value_string() */
const char*
pbl_field_descriptor_default_value_string(const pbl_field_descriptor_t* field, int* size);

/* like FieldDescriptor::default_value_enum() */
const pbl_enum_value_descriptor_t*
pbl_field_descriptor_default_value_enum(const pbl_field_descriptor_t* field);

/* like EnumDescriptor::name() */
const char*
pbl_enum_descriptor_name(const pbl_enum_descriptor_t* anEnum);

/* like EnumDescriptor::full_name() */
const char*
pbl_enum_descriptor_full_name(const pbl_enum_descriptor_t* anEnum);

/* like EnumDescriptor::value_count() */
int
pbl_enum_descriptor_value_count(const pbl_enum_descriptor_t* anEnum);

/* like EnumDescriptor::value() */
const pbl_enum_value_descriptor_t*
pbl_enum_descriptor_value(const pbl_enum_descriptor_t* anEnum, int value_index);

/* like EnumDescriptor::FindValueByNumber() */
const pbl_enum_value_descriptor_t*
pbl_enum_descriptor_FindValueByNumber(const pbl_enum_descriptor_t* anEnum, int number);

/* like EnumDescriptor::FindValueByName() */
const pbl_enum_value_descriptor_t*
pbl_enum_descriptor_FindValueByName(const pbl_enum_descriptor_t* anEnum, const char* name);

/* like EnumValueDescriptor::name() */
const char*
pbl_enum_value_descriptor_name(const pbl_enum_value_descriptor_t* enumValue);

/* like EnumValueDescriptor::full_name() */
const char*
pbl_enum_value_descriptor_full_name(const pbl_enum_value_descriptor_t* enumValue);

/* like EnumValueDescriptor::number() */
int
pbl_enum_value_descriptor_number(const pbl_enum_value_descriptor_t* enumValue);

/* visit all message in this pool */
void
pbl_foreach_message(const pbl_descriptor_pool_t* pool, void (*cb)(const pbl_message_descriptor_t*, void*), void* userdata);

/*
 * Following are tree building functions.
 */

/* create a normal node */
pbl_node_t*
pbl_create_node(pbl_file_descriptor_t* file, int lineno, pbl_node_type_t nodetype, const char* name);

/* change the name of node */
pbl_node_t*
pbl_set_node_name(pbl_node_t* node, int lineno, const char* newname);

/* get the name of node */
static inline const char*
pbl_get_node_name(pbl_node_t* node)
{
    return node->name;
}

/* get the full name of node. if it is NULL, it will be built. */
const char*
pbl_get_node_full_name(pbl_node_t* node);

/* append a node as a child of the parent node, and return the parent pointer */
pbl_node_t*
pbl_add_child(pbl_node_t* parent, pbl_node_t* child);

/* create an enumeration field node */
pbl_node_t*
pbl_create_enum_value_node(pbl_file_descriptor_t* file, int lineno, const char* name, int number);

/* merge one('from') node's children to another('to') node, and return the 'to' pointer */
pbl_node_t*
pbl_merge_children(pbl_node_t* to, pbl_node_t* from);

/* create a field node */
pbl_node_t*
pbl_create_field_node(pbl_file_descriptor_t* file, int lineno, const char* label, const char* type_name, const char* name, int number, pbl_node_t* options);

/* create a map field node */
pbl_node_t*
pbl_create_map_field_node(pbl_file_descriptor_t* file, int lineno, const char* name, int number, pbl_node_t* options);

/* create a method (rpc or stream of service) node */
pbl_node_t*
pbl_create_method_node(pbl_file_descriptor_t* file, int lineno, const char* name, const char* in_msg_type, bool in_is_stream, const char* out_msg_type, bool out_is_stream);

/* create an option node */
pbl_node_t*
pbl_create_option_node(pbl_file_descriptor_t* file, int lineno, const char* name, const char* value);

/* free a pbl_node_t and its children. */
void
pbl_free_node(void *anode);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PROTOBUF_LANG_TREE_H__ */

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
