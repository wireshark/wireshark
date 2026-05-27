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
#pragma once
#include <wireshark.h>

#include <stdio.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define PBL_DEFAULT_PACKAGE_NAME ""

typedef void(*pbl_report_error_cb_t)(const char *msg_format, ...);

/**
 * @brief Node types in the Protocol Buffers language (proto2/proto3) parse tree.
 */
typedef enum {
    PBL_UNKNOWN   = 0, /**< Unknown or uninitialized node type */
    PBL_PACKAGE,       /**< Package declaration node */
    PBL_MESSAGE,       /**< Message type definition node */
    PBL_FIELD,         /**< Message field definition node */
    PBL_ONEOF,         /**< oneof group definition node */
    PBL_MAP_FIELD,     /**< map<K,V> field definition node */
    PBL_ENUM,          /**< Enum type definition node */
    PBL_ENUM_VALUE,    /**< Individual enum value node */
    PBL_SERVICE,       /**< Service definition node */
    PBL_METHOD,        /**< RPC or stream method node within a service */
    PBL_OPTIONS,       /**< Options block node */
    PBL_OPTION         /**< Single option key/value node */
} pbl_node_type_t;


/**
 * @brief Central descriptor pool for all parsed .proto files; analogous to
 *        google::protobuf::DescriptorPool in the protobuf C++ library.
 */
typedef struct {
    GQueue      *source_paths;             /**< Ordered list of directory paths searched for imported .proto files */
    pbl_report_error_cb_t error_cb;        /**< Callback invoked to report parse or resolution errors */
    GHashTable  *packages;                 /**< Hash table of all packages encountered across parsed files, keyed by package name */
    GHashTable  *proto_files;              /**< Hash table of all known .proto files (parsed or pending), keyed by filename */
    GQueue      *proto_files_to_be_parsed; /**< Queue of .proto filenames that have been discovered but not yet parsed */
    struct _protobuf_lang_state_t *parser_state; /**< Active parser state during incremental parsing; NULL when idle */
} pbl_descriptor_pool_t;


/**
 * @brief Descriptor for a single parsed .proto source file.
 */
typedef struct {
    const char            *filename;             /**< Path to the .proto file as provided to the descriptor pool */
    int                    syntax_version;        /**< Proto syntax version declared in the file (2 or 3) */
    const char            *package_name;          /**< Package name declared in the file, or NULL if absent */
    int                    package_name_lineno;   /**< Line number of the package declaration within the file */
    pbl_descriptor_pool_t *pool;                  /**< Descriptor pool that owns this file descriptor */
} pbl_file_descriptor_t;


/**
 * @brief Base node carrying identity and tree linkage for every parse tree element.
 */
typedef struct pbl_node_t {
    pbl_node_type_t    nodetype;          /**< Discriminator identifying the concrete node type */
    char              *name;              /**< Unqualified name of this node as it appears in the source */
    char              *full_name;         /**< Fully-qualified name (e.g., ".package.Message.field"); lazily constructed on first access */
    struct pbl_node_t *parent;            /**< Parent node in the parse tree, or NULL for top-level nodes */
    GQueue            *children;          /**< Ordered list of child pbl_node_t pointers */
    GHashTable        *children_by_name;  /**< Hash table of child nodes keyed by unqualified name for fast lookup */
    pbl_file_descriptor_t *file;          /**< Source file in which this node was declared */
    int                lineno;            /**< Line number of this node's declaration within @ref file */
} pbl_node_t;


/**
 * @brief Descriptor for a single RPC or stream method within a service definition;
 *        analogous to google::protobuf::MethodDescriptor in the protobuf C++ library.
 */
typedef struct {
    pbl_node_t basic_info;    /**< Inherited base node fields (name, parent, file location, etc.) */
    char      *in_msg_type;   /**< Fully-qualified type name of the request message */
    bool       in_is_stream;  /**< True if the request is a streaming input (client-streaming RPC) */
    char      *out_msg_type;  /**< Fully-qualified type name of the response message */
    bool       out_is_stream; /**< True if the response is a streaming output (server-streaming RPC) */
} pbl_method_descriptor_t;


/**
 * @brief Descriptor for a message type definition; analogous to
 *        google::protobuf::Descriptor in the protobuf C++ library.
 */
typedef struct {
    pbl_node_t  basic_info;        /**< Inherited base node fields */
    GQueue     *fields;            /**< Ordered list of field descriptor nodes (pbl_node_t*) */
    GHashTable *fields_by_number;  /**< Hash table of field descriptors keyed by field number for fast lookup */
} pbl_message_descriptor_t;


/**
 * @brief Descriptor for a single enum value; analogous to
 *        google::protobuf::EnumValueDescriptor in the protobuf C++ library.
 */
typedef struct {
    pbl_node_t basic_info; /**< Inherited base node fields */
    int        number;     /**< Integer value assigned to this enum constant */
} pbl_enum_value_descriptor_t;

/**
 * @brief Describes a field in a Protocol Buffer message, similar to `google::protobuf::FieldDescriptor`.
 *
 * This structure holds metadata about a field, including its type, number, repetition status,
 * default value, and any associated options. It supports scalar types, strings, enums, and more.
 */
typedef struct {
    pbl_node_t basic_info; /**< Basic metadata node (e.g., name, documentation). */
    int number;            /**< Field number as defined in the .proto schema. */
    int type;              /**< Field type identifier (see PROTOBUF_TYPE_XXX in protobuf-helper.h). */
    char* type_name;       /**< Optional type name for message or enum fields. */
    pbl_node_t* options_node; /**< Pointer to options metadata node, if present. */

    bool is_repeated;      /**< True if the field is repeated. */
    bool is_required;      /**< True if the field is required. */
    bool has_default_value; /**< True if a default value is explicitly declared. */
    char* orig_default_value; /**< Original default value string from the schema. */
    int string_or_bytes_default_value_length; /**< Length of string or bytes default value, if applicable. */

    /**
     * @brief Union holding the parsed default value for the field.
     *
     * The actual member used depends on the field type.
     */
    union {
        int32_t i32;   /**< Default value for int32 fields. */
        int64_t i64;   /**< Default value for int64 fields. */
        uint32_t u32;  /**< Default value for uint32 fields. */
        uint64_t u64;  /**< Default value for uint64 fields. */
        float f;       /**< Default value for float fields. */
        double d;      /**< Default value for double fields. */
        bool b;        /**< Default value for bool fields. */
        char* s;       /**< Default value for string or bytes fields. */
        const pbl_enum_value_descriptor_t* e; /**< Default enum value descriptor. */
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

/**
 * @brief Store a string token in the parser state and return the input pointer.
 *
 * @param parser_state Pointer to the protobuf_lang_state_t structure.
 * @param dupstr Duplicate of the string token to store.
 * @return The input pointer (dupstr).
 */
static inline char*
pbl_store_string_token(protobuf_lang_state_t* parser_state, char* dupstr)
{
    parser_state->lex_string_tokens = g_slist_prepend(parser_state->lex_string_tokens, dupstr);
    return dupstr;
}

/**
 * @brief Stores a new token in the parser state's list of structure tokens.
 *
 * Store a protobuf_lang_token_t in protobuf_lang_state_t temporarily, and return back
 * the input pointer. It will be freed when protobuf_lang_state_t is released
 *
 * @param parser_state Pointer to the parser state.
 * @param newtoken Pointer to the new token to be stored.
 * @return The newly added token.
 */
static inline protobuf_lang_token_t*
pbl_store_struct_token(protobuf_lang_state_t* parser_state, protobuf_lang_token_t* newtoken)
{
    parser_state->lex_struct_tokens = g_slist_prepend(parser_state->lex_struct_tokens, newtoken);
    return newtoken;
}

/* default error_cb */

/**
 * @brief Prints formatted output to a string.
 *
 * @param fmt Format string.
 */
static inline void
pbl_printf(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

/**
 @brief Reinitialize the protocol buffers pool according to proto files directories.
 @param ppool The output descriptor_pool will be created. If *pool is not NULL, it will free it first.
 @param directories  The root directories containing proto files. Must end with NULL element.
 @param error_cb The error reporter callback function. */
void
pbl_reinit_descriptor_pool(pbl_descriptor_pool_t** ppool, const char** directories, pbl_report_error_cb_t error_cb);

/* free all memory used by this protocol buffers language pool */
/**
 * @brief Free a descriptor pool and its associated resources.
 *
 * @param pool The descriptor pool to free.
 */
void
pbl_free_pool(pbl_descriptor_pool_t* pool);

/* add a proto file to pool. this file will not be parsed until run_pbl_parser function is invoked. */
/**
 * @brief Adds a Protocol Buffers file to be parsed.
 *
 * @param pool The descriptor pool to which the file will be added.
 * @param filepath The path to the Protocol Buffers file.
 */
bool
pbl_add_proto_file_to_be_parsed(pbl_descriptor_pool_t* pool, const char* filepath);

/* run C protocol buffers language parser, return 0 if success */

/**
 * @brief Runs the Protocol Buffers Language parser.
 *
 * @param pool The descriptor pool to parse.
 * @return 0 on success, non-zero on failure.
 */
int run_pbl_parser(pbl_descriptor_pool_t* pool);

/* like descriptor_pool::FindMethodByName */
/**
 * @brief Finds a method descriptor by its name in a message descriptor pool.
 *
 * @param pool The message descriptor pool to search within.
 * @param name The name of the method descriptor to find.
 * @return A pointer to the found method descriptor, or NULL if not found.
 */
const pbl_method_descriptor_t*
pbl_message_descriptor_pool_FindMethodByName(const pbl_descriptor_pool_t* pool, const char* name);

/* like MethodDescriptor::name() */
/**
 * @brief Retrieves the name of a method descriptor.
 *
 * @param method Pointer to the method descriptor.
 * @return The name of the method descriptor.
 */
const char*
pbl_method_descriptor_name(const pbl_method_descriptor_t* method);

/* like MethodDescriptor::full_name() */
/**
 * @brief Retrieves the full name of a method descriptor.
 *
 * @param method Pointer to the method descriptor.
 * @return The full name of the method descriptor as a string.
 */
const char*
pbl_method_descriptor_full_name(const pbl_method_descriptor_t* method);

/* like MethodDescriptor::input_type() */
/**
 * @brief Retrieves the input message descriptor type for a method.
 *
 * @param method Pointer to the method descriptor.
 * @return const pbl_message_descriptor_t* Pointer to the input message descriptor, or NULL if not found.
 */
const pbl_message_descriptor_t*
pbl_method_descriptor_input_type(const pbl_method_descriptor_t* method);

/* like MethodDescriptor::output_type() */
/**
 * @brief Retrieves the output type of a method descriptor.
 *
 * @param method The method descriptor to query.
 * @return const pbl_message_descriptor_t* A pointer to the message descriptor if found, otherwise NULL.
 */
const pbl_message_descriptor_t*
pbl_method_descriptor_output_type(const pbl_method_descriptor_t* method);

/* like descriptor_pool::FindMessageTypeByName() */
/**
 * @brief Finds a message descriptor by its name in a descriptor pool.
 *
 * @param pool The descriptor pool to search within.
 * @param name The name of the message descriptor to find.
 * @return const pbl_message_descriptor_t* A pointer to the found message descriptor, or NULL if not found.
 */
const pbl_message_descriptor_t*
pbl_message_descriptor_pool_FindMessageTypeByName(const pbl_descriptor_pool_t* pool, const char* name);

/* like Descriptor::name() */
/**
 * @brief Retrieves the name of a message descriptor.
 *
 * @param message Pointer to the message descriptor.
 * @return const char* The full name of the message descriptor.
 */
const char*
pbl_message_descriptor_name(const pbl_message_descriptor_t* message);

/* like Descriptor::full_name() */
/**
 * @brief Retrieves the full name of a message descriptor.
 *
 * @param message Pointer to the message descriptor.
 * @return const char* The full name of the message descriptor.
 */
const char*
pbl_message_descriptor_full_name(const pbl_message_descriptor_t* message);

/* like Descriptor::field_count() */
/**
 * @brief Get the count of fields in a message descriptor.
 *
 * @param message Pointer to the message descriptor.
 * @return int The number of fields in the message descriptor.
 */
int
pbl_message_descriptor_field_count(const pbl_message_descriptor_t* message);

/* like Descriptor::field() */
/**
 * @brief Retrieves a field descriptor from a message descriptor by index.
 *
 * @param message The message descriptor to search.
 * @param field_index The index of the field descriptor to retrieve.
 * @return const pbl_field_descriptor_t* A pointer to the field descriptor, or NULL if not found.
 */
const pbl_field_descriptor_t*
pbl_message_descriptor_field(const pbl_message_descriptor_t* message, int field_index);

/* like Descriptor::FindFieldByNumber() */
/**
 * @brief Finds a field descriptor by its number in a message descriptor.
 *
 * @param message The message descriptor to search within.
 * @param number The number of the field descriptor to find.
 * @return const pbl_field_descriptor_t* A pointer to the found field descriptor, or NULL if not found.
 */
const pbl_field_descriptor_t*
pbl_message_descriptor_FindFieldByNumber(const pbl_message_descriptor_t* message, int number);

/* like Descriptor::FindFieldByName() */
/**
 * @brief Finds a field descriptor by name in a message descriptor.
 *
 * @param message The message descriptor to search within.
 * @param name The name of the field descriptor to find.
 * @return const char* A pointer to the found field descriptor, or NULL if not found.
 */
const pbl_field_descriptor_t*
pbl_message_descriptor_FindFieldByName(const pbl_message_descriptor_t* message, const char* name);

/* like FieldDescriptor::full_name() */
/**
 * @brief Retrieves the full name of a field descriptor.
 *
 * @param field Pointer to the field descriptor.
 * @return const char* The full name of the field.
 */
const char*
pbl_field_descriptor_full_name(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::name() */
/**
 * @brief Retrieves the name of a field descriptor.
 *
 * @param field Pointer to the field descriptor.
 * @return The name of the field descriptor.
 */
const char*
pbl_field_descriptor_name(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::number() */
/**
 * @brief Retrieves the number associated with a field descriptor.
 *
 * @param field Pointer to the field descriptor structure.
 * @return The number of the field descriptor.
 */
int
pbl_field_descriptor_number(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::type() */
/**
 * @brief Get the type of a field descriptor.
 *
 * @param field The field descriptor to query.
 * @return The type of the field descriptor.
 */
int
pbl_field_descriptor_type(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::is_repeated() */
/**
 * @brief Checks if a field descriptor is repeated.
 *
 * @param field Pointer to the field descriptor.
 * @return 1 if the field is repeated, 0 otherwise.
 */
int
pbl_field_descriptor_is_repeated(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::is_packed() */
/**
 * @brief Checks if a field descriptor is packed.
 *
 * @param field The field descriptor to check.
 * @return true If the field is packed, false otherwise.
 */
int

pbl_field_descriptor_is_packed(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::TypeName() */
/**
 * @brief Retrieves the type name for a given field type.
 *
 * @param scope Memory allocator scope.
 * @param field_type The field type to retrieve the type name for.
 * @return const char* The type name of the field type, or "UNKNOWN_FIELD_TYPE(%d)" if not found.
 */
const char*
pbl_field_descriptor_TypeName(wmem_allocator_t* scope, int field_type);

/* like FieldDescriptor::message_type() */
/**
 * @brief Retrieves the message type descriptor for a field.
 *
 * @param field The field descriptor to query.
 * @return const pbl_message_descriptor_t* Pointer to the message type descriptor, or NULL if not applicable.
 */
const pbl_message_descriptor_t*pbl_field_descriptor_message_type(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::enum_type() */
/**
 * @brief Get the enum descriptor for a field.
 *
 * @param field The field descriptor to query.
 * @return const pbl_enum_descriptor_t* The enum descriptor if the field is of type ENUM, otherwise NULL.
 */
const pbl_enum_descriptor_t*
pbl_field_descriptor_enum_type(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::is_required() */
/**
 * @brief Checks if a field descriptor is required.
 *
 * @param field The field descriptor to check.
 * @return true if the field is required, false otherwise.
 */
bool
pbl_field_descriptor_is_required(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::has_default_value().
 * Does this field have an explicitly-declared default value? */
/**
 * @brief Checks if a field descriptor has a default value.
 *
 * @param field The field descriptor to check.
 * @return int 1 if the field has a default value, 0 otherwise.
 */
bool
pbl_field_descriptor_has_default_value(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::default_value_int32() */
/**
 * @brief Retrieves the default value for an int32 field descriptor.
 *
 * @param field Pointer to the pbl_field_descriptor_t structure.
 * @return The default value of the int32 field.
 */
int32_t
pbl_field_descriptor_default_value_int32(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::default_value_int64() */
/**
 * @brief Retrieves the default value of a field descriptor as an int64.
 *
 * @param field Pointer to the pbl_field_descriptor_t structure.
 * @return The default value of the field as an int64.
 */
int64_t
pbl_field_descriptor_default_value_int64(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::default_value_uint32() */
/**
 * @brief Retrieves the default value of a field descriptor as a uint32.
 *
 * @param field The field descriptor from which to retrieve the default value.
 * @return The default value of the field as a uint32.
 */
uint32_t
pbl_field_descriptor_default_value_uint32(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::default_value_uint64() */
/**
 * @brief Retrieves the default value of a field descriptor as a 64-bit unsigned integer.
 *
 * @param field Pointer to the field descriptor.
 * @return The default value of the field as a 64-bit unsigned integer.
 */
uint64_t
pbl_field_descriptor_default_value_uint64(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::default_value_float() */
/**
 * @brief Retrieves the default value of a float field descriptor.
 *
 * @param field Pointer to the pbl_field_descriptor_t structure.
 * @return The default value as a float.
 */
float
pbl_field_descriptor_default_value_float(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::default_value_double() */
/**
 * @brief Retrieves the default value of a double field descriptor.
 *
 * @param field Pointer to the field descriptor.
 * @return The default value of the double field.
 */
double
pbl_field_descriptor_default_value_double(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::default_value_bool() */
/**
 * @brief Retrieves the default value of a boolean field descriptor.
 *
 * @param field Pointer to the field descriptor.
 * @return The default value as a boolean.
 */
bool
pbl_field_descriptor_default_value_bool(const pbl_field_descriptor_t* field);

/* like FieldDescriptor::default_value_string() */
/**
 * @brief Get the default value string of a Protocol Buffers field descriptor.
 *
 * @param field Pointer to the Protocol Buffers field descriptor.
 * @param size Pointer to an integer where the length of the default value string will be stored.
 * @return const char* The default value string.
 */
const char*
pbl_field_descriptor_default_value_string(const pbl_field_descriptor_t* field, int* size);

/* like FieldDescriptor::default_value_enum() */
/**
 * @brief Retrieves the default value enum for a field descriptor.
 *
 * @param field The field descriptor to query.
 * @return const pbl_enum_value_descriptor_t* The default value enum, or NULL if not applicable.
 */
const pbl_enum_value_descriptor_t*
pbl_field_descriptor_default_value_enum(const pbl_field_descriptor_t* field);

/* like EnumDescriptor::name() */
/**
 * @brief Get the name of an enum descriptor.
 *
 * @param anEnum Pointer to the enum descriptor.
 * @return const char* The name of the enum descriptor.
 */
const char*
pbl_enum_descriptor_name(const pbl_enum_descriptor_t* anEnum);

/* like EnumDescriptor::full_name() */
/**
 * @brief Get the full name of an enum descriptor.
 *
 * @param anEnum Pointer to the enum descriptor.
 * @return const char* Full name of the enum descriptor.
 */
const char*
pbl_enum_descriptor_full_name(const pbl_enum_descriptor_t* anEnum);

/* like EnumDescriptor::value_count() */
/**
 * @brief Get the count of values in an enum descriptor.
 *
 * @param anEnum Pointer to the enum descriptor.
 * @return int The number of values in the enum descriptor.
 */
int
pbl_enum_descriptor_value_count(const pbl_enum_descriptor_t* anEnum);

/* like EnumDescriptor::value() */
/**
 * @brief Retrieves an enum value descriptor by its index.
 *
 * @param anEnum Pointer to the enum descriptor.
 * @param value_index Index of the enum value descriptor to retrieve.
 * @return const pbl_enum_value_descriptor_t* Pointer to the enum value descriptor, or NULL if not found.
 */
const pbl_enum_value_descriptor_t*
pbl_enum_descriptor_value(const pbl_enum_descriptor_t* anEnum, int value_index);

/* like EnumDescriptor::FindValueByNumber() */
/**
 * @brief Finds an enumeration value descriptor by its number.
 *
 * @param anEnum Pointer to the enumeration descriptor.
 * @param number The number of the enumeration value to find.
 * @return const pbl_enum_value_descriptor_t* Pointer to the found enumeration value descriptor, or NULL if not found.
 */
const pbl_enum_value_descriptor_t*
pbl_enum_descriptor_FindValueByNumber(const pbl_enum_descriptor_t* anEnum, int number);

/* like EnumDescriptor::FindValueByName() */
/**
 * @brief Finds an enumeration value descriptor by name within a given enumeration descriptor.
 *
 * @param anEnum Pointer to the enumeration descriptor.
 * @param name The name of the enumeration value descriptor to find.
 * @return const char* Pointer to the found enumeration value descriptor, or NULL if not found.
 */
const pbl_enum_value_descriptor_t*
pbl_enum_descriptor_FindValueByName(const pbl_enum_descriptor_t* anEnum, const char* name);

/* like EnumValueDescriptor::name() */
/**
 * @brief Retrieves the name of an enum value descriptor.
 *
 * @param enumValue Pointer to the enum value descriptor.
 * @return const char* The name of the enum value descriptor.
 */
const char*
pbl_enum_value_descriptor_name(const pbl_enum_value_descriptor_t* enumValue);

/* like EnumValueDescriptor::full_name() */
/**
 * @brief Get the full name of an enum value descriptor.
 *
 * @param enumValue Pointer to the enum value descriptor.
 * @return const char* The full name of the enum value descriptor.
 */
const char*
pbl_enum_value_descriptor_full_name(const pbl_enum_value_descriptor_t* enumValue);

/* like EnumValueDescriptor::number() */
/**
 * @brief Retrieves the number associated with an enum value descriptor.
 *
 * @param enumValue Pointer to the enum value descriptor.
 * @return The number of the enum value.
 */
int
pbl_enum_value_descriptor_number(const pbl_enum_value_descriptor_t* enumValue);

/* visit all message in this pool */
/**
 * @brief Iterates over all message descriptors in a descriptor pool.
 *
 * @param pool The descriptor pool to iterate over.
 * @param cb Callback function to call for each message descriptor.
 * @param userdata User data to pass to the callback function.
 */
void
pbl_foreach_message(const pbl_descriptor_pool_t* pool, void (*cb)(const pbl_message_descriptor_t*, void*), void* userdata);

/*
 * Following are tree building functions.
 */

/* create a normal node */
/**
 * @brief Creates a new node in the Protocol Buffers language tree.
 *
 * @param file The file descriptor associated with the node.
 * @param lineno The line number where the node is defined.
 * @param nodetype The type of the node to create.
 * @param name The name of the node.
 * @return A pointer to the newly created node, or NULL if an invalid node type is provided.
 */
pbl_node_t*
pbl_create_node(pbl_file_descriptor_t* file, int lineno, pbl_node_type_t nodetype, const char* name);

/* change the name of node */
/**
 * @brief Set the name of a node.
 *
 * @param node Pointer to the node whose name is to be set.
 * @param lineno Line number where this function was called (for debugging purposes).
 * @param newname New name for the node.
 * @return Pointer to the modified node.
 */
pbl_node_t*
pbl_set_node_name(pbl_node_t* node, int lineno, const char* newname);

/* get the name of node */
/**
 * @brief Get the name of a node.
 *
 * @param node Pointer to the node.
 * @return const char* The name of the node.
 */
static inline const char*
pbl_get_node_name(pbl_node_t* node)
{
    return node->name;
}

/* get the full name of node. if it is NULL, it will be built. */
/**
 * @brief Get the full name of a node.
 *
 * @param node The node to get the full name for.
 * @return The full name of the node, or NULL if not available.
 */
const char*
pbl_get_node_full_name(pbl_node_t* node);

/* append a node as a child of the parent node, and return the parent pointer */
/**
 * @brief Adds a child node to a parent node.
 *
 * @param parent The parent node to which the child will be added.
 * @param child The child node to add.
 * @return The updated parent node with the child added, or NULL if an error occurred.
 */
pbl_node_t*
pbl_add_child(pbl_node_t* parent, pbl_node_t* child);

/* create an enumeration field node */

/**
 * @brief Create a new enum value node.
 *
 * @param file The file descriptor associated with this node.
 * @param lineno The line number in the source code where this node is created.
 * @param name The name of the enum value.
 * @param number The numeric value of the enum.
 * @return A pointer to the newly created enum value node.
 */
pbl_node_t*
pbl_create_enum_value_node(pbl_file_descriptor_t* file, int lineno, const char* name, int number);

/* merge one('from') node's children to another('to') node, and return the 'to' pointer */
/**
 * @brief Merges children from one node to another.
 *
 * This function merges all children from the 'from' node into the 'to' node.
 * It then frees the resources associated with the 'from' node's children.
 *
 * @param to The target node to which children will be added.
 * @param from The source node from which children will be taken.
 * @return The target node after merging.
 */
pbl_node_t*
pbl_merge_children(pbl_node_t* to, pbl_node_t* from);

/* create a field node */
/**
 * @brief Create a field node for a Protocol Buffers message.
 *
 * @param file The file descriptor associated with the message.
 * @param lineno The line number in the source code where this function is called.
 * @param label The label of the field, indicating if it's required, repeated, or optional.
 * @param type_name The name of the data type of the field.
 * @param name The name of the field.
 * @param number The unique identifier for the field within the message.
 * @param options A node containing additional options for the field.
 * @return A pointer to the created field node.
 */
pbl_node_t*
pbl_create_field_node(pbl_file_descriptor_t* file, int lineno, const char* label, const char* type_name, const char* name, int number, pbl_node_t* options);

/* create a map field node */
/**
 * @brief Create a map field node in the Protocol Buffers language tree.
 *
 * @param file Pointer to the file descriptor.
 * @param lineno Line number where this node is defined.
 * @param name Name of the map field.
 * @param number Field number.
 * @param options Options for the map field.
 * @return Pointer to the created map field node.
 */
pbl_node_t*
pbl_create_map_field_node(pbl_file_descriptor_t* file, int lineno, const char* name, int number, pbl_node_t* options);

/* create a method (rpc or stream of service) node */
/**
 * @brief Create a method node for Protocol Buffers.
 *
 * @param file Pointer to the file descriptor.
 * @param lineno Line number in the source code.
 * @param name Name of the method.
 * @param in_msg_type Type of the input message.
 * @param in_is_stream Indicates if the input is a stream.
 * @param out_msg_type Type of the output message.
 * @param out_is_stream Indicates if the output is a stream.
 * @return Pointer to the created method node.
 */
pbl_node_t*
pbl_create_method_node(pbl_file_descriptor_t* file, int lineno, const char* name, const char* in_msg_type, bool in_is_stream, const char* out_msg_type, bool out_is_stream);

/* create an option node */

/**
 * @brief Creates a new option node for Protocol Buffers Language Tree.
 *
 * @param file Pointer to the file descriptor.
 * @param lineno Line number where the node is created.
 * @param name Name of the option.
 * @param value Value of the option, can be NULL.
 * @return Pointer to the newly created option node.
 */
pbl_node_t*
pbl_create_option_node(pbl_file_descriptor_t* file, int lineno, const char* name, const char* value);

/**
 * @brief Frees a protocol buffer language tree node and its children.
 *
 * This function releases all resources associated with a given protocol buffer
 * language tree node and sets it to NULL.
 *
 * @param anode Pointer to the node to be freed.
 */
void
pbl_free_node(void *anode);

#ifdef __cplusplus
}
#endif /* __cplusplus */

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
