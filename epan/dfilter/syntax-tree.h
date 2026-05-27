/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SYNTAX_TREE_H
#define SYNTAX_TREE_H

#include <stdio.h>
#include <inttypes.h>

#include <wsutil/ws_assert.h>
#include <wsutil/wslog.h>
#include <epan/ftypes/ftypes.h>
#include "dfilter-loc.h"

/** @file
 */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define ASSERT_STTYPE_NOT_REACHED(st) \
	ws_error("Invalid syntax node type '%s'.", sttype_name(st))

#define ASSERT_STNODE_OP_NOT_REACHED(op) \
	ws_error("Invalid stnode op '%s'.", stnode_op_name(op))

/**
 * @brief Type identifier tags for syntax tree nodes in the display filter compiler.
 */
typedef enum {
    STTYPE_UNINITIALIZED, /**< Node has not been assigned a type yet */
    STTYPE_TEST,          /**< Node represents a boolean test expression */
    STTYPE_UNPARSED,      /**< Raw lexical token; must be resolved to a literal or field */
    STTYPE_LITERAL,       /**< Node holds a resolved literal value */
    STTYPE_REFERENCE,     /**< Node holds a field reference (e.g., ${field}) */
    STTYPE_STRING,        /**< Node holds a quoted string constant */
    STTYPE_CHARCONST,     /**< Node holds a character constant */
    STTYPE_NUMBER,        /**< Node holds a numeric constant */
    STTYPE_FIELD,         /**< Node refers to a protocol header field (hfinfo) */
    STTYPE_FVALUE,        /**< Node holds a typed field value (fvalue_t) */
    STTYPE_SLICE,         /**< Node represents a byte-range slice expression */
    STTYPE_FUNCTION,      /**< Node represents a display filter function call */
    STTYPE_SET,           /**< Node represents a set literal for use with 'in' operator */
    STTYPE_PCRE,          /**< Node holds a compiled PCRE regular expression */
    STTYPE_ARITHMETIC,    /**< Node represents an arithmetic sub-expression */
    STTYPE_NUM_TYPES      /**< Sentinel value; total count of defined type IDs */
} sttype_id_t;


/**
 * @brief Allocates and initializes type-specific data for a syntax tree node.
 * @param data Pointer to initialization data passed to the constructor.
 * @return Pointer to the newly allocated type data, or NULL.
 */
typedef void *(*STTypeNewFunc)(void *data);

/**
 * @brief Performs a deep copy of type-specific node data.
 * @param data Pointer to the source type data to duplicate.
 * @return Pointer to the newly allocated duplicate, or NULL.
 */
typedef void *(*STTypeDupFunc)(const void *data);

/**
 * @brief Releases type-specific data associated with a syntax tree node.
 * @param data Pointer to the type data to free.
 */
typedef void (*STTypeFreeFunc)(void *data);

/**
 * @brief Converts type-specific node data to a human-readable string.
 * @param data   Pointer to the type data to render.
 * @param pretty If true, produce a display-friendly representation; otherwise a debug form.
 * @return Newly allocated string representation; caller is responsible for freeing it.
 */
typedef char *(*STTypeToStrFunc)(const void *data, bool pretty);


/**
 * @brief Describes a syntax tree node type, including its lifecycle and serialization callbacks.
 */
typedef struct {
    sttype_id_t     id;          /**< Unique type identifier from sttype_id_t */
    STTypeNewFunc   func_new;    /**< Constructor: allocates and initializes type data */
    STTypeFreeFunc  func_free;   /**< Destructor: releases type data */
    STTypeDupFunc   func_dup;    /**< Copy constructor: deep-duplicates type data */
    STTypeToStrFunc func_tostr;  /**< Serializer: converts type data to a string */
} sttype_t;


/**
 * @brief Numeric sub-type tag for STTYPE_NUMBER nodes.
 */
typedef enum {
    STNUM_NONE     = 0, /**< No numeric value; uninitialized */
    STNUM_INTEGER,      /**< Signed integer constant */
    STNUM_UNSIGNED,     /**< Unsigned integer constant */
    STNUM_FLOAT,        /**< Floating-point constant */
} stnumber_t;


/** @brief Lexical value is ambiguous and may represent either a protocol field or a literal value. */
#define STFLAG_UNPARSED (1 << 0)


/**
 * @brief A single node instance in the display filter syntax tree.
 */
typedef struct stnode {
    sttype_t *type;         /**< Pointer to the type descriptor for this node */
    void     *data;         /**< Type-specific payload managed by @ref sttype_t callbacks */
    char     *repr_token;   /**< Raw source token string as it appeared in the filter expression */
    char     *repr_display; /**< Human-readable display representation of this node */
    char     *repr_debug;   /**< Internal debug representation of this node */
    df_loc_t  location;     /**< Source location (offset/length) of this node in the filter string */
    uint16_t  flags;        /**< Bitmask of STFLAG_* flags (e.g., STFLAG_UNPARSED) */
} stnode_t;


/**
 * @brief Operator types for test and arithmetic syntax tree nodes.
 */
typedef enum {
    STNODE_OP_UNINITIALIZED, /**< Operator has not been set */
    STNODE_OP_NOT,           /**< Logical NOT */
    STNODE_OP_AND,           /**< Logical AND */
    STNODE_OP_OR,            /**< Logical OR */
    STNODE_OP_ALL_EQ,        /**< All-quantified equality (all values ==) */
    STNODE_OP_ANY_EQ,        /**< Any-quantified equality (any value ==) */
    STNODE_OP_ALL_NE,        /**< All-quantified inequality (all values !=) */
    STNODE_OP_ANY_NE,        /**< Any-quantified inequality (any value !=) */
    STNODE_OP_GT,            /**< Greater-than comparison */
    STNODE_OP_GE,            /**< Greater-than-or-equal comparison */
    STNODE_OP_LT,            /**< Less-than comparison */
    STNODE_OP_LE,            /**< Less-than-or-equal comparison */
    STNODE_OP_CONTAINS,      /**< Substring/value containment test */
    STNODE_OP_MATCHES,       /**< PCRE regular expression match */
    STNODE_OP_IN,            /**< Set membership test */
    STNODE_OP_NOT_IN,        /**< Set non-membership test */
    STNODE_OP_BITWISE_AND,   /**< Bitwise AND of two values */
    STNODE_OP_UNARY_MINUS,   /**< Arithmetic unary negation */
    STNODE_OP_ADD,           /**< Arithmetic addition */
    STNODE_OP_SUBTRACT,      /**< Arithmetic subtraction */
    STNODE_OP_MULTIPLY,      /**< Arithmetic multiplication */
    STNODE_OP_DIVIDE,        /**< Arithmetic division */
    STNODE_OP_MODULO,        /**< Arithmetic modulo */
} stnode_op_t;


/**
 * @brief Quantifier controlling how many field values must satisfy a match condition.
 */
typedef enum {
    STNODE_MATCH_DEF, /**< Default quantifier; behavior determined by operator context */
    STNODE_MATCH_ANY, /**< Match succeeds if any field value satisfies the condition */
    STNODE_MATCH_ALL, /**< Match succeeds only if all field values satisfy the condition */
} stmatch_t;

/* These are the sttype_t registration function prototypes. */
/**
 * @brief Register the field type in the syntax tree type system.
 */
void sttype_register_field(void);

/**
 * @brief Register the function type in the syntax tree type system.
 */
void sttype_register_function(void);

/**
 * @brief Register the number type in the syntax tree type system.
 */
void sttype_register_number(void);

/**
 * @brief Register the pointer type in the syntax tree type system.
 */
void sttype_register_pointer(void);

/**
 * @brief Register the set type in the syntax tree type system.
 */
void sttype_register_set(void);

/**
 * @brief Register the slice type in the syntax tree type system.
 */
void sttype_register_slice(void);

/**
 * @brief Register the string type in the syntax tree type system.
 */
void sttype_register_string(void);

/**
 * @brief Register the operator types in the syntax tree type system.
 */
void sttype_register_opers(void);

/**
 * @brief Initialize the syntax tree types.
 *
 * This function initializes the various types used in the syntax tree,
 * including fvalue, pcre, and charconst types.
 */
void
sttype_init(void);

/**
 * @brief Cleans up resources associated with the syntax tree types.
 *
 * This function is responsible for releasing any resources that were allocated
 * during the registration of various syntax tree types, such as strings,
 * literals, and unparsed types.
 */
void
sttype_cleanup(void);

/**
 * @brief Registers a syntax tree type.
 *
 * This function adds a new syntax tree type to the system, allowing it to be used in the construction of syntax trees.
 *
 * @param type The syntax tree type to register.
 */
void
sttype_register(sttype_t *type);

/**
 * @brief Get the name of a syntax tree type.
 *
 * @param type The syntax tree type ID.
 * @return The name of the syntax tree type, or "(unknown sttype)" if the type is not recognized.
 */
WS_DLL_PUBLIC
const char *
sttype_name(const sttype_id_t type);


/**
 * @brief Get the name of an operation based on its type.
 *
 * @param op The operation type to get the name for.
 * @return const char* The name of the operation or "(null)" if unknown.
 */
WS_DLL_PUBLIC
const char *
stnode_op_name(const stnode_op_t op);

/**
 * @brief Creates a new syntax tree node with the given type ID, data, token, and location.
 *
 * @param type_id The type ID of the node.
 * @param data The data associated with the node.
 * @param token The token representing the node.
 * @param loc The location information for the node.
 * @return A pointer to the newly created syntax tree node.
 */
WS_DLL_PUBLIC
stnode_t*
stnode_new(sttype_id_t type_id, void *data, char *token, df_loc_t loc);

/**
 * @brief Creates a new empty syntax tree node.
 *
 * @param type_id The type identifier for the new node.
 * @return A pointer to the newly created empty syntax tree node.
 */
WS_DLL_PUBLIC
stnode_t*
stnode_new_empty(sttype_id_t type_id);

/**
 * @brief Duplicates a syntax tree node.
 *
 * Creates a new syntax tree node that is a deep copy of the given node.
 *
 * @param org The original syntax tree node to duplicate.
 * @return A pointer to the newly created duplicated node.
 */
WS_DLL_PUBLIC
stnode_t*
stnode_dup(const stnode_t *org);

/**
 * @brief Clears the contents of a syntax tree node.
 *
 * This function releases any resources associated with the node and resets its fields to their initial state.
 *
 * @param node Pointer to the syntax tree node to be cleared.
 */
WS_DLL_PUBLIC
void
stnode_clear(stnode_t *node);

/**
 * @brief Initialize a syntax tree node.
 *
 * @param node Pointer to the syntax tree node to initialize.
 * @param type_id Type identifier for the node.
 * @param data Data associated with the node.
 * @param token Token string representing the node.
 * @param loc Location information for the node.
 */
WS_DLL_PUBLIC
void
stnode_init(stnode_t *node, sttype_id_t type_id, void *data, char *token, df_loc_t loc);

/**
 * @brief Replaces a node in the syntax tree with a new type and data.
 *
 * @param node Pointer to the node to be replaced.
 * @param type_id The new type ID for the node.
 * @param data Pointer to the new data for the node.
 */
WS_DLL_PUBLIC
void
stnode_replace(stnode_t *node, sttype_id_t type_id, void *data);

/**
 * @brief Mutates the type of a syntax tree node.
 *
 * @param node Pointer to the syntax tree node to be mutated.
 * @param type_id The new type ID for the node.
 */
WS_DLL_PUBLIC
void
stnode_mutate(stnode_t *node, sttype_id_t type_id);

/**
 * @brief Frees a syntax tree node.
 *
 * @param node Pointer to the syntax tree node to be freed.
 */
WS_DLL_PUBLIC
void
stnode_free(stnode_t *node);

/**
 * @brief Get the type name of a syntax tree node.
 *
 * @param node Pointer to the syntax tree node.
 * @return The type name of the node.
 */
WS_DLL_PUBLIC
const char*
stnode_type_name(const stnode_t *node);

/**
 * @brief Retrieves the type ID of a syntax tree node.
 *
 * @param node Pointer to the syntax tree node.
 * @return The type ID of the node, or STTYPE_UNINITIALIZED if not set.
 */
WS_DLL_PUBLIC
sttype_id_t
stnode_type_id(const stnode_t *node);

/**
 * @brief Retrieves the data associated with a syntax tree node.
 *
 * @param node Pointer to the syntax tree node.
 * @return Pointer to the data stored in the node.
 */
WS_DLL_PUBLIC
void *
stnode_data(stnode_t *node);

/**
 * @brief Retrieves the string data from a syntax tree node.
 *
 * @param node Pointer to the syntax tree node.
 * @return The string data stored in the node.
 */
WS_DLL_PUBLIC
GString *
stnode_string(stnode_t *node);

/**
 * @brief Steals and returns the data associated with a syntax tree node.
 *
 * @param node The syntax tree node from which to steal the data.
 * @return The stolen data, or NULL if no data was present.
 */
WS_DLL_PUBLIC
void *
stnode_steal_data(stnode_t *node);

WS_DLL_PUBLIC

/**
 * @brief Retrieves the token representation of a syntax tree node.
 *
 * @param node Pointer to the syntax tree node.
 * @return The token representation of the node.
 */
const char *
stnode_token(const stnode_t *node);

/**
 * @brief Get the location of a syntax tree node.
 *
 * @param node The syntax tree node to get the location from.
 * @return df_loc_t The location of the node.
 */
WS_DLL_PUBLIC
df_loc_t
stnode_location(const stnode_t *node);

/**
 * @brief Set the location for a syntax tree node.
 *
 * @param node The syntax tree node to set the location for.
 * @param loc The new location to set.
 */
WS_DLL_PUBLIC
void
stnode_set_location(stnode_t *node, df_loc_t loc);

/**
 * @brief Get flags from a syntax tree node.
 *
 * @param node Pointer to the syntax tree node.
 * @param flags Flags to retrieve.
 * @return uint16_t The intersection of the node's flags and the requested flags.
 */
WS_DLL_PUBLIC
bool
stnode_get_flags(stnode_t *node, uint16_t flags);

/**
 * @brief Sets flags for a syntax tree node.
 *
 * @param node Pointer to the syntax tree node.
 * @param flags Flags to be set.
 */
WS_DLL_PUBLIC
void
stnode_set_flags(stnode_t *node, uint16_t flags);

/**
 * @brief Merges location information from two syntax tree nodes into a destination node.
 *
 * This function updates the location of the destination node to encompass the locations of both input nodes.
 *
 * @param dst Pointer to the destination syntax tree node where the merged location will be stored.
 * @param n1 Pointer to the first source syntax tree node.
 * @param n2 Pointer to the second source syntax tree node.
 */
void
stnode_merge_location(stnode_t *dst, stnode_t *n1, stnode_t *n2);

/**
 * @brief Convert a syntax tree node to a string representation.
 *
 * @param node The syntax tree node to convert.
 * @param pretty If true, produce a pretty-printed string; otherwise, produce a debug-friendly string.
 * @return A string representing the syntax tree node.
 */
WS_DLL_PUBLIC
const char *
stnode_tostr(stnode_t *node, bool pretty);

/**
 * @brief Convert a syntax tree node to a printable string.
 *
 * This function returns a string representation of the syntax tree node that is suitable for display purposes.
 *
 * @param node The syntax tree node to convert.
 * @return A string representing the syntax tree node for display.
 */
#define stnode_todisplay(node) stnode_tostr(node, true)

/**
 * @brief Convert a syntax tree node to a debug string.
 *
 * This function returns a string representation of the syntax tree node that is suitable for debugging purposes.
 *
 * @param node The syntax tree node to convert.
 * @return A string representing the syntax tree node for debugging.
 */
#define stnode_todebug(node) stnode_tostr(node, false)

/**
 * @brief Logs a full message with detailed information about a syntax tree node.
 *
 * @param level The log level for this message.
 * @param file The source file where the function is called.
 * @param line The line number in the source file where the function is called.
 * @param func The name of the function calling this one.
 * @param node The syntax tree node to be logged.
 * @param msg A custom message to accompany the log entry.
 */
void
log_node_full(enum ws_log_level level,
			const char *file, int line, const char *func,
			stnode_t *node, const char *msg);

/**
 * @brief Logs a full test message for a syntax tree node.
 *
 * @param level The log level to use.
 * @param file The source file name where the function is called.
 * @param line The line number in the source file where the function is called.
 * @param func The function name where the function is called.
 * @param node The syntax tree node to log.
 * @param msg A message describing the test.
 */
void
log_test_full(enum ws_log_level level,
			const char *file, int line, const char *func,
			stnode_t *node, const char *msg);

#ifdef WS_DEBUG
#define log_node(node) \
	log_node_full(LOG_LEVEL_NOISY, __FILE__, __LINE__, __func__, node, #node)
#define log_test(node) \
	log_test_full(LOG_LEVEL_NOISY, __FILE__, __LINE__, __func__, node, #node)
#define LOG_NODE(node) \
	do { \
		if (stnode_type_id(node) == STTYPE_TEST) \
			log_test(node);			\
		else					\
			log_node(node);			\
	} while (0)
#else
#define log_node(node) (void)0
#define log_test(node) (void)0
#define LOG_NODE(node) (void)0
#endif

/**
 * @brief Dumps a syntax tree to a string.
 *
 * @param root Pointer to the root node of the syntax tree.
 * @return A string representation of the syntax tree.
 */
char *
dump_syntax_tree_str(stnode_t *root);

/**
 * @brief Logs a syntax tree with an optional message and caches the result.
 *
 * @param level The log level to use for logging.
 * @param root The root node of the syntax tree to log.
 * @param msg An optional message to include in the log entry.
 * @param cache_ptr A pointer to a char pointer where the logged string will be cached, or NULL if not needed.
 */
void
log_syntax_tree(enum ws_log_level level, stnode_t *root, const char *msg, char **cache_ptr);

#ifdef WS_DEBUG
#define ws_assert_magic(obj, mnum) \
	do { \
		ws_assert(obj); \
		if ((obj)->magic != (mnum)) { \
			ws_log_full(LOG_DOMAIN_DFILTER, LOG_LEVEL_ERROR, \
				__FILE__, __LINE__, __func__, \
				"Magic num is 0x%08" PRIx32", " \
				"but should be 0x%08" PRIx32, \
				(obj)->magic, (mnum)); \
		} \
	} while(0)
#else
#define ws_assert_magic(obj, mnum) (void)0
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SYNTAX_TREE_H */
