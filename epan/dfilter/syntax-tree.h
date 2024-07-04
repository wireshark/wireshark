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
#include <glib.h>

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

typedef enum {
	STTYPE_UNINITIALIZED,
	STTYPE_TEST,
	STTYPE_UNPARSED, /* Must be resolved into a literal or a field. */
	STTYPE_LITERAL,
	STTYPE_REFERENCE,
	STTYPE_STRING,
	STTYPE_CHARCONST,
	STTYPE_NUMBER,
	STTYPE_FIELD,
	STTYPE_FVALUE,
	STTYPE_SLICE,
	STTYPE_FUNCTION,
	STTYPE_SET,
	STTYPE_PCRE,
	STTYPE_ARITHMETIC,
	STTYPE_NUM_TYPES
} sttype_id_t;

typedef void *          (*STTypeNewFunc)(void *);
typedef void *          (*STTypeDupFunc)(const void *);
typedef void            (*STTypeFreeFunc)(void *);
typedef char*           (*STTypeToStrFunc)(const void *, bool pretty);


/* Type information */
typedef struct {
	sttype_id_t		id;
	STTypeNewFunc		func_new;
	STTypeFreeFunc		func_free;
	STTypeDupFunc		func_dup;
	STTypeToStrFunc		func_tostr;
} sttype_t;

typedef enum {
	STNUM_NONE = 0,
	STNUM_INTEGER,
	STNUM_UNSIGNED,
	STNUM_FLOAT,
} stnumber_t;

/* Lexical value is ambiguous (can be a protocol field or a literal). */
#define STFLAG_UNPARSED		(1 << 0)

/** Node (type instance) information */
typedef struct stnode {
	sttype_t	*type;
	void 		*data;
	char 		*repr_token;
	char 		*repr_display;
	char 		*repr_debug;
	df_loc_t	location;
	uint16_t	flags;
} stnode_t;

typedef enum {
	STNODE_OP_UNINITIALIZED,
	STNODE_OP_NOT,
	STNODE_OP_AND,
	STNODE_OP_OR,
	STNODE_OP_ALL_EQ,
	STNODE_OP_ANY_EQ,
	STNODE_OP_ALL_NE,
	STNODE_OP_ANY_NE,
	STNODE_OP_GT,
	STNODE_OP_GE,
	STNODE_OP_LT,
	STNODE_OP_LE,
	STNODE_OP_CONTAINS,
	STNODE_OP_MATCHES,
	STNODE_OP_IN,
	STNODE_OP_NOT_IN,
	STNODE_OP_BITWISE_AND,
	STNODE_OP_UNARY_MINUS,
	STNODE_OP_ADD,
	STNODE_OP_SUBTRACT,
	STNODE_OP_MULTIPLY,
	STNODE_OP_DIVIDE,
	STNODE_OP_MODULO,
} stnode_op_t;

typedef enum {
	STNODE_MATCH_DEF,
	STNODE_MATCH_ANY,
	STNODE_MATCH_ALL,
} stmatch_t;

/* These are the sttype_t registration function prototypes. */
void sttype_register_field(void);
void sttype_register_function(void);
void sttype_register_number(void);
void sttype_register_pointer(void);
void sttype_register_set(void);
void sttype_register_slice(void);
void sttype_register_string(void);
void sttype_register_opers(void);

void
sttype_init(void);

void
sttype_cleanup(void);

void
sttype_register(sttype_t *type);

WS_DLL_PUBLIC
const char *
sttype_name(sttype_id_t type);

WS_DLL_PUBLIC
const char *
stnode_op_name(stnode_op_t op);

WS_DLL_PUBLIC
stnode_t*
stnode_new(sttype_id_t type_id, void *data, char *token, df_loc_t loc);

WS_DLL_PUBLIC
stnode_t*
stnode_new_empty(sttype_id_t type_id);

WS_DLL_PUBLIC
stnode_t*
stnode_dup(const stnode_t *org);

WS_DLL_PUBLIC
void
stnode_clear(stnode_t *node);

WS_DLL_PUBLIC
void
stnode_init(stnode_t *node, sttype_id_t type_id, void *data, char *token, df_loc_t loc);

WS_DLL_PUBLIC
void
stnode_replace(stnode_t *node, sttype_id_t type_id, void *data);

WS_DLL_PUBLIC
void
stnode_mutate(stnode_t *node, sttype_id_t type_id);

WS_DLL_PUBLIC
void
stnode_free(stnode_t *node);

WS_DLL_PUBLIC
const char*
stnode_type_name(stnode_t *node);

WS_DLL_PUBLIC
sttype_id_t
stnode_type_id(stnode_t *node);

WS_DLL_PUBLIC
void *
stnode_data(stnode_t *node);

WS_DLL_PUBLIC
GString *
stnode_string(stnode_t *node);

WS_DLL_PUBLIC
void *
stnode_steal_data(stnode_t *node);

WS_DLL_PUBLIC
const char *
stnode_token(stnode_t *node);

WS_DLL_PUBLIC
df_loc_t
stnode_location(stnode_t *node);

WS_DLL_PUBLIC
void
stnode_set_location(stnode_t *node, df_loc_t loc);

WS_DLL_PUBLIC
bool
stnode_get_flags(stnode_t *node, uint16_t flags);

WS_DLL_PUBLIC
void
stnode_set_flags(stnode_t *node, uint16_t flags);

void
stnode_merge_location(stnode_t *dst, stnode_t *n1, stnode_t *n2);

WS_DLL_PUBLIC
const char *
stnode_tostr(stnode_t *node, bool pretty);

#define stnode_todisplay(node) stnode_tostr(node, true)

#define stnode_todebug(node) stnode_tostr(node, false)

void
log_node_full(enum ws_log_level level,
			const char *file, int line, const char *func,
			stnode_t *node, const char *msg);

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

char *
dump_syntax_tree_str(stnode_t *root);

void
log_syntax_tree(enum ws_log_level, stnode_t *root, const char *msg, char **cache_ptr);

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
