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

/** @file
 */

typedef enum {
	STTYPE_UNINITIALIZED,
	STTYPE_TEST,
	STTYPE_LITERAL,
	STTYPE_REFERENCE,
	STTYPE_STRING,
	STTYPE_CHARCONST,
	STTYPE_FIELD,
	STTYPE_FVALUE,
	STTYPE_SLICE,
	STTYPE_FUNCTION,
	STTYPE_SET,
	STTYPE_PCRE,
	STTYPE_ARITHMETIC,
	STTYPE_NUM_TYPES
} sttype_id_t;

typedef gpointer        (*STTypeNewFunc)(gpointer);
typedef gpointer        (*STTypeDupFunc)(gconstpointer);
typedef void            (*STTypeFreeFunc)(gpointer);
typedef char*           (*STTypeToStrFunc)(gconstpointer, gboolean pretty);


/* Type information */
typedef struct {
	sttype_id_t		id;
	const char		*name;
	STTypeNewFunc		func_new;
	STTypeFreeFunc		func_free;
	STTypeDupFunc		func_dup;
	STTypeToStrFunc		func_tostr;
} sttype_t;

typedef struct {
	long col_start;
	size_t col_len;
} stloc_t;

/** Node (type instance) information */
typedef struct {
	uint32_t	magic;
	sttype_t	*type;
	gpointer	data;
	char 		*repr_token;
	char 		*repr_display;
	char 		*repr_debug;
	stloc_t		location;
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

stnode_t*
stnode_new(sttype_id_t type_id, gpointer data, char *token, const stloc_t *loc);

stnode_t*
stnode_dup(const stnode_t *org);

void
stnode_clear(stnode_t *node);

void
stnode_init(stnode_t *node, sttype_id_t type_id, gpointer data, char *token, const stloc_t *loc);

void
stnode_replace(stnode_t *node, sttype_id_t type_id, gpointer data);

void
stnode_free(stnode_t *node);

const char*
stnode_type_name(stnode_t *node);

sttype_id_t
stnode_type_id(stnode_t *node);

gpointer
stnode_data(stnode_t *node);

GString *
stnode_string(stnode_t *node);

gpointer
stnode_steal_data(stnode_t *node);

const char *
stnode_token(stnode_t *node);

stloc_t *
stnode_location(stnode_t *node);

const char *
stnode_tostr(stnode_t *node, gboolean pretty);

#define stnode_todisplay(node) stnode_tostr(node, TRUE)

#define stnode_todebug(node) stnode_tostr(node, FALSE)

void
log_node_full(enum ws_log_level level,
			const char *file, int line, const char *func,
			stnode_t *node, const char *msg);

void
log_test_full(enum ws_log_level level,
			const char *file, int line, const char *func,
			stnode_t *node, const char *msg);

#ifdef WS_DISABLE_DEBUG
#define log_node(node) (void)0;
#define log_test(node) (void)0;
#define LOG_NODE(node) (void)0;
#else
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
#endif

char *
dump_syntax_tree_str(stnode_t *root);

void
log_syntax_tree(enum ws_log_level, stnode_t *root, const char *msg, char **cache_ptr);

#ifdef WS_DISABLE_DEBUG
#define ws_assert_magic(obj, mnum) (void)0
#else
#define ws_assert_magic(obj, mnum) \
	do { \
		ws_assert(obj); \
		if ((obj)->magic != (mnum)) { \
			ws_log_full(LOG_DOMAIN_DFILTER, LOG_LEVEL_CRITICAL, \
				__FILE__, __LINE__, __func__, \
				"Magic num is 0x%08"PRIx32", " \
				"but should be 0x%08"PRIx32, \
				(obj)->magic, (mnum)); \
		} \
	} while(0)
#endif

#endif /* SYNTAX_TREE_H */
