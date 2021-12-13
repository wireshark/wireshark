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

/** @file
 */

typedef enum {
	STTYPE_UNINITIALIZED,
	STTYPE_TEST,
	STTYPE_UNPARSED,
	STTYPE_STRING,
	STTYPE_CHARCONST,
	STTYPE_FIELD,
	STTYPE_FVALUE,
	STTYPE_RANGE,
	STTYPE_FUNCTION,
	STTYPE_SET,
	STTYPE_PCRE,
	STTYPE_NUM_TYPES
} sttype_id_t;

typedef enum {
	TEST_OP_UNINITIALIZED,
	TEST_OP_EXISTS,
	TEST_OP_NOT,
	TEST_OP_AND,
	TEST_OP_OR,
	TEST_OP_ALL_EQ,
	TEST_OP_ANY_EQ,
	TEST_OP_ALL_NE,
	TEST_OP_ANY_NE,
	TEST_OP_GT,
	TEST_OP_GE,
	TEST_OP_LT,
	TEST_OP_LE,
	TEST_OP_BITWISE_AND,
	TEST_OP_CONTAINS,
	TEST_OP_MATCHES,
	TEST_OP_IN
} test_op_t;

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

#define STNODE_F_INSIDE_PARENS (1 << 0)

/** Node (type instance) information */
typedef struct {
	uint32_t	magic;
	sttype_t	*type;
	uint16_t	flags;
	gpointer	data;
	char 		*repr_token;
	char 		*repr_display;
	char 		*repr_debug;
} stnode_t;

/* These are the sttype_t registration function prototypes. */
void sttype_register_function(void);
void sttype_register_integer(void);
void sttype_register_pointer(void);
void sttype_register_range(void);
void sttype_register_set(void);
void sttype_register_string(void);
void sttype_register_test(void);

void
sttype_init(void);

void
sttype_cleanup(void);

void
sttype_register(sttype_t *type);

stnode_t*
stnode_new(sttype_id_t type_id, gpointer data, char *token);

stnode_t *
stnode_new_test(test_op_t op, char *token);

stnode_t *
stnode_new_string(const char *str, char *token);

stnode_t *
stnode_new_unparsed(const char *str, char *token);

stnode_t *
stnode_new_charconst(unsigned long number, char *token);

stnode_t*
stnode_dup(const stnode_t *org);

void
stnode_clear(stnode_t *node);

void
stnode_init(stnode_t *node, sttype_id_t type_id, gpointer data, char *token);

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

gpointer
stnode_steal_data(stnode_t *node);

const char *
stnode_tostr(stnode_t *node, gboolean pretty);

#define stnode_todisplay(node) stnode_tostr(node, TRUE)

#define stnode_todebug(node) stnode_tostr(node, FALSE)

gboolean
stnode_inside_parens(stnode_t *node);

void
stnode_set_inside_parens(stnode_t *node, gboolean inside);

void
log_test_full(enum ws_log_level level,
			const char *file, int line, const char *func,
			stnode_t *node, const char *msg);

#ifdef WS_DISABLE_DEBUG
#define log_test(node) (void)0;
#else
#define log_test(node) \
	log_test_full(LOG_LEVEL_NOISY, __FILE__, __LINE__, __func__, node, #node)
#endif

void
log_syntax_tree(enum ws_log_level, stnode_t *root, const char *msg);

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
