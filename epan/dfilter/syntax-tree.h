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
#include <stdint.h>
#include <glib.h>

#include "ws_log_defs.h"

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
	STTYPE_INTEGER,
	STTYPE_RANGE,
	STTYPE_FUNCTION,
	STTYPE_SET,
	STTYPE_PCRE,
	STTYPE_NUM_TYPES
} sttype_id_t;

typedef gpointer        (*STTypeNewFunc)(gpointer);
typedef gpointer        (*STTypeDupFunc)(gconstpointer);
typedef void            (*STTypeFreeFunc)(gpointer);
typedef char*           (*STTypeToStrFunc)(gconstpointer);


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

	/* This could be made an enum, but I haven't
	 * set aside to time to do so. */
	gpointer	data;
	int32_t		value;

	char		*token_value;
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
stnode_new(sttype_id_t type_id, gpointer data, const char *token_value);

stnode_t*
stnode_dup(const stnode_t *org);

void
stnode_clear(stnode_t *node);

void
stnode_init(stnode_t *node, sttype_id_t type_id, gpointer data, const char *token_value);

void
stnode_init_int(stnode_t *node, sttype_id_t type_id, gint32 value, const char *token_value);

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

gint32
stnode_value(stnode_t *node);

const char *
stnode_token_value(stnode_t *node);

char *
stnode_tostr(stnode_t *node);

gboolean
stnode_inside_parens(stnode_t *node);

void
stnode_set_inside_parens(stnode_t *node, gboolean inside);

void
log_stnode_full(enum ws_log_level level,
			const char *file, int line, const char *func,
			stnode_t *node, const char *msg);

#ifdef WS_DISABLE_DEBUG
#define log_stnode(node) (void)0;
#else
#define log_stnode(node) \
	log_stnode_full(LOG_LEVEL_NOISY, __FILE__, __LINE__, __func__, node, #node)
#endif

void
log_syntax_tree(enum ws_log_level, stnode_t *root, const char *msg);

void
ws_assert_magic_full(const char *domain, enum ws_log_level level,
				const char *file, int line, const char *func,
				const void *node, uint32_t magic);

#ifdef WS_DISABLE_DEBUG
#define ws_assert_magic(obj, mnum) (void)0
#else
#define ws_assert_magic(obj, mnum) \
	ws_assert_magic_full(LOG_DOMAIN_DFILTER, LOG_LEVEL_CRITICAL, \
			__FILE__, __LINE__, __func__, \
			obj, mnum)
#endif

#endif /* SYNTAX_TREE_H */
