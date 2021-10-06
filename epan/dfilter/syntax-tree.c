/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#define WS_LOG_DOMAIN LOG_DOMAIN_DFILTER

#include <inttypes.h>
#include "syntax-tree.h"
#include <wsutil/ws_assert.h>
#include <wsutil/wslog.h>
#include <wsutil/wmem/wmem.h>
#include <wsutil/str_util.h>
#include "sttype-test.h"

/* Keep track of sttype_t's via their sttype_id_t number */
static sttype_t* type_list[STTYPE_NUM_TYPES];


#define STNODE_MAGIC	0xe9b00b9e


void
sttype_init(void)
{
	sttype_register_function();
	sttype_register_integer();
	sttype_register_pointer();
	sttype_register_range();
	sttype_register_set();
	sttype_register_string();
	sttype_register_test();
}

void
sttype_cleanup(void)
{
	/* nothing to do */
}


void
sttype_register(sttype_t *type)
{
	sttype_id_t	type_id;

	type_id = type->id;

	/* Check input */
	ws_assert(type_id < STTYPE_NUM_TYPES);

	/* Don't re-register. */
	ws_assert(type_list[type_id] == NULL);

	type_list[type_id] = type;
}

static sttype_t*
sttype_lookup(sttype_id_t type_id)
{
	sttype_t	*result;

	/* Check input */
	ws_assert(type_id < STTYPE_NUM_TYPES);

	result = type_list[type_id];

	/* Check output. */
	ws_assert(result != NULL);

	return result;
}

static void
_node_clear(stnode_t *node)
{
	ws_assert_magic(node, STNODE_MAGIC);
	if (node->type) {
		if (node->type->func_free && node->data) {
			node->type->func_free(node->data);
		}
	}
	else {
		ws_assert(!node->data);
	}

	node->type = NULL;
	node->flags = 0;
	node->data = NULL;
	node->value = 0;
}

void
stnode_clear(stnode_t *node)
{
	_node_clear(node);
	g_free(node->token_value);
	node->token_value = NULL;
}

static void
_node_init(stnode_t *node, sttype_id_t type_id, gpointer data)
{
	sttype_t	*type;

	ws_assert_magic(node, STNODE_MAGIC);
	ws_assert(!node->type);
	ws_assert(!node->data);
	node->flags = 0;
	node->value = 0;

	if (type_id == STTYPE_UNINITIALIZED) {
		node->type = NULL;
		node->data = NULL;
	}
	else {
		type = sttype_lookup(type_id);
		ws_assert(type);
		node->type = type;
		if (type->func_new) {
			node->data = type->func_new(data);
		}
		else {
			node->data = data;
		}
	}
}

void
stnode_init(stnode_t *node, sttype_id_t type_id, gpointer data,  const char *token_value)
{
	_node_init(node, type_id, data);
	ws_assert(node->token_value == NULL);
	node->token_value = g_strdup(token_value);
}

void
stnode_init_int(stnode_t *node, sttype_id_t type_id, gint32 value, const char *token_value)
{
	stnode_init(node, type_id, NULL, token_value);
	node->value = value;
}

void
stnode_replace(stnode_t *node, sttype_id_t type_id, gpointer data)
{
	uint16_t flags = node->flags; /* Save flags. */
	_node_clear(node);
	_node_init(node, type_id, data);
	node->flags = flags;
}

stnode_t*
stnode_new(sttype_id_t type_id, gpointer data, const char *token_value)
{
	stnode_t	*node;

	node = g_new0(stnode_t, 1);
	node->magic = STNODE_MAGIC;

	stnode_init(node, type_id, data, token_value);

	return node;
}

stnode_t*
stnode_dup(const stnode_t *org)
{
	sttype_t	*type;
	stnode_t	*node;

	if (!org)
		return NULL;

	type = org->type;

	node = g_new(stnode_t, 1);
	node->magic = STNODE_MAGIC;

	node->type = type;
	node->flags = org->flags;

	if (type && type->func_dup)
		node->data = type->func_dup(org->data);
	else
		node->data = org->data;
	node->value = org->value;

	node->token_value = g_strdup(org->token_value);

	return node;
}

void
stnode_free(stnode_t *node)
{
	ws_assert_magic(node, STNODE_MAGIC);
	stnode_clear(node);
	g_free(node);
}

const char*
stnode_type_name(stnode_t *node)
{
	ws_assert_magic(node, STNODE_MAGIC);
	if (node->type)
		return node->type->name;
	else
		return "UNINITIALIZED";
}

sttype_id_t
stnode_type_id(stnode_t *node)
{
	ws_assert_magic(node, STNODE_MAGIC);
	if (node->type)
		return node->type->id;
	else
		return STTYPE_UNINITIALIZED;
}

gpointer
stnode_data(stnode_t *node)
{
	ws_assert_magic(node, STNODE_MAGIC);
	return node->data;
}

gpointer
stnode_steal_data(stnode_t *node)
{
	ws_assert_magic(node, STNODE_MAGIC);
	gpointer data = node->data;
	ws_assert(data);
	node->data = NULL;
	return data;
}

gint32
stnode_value(stnode_t *node)
{
	ws_assert_magic(node, STNODE_MAGIC);
	return node->value;
}

const char *
stnode_token_value(stnode_t *node)
{
	if (node->token_value) {
		return node->token_value;
	}
	return "<unknown token>";
}

gboolean
stnode_inside_parens(stnode_t *node)
{
	return node->flags & STNODE_F_INSIDE_PARENS;
}

void
stnode_set_inside_parens(stnode_t *node, gboolean inside)
{
	if (inside) {
		node->flags |= STNODE_F_INSIDE_PARENS;
	}
	else {
		node->flags &= ~STNODE_F_INSIDE_PARENS;
	}
}

char *
stnode_tostr(stnode_t *node)
{
	if (stnode_type_id(node) == STTYPE_INTEGER)
		return g_strdup_printf("%"PRId32, stnode_value(node));

	if (node->type->func_tostr == NULL)
		return g_strdup("<FIXME>");

	return node->type->func_tostr(node->data);
}

static char *
sprint_node(stnode_t *node)
{
	wmem_strbuf_t *buf = wmem_strbuf_new(NULL, NULL);
	char *s;

	wmem_strbuf_append_printf(buf, "stnode <%p> = {\n", (void *)node);
	wmem_strbuf_append_printf(buf, "\tmagic = %"PRIx32"\n", node->magic);
	wmem_strbuf_append_printf(buf, "\ttype = %s\n", stnode_type_name(node));
	wmem_strbuf_append_printf(buf,
			"\tflags = %"PRIx16" (inside_parens = %s)\n",
			node->flags, true_or_false(stnode_inside_parens(node)));
	s = stnode_tostr(node);
	wmem_strbuf_append_printf(buf, "\tdata = %s<%s>\n", stnode_type_name(node), s);
	g_free(s);
	wmem_strbuf_append_printf(buf, "\tvalue = %"PRId32"\n", stnode_value(node));
	wmem_strbuf_append_printf(buf, "}\n");
	return wmem_strbuf_finalize(buf);
}

void
log_stnode_full(enum ws_log_level level,
			const char *file, int line, const char *func,
			stnode_t *node, const char *msg)
{
	if (!ws_log_msg_is_active(LOG_DOMAIN_DFILTER, level))
		return;

	char *str = sprint_node(node);
	ws_log_write_always_full(LOG_DOMAIN_DFILTER, level,
					file, line, func, "%s:\n%s", msg, str);
	g_free(str);
}

static void
indent(wmem_strbuf_t *buf, int level)
{
	for (int i = 0; i < level * 2; i++) {
		wmem_strbuf_append_c(buf, ' ');
	}
}

static void
visit_tree(wmem_strbuf_t *buf, stnode_t *node, int level)
{
	stnode_t *left, *right;
	char *str;

	if (stnode_type_id(node) == STTYPE_TEST) {
		str = stnode_tostr(node);
		wmem_strbuf_append_printf(buf, "%s(", str);
		g_free(str);
		sttype_test_get(node, NULL, &left, &right);
		if (left && right) {
			wmem_strbuf_append_c(buf, '\n');
			indent(buf, level + 1);
			wmem_strbuf_append(buf, "LHS = ");
			visit_tree(buf, left, level + 1);
			wmem_strbuf_append_c(buf, '\n');
			indent(buf, level + 1);
			wmem_strbuf_append(buf, "RHS = ");
			visit_tree(buf, right, level + 1);
			wmem_strbuf_append(buf, "\n");
			indent(buf, level);
		}
		else if (left) {
			visit_tree(buf, left, level);
		}
		else if (right) {
			visit_tree(buf, right, level);
		}
		wmem_strbuf_append(buf, ")");
	}
	else {
		str = stnode_tostr(node);
		wmem_strbuf_append_printf(buf, "%s<%s>", stnode_type_name(node), str);
		g_free(str);
	}
}

void
log_syntax_tree(enum ws_log_level level, stnode_t *root, const char *msg)
{
	if (!ws_log_msg_is_active(LOG_DOMAIN_DFILTER, level))
		return;

	wmem_strbuf_t *buf = wmem_strbuf_new(NULL, NULL);

	visit_tree(buf, root, 0);
	ws_log_write_always_full(LOG_DOMAIN_DFILTER, level, NULL, -1, NULL,
				"%s:\n%s", msg, wmem_strbuf_get_str(buf));
	wmem_strbuf_destroy(buf);
}

void
ws_assert_magic_full(const char *domain, enum ws_log_level level,
				const char *file, int line, const char *func,
				const void *ptr, uint32_t magic)
{
	const stnode_t *node = (const stnode_t *)ptr;
	ws_assert(node);
	if (node->magic != magic) {
		ws_log_full(domain, level, file, line, func,
			"Magic num is 0x%08"PRIx32", but should be 0x%08"PRIx32,
			node->magic, magic);
	}
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
