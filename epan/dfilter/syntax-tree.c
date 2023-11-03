/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#define WS_LOG_DOMAIN LOG_DOMAIN_DFILTER

#include "syntax-tree.h"
#include <wsutil/wmem/wmem.h>
#include <wsutil/str_util.h>
#include <wsutil/glib-compat.h>
#include "sttype-op.h"
#include "sttype-function.h"
#include "dfilter-int.h"

/* Keep track of sttype_t's via their sttype_id_t number */
static sttype_t* type_list[STTYPE_NUM_TYPES];


void
sttype_init(void)
{
	sttype_register_field();
	sttype_register_function();
	sttype_register_number();
	sttype_register_pointer();
	sttype_register_set();
	sttype_register_slice();
	sttype_register_string();
	sttype_register_opers();
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

const char *
sttype_name(sttype_id_t type)
{
	switch (type) {
		case STTYPE_UNINITIALIZED: return "UNINITIALIZED";
		case STTYPE_TEST:	return "TEST";
		case STTYPE_LITERAL:	return "LITERAL";
		case STTYPE_UNPARSED:	return "UNPARSED";
		case STTYPE_REFERENCE:	return "REFERENCE";
		case STTYPE_STRING:	return "STRING";
		case STTYPE_CHARCONST:	return "CHARCONST";
		case STTYPE_NUMBER:	return "NUMBER";
		case STTYPE_FIELD:	return "FIELD";
		case STTYPE_FVALUE:	return "FVALUE";
		case STTYPE_SLICE:	return "SLICE";
		case STTYPE_FUNCTION:	return "FUNCTION";
		case STTYPE_SET:	return "SET";
		case STTYPE_PCRE:	return "PCRE";
		case STTYPE_ARITHMETIC:	return "ARITHMETIC";
		case STTYPE_NUM_TYPES:	return "NUM_TYPES";
	}
	return "(unknown sttype)";
}

const char *
stnode_op_name(stnode_op_t op)
{
	const char *s = "(null)";

	switch(op) {
		case STNODE_OP_NOT:
			s = "TEST_NOT";
			break;
		case STNODE_OP_AND:
			s = "TEST_AND";
			break;
		case STNODE_OP_OR:
			s = "TEST_OR";
			break;
		case STNODE_OP_ALL_EQ:
			s = "TEST_ALL_EQ";
			break;
		case STNODE_OP_ANY_EQ:
			s = "TEST_ANY_EQ";
			break;
		case STNODE_OP_ALL_NE:
			s = "TEST_ALL_NE";
			break;
		case STNODE_OP_ANY_NE:
			s = "TEST_ANY_NE";
			break;
		case STNODE_OP_GT:
			s = "TEST_GT";
			break;
		case STNODE_OP_GE:
			s = "TEST_GE";
			break;
		case STNODE_OP_LT:
			s = "TEST_LT";
			break;
		case STNODE_OP_LE:
			s = "TEST_LE";
			break;
		case STNODE_OP_BITWISE_AND:
			s = "OP_BITWISE_AND";
			break;
		case STNODE_OP_UNARY_MINUS:
			s = "OP_UNARY_MINUS";
			break;
		case STNODE_OP_ADD:
			s = "OP_ADD";
			break;
		case STNODE_OP_SUBTRACT:
			s = "OP_SUBTRACT";
			break;
		case STNODE_OP_MULTIPLY:
			s = "OP_MULTIPLY";
			break;
		case STNODE_OP_DIVIDE:
			s = "OP_DIVIDE";
			break;
		case STNODE_OP_MODULO:
			s = "OP_MODULO";
			break;
		case STNODE_OP_CONTAINS:
			s = "TEST_CONTAINS";
			break;
		case STNODE_OP_MATCHES:
			s = "TEST_MATCHES";
			break;
		case STNODE_OP_IN:
			s = "TEST_IN";
			break;
		case STNODE_OP_NOT_IN:
			s = "TEST_NOT_IN";
			break;
		case STNODE_OP_UNINITIALIZED:
			s = "(uninitialized)";
			break;
	}

	return s;
}

void
stnode_clear(stnode_t *node)
{
	if (node->type) {
		if (node->type->func_free && node->data) {
			node->type->func_free(node->data);
		}
	}
	else {
		ws_assert(!node->data);
	}

	node->type = NULL;
	node->data = NULL;
	g_free(node->repr_display);
	node->repr_display = NULL;
	g_free(node->repr_debug);
	node->repr_debug = NULL;
	g_free(node->repr_token);
	node->repr_token = NULL;
	node->location.col_start = -1;
	node->location.col_len = 0;
	node->flags = 0;
}

void
stnode_init(stnode_t *node, sttype_id_t type_id, void *data, char *token, df_loc_t loc)
{
	sttype_t	*type;

	ws_assert(!node->type);
	ws_assert(!node->data);
	node->repr_display = NULL;
	node->repr_debug = NULL;
	node->repr_token = token;
	node->location = loc;
	node->flags = 0;

	if (type_id == STTYPE_UNINITIALIZED) {
		node->type = NULL;
		node->data = NULL;
	}
	else {
		/* Creating an initialized node with a NULL pointer is
		 * allowed and needs to be safe. The parser relies on that. */
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
stnode_replace(stnode_t *node, sttype_id_t type_id, void *data)
{
	char *token = g_strdup(node->repr_token);
	df_loc_t loc = node->location;
	uint16_t flags = node->flags;
	stnode_clear(node);
	stnode_init(node, type_id, data, token, loc);
	node->flags = flags;
}

void
stnode_mutate(stnode_t *node, sttype_id_t type_id)
{
	//FIXME: Assert there all the same sttype
	node->type = sttype_lookup(type_id);
	ws_assert(node->type);
}

stnode_t*
stnode_new(sttype_id_t type_id, void *data, char *token, df_loc_t loc)
{
	stnode_t *node = g_new0(stnode_t, 1);
	stnode_init(node, type_id, data, token, loc);
	return node;
}

stnode_t*
stnode_new_empty(sttype_id_t type_id)
{
	df_loc_t loc = {-1, 0};
	return stnode_new(type_id, NULL, NULL, loc);
}

stnode_t*
stnode_dup(const stnode_t *node)
{
	stnode_t *new;

	new = g_new(stnode_t, 1);
	new->repr_display = NULL;
	new->repr_debug = NULL;
	new->repr_token = g_strdup(node->repr_token);
	new->location = node->location;
	new->flags = node->flags;

	new->type = node->type;
	if (node->type == NULL)
		new->data = NULL;
	else if (node->type->func_dup)
		new->data = node->type->func_dup(node->data);
	else
		new->data = node->data;

	return new;
}

void
stnode_free(stnode_t *node)
{
	stnode_clear(node);
	g_free(node);
}

const char*
stnode_type_name(stnode_t *node)
{
	return sttype_name(node->type->id);
}

sttype_id_t
stnode_type_id(stnode_t *node)
{
	if (node->type)
		return node->type->id;
	else
		return STTYPE_UNINITIALIZED;
}

void *
stnode_data(stnode_t *node)
{
	return node->data;
}

GString *
stnode_string(stnode_t *node)
{
	ws_assert(stnode_type_id(node) == STTYPE_STRING);
	return stnode_data(node);
}

void *
stnode_steal_data(stnode_t *node)
{
	void *data = node->data;
	ws_assert(data);
	node->data = NULL;
	return data;
}

const char *
stnode_token(stnode_t *node)
{
	return node->repr_token;
}

df_loc_t
stnode_location(stnode_t *node)
{
	return node->location;
}

void
stnode_set_location(stnode_t *node, df_loc_t loc)
{
	node->location = loc;
}

bool
stnode_get_flags(stnode_t *node, uint16_t flags)
{
	return node->flags & flags;
}

void
stnode_set_flags(stnode_t *node, uint16_t flags)
{
	node->flags |= flags;
}

/* Finds the first and last location from a set and creates
 * a new location from start of first (col_start) to end of
 * last (col_start + col_len). Sets the result to dst. */
void
stnode_merge_location(stnode_t *dst, stnode_t *n1, stnode_t *n2)
{
	df_loc_t first, last;
	df_loc_t loc2;

	first = last = stnode_location(n1);
	loc2 = stnode_location(n2);
	if (loc2.col_start >= 0 && loc2.col_start > first.col_start)
		last = loc2;
	dst->location.col_start = first.col_start;
	dst->location.col_len = last.col_start - first.col_start + last.col_len;
}

#define IS_OPERATOR(node) \
	(stnode_type_id(node) == STTYPE_TEST || \
		stnode_type_id(node) == STTYPE_ARITHMETIC)

static char *
_node_tostr(stnode_t *node, bool pretty)
{
	char *s, *repr;

	if (node->type->func_tostr == NULL)
		s = g_strdup("FIXME");
	else
		s = node->type->func_tostr(node->data, pretty);

	if (pretty)
		return s;

	if (IS_OPERATOR(node)) {
		repr = s;
	}
	else {
		repr = ws_strdup_printf("%s(%s)", stnode_type_name(node), s);
		g_free(s);
	}

	return repr;
}

const char *
stnode_tostr(stnode_t *node, bool pretty)
{
	if (pretty && IS_OPERATOR(node) && node->repr_token != NULL) {
		/* Some operators can have synonyms, like "or" and "||".
		 * Show the user the same representation as he typed. */
		g_free(node->repr_display);
		node->repr_display = g_strdup(node->repr_token);
		return node->repr_display;
	}

	char *str = _node_tostr(node, pretty);

	if (pretty) {
		g_free(node->repr_display);
		node->repr_display = str;
	}
	else {
		g_free(node->repr_debug);
		node->repr_debug = str;
	}

	return str;
}

static char *
sprint_node(stnode_t *node)
{
	wmem_strbuf_t *buf = wmem_strbuf_new(NULL, NULL);

	wmem_strbuf_append_printf(buf, "{ ");
	wmem_strbuf_append_printf(buf, "type = %s, ", stnode_type_name(node));
	wmem_strbuf_append_printf(buf, "data = %s, ", stnode_todebug(node));
	wmem_strbuf_append_printf(buf, "location = %ld:%zu",
			node->location.col_start, node->location.col_len);
	wmem_strbuf_append_printf(buf, " }");
	return wmem_strbuf_finalize(buf);
}

void
log_node_full(enum ws_log_level level,
			const char *file, int line, const char *func,
			stnode_t *node, const char *msg)
{
	if (!ws_log_msg_is_active(WS_LOG_DOMAIN, level))
		return;

	if (node == NULL) {
		ws_log_write_always_full(WS_LOG_DOMAIN, level,
					file, line, func, "%s is NULL", msg);
		return;
	}

	char *str = sprint_node(node);

	ws_log_write_always_full(WS_LOG_DOMAIN, level, file, line, func,
				"%s = %s", msg, str);

	g_free(str);
}

void
log_test_full(enum ws_log_level level,
			const char *file, int line, const char *func,
			stnode_t *node, const char *msg)
{
	if (!ws_log_msg_is_active(WS_LOG_DOMAIN, level))
		return;

	if (node == NULL) {
		ws_log_write_always_full(WS_LOG_DOMAIN, level,
					file, line, func, "%s is NULL", msg);
		return;
	}

	stnode_op_t st_op;
	stnode_t *st_lhs = NULL, *st_rhs = NULL;
	char *lhs = NULL, *rhs = NULL;

	sttype_oper_get(node, &st_op, &st_lhs, &st_rhs);

	if (st_lhs)
		lhs = sprint_node(st_lhs);
	if (st_rhs)
		rhs = sprint_node(st_rhs);

	ws_log_write_always_full(WS_LOG_DOMAIN, level, file, line, func,
				"%s:\n LHS = %s\n RHS = %s",
				stnode_todebug(node),
				lhs ? lhs : "NULL",
				rhs ? rhs : "NULL");

	g_free(lhs);
	g_free(rhs);
}

static void
indent(wmem_strbuf_t *buf, int level)
{
	for (int i = 0; i < level * 2; i++) {
		wmem_strbuf_append_c(buf, ' ');
	}
	wmem_strbuf_append_printf(buf, "% 2d ", level);
}

static void
visit_tree(wmem_strbuf_t *buf, stnode_t *node, int level)
{
	stnode_t *left, *right;
	stnode_t *lower, *upper;
	GSList *params;
	GSList *nodelist;

	if (stnode_type_id(node) == STTYPE_TEST ||
			stnode_type_id(node) == STTYPE_ARITHMETIC) {
		wmem_strbuf_append_printf(buf, "%s:\n", stnode_todebug(node));
		sttype_oper_get(node, NULL, &left, &right);
		if (left && right) {
			indent(buf, level + 1);
			visit_tree(buf, left, level + 1);
			wmem_strbuf_append_c(buf, '\n');
			indent(buf, level + 1);
			visit_tree(buf, right, level + 1);
		}
		else if (left) {
			indent(buf, level + 1);
			visit_tree(buf, left, level + 1);
		}
		else if (right) {
			ws_assert_not_reached();
		}
	}
	else if (stnode_type_id(node) == STTYPE_SET) {
		nodelist = stnode_data(node);
		wmem_strbuf_append_printf(buf, "SET(#%u):\n", g_slist_length(nodelist) / 2);
		while (nodelist) {
			indent(buf, level + 1);
			lower = nodelist->data;
			wmem_strbuf_append(buf, stnode_tostr(lower, false));
			/* Set elements are always in pairs; upper may be null. */
			nodelist = g_slist_next(nodelist);
			ws_assert(nodelist);
			upper = nodelist->data;
			if (upper != NULL) {
				wmem_strbuf_append(buf, " .. ");
				wmem_strbuf_append(buf, stnode_tostr(upper, false));
			}
			nodelist = g_slist_next(nodelist);
			if (nodelist != NULL) {
				wmem_strbuf_append_c(buf, '\n');
			}
		}
	}
	else if (stnode_type_id(node) == STTYPE_FUNCTION) {
		wmem_strbuf_append_printf(buf, "%s:\n", stnode_todebug(node));
		params = sttype_function_params(node);
		while (params) {
			indent(buf, level + 1);
			visit_tree(buf, params->data, level + 1);
			if (params->next != NULL) {
				wmem_strbuf_append_c(buf, '\n');
			}
			params = params->next;
		}
	}
	else {
		wmem_strbuf_append(buf, stnode_todebug(node));
	}
}

char *
dump_syntax_tree_str(stnode_t *root)
{
	wmem_strbuf_t *buf = wmem_strbuf_new(NULL, NULL);
	indent(buf, 0);
	visit_tree(buf, root, 0);
	return wmem_strbuf_finalize(buf);
}

void
log_syntax_tree(enum ws_log_level level, stnode_t *root, const char *msg, char **cache_ptr)
{
	if (!ws_log_msg_is_active(LOG_DOMAIN_DFILTER, level))
		return;

	char *str = dump_syntax_tree_str(root);

	ws_log_write_always_full(LOG_DOMAIN_DFILTER, level, NULL, -1, NULL,
				"%s:\n%s", msg, str);

	if (cache_ptr) {
		*cache_ptr = str;
	}
	else {
		g_free(str);
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
