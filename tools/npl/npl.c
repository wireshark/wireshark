/*
 * Copyright 2012-2013, Jakub Zawadzki <darkjames-ws@darkjames.pl>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include "ast.h"
#include "xmem.h"

int npl_parse_file(npl_code_t *code, FILE *f, const char *filename); /* parser.l */

struct ettinfo {
	struct ettinfo *next;
	npl_struct_t *st;
};

struct hfinfo {
	struct hfinfo *next;
	struct _npl_statement_field *st;
	const char *parent;

	const char *hf_type;
};

enum symbol_type {
	SYMBOL_ANY    = (~0),
	SYMBOL_EXPR   = (1 << 0),
	SYMBOL_STRUCT = (1 << 1),
	SYMBOL_TABLE  = (1 << 2),
	SYMBOL_TYPE   = (1 << 3),
	SYMBOL_FIELD  = (1 << 4),

	SYMBOL_SIMPLE = (1 << 5),
	SYMBOL_PROTO  = (1 << 6),
};

struct symbol {
	struct symbol *next;

	const char *id;
	void *data;

	unsigned int hash;
	enum symbol_type type;

	int lvl;
	int is_static:1;
	int is_used:1;
};

struct parent_info {
	const char *id;
	npl_expression_t *byte_order;

	int cur_offset;
	/* size, offset, bitoffset, ... ? */
};

static struct symbol *gen_expr(FILE *f, npl_expression_t *e);
static void gen_statements(FILE *f, struct parent_info *parent, struct _npl_statements *sts);
static void gen_struct(FILE *f, npl_struct_t *s, npl_attribute_list_t *attr_list);

static struct symbol *symbols;
static struct hfinfo *hfs;
static struct ettinfo *etts;

static npl_expression_t format_string_e;
static npl_expression_t is_value_none_e;
static npl_expression_t this_e;

static npl_expression_t property_e;
static npl_expression_t global_e;
static npl_expression_t local_e;

static void _fail(const char *file, int line, const char *msg) {
	fprintf(stderr, "!!! %s:%d fail(%s)\n", file, line, msg);
	abort();
}

#define fail(msg) _fail(__FILE__, __LINE__, msg)

#define xassert(expr) \
	do { if (!(expr)) fail("Assertion failed: " #expr); } while(0);


static int symbols_lvl = 0;

static struct symbol *
symbols_push(void)
{
	symbols_lvl++;

	return symbols;
}

static void
symbols_pop(struct symbol *sym)
{
	--symbols_lvl;

	while (symbols != sym) {
		struct symbol *s = symbols;

		symbols = symbols->next;
		free(s);
	}
}

static unsigned int
symbol_hash(const char *str)
{
	unsigned int hash = 5381;

	while (*str) {
		hash = ((hash << 5) + hash) + tolower(*str);
		str++;
	}

	return hash;
}

static struct symbol *
symbol_find(const char *id, int type)
{
	struct symbol *sym;
	unsigned int hash;

	hash = symbol_hash(id);

	for (sym = symbols; sym; sym = sym->next) {
		if (sym->hash == hash && !strcasecmp(sym->id, id)) {
			// XXX, check type
			return sym;
		}
	}
	return NULL;
}

static struct symbol *
symbol_add(const char *id, enum symbol_type type, void *data)
{
	struct symbol *sym;

	sym = symbol_find(id, SYMBOL_ANY);
	if (sym) {
		if (sym->lvl == symbols_lvl) {
			fprintf(stderr, "Error: symbol %s already added [type: %d]\n", id, sym->type);
			abort();
		} else
			fprintf(stderr, "Warning: symbol %s shadow another symbol [type: %d]\n", id, sym->type);
	}
	
	sym = xnew(struct symbol);

	sym->id = id;
	sym->hash = symbol_hash(id);
	sym->type = type;
	sym->lvl = symbols_lvl;
	sym->data = data;

	sym->next = symbols;
	symbols = sym;

	return sym;
}

static struct ettinfo *
ett_add(npl_struct_t *st)
{
	struct ettinfo *new = xnew(struct ettinfo);

	new->st = st;

	new->next = etts;
	etts = new;

	return new;
}

static const char *
ett_var(const struct ettinfo *ett)
{
	static char ett_name[256];

	snprintf(ett_name, sizeof(ett_name), "ett_%s", ett->st->id);

	return ett_name;
}

static struct hfinfo *
hfi_add(struct _npl_statement_field *st, const struct parent_info *parent)
{
	struct hfinfo *new = xnew(struct hfinfo);

	new->st = st;
	new->parent = parent->id;

	new->next = hfs;
	hfs = new;

	return new;
}

static size_t
hfi_put_name(char *buf, size_t buflen, const char *str)
{
	size_t pos = 0;
	int i;

	int t = 0;
	int toldup = -1;

	for (i = 0; str[i]; i++) {
		int tup = isupper(str[i]);

		if (toldup != tup && tup) {
			if (t > 0) {
				if (pos < buflen)
					buf[pos++] = '_';
			}
			t++;
		}
		toldup = tup;

		if (pos < buflen)
			buf[pos++] = tolower(str[i]);
	}
	return pos;
}

static const char *
hfi_var(const struct hfinfo *hfi)
{
	static char hf_name[256];
	size_t pos;

	pos = snprintf(hf_name, sizeof(hf_name), "hf_field_");
	xassert(pos < sizeof(hf_name));

	if (hfi->parent) {
		pos += hfi_put_name(hf_name + pos, sizeof(hf_name) - pos, hfi->parent);
		xassert(pos < sizeof(hf_name));

		hf_name[pos++] = '_';
		xassert(pos < sizeof(hf_name));
	}

	pos += hfi_put_name(hf_name + pos, sizeof(hf_name) - pos, hfi->st->id);
	xassert(pos < sizeof(hf_name));

	hf_name[pos++] = '\0';

	return hf_name;
}

static const char *
hfi_name(const struct hfinfo *hfi)
{
	return hfi->st->id;
}

static const char *
hfi_filter(const struct hfinfo *hfi)
{
	static char filter_name[1024];
	size_t pos;

	pos = 0;

	if (hfi->parent) {
		pos += hfi_put_name(filter_name + pos, sizeof(filter_name)-pos, hfi->parent);
		xassert(pos < sizeof(filter_name));

		filter_name[pos++] = '.';
		xassert(pos < sizeof(filter_name));
	}

	pos += hfi_put_name(filter_name + pos, sizeof(filter_name)-pos, hfi->st->id);
	xassert(pos < sizeof(filter_name));

	filter_name[pos++] = '\0';
	xassert(pos < sizeof(filter_name));

	return filter_name;
}

static const char *
hfi_type(const struct hfinfo *hfi)
{
	if (hfi->hf_type)
		return hfi->hf_type;
	/* TODO stub */
	return "FT_BYTES";
}

static const char *
hfi_display(const struct hfinfo *hfi)
{
	/* TODO stub */
	return "BASE_NONE";
}

static unsigned int
hfi_mask(const struct hfinfo *hfi)
{
	/* TODO stub */
	return 0;
}

static int
count_expression_list(const npl_expression_list_t *exprs)
{
	int c = 0;

	while (exprs) {
		c++;
		exprs = exprs->next;
	}
	return c;
}

static struct symbol *
expr_to_symbol(const npl_expression_t *e)
{
	struct symbol *sym = NULL;

	if (e->type == EXPRESSION_ID) {
		const char *id = e->id.id;

		sym = symbol_find(id, SYMBOL_ANY);
		if (!sym) {
			fprintf(stderr, "can't find id: %s\n", id);
			abort();
		}
		/* XXX, sym->is_used */

		if (sym->type == SYMBOL_EXPR) {
			struct symbol *new_sym = expr_to_symbol(sym->data);

			if (new_sym)
				sym = new_sym;
		}
	}
	return sym;
}

static int
expr_to_const_int(const npl_expression_t *e, int *val)
{
	struct symbol *sym;

	if (e->type == EXPRESSION_INT) {
		*val = e->num.digit;
		return 1;
	}
	if (e->type == EXPRESSION_UNARY) {
		if (!expr_to_const_int(e->u.operand, val))
			return 0;

		switch (e->u.operator) {
			case OP1_MINUS:
				*val = -(*val);
				return 1;
			case OP1_NEG:
				*val = ~(*val);
				return 1;
			case OP1_NOT:
				*val = !(*val);
				return 1;
		}
		return 0;
	}

	sym = expr_to_symbol(e);
	if (sym && sym->type == SYMBOL_EXPR)
		return expr_to_const_int(sym->data, val);

	return 0;
}

static int
expr_to_const_str(const npl_expression_t *e, const char **val)
{
	struct symbol *sym;

	if (e->type == EXPRESSION_STR) {
		*val = e->str.str;
		return 1;
	}

	sym = expr_to_symbol(e);
	if (sym && sym->type == SYMBOL_EXPR)
		return expr_to_const_str(sym->data, val);

	return 0;
}

static const char *
type_to_ctype(const npl_type_t *t, int size)
{
	switch (t->type) {
		case FIELD_DECIMAL:
			if (size == 4)
				return "float";
			if (size == 8)
				return "double";

			fprintf(stderr, "!!! decimal, size: %d\n", size);
			return NULL;

		case FIELD_NUMBER:
			if (size == 1)
				return "gint8";
			if (size == 2)
				return "gint16";
			if (size == 3 || size == 4)
				return "gint32";
			if (size > 4 && size <= 8)
				return "gint64";

			fprintf(stderr, "!!! number, size: %d\n", size);
			return NULL;

		case FIELD_UNSIGNED_NUMBER:
			if (size == 1)
				return "guint8";
			if (size == 2)
				return "guint16";
			if (size == 3 || size == 4)
				return "guint32";
			if (size > 4 && size <= 8)
				return "guint64";

			fprintf(stderr, "!!! number, size: %d\n", size);
			return NULL;

		case FIELD_TIME:
			return "nstime_t";
	}
	fprintf(stderr, "!!! not handled, type: %d, size: %d\n", t->type, size);
	return NULL;
}

#define NPL_ENDIAN_LE 0
#define NPL_ENDIAN_BE 1

static const char *
type_to_tvb(const npl_type_t *t, int size, int endian)
{
	switch (t->type) {
		case FIELD_DECIMAL:
			if (size == 4 && endian == NPL_ENDIAN_LE)
				return "tvb_get_letohieee_float";
			if (size == 4 && endian == NPL_ENDIAN_BE)
				return "tvb_get_ntohieee_float";

			if (size == 8 && endian == NPL_ENDIAN_LE)
				return "tvb_get_letohieee_double";
			if (size == 8 && endian == NPL_ENDIAN_BE)
				return "tvb_get_ntohieee_double";

			fprintf(stderr, "!!! decimal, size: %d, endian: %d\n", size, endian);
			return NULL;

		case FIELD_UNSIGNED_NUMBER:
		case FIELD_NUMBER:
			if (size == 1)
				return "tvb_get_guint8";

			if (size == 2 && endian == NPL_ENDIAN_LE)
				return "tvb_get_letohs";
			if (size == 2 && endian == NPL_ENDIAN_BE)
				return "tvb_get_ntohs";

			if (t->type == FIELD_UNSIGNED_NUMBER && size == 3 && endian == NPL_ENDIAN_LE)
				return "tvb_get_letoh24";
			if (t->type == FIELD_UNSIGNED_NUMBER && size == 3 && endian == NPL_ENDIAN_BE)
				return "tvb_get_ntoh24";

			if (size == 4 && endian == NPL_ENDIAN_LE)
				return "tvb_get_letohl";
			if (size == 4 && endian == NPL_ENDIAN_BE)
				return "tvb_get_ntohl";

			fprintf(stderr, "!!! number, size: %d, endian: %d\n", size, endian);
			return NULL;
	}
	fprintf(stderr, "!!! not handled, type: %d, size: %d, endian: %d\n", t->type, size, endian);
	return NULL;
}

static const char *
type_to_ft(const npl_type_t *t, int size)
{
	switch (t->type) {
		case FIELD_DECIMAL:
			if (size == 4)
				return "FT_FLOAT";
			if (size == 8)
				return "FT_DOUBLE";

			fprintf(stderr, "!!! decimal, size: %d\n", size);
			return NULL;

		case FIELD_NUMBER:
			if (size == 1)
				return "FT_INT8";
			if (size == 2)
				return "FT_INT16";
			if (size == 3)
				return "FT_INT24";
			if (size == 4)
				return "FT_INT32";
			if (size > 4 && size <= 8)
				return "FT_INT64";

			fprintf(stderr, "!!! number, size: %d\n", size);
			return NULL;

		case FIELD_UNSIGNED_NUMBER:
			if (size == 1)
				return "FT_UINT8";
			if (size == 2)
				return "FT_UINT16";
			if (size == 3)
				return "FT_UINT24";
			if (size == 4)
				return "FT_UINT32";
			if (size > 4 && size <= 8)
				return "FT_UINT64";

			fprintf(stderr, "!!! number, size: %d\n", size);
			return NULL;

		case FIELD_TIME:
			/* XXX, FT_ABSOLUTE_TIME or FT_RELATIVE_TIME? */
			fprintf(stderr, "!!! time, size: %d\n", size);
			return "FT_ABSOLUTE_TIME";
	}
	fprintf(stderr, "!!! not handled, type: %d, size: %d\n", t->type, size);
	return NULL;
}

#define gen_fprintf(f, args...)			\
	do {								\
		if (f) fprintf(f, args);		\
	} while (0)

static const char *
op1_to_str(npl_op1_t op)
{
	switch (op) {
		case OP1_MINUS:
			return "-";
		case OP1_NOT:
			return "!";
		case OP1_NEG:
			return "~";
	}
	fprintf(stderr, "XXX op: %d\n", op);
	return "";
}

static const char *
op2_to_str(npl_op2_t op)
{
	switch (op) {
		case OP2_PLUS:
			return "+";
		case OP2_MINUS:
			return "-";
		case OP2_SHL:
			return "<<";
		case OP2_SHR:
			return ">>";
		case OP2_EQUAL:
			return "==";
		case OP2_NOTEQUAL:
			return "!=";
		case OP2_LOGIC_OR:
			return "||";
		case OP2_LOGIC_AND:
			return "&&";
		case OP2_OR:
			return "|";
		case OP2_XOR:
			return "^";
		case OP2_AND:
			return "&";
		case OP2_GREATER:
			return ">";
		case OP2_GEQUAL:
			return ">=";
		case OP2_LESS:
			return "<";
		case OP2_LEQUAL:
			return "<=";
	}
	fprintf(stderr, "XXX op: %d\n", op);
	return "";
}

enum attr_flag {
	ATTR_PROPERTY	= 0,

	ATTR_GLOBAL	= 1 << 0,
	ATTR_LOCAL	= 1 << 1,

	ATTR_CONV	= 1 << 5,
	
	ATTR_POST	= 1 << 10
};

static enum attr_flag
resolve_attr_id(const char *id)
{
	if (!strcasecmp(id, "property"))
		return ATTR_PROPERTY;
	if (!strcasecmp(id, "Global"))
		return ATTR_GLOBAL;
	if (!strcasecmp(id, "local"))
		return ATTR_LOCAL;
	if (!strcasecmp(id, "conversation"))
		return ATTR_CONV;
	if (!strcasecmp(id, "post"))
		return ATTR_POST;

	fprintf(stderr, ":: attr-id: %s\n", id);
	abort();
	return -1;
}

static int
resolve_attr_expr(const struct _npl_expression *expr)
{
	int flags = 0;

	switch (expr->type) {
		case EXPRESSION_ID:
			flags |= (int) resolve_attr_id(expr->id.id);
			break;
			
		case EXPRESSION_FIELD:
			flags |= resolve_attr_expr(expr->fld.base);
			flags |= (int) resolve_attr_id(expr->fld.field);
			break;

		default:
			fprintf(stderr, "resolve_attr_expr() %d\n", expr->type);
			break;
	}

	xassert(!((flags & ATTR_GLOBAL) && (flags & ATTR_LOCAL)));

	return flags;
}

static void
resolve_attr_list(npl_attribute_list_t *attr)
{
	while (attr) {
		struct _npl_expression *expr;
		const char *id = NULL;
		int flags = 0;

		if (attr->expr->type == EXPRESSION_BINARY && attr->expr->b.operator == OP2_ASSIGN) {
			/* XXX, handle: a = b = c ? */
			expr = attr->expr->b.operand1;
			attr->assign_expr = attr->expr->b.operand2;
		} else
			expr = attr->expr;

		switch (expr->type) {
			case EXPRESSION_ID:
				id = expr->id.id;
				break;

			case EXPRESSION_FIELD:
				flags = resolve_attr_expr(expr->fld.base);
				id = expr->fld.field;
				break;

			default:
				fprintf(stderr, "resolve_attr_list() expr: %d\n", expr->type);
				break;
		}

		attr->flags = flags;
		attr->resolved = id;

		attr = attr->next;
	}
}

static void
gen_expr_field(FILE *f, struct _npl_statement_field *field)
{
	xassert(field->generate_var || f == NULL);

	field->generate_var = 1;
	gen_fprintf(f, "_field_%s", field->id);
}

static void
gen_expr_type(FILE *f, npl_type_t *t)
{
	int size = -1;
	int byte_order = -1;
	const char *fetch_func;

	if (t->size && !expr_to_const_int(t->size, &size))
		fprintf(stderr, "!!! expr_to_const_int(size) failed for type: %s\n", t->id);

	if (t->byte_order && !expr_to_const_int(t->byte_order, &byte_order))
		fprintf(stderr, "!!! expr_to_const_int(byte_order) failed for type: %s\n", t->id);

	fetch_func = type_to_tvb(t, size, byte_order);
	if (fetch_func)
		gen_fprintf(f, "%s", fetch_func);
	else
		gen_fprintf(f, "<<TYPE %s>>", t->id);
}

static void
gen_expr_table(FILE *f, npl_table_t *t)
{
	gen_fprintf(f, " format_table_%s ", t->id);
}

static struct symbol *
gen_expr(FILE *f, npl_expression_t *e)
{
	switch (e->type) {
		case EXPRESSION_ID:
		{
			struct symbol *sym = symbol_find(e->id.id, SYMBOL_EXPR | SYMBOL_FIELD | SYMBOL_TYPE | SYMBOL_SIMPLE | SYMBOL_TABLE);

			if (!sym) {
				fprintf(stderr, "can't find id: %s\n", e->id.id);
				abort();
			}
			sym->is_used = 1;

			if (sym->type == SYMBOL_EXPR)
				gen_expr(f, sym->data);

			else if (sym->type == SYMBOL_FIELD)
				gen_expr_field(f, sym->data);

			else if (sym->type == SYMBOL_TYPE)
				gen_expr_type(f, sym->data);

			else if (sym->type == SYMBOL_TABLE)
				gen_expr_table(f, sym->data);

			else if (sym->type == SYMBOL_SIMPLE)
				gen_fprintf(f, "%s", (const char *) sym->data);

			else {
				fprintf(stderr, "ID %s wrong type [%d]\n", sym->id, sym->type);
				abort();
			}
			return sym;
		}

		case EXPRESSION_INT:
			gen_fprintf(f, " %d ", e->num.digit);
			return NULL;

		case EXPRESSION_STR:
			// XXX e->str.str is escaped, almost like C-string so just print it.
			gen_fprintf(f, " \"%s\" ", e->str.str);
			return NULL;

		case EXPRESSION_UNARY:
			gen_fprintf(f, "(");
			gen_fprintf(f, "%s", op1_to_str(e->u.operator));
			gen_expr(f, e->u.operand);
			gen_fprintf(f, ")");
			return NULL;

		case EXPRESSION_BINARY:
			gen_fprintf(f, "(");
			gen_expr(f, e->b.operand1);
			gen_fprintf(f, " %s ", op2_to_str(e->b.operator));
			gen_expr(f, e->b.operand2);
			gen_fprintf(f, ")");
			return NULL;

		case EXPRESSION_CALL:
		{
			npl_expression_list_t *arg;
			struct symbol *sym;
			const char *ind = "";

			sym = gen_expr(NULL, e->call.fn);
			if (!sym) {
				fprintf(stderr, "can't call no-symbol\n");
				abort();
			}
			/* XXX check if sym->type can be called (function) */


			gen_expr(f, e->call.fn);
			gen_fprintf(f, "(");
			for (arg = e->call.args; arg; arg = arg->next) {
				gen_fprintf(f, "%s", ind);
				gen_expr(f, arg->expr);
				ind = ", ";
			}
			gen_fprintf(f, ")");
			return NULL;
		}

		case EXPRESSION_COND:
			gen_fprintf(f, "((");
			gen_expr(f, e->c.test_expr);
			gen_fprintf(f, ") ? ");
			gen_expr(f, e->c.true_expr);
			gen_fprintf(f, " : ");
			gen_expr(f, e->c.false_expr);
			gen_fprintf(f, ")");
			return NULL;

		case EXPRESSION_FIELD:
		{
			struct symbol *sym;

			sym = gen_expr(NULL, e->fld.base);
			if (!sym) {
				fprintf(stderr, "can't field no-symbol   (accessing %s)\n", e->fld.field);
				abort();
			}
			/* XXX check if sym->type can be dereferenced (struct) */

			if (sym->data == &property_e) {
				gen_fprintf(f, "<< PROPERTY %s>>", e->fld.field);
			} else if (sym->data == &local_e) {
				gen_fprintf(f, "_local_property_%s", e->fld.field);
			} else if (sym->data == &global_e) {
				gen_fprintf(f, "<< GLOBAL PROPERTY %s>>", e->fld.field);
			} else {
				gen_expr(f, e->fld.base);
				gen_fprintf(f, ".%s ", e->fld.field);
			}
			return NULL;
		}
	}

	if (e == &this_e)
		gen_fprintf(f, "<< this >>");
	else if (e == &format_string_e)
		gen_fprintf(f, "<< FORMAT STRING >>");
	else if (e == &is_value_none_e)
		gen_fprintf(f, "<< IS VALUE NONE >>");

	else if (e == &property_e || e == &global_e || e == &local_e)
		{ /* silent expr->type: 0 warnings */ }
	else
		fprintf(stderr, "XXX expr->type: %d\n", e->type);

	return NULL;
}

enum table_struct { TABLE_FULL, TABLE_VALUE_STRING, TABLE_STRING_STRING };

static enum table_struct
gen_table_struct(FILE *f, npl_table_t *t)
{
	struct npl_table_case *c;

	int all_int = 1;
	int all_str = 1;

	if (t->params.count > 1 || !t->switch_expr)
		return TABLE_FULL;

	for (c = t->cases; c; c = c->next) {
		const char *str;
		int val;

		if (!c->return_expr || !expr_to_const_str(c->return_expr, &str))
			return 0;

		if (all_int && !expr_to_const_int(&c->e, &val))
			all_int = 0;
		if (all_str && !expr_to_const_str(&c->e, &str))
			all_str = 0;

		if (!all_int && !all_str)
			return TABLE_FULL;
	}

	/* table can be converted to value_string, generate one */
	if (all_int) {
		gen_fprintf(f,
			"static const value_string %s_vals[] = {\n",
			t->id);

		if (f)
		for (c = t->cases; c; c = c->next) {
			const char *str;
			int val;

			/* checked above, should not fail now */
			if (!expr_to_const_str(c->return_expr, &str))
				fail("expr_to_const_str(str)");
			if (!expr_to_const_int(&c->e, &val))
				fail("expr_to_const_int(val)");

			gen_fprintf(f, "\t{ 0x%x, \"%s\" },\n", val, str);
		}
		gen_fprintf(f, "\t{ 0, NULL }\n");
		gen_fprintf(f, "};\n");
		return TABLE_VALUE_STRING;
	}

	/* table can be converted to string_string, generate one */
	if (all_str) {
		gen_fprintf(f,
			"static const string_string %s_vals[] = {\n",
			t->id);

		if (f)
		for (c = t->cases; c; c = c->next) {
			const char *str;
			const char *val;

			/* checked above, should not fail now */
			if (!expr_to_const_str(c->return_expr, &str))
				fail("expr_to_const_str(str)");
			if (!expr_to_const_str(&c->e, &val))
				fail("expr_to_const_str(val)");

			gen_fprintf(f, "\t{ \"%s\", \"%s\" },\n", val, str);
		}
		gen_fprintf(f, "\t{ NULL, NULL }\n");
		gen_fprintf(f, "};\n");
		return TABLE_STRING_STRING;
	}

	return TABLE_FULL;
}

static void
gen_table_func(FILE *f, npl_table_t *t)
{
	struct npl_table_case *c;

	if (t->switch_expr) {
		gen_fprintf(f, "\tswitch (");
		gen_expr(f, t->switch_expr);
		gen_fprintf(f, ") {\n");

		for (c = t->cases; c; c = c->next) {
again1:
			gen_fprintf(f, "\t\tcase ");
			gen_expr(f, &c->e);
			gen_fprintf(f, ": ");

			if (!c->return_expr) {
				c = c->next;
				xassert(c != NULL);
				gen_fprintf(f, "\n");
				goto again1;
			} else {
				gen_fprintf(f, "\n");
				gen_fprintf(f, "\t\t\treturn ");
				gen_expr(f, c->return_expr);
				gen_fprintf(f, ";\n");
			}
		}

		gen_fprintf(f, "\t}\n");
	} else {
		for (c = t->cases; c; c = c->next) {

			if (c == t->cases)
				gen_fprintf(f, "\tif (");
			else
				gen_fprintf(f, "\telse if (");

again2:
			gen_fprintf(f, "(");
			gen_expr(f, &c->e);
			gen_fprintf(f, ")");

			if (!c->return_expr) {
				gen_fprintf(f, " || ");
				c = c->next;
				xassert(c != NULL);
				goto again2;
			} else {
				gen_fprintf(f, ")\n");

				gen_fprintf(f, "\t\treturn ");
				gen_expr(f, c->return_expr);
				gen_fprintf(f, ";\n");
			}
		}
	}
}

static void
decl_table(npl_table_t *t)
{
	if (!t->sym)
		t->sym = symbol_add(t->id, SYMBOL_TABLE, t);
}

static void
gen_table(FILE *f, npl_table_t *t)
{
	struct symbol *symroot;
	const char *first_arg;
	enum table_struct type;

	t->sym->is_static = 1;
	gen_fprintf(f,
		"static const char *\n"
		"format_table_%s", t->id);

	symroot = symbols_push();

	gen_fprintf(f, "(");
	if (t->params.count) {
		int i;

		for (i = 0; i < t->params.count; i++) {
			if (i)
				gen_fprintf(f, ", ");
			gen_fprintf(f, "TYPE %s", t->params.args[i]);
			symbol_add(t->params.args[i], SYMBOL_SIMPLE, t->params.args[i]);
		}
		first_arg = t->params.args[0];

	} else {
		/* default */
		gen_fprintf(f, "TYPE value");
		symbol_add("value", SYMBOL_SIMPLE, "value");
		first_arg = "value";
	}
	gen_fprintf(f, ")\n{\n");

	type = gen_table_struct(f, t);
	switch (type) {
		case TABLE_VALUE_STRING:
			gen_fprintf(f, "\n");
			gen_fprintf(f, "\tconst char *tmp = match_strval(%s_vals, %s);\n", t->id, first_arg);
			gen_fprintf(f, "\tif (tmp)\n\t\treturn tmp;\n");
			break;

		case TABLE_STRING_STRING:
			gen_fprintf(f, "\tconst char *tmp = match_strstr(%s_vals, %s);\n", t->id, first_arg);
			gen_fprintf(f, "\tif (tmp)\n\t\treturn tmp;\n");
			break;

		case TABLE_FULL:
		default:
			gen_table_func(f, t);
			break;
	}

	if (t->default_expr) {
		gen_fprintf(f, "\treturn ");
		gen_expr(f, t->default_expr);
		gen_fprintf(f, ";\n");
	} else
		gen_fprintf(f, "\treturn \"\";\n");

	gen_fprintf(f, "}\n\n");

	symbols_pop(symroot);
}

static void
gen_field_proto(FILE *f, struct _npl_statement_field *field, npl_protocol_t *p)
{
	/* XXX */
	gen_fprintf(f, "\t << CALL PROTOCOL %s >>\n", p->id);
	/* XXX, do we care? (only when not @ tail?) */
	field->field_size = -1;
}

static void
gen_field_struct(FILE *f, struct _npl_statement_field *field, npl_struct_t *s)
{
	// XXX st->f.bits, st->f.arr, st->f.format, st->f.sts
	// XXX, st->f.generate_var

	gen_fprintf(f, "\toffset = dissect_struct_%s(tvb, pinfo, tree, %s, offset);\n", s->tmpid, hfi_var(field->hfi));

	field->hfi->hf_type = "FT_BYTES";
	field->field_size = -1;
}

static void
gen_field_size(FILE *f, struct symbol *sym_size, int size)
{
	if (sym_size) {
		/* runtime */
		if (sym_size->type == SYMBOL_FIELD) {
			gen_fprintf(f, "_field_%s", sym_size->id);

		} else if (sym_size->type == SYMBOL_EXPR) {
			gen_fprintf(f, "(");
			gen_expr(f, sym_size->data);
			gen_fprintf(f, ") ");

		} else if (sym_size->type == SYMBOL_SIMPLE) {
			gen_fprintf(f, "%s ", (const char *) sym_size->data);

		} else {
			fprintf(stderr, "::: %s (%d)\n", sym_size->id, sym_size->type);
			gen_fprintf(f, "<<SYMBOL %s>>\n", sym_size->id);
		}

	} else {
		/* const */
		gen_fprintf(f, "%d", size);
	}
}

static void
gen_field_type(FILE *f, struct _npl_statement_field *field, npl_type_t *t)
{
	struct symbol *symroot;
	int i;

	// XXX field.bits, field.arr, field.sts

	int size = -1;
	struct symbol *size_sym = NULL;

	int byte_order = -1;
	npl_expression_t *byte_order_expr;
	struct symbol *byte_order_sym = NULL;

	npl_expression_t *display_format;

	const char *hf_type;

	npl_expression_list_t *argv = field->params;
	int argc = count_expression_list(argv);

	if (t->params.count != argc) {
		fprintf(stderr, "%s: number of params != number of argc (%d != %d)\n", t->id, t->params.count, argc);
		abort();
	}

	symroot = symbols_push();

	for (i = 0; i < argc; i++) {
		symbol_add(t->params.args[i], SYMBOL_EXPR, argv->expr);
		argv = argv->next;
	}

	xassert(t->size != NULL);
	if (!expr_to_const_int(t->size, &size)) {
		size_sym = expr_to_symbol(t->size);

		if (!size_sym) {
			fprintf(stderr, "!!! expr_to_const_int, _symbol(size) failed for type: %s\n", t->id);
			abort();
		}
	}

	if (field->byte_order_attr)
		byte_order_expr = field->byte_order_attr;
	else if (t->byte_order)
		byte_order_expr = t->byte_order;
	else
		byte_order_expr = NULL;

	if (field->format)
		display_format = field->format;
	else
		display_format = t->display_format;

	if (byte_order_expr) {
		if (!expr_to_const_int(byte_order_expr, &byte_order)) {
			byte_order_sym = expr_to_symbol(byte_order_expr);
			if (!byte_order_sym) {
				fprintf(stderr, "!!! expr_to_const_int, _symbol(byte_order) failed for type: %s\n", t->id);
				abort();
			}
		}
	}

	if (field->generate_var) {
		/* XXX, size_sym, byte_order_sym */

		const char *ctype = type_to_ctype(t, size);
		const char *fetch_func = type_to_tvb(t, size, byte_order);

/*
		if (!ctype || !fetch_func)
			abort();
*/

		/* XXX, we should declare variable on begin of block (< C99) */
		gen_fprintf(f, "\t%s _field_%s = %s(tvb, offset);\n", ctype, field->id, fetch_func);
	}

	if (size_sym) {
		if (size_sym->type == SYMBOL_FIELD) {
			struct _npl_statement_field *sym_field = size_sym->data;

			xassert(sym_field->generate_var || f == NULL);

			sym_field->generate_var = 1;
		} else
			fprintf(stderr, "::: %s (%d)\n", size_sym->id, size_sym->type);

		hf_type = NULL;

	} else
		hf_type = type_to_ft(t, size);

	field->hfi->hf_type = hf_type;
	field->field_size = size;

	/* XXX, when generate_var we can use fetched value, not proto_tree_add_item() */

#if 0
	if (display_format)
		fprintf(stderr, "XXX, format\n");
	else
#endif
	gen_fprintf(f, "\tproto_tree_add_item(tree, %s, tvb, offset, ", hfi_var(field->hfi));
	/* XXX, emit temporary variable? expressions might be time-consuming, we could also check if size < 0 */
	gen_field_size(f, size_sym, size);
	gen_fprintf(f, ", %s);\n",
		(byte_order == NPL_ENDIAN_LE) ? "ENC_LITTLE_ENDIAN" : 
		(byte_order == NPL_ENDIAN_BE) ? "ENC_BIG_ENDIAN" : 
		"ENC_NA");

	gen_fprintf(f, "\toffset += ");
	gen_field_size(f, size_sym, size);
	gen_fprintf(f, ";\n");

	symbols_pop(symroot);
}

static void
gen_statement_field(FILE *f, struct parent_info *parent, struct _npl_statement_field *field, npl_attribute_list_t *attr_list)
{
	struct symbol *sym;
	const char *property_name = NULL;
	int property_flags = 0;

	sym = symbol_find(field->t_id, SYMBOL_STRUCT | SYMBOL_PROTO | SYMBOL_TYPE);
	if (!sym) {
		fprintf(stderr, "can't find: %s\n", field->t_id);
		abort();
	}
	sym->is_used = 1;

	if (!field->hfi && sym->type != SYMBOL_PROTO) {
		field->hfi = hfi_add(field, parent);
		xassert(f == NULL);
	}

	symbol_add(field->id, SYMBOL_FIELD, field);

	field->byte_order_attr = parent->byte_order;

	/* already resolved */
	while (attr_list) {
		const char *attr_name = attr_list->resolved;
		npl_expression_t *attr_expr = attr_list->assign_expr;
		int attr_flags = attr_list->flags;

		if (attr_name) {
			if (!strcasecmp(attr_name, "DataFieldByteOrder")) {
				xassert(attr_flags == 0);
				xassert(attr_expr != NULL);

				field->byte_order_attr = attr_expr;

			} else if (attr_expr) {
				if (attr_flags & ATTR_LOCAL) {
					/* XXX, declare only when first use. support < C99 */
					gen_fprintf(f, "\tTYPE _local_property_%s = ", attr_name);
					gen_expr(f, attr_expr);
					gen_fprintf(f, ";\n");
				} else {
					gen_fprintf(f, "<<PROPERTY(%d) %s = ", attr_flags, attr_name);
					gen_expr(f, attr_expr);
					gen_fprintf(f, ">>\n");
				}

			} else {
				/* only one for now */
				xassert(property_name == NULL);

				property_name = attr_name;
				property_flags = attr_flags;
				field->generate_var = 1;
			}
		} else
			fprintf(stderr, "!!! generating field attr: not resolved!\n");

		attr_list = attr_list->next;
	}

	if (sym->type == SYMBOL_STRUCT)
		gen_field_struct(f, field, sym->data);
	else if (sym->type == SYMBOL_TYPE)
		gen_field_type(f, field, sym->data);
	else if (sym->type == SYMBOL_PROTO)
		gen_field_proto(f, field, sym->data);
	else {
		/* XXX, SYMBOL_TABLE? */
		fprintf(stderr, "%s: wrong type [%d]\n", sym->id, sym->type);
		abort();
	}

	if (property_name) {
		/* XXX */
		gen_fprintf(f, "<<PROPERTY(%d) %s = FIELD %s>>\n", property_flags, property_name, field->id);
	}
}

static void
gen_statement(FILE *f, struct parent_info *parent, npl_statement_t *st)
{
	resolve_attr_list(st->attr_list);

	switch (st->type) {
		case STATEMENT_WHILE:
			// XXX ->id
			gen_fprintf(f, "\twhile (");
			gen_expr(f, &st->w.expr);
			gen_fprintf(f, ") {\n");

			/* gen_fprintf(f, "\tconst int __while%d_offset = %d;\n", _while_id, offset); */

			parent->cur_offset = -1;
			gen_statements(f, parent, st->w.sts);

			/* gen_fprintf(f, "\tassert(__while%d_offset > offset);\n", _while_id, offset); */

			gen_fprintf(f, "\t}\n"); 
			return;

		case STATEMENT_STRUCT:
			/* XXX, fix if we know size of structure */
			parent->cur_offset = -1;
			gen_struct(NULL, &st->s.data, NULL);
			// XXX put st->s.data somewhere to create this proc.
			gen_fprintf(f, "\toffset = dissect_struct_%s(tvb, pinfo, tree, hf_costam, offset);\n", st->s.data.tmpid);
			return;

		case STATEMENT_FIELD:
			gen_statement_field(f, parent, &st->f, st->attr_list);
			if (parent->cur_offset != -1) {
				if (st->f.field_size != -1)
					parent->cur_offset += st->f.field_size;
				else
					parent->cur_offset = -1;
			}
			return;

		/* case STATEMENT_DYNAMIC_SWITCH: */
		case STATEMENT_SWITCH:
		{
			struct npl_switch_case *c = st->sw.data.cases;

			parent->cur_offset = -1;
			if (st->sw.data.switch_expr) {
				gen_fprintf(f, "\tswitch (");
				gen_expr(f, st->sw.data.switch_expr);
				gen_fprintf(f, ") {\n");

				while (c) {
					gen_fprintf(f, "\t\tcase ");
					gen_expr(f, &c->e);
					gen_fprintf(f, ":\n");

					if (c->st) {
						gen_fprintf(f, "\t\t");
						gen_statement(f, parent, c->st);
						gen_fprintf(f, "\t\t\tbreak;\n");
					}
					c = c->next;
				}

				if (st->sw.data.default_st) {
					gen_fprintf(f, "\t\tdefault:\n");
					gen_fprintf(f, "\t\t");
					gen_statement(f, parent, st->sw.data.default_st);
				}

				gen_fprintf(f, "\t}\n");
				return;
			}

			if (c) {
				npl_statement_t *default_st = st->sw.data.default_st;

				gen_fprintf(f, "\t");
				while (c) {
					npl_statement_t *case_st;
					gen_fprintf(f, "if (");

					gen_fprintf(f, "(");
					gen_expr(f, &c->e);
					gen_fprintf(f, ")");

					case_st = c->st;
					c = c->next;

					while (c && !case_st) {
						case_st = c->st;

						gen_fprintf(f, " || ");
						gen_fprintf(f, "(");
						gen_expr(f, &c->e);
						gen_fprintf(f, ")");
						c = c->next;
					}

					if (!case_st) {
						gen_fprintf(f, " || 1");
						case_st = default_st;
						default_st = NULL;
					}
					gen_fprintf(f, ") {\n");
					gen_fprintf(f, "\t");
					gen_statement(f, parent, case_st);
					gen_fprintf(f, "\t} ");

					if (c || default_st)
						gen_fprintf(f, "else ");
				}

				if (default_st) {
					gen_fprintf(f, "{\n");
					gen_fprintf(f, "\t");
					gen_statement(f, parent, default_st);
					gen_fprintf(f, "\t}\n");
				}

			} else {
				if (st->sw.data.default_st)
					gen_statement(f, parent, st->sw.data.default_st);
			}
			return;
		}
	}
	fprintf(stderr, "gen_statement: %d\n", st->type);
}

static void
gen_statements(FILE *f, struct parent_info *parent, struct _npl_statements *sts)
{
	struct symbol *symroot;

	symroot = symbols_push();

	while (sts) {
		gen_statement(f, parent, &sts->st);

		sts = sts->next;
	}

	symbols_pop(symroot);
}

static void
decl_protocol(npl_protocol_t *p)
{
	if (!p->sym)
		p->sym = symbol_add(p->id, SYMBOL_PROTO, p);
}

static void
gen_protocol(FILE *f, npl_protocol_t *p, npl_attribute_list_t *attr_list)
{
	struct parent_info this;
	npl_expression_t *byte_order_attr = NULL;

	p->sym->is_static = 1;
	gen_fprintf(f, 
		"static int\n"
		"dissect_%s(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)\n", p->id);

	/* XXX, use data */
	xassert(p->params.count == 0);

	gen_fprintf(f, "{\n");
	gen_fprintf(f, 
		"\tint offset = 0;\n"
		"\tproto_tree *tree = NULL;\n"
		"\tproto_item *ti = NULL;\n"
		"\n"
	);

	resolve_attr_list(attr_list);
	while (attr_list) {
		const char *attr_name = attr_list->resolved;
		npl_expression_t *attr_expr = attr_list->assign_expr;
		int flags = attr_list->flags;

		if (attr_name) {
			if (!strcasecmp(attr_name, "DataTypeByteOrder")) {
				xassert(flags == 0);
				xassert(attr_expr != NULL);

				byte_order_attr = attr_expr;
			} else
				fprintf(stderr, "!!! generating protocol attr: %s not handled!\n", attr_name);
		} else
			fprintf(stderr, "!!! generating protocol attr: not resolved!\n");

		attr_list = attr_list->next;
	}

	gen_fprintf(f, "\tif (parent_tree) {\n");

	if (p->format) {
		/* TODO */
		gen_fprintf(f, "\t\tti = proto_tree_add_protocol_format(parent_tree, proto_%s, tvb, offset, -1, ", p->id);
		gen_fprintf(f, "\"TODO\"");
		gen_expr(stderr, p->format);
		gen_fprintf(f, ");\n");
	} else
		gen_fprintf(f, "\t\tti = proto_tree_add_item(parent_tree, proto_%s, tvb, offset, -1, ENC_NA);\n", p->id);

	gen_fprintf(f, "\t\ttree = proto_item_add_subtree(ti, ett_%s);\n", p->id);
	gen_fprintf(f, "\t}\n");

	memset(&this, 0, sizeof(this));
	this.id = p->id;
	this.id = NULL;
	this.byte_order = byte_order_attr;

	gen_statements(f, &this, p->sts);

	gen_fprintf(f, "\tproto_item_set_len(ti, offset);\n");
	gen_fprintf(f, "\treturn offset;\n");
	gen_fprintf(f, "}\n");
	gen_fprintf(f, "\n");
}

static void
decl_struct(npl_struct_t *s)
{
	if (!s->sym && s->id) {
		s->tmpid = s->id;
		s->sym = symbol_add(s->id, SYMBOL_STRUCT, s);
	}
}

static void
gen_struct(FILE *f, npl_struct_t *s, npl_attribute_list_t *attr_list)
{
	const char *id = s->tmpid;
	struct parent_info this;

	if (!id)
		id = s->tmpid = s->id;

	if (!id) {
		static unsigned int _id = 0;
		char tmp_id[32];

		snprintf(tmp_id, sizeof(tmp_id), "_noname%u", ++_id);
		id = s->tmpid = xstrdup(tmp_id);

		xassert(f == NULL);
	}

	if (s->count_expr) {
		/* TODO */
		fprintf(stderr, "TODO: s->count_expr");
	}

	if (s->sym)
		s->sym->is_static = 1;
	gen_fprintf(f,
			"static int\n"
			"dissect_struct_%s(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int hf_index%s, int offset)\n"
			"{\n", id, s->private ? " _U_" : "");

	if (!s->private) {
		gen_fprintf(f, "\tconst int org_offset = offset;\n");

		gen_fprintf(f, "\tproto_tree *tree = NULL;\n");
		gen_fprintf(f, "\tproto_item *ti = NULL;\n");
	} else
		gen_fprintf(f, "\tproto_tree *tree = parent_tree;\n");

	gen_fprintf(f,"\n");

	resolve_attr_list(attr_list);
	while (attr_list) {
		const char *attr_name = attr_list->resolved;
	/*
		npl_expression_t *attr_expr = attr_list->assign_expr;
		int attr_flags = attr_list->flags;
	 */

		if (attr_name) {
			fprintf(stderr, "!!! generating struct attr: %s!\n", attr_name);
		} else
			fprintf(stderr, "!!! generating struct attr: not resolved!\n");

		attr_list = attr_list->next;
	}

	if (!s->private) {
/*
		if (s->format) {
			fprintf(stderr, "gen_struct() s->format: '");
			gen_expr(stderr, s->format);
			fprintf(stderr, "\n\n");
		}
 */
		if (!s->ett)
			s->ett = ett_add(s);

		gen_fprintf(f,
			"\tif (parent_tree) {\n"
			"\t\tti = proto_tree_add_bytes_format_value(parent_tree, hf_index, tvb, offset, %d, NULL, \"%s\");\n"
			"\t\ttree = proto_item_add_subtree(ti, %s);\n"
			"\t}\n", s->struct_size, "", ett_var(s->ett));

	} else {
		if (s->format)
			fprintf(stderr, "s->private && s->format?\n");
	}

	memset(&this, 0, sizeof(this));
	this.id = s->id;

	gen_statements(f, &this, s->sts);
	s->struct_size = this.cur_offset;

	if (s->struct_size != -1) {
		/* XXX, assert runtime s->struct_size == offset - org_offset (?) */
	}

	if (!s->private && s->struct_size == -1)
		gen_fprintf(f, "\tproto_item_set_len(ti, offset - org_offset);\n");

	if (s->struct_size == -1)
		s->struct_size = 0;

	gen_fprintf(f, "\treturn offset;\n");
	gen_fprintf(f, "}\n");
	gen_fprintf(f, "\n");
}

static void
decl_const(npl_const_t *c)
{
	if (!c->sym)
		c->sym = symbol_add(c->id, SYMBOL_EXPR, &c->expr);
}

#if 0
static void
gen_const(FILE *f, npl_const_t *c)
{
	gen_fprintf(f, "#define %s ", c->id);
	gen_expr(f, &c->expr);
	gen_fprintf(f, "\n");
}
#endif

static void
decl_type(npl_type_t *t)
{
	if (!t->sym)
		t->sym = symbol_add(t->id, SYMBOL_TYPE, t);
}

static void
walk_decl(FILE *f, npl_decl_t *d, int full_run)
{
	switch (d->type) {
		case DECL_STRUCT:
			decl_struct(&d->s.data);
			if (!full_run)
				return;
			gen_struct(f, &d->s.data, d->attr_list);
			return;
		case DECL_TABLE:
			xassert(d->attr_list == NULL);
			decl_table(&d->t.data);
			if (!full_run)
				return;
			gen_table(f, &d->t.data);
			return;
		case DECL_PROTOCOL:
			decl_protocol(&d->p.data);
			if (!full_run)
				return;
			gen_protocol(f, &d->p.data, d->attr_list);
			return;
		case DECL_CONST:
			xassert(d->attr_list == NULL);
			decl_const(&d->c.data);
			if (!full_run)
				return;
			return;
		case DECL_TYPE:
			xassert(d->attr_list == NULL);
			decl_type(&d->ty.data);
			if (!full_run)
				return;
			return;
		case DECL_INCLUDE:
			xassert(d->attr_list == NULL);
			/* done in parse_includes() */
			return;
	}
	fprintf(stderr, "gen_decl() type: %d\n", d->type);
}

static void
walk_code(FILE *f, npl_code_t *c, int full_run)
{
	struct _npl_decl_list *decl;

	for (decl = c->decls; decl; decl = decl->next)
		walk_decl(f, &decl->d, 0);

	if (!full_run)
		return;

	for (decl = c->decls; decl; decl = decl->next)
		walk_decl(f, &decl->d, full_run);
}

static void
parse_includes(npl_code_t *c)
{
	struct _npl_decl_list *decl;

	for (decl = c->decls; decl; decl = decl->next) {
		if (decl->d.type == DECL_INCLUDE) {
			const char *filename = decl->d.i.file;
			FILE *f;

			npl_code_t icode;
			int parse_ok;

			if (!(f = fopen(filename, "rb"))) {
				fprintf(stderr, "can't open: %s\n", filename);
				abort();
			}
			memset(&icode, 0, sizeof(icode));
			parse_ok = npl_parse_file(&icode, f, filename);
			fclose(f);

			if (!parse_ok) {
				fprintf(stderr, "can't parse %s\n", filename);
				abort();
			}

			parse_includes(&icode);
			walk_code(NULL, &icode, 0);
		}
	}
}

static void
gen_vars(FILE *f)
{
	struct hfinfo *hfi;
	struct ettinfo *ett;

	for (hfi = hfs; hfi; hfi = hfi->next)
		gen_fprintf(f, "static int %s = -1;\n", hfi_var(hfi));
	gen_fprintf(f, "\n");

	for (ett = etts; ett; ett = ett->next)
		gen_fprintf(f, "static int %s = -1;\n", ett_var(ett));
	gen_fprintf(f, "\n");
}

static void
gen_proto_register(FILE *f, const char *proto_name)
{
	struct hfinfo *hfi;
	struct ettinfo *ett;

	gen_fprintf(f, 
		"void\n"
		"proto_register_%s(void)\n"
		"{\n", proto_name);

	/* hf array */
	gen_fprintf(f, "\tstatic hf_register_info hf[] = {\n");
	for (hfi = hfs; hfi; hfi = hfi->next) {
		gen_fprintf(f,
			"\t\t{ &%s,\n"
				"\t\t\t{ \"%s\", \"%s.%s\", %s, %s, NULL, 0x%.2x, NULL, HFILL }\n"
			"\t\t},\n", hfi_var(hfi), hfi_name(hfi), proto_name, hfi_filter(hfi), hfi_type(hfi), hfi_display(hfi), hfi_mask(hfi) );
	}
	gen_fprintf(f, "\t};\n\n");

	/* ett array */
	gen_fprintf(f, "\tstatic gint *ett[] = {\n");
	for (ett = etts; ett; ett = ett->next)
		gen_fprintf(f, "\t\t&%s,\n", ett_var(ett));
	gen_fprintf(f, "\t};\n\n");


	gen_fprintf(f, "\tproto_%s = proto_register_protocol(\"%s\", \"%s\", \"%s\");\n\n", proto_name, proto_name, proto_name, proto_name);

	gen_fprintf(f, "\tproto_register_field_array(proto_%s, hf, array_length(hf));\n", proto_name);
	gen_fprintf(f, "\tproto_register_subtree_array(ett, array_length(ett));\n");

	gen_fprintf(f, "}\n\n");
}

static void
gen_proto_handoff(FILE *f, const char *proto_name)
{
	gen_fprintf(f,
		"void\n"
		"proto_reg_handoff_%s(void)\n"
		"{\n", proto_name);

	gen_fprintf(f, "\tdissector_handle_t %s_handle = new_create_dissector_handle(dissect_%s, proto_%s);\n", proto_name, proto_name, proto_name);

#if 0
	dissector_add_uint("REG", XXX, %s_handle);

	xml_handle = find_dissector("xml");
#endif
	gen_fprintf(f, "}\n\n");
}

static const npl_protocol_t *
get_protocol(npl_code_t *code)
{
	struct _npl_decl_list *decl;

	for (decl = code->decls; decl; decl = decl->next) {
		/* XXX, for now return first */
		if (decl->d.type == DECL_PROTOCOL)
			return &decl->d.p.data;
	}
	return NULL;
}

static void
merge_code(npl_code_t *code, npl_code_t *subcode)
{
	struct _npl_decl_list **p = &code->decls;

	while (*p)
		p = &(*p)->next;

	*p = subcode->decls;
}

/* XXX, move to checker.c */
static void
check_code(npl_code_t *code)
{
	parse_includes(code);
	walk_code(NULL, code, 1);
}

/* XXX, move to generator-c.c */
static void
generate_code(npl_code_t *code)
{
	const npl_protocol_t *proto = get_protocol(code);
	const char *proto_name = (proto) ? proto->id : "noname";
	FILE *out;
	struct symbol *sym;

	out = fopen("/tmp/npl.c", "w");

	/* includes */
	gen_fprintf(out, "#include \"config.h\"\n");
	gen_fprintf(out, "#include <glib.h>\n");
	gen_fprintf(out, "#include <epan/packet.h>\n");
	gen_fprintf(out, "\n");

	/* declare forward (or extern) */
	/* XXX, not enough to generate from table (like private structs) */
	for (sym = symbols; sym; sym = sym->next) {
		const char *sstatic = (sym->is_static) ? "static " : "";

		if (!sym->is_used)
			continue;

		switch (sym->type) {
			case SYMBOL_TABLE:
				gen_fprintf(out, "%sconst char *format_table_%s(...);\n", sstatic, sym->id);
				break;
			case SYMBOL_STRUCT:
				gen_fprintf(out, "%sint dissect_struct_%s(tvbuff_t *, packet_info *, proto_tree *, int, int);\n", sstatic, sym->id);
				break;
			case SYMBOL_PROTO:
				gen_fprintf(out, "%sint dissect_%s(tvbuff_t *, packet_info *, proto_tree *, void *);\n", sstatic, sym->id);
				break;
		}
	}
	gen_fprintf(out, "\n");

	gen_fprintf(out, "static int proto_%s = -1;\n", proto_name);
	gen_fprintf(out, "static int ett_%s = -1;\n", proto_name);
	gen_vars(out);

	walk_code(out, code, 1);

	gen_proto_register(out, proto_name);
	gen_proto_handoff(out, proto_name);

	fclose(out);
}

int main(int argc, char **argv) {
	FILE *f;
	npl_code_t code;

	int i;

	if (argc < 2) {
		fprintf(stderr, "usage: %s filename\n", argv[0]);
		return 1;
	}

	/* build-in expressions */
	symbol_add("FrameOffset", SYMBOL_SIMPLE, "offset");
	symbol_add("FrameData", SYMBOL_SIMPLE, "tvb");
	symbol_add("this", SYMBOL_EXPR, &this_e);

	/* built-in functions */
	symbol_add("FormatString", SYMBOL_EXPR, &format_string_e);
	symbol_add("IsValueNone", SYMBOL_EXPR, &is_value_none_e);

	/* built-in structs (?) */
	symbol_add("Property", SYMBOL_EXPR, &property_e); /* XXX, SYMBOL_STRUCT */
	symbol_add("Global", SYMBOL_EXPR, &global_e); /* XXX, SYMBOL_STRUCT */
	symbol_add("Local", SYMBOL_EXPR, &local_e); /* XXX, SYMBOL_STRUCT */

	memset(&code, 0, sizeof(code));

	for (i = 1; i < argc; i++) {
		npl_code_t mcode;
		int parse_ok;

		if (!(f = fopen(argv[i], "rb"))) {
			fprintf(stderr, "can't open: %s\n", argv[i]);
			continue;
			return 1;
		}

		memset(&mcode, 0, sizeof(mcode));
		parse_ok = npl_parse_file(&mcode, f, argv[i]);
		fclose(f);

		if (!parse_ok) {
			fprintf(stderr, "can't parse: %s\n", argv[i]);
			return 1;
		}

		merge_code(&code, &mcode);
	}

	check_code(&code);
	generate_code(&code);

	return 0;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
