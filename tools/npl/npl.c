/* 
 * Copyright 2012-2013, Jakub Zawadzki <darkjames-ws@darkjames.pl>
 *
 * $Id$
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
#include <string.h>
#include <stdlib.h>

#include "ast.h"
#include "xmem.h"

int npl_parse_file(npl_code_t *code, FILE *f, const char *filename); /* parser.l */

static void gen_expr(FILE *f, npl_expression_t *e);
static void gen_statements(FILE *f, struct _npl_statements *sts);
static void gen_struct(FILE *f, npl_struct_t *s);

struct ettinfo {
	struct ettinfo *next;
	npl_struct_t *st;
};

struct hfinfo {
	struct hfinfo *next;
	struct _npl_statement_field *st;

	unsigned int id;
	const char *hf_type;
};

enum symbol_type {
	SYMBOL_ANY    = (~0),
	SYMBOL_EXPR   = (1 << 0),
	SYMBOL_STRUCT = (1 << 1),
	SYMBOL_TABLE  = (1 << 2),
	SYMBOL_TYPE   = (1 << 3),
	SYMBOL_FIELD  = (1 << 4)
};

struct symbol {
	struct symbol *next;

	const char *id;
	enum symbol_type type;
	int lvl;
	void *data;
};

struct symbol *symbols;
struct hfinfo *hfs;
struct ettinfo *etts;

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

static struct symbol *
symbol_find(const char *id, int type)
{
	struct symbol *sym;

	for (sym = symbols; sym; sym = sym->next) {
		if (!strcasecmp(sym->id, id)) {
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
hfi_add(struct _npl_statement_field *st)
{
	static unsigned int _hf_id = 0;

	struct hfinfo *new = xnew(struct hfinfo);

	new->st = st;
	new->id = ++_hf_id;

	new->next = hfs;
	hfs = new;

	return new;
}

static const char *
hfi_var(const struct hfinfo *hfi)
{
	/* XXX nicer name */
	static char hf_name[64];

	snprintf(hf_name, sizeof(hf_name), "hf_field_%u", hfi->id);

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
	/* TODO stub */
	return "";
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
static const npl_expression_t *
id_to_expr(const char *id)
{
	struct symbol *sym = symbol_find(id, SYMBOL_EXPR | SYMBOL_FIELD);

	if (!sym) {
		fprintf(stderr, "can't find id: %s\n", id);
		abort();
	}

	if (sym->type == SYMBOL_EXPR)
		return sym->data;
	else if (sym->type == SYMBOL_FIELD) {
		fprintf(stderr, "XXX ID %s SYMBOL_FIELD\n", sym->id);
		return NULL;
	} else {
		fprintf(stderr, "ID %s invalid type [%d]\n", sym->id, sym->type);
		abort();
	}
}

static int
expr_to_int(const npl_expression_t *e, int *val)
{
	if (e->type == EXPRESSION_INT) {
		*val = e->num.digit;
		return 1;
	}
	if (e->type == EXPRESSION_UNARY) {
		if (!expr_to_int(e->u.operand, val))
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
	}
	if (e->type == EXPRESSION_ID) {
		e = id_to_expr(e->id.id);
		if (e)
			return expr_to_int(e, val);
	}
	return 0;
}

static int
expr_to_str(const npl_expression_t *e, const char **val)
{
	if (e->type == EXPRESSION_STR) {
		*val = e->str.str;
		return 1;
	}
	if (e->type == EXPRESSION_ID) {
		e = id_to_expr(e->id.id);
		if (e)
			return expr_to_str(e, val);
	}
	return 0;
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

static void
gen_expr_type(FILE *f, npl_type_t *t)
{
	fprintf(stderr, "XXX gen expr type: %s\n", t->id);

	gen_fprintf(f, "<<TYPE %s>>", t->id);
}

static void
gen_expr(FILE *f, npl_expression_t *e)
{
	switch (e->type) {
		case EXPRESSION_ID:
			{
				struct symbol *sym = symbol_find(e->id.id, SYMBOL_EXPR | SYMBOL_FIELD | SYMBOL_TYPE);

				if (!sym) {
					fprintf(stderr, "can't find id: %s\n", e->id.id);
					gen_fprintf(f, " <<UNK %s>> ", e->id.id);
					return;
					abort();
				}

				if (sym->type == SYMBOL_EXPR) {
					gen_expr(f, sym->data);
				} else if (sym->type == SYMBOL_FIELD) {
					struct _npl_statement_field *field = sym->data;

					xassert(field->generate_var || f == NULL);

					field->generate_var = 1;
					gen_fprintf(f, "_field_%s", sym->id);

				} else if (sym->type == SYMBOL_TYPE) {
					npl_type_t *t = sym->data;

					gen_expr_type(f, t);
				} else {
					fprintf(stderr, "ID %s wrong type [%d]\n", sym->id, sym->type);
					abort();
				}
			}
			return;

		case EXPRESSION_INT:
			gen_fprintf(f, " %d ", e->num.digit);
			return;

		case EXPRESSION_STR:
			// XXX e->str.str is escaped, almost like C-string so just print it.
			gen_fprintf(f, " \"%s\" ", e->str.str);
			return;

		case EXPRESSION_UNARY:
			gen_fprintf(f, "(");
			gen_fprintf(f, "%s", op1_to_str(e->u.operator));
			gen_expr(f, e->u.operand);
			gen_fprintf(f, ")");
			return;

		case EXPRESSION_BINARY:
			gen_fprintf(f, "(");
			gen_expr(f, e->b.operand1);
			gen_fprintf(f, " %s ", op2_to_str(e->b.operator));
			gen_expr(f, e->b.operand2);
			gen_fprintf(f, ")");
			return;

		case EXPRESSION_CALL:
		{
			npl_expression_list_t *arg;
			char *ind = "";

			gen_expr(f, e->call.fn);
			gen_fprintf(f, "(");
			for (arg = e->call.args; arg; arg = arg->next) {
				gen_fprintf(f, "%s", ind);
				gen_expr(f, arg->expr);
				ind = ", ";
			}
			gen_fprintf(f, ")");
			return;
		}

		case EXPRESSION_FIELD:
			gen_expr(f, e->fld.base);
			gen_fprintf(f, ".%s ", e->fld.field);
			return;
	}
	fprintf(stderr, "XXX expr->type: %d\n", e->type);
}

static int
gen_table_struct(FILE *f, npl_table_t *t)
{
	enum { CANT, VALUE_STRING, STRING_STRING } type;
	struct npl_table_case *c;

	int all_int = 1;
	int all_str = 1;

	if (t->params.count || !t->switch_expr || t->default_expr)
		return 0;

	for (c = t->cases; c; c = c->next) {
		const char *str;
		int val;

		if (!c->return_expr || !expr_to_str(c->return_expr, &str))
			return 0;

		if (all_int && !expr_to_int(&c->e, &val))
			all_int = 0;
		if (all_str && !expr_to_str(&c->e, &str))
			all_str = 0;

		if (!all_int && !all_str)
			return 0;
	}

	if (all_int)
		type = VALUE_STRING;
	else if (all_str)
		type = STRING_STRING;
	else
		type = CANT;

	/* table can be converted to value_string, generate one */
	if (f && type == VALUE_STRING) {
		gen_fprintf(f,
			"static const value_string %s[] = {\n",
			t->id);

		for (c = t->cases; c; c = c->next) {
			const char *str;
			int val;

			/* checked above, should not fail now */
			if (!expr_to_str(c->return_expr, &str))
				fail("expr_to_str(str)");
			if (!expr_to_int(&c->e, &val))
				fail("expr_to_int(val)");

			gen_fprintf(f, "\t{ 0x%x, \"%s\" },\n", val, str);
		}
		gen_fprintf(f, "\t{ 0, NULL }\n");
		gen_fprintf(f, "};\n");
		return 1;
	}

	/* table can be converted to string_string, generate one */
	if (f && type == STRING_STRING) {
		gen_fprintf(f,
			"static const string_string %s[] = {\n",
			t->id);

		for (c = t->cases; c; c = c->next) {
			const char *str;
			const char *val;

			/* checked above, should not fail now */
			if (!expr_to_str(c->return_expr, &str))
				fail("expr_to_str(str)");
			if (!expr_to_str(&c->e, &val))
				fail("expr_to_str(val)");

			gen_fprintf(f, "\t{ \"%s\", \"%s\" },\n", val, str);
		}
		gen_fprintf(f, "\t{ NULL, NULL }\n");
		gen_fprintf(f, "};\n");
		return 1;
	}

	return 0;
}

static void
gen_table_func(FILE *f, npl_table_t *t)
{
	struct npl_table_case *c;

	gen_fprintf(f,
		"static const char *\n"
		"format_table_%s", t->id);

	gen_fprintf(f, "(");
	if (t->params.count) {
		int i;

		for (i = 0; i < t->params.count; i++) {
			if (i)
				gen_fprintf(f, ", ");
			gen_fprintf(f, "TYPE %s", t->params.args[i]);
		}

	} else {
		/* default */
		gen_fprintf(f, "TYPE value");
	}
	gen_fprintf(f, ")\n{\n");

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

	if (t->default_expr) {
		gen_fprintf(f, "\treturn ");
		gen_expr(f, t->default_expr);
		gen_fprintf(f, ";\n");
	} else
		gen_fprintf(f, "\treturn \"\";\n");

	gen_fprintf(f, "}\n");
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
	if (!gen_table_struct(f, t))
		gen_table_func(f, t);

	gen_fprintf(f, "\n");
}

static void
gen_field_struct(FILE *f, npl_statement_t *st, npl_struct_t *s)
{
	// XXX st->f.bits, st->f.arr, st->f.format, st->f.sts

	gen_fprintf(f, "\toffset = dissect_struct_%s(tvb, pinfo, tree, %s, offset);\n", s->tmpid, hfi_var(st->f.hfi));

	st->f.hfi->hf_type = "FT_BYTES";
}

static void
gen_field_type(FILE *f, npl_statement_t *st, npl_type_t *t)
{
	struct symbol *symroot;
	int i;

	// XXX st->f.bits, st->f.arr, st->f.sts

	int size = -1;
	int byte_order = -1;
	npl_expression_t *display_format = t->display_format;
	const char *hf_type;

	npl_expression_list_t *argv = st->f.params;
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

	if (t->size && !expr_to_int(t->size, &size))
		fprintf(stderr, "!!! expr_to_int(size) failed for type: %s\n", t->id);

	if (t->byte_order && !expr_to_int(t->byte_order, &byte_order))
		fprintf(stderr, "!!! expr_to_int(byte_order) failed for type: %s\n", t->id);

	hf_type = type_to_ft(t, size);

	st->f.hfi->hf_type = hf_type;

	/* prefer statement format over type one (?) */
	if (st->f.format)
		display_format = st->f.format;
#if 0
	if (display_format)
		fprintf(stderr, "XXX, format\n");
	else
#endif
	gen_fprintf(f, "\tproto_tree_add_item(tree, %s, tvb, offset, %d, %s); ",
		hfi_var(st->f.hfi),
		size,
		(byte_order == 0) ? "ENC_LITTLE_ENDIAN" : 
		(byte_order == 1) ? "ENC_BIG_ENDIAN" : 
		"ENC_NA");
	gen_fprintf(f, "offset += %d;\n", size);

	symbols_pop(symroot);
}

static void
gen_statement(FILE *f, npl_statement_t *st)
{
	switch (st->type) {
		case STATEMENT_WHILE:
			// XXX ->id
			gen_fprintf(f, "\twhile (");
			gen_expr(f, &st->w.expr);
			gen_fprintf(f, ") {\n");

			gen_statements(f, st->w.sts);

			gen_fprintf(f, "\t}\n"); 
			return;

		case STATEMENT_STRUCT:
			gen_struct(NULL, &st->s.data);
			// XXX put st->s.data somewhere to create this proc.
			gen_fprintf(f, "\toffset = dissect_struct_%s(tvb, pinfo, tree, hf_costam, offset);\n", st->s.data.tmpid);
			return;

		case STATEMENT_FIELD:
		{
			struct symbol *sym;
			
			if (!st->f.hfi) {
				st->f.hfi = hfi_add(&st->f);
				xassert(f == NULL);
			}

			sym = symbol_find(st->f.t_id, SYMBOL_STRUCT | SYMBOL_TYPE);

			if (!sym) {
				fprintf(stderr, "can't find: %s\n", st->f.t_id);
				abort();
			}

			if (st->f.generate_var) {
				// XXX
				gen_fprintf(f, "\t_field_%s = tvb_...\n", st->f.id);
			}

			symbol_add(st->f.id, SYMBOL_FIELD, &st->f);

			if (sym->type == SYMBOL_STRUCT)
				gen_field_struct(f, st, sym->data);
			else if (sym->type == SYMBOL_TYPE)
				gen_field_type(f, st, sym->data);
			else {
				/* XXX, SYMBOL_TABLE? */
				fprintf(stderr, "%s: wrong type [%d]\n", st->f.t_id, sym->type);
				abort();
			}
			return;
		}

		/* case STATEMENT_DYNAMIC_SWITCH: */
		case STATEMENT_SWITCH:
		{
			struct npl_switch_case *c = st->sw.data.cases;

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
						gen_statement(f, c->st);
						gen_fprintf(f, "\t\t\tbreak;\n");
					}
					c = c->next;
				}

				if (st->sw.data.default_st) {
					gen_fprintf(f, "\t\tdefault:\n");
					gen_fprintf(f, "\t\t");
					gen_statement(f, st->sw.data.default_st);
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
					gen_statement(f, case_st);
					gen_fprintf(f, "\t} ");

					if (c || default_st)
						gen_fprintf(f, "else ");
				}

				if (default_st) {
					gen_fprintf(f, "{\n");
					gen_fprintf(f, "\t");
					gen_statement(f, default_st);
					gen_fprintf(f, "\t}\n");
				}

			} else {
				if (st->sw.data.default_st)
					gen_statement(f, st->sw.data.default_st);
			}
			return;
		}
	}
	fprintf(stderr, "gen_statement: %d\n", st->type);
}

static void
gen_statements(FILE *f, struct _npl_statements *sts)
{
	struct symbol *symroot;

	symroot = symbols_push();

	while (sts) {
		gen_statement(f, &sts->st);

		sts = sts->next;
	}

	symbols_pop(symroot);
}

static void
gen_protocol(FILE *f, npl_protocol_t *p)
{
	gen_fprintf(f, 
		"static int\n"
		"dissect_%s(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)\n", p->id);

	gen_fprintf(f, "{\n");
	gen_fprintf(f, 
		"\tint offset = 0;\n"
		"\tproto_tree *tree = NULL;\n"
		"\tproto_item *ti = NULL;\n"
		"\n"
	);

	if (p->format) {


	}

	gen_statements(f, p->sts);

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
gen_struct(FILE *f, npl_struct_t *s)
{
	const char *id = s->tmpid;

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

	gen_fprintf(f,
			"static int\n"
			"dissect_struct_%s(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int hf_index%s, int offset)\n"
			"{\n", id, s->private ? " _U_" : "");

	if (!s->private) {
		gen_fprintf(f, "\tconst int org_offset = offset;\n");

		gen_fprintf(f, "\tproto_tree *tree = NULL\n");
		gen_fprintf(f, "\tproto_item *ti = NULL;\n");
	} else
		gen_fprintf(f, "\tproto_tree *tree = parent_tree\n");

	gen_fprintf(f,"\n");

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
			"\t\tti = proto_tree_add_bytes_format(tree, hf_index, tvb, offset, 0, NULL, \"%s\");\n"
			"\t\ttree = proto_item_add_subtree(ti, %s);\n"
			"\t}\n", "description", ett_var(s->ett));

	} else {
		if (s->format)
			fprintf(stderr, "s->private && s->format?\n");
	}

	gen_statements(f, s->sts);

	if (!s->private)
		gen_fprintf(f, "\tproto_item_set_len(ti, offset - org_offset);\n");
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
gen_attr(FILE *f, npl_attr_t *a)
{
	fprintf(stderr, "gen_attr() TODO\n");
}

static void
walk_decl(FILE *f, npl_decl_t *d, int full_run)
{
	switch (d->type) {
		case DECL_ATTR:
			if (!full_run)
				return;
			gen_attr(f, &d->a.data);
			return;
		case DECL_STRUCT:
			decl_struct(&d->s.data);
			if (!full_run)
				return;
			gen_struct(f, &d->s.data);
			return;
		case DECL_TABLE:
			decl_table(&d->t.data);
			if (!full_run)
				return;
			gen_table(f, &d->t.data);
			return;
		case DECL_PROTOCOL:
			/* XXX decl_protocol */
			if (!full_run)
				return;
			gen_protocol(f, &d->p.data);
			return;
		case DECL_CONST:
			decl_const(&d->c.data);
			if (!full_run)
				return;
			return;
		case DECL_TYPE:
			decl_type(&d->ty.data);
			if (!full_run)
				return;
			return;
		case DECL_INCLUDE:
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
				"\t\t\t{ \"%s\", \"%s\", %s, %s, NULL, 0x%.2x, NULL, HFILL }\n"
			"\t\t},\n", hfi_var(hfi), hfi_name(hfi), hfi_filter(hfi), hfi_type(hfi), hfi_display(hfi), hfi_mask(hfi) );
	}
	gen_fprintf(f, "\t};\n\n");

	/* ett array */
	gen_fprintf(f, "\tstatic gint *ett[] = {\n");
	for (ett = etts; ett; ett = ett->next)
		gen_fprintf(f, "\t\t&%s,\n", ett_var(ett));
	gen_fprintf(f, "\t};\n\n");


	gen_fprintf(f, "\tproto_%s = proto_register_protocol(\"foo1\", \"foo2\", \"%s\");\n\n", proto_name, proto_name);

	gen_fprintf(f, "\tproto_register_field_array(proto_%s, hf, array_length(hf));\n", proto_name);
	gen_fprintf(f, "\tproto_register_subtree_array(ett, array_length(ett));\n");

	gen_fprintf(f, "}\n");
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
	gen_fprintf(f, "}\n");
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

int main(int argc, char **argv) {
	FILE *f;
	npl_code_t code;
	int parse_ok;

	if (argc != 2) {
		fprintf(stderr, "usage: %s filename\n", argv[0]);
		return 1;
	}

	if (!(f = fopen(argv[1], "rb"))) {
		fprintf(stderr, "can't open: %s\n", argv[1]);
		return 1;
	}

	memset(&code, 0, sizeof(code));
	parse_ok = npl_parse_file(&code, f, argv[1]);

// parse_ok = 0;
	if (parse_ok) {
		const npl_protocol_t *proto = get_protocol(&code);
		const char *proto_name = (proto) ? proto->id : "noname";
		FILE *out;

		parse_includes(&code);
		walk_code(NULL, &code, 1);

		out = fopen("/tmp/npl.c", "w");

		/* includes */
		gen_fprintf(out, "#include \"config.h\"\n");
		gen_fprintf(out, "#include <glib.h>\n");
		gen_fprintf(out, "#include <epan/packet.h>\n");
		gen_fprintf(out, "\n");

		/* TODO declare forward */

		gen_fprintf(out, "static int proto_%s = -1;\n", proto_name);
		gen_vars(out);

		walk_code(out, &code, 1);

		gen_proto_register(out, proto_name);
		gen_proto_handoff(out, proto_name);

		fclose(out);
	}
	fclose(f);
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
