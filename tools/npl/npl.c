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

void npl_parse_file(npl_code_t *code, FILE *f, const char *filename); /* parser.l */

static void gen_expr(FILE *f, npl_expression_t *e);
static void gen_statements(FILE *f, struct _npl_statements *sts);

struct hfinfo {
	struct hfinfo *next;
	npl_statement_t *st;

	unsigned int id;
};

struct hfinfo *hfs;


static struct hfinfo *
add_hfi(npl_statement_t *st)
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
hfi_name(const struct hfinfo *hfi)
{
	static char hf_name[64];

	snprintf(hf_name, sizeof(hf_name), "hf_field_%u", hfi->id);

	return hf_name;
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
	fprintf(stderr, "XXXX op: %d\n", op);
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
	fprintf(stderr, "XXXX op: %d\n", op);
	return "";
}

static void
gen_expr(FILE *f, npl_expression_t *e)
{
	switch (e->type) {
		case EXPRESSION_ID:
			gen_fprintf(f, " %s ", e->id.id);
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
			struct _npl_expression_list *arg;
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
	}
	fprintf(stderr, "XXXX expr->type: %d\n", e->type);
}

static void
gen_table(FILE *f, npl_table_t *t)
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
				if (!c)
					abort();
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
				if (!c)
					abort();
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
	gen_fprintf(f, "\n");
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
			// XXX put st->s somewhere to create this proc.
			gen_fprintf(f, "\toffset = dissect_struct_%s(tvb, tree, hf_costam, offset);\n", st->s.data.id);
			return;

		case STATEMENT_FIELD:
		{
			if (!st->f.hfi) {
				st->f.hfi = add_hfi(st);
				// asssert f == NULL
			}

			if (f) {
				// XXX, search for st->f.t_id in table.
				gen_fprintf(f, "\toffset = dissect_%s(tvb, tree, %s, offset);\n", st->f.t_id, hfi_name(st->f.hfi));
			}
			// XXX st->f.bits, st->f.arr, st->f.format, st->f.sts
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
	while (sts) {
		gen_statement(f, &sts->st);

		sts = sts->next;
	}
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
gen_struct(FILE *f, npl_struct_t *s)
{
	const char *tree_var;

	if (!s->id) {
		static unsigned int _id = 0;
		char id[32];

		snprintf(id, sizeof(id), "_noname%u", ++_id);
		s->id = xstrdup(id);

		if (f != NULL)
			abort();
	}

	if (s->count_expr) {
		/* TODO */
		fprintf(stderr, "TODO: s->count_expr");
	}

	gen_fprintf(f,
			"static int\n"
			"dissect_struct_%s(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)\n"
			"{\n", s->id);

	if (!s->private) {
		gen_fprintf(f, "\tconst int org_offset = offset;\n");

		gen_fprintf(f, "\tproto_tree *tree = NULL\n");
		gen_fprintf(f, "\tproto_item *ti = NULL;\n");
	} else
		gen_fprintf(f, "\tproto_tree *tree = parent_tree\n");

	gen_fprintf(f,"\n");

	if (!s->private) {
		static unsigned int _ett_id = 0;
		char ett_name[64];
/*
		if (s->format) {
			fprintf(stderr, "gen_struct() s->format: '");
			gen_expr(stderr, s->format);
			fprintf(stderr, "\n\n");
		}
 */
		snprintf(ett_name, sizeof(ett_name), "ett_field_%u", ++_ett_id);

		gen_fprintf(f,
			"\tif (parent_tree) {\n"
			"\t\tti = proto_tree_add_bytes_format(tree, hf_%s, tvb, offset, 0, NULL, \"%s\");\n"
			"\t\ttree = proto_item_add_subtree(ti, %s);\n"
			"\t}\n", "hf_name", "description", ett_name);

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
gen_const(FILE *f, npl_const_t *c)
{
// TODO
	fprintf(stderr, "gen_const() TODO\n");
}

static void
gen_type(FILE *f, npl_type_t *t)
{
	gen_fprintf(f,
			"static int\n"
			"dissect_type_%s(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)\n"
			"{\n", t->name);

#if 0
	npl_params_t params;

	npl_expression_t *byte_order;
	npl_expression_t *display_format;
	npl_expression_t *size;
#endif

	gen_fprintf(f, "\treturn offset;\n");
	gen_fprintf(f, "}\n");
	gen_fprintf(f, "\n");
}

static void
gen_attr(FILE *f, npl_attr_t *a)
{
// TODO
	fprintf(stderr, "gen_attr() TODO");
}

static void
gen_decl(FILE *f, npl_decl_t *d)
{
	switch (d->type) {
		case DECL_ATTR:
			gen_attr(f, &d->a.data);
			return;
		case DECL_STRUCT:
			gen_struct(f, &d->s.data);
			return;
		case DECL_TABLE:
			gen_table(f, &d->t.data);
			return;
		case DECL_PROTOCOL:
			gen_protocol(f, &d->p.data);
			return;
		case DECL_CONST:
			gen_const(f, &d->c.data);
			return;
		case DECL_TYPE:
			gen_type(f, &d->ty.data);
			return;
	}
	fprintf(stderr, "gen_decl() type: %d\n", d->type);
}

static void
gen_code(FILE *f, npl_code_t *c)
{
	struct _npl_decl_list *decl;

	for (decl = c->decls; decl; decl = decl->next)
		gen_decl(f, &decl->d);
}

static void
gen_hf(FILE *f)
{
	struct hfinfo *hfi;

	for (hfi = hfs; hfi; hfi = hfi->next)
		gen_fprintf(f, "static int %s = -1;\n", hfi_name(hfi));
}

static const char proto_name[] = "foo"; /* TODO, hardcoded */

static void
gen_proto_register(FILE *f)
{
	struct hfinfo *hfi;

	gen_fprintf(f, 
		"void\n"
		"proto_register_%s(void)\n"
		"{\n", proto_name);

	/* hf array */
	gen_fprintf(f, "\tstatic hf_register_info hf[] = {\n");
	for (hfi = hfs; hfi; hfi = hfi->next) {
		npl_statement_t *st = hfi->st;

		gen_fprintf(f, 
			"\t\t{ &%s,\n"
				"\t\t\t{ \"%s\", \"%s\", %s, %s, NULL, 0x%.2x, NULL, HFILL }\n"
			"\t\t},\n", hfi_name(hfi), st->f.id, "filtr", "typ", "dec", 0x00 );
	}
	gen_fprintf(f, "\t}\n\n");

	gen_fprintf(f, "\tstatic gint *ett[] = {\n");
#if 0
		&ett_foo,
		&ett_foo_smth1
#endif
	gen_fprintf(f, "\t}\n\n");


	gen_fprintf(f, "\tproto_%s = proto_register_protocol(\"foo1\", \"foo2\", \"%s\");\n\n", proto_name, proto_name);

	gen_fprintf(f, "\tproto_register_field_array(proto_%s, hf, array_length(hf));\n", proto_name);
	gen_fprintf(f, "\tproto_register_subtree_array(ett, array_length(ett));\n");

	gen_fprintf(f, "}\n");
}

static void
gen_proto_handoff(FILE *f)
{
	gen_fprintf(f,
		"void\n"
		"proto_reg_handoff_%s(void)\n"
		"{", proto_name);

	gen_fprintf(f, "dissector_handle_t %s_handle = new_create_dissector_handle(dissect_%s, proto_%s);\n", proto_name, proto_name, proto_name);

#if 0
	dissector_add_uint("REG", XXX, %s_handle);

	xml_handle = find_dissector("xml");
#endif
	gen_fprintf(f, "}\n");
}

int main(int argc, char **argv) {
	FILE *f;
	npl_code_t code;
	
	if (argc != 2) {
		fprintf(stderr, "usage: %s filename\n", argv[0]);
		return 1;
	}

	if (!(f = fopen(argv[1], "rb"))) {
		fprintf(stderr, "can't open: %s\n", argv[1]);
		return 1;
	}

	memset(&code, 0, sizeof(code));
	printf("%s:\n", argv[1]);
	npl_parse_file(&code, f, argv[1]);

	if (code.parse_ok) {
		FILE *out;

		gen_code(NULL, &code);

		out = fopen("/tmp/npl.c", "w");

		/* TODO declare ett_ */
		gen_hf(out);

		gen_fprintf(out, "\n\n");

		gen_code(out, &code);

		gen_proto_register(out);
		gen_proto_handoff(out);
	}
	fclose(f);
	return 0;
}
