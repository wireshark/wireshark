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

%option noyywrap 
%option nounput

%option noyy_scan_buffer
%option noyy_scan_bytes
%option noyy_scan_string

%option yylineno
%option never-interactive

%option case-insensitive

%{
#define YY_DECL static token_type_t yylex(void)

#include <setjmp.h>
#include "ast.h"
#include "xmem.h"

typedef enum {
	TOKEN_ERROR = -1,
	TOKEN_EOF = 0,

	TOKEN_INCLUDE,
	TOKEN_STRUCT,
	TOKEN_PRIVATE_STRUCT,
	TOKEN_CONST,
	TOKEN_PROTOCOL,

	TOKEN_WHILE,

	TOKEN_DYNAMIC_SWITCH,
	TOKEN_SWITCH,
	TOKEN_TABLE,
	TOKEN_CASE,
	TOKEN_DEFAULT,

	TOKEN_ID,
	TOKEN_STR,
	TOKEN_CHAR,
	TOKEN_DIGIT,
	TOKEN_FLOAT,

	TOKEN_LPAREN,
	TOKEN_RPAREN,
	TOKEN_LBRACKET,
	TOKEN_RBRACKET,
	TOKEN_LCURLY,
	TOKEN_RCURLY,

	TOKEN_ANDAND,
	TOKEN_OROR,

	TOKEN_EQUAL,
	TOKEN_NOTEQUAL,
	TOKEN_NOTEQUAL2,

	TOKEN_LEQUAL,
	TOKEN_GEQUAL,

	TOKEN_ASSIGN,
	TOKEN_ASSIGN_PLUS,
	TOKEN_PLUS,
	TOKEN_MINUS,
	TOKEN_MULTIPLY,
	TOKEN_DIV,
	TOKEN_LOGIC_OR,
	TOKEN_OR,
	TOKEN_LOGIC_AND,
	TOKEN_AND,
	TOKEN_NOT,
	TOKEN_NEG,
	TOKEN_XOR,

	TOKEN_SHL,
	TOKEN_SHR,

	TOKEN_PERCENT,
	TOKEN_DOLLAR,
	TOKEN_COND,
	TOKEN_COLON,

	TOKEN_SEMICOLON,
	TOKEN_DOT,
	TOKEN_COMMA,

	TOKEN_LESS,
	TOKEN_GREATER,

	TOKEN_NUMBER,
	TOKEN_UNSIGNED_NUMBER,
	TOKEN_DECIMAL,
	TOKEN_TIME,
	TOKEN_BYTE_ORDER,
	TOKEN_DISPLAY_FORMAT,
	TOKEN_SIZE

} token_type_t;

%}

%x cppcomment
%x lch
%x lstr
%x lstrescape

DIGIT10  [0-9]
DIGIT16  [0-9a-fA-F]

ID       [_a-zA-Z][_a-zA-Z0-9]*

%%

include return TOKEN_INCLUDE;
struct return TOKEN_STRUCT;
_struct return TOKEN_PRIVATE_STRUCT;

const return TOKEN_CONST;
protocol return TOKEN_PROTOCOL;

while return TOKEN_WHILE;

DynamicSwitch return TOKEN_DYNAMIC_SWITCH;
switch return TOKEN_SWITCH;
table return TOKEN_TABLE;
case return TOKEN_CASE;
default return TOKEN_DEFAULT;

Number return TOKEN_NUMBER;
UnsignedNumber return TOKEN_UNSIGNED_NUMBER;
Decimal return TOKEN_DECIMAL;
Time return TOKEN_TIME;
ByteOrder return TOKEN_BYTE_ORDER;
DisplayFormat return TOKEN_DISPLAY_FORMAT;
Size return TOKEN_SIZE;

"(" return TOKEN_LPAREN;
")" return TOKEN_RPAREN;
"[" return TOKEN_LBRACKET;
"]" return TOKEN_RBRACKET;
"{" return TOKEN_LCURLY;
"}" return TOKEN_RCURLY;

and  return TOKEN_ANDAND;
or   return TOKEN_OROR;

"==" return TOKEN_EQUAL;
"!=" return TOKEN_NOTEQUAL;
"<>" return TOKEN_NOTEQUAL2;

">=" return TOKEN_GEQUAL;
"<=" return TOKEN_LEQUAL;

"+=" return TOKEN_ASSIGN_PLUS;
"=" return TOKEN_ASSIGN;
"+" return TOKEN_PLUS;
"-" return TOKEN_MINUS;
"*" return TOKEN_MULTIPLY;
"/" return TOKEN_DIV;
"||" return TOKEN_LOGIC_OR;
"|" return TOKEN_OR;
"&&" return TOKEN_LOGIC_AND;
"&" return TOKEN_AND;
"!" return TOKEN_NOT;
"~" return TOKEN_NEG;
"^" return TOKEN_XOR;
"<<" return TOKEN_SHL;
">>" return TOKEN_SHR;
"%" return TOKEN_PERCENT;
"$" return TOKEN_DOLLAR;
"?" return TOKEN_COND;

";" return TOKEN_SEMICOLON;
"." return TOKEN_DOT;
"," return TOKEN_COMMA;
":" return TOKEN_COLON;

"<" return TOKEN_LESS;
">" return TOKEN_GREATER;

"'" yymore(); BEGIN(lch);
<lch>{
	"'" BEGIN(INITIAL); return TOKEN_CHAR;
	"\n" return TOKEN_ERROR;
	. yymore();
}

"\"" yymore(); BEGIN(lstr);
<lstr>{
	"\"" BEGIN(INITIAL); return TOKEN_STR;
	"\\" yymore(); BEGIN(lstrescape);
	"\n" return TOKEN_ERROR;
	. yymore();
}

<lstrescape>{
	"\n" return TOKEN_ERROR;
	. yymore(); BEGIN(lstr); 
}

"//" BEGIN(cppcomment);
<cppcomment>{
	"\n" BEGIN(INITIAL);
	. ;
}

"/*" {
	int nested = 1;
	int ch, last_ch;

	last_ch = '*';

	/* XXX, can comments be nested? (can't be determinated by current example file set) */

	do {
		ch = input();

		if (last_ch == '*' && ch == '/')
			nested--;

		if (last_ch == '/' && ch == '*')
			nested++;

		if (ch == EOF)
			return TOKEN_ERROR;

		last_ch = ch;

	} while(nested);
}

{ID} return TOKEN_ID;
{DIGIT10}+"."{DIGIT10}* return TOKEN_FLOAT;
{DIGIT10}+ return TOKEN_DIGIT;
"0x"{DIGIT16}+ return TOKEN_DIGIT;

[[:space:]] ;

.      return TOKEN_ERROR;

%%

static const char *yyfilename;
static int token;

static const char *token_name(token_type_t tok) {
	static char buf[64];

	switch (tok) {
		case TOKEN_EOF: return "<<eof>>";
		case TOKEN_ERROR: return "<<error>>";

		case TOKEN_ID:
			return "<ID>";
		case TOKEN_STR:
			return "<STR>";
		case TOKEN_CHAR:
			return "<CHAR>";
		case TOKEN_DIGIT:
			return "<DIGIT>";
		case TOKEN_FLOAT:
			return "<FLOAT>";

		case TOKEN_STRUCT:
			return "struct";
		case TOKEN_PRIVATE_STRUCT:
			return "_struct";
		case TOKEN_CONST:
			return "const";
		case TOKEN_WHILE:
			return "while";
		case TOKEN_SWITCH:
			return "switch";
		case TOKEN_DYNAMIC_SWITCH:
			return "dynamic switch";
		case TOKEN_CASE:
			return "case";

		/* ... */
		default:
			;
	}

	snprintf(buf, sizeof(buf), "<token #%d>", tok);
	return buf;
}

static jmp_buf parser_exception;

static void xfail(void) { longjmp(parser_exception, 1); }

static void next_token(void) { token = yylex(); }

static inline int is_token(token_type_t tok) { return (token == tok); }

static void _strange(int line) {
	fprintf(stdout, "?!?!? %s:%d got: %d (%s) @%s:%d\n", __FILE__, line, token, yytext, yyfilename, yylineno);
}
#define strange() _strange(__LINE__)

static void _nomatch(int line) {
	fprintf(stdout, "!!!! %s:%d got: %d (%s) @%s:%d\n", __FILE__, line, token, yytext, yyfilename, yylineno);
	xfail();
}
#define nomatch() _nomatch(__LINE__)

static void _accept(token_type_t tok, int line) {
	if (tok != token) {
		fprintf(stdout, "%s:%d got: %d (%s) expected %s @%s:%d\n", __FILE__, line, token, yytext, token_name(tok), yyfilename, yylineno);
		xfail();
	}
	next_token();
}
#define accept(tok) _accept(tok, __LINE__)

static int is_id(void) {
	/* Some NPL files use keyword as ID (sucks...) */
	return
		is_token(TOKEN_PROTOCOL) ||
		is_token(TOKEN_SIZE) ||
		is_token(TOKEN_DEFAULT) ||
		is_token(TOKEN_NUMBER) ||
		is_token(TOKEN_DECIMAL) ||
		is_token(TOKEN_TIME) ||
		is_token(TOKEN_BYTE_ORDER) ||
		is_token(TOKEN_OROR) || is_token(TOKEN_ANDAND) ||
		is_token(TOKEN_STRUCT) || is_token(TOKEN_TABLE) ||
		is_token(TOKEN_ID);
}

static char *_accept_id(int line) {
	char *id;

	if (!is_id()) {
		fprintf(stdout, "%s:%d got: %d (%s) expected %s @%s:%d\n", __FILE__, line, token, yytext, token_name(TOKEN_ID), yyfilename, yylineno);
		xfail();
	}
	
	id = xstrdup(yytext);
	next_token();

	return id;
}

#define accept_id() _accept_id(__LINE__)

static unsigned int _accept_int(int line) {
	unsigned int num;

	if (token != TOKEN_DIGIT) {
		fprintf(stdout, "%s:%d got: %d (%s) expected %s @%s:%d\n", __FILE__, line, token, yytext, token_name(TOKEN_DIGIT), yyfilename, yylineno);
		xfail();
	}

	if (yytext[0] == '0' && yytext[1] == 'x')
		num = strtol(yytext + 2, NULL, 16);
	else
		num = strtol(yytext, NULL, 10);

	next_token();

	return num;
}

#define accept_int() _accept_int(__LINE__)


static char *_accept_str(int line) {
	size_t len;
	char *str;

	if (token != TOKEN_STR) {
		fprintf(stdout, "%s:%d got: %d (%s) expected %s @%s:%d\n", __FILE__, line, token, yytext, token_name(TOKEN_STR), yyfilename, yylineno);
		xfail();
	}

	len = strlen(yytext);

	if (len < 2 || yytext[0] != '"' || yytext[len-1] != '"')
		xfail();
#if 0
	char *ptr;
	size_t i;

	ptr = str = xmalloc(len-2+1);
	for (i = 1; i < len-1; i++) {
		if (yytext[i] == '\\') {
			i++;

			if (yytext[i] == '0' && yytext[i+1] == 'x') {
				i += 2;

				// XXX
				*ptr++ = yytext[i];
			} else
				switch (yytext[i]) {
					case '0':
						*ptr++ = '\0';
						break;
					case '\\':
						*ptr++ = '\\';
						break;
					case 'r':
						*ptr++ = '\r';
						break;
					case 'n':
						*ptr++ = '\n';
						break;
					case 't':
						*ptr++ = '\t';
						break;

					case '"':
						*ptr++ = '"';
						break;
					case '\'':
						*ptr++ = '\'';
						break;

					default:
						fprintf(stdout, "unrecog: %c @ %d\n", yytext[i], yylineno);
						*ptr++ = yytext[i];
				}

		} else
			*ptr++ = yytext[i];
	}

	*ptr = '\0';
#else
	len -= 2;
	/* escaping is done almost like in C so don't unescape (cause it'd require escaping later...) */
	str = xmalloc(len + 1);
	memcpy(str, yytext + 1, len);
	str[len] = '\0';
#endif

	next_token();

	return str;
}
#define accept_str() _accept_str(__LINE__)

static int is_token_accept(token_type_t tok) {
	if (is_token(tok)) {
		next_token();
		return 1;
	}
	return 0;
}

static int is_params(void) { return is_token(TOKEN_LPAREN); }

static void
parse_params(npl_params_t *p)
{
	int i = 0;

	accept(TOKEN_LPAREN);
	do {
		if (i == NPL_PARAMS_MAX) {
			fprintf(stdout, "i == NPL_PARAMS_MAX");
			xfail();
		}

		p->args[i++] = accept_id();

	} while (is_token_accept(TOKEN_COMMA));
	accept(TOKEN_RPAREN);

	p->count = i;
}

static void parse_expression(npl_expression_t *expr);
static npl_expression_t *xparse_expression(void);

static void
parse_primary(npl_expression_t *expr)
{
	if (is_id()) {
		expr->type = EXPRESSION_ID;
		expr->id.id = accept_id();
		return;
	}

	if (is_token(TOKEN_DIGIT)) {
		expr->type = EXPRESSION_INT;
		expr->num.digit = accept_int();
		return;
	}

	if (is_token(TOKEN_FLOAT)) {
		// XXX ast
		accept(TOKEN_FLOAT);
		expr->type = -1;
		return;
	}

	if (is_token(TOKEN_CHAR)) {
		// XXX ast
		accept(TOKEN_CHAR);
		expr->type = -2;
		return;
	}

	if (is_token(TOKEN_STR)) {
		expr->type = EXPRESSION_STR;
		expr->str.str = accept_str();
		return;
	}

	if (is_token_accept(TOKEN_LPAREN)) {
		parse_expression(expr);
		accept(TOKEN_RPAREN);
		return;
	}

	nomatch();
}

/* ExpressionList = Expression, { ",", Expression } ; */
static void
parse_expression_list(npl_expression_list_t **ptr)
{
	do {
		npl_expression_list_t *cur = xnew(npl_expression_list_t);

		*ptr = cur;
		ptr = &(cur->next);
		cur->expr = xparse_expression();

	} while (is_token_accept(TOKEN_COMMA));

	*ptr = NULL;
}

static void
parse_expression1(npl_expression_t *expr)
{
	parse_primary(expr);

	do {
		if (is_token_accept(TOKEN_LPAREN)) {	/* foo() */
			npl_expression_t *fun = xdup(npl_expression_t, expr);
			npl_expression_list_t *args = NULL;

			if (!is_token(TOKEN_RPAREN))
				parse_expression_list(&args);
			accept(TOKEN_RPAREN);

			expr->type = EXPRESSION_CALL;
			expr->call.fn = fun;
			expr->call.args = args;

		} else if (is_token_accept(TOKEN_DOLLAR)) { /* arr$[field1, field2, ...] */
			npl_expression_t *base = xdup(npl_expression_t, expr);
			npl_expression_list_t *indexes;

			accept(TOKEN_LBRACKET);
			parse_expression_list(&indexes);
			accept(TOKEN_RBRACKET);

			expr->type = EXPRESSION_MULTI_INDEX;
			expr->aarr.base = base;
			expr->aarr.indexes = indexes;

		} else if (is_token_accept(TOKEN_LBRACKET)) { /* arr[10] */
			npl_expression_t *base = xdup(npl_expression_t, expr);
			npl_expression_t *idx;

			idx = xparse_expression();
			accept(TOKEN_RBRACKET);

			expr->type = EXPRESSION_INDEX;
			expr->arr.base = base;
			expr->arr.index = idx;

		} else if (is_token_accept(TOKEN_DOT)) {
			npl_expression_t *base = xdup(npl_expression_t, expr);
			char *field;

			field = accept_id();

			expr->type = EXPRESSION_FIELD;
			expr->fld.base = base;
			expr->fld.field = field;

		} else
			break;

	} while (1);
}

static void
parse_expression2(npl_expression_t *expr)
{
	npl_op1_t op;
	
	do {
		op = 
			(is_token_accept(TOKEN_MINUS)) ? OP1_MINUS : 
			(is_token_accept(TOKEN_NOT)) ? OP1_NOT :
			(is_token_accept(TOKEN_NEG)) ? OP1_NEG :
			OP1_INVALID;

		if (op != OP1_INVALID) {
			expr->type = EXPRESSION_UNARY;
			expr->u.operator = op;

			expr = expr->u.operand = xnew(npl_expression_t);
		}
	} while (op != OP1_INVALID);

	parse_expression1(expr);
}

static void
parse_expression3(npl_expression_t *expr)
{
	npl_op2_t op;

	parse_expression2(expr);
again:
	op = 
		(is_token_accept(TOKEN_MULTIPLY)) ? OP2_MULTIPLY :
		(is_token_accept(TOKEN_DIV)) ? OP2_DIV : 
		(is_token_accept(TOKEN_PERCENT)) ? OP2_MOD :
		OP2_INVALID;

	if (op != OP2_INVALID) {
		npl_expression_t *operand = xdup(npl_expression_t, expr);
		npl_expression_t *e;

		expr->b.operand2 = e = xnew(npl_expression_t);
		parse_expression3(e);

		expr->b.operator = op;
		expr->b.operand1 = operand;
		expr->type = EXPRESSION_BINARY;
		goto again;
	}
}

static void
parse_expression4(npl_expression_t *expr)
{
	npl_op2_t op;

	parse_expression3(expr);
again:
	op = 
		(is_token_accept(TOKEN_PLUS)) ? OP2_PLUS :
		(is_token_accept(TOKEN_MINUS)) ? OP2_MINUS : 
		OP2_INVALID;

	if (op != OP2_INVALID) {
		npl_expression_t *operand = xdup(npl_expression_t, expr);
		npl_expression_t *e;

		expr->b.operand2 = e = xnew(npl_expression_t);
		parse_expression4(e);

		expr->b.operator = op;
		expr->b.operand1 = operand;
		expr->type = EXPRESSION_BINARY;
		goto again;
	}
}

static void
parse_expression5(npl_expression_t *expr)
{
	npl_op2_t op;

	parse_expression4(expr);
again:
	op = 
		(is_token_accept(TOKEN_SHL)) ? OP2_SHL :
		(is_token_accept(TOKEN_SHR)) ? OP2_SHR : 
		OP2_INVALID;

	if (op != OP2_INVALID) {
		npl_expression_t *operand = xdup(npl_expression_t, expr);
		npl_expression_t *e;

		expr->b.operand2 = e = xnew(npl_expression_t);
		parse_expression5(e);

		expr->b.operator = op;
		expr->b.operand1 = operand;
		expr->type = EXPRESSION_BINARY;
		goto again;
	}
}

static void
parse_expression6(npl_expression_t *expr)
{
	npl_op2_t op;

	parse_expression5(expr);
again:
	op = 
		(is_token_accept(TOKEN_LESS)) ? OP2_LESS :
		(is_token_accept(TOKEN_GREATER)) ? OP2_GREATER : 
		(is_token_accept(TOKEN_LEQUAL)) ? OP2_LEQUAL :
		(is_token_accept(TOKEN_GEQUAL)) ? OP2_GEQUAL : 
		OP2_INVALID;

	if (op != OP2_INVALID) {
		npl_expression_t *operand = xdup(npl_expression_t, expr);
		npl_expression_t *e;

		expr->b.operand2 = e = xnew(npl_expression_t);
		parse_expression6(e);

		expr->b.operator = op;
		expr->b.operand1 = operand;
		expr->type = EXPRESSION_BINARY;
		goto again;
	}
}

static void
parse_expression7(npl_expression_t *expr)
{
	npl_op2_t op;

	parse_expression6(expr);
again:
	op = 
		(is_token_accept(TOKEN_EQUAL)) ? OP2_EQUAL :
		(is_token_accept(TOKEN_NOTEQUAL)) ? OP2_NOTEQUAL : 
		(is_token_accept(TOKEN_NOTEQUAL2)) ? OP2_NOTEQUAL : 
		OP2_INVALID;

	if (op != OP2_INVALID) {
		npl_expression_t *operand = xdup(npl_expression_t, expr);
		npl_expression_t *e;

		expr->b.operand2 = e = xnew(npl_expression_t);
		parse_expression7(e);

		expr->b.operator = op;
		expr->b.operand1 = operand;
		expr->type = EXPRESSION_BINARY;
		goto again;
	}
}

static void
parse_expression8(npl_expression_t *expr)
{
	parse_expression7(expr);
again:
	if (is_token_accept(TOKEN_AND)) {
		npl_expression_t *operand = xdup(npl_expression_t, expr);
		npl_expression_t *e;

		expr->b.operand2 = e = xnew(npl_expression_t);
		parse_expression8(e);

		expr->b.operator = OP2_AND;
		expr->b.operand1 = operand;
		expr->type = EXPRESSION_BINARY;
		goto again;
	}
}

static void
parse_expression9(npl_expression_t *expr)
{
	parse_expression8(expr);
again:
	if (is_token_accept(TOKEN_XOR)) {
		npl_expression_t *operand = xdup(npl_expression_t, expr);
		npl_expression_t *e;

		expr->b.operand2 = e = xnew(npl_expression_t);
		parse_expression9(e);

		expr->b.operator = OP2_XOR;
		expr->b.operand1 = operand;
		expr->type = EXPRESSION_BINARY;
		goto again;
	}
}

static void
parse_expression10(npl_expression_t *expr)
{
	parse_expression9(expr);
again:
	if (is_token_accept(TOKEN_OR)) {
		npl_expression_t *operand = xdup(npl_expression_t, expr);
		npl_expression_t *e;

		expr->b.operand2 = e = xnew(npl_expression_t);
		parse_expression10(e);

		expr->b.operator = OP2_OR;
		expr->b.operand1 = operand;
		expr->type = EXPRESSION_BINARY;
		goto again;
	}
}

static void
parse_expression11(npl_expression_t *expr)
{
	npl_op2_t op;

	parse_expression10(expr);
again:
	op = 
		(is_token_accept(TOKEN_LOGIC_AND)) ? OP2_LOGIC_AND :
		(is_token_accept(TOKEN_ANDAND)) ? OP2_LOGIC_AND : 
		OP2_INVALID;

	if (op != OP2_INVALID) {
		npl_expression_t *operand = xdup(npl_expression_t, expr);
		npl_expression_t *e;

		expr->b.operand2 = e = xnew(npl_expression_t);
		parse_expression11(e);

		expr->b.operator = op;
		expr->b.operand1 = operand;
		expr->type = EXPRESSION_BINARY;
		goto again;
	}
}

static void
parse_expression12(npl_expression_t *expr)
{
	npl_op2_t op;

	parse_expression11(expr);
again:
	op = 
		(is_token_accept(TOKEN_LOGIC_OR)) ? OP2_LOGIC_OR :
		(is_token_accept(TOKEN_OROR)) ? OP2_LOGIC_OR : 
		OP2_INVALID;

	if (op != OP2_INVALID) {
		npl_expression_t *operand = xdup(npl_expression_t, expr);
		npl_expression_t *e;

		expr->b.operand2 = e = xnew(npl_expression_t);
		parse_expression12(e);

		expr->b.operator = op;
		expr->b.operand1 = operand;
		expr->type = EXPRESSION_BINARY;
		goto again;
	}
}

static void
parse_expression13(npl_expression_t *expr)
{
	parse_expression12(expr);

	if (is_token_accept(TOKEN_COND)) {
		npl_expression_t *operand = xdup(npl_expression_t, expr);
		npl_expression_t *e;

		expr->c.test_expr = operand;

		e = xnew(npl_expression_t);
		parse_expression(e);
		expr->c.true_expr = e;
		accept(TOKEN_COLON);

		e = xnew(npl_expression_t);
		parse_expression13(e);
		expr->c.false_expr = e;

		expr->type = EXPRESSION_COND;
	}
}

static npl_expression_t *
xparse_expression(void)
{
	npl_expression_t *expr = xnew(npl_expression_t);

	parse_expression(expr);
	return expr;
}

static void
parse_expression(npl_expression_t *expr)
{
	npl_op2_t op;

	parse_expression13(expr);

	op = 
		(is_token_accept(TOKEN_ASSIGN)) ? OP2_ASSIGN :
		(is_token_accept(TOKEN_ASSIGN_PLUS)) ? OP2_ASSIGN_PLUS : 
		OP2_INVALID;

	if (op != OP2_INVALID) {
		npl_expression_t *operand = xdup(npl_expression_t, expr);

		expr->b.operand2 = xparse_expression();

		expr->b.operator = op;
		expr->b.operand1 = operand;
		expr->type = EXPRESSION_BINARY;
	}
}

static int is_attribute(void) { return is_token(TOKEN_LBRACKET); }

static npl_attribute_list_t **
pparse_attributes(npl_attribute_list_t **ptr)
{
	accept(TOKEN_LBRACKET);

	do {
		npl_attribute_list_t *cur = xnew(npl_attribute_list_t);

		*ptr = cur;
		ptr = &(cur->next);
		cur->expr = xparse_expression();

		if (is_token_accept(TOKEN_SEMICOLON))
			{ }
		else if (is_token_accept(TOKEN_COMMA))
			{ }
	} 
	while (!is_token(TOKEN_RBRACKET));
//	while (is_token_accept(TOKEN_COMMA));

	accept(TOKEN_RBRACKET);
	return ptr;
}

static void
parse_all_attributes(npl_attribute_list_t **attr_ptr)
{
	while (is_attribute())
		attr_ptr = pparse_attributes(attr_ptr);
	*attr_ptr = NULL;
}

static void parse_statement(npl_statement_t *st);

static npl_statement_t *
xparse_statement(void)
{
	npl_statement_t *st = xnew(npl_statement_t);

	parse_statement(st);
	return st;
}

static void
parse_switch_body(npl_switch_t *sw)
{
	struct npl_switch_case **ptr = &sw->cases;

	while (is_token(TOKEN_CASE)) {
		struct npl_switch_case *cur = xnew(struct npl_switch_case);

		*ptr = cur;

		ptr = &(cur->next);

		accept(TOKEN_CASE);
		parse_expression(&cur->e);
		accept(TOKEN_COLON);

		if (!is_token(TOKEN_CASE) && !is_token(TOKEN_DEFAULT)) {
			cur->st = xparse_statement();
			is_token_accept(TOKEN_SEMICOLON);
		}
	}
	*ptr = NULL;

	if (is_token_accept(TOKEN_DEFAULT)) {
		accept(TOKEN_COLON);
		sw->default_st = xparse_statement();
	}
}

static void
parse_switch(npl_switch_t *sw)
{
	accept(TOKEN_SWITCH);

	if (is_token_accept(TOKEN_LPAREN)) {
		sw->switch_expr = xparse_expression();
		accept(TOKEN_RPAREN);
	}

	accept(TOKEN_LCURLY);
	parse_switch_body(sw);
	accept(TOKEN_RCURLY);
	is_token_accept(TOKEN_SEMICOLON);
}

static void
parse_dynamic_switch(npl_switch_t *sw)
{
	accept(TOKEN_DYNAMIC_SWITCH);

	sw->switch_expr = xparse_expression();

	accept(TOKEN_LCURLY);
	parse_switch_body(sw);
	accept(TOKEN_RCURLY);
	is_token_accept(TOKEN_SEMICOLON);
}

static int is_statement(void) {
	return 
		is_token(TOKEN_WHILE) ||
		is_token(TOKEN_TABLE) || 
		is_token(TOKEN_STRUCT) || is_token(TOKEN_PRIVATE_STRUCT) ||
		is_token(TOKEN_SWITCH) || is_token(TOKEN_DYNAMIC_SWITCH) ||
		is_id() || is_attribute() ||
#if 1
		is_token(TOKEN_SEMICOLON) ||
#endif
		0
		;
}

/* Statements = { Statement } ; */
static struct _npl_statements *
xparse_statements(void)
{
	struct _npl_statements *ret;
	struct _npl_statements **ptr = &ret;

	while (is_statement()) {
		struct _npl_statements *cur = xnew(struct _npl_statements);

		parse_statement(&cur->st);

		*ptr = cur;
		ptr = &(cur->next);
	}
	*ptr = NULL;

	return ret;
}

static void
parse_while(npl_statement_t *st)
{
	accept(TOKEN_WHILE);

	if (is_id())
		st->w.id = accept_id();

	accept(TOKEN_LBRACKET);
	parse_expression(&st->w.expr);
	accept(TOKEN_RBRACKET);

	accept(TOKEN_LCURLY);
	st->w.sts = xparse_statements();
	accept(TOKEN_RCURLY);
	is_token_accept(TOKEN_SEMICOLON);
}

static int is_formatting(void) { return is_token(TOKEN_ASSIGN); }

/* Formatting = "=", Expression ; */
static npl_expression_t *
xparse_formatting(void)
{
	npl_expression_t *format;

	accept(TOKEN_ASSIGN);
	
	format = xnew(npl_expression_t);
	parse_expression(format);
	return format;
}

static void parse_table(npl_table_t *);
static void parse_struct(npl_struct_t *s, int statement);

static void
parse_statement(npl_statement_t *st)
{
	parse_all_attributes(&st->attr_list);

	if (is_token(TOKEN_WHILE)) {
		parse_while(st);
		st->type = STATEMENT_WHILE;
		return;
	}

	if (is_token(TOKEN_TABLE)) {
		parse_table(&st->t.data);
		st->type = STATEMENT_TABLE;
		return;
	}

	if (is_token(TOKEN_STRUCT) || is_token(TOKEN_PRIVATE_STRUCT)) {
		parse_struct(&st->s.data, 1);
		st->type = STATEMENT_STRUCT;
		return;
	}

	if (is_token(TOKEN_SWITCH)) {
		parse_switch(&(st->sw.data));
		st->type = STATEMENT_SWITCH;
		return;
	}

	if (is_token(TOKEN_DYNAMIC_SWITCH)) {
		parse_dynamic_switch(&(st->sw.data));
		st->type = STATEMENT_DYNAMIC_SWITCH;
		return;
	}
#if 1
	if (is_token(TOKEN_SEMICOLON)) {
		accept(TOKEN_SEMICOLON);
		st->type = -3;
		return;
	}
#endif

	st->type = STATEMENT_FIELD;
	st->f.t_id = accept_id();

	if (is_token_accept(TOKEN_LPAREN)) {
		parse_expression_list(&st->f.params);
		accept(TOKEN_RPAREN);

	} else
		st->f.params = NULL;

	st->f.id = accept_id();
	if (is_token_accept(TOKEN_COLON))
		st->f.bits = accept_int();

	else if (is_token_accept(TOKEN_LBRACKET)) {
		st->f.arr = xparse_expression();
		accept(TOKEN_RBRACKET);
	}

	if (is_formatting())
		st->f.format = xparse_formatting();

	if (is_token_accept(TOKEN_LCURLY)) {
		st->f.sts = xparse_statements();
		accept(TOKEN_RCURLY);
		is_token_accept(TOKEN_SEMICOLON);
		return;
	}

	accept(TOKEN_SEMICOLON);
}

/* Protocol = "protocol", ID, [Params], [Formatting], "{", Statements, "}", ";" ; */
static void
parse_protocol(npl_protocol_t *p)
{
	accept(TOKEN_PROTOCOL);
	p->id = accept_id();

	if (is_params())
		parse_params(&p->params);

	if (is_formatting())
		p->format = xparse_formatting();

	accept(TOKEN_LCURLY);
	p->sts = xparse_statements();
	accept(TOKEN_RCURLY);
	is_token_accept(TOKEN_SEMICOLON);
}

static void
parse_struct(npl_struct_t *s, int statement)
{
	if (is_token_accept(TOKEN_STRUCT))
		s->private = 0;
	else if (is_token_accept(TOKEN_PRIVATE_STRUCT))
		s->private = 1;
	else
		nomatch();

	if (!statement || is_id())
		s->id = accept_id();

	if (is_params())
		parse_params(&s->params);

	if (statement) {
		if (is_token_accept(TOKEN_LBRACKET)) {
			s->count_expr = xparse_expression();
			accept(TOKEN_RBRACKET);
		}
	}

	if (is_formatting())
		s->format = xparse_formatting();

	accept(TOKEN_LCURLY);
	s->sts = xparse_statements();
	accept(TOKEN_RCURLY);
	is_token_accept(TOKEN_SEMICOLON);
}

/* Table = "table", ID, [Params], "{", "switch", [ "(", Expr, ")" ], {TableCase}, [DefaultCase], "}", ";" ;

   DefaultCase = "default", ":", Expression", ";" ;
 */
static void
parse_table(npl_table_t *t)
{
	accept(TOKEN_TABLE);
	t->id = accept_id();
	if (is_params())
		parse_params(&t->params);

	accept(TOKEN_LCURLY);
	{
		struct npl_table_case **ptr;

		accept(TOKEN_SWITCH);
		if (is_token_accept(TOKEN_LPAREN)) {
			t->switch_expr = xparse_expression();
			accept(TOKEN_RPAREN);
		}

		accept(TOKEN_LCURLY);

		ptr = &(t->cases);
		while (is_token_accept(TOKEN_CASE)) {
			struct npl_table_case *cur;

			cur = *ptr = xnew(struct npl_table_case);
			ptr = &(cur->next);

			parse_expression(&(cur->e));
			accept(TOKEN_COLON);

			while (is_token_accept(TOKEN_CASE)) {
				cur = *ptr = xnew(struct npl_table_case);
				ptr = &(cur->next);

				parse_expression(&(cur->e));
				accept(TOKEN_COLON);
			}
			cur->return_expr = xparse_expression();
			accept(TOKEN_SEMICOLON);
		}
		*ptr = NULL;

		if (is_token_accept(TOKEN_DEFAULT)) {
			accept(TOKEN_COLON);
			t->default_expr = xparse_expression();
			accept(TOKEN_SEMICOLON);
		}
		accept(TOKEN_RCURLY);

	}
	accept(TOKEN_RCURLY);
	is_token_accept(TOKEN_SEMICOLON);
}

static int
is_type(void)
{
	return
		is_token(TOKEN_DECIMAL) ||
		is_token(TOKEN_NUMBER) ||
		is_token(TOKEN_TIME) ||
		is_token(TOKEN_UNSIGNED_NUMBER);
}

/* Type = BasicType, ID, [Params], "{", {TypeAttr}, "}" ;
 
   BasicType = "Decimal" | "Number" | "Time" | "UnsignedNumber" ;

   TypeAttr = AttrName, "=", Expression ;

   AttrName = "ByteOrder" | "DisplayFormat" | "Size" ;
 */
static void
parse_type(npl_type_t *t)
{
	if (is_token_accept(TOKEN_DECIMAL))
		t->type = FIELD_DECIMAL;
	else if (is_token_accept(TOKEN_NUMBER))
		t->type = FIELD_NUMBER;
	else if (is_token_accept(TOKEN_TIME))
		t->type = FIELD_TIME;
	else if (is_token_accept(TOKEN_UNSIGNED_NUMBER))
		t->type = FIELD_UNSIGNED_NUMBER;
	else
		nomatch();

	t->id = accept_id();
	if (is_params())
		parse_params(&t->params);
	accept(TOKEN_LCURLY);

	while (!is_token(TOKEN_RCURLY)) {
		npl_expression_t **ptr;

		if (is_token_accept(TOKEN_BYTE_ORDER))
			ptr = &t->byte_order;
		else if (is_token_accept(TOKEN_DISPLAY_FORMAT))
			ptr = &t->display_format;
		else if (is_token_accept(TOKEN_SIZE))
			ptr = &t->size;
		else
			nomatch();
#if 0
		if (*ptr)
			fprintf(stdout, "already got %s attr!\n", str);
#endif
		accept(TOKEN_ASSIGN);
		*ptr = xparse_expression();

		if (is_token_accept(TOKEN_COMMA))
			{ }
		else if (is_token_accept(TOKEN_SEMICOLON))
			{ }
	}
	accept(TOKEN_RCURLY);
}

/* Const = "const", ID, "=", Expression, ";" ; */
static void
parse_const(npl_const_t *c)
{
	accept(TOKEN_CONST);
	c->id = accept_id();
	accept(TOKEN_ASSIGN);
	parse_expression(&c->expr);
	accept(TOKEN_SEMICOLON);
}

/* Declaration = Attributes
               | Struct
               | Table
               | Const
               | Protocol
               | Type
               | ( "include", STR )
               ;
 */
static void
parse_decl(npl_decl_t *d)
{
	parse_all_attributes(&d->attr_list);

	if (is_token(TOKEN_STRUCT)) {
		d->type = DECL_STRUCT;
		parse_struct(&d->s.data, 0);

	} else if (is_token(TOKEN_TABLE)) {
		d->type = DECL_TABLE;
		parse_table(&d->t.data);

	} else if (is_token(TOKEN_CONST)) {
		d->type = DECL_CONST;
		parse_const(&d->c.data);

	} else if (is_token(TOKEN_PROTOCOL)) {
		d->type = DECL_PROTOCOL;
		parse_protocol(&d->p.data);

	} else if (is_type()) {
		d->type = DECL_TYPE;
		parse_type(&d->ty.data);

	} else if (is_token_accept(TOKEN_INCLUDE)) {
		d->type = DECL_INCLUDE;
		d->i.file = accept_str();	/* XXX, it's C-escaped */ /* XXX, unix / vs dos \\  */

	} else
		nomatch();
}

/* NPL = { Declaration } ; */
static void
parse_npl(npl_code_t *code)
{
	struct _npl_decl_list **ptr = &(code->decls);

	while (!is_token_accept(TOKEN_EOF)) {
		struct _npl_decl_list *cur = xnew(struct _npl_decl_list);

		*ptr = cur;
		ptr = &(cur->next);

		parse_decl(&cur->d);
	}
	*ptr = NULL;
}

int
npl_parse_file(npl_code_t *code, FILE *f, const char *filename)
{
	volatile int parse_ok = 0;

	yyfilename = filename;
	yyin = f;

	if (!setjmp(parser_exception)) {
		next_token();
		parse_npl(code);
		parse_ok = 1;
	}

	yylex_destroy();

	return (parse_ok == 1);
}

