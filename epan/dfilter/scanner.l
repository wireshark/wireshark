%{
/*
 * $Id: scanner.l,v 1.5 2001/06/22 16:29:13 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 2001 Gerald Combs
 *
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <errno.h>

#include "glib-util.h"
#include "dfilter-int.h"
#include "syntax-tree.h"
#include "grammar.h"

#define LVAL		df_lval
#define LVAL_TYPE	stnode_t*
#define LVAL_INIT_VAL	NULL
#define MODNAME		df

#include <lemonflex-head.inc>

/*#undef YY_NO_UNPUT*/

static int set_lval(int token, gpointer data);
static int set_lval_int(int token, char *s);
static int simple(int token);
static gboolean str_to_guint32(char *s, guint32* pint);

%}

%x RANGE_INT
%x RANGE_PUNCT


%%

[[:blank:]\n]+	/* ignore whitespace */



"("				return simple(TOKEN_LPAREN);
")"				return simple(TOKEN_RPAREN);
"/"				return simple(TOKEN_SLASH);

"=="				return simple(TOKEN_TEST_EQ);
"eq"				return simple(TOKEN_TEST_EQ);
"!="				return simple(TOKEN_TEST_NE);
"ne"				return simple(TOKEN_TEST_NE);
">"				return simple(TOKEN_TEST_GT);
"gt"				return simple(TOKEN_TEST_GT);
">="				return simple(TOKEN_TEST_GE);
"ge"				return simple(TOKEN_TEST_GE);
"<"				return simple(TOKEN_TEST_LT);
"lt"				return simple(TOKEN_TEST_LT);
"<="				return simple(TOKEN_TEST_LE);
"le"				return simple(TOKEN_TEST_LE);

"!"				return simple(TOKEN_TEST_NOT);
"not"				return simple(TOKEN_TEST_NOT);
"&&"				return simple(TOKEN_TEST_AND);
"and"				return simple(TOKEN_TEST_AND);
"||"				return simple(TOKEN_TEST_OR);
"or"				return simple(TOKEN_TEST_OR);



"["					{
	BEGIN(RANGE_INT);
	return simple(TOKEN_LBRACKET);
}

<RANGE_INT>[+-]?[[:digit:]]+		{
	BEGIN(RANGE_PUNCT);
	return set_lval_int(TOKEN_INTEGER, yytext);
}
<RANGE_INT>[+-]?0x[[:xdigit:]]+		{
	BEGIN(RANGE_PUNCT);
	return set_lval_int(TOKEN_INTEGER, yytext);
}

<RANGE_INT,RANGE_PUNCT>":"		{
	BEGIN(RANGE_INT);
	return simple(TOKEN_COLON);
}

<RANGE_PUNCT>"-"			{
	BEGIN(RANGE_INT);
	return simple(TOKEN_HYPHEN);
}

<RANGE_INT,RANGE_PUNCT>","		{
	BEGIN(RANGE_INT);
	return simple(TOKEN_COMMA);
}

<RANGE_INT,RANGE_PUNCT>"]"		{
	BEGIN(INITIAL);
	return simple(TOKEN_RBRACKET);
}


\"[^"]*\"				{
	return set_lval(TOKEN_STRING, g_substrdup(yytext, 1, -2));
}



[[:alnum:]_.:]+	{
	/* Is it a field name? */
	header_field_info *hfinfo;

	hfinfo = dfilter_lookup_token(yytext);
	if (hfinfo) {
		/* Yes, it's a field name */
		return set_lval(TOKEN_FIELD, hfinfo);
	}
	else {
		/* No, so treat it as a string */
		return set_lval(TOKEN_STRING, g_strdup(yytext));
	}
}

. {
	/* Default */
	return set_lval(TOKEN_STRING, g_strdup(yytext));
}


%%

static int
simple(int token)
{
	switch (token) {
		case TOKEN_LPAREN:
		case TOKEN_RPAREN:
		case TOKEN_LBRACKET:
		case TOKEN_RBRACKET:
		case TOKEN_COLON:
		case TOKEN_COMMA:
		case TOKEN_HYPHEN:
		case TOKEN_SLASH:
		case TOKEN_TEST_EQ:
		case TOKEN_TEST_NE:
		case TOKEN_TEST_GT:
		case TOKEN_TEST_GE:
		case TOKEN_TEST_LT:
		case TOKEN_TEST_LE:
		case TOKEN_TEST_NOT:
		case TOKEN_TEST_AND:
		case TOKEN_TEST_OR:
			break;
		default:
			g_assert_not_reached();
	}
	return token;
}

static int
set_lval(int token, gpointer data)
{
	sttype_id_t	type_id = STTYPE_UNINITIALIZED;

	switch (token) {
		case TOKEN_STRING:
			type_id = STTYPE_STRING;
			break;
		case TOKEN_FIELD:
			type_id = STTYPE_FIELD;
			break;
		default:
			g_assert_not_reached();
	}

	stnode_init(df_lval, type_id, data);
	return token;
}

static int
set_lval_int(int token, char *s)
{
	sttype_id_t	type_id = STTYPE_UNINITIALIZED;
	guint32		val;

	if (!str_to_guint32(s, &val)) {
		return 0;
	}	

	switch (token) {
		case TOKEN_INTEGER:
			type_id = STTYPE_INTEGER;
			break;
		default:
			g_assert_not_reached();
	}

	stnode_init_int(df_lval, type_id, val);
	return token;
}


static gboolean
str_to_guint32(char *s, guint32* pint)
{
	char    *endptr;
	guint32	integer;

	integer = strtoul(s, &endptr, 0);

	if (endptr == s || *endptr != '\0') {
		/* This isn't a valid number. */
		dfilter_fail("\"%s\" is not a valid number.", s);
		return FALSE;
	}
	if (errno == ERANGE) {
		if (integer == ULONG_MAX) {
			dfilter_fail("\"%s\" causes an integer overflow.", s);
		}
		else {
			dfilter_fail("\"%s\" is not an integer.", s);
		}
		return FALSE;
	}

	*pint = integer;
	return TRUE;
}

#include <lemonflex-tail.inc>
