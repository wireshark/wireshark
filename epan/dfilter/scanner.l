%{
/*
 * $Id: scanner.l,v 1.14 2004/01/07 05:24:04 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 2001 Gerald Combs
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
GString* quoted_string = NULL;

#define SCAN_FAILED	0

%}

%x RANGE_INT
%x RANGE_PUNCT
%x DQUOTE

%%

[[:blank:]\n]+	/* ignore whitespace */



"("				return simple(TOKEN_LPAREN);
")"				return simple(TOKEN_RPAREN);

"=="			return simple(TOKEN_TEST_EQ);
"eq"			return simple(TOKEN_TEST_EQ);
"!="			return simple(TOKEN_TEST_NE);
"ne"			return simple(TOKEN_TEST_NE);
">"				return simple(TOKEN_TEST_GT);
"gt"			return simple(TOKEN_TEST_GT);
">="			return simple(TOKEN_TEST_GE);
"ge"			return simple(TOKEN_TEST_GE);
"<"				return simple(TOKEN_TEST_LT);
"lt"			return simple(TOKEN_TEST_LT);
"<="			return simple(TOKEN_TEST_LE);
"le"			return simple(TOKEN_TEST_LE);
"contains"		return simple(TOKEN_TEST_CONTAINS);
"matches"		return simple(TOKEN_TEST_MATCHES);
"!"				return simple(TOKEN_TEST_NOT);
"not"			return simple(TOKEN_TEST_NOT);
"&&"			return simple(TOKEN_TEST_AND);
"and"			return simple(TOKEN_TEST_AND);
"||"			return simple(TOKEN_TEST_OR);
"or"			return simple(TOKEN_TEST_OR);



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

\"					{
	/* start quote */
	/* The example of how to scan for strings was taken from
	the flex 2.5.4 manual, from the section "Start Conditions".
	See:
	http://www.gnu.org/manual/flex-2.5.4/html_node/flex_11.html */

	BEGIN(DQUOTE);
	/* A previous filter that failed to compile due to
	a missing end quote will have left quoted_string set
	to something. Clear it now that we are starting
	a new quoted string. */
	if (quoted_string) {
		g_string_free(quoted_string, TRUE);
		/* Don't set quoted_string to NULL, as we
		do in other quoted_string-cleanup code, as we're
		about to set it in the next line. */
	}
	quoted_string = g_string_new("");
}

<DQUOTE>\"				{
	/* end quote */
	char *my_string = g_strdup(quoted_string->str);
	BEGIN(INITIAL);
	g_string_free(quoted_string, TRUE);
	quoted_string = NULL;
	return set_lval(TOKEN_STRING, my_string);
}

<DQUOTE>\\[0-7]{1,3} {
	/* octal sequence */
	unsigned int result;
	sscanf(yytext + 1, "%o", &result);
	if (result > 0xff) {
		g_string_free(quoted_string, TRUE);
		quoted_string = NULL;
		dfilter_fail("%s is larger than 255.", yytext);
		return SCAN_FAILED;
	}
	g_string_append_c(quoted_string, (gchar) result);
}

<DQUOTE>\\x[[:xdigit:]]{1,2} {
	/* hex sequence */
	unsigned int result;
	sscanf(yytext + 2, "%x", &result);
	if (result > 0xff) {
		g_string_free(quoted_string, TRUE);
		quoted_string = NULL;
		dfilter_fail("%s is larger than 255.", yytext);
		return SCAN_FAILED;
	}
	g_string_append_c(quoted_string, (gchar) result);
}


<DQUOTE>\\.				{
	/* escaped character */
	g_string_append_c(quoted_string, yytext[1]);
}

<DQUOTE>[^\\\"]+			{
	/* non-escaped string */
	g_string_append(quoted_string, yytext);
}



[-[:alnum:]_\.]+\/[[:digit:]]+  {
        /* CIDR */
        return set_lval(TOKEN_UNPARSED, g_strdup(yytext));
}

[-\+[:alnum:]_.,:]+	{
	/* Is it a field name? */
	header_field_info *hfinfo;

	hfinfo = proto_registrar_get_byname(yytext);
	if (hfinfo) {
		/* Yes, it's a field name */
		return set_lval(TOKEN_FIELD, hfinfo);
	}
	else {
		/* No, so treat it as an unparsed string */
		return set_lval(TOKEN_UNPARSED, g_strdup(yytext));
	}
}

. {
	/* Default */
	return set_lval(TOKEN_UNPARSED, g_strdup(yytext));
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
		case TOKEN_TEST_EQ:
		case TOKEN_TEST_NE:
		case TOKEN_TEST_GT:
		case TOKEN_TEST_GE:
		case TOKEN_TEST_LT:
		case TOKEN_TEST_LE:
		case TOKEN_TEST_CONTAINS:
		case TOKEN_TEST_MATCHES:
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
		case TOKEN_UNPARSED:
			type_id = STTYPE_UNPARSED;
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
		return SCAN_FAILED;
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
