%{
/* scanner.l
 * Scanner for Ethereal's dfilter language
 *
 * $Id: scanner.l,v 1.1 2001/02/01 20:21:18 gram Exp $
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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

int set_lval(int token, gpointer data);
int simple(int token);

%}

%x RANGE

BWCHARS		[[:alnum:]\[\]\-_.+!@#%^&*=/:]
INITVAR		[_A-Za-z]
VARCHARS	[[:alnum:]_]


%%

[[:blank:]\n]+	/* ignore whitespace */



"("				return simple(TOKEN_LPAREN);
")"				return simple(TOKEN_RPAREN);

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


"["				{
	BEGIN(RANGE);
	return simple(TOKEN_LBRACKET);
}

<RANGE>[+-]?[[:digit:]]+		{
	return set_lval(TOKEN_STRING, g_strdup(yytext));
}
<RANGE>[+-]?0x[[:xdigit:]]+		{
	return set_lval(TOKEN_STRING, g_strdup(yytext));
}
<RANGE>":"			return simple(TOKEN_COLON);

<RANGE>"]"			{
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



%%

int
simple(int token)
{
	switch (token) {
		case TOKEN_LPAREN:
		case TOKEN_RPAREN:
		case TOKEN_LBRACKET:
		case TOKEN_RBRACKET:
		case TOKEN_COLON:
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

int
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

#include <lemonflex-tail.inc>
