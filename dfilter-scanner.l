%{

/* dfilter-scanner.l
 * Scanner for display filters
 *
 * $Id: dfilter-scanner.l,v 1.13 1999/10/04 18:09:04 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
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
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifndef _STDIO_H
#include <stdio.h>
#endif

#ifndef _STRING_H
#include <string.h>
#endif

#ifndef __G_LIB_H__
#include <glib.h>
#endif

#ifndef __PROTO_H__
#include "proto.h"
#endif

#ifndef __DFILTER_H__
#include "dfilter.h"
#endif

#include "dfilter-int.h"

#include "dfilter-grammar.h"

/* Flex has a few routines which help us get the scanner to read
 * from a string rather than from a file. POSIX lex only provides
 * for reading from a file; any method of reading from a string
 * is inherently non-portable.  Besides reading from a string,
 * we have to worry about resetting the scanner after a bad
 * parse; this too is non-portable. Combine the reset with
 * a string input, and you have major non-portability. I'll provide
 * the routines for flex here. If you really want to modify the
 * scanner and use a non-flex lex implementation, you may
 * add more ifdef's below.
 */
#ifdef FLEX_SCANNER

/* Flex has built-in support for using a string as an input source
 * instead of using a file. Nice!
 */
YY_BUFFER_STATE	string_input_buffer;

#else

static char *in_buffer;
#undef getc
#define getc(fp)  (*in_buffer == 0 ? EOF : *in_buffer++)

#endif

%}

whitespace	[\t ]
hex		[A-Fa-f0-9]{1,2}
hexsep		[-:\.]

%%

[\t\n ]+	/* ignore whitespace */


and|\&\&	{ dfilter_lval.operand = TOK_AND; return TOK_AND; }
or|\|\|		{ dfilter_lval.operand = TOK_OR; return TOK_OR; }
not|\!		{ dfilter_lval.operand = TOK_NOT; return TOK_NOT; }
xor|\^\^	{ dfilter_lval.operand = TOK_XOR; return TOK_XOR; }
eq|\=\=		{ dfilter_lval.operand = TOK_EQ; return TOK_EQ; }
ne|\!\=		{ dfilter_lval.operand = TOK_NE; return TOK_NE; }
gt|\>		{ dfilter_lval.operand = TOK_GT; return TOK_GT; }
ge|\>\=		{ dfilter_lval.operand = TOK_GE; return TOK_GE; }
lt|\<		{ dfilter_lval.operand = TOK_LT; return TOK_LT; }
le|\<\=		{ dfilter_lval.operand = TOK_LE; return TOK_LE; }

\[{whitespace}*-?[0-9]+{whitespace}*:{whitespace}*[0-9]+{whitespace}*\] { /* range [ x : y ] */

	char	*byterange_string = g_strdup(yytext);
	char	*s = byterange_string + 1; /* I don't want the first '[' */
	char	*p;

	/* Get the offset from the string */
	if ((p = strtok(s, ":"))) {
		dfilter_lval.byte_range.offset = strtol(p, NULL, 10);
	}
	else {
		g_free(byterange_string);
		return 0;
	}

	/* Get the Length from the string */
	if ((p = strtok(NULL, "]"))) {
		dfilter_lval.byte_range.length = strtoul(p, NULL, 10);
	}
	else {
		g_free(byterange_string);
		return 0;
	}
	g_free(byterange_string);
	return T_VAL_BYTE_RANGE;
}


{hex}({hexsep}{hex})+ {			/* byte string, any length */
	dfilter_lval.string = g_strdup(yytext);
	return T_VAL_BYTE_STRING;
}


[A-Za-z][A-Za-z0-9\.\_]+	{	/* looks like a protocol or field name */

	int retval = 0;
	enum ftenum ftype;
	dfilter_lval.variable.id = dfilter_lookup_token(yytext);
	if (dfilter_lval.variable.id < 0) {
		dfilter_lval.string = g_strdup(yytext);
		return T_VAL_UNQUOTED_STRING;
	}
	
	ftype = proto_registrar_get_ftype(dfilter_lval.variable.id);
	switch (ftype) {
		case FT_UINT8:
		case FT_VALS_UINT8:
			retval = T_FT_UINT8;
			break;
		case FT_UINT16:
		case FT_VALS_UINT16:
			retval = T_FT_UINT16;
			break;
		case FT_UINT32:
		case FT_VALS_UINT32:
		case FT_VALS_UINT24:
			retval = T_FT_UINT32;
			break;
		case FT_ETHER:
			retval = T_FT_ETHER;
			break;
		case FT_IPv4:
			retval = T_FT_IPv4;
			break;
		case FT_NONE:
			retval = T_FT_NONE;
			break;
		case FT_BYTES:
			retval = T_FT_BYTES;
			break;
		case FT_BOOLEAN:
			retval = T_FT_BOOLEAN;
			break;
		case FT_IPXNET:
			retval = T_FT_IPXNET;
			break;
		default:
			g_assert_not_reached();
			retval = 0;
			break;
	}
	dfilter_lval.variable.type = retval;
	return retval;
}

[0-9]+ {				/* decimal or octal values */
	dfilter_lval.string = g_strdup(yytext);
	return T_VAL_NUMBER_STRING;
}


0[xX][A-Fa-f0-9]+ {			/* hex values */
	dfilter_lval.string = g_strdup(yytext);
	return T_VAL_NUMBER_STRING;
}

[0-9\:\.]+ {
	dfilter_lval.string = g_strdup(yytext);
	return T_VAL_UNQUOTED_STRING;
}

.	return yytext[0];
%%

/* Resets scanner and assigns the char* argument
 * as the text to scan
 */
void
dfilter_scanner_text(char *text)
{
#ifdef FLEX_SCANNER
	string_input_buffer = yy_scan_string(text);
#else
	in_buffer = text;
#endif
}

void
dfilter_scanner_cleanup(void)
{
#ifdef FLEX_SCANNER
	yy_delete_buffer(string_input_buffer);
#else
	/* There is no standard way to reset a lex scanner.
	 * This is necessary after a failed parse on a syntactically
	 * incorrect display filter. You have to reset the scanner
	 * so that yy_lex() doesn't start scanning from the middle
	 * of the previous input string.
	 */
#endif
}

/* Flex has an option '%option noyywrap' so that I don't have to
 * provide this yywrap function, but in order to maintain portability,
 * I'll just use this yywrap() function.
 */
int
yywrap()
{
	return 1; /* stop at EOF, instead of looking for next file */
}

/* converts a string representing a byte array
 * to a guint8 array.
 *
 * Returns a non-null GByteArray pointer on success, NULL on failure.
 */
GByteArray*
byte_str_to_guint8_array(const char *s)
{
	GByteArray	*barray;
	guint8		val;
	char		*byte_str = g_strdup(s); /* local copy of string */
	char		*p, *str;

	barray = g_byte_array_new();
	/* XXX - don't use global_df, but pass in pointer to GSList* */
	global_df->list_of_byte_arrays = g_slist_append(global_df->list_of_byte_arrays, barray);

	byte_str = g_strdup(s);
	str = byte_str;
	while ((p = strtok(str, "-:."))) {
		val = (guint8) strtoul(p, NULL, 16);
		g_byte_array_append(barray, &val, 1);

		/* subsequent calls to strtok() require NULL as arg 1 */
		str = NULL;
	}

	g_free(byte_str);
	return barray;
}
