%{
#include <glib.h>
#include <stdio.h>
#include "ct-tokdefs.h"
int lex_line_number = 1;
%}

N	([0-9]+|(0X|0x)[0-9A-Fa-f]+)
B	[0-9A-Fa-f][0-9A-Fa-f]?
W	[A-Za-z_]
quoted	\"[^"\n]*["\n]

%%

\n		lex_line_number++;
[\t ]+	/* eat whitespace */
#.*		/* one-line shell-style comments */

{quoted} {
	yylval.s = g_string_new(yytext + 1);
	g_string_truncate(yylval.s, strlen(yytext) - 2);
/*	g_print("lex made QUOTED (%s)\n", yylval.s->str);*/
	return QUOTED;
}

";"		return ';';
","		return ',';
"("		return '(';
")"		return ')';
"@"		return '@';
"["		return '[';
"]"		return ']';

protocol		return PROTOCOL;
parents			return PARENTS;
field			return FIELD;
alias			return ALIAS;

boolean			return BOOLEAN;
ether			return ETHER;
uint8			return UINT8;
uint16			return UINT16;
uint32			return UINT32;
byte			return BYTE;

and_mask		return AND_MASK;
byte_offset		return BYTE_OFFSET;
either_of		return EITHER_OF;


{N} {
	yylval.d = atoi(yytext);
	return NUMBER;
}

{W}+	{
	yylval.s = g_string_new(yytext);
/*	g_print("lex made TEXT (%s)\n", yylval.s->str);*/
	return TEXT;
	}

%%

int
yywrap()
{
	return 1;
}

void yyerror(char *string)
{
	fprintf(stderr,"%s on line %d\n",string, lex_line_number);
	exit(0);
}
