%{
#include <glib.h>
#include <stdio.h>
#include "ct-grammar.h"
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
	wtap_lval.s = g_string_new(wtap_text + 1);
	g_string_truncate(wtap_lval.s, strlen(wtap_text) - 2);
/*	g_print("lex made QUOTED (%s)\n", wtap_lval.s->str);*/
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
	wtap_lval.d = atoi(wtap_text);
	return NUMBER;
}

{W}+	{
	wtap_lval.s = g_string_new(wtap_text);
/*	g_print("lex made TEXT (%s)\n", wtap_lval.s->str);*/
	return TEXT;
	}

%%

int
wtap_wrap()
{
	return 1;
}

void wtap_error(char *string)
{
	fprintf(stderr,"%s on line %d\n",string, lex_line_number);
	exit(0);
}
