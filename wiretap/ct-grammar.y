%{

#include <stdlib.h>
#include <stdio.h>
#include "ct-compile.h"

#include "config.h"

#ifdef HAVE_GLIB10
#include "glib-new.h"
#endif

struct field_info working_field;
gchar *current_protocol = NULL;
char *full_field_name = NULL;

%}

%union {
	gint	d;
	GString	*s;
	GSList	*a;
}

%type	<s> sentence protocol
%type	<a> parents text_list

%token <s>	TEXT PROTOCOL PARENTS QUOTED
%token <d>	NUMBER BOOLEAN ETHER UINT8 UINT16 UINT32 BYTE
%token FIELD ALIAS
%token AND_MASK BYTE_OFFSET EITHER_OF

%%

paragraph: /* EMPTY */
		| paragraph sentence
		;

sentence:	protocol
{
	if (current_protocol)
		free(current_protocol);
	current_protocol = g_strdup($1->str);
}
		|	parents
{
	g_print("sentence Got parents %d\n", g_slist_length($1));
}
		| alias { }
		| field { }
		;

protocol:	PROTOCOL TEXT QUOTED ';'
{
	protocol_layer_add($2->str, $3->str);
	$$ = $2;
}
		;

parents:	PARENTS text_list ';'
{
	$$ = $2;
	g_slist_free($2);
}
		;

alias: ALIAS TEXT text_list ';'
{
	full_field_name = g_strjoin(".", current_protocol, $2->str, NULL);
	field_info_add_alias(full_field_name, $3);
	g_free(full_field_name);
}
	

field:	FIELD TEXT QUOTED ',' field_type ',' field_location ';'
{
	working_field.name = g_strjoin(".", current_protocol, $2->str, NULL);
	working_field.short_name = g_strdup($2->str);
	working_field.description = g_strdup($3->str);

	field_info_add(&working_field, current_protocol);
	field_info_zero(&working_field);
}


field_type:	BOOLEAN
{
	working_field.field_type = FTYPE_BOOLEAN;
	working_field.length = FLEN_BOOLEAN;
}
		| ETHER
{
	working_field.field_type = FTYPE_ETHER;
	working_field.length = FLEN_ETHER;
}
		| UINT8
{
	working_field.field_type = FTYPE_UINT8;
	working_field.length = FLEN_UINT8;
}
		| UINT16
{
	working_field.field_type = FTYPE_UINT16;
	working_field.length = FLEN_UINT16;
}
		| UINT32
{
	working_field.field_type = FTYPE_UINT32;
	working_field.length = FLEN_UINT32;
}
		| BYTE '[' NUMBER ']'
{
	working_field.field_type = FTYPE_BYTE;
	working_field.length = $3;
}
		;

field_location: AND_MASK '(' NUMBER '@' NUMBER ')'
{
	working_field.computation_type = CTYPE_ANDMASK;
	working_field.value = $3;
	working_field.offset = $5;
}
		| BYTE_OFFSET '(' NUMBER ')'
{
	working_field.computation_type = CTYPE_BYTECMP;
	working_field.offset = $3;
}
		| EITHER_OF '(' text_list ')'
{
	working_field.computation_type = CTYPE_EITHEROF;
	working_field.many_list = field_info_list($3, current_protocol);
	g_slist_free($3);
}

		;

text_list: TEXT
{
	$$ = g_slist_alloc();
	g_slist_append($$, $1);
}
		| text_list ',' TEXT
{
	$$ = $1;
	g_slist_append($$, $3);
}

		;
