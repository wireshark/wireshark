/*
 * We don't use unput, so don't generate code for it.
 */
%option nounput

/*
 * We don't read from the terminal.
 */
%option never-interactive

/*
 * The language we're scanning is case-insensitive.
 */
%option caseless

/*
 * We use start condition stacks.
 */
%option stack

/*
 * Prefix scanner routines with "WimaxasncpDict" rather than "yy", so this
 * scanner can coexist with other scanners.
 */
%option prefix="WimaxasncpDict"

%option outfile="wimaxasncp_dict.c"

%{
	/*
	 ** wimaxasncp_dict.h
	 ** WIMAXASNCP Dictionary Import Routines
	 **
	 ** $Id$
	 **
	 ** (c) 2007, Luis E. Garcia Ontanon <luis@ontanon.org>
	 ** (c) 2007, Stephen Croll <stephen.d.croll@gmail.com>
	 **
	 ** This library is free software; you can redistribute it and/or
	 ** modify it under the terms of the GNU Library General Public
	 ** License as published by the Free Software Foundation; either
	 ** version 2 of the License, or (at your option) any later version.
	 **
	 ** This library is distributed in the hope that it will be useful,
	 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
	 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	 ** Library General Public License for more details.
	 **
	 ** You should have received a copy of the GNU Library General Public
	 ** License along with this library; if not, write to the Free Software
	 ** Foundation, Inc., 51 Franklin Street, Fifth Floor,
	 ** Boston, MA  02110-1301, USA.
	 */

#include "config.h"

#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <epan/emem.h>
#include <epan/value_string.h>
#include <epan/packet.h>	/* array_length */
#include <wsutil/file_util.h>

#include "wimaxasncp_dict.h"
#include "wimaxasncp_dict_lex.h"

typedef struct entity_t {
	gchar *name;
	gchar *file;
	struct entity_t *next;
} entity_t;

#define ATTR_UINT(cont) do { D(("attr_uint " #cont "\t" )); attr_uint = &(cont); yy_push_state(GET_UINT_ATTR); } while(0)
#define ATTR_UINT16(cont) do { D(("attr_uint16 " #cont "\t" )); attr_uint16 = &(cont); yy_push_state(GET_UINT16_ATTR); } while(0)
#define ATTR_STR(cont) do { D(("attr_str " #cont "\t" )); attr_str = &(cont); yy_push_state(GET_ATTR); } while(0)
#define ATTR_DECODER(cont) do { D(("attr_decoder " #cont "\t" )); attr_uint = &(cont); yy_push_state(GET_DECODER_ATTR); } while(0)
#define WIMAXASNCP_IGNORE() do { D(("ignore: %s\t",yytext)); yy_push_state(IGNORE_ATTR); } while(0)

#define D(args) wimaxasncp_dict_debug args

#define MAX_INCLUDE_DEPTH 10
#define YY_INPUT(buf,result,max_size) { result = current_yyinput(buf,max_size); }
#define ECHO
#define APPEND(txt,len) append_to_buffer(txt,len)

static entity_t ents;
static YY_BUFFER_STATE include_stack[MAX_INCLUDE_DEPTH];
static int include_stack_ptr = 0;
static size_t (*current_yyinput)(gchar*,size_t);
static const gchar *sys_dir;
static wimaxasncp_dict_t *dict;
static wimaxasncp_dict_tlv_t *tlv;
static wimaxasncp_dict_enum_t *enumitem;
static wimaxasncp_dict_xmlpi_t *xmlpi;

static wimaxasncp_dict_tlv_t *last_tlv;
static wimaxasncp_dict_enum_t *last_enumitem;
static wimaxasncp_dict_xmlpi_t *last_xmlpi;

static gchar **attr_str;
static guint *attr_uint;
static gint16 *attr_uint16;

static guint wimaxasncp_bits(guint bits, char *n);
static gint wimaxasncp_decode_type(const gchar *name);
static void wimaxasncp_dict_debug(const gchar *fmt, ...);
static void append_to_buffer(gchar *txt, int len);
static FILE *wimaxasncp_dict_open(const gchar*, const gchar*);

static GString *dict_error = NULL;

%}


xmlpi_start [[:blank:] \r\n]*<\?[[:blank:] \r\n]*
xmlpi_end [[:blank:] \r\n]*\?>[[:blank:] \r\n]*
xmlpi_key_attr [[:blank:] \r\n]*key[[:blank:] \r\n]*=[[:blank:] \r\n]*\042
xmlpi_value_attr [[:blank:] \r\n]*value[[:blank:] \r\n]*=[[:blank:] \r\n]*\042

comment_start [[:blank:] \r\n]*<!--[[:blank:] \r\n]*
comment_end [[:blank:] \r\n]*-->[[:blank:] \r\n]*
open_tag [[:blank:] \r\n]*<[[:blank:] \r\n]*
end_tag [[:blank:] \r\n]*\/>[[:blank:] \r\n]*
close_tag [[:blank:] \r\n]*>[[:blank:] \r\n]*
open_closetag [[:blank:] \r\n]*<\/[[:blank:] \r\n]*
equals [[:blank:] \r\n]*=[[:blank:] \r\n]*
whitespace [[:blank:] \r\n]*
dquoted \042[^\042]*\042

doctype [[:blank:] \r\n]*<!DOCTYPE[^\[]*\[[[:blank:] \r\n]*
doctype_end [[:blank:] \r\n]*\][[:blank:] \r\n]*>[[:blank:] \r\n]*

start_entity [[:blank:] \r\n]*<\!ENTITY[[:blank:] \r\n]*
system [[:blank:] \r\n]*SYSTEM[[:blank:] \r\n]*\042
entityname [a-z0-9-]+
ndquot [^\042]+
end_entity \042[[:blank:] \r\n]*>[[:blank:] \r\n]*

entity \&[a-z0-9-]+;

any .




stop >
stop_end \/>
dquot \042
number [-]?[0-9]*|(0x)?[0-9a-fA-F]*

dictionary_start <dictionary>
dictionary_end <\/dictionary>

tlv_start <tlv
tlv_end <\/tlv>

type_start <type
enum_start <enum

ignored_attr [a-z0-9-]+=
ignored_quoted \042[^\042]*\042

name_attr name=\042
type_attr type=\042
code_attr code=\042
typename_attr type-name=\042
description_attr description=\042
decoder_attr decoder=\042
since_attr since=\042


%S LOADING LOADING_COMMENT LOADING_XMLPI ENTITY GET_SYSTEM GET_FILE END_ENTITY
%S GET_ATTR GET_UINT_ATTR GET_UINT16_ATTR
%S BIT32 BIT16 BIT8 GET_DECODER_ATTR END_ATTR
%S OUTSIDE IN_DICT IN_APPL IN_TLV IGNORE_ATTR
%S ENUM_ATTRS TLV_ATTRS
%S XMLPI_ATTRS XMLPI_GETKEY XMLPI_GETVAL XMLPI_ENDATTR
%%
<LOADING>{doctype} ;
<LOADING>{doctype_end} ;

<LOADING>{comment_start} BEGIN LOADING_COMMENT;
<LOADING_COMMENT>. ;
<LOADING_COMMENT>{comment_end} BEGIN LOADING;

<LOADING>{xmlpi_start} BEGIN LOADING_XMLPI;
<LOADING_XMLPI>{whitespace} ;
<LOADING_XMLPI>{entityname} {
	xmlpi = g_malloc(sizeof(wimaxasncp_dict_xmlpi_t));
	xmlpi->name = g_strdup(yytext);
	xmlpi->key = NULL;
	xmlpi->value = NULL;
	xmlpi->next = NULL;

	if (!dict->xmlpis) last_xmlpi = dict->xmlpis = xmlpi;
	else last_xmlpi = last_xmlpi->next = xmlpi;

	BEGIN XMLPI_ATTRS;
}

<XMLPI_ATTRS>{xmlpi_key_attr} BEGIN XMLPI_GETKEY;
<XMLPI_GETKEY>{ndquot} { xmlpi->key = g_strdup(yytext); BEGIN XMLPI_ATTRS; }

<XMLPI_ATTRS>{xmlpi_value_attr} BEGIN XMLPI_GETVAL;
<XMLPI_GETVAL>{ndquot} { xmlpi->value = g_strdup(yytext); BEGIN XMLPI_ATTRS; }

<XMLPI_ATTRS>.
<XMLPI_ATTRS>{xmlpi_end} BEGIN LOADING;


<LOADING>{start_entity} BEGIN ENTITY;
<ENTITY>{entityname} {
	entity_t *e = g_malloc(sizeof(entity_t));
	D(("ENTITY: %s\n",yytext));
	e->name = g_strdup(yytext);
	e->next = ents.next;
	ents.next = e;
	BEGIN GET_SYSTEM;
};
<GET_SYSTEM>{system} BEGIN GET_FILE;
<GET_FILE>{ndquot} {
	D(("GET_FILE: %s\n",yytext));
	ents.next->file = g_strdup(yytext);
	BEGIN END_ENTITY;
}
<END_ENTITY>{end_entity} BEGIN LOADING;

<LOADING>{open_tag} APPEND("<",1);

<LOADING>{close_tag} APPEND(">",1);

<LOADING>{end_tag} APPEND("/>",2);

<LOADING>{open_closetag} APPEND("</",2);

<LOADING>{whitespace} APPEND(" ",1);

<LOADING>{dquoted} APPEND(yytext,yyleng);

<LOADING>{equals} APPEND("=",1);

<LOADING>{any} APPEND(yytext,yyleng);

<LOADING,IN_DICT>{entity} {
	gchar *p = ++yytext, *temp_str;
	entity_t* e;

	while(*p != ';') p++;

	*p = '\0';

	D(("looking for entity: %s\n",yytext));

	if ( include_stack_ptr >= MAX_INCLUDE_DEPTH ) {
		dict_error = g_string_append(
			dict_error, "included files nested too deeply\n");
		yyterminate();
	}

	include_stack[include_stack_ptr++] = YY_CURRENT_BUFFER;


	for (e = ents.next; e; e = e->next) {
		if (strcmp(e->name,yytext) == 0) {
			yyin = wimaxasncp_dict_open(sys_dir,e->file);
			D(("entity: %s filename: %s yyin: %p\n",e->name,e->file,yyin));
			if (!yyin) {
				yyterminate();
			} else {
				yy_switch_to_buffer(yy_create_buffer( yyin, YY_BUF_SIZE ) );
			}
			break;
		}
	}

	if (!e) {
		temp_str = g_strdup_printf(
			"cannot find entity: '%s'\n", yytext);
		dict_error = g_string_append(dict_error, temp_str);
		g_free(temp_str);
		yyterminate();
	}

}

<<EOF>> {
	if (!yyin) yyterminate();

	fclose(yyin);
	D(("closing: %p %i\n",yyin,include_stack_ptr));

	if ( --include_stack_ptr < 0 ) {
		D(("DONE READING\n"));
		yyin = NULL;
		yyterminate();
	} else {
		yy_delete_buffer( YY_CURRENT_BUFFER );
		yy_switch_to_buffer(include_stack[include_stack_ptr]);
		BEGIN LOADING;
	}
}


<GET_ATTR>{ndquot} {
	*attr_str = g_strdup(yytext);
	D(("%s\n",yytext));
	attr_str = NULL;
	BEGIN END_ATTR;
}

<GET_UINT_ATTR>{number} {
	*attr_uint = strtoul(yytext,NULL,0);
	D(("%s\n",yytext););
	attr_uint = NULL;
	BEGIN END_ATTR;
}

<GET_UINT16_ATTR>{number} {
	*attr_uint16 = (gint16) strtol(yytext,NULL,0);
	D(("%s\n",yytext););
	attr_uint16 = NULL;
	BEGIN END_ATTR;
}

<GET_UINT_ATTR>"WIMAXASNCP_BIT32"[ \t]*"("    { BEGIN BIT32; }

<BIT32>[0-9]+ {
	*attr_uint = wimaxasncp_bits(32, yytext);
	D(("WIMAXASNCP_BIT32(%s)\n",yytext););
	attr_uint = NULL;
}

<GET_UINT_ATTR>"WIMAXASNCP_BIT16"[ \t]*"("    { BEGIN BIT16; }

<BIT16>[0-9]+ {
	*attr_uint = wimaxasncp_bits(16, yytext);
	D(("WIMAXASNCP_BIT16(%s)\n",yytext););
	attr_uint = NULL;
}

<GET_UINT_ATTR>"WIMAXASNCP_BIT8"[ \t]*"("     { BEGIN BIT8; }

<BIT8>[0-9]+ {
	*attr_uint = wimaxasncp_bits(8, yytext);
	D(("WIMAXASNCP_BIT8(%s)\n",yytext););
	attr_uint = NULL;
}

<BIT32,BIT16,BIT8>[ \t]*")" { BEGIN END_ATTR; }

<GET_DECODER_ATTR>{ndquot} {
	*attr_uint = wimaxasncp_decode_type(yytext);
	D(("%s\n",yytext));
	attr_uint = NULL;
	BEGIN END_ATTR;
}

<END_ATTR>{dquot} {	yy_pop_state(); }

<IGNORE_ATTR>. {
	/* XXX: should go?*/
	D(("{%s}",yytext));
}

<IGNORE_ATTR>{ignored_quoted} {
	D(("=>%s<=\n",yytext));
	yy_pop_state();
}

<OUTSIDE>{dictionary_start} {
	D(("dictionary_start\n"));

	BEGIN IN_DICT;
}

<IN_DICT>{tlv_start}	{
	D(("tlv_start\n"));

	tlv = g_malloc(sizeof(wimaxasncp_dict_tlv_t));
	tlv->type = 0;
	tlv->name = NULL;
	tlv->description = NULL;
	tlv->decoder = 0;
	tlv->since = 0;
	tlv->hf_root = -1;
	tlv->hf_value = -1;
	tlv->hf_ipv4 = -1;
	tlv->hf_ipv6 = -1;
	tlv->hf_bsid = -1;
	tlv->hf_protocol = -1;
	tlv->hf_port_low = -1;
	tlv->hf_port_high = -1;
	tlv->hf_ipv4_mask = -1;
	tlv->hf_ipv6_mask = -1;
	tlv->hf_vendor_id = -1;
	tlv->hf_vendor_rest_of_info = -1;
	tlv->enum_vs = NULL;
	tlv->enums = NULL;
	tlv->next = NULL;

	if (! dict->tlvs ) last_tlv = dict->tlvs = tlv;
	else last_tlv = last_tlv->next = tlv;

	BEGIN TLV_ATTRS;
}

<TLV_ATTRS>{name_attr}			{ ATTR_STR(tlv->name); }
<TLV_ATTRS>{description_attr}		{ ATTR_STR(tlv->description); }
<TLV_ATTRS>{type_attr}			{ ATTR_UINT16(tlv->type); }
<TLV_ATTRS>{decoder_attr}		{ ATTR_DECODER(tlv->decoder); }
<TLV_ATTRS>{since_attr}			{ ATTR_UINT(tlv->since); }
<TLV_ATTRS>{stop}			{ BEGIN IN_TLV;	 }
<TLV_ATTRS>{stop_end}			{ BEGIN IN_DICT; }


<IN_TLV>{enum_start} {
	D(("enum_start\n"));

	enumitem = g_malloc(sizeof(wimaxasncp_dict_enum_t));
	enumitem->name = NULL;
	enumitem->code = 0;
	enumitem->next = NULL;

	if (!tlv->enums) last_enumitem = tlv->enums = enumitem;
	else last_enumitem = last_enumitem->next = enumitem;

	BEGIN ENUM_ATTRS;
}


<ENUM_ATTRS>{name_attr}			{ ATTR_STR(enumitem->name); }
<ENUM_ATTRS>{code_attr}			{ ATTR_UINT(enumitem->code); }

<ENUM_ATTRS>{stop}	     { BEGIN IN_TLV; }
<ENUM_ATTRS>{stop_end}	     { BEGIN IN_TLV; }

<IN_TLV>{tlv_end} { D(("tlv_end")); BEGIN IN_DICT; }

<IN_DICT>{dictionary_end} {
	yyterminate();
}

<TLV_ATTRS,ENUM_ATTRS>{ignored_attr} WIMAXASNCP_IGNORE();

<OUTSIDE>. ;






%%

static int debugging  = 0;

static void wimaxasncp_dict_debug(const gchar *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	if (debugging) vfprintf(stderr, fmt, ap);
	va_end(ap);

	fflush(stderr);
}

static guint wimaxasncp_bits(guint bits, char *n)
{
	return 1 << ((bits - 1) - (strtoul(n, NULL, 10)));
}

static const value_string wimaxasncp_decode_type_vals[] =
{
  { WIMAXASNCP_TLV_TBD,                 "WIMAXASNCP_TLV_TBD"},
  { WIMAXASNCP_TLV_COMPOUND,            "WIMAXASNCP_TLV_COMPOUND"},
  { WIMAXASNCP_TLV_BYTES,               "WIMAXASNCP_TLV_BYTES"},
  { WIMAXASNCP_TLV_ENUM8,               "WIMAXASNCP_TLV_ENUM8"},
  { WIMAXASNCP_TLV_ENUM16,              "WIMAXASNCP_TLV_ENUM16"},
  { WIMAXASNCP_TLV_ENUM32,              "WIMAXASNCP_TLV_ENUM32"},
  { WIMAXASNCP_TLV_ETHER,               "WIMAXASNCP_TLV_ETHER"},
  { WIMAXASNCP_TLV_ASCII_STRING,        "WIMAXASNCP_TLV_ASCII_STRING"},
  { WIMAXASNCP_TLV_FLAG0,               "WIMAXASNCP_TLV_FLAG0"},
  { WIMAXASNCP_TLV_BITFLAGS8,           "WIMAXASNCP_TLV_BITFLAGS8"},
  { WIMAXASNCP_TLV_BITFLAGS16,          "WIMAXASNCP_TLV_BITFLAGS16"},
  { WIMAXASNCP_TLV_BITFLAGS32,          "WIMAXASNCP_TLV_BITFLAGS32"},
  { WIMAXASNCP_TLV_ID,                  "WIMAXASNCP_TLV_ID"},
  { WIMAXASNCP_TLV_HEX8,                "WIMAXASNCP_TLV_HEX8"},
  { WIMAXASNCP_TLV_HEX16,               "WIMAXASNCP_TLV_HEX16"},
  { WIMAXASNCP_TLV_HEX32,               "WIMAXASNCP_TLV_HEX32"},
  { WIMAXASNCP_TLV_DEC8,                "WIMAXASNCP_TLV_DEC8"},
  { WIMAXASNCP_TLV_DEC16,               "WIMAXASNCP_TLV_DEC16"},
  { WIMAXASNCP_TLV_DEC32,               "WIMAXASNCP_TLV_DEC32"},
  { WIMAXASNCP_TLV_IP_ADDRESS,          "WIMAXASNCP_TLV_IP_ADDRESS"},
  { WIMAXASNCP_TLV_IPV4_ADDRESS,        "WIMAXASNCP_TLV_IPV4_ADDRESS"},
  { WIMAXASNCP_TLV_PROTOCOL_LIST,       "WIMAXASNCP_TLV_PROTOCOL_LIST"},
  { WIMAXASNCP_TLV_PORT_RANGE_LIST,     "WIMAXASNCP_TLV_PORT_RANGE_LIST"},
  { WIMAXASNCP_TLV_IP_ADDRESS_MASK_LIST,"WIMAXASNCP_TLV_IP_ADDRESS_MASK_LIST"},
  { WIMAXASNCP_TLV_EAP,                 "WIMAXASNCP_TLV_EAP"},
  { WIMAXASNCP_TLV_VENDOR_SPECIFIC,     "WIMAXASNCP_TLV_VENDOR_SPECIFIC"},
  { 0, NULL}
};

static gint wimaxasncp_decode_type(const gchar *name)
{
	gsize i;
	for (i = 0; i < array_length(wimaxasncp_decode_type_vals) - 1; ++i)
	{
		if (strcmp(name, wimaxasncp_decode_type_vals[i].strptr) == 0)
		{
			return wimaxasncp_decode_type_vals[i].value;
		}
	}

	/* not found, emit some sort of error here? */

	return WIMAXASNCP_TLV_TBD;
}

static gchar *strbuf = NULL;
static gchar *write_ptr = NULL;
static gchar *read_ptr = NULL;

static guint size_strbuf = 8192;
static guint len_strbuf = 0;

extern void wimaxasncp_dict_unused(void);
void wimaxasncp_dict_unused(void) {
	yy_top_state();
}

static void append_to_buffer(gchar *txt, int len) {

	if (strbuf == NULL) {
		read_ptr = write_ptr = strbuf = g_malloc(size_strbuf);
	}

	if ( (len_strbuf + len + 1) >= size_strbuf ) {
		read_ptr = strbuf = g_realloc(strbuf,size_strbuf *= 2);
	}

	write_ptr = strbuf + len_strbuf;
	strncpy(write_ptr,txt,len);
	len_strbuf += len;
	strbuf[len_strbuf] = '\0';
}

static size_t file_input(gchar *buf, size_t max) {
	size_t read;

	read = fread(buf,1,max,yyin);

	if ( read == max ) {
		return max;
	} else if (read > 0) {
		return read;
	} else {
		return YY_NULL;
	}
}


static size_t string_input(gchar *buf, size_t max) {
	if (read_ptr >= write_ptr ) {
		return YY_NULL;
	} else if ( read_ptr + max > write_ptr ) {
		max = write_ptr - read_ptr;
	}

	memcpy(buf,read_ptr,max);
	read_ptr += max;

	return max;
}

static FILE *wimaxasncp_dict_open(
	const gchar *system_directory,
	const gchar *filename)
{
	FILE *fh;
	gchar *fname;
	if (system_directory)
	{
		fname = g_strdup_printf("%s%s%s",
			   system_directory, G_DIR_SEPARATOR_S,filename);
	}
	else
	{
		fname = g_strdup(filename);
	}

	fh = ws_fopen(fname,"r");

	D(("fname: %s fh: %p\n",fname,fh));

	g_free(fname);


	return fh;
}

wimaxasncp_dict_t *wimaxasncp_dict_scan(
	const gchar *system_directory, const gchar *filename, int dbg,
	gchar **error) {

	entity_t *e;

	dict_error = g_string_new("");

	debugging = dbg;

	sys_dir = system_directory;

	write_ptr = NULL;
	read_ptr = NULL;

	if (dict)
	{
		wimaxasncp_dict_free(dict);
	}

	dict = g_malloc(sizeof(wimaxasncp_dict_t));
	dict->tlvs = NULL;
	dict->xmlpis = NULL;

	tlv = NULL;
	enumitem = NULL;
	xmlpi = NULL;

	last_tlv = NULL;
	last_enumitem = NULL;
	last_xmlpi = NULL;

	ents.next = NULL;

	yyin = wimaxasncp_dict_open(sys_dir,filename);

	if (yyin)
	{
		current_yyinput = file_input;
		BEGIN LOADING;
		yylex();

		D(("\n---------------\n%s\n------- %d -------\n",
		   strbuf, len_strbuf));

		current_yyinput = string_input;

		BEGIN OUTSIDE;
		yylex();
	}

	e = ents.next;
	while (e)
	{
		entity_t *next = e->next;
		g_free(e->name);
		g_free(e->file);
		g_free(e);
		e = next;
	}

	g_free(strbuf);
	strbuf = NULL;
	size_strbuf = 8192;

	if (dict_error->len > 0)
	{
		*error = dict_error->str;
		g_string_free(dict_error, FALSE);
	}
	else
	{
		*error = NULL;
		g_string_free(dict_error, TRUE);
	}

	return dict;
}

void wimaxasncp_dict_free(wimaxasncp_dict_t *d) {
	wimaxasncp_dict_tlv_t *t, *tn;

#define FREE_NAMEANDOBJ(n) do { if(n->name) g_free(n->name); g_free(n); } while(0)

	for (t = d->tlvs; t; t = tn) {
		wimaxasncp_dict_enum_t *e, *en;
		tn = t->next;

		for (e = t->enums; e; e = en) {
			en = e->next;
			FREE_NAMEANDOBJ(e);
		}

		if (!t->description)  g_free(t->description);
		FREE_NAMEANDOBJ(t);
	}

	g_free(d);
}

void wimaxasncp_dict_print(FILE *fh, wimaxasncp_dict_t *d) {
	wimaxasncp_dict_tlv_t *tlv;

	fprintf(fh,"\n");

	for (tlv = d->tlvs; tlv; tlv = tlv->next) {
		wimaxasncp_dict_enum_t *e;
		fprintf(fh,"TLV: %s[%u] %s[%d] %s (since %u)\n",
				tlv->name ? tlv->name : "-",
				tlv->type,
				val_to_str(tlv->decoder,
					   wimaxasncp_decode_type_vals,
					   "Unknown"),
				tlv->decoder,
				tlv->description ? tlv->description : "",
            			tlv->since);

		for (e = tlv->enums; e; e = e->next) {
			fprintf(fh,"\tEnum: %s[%u]\n",
					e->name ? e->name : "-",
					e->code);
		}
	}
}

/*
 * We want to stop processing when we get to the end of the input.
 * (%option noyywrap is not used because if used then
 * some flex versions (eg: 2.5.35) generate code which causes
 * warnings by the Windows VC compiler).
 */

int yywrap(void) {
    return 1;
}

#ifdef TEST_WIMAXASNCP_DICT_STANDALONE
int main(int argc, char **argv) {
	wimaxasncp_dict_t *d;
	gchar *dname = NULL;
	gchar *fname;
	int i = 1;

	switch (argc) {
		case 3:
			dname = argv[i++];
		case 2:
			fname = argv[i];
			break;
		default:
			fprintf(stderr,"%s: usage [dictionary_dir] dictionary_filename\n",argv[0]);
			return 1;
	}

	d = wimaxasncp_dict_scan(dname,fname,1,&dict_error);

	if (dict_error)
	{
		printf("wimaxasncp - %s", dict_error);
		g_free(dict_error);
	}

	wimaxasncp_dict_print(stdout, d);

	return 0;
}
#endif
