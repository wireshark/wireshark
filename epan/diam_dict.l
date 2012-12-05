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
 * Prefix scanner routines with "DiamDict" rather than "yy", so this scanner
 * can coexist with other scanners.
 */
%option prefix="DiamDict"

%option outfile="diam_dict.c"

%{
	/*
	 ** diam_dict.h
	 ** Diameter Dictionary Import Routines
	 **
	 ** $Id$
	 **
	 ** (c) 2007, Luis E. Garcia Ontanon <luis@ontanon.org>
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
#include "diam_dict.h"
#include "diam_dict_lex.h"
#include <wsutil/file_util.h>

typedef struct entity_t {
	char* name;
	char* file;
	struct entity_t* next;
} entity_t;

#define ATTR_UINT(cont) do { D(("attr_uint " #cont "\t" )); attr_uint = &(cont); yy_push_state(GET_UINT_ATTR); } while(0)
#define ATTR_STR(cont) do { D(("attr_str " #cont "\t" )); attr_str = &(cont); yy_push_state(GET_ATTR); } while(0)
#define IGNORE() do { D(("ignore: %s\t",yytext)); yy_push_state(IGNORE_ATTR); } while(0)

#define D(args) ddict_debug args

#define MAX_INCLUDE_DEPTH 10
#define YY_INPUT(buf,result,max_size) { result = current_yyinput(buf,max_size); }
#define ECHO
#define APPEND(txt,len) append_to_buffer(txt,len)

static entity_t ents;
static YY_BUFFER_STATE include_stack[MAX_INCLUDE_DEPTH];
static int include_stack_ptr = 0;
static size_t (*current_yyinput)(char*,size_t);
static const char* sys_dir;
static ddict_t* dict;
static ddict_application_t* appl;
static ddict_avp_t* avp;
static ddict_enum_t* enumitem;
static ddict_gavp_t* gavp;
static ddict_typedefn_t* typedefn;
static ddict_cmd_t* cmd;
static ddict_vendor_t* vnd;
static ddict_xmlpi_t* xmlpi;

static ddict_application_t* last_appl;
static ddict_avp_t* last_avp;
static ddict_enum_t* last_enumitem;
static ddict_gavp_t* last_gavp;
static ddict_typedefn_t* last_typedefn;
static ddict_cmd_t* last_cmd;
static ddict_vendor_t* last_vnd;
static ddict_xmlpi_t* last_xmlpi;

static char** attr_str;
static unsigned* attr_uint;

static void ddict_debug(const char* fmt, ...);
static void append_to_buffer(char* txt, int len);
static FILE* ddict_open(const char*, const char*);

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
number [-]?[0-9]*

dictionary_start <dictionary>
dictionary_end <\/dictionary>

base_start <base[^>*]*>
base_end <\/base>

application_start <application
application_end<\/application>

command_start <command
command_end<\/command>

typedefn_start <typedefn

avp_start <avp
avp_end <\/avp>

type_start <type
enum_start <enum

grouped_start <grouped>
grouped_end <\/grouped>

vendor_start <vendor
gavp_start <gavp

ignored_attr [a-z0-9-]+=
ignored_quoted \042[^\042]*\042

name_attr name=\042
id_attr id=\042
code_attr code=\042
vendor_attr vendor-id=\042
typename_attr type-name=\042
typeparent_attr type-parent=\042
description_attr description=\042



%S LOADING LOADING_COMMENT LOADING_XMLPI ENTITY GET_SYSTEM GET_FILE END_ENTITY
%S GET_ATTR GET_UINT_ATTR END_ATTR OUTSIDE IN_DICT IN_APPL IN_AVP APPL_ATTRS IGNORE_ATTR
%S TYPE_ATTRS GAVP_ATTRS ENUM_ATTRS AVP_ATTRS VENDOR_ATTRS COMMAND_ATTRS TYPEDEFN_ATTRS
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
	xmlpi = g_malloc(sizeof(ddict_xmlpi_t));
	xmlpi->name = g_strdup(yytext);
	xmlpi->key = NULL;
	xmlpi->value = NULL;
	xmlpi->next = NULL;

	if (!dict->xmlpis) last_xmlpi = dict->xmlpis = xmlpi;
	else last_xmlpi = last_xmlpi->next = xmlpi;

	BEGIN XMLPI_ATTRS;
}

<XMLPI_ATTRS>{xmlpi_key_attr} BEGIN XMLPI_GETKEY;
<XMLPI_GETKEY>{ndquot} { xmlpi->key = strdup(yytext); BEGIN XMLPI_ATTRS; }

<XMLPI_ATTRS>{xmlpi_value_attr} BEGIN XMLPI_GETVAL;
<XMLPI_GETVAL>{ndquot} { xmlpi->value = strdup(yytext); BEGIN XMLPI_ATTRS; }

<XMLPI_ATTRS>.
<XMLPI_ATTRS>{xmlpi_end} BEGIN LOADING;


<LOADING>{start_entity} BEGIN ENTITY;
<ENTITY>{entityname} {
	entity_t* e = g_malloc(sizeof(entity_t));
	e->name = strdup(yytext);
	e->next = ents.next;
	ents.next = e;
	BEGIN GET_SYSTEM;
	};
<GET_SYSTEM>{system} BEGIN GET_FILE;
<GET_FILE>{ndquot} {
		ents.next->file = strdup(yytext);
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

<LOADING>{entity} {
	char* p = ++yytext;
	entity_t* e;

	while(*p != ';') p++;

	*p = '\0';

	D(("looking for entity: %s\n",yytext));

	if ( include_stack_ptr >= MAX_INCLUDE_DEPTH ) {
		fprintf(stderr, "included files nested to deeply\n");
		yyterminate();
	}

	for (e = ents.next; e; e = e->next) {
		if (strcmp(e->name,yytext) == 0) {
			yyin = ddict_open(sys_dir,e->file);
			D(("entity: %s filename: %s yyin: %p\n",e->name,e->file,yyin));
			if (!yyin) {
				if (errno)
					fprintf(stderr, "Could not open file: '%s', error: %s\n", e->file, g_strerror(errno) );
				else
					fprintf(stderr, "Could not open file: '%s', error unknown (errno == 0)\n", e->file );
				yyterminate();
			} else {
				include_stack[include_stack_ptr++] = YY_CURRENT_BUFFER;
				yy_switch_to_buffer(yy_create_buffer( yyin, YY_BUF_SIZE ) );
				BEGIN LOADING;
			}
			break;
		}
	}

	if (!e) {
		fprintf(stderr, "Could not find entity: '%s'\n", yytext );
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
	*attr_str = strdup(yytext);
	D(("%s\n",yytext));
	attr_str = NULL;
	BEGIN END_ATTR;
}

<GET_UINT_ATTR>{number} {
	*attr_uint = strtoul(yytext,NULL,10);
	D(("%s\n",yytext););
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

<IN_DICT>{base_start} {
	D(("base_start\n"));
	BEGIN IN_APPL;
}

<IN_DICT>{application_start} {
	D(("application_start\n"));

	appl = g_malloc(sizeof(ddict_application_t));
	appl->name = NULL;
	appl->code = 0;
	appl->next = NULL;

	if (!dict->applications) last_appl = dict->applications = appl;
	else last_appl = last_appl->next = appl;

	BEGIN APPL_ATTRS;
}

<APPL_ATTRS>{name_attr} { ATTR_STR(appl->name); }
<APPL_ATTRS>{id_attr} { ATTR_UINT(appl->code); }

<APPL_ATTRS>{stop} BEGIN IN_APPL;
<APPL_ATTRS>{stop_end} BEGIN IN_DICT;

<IN_APPL>{command_end}			;

<IN_APPL>{command_start}		{
	D(("command_start\n"));

	cmd = g_malloc(sizeof(ddict_cmd_t));
	cmd->name = NULL;
	cmd->vendor = NULL;
	cmd->code = 0;
	cmd->next = NULL;

	if (!dict->cmds) last_cmd = dict->cmds = cmd;
	else last_cmd = last_cmd->next = cmd;

	BEGIN COMMAND_ATTRS;
}

<COMMAND_ATTRS>{name_attr}		{ ATTR_STR(cmd->name); }
<COMMAND_ATTRS>{vendor_attr}	{ ATTR_STR(cmd->vendor); }
<COMMAND_ATTRS>{code_attr}		{ ATTR_UINT(cmd->code); }
<COMMAND_ATTRS>{stop}			|
<COMMAND_ATTRS>{stop_end}		{ BEGIN IN_APPL; }

<IN_APPL>{vendor_start} {
	D(("vendor_start\n"));

	vnd = g_malloc(sizeof(ddict_vendor_t));
	vnd->name = NULL;
	vnd->code = 0;
	vnd->next = NULL;

	if (!dict->vendors) last_vnd = dict->vendors = vnd;
	else last_vnd = last_vnd->next = vnd;

	BEGIN VENDOR_ATTRS;
}

<VENDOR_ATTRS>{name_attr}		{ ATTR_STR(vnd->desc); }
<VENDOR_ATTRS>{vendor_attr}		{ ATTR_STR(vnd->name); }
<VENDOR_ATTRS>{code_attr}		{ ATTR_UINT(vnd->code); }
<VENDOR_ATTRS>{stop}			|
<VENDOR_ATTRS>{stop_end}		{ BEGIN IN_APPL; }

<IN_APPL>{typedefn_start} {
	D(("typedefn_start\n"));

	typedefn = g_malloc(sizeof(ddict_typedefn_t));
	typedefn->name = NULL;
	typedefn->parent = NULL;
	typedefn->next = NULL;

	if (!dict->typedefns) last_typedefn = dict->typedefns = typedefn;
	else last_typedefn = last_typedefn->next = typedefn;

	BEGIN TYPEDEFN_ATTRS;
}

<TYPEDEFN_ATTRS>{typename_attr}		{ ATTR_STR(typedefn->name); }
<TYPEDEFN_ATTRS>{typeparent_attr}	{ ATTR_STR(typedefn->parent); }
<TYPEDEFN_ATTRS>{stop}			|
<TYPEDEFN_ATTRS>{stop_end}		{ BEGIN IN_APPL; }


<IN_APPL>{avp_start}	{
	D(("avp_start\n"));

	avp = g_malloc(sizeof(ddict_avp_t));
	avp->name = NULL;
	avp->description = NULL;
	avp->vendor = NULL;
	avp->code = 0;
	avp->type = NULL;
	avp->enums = NULL;
	avp->gavps = NULL;
	avp->next = NULL;

	if (! dict->avps ) last_avp = dict->avps = avp;
	else last_avp = last_avp->next = avp;

	BEGIN AVP_ATTRS;
}

<AVP_ATTRS>{name_attr}			{ ATTR_STR(avp->name); }
<AVP_ATTRS>{description_attr}	{ ATTR_STR(avp->description); }
<AVP_ATTRS>{vendor_attr}		{ ATTR_STR(avp->vendor); }
<AVP_ATTRS>{code_attr}			{ ATTR_UINT(avp->code); }
<AVP_ATTRS>{stop}				{ BEGIN IN_AVP;  }
<AVP_ATTRS>{stop_end}			{ BEGIN IN_APPL; }


<IN_AVP>{grouped_start} { avp->type = strdup("Grouped"); };
<IN_AVP>{grouped_end} ;

<IN_AVP>{type_start} { BEGIN TYPE_ATTRS; }
<TYPE_ATTRS>{typename_attr}			{ ATTR_STR(avp->type); }

<IN_AVP>{gavp_start} {
	D(("gavp_start\n"));

	gavp = g_malloc(sizeof(ddict_gavp_t));
	gavp->name = NULL;
	gavp->code = 0;
	gavp->next = NULL;

	if (!avp->gavps) last_gavp = avp->gavps = gavp;
	else last_gavp = last_gavp->next = gavp;

	BEGIN GAVP_ATTRS;
}


<GAVP_ATTRS>{name_attr}			{ ATTR_STR(gavp->name); }


<IN_AVP>{enum_start} {
	D(("enum_start\n"));

	enumitem = g_malloc(sizeof(ddict_enum_t));
	enumitem->name = NULL;
	enumitem->code = 0;
	enumitem->next = NULL;

	if (!avp->enums) last_enumitem = avp->enums = enumitem;
	else last_enumitem = last_enumitem->next = enumitem;

	BEGIN ENUM_ATTRS;
}


<ENUM_ATTRS>{name_attr}			{ ATTR_STR(enumitem->name); }
<ENUM_ATTRS>{code_attr}			{ ATTR_UINT(enumitem->code); }

<TYPE_ATTRS,GAVP_ATTRS,ENUM_ATTRS>{stop}			{ BEGIN IN_AVP; }
<TYPE_ATTRS,GAVP_ATTRS,ENUM_ATTRS>{stop_end}		{ BEGIN IN_AVP; }

<IN_AVP>{avp_end} { D(("avp_end")); BEGIN IN_APPL; }

<IN_APPL>{application_end} |
<IN_APPL>{base_end} {
	BEGIN IN_DICT;
}

<IN_DICT>{dictionary_end} {
	yyterminate();
}

<AVP_ATTRS,ENUM_ATTRS,GAVP_ATTRS,TYPE_ATTRS,TYPEDEFN_ATTRS,VENDOR_ATTRS,APPL_ATTRS,COMMAND_ATTRS>{ignored_attr} IGNORE();

<OUTSIDE>. ;






%%

static int debugging  = 0;

static void ddict_debug(const char* fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	if (debugging) vfprintf(stderr, fmt, ap);
	va_end(ap);

	fflush(stderr);
}


static char* strbuf = NULL;
static char* write_ptr = NULL;
static char* read_ptr = NULL;

static unsigned size_strbuf = 8192;
static unsigned len_strbuf = 0;

extern void ddict_unused(void);
void ddict_unused(void) {
	yy_top_state();
}

static void append_to_buffer(char* txt, int len) {

	if (strbuf == NULL) {
		read_ptr = write_ptr = strbuf = g_malloc(size_strbuf);
	}

	if ( (len_strbuf + len) >= size_strbuf ) {
		read_ptr = strbuf = g_realloc(strbuf,size_strbuf *= 2);
	}

	write_ptr = strbuf + len_strbuf;
	strncpy(write_ptr,txt,len);
	len_strbuf += len;

}

static size_t file_input(char* buf, size_t max) {
	size_t read_cnt;

	read_cnt = fread(buf,1,max,yyin);

	if ( read_cnt == max ) {
		return max;
	} else if (read_cnt > 0) {
		return read_cnt;
	} else {
		return YY_NULL;
	}
}


static size_t string_input(char* buf, size_t max) {
	if (read_ptr >= write_ptr ) {
		return YY_NULL;
	} else if ( read_ptr + max > write_ptr ) {
		max = write_ptr - read_ptr;
	}

	memcpy(buf,read_ptr,max);
	read_ptr += max;

	return max;
}

static FILE* ddict_open(const char* system_directory, const char* filename) {
	FILE* fh;
	char* fname;
	if (system_directory) {
		fname = g_strdup_printf("%s" G_DIR_SEPARATOR_S "%s",
		    system_directory,filename);
	} else {
		fname = g_strdup(filename);
	}

	fh = ws_fopen(fname,"r");

	D(("fname: %s fh: %p\n",fname,fh));

	g_free(fname);


	return fh;
}

ddict_t* ddict_scan(const char* system_directory, const char* filename, int dbg) {

	debugging = dbg;

	sys_dir = system_directory;

	yyin = ddict_open(sys_dir,filename);

	if (yyin == NULL) {
		D(("unable to open %s\n", filename));
		return NULL;
	}

	write_ptr = NULL;
	read_ptr = NULL;

	dict = g_malloc(sizeof(ddict_t));
	dict->applications = NULL;
	dict->cmds = NULL;
	dict->vendors = NULL;
	dict->typedefns = NULL;
	dict->avps = NULL;
	dict->xmlpis = NULL;

	appl = NULL;
	avp = NULL;
	enumitem = NULL;
	gavp = NULL;
	typedefn = NULL;
	cmd = NULL;
	vnd = NULL;
	xmlpi = NULL;

	last_appl = NULL;
	last_avp = NULL;
	last_enumitem = NULL;
	last_gavp = NULL;
	last_typedefn = NULL;
	last_cmd = NULL;
	last_vnd = NULL;
	last_xmlpi = NULL;

	ents.next = NULL;
	current_yyinput = file_input;
	BEGIN LOADING;
	yylex();

	D(("\n---------------\n%s\n------- %d -------\n",strbuf,len_strbuf));

	current_yyinput = string_input;

	BEGIN OUTSIDE;
	yylex();

	g_free(strbuf);
	strbuf = NULL;
	size_strbuf = 8192;

	return dict;
}

void ddict_free(ddict_t* d) {
	ddict_application_t *p, *pn;
	ddict_vendor_t *v, *vn;
	ddict_cmd_t *c, *cn;
	ddict_typedefn_t *t, *tn;
	ddict_avp_t *a, *an;

#define FREE_NAMEANDOBJ(n) do { if(n->name) g_free(n->name); g_free(n); } while(0)

	for (p = d->applications; p; p = pn ) {
		pn = p->next;
		FREE_NAMEANDOBJ(p);
	}

	for (v = d->vendors; v; v = vn) {
		vn = v->next;
		if (!v->desc)  g_free(v->desc);
		FREE_NAMEANDOBJ(v);
	}

	for (c = d->cmds; c; c = cn ) {
		cn = c->next;
		FREE_NAMEANDOBJ(c);
	}

	for (t = d->typedefns; t; t = tn) {
		tn = t->next;
		if (!t->parent)  g_free(t->parent);
		FREE_NAMEANDOBJ(t);
	}

	for (a = d->avps; a; a = an) {
		ddict_gavp_t* g, *gn;
		ddict_enum_t* e, *en;
		an = a->next;

		for (g = a->gavps; g; g = gn) {
			gn = g->next;
			FREE_NAMEANDOBJ(g);
		}

		for (e = a->enums; e; e = en) {
			en = e->next;
			FREE_NAMEANDOBJ(e);
		}

		if (!a->vendor)  g_free(a->vendor);
		if (!a->type)  g_free(a->type);
		if (!a->description)  g_free(a->description);
		FREE_NAMEANDOBJ(a);
	}

	g_free(d);
}

void ddict_print(FILE* fh, ddict_t* d) {
	ddict_application_t* p;
	ddict_vendor_t* v;
	ddict_cmd_t* c;
	ddict_typedefn_t* t;
	ddict_avp_t* a;


	for (p = d->applications; p; p = p->next) {
		fprintf(fh,"Application: %s[%u]:\n",
				p->name ? p->name : "-",
				p->code);
	}

	for (v = d->vendors; v; v = v->next) {
		fprintf(fh,"Vendor: %s[%u]:\n",
				v->name ? v->name : "-",
				v->code);
	}

	for (c = d->cmds; c; c = c->next) {
		fprintf(fh,"Command: %s[%u] \n",
				c->name ? c->name : "-",
				c->code);
	}

	for (t = d->typedefns; t; t = t->next) {
		fprintf(fh,"Type: %s -> %s \n",
				t->name ? t->name : "-",
				t->parent ? t->parent : "" );
	}

	for (a = d->avps; a; a = a->next) {
		ddict_gavp_t* g;
		ddict_enum_t* e;
		fprintf(fh,"AVP: %s[%u:%s] %s %s\n",
				a->name ? a->name : "-",
				a->code,
				a->vendor ? a->vendor : "None",
				a->type ? a->type : "-",
				a->description ? a->description : "");

		for (g = a->gavps; g; g = g->next) {
			fprintf(fh,"\tGAVP: %s\n",
					g->name ? g->name : "-" );
		}

		for (e = a->enums; e; e = e->next) {
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

#ifdef TEST_DIAM_DICT_STANDALONE
int main(int argc, char** argv) {
	ddict_t* d;
	char* dname = NULL;
	char* fname;
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

	d = ddict_scan(dname,fname,1);
	if (d == NULL) {
		fprintf(stderr, "Can't open dictionary\n");
		return 2;
	}

	ddict_print(stdout, d);

	return 0;
}
#endif
