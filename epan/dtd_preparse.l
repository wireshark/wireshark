%option noyywrap
%option nounput
%option prefix="Dtd_PreParse_"
%option never-interactive
%option caseless
%option outfile="dtd_preparse.c"

%{
	/*
	 * dtd_preparser.l
	 *
	 * an XML dissector for ethereal 
	 *
	 * DTD Preparser -  import a dtd file into a GString
	 *					including files, removing comments
	 *                  and resolving %entities;
	 * 
	 * Copyright 2004, Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
	 *
	 * $Id$
	 *
	 * Ethereal - Network traffic analyzer
	 * By Gerald Combs <gerald@ethereal.com>
	 * Copyright 1998 Gerald Combs
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
	 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
	 */
			
#include <glib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include "dtd.h"

#define MAX_INCLUDE_DEPTH 10
static YY_BUFFER_STATE include_stack[MAX_INCLUDE_DEPTH];
static int include_stack_ptr = 0;

#define ECHO g_string_append(current,yytext);

GString* current;
GString* output;
GHashTable* entities;
gchar* entity_name;
GString* error;

const gchar* dirname;
const gchar* filename;
guint linenum;

GString* textstr;

static gchar* replace_entity(gchar* s);
static const gchar* location(void);

%}
xmlpi_start "<?"
xmlpi_stop  "?>"
xmlpi_chars .

comment_start "<!--"
comment_stop "-->"
special_start "<!"
special_stop ">"

entity_start     "<!"[[:blank:]\n]*entity[[:blank:]\n]*"%"
system     SYSTEM
filename   [^"]+


name [A-Za-z][-:A-Za-z0-9_\.]*

quote "\""
percent [%]
escaped_quote "\\\""
non_quote [^"%]+

avoid_editor_bug ["]

entity        [%&][A-Za-z][-A-Za-z0-9_]*;

whitespace [[blank:]]+
newline    \n
%START OUTSIDE IN_COMMENT IN_ENTITY NAMED_ENTITY IN_QUOTE ENTITY_DONE XMLPI
%%


{entity}						if (current) g_string_sprintfa(current,"%s\n%s\n",replace_entity(yytext),location());

{whitespace}					if (current) g_string_append(current," ");

<OUTSIDE>{xmlpi_start}			{ g_string_append(current,yytext); BEGIN XMLPI; }
<XMLPI>{xmlpi_chars}			{ g_string_append(current,yytext); }
<XMLPI>{newline}				{ g_string_append(current,yytext); }
<XMLPI>{xmlpi_stop}				{ g_string_append(current,yytext); BEGIN OUTSIDE; }

<OUTSIDE>{comment_start}		{ current = NULL; BEGIN IN_COMMENT; }
<IN_COMMENT>[^-]?				|
<IN_COMMENT>[-]					;
<IN_COMMENT>{comment_stop}		{ current = output; BEGIN OUTSIDE; }
	
{newline}						{
	linenum++;
	if (current) g_string_sprintfa(current,"%s\n",location());
}


<OUTSIDE>{entity_start}			{ BEGIN IN_ENTITY; }
<IN_ENTITY>{name}				{ entity_name = g_strdup_printf("%%%s;",yytext); BEGIN NAMED_ENTITY; }
<NAMED_ENTITY>{quote}			{ current = g_string_new(location()); BEGIN IN_QUOTE; }
<IN_QUOTE>{quote}				{ g_hash_table_insert(entities,entity_name,current);  BEGIN ENTITY_DONE; }
<IN_QUOTE>{percent}				|
<IN_QUOTE>{non_quote}			|
<IN_QUOTE>{escaped_quote}		g_string_append(current,yytext);
<NAMED_ENTITY>{system}			{
    g_string_sprintfa(error,"at %s:%u: file inclusion is not supported!", filename, linenum);
    yyterminate();
}
<ENTITY_DONE>{special_stop}		{ current = output; g_string_append(current,"\n"); BEGIN OUTSIDE; }

%%

static gchar* replace_entity(gchar* entity) {
	GString* replacement;
	
	*entity = '%';
	
	replacement = g_hash_table_lookup(entities,entity);
	
	if (replacement) {
		return replacement->str;
	} else {
		g_string_sprintfa(error,"dtd_preparse: in file '%s': entity %s does not exists\n", filename, entity);
		return "";
	}
	
}

static const gchar* location(void) {
	static GString* loc = NULL;
	guint i = include_stack_ptr + 1;
	
	if (loc) {
		g_string_truncate(loc,0);
	} else {
		loc = g_string_new("");
	}

	g_string_sprintfa(loc,"<? ethereal:location ");

	while (i--) {
			g_string_sprintfa(loc, "%s:%u from",
							  filename,
							  linenum);			
	}

	g_string_truncate(loc,(loc->len) - 4);
	
	g_string_sprintfa(loc,"?>");
	
	return loc->str;
}

static gboolean free_gstring_hash_items(gpointer k,gpointer v,gpointer p _U_) {
	g_free(k);
	g_string_free(v,TRUE);
	return TRUE;
}

extern GString* dtd_preparse(const gchar* dname,const  gchar* fname, GString* err) {
	gchar* fullname = g_strdup_printf("%s%c%s",dname,G_DIR_SEPARATOR,fname);

	dirname = dname;
	filename = fname;

	yyin = fopen(fullname,"r");
	
	g_free(fullname);
	
	if (!yyin) {
		if (err)
			g_string_sprintfa(err, "Could not open file: '%s', error: %s",filename,strerror(errno));
			
		return NULL;
	}
	
	filename = filename;
	linenum = 1;
	
	error = err;
	
	entities = g_hash_table_new(g_str_hash,g_str_equal);
	current = output = g_string_new(location());
	
	BEGIN OUTSIDE;

	yylex();
		
	yyrestart(NULL);

	g_hash_table_foreach_remove(entities,free_gstring_hash_items,NULL);
	g_hash_table_destroy(entities);

	return output;
}
