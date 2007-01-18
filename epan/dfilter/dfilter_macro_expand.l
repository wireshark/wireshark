%option noyywrap
%option never-interactive
%option prefix="dfmacro_expand_"
%option outfile="dfilter_macro_expand.c"
%option nounput
%{
/* dfilter_macro_expand.l
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
#include "dfilter-macro.h"
#include <epan/emem.h>

	static int include_stack_ptr = 0;

#define MAX_MACRO_DEPTH 32

	static struct _macro_frame {
		char* macro_name;
		GString* macro_arg;
		GPtrArray* macro_args;
		YY_BUFFER_STATE buffer_state;
	} macro_stack[MAX_MACRO_DEPTH];
		
#define MACRO_FRAME macro_stack[include_stack_ptr]

#define MACRO_ARG_APPEND(t) \
	g_string_append(MACRO_FRAME.macro_arg,(t));

#define MACRO_END_ARG()	\
	g_ptr_array_add(MACRO_FRAME.macro_args,MACRO_FRAME.macro_arg->str); \
	if (MACRO_FRAME.macro_arg) g_string_free(MACRO_FRAME.macro_arg, FALSE); \
	MACRO_FRAME.macro_arg = g_string_new("");

#define MACRO_CLEAN_ALL() { \
	int s = include_stack_ptr; \
	for (include_stack_ptr = 0; include_stack_ptr < MAX_MACRO_DEPTH; include_stack_ptr++) { MACRO_CLEAN_FRAME(); } \
	include_stack_ptr = s; }

#define MACRO_CLEAN_FRAME() dfmacro_clean_frame(&(macro_stack[include_stack_ptr]))

	static void dfmacro_clean_frame(struct _macro_frame* f);

#define DEBUG_EXPAN_LEX__
#ifndef DEBUG_EXPAN_LEX
#define DS(id,var) 
#else
#define DS(id,var) printf(#id " "  #var "=%s\n",var)
#endif
	
	static GString* output;
	static gchar* error_msg;
	
#define APPEND_OUT(txt) g_string_append(output,txt)
	
	static void dfm_error(char* fmt, ...);
	
#define ERROR(args) dfm_error args ; MACRO_CLEAN_ALL(); yyterminate()

%}

esc_macro "\\$"
macro_intro "${"
macro_name [a-zA-Z][-_[:alnum:]]*
macro_argstart ":"
macro_argbody [^;}\\]*
macro_argbodyesc \\.
macro_argsep ;
macro_stop "}"

%x MACRO_START
%x MACRO_NAME
%x MACRO_ARG

%%

{macro_intro} {
	DS("{macro_intro}",yytext);
	MACRO_CLEAN_FRAME();
	BEGIN(MACRO_NAME);
}

<MACRO_START,MACRO_NAME,MACRO_ARG><<EOF>> {
	DS("<MACRO_NAME><<EOF>>",yytext);
	ERROR(("found end of filter before end of macro"));
}

<MACRO_NAME>{macro_name} {
	DS("<MACRO_NAME>{macro_name}",yytext);
	MACRO_FRAME.macro_name = g_strdup(yytext);
	BEGIN(MACRO_START);
}


<MACRO_START>{macro_stop} {
	DS("<MACRO_START>{macro_stop}",yytext);
	gchar* resolved_macro;
	gchar** args[] = { NULL };
	gchar* macro_error;
	
	resolved_macro = dfilter_macro_resolve(MACRO_FRAME.macro_name,
										   args,
										   &macro_error);
	
	g_free(MACRO_FRAME.macro_name);
	MACRO_FRAME.macro_name = NULL;
	
	if (!resolved_macro) {
		ERROR(("%s",macro_error));
	}
	
	BEGIN(INITIAL);
	
	if ( include_stack_ptr >= MAX_MACRO_DEPTH ) {
		ERROR(("macro buffers nested to deeply"));
	}
	
	/* push a new buffer */
	MACRO_FRAME.buffer_state = YY_CURRENT_BUFFER;
	
	/* set the pointer to scan the new buffer */
	include_stack_ptr++;

	yy_scan_string(resolved_macro);	
}

<MACRO_START>{macro_argstart} {
	DS("<MACRO_START>{macro_argstart}",yytext);
	if (MACRO_FRAME.macro_arg) {
		g_string_free(MACRO_FRAME.macro_arg,TRUE);
	}
	if (MACRO_FRAME.macro_args) {
		while(MACRO_FRAME.macro_args->len) g_ptr_array_remove_index_fast(MACRO_FRAME.macro_args,0);
		g_ptr_array_free(MACRO_FRAME.macro_args,TRUE);
	}
	MACRO_FRAME.macro_arg = g_string_new("");
	MACRO_FRAME.macro_args = g_ptr_array_new();
	BEGIN(MACRO_ARG);
}

<MACRO_ARG>{macro_argbody} {
	DS("<MACRO_ARG>{macro_argbody}",yytext);
	MACRO_ARG_APPEND(yytext);
}

<MACRO_ARG>{macro_argbodyesc} {
	DS("<MACRO_ARG>{macro_argbody}",yytext);
	MACRO_ARG_APPEND(yytext+1);
}

<MACRO_ARG>{macro_argsep} {
	DS("<MACRO_ARG>{macro_argsep}",yytext);
	MACRO_END_ARG();
}

<MACRO_ARG>{macro_stop} {
	gchar* resolved_macro;
	gchar* macro_error;
	gchar**  args = NULL;

	DS("<MACRO_ARG>{macro_stop}",yytext);
	MACRO_END_ARG();

	if(MACRO_FRAME.macro_args) {
		g_ptr_array_add(MACRO_FRAME.macro_args,NULL);
		args = (gchar**)MACRO_FRAME.macro_args->pdata;
	}
	
	resolved_macro = dfilter_macro_resolve(MACRO_FRAME.macro_name,
										   args,
										   &macro_error);
	
	while(MACRO_FRAME.macro_args->len) g_ptr_array_remove_index_fast(MACRO_FRAME.macro_args,0);
	g_ptr_array_free(MACRO_FRAME.macro_args,TRUE);
	MACRO_FRAME.macro_args = NULL;
	
	g_free(MACRO_FRAME.macro_name);
	MACRO_FRAME.macro_name = NULL;

	g_string_free(MACRO_FRAME.macro_arg,TRUE);
	MACRO_FRAME.macro_arg = NULL;
	
	if (!resolved_macro) {
		ERROR(("%s",macro_error));
	}
	
	BEGIN(INITIAL);
	
	if ( include_stack_ptr >= MAX_MACRO_DEPTH ) {
		ERROR(("macro buffers nested to deeply"));
	}
	
	/* push a new buffer */
	macro_stack[include_stack_ptr].buffer_state = YY_CURRENT_BUFFER;
	
	/* set the pointer to scan the new buffer */
	include_stack_ptr++;

	yy_scan_string(resolved_macro);	
}

<MACRO_START>. {
	gchar* resolved_macro;
	gchar* macro_error;
	gchar**  args = NULL;
	
	DS("<MACRO_START>",yytext);
	BEGIN(INITIAL);
	
	
	if(MACRO_FRAME.macro_args) {
		g_ptr_array_add(MACRO_FRAME.macro_args,NULL);
		args = (gchar**)MACRO_FRAME.macro_args->pdata;
	}
	
	resolved_macro = dfilter_macro_resolve(MACRO_FRAME.macro_name,
										   args,
										   &macro_error);
	
	while(MACRO_FRAME.macro_args->len) g_ptr_array_remove_index_fast(MACRO_FRAME.macro_args,0);
	g_ptr_array_free(MACRO_FRAME.macro_args,TRUE);
	MACRO_FRAME.macro_args = NULL;
	
	g_free(MACRO_FRAME.macro_name);
	MACRO_FRAME.macro_name = NULL;
	
	g_string_free(MACRO_FRAME.macro_arg,TRUE);
	MACRO_FRAME.macro_arg = NULL;
	
	
	if (!resolved_macro) {
		ERROR(("%s",macro_error));
	}
		
	if ( include_stack_ptr >= MAX_MACRO_DEPTH ) {
		ERROR(("macro buffers nested to deeply"));
	}
	
	yyless(1); /* return the one char back to the current buffer */
	
	/* push a new buffer */
	macro_stack[include_stack_ptr].buffer_state = YY_CURRENT_BUFFER;
	
	/* set the pointer to scan the new buffer */
	include_stack_ptr++;
	
	yy_scan_string(resolved_macro);
}

<<EOF>> {
	DS("<<EOF>>",yytext);
	if ( include_stack_ptr <= 0 ) {
		yyterminate();
	} else {
		dfmacro_clean_frame(&(MACRO_FRAME));
		yy_delete_buffer( YY_CURRENT_BUFFER );
		yy_switch_to_buffer(macro_stack[--include_stack_ptr].buffer_state);
	}
}

esc_macro {
	/* Default */
	APPEND_OUT("$");
}

. {
	/* Default */
	APPEND_OUT(yytext);
}


%%

static void dfm_error(char* fmt, ...) {
	va_list	args;

	va_start(args, fmt);
	
	error_msg = ep_strdup_vprintf(fmt, args);

	va_end(args);
	
}

static void dfmacro_clean_frame(struct _macro_frame* f) {
	if (f->macro_name) {
		g_free(f->macro_name);
		f->macro_name = NULL;
	}
	
	if (f->macro_args) {
		while(f->macro_args->len) g_ptr_array_remove_index_fast(f->macro_args,0);
		g_ptr_array_free(f->macro_args,TRUE);
		f->macro_args = NULL;
	}
	
	if (f->macro_arg) {
		g_string_free(f->macro_arg,TRUE);
		f->macro_arg = NULL;
	}	
}

gchar* dfilter_macro_expand(const char *text, gchar** error) {
	gchar* out;
	/* cleanup leftovers of last failed scan (if any) */

	for (include_stack_ptr = 0; include_stack_ptr < MAX_MACRO_DEPTH; include_stack_ptr++) {
		MACRO_CLEAN_FRAME();
	}
	
	if (output) {
		g_string_free(output,TRUE);
		output = NULL;
	}
	
	output = g_string_sized_new(64);
	
	error_msg = NULL;
	include_stack_ptr = 0;
	BEGIN(INITIAL);
	
	macro_stack[include_stack_ptr].buffer_state = yy_scan_string(text);
	
	yylex();
	
	if (error_msg) {
		*error = error_msg;
		g_string_free(output,TRUE);
		output = NULL;
		out =  NULL;
	} else {	
		*error = NULL;
		out = output->str;	
		g_string_free(output,FALSE);
		output = NULL;
	}
	
	return out;
}

void dfilter_macro_cleannup(void) {
	int i;
		
	for (i = 0; i < MAX_MACRO_DEPTH; i++) {
		dfmacro_clean_frame(&(macro_stack[i]));
	}
	
	include_stack_ptr = 0;
	BEGIN(INITIAL);

}
