%option never-interactive
%option prefix="dfml_"
%option outfile="dfilter_macro_load.c"
%option nounput
%option noyywrap
%{
/* dfilter_macro_load.l
 *
 * $Id: dfilter_macro_expand.l 18197 2006-05-21 05:12:17Z sahlberg $
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
	
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "dfilter-int.h"
#include "dfilter.h"
#include "dfilter-macro.h"
#include <epan/emem.h>
#include <epan/filesystem.h>
	
	static char* macro_name;
	static char* macro_body;
	static gchar* err;
	static const gchar* fname;
	static int linenum;
	
%}
name [a-zA-Z][-_[:alnum:]]*
colon ":"
body [^\r\n]+
nl [\r]?\n
ws [:blank:]+

%START GET_NAME GET_COLON GET_BODY GET_NL
%%
<GET_NAME>[:blank:]*[\r]?\n ; /* ignore empty lines*/

<GET_NAME>{name}	{ macro_name = ep_strdup(yytext); BEGIN GET_COLON; }
<GET_NAME>{ws}		;
<GET_NAME>.			{ 
	err = ep_strdup_printf("%s:%d: unexpected char at: '%s'", fname, linenum, yytext);
	yyterminate();
}

<GET_COLON>{colon}	{ BEGIN GET_BODY; };
<GET_COLON>{ws}		;
<GET_COLON>.		{ 
	err = ep_strdup_printf("%s:%d: unexpected char at: '%s'", fname, linenum, yytext);
	yyterminate();
}

<GET_BODY>{body}	{ macro_body = ep_strdup(yytext); BEGIN GET_NL; }
<GET_BODY>{nl}		{ 
	err = ep_strdup_printf("%s:%d: empty body", fname, linenum);
	yyterminate();
}

<GET_NL>{nl}		{
	dfilter_macro_add(macro_name, macro_body, &err);
	if (err) yyterminate();
	BEGIN GET_NAME;
}
<GET_NL><<EOF>>		{
	dfilter_macro_add(macro_name, macro_body, &err);
	if (err) yyterminate();
	return 1;
}

%%

gboolean dfilter_macro_load(gchar** error) {

	linenum = 1;
	macro_name = NULL;
	macro_body = NULL;
	err = NULL;
	*error = NULL;

	fname = get_persconffile_path(DFILTER_MACRO_FILENAME,FALSE);
	
	yyin = fopen(fname,"r");

	if (!yyin) {
		if(errno != ENOENT) {		
			*error = ep_strdup_printf("Could not open file: '%s', error: %s\n", fname, strerror(errno));
			return FALSE;
		}

		fname = get_datafile_path(DFILTER_MACRO_FILENAME);

		yyin = fopen(fname,"r");
		
		if (!yyin) {
			if(errno != ENOENT) {		
				*error = ep_strdup_printf("Could not open file: '%s', error: %s\n", fname, strerror(errno));
				return FALSE;
			} else {
				return TRUE;
			}
		}			
	}

	BEGIN GET_NAME;

	yylex();

	if (err) {
		*error = err;
		return FALSE;
	}
	
	return TRUE;
}
