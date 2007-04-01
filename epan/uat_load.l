%option noyywrap
%option prefix="uat_load_"
%option never-interactive
%option nounput

%{
	/*
	 * uat_load.l
	 *
	 * $Id$
	 *
	 *  User Accessible Tables
	 *  Mantain an array of user accessible data strucures
	 *  One parser to fit them all
	 *
	 * (c) 2007, Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
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
# include "config.h"
#endif
	
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
	
#include <glib.h>

#include <epan/emem.h>
#include "uat-int.h"
	
	static uat_t* uat;
	static guint colnum;
	static gchar* ptr;
	static guint len;
	static gchar* error;
	static void* record;
	static guint linenum;

#define ERROR(fmtd) do { error = ep_strdup_printf("%s:%d: %s",uat->filename,linenum,ep_strdup_printf fmtd); yyterminate(); } while(0)

#define SET_FIELD() \
	{ gchar* err; \
	if (uat->fields[colnum].cb.chk) { \
		if ( ! uat->fields[colnum].cb.chk(record, ptr, len, uat->fields[colnum].cbdata.chk, uat->fields[colnum].fld_data, &err) ) { \
			ERROR(("%s",err)); \
		}\
	}\
	uat->fields[colnum].cb.set(record, ptr, len, uat->fields[colnum].cbdata.chk, uat->fields[colnum].fld_data);\
	g_free(ptr);\
		colnum++; \
	} while(0)

#ifdef DEBUG_UAT_LOAD
#define DUMP_FIELD(str) \
		{ guint i; printf("%s: %s='",str,uat->fields[colnum].name); for(i=0;i<len;i++) if (uat->fields[colnum].mode == PT_TXTMOD_HEXBYTES) { printf("%.2x ",((guint8*)ptr)[i]); } else putc(ptr[i],stdout); printf("'[%d]\n",len); }

#define DUMP(str) printf("%s\n",str)
#else
#define DUMP_FIELD(s)
#define DUMP(s)
#endif
		/*
		 * XXX
		 * quoted_string below fails badly on "...\\"
		 * workarround in uat_save(), using /x5c and /x22
		 */
%}

quoted_string \042([^\042]|\134\134|\134\042)*\042
binstring ([0-9a-zA-Z][0-9a-zA-Z])*
separator [ \t]*,
newline [ \t]*[\r]?\n
ws [ \t]+
comment #[^\n]*\n

%x START_OF_LINE NEXT_FIELD SEPARATOR END_OF_RECORD ERRORED
%%
<START_OF_LINE,NEXT_FIELD>{ws} ;
<START_OF_LINE>{newline} linenum++;
<START_OF_LINE>{comment} ;

<START_OF_LINE,NEXT_FIELD>{separator} {
	ptr = g_strdup("");
	len = 0;
	
	DUMP_FIELD("empty->next");
	
	SET_FIELD();
	
	if ( colnum >= uat->ncols ) {
		ERROR(("more fields than required"));
	}
	
	BEGIN NEXT_FIELD;
}

<START_OF_LINE,NEXT_FIELD>{newline}   {
	ptr = "";
	len = 0;
	
	BEGIN END_OF_RECORD;

	yyless(yyleng);
}

<START_OF_LINE,NEXT_FIELD>{quoted_string} {
	ptr = uat_undquote(yytext,yyleng,&len);
	
	
	if (colnum < uat->ncols - 1) {
		DUMP("quoted_str->s");
		BEGIN SEPARATOR;
	} else {
		DUMP("quoted_str->eor");
		BEGIN END_OF_RECORD;
	}
}

<START_OF_LINE,NEXT_FIELD>{binstring} {
	ptr = uat_unbinstring(yytext,yyleng,&len);

	if (!ptr) {
		ERROR(("uneven hexstring for field %s",uat->fields[colnum].name));
	}
	
	if ( colnum < uat->ncols - 1 ) {
		DUMP("binstring->s");
		BEGIN SEPARATOR;
	} else {
		DUMP("binstring->eor");
		BEGIN END_OF_RECORD;
	}
}

<SEPARATOR>{separator} {
	
	DUMP_FIELD("separator->next");

	SET_FIELD();

	if ( colnum >= uat->ncols ) {
		ERROR(("more fields than required"));
	}
	
	BEGIN NEXT_FIELD;
}

<SEPARATOR>{newline} {
	linenum++;
	ERROR(("expecting field %s in previuos line",uat->fields[colnum].name));
	BEGIN START_OF_LINE;
}

<SEPARATOR>. {
	ERROR(("unexpected char '%s' while looking for field %s",yytext,uat->fields[colnum].name));
	BEGIN ERRORED;
}

<END_OF_RECORD>{separator} {
	ERROR(("more fields than required"));
	BEGIN ERRORED;
}

<END_OF_RECORD>{newline} {
	void* rec;
	gchar* err = NULL;
	
	linenum++;

	DUMP_FIELD("newline->start");

	SET_FIELD();
	
	rec = uat_add_record(uat, record);

	if (uat->update_cb)
		uat->update_cb(rec,&err);
	
	if (err) {
		ERROR(("%s",err));
	}
	
	colnum = 0;;
	ptr = NULL;
	len = 0;
	memset(record,0,uat->record_size);
	
	BEGIN START_OF_LINE;
 }

<END_OF_RECORD>. {
	ERROR(("unexpected char while looking for end of line"));
	BEGIN ERRORED;
}

<ERRORED>{newline} { linenum++; BEGIN START_OF_LINE; }
<ERRORED>. ;

{newline} { linenum++; ERROR(("incomplete record")); BEGIN START_OF_LINE; }
. { ERROR(("unexpected input")); }

%%




gboolean uat_load(uat_t* uat_in, char** err) {
	gchar* fname = uat_get_actual_filename(uat_in, FALSE);

	uat = uat_in;

	if (!fname) {
		UAT_UPDATE(uat);
		return TRUE;
	}
	

	if (!(yyin = fopen(fname,"r"))) {
		*err = strerror(errno);
		return FALSE;
	}
	
	error = NULL;
	colnum = 0;
	record = g_malloc0(uat->record_size);
	linenum = 1;
	
	BEGIN START_OF_LINE;
	DUMP(fname);
	
	yylex();
	yyrestart(NULL);

	uat->changed = FALSE;

	if (error) {
		UAT_UPDATE(uat);
		*err = ep_strdup(error);
		return FALSE;
	} else {
		UAT_UPDATE(uat);		
		*err = NULL;
		return TRUE;
	}
}
