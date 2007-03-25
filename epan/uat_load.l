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

	static char* unbinstring(const char* si, guint in_len, guint* len_p);
	static char* undquote(const char* si, guint in_len, guint* len_p);
	
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
	ptr = undquote(yytext,yyleng,&len);
	
	
	if (colnum < uat->ncols - 1) {
		DUMP("quoted_str->s");
		BEGIN SEPARATOR;
	} else {
		DUMP("quoted_str->eor");
		BEGIN END_OF_RECORD;
	}
}

<START_OF_LINE,NEXT_FIELD>{binstring} {
	ptr = unbinstring(yytext,yyleng,&len);

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

static int xton(char d) {
	switch(d) {
		case '0': return 0;
		case '1': return 1; 
		case '2': return 2;
		case '3': return 3;
		case '4': return 4;
		case '5': return 5;
		case '6': return 6;
		case '7': return 7;
		case '8': return 8;
		case '9': return 9;
		case 'a':  case 'A': return 10;
		case 'b':  case 'B': return 11;
		case 'c':  case 'C': return 12;
		case 'd':  case 'D': return 13;
		case 'e':  case 'E': return 14;
		case 'f':  case 'F': return 15;
		default: return -1;
	}
}

static char* unbinstring(const char* si, guint in_len, guint* len_p) {
	guint8* buf;
	guint len = in_len/2;
	int i = 0;
	
	if (in_len%2) {
		return NULL;
	}
	
	buf= g_malloc(len);
	*len_p = len;

	while(in_len) {
		int d1 = xton(*(si++));
		int d0 = xton(*(si++));
		
		buf[i++] = (d1 * 16) + d0;
		
		in_len -= 2;
	}
	
	return (void*)buf;
}

static char* undquote(const char* si, guint in_len, guint* len_p) {
	char* buf = g_malloc(in_len); /* wastes one byte for every '\\' in text */
	char* p = buf;
	guint len = 0;
	char* end = buf+in_len;
	const guint8* s = (void*)si;
	
	for (s++; p < end; s++) {
		switch(*s) {
			case '\0':
				*(p-1) = '\0';
				goto done;
			case '\\':
				switch(*(++s)) {
					case 'a': *(p++) = '\a'; len++; break;
					case 'b': *(p++) = '\b'; len++; break;
					case 'e': *(p++) = '\033' /* '\e' is non ANSI-C */; len++; break;
					case 'f': *(p++) = '\f'; len++; break;
					case 'n': *(p++) = '\n'; len++; break;
					case 'r': *(p++) = '\r'; len++; break;
					case 't': *(p++) = '\t'; len++; break;
					case 'v': *(p++) = '\v'; len++; break;
						
					case '0':
					case '1': 
					case '2': 
					case '3': 
					case '4': 
					case '5': 
					case '6': 
					case '7': 
					{
						int c0 = 0;
						int c1 = 0;
						int c2 = 0;
						int c = 0;
						
						c0 = (*s) - '0';
						
						if ( s[1] >= '0' && s[1] <= '7' ) {
							c1 = c0;
							c0 = (*++s) - '0';
							
							if ( s[1] >= '0' && s[1] <= '7' ) {
								c2 = c1;
								c1 = c0;
								c0 = (*++s) - '0';
							}
						}
						c = (64 * c2) + (8 * c1) + c0;
						*(p++) = (char) (c > 255 ? 255 : c);
						len++;
						break;
					}
						
					case 'x':
					{
						char c1 = *(s+1);
						char c0 = *(s+2);
												
						if (isxdigit(c1) && isxdigit(c0)) {
							*(p++) = (xton(c1) * 0x10) + xton(c0);
							s += 2;
						} else {
							*(p++) = *s;
						}
						len++;
						break;
					}
					default:
						*p++ = *s;
						break;
				}
				break;
			default:
				*(p++) = *s;
				len++;
				break;
		}
	}
	
done:
		
	while ( p < end ) *(p++) = '\0';
	buf[len] = '\0';
	len--;
	if (len_p) *len_p = len;
	return buf;
}

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
