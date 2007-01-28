%option noyywrap
%option nounput
%option prefix="uat_load_"
%option never-interactive

%{
	/*
	 * one parser to fit them all
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
	static uat_fld_t* uat_fld;
	static gchar* ptr;
	static guint len;
	static gchar* error;
	static void* record;
	
	static char* unbinstring(const char* si, guint in_len, guint* len_p);
	static char* undquote(const char* si, guint in_len, guint* len_p);
	
#define ERROR(txt) do { error = txt; yyterminate(); } while(0)

#define SET_FIELD() \
	{ gchar* err; \
	if (uat_fld->chk_cb) { \
		if ( ! uat_fld->chk_cb(record, ptr, len, &err) ) { \
			ERROR(err); \
		}\
	}\
	uat_fld->set_cb(record, ptr, len);\
	g_free(ptr);\
	} while(0)


%}

quoted_string \042([^\042]|\134\042)*\042
binstring ([0-9a-zA-Z][0-9a-zA-Z])+
separator ,
newline [ \t]*[\r]?\n

%x START_OF_LINE NEXT_FIELD SEPARATOR END_OF_RECORD
%%

<START_OF_LINE,NEXT_FIELD>{quoted_string} {
	ptr = undquote(yytext,yyleng,&len);
		
	if (( uat_fld = uat_fld->next )) {
		BEGIN SEPARATOR;
	} else {
		BEGIN END_OF_RECORD;
	}
}

<START_OF_LINE,NEXT_FIELD>{binstring} {
	ptr = unbinstring(yytext,yyleng,&len);
	
	if (!ptr) {
		ERROR("uneven hexstring");
	}
	
	if (( uat_fld = uat_fld->next )) {
		BEGIN SEPARATOR;
	} else {
		BEGIN END_OF_RECORD;
	}
}

<SEPARATOR>{separator} {
	SET_FIELD();
	uat_fld = uat_fld->next;
	if (! uat_fld ) {
		ERROR("more fields than required");
	}
}

<END_OF_RECORD>{newline} {
	void* rec;
	gchar* err = NULL;
	
	SET_FIELD();
	
	rec = uat_add_record(uat, record);
	
	if (uat->update_cb)
		uat->update_cb(rec,&err);
	
	if (err) {
		ERROR(err);
	}
	
	uat_fld = uat->fields;
	ptr = NULL;
	len = 0;
	memset(record,0,uat->record_size);
	
	BEGIN START_OF_LINE;
 }

{newline} { ERROR("incomplete record"); }
. { ERROR("unexpected input"); }
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
	char* buf;
	guint len = in_len/2;
	int i = 0;
	
	if (in_len%2) {
		return NULL;
	}
	
	buf= g_malloc(len); /* wastes one byte for every '\\' in text */
	*len_p = len;

	while(in_len) {
		int d1 = xton(*(si++));
		int d0 = xton(*(si++));
		
		buf[i++] = (d1 * 16) + d0;
		
		in_len -= 2;
	}
	
	return buf;
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
					case 'e': *(p++) = '\e'; len++; break;
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

gboolean uat_load(uat_t* dt_in, char** err) {
	gchar* fname = uat_get_actual_filename(uat, FALSE);
	
	g_assert(uat->finalized && uat->locked);
	
	uat = dt_in;
	
	;
	if (!(yyin = fopen(fname,"r"))) {
		*err = strerror(errno);
		return FALSE;
	}
	
	error = NULL;
	uat_fld = uat->fields;
	record = g_malloc0(uat->record_size);
	
	BEGIN START_OF_LINE;
	
	yylex();
	
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
