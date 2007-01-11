%option noyywrap
%option nounput
%option prefix="Snmp_UE_file_"
%option never-interactive
%option caseless

%{
	/*
	 * load_snmp_users_file.l
	 *
	 * User-based Security Model for SNMPv3
	 * SNMP user-engine association file parser 
	 *
	 * Copyright 2007, Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
	 *
	 * $Id$
	 *
	 * Wireshark - Network traffic analyzer
	 * By Gerald Combs <gerald@wireshark.org>
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
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
	
	
#include <glib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>


#include <epan/tvbuff.h>
#include <epan/proto.h>
#include <epan/packet_info.h>
#include <epan/emem.h>
	
#include <epan/dissectors/packet-snmp.h>
	
#define AUTH_MD5 1
#define AUTH_SHA 2
#define PRIV_DES 4
#define PRIV_AES 5

	static GString* error;
	static GArray* assoc_arr = NULL;
	
	static guint8* engine = NULL;
	static guint engine_len = 0; 
	static guint8* user = NULL;
	static guint user_len = 0; 
	static guint8* auth_password = NULL;
	static guint auth_password_len = 0; 
	static guint8* priv_password = NULL;
	static guint priv_password_len = 0; 
	static int auth = AUTH_MD5;
	static int enc = PRIV_DES;
	static guint linenum = 0;
	static const gchar* filename = "";
	static guint loaded = 0;
	
	static void add_engine(void);
	static guint8* unhexbytes(const char* s, guint len, guint* len_p);
	static guint8* undquote(const char* s, guint in_len, guint* len_p);
	
	static snmp_usm_auth_model_t model_md5 = {snmp_usm_password_to_key_md5, snmp_usm_auth_md5, 16};
	static snmp_usm_auth_model_t model_sha1 = {snmp_usm_password_to_key_sha1, snmp_usm_auth_sha1, 20};
	
#define ERR(str) 
#define START_LINE() { \
		linenum++; \
		engine = NULL;\
		engine_len = 0;\
		user = NULL;\
		user_len = 0;\
		auth_password = NULL;\
		auth_password_len = 0;\
		priv_password = NULL;\
		priv_password_len = 0;\
		auth = AUTH_MD5;\
		enc = PRIV_DES;\
		BEGIN START_ENGINE;\
	}

%}

hex_bytes [0-9A-Fa-f]+
quoted_string \042([^\042]|\134\042)*\042
any_engine \052
whitespace [ \t]+
newline [\r]?\n
dash -
des [dD][Ee][Ss]
aes [aA][Ee][Ss]
md5 [mM][dD]5
sha [sS][hH][aA][1]?
comment [ \t]*\043[^\n]*\n

%START START_ENGINE STOP_ENGINE
%START START_USER STOP_USER
%START START_AUTHPASSWORD STOP_AUTHPASSWORD
%START START_PRIVPASSWORD STOP_PRIVPASSWORD
%START ATTRIBUTES
%START ERRORED
%%

<ERRORED>. ;
<ERRORED>{newline} { START_LINE(); }

<START_ENGINE>{newline}	{ START_LINE(); }
<START_ENGINE>{comment} { START_LINE(); }

<START_ENGINE>{quoted_string} { engine = undquote(yytext, yyleng, &engine_len); BEGIN STOP_ENGINE; }
<START_ENGINE>{hex_bytes} { engine = unhexbytes(yytext, yyleng, &engine_len); BEGIN STOP_ENGINE; }
<START_ENGINE>{any_engine} { engine =  NULL; engine_len = 0; BEGIN STOP_ENGINE; }
<START_ENGINE>. { ERR("Invalid engineId"); }

<STOP_ENGINE>{whitespace} { BEGIN START_USER; }

<START_USER>{quoted_string} { user = undquote(yytext, yyleng,&user_len); BEGIN STOP_USER; }
<START_USER>{hex_bytes} { user = unhexbytes(yytext, yyleng, &user_len); BEGIN STOP_USER; }
<START_USER>. { ERR("Invalid userName"); }

<STOP_USER>{whitespace} { BEGIN START_AUTHPASSWORD; }

<START_AUTHPASSWORD>{quoted_string} { auth_password = undquote(yytext, yyleng, &auth_password_len); BEGIN STOP_AUTHPASSWORD; }
<START_AUTHPASSWORD>{hex_bytes} { auth_password = unhexbytes(yytext, yyleng, &auth_password_len); BEGIN STOP_AUTHPASSWORD; }
<START_AUTHPASSWORD>. { ERR("Invalid authPassword"); }

<STOP_AUTHPASSWORD>{whitespace} { BEGIN START_PRIVPASSWORD; }

<START_PRIVPASSWORD>{quoted_string} { priv_password = undquote(yytext, yyleng, &priv_password_len); BEGIN STOP_PRIVPASSWORD; }
<START_PRIVPASSWORD>{hex_bytes} { priv_password = unhexbytes(yytext, yyleng, &priv_password_len); BEGIN STOP_PRIVPASSWORD; }
<START_PRIVPASSWORD>. { ERR("Invalid privPassword"); }

<STOP_PRIVPASSWORD>{whitespace} { BEGIN ATTRIBUTES; }
<STOP_PRIVPASSWORD>{newline} { add_engine(); START_LINE(); }

<ATTRIBUTES>{whitespace} ;
<ATTRIBUTES>{md5} { auth = AUTH_MD5; }
<ATTRIBUTES>{sha} { auth = AUTH_SHA; }
<ATTRIBUTES>{des} { enc = PRIV_DES; }
<ATTRIBUTES>{aes} { enc = PRIV_AES; }
<ATTRIBUTES>{newline} { add_engine(); START_LINE(); }
<ATTRIBUTES>. { ERR("Invalid char in attributes"); }

%%

static guint8* unhexbytes(const char* si, guint len, guint* len_p) {
	guint8* buf;
	guint8* p;
	const guint8* s = (void*)si;
	unsigned i;
	
	if (len % 2) {
		ERR("Uneven number of chars hex string");
		return NULL;
	}
	
	buf = g_malloc(len);
	p = buf;
	
	for (i = 0; i<len ; i += 2) {
		guint8 lo = s[i+1];
		guint8 hi = s[i];
		
		if (hi >= '0' && hi <= '9') {
			hi -= '0';
		} else if (hi >= 'a' && hi <= 'f') {
			hi -=  'a';
			hi += 0xa;
		} else if (hi >= 'A' && hi <= 'F') {
			hi -=  'A';
			hi += 0xa;
		} else {
			goto on_error;
		}
		
		if (lo >= '0' && lo <= '9') {
			lo -= '0';
		} else if (lo >= 'a' && lo <= 'f') {
			lo -=  'a';
			lo += 0xa;
		} else if (lo >= 'A' && lo <= 'F') {
			lo -=  'A';
			lo += 0xa;
		} else {
			goto on_error;
		}
		
		*(p++) = (hi*0x10) + lo;
	}
	
	len /= 2;

	if (len_p) *len_p = len;
	
	return buf;

on_error:
	ERR("Error parsing hex string");
	g_free(buf);
	return NULL;
}

static guint8* undquote(const char* si, guint in_len, guint* len_p) {
	guint8* buf = g_malloc(in_len); /* wastes one byte for every '\\' in text */
	guint8* p = buf;
	guint len = 0;
	guint8* end = buf+in_len;
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
					default:
						*p++ = *s;
						len++;
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



static void add_engine(void) {
	snmp_ue_assoc_t a;
	


	a.user.userName.data = user;
	a.user.userName.len = user_len;
	
	a.user.authPassword.data = auth_password;
	a.user.authPassword.len = auth_password_len;

	a.user.privPassword.data = priv_password;
	a.user.privPassword.len = priv_password_len;
	
	switch (auth) {
		case AUTH_MD5:
			a.user.authModel = &model_md5;
			break;
		case AUTH_SHA:
			a.user.authModel = &model_sha1;
			break;
		default:
			g_assert_not_reached();
			break;
	}
	
	switch(enc) {
		case PRIV_DES:
			a.user.privProtocol = snmp_usm_priv_des;
			break;
		case PRIV_AES:
			a.user.privProtocol = snmp_usm_priv_aes;
			break;
		default:
			g_assert_not_reached();
			break;
	}

	if (engine) {
			a.engine.data = engine;
			a.engine.len = engine_len;
			
			if (a.user.authModel) {
				a.user.authKey.data = g_malloc(a.user.authModel->key_size);
				a.user.authKey.len = a.user.authModel->key_size;
				a.user.privKey.data = g_malloc(a.user.authModel->key_size);
				a.user.privKey.len = a.user.authModel->key_size;
				a.user.authModel->pass2key( auth_password, auth_password_len, engine, engine_len, a.user.authKey.data);
				a.user.authModel->pass2key( priv_password, priv_password_len, engine, engine_len, a.user.privKey.data);
			} else {
				a.user.authKey.data = NULL;
				a.user.authKey.len = 0;
				a.user.privKey.data = NULL;
				a.user.privKey.len = 0;
			}
			
	} else {
		a.engine.data = NULL;
		a.engine.len = 0;
		a.user.authKey.data = NULL;
		a.user.authKey.len = 0;
		a.user.privKey.data = NULL;
		a.user.privKey.len = 0;		
	}
	
	g_array_append_val(assoc_arr,a);
	loaded++;
	
	return;
}

gchar* load_snmp_users_file(const char* fname, snmp_ue_assoc_t** assocs) {
	gchar* err_str = NULL;
	
	*assocs = NULL;

	assoc_arr = g_array_new(TRUE,FALSE,sizeof(snmp_ue_assoc_t));
	filename = fname;
	
	yyin = fopen(filename,"r");

	if (!yyin) {
		return ep_strdup_printf("Could not open file: '%s', error: %s",filename,strerror(errno));
	}
	
	error = g_string_new("");
	loaded = 0;

	START_LINE();
	
	yylex();
	
	fclose(yyin);
	
	yyrestart(NULL);

	if (loaded) {
		*assocs = (snmp_ue_assoc_t*)assoc_arr->data;
		g_array_free(assoc_arr,FALSE);
	} else {
		*assocs = NULL;		
		g_array_free(assoc_arr,TRUE);
	}
	
	
	if (error->len) {
		err_str = error->str;
	}
	
	
	
	return err_str;
}
