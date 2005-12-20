%option noyywrap

%option nounput
%option never-interactive
%option prefix="Radius"
%option caseless

%option outfile="radius_dict.c"

%{
	/* packet-radius.c
	*
	* RADIUS dictionary parser
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
	* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
	*
	*/
	
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
	
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <epan/packet.h>
#include <epan/dissectors/packet-radius.h>
#define DIR_SEPARATOR '/'
#define ECHO
#define MAX_INCLUDE_DEPTH 10

	void add_vendor(const gchar* name, guint32 vendor_id);
	void add_value(const gchar* attrib_name,const  gchar* value_repr, long value);
	void add_attribute(const gchar*,const  gchar*, radius_attr_dissector_t,const  gchar*, gboolean, gboolean);
	
	static YY_BUFFER_STATE include_stack[10];
	static int include_stack_ptr = 0;
	
	static radius_dictionary_t* dict = NULL;
	static GHashTable* value_strings = NULL; /* GArray(value_string) by attribute name */
	
	static gchar* attr_name = NULL;
	static gchar* attr_id = NULL;
	static radius_attr_dissector_t* attr_type = NULL;
	static gchar* attr_vendor = NULL;
	static gchar* vendor_name = NULL;
	static gchar* value_repr = NULL;
	static gboolean encrypted = FALSE;
	static gboolean has_tag = FALSE;
	static gchar* current_vendor = NULL;
	
	static GString* error = NULL;
	static gchar* directory = NULL;
	static int linenums[] = {1,1,1,1,1,1,1,1,1,1};
	static gchar* fullpaths[] = {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};
	
%}

%START OUT VENDOR VENDOR_W_NAME ATTR ATTR_W_NAME ATTR_W_ID ATTR_W_TYPE ATTR_W_VENDOR VALUE VALUE_W_ATTR VALUE_W_NAME INCLUDE JUNK BEGIN_VENDOR END_VENDOR
%%
[:blank:]   ;
#[^\n]*		;

<JUNK>.*\qn		;

<OUT>VENDOR { BEGIN VENDOR; }
<OUT>ATTRIBUTE { BEGIN ATTR; }
<OUT>VALUE { BEGIN VALUE; }
<OUT>\$INCLUDE { BEGIN INCLUDE; }
<OUT>BEGIN-VENDOR { BEGIN BEGIN_VENDOR; }
<OUT>END-VENDOR { BEGIN END_VENDOR; }

<BEGIN_VENDOR>[0-9a-z_-]+ {
    if (current_vendor) {
        g_free(current_vendor);
    }
    current_vendor = g_strdup(yytext);
    BEGIN OUT;
}
<END_VENDOR>[^\n]* {
    if (current_vendor) {
        g_free(current_vendor);
        current_vendor = NULL;
    }
    BEGIN OUT;
}

<VENDOR>[0-9a-z_-]+   { vendor_name = g_strdup(yytext); BEGIN VENDOR_W_NAME; }
<VENDOR_W_NAME>[0-9]+   {
    add_vendor(vendor_name,strtol(yytext,NULL,10));
    g_free(vendor_name);
    BEGIN OUT;
}
<VENDOR_W_NAME>0x[0-9a-f]+   {
    add_vendor(vendor_name,strtol(yytext,NULL,16));
    g_free(vendor_name);
    BEGIN OUT;
}

<ATTR>[0-9a-z_/-]+			{ attr_name = g_strdup(yytext); encrypted = FALSE; has_tag = FALSE; BEGIN ATTR_W_NAME; }
<ATTR_W_NAME>[0-9]+			{ attr_id = g_strdup(yytext);  BEGIN ATTR_W_ID;}
<ATTR_W_NAME>0x[0-9a-f]+		{ attr_id = g_strdup_printf("%u",(int)strtoul(yytext,NULL,16)); BEGIN ATTR_W_ID;}
<ATTR_W_ID>integer			{ attr_type = radius_integer;  BEGIN ATTR_W_TYPE; }
<ATTR_W_ID>string			{ attr_type = radius_string;  BEGIN ATTR_W_TYPE; }
<ATTR_W_ID>octets			{ attr_type = radius_octets;  BEGIN ATTR_W_TYPE; }
<ATTR_W_ID>ipaddr			{ attr_type = radius_ipaddr;  BEGIN ATTR_W_TYPE; }
<ATTR_W_ID>ipv6addr			{ attr_type = radius_ipv6addr;  BEGIN ATTR_W_TYPE; }
<ATTR_W_ID>ipxnet			{ attr_type = radius_ipxnet;  BEGIN ATTR_W_TYPE; }
<ATTR_W_ID>date				{ attr_type = radius_date;  BEGIN ATTR_W_TYPE; }
<ATTR_W_ID>ifid				{ attr_type = radius_ifid;  BEGIN ATTR_W_TYPE; }
<ATTR_W_ID>[0-9a-z_-]+			{ attr_type = radius_octets;  BEGIN ATTR_W_TYPE; }
<ATTR_W_TYPE>has_tag[,]?		{ has_tag = TRUE; attr_vendor = NULL;  BEGIN ATTR_W_VENDOR; }
<ATTR_W_TYPE>encrypt=1[,]?		{ encrypted=TRUE;  attr_vendor = NULL;  BEGIN ATTR_W_VENDOR; }
<ATTR_W_TYPE>[,0-9a-z_-]+=([^\n]+)	{ /* ignore other parameters */  attr_vendor = NULL;  BEGIN ATTR_W_VENDOR; }
<ATTR_W_TYPE>[0-9a-z_-]+		{
    attr_vendor = g_strdup(yytext);
    add_attribute(attr_name,attr_id,attr_type,attr_vendor,encrypted,has_tag);
    g_free(attr_id);
    g_free(attr_vendor);
    g_free(attr_name);
    attr_id = NULL;
    attr_vendor = NULL;
    attr_name = NULL;
    BEGIN OUT;
}
<ATTR_W_TYPE>\n						{
    add_attribute(attr_name,attr_id,attr_type,current_vendor,encrypted,has_tag);
    g_free(attr_id);
    g_free(attr_name);
    linenums[include_stack_ptr]++;
    BEGIN OUT;
}
<ATTR_W_VENDOR>\n					{
    add_attribute(attr_name,attr_id,attr_type,attr_vendor,encrypted,has_tag);
    g_free(attr_id);
    g_free(attr_vendor);
    g_free(attr_name);
    linenums[include_stack_ptr]++; 
    BEGIN OUT;
};

<VALUE>[0-9a-z_/-]+					{ attr_name = g_strdup(yytext); BEGIN VALUE_W_ATTR; }
<VALUE_W_ATTR>[^[:blank:]]+			{ value_repr = g_strdup(yytext); BEGIN VALUE_W_NAME; }
<VALUE_W_NAME>[0-9]+				{ add_value(attr_name,value_repr,strtol(yytext,NULL,10));  g_free(attr_name); g_free(value_repr); BEGIN OUT;}
<VALUE_W_NAME>0x[0-9a-f]+			{ add_value(attr_name,value_repr,strtol(yytext,NULL,16));  g_free(attr_name); g_free(value_repr); BEGIN OUT;}

<INCLUDE>[^[:blank:]\n]+   {
	if ( include_stack_ptr >= MAX_INCLUDE_DEPTH ) {
		g_string_sprintfa(error, "$INCLUDE files nested to deeply\n");
		yyterminate();
	}
	
	include_stack[include_stack_ptr++] = YY_CURRENT_BUFFER;
	
	fullpaths[include_stack_ptr] = g_strdup_printf("%s%c%s",directory,DIR_SEPARATOR,yytext);

	yyin = fopen( fullpaths[include_stack_ptr], "r" );
	
	if (!yyin) {
		if (errno) {
			g_string_sprintfa(error, "Could not open file: '%s', error: %s\n", fullpaths[include_stack_ptr], strerror(errno) );
			yyterminate();
		}
	} else {
		linenums[include_stack_ptr] = 1;
		yy_switch_to_buffer(yy_create_buffer( yyin, YY_BUF_SIZE ) );
	}
	

	BEGIN OUT;
}

<<EOF>> {
	
	fclose(yyin);
	yyin = NULL;
    
	if ( --include_stack_ptr < 0 ) {
		yyterminate();
	} else {
		g_free(fullpaths[include_stack_ptr+1]);
		fullpaths[include_stack_ptr+1] = NULL;
		
		yy_delete_buffer( YY_CURRENT_BUFFER );
		yy_switch_to_buffer(include_stack[include_stack_ptr]);
	}

	BEGIN OUT;
}

\n 	{ linenums[include_stack_ptr]++; BEGIN OUT; }


%%

void add_vendor(const gchar* name, guint32 vendor_id) {
	radius_vendor_info_t* v = g_malloc(sizeof(radius_vendor_info_t));
	
	v->name = g_strdup(name);
	v->code = vendor_id;
	v->attrs_by_id = g_hash_table_new(g_direct_hash,g_direct_equal);
	v->ett = -1;
    
	g_hash_table_insert(dict->vendors_by_id,GUINT_TO_POINTER(v->code),v);
	g_hash_table_insert(dict->vendors_by_name,v->name,v);
}

void add_attribute(const gchar* name, const  gchar* code, radius_attr_dissector_t type, const  gchar* vendor_name, gboolean crypt, gboolean tagged) {
	radius_attr_info_t* a = g_malloc(sizeof(radius_attr_info_t));
	GHashTable* by_id;
	
	if (vendor_name) {
		radius_vendor_info_t* v;
		v = g_hash_table_lookup(dict->vendors_by_name,vendor_name);
		
		if (! v) {
			g_string_sprintfa(error, "Vendor: '%s', does not exist in %s:%i \n", vendor_name, fullpaths[include_stack_ptr], linenums[include_stack_ptr] );
			BEGIN JUNK;
			return;
		} else {
			by_id = v->attrs_by_id;
		}
	} else {
		by_id = dict->attrs_by_id;
	}
	
	a->name = g_strdup(name);
	a->code = strtol(code,NULL,10);
	a->encrypt = crypt;
	a->tagged =  tagged;
	a->type = type;
	a->dissector = NULL;
	a->vs = NULL;
	a->hf = -1;
	a->hf64 = -1;
	a->hf_tag = -1;
	a->hf_len = -1;
	a->ett = -1;
	
	g_hash_table_insert(by_id,GUINT_TO_POINTER(a->code),a);
	g_hash_table_insert(dict->attrs_by_name,(gpointer) (a->name),a);
}

void add_value(const gchar* attrib_name, const gchar* value_repr, long value) {
	value_string v;
	GArray* a = g_hash_table_lookup(value_strings,attrib_name);
	
	if (! a) {
		a = g_array_new(TRUE,TRUE,sizeof(value_string));
		g_hash_table_insert(value_strings,g_strdup(attrib_name),a);
	}
	
	v.value = value;
	v.strptr = g_strdup(value_repr);
	
	g_array_append_val(a,v);
}


static void setup_attrs(gpointer k _U_, gpointer v, gpointer p _U_) {
	radius_attr_info_t* a = v;
	gpointer key;
	
	union {
		GArray* a;
		gpointer p;
	} vs;
	
	if (g_hash_table_lookup_extended(value_strings,a->name,&key,&vs.p) ) {
		a->vs = (value_string*) vs.a->data;
		g_array_free(vs.a,FALSE);
		g_hash_table_remove(value_strings,key);
		g_free(key);
	}
}

static void setup_vendors(gpointer k _U_, gpointer v, gpointer p) {
	radius_vendor_info_t* vnd = v;
	
	g_hash_table_foreach(vnd->attrs_by_id,setup_attrs,p);	
}

static gboolean destroy_value_strings(gpointer k, gpointer v, gpointer p _U_) {
    value_string* vs = (value_string*)(((GArray*)v)->data);
    
	g_free(k);
    
    for (;vs->strptr;vs++) {
        g_free((void*)vs->strptr);
    }
    
	g_array_free(v,TRUE);
	return TRUE;
}

static gboolean destroy_attrs(gpointer k _U_, gpointer v, gpointer p _U_) {
	radius_attr_info_t* a = v;
	int i;
	
	g_free((gpointer) (a->name));
	if (a->vs) {
		for(i=0; a->vs[i].strptr; i++) {
			g_free((void *)a->vs[i].strptr);
		}
		g_free((void *)a->vs);
	}
	g_free(a);
	return TRUE;
}

static gboolean destroy_vendors(gpointer k _U_, gpointer v, gpointer p) {
	radius_vendor_info_t* vnd = v;
	g_free(vnd->name);
	g_hash_table_foreach_remove(vnd->attrs_by_id,destroy_attrs,p);
	g_hash_table_destroy(vnd->attrs_by_id);
	g_free(vnd);
	return TRUE;
}

static void destroy_dict(radius_dictionary_t* d) {
	g_hash_table_foreach_remove(d->attrs_by_id,destroy_attrs,NULL);
	g_hash_table_foreach_remove(d->vendors_by_id,destroy_vendors,NULL);	
	g_hash_table_destroy(d->vendors_by_id);
	g_hash_table_destroy(d->attrs_by_id);
	g_hash_table_destroy(d->vendors_by_name);
	g_hash_table_destroy(d->attrs_by_name);
	g_free(d);
}

radius_dictionary_t* radius_load_dictionary (gchar* dir, const gchar* filename, gchar** err_str) {
	int i;
	
	directory = dir;
	
	fullpaths[include_stack_ptr] = g_strdup_printf("%s%c%s",directory,DIR_SEPARATOR,filename);
	
	error = g_string_new("");

	yyin = fopen(fullpaths[include_stack_ptr],"r");
	
	if (!yyin) {
		g_string_sprintfa(error, "Could not open file: '%s', error: %s\n", fullpaths[include_stack_ptr], strerror(errno) );
		g_free(fullpaths[include_stack_ptr]);
		*err_str = error->str;
		g_string_free(error,FALSE);
		return NULL;
	}

	dict = g_malloc(sizeof(radius_dictionary_t));
	dict->attrs_by_id = g_hash_table_new(g_direct_hash,g_direct_equal);
	dict->attrs_by_name = g_hash_table_new(g_str_hash,g_str_equal);
	dict->vendors_by_id = g_hash_table_new(g_direct_hash,g_direct_equal);
	dict->vendors_by_name = g_hash_table_new(g_str_hash,g_str_equal);
	
	value_strings = g_hash_table_new(g_str_hash,g_str_equal);
	
	BEGIN OUT;

	yylex();

	if (yyin != NULL) fclose(yyin);
	yyin = NULL;
    
	for (i=0; i < 10; i++) {
		if (fullpaths[i]) g_free(fullpaths[i]);
	}
		
	g_hash_table_foreach(dict->attrs_by_id,setup_attrs,NULL);
	g_hash_table_foreach(dict->vendors_by_id,setup_vendors,NULL);	
	g_hash_table_foreach_remove(value_strings,destroy_value_strings,NULL);
	
	if (error->len > 0) {
		 *err_str = error->str;
		g_string_free(error,FALSE);
		destroy_dict(dict);
		return NULL;
	} else {
		*err_str = NULL;
		g_string_free(error,TRUE);
		return dict;
	}
}
