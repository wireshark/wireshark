/* packet-xml.c
 * ethereal's xml dissector .
 *
 * (C) 2005, Luis E. Garcia Ontanon.
 *
 * $Id$
 *
 * Refer to the AUTHORS file or the AUTHORS section in the man page
 * for contacting the author(s) of this file.
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
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <stdio.h>

#include <glib.h>
#include <epan/emem.h>
#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/tvbparse.h>
#include <epan/dtd.h>

typedef struct _xml_names_t {
	gchar* name;
	gchar* longname;
	gchar* blurb;
	int hf_tag;
	int hf_cdata;
	gint ett;
	
	gboolean is_root;

	GHashTable* attributes;
	GHashTable* elements;
} xml_names_t;

typedef struct {
	proto_tree* tree;
	proto_item* item;
	proto_item* last_item;
	xml_names_t* ns;
	int start_offset;
} xml_frame_t;

static gint ett_dtd = -1;
static gint ett_xmpli = -1;

static int hf_junk = -1;
static int hf_unknowwn_attrib = -1;
static int hf_comment = -1;
static int hf_xmlpi = -1;
static int hf_dtd_tag = -1;
static int hf_doctype = -1;

/* Dissector handles */
static dissector_handle_t xml_handle;

/* tokenizer defs */
static tvbparse_wanted_t* want;
static tvbparse_wanted_t* want_ignore;

static GHashTable* xmpli_names;
static GHashTable* media_types;

static xml_names_t xml_ns = {"xml","eXtesible Markup Language","XML",-1,-1,-1,TRUE,NULL,NULL};
static xml_names_t unknown_ns = {"","","",-1,-1,-1,TRUE,NULL,NULL};
static xml_names_t* root_ns;

#define XML_CDATA -1000

GArray* hf;
GArray* ett_arr;

static void
dissect_xml(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tvbparse_t* tt;
	tvbparse_elem_t* tok = NULL;
	static GPtrArray* stack = NULL;
	xml_frame_t* current_frame;
	
	if(!tree) return;
	
	if (stack != NULL)
		g_ptr_array_free(stack,FALSE);
	
	stack = g_ptr_array_new();
	current_frame = ep_alloc(sizeof(xml_frame_t));
	g_ptr_array_add(stack,current_frame);

	tt = tvbparse_init(tvb,0,-1,stack,want_ignore);
	current_frame->start_offset = 0;
	
	root_ns = g_hash_table_lookup(media_types,pinfo->match_string);
	
	if (! root_ns ) {
		root_ns = &unknown_ns;
	}
	
	current_frame->ns = root_ns;
	
	current_frame->item = proto_tree_add_item(tree,xml_ns.hf_tag,tvb,0,-1,FALSE);
	current_frame->tree = proto_item_add_subtree(current_frame->item,xml_ns.ett);
	current_frame->last_item = current_frame->item;
	
	while(( tok = tvbparse_get(tt, want) )) ;
} 


static void after_token(void* tvbparse_data, const void* wanted_data _U_, tvbparse_elem_t* tok) {
	GPtrArray* stack = tvbparse_data;
	xml_frame_t* current_frame = g_ptr_array_index(stack,stack->len - 1);
	int hfid;
	proto_item* pi;

	if (tok->id == XML_CDATA) {
		hfid = current_frame->ns->hf_cdata;
	} else if ( tok->id > 0) {
		hfid = tok->id;
	} else {
		hfid = hf_junk;
	}
	
	pi = proto_tree_add_item(current_frame->tree, hfid, tok->tvb, tok->offset, tok->len, FALSE);
	
	proto_item_set_text(pi, "%s",
						tvb_format_text(tok->tvb,tok->offset,tok->len));
}

static void before_xmpli(void* tvbparse_data, const void* wanted_data _U_, tvbparse_elem_t* tok) {
	GPtrArray* stack = tvbparse_data;
	xml_frame_t* current_frame = g_ptr_array_index(stack,stack->len - 1);
	proto_item* pi;
	proto_tree* pt;
	tvbparse_elem_t* name_tok = tok->sub->next;
	gchar* name = g_strdown(tvb_get_ephemeral_string(name_tok->tvb,name_tok->offset,name_tok->len));
	xml_names_t* ns = g_hash_table_lookup(xmpli_names,name);
	int hf_tag;
	gint ett;
	
	if (!ns) {
		hf_tag = hf_xmlpi;
		ett = ett_xmpli;
	} else {
		hf_tag = ns->hf_tag;
		ett = ns->ett;
	}
	
	pi = proto_tree_add_item(current_frame->tree,hf_tag,tok->tvb,tok->offset,tok->len,FALSE);
	
	proto_item_set_text(pi,tvb_format_text(tok->tvb,tok->offset,(name_tok->offset - tok->offset) + name_tok->len));
	
	pt = proto_item_add_subtree(pi,ett);
	
	current_frame = ep_alloc(sizeof(xml_frame_t));
	current_frame->item = pi;
	current_frame->last_item = pi;
	current_frame->tree = pt;
	current_frame->start_offset = tok->offset;
	current_frame->ns = ns;

	g_ptr_array_add(stack,current_frame);
	
}

static void after_xmlpi(void* tvbparse_data, const void* wanted_data _U_, tvbparse_elem_t* tok) {
	GPtrArray* stack = tvbparse_data;
	xml_frame_t* current_frame = g_ptr_array_index(stack,stack->len - 1);
		
	proto_tree_add_text(current_frame->tree,
						   tok->tvb, tok->offset, tok->len,
						   tvb_format_text(tok->tvb,tok->offset,tok->len));
	
	if (stack->len > 1) {
		g_ptr_array_remove_index_fast(stack,stack->len - 1);
	} else {
		proto_tree_add_text(current_frame->tree,tok->tvb,tok->offset,tok->len,"[ ERROR: Closing an unopened xmpli tag ]");
	}
}

static void before_tag(void* tvbparse_data, const void* wanted_data _U_, tvbparse_elem_t* tok) {
	GPtrArray* stack = tvbparse_data;
	xml_frame_t* current_frame = g_ptr_array_index(stack,stack->len - 1);
	tvbparse_elem_t* name_tok = tok->sub->next;
	gchar* name = g_strdown(tvb_get_ephemeral_string(name_tok->tvb,name_tok->offset,name_tok->len));
	xml_names_t* ns = g_hash_table_lookup(current_frame->ns->elements,name);
	xml_frame_t* new_frame;
	proto_item* pi;
	proto_tree* pt;
	
	if (!ns) {
		if (! ( ns = g_hash_table_lookup(root_ns->elements,name) ) ) {
			ns = &unknown_ns;
		}
	}
	
	pi = proto_tree_add_item(current_frame->tree,ns->hf_tag,tok->tvb,tok->offset,tok->len,FALSE);
	proto_item_set_text(pi,tvb_format_text(tok->tvb,tok->offset,(name_tok->offset - tok->offset) + name_tok->len));
	
	pt = proto_item_add_subtree(pi,ns->ett);
	
	new_frame = ep_alloc(sizeof(xml_frame_t));
	new_frame->item = pi;
	new_frame->last_item = pi;
	new_frame->tree = pt;
	new_frame->start_offset = tok->offset;
	new_frame->ns = ns;

	g_ptr_array_add(stack,new_frame);

}

static void after_open_tag(void* tvbparse_data, const void* wanted_data _U_, tvbparse_elem_t* tok _U_) {
	GPtrArray* stack = tvbparse_data;
	xml_frame_t* current_frame = g_ptr_array_index(stack,stack->len - 1);

	proto_item_append_text(current_frame->last_item,">");
}

static void after_closed_tag(void* tvbparse_data, const void* wanted_data _U_, tvbparse_elem_t* tok) {
	GPtrArray* stack = tvbparse_data;
	xml_frame_t* current_frame = g_ptr_array_index(stack,stack->len - 1);

	proto_item_append_text(current_frame->last_item,"/>");					

	if (stack->len > 1) {
		g_ptr_array_remove_index_fast(stack,stack->len - 1);
	} else {
		proto_tree_add_text(current_frame->tree,tok->tvb,tok->offset,tok->len,"[ ERROR: Closing an unopened tag ]");
	}	
}

void after_untag(void* tvbparse_data, const void* wanted_data _U_, tvbparse_elem_t* tok){
	GPtrArray* stack = tvbparse_data;
	xml_frame_t* current_frame = g_ptr_array_index(stack,stack->len - 1);

	proto_item_set_len(current_frame->item, (tok->offset - current_frame->start_offset) + tok->len);
	
	proto_tree_add_text(current_frame->tree,tok->tvb,tok->offset,tok->len,"%s",
						tvb_format_text(tok->tvb,tok->offset,tok->len));

	if (stack->len > 1) {
		g_ptr_array_remove_index_fast(stack,stack->len - 1);
	} else {
		proto_tree_add_text(current_frame->tree,tok->tvb,tok->offset,tok->len,
							"[ ERROR: Closing an unopened tag ]");
	}
}

static void before_dtd_doctype(void* tvbparse_data, const void* wanted_data _U_, tvbparse_elem_t* tok){
	GPtrArray* stack = tvbparse_data;
	xml_frame_t* current_frame = g_ptr_array_index(stack,stack->len - 1);
	tvbparse_elem_t* name_tok = tok->sub->next->next->next->sub->sub;
	proto_tree* dtd_item = proto_tree_add_item(current_frame->tree, hf_doctype,
											   name_tok->tvb, name_tok->offset, name_tok->len, FALSE);
											   
	proto_item_set_text(dtd_item,"%s",tvb_format_text(tok->tvb,tok->offset,tok->len));

	current_frame = ep_alloc(sizeof(xml_frame_t));
	current_frame->item = dtd_item;
	current_frame->last_item = dtd_item;
	current_frame->tree = proto_item_add_subtree(dtd_item,ett_dtd);
	current_frame->start_offset = tok->offset;
	current_frame->ns = NULL;

	g_ptr_array_add(stack,current_frame);
}

static void pop_stack(void* tvbparse_data, const void* wanted_data _U_, tvbparse_elem_t* tok _U_) {
	GPtrArray* stack = tvbparse_data;
	xml_frame_t* current_frame = g_ptr_array_index(stack,stack->len - 1);

	if (stack->len > 1) {
		g_ptr_array_remove_index_fast(stack,stack->len - 1);
	} else {
		proto_tree_add_text(current_frame->tree,tok->tvb,tok->offset,tok->len,
							"[ ERROR: Closing an unopened tag ]");
	}	
}

static void after_dtd_close(void* tvbparse_data, const void* wanted_data _U_, tvbparse_elem_t* tok){
	GPtrArray* stack = tvbparse_data;
	xml_frame_t* current_frame = g_ptr_array_index(stack,stack->len - 1);
	
	proto_tree_add_text(current_frame->tree,tok->tvb,tok->offset,tok->len,"%s",
						tvb_format_text(tok->tvb,tok->offset,tok->len));
	if (stack->len > 1) {
		g_ptr_array_remove_index_fast(stack,stack->len - 1);
	} else {
		proto_tree_add_text(current_frame->tree,tok->tvb,tok->offset,tok->len,"[ ERROR: Closing an unopened tag ]");
	}
}

static void get_attrib_value(void* tvbparse_data _U_, const void* wanted_data _U_, tvbparse_elem_t* tok) {
	tok->data = tok->sub;
}

static void after_attrib(void* tvbparse_data, const void* wanted_data _U_, tvbparse_elem_t* tok) {
	GPtrArray* stack = tvbparse_data;
	xml_frame_t* current_frame = g_ptr_array_index(stack,stack->len - 1);
	gchar* name = g_strdown(tvb_get_ephemeral_string(tok->sub->tvb,tok->sub->offset,tok->sub->len));
	tvbparse_elem_t* value = tok->sub->next->next->data;
	int* hfidp;
	int hfid;

	if(current_frame->ns && (hfidp = g_hash_table_lookup(current_frame->ns->attributes,g_strdown(name)) )) {
		hfid = *hfidp;
	} else {
		hfid = hf_unknowwn_attrib;
		value = tok;
	}
	
	current_frame->last_item = proto_tree_add_item(current_frame->tree,hfid,value->tvb,value->offset,value->len,FALSE);
	proto_item_set_text(current_frame->last_item, "%s", tvb_format_text(tok->tvb,tok->offset,tok->len));

}

static void unrecognized_token(void* tvbparse_data, const void* wanted_data _U_, tvbparse_elem_t* tok _U_){
	GPtrArray* stack = tvbparse_data;
	xml_frame_t* current_frame = g_ptr_array_index(stack,stack->len - 1);
	
	proto_tree_add_text(current_frame->tree,tok->tvb,tok->offset,tok->len,"[ ERROR: Unrecognized text ]");

}



void init_xml_parser(void) {	
	tvbparse_wanted_t* want_name = tvbparse_chars(-1,0,0,"abcdefghijklmnopqrstuvwxyz-_:ABCDEFGHIJKLMNOPQRSTUVWXYZ",NULL,NULL,NULL);

	tvbparse_wanted_t* want_attributes = tvbparse_one_or_more(-1, NULL, NULL, NULL,
															  tvbparse_set_seq(-1, NULL, NULL, after_attrib,
																			   want_name,
																			   tvbparse_char(-1,"=",NULL,NULL,NULL),
																			   tvbparse_set_oneof(0, NULL, NULL, get_attrib_value,
																								  tvbparse_quoted(-1, NULL, NULL, tvbparse_shrink_token_cb,'\"','\\'),
																								  tvbparse_quoted(-1, NULL, NULL, tvbparse_shrink_token_cb,'\'','\\'),
																								  tvbparse_chars(-1,0,0,"0123456789",NULL,NULL,NULL),
																								  want_name,
																								  NULL),
																			   NULL));
	
	tvbparse_wanted_t* want_stoptag = tvbparse_set_oneof(-1,NULL,NULL,NULL,
														 tvbparse_char(-1, ">", NULL, NULL, after_open_tag),
														 tvbparse_string(-1, "/>", NULL, NULL, after_closed_tag),
														 NULL);
	
	tvbparse_wanted_t* want_stopxmlpi = tvbparse_string(-1,"?>",NULL,NULL,after_xmlpi);
	
	want_ignore = tvbparse_chars(-1,0,0," \t\r\n",NULL,NULL,NULL);
	
	want = tvbparse_set_oneof(-1, NULL, NULL, NULL,
							  tvbparse_set_seq(hf_comment,NULL,NULL,after_token,
											   tvbparse_string(-1,"<!--",NULL,NULL,NULL),
											   tvbparse_until(-1,NULL,NULL,NULL,
															  tvbparse_string(-1,"-->",NULL,NULL,NULL),
															  TRUE),
											   NULL),
							  tvbparse_set_seq(hf_xmlpi,NULL,before_xmpli,NULL,
											   tvbparse_string(-1,"<?",NULL,NULL,NULL),
											   want_name,
											   tvbparse_set_oneof(-1,NULL,NULL,NULL,
																  want_stopxmlpi,
																  tvbparse_set_seq(-1,NULL,NULL,NULL,
																				   want_attributes,
																				   want_stopxmlpi,
																				   NULL),
																  NULL),
											   NULL),
							  tvbparse_set_seq(0,NULL,NULL,after_untag,
											   tvbparse_char(-1, "<", NULL, NULL, NULL),
											   tvbparse_char(-1, "/", NULL, NULL, NULL),
											   want_name,
											   tvbparse_char(-1, ">", NULL, NULL, NULL),
											   NULL),
							  tvbparse_set_seq(-1,NULL,before_dtd_doctype,NULL,
											   tvbparse_char(-1,"<",NULL,NULL,NULL),
											   tvbparse_char(-1,"!",NULL,NULL,NULL),
											   tvbparse_casestring(-1,"DOCTYPE",NULL,NULL,NULL),
											   tvbparse_set_oneof(-1,NULL,NULL,NULL,
																  tvbparse_set_seq(-1,NULL,NULL,NULL,
																				   want_name,
																				   tvbparse_char(-1,"[",NULL,NULL,NULL),
																				   NULL),
																  tvbparse_set_seq(-1,NULL,NULL,pop_stack,
																				   want_name,
																				   tvbparse_set_oneof(-1,NULL,NULL,NULL,
																									  tvbparse_casestring(-1,"PUBLIC",NULL,NULL,NULL),
																									  tvbparse_casestring(-1,"SYSTEM",NULL,NULL,NULL),
																									  NULL),
																				   tvbparse_until(-1,NULL,NULL,NULL,
																								  tvbparse_char(-1,">",NULL,NULL,NULL),
																								  TRUE),
																				   NULL),
																  NULL),
											   NULL),
							  tvbparse_set_seq(-1,NULL,NULL,after_dtd_close,
											   tvbparse_char(-1,"]",NULL,NULL,NULL),
											   tvbparse_char(-1,">",NULL,NULL,NULL),
											   NULL),
							  tvbparse_set_seq(hf_dtd_tag,NULL,NULL,after_token,
											   tvbparse_char(-1,"<",NULL,NULL,NULL),
											   tvbparse_char(-1,"!",NULL,NULL,NULL),
											   tvbparse_until(-1,NULL,NULL,NULL,
															  tvbparse_char(-1, ">", NULL, NULL, NULL),
															  TRUE),
											   NULL),
							  tvbparse_set_seq(-1, NULL, before_tag, NULL,
											   tvbparse_char(-1,"<",NULL,NULL,NULL),
											   want_name,
											   tvbparse_set_oneof(-1,NULL,NULL,NULL,
																  tvbparse_set_seq(-1,NULL,NULL,NULL,
																				   want_attributes,
																				   want_stoptag,
																				   NULL),
																  want_stoptag,
																  NULL),
											   NULL),
							  tvbparse_not_chars(XML_CDATA,0,0,"<",NULL,NULL,after_token),
							  tvbparse_not_chars(-1,0,0," \t\r\n",NULL,NULL,unrecognized_token),
							  NULL);
	
	
}


xml_names_t* xml_new_namespace(GHashTable* hash, gchar* name, gchar* longname, gchar* blurb, ...) {
	xml_names_t* ns = g_malloc(sizeof(xml_names_t));
	va_list ap;
	gchar* attr_name;
	
	ns->name = g_strdup(name);
	ns->longname = g_strdup(longname);
	ns->blurb = g_strdup(blurb);
	ns->hf_tag = -1;
	ns->hf_cdata = -1;
	ns->ett = -1;
	ns->attributes = g_hash_table_new(g_str_hash,g_str_equal);
	ns->elements = g_hash_table_new(g_str_hash,g_str_equal);
	
	va_start(ap,blurb);
	
	while(( attr_name = va_arg(ap,gchar*) )) {
		int* hfp = g_malloc(sizeof(int));
		*hfp = -1;
		g_hash_table_insert(ns->attributes,g_strdup(attr_name),hfp);
	};
	
	va_end(ap);
	
	g_hash_table_insert(hash,ns->name,ns);
	
	return ns;
}

void add_xml_attribute_names(gpointer k, gpointer v, gpointer p) {
	gchar* basename = g_strdup_printf("%s.%s",(gchar*)p,(gchar*)k);
	hf_register_info hfri;
	
	hfri.p_id = (int*)v;
	hfri.hfinfo.name = basename;
	hfri.hfinfo.abbrev = basename;
	hfri.hfinfo.type = FT_STRING;
	hfri.hfinfo.display = BASE_NONE;
	hfri.hfinfo.strings = NULL;
	hfri.hfinfo.bitmask = 0x0;
	hfri.hfinfo.blurb = basename;
	hfri.hfinfo.id = 0;
	hfri.hfinfo.parent = 0;
	hfri.hfinfo.ref_count = 0;
	hfri.hfinfo.bitshift = 0;
	hfri.hfinfo.same_name_next = NULL;
	hfri.hfinfo.same_name_prev = NULL;
	
	g_array_append_val(hf,hfri);
}

void add_xmlpi_namespace(gpointer k _U_, gpointer v, gpointer p) {
	xml_names_t* ns = v;
	hf_register_info hfri;
	gchar* basename = g_strdup_printf("%s.%s",(gchar*)p,ns->name);
	gint* ett_p = &(ns->ett);
	
	hfri.p_id = &(ns->hf_tag);
	hfri.hfinfo.name = basename;
	hfri.hfinfo.abbrev = basename;
	hfri.hfinfo.type = FT_STRING;
	hfri.hfinfo.display = BASE_NONE;
	hfri.hfinfo.strings = NULL;
	hfri.hfinfo.bitmask = 0x0;
	hfri.hfinfo.blurb = basename;
	hfri.hfinfo.id = 0;
	hfri.hfinfo.parent = 0;
	hfri.hfinfo.ref_count = 0;
	hfri.hfinfo.bitshift = 0;
	hfri.hfinfo.same_name_next = NULL;
	hfri.hfinfo.same_name_prev = NULL;

	g_array_append_val(hf,hfri);
	g_array_append_val(ett_arr,ett_p);
	
	g_hash_table_foreach(ns->attributes,add_xml_attribute_names,basename);

}

void init_xml_names(void) {
	xml_names_t* xmlpi_xml_ns;

	xmpli_names = g_hash_table_new(g_str_hash,g_str_equal);
	media_types = g_hash_table_new(g_str_hash,g_str_equal);
	
	unknown_ns.elements = g_hash_table_new(g_str_hash,g_str_equal);
	unknown_ns.attributes = g_hash_table_new(g_str_hash,g_str_equal);
	
	xmlpi_xml_ns = xml_new_namespace(xmpli_names,"xml","XML XMLPI","XML XMLPI",
									 "version","encoding","standalone",NULL);
	
	g_hash_table_destroy(xmlpi_xml_ns->elements);
	xmlpi_xml_ns->elements = NULL;
	
	g_hash_table_foreach(xmpli_names,add_xmlpi_namespace,"xml.xmlpi");
}


void
proto_register_xml(void) {
	
	static gint *ett_base[] = {
		&unknown_ns.ett,
		&xml_ns.ett,
		&ett_dtd,
		&ett_xmpli
	};
	
	static hf_register_info hf_base[] = {
		{ &hf_xmlpi, {"XMLPI", "xml.xmlpi", FT_STRING, BASE_NONE, NULL, 0, "", HFILL }},
		{ &hf_comment, {"Comment", "xml.comment", FT_STRING, BASE_NONE, NULL, 0, "", HFILL }},
		{ &hf_unknowwn_attrib, {"Attribute", "xml.attribute", FT_STRING, BASE_NONE, NULL, 0, "", HFILL }},
		{ &hf_doctype, {"Doctype", "xml.doctype", FT_STRING, BASE_NONE, NULL, 0, "", HFILL }},
		{ &hf_dtd_tag, {"DTD Tag", "xml.dtdtag", FT_STRING, BASE_NONE, NULL, 0, "", HFILL }},
		{ &unknown_ns.hf_cdata, {"CDATA", "xml.cdata", FT_STRING, BASE_NONE, NULL, 0, "", HFILL }},
		{ &unknown_ns.hf_tag, {"Tag", "xml.tag", FT_STRING, BASE_NONE, NULL, 0, "", HFILL }},
		{ &hf_junk, {"Unknown", "xml.unknown", FT_STRING, BASE_NONE, NULL, 0, "", HFILL }}
	};

	hf = g_array_new(FALSE,FALSE,sizeof(hf_register_info));
	ett_arr = g_array_new(FALSE,FALSE,sizeof(gint*));

	g_array_append_vals(hf,hf_base,array_length(hf_base));
	g_array_append_vals(ett_arr,ett_base,array_length(ett_base));
	
	init_xml_names();

	xml_ns.hf_tag = proto_register_protocol(xml_ns.blurb, xml_ns.longname, xml_ns.name);

	proto_register_field_array(xml_ns.hf_tag, (hf_register_info*)hf->data, hf->len);
	proto_register_subtree_array((gint**)ett_arr->data, ett_arr->len);
	
	register_dissector("xml", dissect_xml, xml_ns.hf_tag);
	
	init_xml_parser();
}

void
proto_reg_handoff_xml(void)
{
	
	xml_handle = find_dissector("xml");
	
	dissector_add_string("media_type", "text/xml", xml_handle);
	dissector_add_string("media_type", "application/xml", xml_handle);
	dissector_add_string("media_type", "application/soap+xml", xml_handle);
	dissector_add_string("media_type", "application/xml-dtd", xml_handle);
	/* WAP and OMA XML media */
	dissector_add_string("media_type", "text/vnd.wap.wml", xml_handle);
	dissector_add_string("media_type", "text/vnd.wap.si", xml_handle);
	dissector_add_string("media_type", "text/vnd.wap.sl", xml_handle);
	dissector_add_string("media_type", "text/vnd.wap.co", xml_handle);
	dissector_add_string("media_type", "text/vnd.wap.emn", xml_handle);
	dissector_add_string("media_type", "application/vnd.wv.csp+xml", xml_handle);
	/* The Extensible Markup Language (XML) Configuration Access Protocol (XCAP)
		* draft-ietf-simple-xcap-06
		*/
	dissector_add_string("media_type", "application/xcap-el+xml", xml_handle);
	dissector_add_string("media_type", "application/xcap-att+xml", xml_handle);
	dissector_add_string("media_type", "application/xcap-error+xml", xml_handle);
	dissector_add_string("media_type", "application/xcap-caps+xml", xml_handle);
	/* draft-ietf-simple-presence-rules-02 */
	dissector_add_string("media_type", "application/auth-policy+xml", xml_handle);
	/* Other */
	dissector_add_string("media_type", "application/smil", xml_handle);
	dissector_add_string("media_type", "application/cpim-pidf+xml", xml_handle);
	dissector_add_string("media_type", "application/rdf+xml", xml_handle);
	dissector_add_string("media_type", "application/xslt+xml", xml_handle);
	dissector_add_string("media_type", "application/mathml+xml", xml_handle);
	dissector_add_string("media_type", "image/svg+xml", xml_handle);
	dissector_add_string("media_type", "application/vnd.wv.csp.xml", xml_handle);
	
}
